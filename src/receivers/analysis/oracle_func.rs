use crate::backend::event::{Entry, EventKind};
use crate::common::symbol_index::SymbolIndex;
use crate::receivers::oracle_match::{MatchStats, PairSink};
use crate::receivers::stack_unwinder::StackUnwinder;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Arc;

/* Function-level timing error against the TraceDoctor oracle.
 *
 * The unwinder is driven purely by control flow -- it is handed
 * `Entry::Event { timestamp: 0, .. }`, so frames cannot depend on any clock.
 * Since every estimator reproduces the identical event sequence, all of them
 * see the identical frames. "Function" is therefore an arbitrary but *shared*
 * partition of one stream: whatever the unwinder's call/return heuristics get
 * wrong, they get wrong the same way on both sides, so the comparison stays
 * exact even where the partition would not survive scrutiny as ground truth.
 *
 * Two aggregations come out of the same pass:
 *   self       cycles while the frame is innermost, settled at frame close
 *   inclusive  cycles between frame open and close, callees included
 *
 * The lossless reference delta is carried through the same stacks, giving a
 * function-level floor directly comparable to the BB-level one -- the question
 * being how much of the oracle's flush-attribution convention survives
 * aggregation to function granularity (flushes that stay inside one function
 * cancel; those crossing a call boundary do not).
 */
pub struct FuncSink {
    unwinder: StackUnwinder,

    // parallel to the unwinder's frame stack, all in twelfths
    self_t: Vec<u64>,
    self_that: Vec<u64>,
    self_ref: Vec<u64>,
    open_t: Vec<u128>,
    open_that: Vec<u128>,
    open_ref: Vec<u128>,

    cum_t: u128,
    cum_that: u128,
    cum_ref: u128,

    self_num: u128,
    self_den: u128,
    self_ref_num: u128,
    incl_num: u128,
    incl_den: u128,
    incl_ref_num: u128,
    closes: u64,
    max_depth: usize,
    // cycles that elapsed while no frame was open (unresolved symbols)
    orphan_t: u128,

    by_symbol: HashMap<String, (u128, u128, u128)>, // name -> (self t, |d|, |d_ref|)
    writer: Option<BufWriter<File>>,
    top_n: usize,
}

impl FuncSink {
    pub fn new(cfg: &serde_json::Value, symbols: Arc<SymbolIndex>) -> Self {
        // NB: the per-frame dump is keyed "dump", never "path" -- "path" is the
        // oracle input this sink reads, and creating a writer on it truncates
        // the capture. Refuse the aliasing outright rather than trust the key.
        let oracle_path = cfg.get("path").and_then(|v| v.as_str());
        let writer = cfg
            .get("dump")
            .and_then(|v| v.as_str())
            .map(|p| {
                assert!(
                    Some(p) != oracle_path,
                    "oracle_func: 'dump' ({}) must not be the oracle 'path'",
                    p
                );
                let mut w = BufWriter::new(File::create(p).unwrap());
                w.write_all(b"self_t,self_that,self_ref,incl_t,incl_that,incl_ref,symbol\n")
                    .unwrap();
                w
            });
        Self {
            unwinder: StackUnwinder::new(symbols).expect("init unwinder"),
            self_t: Vec::new(),
            self_that: Vec::new(),
            self_ref: Vec::new(),
            open_t: Vec::new(),
            open_that: Vec::new(),
            open_ref: Vec::new(),
            cum_t: 0,
            cum_that: 0,
            cum_ref: 0,
            self_num: 0,
            self_den: 0,
            self_ref_num: 0,
            incl_num: 0,
            incl_den: 0,
            incl_ref_num: 0,
            closes: 0,
            max_depth: 0,
            orphan_t: 0,
            by_symbol: HashMap::new(),
            writer,
            top_n: cfg.get("top_n").and_then(|v| v.as_u64()).unwrap_or(15) as usize,
        }
    }

    /// Apply one unwinder step: settle every frame it closed, then open the
    /// new one. Shared by the paired and out-of-band paths.
    fn apply(&mut self, kind: &EventKind) {
        let update = self
            .unwinder
            .step(&Entry::Event { timestamp: 0, kind: kind.clone() });
        let Some(update) = update else { return };

        for frame in update.frames_closed {
            let (st, sh, sr) = match (
                self.self_t.pop(),
                self.self_that.pop(),
                self.self_ref.pop(),
            ) {
                (Some(a), Some(b), Some(c)) => (a, b, c),
                _ => continue, // unwinder closed a frame we never opened
            };
            let (ot, oh, or_) = match (
                self.open_t.pop(),
                self.open_that.pop(),
                self.open_ref.pop(),
            ) {
                (Some(a), Some(b), Some(c)) => (a, b, c),
                _ => continue,
            };
            let it = self.cum_t - ot;
            let ih = self.cum_that - oh;
            let ir = self.cum_ref - or_;

            self.self_num += st.abs_diff(sh) as u128;
            self.self_den += st as u128;
            self.self_ref_num += st.abs_diff(sr) as u128;
            self.incl_num += it.abs_diff(ih);
            self.incl_den += it;
            self.incl_ref_num += it.abs_diff(ir);
            self.closes += 1;

            let e = self
                .by_symbol
                .entry(frame.symbol.name.clone())
                .or_insert((0, 0, 0));
            e.0 += st as u128;
            e.1 += st.abs_diff(sh) as u128;
            e.2 += st.abs_diff(sr) as u128;

            if let Some(ref mut w) = self.writer {
                writeln!(
                    w,
                    "{},{},{},{},{},{},{}",
                    st, sh, sr, it, ih, ir, frame.symbol.name
                )
                .unwrap();
            }
        }

        if update.frames_opened.is_some() {
            self.self_t.push(0);
            self.self_that.push(0);
            self.self_ref.push(0);
            self.open_t.push(self.cum_t);
            self.open_that.push(self.cum_that);
            self.open_ref.push(self.cum_ref);
            self.max_depth = self.max_depth.max(self.self_t.len());
        }
    }
}

impl PairSink for FuncSink {
    fn on_pair(
        &mut self,
        t_x12: u64,
        that_x12: u64,
        ref_delta_x12: Option<u64>,
        kind: &EventKind,
    ) {
        // the instance's cycles belong to the frame that was innermost while
        // it ran, so they land before the transition this event describes
        let r = ref_delta_x12.unwrap_or(t_x12);
        if let Some(top) = self.self_t.last_mut() {
            *top += t_x12;
        } else {
            self.orphan_t += t_x12 as u128;
        }
        if let Some(top) = self.self_that.last_mut() {
            *top += that_x12;
        }
        if let Some(top) = self.self_ref.last_mut() {
            *top += r;
        }
        self.cum_t += t_x12 as u128;
        self.cum_that += that_x12 as u128;
        self.cum_ref += r as u128;

        self.apply(kind);
    }

    fn on_out_of_band(&mut self, kind: &EventKind) {
        self.apply(kind);
    }

    fn finish(&mut self, label: &str, _stats: &MatchStats) {
        if let Some(ref mut w) = self.writer {
            w.flush().unwrap();
        }
        if self.self_den == 0 {
            println!("{}: no closed frames", label);
            return;
        }
        let sd = self.self_den as f64;
        let idn = self.incl_den as f64;
        println!(
            "{}: frames closed {} (max depth {}, {} frames still open, \
orphan {} twelfths)",
            label,
            self.closes,
            self.max_depth,
            self.self_t.len(),
            self.orphan_t
        );
        println!(
            "{}: epsilon(self) = {:.2}%   floor {:.2}%   (sum t {} twelfths)",
            label,
            100.0 * self.self_num as f64 / sd,
            100.0 * self.self_ref_num as f64 / sd,
            self.self_den
        );
        if self.incl_den > 0 {
            println!(
                "{}: epsilon(incl) = {:.2}%   floor {:.2}%   (sum t {} twelfths)",
                label,
                100.0 * self.incl_num as f64 / idn,
                100.0 * self.incl_ref_num as f64 / idn,
                self.incl_den
            );
        }
        let mut v: Vec<_> = self.by_symbol.iter().collect();
        v.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
        println!("{}: top {} by self time", label, self.top_n.min(v.len()));
        for (name, (t, d, dr)) in v.into_iter().take(self.top_n) {
            println!(
                "{}:   {:>14} twelfths  eps {:6.2}%  floor {:6.2}%  {}",
                label,
                t,
                100.0 * *d as f64 / *t.max(&1) as f64,
                100.0 * *dr as f64 / *t.max(&1) as f64,
                name
            );
        }
    }
}
