use crate::backend::event::EventKind;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};

/* Streaming BB-level timing error against the TraceDoctor oracle.
 *
 *     eps(BB) = sum_i |t_i - that_i| / sum_i t_i
 *
 * t_i is the oracle's attributed residency for dynamic BB instance i (the
 * four TIP state columns, already in twelfths); that_i is the estimate under
 * test -- the forward delta between the two control-flow events bracketing
 * that instance. Instance i is entered at event i-1 (whose arc target is the
 * instance's start pc) and exited at event i.
 *
 * Both sides stay streamed with bounded lookahead, so memory is O(resync
 * window) no matter how long the capture runs; this is the whole point of
 * doing it in-decoder rather than dumping events to disk first.
 *
 * The same core serves two callers: the decoded TACIT stream (an ordinary
 * receiver) and each emulated sparse format (an emulation error analyzer,
 * pushing emu_ts). They see byte-identical event sequences and match on arc
 * targets, which carry no timing, so every consumer locks onto the same
 * oracle rows and the denominators are identical by construction.
 *
 * Arithmetic is exact: everything is kept in twelfths, so an estimate delta
 * is scaled by 12 rather than the oracle being divided down. The |d| >= 1
 * cycle split is therefore |d_x12| >= 12 with no float anywhere.
 *
 * Control flow is expected to be reproduced exactly; a divergence means the
 * two windows have drifted (a foreign-asid excursion the decoder cannot
 * symbolize, a trap), so we search for the minimal skip on either side that
 * re-locks for RESYNC_PROBE consecutive instances and report the coverage.
 */

const RESYNC_INST_WINDOW: usize = 8192; // max oracle rows skipped at once
const RESYNC_EV_WINDOW: usize = 64; // max events skipped at once
const RESYNC_PROBE: usize = 8; // consecutive matches required to accept a lock

const BB_HEADER: &str = "entry_tsc,exit_tsc,bb_pc,prv,asid,retired,computing_x12,\
stalled_x12,flushed_x12,drained_x12";

pub struct Instance {
    pub bb_pc: u64,
    pub cycles_x12: u64,
    /// exit_tsc minus the exit_tsc of this row's immediate predecessor in the
    /// RAW csv -- tracked before asid filtering, so neither a filtered row nor
    /// a later resync skip can stretch it across a gap. This is what a
    /// lossless estimator would report, i.e. the reference's own floor.
    pub ref_delta: Option<u64>,
}

struct OracleReader {
    lines: Box<dyn Iterator<Item = std::io::Result<String>> + Send>,
    user_asids: Option<HashSet<u64>>,
    prev_raw_exit: Option<u64>,
    row_no: u64,
    dropped: u64,
    yielded: u64,
    limit: Option<u64>,
}

impl OracleReader {
    fn new(path: &str, user_asids: Option<HashSet<u64>>, limit: Option<u64>) -> Self {
        let file = File::open(path)
            .unwrap_or_else(|e| panic!("oracle_bb: cannot open {}: {}", path, e));
        let reader: Box<dyn BufRead + Send> = if path.ends_with(".zst") {
            let dec = zstd::stream::read::Decoder::new(file)
                .unwrap_or_else(|e| panic!("oracle_bb: zstd init for {}: {}", path, e));
            Box::new(BufReader::with_capacity(1 << 20, dec))
        } else {
            Box::new(BufReader::with_capacity(1 << 20, file))
        };
        let mut lines = reader.lines();
        match lines.next() {
            Some(Ok(h)) if h.trim() == BB_HEADER => {}
            Some(Ok(h)) => panic!(
                "oracle_bb: {}: unexpected header {:?}; expected the 10-column \
bboracle csv with exit_tsc",
                path,
                h.trim()
            ),
            _ => panic!("oracle_bb: {}: empty or unreadable", path),
        }
        Self {
            lines: Box::new(lines),
            user_asids,
            prev_raw_exit: None,
            row_no: 1,
            dropped: 0,
            yielded: 0,
            limit,
        }
    }

    fn next_instance(&mut self) -> Option<Instance> {
        loop {
            if let Some(l) = self.limit {
                if self.yielded >= l {
                    return None;
                }
            }
            let line = match self.lines.next() {
                Some(Ok(l)) => l,
                Some(Err(e)) => panic!("oracle_bb: read error at row {}: {}", self.row_no, e),
                None => return None,
            };
            self.row_no += 1;
            if line.trim().is_empty() {
                continue;
            }
            let f: Vec<&str> = line.split(',').collect();
            if f.len() != 10 {
                panic!(
                    "oracle_bb: row {} has {} fields, expected 10: {:?}",
                    self.row_no,
                    f.len(),
                    line
                );
            }
            let row_no = self.row_no;
            let num = |s: &str, what: &str| -> u64 {
                s.trim()
                    .parse::<u64>()
                    .unwrap_or_else(|_| panic!("oracle_bb: bad {} at row {}", what, row_no))
            };
            let exit = num(f[1], "exit_tsc");
            let bb_pc = u64::from_str_radix(f[2].trim().trim_start_matches("0x"), 16)
                .unwrap_or_else(|_| panic!("oracle_bb: bad bb_pc at row {}", row_no));
            let prv = f[3].trim();
            let asid = num(f[4], "asid");
            let cycles_x12 = num(f[6], "computing_x12")
                + num(f[7], "stalled_x12")
                + num(f[8], "flushed_x12")
                + num(f[9], "drained_x12");

            // user-mode rows in an address space the decoder holds no binary
            // for cannot be symbolized, so they are not comparable
            if let Some(ref keep) = self.user_asids {
                if prv == "0" && !keep.contains(&asid) {
                    self.dropped += 1;
                    self.prev_raw_exit = Some(exit);
                    continue;
                }
            }

            let ref_delta = self.prev_raw_exit.map(|p| exit.saturating_sub(p));
            self.prev_raw_exit = Some(exit);
            self.yielded += 1;
            return Some(Instance {
                bb_pc,
                cycles_x12,
                ref_delta,
            });
        }
    }
}

/// Per-pair statistics the matcher owns; sinks read these at finish.
pub struct MatchStats {
    pub matched: u64,
    pub resyncs: u64,
    pub skip_i: u64,
    pub skip_k: u64,
    pub tail_i: u64,
    pub tail_k: u64,
    pub dropped: u64,
}

/// What to do with a matched (oracle instance, estimator delta) pair.
///
/// `t_x12` is the oracle's attributed residency for the instance and
/// `that_x12` the estimator's, both in twelfths so the comparison stays in
/// exact integers. `ref_delta_x12` is what a lossless estimator would have
/// reported (None only for the very first instance). `kind` is the event that
/// closed the instance -- sinks that model the call stack need it; the BB sink
/// ignores it.
pub trait PairSink {
    fn on_pair(
        &mut self,
        t_x12: u64,
        that_x12: u64,
        ref_delta_x12: Option<u64>,
        kind: &EventKind,
    );
    /// Stack-relevant events that carry no arc and so close no block.
    /// `SyncStart` seeds the unwinder's prv/ctx (its only job -- it opens no
    /// frame); `Pause`/`Resume` bracket a lossy gap. These are handed over
    /// immediately rather than through the pair buffer, which is exact for a
    /// session's opening `SyncStart` because it precedes every arc event. The
    /// matcher warns if one ever lands with pairs still buffered.
    fn on_out_of_band(&mut self, _kind: &EventKind) {}

    fn finish(&mut self, label: &str, stats: &MatchStats);
}

/// Streams the oracle against an event stream and hands matched pairs to a
/// sink. Generic rather than boxed: at ~10^9 pairs a virtual call per pair is
/// seconds of pure overhead, and the sink type is known at construction.
pub struct OracleMatcher<S: PairSink> {
    label: String,
    reader: OracleReader,
    sink: S,
    ibuf: VecDeque<Instance>,
    ebuf: VecDeque<(u64, u64, EventKind)>, // (timestamp, arc target, event)
    primed: bool,
    finished: bool,
    matched: u64,
    resyncs: u64,
    skip_i: u64,
    skip_k: u64,
    resync_failed: bool,
    oob_late: u64,
}

impl<S: PairSink> OracleMatcher<S> {
    pub fn from_config(label: String, cfg: &serde_json::Value, sink: S) -> Self {
        let path = cfg
            .get("path")
            .and_then(|v| v.as_str())
            .expect("oracle matcher: 'path' (bboracle csv[.zst]) is required");
        let user_asids = cfg.get("asids").and_then(|v| v.as_array()).map(|a| {
            a.iter()
                .filter_map(|v| v.as_u64())
                .collect::<HashSet<u64>>()
        });
        let limit = cfg.get("limit").and_then(|v| v.as_u64());
        Self::new(label, path, user_asids, limit, sink)
    }

    pub fn new(
        label: String,
        path: &str,
        user_asids: Option<HashSet<u64>>,
        limit: Option<u64>,
        sink: S,
    ) -> Self {
        Self {
            label,
            reader: OracleReader::new(path, user_asids, limit),
            sink,
            ibuf: VecDeque::new(),
            ebuf: VecDeque::new(),
            primed: false,
            finished: false,
            matched: 0,
            resyncs: 0,
            skip_i: 0,
            skip_k: 0,
            resync_failed: false,
            oob_late: 0,
        }
    }

    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    /// Arc-bearing events terminate a basic block; everything else (sync,
    /// pause/resume, breakpoint chatter) carries no arc and is not a block
    /// boundary, so it never enters the pairing.
    pub fn push(&mut self, timestamp: u64, kind: &EventKind) {
        let arc = match kind {
            EventKind::TakenBranch { arc }
            | EventKind::NonTakenBranch { arc }
            | EventKind::UninferableJump { arc }
            | EventKind::InferrableJump { arc } => *arc,
            EventKind::Trap { arc, .. } => *arc,
            EventKind::SyncStart { .. } | EventKind::Pause { .. } | EventKind::Resume { .. } => {
                if self.finished {
                    return;
                }
                // in order iff nothing is buffered; true for a session's
                // opening SyncStart, and all our captures are single-session
                if !self.ebuf.is_empty() {
                    self.oob_late += 1;
                    if self.oob_late == 1 {
                        println!(
                            "{}: WARNING out-of-band event with {} pairs buffered; \
stack seeding is applied ahead of them",
                            self.label,
                            self.ebuf.len()
                        );
                    }
                }
                self.sink.on_out_of_band(kind);
                return;
            }
            _ => return,
        };
        if self.finished || self.resync_failed {
            return;
        }
        self.ebuf.push_back((timestamp, arc.1, kind.clone()));
        self.drive(false);
    }

    fn fill_i(&mut self, n: usize) -> usize {
        while self.ibuf.len() < n {
            match self.reader.next_instance() {
                Some(i) => self.ibuf.push_back(i),
                None => break,
            }
        }
        self.ibuf.len()
    }

    fn probe(&self, di: usize, dk: usize, n: usize) -> bool {
        let ni = self.ibuf.len().saturating_sub(di);
        let nk = self.ebuf.len().saturating_sub(dk);
        let n = n.min(ni).min(nk);
        if n == 0 {
            return false;
        }
        (0..n).all(|j| self.ibuf[di + j].bb_pc == self.ebuf[dk + j].1)
    }

    fn drive(&mut self, draining: bool) {
        loop {
            if self.resync_failed {
                return;
            }
            // instance 0's entry is unobservable: nothing precedes it to
            // stamp, so it is dropped once, up front
            if !self.primed {
                if self.fill_i(2) < 2 {
                    return;
                }
                self.ibuf.pop_front();
                self.primed = true;
            }
            if self.fill_i(1) < 1 {
                return; // oracle exhausted
            }
            if self.ebuf.len() < 2 {
                return; // need one event of lookahead to close the instance
            }
            if self.ibuf[0].bb_pc == self.ebuf[0].1 {
                let ts_delta = self.ebuf[1].0.saturating_sub(self.ebuf[0].0);
                let inst = self.ibuf.pop_front().unwrap();
                let (_, _, kind) = self.ebuf.pop_front().unwrap();
                self.matched += 1;
                self.sink.on_pair(
                    inst.cycles_x12,
                    ts_delta.saturating_mul(12),
                    inst.ref_delta.map(|d| d.saturating_mul(12)),
                    &kind,
                );
                continue;
            }
            // divergence: wait for a full search window unless we are draining
            if !draining && self.ebuf.len() < RESYNC_EV_WINDOW + 1 + RESYNC_PROBE {
                return;
            }
            if !self.resync() {
                return;
            }
        }
    }

    /// Minimal-total skip on either side that re-locks for RESYNC_PROBE
    /// consecutive instances. Returns false if no lock was found.
    fn resync(&mut self) -> bool {
        self.fill_i(RESYNC_INST_WINDOW);
        let horizon = self.ibuf.len().min(RESYNC_INST_WINDOW);
        let mut upcoming: HashMap<u64, Vec<usize>> = HashMap::new();
        for di in 0..horizon {
            upcoming.entry(self.ibuf[di].bb_pc).or_default().push(di);
        }
        let mut best: Option<(usize, usize)> = None;
        let ev_horizon = (RESYNC_EV_WINDOW + 1).min(self.ebuf.len());
        for dk in 0..ev_horizon {
            if let Some(dis) = upcoming.get(&self.ebuf[dk].1) {
                for &di in dis {
                    if di == 0 && dk == 0 {
                        continue;
                    }
                    if let Some((bi, bk)) = best {
                        if di + dk >= bi + bk {
                            break;
                        }
                    }
                    if self.probe(di, dk, RESYNC_PROBE) {
                        best = Some((di, dk));
                        break;
                    }
                }
            }
        }
        match best {
            Some((di, dk)) => {
                self.resyncs += 1;
                self.skip_i += di as u64;
                self.skip_k += dk as u64;
                for _ in 0..di {
                    self.ibuf.pop_front();
                }
                for _ in 0..dk {
                    self.ebuf.pop_front();
                }
                true
            }
            None => {
                println!(
                    "{}: resync failed (oracle bb {:#x}, event target {:#x}); \
truncating comparison here",
                    self.label, self.ibuf[0].bb_pc, self.ebuf[0].1
                );
                self.resync_failed = true;
                false
            }
        }
    }

    pub fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.drive(true);

        // whatever the oracle still holds was never paired
        let mut tail_i = self.ibuf.len() as u64;
        while self.reader.next_instance().is_some() {
            tail_i += 1;
        }
        let stats = MatchStats {
            matched: self.matched,
            resyncs: self.resyncs,
            skip_i: self.skip_i,
            skip_k: self.skip_k,
            tail_i,
            tail_k: self.ebuf.len() as u64,
            dropped: self.reader.dropped,
        };

        if stats.dropped > 0 {
            println!(
                "{}: filtered {} foreign-asid user instances",
                self.label, stats.dropped
            );
        }
        println!(
            "{}: matched {} pairs (resyncs: {}, skipped {} inst / {} ev \
mid-stream; tail: {} inst / {} ev)",
            self.label, stats.matched, stats.resyncs, stats.skip_i, stats.skip_k,
            stats.tail_i, stats.tail_k
        );
        let total_pairs = stats.matched + stats.skip_i + stats.skip_k;
        if stats.matched > 0 {
            println!(
                "{}: coverage {:.2}% of aligned rows",
                self.label,
                100.0 * stats.matched as f64 / total_pairs.max(1) as f64
            );
        }
        if self.oob_late > 0 {
            println!(
                "{}: {} out-of-band events arrived mid-stream",
                self.label, self.oob_late
            );
        }
        let label = self.label.clone();
        self.sink.finish(&label, &stats);
    }
}
