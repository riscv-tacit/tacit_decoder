use crate::backend::event::{Entry, EventKind};
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use crate::receivers::latency_hist::{LatencyHist, HIST_BINS};

use bus::BusReader;
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::ops::Bound::{Excluded, Included};

/* Interpreter dispatch profiler: given the set of handler entry addresses
   (e.g. a bytecode dispatch table), records the latency of each handler's
   ENTRY basic block conditioned on which handler ran immediately before it.
   Unlike bb_pair_stats' one-hop predecessor, the "from" side here is the
   last handler entered, which attributes transitions correctly even when
   the compiler merges handler tails into shared dispatch blocks of
   arbitrary chain depth. Traps/syncs reset the tracked handler.

   A handler is entered in one of two ways, and both count:

   * an arc lands exactly on a handler entry address (the indirect `jr`
     through the dispatch table, or any direct branch to the label);

   * an arc lands on a block that FALLS THROUGH into a handler entry: the
     entry address lies strictly inside the block [arc target, next arc
     source]. This is what a guarded direct branch (`if (op == g) goto L_g`)
     produces -- the compiler needs an instruction on the taken edge (the
     `pc++` register copy), splits the edge into a stub, and lays the stub
     out in front of the target label. The arrival is canonicalised to the
     entry it flows into, so the transition is recorded under the right
     handler and the "last handler" state does not go stale. The block's
     latency then includes the stub, which is the cost that path pays.
     Every such entry point is counted and reported in the summary so the
     caller can check the number against what it expects (e.g. the number
     of guards it declared).

   Besides the (from, to) tables, the receiver writes the dispatch SITE that
   produced each transition -- the PC and kind (`jr`/`br`/`jal`) of the arc
   that entered the handler -- so "one predecessor dispatches from several
   sites" is visible in the output rather than inferred. */

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum SiteKind {
    Jr,
    Br,
    Jal,
    Nt,
}

impl SiteKind {
    fn name(self) -> &'static str {
        match self {
            SiteKind::Jr => "jr",
            SiteKind::Br => "br",
            SiteKind::Jal => "jal",
            SiteKind::Nt => "nt",
        }
    }
}

#[derive(Clone, Copy)]
struct Site {
    pc: u64,
    kind: SiteKind,
}

pub struct DispatchStatsReceiver {
    path: String,
    writer: BufWriter<File>,
    seq_writer: Option<BufWriter<File>>,
    seq_limit: u64,
    seq_written: u64,
    receiver: BusReceiver,
    handlers: BTreeSet<u64>,
    // (from_handler, to_handler) -> latency distribution (entry block, or whole
    // handler in span mode)
    records: HashMap<(u64, u64), LatencyHist>,
    // (from_handler, site pc, site kind, to_handler) -> the same latency, per site
    site_records: HashMap<(u64, u64, SiteKind, u64), LatencyHist>,
    // (block start, handler entry it falls through into) -> arrivals
    fallthrough: HashMap<(u64, u64), u64>,
    entries_total: u64,
    hist_writer: Option<BufWriter<File>>,
    sites_path: String,
    summary_path: String,
    curr_handler: Option<u64>,
    // a handler entry whose entry-block interval is not yet complete:
    // (handler_addr, entry_timestamp, from_handler, site)
    pending: Option<(u64, u64, Option<u64>, Site)>,
    // the arc that started the block currently executing, and when
    prev_addr: u64,
    prev_ts: u64,
    prev_site: Site,
    // "span": "handler" -- time the WHOLE handler (entry to the next handler entry)
    // instead of just its entry block. Under a sparse format that stamps every
    // uninferable jump exactly (TNT+CYC), this is the interval such a tracer can
    // measure without smearing, so it is the fair best case for comparison.
    span_handler: bool,
    // handler currently executing: (handler_addr, entry_timestamp, from_handler, site)
    curr_span: Option<(u64, u64, Option<u64>, Site)>,
}

fn sibling(path: &str, suffix: &str) -> String {
    match path.strip_suffix(".csv") {
        Some(stem) => format!("{}{}", stem, suffix),
        None => format!("{}{}", path, suffix),
    }
}

impl DispatchStatsReceiver {
    pub fn new(bus_rx: BusReader<Entry>, path: String, handlers: BTreeSet<u64>,
               seq_path: Option<String>, seq_limit: u64, hist_path: Option<String>,
               sites_path: Option<String>, summary_path: Option<String>,
               span_handler: bool) -> Self {
        let sites_path = sites_path.unwrap_or_else(|| sibling(&path, ".sites.csv"));
        let summary_path = summary_path.unwrap_or_else(|| sibling(&path, ".summary.json"));
        Self {
            writer: BufWriter::new(File::create(&path).unwrap()),
            path,
            seq_writer: seq_path.map(|p| {
                let mut w = BufWriter::new(File::create(p).unwrap());
                w.write_all(b"timestamp,to_handler\n").unwrap();
                w
            }),
            seq_limit,
            seq_written: 0,
            receiver: BusReceiver {
                name: "dispatch_stats".to_string(),
                bus_rx,
                checksum: 0,
            },
            handlers,
            records: HashMap::new(),
            site_records: HashMap::new(),
            fallthrough: HashMap::new(),
            entries_total: 0,
            hist_writer: hist_path.map(|p| BufWriter::new(File::create(p).unwrap())),
            sites_path,
            summary_path,
            curr_handler: None,
            pending: None,
            prev_addr: 0,
            prev_ts: 0,
            prev_site: Site { pc: 0, kind: SiteKind::Jr },
            span_handler,
            curr_span: None,
        }
    }

    fn reset_flow(&mut self, to_addr: u64, timestamp: u64) {
        self.curr_handler = None;
        self.pending = None;
        self.curr_span = None;
        self.prev_addr = to_addr;
        self.prev_ts = timestamp;
    }

    fn record(&mut self, from: Option<u64>, site: Site, to: u64, latency: u64) {
        if let Some(f) = from {
            self.records.entry((f, to)).or_default().add(latency);
            self.site_records
                .entry((f, site.pc, site.kind, to))
                .or_default()
                .add(latency);
        }
    }

    // A handler `entry` is entered at `entry_ts` via `site`. In entry mode the
    // block latency is known only when the block ends; `block_end` carries it
    // for the fall-through case, where the block has already ended.
    fn enter(&mut self, entry: u64, entry_ts: u64, site: Site, block_end: Option<u64>) {
        self.entries_total += 1;
        if self.seq_written < self.seq_limit {
            if let Some(ref mut w) = self.seq_writer {
                w.write_all(format!("{},{:#x}\n", entry_ts, entry).as_bytes()).unwrap();
                self.seq_written += 1;
            }
        }
        if self.span_handler {
            // the handler that was running ends here; book its whole span
            if let Some((h, ts0, from, s)) = self.curr_span.take() {
                self.record(from, s, h, entry_ts.saturating_sub(ts0));
                self.curr_handler = Some(h);
            }
            self.curr_span = Some((entry, entry_ts, self.curr_handler, site));
            return;
        }
        match block_end {
            Some(end) => {
                let from = self.curr_handler;
                self.record(from, site, entry, end.saturating_sub(entry_ts));
                self.curr_handler = Some(entry);
            }
            None => self.pending = Some((entry, entry_ts, self.curr_handler, site)),
        }
    }

    // a CFI event: the BB [prev_addr, from_addr] just finished at `timestamp`,
    // and the next BB starts at to_addr
    fn step(&mut self, from_addr: u64, to_addr: u64, timestamp: u64, kind: SiteKind) {
        // complete a pending handler entry block (entry mode)
        if let Some((handler, entry_ts, from, site)) = self.pending.take() {
            self.record(from, site, handler, timestamp.saturating_sub(entry_ts));
            self.curr_handler = Some(handler);
        }
        // did the block that just finished fall through into a handler entry?
        // (only when it did not itself start at one -- that case was handled as a
        // direct entry when the block began)
        if !self.handlers.contains(&self.prev_addr) {
            let contained = self
                .handlers
                .range((Excluded(self.prev_addr), Included(from_addr)))
                .next()
                .copied();
            if let Some(e) = contained {
                *self.fallthrough.entry((self.prev_addr, e)).or_default() += 1;
                let (ts, site) = (self.prev_ts, self.prev_site);
                self.enter(e, ts, site, Some(timestamp));
            }
        }
        // does the next BB start at a handler entry?
        let site = Site { pc: from_addr, kind };
        if self.handlers.contains(&to_addr) {
            self.enter(to_addr, timestamp, site, None);
        }
        self.prev_addr = to_addr;
        self.prev_ts = timestamp;
        self.prev_site = site;
    }

    fn write_row(w: &mut BufWriter<File>, d: &LatencyHist, tail: &str) {
        let count = d.n;
        let mean = d.sum as f64 / count as f64;
        let min = d.min();
        // min() falls back to max when every sample overflowed the bins
        let netvar = d.sum.saturating_sub(min * count);
        w.write_all(
            format!(
                "{}, {}, {}, {}, {}, {}, {}, {}, {}\n",
                count, mean, min, d.quantile(0.50), d.quantile(0.90), d.quantile(0.99),
                d.max, netvar, tail,
            )
            .as_bytes(),
        )
        .unwrap();
    }
}

pub fn factory(
    _shared: &Shared,
    config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let path = config
        .get("path")
        .and_then(|value| value.as_str())
        .unwrap_or("trace.dispatch_stats.csv")
        .to_string();
    let opt = |k: &str| config.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
    let seq_path = opt("seq_path");
    let seq_limit = config.get("seq_limit").and_then(|v| v.as_u64()).unwrap_or(0);
    let hist_path = opt("hist_path");
    let sites_path = opt("sites_path");
    let summary_path = opt("summary_path");
    let span_handler = match config.get("span").and_then(|v| v.as_str()).unwrap_or("entry") {
        "entry" => false,
        "handler" => true,
        other => panic!("dispatch_stats: unknown span '{}' (expected 'entry' or 'handler')", other),
    };
    let handlers: BTreeSet<u64> = config
        .get("handlers")
        .and_then(|value| value.as_array())
        .expect("dispatch_stats requires 'handlers': [\"0x...\", ...]")
        .iter()
        .map(|v| {
            let s = v.as_str().expect("handler addresses must be hex strings");
            u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("bad handler address")
        })
        .collect();
    Box::new(DispatchStatsReceiver::new(bus_rx, path, handlers, seq_path, seq_limit, hist_path,
                                        sites_path, summary_path, span_handler))
}

crate::register_receiver!("dispatch_stats", factory);

impl AbstractReceiver for DispatchStatsReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry {
            Entry::Event {
                timestamp,
                kind: EventKind::SyncStart { start_pc, .. },
            } => {
                self.reset_flow(start_pc, timestamp);
            }
            Entry::Event {
                timestamp,
                kind: EventKind::InferrableJump { arc },
            } => self.step(arc.0, arc.1, timestamp, SiteKind::Jal),
            Entry::Event {
                timestamp,
                kind: EventKind::UninferableJump { arc },
            } => self.step(arc.0, arc.1, timestamp, SiteKind::Jr),
            Entry::Event {
                timestamp,
                kind: EventKind::TakenBranch { arc },
            } => self.step(arc.0, arc.1, timestamp, SiteKind::Br),
            Entry::Event {
                timestamp,
                kind: EventKind::NonTakenBranch { arc },
            } => self.step(arc.0, arc.1, timestamp, SiteKind::Nt),
            Entry::Event {
                timestamp,
                kind: EventKind::Trap { arc, .. },
            } => {
                self.reset_flow(arc.1, timestamp);
            }
            Entry::Event {
                timestamp,
                kind: EventKind::Resume { pc, .. },
            } => {
                self.reset_flow(pc, timestamp);
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        if let Some(ref mut w) = self.seq_writer {
            w.flush().unwrap();
        }
        self.writer
            .write_all(b"count,mean,min,p50,p90,p99,max,netvar,from_handler,to_handler\n")
            .unwrap();
        if let Some(ref mut w) = self.hist_writer {
            w.write_all(b"from_handler,to_handler,cycles,count\n").unwrap();
        }
        let mut keys: Vec<_> = self.records.keys().copied().collect();
        keys.sort();
        for (from, to) in keys {
            let d = &self.records[&(from, to)];
            if d.n == 0 {
                continue;
            }
            Self::write_row(&mut self.writer, d, &format!("{:#x}, {:#x}", from, to));
            if let Some(ref mut w) = self.hist_writer {
                for (c, &k) in d.hist.iter().enumerate() {
                    if k > 0 {
                        w.write_all(format!("{:#x},{:#x},{},{}\n", from, to, c, k).as_bytes())
                            .unwrap();
                    }
                }
                if d.over_n > 0 {
                    // everything at or past the last bin lands in one row (cycles ==
                    // HIST_BINS) so the column stays numeric and counts still sum to n
                    w.write_all(
                        format!("{:#x},{:#x},{},{}\n", from, to, HIST_BINS, d.over_n)
                            .as_bytes(),
                    )
                    .unwrap();
                }
            }
        }
        if let Some(ref mut w) = self.hist_writer {
            w.flush().unwrap();
        }
        self.writer.flush().unwrap();

        // per-site table: which PC, and which kind of branch, produced each transition
        let mut sw = BufWriter::new(File::create(&self.sites_path).unwrap());
        sw.write_all(b"count,mean,min,p50,p90,p99,max,netvar,from_handler,site_pc,site_kind,to_handler\n")
            .unwrap();
        let mut skeys: Vec<_> = self.site_records.keys().copied().collect();
        skeys.sort_by_key(|&(f, pc, k, t)| (f, t, pc, k.name()));
        for (f, pc, k, t) in skeys {
            let d = &self.site_records[&(f, pc, k, t)];
            if d.n > 0 {
                Self::write_row(&mut sw, d, &format!("{:#x}, {:#x}, {}, {:#x}", f, pc, k.name(), t));
            }
        }
        sw.flush().unwrap();

        // summary: the entry-count invariant and the fall-through entries found, so a
        // caller can check both against what it expects for this binary
        let mut ft: Vec<_> = self.fallthrough.iter().map(|(&(b, e), &n)| (b, e, n)).collect();
        ft.sort_by_key(|&(_, _, n)| std::cmp::Reverse(n));
        let summary = serde_json::json!({
            "path": self.path,
            "span": if self.span_handler { "handler" } else { "entry" },
            "handlers": self.handlers.len(),
            "entries_total": self.entries_total,
            "fallthrough_entries": ft.iter().map(|&(b, e, n)| serde_json::json!({
                "block_start": format!("{:#x}", b),
                "handler": format!("{:#x}", e),
                "count": n,
            })).collect::<Vec<_>>(),
        });
        std::fs::write(&self.summary_path, serde_json::to_string_pretty(&summary).unwrap() + "\n")
            .unwrap();
        println!(
            "dispatch_stats: {} handler entries; {} fall-through entry point(s){}",
            self.entries_total,
            ft.len(),
            if ft.is_empty() {
                String::new()
            } else {
                format!(
                    ": {}",
                    ft.iter()
                        .map(|&(b, e, n)| format!("{:#x}->{:#x} x{}", b, e, n))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        );
    }
}
