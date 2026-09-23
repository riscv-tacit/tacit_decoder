use crate::backend::event::{Entry, EventKind};
use crate::common::prv::Prv;
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use crate::receivers::latency_hist::LatencyHist;

use bus::BusReader;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub struct BB {
    start_addr: u64,
    end_addr: u64,
}

/* Receiver for answering the question: "How many cycles were executed in each basic block?" */
pub struct BBStatsReceiver {
    writer: BufWriter<File>,
    hist_writer: Option<BufWriter<File>>,
    hist_top: usize,          // dump histograms for the N highest-span blocks (0 = all)
    hist_bbs: HashSet<u64>,   // ...plus these block start addresses, always
    receiver: BusReceiver,
    bb_records: HashMap<BB, LatencyHist>,
    prev_addr: u64,
    prev_timestamp: u64,
    asid_of_interest: Vec<u64>,
    prv_of_interest: Vec<Prv>,
    interested: bool,
}

impl BBStatsReceiver {
    pub fn new(
        bus_rx: BusReader<Entry>,
        path: String,
        asid_of_interest: Vec<u64>,
        prv_of_interest: Vec<Prv>,
        hist_path: Option<String>,
        hist_top: usize,
        hist_bbs: HashSet<u64>,
    ) -> Self {
        Self {
            writer: BufWriter::new(File::create(path).unwrap()),
            hist_writer: hist_path.map(|p| BufWriter::new(File::create(p).unwrap())),
            hist_top,
            hist_bbs,
            receiver: BusReceiver {
                name: "bb_stats".to_string(),
                bus_rx,
                checksum: 0,
            },
            bb_records: HashMap::new(),
            prev_addr: 0,
            prev_timestamp: 0,
            asid_of_interest: asid_of_interest,
            prv_of_interest: prv_of_interest,
            interested: false,
        }
    }
}

pub fn factory(
    _shared: &Shared,
    _config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let path = _config
        .get("path")
        .and_then(|value| value.as_str())
        .unwrap_or("trace.bb_stats.csv")
        .to_string();
    // optional: dump the full per-block latency histogram, not just the percentiles
    let hist_path = _config
        .get("hist_path")
        .and_then(|value| value.as_str())
        .map(|s| s.to_string());
    let hist_top = _config
        .get("hist_top")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let hist_bbs: HashSet<u64> = _config
        .get("hist_bbs")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .collect()
        })
        .unwrap_or_default();
    let asid_of_interest = _config
        .get("asid_of_interest")
        .and_then(|value| value.as_array())
        .unwrap_or(&vec![])
        .iter()
        .map(|value| value.as_u64().unwrap())
        .collect();
    let mut prv_of_interest = vec![];
    if _config
        .get("do_user")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        prv_of_interest.push(Prv::PrvUser);
    }
    if _config
        .get("do_supervisor")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        prv_of_interest.push(Prv::PrvSupervisor);
    }
    if _config
        .get("do_machine")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        prv_of_interest.push(Prv::PrvMachine);
    }
    Box::new(BBStatsReceiver::new(
        bus_rx,
        path,
        asid_of_interest,
        prv_of_interest,
        hist_path,
        hist_top,
        hist_bbs,
    ))
}

crate::register_receiver!("bb_stats", factory);

impl BBStatsReceiver {
    fn update_bb_records(&mut self, from_addr: u64, to_addr: u64, timestamp: u64) {
        let bb = BB {
            start_addr: self.prev_addr,
            end_addr: from_addr,
        };
        self.bb_records
            .entry(bb)
            .or_default()
            .add(timestamp - self.prev_timestamp);
        self.prev_addr = to_addr;
        self.prev_timestamp = timestamp;
    }
}

impl AbstractReceiver for BBStatsReceiver {
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
                kind:
                    EventKind::SyncStart {
                        runtime_cfg: _,
                        start_pc,
                        start_prv: _,
                        start_ctx: _,
                    },
            } => {
                self.prev_addr = start_pc;
                self.prev_timestamp = timestamp;
            }
            Entry::Event {
                timestamp,
                kind: EventKind::InferrableJump { arc },
            } => {
                self.update_bb_records(arc.0, arc.1, timestamp);
            }
            Entry::Event {
                timestamp,
                kind: EventKind::UninferableJump { arc },
            } => {
                self.update_bb_records(arc.0, arc.1, timestamp);
            }
            Entry::Event {
                timestamp,
                kind: EventKind::TakenBranch { arc },
            } => {
                self.update_bb_records(arc.0, arc.1, timestamp);
            }
            Entry::Event {
                timestamp,
                kind: EventKind::NonTakenBranch { arc },
            } => {
                self.update_bb_records(arc.0, arc.1, timestamp);
            }
            Entry::Event {
                timestamp,
                kind:
                    EventKind::Trap {
                        reason: _,
                        prv_arc,
                        arc,
                        ctx,
                    },
            } => {
                if self.prv_of_interest.contains(&prv_arc.1) {
                    if prv_arc.1 == Prv::PrvUser {
                        if self.asid_of_interest.contains(&ctx.unwrap()) {
                            self.interested = true;
                        }
                    } else {
                        self.interested = true;
                    }
                }
                // drop the last bb, but update prev_addr and prev_timestamp
                self.prev_addr = arc.1;
                self.prev_timestamp = timestamp;
            }
            Entry::Event {
                timestamp,
                kind: EventKind::Pause { pause_pc },
            } => {
                // the block ending at the paused control-flow instruction is
                // exact (straight-line walk, exact cycle); only its successor is lost
                self.update_bb_records(pause_pc, pause_pc, timestamp);
            }
            Entry::Event {
                timestamp,
                kind: EventKind::Resume { pc, .. },
            } => {
                // gap cycles belong to no block
                self.prev_addr = pc;
                self.prev_timestamp = timestamp;
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        // write the header
        self.writer
            .write_all(b"count,mean,min,p5,p25,p50,p90,p99,max,netvar,vbb,bb\n")
            .unwrap();
        // Dumping every block's histogram is mostly empty rows; only a handful are ever
        // plotted. Select the highest-span blocks plus any explicitly named ones.
        let mut hist_keep: HashSet<BB> = HashSet::new();
        if self.hist_writer.is_some() {
            if self.hist_top == 0 && self.hist_bbs.is_empty() {
                hist_keep.extend(self.bb_records.keys().copied());
            } else {
                let mut ranked: Vec<(f64, BB)> = self
                    .bb_records
                    .iter()
                    .filter(|(_, d)| d.n > 0)
                    .map(|(bb, d)| {
                        let mean = d.sum as f64 / d.n as f64;
                        ((d.n as f64) * (mean - d.quantile(0.05) as f64).max(0.0), *bb)
                    })
                    .collect();
                ranked.sort_unstable_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
                hist_keep.extend(ranked.iter().take(self.hist_top).map(|(_, bb)| *bb));
                hist_keep.extend(
                    self.bb_records
                        .keys()
                        .filter(|bb| self.hist_bbs.contains(&bb.start_addr))
                        .copied(),
                );
            }
            let n_keep = hist_keep.len();
            if let Some(ref mut w) = self.hist_writer {
                w.write_all(b"bb,cycles,count\n").unwrap();
                println!("bb_stats: dumping histograms for {} of {} blocks",
                         n_keep, self.bb_records.len());
            }
        }
        for (bb, d) in self.bb_records.iter() {
            if d.n == 0 {
                continue;
            }
            if let (Some(ref mut w), true) = (self.hist_writer.as_mut(), hist_keep.contains(bb)) {
                for (c, &k) in d.hist.iter().enumerate() {
                    if k > 0 {
                        w.write_all(format!("{:#x}-{:#x},{},{}\n",
                                            bb.start_addr, bb.end_addr, c, k).as_bytes())
                            .unwrap();
                    }
                }
                if d.over_n > 0 {
                    w.write_all(format!("{:#x}-{:#x},{},{}\n", bb.start_addr, bb.end_addr,
                                        crate::receivers::latency_hist::HIST_BINS,
                                        d.over_n).as_bytes()).unwrap();
                }
            }
            let count = d.n;
            let mean = d.sum as f64 / count as f64;
            let min = d.min();
            // `vbb` is the ranking metric: expected cycles per execution above this
            // block's near-best case, times executions -- i.e. the time attributable to
            // microarchitectural variation rather than to the work itself. The floor is p5,
            // not min: min is a single luckiest sample and drifts ~10% between identical
            // runs, while p5 is stable. Both are exact here because the histogram bins are
            // one cycle wide. netvar (the min-based version) is kept for comparison.
            let p5 = d.quantile(0.05);
            let p25 = d.quantile(0.25);
            let p90 = d.quantile(0.90);
            let netvar = d.sum.saturating_sub(min * count);
            let vbb = (count as f64) * (mean - p5 as f64).max(0.0);
            self.writer
                .write_all(
                    format!(
                        "{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {:#x}-{:#x}\n",
                        count, mean, min, p5, p25, d.quantile(0.50),
                        p90, d.quantile(0.99), d.max, netvar, vbb,
                        bb.start_addr, bb.end_addr,
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
        if let Some(ref mut w) = self.hist_writer {
            w.flush().unwrap();
        }
        self.writer.flush().unwrap();
    }
}
