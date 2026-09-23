use crate::backend::event::{Entry, EventKind};
use crate::common::prv::Prv;
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use crate::receivers::latency_hist::LatencyHist;

use bus::BusReader;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub struct BB {
    start_addr: u64,
    end_addr: u64,
}

/* Predecessor-conditioned bb_stats: "how many cycles did this basic block
   take, given which basic block ran immediately before it?" The key is the
   pair (previous BB, current BB); the recorded interval is the current BB's
   execution time, defined exactly as in bb_stats. Pairs never span a trap or
   a sync: discontinuities reset the predecessor, so the first BB after a
   trap/sync contributes no pair.

   Intervals are kept as a LatencyHist per pair, like bb_stats and dispatch_stats,
   not as a Vec of every sample: on a 300M-dispatch capture the Vec form held
   1.8G samples and peaked near 29 GB, and was only ever summarised. Percentiles
   are exact below HIST_BINS cycles, which covers every pair this is used for. */
pub struct BBPairStatsReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    pair_records: HashMap<(BB, BB), LatencyHist>,
    prev_addr: u64,
    prev_timestamp: u64,
    prev_bb: Option<BB>,
    curr_prv: Prv,
    curr_ctx: u64,
    asid_of_interest: Vec<u64>,
    prv_of_interest: Vec<Prv>,
    min_count: usize,
}

impl BBPairStatsReceiver {
    pub fn new(
        bus_rx: BusReader<Entry>,
        path: String,
        asid_of_interest: Vec<u64>,
        prv_of_interest: Vec<Prv>,
        min_count: usize,
    ) -> Self {
        Self {
            writer: BufWriter::new(File::create(path).unwrap()),
            receiver: BusReceiver {
                name: "bb_pair_stats".to_string(),
                bus_rx,
                checksum: 0,
            },
            pair_records: HashMap::new(),
            prev_addr: 0,
            prev_timestamp: 0,
            prev_bb: None,
            curr_prv: Prv::PrvMachine,
            curr_ctx: 0,
            asid_of_interest,
            prv_of_interest,
            min_count,
        }
    }

    // filters only suppress recording; BB tracking continues regardless
    fn interested(&self) -> bool {
        if !self.prv_of_interest.is_empty() && !self.prv_of_interest.contains(&self.curr_prv) {
            return false;
        }
        if self.curr_prv == Prv::PrvUser
            && !self.asid_of_interest.is_empty()
            && !self.asid_of_interest.contains(&self.curr_ctx)
        {
            return false;
        }
        true
    }

    fn update_pair_records(&mut self, from_addr: u64, to_addr: u64, timestamp: u64) {
        let bb = BB {
            start_addr: self.prev_addr,
            end_addr: from_addr,
        };
        if self.interested() {
            if let Some(prev) = self.prev_bb {
                self.pair_records
                    .entry((prev, bb))
                    .or_default()
                    .add(timestamp - self.prev_timestamp);
            }
        }
        self.prev_bb = Some(bb);
        self.prev_addr = to_addr;
        self.prev_timestamp = timestamp;
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
        .unwrap_or("trace.bb_pair_stats.csv")
        .to_string();
    let asid_of_interest = config
        .get("asid_of_interest")
        .and_then(|value| value.as_array())
        .unwrap_or(&vec![])
        .iter()
        .map(|value| value.as_u64().unwrap())
        .collect();
    let mut prv_of_interest = vec![];
    if config
        .get("do_user")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        prv_of_interest.push(Prv::PrvUser);
    }
    if config
        .get("do_supervisor")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        prv_of_interest.push(Prv::PrvSupervisor);
    }
    if config
        .get("do_machine")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        prv_of_interest.push(Prv::PrvMachine);
    }
    let min_count = config
        .get("min_count")
        .and_then(|value| value.as_u64())
        .unwrap_or(0) as usize;
    Box::new(BBPairStatsReceiver::new(
        bus_rx,
        path,
        asid_of_interest,
        prv_of_interest,
        min_count,
    ))
}

crate::register_receiver!("bb_pair_stats", factory);

impl AbstractReceiver for BBPairStatsReceiver {
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
                        start_prv,
                        start_ctx,
                    },
            } => {
                self.curr_prv = start_prv;
                self.curr_ctx = start_ctx;
                self.prev_addr = start_pc;
                self.prev_timestamp = timestamp;
                self.prev_bb = None;
            }
            Entry::Event {
                timestamp,
                kind: EventKind::InferrableJump { arc },
            } => {
                self.update_pair_records(arc.0, arc.1, timestamp);
            }
            Entry::Event {
                timestamp,
                kind: EventKind::UninferableJump { arc },
            } => {
                self.update_pair_records(arc.0, arc.1, timestamp);
            }
            Entry::Event {
                timestamp,
                kind: EventKind::TakenBranch { arc },
            } => {
                self.update_pair_records(arc.0, arc.1, timestamp);
            }
            Entry::Event {
                timestamp,
                kind: EventKind::NonTakenBranch { arc },
            } => {
                self.update_pair_records(arc.0, arc.1, timestamp);
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
                self.curr_prv = prv_arc.1;
                if let Some(c) = ctx {
                    self.curr_ctx = c;
                }
                // drop the BB spanning the trap and forget the predecessor
                self.prev_addr = arc.1;
                self.prev_timestamp = timestamp;
                self.prev_bb = None;
            }
            Entry::Event {
                timestamp,
                kind: EventKind::Pause { pause_pc },
            } => {
                // block and pair up to the paused instruction are exact
                self.update_pair_records(pause_pc, pause_pc, timestamp);
                self.prev_bb = None;
            }
            Entry::Event {
                timestamp,
                kind: EventKind::Resume { pc, prv, ctx, .. },
            } => {
                self.curr_prv = prv;
                self.curr_ctx = ctx;
                self.prev_addr = pc;
                self.prev_timestamp = timestamp;
                self.prev_bb = None;
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        self.writer
            .write_all(b"count,mean,min,p50,p90,p99,max,netvar,prev_bb,bb\n")
            .unwrap();
        for ((prev, bb), d) in self.pair_records.iter() {
            if d.n == 0 || (d.n as usize) < self.min_count {
                continue;
            }

            // Same summary as the Vec-based version: nearest-rank percentiles on the
            // implied sorted sample (LatencyHist::quantile), min from the first
            // occupied bin, netvar = sum - min*count.
            let count = d.n;
            let sum = d.sum;
            let mean = sum as f64 / count as f64;
            let min = d.min();
            let p50 = d.quantile(0.50);
            let p90 = d.quantile(0.90);
            let p99 = d.quantile(0.99);
            let max = d.max;
            let netvar = sum.saturating_sub(min * count);

            self.writer
                .write_all(
                    format!(
                        "{}, {}, {}, {}, {}, {}, {}, {}, {:#x}-{:#x}, {:#x}-{:#x}\n",
                        count,
                        mean,
                        min,
                        p50,
                        p90,
                        p99,
                        max,
                        netvar,
                        prev.start_addr,
                        prev.end_addr,
                        bb.start_addr,
                        bb.end_addr,
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
        self.writer.flush().unwrap();
    }
}
