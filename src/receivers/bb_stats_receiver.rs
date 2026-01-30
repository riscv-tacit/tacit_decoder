use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use crate::backend::event::{Entry, EventKind};

use bus::BusReader;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct BB {
    start_addr: u64,
    end_addr: u64,
}

/* Receiver for answering the question: "How many cycles were executed in each basic block?" */
pub struct BBStatsReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    bb_records: HashMap<BB, Vec<u64>>,
    prev_addr: u64,
    prev_timestamp: u64,
}

impl BBStatsReceiver {
    pub fn new(bus_rx: BusReader<Entry>, path: String) -> Self {
        Self {
            writer: BufWriter::new(File::create(path).unwrap()),
            receiver: BusReceiver {
                name: "bb_stats".to_string(),
                bus_rx,
                checksum: 0,
            },
            bb_records: HashMap::new(),
            prev_addr: 0,
            prev_timestamp: 0,
        }
    }
}

pub fn factory(
    _shared: &Shared,
    _config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let path = _config.get("path").and_then(|value| value.as_str()).unwrap_or("trace.bb_stats.csv").to_string();
    Box::new(BBStatsReceiver::new(bus_rx, path))
}

crate::register_receiver!("bb_stats", factory);

impl BBStatsReceiver {
    fn update_bb_records(&mut self, from_addr: u64, to_addr: u64, timestamp: u64) {
        let bb = BB {
            start_addr: self.prev_addr,
            end_addr: from_addr,
        };
        if self.bb_records.contains_key(&bb) {
            self.bb_records
                .get_mut(&bb)
                .unwrap()
                .push(timestamp - self.prev_timestamp);
        } else {
            self.bb_records
                .insert(bb, vec![timestamp - self.prev_timestamp]);
        }
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
            _ => {}
        }
    }

    fn _flush(&mut self) {
        // write the header
        self.writer.write_all(b"count,mean,netvar,bb\n").unwrap();
        for (bb, intervals) in self.bb_records.iter() {
            if intervals.is_empty() {
                continue;
            }

            // Calculate mean manually
            let sum: u64 = intervals.iter().sum();
            let min = intervals.iter().min().unwrap();
            let mean = sum as f64 / intervals.len() as f64;
            let count = intervals.len();
            let netvar = sum - min * count as u64;

            self.writer
                .write_all(
                    format!(
                        "{}, {}, {}, {:#x}-{:#x}\n",
                        count,
                        mean,
                        netvar,
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
