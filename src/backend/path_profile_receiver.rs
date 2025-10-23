use crate::backend::abstract_receiver::{AbstractReceiver, BusReceiver};
use crate::backend::event::{Entry, EventKind};
use crate::backend::stack_unwinder::StackUnwinder;
use crate::common::insn_index::InstructionIndex;
use crate::common::symbol_index::SymbolIndex;
use std::sync::Arc;
use bus::BusReader;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Path {
    entry_point: u64,
    branches: Vec<bool>,
}

pub struct PathRecord {
    path: Path,
    times: Vec<u64>,
}

pub struct PathProfileReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    path_records: HashMap<Path, Vec<u64>>,
    unwinder: StackUnwinder,
    current_paths: Vec<PathRecord>,
}

impl PathProfileReceiver {
    pub fn new(
        bus_rx: BusReader<Entry>,
        symbols: Arc<SymbolIndex>,
        insns: Arc<InstructionIndex>,
    ) -> Self {
        let unwinder = StackUnwinder::new(Arc::clone(&symbols), Arc::clone(&insns)).expect("stack unwinder");
        Self {
            writer: BufWriter::new(File::create("trace.path_profile.txt").unwrap()),
            receiver: BusReceiver {
                name: "path_profile".to_string(),
                bus_rx,
                checksum: 0,
            },
            path_records: HashMap::new(),
            unwinder,
            current_paths: Vec::new(),
        }
    }

    fn record_branch(&mut self, taken: bool, timestamp: u64) {
        // peek the top of the current paths
        if let Some(path_record) = self.current_paths.last_mut() {
            path_record.path.branches.push(taken);
            path_record.times.push(timestamp);
        }
    }
}

impl AbstractReceiver for PathProfileReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry {
            Entry::Instruction { .. } => {}
            Entry::Event { timestamp, kind } => {
                match kind {
                    EventKind::TakenBranch { .. } => {
                        self.record_branch(true, timestamp);
                    }
                    EventKind::NonTakenBranch { .. } => {
                        self.record_branch(false, timestamp);
                    }
                    _ => {}
                }
                if let Some(update) = self.unwinder.step(&Entry::Event {
                    timestamp,
                    kind: kind.clone(),
                }) {
                    // dump all closed frames' paths
                    for frame in update.frames_closed {
                        let path = self.current_paths.pop().unwrap();
                        // if path record is not empty, write it to the writer
                        if !path.times.is_empty() {
                            self.writer.write_all(format!("pop {:?} @ 0x{:x}\n", frame.symbol.name, frame.addr).as_bytes()).unwrap();
                            self.writer.write_all(format!("times: {:?}\n", path.times).as_bytes()).unwrap();
                            self.writer.write_all(format!("branches: {:?}\n", path.path.branches).as_bytes()).unwrap();
                            self.writer.write_all(format!("--------------------------------\n").as_bytes()).unwrap();
                        }
                    }
                    // push a new path for each opened frame
                    for frame in update.frames_opened {
                        let path = Path {
                            entry_point: frame.addr,
                            branches: Vec::new(),
                        };
                        self.current_paths.push(PathRecord {
                            path,
                            times: Vec::new(),
                        });
                    }
                }
                // otherwise, append the the currently logging path

            }
        }
    }

    fn _flush(&mut self) {
        self.writer.flush().unwrap();
    }
}
