use crate::backend::abstract_receiver::{AbstractReceiver, BusReceiver};
use crate::backend::event::{Entry, EventKind};
use crate::backend::stack_unwinder::StackUnwinder;
use crate::common::symbol_index::SymbolIndex;
use bus::BusReader;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Arc;

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Path {
    entry_point: u64,
    name: String,
    branches: Vec<bool>,
}

impl Path {
    pub fn to_string(&self) -> String {
        // convert branches to a string of 0s and 1s
        let branches_str = self
            .branches
            .iter()
            .map(|b| if *b { "1" } else { "0" })
            .collect::<Vec<_>>()
            .join("");
        format!("{}-0x{:x}-{}", self.name, self.entry_point, branches_str)
    }
}

pub struct PathProfileReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    path_records: HashMap<Path, Vec<u64>>,
    unwinder: StackUnwinder,
    current_path: Option<Path>,
    current_start_time: u64,
}

impl PathProfileReceiver {
    pub fn new(
        bus_rx: BusReader<Entry>,
        symbols: Arc<SymbolIndex>,
    ) -> Self {
        let unwinder =
            StackUnwinder::new(Arc::clone(&symbols)).expect("stack unwinder");
        Self {
            writer: BufWriter::new(File::create("trace.path_profile.csv").unwrap()),
            receiver: BusReceiver {
                name: "path_profile".to_string(),
                bus_rx,
                checksum: 0,
            },
            path_records: HashMap::new(),
            unwinder,
            current_path: None,
            current_start_time: 0,
        }
    }

    fn record_branch(&mut self, taken: bool) {
        // peek the top of the current paths
        if let Some(ref mut path) = self.current_path {
            path.branches.push(taken);
        }
    }

    fn dump_current_path(&mut self, end_timestamp: u64) {
        if let Some(path) = self.current_path.take() {
            // insert a record for this path
            let duration = end_timestamp - self.current_start_time;
            if let Some(records) = self.path_records.get_mut(&path) {
                records.push(duration);
            } else {
                self.path_records.insert(path, vec![duration]);
            }
        }
        self.current_path = None;
        self.current_start_time = 0;
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
                        self.record_branch(true);
                    }
                    EventKind::NonTakenBranch { .. } => {
                        self.record_branch(false);
                    }
                    _ => {}
                }
                if let Some(update) = self.unwinder.step(&Entry::Event {
                    timestamp,
                    kind: kind,
                }) {
                    // dump all closed frames' paths
                    if !update.frames_closed.is_empty() {
                        self.dump_current_path(timestamp);
                        // peek the top of the current stack to create a new path
                        if !self.unwinder.frame_stack.is_empty() {
                            let frame = self.unwinder.peek_head_frames();
                            let path = Path {
                                name: frame.symbol.name.clone() + "-dirty",
                                entry_point: frame.addr,
                                branches: Vec::new(),
                            };
                            self.current_path = Some(path);
                            self.current_start_time = timestamp;
                        }
                    } else if let Some(frame) = update.frames_opened {
                        let path = Path {
                            name: frame.symbol.name.clone(),
                            entry_point: frame.addr,
                            branches: Vec::new(),
                        };
                        self.current_path = Some(path);
                        self.current_start_time = timestamp;
                    }
                }
            }
        }
    }

    fn _flush(&mut self) {
        // path net variation time(i)= total path execution time(i)–(path frequency(i) x (path basetime(i)))
        self.writer.write_all(format!("count,mean,netvar,path\n").as_bytes()).unwrap();
        for (path, records) in self.path_records.iter() {
            // compute mean and standard deviation
            let mean = records.iter().sum::<u64>() as f64 / records.len() as f64;
            let min = records.iter().min().unwrap();
            let net_var = records.iter().sum::<u64>() as f64 - (records.len() as f64 * *min as f64);
            self.writer
                .write_all(format!("{}, {}, {}, {}\n", records.len(), mean, net_var, path.to_string()).as_bytes())
                .unwrap();
        }
        self.writer.flush().unwrap();
    }
}
