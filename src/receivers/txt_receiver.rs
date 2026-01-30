use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use crate::backend::event::{Entry, EventKind};
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};

pub struct TxtReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
}

/* Receiver for dumping the trace to a text file */
impl TxtReceiver {
    pub fn new(bus_rx: BusReader<Entry>, path: String) -> Self {
        Self {
            writer: BufWriter::new(File::create(path).unwrap()),
            receiver: BusReceiver {
                name: "txt".to_string(),
                bus_rx: bus_rx,
                checksum: 0,
            },
        }
    }
}

pub fn factory(
    _shared: &Shared,
    _config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let path = _config.get("path").and_then(|value| value.as_str()).unwrap_or("trace.txt").to_string();
    Box::new(TxtReceiver::new(bus_rx, path))
}

crate::register_receiver!("txt", factory);

impl AbstractReceiver for TxtReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry {
            Entry::Instruction { insn, pc } => {
                self.writer
                    .write_all(format!("{:#x}:", pc).as_bytes())
                    .unwrap();
                self.writer
                    .write_all(format!(" {}", insn.to_string()).as_bytes())
                    .unwrap();
                self.writer.write_all(b"\n").unwrap();
            }
            Entry::Event {
                timestamp: _,
                kind: EventKind::BPHit { hit_count },
            } => {
                self.writer
                    .write_all(format!("[hit count: {}]", hit_count).as_bytes())
                    .unwrap();
                self.writer.write_all(b" BPHit\n").unwrap();
            }
            Entry::Event { timestamp, kind } => {
                self.writer
                    .write_all(format!("[timestamp: {}]", timestamp).as_bytes())
                    .unwrap();
                // write the event
                self.writer
                    .write_all(format!(" {}", kind).as_bytes())
                    .unwrap();
                self.writer.write_all(b"\n").unwrap();
            }
        }
    }

    fn _flush(&mut self) {
        self.writer.flush().unwrap();
    }
}
