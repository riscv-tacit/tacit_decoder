use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use crate::backend::event::Entry;
use crate::receivers::stack_unwinder::{StackUnwinder, StackUpdateResult};
use crate::common::symbol_index::SymbolIndex;
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Arc;

pub struct StackTxtReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    unwinder: StackUnwinder,
}

impl StackTxtReceiver {
    pub fn new(
        bus_rx: BusReader<Entry>,
        symbols: Arc<SymbolIndex>,
        path: String,
    ) -> Self {
        let unwinder = StackUnwinder::new(symbols).expect("init unwinder");
        Self {
            writer: BufWriter::new(File::create(path).unwrap()),
            receiver: BusReceiver {
                name: "stacktxt".into(),
                bus_rx,
                checksum: 0,
            },
            unwinder,
        }
    }
}

pub fn factory(
    _shared: &Shared,
    _config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let path = _config.get("path").and_then(|value| value.as_str()).unwrap_or("trace.stack.txt").to_string();
    Box::new(StackTxtReceiver::new(bus_rx, Arc::clone(&_shared.symbol_index), path))
}
crate::register_receiver!("stack_txt", factory);

impl StackTxtReceiver {
    fn dump_current_stack(&mut self) -> std::io::Result<()> {
        let all_frames = self.unwinder.peek_all_frames();
        let size = all_frames.len();
        writeln!(self.writer, "  Stack (size: {})", size)?;
        for frame in all_frames {
            writeln!(
                self.writer,
                "    {:?} :: {} @ {:?}",
                frame.symbol.prv, frame.symbol.name, frame.symbol.src
            )?;
        }
        writeln!(self.writer)?;
        Ok(())
    }

    fn handle_stack_update(&mut self, ts: u64, update: StackUpdateResult) {
        for frame in update.frames_closed {
            writeln!(
                self.writer,
                "[ts {ts}] pop {:?} :: {} @ 0x{:x}",
                frame.symbol.prv, frame.symbol.name, frame.addr
            )
            .unwrap();
        }

        if let Some(frame) = update.frames_opened {
            writeln!(
                self.writer,
                "[ts {ts}] push {:?} :: {} @ 0x{:x}",
                frame.symbol.prv, frame.symbol.name, frame.addr
            )
            .unwrap();
        }

        self.dump_current_stack().unwrap();
    }
}

impl AbstractReceiver for StackTxtReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry {
            Entry::Instruction { insn: _, pc: _ } => {}
            Entry::Event { timestamp, kind } => {
                // log the event
                writeln!(self.writer, "[ts {timestamp}] {:?}", kind).unwrap();
                if let Some(update) = self.unwinder.step(&Entry::Event { timestamp, kind }) {
                    self.handle_stack_update(timestamp, update);
                }
            }
        }
    }

    fn _flush(&mut self) {
        self.writer.flush().unwrap();
    }
}
