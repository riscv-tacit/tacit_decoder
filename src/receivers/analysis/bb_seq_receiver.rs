use crate::backend::event::{Entry, EventKind};
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};

use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};

/* Basic-block sequence dump: one row per control-flow event, i.e. per basic block
   executed, for the first `limit` events. Each event closes the block that started at
   the previous event's target:

       timestamp, bb_start, bb_end, kind

   where bb_end is the PC of the branch/jump that ended the block (the arc source) and
   kind is jr / br / nt / jal. Consecutive rows are consecutive blocks, so any per-instance
   question -- "which block of this handler execution took the cycles, given what ran
   before and after it" -- can be answered offline without another receiver. Syncs, traps
   and resumes write a row with kind = sync / trap / resume and no bb_end, so a consumer
   can drop intervals that span them. */
pub struct BBSeqReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    limit: u64,
    written: u64,
    prev_addr: u64,
}

impl BBSeqReceiver {
    pub fn new(bus_rx: BusReader<Entry>, path: String, limit: u64) -> Self {
        let mut writer = BufWriter::new(File::create(path).unwrap());
        writer.write_all(b"timestamp,bb_start,bb_end,kind\n").unwrap();
        Self {
            writer,
            receiver: BusReceiver { name: "bb_seq".to_string(), bus_rx, checksum: 0 },
            limit,
            written: 0,
            prev_addr: 0,
        }
    }

    fn row(&mut self, timestamp: u64, from: Option<u64>, to: u64, kind: &str) {
        if self.written < self.limit {
            let end = from.map(|f| format!("{:#x}", f)).unwrap_or_default();
            self.writer
                .write_all(format!("{},{:#x},{},{}\n", timestamp, self.prev_addr, end, kind).as_bytes())
                .unwrap();
            self.written += 1;
        }
        self.prev_addr = to;
    }
}

pub fn factory(
    _shared: &Shared,
    config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let path = config
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("trace.bb_seq.csv")
        .to_string();
    let limit = config.get("limit").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
    Box::new(BBSeqReceiver::new(bus_rx, path, limit))
}

crate::register_receiver!("bb_seq", factory);

impl AbstractReceiver for BBSeqReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry {
            Entry::Event { timestamp, kind: EventKind::SyncStart { start_pc, .. } } => {
                self.row(timestamp, None, start_pc, "sync")
            }
            Entry::Event { timestamp, kind: EventKind::InferrableJump { arc } } => {
                self.row(timestamp, Some(arc.0), arc.1, "jal")
            }
            Entry::Event { timestamp, kind: EventKind::UninferableJump { arc } } => {
                self.row(timestamp, Some(arc.0), arc.1, "jr")
            }
            Entry::Event { timestamp, kind: EventKind::TakenBranch { arc } } => {
                self.row(timestamp, Some(arc.0), arc.1, "br")
            }
            Entry::Event { timestamp, kind: EventKind::NonTakenBranch { arc } } => {
                self.row(timestamp, Some(arc.0), arc.1, "nt")
            }
            Entry::Event { timestamp, kind: EventKind::Trap { arc, .. } } => {
                self.row(timestamp, Some(arc.0), arc.1, "trap")
            }
            Entry::Event { timestamp, kind: EventKind::Resume { pc, .. } } => {
                self.row(timestamp, None, pc, "resume")
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        self.writer.flush().unwrap();
    }
}
