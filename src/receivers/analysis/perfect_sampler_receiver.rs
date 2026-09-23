// Emulates an idealized sampling profiler on top of the decoded trace: a
// periodic sample every `interval` cycles, each capturing the full call stack
// with zero skid, zero overhead, and exact timestamps. Strictly generous
// versus any real sampler. Because events arrive per basic block and the
// stack is constant between events, attributing every sample instant in
// [prev_event_ts, event_ts) to the current stack is exact.
//
// One frequency per run: to emulate a different rate, rerun the decoder with
// a different `interval` (and `path`).
//
// Output: `<path>.samples.csv` (timestamp,stack_id) and `<path>.stacks.csv`
// (stack_id,leaf,folded).
use crate::backend::event::{Entry, EventKind};
use crate::common::prv::Prv;
use crate::common::symbol_index::SymbolIndex;
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use crate::receivers::stack_unwinder::StackUnwinder;
use bus::BusReader;
use log::info;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Arc;

pub struct PerfectSamplerReceiver {
    receiver: BusReceiver,
    unwinder: StackUnwinder,
    interval: u64,
    path: String,
    next_ts: u64,
    synced: bool,
    gap_ticks: u64,
    samples: Vec<(u64, u32)>,
    stack_ids: HashMap<Vec<u64>, u32>,
    stack_leaf: Vec<String>,
    stack_folded: Vec<String>,
}

impl PerfectSamplerReceiver {
    pub fn new(
        bus_rx: BusReader<Entry>,
        symbols: Arc<SymbolIndex>,
        path: String,
        interval: u64,
    ) -> Self {
        let unwinder = StackUnwinder::new(Arc::clone(&symbols)).expect("stack unwinder");
        Self {
            receiver: BusReceiver {
                name: "perfect_sampler".into(),
                bus_rx,
                checksum: 0,
            },
            unwinder,
            interval,
            path,
            next_ts: 0,
            synced: false,
            gap_ticks: 0,
            samples: Vec::new(),
            stack_ids: HashMap::new(),
            stack_leaf: Vec::new(),
            stack_folded: Vec::new(),
        }
    }

    // match the speedscope receiver's privilege prefixes so names join 1:1
    fn frame_name(prv: &Prv, name: &str) -> String {
        match prv {
            Prv::PrvUser => name.to_string(),
            Prv::PrvSupervisor => format!("k:{}", name),
            Prv::PrvMachine => format!("m:{}", name),
            _ => format!("h:{}", name),
        }
    }

    fn take_sample(&mut self, ts: u64) {
        let key: Vec<u64> = if self.unwinder.frame_stack.is_empty() {
            // distinguish empty stacks by privilege level
            vec![u64::MAX - self.unwinder.curr_prv.clone() as u64]
        } else {
            self.unwinder.frame_stack.iter().map(|f| f.addr).collect()
        };
        let id = match self.stack_ids.get(&key) {
            Some(&id) => id,
            None => {
                let id = self.stack_folded.len() as u32;
                let (leaf, folded) = if self.unwinder.frame_stack.is_empty() {
                    let none = format!("[none:{:?}]", self.unwinder.curr_prv);
                    (none.clone(), none)
                } else {
                    let last = self.unwinder.frame_stack.last().unwrap();
                    let leaf = Self::frame_name(&last.prv, &last.symbol.name);
                    let folded = self
                        .unwinder
                        .frame_stack
                        .iter()
                        .map(|f| Self::frame_name(&f.prv, &f.symbol.name))
                        .collect::<Vec<_>>()
                        .join(";");
                    (leaf, folded)
                };
                self.stack_ids.insert(key, id);
                self.stack_leaf.push(leaf);
                self.stack_folded.push(folded);
                id
            }
        };
        self.samples.push((ts, id));
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
        .unwrap_or("trace.samples")
        .to_string();
    let interval = _config
        .get("interval")
        .and_then(|value| value.as_u64())
        .unwrap_or(10_000);
    Box::new(PerfectSamplerReceiver::new(
        bus_rx,
        _shared.symbol_index.clone(),
        path,
        interval,
    ))
}

crate::register_receiver!("perfect_sampler", factory);

impl AbstractReceiver for PerfectSamplerReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum = self.receiver.checksum.wrapping_add(1);
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match &entry {
            Entry::Event { timestamp, kind } => {
                let t = *timestamp;
                if let EventKind::SyncStart { .. } = kind {
                    if !self.synced {
                        self.synced = true;
                        self.next_ts = t + self.interval;
                    }
                }
                // sample all tick instants strictly before this event, using
                // the pre-event stack (the stack is constant between events)
                if self.synced {
                    while self.next_ts < t {
                        let ts = self.next_ts;
                        self.take_sample(ts);
                        self.next_ts += self.interval;
                    }
                }
                match kind {
                    // no samples inside a gap: the stack is unknown there
                    EventKind::SyncEnd { .. } | EventKind::Pause { .. } => {
                        self.synced = false;
                    }
                    EventKind::Resume { .. } => {
                        // skip the ticks that fell in the gap, resume sampling after
                        while self.next_ts < t {
                            self.next_ts += self.interval;
                            self.gap_ticks += 1;
                        }
                        self.synced = true;
                    }
                    _ => {}
                }
                self.unwinder.step(&entry);
            }
        }
    }

    fn _flush(&mut self) {
        let mut sw = BufWriter::new(File::create(format!("{}.samples.csv", self.path)).unwrap());
        writeln!(sw, "timestamp,stack_id").unwrap();
        for (ts, id) in &self.samples {
            writeln!(sw, "{},{}", ts, id).unwrap();
        }
        sw.flush().unwrap();

        let mut kw = BufWriter::new(File::create(format!("{}.stacks.csv", self.path)).unwrap());
        writeln!(kw, "stack_id,leaf,folded").unwrap();
        for (id, (leaf, folded)) in self
            .stack_leaf
            .iter()
            .zip(self.stack_folded.iter())
            .enumerate()
        {
            writeln!(kw, "{},\"{}\",\"{}\"", id, leaf, folded).unwrap();
        }
        kw.flush().unwrap();

        info!(
            "perfect_sampler: interval={} cycles, {} samples, {} unique stacks",
            self.interval,
            self.samples.len(),
            self.stack_folded.len()
        );
        println!(
            "--------------------------------\nPerfect sampler: interval={} cycles, {} samples, {} unique stacks, {} ticks skipped in gaps\n--------------------------------",
            self.interval,
            self.samples.len(),
            self.stack_folded.len(),
            self.gap_ticks
        );
    }
}
