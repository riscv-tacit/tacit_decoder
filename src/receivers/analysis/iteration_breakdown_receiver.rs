use crate::backend::event::{Entry, EventKind};
use crate::common::prv::Prv;
use crate::common::symbol_index::SymbolIndex;
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use crate::receivers::stack_unwinder::StackUnwinder;
use bus::BusReader;
use log::warn;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Arc;

struct IterationState {
    start_ts: u64,
    user_cycles: u64,
    supervisor_cycles: u64,
    machine_cycles: u64,
    tracked_func_count: u64,
    tracked_func_cycles: u64,
}

pub struct IterationBreakdownReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    unwinder: StackUnwinder,
    marker_func: String,
    tracked_func: String,
    marker_exit_count: usize,
    in_iteration: bool,
    in_tracked_func: bool,
    tracked_func_entry_ts: u64,
    current_iter: Option<IterationState>,
    completed_iters: Vec<(IterationState, u64)>, // (state, end_ts)
    curr_prv: Prv,
    prev_timestamp: u64,
}

impl IterationBreakdownReceiver {
    pub fn new(
        bus_rx: BusReader<Entry>,
        symbol_index: Arc<SymbolIndex>,
        marker_func: String,
        tracked_func: String,
        csv_path: String,
    ) -> Self {
        Self {
            writer: BufWriter::new(File::create(&csv_path).unwrap()),
            receiver: BusReceiver {
                name: "iteration_breakdown".to_string(),
                bus_rx,
                checksum: 0,
            },
            unwinder: StackUnwinder::new(symbol_index).unwrap(),
            marker_func,
            tracked_func,
            marker_exit_count: 0,
            in_iteration: false,
            in_tracked_func: false,
            tracked_func_entry_ts: 0,
            current_iter: None,
            completed_iters: Vec::new(),
            curr_prv: Prv::PrvMachine,
            prev_timestamp: 0,
        }
    }

    fn update_prv_cycles(&mut self, timestamp: u64) {
        if !self.in_iteration {
            return;
        }
        if let Some(ref mut iter_state) = self.current_iter {
            let delta = timestamp.saturating_sub(self.prev_timestamp);
            match self.curr_prv {
                Prv::PrvUser => iter_state.user_cycles += delta,
                Prv::PrvSupervisor => iter_state.supervisor_cycles += delta,
                Prv::PrvMachine => iter_state.machine_cycles += delta,
                _ => {}
            }
        }
    }

    fn start_iteration(&mut self, timestamp: u64) {
        self.in_iteration = true;
        self.current_iter = Some(IterationState {
            start_ts: timestamp,
            user_cycles: 0,
            supervisor_cycles: 0,
            machine_cycles: 0,
            tracked_func_count: 0,
            tracked_func_cycles: 0,
        });
    }

    fn end_iteration(&mut self, timestamp: u64) {
        if let Some(iter_state) = self.current_iter.take() {
            self.completed_iters.push((iter_state, timestamp));
        }
        self.in_iteration = false;
    }
}

pub fn factory(
    shared: &Shared,
    config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let marker_func = config
        .get("marker_func")
        .and_then(|v| v.as_str())
        .unwrap_or("syscall")
        .to_string();
    let tracked_func = config
        .get("tracked_func")
        .and_then(|v| v.as_str())
        .unwrap_or("run_ksoftirqd")
        .to_string();
    let csv_path = config
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("trace.iteration_breakdown.csv")
        .to_string();
    Box::new(IterationBreakdownReceiver::new(
        bus_rx,
        shared.symbol_index.clone(),
        marker_func,
        tracked_func,
        csv_path,
    ))
}

crate::register_receiver!("iteration_breakdown", factory);

impl AbstractReceiver for IterationBreakdownReceiver {
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
                ref kind,
            } => {
                // 1. Feed to stack unwinder
                let update = self.unwinder.step(&entry);

                // Frames closed by a Pause are not real exits and the frame
                // opened by a Resume is not a real entry: skip marker/tracked
                // logic for gap events. A tracked-function invocation cut by a
                // gap is dropped rather than counted with a bogus duration.
                let is_gap_event = matches!(kind, EventKind::Pause { .. } | EventKind::Resume { .. });
                if is_gap_event {
                    self.in_tracked_func = false;
                }

                // 2. Check for marker function exit
                if let (Some(ref upd), false) = (&update, is_gap_event) {
                    for frame in &upd.frames_closed {
                        if frame.symbol.name == self.marker_func {
                            // Account cycles up to this point before changing iteration state
                            self.update_prv_cycles(timestamp);
                            self.prev_timestamp = timestamp;

                            self.marker_exit_count += 1;
                            if self.marker_exit_count % 2 == 1 {
                                // Odd exit = iteration start
                                self.start_iteration(timestamp);
                            } else {
                                // Even exit = iteration end
                                self.end_iteration(timestamp);
                            }
                            // Only handle one marker per event
                            break;
                        }
                    }
                }

                // 3. Track target function entry/exit
                if self.in_iteration && !is_gap_event {
                    if let Some(ref upd) = update {
                        if let Some(ref frame) = upd.frames_opened {
                            if frame.symbol.name == self.tracked_func {
                                self.in_tracked_func = true;
                                self.tracked_func_entry_ts = timestamp;
                            }
                        }
                        for frame in &upd.frames_closed {
                            if frame.symbol.name == self.tracked_func && self.in_tracked_func {
                                self.in_tracked_func = false;
                                let cycles = timestamp.saturating_sub(self.tracked_func_entry_ts);
                                if let Some(ref mut iter_state) = self.current_iter {
                                    iter_state.tracked_func_count += 1;
                                    iter_state.tracked_func_cycles += cycles;
                                }
                            }
                        }
                    }
                }

                // 4. Privilege-level cycle accounting
                match kind {
                    EventKind::SyncStart {
                        start_prv,
                        start_ctx: _,
                        ..
                    } => {
                        self.curr_prv = start_prv.clone();
                        self.prev_timestamp = timestamp;
                    }
                    EventKind::Trap { prv_arc, .. } => {
                        self.update_prv_cycles(timestamp);
                        self.curr_prv = prv_arc.1;
                        self.prev_timestamp = timestamp;
                    }
                    EventKind::Resume { prv, .. } => {
                        // gap cycles are attributed to nothing
                        self.curr_prv = prv.clone();
                        self.prev_timestamp = timestamp;
                    }
                    _ => {
                        self.update_prv_cycles(timestamp);
                        self.prev_timestamp = timestamp;
                    }
                }
            }
        }
    }

    fn _flush(&mut self) {
        if self.marker_exit_count == 0 {
            warn!(
                "iteration_breakdown: no exits of marker function '{}' detected",
                self.marker_func
            );
        }
        if self.in_iteration {
            warn!("iteration_breakdown: discarding incomplete iteration (odd number of marker exits: {})", self.marker_exit_count);
        }

        // Write CSV
        writeln!(
            self.writer,
            "iter,total_cycles,user_cycles,supervisor_cycles,machine_cycles,{}_count,{}_cycles,{}_avg_cycles",
            self.tracked_func, self.tracked_func, self.tracked_func
        )
        .unwrap();
        for (i, (state, end_ts)) in self.completed_iters.iter().enumerate() {
            let total_cycles = end_ts - state.start_ts;
            let avg_cycles = if state.tracked_func_count > 0 {
                state.tracked_func_cycles as f64 / state.tracked_func_count as f64
            } else {
                0.0
            };
            writeln!(
                self.writer,
                "{},{},{},{},{},{},{},{:.0}",
                i,
                total_cycles,
                state.user_cycles,
                state.supervisor_cycles,
                state.machine_cycles,
                state.tracked_func_count,
                state.tracked_func_cycles,
                avg_cycles
            )
            .unwrap();
        }
        self.writer.flush().unwrap();

        println!("--------------------------------");
        println!(
            "Iteration breakdown: {} iterations completed",
            self.completed_iters.len()
        );
        if !self.completed_iters.is_empty() {
            let totals: Vec<u64> = self
                .completed_iters
                .iter()
                .map(|(s, e)| e - s.start_ts)
                .collect();
            let min = totals.iter().min().unwrap();
            let max = totals.iter().max().unwrap();
            let sum: u64 = totals.iter().sum();
            let mean = sum as f64 / totals.len() as f64;
            println!(
                "  Total cycles: min={}, max={}, mean={:.0}",
                min, max, mean
            );
        }
        println!("--------------------------------");
    }
}
