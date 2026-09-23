use crate::backend::event::{Entry, EventKind};
use crate::common::insn_index::InstructionIndex;
use crate::common::prv::Prv;
use crate::receivers::emulation::abstract_emulator::{share, AbstractEmulatedAnalyzer, AbstractEmulator, EmulationResult};
use circular_buffer::CircularBuffer;
use std::sync::Arc;

const STACK_DEPTH: usize = 64;

// Emulates a TNT based encoder, emitting CYC packets
// It never compresses RET packets ever
pub struct TNTCycRETCompressedEmulator {
    event_staging: Vec<(u64, EventKind)>,
    lim_tnt: u64,
    n_tnt: u64,
    curr_cyc: u64,
    emu_clock: u64,
    analyzer: Box<dyn AbstractEmulatedAnalyzer>,
    insn_index: Arc<InstructionIndex>,
    curr_prv: Prv,
    curr_ctx: u64,
    stack: CircularBuffer<STACK_DEPTH, u64>,
    needs_flush: bool,
    num_compressed: u64,
}

impl TNTCycRETCompressedEmulator {
    pub fn new(analyzer: Box<dyn AbstractEmulatedAnalyzer>, lim_tnt: u64, insn_index: Arc<InstructionIndex>) -> Self {
        Self {
            event_staging: Vec::new(),
            analyzer,
            lim_tnt,
            n_tnt: 0,
            curr_cyc: 0,
            emu_clock: 0,
            insn_index,
            curr_prv: Prv::PrvMachine,
            curr_ctx: 0,
            stack: CircularBuffer::<STACK_DEPTH, u64>::new(),
            needs_flush: false,
            num_compressed: 0,
        }
    }
}

impl AbstractEmulator for TNTCycRETCompressedEmulator {
    fn push_event(&mut self, entry: Entry) {
        match entry {
            Entry::Event { timestamp, kind } => {
                match kind {
                    // first, always stage the event
                    EventKind::SyncStart { start_prv, start_ctx, .. } => {
                        self.curr_cyc = timestamp;
                        self.emu_clock = timestamp;
                        self.curr_prv = start_prv;
                        self.curr_ctx = start_ctx;
                        self.analyzer.push_emulated_event(EmulationResult {
                            ref_ts: timestamp,
                            emu_ts: timestamp,
                            event: kind,
                        });
                    }
                    EventKind::TakenBranch { .. } => {
                        self.n_tnt += 1;
                        self.event_staging.push((timestamp, kind.clone()));
                    }
                    EventKind::NonTakenBranch { .. } => {
                        self.n_tnt += 1;
                        self.event_staging.push((timestamp, kind.clone()));
                    }
                    EventKind::InferrableJump { arc } => {
                        let insn_map = self.insn_index.get(self.curr_prv, self.curr_ctx);
                        let insn_len = insn_map.get(&arc.0).map(|insn| insn.len as u64).unwrap_or(4);
                        self.stack.push_back(arc.0 + insn_len);
                        self.event_staging.push((timestamp, kind.clone()));
                    }
                    EventKind::UninferableJump { arc } => {
                        self.event_staging.push((timestamp, kind.clone()));
                        if !self.stack.is_empty() {
                            let curr_top = *self.stack.nth_back(0).unwrap();
                            // if the current top is the same as where we will return to, then we can compress the event
                            if curr_top == arc.1 {
                                self.stack.pop_back();
                                self.n_tnt += 1;
                                self.num_compressed += 1;
                            } else {
                                // inform a flush
                                self.needs_flush = true;
                            }
                        }
                    }
                    EventKind::Trap { prv_arc, ctx, .. } => {
                        self.curr_prv = prv_arc.1;
                        if let Some(c) = ctx {
                            self.curr_ctx = c;
                        }
                        self.event_staging.push((timestamp, kind.clone()));
                        self.needs_flush = true; // unconditionally flush on trap
                    }
                    EventKind::Pause { .. } => {
                        // exact cycle, end of observable stream: flush like a trap
                        self.event_staging.push((timestamp, kind.clone()));
                        self.needs_flush = true;
                    }
                    EventKind::Resume { prv, ctx, .. } => {
                        // a gap re-establishes the time base, like a sync; the
                        // return-address stack is unknowable across it
                        self.event_staging.clear();
                        self.stack.clear();
                        self.n_tnt = 0;
                        self.needs_flush = false;
                        self.curr_cyc = timestamp;
                        self.emu_clock = timestamp;
                        self.curr_prv = prv;
                        self.curr_ctx = ctx;
                        self.analyzer.push_emulated_event(EmulationResult {
                            ref_ts: timestamp,
                            emu_ts: timestamp,
                            event: kind,
                        });
                        return;
                    }
                    _ => {
                        self.event_staging.push((timestamp, kind));
                    }
                }

                // then, detect if we should release the events
                if self.n_tnt >= self.lim_tnt || self.needs_flush
                {
                    // smear the timestamps distributing across all events staged, excluding the current event
                    let slack = timestamp - self.curr_cyc;
                    let num_events = self.event_staging.len() as u64;

                    if num_events > 0 {
                        // cumulative rounding: shares sum to `slack`, none is more than one
                        // cycle from the even split (see `share`)
                        let staged = std::mem::take(&mut self.event_staging);
                        for (j, (event_timestamp, event)) in staged.into_iter().enumerate() {
                            self.emu_clock += share(slack, num_events, j as u64);
                            self.analyzer.push_emulated_event(EmulationResult {
                                ref_ts: event_timestamp,
                                emu_ts: self.emu_clock,
                                event,
                            });
                        }
                        self.n_tnt = 0;
                    }

                    // update the current cycle
                    self.curr_cyc = timestamp;
                    // reset the needs_flush flag
                    self.needs_flush = false;
                }
            }
            _ => {}
        }
    }

    fn flush(&mut self) {
        self.event_staging.clear();
        self.analyzer.flush();
        println!("Number of compressed events: {}", self.num_compressed);
    }
}


