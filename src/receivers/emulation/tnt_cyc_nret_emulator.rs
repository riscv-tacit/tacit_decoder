use crate::backend::event::{Entry, EventKind};
use crate::receivers::emulation::abstract_emulator::{share, AbstractEmulatedAnalyzer, AbstractEmulator, EmulationResult};

// Emulates a TNT based encoder, emitting CYC packets
// It never compresses RET packets ever
pub struct TNTCycNRETEmulator {
    event_staging: Vec<(u64, EventKind)>,
    lim_tnt: u64,
    n_tnt: u64,
    curr_cyc: u64,
    emu_clock: u64,
    analyzer: Box<dyn AbstractEmulatedAnalyzer>,
}

impl TNTCycNRETEmulator {
    pub fn new(analyzer: Box<dyn AbstractEmulatedAnalyzer>, lim_tnt: u64) -> Self {
        Self {
            event_staging: Vec::new(),
            analyzer,
            lim_tnt: lim_tnt,
            n_tnt: 0,
            curr_cyc: 0,
            emu_clock: 0,
        }
    }
}

impl AbstractEmulator for TNTCycNRETEmulator {
    fn push_event(&mut self, entry: Entry) {
        match entry {
            Entry::Event { timestamp, kind } => {
                match kind {
                    // first, always stage the event
                    EventKind::SyncStart { .. } => {
                        self.curr_cyc = timestamp;
                        self.emu_clock = timestamp;
                        self.analyzer.push_emulated_event(EmulationResult {
                            ref_ts: timestamp,
                            emu_ts: timestamp,
                            event: kind.clone(),
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
                    EventKind::Resume { .. } => {
                        // a gap re-establishes the time base, like a sync
                        self.event_staging.clear();
                        self.n_tnt = 0;
                        self.curr_cyc = timestamp;
                        self.emu_clock = timestamp;
                        self.analyzer.push_emulated_event(EmulationResult {
                            ref_ts: timestamp,
                            emu_ts: timestamp,
                            event: kind.clone(),
                        });
                        return;
                    }
                    _ => {
                        self.event_staging.push((timestamp, kind.clone()));
                    }
                }

                // then, detect if we should release the events
                // (a Pause carries an exact cycle and ends the observable stream, so it flushes like a trap)
                if self.n_tnt >= self.lim_tnt
                    || matches!(&kind, EventKind::UninferableJump { .. })
                    || matches!(&kind, EventKind::Trap { .. })
                    || matches!(&kind, EventKind::Pause { .. })
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
                }
            }
            _ => {}
        }
    }

    fn flush(&mut self) {
        self.event_staging.clear();
        self.analyzer.flush();
    }
}
