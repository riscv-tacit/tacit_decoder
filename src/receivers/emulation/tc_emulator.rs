use crate::backend::event::{Entry, EventKind};
use crate::receivers::emulation::abstract_emulator::{share, AbstractEmulatedAnalyzer, AbstractEmulator, EmulationResult};

pub struct TCEmulator {
    event_staging: Vec<(u64, EventKind)>,
    analyzer: Box<dyn AbstractEmulatedAnalyzer>,
    curr_tc: u64,
    curr_timestamp: u64,
    emu_clock: u64,
    interval: u64,
}

impl TCEmulator {
    pub fn new(analyzer: Box<dyn AbstractEmulatedAnalyzer>, interval: u64) -> Self {
        Self {
            event_staging: Vec::new(),
            analyzer,
            curr_tc: 0,
            curr_timestamp: 0,
            emu_clock: 0,
            interval,
        }
    }
}

impl AbstractEmulator for TCEmulator {
    fn push_event(&mut self, entry: Entry) {
        match entry {
            Entry::Event { timestamp, kind: kind @ EventKind::SyncStart { .. } } => {
                self.curr_tc = timestamp / self.interval; // initialize the current TC
                self.curr_timestamp = timestamp;
                self.emu_clock = timestamp;
                self.analyzer.push_emulated_event(EmulationResult {
                    ref_ts: timestamp,
                    emu_ts: timestamp,
                    event: kind,
                });
            }
            Entry::Event { timestamp, kind: kind @ EventKind::Resume { .. } } => {
                // events staged before the Pause are released at the TC tick
                // following the Pause (the emulated encoder would have flushed
                // them there), then the gap re-establishes the time base
                if !self.event_staging.is_empty() {
                    let pause_ts = self.event_staging.last().unwrap().0;
                    self.release_staged(pause_ts / self.interval + 1);
                }
                self.curr_tc = timestamp / self.interval;
                self.curr_timestamp = timestamp;
                self.emu_clock = timestamp;
                self.analyzer.push_emulated_event(EmulationResult {
                    ref_ts: timestamp,
                    emu_ts: timestamp,
                    event: kind,
                });
            }
            Entry::Event { timestamp, kind } => {
                if timestamp / self.interval != self.curr_tc && !self.event_staging.is_empty() {
                    self.release_staged(timestamp / self.interval);
                }
                self.event_staging.push((timestamp, kind.clone()));
            }
            _ => {}
        }
    }

    fn flush(&mut self) {
        self.event_staging.clear();
        self.analyzer.flush();
    }
}

impl TCEmulator {
    /// Smear the staged events' emulated timestamps evenly up to TC `next_tc`.
    fn release_staged(&mut self, next_tc: u64) {
        let slack = next_tc.saturating_sub(self.curr_tc) * self.interval;
        let num_events = self.event_staging.len() as u64;
        self.curr_tc = next_tc;
        if num_events == 0 {
            return;
        }
        // cumulative rounding: shares sum to `slack`, none is more than one cycle from the
        // even split (see `share`)
        let staged = std::mem::take(&mut self.event_staging);
        let last_event_timestamp = staged.last().map(|(t, _)| *t).unwrap_or(self.curr_timestamp);
        for (j, (event_timestamp, event)) in staged.into_iter().enumerate() {
            self.emu_clock += share(slack, num_events, j as u64);
            self.analyzer.push_emulated_event(EmulationResult {
                ref_ts: event_timestamp,
                emu_ts: self.emu_clock,
                event,
            });
        }
        self.curr_timestamp = last_event_timestamp;
    }
}