use crate::backend::event::{Entry, EventKind};

pub trait AbstractEmulator: Send + 'static {
    fn push_event(&mut self, entry: Entry);
    fn flush(&mut self);

}

pub trait AbstractEmulatedAnalyzer: Send + 'static {
    fn push_emulated_event(&mut self, event: EmulationResult);
    fn flush(&mut self);
}

// One trace event under two clocks. `ref_ts` is the golden hardware timestamp;
// `emu_ts` is the timestamp the emulated sparse format would attribute to the
// same event. Both are absolute, so consumers can either diff consecutive
// results (error analyzers) or project `emu_ts` into a re-timed Entry stream
// (fan-out to ordinary receivers).
#[derive(Clone)]
pub struct EmulationResult {
    pub ref_ts: u64,
    pub emu_ts: u64,
    pub event: EventKind,
}
/// Integer share of an interval of `slack` cycles for event `j` of `n`, by cumulative
/// rounding: the j-th boundary sits at floor((j+1)·slack/n), so every share is
/// floor(slack/n) or one more, the shares sum to `slack` exactly, and the remainder is
/// spread across the interval instead of landing on one event. Handing the whole remainder
/// to the last event (the previous rule) credited up to n−1 extra cycles to whichever
/// event happened to close an interval -- at a `jr` or at the count limit, i.e. exactly at
/// handler boundaries -- and manufactured latency modes that were not in the data.
pub fn share(slack: u64, n: u64, j: u64) -> u64 {
    let s = slack as u128;
    let hi = (s * (j as u128 + 1) / n as u128) as u64;
    let lo = (s * j as u128 / n as u128) as u64;
    hi - lo
}
