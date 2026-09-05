use crate::common::symbol_index::SymbolIndex;
use crate::receivers::emulation::abstract_emulator::{AbstractEmulatedAnalyzer, EmulationResult};
use crate::receivers::oracle_func::FuncSink;
use crate::receivers::oracle_match::OracleMatcher;
use std::sync::Arc;

/* Function-level epsilon for an emulated sparse format against the oracle.
 * Every emulator re-times events without dropping or reordering them, so the
 * unwinder -- driven by control flow alone -- produces frames identical to
 * TACIT's, and every format shares one denominator.
 *
 * Config, inside an emulation spec:
 *   "error": {"oracle_func": {"path": "...csv.zst", "asids": [125]}}
 */
pub struct OracleFuncAnalyzer {
    matcher: OracleMatcher<FuncSink>,
}

impl OracleFuncAnalyzer {
    pub fn new(name: String, cfg: &serde_json::Value, symbols: Arc<SymbolIndex>) -> Self {
        let sink = FuncSink::new(cfg, symbols);
        Self {
            matcher: OracleMatcher::from_config(format!("oracle_func/{}", name), cfg, sink),
        }
    }
}

impl AbstractEmulatedAnalyzer for OracleFuncAnalyzer {
    fn push_emulated_event(&mut self, event: EmulationResult) {
        self.matcher.push(event.emu_ts, &event.event);
    }
    fn flush(&mut self) {
        self.matcher.finish();
    }
}
