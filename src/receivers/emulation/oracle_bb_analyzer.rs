use crate::receivers::oracle_epsilon::OracleEpsilon;
use crate::receivers::emulation::abstract_emulator::{AbstractEmulatedAnalyzer, EmulationResult};

/* eps(BB) for an emulated sparse format against the TraceDoctor oracle.
 *
 * Unlike BBAnalyzer -- which scores the emulated clock against TACIT's own
 * timestamps -- this scores it against the oracle's attributed cycles, the
 * same reference the decoded TACIT stream is measured on. Since every
 * emulator re-times events without dropping or reordering them, the arc
 * targets driving the pairing are identical across formats, so each analyzer
 * locks onto the same oracle rows and every format's epsilon shares one
 * denominator.
 *
 * Config, inside an emulation spec:
 *   "error": {"oracle_bb": {"path": "...csv.zst", "asids": [125]}}
 */

pub struct OracleBBAnalyzer {
    eps: OracleEpsilon,
}

impl OracleBBAnalyzer {
    pub fn new(name: String, cfg: &serde_json::Value) -> Self {
        Self {
            eps: OracleEpsilon::from_config(format!("oracle_bb/{}", name), cfg),
        }
    }
}

impl AbstractEmulatedAnalyzer for OracleBBAnalyzer {
    fn push_emulated_event(&mut self, event: EmulationResult) {
        self.eps.push(event.emu_ts, &event.event);
    }

    fn flush(&mut self) {
        self.eps.finish();
    }
}
