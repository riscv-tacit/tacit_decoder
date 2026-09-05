use crate::backend::event::EventKind;
use crate::receivers::oracle_match::{MatchStats, OracleMatcher, PairSink};

/* BB-level timing error against the TraceDoctor oracle:
 *
 *     eps(BB) = sum_i |t_i - that_i| / sum_i t_i
 *
 * over the dynamic basic-block instances the matcher pairs up. See
 * oracle_match.rs for the pairing rules, the resync, and why every estimator
 * locks onto the same oracle rows. This file is only the accounting.
 *
 * Arithmetic stays in twelfths, so the sub-cycle split is |d_x12| < 12 with no
 * float anywhere. Against the `boundary` oracle every value is a whole cycle
 * by construction, so that bucket is always empty there; it earns its keep
 * only against the default 1/n-split capture.
 */
pub struct BBSink {
    num: u128,
    den: u128,
    num_q: u128,
    num_s: u128,
    num_ref: u128,
    cq: u64,
    cs: u64,
    cs_ref: u64,
    ref_pairs: u64,
}

impl BBSink {
    pub fn new() -> Self {
        Self {
            num: 0,
            den: 0,
            num_q: 0,
            num_s: 0,
            num_ref: 0,
            cq: 0,
            cs: 0,
            cs_ref: 0,
            ref_pairs: 0,
        }
    }
}

impl PairSink for BBSink {
    fn on_pair(
        &mut self,
        t_x12: u64,
        that_x12: u64,
        ref_delta_x12: Option<u64>,
        _kind: &EventKind,
    ) {
        let d = t_x12.abs_diff(that_x12);
        self.num += d as u128;
        self.den += t_x12 as u128;
        if d >= 12 {
            self.num_s += d as u128;
            self.cs += 1;
        } else if d > 0 {
            self.num_q += d as u128;
            self.cq += 1;
        }
        if let Some(rd) = ref_delta_x12 {
            let dr = t_x12.abs_diff(rd);
            self.num_ref += dr as u128;
            self.ref_pairs += 1;
            if dr >= 12 {
                self.cs_ref += 1;
            }
        }
    }

    fn finish(&mut self, label: &str, _stats: &MatchStats) {
        if self.den == 0 {
            println!("{}: no comparable pairs", label);
            return;
        }
        let den = self.den as f64;
        println!(
            "{}: epsilon(BB) = {:.2}%   (sum|d| {} / sum t {}, twelfths)",
            label,
            100.0 * self.num as f64 / den,
            self.num,
            self.den
        );
        println!(
            "{}:   quantization (|d|<1): {:.2}%  ({} instances)",
            label,
            100.0 * self.num_q as f64 / den,
            self.cq
        );
        println!(
            "{}:   semantic (|d|>=1):    {:.2}%  ({} instances)",
            label,
            100.0 * self.num_s as f64 / den,
            self.cs
        );
        if self.ref_pairs > 0 {
            println!(
                "{}: reference floor      = {:.2}%   (same {} matched \
instances, oracle exit deltas; {} with |d|>=1)",
                label,
                100.0 * self.num_ref as f64 / den,
                self.ref_pairs,
                self.cs_ref
            );
        }
    }
}

/// Thin facade so the receiver and emulation wrappers keep their existing API.
pub struct OracleEpsilon {
    matcher: OracleMatcher<BBSink>,
}

impl OracleEpsilon {
    pub fn from_config(label: String, cfg: &serde_json::Value) -> Self {
        Self {
            matcher: OracleMatcher::from_config(label, cfg, BBSink::new()),
        }
    }

    pub fn push(&mut self, timestamp: u64, kind: &EventKind) {
        self.matcher.push(timestamp, kind);
    }

    pub fn finish(&mut self) {
        self.matcher.finish();
    }
}
