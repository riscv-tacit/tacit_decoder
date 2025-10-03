use crate::frontend::br_mode::*;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecoderRuntimeCfg {
    pub br_mode: BrMode,
    pub bp_entries: u64,
}
