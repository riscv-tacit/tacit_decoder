use crate::frontend::br_mode::*;
use crate::frontend::ctx_mode::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoderRuntimeCfg {
    pub br_mode: BrMode,
    pub bp_entries: u64,
    pub ctx_mode: CtxMode,
    pub ctx_id: u64,
}
