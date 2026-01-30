use crate::backend::event::Entry;
use crate::common::insn_index::{build_instruction_index, InstructionIndex};
use crate::common::static_cfg::DecoderStaticCfg;
use crate::common::symbol_index::{build_symbol_index, SymbolIndex};
use crate::frontend::runtime_cfg::DecoderRuntimeCfg;
use anyhow::Result;
use bus::BusReader;
use std::sync::Arc;
use std::thread;

pub struct BusReceiver {
    pub name: String, // name of the type of receiver
    pub bus_rx: BusReader<Entry>,
    pub checksum: usize,
}

pub trait AbstractReceiver: Send + 'static {
    fn bus_rx(&mut self) -> &mut BusReader<Entry>;
    fn try_receive_loop(&mut self) {
        loop {
            match self.bus_rx().try_recv() {
                Ok(entry) => {
                    self._receive_entry(entry);
                    self._bump_checksum();
                }
                // if the bus is disconnected, we're done!
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self._flush();
                    return;
                }
                // if the bus is empty, yield until later
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    thread::yield_now();
                }
            }
        }
    }
    // unused
    fn _bump_checksum(&mut self);
    // step through the trace
    fn _receive_entry(&mut self, entry: Entry);
    // any final actions
    fn _flush(&mut self);
}

pub struct Shared {
    pub static_cfg: DecoderStaticCfg,
    pub runtime_cfg: DecoderRuntimeCfg,
    pub symbol_index: Arc<SymbolIndex>,
    pub insn_index: Arc<InstructionIndex>,
}

impl Shared {
    pub fn new(static_cfg: &DecoderStaticCfg, runtime_cfg: &DecoderRuntimeCfg) -> Result<Self> {
        Ok(Self {
            static_cfg: static_cfg.clone(),
            runtime_cfg: runtime_cfg.clone(),
            symbol_index: Arc::new(build_symbol_index(static_cfg.clone())?),
            insn_index: Arc::new(build_instruction_index(static_cfg.clone())?),
        })
    }
}