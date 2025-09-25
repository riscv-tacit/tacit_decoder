use anyhow::Result;
use std::sync::Arc;

use crate::backend::event::{Entry, EventKind};
use crate::common::insn_index::InstructionIndex;
use crate::common::prv::Prv;
use crate::common::symbol_index::{SymbolIndex, SymbolInfo};

#[derive(Clone)]
pub struct Frame {
    pub prv: Prv,
    pub symbol: SymbolInfo,
    pub addr: u64,
}

pub struct StackUnwinder {
    // addr -> symbol info <name, index, line, file>
    pub func_symbol_map: Arc<SymbolIndex>,
    // addr -> insn
    pub insn_map: Arc<InstructionIndex>,
    // stack model
    pub frame_stack: Vec<Frame>,
    // current privilege level
    pub curr_prv: Prv,
}

pub struct StackUpdateResult {
    pub frame_stack_size: usize,
    pub frames_opened: Vec<Frame>,
    pub frames_closed: Vec<Frame>,
}

impl StackUnwinder {
    pub fn new(
        func_symbol_map: Arc<SymbolIndex>,
        insn_index: Arc<InstructionIndex>,
    ) -> Result<Self> {
        Ok(Self {
            func_symbol_map: func_symbol_map,
            insn_map: insn_index,
            frame_stack: Vec::new(),
            curr_prv: Prv::PrvMachine,
        })
    }

    fn push_frame(&mut self, prv: Prv, addr: u64) -> Option<Frame> {
        let symbol = self.func_symbol_map.get(prv).get(&addr).cloned()?;
        let frame = Frame { prv, symbol, addr };
        self.frame_stack.push(frame.clone());
        Some(frame)
    }

    fn pop_frame(&mut self) -> Option<Frame> {
        self.frame_stack.pop().map(|frame| frame)
    }

    pub fn step(&mut self, entry: &Entry) -> Option<StackUpdateResult> {
        let Entry::Event { kind, .. } = entry else {
            return None;
        };
        match kind {
            EventKind::SyncStart {
                runtime_cfg: _,
                start_pc: _,
                start_prv,
            } => self.step_sync_start(start_prv),
            EventKind::InferrableJump { arc } => self.step_ij(arc.1),
            EventKind::UninferableJump { arc } => self.step_uj(arc.1),
            _ => return None,
        }
    }

    pub fn step_sync_start(&mut self, start_prv: &Prv) -> Option<StackUpdateResult> {
        self.curr_prv = start_prv.clone();
        None
    }

    pub fn step_ij(&mut self, to_addr: u64) -> Option<StackUpdateResult> {
        let frame = self.push_frame(self.curr_prv, to_addr);
        if let Some(frame) = frame {
            return Some(StackUpdateResult {
                frame_stack_size: self.frame_stack.len(),
                frames_opened: vec![frame],
                frames_closed: Vec::new(),
            });
        } else {
            return None;
        }
    }

    pub fn step_uj(&mut self, to_addr: u64) -> Option<StackUpdateResult> {
        let target = to_addr;
        // If we see an indirect call, push the new function
        let is_call = self
            .func_symbol_map
            .get(self.curr_prv)
            .contains_key(&target);
        if is_call {
            let frame: Frame = Frame {
                prv: self.curr_prv,
                symbol: self.func_symbol_map.get(self.curr_prv)[&target].clone(),
                addr: target,
            };
            self.frame_stack.push(frame.clone());
            return Some(StackUpdateResult {
                frame_stack_size: self.frame_stack.len(),
                frames_opened: vec![frame],
                frames_closed: Vec::new(),
            });
        }

        // Otherwise, if it's an indirect jump and we still have frames,
        //    treat it like a return within the unwinding loop.
        let mut closed: Vec<Frame> = Vec::new();
        loop {
            let frame = self.pop_frame();
            if let Some(frame) = frame {
                closed.push(frame.clone());
                let (start, end) = self
                    .func_symbol_map
                    .range(self.curr_prv, frame.addr)
                    .expect("missing symbol in map");
                if start <= target && end > target {
                    return Some(StackUpdateResult {
                        frame_stack_size: self.frame_stack.len(),
                        frames_opened: Vec::new(),
                        frames_closed: closed,
                    });
                }
            } else {
                return None;
            }
        }
    }

    pub fn flush(&mut self) -> Option<StackUpdateResult> {
        // just return the frames
        return Some(StackUpdateResult {
            frame_stack_size: self.frame_stack.len(),
            frames_opened: Vec::new(),
            frames_closed: self.frame_stack.clone(),
        });
    }

    pub fn peak_curr_frames(&self) -> Vec<Frame> {
        self.frame_stack.clone()
    }
}
