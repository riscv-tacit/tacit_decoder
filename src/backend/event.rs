use capstone::Insn;
use crate::frontend::packet::TrapType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    None,
    TakenBranch,
    NonTakenBranch,
    UninferableJump,
    InferrableJump,
    TrapException,
    TrapInterrupt,
    TrapReturn,
    Timestamp,
}

impl Event {
    pub fn from_trap_type(trap_type: TrapType) -> Self {
        match trap_type {
            TrapType::TException => Event::TrapException,
            TrapType::TInterrupt => Event::TrapInterrupt,
            TrapType::TReturn => Event::TrapReturn,
            TrapType::TNone => panic!("TNone should not be converted to Event"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub event: Event,
    pub pc: u64,
    pub insn_bytes: Vec<u8>,
    pub insn_mnemonic: Option<String>,
    pub insn_op_str: Option<String>,
    pub insn_len: usize,
    pub timestamp: Option<u64>,
}

impl Entry {
    pub fn new_timestamp(timestamp: u64) -> Self {
        Self { event: Event::Timestamp, pc: 0, insn_bytes: vec![], insn_mnemonic: None, insn_op_str: None, insn_len: 0, timestamp: Some(timestamp) }
    }

    pub fn new_insn(insn: &Insn) -> Self {
        Self { event: Event::None, pc: insn.address(), insn_bytes: insn.bytes().to_vec(), insn_mnemonic: Some(insn.mnemonic().unwrap().to_string()), insn_op_str: Some(insn.op_str().unwrap().to_string()), insn_len: insn.len(), timestamp: None }
    }

    pub fn new_trap(trap_type: TrapType) -> Self {
        Self { event: Event::from_trap_type(trap_type), pc: 0, insn_bytes: vec![], insn_mnemonic: None, insn_op_str: None, insn_len: 0, timestamp: None }
    }
}
