use crate::common::prv::Prv;
use crate::frontend::runtime_cfg::DecoderRuntimeCfg;
use crate::frontend::trap_type::TrapType;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub enum Entry {
    Event { timestamp: u64, kind: EventKind },
}

#[derive(Debug, Clone, Serialize)]
pub enum EventKind {
    TakenBranch {
        arc: (u64, u64),
    },
    NonTakenBranch {
        arc: (u64, u64),
    },
    UninferableJump {
        arc: (u64, u64),
    },
    InferrableJump {
        arc: (u64, u64),
    },
    Trap {
        reason: TrapReason,
        prv_arc: (Prv, Prv),
        arc: (u64, u64),
        ctx: Option<u64>,
    },
    SyncStart {
        runtime_cfg: DecoderRuntimeCfg,
        start_pc: u64,
        start_prv: Prv,
        start_ctx: u64,
    },
    SyncEnd {
        end_pc: u64,
    },
    SyncPeriodic,
    /// Lossy mode: control flow is unknown from here until the next `Resume`.
    /// `pause_pc` is the first instruction whose event was not encoded; the
    /// entry's timestamp is its retire cycle. Same session / time base continues.
    Pause {
        pause_pc: u64,
    },
    /// Lossy mode: exact decoding restarts at `pc` with the given prv/ctx; the
    /// entry's timestamp is absolute. `dropped` packets were lost since the
    /// matching `Pause` at `pause_ts`.
    Resume {
        pc: u64,
        prv: Prv,
        ctx: u64,
        dropped: u64,
        pause_ts: u64,
    },
    BPHit {
        hit_count: u64,
    },
    BPMiss,
    Panic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum TrapReason {
    Exception,
    Interrupt,
    Return,
}

impl Entry {
    pub fn event(event: EventKind, timestamp: u64) -> Self {
        Entry::Event {
            timestamp,
            kind: event,
        }
    }

}

impl EventKind {
    // constructors
    pub fn taken_branch(arc: (u64, u64)) -> Self {
        EventKind::TakenBranch { arc }
    }

    pub fn non_taken_branch(arc: (u64, u64)) -> Self {
        EventKind::NonTakenBranch { arc }
    }

    pub fn uninferable_jump(arc: (u64, u64)) -> Self {
        EventKind::UninferableJump { arc }
    }

    pub fn inferrable_jump(arc: (u64, u64)) -> Self {
        EventKind::InferrableJump { arc }
    }

    pub fn trap(reason: TrapReason, prv_arc: (Prv, Prv), arc: (u64, u64)) -> Self {
        EventKind::Trap {
            reason,
            prv_arc,
            arc,
            ctx: None,
        }
    }

    pub fn trap_with_ctx(
        reason: TrapReason,
        prv_arc: (Prv, Prv),
        arc: (u64, u64),
        ctx: u64,
    ) -> Self {
        EventKind::Trap {
            reason,
            prv_arc,
            arc,
            ctx: Some(ctx),
        }
    }

    pub fn sync_start(
        runtime_cfg: DecoderRuntimeCfg,
        start_pc: u64,
        start_prv: Prv,
        start_ctx: u64,
    ) -> Self {
        EventKind::SyncStart {
            runtime_cfg,
            start_pc,
            start_prv,
            start_ctx,
        }
    }

    pub fn sync_end(end_pc: u64) -> Self {
        EventKind::SyncEnd { end_pc }
    }

    // pub fn sync_periodic() -> Self {
    //     EventKind::SyncPeriodic
    // }

    pub fn pause(pause_pc: u64) -> Self {
        EventKind::Pause { pause_pc }
    }

    pub fn resume(pc: u64, prv: Prv, ctx: u64, dropped: u64, pause_ts: u64) -> Self {
        EventKind::Resume {
            pc,
            prv,
            ctx,
            dropped,
            pause_ts,
        }
    }

    pub fn bphit(hit_count: u64) -> Self {
        EventKind::BPHit { hit_count }
    }

    pub fn bpmiss() -> Self {
        EventKind::BPMiss
    }

    // pub fn context_change(ctx: u64) -> Self {
    //     EventKind::ContextChange { ctx }
    // }

    pub fn panic() -> Self {
        EventKind::Panic
    }

    // getters
    // pub fn get_from_addr(&self) -> Option<u64> {
    //     match self {
    //         EventKind::TakenBranch { arc } => Some(arc.0),
    //         EventKind::UninferableJump { arc } => Some(arc.0),
    //         EventKind::InferrableJump { arc } => Some(arc.0),
    //         _ => None,
    //     }
    // }

    // pub fn get_to_addr(&self) -> Option<u64> {
    //     match self {
    //         EventKind::TakenBranch { arc } => Some(arc.1),
    //         EventKind::UninferableJump { arc } => Some(arc.1),
    //         EventKind::InferrableJump { arc } => Some(arc.1),
    //         _ => None,
    //     }
    // }

    // pub fn get_trap_reason(&self) -> Option<TrapReason> {
    //     match self {
    //         EventKind::Trap { reason, .. } => Some(reason.clone()),
    //         _ => None,
    //     }
    // }

    // pub fn get_prv_arc(&self) -> Option<(Prv, Prv)> {
    //     match self {
    //         EventKind::Trap { prv_arc, .. } => Some(prv_arc.clone()),
    //         _ => None,
    //     }
    // }

    // pub fn get_ctx(&self) -> Option<u64> {
    //     match self {
    //         EventKind::ContextChange { ctx } => Some(ctx.clone()),
    //         _ => None,
    //     }
    // }
}

impl From<TrapType> for TrapReason {
    fn from(trap_type: TrapType) -> Self {
        match trap_type {
            TrapType::TException => TrapReason::Exception,
            TrapType::TInterrupt => TrapReason::Interrupt,
            TrapType::TReturn => TrapReason::Return,
            TrapType::TNone => panic!("TNone should not be converted to TrapReason"),
        }
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventKind::TakenBranch { arc } => {
                write!(f, "TakenBranch: {:#x} -> {:#x}", arc.0, arc.1)
            }
            EventKind::NonTakenBranch { arc } => {
                write!(f, "NonTakenBranch: {:#x} -> {:#x}", arc.0, arc.1)
            }
            EventKind::UninferableJump { arc } => {
                write!(f, "UninferableJump: {:#x} -> {:#x}", arc.0, arc.1)
            }
            EventKind::InferrableJump { arc } => {
                write!(f, "InferrableJump: {:#x} -> {:#x}", arc.0, arc.1)
            }
            EventKind::Trap {
                reason,
                prv_arc,
                arc,
                ctx,
            } => write!(
                f,
                "Trap: {:#x} -> {:#x} ({:?} {:?}) (ctx: {:?})",
                arc.0, arc.1, reason, prv_arc, ctx
            ),
            EventKind::SyncStart {
                runtime_cfg,
                start_pc,
                start_prv,
                start_ctx,
            } => write!(
                f,
                "SyncStart: {:#x} ({:?} {:?}) {:?}",
                start_pc, start_prv, start_ctx, runtime_cfg
            ),
            EventKind::SyncEnd { end_pc } => write!(f, "SyncEnd: {:#x}", end_pc),
            EventKind::SyncPeriodic => write!(f, "SyncPeriodic"),
            EventKind::Pause { pause_pc } => write!(f, "Pause: {:#x}", pause_pc),
            EventKind::Resume {
                pc,
                prv,
                ctx,
                dropped,
                pause_ts,
            } => write!(
                f,
                "Resume: {:#x} ({:?} {:?}) dropped {} since {}",
                pc, prv, ctx, dropped, pause_ts
            ),
            EventKind::BPHit { hit_count } => write!(f, "BPHit: {}", hit_count),
            EventKind::BPMiss => write!(f, "BPMiss"),
            EventKind::Panic => write!(f, "Panic"),
        }
    }
}

impl EventKind {
    pub fn to_csv_string(&self) -> String {
        match self {
            EventKind::TakenBranch { arc } => {
                format!("TB,{:#x},{:#x}", arc.0, arc.1)
            }
            EventKind::NonTakenBranch { arc } => {
                format!("NTB,{:#x},{:#x}", arc.0, arc.1)
            }
            EventKind::UninferableJump { arc } => {
                format!("UJ,{:#x},{:#x}", arc.0, arc.1)
            }
            EventKind::InferrableJump { arc } => {
                format!("IJ,{:#x},{:#x}", arc.0, arc.1)
            }
            EventKind::Trap { reason, prv_arc: _, arc, ctx: _ } => {
                match reason {
                    TrapReason::Exception => {
                        format!("TRAP_EXC,{:#x},{:#x}", arc.0, arc.1)
                    }
                    TrapReason::Interrupt => {
                        format!("TRAP_INT,{:#x},{:#x}", arc.0, arc.1)
                    }
                    TrapReason::Return => {
                        format!("TRAP_RET,{:#x},{:#x}", arc.0, arc.1)
                    }
                }
            }
            EventKind::SyncStart { runtime_cfg: _, start_pc, start_prv: _, start_ctx: _ } => {
                format!("SYNC_START,{:#x}, 0x0", start_pc)
            }
            EventKind::SyncEnd { end_pc } => {
                format!("SYNC_END,0x0,{:#x}", end_pc)
            }
            EventKind::SyncPeriodic => {
                format!("SYNC_PERIODIC,0x0,0x0")
            }
            EventKind::Pause { pause_pc } => {
                format!("PAUSE,{:#x},0x0", pause_pc)
            }
            EventKind::Resume { pc, dropped, .. } => {
                format!("RESUME,0x0,{:#x},{}", pc, dropped)
            }
            // EventKind::BPHit { hit_count } => {
            //     format!("BPHIT,{}", hit_count)
            // }
            // EventKind::BPMiss => {
            //     format!("BPMISS")
            // }
            // EventKind::Panic => {
            //     format!("PANIC")
            // }
            _ => panic!("Unsupported event kind: {:?}", self)
        }
    }
}