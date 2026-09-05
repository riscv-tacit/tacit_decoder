#[path = "core/abstract_receiver.rs"]
pub mod abstract_receiver;
#[path = "core/registry.rs"]
pub mod registry;
#[path = "core/stack_unwinder.rs"]
pub mod stack_unwinder;

#[path = "analysis/bb_stats_receiver.rs"]
pub mod bb_stats_receiver;
#[path = "analysis/path_profile_receiver.rs"]
pub mod path_profile_receiver;
#[path = "analysis/prv_breakdown_receiver.rs"]
pub mod prv_breakdown_receiver;
#[path = "analysis/iteration_breakdown_receiver.rs"]
pub mod iteration_breakdown_receiver;
#[path = "analysis/func_path_receiver.rs"]
pub mod func_path_receiver;
#[path = "analysis/perfect_sampler_receiver.rs"]
pub mod perfect_sampler_receiver;

#[path = "print/speedscope_receiver.rs"]
pub mod speedscope_receiver;
#[path = "print/stack_txt_receiver.rs"]
pub mod stack_txt_receiver;
#[path = "print/txt_delta_receiver.rs"]
pub mod txt_delta_receiver;
#[path = "print/txt_receiver.rs"]
pub mod txt_receiver;
#[path = "print/sqlite_receiver.rs"]
pub mod sqlite_receiver;

// #[path = "emulation/cyc_bb_emulation_receiver.rs"]
// pub mod cyc_bb_emulation_receiver;
// #[path = "emulation/tc_bb_emulation_receiver.rs"]
// pub mod tc_bb_emulation_receiver;
// #[path = "emulation/cyc_func_emulation_receiver.rs"]
// pub mod cyc_func_emulation_receiver;
// pub mod tc_func_emulation_receiver;

#[path = "emulation/mod.rs"]
pub mod emulation;

// #[path = "emulation/reference_bb_receiver.rs"]
// pub mod reference_bb_receiver;
// #[path = "emulation/reference_func_receiver.rs"]
// pub mod reference_func_receiver;

// TODO: mask off for now until verified again
// #[path = "experimental/afdo_receiver.rs"]
// pub mod afdo_receiver;
// #[path = "experimental/gcda_receiver.rs"]
// pub mod gcda_receiver;
// #[path = "experimental/atomic_receiver.rs"]
// pub mod atomic_receiver;
// #[path = "experimental/perfetto_receiver.rs"]
// pub mod perfetto_receiver;

#[path = "analysis/bb_pair_stats_receiver.rs"]
pub mod bb_pair_stats_receiver;

#[path = "analysis/dispatch_stats_receiver.rs"]
pub mod dispatch_stats_receiver;

#[path = "analysis/oracle_match.rs"]
pub mod oracle_match;

#[path = "analysis/oracle_epsilon.rs"]
pub mod oracle_epsilon;

#[path = "analysis/oracle_func.rs"]
pub mod oracle_func;

#[path = "analysis/oracle_func_receiver.rs"]
pub mod oracle_func_receiver;

#[path = "analysis/oracle_bb_receiver.rs"]
pub mod oracle_bb_receiver;
