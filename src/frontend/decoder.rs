use anyhow::Result;
use bus::Bus;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, trace};
use std::fs::File;
use std::io::{BufReader, Seek};

use crate::backend::event::{Entry, EventKind, TrapReason};
use crate::common::insn_index::InstructionIndex;
use crate::common::prv::Prv;
use crate::common::static_cfg::DecoderStaticCfg;
use crate::frontend::bp_double_saturating_counter::BpDoubleSaturatingCounter;
use crate::frontend::br_mode::BrMode;
use crate::frontend::f_header::FHeader;
use crate::frontend::packet;
use crate::frontend::runtime_cfg::DecoderRuntimeCfg;
use crate::frontend::trap_type::TrapType;

use rvdasm::insn::Insn;
use std::collections::HashMap;
use std::sync::Arc;

// const ADDR_BITS: u64 = 64;
const ADDR_BITS: u64 = 40;
const ADDR_MASK: u64 = if ADDR_BITS == 64 {
    0xffffffffffffffff
} else {
    (1 << ADDR_BITS) - 1
};
const ADDR_EXTENDER_BITS: u64 = 64 - ADDR_BITS;
const SIGNED_ADDR_EXTENDER_MASK: u64 = if ADDR_EXTENDER_BITS == 64 {
    0x0
} else {
    (1 << ADDR_EXTENDER_BITS) - 1
};
const UNSIGNED_ADDR_EXTENDER_MASK: u64 = 0x0;

struct PC {
    addr: u64,
}

impl PC {
    fn new(unshifted_addr: u64) -> Self {
        Self {
            addr: unshifted_addr << 1,
        }
    }

    fn compute_from_xored_target_addr(&mut self, target_addr: u64) -> u64 {
        let refunded_delta = target_addr << 1;
        trace!(
            "refunded_delta {:x}, current pc: {:x}",
            refunded_delta,
            self.addr
        );
        let xored_addr = (self.addr & ADDR_MASK) ^ refunded_delta;
        trace!("xored_addr: {:x}", xored_addr);
        xored_addr
    }

    fn get_addr(&self) -> u64 {
        // sign extend by the 40th bit
        let sign_bit = self.addr >> (ADDR_BITS - 1);
        let extender = if sign_bit == 1 {
            SIGNED_ADDR_EXTENDER_MASK
        } else {
            UNSIGNED_ADDR_EXTENDER_MASK
        };
        let extended_addr = self.addr
            | if ADDR_BITS == 64 {
                0x0
            } else {
                extender << ADDR_BITS
            };
        extended_addr
    }

    fn set_addr(&mut self, addr: u64) {
        self.addr = addr;
    }
}

fn refund_addr(addr: u64) -> u64 {
    let shifted_addr = addr << 1;
    let sign_bit = shifted_addr >> 39;
    let extender = if sign_bit == 1 {
        SIGNED_ADDR_EXTENDER_MASK
    } else {
        UNSIGNED_ADDR_EXTENDER_MASK
    };
    let extended_addr = shifted_addr | (extender << 40);
    extended_addr
    // extended_addr << 1
}

// step until encountering a br/jump
fn step_bb(pc: u64, insn_map: &HashMap<u64, Insn>, bus: &mut Bus<Entry>, br_mode: &BrMode) -> u64 {
    let mut pc = pc;
    let stop_on_ij = *br_mode == BrMode::BrTarget;
    loop {
        trace!("stepping bb pc: {:x}", pc);
        let insn = insn_map.get(&pc).unwrap();
        bus.broadcast(Entry::instruction(insn, pc));
        if stop_on_ij {
            if insn.is_branch() || insn.is_direct_jump() || insn.is_indirect_jump() {
                break;
            } else {
                pc += insn.len as u64;
            }
        } else {
            if insn.is_branch() || insn.is_indirect_jump() {
                break;
            } else if insn.is_direct_jump() {
                let new_pc =
                    (pc as i64 + insn.get_imm().unwrap().get_val_signed_imm() as i64) as u64;
                pc = new_pc;
            } else {
                pc += insn.len as u64;
            }
        }
    }
    pc
}

fn step_bb_until(
    pc: u64,
    insn_map: &HashMap<u64, Insn>,
    target_pc: u64,
    bus: &mut Bus<Entry>,
) -> u64 {
    debug!("stepping bb from pc: {:x} until pc: {:x}", pc, target_pc);
    let mut pc = pc;

    loop {
        let insn = insn_map.get(&pc).unwrap();
        bus.broadcast(Entry::instruction(insn, pc));
        if insn.is_branch() || insn.is_direct_jump() {
            break;
        }
        if pc == target_pc {
            break;
        }
        pc += insn.len as u64;
    }
    pc
}

fn find_ctx(ctx: u64, static_cfg: &DecoderStaticCfg) -> bool {
    for (_, asid) in static_cfg.application_binary_asid_tuples.iter() {
        if asid.parse::<u64>().unwrap() == ctx {
            return true;
        }
    }
    false
}

pub fn decode_trace(
    encoded_trace: String,
    static_cfg: DecoderStaticCfg,
    runtime_cfg: DecoderRuntimeCfg,
    insn_index: Arc<InstructionIndex>,
    mut bus: Bus<Entry>,
) -> Result<()> {
    // Open and parse the first packet (SyncStart)
    let trace_file = File::open(encoded_trace.clone())?;

    // get the file size
    let trace_file_size = trace_file.metadata()?.len();
    let progress_bar = ProgressBar::new(trace_file_size);
    progress_bar.set_style(ProgressStyle::default_bar().template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/green}] {bytes}/{total_bytes} ({eta})")?);

    let mut trace_reader = BufReader::new(trace_file);
    let (first_packet, first_runtime_cfg) = packet::read_first_packet(&mut trace_reader)?;

    let br_mode = runtime_cfg.br_mode;
    let mode_is_predict = br_mode == BrMode::BrPredict;
    let mut bp_counter = BpDoubleSaturatingCounter::new(runtime_cfg.bp_entries);

    // initial state from first packet
    let mut packet_count = 0u64;
    let mut pc = PC::new(first_packet.target_address);
    let mut timestamp = first_packet.timestamp;
    let mut prv = first_packet.target_prv;
    let mut ctx = first_packet.target_ctx;
    let mut u_unknown_ctx = false;
    bus.broadcast(Entry::event(
        EventKind::sync_start(first_runtime_cfg, pc.get_addr(), prv, ctx),
        first_packet.timestamp,
    ));

    loop {
        let packet = match packet::read_packet(&mut trace_reader) {
            Ok(pkt) => pkt,
            Err(_) => break,
        };
        let current_position = trace_reader.stream_position()?;
        progress_bar.set_position(current_position);

        debug!("packet: {:?}", packet);
        packet_count += 1;

        // Select the correct instruction map based on privilege and context
        let get_insn_map = |p: Prv, ctx: u64| -> &HashMap<u64, Insn> { insn_index.get(p, ctx) };

        if packet.f_header == FHeader::FSync {
            let new_pc = step_bb_until(
                pc.get_addr(),
                get_insn_map(prv, ctx),
                refund_addr(packet.target_address),
                &mut bus,
            );
            pc.set_addr(new_pc);
            bus.broadcast(Entry::event(
                EventKind::sync_end(pc.get_addr()),
                packet.timestamp,
            ));
            break;
        } else if packet.f_header == FHeader::FTrap {
            // step until the trap's from_address (previous insn)
            // only step if we are in a known ctx
            let trapping_pc = refund_addr(packet.from_address);
            if !(u_unknown_ctx && prv == Prv::PrvUser) {
                let new_pc =
                    step_bb_until(pc.get_addr(), get_insn_map(prv, ctx), trapping_pc, &mut bus);
                assert!(
                    new_pc == trapping_pc,
                    "new_pc: {:x}, trapping_pc: {:x}",
                    new_pc,
                    trapping_pc
                );
            }
            // trap event
            let trap_type = match packet.func3 {
                crate::frontend::packet::SubFunc3::TrapType(t) => t,
                _ => unreachable!(),
            };
            timestamp += packet.timestamp;
            let report_ctx = trap_type == TrapType::TReturn && packet.target_prv == Prv::PrvUser;
            if report_ctx {
                if find_ctx(packet.target_ctx, &static_cfg) {
                    ctx = packet.target_ctx;
                    u_unknown_ctx = false; // we now are in a known ctx
                } else {
                    u_unknown_ctx = true; // we are in an unknown ctx
                }
                bus.broadcast(Entry::event(
                    EventKind::trap_with_ctx(
                        TrapReason::from(trap_type),
                        (prv, packet.target_prv),
                        (pc.get_addr(), trapping_pc),
                        packet.target_ctx,
                    ),
                    timestamp,
                ));
            } else {
                bus.broadcast(Entry::event(
                    EventKind::trap(
                        TrapReason::from(trap_type),
                        (prv, packet.target_prv),
                        (pc.get_addr(), trapping_pc),
                    ),
                    timestamp,
                ));
            }
            trace!("u_unknown_ctx: {}, ctx: {}", u_unknown_ctx, ctx);
            prv = packet.target_prv;
            pc.set_addr(trapping_pc);
            let new_pc = pc.compute_from_xored_target_addr(packet.target_address);
            pc.set_addr(new_pc);
            trace!("new set pc: {:x}", pc.get_addr());
            continue;
        }

        if mode_is_predict && packet.f_header == FHeader::FTb {
            // predicted hit with hit-count = packet.timestamp
            bus.broadcast(Entry::event(
                EventKind::bphit(packet.timestamp),
                packet.timestamp,
            ));
            for _ in 0..packet.timestamp {
                let new_pc = step_bb(pc.get_addr(), get_insn_map(prv, ctx), &mut bus, &br_mode);
                pc.set_addr(new_pc);
                let insn_to_resolve = get_insn_map(prv, ctx).get(&pc.get_addr()).unwrap();
                if !insn_to_resolve.is_branch() {
                    bus.broadcast(Entry::event(EventKind::panic(), 0));
                    panic!("pc: {:x}, insn: {:?}", pc.get_addr(), insn_to_resolve);
                }
                let taken = bp_counter.predict(pc.get_addr(), true);
                if taken {
                    let new_pc = (pc.get_addr() as i64
                        + insn_to_resolve.get_imm().unwrap().get_val_signed_imm() as i64)
                        as u64;
                    bus.broadcast(Entry::event(
                        EventKind::taken_branch((pc.get_addr(), new_pc)),
                        timestamp,
                    ));
                    pc.set_addr(new_pc);
                } else {
                    let new_pc = pc.get_addr() + insn_to_resolve.len as u64;
                    bus.broadcast(Entry::event(
                        EventKind::non_taken_branch((pc.get_addr(), new_pc)),
                        timestamp,
                    ));
                    pc.set_addr(new_pc);
                }
            }
        } else if mode_is_predict && packet.f_header == FHeader::FNt {
            // predicted miss
            timestamp += packet.timestamp;
            bus.broadcast(Entry::event(EventKind::bpmiss(), timestamp));
            let new_pc = step_bb(pc.get_addr(), get_insn_map(prv, ctx), &mut bus, &br_mode);
            pc.set_addr(new_pc);
            let insn_to_resolve = get_insn_map(prv, ctx).get(&pc.get_addr()).unwrap();
            if !insn_to_resolve.is_branch() {
                bus.broadcast(Entry::event(EventKind::panic(), 0));
                panic!(
                    "pc: {:x}, timestamp: {}, insn: {:?}",
                    pc.get_addr(),
                    timestamp,
                    insn_to_resolve
                );
            }
            let taken = bp_counter.predict(pc.get_addr(), false);
            if !taken {
                let new_pc = (pc.get_addr() as i64
                    + insn_to_resolve.get_imm().unwrap().get_val_signed_imm() as i64)
                    as u64;
                bus.broadcast(Entry::event(
                    EventKind::taken_branch((pc.get_addr(), new_pc)),
                    timestamp,
                ));
                pc.set_addr(new_pc);
            } else {
                let new_pc = pc.get_addr() + insn_to_resolve.len as u64;
                bus.broadcast(Entry::event(
                    EventKind::non_taken_branch((pc.get_addr(), new_pc)),
                    timestamp,
                ));
                pc.set_addr(new_pc);
            }
        } else {
            // branch target mode
            // if we're in unknown ctx and we are in user priv, we should ingnore such packet
            if u_unknown_ctx && prv == Prv::PrvUser {
                timestamp += packet.timestamp;
                trace!("ignoring packet in unknown ctx");
                continue;
            }
            // only enter here if we are either in a known ctx or we are in a unknown ctx and we are in a supervisor priv
            let new_pc = step_bb(pc.get_addr(), get_insn_map(prv, ctx), &mut bus, &br_mode);
            pc.set_addr(new_pc);
            let insn_to_resolve = get_insn_map(prv, ctx).get(&pc.get_addr()).unwrap();
            timestamp += packet.timestamp;
            match packet.f_header {
                FHeader::FTb => {
                    if !insn_to_resolve.is_branch() {
                        bus.broadcast(Entry::event(EventKind::panic(), 0));
                        panic!(
                            "pc: {:x}, timestamp: {}, insn: {:?}",
                            pc.get_addr(),
                            timestamp,
                            insn_to_resolve
                        );
                    }
                    let new_pc = (pc.get_addr() as i64
                        + insn_to_resolve.get_imm().unwrap().get_val_signed_imm() as i64)
                        as u64;
                    bus.broadcast(Entry::event(
                        EventKind::taken_branch((pc.get_addr(), new_pc)),
                        timestamp,
                    ));
                    pc.set_addr(new_pc);
                }
                FHeader::FNt => {
                    if !insn_to_resolve.is_branch() {
                        bus.broadcast(Entry::event(EventKind::panic(), 0));
                        panic!(
                            "pc: {:x}, timestamp: {}, insn: {:?}",
                            pc.get_addr(),
                            timestamp,
                            insn_to_resolve
                        );
                    }
                    let new_pc = pc.get_addr() + insn_to_resolve.len as u64;
                    bus.broadcast(Entry::event(
                        EventKind::non_taken_branch((pc.get_addr(), new_pc)),
                        timestamp,
                    ));
                    pc.set_addr(new_pc);
                }
                FHeader::FIj => {
                    if !insn_to_resolve.is_direct_jump() {
                        bus.broadcast(Entry::event(EventKind::panic(), 0));
                        panic!(
                            "pc: {:x}, timestamp: {}, insn: {:?}",
                            pc.get_addr(),
                            timestamp,
                            insn_to_resolve
                        );
                    }
                    let new_pc = (pc.get_addr() as i64
                        + insn_to_resolve.get_imm().unwrap().get_val_signed_imm() as i64)
                        as u64;
                    bus.broadcast(Entry::event(
                        EventKind::inferrable_jump((pc.get_addr(), new_pc)),
                        timestamp,
                    ));
                    pc.set_addr(new_pc);
                }
                FHeader::FUj => {
                    if !insn_to_resolve.is_indirect_jump() {
                        bus.broadcast(Entry::event(EventKind::panic(), 0));
                        panic!(
                            "pc: {:x}, timestamp: {}, insn: {:?}",
                            pc.get_addr(),
                            timestamp,
                            insn_to_resolve
                        );
                    }
                    let new_pc = pc.compute_from_xored_target_addr(packet.target_address);
                    bus.broadcast(Entry::event(
                        EventKind::uninferable_jump((pc.get_addr(), new_pc)),
                        timestamp,
                    ));
                    pc.set_addr(new_pc);
                }
                _ => {
                    bus.broadcast(Entry::event(EventKind::panic(), 0));
                    panic!("unknown FHeader: {:?}", packet.f_header);
                }
            }
        }
    }

    drop(bus);
    println!("[Success] Decoded {} packets", packet_count);
    Ok(())
}
