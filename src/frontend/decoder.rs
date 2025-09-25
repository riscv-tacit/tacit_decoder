use anyhow::Result;
use bus::Bus;
use log::{debug, trace};
use std::fs::File;
use std::io::BufReader;

use crate::backend::event::{Entry, EventKind, TrapReason};
use crate::common::insn_index::InstructionIndex;
use crate::common::prv::Prv;
use crate::frontend::bp_double_saturating_counter::BpDoubleSaturatingCounter;
use crate::frontend::br_mode::BrMode;
use crate::frontend::f_header::FHeader;
use crate::frontend::packet;
use crate::frontend::runtime_cfg::DecoderRuntimeCfg;

use rvdasm::insn::Insn;
use std::collections::HashMap;
use std::sync::Arc;

fn refund_addr(addr: u64) -> u64 {
    addr << 1
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

pub fn decode_trace(
    encoded_trace: String,
    runtime_cfg: DecoderRuntimeCfg,
    insn_index: Arc<InstructionIndex>,
    mut bus: Bus<Entry>,
) -> Result<()> {
    // Open and parse the first packet (SyncStart)
    let trace_file = File::open(encoded_trace.clone())?;
    let mut trace_reader = BufReader::new(trace_file);
    let (first_packet, first_runtime_cfg) = packet::read_first_packet(&mut trace_reader)?;

    let br_mode = runtime_cfg.br_mode;
    let mode_is_predict = br_mode == BrMode::BrPredict;
    let mut bp_counter = BpDoubleSaturatingCounter::new(runtime_cfg.bp_entries);

    // initial state from first packet
    let mut packet_count = 0u64;
    let mut pc = refund_addr(first_packet.target_address);
    let mut timestamp = first_packet.timestamp;
    let mut prv = first_packet.target_prv;
    bus.broadcast(Entry::event(
        EventKind::sync_start(first_runtime_cfg, pc, prv),
        first_packet.timestamp,
    ));

    loop {
        let packet = match packet::read_packet(&mut trace_reader) {
            Ok(pkt) => pkt,
            Err(_) => break,
        };
        debug!("packet: {:?}", packet);
        packet_count += 1;

        // Select the correct instruction map based on privilege
        let get_insn_map = |p: Prv| -> &HashMap<u64, Insn> { insn_index.get(p) };

        if packet.f_header == FHeader::FSync {
            pc = step_bb_until(
                pc,
                get_insn_map(prv),
                refund_addr(packet.target_address),
                &mut bus,
            );
            bus.broadcast(Entry::event(EventKind::sync_end(pc), packet.timestamp));
            break;
        } else if packet.f_header == FHeader::FTrap {
            // step until the trap's from_address (previous insn)
            pc = step_bb_until(
                pc,
                get_insn_map(prv),
                refund_addr(packet.from_address),
                &mut bus,
            );
            // trap event
            let trap_type = match packet.func3 {
                crate::frontend::packet::SubFunc3::TrapType(t) => t,
                _ => unreachable!(),
            };
            let new_pc = refund_addr(packet.target_address ^ (pc >> 1));
            timestamp += packet.timestamp;
            bus.broadcast(Entry::event(
                EventKind::trap(TrapReason::from(trap_type), (prv, prv)),
                timestamp,
            ));
            prv = packet.target_prv;
            pc = new_pc;
            continue;
        }

        if mode_is_predict && packet.f_header == FHeader::FTb {
            // predicted hit with hit-count = packet.timestamp
            bus.broadcast(Entry::event(
                EventKind::bphit(packet.timestamp),
                packet.timestamp,
            ));
            for _ in 0..packet.timestamp {
                pc = step_bb(pc, get_insn_map(prv), &mut bus, &br_mode);
                let insn_to_resolve = get_insn_map(prv).get(&pc).unwrap();
                if !insn_to_resolve.is_branch() {
                    bus.broadcast(Entry::event(EventKind::panic(), 0));
                    panic!("pc: {:x}, insn: {:?}", pc, insn_to_resolve);
                }
                let taken = bp_counter.predict(pc, true);
                if taken {
                    let new_pc = (pc as i64
                        + insn_to_resolve.get_imm().unwrap().get_val_signed_imm() as i64)
                        as u64;
                    bus.broadcast(Entry::event(
                        EventKind::taken_branch((pc, new_pc)),
                        timestamp,
                    ));
                    pc = new_pc;
                } else {
                    let new_pc = pc + insn_to_resolve.len as u64;
                    bus.broadcast(Entry::event(
                        EventKind::non_taken_branch((pc, new_pc)),
                        timestamp,
                    ));
                    pc = new_pc;
                }
            }
        } else if mode_is_predict && packet.f_header == FHeader::FNt {
            // predicted miss
            timestamp += packet.timestamp;
            bus.broadcast(Entry::event(EventKind::bpmiss(), timestamp));
            pc = step_bb(pc, get_insn_map(prv), &mut bus, &br_mode);
            let insn_to_resolve = get_insn_map(prv).get(&pc).unwrap();
            if !insn_to_resolve.is_branch() {
                bus.broadcast(Entry::event(EventKind::panic(), 0));
                panic!(
                    "pc: {:x}, timestamp: {}, insn: {:?}",
                    pc, timestamp, insn_to_resolve
                );
            }
            let taken = bp_counter.predict(pc, false);
            if !taken {
                let new_pc = (pc as i64
                    + insn_to_resolve.get_imm().unwrap().get_val_signed_imm() as i64)
                    as u64;
                bus.broadcast(Entry::event(
                    EventKind::taken_branch((pc, new_pc)),
                    timestamp,
                ));
                pc = new_pc;
            } else {
                let new_pc = pc + insn_to_resolve.len as u64;
                bus.broadcast(Entry::event(
                    EventKind::non_taken_branch((pc, new_pc)),
                    timestamp,
                ));
                pc = new_pc;
            }
        } else {
            // branch target mode
            pc = step_bb(pc, get_insn_map(prv), &mut bus, &br_mode);
            let insn_to_resolve = get_insn_map(prv).get(&pc).unwrap();
            timestamp += packet.timestamp;
            match packet.f_header {
                FHeader::FTb => {
                    if !insn_to_resolve.is_branch() {
                        bus.broadcast(Entry::event(EventKind::panic(), 0));
                        panic!(
                            "pc: {:x}, timestamp: {}, insn: {:?}",
                            pc, timestamp, insn_to_resolve
                        );
                    }
                    let new_pc = (pc as i64
                        + insn_to_resolve.get_imm().unwrap().get_val_signed_imm() as i64)
                        as u64;
                    bus.broadcast(Entry::event(
                        EventKind::taken_branch((pc, new_pc)),
                        timestamp,
                    ));
                    pc = new_pc;
                }
                FHeader::FNt => {
                    if !insn_to_resolve.is_branch() {
                        bus.broadcast(Entry::event(EventKind::panic(), 0));
                        panic!(
                            "pc: {:x}, timestamp: {}, insn: {:?}",
                            pc, timestamp, insn_to_resolve
                        );
                    }
                    let new_pc = pc + insn_to_resolve.len as u64;
                    bus.broadcast(Entry::event(
                        EventKind::non_taken_branch((pc, new_pc)),
                        timestamp,
                    ));
                    pc = new_pc;
                }
                FHeader::FIj => {
                    if !insn_to_resolve.is_direct_jump() {
                        bus.broadcast(Entry::event(EventKind::panic(), 0));
                        panic!(
                            "pc: {:x}, timestamp: {}, insn: {:?}",
                            pc, timestamp, insn_to_resolve
                        );
                    }
                    let new_pc = (pc as i64
                        + insn_to_resolve.get_imm().unwrap().get_val_signed_imm() as i64)
                        as u64;
                    bus.broadcast(Entry::event(
                        EventKind::inferrable_jump((pc, new_pc)),
                        timestamp,
                    ));
                    pc = new_pc;
                }
                FHeader::FUj => {
                    if !insn_to_resolve.is_indirect_jump() {
                        bus.broadcast(Entry::event(EventKind::panic(), 0));
                        panic!(
                            "pc: {:x}, timestamp: {}, insn: {:?}",
                            pc, timestamp, insn_to_resolve
                        );
                    }
                    let new_pc = refund_addr(packet.target_address ^ (pc >> 1));
                    bus.broadcast(Entry::event(
                        EventKind::uninferable_jump((pc, new_pc)),
                        timestamp,
                    ));
                    pc = new_pc;
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
