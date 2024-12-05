extern crate clap;
extern crate object;
extern crate capstone;
extern crate bus;

mod frontend {
    pub mod packet;
}
mod backend {
    pub mod abstract_receiver;
    pub mod event;
    pub mod txt_receiver;
    pub mod json_receiver;
    pub mod afdo_receiver;
}
use frontend::packet::FHeader;
use std::fs::File;
use std::io::{Read, BufReader};
use std::collections::HashMap;
use clap::Parser;
use capstone::prelude::*;
use capstone::arch::riscv::{ArchMode, ArchExtraMode};
use capstone::Insn;
use object::{Object, ObjectSection};
use bus::Bus;
use backend::event::{Entry, Event};
use backend::txt_receiver::TxtReceiver;
use backend::json_receiver::JsonReceiver;
use backend::afdo_receiver::AfdoReceiver;
use backend::abstract_receiver::AbstractReceiver;
use std::thread;
use anyhow::Result;

const BRANCH_OPCODES: &[&str] = &["beq", "bge", "bgeu", "blt", "bltu", "bne", "beqz", "bnez",
                                "bgez", "blez", "bltz", "bgtz", "bgt", "ble", "bgtu", "bleu",
                                "c.beqz", "c.bnez", "c.bltz", "c.bgez"];
const JUMP_OPCODES: &[&str] = &["jal", "jalr", "j", "jr", "call", "ret", "tail", "c.j", "c.jal", "c.jr", "c.jalr"];
const BUS_SIZE: usize = 1024;

#[derive(Clone, Parser)]
#[command(name = "trace-decoder", version = "0.1.0", about = "Decode trace files")]
struct Args {
    #[arg(short, long)]
    // path to the encoded trace file
    encoded_trace: String,
    #[arg(short, long)]
    // path to the binary file
    binary: String,
    #[arg(short, long, default_value_t = false)]
    // print verbose messages
    verbose: bool,
    #[arg(short, long, default_value_t = String::from("trace.dump"))]
    // path to the decoded trace file
    decoded_trace: String,
    #[arg(short, long, default_value_t = false)]
    // print the timestamp in the decoded trace file
    timestamp: bool,
    #[arg(long, default_value_t = true)]
    // output the decoded trace in text format
    to_txt: bool,
    #[arg(long, default_value_t = false)]
    // print the decoded trace in JSON format
    to_json: bool,
    #[arg(long, default_value_t = false)]
    // output the decoded trace in afdo format
    to_afdo: bool,
}

fn refund_addr(addr: u64) -> u64 {
    addr << 1
}

fn print_verbose(msg: &str, verbose: bool) {
    if verbose {
        println!("{}", msg);
    }
}

// FIXME: hacky way to get the offset operand, always the last one
fn compute_offset(insn: &Insn) -> i64 {
    let offset = insn.op_str().unwrap().split(",").last().unwrap();
    // remove leading spaces
    let offset = offset.trim();
    let offset_value: i64;
    if offset.starts_with("-0x") {
        offset_value = i64::from_str_radix(&offset[3..], 16).unwrap() * -1;
    } else if offset.starts_with("0x") {
        offset_value = i64::from_str_radix(&offset[2..], 16).unwrap();
    } else if offset.starts_with("-") {
        offset_value = i64::from_str_radix(&offset[1..], 10).unwrap() * -1;
    } else {
        offset_value = i64::from_str_radix(&offset, 10).unwrap();
    }
    offset_value
}

// step until encountering a br/jump
fn step_bb(pc: u64, insn_map: &HashMap<u64, &Insn>, bus: &mut Bus<Entry>) -> u64 {
    let mut pc = pc;
    loop {
        let insn = insn_map.get(&pc).unwrap();
        bus.broadcast(Entry::new_insn(insn));
        if BRANCH_OPCODES.contains(&insn.mnemonic().unwrap()) || JUMP_OPCODES.contains(&insn.mnemonic().unwrap()) {
            break;
        }
        // REMOVE ME: if we encounter something starts with b, j, c.b, or c.j, we should report
        if insn.mnemonic().unwrap().starts_with("b") || insn.mnemonic().unwrap().starts_with("j") || insn.mnemonic().unwrap().starts_with("c.b") || insn.mnemonic().unwrap().starts_with("c.j") {
            panic!("UNHANDLED: pc: {:x}, insn: {}", pc, insn.mnemonic().unwrap());
        }
        pc += insn.len() as u64;
    }
    pc
}

fn step_bb_until(pc: u64, insn_map: &HashMap<u64, &Insn>, target_pc: u64, bus: &mut Bus<Entry>) -> u64 {
    println!("stepping bb from pc: {:x} until pc: {:x}", pc, target_pc);
    let mut pc = pc;
    loop {
        let insn = insn_map.get(&pc).unwrap();
        bus.broadcast(Entry::new_insn(insn));
        if BRANCH_OPCODES.contains(&insn.mnemonic().unwrap()) || JUMP_OPCODES.contains(&insn.mnemonic().unwrap()) {
            break;
        }
        pc += insn.len() as u64;
        if pc == target_pc {
            break;
        }
    }
    pc
}

// frontend decoding packets and pushing entries to the bus
fn trace_decoder(args: &Args, mut bus: Bus<Entry>) -> Result<()> {
    let mut elf_file = File::open(args.binary.clone())?;
    let mut elf_buffer = Vec::new();
    elf_file.read_to_end(&mut elf_buffer)?;
    let elf = object::File::parse(&*elf_buffer)?;
    assert!(elf.architecture() == object::Architecture::Riscv64);

    // Find the .text section (where the executable code resides)
    let text_section = elf.section_by_name(".text").ok_or_else(|| anyhow::anyhow!("No .text section found"))?;
    let text_data = text_section.data()?;
    let entry_point = elf.entry();

    let cs = Capstone::new()
        .riscv()
        .mode(ArchMode::RiscV64)
        .extra_mode([ArchExtraMode::RiscVC].iter().copied())
        .detail(true)
        .build()?;

    let decoded_instructions = cs.disasm_all(&text_data, entry_point)?;
    print_verbose(&format!("found {} instructions", decoded_instructions.len()), args.verbose);

    // create a map of address to instruction 
    let mut insn_map : HashMap<u64, &Insn> = HashMap::new();
    for insn in decoded_instructions.as_ref() {
        insn_map.insert(insn.address(), insn);
    }

    let encoded_trace_file = File::open(args.encoded_trace.clone())?;
    let mut encoded_trace_reader : BufReader<File> = BufReader::new(encoded_trace_file);

    let packet = frontend::packet::read_packet(&mut encoded_trace_reader)?;
    print_verbose(&format!("packet: {:?}", packet), args.verbose);
    let mut pc = refund_addr(packet.target_address);
    let mut timestamp = packet.timestamp;
    bus.broadcast(Entry::new_timed_event(Event::Start, packet.timestamp, pc, 0));

    while let Ok(packet) = frontend::packet::read_packet(&mut encoded_trace_reader) {
        // special handling for the last packet, should be unlikely hinted
        print_verbose(&format!("packet: {:?}", packet), args.verbose);
        if packet.f_header == FHeader::FSync {
            pc = step_bb_until(pc, &insn_map, refund_addr(packet.target_address), &mut bus);
            println!("detected FSync packet, trace ending!");
            bus.broadcast(Entry::new_timed_event(Event::End, packet.timestamp, pc, 0));
            break;
        } else if packet.f_header == FHeader::FTrap {
            bus.broadcast(Entry::new_timed_trap(packet.trap_type, packet.timestamp, pc, packet.trap_address));
            pc = step_bb_until(pc, &insn_map, packet.trap_address, &mut bus);
            pc = refund_addr(packet.target_address ^ (pc >> 1));
            timestamp += packet.timestamp;
        } else {
            pc = step_bb(pc, &insn_map, &mut bus);
            let insn_to_resolve = insn_map.get(&pc).unwrap();
            print_verbose(&format!("pc: {:x}", pc), args.verbose);
            timestamp += packet.timestamp;
            match packet.f_header {
                FHeader::FTb => {
                    assert!(BRANCH_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()));
                    let new_pc = (pc as i64 + compute_offset(insn_to_resolve) as i64) as u64;
                    bus.broadcast(Entry::new_timed_event(Event::TakenBranch, timestamp, pc, new_pc));
                    pc = new_pc;
                }
                FHeader::FNt => {
                    assert!(BRANCH_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()));
                    let new_pc = pc + insn_to_resolve.len() as u64;
                    bus.broadcast(Entry::new_timed_event(Event::NonTakenBranch, timestamp, pc, new_pc));
                    pc = new_pc;
                }
                FHeader::FIj => {
                    assert!(JUMP_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()));
                    let new_pc = (pc as i64 + compute_offset(insn_to_resolve) as i64) as u64;
                    bus.broadcast(Entry::new_timed_event(Event::InferrableJump, timestamp, pc, new_pc));
                    pc = new_pc;
                }
                FHeader::FUj => {
                    assert!(JUMP_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()));
                    let new_pc = refund_addr(packet.target_address ^ (pc >> 1));
                    bus.broadcast(Entry::new_timed_event(Event::UninferableJump, timestamp, pc, new_pc));
                    pc = new_pc;
                }
                FHeader::FTrap => {
                    bus.broadcast(Entry::new_timed_trap(packet.trap_type, packet.timestamp, pc, packet.trap_address));
                    pc = refund_addr(packet.target_address ^ (pc >> 1));
                }
                _ => {
                    panic!("unknown FHeader: {:?}", packet.f_header);
                }
            }
            // log the timestamp
        }
    }

    drop(bus);
    println!("[fe-decoder] bus dropped");

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut bus: Bus<Entry> = Bus::new(BUS_SIZE);
    let mut receivers: Vec<Box<dyn AbstractReceiver>> = vec![];
    
    // add a receiver to the bus for txt output
    if args.to_txt {
        let txt_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(TxtReceiver::new(txt_bus_endpoint)));
    }

    // add a receiver to the bus for json output
    if args.to_json {
        let json_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(JsonReceiver::new(json_bus_endpoint)));
    }

    if args.to_afdo {
        let afdo_bus_endpoint = bus.add_rx();
        let mut elf_file = File::open(args.binary.clone())?;
        let mut elf_buffer = Vec::new();
        elf_file.read_to_end(&mut elf_buffer)?;
        let elf = object::File::parse(&*elf_buffer)?;
        receivers.push(Box::new(AfdoReceiver::new(afdo_bus_endpoint, elf.entry().clone())));
        drop(elf_file);
    }

    let frontend_handle = thread::spawn(move || trace_decoder(&args, bus));
    let receiver_handles: Vec<_> = receivers.into_iter()
        .map(|mut receiver| thread::spawn(move || receiver.try_receive_loop()))
        .collect();

    frontend_handle.join().unwrap()?;
    for handle in receiver_handles {
        handle.join().unwrap();
    }

    Ok(())
}
