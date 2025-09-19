extern crate bus;
extern crate clap;
extern crate env_logger;
extern crate gcno_reader;
extern crate log;
extern crate object;
extern crate rvdasm;
mod frontend {
    pub mod bp_double_saturating_counter;
    pub mod br_mode;
    pub mod c_header;
    pub mod ctx_mode;
    pub mod prv;
    pub mod f_header;
    pub mod packet;
    pub mod runtime_cfg;
    pub mod sync_type;
    pub mod trap_type;
}
mod backend {
    pub mod abstract_receiver;
    pub mod afdo_receiver;
    pub mod atomic_receiver;
    pub mod event;
    pub mod foc_receiver;
    pub mod gcda_receiver;
    pub mod perfetto_receiver;
    pub mod speedscope_receiver;
    pub mod stack_txt_receiver;
    pub mod stack_unwinder;
    pub mod stats_receiver;
    pub mod txt_receiver;
    pub mod vbb_receiver;
    pub mod vpp_receiver;
}

use frontend::f_header::FHeader;

// file IO
use std::fs::File;
use std::io::{BufReader, BufRead, Read};
// collections
use std::collections::HashMap;
// argparse dependency
use clap::Parser;
// objdump dependency
use object::elf::SHF_EXECINSTR;
use object::{Object, ObjectSection};
use rvdasm::disassembler::*;
use rvdasm::insn::*;
// path dependency
use std::path::Path;
// bus dependency
use bus::Bus;
use std::thread;
// frontend dependency
use frontend::bp_double_saturating_counter::BpDoubleSaturatingCounter;
use frontend::br_mode::BrMode;
use frontend::prv::Prv;
use frontend::runtime_cfg::DecoderRuntimeCfg;
// backend dependency
use backend::abstract_receiver::AbstractReceiver;
use backend::afdo_receiver::AfdoReceiver;
use backend::atomic_receiver::AtomicReceiver;
use backend::event::{Entry, Event};
use backend::foc_receiver::FOCReceiver;
use backend::gcda_receiver::GcdaReceiver;
use backend::perfetto_receiver::PerfettoReceiver;
use backend::speedscope_receiver::SpeedscopeReceiver;
use backend::stack_txt_receiver::StackTxtReceiver;
use backend::stats_receiver::StatsReceiver;
use backend::txt_receiver::TxtReceiver;
use backend::vbb_receiver::VBBReceiver;
use backend::vpp_receiver::VPPReceiver;
// error handling
use anyhow::Result;
// logging
use log::{debug, trace};
use serde::{Deserialize, Serialize};

const BRANCH_OPCODES: &[&str] = &[
    "beq", "bge", "bgeu", "blt", "bltu", "bne", "beqz", "bnez", "bgez", "blez", "bltz", "bgtz",
    "bgt", "ble", "bgtu", "bleu", "c.beqz", "c.bnez", "c.bltz", "c.bgez",
];
const IJ_OPCODES: &[&str] = &["jal", "j", "call", "tail", "c.j", "c.jal"];
const UJ_OPCODES: &[&str] = &["jalr", "jr", "c.jr", "c.jalr", "ret"];
const BUS_SIZE: usize = 1024;

#[derive(Clone, Parser)]
#[command(
    name = "trace-decoder",
    version = "0.1.0",
    about = "Decode trace files"
)]
struct Args {
    // optional JSON config file to control receivers
    #[arg(long)]
    config: Option<String>,
    // path to the encoded trace file
    #[arg(short, long)]
    encoded_trace: Option<String>,
    // path to the binary file
    #[arg(long)]
    application_binary: Option<String>,
    // path to the sbi binary file
    #[arg(long)]
    sbi_binary: Option<String>,
    // path to the kernel binary file
    #[arg(long)]
    kernel_binary: Option<String>,
    // optionally write the final receiver config to JSON
    #[arg(long)]
    dump_effective_config: Option<String>,
    // print the header configuration and exit
    #[arg(long)]
    header_only: Option<bool>,
    // output the decoded trace in stats format
    #[arg(long)]
    to_stats: Option<bool>,
    // output the decoded trace in text format
    #[arg(long)]
    to_txt: Option<bool>,
    // output the tracked callstack in text format
    #[arg(long)]
    to_stack_txt: Option<bool>,
    // output a trace of atomic operations in text format
    #[arg(long)]
    to_atomics: Option<bool>,
    // output the decoded trace in afdo format
    #[arg(long)]
    to_afdo: Option<bool>,
    // path to the gcno file, must be provided if to_afdo is true
    #[arg(long)]
    gcno: Option<String>,
    // output the decoded trace in gcda format
    #[arg(long)]
    to_gcda: Option<bool>,
    // output the decoded trace in speedscope format
    #[arg(long)]
    to_speedscope: Option<bool>,
    // output the decoded trace in perfetto format
    #[arg(long)]
    to_perfetto: Option<bool>,
    // output the decoded trace in vpp format
    #[arg(long)]
    to_vpp: Option<bool>,
    // output the decoded trace in foc format
    #[arg(long)]
    to_foc: Option<bool>,
    // output the decoded trace in vbb format
    #[arg(long)]
    to_vbb: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct DecoderStaticCfg {
    encoded_trace: String,
    application_binary: String,
    sbi_binary: String,
    kernel_binary: String,
    kernel_jump_label_patch_log: String,
    driver_binary_entry_tuples: Vec<(String, String)>,
    header_only: bool,
    to_stats: bool,
    to_txt: bool,
    to_stack_txt: bool,
    to_atomics: bool,
    to_afdo: bool,
    gcno: String,
    to_gcda: bool,
    to_speedscope: bool,
    to_perfetto: bool,
    to_vpp: bool,
    to_foc: bool,
    to_vbb: bool,
}

fn load_file_config(path: &str) -> Result<DecoderStaticCfg> {
    let f = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(f);
    let cfg: DecoderStaticCfg = serde_json::from_reader(reader)?;
    Ok(cfg)
}

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
        bus.broadcast(Entry::new_insn(insn, pc));
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
        bus.broadcast(Entry::new_insn(insn, pc));
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

// frontend decoding packets and pushing entries to the bus
fn trace_decoder(static_cfg: DecoderStaticCfg, runtime_cfg: DecoderRuntimeCfg, mut bus: Bus<Entry>) -> Result<()> {
    let mut u_elf_file = File::open(static_cfg.application_binary.clone())?;
    let mut u_elf_buffer = Vec::new();
    u_elf_file.read_to_end(&mut u_elf_buffer)?;
    let u_elf = object::File::parse(&*u_elf_buffer)?;
    let u_elf_arch = u_elf.architecture();

    let xlen = if u_elf_arch == object::Architecture::Riscv64 {
        Xlen::XLEN64
    } else if u_elf_arch == object::Architecture::Riscv32 {
        Xlen::XLEN32
    } else {
        panic!("Unsupported architecture: {:?}", u_elf_arch);
    };

    let dasm = Disassembler::new(xlen);
     
    /* produce the instruction maps for all ELF files */

    // user-space instruction map
    let mut u_insn_map = HashMap::new();
    for section in u_elf.sections() {
        if let object::SectionFlags::Elf { sh_flags } = section.flags() {
            if sh_flags & (SHF_EXECINSTR as u64) != 0 {
                let addr = section.address();
                let data = section.data()?;
                let sec_map = dasm.disassemble_all(&data, addr);
                debug!(
                    "user applicationsection `{}` @ {:#x}: {} insns",
                    section.name().unwrap_or("<unnamed>"),
                    addr,
                    sec_map.len()
                );
                u_insn_map.extend(sec_map);
            }
        }
    }
    if u_insn_map.is_empty() {
        return Err(anyhow::anyhow!(
            "No executable instructions found in ELF file"
        ));
    }
    debug!("[main] found {} instructions", u_insn_map.len());


    // kernel-space instruction map
    let mut k_elf_file = File::open(static_cfg.kernel_binary.clone())?;
    let mut k_elf_buffer = Vec::new();
    k_elf_file.read_to_end(&mut k_elf_buffer)?;
    let k_elf = object::File::parse(&*k_elf_buffer)?;
    let k_elf_arch = k_elf.architecture();
    assert!(k_elf_arch == u_elf_arch, "Kernel and user ELF architectures must match");
    
    let mut k_insn_map = HashMap::new();
    for section in k_elf.sections() {
        if let object::SectionFlags::Elf { sh_flags } = section.flags() {
            if sh_flags & (SHF_EXECINSTR as u64) != 0 {
                let addr = section.address();
                let data = section.data()?;
                let sec_map = dasm.disassemble_all(&data, addr);
                debug!(
                    "kernel binary section `{}` @ {:#x}: {} insns",
                    section.name().unwrap_or("<unnamed>"),
                    addr,
                    sec_map.len()
                );
                k_insn_map.extend(sec_map);
            }
        }
    }
    if k_insn_map.is_empty() {
        return Err(anyhow::anyhow!("No executable instructions found in ELF file"));
    }

    debug!("[main] found {} kernel-space instructions", k_insn_map.len());

    /* read the jump label patch log
    example line: ffffffff800033f4,00000013
    */
    let jump_label_patch_log = File::open(static_cfg.kernel_jump_label_patch_log.clone())?;
    let jump_label_patch_log_reader = BufReader::new(jump_label_patch_log);
    for line in jump_label_patch_log_reader.lines() {
        let line = line?;
        let parts = line.split(",").collect::<Vec<&str>>();
        let addr = u64::from_str_radix(parts[0], 16)?;
        let raw_insn = u32::from_str_radix(parts[1], 16)?;
        let new_insn = dasm.disassmeble_one(raw_insn).unwrap();
        // replace the insn with the new insn
        k_insn_map.insert(addr, new_insn);
    }

    debug!("[main] patched kernel-space instructions");

    // driver-space instruction map, add to k_insn_map
    for (binary, entry) in static_cfg.driver_binary_entry_tuples {
        let mut driver_elf_file = File::open(binary.clone())?;
        let mut driver_elf_buffer = Vec::new();
        driver_elf_file.read_to_end(&mut driver_elf_buffer)?;
        let driver_elf = object::File::parse(&*driver_elf_buffer)?;
        let driver_elf_arch = driver_elf.architecture();
        assert!(driver_elf_arch == u_elf_arch, "Driver and user ELF architectures must match");
        let driver_text_section = driver_elf.section_by_name(".text").ok_or_else(|| anyhow::anyhow!("No .text section found"))?;
        let driver_text_data = driver_text_section.data()?;
        let driver_entry_point = u64::from_str_radix(entry.trim_start_matches("0x"), 16)?;
        let driver_insn_map = dasm.disassemble_all(&driver_text_data, driver_entry_point);
        debug!(
            "driver binary `{}` @ {:#x}: {} insns",
            binary, driver_entry_point, driver_insn_map.len()
        );
        k_insn_map.extend(driver_insn_map);
    }

    // machine-space instruction map
    let mut m_elf_file = File::open(static_cfg.sbi_binary.clone())?;
    let mut m_elf_buffer = Vec::new();
    m_elf_file.read_to_end(&mut m_elf_buffer)?;
    let m_elf = object::File::parse(&*m_elf_buffer)?;
    let m_elf_arch = m_elf.architecture();
    assert!(m_elf_arch == u_elf_arch, "Machine and user ELF architectures must match");
    let m_text_section = m_elf.section_by_name(".text").ok_or_else(|| anyhow::anyhow!("No .text section found"))?;
    let m_text_data = m_text_section.data()?;
    let m_entry_point = m_elf.entry();
    
    let m_insn_map = dasm.disassemble_all(&m_text_data, m_entry_point);
    if m_insn_map.is_empty() {
        return Err(anyhow::anyhow!("No executable instructions found in ELF file"));
    }
    debug!("[main] found {} machine-space instructions", m_insn_map.len());

    /* ingest the trace stream */

    let encoded_trace_file = File::open(static_cfg.encoded_trace.clone())?;
    let mut encoded_trace_reader: BufReader<File> = BufReader::new(encoded_trace_file);

    // read the first packet
    let (first_packet, _) = frontend::packet::read_first_packet(&mut encoded_trace_reader)?;

    if static_cfg.header_only {
        println!("Printing header configuration: {:?}", runtime_cfg);
        println!("Printing first packet: {:?}", first_packet);
        println!("Printing starting address: 0x{:x}", refund_addr(first_packet.target_address));
        println!("Printing starting prv: {:?}", first_packet.target_prv);
        std::process::exit(0);
    }

    let mut bp_counter = BpDoubleSaturatingCounter::new(runtime_cfg.bp_entries);

    let br_mode = runtime_cfg.br_mode;
    let mode_is_predict = br_mode == BrMode::BrPredict || br_mode == BrMode::BrHistory;

    let mut packet_count = 0;

    trace!("first packet: {:?}", first_packet);
    let mut pc = refund_addr(first_packet.target_address);
    let mut timestamp = first_packet.timestamp;
    let mut prv = first_packet.target_prv;
    bus.broadcast(Entry::new_timed_event(
        Event::Start,
        first_packet.timestamp,
        pc,
        0,
    ));

    let get_insn_map = |prv: Prv| -> &HashMap<u64, Insn> {
        trace!("getting insn map for prv: {:?}", prv);
        match prv {
            Prv::PrvUser => &u_insn_map,
            Prv::PrvSupervisor => &k_insn_map,
            Prv::PrvMachine => &m_insn_map,
            _ => panic!("Invalid Prv: {:?}", prv),
        }
    };

    while let Ok(packet) = frontend::packet::read_packet(&mut encoded_trace_reader) {
        packet_count += 1;
        // special handling for the last packet, should be unlikely hinted
        debug!("[{}]: packet: {:?}", packet_count, packet);
        if packet.f_header == FHeader::FSync {
            pc = step_bb_until(pc, get_insn_map(prv), refund_addr(packet.target_address), &mut bus);
            println!("detected FSync packet, trace ending!");
            bus.broadcast(Entry::new_timed_event(Event::End, packet.timestamp, pc, 0));
            break;
        } else if packet.f_header == FHeader::FTrap {
            pc = step_bb_until(pc, get_insn_map(prv), refund_addr(packet.from_address), &mut bus);
            pc = refund_addr(packet.target_address ^ (pc >> 1));
            debug!("pc after FTrap packet: {:x}", pc);
            // assert!(prv == packet.from_prv, "prv mismatch in FTrap packet, expected {:?}, got {:?}", packet.from_prv, prv);
            prv = packet.target_prv;
            timestamp += packet.timestamp;
            if let frontend::packet::SubFunc3::TrapType(trap_type) = packet.func3 {
                bus.broadcast(Entry::new_timed_trap(
                    trap_type,
                    timestamp,
                    refund_addr(packet.from_address),
                    pc,
                ));
            } else {
                panic!("Invalid SubFunc3 for FTrap packet: {:?}", packet.func3);
            }
        } else if mode_is_predict && packet.f_header == FHeader::FTb {
            // predicted hit
            bus.broadcast(Entry::new_timed_event(
                Event::BPHit,
                packet.timestamp,
                pc,
                pc,
            ));
            // predict for timestamp times
            for _ in 0..packet.timestamp {
                pc = step_bb(pc, get_insn_map(prv), &mut bus, &br_mode);
                let insn_to_resolve = get_insn_map(prv).get(&pc).unwrap();
                if !BRANCH_OPCODES.contains(&insn_to_resolve.get_name().as_str()) {
                    bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                    panic!(
                        "pc: {:x}, timestamp: {}, insn: {:?}",
                        pc, timestamp, insn_to_resolve
                    );
                }
                let taken = bp_counter.predict(pc, true);
                if taken {
                    let new_pc = (pc as i64
                        + insn_to_resolve.get_imm().unwrap().get_val_signed_imm() as i64)
                        as u64;
                    bus.broadcast(Entry::new_timed_event(
                        Event::TakenBranch,
                        timestamp,
                        pc,
                        new_pc,
                    ));
                    pc = new_pc;
                } else {
                    let new_pc = pc + insn_to_resolve.len as u64;
                    bus.broadcast(Entry::new_timed_event(
                        Event::NonTakenBranch,
                        timestamp,
                        pc,
                        new_pc,
                    ));
                    pc = new_pc;
                }
            }
        } else if mode_is_predict && packet.f_header == FHeader::FNt {
            // predicted miss
            timestamp += packet.timestamp;
            bus.broadcast(Entry::new_timed_event(Event::BPMiss, timestamp, pc, pc));
            pc = step_bb(pc, get_insn_map(prv), &mut bus, &br_mode);
            let insn_to_resolve = get_insn_map(prv).get(&pc).unwrap();
            if !BRANCH_OPCODES.contains(&insn_to_resolve.get_name().as_str()) {
                bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                panic!(
                    "pc: {:x}, timestamp: {}, insn: {:?}",
                    pc, timestamp, insn_to_resolve
                );
            }
            let taken = bp_counter.predict(pc, false);
            if !taken {
                // reverse as we mispredicted
                let new_pc = (pc as i64
                    + insn_to_resolve.get_imm().unwrap().get_val_signed_imm() as i64)
                    as u64;
                bus.broadcast(Entry::new_timed_event(
                    Event::TakenBranch,
                    timestamp,
                    pc,
                    new_pc,
                ));
                pc = new_pc;
            } else {
                let new_pc = pc + insn_to_resolve.len as u64;
                bus.broadcast(Entry::new_timed_event(
                    Event::NonTakenBranch,
                    timestamp,
                    pc,
                    new_pc,
                ));
                pc = new_pc;
            }
        } else {
            // trace!("pc before step_bb: {:x}", pc);
            pc = step_bb(pc, get_insn_map(prv), &mut bus, &br_mode);
            let insn_to_resolve = get_insn_map(prv).get(&pc).unwrap();
            // trace!("pc after step_bb: {:x}", pc);
            timestamp += packet.timestamp;
            match packet.f_header {
                FHeader::FTb => {
                    if !BRANCH_OPCODES.contains(&insn_to_resolve.get_name().as_str()) {
                        bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                        panic!(
                            "pc: {:x}, timestamp: {}, insn: {:?}",
                            pc, timestamp, insn_to_resolve
                        );
                    }
                    let new_pc = (pc as i64
                        + insn_to_resolve.get_imm().unwrap().get_val_signed_imm() as i64)
                        as u64;
                    bus.broadcast(Entry::new_timed_event(
                        Event::TakenBranch,
                        timestamp,
                        pc,
                        new_pc,
                    ));
                    // trace!("pc before br: {:x}, after taken branch: {:x}", pc, new_pc);
                    pc = new_pc;
                }
                FHeader::FNt => {
                    if !BRANCH_OPCODES.contains(&insn_to_resolve.get_name().as_str()) {
                        bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                        panic!(
                            "pc: {:x}, timestamp: {}, insn: {:?}",
                            pc, timestamp, insn_to_resolve
                        );
                    }
                    let new_pc = pc + insn_to_resolve.len as u64;
                    bus.broadcast(Entry::new_timed_event(
                        Event::NonTakenBranch,
                        timestamp,
                        pc,
                        new_pc,
                    ));
                    // trace!("pc before nt: {:x}, after nt: {:x}", pc, new_pc);
                    pc = new_pc;
                }
                FHeader::FIj => {
                    if !IJ_OPCODES.contains(&insn_to_resolve.get_name().as_str()) {
                        bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                        panic!(
                            "pc: {:x}, timestamp: {}, insn: {:?}",
                            pc, timestamp, insn_to_resolve
                        );
                    }
                    let new_pc = (pc as i64
                        + insn_to_resolve.get_imm().unwrap().get_val_signed_imm() as i64)
                        as u64;
                    bus.broadcast(Entry::new_timed_event(
                        Event::InferrableJump,
                        timestamp,
                        pc,
                        new_pc,
                    ));
                    // trace!("pc before ij: {:x}, after ij: {:x}", pc, new_pc);
                    pc = new_pc;
                }
                FHeader::FUj => {
                    if !UJ_OPCODES.contains(&insn_to_resolve.get_name().as_str()) {
                        bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                        panic!(
                            "pc: {:x}, timestamp: {}, insn: {:?}",
                            pc, timestamp, insn_to_resolve
                        );
                    }
                    let new_pc = refund_addr(packet.target_address ^ (pc >> 1));
                    bus.broadcast(Entry::new_timed_event(
                        Event::UninferableJump,
                        timestamp,
                        pc,
                        new_pc,
                    ));
                    // trace!("pc before uj: {:x}, after uj: {:x}", pc, new_pc);
                    pc = new_pc;
                }
                _ => {
                    bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                    panic!("unknown FHeader: {:?}", packet.f_header);
                }
            }
        }
    }

    drop(bus);
    println!("[Success] Decoded {} packets", packet_count);

    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    // If a config file is supplied, use it for receiver toggles (CLI still supplies paths).
    let file_cfg= if let Some(path) = &args.config {
        load_file_config(path)?
    } else {
        DecoderStaticCfg::default()
    };


    fn pick_arg<T: Clone>(cli: Option<T>, file: T) -> T {
        cli.unwrap_or(file)
    }

    // Resolve toggles: config file takes precedence if provided; otherwise use CLI flags
    let encoded_trace = pick_arg(args.encoded_trace, file_cfg.encoded_trace);
    let application_binary = pick_arg(args.application_binary, file_cfg.application_binary);
    let kernel_binary = pick_arg(args.kernel_binary, file_cfg.kernel_binary);
    let kernel_jump_label_patch_log = file_cfg.kernel_jump_label_patch_log;
    let driver_binary_entry_tuples = file_cfg.driver_binary_entry_tuples;
    let sbi_binary = pick_arg(args.sbi_binary, file_cfg.sbi_binary);
    let header_only = pick_arg(args.header_only, file_cfg.header_only);
    let to_stats = pick_arg(args.to_stats, file_cfg.to_stats);
    let to_txt = pick_arg(args.to_txt, file_cfg.to_txt);
    let to_stack_txt = pick_arg(args.to_stack_txt, file_cfg.to_stack_txt);
    let to_atomics = pick_arg(args.to_atomics, file_cfg.to_atomics);
    let to_afdo = pick_arg(args.to_afdo, file_cfg.to_afdo);
    let gcno_path = pick_arg(args.gcno, file_cfg.gcno);
    let to_gcda = pick_arg(args.to_gcda, file_cfg.to_gcda);
    let to_speedscope = pick_arg(args.to_speedscope, file_cfg.to_speedscope);
    let to_perfetto = pick_arg(args.to_perfetto, file_cfg.to_perfetto);
    let to_vpp = pick_arg(args.to_vpp, file_cfg.to_vpp);
    let to_foc = pick_arg(args.to_foc, file_cfg.to_foc);
    let to_vbb = pick_arg(args.to_vbb, file_cfg.to_vbb);
    let static_cfg = DecoderStaticCfg { encoded_trace, application_binary, kernel_binary, kernel_jump_label_patch_log, driver_binary_entry_tuples, sbi_binary, header_only, to_stats, to_txt, to_stack_txt, to_atomics, to_afdo, gcno: gcno_path.clone(), to_gcda, to_speedscope, to_perfetto, to_vpp, to_foc, to_vbb };

    // verify the binary exists and is a file
    if !Path::new(&static_cfg.application_binary).exists() || !Path::new(&static_cfg.application_binary).is_file() {
        return Err(anyhow::anyhow!("Application binary file is not valid: {}", static_cfg.application_binary));
    }
    if static_cfg.sbi_binary != "" && !Path::new(&static_cfg.sbi_binary).exists() || !Path::new(&static_cfg.sbi_binary).is_file() {
        return Err(anyhow::anyhow!("SBI binary file is not valid: {}", static_cfg.sbi_binary));
    }
    if static_cfg.kernel_binary != "" && !Path::new(&static_cfg.kernel_binary).exists() || !Path::new(&static_cfg.kernel_binary).is_file() {
        return Err(anyhow::anyhow!("Kernel binary file is not valid: {}", static_cfg.kernel_binary));
    }

    // verify the encoded trace exists and is a file
    if !Path::new(&static_cfg.encoded_trace).exists() || !Path::new(&static_cfg.encoded_trace).is_file() {
        return Err(anyhow::anyhow!("Encoded trace file is not valid: {}", static_cfg.encoded_trace));
    }

    if let Some(path) = &args.dump_effective_config {
        let mut f = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(&mut f, &static_cfg)?;
    }


    let (_, runtime_cfg) = {
        let trace_file = File::open(static_cfg.encoded_trace.clone())?;
        let mut trace_reader = BufReader::new(trace_file);
        frontend::packet::read_first_packet(&mut trace_reader)?
    };

    let mut bus: Bus<Entry> = Bus::new(BUS_SIZE);
    let mut receivers: Vec<Box<dyn AbstractReceiver>> = vec![];

    // add a receiver to the bus for stats output
    if to_stats {
        let encoded_trace_file = File::open(static_cfg.encoded_trace.clone())?;
        // get the file size
        let file_size = encoded_trace_file.metadata()?.len();
        // close the file
        drop(encoded_trace_file);
        let stats_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(StatsReceiver::new(
            stats_bus_endpoint,
            runtime_cfg.br_mode,
            file_size,
        )));
    }

    // add a receiver to the bus for txt output
    if to_txt {
        let txt_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(TxtReceiver::new(txt_bus_endpoint)));
    }

    if to_stack_txt {
        let stack_txt_rx = StackTxtReceiver::new(bus.add_rx(), static_cfg.application_binary.clone());
        receivers.push(Box::new(stack_txt_rx));
    }

    if to_atomics {
        let atomic_rx = AtomicReceiver::new(bus.add_rx(), static_cfg.application_binary.clone());
        receivers.push(Box::new(atomic_rx));
    }

    if to_afdo {
        let afdo_bus_endpoint = bus.add_rx();
        let mut elf_file = File::open(static_cfg.application_binary.clone())?;
        let mut elf_buffer = Vec::new();
        elf_file.read_to_end(&mut elf_buffer)?;
        let elf = object::File::parse(&*elf_buffer)?;
        receivers.push(Box::new(AfdoReceiver::new(
            afdo_bus_endpoint,
            elf.entry().clone(),
        )));
        drop(elf_file);
    }

    if to_gcda {
        let gcda_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(GcdaReceiver::new(
            gcda_bus_endpoint,
            gcno_path.clone(),
            static_cfg.application_binary.clone(),
        )));
    }

    if to_speedscope {
        let speedscope_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(SpeedscopeReceiver::new(
            speedscope_bus_endpoint,
            static_cfg.application_binary.clone(),
        )));
    }

    if to_perfetto {
        let perfetto_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(PerfettoReceiver::new(
            perfetto_bus_endpoint,
            static_cfg.application_binary.clone(),
        )));
    }

    if to_vpp {
        let vpp_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(VPPReceiver::new(
            vpp_bus_endpoint,
            static_cfg.application_binary.clone(),
            runtime_cfg.br_mode == BrMode::BrTarget,
        )));
    }

    if to_foc {
        let foc_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(FOCReceiver::new(
            foc_bus_endpoint,
            static_cfg.application_binary.clone(),
        )));
    }

    if to_vbb {
        let vbb_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(VBBReceiver::new(vbb_bus_endpoint)));
    }

    let frontend_handle =
        thread::spawn(move || trace_decoder(static_cfg.clone(), runtime_cfg.clone(), bus));
    let receiver_handles: Vec<_> = receivers
        .into_iter()
        .map(|mut receiver| thread::spawn(move || receiver.try_receive_loop()))
        .collect();

    // Handle frontend thread
    match frontend_handle.join() {
        Ok(result) => result?,
        Err(e) => {
            // still join the receivers
            for handle in receiver_handles {
                handle.join().unwrap();
            }
            println!("frontend thread panicked: {:?}", e);
            return Err(anyhow::anyhow!("Frontend thread panicked: {:?}", e));
        }
    }

    // Handle receiver threads
    for (i, handle) in receiver_handles.into_iter().enumerate() {
        if let Err(e) = handle.join() {
            return Err(anyhow::anyhow!("Receiver thread {} panicked: {:?}", i, e));
        }
    }

    Ok(())
}
