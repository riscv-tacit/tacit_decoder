use crate::common::prv::*;
use crate::common::static_cfg::DecoderStaticCfg;
use anyhow::Result;
use log::debug;
use object::elf::SHF_EXECINSTR;
use object::{Object, ObjectSection};
use rvdasm::disassembler::*;
use rvdasm::insn::Insn;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};

pub struct InstructionIndex {
    u_insn_map: HashMap<u64, Insn>,
    k_insn_map: HashMap<u64, Insn>,
    m_insn_map: HashMap<u64, Insn>,
}

impl InstructionIndex {
    pub fn get(&self, space: Prv) -> &HashMap<u64, Insn> {
        match space {
            Prv::PrvUser => &self.u_insn_map,
            Prv::PrvSupervisor => &self.k_insn_map,
            Prv::PrvMachine => &self.m_insn_map,
            _ => panic!("Unsupported privilege level: {:?}", space),
        }
    }
}

pub fn build_instruction_index(cfg: DecoderStaticCfg) -> Result<InstructionIndex> {
    // Determine architecture and create a disassembler from the application binary
    let mut u_elf_file = File::open(cfg.application_binary)?;
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

    // User-space instruction map
    let mut u_insn_map = HashMap::new();
    for section in u_elf.sections() {
        if let object::SectionFlags::Elf { sh_flags } = section.flags() {
            if sh_flags & (SHF_EXECINSTR as u64) != 0 {
                let addr = section.address();
                let data = section.data()?;
                let sec_map = dasm.disassemble_all(&data, addr);
                debug!(
                    "user application section `{}` @ {:#x}: {} insns",
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
            "No executable instructions found in app ELF"
        ));
    }

    let mut k_insn_map = HashMap::new();
    // Kernel-space instruction map
    if cfg.kernel_binary != "" {
        let mut k_elf_file = File::open(cfg.kernel_binary)?;
        let mut k_elf_buffer = Vec::new();
        k_elf_file.read_to_end(&mut k_elf_buffer)?;
        let k_elf = object::File::parse(&*k_elf_buffer)?;
        let k_elf_arch = k_elf.architecture();
        assert!(
            k_elf_arch == u_elf_arch,
            "Kernel and user ELF architectures must match"
        );

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
            return Err(anyhow::anyhow!(
                "No executable instructions found in kernel ELF"
            ));
        }

        // Apply kernel jump label patch log
        if cfg.kernel_jump_label_patch_log != "" {
            let jump_label_patch_log = File::open(cfg.kernel_jump_label_patch_log)?;
            let jump_label_patch_log_reader = BufReader::new(jump_label_patch_log);
            for line in jump_label_patch_log_reader.lines() {
                let line = line?;
                let parts = line.split(',').collect::<Vec<&str>>();
                let addr = u64::from_str_radix(parts[0], 16)?;
                let raw_insn = u32::from_str_radix(parts[1], 16)?;
                let new_insn = dasm.disassmeble_one(raw_insn).unwrap();
                k_insn_map.insert(addr, new_insn);
            }
            debug!("[insn_index] patched kernel-space instructions");
        }

        // Merge driver instruction maps into kernel map
        for (binary, entry) in cfg.driver_binary_entry_tuples {
            let mut driver_elf_file = File::open(binary.clone())?;
            let mut driver_elf_buffer = Vec::new();
            driver_elf_file.read_to_end(&mut driver_elf_buffer)?;
            let driver_elf = object::File::parse(&*driver_elf_buffer)?;
            let driver_elf_arch = driver_elf.architecture();
            assert!(
                driver_elf_arch == u_elf_arch,
                "Driver and user ELF architectures must match"
            );
            let driver_text_section = driver_elf
                .section_by_name(".text")
                .ok_or_else(|| anyhow::anyhow!("No .text section found"))?;
            let driver_text_data = driver_text_section.data()?;
            let driver_entry_point = u64::from_str_radix(entry.trim_start_matches("0x"), 16)?;
            let driver_insn_map = dasm.disassemble_all(&driver_text_data, driver_entry_point);
            debug!(
                "driver binary `{}` @ {:#x}: {} insns",
                binary,
                driver_entry_point,
                driver_insn_map.len()
            );
            k_insn_map.extend(driver_insn_map);
        }
    }

    let mut m_insn_map = HashMap::new();
    if cfg.sbi_binary != "" {
        // Machine-space instruction map (SBI)
        let mut m_elf_file = File::open(cfg.sbi_binary)?;
        let mut m_elf_buffer = Vec::new();
        m_elf_file.read_to_end(&mut m_elf_buffer)?;
        let m_elf = object::File::parse(&*m_elf_buffer)?;
        let m_elf_arch = m_elf.architecture();
        assert!(
            m_elf_arch == u_elf_arch,
            "Machine and user ELF architectures must match"
        );
        let m_text_section = m_elf
            .section_by_name(".text")
            .ok_or_else(|| anyhow::anyhow!("No .text section found"))?;
        let m_text_data = m_text_section.data()?;
        let m_entry_point = m_elf.entry();
        m_insn_map = dasm.disassemble_all(&m_text_data, m_entry_point);
        if m_insn_map.is_empty() {
            return Err(anyhow::anyhow!(
                "No executable instructions found in SBI ELF"
            ));
        }
        debug!(
            "[insn_index] found {} machine-space instructions",
            m_insn_map.len()
        );
    }

    Ok(InstructionIndex {
        u_insn_map,
        k_insn_map,
        m_insn_map,
    })
}
