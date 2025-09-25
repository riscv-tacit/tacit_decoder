use addr2line::Loader;
use anyhow::Result;
use log::{debug, warn};
use object::elf::SHF_EXECINSTR;
use object::{Object, ObjectSection, ObjectSymbol, SectionFlags};
use std::collections::BTreeMap;
use std::fs;

use crate::common::prv::Prv;
use crate::common::source_location::SourceLocation;
use crate::common::static_cfg::DecoderStaticCfg;

// everything you need to know about a symbol
#[derive(Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub src: SourceLocation,
    pub prv: Prv,
}

pub struct SymbolIndex {
    // use BTreeMap as symbol maps need to be ordered
    u_symbol_map: BTreeMap<u64, SymbolInfo>,
    k_symbol_map: BTreeMap<u64, SymbolInfo>,
    m_symbol_map: BTreeMap<u64, SymbolInfo>,
}

impl SymbolIndex {
    pub fn get(&self, prv: Prv) -> &BTreeMap<u64, SymbolInfo> {
        match prv {
            Prv::PrvUser => &self.u_symbol_map,
            Prv::PrvSupervisor => &self.k_symbol_map,
            Prv::PrvMachine => &self.m_symbol_map,
            _ => panic!("Unsupported privilege level: {:?}", prv),
        }
    }

    // lookup a symbol by prv and address
    pub fn lookup(&self, prv: Prv, addr: u64) -> Option<&SymbolInfo> {
        self.get(prv).get(&addr)
    }

    /// Return the half-open address range `[start, end)` for the function that
    /// begins at `addr`. The end is the start of the next symbol in that
    /// privilege space, or `u64::MAX` if this is the last symbol.
    pub fn range(&self, prv: Prv, addr: u64) -> Option<(u64, u64)> {
        let map = self.get(prv);

        if !map.contains_key(&addr) {
            return None;
        }

        // Find the symbol that starts at `addr` (or the nearest one <= addr)
        let (&start, _) = map.range(..=addr).next_back()?;

        // End is the next symbol start, if any
        let end = map
            .range((start + 1)..)
            .next()
            .map(|(&next_start, _)| next_start)
            .unwrap_or(u64::MAX);

        Some((start, end))
    }
}
pub fn build_single_symbol_index(elf_path: String, prv: Prv) -> Result<BTreeMap<u64, SymbolInfo>> {
    // open application elf for symbol processing
    let elf_data = fs::read(&elf_path)?;
    let obj_file = object::File::parse(&*elf_data)?;
    let loader = Loader::new(&elf_path).map_err(|e| anyhow::Error::msg(e.to_string()))?;

    // Gather indices of all executable sections
    let exec_secs: std::collections::HashSet<_> = obj_file
        .sections()
        .filter_map(|sec| {
            if let SectionFlags::Elf { sh_flags } = sec.flags() {
                if sh_flags & (SHF_EXECINSTR as u64) != 0 {
                    return Some(sec.index());
                }
            }
            None
        })
        .collect();

    // Build func_symbol_map from _all_ symbols in executable sections
    let mut func_symbol_map: BTreeMap<u64, SymbolInfo> = BTreeMap::new();
    for symbol in obj_file.symbols() {
        // only symbols tied to an exec section
        if let Some(sec_idx) = symbol.section_index() {
            if exec_secs.contains(&sec_idx) {
                if let Ok(name) = symbol.name() {
                    // filter out ghost symbols
                    if !name.starts_with("$x") {
                        let addr = symbol.address();
                        // lookup source location (may return None)
                        if let Ok(Some(loc)) = loader.find_location(addr) {
                            let src: SourceLocation = SourceLocation::from_addr2line(loc, prv);
                            let info = SymbolInfo {
                                name: name.to_string(),
                                src: src,
                                prv: prv,
                            };
                            // dedupe aliases: prefer non‑empty over empty
                            if let Some(existing) = func_symbol_map.get_mut(&addr) {
                                if existing.name.trim().is_empty() && !info.name.trim().is_empty() {
                                    *existing = info;
                                } else {
                                    warn!(
                                  "func_addr 0x{:x} already in map as `{}`, ignoring alias `{}`",
                                  addr, existing.name, info.name
                              );
                                }
                            } else {
                                func_symbol_map.insert(addr, info);
                            }
                        }
                    }
                }
            }
        }
    }
    debug!("func_symbol_map size: {}", func_symbol_map.len());
    Ok(func_symbol_map)
}

pub fn build_symbol_index(cfg: DecoderStaticCfg) -> Result<SymbolIndex> {
    let u_func_symbol_map =
        build_single_symbol_index(cfg.application_binary.clone(), Prv::PrvUser)?;
    let k_func_symbol_map =
        build_single_symbol_index(cfg.application_binary.clone(), Prv::PrvSupervisor)?;
    let m_func_symbol_map =
        build_single_symbol_index(cfg.application_binary.clone(), Prv::PrvMachine)?;
    Ok(SymbolIndex {
        u_symbol_map: u_func_symbol_map,
        k_symbol_map: k_func_symbol_map,
        m_symbol_map: m_func_symbol_map,
    })
}
