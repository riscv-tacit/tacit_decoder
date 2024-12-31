use crate::backend::event::{Entry, Event};
use crate::backend::abstract_receiver::{AbstractReceiver, BusReceiver};
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};
use jsonschema::{JSONSchema, Draft};
use serde_json::{json, Value};
use serde::Serialize;

use indexmap::IndexMap;

use std::fs;
use object::{Object, ObjectSymbol};
use addr2line::Loader;
use gcno_reader::cfg::SourceLocation;

use log::{trace, debug, warn};

// everything you need to know about a symbol
pub struct SymbolInfo {
    name: String,
    index: u32, 
    line: u32,
    file: String,
}

#[derive(Serialize)]
pub struct ProfileEntry {
    r#type: String,
    frame: u32,
    at: u64,
}

pub struct SpeedscopeReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    schema: JSONSchema,
    frames: Vec<Value>, 
    start: u64,
    end: u64,
    func_symbol_map: IndexMap<u64, SymbolInfo>,
    idx_2_addr_range: IndexMap<u32, (u64, u64)>,
    profile_entries: Vec<ProfileEntry>,
    curr_frame: Vec<u32>,

    // book keeping transient states
    prev_insn: Entry,
}

impl SpeedscopeReceiver {
    
    pub fn new(bus_rx: BusReader<Entry>, elf_path: String) -> Self {
        debug!("SpeedscopeReceiver::new");
        // load all function symbols from the binary
        let mut func_symbol_map: IndexMap<u64, SymbolInfo> = IndexMap::new();
        // object handler
        let elf_data = fs::read(elf_path.clone()).unwrap();
        let obj_file = object::File::parse(&*elf_data).unwrap();
        let loader = Loader::new(elf_path.clone()).unwrap();
        let mut next_index = 0;
        for symbol in obj_file.symbols().filter(|s| s.kind() == object::SymbolKind::Text) {
            let func_addr = symbol.address();
            let loc: SourceLocation = SourceLocation::from_addr2line(loader.find_location(func_addr).unwrap());
            let func_info = SymbolInfo {
                name: String::from(symbol.name().unwrap()),
                index: next_index,
                line: loc.lines,
                file: String::from(loc.file),
            };
            debug!("func_info: addr: {:#x}, name: {}, index: {}", func_addr, func_info.name, func_info.index);
            // check if the func_addr is already in the map
            if func_symbol_map.contains_key(&func_addr) {
                warn!("func_addr: {:#x} already in the map with name: {}", func_addr, func_symbol_map[&func_addr].name);
                warn!("{} is alias and will be ignored", func_info.name);
            } else {
                func_symbol_map.insert(func_addr, func_info);
                next_index += 1;
            }
        }
  
        // Load the schema from the file
        let schema_file = File::open("src/backend/speedoscope-schema.json").unwrap();
        let schema_value: Value = serde_json::from_reader(schema_file).unwrap();
        let schema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(&schema_value)
            .unwrap();
        // for each function symbol, add a frame to the frames vector
        let mut frames = Vec::new();
        for (_, func_info) in func_symbol_map.iter() {
            frames.push(json!({"name": func_info.name, "line": func_info.line, "file": func_info.file}));
        }
        // sort the func_symbol_map by address
        let mut func_symbol_addr_sorted = func_symbol_map.keys().cloned().collect::<Vec<u64>>();
        func_symbol_addr_sorted.sort();

        // create the idx_2_addr_range map
        let mut idx_2_addr_range = IndexMap::new();
        for (addr, func_info) in func_symbol_map.iter() {
            let curr_position = func_symbol_addr_sorted.iter().position(|&x| x == *addr).unwrap();
            let next_position = if curr_position == func_symbol_addr_sorted.len() - 1 { 0 } else { curr_position + 1 };
            let next_addr = func_symbol_addr_sorted[next_position];
            idx_2_addr_range.insert(func_info.index, (addr.clone(), next_addr.clone()));
        }

        Self { 
            writer: BufWriter::new(File::create("trace.speedscope.json").unwrap()),
            receiver: BusReceiver { 
                name: "speedscope".to_string(), 
                bus_rx, 
                checksum: 0 
            },
            schema,
            frames,
            start: 0,
            end: 0,
            func_symbol_map: func_symbol_map,
            idx_2_addr_range: idx_2_addr_range,
            profile_entries: Vec::new(),
            prev_insn: Entry::new_timed_event(Event::None, 0, 0, 0), // dummy entry
            curr_frame: Vec::new(),
        }
    }
}

impl AbstractReceiver for SpeedscopeReceiver {

    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry.event {
            Event::InferrableJump => {
                // debug!("Handling jump: {:?}", entry);
                if self.func_symbol_map.contains_key(&entry.arc.1) {
                    let frame_idx = self.func_symbol_map[&entry.arc.1].index;
                    self.curr_frame.push(frame_idx);
                    // debug!("opening frame: {} : {}", frame_idx, self.func_symbol_map[&entry.arc.1].name);
                    self.profile_entries.push(ProfileEntry {
                        r#type: "O".to_string(), // opening a frame
                        frame: frame_idx,
                        at: entry.timestamp.unwrap(),
                    });
                }
            }
            Event::UninferableJump => {
                // check if the previous instruction is a ret or c.jr ra
                if self.prev_insn.insn_mnemonic == Some("ret".to_string()) || (self.prev_insn.insn_mnemonic == Some("c.jr".to_string()) && self.prev_insn.insn_op_str == Some("ra".to_string())) {
                    // we may start with a ret, so we need to check if the current frame is empty
                    let target_frame_addr = entry.arc.1;
                    loop {
                        // debug!("infinite loop?");
                        // peak the top of the stack
                        if let Some(frame_idx) = self.curr_frame.last() {
                            // if this function range is within the target frame range, we can stop
                            let (start, end) = self.idx_2_addr_range[frame_idx];
                            if target_frame_addr >= start && target_frame_addr < end {
                                break;
                            }
                            // if not, pop the stack
                            if let Some(frame_idx) = self.curr_frame.pop() {
                                debug!("closing frame: {}", frame_idx);
                                self.profile_entries.push(ProfileEntry {
                                    r#type: "C".to_string(), // closing a frame
                                    frame: frame_idx,
                                    at: entry.timestamp.unwrap(),
                                });
                            } // if the stack is empty, we are done
                            else {
                                warn!("stack is empty, but target frame is not in the range");
                                break;
                            }
                        } else {
                            warn!("stack is empty, but target frame is not in the range");
                            break;
                        }
                    } 
                    
                }
            }
            Event::None => {
                self.prev_insn = entry;
            }
            Event::Start => {
                // debug!("start: {}", entry.timestamp.unwrap());
                self.start = entry.timestamp.unwrap();
            }
            Event::End => {
                // debug!("end: {}", entry.timestamp.unwrap());
                self.end = entry.timestamp.unwrap();
            }
            _ => {
                // do nothing
            }
        }
    }

    fn _flush(&mut self) {
        debug!("Remaining size of the queue: {}", self.curr_frame.len());
        // forcefully close all open frames
        while let Some(frame_idx) = self.curr_frame.pop() {
            warn!("closing frame: {}", frame_idx);
            self.profile_entries.push(ProfileEntry {
                r#type: "C".to_string(), // closing a frame
                frame: frame_idx,
                at: self.end,
            });
        }
        debug!("Total size of the symbol map: {}", self.func_symbol_map.len());
        // debug the total size of the frames
        debug!("Total size of the frames: {}", self.frames.len());
        
        // Write the JSON structure manually in a deterministic order
        writeln!(self.writer, "{{").unwrap();
        writeln!(self.writer, "  \"version\": \"0.0.1\",").unwrap();
        writeln!(self.writer, "  \"$schema\": \"https://www.speedscope.app/file-format-schema.json\",").unwrap();
        writeln!(self.writer, "  \"shared\": {{").unwrap();
        writeln!(self.writer, "    \"frames\": [").unwrap();
        
        // Write frames in order
        for (i, frame) in self.frames.iter().enumerate() {
            let comma = if i < self.frames.len() - 1 { "," } else { "" };
            writeln!(self.writer, "      {{").unwrap();
            writeln!(self.writer, "        \"name\": \"{}\",", frame["name"].as_str().unwrap()).unwrap();
            writeln!(self.writer, "        \"file\": \"{}\",", frame["file"].as_str().unwrap()).unwrap();
            writeln!(self.writer, "        \"line\": {}", frame["line"].as_u64().unwrap()).unwrap();
            writeln!(self.writer, "      }}{}", comma).unwrap();
        }
        
        writeln!(self.writer, "    ]").unwrap();
        writeln!(self.writer, "  }},").unwrap();
        writeln!(self.writer, "  \"profiles\": [").unwrap();
        writeln!(self.writer, "    {{").unwrap();
        writeln!(self.writer, "      \"name\": \"tacit\",").unwrap();
        writeln!(self.writer, "      \"type\": \"evented\",").unwrap();
        writeln!(self.writer, "      \"unit\": \"none\",").unwrap();
        writeln!(self.writer, "      \"startValue\": {},", self.start).unwrap();
        writeln!(self.writer, "      \"endValue\": {},", self.end).unwrap();
        writeln!(self.writer, "      \"events\": [").unwrap();
        
        // Write profile entries in order
        for (i, entry) in self.profile_entries.iter().enumerate() {
            let comma = if i < self.profile_entries.len() - 1 { "," } else { "" };
            writeln!(self.writer, "        {{").unwrap();
            writeln!(self.writer, "          \"type\": \"{}\",", entry.r#type).unwrap();
            writeln!(self.writer, "          \"frame\": {},", entry.frame).unwrap();
            writeln!(self.writer, "          \"at\": {}", entry.at).unwrap();
            writeln!(self.writer, "        }}{}", comma).unwrap();
        }
        
        writeln!(self.writer, "      ]").unwrap();
        writeln!(self.writer, "    }}").unwrap();
        writeln!(self.writer, "  ]").unwrap();
        writeln!(self.writer, "}}").unwrap();
        
        self.writer.flush().unwrap();
    }
}
