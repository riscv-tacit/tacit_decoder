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

use log::{debug, warn};

use crate::backend::stack_unwinder::StackUnwinder;

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
    profile_entries: Vec<ProfileEntry>,
    stack_unwinder: StackUnwinder,
}

impl SpeedscopeReceiver {
    
    pub fn new(bus_rx: BusReader<Entry>, elf_path: String) -> Self {
        debug!("SpeedscopeReceiver::new");
        
        // create the stack unwinder
        let stack_unwinder = StackUnwinder::new(elf_path.clone()).unwrap();

        // Load the schema from the file
        let schema_file = File::open("src/backend/speedoscope-schema.json").unwrap();
        let schema_value: Value = serde_json::from_reader(schema_file).unwrap();
        let schema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(&schema_value)
            .unwrap();

        // for each function symbol, add a frame to the frames vector
        let mut frames = Vec::new();
        for (_, func_info) in stack_unwinder.func_symbol_map().iter() {
            frames.push(json!({"name": func_info.name, "line": func_info.line, "file": func_info.file}));
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
            stack_unwinder,
            profile_entries: Vec::new(),
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
                let (success, frame_stack_size, opened_frame) = self.stack_unwinder.step_ij(entry.clone());
                if success {
                    self.profile_entries.push(ProfileEntry {
                        r#type: "O".to_string(), // opening a frame
                        frame: opened_frame.unwrap().index,
                        at: entry.timestamp.unwrap(),
                    });
                }
            }
            Event::UninferableJump => {
                let (success, frame_stack_size, closed_frames) = self.stack_unwinder.step_uj(entry.clone());
                if success {
                    for frame in closed_frames {
                        self.profile_entries.push(ProfileEntry {
                            r#type: "C".to_string(), // closing a frame
                            frame: frame.index,
                            at: entry.timestamp.unwrap(),
                        });
                    }
                }
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
        // forcefully close all open frames
        let closed_frames = self.stack_unwinder.flush();
        for frame in closed_frames {
            self.profile_entries.push(ProfileEntry {
                r#type: "C".to_string(), // closing a frame
                frame: frame.index,
                at: self.end,
            });
        }
        
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
