extern crate bus;
extern crate clap;
extern crate env_logger;
extern crate gcno_reader;
extern crate indicatif;
extern crate log;
extern crate object;
extern crate rvdasm;
extern crate rustc_data_structures;

mod frontend {
    pub mod bp_double_saturating_counter;
    pub mod br_mode;
    pub mod c_header;
    pub mod ctx_mode;
    pub mod decoder;
    pub mod decoder_cache;
    pub mod f_header;
    pub mod packet;
    pub mod runtime_cfg;
    pub mod sync_type;
    pub mod trap_type;
}

mod receivers;

mod backend {
    pub mod event;
    pub mod stack_unwinder;
}

mod common {
    pub mod insn_index;
    pub mod prv;
    pub mod source_location;
    pub mod static_cfg;
    pub mod symbol_index;
}

// file IO
use std::fs::File;
use std::io::{BufReader, Read};
// argparse dependency
use clap::Parser;
use object::Object;
// path dependency
use std::path::Path;
use std::io::Write;
// bus dependency
use bus::Bus;
use std::thread;
// backend dependency
use backend::event::Entry;
use common::static_cfg::{load_file_config, DecoderStaticCfg};
use receivers::abstract_receiver::AbstractReceiver;
use receivers::registry;
// error handling
use anyhow::Result;

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
    // dump the symbol index to a JSON file
    #[arg(long)]
    dump_symbol_index: Option<String>,
    // print the header configuration and exit
    #[arg(long)]
    header_only: Option<bool>,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    // If a config file is supplied, use it for receiver toggles (CLI still supplies paths).
    let static_cfg = if let Some(path) = &args.config {
        load_file_config(path)?
    } else {
        DecoderStaticCfg::default()
    };

    // verify the binary exists and is a file
    for (binary, _) in static_cfg.application_binary_asid_tuples.clone() {
        if !Path::new(&binary).exists() || !Path::new(&binary).is_file() {
            return Err(anyhow::anyhow!(
                "Application binary file is not valid: {}",
                binary
            ));
        }
    }
    if static_cfg.sbi_binary != ""
        && (!Path::new(&static_cfg.sbi_binary).exists()
            || !Path::new(&static_cfg.sbi_binary).is_file())
    {
        return Err(anyhow::anyhow!(
            "SBI binary file is not valid: {}",
            static_cfg.sbi_binary
        ));
    }
    if static_cfg.kernel_binary != ""
        && (!Path::new(&static_cfg.kernel_binary).exists()
            || !Path::new(&static_cfg.kernel_binary).is_file())
    {
        return Err(anyhow::anyhow!(
            "Kernel binary file is not valid: {}",
            static_cfg.kernel_binary
        ));
    }

    // verify the encoded trace exists and is a file
    if !Path::new(&static_cfg.encoded_trace).exists()
        || !Path::new(&static_cfg.encoded_trace).is_file()
    {
        return Err(anyhow::anyhow!(
            "Encoded trace file is not valid: {}",
            static_cfg.encoded_trace
        ));
    }

    let (first_packet, runtime_cfg) = {
        let trace_file = File::open(static_cfg.encoded_trace.clone())?;
        let mut trace_reader = BufReader::new(trace_file);
        let (first_packet, runtime_cfg) = frontend::packet::read_first_packet(&mut trace_reader)?;
        drop(trace_reader);
        (first_packet, runtime_cfg)
    };

    if static_cfg.header_only {
        println!("Printing header configuration: {:?}", runtime_cfg);
        println!("Printing first packet: {:?}", first_packet);
        println!(
            "Printing starting address: 0x{:x}",
            (first_packet.target_address << 1)
        );
        println!("Printing starting prv: {:?}", first_packet.target_prv);
        std::process::exit(0);
    }

    // Build instruction index once
    // Notice that this operation is very slow for large binaries
    let insn_index = common::insn_index::build_instruction_index(static_cfg.clone())?;
    let insn_index = std::sync::Arc::new(insn_index);

    // Build symbol index once
    let symbol_index = common::symbol_index::build_symbol_index(static_cfg.clone())?;
    let symbol_index = std::sync::Arc::new(symbol_index);

    if let Some(path) = &args.dump_symbol_index {
        let mut f = std::fs::File::create(path)?;
        for (asid, symbol_map) in symbol_index.get_user_symbol_map().iter() {
            for (addr, symbol) in symbol_map.iter() {
                writeln!(f, "{} 0x{:x} {}", symbol.name, addr, asid).unwrap();
            }
        }
        for (addr, symbol) in symbol_index.get_kernel_symbol_map().iter() {
            writeln!(f, "{} 0x{:x} {}", symbol.name, addr, 0).unwrap();
        }
        for (addr, symbol) in symbol_index.get_machine_symbol_map().iter() {
            writeln!(f, "{} 0x{:x} {}", symbol.name, addr, 0).unwrap();
        }
    }

    let mut bus: Bus<Entry> = Bus::new(BUS_SIZE);
    let mut receivers: Vec<Box<dyn AbstractReceiver>> = vec![];

    let receiver_cfg = if let Some(path) = &args.config {
        let f = File::open(path)?;
        let reader = BufReader::new(f);
        let value: serde_json::Value = serde_json::from_reader(reader)?;
        value
            .get("receivers")
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Null)
    } else {
        serde_json::Value::Null
    };

    if !receiver_cfg.is_null() {
        let shared = receivers::abstract_receiver::Shared {
            static_cfg: static_cfg.clone(),
            runtime_cfg: runtime_cfg.clone(),
            symbol_index: None,
            insn_index: None,
        };

        let receiver_map = receiver_cfg.as_object().ok_or_else(|| {
            anyhow::anyhow!("receivers config must be an object map of name -> config")
        })?;
        for (name, cfg) in receiver_map {
            let enabled = cfg
                .get("enabled")
                .and_then(|value| value.as_bool())
                .unwrap_or(true);
            if !enabled {
                continue;
            }
            let bus_rx = bus.add_rx();
            let receiver =
                registry::make_receiver(name, &shared, cfg.clone(), bus_rx)?;
            receivers.push(receiver);
        }
    }

    let encoded_trace_path = static_cfg.encoded_trace.clone();
    let frontend_insn_index = std::sync::Arc::clone(&insn_index);
    let frontend_handle = thread::spawn(move || {
        frontend::decoder::decode_trace(
            encoded_trace_path,
            static_cfg.clone(),
            runtime_cfg.clone(),
            frontend_insn_index,
            bus,
        )
    });
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
