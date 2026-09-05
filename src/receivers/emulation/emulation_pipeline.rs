use crate::backend::event::Entry;
use crate::receivers::abstract_receiver::{AbstractReceiver, Shared};
use crate::receivers::emulation::abstract_emulator::{AbstractEmulatedAnalyzer, AbstractEmulator, EmulationResult};
use crate::receivers::emulation::bb_analyzer::BBAnalyzer;
use crate::receivers::emulation::emulation_receivers::EmulationReceiver;
use crate::receivers::emulation::func_analyzer::FuncAnalyzer;
use crate::receivers::emulation::inclusive_func_analyzer::InclusiveFuncAnalyzer;
use crate::receivers::emulation::oracle_bb_analyzer::OracleBBAnalyzer;
use crate::receivers::emulation::oracle_func_analyzer::OracleFuncAnalyzer;
use crate::receivers::emulation::tc_emulator::TCEmulator;
use crate::receivers::emulation::tnt_cyc_nret_emulator::TNTCycNRETEmulator;
use crate::receivers::emulation::tnt_cyc_retcompressed_emulator::TNTCycRETCompressedEmulator;
use crate::receivers::registry;
use anyhow::{anyhow, bail, Result};
use bus::{Bus, BusReader};
use std::sync::Arc;

// Broadcasts one emulator's pair stream to several pair-consumers.
struct BroadcastAnalyzer {
    consumers: Vec<Box<dyn AbstractEmulatedAnalyzer>>,
}

impl AbstractEmulatedAnalyzer for BroadcastAnalyzer {
    fn push_emulated_event(&mut self, event: EmulationResult) {
        if let Some((last, rest)) = self.consumers.split_last_mut() {
            for consumer in rest {
                consumer.push_emulated_event(event.clone());
            }
            last.push_emulated_event(event);
        }
    }

    fn flush(&mut self) {
        for consumer in self.consumers.iter_mut() {
            consumer.flush();
        }
    }
}

// Projects the emulated half of the pair stream into an ordinary Entry stream
// and drives unchanged AbstractReceivers with it. The receivers are driven
// directly through _receive_entry; their bus readers are inert dummies.
struct FanoutAnalyzer {
    receivers: Vec<Box<dyn AbstractReceiver>>,
}

impl AbstractEmulatedAnalyzer for FanoutAnalyzer {
    fn push_emulated_event(&mut self, event: EmulationResult) {
        let entry = Entry::Event {
            timestamp: event.emu_ts,
            kind: event.event,
        };
        for receiver in self.receivers.iter_mut() {
            receiver._receive_entry(entry.clone());
        }
    }

    fn flush(&mut self) {
        for receiver in self.receivers.iter_mut() {
            receiver._flush();
        }
    }
}

fn enabled(cfg: &serde_json::Value) -> bool {
    cfg.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true)
}

/// Build one emulation pipeline from a spec of the form:
/// {
///   "name": "pt_like",                     // optional, defaults to format
///   "format": "tnt_cyc_retcompressed",     // tnt_cyc_nret | tnt_cyc_retcompressed | tc
///   "lim_tnt": 47,                         // tnt formats; default 6
///   "interval": 1000,                      // tc format; default 1000000
///   "error": {                             // optional pair-consumers
///     "bb": {"path": "..."},            // vs TACIT timestamps
///     "oracle_bb": {"path": "bboracle_boundary.csv.zst", "asids": [125]},
///     "func": {"path": "..."},
///     "inclusive_func": {"path": "..."}
///   },
///   "receivers": {                         // optional chained entry-receivers
///     "speedscope": {"path": "..."},
///     "iteration_breakdown": {...}
///   }
/// }
pub fn build_emulation_pipeline(
    shared: &Shared,
    spec: &serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Result<Box<dyn AbstractReceiver>> {
    let format = spec
        .get("format")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("emulation spec missing 'format'"))?;
    let name = spec
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(format)
        .to_string();

    let mut consumers: Vec<Box<dyn AbstractEmulatedAnalyzer>> = Vec::new();

    if let Some(error_cfg) = spec.get("error").and_then(|v| v.as_object()) {
        for (kind, cfg) in error_cfg {
            if !enabled(cfg) {
                continue;
            }
            let path = cfg.get("path").and_then(|v| v.as_str()).map(|s| s.to_string());
            // a given path implies the caller wants the per-event CSV
            let dump_csv = cfg
                .get("dump_csv")
                .and_then(|v| v.as_bool())
                .unwrap_or(path.is_some());
            let analyzer_name = format!("{}/{}", name, kind);
            let analyzer: Box<dyn AbstractEmulatedAnalyzer> = match kind.as_str() {
                "bb" => Box::new(BBAnalyzer::new(analyzer_name, path, dump_csv)),
                "func" => Box::new(FuncAnalyzer::new(
                    analyzer_name,
                    path,
                    dump_csv,
                    Arc::clone(&shared.symbol_index),
                )),
                "inclusive_func" => Box::new(InclusiveFuncAnalyzer::new(
                    analyzer_name,
                    path,
                    dump_csv,
                    Arc::clone(&shared.symbol_index),
                )),
                // scored against the oracle rather than TACIT, so it takes the
                // whole cfg (path/asids/limit) instead of the path+dump pair
                "oracle_bb" => Box::new(OracleBBAnalyzer::new(analyzer_name, cfg)),
                "oracle_func" => Box::new(OracleFuncAnalyzer::new(
                    analyzer_name,
                    cfg,
                    Arc::clone(&shared.symbol_index),
                )),
                other => bail!("emulation '{}': unknown error analyzer '{}'", name, other),
            };
            consumers.push(analyzer);
        }
    }

    if let Some(receiver_cfg) = spec.get("receivers").and_then(|v| v.as_object()) {
        let mut receivers: Vec<Box<dyn AbstractReceiver>> = Vec::new();
        for (receiver_name, cfg) in receiver_cfg {
            if !enabled(cfg) {
                continue;
            }
            // the receiver never polls this reader; it is driven via _receive_entry
            let mut dummy_bus: Bus<Entry> = Bus::new(1);
            let receiver = registry::make_receiver(receiver_name, shared, cfg.clone(), dummy_bus.add_rx())?;
            receivers.push(receiver);
        }
        if !receivers.is_empty() {
            consumers.push(Box::new(FanoutAnalyzer { receivers }));
        }
    }

    if consumers.is_empty() {
        bail!("emulation '{}' declares no error analyzers and no receivers", name);
    }

    let analyzer: Box<dyn AbstractEmulatedAnalyzer> = if consumers.len() == 1 {
        consumers.pop().unwrap()
    } else {
        Box::new(BroadcastAnalyzer { consumers })
    };

    let emulator: Box<dyn AbstractEmulator> = match format {
        "tnt_cyc_nret" => {
            let lim_tnt = spec.get("lim_tnt").and_then(|v| v.as_u64()).unwrap_or(6);
            Box::new(TNTCycNRETEmulator::new(analyzer, lim_tnt))
        }
        "tnt_cyc_retcompressed" => {
            let lim_tnt = spec.get("lim_tnt").and_then(|v| v.as_u64()).unwrap_or(6);
            Box::new(TNTCycRETCompressedEmulator::new(
                analyzer,
                lim_tnt,
                Arc::clone(&shared.insn_index),
            ))
        }
        "tc" => {
            let interval = spec.get("interval").and_then(|v| v.as_u64()).unwrap_or(1000000);
            Box::new(TCEmulator::new(analyzer, interval))
        }
        other => bail!("emulation '{}': unknown format '{}'", name, other),
    };

    Ok(Box::new(EmulationReceiver::new(
        bus_rx,
        format!("emulation_{}", name),
        emulator,
    )))
}
