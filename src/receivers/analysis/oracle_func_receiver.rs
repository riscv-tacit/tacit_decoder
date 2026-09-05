use crate::backend::event::Entry;
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use crate::receivers::oracle_func::FuncSink;
use crate::receivers::oracle_match::OracleMatcher;
use bus::BusReader;
use std::sync::Arc;

/* Function-level epsilon for the decoded TACIT stream against the oracle.
 * The emulated formats get the same measurement through
 * emulation/oracle_func_analyzer.rs. See oracle_func.rs for the metric.
 *
 * Config: {"path": "bboracle_boundary.csv.zst", "asids": [125],
 *          "dump": "frames.csv", "top_n": 15}
 */
pub struct OracleFuncReceiver {
    receiver: BusReceiver,
    matcher: OracleMatcher<FuncSink>,
}

pub fn factory(
    shared: &Shared,
    config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let label = config
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("tacit")
        .to_string();
    let sink = FuncSink::new(&config, Arc::clone(&shared.symbol_index));
    Box::new(OracleFuncReceiver {
        receiver: BusReceiver {
            name: "oracle_func".to_string(),
            bus_rx,
            checksum: 0,
        },
        matcher: OracleMatcher::from_config(format!("oracle_func/{}", label), &config, sink),
    })
}

crate::register_receiver!("oracle_func", factory);

impl AbstractReceiver for OracleFuncReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }
    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }
    fn _receive_entry(&mut self, entry: Entry) {
        if let Entry::Event { timestamp, kind } = entry {
            self.matcher.push(timestamp, &kind);
        }
    }
    fn _flush(&mut self) {
        self.matcher.finish();
    }
}
