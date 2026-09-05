use crate::backend::event::Entry;
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use crate::receivers::oracle_epsilon::OracleEpsilon;
use bus::BusReader;

/* eps(BB) for the decoded TACIT stream itself, against the TraceDoctor
 * oracle. The emulated sparse formats get the same measurement through
 * emulation/oracle_bb_analyzer.rs, which drives the identical core with
 * emu_ts, so all four numbers share a denominator and are directly
 * comparable. See oracle_epsilon.rs for the metric and the pairing rules.
 *
 * Config: {"path": "bboracle_boundary.csv.zst", "asids": [125], "limit": N}
 * `asids` lists the user address spaces the decoder holds binaries for;
 * user-mode rows in any other are dropped (and cannot be compared). `limit`
 * caps oracle rows for a quick windowed run.
 */

pub struct OracleBBReceiver {
    receiver: BusReceiver,
    eps: OracleEpsilon,
}

pub fn factory(
    _shared: &Shared,
    config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let label = config
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("tacit")
        .to_string();
    Box::new(OracleBBReceiver {
        receiver: BusReceiver {
            name: "oracle_bb".to_string(),
            bus_rx,
            checksum: 0,
        },
        eps: OracleEpsilon::from_config(format!("oracle_bb/{}", label), &config),
    })
}

crate::register_receiver!("oracle_bb", factory);

impl AbstractReceiver for OracleBBReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        if let Entry::Event { timestamp, kind } = entry {
            self.eps.push(timestamp, &kind);
        }
    }

    fn _flush(&mut self) {
        self.eps.finish();
    }
}
