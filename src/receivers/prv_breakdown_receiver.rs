use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use crate::backend::event::{Entry, EventKind};
use bus::BusReader;
use crate::common::prv::Prv;

/* Receiver for answering the question: "How many cycles were executed in each privilege level?" */
pub struct PrvBreakdownReceiver {
    receiver: BusReceiver,
    curr_prv: Prv,
    u_prv_cycles: u64,
    k_prv_cycles: u64,
    m_prv_cycles: u64,
    prev_timestamp: u64,
}

impl PrvBreakdownReceiver {
    pub fn new(bus_rx: BusReader<Entry>) -> Self {
        Self {
            receiver: BusReceiver {
                name: "prv_breakdown".to_string(),
                bus_rx: bus_rx,
                checksum: 0,
            },
            curr_prv: Prv::PrvUser,
            u_prv_cycles: 0,
            k_prv_cycles: 0,
            m_prv_cycles: 0,
            prev_timestamp: 0,
        }
    }
}

pub fn factory(
    _shared: &Shared,
    _config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    Box::new(PrvBreakdownReceiver::new(bus_rx))
}

crate::register_receiver!("prv_breakdown", factory);

impl AbstractReceiver for PrvBreakdownReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry {
            Entry::Event { timestamp, kind: EventKind::SyncStart { start_prv, .. } } => {
                self.curr_prv = start_prv;
                self.prev_timestamp = timestamp;
            }
            Entry::Event { timestamp, kind: EventKind::Trap { prv_arc, .. } } => {
              self.update_prv_cycles(timestamp);
              self.curr_prv = prv_arc.1;
            }
            Entry::Event { timestamp, .. } => {
              self.update_prv_cycles(timestamp);
            }
            Entry::Instruction { .. } => {
              // do nothing
            }
        }
    }

    fn _flush(&mut self) {
      println!("--------------------------------");
      println!("Privilege level breakdown:");
      let total_cycles = self.u_prv_cycles + self.k_prv_cycles + self.m_prv_cycles;
      println!("User privilege level cycles: {} ({:.2}%)", self.u_prv_cycles, self.u_prv_cycles as f64 / total_cycles as f64 * 100.0);
      println!("Supervisor privilege level cycles: {} ({:.2}%)", self.k_prv_cycles, self.k_prv_cycles as f64 / total_cycles as f64 * 100.0);
      println!("Machine privilege level cycles: {} ({:.2}%)", self.m_prv_cycles, self.m_prv_cycles as f64 / total_cycles as f64 * 100.0);
      println!("--------------------------------");
    }
}

impl PrvBreakdownReceiver {
    fn update_prv_cycles(&mut self, timestamp: u64) {
        match self.curr_prv {
            Prv::PrvUser => {
                self.u_prv_cycles += timestamp - self.prev_timestamp;
            }
            Prv::PrvSupervisor => {
                self.k_prv_cycles += timestamp - self.prev_timestamp;
            }
            Prv::PrvMachine => {
                self.m_prv_cycles += timestamp - self.prev_timestamp;
            }
            _ => {
                panic!("Unsupported privilege level: {:?}", self.curr_prv);
            }
        }
        self.prev_timestamp = timestamp;
    }
}
