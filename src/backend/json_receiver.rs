use crate::backend::event::{Entry, Event};
use crate::backend::abstract_receiver::{AbstractReceiver, BusReceiver};
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};

pub struct JsonReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
}

impl JsonReceiver {
    pub fn new(bus_rx: BusReader<Entry>) -> Self {
        Self { writer: BufWriter::new(File::create("trace.json").unwrap()), 
               receiver: BusReceiver { name: "json".to_string(), bus_rx: bus_rx, checksum: 0 } }
    }
}

impl AbstractReceiver for JsonReceiver {

    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry.event {
            Event::None => {}
            _ => {
                self.writer.write_all(serde_json::to_string(&entry).unwrap().as_bytes()).unwrap();
            }
        }
    }

    fn _flush(&mut self) {
        self.writer.flush().unwrap();
    }
}
