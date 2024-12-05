use crate::backend::event::Entry;
use bus::BusReader;
use std::thread;

pub struct BusReceiver {
    pub name: String, // name of the type of receiver
    pub bus_rx: BusReader<Entry>,
    pub checksum: usize,
}

pub trait AbstractReceiver: Send + 'static {
    fn bus_rx(&mut self) -> &mut BusReader<Entry>;
    fn try_receive_loop(&mut self) {
        loop {
            match self.bus_rx().try_recv() {
                Ok(entry) => {
                    self._receive_entry(entry);
                    self._bump_checksum();
                }
                // if the bus is disconnected, we're done!
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self._flush();
                    return;
                }
                // if the bus is empty, yield until later
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    thread::yield_now();
                }
            }
        }
    }
    fn _bump_checksum(&mut self);
    fn _receive_entry(&mut self, entry: Entry);
    fn _flush(&mut self);
}
