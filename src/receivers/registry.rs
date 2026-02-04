use crate::backend::event::Entry;
use crate::receivers::abstract_receiver::{AbstractReceiver, Shared};
use anyhow::Result;
use bus::BusReader;

pub type ReceiverFactory =
    fn(shared: &Shared, config: serde_json::Value, bus_rx: BusReader<Entry>)
        -> Box<dyn AbstractReceiver>;

pub struct ReceiverRegistration {
    pub name: &'static str,
    pub factory: ReceiverFactory,
}

::inventory::collect!(ReceiverRegistration);

#[macro_export]
macro_rules! register_receiver {
    ($name:expr, $factory:path) => {
        ::inventory::submit! {
            $crate::receivers::registry::ReceiverRegistration {
                name: $name,
                factory: $factory,
            }
        }
    };
}

pub fn make_receiver(
    name: &str,
    shared: &Shared,
    config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Result<Box<dyn AbstractReceiver>> {
    for reg in ::inventory::iter::<ReceiverRegistration> {
        if reg.name == name {
            return Ok((reg.factory)(shared, config, bus_rx));
        }
    }
    Err(anyhow::anyhow!(
        "Receiver factory not found for name: {}",
        name
    ))
}
