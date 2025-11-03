use rustc_data_structures::fx::FxHashMap;
use rvdasm::insn::Insn;

pub struct DecoderCache {
    cache: FxHashMap<u64, u64>,
}

impl DecoderCache {
    pub fn new() -> Self {
        Self { cache: FxHashMap::default() }
    }

    pub fn get(&self, pc: u64) -> Option<&u64> {
        self.cache.get(&pc)
    }

    pub fn insert(&mut self, pc: u64, target_pc: u64) {
        self.cache.insert(pc, target_pc);
    }

    pub fn contains_key(&self, pc: u64) -> bool {
        self.cache.contains_key(&pc)
    }

    pub fn reset(&mut self) {
        self.cache.clear();
    }
}