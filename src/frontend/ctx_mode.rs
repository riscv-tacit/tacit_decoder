#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtxMode {
    CtxBare = 0b00,
    CtxUser = 0b01,
    CtxWatch = 0b10,
    CtxAll = 0b11,
}

impl From<u8> for CtxMode {
    fn from(value: u8) -> Self {
        match value {
            0b00 => CtxMode::CtxBare,  // baremetal, no context
            0b01 => CtxMode::CtxUser,  // User-space only context
            0b10 => CtxMode::CtxWatch, // watch for a specific context
            0b11 => CtxMode::CtxAll,   // all contexts
            _ => panic!("Invalid CtxMode value"),
        }
    }
}
