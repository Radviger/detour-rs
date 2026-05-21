use crate::{error::Result, pic};

/// Absolute jumps reach any 32-bit address; no proximity constraint needed.
pub const DETOUR_RANGE: usize = 0x7FFF_FFFF;

/// The patcher always uses an 8-byte absolute jump.
pub fn prolog_margin(_target: *const ()) -> usize {
    8
}

/// ARM32 absolute jumps reach any address; no relay is ever needed.
pub fn relay_builder(_target: *const (), _detour: *const ()) -> Result<Option<pic::CodeEmitter>> {
    Ok(None)
}
