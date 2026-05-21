use super::thunk;
use crate::{error::Result, pic};

/// Trampoline range: absolute jumps reach everything, so use a large value.
pub const DETOUR_RANGE: usize = 0x7FFF_FFFF_FFFF_FFFF;

/// The patcher always uses a 16-byte absolute jump (LDR X16, #8; BR X16; .quad).
pub fn prolog_margin(_target: *const ()) -> usize {
    16
}

/// AArch64 absolute jumps reach any address; no relay is ever needed.
pub fn relay_builder(_target: *const (), _detour: *const ()) -> Result<Option<pic::CodeEmitter>> {
    Ok(None)
}

/// Builds a 16-byte absolute-jump emitter from `target` to `detour`.
pub fn build_jump(detour: *const ()) -> pic::CodeEmitter {
    let mut emitter = pic::CodeEmitter::new();
    emitter.add_thunk(thunk::jmp_abs(detour as usize));
    emitter
}
