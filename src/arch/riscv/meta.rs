use super::thunk;
use crate::{error::Result, pic};

/// AUIPC+JALR reaches ±2 GiB from the instruction.  For RV32 this covers
/// the entire 4 GiB address space, so a relay is never needed there.
pub const DETOUR_RANGE: usize = 0x7FFF_FFFF;

/// Two instructions: AUIPC t1, hi20 + JALR x0, t1, lo12 = 8 bytes.
pub fn prolog_margin(_target: *const ()) -> usize {
    8
}

/// On RV64 a detour more than ±2 GiB away needs an absolute relay.
/// The relay is allocated close to the target so the 8-byte AUIPC+JALR
/// patch can always reach it.
pub fn relay_builder(target: *const (), detour: *const ()) -> Result<Option<pic::CodeEmitter>> {
    let displacement = (detour as isize).wrapping_sub(target as isize);
    if !crate::arch::is_within_range(displacement) {
        let mut emitter = pic::CodeEmitter::new();
        emitter.add_thunk(thunk::jmp_abs(detour as usize));
        Ok(Some(emitter))
    } else {
        Ok(None)
    }
}
