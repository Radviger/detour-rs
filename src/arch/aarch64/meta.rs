use super::thunk;
use crate::{error::Result, pic};

/// Maximum reach of a `B imm26` instruction (±128 MiB).
pub const DETOUR_RANGE: usize = 0x800_0000;

/// Minimum prolog bytes the patcher needs: one 4-byte `B imm26`.
pub fn prolog_margin(_target: *const ()) -> usize {
    4
}

/// Builds a relay when the detour is more than ±128 MiB from the target.
/// The relay (a 16-byte absolute jump) is allocated close to the target so
/// the patcher's `B imm26` can always reach it.
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
