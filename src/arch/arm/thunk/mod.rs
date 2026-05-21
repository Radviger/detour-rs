//! ARM32 instruction encoding helpers (ARM state only; Thumb is not supported).

use crate::pic::Thunkable;

/// `LDR PC, [PC, #-4]; .word dest` — 8 bytes, absolute unconditional jump.
///
/// When the CPU fetches this instruction, PC = instr_addr + 8 (pipeline).
/// `LDR PC, [PC, #-4]` loads from `(instr_addr + 8 - 4)` = `instr_addr + 4`,
/// which is the `.word dest` immediately following.
pub fn jmp_abs(dest: usize) -> Box<dyn Thunkable> {
    let mut code = Vec::with_capacity(8);
    code.extend_from_slice(&0xE51F_F004u32.to_le_bytes()); // LDR PC, [PC, #-4]
    code.extend_from_slice(&(dest as u32).to_le_bytes());  // .word dest
    Box::new(code)
}

/// ARM32 NOP (hint encoding `E320F000`).
pub fn nop() -> Box<dyn Thunkable> {
    Box::new(0xE320_F000u32.to_le_bytes().to_vec())
}
