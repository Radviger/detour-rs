//! AArch64 instruction encoding helpers for trampolines and patches.

use crate::pic::Thunkable;

pub const X16: u8 = 16;
pub const X17: u8 = 17;

fn encode_mov_imm64(reg: u8, value: u64) -> Vec<u8> {
    let mut code = Vec::with_capacity(16);
    let parts = [
        (value & 0xFFFF) as u32,
        ((value >> 16) & 0xFFFF) as u32,
        ((value >> 32) & 0xFFFF) as u32,
        ((value >> 48) & 0xFFFF) as u32,
    ];
    // MOVZ Xreg, #parts[0]
    code.extend_from_slice(&(0xD280_0000u32 | (parts[0] << 5) | reg as u32).to_le_bytes());
    // MOVK Xreg, #parts[1], LSL#16
    code.extend_from_slice(&(0xF2A0_0000u32 | (parts[1] << 5) | reg as u32).to_le_bytes());
    // MOVK Xreg, #parts[2], LSL#32
    code.extend_from_slice(&(0xF2C0_0000u32 | (parts[2] << 5) | reg as u32).to_le_bytes());
    // MOVK Xreg, #parts[3], LSL#48
    code.extend_from_slice(&(0xF2E0_0000u32 | (parts[3] << 5) | reg as u32).to_le_bytes());
    code
}

/// `LDR X16, #8; BR X16; .quad dest` — 16 bytes, absolute unconditional jump.
pub fn jmp_abs(dest: usize) -> Box<dyn Thunkable> {
    let mut code = Vec::with_capacity(16);
    code.extend_from_slice(&0x5800_0050u32.to_le_bytes()); // LDR X16, [PC+8]
    code.extend_from_slice(&0xD61F_0200u32.to_le_bytes()); // BR X16
    code.extend_from_slice(&(dest as u64).to_le_bytes());  // .quad dest
    Box::new(code)
}

/// `LDR X16, #8; BLR X16; .quad dest` — 16 bytes, absolute call.
pub fn call_abs(dest: usize) -> Box<dyn Thunkable> {
    let mut code = Vec::with_capacity(16);
    code.extend_from_slice(&0x5800_0050u32.to_le_bytes()); // LDR X16, [PC+8]
    code.extend_from_slice(&0xD63F_0200u32.to_le_bytes()); // BLR X16
    code.extend_from_slice(&(dest as u64).to_le_bytes());  // .quad dest
    Box::new(code)
}

/// `MOVZ Xreg, #lo; MOVK …×3` — 16 bytes, load 64-bit immediate into register.
pub fn mov_imm64(reg: u8, value: u64) -> Box<dyn Thunkable> {
    Box::new(encode_mov_imm64(reg, value))
}

/// NOP — 4 bytes.
pub fn nop() -> Box<dyn Thunkable> {
    Box::new(0xD503_201Fu32.to_le_bytes().to_vec())
}

/// Expands `CBZ/CBNZ Xn/Wn, far_label` to a 20-byte sequence that inverts
/// the condition to skip an absolute jump when the branch is not taken.
pub fn cbz_far(reg: u8, sf_64: bool, negate: bool, dest: usize) -> Box<dyn Thunkable> {
    let mut code = Vec::with_capacity(20);
    // Inverted branch over the jump: imm19 = 5 (5*4 = 20 bytes forward)
    let base = match (negate, sf_64) {
        (false, true)  => 0xB500_0000u32, // original CBZ X → use CBNZ X
        (false, false) => 0x3500_0000u32, // original CBZ W → use CBNZ W
        (true,  true)  => 0xB400_0000u32, // original CBNZ X → use CBZ X
        (true,  false) => 0x3400_0000u32, // original CBNZ W → use CBZ W
    };
    code.extend_from_slice(&(base | (5u32 << 5) | reg as u32).to_le_bytes());
    code.extend_from_slice(&0x5800_0050u32.to_le_bytes()); // LDR X16, [PC+8]
    code.extend_from_slice(&0xD61F_0200u32.to_le_bytes()); // BR X16
    code.extend_from_slice(&(dest as u64).to_le_bytes());  // .quad dest
    Box::new(code)
}

/// Expands `TBZ/TBNZ Xn/Wn, #bit, far_label` to 20 bytes.
pub fn tbz_far(reg: u8, bit: u8, negate: bool, dest: usize) -> Box<dyn Thunkable> {
    let mut code = Vec::with_capacity(20);
    let b5 = ((bit >> 5) & 1) as u32;
    let b40 = (bit & 31) as u32;
    // Invert condition: TBZ→TBNZ, TBNZ→TBZ; imm14 = 5 (5*4 = 20 bytes forward)
    let opcode = if negate { 0x3600_0000u32 } else { 0x3700_0000u32 };
    let insn = (b5 << 31) | opcode | (b40 << 19) | (5u32 << 5) | reg as u32;
    code.extend_from_slice(&insn.to_le_bytes());
    code.extend_from_slice(&0x5800_0050u32.to_le_bytes()); // LDR X16, [PC+8]
    code.extend_from_slice(&0xD61F_0200u32.to_le_bytes()); // BR X16
    code.extend_from_slice(&(dest as u64).to_le_bytes());  // .quad dest
    Box::new(code)
}

/// Expands `LDR Xt, label` (64-bit literal load) to 20 bytes using X17 (or X16
/// if Rt == X17) as address scratch register.
pub fn ldr_literal_64(rt: u8, src_addr: usize) -> Box<dyn Thunkable> {
    let addr_reg = if rt == X17 { X16 } else { X17 };
    let mut code = encode_mov_imm64(addr_reg, src_addr as u64); // 16 bytes
    code.extend_from_slice(
        &(0xF940_0000u32 | ((addr_reg as u32) << 5) | rt as u32).to_le_bytes(),
    );
    Box::new(code)
}

/// Expands `LDR Wt, label` (32-bit literal load) to 20 bytes.
pub fn ldr_literal_32(rt: u8, src_addr: usize) -> Box<dyn Thunkable> {
    let addr_reg = if rt == X17 { X16 } else { X17 };
    let mut code = encode_mov_imm64(addr_reg, src_addr as u64);
    code.extend_from_slice(
        &(0xB940_0000u32 | ((addr_reg as u32) << 5) | rt as u32).to_le_bytes(),
    );
    Box::new(code)
}

/// Expands `LDRSW Xt, label` to 20 bytes.
pub fn ldrsw_literal(rt: u8, src_addr: usize) -> Box<dyn Thunkable> {
    let addr_reg = if rt == X17 { X16 } else { X17 };
    let mut code = encode_mov_imm64(addr_reg, src_addr as u64);
    code.extend_from_slice(
        &(0xB980_0000u32 | ((addr_reg as u32) << 5) | rt as u32).to_le_bytes(),
    );
    Box::new(code)
}
