//! RISC-V instruction encoding helpers for trampolines and patches.
//!
//! Absolute jumps use `AUIPC t1, 0; LD/LW t1, 12(t1); JALR rd, t1, 0; <dest>`
//! which is position-independent (AUIPC captures the current PC into t1, then
//! the inline literal is loaded from t1+12).  t1 (x6) is used as scratch;
//! it is caller-saved so clobbering it is always ABI-safe.

use crate::pic::Thunkable;

/// RISC-V NOP = ADDI x0, x0, 0 (4 bytes).
#[allow(dead_code)]
pub fn nop() -> Box<dyn Thunkable> {
    Box::new(0x0000_0013u32.to_le_bytes().to_vec())
}

/// Absolute unconditional jump to `dest` (20 bytes on RV64, 16 bytes on RV32).
/// Clobbers t1 (x6).
pub fn jmp_abs(dest: usize) -> Box<dyn Thunkable> {
    jmp_abs_rd(0, dest)
}

/// Absolute call saving return address in ra (x1).
/// Clobbers t1 (x6).
#[allow(dead_code)]
pub fn call_abs(dest: usize) -> Box<dyn Thunkable> {
    jmp_abs_rd(1, dest)
}

/// Absolute call/jump saving return address in `rd`.
/// If `rd == 0` this is an unconditional jump (no link saved).
/// Clobbers t1 (x6).
pub fn call_abs_rd(rd: u8, dest: usize) -> Box<dyn Thunkable> {
    jmp_abs_rd(rd as u32, dest)
}

/// Load absolute address `value` into `rd` without clobbering any other
/// register.  Uses the "JAL rd / literal / LD rd,0(rd)" trick:
///   JAL rd, skip  → rd = this PC + 4 (= address of literal), jump past literal
///   <value>       → the literal (8 bytes on RV64, 4 bytes on RV32)
///   LD  rd, 0(rd) → rd = [rd] = value
/// Total: 16 bytes on RV64, 12 bytes on RV32.
pub fn li_abs(rd: u8, value: usize) -> Box<dyn Thunkable> {
    let rd = rd as u32;

    // JAL rd, skip: rd = PC+4, jump to PC+skip (past the literal)
    #[cfg(target_arch = "riscv64")]
    let (skip, load_funct3): (u32, u32) = (12, 3); // LD
    #[cfg(not(target_arch = "riscv64"))]
    let (skip, load_funct3): (u32, u32) = (8, 2); // LW

    let jal = encode_j_type(rd, skip as i32);
    // LD/LW rd, 0(rd): rd = [rd]
    let load = (rd << 15) | (load_funct3 << 12) | (rd << 7) | 0x03;

    let mut code = Vec::new();
    code.extend_from_slice(&jal.to_le_bytes());
    #[cfg(target_arch = "riscv64")]
    code.extend_from_slice(&(value as u64).to_le_bytes());
    #[cfg(not(target_arch = "riscv64"))]
    code.extend_from_slice(&(value as u32).to_le_bytes());
    code.extend_from_slice(&load.to_le_bytes());
    Box::new(code)
}

/// Expands a B-type conditional branch to `dest` (far target) to:
///   B_inverted rs1, rs2, skip  — if NOT taken, skip past jmp_abs
///   <jmp_abs(dest)>            — 20 bytes (RV64) / 16 bytes (RV32)
/// Total: 24 bytes (RV64) / 20 bytes (RV32).
pub fn branch_far(instr: u32, dest: usize) -> Box<dyn Thunkable> {
    let rs1 = (instr >> 15) & 0x1F;
    let rs2 = (instr >> 20) & 0x1F;
    let funct3 = ((instr >> 12) & 0x7) ^ 1; // invert condition (bit 0 toggles EQ↔NE, LT↔GE)

    #[cfg(target_arch = "riscv64")]
    let jmp_size: i32 = 20;
    #[cfg(not(target_arch = "riscv64"))]
    let jmp_size: i32 = 16;

    let skip = 4 + jmp_size; // offset to instruction after jmp_abs
    let branch_skip = encode_b_type(funct3, rs1, rs2, skip);

    let mut code = Vec::new();
    code.extend_from_slice(&branch_skip.to_le_bytes());
    // Inline jmp_abs bytes (avoids double allocation)
    code.extend_from_slice(&jmp_abs_bytes(0, dest));
    Box::new(code)
}

// ── internal helpers ─────────────────────────────────────────────────────────

/// Returns the raw bytes of an absolute jump/call with link saved to `rd`.
/// Used internally to inline jmp_abs into branch_far.
fn jmp_abs_bytes(rd: u32, dest: usize) -> Vec<u8> {
    const T1: u32 = 6; // x6
    // AUIPC t1, 0: t1 = this PC
    let auipc = (T1 << 7) | 0x17u32;
    // LD/LW t1, 12(t1): t1 = [t1 + 12] = dest
    #[cfg(target_arch = "riscv64")]
    let load = (12u32 << 20) | (T1 << 15) | (3u32 << 12) | (T1 << 7) | 0x03u32; // LD
    #[cfg(not(target_arch = "riscv64"))]
    let load = (12u32 << 20) | (T1 << 15) | (2u32 << 12) | (T1 << 7) | 0x03u32; // LW
    // JALR rd, t1, 0: PC = t1; rd = PC+4 (link)
    let jalr = (T1 << 15) | (rd << 7) | 0x67u32;

    let mut code = Vec::new();
    code.extend_from_slice(&auipc.to_le_bytes());
    code.extend_from_slice(&load.to_le_bytes());
    code.extend_from_slice(&jalr.to_le_bytes());
    #[cfg(target_arch = "riscv64")]
    code.extend_from_slice(&(dest as u64).to_le_bytes());
    #[cfg(not(target_arch = "riscv64"))]
    code.extend_from_slice(&(dest as u32).to_le_bytes());
    code
}

fn jmp_abs_rd(rd: u32, dest: usize) -> Box<dyn Thunkable> {
    Box::new(jmp_abs_bytes(rd, dest))
}

/// Encodes a J-type (JAL) instruction.
/// `imm` is the signed byte offset (must be even and fit in 21 bits).
fn encode_j_type(rd: u32, imm: i32) -> u32 {
    let imm = imm as u32;
    (((imm >> 20) & 1) << 31)        // imm[20] → bit 31
        | (((imm >> 1) & 0x3FF) << 21) // imm[10:1] → bits 30:21
        | (((imm >> 11) & 1) << 20)    // imm[11] → bit 20
        | (((imm >> 12) & 0xFF) << 12) // imm[19:12] → bits 19:12
        | (rd << 7)
        | 0x6F
}

/// Encodes a B-type (branch) instruction.
/// `imm` is the signed byte offset (must be even and fit in 13 bits).
fn encode_b_type(funct3: u32, rs1: u32, rs2: u32, imm: i32) -> u32 {
    let imm = imm as u32;
    (((imm >> 12) & 1) << 31)         // imm[12] → bit 31
        | (((imm >> 5) & 0x3F) << 25) // imm[10:5] → bits 30:25
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | (((imm >> 1) & 0xF) << 8)   // imm[4:1] → bits 11:8
        | (((imm >> 11) & 1) << 7)    // imm[11] → bit 7
        | 0x63
}
