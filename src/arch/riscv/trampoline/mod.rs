//! RISC-V trampoline generator (base ISA, 4-byte aligned instructions).
//!
//! Compressed (16-bit, C-extension) instructions are rejected with
//! `UnsupportedInstruction`; they are identified by bits[1:0] != 0b11.

use crate::arch::riscv::thunk;
use crate::error::{Error, Result};
use crate::pic;

pub struct Trampoline {
    emitter: pic::CodeEmitter,
    prolog_size: usize,
}

impl Trampoline {
    pub unsafe fn new(target: *const (), margin: usize) -> Result<Trampoline> {
        Builder::new(target, margin).build()
    }

    pub fn emitter(&self) -> &pic::CodeEmitter {
        &self.emitter
    }

    pub fn prolog_size(&self) -> usize {
        self.prolog_size
    }
}

struct Builder {
    target: *const (),
    margin: usize,
    total_bytes: usize,
    finished: bool,
    /// Furthest forward-branch target within the prolog (for change-size guard).
    branch_address: Option<usize>,
}

impl Builder {
    fn new(target: *const (), margin: usize) -> Self {
        Builder { target, margin, total_bytes: 0, finished: false, branch_address: None }
    }

    unsafe fn build(mut self) -> Result<Trampoline> {
        let mut emitter = pic::CodeEmitter::new();
        let target_addr = self.target as usize;

        while !self.finished {
            let instr_addr = target_addr + self.total_bytes;
            let raw: u32 = (instr_addr as *const u32).read_unaligned();
            let (thunk, expanded) = self.process(raw, instr_addr)?;
            let orig_size = 4usize;

            // If this instruction is inside a forward-branch span and it
            // expands, the branch target would land at the wrong offset.
            if self.is_in_branch(instr_addr) && expanded != orig_size {
                return Err(Error::UnsupportedInstruction);
            }

            emitter.add_thunk(thunk);
            self.total_bytes += orig_size;

            if self.total_bytes >= self.margin && !self.finished {
                emitter.add_thunk(thunk::jmp_abs(target_addr + self.total_bytes));
                self.finished = true;
            }
        }

        Ok(Trampoline { prolog_size: self.total_bytes, emitter })
    }

    /// Returns `(thunk, expanded_byte_count)` for `instr` at `pc`.
    fn process(
        &mut self,
        instr: u32,
        pc: usize,
    ) -> Result<(Box<dyn pic::Thunkable>, usize)> {
        let target_addr = self.target as usize;
        let prolog_range = target_addr..target_addr + self.margin;

        // ── Compressed instructions (bits[1:0] != 0b11) ──────────────────────
        if (instr & 0x3) != 0x3 {
            return Err(Error::UnsupportedInstruction);
        }

        let opcode = instr & 0x7F;

        // ── JAL (J-type, opcode 0x6F) ────────────────────────────────────────
        if opcode == 0x6F {
            let imm = decode_j_type(instr);
            let dest = pc.wrapping_add(imm as usize);
            let rd = (instr >> 7) & 0x1F;

            if rd == 0 {
                // Unconditional jump: terminal unless inside a branch span.
                self.finished = !self.is_in_branch(pc);
                if prolog_range.contains(&dest) {
                    self.track_branch(dest);
                    return Ok((Box::new(instr.to_le_bytes().to_vec()), 4));
                }
                let t = thunk::jmp_abs(dest);
                let sz = t.len();
                return Ok((t, sz));
            } else {
                // Call with link: rare in a prolog; copy if near, expand if far.
                if prolog_range.contains(&dest) {
                    self.track_branch(dest);
                    return Ok((Box::new(instr.to_le_bytes().to_vec()), 4));
                }
                let t = thunk::call_abs_rd(rd as u8, dest);
                let sz = t.len();
                return Ok((t, sz));
            }
        }

        // ── JALR (I-type, opcode 0x67) ───────────────────────────────────────
        if opcode == 0x67 {
            let rd = (instr >> 7) & 0x1F;
            // Computed jump: copy as-is (cannot fix up unknown rs1 at trampoline
            // build time).  If rd == 0 it is an unconditional jump (e.g. RET),
            // so mark the prolog finished.
            if rd == 0 {
                self.finished = !self.is_in_branch(pc);
            }
            return Ok((Box::new(instr.to_le_bytes().to_vec()), 4));
        }

        // ── AUIPC (U-type, opcode 0x17) ──────────────────────────────────────
        if opcode == 0x17 {
            // AUIPC rd, imm20: rd = PC + sign_extend(imm20 << 12).
            // The upper 20 bits of the instruction word already encode the
            // page-aligned displacement (with the sign bit at bit 31).
            let page_disp = (instr as i32 & 0xFFFFF000u32 as i32) as isize;
            let actual_addr = pc.wrapping_add(page_disp as usize);
            let rd = (instr >> 7) & 0x1F;
            let t = thunk::li_abs(rd as u8, actual_addr);
            let sz = t.len();
            return Ok((t, sz));
        }

        // ── B-type conditional branches (opcode 0x63) ────────────────────────
        if opcode == 0x63 {
            let imm = decode_b_type(instr);
            let dest = pc.wrapping_add(imm as usize);

            if prolog_range.contains(&dest) {
                self.track_branch(dest);
                return Ok((Box::new(instr.to_le_bytes().to_vec()), 4));
            }
            let t = thunk::branch_far(instr, dest);
            let sz = t.len();
            return Ok((t, sz));
        }

        // All other instructions: copy verbatim.
        Ok((Box::new(instr.to_le_bytes().to_vec()), 4))
    }

    fn track_branch(&mut self, dest: usize) {
        match self.branch_address {
            None => self.branch_address = Some(dest),
            Some(e) if dest > e => self.branch_address = Some(dest),
            _ => {}
        }
    }

    fn is_in_branch(&self, pc: usize) -> bool {
        self.branch_address.map_or(false, |a| pc < a)
    }
}

/// Decode the signed immediate from a J-type (JAL) instruction.
fn decode_j_type(instr: u32) -> i32 {
    let imm20 = (instr >> 31) & 1;
    let imm10_1 = (instr >> 21) & 0x3FF;
    let imm11 = (instr >> 20) & 1;
    let imm19_12 = (instr >> 12) & 0xFF;
    let raw = (imm20 << 20) | (imm19_12 << 12) | (imm11 << 11) | (imm10_1 << 1);
    // Sign-extend from bit 20.
    ((raw << 11) as i32) >> 11
}

/// Decode the signed immediate from a B-type (branch) instruction.
fn decode_b_type(instr: u32) -> i32 {
    let imm12 = (instr >> 31) & 1;
    let imm10_5 = (instr >> 25) & 0x3F;
    let imm4_1 = (instr >> 8) & 0xF;
    let imm11 = (instr >> 7) & 1;
    let raw = (imm12 << 12) | (imm11 << 11) | (imm10_5 << 5) | (imm4_1 << 1);
    // Sign-extend from bit 12.
    ((raw << 19) as i32) >> 19
}

unsafe impl Send for Builder {}
