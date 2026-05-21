//! ARM32 trampoline generator (ARM state only).
//!
//! Thumb-state targets (bit 0 of address = 1) are rejected with
//! `UnsupportedInstruction`; Thumb disassembly would need a separate decoder
//! because instructions are 2 or 4 bytes.

use crate::arch::arm::thunk;
use crate::error::{Error, Result};
use crate::pic;

pub struct Trampoline {
    emitter: pic::CodeEmitter,
    prolog_size: usize,
}

impl Trampoline {
    pub unsafe fn new(target: *const (), margin: usize) -> Result<Trampoline> {
        // Reject Thumb-state targets (bit 0 set).
        if (target as usize) & 1 != 0 {
            return Err(Error::UnsupportedInstruction);
        }
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
    branch_address: Option<usize>,
}

impl Builder {
    fn new(target: *const (), margin: usize) -> Self {
        Builder {
            target,
            margin,
            total_bytes: 0,
            finished: false,
            branch_address: None,
        }
    }

    unsafe fn build(mut self) -> Result<Trampoline> {
        let mut emitter = pic::CodeEmitter::new();
        let target_addr = self.target as usize;

        while !self.finished {
            let instr_addr = target_addr + self.total_bytes;
            let raw: u32 = (instr_addr as *const u32).read_unaligned();
            let thunk = self.process(raw, instr_addr)?;

            emitter.add_thunk(thunk);
            self.total_bytes += 4;

            if self.total_bytes >= self.margin && !self.finished {
                emitter.add_thunk(thunk::jmp_abs(target_addr + self.total_bytes));
                self.finished = true;
            }
        }

        Ok(Trampoline {
            prolog_size: self.total_bytes,
            emitter,
        })
    }

    fn process(&mut self, instr: u32, pc: usize) -> Result<Box<dyn pic::Thunkable>> {
        let target_addr = self.target as usize;
        let prolog_range = target_addr..target_addr + self.margin;

        // Extract condition field (bits 31-28).  0xF = unconditional (ARMv6T2+).
        let cond = instr >> 28;

        // ── Unconditional branch B / BL (cond != 0xF, bits 27-24 = 1010/1011) ──
        if cond != 0xF && (instr & 0x0E00_0000) == 0x0A00_0000 {
            let imm24 = sign_extend_arm((instr & 0x00FF_FFFF) as usize, 24);
            // ARM PC reads as instr_addr + 8 when executing.
            let dest = (pc + 8).wrapping_add(imm24 << 2);
            let is_bl = (instr & 0x0100_0000) != 0;

            if prolog_range.contains(&dest) {
                self.track_branch(dest);
                return Ok(Box::new(instr.to_le_bytes().to_vec()));
            }

            // Replace far branches with absolute jumps.  BL semantics (LR update)
            // are lost for far targets; this is the same trade-off as x86.
            if is_bl {
                // We can't perfectly replicate BL (which sets LR) with LDR PC.
                // A BL in a function prolog is very unusual; bail out safely.
                return Err(Error::UnsupportedInstruction);
            }
            return Ok(thunk::jmp_abs(dest));
        }

        // ── RET-like patterns ────────────────────────────────────────────────
        // BX Rn (cond != 0xF): 0x012FFF10 | Rn
        if cond != 0xF && (instr & 0x0FFF_FFF0) == 0x012F_FF10 {
            self.finished = !self.is_in_branch(pc);
            return Ok(Box::new(instr.to_le_bytes().to_vec()));
        }
        // MOV PC, Rn: 0x01A0F000 | Rn
        if cond != 0xF && (instr & 0x0FEF_F000) == 0x01A0_F000 {
            self.finished = !self.is_in_branch(pc);
            return Ok(Box::new(instr.to_le_bytes().to_vec()));
        }
        // LDM/POP with PC in register list (bit 15 = 1, base = SP typically)
        if cond != 0xF && (instr & 0x0E10_8000) == 0x0810_8000 {
            self.finished = !self.is_in_branch(pc);
            return Ok(Box::new(instr.to_le_bytes().to_vec()));
        }

        // ── Reject instructions that use PC as a source ──────────────────────
        // LDR Rd, [PC, #n] — literal pool load
        if cond != 0xF && (instr & 0x0F7F_0000) == 0x051F_0000 {
            // Rd is bits[15:12]; if Rd == PC this is an indirect jump (safe to copy).
            let rd = (instr >> 12) & 0xF;
            if rd != 15 {
                // The displacement will be wrong in the trampoline — unsupported.
                return Err(Error::UnsupportedInstruction);
            }
        }

        // Catch-all for other instructions with PC as a source operand in the
        // data-processing encoding (Rn = PC, bits[19:16] = 0xF).
        if cond != 0xF
            && (instr & 0x0C00_0000) == 0x0000_0000 // data-processing
            && ((instr >> 16) & 0xF) == 15 // Rn = PC
        {
            return Err(Error::UnsupportedInstruction);
        }

        // Copy all other instructions verbatim.
        Ok(Box::new(instr.to_le_bytes().to_vec()))
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

fn sign_extend_arm(value: usize, bits: u32) -> usize {
    let shift = usize::BITS - bits;
    ((value << shift) as isize >> shift) as usize
}
