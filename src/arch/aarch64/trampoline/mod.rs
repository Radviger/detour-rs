use crate::arch::aarch64::thunk;
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
    /// Address of an internal forward-branch target (for change-size guard).
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
            let (thunk, size) = self.process(raw, instr_addr)?;
            let orig_size = 4usize;

            // Internal branch + size change → behaviour would be wrong
            if self.is_in_branch(instr_addr) && size != orig_size {
                return Err(Error::UnsupportedInstruction);
            }

            emitter.add_thunk(thunk);
            self.total_bytes += orig_size;

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

    /// Returns `(thunk, expanded_byte_count)` for `instr` at `pc`.
    fn process(
        &mut self,
        instr: u32,
        pc: usize,
    ) -> Result<(Box<dyn pic::Thunkable>, usize)> {
        let target_addr = self.target as usize;
        let prolog_range = target_addr..target_addr + self.margin;

        // ── B imm26 ──────────────────────────────────────────────────────────
        if (instr & 0xFC00_0000) == 0x1400_0000 {
            let imm26 = sign_extend((instr & 0x03FF_FFFF) as usize, 26);
            let dest = pc.wrapping_add(imm26 << 2);
            self.finished = !self.is_in_branch(pc);

            if prolog_range.contains(&dest) {
                self.track_branch(dest);
                return Ok((Box::new(instr.to_le_bytes().to_vec()), 4));
            }
            return Ok((thunk::jmp_abs(dest), 16));
        }

        // ── BL imm26 ─────────────────────────────────────────────────────────
        if (instr & 0xFC00_0000) == 0x9400_0000 {
            let imm26 = sign_extend((instr & 0x03FF_FFFF) as usize, 26);
            let dest = pc.wrapping_add(imm26 << 2);
            return Ok((thunk::call_abs(dest), 16));
        }

        // ── CBZ / CBNZ ───────────────────────────────────────────────────────
        if (instr & 0x7E00_0000) == 0x3400_0000 {
            let imm19 = sign_extend(((instr >> 5) & 0x7_FFFF) as usize, 19);
            let dest = pc.wrapping_add(imm19 << 2);
            let sf_64 = (instr >> 31) != 0;
            let negate = (instr & 0x0100_0000) != 0; // bit24: 0=CBZ, 1=CBNZ

            if prolog_range.contains(&dest) {
                self.track_branch(dest);
                return Ok((Box::new(instr.to_le_bytes().to_vec()), 4));
            }
            return Ok((thunk::cbz_far(instr as u8 & 0x1F, sf_64, negate, dest), 20));
        }

        // ── TBZ / TBNZ ───────────────────────────────────────────────────────
        if (instr & 0x7E00_0000) == 0x3600_0000 {
            let imm14 = sign_extend(((instr >> 5) & 0x3FFF) as usize, 14);
            let dest = pc.wrapping_add(imm14 << 2);
            let bit = (((instr >> 31) & 1) << 5 | ((instr >> 19) & 0x1F)) as u8;
            let negate = (instr & 0x0100_0000) != 0; // bit24: 0=TBZ, 1=TBNZ

            if prolog_range.contains(&dest) {
                self.track_branch(dest);
                return Ok((Box::new(instr.to_le_bytes().to_vec()), 4));
            }
            return Ok((thunk::tbz_far(instr as u8 & 0x1F, bit, negate, dest), 20));
        }

        // ── ADR Xd, label ────────────────────────────────────────────────────
        if (instr & 0x9F00_0000) == 0x1000_0000 {
            let immlo = (instr >> 29) & 0x3;
            let immhi = (instr >> 5) & 0x7_FFFF;
            let imm21 = sign_extend(((immhi << 2) | immlo) as usize, 21);
            let dest = pc.wrapping_add(imm21);
            let rd = (instr & 0x1F) as u8;
            return Ok((thunk::mov_imm64(rd, dest as u64), 16));
        }

        // ── ADRP Xd, label ───────────────────────────────────────────────────
        if (instr & 0x9F00_0000) == 0x9000_0000 {
            let immlo = (instr >> 29) & 0x3;
            let immhi = (instr >> 5) & 0x7_FFFF;
            let imm21 = sign_extend(((immhi << 2) | immlo) as usize, 21);
            let dest = (pc & !0xFFF).wrapping_add(imm21 << 12);
            let rd = (instr & 0x1F) as u8;
            return Ok((thunk::mov_imm64(rd, dest as u64), 16));
        }

        // ── LDR literal family ───────────────────────────────────────────────
        if (instr & 0x3B00_0000) == 0x1800_0000 {
            let is_simd = (instr & 0x0400_0000) != 0;
            if is_simd {
                // SIMD/FP literal loads are uncommon in prologues; bail out.
                return Err(Error::UnsupportedInstruction);
            }
            let imm19 = sign_extend(((instr >> 5) & 0x7_FFFF) as usize, 19);
            let src_addr = pc.wrapping_add(imm19 << 2);
            let rt = (instr & 0x1F) as u8;
            let opc2 = (instr >> 30) & 0x3; // 00=LDR W, 01=LDR X, 10=LDRSW, 11=PRFM

            let thunk: Box<dyn pic::Thunkable> = match opc2 {
                0b00 => thunk::ldr_literal_32(rt, src_addr),
                0b01 => thunk::ldr_literal_64(rt, src_addr),
                0b10 => thunk::ldrsw_literal(rt, src_addr),
                _ /* PRFM */ => thunk::nop(),
            };
            let sz = thunk.len();
            return Ok((thunk, sz));
        }

        // ── RET ──────────────────────────────────────────────────────────────
        if (instr & 0xFFFF_FC1F) == 0xD65F_0000 {
            self.finished = !self.is_in_branch(pc);
            return Ok((Box::new(instr.to_le_bytes().to_vec()), 4));
        }

        // All other instructions: copy as-is.
        Ok((Box::new(instr.to_le_bytes().to_vec()), 4))
    }

    fn track_branch(&mut self, dest: usize) {
        match self.branch_address {
            None => self.branch_address = Some(dest),
            Some(existing) => {
                if dest > existing {
                    self.branch_address = Some(dest);
                }
            }
        }
    }

    fn is_in_branch(&self, pc: usize) -> bool {
        self.branch_address.map_or(false, |addr| pc < addr)
    }
}

/// Sign-extends a `bits`-wide unsigned value to `usize`.
fn sign_extend(value: usize, bits: u32) -> usize {
    let shift = usize::BITS - bits;
    ((value << shift) as isize >> shift) as usize
}

// Safety: the raw pointer arithmetic in Builder is guarded by the caller
// holding the memory pool lock, matching the x86 trampoline convention.
unsafe impl Send for Builder {}
