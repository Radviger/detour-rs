use crate::error::{Error, Result};
use std::slice;

pub struct Patcher {
    patch_area: &'static mut [u8],
    original_prolog: Vec<u8>,
    detour_prolog: Vec<u8>,
}

impl Patcher {
    /// `prolog_size` is the number of original bytes disassembled by the
    /// trampoline builder; the patch itself is always 8 bytes (AUIPC + JALR).
    pub unsafe fn new(
        target: *const (),
        detour: *const (),
        prolog_size: usize,
    ) -> Result<Patcher> {
        let patch_area = Self::patch_area(target, prolog_size)?;
        let patch_address = patch_area.as_ptr() as *const ();
        let original_prolog = patch_area.to_vec();
        let detour_prolog = Self::branch_bytes(patch_address, detour);
        Ok(Patcher { patch_area, original_prolog, detour_prolog })
    }

    pub fn area(&self) -> &[u8] {
        self.patch_area
    }

    pub unsafe fn toggle(&mut self, enable: bool) {
        self.patch_area.copy_from_slice(if enable {
            &self.detour_prolog
        } else {
            &self.original_prolog
        });
    }

    unsafe fn patch_area(target: *const (), prolog_size: usize) -> Result<&'static mut [u8]> {
        const JUMP_SIZE: usize = 8; // AUIPC + JALR

        if prolog_size >= JUMP_SIZE {
            return Ok(slice::from_raw_parts_mut(target as *mut u8, JUMP_SIZE));
        }

        // Try to extend with NOP/zero padding that follows the prolog.
        let extra = slice::from_raw_parts(
            (target as usize + prolog_size) as *const u8,
            JUMP_SIZE - prolog_size,
        );
        if Self::is_code_padding(extra) {
            Ok(slice::from_raw_parts_mut(target as *mut u8, JUMP_SIZE))
        } else {
            Err(Error::NoPatchArea)
        }
    }

    /// Encodes `AUIPC t1, hi20; JALR x0, t1, lo12` (8 bytes, ±2 GiB reach).
    fn branch_bytes(from: *const (), to: *const ()) -> Vec<u8> {
        let offset = (to as isize).wrapping_sub(from as isize);
        // Guaranteed to fit in i32 by relay_builder (|offset| ≤ DETOUR_RANGE = i32::MAX).
        let offset32 = offset as i32;
        // hi20: rounded so that lo12 stays in [-2048, 2047].
        let hi20 = (offset32 + 0x800) >> 12;
        let lo12 = offset32 - (hi20 << 12);

        debug_assert!(lo12 >= -2048 && lo12 < 2048);

        // AUIPC t1 (x6), hi20
        let auipc = ((hi20 as u32 & 0x000F_FFFF) << 12) | (6u32 << 7) | 0x17u32;
        // JALR x0, t1, lo12
        let jalr = ((lo12 as u32 & 0x0000_0FFF) << 20) | (6u32 << 15) | 0x67u32;

        let mut bytes = Vec::with_capacity(8);
        bytes.extend_from_slice(&auipc.to_le_bytes());
        bytes.extend_from_slice(&jalr.to_le_bytes());
        bytes
    }

    fn is_code_padding(buf: &[u8]) -> bool {
        buf.chunks(4).all(|chunk| {
            if chunk.len() == 4 {
                let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                w == 0x0000_0013 || w == 0 // NOP (ADDI x0,x0,0) or zero
            } else {
                chunk.iter().all(|&b| b == 0x00)
            }
        })
    }
}
