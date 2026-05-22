use crate::error::{Error, Result};
use std::slice;

pub struct Patcher {
    patch_area: &'static mut [u8],
    original_prolog: Vec<u8>,
    detour_prolog: Vec<u8>,
}

impl Patcher {
    /// `prolog_size` is the number of original bytes disassembled by the
    /// trampoline builder; the patch itself is always 4 bytes (`B imm26`).
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
        const JUMP_SIZE: usize = 4;

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

    /// Encodes `B offset` from `from` to `to` (4 bytes, ±128 MiB).
    fn branch_bytes(from: *const (), to: *const ()) -> Vec<u8> {
        let displacement = (to as isize).wrapping_sub(from as isize);
        debug_assert!(
            displacement % 4 == 0,
            "branch target not 4-byte aligned"
        );
        // imm26 is signed, stored as two's complement in 26 bits.
        let imm26 = (displacement >> 2) as u32 & 0x03FF_FFFF;
        (0x1400_0000u32 | imm26).to_le_bytes().to_vec()
    }

    fn is_code_padding(buf: &[u8]) -> bool {
        buf.chunks(4).all(|chunk| {
            if chunk.len() == 4 {
                let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                w == 0xD503_201F || w == 0 // NOP or zero
            } else {
                chunk.iter().all(|&b| b == 0x00)
            }
        })
    }
}
