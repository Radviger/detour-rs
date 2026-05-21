use super::thunk;
use crate::error::{Error, Result};
use crate::pic;
use std::slice;

pub struct Patcher {
    patch_area: &'static mut [u8],
    original_prolog: Vec<u8>,
    detour_prolog: Vec<u8>,
}

impl Patcher {
    pub unsafe fn new(
        target: *const (),
        detour: *const (),
        prolog_size: usize,
    ) -> Result<Patcher> {
        let patch_area = Self::patch_area(target, prolog_size)?;
        let original_prolog = patch_area.to_vec();
        let detour_prolog = Self::hook_bytes(patch_area.as_ptr() as *const (), detour);
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

    /// Returns a slice covering the function's patch area (at least `prolog_size` bytes,
    /// extended by NOP padding to fill a complete 16-byte jump if needed).
    unsafe fn patch_area(target: *const (), prolog_size: usize) -> Result<&'static mut [u8]> {
        const JUMP_SIZE: usize = 16;

        if prolog_size >= JUMP_SIZE {
            return Ok(slice::from_raw_parts_mut(target as *mut u8, JUMP_SIZE));
        }

        // Check if trailing NOP/INT3/zero padding can extend the prolog.
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

    /// Generates the 16-byte absolute-jump patch bytes.
    fn hook_bytes(_patch_address: *const (), detour: *const ()) -> Vec<u8> {
        let mut emitter = pic::CodeEmitter::new();
        emitter.add_thunk(thunk::jmp_abs(detour as usize));
        emitter.emit(_patch_address)
    }

    fn is_code_padding(buf: &[u8]) -> bool {
        // NOP (0xD503201F as LE bytes), INT3-equivalent (0xCC), or zero bytes
        buf.chunks(4).all(|chunk| {
            if chunk.len() == 4 {
                let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                w == 0xD503_201F || w == 0 || w == 0xCCCC_CCCC
            } else {
                chunk.iter().all(|&b| b == 0x00 || b == 0xCC)
            }
        })
    }
}
