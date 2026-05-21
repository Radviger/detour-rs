use crate::{alloc, arch, error::Result, pic};
#[allow(unused_imports)]
use crate::arch::flush_instruction_cache;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
  /// Shared allocator for all detours.
  pub static ref POOL: Mutex<alloc::ThreadAllocator> = {
    // Use a range of +/- 2 GB for seeking a memory block
    Mutex::new(alloc::ThreadAllocator::new(arch::meta::DETOUR_RANGE))
  };
}

/// Allocates PIC code at the specified address.
pub fn allocate_pic(
  pool: &mut alloc::ThreadAllocator,
  emitter: &pic::CodeEmitter,
  origin: *const (),
) -> Result<alloc::ExecutableMemory> {
  // Allocate memory close to the origin
  pool.allocate(origin, emitter.len()).map(|mut memory| {
    // Generate code for the obtained address
    let code = emitter.emit(memory.as_ptr() as *const _);
    memory.copy_from_slice(code.as_slice());
    // On ARM/AArch64 flush I-cache after writing executable code.
    unsafe { flush_instruction_cache(memory.as_ptr() as *const (), memory.len()) };
    memory
  })
}
