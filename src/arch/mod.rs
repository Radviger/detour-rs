/// Architecture specific code
///
/// Each architecture module must expose:
/// - `Patcher`    — patches a target in-memory.
/// - `Trampoline` — generates a callable stub to the original target.
/// - `meta`       — `DETOUR_RANGE`, `prolog_margin`, `relay_builder`.
pub use self::detour::Detour;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        mod x86;
        use self::x86::{Patcher, Trampoline, meta};
    } else if #[cfg(target_arch = "aarch64")] {
        mod aarch64;
        use self::aarch64::{Patcher, Trampoline, meta};
    } else if #[cfg(target_arch = "arm")] {
        mod arm;
        use self::arm::{Patcher, Trampoline, meta};
    } else {
        compile_error!("detour-rs: unsupported target architecture");
    }
}

mod detour;
mod memory;

/// Returns true if the displacement is within `meta::DETOUR_RANGE`.
pub fn is_within_range(displacement: isize) -> bool {
    let range = meta::DETOUR_RANGE as i64;
    (-range..range).contains(&(displacement as i64))
}

/// Flushes the instruction cache after writing executable code.
///
/// Required on ARM/AArch64 because their I-caches are not kept coherent with
/// D-cache writes by hardware.  No-op on x86 where cache coherence is guaranteed.
pub unsafe fn flush_instruction_cache(ptr: *const (), len: usize) {
    cfg_if! {
        if #[cfg(any(target_arch = "arm", target_arch = "aarch64"))] {
            flush_icache_arm(ptr, len);
        } else {
            // x86/x86_64: I-cache coherent with D-cache; nothing needed.
            let _ = (ptr, len);
        }
    }
}

#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), target_os = "macos"))]
unsafe fn flush_icache_arm(ptr: *const (), len: usize) {
    extern "C" {
        fn sys_icache_invalidate(start: *mut libc::c_void, len: libc::size_t);
    }
    sys_icache_invalidate(ptr as *mut _, len);
}

#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), not(target_os = "macos")))]
unsafe fn flush_icache_arm(ptr: *const (), len: usize) {
    extern "C" {
        fn __clear_cache(beg: *const libc::c_char, end: *const libc::c_char);
    }
    let end = (ptr as usize + len) as *const libc::c_char;
    __clear_cache(ptr as *const _, end);
}
