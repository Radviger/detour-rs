pub use self::patcher::Patcher;
pub use self::trampoline::Trampoline;

pub mod meta;
mod patcher;
mod thunk;
mod trampoline;

#[cfg(all(feature = "nightly", test))]
mod tests {
    use std::arch::naked_asm;
    use crate::error::{Error, Result};
    use crate::RawDetour;
    use matches::assert_matches;
    use std::mem;

    type CRet = unsafe extern "C" fn() -> i32;

    /// Detours `target`, asserts it returns `result` before the hook,
    /// `10` while hooked, and `result` again after disabling.
    unsafe fn detour_test(target: CRet, result: i32) -> Result<()> {
        let hook = RawDetour::new(target as *const (), ret10 as *const ())?;

        assert_eq!(target(), result);
        hook.enable()?;
        {
            assert_eq!(target(), 10);
            let original: CRet = mem::transmute(hook.trampoline());
            assert_eq!(original(), result);
        }
        hook.disable()?;
        assert_eq!(target(), result);
        Ok(())
    }

    /// Default detour target: returns 10.
    unsafe extern "C" fn ret10() -> i32 {
        10
    }

    // ── basic ────────────────────────────────────────────────────────────────

    #[test]
    fn detour_basic() -> Result<()> {
        #[unsafe(naked)]
        unsafe extern "C" fn ret5() -> i32 {
            naked_asm!("mov w0, #5", "ret");
        }
        unsafe { detour_test(ret5, 5) }
    }

    // ── NOP padding (hot-patch area) ─────────────────────────────────────────

    #[test]
    fn detour_nop_padding() -> Result<()> {
        // NOPs before the meaningful code: the patcher must look past them.
        #[unsafe(naked)]
        unsafe extern "C" fn nop_ret3() -> i32 {
            naked_asm!(
                "nop",
                "nop",
                "nop",
                "nop",
                "mov w0, #3",
                "ret",
            );
        }

        // Hook starting at the 5th instruction (past the NOPs).
        unsafe {
            detour_test(mem::transmute(nop_ret3 as usize + 16), 3)
        }
    }

    // ── conditional branch (CBZ) in prolog ──────────────────────────────────

    #[test]
    fn detour_cbz_in_prolog() -> Result<()> {
        // The very first instruction is CBZ: jumps over mov to the `taken` label.
        #[unsafe(naked)]
        unsafe extern "C" fn cbz_ret5() -> i32 {
            naked_asm!(
                "cbz  w0, taken",  // w0 = 0 at entry (no args in caller) → always taken
                "mov  w0, #2",
                "ret",
                "taken:",
                "mov  w0, #5",
                "ret",
            );
        }

        // w0 is 0 at entry (no arguments were passed), so CBZ branches
        // and the function returns 5.
        unsafe { detour_test(cbz_ret5, 5) }
    }

    // ── ADRP + LDR (PC-relative page load) in prolog ────────────────────────

    #[test]
    fn detour_adrp() -> Result<()> {
        static VALUE: i32 = 195;

        // Compiler emits ADRP + LDR to load a global.  The trampoline must
        // fix up the ADRP so it still refers to the original page.
        #[unsafe(naked)]
        unsafe extern "C" fn adrp_load() -> i32 {
            naked_asm!(
                "adrp x0, {val}",
                "ldr  w0, [x0, :lo12:{val}]",
                "ret",
                val = sym VALUE,
            );
        }

        unsafe { detour_test(adrp_load, 195) }
    }

    // ── unconditional branch (B) in prolog ──────────────────────────────────

    #[test]
    fn detour_unconditional_branch() -> Result<()> {
        // First instruction jumps over dead code straight to the return value.
        #[unsafe(naked)]
        unsafe extern "C" fn b_ret7() -> i32 {
            naked_asm!(
                "b    done",
                "mov  w0, #0",   // dead
                "done:",
                "mov  w0, #7",
                "ret",
            );
        }

        unsafe { detour_test(b_ret7, 7) }
    }

    // ── same target and detour ───────────────────────────────────────────────

    #[test]
    fn same_detour_and_target() {
        #[inline(never)]
        extern "C" fn identity(x: i32) -> i32 {
            unsafe { std::ptr::read_volatile(&x as *const i32) }
        }

        let err = unsafe {
            RawDetour::new(identity as *const (), identity as *const ())
        }
        .unwrap_err();
        assert_matches!(err, Error::SameAddress);
    }

    // ── shared target (two detours on the same function) ────────────────────

    #[test]
    fn detours_share_target() -> Result<()> {
        #[inline(never)]
        extern "C" fn add(x: i32, y: i32) -> i32 {
            unsafe { std::ptr::read_volatile(&x as *const i32) + y }
        }

        let hook1 = unsafe {
            extern "C" fn sub(x: i32, y: i32) -> i32 {
                x - y
            }
            RawDetour::new(add as *const (), sub as *const ())?
        };
        unsafe { hook1.enable()? };
        assert_eq!(add(5, 5), 0); // sub(5,5) = 0

        let hook2 = unsafe {
            extern "C" fn div(x: i32, y: i32) -> i32 {
                x / y
            }
            RawDetour::new(add as *const (), div as *const ())?
        };
        unsafe { hook2.enable()? };

        // hook2.call → hook2's trampoline → hook1's detour (sub)
        assert_eq!(
            unsafe {
                let f: extern "C" fn(i32, i32) -> i32 =
                    mem::transmute(hook2.trampoline());
                f(5, 5)
            },
            0
        );
        assert_eq!(add(10, 5), 2); // div(10,5) = 2
        Ok(())
    }
}
