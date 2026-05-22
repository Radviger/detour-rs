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

    #[unsafe(naked)]
    unsafe extern "C" fn ret10() -> i32 {
        naked_asm!("li a0, 10", "ret");
    }

    // ── basic ────────────────────────────────────────────────────────────────

    #[test]
    fn detour_basic() -> Result<()> {
        #[unsafe(naked)]
        unsafe extern "C" fn ret5() -> i32 {
            naked_asm!("li a0, 5", "ret");
        }
        unsafe { detour_test(ret5, 5) }
    }

    // ── NOP padding (hot-patch area) ─────────────────────────────────────────

    #[test]
    fn detour_nop_padding() -> Result<()> {
        #[unsafe(naked)]
        unsafe extern "C" fn nop_ret3() -> i32 {
            naked_asm!(
                "nop",
                "nop",
                "nop",
                "nop",
                "li a0, 3",
                "ret",
            );
        }
        // Hook starting at the 5th instruction (past the NOPs).
        unsafe { detour_test(mem::transmute(nop_ret3 as usize + 16), 3) }
    }

    // ── AUIPC in prolog (PC-relative global load) ─────────────────────────────

    #[test]
    fn detour_auipc() -> Result<()> {
        static VALUE: i32 = 195;

        #[unsafe(naked)]
        unsafe extern "C" fn auipc_load() -> i32 {
            naked_asm!(
                "auipc a0, %pcrel_hi({val})",
                "lw    a0, %pcrel_lo(1b)(a0)",
                "ret",
                val = sym VALUE,
            );
        }

        unsafe { detour_test(auipc_load, 195) }
    }

    // ── unconditional branch (JAL x0) in prolog ──────────────────────────────

    #[test]
    fn detour_unconditional_branch() -> Result<()> {
        #[unsafe(naked)]
        unsafe extern "C" fn jal_ret7() -> i32 {
            naked_asm!(
                "j    done",      // JAL x0, done
                "li   a0, 0",     // dead
                "done:",
                "li   a0, 7",
                "ret",
            );
        }
        unsafe { detour_test(jal_ret7, 7) }
    }

    // ── conditional branch (BEQ) in prolog ───────────────────────────────────

    #[test]
    fn detour_conditional_branch() -> Result<()> {
        // BEQ x0, x0 is always taken (both operands are the zero register).
        // This exercises the branch_far expansion path.
        #[unsafe(naked)]
        unsafe extern "C" fn beq_ret5() -> i32 {
            naked_asm!(
                "beq  x0, x0, taken", // always taken
                "li   a0, 2",          // unreachable
                "ret",
                "taken:",
                "li   a0, 5",
                "ret",
            );
        }
        unsafe { detour_test(beq_ret5, 5) }
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

    // ── shared target (two detours on the same function) ─────────────────────

    #[test]
    fn detours_share_target() -> Result<()> {
        #[inline(never)]
        extern "C" fn add(x: i32, y: i32) -> i32 {
            unsafe { std::ptr::read_volatile(&x as *const i32) + y }
        }

        let hook1 = unsafe {
            extern "C" fn sub(x: i32, y: i32) -> i32 { x - y }
            RawDetour::new(add as *const (), sub as *const ())?
        };
        unsafe { hook1.enable()? };
        assert_eq!(add(5, 5), 0);

        let hook2 = unsafe {
            extern "C" fn div(x: i32, y: i32) -> i32 { x / y }
            RawDetour::new(add as *const (), div as *const ())?
        };
        unsafe { hook2.enable()? };

        assert_eq!(
            unsafe {
                let f: extern "C" fn(i32, i32) -> i32 = mem::transmute(hook2.trampoline());
                f(5, 5)
            },
            0
        );
        assert_eq!(add(10, 5), 2);
        Ok(())
    }
}
