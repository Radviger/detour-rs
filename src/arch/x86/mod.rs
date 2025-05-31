#![allow(named_asm_labels)]
pub use self::patcher::Patcher;
pub use self::trampoline::Trampoline;

pub mod meta;
mod patcher;
mod thunk;
mod trampoline;

// TODO: Add test for targets further away than DETOUR_RANGE
// TODO: Add test for unsupported branches
// TODO: Add test for negative branch displacements
#[cfg(all(feature = "nightly", test))]
mod tests {
  use std::arch::naked_asm;
  use crate::error::{Error, Result};
  use crate::RawDetour;
  use matches::assert_matches;
  use std::mem;

  /// Default test case function definition.
  type CRet = unsafe extern "C" fn() -> i32;

  /// Detours a C function returning an integer, and asserts its return value.
  #[inline(never)]
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

  #[test]
  fn detour_relative_branch() -> Result<()> {
    #[unsafe(naked)]
    unsafe extern "C" fn branch_ret5() -> i32 {
      naked_asm!(
        "
            xor eax, eax
            je ret5
            mov eax, 2
            jmp done
          ret5:
            mov eax, 5
          done:
            ret",
      );
    }

    unsafe { detour_test(mem::transmute(branch_ret5 as usize), 5) }
  }

  #[test]
  fn detour_hotpatch() -> Result<()> {
    #[unsafe(naked)]
    unsafe extern "C" fn hotpatch_ret0() -> i32 {
      naked_asm!(
        "
            nop
            nop
            nop
            nop
            nop
            xor eax, eax
            ret
            mov eax, 5",
      );
    }

    unsafe { detour_test(mem::transmute(hotpatch_ret0 as usize + 5), 0) }
  }

  #[test]
  fn detour_padding_after() -> Result<()> {
    #[unsafe(naked)]
    unsafe extern "C" fn padding_after_ret0() -> i32 {
      naked_asm!(
        "
            mov edi, edi
            xor eax, eax
            ret
            nop
            nop",
      );
    }

    unsafe { detour_test(mem::transmute(padding_after_ret0 as usize + 2), 0) }
  }

  #[test]
  fn detour_external_loop() {
    #[unsafe(naked)]
    unsafe extern "C" fn external_loop() -> i32 {
      naked_asm!(
        "
            loop dest
            nop
            nop
            nop
            dest:",
      );
    }

    let error =
      unsafe { RawDetour::new(external_loop as *const (), ret10 as *const ()) }.unwrap_err();
    assert_matches!(error, Error::UnsupportedInstruction);
  }

  #[test]
  #[cfg(target_arch = "x86_64")]
  fn detour_rip_relative_pos() -> Result<()> {
    #[unsafe(naked)]
    unsafe extern "C" fn rip_relative_ret195() -> i32 {
      naked_asm!(
        "
            xor eax, eax
            mov al, [rip+0x3]
            nop
            nop
            nop
            ret",
      );
    }

    unsafe { detour_test(rip_relative_ret195, 195) }
  }

  #[test]
  #[cfg(target_arch = "x86_64")]
  fn detour_rip_relative_neg() -> Result<()> {
    #[unsafe(naked)]
    unsafe extern "C" fn rip_relative_prolog_ret49() -> i32 {
      naked_asm!(
        "
            xor eax, eax
            mov al, [rip-0x8]
            ret",
      );
    }

    unsafe { detour_test(rip_relative_prolog_ret49, 49) }
  }

  /// Default detour target.
  unsafe extern "C" fn ret10() -> i32 {
    10
  }
}
