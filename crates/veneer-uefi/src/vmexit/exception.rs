//! Exception (#0..#31) intercept handler.
//!
//! We arm the VMCB to intercept *every* CPU exception (intercept_exceptions
//! = 0xFFFFFFFF). The default behaviour for any exception in v0.5-batch is
//! to log it and abort — none of them should happen for our well-formed
//! guest. Once a real OS boots as a guest, individual vectors get routed
//! to per-exception handlers (#PF for shadow-paging, #UD for emulation,
//! etc.).

use crate::svm::gprs::GuestGprs;
use crate::svm::vmcb::Vmcb;

use super::Action;

/// AMD exit_code range for exceptions: 0x040..=0x05F (vector 0..31).
pub const EXCP_BASE: u64 = 0x40;
pub const EXCP_MAX: u64 = 0x5F;

#[inline]
pub fn is_exception(exit_code: u64) -> bool {
    (EXCP_BASE..=EXCP_MAX).contains(&exit_code)
}

pub unsafe fn handle(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    let c = unsafe { &(*vmcb).control };
    let s = unsafe { &(*vmcb).state };
    // Pull packed-struct fields by value before formatting (sprintln
    // takes references, which is UB on packed fields).
    let exit_code  = { c.exit_code };
    let exit_info1 = { c.exit_info_1 };
    let exit_info2 = { c.exit_info_2 };
    let rip = s.rip;
    let rax = s.rax;
    let rsp = s.rsp;
    let vector = (exit_code - EXCP_BASE) as u8;
    crate::sprintln!(
        "[excp!] {} (vec=0x{:X}) info1=0x{:X} info2=0x{:X} RIP=0x{:016X}",
        name(vector), vector, exit_info1, exit_info2, rip,
    );
    crate::sprintln!(
        "[excp!]   RAX=0x{:X} RBX=0x{:X} RCX=0x{:X} RDX=0x{:X} RSP=0x{:X} RBP=0x{:X}",
        rax, gprs.rbx, gprs.rcx, gprs.rdx, rsp, gprs.rbp,
    );
    Action::Abort
}

/// Friendly name for the standard 0..31 exception vectors. Used by the
/// launcher's report when an exception fires.
pub fn name(vector: u8) -> &'static str {
    match vector {
        0 => "#DE  divide-by-zero",
        1 => "#DB  debug",
        2 => "NMI",
        3 => "#BP  breakpoint",
        4 => "#OF  overflow",
        5 => "#BR  bound-range",
        6 => "#UD  invalid-opcode",
        7 => "#NM  device-not-available",
        8 => "#DF  double-fault",
        10 => "#TS  invalid-tss",
        11 => "#NP  segment-not-present",
        12 => "#SS  stack-segment-fault",
        13 => "#GP  general-protection",
        14 => "#PF  page-fault",
        16 => "#MF  x87-floating-point",
        17 => "#AC  alignment-check",
        18 => "#MC  machine-check",
        19 => "#XF  SIMD-floating-point",
        21 => "#CP  control-protection",
        _ => "(reserved)",
    }
}
