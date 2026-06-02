//! One-shot guest-state snapshot for diagnosing a stuck guest (spin / deadlock
//! / NPF storm).
//!
//! Pure VMI read-out — guest registers (VMCB + software-saved GPRs) plus guest
//! memory read through `introspect`. The image base is recovered generically by
//! walking down for the PE header, so RVAs are correct wherever the guest is
//! stuck (not just at one hard-coded function). The point is to replace "patch
//! a guess, rebuild, boot" with one observation of ground truth.
//!
//! Triggered by the VMEXIT dispatcher's spin detector when the guest hammers
//! one RIP far past the convergence-floor threshold — a real wedge.

use crate::hypervisor::svm::gprs::GuestGprs;
use crate::hypervisor::svm::vmcb::Vmcb;
use crate::introspect::mem;

// Kernel-mode canonical code range the guest's nt/HAL live in (0xFFFFF80X...).
const KERN_LO: u64 = 0xFFFF_F800_0000_0000;
const KERN_HI: u64 = 0xFFFF_F810_0000_0000;
const VMEXIT_NPF: u64 = 0x400;

#[inline]
fn is_kern_code(v: u64) -> bool {
    (KERN_LO..KERN_HI).contains(&v)
}

/// Base of the PE image containing `va`: walk down 2 MiB-aligned pages for an
/// 'MZ' DOS header whose `e_lfanew` points at a 'PE\0\0' signature. OS-agnostic
/// (PE format). `max_2mb` bounds the search.
fn image_base(cr3: u64, va: u64, max_2mb: u64) -> Option<u64> {
    let mut base = va & !0x1F_FFFF;
    let mut steps = 0u64;
    loop {
        if let Some(w) = mem::read_u64(cr3, base) {
            if (w & 0xFFFF) == 0x5A4D {
                if let Some(e_lfanew) = mem::read_struct::<u32>(cr3, base + 0x3C) {
                    if let Some(sig) = mem::read_struct::<u32>(cr3, base + e_lfanew as u64) {
                        if sig == 0x0000_4550 {
                            return Some(base);
                        }
                    }
                }
            }
        }
        steps += 1;
        if steps > max_2mb || base < 0x20_0000 {
            return None;
        }
        base -= 0x20_0000;
    }
}

/// Dump current guest state. `reason` labels why we fired.
///
/// Safety: `vmcb` must be the live VMCB and `gprs` the matching software-saved
/// GPRs for this exit.
pub unsafe fn dump(vmcb: *mut Vmcb, gprs: &GuestGprs, reason: &str) {
    let s = unsafe { &(*vmcb).state };
    let c = unsafe { &(*vmcb).control };
    // Copy out of the #[repr(C, packed)] state before formatting (a reference
    // to a packed field is UB).
    let rip = s.rip;
    let rsp = s.rsp;
    let cr3 = s.cr3;
    let rflags = s.rflags;
    let cpl = s.cpl;
    let rax = s.rax;
    let vintr = c.vintr;
    let exit_code = c.exit_code;
    let info1 = c.exit_info_1;
    let info2 = c.exit_info_2;
    let vtpr = (vintr & 0xFF) as u32;
    let base = image_base(cr3, rip, 256); // up to 512 MiB below rip

    crate::sprintln!("[diag] ===== guest snapshot: {} =====", reason);
    match base {
        Some(b) => crate::sprintln!("[diag] rip=0x{:X}  image_base=0x{:X}  rip=base+0x{:X}", rip, b, rip - b),
        None => crate::sprintln!("[diag] rip=0x{:X}  image_base=<not found>", rip),
    }
    crate::sprintln!(
        "[diag] exit=0x{:X} info1=0x{:X} info2=0x{:X}{}",
        exit_code, info1, info2,
        if exit_code == VMEXIT_NPF { "  (NPF: info2=faulting GPA, info1=flags)" } else { "" }
    );
    crate::sprintln!(
        "[diag] rsp=0x{:X} cr3=0x{:X} rflags=0x{:X} (IF={}) cpl={} vtpr=0x{:02X}(cr8={})",
        rsp, cr3, rflags, (rflags >> 9) & 1, cpl, vtpr, vtpr >> 4
    );
    crate::sprintln!(
        "[diag] rdi=0x{:X} rsi=0x{:X} rbp=0x{:X} rbx=0x{:X} rcx=0x{:X} rdx=0x{:X} rax=0x{:X}",
        gprs.rdi, gprs.rsi, gprs.rbp, gprs.rbx, gprs.rcx, gprs.rdx, rax
    );

    // Instruction bytes at rip — identifies the faulting/spinning instruction.
    let mut ib = [0u8; 16];
    if mem::read_virt(cr3, rip, &mut ib) {
        crate::sprintln!("[diag] code@rip = {:02X?}", ib);
    }

    // Stack walk: the return-address chain (= call stack) for offline symbols.
    crate::sprintln!("[diag] stack (kernel return addrs):");
    let b = base.unwrap_or(0);
    let mut off = 0u64;
    let mut shown = 0u32;
    while off < 96 * 8 && shown < 32 {
        if let Some(v) = mem::read_u64(cr3, rsp.wrapping_add(off)) {
            if is_kern_code(v) {
                if b != 0 && v >= b {
                    crate::sprintln!("[diag]   [rsp+0x{:03X}] 0x{:X}  base+0x{:X}", off, v, v - b);
                } else {
                    crate::sprintln!("[diag]   [rsp+0x{:03X}] 0x{:X}", off, v);
                }
                shown += 1;
            }
        }
        off += 8;
    }
    crate::sprintln!("[diag] ===== end snapshot =====");
}
