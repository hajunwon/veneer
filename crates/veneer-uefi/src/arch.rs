//! Raw x86_64 architectural primitives needed inside the UEFI app:
//! port I/O, CPUID, MSR access, halt. All `unsafe` for a reason — the caller
//! is responsible for "the CPU is actually AMD and supports this MSR" etc.

use core::arch::asm;

#[derive(Clone, Copy, Debug)]
pub struct CpuidRegs {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

#[inline]
pub fn cpuid(leaf: u32) -> CpuidRegs {
    cpuid_count(leaf, 0)
}

#[inline]
pub fn cpuid_count(leaf: u32, sub: u32) -> CpuidRegs {
    let mut eax = leaf;
    let mut ebx: u32;
    let mut ecx = sub;
    let mut edx: u32;
    unsafe {
        asm!(
            "mov {0:r}, rbx",
            "cpuid",
            "xchg rbx, {0:r}",
            out(reg) ebx,
            inout("eax") eax,
            inout("ecx") ecx,
            lateout("edx") edx,
            options(nostack, preserves_flags),
        );
    }
    CpuidRegs { eax, ebx, ecx, edx }
}

#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo,
        out("edx") hi,
        options(nomem, nostack, preserves_flags),
    );
    ((hi as u64) << 32) | (lo as u64)
}

#[inline]
pub unsafe fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") lo,
        in("edx") hi,
        options(nomem, nostack, preserves_flags),
    );
}

#[inline]
pub unsafe fn outb(port: u16, val: u8) {
    asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nomem, nostack, preserves_flags),
    );
}

#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    asm!(
        "in al, dx",
        in("dx") port,
        out("al") val,
        options(nomem, nostack, preserves_flags),
    );
    val
}

#[inline]
pub fn read_cr0() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) }
    v
}

#[inline]
pub fn read_cr3() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) }
    v
}

#[inline]
pub fn read_cr4() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) }
    v
}

pub fn halt_forever() -> ! {
    loop {
        unsafe {
            asm!("cli; hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

// AMD-specific MSRs and EFER bits (AMD APM Vol 2 §15.3, Appendix A)
pub const MSR_EFER: u32 = 0xC000_0080;
pub const MSR_VM_HSAVE_PA: u32 = 0xC001_0117;
pub const EFER_SVME: u64 = 1 << 12;
