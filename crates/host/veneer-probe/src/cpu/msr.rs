//! MSR (Model-Specific Register) addresses we care about during hypervisor
//! bring-up. *Constants only* — actual `rdmsr`/`wrmsr` happens in the
//! platform launcher (privileged, can't do it from user-mode).
//!
//! AMD APM Vol 2, Appendix B + Intel SDM Vol 4 are the references.

#![allow(dead_code)]

// ── shared ─────────────────────────────────────────────────────────────

/// Extended Feature Enable Register (EFER). Bit layout differs subtly
/// between AMD/Intel; veneer only sets the bits that mean the same on both.
pub const IA32_EFER: u32 = 0xC000_0080;
pub const EFER_SCE:  u64 = 1 << 0;    // SYSCALL/SYSRET enable
pub const EFER_LME:  u64 = 1 << 8;    // long-mode enable
pub const EFER_LMA:  u64 = 1 << 10;   // long-mode active (read-only)
pub const EFER_NXE:  u64 = 1 << 11;   // no-execute enable
pub const EFER_SVME: u64 = 1 << 12;   // AMD only: SVM enable

// ── AMD SVM ────────────────────────────────────────────────────────────

/// VM_CR — SVM disable bit lives here. Some BIOSes ship with SVM disabled
/// here even if CPUID claims SVM exists; we check before VMRUN.
pub const VM_CR: u32 = 0xC001_0114;
pub const VM_CR_SVMDIS:       u64 = 1 << 4;   // SVM disabled by firmware
pub const VM_CR_LOCK:         u64 = 1 << 3;   // VM_CR locked

/// VM_HSAVE_PA — physical address of a 4 KiB host-state save area, used
/// by the CPU to stash host state during VMRUN.
pub const VM_HSAVE_PA: u32 = 0xC001_0117;

// ── Intel VT-x ─────────────────────────────────────────────────────────

/// IA32_FEATURE_CONTROL — lockable register that gates whether VMX can be
/// enabled outside SMX (BIOS Lock bit 0, VMX-outside-SMX bit 2).
pub const IA32_FEATURE_CONTROL: u32 = 0x003A;
pub const FC_LOCK:               u64 = 1 << 0;
pub const FC_VMX_OUTSIDE_SMX:    u64 = 1 << 2;
pub const FC_VMX_INSIDE_SMX:     u64 = 1 << 1;

pub const IA32_VMX_BASIC:         u32 = 0x0480;
pub const IA32_VMX_PINBASED_CTLS: u32 = 0x0481;
pub const IA32_VMX_PROCBASED_CTLS: u32 = 0x0482;
pub const IA32_VMX_EXIT_CTLS:      u32 = 0x0483;
pub const IA32_VMX_ENTRY_CTLS:     u32 = 0x0484;
pub const IA32_VMX_EPT_VPID_CAP:   u32 = 0x048C;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn efer_bit_layout() {
        assert_eq!(EFER_LME, 0x100);
        assert_eq!(EFER_LMA, 0x400);
        assert_eq!(EFER_SVME, 0x1000);
    }
    #[test]
    fn vm_cr_layout() {
        assert_eq!(VM_CR_SVMDIS, 0x10);
        assert_eq!(VM_CR_LOCK,   0x08);
    }
}
