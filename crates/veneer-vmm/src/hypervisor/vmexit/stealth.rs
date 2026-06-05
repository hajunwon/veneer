//! Stealth handlers — block side-channel hypervisor detection paths.
//!
//! Each handler here trades guest correctness on a particular fringe
//! instruction for hypervisor invisibility. Real OS-boot will need most
//! of these reworked to honour ring-3 semantics (UMIP, etc.); for now we
//! just ensure none of them leak host state.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::infra::arch::cpuid;
use crate::hypervisor::svm::gprs::GuestGprs;
use crate::hypervisor::svm::vmcb::Vmcb;

use super::{lengths, Action};

// Per-vCPU monotonic performance counters. A real PMU advances each
// counter on selected events (instructions retired, branch mispredicts,
// cache misses, …) — anything from a few hundred to millions per
// millisecond. Returning a *fixed* 0 every call is a tell: real CPUs
// always have *some* activity. We pick a conservative per-call stride
// that's plausible for "things you'd see on a quiet system".
const MAX_VCPU_SLOTS: usize = 256;
const RDPMC_STRIDE: u64 = 0x1_0000; // ~65 K events per RDPMC call

#[allow(clippy::declare_interior_mutable_const)]
const COUNTER_INIT: AtomicU64 = AtomicU64::new(0);
static RDPMC_COUNTERS: [AtomicU64; MAX_VCPU_SLOTS] = [COUNTER_INIT; MAX_VCPU_SLOTS];

#[inline]
fn current_vcpu_slot() -> usize {
    ((cpuid(1).ebx >> 24) & 0xFF) as usize
}

pub unsafe fn handle_rdpmc(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    // Advance the per-vCPU counter and return its new value split into
    // RDX:RAX the way RDPMC does. Stays monotonic across calls so
    // `rdpmc; rdpmc` always shows non-zero delta — same shape a real
    // PMU produces on a barely-loaded core.
    let slot = current_vcpu_slot();
    let prior = RDPMC_COUNTERS[slot].fetch_add(RDPMC_STRIDE, Ordering::Relaxed);
    let value = prior.wrapping_add(RDPMC_STRIDE);
    let s = unsafe { &mut (*vmcb).state };
    s.rax = value & 0xFFFF_FFFF;
    gprs.rdx = (value >> 32) & 0xFFFF_FFFF;
    s.rip = s.rip.wrapping_add(lengths::RDPMC);
    Action::Resume
}

pub unsafe fn handle_pushf(vmcb: *mut Vmcb, _gprs: &mut GuestGprs) -> Action {
    let s = unsafe { &mut (*vmcb).state };
    // Skip the actual stack write; emulating it requires resolving the
    // guest RSP through GVA → GPA → HPA. The fact that we *trapped* the
    // pushf is what matters here — we let the guest continue. Future
    // work: actually push a synthesised RFLAGS the guest expects.
    s.rip = s.rip.wrapping_add(lengths::PUSHF);
    Action::Resume
}

pub unsafe fn handle_popf(vmcb: *mut Vmcb, _gprs: &mut GuestGprs) -> Action {
    let s = unsafe { &mut (*vmcb).state };
    // Likewise drop. Guest's IF/TF/etc. requests don't escape veneer.
    s.rip = s.rip.wrapping_add(lengths::POPF);
    Action::Resume
}

/// INVD — invalidate cache without writeback (CPL-0). Silently absorbed:
/// our micro-blob doesn't actually need cache invalidation, and nested-OS
/// support would issue a real `invd` on the host. Returning a #VMEXIT
/// without doing anything is fine because the guest hasn't observed any
/// state we need to flush.
pub unsafe fn handle_invd(vmcb: *mut Vmcb, _gprs: &mut GuestGprs) -> Action {
    let s = unsafe { &mut (*vmcb).state };
    s.rip = s.rip.wrapping_add(lengths::INVD);
    Action::Resume
}

/// WBINVD — writeback + invalidate. Same story as INVD. Nested-OS will
/// want a real host `wbinvd` here for cache-coherent device DMA.
pub unsafe fn handle_wbinvd(vmcb: *mut Vmcb, _gprs: &mut GuestGprs) -> Action {
    let s = unsafe { &mut (*vmcb).state };
    s.rip = s.rip.wrapping_add(lengths::WBINVD);
    Action::Resume
}

/// MONITOR — arm a memory address for MWAIT wakeup. Real semantics
/// require RAX/RCX/RDX to be valid; we silently absorb. The matching
/// MWAIT (below) will also be intercepted, so the guest won't actually
/// stall the host CPU on a guest virtual address.
pub unsafe fn handle_monitor(vmcb: *mut Vmcb, _gprs: &mut GuestGprs) -> Action {
    let s = unsafe { &mut (*vmcb).state };
    s.rip = s.rip.wrapping_add(lengths::MONITOR);
    Action::Resume
}

/// MWAIT — sleep until the previously armed monitor fires. We do not
/// actually halt the host CPU; we just resume the guest. For nested-OS
/// idling we may eventually park here in HLT-like fashion.
pub unsafe fn handle_mwait(vmcb: *mut Vmcb, _gprs: &mut GuestGprs) -> Action {
    let s = unsafe { &mut (*vmcb).state };
    s.rip = s.rip.wrapping_add(lengths::MWAIT);
    Action::Resume
}

/// XSETBV — write extended-state enable mask (XCR0/XCR1). EDX:EAX is
/// the value, ECX selects the register (only 0 = XCR0 is defined).
///
/// Standard hypervisor emulation: clamp the guest's requested bits
/// against the host's actual XCR0 valid mask (CPUID 0xD sub-leaf 0,
/// EDX:EAX), force bit 0 (x87 FPU, mandatory), then issue the real
/// XSETBV against the host CPU. The result is that the guest can
/// successfully turn on AVX / AVX-512 / etc. up to whatever the host
/// supports; bits the host doesn't have are silently dropped instead
/// of triggering a #GP that would crash the guest kernel.
///
/// Earlier veneer revisions silently no-op'd this. Real OSes interpret
/// the absorbed write as success, then try to xsave/xrstor based on
/// the bitmap they THINK is live — when host XCR0 doesn't match, the
/// XSAVE area size disagrees and `fpu__init_system_xstate` WARNs and
/// panics ("Attempted to kill the idle task").
pub unsafe fn handle_xsetbv(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    let s = unsafe { &mut (*vmcb).state };
    let xcr_id = gprs.rcx as u32;

    if xcr_id == 0 {
        // Valid XCR0 bits from host CPUID 0xD sub-leaf 0.
        let host_d = crate::infra::arch::cpuid(0x0000_000D);
        let valid_lo = host_d.eax;
        let valid_hi = host_d.edx;

        // Guest-requested value.
        let lo = (s.rax & 0xFFFF_FFFF) as u32;
        let hi = (gprs.rdx & 0xFFFF_FFFF) as u32;

        // Clamp + force x87 (bit 0). Forcing it satisfies the Intel/AMD
        // architectural requirement that XCR0.X87 = 1; sloppy guests
        // sometimes clear it and the actual XSETBV would #GP.
        let clamped_lo = (lo & valid_lo) | 0x1;
        let clamped_hi = hi & valid_hi;

        // XSETBV raises #UD when CR4.OSXSAVE is clear — UEFI Boot
        // Services typically leaves it off because the firmware
        // doesn't itself touch XSAVE state. Set it before issuing the
        // instruction so we don't crash the hypervisor with an
        // invalid-opcode trap inside this handler.
        unsafe {
            let mut cr4: u64;
            core::arch::asm!(
                "mov {}, cr4",
                out(reg) cr4,
                options(nomem, nostack, preserves_flags),
            );
            if cr4 & (1u64 << 18) == 0 {
                cr4 |= 1u64 << 18; // OSXSAVE
                core::arch::asm!(
                    "mov cr4, {}",
                    in(reg) cr4,
                    options(nomem, nostack, preserves_flags),
                );
            }
        }

        // Issue the real instruction against host CPU.
        unsafe {
            core::arch::asm!(
                "xsetbv",
                in("ecx") xcr_id,
                in("eax") clamped_lo,
                in("edx") clamped_hi,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    // xcr_id != 0: only XCR0 is architecturally defined. We silently
    // accept (advancing RIP); a strict implementation would inject
    // #GP(0), but none of our boot targets touch XCR1+ today.

    s.rip = s.rip.wrapping_add(lengths::XSETBV);
    Action::Resume
}
