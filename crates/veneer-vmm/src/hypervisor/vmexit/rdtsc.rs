//! RDTSC / RDTSCP intercept handlers.
//!
//! Standard hypervisor model (KVM `vmx_handle_exit` for RDTSC,
//! Cloud Hypervisor, Firecracker): when the guest executes RDTSC we
//! return (host_tsc + VMCB.tsc_offset). The offset is set once at
//! guest entry (`enter_linux_guest`) so the guest sees RDTSC counting
//! from ~0 at boot, exactly like a real PC at power-on.
//!
//! Earlier veneer revisions advanced a software counter by a fixed
//! 30-cycle stride on each intercepted RDTSC. That broke two things:
//!   1. The guest's perceived TSC rate was decoupled from wall clock
//!      time — PIT-based calibration measured an unrealistic value
//!      and BogoMIPS / sleep durations were nonsensical.
//!   2. A fixed inter-RDTSC delta is itself a fingerprint — real CPUs
//!      produce variable deltas depending on pipeline state, cache,
//!      and pending µops. Constant 30 cycles is an *active* tell.
//!
//! Now we just read the host TSC and let the offset do the rest.
//! Variance arises naturally from the host's own execution noise.

use crate::hypervisor::svm::gprs::GuestGprs;
use crate::hypervisor::svm::vmcb::Vmcb;

use super::{lengths, Action};

/// Read host TSC and add the active VMCB tsc_offset — the same
/// computation hardware would do if RDTSC weren't intercepted.
///
/// We use the `RDTSC` instruction itself (`_rdtsc`) rather than
/// `RDMSR(0x10)` because the two can diverge under VMware nested
/// SVM: VMware virtualises the RDTSC instruction at a controlled
/// rate but leaves RDMSR(IA32_TSC) reading the real host TSC. Our
/// `tsc_freq::calibrate` measures the rate using `_rdtsc`; staying
/// on the same source keeps every timestamp consistent.
unsafe fn synthesise_tsc(vmcb: *mut Vmcb, gprs: &mut GuestGprs) {
    // Guest-visible TSC = the filtered monotonic virtual clock, not raw
    // host TSC + offset. The raw counter takes VMware's one-time nested-SVM
    // TSC step, which leapt the guest clocksource ~160000 s forward and
    // tripped an RCU stall (fatal once ACPI IRQ routing / _PRT was active).
    // clock::now() is the same domain the LAPIC timer and ACPI PM timer use,
    // so every guest time source stays mutually consistent and step-immune.
    // The tight-delay-spin floor (clock::now_min) is applied centrally by the
    // dispatcher's RIP tracker, so a plain now() here already reflects it.
    let visible = crate::infra::clock::now();
    let s = unsafe { &mut (*vmcb).state };
    s.rax = visible & 0xFFFF_FFFF;
    gprs.rdx = (visible >> 32) & 0xFFFF_FFFF;
}

pub unsafe fn handle(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    unsafe { synthesise_tsc(vmcb, gprs) };
    let s = unsafe { &mut (*vmcb).state };
    s.rip = s.rip.wrapping_add(lengths::RDTSC);
    Action::Resume
}

/// RDTSCP differs from RDTSC only in that it also writes ECX (= IA32_TSC_AUX).
/// We expose a fixed processor-signature word (0) — anti-detect: don't leak
/// host TSC_AUX which often carries the host's NUMA node / APIC ID.
pub unsafe fn handle_rdtscp(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    unsafe { synthesise_tsc(vmcb, gprs) };
    gprs.rcx = 0; // hide IA32_TSC_AUX
    let s = unsafe { &mut (*vmcb).state };
    s.rip = s.rip.wrapping_add(lengths::RDTSCP);
    Action::Resume
}
