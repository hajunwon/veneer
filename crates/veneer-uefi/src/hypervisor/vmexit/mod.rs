//! VMEXIT dispatcher.
//!
//! `dispatch()` is called after every VMRUN/VMEXIT round-trip. It looks at
//! `vmcb.control.exit_code` and routes to the appropriate handler, which
//! mutates VMCB.state in place (synthesising responses, advancing RIP, etc.)
//! and returns an `Action` telling the launcher loop what to do next.
//!
//! Handlers live in submodules (cpuid.rs, hlt.rs, ...) so v0.5 can grow
//! MSR / IO / exception handlers without touching this file.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::hypervisor::svm::gprs::GuestGprs;
use crate::hypervisor::svm::vmcb::{exit_code, Vmcb};

// ---- CPU SVM feature flags (set once at bring-up, read on every exit) ----
//
// NRIPS (CPUID 0x8000_000A.EDX bit 3): the CPU writes the linear address of
// the instruction following an intercepted one into VMCB.control.next_rip.
// When available we prefer it over the hardcoded `lengths::*` table because
// it is correct regardless of prefixes/REX bytes that the length table does
// not account for. AMD APM Vol 2 §15.7.1 lists the intercepts for which
// next_rip is valid (CPUID, MSR, CR/DR, INVLPG, IOIO, PAUSE, HLT, etc.);
// it is explicitly NOT valid for fault-class exits such as NPF, so the NPF
// path keeps decoding the instruction itself.
static NRIPS_AVAILABLE: AtomicBool = AtomicBool::new(false);
static DECODE_ASSISTS_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Record the SVM decode-helper capabilities discovered at bring-up.
pub fn set_cpu_features(nrips: bool, decode_assists: bool) {
    NRIPS_AVAILABLE.store(nrips, Ordering::Relaxed);
    DECODE_ASSISTS_AVAILABLE.store(decode_assists, Ordering::Relaxed);
}

#[inline]
pub fn nrips_available() -> bool {
    NRIPS_AVAILABLE.load(Ordering::Relaxed)
}

// Currently informational: the NPF decoder always tries guest_inst_bytes and
// falls back to abort. A future guest-RIP instruction-fetch fallback (for
// CPUs without DecodeAssists) would gate on this.
#[allow(dead_code)]
#[inline]
pub fn decode_assists_available() -> bool {
    DECODE_ASSISTS_AVAILABLE.load(Ordering::Relaxed)
}

/// Advance guest RIP past an intercepted instruction.
///
/// Prefers the hardware-supplied next_rip (NRIPS) when it is available *and*
/// plausible (non-zero and strictly ahead of the current RIP — a zero or
/// stale value means the CPU did not populate it for this intercept, so we
/// fall back to the length table). Otherwise adds the conservative hardcoded
/// `fallback_len`.
///
/// This is the single choke point that fixes the REX/prefix RIP-drift bug:
/// real Windows code carries prefixes that the fixed length constants do not
/// model, but next_rip is always exact.
///
/// `state` and `next_rip` are passed separately (rather than re-deriving from
/// `*mut Vmcb`) so callers that already hold a `&mut VmcbStateSave` borrow do
/// not create an aliasing second mutable borrow through the raw pointer.
#[inline]
pub fn advance_rip(state: &mut crate::hypervisor::svm::vmcb::VmcbStateSave, next_rip: u64, fallback_len: u64) {
    let cur_rip = state.rip;
    if nrips_available() && next_rip != 0 && next_rip > cur_rip {
        state.rip = next_rip;
    } else {
        state.rip = cur_rip.wrapping_add(fallback_len);
    }
}

// Tight-delay-spin detector. A guest hammering one RIP (RDTSC, ACPI PM-timer
// `in`, or HPET MMIO in a `rdtsc/in; cmp deadline; jl` delay loop) would
// otherwise crawl: VMware throttles our host TSC while the VM is busy, so the
// clock barely advances per iteration and a 0.1 s delay takes hundreds of
// seconds. When the same RIP exits repeatedly we set a virtual-clock advance
// floor so the delay converges at roughly the calibrated rate.
static SPIN_RIP: AtomicU64 = AtomicU64::new(0);
static SPIN_COUNT: AtomicU32 = AtomicU32::new(0);
static PROF_LOWMEM: AtomicU32 = AtomicU32::new(0);
static PROF_CDBOOT: AtomicU32 = AtomicU32::new(0);
static PROF_FW: AtomicU32 = AtomicU32::new(0);
static PROF_OTHER: AtomicU32 = AtomicU32::new(0);
static PROF_TOTAL: AtomicU32 = AtomicU32::new(0);
/// A++ phase flag: false = RDTSC intercepted (filtered, pre-step), true =
/// native (post-step, fast). Flipped once by the step-absorption check.
static RDTSC_NATIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[inline]
fn rdtsc_raw() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)); }
    ((hi as u64) << 32) | (lo as u64)
}
/// A same-RIP run this long is a wedge (deadlock), not a delay loop — delay
/// loops now converge on real time via the host tick. Fires one diag snapshot.
const DIAG_SPIN_THRESHOLD: u32 = 20_000;
const DIAG_DUMP_CAP: u32 = 3;
static DIAG_LAST_PAGE: AtomicU64 = AtomicU64::new(0);
static DIAG_DUMPS: AtomicU32 = AtomicU32::new(0);

pub mod cpuid;
pub mod cr;
pub mod decode;
pub mod dr;
pub mod dt;
pub mod exception;
pub mod hlt;
pub mod io;
pub mod lengths;
pub mod msr;
pub mod npf;
pub mod rdtsc;
pub mod stealth;
pub mod vmmcall;

#[derive(Debug, Clone, Copy)]
pub enum Action {
    /// Run VMRUN again with the current VMCB state.
    Resume,
    /// Guest reached a clean termination point.
    Halt,
    /// Something went wrong; tell the launcher to give up.
    Abort,
}

pub unsafe fn dispatch(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    let rip = unsafe { (*vmcb).state.rip };
    let code = unsafe { (*vmcb).control.exit_code };
    // Re-anchor the clock to the host HPET on each preemption tick. Reading
    // the host HPET is a VMware exit, so it's done here at tick rate (~200 Hz)
    // rather than per now() call.
    if code == exit_code::INTR && crate::infra::clock::host_tick::armed() {
        crate::infra::clock::discipline();
    }
    // The host preemption tick (physical INTR, ~200 Hz) fires at an arbitrary
    // guest RIP. Skip it in the wedge detector so it doesn't reset the
    // same-RIP run every ~5 ms and mask a real deadlock.
    if code != exit_code::INTR {
        let count = if SPIN_RIP.swap(rip, Ordering::Relaxed) == rip {
            SPIN_COUNT.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            SPIN_COUNT.store(0, Ordering::Relaxed);
            0
        };
        // Sustained same-RIP spin far past the floor threshold = a real wedge.
        // Fire once per distinct stall page (cap a few) so a transient earlier
        // spin AND the terminal wedge are both captured if they differ.
        if count >= DIAG_SPIN_THRESHOLD {
            let page = rip & !0xFFF;
            if DIAG_LAST_PAGE.load(Ordering::Relaxed) != page
                && DIAG_DUMPS.load(Ordering::Relaxed) < DIAG_DUMP_CAP
            {
                DIAG_LAST_PAGE.store(page, Ordering::Relaxed);
                DIAG_DUMPS.fetch_add(1, Ordering::Relaxed);
                unsafe { crate::diag::snapshot::dump(vmcb, gprs, "sustained-spin") };
            }
        }
    }

    // Real-time RIP profiler: VMEXITs in the slow phase are dominated by the
    // host timer's physical-INTR exits (~1 kHz), so bucketing the interrupted
    // RIP by region approximates where guest *wall-clock* time is spent. Logs
    // a windowed distribution so we can see the exact code soaking the runtime.
    {
        if (0x0010_0000..0x1000_0000).contains(&rip) { PROF_LOWMEM.fetch_add(1, Ordering::Relaxed); }
        else if (0x1000_0000..0x1100_0000).contains(&rip) { PROF_CDBOOT.fetch_add(1, Ordering::Relaxed); }
        else if (0x7E00_0000..0x8000_0000).contains(&rip) { PROF_FW.fetch_add(1, Ordering::Relaxed); }
        else { PROF_OTHER.fetch_add(1, Ordering::Relaxed); }
        let t = PROF_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        if t % 50000 == 0 {
            crate::sprintln!("[prof] win50k: lowmem(winload)={} cdboot={} fw(ovmf)={} other={} lastrip=0x{:X}",
                PROF_LOWMEM.swap(0, Ordering::Relaxed),
                PROF_CDBOOT.swap(0, Ordering::Relaxed),
                PROF_FW.swap(0, Ordering::Relaxed),
                PROF_OTHER.swap(0, Ordering::Relaxed),
                rip);
        }
    }

    // A+ TSC step absorption: the OVMF guest runs RDTSC NATIVELY (we don't
    // intercept it — that cost a ~500µs nested VMEXIT each and wedged the
    // delay loops). To keep the guest's native TSC smooth despite VMware's
    // one-time nested-SVM host-TSC step (~700e12-cycle forward jump), retune
    // VMCB.tsc_offset every exit so guest_tsc = host_tsc + offset = the
    // step-filtered monotonic clock::now(). clock::now() absorbs the jump
    // (NOMINAL advance on implausible deltas), so the guest never sees it and
    // timed waits (cdboot "press any key", winload Stall) keep real durations.
    unsafe {
        let host = rdtsc_raw();
        let smooth = crate::infra::clock::now();
        (*vmcb).control.tsc_offset = smooth.wrapping_sub(host);
    }

    // A++ adaptive phase-switch (hysteresis): RDTSC is INTERCEPTED (filtered →
    // the guest never sees VMware's host-TSC step, at the cost of a nested
    // VMEXIT per RDTSC) while a step is recent, and NATIVE (host_tsc + offset,
    // no VMEXIT, bare-metal-like) once the clock has been quiet for
    // STABLE_CALLS. clock::step_absorbed() is the oracle. We RECONCILE the
    // intercept state to it on every exit rather than switching once:
    //   * quiet & currently intercepted  -> go NATIVE
    //   * fresh step & currently native   -> RE-INTERCEPT until quiet again
    // VMware steps the TSC in a CLUSTER, not once, so a one-shot switch had to
    // wait out the whole cluster (huge STABLE_CALLS) or risk a late step hitting
    // the native phase and corrupting a guest timed-wait (cdboot's "press any
    // key" countdown). Re-intercepting on any late step removes that risk, so
    // the window only has to outlast the intra-cluster gap. The offset retuned
    // above carries the smooth clock across every transition.
    {
        let want_native = crate::infra::clock::step_absorbed();
        let is_native = RDTSC_NATIVE.load(Ordering::Relaxed);
        if want_native && !is_native {
            RDTSC_NATIVE.store(true, Ordering::Relaxed);
            unsafe {
                let c = &mut (*vmcb).control;
                c.intercept_vec1 &= !crate::hypervisor::svm::vmcb::intercept_vec1::RDTSC;
                c.intercept_vec2 &= !crate::hypervisor::svm::vmcb::intercept_vec2::RDTSCP;
            }
            crate::sprintln!(
                "[clock] step cluster quiet ({} steps) -> RDTSC NATIVE (no intercept)",
                crate::infra::clock::steps_seen()
            );
        } else if !want_native && is_native {
            // A new step arrived after we'd gone native. Re-arm the intercept so
            // the filtered path hides it from the guest until things settle.
            RDTSC_NATIVE.store(false, Ordering::Relaxed);
            unsafe {
                let c = &mut (*vmcb).control;
                c.intercept_vec1 |= crate::hypervisor::svm::vmcb::intercept_vec1::RDTSC;
                c.intercept_vec2 |= crate::hypervisor::svm::vmcb::intercept_vec2::RDTSCP;
            }
            crate::sprintln!(
                "[clock] late TSC step (now {} total) -> RDTSC RE-INTERCEPTED",
                crate::infra::clock::steps_seen()
            );
        }
    }

    let action = unsafe { dispatch_exit(vmcb, gprs) };
    // After the per-exit handler runs, stage any pending interrupts
    // (LAPIC timer, future IO-APIC / PIC) so hardware injects them on
    // the next VMRUN entry. Only fire on Resume — Halt/Abort terminate
    // the VMRUN loop and any pending IRQ is moot.
    if matches!(action, Action::Resume) {
        unsafe { crate::hardware::devices::irq::inject::stage_pending(vmcb) };
    }
    action
}

unsafe fn dispatch_exit(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    let code = unsafe { (*vmcb).control.exit_code };
    if exception::is_exception(code) {
        // #DB (vector 1) may be the completion of a hook single-step.
        if code == exception::EXCP_BASE + 1 && unsafe { crate::introspect::hook::on_single_step(vmcb) } {
            return Action::Resume;
        }
        return unsafe { exception::handle(vmcb, gprs) };
    }
    if exit_code::is_cr_read(code) {
        let n = (code - exit_code::CR_READ_BASE) as u8;
        return unsafe { cr::handle_read(vmcb, gprs, n) };
    }
    if exit_code::is_cr_write(code) {
        let n = (code - exit_code::CR_WRITE_BASE) as u8;
        return unsafe { cr::handle_write(vmcb, gprs, n) };
    }
    if exit_code::is_dr_read(code) {
        return unsafe { dr::handle_read(vmcb, gprs) };
    }
    if exit_code::is_dr_write(code) {
        return unsafe { dr::handle_write(vmcb, gprs) };
    }
    match code {
        // Host preemption tick (host_tick): a physical interrupt forced this
        // exit so we could inject pending guest IRQs. The interrupt itself was
        // already drained by the interrupt window in vmrun::vmrun; nothing to do
        // but resume — stage_pending (on Resume) delivers the guest's timer/IRQ.
        exit_code::INTR => Action::Resume,
        exit_code::CPUID => unsafe { cpuid::handle(vmcb, gprs) },
        exit_code::HLT => unsafe { hlt::handle(vmcb, gprs) },
        exit_code::IOIO => unsafe { io::handle(vmcb, gprs) },
        exit_code::MSR => {
            // exit_info_1 bit 0: 0 = RDMSR, 1 = WRMSR
            let is_write = unsafe { (*vmcb).control.exit_info_1 & 1 } != 0;
            if is_write {
                unsafe { msr::handle_wrmsr(vmcb, gprs) }
            } else {
                unsafe { msr::handle_rdmsr(vmcb, gprs) }
            }
        }
        exit_code::RDTSC => unsafe { rdtsc::handle(vmcb, gprs) },
        exit_code::RDTSCP => unsafe { rdtsc::handle_rdtscp(vmcb, gprs) },
        exit_code::VMMCALL => unsafe { vmmcall::handle(vmcb, gprs) },
        exit_code::NPF => unsafe { npf::handle(vmcb, gprs) },
        exit_code::RDPMC => unsafe { stealth::handle_rdpmc(vmcb, gprs) },
        exit_code::PUSHF => unsafe { stealth::handle_pushf(vmcb, gprs) },
        exit_code::POPF => unsafe { stealth::handle_popf(vmcb, gprs) },
        exit_code::IDTR_READ => unsafe { dt::handle_sidt(vmcb, gprs) },
        exit_code::GDTR_READ => unsafe { dt::handle_sgdt(vmcb, gprs) },
        exit_code::LDTR_READ => unsafe { dt::handle_sldt(vmcb, gprs) },
        exit_code::TR_READ => unsafe { dt::handle_str(vmcb, gprs) },
        exit_code::INVD => unsafe { stealth::handle_invd(vmcb, gprs) },
        exit_code::WBINVD => unsafe { stealth::handle_wbinvd(vmcb, gprs) },
        exit_code::MONITOR => unsafe { stealth::handle_monitor(vmcb, gprs) },
        exit_code::MWAIT => unsafe { stealth::handle_mwait(vmcb, gprs) },
        exit_code::XSETBV => unsafe { stealth::handle_xsetbv(vmcb, gprs) },
        exit_code::INVALID => Action::Abort,
        // PAUSE (0x77): DIAG only — intercepted so a guest CpuDeadLoop
        // (pause spin with IF=0) still yields VMEXITs for the stuck dumper.
        // Step past `F3 90` — with NRIPS this is exact even if the encoding
        // carries extra prefixes; otherwise fall back to the 2-byte length.
        0x77 => {
            let next_rip = unsafe { (*vmcb).control.next_rip };
            let s = unsafe { &mut (*vmcb).state };
            advance_rip(s, next_rip, lengths::PAUSE);
            Action::Resume
        }
        _ => Action::Abort,
    }
}
