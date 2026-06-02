//! Monotonic virtual TSC.
//!
//! Under VMware nested SVM the host TSC veneer reads can take a one-time
//! step: observed as a single ~2.5e14-cycle forward jump when VMware
//! switches the L1 from a boot-relative TSC to host-TSC passthrough mid
//! boot. Timers scaled straight off raw RDTSC then wrap thousands of
//! times at the jump and strand firmware delay loops (OVMF's
//! `InternalAcpiDelay` never reaches its latched deadline).
//!
//! `now()` filters the step: a real per-call delta within a plausible
//! bound advances the virtual clock by that delta; an absurd-forward or
//! backward delta advances by a small nominal tick instead. The result
//! is monotonic and tracks real wall rate on both sides of the
//! discontinuity, so every timer built on it (`now()` units == host TSC
//! cycles) is immune to the jump.

pub mod host_tick;
pub mod tsc_freq;

use core::sync::atomic::{AtomicU64, Ordering};

/// A delta larger than this between consecutive reads is a discontinuity,
/// not elapsed time (~0.1 s at 3 GHz; real spacing is microseconds).
const MAX_PLAUSIBLE_DELTA: u64 = 300_000_000;
/// Advance substituted for a filtered step — non-zero so the clock keeps
/// moving, small enough to be negligible against real deltas.
const NOMINAL_DELTA: u64 = 1_000;

static LAST_REAL: AtomicU64 = AtomicU64::new(0);
static VIRTUAL: AtomicU64 = AtomicU64::new(0);

/// A forward delta this large between two clock reads is VMware's one-time
/// host-TSC step, not elapsed time (~333 s @3 GHz — far beyond any real idle
/// gap, far below the ~7e14-cycle step we actually observe).
const STEP_THRESHOLD: u64 = 1_000_000_000_000;
/// Set once a VMware TSC step has been observed. VMware steps MORE THAN ONCE
/// (clustered around mid-boot), so we don't go native on the first one —
/// switching too early lets a later step hit the native phase and corrupt a
/// guest timed-wait (e.g. cdboot's "press any key" countdown).
static STEP_SEEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// now()-call counter and the count at the most recent step. We only declare
/// the steps "settled" after a sustained stable stretch with no new step.
static CALL_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_STEP_CALL: AtomicU64 = AtomicU64::new(0);
/// Total VMware TSC steps observed so far (diagnostic + native-switch log).
static STEP_COUNT: AtomicU64 = AtomicU64::new(0);
/// Stable now()-calls required after the last step before going native.
/// A LATE step (after we've gone native) is no longer fatal: the dispatcher
/// reconciles every exit and RE-INTERCEPTS RDTSC on any fresh step (see
/// `vmexit::dispatch`), so this no longer has to be large enough to outlast
/// the entire cluster — it only has to outlast the gap *between* two steps in
/// the cluster, so the brief native windows mid-cluster don't expose a guest
/// timed-wait. Provisional: tune from the `[clock] TSC step` gap log.
const STABLE_CALLS: u64 = 50_000;

/// Number of VMware host-TSC steps observed so far. Used by the dispatcher's
/// native-switch log; also a coarse boot-phase signal.
pub fn steps_seen() -> u64 {
    STEP_COUNT.load(Ordering::Relaxed)
}

/// True once the VMware host-TSC step CLUSTER has passed and the clock has
/// been stable since. Until then RDTSC stays intercepted (filtered) so the
/// guest never sees a jump; the slow intercepted window is only the pre-stable
/// boot phase (no tight RDTSC delay loops there). After this the guest reads
/// RDTSC natively with the offset carrying the smooth clock.
pub fn step_absorbed() -> bool {
    STEP_SEEN.load(Ordering::Relaxed)
        && CALL_COUNT.load(Ordering::Relaxed).wrapping_sub(LAST_STEP_CALL.load(Ordering::Relaxed))
            > STABLE_CALLS
}

/// Per-call minimum advance, set by the dispatcher's tight-spin detector.
/// Non-zero while the guest is hammering one RIP (a TSC / PM-timer delay
/// loop), so any clock read in that handler — RDTSC, ACPI PM timer, HPET —
/// floors its advance and the delay converges instead of crawling on the
/// host TSC VMware throttles during busy spins.
static SPIN_FLOOR: AtomicU64 = AtomicU64::new(0);

/// Set the tight-spin advance floor (0 = not spinning). Called once per
/// VMEXIT by the dispatcher.
pub fn set_spin_floor(floor: u64) {
    SPIN_FLOOR.store(floor, Ordering::Relaxed);
}

/// Diagnostic: current tight-spin advance floor (0 = detector not engaged).
pub fn spin_floor() -> u64 {
    SPIN_FLOOR.load(Ordering::Relaxed)
}

#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)); }
    ((hi as u64) << 32) | (lo as u64)
}

/// Monotonic virtual TSC in host-TSC cycle units, immune to one-time
/// host-TSC steps. The CAS on `LAST_REAL` serialises the advance so the
/// `VIRTUAL` fetch_add can't double-count under concurrent callers.
pub fn now() -> u64 {
    now_min(SPIN_FLOOR.load(Ordering::Relaxed))
}

/// Like [`now`], but guarantees the clock advances by at least `floor`
/// cycles on this call. The RDTSC handler uses this during a detected tight
/// TSC delay-spin: VMware throttles the host TSC while our VM is busy, so the
/// real per-call delta collapses to a few cycles and a deadline that should
/// take 0.1 s would take hundreds of seconds. Flooring the advance lets the
/// spin converge at roughly the calibrated rate. `floor = 0` is plain `now`.
pub fn now_min(floor: u64) -> u64 {
    let real = rdtsc();
    let cc = CALL_COUNT.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    loop {
        let last = LAST_REAL.load(Ordering::Relaxed);
        let real_adv = if last == 0 {
            0
        } else if real > last && real - last <= MAX_PLAUSIBLE_DELTA {
            real - last
        } else {
            // Implausible forward delta. A GIANT one (≫ any real idle gap) is
            // VMware's one-time nested-SVM host-TSC step (~7e14 cycles). Flag
            // it so the dispatcher can switch the guest's RDTSC from the
            // (slow, intercepted) filtered path to NATIVE once the step is
            // safely behind us. A normal long idle gap stays well under this.
            if last != 0 && real > last && real - last > STEP_THRESHOLD {
                let prev_step_call = LAST_STEP_CALL.swap(cc, Ordering::Relaxed); // reset the stable window
                STEP_SEEN.store(true, Ordering::Relaxed);
                let n = STEP_COUNT.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
                // Diagnostic: when each step lands (call index), how far it is
                // from the previous step (calls), and its magnitude. The
                // gap_from_prev values across the cluster are exactly what
                // STABLE_CALLS must exceed; the last step's call index tells us
                // when the cluster ends relative to the heavy delay loops.
                crate::sprintln!(
                    "[clock] TSC step #{}: call={} gap_from_prev={} raw_delta=0x{:X} virt=0x{:X}",
                    n,
                    cc,
                    cc.wrapping_sub(prev_step_call),
                    real - last,
                    VIRTUAL.load(Ordering::Relaxed)
                );
            }
            NOMINAL_DELTA
        };
        let advance = real_adv.max(floor);
        if LAST_REAL
            .compare_exchange(last, real, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return VIRTUAL.fetch_add(advance, Ordering::Relaxed).wrapping_add(advance);
        }
    }
}
