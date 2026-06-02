//! Host TSC frequency calibration against real wall-clock time.
//!
//! veneer's PIT emulator (intercept/pit.rs), kvmclock anchor, and
//! HPET counter scaling all need to translate host TSC cycles into
//! seconds. Getting that ratio right is harder than it looks under
//! VMware nested SVM: VMware can virtualise both the RDTSC instruction
//! *and* the PIT in lockstep at a rate that's hundreds of times the
//! real wall clock. PIT-vs-TSC calibration measures their ratio
//! correctly, but a guest using our cpu_khz figure ends up with a
//! kernel clock that races against actual time (boot reaches
//! `[22000.000]` after ~30 seconds of real time).
//!
//! Anchor on real wall clock instead. `uefi::boot::stall(N)` blocks
//! for N microseconds of true elapsed time per the UEFI Boot Services
//! spec (the firmware uses its own hardware timer source). Sandwich
//! `_rdtsc()` reads around it and divide.
//!
//! Cross-checked with PIT counter polling as a sanity guard: if the two
//! disagree by more than a few percent the wall-clock figure wins
//! (PIT-derived is what was already broken). Both numbers get logged
//! so the operator can spot virtualised-clock weirdness.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{inb, outb};

/// Nominal PIT frequency — fixed by ISA spec since 1981.
const PIT_FREQ_HZ: u64 = 1_193_182;

/// Calibration interval: 50 ms at 1.193 MHz ≈ 59659 PIT ticks. Round to
/// 0xE903 (= 59651, close enough — the residual tolerance gets absorbed
/// into the actual measured tsc/wall_clock ratio).
const CALIBRATE_TICKS: u16 = 0xE903;

/// Wall-clock interval handed to `uefi::boot::stall` for the primary
/// calibration. 50 ms is long enough to dwarf any single host
/// scheduling hiccup yet short enough that veneer startup doesn't
/// stall the user-visible boot.
const STALL_MICROS: usize = 50_000;

/// Fallback when calibration fails (unlikely — PIT is one of the most
/// reliable bits of x86 hardware). Matches Ryzen 7000-series base clock.
const FALLBACK_HZ: u64 = 4_700_000_000;

/// Measured host TSC frequency in Hz. Set once by `calibrate()`; read by
/// any emulator that needs to translate host TSC cycles to wall-clock
/// time. Initial 0 means "not measured yet" — `host_tsc_freq()` returns
/// the fallback in that case.
static HOST_TSC_FREQ: AtomicU64 = AtomicU64::new(0);

#[inline]
fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Measure host TSC frequency. Two methods cross-checked:
///   1. UEFI Boot Services `stall(50ms)` — anchored on real wall clock
///      via firmware's own timer source. Authoritative.
///   2. PIT counter-2 polling — same routine Linux uses. Logged as a
///      sanity check; ignored if it disagrees badly (which it does
///      under VMware nested SVM, where both the PIT and the RDTSC
///      instruction race wall clock by ~700×).
///
/// Safety: must be called from CPL=0 during UEFI BootServices (before
/// `ExitBootServices` and before SVM intercepts can redirect IO ports).
pub fn calibrate() -> u64 {
    let wall = calibrate_via_stall();
    let pit = calibrate_via_pit();
    // Real-time anchor wins; PIT is informational only.
    crate::sprintln!(
        "[tsc ] calibration: wall-stall = {} Hz, PIT-poll = {} Hz ({}%)",
        wall, pit,
        if wall != 0 { pit.saturating_mul(100) / wall } else { 0 },
    );
    HOST_TSC_FREQ.store(wall, Ordering::Relaxed);
    wall
}

/// Method 1 — wall-clock anchored via UEFI Boot Services Stall.
fn calibrate_via_stall() -> u64 {
    let t1 = rdtsc();
    uefi::boot::stall(STALL_MICROS);
    let t2 = rdtsc();
    let delta = t2.wrapping_sub(t1);
    // delta cycles per STALL_MICROS microseconds → freq in Hz.
    let freq = (delta.saturating_mul(1_000_000)) / (STALL_MICROS as u64);
    if freq == 0 { FALLBACK_HZ } else { freq }
}

/// Method 3 — wall-clock anchored via RTC Update-In-Progress edge.
///
/// The MC146818 RTC asserts its Status A bit 7 (UIP) for ~244 µs at the
/// start of every wall-clock second. Polling for two consecutive UIP=1
/// edges samples exactly one second of true wall clock — and crucially,
/// the RTC stays on wall clock even when the host TSC has been scaled
/// by a virtualisation layer (VMware nested SVM, Hyper-V root, etc.).
/// Boot Services `stall` and the PIT both fail this test under nested
/// SVM; RTC is the only host-visible clock source we've found that
/// holds wall-clock semantics after SVM is armed.
///
/// Uses raw `inb`/`outb` against ports 0x70/0x71 — safe at CPL=0 in
/// host context; guest accesses are routed through `intercept/rtc.rs`.
pub fn calibrate_via_rtc_uip() -> u64 {
    /// Read CMOS Status A register (index 0x0A) without disturbing
    /// any other index latch. Bit 7 = UIP.
    fn uip_high() -> bool {
        unsafe { outb(0x70, 0x0A) };
        (unsafe { inb(0x71) }) & 0x80 != 0
    }

    // Iteration cap protects against a wedged RTC — UEFI environments
    // without a working RTC fall back to the bare-metal default rather
    // than hanging boot. A normal RTC fires UIP within 1 second.
    const SPIN_CAP: u64 = 1_000_000_000;

    // 1. Skip any current UIP window so we don't accidentally measure
    //    less than one full second.
    let mut spins: u64 = 0;
    while uip_high() {
        spins += 1;
        if spins >= SPIN_CAP { return FALLBACK_HZ; }
    }
    // 2. Wait for the next UIP=1 — start of a new second.
    spins = 0;
    while !uip_high() {
        spins += 1;
        if spins >= SPIN_CAP { return FALLBACK_HZ; }
    }
    let t1 = rdtsc();
    // 3. Skip this UIP window.
    spins = 0;
    while uip_high() {
        spins += 1;
        if spins >= SPIN_CAP { return FALLBACK_HZ; }
    }
    // 4. Wait for the next UIP=1 — exactly one wall-clock second later.
    spins = 0;
    while !uip_high() {
        spins += 1;
        if spins >= SPIN_CAP { return FALLBACK_HZ; }
    }
    let t2 = rdtsc();

    let delta = t2.wrapping_sub(t1);
    if delta == 0 { FALLBACK_HZ } else { delta }
}

/// Publish a freshly-measured frequency as the authoritative value.
/// Used after the SVM-mode RTC calibration so the rest of veneer
/// (kvmclock pvclock mul/shift, PIT emulator scaling, HPET main-counter
/// scaling, every CPUID 0x40000010 advertise) sees the corrected rate.
pub fn store_host_tsc_freq(hz: u64) {
    HOST_TSC_FREQ.store(hz, Ordering::Relaxed);
}

/// Method 2 — PIT counter-2 polling. Kept for diagnostic comparison.
fn calibrate_via_pit() -> u64 {
    let prev_61 = unsafe { inb(0x61) };
    unsafe { outb(0x61, (prev_61 & !0x02) | 0x01) };

    unsafe { outb(0x43, 0xB0) };
    unsafe { outb(0x42, (CALIBRATE_TICKS & 0xFF) as u8) };
    unsafe { outb(0x42, (CALIBRATE_TICKS >> 8) as u8) };

    let t1 = rdtsc();
    let cap: u64 = 1_000_000_000;
    let mut iters: u64 = 0;
    while unsafe { inb(0x61) } & 0x20 == 0 {
        iters += 1;
        if iters >= cap {
            unsafe { outb(0x61, prev_61) };
            return FALLBACK_HZ;
        }
    }
    let t2 = rdtsc();
    unsafe { outb(0x61, prev_61) };

    let delta_tsc = t2.wrapping_sub(t1);
    (delta_tsc.saturating_mul(PIT_FREQ_HZ)) / (CALIBRATE_TICKS as u64)
}

/// Cached host TSC frequency. Returns `FALLBACK_HZ` if `calibrate()`
/// hasn't run yet — every consumer must be robust to this case (worst
/// case is the bare-metal default which is the right answer on real HW).
pub fn host_tsc_freq() -> u64 {
    let f = HOST_TSC_FREQ.load(Ordering::Relaxed);
    if f == 0 { FALLBACK_HZ } else { f }
}
