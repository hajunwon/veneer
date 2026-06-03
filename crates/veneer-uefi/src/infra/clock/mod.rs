//! Faithful invariant guest clock, disciplined to the host HPET.
//!
//! The guest TSC, the HPET main counter, the ACPI PM timer and the LAPIC
//! timer are all built on `now()`. For an OS to trust the TSC (and pick the
//! LAPIC TSC-deadline timer over a per-tick HPET MMIO read), `now()` must
//! behave like a real invariant TSC: monotonic, constant real rate.
//!
//! Under VMware nested SVM the host TSC is not a reliable wall clock on its
//! own — it steps once mid boot and is throttled during guest busy-spins, so
//! a passthrough crawls and a per-call floor (an earlier design) makes the
//! rate depend on how often veneer is entered, which an OS rejects. But the
//! host HPET *does* keep wall-clock semantics here (measured at 99% of its
//! advertised 14.318 MHz over an RTC second), so it is the real-time anchor.
//!
//!   now() = ANCHOR_REALTIME + (rdtsc() - ANCHOR_TSC)
//!
//! Each host preemption tick (~200 Hz) reads the host HPET and re-anchors
//! ANCHOR_REALTIME to true real time (converted to TSC cycles) and ANCHOR_TSC
//! to the raw TSC. Between ticks the raw TSC interpolates for fine resolution;
//! a throttle merely makes the interpolation lag until the next tick snaps it
//! back to real time — accurately, with no accumulated error, so the clock
//! never runs fast (which would storm an OS's TSC-deadline timers). The
//! one-time TSC step is folded into ANCHOR_TSC so it never reaches `now`.

pub mod host_tick;
pub mod tsc_freq;

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Host HPET MMIO base (fixed by the PC platform). GEN_CAP at +0x00
/// (bits 63:32 = period in fs), GEN_CONFIG at +0x10 (bit 0 = enable),
/// main counter at +0xF0.
const HOST_HPET: usize = 0xFED0_0000;

#[inline]
fn host_hpet_counter() -> u64 {
    unsafe { read_volatile((HOST_HPET + 0xF0) as *const u64) }
}

// ── Real-time anchor (disciplined to the host HPET) ──────────────────
static ENABLED: AtomicBool = AtomicBool::new(false);
static HPET_HZ: AtomicU64 = AtomicU64::new(0);
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
static HPET_BASE: AtomicU64 = AtomicU64::new(0);
static TSC_BASE: AtomicU64 = AtomicU64::new(0);
static ANCHOR_REALTIME: AtomicU64 = AtomicU64::new(0);
static ANCHOR_TSC: AtomicU64 = AtomicU64::new(0);
static LAST_NOW: AtomicU64 = AtomicU64::new(0);

/// Guest TSC = host TSC + this offset (== ANCHOR_REALTIME - ANCHOR_TSC). The
/// dispatcher programs it into VMCB.tsc_offset so the guest's NATIVE RDTSC
/// equals now() WITHOUT a per-exit retune — a per-exit retune jumps the TSC at
/// every HPET-read exit and breaks Windows' boot-time TSC calibration. It only
/// changes when the anchor is re-snapped (a rare throttle correction), so the
/// native TSC stays jump-free and Windows accepts it as an invariant TSC.
pub fn current_offset() -> u64 {
    ANCHOR_REALTIME
        .load(Ordering::Relaxed)
        .wrapping_sub(ANCHOR_TSC.load(Ordering::Relaxed))
}

// ── VMware one-time host-TSC step detection ──────────────────────────
/// A forward raw-RDTSC delta this large is VMware's step, not elapsed time.
const STEP_THRESHOLD: u64 = 1_000_000_000_000;
static LAST_RAW: AtomicU64 = AtomicU64::new(0);
static STEP_SEEN: AtomicBool = AtomicBool::new(false);
static CALL_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_STEP_CALL: AtomicU64 = AtomicU64::new(0);
static STEP_COUNT: AtomicU64 = AtomicU64::new(0);
/// Stable now()-calls after the last step before the guest's RDTSC may go
/// native (so a clustered late step doesn't hit the native window).
const STABLE_CALLS: u64 = 50_000;

/// Number of VMware host-TSC steps observed so far.
pub fn steps_seen() -> u64 {
    STEP_COUNT.load(Ordering::Relaxed)
}

/// True once the VMware host-TSC step cluster has passed and the clock has
/// been stable since — the dispatcher then lets the guest read RDTSC
/// natively. A fresh step flips it back (handled in the dispatcher).
pub fn step_absorbed() -> bool {
    STEP_SEEN.load(Ordering::Relaxed)
        && CALL_COUNT.load(Ordering::Relaxed).wrapping_sub(LAST_STEP_CALL.load(Ordering::Relaxed))
            > STABLE_CALLS
}

#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)); }
    ((hi as u64) << 32) | (lo as u64)
}

/// Anchor the clock to the host HPET. `tsc_hz` is the RTC-calibrated host
/// TSC frequency. Reads the HPET advertised period for its own frequency,
/// enables its counter, and snapshots both counters as the origin so `now`
/// starts continuous with the raw TSC. Called once before the VMRUN loop.
pub fn init_hpet_clock(tsc_hz: u64) {
    let cap = unsafe { read_volatile(HOST_HPET as *const u64) };
    let period_fs = (cap >> 32) & 0xFFFF_FFFF;
    if cap == 0 || cap == u64::MAX || period_fs == 0 || period_fs > 100_000_000 {
        crate::sprintln!("[clock] no host HPET (cap=0x{:016X}); falling back to raw TSC", cap);
        return;
    }
    let hpet_hz = 1_000_000_000_000_000u64 / period_fs;
    // Enable the main counter (GEN_CONFIG bit 0).
    let cfg = unsafe { read_volatile((HOST_HPET + 0x10) as *const u64) };
    unsafe { write_volatile((HOST_HPET + 0x10) as *mut u64, cfg | 1) };

    let raw = rdtsc();
    HPET_HZ.store(hpet_hz, Ordering::Relaxed);
    TSC_HZ.store(tsc_hz.max(1), Ordering::Relaxed);
    HPET_BASE.store(host_hpet_counter(), Ordering::Relaxed);
    TSC_BASE.store(raw, Ordering::Relaxed);
    ANCHOR_REALTIME.store(raw, Ordering::Relaxed);
    ANCHOR_TSC.store(raw, Ordering::Relaxed);
    LAST_NOW.store(raw, Ordering::Relaxed);
    LAST_RAW.store(raw, Ordering::Relaxed);
    ENABLED.store(true, Ordering::Relaxed);
    crate::sprintln!("[clock] HPET-disciplined: hpet={} Hz tsc={} Hz base_tsc=0x{:X}", hpet_hz, tsc_hz, raw);
}

/// True elapsed real time since the anchor origin, in host-TSC cycle units,
/// from the throttle-immune host HPET.
#[inline]
fn realtime_from_hpet() -> u64 {
    let hpet_delta = host_hpet_counter().wrapping_sub(HPET_BASE.load(Ordering::Relaxed));
    let tsc_hz = TSC_HZ.load(Ordering::Relaxed) as u128;
    let hpet_hz = HPET_HZ.load(Ordering::Relaxed).max(1) as u128;
    let cycles = (hpet_delta as u128 * tsc_hz / hpet_hz) as u64;
    TSC_BASE.load(Ordering::Relaxed).wrapping_add(cycles)
}

/// Re-anchor `now()` to the host HPET's real time. Called by the dispatcher
/// on every #VMEXIT(INTR) (the ~200 Hz host preemption tick). Reading the
/// host HPET is a VMware exit, so it is done here at tick rate, not per
/// `now()` call. Snapping to the exact real time each tick corrects any
/// throttle accumulated since the last one — without ever overshooting, so
/// the clock can't run fast.
pub fn discipline() {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let raw_now = rdtsc();
    let cur = ANCHOR_REALTIME
        .load(Ordering::Relaxed)
        .wrapping_add(raw_now.wrapping_sub(ANCHOR_TSC.load(Ordering::Relaxed)));
    let target = realtime_from_hpet();
    // Leave the anchor alone on normal ticks so now() (and the guest's native
    // TSC, which shares this offset) keeps advancing at the CONSTANT host-TSC
    // rate, jump-free — the shape Windows' TSC suitability check requires. Only
    // re-snap when the host TSC has throttled far (~10 ms) behind real time (a
    // busy-spin stall); leaving it would crawl timed waits. Forward-only.
    let snap_threshold = (TSC_HZ.load(Ordering::Relaxed) / 100).max(1) as i64;
    if target.wrapping_sub(cur) as i64 > snap_threshold {
        ANCHOR_REALTIME.store(target, Ordering::Relaxed);
        ANCHOR_TSC.store(raw_now, Ordering::Relaxed);
    }
}

/// Monotonic, constant-real-rate virtual TSC in host-TSC cycle units.
pub fn now() -> u64 {
    let raw = rdtsc();
    let cc = CALL_COUNT.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    // VMware's one-time host-TSC step: fold it into ANCHOR_TSC so the
    // interpolation below stays continuous, and flag it for the RDTSC
    // native/intercept oracle.
    let last = LAST_RAW.swap(raw, Ordering::Relaxed);
    if last != 0 && raw > last && raw - last > STEP_THRESHOLD {
        ANCHOR_TSC.fetch_add(raw - last, Ordering::Relaxed);
        LAST_STEP_CALL.store(cc, Ordering::Relaxed);
        STEP_SEEN.store(true, Ordering::Relaxed);
        let n = STEP_COUNT.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        crate::sprintln!("[clock] TSC step #{}: call={} raw_delta=0x{:X}", n, cc, raw - last);
    }
    if !ENABLED.load(Ordering::Relaxed) {
        return raw; // pre-anchor: raw TSC (the anchor starts here)
    }
    // Constant host-TSC rate since the last anchor (jump-free between snaps).
    let interp = raw.wrapping_sub(ANCHOR_TSC.load(Ordering::Relaxed));
    let v = ANCHOR_REALTIME.load(Ordering::Relaxed).wrapping_add(interp);
    // Monotonic backstop: a re-anchor that lands just below the interpolated
    // value (or a step race) must never move `now` backward.
    let last_now = LAST_NOW.load(Ordering::Relaxed);
    let v = if v.wrapping_sub(last_now) as i64 > 0 { v } else { last_now };
    LAST_NOW.store(v, Ordering::Relaxed);
    v
}
