//! HPET (High Precision Event Timer) MMIO emulator.
//!
//! Standard HPET base is 0xFED00000 and the MMIO window is one 4 KiB
//! page (only the first 0x200 bytes have defined registers; reads to
//! the rest return 0). Layout per Intel HPET spec §2.3:
//!
//!   0x000  General Capabilities + ID (u64, RO)
//!   0x010  General Configuration   (u64, RW)
//!   0x020  General Interrupt Status (u64, RW)
//!   0x0F0  Main Counter Value      (u64, RW when ENABLE_CNF=0)
//!   0x100  Timer 0 Config + Cap    (u64)
//!   0x108  Timer 0 Comparator      (u64)
//!   0x110  Timer 0 FSB Route       (u64)
//!   0x120  Timer 1 …
//!   0x140  Timer 2 …
//!
//! We model the General Caps/Config + a free-running 64-bit Main
//! Counter sourced from the virtual clock, plus timer-0 one-shot firing:
//! a comparator match raises an interrupt that `inject.rs` delivers
//! through the IO-APIC GSI the guest programmed (see `timer0_pending` /
//! `timer0_gsi`). Each per-timer Config+Cap register also advertises the
//! read-only capability bits a real HPET exposes (`Tn_INT_ROUTE_CAP`,
//! `Tn_SIZE_CAP`, `Tn_PER_INT_CAP`) so an OS can discover that the
//! comparator is interrupt-capable — without them Windows' HAL treats
//! HPET as a counter-only QPC source and finds no system clock timer.

use core::sync::atomic::{AtomicU64, Ordering};

pub const HPET_BASE: u64 = 0xFED0_0000;
pub const HPET_SIZE: u64 = 0x0000_1000;

/// COUNTER_CLK_PERIOD in femtoseconds. 69841279 fs == 14.31818 MHz —
/// the de-facto x86 PC clock divisor used by every chipset since
/// PIIX4 + ICH. Reporting this value means existing kernel HPET
/// calibration code "just works".
const PERIOD_FS: u64 = 69_841_279;
/// HPET nominal tick rate. Must satisfy `PERIOD_FS * HPET_FREQ_HZ
/// ≈ 1e15` (1 femtosecond × 1 Hz × 1e15 = 1s). 14.31818 MHz precisely.
const HPET_FREQ_HZ: u64 = 14_318_180;

/// Anchor host TSC when the HPET counter was last reset (only on
/// guest-write to 0x0F0 while ENABLE_CNF=0). Initial 0 means
/// "synthesise from current host TSC offset".
static HPET_BASE_TSC: AtomicU64 = AtomicU64::new(0);
/// Counter value at the most recent reset — guest writes land here.
static HPET_BASE_COUNTER: AtomicU64 = AtomicU64::new(0);
const VENDOR_ID: u16 = 0x8086; // Intel-style. Matches real chipsets.
const NUM_TIMERS: u8 = 3;       // 3 comparators
const REV_ID: u8 = 0x01;

const N_TIMERS: usize = 3;

/// General Configuration register. Bit 0 = ENABLE_CNF (counter
/// running), bit 1 = LEG_RT_CNF (legacy IRQ routing).
static GENERAL_CONFIG: AtomicU64 = AtomicU64::new(0);
/// General Interrupt Status — sticky bits for fired comparators.
static GENERAL_INT_STATUS: AtomicU64 = AtomicU64::new(0);

#[allow(clippy::declare_interior_mutable_const)]
const TIMER_INIT: AtomicU64 = AtomicU64::new(0);
static TIMER_CONFIG: [AtomicU64; N_TIMERS]    = [TIMER_INIT; N_TIMERS];
static TIMER_COMPARE: [AtomicU64; N_TIMERS]   = [TIMER_INIT; N_TIMERS];
static TIMER_FSB: [AtomicU64; N_TIMERS]       = [TIMER_INIT; N_TIMERS];

/// Timer 0's live one-shot deadline — the main-counter value it fires at,
/// or u64::MAX when disarmed. Armed by a guest comparator write (see the
/// write handler), cleared by `timer0_serviced`. The power-on comparator
/// (0) is never written, so it never arms — only an explicit guest write
/// does, which is what distinguishes a real deadline from the stale default.
static T0_DEADLINE: AtomicU64 = AtomicU64::new(u64::MAX);

#[inline]
pub fn covers(gpa: u64) -> bool {
    gpa >= HPET_BASE && gpa < HPET_BASE + HPET_SIZE
}

/// Read host TSC. Cheap inline — we don't go through the intercept
/// handler because we're already in host context. Retained for the
/// counter-reset diagnostics; the live counter is sourced from the
/// floored virtual clock (see `main_counter`).
#[inline]
#[allow(dead_code)]
fn host_rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)); }
    ((hi as u64) << 32) | (lo as u64)
}

fn general_caps() -> u64 {
    // LEG_RT_CAP deliberately cleared: with it set, Linux drives the boot
    // clockevent through HPET legacy-replacement in PERIODIC mode and expects
    // the comparator to auto-increment, which our one-shot timer model can't
    // sustain — check_timer then panics ("IO-APIC + timer doesn't work").
    // Without it Linux uses the genuinely-periodic 8254 PIT on IRQ0→GSI2,
    // which inject.rs already delivers through the IO-APIC.
    (PERIOD_FS << 32)
        | ((VENDOR_ID as u64) << 16)
        | (1 << 13)                                // COUNT_SIZE_CAP (64-bit)
        | (((NUM_TIMERS as u64 - 1) & 0x1F) << 8)
        | (REV_ID as u64)
}

#[inline]
fn low_mask(width: u8) -> u64 {
    match width {
        1 => 0xFFu64,
        2 => 0xFFFFu64,
        4 => 0xFFFF_FFFFu64,
        _ => u64::MAX,
    }
}

/// Live main counter value, scaled from the virtual clock to nominal
/// 14.318 MHz. Without this scaling Linux's HPET clocksource registers
/// the host TSC rate (≈4.7 GHz on bare metal, ≈5.9 MHz under VMware
/// nested SVM) as if it were 14.318 MHz — every time-of-day API ends up
/// off by several orders of magnitude.
///
/// The elapsed-cycle source is `crate::infra::clock::now()`, the same filtered,
/// spin-floored virtual-TSC domain RDTSC / ACPI PM-timer / LAPIC timer
/// read from. Using raw host RDTSC here would make the HPET stall during
/// the firmware delay-spins VMware throttles the host TSC through (a
/// timeout measured on HPET would never expire) and would diverge from
/// the other time sources at the one-time nested-SVM TSC step.
fn main_counter() -> u64 {
    let base_tsc = HPET_BASE_TSC.load(Ordering::Relaxed);
    let base_counter = HPET_BASE_COUNTER.load(Ordering::Relaxed);
    let now = crate::infra::clock::now();
    let elapsed_tsc = now.wrapping_sub(base_tsc);
    let host_freq = crate::infra::clock::tsc_freq::host_tsc_freq();
    // elapsed_hpet_ticks = elapsed_tsc × HPET_FREQ_HZ / host_freq.
    // Split to avoid overflow: host_freq is ≤ 5 GHz so the quotient
    // fits, and the remainder stays well inside u64 when multiplied.
    let elapsed_hpet = (elapsed_tsc / host_freq) * HPET_FREQ_HZ
        + ((elapsed_tsc % host_freq) * HPET_FREQ_HZ) / host_freq;
    base_counter.wrapping_add(elapsed_hpet)
}

// ───── Timer 0 interrupt source ──────────────────────────────────────
//
// After Linux disables the LAPIC timer ("APIC frequency too slow") it
// falls back to HPET as its clockevent. We model timer 0 firing when the
// main counter reaches the comparator. One-shot semantics: a fresh
// comparator write re-arms; servicing disarms until the next write (which
// is exactly how the tickless/NOHZ clockevent drives it). Periodic mode
// is logged so we can tell if a guest needs the auto-increment path.

const CFG_ENABLE_CNF: u64 = 1 << 0;
const CFG_LEG_RT_CNF: u64 = 1 << 1;
const TN_INT_ENB: u64 = 1 << 2;
const TN_TYPE_PERIODIC: u64 = 1 << 3;

// Read-only per-timer capability bits in the Tn Config+Cap register
// (Intel HPET spec §2.3.8). A real HPET always advertises these; veneer
// previously returned 0, so Windows' HAL saw a comparator that could not
// route an interrupt to any GSI (Tn_INT_ROUTE_CAP == 0) and registered
// HPET as a counter-only QPC source — never a clock (interrupt) source.
// With no interrupt-capable platform timer, HalpTimerFindIdealClockSource
// returns NULL → bugcheck 0x5C HAL_TIMER_INITIALIZATION_FAILURE.
const TN_PER_INT_CAP: u64 = 1 << 4;   // periodic-capable
const TN_SIZE_CAP: u64 = 1 << 5;      // 64-bit comparator
// Tn_INT_ROUTE_CAP (bits 32..63): bitmap of IO-APIC GSIs the comparator
// can be routed to (bit 32+g => GSI g). veneer's IO-APIC has GSIs 0..23;
// 0..15 are ISA lines and 16..19 are PCI INTx, so advertise the free high
// lines 20..23. The guest picks one, writes it into Tn_INT_ROUTE_CNF
// (bits 9..13), and inject.rs delivers the match through that GSI.
const TN_INT_ROUTE_CAP: u64 = 0xFu64 << 52; // GSIs 20..23
const TN_CAP_BITS: u64 = TN_PER_INT_CAP | TN_SIZE_CAP | TN_INT_ROUTE_CAP;

#[inline]
fn t0_enabled() -> bool {
    GENERAL_CONFIG.load(Ordering::Relaxed) & CFG_ENABLE_CNF != 0
        && TIMER_CONFIG[0].load(Ordering::Relaxed) & TN_INT_ENB != 0
}

static PERIODIC_LOGGED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
fn log_periodic_once() {
    if !PERIODIC_LOGGED.swap(true, Ordering::Relaxed) {
        crate::sprintln!("[hpet] timer0 programmed PERIODIC — one-shot model may miss ticks");
    }
}

/// True when timer 0 is set up to raise interrupts (counter will reach
/// the comparator on its own).
pub fn timer0_armed() -> bool {
    t0_enabled() && T0_DEADLINE.load(Ordering::Relaxed) != u64::MAX
}

/// Non-consuming: has timer 0's comparator match passed?
pub fn timer0_pending() -> bool {
    if !t0_enabled() {
        return false;
    }
    let deadline = T0_DEADLINE.load(Ordering::Relaxed);
    deadline != u64::MAX && main_counter() >= deadline
}

/// Consume timer 0's interrupt. Sets the sticky status bit and disarms;
/// the next comparator write re-arms (one-shot / NOHZ). Periodic guests
/// that don't rewrite the comparator would stall here — caught by the
/// periodic log above.
pub fn timer0_serviced() {
    GENERAL_INT_STATUS.fetch_or(1, Ordering::Relaxed);
    T0_DEADLINE.store(u64::MAX, Ordering::Relaxed);
}

/// How timer 0's interrupt is routed: `Some(gsi)` for an IO-APIC GSI, or
/// the legacy IRQ0 path when LEG_RT_CNF is set. Returns the GSI to look
/// up in the IO-APIC redirection table; legacy maps to GSI2 (the ISA
/// IRQ0 → GSI2 override), matching real HPET legacy-replacement wiring.
pub fn timer0_gsi() -> u32 {
    if GENERAL_CONFIG.load(Ordering::Relaxed) & CFG_LEG_RT_CNF != 0 {
        2 // legacy replacement: timer0 → IRQ0 → GSI2
    } else {
        ((TIMER_CONFIG[0].load(Ordering::Relaxed) >> 9) & 0x1F) as u32
    }
}

/// Diagnostic dump of timer-0 relevant registers.
pub fn debug_dump() {
    crate::sprintln!(
        "[hpet] GEN_CFG=0x{:X} T0_CFG=0x{:X} T0_CMP=0x{:X} main_ctr=0x{:X} enabled={} gsi={}",
        GENERAL_CONFIG.load(Ordering::Relaxed),
        TIMER_CONFIG[0].load(Ordering::Relaxed),
        TIMER_COMPARE[0].load(Ordering::Relaxed),
        main_counter(),
        t0_enabled(),
        timer0_gsi(),
    );
}

fn read_qword(offset: u32) -> u64 {
    match offset {
        0x000 => general_caps(),
        0x010 => GENERAL_CONFIG.load(Ordering::Relaxed),
        0x020 => GENERAL_INT_STATUS.load(Ordering::Relaxed),
        0x0F0 => main_counter(),
        // Timer N: each timer block is 0x20 bytes
        // 0x100..0x107 timer 0 config, 0x108..0x10F comparator, 0x110..0x117 FSB
        // 0x120..  timer 1, 0x140.. timer 2
        o if (0x100..0x100 + (N_TIMERS as u32) * 0x20).contains(&o) => {
            let timer = ((o - 0x100) / 0x20) as usize;
            let sub = (o - 0x100) % 0x20;
            match sub {
                // OR in the read-only capability bits the guest can't write.
                0x00 => TIMER_CONFIG[timer].load(Ordering::Relaxed) | TN_CAP_BITS,
                0x08 => TIMER_COMPARE[timer].load(Ordering::Relaxed),
                0x10 => TIMER_FSB[timer].load(Ordering::Relaxed),
                _ => 0,
            }
        }
        _ => 0,
    }
}

// First-N trace counters (rate-limited, BSS-init 0). Used to confirm
// emulator paths actually fire during nested-guest boot without spamming
// serial. After TRACE_CAP hits the path goes silent.
static HPET_READ_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static HPET_WRITE_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
const HPET_TRACE_CAP: u64 = 0;

pub fn read_register_width(offset: u32, width: u8) -> u64 {
    let aligned = offset & !0x7;
    let shift_bits = (offset & 0x7) * 8;
    let qword = read_qword(aligned);
    let val = (qword >> shift_bits) & low_mask(width);
    let n = HPET_READ_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if n < HPET_TRACE_CAP {
        crate::sprintln!("[hpet] R[0x{:03X}].{}B = 0x{:X} (#{}/{})", offset, width, val, n + 1, HPET_TRACE_CAP);
    }
    val
}

pub fn write_register_width(offset: u32, val: u64, width: u8) {
    let n = HPET_WRITE_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if n < HPET_TRACE_CAP {
        crate::sprintln!("[hpet] W[0x{:03X}].{}B = 0x{:X} (#{}/{})", offset, width, val, n + 1, HPET_TRACE_CAP);
    }
    let aligned = offset & !0x7;
    let shift_bits = (offset & 0x7) * 8;
    let mask = low_mask(width) << shift_bits;
    let shifted = (val & low_mask(width)) << shift_bits;
    match aligned {
        0x000 => {} // General Caps is RO
        0x010 => {
            let prev = GENERAL_CONFIG.load(Ordering::Relaxed);
            GENERAL_CONFIG.store((prev & !mask) | shifted, Ordering::Relaxed);
        }
        0x020 => {
            // Write-1-to-clear semantics: bits set in the write clear
            // the matching sticky status bits.
            let cur = GENERAL_INT_STATUS.load(Ordering::Relaxed);
            GENERAL_INT_STATUS.store(cur & !shifted, Ordering::Relaxed);
        }
        0x0F0 => {
            // Main counter write — spec says this is only valid while
            // ENABLE_CNF=0 ("counter halt") but Linux sometimes touches
            // it anyway to reset the clocksource at suspend/resume.
            // Re-anchor base so subsequent reads count up from the
            // newly-written value.
            HPET_BASE_COUNTER.store((HPET_BASE_COUNTER.load(Ordering::Relaxed) & !mask) | shifted, Ordering::Relaxed);
            // Anchor in the virtual-clock domain (see main_counter) so the
            // re-anchored counter advances on the same floored clock the
            // rest of the timers use.
            HPET_BASE_TSC.store(crate::infra::clock::now(), Ordering::Relaxed);
        }
        a if (0x100..0x100 + (N_TIMERS as u32) * 0x20).contains(&a) => {
            let timer = ((a - 0x100) / 0x20) as usize;
            let sub = (a - 0x100) % 0x20;
            let slot = match sub {
                0x00 => &TIMER_CONFIG[timer],
                0x08 => &TIMER_COMPARE[timer],
                0x10 => &TIMER_FSB[timer],
                _ => return,
            };
            let prev = slot.load(Ordering::Relaxed);
            let mut next = (prev & !mask) | shifted;
            // Tn_INT_ROUTE_CAP / Tn_PER_INT_CAP / Tn_SIZE_CAP are read-only:
            // never let a guest write stick into them so reads keep returning
            // the advertised caps. (Only the config sub-register carries them.)
            if sub == 0x00 {
                next &= !TN_CAP_BITS;
            }
            slot.store(next, Ordering::Relaxed);
            // Arm timer 0's one-shot deadline at the written comparator. It
            // fires when the main counter reaches it; a value already at or
            // behind the counter fires on the next check — late but correct.
            // The IRQL-gated V_IRQ delivery holds the IRQ if the guest is in a
            // HIGH_LEVEL critical section, so firing-when-past no longer risks
            // the HalpHpetSetMatchValue re-entrancy the old future-only arming
            // guarded against. Only an explicit write arms, so the power-on 0
            // comparator stays disarmed.
            if timer == 0 && sub == 0x08 {
                T0_DEADLINE.store(next, Ordering::Relaxed);
                if TIMER_CONFIG[0].load(Ordering::Relaxed) & TN_TYPE_PERIODIC != 0 {
                    log_periodic_once();
                }
            }
        }
        _ => {}
    }
}
