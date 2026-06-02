//! 8254 Programmable Interval Timer (PIT) emulator.
//!
//! Standard hypervisor pattern (KVM/QEMU/Cloud HV/Firecracker all ship
//! one): Linux's TSC fast / refined calibration paths use the PIT as a
//! reference clock. Without a PIT, Linux can't calibrate TSC, can't
//! initialise the local APIC timer, and the boot stalls before
//! schedule_init.
//!
//! Mapping:
//!   IO 0x40   — counter 0 data (timer interrupt source on real HW)
//!   IO 0x41   — counter 1 data (legacy DRAM refresh; unused by Linux)
//!   IO 0x42   — counter 2 data (PC speaker — Linux probes this during
//!               pit_hpet_ptimer_calibrate_cpu)
//!   IO 0x43   — control / mode register (write-only)
//!   IO 0x61   — NMI status & speaker control. Bit 5 mirrors counter 2
//!               OUT line — Linux's fast calibration polls it to wait
//!               for the gate transition.
//!
//! Counter model:
//!   PIT runs at exactly 1.193182 MHz on real hardware. We synthesise
//!   the same rate by reading the host TSC and computing how many PIT
//!   ticks have elapsed since the counter was last (re)loaded:
//!
//!     elapsed_pit = (rdtsc() - start_tsc) * PIT_FREQ_HZ / crate::clock::tsc_freq::host_tsc_freq()
//!     counter_now = (initial - elapsed_pit) mod modulus
//!
//!   crate::clock::tsc_freq::host_tsc_freq() is approximate (Ryzen 7000-series base ~4.7 GHz).
//!   Even if the constant is off by ±10%, Linux's TSC calibration is
//!   *relative* — it computes (delta_tsc) / (delta_pit) and the same
//!   bias on both sides cancels. The guest's TSC will simply read at the
//!   bias factor of real time; for boot completion this is fine.
//!
//! Mode handling: only Mode 0 (single-shot countdown) and Mode 2/3
//! (rate generator / square wave — same observable behaviour for our
//! purposes) are emulated. Other modes fall back to Mode 2 semantics.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

/// 8254 nominal frequency. Hardcoded — every PC platform since 1981.
const PIT_FREQ_HZ: u64 = 1_193_182;

// Host TSC frequency is measured at boot by tsc_freq::calibrate() (via
// the real PIT before SVM is armed) and queried per-call below. Hardcoded
// constants here are fragile because VMware nested SVM virtualises RDTSC
// at ~5.894 MHz instead of the bare-metal 4.7 GHz; a 800× error breaks
// every downstream guest timer.

const N_COUNTERS: usize = 3;

/// 16-bit initial value programmed via 0x43 + counter data port. A 0
/// value means "65536" per real PIT semantics.
static COUNTER_INITIAL: [AtomicU64; N_COUNTERS] =
    [AtomicU64::new(0xFFFF), AtomicU64::new(0xFFFF), AtomicU64::new(0xFFFF)];

/// Host TSC value at the moment the counter was last (re)loaded.
static COUNTER_START_TSC: [AtomicU64; N_COUNTERS] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// Latched value from a 0x43 latch command. 0 means "no latch active —
/// reads return the live count".
static COUNTER_LATCH: [AtomicU64; N_COUNTERS] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
static COUNTER_LATCHED: [AtomicU8; N_COUNTERS] =
    [AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0)];

/// RW mode from the most recent 0x43 write. 1 = LSB only, 2 = MSB only,
/// 3 = LSB then MSB.
static COUNTER_RW_MODE: [AtomicU8; N_COUNTERS] =
    [AtomicU8::new(3), AtomicU8::new(3), AtomicU8::new(3)];

/// Operating mode (0..5) from the most recent 0x43 write.
static COUNTER_MODE: [AtomicU8; N_COUNTERS] =
    [AtomicU8::new(2), AtomicU8::new(2), AtomicU8::new(2)];

/// Toggle for two-byte (RW mode 3) reads / writes.
static COUNTER_READ_LSB_NEXT: [AtomicU8; N_COUNTERS] =
    [AtomicU8::new(1), AtomicU8::new(1), AtomicU8::new(1)];
static COUNTER_WRITE_LSB_NEXT: [AtomicU8; N_COUNTERS] =
    [AtomicU8::new(1), AtomicU8::new(1), AtomicU8::new(1)];

/// Counter 2 gate (port 0x61 bit 0). 0 = gate disabled (counter pauses).
static COUNTER2_GATE: AtomicU8 = AtomicU8::new(0);

/// Host TSC deadline for the next counter-0 IRQ0 (0 = not armed).
static IRQ0_NEXT_TSC: AtomicU64 = AtomicU64::new(0);
/// COUNTER_START_TSC[0] value the current IRQ0 deadline was armed
/// against. A mismatch means the guest reprogrammed counter 0 (new
/// reload) and we re-sync the deadline.
static IRQ0_ARMED_START: AtomicU64 = AtomicU64::new(0);

// Trace counters — kept at 0 in production. Trace adds ~4ms / IO via
// serial sprintln which breaks Linux's PIT-based TSC calibration
// (tscmax > 10×tscmin SMI threshold). Bump to a small number only when
// diagnosing emulator behaviour.
static PIT_IN_COUNT: AtomicU64 = AtomicU64::new(0);
static PIT_OUT_COUNT: AtomicU64 = AtomicU64::new(0);
const PIT_TRACE_CAP: u64 = 32;

#[inline]
fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Compute the live counter value (post-elapsed-time) for `idx`. Honours
/// the counter's modulus (initial value or 65536 for "0" programmed) and
/// the operating mode (Mode 0 = one-shot stops at 0; Mode 2/3 = wrap).
fn live_counter(idx: usize) -> u16 {
    let initial_raw = COUNTER_INITIAL[idx].load(Ordering::Relaxed);
    let modulus: u64 = if initial_raw == 0 { 0x10000 } else { initial_raw };
    // Counter 2 only ticks while gate is high — frozen otherwise.
    if idx == 2 && COUNTER2_GATE.load(Ordering::Relaxed) == 0 {
        return initial_raw as u16;
    }
    let start_tsc = COUNTER_START_TSC[idx].load(Ordering::Relaxed);
    let now = rdtsc();
    let elapsed_tsc = now.wrapping_sub(start_tsc);
    // Multiply then divide is safe because PIT_FREQ_HZ < crate::clock::tsc_freq::host_tsc_freq().
    let elapsed_pit = (elapsed_tsc / crate::clock::tsc_freq::host_tsc_freq()) * PIT_FREQ_HZ
        + ((elapsed_tsc % crate::clock::tsc_freq::host_tsc_freq()) * PIT_FREQ_HZ) / crate::clock::tsc_freq::host_tsc_freq();
    let mode = COUNTER_MODE[idx].load(Ordering::Relaxed);
    if mode == 0 {
        // Mode 0 (interrupt on terminal count) — single-shot countdown.
        // Counter stops at 0 once reached; OUT goes high (handled by
        // counter2_out()). Linux fast-TSC-calibration polls 0x61 bit 5
        // waiting for this.
        if elapsed_pit >= modulus {
            return 0;
        }
        return (modulus - elapsed_pit) as u16;
    }
    // Mode 2 / 3 (rate generator / square wave) — wrap on terminal count.
    let pos = elapsed_pit % modulus;
    modulus.wrapping_sub(pos) as u16
}

/// Counter 2 OUT line state (bit 5 of port 0x61). Real PIT raises OUT
/// to 1 when the counter reaches 0 in Mode 0; in Mode 2/3 it toggles.
/// For Linux's calibration purposes, OUT=1 once the counter has wrapped
/// at least once is sufficient.
fn counter2_out() -> bool {
    if COUNTER2_GATE.load(Ordering::Relaxed) == 0 {
        return false;
    }
    let initial_raw = COUNTER_INITIAL[2].load(Ordering::Relaxed);
    let modulus: u64 = if initial_raw == 0 { 0x10000 } else { initial_raw };
    let start_tsc = COUNTER_START_TSC[2].load(Ordering::Relaxed);
    let now = rdtsc();
    let elapsed_tsc = now.wrapping_sub(start_tsc);
    let elapsed_pit = (elapsed_tsc / crate::clock::tsc_freq::host_tsc_freq()) * PIT_FREQ_HZ
        + ((elapsed_tsc % crate::clock::tsc_freq::host_tsc_freq()) * PIT_FREQ_HZ) / crate::clock::tsc_freq::host_tsc_freq();
    elapsed_pit >= modulus
}

/// Returns true if `port` is one of the PIT IO ports we own.
/// Counter-0 timer period in host TSC cycles for the current divisor.
/// 0 when the divisor is unprogrammed or the host TSC freq is unknown.
fn irq0_period_tsc() -> u64 {
    let initial_raw = COUNTER_INITIAL[0].load(Ordering::Relaxed);
    let modulus: u64 = if initial_raw == 0 { 0x10000 } else { initial_raw };
    modulus.saturating_mul(crate::clock::tsc_freq::host_tsc_freq()) / PIT_FREQ_HZ
}

/// Re-sync the IRQ0 deadline against the latest counter-0 reload. The
/// guest writing a new divisor updates COUNTER_START_TSC[0]; when that
/// differs from the value we armed against, the first interrupt fires one
/// period after the reload instant. Returns the live deadline (0 = not
/// armed / one-shot already consumed).
fn irq0_sync() -> u64 {
    let start = COUNTER_START_TSC[0].load(Ordering::Relaxed);
    if start == 0 {
        return 0;
    }
    if IRQ0_ARMED_START.load(Ordering::Relaxed) != start {
        IRQ0_ARMED_START.store(start, Ordering::Relaxed);
        IRQ0_NEXT_TSC.store(start.wrapping_add(irq0_period_tsc()), Ordering::Relaxed);
    }
    IRQ0_NEXT_TSC.load(Ordering::Relaxed)
}

/// True when counter 0 is programmed as an interrupt source (mode 2/3
/// periodic tick or mode 0 one-shot with a live deadline).
pub fn irq0_armed() -> bool {
    irq0_sync() != 0
}

/// Non-consuming: is a counter-0 timer interrupt due now? The injection
/// layer and the HLT idle path both poll this.
pub fn irq0_pending() -> bool {
    let next = irq0_sync();
    next != 0 && rdtsc() >= next
}

/// Consume one IRQ0. Mode 2/3 (rate generator / square wave) advances to
/// the next periodic deadline; mode 0 (interrupt-on-terminal-count)
/// disarms until the guest's clockevent reprograms the counter.
pub fn irq0_serviced() {
    let mode = COUNTER_MODE[0].load(Ordering::Relaxed);
    if mode == 2 || mode == 3 {
        let period = irq0_period_tsc();
        let now = rdtsc();
        let mut next = IRQ0_NEXT_TSC.load(Ordering::Relaxed).wrapping_add(period);
        if next <= now {
            next = now.wrapping_add(period);
        }
        IRQ0_NEXT_TSC.store(next, Ordering::Relaxed);
    } else {
        // One-shot: mark this reload consumed (keep ARMED_START matching
        // COUNTER_START_TSC so irq0_sync won't immediately re-arm) and
        // clear the deadline. A fresh reload bumps COUNTER_START_TSC and
        // re-arms via the mismatch path.
        IRQ0_NEXT_TSC.store(0, Ordering::Relaxed);
        IRQ0_ARMED_START.store(COUNTER_START_TSC[0].load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

/// Diagnostic dump of counter-0 timer state.
pub fn debug_dump() {
    crate::sprintln!(
        "[pit ] c0 mode={} initial=0x{:X} start_tsc=0x{:X} next=0x{:X} armed_start=0x{:X}",
        COUNTER_MODE[0].load(Ordering::Relaxed),
        COUNTER_INITIAL[0].load(Ordering::Relaxed),
        COUNTER_START_TSC[0].load(Ordering::Relaxed),
        IRQ0_NEXT_TSC.load(Ordering::Relaxed),
        IRQ0_ARMED_START.load(Ordering::Relaxed),
    );
}

#[inline]
pub fn covers(port: u16) -> bool {
    matches!(port, 0x40..=0x43 | 0x61)
}

/// IN — return 8 bits for the given port.
pub fn handle_in(port: u16) -> u8 {
    let val = match port {
        0x40 | 0x41 | 0x42 => {
            let idx = (port - 0x40) as usize;
            let count = if COUNTER_LATCHED[idx].load(Ordering::Relaxed) != 0 {
                COUNTER_LATCH[idx].load(Ordering::Relaxed) as u16
            } else {
                live_counter(idx)
            };
            let rw = COUNTER_RW_MODE[idx].load(Ordering::Relaxed);
            match rw {
                1 => count as u8, // LSB only
                2 => (count >> 8) as u8, // MSB only
                3 => {
                    let lsb_next = COUNTER_READ_LSB_NEXT[idx].load(Ordering::Relaxed);
                    if lsb_next != 0 {
                        COUNTER_READ_LSB_NEXT[idx].store(0, Ordering::Relaxed);
                        count as u8
                    } else {
                        COUNTER_READ_LSB_NEXT[idx].store(1, Ordering::Relaxed);
                        // Latch cleared after MSB read in latched mode.
                        if COUNTER_LATCHED[idx].load(Ordering::Relaxed) != 0 {
                            COUNTER_LATCHED[idx].store(0, Ordering::Relaxed);
                        }
                        (count >> 8) as u8
                    }
                }
                _ => 0,
            }
        }
        0x43 => 0, // Mode register is write-only
        0x61 => {
            // Bit 0 = counter 2 gate, bit 5 = counter 2 OUT.
            let gate = COUNTER2_GATE.load(Ordering::Relaxed);
            let out = if counter2_out() { 1u8 } else { 0 };
            (out << 5) | gate
        }
        _ => 0xFF,
    };
    let n = PIT_IN_COUNT.fetch_add(1, Ordering::Relaxed);
    if n < PIT_TRACE_CAP {
        crate::sprintln!("[pit] IN  0x{:02X} = 0x{:02X} (#{}/{})", port, val, n + 1, PIT_TRACE_CAP);
    }
    val
}

/// OUT — accept 8 bits for the given port.
pub fn handle_out(port: u16, val: u8) {
    let n = PIT_OUT_COUNT.fetch_add(1, Ordering::Relaxed);
    if n < PIT_TRACE_CAP {
        crate::sprintln!("[pit] OUT 0x{:02X} <- 0x{:02X} (#{}/{})", port, val, n + 1, PIT_TRACE_CAP);
    }
    match port {
        0x40 | 0x41 | 0x42 => {
            let idx = (port - 0x40) as usize;
            let rw = COUNTER_RW_MODE[idx].load(Ordering::Relaxed);
            let mut cur = COUNTER_INITIAL[idx].load(Ordering::Relaxed);
            let mut done = false;
            match rw {
                1 => {
                    cur = (cur & 0xFF00) | val as u64;
                    done = true;
                }
                2 => {
                    cur = (cur & 0x00FF) | ((val as u64) << 8);
                    done = true;
                }
                3 => {
                    let lsb_next = COUNTER_WRITE_LSB_NEXT[idx].load(Ordering::Relaxed);
                    if lsb_next != 0 {
                        cur = (cur & 0xFF00) | val as u64;
                        COUNTER_WRITE_LSB_NEXT[idx].store(0, Ordering::Relaxed);
                    } else {
                        cur = (cur & 0x00FF) | ((val as u64) << 8);
                        COUNTER_WRITE_LSB_NEXT[idx].store(1, Ordering::Relaxed);
                        done = true;
                    }
                }
                _ => {}
            }
            COUNTER_INITIAL[idx].store(cur, Ordering::Relaxed);
            if done {
                // Counter (re)started — reset elapsed-time base so the
                // live count reflects this initial value, not whatever
                // had accumulated before.
                COUNTER_START_TSC[idx].store(rdtsc(), Ordering::Relaxed);
                COUNTER_LATCHED[idx].store(0, Ordering::Relaxed);
            }
        }
        0x43 => {
            // Bits 7:6 — counter select (0/1/2; 3 = read-back, not impl)
            // Bits 5:4 — RW mode (0 = latch, 1 = LSB only, 2 = MSB only, 3 = LSB+MSB)
            // Bits 3:1 — operating mode
            // Bit  0   — BCD (1) / binary (0) — ignored, we always binary
            let counter = (val >> 6) & 0x3;
            let rw = (val >> 4) & 0x3;
            let mode = (val >> 1) & 0x7;
            if counter >= 3 {
                return; // read-back command — not implemented
            }
            let idx = counter as usize;
            if rw == 0 {
                // Latch command — snapshot current count for next read.
                let live = live_counter(idx);
                COUNTER_LATCH[idx].store(live as u64, Ordering::Relaxed);
                COUNTER_LATCHED[idx].store(1, Ordering::Relaxed);
                COUNTER_READ_LSB_NEXT[idx].store(1, Ordering::Relaxed);
            } else {
                COUNTER_RW_MODE[idx].store(rw, Ordering::Relaxed);
                COUNTER_MODE[idx].store(mode, Ordering::Relaxed);
                COUNTER_READ_LSB_NEXT[idx].store(1, Ordering::Relaxed);
                COUNTER_WRITE_LSB_NEXT[idx].store(1, Ordering::Relaxed);
                // Programming the mode arms the counter; actual count
                // load happens on the data-port write that follows.
            }
        }
        0x61 => {
            // Bit 0 = counter 2 gate. Linux's calibration toggles this
            // to start / stop the speaker timer.
            let new_gate = val & 0x1;
            let old_gate = COUNTER2_GATE.swap(new_gate, Ordering::Relaxed);
            if new_gate != 0 && old_gate == 0 {
                // Rising edge — restart counter 2 from its initial.
                COUNTER_START_TSC[2].store(rdtsc(), Ordering::Relaxed);
            }
        }
        _ => {}
    }
}
