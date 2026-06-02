//! ACPI Power Management Timer + ICH9 PM base register.
//!
//! veneer advertises a Q35 host bridge, so OVMF runs its ICH9 ACPI
//! bring-up: it programs the PM base (PMBASE, LPC config offset 0x40)
//! then reads the 24-bit Power Management Timer at PMBASE+8 inside its
//! stall loops (`AcpiTimerLib::InternalAcpiDelay`). With no timer the
//! firmware spins forever on ticks that never advance.
//!
//! The timer is a free-running 24-bit counter at the ACPI-fixed
//! 3.579545 MHz, derived from the calibrated host TSC so guest delays
//! track real wall-clock time.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::clock::tsc_freq;

const PM_TIMER_HZ: u64 = 3_579_545;
/// PM1 timer offset above the ACPI I/O base (ICH9 / Q35).
const TMR_OFFSET: u16 = 0x08;
/// Span of the ACPI fixed-register I/O block we answer for.
const PM_IO_SPAN: u16 = 0x40;
/// PMBASE address field; low bits are the I/O-space flag and RTE.
const PMBASE_ADDR_MASK: u32 = 0xFFC0;

const PMBASE_REG: u8 = 0x40;
const ACPI_CNTL_REG: u8 = 0x44;

/// PM1a_CNT (sleep/SCI control) offset above the ACPI I/O base on ICH9.
const CNT_OFFSET: u16 = 0x04;
/// PM1_CNT bit layout (ACPI 6.x §4.8.3.2.1).
const SLP_EN: u32 = 1 << 13;
const SLP_TYP_SHIFT: u32 = 10;
const SLP_TYP_MASK: u32 = 0x7;
/// ICH9 / Q35 hardware-fixed sleep-type value for S5 (soft-off). OVMF's
/// FADT publishes this in \_S5; matching it lets us recognise a real
/// power-off request rather than a transition to a lighter sleep state.
const SLP_TYP_S5: u32 = 0;

static PMBASE: AtomicU32 = AtomicU32::new(0);
static ACPI_CNTL: AtomicU32 = AtomicU32::new(0);
static TIMER_BASE_TSC: AtomicU64 = AtomicU64::new(0);
/// PM1a control shadow (so reads of PM1a_CNT echo what the guest wrote).
static PM1_CNT: AtomicU32 = AtomicU32::new(0);
/// Set once the guest writes SLP_EN with SLP_TYP = S5. The VMRUN loop /
/// IO dispatcher can poll this to drive an orderly VM power-off; we can't
/// force a Halt from inside this `write()` (its `()` return can't signal
/// the dispatcher), so we record the request honestly instead of dropping
/// it silently.
static S5_REQUESTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

static TRACE: AtomicU32 = AtomicU32::new(0);
const TRACE_CAP: u32 = 4;

#[inline]
fn host_rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)); }
    ((hi as u64) << 32) | (lo as u64)
}

#[inline]
fn merge(reg: &AtomicU32, byte_in_dword: u8, val: u32, width: u8) {
    let shift = (byte_in_dword & 0x3) as u32 * 8;
    let m: u32 = match width { 1 => 0xFF, 2 => 0xFFFF, _ => 0xFFFF_FFFF };
    let mask = m << shift;
    let prev = reg.load(Ordering::Relaxed);
    reg.store((prev & !mask) | ((val << shift) & mask), Ordering::Relaxed);
}

/// Is `reg` (LPC config byte offset) one this device owns?
#[inline]
pub fn owns_reg(reg: u8) -> bool {
    matches!(reg & 0xFC, PMBASE_REG | ACPI_CNTL_REG)
}

/// LPC config-space write to a PM register. Snapshots the host TSC the
/// first time a non-zero base is latched so the timer counts from zero.
pub fn config_write(reg: u8, val: u32, width: u8) {
    match reg & 0xFC {
        PMBASE_REG => {
            let prev = PMBASE.load(Ordering::Relaxed);
            merge(&PMBASE, reg - PMBASE_REG, val, width);
            let new = PMBASE.load(Ordering::Relaxed);
            if prev & PMBASE_ADDR_MASK == 0 && new & PMBASE_ADDR_MASK != 0 {
                TIMER_BASE_TSC.store(crate::clock::now(), Ordering::Relaxed);
                let n = TRACE.fetch_add(1, Ordering::Relaxed);
                if n < TRACE_CAP {
                    crate::sprintln!(
                        "[acpipm] PMBASE=0x{:X} -> timer port 0x{:X}",
                        new, (new & PMBASE_ADDR_MASK) as u16 + TMR_OFFSET
                    );
                }
            }
        }
        ACPI_CNTL_REG => merge(&ACPI_CNTL, reg - ACPI_CNTL_REG, val, width),
        _ => {}
    }
}

pub fn pmbase() -> u32 {
    PMBASE.load(Ordering::Relaxed)
}

pub fn acpi_cntl() -> u32 {
    ACPI_CNTL.load(Ordering::Relaxed)
}

#[inline]
fn io_base() -> u16 {
    (PMBASE.load(Ordering::Relaxed) & PMBASE_ADDR_MASK) as u16
}

#[inline]
pub fn covers(port: u16) -> bool {
    let base = io_base();
    base != 0 && port >= base && port < base + PM_IO_SPAN
}

fn timer_ticks_at(now: u64) -> u32 {
    let base = TIMER_BASE_TSC.load(Ordering::Relaxed);
    let elapsed = now.wrapping_sub(base) as u128;
    let ticks = elapsed * PM_TIMER_HZ as u128 / tsc_freq::host_tsc_freq() as u128;
    (ticks as u64 & 0x00FF_FFFF) as u32
}

static READ_TRACE: AtomicU32 = AtomicU32::new(0);
static PREV_TSC: AtomicU64 = AtomicU64::new(0);
static JUMP_LOG: AtomicU32 = AtomicU32::new(0);
/// ~32 ms at 3 GHz. Consecutive PM-timer reads are µs apart, so any gap
/// this large between two reads is a discontinuity, not real elapsed time.
const JUMP_THRESHOLD: u64 = 100_000_000;

pub fn read(port: u16, width: u8) -> u64 {
    let base = io_base();
    let mask: u64 = match width { 1 => 0xFF, 2 => 0xFFFF, _ => 0xFFFF_FFFF };
    if port == base + TMR_OFFSET {
        let now = crate::clock::now();
        let v = timer_ticks_at(now);
        // Diagnostic only: the filtered clock above already absorbs any
        // host-TSC step; this confirms whether the raw step still occurs.
        let real = host_rdtsc();
        let prev = PREV_TSC.swap(real, Ordering::Relaxed);
        let n = READ_TRACE.fetch_add(1, Ordering::Relaxed);
        if prev != 0 {
            let (dir, d) = if real >= prev { ("FWD", real - prev) } else { ("BACK", prev - real) };
            if dir == "BACK" || d > JUMP_THRESHOLD {
                let j = JUMP_LOG.fetch_add(1, Ordering::Relaxed);
                if j < 40 {
                    crate::sprintln!("[tscjump] read#{} {} prev=0x{:X} real=0x{:X} delta=0x{:X}", n, dir, prev, real, d);
                }
            }
        }
        let _ = n;
        return v as u64 & mask;
    }
    if port == base + CNT_OFFSET {
        // PM1a_CNT readback. SLP_EN (bit 13) is self-clearing in hardware
        // once the sleep transition completes, so it always reads back 0;
        // the SCI_EN / bus-master bits echo what the guest programmed.
        return (PM1_CNT.load(Ordering::Relaxed) & !SLP_EN) as u64 & mask;
    }
    // PM1a event and the remaining fixed registers stay quiescent.
    0
}

pub fn write(port: u16, val: u64, _width: u8) {
    let base = io_base();
    if base != 0 && port == base + CNT_OFFSET {
        let v = val as u32;
        // Store everything except the self-clearing SLP_EN strobe.
        PM1_CNT.store(v & !SLP_EN, Ordering::Relaxed);
        if v & SLP_EN != 0 {
            let slp_typ = (v >> SLP_TYP_SHIFT) & SLP_TYP_MASK;
            if slp_typ == SLP_TYP_S5 {
                // Guest requested soft-off (S5). Record it for the VMRUN
                // loop to act on — we deliberately do not force shutdown
                // from here because this handler can't signal Action::Halt.
                if !S5_REQUESTED.swap(true, Ordering::Relaxed) {
                    crate::sprintln!("[acpipm] PM1a_CNT S5 (soft-off) requested");
                }
            } else {
                crate::sprintln!("[acpipm] PM1a_CNT sleep SLP_TYP={} requested", slp_typ);
            }
        }
        return;
    }
    // PM1 event acks and other fixed registers — accept and drop.
}

/// True once the guest has written PM1a_CNT with SLP_EN | SLP_TYP(S5).
/// The host VMRUN loop can poll this to power the guest off cleanly.
#[allow(dead_code)]
pub fn s5_requested() -> bool {
    S5_REQUESTED.load(Ordering::Relaxed)
}
