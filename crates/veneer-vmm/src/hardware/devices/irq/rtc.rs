//! MC146818 RTC + CMOS RAM emulator.
//!
//! IO ports 0x70 (index latch) and 0x71 (data). Linux, Windows, and
//! every PC firmware since 1984 expects a working RTC here to:
//!   - read wall-clock time at boot (`Unable to read current time
//!     from RTC` if absent — Linux falls back to epoch=0)
//!   - read 128 bytes of battery-backed configuration (CMOS RAM)
//!   - read shutdown status byte for INIT-SIPI sequencing on SMP
//!
//! Standard hypervisor pattern (QEMU rtc_mc146818.c, KVM ioapic, Xen
//! pv-rtc, Hyper-V) — synthesise time from host TSC + a stable epoch.
//! The guest can't tell the difference unless it cross-checks against
//! an NTP server.
//!
//! Register layout (CMOS index 0x00..0x7F):
//!   0x00  Seconds      (BCD or binary per Status B bit 2)
//!   0x01  Seconds Alarm
//!   0x02  Minutes
//!   0x03  Minutes Alarm
//!   0x04  Hours
//!   0x05  Hours Alarm
//!   0x06  Day of week  (1=Sunday)
//!   0x07  Day of month
//!   0x08  Month        (1-12)
//!   0x09  Year         (00-99)
//!   0x0A  Status A     (UIP, divider, rate)
//!   0x0B  Status B     (set, periodic IE, alarm IE, update IE,
//!                       sqw, dm=binary mode, 24h, daylight savings)
//!   0x0C  Status C     (interrupt flags, read-clears)
//!   0x0D  Status D     (valid RAM = 0x80)
//!   0x0E..0x7F  CMOS RAM (firmware-defined)
//!
//! Bit 7 of port 0x70 = NMI disable. We ignore it (NMI doesn't apply
//! in our setup) but accept the write.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

/// CMOS RAM — 128 bytes, byte-addressable via port 0x70 index latch.
/// Initialised to zeros except for the few registers firmware would
/// populate (status B = 24h binary mode, status D = valid RAM).
static CMOS_INDEX: AtomicU8 = AtomicU8::new(0);

/// Status B (CMOS 0x0B) read/write shadow. Power-on default 0x02 = 24h
/// mode, BCD, all interrupt-enable bits clear. Real hardware lets the
/// guest set PIE (bit 6) / UIE (bit 4) / AIE (bit 5); we honour the
/// written value so a guest that enables periodic IRQ8 reads its own
/// configuration back instead of a hardcoded constant. Bits 1 (24h) and
/// 2 (data mode = BCD/binary) feed nothing else here — the time-register
/// reads always emit 24h BCD — but echoing them keeps the register
/// honest.
static STATUS_B: AtomicU8 = AtomicU8::new(0x02);

/// Status B interrupt-enable bits.
const SB_UIE: u8 = 1 << 4; // update-ended interrupt enable
const SB_AIE: u8 = 1 << 5; // alarm interrupt enable
const SB_PIE: u8 = 1 << 6; // periodic interrupt enable

/// Status A rate-select field (bits 3:0). The periodic interrupt rate is
/// 65536 >> (rate-1) Hz for rate 3..15; rate 0 disables, 1..2 are the
/// fast 256/128-divider settings. Power-on default mirrors the 0x26 we
/// report from Status A reads (rate 0b0110 = 1024 Hz).
static STATUS_A_RATE: AtomicU8 = AtomicU8::new(0x06);

/// Status C (CMOS 0x0C) interrupt-flag shadow. Bit 7 = IRQF (any), bit 6
/// = PF (periodic), bit 5 = AF (alarm), bit 4 = UF (update-ended). Reads
/// clear it (and deassert IRQ8) exactly like MC146818 hardware.
static STATUS_C: AtomicU8 = AtomicU8::new(0x00);

/// Virtual-clock anchor for the periodic-interrupt phase. Absolute-phase
/// re-arm (base += period) so late delivery doesn't accumulate drift.
static PIE_NEXT_AT: AtomicU64 = AtomicU64::new(0);
/// The rate the current PIE deadline was armed against; a change re-syncs.
static PIE_ARMED_RATE: AtomicU8 = AtomicU8::new(0);

/// Status C interrupt-flag bits.
#[allow(dead_code)]
const SC_UF: u8 = 1 << 4; // update-ended flag — set by the (unwired) UIE path
const SC_PF: u8 = 1 << 6;
const SC_IRQF: u8 = 1 << 7;

/// Epoch (UTC seconds since 1970-01-01) the synthesised clock counts
/// from. 2026-01-01 00:00:00 UTC = 1767225600. Frozen at boot so
/// successive reads form a monotonic, reproducible timeline.
const EPOCH_START_UTC: u64 = 1_767_225_600;

/// Virtual-clock value sampled at the first CMOS access — gives us a
/// stable "boot moment" anchor without needing a startup hook.
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// Read the filtered, spin-floored virtual clock (host-TSC cycle units).
/// Using `crate::infra::clock::now()` rather than raw RDTSC keeps the RTC in the
/// same time domain as RDTSC, the ACPI PM timer, HPET and the LAPIC timer,
/// so the wall clock can't diverge from them at the one-time VMware
/// nested-SVM host-TSC step the clock module filters out.
#[inline]
fn rdtsc() -> u64 {
    crate::infra::clock::now()
}

/// Current wall-clock seconds = EPOCH_START + (virtual_cycles_elapsed /
/// tsc_freq). Anchored on first call. The clock domain is cycles at the
/// host TSC rate, so dividing by `host_tsc_freq()` still yields seconds.
fn now_seconds() -> u64 {
    let boot = BOOT_TSC.load(Ordering::Relaxed);
    let now_tsc = rdtsc();
    let boot = if boot == 0 {
        BOOT_TSC.store(now_tsc, Ordering::Relaxed);
        now_tsc
    } else {
        boot
    };
    let elapsed_tsc = now_tsc.wrapping_sub(boot);
    let freq = crate::infra::clock::tsc_freq::host_tsc_freq();
    EPOCH_START_UTC + (elapsed_tsc / freq)
}

/// Convert UTC seconds to (year, month, day, hour, min, sec). Uses
/// Howard Hinnant's civil_from_days algorithm — exact for any year
/// representable in i64.
fn civil_from_seconds(secs: u64) -> (u16, u8, u8, u8, u8, u8) {
    let days = (secs / 86_400) as i64;
    let sec_of_day = (secs % 86_400) as u32;
    let hour = (sec_of_day / 3600) as u8;
    let minute = ((sec_of_day % 3600) / 60) as u8;
    let sec = (sec_of_day % 60) as u8;
    // Days since 1970-01-01 → civil date (Hinnant).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = (y + if m <= 2 { 1 } else { 0 }) as u16;
    (year, m as u8, d as u8, hour, minute, sec)
}

/// Encode binary 0..99 as BCD.
#[inline]
fn to_bcd(v: u8) -> u8 {
    ((v / 10) << 4) | (v % 10)
}

/// CMOS read with current index. Time/date registers compute live;
/// status registers return spec defaults; RAM bytes default to 0.
static CMOS_TRACE: AtomicU64 = AtomicU64::new(0);

fn read_indexed(idx: u8) -> u8 {
    if matches!(idx & 0x7F, 0x34 | 0x35 | 0x5B | 0x5C | 0x5D) {
        let n = CMOS_TRACE.fetch_add(1, Ordering::Relaxed);
        if n < 12 {
            crate::sprintln!("[cmos] read idx=0x{:02X}", idx & 0x7F);
        }
    }
    // Status B controls BCD vs binary (bit 2 set = binary). We report
    // BCD (the historical default — every firmware does this). Real
    // OSes check status B and decode accordingly.
    let now = now_seconds();
    let (year, month, day, hour, min, sec) = civil_from_seconds(now);
    // 1-indexed day of week (Sunday=1) — Howard Hinnant uses
    // weekday_from_days; equivalent: (days + 4) mod 7 where 0 = Sun.
    let dow = (((now / 86_400) + 4) % 7) as u8 + 1;
    match idx & 0x7F {
        0x00 => to_bcd(sec),
        0x01 => 0, // alarm — not implemented
        0x02 => to_bcd(min),
        0x03 => 0,
        0x04 => to_bcd(hour), // 24h mode (status B bit 1 = 1)
        0x05 => 0,
        0x06 => to_bcd(dow),
        0x07 => to_bcd(day),
        0x08 => to_bcd(month),
        0x09 => to_bcd((year % 100) as u8),
        0x0A => {
            // Status A: divider 010 (32kHz) + the guest-selected rate in
            // bits 3:0. Bit 7 (UIP — Update In Progress) is asserted by
            // real hardware for ~244 µs at the start of every wall-clock
            // second. Cheap timer-driven OS code (Linux's mc146818_get_
            // time, Windows boot RTC read) polls UIP and waits for it to
            // clear; software that *never* sees UIP=1 is a hint a virtual
            // RTC is in use. Mirror the real pattern by computing UIP
            // from the current sub-second virtual-clock offset.
            let host_tsc = rdtsc();
            let freq = crate::infra::clock::tsc_freq::host_tsc_freq();
            let sub_sec_cycles = host_tsc % freq.max(1);
            // 244 µs in cycles ≈ (244e-6) * freq.
            let uip_window_cycles = freq.saturating_mul(244) / 1_000_000;
            let uip = if sub_sec_cycles < uip_window_cycles { 0x80 } else { 0 };
            // bits 6:4 = divider 010 (32 kHz time base), bits 3:0 = rate.
            0x20 | (STATUS_A_RATE.load(Ordering::Relaxed) & 0x0F) | uip
        }
        0x0B => STATUS_B.load(Ordering::Relaxed),  // RW shadow (24h/BCD + IE bits)
        0x0C => {
            // Status C is read-to-clear: latch the current flags, clear the
            // shadow, and deassert IRQ8. This is exactly the MC146818 ack
            // sequence the OS uses inside its IRQ8 handler.
            STATUS_C.swap(0, Ordering::Relaxed)
        }
        0x0D => 0x80,  // Status D: bit 7 = "RAM and time content valid"
        0x32 => to_bcd((year / 100) as u8), // Century byte (per ACPI FADT.century_index)
        0x50 => to_bcd((year / 100) as u8), // Some BIOSes use 0x50 instead

        // ── Memory-size registers (QEMU/OVMF PlatformPei convention) ──
        // OvmfPkg/PlatformPei/MemDetect.c::GetSystemMemorySizeBelow4gb()
        //   reads CMOS 0x34 (low) / 0x35 (high): extended memory above
        //   16 MiB in 64 KiB units. total_below_4g = (val << 16) + 16 MiB.
        // We report exactly the guest RAM veneer maps (LOW_RAM_BYTES) so
        // OVMF lays its permanent PEI memory inside our NPT window instead
        // of near 4 GiB (which faulted at 0xFCFDF000). Above-4GiB regs
        // (0x5B/0x5C/0x5D) stay 0 — no RAM above 4 GiB.
        0x34 => mem_ext_64k_units() as u8,
        0x35 => (mem_ext_64k_units() >> 8) as u8,
        // Above-4 GiB RAM in 64-KiB units (OvmfPkg GetSystemMemorySizeAbove4gb
        // reads 0x5d:0x5c:0x5b as a 24-bit value << 16 = bytes).
        0x5B => ((crate::guest_mem::high_size() >> 16) & 0xFF) as u8,
        0x5C => ((crate::guest_mem::high_size() >> 24) & 0xFF) as u8,
        0x5D => ((crate::guest_mem::high_size() >> 32) & 0xFF) as u8,
        _    => 0,
    }
}

/// Extended memory above 16 MiB in 64-KiB units, derived from the guest
/// RAM veneer actually maps. Capped so (val<<16)+16MiB stays inside the
/// mapped window.
#[inline]
fn mem_ext_64k_units() -> u16 {
    // veneer maps guest_phys 0..GUEST_RAM_BYTES for the guest. Report
    // (LOW_RAM - 16MiB) in 64-KiB units so OVMF's below-4G size matches the
    // NPT-backed window exactly.
    let low_ram = crate::guest_mem::GUEST_RAM_BYTES;
    (((low_ram - 16 * 1024 * 1024) >> 16) & 0xFFFF) as u16
}

// ───── Periodic interrupt (IRQ8) source ──────────────────────────────
//
// When the guest sets Status B PIE (bit 6) with a non-zero Status A rate,
// the MC146818 raises IRQ8 at 65536 >> (rate-1) Hz. We model that as an
// inject source on the virtual-clock domain: `irq8_pending` reports a due
// tick, `irq8_serviced` advances the phase and latches the Status C flags.
//
// OVMF / Windows boot do not enable PIE, so this path stays dormant during
// the current boot — it removes the "register written but no effect" gap
// without perturbing the booting firmware.

/// Periodic-interrupt period in virtual-clock cycles, or 0 when disabled
/// (PIE clear, or rate outside the 3..15 hardware range).
fn pie_period_cycles() -> u64 {
    if STATUS_B.load(Ordering::Relaxed) & SB_PIE == 0 {
        return 0;
    }
    let rate = STATUS_A_RATE.load(Ordering::Relaxed) & 0x0F;
    // MC146818: rate 1..2 use the 256/128-divider fast settings; rate 3..15
    // give 65536 >> (rate-1) Hz. Rate 0 disables. Be conservative and only
    // honour the well-defined 3..15 range.
    if rate < 3 {
        return 0;
    }
    let hz = 65_536u64 >> (rate - 1);
    if hz == 0 {
        return 0;
    }
    crate::infra::clock::tsc_freq::host_tsc_freq() / hz
}

/// Re-sync the periodic deadline against the current rate. Absolute-phase:
/// the deadline advances by whole periods, so a late `irq8_serviced` does
/// not push subsequent ticks out (no accumulating drift). Returns the live
/// deadline (0 = disabled).
fn pie_sync() -> u64 {
    let period = pie_period_cycles();
    if period == 0 {
        PIE_NEXT_AT.store(0, Ordering::Relaxed);
        PIE_ARMED_RATE.store(0, Ordering::Relaxed);
        return 0;
    }
    let rate = STATUS_A_RATE.load(Ordering::Relaxed) & 0x0F;
    if PIE_ARMED_RATE.load(Ordering::Relaxed) != rate || PIE_NEXT_AT.load(Ordering::Relaxed) == 0 {
        PIE_ARMED_RATE.store(rate, Ordering::Relaxed);
        PIE_NEXT_AT.store(crate::infra::clock::now().wrapping_add(period), Ordering::Relaxed);
    }
    PIE_NEXT_AT.load(Ordering::Relaxed)
}

/// Non-consuming: is a periodic IRQ8 due now?
pub fn irq8_pending() -> bool {
    let next = pie_sync();
    next != 0 && crate::infra::clock::now() >= next
}

/// Consume one periodic IRQ8: set Status C PF/IRQF and advance the phase by
/// whole periods (catching up if we fell behind, but never re-basing on a
/// late `now()` so the average rate stays exact).
pub fn irq8_serviced() {
    STATUS_C.fetch_or(SC_PF | SC_IRQF, Ordering::Relaxed);
    let period = pie_period_cycles();
    if period == 0 {
        PIE_NEXT_AT.store(0, Ordering::Relaxed);
        return;
    }
    let now = crate::infra::clock::now();
    let mut next = PIE_NEXT_AT.load(Ordering::Relaxed).wrapping_add(period);
    // If we are more than one period behind, snap forward to the next
    // future boundary on the original phase grid (avoid a burst of
    // back-to-back catch-up injections).
    if next <= now {
        let behind = now.wrapping_sub(next) / period;
        next = next.wrapping_add(behind.wrapping_add(1).wrapping_mul(period));
    }
    PIE_NEXT_AT.store(next, Ordering::Relaxed);
}

/// Status B update-interrupt-enable bit — exposed so the inject layer can
/// tell whether the guest wants update-ended (UIE) IRQ8s too. Currently
/// only PIE is wired; UIE/AIE are reported for completeness.
#[allow(dead_code)]
pub fn uie_enabled() -> bool {
    STATUS_B.load(Ordering::Relaxed) & SB_UIE != 0
}

/// Alarm-interrupt-enable bit (AIE). Not yet driven (no alarm match path).
#[allow(dead_code)]
pub fn aie_enabled() -> bool {
    STATUS_B.load(Ordering::Relaxed) & SB_AIE != 0
}

#[inline]
pub fn covers(port: u16) -> bool {
    matches!(port, 0x70 | 0x71)
}

pub fn handle_in(port: u16) -> u8 {
    match port {
        // 0x70 is officially write-only (latches the next read index).
        // Real chips return the last value on the bus, which we synth as
        // 0xFF to avoid leaking bits. Some firmware reads it for parity
        // checks; returning 0xFF passes the "no value" assumption.
        0x70 => 0xFF,
        0x71 => {
            let idx = CMOS_INDEX.load(Ordering::Relaxed);
            read_indexed(idx)
        }
        _ => 0xFF,
    }
}

pub fn handle_out(port: u16, val: u8) {
    match port {
        0x70 => {
            // Bit 7 = NMI disable. Strip and store only the index bits.
            CMOS_INDEX.store(val & 0x7F, Ordering::Relaxed);
        }
        0x71 => {
            let idx = CMOS_INDEX.load(Ordering::Relaxed) & 0x7F;
            match idx {
                0x0A => {
                    // Status A: only the rate-select field (bits 3:0) and
                    // the divider are guest-writable; UIP (bit 7) is RO. We
                    // keep the divider fixed (32 kHz) and shadow the rate so
                    // the periodic-interrupt period tracks what the guest
                    // programmed.
                    STATUS_A_RATE.store(val & 0x0F, Ordering::Relaxed);
                }
                0x0B => {
                    // Status B is fully writable on real hardware. Shadow it
                    // so PIE/UIE/AIE read back and gate IRQ8 generation.
                    STATUS_B.store(val, Ordering::Relaxed);
                }
                _ => {
                    // Time/date register writes are silently swallowed —
                    // veneer's clock is read-only synthesised. Other CMOS
                    // RAM writes likewise drop; the kernel only writes
                    // scratch values there.
                    let _ = val;
                }
            }
        }
        _ => {}
    }
}
