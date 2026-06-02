//! Local APIC MMIO emulator — per-vCPU register state.
//!
//! LAPIC base 0xFEE00000, 4 KiB window. We model the registers Windows
//! / Linux kernels touch during boot:
//!
//!   0x020  ID                  — host APIC ID (RO, derived from CPUID)
//!   0x030  Version             — P6+ encoding 0x0050_0014
//!   0x080  TPR                 — Task Priority (per-vCPU)
//!   0x0A0  PPR                 — Processor Priority (computed from TPR)
//!   0x0B0  EOI                 — write-1-to-signal end of interrupt
//!   0x0D0  LDR                 — Logical Destination
//!   0x0E0  DFR                 — Destination Format
//!   0x0F0  SVR                 — Spurious Vector Register (SW enable bit)
//!   0x100..0x170  ISR/TMR/IRR  — 256-bit bitmaps, all zero (no pending IRQs)
//!   0x280  ESR                 — Error Status (read clears)
//!   0x300  ICR low             — IPI Command Low (write triggers IPI)
//!   0x310  ICR high            — IPI Command High (dest APIC ID)
//!   0x320  LVT Timer           — Timer interrupt config
//!   0x330  LVT Thermal
//!   0x340  LVT Perf
//!   0x350  LVT LINT0
//!   0x360  LVT LINT1
//!   0x370  LVT Error
//!   0x380  Initial Count
//!   0x390  Current Count       — counts down from Initial (TSC-scaled)
//!   0x3E0  Divide Configuration
//!
//! Per-vCPU storage: APIC ID (0..255) used as index into per-register
//! AtomicU32 arrays. Each host CPU writes only its own slot.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arch::cpuid;

pub const LAPIC_BASE: u64 = 0xFEE0_0000;
pub const LAPIC_SIZE: u64 = 0x0000_1000;

#[inline]
pub fn covers(gpa: u64) -> bool {
    gpa >= LAPIC_BASE && gpa < LAPIC_BASE + LAPIC_SIZE
}

const N_VCPUS: usize = 256;

// AtomicU32 isn't Copy, so [CONST; N] repeat-expr requires a real
// const binding; can't use [AtomicU32::new(x); N] directly.
#[allow(clippy::declare_interior_mutable_const)]
const ZERO: AtomicU32 = AtomicU32::new(0);
#[allow(clippy::declare_interior_mutable_const)]
const SVR_DEFAULT: AtomicU32 = AtomicU32::new(0x0000_01FF);
#[allow(clippy::declare_interior_mutable_const)]
const DFR_DEFAULT: AtomicU32 = AtomicU32::new(0xFFFF_FFFF);
#[allow(clippy::declare_interior_mutable_const)]
const LVT_MASKED: AtomicU32 = AtomicU32::new(0x0001_0000);

// ───── Per-vCPU state ────────────────────────────────────────────────

static TPR:        [AtomicU32; N_VCPUS] = [ZERO; N_VCPUS];
static SVR:        [AtomicU32; N_VCPUS] = [SVR_DEFAULT; N_VCPUS];
static LDR:        [AtomicU32; N_VCPUS] = [ZERO; N_VCPUS];
static DFR:        [AtomicU32; N_VCPUS] = [DFR_DEFAULT; N_VCPUS];
static ESR:        [AtomicU32; N_VCPUS] = [ZERO; N_VCPUS];
static ICR_LO:     [AtomicU32; N_VCPUS] = [ZERO; N_VCPUS];
static ICR_HI:     [AtomicU32; N_VCPUS] = [ZERO; N_VCPUS];
static LVT_TIMER:  [AtomicU32; N_VCPUS] = [LVT_MASKED; N_VCPUS];
static LVT_THERMAL:[AtomicU32; N_VCPUS] = [LVT_MASKED; N_VCPUS];
static LVT_PERF:   [AtomicU32; N_VCPUS] = [LVT_MASKED; N_VCPUS];
static LVT_LINT0:  [AtomicU32; N_VCPUS] = [LVT_MASKED; N_VCPUS];
static LVT_LINT1:  [AtomicU32; N_VCPUS] = [LVT_MASKED; N_VCPUS];
static LVT_ERROR:  [AtomicU32; N_VCPUS] = [LVT_MASKED; N_VCPUS];
static TIMER_INIT_COUNT: [AtomicU32; N_VCPUS] = [ZERO; N_VCPUS];
/// Pending self-IPI vector — written by the ICR_LO handler when the
/// shorthand bits encode "self", consumed by `intercept/inject.rs`.
/// 0 means "no pending IPI"; vectors 0..15 are reserved by Intel so
/// reusing 0 as the sentinel is safe.
static PENDING_IPI: [AtomicU32; N_VCPUS] = [ZERO; N_VCPUS];
/// Pending self-targeted NMI from an ICR write with delivery mode = NMI
/// (0b100). Drained by the inject layer as an AMD TYPE_NMI event. 1 =
/// pending. NMIs carry no vector, so a flag suffices.
static PENDING_NMI: [AtomicU32; N_VCPUS] = [ZERO; N_VCPUS];
// host TSC is 64-bit (~0.91s to overflow u32 at 4.7 GHz). u32 storage
// caused the timer base to wrap roughly once per second and the
// current count to flip between sane and huge garbage. AtomicU64 is the
// correct width for cycles-since-base.
#[allow(clippy::declare_interior_mutable_const)]
const ZERO64: AtomicU64 = AtomicU64::new(0);
static TIMER_BASE_TSC:   [AtomicU64; N_VCPUS] = [ZERO64; N_VCPUS];
static TIMER_DIVCFG:     [AtomicU32; N_VCPUS] = [ZERO; N_VCPUS];
// TSC-deadline mode (LVT timer mode 0b10). The guest arms the timer by
// writing an absolute guest-TSC value to IA32_TSC_DEADLINE (MSR 0x6E0);
// it fires when the guest TSC reaches it. We translate that absolute
// deadline into the local `clock::now()` domain at write time (where the
// VMCB tsc_offset is available) so the fire check needs no offset and
// stays immune to the VMware host-TSC step `clock` already filters.
// `_AT` is the fire time in clock::now() units (0 = disarmed); `_RAW`
// keeps the value the guest wrote so RDMSR(0x6E0) reads back consistently.
static TIMER_DEADLINE_AT:  [AtomicU64; N_VCPUS] = [ZERO64; N_VCPUS];
static TIMER_DEADLINE_RAW: [AtomicU64; N_VCPUS] = [ZERO64; N_VCPUS];

// ───── 256-bit interrupt bitmaps (ISR / IRR / TMR) ───────────────────
//
// Real LAPIC tracks, per 256-vector space, three bitmaps:
//   IRR (0x200) — interrupt requested, not yet in service
//   ISR (0x100) — interrupt in service (acked into the core, awaiting EOI)
//   TMR (0x180) — trigger mode: 1 = level-triggered for the in-service IRQ
// Each is 8 × 32-bit registers spaced 0x10 apart (vector v lives in
// register v/32, bit v%32). We expose them so PPR reflects the in-service
// priority and EOI clears the highest ISR bit — previously these read as a
// constant 0 and EOI was a no-op, which is the "register accepted but no
// side effect" gap. We model the common hypervisor case: an injected
// interrupt is delivered straight into service, so on inject we set ISR
// (and TMR for level lines); the guest's EOI clears the top ISR bit. IRR
// is maintained too for any source staged but not yet injected.
#[allow(clippy::declare_interior_mutable_const)]
const ZERO_BITMAP: [AtomicU32; 8] = [ZERO; 8];
static ISR: [[AtomicU32; 8]; N_VCPUS] = [ZERO_BITMAP; N_VCPUS];
static IRR: [[AtomicU32; 8]; N_VCPUS] = [ZERO_BITMAP; N_VCPUS];
static TMR: [[AtomicU32; 8]; N_VCPUS] = [ZERO_BITMAP; N_VCPUS];

#[inline]
fn bitmap_set(map: &[AtomicU32; 8], vector: u8) {
    let word = (vector >> 5) as usize;
    let bit = (vector & 0x1F) as u32;
    map[word].fetch_or(1u32 << bit, Ordering::Relaxed);
}

#[inline]
fn bitmap_clear(map: &[AtomicU32; 8], vector: u8) {
    let word = (vector >> 5) as usize;
    let bit = (vector & 0x1F) as u32;
    map[word].fetch_and(!(1u32 << bit), Ordering::Relaxed);
}

/// Highest set vector in a bitmap, or None if empty. Vectors are
/// prioritised by numeric value (higher vector = higher priority).
#[inline]
fn bitmap_highest(map: &[AtomicU32; 8]) -> Option<u8> {
    for word in (0..8usize).rev() {
        let v = map[word].load(Ordering::Relaxed);
        if v != 0 {
            let bit = 31 - v.leading_zeros();
            return Some(((word as u32) * 32 + bit) as u8);
        }
    }
    None
}

/// Record that `vector` is being delivered into service on `slot`. Sets
/// the ISR bit and, for a level-triggered line, the matching TMR bit so a
/// subsequent EOI knows to signal the IO-APIC. Called by the inject layer
/// the moment it stages the interrupt into `event_inj`.
pub fn set_in_service(slot: usize, vector: u8, level: bool) {
    if vector < 16 {
        return; // exception space — never tracked as an external IRQ
    }
    // Leaving IRR: the request is now in service.
    bitmap_clear(&IRR[slot], vector);
    bitmap_set(&ISR[slot], vector);
    if level {
        bitmap_set(&TMR[slot], vector);
    } else {
        bitmap_clear(&TMR[slot], vector);
    }
}

/// Mark `vector` as requested (pending) on `slot` without putting it in
/// service. Used for completeness when a source is staged but masking /
/// priority defers actual delivery.
#[allow(dead_code)]
pub fn set_requested(slot: usize, vector: u8) {
    if vector >= 16 {
        bitmap_set(&IRR[slot], vector);
    }
}

/// Whether the in-service interrupt being EOI'd was level-triggered, for
/// the given vector. The IO-APIC remote-IRR clear path consults this.
fn isr_level(slot: usize, vector: u8) -> bool {
    let word = (vector >> 5) as usize;
    let bit = (vector & 0x1F) as u32;
    TMR[slot][word].load(Ordering::Relaxed) & (1u32 << bit) != 0
}

/// Processor Priority Register (0x0A0). Per Intel SDM §10.8.3.1, PPR =
/// max(TPR, ISRV-priority-class), where the priority class is the top
/// nibble of the highest in-service vector. With nothing in service PPR
/// follows TPR; while servicing a high-priority IRQ it rises so lower
/// interrupts are held off until EOI.
fn processor_priority(slot: usize) -> u32 {
    let tpr = TPR[slot].load(Ordering::Relaxed) & 0xFF;
    let isrv = bitmap_highest(&ISR[slot]).map(|v| v as u32).unwrap_or(0);
    let isr_class = isrv & 0xF0;
    if (tpr & 0xF0) >= isr_class {
        // TPR's class dominates: PPR = TPR, sub-class bits included (SDM).
        tpr
    } else {
        // ISR's class dominates: PPR = ISR priority class, sub-class = 0.
        isr_class
    }
}

#[inline]
fn current_vcpu_slot() -> usize {
    ((cpuid(1).ebx >> 24) & 0xFF) as usize
}

#[inline]
fn host_apic_id() -> u32 {
    (cpuid(1).ebx >> 24) & 0xFF
}

#[inline]
fn host_rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)); }
    ((hi as u64) << 32) | (lo as u64)
}

/// Divide-configuration register decode → divisor.
fn timer_divisor(divcfg: u32) -> u32 {
    let v = ((divcfg >> 1) & 0b100) | (divcfg & 0b011);
    match v {
        0b000 => 2,
        0b001 => 4,
        0b010 => 8,
        0b011 => 16,
        0b100 => 32,
        0b101 => 64,
        0b110 => 128,
        0b111 => 1,
        _     => 16,
    }
}

/// Synthesise the current Timer Current Count from base TSC + initial
/// count + divisor. Monotonically decreases; saturates at 0.
fn timer_current_count(slot: usize) -> u32 {
    let init = TIMER_INIT_COUNT[slot].load(Ordering::Relaxed);
    if init == 0 { return 0; }
    let divcfg = TIMER_DIVCFG[slot].load(Ordering::Relaxed);
    let divisor = timer_divisor(divcfg) as u64;
    let base = TIMER_BASE_TSC[slot].load(Ordering::Relaxed);
    let now = crate::clock::now();
    let elapsed = now.wrapping_sub(base) / divisor;
    if elapsed >= init as u64 { 0 } else { (init as u64 - elapsed) as u32 }
}

/// True if a Local APIC timer interrupt is pending delivery on `slot`.
/// Returns the LVT-encoded vector when so, `None` otherwise.
///
/// LVT Timer bit layout:
///   bits  7:0  vector
///   bit  12    delivery status (RO — set while pending; we leave 0)
///   bit  16    mask
///   bits 18:17 mode (0=one-shot, 1=periodic, 2=tsc-deadline)
pub fn timer_pending(slot: usize) -> Option<u8> {
    let lvt = LVT_TIMER[slot].load(Ordering::Relaxed);
    // Bit 16 = mask. If guest hasn't unmasked yet, no IRQ.
    if lvt & (1 << 16) != 0 { return None; }
    // Gate on the SVR Software-Enable bit so we don't deliver IRQs to a
    // LAPIC that hasn't been turned on yet (POST stage).
    let svr = SVR[slot].load(Ordering::Relaxed);
    if svr & (1 << 8) == 0 { return None; }
    if (lvt >> 17) & 0x3 == 2 {
        // TSC-deadline mode: fires once the clock reaches the translated
        // deadline. Modern Linux/Windows prefer this over the count-down
        // timer when CPUID advertises it (leaf 1 ECX bit 24).
        let at = TIMER_DEADLINE_AT[slot].load(Ordering::Relaxed);
        if at == 0 || crate::clock::now() < at { return None; }
        return Some((lvt & 0xFF) as u8);
    }
    // One-shot / periodic count-down timer.
    let init = TIMER_INIT_COUNT[slot].load(Ordering::Relaxed);
    if init == 0 { return None; }
    if timer_current_count(slot) != 0 { return None; }
    Some((lvt & 0xFF) as u8)
}

/// Arm (or disarm) the TSC-deadline timer for the current vCPU.
/// `guest_deadline` is the absolute guest-TSC value the guest wrote to
/// IA32_TSC_DEADLINE; `guest_tsc_now` is the guest's current TSC (host
/// TSC + VMCB tsc_offset). A zero deadline disarms. We convert to the
/// `clock::now()` domain once here so the fire path is offset-free.
pub fn set_tsc_deadline(guest_deadline: u64, guest_tsc_now: u64) {
    let slot = current_vcpu_slot();
    TIMER_DEADLINE_RAW[slot].store(guest_deadline, Ordering::Relaxed);
    if guest_deadline == 0 {
        TIMER_DEADLINE_AT[slot].store(0, Ordering::Relaxed);
        return;
    }
    let now = crate::clock::now();
    let delta = guest_deadline.wrapping_sub(guest_tsc_now);
    // Past-or-now deadline (top bit set after wrap) fires immediately.
    let at = if (delta as i64) <= 0 { now } else { now.wrapping_add(delta) };
    // Never store the disarm sentinel for an armed timer.
    TIMER_DEADLINE_AT[slot].store(if at == 0 { 1 } else { at }, Ordering::Relaxed);
}

/// IA32_TSC_DEADLINE readback. Hardware reads back the armed value and 0
/// once the timer has fired; `timer_serviced` clears RAW on fire.
pub fn tsc_deadline_raw() -> u64 {
    TIMER_DEADLINE_RAW[current_vcpu_slot()].load(Ordering::Relaxed)
}

/// Diagnostic dump of LAPIC timer state for vCPU 0.
pub fn debug_dump() {
    crate::sprintln!(
        "[lapic] LVT_TIMER=0x{:X} init=0x{:X} cur=0x{:X} SVR=0x{:X} divcfg=0x{:X} base=0x{:X} now=0x{:X} dl_at=0x{:X}",
        LVT_TIMER[0].load(Ordering::Relaxed),
        TIMER_INIT_COUNT[0].load(Ordering::Relaxed),
        timer_current_count(0),
        SVR[0].load(Ordering::Relaxed),
        TIMER_DIVCFG[0].load(Ordering::Relaxed),
        TIMER_BASE_TSC[0].load(Ordering::Relaxed),
        crate::clock::now(),
        TIMER_DEADLINE_AT[0].load(Ordering::Relaxed),
    );
}

/// True when the LAPIC timer will eventually fire on its own (unmasked,
/// software-enabled, with a non-zero initial count). The HLT idle path
/// uses this to decide whether sleeping for a timer wake is worthwhile.
pub fn timer_armed(slot: usize) -> bool {
    let lvt = LVT_TIMER[slot].load(Ordering::Relaxed);
    if lvt & (1 << 16) != 0 {
        return false;
    }
    if SVR[slot].load(Ordering::Relaxed) & (1 << 8) == 0 {
        return false;
    }
    if (lvt >> 17) & 0x3 == 2 {
        return TIMER_DEADLINE_AT[slot].load(Ordering::Relaxed) != 0;
    }
    TIMER_INIT_COUNT[slot].load(Ordering::Relaxed) != 0
}

/// x2APIC SELF IPI register (MSR 0x83F) — deliver `vector` to this vCPU.
/// Vectors below 16 are CPU-exception space and ignored.
pub fn self_ipi(vector: u8) {
    if vector >= 16 {
        PENDING_IPI[current_vcpu_slot()].store(vector as u32, Ordering::Relaxed);
    }
}

/// Pending self-IPI (or "all including self") set by an earlier ICR
/// write. Returns the vector and clears the slot so the next staging
/// pass doesn't re-deliver. Vectors below 16 are filtered out (those
/// indices belong to CPU exceptions per Intel SDM and would corrupt
/// guest state if injected as ordinary interrupts).
pub fn ipi_pending(slot: usize) -> Option<u8> {
    let v = PENDING_IPI[slot].swap(0, Ordering::AcqRel);
    if v == 0 { None } else { Some(v as u8) }
}

/// Pending self-NMI from an ICR write with delivery mode = NMI. Returns
/// true once and clears, so the inject layer fires exactly one NMI.
pub fn nmi_pending(slot: usize) -> bool {
    PENDING_NMI[slot].swap(0, Ordering::AcqRel) != 0
}

/// Mark a previously-pending timer IRQ as injected. Periodic mode
/// re-arms (init count stays, base TSC resets); one-shot and
/// TSC-deadline clear the init count so the timer stops.
pub fn timer_serviced(slot: usize) {
    let lvt = LVT_TIMER[slot].load(Ordering::Relaxed);
    let mode = (lvt >> 17) & 0x3;
    match mode {
        1 => {
            // Periodic — re-arm on the absolute phase grid, not from now().
            // Re-basing on now() folds the inject latency (the gap between
            // the count reaching 0 and us servicing it) into every period,
            // so the effective tick rate drifts slow. Advancing the base by
            // exactly one period (init_count × divisor, in clock cycles)
            // keeps the long-run rate exact. If we have fallen more than a
            // period behind (e.g. a long VMEXIT storm), snap forward to the
            // next future boundary on the same grid rather than emit a burst.
            let init = TIMER_INIT_COUNT[slot].load(Ordering::Relaxed) as u64;
            let divisor = timer_divisor(TIMER_DIVCFG[slot].load(Ordering::Relaxed)) as u64;
            let period = init.saturating_mul(divisor);
            if period == 0 {
                TIMER_BASE_TSC[slot].store(crate::clock::now(), Ordering::Relaxed);
            } else {
                let base = TIMER_BASE_TSC[slot].load(Ordering::Relaxed);
                let now = crate::clock::now();
                let mut next_base = base.wrapping_add(period);
                if next_base.wrapping_add(period) <= now {
                    // More than one full period behind — realign to the
                    // most recent boundary that is still ≤ now.
                    let behind = now.wrapping_sub(base) / period;
                    next_base = base.wrapping_add(behind.wrapping_mul(period));
                }
                TIMER_BASE_TSC[slot].store(next_base, Ordering::Relaxed);
            }
        }
        2 => {
            // TSC-deadline is one-shot; hardware clears the MSR on fire and
            // the guest reprograms it each tick.
            TIMER_DEADLINE_AT[slot].store(0, Ordering::Relaxed);
            TIMER_DEADLINE_RAW[slot].store(0, Ordering::Relaxed);
        }
        _ => {
            TIMER_INIT_COUNT[slot].store(0, Ordering::Relaxed);
        }
    }
}

// ───── Width-aware read/write ────────────────────────────────────────

#[inline]
fn low_mask(width: u8) -> u64 {
    match width {
        1 => 0xFFu64,
        2 => 0xFFFFu64,
        4 => 0xFFFF_FFFFu64,
        _ => u64::MAX,
    }
}

fn read_dword(offset: u32) -> u32 {
    let slot = current_vcpu_slot();
    match offset {
        0x020 => host_apic_id() << 24,
        0x030 => 0x0050_0014,                              // Version: max LVT=5, ver=0x14
        0x080 => TPR[slot].load(Ordering::Relaxed),
        0x0A0 => processor_priority(slot),                  // PPR = max(TPR, ISR) class
        0x0B0 => 0,                                         // EOI reads as 0
        0x0D0 => LDR[slot].load(Ordering::Relaxed),
        0x0E0 => DFR[slot].load(Ordering::Relaxed),
        0x0F0 => SVR[slot].load(Ordering::Relaxed),
        // ISR 0x100..0x170, TMR 0x180..0x1F0, IRR 0x200..0x270 — each is
        // 8 × 32-bit registers spaced 0x10 apart. Return the live bitmap
        // word so the OS sees its in-service / requested / trigger state.
        0x100..=0x170 => ISR[slot][((offset - 0x100) >> 4) as usize].load(Ordering::Relaxed),
        0x180..=0x1F0 => TMR[slot][((offset - 0x180) >> 4) as usize].load(Ordering::Relaxed),
        0x200..=0x270 => IRR[slot][((offset - 0x200) >> 4) as usize].load(Ordering::Relaxed),
        0x280 => ESR[slot].load(Ordering::Relaxed),
        0x300 => ICR_LO[slot].load(Ordering::Relaxed),
        0x310 => ICR_HI[slot].load(Ordering::Relaxed),
        0x320 => LVT_TIMER[slot].load(Ordering::Relaxed),
        0x330 => LVT_THERMAL[slot].load(Ordering::Relaxed),
        0x340 => LVT_PERF[slot].load(Ordering::Relaxed),
        0x350 => LVT_LINT0[slot].load(Ordering::Relaxed),
        0x360 => LVT_LINT1[slot].load(Ordering::Relaxed),
        0x370 => LVT_ERROR[slot].load(Ordering::Relaxed),
        0x380 => TIMER_INIT_COUNT[slot].load(Ordering::Relaxed),
        0x390 => timer_current_count(slot),
        0x3E0 => TIMER_DIVCFG[slot].load(Ordering::Relaxed),
        _ => 0,
    }
}

pub fn read_register(offset: u32) -> u32 {
    read_dword(offset & !0x3)
}

static LAPIC_READ_COUNT: AtomicU32 = AtomicU32::new(0);
static LAPIC_WRITE_COUNT: AtomicU32 = AtomicU32::new(0);
const LAPIC_TRACE_CAP: u32 = 0;

static TIMER_TRACE: AtomicU32 = AtomicU32::new(0);
const TIMER_TRACE_CAP: u32 = 24;

pub fn read_register_width(offset: u32, width: u8) -> u64 {
    let aligned = offset & !0x3;
    let shift_bits = (offset & 0x3) * 8;
    let dword = read_dword(aligned);
    let val = ((dword as u64) >> shift_bits) & low_mask(width);
    let n = LAPIC_READ_COUNT.fetch_add(1, Ordering::Relaxed);
    if n < LAPIC_TRACE_CAP {
        crate::sprintln!("[lapic] R[0x{:03X}].{}B = 0x{:X} (#{}/{})", offset, width, val, n + 1, LAPIC_TRACE_CAP);
    }
    if aligned == 0x390 {
        let t = TIMER_TRACE.fetch_add(1, Ordering::Relaxed);
        if t < TIMER_TRACE_CAP {
            crate::sprintln!("[ltmr] R CCR=0x{:X} tsc=0x{:X}", val, host_rdtsc());
        }
    }
    val
}

pub fn write_register_width(offset: u32, val: u64, width: u8) {
    let n = LAPIC_WRITE_COUNT.fetch_add(1, Ordering::Relaxed);
    if n < LAPIC_TRACE_CAP {
        crate::sprintln!("[lapic] W[0x{:03X}].{}B = 0x{:X} (#{}/{})", offset, width, val, n + 1, LAPIC_TRACE_CAP);
    }
    let slot = current_vcpu_slot();
    let aligned = offset & !0x3;
    let shift_bits = (offset & 0x3) * 8;
    let mask_u32 = (low_mask(width) as u32).wrapping_shl(shift_bits);
    let val_u32 = ((val & low_mask(width)) as u32).wrapping_shl(shift_bits);
    let merge = |slot_reg: &AtomicU32| -> u32 {
        let prev = slot_reg.load(Ordering::Relaxed);
        let new = (prev & !mask_u32) | val_u32;
        slot_reg.store(new, Ordering::Relaxed);
        new
    };
    match aligned {
        0x080 => { merge(&TPR[slot]); }
        0x0B0 => {
            // EOI: write-only. Hardware clears the highest-priority ISR
            // bit, which lowers PPR and lets pending lower-priority IRQs
            // through. For a level-triggered IRQ it also broadcasts an EOI
            // to the IO-APIC to clear that GSI's remote-IRR (so the line
            // can re-assert). Previously a no-op — interrupts were never
            // "completed", so PPR stayed at TPR and level lines kept their
            // remote-IRR set forever.
            if let Some(vector) = bitmap_highest(&ISR[slot]) {
                let was_level = isr_level(slot, vector);
                bitmap_clear(&ISR[slot], vector);
                bitmap_clear(&TMR[slot], vector);
                if was_level {
                    super::ioapic::eoi_broadcast(vector);
                }
            }
        }
        0x0D0 => { merge(&LDR[slot]); }
        0x0E0 => { merge(&DFR[slot]); }
        0x0F0 => { merge(&SVR[slot]); }
        0x280 => { ESR[slot].store(0, Ordering::Relaxed); }   // write-to-clear
        0x300 => {
            // ICR low write triggers IPI delivery. Bits 18:19 encode the
            // destination shorthand: 0=use ICR_HI, 1=self, 2=all incl
            // self, 3=all excl self. Single-vCPU veneer treats shorthand
            // 1/2 (self / all incl self) as a self-IPI and stages the
            // vector so the inject layer hands it to event_inj. Other
            // destinations are dropped — no other vCPU exists yet.
            let new = merge(&ICR_LO[slot]);
            ICR_LO[slot].store(new & !(1u32 << 12), Ordering::Relaxed);
            let shorthand = (new >> 18) & 0x3;
            let delivery = (new >> 8) & 0x7;
            let vector = new & 0xFF;
            crate::sprintln!(
                "[icr] val=0x{:X} vec=0x{:X} delivery={} shorthand={}",
                new, vector, delivery, shorthand
            );
            // Delivery mode (ICR bits 10:8): 0=Fixed, 4=NMI, 5=INIT,
            // 6=Startup(SIPI). Only "self" / "all incl self" shorthands
            // target this lone vCPU; other destinations have no recipient.
            let targets_self = shorthand == 0b01 || shorthand == 0b10;
            match delivery {
                0b000 | 0b001 => {
                    // Fixed / lowest-priority — ordinary vectored IPI.
                    if targets_self && vector >= 16 {
                        PENDING_IPI[slot].store(vector, Ordering::Relaxed);
                    }
                }
                0b100 => {
                    // NMI — no vector. Deliver as a real NMI to self; a
                    // broadcast NMI also reaches self on "all incl self".
                    if targets_self {
                        PENDING_NMI[slot].store(1, Ordering::Relaxed);
                    }
                }
                0b101 | 0b110 => {
                    // INIT / SIPI — SMP startup sequencing. With a single
                    // vCPU there is no AP to reset or start, so safely
                    // ignore (matches a uniprocessor real machine where
                    // these target only other CPUs). Logged above.
                }
                _ => {
                    // SMI (0b010) / reserved — accept silently; no model.
                }
            }
        }
        0x310 => { merge(&ICR_HI[slot]); }
        0x320 => {
            let v = merge(&LVT_TIMER[slot]);
            let t = TIMER_TRACE.fetch_add(1, Ordering::Relaxed);
            if t < TIMER_TRACE_CAP { crate::sprintln!("[ltmr] W LVT=0x{:X} tsc=0x{:X}", v, host_rdtsc()); }
        }
        0x330 => { merge(&LVT_THERMAL[slot]); }
        0x340 => { merge(&LVT_PERF[slot]); }
        0x350 => { merge(&LVT_LINT0[slot]); }
        0x360 => { merge(&LVT_LINT1[slot]); }
        0x370 => { merge(&LVT_ERROR[slot]); }
        0x380 => {
            let new = merge(&TIMER_INIT_COUNT[slot]);
            // Snapshot clock base — Current Count counts down from now.
            TIMER_BASE_TSC[slot].store(crate::clock::now(), Ordering::Relaxed);
            let t = TIMER_TRACE.fetch_add(1, Ordering::Relaxed);
            if t < TIMER_TRACE_CAP { crate::sprintln!("[ltmr] W ICR=0x{:X} tsc=0x{:X}", new, host_rdtsc()); }
        }
        0x390 => {} // Current Count is RO
        0x3E0 => {
            let v = merge(&TIMER_DIVCFG[slot]);
            let t = TIMER_TRACE.fetch_add(1, Ordering::Relaxed);
            if t < TIMER_TRACE_CAP { crate::sprintln!("[ltmr] W DCR=0x{:X} div={} tsc=0x{:X}", v, timer_divisor(v), host_rdtsc()); }
        }
        _ => {}
    }
}
