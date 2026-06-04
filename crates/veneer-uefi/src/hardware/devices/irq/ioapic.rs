//! IO APIC MMIO emulator — Intel ICH-style with 24 redirection entries.
//!
//! Base 0xFEC00000, 4 KiB trapped. The IO APIC presents an indirect
//! register file at this address:
//!
//!   0x00 IOREGSEL  (RW) — 8-bit index of the register accessed via IOWIN
//!   0x10 IOWIN     (RW) — reads/writes the IOREGSEL-selected register
//!
//! Selected registers:
//!   0x00 IOAPICID  — bits 24..27 = APIC ID
//!   0x01 IOAPICVER — bits 0..7 version (0x20), bits 16..23 max redir = 23
//!   0x02 IOAPICARB — bits 24..27 arbitration ID
//!   0x10..0x3F — 24 × redirection entries (low/high pair, 8 bytes each)
//!
//! Each redirection entry (64-bit):
//!   bits 0-7   vector
//!   bits 8-10  delivery mode (0=Fixed, 1=LowestPrio, 2=SMI, 4=NMI, 5=INIT, 7=ExtINT)
//!   bit 11     destination mode (0=physical, 1=logical)
//!   bit 12     delivery status (RO)
//!   bit 13     polarity (0=high active, 1=low active)
//!   bit 14     remote IRR (RO, for level-triggered)
//!   bit 15     trigger mode (0=edge, 1=level)
//!   bit 16     mask (1=disabled)
//!   bits 56-63 destination APIC ID (physical) or logical mask
//!
//! At reset all entries are masked (bit 16 = 1). The OS clears the mask
//! per-IRQ as drivers register handlers. We accept all writes; no
//! actual interrupt delivery is performed.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const IOAPIC_BASE: u64 = 0xFEC0_0000;
pub const IOAPIC_SIZE: u64 = 0x0000_1000;

#[inline]
pub fn covers(gpa: u64) -> bool {
    gpa >= IOAPIC_BASE && gpa < IOAPIC_BASE + IOAPIC_SIZE
}

const N_REDIR_ENTRIES: usize = 24;
const IOAPICID_DEFAULT: u32 = 0x0100_0000;     // APIC ID 1 in bits 24..27
const IOAPICVER_DEFAULT: u32 = 0x0017_0020;    // ver=0x20, max-redir=23

static IOREGSEL: AtomicU32 = AtomicU32::new(0);
static IOAPICID: AtomicU32 = AtomicU32::new(IOAPICID_DEFAULT);
static IOAPICARB: AtomicU32 = AtomicU32::new(IOAPICID_DEFAULT);

#[allow(clippy::declare_interior_mutable_const)]
const REDIR_MASKED: AtomicU64 = AtomicU64::new(1u64 << 16);
static REDIR: [AtomicU64; N_REDIR_ENTRIES] = [REDIR_MASKED; N_REDIR_ENTRIES];

/// Redirection-entry bit positions we act on.
const RTE_REMOTE_IRR: u64 = 1 << 14; // RO to the guest; HW-managed
const RTE_TRIGGER_LEVEL: u64 = 1 << 15; // 1 = level-triggered
const RTE_MASK: u64 = 1 << 16;

/// Resolve a GSI to its programmed (vector, masked) pair from the
/// redirection table. Used by the injection layer to deliver a device /
/// timer IRQ with whatever vector the guest assigned. Returns None when
/// the GSI is out of range. `masked` reflects bit 16; an unmasked entry
/// with vector < 16 is still "not deliverable" and the caller skips it.
pub fn redirection(gsi: usize) -> Option<(u8, bool)> {
    if gsi >= N_REDIR_ENTRIES {
        return None;
    }
    let v = REDIR[gsi].load(Ordering::Relaxed);
    let vector = (v & 0xFF) as u8;
    let masked = v & RTE_MASK != 0;
    Some((vector, masked))
}

/// Raw 64-bit redirection-table entry for `gsi` (diagnostics / interrupt-remap
/// decode — the remappable format hides the vector in an IR-table index, so the
/// caller needs the full RTE not just the legacy (vector,masked) view).
pub fn raw_rte(gsi: usize) -> u64 {
    if gsi >= N_REDIR_ENTRIES {
        return 0;
    }
    REDIR[gsi].load(Ordering::Relaxed)
}

/// Is GSI `gsi` programmed level-triggered (RTE bit 15)?
pub fn is_level(gsi: usize) -> bool {
    if gsi >= N_REDIR_ENTRIES {
        return false;
    }
    REDIR[gsi].load(Ordering::Relaxed) & RTE_TRIGGER_LEVEL != 0
}

/// Mark a level-triggered GSI's interrupt as accepted by the LAPIC: set
/// remote-IRR (RTE bit 14). Hardware holds this until an EOI for the
/// matching vector arrives, which gates re-assertion of the same line.
/// Edge-triggered entries have no remote-IRR, so this is a no-op for them.
pub fn set_remote_irr(gsi: usize) {
    if gsi >= N_REDIR_ENTRIES {
        return;
    }
    let v = REDIR[gsi].load(Ordering::Relaxed);
    if v & RTE_TRIGGER_LEVEL != 0 {
        REDIR[gsi].fetch_or(RTE_REMOTE_IRR, Ordering::Relaxed);
    }
}

/// EOI broadcast (from a LAPIC EOI of a level IRQ, or a write to the
/// IO-APIC EOI register at 0x40): clear remote-IRR on every level-
/// triggered entry whose vector matches `vector`. Real IO-APICs match by
/// vector, not GSI, so a shared level vector clears all its lines.
pub fn eoi_broadcast(vector: u8) {
    for gsi in 0..N_REDIR_ENTRIES {
        let v = REDIR[gsi].load(Ordering::Relaxed);
        if v & RTE_TRIGGER_LEVEL != 0
            && v & RTE_REMOTE_IRR != 0
            && (v & 0xFF) as u8 == vector
        {
            REDIR[gsi].fetch_and(!RTE_REMOTE_IRR, Ordering::Relaxed);
        }
    }
}

/// Diagnostic: dump redirection entries 0..16 (vector + mask) so we can
/// see which IRQ lines the guest has actually programmed and unmasked.
pub fn debug_dump() {
    for gsi in 0..16usize {
        let v = REDIR[gsi].load(Ordering::Relaxed);
        let vector = (v & 0xFF) as u8;
        let masked = v & (1 << 16) != 0;
        if vector != 0 || !masked {
            crate::sprintln!(
                "[ioapic] RTE[{}] vector=0x{:02X} masked={} raw=0x{:X}",
                gsi, vector, masked, v
            );
        }
    }
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

/// Read whichever register is indexed by IOREGSEL.
fn read_selected() -> u32 {
    let idx = IOREGSEL.load(Ordering::Relaxed) & 0xFF;
    match idx {
        0x00 => IOAPICID.load(Ordering::Relaxed),
        0x01 => IOAPICVER_DEFAULT,
        0x02 => IOAPICARB.load(Ordering::Relaxed),
        n if (0x10..0x10 + (N_REDIR_ENTRIES * 2) as u32).contains(&n) => {
            let entry = ((n - 0x10) / 2) as usize;
            let is_high = (n - 0x10) & 1 == 1;
            let v = REDIR[entry].load(Ordering::Relaxed);
            if is_high { (v >> 32) as u32 } else { v as u32 }
        }
        _ => 0,
    }
}

fn write_selected(val: u32) {
    let idx = IOREGSEL.load(Ordering::Relaxed) & 0xFF;
    match idx {
        0x00 => IOAPICID.store(val & 0x0F00_0000, Ordering::Relaxed),
        0x01 => {} // IOAPICVER is RO
        0x02 => {} // IOAPICARB is RO (snapshot of IOAPICID)
        n if (0x10..0x10 + (N_REDIR_ENTRIES * 2) as u32).contains(&n) => {
            let entry = ((n - 0x10) / 2) as usize;
            let is_high = (n - 0x10) & 1 == 1;
            let cur = REDIR[entry].load(Ordering::Relaxed);
            let new = if is_high {
                (cur & 0x0000_0000_FFFF_FFFF) | ((val as u64) << 32)
            } else {
                // Low dword: delivery-status (bit 12) and remote-IRR (bit
                // 14) are read-only / hardware-managed. Preserve their
                // current value so a guest RMW of the RTE (e.g. masking an
                // IRQ mid-service) can't accidentally clear remote-IRR and
                // let the level line re-fire before its EOI.
                const RO_LOW: u64 = (1 << 12) | RTE_REMOTE_IRR;
                let high = cur & 0xFFFF_FFFF_0000_0000;
                let guest_low = (val as u64) & !RO_LOW;
                let preserved = cur & RO_LOW;
                high | guest_low | preserved
            };
            REDIR[entry].store(new, Ordering::Relaxed);
        }
        _ => {}
    }
}

fn read_dword(offset: u32) -> u32 {
    match offset {
        0x00 => IOREGSEL.load(Ordering::Relaxed),
        0x10 => read_selected(),
        0x40 => 0,    // EOI register on newer chipsets — silently zero
        _ => 0,
    }
}

static IOAPIC_READ_COUNT: AtomicU32 = AtomicU32::new(0);
static IOAPIC_WRITE_COUNT: AtomicU32 = AtomicU32::new(0);
const IOAPIC_TRACE_CAP: u32 = 48;

pub fn read_register_width(offset: u32, width: u8) -> u64 {
    let aligned = offset & !0x3;
    let shift_bits = (offset & 0x3) * 8;
    let dword = read_dword(aligned);
    let val = ((dword as u64) >> shift_bits) & low_mask(width);
    let n = IOAPIC_READ_COUNT.fetch_add(1, Ordering::Relaxed);
    if n < IOAPIC_TRACE_CAP {
        crate::sprintln!("[ioapic] R[0x{:02X}].{}B = 0x{:X} (#{}/{})", offset, width, val, n + 1, IOAPIC_TRACE_CAP);
    }
    val
}

pub fn write_register_width(offset: u32, val: u64, width: u8) {
    let n = IOAPIC_WRITE_COUNT.fetch_add(1, Ordering::Relaxed);
    if n < IOAPIC_TRACE_CAP {
        crate::sprintln!("[ioapic] W[0x{:02X}].{}B = 0x{:X} (#{}/{})", offset, width, val, n + 1, IOAPIC_TRACE_CAP);
    }
    let aligned = offset & !0x3;
    let shift_bits = (offset & 0x3) * 8;
    let mask_u32 = (low_mask(width) as u32).wrapping_shl(shift_bits);
    let val_u32 = ((val & low_mask(width)) as u32).wrapping_shl(shift_bits);
    match aligned {
        0x00 => {
            let prev = IOREGSEL.load(Ordering::Relaxed);
            IOREGSEL.store((prev & !mask_u32) | val_u32, Ordering::Relaxed);
        }
        0x10 => write_selected(val_u32),
        0x40 => {
            // IO-APIC EOI register (ICH9+): the OS writes the vector here
            // to deassert a level-triggered line's remote-IRR directly,
            // bypassing the LAPIC-EOI→IO-APIC broadcast. Match by vector.
            eoi_broadcast((val_u32 & 0xFF) as u8);
        }
        _ => {}
    }
}
