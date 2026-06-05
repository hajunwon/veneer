//! AMD-Vi (AMD I/O Virtualization Technology) IOMMU — minimal emulation.
//!
//! Why this exists: when the guest enables x2APIC, the Windows HAL marks
//! interrupt remapping as *required* and `HalpIommuInitSystem` bugchecks 0x5C
//! (HAL_INITIALIZATION_FAILED, STATUS_NOT_SUPPORTED) if it can't find a working
//! IOMMU. We are not building a functional IOMMU — there is one vCPU and veneer
//! controls interrupt injection directly, so nothing needs real DMA/IR
//! remapping. The goal is only to present an MMIO + ACPI (IVRS/IVHD) surface
//! that makes the HAL's AMD-Vi init path return success.
//!
//! After the IVRS table alone, the HAL discovers the IOMMU (0x5C cleared) and
//! then drives interrupt remapping through the command buffer:
//!   HalpInterruptRemap → HsaInvalidateRemappingTableEntry → HsaIommuSendCommand
//! which writes a command into the in-memory ring and rings the doorbell (a
//! write to the Command Buffer Tail Pointer, MMIO 0x2008), then spins for
//! completion. So we emulate the command buffer: on a tail write we drain the
//! ring (`command::process_doorbell`) and advance the head so the HAL sees the
//! commands consumed.
//!
//! AMD-Vi MMIO register offsets are spec-fixed (AMD IOMMU spec, "MMIO Registers").

mod command;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// IOMMU MMIO base (guest-physical). Must sit INSIDE the wholesale-trapped MMIO
/// hole [0xFEC00000, 0xFEF00000) (see ovmf-guest hi-RAM mapping) so accesses are
/// not-present in NPT and fault into the NPF dispatcher — an address just below
/// the hole (e.g. 0xFEB80000) is RAM-backed and silently swallows MMIO. 0xFED80000
/// is free between HPET (0xFED00000) and the LAPIC (0xFEE00000). Published to the
/// guest through the IVRS/IVHD "IOMMU Base" field.
pub const IOMMU_MMIO_BASE: u64 = 0xFED8_0000;
/// MMIO window length: control registers at 0x00.. and the head/tail/status
/// bank at 0x2000; 0x8000 covers both with margin.
pub const IOMMU_MMIO_SIZE: u64 = 0x8000;

/// The IOMMU's own PCI Bus/Device/Function, published in the IVHD DeviceID.
/// 00:00.2 is the canonical AMD on-die IOMMU location.
pub const IOMMU_PCI_BDF: u16 = 0x0002;
/// PCI capability block offset published in the IVHD.
pub const IOMMU_CAP_OFFSET: u16 = 0x40;

/// Extended Feature Register (MMIO 0x30), mirrored into the IVHD "EFR
/// Register Image" so the live register and the ACPI table always agree.
/// The value is the active profile's on-die IOMMU EFR (a real per-die
/// value, e.g. Zen4 Raphael) via `efr()`. The fallback is used only before
/// a profile is loaded.
const IOMMU_EFR_FALLBACK: u64 = 0x2465_77ef_a225_4afa; // verified Zen4 Raphael

/// Single source for both this MMIO register and the ACPI IVRS EFR image.
pub fn efr() -> u64 {
    // Honest: a loaded profile's EFR is authoritative even if 0 (an AMD
    // profile with 0 is a profile bug that coherence::validate flags — we
    // surface it rather than mask it with a fabricated value). The fallback
    // applies only before any profile is active.
    match crate::hardware::identity::active::PROFILE.get() {
        Some(p) => unsafe { core::ptr::addr_of!(p.hardware.cpu.spec.iommu.efr).read_unaligned() },
        None => IOMMU_EFR_FALLBACK,
    }
}

/// XTSup (EFR bit 2): does the active die's IOMMU support x2APIC interrupt
/// remapping? The single authority for the bit position (the profile model
/// mirrors the same test). Desktop chiplet dies clear it; APU/server dies set
/// it. Drives the guest APIC mode via `irq::apic_mode::mode`.
pub fn xtsup() -> bool {
    efr() & (1 << 2) != 0
}

// ── MMIO register backing store (single vCPU: accesses are serialized in the
// VMEXIT handler, atomics are just for the static-mut-free pattern) ──
static DEV_TAB_BASE: AtomicU64 = AtomicU64::new(0);
static CMD_BUF_BASE: AtomicU64 = AtomicU64::new(0);
static EVT_LOG_BASE: AtomicU64 = AtomicU64::new(0);
static CONTROL: AtomicU64 = AtomicU64::new(0);
static EXCL_BASE: AtomicU64 = AtomicU64::new(0);
static EXCL_LIMIT: AtomicU64 = AtomicU64::new(0);
static CMD_HEAD: AtomicU64 = AtomicU64::new(0);
static CMD_TAIL: AtomicU64 = AtomicU64::new(0);
static EVT_HEAD: AtomicU64 = AtomicU64::new(0);
static EVT_TAIL: AtomicU64 = AtomicU64::new(0);
static STATUS: AtomicU64 = AtomicU64::new(0);

// Register offsets (spec-fixed).
const REG_DEV_TAB_BASE: u32 = 0x00;
const REG_CMD_BUF_BASE: u32 = 0x08;
const REG_EVT_LOG_BASE: u32 = 0x10;
const REG_CONTROL: u32 = 0x18;
const REG_EXCL_BASE: u32 = 0x20;
const REG_EXCL_LIMIT: u32 = 0x28;
const REG_EFR: u32 = 0x30;
const REG_CMD_HEAD: u32 = 0x2000;
const REG_CMD_TAIL: u32 = 0x2008;
const REG_EVT_HEAD: u32 = 0x2010;
const REG_EVT_TAIL: u32 = 0x2018;
const REG_STATUS: u32 = 0x2020;

#[inline]
pub fn covers(gpa: u64) -> bool {
    (IOMMU_MMIO_BASE..IOMMU_MMIO_BASE + IOMMU_MMIO_SIZE).contains(&gpa)
}

/// Guest-programmed Device Table base (GPA, low bits hold the table length).
/// Exposed for diagnostics / the interrupt-remapping decode that walks the DTE.
pub fn dev_tab_base() -> u64 {
    DEV_TAB_BASE.load(Ordering::Relaxed)
}

/// True once the guest has enabled the IOMMU (Control.IommuEn) with a device
/// table — i.e. interrupts are being remapped and an IO-APIC/MSI "vector" field
/// is really an IR-table index, not a literal vector.
pub fn ir_active() -> bool {
    CONTROL.load(Ordering::Relaxed) & 1 != 0 && DEV_TAB_BASE.load(Ordering::Relaxed) != 0
}

/// Decode a remappable interrupt to its real vector. `index` is the IR-table
/// index carried in the source RTE/MSI "vector" field. Walks the AMD-Vi tables
/// in guest memory: Device Table Entry → Interrupt Remapping Table → IRTE.
///
/// IRTE layout (128-bit, confirmed against the live tables): low qword bit0 =
/// RemapEn; the delivered vector is bits[71:64] (high qword bits[7:0]). All
/// device-table entries point at the same IR table under our all-devices IVHD,
/// so DTE[0]'s Interrupt Table Root Pointer is authoritative. Returns None when
/// IR isn't active or the IRTE isn't a valid remap entry.
pub fn remap_vector(index: u8) -> Option<u8> {
    use crate::introspect::mem;
    if !ir_active() {
        return None;
    }
    let dtb = DEV_TAB_BASE.load(Ordering::Relaxed) & 0x000F_FFFF_FFFF_F000;
    if dtb == 0 {
        return None;
    }
    let mut dte = [0u8; 32];
    if !mem::read_phys(dtb, &mut dte) {
        return None;
    }
    // DTE qword2 (bytes 16..24): Interrupt Table Root Pointer in bits[51:6].
    let q2 = u64::from_le_bytes(dte[16..24].try_into().unwrap());
    let irt = q2 & 0x000F_FFFF_FFFF_FFC0;
    if irt == 0 {
        return None;
    }
    let mut irte = [0u8; 16];
    if !mem::read_phys(irt + (index as u64) * 16, &mut irte) {
        return None;
    }
    let lo = u64::from_le_bytes(irte[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(irte[8..16].try_into().unwrap());
    if lo & 1 == 0 {
        return None; // RemapEn clear — not a live remap entry
    }
    Some((hi & 0xFF) as u8)
}

fn reg_for(aligned_off: u32) -> Option<&'static AtomicU64> {
    Some(match aligned_off {
        REG_DEV_TAB_BASE => &DEV_TAB_BASE,
        REG_CMD_BUF_BASE => &CMD_BUF_BASE,
        REG_EVT_LOG_BASE => &EVT_LOG_BASE,
        REG_CONTROL => &CONTROL,
        REG_EXCL_BASE => &EXCL_BASE,
        REG_EXCL_LIMIT => &EXCL_LIMIT,
        REG_CMD_HEAD => &CMD_HEAD,
        REG_CMD_TAIL => &CMD_TAIL,
        REG_EVT_HEAD => &EVT_HEAD,
        REG_EVT_TAIL => &EVT_TAIL,
        REG_STATUS => &STATUS,
        _ => return None,
    })
}

fn reg_read_u64(aligned_off: u32) -> u64 {
    if aligned_off == REG_EFR {
        return efr(); // RO capability register, sourced from the active profile
    }
    reg_for(aligned_off).map(|r| r.load(Ordering::Relaxed)).unwrap_or(0)
}

#[inline]
fn extract(full: u64, byte_off: u32, width: u8) -> u64 {
    let shift = byte_off * 8;
    if width >= 8 { full >> shift } else { (full >> shift) & ((1u64 << (width * 8)) - 1) }
}

#[inline]
fn splice(cur: u64, byte_off: u32, width: u8, val: u64) -> u64 {
    if width >= 8 { return val; }
    let shift = byte_off * 8;
    let mask = ((1u64 << (width * 8)) - 1) << shift;
    (cur & !mask) | ((val << shift) & mask)
}

// Log cap so a polling HAL can't flood the serial log.
static LOG_N: AtomicU32 = AtomicU32::new(0);
const LOG_CAP: u32 = 512;
fn log(rw: &str, off: u32, val: u64, width: u8) {
    if LOG_N.fetch_add(1, Ordering::Relaxed) < LOG_CAP {
        crate::sprintln!("[iommu] {} off={:#06x} val={:#018x} w{}", rw, off, val, width);
    }
}

pub fn read_register_width(off: u32, width: u8) -> u64 {
    let v = extract(reg_read_u64(off & !7), off & 7, width);
    log("R", off, v, width);
    v
}

pub fn write_register_width(off: u32, val: u64, width: u8) {
    log("W", off, val, width);
    let aligned = off & !7;
    if aligned == REG_EFR {
        return; // RO
    }
    if let Some(r) = reg_for(aligned) {
        let merged = splice(r.load(Ordering::Relaxed), off & 7, width, val);
        r.store(merged, Ordering::Relaxed);
    }
    // Writing the Command Buffer Tail Pointer is the doorbell: drain the ring.
    if aligned == REG_CMD_TAIL {
        command::process_doorbell();
    }
}
