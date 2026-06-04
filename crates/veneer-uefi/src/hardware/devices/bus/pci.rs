//! PCI configuration space emulator.
//!
//! Legacy CONFIG_ADDRESS/CONFIG_DATA port pair (`0xCF8`/`0xCFC`):
//!   - OUT to `0xCF8` (32-bit) latches a 32-bit address with the
//!     standard bus/dev/func/reg encoding.
//!   - IN from `0xCFC` (or aliases 0xCFD/E/F for byte/word reads)
//!     returns the configuration register of the targeted device.
//!
//! Without an intercept the guest's PCI scan would walk *VMware's*
//! virtual PCI bus (VMXNET3, PVSCSI, VMCI, …) — every entry of which
//! self-identifies as VMware. We synthesise replies here so the guest
//! sees the device list veneer wants it to see.
//!
//! For B-4a the emulator returns "no device" (`Vendor=0xFFFF`) at every
//! address. NIC / Disk specifics arrive in B-4b/c.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::hardware::devices::storage::{ahci, nvme};
use crate::hardware::devices::acpi_pm;
use super::{nic, vga, xhci};
use crate::hardware::identity::active;

// Each synthetic device's PCI device:vendor ID comes from the active
// machine profile so different veneer instances present different (yet
// internally consistent) hardware. The fallback is the legacy AMD X670E
// identity used before any profile is loaded. Read the packed field
// through a raw pointer (the profile is `#[repr(C, packed)]`).
#[inline]
fn profile_id(read: impl FnOnce(*const crate::hardware::identity::profile::HardwareProfile) -> u32, fallback: u32) -> u32 {
    match active::PROFILE.get() {
        Some(p) => {
            let v = read(core::ptr::addr_of!(p.hardware));
            if v != 0 { v } else { fallback }
        }
        None => fallback,
    }
}
fn pid_host_bridge() -> u32 { profile_id(|h| unsafe { core::ptr::addr_of!((*h).board.host_bridge_id).read_unaligned() }, 0x29C0_8086) }
fn pid_nic() -> u32   { profile_id(|h| unsafe { core::ptr::addr_of!((*h).network.pci_id).read_unaligned() }, 0x15F3_8086) }
fn pid_nvme() -> u32  { profile_id(|h| unsafe { core::ptr::addr_of!((*h).disk.pci_id).read_unaligned() }, 0xA80A_144D) }
fn pid_lpc() -> u32   { profile_id(|h| unsafe { core::ptr::addr_of!((*h).board.lpc_id).read_unaligned() }, 0x790E_1022) }
fn pid_sata() -> u32  { profile_id(|h| unsafe { core::ptr::addr_of!((*h).board.sata_id).read_unaligned() }, 0x7901_1022) }
fn pid_smbus() -> u32 { profile_id(|h| unsafe { core::ptr::addr_of!((*h).board.smbus_id).read_unaligned() }, 0x790B_1022) }
fn pid_hda() -> u32   { profile_id(|h| unsafe { core::ptr::addr_of!((*h).audio.pci_id).read_unaligned() }, 0x1457_1022) }
fn pid_xhci() -> u32  { profile_id(|h| unsafe { core::ptr::addr_of!((*h).board.xhci_id).read_unaligned() }, 0x149C_1022) }
fn pid_gpu() -> u32   { profile_id(|h| unsafe { core::ptr::addr_of!((*h).gpu.pci_id).read_unaligned() }, 0x164E_1002) }

pub const CONFIG_ADDRESS_PORT: u16 = 0xCF8;
pub const CONFIG_DATA_PORT: u16 = 0xCFC;

#[inline]
pub fn is_config_data_port(port: u16) -> bool {
    (CONFIG_DATA_PORT..CONFIG_DATA_PORT + 4).contains(&port)
}

#[inline]
pub fn is_config_address_port(port: u16) -> bool {
    (CONFIG_ADDRESS_PORT..CONFIG_ADDRESS_PORT + 4).contains(&port)
}

/// PCIe ECAM (Enhanced Configuration Access Mechanism) window. ACPI
/// MCFG advertises `acpi::PCIE_MCFG_BASE = 0xE0000000` as the base, and
/// each PCI function occupies 4 KiB inside this region:
///
///   addr = ECAM_BASE | (bus << 20) | (dev << 15) | (func << 12) | reg
///
/// Modern Linux / Windows kernels prefer ECAM over the legacy CF8/CFC
/// port pair. We model 1 bus (0..1) = 4 KiB × 8 funcs × 32 devs × 1 bus
/// = 1 MiB window; the rest of the 256 MiB advertised in MCFG just
/// reads as no-device.
pub const ECAM_BASE: u64 = crate::hardware::acpi::PCIE_MCFG_BASE;
pub const ECAM_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB (single segment, buses 0..255)

#[inline]
pub fn covers_ecam(gpa: u64) -> bool {
    gpa >= ECAM_BASE && gpa < ECAM_BASE + ECAM_SIZE
}

/// Decode an ECAM physical address into (bus, dev, func, reg).
#[inline]
fn ecam_decode(gpa: u64) -> (u8, u8, u8, u16) {
    let off = gpa - ECAM_BASE;
    let bus = ((off >> 20) & 0xFF) as u8;
    let dev = ((off >> 15) & 0x1F) as u8;
    let func = ((off >> 12) & 0x07) as u8;
    let reg = (off & 0xFFF) as u16;
    (bus, dev, func, reg)
}

/// MMIO read at an ECAM-mapped physical address. Returns the same dword
/// the legacy port pair would yield for the same (bus, dev, func, reg)
/// — same backing per-device dispatch — masked to `width`.
pub fn ecam_read(gpa: u64, width: u8) -> u64 {
    let (bus, dev, func, reg) = ecam_decode(gpa);
    // ECAM uses 12-bit register offset (extended config space 256..4095);
    // our per-device handlers only define values in the standard 0..256
    // window. Anything above 0xFF reads as zero, matching the silicon
    // behaviour for unimplemented Extended Capabilities.
    if reg >= 0x100 {
        return 0;
    }
    let dword = config_read(bus, dev, func, (reg & 0xFC) as u8);
    let byte_shift = (reg & 0x3) as u32 * 8;
    let shifted = (dword as u64) >> byte_shift;
    let mask = match width {
        1 => 0xFFu64,
        2 => 0xFFFFu64,
        4 => 0xFFFF_FFFFu64,
        _ => u64::MAX,
    };
    shifted & mask
}

/// ECAM writes — config space writes from the guest. The synthetic
/// device tree is otherwise read-only (BAR / command-register writes the
/// guest issues during enumeration don't need to persist because veneer
/// never lets DMA reach those BARs), but the ICH9 PM registers must stick
/// so OVMF's AcpiTimerLib reads back the base it just programmed.
pub fn ecam_write(gpa: u64, val: u64, width: u8) {
    let (bus, dev, func, reg) = ecam_decode(gpa);
    if reg >= 0x100 {
        return;
    }
    config_write(bus, dev, func, reg as u8, val as u32, width);
}

/// Last value written to CONFIG_ADDRESS (`0xCF8`). PCI access pattern
/// is "write address, then read/write data" so the data-port handler
/// has to consult what the address-port handler stashed last.
static LATCHED_ADDRESS: AtomicU32 = AtomicU32::new(0);

/// Decode CONFIG_ADDRESS into (bus, device, function, register) where
/// register is a byte offset (multiples of 4 only — we ignore the low
/// 2 bits).
#[inline]
pub fn decode(addr: u32) -> (u8, u8, u8, u8) {
    let bus = ((addr >> 16) & 0xFF) as u8;
    let dev = ((addr >> 11) & 0x1F) as u8;
    let func = ((addr >> 8) & 0x07) as u8;
    let reg = (addr & 0xFC) as u8;
    (bus, dev, func, reg)
}

#[inline]
pub fn enabled(addr: u32) -> bool {
    (addr & 0x8000_0000) != 0
}

pub fn store_address(value: u32) {
    LATCHED_ADDRESS.store(value, Ordering::Relaxed);
}

/// IN from CONFIG_ADDRESS (`0xCF8`..`0xCFB`). CONFIG_ADDRESS is a plain
/// 32-bit register: a read returns the last value written. Linux's
/// `pci_check_type1` writes 0x80000000 then reads it back to decide
/// mechanism #1 is present; without this it falls through to the
/// "no device" path, reads 0xFFFFFFFF, and gives up on PCI entirely.
pub fn read_address(port: u16, width: u8) -> u64 {
    let addr = LATCHED_ADDRESS.load(Ordering::Relaxed) as u64;
    let byte_off = (port - CONFIG_ADDRESS_PORT) as u32;
    (addr >> (byte_off * 8)) & width_mask(width)
}

/// Synthesise a PCI CONFIG_DATA read. `port` (0xCFC..0xCFF) selects the
/// byte offset within the latched register's dword; sub-dword and
/// unaligned accesses must return the shifted/masked slice — a guest
/// reading the device-ID word at 0xCFE expects bits 31:16, not the whole
/// dword. Getting this wrong makes 16-bit ID probes read the vendor in
/// place of the device and breaks chipset detection.
pub fn read_data(port: u16, width: u8) -> u64 {
    let addr = LATCHED_ADDRESS.load(Ordering::Relaxed);
    let byte_off = (port - CONFIG_DATA_PORT) as u32;
    let mask = width_mask(width);
    if !enabled(addr) {
        return 0xFFFF_FFFF_FFFF_FFFF & mask;
    }
    let (bus, dev, func, reg) = decode(addr);
    // Diagnostic: a guest brute-force PCI scan walks every bus. Log on bus
    // change so a finite 0x00→0xFF sweep (climbing numbers) is distinguishable
    // from a true stuck-on-one-bus hang (no new lines). Cheap: ≤256 lines.
    if SCAN_LAST_BUS.swap(bus as u32, Ordering::Relaxed) != bus as u32 {
        crate::sprintln!("[pci-scan] config read bus=0x{:X} (dev=0x{:X} reg=0x{:X})", bus, dev, reg);
    }
    let dword = config_read(bus, dev, func, reg) as u64;
    (dword >> (byte_off * 8)) & mask
}

/// Last bus number seen by a CONFIG_DATA read — drives the [pci-scan] progress
/// log so a brute-force enumeration's bus sweep is visible.
static SCAN_LAST_BUS: AtomicU32 = AtomicU32::new(0xFFFF_FFFF);

#[inline]
fn width_mask(width: u8) -> u64 {
    match width {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        _ => u64::MAX,
    }
}

/// Synthesise a CONFIG_DATA write (`0xCFC`..`0xCFF`). `port` selects the
/// byte offset within the latched register; only the ICH9 PM registers
/// retain state, everything else is dropped.
pub fn write_data(port: u16, val: u32, width: u8) {
    let addr = LATCHED_ADDRESS.load(Ordering::Relaxed);
    if !enabled(addr) {
        return;
    }
    let (bus, dev, func, reg) = decode(addr);
    let byte_off = (port - CONFIG_DATA_PORT) as u8;
    config_write(bus, dev, func, reg + byte_off, val, width);
}

/// Per-device config-space write dispatch. Only two register groups are
/// stateful: the ICH9 LPC PM registers (backed by `acpi_pm`) and the BARs
/// (backed by the sizing-aware `BAR_TABLE`). Everything else is dropped.
fn config_write(bus: u8, dev: u8, func: u8, reg: u8, val: u32, width: u8) {
    let n = CFG_WRITE_TRACE.fetch_add(1, Ordering::Relaxed);
    if n < CFG_WRITE_TRACE_CAP {
        crate::sprintln!(
            "[pciw] {:02X}:{:02X}.{} reg=0x{:02X} val=0x{:X} w={} (#{}/{})",
            bus, dev, func, reg, val, width, n + 1, CFG_WRITE_TRACE_CAP
        );
    }
    // Writable standard-header registers (Command / Interrupt Line) must
    // round-trip on read regardless of device, or a guest RMW re-loops.
    store_cfg(bus, dev, func, reg, val, width);
    if (bus, dev, func) == (0, 0x1F, 0) && acpi_pm::owns_reg(reg) {
        acpi_pm::config_write(reg, val, width);
        return;
    }
    // SATA AHCI (dev 4) MSI capability — guest programs message addr/data
    // and the enable bit; persist so the AHCI emulator can raise it.
    if (bus, dev, func) == (0, 4, 0) && (0x40..0x50).contains(&reg) {
        sata_msi_write(reg - 0x40, val, width);
        return;
    }
    // NVMe (dev 2) MSI capability — same: persist the guest's message so the
    // NVMe emulator can raise completions through it.
    if (bus, dev, func) == (0, 2, 0) && (0x40..0x50).contains(&reg) {
        nvme_msi_write(reg - 0x40, val, width);
        return;
    }
    // BAR writes go through the sizing table. PciBus probes a BAR with a
    // full-dword all-ones write then reads back the length mask, so only
    // 32-bit writes participate; sub-dword BAR writes never occur during
    // enumeration.
    if bus == 0 && func == 0 && width == 4 {
        if let Some(i) = bar_index(dev, reg & 0xFC) {
            bar_write(i, val);
        }
    }
}

static CFG_WRITE_TRACE: AtomicU32 = AtomicU32::new(0);
const CFG_WRITE_TRACE_CAP: u32 = 1500;

// NVMe (dev 2) capability-read trace — per-register last value (reg>>2 bucket,
// covers 0x00..0xBF). Diagnostic only.
#[allow(clippy::declare_interior_mutable_const)]
const CFG_RD_ZERO: AtomicU32 = AtomicU32::new(0);
static CFG_RD_LAST: [AtomicU32; 48] = [CFG_RD_ZERO; 48];

// ───── BAR sizing model ──────────────────────────────────────────────
//
// A PCI BAR is probed by writing all-ones and reading back the size mask
// `~(size-1) | type-bits`; the assigned base is then written and read
// back verbatim. A BAR that merely echoes a fixed address reports that
// address *as its size*, which is how the NIC/SATA/xHCI/GPU BARs each
// claimed hundreds of MiB and overflowed the firmware's 32-bit MMIO
// window (PciHostBridge: "Out of Resources" → no BAR got assigned → the
// NVMe driver never bound). Model every BAR as a register whose readback
// is the length mask while a size probe is in flight, the aligned base
// otherwise.

// Which device emulator (if any) a BAR's MMIO traps to. The base is
// dynamic — on the BAR-assignment write we push the firmware-chosen
// address into the emulator so the NPF router traps the live location,
// not a stale fixed address.
#[derive(Clone, Copy)]
enum BarTrap {
    None,
    Nvme,
    Nic,
    Xhci,
    Ahci,
    VgaFb,   // std-vga framebuffer (BAR0): NPT-map to the host buffer on assign
    VgaMmio, // std-vga DISPI/VGA MMIO (BAR2): NPF-trap window follows the assign
}

struct BarDef {
    dev: u8,
    offset: u8,     // config offset (0x10/0x14/.../0x24)
    size: u32,      // power-of-two byte length
    type_bits: u32, // BAR low bits: [0]=IO, [2:1]=type, [3]=prefetch
    trap: BarTrap,  // device emulator this BAR's MMIO routes to
}

// Realistic on-silicon BAR lengths for the synthetic device tree. All bases
// are firmware-assigned; the trap field tells bar_write which emulator to
// point at the address OVMF chose (the firmware records its own assignment
// and ignores any forced readback, so the bases must follow it dynamically).
const BAR_TABLE: &[BarDef] = &[
    BarDef { dev: 1, offset: 0x10, size: 0x0002_0000, type_bits: 0,    trap: BarTrap::Nic     }, // NIC 128 KiB
    BarDef { dev: 2, offset: 0x10, size: 0x0000_4000, type_bits: 0,    trap: BarTrap::Nvme    }, // NVMe 16 KiB
    BarDef { dev: 4, offset: 0x24, size: 0x0000_2000, type_bits: 0,    trap: BarTrap::Ahci    }, // SATA AHCI 8 KiB (BAR5)
    BarDef { dev: 6, offset: 0x10, size: 0x0000_4000, type_bits: 0,    trap: BarTrap::None    }, // HDA 16 KiB
    BarDef { dev: 7, offset: 0x10, size: 0x0001_0000, type_bits: 0,    trap: BarTrap::Xhci    }, // xHCI 64 KiB
    BarDef { dev: 8, offset: 0x10, size: vga::FB_SIZE as u32,   type_bits: 0x00, trap: BarTrap::VgaFb   }, // std-vga framebuffer (32-bit mem; non-prefetch keeps it in the _CRS window)
    BarDef { dev: 8, offset: 0x18, size: vga::MMIO_SIZE as u32, type_bits: 0,    trap: BarTrap::VgaMmio }, // std-vga DISPI/VGA MMIO
];

// Per-BAR backing register, indexed in lockstep with BAR_TABLE. Starts at
// 0 (BAR not yet assigned by the firmware).
const BAR_COUNT: usize = 7;
static BAR_VALUE: [AtomicU32; BAR_COUNT] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];

fn bar_index(dev: u8, offset: u8) -> Option<usize> {
    BAR_TABLE.iter().position(|b| b.dev == dev && b.offset == offset)
}

// ───── SATA AHCI MSI capability (dev 4) ──────────────────────────────
//
// The AHCI controller needs a working completion interrupt. INTx can't be
// routed (no ACPI _PRT in the OVMF-guest path), so we expose a single-
// vector MSI capability and let the guest program the message. Control
// starts 64-bit-capable, 1 vector, disabled; addr/data are guest-written.
static SATA_MSI_CTRL: AtomicU32 = AtomicU32::new(0x0080); // bit7 = 64-bit capable
static SATA_MSI_ADDR_LO: AtomicU32 = AtomicU32::new(0);
static SATA_MSI_ADDR_HI: AtomicU32 = AtomicU32::new(0);
static SATA_MSI_DATA: AtomicU32 = AtomicU32::new(0);

fn sata_msi_read(reg: u8) -> u32 {
    match reg {
        0x00 => 0x05 | (SATA_MSI_CTRL.load(Ordering::Relaxed) << 16), // cap_id | next=0 | control
        0x04 => SATA_MSI_ADDR_LO.load(Ordering::Relaxed),
        0x08 => SATA_MSI_ADDR_HI.load(Ordering::Relaxed),
        0x0C => SATA_MSI_DATA.load(Ordering::Relaxed),
        _ => 0,
    }
}

fn sata_msi_write(reg: u8, val: u32, _width: u8) {
    // Linux programs addr/data as 32-bit dwords but flips the MSI-enable
    // bit with a *16-bit* write to the Message Control word at cap+0x02 —
    // dropping sub-dword writes left MSI permanently disabled, so the AHCI
    // completion IRQ never armed and ATAPI IDENTIFY timed out.
    match reg {
        0x00 => SATA_MSI_CTRL.store((val >> 16) & 0xFFFF, Ordering::Relaxed), // full dword: control in hi half
        0x02 => SATA_MSI_CTRL.store(val & 0xFFFF, Ordering::Relaxed),          // 16-bit control write
        0x04 => SATA_MSI_ADDR_LO.store(val, Ordering::Relaxed),
        0x08 => SATA_MSI_ADDR_HI.store(val, Ordering::Relaxed),
        0x0C => SATA_MSI_DATA.store(val & 0xFFFF, Ordering::Relaxed),
        _ => {}
    }
    let ctrl = SATA_MSI_CTRL.load(Ordering::Relaxed);
    let enabled = ctrl & 0x1 != 0;
    // With IOMMU interrupt remapping active (x2APIC path) the MSI data field is
    // an IR-table index, not the literal vector — resolve the real vector through
    // the IRTE (same DTE→IRT→IRTE walk the IO-APIC clock uses). Without this the
    // index (a small number) parks as sub-16 and the AHCI completion IRQ never
    // fires, so Setup stalls waiting on disk I/O.
    let data = SATA_MSI_DATA.load(Ordering::Relaxed) & 0xFF;
    let ir = crate::hardware::devices::iommu::ir_active();
    let vector = if ir {
        crate::hardware::devices::iommu::remap_vector(data as u8).map(|v| v as u32).unwrap_or(0)
    } else {
        data
    };
    if enabled {
        crate::sprintln!(
            "[ahci-msi] en={} ir={} data=0x{:X} addr=0x{:X}_{:08X} -> vec=0x{:X}",
            enabled, ir, data,
            SATA_MSI_ADDR_HI.load(Ordering::Relaxed), SATA_MSI_ADDR_LO.load(Ordering::Relaxed), vector
        );
    }
    ahci::set_msi(vector, enabled);
}

// NVMe (dev 2) MSI capability. NVMe advertises both MSI (0x40) and MSI-X
// (0xA0); Windows drives MSI here (it never programs the MSI-X table), so we
// must capture the message and deliver completions through it — otherwise the
// completion IRQ never fires and stornvme retries IDENTIFY NAMESPACE forever,
// so the disk never appears in Setup. Mirrors the AHCI MSI path above.
static NVME_MSI_CTRL: AtomicU32 = AtomicU32::new(0x0086); // bit7 64-bit capable
static NVME_MSI_ADDR_LO: AtomicU32 = AtomicU32::new(0);
static NVME_MSI_ADDR_HI: AtomicU32 = AtomicU32::new(0);
static NVME_MSI_DATA: AtomicU32 = AtomicU32::new(0);

fn nvme_msi_read(reg: u8) -> u32 {
    match reg {
        0x00 => 0x05 | (0x50 << 8) | (NVME_MSI_CTRL.load(Ordering::Relaxed) << 16), // id | next=0x50 | ctrl
        0x04 => NVME_MSI_ADDR_LO.load(Ordering::Relaxed),
        0x08 => NVME_MSI_ADDR_HI.load(Ordering::Relaxed),
        0x0C => NVME_MSI_DATA.load(Ordering::Relaxed),
        _ => 0,
    }
}

fn nvme_msi_write(reg: u8, val: u32, _width: u8) {
    match reg {
        0x00 => NVME_MSI_CTRL.store((val >> 16) & 0xFFFF, Ordering::Relaxed), // full dword: control in hi half
        0x02 => NVME_MSI_CTRL.store(val & 0xFFFF, Ordering::Relaxed),          // 16-bit control write
        0x04 => NVME_MSI_ADDR_LO.store(val, Ordering::Relaxed),
        0x08 => NVME_MSI_ADDR_HI.store(val, Ordering::Relaxed),
        0x0C => NVME_MSI_DATA.store(val & 0xFFFF, Ordering::Relaxed),
        _ => {}
    }
    let ctrl = NVME_MSI_CTRL.load(Ordering::Relaxed);
    let enabled = ctrl & 0x1 != 0;
    // Under IOMMU interrupt remapping (x2APIC path) the MSI data field is an
    // IR-table index, not the literal vector — resolve it through the IRTE.
    let data = NVME_MSI_DATA.load(Ordering::Relaxed) & 0xFF;
    let ir = crate::hardware::devices::iommu::ir_active();
    let vector = if ir {
        crate::hardware::devices::iommu::remap_vector(data as u8).map(|v| v as u32).unwrap_or(0)
    } else {
        data
    };
    if enabled {
        crate::sprintln!(
            "[nvme-msi] en={} ir={} data=0x{:X} addr=0x{:X}_{:08X} -> vec=0x{:X}",
            enabled, ir, data,
            NVME_MSI_ADDR_HI.load(Ordering::Relaxed), NVME_MSI_ADDR_LO.load(Ordering::Relaxed), vector
        );
    }
    nvme::set_msi(vector, enabled);
}

fn bar_read(idx: usize) -> u32 {
    BAR_VALUE[idx].load(Ordering::Relaxed)
}

fn bar_write(idx: usize, val: u32) {
    let d = &BAR_TABLE[idx];
    let addr_mask = !(d.size - 1); // bits the BAR actually decodes
    if val == 0xFFFF_FFFF {
        // Size probe: report the length mask. Crucially, do NOT move the
        // emulator's trap base here — the mask (e.g. 0xFF000000 for a 16 MiB
        // BAR) is not a real address, and routing a device/NPT map at it
        // corrupts unrelated memory.
        BAR_VALUE[idx].store(addr_mask | d.type_bits, Ordering::Relaxed);
        return;
    }
    let v = (val & addr_mask) | d.type_bits; // firmware-assigned base
    BAR_VALUE[idx].store(v, Ordering::Relaxed);
    let base = (v & !0xF) as u64;
    match d.trap {
        BarTrap::Nvme => nvme::set_bar0_base(base),
        BarTrap::Nic => nic::set_base(base),
        BarTrap::Xhci => xhci::set_base(base),
        BarTrap::Ahci => ahci::set_base(base),
        BarTrap::VgaFb => vga::set_fb_base(base),
        BarTrap::VgaMmio => vga::set_mmio_base(base),
        BarTrap::None => {}
    }
}

/// Per-device dispatch. veneer publishes a synthetic PCI tree built to
/// resemble an AMD X670E desktop platform:
///   bus 0 / dev 0 / func 0  →  Host bridge
///   bus 0 / dev 1 / func 0  →  Ethernet NIC (Intel I225-V)
///   bus 0 / dev 2 / func 0  →  NVMe controller (Samsung 980 PRO)
///   bus 0 / dev 3 / func 0  →  LPC / ISA bridge (AMD FCH)
///   bus 0 / dev 4 / func 0  →  SATA AHCI controller (AMD FCH)
///   bus 0 / dev 5 / func 0  →  SMBus controller (AMD FCH)
///   bus 0 / dev 6 / func 0  →  HD Audio controller (AMD FCH)
///   bus 0 / dev 7 / func 0  →  USB 3.1 xHCI controller (AMD FCH)
///   bus 0 / dev 8 / func 0  →  Integrated GPU (AMD Raphael / Intel UHD)
///   everything else         →  no device (0xFFFFFFFF)
// Per-device round-trip of the writable standard-header registers. A guest
// enables Mem/Bus-Master/INTx-disable in the Command register and reads it
// back to confirm; PnP writes the Interrupt Line. If those writes are dropped
// the read-back misses them and the guest re-loops forever (observed: Windows
// boot RMW'ing the xHCI Command register). Status and the rest stay as each
// device's fixed value. Value 0 = "guest hasn't written it, use the default".
const PCI_DEV_COUNT: usize = 32;
const CMD_MARKER: u32 = 1 << 16;       // command stored (low 16 = value)
const CMD_WRITABLE: u32 = 0x0000_0747; // I/O,Mem,BM,ParErr,SERR,FastB2B,INTxDis
const IL_MARKER: u32 = 1 << 8;         // interrupt-line stored (low 8 = value)
#[allow(clippy::declare_interior_mutable_const)]
const CFG_INIT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static DEV_COMMAND: [core::sync::atomic::AtomicU32; PCI_DEV_COUNT] = [CFG_INIT; PCI_DEV_COUNT];
static DEV_INTR_LINE: [core::sync::atomic::AtomicU32; PCI_DEV_COUNT] = [CFG_INIT; PCI_DEV_COUNT];

fn config_read(bus: u8, dev: u8, func: u8, reg: u8) -> u32 {
    let dword = config_read_raw(bus, dev, func, reg);
    if bus != 0 || func != 0 || (dev as usize) >= PCI_DEV_COUNT {
        return dword;
    }
    // Diagnostic: trace the NVMe (dev 2) capability-region reads so we can see
    // whether the guest's storage driver walks the MSI / MSI-X capabilities
    // (interrupt-resource setup) and what it reads. Deduplicated by (reg,value)
    // and capped. Remove once device-MSI setup is understood.
    if dev == 2 && (0x06..=0xBF).contains(&reg) {
        // Per-register dedup: log only when this register's value changes, so
        // repeated enumeration passes don't drown out the distinct cap walk.
        let bucket = (reg >> 2) as usize;
        if bucket < CFG_RD_LAST.len() {
            let key = 0x8000_0000 | dword; // mark "seen" so initial 0 logs once
            if CFG_RD_LAST[bucket].swap(key, Ordering::Relaxed) != key {
                crate::sprintln!("[nvme-cfgrd] reg=0x{:02X} val=0x{:08X}", reg, dword);
            }
        }
    }
    match reg {
        0x04 => {
            let c = DEV_COMMAND[dev as usize].load(Ordering::Relaxed);
            if c & CMD_MARKER != 0 {
                return (dword & 0xFFFF_0000) | (c & 0xFFFF);
            }
        }
        0x3C => {
            let il = DEV_INTR_LINE[dev as usize].load(Ordering::Relaxed);
            if il & IL_MARKER != 0 {
                return (dword & 0xFFFF_FF00) | (il & 0xFF);
            }
        }
        _ => {}
    }
    dword
}

fn config_read_raw(bus: u8, dev: u8, func: u8, reg: u8) -> u32 {
    // BAR slots (0x10..0x28) belong to the sizing table so the firmware's
    // length probe reads a mask, not a fixed address. Offsets with no BAR
    // defined read 0 (BAR not implemented).
    if bus == 0 && func == 0 && (0x10..0x28).contains(&reg) {
        return bar_index(dev, reg).map(bar_read).unwrap_or(0);
    }
    match (bus, dev, func) {
        (0, 0, 0) => host_bridge_read(reg),
        (0, 1, 0) => nic_read(reg),
        (0, 2, 0) => nvme_read(reg),
        (0, 3, 0) => lpc_read(reg),
        (0, 4, 0) => sata_read(reg),
        (0, 5, 0) => smbus_read(reg),
        (0, 6, 0) => hda_read(reg),
        (0, 7, 0) => xhci_read(reg),
        (0, 8, 0) => gpu_read(reg),
        (0, 0x1F, 0) => ich9_lpc_read(reg),
        _ => 0xFFFF_FFFF,
    }
}

/// Persist a write to a writable standard-header register (Command 0x04-05,
/// Interrupt Line 0x3C) so the guest's read-back reflects it. `reg` is the
/// starting byte offset of this (possibly sub-dword) write.
fn store_cfg(bus: u8, dev: u8, func: u8, reg: u8, val: u32, width: u8) {
    if bus != 0 || func != 0 || (dev as usize) >= PCI_DEV_COUNT {
        return;
    }
    let touches = |byte: u8| reg <= byte && byte < reg.saturating_add(width);
    if touches(0x04) || touches(0x05) {
        let base = {
            let c = DEV_COMMAND[dev as usize].load(Ordering::Relaxed);
            if c & CMD_MARKER != 0 { c & 0xFFFF } else { config_read_raw(bus, dev, func, 0x04) & 0xFFFF }
        };
        let mut cmd = base;
        for i in 0..width {
            match reg + i {
                0x04 => cmd = (cmd & 0xFF00) | ((val >> (i as u32 * 8)) & 0xFF),
                0x05 => cmd = (cmd & 0x00FF) | (((val >> (i as u32 * 8)) & 0xFF) << 8),
                _ => {}
            }
        }
        DEV_COMMAND[dev as usize].store((cmd & CMD_WRITABLE) | CMD_MARKER, Ordering::Relaxed);
    }
    if touches(0x3C) {
        let i = 0x3C - reg;
        let il = (val >> (i as u32 * 8)) & 0xFF;
        DEV_INTR_LINE[dev as usize].store(il | IL_MARKER, Ordering::Relaxed);
    }
}

/// Intel ICH9 LPC bridge (0x8086:0x2918) at the fixed Q35 location
/// 00:1f.0. We already advertise a Q35 host bridge, so OVMF expects the
/// ICH9 PM controller here and programs its PMBASE / ACPI control through
/// this function. Those two registers are backed by `acpi_pm`; the rest
/// reads as a plain ISA bridge.
fn ich9_lpc_read(reg: u8) -> u32 {
    const VENDOR_DEVICE: u32 = 0x2918_8086;
    match reg {
        0x00 => VENDOR_DEVICE,
        0x04 => 0x0210_0007,   // status: DEVSEL fast; cmd: IO+Mem+BM
        0x08 => 0x0601_0002,   // class=06 subclass=01 (ISA bridge), rev=2
        0x0C => 0x0000_8000,   // header type 0 + multifunction
        0x2C => VENDOR_DEVICE,
        0x40 => acpi_pm::pmbase(),
        0x44 => acpi_pm::acpi_cntl(),
        _ => 0,
    }
}

/// Intel-style host bridge (Vendor 0x8086, Device 0x29C0 = "Q35").
/// Boot loaders look at offset 0x00..0x10; we keep the rest at 0.
fn host_bridge_read(reg: u8) -> u32 {
    match reg {
        0x00 => pid_host_bridge(), // device:vendor (Q35-compat, profile-driven)
        0x04 => 0x0010_0006, // status:command — Bus Master + MemSpace
        0x08 => 0x0600_0001, // class=06 (Bridge), subclass=00 (Host), rev=1
        0x0C => 0x0000_0000, // header type 0
        _ => 0,
    }
}

/// Synthetic 1 GbE NIC at bus 0 / dev 1. PCI IDs are an Intel I225-V
/// (commonly used on AM5/X670 desktop boards). MMIO BAR0 is a 16 MiB
/// region at 0xE100_0000 — claimed by the config space but not backed
/// by any veneer trap yet (B-4c+ extends with a register emulator).
///
/// Capability list at 0x40 → MSI → PMI → PCIe → MSI-X.
fn nic_read(reg: u8) -> u32 {
    let id = pid_nic();
    match reg {
        0x00 => id,
        0x04 => 0x0010_0007, // status:command — capabilities-list bit set
        0x08 => 0x0200_0003,
        0x0C => 0x0000_0000,
        0x28 => 0,
        0x2C => id,
        0x30 => 0,
        0x34 => 0x0000_0040, // capabilities pointer → 0x40 (MSI cap head)
        0x3C => 0x0000_010B,
        0x40..=0x4F => cap_msi(reg - 0x40, 0x50),
        0x50..=0x5F => cap_pmi(reg - 0x50, 0x60),
        0x60..=0x83 => cap_pcie(reg - 0x60, 0xA0),
        0xA0..=0xAF => cap_msix(reg - 0xA0, 0, 4, 0x10),  // 4 vectors, table @ BAR4+0x10
        _ => 0,
    }
}

/// Synthetic NVMe controller at bus 0 / dev 2. Capability list at 0x40
/// → MSI → PMI → PCIe → MSI-X.
fn nvme_read(reg: u8) -> u32 {
    let id = pid_nvme();
    match reg {
        0x00 => id,
        0x04 => 0x0010_0006,
        0x08 => 0x0108_0203,
        0x0C => 0x0000_0000,
        0x28 => 0,
        0x2C => id,
        0x30 => 0,
        0x34 => 0x0000_0040,
        0x3C => 0x0000_010A,
        0x40..=0x4F => nvme_msi_read(reg - 0x40),
        0x50..=0x5F => cap_pmi(reg - 0x50, 0x60),
        0x60..=0x83 => cap_pcie(reg - 0x60, 0xA0),
        0xA0..=0xAF => cap_msix(reg - 0xA0, 0, 64, 0x2000),  // 64 vectors, table at BAR0+0x2000
        _ => 0,
    }
}

/// AMD FCH LPC bridge (0x1022:0x790E). Standard "ISA bridge" class
/// 0x060100. No BARs — the LPC bridge fronts legacy I/O ports rather
/// than MMIO regions. Windows uses this to host the legacy interrupt
/// controller / RTC / superio enumeration.
fn lpc_read(reg: u8) -> u32 {
    let id = pid_lpc();
    match reg {
        0x00 => id,
        0x04 => 0x0210_0007,   // status: fast-back-to-back + DEVSEL=fast; cmd: IO+Mem+BM
        0x08 => 0x0601_0061,   // class=06 (Bridge), subclass=01 (ISA), rev=0x61
        0x0C => 0x0000_8000,   // header type 0 + multifunction bit (FCH publishes several funcs)
        0x10..=0x24 => 0,      // no BARs
        0x2C => id,
        0x3C => 0x0000_0100,   // intr_line=0, pin=A
        _ => 0,
    }
}

/// AMD FCH SATA AHCI controller (0x1022:0x7901). Class 0x010601 = AHCI.
/// Reports 0 attached devices in BAR-backed registers — Windows will
/// enumerate the controller but find no disks, which is fine because
/// the actual storage is the NVMe device at dev 2.
fn sata_read(reg: u8) -> u32 {
    let id = pid_sata();
    match reg {
        0x00 => id,
        0x04 => 0x0210_0007,
        0x08 => 0x0106_0181,   // class=01, subclass=06, prog_if=01 (AHCI 1.0)
        0x0C => 0x0000_0000,
        0x2C => id,
        0x34 => 0x0000_0040,   // capabilities pointer → 0x40 (MSI cap head)
        0x3C => 0x0000_0110,   // intr_line=16, pin=A
        0x40..=0x4F => sata_msi_read(reg - 0x40),
        _ => 0,
    }
}

/// AMD FCH SMBus controller (0x1022:0x790B). Class 0x0C0500.
fn smbus_read(reg: u8) -> u32 {
    let id = pid_smbus();
    match reg {
        0x00 => id,
        0x04 => 0x0210_0001,
        0x08 => 0x0C05_0061,   // class=0C, subclass=05 (SMBus), rev=0x61
        0x0C => 0x0000_0000,
        0x10..=0x24 => 0,
        0x2C => id,
        0x3C => 0x0000_0000,
        _ => 0,
    }
}

/// AMD FCH HD Audio controller (0x1022:0x1457). Capability list:
/// PMI → PCIe.
fn hda_read(reg: u8) -> u32 {
    let id = pid_hda();
    match reg {
        0x00 => id,
        0x04 => 0x0010_0006,
        0x08 => 0x0403_0001,
        0x0C => 0x0000_0000,
        0x2C => id,
        0x34 => 0x0000_0040,
        0x3C => 0x0000_010B,
        0x40..=0x4F => cap_pmi(reg - 0x40, 0x50),
        0x50..=0x73 => cap_pcie(reg - 0x50, 0),
        _ => 0,
    }
}

// ───── Capability builders ───────────────────────────────────────────
//
// Each helper returns the u32 at byte `offset` within its capability
// structure. The `next` parameter is the byte-offset of the next cap
// in the linked list (0 terminates).

/// MSI Capability (Cap ID 0x05). 14 bytes: header + Message Control +
/// 64-bit Address + Data + Mask + Pending.
fn cap_msi(offset: u8, next: u8) -> u32 {
    let aligned = offset & !0x3;
    match aligned {
        // 0x00: cap_id(0x05) | next(u8) | message_control(u16)
        //   message_control: 64-bit capable(bit 7=1), per-vector mask(bit 8=0),
        //   multiple message enable=0, multiple message capable=001 (2 vectors)
        0x00 => 0x0086_0005 | ((next as u32) << 8),
        // 0x04: Message Address Low
        0x04 => 0,
        // 0x08: Message Address High
        0x08 => 0,
        // 0x0C: Message Data (16-bit), upper 16 reserved
        0x0C => 0,
        _ => 0,
    }
}

/// MSI-X Capability (Cap ID 0x11). 12 bytes.
fn cap_msix(offset: u8, next: u8, table_size: u16, table_offset_bir: u32) -> u32 {
    let aligned = offset & !0x3;
    match aligned {
        // 0x00: cap_id(0x11) | next(u8) | message_control(u16):
        //   table_size = N-1, enable(bit 15)=0, function_mask(bit 14)=0
        0x00 => 0x0011 | ((next as u32) << 8) | (((table_size.saturating_sub(1)) as u32) << 16),
        // 0x04: Table Offset | BIR (bits 0-2)
        0x04 => table_offset_bir,
        // 0x08: PBA Offset | BIR
        0x08 => table_offset_bir.wrapping_add(0x800),
        _ => 0,
    }
}

/// PCI Express Capability (Cap ID 0x10). 36 bytes for v2.
fn cap_pcie(offset: u8, next: u8) -> u32 {
    let aligned = offset & !0x3;
    match aligned {
        // 0x00: cap_id(0x10) | next | pcie_caps_reg(u16):
        //   version=2, device_type=0 (endpoint), slot impl=0, IRQ msg num=0
        0x00 => 0x0002_0010 | ((next as u32) << 8),
        // 0x04: Device Capabilities — max_payload=128 (000), L0s=64ns, L1=1us, …
        0x04 => 0x0000_8000,
        // 0x08: Device Control (u16) + Device Status (u16)
        0x08 => 0x0000_0000,
        // 0x0C: Link Capabilities — Gen5 x16, 1us L0s, 4us L1
        //   max_link_speed=5 (Gen5), max_link_width=0x10 (x16)
        0x0C => 0x0001_0105,
        // 0x10: Link Control (u16) + Link Status (u16)
        //   Status: link_speed=5, link_width=0x10, link active
        0x10 => 0x1105_0000,
        // 0x14: Slot Capabilities — slot empty
        0x14 => 0,
        // 0x18: Slot Control + Status
        0x18 => 0,
        // 0x1C: Root Control + Capabilities
        0x1C => 0,
        // 0x20: Root Status
        0x20 => 0,
        _ => 0,
    }
}

/// Power Management Capability (Cap ID 0x01). 8 bytes.
fn cap_pmi(offset: u8, next: u8) -> u32 {
    let aligned = offset & !0x3;
    match aligned {
        // 0x00: cap_id(0x01) | next | pmc(u16):
        //   version=3, PME D0/D3hot, AUX_current=0
        0x00 => 0x0803_0001 | ((next as u32) << 8),
        // 0x04: PMCSR (u16) — currently D0 — + status + data
        0x04 => 0x0000_0000,
        _ => 0,
    }
}

/// AMD FCH USB 3.1 xHCI controller (0x1022:0x149C). Capability list:
/// MSI → PMI → PCIe → MSI-X.
fn xhci_read(reg: u8) -> u32 {
    let id = pid_xhci();
    match reg {
        0x00 => id,
        0x04 => 0x0010_0006,
        0x08 => 0x0C03_3001,
        0x0C => 0x0000_0000,
        0x2C => id,
        0x34 => 0x0000_0040,
        0x3C => 0x0000_010A,
        0x40..=0x4F => cap_msi(reg - 0x40, 0x50),
        0x50..=0x5F => cap_pmi(reg - 0x50, 0x60),
        0x60..=0x83 => cap_pcie(reg - 0x60, 0xA0),
        0xA0..=0xAF => cap_msix(reg - 0xA0, 0, 8, 0x3000),
        _ => 0,
    }
}

/// Display controller. We present the standard-VGA + Bochs DISPI device
/// (0x1234:0x1111) because OVMF's QemuVideoDxe binds to it and turns its
/// linear framebuffer into a UEFI GOP that any OS uses driver-free (Windows
/// "Basic Display Adapter", Linux efifb). BAR0 = framebuffer, BAR2 = DISPI
/// MMIO — both fixed (see BAR_TABLE + intercept/vga). No caps, no INTx.
///
/// NOTE (anti-detect): 0x1234:0x1111 is a recognisable virtual-VGA id. The
/// framebuffer→GOP *mechanism* is universal; only the identifier is a tell,
/// acceptable for the install/bring-up phase and hardened later (real-GPU
/// framebuffer or post-boot hide). Pin to the std-vga id — QemuVideoDxe binds
/// to nothing else with a simple linear framebuffer.
fn gpu_read(reg: u8) -> u32 {
    let _ = pid_gpu(); // profile GPU id reserved for the hardened path
    match reg {
        0x00 => 0x1111_1234,  // QEMU std-vga (device 0x1111 : vendor 0x1234)
        0x04 => 0x0000_0003,  // command: I/O + memory space; no cap list
        0x08 => 0x0300_0002,  // class 0x03 display / 0x00 VGA, prog-if 0, rev 2
        0x0C => 0x0000_0000,  // header type 0
        0x2C => 0x1111_1234,  // subsystem = same id
        0x34 => 0x0000_0000,  // no capability list
        0x3C => 0x0000_0000,  // no interrupt line/pin
        _ => 0,
    }
}
