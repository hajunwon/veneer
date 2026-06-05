//! Device model — the registry of runtime-trapped emulated devices.
//!
//! Each device exposes a uniform role interface (`MmioDevice` for now; port /
//! MSR roles follow) and registers here. The vmexit dispatcher routes a
//! faulting access to the device that claims it instead of a hand-coded
//! match, so adding, deepening, or swapping a device (including emulated ↔
//! passthrough) is local to its module plus one registry entry.

use crate::diag::serial_kd;
use crate::hardware::devices::bus::{nic, pci, vga, xhci};
use crate::hardware::devices::iommu;
use crate::hardware::devices::irq::{hpet, ioapic, lapic, pic, pit, rtc};
use crate::hardware::devices::storage::{ahci, nvme};
use crate::hardware::devices::{acpi_pm, fwcfg, tpm};

/// A device reachable through trapped guest-physical MMIO. Read/write take the
/// absolute faulting GPA; each device maps it to its own register offset.
pub trait MmioDevice: Sync {
    fn covers(&self, gpa: u64) -> bool;
    fn read(&self, gpa: u64, width: u8) -> u64;
    fn write(&self, gpa: u64, val: u64, width: u8);
    fn name(&self) -> &'static str;
}

struct Lapic;
impl MmioDevice for Lapic {
    fn covers(&self, g: u64) -> bool { lapic::covers(g) }
    fn read(&self, g: u64, w: u8) -> u64 { lapic::read_register_width((g - lapic::LAPIC_BASE) as u32, w) }
    fn write(&self, g: u64, v: u64, w: u8) { lapic::write_register_width((g - lapic::LAPIC_BASE) as u32, v, w) }
    fn name(&self) -> &'static str { "lapic" }
}

struct Nic;
impl MmioDevice for Nic {
    fn covers(&self, g: u64) -> bool { nic::covers(g) }
    fn read(&self, g: u64, w: u8) -> u64 { nic::read_register_width((g - nic::base()) as u32, w) }
    fn write(&self, g: u64, v: u64, w: u8) { nic::write_register_width((g - nic::base()) as u32, v, w) }
    fn name(&self) -> &'static str { "nic" }
}

struct Nvme;
impl MmioDevice for Nvme {
    fn covers(&self, g: u64) -> bool { nvme::covers(g) }
    fn read(&self, g: u64, w: u8) -> u64 { nvme::read_register_width((g - nvme::bar0_base()) as u32, w) }
    fn write(&self, g: u64, v: u64, w: u8) { nvme::write_register_width((g - nvme::bar0_base()) as u32, v, w) }
    fn name(&self) -> &'static str { "nvme" }
}

struct Hpet;
impl MmioDevice for Hpet {
    fn covers(&self, g: u64) -> bool { hpet::covers(g) }
    fn read(&self, g: u64, w: u8) -> u64 { hpet::read_register_width((g - hpet::HPET_BASE) as u32, w) }
    fn write(&self, g: u64, v: u64, w: u8) { hpet::write_register_width((g - hpet::HPET_BASE) as u32, v, w) }
    fn name(&self) -> &'static str { "hpet" }
}

struct Tpm;
impl MmioDevice for Tpm {
    fn covers(&self, g: u64) -> bool { tpm::covers(g) }
    fn read(&self, g: u64, w: u8) -> u64 { tpm::read_register_width((g - tpm::TPM_BASE) as u32, w) }
    fn write(&self, g: u64, v: u64, w: u8) { tpm::write_register_width((g - tpm::TPM_BASE) as u32, v, w) }
    fn name(&self) -> &'static str { "tpm" }
}

struct IoApic;
impl MmioDevice for IoApic {
    fn covers(&self, g: u64) -> bool { ioapic::covers(g) }
    fn read(&self, g: u64, w: u8) -> u64 { ioapic::read_register_width((g - ioapic::IOAPIC_BASE) as u32, w) }
    fn write(&self, g: u64, v: u64, w: u8) { ioapic::write_register_width((g - ioapic::IOAPIC_BASE) as u32, v, w) }
    fn name(&self) -> &'static str { "ioapic" }
}

struct Xhci;
impl MmioDevice for Xhci {
    fn covers(&self, g: u64) -> bool { xhci::covers(g) }
    fn read(&self, g: u64, w: u8) -> u64 { xhci::read_register_width((g - xhci::base()) as u32, w) }
    fn write(&self, g: u64, v: u64, w: u8) { xhci::write_register_width((g - xhci::base()) as u32, v, w) }
    fn name(&self) -> &'static str { "xhci" }
}

struct Ahci;
impl MmioDevice for Ahci {
    fn covers(&self, g: u64) -> bool { ahci::covers(g) }
    fn read(&self, g: u64, w: u8) -> u64 { ahci::read_register_width((g - ahci::base()) as u32, w) }
    fn write(&self, g: u64, v: u64, w: u8) { ahci::write_register_width((g - ahci::base()) as u32, v, w) }
    fn name(&self) -> &'static str { "ahci" }
}

struct Vga;
impl MmioDevice for Vga {
    fn covers(&self, g: u64) -> bool { vga::mmio_covers(g) }
    fn read(&self, g: u64, w: u8) -> u64 { vga::mmio_read(g, w) }
    fn write(&self, g: u64, v: u64, w: u8) { vga::mmio_write(g, v, w) }
    fn name(&self) -> &'static str { "vga" }
}

struct Iommu;
impl MmioDevice for Iommu {
    fn covers(&self, g: u64) -> bool { iommu::covers(g) }
    fn read(&self, g: u64, w: u8) -> u64 { iommu::read_register_width((g - iommu::IOMMU_MMIO_BASE) as u32, w) }
    fn write(&self, g: u64, v: u64, w: u8) { iommu::write_register_width((g - iommu::IOMMU_MMIO_BASE) as u32, v, w) }
    fn name(&self) -> &'static str { "iommu" }
}

struct Ecam;
impl MmioDevice for Ecam {
    fn covers(&self, g: u64) -> bool { pci::covers_ecam(g) }
    fn read(&self, g: u64, w: u8) -> u64 { pci::ecam_read(g, w) }
    fn write(&self, g: u64, v: u64, w: u8) { pci::ecam_write(g, v, w) }
    fn name(&self) -> &'static str { "ecam" }
}

/// Registration order = probe order for `find_mmio` (windows are disjoint, so
/// order only affects the unmapped-fallback path, not correctness).
static MMIO_DEVICES: &[&dyn MmioDevice] = &[
    &Lapic, &Nic, &Nvme, &Hpet, &Tpm, &IoApic, &Xhci, &Ahci, &Vga, &Iommu, &Ecam,
];

pub const MMIO_COUNT: usize = MMIO_DEVICES.len();

/// The device claiming `gpa`, with its registration index (for diagnostics).
pub fn find_mmio(gpa: u64) -> Option<(usize, &'static dyn MmioDevice)> {
    let mut i = 0;
    while i < MMIO_DEVICES.len() {
        if MMIO_DEVICES[i].covers(gpa) {
            return Some((i, MMIO_DEVICES[i]));
        }
        i += 1;
    }
    None
}

/// Device name by registration index; `MMIO_COUNT` (or out of range) = unmapped.
pub fn mmio_name_at(i: usize) -> &'static str {
    match MMIO_DEVICES.get(i) {
        Some(d) => d.name(),
        None => "unmapped",
    }
}

/// Device name claiming `gpa`, or "UNMAPPED".
pub fn mmio_name(gpa: u64) -> &'static str {
    match find_mmio(gpa) {
        Some((_, d)) => d.name(),
        None => "UNMAPPED",
    }
}

// ───── port-mapped devices (legacy + chipset IO) ─────────────────────────
//
// Side-effecting / multi-register ports (COM1 serial line-buffer, the 0x402
// debugcon, the VMware backdoor) stay special-cased in the IOIO handler —
// they are diagnostic-critical or don't fit a scalar read→rax model.

/// A device reachable through trapped IO ports. Byte-only devices ignore
/// `width`; width-aware devices (PCI config, ACPI PM) honor it.
pub trait PortDevice: Sync {
    fn covers(&self, port: u16) -> bool;
    fn read(&self, port: u16, width: u8) -> u64;
    fn write(&self, port: u16, val: u64, width: u8);
    fn name(&self) -> &'static str;
}

struct Pit;
impl PortDevice for Pit {
    fn covers(&self, p: u16) -> bool { pit::covers(p) }
    fn read(&self, p: u16, _w: u8) -> u64 { pit::handle_in(p) as u64 }
    fn write(&self, p: u16, v: u64, _w: u8) { pit::handle_out(p, v as u8) }
    fn name(&self) -> &'static str { "pit" }
}

struct Pic;
impl PortDevice for Pic {
    fn covers(&self, p: u16) -> bool { pic::covers(p) }
    fn read(&self, p: u16, _w: u8) -> u64 { pic::handle_in(p) as u64 }
    fn write(&self, p: u16, v: u64, _w: u8) { pic::handle_out(p, v as u8) }
    fn name(&self) -> &'static str { "pic" }
}

struct Rtc;
impl PortDevice for Rtc {
    fn covers(&self, p: u16) -> bool { rtc::covers(p) }
    fn read(&self, p: u16, _w: u8) -> u64 { rtc::handle_in(p) as u64 }
    fn write(&self, p: u16, v: u64, _w: u8) { rtc::handle_out(p, v as u8) }
    fn name(&self) -> &'static str { "rtc" }
}

struct I8042;
impl PortDevice for I8042 {
    fn covers(&self, p: u16) -> bool { crate::hardware::devices::i8042::covers(p) }
    fn read(&self, p: u16, _w: u8) -> u64 { crate::hardware::devices::i8042::handle_in(p) as u64 }
    fn write(&self, p: u16, v: u64, _w: u8) { crate::hardware::devices::i8042::handle_out(p, v as u8) }
    fn name(&self) -> &'static str { "i8042" }
}

struct AcpiPm;
impl PortDevice for AcpiPm {
    fn covers(&self, p: u16) -> bool { acpi_pm::covers(p) }
    fn read(&self, p: u16, w: u8) -> u64 { acpi_pm::read(p, w) }
    fn write(&self, p: u16, v: u64, w: u8) { acpi_pm::write(p, v, w) }
    fn name(&self) -> &'static str { "acpi-pm" }
}

struct PciConfig;
impl PortDevice for PciConfig {
    fn covers(&self, p: u16) -> bool { pci::is_config_address_port(p) || pci::is_config_data_port(p) }
    fn read(&self, p: u16, w: u8) -> u64 {
        if pci::is_config_address_port(p) { pci::read_address(p, w) } else { pci::read_data(p, w) }
    }
    fn write(&self, p: u16, v: u64, w: u8) {
        if pci::is_config_address_port(p) { pci::store_address(v as u32) } else { pci::write_data(p, v as u32, w) }
    }
    fn name(&self) -> &'static str { "pci-cfg" }
}

struct Fwcfg;
impl PortDevice for Fwcfg {
    fn covers(&self, p: u16) -> bool { p == fwcfg::SELECTOR_PORT || p == fwcfg::DATA_PORT }
    fn read(&self, p: u16, _w: u8) -> u64 {
        if p == fwcfg::DATA_PORT { fwcfg::next_byte() as u64 } else { 0xFF }
    }
    fn write(&self, p: u16, v: u64, _w: u8) {
        if p == fwcfg::SELECTOR_PORT { fwcfg::select(v as u16) }
    }
    fn name(&self) -> &'static str { "fwcfg" }
}

struct SerialKd;
impl PortDevice for SerialKd {
    fn covers(&self, p: u16) -> bool { serial_kd::covers(p) }
    fn read(&self, p: u16, _w: u8) -> u64 { serial_kd::read(p - 0x2F8) }
    fn write(&self, p: u16, v: u64, _w: u8) { serial_kd::write(p - 0x2F8, v as u8) }
    fn name(&self) -> &'static str { "kd-com2" }
}

static PORT_DEVICES: &[&dyn PortDevice] =
    &[&Pit, &Pic, &Rtc, &I8042, &AcpiPm, &PciConfig, &Fwcfg, &SerialKd];

/// The port device claiming `port`, if any.
pub fn find_port(port: u16) -> Option<&'static dyn PortDevice> {
    let mut i = 0;
    while i < PORT_DEVICES.len() {
        if PORT_DEVICES[i].covers(port) {
            return Some(PORT_DEVICES[i]);
        }
        i += 1;
    }
    None
}
