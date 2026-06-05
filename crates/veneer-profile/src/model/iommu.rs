//! On-die IOMMU identity (AMD-Vi). Lives under the CPU spec because the
//! IOMMU is part of the CPU/SoC die — its feature set is fixed by the die,
//! not the board.
//!
//! `efr` is the Extended Feature Register (MMIO 0x30), mirrored into the
//! IVRS/IVHD "EFR Register Image". The live MMIO register emitter and the
//! ACPI IVRS emitter MUST both read this one field so the value a guest
//! sees through `GetSystemFirmwareTable("ACPI","IVRS")` (user mode) and the
//! live MMIO read (kernel mode) can never disagree.

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct IommuModel {
    /// Extended Feature Register (MMIO 0x30 / IVHD EFR image).
    pub efr: u64,
    /// Extended Feature Register 2 (MMIO 0x1A0). 0 on Zen3/Zen4.
    pub efr2: u64,
    /// IOMMU PCI function device:vendor (config 0x00 layout: device<<16 | vendor).
    pub pci_id: u32,
}

impl IommuModel {
    pub const fn new(efr: u64, efr2: u64, pci_id: u32) -> Self {
        Self { efr, efr2, pci_id }
    }

    pub const fn empty() -> Self {
        Self { efr: 0, efr2: 0, pci_id: 0 }
    }

    /// XTSup (EFR bit 2): IOMMU x2APIC-mode interrupt remapping support.
    /// Desktop chiplet dies (Vermeer/Raphael) report this clear; APU and
    /// server dies report it set. Derived from `efr`, never stored twice.
    pub fn xtsup(&self) -> bool {
        let efr = unsafe { core::ptr::addr_of!(self.efr).read_unaligned() };
        efr & (1 << 2) != 0
    }
}
