//! Guest APIC mode (xAPIC vs x2APIC), fixed by the profile die's IOMMU.

use crate::hardware::devices::iommu;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ApicMode {
    XApic,
    X2Apic,
}

/// Real hardware only runs the LAPIC in x2APIC mode when the IOMMU can remap
/// interrupts for it (EFR XTSup): desktop chiplet dies clear it and stay in
/// xAPIC, APU/server dies set it. veneer mirrors that so the guest OS reaches
/// the decision its real die would, instead of being forced one way.
pub fn mode() -> ApicMode {
    if iommu::xtsup() {
        ApicMode::X2Apic
    } else {
        ApicMode::XApic
    }
}

/// IA32_APIC_BASE the guest reads before it writes its own: base 0xFEE00000 +
/// global enable (bit 11) + BSP (bit 8), plus EXTD (bit 10) only in x2APIC
/// mode. xAPIC leaves EXTD clear so the guest drives the LAPIC via MMIO;
/// x2APIC sets it so the guest uses the MSR window (0x800-0x8FF).
pub fn base_default() -> u64 {
    match mode() {
        ApicMode::X2Apic => 0xFEE0_0D00,
        ApicMode::XApic => 0xFEE0_0900,
    }
}
