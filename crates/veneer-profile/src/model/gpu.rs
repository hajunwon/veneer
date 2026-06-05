//! GPU. Peripheral — carries a delivery mode (the prime future candidate
//! for emulate-vs-passthrough). PCI identity only for now.

use crate::model::delivery::DeliveryMode;

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct GpuSpec {
    pub pci_id: u32, // device:vendor
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct GpuComponent {
    pub delivery: DeliveryMode,
    pub spec: GpuSpec,
}

impl GpuComponent {
    pub const fn empty() -> Self {
        Self { delivery: DeliveryMode::EMULATED, spec: GpuSpec { pci_id: 0 } }
    }
}
