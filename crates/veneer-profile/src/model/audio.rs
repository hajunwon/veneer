//! HD Audio controller. Peripheral — carries a delivery mode. PCI identity.

use crate::model::delivery::DeliveryMode;

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct AudioSpec {
    pub pci_id: u32, // device:vendor
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct AudioComponent {
    pub delivery: DeliveryMode,
    pub spec: AudioSpec,
}

impl AudioComponent {
    pub const fn empty() -> Self {
        Self { delivery: DeliveryMode::EMULATED, spec: AudioSpec { pci_id: 0 } }
    }
}
