//! Storage device (NVMe). Peripheral — carries a delivery mode. Model/PCI
//! identity is spec; the controller serial is per-unit (instance).

use crate::model::delivery::DeliveryMode;
use crate::primitives::{ProfileStr, SmbiosLong, SmbiosShort};

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct StorageSpec {
    pub slot: SmbiosShort, // e.g. "nvme0:0"
    pub model: SmbiosLong,
    /// NVMe IDENTIFY FR field (firmware revision, 8 bytes).
    pub firmware_rev: ProfileStr<8>,
    /// NVMe IDENTIFY IEEE OUI (controller vendor, 3 bytes, little-endian).
    pub ieee_oui: [u8; 3],
    /// NVMe controller PCI device:vendor (config 0x00 layout).
    pub pci_id: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct StorageInstance {
    pub serial: SmbiosShort,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct StorageComponent {
    pub delivery: DeliveryMode,
    pub spec: StorageSpec,
    pub instance: StorageInstance,
}

impl StorageComponent {
    pub const fn empty() -> Self {
        Self {
            delivery: DeliveryMode::EMULATED,
            spec: StorageSpec {
                slot: SmbiosShort::empty(),
                model: SmbiosLong::empty(),
                firmware_rev: ProfileStr::empty(),
                ieee_oui: [0; 3],
                pci_id: 0,
            },
            instance: StorageInstance { serial: SmbiosShort::empty() },
        }
    }
}
