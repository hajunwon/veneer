//! Motherboard / chipset. Baseboard identity + chipset PCI device IDs are
//! spec; baseboard/chassis serials are per-unit (instance).

use crate::primitives::{SmbiosLong, SmbiosShort};

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct BoardSpec {
    pub baseboard_manufacturer: SmbiosLong,
    pub baseboard_product: SmbiosLong,
    /// Chipset PCI device:vendor IDs (config 0x00 layout).
    pub host_bridge_id: u32,
    pub lpc_id: u32,
    pub sata_id: u32,
    pub smbus_id: u32,
    pub xhci_id: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct BoardInstance {
    pub baseboard_serial: SmbiosShort,
    pub chassis_serial: SmbiosShort,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct BoardComponent {
    pub spec: BoardSpec,
    pub instance: BoardInstance,
}

impl BoardComponent {
    pub const fn empty() -> Self {
        Self {
            spec: BoardSpec {
                baseboard_manufacturer: SmbiosLong::empty(),
                baseboard_product: SmbiosLong::empty(),
                host_bridge_id: 0,
                lpc_id: 0,
                sata_id: 0,
                smbus_id: 0,
                xhci_id: 0,
            },
            instance: BoardInstance {
                baseboard_serial: SmbiosShort::empty(),
                chassis_serial: SmbiosShort::empty(),
            },
        }
    }
}
