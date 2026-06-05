//! NIC. Peripheral — carries a delivery mode. PCI/PHY identity and the OUI
//! are spec; the MAC is per-unit (instance) and must be generated within
//! this OUI so the prefix matches the NIC vendor.

use crate::model::delivery::DeliveryMode;
use crate::primitives::MacStr;

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct NetworkSpec {
    /// PCI device:vendor (config 0x00 layout: device<<16 | vendor).
    pub pci_id: u32,
    /// MII PHY identifier the driver reads from MDIC.
    pub phy_id: u16,
    /// OUI prefix the per-unit MAC is generated under (3 bytes).
    pub oui: [u8; 3],
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct NetworkInstance {
    pub mac: MacStr,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct NetworkComponent {
    pub delivery: DeliveryMode,
    pub spec: NetworkSpec,
    pub instance: NetworkInstance,
}

impl NetworkComponent {
    pub const fn empty() -> Self {
        Self {
            delivery: DeliveryMode::EMULATED,
            spec: NetworkSpec { pci_id: 0, phy_id: 0, oui: [0; 3] },
            instance: NetworkInstance { mac: MacStr::empty() },
        }
    }
}
