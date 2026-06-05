//! NIC catalog — one `NetworkSpec` per model. `oui` is the prefix the
//! per-unit MAC is generated under; for onboard NICs it commonly tracks the
//! board vendor's OUI block, so these pair with a typical board.

use crate::*;

pub const INTEL_I225V: NetworkSpec =
    NetworkSpec { pci_id: 0x15F3_8086, phy_id: 0x67C9, oui: [0x04, 0x7C, 0x16] }; // ASUS OUI

// I226-V is integrated MAC+PHY (no external MII PHY); phy_id is informational.
pub const INTEL_I226V: NetworkSpec =
    NetworkSpec { pci_id: 0x125C_8086, phy_id: 0x0005, oui: [0xE0, 0x4F, 0x43] }; // verified 8086:125C; ASUS NUC OUI

pub const INTEL_I219V: NetworkSpec =
    NetworkSpec { pci_id: 0x1A1F_8086, phy_id: 0x0D71, oui: [0x00, 0x1B, 0x21] }; // Intel OUI
