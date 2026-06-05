//! NVMe SSD catalog — one `StorageSpec` per model (model string, controller
//! PCI id, IEEE OUI, firmware rev). The per-unit serial is generated later.

use crate::*;

pub const WD_BLACK_SN850X_2TB: StorageSpec = StorageSpec {
    slot: SmbiosShort::from_static("nvme0:0"),
    model: SmbiosLong::from_static("WD_BLACK SN850X 2000GB"),
    firmware_rev: ProfileStr::from_static("620361WD"),
    ieee_oui: [0x44, 0x1B, 0x00], // WD/SanDisk OUI 00:1B:44 (LE)
    pci_id: 0x5011_15B7,          // SanDisk/WD 0x15B7
};

pub const SAMSUNG_980PRO_1TB: StorageSpec = StorageSpec {
    slot: SmbiosShort::from_static("nvme0:0"),
    model: SmbiosLong::from_static("Samsung SSD 980 PRO 1TB"),
    firmware_rev: ProfileStr::from_static("5B2QGXA7"),
    ieee_oui: [0x38, 0x25, 0x00], // Samsung OUI 00:25:38 (LE)
    pci_id: 0xA80A_144D,          // Samsung 0x144D
};

pub const CRUCIAL_T700_1TB: StorageSpec = StorageSpec {
    slot: SmbiosShort::from_static("nvme0:0"),
    model: SmbiosLong::from_static("Crucial T700 1TB"),
    // UNVERIFIED: Micron IEEE OUI and a real T700 FR string could not be
    // confirmed — capture from `nvme id-ctrl` on a real T700 before relying
    // on this profile. pci_id is verified.
    firmware_rev: ProfileStr::from_static("PACR5111"),
    ieee_oui: [0x3E, 0xA2, 0x00], // UNVERIFIED Micron OUI 00:A2:3E (LE)
    pci_id: 0x5419_C0A9,          // verified Micron 0xC0A9
};
