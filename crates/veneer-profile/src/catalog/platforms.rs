//! Platform catalog — a motherboard/OEM identity spans three SMBIOS-adjacent
//! components (Type 1 system, Type 2/3 board+chassis, Type 0 firmware/ACPI),
//! which all co-vary by the board. A `Platform` bundles those three specs so
//! a machine picks one coherent platform identity.

use crate::*;

#[derive(Clone, Copy)]
pub struct Platform {
    pub system: SystemSpec,
    pub board: BoardSpec,
    pub firmware: FirmwareSpec,
}

pub const ASUS_ROG_X670E_E: Platform = Platform {
    system: SystemSpec {
        manufacturer: SmbiosLong::from_static("ASUSTeK COMPUTER INC."),
        product: SmbiosLong::from_static("ROG STRIX X670E-E GAMING WIFI"),
        version: SmbiosShort::from_static("Rev 1.xx"),
    },
    board: BoardSpec {
        baseboard_manufacturer: SmbiosLong::from_static("ASUSTeK COMPUTER INC."),
        baseboard_product: SmbiosLong::from_static("ROG STRIX X670E-E GAMING WIFI"),
        host_bridge_id: 0x29C0_8086,
        lpc_id: 0x790E_1022,
        sata_id: 0x7901_1022,
        smbus_id: 0x790B_1022,
        xhci_id: 0x149C_1022,
    },
    firmware: FirmwareSpec {
        bios_vendor: SmbiosShort::from_static("American Megatrends Inc."),
        bios_version: SmbiosShort::from_static("1820"),
        bios_date: SmbiosShort::from_static("09/05/2024"),
        acpi_oem_id: ProfileStr::from_static("ALASKA"),
        acpi_oem_table_id: ProfileStr::from_static("A M I"),
        acpi_creator_id: ProfileStr::from_static("AMI "),
    },
};

pub const LENOVO_THINKPAD_T14_G3: Platform = Platform {
    system: SystemSpec {
        manufacturer: SmbiosLong::from_static("LENOVO"),
        product: SmbiosLong::from_static("ThinkPad T14 Gen 3"),
        version: SmbiosShort::from_static("ThinkPad T14 Gen 3"),
    },
    board: BoardSpec {
        baseboard_manufacturer: SmbiosLong::from_static("LENOVO"),
        baseboard_product: SmbiosLong::from_static("21CF"),
        host_bridge_id: 0x29C0_8086,
        lpc_id: 0x5182_8086,
        sata_id: 0x51D3_8086, // Alder Lake-P SATA AHCI (0x7AE2 = -S desktop, wrong block)
        smbus_id: 0x51A3_8086, // Alder Lake-P SMBus (0x7AA3 = -S desktop, wrong block)
        xhci_id: 0x51ED_8086,
    },
    firmware: FirmwareSpec {
        bios_vendor: SmbiosShort::from_static("LENOVO"),
        bios_version: SmbiosShort::from_static("R23ET75W (1.50)"),
        bios_date: SmbiosShort::from_static("06/14/2024"),
        acpi_oem_id: ProfileStr::from_static("LENOVO"),
        acpi_oem_table_id: ProfileStr::from_static("TP-R23  "),
        acpi_creator_id: ProfileStr::from_static("LNVO"),
    },
};

pub const ASUS_ROG_NUC: Platform = Platform {
    system: SystemSpec {
        manufacturer: SmbiosLong::from_static("ASUS"),
        product: SmbiosLong::from_static("ROG NUC"),
        version: SmbiosShort::from_static("1.0"),
    },
    board: BoardSpec {
        baseboard_manufacturer: SmbiosLong::from_static("ASUS"),
        baseboard_product: SmbiosLong::from_static("ROG NUC 970"),
        host_bridge_id: 0x29C0_8086,
        lpc_id: 0x790E_1022,
        sata_id: 0x7901_1022,
        smbus_id: 0x790B_1022,
        xhci_id: 0x15B6_1022,
    },
    firmware: FirmwareSpec {
        bios_vendor: SmbiosShort::from_static("Insyde Corp."),
        bios_version: SmbiosShort::from_static("RNUC04.0050"),
        bios_date: SmbiosShort::from_static("11/22/2024"),
        acpi_oem_id: ProfileStr::from_static("_ASUS_"),
        acpi_oem_table_id: ProfileStr::from_static("Notebook"),
        acpi_creator_id: ProfileStr::from_static("ASUS"),
    },
};
