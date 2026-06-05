//! Firmware / BIOS + ACPI table identity. All model-class (spec).

use crate::primitives::{ProfileStr, SmbiosShort};

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct FirmwareSpec {
    pub bios_vendor: SmbiosShort,
    pub bios_version: SmbiosShort,
    pub bios_date: SmbiosShort,
    /// ACPI table OEM identity (replaces the hard-coded "VENEER"/"VNEE").
    pub acpi_oem_id: ProfileStr<6>,
    pub acpi_oem_table_id: ProfileStr<8>,
    pub acpi_creator_id: ProfileStr<4>,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct FirmwareComponent {
    pub spec: FirmwareSpec,
}

impl FirmwareComponent {
    pub const fn empty() -> Self {
        Self {
            spec: FirmwareSpec {
                bios_vendor: SmbiosShort::empty(),
                bios_version: SmbiosShort::empty(),
                bios_date: SmbiosShort::empty(),
                acpi_oem_id: ProfileStr::empty(),
                acpi_oem_table_id: ProfileStr::empty(),
                acpi_creator_id: ProfileStr::empty(),
            },
        }
    }
}
