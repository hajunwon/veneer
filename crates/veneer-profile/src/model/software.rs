//! OS-level identity. Changing these can break Windows activation / SID /
//! login, so veneer does NOT enforce them — the schema is kept so a
//! downstream tool (fake-vgc / vmlatch) can read the same profile and apply.

use crate::primitives::{ProfileStr, UuidStr};

pub type OsString = ProfileStr<64>;

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct OsProfile {
    pub product_name: OsString,
    pub build_lab: OsString,
    pub product_id: OsString,
    pub edition_id: OsString,
    pub computer_name: OsString,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct RegistryProfile {
    pub machine_guid: UuidStr,
    pub hardware_profile_guid: UuidStr,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct VolumeProfile {
    pub c_drive_serial: ProfileStr<16>,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct LocaleProfile {
    pub language: ProfileStr<16>,
    pub timezone: ProfileStr<32>,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct SoftwareModel {
    pub os: OsProfile,
    pub registry: RegistryProfile,
    pub volume: VolumeProfile,
    pub locale: LocaleProfile,
}

impl SoftwareModel {
    pub const fn empty() -> Self {
        Self {
            os: OsProfile {
                product_name: OsString::empty(),
                build_lab: OsString::empty(),
                product_id: OsString::empty(),
                edition_id: OsString::empty(),
                computer_name: OsString::empty(),
            },
            registry: RegistryProfile {
                machine_guid: UuidStr::empty(),
                hardware_profile_guid: UuidStr::empty(),
            },
            volume: VolumeProfile { c_drive_serial: ProfileStr::empty() },
            locale: LocaleProfile {
                language: ProfileStr::empty(),
                timezone: ProfileStr::empty(),
            },
        }
    }
}
