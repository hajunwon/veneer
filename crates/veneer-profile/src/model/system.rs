//! System enclosure identity (SMBIOS Type 1). Manufacturer/product/version
//! are spec; the system serial + UUID are per-unit (instance).

use crate::primitives::{SmbiosLong, SmbiosShort, UuidStr};

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct SystemSpec {
    pub manufacturer: SmbiosLong,
    pub product: SmbiosLong,
    pub version: SmbiosShort,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct SystemInstance {
    pub serial: SmbiosShort,
    pub uuid: UuidStr,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct SystemComponent {
    pub spec: SystemSpec,
    pub instance: SystemInstance,
}

impl SystemComponent {
    pub const fn empty() -> Self {
        Self {
            spec: SystemSpec {
                manufacturer: SmbiosLong::empty(),
                product: SmbiosLong::empty(),
                version: SmbiosShort::empty(),
            },
            instance: SystemInstance {
                serial: SmbiosShort::empty(),
                uuid: UuidStr::empty(),
            },
        }
    }
}
