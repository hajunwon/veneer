//! System memory (SMBIOS Type 16/17). One manufacturer/part across the
//! populated DIMMs (spec); per-DIMM serials are per-unit (instance).

use crate::primitives::{ProfileStr, SmbiosShort};

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct MemorySpec {
    pub manufacturer: SmbiosShort,
    pub part_number: SmbiosShort,
    pub size_mb_per_dimm: u32,
    pub speed_mts: u16,
    pub dimm_count: u8,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct MemoryInstance {
    pub serial0: ProfileStr<16>,
    pub serial1: ProfileStr<16>,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct MemoryComponent {
    pub spec: MemorySpec,
    pub instance: MemoryInstance,
}

impl MemoryComponent {
    pub const fn empty() -> Self {
        Self {
            spec: MemorySpec {
                manufacturer: SmbiosShort::empty(),
                part_number: SmbiosShort::empty(),
                size_mb_per_dimm: 0,
                speed_mts: 0,
                dimm_count: 0,
            },
            instance: MemoryInstance {
                serial0: ProfileStr::empty(),
                serial1: ProfileStr::empty(),
            },
        }
    }
}
