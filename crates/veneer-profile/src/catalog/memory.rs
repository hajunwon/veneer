//! Memory-kit catalog — one `MemorySpec` per kit. Per-DIMM serials are
//! generated later.

use crate::*;

pub const CORSAIR_DDR5_5200_2X16: MemorySpec = MemorySpec {
    manufacturer: SmbiosShort::from_static("Corsair"),
    part_number: SmbiosShort::from_static("CMK32GX5M2B5200C40"),
    size_mb_per_dimm: 16384,
    speed_mts: 5200,
    dimm_count: 2,
};

pub const SAMSUNG_DDR5_4800_2X16: MemorySpec = MemorySpec {
    manufacturer: SmbiosShort::from_static("Samsung"),
    part_number: SmbiosShort::from_static("M425R2GA3BB0-CWMOD"),
    size_mb_per_dimm: 16384,
    speed_mts: 4800,
    dimm_count: 2,
};

pub const CRUCIAL_DDR5_5600_2X16: MemorySpec = MemorySpec {
    manufacturer: SmbiosShort::from_static("Crucial"),
    part_number: SmbiosShort::from_static("CT16G56C46S5"),
    size_mb_per_dimm: 16384,
    speed_mts: 5600,
    dimm_count: 2,
};
