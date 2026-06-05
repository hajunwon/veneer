//! GPU catalog — PCI identity per model.

use crate::*;

pub const AMD_RAPHAEL_IGPU: GpuSpec = GpuSpec { pci_id: 0x164E_1002 }; // RDNA2 iGPU
pub const AMD_RADEON_780M: GpuSpec = GpuSpec { pci_id: 0x15BF_1002 };  // Phoenix iGPU
pub const INTEL_IRIS_XE: GpuSpec = GpuSpec { pci_id: 0x46A6_8086 };    // Alder Lake-P
