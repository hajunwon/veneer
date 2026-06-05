//! HD Audio controller catalog — PCI identity per model.

use crate::*;

pub const AMD_FCH_HDA: AudioSpec = AudioSpec { pci_id: 0x1457_1022 };
pub const AMD_REMBRANDT_HDA: AudioSpec = AudioSpec { pci_id: 0x15E3_1022 };
pub const INTEL_SMARTSOUND: AudioSpec = AudioSpec { pci_id: 0x51C8_8086 };
