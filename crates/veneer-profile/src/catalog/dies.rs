//! Verified AMD IOMMU per-die values, read verbatim from real-hardware
//! Linux dmesg (`AMD-Vi: Extended features (...)`) on primary-source pages,
//! attributed to a specific CPU. EFR is fixed by the die (shared across a
//! generation's SKUs), so a profile picks the die its CPU belongs to.
//!
//! Source notes per entry. `pci_id` is the on-die IOMMU PCI function
//! device:vendor; only filled where independently verified (lspci), else 0.

use crate::model::iommu::IommuModel;

/// Zen4 "Raphael" desktop chiplet (7600X/7700X/7900X/7950X + all X3D).
/// XTSup absent. dmesg: `0x246577efa2254afa, 0x0: PPR NX GT IA GA PC GA_vAPIC`.
/// IOMMU PCI id 1022:14d9 confirmed via lspci on a 7900X board.
pub const ZEN4_RAPHAEL: IommuModel = IommuModel::new(0x246577efa2254afa, 0x0, 0x14D9_1022);

/// Zen4 "Phoenix"/"Hawk Point" monolithic APU/mobile (8945HS/8845HS, 7040).
/// XTSup present. dmesg: `0x246577efa2054ada, 0x0`. pci_id unverified.
pub const ZEN4_PHOENIX: IommuModel = IommuModel::new(0x246577efa2054ada, 0x0, 0);

/// Zen3 "Vermeer" desktop chiplet (5600X/5800X/5900X/5950X, 5800X3D/5700X3D).
/// XTSup absent. dmesg (5 independent reads identical): `0x58f77ef22294a5a`.
pub const ZEN3_VERMEER: IommuModel = IommuModel::new(0x058f_77ef_2229_4a5a, 0x0, 0);

/// Zen3 "Cezanne" monolithic APU (5600G/5700G desktop, 5700U mobile).
/// XTSup present. dmesg: `0x206d73ef22254ade, 0x0`.
pub const ZEN3_CEZANNE: IommuModel = IommuModel::new(0x206d_73ef_2225_4ade, 0x0, 0);

/// Zen3 "Milan" server (EPYC 7003, e.g. 7313P). XTSup present, advertises
/// SNP, drops GT/GA_vAPIC. dmesg: `0x841f77e022094ace, 0x0` (4 IOMMU
/// instances, all identical).
pub const ZEN3_MILAN: IommuModel = IommuModel::new(0x841f_77e0_2209_4ace, 0x0, 0);
