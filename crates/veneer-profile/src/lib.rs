#![no_std]
#![allow(dead_code)]
//! Synthetic guest-visible identity profile.
//!
//! Layered:
//!   - `model`      — canonical truth, by physical component. Each component
//!                    splits model-class `spec` (from `catalog`) from per-unit
//!                    `instance` (generated + persisted); peripherals carry a
//!                    `delivery` mode (emulated / passthrough / absent).
//!   - `catalog`    — verified real-hardware parts that fill `spec`.
//!   - `coherence`  — cross-surface invariant validator.
//!   - `toml`       — overlay parser (schema is byte-compatible with vmlatch).
//!
//! Emitters (in veneer-uefi) read this model to render each surface; nothing
//! here knows how the guest accesses hardware. The whole `Profile` serializes
//! to NVRAM as a raw `repr(C, packed)` byte copy, so any layout change must
//! bump `PROFILE_VERSION` (stale caches are then rejected and regenerated).

pub mod primitives;
pub mod model;
pub mod catalog;
pub mod identity;
pub mod coherence;
pub mod toml;

pub use primitives::*;
pub use model::HardwareModel;
pub use model::delivery::DeliveryMode;
pub use model::iommu::IommuModel;
pub use model::cpu::{CpuComponent, CpuSpec};
pub use model::memory::{MemoryComponent, MemoryInstance, MemorySpec};
pub use model::storage::{StorageComponent, StorageInstance, StorageSpec};
pub use model::gpu::{GpuComponent, GpuSpec};
pub use model::audio::{AudioComponent, AudioSpec};
pub use model::network::{NetworkComponent, NetworkInstance, NetworkSpec};
pub use model::board::{BoardComponent, BoardInstance, BoardSpec};
pub use model::firmware::{FirmwareComponent, FirmwareSpec};
pub use model::system::{SystemComponent, SystemInstance, SystemSpec};
pub use model::software::{
    LocaleProfile, OsProfile, OsString, RegistryProfile, SoftwareModel, VolumeProfile,
};

// ───── Profile root ─────────────────────────────────────────────────────

/// On-disk / on-NVRAM serialization magic ("VNPF").
pub const PROFILE_MAGIC: u32 = 0x56_4E_50_46;
/// Bumped at every layout-breaking change. Stale caches from older veneer
/// builds get rejected by `Profile::is_valid` and regenerated.
/// v7: model re-architected into per-component spec/instance + delivery,
///     CPU gained an on-die IommuModel (EFR/EFR2/pci_id), SMBIOS storage
///     split into `system` (Type 1) + `firmware` (Type 0) + `board`.
pub const PROFILE_VERSION: u32 = 7;

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Profile {
    pub magic: u32,
    pub version: u32,
    pub name: ProfileName,
    pub hardware: HardwareModel,
    pub software: SoftwareModel,
}

impl Profile {
    pub const fn empty() -> Self {
        Self {
            magic: PROFILE_MAGIC,
            version: PROFILE_VERSION,
            name: ProfileName::empty(),
            hardware: HardwareModel::empty(),
            software: SoftwareModel::empty(),
        }
    }

    /// Sanity-check a freshly loaded profile (e.g. from NVRAM). Catches stale
    /// binary layouts from previous veneer versions.
    pub fn is_valid(&self) -> bool {
        let magic = unsafe { core::ptr::addr_of!(self.magic).read_unaligned() };
        let version = unsafe { core::ptr::addr_of!(self.version).read_unaligned() };
        magic == PROFILE_MAGIC && version == PROFILE_VERSION
    }
}

// ───── Legacy stub kept for back-compat with v0.6 callers ──────────────

#[derive(Debug, Clone, Copy)]
pub struct LegacyDefaults {
    pub tsc_seed: u64,
    pub vmmcall_signature: u64,
}

pub const DEFAULT: LegacyDefaults = LegacyDefaults {
    tsc_seed: 0x1000_0000_0000_0000,
    vmmcall_signature: 0,
};
