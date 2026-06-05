//! Canonical hardware model — the single source of truth for "what machine
//! are we", organized by physical component. Each component separates
//! model-class facts (`spec`, filled from the catalog) from per-unit
//! identifiers (`instance`, generated + persisted). Peripherals additionally
//! carry a `delivery` mode (emulated vs passthrough vs absent).
//!
//! Emitters (in veneer-uefi) read this model and render each observation
//! surface (CPUID / SMBIOS / ACPI / PCI / NVMe). Nothing here knows how the
//! guest accesses hardware — that is the runtime's concern.

pub mod delivery;
pub mod iommu;

pub mod cpu;
pub mod memory;
pub mod storage;
pub mod gpu;
pub mod audio;
pub mod network;
pub mod board;
pub mod firmware;
pub mod system;
pub mod software;

use audio::AudioComponent;
use board::BoardComponent;
use cpu::CpuComponent;
use firmware::FirmwareComponent;
use gpu::GpuComponent;
use memory::MemoryComponent;
use network::NetworkComponent;
use storage::StorageComponent;
use system::SystemComponent;

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct HardwareModel {
    pub cpu: CpuComponent,
    pub memory: MemoryComponent,
    pub system: SystemComponent,
    pub board: BoardComponent,
    pub firmware: FirmwareComponent,
    pub gpu: GpuComponent,
    pub audio: AudioComponent,
    pub network: NetworkComponent,
    pub storage: StorageComponent,
}

impl HardwareModel {
    pub const fn empty() -> Self {
        Self {
            cpu: CpuComponent::empty(),
            memory: MemoryComponent::empty(),
            system: SystemComponent::empty(),
            board: BoardComponent::empty(),
            firmware: FirmwareComponent::empty(),
            gpu: GpuComponent::empty(),
            audio: AudioComponent::empty(),
            network: NetworkComponent::empty(),
            storage: StorageComponent::empty(),
        }
    }
}
