//! Reference machines — real parts composed into a coherent whole. A machine
//! picks one part from each catalog module; `machine()` wires them with empty
//! per-unit instance fields (filled later by identity generation). Mixing a
//! new machine is a one-line const here; the runtime coherence validator
//! checks the combination.

use crate::catalog::platforms::Platform;
use crate::catalog::{audio, cpus, disks, gpus, memory, nics, platforms};
use crate::*;

const COMMON_SOFTWARE: SoftwareModel = SoftwareModel {
    os: OsProfile {
        product_name: OsString::from_static("Windows 11 Pro"),
        build_lab: OsString::from_static(""),
        product_id: OsString::from_static(""),
        edition_id: OsString::from_static("Professional"),
        computer_name: OsString::from_static(""),
    },
    registry: RegistryProfile {
        machine_guid: UuidStr::empty(),
        hardware_profile_guid: UuidStr::empty(),
    },
    volume: VolumeProfile { c_drive_serial: ProfileStr::empty() },
    locale: LocaleProfile { language: ProfileStr::empty(), timezone: ProfileStr::empty() },
};

#[allow(clippy::too_many_arguments)]
const fn machine(
    name: &'static str,
    cpu: CpuSpec,
    plat: Platform,
    mem: MemorySpec,
    disk: StorageSpec,
    nic: NetworkSpec,
    gpu: GpuSpec,
    aud: AudioSpec,
) -> Profile {
    Profile {
        magic: PROFILE_MAGIC,
        version: PROFILE_VERSION,
        name: ProfileName::from_static(name),
        hardware: HardwareModel {
            cpu: CpuComponent { spec: cpu },
            memory: MemoryComponent {
                spec: mem,
                instance: MemoryInstance { serial0: ProfileStr::empty(), serial1: ProfileStr::empty() },
            },
            system: SystemComponent {
                spec: plat.system,
                instance: SystemInstance { serial: SmbiosShort::empty(), uuid: UuidStr::empty() },
            },
            board: BoardComponent {
                spec: plat.board,
                instance: BoardInstance {
                    baseboard_serial: SmbiosShort::empty(),
                    chassis_serial: SmbiosShort::empty(),
                },
            },
            firmware: FirmwareComponent { spec: plat.firmware },
            gpu: GpuComponent { delivery: DeliveryMode::EMULATED, spec: gpu },
            audio: AudioComponent { delivery: DeliveryMode::EMULATED, spec: aud },
            network: NetworkComponent {
                delivery: DeliveryMode::EMULATED,
                spec: nic,
                instance: NetworkInstance { mac: MacStr::empty() },
            },
            storage: StorageComponent {
                delivery: DeliveryMode::EMULATED,
                spec: disk,
                instance: StorageInstance { serial: SmbiosShort::empty() },
            },
        },
        software: COMMON_SOFTWARE,
    }
}

pub const AMD_DESKTOP: Profile = machine(
    "amd_desktop",
    cpus::RYZEN_9_7900X,
    platforms::ASUS_ROG_X670E_E,
    memory::CORSAIR_DDR5_5200_2X16,
    disks::WD_BLACK_SN850X_2TB,
    nics::INTEL_I225V,
    gpus::AMD_RAPHAEL_IGPU,
    audio::AMD_FCH_HDA,
);

pub const RYZEN_NUC: Profile = machine(
    "ryzen_nuc",
    cpus::RYZEN_7_7840HS,
    platforms::ASUS_ROG_NUC,
    memory::CRUCIAL_DDR5_5600_2X16,
    disks::CRUCIAL_T700_1TB,
    nics::INTEL_I226V,
    gpus::AMD_RADEON_780M,
    audio::AMD_REMBRANDT_HDA,
);

pub const INTEL_LAPTOP: Profile = machine(
    "intel_laptop",
    cpus::CORE_I7_12700H,
    platforms::LENOVO_THINKPAD_T14_G3,
    memory::SAMSUNG_DDR5_4800_2X16,
    disks::SAMSUNG_980PRO_1TB,
    nics::INTEL_I219V,
    gpus::INTEL_IRIS_XE,
    audio::INTEL_SMARTSOUND,
);
