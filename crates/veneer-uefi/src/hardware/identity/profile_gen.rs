//! Policy-driven profile generation. A `QuickPolicy` selects a base
//! template (CPU brand, vendor strings, SMBIOS pillars) and we fill the
//! per-instance fields (UUID, serial, MAC) with RDRAND-derived random.
//!
//! The output `Profile` is what gets cached in NVRAM. On NVRAM-miss
//! boots we run this once; on NVRAM-hit boots we skip it and reuse the
//! cached profile so the guest sees the same machine identity.

#![allow(dead_code)]

use core::arch::asm;

use crate::infra::config::QuickPolicy;
use crate::hardware::identity::profile::{
    AudioProfile, BoardProfile, CpuBrand, CpuProfile, CpuVendor, DiskProfile, GpuProfile,
    HardwareProfile, MacStr, MemoryProfile, NetworkProfile, Profile, ProfileName, ProfileStr,
    SmbiosLong, SmbiosProfile, SmbiosShort, SoftwareProfile, UuidStr,
};

// ───── RDRAND wrapper ──────────────────────────────────────────────────

pub struct Rdrand;

impl Rdrand {
    /// Read a 64-bit value via the `RDRAND` instruction. Retries up to
    /// 10 times if hardware reports entropy starvation (CF=0). Falls
    /// back to a deterministic constant on persistent failure — should
    /// never happen on Ryzen.
    pub fn next_u64(&mut self) -> u64 {
        for _ in 0..10 {
            let v: u64;
            let ok: u64;
            unsafe {
                asm!(
                    "rdrand {0}",
                    "setc {1:l}",
                    out(reg) v,
                    out(reg) ok,
                    options(nomem, nostack),
                );
            }
            if ok != 0 {
                return v;
            }
        }
        0xDEAD_BEEF_CAFE_BABE
    }

    pub fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
}

// ───── hex helpers ──────────────────────────────────────────────────────

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn write_hex_byte(buf: &mut [u8], idx: usize, v: u8, upper: bool) {
    let table = if upper { HEX_UPPER } else { HEX_LOWER };
    buf[idx] = table[(v >> 4) as usize];
    buf[idx + 1] = table[(v & 0xF) as usize];
}

/// Random RFC-4122 v4 UUID, canonical text form (lowercase, dashes).
fn format_uuid(rng: &mut Rdrand) -> [u8; 36] {
    let lo = rng.next_u64();
    let hi = rng.next_u64();
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&lo.to_le_bytes());
    bytes[8..].copy_from_slice(&hi.to_le_bytes());
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant 10

    let mut out = [b'-'; 36];
    let positions = [0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34];
    for (i, &pos) in positions.iter().enumerate() {
        write_hex_byte(&mut out, pos, bytes[i], false);
    }
    out
}

/// Random MAC with the supplied OUI prefix. Format `XX:XX:XX:XX:XX:XX`.
fn format_mac(rng: &mut Rdrand, oui: [u8; 3]) -> [u8; 17] {
    let v = rng.next_u32();
    let octets = [oui[0], oui[1], oui[2], v as u8, (v >> 8) as u8, (v >> 16) as u8];
    let mut out = [b':'; 17];
    let positions = [0, 3, 6, 9, 12, 15];
    for (i, &pos) in positions.iter().enumerate() {
        write_hex_byte(&mut out, pos, octets[i], true);
    }
    out
}

/// Random 16-char alphanumeric (uppercase) disk serial.
fn format_disk_serial(rng: &mut Rdrand) -> [u8; 16] {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut out = [0u8; 16];
    let mut bits_left = 0u32;
    let mut pool = 0u64;
    for slot in out.iter_mut() {
        if bits_left < 6 {
            pool = rng.next_u64();
            bits_left = 64;
        }
        let idx = (pool & 0x3F) as usize % CHARSET.len();
        *slot = CHARSET[idx];
        pool >>= 6;
        bits_left -= 6;
    }
    out
}

/// Random 7-digit numeric Windows ProductID-ish identifier for SMBIOS.
fn format_smbios_serial(rng: &mut Rdrand) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = b'P';
    out[1] = b'F';
    let v = rng.next_u64();
    for i in 0..10 {
        out[i + 2] = b'0' + ((v >> (i * 4)) & 0xF) as u8 % 36 % 10 + 0;
    }
    out
}

// ───── policy templates ────────────────────────────────────────────────

const INTEL_LAPTOP: Profile = Profile {
    magic: crate::hardware::identity::profile::PROFILE_MAGIC,
    version: crate::hardware::identity::profile::PROFILE_VERSION,
    name: ProfileName::from_static("intel_laptop"),
    hardware: HardwareProfile {
        cpu: CpuProfile {
            brand: CpuBrand::from_static("Intel(R) Core(TM) i7-12700H @ 2.30GHz"),
            vendor: CpuVendor::from_static("GenuineIntel"),
            hide_hypervisor_bit: true,
            hide_hypervisor_leaf: true,
            tsc_seed: 0x1000_0000_0000_0000,
            microcode_signature: 0,
            platform_id: 0,
            // Alder Lake P-core: family 0x06, model 0x9A, stepping 0x3.
            // (ext_family=0)(ext_model=9)(0)(family=6)(model=A)(stepping=3)
            cpuid_eax_v1: 0x0009_06A3,
            cpuid_brand_idx: 0,
            cpuid_cores_override: 0,
            // 0xB3 = Intel Core i7 (SMBIOS 3.x § 7.5.2).
            smbios_processor_family: 0x00B3,
            smbios_socket: ProfileStr::from_static("FCBGA1744"),
            // Alder Lake-P: 80 KiB L1 (48 KiB L1d + 32 KiB L1i) per P-core,
            // 1.25 MiB L2 per P-core, 24 MiB shared L3.
            cache_l1_per_core_kib: 80,
            cache_l2_per_core_kib: 1280,
            cache_l3_total_kib: 24 * 1024,
            cpu_max_speed_mhz: 4700,
            cpu_current_speed_mhz: 2300,
        },
        smbios: SmbiosProfile {
            manufacturer: SmbiosLong::from_static("LENOVO"),
            product: SmbiosLong::from_static("ThinkPad T14 Gen 3"),
            serial: SmbiosShort::empty(),       // filled by RDRAND
            version: SmbiosShort::from_static("ThinkPad T14 Gen 3"),
            uuid: UuidStr::empty(),              // filled by RDRAND
            bios_vendor: SmbiosShort::from_static("LENOVO"),
            bios_version: SmbiosShort::from_static("R23ET75W (1.50)"),
            bios_date: SmbiosShort::from_static("06/14/2024"),
        },
        board: BoardProfile {
            baseboard_manufacturer: SmbiosLong::from_static("LENOVO"),
            baseboard_product: SmbiosLong::from_static("21CF"),
            baseboard_serial: SmbiosShort::empty(),
            chassis_serial: SmbiosShort::empty(),
            host_bridge_id: 0x29C0_8086, // Q35 (OVMF-compat; Alder Lake alignment = TODO)
            lpc_id: 0x5182_8086,         // Intel 600-series LPC (TODO verify)
            sata_id: 0x7AE2_8086,        // Intel 600-series SATA AHCI (TODO verify)
            smbus_id: 0x7AA3_8086,       // Intel 600-series SMBus (TODO verify)
            xhci_id: 0x51ED_8086,        // Intel 600-series (Alder Lake-P) xHCI
            acpi_oem_id: ProfileStr::from_static("LENOVO"),
            acpi_oem_table_id: ProfileStr::from_static("TP-R23  "),
            acpi_creator_id: ProfileStr::from_static("LNVO"),
        },
        memory: MemoryProfile {
            manufacturer: SmbiosShort::from_static("Samsung"),
            part_number: SmbiosShort::from_static("M425R2GA3BB0-CWMOD"),
            serial0: ProfileStr::empty(),
            serial1: ProfileStr::empty(),
            size_mb_per_dimm: 16384,
            speed_mts: 4800,
            dimm_count: 2,
        },
        gpu: GpuProfile { pci_id: 0x46A6_8086 },   // Intel Iris Xe (Alder Lake-P)
        audio: AudioProfile { pci_id: 0x51C8_8086 }, // Intel SmartSound
        network: NetworkProfile {
            mac: MacStr::empty(), // RDRAND with Intel OUI
            pci_id: 0x1A1F_8086, // Intel I219-V (TODO verify laptop NIC)
            phy_id: 0x0D71,
        },
        disk: DiskProfile {
            slot: SmbiosShort::from_static("nvme0:0"),
            serial: SmbiosShort::empty(),
            model: SmbiosLong::from_static("Samsung SSD 980 PRO 1TB"),
            firmware_rev: ProfileStr::from_static("5B2QGXA7"), // Samsung 980 PRO
            ieee_oui: [0x38, 0x25, 0x00], // Samsung OUI 00:25:38 (LE)
            pci_id: 0xA80A_144D,          // Samsung 980 PRO controller
        },
    },
    software: SoftwareProfile {
        os: crate::hardware::identity::profile::OsProfile {
            product_name: crate::hardware::identity::profile::OsString::from_static("Windows 11 Pro"),
            build_lab: crate::hardware::identity::profile::OsString::from_static(""),
            product_id: crate::hardware::identity::profile::OsString::from_static(""),
            edition_id: crate::hardware::identity::profile::OsString::from_static("Professional"),
            computer_name: crate::hardware::identity::profile::OsString::from_static(""),
        },
        registry: crate::hardware::identity::profile::RegistryProfile {
            machine_guid: UuidStr::empty(),
            hardware_profile_guid: UuidStr::empty(),
        },
        volume: crate::hardware::identity::profile::VolumeProfile { c_drive_serial: ProfileStr::empty() },
        locale: crate::hardware::identity::profile::LocaleProfile {
            language: ProfileStr::empty(),
            timezone: ProfileStr::empty(),
        },
    },
};

const AMD_DESKTOP: Profile = Profile {
    magic: crate::hardware::identity::profile::PROFILE_MAGIC,
    version: crate::hardware::identity::profile::PROFILE_VERSION,
    name: ProfileName::from_static("amd_desktop"),
    hardware: HardwareProfile {
        cpu: CpuProfile {
            brand: CpuBrand::from_static("AMD Ryzen 9 7900X 12-Core Processor"),
            vendor: CpuVendor::from_static("AuthenticAMD"),
            hide_hypervisor_bit: true,
            hide_hypervisor_leaf: true,
            tsc_seed: 0x1000_0000_0000_0000,
            microcode_signature: 0,
            platform_id: 0,
            // Zen 4 Raphael: family 0x19, model 0x61, stepping 0x2.
            // (ext_family=A)(0)(ext_model=6)(family=F)(model=1)(stepping=2)
            cpuid_eax_v1: 0x00A6_0F12,
            cpuid_brand_idx: 0,
            cpuid_cores_override: 0,
            // 0xCE = AMD Ryzen (SMBIOS 3.x § 7.5.2).
            smbios_processor_family: 0x00CE,
            smbios_socket: ProfileStr::from_static("AM5"),
            // Zen 4 Raphael: 64 KiB L1 (32 KiB L1d + 32 KiB L1i) per core,
            // 1 MiB L2 per core, 64 MiB total L3 (2 CCD × 32 MiB).
            cache_l1_per_core_kib: 64,
            cache_l2_per_core_kib: 1024,
            cache_l3_total_kib: 64 * 1024,
            cpu_max_speed_mhz: 5600,
            cpu_current_speed_mhz: 4700,
        },
        smbios: SmbiosProfile {
            manufacturer: SmbiosLong::from_static("ASUSTeK COMPUTER INC."),
            product: SmbiosLong::from_static("ROG STRIX X670E-E GAMING WIFI"),
            serial: SmbiosShort::empty(),
            version: SmbiosShort::from_static("Rev 1.xx"),
            uuid: UuidStr::empty(),
            bios_vendor: SmbiosShort::from_static("American Megatrends Inc."),
            bios_version: SmbiosShort::from_static("1820"),
            bios_date: SmbiosShort::from_static("09/05/2024"),
        },
        board: BoardProfile {
            baseboard_manufacturer: SmbiosLong::from_static("ASUSTeK COMPUTER INC."),
            baseboard_product: SmbiosLong::from_static("ROG STRIX X670E-E GAMING WIFI"),
            baseboard_serial: SmbiosShort::empty(),
            chassis_serial: SmbiosShort::empty(),
            host_bridge_id: 0x29C0_8086, // Q35 (OVMF-compat; AMD-chipset alignment = TODO)
            lpc_id: 0x790E_1022,         // AMD FCH LPC
            sata_id: 0x7901_1022,        // AMD FCH SATA AHCI
            smbus_id: 0x790B_1022,       // AMD FCH SMBus
            xhci_id: 0x149C_1022,        // AMD FCH USB 3.1 xHCI
            acpi_oem_id: ProfileStr::from_static("ALASKA"),
            acpi_oem_table_id: ProfileStr::from_static("A M I"),
            acpi_creator_id: ProfileStr::from_static("AMI "),
        },
        memory: MemoryProfile {
            manufacturer: SmbiosShort::from_static("Corsair"),
            part_number: SmbiosShort::from_static("CMK32GX5M2B5200C40"),
            serial0: ProfileStr::empty(),
            serial1: ProfileStr::empty(),
            size_mb_per_dimm: 16384,
            speed_mts: 5200,
            dimm_count: 2,
        },
        gpu: GpuProfile { pci_id: 0x164E_1002 },   // AMD Raphael iGPU (RDNA2)
        audio: AudioProfile { pci_id: 0x1457_1022 }, // AMD FCH HD Audio
        network: NetworkProfile {
            mac: MacStr::empty(),
            pci_id: 0x15F3_8086, // Intel I225-V
            phy_id: 0x67C9,
        },
        disk: DiskProfile {
            slot: SmbiosShort::from_static("nvme0:0"),
            serial: SmbiosShort::empty(),
            model: SmbiosLong::from_static("WD_BLACK SN850X 2000GB"),
            firmware_rev: ProfileStr::from_static("620361WD"), // TODO verify SN850X rev
            ieee_oui: [0x44, 0x1B, 0x00], // WD/SanDisk OUI 00:1B:44 (LE) TODO verify
            pci_id: 0x5011_15B7,          // WD SN850X (SanDisk 0x15B7) TODO verify
        },
    },
    software: SoftwareProfile {
        os: crate::hardware::identity::profile::OsProfile {
            product_name: crate::hardware::identity::profile::OsString::from_static("Windows 11 Pro"),
            build_lab: crate::hardware::identity::profile::OsString::from_static(""),
            product_id: crate::hardware::identity::profile::OsString::from_static(""),
            edition_id: crate::hardware::identity::profile::OsString::from_static("Professional"),
            computer_name: crate::hardware::identity::profile::OsString::from_static(""),
        },
        registry: crate::hardware::identity::profile::RegistryProfile {
            machine_guid: UuidStr::empty(),
            hardware_profile_guid: UuidStr::empty(),
        },
        volume: crate::hardware::identity::profile::VolumeProfile { c_drive_serial: ProfileStr::empty() },
        locale: crate::hardware::identity::profile::LocaleProfile {
            language: ProfileStr::empty(),
            timezone: ProfileStr::empty(),
        },
    },
};

const RYZEN_NUC: Profile = Profile {
    magic: crate::hardware::identity::profile::PROFILE_MAGIC,
    version: crate::hardware::identity::profile::PROFILE_VERSION,
    name: ProfileName::from_static("ryzen_nuc"),
    hardware: HardwareProfile {
        cpu: CpuProfile {
            brand: CpuBrand::from_static("AMD Ryzen 7 7840HS w/ Radeon 780M Graphics"),
            vendor: CpuVendor::from_static("AuthenticAMD"),
            hide_hypervisor_bit: true,
            hide_hypervisor_leaf: true,
            tsc_seed: 0x1000_0000_0000_0000,
            microcode_signature: 0,
            platform_id: 0,
            // Zen 4 Phoenix: family 0x19, model 0x74, stepping 0x1.
            // (ext_family=A)(0)(ext_model=7)(family=F)(model=4)(stepping=1)
            cpuid_eax_v1: 0x00A7_0F41,
            cpuid_brand_idx: 0,
            cpuid_cores_override: 0,
            // 0xCE = AMD Ryzen (SMBIOS 3.x § 7.5.2).
            smbios_processor_family: 0x00CE,
            smbios_socket: ProfileStr::from_static("FP7"),
            // Zen 4 Phoenix: 64 KiB L1 per core, 1 MiB L2 per core,
            // 16 MiB total L3 (single CCX).
            cache_l1_per_core_kib: 64,
            cache_l2_per_core_kib: 1024,
            cache_l3_total_kib: 16 * 1024,
            cpu_max_speed_mhz: 5100,
            cpu_current_speed_mhz: 3800,
        },
        smbios: SmbiosProfile {
            manufacturer: SmbiosLong::from_static("ASUS"),
            product: SmbiosLong::from_static("ROG NUC"),
            serial: SmbiosShort::empty(),
            version: SmbiosShort::from_static("1.0"),
            uuid: UuidStr::empty(),
            bios_vendor: SmbiosShort::from_static("Insyde Corp."),
            bios_version: SmbiosShort::from_static("RNUC04.0050"),
            bios_date: SmbiosShort::from_static("11/22/2024"),
        },
        board: BoardProfile {
            baseboard_manufacturer: SmbiosLong::from_static("ASUS"),
            baseboard_product: SmbiosLong::from_static("ROG NUC 970"),
            baseboard_serial: SmbiosShort::empty(),
            chassis_serial: SmbiosShort::empty(),
            host_bridge_id: 0x29C0_8086, // Q35 (OVMF-compat; Phoenix alignment = TODO)
            lpc_id: 0x790E_1022,         // AMD FCH LPC
            sata_id: 0x7901_1022,        // AMD FCH SATA AHCI
            smbus_id: 0x790B_1022,       // AMD FCH SMBus
            xhci_id: 0x15B6_1022,        // AMD Phoenix USB xHCI
            acpi_oem_id: ProfileStr::from_static("_ASUS_"),
            acpi_oem_table_id: ProfileStr::from_static("Notebook"),
            acpi_creator_id: ProfileStr::from_static("ASUS"),
        },
        memory: MemoryProfile {
            manufacturer: SmbiosShort::from_static("Crucial"),
            part_number: SmbiosShort::from_static("CT16G56C46S5"),
            serial0: ProfileStr::empty(),
            serial1: ProfileStr::empty(),
            size_mb_per_dimm: 16384,
            speed_mts: 5600,
            dimm_count: 2,
        },
        gpu: GpuProfile { pci_id: 0x15BF_1002 },   // AMD Radeon 780M (Phoenix)
        audio: AudioProfile { pci_id: 0x15E3_1022 }, // AMD Rembrandt HD Audio
        network: NetworkProfile {
            mac: MacStr::empty(),
            pci_id: 0x43F0_8086, // Intel I226-V (TODO verify NUC NIC)
            phy_id: 0x67C9,
        },
        disk: DiskProfile {
            slot: SmbiosShort::from_static("nvme0:0"),
            serial: SmbiosShort::empty(),
            model: SmbiosLong::from_static("Crucial T700 1TB"),
            firmware_rev: ProfileStr::from_static("PACR5111"), // TODO verify T700 rev
            ieee_oui: [0x3E, 0xA2, 0x00], // Micron OUI 00:A2:3E (LE) TODO verify
            pci_id: 0x5419_C0A9,          // Micron T700 (Micron 0xC0A9) TODO verify
        },
    },
    software: SoftwareProfile {
        os: crate::hardware::identity::profile::OsProfile {
            product_name: crate::hardware::identity::profile::OsString::from_static("Windows 11 Pro"),
            build_lab: crate::hardware::identity::profile::OsString::from_static(""),
            product_id: crate::hardware::identity::profile::OsString::from_static(""),
            edition_id: crate::hardware::identity::profile::OsString::from_static("Professional"),
            computer_name: crate::hardware::identity::profile::OsString::from_static(""),
        },
        registry: crate::hardware::identity::profile::RegistryProfile {
            machine_guid: UuidStr::empty(),
            hardware_profile_guid: UuidStr::empty(),
        },
        volume: crate::hardware::identity::profile::VolumeProfile { c_drive_serial: ProfileStr::empty() },
        locale: crate::hardware::identity::profile::LocaleProfile {
            language: ProfileStr::empty(),
            timezone: ProfileStr::empty(),
        },
    },
};

// ───── public entry ─────────────────────────────────────────────────────

pub fn template_for(policy: QuickPolicy) -> Profile {
    match policy {
        QuickPolicy::IntelLaptop => INTEL_LAPTOP,
        QuickPolicy::AmdDesktop => AMD_DESKTOP,
        QuickPolicy::RyzenNuc => RYZEN_NUC,
    }
}

/// Per-policy OUI for the random MAC. Picked so the synthesised MAC
/// doesn't collide with any VMware OUI prefix (00:0C:29 / 00:1C:14 /
/// 00:50:56 / 00:05:69) — those would self-report "VMware NIC" to any
/// guest with an OUI table.
fn oui_for(policy: QuickPolicy) -> [u8; 3] {
    match policy {
        QuickPolicy::IntelLaptop => [0x00, 0x1B, 0x21], // Intel
        QuickPolicy::AmdDesktop => [0x04, 0x7C, 0x16], // ASUSTeK
        QuickPolicy::RyzenNuc => [0xE0, 0x4F, 0x43],   // ASUS NUC range
    }
}

/// Fill in the random-per-instance fields (UUID, serial, MAC, disk
/// serial). Run once on NVRAM-miss, then cache.
pub fn build_profile(policy: QuickPolicy) -> Profile {
    let mut p = template_for(policy);
    let mut rng = Rdrand;

    let uuid = format_uuid(&mut rng);
    p.hardware.smbios.uuid = UuidStr::from_bytes(&uuid);

    let serial = format_smbios_serial(&mut rng);
    p.hardware.smbios.serial = SmbiosShort::from_bytes(&serial);

    let mac = format_mac(&mut rng, oui_for(policy));
    p.hardware.network.mac = MacStr::from_bytes(&mac);

    let disk_serial = format_disk_serial(&mut rng);
    p.hardware.disk.serial = SmbiosShort::from_bytes(&disk_serial);

    // Per-DIMM serials + board/chassis serials are per-instance too.
    let dimm0 = format_disk_serial(&mut rng);
    p.hardware.memory.serial0 = ProfileStr::from_bytes(&dimm0);
    let dimm1 = format_disk_serial(&mut rng);
    p.hardware.memory.serial1 = ProfileStr::from_bytes(&dimm1);

    let board_serial = format_smbios_serial(&mut rng);
    p.hardware.board.baseboard_serial = SmbiosShort::from_bytes(&board_serial);
    let chassis_serial = format_smbios_serial(&mut rng);
    p.hardware.board.chassis_serial = SmbiosShort::from_bytes(&chassis_serial);

    p
}
