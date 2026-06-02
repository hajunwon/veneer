#![no_std]
#![allow(dead_code)]
//! Synthetic guest-visible identity profile (HW) + veneer behavior (Config).
//!
//! Layered architecture, mirrors std-side `src/profile/`:
//!   - `HardwareProfile`  — guest-visible fingerprints (safe to change)
//!   - `SoftwareProfile`  — OS-level identifiers (schema only here; enforce
//!                          is done by fake-vgc / vmlatch, not veneer
//!                          itself, because changing these can break
//!                          Windows activation / login)
//!   - `Config`           — veneer's own behavior knobs (menu timeout,
//!                          intercept on/off, runtime budgets)
//!
//! All strings are fixed-size `ProfileStr<N>` to stay no_std. NVRAM
//! serialization is just `core::mem::transmute`-equivalent copy of the
//! `repr(C, packed)` struct — no dynamic encoding needed because the
//! layout is fully static.

#![allow(dead_code)]

// ───── fixed-size string buffer ─────────────────────────────────────────

/// Fixed-size string buffer. `repr(C, packed)` so the struct has 1-byte
/// alignment — that lets us embed it inside other `repr(C, packed)`
/// parents (Profile / Config) without dragging in alignment padding
/// that would invalidate the on-NVRAM byte layout. Field access goes
/// through raw pointers because Rust forbids references to misaligned
/// packed fields even when N is even.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct ProfileStr<const N: usize> {
    buf: [u8; N],
    len: u16,
}

impl<const N: usize> ProfileStr<N> {
    pub const fn empty() -> Self {
        Self { buf: [0; N], len: 0 }
    }

    /// Build from a `&'static str`. const-fn safe because we copy into a
    /// fresh local `[u8; N]` (not packed) before the struct literal.
    pub const fn from_static(s: &'static str) -> Self {
        let bytes = s.as_bytes();
        let mut buf = [0u8; N];
        let n = if bytes.len() < N { bytes.len() } else { N };
        let mut i = 0;
        while i < n {
            buf[i] = bytes[i];
            i += 1;
        }
        Self { buf, len: n as u16 }
    }

    pub fn from_bytes(s: &[u8]) -> Self {
        let mut buf = [0u8; N];
        let n = s.len().min(N);
        buf[..n].copy_from_slice(&s[..n]);
        Self { buf, len: n as u16 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        let len = unsafe { core::ptr::addr_of!(self.len).read_unaligned() } as usize;
        let ptr = self as *const Self as *const u8;
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    /// Pad-write `self` into a `[u8; N]` (zero fill). Used by handlers
    /// that need a deterministic full-width register write (e.g. CPUID
    /// brand = exactly 48 bytes across 12 registers).
    pub fn to_padded(&self) -> [u8; N] {
        let mut out = [0u8; N];
        let src = self as *const Self as *const u8;
        unsafe { core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), N); }
        out
    }
}

// ───── HardwareProfile ──────────────────────────────────────────────────

/// `CpuProfile.brand` matches CPUID brand string limit (12 registers × 4
/// bytes = 48). `vendor` is the CPUID 0x0 vendor (12 bytes).
pub type CpuBrand = ProfileStr<48>;
pub type CpuVendor = ProfileStr<12>;

/// SMBIOS strings — bounded by realistic vendor entries.
pub type SmbiosShort = ProfileStr<32>;
pub type SmbiosLong = ProfileStr<64>;

/// UUID stored canonical text form (36 chars with dashes).
pub type UuidStr = ProfileStr<36>;

/// MAC canonical text form (`XX:XX:XX:XX:XX:XX` = 17 chars).
pub type MacStr = ProfileStr<17>;

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct CpuProfile {
    pub brand: CpuBrand,
    pub vendor: CpuVendor,
    pub hide_hypervisor_bit: bool,
    pub hide_hypervisor_leaf: bool,
    /// Synthetic 64-bit TSC seed (first visible RDTSC = this value).
    pub tsc_seed: u64,
    /// IA32_BIOS_SIGN_ID — CPU microcode patch level. Synthesised
    /// per-policy so two boots of the same profile report the same
    /// patch level (anti-cheat caches this across sessions).
    pub microcode_signature: u64,
    /// IA32_PLATFORM_ID — bits 50:52 encode the CPU's package type.
    /// Synthesised per-policy. Intel-only MSR but AMD CPUs return 0
    /// when probed; we still report a stable value to flatten timing
    /// differences between hypervisor and bare metal.
    pub platform_id: u64,
    /// CPUID 1.EAX (family/model/stepping/type). 0 = host pass-through.
    /// Without this, brand says one generation while leaf 1 reports the
    /// host's generation — vgc cross-checks these.
    pub cpuid_eax_v1: u32,
    /// CPUID 1.EBX low byte = brand index. 0 = host pass-through.
    pub cpuid_brand_idx: u8,
    /// CPUID 0x80000008.ECX[7:0] override (cores-1). 0 = derive from
    /// MP Services vCPU count at runtime.
    pub cpuid_cores_override: u8,
    /// SMBIOS Type 4 "Processor Family" enum (SMBIOS 3.x § 7.5.2).
    /// 0xCE = AMD Ryzen, 0xC8 = AMD A-series, 0xB3 = Intel Core i7,
    /// 0xB6 = Intel Core i5, … A profile MUST set this to a value
    /// consistent with its vendor/brand so Type 1 (Intel system) vs
    /// Type 4 (AMD family) don't contradict. 0 = fall back to the
    /// vendor-derived default in smbios.rs.
    pub smbios_processor_family: u16,
    /// SMBIOS Type 4 socket designation + Type 7 cache socket. e.g.
    /// "AM5", "LGA1700". Empty = vendor-derived default.
    pub smbios_socket: ProfileStr<16>,
    /// Per-core L1 (sum of L1d+L1i), L2, and total L3 cache sizes in KiB.
    /// SMBIOS Type 7 totals are derived as (per_core × cores) for L1/L2
    /// and the flat L3 value, so they track effective_core_count(). 0 =
    /// fall back to the Zen-4 defaults in smbios.rs.
    pub cache_l1_per_core_kib: u32,
    pub cache_l2_per_core_kib: u32,
    pub cache_l3_total_kib: u32,
    /// SMBIOS Type 4 max / current speed in MHz. 0 = default.
    pub cpu_max_speed_mhz: u16,
    pub cpu_current_speed_mhz: u16,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct SmbiosProfile {
    pub manufacturer: SmbiosLong,
    pub product: SmbiosLong,
    pub serial: SmbiosShort,
    pub version: SmbiosShort,
    pub uuid: UuidStr,
    pub bios_vendor: SmbiosShort,
    pub bios_version: SmbiosShort,
    pub bios_date: SmbiosShort,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct NetworkProfile {
    pub mac: MacStr,
    /// PCI device:vendor (config offset 0x00 layout: device<<16 | vendor).
    pub pci_id: u32,
    /// MII PHY identifier the driver reads from MDIC.
    pub phy_id: u16,
}

/// One disk slot (we hard-cap at one disk for v0.7; v0.8 may grow).
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct DiskProfile {
    pub slot: SmbiosShort,    // e.g. "nvme0:0"
    pub serial: SmbiosShort,
    pub model: SmbiosLong,
    /// NVMe IDENTIFY FR field (firmware revision, 8 bytes).
    pub firmware_rev: ProfileStr<8>,
    /// NVMe IDENTIFY IEEE OUI (controller vendor, 3 bytes, little-endian).
    pub ieee_oui: [u8; 3],
    /// NVMe controller PCI device:vendor (config 0x00 layout).
    pub pci_id: u32,
}

/// System memory — SMBIOS Type 16/17. One manufacturer/part across the
/// populated DIMMs; serials are per-DIMM (anti-cheat reads them).
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct MemoryProfile {
    pub manufacturer: SmbiosShort,
    pub part_number: SmbiosShort,
    pub serial0: ProfileStr<16>,
    pub serial1: ProfileStr<16>,
    pub size_mb_per_dimm: u32,
    pub speed_mts: u16,
    pub dimm_count: u8,
}

/// Integrated/discrete GPU — PCI identity only (no framebuffer state yet).
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct GpuProfile {
    pub pci_id: u32, // device:vendor
}

/// HD Audio controller — PCI identity.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct AudioProfile {
    pub pci_id: u32, // device:vendor
}

/// Motherboard / chipset identity: SMBIOS Type 2 (baseboard) + Type 3
/// (chassis) serials, the chipset PCI device IDs, and the ACPI OEM strings.
/// These all derive from the board model, so they live together.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct BoardProfile {
    pub baseboard_manufacturer: SmbiosLong,
    pub baseboard_product: SmbiosLong,
    pub baseboard_serial: SmbiosShort,
    pub chassis_serial: SmbiosShort,
    /// Chipset PCI device:vendor IDs (config 0x00 layout).
    pub host_bridge_id: u32,
    pub lpc_id: u32,
    pub sata_id: u32,
    pub smbus_id: u32,
    pub xhci_id: u32,
    /// ACPI table OEM identity (replaces the hard-coded "VENEER"/"VNEE").
    pub acpi_oem_id: ProfileStr<6>,
    pub acpi_oem_table_id: ProfileStr<8>,
    pub acpi_creator_id: ProfileStr<4>,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct HardwareProfile {
    pub cpu: CpuProfile,
    pub board: BoardProfile,
    pub memory: MemoryProfile,
    pub gpu: GpuProfile,
    pub audio: AudioProfile,
    pub smbios: SmbiosProfile,
    pub network: NetworkProfile,
    pub disk: DiskProfile,
}

// ───── SoftwareProfile (schema only — enforce by fake-vgc/vmlatch) ─────

/// OS-level identifiers. Changing these can break Windows activation /
/// SID / login — veneer does not enforce them; we keep the schema so a
/// downstream tool (fake-vgc, vmlatch) can read the same TOML and apply.
pub type OsString = ProfileStr<64>;

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct OsProfile {
    pub product_name: OsString,    // "Windows 11 Pro"
    pub build_lab: OsString,        // "26100.1.amd64fre..."
    pub product_id: OsString,
    pub edition_id: OsString,
    pub computer_name: OsString,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct RegistryProfile {
    pub machine_guid: UuidStr,                    // HKLM\SOFTWARE\Microsoft\Cryptography
    pub hardware_profile_guid: UuidStr,           // HKLM\SYSTEM\...\IDConfigDB
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct VolumeProfile {
    pub c_drive_serial: ProfileStr<16>,   // "B4F3-2A91" (8 hex chars + dash)
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct LocaleProfile {
    pub language: ProfileStr<16>,    // "ko-KR"
    pub timezone: ProfileStr<32>,    // "Asia/Seoul"
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct SoftwareProfile {
    pub os: OsProfile,
    pub registry: RegistryProfile,
    pub volume: VolumeProfile,
    pub locale: LocaleProfile,
}

// ───── Profile root ─────────────────────────────────────────────────────

pub type ProfileName = ProfileStr<32>;

/// On-disk / on-NVRAM serialization format. Versioned so a stale cache
/// from a future veneer release doesn't get misread.
pub const PROFILE_MAGIC: u32 = 0x56_4E_50_46; // "VNPF" (Veneer Profile)
/// Bumped at every layout-breaking change. Stale caches from older
/// veneer builds get rejected by `Profile::is_valid` and regenerated.
/// v6: CpuProfile gained smbios_processor_family / smbios_socket /
///     cache_l{1,2,3} / cpu_{max,current}_speed_mhz (SMBIOS Type 4/7
///     are now profile-driven instead of 7900X literals).
pub const PROFILE_VERSION: u32 = 6;

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Profile {
    pub magic: u32,
    pub version: u32,
    pub name: ProfileName,
    pub hardware: HardwareProfile,
    pub software: SoftwareProfile,
}

impl Profile {
    pub const fn empty() -> Self {
        Self {
            magic: PROFILE_MAGIC,
            version: PROFILE_VERSION,
            name: ProfileName::empty(),
            hardware: HardwareProfile {
                cpu: CpuProfile {
                    brand: CpuBrand::empty(),
                    vendor: CpuVendor::empty(),
                    hide_hypervisor_bit: false,
                    hide_hypervisor_leaf: false,
                    tsc_seed: 0,
                    microcode_signature: 0,
                    platform_id: 0,
                    cpuid_eax_v1: 0,
                    cpuid_brand_idx: 0,
                    cpuid_cores_override: 0,
                    smbios_processor_family: 0,
                    smbios_socket: ProfileStr::empty(),
                    cache_l1_per_core_kib: 0,
                    cache_l2_per_core_kib: 0,
                    cache_l3_total_kib: 0,
                    cpu_max_speed_mhz: 0,
                    cpu_current_speed_mhz: 0,
                },
                smbios: SmbiosProfile {
                    manufacturer: SmbiosLong::empty(),
                    product: SmbiosLong::empty(),
                    serial: SmbiosShort::empty(),
                    version: SmbiosShort::empty(),
                    uuid: UuidStr::empty(),
                    bios_vendor: SmbiosShort::empty(),
                    bios_version: SmbiosShort::empty(),
                    bios_date: SmbiosShort::empty(),
                },
                board: BoardProfile {
                    baseboard_manufacturer: SmbiosLong::empty(),
                    baseboard_product: SmbiosLong::empty(),
                    baseboard_serial: SmbiosShort::empty(),
                    chassis_serial: SmbiosShort::empty(),
                    host_bridge_id: 0,
                    lpc_id: 0,
                    sata_id: 0,
                    smbus_id: 0,
                    xhci_id: 0,
                    acpi_oem_id: ProfileStr::empty(),
                    acpi_oem_table_id: ProfileStr::empty(),
                    acpi_creator_id: ProfileStr::empty(),
                },
                memory: MemoryProfile {
                    manufacturer: SmbiosShort::empty(),
                    part_number: SmbiosShort::empty(),
                    serial0: ProfileStr::empty(),
                    serial1: ProfileStr::empty(),
                    size_mb_per_dimm: 0,
                    speed_mts: 0,
                    dimm_count: 0,
                },
                gpu: GpuProfile { pci_id: 0 },
                audio: AudioProfile { pci_id: 0 },
                network: NetworkProfile { mac: MacStr::empty(), pci_id: 0, phy_id: 0 },
                disk: DiskProfile {
                    slot: SmbiosShort::empty(),
                    serial: SmbiosShort::empty(),
                    model: SmbiosLong::empty(),
                    firmware_rev: ProfileStr::empty(),
                    ieee_oui: [0; 3],
                    pci_id: 0,
                },
            },
            software: SoftwareProfile {
                os: OsProfile {
                    product_name: OsString::empty(),
                    build_lab: OsString::empty(),
                    product_id: OsString::empty(),
                    edition_id: OsString::empty(),
                    computer_name: OsString::empty(),
                },
                registry: RegistryProfile {
                    machine_guid: UuidStr::empty(),
                    hardware_profile_guid: UuidStr::empty(),
                },
                volume: VolumeProfile { c_drive_serial: ProfileStr::empty() },
                locale: LocaleProfile {
                    language: ProfileStr::empty(),
                    timezone: ProfileStr::empty(),
                },
            },
        }
    }

    /// Sanity-check on a freshly loaded profile (e.g. from NVRAM). Catches
    /// stale binary layouts from previous veneer versions.
    pub fn is_valid(&self) -> bool {
        // Packed-struct field reads must go through unaligned reads.
        let magic = unsafe { core::ptr::addr_of!(self.magic).read_unaligned() };
        let version = unsafe { core::ptr::addr_of!(self.version).read_unaligned() };
        magic == PROFILE_MAGIC && version == PROFILE_VERSION
    }
}

// ───── Legacy stub kept for back-compat with v0.6 callers ──────────────
// The 12-iter blob and BSP self-test still verify against this signature.
// Promote into `Config` proper in batch 1c.

#[derive(Debug, Clone, Copy)]
pub struct LegacyDefaults {
    pub tsc_seed: u64,
    pub vmmcall_signature: u64,
}

pub const DEFAULT: LegacyDefaults = LegacyDefaults {
    tsc_seed: 0x1000_0000_0000_0000,
    // Neutral VMMCALL hello reply — the 0xC0FFEE… magic was a watermark.
    // (Proper fix is to #UD VMMCALL like bare metal; tracked as debt.)
    vmmcall_signature: 0,
};

pub mod toml;
