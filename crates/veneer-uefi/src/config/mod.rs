//! Veneer behavior config — knobs that govern how veneer itself operates,
//! distinct from the guest-visible identity `Profile`.
//!
//! Two sources merge to form the active Config:
//!   1. compile-time `DEFAULT` (this file)
//!   2. NVRAM `VeneerConfig` (overrides default if present + valid)
//!   3. ESP `\EFI\BOOT\config.toml` (batch 1c — overrides NVRAM)
//!
//! When the user changes anything via the in-veneer advanced settings
//! menu, the merged Config is written back to NVRAM.

#![allow(dead_code)]

pub mod toml;

use crate::identity::profile::ProfileStr;

pub const CONFIG_MAGIC: u32 = 0x56_4E_43_46; // "VNCF" (Veneer Config)
pub const CONFIG_VERSION: u32 = 1;

// ───── enums (kept simple — u8 discriminants for stable on-disk layout) ─

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogLevel {
    None = 0,
    Minimal = 1,
    Verbose = 2,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmwareBackdoorPolicy {
    Block = 0,       // intercept + return sentinel
    Passthrough = 1, // let it through (loses anti-detect cover)
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QuickPolicy {
    IntelLaptop = 0,
    AmdDesktop = 1,
    RyzenNuc = 2,
}

// ───── sub-configs ─────────────────────────────────────────────────────

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct MenuConfig {
    pub timeout_secs: u8,    // countdown when cached profile exists
    pub force_show: bool,    // always show menu regardless of cache
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct PolicyConfig {
    pub default: QuickPolicy,         // used on NVRAM miss when prompt_on_miss=false
    pub prompt_on_miss: bool,         // false → silent default, true → menu
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct LogConfig {
    pub serial: LogLevel,
    pub console: LogLevel,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct InterceptConfig {
    pub lapic_emulation: bool,
    pub vmware_backdoor: VmwareBackdoorPolicy,
    pub ap_probe: bool,
    pub bsp_self_test: bool,
    pub multi_vcpu_vmrun: bool,
    pub rdrand_intercept: bool,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct TimingConfig {
    pub rdtsc_stride: u32,
    pub rdtsc_seed: u64,
    pub vmmcall_signature: u64,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct NvramConfig {
    pub profile_var_name: ProfileStr<32>,
    pub config_var_name: ProfileStr<32>,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct RuntimeConfig {
    pub max_vmrun_iters: u32,
    pub asid_base_bsp: u32,
    pub asid_base_ap: u32,
}

// ───── Config root ─────────────────────────────────────────────────────

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Config {
    pub magic: u32,
    pub version: u32,
    pub menu: MenuConfig,
    pub policy: PolicyConfig,
    pub log: LogConfig,
    pub intercept: InterceptConfig,
    pub timing: TimingConfig,
    pub nvram: NvramConfig,
    pub runtime: RuntimeConfig,
}

impl Config {
    pub fn is_valid(&self) -> bool {
        let magic = unsafe { core::ptr::addr_of!(self.magic).read_unaligned() };
        let version = unsafe { core::ptr::addr_of!(self.version).read_unaligned() };
        magic == CONFIG_MAGIC && version == CONFIG_VERSION
    }
}

/// Compile-time default Config. Used when NVRAM `VeneerConfig` is empty
/// or invalid (e.g. first boot, version bump).
pub const DEFAULT: Config = Config {
    magic: CONFIG_MAGIC,
    version: CONFIG_VERSION,
    menu: MenuConfig {
        timeout_secs: 5,
        force_show: false,
    },
    policy: PolicyConfig {
        default: QuickPolicy::AmdDesktop,
        prompt_on_miss: true,
    },
    log: LogConfig {
        serial: LogLevel::Verbose,
        console: LogLevel::Minimal,
    },
    intercept: InterceptConfig {
        lapic_emulation: true,
        vmware_backdoor: VmwareBackdoorPolicy::Block,
        ap_probe: true,
        bsp_self_test: false,
        multi_vcpu_vmrun: true,
        rdrand_intercept: false,
    },
    timing: TimingConfig {
        rdtsc_stride: 30,
        rdtsc_seed: 0x1000_0000_0000_0000,
        vmmcall_signature: 0xC0FFEE_C0FFEE_BEEF,
    },
    nvram: NvramConfig {
        profile_var_name: ProfileStr::from_static("VeneerProfile"),
        config_var_name: ProfileStr::from_static("VeneerConfig"),
    },
    runtime: RuntimeConfig {
        max_vmrun_iters: 32,
        asid_base_bsp: 1,
        asid_base_ap: 2,
    },
};

/// Common GUID used for all veneer NVRAM variables. Picked to be visually
/// distinctive in NVRAM dumps so operators can spot our variables. Not a
/// magic UEFI-spec value — purely a veneer namespace.
pub const VENEER_NVRAM_GUID: [u8; 16] = [
    0xc0, 0xff, 0xee, 0xc0, 0xff, 0xee, 0xbe, 0xef,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
