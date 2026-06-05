//! CPU catalog — one `CpuSpec` per real model. Each references its on-die
//! IOMMU from `dies`. Add a model = add a const here.
//!
//! More models (Vermeer/Cezanne/Milan desktop+server variants) are being
//! filled from verified per-model specs; the set below covers the machines
//! currently composed in `machines.rs`.

use crate::catalog::dies;
use crate::*;

pub const RYZEN_9_7900X: CpuSpec = CpuSpec {
    brand: CpuBrand::from_static("AMD Ryzen 9 7900X 12-Core Processor"),
    vendor: CpuVendor::from_static("AuthenticAMD"),
    hide_hypervisor_bit: true,
    hide_hypervisor_leaf: true,
    tsc_seed: 0x1000_0000_0000_0000,
    microcode_signature: 0,
    platform_id: 0,
    cpuid_eax_v1: 0x00A6_0F12, // Zen4 Raphael: fam 0x19 model 0x61 step 2
    cpuid_brand_idx: 0,
    cpuid_cores_override: 0,
    smbios_processor_family: 0x00CE, // AMD Ryzen
    smbios_socket: ProfileStr::from_static("AM5"),
    cache_l1_per_core_kib: 64,
    cache_l2_per_core_kib: 1024,
    cache_l3_total_kib: 64 * 1024,
    cpu_max_speed_mhz: 5600,
    cpu_current_speed_mhz: 4700,
    iommu: dies::ZEN4_RAPHAEL,
};

pub const RYZEN_7_7840HS: CpuSpec = CpuSpec {
    brand: CpuBrand::from_static("AMD Ryzen 7 7840HS w/ Radeon 780M Graphics"),
    vendor: CpuVendor::from_static("AuthenticAMD"),
    hide_hypervisor_bit: true,
    hide_hypervisor_leaf: true,
    tsc_seed: 0x1000_0000_0000_0000,
    microcode_signature: 0,
    platform_id: 0,
    cpuid_eax_v1: 0x00A7_0F41, // Zen4 Phoenix: fam 0x19 model 0x74 step 1
    cpuid_brand_idx: 0,
    cpuid_cores_override: 0,
    smbios_processor_family: 0x00CE,
    smbios_socket: ProfileStr::from_static("FP7"),
    cache_l1_per_core_kib: 64,
    cache_l2_per_core_kib: 1024,
    cache_l3_total_kib: 16 * 1024,
    cpu_max_speed_mhz: 5100,
    cpu_current_speed_mhz: 3800,
    iommu: dies::ZEN4_PHOENIX,
};

pub const CORE_I7_12700H: CpuSpec = CpuSpec {
    brand: CpuBrand::from_static("12th Gen Intel(R) Core(TM) i7-12700H"),
    vendor: CpuVendor::from_static("GenuineIntel"),
    hide_hypervisor_bit: true,
    hide_hypervisor_leaf: true,
    tsc_seed: 0x1000_0000_0000_0000,
    microcode_signature: 0,
    platform_id: 0,
    cpuid_eax_v1: 0x0009_06A3, // Alder Lake P: fam 6 model 0x9A step 3
    cpuid_brand_idx: 0,
    cpuid_cores_override: 0,
    smbios_processor_family: 0x00B3, // Intel Core i7
    smbios_socket: ProfileStr::from_static("FCBGA1744"),
    cache_l1_per_core_kib: 80,
    cache_l2_per_core_kib: 1280,
    cache_l3_total_kib: 24 * 1024,
    cpu_max_speed_mhz: 4700,
    cpu_current_speed_mhz: 2300,
    iommu: IommuModel::empty(), // Intel VT-d (DMAR), not AMD-Vi — not modeled
};

/// Zen3 Milan server part. Verified specs; not yet wired into a machine
/// (needs an SP3 server platform). smbios_processor_family is the Ryzen
/// enum pending confirmation of an EPYC-specific SMBIOS code.
pub const EPYC_7313P: CpuSpec = CpuSpec {
    brand: CpuBrand::from_static("AMD EPYC 7313P 16-Core Processor"),
    vendor: CpuVendor::from_static("AuthenticAMD"),
    hide_hypervisor_bit: true,
    hide_hypervisor_leaf: true,
    tsc_seed: 0x1000_0000_0000_0000,
    microcode_signature: 0,
    platform_id: 0,
    cpuid_eax_v1: 0x00A0_0F11, // Zen3 Milan: fam 0x19 model 0x01 step 1 (rev B1)
    cpuid_brand_idx: 0,
    cpuid_cores_override: 0,
    smbios_processor_family: 0x00CE, // TODO confirm EPYC-specific SMBIOS family enum
    smbios_socket: ProfileStr::from_static("SP3"),
    cache_l1_per_core_kib: 64,
    cache_l2_per_core_kib: 512,
    cache_l3_total_kib: 128 * 1024,
    cpu_max_speed_mhz: 3700,
    cpu_current_speed_mhz: 3000,
    iommu: dies::ZEN3_MILAN,
};

// ── verified variety (InstLatx64 real-chip CPUID dumps) ──
// X3D L3 (98304 KiB = 96 MB) lives in CPUID leaf 0x8000001D, not just the
// legacy 0x80000006 — the CPUID cache emitter must honor that (follow-up).

pub const RYZEN_9_7950X: CpuSpec = CpuSpec {
    brand: CpuBrand::from_static("AMD Ryzen 9 7950X 16-Core Processor"),
    vendor: CpuVendor::from_static("AuthenticAMD"),
    hide_hypervisor_bit: true,
    hide_hypervisor_leaf: true,
    tsc_seed: 0x1000_0000_0000_0000,
    microcode_signature: 0,
    platform_id: 0,
    cpuid_eax_v1: 0x00A6_0F12, // Zen4 Raphael, model 0x61 step 2
    cpuid_brand_idx: 0,
    cpuid_cores_override: 0,
    smbios_processor_family: 0x00CE,
    smbios_socket: ProfileStr::from_static("AM5"),
    cache_l1_per_core_kib: 64,
    cache_l2_per_core_kib: 1024,
    cache_l3_total_kib: 64 * 1024,
    cpu_max_speed_mhz: 5700,
    cpu_current_speed_mhz: 4500,
    iommu: dies::ZEN4_RAPHAEL,
};

pub const RYZEN_7_7800X3D: CpuSpec = CpuSpec {
    brand: CpuBrand::from_static("AMD Ryzen 7 7800X3D 8-Core Processor"),
    vendor: CpuVendor::from_static("AuthenticAMD"),
    hide_hypervisor_bit: true,
    hide_hypervisor_leaf: true,
    tsc_seed: 0x1000_0000_0000_0000,
    microcode_signature: 0,
    platform_id: 0,
    cpuid_eax_v1: 0x00A6_0F12, // Zen4 Raphael X3D (same sig as plain Raphael)
    cpuid_brand_idx: 0,
    cpuid_cores_override: 0,
    smbios_processor_family: 0x00CE,
    smbios_socket: ProfileStr::from_static("AM5"),
    cache_l1_per_core_kib: 64,
    cache_l2_per_core_kib: 1024,
    cache_l3_total_kib: 96 * 1024, // 3D V-cache: 32MB base + 64MB stacked
    cpu_max_speed_mhz: 5000,
    cpu_current_speed_mhz: 4200,
    iommu: dies::ZEN4_RAPHAEL,
};

pub const RYZEN_9_5950X: CpuSpec = CpuSpec {
    brand: CpuBrand::from_static("AMD Ryzen 9 5950X 16-Core Processor"),
    vendor: CpuVendor::from_static("AuthenticAMD"),
    hide_hypervisor_bit: true,
    hide_hypervisor_leaf: true,
    tsc_seed: 0x1000_0000_0000_0000,
    microcode_signature: 0,
    platform_id: 0,
    cpuid_eax_v1: 0x00A2_0F10, // Zen3 Vermeer, model 0x21 step 0
    cpuid_brand_idx: 0,
    cpuid_cores_override: 0,
    smbios_processor_family: 0x00CE,
    smbios_socket: ProfileStr::from_static("AM4"),
    cache_l1_per_core_kib: 64,
    cache_l2_per_core_kib: 512,
    cache_l3_total_kib: 64 * 1024,
    cpu_max_speed_mhz: 4900,
    cpu_current_speed_mhz: 3400,
    iommu: dies::ZEN3_VERMEER,
};

pub const RYZEN_7_5800X3D: CpuSpec = CpuSpec {
    brand: CpuBrand::from_static("AMD Ryzen 7 5800X3D 8-Core Processor"),
    vendor: CpuVendor::from_static("AuthenticAMD"),
    hide_hypervisor_bit: true,
    hide_hypervisor_leaf: true,
    tsc_seed: 0x1000_0000_0000_0000,
    microcode_signature: 0,
    platform_id: 0,
    cpuid_eax_v1: 0x00A2_0F12, // Zen3 Vermeer X3D, model 0x21 step 2 (B2)
    cpuid_brand_idx: 0,
    cpuid_cores_override: 0,
    smbios_processor_family: 0x00CE,
    smbios_socket: ProfileStr::from_static("AM4"),
    cache_l1_per_core_kib: 64,
    cache_l2_per_core_kib: 512,
    cache_l3_total_kib: 96 * 1024, // 3D V-cache: 32MB base + 64MB stacked
    cpu_max_speed_mhz: 4500,
    cpu_current_speed_mhz: 3400,
    iommu: dies::ZEN3_VERMEER,
};

pub const RYZEN_7_5700G: CpuSpec = CpuSpec {
    brand: CpuBrand::from_static("AMD Ryzen 7 5700G with Radeon Graphics"),
    vendor: CpuVendor::from_static("AuthenticAMD"),
    hide_hypervisor_bit: true,
    hide_hypervisor_leaf: true,
    tsc_seed: 0x1000_0000_0000_0000,
    microcode_signature: 0,
    platform_id: 0,
    cpuid_eax_v1: 0x00A5_0F00, // Zen3 Cezanne APU, model 0x50 step 0
    cpuid_brand_idx: 0,
    cpuid_cores_override: 0,
    smbios_processor_family: 0x00CE,
    smbios_socket: ProfileStr::from_static("AM4"),
    cache_l1_per_core_kib: 64,
    cache_l2_per_core_kib: 512,
    cache_l3_total_kib: 16 * 1024, // monolithic APU
    cpu_max_speed_mhz: 4600,
    cpu_current_speed_mhz: 3800,
    iommu: dies::ZEN3_CEZANNE,
};
