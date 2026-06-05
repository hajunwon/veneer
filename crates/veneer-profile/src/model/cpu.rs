//! CPU component. All fields are model-class (spec) — modern x86 exposes no
//! per-unit CPU serial, so there is no `instance`.

use crate::model::iommu::IommuModel;
use crate::primitives::{CpuBrand, CpuVendor, ProfileStr};

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct CpuSpec {
    pub brand: CpuBrand,
    pub vendor: CpuVendor,
    pub hide_hypervisor_bit: bool,
    pub hide_hypervisor_leaf: bool,
    /// Synthetic 64-bit TSC seed (first visible RDTSC = this value).
    pub tsc_seed: u64,
    /// IA32_BIOS_SIGN_ID — microcode patch level, stable per profile.
    pub microcode_signature: u64,
    /// IA32_PLATFORM_ID — package-type bits; stable synthetic value.
    pub platform_id: u64,
    /// CPUID 1.EAX (family/model/stepping/type). 0 = host pass-through.
    pub cpuid_eax_v1: u32,
    /// CPUID 1.EBX low byte = brand index. 0 = host pass-through.
    pub cpuid_brand_idx: u8,
    /// CPUID 0x80000008.ECX[7:0] override (cores-1). 0 = derive at runtime.
    pub cpuid_cores_override: u8,
    /// SMBIOS Type 4 "Processor Family" enum. 0xCE = AMD Ryzen, 0xB3 = i7…
    pub smbios_processor_family: u16,
    /// SMBIOS Type 4 socket designation (e.g. "AM5", "LGA1700").
    pub smbios_socket: ProfileStr<16>,
    pub cache_l1_per_core_kib: u32,
    pub cache_l2_per_core_kib: u32,
    pub cache_l3_total_kib: u32,
    pub cpu_max_speed_mhz: u16,
    pub cpu_current_speed_mhz: u16,
    /// On-die IOMMU (AMD-Vi). Single source for both the live MMIO EFR
    /// register and the ACPI IVRS EFR image emitters.
    pub iommu: IommuModel,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct CpuComponent {
    pub spec: CpuSpec,
}

impl CpuComponent {
    pub const fn empty() -> Self {
        Self {
            spec: CpuSpec {
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
                iommu: IommuModel::empty(),
            },
        }
    }
}
