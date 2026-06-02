//! Capability probe — what does the host CPU let us do.
//!
//! veneer only runs if:
//!   - host vendor is AMD or Intel (real silicon, not a weird emulator)
//!   - vendor-appropriate virt extension is present and not disabled in firmware
//!   - nested paging (NPT for AMD, EPT for Intel) is supported
//!   - 64-bit long mode and 1 GiB+ pages are available
//!
//! This module is *read-only* — we only inspect, never enable. Enabling
//! happens in the platform launcher when it actually transitions to L1.

use raw_cpuid::CpuId;

use super::vendor::{host_vendor, Vendor};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCaps {
    pub vendor:         Vendor,
    /// Family/Model/Stepping packed into the canonical 32-bit "signature"
    /// form (EAX from CPUID leaf 1, masked the AMD/Intel-standard way).
    pub family_model:   u32,
    /// AMD: leaf 0x8000_0001 ECX bit 2  (SVM)
    /// Intel: leaf 1 ECX bit 5         (VMX)
    pub virt_extension: bool,
    /// AMD: NPT — leaf 0x8000_000A EDX bit 0
    /// Intel: EPT — IA32_VMX_EPT_VPID_CAP (MSR), we approximate via leaf 1
    pub nested_paging:  bool,
    /// CPUID 0x8000_0001 EDX bit 26 — 1 GiB pages available
    pub large_pages:    bool,
    /// CPUID 0x8000_0001 EDX bit 29 — long-mode (64-bit) supported
    pub long_mode:      bool,
    /// CPUID 0x8000_000A EBX — number of ASIDs available (AMD only)
    /// Intel uses VPID, same concept; we leave 0 there for now.
    pub max_asid:       u32,
}

pub fn probe() -> HostCaps {
    let id = CpuId::new();
    let vendor = host_vendor();
    let family_model = id.get_feature_info()
        .map(|f| {
            ((f.extended_family_id() as u32) << 20)
                | ((f.extended_model_id() as u32) << 16)
                | ((f.family_id() as u32) << 8)
                | (f.model_id() as u32)
        })
        .unwrap_or(0);

    let virt_extension = match vendor {
        Vendor::AuthenticAmd => id.get_extended_processor_and_feature_identifiers()
            .map(|f| f.has_svm()).unwrap_or(false),
        Vendor::GenuineIntel => id.get_feature_info()
            .map(|f| f.has_vmx()).unwrap_or(false),
        Vendor::Other => false,
    };

    let (nested_paging, max_asid) = match vendor {
        Vendor::AuthenticAmd => {
            let svm = id.get_svm_info();
            let np = svm.as_ref().map(|s| s.has_nested_paging()).unwrap_or(false);
            let asids = svm.as_ref().map(|s| s.supported_asids()).unwrap_or(0);
            (np, asids)
        }
        Vendor::GenuineIntel => {
            // Proper EPT-cap probing needs an MSR (IA32_VMX_EPT_VPID_CAP);
            // we can't read MSRs from user-mode. Approximate by assuming
            // any modern Intel with VMX also has EPT.
            (virt_extension, 0)
        }
        Vendor::Other => (false, 0),
    };

    let ext = id.get_extended_processor_and_feature_identifiers();
    let large_pages = ext.as_ref().map(|f| f.has_1gib_pages()).unwrap_or(false);
    let long_mode   = ext.as_ref().map(|f| f.has_64bit_mode()).unwrap_or(false);

    HostCaps { vendor, family_model, virt_extension, nested_paging, large_pages, long_mode, max_asid }
}

impl HostCaps {
    /// Sufficient to run veneer as-designed?
    pub fn viable(&self) -> bool {
        self.virt_extension && self.nested_paging && self.long_mode
    }

    pub fn blockers(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.virt_extension { out.push("no SVM/VMX (BIOS may have it disabled)"); }
        if !self.nested_paging  { out.push("no nested-paging (NPT/EPT) — veneer requires it"); }
        if !self.long_mode      { out.push("no 64-bit long mode"); }
        if matches!(self.vendor, Vendor::Other) {
            out.push("unsupported CPU vendor (neither AMD nor Intel)");
        }
        out
    }
}
