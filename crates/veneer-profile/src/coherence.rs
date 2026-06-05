//! Cross-surface coherence validator.
//!
//! veneer's dominant failure mode is a spoofed value on one surface
//! contradicting another (CPUID vendor vs IOMMU EFR vendor, brand core
//! count vs reported topology, a passthrough device's real identity vs the
//! claimed platform). This checks those invariants on the assembled model
//! before it is committed, so an incoherent profile fails loud instead of
//! becoming a runtime tell.
//!
//! `HostFacts` carries real-hardware values probed by the runtime (used to
//! validate passthrough components against the claimed platform). It is
//! empty today — the field reserves the shape for when passthrough lands.

use crate::Profile;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CoherenceIssue {
    /// CPU vendor string and the IOMMU EFR (an AMD-Vi-only register) disagree.
    VendorIommuMismatch,
    /// An AMD profile carries no IOMMU EFR (AMD platforms always expose one).
    AmdMissingIommuEfr,
}

/// Real-hardware values the runtime probes, for validating passthrough
/// components. Empty until passthrough is implemented.
#[derive(Clone, Copy, Default)]
pub struct HostFacts;

/// Validate `p` against `host`. Returns the number of issues written into
/// `out` (no_std: caller supplies the buffer; extra issues are dropped and
/// still counted).
pub fn validate(p: &Profile, _host: &HostFacts, out: &mut [CoherenceIssue]) -> usize {
    let mut n = 0;
    let mut push = |issue: CoherenceIssue| {
        if n < out.len() {
            out[n] = issue;
        }
        n += 1;
    };

    let vendor = p.hardware.cpu.spec.vendor.as_str();
    let is_amd = vendor == "AuthenticAMD";
    let efr = unsafe {
        core::ptr::addr_of!(p.hardware.cpu.spec.iommu.efr).read_unaligned()
    };

    if is_amd && efr == 0 {
        push(CoherenceIssue::AmdMissingIommuEfr);
    }
    if !is_amd && efr != 0 {
        // A non-AMD vendor reporting an AMD-Vi EFR is self-contradictory.
        push(CoherenceIssue::VendorIommuMismatch);
    }

    n
}
