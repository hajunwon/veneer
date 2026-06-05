//! Policy → reference-machine selection + per-instance generation.
//!
//! The reference machines and the generation rules live in `veneer-profile`
//! (the identity domain). This file only provides the RDRAND randomness
//! source, maps the boot policy to a catalog machine, then runs the shared
//! instance-fill and the coherence check.
//!
//! The output `Profile` is cached in NVRAM. On NVRAM-miss boots we run this
//! once; on NVRAM-hit boots we reuse the cached profile so the guest sees
//! the same machine identity.

#![allow(dead_code)]

use core::arch::asm;

use crate::sprintln;
use crate::infra::config::QuickPolicy;
use crate::hardware::identity::profile::catalog::machines;
use crate::hardware::identity::profile::coherence::{self, CoherenceIssue, HostFacts};
use crate::hardware::identity::profile::identity::{generate, Rng};
use crate::hardware::identity::profile::Profile;

/// RDRAND-backed randomness source. Retries on entropy starvation (CF=0);
/// falls back to a constant on persistent failure — never expected on Ryzen.
pub struct Rdrand;

impl Rng for Rdrand {
    fn next_u64(&mut self) -> u64 {
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
}

pub fn template_for(policy: QuickPolicy) -> Profile {
    match policy {
        QuickPolicy::IntelLaptop => machines::INTEL_LAPTOP,
        QuickPolicy::AmdDesktop => machines::AMD_DESKTOP,
        QuickPolicy::RyzenNuc => machines::RYZEN_NUC,
    }
}

/// Build a full profile: a catalog machine + freshly generated per-unit
/// identifiers, validated for cross-surface coherence (issues logged).
pub fn build_profile(policy: QuickPolicy) -> Profile {
    let mut p = template_for(policy);
    let mut rng = Rdrand;
    generate::fill_instance(&mut p, &mut rng);

    let mut issues = [CoherenceIssue::AmdMissingIommuEfr; 4];
    let n = coherence::validate(&p, &HostFacts::default(), &mut issues);
    let shown = n.min(issues.len());
    for issue in issues.iter().take(shown) {
        sprintln!("[prof] coherence WARNING: {:?}", issue);
    }
    if n > shown {
        sprintln!("[prof] coherence: {} additional issue(s)", n - shown);
    }
    p
}
