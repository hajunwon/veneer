//! veneer-probe — host-side pre-flight for the veneer hypervisor.
//!
//!  modes/      CLI verbs (inspect, plan, profile-check)
//!  platform/   backend selection (which of SVM / VMX is viable on this host)
//!  cpu/        host CPU detection (vendor, features, MSRs)
//!  profile/    vmlatch-compatible synthetic-PC profile loader

pub mod cpu;
pub mod profile;
pub mod platform;

pub use profile::{Profile, HardwareProfile};
