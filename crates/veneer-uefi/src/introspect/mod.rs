//! Virtual Machine Introspection (VMI).
//!
//! veneer runs at L1, below the guest. PatchGuard and HVCI are in-guest
//! defenses — they guard the guest's own view of memory and cannot observe
//! the hypervisor reading or writing the underlying physical pages. This
//! module is the read/translate foundation; the `hook` module builds the
//! NPT-based stealth interception on top of it.

pub mod translate;
pub mod mem;
pub mod hook;

pub use mem::read_phys;
