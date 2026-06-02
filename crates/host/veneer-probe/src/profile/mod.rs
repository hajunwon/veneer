//! Synthetic-PC profile — re-exported from the shared `veneer-profile`
//! crate (no_std, NVRAM byte-layout) so the host tool validates the exact
//! schema the hypervisor uses, not a separate copy.

pub use veneer_profile::*;

pub mod load;
