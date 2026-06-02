//! Synthetic machine identity — what the guest sees, how it is generated,
//! and where it persists across boots.

pub mod profile;
pub mod profile_gen;
pub mod smbios;
pub mod nvram_io;
pub mod uefi_vars;
pub mod active;
