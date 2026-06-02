//! Guest bring-up — UEFI plumbing and loading the guest image into memory.

pub mod chain_load;
pub mod esp_io;
pub mod guest_blob;
pub mod guest_mem;
pub mod linux_loader;
pub mod menu;
pub mod uefi_config;
