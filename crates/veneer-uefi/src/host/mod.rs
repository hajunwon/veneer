//! Host-facing adapter modules — the UEFI side of the core↔environment split.
//!
//! These talk to real host hardware/firmware (keyboard/mouse, disk, NVRAM
//! variables) and implement the traits the `veneer-vmm` core depends on. The
//! core never references these directly; it sees only the injected traits.

pub mod platform;
pub mod input;
pub mod storage_backend;
pub mod host_ahci;
pub mod nvram_io;
pub mod uefi_vars;
