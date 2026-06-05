//! Storage subsystem — presents block storage to the guest.
//!
//! Two concerns, two module boundaries:
//!   - the guest-facing controllers (`nvme`, `ahci`) — what the guest sees.
//!   - the host-side `backend` — where the bytes come from (host disk via
//!     UEFI). The controllers depend only on the `HostStorage` trait below;
//!     the concrete backend is injected at boot, so it is the core ↔ host
//!     seam (a file or RAM backend would slot in behind the same surface,
//!     and in a core/adapter split the backend lives on the adapter side).

pub mod ahci;
pub mod nvme;

use crate::hardware::identity::active::Slot;

/// Host-side block storage backing the emulated controllers. NVMe namespaces
/// (1 = install target) plus the AHCI ATAPI "media" (install ISO) surface.
/// `dest`/`src` are raw guest-staging buffers the controller has already
/// validated. The guest-facing controllers call only this trait.
pub trait HostStorage: Sync {
    fn ns_present(&self, nsid: u32) -> bool;
    fn ns_count(&self) -> u32;
    fn block_size(&self, nsid: u32) -> u32;
    fn block_count(&self, nsid: u32) -> u64;
    fn read(&self, nsid: u32, lba: u64, blocks: u32, dest: *mut u8) -> bool;
    fn write(&self, nsid: u32, lba: u64, blocks: u32, src: *const u8) -> bool;
    fn media_ready(&self) -> bool;
    fn media_block_size(&self) -> u32;
    fn media_block_count(&self) -> u64;
    fn media_read(&self, lba: u64, blocks: u32, dest: *mut u8) -> bool;
}

static HOST: Slot<&'static dyn HostStorage> = Slot::new();

/// Register the host storage backend (called once at boot by the backend).
pub fn set_host_storage(h: &'static dyn HostStorage) {
    HOST.set(h);
}

// Thin delegators so the controllers read like before; each routes to the
// injected backend, or reports "no disk" until one is registered.
pub fn ns_present(nsid: u32) -> bool { HOST.get().map_or(false, |h| h.ns_present(nsid)) }
pub fn ns_count() -> u32 { HOST.get().map_or(0, |h| h.ns_count()) }
pub fn block_size(nsid: u32) -> u32 { HOST.get().map_or(0, |h| h.block_size(nsid)) }
pub fn block_count(nsid: u32) -> u64 { HOST.get().map_or(0, |h| h.block_count(nsid)) }
pub fn read(nsid: u32, lba: u64, blocks: u32, dest: *mut u8) -> bool {
    HOST.get().map_or(false, |h| h.read(nsid, lba, blocks, dest))
}
pub fn write(nsid: u32, lba: u64, blocks: u32, src: *const u8) -> bool {
    HOST.get().map_or(false, |h| h.write(nsid, lba, blocks, src))
}
pub fn media_ready() -> bool { HOST.get().map_or(false, |h| h.media_ready()) }
pub fn media_block_size() -> u32 { HOST.get().map_or(0, |h| h.media_block_size()) }
pub fn media_block_count() -> u64 { HOST.get().map_or(0, |h| h.media_block_count()) }
pub fn media_read(lba: u64, blocks: u32, dest: *mut u8) -> bool {
    HOST.get().map_or(false, |h| h.media_read(lba, blocks, dest))
}
