//! Host environment seam — the few services the VMM core needs from whoever
//! boots it (a UEFI app, a bare-metal loader, a test harness). The host
//! installs a `Platform` at startup; the core reaches the environment only
//! through these accessors, so it carries no firmware dependency itself.
//!
//! Mechanism lives on the host side (e.g. UEFI Boot Services / MP Services);
//! policy (what to allocate, how to bring SVM up across cores) stays in core.

use core::ffi::c_void;
use core::ptr::NonNull;

use crate::hardware::identity::active::Slot;

pub trait Platform: Sync {
    /// Allocate `pages` contiguous, zeroed 4 KiB pages; return the base.
    fn alloc_pages(&self, pages: usize) -> Result<NonNull<u8>, ()>;
    /// Busy-wait `micros` microseconds on the host timer.
    fn stall(&self, micros: usize);
    /// `(total, enabled)` logical-processor count.
    fn mp_processor_count(&self) -> Result<(usize, usize), ()>;
    /// Index of the bootstrap processor.
    fn mp_who_am_i(&self) -> Result<usize, ()>;
    /// Run `entry(arg)` on every Application Processor (blocking, with timeout).
    fn mp_startup_all_aps(
        &self,
        entry: extern "efiapi" fn(*mut c_void),
        arg: *mut c_void,
        timeout_secs: u64,
    ) -> Result<(), ()>;
}

static PLATFORM: Slot<&'static dyn Platform> = Slot::new();

/// Install the host platform (called once at boot before any core service).
pub fn set_platform(p: &'static dyn Platform) {
    PLATFORM.set(p);
}

fn host() -> &'static dyn Platform {
    *PLATFORM.get().expect("platform not installed")
}

pub fn alloc_pages(pages: usize) -> Result<NonNull<u8>, ()> {
    host().alloc_pages(pages)
}
pub fn stall(micros: usize) {
    host().stall(micros)
}
pub fn mp_processor_count() -> Result<(usize, usize), ()> {
    host().mp_processor_count()
}
pub fn mp_who_am_i() -> Result<usize, ()> {
    host().mp_who_am_i()
}
pub fn mp_startup_all_aps(
    entry: extern "efiapi" fn(*mut c_void),
    arg: *mut c_void,
    timeout_secs: u64,
) -> Result<(), ()> {
    host().mp_startup_all_aps(entry, arg, timeout_secs)
}
