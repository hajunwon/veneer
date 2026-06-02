//! One-shot slots holding the active Profile and Config.
//!
//! BSP calls `PROFILE.set(...)` / `CONFIG.set(...)` once during boot
//! (after NVRAM load + policy resolution). Intercept handlers — which
//! run on every host CPU — read via `PROFILE.get()` / `CONFIG.get()`.
//! Single-writer + many-reader pattern, so `Acquire/Release` ordering
//! on a plain `AtomicBool` ready flag is enough.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::infra::config::Config;
use crate::hardware::identity::profile::Profile;

pub struct Slot<T> {
    cell: UnsafeCell<MaybeUninit<T>>,
    ready: AtomicBool,
}

unsafe impl<T> Sync for Slot<T> {}

impl<T> Slot<T> {
    pub const fn new() -> Self {
        Self {
            cell: UnsafeCell::new(MaybeUninit::uninit()),
            ready: AtomicBool::new(false),
        }
    }

    pub fn set(&self, v: T) {
        unsafe { (*self.cell.get()).write(v); }
        self.ready.store(true, Ordering::Release);
    }

    pub fn get(&self) -> Option<&T> {
        if self.ready.load(Ordering::Acquire) {
            Some(unsafe { &*(*self.cell.get()).as_ptr() })
        } else {
            None
        }
    }
}

pub static PROFILE: Slot<Profile> = Slot::new();
pub static CONFIG: Slot<Config> = Slot::new();
