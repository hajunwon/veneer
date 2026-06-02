//! Guest-physical → host translation for the split guest RAM layout.
//!
//! A PC's physical address space is not flat RAM: device MMIO (PCI/ECAM,
//! LAPIC, IO-APIC, HPET, the firmware flash) occupies the window below 4 GiB.
//! So guest RAM is split the way every real machine and hypervisor splits it:
//!
//!   [0,              LOW_TOP)            low RAM   (below the MMIO hole)
//!   [LOW_TOP,        4 GiB)             device MMIO hole (trapped, not RAM)
//!   [4 GiB,          4 GiB + high_size)  high RAM  (above the hole)
//!
//! Both regions are backed by separate contiguous host blocks; NPT maps each
//! guest range onto its block. Every consumer that dereferences a guest
//! address (device DMA in nvme/ahci, the INS/OUTS bridge, dump helpers) must
//! translate through here so a buffer the guest placed in high RAM resolves
//! to the right host page instead of being silently rejected.

use core::sync::atomic::{AtomicU64, Ordering};

/// Top of low RAM = base of the device MMIO hole. The synthetic PCI tree's
/// `_CRS` window, ECAM, and the LAPIC/IO-APIC/HPET blocks all live at or above
/// 0x8000_0000, so low RAM must stop here.
pub const LOW_TOP: u64 = 0x8000_0000; // 2 GiB
/// Guest-physical base of the high RAM region (immediately above 4 GiB).
pub const HIGH_BASE_GPA: u64 = 0x1_0000_0000; // 4 GiB

static LOW_BASE: AtomicU64 = AtomicU64::new(0);
static LOW_SIZE: AtomicU64 = AtomicU64::new(0);
static HIGH_BASE: AtomicU64 = AtomicU64::new(0);
static HIGH_SIZE: AtomicU64 = AtomicU64::new(0);

/// Record the host-physical bases and sizes of the two RAM regions. Called
/// once by the guest-entry path after the host blocks are allocated.
/// `high_size == 0` means no high RAM (single low region).
pub fn set_layout(low_base: u64, low_size: u64, high_base: u64, high_size: u64) {
    LOW_BASE.store(low_base, Ordering::Release);
    LOW_SIZE.store(low_size, Ordering::Release);
    HIGH_BASE.store(high_base, Ordering::Release);
    HIGH_SIZE.store(high_size, Ordering::Release);
}

pub fn low_size() -> u64 {
    LOW_SIZE.load(Ordering::Acquire)
}
pub fn high_size() -> u64 {
    HIGH_SIZE.load(Ordering::Acquire)
}

/// Translate a guest-physical address to its host-physical (== host-virtual
/// under UEFI identity paging) address, or `None` if it falls outside mapped
/// RAM (in the MMIO hole or past the end of high RAM).
#[inline]
pub fn to_host(gpa: u64) -> Option<u64> {
    let ls = LOW_SIZE.load(Ordering::Acquire);
    if gpa < ls {
        return Some(LOW_BASE.load(Ordering::Acquire) + gpa);
    }
    let hs = HIGH_SIZE.load(Ordering::Acquire);
    if hs != 0 && gpa >= HIGH_BASE_GPA && gpa < HIGH_BASE_GPA + hs {
        return Some(HIGH_BASE.load(Ordering::Acquire) + (gpa - HIGH_BASE_GPA));
    }
    None
}

/// Convenience for the many call sites that want a raw pointer or null.
#[inline]
pub fn to_host_ptr(gpa: u64) -> *mut u8 {
    to_host(gpa).map(|h| h as *mut u8).unwrap_or(core::ptr::null_mut())
}
