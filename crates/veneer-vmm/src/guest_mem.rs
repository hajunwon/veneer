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

// ── guest memory layout (the VMM owns the guest's physical map) ──
/// Bootstrap stack region; grows down toward STACK_PHYS.
pub const STACK_PHYS: u64 = 0x0008_0000;
pub const STACK_BYTES: u64 = 0x0000_4000; // 16 KiB
pub const STACK_TOP: u64 = STACK_PHYS + STACK_BYTES;
/// Total low guest RAM presented to the guest (matches LOW_TOP).
pub const GUEST_RAM_BYTES: u64 = 2 * 1024 * 1024 * 1024;

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

// ── guest page-walk / code diagnostics (debug aids) ──

/// Dump 48 bytes around `addr` in guest low RAM (identity-mapped to host_base).
pub fn dump_code_window(host_base: u64, addr: u64, tag: &str) {
    let start = addr.saturating_sub(16);
    let mut bytes = [0u8; 48];
    unsafe { core::ptr::copy_nonoverlapping((host_base + start) as *const u8, bytes.as_mut_ptr(), 48); }
    crate::sprintln!("[stuck] {} @ 0x{:X} (start 0x{:X}): {:02X?}", tag, addr, start, bytes);
}

/// Walk the guest's 4-level page table (rooted at `cr3`) for `va`, reading each
/// level out of guest low RAM (identity-mapped to `host_base`). Logs every entry
/// so a wrong mapping / reserved NX bit is visible.
pub unsafe fn dump_pagewalk(host_base: u64, cr3: u64, va: u64) {
    let rd = |phys: u64| -> u64 {
        if phys >= GUEST_RAM_BYTES { return 0; }
        unsafe { core::ptr::read_unaligned((host_base + phys) as *const u64) }
    };
    let names = ["PML4", "PDPT", "PD", "PT"];
    let shifts = [39u32, 30, 21, 12];
    let mut table = cr3 & 0x000F_FFFF_FFFF_F000;
    crate::sprintln!("[pw] walk VA 0x{:X} cr3=0x{:X}", va, cr3);
    for lvl in 0..4 {
        if table >= GUEST_RAM_BYTES {
            crate::sprintln!("[pw]   {} table phys 0x{:X} OUTSIDE guest RAM", names[lvl], table);
            return;
        }
        let idx = ((va >> shifts[lvl]) & 0x1FF) as u64;
        let e = rd(table + idx * 8);
        crate::sprintln!("[pw]   {}[{}] @0x{:X} = 0x{:016X} (P={} RW={} US={} NX={})",
            names[lvl], idx, table + idx * 8, e, e & 1, (e >> 1) & 1, (e >> 2) & 1, e >> 63);
        if e & 1 == 0 {
            crate::sprintln!("[pw]   -> NOT PRESENT");
            return;
        }
        if lvl < 3 && (e >> 7) & 1 != 0 {
            crate::sprintln!("[pw]   -> large page, stops here");
            return;
        }
        table = e & 0x000F_FFFF_FFFF_F000;
    }
    crate::sprintln!("[pw]   -> final phys 0x{:X} (VA->PA, identity expected)", table | (va & 0xFFF));
}
