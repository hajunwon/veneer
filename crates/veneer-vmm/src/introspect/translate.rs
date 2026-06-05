//! Guest-virtual → guest-physical translation via a 4-level page walk.
//!
//! Reads the guest's own page tables straight out of guest RAM, so it works
//! for any guest CR3 regardless of in-guest protections (PatchGuard / HVCI
//! guard the guest's *view*, not the hypervisor's physical access).

use crate::guest_mem;

const PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Walk the guest 4-level page table rooted at `cr3` and return the GPA that
/// `gva` maps to. Handles 1 GiB / 2 MiB large pages. Returns `None` if a
/// level is not present or a table lands outside mapped guest RAM.
pub fn gva_to_gpa(cr3: u64, gva: u64) -> Option<u64> {
    let rd = |phys: u64| -> Option<u64> {
        let h = guest_mem::to_host(phys)?;
        Some(unsafe { core::ptr::read_unaligned(h as *const u64) })
    };
    let shifts = [39u32, 30, 21, 12];
    let mut table = cr3 & PFN_MASK;
    for lvl in 0..4 {
        let e = rd(table + ((gva >> shifts[lvl]) & 0x1FF) * 8)?;
        if e & 1 == 0 {
            return None; // not present
        }
        if lvl < 3 && (e >> 7) & 1 != 0 {
            // large page: PS bit set before the PT level
            let page_mask = (1u64 << shifts[lvl]) - 1;
            return Some((e & PFN_MASK & !page_mask) | (gva & page_mask));
        }
        table = e & PFN_MASK;
    }
    Some(table | (gva & 0xFFF))
}
