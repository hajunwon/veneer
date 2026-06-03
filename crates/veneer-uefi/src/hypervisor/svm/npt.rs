//! Nested Page Tables — host-physical mapping for the guest.
//!
//! AMD SVM with nested paging does two walks per guest memory access:
//!
//!     guest virtual ── (guest CR3 walk) ──> guest physical (GPA)
//!     GPA ── (NCR3 walk) ──> host physical (HPA)
//!
//! For v0.4-δ we identity-map a large prefix of the physical address space
//! using 1-GiB huge pages, so GPA == HPA for everything the guest touches.
//! That gives the guest the same view of memory as the host, but routes
//! every access through hardware nested-paging — which lets the hypervisor
//! later remap, hide, or trap arbitrary regions.
//!
//! Layout:
//!   - 2 levels in use (PML4 + PDPT). PDPT entries use the PS bit (1 GiB
//!     huge pages) so we don't need PD/PT.
//!   - One PML4 page (4 KiB) — first entry points at the PDPT.
//!   - One PDPT page (4 KiB) — 512 entries × 1 GiB = 512 GiB identity map.
//!   - Total cost: 2 × 4 KiB = 8 KiB of physical memory.

use uefi::boot::{self, AllocateType, MemoryType};

// 4-level paging entry flag bits.
const PG_PRESENT: u64 = 1 << 0;
const PG_RW:      u64 = 1 << 1;
const PG_USER:    u64 = 1 << 2;
const PG_PS:      u64 = 1 << 7; // set in PDPT/PD entry for huge page

pub const ONE_GIB: u64 = 1024 * 1024 * 1024;
pub const PDPT_ENTRIES: usize = 512;

#[derive(Debug, Clone, Copy)]
pub struct NptRoot {
    pub pml4_phys: u64,
    pub pdpt_phys: u64,
    pub coverage_bytes: u64,
}

#[derive(Debug)]
#[allow(dead_code)] // NotPageAligned.0 is for diagnostics if the assert ever fires.
pub enum NptError {
    PageAllocFailed,
    NotPageAligned(u64),
}

/// Build a PML4 + PDPT that maps guest_phys [0, n_gib*1GiB) onto
/// host_phys [host_base, host_base + n_gib*1GiB) using 1-GiB huge pages.
/// Lets us isolate guest RAM from veneer's own UEFI BootServices memory:
/// the guest sees a clean 0-based physical space, and any of its accesses
/// outside the mapped range fault into NPF instead of stomping on our
/// hypervisor state.
///
/// `host_base` must be 1 GiB-aligned.
pub fn build_translated(host_base: u64, n_gib: usize) -> Result<NptRoot, NptError> {
    if host_base & (ONE_GIB - 1) != 0 {
        return Err(NptError::NotPageAligned(host_base));
    }
    if n_gib == 0 || n_gib > PDPT_ENTRIES {
        return Err(NptError::PageAllocFailed);
    }
    let pml4 = alloc_zero_page()?;
    let pdpt = alloc_zero_page()?;

    unsafe {
        let pml4_ptr = pml4 as *mut u64;
        *pml4_ptr.offset(0) = pdpt | PG_PRESENT | PG_RW | PG_USER;

        let pdpt_ptr = pdpt as *mut u64;
        for i in 0..n_gib {
            let host_phys = host_base + (i as u64) * ONE_GIB;
            *pdpt_ptr.add(i) =
                host_phys | PG_PRESENT | PG_RW | PG_USER | PG_PS;
        }
        // Entries above n_gib stay zero (not present) → any guest
        // access there faults; npf::handle sees an unknown GPA and
        // Aborts, surfacing the rogue access in the serial log.
    }

    Ok(NptRoot {
        pml4_phys: pml4,
        pdpt_phys: pdpt,
        coverage_bytes: (n_gib as u64) * ONE_GIB,
    })
}

/// Add `n_gib` 1-GiB huge-page mappings at guest-physical `gpa_base` onto
/// host_phys [host_base, host_base + n_gib*1GiB), reusing `root`'s existing
/// PDPT (PML4[0] already covers [0, 512 GiB)). Used to back the high-RAM
/// region above the 4 GiB device hole. Both addresses must be 1 GiB-aligned.
pub fn map_translated_at(root: &NptRoot, gpa_base: u64, host_base: u64, n_gib: usize) -> Result<(), NptError> {
    if gpa_base & (ONE_GIB - 1) != 0 {
        return Err(NptError::NotPageAligned(gpa_base));
    }
    if host_base & (ONE_GIB - 1) != 0 {
        return Err(NptError::NotPageAligned(host_base));
    }
    let first = (gpa_base / ONE_GIB) as usize;
    if first + n_gib > PDPT_ENTRIES {
        return Err(NptError::PageAllocFailed);
    }
    unsafe {
        let pdpt_ptr = root.pdpt_phys as *mut u64;
        for i in 0..n_gib {
            let host_phys = host_base + (i as u64) * ONE_GIB;
            *pdpt_ptr.add(first + i) = host_phys | PG_PRESENT | PG_RW | PG_USER | PG_PS;
        }
    }
    Ok(())
}

/// Build a PML4 + PDPT that identity-maps the first 512 GiB using 1-GiB
/// huge pages. Returns the PML4 physical address — pass it to
/// `vmcb::enable_npt()` as the NCR3.
pub fn build_identity_512gib() -> Result<NptRoot, NptError> {
    let pml4 = alloc_zero_page()?;
    let pdpt = alloc_zero_page()?;

    unsafe {
        // PML4[0] → PDPT
        let pml4_ptr = pml4 as *mut u64;
        *pml4_ptr.offset(0) = pdpt | PG_PRESENT | PG_RW | PG_USER;

        // PDPT[i] → 1 GiB huge page at i * 1 GiB
        let pdpt_ptr = pdpt as *mut u64;
        for i in 0..PDPT_ENTRIES {
            let phys = (i as u64) * ONE_GIB;
            *pdpt_ptr.add(i) =
                phys | PG_PRESENT | PG_RW | PG_USER | PG_PS;
        }
    }

    Ok(NptRoot {
        pml4_phys: pml4,
        pdpt_phys: pdpt,
        coverage_bytes: (PDPT_ENTRIES as u64) * ONE_GIB,
    })
}

const PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000; // 52-bit physical address mask, page-aligned
const TWO_MIB: u64 = 2 * 1024 * 1024;
const FOUR_KIB: u64 = 4096;

/// Mark a single 4-KiB guest-physical page as not-present, so any guest
/// access faults into our NPF handler. Walks/splits the 1-GiB and 2-MiB
/// huge pages along the way as needed (the rest of the identity region
/// stays mapped, just at a finer granularity for the affected slot).
pub fn install_trap_page(npt: &NptRoot, gpa: u64) -> Result<(), NptError> {
    let pdpt_index = (gpa / ONE_GIB) as usize;
    if pdpt_index >= PDPT_ENTRIES {
        return Err(NptError::PageAllocFailed);
    }

    unsafe {
        let pdpt = npt.pdpt_phys as *mut u64;
        let pdpt_entry = *pdpt.add(pdpt_index);

        // Step 1: ensure the PDPT entry points at a PD (split the 1-GiB
        // huge page if it doesn't already).
        let pd_phys = if pdpt_entry & PG_PS != 0 {
            let pd = alloc_zero_page()?;
            let pd_ptr = pd as *mut u64;
            for i in 0..512u64 {
                let base = (pdpt_index as u64) * ONE_GIB + i * TWO_MIB;
                *pd_ptr.add(i as usize) = base | PG_PRESENT | PG_RW | PG_USER | PG_PS;
            }
            *pdpt.add(pdpt_index) = pd | PG_PRESENT | PG_RW | PG_USER;
            pd
        } else {
            pdpt_entry & PHYS_MASK
        };

        // Step 2: ensure the PD entry points at a PT (split the 2-MiB
        // huge page if it doesn't already).
        let pd_index = ((gpa % ONE_GIB) / TWO_MIB) as usize;
        let pd = pd_phys as *mut u64;
        let pd_entry = *pd.add(pd_index);
        let pt_phys = if pd_entry & PG_PS != 0 {
            let pt = alloc_zero_page()?;
            let pt_ptr = pt as *mut u64;
            for i in 0..512u64 {
                let base = (pdpt_index as u64) * ONE_GIB
                    + (pd_index as u64) * TWO_MIB
                    + i * FOUR_KIB;
                *pt_ptr.add(i as usize) = base | PG_PRESENT | PG_RW | PG_USER;
            }
            *pd.add(pd_index) = pt | PG_PRESENT | PG_RW | PG_USER;
            pt
        } else {
            pd_entry & PHYS_MASK
        };

        // Step 3: clear the chosen 4-KiB PT entry → guest access faults.
        let pt_index = ((gpa % TWO_MIB) / FOUR_KIB) as usize;
        let pt = pt_phys as *mut u64;
        *pt.add(pt_index) = 0;
    }
    Ok(())
}

const PG_NX: u64 = 1 << 63;

/// Split the huge page covering `gpa` down to a 4-KiB PT and return the PT's
/// physical address (reusing an existing split if present).
fn pt_phys_for(npt: &NptRoot, gpa: u64) -> Result<u64, NptError> {
    let pdpt_index = (gpa / ONE_GIB) as usize;
    if pdpt_index >= PDPT_ENTRIES {
        return Err(NptError::PageAllocFailed);
    }
    unsafe {
        let pdpt = npt.pdpt_phys as *mut u64;
        let pdpt_entry = *pdpt.add(pdpt_index);
        let pd_phys = if pdpt_entry & PG_PS != 0 {
            let pd = alloc_zero_page()?;
            let pd_ptr = pd as *mut u64;
            for i in 0..512u64 {
                let base = (pdpt_index as u64) * ONE_GIB + i * TWO_MIB;
                *pd_ptr.add(i as usize) = base | PG_PRESENT | PG_RW | PG_USER | PG_PS;
            }
            *pdpt.add(pdpt_index) = pd | PG_PRESENT | PG_RW | PG_USER;
            pd
        } else {
            pdpt_entry & PHYS_MASK
        };
        let pd_index = ((gpa % ONE_GIB) / TWO_MIB) as usize;
        let pd = pd_phys as *mut u64;
        let pd_entry = *pd.add(pd_index);
        let pt_phys = if pd_entry & PG_PS != 0 {
            let pt = alloc_zero_page()?;
            let pt_ptr = pt as *mut u64;
            for i in 0..512u64 {
                let base = (pdpt_index as u64) * ONE_GIB
                    + (pd_index as u64) * TWO_MIB
                    + i * FOUR_KIB;
                *pt_ptr.add(i as usize) = base | PG_PRESENT | PG_RW | PG_USER;
            }
            *pd.add(pd_index) = pt | PG_PRESENT | PG_RW | PG_USER;
            pt
        } else {
            pd_entry & PHYS_MASK
        };
        Ok(pt_phys)
    }
}

/// Arm an execute-trap on the 4-KiB guest page containing `gpa`: the page
/// stays readable/writable (guest reads — and PatchGuard's integrity scans
/// — see the real bytes) but instruction fetch faults into NPF (exit_info_1
/// bit 4 = I-fetch). Splits the covering huge page to 4 KiB first.
pub fn arm_exec_trap(npt: &NptRoot, gpa: u64) -> Result<(), NptError> {
    let pt_phys = pt_phys_for(npt, gpa)?;
    let pt_index = ((gpa % TWO_MIB) / FOUR_KIB) as usize;
    let page = gpa & !(FOUR_KIB - 1);
    unsafe { *(pt_phys as *mut u64).add(pt_index) = page | PG_PRESENT | PG_RW | PG_USER | PG_NX; }
    Ok(())
}

/// Remove an execute-trap: restore a normal R/W/X 4-KiB mapping for the page.
pub fn disarm_exec_trap(npt: &NptRoot, gpa: u64) -> Result<(), NptError> {
    let pt_phys = pt_phys_for(npt, gpa)?;
    let pt_index = ((gpa % TWO_MIB) / FOUR_KIB) as usize;
    let page = gpa & !(FOUR_KIB - 1);
    unsafe { *(pt_phys as *mut u64).add(pt_index) = page | PG_PRESENT | PG_RW | PG_USER; }
    Ok(())
}

/// Map a single 4-KiB guest-physical page to host-physical `hpa`,
/// present + RW. Unlike `install_trap_page` (which assumes the covering
/// entries are present huge pages and clears a PTE), this also handles
/// **not-present** PDPT/PD entries by allocating fresh, all-not-present
/// tables — so it can punch a mapped hole into an otherwise unmapped
/// region (e.g. placing OVMF at the top of 4 GiB while the surrounding
/// MMIO addresses stay not-present and route through NPF).
pub fn map_page(npt: &NptRoot, gpa: u64, hpa: u64) -> Result<(), NptError> {
    let pdpt_index = (gpa / ONE_GIB) as usize;
    if pdpt_index >= PDPT_ENTRIES {
        return Err(NptError::PageAllocFailed);
    }

    unsafe {
        let pdpt = npt.pdpt_phys as *mut u64;
        let pdpt_entry = *pdpt.add(pdpt_index);

        // Resolve PDPT[i] → PD. Three cases: present huge (split to PD),
        // present table (descend), not-present (alloc empty PD).
        let pd_phys = if pdpt_entry & PG_PRESENT == 0 {
            let pd = alloc_zero_page()?; // all entries not-present
            *pdpt.add(pdpt_index) = pd | PG_PRESENT | PG_RW | PG_USER;
            pd
        } else if pdpt_entry & PG_PS != 0 {
            let pd = alloc_zero_page()?;
            let pd_ptr = pd as *mut u64;
            for i in 0..512u64 {
                let base = (pdpt_index as u64) * ONE_GIB + i * TWO_MIB;
                *pd_ptr.add(i as usize) = base | PG_PRESENT | PG_RW | PG_USER | PG_PS;
            }
            *pdpt.add(pdpt_index) = pd | PG_PRESENT | PG_RW | PG_USER;
            pd
        } else {
            pdpt_entry & PHYS_MASK
        };

        // Resolve PD[i] → PT (same three cases).
        let pd_index = ((gpa % ONE_GIB) / TWO_MIB) as usize;
        let pd = pd_phys as *mut u64;
        let pd_entry = *pd.add(pd_index);
        let pt_phys = if pd_entry & PG_PRESENT == 0 {
            let pt = alloc_zero_page()?;
            *pd.add(pd_index) = pt | PG_PRESENT | PG_RW | PG_USER;
            pt
        } else if pd_entry & PG_PS != 0 {
            let pt = alloc_zero_page()?;
            let pt_ptr = pt as *mut u64;
            for i in 0..512u64 {
                let base = (pdpt_index as u64) * ONE_GIB
                    + (pd_index as u64) * TWO_MIB
                    + i * FOUR_KIB;
                *pt_ptr.add(i as usize) = base | PG_PRESENT | PG_RW | PG_USER | PG_PS;
            }
            *pd.add(pd_index) = pt | PG_PRESENT | PG_RW | PG_USER;
            pt
        } else {
            pd_entry & PHYS_MASK
        };

        // Set the 4-KiB PTE to the requested host page.
        let pt_index = ((gpa % TWO_MIB) / FOUR_KIB) as usize;
        let pt = pt_phys as *mut u64;
        *pt.add(pt_index) = (hpa & PHYS_MASK) | PG_PRESENT | PG_RW | PG_USER;
    }
    Ok(())
}

/// Map a contiguous 4-KiB-aligned guest range [gpa_start, +len) onto
/// host [hpa_start, +len). Used to place guest firmware (OVMF) at the
/// top of the guest's 4-GiB physical window.
pub fn map_range(npt: &NptRoot, gpa_start: u64, hpa_start: u64, len: u64) -> Result<(), NptError> {
    let mut off: u64 = 0;
    while off < len {
        map_page(npt, gpa_start + off, hpa_start + off)?;
        off += FOUR_KIB;
    }
    Ok(())
}

/// Diagnostic: walk the 4-level NPT for `gpa` and log each level's entry,
/// so a "should be mapped but faults" bug is visible in the serial log.
pub fn debug_walk(npt: &NptRoot, gpa: u64) {
    unsafe {
        let pml4 = npt.pml4_phys as *const u64;
        let pml4e = *pml4.add(((gpa >> 39) & 0x1FF) as usize);
        crate::sprintln!("[npt-walk] gpa=0x{:X} PML4[{}]=0x{:X}", gpa, (gpa >> 39) & 0x1FF, pml4e);
        if pml4e & PG_PRESENT == 0 { return; }
        let pdpt = (pml4e & PHYS_MASK) as *const u64;
        let pdpte = *pdpt.add(((gpa >> 30) & 0x1FF) as usize);
        crate::sprintln!("[npt-walk]   PDPT[{}]=0x{:X} (PS={})", (gpa >> 30) & 0x1FF, pdpte, (pdpte & PG_PS) != 0);
        if pdpte & PG_PRESENT == 0 || pdpte & PG_PS != 0 { return; }
        let pd = (pdpte & PHYS_MASK) as *const u64;
        let pde = *pd.add(((gpa >> 21) & 0x1FF) as usize);
        crate::sprintln!("[npt-walk]   PD[{}]=0x{:X} (PS={})", (gpa >> 21) & 0x1FF, pde, (pde & PG_PS) != 0);
        if pde & PG_PRESENT == 0 || pde & PG_PS != 0 { return; }
        let pt = (pde & PHYS_MASK) as *const u64;
        let pte = *pt.add(((gpa >> 12) & 0x1FF) as usize);
        crate::sprintln!("[npt-walk]   PT[{}]=0x{:X}", (gpa >> 12) & 0x1FF, pte);
    }
}

/// Mark a contiguous 4-KiB-aligned range as trapped. Used by the LAPIC
/// MMIO emulator to claim the standard 4-KiB Local APIC window.
pub fn install_trap_range(npt: &NptRoot, gpa_start: u64, len: u64) -> Result<(), NptError> {
    let mut addr = gpa_start & !(FOUR_KIB - 1);
    let end = gpa_start + len;
    while addr < end {
        install_trap_page(npt, addr)?;
        addr += FOUR_KIB;
    }
    Ok(())
}

/// Allocate a fresh zeroed 4-KiB host page and map it (writable) at guest
/// `gpa`, so guest accesses to that page hit RAM instead of faulting. Returns
/// the page's host address (== HPA under UEFI identity mapping), which the
/// caller can also write to directly to reconcile emulated device state.
/// Used for the writable-shadow HPET MMIO page (eliminates the per-arm NPF
/// storm). Replaces an `install_trap_page` for the same GPA.
pub fn map_backing_page(npt: &NptRoot, gpa: u64) -> Result<u64, NptError> {
    let page = alloc_zero_page()?;
    map_page(npt, gpa, page)?;
    Ok(page)
}

fn alloc_zero_page() -> Result<u64, NptError> {
    let page = boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::RUNTIME_SERVICES_DATA,
        1,
    )
    .map_err(|_| NptError::PageAllocFailed)?;
    let ptr = page.as_ptr();
    let addr = ptr as u64;
    if addr & 0xFFF != 0 {
        return Err(NptError::NotPageAligned(addr));
    }
    unsafe { core::ptr::write_bytes(ptr, 0u8, 4096) };
    Ok(addr)
}

// (Earlier draft of `install_trap_2mib` was removed — the PDPT path-walk
// it needed isn't tracked in NptRoot yet. It'll come back when MMIO trap
// regions land, properly designed with a `Pdpt` handle threaded through.)
