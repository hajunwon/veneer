//! Read / write guest physical and virtual memory from L1.
//!
//! Everything routes through the host mapping of guest RAM, so it sees the
//! true physical bytes — under PatchGuard's checksums and under HVCI's
//! VTL0/VTL1 split. This is the foundation every research primitive builds on.

use crate::boot::guest_mem;

use super::translate::gva_to_gpa;

/// Read `buf.len()` bytes from guest-physical `gpa`. Returns false if the
/// range isn't a single contiguous span of mapped guest RAM (the caller can
/// fall back to `read_virt`, which walks page-by-page).
pub fn read_phys(gpa: u64, buf: &mut [u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    let h0 = match guest_mem::to_host(gpa) {
        Some(h) => h,
        None => return false,
    };
    let hl = match guest_mem::to_host(gpa + buf.len() as u64 - 1) {
        Some(h) => h,
        None => return false,
    };
    // Contiguous in host iff the host span equals the gpa span.
    if hl.wrapping_sub(h0) != buf.len() as u64 - 1 {
        return false;
    }
    unsafe { core::ptr::copy_nonoverlapping(h0 as *const u8, buf.as_mut_ptr(), buf.len()); }
    true
}

/// Write `buf` to guest-physical `gpa`. Same contiguity contract as `read_phys`.
pub fn write_phys(gpa: u64, buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    let h0 = match guest_mem::to_host(gpa) {
        Some(h) => h,
        None => return false,
    };
    let hl = match guest_mem::to_host(gpa + buf.len() as u64 - 1) {
        Some(h) => h,
        None => return false,
    };
    if hl.wrapping_sub(h0) != buf.len() as u64 - 1 {
        return false;
    }
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), h0 as *mut u8, buf.len()); }
    true
}

/// Read `buf.len()` bytes from guest-virtual `gva` under page table `cr3`,
/// walking one page at a time so reads spanning page (and large-page)
/// boundaries work. Returns false on the first unmapped page.
pub fn read_virt(cr3: u64, gva: u64, buf: &mut [u8]) -> bool {
    let mut off = 0usize;
    while off < buf.len() {
        let cur = gva + off as u64;
        let gpa = match gva_to_gpa(cr3, cur) {
            Some(g) => g,
            None => return false,
        };
        let page_off = (cur & 0xFFF) as usize;
        let n = core::cmp::min(0x1000 - page_off, buf.len() - off);
        if !read_phys(gpa, &mut buf[off..off + n]) {
            return false;
        }
        off += n;
    }
    true
}

/// Write `buf` to guest-virtual `gva` under `cr3`, page by page.
pub fn write_virt(cr3: u64, gva: u64, buf: &[u8]) -> bool {
    let mut off = 0usize;
    while off < buf.len() {
        let cur = gva + off as u64;
        let gpa = match gva_to_gpa(cr3, cur) {
            Some(g) => g,
            None => return false,
        };
        let page_off = (cur & 0xFFF) as usize;
        let n = core::cmp::min(0x1000 - page_off, buf.len() - off);
        if !write_phys(gpa, &buf[off..off + n]) {
            return false;
        }
        off += n;
    }
    true
}

/// Read a `Copy` value of type `T` from guest-virtual `gva` under `cr3`.
pub fn read_struct<T: Copy>(cr3: u64, gva: u64) -> Option<T> {
    let mut val = core::mem::MaybeUninit::<T>::uninit();
    let buf = unsafe {
        core::slice::from_raw_parts_mut(val.as_mut_ptr() as *mut u8, core::mem::size_of::<T>())
    };
    if read_virt(cr3, gva, buf) {
        Some(unsafe { val.assume_init() })
    } else {
        None
    }
}

/// Convenience: read one little-endian u64 from `gva`.
pub fn read_u64(cr3: u64, gva: u64) -> Option<u64> {
    read_struct::<u64>(cr3, gva)
}
