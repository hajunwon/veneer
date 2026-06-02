//! IO Port Permission Map (IOPM).
//!
//! AMD SVM consults this 8 KiB + 3-byte bitmap on every IN/OUT if
//! `intercept_vec1.IOIO_PROT = 1`. One bit per port; bit set = intercept.
//! For v0.5-α we allocate two contiguous pages and fill with 0xFF — i.e.
//! intercept every port access — and route through `intercept/io.rs`.
//!
//! AMD requires the IOPM to span 8 KiB plus 3 reserved bytes (technically
//! 12 KiB rounded up). We allocate 3 pages so the structure isn't truncated
//! at a page boundary by accident.

use uefi::boot::{self, AllocateType, MemoryType};

#[derive(Debug)]
pub enum IopmError {
    AllocFailed,
}

/// Allocate a 12-KiB IOPM (3 contiguous pages), fill all 8 KiB of port bits
/// with 0xFF (intercept all 64K ports). Returns the physical address suitable
/// for VMCB.control.iopm_pa.
pub fn alloc_intercept_all() -> Result<u64, IopmError> {
    let pages = boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::RUNTIME_SERVICES_DATA,
        3,
    )
    .map_err(|_| IopmError::AllocFailed)?;
    let ptr = pages.as_ptr();
    unsafe { core::ptr::write_bytes(ptr, 0xFF, 8 * 1024 + 3) };
    Ok(ptr as u64)
}
