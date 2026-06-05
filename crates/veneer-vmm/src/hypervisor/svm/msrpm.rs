//! MSR Permission Map (MSRPM).
//!
//! AMD SVM consults this 8-KiB bitmap on every RDMSR/WRMSR if
//! `intercept_vec1.MSR_PROT = 1`. Two bits per MSR (read + write). We allocate
//! the page pair, point VMCB.control.msrpm_pa at it, and (for v0.4-final)
//! fill every byte with 0xFF — i.e. intercept *every* MSR access. The
//! handler in `intercept/msr.rs` then routes per request.
//!
//! Layout (AMD APM Vol 2 §15.11):
//!   bytes 0x0000–0x07FF : MSRs 0x0000_0000–0x0000_1FFF (low)
//!   bytes 0x0800–0x0FFF : MSRs 0xC000_0000–0xC000_1FFF (high)
//!   bytes 0x1000–0x17FF : MSRs 0xC001_0000–0xC001_1FFF (AMD-specific)
//!   bytes 0x1800–0x1FFF : reserved
//! Each MSR occupies 2 bits: bit 0 = read intercept, bit 1 = write intercept.


pub const MSRPM_BYTES: usize = 8 * 1024;

#[derive(Debug)]
pub enum MsrpmError {
    AllocFailed,
}

/// Allocate the MSRPM (2 contiguous pages), fill with 0xFF (intercept all),
/// return the physical address suitable for VMCB.control.msrpm_pa.
pub fn alloc_intercept_all() -> Result<u64, MsrpmError> {
    // 2 contiguous pages = 8 KiB.
    let pages = crate::platform::alloc_pages(2,
    )
    .map_err(|_| MsrpmError::AllocFailed)?;
    let ptr = pages.as_ptr();
    unsafe { core::ptr::write_bytes(ptr, 0xFF, MSRPM_BYTES) };
    Ok(ptr as u64)
}
