//! AMD SVM bring-up sequence. v0.3-alpha: detect → enable EFER.SVME →
//! allocate host save area → write VM_HSAVE_PA. No VMCB / VMRUN yet.
//!
//! References:
//!   AMD64 Architecture Programmer's Manual Volume 2 — System Programming
//!     §15.3 "Enabling SVM"
//!     §15.5.1 "Host State-Save Area"
//!     Appendix A.7 "SVM-Related MSRs"

pub mod vmcb;
pub mod vmrun;
pub mod npt;
pub mod msrpm;
pub mod iopm;
pub mod smp;
pub mod vcpu_pool;
pub mod gprs;

use crate::infra::arch::{cpuid, rdmsr, wrmsr, EFER_SVME, MSR_EFER, MSR_VM_HSAVE_PA};
use uefi::boot::{self, AllocateType, MemoryType};

#[derive(Debug)]
pub struct SvmState {
    pub vendor: [u8; 12],
    pub family_model_stepping: u32,
    pub svm_supported: bool,
    pub nested_paging: bool,
    /// CPUID 0x8000_000A.EDX bit 3 — NRIPS. When set, the CPU writes the
    /// linear address of the instruction *following* the intercepted one
    /// into VMCB.control.next_rip (offset 0x0C8) on most intercepts, so
    /// handlers can advance RIP without computing instruction length.
    pub nrips: bool,
    /// CPUID 0x8000_000A.EDX bit 7 — DecodeAssists. When set the CPU fills
    /// guest_inst_bytes / guest_inst_len on NPF (and supplies the GPR index
    /// in CR exit_info_1). Used by the NPF MOV decoder.
    pub decode_assists: bool,
    pub n_asids: u32,
    pub efer_before: u64,
    pub efer_after: u64,
    pub vm_hsave_pa_before: u64,
    pub vm_hsave_pa_after: u64,
    pub ext_save_pa: u64,
    pub vmcb_phys: u64,
    pub vmcb_intercept_vec1: u32,
    pub vmcb_intercept_vec2: u32,
    pub vmcb_guest_asid: u32,
    /// MSR-permissions map (8 KiB) used by every vCPU's VMCB. Shared so
    /// AP VMCBs can reuse the same trap-all bitmap.
    pub msrpm_phys: u64,
    /// IO-permissions map (12 KiB) used by every vCPU's VMCB.
    pub iopm_phys: u64,
}

#[derive(Debug)]
pub enum BringupError {
    NotAmd,
    SvmUnsupported,
    SvmDisabledByBios,
    EferWriteRejected,
    HostSaveAllocFailed,
    HsavePaReadbackMismatch { wrote: u64, read: u64 },
    VmcbAllocFailed(vmcb::AllocError),
}

const SVM_CPUID_FLAG: u32 = 1 << 2;        // CPUID 0x8000_0001.ECX bit 2
const NESTED_PAGING_FLAG: u32 = 1 << 0;    // CPUID 0x8000_000A.EDX bit 0
const NRIPS_FLAG: u32 = 1 << 3;            // CPUID 0x8000_000A.EDX bit 3
const DECODE_ASSISTS_FLAG: u32 = 1 << 7;   // CPUID 0x8000_000A.EDX bit 7
const VM_CR_MSR: u32 = 0xC001_0114;        // AMD APM Vol2 §15.3
const VM_CR_SVMDIS: u64 = 1 << 4;          // "SVM disabled at BIOS"
const FOUR_KIB: usize = 4096;

/// Enable SVM, allocate host save area, register it with the CPU.
/// Returns a structured snapshot of every state transition for logging.
pub fn bringup() -> Result<SvmState, BringupError> {
    // ---- 1. Vendor string from CPUID leaf 0 ----
    let leaf0 = cpuid(0);
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&leaf0.ecx.to_le_bytes());
    if &vendor != b"AuthenticAMD" {
        return Err(BringupError::NotAmd);
    }

    // ---- 2. SVM support flag ----
    let leaf81 = cpuid(0x8000_0001);
    if leaf81.ecx & SVM_CPUID_FLAG == 0 {
        return Err(BringupError::SvmUnsupported);
    }

    // ---- 3. BIOS disable check (VM_CR.SVMDIS) ----
    // If SVMDIS is set, EFER.SVME writes are silently ignored.
    let vm_cr = unsafe { rdmsr(VM_CR_MSR) };
    if vm_cr & VM_CR_SVMDIS != 0 {
        return Err(BringupError::SvmDisabledByBios);
    }

    // ---- 4. Capability detail (CPUID 0x8000_000A) ----
    let leaf8a = cpuid(0x8000_000A);
    let nested_paging = leaf8a.edx & NESTED_PAGING_FLAG != 0;
    let nrips = leaf8a.edx & NRIPS_FLAG != 0;
    let decode_assists = leaf8a.edx & DECODE_ASSISTS_FLAG != 0;
    let n_asids = leaf8a.ebx;

    // Publish the NRIPS / DecodeAssists capability to the intercept layer so
    // RIP-advance helpers can prefer the hardware-provided next_rip over the
    // hardcoded instruction-length table. Done before any VMRUN so the very
    // first intercept already sees the correct flags.
    crate::hypervisor::vmexit::set_cpu_features(nrips, decode_assists);

    // ---- 5. Family/Model/Stepping for reporting ----
    let leaf1 = cpuid(1);
    let fms = leaf1.eax;

    // ---- 6. Read EFER, set SVME, verify ----
    let efer_before = unsafe { rdmsr(MSR_EFER) };
    unsafe { wrmsr(MSR_EFER, efer_before | EFER_SVME) };
    let efer_after = unsafe { rdmsr(MSR_EFER) };
    if efer_after & EFER_SVME == 0 {
        return Err(BringupError::EferWriteRejected);
    }

    // ---- 7. Allocate 4KB physically-contiguous, 4KB-aligned host save area.
    // UEFI BootServices.AllocatePages returns a physical address that is
    // already identity-mapped (UEFI requires this). The page is 4KB-aligned by
    // definition (the API only deals in pages).
    let phys = boot::allocate_pages(AllocateType::AnyPages, MemoryType::RUNTIME_SERVICES_DATA, 1)
        .map_err(|_| BringupError::HostSaveAllocFailed)?;
    let phys_addr = phys.as_ptr() as u64;

    // Zero the page (AMD APM doesn't require this, but it makes inspection
    // easier when something goes wrong).
    unsafe { core::ptr::write_bytes(phys.as_ptr(), 0u8, FOUR_KIB) };

    // ---- 8. Tell the CPU about it via VM_HSAVE_PA ----
    let vm_hsave_pa_before = unsafe { rdmsr(MSR_VM_HSAVE_PA) };
    unsafe { wrmsr(MSR_VM_HSAVE_PA, phys_addr) };
    let vm_hsave_pa_after = unsafe { rdmsr(MSR_VM_HSAVE_PA) };
    if vm_hsave_pa_after != phys_addr {
        return Err(BringupError::HsavePaReadbackMismatch {
            wrote: phys_addr,
            read: vm_hsave_pa_after,
        });
    }

    // ---- 8b. Allocate extended host save area for VMSAVE/VMLOAD.
    // VMRUN/VMEXIT save/restore the basic state to VM_HSAVE_PA, but
    // FS.base, GS.base, KernelGsBase, STAR/LSTAR/CSTAR/SFMASK,
    // SYSENTER_* require manual VMSAVE/VMLOAD. Without this, every
    // guest GS-relative percpu access reads from kernel image template
    // (CPU.GS.base stays 0) -> silent zero -> __list_del_entry NULL deref.
    let ext_save = boot::allocate_pages(AllocateType::AnyPages, MemoryType::RUNTIME_SERVICES_DATA, 1)
        .map_err(|_| BringupError::HostSaveAllocFailed)?;
    let ext_save_pa = ext_save.as_ptr() as u64;
    unsafe { core::ptr::write_bytes(ext_save.as_ptr(), 0u8, FOUR_KIB) };

    // ---- 9. Allocate MSRPM (8 KiB, intercept-all) + IOPM (12 KiB, intercept-all) ----
    let msrpm_phys = crate::hypervisor::svm::msrpm::alloc_intercept_all()
        .map_err(|_| BringupError::HostSaveAllocFailed)?;
    let iopm_phys = crate::hypervisor::svm::iopm::alloc_intercept_all()
        .map_err(|_| BringupError::HostSaveAllocFailed)?;

    // ---- 10. Allocate VMCB (4 KiB), configure intercepts ----
    let vmcb = vmcb::alloc_vmcb().map_err(BringupError::VmcbAllocFailed)?;
    unsafe { vmcb::init_for_cpuid_intercept(vmcb, msrpm_phys, iopm_phys) };
    let vmcb_phys = vmcb as u64;
    // Read back the intercept fields to confirm the writes actually landed
    // in the 4 KiB page (catches typos in offset constants).
    let (ivec1, ivec2, asid) = unsafe {
        let c = &(*vmcb).control;
        // SAFETY: VMCB control is `#[repr(C, packed)]`. Copy each field by
        // value before reading to avoid unaligned-reference UB.
        (c.intercept_vec1, c.intercept_vec2, c.guest_asid)
    };

    Ok(SvmState {
        vendor,
        family_model_stepping: fms,
        svm_supported: true,
        nested_paging,
        nrips,
        decode_assists,
        n_asids,
        efer_before,
        efer_after,
        vm_hsave_pa_before,
        vm_hsave_pa_after,
        ext_save_pa,
        vmcb_phys,
        vmcb_intercept_vec1: ivec1,
        vmcb_intercept_vec2: ivec2,
        vmcb_guest_asid: asid,
        msrpm_phys,
        iopm_phys,
    })
}
