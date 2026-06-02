//! Multi-processor bring-up via UEFI MP Services.
//!
//! UEFI exposes the Multi-Processor Services Protocol (PI spec §13.4) which
//! lets a UEFI app discover how many processors the platform exposes and
//! dispatch work to APs (Application Processors) without us having to
//! hand-craft INIT-SIPI-SIPI sequences against the local APIC.
//!
//! For v0.6-B we:
//!   1. Locate the MP Services protocol (if the firmware provides it — on
//!      some constrained guest VMs the protocol is absent and we just
//!      report a single-CPU topology).
//!   2. Query `get_number_of_processors()` for total + enabled AP counts.
//!   3. Cross-check against CPUID 0x8000_0008 (we already use this).
//!   4. Per-vCPU VM_HSAVE_PA allocation (one 4 KiB page each).
//!
//! Actual SVM enable on the AP + per-vCPU VMRUN dispatch is v0.6-C; here
//! we lay the structural groundwork only.

use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use uefi::boot::{self, AllocateType, MemoryType};
use uefi::proto::pi::mp::MpServices;

use crate::arch::{
    cpuid, rdmsr, read_cr0, read_cr3, read_cr4, wrmsr, EFER_SVME, MSR_EFER, MSR_VM_HSAVE_PA,
};
use crate::svm::gprs::GuestGprs;
use crate::vmexit::{self, Action};
use crate::identity::profile;
use crate::svm::vmcb::Vmcb;
use crate::svm::vmrun;

#[derive(Debug, Clone, Copy)]
pub struct SmpInfo {
    pub total: usize,
    pub enabled: usize,
    pub bsp_index: usize,
}

#[derive(Debug)]
pub enum SmpError {
    ProtocolMissing,
    QueryFailed,
    AllocFailed,
}

// AMD SVM-related constants — duplicated from svm.rs so AP code doesn't
// have to reach across modules (the AP callback is the only place outside
// svm.rs that needs them).
const SVM_CPUID_FLAG: u32 = 1 << 2;       // CPUID 0x8000_0001.ECX bit 2
const VM_CR_MSR: u32 = 0xC001_0114;
const VM_CR_SVMDIS: u64 = 1 << 4;

/// Returns Some(SmpInfo) if MP Services is available, None otherwise. UEFI
/// VMs sometimes omit the protocol; in that case the launcher should fall
/// back to CPUID-derived counts.
pub fn probe() -> Result<SmpInfo, SmpError> {
    let handle = boot::get_handle_for_protocol::<MpServices>()
        .map_err(|_| SmpError::ProtocolMissing)?;
    let mp = boot::open_protocol_exclusive::<MpServices>(handle)
        .map_err(|_| SmpError::ProtocolMissing)?;
    let count = mp.get_number_of_processors().map_err(|_| SmpError::QueryFailed)?;
    let bsp = mp.who_am_i().map_err(|_| SmpError::QueryFailed)?;
    Ok(SmpInfo {
        total: count.total,
        enabled: count.enabled,
        bsp_index: bsp,
    })
}

/// Per-AP VM_HSAVE_PA allocation. AMD requires a unique host-save area for
/// every CPU that executes VMRUN, distinct from the BSP's. We allocate one
/// 4 KiB page per AP and return their physical addresses.
pub fn alloc_per_ap_hsave(n_aps: usize) -> Result<heapless_vec::Vec<u64, 32>, SmpError> {
    let mut out = heapless_vec::Vec::new();
    for _ in 0..n_aps {
        let p = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::RUNTIME_SERVICES_DATA,
            1,
        )
        .map_err(|_| SmpError::AllocFailed)?;
        unsafe { core::ptr::write_bytes(p.as_ptr(), 0u8, 4096) };
        out.push(p.as_ptr() as u64).map_err(|_| SmpError::AllocFailed)?;
    }
    Ok(out)
}

/// Per-AP extended host save area for VMSAVE/VMLOAD. Distinct from
/// VM_HSAVE_PA (hardware auto-save target). Stores host FS.base, GS.base,
/// KernelGsBase, STAR/LSTAR/CSTAR/SFMASK, SYSENTER_* across guest entry.
pub fn alloc_per_ap_ext_save(n_aps: usize) -> Result<heapless_vec::Vec<u64, 32>, SmpError> {
    let mut out = heapless_vec::Vec::new();
    for _ in 0..n_aps {
        let p = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::RUNTIME_SERVICES_DATA,
            1,
        )
        .map_err(|_| SmpError::AllocFailed)?;
        unsafe { core::ptr::write_bytes(p.as_ptr(), 0u8, 4096) };
        out.push(p.as_ptr() as u64).map_err(|_| SmpError::AllocFailed)?;
    }
    Ok(out)
}

/// Per-AP snapshot filled in by `ap_callback`. APs run concurrently; each
/// writes into its own slot (indexed by APIC ID) so there's no contention.
#[derive(Debug, Default, Clone, Copy)]
pub struct ApReport {
    pub valid: bool,
    pub apic_id: u8,
    pub vendor: [u8; 12],
    pub svm_supported: bool,
    pub svmdis: bool,
    pub efer: u64,
}

pub const MAX_AP_SLOTS: usize = 16;

#[derive(Clone, Copy)]
pub struct ApReports {
    pub slots: [ApReport; MAX_AP_SLOTS],
}

impl ApReports {
    fn empty() -> Self {
        Self { slots: [ApReport::default(); MAX_AP_SLOTS] }
    }
}

/// Callback invoked on every AP by UEFI MP Services. Must be re-entrant —
/// each call runs on a different physical CPU, but slot indexing by APIC
/// ID gives every AP a private write target.
extern "efiapi" fn ap_callback(arg: *mut c_void) {
    if arg.is_null() {
        return;
    }
    let reports = unsafe { &mut *(arg as *mut ApReports) };

    let leaf0 = cpuid(0);
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&leaf0.ecx.to_le_bytes());

    let leaf1 = cpuid(1);
    let apic_id = ((leaf1.ebx >> 24) & 0xFF) as u8;

    let leaf_ext1 = cpuid(0x8000_0001);
    let svm_supported = (leaf_ext1.ecx & SVM_CPUID_FLAG) != 0;

    // VM_CR + EFER reads need rdmsr — safe in UEFI ring-0 even on the AP.
    let vm_cr = unsafe { rdmsr(VM_CR_MSR) };
    let svmdis = (vm_cr & VM_CR_SVMDIS) != 0;
    let efer = unsafe { rdmsr(MSR_EFER) };

    let idx = (apic_id as usize) & (MAX_AP_SLOTS - 1);
    let slot = &mut reports.slots[idx];
    slot.valid = true;
    slot.apic_id = apic_id;
    slot.vendor = vendor;
    slot.svm_supported = svm_supported;
    slot.svmdis = svmdis;
    slot.efer = efer;
}

/// Dispatch `ap_callback` to every AP (BSP excluded) via UEFI MP Services
/// and return the populated snapshot. Single-CPU systems short-circuit to
/// an empty report.
pub fn run_ap_probe() -> Result<ApReports, SmpError> {
    let handle = boot::get_handle_for_protocol::<MpServices>()
        .map_err(|_| SmpError::ProtocolMissing)?;
    let mp = boot::open_protocol_exclusive::<MpServices>(handle)
        .map_err(|_| SmpError::ProtocolMissing)?;
    let count = mp.get_number_of_processors().map_err(|_| SmpError::QueryFailed)?;
    if count.enabled <= 1 {
        return Ok(ApReports::empty());
    }
    let mut reports = ApReports::empty();
    let arg = &mut reports as *mut ApReports as *mut c_void;
    mp.startup_all_aps(false, ap_callback, arg, None, Some(Duration::from_secs(5)))
        .map_err(|_| SmpError::QueryFailed)?;
    Ok(reports)
}

/// Result snapshot from one AP's complete SVM-bringup-and-VMRUN round.
/// `last_*` fields capture the most recent VMEXIT — useful when the loop
/// aborts and we need to know *why* without serial access from the AP.
#[derive(Default, Clone, Copy)]
pub struct ApVmRunResult {
    pub valid: bool,
    pub apic_id: u8,
    pub iter_count: u32,
    pub final_rax: u64,
    pub signature_match: bool,
    pub aborted: bool,
    pub last_exit_code: u64,
    pub last_exit_info_1: u64,
    pub last_exit_info_2: u64,
    pub last_rip: u64,
    pub efer_after_svme: u64,
    pub vm_hsave_pa_readback: u64,
    pub host_cr0: u64,
    pub host_cr3: u64,
    pub host_cr4: u64,
    pub vmcb_guest_efer: u64,
    pub vmcb_guest_cr0: u64,
    pub vmcb_guest_cr3: u64,
    pub vmcb_guest_cr4: u64,
    pub vmcb_asid: u32,
}

/// Per-AP VMRUN setup. BSP populates `vmcb_phys[i]` and `hsave_pa[i]` for
/// each AP slot (i ∈ 0..n_aps) before calling `run_ap_vmrun`. Each AP
/// claims a slot via the atomic counter, performs its own SVM bring-up
/// using the assigned hsave page, and runs VMRUN against its assigned
/// VMCB. Results land back in `results[i]`.
pub struct ApVmRunSetup {
    pub n_aps: usize,
    pub vmcb_phys: [u64; MAX_AP_SLOTS],
    pub hsave_pa: [u64; MAX_AP_SLOTS],
    pub ext_save_pa: [u64; MAX_AP_SLOTS],
    pub results: [ApVmRunResult; MAX_AP_SLOTS],
}

impl ApVmRunSetup {
    pub fn empty() -> Self {
        Self {
            n_aps: 0,
            vmcb_phys: [0; MAX_AP_SLOTS],
            hsave_pa: [0; MAX_AP_SLOTS],
            ext_save_pa: [0; MAX_AP_SLOTS],
            results: [ApVmRunResult::default(); MAX_AP_SLOTS],
        }
    }
}

/// Slot dispenser. Each AP fetches a unique index into `setup.vmcb_phys`/
/// `hsave_pa` from this counter. Reset to 0 at the start of every probe.
static AP_SLOT_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Maximum VMRUN iterations per AP — same budget as the BSP loop. With
/// the 21-path guest blob, ~21 iterations finish; anything more means we
/// derailed and the watchdog should give up.
pub const MAX_AP_VMRUN_ITERS: u32 = 32;

/// Callback invoked by UEFI MP Services on every AP. Each AP:
///   1. Claims a unique slot via AP_SLOT_COUNTER
///   2. Reads its APIC ID for reporting
///   3. Brings up SVM on itself (EFER.SVME=1 + VM_HSAVE_PA ← per-AP page)
///   4. Runs VMRUN against its assigned VMCB until HLT/abort/timeout
///   5. Writes a result snapshot back into setup.results[slot]
///
/// AP code path does NOT touch the serial port — all I/O is BSP-only to
/// avoid race conditions on COM1. Result aggregation happens after
/// `startup_all_aps` returns.
extern "efiapi" fn ap_vmrun_callback(arg: *mut c_void) {
    if arg.is_null() {
        return;
    }
    let setup = unsafe { &mut *(arg as *mut ApVmRunSetup) };
    let slot = AP_SLOT_COUNTER.fetch_add(1, Ordering::SeqCst);
    if slot >= setup.n_aps {
        return;
    }

    let vmcb_phys = setup.vmcb_phys[slot];
    let hsave_pa = setup.hsave_pa[slot];
    let ext_save_pa = setup.ext_save_pa[slot];
    let apic_id = ((cpuid(1).ebx >> 24) & 0xFF) as u8;

    // Per-AP SVM bring-up. Mirror of svm::bringup but trimmed: AP shares
    // the BSP's vendor/SVM-capable verification (already passed in the
    // ap_probe phase), so we only need to flip EFER.SVME and point
    // VM_HSAVE_PA at our private host save area.
    let (efer_after, hsave_readback) = unsafe {
        let efer = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer | EFER_SVME);
        wrmsr(MSR_VM_HSAVE_PA, hsave_pa);
        (rdmsr(MSR_EFER), rdmsr(MSR_VM_HSAVE_PA))
    };

    // VMRUN loop against the assigned VMCB. BSP has already done
    // init_guest + enable_npt for this VMCB before dispatching us.
    let mut gprs = GuestGprs::default();
    let mut iters = 0u32;
    let mut final_rax = 0u64;
    let mut sig_match = false;
    let mut aborted = false;
    let mut last_exit_code = 0u64;
    let mut last_exit_info_1 = 0u64;
    let mut last_exit_info_2 = 0u64;
    let mut last_rip = 0u64;

    while iters < MAX_AP_VMRUN_ITERS {
        iters += 1;
        let info = unsafe { vmrun::vmrun(vmcb_phys, ext_save_pa, &mut gprs) };
        last_exit_code = info.exit_code;
        last_exit_info_1 = info.exit_info_1;
        last_exit_info_2 = info.exit_info_2;
        last_rip = info.guest_rip;
        let action = unsafe { vmexit::dispatch(vmcb_phys as *mut Vmcb, &mut gprs) };
        match action {
            Action::Resume => continue,
            Action::Halt => {
                final_rax = unsafe { (*(vmcb_phys as *mut Vmcb)).state.rax };
                sig_match = final_rax == profile::DEFAULT.vmmcall_signature;
                break;
            }
            Action::Abort => {
                aborted = true;
                break;
            }
        }
    }

    // Capture host context + VMCB state for diagnosis. Doing this after
    // the VMRUN loop is OK because no handler mutates host context.
    let host_cr0 = read_cr0();
    let host_cr3 = read_cr3();
    let host_cr4 = read_cr4();
    let (vmcb_efer, vmcb_cr0, vmcb_cr3, vmcb_cr4, vmcb_asid) = unsafe {
        let v = vmcb_phys as *const Vmcb;
        let st = &(*v).state;
        let ct = &(*v).control;
        // Packed-struct fields need to be read via copy to avoid
        // unaligned-reference UB.
        let efer = core::ptr::addr_of!(st.efer).read_unaligned();
        let cr0 = core::ptr::addr_of!(st.cr0).read_unaligned();
        let cr3 = core::ptr::addr_of!(st.cr3).read_unaligned();
        let cr4 = core::ptr::addr_of!(st.cr4).read_unaligned();
        let asid = core::ptr::addr_of!(ct.guest_asid).read_unaligned();
        (efer, cr0, cr3, cr4, asid)
    };

    setup.results[slot] = ApVmRunResult {
        valid: true,
        apic_id,
        iter_count: iters,
        final_rax,
        signature_match: sig_match,
        aborted,
        last_exit_code,
        last_exit_info_1,
        last_exit_info_2,
        last_rip,
        efer_after_svme: efer_after,
        vm_hsave_pa_readback: hsave_readback,
        host_cr0,
        host_cr3,
        host_cr4,
        vmcb_guest_efer: vmcb_efer,
        vmcb_guest_cr0: vmcb_cr0,
        vmcb_guest_cr3: vmcb_cr3,
        vmcb_guest_cr4: vmcb_cr4,
        vmcb_asid,
    };

    // Defensive in-callback SVM cleanup: clear EFER.SVME and zero
    // VM_HSAVE_PA so the AP returns to the UEFI MP-services idle loop
    // (and ultimately to Linux's SIPI handler) without a stale host
    // save area pointer. INIT-from-Linux would reset EFER anyway, but
    // doing it here means no AP ever sits idle in SVM host state.
    unsafe {
        let efer = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer & !EFER_SVME);
        wrmsr(MSR_VM_HSAVE_PA, 0);
    }
}

/// Dispatch `ap_vmrun_callback` to every AP and block until they all
/// finish (or the 10-second watchdog fires). The caller must have
/// already populated `setup.n_aps`, `setup.vmcb_phys[..n_aps]`, and
/// Per-AP cleanup before chain-loading a guest OS. Clears EFER.SVME and
/// zeroes VM_HSAVE_PA on every AP so the chain-loaded kernel doesn't
/// inherit AP cores stuck in SVM host state with a stashed hsave page
/// that points into our (soon-to-be-reclaimed) UEFI loader memory. When
/// Linux later sends INIT-SIPI to those APs, they wake up in a clean
/// CPU state instead of wrapping around our hypervisor context.
extern "efiapi" fn ap_svm_cleanup_callback(arg: *mut c_void) {
    let efer_out = arg as *mut u64;
    unsafe {
        let efer_before = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer_before & !EFER_SVME);
        wrmsr(MSR_VM_HSAVE_PA, 0);
        let efer_after = rdmsr(MSR_EFER);
        // Record the AP's post-cleanup EFER for BSP-side logging. We
        // index by APIC ID to give every AP a private slot; collisions
        // are impossible because each callback runs on a distinct CPU.
        let leaf1 = cpuid(1);
        let apic_id = ((leaf1.ebx >> 24) & 0xFF) as usize;
        let idx = apic_id & (MAX_AP_SLOTS - 1);
        if !efer_out.is_null() {
            efer_out.add(idx).write_volatile(efer_after);
        }
    }
}

/// Disable SVM on every AP and zero VM_HSAVE_PA. Returns a per-AP-slot
/// array of post-cleanup EFER values (indexed by APIC ID modulo
/// MAX_AP_SLOTS) so the BSP can log/verify.
pub fn cleanup_ap_svm() -> Result<[u64; MAX_AP_SLOTS], SmpError> {
    crate::sprintln!("[svm-cleanup]   step 1: get_handle_for_protocol<MpServices>");
    let handle = boot::get_handle_for_protocol::<MpServices>()
        .map_err(|_| SmpError::ProtocolMissing)?;
    crate::sprintln!("[svm-cleanup]   step 2: open_protocol_exclusive<MpServices>");
    let mp = boot::open_protocol_exclusive::<MpServices>(handle)
        .map_err(|_| SmpError::ProtocolMissing)?;
    crate::sprintln!("[svm-cleanup]   step 3: get_number_of_processors");
    let count = mp.get_number_of_processors().map_err(|_| SmpError::QueryFailed)?;
    crate::sprintln!(
        "[svm-cleanup]   step 3 done: total={} enabled={}",
        count.total, count.enabled,
    );
    let mut efers = [0u64; MAX_AP_SLOTS];
    if count.enabled <= 1 {
        return Ok(efers);
    }
    let arg = efers.as_mut_ptr() as *mut c_void;
    crate::sprintln!("[svm-cleanup]   step 4: startup_all_aps (blocking, 5s timeout)");
    mp.startup_all_aps(
        false,
        ap_svm_cleanup_callback,
        arg,
        None,
        Some(Duration::from_secs(5)),
    )
    .map_err(|_| SmpError::QueryFailed)?;
    crate::sprintln!("[svm-cleanup]   step 5: startup_all_aps returned");
    Ok(efers)
}

/// `setup.hsave_pa[..n_aps]`.
pub fn run_ap_vmrun(setup: &mut ApVmRunSetup) -> Result<(), SmpError> {
    if setup.n_aps == 0 {
        return Ok(());
    }
    AP_SLOT_COUNTER.store(0, Ordering::SeqCst);
    let handle = boot::get_handle_for_protocol::<MpServices>()
        .map_err(|_| SmpError::ProtocolMissing)?;
    let mp = boot::open_protocol_exclusive::<MpServices>(handle)
        .map_err(|_| SmpError::ProtocolMissing)?;
    let arg = setup as *mut ApVmRunSetup as *mut c_void;
    mp.startup_all_aps(
        false,
        ap_vmrun_callback,
        arg,
        None,
        Some(Duration::from_secs(10)),
    )
    .map_err(|_| SmpError::QueryFailed)?;
    Ok(())
}

// Tiny inline fixed-capacity Vec wrapper — uefi crate 0.32 doesn't pull in
// `alloc` by default, so we hand-roll one with up-to-32-vCPU capacity.
#[allow(dead_code)] // `iter` is for future per-AP launch code
pub mod heapless_vec {
    pub struct Vec<T: Copy, const N: usize> {
        buf: [Option<T>; N],
        len: usize,
    }

    impl<T: Copy, const N: usize> Vec<T, N> {
        pub fn new() -> Self {
            Self {
                buf: [None; N],
                len: 0,
            }
        }
        pub fn push(&mut self, v: T) -> Result<(), ()> {
            if self.len >= N {
                return Err(());
            }
            self.buf[self.len] = Some(v);
            self.len += 1;
            Ok(())
        }
        pub fn len(&self) -> usize {
            self.len
        }
        pub fn iter(&self) -> impl Iterator<Item = &T> {
            self.buf[..self.len].iter().filter_map(Option::as_ref)
        }
    }
}
