//! Stealth execution-hook engine.
//!
//! Built on `introspect` (VMI) + the NPT execute-trap (`npt::arm_exec_trap`).
//! A hooked page is marked execute-trap in the NPT: the guest *reading* it —
//! and PatchGuard's integrity scans / HVCI's code-integrity reads — see the
//! real bytes with no fault, but instruction *fetch* faults into NPF, where
//! we capture the guest context. Invisible to in-guest defenses: nothing in
//! the guest's own memory view changes and no guest code is patched.
//!
//! Re-arm uses a transient single-step: on a hit we disarm the page (so the
//! trapped instruction runs), set RFLAGS.TF, and intercept #DB *only for that
//! one step*. The #DB after the instruction re-arms the page and drops the
//! intercept — so the hook captures *every* execution, and the guest's own
//! #DB outside the step window are never intercepted (no reinjection needed).
//!
//! ## Status / TODO
//! - [x] NX view-split exec-trap (reads pass → PatchGuard-safe; exec faults).
//! - [x] Single-step re-arm (capture on every execution, transient #DB intercept).
//! - [x] NPT root published once at bring-up; OS-agnostic (no Windows specifics).
//! - [ ] Argument capture: decode calling convention, read register/stack args via VMI.
//! - [ ] Targeting: resolve vgk.sys base / function GPA (offset extractor + EPROCESS/module walk).
//! - [ ] INT3 exec-split primitive (instruction-granular, vs page-granular NX).
//! - [ ] Hide RFLAGS.TF from guest reads during the step (full stealth).
//! - [ ] HVCI-on (nested) NPT reconciliation.
//! - [ ] >1 concurrent pending step (today: single vCPU, one pending slot).
//! - [ ] Live-guest validation (untested — no Windows boot yet).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hypervisor::svm::gprs::GuestGprs;
use crate::hypervisor::svm::npt::{self, NptRoot};
use crate::hypervisor::svm::vmcb::Vmcb;

const MAX_HOOKS: usize = 64;
const PAGE_MASK: u64 = !0xFFF;
const RFLAGS_TF: u64 = 1 << 8; // single-step trap flag
const EXCP_DB: u32 = 1 << 1; // intercept_exceptions bit for #DB (vector 1)

static HOOK_PAGE: [AtomicU64; MAX_HOOKS] = [const { AtomicU64::new(0) }; MAX_HOOKS];
static HOOK_HITS: [AtomicU64; MAX_HOOKS] = [const { AtomicU64::new(0) }; MAX_HOOKS];

// ── Delay/stall diagnostic probe ──
// Per-slot exact function-entry GVA + kind (0 = plain exec hook). On a hit AT
// the entry we log the requested duration + caller (who timed-waits and how
// long), to diagnose the ~80%-idle boot. The page-granular NX trap also faults
// the entry's page-mates; the rip==entry check filters to the probed function.
static HOOK_ENTRY: [AtomicU64; MAX_HOOKS] = [const { AtomicU64::new(0) }; MAX_HOOKS];
static HOOK_KIND: [AtomicU64; MAX_HOOKS] = [const { AtomicU64::new(0) }; MAX_HOOKS];
static DELAY_NT_BASE: AtomicU64 = AtomicU64::new(0);
static DELAY_LOG: AtomicU64 = AtomicU64::new(0);
const KIND_DELAY: u64 = 1;

/// Arm an exec-probe on KeDelayExecutionThread so each timed sleep logs its
/// interval + caller. `nt_base` = ntoskrnl image base (ASLR); `cr3` any guest
/// CR3 (kernel is global). Idempotent; armed once the base is known.
pub fn arm_delay_probes(nt_base: u64, cr3: u64) {
    use core::sync::atomic::AtomicBool;
    static ARMED: AtomicBool = AtomicBool::new(false);
    if ARMED.swap(true, Ordering::AcqRel) {
        return;
    }
    DELAY_NT_BASE.store(nt_base, Ordering::Relaxed);
    let root = match active_npt() { Some(r) => r, None => return };
    // KeDelayExecutionThread RVA (tiny11 26100.8036).
    let gva = nt_base.wrapping_add(0x33_BC60);
    let gpa = match crate::introspect::translate::gva_to_gpa(cr3, gva) {
        Some(g) => g,
        None => { crate::sprintln!("[delay-probe] gva_to_gpa failed for 0x{:X}", gva); return; }
    };
    let page = gpa & PAGE_MASK;
    for (i, slot) in HOOK_PAGE.iter().enumerate() {
        if slot.compare_exchange(0, page, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            if npt::arm_exec_trap(&root, page).is_ok() {
                HOOK_ENTRY[i].store(gva, Ordering::Relaxed);
                HOOK_KIND[i].store(KIND_DELAY, Ordering::Relaxed);
                HOOK_HITS[i].store(0, Ordering::Relaxed);
                crate::sprintln!("[delay-probe] armed KeDelayExecutionThread gva=0x{:X} gpa=0x{:X}", gva, gpa);
            } else {
                slot.store(0, Ordering::Release);
            }
            return;
        }
    }
}

/// Capture a delay-probe hit: log the requested sleep interval + the caller.
unsafe fn probe_capture(vmcb: *mut Vmcb, gprs: &GuestGprs, _kind: u64) {
    let cr3 = unsafe { (*vmcb).state.cr3 };
    let rsp = unsafe { (*vmcb).state.rsp };
    let nt = DELAY_NT_BASE.load(Ordering::Relaxed);
    let caller = crate::introspect::mem::read_u64(cr3, rsp).unwrap_or(0);
    let n = DELAY_LOG.fetch_add(1, Ordering::Relaxed);
    if n < 80 || n % 200 == 0 {
        // KeDelayExecutionThread(WaitMode=RCX, Alertable=RDX, Interval=R8 ptr).
        // Interval is signed 100 ns units; negative = relative delay.
        let interval = crate::introspect::mem::read_u64(cr3, gprs.r8).unwrap_or(0) as i64;
        let ms = (if interval < 0 { -interval } else { interval }) / 10_000;
        crate::sprintln!(
            "[delay] #{} {}ms (raw {:#X}) caller=base+0x{:X} (0x{:X})",
            n, ms, interval, caller.wrapping_sub(nt), caller
        );
    }
}

// Page disarmed for an in-flight single-step, to re-arm on the next #DB.
// 0 = no step pending. Single vCPU → at most one pending at a time.
static PENDING_REARM: AtomicU64 = AtomicU64::new(0);

// Active NPT root, published once at bring-up so the NPF dispatch path can
// arm/disarm pages without threading the root through every caller.
static NPT_PML4: AtomicU64 = AtomicU64::new(0);
static NPT_PDPT: AtomicU64 = AtomicU64::new(0);
static NPT_COV: AtomicU64 = AtomicU64::new(0);

/// Publish the active NPT root (call once after `build_identity_512gib`).
pub fn set_npt(root: &NptRoot) {
    NPT_PML4.store(root.pml4_phys, Ordering::Release);
    NPT_COV.store(root.coverage_bytes, Ordering::Release);
    // pdpt stored last: a non-zero pdpt is the "ready" flag for active_npt().
    NPT_PDPT.store(root.pdpt_phys, Ordering::Release);
}

fn active_npt() -> Option<NptRoot> {
    let pdpt = NPT_PDPT.load(Ordering::Acquire);
    if pdpt == 0 {
        return None;
    }
    Some(NptRoot {
        pml4_phys: NPT_PML4.load(Ordering::Acquire),
        pdpt_phys: pdpt,
        coverage_bytes: NPT_COV.load(Ordering::Acquire),
    })
}

/// Arm an execute-trap hook on the 4-KiB page containing guest-physical
/// `gpa`. Idempotent; returns false if the table is full or arming fails.
pub fn register_exec(npt: &NptRoot, gpa: u64) -> bool {
    let page = gpa & PAGE_MASK;
    for slot in HOOK_PAGE.iter() {
        if slot.load(Ordering::Relaxed) == page {
            return true; // already hooked
        }
    }
    for (i, slot) in HOOK_PAGE.iter().enumerate() {
        if slot
            .compare_exchange(0, page, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            if npt::arm_exec_trap(npt, page).is_err() {
                slot.store(0, Ordering::Release);
                return false;
            }
            HOOK_HITS[i].store(0, Ordering::Relaxed);
            return true;
        }
    }
    false
}

/// Arm an exec-hook on the page containing `gpa` using the published NPT
/// root. Convenience over `register_exec` for callers that don't hold a root.
pub fn arm_page(gpa: u64) -> bool {
    match active_npt() {
        Some(root) => register_exec(&root, gpa),
        None => false,
    }
}

/// True when an NPF `exit_info_1` indicates an instruction-fetch fault
/// (AMD APM Vol 2 §15.25.6, bit 4).
#[inline]
pub fn is_exec_fault(info1: u64) -> bool {
    info1 & (1 << 4) != 0
}

/// NPF dispatch entry for the handler. On an instruction-fetch fault on an
/// armed page: log the hit, then disarm + arm a single-step so the trapped
/// instruction runs and `on_single_step` re-arms afterward. Returns true
/// (handled → resume) only for a hooked exec fault; false otherwise so the
/// caller falls through to MMIO routing (no-op when no hooks are armed).
///
/// # Safety
/// `vmcb` must be the live VMCB for the faulting guest.
pub unsafe fn dispatch(vmcb: *mut Vmcb, gpa: u64, info1: u64, rip: u64, gprs: &GuestGprs) -> bool {
    if !is_exec_fault(info1) {
        return false;
    }
    let root = match active_npt() {
        Some(r) => r,
        None => return false,
    };
    let page = gpa & PAGE_MASK;
    for (i, slot) in HOOK_PAGE.iter().enumerate() {
        if slot.load(Ordering::Relaxed) == page {
            let n = HOOK_HITS[i].fetch_add(1, Ordering::Relaxed);
            let entry = HOOK_ENTRY[i].load(Ordering::Relaxed);
            if entry != 0 {
                // Probe page: capture only at the exact function entry (page-
                // mates fault too but aren't the probed function).
                if rip == entry {
                    unsafe { probe_capture(vmcb, gprs, HOOK_KIND[i].load(Ordering::Relaxed)); }
                }
            } else {
                let mut code = [0u8; 16];
                let got = crate::introspect::read_phys(gpa, &mut code);
                crate::sprintln!("[hook] exec page=0x{:X} gpa=0x{:X} rip=0x{:X} #{}", page, gpa, rip, n);
                if got {
                    crate::sprintln!("[hook]   code={:02X?}", code);
                }
            }
            // Single-step setup: disarm (instruction runs), set TF, and
            // intercept #DB transiently — only until on_single_step re-arms.
            let _ = npt::disarm_exec_trap(&root, gpa);
            unsafe {
                (*vmcb).state.rflags |= RFLAGS_TF;
                (*vmcb).control.intercept_exceptions |= EXCP_DB;
            }
            PENDING_REARM.store(page, Ordering::Release);
            return true;
        }
    }
    false
}

/// #DB dispatch entry. If a single-step we set up just completed, re-arm the
/// page, drop TF + the transient #DB intercept, and resume. Returns true if
/// the #DB was ours; false for a guest-originated #DB (the normal exception
/// path handles that).
///
/// # Safety
/// `vmcb` must be the live VMCB for the faulting guest.
pub unsafe fn on_single_step(vmcb: *mut Vmcb) -> bool {
    let page = PENDING_REARM.load(Ordering::Acquire);
    if page == 0 {
        return false;
    }
    unsafe {
        (*vmcb).state.rflags &= !RFLAGS_TF;
        (*vmcb).control.intercept_exceptions &= !EXCP_DB;
    }
    if let Some(root) = active_npt() {
        let _ = npt::arm_exec_trap(&root, page);
    }
    PENDING_REARM.store(0, Ordering::Release);
    true
}
