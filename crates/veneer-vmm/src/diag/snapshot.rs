//! One-shot guest-state snapshot for diagnosing a stuck guest (spin / deadlock
//! / NPF storm).
//!
//! Pure VMI read-out — guest registers (VMCB + software-saved GPRs) plus guest
//! memory read through `introspect`. The image base is recovered generically by
//! walking down for the PE header, so RVAs are correct wherever the guest is
//! stuck (not just at one hard-coded function). The point is to replace "patch
//! a guess, rebuild, boot" with one observation of ground truth.
//!
//! Triggered by the VMEXIT dispatcher's spin detector when the guest hammers
//! one RIP far past the convergence-floor threshold — a real wedge.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// One-shot guard for the x2APIC interrupt-remap structure capture.
static IRQ_CAP_DONE: AtomicBool = AtomicBool::new(false);

use crate::hypervisor::svm::gprs::GuestGprs;
use crate::hypervisor::svm::vmcb::Vmcb;
use crate::introspect::mem;

// Kernel-mode canonical code range the guest's nt/HAL live in (0xFFFFF80X...).
const KERN_LO: u64 = 0xFFFF_F800_0000_0000;
const KERN_HI: u64 = 0xFFFF_F810_0000_0000;
const VMEXIT_NPF: u64 = 0x400;

#[inline]
fn is_kern_code(v: u64) -> bool {
    (KERN_LO..KERN_HI).contains(&v)
}

/// Base of the PE image containing `va`: walk down 2 MiB-aligned pages for an
/// 'MZ' DOS header whose `e_lfanew` points at a 'PE\0\0' signature. OS-agnostic
/// (PE format). `max_2mb` bounds the search.
fn image_base(cr3: u64, va: u64, max_2mb: u64) -> Option<u64> {
    let mut base = va & !0x1F_FFFF;
    let mut steps = 0u64;
    loop {
        if let Some(w) = mem::read_u64(cr3, base) {
            if (w & 0xFFFF) == 0x5A4D {
                if let Some(e_lfanew) = mem::read_struct::<u32>(cr3, base + 0x3C) {
                    if let Some(sig) = mem::read_struct::<u32>(cr3, base + e_lfanew as u64) {
                        if sig == 0x0000_4550 {
                            return Some(base);
                        }
                    }
                }
            }
        }
        steps += 1;
        if steps > max_2mb || base < 0x20_0000 {
            return None;
        }
        base -= 0x20_0000;
    }
}

/// Cached ntoskrnl image base (derived once via the PE-header walk) for the
/// cheap idle-routine exclusion in `sample_if_worker`.
static CACHED_NT_BASE: AtomicU64 = AtomicU64::new(0);

/// The derived ntoskrnl image base (0 until the first worker sample runs).
pub fn nt_base() -> u64 { CACHED_NT_BASE.load(Ordering::Relaxed) }

/// ntoskrnl idle / zero-page-thread RVA ranges (tiny11 26100.8036) that fill the
/// CPU whenever the boot is otherwise idle. Excluded from worker sampling — they
/// just show "idle"; we want the rare AWAKE worker threads (what they wait on).
fn is_idle_rva(rva: u64) -> bool {
    matches!(rva,
        0x6B3390..=0x6B33E0 |   // KeZeroPages
        0x6A5A80..=0x6A5AD0 |   // HalProcessorIdle
        0x20A480..=0x20AC60 |   // MiBackgroundZeroLocalPages
        0x20BD20..=0x20BF40 |   // MiTryZeroMemory
        0x4EA4C0..=0x4EA520 |   // PpmIdleDefaultExecute
        0x4C8600..=0x4C8700)    // PpmWakeClockOwnerIfNeeded
}

/// Sample the AWAKE worker context, skipping the idle/zero-page fillers (which
/// otherwise dominate — the boot is ~80% idle). Returns true if it dumped, so
/// the caller can rate-limit + cap. The host preemption tick only fires while
/// the guest is running in VMRUN (idle HLT spins on the host with no exit), so
/// this is already biased to awake contexts; the idle-RVA filter removes the
/// low-priority zero-page thread that fills the gaps.
pub unsafe fn sample_if_worker(vmcb: *mut Vmcb, gprs: &GuestGprs) -> bool {
    let rip = unsafe { (*vmcb).state.rip };
    let cr3 = unsafe { (*vmcb).state.cr3 };
    if !is_kern_code(rip) {
        return false; // user-mode or firmware — not a kernel worker init path
    }
    let mut base = CACHED_NT_BASE.load(Ordering::Relaxed);
    if base == 0 {
        match image_base(cr3, rip, 256) {
            Some(b) => { base = b; CACHED_NT_BASE.store(b, Ordering::Relaxed); }
            None => return false,
        }
    }
    // Skip only when the RIP is inside an ntoskrnl idle routine; a RIP outside
    // ntoskrnl (a driver, above/below base) is a worker and gets dumped.
    if rip >= base && is_idle_rva(rip - base) {
        return false;
    }
    unsafe { dump(vmcb, gprs, "awake-worker") };
    true
}

/// Dump current guest state. `reason` labels why we fired.
///
/// Safety: `vmcb` must be the live VMCB and `gprs` the matching software-saved
/// GPRs for this exit.
pub unsafe fn dump(vmcb: *mut Vmcb, gprs: &GuestGprs, reason: &str) {
    let s = unsafe { &(*vmcb).state };
    let c = unsafe { &(*vmcb).control };
    // Copy out of the #[repr(C, packed)] state before formatting (a reference
    // to a packed field is UB).
    let rip = s.rip;
    let rsp = s.rsp;
    let cr3 = s.cr3;
    let rflags = s.rflags;
    let cpl = s.cpl;
    let rax = s.rax;
    let vintr = c.vintr;
    let exit_code = c.exit_code;
    let info1 = c.exit_info_1;
    let info2 = c.exit_info_2;
    let vtpr = (vintr & 0xFF) as u32;
    let base = image_base(cr3, rip, 256); // up to 512 MiB below rip

    crate::sprintln!("[diag] ===== guest snapshot: {} =====", reason);
    match base {
        Some(b) => crate::sprintln!("[diag] rip=0x{:X}  image_base=0x{:X}  rip=base+0x{:X}", rip, b, rip - b),
        None => crate::sprintln!("[diag] rip=0x{:X}  image_base=<not found>", rip),
    }
    crate::sprintln!(
        "[diag] exit=0x{:X} info1=0x{:X} info2=0x{:X}{}",
        exit_code, info1, info2,
        if exit_code == VMEXIT_NPF { "  (NPF: info2=faulting GPA, info1=flags)" } else { "" }
    );
    crate::sprintln!(
        "[diag] rsp=0x{:X} cr3=0x{:X} rflags=0x{:X} (IF={}) cpl={} vtpr=0x{:02X}(irql/cr8={})",
        rsp, cr3, rflags, (rflags >> 9) & 1, cpl, vtpr, vtpr & 0xF
    );
    crate::sprintln!(
        "[diag] rdi=0x{:X} rsi=0x{:X} rbp=0x{:X} rbx=0x{:X} rcx=0x{:X} rdx=0x{:X} rax=0x{:X}",
        gprs.rdi, gprs.rsi, gprs.rbp, gprs.rbx, gprs.rcx, gprs.rdx, rax
    );

    // Instruction bytes at rip — identifies the faulting/spinning instruction.
    let mut ib = [0u8; 16];
    if mem::read_virt(cr3, rip, &mut ib) {
        crate::sprintln!("[diag] code@rip = {:02X?}", ib);
    }

    // KiBugCheckData[5] (code + 4 params). Nonzero code == the guest took a
    // bugcheck (BSOD) and is now halting; decoding it here turns a silent wedge
    // into a named stop. RVA is for ntoskrnl 26100.8036 (same build the idle-RVA
    // table above is keyed to). KiBugCheckData is ULONG_PTR[5].
    const KIBUGCHECKDATA_RVA: u64 = 0x00F2_2740;
    if let Some(b) = base {
        if let Some(code) = mem::read_u64(cr3, b + KIBUGCHECKDATA_RVA) {
            if code != 0 {
                let p1 = mem::read_u64(cr3, b + KIBUGCHECKDATA_RVA + 0x08).unwrap_or(0);
                let p2 = mem::read_u64(cr3, b + KIBUGCHECKDATA_RVA + 0x10).unwrap_or(0);
                let p3 = mem::read_u64(cr3, b + KIBUGCHECKDATA_RVA + 0x18).unwrap_or(0);
                let p4 = mem::read_u64(cr3, b + KIBUGCHECKDATA_RVA + 0x20).unwrap_or(0);
                crate::sprintln!(
                    "[diag] BUGCHECK code=0x{:X} p1=0x{:X} p2=0x{:X} p3=0x{:X} p4=0x{:X}",
                    code, p1, p2, p3, p4
                );
                // For HAL interrupt/timer bugchecks the exact failing call site is
                // recorded in HalpInterruptLastProblemLine (the source line passed to
                // HalpInterruptSetProblemEx). Decoding it pinpoints which routing /
                // remap step returned the failure — e.g. 0xdf5 = FindBestRouting
                // no-route, 0xab6 = IrtAllocateIndex, 0xac6 = DestinationToTarget,
                // 0xbae = unhandled interrupt type. RVA for ntoskrnl 26100.8036.
                const HALP_INT_LAST_PROBLEM_RVA: u64 = 0x00F8_F8E0;
                const HALP_INT_LAST_PROBLEM_LINE_RVA: u64 = 0x00F8_F920;
                let prob = mem::read_u64(cr3, b + HALP_INT_LAST_PROBLEM_RVA).unwrap_or(0);
                let line = mem::read_u64(cr3, b + HALP_INT_LAST_PROBLEM_LINE_RVA).unwrap_or(0) & 0xFFFF_FFFF;
                crate::sprintln!(
                    "[diag] HAL int problem: line=0x{:X} problem=0x{:X}",
                    line, prob
                );
                // HAL *timer* problems use a separate recorder (HalpTimerSetProblemEx):
                // a global code at RVA 0xE0F1F0, and per-timer-object fields at
                // obj+0xFC (code) / obj+0x110 (source line). For a 0x5C/0x110
                // (HAL Timer) bugcheck p2 is that timer object, so decoding its line
                // pinpoints the failing HalpTimer* site without a guest breakpoint.
                const HALP_TIMER_LAST_PROBLEM_RVA: u64 = 0x00E0_F1F0;
                let tg = mem::read_u64(cr3, b + HALP_TIMER_LAST_PROBLEM_RVA).unwrap_or(0) & 0xFFFF_FFFF;
                let tcode = mem::read_u64(cr3, p2.wrapping_add(0xFC)).unwrap_or(0) & 0xFFFF_FFFF;
                let tline = mem::read_u64(cr3, p2.wrapping_add(0x110)).unwrap_or(0) & 0xFFFF_FFFF;
                crate::sprintln!(
                    "[diag] HAL timer problem: global=0x{:X} obj.code=0x{:X} obj.line=0x{:X}",
                    tg, tcode, tline
                );
                // x2APIC interrupt-remap capture (ONCE): the clock GSI 20 RTE is in
                // remappable format, so its real vector lives in a guest IRTE reached
                // via the IOMMU Device Table. Dump the raw RTE + device-table base +
                // any DTE with an Interrupt Table pointer + its IRTEs, so the remap
                // decode can be built to the actual AMD-Vi format.
                if !IRQ_CAP_DONE.swap(true, Ordering::Relaxed) {
                    let rte20 = crate::hardware::devices::irq::ioapic::raw_rte(20);
                    let dtb = crate::hardware::devices::iommu::dev_tab_base();
                    crate::sprintln!("[irq-cap] GSI20 RTE=0x{:016X} dev_tab_base=0x{:X}", rte20, dtb);
                    let dt = dtb & 0x000F_FFFF_FFFF_F000;
                    let mut shown = 0u32;
                    if dt != 0 {
                        for devid in 0u64..0x100 {
                            if shown >= 6 { break; }
                            let mut dte = [0u8; 32];
                            if !mem::read_phys(dt + devid * 32, &mut dte) { break; }
                            let q0 = u64::from_le_bytes(dte[0..8].try_into().unwrap());
                            let q2 = u64::from_le_bytes(dte[16..24].try_into().unwrap());
                            if q2 == 0 { continue; }
                            shown += 1;
                            crate::sprintln!("[irq-cap] DTE[{:#x}] q0=0x{:016X} q2=0x{:016X}", devid, q0, q2);
                            let irt = q2 & 0x000F_FFFF_FFFF_FFC0;
                            if irt != 0 {
                                for idx in 0u64..8 {
                                    let mut irte = [0u8; 16];
                                    if !mem::read_phys(irt + idx * 16, &mut irte) { break; }
                                    let lo = u64::from_le_bytes(irte[0..8].try_into().unwrap());
                                    let hi = u64::from_le_bytes(irte[8..16].try_into().unwrap());
                                    if lo != 0 || hi != 0 {
                                        crate::sprintln!("[irq-cap]   IRTE[{}] lo=0x{:016X} hi=0x{:016X}", idx, lo, hi);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Stack walk: the return-address chain (= call stack) for offline symbols.
    crate::sprintln!("[diag] stack (kernel return addrs):");
    let b = base.unwrap_or(0);
    let mut off = 0u64;
    let mut shown = 0u32;
    while off < 96 * 8 && shown < 32 {
        if let Some(v) = mem::read_u64(cr3, rsp.wrapping_add(off)) {
            if is_kern_code(v) {
                if b != 0 && v >= b {
                    crate::sprintln!("[diag]   [rsp+0x{:03X}] 0x{:X}  base+0x{:X}", off, v, v - b);
                } else {
                    crate::sprintln!("[diag]   [rsp+0x{:03X}] 0x{:X}", off, v);
                }
                shown += 1;
            }
        }
        off += 8;
    }
    crate::sprintln!("[diag] ===== end snapshot =====");
}
