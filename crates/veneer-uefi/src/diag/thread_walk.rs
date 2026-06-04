//! Read-only VMI walk of the guest thread list to find WHO is timed-waiting
//! during the ~80%-idle boot (the dominant boot-time cost). Unlike an exec-hook
//! (which triple-faulted the live guest), this only *reads* guest memory via
//! `introspect`, so it cannot fault the guest.
//!
//! Walk: PsActiveProcessHead → EPROCESS list → each ThreadListHead → ETHREAD
//! list. For every thread in the Waiting state, log its WaitReason + the thread
//! StartAddress (which driver/ntoskrnl routine the thread runs — symbolicate
//! offline to name the subsystem doing the sleeping).
//!
//! Offsets are tiny11 26100.8036 (from the PDB); other builds need re-extraction.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::hypervisor::svm::vmcb::Vmcb;
use crate::introspect::mem;

// ── 26100.8036 layout ──
const PS_ACTIVE_HEAD_RVA: u64 = 0xF0_5980;
const EP_ACTIVE_LINKS: u64 = 0x1D8; // EPROCESS.ActiveProcessLinks (LIST_ENTRY)
const EP_IMAGE_NAME: u64 = 0x338;   // EPROCESS.ImageFileName [15]
const EP_THREAD_LIST: u64 = 0x370;  // EPROCESS.ThreadListHead (LIST_ENTRY)
const ET_START_ADDR: u64 = 0x4E0;   // ETHREAD.StartAddress
const ET_LIST_ENTRY: u64 = 0x578;   // ETHREAD.ThreadListEntry (LIST_ENTRY)
const KT_STATE: u64 = 0x184;        // KTHREAD.State (UChar)
const KT_WAIT_REASON: u64 = 0x283;  // KTHREAD.WaitReason (UChar)
const STATE_WAITING: u8 = 5;

static WALK_COUNT: AtomicU32 = AtomicU32::new(0);
const MAX_WALKS: u32 = 8;

#[inline]
fn read_u8(cr3: u64, gva: u64) -> Option<u8> {
    mem::read_struct::<u8>(cr3, gva)
}

/// One read-only pass over all guest threads; logs the Waiting ones. `nt_base`
/// is the ntoskrnl image base (so the StartAddress is reported base-relative).
pub unsafe fn walk(vmcb: *mut Vmcb, nt_base: u64) {
    let w = WALK_COUNT.fetch_add(1, Ordering::Relaxed);
    if w >= MAX_WALKS {
        return;
    }
    let cr3 = unsafe { (*vmcb).state.cr3 };
    let head = nt_base.wrapping_add(PS_ACTIVE_HEAD_RVA);
    let mut link = match mem::read_u64(cr3, head) {
        Some(l) => l,
        None => { crate::sprintln!("[twalk] #{} PsActiveProcessHead read failed", w); return; }
    };
    crate::sprintln!("[twalk] #{} ===== waiting-thread census =====", w);
    let mut procs = 0u32;
    let mut waiting = 0u32;
    while link != head && link != 0 && procs < 256 {
        let eproc = link.wrapping_sub(EP_ACTIVE_LINKS);
        // Process image name (15 ASCII bytes).
        let mut nm = [0u8; 16];
        let _ = mem::read_virt(cr3, eproc.wrapping_add(EP_IMAGE_NAME), &mut nm[..15]);
        let nlen = nm.iter().position(|&b| b == 0).unwrap_or(15);
        let name = core::str::from_utf8(&nm[..nlen]).unwrap_or("?");
        // Walk this process's threads.
        let tl_head = eproc.wrapping_add(EP_THREAD_LIST);
        let mut tlink = mem::read_u64(cr3, tl_head).unwrap_or(0);
        let mut threads = 0u32;
        while tlink != tl_head && tlink != 0 && threads < 4096 {
            let ethread = tlink.wrapping_sub(ET_LIST_ENTRY);
            if read_u8(cr3, ethread.wrapping_add(KT_STATE)) == Some(STATE_WAITING) {
                let reason = read_u8(cr3, ethread.wrapping_add(KT_WAIT_REASON)).unwrap_or(0xFF);
                let start = mem::read_u64(cr3, ethread.wrapping_add(ET_START_ADDR)).unwrap_or(0);
                waiting += 1;
                if waiting <= 80 {
                    crate::sprintln!(
                        "[twalk]   {:<15} wait_reason={} start=base+0x{:X} (0x{:X})",
                        name, reason, start.wrapping_sub(nt_base), start
                    );
                }
            }
            tlink = mem::read_u64(cr3, ethread.wrapping_add(ET_LIST_ENTRY)).unwrap_or(0);
            threads += 1;
        }
        link = mem::read_u64(cr3, eproc.wrapping_add(EP_ACTIVE_LINKS)).unwrap_or(0);
        procs += 1;
    }
    crate::sprintln!("[twalk] #{} procs={} waiting_threads={}", w, procs, waiting);
}
