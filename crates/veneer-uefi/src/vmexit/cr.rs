//! Control-register intercept handler.
//!
//! Reads return the host CRn (with future hooks for spoofing). Writes are
//! silently dropped — the guest cannot poke CR0/CR3/CR4 through us.
//!
//! exit_info_1 layout (AMD APM Vol 2 §15.10): bits 0..3 hold the
//! source/destination GPR index. AMD does NOT populate exit_info_2 with
//! next_rip for CR intercepts; we step `crate::vmexit::lengths::CR_ACCESS`
//! bytes manually.

use crate::arch;
use crate::svm::gprs::GuestGprs;
use crate::svm::vmcb::Vmcb;

use super::{advance_rip, lengths, Action};

// CR0 bit positions (AMD APM Vol 2 §3.1.1).
const CR0_PE: u64 = 1 << 0;
const CR0_PG: u64 = 1 << 31;
const CR0_CD: u64 = 1 << 30;
const CR0_NW: u64 = 1 << 29;

// event_inj layout (AMD APM Vol 2 §15.20): vector | (type<<8) | (errvalid<<11)
// | VALID<<31 | (errcode<<32). Type 3 = exception, vector 13 = #GP.
const EVENT_VALID: u64 = 1 << 31;
const EVENT_TYPE_EXCEPTION: u64 = 3 << 8;
const EVENT_ERR_VALID: u64 = 1 << 11;
const VECTOR_GP: u64 = 13;

/// Inject a #GP(error_code) into the guest on the next VMRUN instead of
/// committing an architecturally-invalid CRn write. RIP is left on the
/// faulting instruction (faults push the faulting RIP), so we do NOT
/// advance it. Only stages if no event is already pending.
fn inject_gp(c: &mut crate::svm::vmcb::VmcbControl, error_code: u32) {
    if c.event_inj & EVENT_VALID != 0 {
        return;
    }
    c.event_inj = VECTOR_GP
        | EVENT_TYPE_EXCEPTION
        | EVENT_ERR_VALID
        | EVENT_VALID
        | ((error_code as u64) << 32);
}

pub unsafe fn handle_read(vmcb: *mut Vmcb, gprs: &mut GuestGprs, cr_index: u8) -> Action {
    let next_rip = unsafe { (*vmcb).control.next_rip };
    let gpr_index = unsafe { ((*vmcb).control.exit_info_1 & 0xF) as u8 };
    let val = match cr_index {
        0 => arch::read_cr0(),
        3 => arch::read_cr3(),
        4 => arch::read_cr4(),
        _ => 0,
    };
    let s = unsafe { &mut (*vmcb).state };
    gprs.write_indexed(s, gpr_index, val);
    advance_rip(s, next_rip, lengths::CR_ACCESS);
    Action::Resume
}

pub unsafe fn handle_write(vmcb: *mut Vmcb, gprs: &mut GuestGprs, cr_index: u8) -> Action {
    let next_rip = unsafe { (*vmcb).control.next_rip };
    let gpr_index = unsafe { ((*vmcb).control.exit_info_1 & 0xF) as u8 };
    let new_val = {
        let s = unsafe { &(*vmcb).state };
        gprs.read_indexed(s, gpr_index)
    };

    // Validate CR0 *before* taking the long-lived &mut state borrow, so the
    // #GP injection path can touch VMCB.control without aliasing. The two
    // illegal CR0 combinations AMD's VMRUN consistency check enumerates
    // would otherwise make the next VMRUN die with #VMEXIT(INVALID); reflect
    // a #GP(0) the way real hardware does on such a MOV-to-CR0.
    if cr_index == 0 {
        let nw_cd_bad = (new_val & CR0_NW != 0) && (new_val & CR0_CD == 0);
        let pg_pe_bad = (new_val & CR0_PG != 0) && (new_val & CR0_PE == 0);
        if nw_cd_bad || pg_pe_bad {
            let c = unsafe { &mut (*vmcb).control };
            inject_gp(c, 0);
            // Do not advance RIP: a fault re-executes the instruction.
            return Action::Resume;
        }
    }

    let s = unsafe { &mut (*vmcb).state };
    // Apply to the guest CRn. For a nested guest OS this matters most
    // on CR3 swaps -- Linux's decompressor builds its own page table
    // and switches to it; if we drop the write the guest keeps faulting
    // because the old CR3 has no kernel mappings. CR0/CR4 writes also
    // need to land so paging/PAE bits the kernel sets stick.
    match cr_index {
        0 => s.cr0 = new_val,
        3 => {
            use core::sync::atomic::{AtomicU32, Ordering};
            static CR3_W: AtomicU32 = AtomicU32::new(0);
            let n = CR3_W.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                let efer = s.efer;
                let rip = s.rip;
                crate::sprintln!(
                    "[cr3] write #{} cr3=0x{:X} EFER=0x{:X}(NXE={}) rip=0x{:X}",
                    n, new_val, efer, (efer >> 11) & 1, rip
                );
                // Walk the new table for the CpuDxe fault VA to see its
                // mapping + NX once it's the protected (non-0x800000) table.
                if new_val != 0x800000 {
                    let base = crate::vmexit::io::guest_ram_base();
                    if base != 0 {
                        unsafe { crate::dump_pagewalk(base, new_val, 0x3EF1102E); }
                        crate::dump_code_window(base, 0x3EF1102E, "cpudxe-fault");
                    }
                }
            }
            s.cr3 = new_val;
        }
        4 => s.cr4 = new_val,
        _ => {}
    }
    advance_rip(s, next_rip, lengths::CR_ACCESS);
    Action::Resume
}
