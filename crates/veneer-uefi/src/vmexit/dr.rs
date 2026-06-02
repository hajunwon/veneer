//! Debug-register intercept handler.
//!
//! Reads return 0 (anti-debug: clean state, no hardware breakpoints).
//! Writes are silently dropped.
//!
//! exit_info_1 layout (AMD APM Vol 2 §15.10): bits 0..3 hold the
//! source/destination GPR index. AMD does NOT populate exit_info_2 with
//! next_rip; we step `crate::vmexit::lengths::DR_ACCESS` bytes manually.

use crate::svm::gprs::GuestGprs;
use crate::svm::vmcb::Vmcb;

use super::{advance_rip, lengths, Action};

pub unsafe fn handle_read(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    let next_rip = unsafe { (*vmcb).control.next_rip };
    let gpr_index = unsafe { ((*vmcb).control.exit_info_1 & 0xF) as u8 };
    let s = unsafe { &mut (*vmcb).state };
    gprs.write_indexed(s, gpr_index, 0);
    advance_rip(s, next_rip, lengths::DR_ACCESS);
    Action::Resume
}

pub unsafe fn handle_write(vmcb: *mut Vmcb, _gprs: &mut GuestGprs) -> Action {
    let next_rip = unsafe { (*vmcb).control.next_rip };
    let s = unsafe { &mut (*vmcb).state };
    advance_rip(s, next_rip, lengths::DR_ACCESS);
    Action::Resume
}
