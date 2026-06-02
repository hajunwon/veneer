//! VMMCALL intercept — guest's hypercall ABI.
//!
//! Guest executes `vmmcall` (0F 01 D9) to talk to veneer directly. We use
//! RAX as the call number, return value goes back into RAX, other args
//! follow Linux KVM-style (RBX/RCX/RDX...).
//!
//! For v0.5-batch we implement one call:
//!   EAX = 0: "hello" — return profile signature so the guest can confirm
//!                       it's actually talking to veneer (and not some
//!                       other hypervisor that traps vmmcall too).

use crate::svm::gprs::GuestGprs;
use crate::identity::profile;
use crate::svm::vmcb::Vmcb;

use super::{lengths, Action};

pub unsafe fn handle(vmcb: *mut Vmcb, _gprs: &mut GuestGprs) -> Action {
    let s = unsafe { &mut (*vmcb).state };
    let call_no = s.rax;

    match call_no {
        0 => {
            // Hello — return the signature.
            s.rax = profile::DEFAULT.vmmcall_signature;
        }
        _ => {
            // Unknown call number — return -1.
            s.rax = u64::MAX;
        }
    }

    s.rip = s.rip.wrapping_add(lengths::VMMCALL);
    Action::Resume
}
