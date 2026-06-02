//! Platform abstraction — where veneer actually executes.
//!
//! The hypervisor core (svm, vmx, intercept, memory) is identical across
//! the three targets. Only the launcher differs: how it enters ring 0,
//! where it gets contiguous physical memory, and how it hands the
//! eventual guest's RIP+CR3 to VMRUN.
//!
//! v0.0.x only wires `usermode` — enough to compile the whole tree and
//! run the unit tests. UEFI and kernel-driver targets are *documented*
//! here so the future implementer has a contract.

pub mod usermode;
// Future: pub mod uefi;
// Future: pub mod kernel_driver;

use crate::cpu::HostCaps;
use crate::profile::Profile;

/// Backend the launcher would use, given a [`HostCaps`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Svm,
    Vmx,
    None,
}

/// What the launcher promises to do for the core. Today only `usermode`
/// implements it; UEFI / kernel-driver will when ready.
pub trait Platform {
    /// Allocate a 4 KiB, page-aligned, physically-contiguous region and
    /// return its (virtual, physical) address pair. The page is
    /// zero-initialised.
    fn alloc_page(&mut self) -> anyhow::Result<(usize, u64)>;

    /// Enter VMRUN / VMLAUNCH on the current CPU with the prepared VMCB
    /// / VMCS. Returns when the loop in `svm::vmrun::dispatch_vmexit`
    /// asks for `Action::FatalGuest` or `Action::Reboot`.
    fn run_guest(&mut self, backend: Backend, profile: &Profile) -> anyhow::Result<()>;
}

/// Pick a backend from the host capabilities. Caller decides what to do
/// if `Backend::None` (currently: refuse to launch).
pub fn pick_backend(caps: &HostCaps) -> Backend {
    if !caps.viable() { return Backend::None; }
    match caps.vendor {
        crate::cpu::Vendor::AuthenticAmd => Backend::Svm,
        crate::cpu::Vendor::GenuineIntel => Backend::Vmx,
        crate::cpu::Vendor::Other        => Backend::None,
    }
}
