//! The hypervisor core (VMM): the L1 that runs and traps the guest. SVM
//! mechanics (VMCB/VMRUN/NPT/SMP) plus the VMEXIT dispatcher and handlers.

pub mod svm;
pub mod vmexit;
