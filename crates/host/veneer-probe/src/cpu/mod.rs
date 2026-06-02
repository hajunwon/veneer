//! Host CPU detection. Used to decide between SVM (AMD) and VMX (Intel)
//! backends, and to verify the host actually supports nested paging,
//! sufficient ASID space, etc., before we promise we can run.

pub mod vendor;
pub mod features;
pub mod msr;

pub use vendor::{Vendor, host_vendor};
pub use features::{HostCaps, probe};
