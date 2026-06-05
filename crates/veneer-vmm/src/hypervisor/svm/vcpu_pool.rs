//! Per-vCPU resource substrate.
//!
//! v0.5-batch: detect the number of vCPUs visible to veneer (via CPUID
//! 0x8000_0008) and allocate one VMCB per vCPU up to MAX_VCPUS. Actual
//! AP-on-AP SVM bring-up (INIT-SIPI-SIPI → BSP-synchronised VMRUN per
//! core) is v0.6 — we only set up the pool here so a future launcher can
//! iterate.
//!
//! BSP (boot-strap processor) uses entry 0. Entries 1..N hold VMCBs for
//! application processors but those processors are still parked.

use crate::infra::arch::cpuid;
use crate::hypervisor::svm::vmcb::{self, Vmcb};

pub const MAX_VCPUS: usize = 16;

pub struct VcpuPool {
    pub count: usize,
    pub vmcb: [Option<*mut Vmcb>; MAX_VCPUS],
}

#[derive(Debug)]
pub enum VcpuPoolError {
    AllocFailed,
}

/// Read host vCPU count from CPUID. AMD CPUID 0x8000_0008 ECX[7:0] = NC =
/// "number of cores - 1".
pub fn detect_count() -> usize {
    let r = cpuid(0x8000_0008);
    ((r.ecx & 0xFF) + 1) as usize
}

pub fn alloc_pool(count: usize) -> Result<VcpuPool, VcpuPoolError> {
    let mut pool = VcpuPool {
        count: count.min(MAX_VCPUS),
        vmcb: [None; MAX_VCPUS],
    };
    for i in 0..pool.count {
        let v = vmcb::alloc_vmcb().map_err(|_| VcpuPoolError::AllocFailed)?;
        pool.vmcb[i] = Some(v);
    }
    Ok(pool)
}
