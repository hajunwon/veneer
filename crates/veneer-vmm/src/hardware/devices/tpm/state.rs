//! Persistent TPM 2.0 state shared between command invocations.
//!
//! We model the minimum subset of TPM internal state required for a
//! plausible identity + PCR / NV / session conversation:
//!
//!   - **PCR banks** — 24 SHA-256 PCRs (the TPM 2.0 minimum). PCR_Read
//!     returns the current value; PCR_Extend hashes (current ‖ extend).
//!   - **NV indices** — a small bounded registry indexed by handle. Pre-
//!     populated with a synthetic EK certificate at 0x01C0_0002 so vgc
//!     reading the standard EK cert NV index sees a structurally valid
//!     X.509 blob.
//!   - **Boot clock** — monotonic 64-bit count of milliseconds since
//!     TPM2_Startup, used by TPM2_ReadClock and timed-policy paths.
//!
//! Multi-vCPU access is serialised by a single AtomicBool spinlock.
//! Real TPMs single-thread commands by hardware design — we mirror that.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::ek_cert;

/// SHA-256 PCR bank, 24 registers × 32 bytes. Lock acquired through
/// `lock()` below.
pub struct PcrBank {
    pub pcrs: [[u8; 32]; 24],
}

const PCR_INIT: [u8; 32] = [0u8; 32];

/// Per-PCR Locality reset values. Spec § 17.1: most PCRs reset to 0 at
/// platform power-on, but PCR 17..22 reset to all-FF (DRTM territory).
/// We use the standard initial state for all 24 since DRTM isn't
/// emulated.
const fn make_pcr_bank() -> PcrBank {
    PcrBank { pcrs: [PCR_INIT; 24] }
}

static mut PCR_BANK: PcrBank = make_pcr_bank();

/// One NV-defined index. Real TPMs allow ~1 KiB per index; we cap at
/// 2 KiB to fit the synthetic EK certificate plus headroom.
#[derive(Clone, Copy)]
pub struct NvIndex {
    pub handle: u32,
    pub attributes: u32,
    pub data_len: u16,
    pub data: [u8; 2048],
}

impl NvIndex {
    pub const fn empty() -> Self {
        Self { handle: 0, attributes: 0, data_len: 0, data: [0u8; 2048] }
    }
}

const NV_CAPACITY: usize = 16;

static mut NV_INDICES: [NvIndex; NV_CAPACITY] = [NvIndex::empty(); NV_CAPACITY];
static NV_USED: AtomicU64 = AtomicU64::new(0); // bitmap (cap 64, we use 16)

/// Boot-time-in-milliseconds counter. Real TPM2_ReadClock returns this
/// plus the resetCount + restartCount + safe flag.
pub static BOOT_CLOCK_MS: AtomicU64 = AtomicU64::new(0);
pub static TPM_RESET_COUNT: AtomicU64 = AtomicU64::new(0);
pub static TPM_RESTART_COUNT: AtomicU64 = AtomicU64::new(0);

/// True after TPM2_Startup succeeded; TPM2_Startup is required before
/// any other command per spec.
pub static TPM_STARTED: AtomicBool = AtomicBool::new(false);

// ───── Spinlock ────────────────────────────────────────────────────────

static LOCK: AtomicBool = AtomicBool::new(false);

pub struct Guard;
impl Drop for Guard { fn drop(&mut self) { LOCK.store(false, Ordering::Release); } }

pub fn lock() -> Guard {
    while LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    Guard
}

// ───── PCR access ──────────────────────────────────────────────────────

pub fn pcr_read(_g: &Guard, index: usize) -> Option<[u8; 32]> {
    if index >= 24 { return None; }
    Some(unsafe { PCR_BANK.pcrs[index] })
}

pub fn pcr_extend(_g: &Guard, index: usize, data: &[u8; 32]) -> bool {
    if index >= 24 { return false; }
    let cur = unsafe { PCR_BANK.pcrs[index] };
    let mut h = super::sha256::Sha256::new();
    h.update(&cur);
    h.update(data);
    let new = h.finalize();
    unsafe { PCR_BANK.pcrs[index] = new; }
    true
}

// ───── NV access ───────────────────────────────────────────────────────

pub fn nv_find(_g: &Guard, handle: u32) -> Option<usize> {
    let used = NV_USED.load(Ordering::Relaxed);
    for i in 0..NV_CAPACITY {
        if used & (1u64 << i) != 0 {
            let h = unsafe { NV_INDICES[i].handle };
            if h == handle { return Some(i); }
        }
    }
    None
}

pub fn nv_define(_g: &Guard, handle: u32, attributes: u32, data: &[u8]) -> Option<usize> {
    let mut used = NV_USED.load(Ordering::Relaxed);
    // Already defined?
    for i in 0..NV_CAPACITY {
        if used & (1u64 << i) != 0 && unsafe { NV_INDICES[i].handle } == handle {
            return Some(i);
        }
    }
    for i in 0..NV_CAPACITY {
        if used & (1u64 << i) == 0 {
            unsafe {
                NV_INDICES[i].handle = handle;
                NV_INDICES[i].attributes = attributes;
                let n = data.len().min(2048);
                NV_INDICES[i].data_len = n as u16;
                NV_INDICES[i].data[..n].copy_from_slice(&data[..n]);
            }
            used |= 1u64 << i;
            NV_USED.store(used, Ordering::Relaxed);
            return Some(i);
        }
    }
    None
}

pub fn nv_read(_g: &Guard, slot: usize, offset: u16, size: u16, out: &mut [u8]) -> usize {
    let entry = unsafe { &NV_INDICES[slot] };
    let total = entry.data_len as usize;
    let start = offset as usize;
    let end = (start + size as usize).min(total);
    if start >= total { return 0; }
    let len = end - start;
    if out.len() < len { return 0; }
    out[..len].copy_from_slice(&entry.data[start..end]);
    len
}

pub fn nv_get_attributes(_g: &Guard, slot: usize) -> (u32, u16) {
    let entry = unsafe { &NV_INDICES[slot] };
    (entry.attributes, entry.data_len)
}

// ───── Init ────────────────────────────────────────────────────────────

/// Populate the NV registry with the standard TCG-spec EK certificate
/// (NV index 0x01C00002, plus the EK template at 0x01C00004). Called
/// once at TPM bring-up time.
pub fn init() {
    let g = lock();

    // EK certificate at the standard NV index. attributes mark it as
    // platform-provisioned, read-only, no auth required.
    const TPMA_NV_PLATFORMCREATE: u32 = 0x4000_0000;
    const TPMA_NV_OWNERREAD:      u32 = 0x0002_0000;
    const TPMA_NV_AUTHREAD:       u32 = 0x0004_0000;
    const TPMA_NV_WRITTEN:        u32 = 0x2000_0000;
    let ek_attrs = TPMA_NV_PLATFORMCREATE
                 | TPMA_NV_OWNERREAD
                 | TPMA_NV_AUTHREAD
                 | TPMA_NV_WRITTEN;
    // Patch the EK cert serial with a per-machine value derived from the
    // SMBIOS UUID, so the EK isn't a fixed global fingerprint across veneer
    // instances (and never the old 0xC0FFEE watermark). Falls back to the
    // cert's static serial when no profile is active.
    let mut ek = [0u8; 1024];
    ek.copy_from_slice(ek_cert::EK_CERT_DER);
    if let Some(p) = crate::hardware::identity::active::PROFILE.get() {
        let uuid = unsafe { core::ptr::addr_of!(p.hardware.system.instance.uuid).read_unaligned() };
        let bytes = uuid.as_bytes();
        if !bytes.is_empty() {
            let h = super::sha256::hash(bytes);
            // serialNumber lives at offset 15..24 (INTEGER tag 0x02, len 0x09).
            // Force a positive, non-zero ASN.1 leading byte (high bit clear).
            ek[15] = (h[0] & 0x7F) | 0x40;
            ek[16..24].copy_from_slice(&h[1..9]);
        }
    }
    let _ = nv_define(&g, 0x01C0_0002, ek_attrs, &ek);

    // EK template (RSA 2048).
    let _ = nv_define(&g, 0x01C0_0004, ek_attrs, ek_cert::EK_TEMPLATE);
}
