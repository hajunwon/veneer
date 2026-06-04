//! NVMe 1.4 controller register-window emulator (Samsung 980 PRO-class).
//!
//! BAR0 = 0xE200_0000 (16 KiB trapped). Layout per NVMe Base Spec
//! § 3.1.4:
//!
//!   0x000  CAP   (8B)   — Controller Capabilities (RO)
//!   0x008  VS    (4B)   — Version (RO) = NVMe 1.4 (0x0001_0400)
//!   0x00C  INTMS (4B)   — Interrupt Mask Set
//!   0x010  INTMC (4B)   — Interrupt Mask Clear
//!   0x014  CC    (4B)   — Controller Configuration (EN bit drives RDY)
//!   0x01C  CSTS  (4B)   — Controller Status (RDY mirrors CC.EN)
//!   0x024  AQA   (4B)   — Admin Queue Attributes
//!   0x028  ASQ   (8B)   — Admin SQ Base Address
//!   0x030  ACQ   (8B)   — Admin CQ Base Address
//!   0x1000 doorbells    — SQ0TDBL, CQ0HDBL, … (stride 4)
//!
//! State machine: setting CC.EN=1 → CSTS.RDY=1 after a (synthetic) ready
//! delay = 0. Doorbell writes are stashed but not acted on — we don't
//! parse admin queue entries, so Identify Controller never completes and
//! NDIS times out at CAP.TO * 500ms = 12s. Real I/O emulation would need
//! a full admin queue command processor — out of scope for the substrate.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::hardware::identity::active;

use super::backend;

pub const NVME_BAR0_DEFAULT: u64 = 0xE200_0000;
pub const NVME_BAR0_TRAP_SIZE: u64 = 0x0000_4000;

/// Live BAR0 base. PciBusDxe sizes the BAR (write 0xFFFFFFFF, read mask)
/// then assigns a base anywhere in its MMIO window; we must trap wherever
/// it lands, so the base is dynamic (updated from pci.rs on the config
/// write) rather than the hard-coded default.
static NVME_BAR0: AtomicU64 = AtomicU64::new(NVME_BAR0_DEFAULT);

pub fn bar0_base() -> u64 {
    NVME_BAR0.load(Ordering::Relaxed)
}

pub fn set_bar0_base(base: u64) {
    NVME_BAR0.store(base, Ordering::Relaxed);
}

/// Host-physical base of the guest's 1 GiB RAM block. NPT translates
/// guest_phys 0..1 GiB onto this block, so any guest-physical address the
/// driver hands us (queue base, PRP entry, CQ slot) reaches host memory
/// only through `g2h()`. Set once from `enter_linux_guest`.
static HOST_RAM_BASE: AtomicU64 = AtomicU64::new(0);

const PAGE: u64 = 4096;

pub fn set_host_ram_base(base: u64) {
    HOST_RAM_BASE.store(base, Ordering::Release);
}

/// Translate a guest-physical address to a host pointer, or null if the
/// GPA lies outside mapped guest RAM (so callers bail instead of
/// scribbling on host memory).
#[inline]
fn g2h(gpa: u64) -> *mut u8 {
    crate::guest::boot::guest_mem::to_host_ptr(gpa)
}

#[inline]
pub fn covers(gpa: u64) -> bool {
    let base = bar0_base();
    gpa >= base && gpa < base + NVME_BAR0_TRAP_SIZE
}

// CAP value:
//   MQES=0x3FFF (16K queue entries), CQR=1, TO=0x30 (24*500ms = 12s),
//   DSTRD=0 (4-byte doorbell stride), CSS=0x01 (NVM cmd set),
//   CRMS=01b (CRWMS — Controller Ready With Media Supported).
const CAP_LO: u32 = 0x0030_3FFF;      // bits 31:0
const CAP_HI: u32 = 0x0800_0030;      // bits 63:32 — CSS+CRMS

const VS_VALUE: u32 = 0x0001_0400;    // NVMe 1.4.0.0

// ───── Register state ────────────────────────────────────────────────

static INTMS: AtomicU32  = AtomicU32::new(0);
static CC:    AtomicU32  = AtomicU32::new(0);
static CSTS:  AtomicU32  = AtomicU32::new(0);
static NSSR:  AtomicU32  = AtomicU32::new(0);
static AQA:   AtomicU32  = AtomicU32::new(0);
static ASQ_LO: AtomicU32 = AtomicU32::new(0);
static ASQ_HI: AtomicU32 = AtomicU32::new(0);
static ACQ_LO: AtomicU32 = AtomicU32::new(0);
static ACQ_HI: AtomicU32 = AtomicU32::new(0);

/// Doorbell + tail-of-region scratch. NVMe spec puts the first
/// doorbell at 0x1000; we allocate 0x3000 bytes after that for SQ/CQ
/// doorbell pairs (3 KiB / 4 = 768 doorbells), well past anything a
/// driver bind sequence will touch.
const DOORBELL_BASE: u32 = 0x1000;
const DOORBELL_COUNT: usize = 768;
static mut DOORBELLS: [u32; DOORBELL_COUNT] = [0u32; DOORBELL_COUNT];

// ───── Admin Queue state ─────────────────────────────────────────────
//
// Tracks where in the guest's Admin SQ/CQ we last processed a command.
// On SQ-tail doorbell (offset 0x1000) write we walk from SQ_HEAD to the
// new tail, build a CQ entry per command, and advance both queues. CQ
// entries get a phase tag that flips on each wrap so the guest driver
// can spot fresh completions without an interrupt.

static SQ_HEAD: AtomicU32  = AtomicU32::new(0);
static CQ_TAIL: AtomicU32  = AtomicU32::new(0);
static CQ_PHASE: AtomicU32 = AtomicU32::new(1);

// ───── I/O queue state ───────────────────────────────────────────────
//
// Admin CREATE_CQ / CREATE_SQ register the guest's I/O queues here. The
// guest then rings an I/O SQ tail doorbell; we walk that SQ, serve each
// READ/WRITE from the backing disk into the command's PRP buffers, post a
// completion to the paired CQ, and raise that CQ's MSI-X vector. Linux's
// nvme driver uses one I/O queue pair per CPU and the guest is pinned to
// one CPU here, so a small fixed set covers it.

const MAX_QUEUES: usize = 8;

#[derive(Clone, Copy)]
struct IoSq {
    base: u64,   // guest-physical SQ base
    size: u32,   // entries (1-based)
    cqid: u16,   // paired completion queue
    head: u32,   // our consumer cursor
    active: bool,
}

#[derive(Clone, Copy)]
struct IoCq {
    base: u64,   // guest-physical CQ base
    size: u32,   // entries (1-based)
    iv: u16,     // MSI-X interrupt-vector index
    tail: u32,   // our producer cursor
    phase: u32,  // phase tag, flips each wrap
    active: bool,
}

const EMPTY_SQ: IoSq = IoSq { base: 0, size: 0, cqid: 0, head: 0, active: false };
const EMPTY_CQ: IoCq = IoCq { base: 0, size: 0, iv: 0, tail: 0, phase: 1, active: false };

static mut IO_SQ: [IoSq; MAX_QUEUES] = [EMPTY_SQ; MAX_QUEUES];
static mut IO_CQ: [IoCq; MAX_QUEUES] = [EMPTY_CQ; MAX_QUEUES];

// NVM command set opcodes (I/O queues).
const IO_OPC_FLUSH:        u8 = 0x00;
const IO_OPC_WRITE:        u8 = 0x01;
const IO_OPC_READ:         u8 = 0x02;
const IO_OPC_WRITE_ZEROES: u8 = 0x08;
const IO_OPC_DSM:          u8 = 0x09;

// ───── MSI-X (BAR0 + 0x2000) ─────────────────────────────────────────
//
// The NVMe driver polls nothing — it waits for a completion interrupt.
// We advertise MSI-X (64 vectors, table at BAR0+0x2000) in PCI config
// space; the guest programs the table through this trapped BAR0 window
// (config space itself is read-only in our model, but the table lives in
// MMIO so its writes stick). Each entry is 16 bytes: msg_addr_lo,
// msg_addr_hi, msg_data, vector_ctrl (bit 0 = mask).
const MSIX_TABLE_OFFSET: u32 = 0x2000;
const MSIX_TABLE_ENTRIES: usize = 64;
static mut MSIX_TABLE: [u32; MSIX_TABLE_ENTRIES * 4] = [0u32; MSIX_TABLE_ENTRIES * 4];
const MSIX_NONE: u32 = 0xFFFF_FFFF;
/// Vector raised by the most recent completion, awaiting injection by
/// intercept/inject.rs. MSIX_NONE = nothing pending.
static MSIX_PENDING: AtomicU32 = AtomicU32::new(MSIX_NONE);

#[inline]
fn msix_table_covers(off: u32) -> bool {
    off >= MSIX_TABLE_OFFSET
        && off < MSIX_TABLE_OFFSET + (MSIX_TABLE_ENTRIES as u32) * 16
}

/// MSI completion vector (IR-decoded, set from the PCI MSI capability). 0 when
/// MSI is disabled. When set it takes priority over the MSI-X table because
/// Windows here drives MSI, never programming the MSI-X table.
static MSI_VECTOR: AtomicU32 = AtomicU32::new(0);

/// pci.rs: the guest (re)programmed the MSI capability. `vector` is already
/// IR-decoded; a disabled or sub-16 vector parks delivery.
pub fn set_msi(vector: u32, enabled: bool) {
    MSI_VECTOR.store(if enabled && vector >= 16 { vector } else { 0 }, Ordering::Relaxed);
}

/// Raise the completion interrupt for CQ interrupt-vector `iv`. Prefers the MSI
/// vector (the path Windows uses); falls back to the MSI-X table entry's
/// message data if a guest drives MSI-X instead. The admin CQ uses IV 0.
fn raise_msix(iv: u16) {
    let msi = MSI_VECTOR.load(Ordering::Relaxed);
    if msi != 0 {
        let t = NVME_TRACE.fetch_add(1, Ordering::Relaxed);
        if t < NVME_TRACE_CAP {
            crate::sprintln!("[nvme] raise(MSI) iv={} vector=0x{:X}", iv, msi);
        }
        MSIX_PENDING.store(msi, Ordering::Relaxed);
        return;
    }
    let base = (iv as usize) * 4;
    if base + 3 >= MSIX_TABLE_ENTRIES * 4 {
        return;
    }
    let vector_ctrl = unsafe { MSIX_TABLE[base + 3] };
    if vector_ctrl & 1 != 0 {
        return; // entry masked by the guest
    }
    let vector = unsafe { MSIX_TABLE[base + 2] } & 0xFF;
    let t = NVME_TRACE.fetch_add(1, Ordering::Relaxed);
    if t < NVME_TRACE_CAP {
        crate::sprintln!("[nvme] raise_msix iv={} vector=0x{:X} ctrl=0x{:X}", iv, vector, vector_ctrl);
    }
    if vector >= 16 {
        MSIX_PENDING.store(vector, Ordering::Relaxed);
    }
}

static NVME_TRACE: AtomicU32 = AtomicU32::new(0);
const NVME_TRACE_CAP: u32 = 400;

// MSI-X table-write capture (diagnostic): record the entries the guest's
// driver programs so the IR remappable format is read from a boot, not guessed.
static MSIX_WR_TRACE: AtomicU32 = AtomicU32::new(0);
const MSIX_WR_CAP: u32 = 64;

// Register-access walk (diagnostic): log every BAR0 register touch, collapsing
// identical consecutive accesses (RDY/CSTS polling spins) into one line, so the
// exact register sequence a driver performs — and where it stops — is legible.
static REG_TRACE_N: AtomicU32 = AtomicU32::new(0);
static REG_TRACE_LAST: AtomicU64 = AtomicU64::new(u64::MAX);
const REG_TRACE_CAP: u32 = 600;
fn reg_trace(is_write: bool, off: u32, val: u64) {
    let key = ((is_write as u64) << 48) | ((off as u64) << 32) | (val & 0xFFFF_FFFF);
    if REG_TRACE_LAST.swap(key, Ordering::Relaxed) == key {
        return; // identical to the previous access — fold the polling loop
    }
    if REG_TRACE_N.fetch_add(1, Ordering::Relaxed) < REG_TRACE_CAP {
        crate::sprintln!("[nvme-reg] {} off=0x{:03X} val=0x{:X}", if is_write { "W" } else { "R" }, off, val);
    }
}

/// Consume the pending completion vector (called by the injection layer).
pub fn pending_irq() -> Option<u8> {
    let v = MSIX_PENDING.swap(MSIX_NONE, Ordering::AcqRel);
    if v == MSIX_NONE {
        None
    } else {
        Some(v as u8)
    }
}

const NVME_OPC_DELETE_SQ:     u8 = 0x00;
const NVME_OPC_CREATE_SQ:     u8 = 0x01;
const NVME_OPC_GET_LOG_PAGE:  u8 = 0x02;
const NVME_OPC_DELETE_CQ:     u8 = 0x04;
const NVME_OPC_CREATE_CQ:     u8 = 0x05;
const NVME_OPC_IDENTIFY:      u8 = 0x06;
const NVME_OPC_ABORT:         u8 = 0x08;
const NVME_OPC_SET_FEATURES:  u8 = 0x09;
const NVME_OPC_GET_FEATURES:  u8 = 0x0A;
const NVME_OPC_ASYNC_EVENT:   u8 = 0x0C;
const NVME_OPC_KEEP_ALIVE:    u8 = 0x18;

const CNS_IDENTIFY_NAMESPACE: u8 = 0x00;
const CNS_IDENTIFY_CONTROLLER: u8 = 0x01;
const CNS_ACTIVE_NS_LIST:     u8 = 0x02;

// ───── Width-aware read/write ────────────────────────────────────────

#[inline]
fn low_mask(width: u8) -> u64 {
    match width {
        1 => 0xFFu64,
        2 => 0xFFFFu64,
        4 => 0xFFFF_FFFFu64,
        _ => u64::MAX,
    }
}

fn read_dword(offset: u32) -> u32 {
    match offset {
        0x000 => CAP_LO,
        0x004 => CAP_HI,
        0x008 => VS_VALUE,
        0x00C => INTMS.load(Ordering::Relaxed),
        0x010 => INTMS.load(Ordering::Relaxed),  // INTMC reads INTMS state
        0x014 => CC.load(Ordering::Relaxed),
        0x01C => CSTS.load(Ordering::Relaxed),
        0x020 => NSSR.load(Ordering::Relaxed),
        0x024 => AQA.load(Ordering::Relaxed),
        0x028 => ASQ_LO.load(Ordering::Relaxed),
        0x02C => ASQ_HI.load(Ordering::Relaxed),
        0x030 => ACQ_LO.load(Ordering::Relaxed),
        0x034 => ACQ_HI.load(Ordering::Relaxed),
        o if msix_table_covers(o) => {
            let idx = ((o - MSIX_TABLE_OFFSET) / 4) as usize;
            unsafe { MSIX_TABLE[idx] }
        }
        o if o >= DOORBELL_BASE => {
            let idx = ((o - DOORBELL_BASE) / 4) as usize;
            if idx < DOORBELL_COUNT { unsafe { DOORBELLS[idx] } } else { 0 }
        }
        _ => 0,
    }
}

pub fn read_register(offset: u32) -> u32 {
    read_dword(offset & !0x3)
}

pub fn read_register_width(offset: u32, width: u8) -> u64 {
    let aligned = offset & !0x3;
    let shift_bits = (offset & 0x3) * 8;
    let dword = read_dword(aligned);
    let val = ((dword as u64) >> shift_bits) & low_mask(width);
    reg_trace(false, offset, val);
    val
}

pub fn write_register_width(offset: u32, val: u64, width: u8) {
    reg_trace(true, offset, val & low_mask(width));
    let aligned = offset & !0x3;
    let shift_bits = (offset & 0x3) * 8;
    let mask_u32 = (low_mask(width) as u32).wrapping_shl(shift_bits);
    let val_u32 = ((val & low_mask(width)) as u32).wrapping_shl(shift_bits);
    let merge = |slot: &AtomicU32| -> u32 {
        let prev = slot.load(Ordering::Relaxed);
        let new = (prev & !mask_u32) | val_u32;
        slot.store(new, Ordering::Relaxed);
        new
    };
    match aligned {
        0x00C => { merge(&INTMS); }
        0x010 => {
            // INTMC: write-1-to-clear against INTMS.
            let prev = INTMS.load(Ordering::Relaxed);
            INTMS.store(prev & !val_u32, Ordering::Relaxed);
        }
        0x014 => {
            let new_cc = merge(&CC);
            {
                let t = NVME_TRACE.fetch_add(1, Ordering::Relaxed);
                if t < NVME_TRACE_CAP {
                    crate::sprintln!("[nvme] CC=0x{:X} EN={}", new_cc, new_cc & 1);
                }
            }
            // EN bit 0: setting → CSTS.RDY=1 (controller ready);
            // clearing → CSTS.RDY=0 (going through CC.SHN if non-zero).
            let prev = CSTS.load(Ordering::Relaxed);
            let mut new = if new_cc & 1 != 0 {
                (prev & !0x1) | 0x1                  // set RDY
            } else {
                // Controller Reset (NVMe 1.4 §3.1.5): EN 1→0 resets every
                // queue. The admin SQ/CQ pointers must return to the fresh
                // state or a re-enabling driver (Linux after OVMF used the
                // controller) walks from a stale head and never sees its
                // own Identify entry, and every I/O queue must drop so a
                // re-created qid rebinds cleanly.
                SQ_HEAD.store(0, Ordering::Relaxed);
                CQ_TAIL.store(0, Ordering::Relaxed);
                CQ_PHASE.store(1, Ordering::Relaxed);
                for i in 0..MAX_QUEUES {
                    unsafe { IO_SQ[i].active = false; IO_CQ[i].active = false; }
                }
                prev & !0x1                           // clear RDY
            };
            // Shutdown Notification (CC.SHN, bits 15:14) → Shutdown Status
            // (CSTS.SHST, bits 3:2). A clean OS shutdown writes CC.SHN=01b
            // (normal) or 10b (abrupt) and then polls CSTS.SHST for 10b
            // ("shutdown processing complete"). With no SHST transition the
            // driver's shutdown wait (CAP.TO bounded) spins to timeout every
            // reboot. We process instantly: SHN non-zero → SHST=10b; the
            // controller is also no longer ready once shut down.
            let shn = (new_cc >> 14) & 0x3;
            new &= !(0x3 << 2); // clear SHST
            if shn != 0 {
                new |= 0b10 << 2; // SHST = shutdown complete
                new &= !0x1;      // RDY drops on shutdown
            }
            CSTS.store(new, Ordering::Relaxed);
        }
        0x01C => { merge(&CSTS); }
        0x020 => { merge(&NSSR); }
        0x024 => { merge(&AQA); }
        0x028 => { merge(&ASQ_LO); }
        0x02C => { merge(&ASQ_HI); }
        0x030 => { merge(&ACQ_LO); }
        0x034 => { merge(&ACQ_HI); }
        // Admin SQ tail doorbell: process any new SQ entries up to the
        // posted tail, building CQ entries directly in guest memory.
        0x1000 => {
            unsafe {
                let prev = DOORBELLS[0];
                let new = (prev & !mask_u32) | val_u32;
                DOORBELLS[0] = new;
            }
            let new_tail = val_u32 & 0xFFFF;
            process_admin_queue(new_tail);
        }
        a if msix_table_covers(a) => {
            let idx = ((a - MSIX_TABLE_OFFSET) / 4) as usize;
            unsafe {
                let prev = MSIX_TABLE[idx];
                MSIX_TABLE[idx] = (prev & !mask_u32) | val_u32;
            }
            // Capture what the guest programs into the MSI-X table so the IR
            // remappable format (addr handle vs data index) can be read off a
            // boot rather than guessed. Log the whole entry once its control
            // dword (word%4==3) settles. Diagnostic only — no delivery change.
            if idx % 4 == 3 {
                let entry = idx & !3;
                let n = MSIX_WR_TRACE.fetch_add(1, Ordering::Relaxed);
                if n < MSIX_WR_CAP {
                    let ir = crate::hardware::devices::iommu::ir_active();
                    let (alo, ahi, data, ctrl) = unsafe {
                        (MSIX_TABLE[entry], MSIX_TABLE[entry + 1],
                         MSIX_TABLE[entry + 2], MSIX_TABLE[entry + 3])
                    };
                    crate::sprintln!(
                        "[nvme-msix] entry={} ir={} addr=0x{:08X}_{:08X} data=0x{:X} ctrl=0x{:X}",
                        entry / 4, ir, ahi, alo, data, ctrl,
                    );
                }
            }
        }
        a if a >= DOORBELL_BASE => {
            let idx = ((a - DOORBELL_BASE) / 4) as usize;
            if idx < DOORBELL_COUNT {
                unsafe {
                    let prev = DOORBELLS[idx];
                    DOORBELLS[idx] = (prev & !mask_u32) | val_u32;
                }
            }
            // DSTRD=0 → 4-byte stride. idx 2y = SQ y tail, 2y+1 = CQ y head.
            // idx 0 (admin SQ) is handled above; an even idx ≥ 2 is an I/O
            // SQ tail doorbell we must service. CQ head doorbells (odd) just
            // advance the guest's consumer cursor — nothing for us to do.
            if idx >= 2 && idx % 2 == 0 {
                let qid = (idx / 2) as u16;
                process_io_sq(qid, val_u32 & 0xFFFF);
            }
        }
        _ => {}
    }
}

// ───── Admin Queue command processor ─────────────────────────────────

fn process_admin_queue(new_tail: u32) {
    let asq_base = make_addr(ASQ_LO.load(Ordering::Relaxed), ASQ_HI.load(Ordering::Relaxed));
    let aqa = AQA.load(Ordering::Relaxed);
    let asqs = (aqa & 0xFFF) + 1;
    let mut processed = false;

    while SQ_HEAD.load(Ordering::Relaxed) != new_tail {
        let head = SQ_HEAD.load(Ordering::Relaxed);
        let src = g2h(asq_base.wrapping_add((head as u64) * 64));
        if src.is_null() { break; }

        // Read 64-byte SQ entry from guest memory (NPT-translated).
        let mut entry = [0u8; 64];
        unsafe { core::ptr::copy_nonoverlapping(src as *const u8, entry.as_mut_ptr(), 64); }

        let cdw0 = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let opcode = (cdw0 & 0xFF) as u8;
        let cid = ((cdw0 >> 16) & 0xFFFF) as u16;
        let nsid = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
        let prp1 = u64::from_le_bytes([
            entry[24], entry[25], entry[26], entry[27],
            entry[28], entry[29], entry[30], entry[31],
        ]);
        let cdw10 = u32::from_le_bytes([entry[40], entry[41], entry[42], entry[43]]);
        let cdw11 = u32::from_le_bytes([entry[44], entry[45], entry[46], entry[47]]);

        {
            let t = NVME_TRACE.fetch_add(1, Ordering::Relaxed);
            if t < NVME_TRACE_CAP {
                crate::sprintln!("[nvme] admin opc=0x{:02X} cid={} nsid={} cdw10=0x{:X} cdw11=0x{:X}", opcode, cid, nsid, cdw10, cdw11);
            }
        }

        let status_word: u16 = match opcode {
            NVME_OPC_IDENTIFY => {
                run_identify(prp1, cdw10, nsid);
                0
            }
            NVME_OPC_CREATE_CQ => create_io_cq(prp1, cdw10, cdw11),
            NVME_OPC_CREATE_SQ => create_io_sq(prp1, cdw10, cdw11),
            NVME_OPC_DELETE_CQ => delete_io_cq(cdw10),
            NVME_OPC_DELETE_SQ => delete_io_sq(cdw10),
            NVME_OPC_SET_FEATURES
            | NVME_OPC_GET_FEATURES
            | NVME_OPC_GET_LOG_PAGE
            | NVME_OPC_ABORT
            | NVME_OPC_KEEP_ALIVE => 0,
            NVME_OPC_ASYNC_EVENT => {
                // Real controllers hold AEN requests in flight until an
                // event fires. We never fire events, so the simplest
                // honest answer is to keep retrying — return SUCCESS
                // anyway so the driver doesn't see a hard fail.
                0
            }
            _ => 0x01, // generic command-specific error
        };

        write_cq_entry(cid, status_word, 0);
        let next_head = (head + 1) % asqs;
        SQ_HEAD.store(next_head, Ordering::Relaxed);
        processed = true;
    }

    // One completion interrupt for the batch — the driver drains every
    // fresh CQ entry (phase-tagged) once woken. Admin CQ uses IV 0.
    if processed {
        raise_msix(0);
    }
}

fn write_cq_entry(cid: u16, status_code: u16, cdw0: u32) {
    let acq_base = make_addr(ACQ_LO.load(Ordering::Relaxed), ACQ_HI.load(Ordering::Relaxed));
    let aqa = AQA.load(Ordering::Relaxed);
    let acqs = ((aqa >> 16) & 0xFFF) + 1;
    if acq_base == 0 { return; }

    let tail = CQ_TAIL.load(Ordering::Relaxed);
    let phase = CQ_PHASE.load(Ordering::Relaxed) & 1;

    // CQ entry: 16 bytes
    //   0-3:   DW0 (command-specific)
    //   4-7:   DW1 (command-specific)
    //   8-9:   SQ Head Pointer (u16)
    //   10-11: SQ ID (u16) — 0 for admin
    //   12-13: CID (u16)
    //   14-15: Status field — bit 0 = phase, bits 1-15 = status code/type
    let mut entry = [0u8; 16];
    entry[0..4].copy_from_slice(&cdw0.to_le_bytes());
    let sq_head = SQ_HEAD.load(Ordering::Relaxed) as u16;
    entry[8..10].copy_from_slice(&sq_head.to_le_bytes());
    // SQ ID = 0 implicit
    entry[12..14].copy_from_slice(&cid.to_le_bytes());
    let status_word = (phase as u16) | (status_code << 1);
    entry[14..16].copy_from_slice(&status_word.to_le_bytes());

    let dst = g2h(acq_base.wrapping_add((tail as u64) * 16));
    if dst.is_null() { return; }
    unsafe { core::ptr::copy_nonoverlapping(entry.as_ptr(), dst, 16); }

    let next_tail = (tail + 1) % acqs;
    if next_tail == 0 {
        CQ_PHASE.fetch_xor(1, Ordering::Relaxed);
    }
    CQ_TAIL.store(next_tail, Ordering::Relaxed);
}

fn run_identify(prp1: u64, cdw10: u32, nsid: u32) {
    if prp1 == 0 { return; }
    let cns = (cdw10 & 0xFF) as u8;
    let mut buf = [0u8; 4096];
    match cns {
        CNS_IDENTIFY_NAMESPACE => build_identify_namespace(&mut buf, nsid),
        CNS_IDENTIFY_CONTROLLER => build_identify_controller(&mut buf),
        CNS_ACTIVE_NS_LIST => build_active_namespace_list(&mut buf),
        _ => {} // empty buffer
    }
    let dst = g2h(prp1);
    let t = NVME_TRACE.fetch_add(1, Ordering::Relaxed);
    if t < NVME_TRACE_CAP {
        let nsze = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        crate::sprintln!(
            "[nvme-id] cns={} nsid={} prp1=0x{:X} dst_null={} present={} nsze={}",
            cns, nsid, prp1, dst.is_null(), backend::ns_present(nsid), nsze
        );
    }
    if dst.is_null() { return; }
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, 4096); }
}

/// PCI vendor ID for this NVMe controller, taken from the active profile's
/// `disk.pci_id` (config-space layout: device<<16 | vendor) so IDENTIFY's
/// VID matches what the PCI config emulator reports. Fallback 0x144D
/// (Samsung) matches pci.rs's `pid_nvme` default.
fn nvme_vendor_id() -> u16 {
    active::PROFILE
        .get()
        .map(|p| unsafe { core::ptr::addr_of!(p.hardware.disk.pci_id).read_unaligned() })
        .filter(|&v| v != 0)
        .map(|v| (v & 0xFFFF) as u16)
        .unwrap_or(0x144D)
}

fn build_identify_controller(buf: &mut [u8; 4096]) {
    // VID / SSVID (0-3): derived from the controller's PCI vendor so
    // IDENTIFY agrees with PCI config space (a mismatch is a classic
    // emulation tell). SSVID = VID (no separate subsystem vendor modelled).
    let vid = nvme_vendor_id();
    buf[0..2].copy_from_slice(&vid.to_le_bytes());
    buf[2..4].copy_from_slice(&vid.to_le_bytes());

    // SN (4-23): 20-byte ASCII serial, space-padded
    let serial = active::PROFILE.get().map(|p| {
        let s = unsafe { core::ptr::addr_of!(p.hardware.disk.serial).read_unaligned() };
        let b = s.as_bytes();
        let mut out = [b' '; 20];
        let n = b.len().min(20);
        out[..n].copy_from_slice(&b[..n]);
        out
    }).unwrap_or([b' '; 20]);
    buf[4..24].copy_from_slice(&serial);

    // MN (24-63): 40-byte ASCII model, space-padded
    let model = active::PROFILE.get().map(|p| {
        let m = unsafe { core::ptr::addr_of!(p.hardware.disk.model).read_unaligned() };
        let b = m.as_bytes();
        let mut out = [b' '; 40];
        let n = b.len().min(40);
        out[..n].copy_from_slice(&b[..n]);
        out
    }).unwrap_or([b' '; 40]);
    buf[24..64].copy_from_slice(&model);

    // FR (64-71): firmware revision — from profile (space-padded 8 bytes).
    let fw = active::PROFILE.get().map(|p| {
        let s = unsafe { core::ptr::addr_of!(p.hardware.disk.firmware_rev).read_unaligned() };
        let b = s.as_bytes();
        let mut out = [b' '; 8];
        let n = b.len().min(8);
        out[..n].copy_from_slice(&b[..n]);
        out
    }).unwrap_or([b' '; 8]);
    buf[64..72].copy_from_slice(&fw);
    buf[72] = 6;                       // RAB
    // IEEE OUI (73-75): controller vendor, from profile (LE).
    let oui = active::PROFILE.get()
        .map(|p| unsafe { core::ptr::addr_of!(p.hardware.disk.ieee_oui).read_unaligned() })
        .unwrap_or([0, 0, 0]);
    buf[73..76].copy_from_slice(&oui);
    buf[77] = 7;                       // MDTS = 2^7 pages
    buf[78..80].copy_from_slice(&1u16.to_le_bytes()); // CNTLID
    buf[80..84].copy_from_slice(&0x0001_0400u32.to_le_bytes()); // VER NVMe 1.4
    buf[256..258].copy_from_slice(&0x0014u16.to_le_bytes()); // OACS
    buf[258] = 3;                      // ACL
    buf[259] = 3;                      // AERL
    buf[260] = 0x16;                   // FRMW
    buf[261] = 0x0F;                   // LPA
    buf[262] = 0x7F;                   // ELPE
    buf[263] = 5;                      // NPSS
    buf[264] = 1;                      // AVSCC
    buf[265] = 1;                      // APSTA
    buf[266..268].copy_from_slice(&0x0158u16.to_le_bytes()); // WCTEMP = 71°C
    buf[268..270].copy_from_slice(&0x0163u16.to_le_bytes()); // CCTEMP = 82°C

    // TNVMCAP / UNVMCAP (280-311): 16 bytes each, 2 TB in bytes
    let cap_bytes: u128 = 2u128 * 1024 * 1024 * 1024 * 1024;
    buf[280..296].copy_from_slice(&cap_bytes.to_le_bytes());
    buf[296..312].copy_from_slice(&cap_bytes.to_le_bytes());

    buf[512] = 0x66;                   // SQES (required 64, max 64)
    buf[513] = 0x44;                   // CQES (required 16, max 16)
    buf[514..516].copy_from_slice(&1024u16.to_le_bytes()); // MAXCMD
    buf[516..520].copy_from_slice(&backend::ns_count().to_le_bytes()); // NN = namespace count
    buf[520..522].copy_from_slice(&0x0072u16.to_le_bytes()); // ONCS: DSM+WriteZeros+Save/Select+Reservations
    buf[525] = 1;                      // VWC: volatile write cache present

    // SUBNQN (768-1023): standard uuid form, per-machine. Real controllers
    // never embed a vendor codename — "veneer" in the NQN was a giveaway.
    let head = b"nqn.2014-08.org.nvmexpress:uuid:";
    let mut nqn = [0u8; 256];
    nqn[..head.len()].copy_from_slice(head);
    let mut end = head.len();
    if let Some(p) = active::PROFILE.get() {
        let u = unsafe { core::ptr::addr_of!(p.hardware.smbios.uuid).read_unaligned() };
        let ub = u.as_bytes();
        let n = ub.len().min(36);
        nqn[end..end + n].copy_from_slice(&ub[..n]);
        end += n;
    }
    buf[768..768 + end].copy_from_slice(&nqn[..end]);
}

fn build_identify_namespace(buf: &mut [u8; 4096], nsid: u32) {
    // Report the backing disk geometry for this namespace so the guest's
    // partition scanner and filesystem see exactly the LBAs that exist.
    // A namespace with no backing disk reports zero size (inactive).
    let (lba_count, lbads): (u64, u8) = if backend::ns_present(nsid) {
        let bs = backend::block_size(nsid);
        (backend::block_count(nsid), bs.trailing_zeros() as u8)
    } else {
        (0, 9)
    };
    let cap_bytes: u128 = (lba_count as u128) << lbads;

    buf[0..8].copy_from_slice(&lba_count.to_le_bytes());     // NSZE
    buf[8..16].copy_from_slice(&lba_count.to_le_bytes());    // NCAP
    buf[16..24].copy_from_slice(&lba_count.to_le_bytes());   // NUSE
    buf[24] = 0x02;                                           // NSFEAT: thin provisioning
    buf[25] = 0;                                              // NLBAF (1 format, 0-based)
    buf[26] = 0;                                              // FLBAS: format 0 selected
    buf[33] = 9;                                              // DLFEAT
    buf[48..64].copy_from_slice(&cap_bytes.to_le_bytes());   // NVMCAP
    // LBA Format 0 (128-131): LBADS in bits 23:16, MS=0, RP=0.
    let lbaf0: u32 = (lbads as u32) << 16;
    buf[128..132].copy_from_slice(&lbaf0.to_le_bytes());
}

fn build_active_namespace_list(buf: &mut [u8; 4096]) {
    // 4-byte namespace IDs, ascending, zero-terminated.
    let mut off = 0;
    for nsid in 1..=2u32 {
        if backend::ns_present(nsid) {
            buf[off..off + 4].copy_from_slice(&nsid.to_le_bytes());
            off += 4;
        }
    }
}

// ───── I/O queue management (admin CREATE/DELETE handlers) ───────────

/// CREATE I/O COMPLETION QUEUE (admin opcode 0x05).
///   PRP1  = CQ base (guest-physical, physically contiguous)
///   CDW10 = QID[15:0] | QSIZE[31:16] (0-based)
///   CDW11 = PC[0] | IEN[1] | IV[31:16]
fn create_io_cq(prp1: u64, cdw10: u32, cdw11: u32) -> u16 {
    let qid = (cdw10 & 0xFFFF) as usize;
    let qsize = ((cdw10 >> 16) & 0xFFFF) + 1;
    let iv = ((cdw11 >> 16) & 0xFFFF) as u16;
    if qid == 0 || qid >= MAX_QUEUES {
        return 0x01;
    }
    unsafe {
        IO_CQ[qid] = IoCq { base: prp1, size: qsize, iv, tail: 0, phase: 1, active: true };
    }
    let t = NVME_TRACE.fetch_add(1, Ordering::Relaxed);
    if t < NVME_TRACE_CAP {
        crate::sprintln!("[nvme] create CQ qid={} size={} iv={} base=0x{:X}", qid, qsize, iv, prp1);
    }
    0
}

/// CREATE I/O SUBMISSION QUEUE (admin opcode 0x01).
///   PRP1  = SQ base (guest-physical, physically contiguous)
///   CDW10 = QID[15:0] | QSIZE[31:16] (0-based)
///   CDW11 = PC[0] | QPRIO[2:1] | CQID[31:16]
fn create_io_sq(prp1: u64, cdw10: u32, cdw11: u32) -> u16 {
    let qid = (cdw10 & 0xFFFF) as usize;
    let qsize = ((cdw10 >> 16) & 0xFFFF) + 1;
    let cqid = ((cdw11 >> 16) & 0xFFFF) as u16;
    if qid == 0 || qid >= MAX_QUEUES {
        return 0x01;
    }
    unsafe {
        IO_SQ[qid] = IoSq { base: prp1, size: qsize, cqid, head: 0, active: true };
    }
    let t = NVME_TRACE.fetch_add(1, Ordering::Relaxed);
    if t < NVME_TRACE_CAP {
        crate::sprintln!("[nvme] create SQ qid={} size={} cqid={} base=0x{:X}", qid, qsize, cqid, prp1);
    }
    0
}

fn delete_io_cq(cdw10: u32) -> u16 {
    let qid = (cdw10 & 0xFFFF) as usize;
    if qid == 0 || qid >= MAX_QUEUES { return 0x01; }
    unsafe { IO_CQ[qid].active = false; }
    0
}

fn delete_io_sq(cdw10: u32) -> u16 {
    let qid = (cdw10 & 0xFFFF) as usize;
    if qid == 0 || qid >= MAX_QUEUES { return 0x01; }
    unsafe { IO_SQ[qid].active = false; }
    0
}

// ───── I/O command processor ─────────────────────────────────────────

/// Service an I/O submission queue up to the posted tail. Each command is
/// executed against the backing disk, a completion is posted to the
/// paired CQ, and the CQ's MSI-X vector is raised once for the batch.
fn process_io_sq(qid: u16, new_tail: u32) {
    let q = qid as usize;
    if q == 0 || q >= MAX_QUEUES {
        return;
    }
    let (base, size, cqid, active) = unsafe {
        (IO_SQ[q].base, IO_SQ[q].size, IO_SQ[q].cqid, IO_SQ[q].active)
    };
    if !active || size == 0 {
        return;
    }
    let mut processed = false;

    while unsafe { IO_SQ[q].head } != new_tail {
        let head = unsafe { IO_SQ[q].head };
        let src = g2h(base.wrapping_add((head as u64) * 64));
        if src.is_null() { break; }
        let mut entry = [0u8; 64];
        unsafe { core::ptr::copy_nonoverlapping(src as *const u8, entry.as_mut_ptr(), 64); }

        let cdw0 = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let opcode = (cdw0 & 0xFF) as u8;
        let cid = ((cdw0 >> 16) & 0xFFFF) as u16;
        let nsid = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
        let prp1 = u64::from_le_bytes([
            entry[24], entry[25], entry[26], entry[27],
            entry[28], entry[29], entry[30], entry[31],
        ]);
        let prp2 = u64::from_le_bytes([
            entry[32], entry[33], entry[34], entry[35],
            entry[36], entry[37], entry[38], entry[39],
        ]);
        let slba = (u32::from_le_bytes([entry[40], entry[41], entry[42], entry[43]]) as u64)
            | ((u32::from_le_bytes([entry[44], entry[45], entry[46], entry[47]]) as u64) << 32);
        let nlb = (u32::from_le_bytes([entry[48], entry[49], entry[50], entry[51]]) & 0xFFFF) + 1;

        let status: u16 = match opcode {
            IO_OPC_READ  => do_rw(true, slba, nlb, prp1, prp2, nsid),
            IO_OPC_WRITE => do_rw(false, slba, nlb, prp1, prp2, nsid),
            IO_OPC_FLUSH => 0,
            IO_OPC_WRITE_ZEROES | IO_OPC_DSM => 0,
            _ => 0x01,
        };

        let t = NVME_TRACE.fetch_add(1, Ordering::Relaxed);
        if t < NVME_TRACE_CAP {
            crate::sprintln!("[nvme] io qid={} ns={} opc=0x{:02X} slba={} nlb={} status={}", qid, nsid, opcode, slba, nlb, status);
        }

        io_cq_post(cqid, cid, qid, status, head as u16);
        let next = (head + 1) % size;
        unsafe { IO_SQ[q].head = next; }
        processed = true;
    }

    if processed {
        let iv = unsafe { IO_CQ[cqid as usize].iv };
        raise_msix(iv);
    }
}

// Aligned staging window for disk<->PRP transfers. The backing BlockIO
// reads/writes whole LBAs into this buffer (it satisfies the controller's
// io_align), and we scatter/gather bytes between it and the command's PRP
// fragments. The guest serialises I/O on one queue here, so a single
// shared buffer is safe.
const STAGE_BYTES: usize = 0x1_0000; // 64 KiB

#[repr(align(4096))]
struct Stage([u8; STAGE_BYTES]);
static mut STAGE: Stage = Stage([0u8; STAGE_BYTES]);

#[inline]
fn stage_ptr() -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!(STAGE.0) as *mut u8 }
}

/// Execute a READ/WRITE. LBA boundaries and PRP page boundaries need not
/// align — PRP1 can carry a byte offset — so the disk side stays
/// LBA-aligned (via the staging buffer) while the guest side is copied
/// byte-granular across the PRP fragments.
fn do_rw(read: bool, slba: u64, nlb: u32, prp1: u64, prp2: u64, nsid: u32) -> u16 {
    if !backend::ns_present(nsid) {
        return if read { 0 } else { 0x01 }; // read-zeros benign; write needs media
    }
    let bs = backend::block_size(nsid) as u64;
    if bs == 0 {
        return 0x01;
    }
    let total = (nlb as u64) * bs;
    if total == 0 {
        return 0;
    }
    if read {
        stream_read(slba, total, prp1, prp2, bs, nsid)
    } else {
        stream_write(slba, total, prp1, prp2, bs, nsid)
    }
}

/// Pull whole-LBA chunks from the disk into the staging buffer and scatter
/// the bytes into the PRP fragments in order.
fn stream_read(slba: u64, total: u64, prp1: u64, prp2: u64, bs: u64, nsid: u32) -> u16 {
    let mut lba = slba;
    let mut disk_left = total;
    let mut filled = 0usize; // valid bytes in stage
    let mut pos = 0usize;    // consumed bytes in stage
    let ok = prp_for_each(prp1, prp2, total, |gpa, len| {
        let dst = g2h(gpa);
        if dst.is_null() {
            return false;
        }
        let need = len as usize;
        let mut done = 0usize;
        while done < need {
            if pos == filled {
                let want = core::cmp::min(disk_left, STAGE_BYTES as u64);
                if want == 0 {
                    return false;
                }
                let blocks = (want / bs) as u32;
                if !backend::read(nsid, lba, blocks, stage_ptr()) {
                    return false;
                }
                lba += blocks as u64;
                disk_left -= want;
                filled = want as usize;
                pos = 0;
            }
            let n = core::cmp::min(need - done, filled - pos);
            unsafe {
                core::ptr::copy_nonoverlapping((stage_ptr() as *const u8).add(pos), dst.add(done), n);
            }
            done += n;
            pos += n;
        }
        true
    });
    if ok { 0 } else { 0x01 }
}

/// Gather the PRP fragments into the staging buffer and flush whole-LBA
/// chunks to the disk. `total` is an LBA multiple, so the final partial
/// fill is also LBA-aligned.
fn stream_write(slba: u64, total: u64, prp1: u64, prp2: u64, bs: u64, nsid: u32) -> u16 {
    let mut lba = slba;
    let mut filled = 0usize;
    let ok = prp_for_each(prp1, prp2, total, |gpa, len| {
        let src = g2h(gpa);
        if src.is_null() {
            return false;
        }
        let need = len as usize;
        let mut done = 0usize;
        while done < need {
            let n = core::cmp::min(need - done, STAGE_BYTES - filled);
            unsafe {
                core::ptr::copy_nonoverlapping((src as *const u8).add(done), stage_ptr().add(filled), n);
            }
            filled += n;
            done += n;
            if filled == STAGE_BYTES {
                let blocks = (STAGE_BYTES as u64 / bs) as u32;
                if !backend::write(nsid, lba, blocks, stage_ptr() as *const u8) {
                    return false;
                }
                lba += blocks as u64;
                filled = 0;
            }
        }
        true
    });
    if !ok {
        return 0x01;
    }
    if filled > 0 {
        let blocks = (filled as u64 / bs) as u32;
        if !backend::write(nsid, lba, blocks, stage_ptr() as *const u8) {
            return 0x01;
        }
    }
    0
}

/// Walk a command's PRP1/PRP2 data pointer, invoking `f(gpa, len)` for
/// each physically-contiguous guest chunk covering `total` bytes. Returns
/// false if `f` rejects a chunk or a list page is unreachable. Implements
/// the NVMe PRP rules: PRP1 may carry a page offset; PRP2 is the second
/// page when the transfer fits in two pages, else it points to a PRP List
/// whose last entry chains to the next list page when more remains.
fn prp_for_each<F: FnMut(u64, u64) -> bool>(prp1: u64, prp2: u64, total: u64, mut f: F) -> bool {
    if total == 0 {
        return true;
    }
    let off = prp1 & (PAGE - 1);
    let first = core::cmp::min(total, PAGE - off);
    if !f(prp1, first) {
        return false;
    }
    let mut remaining = total - first;
    if remaining == 0 {
        return true;
    }
    if remaining <= PAGE {
        return f(prp2, remaining);
    }

    // PRP2 is a list pointer. Each list page holds 512 entries; the last
    // entry chains to the next list page while more than one page remains.
    let entries = (PAGE / 8) as usize;
    let mut list_gpa = prp2;
    loop {
        let list = g2h(list_gpa);
        if list.is_null() {
            return false;
        }
        for i in 0..entries {
            let entry = unsafe { core::ptr::read_unaligned((list as *const u64).add(i)) };
            if i == entries - 1 && remaining > PAGE {
                list_gpa = entry;
                break;
            }
            let chunk = core::cmp::min(remaining, PAGE);
            if !f(entry, chunk) {
                return false;
            }
            remaining -= chunk;
            if remaining == 0 {
                return true;
            }
        }
    }
}

/// Post a 16-byte completion to I/O completion queue `cqid`.
fn io_cq_post(cqid: u16, cid: u16, sqid: u16, status_code: u16, sq_head: u16) {
    let c = cqid as usize;
    if c == 0 || c >= MAX_QUEUES {
        return;
    }
    let (base, size, tail, phase, active) = unsafe {
        (IO_CQ[c].base, IO_CQ[c].size, IO_CQ[c].tail, IO_CQ[c].phase, IO_CQ[c].active)
    };
    if !active || size == 0 {
        return;
    }
    let dst = g2h(base.wrapping_add((tail as u64) * 16));
    if dst.is_null() {
        return;
    }
    let mut entry = [0u8; 16];
    // DW0/DW1 command-specific = 0.
    entry[8..10].copy_from_slice(&sq_head.to_le_bytes());
    entry[10..12].copy_from_slice(&sqid.to_le_bytes());
    entry[12..14].copy_from_slice(&cid.to_le_bytes());
    let status_word = (phase as u16 & 1) | (status_code << 1);
    entry[14..16].copy_from_slice(&status_word.to_le_bytes());
    unsafe { core::ptr::copy_nonoverlapping(entry.as_ptr(), dst, 16); }

    let next = (tail + 1) % size;
    unsafe {
        IO_CQ[c].tail = next;
        if next == 0 {
            IO_CQ[c].phase ^= 1;
        }
    }
}

#[inline]
fn make_addr(lo: u32, hi: u32) -> u64 {
    ((hi as u64) << 32) | (lo as u64)
}
