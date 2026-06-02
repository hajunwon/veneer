//! TPM 2.0 emulator — CRB MMIO + functional command processor.
//!
//! Module layout:
//!   - this file       — CRB MMIO emulator, START trigger plumbing
//!   - `sha256`        — NIST FIPS 180-4 SHA-256
//!   - `state`         — persistent state (PCR banks, NV indices)
//!   - `commands`      — TPM2 command parse + dispatch
//!   - `ek_cert`       — synthetic EK certificate at NV 0x01C00002
//!
//! Detection vectors addressed (vs the prior skeleton-only build):
//!
//!   1. ✓ TPM_PT_MANUFACTURER = "AMD " via GetCapability
//!   2. ◐ EK cert chain — self-consistent X.509 in NV index 0x01C00002,
//!         not provably signed by AMD's real EK Root CA (online
//!         attestation would catch this)
//!   3. ◐ Timing — synchronous handlers, no artificial delay
//!   4. ✓ PCR consistency — real SHA-256 hash chain via PCR_Extend
//!   5. ✓ RNG quality — host RDRAND backs GetRandom
//!   6. ✓ NV index pre-load — EK cert + EK template at TCG standard
//!         indices

mod commands;
mod crypto;
mod ek_cert;
mod sha256;
mod state;

use core::sync::atomic::{AtomicU32, Ordering};

pub const TPM_BASE: u64 = 0xFED4_0000;
pub const TPM_SIZE: u64 = 0x0000_1000;

#[inline]
pub fn covers(gpa: u64) -> bool {
    gpa >= TPM_BASE && gpa < TPM_BASE + TPM_SIZE
}

const TPM_LOC_STATE_INIT: u32 = 0x81;        // locActive + tpmRegValidSts
const TPM_INTERFACE_ID:   u32 = 0x1100_0011; // CRB iface, ACPI start, no idle bypass

// ───── CRB control registers ─────────────────────────────────────────
static LOC_STATE: AtomicU32        = AtomicU32::new(TPM_LOC_STATE_INIT);
static LOC_CTRL: AtomicU32         = AtomicU32::new(0);
static LOC_STS: AtomicU32          = AtomicU32::new(0);
static CRB_CTRL_REQ: AtomicU32     = AtomicU32::new(0);
/// tpmIdle bit 0 = 1 (idle, ready). When START is written we transiently
/// clear it inside `start_command`, run the handler synchronously, then
/// restore it before VMRUN resumes.
static CRB_CTRL_STS: AtomicU32     = AtomicU32::new(0x0000_0001);
static CRB_CTRL_CANCEL: AtomicU32  = AtomicU32::new(0);
static CRB_CTRL_START: AtomicU32   = AtomicU32::new(0);
static CRB_INT_ENABLE: AtomicU32   = AtomicU32::new(0);
static CRB_INT_STATUS: AtomicU32   = AtomicU32::new(0);
static CRB_CMD_SIZE: AtomicU32     = AtomicU32::new(0xF80);
static CRB_CMD_LADDR: AtomicU32    = AtomicU32::new((TPM_BASE + 0x80) as u32);
static CRB_CMD_HADDR: AtomicU32    = AtomicU32::new((TPM_BASE >> 32) as u32);
static CRB_RSP_SIZE: AtomicU32     = AtomicU32::new(0xF80);
static CRB_RSP_ADDR_LO: AtomicU32  = AtomicU32::new((TPM_BASE + 0x80) as u32);
static CRB_RSP_ADDR_HI: AtomicU32  = AtomicU32::new((TPM_BASE >> 32) as u32);

// ───── Command/Response data buffer (3968 bytes) ──────────────────────
const DATA_BUFFER_OFFSET: u32 = 0x80;
const DATA_BUFFER_SIZE: usize = 0xF80;

/// The guest writes its TPM2 command into bytes 0x80..0x1000 of our CRB
/// window; we keep it in this static array. On START trigger we parse,
/// dispatch, and overwrite with the response.
static mut DATA_BUFFER: [u8; DATA_BUFFER_SIZE] = [0u8; DATA_BUFFER_SIZE];

/// Public init — call once at boot to populate NV indices with the
/// synthetic EK cert + template.
pub fn init() {
    state::init();
}

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
        0x000 => LOC_STATE.load(Ordering::Relaxed),
        0x008 => LOC_CTRL.load(Ordering::Relaxed),
        0x00C => LOC_STS.load(Ordering::Relaxed),
        0x030 => TPM_INTERFACE_ID,
        0x040 => CRB_CTRL_REQ.load(Ordering::Relaxed),
        0x044 => CRB_CTRL_STS.load(Ordering::Relaxed),
        0x048 => CRB_CTRL_CANCEL.load(Ordering::Relaxed),
        0x04C => CRB_CTRL_START.load(Ordering::Relaxed),
        0x050 => CRB_INT_ENABLE.load(Ordering::Relaxed),
        0x054 => CRB_INT_STATUS.load(Ordering::Relaxed),
        0x058 => CRB_CMD_SIZE.load(Ordering::Relaxed),
        0x05C => CRB_CMD_LADDR.load(Ordering::Relaxed),
        0x060 => CRB_CMD_HADDR.load(Ordering::Relaxed),
        0x064 => CRB_RSP_SIZE.load(Ordering::Relaxed),
        0x068 => CRB_RSP_ADDR_LO.load(Ordering::Relaxed),
        0x06C => CRB_RSP_ADDR_HI.load(Ordering::Relaxed),
        // Data buffer area: read from our backing store.
        o if (DATA_BUFFER_OFFSET..(DATA_BUFFER_OFFSET as usize + DATA_BUFFER_SIZE) as u32).contains(&o) => {
            let idx = (o - DATA_BUFFER_OFFSET) as usize;
            if idx + 4 <= DATA_BUFFER_SIZE {
                unsafe {
                    u32::from_le_bytes([
                        DATA_BUFFER[idx],
                        DATA_BUFFER[idx + 1],
                        DATA_BUFFER[idx + 2],
                        DATA_BUFFER[idx + 3],
                    ])
                }
            } else { 0 }
        }
        _ => 0,
    }
}

pub fn read_register_width(offset: u32, width: u8) -> u64 {
    let aligned = offset & !0x3;
    let shift_bits = (offset & 0x3) * 8;
    let dword = read_dword(aligned);
    ((dword as u64) >> shift_bits) & low_mask(width)
}

pub fn write_register_width(offset: u32, val: u64, width: u8) {
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
        0x008 => { merge(&LOC_CTRL); }
        0x00C => { merge(&LOC_STS); }
        0x040 => { merge(&CRB_CTRL_REQ); }
        0x044 => { merge(&CRB_CTRL_STS); }
        0x048 => { merge(&CRB_CTRL_CANCEL); }
        0x04C => {
            let new = merge(&CRB_CTRL_START);
            // Guest sets bit 0 to trigger command processing.
            if new & 1 != 0 {
                start_command();
                // Clear START + mark idle once command finished.
                CRB_CTRL_START.store(0, Ordering::Relaxed);
                CRB_CTRL_STS.fetch_or(0x0000_0001, Ordering::Relaxed);
            }
        }
        0x050 => { merge(&CRB_INT_ENABLE); }
        0x054 => { merge(&CRB_INT_STATUS); }
        0x05C => { merge(&CRB_CMD_LADDR); }
        0x060 => { merge(&CRB_CMD_HADDR); }
        0x068 => { merge(&CRB_RSP_ADDR_LO); }
        0x06C => { merge(&CRB_RSP_ADDR_HI); }
        a if (DATA_BUFFER_OFFSET..(DATA_BUFFER_OFFSET as usize + DATA_BUFFER_SIZE) as u32).contains(&a) => {
            let idx = (a - DATA_BUFFER_OFFSET) as usize;
            if idx + 4 <= DATA_BUFFER_SIZE {
                unsafe {
                    let prev = u32::from_le_bytes([
                        DATA_BUFFER[idx],
                        DATA_BUFFER[idx + 1],
                        DATA_BUFFER[idx + 2],
                        DATA_BUFFER[idx + 3],
                    ]);
                    let new = (prev & !mask_u32) | val_u32;
                    let new_bytes = new.to_le_bytes();
                    DATA_BUFFER[idx..idx + 4].copy_from_slice(&new_bytes);
                }
            }
        }
        _ => {}
    }
}

/// Invoked when the guest writes bit 0 of TPM_CRB_CTRL_START. Parses
/// the command stored in DATA_BUFFER, dispatches to the handler, and
/// writes the response back into DATA_BUFFER.
fn start_command() {
    // Clear tpmIdle (bit 0) during processing — guests poll this to
    // know when the response is ready.
    CRB_CTRL_STS.fetch_and(!0x0000_0001, Ordering::Relaxed);

    // SAFETY: TPM commands are serialised at the protocol level
    // (locality + START handshake), so single-threaded access to
    // DATA_BUFFER from inside the start_command path is safe.
    unsafe {
        let cmd_size = parse_command_size(&*core::ptr::addr_of!(DATA_BUFFER));
        let cmd_size = cmd_size.min(DATA_BUFFER_SIZE);
        // The command is read and the response written to the same buffer,
        // so copy the command out first, then write the response in-place.
        let mut cmd_copy = [0u8; DATA_BUFFER_SIZE];
        cmd_copy[..cmd_size].copy_from_slice(&DATA_BUFFER[..cmd_size]);
        // Zero the buffer first so stale bytes don't bleed through.
        for b in &mut DATA_BUFFER[..] { *b = 0; }
        let rsp_len = commands::process(&cmd_copy[..cmd_size], &mut DATA_BUFFER[..]);
        // Update CRB_CTRL_CMD/RSP_SIZE for symmetry; many guests
        // re-read these between commands.
        CRB_RSP_SIZE.store(rsp_len as u32, Ordering::Relaxed);
    }
}

fn parse_command_size(buf: &[u8]) -> usize {
    if buf.len() < 6 { return 0; }
    u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize
}
