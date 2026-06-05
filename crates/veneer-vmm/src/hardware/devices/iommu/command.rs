//! AMD-Vi command-buffer engine.
//!
//! The HAL builds 16-byte commands in an in-memory ring (Command Buffer Base,
//! a guest-physical address) and rings the doorbell by writing the Command
//! Buffer Tail Pointer (MMIO 0x2008). Real hardware then consumes commands from
//! Head to Tail and advances Head. We do the same: drain the ring and set
//! Head = Tail so the HAL sees its commands consumed.
//!
//! We do not perform real DMA/interrupt remapping (one vCPU, veneer injects
//! interrupts directly). The only command with an observable side effect we
//! must honor is COMPLETION_WAIT (opcode 1): if its store (s) bit is set we
//! write its data to its store address, and we raise the ComWaitInt status —
//! that is how the HAL learns the flush it queued has finished.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::introspect::mem;

use super::{CMD_BUF_BASE, CMD_HEAD, CMD_TAIL, STATUS};

const OPCODE_COMPLETION_WAIT: u64 = 0x1;
const STATUS_COM_WAIT_INT: u64 = 0x4; // MMIO Status register bit 2

// Log the opcode of each command the guest issues (capped). Reveals, without a
// guest breakpoint, how far the HAL's interrupt-remapping path gets: AMD-Vi
// opcodes are 0x1 COMPLETION_WAIT, 0x2 INVALIDATE_DEVTAB_ENTRY, 0x3
// INVALIDATE_IOMMU_PAGES, 0x4 INVALIDATE_IOTLB_PAGES, 0x5
// INVALIDATE_INTERRUPT_TABLE, 0x8 INVALIDATE_IOMMU_ALL. Seeing 0x5 means the
// guest reached the interrupt-remap step; not seeing it means it failed earlier.
static CMD_LOG_N: AtomicU32 = AtomicU32::new(0);
const CMD_LOG_CAP: u32 = 256;

/// Drain the command ring from Head to Tail. Called on a doorbell (tail write).
pub fn process_doorbell() {
    let base_reg = CMD_BUF_BASE.load(Ordering::Relaxed);
    let buf_gpa = base_reg & 0x000F_FFFF_FFFF_F000; // bits[51:12], 4 KiB-aligned
    if buf_gpa == 0 {
        return;
    }
    // ComLen (bits[59:56]) → ring size = 2^ComLen entries × 16 B (ComLen 8 ⇒ 4 KiB).
    let comlen = ((base_reg >> 56) & 0xF) as u32;
    let size = if (8..=15).contains(&comlen) { (1u64 << comlen) * 16 } else { 0x1000 };
    let mask = size - 1;

    let tail = CMD_TAIL.load(Ordering::Relaxed) & mask & !0xF;
    let mut head = CMD_HEAD.load(Ordering::Relaxed) & mask & !0xF;

    let mut guard = 0u64;
    let cap = size / 16 + 1;
    while head != tail && guard < cap {
        let mut cmd = [0u8; 16];
        if !mem::read_phys(buf_gpa + head, &mut cmd) {
            break;
        }
        let q0 = u64::from_le_bytes(cmd[0..8].try_into().unwrap());
        let q1 = u64::from_le_bytes(cmd[8..16].try_into().unwrap());
        let opcode = (q0 >> 60) & 0xF;
        if CMD_LOG_N.fetch_add(1, Ordering::Relaxed) < CMD_LOG_CAP {
            crate::sprintln!("[iommu] cmd op={:#x} q0={:#018x} q1={:#018x}", opcode, q0, q1);
        }
        if opcode == OPCODE_COMPLETION_WAIT {
            // s-bit (bit0): store q1 (data) to the store address in bits[51:3].
            if q0 & 1 != 0 {
                let store_gpa = q0 & 0x000F_FFFF_FFFF_FFF8;
                let _ = mem::write_phys(store_gpa, &q1.to_le_bytes());
            }
            STATUS.fetch_or(STATUS_COM_WAIT_INT, Ordering::Relaxed);
        }
        // Invalidate* and other commands need no action: we keep no shadow
        // page/interrupt tables, so there is nothing to flush.
        head = (head + 16) & mask;
        guard += 1;
    }
    // All queued commands consumed.
    CMD_HEAD.store(tail, Ordering::Relaxed);
}
