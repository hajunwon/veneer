//! AHCI SATA host controller exposing one ATAPI CD-ROM port that serves
//! the install media (ISO). OVMF's AHCI + ATAPI + ISO9660/El-Torito stack
//! boots from this — the standard "boot media" path. Forcing a 2048-byte
//! ISO through an NVMe namespace breaks isohybrid 512-byte MBR/GPT LBAs,
//! so the media gets its own native-2048 ATAPI device here.
//!
//! OVMF drives AHCI synchronously: it builds a command list / command
//! table / PRDT in guest RAM, sets PxCI, then polls PxCI back to 0. We
//! process the command inline on the PxCI write and clear the bit, so no
//! interrupt is needed for the boot path.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};


// ───── ATAPI sense / UNIT ATTENTION state ────────────────────────────
// Removable-media ATAPI: after power-on/reset the device reports a UNIT
// ATTENTION on the first command (except INQUIRY / REQUEST SENSE), and the
// driver clears it with REQUEST SENSE. Without modelling this the driver
// loops TEST-UNIT-READY + REQUEST SENSE forever and never reads the media.
static SENSE_KEY: AtomicU8 = AtomicU8::new(0x06);   // UNIT ATTENTION
static SENSE_ASC: AtomicU8 = AtomicU8::new(0x29);   // POWER ON / RESET OCCURRED
static SENSE_ASCQ: AtomicU8 = AtomicU8::new(0x00);
/// Set by handle_scsi when the command should complete with CHECK CONDITION
/// (ERR) instead of GOOD; the completion path reads it to pick the D2H FIS.
static CHECK_CONDITION: AtomicBool = AtomicBool::new(false);

fn set_sense(key: u8, asc: u8, ascq: u8) {
    SENSE_KEY.store(key, Ordering::Relaxed);
    SENSE_ASC.store(asc, Ordering::Relaxed);
    SENSE_ASCQ.store(ascq, Ordering::Relaxed);
}

pub const AHCI_ABAR_DEFAULT: u64 = 0xE300_0000;
pub const AHCI_ABAR_SIZE: u64 = 0x2000;

static ABAR: AtomicU64 = AtomicU64::new(AHCI_ABAR_DEFAULT);

pub fn base() -> u64 {
    ABAR.load(Ordering::Relaxed)
}
pub fn set_base(b: u64) {
    ABAR.store(b, Ordering::Relaxed);
    crate::sprintln!("[ahci] set_base 0x{:X}", b);
}

#[inline]
pub fn covers(gpa: u64) -> bool {
    let b = base();
    gpa >= b && gpa < b + AHCI_ABAR_SIZE
}

static HOST_RAM_BASE: AtomicU64 = AtomicU64::new(0);

pub fn set_host_ram_base(b: u64) {
    HOST_RAM_BASE.store(b, Ordering::Release);
}

#[inline]
fn g2h(gpa: u64) -> *mut u8 {
    crate::guest_mem::to_host_ptr(gpa)
}

#[inline]
fn make_addr(lo: u32, hi: u32) -> u64 {
    ((hi as u64) << 32) | lo as u64
}

// 2048-aligned staging buffer for media reads (CD io_align), scattered
// byte-granular into the command's PRDT afterwards. The guest serialises
// I/O on one port, so a single shared buffer is safe.
const STAGE_BYTES: usize = 0x10_0000; // 1 MiB — fewer host ATAPI commands per large read
#[repr(align(4096))]
struct Stage([u8; STAGE_BYTES]);
static mut AHCI_STAGE: Stage = Stage([0u8; STAGE_BYTES]);
#[inline]
fn stage_ptr() -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!(AHCI_STAGE.0) as *mut u8 }
}

// ───── HBA generic registers ─────────────────────────────────────────
// CAP: S64A=1, SAM=1 (AHCI-only), ISS=2 (3 Gb/s), NCS=31 (32 slots), NP=0.
const HBA_CAP: u32 = (1 << 31) | (1 << 18) | (2 << 20) | (31 << 8);
const HBA_PI: u32 = 0x1; // port 0 implemented
const HBA_VS: u32 = 0x0001_0301; // AHCI 1.3.1

static GHC: AtomicU32 = AtomicU32::new(0x8000_0000); // AE set
static HBA_IS: AtomicU32 = AtomicU32::new(0);

// ───── Port 0 registers ──────────────────────────────────────────────
const PORT0_OFF: u32 = 0x100;
const SIG_ATAPI: u32 = 0xEB14_0101;
const SSTS_PRESENT: u32 = 0x0123; // DET=3, SPD=2, IPM=1
const TFD_IDLE: u32 = 0x0000_0050; // DRDY|DSC, no BSY/DRQ/ERR

static P_CLB: AtomicU32 = AtomicU32::new(0);
static P_CLBU: AtomicU32 = AtomicU32::new(0);
static P_FB: AtomicU32 = AtomicU32::new(0);
static P_FBU: AtomicU32 = AtomicU32::new(0);
static P_IS: AtomicU32 = AtomicU32::new(0);
static P_IE: AtomicU32 = AtomicU32::new(0);
static P_CMD: AtomicU32 = AtomicU32::new(0);
static P_TFD: AtomicU32 = AtomicU32::new(TFD_IDLE);
static P_SCTL: AtomicU32 = AtomicU32::new(0);
static P_SERR: AtomicU32 = AtomicU32::new(0);
static P_SACT: AtomicU32 = AtomicU32::new(0);
static P_CI: AtomicU32 = AtomicU32::new(0);

// MSI delivery. Real AHCI controllers signal command completion with an
// interrupt; OVMF's pass-through driver polled PxCI so it never mattered,
// but Linux's libata is interrupt-driven and times out commands without
// it (and INTx can't be routed here — no ACPI _PRT). The MSI vector is
// pushed in from the PCI config-space emulator when the guest programs the
// device's MSI capability (same direction as `set_base`, so storage never
// has to depend back on the pci module). 0 = MSI disabled.
static MSI_VECTOR: AtomicU32 = AtomicU32::new(0);
const IRQ_NONE: u32 = 0xFFFF_FFFF;
static IRQ_PENDING: AtomicU32 = AtomicU32::new(IRQ_NONE);

/// Set (or clear) the AHCI completion-interrupt vector. `enabled` reflects
/// the MSI Enable bit; a disabled or sub-16 vector parks delivery.
pub fn set_msi(vector: u32, enabled: bool) {
    MSI_VECTOR.store(if enabled && vector >= 16 { vector } else { 0 }, Ordering::Relaxed);
}

/// Consume the pending completion vector (called by intercept/inject.rs).
pub fn pending_irq() -> Option<u8> {
    let v = IRQ_PENDING.swap(IRQ_NONE, Ordering::AcqRel);
    if v == IRQ_NONE { None } else { Some(v as u8) }
}

/// Raise the completion interrupt if the guest armed AHCI interrupts
/// (GHC.IE) and the port's enabled status bits (PxIE & PxIS) are live.
fn raise_completion_irq() {
    // HBA_IS (global interrupt status) is computed live on read from
    // (PxIS & PxIE), so there is nothing to latch here. This function only
    // delivers an *actual* interrupt, which the guest gates with GHC.IE.
    if P_IS.load(Ordering::Relaxed) & P_IE.load(Ordering::Relaxed) == 0 {
        return; // no enabled port interrupt source asserted
    }
    if GHC.load(Ordering::Relaxed) & (1 << 1) != 0 {
        let v = MSI_VECTOR.load(Ordering::Relaxed);
        if v >= 16 {
            IRQ_PENDING.store(v, Ordering::Relaxed);
        }
    }
}

static AHCI_TRACE: AtomicU32 = AtomicU32::new(0);
const AHCI_TRACE_CAP: u32 = 100;
static AHCI_CI_TRACE: AtomicU32 = AtomicU32::new(0);
static PORT_STARTS: AtomicU32 = AtomicU32::new(0);
static AHCI_PXCMD_TRACE: AtomicU32 = AtomicU32::new(0);
static SCSI_PROGRESS: AtomicU32 = AtomicU32::new(0);
static MEDIA_READ_CALLS: AtomicU32 = AtomicU32::new(0);
static MEDIA_READ_CYCLES: AtomicU64 = AtomicU64::new(0);

#[inline]
fn host_rdtsc_ahci() -> u64 {
    let lo: u32; let hi: u32;
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)); }
    ((hi as u64) << 32) | (lo as u64)
}
static MEDIA_READS: AtomicU32 = AtomicU32::new(0);
static MEDIA_MIB: AtomicU64 = AtomicU64::new(0);

#[inline]
fn low_mask(width: u8) -> u64 {
    match width {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        _ => u64::MAX,
    }
}

fn read_dword(off: u32) -> u32 {
    match off {
        0x00 => HBA_CAP,
        0x04 => GHC.load(Ordering::Relaxed),
        // Global interrupt status: bit N is set when port N has a pending
        // *enabled* interrupt, i.e. (PxIS & PxIE) != 0 (AHCI 1.3.1 §3.1.1).
        // Computed live and INDEPENDENT of GHC.IE — GHC.IE only gates whether
        // an actual interrupt is generated, not this status. A polling driver
        // (GHC.IE=0) reads HBA_IS to discover which port completed; if it
        // always read 0 (the old bug: HBA_IS was only set inside
        // raise_completion_irq when GHC.IE was set) the driver never sees the
        // completion and spins resetting the port forever.
        0x08 => {
            // Global IS reflects (PxIS & PxIE) per port, independent of GHC.IE
            // (AHCI 1.3.1 §3.1.1). Spec-correct; not the boot blocker (OVMF
            // here runs with PxIE=0 and clears PxIS itself).
            if P_IS.load(Ordering::Relaxed) & P_IE.load(Ordering::Relaxed) != 0 {
                HBA_PI
            } else {
                0
            }
        }
        0x0C => HBA_PI,
        0x10 => HBA_VS,
        o if (PORT0_OFF..PORT0_OFF + 0x80).contains(&o) => port_read(o - PORT0_OFF),
        _ => 0,
    }
}

fn port_read(po: u32) -> u32 {
    match po {
        0x00 => P_CLB.load(Ordering::Relaxed),
        0x04 => P_CLBU.load(Ordering::Relaxed),
        0x08 => P_FB.load(Ordering::Relaxed),
        0x0C => P_FBU.load(Ordering::Relaxed),
        0x10 => P_IS.load(Ordering::Relaxed),
        0x14 => P_IE.load(Ordering::Relaxed),
        0x18 => P_CMD.load(Ordering::Relaxed),
        0x20 => P_TFD.load(Ordering::Relaxed),
        0x24 => if super::media_ready() { SIG_ATAPI } else { 0xFFFF_FFFF },
        0x28 => if super::media_ready() { SSTS_PRESENT } else { 0 },
        0x2C => P_SCTL.load(Ordering::Relaxed),
        0x30 => P_SERR.load(Ordering::Relaxed),
        0x34 => P_SACT.load(Ordering::Relaxed),
        0x38 => P_CI.load(Ordering::Relaxed),
        _ => 0,
    }
}

pub fn read_register_width(off: u32, width: u8) -> u64 {
    let aligned = off & !0x3;
    let shift = (off & 0x3) * 8;
    ((read_dword(aligned) as u64) >> shift) & low_mask(width)
}

pub fn write_register_width(off: u32, val: u64, width: u8) {
    let aligned = off & !0x3;
    let shift = (off & 0x3) * 8;
    let mask = (low_mask(width) as u32).wrapping_shl(shift);
    let v = ((val & low_mask(width)) as u32).wrapping_shl(shift);
    match aligned {
        0x04 => {
            let p = GHC.load(Ordering::Relaxed);
            // HR (bit 0, HBA reset) self-clears once the reset completes —
            // the driver polls it back to 0. AE/IE persist.
            GHC.store(((p & !mask) | v) & !0x1, Ordering::Relaxed);
        }
        0x08 => {
            let p = HBA_IS.load(Ordering::Relaxed);
            HBA_IS.store(p & !v, Ordering::Relaxed); // W1C
        }
        o if (PORT0_OFF..PORT0_OFF + 0x80).contains(&o) => port_write(o - PORT0_OFF, v, mask),
        _ => {}
    }
}

fn port_write(po: u32, v: u32, mask: u32) {
    let merge = |slot: &AtomicU32| {
        let p = slot.load(Ordering::Relaxed);
        slot.store((p & !mask) | v, Ordering::Relaxed);
    };
    match po {
        0x00 => merge(&P_CLB),
        0x04 => merge(&P_CLBU),
        0x08 => merge(&P_FB),
        0x0C => merge(&P_FBU),
        0x10 => {
            let p = P_IS.load(Ordering::Relaxed);
            P_IS.store(p & !v, Ordering::Relaxed); // W1C
        }
        0x14 => merge(&P_IE),
        0x18 => {
            let prev = P_CMD.load(Ordering::Relaxed);
            merge(&P_CMD);
            reflect_cmd();
            let now = P_CMD.load(Ordering::Relaxed);
            // Diagnostic: count ST(bit0) 0->1 starts. The spin is a port
            // start/stop retry loop; once we're deep in it, reset the scsi
            // trace so the LOOP's commands (not the boot.wim-load reads that
            // exhausted the cap) become visible.
            if prev & 1 == 0 && now & 1 != 0 {
                let s = PORT_STARTS.fetch_add(1, Ordering::Relaxed);
                if s == 60 {
                    AHCI_TRACE.store(0, Ordering::Relaxed);
                    crate::sprintln!("[ahci] --- retry-loop trace window (scsi re-enabled) ---");
                }
            }
            let t = AHCI_PXCMD_TRACE.fetch_add(1, Ordering::Relaxed);
            if (t < 16 || (PORT_STARTS.load(Ordering::Relaxed) >= 60 && t % 64 == 0)) && (prev ^ now) & 0x11 != 0 {
                crate::sprintln!("[ahci] PxCMD wr=0x{:X} {:#X}->{:#X} ST={} CR={} FRE={} FR={}",
                    v, prev, now, now & 1, (now >> 15) & 1, (now >> 4) & 1, (now >> 14) & 1);
            }
        }
        0x2C => merge(&P_SCTL),
        0x30 => {
            let p = P_SERR.load(Ordering::Relaxed);
            P_SERR.store(p & !v, Ordering::Relaxed); // W1C
        }
        0x34 => merge(&P_SACT),
        0x38 => {
            merge(&P_CI);
            let ci = P_CI.load(Ordering::Relaxed);
            // Diagnostic: a command issued while the engine is stopped (ST=0)
            // can never run on real HW — flag it (first few only).
            let cmd = P_CMD.load(Ordering::Relaxed);
            if ci != 0 && cmd & 1 == 0 {
                let t = AHCI_CI_TRACE.fetch_add(1, Ordering::Relaxed);
                if t < 12 {
                    crate::sprintln!("[ahci] PxCI=0x{:X} issued with ST=0 (engine stopped) PxCMD=0x{:X}", ci, cmd);
                }
            }
            process_commands(ci);
        }
        _ => {}
    }
}

/// FR mirrors FRE (bit 4 → bit 14), CR mirrors ST (bit 0 → bit 15).
fn reflect_cmd() {
    let mut c = P_CMD.load(Ordering::Relaxed);
    if c & (1 << 4) != 0 { c |= 1 << 14; } else { c &= !(1 << 14); }
    if c & (1 << 0) != 0 { c |= 1 << 15; } else { c &= !(1 << 15); }
    P_CMD.store(c, Ordering::Relaxed);
}

fn process_commands(ci: u32) {
    let mut had_error = false;
    for slot in 0..32u32 {
        if ci & (1 << slot) == 0 {
            continue;
        }
        process_slot(slot);
        if CHECK_CONDITION.load(Ordering::Relaxed) {
            had_error = true;
        }
        let p = P_CI.load(Ordering::Relaxed);
        P_CI.store(p & !(1 << slot), Ordering::Relaxed); // completion
    }
    // Interrupt status (AHCI 1.3.1 §3.3.5). A D2H Register FIS receipt raises
    // DHRS (bit 0). We deliberately do NOT raise TFES (bit 30) on an ATAPI
    // CHECK CONDITION: the sense is already conveyed via PxTFD.ERR + the D2H
    // FIS ERR status byte (0x51), which the ATAPI driver reads to issue
    // REQUEST SENSE and retry — the normal, working path. Setting TFES instead
    // drives OVMF into full AHCI port error recovery (PxCMD.ST→CR clear, PxSERR
    // dance, restart) that our inline-completion model doesn't satisfy, which
    // loops the boot forever. [regression fix 2026-05-31: TFES was added this
    // session and broke ATAPI UNIT-ATTENTION recovery.]
    let _ = had_error;
    P_IS.fetch_or(0x1, Ordering::Relaxed); // DHRS only
    raise_completion_irq();
}

fn process_slot(slot: u32) {
    let clb = make_addr(P_CLB.load(Ordering::Relaxed), P_CLBU.load(Ordering::Relaxed));
    let hdr = g2h(clb + (slot as u64) * 0x20);
    if hdr.is_null() {
        return;
    }
    let mut h = [0u8; 0x20];
    unsafe { core::ptr::copy_nonoverlapping(hdr as *const u8, h.as_mut_ptr(), 0x20); }
    let dw0 = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
    let prdtl = (dw0 >> 16) & 0xFFFF;
    let ctba = make_addr(
        u32::from_le_bytes([h[8], h[9], h[10], h[11]]),
        u32::from_le_bytes([h[12], h[13], h[14], h[15]]),
    );
    let ct = g2h(ctba);
    if ct.is_null() {
        return;
    }
    // CFIS (command FIS) at offset 0x00; byte 2 = the ATA command. ATAPI
    // devices answer IDENTIFY PACKET DEVICE (0xA1) before any PACKET (0xA0)
    // SCSI traffic — without it the driver never recognises the CD-ROM.
    let cmd = unsafe { *(ct as *const u8).add(2) };
    let written = match cmd {
        0xA0 => {
            let mut cdb = [0u8; 16];
            unsafe { core::ptr::copy_nonoverlapping((ct as *const u8).add(0x40), cdb.as_mut_ptr(), 16); }
            handle_scsi(&cdb, ctba, prdtl)
        }
        0xA1 => build_identify_packet(ctba, prdtl),
        _ => 0,
    };

    {
        let t = AHCI_TRACE.fetch_add(1, Ordering::Relaxed);
        if t < AHCI_TRACE_CAP {
            crate::sprintln!("[ahci] slot={} cmd=0x{:02X} prdtl={} written={}", slot, cmd, prdtl, written);
        }
    }

    // command header DW1 = PRDBC (bytes transferred)
    unsafe {
        let prdbc = (hdr as *mut u8).add(4) as *mut u32;
        core::ptr::write_unaligned(prdbc, written);
    }
    if CHECK_CONDITION.load(Ordering::Relaxed) {
        // ATAPI error register: sense key in bits 7:4. Status DRDY|DSC|ERR.
        let err = (SENSE_KEY.load(Ordering::Relaxed) << 4) | 0x04;
        P_TFD.store(((err as u32) << 8) | 0x51, Ordering::Relaxed);
        post_d2h_fis(0x51, err);
    } else {
        P_TFD.store(TFD_IDLE, Ordering::Relaxed);
        post_d2h_fis(0x50, 0);
    }
}

fn post_d2h_fis(status: u8, error: u8) {
    let fb = make_addr(P_FB.load(Ordering::Relaxed), P_FBU.load(Ordering::Relaxed));
    let dst = g2h(fb + 0x40); // D2H Register FIS area within the FIS receive block
    if dst.is_null() {
        return;
    }
    let mut fis = [0u8; 20];
    fis[0] = 0x34;       // FIS type: D2H Register
    fis[2] = status;     // status (0x50 good, 0x51 = +ERR)
    fis[3] = error;      // error register (sense key in bits 7:4 on CHECK CONDITION)
    unsafe { core::ptr::copy_nonoverlapping(fis.as_ptr(), dst, 20); }
}

// ───── ATA IDENTIFY PACKET DEVICE (0xA1) ─────────────────────────────

/// Write an ATA identify string: space-padded, byte-swapped within each
/// 16-bit word (ATA stores "ASUS" as "SA US…").
fn put_ata_str(buf: &mut [u8], off: usize, s: &[u8], len: usize) {
    for i in 0..len {
        let c = if i < s.len() { s[i] } else { b' ' };
        buf[off + (i ^ 1)] = c; // swap adjacent bytes within the word
    }
}

fn build_identify_packet(ctba: u64, prdtl: u32) -> u32 {
    let mut id = [0u8; 512];
    // Word 0: ATAPI device (bits 15:14 = 10b), CD-ROM (bits 12:8 = 0x05),
    // removable (bit 7), 12-byte command packet (bits 1:0 = 0).
    id[0..2].copy_from_slice(&0x85C0u16.to_le_bytes());
    // Serial number (words 10-19, 20 bytes). This models an optical drive,
    // a distinct device from the NVMe system disk, so it does NOT reuse the
    // disk profile's serial. The previous value "VNR0000000000001" was a
    // veneer watermark (the "VNR" prefix fingerprinted the hypervisor); it
    // is replaced with a realistic ASUS-style optical-drive serial.
    put_ata_str(&mut id, 20, b"K1D0BL12345", 20);
    // Firmware revision (words 23-26, 8 bytes).
    put_ata_str(&mut id, 46, b"1.00", 8);
    // Model number (words 27-46, 40 bytes). Realistic retail optical drive.
    put_ata_str(&mut id, 54, b"ASUS DVD-ROM DRW-24D5MT", 40);
    // Word 49 capabilities: LBA (bit 9) + DMA (bit 8) + IORDY (bit 11).
    id[98..100].copy_from_slice(&0x0F00u16.to_le_bytes());
    // Word 53: words 64-70 / 88 valid.
    id[106..108].copy_from_slice(&0x0006u16.to_le_bytes());
    prdt_write(ctba, prdtl, &id)
}

// ───── ATAPI / SCSI ──────────────────────────────────────────────────

fn be16(b: &[u8]) -> u32 {
    ((b[0] as u32) << 8) | b[1] as u32
}
fn be32(b: &[u8]) -> u64 {
    ((b[0] as u64) << 24) | ((b[1] as u64) << 16) | ((b[2] as u64) << 8) | b[3] as u64
}

fn handle_scsi(cdb: &[u8; 16], ctba: u64, prdtl: u32) -> u32 {
    {
        let t = AHCI_TRACE.fetch_add(1, Ordering::Relaxed);
        if t < AHCI_TRACE_CAP {
            crate::sprintln!("[ahci] scsi op=0x{:02X} lba={} len={} prdtl={}",
                cdb[0], be32(&cdb[2..6]), be16(&cdb[7..9]), prdtl);
        }
    }
    // Uncapped progress probe: every 256 SCSI commands, log the running count
    // + current op/lba so a long run reveals slow-but-progressing (lba climbs)
    // vs a true remount loop (lba bounded/repeating). Keeps the serial growing
    // so the watchdog doesn't false-trip on the slow per-command phase.
    {
        let p = SCSI_PROGRESS.fetch_add(1, Ordering::Relaxed);
        if p % 256 == 0 {
            crate::sprintln!("[ahci] scsi-progress #{} op=0x{:02X} lba={}",
                p, cdb[0], be32(&cdb[2..6]));
        }
    }
    // UNIT ATTENTION: report the pending condition (CHECK CONDITION) on the
    // first command that isn't INQUIRY/REQUEST SENSE, then let the driver
    // clear it via REQUEST SENSE. Until then, don't execute the command.
    if SENSE_KEY.load(Ordering::Relaxed) != 0 && cdb[0] != 0x12 && cdb[0] != 0x03 {
        CHECK_CONDITION.store(true, Ordering::Relaxed);
        return 0;
    }
    CHECK_CONDITION.store(false, Ordering::Relaxed);
    match cdb[0] {
        0x00 => 0, // TEST UNIT READY → good status, no data
        0x03 => {
            // REQUEST SENSE: fixed-format sense buffer, then clear the
            // pending condition so subsequent commands run normally.
            let mut d = [0u8; 18];
            d[0] = 0x70; // response code: current error, info valid
            d[2] = SENSE_KEY.load(Ordering::Relaxed) & 0x0F; // sense key
            d[7] = 10; // additional sense length (18 - 8)
            d[12] = SENSE_ASC.load(Ordering::Relaxed);
            d[13] = SENSE_ASCQ.load(Ordering::Relaxed);
            set_sense(0, 0, 0); // condition cleared
            let want = if cdb[4] == 0 { 18 } else { (cdb[4] as usize).min(18) };
            prdt_write(ctba, prdtl, &d[..want])
        }
        0x12 => {
            // INQUIRY — present a plausible optical drive. TODO: profile.
            let mut d = [0u8; 96];
            d[0] = 0x05; // peripheral device type = CD/DVD
            d[1] = 0x80; // RMB (removable)
            d[2] = 0x00; // ANSI version
            d[3] = 0x21; // HiSup + response data format 2
            d[4] = 91; // additional length
            d[8..16].copy_from_slice(b"ASUS    ");
            d[16..32].copy_from_slice(b"DRW-24D5MT      ");
            d[32..36].copy_from_slice(b"1.00");
            let want = if cdb[4] == 0 { 96 } else { (cdb[4] as usize).min(96) };
            prdt_write(ctba, prdtl, &d[..want])
        }
        0x25 => {
            // READ CAPACITY(10): last LBA + block size (2048), big-endian.
            let last = super::media_block_count().saturating_sub(1) as u32;
            let bs = super::media_block_size();
            let mut d = [0u8; 8];
            d[0..4].copy_from_slice(&last.to_be_bytes());
            d[4..8].copy_from_slice(&bs.to_be_bytes());
            prdt_write(ctba, prdtl, &d)
        }
        0x28 => {
            // READ(10): LBA (bytes 2-5 BE), length (bytes 7-8 BE).
            let lba = be32(&cdb[2..6]);
            let blocks = be16(&cdb[7..9]);
            atapi_read(ctba, prdtl, lba, blocks)
        }
        0xA8 => {
            // READ(12): LBA (2-5 BE), length (6-9 BE).
            let lba = be32(&cdb[2..6]);
            let blocks = be32(&cdb[6..10]) as u32;
            atapi_read(ctba, prdtl, lba, blocks)
        }
        0x1B => 0, // START STOP UNIT
        0x1E => 0, // PREVENT/ALLOW MEDIUM REMOVAL
        0x35 => 0, // SYNCHRONIZE CACHE
        0x1A | 0x5A => {
            // MODE SENSE(6/10): minimal header, no pages.
            let d = [0u8; 8];
            prdt_write(ctba, prdtl, &d[..if cdb[0] == 0x1A { 4 } else { 8 }])
        }
        0x46 => {
            // GET CONFIGURATION: minimal feature header (current profile = CD-ROM 0x0008).
            let mut d = [0u8; 12];
            d[3] = 8; // data length
            d[6] = 0x00;
            d[7] = 0x08; // current profile: CD-ROM
            prdt_write(ctba, prdtl, &d)
        }
        0x4A => {
            // GET EVENT STATUS NOTIFICATION: no events.
            let mut d = [0u8; 8];
            d[1] = 6; // event data length
            d[2] = 0x00; // NEA=0, no event
            d[3] = 0x04; // supported event class
            prdt_write(ctba, prdtl, &d)
        }
        0x43 => {
            // READ TOC: minimal single-track TOC.
            let mut d = [0u8; 20];
            d[1] = 18; // toc data length
            d[2] = 1; // first track
            d[3] = 1; // last track
            prdt_write(ctba, prdtl, &d)
        }
        _ => 0, // unhandled → good status, no data (lenient)
    }
}

/// Scatter `data` across the command's PRDT entries; returns bytes written.
fn prdt_write(ctba: u64, prdtl: u32, data: &[u8]) -> u32 {
    let mut off = 0usize;
    for i in 0..prdtl as usize {
        if off >= data.len() {
            break;
        }
        let e = g2h(ctba + 0x80 + (i as u64) * 16);
        if e.is_null() {
            break;
        }
        let mut entry = [0u8; 16];
        unsafe { core::ptr::copy_nonoverlapping(e as *const u8, entry.as_mut_ptr(), 16); }
        let dba = make_addr(
            u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]),
            u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]),
        );
        let dbc = (u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) & 0x3F_FFFF) as usize + 1;
        let dst = g2h(dba);
        if dst.is_null() {
            break;
        }
        let n = core::cmp::min(dbc, data.len() - off);
        unsafe { core::ptr::copy_nonoverlapping(data[off..].as_ptr(), dst, n); }
        off += n;
    }
    off as u32
}

/// Stream a READ(10/12): pull whole media blocks into the staging buffer
/// and scatter bytes across the PRDT (media LBA size and PRD byte counts
/// need not align). Returns total bytes written.
fn atapi_read(ctba: u64, prdtl: u32, lba: u64, blocks: u32) -> u32 {
    if !super::media_ready() || blocks == 0 {
        return 0;
    }
    let bs = super::media_block_size() as u64;
    if bs == 0 {
        return 0;
    }
    let total = blocks as u64 * bs;
    let mut cur_lba = lba;
    let mut disk_left = total;
    let mut filled = 0usize; // valid bytes in stage
    let mut pos = 0usize; // consumed bytes in stage
    let mut written = 0usize;

    for i in 0..prdtl as usize {
        let e = g2h(ctba + 0x80 + (i as u64) * 16);
        if e.is_null() {
            break;
        }
        let mut entry = [0u8; 16];
        unsafe { core::ptr::copy_nonoverlapping(e as *const u8, entry.as_mut_ptr(), 16); }
        let dba = make_addr(
            u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]),
            u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]),
        );
        let dbc = (u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) & 0x3F_FFFF) as usize + 1;
        let dst = g2h(dba);
        if dst.is_null() {
            break;
        }
        let mut done = 0usize;
        while done < dbc {
            if pos == filled {
                let want = core::cmp::min(disk_left, STAGE_BYTES as u64);
                if want == 0 {
                    return written as u32;
                }
                let bl = (want / bs) as u32;
                // Measure host BlockIO read latency: if single-block ATAPI
                // reads (len=1) each incur a high-latency host read with no
                // read-ahead, that's the per-command slowness. host_rdtsc delta
                // is raw cycles (~host TSC freq); log slow reads + a running sum.
                let t0 = host_rdtsc_ahci();
                let ok = super::media_read(cur_lba, bl, stage_ptr());
                let dt = host_rdtsc_ahci().wrapping_sub(t0);
                {
                    let c = MEDIA_READ_CALLS.fetch_add(1, Ordering::Relaxed);
                    MEDIA_READ_CYCLES.fetch_add(dt, Ordering::Relaxed);
                    if c % 128 == 0 {
                        let sum = MEDIA_READ_CYCLES.load(Ordering::Relaxed);
                        crate::sprintln!("[ahci] media_read #{} bl={} this_dt=0x{:X}cyc sum=0x{:X}cyc", c, bl, dt, sum);
                    }
                }
                if !ok {
                    crate::sprintln!("[ahci] media_read FAILED lba={} bl={}", cur_lba, bl);
                    return written as u32;
                }
                // Coarse progress so a multi-hundred-MB boot.wim load keeps the
                // serial log growing (else the watchdog calls a long-but-live
                // load a hang). One line per ~32 MiB transferred.
                let n = MEDIA_READS.fetch_add(1, Ordering::Relaxed);
                let mb = (MEDIA_MIB.fetch_add(bl as u64 * bs, Ordering::Relaxed)
                    + bl as u64 * bs)
                    >> 20;
                // Disarm the auto-keypress only once a LARGE amount has been
                // read from the CD — that is the OS boot payload (bootmgr +
                // boot.wim / PE, hundreds of MB) loading, which only happens
                // AFTER the keypress dismissed cdboot's "press any key" prompt.
                // The El Torito / filesystem probe and cdboot.efi itself are a
                // few MB at most, so this keeps the keypress armed THROUGH the
                // prompt (disarming on probe-read had cdboot fall back to the
                // menu) yet stops stray Enters before the interactive installer.
                // OS-agnostic: any bootable medium streams its payload here.
                if mb >= 32 {
                    crate::hardware::devices::i8042::disarm_auto_key();
                }
                if n % 64 == 0 {
                    crate::sprintln!("[ahci] cd-load lba={} ~{}MiB read#{}", cur_lba, mb, n);
                }
                cur_lba += bl as u64;
                disk_left -= want;
                filled = want as usize;
                pos = 0;
            }
            let n = core::cmp::min(dbc - done, filled - pos);
            unsafe {
                core::ptr::copy_nonoverlapping((stage_ptr() as *const u8).add(pos), dst.add(done), n);
            }
            done += n;
            pos += n;
            written += n;
        }
    }
    written as u32
}
