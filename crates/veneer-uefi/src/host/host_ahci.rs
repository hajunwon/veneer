//! Polling driver for the VM's *real* SATA AHCI controller.
//!
//! veneer drives the host SATA controller directly instead of borrowing
//! the host firmware's BlockIo — that BlockIo stalls inside the VMEXIT
//! timer context (`gBS->Stall` never returns). We issue commands and
//! busy-poll PxCI to completion (no interrupts, no timer), the way SeaBIOS
//! does in BIOS context. This is the mirror of our guest-side ahci.rs
//! emulator: there we answered an AHCI driver, here we *are* one.
//!
//! Reference: SeaBIOS src/hw/ahci.c (polling), EDK2 AtaAtapiPassThru.

use core::ptr::{addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};


static ABAR: AtomicU64 = AtomicU64::new(0);
// Port number + 1 (0 = none) for the ATAPI CD and the SATA disk.
static MEDIA_PORT: AtomicU32 = AtomicU32::new(0);
static TARGET_PORT: AtomicU32 = AtomicU32::new(0);

const SIG_ATAPI: u32 = 0xEB14_0101;
const SIG_ATA: u32 = 0x0000_0101;

// Port register offsets (relative to abar + 0x100 + port*0x80).
const PX_CLB: u64 = 0x00;
const PX_FB: u64 = 0x08;
const PX_IS: u64 = 0x10;
const PX_CMD: u64 = 0x18;
const PX_TFD: u64 = 0x20;
const PX_SIG: u64 = 0x24;
const PX_SSTS: u64 = 0x28;
const PX_SERR: u64 = 0x30;
const PX_CI: u64 = 0x38;

// PxCMD bits.
const CMD_ST: u32 = 1 << 0;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;

// Driver-owned command list / FIS-receive / command-table buffers. One
// transfer at a time (the guest serialises I/O), so a single shared set is
// enough; we point the active port's PxCLB/PxFB at it per command.
#[repr(C, align(1024))]
struct AhciBufs {
    list: [u8; 1024], // command list (32 slots × 32 B)
    fis: [u8; 256],   // FIS receive area
    ctab: [u8; 768],  // command table: CFIS(64) + ACMD(16) + PRDT
}
static mut BUFS: AhciBufs = AhciBufs { list: [0; 1024], fis: [0; 256], ctab: [0; 768] };

#[inline]
fn rd(a: u64) -> u32 {
    unsafe { read_volatile(a as *const u32) }
}
#[inline]
fn wr(a: u64, v: u32) {
    unsafe { write_volatile(a as *mut u32, v) }
}

fn port_base(port: u64) -> u64 {
    ABAR.load(Ordering::Relaxed) + 0x100 + port * 0x80
}

/// Enumerate the HBA ports and bind the ATAPI CD + SATA disk.
pub fn init(abar: u64) {
    if abar == 0 {
        return;
    }
    ABAR.store(abar, Ordering::Relaxed);
    let cap = rd(abar + 0x00);
    let pi = rd(abar + 0x0C);
    sprintln!("[hahci] init ABAR=0x{:X} CAP=0x{:08X} PI=0x{:X}", abar, cap, pi);
    for port in 0..32u64 {
        if pi & (1 << port) == 0 {
            continue;
        }
        let pb = abar + 0x100 + port * 0x80;
        let ssts = rd(pb + PX_SSTS);
        if ssts & 0xF != 3 {
            continue; // DET != 3: no device / no PHY comm
        }
        let sig = rd(pb + PX_SIG);
        if sig == SIG_ATAPI {
            MEDIA_PORT.store(port as u32 + 1, Ordering::Relaxed);
            sprintln!("[hahci] ATAPI CD-ROM at port {}", port);
        } else if sig == SIG_ATA {
            TARGET_PORT.store(port as u32 + 1, Ordering::Relaxed);
            sprintln!("[hahci] SATA disk at port {}", port);
        } else {
            sprintln!("[hahci] port {} unknown SIG=0x{:08X}", port, sig);
        }
    }
}

pub fn media_present() -> bool {
    MEDIA_PORT.load(Ordering::Relaxed) != 0
}

fn port_stop(pb: u64) {
    wr(pb + PX_CMD, rd(pb + PX_CMD) & !CMD_ST);
    let mut spins = 0u32;
    while rd(pb + PX_CMD) & CMD_CR != 0 {
        spins += 1;
        if spins > 2_000_000 {
            break;
        }
    }
    wr(pb + PX_CMD, rd(pb + PX_CMD) & !CMD_FRE);
}

fn port_start(pb: u64) {
    let mut spins = 0u32;
    while rd(pb + PX_CMD) & CMD_CR != 0 {
        spins += 1;
        if spins > 2_000_000 {
            break;
        }
    }
    wr(pb + PX_CMD, rd(pb + PX_CMD) | CMD_FRE);
    wr(pb + PX_CMD, rd(pb + PX_CMD) | CMD_ST);
}

/// Issue an ATAPI PACKET command (DMA) with `cdb` and read `len` bytes into
/// `dest`. Busy-polls PxCI to completion. Returns false on error/timeout.
fn issue_atapi(port: u64, cdb: &[u8; 16], dest: *mut u8, len: u32) -> bool {
    let pb = port_base(port);
    port_stop(pb);

    let (list, fis, ctab) = unsafe {
        (
            addr_of_mut!(BUFS.list) as u64,
            addr_of_mut!(BUFS.fis) as u64,
            addr_of_mut!(BUFS.ctab) as u64,
        )
    };

    wr(pb + PX_CLB, list as u32);
    wr(pb + PX_CLB + 4, (list >> 32) as u32);
    wr(pb + PX_FB, fis as u32);
    wr(pb + PX_FB + 4, (fis >> 32) as u32);
    wr(pb + PX_SERR, 0xFFFF_FFFF);
    wr(pb + PX_IS, 0xFFFF_FFFF);

    port_start(pb);

    unsafe {
        let ct = ctab as *mut u8;
        core::ptr::write_bytes(ct, 0, 768);
        // CFIS — H2D Register FIS, ATAPI PACKET.
        *ct.add(0) = 0x27; // FIS type H2D
        *ct.add(1) = 0x80; // C bit (command)
        *ct.add(2) = 0xA0; // ATA_CMD_PACKET
        *ct.add(3) = 0x01; // features: DMA
        *ct.add(5) = (len & 0xFF) as u8; // byte-count low (lba_mid)
        *ct.add(6) = ((len >> 8) & 0xFF) as u8; // byte-count high (lba_high)
        // ACMD — 16-byte ATAPI CDB at offset 0x40.
        core::ptr::copy_nonoverlapping(cdb.as_ptr(), ct.add(0x40), 16);
        // PRDT[0] at offset 0x80: DBA / DBAU / rsv / DBC(byte count-1).
        let prdt = ct.add(0x80);
        let b = dest as u64;
        write_volatile(prdt as *mut u32, b as u32);
        write_volatile(prdt.add(4) as *mut u32, (b >> 32) as u32);
        write_volatile(prdt.add(12) as *mut u32, (len - 1) & 0x003F_FFFF);

        // Command list slot 0.
        let l = list as *mut u32;
        // PRDTL=1 | ATAPI(bit5) | CFL=5 dwords.
        write_volatile(l, (1u32 << 16) | (1 << 5) | 5);
        write_volatile(l.add(1), 0); // PRDBC
        write_volatile(l.add(2), ctab as u32); // CTBA
        write_volatile(l.add(3), (ctab >> 32) as u32);
    }

    wr(pb + PX_CI, 1); // issue slot 0

    let mut spins = 0u64;
    loop {
        if rd(pb + PX_CI) & 1 == 0 {
            break; // command consumed
        }
        let tfd = rd(pb + PX_TFD);
        if tfd & 0x01 != 0 {
            return false; // ERR in task file status
        }
        spins += 1;
        if spins > 200_000_000 {
            sprintln!("[hahci] ATAPI timeout port={} tfd=0x{:X}", port, rd(pb + PX_TFD));
            return false;
        }
    }
    rd(pb + PX_TFD) & 0x01 == 0
}

/// Issue an ATA READ/WRITE DMA EXT (LBA48) to a SATA port and busy-poll
/// PxCI to completion. Same command-table layout as `issue_atapi` minus the
/// ATAPI bit; the W bit in the slot header distinguishes write from read.
fn issue_ata(port: u64, write: bool, lba: u64, blocks: u16, buf: *mut u8, len: u32) -> bool {
    let pb = port_base(port);
    port_stop(pb);

    let (list, fis, ctab) = unsafe {
        (
            addr_of_mut!(BUFS.list) as u64,
            addr_of_mut!(BUFS.fis) as u64,
            addr_of_mut!(BUFS.ctab) as u64,
        )
    };

    wr(pb + PX_CLB, list as u32);
    wr(pb + PX_CLB + 4, (list >> 32) as u32);
    wr(pb + PX_FB, fis as u32);
    wr(pb + PX_FB + 4, (fis >> 32) as u32);
    wr(pb + PX_SERR, 0xFFFF_FFFF);
    wr(pb + PX_IS, 0xFFFF_FFFF);

    port_start(pb);

    unsafe {
        let ct = ctab as *mut u8;
        core::ptr::write_bytes(ct, 0, 768);
        // CFIS — H2D Register FIS, ATA READ/WRITE DMA EXT (48-bit LBA).
        *ct.add(0) = 0x27; // FIS type H2D
        *ct.add(1) = 0x80; // C bit (command)
        *ct.add(2) = if write { 0x35 } else { 0x25 }; // WRITE/READ DMA EXT
        *ct.add(4) = lba as u8; // LBA[7:0]
        *ct.add(5) = (lba >> 8) as u8; // LBA[15:8]
        *ct.add(6) = (lba >> 16) as u8; // LBA[23:16]
        *ct.add(7) = 0x40; // device: LBA mode
        *ct.add(8) = (lba >> 24) as u8; // LBA[31:24]
        *ct.add(9) = (lba >> 32) as u8; // LBA[39:32]
        *ct.add(10) = (lba >> 40) as u8; // LBA[47:40]
        *ct.add(12) = blocks as u8; // sector count low
        *ct.add(13) = (blocks >> 8) as u8; // sector count high
        // PRDT[0] at offset 0x80: DBA / DBAU / rsv / DBC(byte count-1).
        let prdt = ct.add(0x80);
        let b = buf as u64;
        write_volatile(prdt as *mut u32, b as u32);
        write_volatile(prdt.add(4) as *mut u32, (b >> 32) as u32);
        write_volatile(prdt.add(12) as *mut u32, (len - 1) & 0x003F_FFFF);

        // Command list slot 0: PRDTL=1 | W(bit6) | CFL=5 dwords.
        let l = list as *mut u32;
        let wbit = if write { 1u32 << 6 } else { 0 };
        write_volatile(l, (1u32 << 16) | wbit | 5);
        write_volatile(l.add(1), 0); // PRDBC
        write_volatile(l.add(2), ctab as u32); // CTBA
        write_volatile(l.add(3), (ctab >> 32) as u32);
    }

    wr(pb + PX_CI, 1); // issue slot 0

    let mut spins = 0u64;
    loop {
        if rd(pb + PX_CI) & 1 == 0 {
            break;
        }
        if rd(pb + PX_TFD) & 0x01 != 0 {
            return false; // ERR in task file status
        }
        spins += 1;
        if spins > 200_000_000 {
            sprintln!("[hahci] ATA timeout port={} tfd=0x{:X}", port, rd(pb + PX_TFD));
            return false;
        }
    }
    rd(pb + PX_TFD) & 0x01 == 0
}

pub fn target_present() -> bool {
    TARGET_PORT.load(Ordering::Relaxed) != 0
}

/// Read `blocks` × `bs`-byte sectors from the SATA target disk into `dest`.
pub fn ata_read(lba: u64, blocks: u32, dest: *mut u8, bs: u32) -> bool {
    let p = TARGET_PORT.load(Ordering::Relaxed);
    if p == 0 {
        return false;
    }
    issue_ata((p - 1) as u64, false, lba, blocks as u16, dest, blocks * bs)
}

/// Write `blocks` × `bs`-byte sectors from `src` to the SATA target disk.
pub fn ata_write(lba: u64, blocks: u32, src: *const u8, bs: u32) -> bool {
    let p = TARGET_PORT.load(Ordering::Relaxed);
    if p == 0 {
        return false;
    }
    issue_ata((p - 1) as u64, true, lba, blocks as u16, src as *mut u8, blocks * bs)
}

/// Read `blocks` × `bs`-byte sectors from the ATAPI CD into `dest`.
pub fn atapi_read(lba: u64, blocks: u32, dest: *mut u8, bs: u32) -> bool {
    let p = MEDIA_PORT.load(Ordering::Relaxed);
    if p == 0 {
        return false;
    }
    let port = (p - 1) as u64;
    let mut cdb = [0u8; 16];
    cdb[0] = 0x28; // READ(10)
    cdb[2] = (lba >> 24) as u8;
    cdb[3] = (lba >> 16) as u8;
    cdb[4] = (lba >> 8) as u8;
    cdb[5] = lba as u8;
    cdb[7] = (blocks >> 8) as u8;
    cdb[8] = blocks as u8;
    issue_atapi(port, &cdb, dest, blocks * bs)
}
