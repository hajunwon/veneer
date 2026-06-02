//! Intel I225-V (0x8086:0x15F3) NIC register-window emulator.
//!
//! BAR0 = 0xE100_0000 (4 KiB trapped region). Real silicon exposes
//! thousands of registers; we model the subset Windows / Linux drivers
//! read during bind-up, plus the MAC address slot vgc / WMI inspect:
//!
//!   0x0000  CTRL          — Device Control (RW)
//!   0x0008  STATUS        — Link status (RO, computed from CTRL.SLU)
//!   0x0010  EECD          — EEPROM Control (RW, present-bit set)
//!   0x0014  EERD          — EEPROM Read (R/W with DONE bit auto-set)
//!   0x0018  CTRL_EXT      — Extended control (RW)
//!   0x0020  MDIC          — MII Data In/Out (RW, returns plausible PHY ID)
//!   0x00C0  ICR           — Interrupt Cause Read (clear-on-read)
//!   0x00C8  ICS           — Interrupt Cause Set (W1S)
//!   0x00D0  IMS           — Interrupt Mask Set/Read
//!   0x00D8  IMC           — Interrupt Mask Clear (W1C)
//!   0x0100  RCTL          — Receive Control
//!   0x0400  TCTL          — Transmit Control
//!   0x5400  RAL0          — Receive Address Low (MAC bytes 0..3)
//!   0x5404  RAH0          — Receive Address High (MAC bytes 4..5 + AV bit)
//!   anything else         — generic store-then-read (writes saved, reads
//!                            return last write)
//!
//! Link is reported permanently down (legitimate "no cable plugged
//! in"). RX/TX rings receive the guest's pointer writes but produce no
//! descriptor activity — the NDIS driver will bring the controller up
//! and then sit idle waiting for link.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::identity::active;

pub const NIC_BAR0_TRAP_SIZE: u64 = 0x0000_1000;
const NIC_BAR0_DEFAULT: u64 = 0xE100_0000;

// BAR0 base is assigned dynamically by the guest firmware; pci.rs pushes
// the assigned address here so the NPF router traps the live location.
static NIC_BAR0: AtomicU64 = AtomicU64::new(NIC_BAR0_DEFAULT);

pub fn base() -> u64 {
    NIC_BAR0.load(Ordering::Relaxed)
}

pub fn set_base(b: u64) {
    NIC_BAR0.store(b, Ordering::Relaxed);
}

#[inline]
pub fn covers(gpa: u64) -> bool {
    let b = base();
    gpa >= b && gpa < b + NIC_BAR0_TRAP_SIZE
}

// ───── Register state ────────────────────────────────────────────────

static CTRL: AtomicU32       = AtomicU32::new(0x0008_0241); // FD + ASDE defaults
static CTRL_EXT: AtomicU32   = AtomicU32::new(0x0010_0000);
static EECD: AtomicU32       = AtomicU32::new(0x0000_0100); // EE present
static EERD: AtomicU32       = AtomicU32::new(0);
static MDIC: AtomicU32       = AtomicU32::new(0);
static ICR: AtomicU32        = AtomicU32::new(0);
static IMS: AtomicU32        = AtomicU32::new(0);
static RCTL: AtomicU32       = AtomicU32::new(0);
static TCTL: AtomicU32       = AtomicU32::new(0);
static RDBAL: AtomicU32      = AtomicU32::new(0);
static RDBAH: AtomicU32      = AtomicU32::new(0);
static RDLEN: AtomicU32      = AtomicU32::new(0);
static RDH: AtomicU32        = AtomicU32::new(0);
static RDT: AtomicU32        = AtomicU32::new(0);
static TDBAL: AtomicU32      = AtomicU32::new(0);
static TDBAH: AtomicU32      = AtomicU32::new(0);
static TDLEN: AtomicU32      = AtomicU32::new(0);
static TDH: AtomicU32        = AtomicU32::new(0);
static TDT: AtomicU32        = AtomicU32::new(0);
/// Catch-all for unmodelled registers — first 4 KiB of stash. Each MMIO
/// dword the guest writes lands here; subsequent reads return what it
/// wrote, which is what most "is the controller initialised" probes
/// check for.
const STASH_SLOTS: usize = 1024;
static mut STASH: [u32; STASH_SLOTS] = [0u32; STASH_SLOTS];

// ───── MAC parse from profile ────────────────────────────────────────

/// Convert profile.network.mac (`XX:XX:XX:XX:XX:XX` text) into 6 raw
/// bytes. Falls back to a fixed pattern if the profile slot is empty.
fn mac_bytes() -> [u8; 6] {
    let mut out = [0x04u8, 0x7C, 0x16, 0x00, 0x00, 0x01];
    if let Some(p) = active::PROFILE.get() {
        let mac_str = unsafe { core::ptr::addr_of!(p.hardware.network.mac).read_unaligned() };
        let bytes = mac_str.as_bytes();
        let mut nibble_idx = 0usize;
        for &c in bytes {
            if c == b':' { continue; }
            let nibble = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => continue,
            };
            if nibble_idx >= 12 { break; }
            let byte_idx = nibble_idx / 2;
            if nibble_idx & 1 == 0 {
                out[byte_idx] = nibble << 4;
            } else {
                out[byte_idx] |= nibble;
            }
            nibble_idx += 1;
        }
    }
    out
}

/// PHY identifier reported through MDIC (MII PHYIDR1). Sourced from the
/// active profile so it stays consistent with the NIC's PCI identity; the
/// fallback is the Intel I225-V integrated-PHY value (0x67C9) matching the
/// default NIC PCI id.
fn phy_id() -> u16 {
    active::PROFILE
        .get()
        .map(|p| unsafe { core::ptr::addr_of!(p.hardware.network.phy_id).read_unaligned() })
        .filter(|&v| v != 0)
        .unwrap_or(0x67C9)
}

fn ral0_value() -> u32 {
    let m = mac_bytes();
    u32::from_le_bytes([m[0], m[1], m[2], m[3]])
}

fn rah0_value() -> u32 {
    let m = mac_bytes();
    // High 16 bits = MAC bytes 4-5, plus AV bit (31) = address valid.
    let lo = u32::from_le_bytes([m[4], m[5], 0, 0]);
    lo | 0x8000_0000
}

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
        0x0000 => CTRL.load(Ordering::Relaxed),
        0x0008 => status_value(),
        0x0010 => EECD.load(Ordering::Relaxed),
        0x0014 => {
            // EERD: bit 1 DONE auto-set on read. Data field (high 16)
            // returns 0 except for word 0 which carries the MAC OUI.
            let cur = EERD.load(Ordering::Relaxed);
            cur | 0x0000_0002
        }
        0x0018 => CTRL_EXT.load(Ordering::Relaxed),
        0x0020 => {
            // MDIC: MII management read-back. The driver writes MDIC with
            // OP=read (bits 27:26 = 10b) + the target PHY register (bits
            // 20:16), then polls for R (bit 28, Ready). We complete the
            // access instantly (R=1, E=0) and substitute the DATA field
            // (bits 15:0) for PHY-identity registers so the driver reads a
            // coherent PHY ID instead of whatever it last wrote.
            //
            //   MII reg 2 (PHYIDR1) = PHY OUI high → profile phy_id
            //   MII reg 3 (PHYIDR2) = OUI low | model | revision
            //
            // PHYIDR1 carries the model/vendor word the I225-V driver checks;
            // PHYIDR2 is reported as 0 (revision/model not probed by bind).
            let cur = MDIC.load(Ordering::Relaxed);
            let regaddr = (cur >> 16) & 0x1F;
            let data = match regaddr {
                2 => phy_id() as u32,
                3 => 0x0000,
                _ => cur & 0xFFFF, // non-identity reg: echo last written data
            };
            (cur & 0xFFFF_0000) | data | (1u32 << 28) // set DATA + Ready, clear Error
        }
        0x00C0 => {
            // ICR: read-to-clear.
            ICR.swap(0, Ordering::Relaxed)
        }
        0x00D0 => IMS.load(Ordering::Relaxed),
        0x0100 => RCTL.load(Ordering::Relaxed),
        0x0400 => TCTL.load(Ordering::Relaxed),
        0x2800 => RDBAL.load(Ordering::Relaxed),
        0x2804 => RDBAH.load(Ordering::Relaxed),
        0x2808 => RDLEN.load(Ordering::Relaxed),
        0x2810 => RDH.load(Ordering::Relaxed),
        0x2818 => RDT.load(Ordering::Relaxed),
        0x3800 => TDBAL.load(Ordering::Relaxed),
        0x3804 => TDBAH.load(Ordering::Relaxed),
        0x3808 => TDLEN.load(Ordering::Relaxed),
        0x3810 => TDH.load(Ordering::Relaxed),
        0x3818 => TDT.load(Ordering::Relaxed),
        0x5400 => ral0_value(),
        0x5404 => rah0_value(),
        o if (o as usize) / 4 < STASH_SLOTS => unsafe { STASH[(o as usize) / 4] },
        _ => 0,
    }
}

fn status_value() -> u32 {
    let ctrl = CTRL.load(Ordering::Relaxed);
    // STATUS layout: bit 0 FD, bit 1 LU (link up), bits 6-7 SPEED, bit 19 PF_RST_DONE.
    //
    // Link is reported permanently DOWN ("no cable plugged in"). Previously
    // LU tracked CTRL.SLU, so a driver that set Set-Link-Up saw the link come
    // up — but we deliver no RX/TX/interrupt activity, producing a dishonest
    // "link up yet totally silent" controller that a real PHY never shows. An
    // unplugged-cable link (LU=0, SPEED undefined) is internally consistent
    // with the dead datapath: the NDIS driver binds, brings the controller
    // up, and idles waiting for a link event that legitimately never comes.
    let fd = ctrl & 1; // full-duplex reflects CTRL.FD
    // LU (bit 1) and SPEED (bits 7:6) stay 0: link permanently down.
    fd | (1 << 19)
}

pub fn read_register(offset: u32) -> u32 {
    read_dword(offset & !0x3)
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
    let merge = |slot: &AtomicU32| {
        let prev = slot.load(Ordering::Relaxed);
        slot.store((prev & !mask_u32) | val_u32, Ordering::Relaxed);
    };
    match aligned {
        0x0000 => merge(&CTRL),
        0x0010 => merge(&EECD),
        0x0014 => merge(&EERD),
        0x0018 => merge(&CTRL_EXT),
        0x0020 => merge(&MDIC),
        0x00C8 => {
            // ICS: W1S into ICR.
            let prev = ICR.load(Ordering::Relaxed);
            ICR.store(prev | val_u32, Ordering::Relaxed);
        }
        0x00D0 => merge(&IMS),
        0x00D8 => {
            // IMC: W1C against IMS.
            let prev = IMS.load(Ordering::Relaxed);
            IMS.store(prev & !val_u32, Ordering::Relaxed);
        }
        0x0100 => merge(&RCTL),
        0x0400 => merge(&TCTL),
        0x2800 => merge(&RDBAL),
        0x2804 => merge(&RDBAH),
        0x2808 => merge(&RDLEN),
        0x2810 => merge(&RDH),
        0x2818 => merge(&RDT),
        0x3800 => merge(&TDBAL),
        0x3804 => merge(&TDBAH),
        0x3808 => merge(&TDLEN),
        0x3810 => merge(&TDH),
        0x3818 => merge(&TDT),
        // MAC slot is RO (programmed by EEPROM in real HW).
        0x5400 | 0x5404 => {}
        a if (a as usize) / 4 < STASH_SLOTS => unsafe {
            let prev = STASH[(a as usize) / 4];
            STASH[(a as usize) / 4] = (prev & !mask_u32) | val_u32;
        }
        _ => {}
    }
}
