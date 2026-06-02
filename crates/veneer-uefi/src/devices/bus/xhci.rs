//! xHCI USB host controller MMIO emulator — AMD FCH USB 3.1 class.
//!
//! BAR0 = 0xE400_0000 (16 KiB trapped). xHCI register space splits into
//! four windows (xHCI 1.1 § 5):
//!
//!   Capability Registers @ 0x0000 — read-only controller identity
//!   Operational Registers @ CAPLENGTH (0x40) — USBCMD/USBSTS/PAGESIZE/…
//!   Doorbell Array        @ DBOFF (0x1000) — 256 × 4-byte slots
//!   Runtime Registers     @ RTSOFF (0x2000) — MFINDEX + 1024 interrupters
//!   Port Register Sets    @ Op-base + 0x400 — 4 ports × 0x10 bytes
//!
//! State: Windows usbxhci.sys binds, reads capability registers, walks
//! port set, sees all ports "disconnected" (legitimate "no USB devices
//! plugged in" pattern). USBCMD.Run/Stop transitions are accepted but
//! we never process a command ring entry — drivers polling for events
//! get nothing, which mirrors an empty controller.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const XHCI_SIZE: u64 = 0x0000_4000; // 16 KiB register window
const XHCI_BASE_DEFAULT: u64 = 0xE400_0000;

// BAR0 base is whatever the guest firmware's PCI resource allocator
// assigns; pci.rs pushes that address here on the BAR write so the NPF
// router traps wherever the BAR actually landed.
static XHCI_BAR0: AtomicU64 = AtomicU64::new(XHCI_BASE_DEFAULT);

pub fn base() -> u64 {
    XHCI_BAR0.load(Ordering::Relaxed)
}

pub fn set_base(b: u64) {
    XHCI_BAR0.store(b, Ordering::Relaxed);
}

#[inline]
pub fn covers(gpa: u64) -> bool {
    let b = base();
    gpa >= b && gpa < b + XHCI_SIZE
}

// ───── Capability Registers (RO) ─────────────────────────────────────

const CAPLENGTH: u8  = 0x40;
const HCIVERSION: u16 = 0x0110;          // xHCI 1.1
const N_SLOTS: u8 = 32;
const N_INTRS: u16 = 1;
const N_PORTS: u8 = 4;
const DBOFF: u32 = 0x1000;
const RTSOFF: u32 = 0x2000;

const HCSPARAMS1: u32 =
    (N_SLOTS as u32)
    | ((N_INTRS as u32) << 8)
    | ((N_PORTS as u32) << 24);
const HCSPARAMS2: u32 = 0x0000_0000;
const HCSPARAMS3: u32 = 0x0000_0000;
const EXTCAP_OFFSET: u32 = 0x500;        // extended-capability list base (BAR-relative)
const HCCPARAMS1: u32 = 0x0000_0001 | ((EXTCAP_OFFSET >> 2) << 16); // AC64=1, xECP → ext caps
const HCCPARAMS2: u32 = 0x0000_0000;
const XHC_USB_NAME: u32 = 0x2042_5355;   // "USB " supported-protocol name string

// ───── Operational Registers (RW, persistent) ────────────────────────

const OP_BASE: u32 = CAPLENGTH as u32;

static USBCMD:  AtomicU32 = AtomicU32::new(0);
static USBSTS:  AtomicU32 = AtomicU32::new(0x0000_0001); // HCH (halted) = 1
static DNCTRL:  AtomicU32 = AtomicU32::new(0);
static CRCR_LO: AtomicU32 = AtomicU32::new(0);
static CRCR_HI: AtomicU32 = AtomicU32::new(0);
static DCBAAP_LO: AtomicU32 = AtomicU32::new(0);
static DCBAAP_HI: AtomicU32 = AtomicU32::new(0);
static CONFIG:  AtomicU32 = AtomicU32::new(0);

// Port status — one entry per port, modelling an always-powered root port
// with nothing plugged in. Critical bits (xHCI 1.1 §5.4.8):
//   CCS  (bit 0)   = 0  — no device connected
//   PP   (bit 9)   = 1  — port powered. HCCPARAMS1.PPC=0 means ports are
//                         ALWAYS powered, so PP must read 1; a 0 here is a
//                         spec violation that makes XhcDxe poll the port
//                         forever waiting for it to stabilise.
//   PLS  (bits 8:5)= 5  — RxDetect, the steady disconnected USB3 link state
//                         (U0/0 implies an active link, impossible with CCS=0).
// = (1<<9) | (5<<5) = 0x2A0.
const PORTSC_EMPTY_POWERED: u32 = (1 << 9) | (5 << 5);
#[allow(clippy::declare_interior_mutable_const)]
const PORTSC_INIT: AtomicU32 = AtomicU32::new(PORTSC_EMPTY_POWERED);
static PORTSC: [AtomicU32; N_PORTS as usize] = [PORTSC_INIT; N_PORTS as usize];

// ───── Doorbells + Runtime ───────────────────────────────────────────

static mut DOORBELLS: [u32; 256] = [0u32; 256];
static MFINDEX: AtomicU32 = AtomicU32::new(0);
// Single interrupter (IR0) — IMAN/IMOD/ERSTSZ/ERSTBA/ERDP
static IMAN:    AtomicU32 = AtomicU32::new(0);
static IMOD:    AtomicU32 = AtomicU32::new(0);
static ERSTSZ:  AtomicU32 = AtomicU32::new(0);
static ERSTBA_LO: AtomicU32 = AtomicU32::new(0);
static ERSTBA_HI: AtomicU32 = AtomicU32::new(0);
static ERDP_LO: AtomicU32 = AtomicU32::new(0);
static ERDP_HI: AtomicU32 = AtomicU32::new(0);

// USB Legacy Support (ext cap ID 1): HC OS-Owned semaphore stash (bit 24)
// + USBLEGCTLSTS. HC BIOS-Owned (bit 16) is always 0 so the driver's
// ownership handoff completes immediately.
static USBLEGSUP_OS: AtomicU32 = AtomicU32::new(0);
static USBLEGCTLSTS: AtomicU32 = AtomicU32::new(0);

// ───── Bounded MMIO trace (init-sequence diagnostic) ─────────────────
// Writes are discrete init steps; reads are deduped by register so a
// poll loop collapses to one line. The last line before the serial
// freezes is the register the driver is waiting on.
static WR_TRACE: AtomicU32 = AtomicU32::new(0);
static RD_TRACE: AtomicU32 = AtomicU32::new(0);
static RD_LAST: AtomicU32 = AtomicU32::new(0xFFFF_FFFF);
const WR_TRACE_CAP: u32 = 80;
const RD_TRACE_CAP: u32 = 120;

// Set when a consumer writes the USBLEGSUP HC OS-Owned semaphore (bit 24).
// The guest has been observed to drop into a native (exit-free) spin right
// after this handoff; the VMRUN loop consumes these to dump guest state at
// that exact point. Counter, not a bool: OVMF and the OS each hand off, and
// the dump we care about is the last one (right before the stall).
static HANDOFF_PENDING: AtomicU32 = AtomicU32::new(0);

// Legacy-support read-probe dump request. The hot-path trigger that used to
// arm this from ordinary USBLEGSUP reads has been removed (it was a pure
// host-side diagnostic with no guest-visible effect); the consumer below is
// retained for the VMRUN loop's stable ABI, so it now simply never fires.
static READ_PROBE_PENDING: AtomicU32 = AtomicU32::new(0);

/// Consume one pending USBLEGSUP-read probe dump request.
pub fn take_read_probe_dump() -> bool {
    loop {
        let n = READ_PROBE_PENDING.load(Ordering::Relaxed);
        if n == 0 {
            return false;
        }
        if READ_PROBE_PENDING
            .compare_exchange(n, n - 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

/// Consume one pending OS-Owned-handoff dump request (VMRUN loop calls this
/// each iteration). True means a handoff write just happened.
pub fn take_handoff_dump() -> bool {
    loop {
        let n = HANDOFF_PENDING.load(Ordering::Relaxed);
        if n == 0 {
            return false;
        }
        if HANDOFF_PENDING
            .compare_exchange(n, n - 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

fn reg_name(off: u32) -> &'static str {
    match off {
        0x00 => "CAPLEN/HCIVER",
        0x04 => "HCSPARAMS1",
        0x10 => "HCCPARAMS1",
        0x14 => "DBOFF",
        0x18 => "RTSOFF",
        o if o == OP_BASE + 0x00 => "USBCMD",
        o if o == OP_BASE + 0x04 => "USBSTS",
        o if o == OP_BASE + 0x08 => "PAGESIZE",
        o if o == OP_BASE + 0x18 => "CRCR_LO",
        o if o == OP_BASE + 0x1C => "CRCR_HI",
        o if o == OP_BASE + 0x30 => "DCBAAP_LO",
        o if o == OP_BASE + 0x34 => "DCBAAP_HI",
        o if o == OP_BASE + 0x38 => "CONFIG",
        0x500 => "USBLEGSUP",
        0x504 => "USBLEGCTLSTS",
        o if o == RTSOFF + 0x00 => "MFINDEX",
        o if o == RTSOFF + 0x20 => "IMAN",
        o if o == RTSOFF + 0x24 => "IMOD",
        o if o == RTSOFF + 0x28 => "ERSTSZ",
        o if o == RTSOFF + 0x30 => "ERSTBA_LO",
        o if o == RTSOFF + 0x34 => "ERSTBA_HI",
        o if o == RTSOFF + 0x38 => "ERDP_LO",
        o if o == RTSOFF + 0x3C => "ERDP_HI",
        o if (DBOFF..DBOFF + 256 * 4).contains(&o) => "DOORBELL",
        o if (OP_BASE + 0x400..OP_BASE + 0x400 + (N_PORTS as u32) * 0x10).contains(&o) => "PORTSC",
        _ => "?",
    }
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

fn host_rdtsc() -> u64 {
    let lo: u32; let hi: u32;
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)); }
    ((hi as u64) << 32) | (lo as u64)
}

fn read_dword(offset: u32) -> u32 {
    match offset {
        // ── Capability Registers ──
        0x00 => (CAPLENGTH as u32) | ((HCIVERSION as u32) << 16),
        0x04 => HCSPARAMS1,
        0x08 => HCSPARAMS2,
        0x0C => HCSPARAMS3,
        0x10 => HCCPARAMS1,
        0x14 => DBOFF,
        0x18 => RTSOFF,
        0x1C => HCCPARAMS2,
        // ── Operational Registers ──
        o if o == OP_BASE + 0x00 => USBCMD.load(Ordering::Relaxed),
        o if o == OP_BASE + 0x04 => USBSTS.load(Ordering::Relaxed),
        o if o == OP_BASE + 0x08 => 1,    // PAGESIZE = 4 KiB (bit 0)
        o if o == OP_BASE + 0x14 => DNCTRL.load(Ordering::Relaxed),
        o if o == OP_BASE + 0x18 => CRCR_LO.load(Ordering::Relaxed),
        o if o == OP_BASE + 0x1C => CRCR_HI.load(Ordering::Relaxed),
        o if o == OP_BASE + 0x30 => DCBAAP_LO.load(Ordering::Relaxed),
        o if o == OP_BASE + 0x34 => DCBAAP_HI.load(Ordering::Relaxed),
        o if o == OP_BASE + 0x38 => CONFIG.load(Ordering::Relaxed),
        // ── Port Registers (at OP_BASE + 0x400) ──
        o if (OP_BASE + 0x400 .. OP_BASE + 0x400 + (N_PORTS as u32) * 0x10).contains(&o) => {
            let port = ((o - (OP_BASE + 0x400)) / 0x10) as usize;
            let sub = (o - (OP_BASE + 0x400)) % 0x10;
            match sub {
                // Defensive: PP (bit 9) always reads 1 (PPC=0, always powered).
                0x00 => PORTSC[port].load(Ordering::Relaxed) | (1 << 9),
                _ => 0,
            }
        }
        // ── Extended Capabilities (xECP → 0x500) ──
        //   0x500 USB Legacy Support (ID 1) → 0x510 Supported Protocol USB3
        //   (ID 2) → 0x520 Supported Protocol USB2 (ID 2, list end). Next
        //   pointers are in dwords (byte offset = next << 2).
        0x500 => 0x0000_0401 | USBLEGSUP_OS.load(Ordering::Relaxed), // id=1, next=4dw, OS-owned bit
        0x504 => USBLEGCTLSTS.load(Ordering::Relaxed),
        0x510 => 0x0300_0402,  // id=2, next=4dw, major rev 3 (USB3)
        0x514 => XHC_USB_NAME,
        0x518 => 0x0000_0201,  // compat port offset 1, count 2, PSIC 0
        0x51C => 0x0000_0000,  // protocol slot type 0
        0x520 => 0x0200_0002,  // id=2, next=0 (list end), major rev 2 (USB2)
        0x524 => XHC_USB_NAME,
        0x528 => 0x0000_0203,  // compat port offset 3, count 2
        0x52C => 0x0000_0000,
        // ── Doorbells ──
        o if (DBOFF..DBOFF + 256 * 4).contains(&o) => {
            let idx = ((o - DBOFF) / 4) as usize;
            if idx < 256 { unsafe { DOORBELLS[idx] } } else { 0 }
        }
        // ── Runtime: MFINDEX + IR0 ──
        o if o == RTSOFF + 0x00 => {
            // MFINDEX advances every microframe (125us). Synthesise via TSC.
            (host_rdtsc() & 0x3FFF) as u32
        }
        o if o == RTSOFF + 0x20 => IMAN.load(Ordering::Relaxed),
        o if o == RTSOFF + 0x24 => IMOD.load(Ordering::Relaxed),
        o if o == RTSOFF + 0x28 => ERSTSZ.load(Ordering::Relaxed),
        o if o == RTSOFF + 0x30 => ERSTBA_LO.load(Ordering::Relaxed),
        o if o == RTSOFF + 0x34 => ERSTBA_HI.load(Ordering::Relaxed),
        o if o == RTSOFF + 0x38 => ERDP_LO.load(Ordering::Relaxed),
        o if o == RTSOFF + 0x3C => ERDP_HI.load(Ordering::Relaxed),
        _ => 0,
    }
}

pub fn read_register_width(offset: u32, width: u8) -> u64 {
    let aligned = offset & !0x3;
    let shift_bits = (offset & 0x3) * 8;
    let dword = read_dword(aligned);
    let val = ((dword as u64) >> shift_bits) & low_mask(width);
    if RD_LAST.swap(aligned, Ordering::Relaxed) != aligned {
        let t = RD_TRACE.fetch_add(1, Ordering::Relaxed);
        if t < RD_TRACE_CAP {
            crate::sprintln!("[xhci] R {}(+0x{:X}) = 0x{:X} w{}", reg_name(aligned), aligned, val, width);
        }
    }
    val
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
    let t = WR_TRACE.fetch_add(1, Ordering::Relaxed);
    if t < WR_TRACE_CAP {
        if (DBOFF..DBOFF + 256 * 4).contains(&aligned) {
            crate::sprintln!("[xhci] >>> DOORBELL[{}] = 0x{:X}", (aligned - DBOFF) / 4, val & low_mask(width));
        } else {
            crate::sprintln!("[xhci] W {}(+0x{:X}) = 0x{:X} w{}", reg_name(aligned), aligned, val & low_mask(width), width);
        }
    }
    match aligned {
        // ── Operational ──
        o if o == OP_BASE + 0x00 => {
            let mut new = merge(&USBCMD);
            // HCRST (bit 1): a real HC resets and self-clears this bit when
            // done; Linux's xhci_handshake spins on it reading back 0 (and
            // on USBSTS.CNR clearing). We complete the reset instantly.
            if new & 0x2 != 0 {
                new &= !0x2;
                USBCMD.store(new, Ordering::Relaxed);
            }
            // R/S bit 0: setting 1 → controller running (USBSTS.HCH clears);
            // 0 → controller halted (USBSTS.HCH sets). Keep CNR (bit 11)
            // clear so the post-reset readiness handshake also passes.
            let prev_sts = USBSTS.load(Ordering::Relaxed);
            let mut new_sts = if new & 1 != 0 { prev_sts & !1 } else { prev_sts | 1 };
            new_sts &= !(1 << 11);
            USBSTS.store(new_sts, Ordering::Relaxed);
        }
        o if o == OP_BASE + 0x04 => {
            // USBSTS: most bits are W1C
            let prev = USBSTS.load(Ordering::Relaxed);
            USBSTS.store(prev & !val_u32, Ordering::Relaxed);
        }
        o if o == OP_BASE + 0x14 => { merge(&DNCTRL); }
        o if o == OP_BASE + 0x18 => { merge(&CRCR_LO); }
        o if o == OP_BASE + 0x1C => { merge(&CRCR_HI); }
        o if o == OP_BASE + 0x30 => { merge(&DCBAAP_LO); }
        o if o == OP_BASE + 0x34 => { merge(&DCBAAP_HI); }
        o if o == OP_BASE + 0x38 => { merge(&CONFIG); }
        // ── Port Registers ──
        o if (OP_BASE + 0x400 .. OP_BASE + 0x400 + (N_PORTS as u32) * 0x10).contains(&o) => {
            let port = ((o - (OP_BASE + 0x400)) / 0x10) as usize;
            let sub = (o - (OP_BASE + 0x400)) % 0x10;
            if sub == 0 {
                // PORTSC write for an always-empty, always-powered port
                // (xHCI 1.1 §5.4.8). A bare stash is wrong: the RW1C change
                // bits would latch the guest's acknowledging 1 instead of
                // clearing, so XhcDxe sees a perpetual change and re-polls.
                let prev = PORTSC[port].load(Ordering::Relaxed);
                const RW1C: u32 = 0x00FE_0000; // CSC,PEC,WRC,OCC,PRC,PLC,CEC (17..23)
                // Write-1-to-clear the change bits the guest acknowledges.
                let mut new = prev & !(val_u32 & RW1C);
                // Port Reset (bit 4): no device, so the reset "completes"
                // instantly — clear PR and raise PRC so the reset wait ends.
                if val_u32 & (1 << 4) != 0 {
                    new &= !(1 << 4);
                    new |= 1 << 21; // PRC
                }
                // Link State Write strobe (bit 16): accept the requested PLS.
                if val_u32 & (1 << 16) != 0 {
                    new = (new & !(0xF << 5)) | (val_u32 & (0xF << 5));
                }
                new |= 1 << 9;   // PP — always powered (PPC=0)
                new &= !1;       // CCS — never connected
                new &= !(1 << 1); // PED — empty port never enables
                PORTSC[port].store(new, Ordering::Relaxed);
            }
        }
        // ── Extended Capability: USB Legacy Support ownership handoff ──
        0x500 => {
            // HC OS Owned (bit 24). Reading the semaphore back as set lets the
            // consumer's ownership handoff complete.
            USBLEGSUP_OS.store(val_u32 & 0x0100_0000, Ordering::Relaxed);
            if val_u32 & 0x0100_0000 != 0 {
                HANDOFF_PENDING.fetch_add(1, Ordering::Relaxed);
                // Reopen the bounded MMIO trace: the OVMF-phase accesses long
                // exhausted the original window, so reset it here to capture the
                // OS driver's post-ownership init (HCRST, CRCR/ERST/DCBAA setup,
                // the first doorbell ring, and the register it finally polls —
                // the last line before the exit-free spin is what it waits on).
                WR_TRACE.store(0, Ordering::Relaxed);
                RD_TRACE.store(0, Ordering::Relaxed);
                RD_LAST.store(0xFFFF_FFFF, Ordering::Relaxed);
            }
        }
        0x504 => { merge(&USBLEGCTLSTS); }
        // ── Doorbells: writes are commands; we accept and stash ──
        o if (DBOFF..DBOFF + 256 * 4).contains(&o) => {
            let idx = ((o - DBOFF) / 4) as usize;
            if idx < 256 {
                unsafe {
                    let prev = DOORBELLS[idx];
                    DOORBELLS[idx] = (prev & !mask_u32) | val_u32;
                }
            }
        }
        // ── Runtime IR0 ──
        o if o == RTSOFF + 0x20 => { merge(&IMAN); }
        o if o == RTSOFF + 0x24 => { merge(&IMOD); }
        o if o == RTSOFF + 0x28 => { merge(&ERSTSZ); }
        o if o == RTSOFF + 0x30 => { merge(&ERSTBA_LO); }
        o if o == RTSOFF + 0x34 => { merge(&ERSTBA_HI); }
        o if o == RTSOFF + 0x38 => { merge(&ERDP_LO); }
        o if o == RTSOFF + 0x3C => { merge(&ERDP_HI); }
        _ => {}
    }
}
