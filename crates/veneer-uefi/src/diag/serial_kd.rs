//! COM2 (0x2F8) bidirectional bridge for Windows kernel debugging (KD).
//!
//! The guest's KD transport (bcdedit `/dbgsettings serial debugport:2`) needs a
//! REAL bidirectional 16550: WinDbg's packets must reach the guest (RBR) and
//! the guest's packets must reach WinDbg (THR). veneer's COM1 model
//! (`io::com1`) is output-only and shares the port with veneer's own logging,
//! so KD gets a dedicated COM2 here.
//!
//! Topology:  guest COM2 (this emulated 16550)  <->  veneer host bridge  <->
//!            physical COM2 0x2F8 (VMware serial1 = named pipe)  <->  WinDbg.
//!
//! veneer is single-vCPU and strictly sequential through the dispatcher: guest
//! COM2 register access happens during an IOIO #VMEXIT (dispatch), the host
//! bridge runs in the VMRUN loop body between exits — never concurrently. So
//! the two SPSC rings need no locking; AtomicUsize indices suffice.
//!
//! Only enabled if a physical COM2 is actually present (16550 scratch-register
//! probe in `host_init`) — otherwise reads of an absent 0x2F8 return 0xFF and
//! would inject garbage into the guest. KD off the wire is harmless.

use crate::infra::arch;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

/// Physical and guest-visible COM2 base (they coincide; VMware presents
/// serial1 as a standard 16550 at 0x2F8 to veneer's host context).
const COM2: u16 = 0x2F8;
const END: u16 = 0x2FF;

// 16550 register offsets from the base (DLAB=0 unless noted).
const R_RBR_THR: u16 = 0; // RBR (read) / THR (write) / DLL (DLAB)
const R_IER_DLM: u16 = 1; // IER / DLM (DLAB)
const R_IIR_FCR: u16 = 2; // IIR (read) / FCR (write)
const R_LCR: u16 = 3;
const R_MCR: u16 = 4;
const R_LSR: u16 = 5;
const R_MSR: u16 = 6;
const R_SCR: u16 = 7;
const LCR_DLAB: u8 = 1 << 7;

/// Set once host_init confirms a physical COM2 is present.
static PRESENT: AtomicBool = AtomicBool::new(false);

// ── Guest-facing 16550 register shadows ──────────────────────────────
static IER: AtomicU8 = AtomicU8::new(0);
static LCR: AtomicU8 = AtomicU8::new(0x03);
static MCR: AtomicU8 = AtomicU8::new(0);
static SCR: AtomicU8 = AtomicU8::new(0);
static FCR: AtomicU8 = AtomicU8::new(0);
static DLL: AtomicU8 = AtomicU8::new(0x01);
static DLM: AtomicU8 = AtomicU8::new(0x00);

// ── SPSC rings (sequential, see module doc) ──────────────────────────
// 16 KiB each: a single KDCOM packet is <=4 KiB, so this absorbs several
// in-flight packets even if the physical UART briefly stalls draining.
const RING: usize = 16384;
const MASK: usize = RING - 1;
// host -> guest (WinDbg's bytes, popped by guest RBR reads)
static mut RX_BUF: [u8; RING] = [0; RING];
static RX_HEAD: AtomicUsize = AtomicUsize::new(0); // producer: host bridge
static RX_TAIL: AtomicUsize = AtomicUsize::new(0); // consumer: guest RBR
// guest -> host (guest THR bytes, drained by bridge to physical COM2)
static mut TX_BUF: [u8; RING] = [0; RING];
static TX_HEAD: AtomicUsize = AtomicUsize::new(0); // producer: guest THR
static TX_TAIL: AtomicUsize = AtomicUsize::new(0); // consumer: host bridge

#[inline]
fn dlab() -> bool {
    LCR.load(Ordering::Relaxed) & LCR_DLAB != 0
}

#[inline]
fn rx_has_data() -> bool {
    RX_HEAD.load(Ordering::Relaxed) != RX_TAIL.load(Ordering::Relaxed)
}

fn rx_pop() -> Option<u8> {
    let tail = RX_TAIL.load(Ordering::Relaxed);
    if tail == RX_HEAD.load(Ordering::Relaxed) {
        return None;
    }
    let b = unsafe { RX_BUF[tail & MASK] };
    RX_TAIL.store(tail.wrapping_add(1), Ordering::Relaxed);
    Some(b)
}

fn rx_push(b: u8) {
    let head = RX_HEAD.load(Ordering::Relaxed);
    // Drop on overflow rather than overwrite unread bytes (KD resyncs).
    if head.wrapping_sub(RX_TAIL.load(Ordering::Relaxed)) >= RING {
        return;
    }
    unsafe { RX_BUF[head & MASK] = b };
    RX_HEAD.store(head.wrapping_add(1), Ordering::Relaxed);
}

fn tx_push(b: u8) {
    let head = TX_HEAD.load(Ordering::Relaxed);
    if head.wrapping_sub(TX_TAIL.load(Ordering::Relaxed)) >= RING {
        return;
    }
    unsafe { TX_BUF[head & MASK] = b };
    TX_HEAD.store(head.wrapping_add(1), Ordering::Relaxed);
}

fn tx_pop() -> Option<u8> {
    let tail = TX_TAIL.load(Ordering::Relaxed);
    if tail == TX_HEAD.load(Ordering::Relaxed) {
        return None;
    }
    let b = unsafe { TX_BUF[tail & MASK] };
    TX_TAIL.store(tail.wrapping_add(1), Ordering::Relaxed);
    Some(b)
}

/// Master switch for the Windows KD transport. When false, COM2 is left
/// unpresented so the guest's UART probe fails and KD stays off — without it,
/// Windows' KdPollBreakIn polls COM2 (LSR/MSR) continuously, which under
/// VMware nested SVM is ~half of all VMEXITs and roughly doubles boot time.
/// Flip to true only when actually attaching WinDbg to the COM2 pipe.
const KD_ENABLED: bool = false;

/// Always own the COM2 register range so io.rs never falls back to the
/// `SYNTH_IO_DWORD` (0xFFFFFFFF) default for it. Returning 0xFF for the LSR
/// sets the DR (data-ready) bit forever, which makes the guest's KDCOM
/// `KdReceivePacket` read phantom 0xFF bytes in a tight spin (a boot wedge —
/// observed once the HPET storm was removed and the boot raced to KD init).
/// When KD is off we model a quiescent idle 16550 (DR clear) instead; when on,
/// the bridged transport below takes over.
#[inline]
pub fn covers(port: u16) -> bool {
    port >= COM2 && port <= END
}

/// Guest read of a COM2 register (IOIO #VMEXIT path).
pub fn read(off: u16) -> u64 {
    // KD off: present a quiescent idle 16550 (a real COM2 header with nothing
    // on the wire). No physical-port access — routing to the live bridge with
    // no WinDbg attached risks the physical LSR reading 0xFF (pipe drained/
    // disconnected) and re-injecting the phantom-DR spin. DR clear, transmitter
    // always ready, registers round-trip so a UART presence probe still passes.
    if !KD_ENABLED {
        return match off {
            R_RBR_THR => if dlab() { DLL.load(Ordering::Relaxed) as u64 } else { 0 },
            R_IER_DLM => if dlab() { DLM.load(Ordering::Relaxed) as u64 } else { IER.load(Ordering::Relaxed) as u64 },
            R_IIR_FCR => {
                let fifo = if FCR.load(Ordering::Relaxed) & 1 != 0 { 0xC0 } else { 0x00 };
                (fifo | 0x01) as u64 // no interrupt pending
            }
            R_LCR => LCR.load(Ordering::Relaxed) as u64,
            R_MCR => MCR.load(Ordering::Relaxed) as u64,
            R_LSR => 0x60, // THRE+TEMT set, DR clear (no incoming data, ever)
            R_MSR => 0xB0, // CTS+DSR+DCD asserted, no RI
            R_SCR => SCR.load(Ordering::Relaxed) as u64,
            _ => 0xFF,
        };
    }
    // Demand-driven pump: while KD is active the guest hammers COM2 (polling
    // LSR for DR, popping RBR). Pumping on every access drains the physical
    // 16-byte RX FIFO before it can overflow — the root cause of the link
    // breaking under `u`/`kb`/`!analyze` load. Idle => no access => no pump.
    pump();
    match off {
        R_RBR_THR => {
            if dlab() {
                DLL.load(Ordering::Relaxed) as u64
            } else {
                rx_pop().unwrap_or(0) as u64
            }
        }
        R_IER_DLM => {
            if dlab() { DLM.load(Ordering::Relaxed) as u64 } else { IER.load(Ordering::Relaxed) as u64 }
        }
        R_IIR_FCR => {
            let fifo = if FCR.load(Ordering::Relaxed) & 1 != 0 { 0xC0 } else { 0x00 };
            (fifo | 0x01) as u64 // no interrupt pending
        }
        R_LCR => LCR.load(Ordering::Relaxed) as u64,
        R_MCR => MCR.load(Ordering::Relaxed) as u64,
        R_LSR => {
            // DR (bit0) when WinDbg has sent us bytes; THRE+TEMT (bits 5/6)
            // always set so the guest never blocks transmitting.
            let dr = if rx_has_data() { 1 } else { 0 };
            (dr | 0x60) as u64
        }
        R_MSR => 0xB0, // CTS+DSR+DCD asserted, no RI — a "ready" wiring
        R_SCR => SCR.load(Ordering::Relaxed) as u64,
        _ => 0xFF,
    }
}

/// Guest write of a COM2 register (IOIO #VMEXIT path).
pub fn write(off: u16, val: u8) {
    // KD off: update the register shadows so reads round-trip (UART probe),
    // but never touch the physical port or queue TX — there is no bridge.
    if !KD_ENABLED {
        match off {
            R_RBR_THR => if dlab() { DLL.store(val, Ordering::Relaxed); }, // THR data dropped
            R_IER_DLM => if dlab() { DLM.store(val, Ordering::Relaxed); } else { IER.store(val, Ordering::Relaxed); },
            R_IIR_FCR => FCR.store(val, Ordering::Relaxed),
            R_LCR => LCR.store(val, Ordering::Relaxed),
            R_MCR => MCR.store(val & 0x1F, Ordering::Relaxed),
            R_SCR => SCR.store(val, Ordering::Relaxed),
            _ => {}
        }
        return;
    }
    match off {
        R_RBR_THR => {
            if dlab() {
                DLL.store(val, Ordering::Relaxed);
            } else {
                tx_push(val); // queue for the host bridge -> WinDbg
                pump();       // flush immediately so big responses don't back up
            }
        }
        R_IER_DLM => {
            if dlab() { DLM.store(val, Ordering::Relaxed); } else { IER.store(val, Ordering::Relaxed); }
        }
        R_IIR_FCR => FCR.store(val, Ordering::Relaxed),
        R_LCR => LCR.store(val, Ordering::Relaxed),
        R_MCR => MCR.store(val & 0x1F, Ordering::Relaxed),
        R_SCR => SCR.store(val, Ordering::Relaxed),
        _ => {} // LSR/MSR read-only
    }
}

/// Probe + initialise physical COM2 (0x2F8). Enables the bridge only if a
/// 16550 actually answers (scratch-register round-trip). Call once, host ctx.
pub fn host_init() {
    unsafe {
        // 16550 scratch-register presence test.
        arch::outb(COM2 + R_SCR, 0xA5);
        let probe = arch::inb(COM2 + R_SCR);
        if probe != 0xA5 {
            crate::sprintln!("[kd] no physical COM2 (scratch=0x{:02X}); KD bridge OFF", probe);
            return;
        }
        // Standard 16550 init: 115200 8N1, FIFO on, no host-side interrupts
        // (we poll in bridge()).
        arch::outb(COM2 + R_IER_DLM, 0x00); // ints off
        arch::outb(COM2 + R_LCR, 0x80);     // DLAB
        arch::outb(COM2 + R_RBR_THR, 0x01); // divisor low = 115200
        arch::outb(COM2 + R_IER_DLM, 0x00); // divisor high
        arch::outb(COM2 + R_LCR, 0x03);     // 8N1, DLAB off
        arch::outb(COM2 + R_IIR_FCR, 0xC7); // FIFO enable+clear, 14-byte
        arch::outb(COM2 + R_MCR, 0x0B);     // DTR/RTS/OUT2
        PRESENT.store(true, Ordering::Relaxed);
        crate::sprintln!("[kd] COM2 bridge armed (0x2F8 <-> guest KD); attach WinDbg to the pipe");
    }
}

/// Pump bytes both directions between physical COM2 (WinDbg pipe) and the
/// guest rings. Call frequently from the VMRUN loop. Bounded per call so a
/// flooded line can't starve the loop.
static TX_TOTAL: AtomicUsize = AtomicUsize::new(0);
static RX_TOTAL: AtomicUsize = AtomicUsize::new(0);
static LOG_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Core byte mover between physical COM2 (WinDbg pipe) and the guest rings.
/// Bounded per call so a flooded line can't starve the caller. Cheap when
/// idle (a couple of port reads). Called both from every guest COM2 access
/// (demand-driven, the hot path under KD load) and sparsely from the VMRUN
/// loop (covers idle / break-in when the guest isn't touching COM2).
/// Returns (rx_bytes, tx_bytes) moved this call.
fn pump() -> (usize, usize) {
    if !PRESENT.load(Ordering::Relaxed) {
        return (0, 0);
    }
    let mut rxn = 0usize;
    let mut txn = 0usize;
    unsafe {
        // Physical RX (WinDbg -> guest): drain while data-ready.
        while arch::inb(COM2 + R_LSR) & 0x01 != 0 && rxn < 4096 {
            rx_push(arch::inb(COM2 + R_RBR_THR));
            rxn += 1;
        }
        // Guest TX (guest -> WinDbg): send while the UART can accept.
        while txn < 4096 {
            if arch::inb(COM2 + R_LSR) & 0x20 == 0 {
                break; // THR not empty yet
            }
            match tx_pop() {
                Some(b) => arch::outb(COM2 + R_RBR_THR, b),
                None => break,
            }
            txn += 1;
        }
    }
    (rxn, txn)
}

pub fn bridge() {
    let (rxn, txn) = pump();
    // Diagnostic: confirm bytes actually flow (guest KD -> pipe, pipe -> guest).
    // Capped so it can't flood once we trust the bridge.
    if (rxn != 0 || txn != 0) && LOG_COUNT.load(Ordering::Relaxed) < 60 {
        let tot_tx = TX_TOTAL.fetch_add(txn, Ordering::Relaxed) + txn;
        let tot_rx = RX_TOTAL.fetch_add(rxn, Ordering::Relaxed) + rxn;
        LOG_COUNT.fetch_add(1, Ordering::Relaxed);
        crate::sprintln!("[kd] bridge tx+={} rx+={} (total tx={} rx={})", txn, rxn, tot_tx, tot_rx);
    } else {
        TX_TOTAL.fetch_add(txn, Ordering::Relaxed);
        RX_TOTAL.fetch_add(rxn, Ordering::Relaxed);
    }
}
