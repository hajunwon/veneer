//! IOIO intercept handler — guest executed an in/out instruction.
//!
//! AMD APM Vol 2 Table 15-3 — `exit_info_1` decode:
//!   bit  0    : TYPE          0 = OUT, 1 = IN
//!   bit  2    : STR           string instruction (ins/outs)
//!   bit  3    : REP           repeated
//!   bit  4..6 : SZ8/16/32     operand size
//!   bit  7..9 : A16/A32/A64   address size
//!   bit 16..31: PORT          16-bit port number
//!
//! `exit_info_2` carries the RIP of the *next* instruction (AMD always
//! provides this for IOIO), so we don't have to compute the instruction
//! length ourselves.

use core::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};

use crate::hypervisor::svm::gprs::GuestGprs;
use crate::sprint;
use crate::hypervisor::svm::vmcb::Vmcb;

use super::Action;
use crate::hardware::devices::fwcfg;
use crate::hardware::devices::registry;

/// COM1 IO range. `0x3F8` is data, `0x3F9..0x3FF` are control/status. A
/// Linux guest running with `console=ttyS0,115200` writes printk through
/// the data port; we *line-buffer* those bytes and flush each line as a
/// `[guest] ...` prefix so they stay readable alongside our sprintln!.
///
/// The control registers are a coherent 16550 model — see `com1` below. A
/// bare stub (LSR fixed, everything else 0xFF) failed OVMF PciSioSerialDxe's
/// hardware-verify *loopback* test, which is what produced "Create SIO child
/// serial device - Device Error": the driver sets MCR.LOOP, writes a byte to
/// THR, then expects to read it back from RBR with the modem-control bits
/// echoed in MSR. Without a working scratch register + loopback path the
/// verify aborts and no SIO child is created.
const COM1_BASE: u16 = 0x3F8;
const COM1_END:  u16 = 0x3FF;

// 16550 register offsets from COM1_BASE (DLAB=0 unless noted).
const R_RBR_THR: u16 = 0; // RBR (read) / THR (write); DLL when DLAB=1
const R_IER_DLM: u16 = 1; // IER; DLM when DLAB=1
const R_IIR_FCR: u16 = 2; // IIR (read) / FCR (write)
const R_LCR:     u16 = 3; // line control (bit 7 = DLAB)
const R_MCR:     u16 = 4; // modem control (bit 4 = LOOP)
const R_LSR:     u16 = 5; // line status (RO)
const R_MSR:     u16 = 6; // modem status (RO)
const R_SCR:     u16 = 7; // scratch (RW)

#[inline]
fn in_com1_range(port: u16) -> bool {
    port >= COM1_BASE && port <= COM1_END
}

/// 16550 UART register file for COM1. Only one guest vCPU drives the
/// intercept path (see LINE_BUF doc), so plain atomics with Relaxed
/// ordering model the chip without locking. The model is deliberately
/// conservative: it never raises an interrupt (IER is honoured for
/// read-back only) and veneer's own serial logging keeps owning the
/// real TX, so the guest sees a quiescent-but-fully-present 16550A.
mod com1 {
    use super::*;

    pub static IER: AtomicU8 = AtomicU8::new(0);
    pub static LCR: AtomicU8 = AtomicU8::new(0x03); // 8N1, DLAB=0
    pub static MCR: AtomicU8 = AtomicU8::new(0);
    pub static SCR: AtomicU8 = AtomicU8::new(0);
    pub static FCR: AtomicU8 = AtomicU8::new(0); // shadow of last FCR write
    pub static DLL: AtomicU8 = AtomicU8::new(0x01); // divisor latch low (115200)
    pub static DLM: AtomicU8 = AtomicU8::new(0x00); // divisor latch high
    /// Byte captured in internal loopback (MCR.LOOP) until the guest reads
    /// it back from RBR. 0x100 = empty.
    pub static LOOPBACK_RX: AtomicU64 = AtomicU64::new(0x100);

    const LCR_DLAB: u8 = 1 << 7;
    const MCR_LOOP: u8 = 1 << 4;

    #[inline]
    fn dlab() -> bool {
        LCR.load(Ordering::Relaxed) & LCR_DLAB != 0
    }
    #[inline]
    pub fn loopback() -> bool {
        MCR.load(Ordering::Relaxed) & MCR_LOOP != 0
    }

    /// Read a COM1 register, returning the 8-bit value as u64 for the IOIO
    /// path. Outside internal loopback the receive path is empty (a real
    /// idle port with nothing connected), so RBR reads return 0.
    pub fn read(off: u16) -> u64 {
        match off {
            R_RBR_THR => {
                if dlab() {
                    DLL.load(Ordering::Relaxed) as u64
                } else if loopback() {
                    // Return (and consume) any byte the loopback captured.
                    let v = LOOPBACK_RX.swap(0x100, Ordering::Relaxed);
                    if v <= 0xFF { v } else { 0 }
                } else {
                    0 // no device feeding RX; reads return 0
                }
            }
            R_IER_DLM => {
                if dlab() { DLM.load(Ordering::Relaxed) as u64 }
                else { IER.load(Ordering::Relaxed) as u64 }
            }
            R_IIR_FCR => {
                // IIR: bits 7:6 = FIFO enabled (11 when FCR.FIFOE set),
                // bits 3:0 = interrupt id; 0x01 = "no interrupt pending".
                let fifo = if FCR.load(Ordering::Relaxed) & 1 != 0 { 0xC0 } else { 0x00 };
                (fifo | 0x01) as u64
            }
            R_LCR => LCR.load(Ordering::Relaxed) as u64,
            R_MCR => MCR.load(Ordering::Relaxed) as u64,
            R_LSR => {
                // bit 0 DR (data ready) — set only when loopback has a byte.
                // bits 5 THRE + 6 TEMT always set (transmitter idle/empty) so
                // the guest never spins waiting to send.
                let dr = if loopback() && LOOPBACK_RX.load(Ordering::Relaxed) <= 0xFF { 1 } else { 0 };
                (dr | 0x60) as u64
            }
            R_MSR => {
                // In loopback the modem-control outputs feed the modem-status
                // inputs (16550 datasheet): MCR DTR(0)→DSR(5), RTS(1)→CTS(4),
                // OUT1(2)→RI(6), OUT2(3)→DCD(7). PciSioSerialDxe's verify sets
                // RTS|DTR and checks they appear in MSR.
                if loopback() {
                    let m = MCR.load(Ordering::Relaxed);
                    let dsr = (m & 0x01) << 5; // DTR → DSR
                    let cts = (m & 0x02) << 3; // RTS → CTS
                    let ri  = (m & 0x04) << 4; // OUT1 → RI
                    let dcd = (m & 0x08) << 4; // OUT2 → DCD
                    (dsr | cts | ri | dcd) as u64
                } else {
                    // No real modem attached: CTS+DSR+DCD asserted (a typical
                    // "ready" wiring), no RI, no delta bits.
                    0xB0
                }
            }
            R_SCR => SCR.load(Ordering::Relaxed) as u64,
            _ => 0xFF,
        }
    }

    /// Write a COM1 register. Returns Some(byte) when a data byte should be
    /// emitted to veneer's serial log (THR write outside loopback).
    pub fn write(off: u16, val: u8) -> Option<u8> {
        match off {
            R_RBR_THR => {
                if dlab() {
                    DLL.store(val, Ordering::Relaxed);
                    None
                } else if loopback() {
                    // Internal loopback: THR feeds RBR, nothing goes on the wire.
                    LOOPBACK_RX.store(val as u64, Ordering::Relaxed);
                    None
                } else {
                    Some(val) // real transmit → guest serial line buffer
                }
            }
            R_IER_DLM => {
                if dlab() { DLM.store(val, Ordering::Relaxed); }
                else { IER.store(val, Ordering::Relaxed); }
                None
            }
            R_IIR_FCR => { FCR.store(val, Ordering::Relaxed); None }
            R_LCR => { LCR.store(val, Ordering::Relaxed); None }
            R_MCR => { MCR.store(val & 0x1F, Ordering::Relaxed); None }
            R_SCR => { SCR.store(val, Ordering::Relaxed); None }
            // LSR / MSR are read-only; writes ignored.
            _ => None,
        }
    }
}

// ── guest ttyS0 line buffer ───────────────────────────────────────────
//
// kernel printk arrives one byte at a time through 0x3F8. Writing each
// byte through our own host serial as it comes interleaves with veneer
// sprintln output, making the log unreadable. We accumulate up to
// LINE_CAP bytes; on '\n', when the buffer fills, or on the very next
// printk byte after a long silence, we emit one neat
// `[guest] <line>` row.
//
// Safe because veneer is strictly single-vCPU through the intercept
// dispatcher. If we ever fan an OS guest out across multiple host
// CPUs concurrently this needs per-vCPU buffers.
const LINE_CAP: usize = 256;
static mut LINE_BUF: [u8; LINE_CAP] = [0u8; LINE_CAP];
static LINE_LEN: AtomicUsize = AtomicUsize::new(0);

fn guest_serial_putc(b: u8) {
    let mut len = LINE_LEN.load(Ordering::Relaxed);
    // Drop CR; we add our own newline at flush.
    if b == b'\r' {
        return;
    }
    if b == b'\n' || len >= LINE_CAP {
        flush_guest_line();
        len = 0;
    }
    if b != b'\n' && (32..=126).contains(&b) {
        unsafe { LINE_BUF[len] = b; }
        LINE_LEN.store(len + 1, Ordering::Relaxed);
    }
    if b == b'\n' && len > 0 {
        // already flushed above, len is now 0
    }
}

fn flush_guest_line() {
    let len = LINE_LEN.swap(0, Ordering::Relaxed);
    if len == 0 {
        return;
    }
    // SAFETY: single-vCPU access guaranteed (see LINE_BUF doc above).
    #[allow(static_mut_refs)]
    let slice = unsafe { &LINE_BUF[..len] };
    if let Ok(s) = core::str::from_utf8(slice) {
        crate::sprintln!("[guest] {}", s);
    } else {
        // Non-UTF-8 bytes (rare) -- hex-dump.
        sprint!("[guest] <bin:");
        for b in slice {
            sprint!(" {:02X}", b);
        }
        crate::sprintln!(">");
    }
}

/// "No device responds on this port" — what a real ISA bus reads when
/// no chip drives the lines. Returning this for unconfigured ports is
/// indistinguishable from bare metal; previously we returned a custom
/// sentinel (0xDEAD0BAD) which itself fingerprinted veneer to anyone
/// inspecting unexpected port reads.
pub const SYNTH_IO_DWORD: u64 = 0xFFFF_FFFF;

/// VMware backdoor port (`port 0x5658`, "VX"). Probing software writes the
/// magic `0x564D5868` ("VMXh") to EAX with this port; on a real VMware host
/// the IN response returns the magic back in EBX. We pretend the port is
/// dead so a Vanguard-style anti-cheat doesn't conclude "running in VMware".
const VMWARE_BACKDOOR_PORT: u16 = 0x5658;

static IO_TRACE: AtomicUsize = AtomicUsize::new(0);

/// Host base of guest low RAM, set by the OVMF-guest entry. Used to walk
/// DS:[RSI] / ES:[RDI] for string I/O (INS/OUTS).
static GUEST_RAM_BASE: AtomicU64 = AtomicU64::new(0);

pub fn set_guest_ram_base(base: u64) {
    GUEST_RAM_BASE.store(base, Ordering::Release);
}

pub fn guest_ram_base() -> u64 {
    GUEST_RAM_BASE.load(Ordering::Acquire)
}

pub unsafe fn handle(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    let c = unsafe { &(*vmcb).control };
    let s = unsafe { &mut (*vmcb).state };

    let is_in = (c.exit_info_1 & 0x1) != 0;
    let port = ((c.exit_info_1 >> 16) & 0xFFFF) as u16;
    let width: u8 = if c.exit_info_1 & (1 << 4) != 0 {
        1
    } else if c.exit_info_1 & (1 << 5) != 0 {
        2
    } else {
        4
    };

    // String I/O (INS/OUTS, incl. REP). The scalar path below assumes the
    // operand is in RAX; string ops stream through DS:[RSI] / ES:[RDI]
    // instead. OVMF's DEBUG output is REP OUTSB to 0x402, so capturing it
    // means walking guest memory rather than reading RAX.
    if c.exit_info_1 & (1 << 2) != 0 {
        let is_rep = c.exit_info_1 & (1 << 3) != 0;
        let df = (s.rflags & (1 << 10)) != 0;
        let step = width as u64;
        let delta = if df { step.wrapping_neg() } else { step };
        let count = if is_rep { gprs.rcx.min(65536) } else { 1 };
        if is_in {
            // INS: store the port's read value into ES:[RDI]. No emulated
            // device uses string IN, so a "no device" fill is sufficient.
            let mut rdi = gprs.rdi;
            let from_fwcfg = port == fwcfg::DATA_PORT;
            for _ in 0..count {
                if let Some(dst) = crate::guest_mem::to_host(rdi) {
                    let dst = dst as *mut u8;
                    unsafe {
                        for b in 0..width as usize {
                            *dst.add(b) = if from_fwcfg { fwcfg::next_byte() } else { 0xFF };
                        }
                    }
                }
                rdi = rdi.wrapping_add(delta);
            }
            gprs.rdi = rdi;
        } else {
            // OUTS: stream DS:[RSI] to the port. Only the debug/serial
            // ports consume the bytes; everything else is drained.
            let mut rsi = gprs.rsi;
            let forward = port == 0x402 || port == COM1_BASE; // 0x402 debugcon, 0x3F8 THR
            for _ in 0..count {
                if forward {
                    if let Some(src) = crate::guest_mem::to_host(rsi) {
                        let src = src as *const u8;
                        unsafe { for b in 0..width as usize { guest_serial_putc(*src.add(b)); } }
                    }
                }
                rsi = rsi.wrapping_add(delta);
            }
            gprs.rsi = rsi;
        }
        if is_rep {
            gprs.rcx = 0;
        }
        s.rip = c.exit_info_2;
        return Action::Resume;
    }

    // Diagnostic: trace fw_cfg (0x510-0x51F) + any high/unusual port so we
    // can see how OVMF probes for QEMU paravirt interfaces it expects.
    {
        let n = IO_TRACE.fetch_add(1, Ordering::Relaxed);
        if n < 80 && (port >= 0x500 || (0x80..0x90).contains(&port)) {
            crate::sprintln!("[io] {} port=0x{:X}", if is_in { "IN " } else { "OUT" }, port);
        }
    }

    if is_in {
        if port == VMWARE_BACKDOOR_PORT {
            // The host VMware backdoor echoes "VMXh" in EBX; ours does not.
            s.rax = 0;
            gprs.rbx = 0;
            gprs.rcx = 0;
            gprs.rdx = 0;
        } else if in_com1_range(port) {
            // 16550 COM1 — loopback/scratch/divisor model in `com1`.
            s.rax = com1::read(port - COM1_BASE);
        } else if port == 0x402 {
            // EDK2 debugcon probe expects the 0xE9 magic back.
            s.rax = 0xE9;
        } else if let Some(d) = registry::find_port(port) {
            s.rax = d.read(port, width);
        } else {
            s.rax = SYNTH_IO_DWORD;
        }
    } else {
        // OUT — the COM1 serial line buffer and the 0x402 debugcon feed our
        // `[guest]` log output, so they stay here; everything else routes to
        // the port-device registry. Unhandled ports drop on the floor.
        if in_com1_range(port) {
            if let Some(byte) = com1::write(port - COM1_BASE, s.rax as u8) {
                guest_serial_putc(byte);
            }
        } else if port == 0x402 {
            guest_serial_putc(s.rax as u8);
        } else if let Some(d) = registry::find_port(port) {
            d.write(port, s.rax, width);
        }
    }

    // AMD writes RIP of next instruction into exit_info_2 for IOIO.
    s.rip = c.exit_info_2;
    Action::Resume
}
