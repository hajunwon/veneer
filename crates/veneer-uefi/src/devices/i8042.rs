//! Intel 8042 PS/2 keyboard controller — the universal PC keyboard
//! interface (every x86 platform since the IBM PC/AT, every OS has a built-in
//! driver). Same standard-component family as the 8254 PIT and 8259 PIC we
//! already emulate; it is *not* a vendor-specific part.
//!
//! OVMF's SioBusDxe exposes a fixed PS/2 keyboard (PNP0303) on the ISA
//! bridge and Ps2KeyboardDxe probes this controller (self-test, reset,
//! enable). Without a responding 8042 the probe fails and the guest gets no
//! console input device, so cdboot's "press any key" / the OS installer
//! never receive a keystroke. We emulate just enough of the controller for
//! that probe to pass, then feed scancodes injected from the host keyboard
//! (see the input bridge in the VMRUN loop) into the output buffer and raise
//! IRQ1.
//!
//! Ports:
//!   0x60  data    — read pops the output buffer; write is a keyboard
//!                   command (or data for a pending controller command).
//!   0x64  status/cmd — read returns the status register; write is a
//!                   controller command.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

const DATA_PORT: u16 = 0x60;
const CMD_PORT: u16 = 0x64;

// Status register bits (read 0x64).
const ST_OBF: u8 = 1 << 0; // output buffer full (data for the CPU to read)
const ST_IBF: u8 = 1 << 1; // input buffer full (we always drain immediately)
const ST_SYS: u8 = 1 << 2; // system flag (set after a successful self-test)
const ST_A2: u8 = 1 << 3; // last write went to 0x64 (command) not 0x60 (data)

// Controller command byte bits (the "command byte" read/written via 0x20/0x60).
const CFG_KBD_INT: u8 = 1 << 0; // IRQ1 enabled
const CFG_SYS: u8 = 1 << 2; // system flag mirrored here
const CFG_KBD_DISABLE: u8 = 1 << 4;
// Translation: when set, the controller delivers set-1 scancodes (translated
// from the keyboard's set-2). x86 OSes/firmware run with this on and expect
// set 1 — which is exactly what inject_uefi_key() produces — so default it on
// for consistency before the driver writes its own command byte.
const CFG_TRANSLATE: u8 = 1 << 6;

// A small output FIFO. Keyboard bursts (reset → 0xFA 0xAA, identify → 3
// bytes) and typed scancodes queue here; the guest pops them via 0x60.
const FIFO_CAP: usize = 32;
static mut FIFO: [u8; FIFO_CAP] = [0u8; FIFO_CAP];
static FIFO_HEAD: AtomicU8 = AtomicU8::new(0);
static FIFO_TAIL: AtomicU8 = AtomicU8::new(0);

static CONFIG: AtomicU8 = AtomicU8::new(CFG_KBD_INT | CFG_SYS | CFG_TRANSLATE);
static SYS_FLAG: AtomicBool = AtomicBool::new(false);
/// True while the most recent port write went to 0x64 (command) rather than
/// 0x60 (data) — reflected in status bit 3 (A2), which some drivers inspect.
static LAST_WRITE_CMD: AtomicBool = AtomicBool::new(false);

// Pending multi-byte controller/keyboard command state. 0 = none.
//   0x60 = next data byte is the new config byte
//   0xD1 = next data byte is the output-port value (A20 etc., ignored)
//   0xED/0xF0/0xF3 = next data byte is a keyboard sub-parameter (ACK it)
static PENDING_DATA: AtomicU8 = AtomicU8::new(0);

/// IRQ1 latched while the output buffer holds a byte and the controller's
/// keyboard interrupt is enabled. Edge-injected by inject.rs.
static IRQ1: AtomicBool = AtomicBool::new(false);

// ── Unattended "press any key to boot from CD" affordance ────────────
// The guest CD bootloader blocks until a keystroke. When veneer runs
// headless (nobody typing into the VMware console for the host bridge to
// forward), synthesise Enter directly into the FIFO. To avoid corrupting
// Ps2KeyboardDxe's init handshake, we only inject AFTER scanning is enabled
// (0xF4, sets KBD_READY) and the output buffer is drained. Pacing is by the
// VIRTUAL CLOCK, not VMRUN-iteration counts: the old iteration pace fired ~8x
// too slowly once RDTSC went native (exits become sparse, ~1 kHz) and missed
// cdboot.efi's ~5 s "press any key to boot from CD" countdown entirely. A
// wall-clock gap behaves identically in the intercepted and native phases.
// Stays armed across the El Torito probe AND cdboot's own prompt; disarmed
// once the OS loader runs in low RAM (dispatcher), so no stray Enter reaches
// the OS installer. In-hypervisor, not an external input-automation script.
const AUTO_CD_KEYPRESS: bool = true;
/// Minimum virtual-clock spacing between synthetic Enters, as a divisor of the
/// host TSC frequency: host_tsc_freq / 6 ≈ 167 ms.
const AUTO_KEY_MIN_GAP_DIV: u64 = 6;
/// Flood-safety cap only. Far above what any prompt needs — the real stop is
/// `disarm_auto_key()` once the OS loader executes. (Was 40, which the firmware
/// idle prompts exhausted *before* cdboot's prompt ever appeared.)
const AUTO_KEY_MAX: u32 = 4000;
static KBD_READY: AtomicBool = AtomicBool::new(false);
static AUTO_KEY_COUNT: AtomicU32 = AtomicU32::new(0);
/// clock::now() value at the last synthetic Enter (0 = none yet).
static AUTO_KEY_LAST: AtomicU64 = AtomicU64::new(0);
static AUTO_KEY_DISARMED: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn covers(port: u16) -> bool {
    port == DATA_PORT || port == CMD_PORT
}

fn fifo_push(b: u8) {
    let tail = FIFO_TAIL.load(Ordering::Relaxed);
    let next = (tail + 1) % FIFO_CAP as u8;
    if next == FIFO_HEAD.load(Ordering::Relaxed) {
        return; // full — drop (real controllers also overflow silently)
    }
    // SAFETY: single-vCPU through the intercept dispatcher; the input-bridge
    // poll runs in the same loop between VMEXITs, never concurrently.
    unsafe { (*core::ptr::addr_of_mut!(FIFO))[tail as usize] = b; }
    FIFO_TAIL.store(next, Ordering::Relaxed);
    if CONFIG.load(Ordering::Relaxed) & CFG_KBD_INT != 0 {
        IRQ1.store(true, Ordering::Relaxed);
    }
}

fn fifo_pop() -> u8 {
    let head = FIFO_HEAD.load(Ordering::Relaxed);
    if head == FIFO_TAIL.load(Ordering::Relaxed) {
        return 0x00; // empty
    }
    let b = unsafe { (*core::ptr::addr_of!(FIFO))[head as usize] };
    FIFO_HEAD.store((head + 1) % FIFO_CAP as u8, Ordering::Relaxed);
    b
}

fn fifo_has_data() -> bool {
    FIFO_HEAD.load(Ordering::Relaxed) != FIFO_TAIL.load(Ordering::Relaxed)
}

fn status() -> u8 {
    let mut s = 0u8;
    if fifo_has_data() {
        s |= ST_OBF;
    }
    if SYS_FLAG.load(Ordering::Relaxed) {
        s |= ST_SYS;
    }
    if LAST_WRITE_CMD.load(Ordering::Relaxed) {
        s |= ST_A2;
    }
    let _ = ST_IBF;
    s
}

/// IN from 0x60/0x64.
pub fn handle_in(port: u16) -> u8 {
    match port {
        DATA_PORT => {
            let b = fifo_pop();
            // Dropping OBF after the read is implicit (fifo emptied). Re-arm
            // IRQ1 if more bytes remain so the guest keeps draining.
            if fifo_has_data() && CONFIG.load(Ordering::Relaxed) & CFG_KBD_INT != 0 {
                IRQ1.store(true, Ordering::Relaxed);
            }
            b
        }
        CMD_PORT => status(),
        _ => 0xFF,
    }
}

/// OUT to 0x60/0x64.
pub fn handle_out(port: u16, val: u8) {
    LAST_WRITE_CMD.store(port == CMD_PORT, Ordering::Relaxed);
    match port {
        DATA_PORT => {
            let pending = PENDING_DATA.swap(0, Ordering::Relaxed);
            match pending {
                0x60 => {
                    // New controller config byte.
                    CONFIG.store(val, Ordering::Relaxed);
                    return;
                }
                0xD1 => return, // output-port write (A20 gate etc.) — ignore
                0xED | 0xF0 | 0xF3 => {
                    // Keyboard sub-parameter (LEDs / scancode set / typematic).
                    fifo_push(0xFA);
                    return;
                }
                _ => {}
            }
            // Otherwise this is a keyboard command.
            keyboard_command(val);
        }
        CMD_PORT => controller_command(val),
        _ => {}
    }
}

fn controller_command(cmd: u8) {
    match cmd {
        0x20 => fifo_push(CONFIG.load(Ordering::Relaxed)), // read config byte
        0x60 => { PENDING_DATA.store(0x60, Ordering::Relaxed); } // write config byte
        0xAA => {
            // Controller self-test → 0x55, and set the system flag.
            SYS_FLAG.store(true, Ordering::Relaxed);
            CONFIG.fetch_or(CFG_SYS, Ordering::Relaxed);
            fifo_push(0x55);
        }
        0xAB => fifo_push(0x00),      // keyboard interface test ok
        0xA9 => fifo_push(0x00),      // aux interface test ok
        0xAD => { CONFIG.fetch_or(CFG_KBD_DISABLE, Ordering::Relaxed); } // disable kbd
        0xAE => { CONFIG.fetch_and(!CFG_KBD_DISABLE, Ordering::Relaxed); } // enable kbd
        0xA7 | 0xA8 => {}             // disable/enable aux (no mouse yet)
        0xC0 => fifo_push(0xFF),      // read input port
        0xD0 => fifo_push(0x01),      // read output port (A20 on)
        0xD1 => { PENDING_DATA.store(0xD1, Ordering::Relaxed); } // write output port
        0xFE..=0xFF => {}             // pulse output / reset line — ignore
        _ => {}
    }
}

fn keyboard_command(cmd: u8) {
    match cmd {
        0xFF => {
            // Reset: ACK then Basic Assurance Test pass.
            fifo_push(0xFA);
            fifo_push(0xAA);
        }
        0xF2 => {
            // Identify: ACK + MF2 keyboard id (0xAB 0x83).
            fifo_push(0xFA);
            fifo_push(0xAB);
            fifo_push(0x83);
        }
        0xED | 0xF0 | 0xF3 => {
            // Set LEDs / scancode set / typematic — ACK, expect one data byte.
            fifo_push(0xFA);
            PENDING_DATA.store(cmd, Ordering::Relaxed);
        }
        0xF4 => {
            // Enable scanning — Ps2KeyboardDxe's last init step. After this
            // the keyboard is live and the boot prompt can receive keys.
            KBD_READY.store(true, Ordering::Relaxed);
            fifo_push(0xFA);
        }
        0xF5 | 0xF6 | 0xFA => fifo_push(0xFA), // disable/defaults
        _ => fifo_push(0xFA),                          // ACK anything else
    }
}

/// Queue a PS/2 scancode (set 1) from the host-keyboard bridge and assert
/// IRQ1. Make/break codes are pushed as-is by the caller.
pub fn inject_scancode(sc: u8) {
    fifo_push(sc);
}

// PS/2 scan-code set 1 make codes, indexed a..z and 0..9.
const SET1_AZ: [u8; 26] = [
    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32,
    0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
];
const SET1_09: [u8; 10] = [0x0B, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];

/// ASCII → (set-1 make code, needs-shift). Covers the keys boot menus and the
/// OS installer use; extend as needed.
fn ascii_to_set1(c: u8) -> Option<(u8, bool)> {
    match c {
        b'a'..=b'z' => Some((SET1_AZ[(c - b'a') as usize], false)),
        b'A'..=b'Z' => Some((SET1_AZ[(c - b'A') as usize], true)),
        b'0'..=b'9' => Some((SET1_09[(c - b'0') as usize], false)),
        b' ' => Some((0x39, false)),
        b'\r' | b'\n' => Some((0x1C, false)), // Enter
        0x08 => Some((0x0E, false)),          // Backspace
        b'\t' => Some((0x0F, false)),         // Tab
        0x1B => Some((0x01, false)),          // Esc
        b'-' => Some((0x0C, false)),
        b'=' => Some((0x0D, false)),
        b'.' => Some((0x34, false)),
        b',' => Some((0x33, false)),
        b'/' => Some((0x35, false)),
        b'\\' => Some((0x2B, false)),
        b';' => Some((0x27, false)),
        b':' => Some((0x27, true)),
        _ => None,
    }
}

const LSHIFT_MAKE: u8 = 0x2A;
const LSHIFT_BREAK: u8 = 0xAA;

/// Translate one UEFI keystroke (raw EFI_INPUT_KEY: `scan` = EFI scan code,
/// `unicode` = UTF-16 char) into PS/2 set-1 scancodes and queue make+break.
/// The host-keyboard bridge in the VMRUN loop feeds keystrokes here.
pub fn inject_uefi_key(scan: u16, unicode: u16) {
    if scan != 0 {
        // Navigation / function keys. Extended (0xE0-prefixed) for the
        // grey arrow/nav cluster.
        let (code, ext) = match scan {
            0x01 => (0x48, true),  // Up
            0x02 => (0x50, true),  // Down
            0x03 => (0x4D, true),  // Right
            0x04 => (0x4B, true),  // Left
            0x05 => (0x47, true),  // Home
            0x06 => (0x4F, true),  // End
            0x07 => (0x52, true),  // Insert
            0x08 => (0x53, true),  // Delete
            0x09 => (0x49, true),  // Page Up
            0x0A => (0x51, true),  // Page Down
            0x0B..=0x14 => (0x3B + (scan - 0x0B) as u8, false), // F1..F10
            0x15 => (0x57, false), // F11
            0x16 => (0x58, false), // F12
            0x17 => (0x01, false), // Esc
            _ => return,
        };
        if ext {
            inject_scancode(0xE0);
            inject_scancode(code);
            inject_scancode(0xE0);
            inject_scancode(code | 0x80);
        } else {
            inject_scancode(code);
            inject_scancode(code | 0x80);
        }
        return;
    }
    if let Some((code, shift)) = ascii_to_set1(unicode as u8) {
        if shift {
            inject_scancode(LSHIFT_MAKE);
        }
        inject_scancode(code);
        inject_scancode(code | 0x80);
        if shift {
            inject_scancode(LSHIFT_BREAK);
        }
    }
}

/// Host-keyboard bridge: drain every keystroke buffered in the host UEFI
/// console (VMware's keyboard, reachable because this guest path never calls
/// ExitBootServices) and feed it into the emulated controller. Called sparsely
/// from the VMRUN loop — a UEFI key read costs far more than a single VMEXIT.
pub fn poll_host_input() {
    use uefi::proto::console::text::Key;
    while let Ok(Some(key)) = uefi::system::with_stdin(|s| s.read_key()) {
        match key {
            Key::Printable(c) => {
                let ch: char = c.into();
                inject_uefi_key(0, ch as u16);
            }
            Key::Special(sc) => inject_uefi_key(sc.0, 0),
        }
    }
}

/// VMRUN loop: drive the unattended CD-boot keypress. Injects Enter when the
/// keyboard is enabled (0xF4) and the FIFO is drained — i.e. the guest is
/// parked waiting for a key — paced by the virtual clock so the cadence is the
/// same whether RDTSC is intercepted or native. No-op after `disarm_auto_key`.
pub fn auto_boot_key_tick() {
    if !AUTO_CD_KEYPRESS || AUTO_KEY_DISARMED.load(Ordering::Relaxed) {
        return;
    }
    // Not past keyboard init, or the guest is still draining a response — never
    // interleave a synthetic key with the Ps2KeyboardDxe handshake.
    if !KBD_READY.load(Ordering::Relaxed) || fifo_has_data() {
        return;
    }
    // Wall-clock pace: at most one Enter per ~167 ms of virtual time. Regime
    // independent — a 5 s native countdown gets dozens of attempts, the first
    // of which dismisses the prompt, while a fast intercepted phase still can't
    // flood (the gap is real time, not exits).
    let now = crate::clock::now();
    let gap = (crate::clock::tsc_freq::host_tsc_freq() / AUTO_KEY_MIN_GAP_DIV).max(1);
    let last = AUTO_KEY_LAST.load(Ordering::Relaxed);
    if last != 0 && now.wrapping_sub(last) < gap {
        return;
    }
    let c = AUTO_KEY_COUNT.fetch_add(1, Ordering::Relaxed);
    if c >= AUTO_KEY_MAX {
        return;
    }
    AUTO_KEY_LAST.store(now, Ordering::Relaxed);
    // Enter make + break — satisfies "press any key to boot from CD".
    inject_scancode(0x1C);
    inject_scancode(0x9C);
    if c < 8 {
        crate::sprintln!("[i8042] auto-keypress Enter #{} (idle prompt)", c);
    }
}

/// Stop the unattended keypress permanently. Called once CD loading starts
/// (we're past the prompt) so no synthetic keys reach the OS installer.
pub fn disarm_auto_key() {
    if !AUTO_KEY_DISARMED.swap(true, Ordering::Relaxed) {
        crate::sprintln!("[i8042] auto-keypress disarmed (CD loading)");
    }
}

/// inject.rs: is a keyboard IRQ1 pending?
pub fn irq1_pending() -> bool {
    IRQ1.load(Ordering::Relaxed)
}

/// inject.rs: IRQ1 delivered.
pub fn irq1_serviced() {
    IRQ1.store(false, Ordering::Relaxed);
}
