//! Intel 8042 PS/2 controller — the universal PC keyboard + auxiliary (mouse)
//! interface present on every x86 platform since the IBM PC/AT. Standard
//! component, not vendor-specific (same family as the 8254 PIT / 8259 PIC).
//!
//! Two devices share one controller:
//!   - first port  → keyboard (PNP0303), data on IRQ1
//!   - aux port    → mouse    (PNP0F13), data on IRQ12
//!
//! Both drain through the single output buffer at port 0x60; the status
//! register's AUXB bit (0x20) tells the OS which device a byte came from.
//! Controller commands arrive on port 0x64; a `0xD4` prefix routes the next
//! 0x60 write to the mouse instead of the keyboard.
//!
//! The host-side capture that feeds typed keys / mouse motion lives in
//! `devices::input`; this module is purely the emulated controller plus the
//! injection entry points that module calls.
//!
//! Ports:
//!   0x60  data       — read pops the output buffer; write is device data/cmd
//!   0x64  status/cmd — read returns status; write is a controller command

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

const DATA_PORT: u16 = 0x60;
const CMD_PORT: u16 = 0x64;

// Status register bits (read 0x64).
const ST_OBF: u8 = 1 << 0; // output buffer full (data for the CPU to read)
const ST_IBF: u8 = 1 << 1; // input buffer full (we always drain immediately)
const ST_SYS: u8 = 1 << 2; // system flag (set after a successful self-test)
const ST_A2: u8 = 1 << 3; // last write went to 0x64 (command) not 0x60 (data)
const ST_AUXB: u8 = 1 << 5; // output byte came from the aux (mouse) port

// Controller command byte bits (read/written via 0x20 / 0x60).
const CFG_KBD_INT: u8 = 1 << 0; // IRQ1 enabled
const CFG_AUX_INT: u8 = 1 << 1; // IRQ12 enabled
const CFG_SYS: u8 = 1 << 2; // system flag mirrored here
const CFG_KBD_DISABLE: u8 = 1 << 4;
const CFG_AUX_DISABLE: u8 = 1 << 5;
// Translation: when set, the controller delivers set-1 scancodes (translated
// from the keyboard's set-2). x86 OSes/firmware run with this on and expect
// set 1 — which is exactly what the input bridge produces — so default it on
// before the driver writes its own command byte.
const CFG_TRANSLATE: u8 = 1 << 6;

// Unified output FIFO. Each entry is `(is_aux << 8) | byte`; the AUXB status
// bit reflects the head entry's source. Sized generously so a burst of mouse
// packets during fast motion doesn't overflow before the guest drains it.
const FIFO_CAP: usize = 64;
const AUX_FLAG: u16 = 1 << 8;
static mut FIFO: [u16; FIFO_CAP] = [0u16; FIFO_CAP];
static FIFO_HEAD: AtomicU8 = AtomicU8::new(0);
static FIFO_TAIL: AtomicU8 = AtomicU8::new(0);

static CONFIG: AtomicU8 = AtomicU8::new(CFG_KBD_INT | CFG_SYS | CFG_TRANSLATE);
static SYS_FLAG: AtomicBool = AtomicBool::new(false);
/// True while the most recent port write went to 0x64 (command) rather than
/// 0x60 (data) — reflected in status bit 3 (A2), which some drivers inspect.
static LAST_WRITE_CMD: AtomicBool = AtomicBool::new(false);

// Pending controller-level data byte (the next 0x60 write is consumed here):
//   0x60 = new config byte   0xD1 = output-port value (A20 etc., ignored)
//   0xD4 = next byte is a command/param for the mouse
static PENDING_DATA: AtomicU8 = AtomicU8::new(0);
// Keyboard expecting a sub-parameter (after 0xED/0xF0/0xF3).
static KBD_EXPECT: AtomicU8 = AtomicU8::new(0);
// Mouse expecting a sub-parameter (after 0xF3 sample-rate / 0xE8 resolution).
static MOUSE_EXPECT: AtomicU8 = AtomicU8::new(0);
/// Mouse stream reporting enabled (0xF4). Motion packets only flow once set.
static MOUSE_REPORTING: AtomicBool = AtomicBool::new(false);
/// Sample rate the guest configured (0xF3 + value), in Hz. Default 100 — the
/// rate the input bridge emits coalesced motion packets at.
static MOUSE_SAMPLE_RATE: AtomicU32 = AtomicU32::new(100);

/// Pending edge IRQs, consumed by inject.rs. IRQ1 = keyboard, IRQ12 = mouse.
static IRQ1: AtomicBool = AtomicBool::new(false);
static IRQ12: AtomicBool = AtomicBool::new(false);

// ── Unattended "press any key to boot from CD" affordance ────────────
// The guest CD bootloader blocks until a keystroke. When veneer runs headless
// (nobody typing into the VMware console), synthesise Enter directly into the
// FIFO once scanning is enabled (0xF4). Paced by the VIRTUAL CLOCK so the
// cadence is identical in the intercepted and native-RDTSC phases.
const AUTO_CD_KEYPRESS: bool = true;
const AUTO_KEY_MIN_GAP_DIV: u64 = 6; // host_tsc_freq / 6 ≈ 167 ms
const AUTO_KEY_MAX: u32 = 4000;
static KBD_READY: AtomicBool = AtomicBool::new(false);
static AUTO_KEY_COUNT: AtomicU32 = AtomicU32::new(0);
static AUTO_KEY_LAST: AtomicU64 = AtomicU64::new(0);
static AUTO_KEY_DISARMED: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn covers(port: u16) -> bool {
    port == DATA_PORT || port == CMD_PORT
}

// ───── output FIFO ───────────────────────────────────────────────────

fn fifo_push(entry: u16) {
    let tail = FIFO_TAIL.load(Ordering::Relaxed);
    let next = (tail + 1) % FIFO_CAP as u8;
    if next == FIFO_HEAD.load(Ordering::Relaxed) {
        return; // full — drop (real controllers overflow silently)
    }
    // SAFETY: single-vCPU through the intercept dispatcher; the input-bridge
    // poll runs in the same loop between VMEXITs, never concurrently.
    unsafe { (*core::ptr::addr_of_mut!(FIFO))[tail as usize] = entry; }
    FIFO_TAIL.store(next, Ordering::Relaxed);
}

/// Push a keyboard byte and latch IRQ1 if keyboard interrupts are enabled.
fn kbd_push(b: u8) {
    fifo_push(b as u16);
    if CONFIG.load(Ordering::Relaxed) & CFG_KBD_INT != 0 {
        IRQ1.store(true, Ordering::Relaxed);
    }
}

/// Push an aux (mouse) byte and latch IRQ12 if aux interrupts are enabled.
fn aux_push(b: u8) {
    fifo_push(AUX_FLAG | b as u16);
    if CONFIG.load(Ordering::Relaxed) & CFG_AUX_INT != 0 {
        IRQ12.store(true, Ordering::Relaxed);
    }
}

fn fifo_head() -> Option<u16> {
    let head = FIFO_HEAD.load(Ordering::Relaxed);
    if head == FIFO_TAIL.load(Ordering::Relaxed) {
        return None;
    }
    Some(unsafe { (*core::ptr::addr_of!(FIFO))[head as usize] })
}

fn fifo_pop() -> u16 {
    match fifo_head() {
        None => 0,
        Some(e) => {
            let head = FIFO_HEAD.load(Ordering::Relaxed);
            FIFO_HEAD.store((head + 1) % FIFO_CAP as u8, Ordering::Relaxed);
            e
        }
    }
}

fn fifo_has_data() -> bool {
    FIFO_HEAD.load(Ordering::Relaxed) != FIFO_TAIL.load(Ordering::Relaxed)
}

fn status() -> u8 {
    let mut s = 0u8;
    if let Some(head) = fifo_head() {
        s |= ST_OBF;
        if head & AUX_FLAG != 0 {
            s |= ST_AUXB;
        }
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

// ───── port I/O ──────────────────────────────────────────────────────

/// IN from 0x60/0x64.
pub fn handle_in(port: u16) -> u8 {
    match port {
        DATA_PORT => {
            let entry = fifo_pop();
            // Re-arm the appropriate IRQ if more bytes of that kind remain so
            // the guest keeps draining.
            if let Some(next) = fifo_head() {
                let cfg = CONFIG.load(Ordering::Relaxed);
                if next & AUX_FLAG != 0 {
                    if cfg & CFG_AUX_INT != 0 { IRQ12.store(true, Ordering::Relaxed); }
                } else if cfg & CFG_KBD_INT != 0 {
                    IRQ1.store(true, Ordering::Relaxed);
                }
            }
            entry as u8
        }
        CMD_PORT => status(),
        _ => 0xFF,
    }
}

/// OUT to 0x60/0x64.
pub fn handle_out(port: u16, val: u8) {
    LAST_WRITE_CMD.store(port == CMD_PORT, Ordering::Relaxed);
    match port {
        DATA_PORT => data_write(val),
        CMD_PORT => controller_command(val),
        _ => {}
    }
}

fn data_write(val: u8) {
    match PENDING_DATA.swap(0, Ordering::Relaxed) {
        0x60 => { CONFIG.store(val, Ordering::Relaxed); return; }
        0xD1 => return, // output-port write (A20 gate etc.) — ignore
        0xD4 => { mouse_byte(val); return; } // routed to the mouse
        _ => {}
    }
    if KBD_EXPECT.swap(0, Ordering::Relaxed) != 0 {
        kbd_push(0xFA); // keyboard sub-parameter (LEDs / set / typematic)
        return;
    }
    keyboard_command(val);
}

fn controller_command(cmd: u8) {
    match cmd {
        0x20 => kbd_push(CONFIG.load(Ordering::Relaxed)), // read config byte
        0x60 => { PENDING_DATA.store(0x60, Ordering::Relaxed); } // write config byte
        0xAA => {
            // Controller self-test → 0x55, set the system flag.
            SYS_FLAG.store(true, Ordering::Relaxed);
            CONFIG.fetch_or(CFG_SYS, Ordering::Relaxed);
            kbd_push(0x55);
        }
        0xAB => kbd_push(0x00), // keyboard interface test ok
        0xA9 => kbd_push(0x00), // aux interface test ok
        0xAD => { CONFIG.fetch_or(CFG_KBD_DISABLE, Ordering::Relaxed); }
        0xAE => { CONFIG.fetch_and(!CFG_KBD_DISABLE, Ordering::Relaxed); }
        0xA7 => { CONFIG.fetch_or(CFG_AUX_DISABLE, Ordering::Relaxed); }
        0xA8 => { CONFIG.fetch_and(!CFG_AUX_DISABLE, Ordering::Relaxed); }
        0xC0 => kbd_push(0xFF), // read input port
        0xD0 => kbd_push(0x01), // read output port (A20 on)
        0xD1 => { PENDING_DATA.store(0xD1, Ordering::Relaxed); } // write output port
        0xD4 => { PENDING_DATA.store(0xD4, Ordering::Relaxed); } // next data byte → mouse
        0xFE..=0xFF => {} // pulse output / reset line — ignore
        _ => {}
    }
}

fn keyboard_command(cmd: u8) {
    match cmd {
        0xFF => { kbd_push(0xFA); kbd_push(0xAA); } // reset: ACK + BAT pass
        0xF2 => { kbd_push(0xFA); kbd_push(0xAB); kbd_push(0x83); } // identify (MF2)
        0xED | 0xF0 | 0xF3 => { kbd_push(0xFA); KBD_EXPECT.store(cmd, Ordering::Relaxed); }
        0xF4 => { KBD_READY.store(true, Ordering::Relaxed); kbd_push(0xFA); } // enable scanning
        0xF5 | 0xF6 | 0xFA => kbd_push(0xFA),
        _ => kbd_push(0xFA),
    }
}

/// A byte routed to the mouse (preceded by controller command 0xD4). Either a
/// sub-parameter for a pending command, or a fresh mouse command.
fn mouse_byte(val: u8) {
    let expect = MOUSE_EXPECT.swap(0, Ordering::Relaxed);
    if expect != 0 {
        if expect == 0xF3 && val != 0 {
            MOUSE_SAMPLE_RATE.store(val as u32, Ordering::Relaxed); // guest-set rate
        }
        aux_push(0xFA); // sample-rate / resolution value — ACK
        return;
    }
    match val {
        0xFF => { aux_push(0xFA); aux_push(0xAA); aux_push(0x00); } // reset: ACK + BAT + id
        0xF2 => { aux_push(0xFA); aux_push(0x00); } // identify → standard mouse (id 0)
        0xF3 | 0xE8 => { aux_push(0xFA); MOUSE_EXPECT.store(val, Ordering::Relaxed); } // expects a value
        0xE9 => { aux_push(0xFA); aux_push(0x00); aux_push(0x02); aux_push(0x64); } // status request
        0xF4 => { MOUSE_REPORTING.store(true, Ordering::Relaxed); aux_push(0xFA); } // enable reporting
        0xF5 => { MOUSE_REPORTING.store(false, Ordering::Relaxed); aux_push(0xFA); } // disable reporting
        0xF6 => { aux_push(0xFA); } // set defaults
        0xE6 | 0xE7 | 0xEA => aux_push(0xFA), // scaling / stream mode
        _ => aux_push(0xFA),
    }
}

// ───── injection API (called by devices::input) ──────────────────────

/// Queue a PS/2 set-1 keyboard scancode and assert IRQ1.
pub fn inject_scancode(sc: u8) {
    kbd_push(sc);
}

/// Build and queue a standard 3-byte PS/2 mouse packet from a relative motion
/// + button sample, asserting IRQ12. No-op until the guest enables reporting.
/// `dx`/`dy` are screen-space deltas (right / down positive); PS/2 reports Y
/// up-positive, so Y is inverted here.
pub fn inject_mouse_packet(dx: i32, dy: i32, left: bool, right: bool, middle: bool) {
    if !MOUSE_REPORTING.load(Ordering::Relaxed) {
        return;
    }
    let dx = dx.clamp(-255, 255);
    let dy = (-dy).clamp(-255, 255);
    let mut b0 = 0x08u8; // bit3 always 1
    if left { b0 |= 0x01; }
    if right { b0 |= 0x02; }
    if middle { b0 |= 0x04; }
    if dx < 0 { b0 |= 0x10; } // X sign
    if dy < 0 { b0 |= 0x20; } // Y sign
    aux_push(b0);
    aux_push((dx & 0xFF) as u8);
    aux_push((dy & 0xFF) as u8);
}

/// inject.rs: keyboard IRQ1 pending? / serviced.
pub fn irq1_pending() -> bool { IRQ1.load(Ordering::Relaxed) }
pub fn irq1_serviced() { IRQ1.store(false, Ordering::Relaxed); }

/// inject.rs: mouse IRQ12 pending? / serviced.
pub fn irq12_pending() -> bool { IRQ12.load(Ordering::Relaxed) }
pub fn irq12_serviced() { IRQ12.store(false, Ordering::Relaxed); }

/// devices::input: has the keyboard driver enabled scanning (0xF4)?
pub fn kbd_ready() -> bool { KBD_READY.load(Ordering::Relaxed) }

/// devices::input: the guest-configured mouse sample rate (Hz).
pub fn mouse_sample_rate() -> u32 { MOUSE_SAMPLE_RATE.load(Ordering::Relaxed) }

// ───── unattended CD-boot keypress ───────────────────────────────────

/// VMRUN loop: drive the unattended CD-boot keypress. Injects Enter when the
/// keyboard is enabled and the FIFO is drained, paced by the virtual clock.
pub fn auto_boot_key_tick() {
    if !AUTO_CD_KEYPRESS || AUTO_KEY_DISARMED.load(Ordering::Relaxed) {
        return;
    }
    if !KBD_READY.load(Ordering::Relaxed) || fifo_has_data() {
        return;
    }
    let now = crate::infra::clock::now();
    let gap = (crate::infra::clock::tsc_freq::host_tsc_freq() / AUTO_KEY_MIN_GAP_DIV).max(1);
    let last = AUTO_KEY_LAST.load(Ordering::Relaxed);
    if last != 0 && now.wrapping_sub(last) < gap {
        return;
    }
    let c = AUTO_KEY_COUNT.fetch_add(1, Ordering::Relaxed);
    if c >= AUTO_KEY_MAX {
        return;
    }
    AUTO_KEY_LAST.store(now, Ordering::Relaxed);
    inject_scancode(0x1C); // Enter make
    inject_scancode(0x9C); // Enter break
    if c < 8 {
        crate::sprintln!("[i8042] auto-keypress Enter #{} (idle prompt)", c);
    }
}

/// Stop the unattended keypress permanently (called once CD loading starts).
pub fn disarm_auto_key() {
    if !AUTO_KEY_DISARMED.swap(true, Ordering::Relaxed) {
        crate::sprintln!("[i8042] auto-keypress disarmed (CD loading)");
    }
}
