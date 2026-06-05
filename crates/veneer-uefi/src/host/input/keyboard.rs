//! Host keyboard capture → emulated 8042 keyboard.
//!
//! Primary source is the UEFI Simple Text Input **Ex** protocol: unlike plain
//! ConIn it reports the modifier (Ctrl/Alt/Shift) state alongside each key, and
//! delivers raw keystrokes rather than the firmware's cooked, repeat-throttled
//! stream — so typing feels responsive and Ctrl/Alt chords work. The crate
//! doesn't wrap Ex, so we declare the raw protocol and cache its interface
//! pointer (firmware-resident, never closed). If Ex can't be opened we fall
//! back to plain ConIn (no modifiers).
//!
//! Translation targets PS/2 scan-code set 1, which the 8042's translate bit
//! hands the guest. Modifier chords are synthesised by bracketing the key's
//! make/break with the modifier's make/break.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use uefi::{guid, Guid, Status};

use veneer_vmm::hardware::devices::i8042;

// ───── SimpleTextInputEx raw protocol ────────────────────────────────

#[repr(C)]
struct InputKey {
    scan_code: u16,
    unicode_char: u16,
}

#[repr(C)]
struct KeyState {
    shift_state: u32,
    toggle_state: u8,
}

#[repr(C)]
struct KeyData {
    key: InputKey,
    key_state: KeyState,
}

#[repr(C)]
struct TextInputEx {
    reset: unsafe extern "efiapi" fn(*mut TextInputEx, bool) -> Status,
    read_key_stroke_ex: unsafe extern "efiapi" fn(*mut TextInputEx, *mut KeyData) -> Status,
    wait_for_key_ex: *mut c_void,
    set_state: *mut c_void,
    register_key_notify: *mut c_void,
    unregister_key_notify: *mut c_void,
}

const TEXT_INPUT_EX_GUID: Guid = guid!("dd9e7534-7762-4698-8c14-f58517a625aa");

// KeyShiftState bits (UEFI spec § Simple Text Input Ex).
const SHIFT_STATE_VALID: u32 = 0x8000_0000;
const RIGHT_SHIFT: u32 = 0x0000_0001;
const LEFT_SHIFT: u32 = 0x0000_0002;
const RIGHT_CONTROL: u32 = 0x0000_0004;
const LEFT_CONTROL: u32 = 0x0000_0008;
const RIGHT_ALT: u32 = 0x0000_0010;
const LEFT_ALT: u32 = 0x0000_0020;

static EX_PTR: AtomicPtr<TextInputEx> = AtomicPtr::new(core::ptr::null_mut());
static EX_TRIED: AtomicBool = AtomicBool::new(false);

/// Locate + open the Ex protocol once, caching its raw interface pointer. The
/// interface is firmware-resident, so we keep it open for the process lifetime
/// (veneer never calls ExitBootServices). Returns None if Ex is unavailable.
fn ex_protocol() -> Option<*mut TextInputEx> {
    if !EX_TRIED.swap(true, Ordering::Relaxed) {
        if let Ok(buf) =
            uefi::boot::locate_handle_buffer(uefi::boot::SearchType::ByProtocol(&TEXT_INPUT_EX_GUID))
        {
            if let Some(&handle) = buf.first() {
                #[uefi::proto::unsafe_protocol("dd9e7534-7762-4698-8c14-f58517a625aa")]
                #[repr(transparent)]
                struct ExWrapper(TextInputEx);

                if let Ok(scoped) = uefi::boot::open_protocol_exclusive::<ExWrapper>(handle) {
                    let raw = &scoped.0 as *const TextInputEx as *mut TextInputEx;
                    core::mem::forget(scoped); // keep the protocol open
                    EX_PTR.store(raw, Ordering::Relaxed);
                }
            }
        }
    }
    let p = EX_PTR.load(Ordering::Relaxed);
    if p.is_null() { None } else { Some(p) }
}

/// Drain every buffered host keystroke and inject it into the emulated 8042.
pub fn poll() {
    // Bounded drain per poll: a misbehaving firmware that always returns a key
    // must not spin the VMRUN loop. 64 keys/poll is far above any real burst.
    const MAX_DRAIN: u32 = 64;
    if let Some(ex) = ex_protocol() {
        let mut kd = KeyData {
            key: InputKey { scan_code: 0, unicode_char: 0 },
            key_state: KeyState { shift_state: 0, toggle_state: 0 },
        };
        let mut n = 0;
        while n < MAX_DRAIN {
            let st = unsafe { ((*ex).read_key_stroke_ex)(ex, &mut kd) };
            if st != Status::SUCCESS {
                break; // NOT_READY (no key) or error
            }
            inject(kd.key.scan_code, kd.key.unicode_char, kd.key_state.shift_state);
            n += 1;
        }
        return;
    }
    // Fallback: plain ConIn, no modifier state.
    let mut n = 0;
    while n < MAX_DRAIN {
        match uefi::system::with_stdin(|s| s.read_key()) {
            Ok(Some(key)) => {
                use uefi::proto::console::text::Key;
                match key {
                    Key::Printable(c) => inject(0, u16::from(c), 0),
                    Key::Special(sc) => inject(sc.0, 0, 0),
                }
            }
            _ => break,
        }
        n += 1;
    }
}

// ───── translation: UEFI key (+modifiers) → set-1 scancodes ──────────

const LCTRL_MAKE: u8 = 0x1D;
const LALT_MAKE: u8 = 0x38;
const LSHIFT_MAKE: u8 = 0x2A;

fn inject(scan: u16, unicode: u16, shift_state: u32) {
    let valid = shift_state & SHIFT_STATE_VALID != 0;
    let ctrl = valid && shift_state & (RIGHT_CONTROL | LEFT_CONTROL) != 0;
    let alt = valid && shift_state & (RIGHT_ALT | LEFT_ALT) != 0;
    let shift_held = valid && shift_state & (RIGHT_SHIFT | LEFT_SHIFT) != 0;

    // Resolve the base key to (make code, needs-shift, extended).
    let base = if scan != 0 {
        special_to_set1(scan).map(|(c, e)| (c, false, e))
    } else if ctrl && (1..=26).contains(&unicode) {
        // Ctrl+letter arrives as a control char (^A = 0x01); recover the letter.
        Some((SET1_AZ[(unicode - 1) as usize], false, false))
    } else if unicode != 0 && unicode < 0x80 {
        ascii_to_set1(unicode as u8).map(|(c, s)| (c, s, false))
    } else {
        None
    };
    let Some((code, needs_shift, ext)) = base else { return };
    let shift = needs_shift || shift_held;

    if ctrl { i8042::inject_scancode(LCTRL_MAKE); }
    if alt { i8042::inject_scancode(LALT_MAKE); }
    if shift { i8042::inject_scancode(LSHIFT_MAKE); }

    if ext {
        i8042::inject_scancode(0xE0);
        i8042::inject_scancode(code);
        i8042::inject_scancode(0xE0);
        i8042::inject_scancode(code | 0x80);
    } else {
        i8042::inject_scancode(code);
        i8042::inject_scancode(code | 0x80);
    }

    if shift { i8042::inject_scancode(LSHIFT_MAKE | 0x80); }
    if alt { i8042::inject_scancode(LALT_MAKE | 0x80); }
    if ctrl { i8042::inject_scancode(LCTRL_MAKE | 0x80); }
}

// PS/2 scan-code set 1 make codes, indexed a..z and 0..9.
const SET1_AZ: [u8; 26] = [
    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32,
    0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
];
const SET1_09: [u8; 10] = [0x0B, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];

/// EFI scan code (non-printable navigation/function key) → (set-1 make code,
/// extended). Extended keys take the 0xE0 prefix.
fn special_to_set1(scan: u16) -> Option<(u8, bool)> {
    Some(match scan {
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
        _ => return None,
    })
}

/// ASCII → (set-1 make code, needs-shift) for the full US layout.
fn ascii_to_set1(c: u8) -> Option<(u8, bool)> {
    Some(match c {
        b'a'..=b'z' => (SET1_AZ[(c - b'a') as usize], false),
        b'A'..=b'Z' => (SET1_AZ[(c - b'A') as usize], true),
        b'0'..=b'9' => (SET1_09[(c - b'0') as usize], false),
        b' ' => (0x39, false),
        b'\r' | b'\n' => (0x1C, false),
        0x08 => (0x0E, false),
        b'\t' => (0x0F, false),
        0x1B => (0x01, false),
        b'!' => (0x02, true),
        b'@' => (0x03, true),
        b'#' => (0x04, true),
        b'$' => (0x05, true),
        b'%' => (0x06, true),
        b'^' => (0x07, true),
        b'&' => (0x08, true),
        b'*' => (0x09, true),
        b'(' => (0x0A, true),
        b')' => (0x0B, true),
        b'`' => (0x29, false),
        b'~' => (0x29, true),
        b'-' => (0x0C, false),
        b'_' => (0x0C, true),
        b'=' => (0x0D, false),
        b'+' => (0x0D, true),
        b'[' => (0x1A, false),
        b'{' => (0x1A, true),
        b']' => (0x1B, false),
        b'}' => (0x1B, true),
        b'\\' => (0x2B, false),
        b'|' => (0x2B, true),
        b';' => (0x27, false),
        b':' => (0x27, true),
        b'\'' => (0x28, false),
        b'"' => (0x28, true),
        b',' => (0x33, false),
        b'<' => (0x33, true),
        b'.' => (0x34, false),
        b'>' => (0x34, true),
        b'/' => (0x35, false),
        b'?' => (0x35, true),
        _ => return None,
    })
}
