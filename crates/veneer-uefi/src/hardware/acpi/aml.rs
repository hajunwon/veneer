//! Minimal AML (ACPI Machine Language) encoder.
//!
//! The DSDT used to be a hand-assembled byte array, which made PkgLength
//! (the self-including, variable-width length prefix on every package) easy
//! to get wrong and impossible to extend safely. This builds the bytecode
//! programmatically: each constructor returns a finished term whose length
//! prefix is computed from its body, so nesting _CRS resource templates and
//! a _PRT routing package inside Device(PCI0) stays correct by construction.
//!
//! Only the subset the DSDT needs is implemented (Scope, Device, Name,
//! Package, Buffer/ResourceTemplate, integer constants, EisaId, and the
//! Word/DWord address-space resource descriptors).

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

const ZERO_OP: u8 = 0x00;
const ONE_OP: u8 = 0x01;
const NAME_OP: u8 = 0x08;
const BYTE_PREFIX: u8 = 0x0A;
const WORD_PREFIX: u8 = 0x0B;
const DWORD_PREFIX: u8 = 0x0C;
const STRING_PREFIX: u8 = 0x0D;
const QWORD_PREFIX: u8 = 0x0E;
const SCOPE_OP: u8 = 0x10;
const BUFFER_OP: u8 = 0x11;
const PACKAGE_OP: u8 = 0x12;
const METHOD_OP: u8 = 0x14;
const STORE_OP: u8 = 0x70;
const RETURN_OP: u8 = 0xA4;
const ARG0_OP: u8 = 0x68; // Arg0..Arg6 = 0x68..0x6E
const EXT_OP_PREFIX: u8 = 0x5B;
const DEVICE_OP: u8 = 0x82;

const RES_TYPE_MEMORY: u8 = 0;
const RES_TYPE_IO: u8 = 1;
const RES_TYPE_BUS: u8 = 2;
/// General flags: ResourceProducer + MinFixed + MaxFixed + PosDecode.
const GEN_FLAGS_FIXED_PRODUCER: u8 = 0x0C;

/// PkgLength (ACPI 6.4 §20.2.4): a self-including length prefix. The encoded
/// value counts the prefix bytes themselves, so the width is resolved by
/// trying the smallest form that fits.
fn pkg_length(body_len: usize) -> Vec<u8> {
    let total1 = body_len + 1;
    if total1 <= 0x3F {
        return vec![total1 as u8]; // lead bits 7:6 = 00, value in 5:0
    }
    let total2 = body_len + 2;
    if total2 <= 0x0FFF {
        return vec![0x40 | (total2 & 0x0F) as u8, (total2 >> 4) as u8];
    }
    let total3 = body_len + 3;
    if total3 <= 0x0F_FFFF {
        return vec![0x80 | (total3 & 0x0F) as u8, (total3 >> 4) as u8, (total3 >> 12) as u8];
    }
    let total4 = body_len + 4;
    vec![
        0xC0 | (total4 & 0x0F) as u8,
        (total4 >> 4) as u8,
        (total4 >> 12) as u8,
        (total4 >> 20) as u8,
    ]
}

/// Wrap `body` as `opcode + PkgLength + body`. The opcode (1 or 2 bytes) is
/// not counted in the length; everything after it, including the length
/// bytes, is.
fn with_pkg(opcode: &[u8], body: Vec<u8>) -> Vec<u8> {
    let pl = pkg_length(body.len());
    let mut out = Vec::with_capacity(opcode.len() + pl.len() + body.len());
    out.extend_from_slice(opcode);
    out.extend_from_slice(&pl);
    out.extend_from_slice(&body);
    out
}

fn seg(s: &str) -> [u8; 4] {
    let b = s.as_bytes();
    let mut o = [b'_'; 4];
    for i in 0..b.len().min(4) {
        o[i] = b[i];
    }
    o
}

/// Encode a NameString. Supports a leading `\` (root) and `.`-separated
/// 4-char segments (dual / multi name prefixes).
fn name_path(name: &str) -> Vec<u8> {
    let (root, rest) = match name.strip_prefix('\\') {
        Some(r) => (true, r),
        None => (false, name),
    };
    let segs: Vec<&str> = rest.split('.').collect();
    let mut out = Vec::new();
    if root {
        out.push(0x5C);
    }
    match segs.len() {
        1 => out.extend_from_slice(&seg(segs[0])),
        2 => {
            out.push(0x2E);
            out.extend_from_slice(&seg(segs[0]));
            out.extend_from_slice(&seg(segs[1]));
        }
        n => {
            out.push(0x2F);
            out.push(n as u8);
            for s in &segs {
                out.extend_from_slice(&seg(s));
            }
        }
    }
    out
}

/// Integer constant, in the narrowest opcode that holds `v`.
pub fn integer(v: u64) -> Vec<u8> {
    match v {
        0 => vec![ZERO_OP],
        1 => vec![ONE_OP],
        _ if v <= 0xFF => vec![BYTE_PREFIX, v as u8],
        _ if v <= 0xFFFF => vec![WORD_PREFIX, v as u8, (v >> 8) as u8],
        _ if v <= 0xFFFF_FFFF => {
            let mut o = vec![DWORD_PREFIX];
            o.extend_from_slice(&(v as u32).to_le_bytes());
            o
        }
        _ => {
            let mut o = vec![QWORD_PREFIX];
            o.extend_from_slice(&v.to_le_bytes());
            o
        }
    }
}

/// `Name (path, value)`.
pub fn name(path: &str, value: Vec<u8>) -> Vec<u8> {
    let mut o = vec![NAME_OP];
    o.extend(name_path(path));
    o.extend(value);
    o
}

/// `Package () { elements... }`. NumElements is a single byte (PackageOp).
pub fn package(elements: Vec<Vec<u8>>) -> Vec<u8> {
    let mut body = vec![elements.len() as u8];
    for e in elements {
        body.extend(e);
    }
    with_pkg(&[PACKAGE_OP], body)
}

/// `Buffer (len) { bytes... }`.
pub fn buffer(data: Vec<u8>) -> Vec<u8> {
    let mut body = integer(data.len() as u64);
    body.extend(data);
    with_pkg(&[BUFFER_OP], body)
}

/// `Device (path) { body }`.
pub fn device(path: &str, body: Vec<u8>) -> Vec<u8> {
    let mut b = name_path(path);
    b.extend(body);
    with_pkg(&[EXT_OP_PREFIX, DEVICE_OP], b)
}

/// `Scope (path) { body }`.
pub fn scope(path: &str, body: Vec<u8>) -> Vec<u8> {
    let mut b = name_path(path);
    b.extend(body);
    with_pkg(&[SCOPE_OP], b)
}

/// `EisaId("PNP0A08")` → the 4-byte compressed EISA id as a DWord constant.
/// Three uppercase letters pack into 15 bits (big-endian), four hex digits
/// fill the low 16 bits (big-endian).
pub fn eisaid(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let letter = |i: usize| (b[i].wrapping_sub(0x40)) as u32 & 0x1F;
    let mfr = (letter(0) << 10) | (letter(1) << 5) | letter(2);
    let hex = |c: u8| -> u32 {
        match c {
            b'0'..=b'9' => (c - b'0') as u32,
            b'A'..=b'F' => (c - b'A' + 10) as u32,
            b'a'..=b'f' => (c - b'a' + 10) as u32,
            _ => 0,
        }
    };
    let prod = (hex(b[3]) << 12) | (hex(b[4]) << 8) | (hex(b[5]) << 4) | hex(b[6]);
    vec![
        DWORD_PREFIX,
        (mfr >> 8) as u8,
        mfr as u8,
        (prod >> 8) as u8,
        prod as u8,
    ]
}

/// Word Address Space descriptor (tag 0x88) — used for the bus-number range.
fn word_address(res_type: u8, type_flags: u8, gran: u16, min: u16, max: u16, len: u16) -> Vec<u8> {
    let mut o = vec![0x88, 0x0D, 0x00, res_type, GEN_FLAGS_FIXED_PRODUCER, type_flags];
    o.extend_from_slice(&gran.to_le_bytes());
    o.extend_from_slice(&min.to_le_bytes());
    o.extend_from_slice(&max.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes()); // translation offset
    o.extend_from_slice(&len.to_le_bytes());
    o
}

/// DWord Address Space descriptor (tag 0x87) — used for IO and 32-bit MMIO.
fn dword_address(res_type: u8, type_flags: u8, gran: u32, min: u32, max: u32, len: u32) -> Vec<u8> {
    let mut o = vec![0x87, 0x17, 0x00, res_type, GEN_FLAGS_FIXED_PRODUCER, type_flags];
    o.extend_from_slice(&gran.to_le_bytes());
    o.extend_from_slice(&min.to_le_bytes());
    o.extend_from_slice(&max.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes()); // translation offset
    o.extend_from_slice(&len.to_le_bytes());
    o
}

/// Bus-number producer window `[min, max]`.
pub fn bus_range(min: u16, max: u16) -> Vec<u8> {
    word_address(RES_TYPE_BUS, 0x00, 0, min, max, max - min + 1)
}

/// IO producer window `[min, max]` (entire-range type flags).
pub fn io_range(min: u32, max: u32) -> Vec<u8> {
    dword_address(RES_TYPE_IO, 0x03, 0, min, max, max - min + 1)
}

/// 32-bit memory producer window `[min, max]` (read-write, non-cacheable).
pub fn mem32_range(min: u32, max: u32) -> Vec<u8> {
    dword_address(RES_TYPE_MEMORY, 0x01, 0, min, max, max - min + 1)
}

/// Wrap resource descriptors as a ResourceTemplate buffer (appends the
/// EndTag + zero checksum that closes every _CRS).
pub fn resource_template(mut descriptors: Vec<u8>) -> Vec<u8> {
    descriptors.push(0x79); // EndTag
    descriptors.push(0x00); // checksum 0 = "do not verify"
    buffer(descriptors)
}

/// ASCII string object (`AmlString`): prefix + bytes + NUL terminator.
/// Used for string-form `_HID`s such as the processor id "ACPI0007".
pub fn string(s: &str) -> Vec<u8> {
    let mut o = vec![STRING_PREFIX];
    o.extend_from_slice(s.as_bytes());
    o.push(0x00);
    o
}

// ───── Small/large resource descriptors for leaf-device _CRS ─────────
//
// The address-space descriptors above (0x87/0x88) are the *producer*
// windows a bridge hands to its children. Leaf devices (keyboard, RTC,
// HPET, …) instead consume fixed I/O ports, IRQ lines, and fixed MMIO,
// which use these smaller descriptors.

/// Fixed I/O port range descriptor (small tag 0x47), 16-bit decode.
/// `base`..`base+len-1`, with the given alignment.
pub fn io(base: u16, len: u8, align: u8) -> Vec<u8> {
    vec![
        0x47, 0x01, // 16-bit decode
        base as u8, (base >> 8) as u8, // min
        base as u8, (base >> 8) as u8, // max (== min for a fixed port)
        align, len,
    ]
}

/// IRQ descriptor (small tag 0x22) carrying a single ISA IRQ line.
/// `IRQNoFlags(){n}` — the 2-byte form real firmware uses for edge,
/// active-high ISA interrupts.
pub fn irq(line: u8) -> Vec<u8> {
    let mask: u16 = 1u16 << line;
    vec![0x22, mask as u8, (mask >> 8) as u8]
}

/// 32-bit fixed memory range descriptor (large tag 0x86). `writable`
/// sets the read/write bit (cleared = read-only).
pub fn memory32_fixed(base: u32, len: u32, writable: bool) -> Vec<u8> {
    let mut o = vec![0x86, 0x09, 0x00, writable as u8];
    o.extend_from_slice(&base.to_le_bytes());
    o.extend_from_slice(&len.to_le_bytes());
    o
}

// ───── Control-method bytecode (for _PIC, _OSC, …) ───────────────────

/// `ArgN` operand (0..=6).
pub fn arg(n: u8) -> Vec<u8> {
    vec![ARG0_OP + n]
}

/// `Store (src, dstName)` — copy a term into a named object.
pub fn store(src: Vec<u8>, dst: &str) -> Vec<u8> {
    let mut o = vec![STORE_OP];
    o.extend(src);
    o.extend(name_path(dst));
    o
}

/// `Return (value)`.
pub fn ret(value: Vec<u8>) -> Vec<u8> {
    let mut o = vec![RETURN_OP];
    o.extend(value);
    o
}

/// `Method (path, arg_count) { body }`. MethodFlags low 3 bits = arg
/// count, bit 3 = serialized.
pub fn method(path: &str, arg_count: u8, serialized: bool, body: Vec<u8>) -> Vec<u8> {
    let flags = (arg_count & 0x07) | ((serialized as u8) << 3);
    let mut b = name_path(path);
    b.push(flags);
    b.extend(body);
    with_pkg(&[METHOD_OP], b)
}
