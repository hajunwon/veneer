//! Minimal TOML parser — schema-driven, *not* a full TOML implementation.
//!
//! Supported syntax (subset that covers our Profile and Config schemas):
//!   - `[section.subsection]`             section header
//!   - `key = "string"`                   string value (basic UTF-8)
//!   - `key = 123` / `key = 0xABCD`       integer (decimal or hex)
//!   - `key = true` / `key = false`       boolean
//!   - `# comment`                        line comment
//!   - blank lines                         ignored
//!
//! The tokenizer + `Value`/`Line`/`parse_line` and the value/field setter
//! helpers are shared; `apply_profile` fills a `Profile`. The Config half
//! lives in the hypervisor crate (Config is veneer-internal).

use crate::{Profile, ProfileStr};

#[derive(Debug, Clone, Copy)]
pub enum Value<'a> {
    Str(&'a [u8]),
    /// Stored as `u64` so 64-bit unsigned hex literals like
    /// `0xC0FFEEC0FFEEBEEF` parse without overflow. Schema fields that
    /// want signed semantics can `as i64` at apply time.
    Int(u64),
    Bool(bool),
}

#[derive(Debug)]
pub enum TomlError {
    /// A line we don't understand (key without value, unclosed quote, …).
    BadLine,
    /// A `key = value` we recognised structurally but the value type
    /// didn't match the expected schema field (e.g. bool where string expected).
    TypeMismatch,
    /// A `[section]` / `key` pair that doesn't map to any schema field.
    UnknownField,
}

// ───── tokenizer ────────────────────────────────────────────────────────

fn is_ws(b: u8) -> bool { matches!(b, b' ' | b'\t' | b'\r') }

fn trim(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end && is_ws(s[start]) { start += 1; }
    while end > start && is_ws(s[end - 1]) { end -= 1; }
    &s[start..end]
}

fn parse_int(s: &[u8]) -> Option<u64> {
    let s = trim(s);
    if s.is_empty() { return None; }
    let (neg, body) = if s[0] == b'-' { (true, &s[1..]) } else { (false, s) };
    let (radix, digits) = if body.len() > 2 && body[0] == b'0' && (body[1] == b'x' || body[1] == b'X') {
        (16u64, &body[2..])
    } else {
        (10u64, body)
    };
    let mut acc: u64 = 0;
    for &c in digits {
        let d = match c {
            b'0'..=b'9' => (c - b'0') as u64,
            b'a'..=b'f' if radix == 16 => (c - b'a' + 10) as u64,
            b'A'..=b'F' if radix == 16 => (c - b'A' + 10) as u64,
            b'_' => continue,
            _ => return None,
        };
        acc = acc.checked_mul(radix)?.checked_add(d)?;
    }
    Some(if neg { acc.wrapping_neg() } else { acc })
}

fn parse_value(s: &[u8]) -> Option<Value<'_>> {
    let s = trim(s);
    if s.is_empty() { return None; }
    if s.len() >= 2 && s[0] == b'"' && s[s.len() - 1] == b'"' {
        return Some(Value::Str(&s[1..s.len() - 1]));
    }
    if s == b"true" { return Some(Value::Bool(true)); }
    if s == b"false" { return Some(Value::Bool(false)); }
    parse_int(s).map(Value::Int)
}

/// Outcome of inspecting a single line. Section headers and key/value
/// lines are reported separately; comments, blank lines, and bad lines
/// are folded together (caller decides if `Bad` is fatal).
pub enum Line<'a> {
    Section(&'a [u8]),
    KeyValue(&'a [u8], Value<'a>),
    Skip,
    Bad,
}

pub fn parse_line(raw: &[u8]) -> Line<'_> {
    let line = if let Some(&b'\n') = raw.last() { &raw[..raw.len() - 1] } else { raw };
    let line = trim(line);
    if line.is_empty() { return Line::Skip; }
    if line[0] == b'#' { return Line::Skip; }
    if line[0] == b'[' {
        let close = match line.iter().position(|&c| c == b']') {
            Some(i) => i,
            None => return Line::Bad,
        };
        let inside = trim(&line[1..close]);
        return Line::Section(inside);
    }
    let eq = match line.iter().position(|&c| c == b'=') {
        Some(i) => i,
        None => return Line::Bad,
    };
    let key = trim(&line[..eq]);
    let val_raw = trim(&line[eq + 1..]);
    let val = if !val_raw.is_empty() && val_raw[0] == b'"' {
        if let Some(end) = val_raw[1..].iter().position(|&c| c == b'"') {
            &val_raw[..end + 2]
        } else {
            return Line::Bad;
        }
    } else if let Some(hash) = val_raw.iter().position(|&c| c == b'#') {
        trim(&val_raw[..hash])
    } else {
        val_raw
    };
    match parse_value(val) {
        Some(v) => Line::KeyValue(key, v),
        None => Line::Bad,
    }
}

// ───── value extractors + packed-field setters (shared with Config) ──────

pub fn as_str<'a>(v: Value<'a>) -> Option<&'a [u8]> {
    if let Value::Str(s) = v { Some(s) } else { None }
}
pub fn as_bool(v: Value) -> Option<bool> {
    if let Value::Bool(b) = v { Some(b) } else { None }
}
pub fn as_int(v: Value) -> Option<u64> {
    if let Value::Int(n) = v { Some(n) } else { None }
}

/// Write a `ProfileStr<N>` field through a raw pointer. Packed parent
/// structs require this dance (no references to packed fields).
///
/// # Safety
/// `dst` must point at a valid, writable `ProfileStr<N>`.
pub unsafe fn set_str_field<const N: usize>(dst: *mut ProfileStr<N>, src: &[u8]) {
    let s = ProfileStr::<N>::from_bytes(src);
    core::ptr::write_unaligned(dst, s);
}

/// # Safety
/// `dst` must point at a valid, writable `bool`.
pub unsafe fn set_bool_field(dst: *mut bool, src: bool) {
    core::ptr::write_unaligned(dst, src);
}

/// # Safety
/// `dst` must point at a valid, writable `u64`.
pub unsafe fn set_u64_field(dst: *mut u64, src: u64) {
    core::ptr::write_unaligned(dst, src);
}

/// # Safety
/// `dst` must point at a valid, writable `u32`.
pub unsafe fn set_u32_field(dst: *mut u32, src: u32) {
    core::ptr::write_unaligned(dst, src);
}

/// # Safety
/// `dst` must point at a valid, writable `u8`.
pub unsafe fn set_u8_field(dst: *mut u8, src: u8) {
    core::ptr::write_unaligned(dst, src);
}

// ───── Profile schema dispatch ───────────────────────────────────────────

/// Apply each `key = value` to the right field on `Profile` based on the
/// current `[section]`. Unknown keys / wrong types are tallied but don't
/// stop parsing. Returns the count of successful applies.
pub fn apply_profile(text: &[u8], p: &mut Profile, warn_count: &mut u32) -> u32 {
    let mut section: &[u8] = b"";
    let mut applied = 0u32;
    for raw_line in text.split(|&c| c == b'\n') {
        match parse_line(raw_line) {
            Line::Skip => {}
            Line::Bad => *warn_count += 1,
            Line::Section(s) => section = s,
            Line::KeyValue(k, v) => {
                if apply_profile_field(p, section, k, v) {
                    applied += 1;
                } else {
                    *warn_count += 1;
                }
            }
        }
    }
    applied
}

fn apply_profile_field(p: &mut Profile, section: &[u8], key: &[u8], v: Value) -> bool {
    let p_ptr = p as *mut Profile;
    match (section, key) {
        (b"hardware.cpu", b"brand") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.cpu.spec.brand), s); }
            true
        }
        (b"hardware.cpu", b"vendor") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.cpu.spec.vendor), s); }
            true
        }
        (b"hardware.cpu", b"hide_hypervisor_bit") => {
            let b = match as_bool(v) { Some(b) => b, None => return false };
            unsafe { set_bool_field(core::ptr::addr_of_mut!((*p_ptr).hardware.cpu.spec.hide_hypervisor_bit), b); }
            true
        }
        (b"hardware.cpu", b"hide_hypervisor_leaf") => {
            let b = match as_bool(v) { Some(b) => b, None => return false };
            unsafe { set_bool_field(core::ptr::addr_of_mut!((*p_ptr).hardware.cpu.spec.hide_hypervisor_leaf), b); }
            true
        }
        (b"hardware.cpu", b"tsc_seed") => {
            let n = match as_int(v) { Some(n) => n, None => return false };
            unsafe { set_u64_field(core::ptr::addr_of_mut!((*p_ptr).hardware.cpu.spec.tsc_seed), n as u64); }
            true
        }
        (b"hardware.smbios", b"manufacturer") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.system.spec.manufacturer), s); }
            true
        }
        (b"hardware.smbios", b"product") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.system.spec.product), s); }
            true
        }
        (b"hardware.smbios", b"serial") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.system.instance.serial), s); }
            true
        }
        (b"hardware.smbios", b"version") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.system.spec.version), s); }
            true
        }
        (b"hardware.smbios", b"uuid") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.system.instance.uuid), s); }
            true
        }
        (b"hardware.smbios", b"bios_vendor") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.firmware.spec.bios_vendor), s); }
            true
        }
        (b"hardware.smbios", b"bios_version") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.firmware.spec.bios_version), s); }
            true
        }
        (b"hardware.smbios", b"bios_date") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.firmware.spec.bios_date), s); }
            true
        }
        (b"hardware.network", b"mac") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.network.instance.mac), s); }
            true
        }
        (b"hardware.disk", b"slot") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.storage.spec.slot), s); }
            true
        }
        (b"hardware.disk", b"model") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.storage.spec.model), s); }
            true
        }
        (b"hardware.disk", b"serial") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).hardware.storage.instance.serial), s); }
            true
        }
        (b"hardware.iommu", b"efr") => {
            let n = match as_int(v) { Some(n) => n, None => return false };
            unsafe { set_u64_field(core::ptr::addr_of_mut!((*p_ptr).hardware.cpu.spec.iommu.efr), n); }
            true
        }
        (b"hardware.iommu", b"efr2") => {
            let n = match as_int(v) { Some(n) => n, None => return false };
            unsafe { set_u64_field(core::ptr::addr_of_mut!((*p_ptr).hardware.cpu.spec.iommu.efr2), n); }
            true
        }
        (b"hardware.iommu", b"pci_id") => {
            let n = match as_int(v) { Some(n) => n, None => return false };
            unsafe { set_u32_field(core::ptr::addr_of_mut!((*p_ptr).hardware.cpu.spec.iommu.pci_id), n as u32); }
            true
        }
        (b"name", _) | (b"", b"name") => {
            if key != b"name" { return false; }
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).name), s); }
            true
        }
        (b"software.os", b"product_name") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).software.os.product_name), s); }
            true
        }
        (b"software.os", b"computer_name") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).software.os.computer_name), s); }
            true
        }
        (b"software.registry", b"machine_guid") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).software.registry.machine_guid), s); }
            true
        }
        (b"software.volume", b"c_drive_serial") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).software.volume.c_drive_serial), s); }
            true
        }
        (b"software.locale", b"language") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).software.locale.language), s); }
            true
        }
        (b"software.locale", b"timezone") => {
            let s = match as_str(v) { Some(s) => s, None => return false };
            unsafe { set_str_field(core::ptr::addr_of_mut!((*p_ptr).software.locale.timezone), s); }
            true
        }
        _ => false,
    }
}
