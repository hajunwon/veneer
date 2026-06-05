//! Identifier text formatters. Pure functions over an injected `Rng`.

use super::Rng;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn write_hex_byte(buf: &mut [u8], idx: usize, v: u8, upper: bool) {
    let table = if upper { HEX_UPPER } else { HEX_LOWER };
    buf[idx] = table[(v >> 4) as usize];
    buf[idx + 1] = table[(v & 0xF) as usize];
}

/// Random RFC-4122 v4 UUID, canonical text form (lowercase, dashes).
pub fn uuid<R: Rng>(rng: &mut R) -> [u8; 36] {
    let lo = rng.next_u64();
    let hi = rng.next_u64();
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&lo.to_le_bytes());
    bytes[8..].copy_from_slice(&hi.to_le_bytes());
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant 10

    let mut out = [b'-'; 36];
    let positions = [0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34];
    for (i, &pos) in positions.iter().enumerate() {
        write_hex_byte(&mut out, pos, bytes[i], false);
    }
    out
}

/// Random MAC with the supplied OUI prefix. Format `XX:XX:XX:XX:XX:XX`.
pub fn mac<R: Rng>(rng: &mut R, oui: [u8; 3]) -> [u8; 17] {
    let v = rng.next_u32();
    let octets = [oui[0], oui[1], oui[2], v as u8, (v >> 8) as u8, (v >> 16) as u8];
    let mut out = [b':'; 17];
    let positions = [0, 3, 6, 9, 12, 15];
    for (i, &pos) in positions.iter().enumerate() {
        write_hex_byte(&mut out, pos, octets[i], true);
    }
    out
}

/// Random 16-char alphanumeric (uppercase) serial — disks and DIMMs.
pub fn alnum16<R: Rng>(rng: &mut R) -> [u8; 16] {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut out = [0u8; 16];
    let mut bits_left = 0u32;
    let mut pool = 0u64;
    for slot in out.iter_mut() {
        if bits_left < 6 {
            pool = rng.next_u64();
            bits_left = 64;
        }
        let idx = (pool & 0x3F) as usize % CHARSET.len();
        *slot = CHARSET[idx];
        pool >>= 6;
        bits_left -= 6;
    }
    out
}

/// Random 12-char SMBIOS serial (`PF` + 10 digits) — system / board / chassis.
pub fn smbios_serial<R: Rng>(rng: &mut R) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = b'P';
    out[1] = b'F';
    let v = rng.next_u64();
    for i in 0..10 {
        out[i + 2] = b'0' + ((v >> (i * 4)) & 0xF) as u8 % 36 % 10;
    }
    out
}
