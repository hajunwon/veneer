//! Fixed-size, 1-byte-aligned building blocks shared by every model
//! component. Living in one place keeps the NVRAM byte layout (a raw
//! `repr(C, packed)` copy of `Profile`) defined by these types alone.

/// Fixed-size string buffer. `repr(C, packed)` so the struct has 1-byte
/// alignment — that lets us embed it inside other `repr(C, packed)`
/// parents without dragging in alignment padding that would invalidate
/// the on-NVRAM byte layout. Field access goes through raw pointers
/// because Rust forbids references to misaligned packed fields.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct ProfileStr<const N: usize> {
    buf: [u8; N],
    len: u16,
}

impl<const N: usize> ProfileStr<N> {
    pub const fn empty() -> Self {
        Self { buf: [0; N], len: 0 }
    }

    /// Build from a `&'static str`. const-fn safe because we copy into a
    /// fresh local `[u8; N]` (not packed) before the struct literal.
    pub const fn from_static(s: &'static str) -> Self {
        let bytes = s.as_bytes();
        let mut buf = [0u8; N];
        let n = if bytes.len() < N { bytes.len() } else { N };
        let mut i = 0;
        while i < n {
            buf[i] = bytes[i];
            i += 1;
        }
        Self { buf, len: n as u16 }
    }

    pub fn from_bytes(s: &[u8]) -> Self {
        let mut buf = [0u8; N];
        let n = s.len().min(N);
        buf[..n].copy_from_slice(&s[..n]);
        Self { buf, len: n as u16 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        let len = unsafe { core::ptr::addr_of!(self.len).read_unaligned() } as usize;
        let ptr = self as *const Self as *const u8;
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    /// Pad-write `self` into a `[u8; N]` (zero fill). Used by emitters
    /// that need a deterministic full-width register write (e.g. the
    /// CPUID brand = exactly 48 bytes across 12 registers).
    pub fn to_padded(&self) -> [u8; N] {
        let mut out = [0u8; N];
        let src = self as *const Self as *const u8;
        unsafe { core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), N); }
        out
    }
}

// ───── component-specific string widths ─────────────────────────────────

/// CPUID brand string limit (12 registers × 4 bytes = 48).
pub type CpuBrand = ProfileStr<48>;
/// CPUID 0x0 vendor (12 bytes).
pub type CpuVendor = ProfileStr<12>;

pub type SmbiosShort = ProfileStr<32>;
pub type SmbiosLong = ProfileStr<64>;

/// UUID canonical text form (36 chars with dashes).
pub type UuidStr = ProfileStr<36>;
/// MAC canonical text form (`XX:XX:XX:XX:XX:XX` = 17 chars).
pub type MacStr = ProfileStr<17>;

pub type ProfileName = ProfileStr<32>;
