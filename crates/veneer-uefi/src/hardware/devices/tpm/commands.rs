//! TPM 2.0 command dispatcher.
//!
//! Wire format is TCG TPM 2.0 Part 3 (Commands). All fields big-endian.
//!
//! Command header:  TAG(2) | commandSize(4) | commandCode(4) | body
//! Response header: TAG(2) | responseSize(4) | responseCode(4) | body
//!
//! TAG values:
//!   TPM_ST_NO_SESSIONS = 0x8001 — command without auth sessions
//!   TPM_ST_SESSIONS    = 0x8002 — command with auth sessions
//!
//! Implemented commands:
//!   Startup, Shutdown, SelfTest, IncrementalSelfTest, GetTestResult,
//!   GetCapability (TPM_PROPERTIES + ALGS + PCRS + COMMANDS),
//!   GetRandom, StirRandom, ReadClock,
//!   PCR_Read, PCR_Extend, Hash, HashSequenceStart/Update/Complete,
//!   NV_ReadPublic, NV_Read,
//!   StartAuthSession, FlushContext,
//!   Anything else → TPM_RC_COMMAND_CODE.
//!
//! Not implemented (CreatePrimary, Create, Load, RSA/ECC, Sign, Quote,
//! sealed objects, full policy) — would return TPM_RC_COMMAND_CODE,
//! breaking BitLocker but passing local presence/identity checks.

use core::sync::atomic::Ordering;

use super::{sha256, state};
use crate::hardware::identity::active;

/// TPM manufacturer identity derived from the active profile's CPU vendor,
/// so an Intel-profile machine reports an Intel fTPM ("INTC") and an AMD
/// machine reports the AMD fTPM ("AMD"), instead of a hard-coded "AMD" that
/// contradicts an Intel CPUID. Returns (TPM_PT_MANUFACTURER value,
/// vendor-string word 1) as big-endian-packed 4-byte ASCII.
///
///   AMD fTPM   : manufacturer "AMD\0", vendor string "AMD\0"
///   Intel PTT  : manufacturer "INTC",  vendor string "INTC"
///
/// The fallback (no profile) keeps the prior AMD identity.
fn tpm_manufacturer() -> (u32, u32) {
    let amd = (u32::from_be_bytes(*b"AMD\0"), u32::from_be_bytes(*b"AMD\0"));
    let intc = (u32::from_be_bytes(*b"INTC"), u32::from_be_bytes(*b"INTC"));
    match active::PROFILE.get() {
        Some(p) => {
            let v = unsafe { core::ptr::addr_of!(p.hardware.cpu.vendor).read_unaligned() };
            let vendor = v.as_str();
            if vendor.contains("Intel") || vendor.eq_ignore_ascii_case("GenuineIntel") {
                intc
            } else {
                amd
            }
        }
        None => amd,
    }
}

// ───── Tags ──────────────────────────────────────────────────────────
const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS:    u16 = 0x8002;

// ───── Response codes ────────────────────────────────────────────────
const TPM_RC_SUCCESS:      u32 = 0x000;
const TPM_RC_BAD_TAG:      u32 = 0x01E;
const TPM_RC_INITIALIZE:   u32 = 0x100;
const TPM_RC_FAILURE:      u32 = 0x101;
const TPM_RC_COMMAND_SIZE: u32 = 0x142;
const TPM_RC_COMMAND_CODE: u32 = 0x143;
const TPM_RC_HANDLE:       u32 = 0x18B;
const TPM_RC_VALUE_PARAM1: u32 = 0xC4;     // format-one value error for param 1

// ───── Command codes (TPM 2.0 spec Part 2 § 6.5) ─────────────────────
mod cc {
    pub const NV_DEFINE_SPACE:    u32 = 0x0000_012A;
    pub const SELF_TEST:          u32 = 0x0000_0143;
    pub const INCREMENTAL_SELF_TEST: u32 = 0x0000_0142;
    pub const STARTUP:            u32 = 0x0000_0144;
    pub const SHUTDOWN:           u32 = 0x0000_0145;
    pub const STIR_RANDOM:        u32 = 0x0000_0146;
    pub const NV_READ:            u32 = 0x0000_014E;
    pub const NV_READ_PUBLIC:     u32 = 0x0000_0169;
    pub const START_AUTH_SESSION: u32 = 0x0000_0176;
    pub const FLUSH_CONTEXT:      u32 = 0x0000_0165;
    pub const GET_CAPABILITY:     u32 = 0x0000_017A;
    pub const GET_RANDOM:         u32 = 0x0000_017B;
    pub const GET_TEST_RESULT:    u32 = 0x0000_017C;
    pub const HASH:               u32 = 0x0000_017D;
    pub const PCR_READ:           u32 = 0x0000_017E;
    pub const READ_CLOCK:         u32 = 0x0000_0181;
    pub const PCR_EXTEND:         u32 = 0x0000_0182;
    pub const HASH_SEQUENCE_START: u32 = 0x0000_0186;
    pub const SEQUENCE_UPDATE:    u32 = 0x0000_015C;
    pub const SEQUENCE_COMPLETE:  u32 = 0x0000_013E;
}

// ───── Capability categories ─────────────────────────────────────────
const TPM_CAP_ALGS:           u32 = 0x00;
const TPM_CAP_HANDLES:        u32 = 0x01;
const TPM_CAP_COMMANDS:       u32 = 0x02;
const TPM_CAP_PP_COMMANDS:    u32 = 0x03;
const TPM_CAP_AUDIT_COMMANDS: u32 = 0x04;
const TPM_CAP_PCRS:           u32 = 0x05;
const TPM_CAP_TPM_PROPERTIES: u32 = 0x06;
const TPM_CAP_PCR_PROPERTIES: u32 = 0x07;
const TPM_CAP_ECC_CURVES:     u32 = 0x08;

// ───── Algorithm IDs ─────────────────────────────────────────────────
const TPM_ALG_RSA:    u16 = 0x0001;
const TPM_ALG_SHA1:   u16 = 0x0004;
const TPM_ALG_HMAC:   u16 = 0x0005;
const TPM_ALG_AES:    u16 = 0x0006;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_SHA384: u16 = 0x000C;
const TPM_ALG_NULL:   u16 = 0x0010;
const TPM_ALG_ECC:    u16 = 0x0023;
const TPM_ALG_CFB:    u16 = 0x0043;

// ───── Property IDs (TPM_PT_*) ───────────────────────────────────────
const PT_FAMILY_INDICATOR:   u32 = 0x100;
const PT_LEVEL:              u32 = 0x101;
const PT_REVISION:           u32 = 0x102;
const PT_DAY_OF_YEAR:        u32 = 0x103;
const PT_YEAR:               u32 = 0x104;
const PT_MANUFACTURER:       u32 = 0x105;
const PT_VENDOR_STRING_1:    u32 = 0x106;
const PT_VENDOR_STRING_2:    u32 = 0x107;
const PT_VENDOR_STRING_3:    u32 = 0x108;
const PT_VENDOR_STRING_4:    u32 = 0x109;
const PT_VENDOR_TPM_TYPE:    u32 = 0x10A;
const PT_FIRMWARE_VERSION_1: u32 = 0x10B;
const PT_FIRMWARE_VERSION_2: u32 = 0x10C;
const PT_INPUT_BUFFER:       u32 = 0x10D;
const PT_PCR_COUNT:          u32 = 0x112;
const PT_PCR_SELECT_MIN:     u32 = 0x113;
const PT_NV_INDEX_MAX:       u32 = 0x117;
const PT_MAX_COMMAND_SIZE:   u32 = 0x11E;
const PT_MAX_RESPONSE_SIZE:  u32 = 0x11F;
const PT_MAX_DIGEST:         u32 = 0x120;
const PT_PERMANENT:          u32 = 0x200;
const PT_STARTUP_CLEAR:      u32 = 0x201;

// ───── BE byte reader/writer ─────────────────────────────────────────

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }
    fn remaining(&self) -> usize { self.buf.len().saturating_sub(self.pos) }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1; Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        if self.pos + 2 > self.buf.len() { return None; }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2; Some(v)
    }
    fn u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.buf.len() { return None; }
        let v = u32::from_be_bytes([
            self.buf[self.pos], self.buf[self.pos + 1],
            self.buf[self.pos + 2], self.buf[self.pos + 3],
        ]);
        self.pos += 4; Some(v)
    }
    fn slice(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() { return None; }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n; Some(s)
    }
    /// Read a TPM2B (u16 length + bytes).
    fn tpm2b(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.slice(n)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        if self.pos + n > self.buf.len() { return None; }
        self.pos += n; Some(())
    }
}

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}
impl<'a> Writer<'a> {
    fn new(buf: &'a mut [u8]) -> Self { Self { buf, pos: 0 } }
    fn u8(&mut self, v: u8) {
        if self.pos < self.buf.len() { self.buf[self.pos] = v; }
        self.pos += 1;
    }
    fn u16(&mut self, v: u16) {
        let b = v.to_be_bytes();
        if self.pos + 2 <= self.buf.len() { self.buf[self.pos..self.pos + 2].copy_from_slice(&b); }
        self.pos += 2;
    }
    fn u32(&mut self, v: u32) {
        let b = v.to_be_bytes();
        if self.pos + 4 <= self.buf.len() { self.buf[self.pos..self.pos + 4].copy_from_slice(&b); }
        self.pos += 4;
    }
    fn u64(&mut self, v: u64) {
        let b = v.to_be_bytes();
        if self.pos + 8 <= self.buf.len() { self.buf[self.pos..self.pos + 8].copy_from_slice(&b); }
        self.pos += 8;
    }
    fn bytes(&mut self, src: &[u8]) {
        let n = src.len();
        if self.pos + n <= self.buf.len() { self.buf[self.pos..self.pos + n].copy_from_slice(src); }
        self.pos += n;
    }
    fn tpm2b(&mut self, src: &[u8]) {
        self.u16(src.len() as u16);
        self.bytes(src);
    }
    /// Patch a u32 at `at`. Used to fix the responseSize after body is
    /// fully written.
    fn patch_u32(&mut self, at: usize, v: u32) {
        let b = v.to_be_bytes();
        if at + 4 <= self.buf.len() { self.buf[at..at + 4].copy_from_slice(&b); }
    }
}

// ───── RDRAND helper ─────────────────────────────────────────────────

fn rdrand_u64() -> Option<u64> {
    let v: u64;
    let ok: u8;
    unsafe {
        core::arch::asm!(
            "rdrand {0}",
            "setc {1}",
            out(reg) v,
            out(reg_byte) ok,
            options(nomem, nostack)
        );
    }
    if ok != 0 { Some(v) } else { None }
}

fn fill_random(out: &mut [u8]) {
    let mut i = 0;
    while i < out.len() {
        // Up to 10 retries — RDRAND can occasionally return CF=0 on
        // entropy starvation.
        let v = (0..10).find_map(|_| rdrand_u64()).unwrap_or(0xC0FFEE_C0FFEE_BEEF);
        let n = (out.len() - i).min(8);
        out[i..i + n].copy_from_slice(&v.to_le_bytes()[..n]);
        i += n;
    }
}

// ───── Entry point ───────────────────────────────────────────────────

/// Process one TPM2 command from `input` and write a TPM2 response into
/// `output`. Returns the number of bytes written.
pub fn process(input: &[u8], output: &mut [u8]) -> usize {
    let mut r = Reader::new(input);
    let tag = match r.u16() { Some(t) => t, None => return write_error(output, TPM_ST_NO_SESSIONS, TPM_RC_COMMAND_SIZE) };
    let size = match r.u32() { Some(s) => s, None => return write_error(output, tag, TPM_RC_COMMAND_SIZE) };
    let cc = match r.u32() { Some(c) => c, None => return write_error(output, tag, TPM_RC_COMMAND_SIZE) };

    if tag != TPM_ST_NO_SESSIONS && tag != TPM_ST_SESSIONS {
        return write_error(output, tag, TPM_RC_BAD_TAG);
    }
    if (size as usize) > input.len() {
        return write_error(output, tag, TPM_RC_COMMAND_SIZE);
    }

    // Most commands except Startup require prior TPM2_Startup.
    if !state::TPM_STARTED.load(Ordering::Relaxed)
        && cc != cc::STARTUP
        && cc != cc::SELF_TEST
        && cc != cc::GET_CAPABILITY
    {
        return write_error(output, tag, TPM_RC_INITIALIZE);
    }

    match cc {
        cc::STARTUP             => handle_startup(tag, &mut r, output),
        cc::SHUTDOWN            => handle_shutdown(tag, &mut r, output),
        cc::SELF_TEST           => handle_self_test(tag, &mut r, output),
        cc::INCREMENTAL_SELF_TEST => handle_inc_self_test(tag, &mut r, output),
        cc::GET_TEST_RESULT     => handle_get_test_result(tag, &mut r, output),
        cc::GET_CAPABILITY      => handle_get_capability(tag, &mut r, output),
        cc::GET_RANDOM          => handle_get_random(tag, &mut r, output),
        cc::STIR_RANDOM         => handle_stir_random(tag, &mut r, output),
        cc::READ_CLOCK          => handle_read_clock(tag, &mut r, output),
        cc::PCR_READ            => handle_pcr_read(tag, &mut r, output),
        cc::PCR_EXTEND          => handle_pcr_extend(tag, &mut r, output),
        cc::HASH                => handle_hash(tag, &mut r, output),
        cc::NV_READ_PUBLIC      => handle_nv_read_public(tag, &mut r, output),
        cc::NV_READ             => handle_nv_read(tag, &mut r, output),
        cc::START_AUTH_SESSION  => handle_start_auth_session(tag, &mut r, output),
        cc::FLUSH_CONTEXT       => handle_flush_context(tag, &mut r, output),
        _                       => write_error(output, tag, TPM_RC_COMMAND_CODE),
    }
}

fn write_error(out: &mut [u8], tag: u16, rc: u32) -> usize {
    let mut w = Writer::new(out);
    w.u16(tag);
    w.u32(10);  // header is exactly 10 bytes
    w.u32(rc);
    10
}

fn write_header(w: &mut Writer, tag: u16, rc: u32) -> usize {
    w.u16(tag);
    w.u32(0);      // patched at the end
    w.u32(rc);
    10
}

fn finalise(w: &mut Writer) -> usize {
    let len = w.pos as u32;
    w.patch_u32(2, len);
    w.pos
}

// ───── Handlers ──────────────────────────────────────────────────────

fn handle_startup(tag: u16, r: &mut Reader, out: &mut [u8]) -> usize {
    let su = r.u16().unwrap_or(0);   // TPM_SU_CLEAR=0, TPM_SU_STATE=1
    state::TPM_STARTED.store(true, Ordering::Relaxed);
    if su == 0 {
        // CLEAR: bump reset count, init clocks.
        state::TPM_RESET_COUNT.fetch_add(1, Ordering::Relaxed);
        state::BOOT_CLOCK_MS.store(0, Ordering::Relaxed);
    } else {
        state::TPM_RESTART_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    finalise(&mut w)
}

fn handle_shutdown(tag: u16, r: &mut Reader, out: &mut [u8]) -> usize {
    let _su = r.u16();
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    finalise(&mut w)
}

fn handle_self_test(tag: u16, _r: &mut Reader, out: &mut [u8]) -> usize {
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    finalise(&mut w)
}

fn handle_inc_self_test(tag: u16, _r: &mut Reader, out: &mut [u8]) -> usize {
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    // toDoList: empty count=0
    w.u32(0);
    finalise(&mut w)
}

fn handle_get_test_result(tag: u16, _r: &mut Reader, out: &mut [u8]) -> usize {
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    w.tpm2b(&[]);            // outData empty
    w.u32(TPM_RC_SUCCESS);   // testResult
    finalise(&mut w)
}

fn handle_get_random(tag: u16, r: &mut Reader, out: &mut [u8]) -> usize {
    let bytes_req = r.u16().unwrap_or(0).min(64);
    let mut buf = [0u8; 64];
    fill_random(&mut buf[..bytes_req as usize]);
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    w.tpm2b(&buf[..bytes_req as usize]);
    finalise(&mut w)
}

fn handle_stir_random(tag: u16, _r: &mut Reader, out: &mut [u8]) -> usize {
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    finalise(&mut w)
}

fn handle_read_clock(tag: u16, _r: &mut Reader, out: &mut [u8]) -> usize {
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    // TPMS_TIME_INFO: time(u64) | clockInfo { clock(u64) | resetCount(u32) | restartCount(u32) | safe(u8) }
    let clock_ms = state::BOOT_CLOCK_MS.load(Ordering::Relaxed);
    let reset = state::TPM_RESET_COUNT.load(Ordering::Relaxed) as u32;
    let restart = state::TPM_RESTART_COUNT.load(Ordering::Relaxed) as u32;
    w.u64(clock_ms);     // time
    w.u64(clock_ms);     // clock (since manufacture)
    w.u32(reset);
    w.u32(restart);
    w.u8(1);             // safe = true (clock survived shutdowns)
    finalise(&mut w)
}

fn handle_pcr_read(tag: u16, r: &mut Reader, out: &mut [u8]) -> usize {
    // TPML_PCR_SELECTION: count(u32) + (alg:u16 + sizeOfSelect:u8 + bitmap)*
    let count = r.u32().unwrap_or(0).min(4);
    let mut selections: [(u16, [u8; 3]); 4] = [(0, [0u8; 3]); 4];
    let mut sel_count = 0;
    for _ in 0..count {
        let alg = match r.u16() { Some(a) => a, None => break };
        let size_of_select = r.u8().unwrap_or(0).min(8) as usize;
        let mut bitmap = [0u8; 3];
        if let Some(s) = r.slice(size_of_select) {
            for i in 0..size_of_select.min(3) { bitmap[i] = s[i]; }
        }
        if sel_count < 4 {
            selections[sel_count] = (alg, bitmap);
            sel_count += 1;
        }
    }

    // Build response: pcrUpdateCounter (u32) | pcrSelectionOut | digests
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    w.u32(0);                                // pcrUpdateCounter
    w.u32(sel_count as u32);                 // pcrSelectionOut count
    let mut digest_count: u32 = 0;
    let mut digests: [[u8; 32]; 24] = [[0u8; 32]; 24];

    let g = state::lock();
    for s in 0..sel_count {
        let (alg, bitmap) = selections[s];
        w.u16(alg);
        w.u8(3);                              // sizeOfSelect = 3 (24 PCRs)
        w.bytes(&bitmap);
        if alg == TPM_ALG_SHA256 {
            for pcr in 0..24 {
                if bitmap[pcr / 8] & (1 << (pcr % 8)) != 0 {
                    if let Some(v) = state::pcr_read(&g, pcr) {
                        if (digest_count as usize) < digests.len() {
                            digests[digest_count as usize] = v;
                            digest_count += 1;
                        }
                    }
                }
            }
        }
    }
    drop(g);

    w.u32(digest_count);
    for i in 0..digest_count as usize {
        w.tpm2b(&digests[i]);
    }
    finalise(&mut w)
}

fn handle_pcr_extend(tag: u16, r: &mut Reader, out: &mut [u8]) -> usize {
    let pcr_handle = match r.u32() { Some(h) => h, None => return write_error(out, tag, TPM_RC_COMMAND_SIZE) };
    // Skip auth area for sessioned commands.
    if tag == TPM_ST_SESSIONS {
        if let Some(auth_size) = r.u32() {
            if r.skip(auth_size as usize).is_none() { return write_error(out, tag, TPM_RC_COMMAND_SIZE); }
        }
    }
    // TPML_DIGEST_VALUES: count(u32) + (alg:u16 + digest:N)*
    let count = r.u32().unwrap_or(0);
    let pcr_index = (pcr_handle & 0x00FF_FFFF) as usize;
    if pcr_index >= 24 {
        return write_error(out, tag, TPM_RC_HANDLE);
    }
    let g = state::lock();
    for _ in 0..count.min(4) {
        let alg = r.u16().unwrap_or(0);
        let digest_size = match alg {
            TPM_ALG_SHA1 => 20,
            TPM_ALG_SHA256 => 32,
            TPM_ALG_SHA384 => 48,
            _ => break,
        };
        let bytes = r.slice(digest_size);
        if alg == TPM_ALG_SHA256 {
            if let Some(b) = bytes {
                if b.len() == 32 {
                    let mut d = [0u8; 32];
                    d.copy_from_slice(b);
                    state::pcr_extend(&g, pcr_index, &d);
                }
            }
        }
    }
    drop(g);
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    finalise(&mut w)
}

fn handle_hash(tag: u16, r: &mut Reader, out: &mut [u8]) -> usize {
    let data = match r.tpm2b() { Some(d) => d, None => return write_error(out, tag, TPM_RC_COMMAND_SIZE) };
    let alg = r.u16().unwrap_or(0);
    let _hierarchy = r.u32();
    if alg != TPM_ALG_SHA256 {
        return write_error(out, tag, TPM_RC_VALUE_PARAM1);
    }
    let digest = sha256::hash(data);
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    w.tpm2b(&digest);
    // validation TPMT_TK_HASHCHECK: tag(2) | hierarchy(4) | digest(TPM2B, empty)
    w.u16(0x8024);                       // TPM_ST_HASHCHECK
    w.u32(0x4000_0007);                  // TPM_RH_NULL
    w.tpm2b(&[]);
    finalise(&mut w)
}

fn handle_nv_read_public(tag: u16, r: &mut Reader, out: &mut [u8]) -> usize {
    let handle = match r.u32() { Some(h) => h, None => return write_error(out, tag, TPM_RC_COMMAND_SIZE) };
    let g = state::lock();
    let slot = match state::nv_find(&g, handle) {
        Some(s) => s,
        None => { drop(g); return write_error(out, tag, TPM_RC_HANDLE); }
    };
    let (attrs, data_len) = state::nv_get_attributes(&g, slot);
    drop(g);
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    // TPMS_NV_PUBLIC: nvIndex(4) | nameAlg(2) | attributes(4) | authPolicy(TPM2B, empty) | dataSize(2)
    let body_size = 4 + 2 + 4 + 2 + 2;     // 14 bytes
    w.u16(body_size as u16);                // size of public area
    w.u32(handle);
    w.u16(TPM_ALG_SHA256);
    w.u32(attrs);
    w.tpm2b(&[]);                            // authPolicy
    w.u16(data_len);
    // nvName: TPM2B with sha256(public) — return empty placeholder.
    w.tpm2b(&[]);
    finalise(&mut w)
}

fn handle_nv_read(tag: u16, r: &mut Reader, out: &mut [u8]) -> usize {
    let _auth_handle = r.u32();
    let nv_handle = match r.u32() { Some(h) => h, None => return write_error(out, tag, TPM_RC_COMMAND_SIZE) };
    if tag == TPM_ST_SESSIONS {
        if let Some(auth_size) = r.u32() {
            if r.skip(auth_size as usize).is_none() { return write_error(out, tag, TPM_RC_COMMAND_SIZE); }
        }
    }
    let size = r.u16().unwrap_or(0).min(1024);
    let offset = r.u16().unwrap_or(0);
    let g = state::lock();
    let slot = match state::nv_find(&g, nv_handle) {
        Some(s) => s,
        None => { drop(g); return write_error(out, tag, TPM_RC_HANDLE); }
    };
    let mut out_buf = [0u8; 1024];
    let n = state::nv_read(&g, slot, offset, size, &mut out_buf);
    drop(g);
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    if tag == TPM_ST_SESSIONS {
        w.u32(0);                            // parameter size (= 0 placeholder)
    }
    w.tpm2b(&out_buf[..n]);
    finalise(&mut w)
}

fn handle_start_auth_session(tag: u16, _r: &mut Reader, out: &mut [u8]) -> usize {
    // Skeleton — return a session handle in the HMAC range. We don't
    // actually back the session with state; commands that read auth
    // areas just skip them.
    let session_handle: u32 = 0x0200_0000; // TPM_HT_HMAC_SESSION
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    w.u32(session_handle);
    // nonceTPM (TPM2B with 32 random bytes)
    let mut nonce = [0u8; 32];
    fill_random(&mut nonce);
    w.tpm2b(&nonce);
    finalise(&mut w)
}

fn handle_flush_context(tag: u16, _r: &mut Reader, out: &mut [u8]) -> usize {
    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    finalise(&mut w)
}

fn handle_get_capability(tag: u16, r: &mut Reader, out: &mut [u8]) -> usize {
    let capability = r.u32().unwrap_or(0);
    let property = r.u32().unwrap_or(0);
    let max_count = r.u32().unwrap_or(0).min(64);

    let mut w = Writer::new(out);
    write_header(&mut w, tag, TPM_RC_SUCCESS);
    w.u8(0);                                 // moreData = 0 (no more)
    w.u32(capability);

    match capability {
        TPM_CAP_TPM_PROPERTIES => write_tpm_properties(&mut w, property, max_count),
        TPM_CAP_PCRS           => write_pcrs(&mut w),
        TPM_CAP_ALGS           => write_algs(&mut w),
        TPM_CAP_COMMANDS       => { w.u32(0); }   // empty command list
        TPM_CAP_HANDLES        => { w.u32(0); }
        _                      => { w.u32(0); }
    }
    finalise(&mut w)
}

fn write_tpm_properties(w: &mut Writer, start: u32, max: u32) {
    // Build sorted list of (id, value) for the property range we
    // recognise. The caller passes a starting property; we report
    // those at or above that property up to `max`.
    let (mfr, vendor_str_1) = tpm_manufacturer();
    let table: [(u32, u32); 25] = [
        (PT_FAMILY_INDICATOR,   u32::from_be_bytes(*b"2.0\0")),
        (PT_LEVEL,              0),
        (PT_REVISION,           159),                    // spec rev 1.59
        (PT_DAY_OF_YEAR,        274),
        (PT_YEAR,               2024),
        (PT_MANUFACTURER,       mfr),
        (PT_VENDOR_STRING_1,    vendor_str_1),
        (PT_VENDOR_STRING_2,    u32::from_be_bytes(*b"\0\0\0\0")),
        (PT_VENDOR_STRING_3,    0),
        (PT_VENDOR_STRING_4,    0),
        (PT_VENDOR_TPM_TYPE,    0),
        (PT_FIRMWARE_VERSION_1, 0x0003_0058),            // fTPM 3.88
        (PT_FIRMWARE_VERSION_2, 0x0000_0001),
        (PT_INPUT_BUFFER,       1024),
        (PT_PCR_COUNT,          24),
        (PT_PCR_SELECT_MIN,     3),
        (PT_NV_INDEX_MAX,       2048),
        (PT_MAX_COMMAND_SIZE,   4096),
        (PT_MAX_RESPONSE_SIZE,  4096),
        (PT_MAX_DIGEST,         32),
        (PT_PERMANENT,          0),
        (PT_STARTUP_CLEAR,      0x8000_0001),            // phEnable + orderly
        // Sentinel: ensures table-size is fixed; unused tail.
        (0xFFFF_FFFF, 0),
        (0xFFFF_FFFF, 0),
        (0xFFFF_FFFF, 0),
    ];
    let count_slot = w.pos;
    w.u32(0);                                            // patched below
    let mut count = 0u32;
    for &(id, val) in table.iter() {
        if id == 0xFFFF_FFFF { break; }
        if id >= start && count < max {
            w.u32(id);
            w.u32(val);
            count += 1;
        }
    }
    w.patch_u32(count_slot, count);
}

fn write_pcrs(w: &mut Writer) {
    // TPML_PCR_SELECTION: count + (alg + sizeOfSelect + bitmap)*
    w.u32(1);                                            // one bank
    w.u16(TPM_ALG_SHA256);
    w.u8(3);                                             // sizeOfSelect
    // All 24 PCRs allocated
    w.bytes(&[0xFF, 0xFF, 0xFF]);
}

fn write_algs(w: &mut Writer) {
    // TPML_ALG_PROPERTY: count + (algId(u16) + properties(u32))*
    let algs: &[(u16, u32)] = &[
        (TPM_ALG_RSA,    0x0005),   // asymmetric + object
        (TPM_ALG_AES,    0x0202),   // symmetric + encrypt
        (TPM_ALG_HMAC,   0x0006),   // hash + signing
        (TPM_ALG_SHA1,   0x0004),
        (TPM_ALG_SHA256, 0x0004),
        (TPM_ALG_SHA384, 0x0004),
        (TPM_ALG_NULL,   0x0008),
        (TPM_ALG_ECC,    0x0005),
        (TPM_ALG_CFB,    0x0202),
    ];
    w.u32(algs.len() as u32);
    for &(id, props) in algs {
        w.u16(id);
        w.u32(props);
    }
}
