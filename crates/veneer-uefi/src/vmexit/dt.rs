//! Descriptor-table read intercept handler — SGDT, SIDT, SLDT, STR.
//!
//! AMD does *not* fill decode-assist for these intercepts (only NPF and a
//! handful of asynchronous events get `guest_inst_bytes` populated). So
//! we fetch the instruction stream directly from `vmcb.state.rip` and
//! decode the addressing mode ourselves: optional REX, 0F 01 (SGDT/SIDT)
//! or 0F 00 (SLDT/STR), ModR/M, optional SIB, 0/1/4 byte displacement.
//!
//! Under our current guest setup (Long64 mode reusing the host CR0/CR3/
//! CR4/EFER, UEFI identity map) guest linear == host physical for the
//! pages we care about, so writing to the decoded effective address
//! directly writes guest memory. Nested-OS work will require walking
//! the guest CR3 to translate linear → physical.
//!
//! What we write:
//!   - SGDT/SIDT: 2-byte limit + 8-byte base (10 bytes total, LE)
//!     pulled from `vmcb.state.gdtr` / `vmcb.state.idtr`
//!   - SLDT/STR : 2-byte selector pulled from `vmcb.state.ldtr.selector`
//!     / `vmcb.state.tr.selector`. Register form (mode=11) writes to
//!     the GPR identified by ModR/M.rm + REX.B.
//!
//! This is emulation, not deception: the guest set IDTR via LIDT (which
//! is *not* intercepted) and SIDT must return what was set. Anti-VMM
//! is achieved by seeding plausible IDTR/GDTR base values at guest
//! init time (init_guest_longmode), not by lying here.

use crate::svm::gprs::GuestGprs;
use crate::svm::vmcb::Vmcb;

use super::Action;

#[derive(Clone, Copy)]
enum DtKind { Sgdt, Sidt, Sldt, Str }

pub unsafe fn handle_sgdt(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    handle(vmcb, gprs, DtKind::Sgdt)
}
pub unsafe fn handle_sidt(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    handle(vmcb, gprs, DtKind::Sidt)
}
pub unsafe fn handle_sldt(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    handle(vmcb, gprs, DtKind::Sldt)
}
pub unsafe fn handle_str(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    handle(vmcb, gprs, DtKind::Str)
}

unsafe fn handle(vmcb: *mut Vmcb, gprs: &mut GuestGprs, kind: DtKind) -> Action {
    let s = unsafe { &mut (*vmcb).state };
    let rip = s.rip;

    // Fetch up to 15 instruction bytes from guest RIP. Identity mapping
    // means we read host memory at the same physical address.
    let mut buf = [0u8; 15];
    for i in 0..15 {
        buf[i] = unsafe { core::ptr::read_volatile((rip.wrapping_add(i as u64)) as *const u8) };
    }

    let decoded = match decode(&buf) {
        Some(d) => d,
        None => return Action::Abort,
    };

    match kind {
        DtKind::Sgdt => {
            let limit = unsafe {
                core::ptr::addr_of!(s.gdtr.limit).read_unaligned() as u16
            };
            let base = unsafe {
                core::ptr::addr_of!(s.gdtr.base).read_unaligned()
            };
            write_descriptor(s, gprs, &decoded, limit, base);
        }
        DtKind::Sidt => {
            let limit = unsafe {
                core::ptr::addr_of!(s.idtr.limit).read_unaligned() as u16
            };
            let base = unsafe {
                core::ptr::addr_of!(s.idtr.base).read_unaligned()
            };
            write_descriptor(s, gprs, &decoded, limit, base);
        }
        DtKind::Sldt => {
            let sel = unsafe {
                core::ptr::addr_of!(s.ldtr.selector).read_unaligned()
            };
            write_selector(s, gprs, &decoded, sel);
        }
        DtKind::Str => {
            let sel = unsafe {
                core::ptr::addr_of!(s.tr.selector).read_unaligned()
            };
            write_selector(s, gprs, &decoded, sel);
        }
    }

    s.rip = s.rip.wrapping_add(decoded.len);
    Action::Resume
}

unsafe fn write_descriptor(
    s: &mut crate::svm::vmcb::VmcbStateSave,
    gprs: &mut GuestGprs,
    d: &DecodedDt,
    limit: u16,
    base: u64,
) {
    // SGDT/SIDT cannot use register form — mode=11 is #UD on real CPU.
    if d.is_register_form {
        return;
    }
    let addr = compute_effective_address(s, gprs, d);
    unsafe {
        core::ptr::write_unaligned(addr as *mut u16, limit);
        core::ptr::write_unaligned((addr.wrapping_add(2)) as *mut u64, base);
    }
}

unsafe fn write_selector(
    s: &mut crate::svm::vmcb::VmcbStateSave,
    gprs: &mut GuestGprs,
    d: &DecodedDt,
    selector: u16,
) {
    if d.is_register_form {
        // Write u16 into low 16 of GPR identified by rm+REX.B; upper
        // bits unchanged (per Intel SDM SLDT/STR description).
        let cur = gprs.read_indexed(s, d.reg_or_rm);
        let new = (cur & !0xFFFFu64) | (selector as u64);
        gprs.write_indexed(s, d.reg_or_rm, new);
    } else {
        let addr = compute_effective_address(s, gprs, d);
        unsafe { core::ptr::write_unaligned(addr as *mut u16, selector); }
    }
}

/// One decoded SGDT/SIDT/SLDT/STR instruction. The opcode is implicit
/// (selected by the caller routing on VMEXIT code). We just need the
/// length, addressing mode, and operand register info.
struct DecodedDt {
    len: u64,
    is_register_form: bool,
    /// For register form, the destination GPR (rm + REX.B). For memory
    /// form, the base register encoded in ModR/M.rm + REX.B.
    reg_or_rm: u8,
    /// True for `[RIP + disp32]` (mode=00, rm=101).
    rip_relative: bool,
    /// SIB byte if present (mode != 11 and rm == 100).
    sib: Option<u8>,
    /// True when the encoding has no base register (mode=00 with either
    /// rm=101 RIP-relative or SIB.base=5 disp32-only). In that case
    /// `reg_or_rm` is ignored for memory form.
    no_base: bool,
    /// REX prefix byte (0 if absent) — kept around for REX.X (index
    /// extension) when decoding SIB.
    rex: u8,
    /// Signed displacement (sign-extended to i64 by the caller).
    disp: i32,
}

fn decode(bytes: &[u8]) -> Option<DecodedDt> {
    let mut p = 0;
    let mut rex: u8 = 0;

    // Skip legacy prefixes we don't care about (segment overrides, etc.)
    loop {
        match bytes.get(p).copied() {
            Some(0x66) | Some(0x67)
            | Some(0xF0) | Some(0xF2) | Some(0xF3)
            | Some(0x26) | Some(0x2E) | Some(0x36) | Some(0x3E)
            | Some(0x64) | Some(0x65) => p += 1,
            _ => break,
        }
    }
    if let Some(&b) = bytes.get(p) {
        if (0x40..=0x4F).contains(&b) { rex = b; p += 1; }
    }

    // Two-byte opcode escape: must be 0F 00 (SLDT/STR/...) or 0F 01
    // (SGDT/SIDT/SMSW/...). We don't disambiguate by the second opcode
    // byte here because the dispatcher already routed by exit_code —
    // we just need to skip 2 bytes and parse the ModR/M.
    let escape = *bytes.get(p)?;
    if escape != 0x0F { return None; }
    p += 1;
    let _opcode2 = *bytes.get(p)?;
    p += 1;

    let modrm = *bytes.get(p)?;
    p += 1;
    let mode = (modrm >> 6) & 0b11;
    let rm = modrm & 0b111;
    let rex_b = rex & 1;
    let reg_or_rm = (rex_b << 3) | rm;

    if mode == 0b11 {
        return Some(DecodedDt {
            len: p as u64,
            is_register_form: true,
            reg_or_rm,
            rip_relative: false,
            sib: None,
            no_base: false,
            rex,
            disp: 0,
        });
    }

    // SIB if rm == 100.
    let mut sib: Option<u8> = None;
    let mut sib_no_base = false;
    let mut sib_disp_size: Option<usize> = None;
    if rm == 0b100 {
        let s = *bytes.get(p)?;
        sib = Some(s);
        p += 1;
        let sib_base = s & 0b111;
        if mode == 0b00 && sib_base == 0b101 {
            sib_no_base = true;
            sib_disp_size = Some(4);
        }
    }

    // Displacement size: SIB disp32-only special case wins; otherwise
    // mode/rm decides.
    let disp_size: usize = if let Some(n) = sib_disp_size {
        n
    } else {
        match mode {
            0b00 => if rm == 0b101 { 4 } else { 0 }, // RIP-relative
            0b01 => 1,
            0b10 => 4,
            _ => return None,
        }
    };

    if bytes.len() < p + disp_size { return None; }
    let disp: i32 = match disp_size {
        0 => 0,
        1 => (bytes[p] as i8) as i32,
        4 => i32::from_le_bytes([bytes[p], bytes[p+1], bytes[p+2], bytes[p+3]]),
        _ => 0,
    };
    p += disp_size;

    let rip_relative = mode == 0b00 && rm == 0b101 && sib.is_none();
    let no_base = rip_relative || sib_no_base;

    Some(DecodedDt {
        len: p as u64,
        is_register_form: false,
        reg_or_rm,
        rip_relative,
        sib,
        no_base,
        rex,
        disp,
    })
}

/// Compute the linear address the instruction will read from / write to.
/// Long mode + default segment (DS/SS/CS/ES base=0) is assumed; FS/GS
/// override would need the segment base from VMCB which we don't read
/// here. None of the DT instructions take FS/GS overrides in practice.
fn compute_effective_address(
    s: &crate::svm::vmcb::VmcbStateSave,
    gprs: &GuestGprs,
    d: &DecodedDt,
) -> u64 {
    if d.rip_relative {
        // [RIP + disp32]. RIP is the address of the *next* instruction.
        let rip_next = s.rip.wrapping_add(d.len);
        return rip_next.wrapping_add(d.disp as i64 as u64);
    }

    if let Some(sib) = d.sib {
        let scale = (sib >> 6) & 0b11;
        let index = (((d.rex >> 1) & 1) << 3) | ((sib >> 3) & 0b111);
        let base = ((d.rex & 1) << 3) | (sib & 0b111);

        // Index == 4 (RSP) means "no index" per Intel SDM.
        let index_val: u64 = if (index & 0b111) == 0b100 {
            0
        } else {
            gprs.read_indexed(s, index)
        };

        let base_val: u64 = if d.no_base { 0 } else { gprs.read_indexed(s, base) };
        let scaled = index_val.wrapping_shl(scale as u32);
        return base_val.wrapping_add(scaled).wrapping_add(d.disp as i64 as u64);
    }

    // Plain [reg + disp].
    let base_val = gprs.read_indexed(s, d.reg_or_rm);
    base_val.wrapping_add(d.disp as i64 as u64)
}
