//! Nested-page-fault (NPF) handler.
//!
//! Routes by faulting guest-physical address to one of the trapped MMIO
//! regions (LAPIC / NIC BAR0 / NVMe BAR0). For each, we decode the
//! faulting instruction via `decode::decode_mov`, recover the register
//! operand + width + direction, then dispatch:
//!
//!   - **load (8B/8A)** — region.read(gpa, width) → guest register
//!   - **store (89/88)** — guest register → region.write(gpa, val, width)
//!
//! `exit_info_1` carries page-fault flags (P/RW/US/RSVD/I-fetch/data,
//! AMD APM Vol 2 §15.25.6) and `exit_info_2` holds the faulting GPA.
//! We trust the opcode-derived direction rather than EXIT_INFO_1[RW] —
//! the decoder is authoritative for which operand is memory.
//!
//! AMD NRIPS does *not* fill `next_rip` usefully for NPF — the field
//! either equals the faulting RIP or is undefined — so we advance RIP
//! by the decoded instruction length.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hypervisor::svm::gprs::GuestGprs;
use crate::sprintln;
use crate::hypervisor::svm::vmcb::Vmcb;

use crate::hardware::devices::registry::{self, MmioDevice};
use super::{decode, Action};

// Rate-limit "unknown GPA" abort prints. A wild NPF storm during early
// kernel boot can spam the serial log; cap to 16 first instances so
// we still see which addresses are involved without drowning the trace.
static UNKNOWN_NPF_COUNT: AtomicU64 = AtomicU64::new(0);
const UNKNOWN_NPF_LOG_CAP: u64 = 64;

// First-N NPF hits (any region) for boot diagnosis.
static NPF_TOTAL_COUNT: AtomicU64 = AtomicU64::new(0);
const NPF_TOTAL_LOG_CAP: u64 = 24;

static NPF_DECODE_FAIL: AtomicU64 = AtomicU64::new(0);

// Diagnostic (terminal-blocker hunt): the guest spins in OVMF firmware
// (RIP 0x7Exxxxxx-0x7Fxxxxxx) busy-polling some MMIO register. Capture
// which GPA/region it hammers so we can identify the register and why it
// never satisfies. Throttled. Remove once the spin is understood.
static SPIN_NPF_COUNT: AtomicU64 = AtomicU64::new(0);
static SPIN_RD_COUNT: AtomicU64 = AtomicU64::new(0);

// ── NPF region histogram (temporary) ──
// Which device region the kernel-phase NPF storm actually hits (the firmware-
// gated [npf-spin] only samples RIP 0x7E-0x80). HPET should read ~0 now that
// its MMIO is a writable shadow.
#[allow(clippy::declare_interior_mutable_const)]
const NRZ: AtomicU64 = AtomicU64::new(0);
static NPF_REG: [AtomicU64; registry::MMIO_COUNT + 1] = [NRZ; registry::MMIO_COUNT + 1];
fn npf_reg_prof(gpa: u64) {
    let i = registry::find_mmio(gpa).map(|(i, _)| i).unwrap_or(registry::MMIO_COUNT);
    NPF_REG[i].fetch_add(1, Ordering::Relaxed);
    let total: u64 = NPF_REG.iter().map(|c| c.load(Ordering::Relaxed)).sum();
    if total % 50_000 == 0 {
        crate::sprint!("[npf-reg]");
        for (j, c) in NPF_REG.iter().enumerate() {
            crate::sprint!(" {}={}", registry::mmio_name_at(j), c.load(Ordering::Relaxed));
        }
        crate::sprintln!();
    }
}

fn region_name(gpa: u64) -> &'static str {
    registry::mmio_name(gpa)
}

pub unsafe fn handle(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    let c = unsafe { &(*vmcb).control };
    let gpa   = { c.exit_info_2 };
    let info1 = { c.exit_info_1 };
    let rip   = unsafe { (*vmcb).state.rip };
    npf_reg_prof(gpa);

    // Stealth exec-hook: instruction-fetch fault on an armed hook page is
    // captured + resumed here. No-op (falls through) when no hooks are armed.
    if unsafe { crate::introspect::hook::dispatch(vmcb, gpa, info1, rip, gprs) } {
        return Action::Resume;
    }

    // Spin diagnostic: firmware-region NPF poll. The offset within the
    // region (gpa - region base) names the exact register being polled.
    if (0x7E00_0000..0x8000_0000).contains(&rip) {
        let n = SPIN_NPF_COUNT.fetch_add(1, Ordering::Relaxed);
        if n < 8 || n % 8192 == 0 {
            // If clk advances between samples yet the spin persists, the guest
            // is waiting on an event/bit, not a clock timeout.
            let clk = crate::infra::clock::now();
            sprintln!("[npf-spin] GPA=0x{:08X} region={} info1=0x{:X} rip=0x{:X} clk=0x{:X} #{}",
                gpa, region_name(gpa), info1, rip, clk, n);
        }
    }

    let total = NPF_TOTAL_COUNT.fetch_add(1, Ordering::Relaxed);
    if total < NPF_TOTAL_LOG_CAP {
        sprintln!("[npf] GPA=0x{:016X} info1=0x{:X} RIP=0x{:016X} (#{}/{})",
            gpa, info1, rip, total + 1, NPF_TOTAL_LOG_CAP);
    }

    let region: Option<&'static dyn MmioDevice> = match registry::find_mmio(gpa) {
        Some((_, d)) => Some(d),
        None => {
            // Standard hypervisor pattern (KVM `vmx_handle_ept_misconfig`,
            // QEMU `kvm_set_phys_mem`): an MMIO read at an address with
            // no backing device returns all-zeros, a write is silently
            // dropped, and the guest moves on. Real PC firmware does
            // the same with the legacy ISA "no device responds" bus
            // pull-up — drivers see 0xFF for IO ports / 0 for MMIO and
            // bail their probe routines.
            //
            // Aborting on every unknown MMIO would break legitimate
            // driver probes for chipset blocks we haven't modeled
            // (AMD IOMMU at 0xFED80000, motherboard SMBus, etc.). Log
            // the first NN_LOG_CAP hits so a real bug is still visible
            // in the trace.
            let n = UNKNOWN_NPF_COUNT.fetch_add(1, Ordering::Relaxed);
            if n < UNKNOWN_NPF_LOG_CAP {
                sprintln!(
                    "[npf ] unknown GPA=0x{:016X} info1=0x{:X} RIP=0x{:016X} (#{}/{}) -> silent",
                    gpa, info1, rip, n + 1, UNKNOWN_NPF_LOG_CAP,
                );
            }
            None
        }
    };

    let fetched = c.guest_inst_len as usize;
    let bytes = unsafe { &(*vmcb).control.guest_inst_bytes };
    let valid = &bytes[..fetched.min(bytes.len())];

    // REP MOVS between a device BAR and RAM (Windows READ/WRITE_REGISTER_
    // BUFFER_*). The single-MOV decoder can't model a string copy, so
    // emulate it: route the MMIO side through the region emulator and the
    // RAM side through guest-virtual memory.
    if unsafe { emulate_rep_movs(vmcb, gprs, gpa, info1, region, valid) } {
        return Action::Resume;
    }

    let decoded = match decode::decode_mov(valid) {
        Some(d) if d.len > 0 => d,
        _ => {
            let n = NPF_DECODE_FAIL.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                let b = valid;
                sprintln!(
                    "[npf] DECODE FAIL gpa=0x{:X} region={} info1=0x{:X} rip=0x{:X} ilen={} bytes={:02X?} rsi=0x{:X} rdi=0x{:X} rcx=0x{:X}",
                    gpa, region_name(gpa), info1, rip, fetched, b, gprs.rsi, gprs.rdi, gprs.rcx
                );
            }
            return Action::Abort;
        }
    };

    let s = unsafe { &mut (*vmcb).state };

    if decoded.is_write {
        // Store value comes from the immediate (C6/C7) when present,
        // otherwise from the register operand.
        let val = match decoded.imm {
            Some(imm) => imm,
            None => gprs.read_indexed(s, decoded.reg),
        };
        if let Some(ref r) = region {
            r.write(gpa, val, decoded.mem_width);
        }
        // None: unknown MMIO write — silently drop, KVM-style.
    } else {
        let raw = match region {
            Some(ref r) => r.read(gpa, decoded.mem_width),
            // Unknown MMIO read returns 0 (KVM `vmx_handle_ept_misconfig`
            // fallback). Real chipsets behave the same for unmapped
            // bus addresses.
            None => 0,
        };
        // Spin diagnostic: the polled value reveals which bit OVMF waits for.
        // Log a CONTIGUOUS window (#40000..40140) to capture the exact
        // register read sequence of one poll-loop iteration.
        if (0x7E00_0000..0x8000_0000).contains(&rip) {
            let n = SPIN_RD_COUNT.fetch_add(1, Ordering::Relaxed);
            if n < 8 || (40000..40140).contains(&n) || n % 8192 == 0 {
                sprintln!("[npf-rd] {} gpa=0x{:08X} = 0x{:X} w{} rip=0x{:X} #{}",
                    region_name(gpa), gpa, raw, decoded.mem_width, rip, n);
            }
        }
        // Extend the narrow memory operand into the destination register.
        // MOVSX sign-extends; plain MOV / MOVZX zero-extend (which is what
        // write_indexed_width does at reg_width). reg_width == mem_width for
        // the plain MOVs, so the extension is a no-op there.
        let val = if decoded.signed {
            sign_extend(raw, decoded.mem_width)
        } else {
            raw
        };
        gprs.write_indexed_width(s, decoded.reg, val, decoded.reg_width);
    }

    s.rip = s.rip.wrapping_add(decoded.len);
    Action::Resume
}

#[inline]
fn bytes_to_u64(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, &x) in b.iter().enumerate() {
        v |= (x as u64) << (i * 8);
    }
    v
}

#[inline]
fn u64_to_bytes(v: u64, b: &mut [u8]) {
    for (i, x) in b.iter_mut().enumerate() {
        *x = (v >> (i * 8)) as u8;
    }
}

/// Emulate a `REP MOVS` whose source or destination is trapped MMIO.
/// Windows' READ_REGISTER_BUFFER_* / WRITE_REGISTER_BUFFER_* helpers copy
/// between a device BAR and RAM with `rep movsd`/`movsb`, which the
/// single-MOV NPF decoder can't model. Copy `RCX` elements one at a time:
/// the MMIO side goes through the region emulator, the RAM side through
/// guest-virtual memory (translated under the guest CR3). Returns true when
/// the instruction was a REP MOVS and has been fully emulated (RIP/RSI/RDI/
/// RCX advanced). Non-MOVS or non-REP encodings return false to fall back
/// to the single-MOV path.
unsafe fn emulate_rep_movs(
    vmcb: *mut Vmcb,
    gprs: &mut GuestGprs,
    gpa: u64,
    info1: u64,
    region: Option<&dyn MmioDevice>,
    bytes: &[u8],
) -> bool {
    // Parse legacy prefixes + REX ahead of the opcode. REP (F3) is required;
    // 66 selects 2-byte operands, REX.W selects 8-byte; A4=MOVSB (1 byte),
    // A5=MOVS{W,D,Q} (operand-size).
    let mut i = 0;
    let mut rep = false;
    let mut opsize_66 = false;
    let mut rex_w = false;
    while i < bytes.len() {
        match bytes[i] {
            0xF3 | 0xF2 => { rep = true; i += 1; }
            0x66 => { opsize_66 = true; i += 1; }
            0x67 => { i += 1; }                       // addr-size override
            0x40..=0x4F => { rex_w = bytes[i] & 0x08 != 0; i += 1; }
            _ => break,
        }
    }
    if !rep || i >= bytes.len() {
        return false;
    }
    let size: u64 = match bytes[i] {
        0xA4 => 1,
        0xA5 => if rex_w { 8 } else if opsize_66 { 2 } else { 4 },
        _ => return false,
    };
    let instr_len = (i + 1) as u64;

    let s = unsafe { &mut (*vmcb).state };
    let cr3 = s.cr3;
    let df = (s.rflags >> 10) & 1 != 0;
    let step = if df { size.wrapping_neg() } else { size };
    // exit_info_1 bit 1 (RW): 1 = the faulting access was a write, so the
    // MMIO operand is the destination (RDI); otherwise it's the source (RSI).
    let mmio_is_dst = info1 & (1 << 1) != 0;

    let count = gprs.rcx;
    let mut rsi = gprs.rsi;
    let mut rdi = gprs.rdi;
    let mut mmio = gpa;
    let w = size as usize;
    for _ in 0..count {
        let mut buf = [0u8; 8];
        if mmio_is_dst {
            // RAM[RSI] -> MMIO[RDI]
            if !crate::introspect::mem::read_virt(cr3, rsi, &mut buf[..w]) {
                break;
            }
            let val = bytes_to_u64(&buf[..w]);
            if let Some(r) = region {
                r.write(mmio, val, size as u8);
            }
        } else {
            // MMIO[RSI] -> RAM[RDI]
            let val = match region {
                Some(r) => r.read(mmio, size as u8),
                None => 0,
            };
            u64_to_bytes(val, &mut buf[..w]);
            if !crate::introspect::mem::write_virt(cr3, rdi, &buf[..w]) {
                break;
            }
        }
        rsi = rsi.wrapping_add(step);
        rdi = rdi.wrapping_add(step);
        mmio = mmio.wrapping_add(step);
    }
    gprs.rsi = rsi;
    gprs.rdi = rdi;
    gprs.rcx = 0;
    s.rip = s.rip.wrapping_add(instr_len);
    true
}

/// Sign-extend a `width`-byte value held in the low bits of `val` to 64 bits.
fn sign_extend(val: u64, width: u8) -> u64 {
    match width {
        1 => (val as u8 as i8 as i64) as u64,
        2 => (val as u16 as i16 as i64) as u64,
        4 => (val as u32 as i32 as i64) as u64,
        _ => val,
    }
}

