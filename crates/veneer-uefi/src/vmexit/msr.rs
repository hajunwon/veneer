//! RDMSR / WRMSR intercept handlers.
//!
//! Per-MSR routing lives here. The default policy is:
//!   - RDMSR: forward to host CPU for a whitelisted set; everything else
//!     returns 0 (a real #GP from the host would cascade into a host
//!     fault while we hold guest registers, so we eat the leak instead).
//!   - WRMSR: silently drop. Guest writes never reach host hardware.
//!
//! Specific MSRs get policy overrides:
//!   - Anti-VMM (VM_CR/EFER/FEATURE_CONTROL) — synthesise "no VMX/SVM"
//!   - Profile-driven (BIOS_SIGN_ID/PLATFORM_ID) — stable across boots
//!   - Stealth (PERF/THERM/RAPL/DEBUGCTL) — return 0 so monitor MSRs
//!     don't leak "this machine looks idle" timing patterns
//!   - MTRR — synthesised consistent values so a Windows / Linux kernel
//!     reading the MTRR cap+def doesn't see hypervisor-shaped garbage
//!   - PAT — host pass-through (real WB/WT/UC encoding)
//!   - AMD package MSRs — host pass-through where safe, else 0

use core::sync::atomic::{AtomicU64, Ordering};

use crate::identity::active;
use crate::arch::rdmsr as host_rdmsr;
use crate::svm::gprs::GuestGprs;
use crate::svm::vmcb::Vmcb;

use super::{lengths, Action};

// ───── Per-MSR shadow for WRMSR round-trip semantics ─────────────────
//
// A few MSRs are read by the guest after writing them — most notably
// IA32_PAT (Windows sets WB+WT+UC+WC pattern at boot, then reads PAT
// for verification) and the MTRR variable ranges (kernel reconfigures
// MTRRs after BIOS). If WRMSR silently drops and RDMSR returns synth
// defaults, the guest sees its own writes lost — a tell.
//
// Shadow stores the last value written; RDMSR for the shadowed MSR
// returns that instead of host pass-through / synth default. State is
// global (real MTRR/PAT are per-CPU but Windows broadcasts identical
// values, so global is consistent with real-system behaviour).

// Headroom over the ~29 MTRR/PAT slots plus APIC_BASE / MISC_ENABLE /
// TSC_ADJUST and a few speculation-control MSRs, so a write is never
// silently dropped (a dropped MTRR write makes the guest's memory-type
// programming vanish on read-back and re-loop).
const SHADOW_CAPACITY: usize = 64;
struct ShadowSlot {
    msr: AtomicU64, // upper 32 = MSR index, lower 32 = 0 sentinel; 0 = unused
    val: AtomicU64,
}

#[allow(clippy::declare_interior_mutable_const)]
const SHADOW_INIT: ShadowSlot = ShadowSlot {
    msr: AtomicU64::new(0),
    val: AtomicU64::new(0),
};
static SHADOW: [ShadowSlot; SHADOW_CAPACITY] = [SHADOW_INIT; SHADOW_CAPACITY];

fn is_shadowed_msr(msr: u32) -> bool {
    match msr {
        idx::IA32_PAT => true,
        idx::IA32_MTRR_DEF_TYPE => true,
        idx::IA32_MTRR_PHYSBASE0..=idx::IA32_MTRR_PHYSMASK_LAST => true,
        idx::IA32_MTRR_FIX64K_00000
        | idx::IA32_MTRR_FIX16K_80000
        | idx::IA32_MTRR_FIX16K_A0000 => true,
        idx::IA32_MTRR_FIX4K_C0000..=idx::IA32_MTRR_FIX4K_F8000 => true,
        // Round-tripped so the guest's write is reflected on read-back rather
        // than reading the host value (or a synth default) and re-looping.
        idx::IA32_APIC_BASE => true,
        idx::IA32_MISC_ENABLE => true,
        idx::IA32_TSC_ADJUST => true,
        idx::IA32_SPEC_CTRL => true,
        // AMD HWCR — round-tripped so a guest that flips McStatusWrEn /
        // other writable bits reads back its own write rather than the
        // reset default and re-loops.
        idx::AMD_HWCR => true,
        // TSC_AUX — guest writes (per-CPU processor-ID seeding) round-trip
        // rather than read back the host core index.
        idx::TSC_AUX => true,
        _ => false,
    }
}

fn shadow_read(msr: u32) -> Option<u64> {
    let key = (msr as u64) << 32 | 0x1; // bit 0 = "set" marker
    for slot in SHADOW.iter() {
        let cur = slot.msr.load(Ordering::Relaxed);
        if cur == key { return Some(slot.val.load(Ordering::Relaxed)); }
        if cur == 0 { break; }
    }
    None
}

fn shadow_write(msr: u32, val: u64) {
    let key = (msr as u64) << 32 | 0x1;
    // First pass: update if already present.
    for slot in SHADOW.iter() {
        let cur = slot.msr.load(Ordering::Relaxed);
        if cur == key {
            slot.val.store(val, Ordering::Relaxed);
            return;
        }
        if cur == 0 { break; }
    }
    // Second pass: claim the first empty slot.
    for slot in SHADOW.iter() {
        if slot.msr.compare_exchange(0, key, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            slot.val.store(val, Ordering::Relaxed);
            return;
        }
    }
    // Capacity exhausted — silently drop. Won't happen in practice
    // (~29 shadowed MSRs vs 32 capacity).
}

#[allow(dead_code)]
pub mod idx {
    pub const IA32_TSC: u32              = 0x0000_0010;
    pub const IA32_PLATFORM_ID: u32      = 0x0000_0017;
    pub const IA32_APIC_BASE: u32        = 0x0000_001B;
    pub const IA32_TSC_DEADLINE: u32     = 0x0000_06E0;
    pub const IA32_FEATURE_CONTROL: u32  = 0x0000_003A;
    pub const IA32_TSC_ADJUST: u32       = 0x0000_003B;
    pub const IA32_BIOS_SIGN_ID: u32     = 0x0000_008B;
    pub const IA32_MTRRCAP: u32          = 0x0000_00FE;
    pub const IA32_SPEC_CTRL: u32        = 0x0000_0048;
    pub const IA32_PRED_CMD: u32         = 0x0000_0049;
    pub const IA32_ARCH_CAPABILITIES: u32 = 0x0000_010A;
    pub const IA32_FLUSH_CMD: u32        = 0x0000_010B;
    pub const IA32_SYSENTER_CS: u32      = 0x0000_0174;
    pub const IA32_SYSENTER_ESP: u32     = 0x0000_0175;
    pub const IA32_SYSENTER_EIP: u32     = 0x0000_0176;
    pub const IA32_MCG_CAP: u32          = 0x0000_0179;
    pub const IA32_MCG_STATUS: u32       = 0x0000_017A;
    pub const IA32_MCG_CTL: u32          = 0x0000_017B;
    pub const IA32_PERFEVTSEL0: u32      = 0x0000_0186;
    pub const IA32_PERFEVTSEL_LAST: u32  = 0x0000_018D;
    pub const IA32_PERF_STATUS: u32      = 0x0000_0198;
    pub const IA32_PERF_CTL: u32         = 0x0000_0199;
    pub const IA32_CLOCK_MODULATION: u32 = 0x0000_019A;
    pub const IA32_THERM_INTERRUPT: u32  = 0x0000_019B;
    pub const IA32_THERM_STATUS: u32     = 0x0000_019C;
    pub const IA32_MISC_ENABLE: u32      = 0x0000_01A0;
    pub const IA32_ENERGY_PERF_BIAS: u32 = 0x0000_01B0;
    pub const IA32_PACKAGE_THERM_STATUS: u32    = 0x0000_01B1;
    pub const IA32_PACKAGE_THERM_INTERRUPT: u32 = 0x0000_01B2;
    pub const IA32_DEBUGCTL: u32         = 0x0000_01D9;
    pub const IA32_MTRR_PHYSBASE0: u32   = 0x0000_0200;
    pub const IA32_MTRR_PHYSMASK_LAST: u32 = 0x0000_020F;
    pub const IA32_MTRR_FIX64K_00000: u32 = 0x0000_0250;
    pub const IA32_MTRR_FIX16K_80000: u32 = 0x0000_0258;
    pub const IA32_MTRR_FIX16K_A0000: u32 = 0x0000_0259;
    pub const IA32_MTRR_FIX4K_C0000: u32  = 0x0000_0268;
    pub const IA32_MTRR_FIX4K_F8000: u32  = 0x0000_026F;
    pub const IA32_PAT: u32              = 0x0000_0277;
    pub const IA32_MC0_CTL: u32          = 0x0000_0400;
    pub const IA32_MC31_MISC: u32        = 0x0000_047F; // covers MC0..MC31 ctl/status/addr/misc
    pub const IA32_MTRR_DEF_TYPE: u32    = 0x0000_02FF;
    pub const IA32_FIXED_CTR0: u32       = 0x0000_0309;
    pub const IA32_FIXED_CTR2: u32       = 0x0000_030B;
    pub const IA32_PERF_CAPABILITIES: u32 = 0x0000_0345;
    pub const IA32_FIXED_CTR_CTRL: u32   = 0x0000_038D;
    pub const IA32_PERF_GLOBAL_STATUS: u32 = 0x0000_038E;
    pub const IA32_PERF_GLOBAL_CTRL: u32 = 0x0000_038F;
    pub const IA32_PERF_GLOBAL_OVF_CTRL: u32 = 0x0000_0390;
    pub const IA32_RAPL_POWER_UNIT: u32  = 0x0000_0606;
    pub const IA32_PKG_ENERGY_STATUS: u32 = 0x0000_0611;
    pub const IA32_DRAM_ENERGY_STATUS: u32 = 0x0000_0619;
    pub const IA32_PMC0: u32             = 0x0000_00C1;
    pub const IA32_PMC_LAST: u32         = 0x0000_00C8;

    pub const EFER: u32                  = 0xC000_0080;
    pub const STAR: u32                  = 0xC000_0081;
    pub const LSTAR: u32                 = 0xC000_0082;
    pub const CSTAR: u32                 = 0xC000_0083;
    pub const SFMASK: u32                = 0xC000_0084;
    pub const FS_BASE: u32               = 0xC000_0100;
    pub const GS_BASE: u32               = 0xC000_0101;
    pub const KERNEL_GS_BASE: u32        = 0xC000_0102;
    pub const TSC_AUX: u32               = 0xC000_0103;
    pub const AMD_TSC_RATIO: u32         = 0xC000_0104;

    pub const AMD_SYSCFG: u32            = 0xC001_0010;
    pub const AMD_HWCR: u32              = 0xC001_0015;
    pub const AMD_TOP_MEM: u32           = 0xC001_001A;
    pub const AMD_TOP_MEM2: u32          = 0xC001_001D;
    pub const AMD_NB_CFG: u32            = 0xC001_001F;
    pub const VM_CR: u32                 = 0xC001_0114;
    pub const AMD_PERF_CTL0: u32         = 0xC001_0000;
    pub const AMD_PERF_CTL3: u32         = 0xC001_0003;
    pub const AMD_PERF_CTR0: u32         = 0xC001_0004;
    pub const AMD_PERF_CTR3: u32         = 0xC001_0007;

    // KVM paravirt MSRs (CPUID 0x40000001 advertises which are valid).
    // We service them so guests using kvmclock get a sane time source
    // and PV_EOI / async-pf reach a safe no-op fallback. Bit 0 of the
    // _NEW MSRs is the enable flag; the rest is a guest-physical addr.
    pub const KVM_WALL_CLOCK_NEW: u32    = 0x4B56_4D00;
    pub const KVM_SYSTEM_TIME_NEW: u32   = 0x4B56_4D01;
    pub const KVM_ASYNC_PF_EN: u32       = 0x4B56_4D02;
    pub const KVM_STEAL_TIME: u32        = 0x4B56_4D03;
    pub const KVM_PV_EOI_EN: u32         = 0x4B56_4D04;
    pub const KVM_POLL_CONTROL: u32      = 0x4B56_4D05;
    pub const KVM_ASYNC_PF_INT: u32      = 0x4B56_4D06;
    pub const KVM_ASYNC_PF_ACK: u32      = 0x4B56_4D07;
    pub const KVM_MIGRATION_CONTROL: u32 = 0x4B56_4D08;
}

/// Synthesised MTRR capabilities — VCNT=8 variable ranges, FIX support,
/// WC type, no SMRR/PRMRR. Stable across boots, matches typical
/// consumer AMD/Intel firmware.
const SYNTH_MTRRCAP: u64 = 0x0000_0000_0000_0508;
/// Default-type fallback when the guest hasn't written DEF_TYPE yet:
/// Write-Back (06) + overall MTRR enable (bit 11), but fixed-range enable
/// (bit 10, FE) CLEAR. Guest firmware (OVMF) reads this before it
/// configures MTRRs and asserts FE==0; once it WRMSRs DEF_TYPE the
/// shadowed value is returned instead.
const SYNTH_MTRR_DEF_TYPE: u64 = 0x0000_0000_0000_0806;
/// All fixed-range slots = WB (0x06 per 64K subrange). Eight subranges
/// per slot, packed into the 64-bit value as 8 bytes of 0x06.
const SYNTH_MTRR_FIX_WB: u64 = 0x0606_0606_0606_0606;

/// APIC base reset-ish default before the guest writes it: xAPIC global
/// enable (bit 11) + BSP (bit 8) + the architectural base 0xFEE00000.
/// x2APIC-enable (bit 10) is off until the guest sets it (shadowed).
const SYNTH_APIC_BASE: u64 = 0xFEE0_0900;
/// IA32_MISC_ENABLE default: fast-strings (bit 0) on, everything else off.
/// Notably limit-CPUID-maxval (bit 22) clear so the guest sees the full
/// leaf range, and XD-disable (bit 34) clear so NX stays available.
const SYNTH_MISC_ENABLE: u64 = 0x0000_0000_0000_0001;
/// IA32_MCG_CAP: 6 machine-check banks, no MCG_CTL (bit 8) / extended regs.
/// Consistent with CPUID leaf 1 MCE/MCA being advertised; banks 0..5 report
/// no error (MCi_STATUS = 0). A zero here while MCA=1 is an impossible state.
const SYNTH_MCG_CAP: u64 = 0x0000_0000_0000_0006;
/// AMD TSC ratio reset value = 1.0 in 8.32 fixed point. Returning the host's
/// real (non-1.0) nested ratio is a direct "running under SVM" tell.
const SYNTH_AMD_TSC_RATIO: u64 = 0x0000_0001_0000_0000;
/// AMD_HWCR (0xC0010015) Zen reset value. Per AMD PPR for Family 17h/19h
/// the reset state is NOT zero: bit 4 INVD_WBINVD = 1 (INVD treated as
/// WBINVD, the architectural default) and bit 18 McStatusWrEn = 0. A flat
/// 0 here is a tell (real Zen never reports HWCR.INVD_WBINVD clear at
/// reset). Other writable bits (TscFreqSel bit 24, SmmLock bit 0, …) stay
/// 0 — we don't model the features they gate.
const SYNTH_AMD_HWCR: u64 = 0x0000_0000_0000_0010;
/// IA32_RAPL_POWER_UNIT — power 2^-3 W, energy 2^-14 J, time 2^-10 s. Real
/// hardware never reports 0 here; a 0 unit register is a known VM tell.
const SYNTH_RAPL_POWER_UNIT: u64 = 0x0000_0000_000A_0E03;

#[inline]
fn split(v: u64) -> (u64, u64) {
    (v & 0xFFFF_FFFF, (v >> 32) & 0xFFFF_FFFF)
}

/// Inject a #GP(0) into the guest and resume WITHOUT advancing RIP, so the
/// faulting RDMSR/WRMSR is what the guest's #GP handler observes — exactly
/// what real silicon does on an unimplemented/illegal MSR access.
///
/// AMD APM Vol 2 §15.20 event_inj layout: vector (7:0) | type<<8
/// (3 = exception) | err-valid<<11 | valid<<31 | errcode<<32. #GP delivers
/// error code 0 for an MSR fault. We don't touch RIP; the staging guard in
/// inject::stage_pending sees the VALID bit and won't overwrite it.
#[inline]
unsafe fn inject_gp(vmcb: *mut Vmcb) -> Action {
    const GP_VECTOR: u64 = 13;
    const TYPE_EXCEPTION: u64 = 3 << 8;
    const ERR_VALID: u64 = 1 << 11;
    const VALID: u64 = 1 << 31;
    let c = unsafe { &mut (*vmcb).control };
    c.event_inj = GP_VECTOR | TYPE_EXCEPTION | ERR_VALID | VALID; // errcode 0 in 63:32
    Action::Resume
}

/// MSRs that are architecturally Intel-private. A CPU advertising
/// `AuthenticAMD` (CPUID leaf 0 vendor) #GPs on these — real AMD silicon
/// has no IA32_MISC_ENABLE, IA32_PLATFORM_ID, or the IA32 thermal block.
/// Answering them with a value while we advertise an AMD vendor string is a
/// direct vendor/MSR-consistency tell. When the active profile is AMD we
/// inject #GP; on an Intel profile these fall through to their normal
/// (synthesised / silenced) handling below.
///
/// NOTE: RAPL energy MSRs and the speculation-control block
/// (SPEC_CTRL/PRED_CMD/ARCH_CAPABILITIES/FLUSH_CMD) are NOT listed — those
/// are implemented on both vendors (AMD documents the RAPL energy counters
/// and the speculation MSRs), so gating them would itself be a tell.
fn is_intel_only_msr(msr: u32) -> bool {
    matches!(msr,
        idx::IA32_MISC_ENABLE
        | idx::IA32_PLATFORM_ID
        | idx::IA32_THERM_INTERRUPT
        | idx::IA32_THERM_STATUS
        | idx::IA32_PACKAGE_THERM_STATUS
        | idx::IA32_PACKAGE_THERM_INTERRUPT
        | idx::IA32_CLOCK_MODULATION)
    // NOTE: IA32_ENERGY_PERF_BIAS (0x1B0) is implemented on AMD Zen too, so it
    // stays out of this list and keeps its silenced-0 handling.
}

// ───── MTRR trace (CpuDxe MtrrLib convergence diagnosis) ─────────────
// OVMF CpuDxe loops re-reading the MTRRs while computing memory attributes
// for Windows boot. Log what it writes vs what we hand back so any divergence
// between the written value and the read-back is visible.
fn is_mtrr(msr: u32) -> bool {
    matches!(msr,
        idx::IA32_MTRRCAP | idx::IA32_MTRR_DEF_TYPE | idx::IA32_PAT
        | idx::IA32_MTRR_PHYSBASE0..=idx::IA32_MTRR_PHYSMASK_LAST
        | idx::IA32_MTRR_FIX64K_00000 | idx::IA32_MTRR_FIX16K_80000 | idx::IA32_MTRR_FIX16K_A0000
        | idx::IA32_MTRR_FIX4K_C0000..=idx::IA32_MTRR_FIX4K_F8000)
}
static MTRR_RD_N: AtomicU64 = AtomicU64::new(0);
static MTRR_WR_N: AtomicU64 = AtomicU64::new(0);
fn mtrr_trace_read(msr: u32, v: u64) {
    if MTRR_RD_N.fetch_add(1, Ordering::Relaxed) < 220 {
        crate::sprintln!("[mtrr] R 0x{:X} = 0x{:X}", msr, v);
    }
}
fn mtrr_trace_write(msr: u32, v: u64) {
    if MTRR_WR_N.fetch_add(1, Ordering::Relaxed) < 120 {
        crate::sprintln!("[mtrr] W 0x{:X} = 0x{:X} (readback 0x{:X})",
            msr, v, shadow_read(msr).unwrap_or(0xDEAD_DEAD));
    }
}

pub unsafe fn handle_rdmsr(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    let s = unsafe { &mut (*vmcb).state };
    let msr = gprs.rcx as u32;

    // Vendor consistency: an AMD-advertised CPU #GPs on Intel-private MSRs.
    // Checked before the shadow so a value stored under an Intel profile
    // can't leak back on an AMD profile (and so we don't skip RIP).
    if is_intel_only_msr(msr)
        && crate::vmexit::cpuid::profile_vendor() == crate::vmexit::cpuid::ProfileVendor::Amd
    {
        return unsafe { inject_gp(vmcb) };
    }

    // Shadow hit takes precedence — preserves WRMSR round-trip semantics.
    if let Some(v) = shadow_read(msr) {
        if is_mtrr(msr) { mtrr_trace_read(msr, v); }
        s.rax = v & 0xFFFF_FFFF;
        gprs.rdx = (v >> 32) & 0xFFFF_FFFF;
        s.rip = s.rip.wrapping_add(lengths::RDMSR);
        return Action::Resume;
    }

    let (lo, hi) = match msr {
        // ───── Anti-VMM ───────────────────────────────────────────────
        idx::VM_CR => split(1u64 << 4), // SVMDIS=1
        // EFER -- read from our VMCB shadow, mask out SVME so the guest
        // doesn't see we're in SVM-host context. This is the value the
        // guest just wrote via WRMSR (handle_wrmsr applies it to
        // vmcb.state.efer + force-sets SVME); reading back anything else
        // makes Linux think its EFER write was lost and re-attempt.
        idx::EFER => {
            let efer = unsafe { (*vmcb).state.efer };
            split(efer & !(1u64 << 12))
        }
        // FS/GS/KERNEL_GS base + SYSCALL MSRs likewise live in the
        // VMCB state-save area. host_rdmsr would return the firmware's
        // pre-VMRUN value (typically 0 for FS_BASE/GS_BASE), undoing
        // the kernel's per-cpu base setup -> PCP list head 0 -> NULL
        // deref in __list_del_entry_valid_or_report at mem_init.
        idx::FS_BASE        => split(unsafe { (*vmcb).state.fs.base }),
        idx::GS_BASE        => split(unsafe { (*vmcb).state.gs.base }),
        idx::KERNEL_GS_BASE => split(unsafe { (*vmcb).state.kernel_gs_base }),
        idx::STAR           => split(unsafe { (*vmcb).state.star }),
        idx::LSTAR          => split(unsafe { (*vmcb).state.lstar }),
        idx::CSTAR          => split(unsafe { (*vmcb).state.cstar }),
        idx::SFMASK         => split(unsafe { (*vmcb).state.sfmask }),
        idx::IA32_FEATURE_CONTROL => split(1u64),

        // ───── Profile-driven identity ────────────────────────────────
        idx::IA32_BIOS_SIGN_ID => split(
            active::PROFILE
                .get()
                .map(|p| unsafe {
                    core::ptr::addr_of!(p.hardware.cpu.microcode_signature).read_unaligned()
                })
                .unwrap_or(0x0800_0010_0000_0000),
        ),
        idx::IA32_PLATFORM_ID => split(
            active::PROFILE
                .get()
                .map(|p| unsafe {
                    core::ptr::addr_of!(p.hardware.cpu.platform_id).read_unaligned()
                })
                .unwrap_or(0),
        ),

        // ───── MTRR — synthesise consistent table ─────────────────────
        idx::IA32_MTRRCAP => split(SYNTH_MTRRCAP),
        idx::IA32_MTRR_DEF_TYPE => split(shadow_read(msr).unwrap_or(SYNTH_MTRR_DEF_TYPE)),
        // Variable MTRR PHYSBASEn / PHYSMASKn — return 0 (range invalid).
        idx::IA32_MTRR_PHYSBASE0..=idx::IA32_MTRR_PHYSMASK_LAST => split(0),
        // Fixed-range MTRRs — uniform Write-Back across all subranges.
        idx::IA32_MTRR_FIX64K_00000
        | idx::IA32_MTRR_FIX16K_80000
        | idx::IA32_MTRR_FIX16K_A0000 => split(SYNTH_MTRR_FIX_WB),
        idx::IA32_MTRR_FIX4K_C0000..=idx::IA32_MTRR_FIX4K_F8000 => split(SYNTH_MTRR_FIX_WB),

        // ───── PAT — host pass-through ────────────────────────────────
        idx::IA32_PAT => split(unsafe { host_rdmsr(msr) }),

        // ───── Performance counters — silenced ────────────────────────
        idx::IA32_PMC0..=idx::IA32_PMC_LAST => split(0),
        idx::IA32_PERFEVTSEL0..=idx::IA32_PERFEVTSEL_LAST => split(0),
        idx::IA32_FIXED_CTR0..=idx::IA32_FIXED_CTR2 => split(0),
        idx::IA32_PERF_CAPABILITIES
        | idx::IA32_FIXED_CTR_CTRL
        | idx::IA32_PERF_GLOBAL_STATUS
        | idx::IA32_PERF_GLOBAL_CTRL
        | idx::IA32_PERF_GLOBAL_OVF_CTRL
        | idx::IA32_PERF_CTL
        | idx::IA32_PERF_STATUS => split(0),

        // ───── Thermal / power — silenced ─────────────────────────────
        idx::IA32_THERM_INTERRUPT
        | idx::IA32_THERM_STATUS
        | idx::IA32_PACKAGE_THERM_STATUS
        | idx::IA32_PACKAGE_THERM_INTERRUPT
        | idx::IA32_CLOCK_MODULATION
        | idx::IA32_ENERGY_PERF_BIAS
        | idx::IA32_PKG_ENERGY_STATUS
        | idx::IA32_DRAM_ENERGY_STATUS
        | idx::IA32_DEBUGCTL => split(0),
        // Unit register must be non-zero on real silicon (a 0 divisor is a tell).
        idx::IA32_RAPL_POWER_UNIT => split(SYNTH_RAPL_POWER_UNIT),

        // ───── Machine-check — banks present, no errors logged ────────
        idx::IA32_MCG_CAP => split(SYNTH_MCG_CAP),
        idx::IA32_MCG_STATUS => split(0),
        idx::IA32_MCG_CTL => split(0),
        idx::IA32_MC0_CTL..=idx::IA32_MC31_MISC => split(0),

        // ───── Misc Intel speculation-control MSRs ────────────────────
        idx::IA32_ARCH_CAPABILITIES => split(0),
        idx::IA32_FLUSH_CMD => split(0),

        // ───── SYSENTER — host pass-through. (STAR/LSTAR/CSTAR/SFMASK/FS_BASE/
        // GS_BASE/KERNEL_GS_BASE are served from guest VMCB state by the arms
        // above; pass-through here would have leaked host values.) ──────────
        idx::IA32_SYSENTER_CS
        | idx::IA32_SYSENTER_ESP
        | idx::IA32_SYSENTER_EIP => split(unsafe { host_rdmsr(msr) }),

        // TSC_AUX — RDTSCP / RDPID return this as the "processor ID". Host
        // pass-through leaks the real host core index (the OS seeds it with
        // the physical APIC ID, e.g. 0/2/4/… on the Ryzen). Report the
        // guest's BSP index 0 instead, consistent with leaf 0x8000001E
        // extended APIC ID = 0 and the single-BSP MADT/leaf-0xB view.
        // A guest write is round-tripped via the shadow (below) so per-CPU
        // TSC_AUX programming on SMP guests reads back what it wrote.
        idx::TSC_AUX => split(shadow_read(msr).unwrap_or(0)),

        // ───── AMD package MSRs — synthesised, never host pass-through.
        //       Host values leak the real machine: TOP_MEM/TOP_MEM2 reveal
        //       host DRAM size, SYSCFG.SME (bit 23) would contradict the
        //       zeroed CPUID 0x8000001F, TSC_RATIO exposes nested scaling.
        idx::AMD_TOP_MEM => split(crate::boot::linux_loader::GUEST_RAM_BYTES),
        idx::AMD_TOP_MEM2 => split(0), // no RAM above 4 GiB in the guest map
        idx::AMD_SYSCFG => split(0),   // SME off, MTRR-DRAM features off (NPT governs memory type)
        idx::AMD_HWCR => split(shadow_read(msr).unwrap_or(SYNTH_AMD_HWCR)),
        idx::AMD_NB_CFG => split(0),
        idx::AMD_TSC_RATIO => split(SYNTH_AMD_TSC_RATIO),
        idx::AMD_PERF_CTL0..=idx::AMD_PERF_CTL3 => split(0),
        idx::AMD_PERF_CTR0..=idx::AMD_PERF_CTR3 => split(0),

        // ───── TSC — the filtered virtual clock, same as RDTSC ────────
        // RDMSR(0x10) must read back exactly what RDTSC returns. Both use
        // clock::now() (the step-filtered monotonic clock) so the guest TSC
        // can't leap on VMware's one-time nested-SVM host-TSC step.
        idx::IA32_TSC => split(crate::clock::now()),
        // ───── Synthesised, shadow-backed (defaults until first write) ─
        // Host pass-through here leaked host BSP/x2APIC state, host SpeedStep
        // / limit-CPUID bits, and a host TSC_ADJUST inconsistent with our
        // virtual TSC. A dropped guest write then read back the host value →
        // the guest concluded its write was lost and re-looped. Shadow hits
        // are served above; these are the pre-write defaults.
        idx::IA32_APIC_BASE => split(SYNTH_APIC_BASE),
        idx::IA32_MISC_ENABLE => split(SYNTH_MISC_ENABLE),
        idx::IA32_TSC_ADJUST => split(0),
        idx::IA32_SPEC_CTRL | idx::IA32_PRED_CMD => split(0),

        // ───── LAPIC TSC-deadline timer ───────────────────────────────
        idx::IA32_TSC_DEADLINE => split(crate::devices::irq::lapic::tsc_deadline_raw()),

        // ───── x2APIC MSR window (0x800..0x83F) ───────────────────────
        // In x2APIC mode the LAPIC is accessed through MSRs, not the
        // 0xFEE00000 MMIO page — so these route to the same register file
        // as intercept/lapic.rs. The x2APIC register at MSR 0x800+r maps
        // to MMIO offset r<<4. All regs are 32-bit (EDX=0) except ICR
        // (0x830) which is a single atomic 64-bit access.
        0x0000_0830 => {
            let lo = crate::devices::irq::lapic::read_register(0x300) as u64;
            let hi = crate::devices::irq::lapic::read_register(0x310) as u64;
            split((hi << 32) | lo)
        }
        0x0000_0800..=0x0000_083F => {
            let off = ((msr - 0x0000_0800) << 4) as u32;
            split(crate::devices::irq::lapic::read_register(off) as u64)
        }

        // Unknown MSR: zero. Safer than host #GP on an unmapped MSR.
        _ => split(0),
    };

    if is_mtrr(msr) { mtrr_trace_read(msr, (hi << 32) | lo); }
    s.rax = lo;
    gprs.rdx = hi;
    s.rip = s.rip.wrapping_add(lengths::RDMSR);
    Action::Resume
}

pub unsafe fn handle_wrmsr(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    // For MSRs that live in the VMCB state-save area the guest's write
    // MUST land there or the next VMRUN entry will load stale values
    // and the kernel runs with a broken view of its own MSRs. EFER in
    // particular: without NXE the guest's page table NX bits become
    // reserved-bit faults and the kernel spins on page-fault loops.
    // GS_BASE / FS_BASE / KERNEL_GS_BASE carry per-cpu pointers --
    // dropping the write turns every `mov rax, gs:[offset]` into a
    // null-deref.
    let s = unsafe { &mut (*vmcb).state };
    let msr = gprs.rcx as u32;
    let val = (s.rax & 0xFFFF_FFFF) | ((gprs.rdx & 0xFFFF_FFFF) << 32);

    // Vendor consistency: writing an Intel-private MSR on an AMD-advertised
    // CPU #GPs. Inject the fault and don't advance RIP (mirrors RDMSR side).
    if is_intel_only_msr(msr)
        && crate::vmexit::cpuid::profile_vendor() == crate::vmexit::cpuid::ProfileVendor::Amd
    {
        return unsafe { inject_gp(vmcb) };
    }

    match msr {
        idx::EFER => {
            // Keep SVME (bit 12) forced on -- it's how the host CPU
            // knows we're still in SVM-host context. The guest's read
            // is masked separately to hide it.
            s.efer = val | crate::arch::EFER_SVME;
        }
        idx::KVM_SYSTEM_TIME_NEW => {
            crate::devices::kvmclock::handle_wrmsr_system_time(val);
        }
        idx::KVM_WALL_CLOCK_NEW => {
            crate::devices::kvmclock::handle_wrmsr_wall_clock(val);
        }
        idx::STAR           => s.star = val,
        idx::LSTAR          => s.lstar = val,
        idx::CSTAR          => s.cstar = val,
        idx::SFMASK         => s.sfmask = val,
        idx::FS_BASE        => s.fs.base = val,
        idx::GS_BASE        => s.gs.base = val,
        idx::KERNEL_GS_BASE => s.kernel_gs_base = val,
        idx::IA32_TSC_DEADLINE => {
            // Arm the LAPIC TSC-deadline timer. The deadline is an absolute
            // guest-TSC value in the same domain RDTSC returns — now
            // clock::now() — so pass that as the current guest TSC.
            crate::devices::irq::lapic::set_tsc_deadline(val, crate::clock::now());
        }
        // ───── x2APIC MSR window (0x800..0x83F) ───────────────────────
        0x0000_0830 => {
            // ICR: atomic 64-bit. Destination (high 32) then command (low
            // 32) — writing the low word is what triggers IPI delivery.
            crate::devices::irq::lapic::write_register_width(0x310, (val >> 32) & 0xFFFF_FFFF, 4);
            crate::devices::irq::lapic::write_register_width(0x300, val & 0xFFFF_FFFF, 4);
        }
        0x0000_083F => {
            // SELF IPI (x2APIC-only): vector in bits 7:0.
            crate::devices::irq::lapic::self_ipi((val & 0xFF) as u8);
        }
        0x0000_0800..=0x0000_083F => {
            let off = ((msr - 0x0000_0800) << 4) as u32;
            crate::devices::irq::lapic::write_register_width(off, val & 0xFFFF_FFFF, 4);
        }
        _ => {
            if is_shadowed_msr(msr) {
                shadow_write(msr, val);
            }
            if is_mtrr(msr) { mtrr_trace_write(msr, val); }
            // Other MSRs: silently absorb (anti-detect; guest can't
            // poke real host hardware through us).
        }
    }
    s.rip = s.rip.wrapping_add(lengths::WRMSR);
    Action::Resume
}
