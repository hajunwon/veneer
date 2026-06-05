//! CPUID intercept handler — anti-hypervisor-detection edition.
//!
//! The guest just executed `cpuid` and trapped to us. We *forward* the call
//! to the host CPU (so the guest sees real CPU identity, feature flags,
//! topology, etc.), then patch over the specific bits a hypervisor needs
//! to hide:
//!
//!   1. CPUID leaf 1 ECX bit 31 — the "hypervisor present" hint. Cleared
//!      so the guest's OS / anti-cheat never thinks it's virtualised.
//!   2. CPUID leaves 0x4000_0000..0x4000_FFFF — the "hypervisor info"
//!      range that VMM vendors put their signature in. Zeroed entirely so
//!      no leaked vendor string (Microsoft, KVM, VMware, ...) reaches the
//!      guest.
//!
//! Per-leaf profile-driven overrides (synthetic brand string, fake
//! family/model, fake APIC ID, …) will hook in here once the std-side
//! profile schema is shared with the UEFI app.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::hardware::identity::active;
use crate::infra::arch;
use crate::hypervisor::svm::gprs::GuestGprs;
use crate::hypervisor::svm::vmcb::Vmcb;

use super::{lengths, Action};

const HV_PRESENT_BIT: u32 = 1 << 31; // CPUID 1.ECX bit 31

/// Intel/AMD reserve `0x4000_0000..=0x4FFF_FFFF` for hypervisor use.
/// VMware lives at 0x40000000, KVM at 0x40000000+0x40000100, Hyper-V at
/// 0x40000000..0x4000000A + 0x40000080..0x40000086, Xen at 0x40000000-5
/// (HVM stub at 0x40000100). Erasing the whole reserved range means no
/// vendor signature can leak — leaving the inner sub-ranges intact would
/// be an active tell.
const HV_LEAF_LOW: u32 = 0x4000_0000;
const HV_LEAF_HIGH: u32 = 0x4FFF_FFFF;

/// Advertise the KVM paravirt CPUID signature (0x40000000 = "KVMKVMKVM…"
/// + 0x40000010 = {tsc_khz, apic_khz}). Linux skips PIT-based TSC
/// calibration entirely when it sees this and just trusts the advertised
/// `tsc_khz`. Every standard hypervisor (KVM, Cloud Hypervisor,
/// Firecracker, Xen via a different signature) takes this shortcut.
///
/// Trade-off vs anti-detect: a guest that probes 0x40000000 can tell
/// it's virtualised when this is on. For Linux-boot verification we
/// turn it on; for Windows + anti-cheat runs we turn it off (and
/// shoulder the real PIT-emulation work). Override-flagged from the
/// active profile via `hide_hypervisor_leaf` — when that flag is
/// **false** we publish the signature; when **true** (anti-detect
/// default) the whole 0x40000000..0x4FFFFFFF range stays zeroed.
const KVM_SIGNATURE: &[u8; 12] = b"KVMKVMKVM\0\0\0";

/// KVM paravirt feature mask (0x40000001.EAX). We claim the minimum
/// subset that lets Linux's `kvm_init_platform` register kvmclock and
/// trust the TSC frequency we advertise via 0x40000010:
///   bit 3  KVM_FEATURE_CLOCKSOURCE2       (newer paravirt clock — uses
///                                          MSR_KVM_WALL_CLOCK_NEW
///                                          0x4B564D00 and
///                                          MSR_KVM_SYSTEM_TIME_NEW
///                                          0x4B564D01, which we
///                                          implement in
///                                          intercept/kvmclock.rs)
///   bit 24 KVM_FEATURE_CLOCKSOURCE_STABLE (tsc stable — TSC frequency
///                                          stays constant across the
///                                          guest's lifetime, no live
///                                          migration)
/// The legacy `KVM_FEATURE_CLOCKSOURCE` (bit 0) uses the deprecated
/// 0x11 / 0x12 MSRs and is not handled here; advertising it would have
/// Linux probe MSRs we don't service.
const KVM_FEATURE_FLAGS: u32 =
    (1 << 3) | (1 << 24);

/// Live vCPU count, set by main.rs after MP Services probe. Used by leaf
/// 0x80000008 to advertise `cores-1` consistent with what the guest sees
/// via UEFI MP services / ACPI MADT. Defaults to 1 if main forgets to
/// set it (would not boot to that point though).
pub static N_VCPUS: AtomicUsize = AtomicUsize::new(1);

/// Runtime override: publish the KVM paravirt CPUID signature even when
/// the profile asks for `hide_hypervisor_leaf = true`. Set by
/// `enter_linux_guest` so Linux can skip PIT-based TSC calibration; left
/// `false` on chain-load and Windows paths where anti-detect matters
/// more than calibration speed.
pub static PARAVIRT_KVM_OVERRIDE: AtomicBool = AtomicBool::new(false);

/// Fallback brand used when the active profile hasn't been initialized
/// yet (very-early boot edge case). Real boots populate the slot
/// before any guest VMRUN.
const FALLBACK_BRAND: &[u8; 48] = b"veneer virtual cpu 0.7 / amd64                 \0";

/// Materialise the active profile's brand string into a 48-byte buffer
/// (space-padded), then pull a little-endian 32-bit slice at `byte_offset`.
fn brand_chunk(byte_offset: usize) -> u32 {
    let mut padded = [b' '; 48];
    let src: &[u8] = match active::PROFILE.get() {
        Some(p) => {
            let b = p.hardware.cpu.spec.brand.as_bytes();
            if b.is_empty() { FALLBACK_BRAND.as_slice() } else { b }
        }
        None => FALLBACK_BRAND.as_slice(),
    };
    let n = src.len().min(48);
    padded[..n].copy_from_slice(&src[..n]);
    let mut b = [0u8; 4];
    b.copy_from_slice(&padded[byte_offset..byte_offset + 4]);
    u32::from_le_bytes(b)
}

/// Single source of truth for the guest's logical-processor count.
///
/// Every topology consumer derives from this: leaf 1 EBX[23:16],
/// leaf 0xB (extended topology), leaf 0x80000008.ECX, the MADT LAPIC
/// count, and SMBIOS Type 4 core/thread counts. Profile
/// `cpuid_cores_override` (interpreted as cores-1, matching the
/// 0x80000008.ECX encoding) wins; otherwise we use the live MP-Services
/// vCPU count. Clamped to [1, 255].
///
/// veneer presents one logical processor per core (no SMT) — the guest
/// runs one thread per vCPU — so logical == core == thread count here.
pub fn effective_core_count() -> u32 {
    let override_cores_minus_1: u8 = active::PROFILE
        .get()
        .map(|p| unsafe {
            core::ptr::addr_of!(p.hardware.cpu.spec.cpuid_cores_override).read_unaligned()
        })
        .unwrap_or(0);
    if override_cores_minus_1 != 0 {
        // Stored as cores-1 (same encoding as 0x80000008.ECX[7:0]).
        return (override_cores_minus_1 as u32 + 1).min(255);
    }
    (N_VCPUS.load(Ordering::Relaxed).max(1).min(255)) as u32
}

/// Vendor the active profile advertises, for cross-checks that must agree
/// with the CPUID leaf-0 vendor string (Intel-only MSR gating, SMBIOS
/// Type 4 family). `Unknown` when no profile is set yet — callers treat
/// that conservatively (no Intel-only #GP injection during the very-early
/// pre-profile window, matching the synth fallbacks elsewhere).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProfileVendor { Intel, Amd, Unknown }

pub fn profile_vendor() -> ProfileVendor {
    match active::PROFILE.get() {
        Some(p) => {
            let v = unsafe { core::ptr::addr_of!(p.hardware.cpu.spec.vendor).read_unaligned() };
            match v.as_bytes() {
                b"GenuineIntel" => ProfileVendor::Intel,
                b"AuthenticAMD" => ProfileVendor::Amd,
                _ => ProfileVendor::Unknown,
            }
        }
        None => ProfileVendor::Unknown,
    }
}

/// True when the active profile advertises an Intel vendor string. Used by
/// SMBIOS Type 4 (Intel vs AMD processor family) and leaf 4 cache handling.
/// `Unknown`/unset is treated as non-Intel (defaults to the AMD path, which
/// matches the AuthenticAMD vendor fallback in `vendor_buffer`).
pub fn profile_is_intel() -> bool {
    profile_vendor() == ProfileVendor::Intel
}

/// Pull (hide_hypervisor_bit, hide_hypervisor_leaf) from the active
/// profile, defaulting to (true, true) when no profile is set.
fn hide_flags() -> (bool, bool) {
    active::PROFILE
        .get()
        .map(|p| (p.hardware.cpu.spec.hide_hypervisor_bit, p.hardware.cpu.spec.hide_hypervisor_leaf))
        .unwrap_or((true, true))
}

/// 12-byte vendor buffer (space-padded). Used by CPUID leaf 0 /
/// 0x80000000 — both return the same string split into EBX/EDX/ECX.
fn vendor_buffer() -> [u8; 12] {
    let mut padded = [b' '; 12];
    let src: &[u8] = match active::PROFILE.get() {
        Some(p) => {
            let b = p.hardware.cpu.spec.vendor.as_bytes();
            if b.is_empty() { b"AuthenticAMD".as_slice() } else { b }
        }
        None => b"AuthenticAMD".as_slice(),
    };
    let n = src.len().min(12);
    padded[..n].copy_from_slice(&src[..n]);
    padded
}

pub unsafe fn handle(vmcb: *mut Vmcb, gprs: &mut GuestGprs) -> Action {
    let s = unsafe { &mut (*vmcb).state };
    let leaf = s.rax as u32;
    let subleaf = gprs.rcx as u32;

    // Forward to the host CPU.
    let regs = arch::cpuid_count(leaf, subleaf);
    let mut eax = regs.eax;
    let mut ebx = regs.ebx;
    let mut ecx = regs.ecx;
    let mut edx = regs.edx;

    let (hide_bit, hide_leaf_profile) = hide_flags();
    // Runtime override wins over profile setting (Linux-boot verification).
    let hide_leaf = hide_leaf_profile && !PARAVIRT_KVM_OVERRIDE.load(Ordering::Relaxed);
    // Anti-detect: erase hypervisor leaves (profile.cpu.hide_hypervisor_leaf).
    if hide_leaf && (HV_LEAF_LOW..=HV_LEAF_HIGH).contains(&leaf) {
        eax = 0;
        ebx = 0;
        ecx = 0;
        edx = 0;
    }
    // KVM paravirt signature path — published only when the profile
    // explicitly allows it (anti-detect off) or the runtime override is
    // active. Linux uses these to skip PIT-based TSC calibration entirely.
    if !hide_leaf && (HV_LEAF_LOW..=HV_LEAF_HIGH).contains(&leaf) {
        // Default to zero for any unhandled paravirt leaf so we don't
        // leak host garbage in this range.
        eax = 0;
        ebx = 0;
        ecx = 0;
        edx = 0;
        match leaf {
            0x4000_0000 => {
                // EAX = max KVM leaf (we only implement up to 0x40000010)
                // EBX/ECX/EDX = signature in that order
                eax = 0x4000_0010;
                let sig = KVM_SIGNATURE;
                ebx = u32::from_le_bytes([sig[0], sig[1], sig[2], sig[3]]);
                ecx = u32::from_le_bytes([sig[4], sig[5], sig[6], sig[7]]);
                edx = u32::from_le_bytes([sig[8], sig[9], sig[10], sig[11]]);
            }
            0x4000_0001 => {
                // EAX = feature flags. EBX/ECX/EDX reserved by KVM ABI.
                eax = KVM_FEATURE_FLAGS;
            }
            0x4000_0010 => {
                // EAX = guest TSC frequency in KHz. We anchor to the
                // measured host TSC frequency — Linux reads this with
                // `kvm_get_tsc_khz` and stores it as `tsc_khz` /
                // `cpu_khz` directly, skipping the PIT loop.
                let host_hz = crate::infra::clock::tsc_freq::host_tsc_freq();
                eax = (host_hz / 1000).min(u32::MAX as u64) as u32;
                // EBX = local APIC frequency in KHz. Standard PC LAPIC
                // ticks at the FSB / 16 ≈ 100 MHz on modern boards. Use
                // a stable round number — Linux only uses this to seed
                // the LAPIC timer calibration when paravirt clock is on.
                ebx = 100_000;
            }
            _ => {}
        }
    }
    // Anti-detect: clear the "hypervisor present" hint on leaf 1
    // (profile.cpu.hide_hypervisor_bit) and overlay family/model/stepping
    // from the active profile so the brand string ("Ryzen 9 7900X" /
    // "Core i7-12700H" / …) agrees with leaf 1 EAX. Without this, brand
    // says Zen 4 while EAX reports the host's Zen 2 / Coffee Lake / …
    // EBX layout: bits 31:24 = APIC ID, bits 23:16 = max logical CPUs,
    // bits 15:8 = CLFLUSH line size, bits 7:0 = brand index.
    if leaf == 1 {
        // PDCM (Perfmon/Debug Capability, ECX bit 15) gates IA32_PERF_CAPABILITIES,
        // which the MSR handler returns as 0. Clear it so the guest doesn't probe
        // a capability register we don't back — consistent with leaf 0xA = 0.
        ecx &= !(1u32 << 15);
        // Feature bits whose backing MSRs the MSR handler returns as 0 (or
        // #GP for the Intel-only thermal block). Advertising the feature
        // while its register reads 0 / faults is a hypervisor tell, so clear
        // them — same principle already applied to PDCM/CET/ARCH_CAP and to
        // leaf 6 above.
        //   EDX bit 21 = DS   (Debug Store / BTS — IA32_DS_AREA unbacked)
        //   EDX bit 22 = ACPI (thermal monitor + SW clock control via
        //                      IA32_THERM_CONTROL / CLOCK_MODULATION = 0)
        //   EDX bit 29 = TM   (Thermal Monitor 1 — IA32_THERM_* = 0)
        edx &= !(1u32 << 21);
        edx &= !(1u32 << 22);
        edx &= !(1u32 << 29);
        //   ECX bit  3 = MONITOR (MONITOR/MWAIT — intercepted as no-ops in
        //                stealth.rs; advertising lets the guest MWAIT-idle
        //                against a monitor we never trigger)
        //   ECX bit  8 = TM2  (Thermal Monitor 2 — MSR_THERM2_CTL unbacked)
        ecx &= !(1u32 << 3);
        ecx &= !(1u32 << 8);
        // ECX bit 24 = TSC-Deadline LAPIC timer. Force it on: VMware's nested
        // CPUID may clear it, leaving Windows' HAL no per-CPU clock timer but
        // the HPET comparator — whose servicing reads the HPET counter every
        // tick (the dominant boot NPF storm). veneer emulates the deadline
        // timer (lapic::set_tsc_deadline + the inject deadline check), so
        // advertising it lets Windows arm the clock via MSR 0x6E0 (a cheap
        // WRMSR) and check it via native RDTSC — no HPET MMIO.
        ecx |= 1u32 << 24;
        // ECX bit 21 = x2APIC. Force it on so Windows (seeing the type-9 x2APIC
        // MADT entries) enables x2APIC mode and drives the LAPIC via MSRs
        // (handled in msr.rs) instead of trapped MMIO — each xAPIC MMIO access
        // is an NPF #VMEXIT (~155 µs nested), and the per-tick EOI/IPI traffic
        // dominates the awake boot time.
        ecx |= 1u32 << 21;
        // Paravirt override flips both flags atomically — Linux only
        // probes 0x40000000+ when the hypervisor-present bit is set
        // on leaf 1, so hiding the bit while publishing the signature
        // would be wasted effort.
        let hide_bit_effective = hide_bit && !PARAVIRT_KVM_OVERRIDE.load(Ordering::Relaxed);
        if hide_bit_effective {
            ecx &= !HV_PRESENT_BIT;
        } else {
            ecx |= HV_PRESENT_BIT;
        }
        if let Some(p) = active::PROFILE.get() {
            let cpu = &p.hardware.cpu;
            let eax_override = unsafe { core::ptr::addr_of!(cpu.spec.cpuid_eax_v1).read_unaligned() };
            if eax_override != 0 {
                eax = eax_override;
            }
            let brand_idx = unsafe { core::ptr::addr_of!(cpu.spec.cpuid_brand_idx).read_unaligned() };
            if brand_idx != 0 {
                ebx = (ebx & !0xFFu32) | brand_idx as u32;
            }
            // Bits 23:16 = max logical CPU count in the package. Single
            // source: effective_core_count() — same value drives leaf
            // 0x80000008.ECX (as n-1), leaf 0xB, ACPI MADT, and SMBIOS
            // Type 4.
            let n = effective_core_count();
            ebx = (ebx & !0x00FF_0000) | (n << 16);
        }
    }
    // CPUID leaf 0x80000007 EDX bit 8 = Invariant TSC. Required for the guest
    // to use RDTSC as its clocksource (QPC) instead of polling the HPET MMIO
    // counter — which under VMware nested SVM is an NPF #VMEXIT per read and the
    // dominant boot-time cost. veneer's clock::now() is slewed to a smooth
    // constant rate (see infra/clock), so the TSC behaves like a real invariant
    // TSC. Bits other than 8 are power-management capabilities backed by MSRs we
    // don't model — clear them so we advertise only what we honor.
    if leaf == 0x8000_0007 {
        eax = 0;
        ebx = 0;
        ecx = 0;
        edx = 1 << 8;
    }
    // CPUID leaf 0xD — Processor Extended State Enumeration. Linux reads
    // sub-leaf 0 (EAX:EDX = supported user XCR0 bits, EBX = current
    // XSAVE area size, ECX = max XSAVE area size), then walks one sub-
    // leaf per set EAX/EDX bit to learn each component's size/offset,
    // and sums them. If our EAX/EDX advertise a bit (CET, AMX, …)
    // that our actual XCR0 pre-arm doesn't include, Linux's sum
    // disagrees with EBX and `fpu__init_system_xstate` panics.
    //
    // Allowed mask: x87 (0x1) | SSE (0x2) | AVX (0x4) | PKRU (0x200).
    // PKRU is standard on Intel/AMD CPUs since Skylake / Zen 3; Linux
    // signal-handling (copy_fpstate_to_sigframe) WARNs without it.
    const XSAVE_ALLOWED_LO: u32 = 0x207;
    const XSAVE_ALLOWED_HI: u32 = 0;
    if leaf == 0x0000_000D {
        match subleaf {
            0 => {
                eax &= XSAVE_ALLOWED_LO;
                edx &= XSAVE_ALLOWED_HI;
                // EBX is current-XCR0 size; host's XSETBV pre-arm puts
                // XCR0 = 0x207 so the host's own EBX already reflects
                // that. Leave it as host pass-through.
            }
            1 => {
                // EAX low bits = XSAVE feature flags (xsaveopt, etc.).
                // Pass through — these aren't gated on XCR0 contents.
                // ECX:EDX = supervisor state mask (CET_SUPERVISOR etc.).
                // Clamp to 0 so Linux doesn't try to read sub-leaves
                // for those components.
                ecx = 0;
                edx = 0;
            }
            2 => {
                // AVX (YMM upper) component info. Keep host values.
            }
            9 => {
                // PKRU component info. Keep host values so the offset
                // and size agree with the bit we set in sub-leaf 0.
            }
            _ => {
                // Every other sub-leaf describes a component we've
                // hidden. Zero so Linux doesn't include them in its
                // size sum.
                eax = 0; ebx = 0; ecx = 0; edx = 0;
            }
        }
    }
    // CPUID leaf 0xB — Extended Topology Enumeration. Host pass-through
    // would advertise the host's full topology (12 cores / 24 threads on
    // Ryzen 7900X). Override to a topology derived from the single source
    // `effective_core_count()` so every other source (leaf 1 EBX[23:16],
    // leaf 0x80000008.ECX = n-1, MADT LAPIC count, SMBIOS Type 4) agrees.
    //
    // veneer presents 1 thread per core (no SMT), N cores in the package:
    //   sub-leaf 0 (SMT level):  EBX = 1 logical proc, EAX shift = 0
    //                            (one thread per core → no bits to shift).
    //   sub-leaf 1 (Core level): EBX = N logical procs in package,
    //                            EAX shift = ceil(log2(N)) (bits to the
    //                            right of the core ID), level type Core.
    // EDX carries the current logical processor's x2APIC ID; we report 0
    // to match leaf 0x8000001E (extended APIC ID = 0) and the BSP view.
    if leaf == 0x0000_000B {
        let n = effective_core_count();
        // Bits needed to enumerate N cores at the core level. ceil(log2(N)).
        let core_shift: u32 = if n <= 1 { 0 } else { 32 - (n - 1).leading_zeros() };
        match subleaf {
            0 => {
                // Level 0 — SMT. 1 thread per core → shift 0, 1 proc.
                eax = 0;
                ebx = 1;
                ecx = (subleaf & 0xFF) | (1u32 << 8); // level type 1 = SMT
                edx = 0;
            }
            1 => {
                // Level 1 — Core. Shift covers all N cores; EBX = total
                // logical procs visible from the package level.
                eax = core_shift;
                ebx = n;
                ecx = (subleaf & 0xFF) | (2u32 << 8); // level type 2 = Core
                edx = 0;
            }
            _ => {
                // Invalid sub-leaf — level type 0 terminates enumeration.
                eax = 0;
                ebx = 0;
                ecx = subleaf & 0xFF;
                edx = 0;
            }
        }
    }
    // CPUID leaf 7 (structured extended features) — clear bits that
    // commonly differ between hypervisor and bare-metal:
    //   sub-leaf 0:
    //     EBX bit 11 = RTM   (Restricted Transactional Memory) — often disabled in HV
    //     EBX bit 16 = AVX512F                                  — often disabled in HV
    //     EBX bit  4 = HLE   (Hardware Lock Elision)            — often disabled in HV
    //     ECX bit  2 = UMIP  (User-Mode Instruction Prevention) — hides SGDT/SIDT from user mode
    //                  ↑ we WANT this set for stealth so user-mode SGDT/SIDT #GP rather than leak
    if leaf == 7 && subleaf == 0 {
        ebx &= !(1u32 << 4);   // HLE  off
        ebx &= !(1u32 << 11);  // RTM  off
        ecx |= 1u32 << 2;      // UMIP on  (force user-mode SGDT/SIDT/SLDT/STR/SMSW to #GP)
        // Control-flow Enforcement (shadow stacks / IBT): veneer models no
        // CET state in XCR0/XSS, so a guest that enables it (Win11 writes the
        // CET MSRs and shadow-stack page tables) would diverge. Report absent.
        ecx &= !(1u32 << 7);   // CET_SS  off
        edx &= !(1u32 << 20);  // CET_IBT off
        // ARCH_CAPABILITIES MSR (0x10A) is returned as 0 by the MSR handler;
        // clear the leaf-7 present bit so the guest doesn't read 0 against an
        // advertised-present register (a "vulnerable to everything" tell).
        edx &= !(1u32 << 29);  // ARCH_CAPABILITIES absent
    }
    // CPUID leaf 4 — Deterministic Cache Parameters (Intel-defined). AMD
    // CPUs return 0 here and publish cache topology via 0x8000001D instead,
    // so an AuthenticAMD profile must NOT leak the host's leaf-4 cache
    // descriptors (a vendor/topology tell). On an Intel profile we keep the
    // host's cache geometry but rewrite the package/sharing core counts in
    // EAX so they agree with effective_core_count() (and thus SMBIOS Type
    // 7 / leaf 0xB), rather than advertising the host's 12-core sharing.
    //   EAX[25:14] = max threads sharing this cache level − 1
    //   EAX[31:26] = max cores in the package − 1
    if leaf == 0x0000_0004 {
        if profile_is_intel() {
            let n = effective_core_count();
            let cores_minus_1 = n - 1;
            // L1/L2 are per-core (sharing = 1 thread); L3 (cache level in
            // EAX[7:5] == 3) is shared across the whole package.
            let cache_level = (eax >> 5) & 0x7;
            let cache_type = eax & 0x1F; // 0 = null (end of valid subleaves)
            if cache_type != 0 {
                let threads_sharing_minus_1: u32 = if cache_level >= 3 { cores_minus_1 } else { 0 };
                eax = (eax & !0xFFFF_C000)
                    | ((threads_sharing_minus_1 & 0xFFF) << 14)
                    | ((cores_minus_1 & 0x3F) << 26);
            }
        } else {
            // AMD (and unknown) profiles: leaf 4 is not implemented.
            eax = 0; ebx = 0; ecx = 0; edx = 0;
        }
    }
    // CPUID leaf 6 — Thermal and Power Management. Host pass-through
    // advertises DTS / turbo / HWP and the digital thermal sensor, but the
    // backing MSRs (IA32_THERM_STATUS, IA32_THERM_INTERRUPT, HWP MSRs) all
    // read 0 in the MSR handler. Advertising the sensor while its status
    // register reads 0 is an "impossible idle" tell, so report no thermal/
    // power capabilities (EAX/ECX feature bits cleared). This is consistent
    // with the THERM_* MSRs being silenced and with leaf 1 EDX.TM/ACPI being
    // cleared below for the same backing MSRs.
    if leaf == 0x0000_0006 {
        eax = 0; ebx = 0; ecx = 0; edx = 0;
    }
    // CPUID leaf 0xA — Intel architectural performance monitoring. veneer
    // virtualises no PMU (all PMC / PERFEVTSEL / PERF_GLOBAL MSRs read 0), so
    // advertising counters here would let a guest program a PMU that never
    // counts. Report no PMU, consistent with the MSR side and leaf 1 PDCM.
    if leaf == 0x0000_000A {
        eax = 0; ebx = 0; ecx = 0; edx = 0;
    }
    // Clamp the leaf space to what veneer actually models. A guest walking
    // up to the advertised max stops early, AND a guest that probes a high
    // leaf directly (Windows reads 0x8000001F regardless of the advertised
    // max) gets zero instead of leaked host capability: SME/SEV (0x8000001F),
    // cache topology (0x8000001D), PQOS (0x80000020), Intel PT (0x14), etc.
    // The hypervisor range (0x40000000..) and vendor/brand/handled leaves sit
    // outside this window and are dealt with separately.
    const STD_MAX: u32 = 0x0000_000D;
    const EXT_MAX: u32 = 0x8000_0008;
    let out_of_range = (leaf <= 0x3FFF_FFFF && leaf > STD_MAX)
        || ((0x8000_0000..=0x8000_FFFF).contains(&leaf) && leaf > EXT_MAX);
    if out_of_range {
        eax = 0; ebx = 0; ecx = 0; edx = 0;
    }
    // Vendor string spoof + honest ceiling. Leaf 0 and 0x80000000 return the
    // 12-byte vendor in EBX:EDX:ECX (EDX before ECX); clamp EAX to the modeled
    // max so the advertised ceiling matches the zeroing above.
    match leaf {
        0x0000_0000 => {
            let v = vendor_buffer();
            ebx = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
            edx = u32::from_le_bytes([v[4], v[5], v[6], v[7]]);
            ecx = u32::from_le_bytes([v[8], v[9], v[10], v[11]]);
            eax = eax.min(STD_MAX);
        }
        0x8000_0000 => {
            let v = vendor_buffer();
            ebx = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
            edx = u32::from_le_bytes([v[4], v[5], v[6], v[7]]);
            ecx = u32::from_le_bytes([v[8], v[9], v[10], v[11]]);
            eax = eax.min(EXT_MAX);
        }
        _ => {}
    }

    // Brand string spoof. AMD splits across 0x80000002..=0x80000004,
    // 16 bytes per leaf returned via {EAX, EBX, ECX, EDX} in that order.
    match leaf {
        0x8000_0002 => {
            eax = brand_chunk(0);
            ebx = brand_chunk(4);
            ecx = brand_chunk(8);
            edx = brand_chunk(12);
        }
        0x8000_0003 => {
            eax = brand_chunk(16);
            ebx = brand_chunk(20);
            ecx = brand_chunk(24);
            edx = brand_chunk(28);
        }
        0x8000_0004 => {
            eax = brand_chunk(32);
            ebx = brand_chunk(36);
            ecx = brand_chunk(40);
            edx = brand_chunk(44);
        }
        // 0x80000008.ECX[7:0] = (logical-processor count) - 1. Profile
        // override wins, else fall back to N_VCPUS from MP Services.
        // Clamped to 8 bits — anything above 256 logical CPUs is rare
        // enough we'd want to revisit leaf 0xB / 0x8000001E first.
        0x8000_0008 => {
            // ECX[7:0] = (logical-processor count) - 1, from the single
            // topology source. ECX[15:12] = ApicIdCoreIdSize (bits needed
            // to represent core IDs); set it consistent with the count so
            // a guest decoding the field doesn't see "0 size but N cores".
            let n = effective_core_count();
            let cores_minus_1 = n - 1;
            let apic_id_size: u32 = if n <= 1 { 0 } else { 32 - (n - 1).leading_zeros() };
            ecx = (ecx & !0x0000_F0FFu32)
                | (cores_minus_1 & 0xFF)
                | ((apic_id_size & 0xF) << 12);
        }
        // 0x80000001 — extended feature flags. ECX bit 2 = SVM available.
        // Clear it to stay consistent with EFER.SVME being hidden in the
        // MSR handler — a guest that reads SVM=1 here but EFER.SVME=0
        // when probing would see an inconsistency.
        0x8000_0001 => {
            ecx &= !(1u32 << 2);
        }
        // 0x8000001E — AMD Extended APIC ID / Topology. Host pass-
        // through leaks the real APIC ID (Ryzen 7900X uses 0/2/4/.../22
        // for cores); we want the guest to see APIC ID = 0 to match its
        // single-vCPU view from leaf 0xB and MADT.
        0x8000_001E => {
            eax = 0; // Extended APIC ID
            ebx = 0; // bits 7:0 = compute unit ID (=0); bits 15:8 = threads/unit (1−1=0)
            ecx = 0; // bits 7:0 = node ID; bits 10:8 = nodes/package (1−1=0)
            edx = 0; // reserved
        }
        // 0x8000001F — AMD Secure Memory Encryption / SEV / SNP. Host
        // pass-through advertises the Ryzen's SME C-bit and encrypted-guest
        // counts. veneer maps no encryption bit in NPT, so a guest that acts
        // on it (Windows boot reprograms MTRRs + page tables for the C-bit,
        // then loops re-reading 0x8000001F / MTRRs / EFER waiting for state
        // that never settles) wedges. Report no memory-encryption support.
        0x8000_001F => {
            eax = 0; ebx = 0; ecx = 0; edx = 0;
        }
        _ => {}
    }

    // Write back. EAX via VMCB (hardware reloads it on VMRUN); EBX/ECX/EDX
    // via GuestGprs (our asm stub reloads them on VMRUN).
    s.rax = eax as u64;
    gprs.rbx = ebx as u64;
    gprs.rcx = ecx as u64;
    gprs.rdx = edx as u64;

    s.rip = s.rip.wrapping_add(lengths::CPUID);
    Action::Resume
}
