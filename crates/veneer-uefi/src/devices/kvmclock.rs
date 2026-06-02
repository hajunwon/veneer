//! KVM paravirt clock (`kvmclock`) emulator.
//!
//! Linux activates this when it sees the KVM CPUID signature
//! (0x40000000 / 0x40000001) — `kvmclock_init` writes the guest-
//! physical address of a per-vCPU `pvclock_vcpu_time_info` struct to
//! `MSR_KVM_SYSTEM_TIME_NEW` (0x4B564D01), with bit 0 = enable.
//! Hypervisor is then responsible for keeping the struct populated so
//! the guest can read time via:
//!
//!   ns = system_time + ((rdtsc() - tsc_timestamp) * tsc_to_system_mul) >> tsc_shift
//!
//! Once paravirt clock is live, Linux skips PIT-based TSC calibration
//! entirely and uses kvmclock as its `clocksource`.
//!
//! Why this is the right shape for veneer:
//!   - Real hypervisors (KVM, Cloud HV, Firecracker) all implement
//!     this path; it's how Linux *expects* a virtualised PC to deliver
//!     time. Matching the standard pattern is the cleanest way out of
//!     the PIT-calibration corner.
//!   - We already publish the KVM signature in cpuid.rs and advertise
//!     KVM_FEATURE_CLOCKSOURCE2 (bit 3). Linux therefore probes this
//!     MSR; without a handler the guest sees zero, errors out, and
//!     leaves `cpu_khz` unset.

use core::sync::atomic::{AtomicU64, Ordering};

/// Guest-physical base of the pvclock area, latched from the most
/// recent `MSR_KVM_SYSTEM_TIME_NEW` write. Bit 0 of the MSR value is
/// the enable flag; the rest is the GPA aligned to 4 bytes.
static PVCLOCK_GPA: AtomicU64 = AtomicU64::new(0);

/// Host-physical base of the 1 GiB guest RAM block, set by
/// `linux_loader::set_host_ram_base()` after NPT setup. Without this
/// we can't translate `PVCLOCK_GPA` to a writable host pointer.
static HOST_RAM_BASE: AtomicU64 = AtomicU64::new(0);

/// VMCB.tsc_offset — added by hardware to the host TSC before the
/// guest sees RDTSC. Without mirroring this here the pvclock struct's
/// `tsc_timestamp` (real host TSC) and the guest's perceived TSC
/// (host TSC + offset, anchored at 0) belong to different timelines
/// and the guest's `(current_tsc - tsc_timestamp)` underflows by
/// billions of cycles. Stashed at guest-entry time so the same offset
/// the VMCB uses is the one we apply.
static GUEST_TSC_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Set the host-physical base of guest RAM. Called once from
/// `enter_linux_guest` after `host_ram_base` is allocated.
pub fn set_host_ram_base(host_ram_base: u64) {
    HOST_RAM_BASE.store(host_ram_base, Ordering::Release);
}

/// Set the VMCB TSC offset so subsequent pvclock writes anchor on the
/// guest-visible TSC value, not the raw host TSC.
pub fn set_tsc_offset(tsc_offset: u64) {
    GUEST_TSC_OFFSET.store(tsc_offset, Ordering::Release);
}

/// pvclock format per `arch/x86/include/asm/pvclock-abi.h`.
#[repr(C, packed)]
struct PvclockVcpuTimeInfo {
    version: u32,
    pad: u32,
    tsc_timestamp: u64,
    system_time: u64,
    tsc_to_system_mul: u32,
    tsc_shift: i8,
    flags: u8,
    pad2: [u8; 2],
}

/// `pvclock_vcpu_time_info.flags` bit 0 — TSC is stable across
/// (potentially live-migrated) hosts. We always claim stable.
const PVCLOCK_TSC_STABLE_BIT: u8 = 1;

/// Compute the (mul, shift) pair the guest uses to convert a TSC cycle
/// delta to nanoseconds. Linux's `pvclock_clocksource_read` formula:
///
///   ns = ((delta_cycles << tsc_shift) * mul) >> 32          if shift ≥ 0
///   ns = ((delta_cycles >> -tsc_shift) * mul) >> 32         if shift < 0
///
/// For `shift = 0` this simplifies to `ns = (delta * mul) >> 32`. Solving
/// for `mul` so that `ns/cycle = 1e9 / freq_hz`:
///
///   mul = (2^32 * 1e9) / freq_hz
///
/// At 3 GHz this yields ~1.43e9, well inside the u32 budget. We stay at
/// `shift = 0` for any freq in the megahertz–tens-of-gigahertz range
/// veneer cares about; the negative-shift branch isn't needed.
///
/// An earlier revision returned `shift = 32` with the same `mul` value,
/// which the guest evaluated as `delta * mul` rather than `delta * mul
/// >> 32` — every timestamp was inflated by a factor of 2^32 (~4.3 ×
/// 10^9) and Linux's first kvm-clock read landed billions of seconds in
/// the future.
fn compute_mul_shift(tsc_freq_hz: u64) -> (u32, i8) {
    if tsc_freq_hz == 0 {
        return (0, 0);
    }
    let mul_128: u128 = ((1u128 << 32) * 1_000_000_000u128) / (tsc_freq_hz as u128);
    let mul = if mul_128 > u32::MAX as u128 {
        u32::MAX
    } else {
        mul_128 as u32
    };
    (mul, 0)
}

/// Write a fresh pvclock struct into the guest's per-vCPU page.
/// Performed on every wrmsr that enables / re-enables the area, and
/// also lazily from the boot loop so older snapshots don't go stale.
pub fn refresh() {
    let base = PVCLOCK_GPA.load(Ordering::Acquire);
    if base & 1 == 0 {
        return; // not enabled by guest yet
    }
    let host_ram = HOST_RAM_BASE.load(Ordering::Acquire);
    if host_ram == 0 {
        return; // enter_linux_guest hasn't initialised us
    }
    let guest_phys = base & !0x3u64;
    let host_addr = host_ram.wrapping_add(guest_phys);

    let host_tsc = unsafe { core::arch::x86_64::_rdtsc() };
    let freq = crate::clock::tsc_freq::host_tsc_freq();
    let (mul, shift) = compute_mul_shift(freq);

    // Anchor on the guest-visible TSC (host_tsc + VMCB.tsc_offset),
    // not the raw host TSC — the guest's RDTSC starts at 0 because we
    // set tsc_offset = -host_tsc_at_entry. system_time is the elapsed
    // wall-clock nanoseconds since that same anchor, so the guest's
    // `system_time + ((current_tsc - tsc_timestamp) * mul) >> shift`
    // sums to the correct ns since boot.
    let tsc_offset = GUEST_TSC_OFFSET.load(Ordering::Acquire);
    let guest_tsc = host_tsc.wrapping_add(tsc_offset);
    let system_time_ns: u64 = if freq != 0 {
        ((guest_tsc as u128) * 1_000_000_000u128 / (freq as u128)) as u64
    } else {
        0
    };

    // Standard double-write protocol: bump version to odd (write in
    // progress), fill the body, then bump to next even number.
    unsafe {
        let p = host_addr as *mut PvclockVcpuTimeInfo;
        let cur_ver = core::ptr::addr_of!((*p).version).read_unaligned();
        let next_odd = cur_ver.wrapping_add(1) | 1;
        core::ptr::addr_of_mut!((*p).version).write_unaligned(next_odd);
        core::sync::atomic::compiler_fence(Ordering::Release);

        core::ptr::addr_of_mut!((*p).pad).write_unaligned(0);
        core::ptr::addr_of_mut!((*p).tsc_timestamp).write_unaligned(guest_tsc);
        core::ptr::addr_of_mut!((*p).system_time).write_unaligned(system_time_ns);
        core::ptr::addr_of_mut!((*p).tsc_to_system_mul).write_unaligned(mul);
        core::ptr::addr_of_mut!((*p).tsc_shift).write_unaligned(shift);
        core::ptr::addr_of_mut!((*p).flags).write_unaligned(PVCLOCK_TSC_STABLE_BIT);
        core::ptr::addr_of_mut!((*p).pad2).write_unaligned([0, 0]);

        core::sync::atomic::compiler_fence(Ordering::Release);
        let next_even = next_odd.wrapping_add(1);
        core::ptr::addr_of_mut!((*p).version).write_unaligned(next_even);
    }
}

/// MSR_KVM_SYSTEM_TIME_NEW write — Linux passes (guest_phys | 1) here.
/// We latch and immediately populate the struct so the guest's very
/// first read sees a valid snapshot.
pub fn handle_wrmsr_system_time(val: u64) {
    PVCLOCK_GPA.store(val, Ordering::Release);
    if val & 1 != 0 {
        refresh();
    }
}

/// MSR_KVM_WALL_CLOCK_NEW write — Linux passes guest_phys of a
/// `pvclock_wall_clock` struct (12 bytes: version u32, sec u32, nsec u32).
/// We populate it once at write time so the guest reads a sane wall
/// clock for time-of-day initialisation.
pub fn handle_wrmsr_wall_clock(val: u64) {
    let host_ram = HOST_RAM_BASE.load(Ordering::Acquire);
    if host_ram == 0 {
        return;
    }
    let guest_phys = val & !0x3u64;
    let host_addr = host_ram.wrapping_add(guest_phys);

    // Synthesise a wall clock anchored at the RTC epoch + however much
    // wall time has elapsed since boot. Use guest-visible TSC (host +
    // offset) so the elapsed delta matches what the guest's own RDTSC
    // would report.
    let host_tsc = unsafe { core::arch::x86_64::_rdtsc() };
    let tsc_offset = GUEST_TSC_OFFSET.load(Ordering::Acquire);
    let guest_tsc = host_tsc.wrapping_add(tsc_offset);
    let freq = crate::clock::tsc_freq::host_tsc_freq();
    let elapsed_ns = if freq != 0 {
        ((guest_tsc as u128) * 1_000_000_000u128 / (freq as u128)) as u64
    } else {
        0
    };
    // Same epoch as our RTC emulator — 2026-01-01 00:00:00 UTC.
    const EPOCH: u32 = 1_767_225_600;
    let sec = EPOCH + (elapsed_ns / 1_000_000_000) as u32;
    let nsec = (elapsed_ns % 1_000_000_000) as u32;

    unsafe {
        // Format: [version u32][sec u32][nsec u32].
        let p = host_addr as *mut u32;
        // Two-write protocol like pvti.
        p.write_unaligned(1); // odd = in progress
        core::sync::atomic::compiler_fence(Ordering::Release);
        p.add(1).write_unaligned(sec);
        p.add(2).write_unaligned(nsec);
        core::sync::atomic::compiler_fence(Ordering::Release);
        p.write_unaligned(2); // even = done
    }
}
