//! HLT intercept handler.
//!
//! HLT means "halt the CPU until the next interrupt". For a guest that is
//! actually running, the idle task issues HLT constantly to wait for the
//! next timer tick, so HLT is NOT a termination signal — treating it as
//! one strands any boot that blocks on I/O or sleeps. We step past the
//! HLT, and if interrupts are enabled we idle on the host until a
//! deliverable wake source is due, then resume so `inject::stage_pending`
//! injects it. Only a HLT with interrupts masked (IF=0) — machine halt /
//! poweroff / panic spin — is a real terminal state.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hypervisor::svm::gprs::GuestGprs;
use crate::hypervisor::svm::vmcb::Vmcb;

use super::{lengths, Action};
use crate::hardware::devices::irq::{hpet, lapic, pit};

#[inline]
fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

// ── HLT idle-spin profiler (temporary) ──
// Measures the per-HLT busy-wait with BOTH the throttle-immune host HPET (true
// wall-clock) and host RDTSC (which VMware throttles during a busy-spin). The
// wall/rdtsc ratio quantifies the throttle; the wake-source tally shows what the
// guest was actually waiting for. Reveals whether the slow boot phase is HLT
// idle-wait time and whether the writable-shadow deadline is stale in the spin.
static HP_N: AtomicU64 = AtomicU64::new(0);
static HP_WALL: AtomicU64 = AtomicU64::new(0);   // host HPET ticks spent spinning
static HP_RDTSC: AtomicU64 = AtomicU64::new(0);  // host TSC cycles spent spinning
static HP_MAX: AtomicU64 = AtomicU64::new(0);    // longest single spin (HPET ticks)
static WK_LAPIC: AtomicU64 = AtomicU64::new(0);
static WK_HPET: AtomicU64 = AtomicU64::new(0);
static WK_PIT: AtomicU64 = AtomicU64::new(0);
static WK_CAP: AtomicU64 = AtomicU64::new(0);

fn hlt_prof(hpet_ticks: u64, tsc_cyc: u64, wake: &AtomicU64) {
    HP_WALL.fetch_add(hpet_ticks, Ordering::Relaxed);
    HP_RDTSC.fetch_add(tsc_cyc, Ordering::Relaxed);
    if hpet_ticks > HP_MAX.load(Ordering::Relaxed) { HP_MAX.store(hpet_ticks, Ordering::Relaxed); }
    wake.fetch_add(1, Ordering::Relaxed);
    let n = HP_N.fetch_add(1, Ordering::Relaxed) + 1;
    if n % 2000 == 0 {
        let hz = crate::infra::clock::host_hpet_hz().max(1);
        let thz = crate::infra::clock::tsc_freq::host_tsc_freq().max(1);
        let wall_ms = HP_WALL.load(Ordering::Relaxed) * 1000 / hz;
        let rd_ms = HP_RDTSC.load(Ordering::Relaxed) / (thz / 1000).max(1);
        let max_ms = HP_MAX.load(Ordering::Relaxed) * 1000 / hz;
        let (m, d, c) = hpet::diag_state();
        crate::sprintln!(
            "[hlt-prof] n={} wall={}ms rdtsc={}ms (throttle {}x) avg={}us max={}ms wake[lapic={} hpet={} pit={} cap={}] | hpet main=0x{:X} deadline=0x{:X} cmp=0x{:X}",
            n, wall_ms, rd_ms, if rd_ms > 0 { wall_ms / rd_ms } else { 0 },
            HP_WALL.load(Ordering::Relaxed) * 1_000_000 / hz / n, max_ms,
            WK_LAPIC.load(Ordering::Relaxed), WK_HPET.load(Ordering::Relaxed),
            WK_PIT.load(Ordering::Relaxed), WK_CAP.load(Ordering::Relaxed),
            m, d, c,
        );
    }
}

/// A wake source is due right now (non-consuming — staging consumes it).
fn wake_pending() -> bool {
    lapic::timer_pending(0).is_some() || hpet::timer0_pending() || pit::irq0_pending()
}

/// A wake source is armed and will eventually become due on its own.
fn wake_armed() -> bool {
    pit::irq0_armed() || hpet::timer0_armed() || lapic::timer_armed(0)
}

pub unsafe fn handle(vmcb: *mut Vmcb, _gprs: &mut GuestGprs) -> Action {
    let st = unsafe { &mut (*vmcb).state };
    // Resume after the HLT, not on it.
    st.rip = st.rip.wrapping_add(lengths::HLT);
    let rflags = st.rflags; // copy out — packed field can't be borrowed

    // The kernel idle path is `STI; HLT`: STI arms a one-instruction
    // interrupt shadow that covers the HLT. Now that we've stepped past the
    // HLT the shadow is spent, so clear it (what KVM's
    // skip_emulated_instruction does on every skip). Left set, inject's
    // shadow guard refuses the pending tick and the guest spins STI;HLT
    // forever with an undeliverable IRQ — exactly the wedge that stalls the
    // libata probe workqueue after `ata1` registers.
    unsafe { (*vmcb).control.interrupt_shadow &= !1; }

    if rflags & (1 << 9) == 0 {
        // Interrupts masked: nothing can wake the CPU. Real terminal HLT.
        crate::sprintln!(
            "[hlt ] terminal: IF=0 rflags=0x{:X} (machine halt / poweroff / panic)",
            rflags
        );
        return Action::Halt;
    }

    // IF=1: idle until a deliverable interrupt is due. Spin on the host
    // rather than round-tripping through VMRUN (which would burn the
    // guest iteration budget). Cap the spin at ~2 s of host time so a
    // miscomputed deadline can't wedge the VM silently.
    let spin_cap = crate::infra::clock::tsc_freq::host_tsc_freq().saturating_mul(2);
    let start = rdtsc();
    let hpet_start = crate::infra::clock::host_hpet_now();
    loop {
        // Identify the wake source so the profiler can attribute the wait.
        let wake = if lapic::timer_pending(0).is_some() { Some(&WK_LAPIC) }
            else if hpet::timer0_pending() { Some(&WK_HPET) }
            else if pit::irq0_pending() { Some(&WK_PIT) }
            else { None };
        if let Some(w) = wake {
            let hp = crate::infra::clock::host_hpet_now().wrapping_sub(hpet_start);
            hlt_prof(hp, rdtsc().wrapping_sub(start), w);
            return Action::Resume;
        }
        if !wake_armed() {
            // No timer source armed — the guest is waiting on a device
            // IRQ we don't deliver yet. Can't make progress here.
            crate::sprintln!(
                "[hlt ] idle, IF=1, but NO wake source armed: pit_irq0={} hpet_t0={} lapic_timer={} (guest waiting on a device IRQ)",
                pit::irq0_armed(), hpet::timer0_armed(), lapic::timer_armed(0)
            );
            hpet::debug_dump();
            pit::debug_dump();
            lapic::debug_dump();
            crate::hardware::devices::irq::ioapic::debug_dump();
            return Action::Halt;
        }
        if rdtsc().wrapping_sub(start) > spin_cap {
            // Deadline never arrived; resume defensively so the guest can
            // re-evaluate instead of spinning the host forever.
            let hp = crate::infra::clock::host_hpet_now().wrapping_sub(hpet_start);
            hlt_prof(hp, rdtsc().wrapping_sub(start), &WK_CAP);
            return Action::Resume;
        }
        core::hint::spin_loop();
    }
}
