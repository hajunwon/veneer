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

use crate::hypervisor::svm::gprs::GuestGprs;
use crate::hypervisor::svm::vmcb::Vmcb;

use super::{lengths, Action};
use crate::hardware::devices::irq::{hpet, lapic, pit};

#[inline]
fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
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
    loop {
        if wake_pending() {
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
            return Action::Resume;
        }
        core::hint::spin_loop();
    }
}
