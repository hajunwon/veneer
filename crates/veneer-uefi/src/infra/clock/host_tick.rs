//! Independent periodic VMEXIT — the hypervisor preemption tick.
//!
//! veneer injects guest interrupts only while handling a #VMEXIT
//! (`inject::stage_pending`, called from the dispatcher). With RDTSC running
//! NATIVE (A++), a guest that busy-waits — e.g. WinPE spinning on a timer or a
//! device flag — executes with ZERO exits, so veneer never gets the chance to
//! inject the guest's own LAPIC timer and the guest deadlocks (observed: the
//! 256-bus PCI scan completes, then the log freezes with no exits for minutes).
//!
//! Real hypervisors avoid this with a host-driven preemption tick. AMD SVM has
//! no VMX-style preemption timer, so we arm the HOST LAPIC timer to fire
//! periodically and set the INTR intercept (vmcb): a host timer tick that lands
//! while the guest runs forces a #VMEXIT(INTR), giving the dispatcher a chance
//! to inject pending guest interrupts regardless of what the guest is doing.
//!
//! veneer otherwise runs its host context with GIF=0 (no host interrupts; it
//! polls UEFI). #VMEXIT clears GIF, so the pending physical tick is NOT drained
//! automatically — `vmrun` opens a one-instruction interrupt window
//! (stgi/sti/nop/cli/clgi) after each exit so this ISR runs, EOIs the LAPIC,
//! and clears the pending IRQ (otherwise every VMRUN would instantly re-exit on
//! the same pending interrupt = livelock).
//!
//! Hardware facts this relies on were measured first ([hostapic] dump):
//! host is xAPIC (MMIO 0xFEE00000), TSC-deadline unsupported (→ classic
//! periodic timer), 256-entry host IDT we hook one unused vector in.

use crate::infra::arch;
use core::sync::atomic::{AtomicBool, Ordering};

/// LAPIC MMIO register offsets (xAPIC).
const LAPIC_EOI: u64 = 0x0B0;
const LAPIC_LVT_TIMER: u64 = 0x320;
const LAPIC_TIMER_ICR: u64 = 0x380; // initial count
const LAPIC_TIMER_CCR: u64 = 0x390; // current count
const LAPIC_TIMER_DCR: u64 = 0x3E0; // divide config

/// IDT vector for our host timer. High and otherwise unused — hooking it
/// replaces only the default handler for a vector no device raises.
pub const TIMER_VECTOR: u8 = 0xEC;

/// Tick period in ms. Under VMware nested each forced #VMEXIT costs ~500µs, so
/// a 1 kHz tick burned ~50% of wall time. The tick only needs to be frequent
/// enough to break a guest busy-wait and deliver timer IRQs — ~200 Hz (5 ms)
/// cuts the overhead ~5× while staying well under Windows' ~15.6 ms scheduler
/// tick. Raise toward 1 ms only if a guest needs finer timer granularity.
const TICK_PERIOD_MS: u32 = 5;

static ARMED: AtomicBool = AtomicBool::new(false);

/// True once the host preemption tick is armed (the INTR intercept is only
/// meaningful after this).
pub fn armed() -> bool {
    ARMED.load(Ordering::Relaxed)
}

// Naked ISR: acknowledge the LAPIC (write 0 to EOI) and return. Preserves rax
// (the only register it touches) and all flags via iretq. 0xFEE000B0 is the
// fixed xAPIC EOI MMIO address (host is confirmed xAPIC, base 0xFEE00000).
core::arch::global_asm!(
    ".global veneer_timer_isr",
    "veneer_timer_isr:",
    "push rax",
    "mov eax, 0xFEE000B0", // zero-extends into rax
    "mov dword ptr [rax], 0",
    "pop rax",
    "iretq",
);
extern "C" {
    fn veneer_timer_isr();
}

#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | (lo as u64)
}

fn lapic_base() -> u64 {
    (unsafe { arch::rdmsr(0x1B) }) & 0xF_FFFF_F000
}

#[inline]
unsafe fn lapic_rd(base: u64, off: u64) -> u32 {
    unsafe { core::ptr::read_volatile((base + off) as *const u32) }
}

#[inline]
unsafe fn lapic_wr(base: u64, off: u64, v: u32) {
    unsafe { core::ptr::write_volatile((base + off) as *mut u32, v) }
}

/// Hook the timer vector into the live host IDT and arm the host LAPIC timer
/// to fire periodically (~1 ms). Call once, in host context, before the VMRUN
/// loop. Pairs with the INTR intercept (vmcb) + the interrupt window (vmrun).
pub fn install_and_arm() {
    // Host code selector for the IDT gate.
    let cs: u16;
    unsafe {
        core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    // Host IDT base from SIDT.
    let mut idtr = [0u8; 10];
    unsafe {
        core::arch::asm!("sidt [{}]", in(reg) idtr.as_mut_ptr(), options(nostack, preserves_flags));
    }
    let idt_base = u64::from_le_bytes([
        idtr[2], idtr[3], idtr[4], idtr[5], idtr[6], idtr[7], idtr[8], idtr[9],
    ]);

    // Write a 64-bit interrupt gate at IDT[TIMER_VECTOR].
    let isr = veneer_timer_isr as *const () as usize as u64;
    let ent = (idt_base + (TIMER_VECTOR as u64) * 16) as *mut u8;
    unsafe {
        core::ptr::write_volatile(ent as *mut u16, (isr & 0xFFFF) as u16); // offset[15:0]
        core::ptr::write_volatile(ent.add(2) as *mut u16, cs); // selector
        core::ptr::write_volatile(ent.add(4), 0u8); // IST = 0
        core::ptr::write_volatile(ent.add(5), 0x8Eu8); // P=1, DPL=0, 64-bit interrupt gate
        core::ptr::write_volatile(ent.add(6) as *mut u16, ((isr >> 16) & 0xFFFF) as u16); // offset[31:16]
        core::ptr::write_volatile(ent.add(8) as *mut u32, ((isr >> 32) & 0xFFFF_FFFF) as u32); // offset[63:32]
        core::ptr::write_volatile(ent.add(12) as *mut u32, 0u32); // reserved
    }

    // Calibrate the LAPIC timer reload against the host HPET, not the host
    // TSC: under VMware nested SVM the TSC races wall clock by ~250×, so a
    // TSC-timed "1 ms" was really ~4 µs and the periodic tick over-fired
    // ~250× (50 kHz instead of 200 Hz, ~half of all VMEXITs). The host HPET
    // keeps wall-clock semantics here, so timing the calibration interval on
    // it yields a reload that fires at the true period.
    let base = lapic_base();
    const HPET: usize = 0xFED0_0000;
    let _ = idt_base; // (kept above for the gate write)
    unsafe {
        let cap = core::ptr::read_volatile(HPET as *const u64);
        let period_fs = (cap >> 32) & 0xFFFF_FFFF;
        let hpet_hz = if period_fs != 0 { 1_000_000_000_000_000u64 / period_fs } else { 14_318_180 };
        // Enable the HPET main counter so it advances during the measurement.
        let hcfg = core::ptr::read_volatile((HPET + 0x10) as *const u64);
        core::ptr::write_volatile((HPET + 0x10) as *mut u64, hcfg | 1);
        // HPET ticks spanning one tick period of REAL time.
        let hpet_per_period = (hpet_hz / 1000).saturating_mul(TICK_PERIOD_MS as u64).max(1);

        lapic_wr(base, LAPIC_TIMER_DCR, 0x3); // divide by 16
        // Masked one-shot while we measure the count rate (no interrupt).
        lapic_wr(base, LAPIC_LVT_TIMER, 0x1_0000 | TIMER_VECTOR as u32);
        lapic_wr(base, LAPIC_TIMER_ICR, 0xFFFF_FFFF);
        let h0 = core::ptr::read_volatile((HPET + 0xF0) as *const u64);
        let c0 = lapic_rd(base, LAPIC_TIMER_CCR);
        while core::ptr::read_volatile((HPET + 0xF0) as *const u64).wrapping_sub(h0) < hpet_per_period {}
        let c1 = lapic_rd(base, LAPIC_TIMER_CCR);
        let reload = c0.wrapping_sub(c1).max(1); // LAPIC ticks in one real period
        // Periodic, unmasked, our vector.
        lapic_wr(base, LAPIC_LVT_TIMER, 0x2_0000 | TIMER_VECTOR as u32);
        lapic_wr(base, LAPIC_TIMER_ICR, reload);
        crate::sprintln!(
            "[host-tick] armed (HPET-cal): vec=0x{:X} reload={} period={}ms (~{}Hz) hpet={}Hz cs=0x{:X} isr=0x{:X}",
            TIMER_VECTOR, reload, TICK_PERIOD_MS, 1000 / TICK_PERIOD_MS, hpet_hz, cs, isr
        );
    }
    ARMED.store(true, Ordering::Relaxed);
}
