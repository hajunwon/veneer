//! Interrupt-injection layer.
//!
//! After every VMEXIT handler runs, before the next VMRUN, we check for
//! pending interrupts that should be delivered to the guest. Maskable
//! interrupts are raised through the AMD virtual-interrupt mechanism
//! (`VMCB.control.vintr` V_IRQ); the CPU then delivers them only when the
//! guest has IF set and the vector's priority class exceeds V_TPR (the
//! guest's IRQL, virtualised from CR8) — so an interrupt never pre-empts a
//! higher-IRQL critical section. The earlier event_inj path bypassed V_TPR
//! and delivered unconditionally, which let a timer fire into a HIGH_LEVEL
//! HAL critical section and self-deadlock (KxWaitForSpinLock).
//!
//! NMIs are still injected via event_inj (AMD APM Vol 2 §15.20) — they are
//! non-maskable and bypass IF/TPR by design.
//!
//! Sources of pending interrupts:
//!   - LAPIC periodic / one-shot timer (LVT Timer counter hit 0)
//!   - IO-APIC redirection (future: PCI device IRQs)
//!   - 8259 PIC (future: legacy IRQ delivery for Windows paths)
//!
//! Single-vCPU for now — slot 0 only. SMP support adds per-CPU dispatch
//! once we move beyond Linux verification.
//!
//! Why a dedicated module: interrupt staging is a cross-cutting concern
//! (every VMEXIT path leads here on the way out). Inlining it into
//! `mod.rs::dispatch` would tangle scheduler-style logic with the
//! exit-code switch. A standalone module keeps `dispatch` focused on
//! routing and `inject` focused on delivery policy.

use crate::hypervisor::svm::vmcb::{vintr, Vmcb, VmcbControl};

use crate::hardware::devices::storage::{ahci, nvme};
use crate::hardware::devices::i8042;
use crate::hardware::devices::iommu;
use super::{hpet, ioapic, lapic, pic, pit, rtc};

/// AMD event_inj type field encodings. Only NMI is delivered via event_inj
/// now — maskable interrupts go through V_IRQ so the CPU honours V_TPR.
const TYPE_NMI: u64 = 2;

/// Bit 31 of event_inj — set marks the slot live for the next VMRUN.
const VALID: u64 = 1 << 31;

static LAPIC_TIMER_INJ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static NVME_INJ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static AHCI_INJ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static PIT_INJ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static HPET_INJ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static IPI_INJ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static KBD_INJ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static MOUSE_INJ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
// Diagnostic (winload native-spin investigation): counts pending-but-dropped
// timer IRQs (route masked) and firmware-region idle passes. Remove once the
// spin is understood.
static DROP_TRACE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static IDLE_TRACE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Interrupt injection is in the hot path; logging every one floods the
/// serial log (a tick every ~1 ms, a completion per disk command). Trace
/// the first few and a sparse sample after that.
#[inline]
fn throttle(c: &core::sync::atomic::AtomicU64, every: u64) -> bool {
    let n = c.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    n < 4 || n % every == 0
}

/// Raise `vector` as a virtual interrupt (AMD V_IRQ). The CPU delivers it
/// to the guest once GIF=1, guest IF=1 and the vector's priority class
/// exceeds V_TPR (the guest's IRQL, virtualised from CR8); until then it
/// stays pending and the CPU delivers it autonomously when the guest lowers
/// IRQL. Preserves V_TPR and V_INTR_MASKING and leaves V_IGN_TPR clear so
/// IRQL gating applies — this is the path event_inj bypassed.
#[inline]
fn raise_virq(c: &mut VmcbControl, vector: u8) {
    let prio = (vector as u64 >> 4) & 0xF;
    let keep = c.vintr & (vintr::V_TPR_MASK | vintr::V_INTR_MASKING);
    c.vintr = keep
        | vintr::V_IRQ
        | (prio << vintr::V_INTR_PRIO_SHIFT)
        | ((vector as u64) << vintr::V_INTR_VECTOR_SHIFT);
}

/// The single V_IRQ we've raised but the CPU hasn't accepted yet. Real
/// hardware moves a request from IRR to ISR only on accept (guest IF=1, IRQL
/// below the vector's class), holding it in IRR while still pending. Doing
/// the IRR->ISR transition at staging time (possibly IF=0) made HAL's IRR
/// poll (HalpApicRequestInterrupt) see the bit vanish and re-request forever,
/// an xAPIC NPF storm. So defer it: stage V_IRQ now, commit to ISR once the
/// CPU has delivered it (V_IRQ auto-clears on accept). 0 = nothing armed.
static INFLIGHT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
const INFLIGHT_VALID: u32 = 1 << 31;
/// GSI of the in-flight interrupt for the level remote-IRR hand-off, or -1
/// for an edge source (LAPIC timer, MSI/MSI-X, self-IPI).
static INFLIGHT_GSI: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(-1);

/// Raise `vector` as V_IRQ and arm its deferred in-service transition.
/// `gsi` = Some for an IO-APIC-routed line (level / remote-IRR resolved on
/// commit), None for an edge source (LAPIC timer, MSI/MSI-X, self-IPI).
fn stage_virq(c: &mut VmcbControl, vector: u8, gsi: Option<u32>) {
    raise_virq(c, vector);
    INFLIGHT.store(vector as u32 | INFLIGHT_VALID, core::sync::atomic::Ordering::Relaxed);
    INFLIGHT_GSI.store(gsi.map(|g| g as i32).unwrap_or(-1), core::sync::atomic::Ordering::Relaxed);
}

/// Commit the in-flight interrupt into service after the CPU has delivered it
/// (caller checks V_IRQ is clear): move IRR->ISR (TMR for level) and, for a
/// level GSI, set the IO-APIC remote-IRR so the line can't re-fire until EOI.
/// No-op when nothing is armed.
fn commit_inflight() {
    let v = INFLIGHT.swap(0, core::sync::atomic::Ordering::Relaxed);
    if v & INFLIGHT_VALID == 0 {
        return;
    }
    let vector = (v & 0xFF) as u8;
    let gsi = INFLIGHT_GSI.swap(-1, core::sync::atomic::Ordering::Relaxed);
    if gsi >= 0 {
        let level = ioapic::is_level(gsi as usize);
        lapic::set_in_service(0, vector, level);
        if level {
            ioapic::set_remote_irr(gsi as usize);
        }
    } else {
        lapic::set_in_service(0, vector, false);
    }
}

/// Stage any pending interrupts into `VMCB.event_inj` before the next
/// VMRUN. Called by the dispatcher after the per-exit handler returns,
/// regardless of which exit code fired — interrupts are time-driven and
/// independent of why we exited.
///
/// Safety: caller must hold a valid `*mut Vmcb` and the VMCB must not
/// already have a pending event_inj from the previous round (hardware
/// would conflict — handler dispatch already consumed it).
pub unsafe fn stage_pending(vmcb: *mut Vmcb) {
    // event_inj is single-shot per VMRUN cycle. Pick the highest-
    // priority source we have a pending IRQ for. Priority order
    // (informed by real PC ISA conventions):
    //   1. LAPIC timer  — scheduler tick (modern path)
    //   2. PIT IRQ0     — legacy 8254 tick (fallback the guest uses when
    //                     it disables the LAPIC timer)
    //   3. LAPIC self-IPI
    // Reconcile the HPET writable-shadow every exit (publishes the live main
    // counter into the backing page + re-arms timer 0 from the guest's
    // comparator). Cheap no-op when the shadow isn't enabled. Runs before the
    // injection gates so the counter stays fresh even when no IRQ is delivered.
    hpet::shadow_tick();

    let c = unsafe { &mut (*vmcb).control };
    // A V_IRQ we raised earlier and the CPU has since accepted (V_IRQ auto-
    // clears on delivery) moves IRR->ISR here — deferred from staging so the
    // request stays visible in IRR while still pending (IF=0 / high IRQL),
    // matching real hardware and not tripping HAL's IRR poll.
    if c.vintr & vintr::V_IRQ == 0 {
        commit_inflight();
    }
    // Don't clobber an event the handler itself just staged
    // (e.g., an exception forwarded from #PF intercept).
    if c.event_inj & VALID != 0 {
        return;
    }
    // NMI (from an ICR delivery-mode-NMI self-IPI) is non-maskable: it is
    // not gated by IF or the interrupt shadow, so stage it before the
    // maskable-interrupt gate below. event_inj NMI type carries no vector.
    if lapic::nmi_pending(0) {
        crate::sprintln!("[inject] self-nmi");
        c.event_inj = (TYPE_NMI << 8) | VALID;
        return;
    }
    // A virtual interrupt is already programmed but the CPU hasn't delivered
    // it yet — it's holding it behind guest IF or V_TPR (IRQL). Don't stack
    // another; hardware delivers it autonomously once the guest allows, and
    // V_IRQ auto-clears on delivery so the next pass programs the next one.
    if c.vintr & vintr::V_IRQ != 0 {
        return;
    }
    // Self-IPI software interrupts (Windows APC 0x1F / DPC 0x2F) are
    // fire-and-forget: the guest requests them at raised IRQL with IF=0 and
    // relies on the LAPIC delivering them once IRQL/IF drop. Program V_IRQ now
    // even at guest IF=0 — under V_INTR_MASKING the CPU holds the request and
    // delivers it autonomously the moment guest IF=1 and V_INTR_PRIO > V_TPR,
    // with no further VMEXIT. This must run before the IF gate below: gating it
    // on guest IF would never program V_IRQ for the common IF=0 case, the
    // request would be dropped, and the DPC/APC dispatch would starve (the
    // guest then re-requests in a tight self-IPI storm, never progressing).
    if let Some(vector) = lapic::ipi_pending(0) {
        if throttle(&IPI_INJ, 16384) { crate::sprintln!("[inject] self-ipi vec=0x{:X}", vector); }
        stage_virq(c, vector, None);
        return;
    }
    // Stage the remaining maskable interrupts only when the guest has IF set
    // and isn't in an interrupt shadow (the boundary right after STI / MOV SS).
    // Hardware also gates V_IRQ on guest IF, but this early-out keeps a pending
    // device IRQ in its source (and the LAPIC IRR) at IF=0 so a guest polling
    // IRR still sees it, rather than consuming it into a deferred V_IRQ slot.
    let rflags = unsafe { (*vmcb).state.rflags };
    if rflags & (1 << 9) == 0 || c.interrupt_shadow & 1 != 0 {
        return;
    }
    // 0. Device completion interrupts (NVMe MSI-X) — staged the moment a
    //    command completes so the driver's wait wakes immediately.
    if let Some(vector) = nvme::pending_irq() {
        if throttle(&NVME_INJ, 4096) { crate::sprintln!("[inject] nvme-msix vec=0x{:X}", vector); }
        stage_virq(c, vector, None);
        return;
    }
    if let Some(vector) = ahci::pending_irq() {
        if throttle(&AHCI_INJ, 4096) { crate::sprintln!("[inject] ahci-msi vec=0x{:X}", vector); }
        stage_virq(c, vector, None);
        return;
    }
    // PS/2 keyboard IRQ1 (legacy ISA line, no MADT override → GSI1). A typed
    // scancode from the host-keyboard bridge is waiting in the 8042 buffer.
    if i8042::irq1_pending() {
        match gsi_vector(1) {
            Some(vector) => {
                if throttle(&KBD_INJ, 4096) { crate::sprintln!("[inject] kbd-irq1 vec=0x{:X}", vector); }
                stage_virq(c, vector, Some(1));
                i8042::irq1_serviced();
                return;
            }
            None => i8042::irq1_serviced(),
        }
    }
    // PS/2 mouse IRQ12 (aux port, legacy ISA line → GSI12). Pointer motion /
    // button packets from the host bridge wait in the 8042 aux buffer.
    if i8042::irq12_pending() {
        match gsi_vector(12) {
            Some(vector) => {
                if throttle(&MOUSE_INJ, 4096) { crate::sprintln!("[inject] mouse-irq12 vec=0x{:X}", vector); }
                stage_virq(c, vector, Some(12));
                i8042::irq12_serviced();
                return;
            }
            None => i8042::irq12_serviced(),
        }
    }
    // 1. LAPIC timer — periodic / one-shot scheduler tick.
    if let Some(vector) = lapic::timer_pending(0) {
        stage_virq(c, vector, None);
        lapic::timer_serviced(0);
        let n = LAPIC_TIMER_INJ.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if n < 4 || n % 5000 == 0 {
            let rip = unsafe { (*vmcb).state.rip };
            crate::sprintln!("[inject] vec=0x{:X} #{} rip=0x{:X}", vector, n, rip);
        }
        return;
    }
    // 2. HPET timer 0 — the clockevent Linux falls back to after
    //    disabling the LAPIC timer. Routed via IO-APIC (or IRQ0 in
    //    legacy-replacement mode).
    if hpet::timer0_pending() {
        match gsi_vector(hpet::timer0_gsi()) {
            Some(vector) => {
                if throttle(&HPET_INJ, 16384) { crate::sprintln!("[inject] hpet vec=0x{:X}", vector); }
                stage_virq(c, vector, Some(hpet::timer0_gsi()));
                hpet::timer0_serviced();
                return;
            }
            None => {
                if throttle(&DROP_TRACE, 256) {
                    let rip = unsafe { (*vmcb).state.rip };
                    crate::sprintln!("[inject] DROP hpet pending gsi={} route-masked rip=0x{:X}", hpet::timer0_gsi(), rip);
                }
                hpet::timer0_serviced();
            }
        }
    }
    // 3. PIT counter-0 IRQ0 — legacy tick. Resolve the vector the guest
    //    wired it to (IO-APIC GSI2 via the ISA override, else 8259).
    if pit::irq0_pending() {
        match irq0_vector() {
            Some(vector) => {
                if throttle(&PIT_INJ, 8192) { crate::sprintln!("[inject] pit-irq0 vec=0x{:X}", vector); }
                // IRQ0 is overridden to GSI2 on a real PC; the GSI2 entry's
                // trigger mode (edge for the PIT tick) is resolved on commit.
                stage_virq(c, vector, Some(2));
                pit::irq0_serviced();
                return;
            }
            // Route is masked — the guest doesn't want this tick. Consume
            // it so we don't spin re-evaluating the same expired deadline.
            None => {
                if throttle(&DROP_TRACE, 256) {
                    let rip = unsafe { (*vmcb).state.rip };
                    crate::sprintln!("[inject] DROP pit-irq0 pending route-masked rip=0x{:X}", rip);
                }
                pit::irq0_serviced();
            }
        }
    }
    // 4. RTC periodic IRQ8 — only live once the guest sets Status B PIE
    //    with a non-zero rate (OVMF / Windows boot don't, so this is
    //    dormant during the current bring-up). IRQ8 has no ISA→GSI
    //    override; it maps 1:1 to GSI8 in the IO-APIC, or the 8259 slave
    //    if the guest left the PIC in charge.
    if rtc::irq8_pending() {
        match gsi_vector(8) {
            Some(vector) => {
                crate::sprintln!("[inject] rtc-irq8 vec=0x{:X}", vector);
                stage_virq(c, vector, Some(8));
                rtc::irq8_serviced();
                return;
            }
            // Route masked — consume so we don't re-spin the same deadline.
            None => rtc::irq8_serviced(),
        }
    }
    // Diagnostic: reached here = nothing injected this round. If the guest is
    // spinning in firmware (RIP in the OVMF range) with IF=1, no timer source
    // was pending — distinguishes "timer dropped" (DROP logs above) from
    // "timer never armed" (this log). Remove once the spin is understood.
    let rip = unsafe { (*vmcb).state.rip };
    if (0x7E00_0000..0x8000_0000).contains(&rip) && throttle(&IDLE_TRACE, 8192) {
        crate::sprintln!("[inject] idle: no pending irq, IF=1 rip=0x{:X}", rip);
    }
}

/// Vector the guest assigned to the legacy timer IRQ0. Real PC firmware
/// overrides ISA IRQ0 to GSI2, so the guest programs IO-APIC redirection
/// entry 2; fall back to the 8259 master vector base if the guest left
/// the PIC in charge. None when both routes are masked.
fn irq0_vector() -> Option<u8> {
    gsi_vector(2)
}

/// Resolve a GSI to the vector the guest programmed, preferring the
/// IO-APIC redirection table and falling back to the 8259 for the ISA
/// lines (GSI 0..15 map 1:1 to legacy IRQs save the IRQ0→GSI2 override).
fn gsi_vector(gsi: u32) -> Option<u8> {
    // x2APIC path: with the IOMMU's interrupt remapping active, the IO-APIC RTE
    // "vector" field is an IR-table index, not a literal vector. Resolve the real
    // vector through the IRTE (DTE → IR table → IRTE). A masked RTE isn't
    // delivered, and there is no 8259 fallback once IR is on.
    if iommu::ir_active() {
        let rte = ioapic::raw_rte(gsi as usize);
        if rte & (1 << 16) != 0 {
            return None; // masked
        }
        return iommu::remap_vector((rte & 0xFF) as u8).filter(|&v| v >= 16);
    }
    // Legacy (xAPIC) path: the RTE field holds the literal vector.
    if let Some((vector, masked)) = ioapic::redirection(gsi as usize) {
        if !masked && vector >= 16 {
            return Some(vector);
        }
    }
    // PIC fallback: GSI2 is the overridden IRQ0; other GSIs < 16 map to
    // the same-numbered ISA IRQ.
    let irq = if gsi == 2 { 0 } else { gsi as u8 };
    if gsi < 16 {
        pic::irq_vector(irq)
    } else {
        None
    }
}
