//! 8259A Programmable Interrupt Controller (cascaded master+slave) +
//! ELCR (Edge/Level Configuration Register).
//!
//! Standard hypervisor pattern (QEMU pc/i8259.c, KVM arch/x86/kvm/i8259,
//! Cloud Hypervisor pic). Even when the guest uses IO-APIC for actual
//! IRQ delivery, the PIC is still expected to:
//!
//!   1. Respond to ICW1-ICW4 initialisation sequence (PC-AT BIOS does
//!      this at every boot before the OS takes over).
//!   2. Accept OCW1 mask writes (Linux disables PIC by masking all
//!      lines as one of the very first init steps).
//!   3. Echo back the IMR (interrupt mask register) on subsequent reads.
//!   4. ELCR (ports 0x4D0 / 0x4D1) reports edge vs. level trigger
//!      configuration — Linux logs "ACPI: setting ELCR to NNNN" right
//!      before APIC switchover.
//!
//! Ports:
//!   0x20  Master CMD / IRR / ISR / OCW2 (specific EOI etc.)
//!   0x21  Master DATA / IMR / ICW2 / ICW3 / ICW4
//!   0xA0  Slave CMD
//!   0xA1  Slave DATA
//!   0x4D0 ELCR master (IRQ 0-7 trigger mode)
//!   0x4D1 ELCR slave  (IRQ 8-15 trigger mode)

use core::sync::atomic::{AtomicU8, Ordering};

/// Per-chip state. Both master and slave share this layout.
struct PicChip {
    /// Interrupt Mask Register (OCW1) — bit N set = IRQ N masked.
    /// After Linux disables PIC this is 0xFF on both chips.
    imr: AtomicU8,
    /// Interrupt Request Register — pending interrupts. We don't
    /// inject yet, so always 0.
    irr: AtomicU8,
    /// In-Service Register — interrupts currently being handled.
    isr: AtomicU8,
    /// ICW2 (vector base) — kernel writes 0x20 to master, 0x28 to slave.
    vector_base: AtomicU8,
    /// Initialisation state machine: 0 = idle, 1 = expecting ICW2,
    /// 2 = expecting ICW3, 3 = expecting ICW4.
    init_state: AtomicU8,
    /// OCW3 read-select toggle: 0 = read IRR, 1 = read ISR.
    read_select: AtomicU8,
}

#[allow(clippy::declare_interior_mutable_const)]
const PIC_INIT: PicChip = PicChip {
    imr: AtomicU8::new(0xFF),         // Everything masked at reset
    irr: AtomicU8::new(0x00),
    isr: AtomicU8::new(0x00),
    vector_base: AtomicU8::new(0),
    init_state: AtomicU8::new(0),
    read_select: AtomicU8::new(0),
};

static MASTER: PicChip = PIC_INIT;
static SLAVE: PicChip = PIC_INIT;

/// ELCR (Edge/Level Configuration Register) — one byte per PIC.
/// Bit N set = IRQ N is level-triggered. Defaults: all edge per ISA
/// convention except the PCI INTA-D shareable lines (firmware sets
/// these to level). Linux logs the value via "ACPI: setting ELCR".
static ELCR_MASTER: AtomicU8 = AtomicU8::new(0x00);
static ELCR_SLAVE: AtomicU8 = AtomicU8::new(0x00);

/// Vector the guest assigned to ISA `irq` (0..15) through the 8259, or
/// None when that line is masked (IMR bit set) or the PIC is still being
/// initialised. IRQ 0..7 live on the master, 8..15 on the slave; the
/// vector is the chip's ICW2 base plus the in-chip index.
pub fn irq_vector(irq: u8) -> Option<u8> {
    let (chip, idx) = if irq < 8 { (&MASTER, irq) } else { (&SLAVE, irq - 8) };
    if chip.init_state.load(Ordering::Relaxed) != 0 {
        return None; // mid-init, vector base not committed
    }
    if chip.imr.load(Ordering::Relaxed) & (1 << idx) != 0 {
        return None; // masked
    }
    let base = chip.vector_base.load(Ordering::Relaxed);
    if base == 0 {
        return None; // never initialised
    }
    Some(base.wrapping_add(idx))
}

fn handle_command(chip: &PicChip, val: u8) {
    if val & 0x10 != 0 {
        // ICW1 — start of init sequence. Bit 0 indicates ICW4 will
        // follow; we accept either way and just walk the state machine.
        chip.init_state.store(1, Ordering::Relaxed);
        return;
    }
    if val & 0x08 != 0 {
        // OCW3 — read register select (bit 0/1) + special-mask (bit 5).
        // We only honour the read-select bit so subsequent reads return
        // IRR or ISR per the kernel's request.
        if val & 0x02 != 0 {
            chip.read_select.store(val & 0x01, Ordering::Relaxed);
        }
        return;
    }
    // OCW2 — EOI variants. We don't track in-service IRQs (no real
    // delivery yet) so clearing ISR is a no-op; the kernel just needs
    // the write to succeed.
    if val & 0x20 != 0 {
        chip.isr.store(0, Ordering::Relaxed);
    }
}

fn handle_data(chip: &PicChip, val: u8) {
    let state = chip.init_state.load(Ordering::Relaxed);
    match state {
        1 => {
            // ICW2 — vector base. Master typically 0x20, slave 0x28.
            chip.vector_base.store(val & 0xF8, Ordering::Relaxed);
            chip.init_state.store(2, Ordering::Relaxed);
        }
        2 => {
            // ICW3 — cascade info. Ignored (we have a fixed master/slave
            // wiring on IRQ2). State machine moves on.
            chip.init_state.store(3, Ordering::Relaxed);
        }
        3 => {
            // ICW4 — operating mode. Ignored beyond accepting it.
            chip.init_state.store(0, Ordering::Relaxed);
        }
        _ => {
            // OCW1 — mask register write. Linux uses this to mask all
            // IRQs (0xFF on both chips) once IO-APIC takes over.
            chip.imr.store(val, Ordering::Relaxed);
        }
    }
}

fn read_command(chip: &PicChip) -> u8 {
    if chip.read_select.load(Ordering::Relaxed) != 0 {
        chip.isr.load(Ordering::Relaxed)
    } else {
        chip.irr.load(Ordering::Relaxed)
    }
}

#[inline]
fn read_data(chip: &PicChip) -> u8 {
    chip.imr.load(Ordering::Relaxed)
}

#[inline]
pub fn covers(port: u16) -> bool {
    matches!(port, 0x20 | 0x21 | 0xA0 | 0xA1 | 0x4D0 | 0x4D1)
}

pub fn handle_in(port: u16) -> u8 {
    match port {
        0x20 => read_command(&MASTER),
        0x21 => read_data(&MASTER),
        0xA0 => read_command(&SLAVE),
        0xA1 => read_data(&SLAVE),
        0x4D0 => ELCR_MASTER.load(Ordering::Relaxed),
        0x4D1 => ELCR_SLAVE.load(Ordering::Relaxed),
        _ => 0xFF,
    }
}

pub fn handle_out(port: u16, val: u8) {
    {
        static PIC_W: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
        let n = PIC_W.fetch_add(1, Ordering::Relaxed);
        if n < 32 {
            crate::sprintln!("[pic] OUT 0x{:X} <- 0x{:02X}", port, val);
        }
    }
    match port {
        0x20 => handle_command(&MASTER, val),
        0x21 => handle_data(&MASTER, val),
        0xA0 => handle_command(&SLAVE, val),
        0xA1 => handle_data(&SLAVE, val),
        0x4D0 => ELCR_MASTER.store(val, Ordering::Relaxed),
        0x4D1 => ELCR_SLAVE.store(val, Ordering::Relaxed),
        _ => {}
    }
}
