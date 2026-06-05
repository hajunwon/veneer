//! DSDT namespace — the device tree the guest OS walks to discover the
//! platform's non-PCI hardware.
//!
//! Built programmatically via the [`aml`] encoder. The shape mirrors a real
//! desktop firmware's DSDT:
//!
//!   Scope (\_SB) {
//!     Device (PCI0) {                  ; PCIe root (PNP0A08 / PNP0A03)
//!       _HID/_CID/_UID/_BBN/_CRS/_PRT
//!       _OSC                           ; PCIe feature negotiation
//!       Device (SBRG) {                ; LPC/ISA bridge (00:03.0)
//!         PS2K  PNP0303                ; keyboard      (0x60/0x64, IRQ1)
//!         RTC0  PNP0B00                ; RTC           (0x70-0x71, IRQ8)
//!         TIMR  PNP0100                ; 8254 PIT      (0x40-0x43, IRQ0)
//!         SPKR  PNP0800                ; speaker       (0x61)
//!         COMA  PNP0501                ; serial COM1   (0x3F8, IRQ4)
//!         MATH  PNP0C04                ; FPU           (0xF0, IRQ13)
//!         PICD  PNP0000                ; 8259 PIC      (0x20/0xA0, IRQ2)
//!         DMAD  PNP0200                ; 8237 DMA      (0x00/0x80/0xC0)
//!         HPET  PNP0103                ; HPET          (MMIO 0xFED00000)
//!       }
//!     }
//!     Device (SYSR) { PNP0C02 }        ; motherboard reserved resources
//!   }
//!   Name (\_S0) / Name (\_S5)          ; working + soft-off
//!   Method (\_PIC, 1)                  ; APIC-mode handshake
//!
//! Without this namespace the OS can discover PCI devices (the bus is
//! self-describing) but never the legacy/system devices — and, lacking the
//! PNP0C02 consumed-resource map, its PnP arbitrator has no picture of which
//! fixed I/O / MMIO ranges the platform already owns.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use super::aml;
use crate::hardware::devices::iommu::{IOMMU_MMIO_BASE, IOMMU_MMIO_SIZE};
use crate::hardware::devices::irq::hpet::HPET_BASE;
use crate::hardware::devices::tpm::{TPM_BASE, TPM_SIZE};

/// Standard IO-APIC / Local-APIC MMIO windows (architectural fixed bases).
const IO_APIC_BASE: u32 = 0xFEC0_0000;
const LOCAL_APIC_BASE: u32 = 0xFEE0_0000;
/// AMD FCH LPC/ISA bridge PCI address: bus 0, device 3, function 0
/// (matches the synthetic PCI tree in devices/bus/pci.rs).
const LPC_ADR: u64 = 0x0003_0000;

pub fn build_body() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(aml::scope("\\_SB", sb_scope()));

    // Sleep states: working (S0) and soft-off (S5). No S3/S4 — a hypervisor
    // platform doesn't implement suspend-to-RAM/disk, and advertising states
    // we can't honour would fail the OS's sleep handshake.
    body.extend(aml::name(
        "\\_S0",
        aml::package(vec![aml::integer(0), aml::integer(0), aml::integer(0), aml::integer(0)]),
    ));
    body.extend(aml::name(
        "\\_S5",
        aml::package(vec![aml::integer(5), aml::integer(0), aml::integer(0), aml::integer(0)]),
    ));

    // _PIC: the OS calls this with Arg0 = interrupt mode (0 = PIC, 1 = APIC).
    // We route statically via _PRT, so we just latch the mode the OS chose
    // into a global — the acknowledgement is what the OS is after.
    body.extend(aml::name("PICM", aml::integer(0)));
    body.extend(aml::method("\\_PIC", 1, false, aml::store(aml::arg(0), "PICM")));

    body
}

fn sb_scope() -> Vec<u8> {
    let mut sb = Vec::new();
    sb.extend(aml::device("PCI0", pci0()));
    sb.extend(aml::device("SYSR", system_resources()));
    sb
}

fn pci0() -> Vec<u8> {
    let mut pci0 = Vec::new();
    pci0.extend(aml::name("_HID", aml::eisaid("PNP0A08"))); // PCIe root
    pci0.extend(aml::name("_CID", aml::eisaid("PNP0A03"))); // PCI root (compat)
    pci0.extend(aml::name("_UID", aml::integer(0)));
    pci0.extend(aml::name("_BBN", aml::integer(0))); // base bus number

    // _CRS: the resource windows the PCI root produces for its children.
    // The 32-bit MMIO window covers the BARs OVMF assigns (0x8000_0000..)
    // and stops below the 0xE000_0000 ECAM base.
    let mut res = Vec::new();
    res.extend(aml::bus_range(0x00, 0x00));
    res.extend(aml::io_range(0x0000, 0x0CF7)); // legacy IO, below the CF8/CFC config pair
    res.extend(aml::io_range(0x0D00, 0xFFFF)); // remaining PCI IO (includes ACPI PM 0x600)
    res.extend(aml::mem32_range(0x8000_0000, 0xDFFF_FFFF));
    pci0.extend(aml::name("_CRS", aml::resource_template(res)));

    // _PRT: PCI INTA-D → IO-APIC GSI routing. Source 0 + a global system
    // interrupt number routes each pin directly to a GSI (16..19).
    let mut entries: Vec<Vec<u8>> = Vec::new();
    for dev in 0u32..=8 {
        for pin in 0u32..4 {
            let gsi = 16 + ((dev + pin) & 3);
            entries.push(aml::package(vec![
                aml::integer(((dev << 16) | 0xFFFF) as u64),
                aml::integer(pin as u64),
                aml::integer(0),
                aml::integer(gsi as u64),
            ]));
        }
    }
    pci0.extend(aml::name("_PRT", aml::package(entries)));

    // _OSC: PCIe feature negotiation. Returning the capabilities buffer
    // (Arg3) unmodified grants the OS full control of every feature it asks
    // for and clears no error bits — correct for a platform whose firmware
    // runs no PCIe management AML of its own.
    pci0.extend(aml::method("_OSC", 4, true, aml::ret(aml::arg(3))));

    pci0.extend(aml::device("SBRG", lpc_bridge()));
    pci0
}

fn lpc_bridge() -> Vec<u8> {
    let mut lpc = Vec::new();
    lpc.extend(aml::name("_ADR", aml::integer(LPC_ADR)));
    lpc.extend(aml::device("PS2K", keyboard()));
    lpc.extend(aml::device("PS2M", mouse()));
    lpc.extend(aml::device("RTC0", rtc()));
    lpc.extend(aml::device("TIMR", pit()));
    lpc.extend(aml::device("SPKR", speaker()));
    lpc.extend(aml::device("COMA", serial()));
    lpc.extend(aml::device("MATH", coprocessor()));
    lpc.extend(aml::device("PICD", pic_8259()));
    lpc.extend(aml::device("DMAD", dma_8237()));
    lpc.extend(aml::device("HPET", hpet()));
    lpc
}

fn keyboard() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(aml::name("_HID", aml::eisaid("PNP0303")));
    d.extend(aml::name("_CID", aml::eisaid("PNP030B")));
    let mut r = Vec::new();
    r.extend(aml::io(0x0060, 1, 1));
    r.extend(aml::io(0x0064, 1, 1));
    r.extend(aml::irq(1));
    d.extend(aml::name("_CRS", aml::resource_template(r)));
    d
}

fn mouse() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(aml::name("_HID", aml::eisaid("PNP0F13"))); // PS/2 port mouse
    let mut r = Vec::new();
    r.extend(aml::irq(12));
    d.extend(aml::name("_CRS", aml::resource_template(r)));
    d
}

fn rtc() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(aml::name("_HID", aml::eisaid("PNP0B00")));
    let mut r = Vec::new();
    r.extend(aml::io(0x0070, 2, 1));
    r.extend(aml::irq(8));
    d.extend(aml::name("_CRS", aml::resource_template(r)));
    d
}

fn pit() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(aml::name("_HID", aml::eisaid("PNP0100")));
    let mut r = Vec::new();
    r.extend(aml::io(0x0040, 4, 1));
    r.extend(aml::irq(0));
    d.extend(aml::name("_CRS", aml::resource_template(r)));
    d
}

fn speaker() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(aml::name("_HID", aml::eisaid("PNP0800")));
    let mut r = Vec::new();
    r.extend(aml::io(0x0061, 1, 1));
    d.extend(aml::name("_CRS", aml::resource_template(r)));
    d
}

fn serial() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(aml::name("_HID", aml::eisaid("PNP0501")));
    d.extend(aml::name("_UID", aml::integer(1)));
    let mut r = Vec::new();
    r.extend(aml::io(0x03F8, 8, 1));
    r.extend(aml::irq(4));
    d.extend(aml::name("_CRS", aml::resource_template(r)));
    d
}

fn coprocessor() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(aml::name("_HID", aml::eisaid("PNP0C04")));
    let mut r = Vec::new();
    r.extend(aml::io(0x00F0, 16, 1));
    r.extend(aml::irq(13));
    d.extend(aml::name("_CRS", aml::resource_template(r)));
    d
}

fn pic_8259() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(aml::name("_HID", aml::eisaid("PNP0000")));
    let mut r = Vec::new();
    r.extend(aml::io(0x0020, 2, 1));
    r.extend(aml::io(0x00A0, 2, 1));
    r.extend(aml::irq(2)); // cascade
    d.extend(aml::name("_CRS", aml::resource_template(r)));
    d
}

fn dma_8237() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(aml::name("_HID", aml::eisaid("PNP0200")));
    let mut r = Vec::new();
    r.extend(aml::io(0x0000, 16, 1));
    r.extend(aml::io(0x0080, 16, 1));
    r.extend(aml::io(0x00C0, 32, 1));
    d.extend(aml::name("_CRS", aml::resource_template(r)));
    d
}

fn hpet() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(aml::name("_HID", aml::eisaid("PNP0103")));
    let mut r = Vec::new();
    r.extend(aml::memory32_fixed(HPET_BASE as u32, 0x400, true));
    d.extend(aml::name("_CRS", aml::resource_template(r)));
    d
}

/// PNP0C02 — reserves the fixed platform MMIO/IO that no enumerable device
/// claims, so the OS PnP arbitrator marks them consumed. HPET (0xFED00000)
/// is deliberately absent: the HPET device above owns it, and a duplicate
/// reservation would read as a resource conflict.
fn system_resources() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(aml::name("_HID", aml::eisaid("PNP0C02")));
    d.extend(aml::name("_UID", aml::integer(1)));
    let mut r = Vec::new();
    r.extend(aml::memory32_fixed(IO_APIC_BASE, 0x1000, true)); // IO-APIC
    r.extend(aml::memory32_fixed(LOCAL_APIC_BASE, 0x1000, true)); // Local APIC
    r.extend(aml::memory32_fixed(TPM_BASE as u32, TPM_SIZE as u32, true)); // TPM CRB
    r.extend(aml::memory32_fixed(IOMMU_MMIO_BASE as u32, IOMMU_MMIO_SIZE as u32, true)); // AMD-Vi
    r.extend(aml::memory32_fixed(super::PCIE_MCFG_BASE as u32, 0x0010_0000, true)); // ECAM, 1 bus
    r.extend(aml::io(0x0600, 0x80, 1)); // ACPI PM register block
    d.extend(aml::name("_CRS", aml::resource_template(r)));
    d
}
