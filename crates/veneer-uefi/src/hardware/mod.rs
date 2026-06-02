//! Virtual hardware the guest perceives: emulated devices it drives via
//! MMIO/IO/IRQ, plus the static platform tables/identity its firmware reads
//! (ACPI, SMBIOS). The hypervisor drives these to present a machine.

pub mod devices;
pub mod acpi;
pub mod identity;
