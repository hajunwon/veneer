//! Emulated hardware presented to the guest.

pub mod irq;
pub mod bus;
pub mod storage;
pub mod iommu;
pub mod tpm;
pub mod acpi_pm;
pub mod kvmclock;
pub mod fwcfg;
pub mod i8042;
pub mod input;
