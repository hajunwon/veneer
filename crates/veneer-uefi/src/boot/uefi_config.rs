//! UEFI Configuration Table registration.
//!
//! The guest OS finds ACPI / SMBIOS via two well-known GUIDs in the UEFI
//! System Table's ConfigurationTable array. Install our synthesised tables
//! under those GUIDs and any guest that uses the standard EFI lookup path
//! (Windows boot loader, Linux kernel, anything that calls
//! `LocateProtocol`/`GetEfiConfigurationTable`) gets pointed at us.

use uefi::Guid;
use uefi::guid;

pub const EFI_ACPI_20_TABLE_GUID:  Guid = guid!("8868e871-e4f1-11d3-bc22-0080c73c8881");
pub const EFI_ACPI_10_TABLE_GUID:  Guid = guid!("eb9d2d30-2d88-11d3-9a16-0090273fc14d");
pub const EFI_SMBIOS_TABLE_GUID:   Guid = guid!("eb9d2d31-2d88-11d3-9a16-0090273fc14d");
pub const EFI_SMBIOS3_TABLE_GUID:  Guid = guid!("f2fd1544-9794-4a2c-992e-e5bbcf20e394");

/// Install or update a single configuration-table entry.
///
/// SAFETY: caller guarantees `table_phys` points at a valid, lifetime-stable
/// structure of the type implied by `guid`.
pub unsafe fn install(guid: &'static Guid, table_phys: u64) -> Result<(), uefi::Error> {
    let ptr = table_phys as *const core::ffi::c_void;
    unsafe { uefi::boot::install_configuration_table(guid, ptr) }
}
