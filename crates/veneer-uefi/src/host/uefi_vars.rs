//! Read and log standard UEFI Global variables — SecureBoot, SetupMode,
//! AuditMode, DeployedMode, BootCurrent.
//!
//! These live under `EFI_GLOBAL_VARIABLE_GUID` and are normally set by
//! the host firmware during platform initialisation. Windows uses them
//! to populate `Win32_OperatingSystem.SecureBootState` and similar
//! WMI fields — vgc / Vanguard can query that to decide whether the
//! machine is "secure boot booted".
//!
//! Overriding these at runtime via SetVariable requires authenticated
//! variable updates (PK / KEK / db / dbx cert chain). Without a real
//! Platform Key we cannot legitimately call SetVariable on these
//! protected variables; firmware would reject with EFI_SECURITY_VIOLATION.
//!
//! For substrate work we just *read* the host values and log them. A
//! profile-driven override would have to either:
//!   (a) inject before ExitBootServices using auth variable certs we
//!       generate at first boot (heavy lift), or
//!   (b) hook GuestService GetVariable calls at the SMI / VMM level —
//!       not part of veneer's current scope.

use uefi::cstr16;
use uefi::runtime::{self, VariableVendor};
use uefi::{guid, Status};


const EFI_GLOBAL_VARIABLE: VariableVendor =
    VariableVendor(guid!("8be4df61-93ca-11d2-aa0d-00e098032b8c"));

fn read_byte(name: &uefi::CStr16) -> Option<u8> {
    let mut buf = [0u8; 8];
    match runtime::get_variable(name, &EFI_GLOBAL_VARIABLE, &mut buf) {
        Ok((data, _attr)) if !data.is_empty() => Some(data[0]),
        Ok(_) => None,
        Err(e) => {
            if e.status() != Status::NOT_FOUND {
                sprintln!("[uefi-var] unexpected error reading var: {:?}", e.status());
            }
            None
        }
    }
}

fn read_u16(name: &uefi::CStr16) -> Option<u16> {
    let mut buf = [0u8; 8];
    match runtime::get_variable(name, &EFI_GLOBAL_VARIABLE, &mut buf) {
        Ok((data, _attr)) if data.len() >= 2 => Some(u16::from_le_bytes([data[0], data[1]])),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UefiVarSnapshot {
    pub secure_boot: Option<u8>,
    pub setup_mode: Option<u8>,
    pub audit_mode: Option<u8>,
    pub deployed_mode: Option<u8>,
    pub boot_current: Option<u16>,
}

pub fn snapshot() -> UefiVarSnapshot {
    UefiVarSnapshot {
        secure_boot:   read_byte(cstr16!("SecureBoot")),
        setup_mode:    read_byte(cstr16!("SetupMode")),
        audit_mode:    read_byte(cstr16!("AuditMode")),
        deployed_mode: read_byte(cstr16!("DeployedMode")),
        boot_current:  read_u16(cstr16!("BootCurrent")),
    }
}

pub fn log(snap: &UefiVarSnapshot) {
    let fmt_byte = |b: Option<u8>| -> &'static str {
        match b {
            Some(1) => "1",
            Some(0) => "0",
            Some(_) => "?",
            None    => "-",
        }
    };
    sprintln!(
        "[uefi-var] SecureBoot={} SetupMode={} AuditMode={} DeployedMode={} BootCurrent={:#06X}",
        fmt_byte(snap.secure_boot),
        fmt_byte(snap.setup_mode),
        fmt_byte(snap.audit_mode),
        fmt_byte(snap.deployed_mode),
        snap.boot_current.unwrap_or(0),
    );
}
