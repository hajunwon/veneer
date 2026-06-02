//! UEFI Variable (NVRAM) read/write for VeneerProfile and VeneerConfig.
//!
//! On-disk format is the raw `repr(C, packed)` bytes of `Profile` /
//! `Config`. Magic + version in the header lets us reject stale layouts
//! from previous veneer releases.
//!
//! VMware Workstation stores UEFI variables in the VM's `.nvram` file,
//! which persists across reboots unless the VM is reverted to a
//! snapshot taken before the variable was written.

use core::mem::size_of;

use uefi::cstr16;
use uefi::runtime::{
    self, VariableAttributes, VariableVendor,
};
use uefi::{guid, Status};

use crate::config::{Config, VENEER_NVRAM_GUID};
use crate::identity::profile::Profile;

/// Vendor GUID used for every veneer NVRAM variable.
const VENDOR: VariableVendor = VariableVendor(guid!("c0ffeec0-ffee-beef-0000-000000000001"));

/// `NV | BS | RT` — persistent + readable during both boot and runtime.
fn full_attributes() -> VariableAttributes {
    VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS
}

// ───── Profile ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum NvramError {
    /// Variable wasn't present (first boot, deleted, snapshot reverted).
    NotFound,
    /// Variable exists but its size/magic/version doesn't match the
    /// current Profile/Config layout — treat as missing, regenerate.
    LayoutMismatch,
    /// Firmware refused the read/write (read-only NVRAM, security
    /// violation, out of space, etc.).
    Firmware(Status),
}

const PROFILE_BUF_CAP: usize = 4096; // UEFI per-variable cap on most firmware

pub fn load_profile() -> Result<Profile, NvramError> {
    let mut buf = [0u8; PROFILE_BUF_CAP];
    let (data, _attr) = runtime::get_variable(cstr16!("VeneerProfile"), &VENDOR, &mut buf)
        .map_err(|e| match e.status() {
            Status::NOT_FOUND => NvramError::NotFound,
            s => NvramError::Firmware(s),
        })?;

    if data.len() != size_of::<Profile>() {
        return Err(NvramError::LayoutMismatch);
    }
    // SAFETY: Profile is `repr(C, packed)`; any byte sequence of the
    // right length is a valid Profile bitwise. Magic/version check
    // afterwards rejects stale layouts.
    let mut p = Profile::empty();
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            &mut p as *mut Profile as *mut u8,
            size_of::<Profile>(),
        );
    }
    if !p.is_valid() {
        return Err(NvramError::LayoutMismatch);
    }
    Ok(p)
}

pub fn save_profile(p: &Profile) -> Result<(), NvramError> {
    let bytes = unsafe {
        core::slice::from_raw_parts(p as *const Profile as *const u8, size_of::<Profile>())
    };
    runtime::set_variable(cstr16!("VeneerProfile"), &VENDOR, full_attributes(), bytes)
        .map_err(|e| NvramError::Firmware(e.status()))
}

pub fn delete_profile() -> Result<(), NvramError> {
    runtime::delete_variable(cstr16!("VeneerProfile"), &VENDOR)
        .map_err(|e| NvramError::Firmware(e.status()))
}

// ───── Config ───────────────────────────────────────────────────────────

const CONFIG_BUF_CAP: usize = 1024;

pub fn load_config() -> Result<Config, NvramError> {
    let mut buf = [0u8; CONFIG_BUF_CAP];
    let (data, _attr) = runtime::get_variable(cstr16!("VeneerConfig"), &VENDOR, &mut buf)
        .map_err(|e| match e.status() {
            Status::NOT_FOUND => NvramError::NotFound,
            s => NvramError::Firmware(s),
        })?;

    if data.len() != size_of::<Config>() {
        return Err(NvramError::LayoutMismatch);
    }
    let mut c = crate::config::DEFAULT;
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            &mut c as *mut Config as *mut u8,
            size_of::<Config>(),
        );
    }
    if !c.is_valid() {
        return Err(NvramError::LayoutMismatch);
    }
    Ok(c)
}

pub fn save_config(c: &Config) -> Result<(), NvramError> {
    let bytes = unsafe {
        core::slice::from_raw_parts(c as *const Config as *const u8, size_of::<Config>())
    };
    runtime::set_variable(cstr16!("VeneerConfig"), &VENDOR, full_attributes(), bytes)
        .map_err(|e| NvramError::Firmware(e.status()))
}

pub fn delete_config() -> Result<(), NvramError> {
    runtime::delete_variable(cstr16!("VeneerConfig"), &VENDOR)
        .map_err(|e| NvramError::Firmware(e.status()))
}

// Touch the constant so unused-import lint stays clean in builds that
// disable some intercepts — the layout literal is the source of truth.
#[allow(dead_code)]
const _GUID_BYTES: [u8; 16] = VENEER_NVRAM_GUID;
