//! Read `profile.toml` / `config.toml` from the ESP we booted off.
//!
//! UEFI hands us the LoadedImage protocol; from there we walk to the
//! SimpleFileSystem on the same device and open the root volume. Files
//! land in a caller-supplied buffer so callers can size the cap they're
//! willing to spend on TOML text (typical files are 1-2 KiB).

use uefi::boot;
use uefi::cstr16;
use uefi::proto::media::file::{File, FileAttribute, FileMode, FileType, RegularFile};
use uefi::CStr16;

#[derive(Debug)]
pub enum EspError {
    /// LoadedImage / SimpleFileSystem couldn't be opened — boot media
    /// isn't a regular FAT ESP (e.g. PXE / RAM disk boot).
    NoFs,
    /// The requested path doesn't exist on the ESP.
    NotFound,
    /// File exists but isn't a regular file (directory etc).
    NotRegular,
    /// File is bigger than the caller's buffer.
    BufferTooSmall,
    /// Firmware reported an unexpected error.
    Io,
}

/// Load `path` (absolute path within the ESP, e.g.
/// `\EFI\BOOT\profile.toml`) into `buf`. Returns the number of bytes
/// actually read. Reading short files only — no chunked loop because
/// our schema fits in well under 4 KiB.
pub fn load_into(path: &CStr16, buf: &mut [u8]) -> Result<usize, EspError> {
    let image_handle = boot::image_handle();
    let mut fs = boot::get_image_file_system(image_handle).map_err(|_| EspError::NoFs)?;
    let mut root = fs.open_volume().map_err(|_| EspError::Io)?;

    let handle = match root.open(path, FileMode::Read, FileAttribute::empty()) {
        Ok(h) => h,
        Err(e) if e.status() == uefi::Status::NOT_FOUND => return Err(EspError::NotFound),
        Err(_) => return Err(EspError::Io),
    };
    let mut file = match handle.into_type().map_err(|_| EspError::Io)? {
        FileType::Regular(f) => f,
        FileType::Dir(_) => return Err(EspError::NotRegular),
    };

    let n = match RegularFile::read(&mut file, buf) {
        Ok(n) => n,
        Err(_) => return Err(EspError::BufferTooSmall),
    };
    Ok(n)
}

pub const PROFILE_TOML_PATH: &CStr16 = cstr16!("\\EFI\\BOOT\\profile.toml");
pub const CONFIG_TOML_PATH: &CStr16 = cstr16!("\\EFI\\BOOT\\config.toml");
