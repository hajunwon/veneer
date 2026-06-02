//! Chain-load Alpine Linux (EFI-stub vmlinuz) from our own ESP for
//! external validation of veneer's firmware surface from a real OS
//! guest.
//!
//! Architecture:
//!   1) Read \vmlinuz-lts  + \initramfs-lts from the ESP we booted from.
//!   2) Install an `EFI_LOAD_FILE2_PROTOCOL` on a fresh handle, with
//!      a `LINUX_EFI_INITRD_MEDIA_GUID` Vendor Media device path.
//!      Linux >= 5.7 EFI-stub looks this up via LocateHandleBuffer
//!      and calls our `LoadFile` callback to copy the initramfs into
//!      the kernel's buffer. This is how systemd-boot / rEFInd /
//!      GRUB EFI all deliver initramfs to modern kernels.
//!   3) LoadImage(vmlinuz) + set kernel cmdline as LoadOptions +
//!      StartImage. EFI-stub takes over from there.
//!
//! We deliberately don't chain CDROM ISOs -- VMware's UEFI ISO9660
//! SimpleFileSystem driver hangs on the first directory read.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use uefi::boot::{self, EventType, LoadImageSource, MemoryType, Tpl};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode, FileType, RegularFile};
use uefi::{cstr16, guid, Event, Guid, Handle, Status};
use core::ptr::NonNull;

use crate::sprintln;

const KERNEL_PATH: &uefi::CStr16 = cstr16!("\\vmlinuz-lts");
const INITRD_PATH: &uefi::CStr16 = cstr16!("\\initramfs-lts");

/// Alpine LTS bzImage is ~14 MiB. Cap at 32 MiB.
const MAX_KERNEL_BYTES: usize = 32 * 1024 * 1024;
/// Alpine LTS initramfs (stock + our overlay) is ~22 MiB. Cap at 64 MiB.
const MAX_INITRD_BYTES: usize = 64 * 1024 * 1024;

const KERNEL_CMDLINE: &str =
    "earlycon=uart,io,0x3f8,115200n8 \
     console=ttyS0,115200 console=tty0 \
     efi=debug loglevel=8 initcall_debug printk.devkmsg=on \
     panic=10 nokaslr \
     modules=loop,squashfs,sd-mod,usb-storage";

// EFI_LOAD_FILE2_PROTOCOL_GUID = 4006c0c1-fcb3-403e-996d-4a6c8724e06d
const EFI_LOAD_FILE2_PROTOCOL_GUID: Guid = guid!("4006c0c1-fcb3-403e-996d-4a6c8724e06d");
// EFI_DEVICE_PATH_PROTOCOL_GUID
const EFI_DEVICE_PATH_PROTOCOL_GUID: Guid = guid!("09576e91-6d3f-11d2-8e39-00a0c969723b");
// LINUX_EFI_INITRD_MEDIA_GUID (Vendor Media GUID Linux EFI-stub probes)
const LINUX_EFI_INITRD_MEDIA_GUID_BYTES: [u8; 16] = [
    0x27, 0xe4, 0x68, 0x55, 0xfc, 0x68, 0x3d, 0x4f,
    0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68,
];

// ---- LoadFile2 vtable + device path ----------------------------------------

#[repr(C)]
struct LoadFile2Protocol {
    load_file: unsafe extern "efiapi" fn(
        this: *mut LoadFile2Protocol,
        file_path: *const c_void,
        boot_policy: bool,
        buffer_size: *mut usize,
        buffer: *mut c_void,
    ) -> Status,
}

#[repr(C, packed)]
struct InitrdDevicePath {
    /// Vendor Media node (Type 4, SubType 3, length 20)
    vendor_type: u8,
    vendor_subtype: u8,
    vendor_length: u16,
    vendor_guid: [u8; 16],
    /// End of Hardware Path (Type 0x7F, SubType 0xFF, length 4)
    end_type: u8,
    end_subtype: u8,
    end_length: u16,
}

static INITRD_DEVICE_PATH: InitrdDevicePath = InitrdDevicePath {
    vendor_type: 4,         // MEDIA_DEVICE_PATH
    vendor_subtype: 3,      // MEDIA_VENDOR_DP
    vendor_length: 20,
    vendor_guid: LINUX_EFI_INITRD_MEDIA_GUID_BYTES,
    end_type: 0x7F,         // END_DEVICE_PATH_TYPE
    end_subtype: 0xFF,      // END_ENTIRE_DEVICE_PATH_SUBTYPE
    end_length: 4,
};

static INITRD_PROTOCOL: LoadFile2Protocol = LoadFile2Protocol {
    load_file: load_initrd_callback,
};

// initramfs bytes are leaked into 'static at load time; the callback
// just reads ptr/len from these atomics. No locking needed because we
// only install the protocol after the bytes are in place.
static INITRD_PTR: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static INITRD_LEN: AtomicUsize = AtomicUsize::new(0);

unsafe extern "efiapi" fn load_initrd_callback(
    _this: *mut LoadFile2Protocol,
    _file_path: *const c_void,
    boot_policy: bool,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    let provided = if buffer_size.is_null() { 0 } else { unsafe { *buffer_size } };
    sprintln!(
        "[initrd] callback: bp={} buffer_size@{:p}={} buffer={:p}",
        boot_policy as u8, buffer_size, provided, buffer
    );
    // Spec: LoadFile2 must reject BootPolicy=TRUE (that's LoadFile's domain).
    if boot_policy {
        sprintln!("[initrd]   reject: boot_policy=TRUE");
        return Status::UNSUPPORTED;
    }
    let ptr = INITRD_PTR.load(Ordering::Acquire);
    let len = INITRD_LEN.load(Ordering::Acquire);
    if ptr.is_null() || len == 0 {
        sprintln!("[initrd]   NOT_FOUND: ptr={:p} len={}", ptr, len);
        return Status::NOT_FOUND;
    }
    if buffer_size.is_null() {
        sprintln!("[initrd]   INVALID_PARAMETER: buffer_size null");
        return Status::INVALID_PARAMETER;
    }
    if buffer.is_null() || provided < len {
        unsafe { *buffer_size = len };
        sprintln!("[initrd]   BUFFER_TOO_SMALL: report need={}", len);
        return Status::BUFFER_TOO_SMALL;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(ptr, buffer as *mut u8, len);
        *buffer_size = len;
    }
    sprintln!("[initrd]   SUCCESS: copied {} bytes to {:p}", len, buffer);
    Status::SUCCESS
}

// ExitBootServices notification — fires the instant EFI-stub invokes
// ExitBootServices(). Writes to 8250 IO directly (no BootServices calls
// allowed at TPL_NOTIFY). If we never see this line in serial.log,
// EFI-stub is hanging before ExitBootServices.
unsafe extern "efiapi" fn on_exit_boot_services(
    _event: Event,
    _context: Option<NonNull<core::ffi::c_void>>,
) {
    sprintln!("[ebs ] ExitBootServices fired -- BootServices about to vanish");
}

// ---- public entry point ----------------------------------------------------

pub fn try_chain_load() -> bool {
    let our_image_handle = boot::image_handle();
    sprintln!("[chain] reading Alpine vmlinuz + initramfs from own ESP");

    let mut fs = match boot::get_image_file_system(our_image_handle) {
        Ok(f) => f,
        Err(e) => {
            sprintln!("[chain] get_image_file_system failed: {:?}", e.status());
            return false;
        }
    };
    let mut root = match fs.open_volume() {
        Ok(r) => r,
        Err(e) => {
            sprintln!("[chain] open_volume failed: {:?}", e.status());
            return false;
        }
    };

    let vmlinuz = match read_file_at(&mut root, KERNEL_PATH, MAX_KERNEL_BYTES) {
        Ok(b) => b,
        Err(reason) => {
            sprintln!("[chain] vmlinuz: {} -- run tools/build_alpine_overlay.py + make_disk.py", reason);
            return false;
        }
    };
    sprintln!("[chain] vmlinuz : {} bytes", vmlinuz.len());

    let initramfs = match read_file_at(&mut root, INITRD_PATH, MAX_INITRD_BYTES) {
        Ok(b) => b,
        Err(reason) => {
            sprintln!("[chain] initramfs: {}", reason);
            return false;
        }
    };
    sprintln!("[chain] initrd  : {} bytes", initramfs.len());

    if let Err(e) = install_initrd_loader(initramfs) {
        sprintln!("[chain] install_initrd_loader failed: {}", e);
        return false;
    }
    sprintln!(
        "[chain] InitrdLoadFile2 installed: stored ptr={:p} len={}",
        INITRD_PTR.load(Ordering::Acquire),
        INITRD_LEN.load(Ordering::Acquire),
    );

    // Tap EFI's ExitBootServices event so we can prove (or disprove)
    // that the Linux EFI-stub got that far. The callback can't use
    // BootServices (TPL=NOTIFY is raised), but our sprintln writes
    // 8250 IO directly, so it's safe.
    unsafe {
        match boot::create_event(
            EventType::SIGNAL_EXIT_BOOT_SERVICES,
            Tpl::NOTIFY,
            Some(on_exit_boot_services),
            None,
        ) {
            Ok(_ev) => sprintln!("[chain] ExitBootServices event hook installed"),
            Err(e)  => sprintln!("[chain] ExitBootServices hook FAILED: {:?}", e.status()),
        }
    }

    let img = match boot::load_image(
        our_image_handle,
        LoadImageSource::FromBuffer {
            buffer: &vmlinuz,
            file_path: None,
        },
    ) {
        Ok(h) => h,
        Err(e) => {
            sprintln!("[chain] LoadImage(vmlinuz) failed: {:?}", e.status());
            return false;
        }
    };

    if let Err(e) = set_kernel_cmdline(img) {
        sprintln!("[chain] set_kernel_cmdline failed: {}", e);
        return false;
    }
    sprintln!("[chain] cmdline set ({} chars)", KERNEL_CMDLINE.len());

    sprintln!("[chain] StartImage -- handing off to Linux EFI-stub");
    let _ = boot::start_image(img);
    sprintln!("[chain] StartImage returned -- kernel exited (unexpected)");
    true
}

// ---- helpers ---------------------------------------------------------------

fn install_initrd_loader(data: Vec<u8>) -> Result<(), &'static str> {
    // Leak into 'static. We won't ever free this -- the OS we hand
    // off to inherits the whole UEFI memory map anyway.
    let boxed: Box<[u8]> = data.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::leak(boxed).as_mut_ptr();

    INITRD_PTR.store(ptr, Ordering::Release);
    INITRD_LEN.store(len, Ordering::Release);

    // Install LoadFile2 on a fresh handle, then add DevicePath to the
    // same handle. EFI-stub looks up handles by DevicePath GUID match.
    let handle = unsafe {
        boot::install_protocol_interface(
            None,
            &EFI_LOAD_FILE2_PROTOCOL_GUID,
            &INITRD_PROTOCOL as *const _ as *const c_void,
        )
    }
    .map_err(|_| "install LoadFile2 failed")?;

    unsafe {
        boot::install_protocol_interface(
            Some(handle),
            &EFI_DEVICE_PATH_PROTOCOL_GUID,
            &INITRD_DEVICE_PATH as *const _ as *const c_void,
        )
    }
    .map_err(|_| "install DevicePath failed")?;

    Ok(())
}

fn set_kernel_cmdline(img: Handle) -> Result<(), &'static str> {
    let mut li = boot::open_protocol_exclusive::<LoadedImage>(img)
        .map_err(|_| "open_protocol_exclusive<LoadedImage> failed")?;

    let mut cmd: Vec<u16> = KERNEL_CMDLINE.encode_utf16().collect();
    cmd.push(0);
    let bytes_len = cmd.len() * 2;

    let pool_ptr = boot::allocate_pool(MemoryType::LOADER_DATA, bytes_len)
        .map_err(|_| "allocate_pool failed")?;
    unsafe {
        core::ptr::copy_nonoverlapping(
            cmd.as_ptr() as *const u8,
            pool_ptr.as_ptr(),
            bytes_len,
        );
        li.set_load_options(pool_ptr.as_ptr(), bytes_len as u32);
    }
    Ok(())
}

pub fn read_file_at(
    root: &mut uefi::proto::media::file::Directory,
    path: &uefi::CStr16,
    max: usize,
) -> Result<Vec<u8>, &'static str> {
    let file_handle = root
        .open(path, FileMode::Read, FileAttribute::empty())
        .map_err(|_| "not found")?;
    let mut file = match file_handle
        .into_type()
        .map_err(|_| "into_type failed")?
    {
        FileType::Regular(f) => f,
        FileType::Dir(_) => return Err("entry is a directory"),
    };
    let mut info_buf = [0u8; 512];
    let info: &FileInfo = file
        .get_info::<FileInfo>(&mut info_buf)
        .map_err(|_| "get_info failed")?;
    let size = info.file_size() as usize;
    if size == 0 || size > max {
        return Err("implausible size");
    }
    let mut buf = vec![0u8; size];
    RegularFile::read(&mut file, &mut buf).map_err(|_| "read failed")?;
    Ok(buf)
}
