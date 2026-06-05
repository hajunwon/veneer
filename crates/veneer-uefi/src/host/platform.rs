//! UEFI implementation of the VMM core's `Platform` seam: page allocation,
//! stall, and MP/AP services via UEFI Boot Services + MP Services Protocol.
//! Installed once at boot so the (UEFI-free) core can reach the environment.

use core::ffi::c_void;
use core::ptr::NonNull;
use core::time::Duration;

use uefi::boot::{self, AllocateType, MemoryType};
use uefi::proto::pi::mp::MpServices;
use veneer_vmm::platform::Platform;

pub struct UefiPlatform;

pub static UEFI_PLATFORM: UefiPlatform = UefiPlatform;

impl Platform for UefiPlatform {
    fn alloc_pages(&self, pages: usize) -> Result<NonNull<u8>, ()> {
        boot::allocate_pages(AllocateType::AnyPages, MemoryType::RUNTIME_SERVICES_DATA, pages)
            .map_err(|_| ())
    }

    fn stall(&self, micros: usize) {
        boot::stall(micros);
    }

    fn mp_processor_count(&self) -> Result<(usize, usize), ()> {
        let mp = open_mp()?;
        let c = mp.get_number_of_processors().map_err(|_| ())?;
        Ok((c.total, c.enabled))
    }

    fn mp_who_am_i(&self) -> Result<usize, ()> {
        let mp = open_mp()?;
        mp.who_am_i().map_err(|_| ())
    }

    fn mp_startup_all_aps(
        &self,
        entry: extern "efiapi" fn(*mut c_void),
        arg: *mut c_void,
        timeout_secs: u64,
    ) -> Result<(), ()> {
        let mp = open_mp()?;
        mp.startup_all_aps(false, entry, arg, None, Some(Duration::from_secs(timeout_secs)))
            .map_err(|_| ())
    }
}

fn open_mp() -> Result<boot::ScopedProtocol<MpServices>, ()> {
    let handle = boot::get_handle_for_protocol::<MpServices>().map_err(|_| ())?;
    boot::open_protocol_exclusive::<MpServices>(handle).map_err(|_| ())
}
