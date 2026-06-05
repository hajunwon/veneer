//! Host pointer capture → emulated PS/2 mouse (8042 aux port).
//!
//! Source is the standard UEFI Simple Pointer protocol, which reports relative
//! motion (in counts, scaled by the device's counts/mm resolution) and button
//! state. We drain every pending sample each poll and *accumulate* the motion,
//! then emit one coalesced 3-byte PS/2 packet per guest-configured sample
//! interval (default 100 Hz). A real PS/2 mouse reports at its sample rate, not
//! per host-poll — emitting on every poll (~500 Hz) floods the small aux FIFO,
//! which drops packets and makes the cursor stutter.
//!
//! The protocol interface is cached (firmware-resident, never closed) so each
//! poll is a direct GetState with no re-open cost.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, AtomicU64, Ordering};

use uefi::proto::console::pointer::Pointer;

use veneer_vmm::hardware::devices::i8042;

/// All SimplePointer interfaces VMware exposes (e.g. PS/2 mouse + USB tablet).
/// We read from every one and merge, so whichever the host is delivering
/// motion through is caught regardless of which is "first".
const MAX_PTRS: usize = 4;
#[allow(clippy::declare_interior_mutable_const)]
const NULL_PTR: AtomicPtr<Pointer> = AtomicPtr::new(core::ptr::null_mut());
static PTRS: [AtomicPtr<Pointer>; MAX_PTRS] = [NULL_PTR; MAX_PTRS];
static TRIED: AtomicBool = AtomicBool::new(false);
static RES_X: AtomicU32 = AtomicU32::new(0);
static RES_Y: AtomicU32 = AtomicU32::new(0);

// Accumulated motion (device counts) + latest button state between emits.
static ACC_X: AtomicI32 = AtomicI32::new(0);
static ACC_Y: AtomicI32 = AtomicI32::new(0);
static BTN_L: AtomicBool = AtomicBool::new(false);
static BTN_R: AtomicBool = AtomicBool::new(false);
static LAST_BTN_L: AtomicBool = AtomicBool::new(false);
static LAST_BTN_R: AtomicBool = AtomicBool::new(false);
static LAST_EMIT: AtomicU64 = AtomicU64::new(0);

/// Open every SimplePointer handle once, caching the raw interfaces (firmware
/// resident, never closed). Returns how many were opened.
fn init_pointers() {
    if TRIED.swap(true, Ordering::Relaxed) {
        return;
    }
    const POINTER_GUID: uefi::Guid = uefi::guid!("31878c87-0b75-11d5-9a4f-0090273fc14d");
    let Ok(handles) =
        uefi::boot::locate_handle_buffer(uefi::boot::SearchType::ByProtocol(&POINTER_GUID))
    else {
        return;
    };
    // GetProtocol (not Exclusive): exclusive-open makes the firmware disconnect
    // the driver that actually pumps the hardware mouse into the SimplePointer,
    // so GetState then returns nothing. We only peek the state, so open shared.
    let agent = uefi::boot::image_handle();
    let mut slot = 0;
    for &handle in handles.iter() {
        if slot >= MAX_PTRS {
            break;
        }
        let params = uefi::boot::OpenProtocolParams { handle, agent, controller: None };
        let scoped = match unsafe {
            uefi::boot::open_protocol::<Pointer>(params, uefi::boot::OpenProtocolAttributes::GetProtocol)
        } {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut scoped = scoped;
        let m = scoped.mode();
        if RES_X.load(Ordering::Relaxed) == 0 {
            RES_X.store(m.resolution[0] as u32, Ordering::Relaxed);
            RES_Y.store(m.resolution[1] as u32, Ordering::Relaxed);
        }
        let raw = &mut *scoped as *mut Pointer;
        core::mem::forget(scoped); // keep the interface pointer valid for the run
        PTRS[slot].store(raw, Ordering::Relaxed);
        slot += 1;
    }
}

/// Target PS/2 resolution (counts/mm at the wire). Windows applies its own
/// pointer acceleration on top.
const TARGET_COUNTS_PER_MM: i32 = 8;

fn rescale(delta: i32, res_counts_per_mm: u32) -> i32 {
    if res_counts_per_mm == 0 {
        return delta;
    }
    let div = (res_counts_per_mm as i32 / TARGET_COUNTS_PER_MM).max(1);
    delta / div
}

/// Drain + accumulate pending pointer motion, then emit one coalesced PS/2
/// packet per guest sample interval.
pub fn poll() {
    init_pointers();
    let hz = veneer_vmm::infra::clock::tsc_freq::host_tsc_freq();
    let now = veneer_vmm::infra::clock::now();

    // Drain every SimplePointer interface, accumulating motion + buttons.
    for slot in 0..MAX_PTRS {
        let p = PTRS[slot].load(Ordering::Relaxed);
        if p.is_null() {
            continue;
        }
        let pp = unsafe { &mut *p };
        let mut drained = 0u32;
        while drained < 64 {
            drained += 1;
            let Ok(Some(state)) = pp.read_state() else { break };
            ACC_X.fetch_add(state.relative_movement[0], Ordering::Relaxed);
            ACC_Y.fetch_add(state.relative_movement[1], Ordering::Relaxed);
            BTN_L.store(state.button[0], Ordering::Relaxed);
            BTN_R.store(state.button[1], Ordering::Relaxed);
        }
    }

    // Emit one coalesced packet per guest sample interval. inject_mouse_packet
    // is the authority on whether reporting (0xF4) is on.
    let rate = i8042::mouse_sample_rate().clamp(20, 250) as u64;
    let interval = (hz / rate).max(1);
    let last = LAST_EMIT.load(Ordering::Relaxed);
    if last != 0 && now.wrapping_sub(last) < interval {
        return;
    }
    LAST_EMIT.store(now, Ordering::Relaxed);

    let dx = rescale(ACC_X.swap(0, Ordering::Relaxed), RES_X.load(Ordering::Relaxed));
    let dy = rescale(ACC_Y.swap(0, Ordering::Relaxed), RES_Y.load(Ordering::Relaxed));
    let l = BTN_L.load(Ordering::Relaxed);
    let r = BTN_R.load(Ordering::Relaxed);
    let prev_l = LAST_BTN_L.swap(l, Ordering::Relaxed);
    let prev_r = LAST_BTN_R.swap(r, Ordering::Relaxed);
    let btn_changed = prev_l != l || prev_r != r;

    if dx != 0 || dy != 0 || btn_changed {
        i8042::inject_mouse_packet(dx, dy, l, r, false);
    }
}
