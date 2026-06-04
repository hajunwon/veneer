//! Host input bridge — captures the host UEFI keyboard + pointer and feeds the
//! emulated 8042 (keyboard on IRQ1, mouse on IRQ12).
//!
//! Reachable because this guest path never calls ExitBootServices, so the host
//! firmware's console + pointer protocols stay live between VMEXITs. `poll()`
//! is invoked every VMRUN iteration and self-paces off the virtual clock, so
//! input latency is decoupled from how often the loop spins (at guest idle,
//! exits are sparse — an iteration-count gate stretched latency to seconds).

pub mod keyboard;
pub mod mouse;

use core::sync::atomic::{AtomicU64, Ordering};

static LAST_POLL: AtomicU64 = AtomicU64::new(0);

/// Poll rate (Hz). The firmware key/pointer reads are cheap (~2 µs when idle),
/// so polling fast is affordable; the host pointer's own ~20 Hz update rate is
/// the real cap on pointer smoothness, not this.
const POLL_HZ: u64 = 1000;

/// Drain host keyboard + pointer into the emulated 8042, self-paced to POLL_HZ.
pub fn poll() {
    let now = crate::infra::clock::now();
    let interval = (crate::infra::clock::tsc_freq::host_tsc_freq() / POLL_HZ).max(1);
    let last = LAST_POLL.load(Ordering::Relaxed);
    if last != 0 && now.wrapping_sub(last) < interval {
        return;
    }
    LAST_POLL.store(now, Ordering::Relaxed);
    keyboard::poll();
    mouse::poll();
}

/// One-shot report of the host input sources VMware's OVMF exposes, logged
/// during init so the pipeline is built on confirmed protocols.
pub fn probe() {
    use uefi::boot::{self, SearchType};
    use uefi::proto::console::pointer::Pointer;

    match boot::get_handle_for_protocol::<Pointer>() {
        Ok(h) => match boot::open_protocol_exclusive::<Pointer>(h) {
            Ok(p) => {
                let m = p.mode();
                crate::sprintln!(
                    "[input-probe] SimplePointer PRESENT: resolution={:?} buttons={:?}",
                    m.resolution, m.has_button
                );
            }
            Err(e) => crate::sprintln!("[input-probe] SimplePointer present but open failed: {:?}", e),
        },
        Err(_) => crate::sprintln!("[input-probe] SimplePointer: NONE"),
    }

    const TEXT_INPUT_EX_GUID: uefi::Guid = uefi::guid!("dd9e7534-7762-4698-8c14-f58517a625aa");
    match boot::locate_handle_buffer(SearchType::ByProtocol(&TEXT_INPUT_EX_GUID)) {
        Ok(buf) => crate::sprintln!("[input-probe] SimpleTextInputEx PRESENT: {} handle(s)", buf.len()),
        Err(_) => crate::sprintln!("[input-probe] SimpleTextInputEx: NONE"),
    }
}
