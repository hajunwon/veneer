//! SSDT body — processor objects.
//!
//! Real firmware emits one processor object per logical CPU, conventionally
//! in an SSDT generated at boot (the count isn't known until the platform is
//! enumerated). The OS matches each object to its MADT entry by `_UID`, then
//! attaches the processor power/performance driver. With no processor objects
//! the OS still runs but can't associate per-CPU ACPI state, which some
//! configurations treat as a malformed namespace.
//!
//! We use the ACPI 6.0 form — `Device` with `_HID "ACPI0007"` — rather than
//! the deprecated `Processor()` operator.

extern crate alloc;
use alloc::format;
use alloc::vec::Vec;

use super::aml;

/// Build `Scope(\_SB){ Device(Pnnn){ _HID "ACPI0007"; _UID n } … }` for
/// `n_vcpus` CPUs. `_UID`s are 0..n to match the MADT processor UIDs.
pub fn build_body(n_vcpus: usize) -> Vec<u8> {
    let mut sb = Vec::new();
    for uid in 0..n_vcpus.min(16) {
        let mut p = Vec::new();
        p.extend(aml::name("_HID", aml::string("ACPI0007")));
        p.extend(aml::name("_UID", aml::integer(uid as u64)));
        let name = format!("P{:03X}", uid);
        sb.extend(aml::device(&name, p));
    }
    aml::scope("\\_SB", sb)
}
