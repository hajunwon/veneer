//! Fill a profile's per-unit `instance` fields from an `Rng`, respecting
//! each component's `spec` constraints (e.g. the MAC uses the NIC's own OUI
//! so the prefix matches the vendor). Run once on NVRAM-miss; the result is
//! then persisted so the guest sees a stable machine across boots.

use super::format;
use super::Rng;
use crate::primitives::{MacStr, ProfileStr, SmbiosShort, UuidStr};
use crate::Profile;

pub fn fill_instance<R: Rng>(p: &mut Profile, rng: &mut R) {
    let uuid = format::uuid(rng);
    p.hardware.system.instance.uuid = UuidStr::from_bytes(&uuid);

    let serial = format::smbios_serial(rng);
    p.hardware.system.instance.serial = SmbiosShort::from_bytes(&serial);

    // MAC within the NIC's own OUI (read the packed spec field unaligned).
    let oui = unsafe { core::ptr::addr_of!(p.hardware.network.spec.oui).read_unaligned() };
    let mac = format::mac(rng, oui);
    p.hardware.network.instance.mac = MacStr::from_bytes(&mac);

    let disk_serial = format::alnum16(rng);
    p.hardware.storage.instance.serial = SmbiosShort::from_bytes(&disk_serial);

    let dimm0 = format::alnum16(rng);
    p.hardware.memory.instance.serial0 = ProfileStr::from_bytes(&dimm0);
    let dimm1 = format::alnum16(rng);
    p.hardware.memory.instance.serial1 = ProfileStr::from_bytes(&dimm1);

    let board_serial = format::smbios_serial(rng);
    p.hardware.board.instance.baseboard_serial = SmbiosShort::from_bytes(&board_serial);
    let chassis_serial = format::smbios_serial(rng);
    p.hardware.board.instance.chassis_serial = SmbiosShort::from_bytes(&chassis_serial);
}
