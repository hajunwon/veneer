//! Synthetic SMBIOS tables — fake "system information" the guest sees.
//!
//! Coverage (SMBIOS 2.8):
//!   - Type 0  BIOS Information
//!   - Type 1  System Information
//!   - Type 2  Baseboard
//!   - Type 3  System Enclosure / Chassis
//!   - Type 4  Processor (cache-handle-linked)
//!   - Type 7  Cache Information × 3 (L1, L2, L3)
//!   - Type 9  System Slots × 2 (PCIe x16, M.2)
//!   - Type 16 Physical Memory Array
//!   - Type 17 Memory Device × 2 (16 GiB DDR5 × 2 = 32 GiB)
//!   - Type 19 Memory Array Mapped Address
//!   - Type 20 Memory Device Mapped Address × 2
//!   - Type 32 System Boot Information
//!   - Type 127 End-of-Table
//!
//! UEFI exposes the SMBIOS entry-point physical address via the
//! `EFI_SMBIOS_TABLE_GUID` configuration table entry.


use crate::hardware::identity::active;
use crate::hardware::identity::profile::ProfileStr;

pub const ENTRY_POINT_LEN: u8 = 0x1F;
const ENTRY_POINT_INTERMEDIATE: &[u8; 5] = b"_DMI_";

// Handle namespace — each structure has a unique 16-bit handle so other
// structures can reference it. Keep them grouped logically.
mod handle {
    pub const BIOS: u16        = 0x0000;
    pub const SYSTEM: u16      = 0x0001;
    pub const BASEBOARD: u16   = 0x0002;
    pub const CHASSIS: u16     = 0x0003;
    pub const PROCESSOR: u16   = 0x0004;
    pub const CACHE_L1: u16    = 0x0701;
    pub const CACHE_L2: u16    = 0x0702;
    pub const CACHE_L3: u16    = 0x0703;
    pub const SLOT_PCIE: u16   = 0x0901;
    pub const SLOT_M2: u16     = 0x0902;
    pub const MEM_ARRAY: u16   = 0x1000;
    pub const MEM_DEV0: u16    = 0x1001;
    pub const MEM_DEV1: u16    = 0x1002;
    pub const MEM_AMAP: u16    = 0x1300;
    pub const MEM_DMAP0: u16   = 0x1401;
    pub const MEM_DMAP1: u16   = 0x1402;
    pub const BOOT_INFO: u16   = 0x2000;
    pub const END_OF_TABLE: u16 = 0x7F00;
}

// Fallback strings used only when the active profile slot is empty. These
// must NOT watermark the hypervisor — "VENEER"/"Veneer..." was a dead
// giveaway. Use the generic placeholders a real unconfigured OEM board
// ships with (AMI default DMI strings).
const FB_MANUFACTURER: &[u8] = b"To Be Filled By O.E.M.";
const FB_PRODUCT: &[u8] = b"To Be Filled By O.E.M.";
const FB_VERSION: &[u8] = b"To Be Filled By O.E.M.";
const FB_SERIAL: &[u8] = b"To Be Filled By O.E.M.";
const FB_SKU: &[u8] = b"To Be Filled By O.E.M.";
const FB_FAMILY: &[u8] = b"To Be Filled By O.E.M.";

// Memory per-DIMM fallbacks (used only when the active profile leaves the
// memory fields 0). 16 GiB DDR5-5200 per DIMM — the total and device count
// are now derived from the profile at build time (Type 16/17/19/20).
const DIMM_SIZE_MB: u16 = 16 * 1024;          // 16 GiB
const DIMM_SPEED_MTS: u16 = 5200;             // DDR5-5200

#[repr(C, packed)]
struct EntryPoint {
    anchor: [u8; 4],
    checksum: u8,
    length: u8,
    major: u8,
    minor: u8,
    max_struct_size: u16,
    revision: u8,
    formatted_area: [u8; 5],
    intermediate_anchor: [u8; 5],
    intermediate_checksum: u8,
    table_length: u16,
    table_addr: u32,
    n_structs: u16,
    bcd_revision: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct Smbios {
    pub entry_phys: u64,
    pub table_phys: u64,
    pub table_len: usize,
}

#[derive(Debug)]
pub enum SmbiosError { AllocFailed }

/// Builder appending structures to a contiguous byte buffer. Tracks
/// current offset + struct count for the entry-point header.
struct Builder {
    base: *mut u8,
    offset: usize,
    capacity: usize,
    n_structs: u16,
}

impl Builder {
    fn new(base: *mut u8, capacity: usize) -> Self {
        Self { base, offset: 0, capacity, n_structs: 0 }
    }

    unsafe fn write(&mut self, src: &[u8]) {
        if self.offset + src.len() > self.capacity {
            return;
        }
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), self.base.add(self.offset), src.len()); }
        self.offset += src.len();
    }

    unsafe fn write_byte(&mut self, b: u8)    { unsafe { self.write(&[b]); } }
    unsafe fn write_u16(&mut self, v: u16)    { unsafe { self.write(&v.to_le_bytes()); } }
    unsafe fn write_u32(&mut self, v: u32)    { unsafe { self.write(&v.to_le_bytes()); } }
    unsafe fn write_u64(&mut self, v: u64)    { unsafe { self.write(&v.to_le_bytes()); } }
    unsafe fn write_bytes(&mut self, b: &[u8]) { unsafe { self.write(b); } }

    /// Append a NUL-terminated string and return the string-table index
    /// (1-based). Returns 0 if the string is empty (SMBIOS convention).
    unsafe fn add_string(&mut self, s: &[u8], string_count: &mut u8) -> u8 {
        if s.is_empty() { return 0; }
        unsafe { self.write(s); }
        unsafe { self.write_byte(0); }
        *string_count += 1;
        *string_count
    }

    /// Finalise the current struct's string table by writing the
    /// double-NUL terminator. Call exactly once after add_string()s.
    unsafe fn end_struct(&mut self, string_count: u8) {
        // Per SMBIOS 2.x, if a struct has no strings the formatted area
        // is followed by *two* NUL bytes (a zero-length string table).
        // We always emit a final NUL to terminate the last string (or
        // start the empty table), plus another NUL as table-end marker.
        if string_count == 0 {
            unsafe { self.write_byte(0); }
        }
        unsafe { self.write_byte(0); }
        self.n_structs += 1;
    }
}

/// Read a profile field, falling back to `fb` when empty.
unsafe fn ps_or<const N: usize>(p: *const ProfileStr<N>, fb: &'static [u8]) -> [u8; 128] {
    let mut buf = [0u8; 128];
    let s = unsafe { p.read_unaligned() };
    let bytes = s.as_bytes();
    let chosen: &[u8] = if bytes.is_empty() { fb } else { bytes };
    let n = chosen.len().min(127);
    buf[..n].copy_from_slice(&chosen[..n]);
    buf
}

unsafe fn ps_len(b: &[u8; 128]) -> usize {
    b.iter().position(|&c| c == 0).unwrap_or(128)
}

fn parse_uuid_text(s: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut nibble_idx = 0usize;
    for &c in s.iter() {
        if c == b'-' { continue; }
        if nibble_idx >= 32 { break; }
        let nibble = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => continue,
        };
        let byte_idx = nibble_idx / 2;
        if nibble_idx & 1 == 0 { out[byte_idx] = nibble << 4; }
        else { out[byte_idx] |= nibble; }
        nibble_idx += 1;
    }
    out
}

pub fn build() -> Result<Smbios, SmbiosError> {
    let page = crate::platform::alloc_pages(1)
        .map_err(|_| SmbiosError::AllocFailed)?;
    let base = page.as_ptr() as u64;
    unsafe { core::ptr::write_bytes(page.as_ptr(), 0u8, 4096); }

    let entry_phys = base;
    let table_phys = base + 0x100;
    let table_cap = 4096 - 0x100;

    let profile = active::PROFILE.get();
    // Vendor flag drives the Type 1 (system) vs Type 4 (processor family)
    // consistency: an Intel-vendor profile reports an Intel processor
    // family, an AMD one reports AMD. Single source = cpuid::profile_is_intel.
    let is_intel = crate::hypervisor::vmexit::cpuid::profile_is_intel();

    // Memory geometry — profile-driven (Type 16/17/19/20 all derive from
    // these so the mapped-address ranges stay self-consistent). Falls back
    // to the 32 GiB DDR5-5200 (2×16 GiB) defaults when the profile is empty.
    let (dimm_size_mb, dimm_speed_mts, dimm_count): (u16, u16, u8) = match profile {
        Some(p) => {
            let m = core::ptr::addr_of!((*p).hardware.memory);
            let sz = unsafe { core::ptr::addr_of!((*m).spec.size_mb_per_dimm).read_unaligned() };
            let sp = unsafe { core::ptr::addr_of!((*m).spec.speed_mts).read_unaligned() };
            let dc = unsafe { core::ptr::addr_of!((*m).spec.dimm_count).read_unaligned() };
            (
                if sz != 0 { sz.min(u16::MAX as u32) as u16 } else { DIMM_SIZE_MB },
                if sp != 0 { sp } else { DIMM_SPEED_MTS },
                if dc != 0 { dc } else { 2 },
            )
        }
        None => (DIMM_SIZE_MB, DIMM_SPEED_MTS, 2),
    };
    // We physically emit 2 memory devices (Type 17/20 are unrolled ×2);
    // clamp the populated count to that. Total = size × populated DIMMs.
    let populated = (dimm_count as usize).clamp(1, 2);
    let mem_total_kib: u32 = (dimm_size_mb as u32)
        .saturating_mul(1024)
        .saturating_mul(populated as u32);

    let mut b = Builder::new(table_phys as *mut u8, table_cap);

    // ───── Type 0: BIOS Information ───────────────────────────────────
    unsafe {
        b.write_byte(0);                            // type
        b.write_byte(0x18);                         // length 24
        b.write_u16(handle::BIOS);                  // handle
        let mut sc = 0u8;
        // Place strings after the formatted area later; reserve indices
        // here in the order we'll emit them.
        let (s_vendor, s_version, s_date);
        // Stash everything in a single struct then go strings.
        // We need to write the formatted area first then strings.
        // Switch to "manually count strings" approach: write all bytes
        // for the formatted area first using stub indices, then emit
        // strings in order — that locks the indices to 1,2,3,...
        // Reorder: write vendor field as idx 1, version as 2, date as 3.
        b.write_byte(1); // vendor idx
        b.write_byte(2); // version idx
        b.write_u16(0xE800); // starting addr seg
        b.write_byte(3); // release date idx
        b.write_byte(0x7F); // ROM size: 8 MiB
        // characteristics (8 bytes) — typical PCI/USB/EFI capable
        b.write_bytes(&[0x80, 0x98, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00]);
        b.write_bytes(&[0x07, 0x0D]);               // ext chars
        b.write_byte(1);                            // bios major
        b.write_byte(50);                           // bios minor
        b.write_byte(0xFF);                         // ec major
        b.write_byte(0xFF);                         // ec minor
        // Strings
        let vendor = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.firmware.spec.bios_vendor), b"American Megatrends Inc."),
            // No watermark: a real unconfigured AMI board ships this string.
            None    => { let mut x = [0u8; 128]; let s = b"American Megatrends Inc."; x[..s.len()].copy_from_slice(s); x }
        };
        s_vendor = b.add_string(&vendor[..ps_len(&vendor)], &mut sc);
        let version = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.firmware.spec.bios_version), b"1820"),
            None    => { let mut x = [0u8; 128]; let s = b"v0.9"; x[..s.len()].copy_from_slice(s); x }
        };
        s_version = b.add_string(&version[..ps_len(&version)], &mut sc);
        let date = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.firmware.spec.bios_date), b"09/05/2024"),
            None    => { let mut x = [0u8; 128]; let s = b"01/01/2024"; x[..s.len()].copy_from_slice(s); x }
        };
        s_date = b.add_string(&date[..ps_len(&date)], &mut sc);
        let _ = (s_vendor, s_version, s_date);
        b.end_struct(sc);
    }

    // ───── Type 1: System Information ─────────────────────────────────
    unsafe {
        let uuid_bytes = match profile {
            Some(p) => parse_uuid_text(
                core::ptr::addr_of!(p.hardware.system.instance.uuid).read_unaligned().as_bytes()),
            None => [0u8; 16],
        };
        b.write_byte(1);
        b.write_byte(0x1B);                         // length 27
        b.write_u16(handle::SYSTEM);
        b.write_byte(1); // manufacturer idx
        b.write_byte(2); // product idx
        b.write_byte(3); // version idx
        b.write_byte(4); // serial idx
        b.write_bytes(&uuid_bytes);
        b.write_byte(6); // wake-up = Power Switch
        b.write_byte(5); // sku idx
        b.write_byte(6); // family idx
        let mut sc = 0u8;
        let manu = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.system.spec.manufacturer), FB_MANUFACTURER),
            None    => { let mut x = [0u8; 128]; x[..FB_MANUFACTURER.len()].copy_from_slice(FB_MANUFACTURER); x }
        };
        b.add_string(&manu[..ps_len(&manu)], &mut sc);
        let prod = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.system.spec.product), FB_PRODUCT),
            None    => { let mut x = [0u8; 128]; x[..FB_PRODUCT.len()].copy_from_slice(FB_PRODUCT); x }
        };
        b.add_string(&prod[..ps_len(&prod)], &mut sc);
        let ver = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.system.spec.version), FB_VERSION),
            None    => { let mut x = [0u8; 128]; x[..FB_VERSION.len()].copy_from_slice(FB_VERSION); x }
        };
        b.add_string(&ver[..ps_len(&ver)], &mut sc);
        let serial = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.system.instance.serial), FB_SERIAL),
            None    => { let mut x = [0u8; 128]; x[..FB_SERIAL.len()].copy_from_slice(FB_SERIAL); x }
        };
        b.add_string(&serial[..ps_len(&serial)], &mut sc);
        b.add_string(FB_SKU, &mut sc);
        b.add_string(FB_FAMILY, &mut sc);
        b.end_struct(sc);
    }

    // ───── Type 2: Baseboard ──────────────────────────────────────────
    unsafe {
        b.write_byte(2);
        b.write_byte(0x0F);                         // length 15
        b.write_u16(handle::BASEBOARD);
        b.write_byte(1); // manufacturer idx
        b.write_byte(2); // product idx
        b.write_byte(3); // version idx
        b.write_byte(4); // serial idx
        b.write_byte(0); // asset tag (skip)
        b.write_byte(0x09);                         // feature flags (replaceable + hosting)
        b.write_byte(0);                            // location in chassis (skip)
        b.write_u16(handle::CHASSIS);
        b.write_byte(0x0A);                         // board type = Motherboard
        b.write_byte(0);                            // contained objects count
        let mut sc = 0u8;
        let manu = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.system.spec.manufacturer), b"ASUSTeK COMPUTER INC."),
            None    => { let mut x = [0u8; 128]; x[..FB_MANUFACTURER.len()].copy_from_slice(FB_MANUFACTURER); x }
        };
        b.add_string(&manu[..ps_len(&manu)], &mut sc);
        let prod = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.system.spec.product), b"ROG STRIX X670E-E GAMING WIFI"),
            None    => { let mut x = [0u8; 128]; x[..FB_PRODUCT.len()].copy_from_slice(FB_PRODUCT); x }
        };
        b.add_string(&prod[..ps_len(&prod)], &mut sc);
        b.add_string(b"Rev 1.xx", &mut sc);
        // Baseboard serial is its OWN field (distinct from the system serial);
        // real boards report different serials per SMBIOS structure.
        let serial = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.board.instance.baseboard_serial), b"230000000000000"),
            None    => { let mut x = [0u8; 128]; x[..FB_SERIAL.len()].copy_from_slice(FB_SERIAL); x }
        };
        b.add_string(&serial[..ps_len(&serial)], &mut sc);
        b.end_struct(sc);
    }

    // ───── Type 3: Chassis ────────────────────────────────────────────
    unsafe {
        b.write_byte(3);
        b.write_byte(0x16);                         // length 22 (SMBIOS 2.7+)
        b.write_u16(handle::CHASSIS);
        b.write_byte(1); // manufacturer idx
        b.write_byte(0x03);                         // type = Desktop
        b.write_byte(2); // version idx
        b.write_byte(3); // serial idx
        b.write_byte(0); // asset tag
        b.write_byte(0x03);                         // boot-up state = Safe
        b.write_byte(0x03);                         // power supply state = Safe
        b.write_byte(0x03);                         // thermal state = Safe
        b.write_byte(0x02);                         // security status = Unknown
        b.write_u32(0);                             // OEM defined
        b.write_byte(4);                            // height (U) — 0 = unspec
        b.write_byte(0);                            // power cords
        b.write_byte(0);                            // contained elements
        b.write_byte(0);                            // element record length
        b.write_byte(0);                            // SKU number (no string)
        let mut sc = 0u8;
        let manu = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.system.spec.manufacturer), b"ASUSTeK COMPUTER INC."),
            None    => { let mut x = [0u8; 128]; x[..FB_MANUFACTURER.len()].copy_from_slice(FB_MANUFACTURER); x }
        };
        b.add_string(&manu[..ps_len(&manu)], &mut sc);
        b.add_string(b"Default string", &mut sc);
        // Chassis serial is its own field, distinct from system/baseboard.
        let serial = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.board.instance.chassis_serial), b"Default string"),
            None    => { let mut x = [0u8; 128]; x[..FB_SERIAL.len()].copy_from_slice(FB_SERIAL); x }
        };
        b.add_string(&serial[..ps_len(&serial)], &mut sc);
        b.end_struct(sc);
    }

    // ───── Type 7: Cache × 3 (L1, L2, L3) ─────────────────────────────
    // Profile-driven and topology-consistent. Per-core L1/L2 sizes come
    // from the active profile (cpu.cache_l{1,2}_per_core_kib); the SMBIOS
    // total is (per_core × cores) where `cores` is the SINGLE topology
    // source effective_core_count() — so the cache totals scale with the
    // same core count leaf 1 / leaf 0xB / leaf 0x80000008 / MADT / Type 4
    // all report. L3 is a flat package total. Falls back to Zen-4 7900X
    // figures when the profile leaves the fields 0.
    // SMBIOS 2.x Cache Size field is u16 in KiB-units with bit 15 = "granularity 64K".
    // For >= 32768 KiB we set bit 15 and encode the value in 64K units.
    unsafe {
        const fn cache_size_field(kib: u32) -> u16 {
            if kib < 32_768 { kib as u16 & 0x7FFF }
            else { ((kib / 64) as u16) | 0x8000 }
        }
        let cores = crate::hypervisor::vmexit::cpuid::effective_core_count();
        let (l1_per_core, l2_per_core, l3_total) = match profile {
            Some(p) => {
                let c = core::ptr::addr_of!((*p).hardware.cpu);
                let l1 = core::ptr::addr_of!((*c).spec.cache_l1_per_core_kib).read_unaligned();
                let l2 = core::ptr::addr_of!((*c).spec.cache_l2_per_core_kib).read_unaligned();
                let l3 = core::ptr::addr_of!((*c).spec.cache_l3_total_kib).read_unaligned();
                (
                    if l1 != 0 { l1 } else { 64 },
                    if l2 != 0 { l2 } else { 1024 },
                    if l3 != 0 { l3 } else { 64 * 1024 },
                )
            }
            None => (64, 1024, 64 * 1024),
        };
        let l1_total = l1_per_core.saturating_mul(cores);
        let l2_total = l2_per_core.saturating_mul(cores);
        let layouts: [(u16, u32, u16, u8, u8); 3] = [
            // (handle, total_kib, conf, sram_type, level)
            (handle::CACHE_L1, l1_total, 0x0180, 0x10, 0x01),  // L1 enabled, write-back, pipeline burst SRAM
            (handle::CACHE_L2, l2_total, 0x0181, 0x10, 0x02),  // L2 enabled, write-back
            (handle::CACHE_L3, l3_total, 0x0182, 0x10, 0x03),  // L3 enabled, write-back
        ];
        for (h, kib, conf, sram, lvl) in layouts {
            b.write_byte(7);
            b.write_byte(0x13);                     // length 19 (SMBIOS 2.1)
            b.write_u16(h);
            b.write_byte(1);                        // socket designation idx
            b.write_u16(conf);                      // cache configuration
            b.write_u16(cache_size_field(kib));     // max cache size
            b.write_u16(cache_size_field(kib));     // installed size
            b.write_u16(0x0010);                    // supported SRAM = pipeline burst
            b.write_u16(0x0010);                    // current SRAM
            b.write_byte(1);                        // cache speed (ns) — 1 = fastest
            b.write_byte(0x05);                     // error correction = Single-bit ECC
            b.write_byte(0x05);                     // system cache type = Unified
            b.write_byte(0x00);                     // associativity = unknown
            let _ = (sram, lvl);
            let mut sc = 0u8;
            let label: &[u8] = match h {
                handle::CACHE_L1 => b"L1 - Cache",
                handle::CACHE_L2 => b"L2 - Cache",
                _                => b"L3 - Cache",
            };
            b.add_string(label, &mut sc);
            b.end_struct(sc);
        }
    }

    // ───── Type 4: Processor (linked to cache handles + topology source) ─
    // Core/thread counts derive from effective_core_count() (the single
    // topology source) so Type 4 agrees with CPUID leaf 1 / 0xB /
    // 0x80000008 / the MADT LAPIC count. Processor-family enum, socket
    // designation and speeds come from the active profile so an Intel
    // profile reports an Intel family here (no Type1-Intel/Type4-AMD self-
    // contradiction). The Processor ID is the *spoofed* CPUID 1 EAX from
    // the profile (cpuid_eax_v1), not the host's leaf 1 — otherwise the
    // SMBIOS family/model would betray the real silicon.
    unsafe {
        let cores = crate::hypervisor::vmexit::cpuid::effective_core_count().min(255) as u8;
        // Processor ID = {EAX = profile cpuid_eax_v1 (or host), EDX = host
        // feature flags}. Using the spoofed EAX keeps SMBIOS family/model
        // consistent with what CPUID leaf 1 reports to the guest.
        let cpuid1 = crate::infra::arch::cpuid(1);
        let eax_v1 = match profile {
            Some(p) => {
                let v = core::ptr::addr_of!((*p).hardware.cpu.spec.cpuid_eax_v1).read_unaligned();
                if v != 0 { v } else { cpuid1.eax }
            }
            None => cpuid1.eax,
        };
        let mut pid = [0u8; 8];
        pid[..4].copy_from_slice(&eax_v1.to_le_bytes());
        pid[4..].copy_from_slice(&cpuid1.edx.to_le_bytes());

        // Profile-driven Type 4 fields (vendor-consistent defaults if 0).
        let (family, max_mhz, cur_mhz) = match profile {
            Some(p) => {
                let c = core::ptr::addr_of!((*p).hardware.cpu);
                let fam = core::ptr::addr_of!((*c).spec.smbios_processor_family).read_unaligned();
                let mx = core::ptr::addr_of!((*c).spec.cpu_max_speed_mhz).read_unaligned();
                let cu = core::ptr::addr_of!((*c).spec.cpu_current_speed_mhz).read_unaligned();
                (
                    if fam != 0 { fam } else if is_intel { 0x00B3 } else { 0x00CE },
                    if mx != 0 { mx } else { 5500 },
                    if cu != 0 { cu } else { 4500 },
                )
            }
            None => (if is_intel { 0x00B3 } else { 0x00CE }, 5500, 4500),
        };
        // family enum > 0xFF must be escaped as 0xFE in the byte field and
        // the real value placed in family_2 (SMBIOS 2.6+). Our enums are
        // all <= 0xFF, but honour the escape rule for safety.
        let family_byte: u8 = if family > 0xFF { 0xFE } else { family as u8 };

        b.write_byte(4);
        b.write_byte(0x30);                         // length 48 (SMBIOS 3.0)
        b.write_u16(handle::PROCESSOR);
        b.write_byte(1);                            // socket designation idx
        b.write_byte(0x03);                         // processor type = Central
        b.write_byte(family_byte);                  // family (profile/vendor-derived)
        b.write_byte(2);                            // manufacturer idx
        b.write_bytes(&pid);                        // processor_id (spoofed EAX : host EDX)
        b.write_byte(3);                            // version (brand) idx
        b.write_byte(0x82);                         // voltage = 1.2V legacy
        b.write_u16(100);                           // external clock MHz
        b.write_u16(max_mhz);                        // max speed MHz
        b.write_u16(cur_mhz);                        // current speed MHz
        b.write_byte(0x41);                         // status = enabled + populated
        b.write_byte(0x02);                         // upgrade = Unknown (socket named in string)
        b.write_u16(handle::CACHE_L1);
        b.write_u16(handle::CACHE_L2);
        b.write_u16(handle::CACHE_L3);
        b.write_byte(4);                            // serial number idx
        b.write_byte(5);                            // asset tag idx
        b.write_byte(6);                            // part number idx
        b.write_byte(cores);                        // core_count (single topology source)
        b.write_byte(cores);                        // core_enabled
        b.write_byte(cores);                        // thread_count (1 thread/core, no SMT)
        b.write_u16(0x0004);                        // characteristics = 64-bit capable
        b.write_u16(family);                         // family_2 (full 16-bit family)
        let mut sc = 0u8;
        let socket = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.cpu.spec.smbios_socket), b"AM5"),
            None    => { let mut x = [0u8; 128]; let s = b"AM5"; x[..s.len()].copy_from_slice(s); x }
        };
        b.add_string(&socket[..ps_len(&socket)], &mut sc);
        let vendor = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.cpu.spec.vendor), b"AuthenticAMD"),
            None    => { let mut x = [0u8; 128]; let s = b"AuthenticAMD"; x[..s.len()].copy_from_slice(s); x }
        };
        b.add_string(&vendor[..ps_len(&vendor)], &mut sc);
        let brand = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.cpu.spec.brand), b"AMD Processor"),
            None    => { let mut x = [0u8; 128]; let s = b"AMD Processor"; x[..s.len()].copy_from_slice(s); x }
        };
        b.add_string(&brand[..ps_len(&brand)], &mut sc);
        let serial = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.system.instance.serial), b"Unknown"),
            None    => { let mut x = [0u8; 128]; let s = b"Unknown"; x[..s.len()].copy_from_slice(s); x }
        };
        b.add_string(&serial[..ps_len(&serial)], &mut sc);
        b.add_string(b"Unknown", &mut sc);
        b.add_string(b"Unknown", &mut sc);
        b.end_struct(sc);
    }

    // ───── Type 9: Slots × 2 (PCIe x16, M.2) ─────────────────────────
    unsafe {
        // (handle, designation, type, width, bus_dev_fn)
        let slots: [(u16, &[u8], u8, u8); 2] = [
            (handle::SLOT_PCIE, b"PCIEX16_1", 0xB6, 0x0D),  // PCIe x16 Gen5
            (handle::SLOT_M2,   b"M.2_1",      0xB6, 0x0A),  // PCIe x4 Gen4
        ];
        for (h, designation, slot_type, width) in slots {
            b.write_byte(9);
            b.write_byte(0x0D);                     // length 13 (SMBIOS 2.0)
            b.write_u16(h);
            b.write_byte(1);                        // designation idx
            b.write_byte(slot_type);
            b.write_byte(width);
            b.write_byte(0x03);                     // current usage = Available
            b.write_byte(0x03);                     // length = Long
            b.write_u16(0);                         // slot id
            b.write_byte(0x04);                     // characteristics 1 = 3.3V
            let mut sc = 0u8;
            b.add_string(designation, &mut sc);
            b.end_struct(sc);
        }
    }

    // ───── Type 16: Physical Memory Array ─────────────────────────────
    unsafe {
        b.write_byte(16);
        b.write_byte(0x0F);                         // length 15 (SMBIOS 2.1)
        b.write_u16(handle::MEM_ARRAY);
        b.write_byte(0x03);                         // location = System Board
        b.write_byte(0x03);                         // use = System Memory
        b.write_byte(0x03);                         // ECC = None
        b.write_u32(mem_total_kib);                 // max capacity (KiB) — profile-derived
        b.write_u16(0xFFFE);                        // error info handle = Not Provided
        b.write_u16(populated as u16);              // num memory devices
    }
    unsafe { b.end_struct(0); }

    // ───── Type 17: Memory Device × 2 ─────────────────────────────────
    // Manufacturer / part number / per-DIMM serials are profile-driven so
    // they match the Type 16 totals and the rest of the board identity.
    // Form factor stays DIMM (0x09): there's no profile field distinguishing
    // DIMM vs SO-DIMM yet, so we avoid a vendor-keyed guess (laptops on AMD
    // exist). Adding a MemoryProfile.form_factor is deferred (see report).
    unsafe {
        let form_factor: u8 = 0x09; // DIMM
        let mem_manuf = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.memory.spec.manufacturer), b"Corsair"),
            None    => { let mut x = [0u8; 128]; let s = b"Corsair"; x[..s.len()].copy_from_slice(s); x }
        };
        let mem_part = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.memory.spec.part_number), b"CMK32GX5M2B5200C40"),
            None    => { let mut x = [0u8; 128]; let s = b"CMK32GX5M2B5200C40"; x[..s.len()].copy_from_slice(s); x }
        };
        let mem_ser0 = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.memory.instance.serial0), b"5400123456789AB"),
            None    => { let mut x = [0u8; 128]; let s = b"5400123456789AB"; x[..s.len()].copy_from_slice(s); x }
        };
        let mem_ser1 = match profile {
            Some(p) => ps_or(core::ptr::addr_of!(p.hardware.memory.instance.serial1), b"5400CAFE0123456"),
            None    => { let mut x = [0u8; 128]; let s = b"5400CAFE0123456"; x[..s.len()].copy_from_slice(s); x }
        };
        let devs: [(u16, &[u8], &[u8; 128]); 2] = [
            (handle::MEM_DEV0, b"DIMM_A1", &mem_ser0),
            (handle::MEM_DEV1, b"DIMM_B1", &mem_ser1),
        ];
        for (h, locator, serial) in devs {
            b.write_byte(17);
            b.write_byte(0x28);                     // length 40 (SMBIOS 2.7)
            b.write_u16(h);
            b.write_u16(handle::MEM_ARRAY);         // array handle
            b.write_u16(0xFFFE);                    // error info handle
            b.write_u16(64);                        // total width (bits)
            b.write_u16(64);                        // data width
            b.write_u16(dimm_size_mb);              // size (MiB) — profile-derived
            b.write_byte(form_factor);              // form factor
            b.write_byte(0);                        // device set
            b.write_byte(1);                        // device locator idx
            b.write_byte(2);                        // bank locator idx
            b.write_byte(0x22);                     // memory type = DDR5
            b.write_u16(0x0080);                    // type detail = Synchronous
            b.write_u16(dimm_speed_mts);            // speed (MT/s) — profile-derived
            b.write_byte(3);                        // manufacturer idx
            b.write_byte(4);                        // serial idx
            b.write_byte(5);                        // asset tag idx
            b.write_byte(6);                        // part number idx
            b.write_byte(0);                        // attributes (rank)
            b.write_u32(0);                         // extended size
            b.write_u16(dimm_speed_mts);            // configured speed
            b.write_u16(0x04B0);                    // min voltage (mV) = 1.2 V
            b.write_u16(0x04B0);                    // max voltage
            b.write_u16(0x04B0);                    // configured voltage
            let mut sc = 0u8;
            b.add_string(locator, &mut sc);
            b.add_string(b"BANK 0", &mut sc);
            b.add_string(&mem_manuf[..ps_len(&mem_manuf)], &mut sc);
            b.add_string(&serial[..ps_len(serial)], &mut sc);
            b.add_string(b"AssetTagNum0", &mut sc);
            b.add_string(&mem_part[..ps_len(&mem_part)], &mut sc);
            b.end_struct(sc);
        }
    }

    // ───── Type 19: Memory Array Mapped Address ───────────────────────
    unsafe {
        b.write_byte(19);
        b.write_byte(0x1F);                         // length 31 (SMBIOS 2.7)
        b.write_u16(handle::MEM_AMAP);
        b.write_u32(0xFFFF_FFFF);                   // starting addr (deprecated marker)
        b.write_u32(0xFFFF_FFFF);                   // ending addr  (deprecated marker)
        b.write_u16(handle::MEM_ARRAY);
        b.write_byte(populated as u8);              // partition width (populated DIMMs)
        b.write_u64(0x0);                           // extended starting addr (0 = first byte)
        b.write_u64((mem_total_kib as u64) * 1024 - 1);  // extended ending addr
    }
    unsafe { b.end_struct(0); }

    // ───── Type 20: Memory Device Mapped Address × 2 ──────────────────
    unsafe {
        let half = (mem_total_kib as u64) * 1024 / 2;
        let ranges: [(u16, u16, u64, u64); 2] = [
            (handle::MEM_DMAP0, handle::MEM_DEV0, 0,    half - 1),
            (handle::MEM_DMAP1, handle::MEM_DEV1, half, mem_total_kib as u64 * 1024 - 1),
        ];
        for (h, devh, start, end) in ranges {
            b.write_byte(20);
            b.write_byte(0x23);                     // length 35 (SMBIOS 2.7)
            b.write_u16(h);
            b.write_u32(0xFFFF_FFFF);               // deprecated start
            b.write_u32(0xFFFF_FFFF);               // deprecated end
            b.write_u16(devh);
            b.write_u16(handle::MEM_AMAP);
            b.write_byte(0xFF);                     // partition row position
            b.write_byte(0xFF);                     // interleave position
            b.write_byte(0xFF);                     // interleave data depth
            b.write_u64(start);
            b.write_u64(end);
            b.end_struct(0);
        }
    }

    // ───── Type 32: System Boot Information ───────────────────────────
    unsafe {
        b.write_byte(32);
        b.write_byte(0x0B);                         // length 11
        b.write_u16(handle::BOOT_INFO);
        b.write_bytes(&[0u8; 6]);                   // reserved
        b.write_byte(0);                            // boot status = No error
    }
    unsafe { b.end_struct(0); }

    // ───── Type 127: End-of-Table ─────────────────────────────────────
    unsafe {
        b.write_byte(127);
        b.write_byte(0x04);                         // length 4
        b.write_u16(handle::END_OF_TABLE);
    }
    unsafe { b.end_struct(0); }

    let table_total = b.offset;
    let n_structs = b.n_structs;

    // ───── Entry Point ────────────────────────────────────────────────
    let ep = entry_phys as *mut EntryPoint;
    unsafe {
        (*ep).anchor = *b"_SM_";
        (*ep).length = ENTRY_POINT_LEN;
        (*ep).major = 2;
        (*ep).minor = 8;
        (*ep).max_struct_size = table_total as u16;
        (*ep).revision = 0;
        (*ep).formatted_area = [0u8; 5];
        (*ep).intermediate_anchor = *ENTRY_POINT_INTERMEDIATE;
        (*ep).table_length = table_total as u16;
        (*ep).table_addr = table_phys as u32;
        (*ep).n_structs = n_structs;
        (*ep).bcd_revision = 0x28;
        let inter_ptr = (entry_phys as *const u8).add(0x10);
        let inter = core::slice::from_raw_parts(inter_ptr, 0xF);
        let is: u8 = inter.iter().copied().fold(0u8, u8::wrapping_add);
        (*ep).intermediate_checksum = 0u8.wrapping_sub(is);
        let all = core::slice::from_raw_parts(entry_phys as *const u8, ENTRY_POINT_LEN as usize);
        let s: u8 = all.iter().copied().fold(0u8, u8::wrapping_add);
        (*ep).checksum = 0u8.wrapping_sub(s);
    }

    Ok(Smbios { entry_phys, table_phys, table_len: table_total })
}
