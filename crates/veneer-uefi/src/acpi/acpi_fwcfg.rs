//! Packages the synthetic ACPI tables into the QEMU fw_cfg payload OVMF's
//! BiosLinkerLoader consumes.
//!
//! OVMF doesn't read ACPI tables straight from memory the way the legacy
//! chain-load path deploys them; it downloads three fw_cfg files and runs a
//! relocation script:
//!   - `etc/acpi/tables`  : XSDT + all secondary tables, concatenated, with
//!                          cross-table pointers stored as *blob-relative*
//!                          offsets and every checksum byte left zero.
//!   - `etc/acpi/rsdp`    : the Root System Description Pointer (FSEG zone).
//!   - `etc/table-loader` : a list of 128-byte commands that ALLOCATE each
//!                          file, ADD_POINTER (offset += runtime base), and
//!                          ADD_CHECKSUM (fill the checksum bytes) once the
//!                          firmware knows where it placed each blob.
//!
//! We reuse [`acpi::build_at`] with `guest_base = 0` so every internal
//! pointer it writes is already the blob-relative offset the loader expects;
//! we then zero the checksum bytes (the loader recomputes them) and emit the
//! command stream from the same offsets `build_at` reports.

use uefi::boot::{self, AllocateType, MemoryType};

use crate::acpi::{self, field};
use crate::devices::fwcfg;
use crate::sprintln;

const FILE_RSDP: &[u8] = b"etc/acpi/rsdp";
const FILE_TABLES: &[u8] = b"etc/acpi/tables";

const CMD_ALLOCATE: u32 = 1;
const CMD_ADD_POINTER: u32 = 2;
const CMD_ADD_CHECKSUM: u32 = 3;

const ZONE_HIGH: u8 = 1;
const ZONE_FSEG: u8 = 2;

const ENTRY_SIZE: usize = 128;
const NAME_FIELD: usize = 56;

/// The XSDT is laid out before the tables it references; its dead RSDP twin
/// occupies the first 0x40 bytes of the page (build_at puts a full RSDP at
/// offset 0). We zero that region so only the standalone etc/acpi/rsdp file
/// carries the pointer.
const TABLES_HEAD_DEAD: usize = 0x40;

struct Loader {
    base: *mut u8,
    count: usize,
}

impl Loader {
    fn new(base: *mut u8) -> Self {
        Self { base, count: 0 }
    }

    fn len(&self) -> usize {
        self.count * ENTRY_SIZE
    }

    /// Start a fresh 128-byte entry, zero it, stamp the command id, and
    /// return the entry's base pointer.
    unsafe fn entry(&mut self, command: u32) -> *mut u8 {
        let p = unsafe { self.base.add(self.count * ENTRY_SIZE) };
        unsafe {
            core::ptr::write_bytes(p, 0, ENTRY_SIZE);
            core::ptr::write_unaligned(p as *mut u32, command);
        }
        self.count += 1;
        p
    }

    unsafe fn alloc(&mut self, file: &[u8], alignment: u32, zone: u8) {
        let p = unsafe { self.entry(CMD_ALLOCATE) };
        unsafe {
            put_name(p.add(4), file);
            core::ptr::write_unaligned(p.add(60) as *mut u32, alignment);
            *p.add(64) = zone;
        }
    }

    unsafe fn add_pointer(&mut self, ptr_file: &[u8], ptr_off: u32, pointee: &[u8], size: u8) {
        let p = unsafe { self.entry(CMD_ADD_POINTER) };
        unsafe {
            put_name(p.add(4), ptr_file);
            put_name(p.add(60), pointee);
            core::ptr::write_unaligned(p.add(116) as *mut u32, ptr_off);
            *p.add(120) = size;
        }
    }

    unsafe fn add_checksum(&mut self, file: &[u8], offset: u32, start: u32, length: u32) {
        let p = unsafe { self.entry(CMD_ADD_CHECKSUM) };
        unsafe {
            put_name(p.add(4), file);
            core::ptr::write_unaligned(p.add(60) as *mut u32, offset);
            core::ptr::write_unaligned(p.add(64) as *mut u32, start);
            core::ptr::write_unaligned(p.add(68) as *mut u32, length);
        }
    }
}

unsafe fn put_name(dst: *mut u8, name: &[u8]) {
    let n = name.len().min(NAME_FIELD);
    unsafe { core::ptr::copy_nonoverlapping(name.as_ptr(), dst, n) };
}

fn alloc_page() -> Option<u64> {
    boot::allocate_pages(AllocateType::AnyPages, MemoryType::RUNTIME_SERVICES_DATA, 1)
        .ok()
        .map(|p| p.as_ptr() as u64)
}

/// Read an ACPI table's `length` field (u32 LE at header offset 4).
unsafe fn table_len(page: u64, off: usize) -> u32 {
    unsafe { core::ptr::read_unaligned((page + off as u64 + 4) as *const u32) }
}

unsafe fn zero_byte(page: u64, off: usize) {
    unsafe { *((page + off as u64) as *mut u8) = 0 };
}

/// Build the three blobs and hand them to the fw_cfg emulator. After this
/// the OVMF guest reads ACPI through fw_cfg instead of finding none.
pub fn build_and_stage(n_vcpus: usize) {
    let tables = match alloc_page() {
        Some(p) => p,
        None => { sprintln!("[acpi-fw] tables page alloc failed"); return; }
    };
    let rsdp = match alloc_page() {
        Some(p) => p,
        None => { sprintln!("[acpi-fw] rsdp page alloc failed"); return; }
    };
    let loader_page = match alloc_page() {
        Some(p) => p,
        None => { sprintln!("[acpi-fw] loader page alloc failed"); return; }
    };

    // guest_base = 0 → every pointer build_at writes is its blob-relative
    // offset, exactly what the loader's ADD_POINTER expects.
    let a = unsafe { acpi::build_at(tables, 0, n_vcpus) };

    let xsdt = a.xsdt_phys as usize;
    let fadt = a.fadt_phys as usize;
    let madt = a.madt_phys as usize;
    let mcfg = a.mcfg_phys as usize;
    let hpet = a.hpet_phys as usize;
    let dsdt = a.dsdt_phys as usize;
    let ssdt = a.ssdt_phys as usize;
    let spcr = a.spcr_phys as usize;
    let wsmt = a.wsmt_phys as usize;
    let tpm2 = a.tpm2_phys as usize;
    // FACS has no header/checksum and isn't in the XSDT; FADT points to it.
    let facs = a.facs_phys as usize;
    // Blob length = the furthest table end. DSDT sits past TPM2 (it needs the
    // 2 KiB page tail for _CRS/_PRT), so don't assume TPM2 is last.
    let tables_len = [xsdt, fadt, madt, mcfg, hpet, dsdt, ssdt, facs, spcr, wsmt, tpm2]
        .iter()
        .map(|&off| off + unsafe { table_len(tables, off) } as usize)
        .max()
        .unwrap_or(0) as u32;

    // Standalone RSDP: copy build_at's, then blank its two checksum bytes.
    // Its xsdt_addr already holds the relative XSDT offset (0x40) the loader
    // will rebase.
    unsafe {
        core::ptr::copy_nonoverlapping(tables as *const u8, rsdp as *mut u8, field::RSDP_LEN);
        zero_byte(rsdp, field::RSDP_CHECKSUM);
        zero_byte(rsdp, field::RSDP_EXT_CHECKSUM);
    }

    // Tables blob: drop the dead RSDP twin and zero every checksum byte so
    // the loader's ADD_CHECKSUM produces a correct sum (it includes the
    // checksum byte in its range, so it must start at zero).
    let checksummed = [xsdt, fadt, madt, mcfg, hpet, dsdt, ssdt, spcr, wsmt, tpm2];
    unsafe {
        core::ptr::write_bytes(tables as *mut u8, 0, TABLES_HEAD_DEAD);
        for &off in &checksummed {
            zero_byte(tables, off + field::HEADER_CHECKSUM);
        }
    }

    // ── table-loader command stream ──────────────────────────────────
    let mut l = Loader::new(loader_page as *mut u8);
    unsafe {
        l.alloc(FILE_TABLES, 64, ZONE_HIGH);
        l.alloc(FILE_RSDP, 16, ZONE_FSEG);

        // XSDT entries → each secondary table (same order build_at wrote).
        let xsdt_entries = [fadt, madt, mcfg, hpet, ssdt, spcr, wsmt, tpm2];
        for i in 0..field::XSDT_ENTRY_COUNT {
            let off = xsdt + field::HEADER_SIZE + i * 8;
            l.add_pointer(FILE_TABLES, off as u32, FILE_TABLES, 8);
        }
        let _ = xsdt_entries; // documents the pointee order for readers

        // FADT → DSDT and FADT → FACS, both 32- and 64-bit forms.
        l.add_pointer(FILE_TABLES, (fadt + field::FADT_DSDT) as u32, FILE_TABLES, 4);
        l.add_pointer(FILE_TABLES, (fadt + field::FADT_X_DSDT) as u32, FILE_TABLES, 8);
        l.add_pointer(FILE_TABLES, (fadt + field::FADT_FIRMWARE_CTRL) as u32, FILE_TABLES, 4);
        l.add_pointer(FILE_TABLES, (fadt + field::FADT_X_FIRMWARE_CTRL) as u32, FILE_TABLES, 8);

        // RSDP → XSDT.
        l.add_pointer(FILE_RSDP, field::RSDP_XSDT_ADDR as u32, FILE_TABLES, 8);

        // Checksums last: pointer patches above changed bytes inside these
        // ranges, so the sums must be computed afterwards.
        for &off in &checksummed {
            let len = table_len(tables, off);
            l.add_checksum(FILE_TABLES, (off + field::HEADER_CHECKSUM) as u32, off as u32, len);
        }
        l.add_checksum(FILE_RSDP, field::RSDP_CHECKSUM as u32, 0, field::RSDP_V1_CHECKSUM_LEN as u32);
        l.add_checksum(FILE_RSDP, field::RSDP_EXT_CHECKSUM as u32, 0, field::RSDP_LEN as u32);
    }

    let loader_len = l.len() as u32;
    fwcfg::install_acpi(
        rsdp as *const u8,
        field::RSDP_LEN as u32,
        tables as *const u8,
        tables_len,
        loader_page as *const u8,
        loader_len,
    );
    sprintln!(
        "[acpi-fw] staged: tables {} B, rsdp {} B, loader {} B ({} cmds)",
        tables_len, field::RSDP_LEN, loader_len, l.count
    );
}
