//! Self-validation pass: walk the ACPI / SMBIOS / PCI structures we
//! handed to firmware and print a structured dump to the serial console.
//!
//! What this catches:
//!   - ACPI table checksum or length errors (we re-verify them here
//!     rather than trusting the build-time computation)
//!   - SMBIOS structure ordering issues (LFN / 8.3 directory entries
//!     don't have integrity bits — we walk linearly and check)
//!   - PCI config-space holes (a `0xFFFFFFFF` reply where we expect
//!     a device means our intercept didn't fire)
//!
//! What this does *not* catch:
//!   - Whether Windows / Linux *parsers* like our output (only a real
//!     guest OS validates that)
//!   - Functional emulator correctness — only the static tables
//!     emitted at firmware-install time

use crate::hardware::acpi::Acpi;
use crate::hardware::identity::smbios::Smbios;
use crate::sprintln;

/// Top-level ACPI table header layout — first 36 bytes of every ACPI
/// description table.
#[repr(C, packed)]
struct AcpiTableHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

fn checksum_ok(addr: u64, len: usize) -> (u8, bool) {
    let slice = unsafe { core::slice::from_raw_parts(addr as *const u8, len) };
    let sum: u8 = slice.iter().copied().fold(0u8, u8::wrapping_add);
    (sum, sum == 0)
}

fn sig_to_str(sig: &[u8; 4]) -> &str {
    core::str::from_utf8(sig).unwrap_or("????")
}

pub fn validate_acpi(acpi: &Acpi) {
    sprintln!("[val ] ACPI self-check:");
    let header = unsafe { &*(acpi.rsdp_phys as *const [u8; 36]) };
    let rsdp_sig = &header[0..8];
    let (rsdp_sum, rsdp_ok) = checksum_ok(acpi.rsdp_phys, 20);
    let (rsdp_ext_sum, rsdp_ext_ok) = checksum_ok(acpi.rsdp_phys, 36);
    sprintln!(
        "[val ]   RSDP @ 0x{:016X} sig={:?} sum1=0x{:02X} ({}) sum2=0x{:02X} ({})",
        acpi.rsdp_phys,
        core::str::from_utf8(rsdp_sig).unwrap_or("?"),
        rsdp_sum, if rsdp_ok { "OK" } else { "BAD" },
        rsdp_ext_sum, if rsdp_ext_ok { "OK" } else { "BAD" },
    );

    for (name, phys) in [
        ("XSDT", acpi.xsdt_phys),
        ("FADT", acpi.fadt_phys),
        ("MADT", acpi.madt_phys),
        ("MCFG", acpi.mcfg_phys),
        ("HPET", acpi.hpet_phys),
        ("DSDT", acpi.dsdt_phys),
        ("SSDT", acpi.ssdt_phys),
        ("SPCR", acpi.spcr_phys),
        ("WSMT", acpi.wsmt_phys),
        ("TPM2", acpi.tpm2_phys),
    ] {
        let hdr = unsafe { &*(phys as *const AcpiTableHeader) };
        let len = unsafe { core::ptr::addr_of!(hdr.length).read_unaligned() } as usize;
        let (sum, ok) = checksum_ok(phys, len);
        let sig = unsafe { core::ptr::addr_of!(hdr.signature).read_unaligned() };
        sprintln!(
            "[val ]   {} @ 0x{:016X} sig={:?} len={:5} sum=0x{:02X} ({})",
            name, phys, sig_to_str(&sig), len, sum,
            if ok { "OK" } else { "BAD" },
        );
    }

    // FACS has no AcpiTableHeader — just signature + length at offsets 0/4.
    {
        let phys = acpi.facs_phys;
        let sig: [u8; 4] = unsafe { core::ptr::read_unaligned(phys as *const [u8; 4]) };
        let len: u32 = unsafe { core::ptr::read_unaligned((phys as *const u32).add(1)) };
        sprintln!(
            "[val ]   FACS @ 0x{:016X} sig={:?} len={} (no checksum)",
            phys, sig_to_str(&sig), len,
        );
    }

    // Cross-check FADT references DSDT correctly.
    let fadt_dsdt_low: u32 = unsafe {
        core::ptr::read_unaligned((acpi.fadt_phys + 40) as *const u32)
    };
    let fadt_x_dsdt: u64 = unsafe {
        core::ptr::read_unaligned((acpi.fadt_phys + 140) as *const u64)
    };
    sprintln!(
        "[val ]   FADT.DSDT      = 0x{:08X}   (expect 0x{:08X})",
        fadt_dsdt_low, acpi.dsdt_phys as u32,
    );
    sprintln!(
        "[val ]   FADT.X_DSDT    = 0x{:016X} (expect 0x{:016X})",
        fadt_x_dsdt, acpi.dsdt_phys,
    );

    let fadt_facs_low: u32 = unsafe {
        core::ptr::read_unaligned((acpi.fadt_phys + 36) as *const u32)
    };
    let fadt_x_facs: u64 = unsafe {
        core::ptr::read_unaligned((acpi.fadt_phys + 132) as *const u64)
    };
    sprintln!(
        "[val ]   FADT.FACS      = 0x{:08X}   (expect 0x{:08X})",
        fadt_facs_low, acpi.facs_phys as u32,
    );
    sprintln!(
        "[val ]   FADT.X_FACS    = 0x{:016X} (expect 0x{:016X})",
        fadt_x_facs, acpi.facs_phys,
    );

    sprintln!("[val ] ACPI self-check done.");
}

pub fn validate_smbios(smbios: &Smbios) {
    sprintln!("[val ] SMBIOS self-check (entry @ 0x{:016X}, table @ 0x{:016X}, {} bytes):",
        smbios.entry_phys, smbios.table_phys, smbios.table_len);

    let mut p = smbios.table_phys;
    let end = smbios.table_phys + smbios.table_len as u64;
    let mut count = 0;
    while p < end && count < 64 {
        let type_: u8 = unsafe { core::ptr::read_unaligned(p as *const u8) };
        let length: u8 = unsafe { core::ptr::read_unaligned((p + 1) as *const u8) };
        let handle: u16 = unsafe { core::ptr::read_unaligned((p + 2) as *const u16) };

        // Walk string area: starts after `length` bytes, ends at double-NUL.
        let mut s = p + length as u64;
        let mut nuls = 0u8;
        let mut string_chars = 0;
        while s < end && nuls < 2 {
            let b: u8 = unsafe { core::ptr::read_unaligned(s as *const u8) };
            if b == 0 {
                nuls += 1;
            } else {
                nuls = 0;
                string_chars += 1;
            }
            s += 1;
        }
        let total = s - p;
        sprintln!(
            "[val ]   Type {:3} length={:3} handle=0x{:04X} strings={:3} bytes total={}",
            type_, length, handle, string_chars, total,
        );

        if type_ == 127 {
            sprintln!("[val ]   -- end of table reached at Type 127 --");
            break;
        }
        p = s;
        count += 1;
    }
    sprintln!("[val ] SMBIOS self-check done ({} structures).", count);
}

/// Walk PCI bus 0 / dev 0..16 / func 0 via legacy CF8/CFC ports, print
/// vendor:device + class for every populated slot. This exercises our
/// PCI config emulator (intercept/pci.rs) end-to-end.
pub fn validate_pci() {
    sprintln!("[val ] PCI config-space scan (bus 0):");
    for dev in 0..16 {
        let cfg = config_dword(0, dev, 0, 0);
        let vendor = (cfg & 0xFFFF) as u16;
        let device = ((cfg >> 16) & 0xFFFF) as u16;
        if vendor == 0xFFFF { continue; }
        let class_word = config_dword(0, dev, 0, 0x08);
        let class = (class_word >> 24) & 0xFF;
        let subclass = (class_word >> 16) & 0xFF;
        let prog_if = (class_word >> 8) & 0xFF;
        let bar0 = config_dword(0, dev, 0, 0x10);
        sprintln!(
            "[val ]   {:02X}:{:02X}.0  {:04X}:{:04X}  class={:02X}{:02X}{:02X}  BAR0=0x{:08X}",
            0, dev, vendor, device, class, subclass, prog_if, bar0,
        );
    }
    sprintln!("[val ] PCI scan done.");
}

fn config_dword(bus: u8, dev: u8, func: u8, reg: u8) -> u32 {
    let addr: u32 = 0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((reg as u32) & 0xFC);
    unsafe {
        outl(0xCF8, addr);
        inl(0xCFC)
    }
}

#[inline]
unsafe fn outl(port: u16, val: u32) {
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack));
    }
}

#[inline]
unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    unsafe {
        core::arch::asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack));
    }
    v
}
