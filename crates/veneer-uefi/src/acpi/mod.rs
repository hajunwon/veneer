//! Synthetic ACPI tables — what the guest will see instead of the real
//! firmware's tables.
//!
//! For v0.6-A we build a minimal pair:
//!   - RSDP (Root System Description Pointer, ACPI 2.0 / 36 bytes)
//!   - XSDT (Extended System Description Table, header only, 0 entries)
//!
//! UEFI gives the guest access to ACPI via two configuration-table entries
//! identified by GUID; the launcher patches those entries to point at our
//! RSDP. Real OS-boot work (DSDT, MADT for SMP, FADT for power, HPET, …)
//! lands in v0.6-B.

pub mod acpi_fwcfg;
pub mod aml;

extern crate alloc;

use uefi::boot::{self, AllocateType, MemoryType};

use crate::identity::active;

#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8],   // "RSD PTR "
    checksum: u8,         // sum of first 20 bytes == 0
    oem_id: [u8; 6],
    revision: u8,         // 2 = ACPI 2.0+
    rsdt_addr_32: u32,    // for ACPI 1.0; unused at rev 2+
    length: u32,          // 36
    xsdt_addr: u64,
    ext_checksum: u8,     // sum of all 36 bytes == 0
    reserved: [u8; 3],
}

#[repr(C, packed)]
struct AcpiTableHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,         // sum of entire table == 0
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// ACPI 6.4 FADT (Fixed ACPI Description Table). 276-byte formatted
/// area covers all hardware-reduced ACPI fields that boot loaders /
/// kernels look at. Most fields default to 0 — we fill only what the
/// firmware would non-trivially populate.
#[repr(C, packed)]
struct Fadt {
    header: AcpiTableHeader,
    firmware_ctrl: u32,         // 32-bit physical addr of FACS (0 if X_FIRMWARE_CTRL used)
    dsdt: u32,                  // 32-bit physical addr of DSDT (0 if X_DSDT used)
    _reserved1: u8,
    preferred_pm_profile: u8,   // 1 = Desktop, 2 = Mobile, 4 = Workstation
    sci_int: u16,
    smi_cmd: u32,
    acpi_enable: u8,
    acpi_disable: u8,
    s4bios_req: u8,
    pstate_cnt: u8,
    pm1a_evt_blk: u32,
    pm1b_evt_blk: u32,
    pm1a_cnt_blk: u32,
    pm1b_cnt_blk: u32,
    pm2_cnt_blk: u32,
    pm_tmr_blk: u32,
    gpe0_blk: u32,
    gpe1_blk: u32,
    pm1_evt_len: u8,
    pm1_cnt_len: u8,
    pm2_cnt_len: u8,
    pm_tmr_len: u8,
    gpe0_blk_len: u8,
    gpe1_blk_len: u8,
    gpe1_base: u8,
    cst_cnt: u8,
    p_lvl2_lat: u16,
    p_lvl3_lat: u16,
    flush_size: u16,
    flush_stride: u16,
    duty_offset: u8,
    duty_width: u8,
    day_alrm: u8,
    mon_alrm: u8,
    century: u8,
    iapc_boot_arch: u16,
    _reserved2: u8,
    flags: u32,
    reset_reg: [u8; 12],
    reset_value: u8,
    arm_boot_arch: u16,
    fadt_minor_version: u8,
    x_firmware_ctrl: u64,       // 64-bit FACS phys (preferred over firmware_ctrl)
    x_dsdt: u64,                // 64-bit DSDT phys (preferred over dsdt)
    x_pm1a_evt_blk: [u8; 12],
    x_pm1b_evt_blk: [u8; 12],
    x_pm1a_cnt_blk: [u8; 12],
    x_pm1b_cnt_blk: [u8; 12],
    x_pm2_cnt_blk: [u8; 12],
    x_pm_tmr_blk: [u8; 12],
    x_gpe0_blk: [u8; 12],
    x_gpe1_blk: [u8; 12],
    sleep_control_reg: [u8; 12],
    sleep_status_reg: [u8; 12],
    hypervisor_vendor_id: u64,  // populated by the host hypervisor; we keep 0
}

/// MADT header (44 bytes) + per-CPU Local APIC entries + IO APIC entry.
/// Variable-length tail of "Interrupt Controller Structure"s follows.
#[repr(C, packed)]
struct Madt {
    header: AcpiTableHeader,
    local_apic_address: u32,
    flags: u32,                 // bit 0 = "PCAT_COMPAT" — 8259 present
    // Local APIC + IO APIC entries appended at run time.
}

#[repr(C, packed)]
struct MadtLocalApic {
    type_: u8,                  // 0 = Local APIC
    length: u8,                 // 8
    acpi_processor_uid: u8,
    apic_id: u8,
    flags: u32,                 // bit 0 = enabled
}

/// MCFG (PCIe Memory-Mapped Configuration Space) — ACPI table that
/// publishes the base address used by `[bus][dev][func][reg]` MMIO
/// accesses, so guests with PCIe-aware drivers know where to find it.
#[repr(C, packed)]
struct Mcfg {
    header: AcpiTableHeader,
    _reserved: [u8; 8],
    // One allocation entry follows (16 bytes).
}

#[repr(C, packed)]
struct McfgAllocation {
    base_address: u64,
    segment_group: u16,
    start_bus: u8,
    end_bus: u8,
    _reserved: u32,
}

#[repr(C, packed)]
struct MadtIoApic {
    type_: u8,                  // 1 = IO APIC
    length: u8,                 // 12
    io_apic_id: u8,
    _reserved: u8,
    io_apic_address: u32,       // 0xFEC00000 standard
    gsi_base: u32,
}

/// MADT Interrupt Source Override (type 2, 10 bytes). Every real PC
/// firmware emits the ISA IRQ0 → GSI2 override because the 8254 timer is
/// wired to IO-APIC pin 2 (pin 0 carries the 8259 ExtINT cascade).
/// Without it the OS maps IRQ0 → GSI0 and the timer interrupt never
/// reaches the redirection entry we service.
#[repr(C, packed)]
struct MadtIntOverride {
    type_: u8,                  // 2 = Interrupt Source Override
    length: u8,                 // 10
    bus: u8,                    // 0 = ISA
    source: u8,                 // ISA IRQ number
    global_system_int: u32,     // GSI it maps to
    flags: u16,                 // 0 = conforms to bus (ISA: edge, active-high)
}

/// ACPI Generic Address Structure (GAS) — 12 bytes.
#[repr(C, packed)]
struct GenericAddress {
    address_space: u8,          // 0 = System Memory
    register_bit_width: u8,
    register_bit_offset: u8,
    access_size: u8,            // 4 = Q-word
    address: u64,
}

/// HPET ACPI 1.0a table — 56 bytes.
#[repr(C, packed)]
struct Hpet {
    header: AcpiTableHeader,
    event_timer_block_id: u32,  // hw ID + caps from HPET reg 0
    base_address: GenericAddress,
    hpet_number: u8,
    min_clock_tick: u16,        // min ticks between two periodic IRQs
    page_protection: u8,
}

/// FACS — Firmware ACPI Control Structure (ACPI 6.4 § 5.2.10). 64-byte
/// table referenced by FADT.x_firmware_ctrl; unlike the rest, it has
/// NO AcpiTableHeader (no checksum, no OEM ID) — it's a raw control
/// block exposed in low memory for the firmware/OS sleep handshake.
#[repr(C, packed)]
struct Facs {
    signature: [u8; 4],         // "FACS"
    length: u32,                // 64
    hardware_signature: u32,    // hash of hardware config (stable)
    firmware_waking_vector: u32,
    global_lock: u32,
    flags: u32,
    x_firmware_waking_vector: u64,
    version: u8,                // 2 for ACPI 6.x
    _reserved1: [u8; 3],
    ospm_flags: u32,
    _reserved2: [u8; 24],
}

/// SPCR — Serial Port Console Redirection Table. Tells Windows where
/// the boot-time serial console is. We point at COM1 0x3F8 which is
/// what our `serial.rs` already uses, so a guest OS can pick up the
/// same channel for kernel debug output.
#[repr(C, packed)]
struct Spcr {
    header: AcpiTableHeader,
    interface_type: u8,         // 0 = Full 16550
    _reserved1: [u8; 3],
    base_address: GenericAddress,
    interrupt_type: u8,         // 1 = 8259 PIC IRQ
    irq: u8,                    // legacy COM1 IRQ 4
    global_system_int: u32,
    baud_rate: u8,              // 7 = 115200
    parity: u8,
    stop_bits: u8,
    flow_control: u8,
    terminal_type: u8,
    _reserved2: u8,
    pci_device_id: u16,         // 0xFFFF = not a PCI device
    pci_vendor_id: u16,
    pci_bus: u8,
    pci_device: u8,
    pci_function: u8,
    pci_flags: u32,
    pci_segment: u8,
    _reserved3: u32,
}

/// WSMT — Windows SMM Mitigations Table. Microsoft-defined: tells
/// Windows the firmware implements specific anti-attack protections
/// (relevant on real SMM-capable platforms). We claim all three for
/// completeness — there's no SMM to actually protect, so the claim
/// is technically vacuous but matches modern firmware.
#[repr(C, packed)]
struct Wsmt {
    header: AcpiTableHeader,
    protection_flags: u32,
}

/// TPM2 — describes the TPM 2.0 CRB interface to the OS so Windows
/// can locate the locality-0 MMIO window and pick the right start
/// method (CRB = 7 per the TCG ACPI Specification).
#[repr(C, packed)]
struct Tpm2 {
    header: AcpiTableHeader,
    platform_class: u16,            // 0 = PC client
    _reserved: u16,
    control_area_address: u64,       // 0 for CRB direct-MMIO mode
    start_method: u32,               // 7 = CRB
    start_method_specific: [u8; 12], // unused for plain CRB
    log_area_min_length: u32,
    log_area_start_address: u64,
}

/// DSDT body — built programmatically via the `aml` encoder so PkgLength
/// and nesting stay correct as the namespace grows. Contents:
///
///   Scope (\_SB) {
///     Device (PCI0) {            ; PCIe root (PNP0A08 / PNP0A03)
///       _HID / _CID / _UID
///       _CRS                     ; bus + IO + 32-bit MMIO producer windows
///       _PRT                     ; INTA-D → IO-APIC GSI routing
///     }
///   }
///   Name (\_S5, Package(){5,0,0,0})  ; soft-off
///
/// The old hand-assembled body wrongly defined `Method(_OSI)` — a method the
/// OSPM already owns — which made ACPICA abort the table load with
/// AE_ALREADY_EXISTS and leave _S5 unresolved. The bridge also had no _CRS,
/// so the guest couldn't claim any device BAR window ("no compatible bridge
/// window") and no _PRT, so PCI interrupt routing was underivable.
fn build_dsdt_body() -> alloc::vec::Vec<u8> {
    use crate::acpi::aml;
    use alloc::vec;
    use alloc::vec::Vec;

    // _CRS: the resource windows the PCI root produces for its children.
    // The 32-bit MMIO window covers the BARs OVMF assigns (0x8000_0000..)
    // and stops below the 0xE000_0000 ECAM base.
    let mut res = Vec::new();
    res.extend(aml::bus_range(0x00, 0x00));
    res.extend(aml::io_range(0x0000, 0x0CF7)); // legacy IO, below the CF8/CFC config pair
    res.extend(aml::io_range(0x0D00, 0xFFFF)); // remaining PCI IO (includes ACPI PM 0x600)
    res.extend(aml::mem32_range(0x8000_0000, 0xDFFF_FFFF));
    let crs = aml::name("_CRS", aml::resource_template(res));

    let mut pci0 = Vec::new();
    pci0.extend(aml::name("_HID", aml::eisaid("PNP0A08")));
    pci0.extend(aml::name("_CID", aml::eisaid("PNP0A03")));
    pci0.extend(aml::name("_UID", aml::integer(0)));
    pci0.extend(crs);

    // _PRT (PCI interrupt routing). Safe to enable now that the guest TSC is
    // the step-filtered clock::now() (see intercept/rdtsc.rs): the host-TSC
    // jump that used to fire an RCU stall — fatal under ACPI IRQ routing — is
    // gone, so Linux's "Using ACPI for IRQ routing" path no longer crashes.
    const ENABLE_PRT: bool = true;
    if ENABLE_PRT {
        let mut entries: Vec<Vec<u8>> = Vec::new();
        for dev in 0u32..=8 {
            for pin in 0u32..4 {
                let gsi = 16 + ((dev + pin) & 3);
                entries.push(aml::package(vec![
                    aml::integer(((dev << 16) | 0xFFFF) as u64),
                    aml::integer(pin as u64),
                    aml::integer(0), // source 0 → use the global system interrupt below
                    aml::integer(gsi as u64),
                ]));
            }
        }
        pci0.extend(aml::name("_PRT", aml::package(entries)));
    }

    let mut body = Vec::new();
    body.extend(aml::scope("\\_SB", aml::device("PCI0", pci0)));
    body.extend(aml::name(
        "\\_S5",
        aml::package(vec![aml::integer(5), aml::integer(0), aml::integer(0), aml::integer(0)]),
    ));
    body
}

#[derive(Debug, Clone, Copy)]
pub struct Acpi {
    pub rsdp_phys: u64,
    pub xsdt_phys: u64,
    pub fadt_phys: u64,
    pub madt_phys: u64,
    pub mcfg_phys: u64,
    pub hpet_phys: u64,
    pub dsdt_phys: u64,
    pub ssdt_phys: u64,
    pub facs_phys: u64,
    pub spcr_phys: u64,
    pub wsmt_phys: u64,
    pub tpm2_phys: u64,
}

/// PCIe MMCONFIG base. 0xE000_0000 keeps it well clear of the LAPIC
/// (0xFEE00000) and IO APIC (0xFEC00000) windows.
pub const PCIE_MCFG_BASE: u64 = 0xE000_0000;

/// ICH9/Q35 ACPI PM I/O base. OVMF programs PMBASE here (LPC cfg 0x40) and
/// intercept/acpi_pm.rs answers the fixed-register block from it. The FADT
/// must publish the same base so the guest's PM1/PM-timer accesses land on
/// our emulator. Confirmed against the boot log (`[acpipm] PMBASE=0x600`).
const ICH9_PM_IO_BASE: u32 = 0x600;

#[derive(Debug)]
pub enum AcpiError {
    AllocFailed,
}

/// Byte offsets the fw_cfg table-loader patches at runtime (pointer
/// relocation + checksum fill). Derived from the packed structs above with
/// `offset_of!` so they can't drift if a field is reordered.
pub mod field {
    use super::{AcpiTableHeader, Fadt, Rsdp};
    pub const HEADER_CHECKSUM: usize = core::mem::offset_of!(AcpiTableHeader, checksum);
    pub const HEADER_SIZE: usize = core::mem::size_of::<AcpiTableHeader>();
    pub const FADT_FIRMWARE_CTRL: usize = core::mem::offset_of!(Fadt, firmware_ctrl);
    pub const FADT_DSDT: usize = core::mem::offset_of!(Fadt, dsdt);
    pub const FADT_X_FIRMWARE_CTRL: usize = core::mem::offset_of!(Fadt, x_firmware_ctrl);
    pub const FADT_X_DSDT: usize = core::mem::offset_of!(Fadt, x_dsdt);
    pub const RSDP_CHECKSUM: usize = core::mem::offset_of!(Rsdp, checksum);
    pub const RSDP_XSDT_ADDR: usize = core::mem::offset_of!(Rsdp, xsdt_addr);
    pub const RSDP_EXT_CHECKSUM: usize = core::mem::offset_of!(Rsdp, ext_checksum);
    /// RSDP is 36 bytes at ACPI 2.0+; the 1.0 checksum covers the first 20.
    pub const RSDP_LEN: usize = 36;
    pub const RSDP_V1_CHECKSUM_LEN: usize = 20;
    /// XSDT carries 8 × 64-bit table pointers (see `build_at`).
    pub const XSDT_ENTRY_COUNT: usize = 8;
}

// Neutral ACPI identity fallbacks — used only if no profile is active.
// Must NOT carry a hypervisor watermark: "VENEER"/"VNEE" gave the game
// away to anything parsing a single ACPI table. Default to a generic
// AMI-style firmware identity; the real values come from the active
// profile's board fields.
const FB_OEM_ID: [u8; 6] = *b"ALASKA";
const FB_OEM_TABLE_ID: [u8; 8] = *b"A M I   ";
const FB_CREATOR_ID: u32 = u32::from_le_bytes(*b"AMI ");

/// Pad/truncate a profile string to exactly `N` bytes (space fill on
/// short, truncate on long). ACPI OEM_ID is 6 bytes, OEM_TABLE_ID is 8
/// bytes per ACPI spec § 5.2.6 — both space-padded fixed-width fields.
fn fit<const N: usize>(src: &[u8], pad: u8) -> [u8; N] {
    let mut out = [pad; N];
    let n = src.len().min(N);
    out[..n].copy_from_slice(&src[..n]);
    out
}

fn current_oem_id() -> [u8; 6] {
    if let Some(p) = active::PROFILE.get() {
        let s = unsafe { core::ptr::addr_of!(p.hardware.board.acpi_oem_id).read_unaligned() };
        let bytes = s.as_bytes();
        if !bytes.is_empty() { return fit::<6>(bytes, b' '); }
        let m = unsafe { core::ptr::addr_of!(p.hardware.smbios.manufacturer).read_unaligned() };
        let mb = m.as_bytes();
        if !mb.is_empty() { return fit::<6>(mb, b' '); }
    }
    FB_OEM_ID
}

fn current_oem_table_id() -> [u8; 8] {
    if let Some(p) = active::PROFILE.get() {
        let s = unsafe { core::ptr::addr_of!(p.hardware.board.acpi_oem_table_id).read_unaligned() };
        let bytes = s.as_bytes();
        if !bytes.is_empty() { return fit::<8>(bytes, b' '); }
        let m = unsafe { core::ptr::addr_of!(p.hardware.smbios.product).read_unaligned() };
        let mb = m.as_bytes();
        if !mb.is_empty() { return fit::<8>(mb, b' '); }
    }
    FB_OEM_TABLE_ID
}

fn current_creator_id() -> u32 {
    if let Some(p) = active::PROFILE.get() {
        let s = unsafe { core::ptr::addr_of!(p.hardware.board.acpi_creator_id).read_unaligned() };
        let bytes = s.as_bytes();
        if !bytes.is_empty() { return u32::from_le_bytes(fit::<4>(bytes, b' ')); }
    }
    FB_CREATOR_ID
}

/// Standard IO APIC MMIO base on every x86 platform.
const IO_APIC_BASE: u32 = 0xFEC0_0000;
/// Standard Local APIC MMIO base.
const LOCAL_APIC_BASE: u32 = 0xFEE0_0000;

pub fn build(n_vcpus: usize) -> Result<Acpi, AcpiError> {
    // Allocate host page, deploy in place. `host_dest == guest_base` →
    // pointer values inside the tables equal their write targets
    // (legacy chain-load mode).
    let page = boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::RUNTIME_SERVICES_DATA,
        1,
    )
    .map_err(|_| AcpiError::AllocFailed)?;
    let base = page.as_ptr() as u64;
    Ok(unsafe { build_at(base, base, n_vcpus) })
}

/// Build ACPI tables into a caller-provided 4 KiB-aligned page.
///
/// - `host_dest`: host-physical address the table bytes are written to
///   (must be a writable 4 KiB region the caller owns).
/// - `guest_base`: address the tables will appear at from the guest's
///   point of view. Internal pointers (XSDT entries, RSDP.xsdt_addr,
///   FADT.dsdt / x_dsdt, etc.) use `guest_base + offset`. For chain-load
///   pass `guest_base == host_dest`; for nested-guest deploy into guest
///   RAM and pass `guest_base` = the guest-physical address that
///   `host_dest` translates to under NPT.
///
/// Returns an `Acpi` whose `*_phys` fields are *guest-visible* addresses
/// — feed `rsdp_phys` directly into `boot_params.acpi_rsdp_addr`.
///
/// # Safety
/// Caller must ensure `host_dest..host_dest+4096` is owned writable memory.
pub unsafe fn build_at(host_dest: u64, guest_base: u64, n_vcpus: usize) -> Acpi {
    // One page hosts every fixed table — sizes:
    //   RSDP @ 0x000  (36 B)
    //   XSDT @ 0x040  (header 36 + 8×8 entries = 100 B)
    //   FADT @ 0x100  (276 B)
    //   MADT @ 0x220  (44 header + 12 IOAPIC + 8×N_VCPU local APIC)
    // Up to 16 vCPUs fit; we cap there.
    unsafe { core::ptr::write_bytes(host_dest as *mut u8, 0u8, 4096) };

    let rsdp_dest = host_dest;
    let xsdt_dest = host_dest + 0x40;
    let fadt_dest = host_dest + 0x100;
    let madt_dest = host_dest + 0x220;
    let mcfg_dest = host_dest + 0x300;
    let hpet_dest = host_dest + 0x380;
    // DSDT carries _CRS + _PRT now (≈0.7 KiB), too big for the old 0x100
    // slot — give it the 2 KiB tail of the page (the other fixed tables all
    // end before 0x700).
    let dsdt_dest = host_dest + 0x800;
    let ssdt_dest = host_dest + 0x500;
    let facs_dest = host_dest + 0x540;
    let spcr_dest = host_dest + 0x580;
    let wsmt_dest = host_dest + 0x600;
    let tpm2_dest = host_dest + 0x680;

    let rsdp_phys = guest_base;
    let xsdt_phys = guest_base + 0x40;
    let fadt_phys = guest_base + 0x100;
    let madt_phys = guest_base + 0x220;
    let mcfg_phys = guest_base + 0x300;
    let hpet_phys = guest_base + 0x380;
    let dsdt_phys = guest_base + 0x800;
    let ssdt_phys = guest_base + 0x500;
    let facs_phys = guest_base + 0x540;
    let spcr_phys = guest_base + 0x580;
    let wsmt_phys = guest_base + 0x600;
    let tpm2_phys = guest_base + 0x680;

    let oem_id = current_oem_id();
    let oem_table_id = current_oem_table_id();
    let creator = current_creator_id();

    // ---- DSDT first (FADT will reference its physical address) ──────
    let dsdt_body = build_dsdt_body();
    let dsdt_header_size = core::mem::size_of::<AcpiTableHeader>();
    let dsdt_total = (dsdt_header_size + dsdt_body.len()) as u32;
    let dsdt_ptr = dsdt_dest as *mut AcpiTableHeader;
    unsafe {
        (*dsdt_ptr).signature = *b"DSDT";
        (*dsdt_ptr).length = dsdt_total;
        (*dsdt_ptr).revision = 2;          // ACPI 2.0+ DSDT
        (*dsdt_ptr).oem_id = oem_id;
        (*dsdt_ptr).oem_table_id = oem_table_id;
        (*dsdt_ptr).oem_revision = 1;
        (*dsdt_ptr).creator_id = creator;
        (*dsdt_ptr).creator_revision = 1;
        // Append AML body immediately after the header.
        let body_dst = (dsdt_dest + dsdt_header_size as u64) as *mut u8;
        core::ptr::copy_nonoverlapping(dsdt_body.as_ptr(), body_dst, dsdt_body.len());
        // Checksum over the whole table.
        let buf = core::slice::from_raw_parts(dsdt_dest as *const u8, dsdt_total as usize);
        let sum: u8 = buf.iter().copied().fold(0u8, u8::wrapping_add);
        (*dsdt_ptr).checksum = 0u8.wrapping_sub(sum);
    }

    // ---- FADT (Fixed ACPI Description Table) ----
    let fadt_size = core::mem::size_of::<Fadt>() as u32;
    let fadt_ptr = fadt_dest as *mut Fadt;
    unsafe {
        (*fadt_ptr).header.signature = *b"FACP";
        (*fadt_ptr).header.length = fadt_size;
        (*fadt_ptr).header.revision = 6;
        (*fadt_ptr).header.oem_id = oem_id;
        (*fadt_ptr).header.oem_table_id = oem_table_id;
        (*fadt_ptr).header.oem_revision = 1;
        (*fadt_ptr).header.creator_id = creator;
        (*fadt_ptr).header.creator_revision = 1;
        (*fadt_ptr).preferred_pm_profile = 1; // Desktop
        (*fadt_ptr).fadt_minor_version = 4;
        // CMOS century byte index — must match what intercept/rtc.rs
        // returns at index 0x32 (the canonical century location). Real
        // PCs put it at 0x32 since the ACPI 2.0 spec; some firmware
        // additionally mirrors at 0x50. Without this field Linux's
        // RTC driver only reads the 2-digit year (CMOS 0x09) and rolls
        // over every 100 years.
        (*fadt_ptr).century = 0x32;
        // Legacy (NOT hardware-reduced) ACPI. We emulate the full ICH9/Q35
        // fixed-register set, so the OS must drive the PIT/PIC/RTC and the
        // ACPI PM timer. Advertising hardware-reduced earlier made Linux skip
        // the PIT, fail TSC + LAPIC-timer calibration ("Unable to calibrate
        // against PIT", "No reference (HPET/PMTIMER)") and hang with no
        // clockevent. PM blocks sit at the PMBASE OVMF programs; acpi_pm.rs
        // answers the timer at PMBASE+0x08.
        (*fadt_ptr).sci_int = 9;
        (*fadt_ptr).pm1a_evt_blk = ICH9_PM_IO_BASE;
        (*fadt_ptr).pm1a_cnt_blk = ICH9_PM_IO_BASE + 0x04;
        (*fadt_ptr).pm_tmr_blk = ICH9_PM_IO_BASE + 0x08;
        (*fadt_ptr).gpe0_blk = ICH9_PM_IO_BASE + 0x20;
        (*fadt_ptr).pm1_evt_len = 4;
        (*fadt_ptr).pm1_cnt_len = 2;
        (*fadt_ptr).pm_tmr_len = 4;
        (*fadt_ptr).gpe0_blk_len = 4;
        // WBINVD | PROC_C1 | no power button | no sleep button |
        // USE_PLATFORM_CLOCK. PM timer is 24-bit, so TMR_VAL_EXT stays clear.
        (*fadt_ptr).flags = (1u32 << 0) | (1u32 << 2) | (1u32 << 4) | (1u32 << 5) | (1u32 << 15);
        // DSDT pointers — both 32-bit and 64-bit forms set. Windows
        // prefers x_dsdt when non-zero (ACPI 5.0+).
        (*fadt_ptr).dsdt = dsdt_phys as u32;
        (*fadt_ptr).x_dsdt = dsdt_phys;
        // FACS pointer — required for ACPI sleep state handoff.
        (*fadt_ptr).firmware_ctrl = facs_phys as u32;
        (*fadt_ptr).x_firmware_ctrl = facs_phys;
        // Extended (GAS) PM register blocks. With FADT revision >= 3 (we set 6),
        // Windows HAL's HalpAcpiInitializePmRegisters uses the X_ PM blocks and
        // bugchecks 0x5C HAL_INITIALIZATION_FAILED if they're left zero while
        // the 32-bit blocks are set — the asymmetry the DSDT/FACS X_ fields
        // above already avoid. Mirror the 32-bit blocks as SystemIO GAS:
        // address_space=1 (SystemIO), bit_width = LEN*8, access_size matches.
        let gas_io = |width: u8, access: u8, addr: u32| -> [u8; 12] {
            let mut g = [0u8; 12];
            g[0] = 1; // SystemIO
            g[1] = width; // register bit width
            g[3] = access; // access size (2=word, 3=dword)
            g[4..12].copy_from_slice(&(addr as u64).to_le_bytes());
            g
        };
        (*fadt_ptr).x_pm1a_evt_blk = gas_io(32, 2, ICH9_PM_IO_BASE); // PM1_EVT_LEN=4
        (*fadt_ptr).x_pm1a_cnt_blk = gas_io(16, 2, ICH9_PM_IO_BASE + 0x04); // PM1_CNT_LEN=2
        (*fadt_ptr).x_pm_tmr_blk = gas_io(32, 3, ICH9_PM_IO_BASE + 0x08); // PM_TMR_LEN=4
        let buf = core::slice::from_raw_parts(fadt_dest as *const u8, fadt_size as usize);
        let sum: u8 = buf.iter().copied().fold(0u8, u8::wrapping_add);
        (*fadt_ptr).header.checksum = 0u8.wrapping_sub(sum);
    }

    // ---- MADT (Multiple APIC Description Table) ----
    let n = n_vcpus.min(16);
    let madt_header_size = core::mem::size_of::<Madt>();
    let ioapic_size = core::mem::size_of::<MadtIoApic>();
    let override_size = core::mem::size_of::<MadtIntOverride>();
    let lapic_size = core::mem::size_of::<MadtLocalApic>();
    let madt_total = (madt_header_size + ioapic_size + override_size + n * lapic_size) as u32;
    let madt_ptr = madt_dest as *mut Madt;
    unsafe {
        (*madt_ptr).header.signature = *b"APIC";
        (*madt_ptr).header.length = madt_total;
        (*madt_ptr).header.revision = 5;
        (*madt_ptr).header.oem_id = oem_id;
        (*madt_ptr).header.oem_table_id = oem_table_id;
        (*madt_ptr).header.oem_revision = 1;
        (*madt_ptr).header.creator_id = creator;
        (*madt_ptr).header.creator_revision = 1;
        (*madt_ptr).local_apic_address = LOCAL_APIC_BASE;
        (*madt_ptr).flags = 1; // PCAT_COMPAT — legacy 8259 present
    }
    // IO APIC entry immediately after the header.
    let ioapic_ptr = (madt_dest + madt_header_size as u64) as *mut MadtIoApic;
    unsafe {
        (*ioapic_ptr).type_ = 1;
        (*ioapic_ptr).length = ioapic_size as u8;
        (*ioapic_ptr).io_apic_id = 1;
        (*ioapic_ptr).io_apic_address = IO_APIC_BASE;
        (*ioapic_ptr).gsi_base = 0;
    }
    // ISA IRQ0 → GSI2 override, immediately after the IO APIC entry.
    let override_ptr =
        (madt_dest + (madt_header_size + ioapic_size) as u64) as *mut MadtIntOverride;
    unsafe {
        (*override_ptr).type_ = 2;
        (*override_ptr).length = override_size as u8;
        (*override_ptr).bus = 0;
        (*override_ptr).source = 0;
        (*override_ptr).global_system_int = 2;
        (*override_ptr).flags = 0;
    }
    // Local APIC entry per vCPU. APIC IDs are SEQUENTIAL (0, 1, 2, …) to
    // stay consistent with the topology veneer advertises via CPUID leaf
    // 0xB: 1 thread per core (SMT shift = 0) means each core gets the next
    // integer x2APIC ID with no even-only gaps. The earlier `i*2` pattern
    // implied 2 threads/core (an SMT layout we don't expose), contradicting
    // leaf 0xB / leaf 0x8000001E. Sequential IDs also pack into the
    // ceil(log2(N)) core-shift width leaf 0x80000008.ECX[15:12] reports.
    let mut lapic_off = madt_dest + (madt_header_size + ioapic_size + override_size) as u64;
    for i in 0..n {
        let lapic_ptr = lapic_off as *mut MadtLocalApic;
        unsafe {
            (*lapic_ptr).type_ = 0;
            (*lapic_ptr).length = lapic_size as u8;
            (*lapic_ptr).acpi_processor_uid = i as u8;
            (*lapic_ptr).apic_id = i as u8;
            (*lapic_ptr).flags = 1; // enabled
        }
        lapic_off += lapic_size as u64;
    }
    // MADT checksum.
    unsafe {
        let buf = core::slice::from_raw_parts(madt_dest as *const u8, madt_total as usize);
        let sum: u8 = buf.iter().copied().fold(0u8, u8::wrapping_add);
        (*madt_ptr).header.checksum = 0u8.wrapping_sub(sum);
    }

    // ---- MCFG (PCIe MMCONFIG) ----
    let mcfg_header_size = core::mem::size_of::<Mcfg>();
    let mcfg_alloc_size = core::mem::size_of::<McfgAllocation>();
    let mcfg_total = (mcfg_header_size + mcfg_alloc_size) as u32;
    let mcfg_ptr = mcfg_dest as *mut Mcfg;
    unsafe {
        (*mcfg_ptr).header.signature = *b"MCFG";
        (*mcfg_ptr).header.length = mcfg_total;
        (*mcfg_ptr).header.revision = 1;
        (*mcfg_ptr).header.oem_id = oem_id;
        (*mcfg_ptr).header.oem_table_id = oem_table_id;
        (*mcfg_ptr).header.oem_revision = 1;
        (*mcfg_ptr).header.creator_id = creator;
        (*mcfg_ptr).header.creator_revision = 1;
    }
    let mcfg_alloc_ptr = (mcfg_dest + mcfg_header_size as u64) as *mut McfgAllocation;
    unsafe {
        (*mcfg_alloc_ptr).base_address = PCIE_MCFG_BASE;
        (*mcfg_alloc_ptr).segment_group = 0;
        (*mcfg_alloc_ptr).start_bus = 0;
        (*mcfg_alloc_ptr).end_bus = 0; // single bus
        (*mcfg_alloc_ptr)._reserved = 0;
    }
    unsafe {
        let buf = core::slice::from_raw_parts(mcfg_dest as *const u8, mcfg_total as usize);
        let sum: u8 = buf.iter().copied().fold(0u8, u8::wrapping_add);
        (*mcfg_ptr).header.checksum = 0u8.wrapping_sub(sum);
    }

    // ---- HPET ----
    let hpet_size = core::mem::size_of::<Hpet>() as u32;
    let hpet_ptr = hpet_dest as *mut Hpet;
    unsafe {
        (*hpet_ptr).header.signature = *b"HPET";
        (*hpet_ptr).header.length = hpet_size;
        (*hpet_ptr).header.revision = 1;
        (*hpet_ptr).header.oem_id = oem_id;
        (*hpet_ptr).header.oem_table_id = oem_table_id;
        (*hpet_ptr).header.oem_revision = 1;
        (*hpet_ptr).header.creator_id = creator;
        (*hpet_ptr).header.creator_revision = 1;
        // event_timer_block_id encodes the upper half of HPET reg 0
        // (general capabilities): Vendor ID (Intel 0x8086) in bits
        // 31:16, LEG_RT_CAP bit 15, COUNT_SIZE bit 13, NUM_TIM_CAP
        // bits 12:8 (= 2 for 3 timers), rev bits 7:0 = 0x01.
        // LEG_RT_CAP (bit 15) cleared to match the MMIO caps register: we
        // route the boot tick through the PIT, not HPET legacy-replacement.
        (*hpet_ptr).event_timer_block_id = (0x8086 << 16) | (1 << 13) | (2 << 8) | 0x01;
        (*hpet_ptr).base_address = GenericAddress {
            address_space: 0,                  // System Memory
            register_bit_width: 64,
            register_bit_offset: 0,
            access_size: 4,                    // Q-word
            address: crate::devices::irq::hpet::HPET_BASE,
        };
        (*hpet_ptr).hpet_number = 0;
        (*hpet_ptr).min_clock_tick = 0x1000;
        (*hpet_ptr).page_protection = 0;
        let buf = core::slice::from_raw_parts(hpet_dest as *const u8, hpet_size as usize);
        let sum: u8 = buf.iter().copied().fold(0u8, u8::wrapping_add);
        (*hpet_ptr).header.checksum = 0u8.wrapping_sub(sum);
    }

    // ---- SSDT (empty body — extends DSDT namespace but adds no methods) ----
    let ssdt_total = core::mem::size_of::<AcpiTableHeader>() as u32;
    let ssdt_ptr = ssdt_dest as *mut AcpiTableHeader;
    unsafe {
        (*ssdt_ptr).signature = *b"SSDT";
        (*ssdt_ptr).length = ssdt_total;
        (*ssdt_ptr).revision = 2;
        (*ssdt_ptr).oem_id = oem_id;
        (*ssdt_ptr).oem_table_id = oem_table_id;
        (*ssdt_ptr).oem_revision = 1;
        (*ssdt_ptr).creator_id = creator;
        (*ssdt_ptr).creator_revision = 1;
        let buf = core::slice::from_raw_parts(ssdt_dest as *const u8, ssdt_total as usize);
        let sum: u8 = buf.iter().copied().fold(0u8, u8::wrapping_add);
        (*ssdt_ptr).checksum = 0u8.wrapping_sub(sum);
    }

    // ---- FACS (no checksum, no OEM — raw control block) ----
    let facs_size = core::mem::size_of::<Facs>() as u32;
    let facs_ptr = facs_dest as *mut Facs;
    unsafe {
        core::ptr::write_bytes(facs_ptr as *mut u8, 0u8, facs_size as usize);
        (*facs_ptr).signature = *b"FACS";
        (*facs_ptr).length = facs_size;
        // OEM hardware signature (S4-resume config hash). Real firmware
        // commonly leaves this 0; a fixed magic was a hypervisor tell.
        (*facs_ptr).hardware_signature = 0;
        (*facs_ptr).version = 2;
    }

    // ---- SPCR (COM1 0x3F8 @ 115200) ----
    let spcr_size = core::mem::size_of::<Spcr>() as u32;
    let spcr_ptr = spcr_dest as *mut Spcr;
    unsafe {
        core::ptr::write_bytes(spcr_ptr as *mut u8, 0u8, spcr_size as usize);
        (*spcr_ptr).header.signature = *b"SPCR";
        (*spcr_ptr).header.length = spcr_size;
        (*spcr_ptr).header.revision = 2;
        (*spcr_ptr).header.oem_id = oem_id;
        (*spcr_ptr).header.oem_table_id = oem_table_id;
        (*spcr_ptr).header.oem_revision = 1;
        (*spcr_ptr).header.creator_id = creator;
        (*spcr_ptr).header.creator_revision = 1;
        (*spcr_ptr).interface_type = 0;            // 16550 full
        (*spcr_ptr).base_address = GenericAddress {
            address_space: 1,                       // System I/O
            register_bit_width: 8,
            register_bit_offset: 0,
            access_size: 1,                         // byte
            address: 0x3F8,
        };
        (*spcr_ptr).interrupt_type = 1;             // 8259 PIC
        (*spcr_ptr).irq = 4;
        (*spcr_ptr).baud_rate = 7;                  // 115200
        (*spcr_ptr).parity = 0;
        (*spcr_ptr).stop_bits = 1;
        (*spcr_ptr).flow_control = 0;
        (*spcr_ptr).terminal_type = 3;              // ANSI
        (*spcr_ptr).pci_device_id = 0xFFFF;
        (*spcr_ptr).pci_vendor_id = 0xFFFF;
        let buf = core::slice::from_raw_parts(spcr_dest as *const u8, spcr_size as usize);
        let sum: u8 = buf.iter().copied().fold(0u8, u8::wrapping_add);
        (*spcr_ptr).header.checksum = 0u8.wrapping_sub(sum);
    }

    // ---- WSMT (Windows SMM Mitigations) ────────────────────────────
    let wsmt_size = core::mem::size_of::<Wsmt>() as u32;
    let wsmt_ptr = wsmt_dest as *mut Wsmt;
    unsafe {
        (*wsmt_ptr).header.signature = *b"WSMT";
        (*wsmt_ptr).header.length = wsmt_size;
        (*wsmt_ptr).header.revision = 1;
        (*wsmt_ptr).header.oem_id = oem_id;
        (*wsmt_ptr).header.oem_table_id = oem_table_id;
        (*wsmt_ptr).header.oem_revision = 1;
        (*wsmt_ptr).header.creator_id = creator;
        (*wsmt_ptr).header.creator_revision = 1;
        // Claim FIXED_COMM_BUFFERS (bit 0) + COMM_BUFFER_NESTED_PTR (bit 1)
        // + SYSTEM_RESOURCE_PROTECTION (bit 2).
        (*wsmt_ptr).protection_flags = 0x0000_0007;
        let buf = core::slice::from_raw_parts(wsmt_dest as *const u8, wsmt_size as usize);
        let sum: u8 = buf.iter().copied().fold(0u8, u8::wrapping_add);
        (*wsmt_ptr).header.checksum = 0u8.wrapping_sub(sum);
    }

    // ---- TPM2 (TCG ACPI: TPM 2.0 interface descriptor) ─────────────
    let tpm2_size = core::mem::size_of::<Tpm2>() as u32;
    let tpm2_ptr = tpm2_dest as *mut Tpm2;
    unsafe {
        core::ptr::write_bytes(tpm2_ptr as *mut u8, 0u8, tpm2_size as usize);
        (*tpm2_ptr).header.signature = *b"TPM2";
        (*tpm2_ptr).header.length = tpm2_size;
        (*tpm2_ptr).header.revision = 4;        // TCG ACPI 1.3+
        (*tpm2_ptr).header.oem_id = oem_id;
        (*tpm2_ptr).header.oem_table_id = oem_table_id;
        (*tpm2_ptr).header.oem_revision = 1;
        (*tpm2_ptr).header.creator_id = creator;
        (*tpm2_ptr).header.creator_revision = 1;
        (*tpm2_ptr).platform_class = 0;          // PC client
        (*tpm2_ptr).control_area_address = 0;    // CRB direct-MMIO mode
        (*tpm2_ptr).start_method = 7;            // CRB
        let buf = core::slice::from_raw_parts(tpm2_dest as *const u8, tpm2_size as usize);
        let sum: u8 = buf.iter().copied().fold(0u8, u8::wrapping_add);
        (*tpm2_ptr).header.checksum = 0u8.wrapping_sub(sum);
    }

    // ---- XSDT (FADT + MADT + MCFG + HPET + SSDT + SPCR + WSMT + TPM2) ─
    let xsdt_header_size = core::mem::size_of::<AcpiTableHeader>() as u32;
    let xsdt_total = xsdt_header_size + (8 * 8); // 8 × 64-bit pointers
    let xsdt_ptr = xsdt_dest as *mut AcpiTableHeader;
    unsafe {
        (*xsdt_ptr).signature = *b"XSDT";
        (*xsdt_ptr).length = xsdt_total;
        (*xsdt_ptr).revision = 1;
        (*xsdt_ptr).checksum = 0;
        (*xsdt_ptr).oem_id = oem_id;
        (*xsdt_ptr).oem_table_id = oem_table_id;
        (*xsdt_ptr).oem_revision = 1;
        (*xsdt_ptr).creator_id = creator;
        (*xsdt_ptr).creator_revision = 1;
        let entries = (xsdt_dest + xsdt_header_size as u64) as *mut u64;
        entries.add(0).write_unaligned(fadt_phys);
        entries.add(1).write_unaligned(madt_phys);
        entries.add(2).write_unaligned(mcfg_phys);
        entries.add(3).write_unaligned(hpet_phys);
        entries.add(4).write_unaligned(ssdt_phys);
        entries.add(5).write_unaligned(spcr_phys);
        entries.add(6).write_unaligned(wsmt_phys);
        entries.add(7).write_unaligned(tpm2_phys);
        let buf = core::slice::from_raw_parts(xsdt_dest as *const u8, xsdt_total as usize);
        let sum: u8 = buf.iter().copied().fold(0u8, u8::wrapping_add);
        (*xsdt_ptr).checksum = 0u8.wrapping_sub(sum);
    }

    // ---- RSDP ----
    let rsdp_ptr = rsdp_dest as *mut Rsdp;
    unsafe {
        (*rsdp_ptr).signature = *b"RSD PTR ";
        (*rsdp_ptr).oem_id = oem_id;
        (*rsdp_ptr).revision = 2;
        (*rsdp_ptr).rsdt_addr_32 = 0;
        (*rsdp_ptr).length = 36;
        (*rsdp_ptr).xsdt_addr = xsdt_phys;
        (*rsdp_ptr).reserved = [0; 3];
        // First-20-bytes checksum (ACPI 1.0 part).
        let buf20 = core::slice::from_raw_parts(rsdp_dest as *const u8, 20);
        let s1: u8 = buf20.iter().copied().fold(0u8, u8::wrapping_add);
        (*rsdp_ptr).checksum = 0u8.wrapping_sub(s1);
        // Full-36-bytes checksum.
        let buf36 = core::slice::from_raw_parts(rsdp_dest as *const u8, 36);
        let s2: u8 = buf36.iter().copied().fold(0u8, u8::wrapping_add);
        (*rsdp_ptr).ext_checksum = 0u8.wrapping_sub(s2);
    }

    Acpi {
        rsdp_phys,
        xsdt_phys,
        fadt_phys,
        madt_phys,
        mcfg_phys,
        hpet_phys,
        dsdt_phys,
        ssdt_phys,
        facs_phys,
        spcr_phys,
        wsmt_phys,
        tpm2_phys,
    }
}
