//! Linux bzImage loader for SVM-guest entry.
//!
//! Loads a Linux/x86_64 bzImage + initramfs + cmdline into UEFI memory
//! (which is identity-mapped, so host-physical == guest-physical under
//! our 512 GiB-identity NPT) and constructs the `boot_params` struct
//! that the 64-bit kernel entry point expects in RSI.
//!
//! We deliberately bypass the EFI handover entry (offset 0x264) so we
//! don't have to in-guest emulate the UEFI BootServices table. Instead
//! we jump straight to the kernel's 64-bit entry point (`startup_64`),
//! which assumes:
//!
//!   - long mode active (CR0.PG=1 / CR4.PAE=1 / EFER.LME=1 / LMA=1)
//!   - identity-mapped paging covering boot_params + kernel + initramfs
//!   - GDT loaded with __KERNEL_CS (0x10) and __KERNEL_DS (0x18)
//!   - RFLAGS.IF = 0 (interrupts off)
//!   - RSI = boot_params* (the only argument)
//!
//! The VMCB setup for that environment lives in `vmcb::init_guest_linux`.
//! This module is responsible for the memory layout and boot_params fill.
//!
//! ## bzImage layout we depend on
//!
//! Offset 0x1F1..0x2D0 = setup_header (boot protocol 2.15 here).
//! Offset (setup_sects * 512) = start of the protected-mode kernel blob
//! (= 32-bit decompressor stub + compressed kernel). The 32-bit entry is
//! at offset 0 of that blob; the 64-bit entry is at offset 0x200, per
//! `Documentation/x86/boot.rst` "64-bit BOOT PROTOCOL".
//!
//! We copy the blob to `pref_address` (0x01000000 = 16 MiB) and aim
//! VMCB.state.rip at `pref_address + 0x200`.
//!
//! ## boot_params we fill
//!
//! Only the fields the kernel actually reads early. Everything else is
//! zero, which matches what a minimal kexec-style loader does.
//!
//!   - `setup_header` (offset 0x1F1): copied verbatim from the bzImage
//!     (it already encodes pref_address / init_size / version etc.),
//!     then patched with the loader-specific fields below.
//!   - `setup_header.type_of_loader = 0xFF` (Undefined)
//!   - `setup_header.loadflags |= 0x01` (LOADED_HIGH; kernel is above 1M)
//!   - `setup_header.cmd_line_ptr = <cmdline guest_phys>`
//!   - `setup_header.ramdisk_image / ramdisk_size = <initramfs>`
//!   - `setup_header.heap_end_ptr = 0xFE00`
//!   - `e820_entries` + `e820_table` (memory map at offset 0x2D0)
//!   - `acpi_rsdp_addr` (offset 0x070) — lets the kernel skip the
//!     legacy BIOS RSDP scan and pick up our spoofed ACPI directly.

extern crate alloc;
use alloc::vec::Vec;



// ---- bzImage setup_header field offsets (within the bzImage file) ---------

const HDR_TYPE_OF_LOADER:    usize = 0x210;
const HDR_LOADFLAGS:         usize = 0x211;
const HDR_RAMDISK_IMAGE:     usize = 0x218;
const HDR_RAMDISK_SIZE:      usize = 0x21C;
const HDR_HEAP_END_PTR:      usize = 0x224;
const HDR_CMD_LINE_PTR:      usize = 0x228;


// xloadflags bits

// loadflags bits
const LOADFLAG_LOADED_HIGH:      u8 = 1 << 0;

// ---- boot_params struct offsets (within the 4 KiB struct) -----------------

const BP_ACPI_RSDP_ADDR:  usize = 0x070;  // u64
const BP_E820_ENTRIES:    usize = 0x1E8;  // u8
const BP_E820_TABLE:      usize = 0x2D0;  // 128 entries × 20 byte
const BP_SIZE:            usize = 4096;

const E820_ENTRY_SIZE: usize = 20;

const E820_RAM:        u32 = 1;
const E820_RESERVED:   u32 = 2;
const E820_ACPI:       u32 = 3;

// ---- guest physical layout (under our identity NPT, == host physical) ----

/// 4 KiB-aligned boot_params home. Below 1 MiB (kernel scans for it via
/// the value we put in RSI, not via a fixed location, so the address
/// itself isn't load-bearing; we just pick a free conventional-memory
/// page below the kernel).
pub const BOOT_PARAMS_PHYS: u64 = 0x0009_0000;

/// cmdline buffer. Right above boot_params, still under 1 MiB.
pub const CMDLINE_PHYS:     u64 = 0x0009_2000;

/// 16 KiB scratch stack for early kernel entry (verify_cpu, decompressor
/// stub) to push/pop into. Must be a page we explicitly reserve --
/// using any free conventional-memory address blindly hands us stale
/// UEFI BootServices data on the first pop. RSP is set to the *top*
/// of the region; stack grows down toward STACK_PHYS.
pub use veneer_vmm::guest_mem::{STACK_BYTES, STACK_PHYS, STACK_TOP};


/// Guest page table — 4-level identity map for guest_phys 0..1 GiB.
/// PML4 at GUEST_PT_PHYS, PDPT at GUEST_PT_PHYS + 0x1000. One 1-GiB
/// huge entry covers all of guest RAM. Set guest CR3 to this so the
/// decompressor's first instructions can do their LIDT/LGDT/etc reads
/// without faulting on UEFI's host-only page table (which is now
/// inaccessible because NPT isolates guest_phys from host_phys).
pub const GUEST_PT_PHYS:    u64 = 0x0007_0000;


/// initramfs base. Above the kernel's 42 MiB init_size footprint with
/// margin.
pub const INITRD_PHYS:      u64 = 0x1800_0000;

// ---- public types ---------------------------------------------------------

#[derive(Debug)]
pub enum LoaderError {
    KernelTooSmall,
    BadHdrMagic,
    UnsupportedVersion(u16),
    CmdlineTooLong,
    InitrdTooLarge,
    AllocFailed,
}

pub struct LoadedKernel {
    pub entry_rip: u64,
    pub boot_params_phys: u64,
    pub init_size: u32,
    pub host_ram_base: u64,
    pub guest_cr3: u64,
}


// ---- top-level load() ------------------------------------------------------

/// Stage a bzImage + initramfs + cmdline at the fixed guest-physical
/// addresses above and produce the `LoadedKernel` handle that
/// `enter_linux_guest` will hand off to VMRUN.
///
/// `bzimage` is the raw file bytes (whatever ESP gave us). `initrd` is
/// the initramfs cpio.gz bytes. `cmdline` is the kernel command line
/// (NUL terminator added automatically).
///
/// `acpi_rsdp_phys` is our own RSDP physical address (from
/// `acpi::build()`), so the kernel can skip the legacy BIOS scan.
/// Total low guest RAM (below the 0x80000000 device-MMIO hole), handed to
/// the guest as N contiguous 1-GiB NPT huge pages. 2 GiB is the ceiling
/// without a split memory map (RAM above the hole would collide with the
/// PCI/ECAM/LAPIC MMIO at 0x80000000+); more RAM needs a high region above
/// 4 GiB. Windows PE wants ~2 GiB, so this is the no-split maximum.
pub use veneer_vmm::guest_mem::GUEST_RAM_BYTES;

/// Translate a guest-physical address inside [0, GUEST_RAM_BYTES) to
/// the host-physical (== host-virtual under UEFI identity paging) where
/// we actually wrote that page. Returns None for OOB.
#[inline]
fn g2h(host_ram_base: u64, gpa: u64) -> Option<u64> {
    if gpa < GUEST_RAM_BYTES {
        Some(host_ram_base + gpa)
    } else {
        None
    }
}

/// Load a raw vmlinux ELF directly into guest memory by paddr, bypassing
/// the bzImage decompressor entirely. KVM/kvmtool-style.
///
/// `elf_bytes` is the uncompressed vmlinux ELF (produced by
/// `scripts/extract-vmlinux bzImage`). Each PT_LOAD segment is copied
/// to its declared `p_paddr` (translated through our isolated NPT to
/// `host_ram_base + p_paddr`). BSS-style mem-larger-than-file regions
/// are zero-filled. Entry RIP is taken from the ELF header (already a
/// physical address since the kernel linker subtracts LOAD_OFFSET).
///
/// Returns the same `LoadedKernel` handle as `load()` so the caller
/// path stays identical.
pub fn load_elf(
    elf_bytes: &[u8],
    initrd:  &[u8],
    cmdline: &str,
    acpi_rsdp_phys: u64,
    host_ram_base: u64,
) -> Result<LoadedKernel, LoaderError> {
    if elf_bytes.len() < 64 || &elf_bytes[0..4] != b"\x7fELF" {
        return Err(LoaderError::BadHdrMagic);
    }
    if elf_bytes[4] != 2 { // ELFCLASS64
        return Err(LoaderError::UnsupportedVersion(elf_bytes[4] as u16));
    }
    let e_entry = u64::from_le_bytes(elf_bytes[0x18..0x20].try_into().unwrap());
    let e_phoff = u64::from_le_bytes(elf_bytes[0x20..0x28].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(elf_bytes[0x36..0x38].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(elf_bytes[0x38..0x3A].try_into().unwrap()) as usize;

    if cmdline.len() + 1 > 2048 {
        return Err(LoaderError::CmdlineTooLong);
    }
    if initrd.len() > MAX_INITRD_BYTES_HINT {
        return Err(LoaderError::InitrdTooLarge);
    }

    sprintln!(
        "[linux-elf] entry=0x{:016x} phoff=0x{:x} phnum={} phentsize={}",
        e_entry, e_phoff, e_phnum, e_phentsize,
    );

    // Stack zero
    let stack_host = g2h(host_ram_base, STACK_PHYS).ok_or(LoaderError::AllocFailed)?;
    unsafe { core::ptr::write_bytes(stack_host as *mut u8, 0u8, STACK_BYTES as usize) };

    // Page table
    let pml4_gpa = GUEST_PT_PHYS;
    let pdpt_gpa = GUEST_PT_PHYS + 0x1000;
    let pml4_host = g2h(host_ram_base, pml4_gpa).ok_or(LoaderError::AllocFailed)?;
    let pdpt_host = g2h(host_ram_base, pdpt_gpa).ok_or(LoaderError::AllocFailed)?;
    unsafe {
        core::ptr::write_bytes(pml4_host as *mut u8, 0u8, 4096);
        core::ptr::write_bytes(pdpt_host as *mut u8, 0u8, 4096);
        *(pml4_host as *mut u64) = pdpt_gpa | 0x3;
        *(pdpt_host as *mut u64) = 0u64 | 0x83;
    }

    // Copy each PT_LOAD by its declared paddr -- this is the whole
    // point of using vmlinux ELF directly. The bzImage decompressor
    // can't be trusted to place .data/.bss correctly under our NPT.
    let mut loaded_min_paddr = u64::MAX;
    let mut loaded_max_paddr = 0u64;
    for i in 0..e_phnum {
        let ph_off = e_phoff + i * e_phentsize;
        if ph_off + e_phentsize > elf_bytes.len() {
            return Err(LoaderError::KernelTooSmall);
        }
        let p_type = u32::from_le_bytes(elf_bytes[ph_off..ph_off + 4].try_into().unwrap());
        if p_type != 1 {     // PT_LOAD only
            continue;
        }
        let p_offset = u64::from_le_bytes(elf_bytes[ph_off + 8..ph_off + 16].try_into().unwrap()) as usize;
        let p_vaddr = u64::from_le_bytes(elf_bytes[ph_off + 16..ph_off + 24].try_into().unwrap());
        let p_paddr = u64::from_le_bytes(elf_bytes[ph_off + 24..ph_off + 32].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(elf_bytes[ph_off + 32..ph_off + 40].try_into().unwrap()) as usize;
        let p_memsz  = u64::from_le_bytes(elf_bytes[ph_off + 40..ph_off + 48].try_into().unwrap()) as usize;

        if p_paddr + p_memsz as u64 > GUEST_RAM_BYTES {
            sprintln!(
                "[linux-elf] PT_LOAD #{} extends past 1 GiB guest RAM (paddr=0x{:x}+{}); skipping",
                i, p_paddr, p_memsz,
            );
            continue;
        }
        let dst_host = g2h(host_ram_base, p_paddr).ok_or(LoaderError::AllocFailed)?;
        unsafe {
            core::ptr::write_bytes(dst_host as *mut u8, 0u8, p_memsz);
            if p_filesz > 0 {
                if p_offset + p_filesz > elf_bytes.len() {
                    return Err(LoaderError::KernelTooSmall);
                }
                core::ptr::copy_nonoverlapping(
                    elf_bytes.as_ptr().add(p_offset),
                    dst_host as *mut u8,
                    p_filesz,
                );
            }
        }
        sprintln!(
            "[linux-elf] PT_LOAD #{}: paddr=0x{:08x} vaddr=0x{:016x} filesz={} memsz={}",
            i, p_paddr, p_vaddr, p_filesz, p_memsz,
        );
        if p_paddr < loaded_min_paddr { loaded_min_paddr = p_paddr; }
        if p_paddr + p_memsz as u64 > loaded_max_paddr { loaded_max_paddr = p_paddr + p_memsz as u64; }
    }
    sprintln!(
        "[linux-elf] kernel paddr range = 0x{:08x}..0x{:08x}",
        loaded_min_paddr, loaded_max_paddr,
    );

    // initrd
    let initrd_host = g2h(host_ram_base, INITRD_PHYS).ok_or(LoaderError::AllocFailed)?;
    unsafe {
        core::ptr::copy_nonoverlapping(initrd.as_ptr(), initrd_host as *mut u8, initrd.len());
    }

    // cmdline
    let cmdline_host = g2h(host_ram_base, CMDLINE_PHYS).ok_or(LoaderError::AllocFailed)?;
    unsafe {
        core::ptr::write_bytes(cmdline_host as *mut u8, 0u8, 4096);
        core::ptr::copy_nonoverlapping(cmdline.as_ptr(), cmdline_host as *mut u8, cmdline.len());
    }

    // boot_params
    let bp_host = g2h(host_ram_base, BOOT_PARAMS_PHYS).ok_or(LoaderError::AllocFailed)?;
    unsafe {
        let bp = bp_host as *mut u8;
        core::ptr::write_bytes(bp, 0u8, BP_SIZE);
        // setup_header: minimal -- no bzImage to copy, fill what kernel reads
        *bp.add(HDR_TYPE_OF_LOADER) = 0xFF;
        *bp.add(HDR_LOADFLAGS) = LOADFLAG_LOADED_HIGH;
        write_u32(bp, HDR_CMD_LINE_PTR, CMDLINE_PHYS as u32);
        write_u32(bp, HDR_RAMDISK_IMAGE, INITRD_PHYS as u32);
        write_u32(bp, HDR_RAMDISK_SIZE, initrd.len() as u32);
        write_u32(bp, HDR_HEAP_END_PTR, 0xFE00);
        // 2.14+: acpi_rsdp_addr
        *(bp.add(BP_ACPI_RSDP_ADDR) as *mut u64) = acpi_rsdp_phys;
        // e820 (kernel uses this regardless of bzImage). Pass total
        // loaded size as an init_size hint -- not used by build_e820_map
        // since we no longer carve hypervisor pages out.
        let entries = build_e820_map(loaded_max_paddr.saturating_sub(loaded_min_paddr));
        for (i, e) in entries.iter().enumerate() {
            let base = bp.add(BP_E820_TABLE + i * E820_ENTRY_SIZE);
            *(base.add(0)  as *mut u64) = e.addr;
            *(base.add(8)  as *mut u64) = e.size;
            *(base.add(16) as *mut u32) = e.kind;
        }
        *bp.add(BP_E820_ENTRIES) = entries.len() as u8;
    }

    sprintln!(
        "[linux-elf] entry_rip=0x{:08x} bp@0x{:x} initrd@0x{:x}({} byte) cmdline@0x{:x}",
        e_entry, BOOT_PARAMS_PHYS, INITRD_PHYS, initrd.len(), CMDLINE_PHYS,
    );

    Ok(LoadedKernel {
        entry_rip: e_entry,
        boot_params_phys: BOOT_PARAMS_PHYS,
        init_size: (loaded_max_paddr - loaded_min_paddr) as u32,
        host_ram_base,
        guest_cr3: GUEST_PT_PHYS,
    })
}

/// 64 MiB sanity cap for our initramfs (Alpine is ~22 MiB).
const MAX_INITRD_BYTES_HINT: usize = 64 * 1024 * 1024;

// ---- PVH boot ---------------------------------------------------------






// ---- helpers --------------------------------------------------------------


#[inline]
unsafe fn write_u32(base: *mut u8, off: usize, v: u32) {
    unsafe { *(base.add(off) as *mut u32) = v };
}


struct E820Entry {
    addr: u64,
    size: u64,
    kind: u32,
}

/// e820 memory map carved to keep our staged guest payloads out of the
/// kernel's free-page pool.
///
/// Layout (1 GiB total RAM assumed):
///   0x0000_0000 .. STACK_PHYS               RAM   (real-mode IVT + free)
///   STACK_PHYS  .. STACK_PHYS+STACK_BYTES   RES   (our scratch stack)
///   STACK_TOP   .. BOOT_PARAMS_PHYS         RAM
///   BOOT_PARAMS .. CMDLINE_PHYS+4K          RES   (boot_params + gap + cmdline)
///   CMDLINE+4K  .. 0x0009_FC00              RAM
///   0x9FC00     .. 0x0010_0000              RES   (EBDA / ROM hole)
///   0x100000    .. KERNEL_LOAD_PHYS         RAM
///   KERNEL_LOAD .. KERNEL_LOAD+init_size    RES   (kernel image + BSS)
///   KERNEL+init .. 0x4000_0000              RAM   (initrd reserved via
///                                                  boot_params.ramdisk_*)
fn build_e820_map(_init_size: u64) -> Vec<E820Entry> {
    let mut v: Vec<E820Entry> = Vec::with_capacity(16);

    // 0..STACK_PHYS = free low RAM
    if STACK_PHYS > 0 {
        v.push(E820Entry { addr: 0, size: STACK_PHYS, kind: E820_RAM });
    }
    // Stack page block
    v.push(E820Entry { addr: STACK_PHYS, size: STACK_BYTES, kind: E820_RESERVED });
    // Gap between stack top and boot_params
    if STACK_TOP < BOOT_PARAMS_PHYS {
        v.push(E820Entry {
            addr: STACK_TOP,
            size: BOOT_PARAMS_PHYS - STACK_TOP,
            kind: E820_RAM,
        });
    }
    // boot_params + cmdline range (cover the gap between them in one
    // reservation so we don't have to itemise the unused middle page).
    v.push(E820Entry {
        addr: BOOT_PARAMS_PHYS,
        size: (CMDLINE_PHYS + 0x1000) - BOOT_PARAMS_PHYS,
        kind: E820_RESERVED,
    });
    // Free RAM up to EBDA
    let after_cmd = CMDLINE_PHYS + 0x1000;
    if after_cmd < 0x0009_FC00 {
        v.push(E820Entry {
            addr: after_cmd,
            size: 0x0009_FC00 - after_cmd,
            kind: E820_RAM,
        });
    }
    // EBDA + legacy video/ROM
    v.push(E820Entry { addr: 0x0009_FC00, size: 0x0000_0400, kind: E820_RESERVED });
    v.push(E820Entry { addr: 0x000A_0000, size: 0x0006_0000, kind: E820_RESERVED });

    // Conventional RAM 1 MiB up to 1 GiB minus the last 1 MiB. The
    // last 1 MiB is reserved for ACPI tables deployed by veneer in
    // guest RAM (standard hypervisor pattern — see enter_linux_guest
    // in main.rs).
    let total_ram = 1u64 << 30;
    let acpi_start: u64 = 0x3FF0_0000;  // must match GUEST_ACPI_OFFSET
    v.push(E820Entry {
        addr: 0x0010_0000,
        size: acpi_start - 0x0010_0000,
        kind: E820_RAM,
    });
    // ACPI-reclaim block. Linux parses tables, then reuses the page
    // memory for normal allocations — same as physical hardware.
    v.push(E820Entry {
        addr: acpi_start,
        size: total_ram - acpi_start,
        kind: E820_ACPI,
    });
    v
}
