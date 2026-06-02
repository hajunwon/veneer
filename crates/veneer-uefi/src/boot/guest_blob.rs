//! A tiny real-mode guest payload used to drive the first real VMEXIT.
//!
//! The guest executes:
//!
//!   mov eax, 1     ; B8 01 00 00 00   — 5 bytes
//!   cpuid          ; 0F A2            — 2 bytes  → CPUID intercept
//!   hlt            ; F4               — 1 byte   → HLT intercept (safety net)
//!
//! The payload is copied into a 4 KiB UEFI-allocated page. UEFI hands out
//! identity-mapped memory, so the page's host physical address is the same
//! number we put in VMCB.state.rip — no paging dance needed.

use uefi::boot::{self, AllocateType, MemoryType};

// v0.9-batch full intercept-coverage blob (21 intercept paths).
//
// A 4 KiB-aligned blob page also doubles as a scratch buffer at +0x800
// for the SIDT instruction to write IDTR (limit + base = 10 bytes) into.
// SIDT uses `[rip + disp32]` so the encoding is position-independent —
// disp32 = 0x800 - (offset_after_sidt) = 0x7A4 for the layout below.
// Each instruction triggers one of veneer's intercept paths so a single
// boot exercises every handler. The final HLT lets the launcher read out
// the surviving register state and verify each path's footprint.
//
//   mov eax, 0x40000000 ; cpuid       → CPUID intercept (HV-leaf erase)
//   mov eax, 1          ; cpuid       → CPUID intercept (family/model spoof)
//   mov eax, 0x80000002 ; cpuid       → CPUID intercept (brand spoof leaf 1/3)
//   mov ecx, 0x10       ; rdmsr       → MSR intercept (host pass-through for TSC)
//   rdtsc                              → RDTSC intercept (tsc_offset path)
//   rdpmc / pushf / popf / in         → stealth + IOIO intercepts
//   rdtscp                            → RDTSCP intercept (TSC_AUX hide)
//   mov rcx, 0xFEE00020 ; mov eax,[rcx] → NPF read on LAPIC MMIO
//   mov rdx, 0xE1000000 ; mov [rdx], eax → NPF write on NIC BAR0
//   invd / wbinvd                      → INVD/WBINVD intercepts (stealth)
//   mov eax, 0         ; vmmcall      → VMMCALL intercept (returns signature)
//   hlt                                → HLT intercept (final exit)
const BLOB: &[u8] = &[
    0xB8, 0x00, 0x00, 0x00, 0x40, // mov eax, 0x40000000    (5)
    0x0F, 0xA2,                   // cpuid                  (2)  → CPUID (HV erase)
    0x0F, 0x21, 0xC0,             // mov eax, dr0           (3)  → DR-read
    0x0F, 0x20, 0xD8,             // mov eax, cr3           (3)  → CR-read
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1             (5)
    0x0F, 0xA2,                   // cpuid                  (2)  → CPUID (family/model)
    0xB8, 0x02, 0x00, 0x00, 0x80, // mov eax, 0x80000002    (5)
    0x0F, 0xA2,                   // cpuid                  (2)  → CPUID (brand)
    0xB9, 0x10, 0x00, 0x00, 0x00, // mov ecx, 0x10          (5)
    0x0F, 0x32,                   // rdmsr                  (2)  → MSR (TSC)
    0xB9, 0xFE, 0x00, 0x00, 0x00, // mov ecx, 0xFE          (5)
    0x0F, 0x32,                   // rdmsr                  (2)  → MSR (MTRRCAP→0x508)
    0x0F, 0x31,                   // rdtsc                  (2)  → RDTSC
    0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, 0             (5)
    0x0F, 0x33,                   // rdpmc                  (2)  → RDPMC (stealth)
    0x9C,                         // pushf                  (1)  → PUSHF (stealth)
    0x9D,                         // popf                   (1)  → POPF  (stealth)
    0xE5, 0x80,                   // in  eax, 0x80          (2)  → IOIO
    0x0F, 0x01, 0xF9,             // rdtscp                 (3)  → RDTSCP
    0x48, 0xB9, 0x20, 0x00, 0xE0, 0xFE, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0xFEE00020 (10)
    0x8B, 0x01,                   // mov eax, [rcx]         (2)  → NPF (LAPIC read)
    0x48, 0xBA, 0x00, 0x00, 0x00, 0xE1, 0x00, 0x00, 0x00, 0x00, // mov rdx, 0xE1000000 (10)
    0x89, 0x02,                   // mov [rdx], eax         (2)  → NPF (NIC BAR0 write)
    0x0F, 0x08,                   // invd                   (2)  → INVD   (stealth)
    0x0F, 0x09,                   // wbinvd                 (2)  → WBINVD (stealth)
    0x0F, 0x01, 0x0D, 0xA4, 0x07, 0x00, 0x00, // sidt [rip+0x7A4]  (7)  → IDTR_READ
    0x48, 0xBE, 0xF0, 0x00, 0xD0, 0xFE, 0x00, 0x00, 0x00, 0x00, // mov rsi, 0xFED000F0 (10)
    0x48, 0x8B, 0x06,             // mov rax, [rsi]         (3)  → NPF (HPET main counter, 64-bit)
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0             (5)
    0x0F, 0x01, 0xD9,             // vmmcall                (3)  → VMMCALL
    0xF4,                         // hlt                    (1)  → HLT
];

pub const BLOB_DESC: &str = "cpuid(HV); dr0; cr3; cpuid(v1); cpuid(brand); rdmsr(tsc); rdmsr(mtrrcap); rdtsc; rdpmc; pushf; popf; in; rdtscp; lapic_read; nic_write; invd; wbinvd; sidt; hpet_read; vmmcall; hlt";

#[derive(Debug)]
pub enum BlobError {
    AllocFailed,
}

#[derive(Debug, Clone, Copy)]
pub struct BlobAlloc {
    pub phys: u64,
    pub size: usize,
}

pub fn alloc_and_write() -> Result<BlobAlloc, BlobError> {
    let page = boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::RUNTIME_SERVICES_DATA,
        1,
    )
    .map_err(|_| BlobError::AllocFailed)?;
    let ptr = page.as_ptr();
    unsafe {
        core::ptr::write_bytes(ptr, 0u8, 4096);
        core::ptr::copy_nonoverlapping(BLOB.as_ptr(), ptr, BLOB.len());
    }
    Ok(BlobAlloc {
        phys: ptr as u64,
        size: BLOB.len(),
    })
}
