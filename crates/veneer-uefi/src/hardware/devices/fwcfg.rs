//! QEMU fw_cfg emulator (legacy port I/O interface).
//!
//! OVMF probes fw_cfg to learn the platform's CPU count, RAM layout, and —
//! crucially for us — to pull the ACPI and SMBIOS tables it should publish
//! to the OS. Without it OVMF can't read the boot CPU count, defaults
//! MaxCpuCount to 64, broadcasts INIT-SIPI-SIPI, then spin-waits forever
//! for 63 APs that don't exist in our single-vCPU guest (CpuDxe MP hang),
//! and it falls back to its own built-in SMBIOS so the guest sees no DMI.
//!
//! Interface (no DMA — OVMF streams over the slow port path):
//!   0x510  selector (16-bit write) — picks the config item, resets offset
//!   0x511  data (8-bit read)       — streams the item's bytes
//!
//! Built-in items: SIGNATURE ("QEMU"), ID (legacy, no DMA), NB_CPUS /
//! MAX_CPUS = 1, FILE_DIR. Named files (etc/smbios/*, etc/acpi/*) are
//! registered at boot by [`install_smbios`] / [`install_acpi`] and served
//! through selectors at or above [`FILE_SELECTOR_BASE`].

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

pub const SELECTOR_PORT: u16 = 0x510;
pub const DATA_PORT: u16 = 0x511;

const ITEM_SIGNATURE: u16 = 0x0000;
const ITEM_ID: u16 = 0x0001;
const ITEM_NB_CPUS: u16 = 0x0005;
const ITEM_MAX_CPUS: u16 = 0x000F;
const ITEM_FILE_DIR: u16 = 0x0019;

/// First selector handed out to named files (QEMU's FW_CFG_FILE_FIRST).
const FILE_SELECTOR_BASE: u16 = 0x0020;

/// fw_cfg directory entry: a fixed 64-byte record (big-endian scalars).
const DIR_ENTRY_SIZE: usize = 64;
const NAME_MAX: usize = 56;

static SELECTOR: AtomicU32 = AtomicU32::new(0);
static OFFSET: AtomicU32 = AtomicU32::new(0);

/// The "QEMU" signature stays hidden until at least one file is staged:
/// OVMF's FwCfgCache asserts on an empty FILE_DIR once it sees the
/// signature, so we advertise fw_cfg only when there is something to read.
static SIGNATURE_ON: AtomicBool = AtomicBool::new(false);

// Fixed slots — index i maps to selector FILE_SELECTOR_BASE + i. Keeping a
// stable slot per file lets the directory `select` field equal the slot the
// dispatcher reads from, so the two never drift.
const SLOT_SMBIOS_ANCHOR: usize = 0;
const SLOT_SMBIOS_TABLES: usize = 1;
const SLOT_ACPI_RSDP: usize = 2;
const SLOT_ACPI_TABLES: usize = 3;
const SLOT_ACPI_LOADER: usize = 4;
const MAX_FILES: usize = 5;

struct FwCfgFile {
    name: &'static [u8],
    data: AtomicPtr<u8>,
    len: AtomicU32,
}

impl FwCfgFile {
    const fn new(name: &'static [u8]) -> Self {
        Self {
            name,
            data: AtomicPtr::new(core::ptr::null_mut()),
            len: AtomicU32::new(0),
        }
    }

    fn set(&self, ptr: *const u8, len: u32) {
        self.len.store(len, Ordering::Relaxed);
        self.data.store(ptr as *mut u8, Ordering::Release);
    }

    fn ready(&self) -> bool {
        !self.data.load(Ordering::Acquire).is_null()
    }

    fn len(&self) -> u32 {
        self.len.load(Ordering::Relaxed)
    }

    fn byte(&self, off: u32) -> u8 {
        let p = self.data.load(Ordering::Acquire);
        if p.is_null() || off >= self.len.load(Ordering::Relaxed) {
            return 0;
        }
        unsafe { *p.add(off as usize) }
    }
}

static FILES: [FwCfgFile; MAX_FILES] = [
    FwCfgFile::new(b"etc/smbios/smbios-anchor"),
    FwCfgFile::new(b"etc/smbios/smbios-tables"),
    FwCfgFile::new(b"etc/acpi/rsdp"),
    FwCfgFile::new(b"etc/acpi/tables"),
    FwCfgFile::new(b"etc/table-loader"),
];

// FILE_DIR is rebuilt into this buffer whenever a file is staged. Single-vCPU
// through the intercept dispatcher, so a plain static buffer is safe (same
// invariant the io.rs guest line buffer relies on).
const DIR_BUF_CAP: usize = 4 + MAX_FILES * DIR_ENTRY_SIZE;
static mut DIR_BUF: [u8; DIR_BUF_CAP] = [0u8; DIR_BUF_CAP];
static DIR_LEN: AtomicU32 = AtomicU32::new(4); // empty dir = BE count 0

#[inline]
pub fn covers(port: u16) -> bool {
    port == SELECTOR_PORT || port == DATA_PORT
}

/// Stage the SMBIOS entry point + structure table for OVMF to publish.
/// `anchor` is the 31-byte `_SM_` entry point; `tables` is the structure
/// blob it describes. OVMF reads the anchor for the version + table length,
/// then installs the structures via the SMBIOS protocol.
pub fn install_smbios(anchor: *const u8, anchor_len: u32, tables: *const u8, tables_len: u32) {
    FILES[SLOT_SMBIOS_ANCHOR].set(anchor, anchor_len);
    FILES[SLOT_SMBIOS_TABLES].set(tables, tables_len);
    rebuild_dir();
}

/// Stage the ACPI payload OVMF loads through the BiosLinkerLoader script:
/// `rsdp` (etc/acpi/rsdp), `tables` (etc/acpi/tables, concatenated), and
/// `loader` (etc/table-loader, the relocation/checksum command stream).
pub fn install_acpi(
    rsdp: *const u8,
    rsdp_len: u32,
    tables: *const u8,
    tables_len: u32,
    loader: *const u8,
    loader_len: u32,
) {
    FILES[SLOT_ACPI_RSDP].set(rsdp, rsdp_len);
    FILES[SLOT_ACPI_TABLES].set(tables, tables_len);
    FILES[SLOT_ACPI_LOADER].set(loader, loader_len);
    rebuild_dir();
}

/// Rebuild FILE_DIR from the currently-staged files and reveal the
/// signature once the directory is non-empty.
fn rebuild_dir() {
    let mut off = 4usize;
    let mut count = 0u32;
    // SAFETY: single-vCPU; no concurrent reader during boot-time staging.
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(DIR_BUF) };
    for (i, f) in FILES.iter().enumerate() {
        if !f.ready() {
            continue;
        }
        let sel = FILE_SELECTOR_BASE + i as u16;
        buf[off..off + 4].copy_from_slice(&f.len().to_be_bytes());
        buf[off + 4..off + 6].copy_from_slice(&sel.to_be_bytes());
        buf[off + 6..off + 8].copy_from_slice(&0u16.to_be_bytes());
        let name = f.name;
        let n = name.len().min(NAME_MAX);
        buf[off + 8..off + 8 + n].copy_from_slice(&name[..n]);
        for b in &mut buf[off + 8 + n..off + DIR_ENTRY_SIZE] {
            *b = 0;
        }
        off += DIR_ENTRY_SIZE;
        count += 1;
    }
    buf[0..4].copy_from_slice(&count.to_be_bytes());
    DIR_LEN.store(off as u32, Ordering::Release);
    if count > 0 {
        SIGNATURE_ON.store(true, Ordering::Release);
    }
}

/// OUT to the selector port: latch the config item and rewind its stream.
pub fn select(val: u16) {
    SELECTOR.store(val as u32, Ordering::Relaxed);
    OFFSET.store(0, Ordering::Relaxed);
}

fn dir_byte(off: u32) -> u8 {
    if off >= DIR_LEN.load(Ordering::Acquire) {
        return 0;
    }
    let buf = unsafe { &*core::ptr::addr_of!(DIR_BUF) };
    buf[off as usize]
}

/// One byte of the currently-selected item at byte index `off`. fw_cfg
/// integers are little-endian; the file directory is big-endian.
fn item_byte(sel: u16, off: u32) -> u8 {
    let le = |v: u64, n: u32| -> u8 { (v >> (n * 8)) as u8 };
    let sel = sel & 0x3FFF;
    match sel {
        ITEM_SIGNATURE => {
            if SIGNATURE_ON.load(Ordering::Acquire) {
                b"QEMU".get(off as usize).copied().unwrap_or(0)
            } else {
                0
            }
        }
        // bit0 = legacy port interface present, bit1 = DMA (left off).
        ITEM_ID => le(0x0000_0001, off),
        ITEM_NB_CPUS | ITEM_MAX_CPUS => le(1, off), // single vCPU
        ITEM_FILE_DIR => dir_byte(off),
        _ => {
            if sel >= FILE_SELECTOR_BASE {
                let idx = (sel - FILE_SELECTOR_BASE) as usize;
                if idx < MAX_FILES {
                    return FILES[idx].byte(off);
                }
            }
            0
        }
    }
}

/// IN from the data port: next streamed byte, auto-incrementing offset.
pub fn next_byte() -> u8 {
    let sel = SELECTOR.load(Ordering::Relaxed) as u16;
    let off = OFFSET.fetch_add(1, Ordering::Relaxed);
    item_byte(sel, off)
}
