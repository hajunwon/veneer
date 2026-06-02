//! Standard-VGA framebuffer with the Bochs DISPI interface — the universal
//! virtual display OVMF's QemuVideoDxe binds to and turns into a UEFI GOP
//! framebuffer. Any OS draws to it through GOP / the EFI framebuffer without
//! a vendor GPU driver (Windows "Basic Display Adapter", Linux efifb).
//!
//! veneer presents a fixed linear framebuffer at a guest-physical address
//! (NPT-mapped to a host buffer it owns) and, in the VMRUN loop, blits that
//! buffer onto the *host* firmware's GOP framebuffer (VMware's real screen).
//! The guest never calls ExitBootServices on this path, so the host GOP
//! stays valid for the whole run.
//!
//! Why a separate host buffer + blit rather than mapping the guest BAR
//! straight onto the host framebuffer: the guest picks its own resolution
//! from QemuVideoDxe's mode list, which need not match the host GOP mode.
//! The blit clips to the overlap, so any guest resolution renders correctly.
//!
//! DISPI register access (QemuVideoDxe std-vga MMIO variant): the controller
//! MMIO BAR exposes the legacy VGA ports at +0x400 and the 16-bit Bochs DISPI
//! registers at +0x500 (register N at +0x500 + N*2). Only DISPI matters for a
//! linear-framebuffer mode; the planar/text VGA registers don't affect the
//! LFB, so they are accepted as no-ops.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};

/// BAR sizes. OVMF assigns the actual guest-physical bases during PCI
/// enumeration and records them itself — it does *not* honour a forced
/// readback — so the bases are tracked dynamically (set on BAR write) and the
/// framebuffer is NPT-mapped at whatever address OVMF picks.
pub const FB_SIZE: u64 = 16 * 1024 * 1024; // BAR0 framebuffer: ~2048×2048×32bpp
pub const MMIO_SIZE: u64 = 0x1000; // BAR2: VGA window (+0x400) + Bochs DISPI (+0x500)

// Bochs DISPI register indices.
const DISPI_ID: u16 = 0;
const DISPI_XRES: u16 = 1;
const DISPI_YRES: u16 = 2;
const DISPI_BPP: u16 = 3;
const DISPI_ENABLE: u16 = 4;
const DISPI_VIRT_WIDTH: u16 = 6;
/// Reports the framebuffer size in 64 KiB units (read-only). QemuVideoDxe
/// reads this to size its mode list; returning 0 left it with no modes
/// ("AvailableFbSize=0x0").
const DISPI_VIDEO_MEMORY_64K: u16 = 0x0a;
const N_DISPI: usize = 10;

// DISPI_ENABLE bits.
const DISPI_ENABLED: u16 = 0x01;
const DISPI_GETCAPS: u16 = 0x02;

const DISPI_ID5: u16 = 0xB0C5;

#[allow(clippy::declare_interior_mutable_const)]
const ZERO16: AtomicU16 = AtomicU16::new(0);
static DISPI: [AtomicU16; N_DISPI] = [ZERO16; N_DISPI];

// Host GOP framebuffer (VMware's real screen), captured once at guest entry.
static HOST_FB_BASE: AtomicU64 = AtomicU64::new(0);
static HOST_FB_WIDTH: AtomicU32 = AtomicU32::new(0);
static HOST_FB_HEIGHT: AtomicU32 = AtomicU32::new(0);
static HOST_FB_STRIDE: AtomicU32 = AtomicU32::new(0); // pixels per scanline
/// True when the host framebuffer is RGB-ordered (red in the low byte);
/// false = BGR. The guest (std-vga 32bpp) is always BGRX.
static HOST_FB_RGB: AtomicBool = AtomicBool::new(false);

// Host buffer backing the guest framebuffer BAR; NPT-mapped at the BAR0
// address OVMF assigns. The blit reads from this buffer.
static GUEST_FB_BUF: AtomicU64 = AtomicU64::new(0);
// OVMF-assigned guest-physical BAR bases (0 = not yet assigned).
static FB_BASE: AtomicU64 = AtomicU64::new(0);
static MMIO_BASE: AtomicU64 = AtomicU64::new(0);
// NPT PDPT used to map the framebuffer at runtime (map_page indexes the PDPT).
static NPT_PDPT: AtomicU64 = AtomicU64::new(0);

static LAST_BLIT_TSC: AtomicU64 = AtomicU64::new(0);

/// Record the host GOP framebuffer veneer blits onto. `rgb` selects the byte
/// order (true = RGBX, false = BGRX).
pub fn set_host_gop(base: u64, width: u32, height: u32, stride_pixels: u32, rgb: bool) {
    HOST_FB_BASE.store(base, Ordering::Relaxed);
    HOST_FB_WIDTH.store(width, Ordering::Relaxed);
    HOST_FB_HEIGHT.store(height, Ordering::Relaxed);
    HOST_FB_STRIDE.store(stride_pixels, Ordering::Relaxed);
    HOST_FB_RGB.store(rgb, Ordering::Relaxed);
}

/// Record the host-physical base of the framebuffer backing buffer and the
/// NPT PDPT used to map it when the guest assigns BAR0.
pub fn set_fb_buffer(host_base: u64, npt_pdpt: u64) {
    GUEST_FB_BUF.store(host_base, Ordering::Relaxed);
    NPT_PDPT.store(npt_pdpt, Ordering::Relaxed);
}

/// BAR0 assigned by OVMF: record it and NPT-map the framebuffer there so the
/// guest's pixel writes land in our host buffer (real memory, no per-pixel
/// trap). Called from the PCI BAR-write path.
pub fn set_fb_base(gpa: u64) {
    FB_BASE.store(gpa, Ordering::Relaxed);
    let pdpt = NPT_PDPT.load(Ordering::Relaxed);
    let buf = GUEST_FB_BUF.load(Ordering::Relaxed);
    if pdpt == 0 || buf == 0 || gpa == 0 {
        return;
    }
    // Only map inside the 32-bit PCI MMIO window (below the ECAM base). A base
    // outside it (e.g. a transient sizing artefact, or an over-the-flash
    // assignment) must never be mapped — that would overwrite the OVMF window
    // or guest RAM and corrupt the boot.
    if gpa < 0x8000_0000 || gpa + FB_SIZE > crate::hardware::acpi::PCIE_MCFG_BASE {
        crate::sprintln!("[vga ] framebuffer base 0x{:08X} outside MMIO window — not mapping", gpa);
        return;
    }
    let npt = crate::hypervisor::svm::npt::NptRoot { pml4_phys: 0, pdpt_phys: pdpt, coverage_bytes: 0 };
    match crate::hypervisor::svm::npt::map_range(&npt, gpa, buf, FB_SIZE) {
        Ok(_) => crate::sprintln!("[vga ] framebuffer mapped: guest 0x{:08X} -> host 0x{:016X} ({} MiB)",
            gpa, buf, FB_SIZE / (1024 * 1024)),
        Err(e) => crate::sprintln!("[vga ] framebuffer NPT map failed: {:?}", e),
    }
}

/// BAR2 (DISPI/VGA MMIO) assigned by OVMF: the NPF router traps this window.
pub fn set_mmio_base(gpa: u64) {
    MMIO_BASE.store(gpa, Ordering::Relaxed);
}

pub fn ready() -> bool {
    HOST_FB_BASE.load(Ordering::Relaxed) != 0 && GUEST_FB_BUF.load(Ordering::Relaxed) != 0
}

// ───── DISPI register model ──────────────────────────────────────────────

fn dispi_read(index: u16) -> u16 {
    if index == DISPI_ID {
        return DISPI_ID5;
    }
    if index == DISPI_VIDEO_MEMORY_64K {
        return (FB_SIZE / 0x10000) as u16; // 16 MiB / 64 KiB = 256 units
    }
    let getcaps = DISPI[DISPI_ENABLE as usize].load(Ordering::Relaxed) & DISPI_GETCAPS != 0;
    if getcaps {
        // Capability query: report the largest mode we can render, bounded by
        // the host framebuffer (the blit clips, but advertising the host size
        // keeps the guest's chosen mode within what shows 1:1).
        return match index {
            DISPI_XRES => HOST_FB_WIDTH.load(Ordering::Relaxed).min(2560) as u16,
            DISPI_YRES => HOST_FB_HEIGHT.load(Ordering::Relaxed).min(1600) as u16,
            DISPI_BPP => 32,
            _ => DISPI[index as usize].load(Ordering::Relaxed),
        };
    }
    if (index as usize) < N_DISPI {
        DISPI[index as usize].load(Ordering::Relaxed)
    } else {
        0
    }
}

fn dispi_write(index: u16, val: u16) {
    if index == DISPI_ID || index as usize >= N_DISPI {
        return; // ID is read-only (we report a fixed version); ignore OOB.
    }
    DISPI[index as usize].store(val, Ordering::Relaxed);
}

// ───── MMIO BAR (VGA at +0x400, DISPI at +0x500) ─────────────────────────

#[inline]
pub fn mmio_covers(gpa: u64) -> bool {
    let base = MMIO_BASE.load(Ordering::Relaxed);
    base != 0 && gpa >= base && gpa < base + MMIO_SIZE
}

/// MMIO read from the controller BAR. `width` is the access size in bytes.
pub fn mmio_read(gpa: u64, width: u8) -> u64 {
    let off = (gpa - MMIO_BASE.load(Ordering::Relaxed)) as u32;
    // DISPI register file at +0x500, one 16-bit register per index. Cover
    // through index 0x0f (incl VIDEO_MEMORY_64K at 0x0a) — dispi_read returns
    // 0 for indices it doesn't model.
    if (0x500..0x520).contains(&off) {
        let index = ((off - 0x500) / 2) as u16;
        return dispi_read(index) as u64;
    }
    // Legacy VGA register window (+0x400): not used in linear-framebuffer
    // mode. Read back 0.
    let _ = width;
    0
}

/// MMIO write to the controller BAR.
pub fn mmio_write(gpa: u64, val: u64, _width: u8) {
    let off = (gpa - MMIO_BASE.load(Ordering::Relaxed)) as u32;
    if (0x500..0x520).contains(&off) {
        let index = ((off - 0x500) / 2) as u16;
        dispi_write(index, val as u16);
    }
    // +0x400 VGA register writes: no-op (planar/text regs don't drive the LFB).
}

// ───── Blit guest framebuffer → host GOP ─────────────────────────────────

#[inline]
fn host_rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Copy the guest framebuffer onto the host screen, throttled to ~30 fps so
/// the per-frame copy doesn't dominate the VMRUN loop. Clips to the overlap
/// of the guest mode and the host framebuffer. Call frequently from the loop.
pub fn blit() {
    if !ready() {
        return;
    }
    let enable = DISPI[DISPI_ENABLE as usize].load(Ordering::Relaxed);
    if enable & DISPI_ENABLED == 0 {
        return; // guest hasn't enabled the LFB yet
    }
    if DISPI[DISPI_BPP as usize].load(Ordering::Relaxed) != 32 {
        return; // only 32bpp is wired
    }

    // ~30 fps throttle using the raw host TSC (cheap, monotonic enough here).
    let now = host_rdtsc();
    let last = LAST_BLIT_TSC.load(Ordering::Relaxed);
    let min_interval = crate::infra::clock::tsc_freq::host_tsc_freq() / 30;
    if last != 0 && now.wrapping_sub(last) < min_interval {
        return;
    }
    LAST_BLIT_TSC.store(now, Ordering::Relaxed);

    let g_w = DISPI[DISPI_XRES as usize].load(Ordering::Relaxed) as u32;
    let g_h = DISPI[DISPI_YRES as usize].load(Ordering::Relaxed) as u32;
    let g_stride = {
        let v = DISPI[DISPI_VIRT_WIDTH as usize].load(Ordering::Relaxed) as u32;
        if v == 0 { g_w } else { v }
    };
    if g_w == 0 || g_h == 0 {
        return;
    }

    let h_w = HOST_FB_WIDTH.load(Ordering::Relaxed);
    let h_h = HOST_FB_HEIGHT.load(Ordering::Relaxed);
    let h_stride = HOST_FB_STRIDE.load(Ordering::Relaxed);
    let src_base = GUEST_FB_BUF.load(Ordering::Relaxed);
    let dst_base = HOST_FB_BASE.load(Ordering::Relaxed);
    let swap = HOST_FB_RGB.load(Ordering::Relaxed);

    let cols = g_w.min(h_w);
    let rows = g_h.min(h_h);
    // Don't read past the backing buffer.
    let max_rows = (FB_SIZE / (g_stride as u64 * 4)) as u32;
    let rows = rows.min(max_rows);

    for y in 0..rows {
        let src = (src_base + (y as u64) * (g_stride as u64) * 4) as *const u32;
        let dst = (dst_base + (y as u64) * (h_stride as u64) * 4) as *mut u32;
        if swap {
            // Guest BGRX → host RGBX: swap the red/blue bytes per pixel.
            for x in 0..cols as usize {
                let p = unsafe { *src.add(x) };
                let b = p & 0xFF;
                let g = (p >> 8) & 0xFF;
                let r = (p >> 16) & 0xFF;
                unsafe { *dst.add(x) = (b << 16) | (g << 8) | r; }
            }
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(src, dst, cols as usize);
            }
        }
    }
}
