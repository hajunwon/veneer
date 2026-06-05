//! Backing-disk reader: serves real on-disk blocks to the emulated NVMe
//! namespaces through UEFI Block I/O.
//!
//! install-under-veneer needs two devices visible to the guest, mirroring
//! a real OS install: a writable TARGET disk (where the OS installs) and a
//! read-only MEDIA disk (the install ISO it boots from). We expose them as
//! NVMe namespaces 1 and 2. The nested-guest path never calls
//! ExitBootServices, so the BlockIO protocol stays valid for the whole
//! VMRUN loop and guest NVMe commands are satisfied from the real disks.
//!
//! "Which disk is which" is veneer's decision, taken here: the largest
//! writable whole disk is the TARGET, a read-only whole disk is the MEDIA.
//! veneer's own (smaller) ESP boot disk is neither, so it stays hidden.

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::media::block::BlockIO;


/// One bound backing disk behind a namespace.
struct BoundDisk {
    disk: AtomicPtr<BlockIO>,
    media_id: AtomicU32,
    block_size: AtomicU32,
    block_count: AtomicU64,
    ready: AtomicBool,
}

impl BoundDisk {
    const fn new() -> Self {
        Self {
            disk: AtomicPtr::new(core::ptr::null_mut()),
            media_id: AtomicU32::new(0),
            block_size: AtomicU32::new(0),
            block_count: AtomicU64::new(0),
            ready: AtomicBool::new(false),
        }
    }

    fn bind(&self, ptr: *const BlockIO, mid: u32, bs: u32, count: u64) {
        self.disk.store(ptr as *mut BlockIO, Ordering::Release);
        self.media_id.store(mid, Ordering::Relaxed);
        self.block_size.store(bs, Ordering::Relaxed);
        self.block_count.store(count, Ordering::Relaxed);
        self.ready.store(true, Ordering::Release);
    }

    fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    fn block_size(&self) -> u32 {
        self.block_size.load(Ordering::Relaxed)
    }

    fn block_count(&self) -> u64 {
        self.block_count.load(Ordering::Relaxed)
    }

    fn read(&self, lba: u64, blocks: u32, dest: *mut u8) -> bool {
        let p = self.disk.load(Ordering::Acquire);
        if p.is_null() {
            return false;
        }
        let bs = self.block_size.load(Ordering::Relaxed) as usize;
        if bs == 0 {
            return false;
        }
        let bio: &BlockIO = unsafe { &*p };
        let buf = unsafe { core::slice::from_raw_parts_mut(dest, blocks as usize * bs) };
        bio.read_blocks(self.media_id.load(Ordering::Relaxed), lba, buf).is_ok()
    }

    fn write(&self, lba: u64, blocks: u32, src: *const u8) -> bool {
        let p = self.disk.load(Ordering::Acquire);
        if p.is_null() {
            return false;
        }
        let bs = self.block_size.load(Ordering::Relaxed) as usize;
        if bs == 0 {
            return false;
        }
        let bio: &mut BlockIO = unsafe { &mut *p };
        let buf = unsafe { core::slice::from_raw_parts(src, blocks as usize * bs) };
        bio.write_blocks(self.media_id.load(Ordering::Relaxed), lba, buf).is_ok()
    }
}

// Namespace 1 = TARGET (writable, OS installs here).
// Namespace 2 = MEDIA  (read-only install ISO the guest boots from).
static TARGET: BoundDisk = BoundDisk::new();
static MEDIA: BoundDisk = BoundDisk::new();

fn ns(nsid: u32) -> Option<&'static BoundDisk> {
    match nsid {
        1 if TARGET.ready() => Some(&TARGET),
        _ => None,
    }
}

/// NVMe namespace count — the target only. The install media is served as
/// an ATAPI CD-ROM through the AHCI controller (El Torito), not as an NVMe
/// namespace: a 2048-byte ISO forced through NVMe breaks isohybrid LBAs.
pub fn ns_count() -> u32 {
    if TARGET.ready() { 1 } else { 0 }
}

// ───── Install media (served by the AHCI ATAPI CD-ROM) ───────────────
pub fn media_ready() -> bool {
    MEDIA.ready()
}
pub fn media_block_size() -> u32 {
    MEDIA.block_size()
}
pub fn media_block_count() -> u64 {
    MEDIA.block_count()
}
pub fn media_read(lba: u64, blocks: u32, dest: *mut u8) -> bool {
    // Served by veneer's own polling AHCI driver (not host BlockIo, which
    // stalls in the VMEXIT timer context). Geometry came from the firmware
    // BlockIo at init; the actual transfer is ours.
    super::host_ahci::atapi_read(lba, blocks, dest, MEDIA.block_size())
}

pub fn ns_present(nsid: u32) -> bool {
    ns(nsid).is_some()
}

pub fn block_size(nsid: u32) -> u32 {
    ns(nsid).map(|d| d.block_size()).unwrap_or(0)
}

pub fn block_count(nsid: u32) -> u64 {
    ns(nsid).map(|d| d.block_count()).unwrap_or(0)
}

pub fn read(nsid: u32, lba: u64, blocks: u32, dest: *mut u8) -> bool {
    // Runtime target I/O goes through our own polling AHCI driver, NOT host
    // UEFI BlockIO: both the target and the install CD live on the same host
    // AHCI controller, so letting firmware BlockIO drive the target while
    // host_ahci drives the CD makes the two contend for the HBA and storms
    // the guest's CD-completion interrupt. One driver owns the controller.
    match ns(nsid) {
        Some(d) if super::host_ahci::target_present() => {
            super::host_ahci::ata_read(lba, blocks, dest, d.block_size())
        }
        Some(d) => d.read(lba, blocks, dest), // fallback: no host_ahci target bound
        None => false,
    }
}

/// Only the target is writable; the media (install ISO) is read-only.
pub fn write(nsid: u32, lba: u64, blocks: u32, src: *const u8) -> bool {
    match nsid {
        1 if TARGET.ready() && super::host_ahci::target_present() => {
            super::host_ahci::ata_write(lba, blocks, src, TARGET.block_size())
        }
        1 if TARGET.ready() => TARGET.write(lba, blocks, src),
        _ => false,
    }
}

/// Enumerate BlockIO handles and classify: the largest writable whole disk
/// becomes the TARGET, a read-only whole disk becomes the MEDIA. Logical
/// partitions and veneer's own (smaller) ESP boot disk are skipped — the
/// boot disk is neither the largest writable nor read-only. Must run with
/// Boot Services alive, which the nested-guest path satisfies.
pub fn init() {
    let handles = match boot::find_handles::<BlockIO>() {
        Ok(h) => h,
        Err(e) => {
            sprintln!("[bdisk] find_handles(BlockIO) failed: {:?}", e.status());
            return;
        }
    };
    sprintln!("[bdisk] {} BlockIO handle(s) present", handles.len());

    // (interface, media_id, block_size, block_count)
    let mut target: Option<(*const BlockIO, u32, u32, u64)> = None;
    let mut media: Option<(*const BlockIO, u32, u32, u64)> = None;

    for (i, &h) in handles.iter().enumerate() {
        let scoped = match unsafe {
            boot::open_protocol::<BlockIO>(
                OpenProtocolParams {
                    handle: h,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        } {
            Ok(s) => s,
            Err(_) => continue,
        };

        let m = scoped.media();
        let present = m.is_media_present();
        let partition = m.is_logical_partition();
        let read_only = m.is_read_only();
        let bs = m.block_size();
        let count = m.last_block().wrapping_add(1);
        let bytes = count.saturating_mul(bs as u64);
        sprintln!(
            "[bdisk]  #{}: present={} partition={} ro={} bs={} blocks={} ({} MiB)",
            i, present, partition, read_only, bs, count, bytes / (1024 * 1024)
        );

        if !present || partition || bs == 0 {
            continue;
        }
        let ptr = (&*scoped) as *const BlockIO;
        let mid = m.media_id();

        if read_only {
            // Read-only whole disk = the install ISO/CD. Prefer the largest.
            let better = match media {
                None => true,
                Some((_, _, mbs, mcount)) => bytes > (mcount.saturating_mul(mbs as u64)),
            };
            if better {
                core::mem::forget(scoped);
                media = Some((ptr, mid, bs, count));
            }
        } else {
            // Writable whole disk; the largest is the OS install target.
            let better = match target {
                None => true,
                Some((_, _, tbs, tcount)) => bytes > (tcount.saturating_mul(tbs as u64)),
            };
            if better {
                core::mem::forget(scoped);
                target = Some((ptr, mid, bs, count));
            }
        }
    }

    if let Some((ptr, mid, bs, count)) = target {
        TARGET.bind(ptr, mid, bs, count);
        sprintln!("[bdisk] ns1 TARGET: media_id={} bs={} blocks={}", mid, bs, count);
        self_test(&TARGET, "ns1 target");
    } else {
        sprintln!("[bdisk] no writable target disk found");
    }
    if let Some((ptr, mid, bs, count)) = media {
        MEDIA.bind(ptr, mid, bs, count);
        sprintln!("[bdisk] ns2 MEDIA : media_id={} bs={} blocks={}", mid, bs, count);
        self_test(&MEDIA, "ns2 media");
    } else {
        sprintln!("[bdisk] no read-only media disk found (install ISO not attached?)");
    }

    scan_host_disk_controllers();
    veneer_vmm::hardware::devices::storage::set_host_storage(&HOST_DISK);
}

/// Read a host PCI config dword via the CF8/CFC port pair (veneer runs in
/// host context so these reach the VM's real PCI bus, not our emulator).
fn pci_cfg_read32(bus: u8, dev: u8, func: u8, reg: u8) -> u32 {
    let addr = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((reg & 0xFC) as u32);
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") 0xCF8u16, in("eax") addr,
            options(nomem, nostack, preserves_flags));
        let v: u32;
        core::arch::asm!("in eax, dx", out("eax") v, in("dx") 0xCFCu16,
            options(nomem, nostack, preserves_flags));
        v
    }
}

/// Enumerate the VM's real storage controllers (PCI class 0x01) so we can
/// drive them ourselves with a polling driver instead of leaning on the
/// host firmware's BlockIo (which stalls in the VMEXIT timer context).
fn scan_host_disk_controllers() {
    sprintln!("[hostpci] scanning for storage controllers (class 0x01)");
    for bus in 0..4u8 {
        for dev in 0..32u8 {
            for func in 0..8u8 {
                let id = pci_cfg_read32(bus, dev, func, 0x00);
                if id == 0xFFFF_FFFF {
                    if func == 0 { break; }
                    continue;
                }
                let class = pci_cfg_read32(bus, dev, func, 0x08);
                if (class >> 24) & 0xFF == 0x01 {
                    let bar0 = pci_cfg_read32(bus, dev, func, 0x10);
                    let bar5 = pci_cfg_read32(bus, dev, func, 0x24);
                    sprintln!(
                        "[hostpci] {:02X}:{:02X}.{} id=0x{:08X} class=0x{:08X} BAR0=0x{:08X} BAR5=0x{:08X}",
                        bus, dev, func, id, class, bar0, bar5
                    );
                    if (class >> 16) & 0xFF == 0x06 {
                        // SATA AHCI — drive it ourselves (BAR5 = ABAR).
                        super::host_ahci::init((bar5 & 0xFFFF_FFF0) as u64);
                    }
                }
                if func == 0 {
                    let hdr = pci_cfg_read32(bus, dev, 0, 0x0C);
                    if (hdr >> 16) & 0x80 == 0 {
                        break; // single-function device
                    }
                }
            }
        }
    }
}

/// Read LBA 0/1 and log signature bytes so the boot log confirms the
/// BlockIO path works (MBR 0x55AA, GPT "EFI PART", ISO9660 "CD001").
fn self_test(disk: &BoundDisk, label: &str) {
    #[repr(align(4096))]
    struct Buf([u8; 4096]);
    let mut b = Buf([0u8; 4096]);

    if disk.read(0, 1, b.0.as_mut_ptr()) {
        sprintln!(
            "[bdisk] self-test {} LBA0 ok: head={:02X}{:02X} sig@510={:02X}{:02X}",
            label, b.0[0], b.0[1], b.0[510], b.0[511]
        );
    } else {
        sprintln!("[bdisk] self-test {} LBA0 read FAILED", label);
    }
}

/// `HostStorage` over the UEFI/host-AHCI backend — the concrete host disk
/// surface, registered with the storage module at boot. In a core/adapter
/// split this impl is the adapter side; the controllers stay core-side.
pub struct HostDisk;

impl veneer_vmm::hardware::devices::storage::HostStorage for HostDisk {
    fn ns_present(&self, nsid: u32) -> bool { ns_present(nsid) }
    fn ns_count(&self) -> u32 { ns_count() }
    fn block_size(&self, nsid: u32) -> u32 { block_size(nsid) }
    fn block_count(&self, nsid: u32) -> u64 { block_count(nsid) }
    fn read(&self, nsid: u32, lba: u64, blocks: u32, dest: *mut u8) -> bool {
        read(nsid, lba, blocks, dest)
    }
    fn write(&self, nsid: u32, lba: u64, blocks: u32, src: *const u8) -> bool {
        write(nsid, lba, blocks, src)
    }
    fn media_ready(&self) -> bool { media_ready() }
    fn media_block_size(&self) -> u32 { media_block_size() }
    fn media_block_count(&self) -> u64 { media_block_count() }
    fn media_read(&self, lba: u64, blocks: u32, dest: *mut u8) -> bool {
        media_read(lba, blocks, dest)
    }
}

static HOST_DISK: HostDisk = HostDisk;
