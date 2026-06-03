#![no_std]
#![no_main]
// Spec-completeness items (TPM command/cap codes used as P1-P5 lands, hardware
// register maps) and future-wired helpers (AP teardown, device read paths) are
// intentionally defined ahead of use. Genuine dead paths are removed, not allowed.
#![allow(dead_code)]

mod infra;
mod hypervisor;
mod hardware;
mod guest;
#[allow(dead_code)]
mod introspect;
mod diag;

use crate::infra::config::toml;
use crate::infra::{arch, config};
use crate::hypervisor::vmexit;
use crate::hardware::{acpi, devices};
use crate::infra::serial;
use crate::infra::clock::{host_tick, tsc_freq};
use crate::infra::arch::halt_forever;
use crate::hypervisor::svm::{self, vmcb, vmrun, npt, smp, vcpu_pool, gprs};
use crate::hardware::identity::{profile, profile_gen, smbios, nvram_io, uefi_vars, active};
use crate::hardware::acpi::acpi_fwcfg;
use crate::guest::boot::{chain_load, esp_io, guest_blob, guest_mem, linux_loader, menu, uefi_config};
use crate::diag::report::{report_profile, report_ap_probe, verify, report_vmexit, report_success, report_error};
use crate::diag::validator;
use uefi::prelude::*;

const BANNER: &str = concat!(
    "veneer-uefi v",
    env!("CARGO_PKG_VERSION"),
    " — minimal Type-1 hypervisor (boot stub)"
);

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    serial::init();

    sprintln!();
    sprintln!("================================================================");
    sprintln!("{}", BANNER);
    sprintln!("================================================================");
    sprintln!("[boot] firmware handed control to UEFI app");
    sprintln!("[boot] COM1 (0x3F8) configured @ 115200 8N1");

    // Mirror to UEFI console too (visible if graphics are wired up)
    log::info!("{}", BANNER);

    // Calibrate host TSC frequency via the real PIT before SVM is armed
    // (afterwards our intercepts could re-route IO ports). Every emulator
    // that needs to translate host TSC → wall-clock time reads through
    // tsc_freq::host_tsc_freq(). On bare metal this matches the CPU's
    // invariant TSC base; under VMware nested SVM it can be 800× slower
    // because VMware virtualises RDTSC.
    let host_tsc_hz = tsc_freq::calibrate();
    sprintln!(
        "[tsc ] host TSC freq calibrated: {} Hz ({}.{:03} MHz)",
        host_tsc_hz, host_tsc_hz / 1_000_000, (host_tsc_hz / 1_000) % 1000,
    );

    let svm_state = match svm::bringup() {
        Ok(state) => {
            report_success(&state);
            Some(state)
        }
        Err(e) => {
            report_error(&e);
            None
        }
    };
    let vmcb_phys = svm_state.as_ref().map(|s| s.vmcb_phys);
    let bsp_ext_save_pa = svm_state.as_ref().map(|s| s.ext_save_pa).unwrap_or(0);
    let (msrpm_phys, iopm_phys) = svm_state
        .as_ref()
        .map(|s| (s.msrpm_phys, s.iopm_phys))
        .unwrap_or((0, 0));

    // ── Config + Profile resolution ──────────────────────────────────
    // Config (veneer behavior): NVRAM cache → fall back to compile-time
    // DEFAULT. Profile (guest fingerprint): NVRAM cache → generate from
    // config.policy.default → cache to NVRAM. After this block the
    // PROFILE / CONFIG slots are populated; intercept handlers and the
    // ACPI/SMBIOS builders read from them on every VMRUN/VMEXIT.
    // Config resolution: NVRAM → ESP TOML → DEFAULT. ESP overlay is
    // applied last so an operator editing `config.toml` always wins
    // over a stale NVRAM cache.
    let mut config = match nvram_io::load_config() {
        Ok(c) => {
            sprintln!("[cfg ] loaded from NVRAM");
            c
        }
        Err(nvram_io::NvramError::NotFound) => {
            sprintln!("[cfg ] NVRAM miss → using compile-time DEFAULT");
            config::DEFAULT
        }
        Err(nvram_io::NvramError::LayoutMismatch) => {
            sprintln!("[cfg ] NVRAM layout mismatch → resetting to DEFAULT");
            let _ = nvram_io::delete_config();
            config::DEFAULT
        }
        Err(e) => {
            sprintln!("[cfg ] NVRAM read failed ({:?}) → DEFAULT", e);
            config::DEFAULT
        }
    };
    {
        let mut tbuf = [0u8; 4096];
        match esp_io::load_into(esp_io::CONFIG_TOML_PATH, &mut tbuf) {
            Ok(n) => {
                let mut warns = 0u32;
                let applied = toml::apply_config(&tbuf[..n], &mut config, &mut warns);
                sprintln!("[cfg ] config.toml: {} fields applied, {} warnings", applied, warns);
            }
            Err(esp_io::EspError::NotFound) => {
                sprintln!("[cfg ] config.toml not present on ESP — skipping overlay");
            }
            Err(e) => {
                sprintln!("[cfg ] config.toml read failed: {:?}", e);
            }
        }
    }
    active::CONFIG.set(config);

    let cached = match nvram_io::load_profile() {
        Ok(p) => {
            sprintln!("[prof] loaded from NVRAM (cached fingerprint)");
            Some(p)
        }
        Err(nvram_io::NvramError::NotFound) => {
            sprintln!("[prof] NVRAM miss");
            None
        }
        Err(nvram_io::NvramError::LayoutMismatch) => {
            sprintln!("[prof] NVRAM layout mismatch → wiping");
            let _ = nvram_io::delete_profile();
            None
        }
        Err(e) => {
            sprintln!("[prof] NVRAM read failed ({:?})", e);
            None
        }
    };
    if let Some(ref p) = cached {
        active::PROFILE.set(*p);
    }

    // Interactive menu phase. Loops only if the user enters Advanced
    // (which then returns to the parent menu). For unattended boots the
    // countdown picks the default and falls through immediately.
    let profile = run_menu_loop(&config, cached);
    report_profile(&profile);
    active::PROFILE.set(profile);

    // vCPU detection. CPUID is always available but VMware reports the
    // guest core count as 1 there (a well-known quirk); MP Services is
    // authoritative when the firmware exposes it. We use MP Services
    // when present and fall back to CPUID only if it isn't.
    let n_cores_cpuid = vcpu_pool::detect_count();
    sprintln!("[topo] CPUID 0x8000_0008 reports {} core(s)", n_cores_cpuid);
    let mp_count = match smp::probe() {
        Ok(info) => {
            sprintln!(
                "[topo] UEFI MP Services: total={} enabled={} BSP=#{}",
                info.total, info.enabled, info.bsp_index
            );
            Some(info.enabled)
        }
        Err(smp::SmpError::ProtocolMissing) => {
            sprintln!("[topo] UEFI MP Services not exposed by firmware — using CPUID fallback");
            None
        }
        Err(e) => {
            sprintln!("[topo] MP probe failed: {:?}", e);
            None
        }
    };
    let n_vcpus = mp_count.unwrap_or(n_cores_cpuid).min(vcpu_pool::MAX_VCPUS);
    sprintln!(
        "[topo] vCPU count → {} (source: {})",
        n_vcpus,
        if mp_count.is_some() { "MP Services" } else { "CPUID" }
    );
    // Publish to CPUID handler so leaf 1.EBX (logical CPU count) and
    // 0x80000008.ECX (cores-1) report a value consistent with what the
    // guest sees via UEFI MP services and ACPI MADT.
    vmexit::cpuid::N_VCPUS.store(n_vcpus, core::sync::atomic::Ordering::Relaxed);
    if n_vcpus < 2 {
        sprintln!("[topo] note: add `numvcpus = \"4\"` to the .vmx to exercise multi-vCPU bring-up");
    }

    let n_aps = n_vcpus.saturating_sub(1);
    let per_ap_hsave = match smp::alloc_per_ap_hsave(n_aps) {
        Ok(v) => {
            sprintln!(
                "[topo] per-AP VM_HSAVE allocated for {} AP(s) (BSP keeps its own)",
                v.len()
            );
            v
        }
        Err(_) => {
            sprintln!("[topo] per-AP VM_HSAVE alloc failed");
            smp::heapless_vec::Vec::new()
        }
    };
    let per_ap_ext_save = match smp::alloc_per_ap_ext_save(n_aps) {
        Ok(v) => {
            sprintln!(
                "[topo] per-AP ext save (VMSAVE/VMLOAD) allocated for {} AP(s)",
                v.len()
            );
            v
        }
        Err(_) => {
            sprintln!("[topo] per-AP ext save alloc failed");
            smp::heapless_vec::Vec::new()
        }
    };
    if n_aps > 0 {
        match smp::run_ap_probe() {
            Ok(reports) => report_ap_probe(&reports),
            Err(e) => sprintln!("[ap  ] AP probe failed: {:?}", e),
        }
    }
    let pool = match vcpu_pool::alloc_pool(n_vcpus) {
        Ok(p) => {
            sprintln!(
                "[topo] VMCB pool allocated for {} vCPU(s)",
                p.count
            );
            Some(p)
        }
        Err(_) => {
            sprintln!("[topo] VMCB pool alloc failed — falling back to single BSP VMCB");
            None
        }
    };

    // Build ACPI + SMBIOS tables, then install them into the UEFI
    // Configuration Table so any guest using the standard EFI lookup path
    // gets our spoofed copies instead of the host firmware's real ones.
    let built_acpi: Option<acpi::Acpi> = match acpi::build(n_vcpus) {
        Ok(a) => {
            sprintln!(
                "[acpi] RSDP @ 0x{:016X}, XSDT @ 0x{:016X}, FADT @ 0x{:016X}, MADT @ 0x{:016X}, MCFG @ 0x{:016X}, HPET @ 0x{:016X}",
                a.rsdp_phys, a.xsdt_phys, a.fadt_phys, a.madt_phys, a.mcfg_phys, a.hpet_phys,
            );
            sprintln!(
                "[acpi]   DSDT @ 0x{:016X}, SSDT @ 0x{:016X}, FACS @ 0x{:016X}, SPCR @ 0x{:016X}, WSMT @ 0x{:016X}, TPM2 @ 0x{:016X}",
                a.dsdt_phys, a.ssdt_phys, a.facs_phys, a.spcr_phys, a.wsmt_phys, a.tpm2_phys
            );
            unsafe {
                match uefi_config::install(&uefi_config::EFI_ACPI_20_TABLE_GUID, a.rsdp_phys) {
                    Ok(_)  => sprintln!("[acpi] registered under EFI_ACPI_20_TABLE_GUID ✓"),
                    Err(e) => sprintln!("[acpi] registration FAILED: {:?}", e),
                }
                let _ = uefi_config::install(&uefi_config::EFI_ACPI_10_TABLE_GUID, a.rsdp_phys);
            }
            let snap = uefi_vars::snapshot();
            uefi_vars::log(&snap);
            Some(a)
        }
        Err(_) => { sprintln!("[acpi] table build failed"); None }
    };
    let built_smbios: Option<smbios::Smbios> = match smbios::build() {
        Ok(s) => {
            sprintln!(
                "[smb ] entry @ phys 0x{:016X}, table @ phys 0x{:016X}, table_len={}",
                s.entry_phys, s.table_phys, s.table_len
            );
            // Report the actual values the SMBIOS string table holds —
            // these come straight from the active profile when one is
            // set, or from the legacy fallback literals otherwise.
            match active::PROFILE.get() {
                Some(p) => {
                    let m = unsafe { core::ptr::addr_of!(p.hardware.smbios.manufacturer).read_unaligned() };
                    let pr = unsafe { core::ptr::addr_of!(p.hardware.smbios.product).read_unaligned() };
                    sprintln!("[smb ] System: Manufacturer=\"{}\" Product=\"{}\"",
                        m.as_str(), pr.as_str());
                }
                None => sprintln!("[smb ] System: Manufacturer=\"VENEER\" Product=\"Veneer Virtual Workstation\""),
            }
            unsafe {
                // Register under both SMBIOS-2 (32-bit) and SMBIOS-3 (64-bit)
                // GUIDs so guests that look up either path find us.
                match uefi_config::install(&uefi_config::EFI_SMBIOS_TABLE_GUID, s.entry_phys) {
                    Ok(_)  => sprintln!("[smb ] registered under EFI_SMBIOS_TABLE_GUID ✓"),
                    Err(e) => sprintln!("[smb ] registration FAILED: {:?}", e),
                }
                match uefi_config::install(&uefi_config::EFI_SMBIOS3_TABLE_GUID, s.entry_phys) {
                    Ok(_)  => sprintln!("[smb ] registered under EFI_SMBIOS3_TABLE_GUID ✓"),
                    Err(e) => sprintln!("[smb ] SMBIOS3 registration: {:?}", e),
                }
            }
            Some(s)
        }
        Err(_) => { sprintln!("[smb ] table build failed"); None }
    };

    // Feed SMBIOS to the OVMF guest through fw_cfg. OVMF can't see the host
    // UEFI configuration table we registered above, so without this it
    // publishes its own built-in DMI and the guest OS reads the wrong board
    // identity (and earlier saw "DMI not present" entirely).
    if let Some(s) = built_smbios.as_ref() {
        devices::fwcfg::install_smbios(
            s.entry_phys as *const u8,
            smbios::ENTRY_POINT_LEN as u32,
            s.table_phys as *const u8,
            s.table_len as u32,
        );
        sprintln!("[fwcfg] SMBIOS staged: anchor {} B + tables {} B",
            smbios::ENTRY_POINT_LEN, s.table_len);
    }

    // Feed ACPI to the OVMF guest through fw_cfg + the BiosLinkerLoader.
    // Without it OVMF installs no tables, so the guest falls back to APIC
    // virtual-wire mode with no IO-APIC routing and no ACPI interpreter.
    // The guest runs a single vCPU through the intercept dispatcher, so the
    // MADT must list exactly one local APIC — matching fw_cfg NB_CPUS=1.
    // Advertising the host's CPU count made Linux INIT-SIPI APs that never
    // come up and hang at smpboot.
    const GUEST_VCPUS: usize = 1;
    acpi_fwcfg::build_and_stage(GUEST_VCPUS);

    // ── Entry-mode toggle ─────────────────────────────────────────────
    // ENTER_LINUX_GUEST = true  → nested guest OS path (v1.0 trajectory).
    //   SVM stays enabled, we skip the 21-path BSP/AP validation, skip
    //   the BSP SVM cleanup, skip chain-load, and instead VMRUN into a
    //   Linux startup_64 (linux_loader::load + vmcb::init_guest_linux).
    //   First milestone: kernel printk reaches our serial.log.
    //
    // ENTER_LINUX_GUEST = false → legacy host-mode chain-load path,
    //   gated further by SKIP_BSP_VMRUN (diagnostic carry-over from the
    //   external-validator track: BSP entering SVM at all leaves
    //   firmware state that deadlocks ExitBootServices under VMware).
    // ENTER_OVMF_GUEST = true → full-system boot: load OVMF (guest UEFI
    //   firmware) into the top 4 MiB of guest physical and VMRUN from the
    //   architectural reset vector. OVMF then drives the standard boot
    //   chain (PCI scan → NVMe → disk bootloader → OS), exactly like a
    //   real PC. Supersedes the Linux direct-kernel-boot path.
    const ENTER_OVMF_GUEST: bool = true;
    const ENTER_LINUX_GUEST: bool = true;
    const SKIP_BSP_VMRUN: bool = true;

    if !ENTER_LINUX_GUEST {
        if SKIP_BSP_VMRUN {
            sprintln!("[vmm ] BSP VMRUN loop SKIPPED -- diagnostic (firmware untouched by SVM)");
        } else if let Some(phys) = vmcb_phys {
            run_guest(phys, bsp_ext_save_pa, pool.as_ref(), &per_ap_hsave, &per_ap_ext_save, msrpm_phys, iopm_phys);
        }
    }

    // Self-validation pass — walk our own ACPI / SMBIOS / PCI structures
    // and dump structured info to serial. Catches checksum / length /
    // ordering bugs without needing a third-party parser.
    if !ENTER_LINUX_GUEST {
        if let Some(a) = built_acpi.as_ref() {
            validator::validate_acpi(a);
        }
        if let Some(s) = built_smbios.as_ref() {
            validator::validate_smbios(s);
        }
        validator::validate_pci();
    }

    // ── Nested guest OS path (v1.0) ──────────────────────────────────
    // Stage Alpine bzImage + initramfs into guest physical, prime the
    // VMCB for startup_64, and VMRUN. Path doesn't return until the
    // guest halts/faults.
    if ENTER_OVMF_GUEST {
        if let Some(phys) = vmcb_phys {
            enter_ovmf_guest(phys, bsp_ext_save_pa, msrpm_phys, iopm_phys, n_vcpus);
            sprintln!("[ovmf-guest] VMRUN loop returned — halting");
        } else {
            sprintln!("[ovmf-guest] no VMCB available — skipping");
        }
        halt_forever()
    }

    if ENTER_LINUX_GUEST {
        if let Some(phys) = vmcb_phys {
            // ACPI is deployed inside guest RAM by enter_linux_guest itself
            // (host_ram_base + GUEST_ACPI_OFFSET). The host-resident copy
            // built earlier (built_acpi at host_phys ~0xFBB9000) is for
            // chain-load mode only and the guest can't see it through NPT.
            enter_linux_guest(phys, bsp_ext_save_pa, msrpm_phys, iopm_phys, n_vcpus);
            sprintln!("[linux-guest] VMRUN loop returned — halting");
        } else {
            sprintln!("[linux-guest] no VMCB available — skipping");
        }
        halt_forever()
    }

    // SVM cleanup so the chain-loaded image doesn't inherit EFER.SVME=1
    // on the BSP and end up with our hsave/VMCB pages still live when
    // Linux walks the host context after ExitBootServices.
    unsafe {
        let efer_before = arch::rdmsr(arch::MSR_EFER);
        arch::wrmsr(arch::MSR_EFER, efer_before & !(1u64 << 12));
        arch::wrmsr(arch::MSR_VM_HSAVE_PA, 0);
        let efer_after = arch::rdmsr(arch::MSR_EFER);
        sprintln!(
            "[svm-cleanup] BSP EFER 0x{:016x} -> 0x{:016x} (SVME bit cleared)",
            efer_before, efer_after,
        );
    }
    // AP cleanup happens inside ap_vmrun_callback itself (right before
    // each AP returns to the UEFI MP-services idle loop). We don't
    // dispatch a second startup_all_aps from BSP -- that path deadlocks
    // because the firmware can't re-wake APs that finished their first
    // callback while still in SVM host state. Per AMD APM, INIT also
    // resets EFER to 0, so even if our defensive in-callback cleanup
    // hadn't run, Linux's SIPI to each AP would clear SVME implicitly.
    sprintln!("[svm-cleanup] AP cleanup handled inside ap_vmrun_callback");
    sprintln!("[done] verification complete — attempting chain-load to next bootloader");

    if chain_load::try_chain_load() {
        // start_image returned cleanly (rare). Fall through to halt.
        sprintln!("[done] chain-loaded image returned; halting");
    } else {
        sprintln!("[done] no chain-loadable bootloader found; halting");
    }
    halt_forever()
}

fn run_guest(
    vmcb_phys: u64,
    bsp_ext_save_pa: u64,
    pool: Option<&vcpu_pool::VcpuPool>,
    per_ap_hsave: &smp::heapless_vec::Vec<u64, 32>,
    per_ap_ext_save: &smp::heapless_vec::Vec<u64, 32>,
    msrpm_phys: u64,
    iopm_phys: u64,
) {
    let blob = match guest_blob::alloc_and_write() {
        Ok(b) => b,
        Err(_) => {
            sprintln!("[blob] alloc failed — skipping guest run");
            return;
        }
    };
    sprintln!("[blob] guest payload @ phys 0x{:016X} ({} bytes)", blob.phys, blob.size);
    sprintln!("[blob] code: {}", guest_blob::BLOB_DESC);

    // Build the nested page table. Identity-map 512 GiB with 1-GiB huge
    // pages so the guest can fetch from any reasonable host-physical address.
    let npt_root = match npt::build_identity_512gib() {
        Ok(r) => r,
        Err(_) => {
            sprintln!("[npt ] page-table build failed — skipping guest run");
            return;
        }
    };
    sprintln!(
        "[npt ] identity {} GiB built — PML4 @ phys 0x{:016X}",
        npt_root.coverage_bytes / npt::ONE_GIB,
        npt_root.pml4_phys
    );
    // Publish the NPT root so the stealth exec-hook engine can arm/dispatch.
    // (The build_translated paths need the same one call when exercised.)
    crate::introspect::hook::set_npt(&npt_root);

    // Trap the Local APIC MMIO window so guest accesses route through
    // our emulator instead of touching the host LAPIC.
    match npt::install_trap_range(&npt_root, devices::irq::lapic::LAPIC_BASE, devices::irq::lapic::LAPIC_SIZE) {
        Ok(_) => sprintln!(
            "[npt ] trapped LAPIC MMIO 0x{:016X}..0x{:016X} ({} KiB)",
            devices::irq::lapic::LAPIC_BASE,
            devices::irq::lapic::LAPIC_BASE + devices::irq::lapic::LAPIC_SIZE,
            devices::irq::lapic::LAPIC_SIZE / 1024
        ),
        Err(_) => sprintln!("[npt ] LAPIC trap install failed (continuing without LAPIC emulation)"),
    }
    match npt::install_trap_range(&npt_root, devices::bus::nic::base(), devices::bus::nic::NIC_BAR0_TRAP_SIZE) {
        Ok(_) => sprintln!(
            "[npt ] trapped NIC BAR0 0x{:016X}..0x{:016X} ({} KiB)",
            devices::bus::nic::base(),
            devices::bus::nic::base() + devices::bus::nic::NIC_BAR0_TRAP_SIZE,
            devices::bus::nic::NIC_BAR0_TRAP_SIZE / 1024
        ),
        Err(_) => sprintln!("[npt ] NIC BAR0 trap install failed"),
    }
    match npt::install_trap_range(&npt_root, devices::storage::nvme::NVME_BAR0_DEFAULT, devices::storage::nvme::NVME_BAR0_TRAP_SIZE) {
        Ok(_) => sprintln!(
            "[npt ] trapped NVMe BAR0 0x{:016X}..0x{:016X} ({} KiB)",
            devices::storage::nvme::NVME_BAR0_DEFAULT,
            devices::storage::nvme::NVME_BAR0_DEFAULT + devices::storage::nvme::NVME_BAR0_TRAP_SIZE,
            devices::storage::nvme::NVME_BAR0_TRAP_SIZE / 1024
        ),
        Err(_) => sprintln!("[npt ] NVMe BAR0 trap install failed"),
    }
    // HPET MMIO: instead of trapping (every HalpHpetArmTimer re-arm = ~7 NPF
    // at ~155 us each under nested SVM => boot-time storm), back it with a
    // writable host page so guest reads/writes hit RAM. veneer reconciles the
    // counter / comparator lazily in the dispatcher (hpet::shadow_tick).
    match npt::map_backing_page(&npt_root, devices::irq::hpet::HPET_BASE) {
        Ok(page) => {
            devices::irq::hpet::set_backing(page);
            sprintln!(
                "[npt ] HPET MMIO writable-shadow at GPA 0x{:016X} -> HPA 0x{:016X}",
                devices::irq::hpet::HPET_BASE, page
            );
        }
        Err(_) => {
            sprintln!("[npt ] HPET backing-page map FAILED — falling back to trapped MMIO");
            let _ = npt::install_trap_range(&npt_root, devices::irq::hpet::HPET_BASE, devices::irq::hpet::HPET_SIZE);
        }
    }
    match npt::install_trap_range(&npt_root, devices::tpm::TPM_BASE, devices::tpm::TPM_SIZE) {
        Ok(_) => sprintln!(
            "[npt ] trapped TPM CRB 0x{:016X}..0x{:016X} ({} KiB)",
            devices::tpm::TPM_BASE,
            devices::tpm::TPM_BASE + devices::tpm::TPM_SIZE,
            devices::tpm::TPM_SIZE / 1024
        ),
        Err(_) => sprintln!("[npt ] TPM CRB trap install failed"),
    }
    match npt::install_trap_range(&npt_root, devices::irq::ioapic::IOAPIC_BASE, devices::irq::ioapic::IOAPIC_SIZE) {
        Ok(_) => sprintln!(
            "[npt ] trapped IO APIC 0x{:016X}..0x{:016X} ({} KiB)",
            devices::irq::ioapic::IOAPIC_BASE,
            devices::irq::ioapic::IOAPIC_BASE + devices::irq::ioapic::IOAPIC_SIZE,
            devices::irq::ioapic::IOAPIC_SIZE / 1024
        ),
        Err(_) => sprintln!("[npt ] IO APIC trap install failed"),
    }
    match npt::install_trap_range(&npt_root, devices::bus::xhci::base(), devices::bus::xhci::XHCI_SIZE) {
        Ok(_) => sprintln!(
            "[npt ] trapped xHCI MMIO 0x{:016X}..0x{:016X} ({} KiB)",
            devices::bus::xhci::base(),
            devices::bus::xhci::base() + devices::bus::xhci::XHCI_SIZE,
            devices::bus::xhci::XHCI_SIZE / 1024
        ),
        Err(_) => sprintln!("[npt ] xHCI trap install failed"),
    }
    devices::tpm::init();
    sprintln!("[tpm ] CRB + cmd processor ready (AMD fTPM identity, EK cert at NV 0x01C00002)");

    let vmcb_ptr = vmcb_phys as *mut vmcb::Vmcb;
    let mode = vmcb::GuestMode::Long64 { code_lin: blob.phys };
    unsafe { vmcb::init_guest(vmcb_ptr, mode); }
    unsafe { vmcb::enable_npt(vmcb_ptr, npt_root.pml4_phys); }
    sprintln!(
        "[vmcb] guest state primed: {:?} — RIP=0x{:016X}",
        mode, blob.phys
    );
    sprintln!(
        "[vmcb] NPT armed: np_enable=1, NCR3=0x{:016X}",
        npt_root.pml4_phys
    );

    bsp_vmrun_loop(vmcb_phys, bsp_ext_save_pa, vmcb_ptr);

    if let Some(pool) = pool {
        run_aps(pool, bsp_ext_save_pa, per_ap_hsave, per_ap_ext_save, blob.phys, npt_root.pml4_phys, msrpm_phys, iopm_phys);
    }
}

/// BSP-side VMRUN dispatch loop. Verbose — every iteration prints the
/// VMEXIT + the post-handler register snapshot so the operator can audit
/// Nested guest OS entry — stage Alpine bzImage + initramfs, prime VMCB
/// for `startup_64`, VMRUN into the kernel. Long-running; returns only
/// when the guest halts, aborts, or exceeds the iteration cap.
fn enter_linux_guest(
    vmcb_phys: u64,
    host_ext_save_pa: u64,
    msrpm_phys: u64,
    iopm_phys: u64,
    n_vcpus: usize,
) {
    sprintln!("[linux-guest] preparing Linux nested-guest entry");

    // Enable KVM paravirt CPUID signature for the duration of the Linux
    // boot trajectory. Without this AMD CPUs have no way to advertise
    // their TSC frequency to the kernel — Linux falls through to PIT-
    // based calibration which our IO-trap latency makes unreliable, and
    // the boot hangs in `tsc: Marking TSC unstable`. The override is
    // scoped to this path only; chain-load and Windows trajectories
    // keep `hide_hypervisor_leaf = true`.
    vmexit::cpuid::PARAVIRT_KVM_OVERRIDE.store(true, core::sync::atomic::Ordering::Release);
    sprintln!("[cpuid] KVM paravirt CPUID signature ENABLED for Linux boot");

    // Pre-arm host XCR0 with every component the host CPU supports
    // (CPUID 0xD sub-leaf 0 EDX:EAX). The guest's CPUID 0xD.EBX read
    // — which Linux uses to size XSAVE state at boot — depends on the
    // host's current XCR0; if the guest reads it while we're still on
    // UEFI's "x87 only" default and then turns on AVX via XSETBV, the
    // EBX value it cached no longer matches the new state size and
    // fpu__init_system_xstate panics with
    //   "XSAVE consistency problem: size 880 != kernel_size 840"
    //   Kernel panic - not syncing: Attempted to kill the idle task!
    //
    // Lifting XCR0 to max-supported up front means every guest CPUID
    // 0xD read sees the same "fully enabled" sizes and the consistency
    // check passes. Requires CR4.OSXSAVE = 1 (XSETBV would #UD without
    // it on a UEFI-default CR4).
    unsafe {
        let mut cr4: u64;
        core::arch::asm!(
            "mov {}, cr4",
            out(reg) cr4,
            options(nomem, nostack, preserves_flags),
        );
        if cr4 & (1u64 << 18) == 0 {
            cr4 |= 1u64 << 18; // OSXSAVE
            core::arch::asm!(
                "mov cr4, {}",
                in(reg) cr4,
                options(nomem, nostack, preserves_flags),
            );
        }
        // Restrict to the lowest-common-denominator subset Linux 6.x
        // builds compile-time support for and which our CPUID 0xD
        // intercept (see intercept/cpuid.rs) also publishes:
        //   bit 0 = x87 (mandatory)
        //   bit 1 = SSE
        //   bit 2 = AVX
        // CET (bits 11/12, +40 bytes), AMX (bits 17/18, +8 KiB),
        // and PKRU (bit 9) come along when we pass-through the host
        // mask but they all bloat CPUID 0xD.EBX past Linux's own
        // calculated_size, tripping "XSAVE consistency problem:
        // size 880 != kernel_size 840". Capping at AVX keeps the
        // sizes in lockstep.
        let host_d = arch::cpuid(0x0000_000D);
        // x87 | SSE | AVX | PKRU. PKRU (bit 9) is standard on every
        // recent Intel/AMD CPU and Linux's signal-frame fpstate copy
        // (copy_fpstate_to_sigframe → get_xsave_addr_user) WARNs at
        // PID 1 if it asks for the PKRU offset and we've masked it
        // out. Including it costs 8 bytes of XSAVE area and matches
        // what the host CPU actually supports.
        let xcr0_lo = (host_d.eax & 0x207) | 0x1; // x87 | SSE | AVX | PKRU
        let xcr0_hi: u32 = 0;
        core::arch::asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") xcr0_lo,
            in("edx") xcr0_hi,
            options(nomem, nostack, preserves_flags),
        );
        sprintln!(
            "[xcr0] host XCR0 pre-armed = 0x{:08X}_{:08X} (capped at AVX for Linux XSAVE consistency)",
            xcr0_hi, xcr0_lo,
        );
    }

    // Re-calibrate host TSC freq via RTC Update-In-Progress polling.
    // Why RTC and not PIT/Stall: under VMware nested SVM the host TSC
    // rate visible to SVM-mode code diverges from both the PIT and
    // Boot Services Stall (boots earlier observed 250× scaling between
    // wall clock and apparent host TSC). The MC146818 RTC keeps strict
    // 1 Hz semantics across virtualisation layers — UIP edges fire on
    // real wall clock — so it's the one source we can trust to compute
    // a kvmclock anchor that doesn't race time.
    //
    // Cost: one wall-clock second of veneer startup. Cheap relative to
    // the guest boot it unblocks.
    let svm_mode_freq = tsc_freq::calibrate_via_rtc_uip();
    tsc_freq::store_host_tsc_freq(svm_mode_freq);
    sprintln!(
        "[tsc ] SVM-mode RTC-UIP calibration: {} Hz ({}.{:03} MHz)",
        svm_mode_freq,
        svm_mode_freq / 1_000_000,
        (svm_mode_freq / 1_000) % 1000,
    );
    // Anchor the faithful clock to the host HPET (a wall-clock-reliable
    // counter here) using the just-measured host TSC frequency.
    crate::infra::clock::init_hpet_clock(svm_mode_freq);

    // Diagnostic: report whether the host CPU exposes the AMD SVM
    // TscRateMsr feature (CPUID 0x8000_000A.EDX bit 4). When 1, the
    // hardware path for TSC scaling via MSR_AMD64_TSC_RATIO is open
    // and the same software anchor we just applied could later move
    // into the hardware path for free. When 0 (typical under VMware
    // nested SVM that hides AMD SVM extensions), software anchoring
    // via the RTC measurement above is the only option.
    let svm_feat = arch::cpuid(0x8000_000A);
    let tsc_rate_msr = (svm_feat.edx >> 4) & 1;
    sprintln!(
        "[svm ] CPUID 0x8000_000A.EDX = 0x{:08X}, TscRateMsr (bit 4) = {}",
        svm_feat.edx, tsc_rate_msr,
    );

    // ── 1. Read vmlinuz + initramfs from our ESP ────────────────────
    let our_image = uefi::boot::image_handle();
    let mut fs = match uefi::boot::get_image_file_system(our_image) {
        Ok(f) => f,
        Err(e) => {
            sprintln!("[linux-guest] get_image_file_system: {:?}", e.status());
            return;
        }
    };
    let mut root = match fs.open_volume() {
        Ok(r) => r,
        Err(e) => {
            sprintln!("[linux-guest] open_volume: {:?}", e.status());
            return;
        }
    };
    let vmlinux = match chain_load::read_file_at(
        &mut root,
        uefi::cstr16!("\\vmlinux.elf"),
        64 * 1024 * 1024,
    ) {
        Ok(b) => b,
        Err(reason) => {
            sprintln!("[linux-guest] vmlinux.elf: {}", reason);
            return;
        }
    };
    let initrd = match chain_load::read_file_at(
        &mut root,
        uefi::cstr16!("\\initramfs-lts"),
        64 * 1024 * 1024,
    ) {
        Ok(b) => b,
        Err(reason) => {
            sprintln!("[linux-guest] initramfs: {}", reason);
            return;
        }
    };
    sprintln!(
        "[linux-guest] ESP read: vmlinux.elf {} byte, initramfs {} byte",
        vmlinux.len(), initrd.len()
    );

    // ── 2. cmdline ──────────────────────────────────────────────────
    // earlycon=uart,io,0x3f8 → kernel writes printk to our intercepted
    // ttyS0; io.rs forwards those bytes to the host 8250 so they land
    // in veneer-serial.log. No `console=tty0` here -- the guest has no
    // framebuffer in our environment, and adding tty0 would re-route
    // /dev/console there and starve serial.
    // nr_cpus=1 (essential): pin percpu to one CPU even though MADT
    // claims 4 -- 4-way percpu init had broken PCP free-list pointers.
    // Other diagnostic flags removed: page_owner=on / slub_debug=FZPU
    // pulled in stackdepot (8192 pools, 32 MiB memblock alloc) which
    // tripped a fresh triple fault before mem_init even ran. Stripped
    // back to baseline minimum so we can see whether the bare kernel
    // boots at all -- richer instrumentation can come back once we
    // pass mem_init.
    // `tsc=reliable` was hijacking the calibration path — AMD has no
    // CPUID 0x15/0x16 (Intel-only) and `cpu_khz_from_msr` is also Intel,
    // so with `tsc=reliable` Linux skipped quick_pit_calibrate entirely
    // and left cpu_khz=0 → "Marking TSC unstable" + no boot progress.
    // Without it, native_calibrate_cpu_early falls through to quick_pit
    // and our PIT emulator services the calibration the normal way.
    let cmdline =
        "earlycon=uart,io,0x3f8,115200n8 console=ttyS0,115200 \
         nr_cpus=1 maxcpus=1 \
         amd_iommu=off iommu=off \
         loglevel=8 printk.devkmsg=on \
         panic=10 nokaslr";

    // ── 3. Allocate an isolated 1-GiB host-physical block for guest
    //       RAM. NPT will map guest_phys 0..1 GiB onto this block, so
    //       the guest sees a clean zero-based physical space and can't
    //       reach our UEFI BootServices memory or our own VMCB/NPT/
    //       ACPI pages -- triple-fault root cause until now (M1 boots
    //       up through stackdepot then host SHUTDOWN). ────────────────
    let host_ram_pages = (linux_loader::GUEST_RAM_BYTES / 4096) as usize;
    let host_ram_phys = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::RUNTIME_SERVICES_DATA,
        host_ram_pages,
    ) {
        Ok(p) => p.as_ptr() as u64,
        Err(e) => {
            sprintln!(
                "[linux-guest] could not allocate 1 GiB guest RAM block: {:?}",
                e.status()
            );
            return;
        }
    };
    // Round up to 1-GiB alignment (NPT 1-GiB huge entries need it).
    let host_ram_base = (host_ram_phys + (npt::ONE_GIB - 1)) & !(npt::ONE_GIB - 1);
    if host_ram_base != host_ram_phys {
        sprintln!(
            "[linux-guest] allocated 0x{:X}, alignment-rounded to 0x{:X} (skipping {} byte)",
            host_ram_phys, host_ram_base, host_ram_base - host_ram_phys,
        );
        // Note: AllocatePages may not honour 1 GiB alignment; if rounding
        // pushed us into unallocated memory the kernel will crash on
        // first access. For first cut we just log; long-term we should
        // over-allocate and reserve.
    }
    sprintln!(
        "[linux-guest] guest RAM 1 GiB allocated at host phys 0x{:016X}",
        host_ram_base,
    );

    // Wire kvmclock to the freshly-allocated guest RAM so its
    // pvclock_vcpu_time_info / pvclock_wall_clock writes know how to
    // translate guest physical → host pointer.
    devices::kvmclock::set_host_ram_base(host_ram_base);

    // Same translation for the NVMe emulator: queue bases, PRP buffers and
    // CQ slots the guest hands us are guest-physical and reach host memory
    // only through this base. Then bind a real backing disk via UEFI Block
    // I/O (Boot Services still alive here) so guest NVMe READ/WRITE serve
    // actual on-disk blocks.
    devices::storage::nvme::set_host_ram_base(host_ram_base);
    // Central gpa→host translation (low region only on the Linux path).
    guest_mem::set_layout(host_ram_base, linux_loader::GUEST_RAM_BYTES, 0, 0);
    devices::storage::backend::init();

    // ── 3b. Deploy ACPI tables inside guest RAM (standard hypervisor
    // pattern — KVM/QEMU/Cloud HV/Firecracker/Xen all do this). The
    // guest reaches them through NPT; host UEFI memory stays invisible.
    // Last 1 MiB of the 1 GiB block is reserved for ACPI (4 KiB used,
    // rest stays as ACPI-reclaim in e820).
    const GUEST_ACPI_OFFSET: u64 = 0x3FF0_0000;  // 1 GiB - 1 MiB
    let acpi_host_dest = host_ram_base + GUEST_ACPI_OFFSET;
    let acpi = unsafe { acpi::build_at(acpi_host_dest, GUEST_ACPI_OFFSET, n_vcpus) };
    let rsdp_phys = acpi.rsdp_phys;  // = GUEST_ACPI_OFFSET (guest physical)
    sprintln!(
        "[linux-guest] ACPI in guest RAM: RSDP guest_phys 0x{:08X} (host_phys 0x{:016X}), XSDT 0x{:08X}, FADT 0x{:08X}, MADT 0x{:08X}",
        acpi.rsdp_phys, acpi_host_dest, acpi.xsdt_phys, acpi.fadt_phys, acpi.madt_phys,
    );

    // ── 4. Stage kernel + initrd + boot_params via load_elf (bzImage
    //       decompressor bypassed, but classic long-mode boot_params).
    //       boot_params.acpi_rsdp_addr = guest_phys RSDP -> Linux skips
    //       BIOS scan and picks up our ACPI directly.
    let loaded = match linux_loader::load_elf(&vmlinux, &initrd, cmdline, rsdp_phys, host_ram_base) {
        Ok(l) => l,
        Err(e) => {
            sprintln!("[linux-guest] ELF loader: {:?}", e);
            return;
        }
    };

    // ── 5. Build NPT: guest_phys 0..1 GiB → host_phys [host_ram_base, +1 GiB]
    let npt_root = match npt::build_translated(host_ram_base, (linux_loader::GUEST_RAM_BYTES / npt::ONE_GIB) as usize) {
        Ok(r) => r,
        Err(e) => {
            sprintln!("[linux-guest] NPT build failed: {:?}", e);
            return;
        }
    };
    sprintln!(
        "[linux-guest] NPT translated: guest 0..{} GiB -> host 0x{:016X}.., PML4 @ 0x{:016X}",
        npt_root.coverage_bytes / npt::ONE_GIB, host_ram_base, npt_root.pml4_phys,
    );
    // DIAGNOSTIC: NPT MMIO traps disabled. install_trap_range() splits
    // a 1 GiB huge entry down to 4 KiB and rewrites the surrounding
    // PTEs -- if the split has a bug, every neighbouring page in the
    // same GiB becomes wrongly mapped. With identity NPT and no traps
    // the kernel can't reach our emulators (LAPIC/HPET/NVMe/etc fall
    // through to host hardware, which is fine for diagnosing whether
    // mem_init still NULL-derefs), but we get a clean baseline.
    devices::tpm::init();

    // ── 6. Prime VMCB for PVH 32-bit entry ───────────────────────────
    let vmcb_ptr = vmcb_phys as *mut vmcb::Vmcb;
    unsafe {
        vmcb::init_for_cpuid_intercept(vmcb_ptr, msrpm_phys, iopm_phys);
        // The 21-path validator's intercept set is way too aggressive for
        // a real OS kernel. We turn off everything that:
        //   - has a stub handler that doesn't fully emulate the
        //     instruction (PUSHF/POPF skip RSP±8, CR/DR writes drop the
        //     new value), OR
        //   - the kernel will hit thousands of times per second and
        //     resolve itself (CR3 swaps, #PF demand-paging, #UD probes,
        //     IDTR/GDTR loads during boot).
        // What stays trapped: CPUID, MSR, IOIO, HLT, RDTSC, RDPMC,
        // INVD (so we don't kill host caches), VMRUN/VMMCALL/VMSAVE/etc
        // (mandatory or anti-detect-load-bearing), MONITOR/MWAIT,
        // XSETBV, and the rare/catastrophic exceptions (#DE/#DF/#TS/
        // #NP/#SS/#MF/#MC/#XF/#VE/#CP).
        let c = &mut (*vmcb_ptr).control;
        c.intercept_vec1 &= !(
              vmcb::intercept_vec1::PUSHF
            | vmcb::intercept_vec1::POPF
            | vmcb::intercept_vec1::IDTR_READ
            | vmcb::intercept_vec1::GDTR_READ
            | vmcb::intercept_vec1::LDTR_READ
            | vmcb::intercept_vec1::TR_READ
        );
        // XSETBV stays trapped — our handler clamps to the host valid
        // mask and issues the real instruction. Previously we disabled
        // the intercept and let the guest run native XSETBV; that left
        // host XCR0 mismatched with what the guest thought it had set,
        // crashing fpu__init_system_xstate with an "Attempted to kill
        // the idle task" panic. The clamped emulation is the standard
        // hypervisor pattern (KVM `handle_xsetbv`).
        c.intercept_cr_read  = 0;   // no CR0/CR3/CR4/CR2/CR8 read trap
        c.intercept_cr_write = 0;   // no CR write trap (CR3 swap was crashing the kernel)
        c.intercept_dr_read  = 0;   // DR access -- kernel uses for debug
        c.intercept_dr_write = 0;
        // Pass through every exception the guest kernel routinely
        // handles itself. We previously only let #DB/#BP/#UD/#NM/#GP/
        // #PF/#AC through, but Linux/Windows can also raise #DE, #OF,
        // #BR, #DF, #MF (x87), #XF (SSE), and #CP during normal boot
        // and any of those hitting our abort path was a hidden cliff.
        // Only #MC (machine-check) stays intercepted because it has to
        // be handled in host context — a guest #MC is rarely real and
        // we don't want our hypervisor to silently disappear.
        let pass_through_excp: u32 = 0xFFFF_FFFF & !(1u32 << 18);
        c.intercept_exceptions &= !pass_through_excp;
        vmcb::init_guest(vmcb_ptr, vmcb::GuestMode::LinuxKernel {
            entry_rip: loaded.entry_rip,
            boot_params_phys: loaded.boot_params_phys,
            guest_cr3: loaded.guest_cr3,
        });
        vmcb::enable_npt(vmcb_ptr, npt_root.pml4_phys);
        c.guest_asid = 1;
    }
    // AMD SVM TSC offset — VMCB.control.tsc_offset (0x50) is added to
    // host RDTSC before it reaches the guest. Anchoring on the current
    // host TSC means the guest sees RDTSC starting from ~0 at boot,
    // which matches every real PC at power-on. Without this the guest
    // would see whatever host uptime has accumulated (hours of host
    // wall-clock counted as boot time), which trips TSC-based sanity
    // checks in Windows and several anti-cheat heuristics.
    unsafe {
        let c = &mut (*vmcb_ptr).control;
        let now = core::arch::x86_64::_rdtsc();
        let offset = 0u64.wrapping_sub(now);
        c.tsc_offset = offset;
        // Mirror the same offset into kvmclock so its pvclock anchor
        // (tsc_timestamp + system_time) matches what the guest's RDTSC
        // will report. Without this the guest sees a kvm-clock that
        // jumps decades on every read.
        devices::kvmclock::set_tsc_offset(offset);
        sprintln!(
            "[vmcb] TSC offset = -0x{:016X} (guest RDTSC starts at 0)",
            now,
        );
    }

    sprintln!(
        "[linux-guest] VMCB primed: RIP=0x{:016X} RSI=0x{:X}",
        loaded.entry_rip, loaded.boot_params_phys,
    );

    // ── 7. GuestGprs: RSI = boot_params (long-mode boot.rst) ─────────
    let mut gprs = gprs::GuestGprs::default();
    gprs.rsi = loaded.boot_params_phys;

    // ── 8. Long-running VMRUN loop ──────────────────────────────────
    linux_vmrun_loop(vmcb_phys, host_ext_save_pa, vmcb_ptr, &mut gprs, host_ram_base);

    // ── 9. Post-boot host-memory dump for diagnostics ────────────────
    // After the VMRUN loop returns (Abort/Halt), inspect specific
    // guest_phys areas through host-side memory access. Our NPT is
    // identity-translated to host_ram_base..+1G, so we can read any
    // guest_phys gpa as host *((host_ram_base + gpa) as *const u64).
    //
    // Target: .data..percpu template + 0x28EA0 = the address kernel
    // panic dereferenced. If the value is still 0, the kernel never
    // initialized that location (= our hypothesis correct). If
    // non-zero, the kernel wrote it but per_cpu translation took us
    // somewhere else.
    //
    // Vmlinux ELF said .data PT_LOAD is at paddr 0x02C00000 and
    // .data..percpu vaddr 0xffffffff83603000 sits 0xA03000 above the
    // PT_LOAD vaddr (.data starts at vaddr 0xffffffff82c00000),
    // so its paddr is 0x02C00000 + 0xA03000 = 0x03603000.
    // Template+0x28EA0 = 0x0362BEA0 guest_phys = host_ram_base+0x0362BEA0.
    let percpu_template_gpa = 0x0362BEA0u64;
    let percpu_host = host_ram_base + percpu_template_gpa;
    let template_word = unsafe { *(percpu_host as *const u64) };
    sprintln!(
        "[dbg] .data..percpu+0x28EA0 (panic RAX target) @ host_phys 0x{:016X} = 0x{:016X}",
        percpu_host, template_word,
    );
    // Dump 64 bytes around it for context (4 list_heads = 4 pairs of u64)
    for off in (0..64).step_by(8) {
        let addr = percpu_host - 32 + off;
        let v = unsafe { *(addr as *const u64) };
        sprintln!("[dbg]   +{:+4} @ 0x{:X} = 0x{:016X}", (off as i64) - 32, addr, v);
    }
    // GS_BASE per-cpu base dump (if reachable)
    let gs_base_in_panic: u64 = 0xFFFF8880_BB5FD000;
    let page_offset: u64 = 0xFFFF8880_00000000;
    let percpu_real_gpa = gs_base_in_panic.wrapping_sub(page_offset);
    if percpu_real_gpa < linux_loader::GUEST_RAM_BYTES {
        let percpu_real_host = host_ram_base + percpu_real_gpa + 0x28EA0;
        let real_word = unsafe { *(percpu_real_host as *const u64) };
        sprintln!("[dbg] real-percpu+0x28EA0 host 0x{:X} = 0x{:016X}",
            percpu_real_host, real_word);
    } else {
        sprintln!("[dbg] GS_BASE-derived percpu_real_gpa 0x{:X} outside 1 GiB NPT",
            percpu_real_gpa);
    }

    // Stack walk: panic RSP = 0xFFFFFFFF_82C03BE0 (kernel image .data
    // region). [RSP+0x10] = return address pushed by caller's `call
    // __list_del_entry_valid_or_report` = exactly __rmqueue_pcplist+0x4f.
    // Read it from host -- this gives us the caller's virtual address
    // without needing kallsyms decode.
    let panic_rsp_v: u64 = 0xFFFFFFFF_82C03BE0;
    let panic_rsp_phys = 0x02C00000u64 + (panic_rsp_v - 0xFFFFFFFF_82C00000);
    let panic_rsp_host = host_ram_base + panic_rsp_phys;
    sprintln!("[dbg] panic RSP virt=0x{:X} phys=0x{:X} host=0x{:X}",
        panic_rsp_v, panic_rsp_phys, panic_rsp_host);
    sprintln!("[dbg] stack content (first 8 qwords from RSP):");
    for i in 0..8u64 {
        let h = panic_rsp_host + i * 8;
        let v = unsafe { *(h as *const u64) };
        sprintln!("[dbg]   [RSP+0x{:02X}] @ 0x{:X} = 0x{:016X}", i*8, h, v);
    }

    // ── 결정타 DUMP: __per_cpu_offset[] array ──────────────────────
    // virtual = 0xFFFFFFFF_8255F480 (from __ksymtab decode)
    // .rodata base vaddr = 0xFFFFFFFF_82000000 → paddr 0x02000000
    // delta = 0x55F480, paddr = 0x0255F480
    // host_phys = host_ram_base + 0x0255F480
    let per_cpu_offset_gpa: u64 = 0x0255F480;
    let per_cpu_offset_host = host_ram_base + per_cpu_offset_gpa;
    sprintln!(
        "[dbg] === __per_cpu_offset[] @ host_phys 0x{:016X} (first 8 entries) ===",
        per_cpu_offset_host,
    );
    for i in 0..8u64 {
        let entry_host = per_cpu_offset_host + i * 8;
        let val = unsafe { *(entry_host as *const u64) };
        sprintln!("[dbg]   __per_cpu_offset[{}] @ 0x{:X} = 0x{:016X}", i, entry_host, val);
    }
    // If __per_cpu_offset[0] is non-zero, it's the delta from
    // __per_cpu_start to the real per-cpu area base. Then GS_BASE
    // should equal __per_cpu_start + __per_cpu_offset[0].
    // __per_cpu_start vaddr = 0xFFFFFFFF_83603000.
    let entry0 = unsafe { *(per_cpu_offset_host as *const u64) };
    let computed_gs = 0xFFFFFFFF_83603000u64.wrapping_add(entry0);
    sprintln!(
        "[dbg] computed GS_BASE = __per_cpu_start + offset[0] = 0x{:016X}",
        computed_gs,
    );
}

/// Full-system guest entry: load OVMF (guest UEFI firmware) into the top
/// 4 MiB of guest physical, map guest RAM, and VMRUN from the
/// architectural reset vector (0xFFFFFFF0). OVMF then runs SEC → PEI →
/// DXE → BDS and drives the standard PC boot chain off veneer's emulated
/// devices (PCI / NVMe / etc). Long-running; returns on halt/abort/cap.
fn enter_ovmf_guest(
    vmcb_phys: u64,
    host_ext_save_pa: u64,
    msrpm_phys: u64,
    iopm_phys: u64,
    _n_vcpus: usize,
) {
    sprintln!("[ovmf-guest] preparing OVMF firmware boot");

    let svm_mode_freq = tsc_freq::calibrate_via_rtc_uip();
    tsc_freq::store_host_tsc_freq(svm_mode_freq);
    sprintln!("[ovmf-guest] SVM-mode TSC: {} Hz", svm_mode_freq);
    // Anchor the faithful clock to the host HPET (a wall-clock-reliable
    // counter here) using the just-measured host TSC frequency.
    crate::infra::clock::init_hpet_clock(svm_mode_freq);

    // 1. Read OVMF CODE + VARS from our ESP.
    let our_image = uefi::boot::image_handle();
    let mut fs = match uefi::boot::get_image_file_system(our_image) {
        Ok(f) => f,
        Err(e) => { sprintln!("[ovmf-guest] get_image_file_system: {:?}", e.status()); return; }
    };
    let mut root = match fs.open_volume() {
        Ok(r) => r,
        Err(e) => { sprintln!("[ovmf-guest] open_volume: {:?}", e.status()); return; }
    };
    let code = match chain_load::read_file_at(&mut root, uefi::cstr16!("\\OVMFCODE.FD"), 8 * 1024 * 1024) {
        Ok(b) => b,
        Err(r) => { sprintln!("[ovmf-guest] OVMF_CODE_4M.fd: {}", r); return; }
    };
    let vars = match chain_load::read_file_at(&mut root, uefi::cstr16!("\\OVMFVARS.FD"), 4 * 1024 * 1024) {
        Ok(b) => b,
        Err(r) => { sprintln!("[ovmf-guest] OVMF_VARS_4M.fd: {}", r); return; }
    };
    sprintln!("[ovmf-guest] ESP read: CODE {} B, VARS {} B", code.len(), vars.len());

    const OVMF_WINDOW_BASE: u64 = 0xFFC0_0000;
    const OVMF_WINDOW_SIZE: u64 = 0x0040_0000; // 4 MiB
    if (vars.len() as u64 + code.len() as u64) != OVMF_WINDOW_SIZE {
        sprintln!("[ovmf-guest] WARN: CODE+VARS = 0x{:X}, expected 0x{:X}", vars.len() + code.len(), OVMF_WINDOW_SIZE);
    }

    // 2. Allocate guest RAM (1 GiB), 1-GiB aligned. AllocatePages won't
    //    honour alignment, so over-allocate by ONE_GIB and round the base
    //    UP *within* the allocation — guaranteeing [host_ram_base, +1GiB)
    //    is real, owned memory. (The previous code rounded a 1-GiB-exact
    //    allocation up past its own end, leaving the nominal window partly
    //    unowned; later OVMF / NPT-page allocations then landed inside it
    //    and the NPT entries got clobbered → reset-vector NPF.)
    let host_ram_pages = ((linux_loader::GUEST_RAM_BYTES + npt::ONE_GIB) / 4096) as usize;
    let host_ram_phys = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::RUNTIME_SERVICES_DATA,
        host_ram_pages,
    ) {
        Ok(p) => p.as_ptr() as u64,
        Err(e) => { sprintln!("[ovmf-guest] guest RAM alloc failed: {:?}", e.status()); return; }
    };
    let host_ram_base = (host_ram_phys + (npt::ONE_GIB - 1)) & !(npt::ONE_GIB - 1);
    sprintln!(
        "[ovmf-guest] guest RAM 1 GiB @ host 0x{:016X} (alloc 0x{:016X}, 2 GiB reserved)",
        host_ram_base, host_ram_phys
    );

    // 3. Allocate a 4 MiB host block for OVMF, write VARS then CODE.
    let ovmf_pages = (OVMF_WINDOW_SIZE / 4096) as usize;
    let ovmf_host = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::RUNTIME_SERVICES_DATA,
        ovmf_pages,
    ) {
        Ok(p) => p.as_ptr() as u64,
        Err(e) => { sprintln!("[ovmf-guest] OVMF block alloc failed: {:?}", e.status()); return; }
    };
    unsafe {
        core::ptr::write_bytes(ovmf_host as *mut u8, 0, OVMF_WINDOW_SIZE as usize);
        core::ptr::copy_nonoverlapping(vars.as_ptr(), ovmf_host as *mut u8, vars.len());
        core::ptr::copy_nonoverlapping(code.as_ptr(), (ovmf_host + vars.len() as u64) as *mut u8, code.len());
    }
    sprintln!("[ovmf-guest] OVMF staged @ host 0x{:016X} (VARS@+0, CODE@+0x{:X})", ovmf_host, vars.len());

    // 4. Wire emulators + bind backing disk.
    devices::kvmclock::set_host_ram_base(host_ram_base);
    devices::storage::nvme::set_host_ram_base(host_ram_base);
    devices::storage::ahci::set_host_ram_base(host_ram_base);
    vmexit::io::set_guest_ram_base(host_ram_base);
    devices::storage::backend::init();

    // 5. NPT: guest 0..1 GiB -> host RAM; top 4 MiB -> OVMF block.
    let npt_root = match npt::build_translated(host_ram_base, (linux_loader::GUEST_RAM_BYTES / npt::ONE_GIB) as usize) {
        Ok(r) => r,
        Err(e) => { sprintln!("[ovmf-guest] NPT build failed: {:?}", e); return; }
    };
    match npt::map_range(&npt_root, OVMF_WINDOW_BASE, ovmf_host, OVMF_WINDOW_SIZE) {
        Ok(_) => sprintln!("[ovmf-guest] NPT: guest [0x{:08X},0x100000000) -> OVMF block", OVMF_WINDOW_BASE),
        Err(e) => { sprintln!("[ovmf-guest] OVMF NPT map failed: {:?}", e); return; }
    }

    // 5b. High RAM above the 4 GiB device hole. Allocate as much contiguous
    // host memory as we can (fallback ladder) and map it at guest 4 GiB, so the
    // guest total = low (GUEST_RAM_BYTES) + high. The guest reports both halves
    // via CMOS (0x34/0x35 below-4G, 0x5B-0x5D above-4G) and uses them as a
    // standard split memory map. Backs WinPE / large boot.wim loads.
    let low_size = linux_loader::GUEST_RAM_BYTES;
    guest_mem::set_layout(host_ram_base, low_size, 0, 0);
    let mut high_gib = 0u64;
    for gib in [12u64, 8, 4, 2] {
        let pages = ((gib + 1) * npt::ONE_GIB / 4096) as usize; // +1 GiB align slack
        if let Ok(p) = uefi::boot::allocate_pages(
            uefi::boot::AllocateType::AnyPages,
            uefi::boot::MemoryType::RUNTIME_SERVICES_DATA,
            pages,
        ) {
            let raw = p.as_ptr() as u64;
            let high_base = (raw + (npt::ONE_GIB - 1)) & !(npt::ONE_GIB - 1);
            match npt::map_translated_at(&npt_root, guest_mem::HIGH_BASE_GPA, high_base, gib as usize) {
                Ok(_) => {
                    let high_size = gib * npt::ONE_GIB;
                    guest_mem::set_layout(host_ram_base, low_size, high_base, high_size);
                    high_gib = gib;
                    sprintln!(
                        "[ovmf-guest] high RAM {} GiB @ host 0x{:016X} -> guest [0x100000000,0x{:X}); total guest = {} GiB",
                        gib, high_base, guest_mem::HIGH_BASE_GPA + high_size, (low_size + high_size) / npt::ONE_GIB
                    );
                }
                Err(e) => sprintln!("[ovmf-guest] high RAM NPT map failed ({} GiB): {:?}", gib, e),
            }
            break;
        }
    }
    if high_gib == 0 {
        sprintln!("[ovmf-guest] high RAM unavailable; guest = {} GiB low only", low_size / npt::ONE_GIB);
    }
    // EXPERIMENT: OVMF (no CMOS/fw_cfg read) places its permanent PEI
    // memory near ~4 GiB and writes RAM at 0xFCFDF000. Back the region
    // just below the flash [0xFC000000, 0xFFC00000) (60 MiB) with host RAM
    // so we can observe whether OVMF then proceeds (= it just needs RAM
    // there) or faults elsewhere (= different memory model).
    const HI_RAM_BASE: u64 = 0xF000_0000;
    const HI_RAM_SIZE: u64 = OVMF_WINDOW_BASE - HI_RAM_BASE; // 0xFC00000 = 252 MiB
    let hi_pages = (HI_RAM_SIZE / 4096) as usize;
    match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::RUNTIME_SERVICES_DATA,
        hi_pages,
    ) {
        Ok(p) => {
            let hi = p.as_ptr() as u64;
            unsafe { core::ptr::write_bytes(hi as *mut u8, 0, HI_RAM_SIZE as usize); }
            // The IOAPIC/HPET/LAPIC MMIO block [0xFEC00000,0xFEF00000)
            // sits inside this window. It must stay *unmapped* so guest
            // accesses fault to NPF and route to the device emulators —
            // backing it with plain RAM (as a contiguous map would)
            // silently swallows the timer programming and strands the
            // firmware waiting on a tick that never fires.
            const MMIO_HOLE_BASE: u64 = 0xFEC0_0000;
            const MMIO_HOLE_SIZE: u64 = 0x0030_0000; // IOAPIC + HPET + LAPIC
            let lo_len = MMIO_HOLE_BASE - HI_RAM_BASE;
            let hi2_base = MMIO_HOLE_BASE + MMIO_HOLE_SIZE;
            let hi2_len = OVMF_WINDOW_BASE - hi2_base;
            let r1 = npt::map_range(&npt_root, HI_RAM_BASE, hi, lo_len);
            let r2 = npt::map_range(&npt_root, hi2_base, hi + (hi2_base - HI_RAM_BASE), hi2_len);
            match (r1, r2) {
                (Ok(_), Ok(_)) => sprintln!(
                    "[ovmf-guest] hi-RAM [0x{:08X},0x{:08X}) -> host 0x{:016X} (MMIO hole [0x{:08X},0x{:08X}) trapped)",
                    HI_RAM_BASE, OVMF_WINDOW_BASE, hi, MMIO_HOLE_BASE, hi2_base
                ),
                (a, b) => sprintln!("[ovmf-guest] hi-RAM map failed: lo={:?} hi={:?}", a, b),
            }
            // Carve the HPET page (0xFED00000) out of the trapped MMIO hole as a
            // WRITABLE shadow: the guest's per-tick HalpHpetArmTimer re-arms then
            // hit RAM instead of faulting (~7 NPF/arm at ~155us each under nested
            // SVM = boot-time storm). veneer reconciles the counter/comparator in
            // hpet::shadow_tick (every #VMEXIT). IOAPIC (0xFEC00000) and LAPIC
            // (0xFEE00000) stay trapped — only this one page becomes RAM-backed.
            match npt::map_backing_page(&npt_root, devices::irq::hpet::HPET_BASE) {
                Ok(page) => {
                    devices::irq::hpet::set_backing(page);
                    sprintln!("[ovmf-guest] HPET MMIO writable-shadow GPA 0x{:08X} -> HPA 0x{:016X}",
                        devices::irq::hpet::HPET_BASE, page);
                }
                Err(e) => sprintln!("[ovmf-guest] HPET backing map failed: {:?} (stays trapped)", e),
            }
        }
        Err(e) => sprintln!("[ovmf-guest] hi-RAM alloc failed: {:?}", e.status()),
    }
    // Display bring-up: capture the host firmware's GOP framebuffer (the real
    // VMware screen) and NPT-map our std-vga framebuffer onto a host buffer
    // that intercept/vga blits to the host GOP each frame. Boot services stay
    // alive on this guest path, so the GOP is reachable here and from the loop.
    {
        use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
        let opened = uefi::boot::get_handle_for_protocol::<GraphicsOutput>().and_then(|h| unsafe {
            uefi::boot::open_protocol::<GraphicsOutput>(
                uefi::boot::OpenProtocolParams { handle: h, agent: uefi::boot::image_handle(), controller: None },
                uefi::boot::OpenProtocolAttributes::GetProtocol,
            )
        });
        match opened {
            Ok(mut gop) => {
                let mi = gop.current_mode_info();
                let (w, hgt) = mi.resolution();
                let fmt = mi.pixel_format();
                let stride = mi.stride();
                let fb_base = gop.frame_buffer().as_mut_ptr() as u64;
                let linear = matches!(fmt, PixelFormat::Rgb | PixelFormat::Bgr);
                let rgb = matches!(fmt, PixelFormat::Rgb);
                sprintln!("[vga ] host GOP {}x{} stride={} fmt={:?} fb=0x{:016X} linear={}",
                    w, hgt, stride, fmt, fb_base, linear);
                if linear && fb_base != 0 {
                    // Allocate the framebuffer backing buffer. It's NPT-mapped
                    // later, when OVMF assigns BAR0 (vga::set_fb_base), to
                    // whatever guest-physical address the firmware picks.
                    let fb_pages = (devices::bus::vga::FB_SIZE / 4096) as usize;
                    match uefi::boot::allocate_pages(
                        uefi::boot::AllocateType::AnyPages,
                        uefi::boot::MemoryType::RUNTIME_SERVICES_DATA,
                        fb_pages,
                    ) {
                        Ok(p) => {
                            let buf = p.as_ptr() as u64;
                            unsafe { core::ptr::write_bytes(buf as *mut u8, 0, devices::bus::vga::FB_SIZE as usize); }
                            devices::bus::vga::set_fb_buffer(buf, npt_root.pdpt_phys);
                            devices::bus::vga::set_host_gop(fb_base, w as u32, hgt as u32, stride as u32, rgb);
                            sprintln!("[vga ] fb buffer 0x{:016X} ({} MiB), GOP mirror armed (BAR0 maps on assign)",
                                buf, devices::bus::vga::FB_SIZE / (1024 * 1024));
                        }
                        Err(e) => sprintln!("[vga ] fb buffer alloc failed: {:?}", e.status()),
                    }
                } else {
                    sprintln!("[vga ] host GOP not a linear framebuffer — display mirror disabled");
                }
            }
            Err(e) => sprintln!("[vga ] no host GraphicsOutput: {:?} — display mirror disabled", e.status()),
        }
    }

    npt::debug_walk(&npt_root, 0xFFFFFFF0);

    // 6. Prime VMCB for the reset vector.
    let vmcb_ptr = vmcb_phys as *mut vmcb::Vmcb;
    unsafe {
        vmcb::init_for_cpuid_intercept(vmcb_ptr, msrpm_phys, iopm_phys);
        let c = &mut (*vmcb_ptr).control;
        c.intercept_vec1 &= !(
              vmcb::intercept_vec1::PUSHF
            | vmcb::intercept_vec1::POPF
            | vmcb::intercept_vec1::IDTR_READ
            | vmcb::intercept_vec1::GDTR_READ
            | vmcb::intercept_vec1::LDTR_READ
            | vmcb::intercept_vec1::TR_READ
        );
        // RDTSC starts INTERCEPTED (filtered) so the guest never sees VMware's
        // one-time host-TSC step. intercept/mod.rs flips it to NATIVE (drops
        // the intercept) the moment clock::now() has absorbed that step — so
        // cdboot/winload's RDTSC delay loops run native (fast) and step-free.
        // (A++ hybrid: VMCB.tsc_offset, set below + retuned each exit, carries
        // the smooth clock into the native phase.)
        // Intercept physical INTR so the host preemption tick (host_tick) forces
        // a periodic #VMEXIT even while the guest runs exit-free under native
        // RDTSC — otherwise an exit-free busy-wait starves interrupt injection
        // and deadlocks. vmrun opens an interrupt window each exit to drain it.
        c.intercept_vec1 |= vmcb::intercept_vec1::INTR;
        c.intercept_cr_read = 0;
        c.intercept_cr_write = 0;
        c.intercept_dr_read = 0;
        c.intercept_dr_write = 0;
        // A guest OS owns its own IDT and handles every CPU exception
        // itself — #PF (demand paging), #BP/#UD (jump_label / alternatives
        // patching), #GP, #DB, etc. Intercepting any of them breaks the
        // kernel. Pass them all through; veneer still sees NPF (memory) and
        // SHUTDOWN (triple fault) via separate exits.
        c.intercept_exceptions = 0;
        c.guest_asid = 1;
        let now = core::arch::x86_64::_rdtsc();
        let offset = 0u64.wrapping_sub(now);
        c.tsc_offset = offset;
        devices::kvmclock::set_tsc_offset(offset);
        vmcb::init_guest(vmcb_ptr, vmcb::GuestMode::ResetVector);
        vmcb::enable_npt(vmcb_ptr, npt_root.pml4_phys);
    }
    sprintln!("[ovmf-guest] VMCB primed at reset vector (RIP=0xFFFFFFF0); entering VMRUN");

    // Verification for the independent-periodic-VMEXIT work (host LAPIC timer +
    // INTR intercept): dump the host APIC mode / IDT / timer state so the
    // forced-tick mechanism is built from measured facts, not assumptions.
    dump_host_apic_state();

    // Bring up the COM2 <-> WinDbg kernel-debug bridge (no-op if no physical
    // COM2 / VMware serial1 pipe is attached). Lets a host WinDbg attach to the
    // guest's KD transport so an early-boot bugcheck/break is fully visible.
    crate::diag::serial_kd::host_init();

    // Arm the host preemption tick: a host LAPIC timer + INTR intercept forces
    // a periodic #VMEXIT even when the guest runs exit-free (native RDTSC), so
    // pending guest interrupts get injected and the guest can't deadlock in an
    // exit-free busy-wait. Pairs with the interrupt window in vmrun::vmrun.
    host_tick::install_and_arm();

    // 7. VMRUN loop (shared with the Linux path).
    let mut gprs = gprs::GuestGprs::default();
    linux_vmrun_loop(vmcb_phys, host_ext_save_pa, vmcb_ptr, &mut gprs, host_ram_base);
}

/// Read-only dump of host interrupt/APIC state, to design the independent
/// periodic VMEXIT (preemption tick). Records: host IDTR (can we install/hook
/// an ISR), IA32_APIC_BASE (xAPIC MMIO vs x2APIC MSR — picks the timer-program
/// and EOI path), the LAPIC timer LVT/counters UEFI left, TSC-deadline support,
/// and the calibrated host TSC frequency (for the tick period).
fn dump_host_apic_state() {
    let mut idtr = [0u8; 10];
    unsafe {
        core::arch::asm!("sidt [{}]", in(reg) idtr.as_mut_ptr(), options(nostack, preserves_flags));
    }
    let idt_limit = u16::from_le_bytes([idtr[0], idtr[1]]);
    let idt_base = u64::from_le_bytes([
        idtr[2], idtr[3], idtr[4], idtr[5], idtr[6], idtr[7], idtr[8], idtr[9],
    ]);
    sprintln!(
        "[hostapic] IDTR base=0x{:X} limit=0x{:X} (~{} vectors)",
        idt_base, idt_limit, (idt_limit as u32 + 1) / 16
    );

    let apic_base = unsafe { arch::rdmsr(0x1B) };
    let x2 = apic_base & (1 << 10) != 0;
    let glob = apic_base & (1 << 11) != 0;
    let mmio = apic_base & 0xF_FFFF_F000;
    sprintln!(
        "[hostapic] IA32_APIC_BASE=0x{:X} mmio=0x{:X} global_en={} x2apic={}",
        apic_base, mmio, glob as u8, x2 as u8
    );

    let c1 = arch::cpuid(1);
    sprintln!(
        "[hostapic] CPUID.1 ECX=0x{:X} x2apic_sup={} tsc_deadline_sup={}",
        c1.ecx, (c1.ecx >> 21) & 1, (c1.ecx >> 24) & 1
    );

    if x2 {
        unsafe {
            sprintln!(
                "[hostapic] x2APIC ID=0x{:X} VER=0x{:X} SVR=0x{:X} LVT_TMR=0x{:X} ICR=0x{:X} CCR=0x{:X} DCR=0x{:X}",
                arch::rdmsr(0x802), arch::rdmsr(0x803), arch::rdmsr(0x80F),
                arch::rdmsr(0x832), arch::rdmsr(0x838), arch::rdmsr(0x839), arch::rdmsr(0x83E)
            );
        }
    } else {
        let rd = |off: u32| unsafe { core::ptr::read_volatile((mmio + off as u64) as *const u32) };
        sprintln!(
            "[hostapic] xAPIC ID=0x{:X} VER=0x{:X} SVR=0x{:X} LVT_TMR=0x{:X} ICR=0x{:X} CCR=0x{:X} DCR=0x{:X}",
            rd(0x20), rd(0x30), rd(0xF0), rd(0x320), rd(0x380), rd(0x390), rd(0x3E0)
        );
    }
    sprintln!("[hostapic] host_tsc_freq={} Hz", crate::infra::clock::tsc_freq::host_tsc_freq());
}


/// VMRUN loop for the Linux nested guest. Kernel boot generates millions
/// of #VMEXITs across all our intercept paths. We cap iterations at 5M
/// as a safety net; anything past that and we've almost certainly hit
/// an emulator gap that's livelocking on a poll.
fn linux_vmrun_loop(vmcb_phys: u64, host_ext_save_pa: u64, vmcb_ptr: *mut vmcb::Vmcb, gprs: &mut gprs::GuestGprs, guest_ram_host_base: u64) {
    // 500K cap: reaches kernel panic + a bit of emergency_restart
    // spin, then returns so the host-side memory dump can run.
    // 50 M iterations — the 11 pr_info() patches in vmlinux.elf each
    // route through serial sprintln, which dominates per-VMEXIT cost
    // and slows guest CPU time to a crawl (boot reaches PF_INET in
    // 5 M iter but timestamp stays at 0.299s). Until we swap to the
    // stripped vmlinux, the budget needs the slack.
    // Effectively unbounded: at a Windows KD break the guest busy-polls the
    // debug COM port forever (until WinDbg says "go"), so a low cap would halt
    // the guest mid-debug-session and freeze the KD link (observed: 50 M ≈ 2
    // min then halt -> WinDbg BUSY). Keep a giant runaway-backstop instead.
    const MAX_ITERS: u64 = 10_000_000_000_000;
    const REPORT_EVERY: u64 = 250_000;
    /// Print every #VMEXIT for the first VERBOSE_ITERS iterations. Kept
    /// tight so kernel printk forwarded through intercept/io.rs isn't
    /// drowned in our own boot-time trace.
    const VERBOSE_ITERS: u64 = 32;
    // Steady-state diagnosis: the early 32-exit window is long gone by the
    // time a livelock sets in, and per-exit logging is otherwise silenced.
    // Re-open a short verbose window deep into the run so a stuck loop's
    // real exit code, faulting GPA, and instruction bytes are captured.
    const STUCK_TRACE_START: u64 = 1_000_000;
    const STUCK_TRACE_LEN: u64 = 0; // quiet: per-exit verbose window off (serial dominates boot cost)
    let mut iters: u64 = 0;
    // Per-report exit-code histogram + wall-rate, for performance profiling.
    let (mut h_cpuid, mut h_msr, mut h_ioio, mut h_pmtmr, mut h_npf, mut h_hlt, mut h_other) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut h_rdtsc = 0u64;
    let (mut h_pause, mut h_intr) = (0u64, 0u64);
    let mut last_report_tsc = crate::infra::clock::now();
    // Track the heartbeat RIP across reports so a stall (RIP frozen in a small
    // region) is visible and we can dump the code there once.
    let mut last_hb_rip: u64 = 0;
    let mut hb_code_dumped: bool = false;
    // Stuck-RIP detector: when the guest spins on one RIP (e.g. CpuDeadLoop
    // after a firmware exception), dump page-table walk + fault code once.
    let mut last_rip: u64 = 0;
    let mut same_rip: u32 = 0;
    let mut last_dumped_rip: u64 = u64::MAX;
    let mut dump_count: u32 = 0;
    // xHCI USBLEGSUP OS-Owned handoff probe: the guest writes the OS-Owned
    // semaphore then (observed) drops into an exit-free spin we can't see.
    // Capture guest code + caller chain at that exact resume point, and open
    // a short verbose VMEXIT window after, so the stall's nature is on record.
    let mut handoff_dumps: u32 = 0;
    let mut handoff_trace_until: u64 = 0;
    loop {
        iters += 1;
        if iters >= MAX_ITERS {
            sprintln!("[linux-guest] iteration cap reached ({}); halting", MAX_ITERS);
            return;
        }
        if iters.is_multiple_of(REPORT_EVERY) {
            let rip = unsafe { (*vmcb_ptr).state.rip };
            let now = crate::infra::clock::now();
            let ms = now.wrapping_sub(last_report_tsc) / (tsc_freq::host_tsc_freq() / 1000).max(1);
            let rate = if ms > 0 { REPORT_EVERY * 1000 / ms } else { 0 };
            sprintln!("[linux-guest] still running: iter={} RIP=0x{:016X} vclk=0x{:X}", iters, rip, now);
            sprintln!(
                "[perf] {} exits in {} ms ({}/s) cpuid={} msr={} ioio={} pmtmr={} npf={} hlt={} rdtsc={} pause={} intr={} other={}",
                REPORT_EVERY, ms, rate, h_cpuid, h_msr, h_ioio, h_pmtmr, h_npf, h_hlt, h_rdtsc, h_pause, h_intr, h_other,
            );
            h_cpuid = 0; h_msr = 0; h_ioio = 0; h_pmtmr = 0; h_npf = 0; h_hlt = 0; h_rdtsc = 0; h_pause = 0; h_intr = 0; h_other = 0;
            last_report_tsc = now;
            // When the heartbeat RIP barely moves between reports, the guest is
            // wedged in a tight region — dump the code + page walk there once so
            // the loop body / branch condition is on record.
            if guest_ram_host_base != 0 && rip < linux_loader::GUEST_RAM_BYTES {
                if rip.abs_diff(last_hb_rip) < 0x400 {
                    if !hb_code_dumped {
                        hb_code_dumped = true;
                        sprintln!("[hb-stall] RIP region stable near 0x{:X}", rip);
                        dump_code_window(guest_ram_host_base, rip, "hb-rip");
                        let rsp = unsafe { (*vmcb_ptr).state.rsp };
                        dump_guest_code(guest_ram_host_base, rip, rsp);
                        let cr3 = unsafe { (*vmcb_ptr).state.cr3 };
                        unsafe { dump_pagewalk(guest_ram_host_base, cr3, rip); }
                    }
                } else {
                    hb_code_dumped = false;
                }
            }
            last_hb_rip = rip;
        }

        // Host-keyboard bridge: forward UEFI console keystrokes into the
        // guest's emulated 8042 so boot menus / the OS installer receive
        // input. This guest path never calls ExitBootServices, so ConIn is
        // readable between VMEXITs. Polled sparsely — a UEFI key read costs
        // far more than a single VMEXIT.
        // Host I/O bridges (keyboard in, framebuffer out). Both reach the
        // host UEFI services that stay alive on this guest path. Polled
        // sparsely — far costlier than a VMEXIT. vga::blit self-throttles to
        // ~30 fps internally, so calling it here just paces the cap.
        // Host-keyboard bridge polled often so interactive UIs (UEFI Boot
        // Manager menu, OS installer) feel responsive. At an idle menu VMEXITs
        // are sparse (~2 kHz), so the old 16384-exit gate meant ~8 s of input
        // latency — keys "didn't work". 0x3FF (~every 1024 exits) keeps it
        // snappy without flooding UEFI stdin reads during active boot.
        if iters & 0x3FF == 0 {
            devices::i8042::poll_host_input();
        }
        // Pump the COM2 <-> WinDbg KD bridge often so the debugger handshake /
        // break-in stays responsive. Cheap when idle (a couple of port reads).
        if iters & 0xFF == 0 {
            crate::diag::serial_kd::bridge();
        }
        // Finer cadence than host-input polling: once RDTSC is native, VMEXITs
        // (and thus iterations) are sparse (~1 kHz), so a 0x3FF gate would only
        // call this ~1-2x/s — too coarse to land an Enter inside cdboot's ~5 s
        // countdown. The tick self-paces by the virtual clock, so calling it
        // more often is free.
        if iters & 0xFF == 0 {
            devices::i8042::auto_boot_key_tick();
        }
        // Framebuffer blit is heavier; keep it at the coarse cadence.
        if iters & 0x3FFF == 0 {
            devices::bus::vga::blit();
        }

        let info = unsafe { vmrun::vmrun(vmcb_phys, host_ext_save_pa, gprs) };

        match info.exit_code {
            0x72 => h_cpuid += 1,
            0x7C => h_msr += 1,
            0x7B => {
                if ((info.exit_info_1 >> 16) & 0xFFFF) == 0x608 { h_pmtmr += 1 } else { h_ioio += 1 }
            }
            0x400 => h_npf += 1,
            0x78 => h_hlt += 1,
            0x6E | 0x87 => h_rdtsc += 1,
            0x77 => h_pause += 1,
            0x60 => h_intr += 1,
            _ => h_other += 1,
        }

        if dump_count < 6 && guest_ram_host_base != 0 {
            if info.guest_rip == last_rip {
                same_rip += 1;
            } else {
                same_rip = 0;
                last_rip = info.guest_rip;
            }
            if same_rip == 2000 && info.guest_rip != last_dumped_rip {
                last_dumped_rip = info.guest_rip;
                dump_count += 1;
                let (cr3, efer, cr0, cr4) = unsafe {
                    let s = &(*vmcb_ptr).state;
                    (s.cr3, s.efer, s.cr0, s.cr4)
                };
                sprintln!("[pw] STUCK#{} RIP=0x{:X} iter={} EFER=0x{:X}(NXE={}) CR0=0x{:X} CR3=0x{:X} CR4=0x{:X}",
                    dump_count, info.guest_rip, iters, efer, (efer >> 11) & 1, cr0, cr3, cr4);
                if info.guest_rip < linux_loader::GUEST_RAM_BYTES {
                    // Code at the stuck RIP + the caller chain off the stack:
                    // the spinning RIP is usually a frequently-called helper,
                    // so the real outer loop is whoever called it (return
                    // addresses on the stack point at the back-edge).
                    let rsp = unsafe { (*vmcb_ptr).state.rsp };
                    dump_guest_code(guest_ram_host_base, info.guest_rip, rsp);
                    unsafe { dump_pagewalk(guest_ram_host_base, cr3, info.guest_rip); }
                } else if guest_ram_host_base != 0 {
                    // High canonical VA = kernel space (ntoskrnl). The identity
                    // dump can't reach it; walk the guest CR3 to the physical
                    // frame and dump the code + stack-return chain there so a
                    // kernel-level spin is finally visible.
                    let rsp = unsafe { (*vmcb_ptr).state.rsp };
                    unsafe { dump_kernel_stuck(guest_ram_host_base, cr3, info.guest_rip, rsp); }
                }
            }
        }

        let trace_this = iters <= VERBOSE_ITERS
            || (iters >= STUCK_TRACE_START && iters < STUCK_TRACE_START + STUCK_TRACE_LEN)
            || iters < handoff_trace_until;
        if trace_this {
            let name = vmrun::exit_code_name(info.exit_code).unwrap_or("?");
            let rax = unsafe { (*vmcb_ptr).state.rax };
            let ilen = unsafe { (*vmcb_ptr).control.guest_inst_len } as usize;
            let ibytes = unsafe { (*vmcb_ptr).control.guest_inst_bytes };
            let shown = &ibytes[..ilen.min(ibytes.len())];
            sprintln!(
                "[g#{:>4}] exit=0x{:X} ({}) info1=0x{:X} info2=0x{:X} RIP=0x{:X} ilen={} bytes={:02X?} RAX=0x{:X} RCX=0x{:X} RDX=0x{:X}",
                iters, info.exit_code, name, info.exit_info_1, info.exit_info_2, info.guest_rip,
                ilen, shown, rax, gprs.rcx, gprs.rdx,
            );
        }
        if iters == STUCK_TRACE_START && guest_ram_host_base != 0 {
            if info.guest_rip < linux_loader::GUEST_RAM_BYTES {
                let rsp = unsafe { (*vmcb_ptr).state.rsp };
                dump_guest_code(guest_ram_host_base, info.guest_rip, rsp);
            }
            let (cr3, efer, cr0, cr4) = unsafe {
                let s = &(*vmcb_ptr).state;
                (s.cr3, s.efer, s.cr0, s.cr4)
            };
            sprintln!("[pw] EFER=0x{:X}(NXE={}) CR0=0x{:X} CR3=0x{:X} CR4=0x{:X}",
                efer, (efer >> 11) & 1, cr0, cr3, cr4);
            dump_code_window(guest_ram_host_base, 0x3EF1102E, "fault-rip");
            unsafe { dump_pagewalk(guest_ram_host_base, cr3, 0x3EF1102E); }
        }

        let action = unsafe { vmexit::dispatch(vmcb_ptr, gprs) };

        // The handoff write was just serviced inside dispatch(); guest RIP now
        // points at the instruction the consumer resumes on. Dump it before the
        // next VMRUN, which may never return if it spins exit-free.
        if devices::bus::xhci::take_handoff_dump() && handoff_dumps < 4 && guest_ram_host_base != 0 {
            handoff_dumps += 1;
            let (rip, rflags, rsp) = unsafe {
                let s = &(*vmcb_ptr).state;
                (s.rip, s.rflags, s.rsp)
            };
            sprintln!(
                "[xhci-handoff] #{} resume RIP=0x{:X} RFLAGS=0x{:X} (IF={}) RSP=0x{:X} iter={}",
                handoff_dumps, rip, rflags, (rflags >> 9) & 1, rsp, iters,
            );
            if rip < linux_loader::GUEST_RAM_BYTES {
                dump_guest_code(guest_ram_host_base, rip, rsp);
            }
            // Open a verbose per-exit window after the handoff so the post-
            // ownership init exits (ring setup, doorbell, the final poll) are on
            // record. The guest drops into an exit-free spin here, so iters
            // barely advances — a generous window costs little but captures
            // whatever MMIO exits do occur before the stall.
            handoff_trace_until = iters + 8000;
        }

        // Deep-loop probe: the guest just read xHCI USBLEGSUP, then branches on
        // it. Dump the resume RIP (the compare/back-edge) + caller chain so the
        // winload<->firmware retry condition is captured.
        if devices::bus::xhci::take_read_probe_dump() && guest_ram_host_base != 0 {
            let (rip, rflags, rsp) = unsafe {
                let s = &(*vmcb_ptr).state;
                (s.rip, s.rflags, s.rsp)
            };
            sprintln!(
                "[xhci-poll] after USBLEGSUP read: resume RIP=0x{:X} RFLAGS=0x{:X} (IF={}) iter={}",
                rip, rflags, (rflags >> 9) & 1, iters,
            );
            if rip < linux_loader::GUEST_RAM_BYTES {
                dump_guest_code(guest_ram_host_base, rip, rsp);
            }
        }

        match action {
            vmexit::Action::Resume => continue,
            vmexit::Action::Halt => {
                sprintln!(
                    "[linux-guest] guest HLT at iter {} RIP=0x{:016X} (kernel reached HLT -- boot complete or paused)",
                    iters, info.guest_rip,
                );
                if guest_ram_host_base != 0 && info.guest_rip < linux_loader::GUEST_RAM_BYTES {
                    let rsp = unsafe { (*vmcb_ptr).state.rsp };
                    dump_guest_code(guest_ram_host_base, info.guest_rip, rsp);
                }
                return;
            }
            vmexit::Action::Abort => {
                let name = vmrun::exit_code_name(info.exit_code).unwrap_or("(unknown)");
                sprintln!(
                    "[linux-guest] Abort iter={} exit=0x{:X} ({}) info1=0x{:X} info2=0x{:X} RIP=0x{:016X}",
                    iters, info.exit_code, name, info.exit_info_1, info.exit_info_2, info.guest_rip,
                );
                return;
            }
        }
    }
}

/// One-shot dump of guest code around a stuck RIP, plus the caller chain
/// from the stack. Guest low RAM [0,1GiB) identity-maps to `host_base`,
/// and DXE runs identity-paged, so guest virtual == host offset. The
/// faulting RIP sits inside a tiny `IoRead32`-style leaf; the real poll
/// loop is the caller, recovered from [rsp].
fn dump_guest_code(host_base: u64, guest_rip: u64, guest_rsp: u64) {
    dump_code_window(host_base, guest_rip, "rip");
    if guest_rsp >= linux_loader::GUEST_RAM_BYTES {
        return;
    }
    let mut stk = [0u64; 16];
    unsafe { core::ptr::copy_nonoverlapping((host_base + guest_rsp) as *const u64, stk.as_mut_ptr(), 16); }
    sprintln!("[stuck] rsp=0x{:X} stack={:X?}", guest_rsp, stk);
    // Treat any stack qword that lands in the guest RAM window (above 1 MiB)
    // as a possible return address and dump it. Covers both firmware/winload
    // up high (~0x7Fxxxxxx with 2 GiB RAM) and winload's own low-memory code
    // (~0x02xxxxxx) once it switches to its own identity-mapped page tables.
    for v in stk {
        if (0x10_0000..linux_loader::GUEST_RAM_BYTES).contains(&v) {
            dump_code_window(host_base, v, "caller");
        }
    }
}

fn dump_code_window(host_base: u64, addr: u64, tag: &str) {
    let start = addr.saturating_sub(16);
    let mut bytes = [0u8; 48];
    unsafe { core::ptr::copy_nonoverlapping((host_base + start) as *const u8, bytes.as_mut_ptr(), 48); }
    sprintln!("[stuck] {} @ 0x{:X} (start 0x{:X}): {:02X?}", tag, addr, start, bytes);
}

/// Walk the guest's 4-level page table (rooted at `cr3`) for `va`, reading
/// each level out of guest low RAM (identity-mapped to `host_base`). Logs
/// every entry so a wrong mapping / reserved NX bit is visible.
unsafe fn dump_pagewalk(host_base: u64, cr3: u64, va: u64) {
    let rd = |phys: u64| -> u64 {
        if phys >= linux_loader::GUEST_RAM_BYTES { return 0; }
        unsafe { core::ptr::read_unaligned((host_base + phys) as *const u64) }
    };
    let names = ["PML4", "PDPT", "PD", "PT"];
    let shifts = [39u32, 30, 21, 12];
    let mut table = cr3 & 0x000F_FFFF_FFFF_F000;
    sprintln!("[pw] walk VA 0x{:X} cr3=0x{:X}", va, cr3);
    for lvl in 0..4 {
        if table >= linux_loader::GUEST_RAM_BYTES {
            sprintln!("[pw]   {} table phys 0x{:X} OUTSIDE guest RAM", names[lvl], table);
            return;
        }
        let idx = ((va >> shifts[lvl]) & 0x1FF) as u64;
        let e = rd(table + idx * 8);
        sprintln!("[pw]   {}[{}] @0x{:X} = 0x{:016X} (P={} RW={} US={} NX={})",
            names[lvl], idx, table + idx * 8, e, e & 1, (e >> 1) & 1, (e >> 2) & 1, e >> 63);
        if e & 1 == 0 {
            sprintln!("[pw]   -> NOT PRESENT");
            return;
        }
        if lvl < 3 && (e >> 7) & 1 != 0 {
            sprintln!("[pw]   -> large page, stops here");
            return;
        }
        table = e & 0x000F_FFFF_FFFF_F000;
    }
    sprintln!("[pw]   -> final phys 0x{:X} (VA->PA, identity expected)", table | (va & 0xFFF));
}

/// Walk the guest 4-level page table (rooted at `cr3`) and return the guest-
/// physical address `va` maps to, or None if not present / mapped outside the
/// 2 GiB guest RAM window we can read. Handles 1 GiB / 2 MiB large pages.
unsafe fn guest_va_to_phys(_host_base: u64, cr3: u64, va: u64) -> Option<u64> {
    // Read a page-table entry via the proper low/high host mapping — Windows
    // can place tables (and the kernel image) in high RAM above 4 GiB, which is
    // NOT at host_base+phys (that read crashed veneer). guest_mem::to_host knows
    // both regions.
    let rd = |phys: u64| -> Option<u64> {
        let h = crate::guest::boot::guest_mem::to_host(phys)?;
        Some(unsafe { core::ptr::read_unaligned(h as *const u64) })
    };
    let shifts = [39u32, 30, 21, 12];
    let mut table = cr3 & 0x000F_FFFF_FFFF_F000;
    for lvl in 0..4 {
        let e = rd(table + ((va >> shifts[lvl]) & 0x1FF) * 8)?;
        if e & 1 == 0 {
            return None;
        }
        if lvl < 3 && (e >> 7) & 1 != 0 {
            let page_mask = (1u64 << shifts[lvl]) - 1;
            return Some((e & 0x000F_FFFF_FFFF_F000 & !page_mask) | (va & page_mask));
        }
        table = e & 0x000F_FFFF_FFFF_F000;
    }
    Some(table | (va & 0xFFF))
}

/// Dump a stuck KERNEL (high-VA) spin: the page walk, the resolved physical,
/// the code window at the stuck RIP, and the return-address chain off the
/// stack (each kernel-VA qword translated and dumped) — the symbol-less
/// equivalent of a call stack, so we can see what the kernel is waiting on.
unsafe fn dump_kernel_stuck(host_base: u64, cr3: u64, rip: u64, rsp: u64) {
    unsafe { dump_pagewalk(host_base, cr3, rip) };
    // Read a 48-byte code window at a guest-PHYSICAL address through the proper
    // low/high host mapping (guest_mem::to_host) — never host_base+phys, which
    // is wrong for high RAM (>4 GiB) and crashed veneer with an OOB host read.
    let dump_at = |gpa: u64, tag: &str| match crate::guest::boot::guest_mem::to_host(gpa.saturating_sub(16)) {
        Some(h) => {
            let mut bytes = [0u8; 48];
            unsafe { core::ptr::copy_nonoverlapping(h as *const u8, bytes.as_mut_ptr(), 48) };
            sprintln!("[stuck] {} gpa=0x{:X}: {:02X?}", tag, gpa, bytes);
        }
        None => sprintln!("[stuck] {} gpa=0x{:X} not in guest RAM", tag, gpa),
    };

    let Some(rip_phys) = (unsafe { guest_va_to_phys(host_base, cr3, rip) }) else {
        sprintln!("[stuck] kernel RIP 0x{:X} did not translate", rip);
        return;
    };
    sprintln!("[stuck] kernel RIP 0x{:X} -> phys 0x{:X}", rip, rip_phys);
    dump_at(rip_phys, "kern-rip");

    // Stack: translate RSP, read 16 qwords, dump code at each plausible kernel
    // return address (canonical high-half). Reveals the caller / wait site.
    let Some(rsp_phys) = (unsafe { guest_va_to_phys(host_base, cr3, rsp) }) else {
        sprintln!("[stuck] kernel RSP 0x{:X} did not translate", rsp);
        return;
    };
    let Some(rsp_h) = crate::guest::boot::guest_mem::to_host(rsp_phys) else {
        sprintln!("[stuck] kern rsp phys 0x{:X} not in guest RAM", rsp_phys);
        return;
    };
    let mut stk = [0u64; 16];
    unsafe { core::ptr::copy_nonoverlapping(rsp_h as *const u64, stk.as_mut_ptr(), 16) };
    sprintln!("[stuck] kern rsp=0x{:X} (phys 0x{:X}) stack={:X?}", rsp, rsp_phys, stk);
    for v in stk {
        if v >= 0xFFFF_8000_0000_0000 {
            if let Some(p) = unsafe { guest_va_to_phys(host_base, cr3, v) } {
                dump_at(p, "kern-caller");
            }
        }
    }
}

/// every intercept path's footprint.
fn bsp_vmrun_loop(vmcb_phys: u64, host_ext_save_pa: u64, vmcb_ptr: *mut vmcb::Vmcb) {
    let mut gprs = gprs::GuestGprs::default();
    let max_iters: u32 = 32;
    for i in 0..max_iters {
        sprintln!("[vmrun] iteration #{}", i);
        let info = unsafe { vmrun::vmrun(vmcb_phys, host_ext_save_pa, &mut gprs) };
        report_vmexit(&info);

        let action = unsafe { vmexit::dispatch(vmcb_ptr, &mut gprs) };
        match action {
            vmexit::Action::Resume => {
                let rip_now = unsafe { (*vmcb_ptr).state.rip };
                let rax_now = unsafe { (*vmcb_ptr).state.rax };
                sprintln!(
                    "[vmm ] resumed — guest regs after handler: RAX=0x{:08X} RBX=0x{:08X} RCX=0x{:08X} RDX=0x{:08X}  RIP→0x{:016X}",
                    rax_now as u32, gprs.rbx as u32, gprs.rcx as u32, gprs.rdx as u32, rip_now,
                );
            }
            vmexit::Action::Halt => {
                let final_rax = unsafe { (*vmcb_ptr).state.rax };
                sprintln!("[vmm ] guest HLT — last instruction was vmmcall(0)");
                sprintln!("[vmm ]   final RAX (should be vmmcall sig): 0x{:016X}", final_rax);
                sprintln!("[vmm ]   final RBX                         : 0x{:016X}", gprs.rbx);
                sprintln!("[vmm ]   final RCX                         : 0x{:016X}", gprs.rcx);
                sprintln!("[vmm ]   final RDX                         : 0x{:016X}", gprs.rdx);
                verify(
                    "vmmcall signature",
                    final_rax,
                    profile::DEFAULT.vmmcall_signature,
                );
                return;
            }
            vmexit::Action::Abort => {
                sprintln!("[vmm ] dispatcher returned Abort — exit_code 0x{:X}", info.exit_code);
                return;
            }
        }
    }
    sprintln!("[vmm ] iteration limit ({}) reached without HLT — bailing", max_iters);
}

/// Per-AP SVM bring-up + VMRUN orchestration. BSP-side prep is:
///   1. For each AP slot, init the VMCB (guest mode + NPT) with the
///      shared blob/NCR3 — APs run silently and can't print, so we
///      *must* hand them fully-primed VMCBs.
///   2. Populate `ApVmRunSetup` with the per-AP VMCB + hsave pages.
///   3. Dispatch via UEFI MP Services; APs claim slots, do their own
///      SVM bring-up, and run VMRUN until HLT.
///   4. After all APs return, print the aggregated results.
fn run_aps(
    pool: &vcpu_pool::VcpuPool,
    bsp_ext_save_pa: u64,
    per_ap_hsave: &smp::heapless_vec::Vec<u64, 32>,
    per_ap_ext_save: &smp::heapless_vec::Vec<u64, 32>,
    blob_phys: u64,
    ncr3_phys: u64,
    msrpm_phys: u64,
    iopm_phys: u64,
) {
    let n_aps = pool.count.saturating_sub(1).min(per_ap_hsave.len()).min(per_ap_ext_save.len());
    if n_aps == 0 {
        return;
    }

    let mut setup = smp::ApVmRunSetup::empty();
    setup.n_aps = n_aps;
    for i in 0..n_aps {
        let vmcb_ptr = match pool.vmcb[i + 1] {
            Some(p) => p,
            None => {
                sprintln!("[ap-vmrun] AP slot {} has no VMCB; skipping rest", i);
                setup.n_aps = i;
                break;
            }
        };
        let vmcb_phys = vmcb_ptr as u64;
        let mode = vmcb::GuestMode::Long64 { code_lin: blob_phys };
        unsafe {
            // Control fields first: intercept_vec1/vec2 (incl. mandatory
            // VMRUN bit), IOPM/MSRPM bitmaps. Without this the VMCB has
            // intercept_vec2[VMRUN]=0 and VMRUN consistency-checks fail
            // with VMEXIT(INVALID) before the guest even starts.
            vmcb::init_for_cpuid_intercept(vmcb_ptr, msrpm_phys, iopm_phys);
            vmcb::init_guest(vmcb_ptr, mode);
            vmcb::enable_npt(vmcb_ptr, ncr3_phys);
            // Give each AP a distinct ASID. BSP keeps ASID=1; APs claim
            // 2, 3, 4, ... up to N_ASIDs (64 on this host). Without this,
            // 4 host CPUs running VMRUN with ASID=1 share NPT TLB tags.
            (*vmcb_ptr).control.guest_asid = (i as u32) + 2;
        }
        setup.vmcb_phys[i] = vmcb_phys;
        setup.hsave_pa[i] = *per_ap_hsave
            .iter()
            .nth(i)
            .expect("hsave alloc count matches n_aps");
        setup.ext_save_pa[i] = *per_ap_ext_save
            .iter()
            .nth(i)
            .expect("ext_save alloc count matches n_aps");
    }

    // BSP self-test: try running slot 1's VMCB *from BSP* before
    // dispatching to APs. If BSP succeeds on this VMCB, the per-VMCB
    // init is fine and the AP failure is environment-related. If BSP
    // also fails, our init_guest call missed something AP-relevant.
    if setup.n_aps > 0 {
        sprintln!("[bsp-test] running AP slot[0] VMCB from BSP to isolate environment vs init bug");
        let test_phys = setup.vmcb_phys[0];
        let mut tg = gprs::GuestGprs::default();
        let ti = unsafe { vmrun::vmrun(test_phys, bsp_ext_save_pa, &mut tg) };
        let name = vmrun::exit_code_name(ti.exit_code).unwrap_or("(unrecognised)");
        sprintln!(
            "[bsp-test]   exit_code=0x{:X} ({}) info1={:#X} info2={:#X} rip={:#018X}",
            ti.exit_code, name, ti.exit_info_1, ti.exit_info_2, ti.guest_rip,
        );
        // Re-init slot[0] VMCB because BSP's test left it dirty.
        let vmcb_ptr = test_phys as *mut vmcb::Vmcb;
        let mode = vmcb::GuestMode::Long64 { code_lin: blob_phys };
        unsafe {
            vmcb::init_for_cpuid_intercept(vmcb_ptr, msrpm_phys, iopm_phys);
            vmcb::init_guest(vmcb_ptr, mode);
            vmcb::enable_npt(vmcb_ptr, ncr3_phys);
            (*vmcb_ptr).control.guest_asid = 2;
        }
    }

    // DIAGNOSTIC: AP VMRUN dispatch isolated to test whether the
    // firmware's MP-services state survives ExitBootServices() after we
    // touch the APs. If chain-loaded Linux boots only when this is
    // skipped, the AP/SMP path is what's deadlocking exit_boot().
    const SKIP_AP_VMRUN: bool = true;

    if SKIP_AP_VMRUN {
        sprintln!(
            "[ap-vmrun] SKIPPED ({} AP(s) idle, no SVM bring-up) -- diagnostic",
            setup.n_aps
        );
    } else {
        sprintln!(
            "[ap-vmrun] dispatching {} AP(s): per-AP SVM bring-up + 21-path VMRUN",
            setup.n_aps
        );
        if let Err(e) = smp::run_ap_vmrun(&mut setup) {
            sprintln!("[ap-vmrun] failed: {:?}", e);
            return;
        }
        report_ap_vmrun(&setup);
    }
}

fn report_ap_vmrun(setup: &smp::ApVmRunSetup) {
    let want = profile::DEFAULT.vmmcall_signature;
    for i in 0..setup.n_aps {
        let r = &setup.results[i];
        if !r.valid {
            sprintln!("[ap-vmrun] slot#{}: no result (timeout / didn't claim)", i);
            continue;
        }
        let exit_kind = if r.aborted {
            "ABORT"
        } else if r.signature_match {
            "HLT ✓ MATCH"
        } else {
            "HLT ✗ MISMATCH"
        };
        sprintln!(
            "[ap-vmrun] APIC#{:02} iters={:>2} final_rax=0x{:016X}  ({})",
            r.apic_id, r.iter_count, r.final_rax, exit_kind
        );
        sprintln!(
            "[ap-vmrun]   EFER={:#018X} HSAVE_PA_readback={:#018X}",
            r.efer_after_svme, r.vm_hsave_pa_readback
        );
        sprintln!(
            "[ap-vmrun]   host  CR0={:#018X} CR3={:#018X} CR4={:#018X}",
            r.host_cr0, r.host_cr3, r.host_cr4
        );
        sprintln!(
            "[ap-vmrun]   guest CR0={:#018X} CR3={:#018X} CR4={:#018X}  EFER={:#018X} ASID={}",
            r.vmcb_guest_cr0, r.vmcb_guest_cr3, r.vmcb_guest_cr4,
            r.vmcb_guest_efer, r.vmcb_asid
        );
        if r.aborted || !r.signature_match {
            let name = vmrun::exit_code_name(r.last_exit_code).unwrap_or("(unrecognised)");
            sprintln!(
                "[ap-vmrun]   last exit: code=0x{:X} ({}) info1={:#X} info2={:#X} rip={:#018X}",
                r.last_exit_code, name, r.last_exit_info_1, r.last_exit_info_2, r.last_rip,
            );
        }
    }
    sprintln!("[ap-vmrun] expected signature: 0x{:016X}", want);
}

/// Drive the menu state machine until the user picks a terminal action
/// (UseActive / GenerateFresh / SwitchPolicy / WipeAndDefault / LoadToml).
/// `Advanced` re-enters the menu after the sub-screen returns.
fn run_menu_loop(config: &config::Config, cached: Option<profile::Profile>) -> profile::Profile {
    let mut cached_now = cached;
    loop {
        let choice = match cached_now.as_ref() {
            Some(p) => menu::run_cached_menu(p, config),
            None => menu::run_no_cache_menu(config),
        };
        match choice {
            menu::MenuChoice::UseActive => {
                if let Some(p) = cached_now {
                    menu::draw_transition(
                        "Using cached profile from NVRAM",
                        "Same machine identity preserved across reboots.",
                    );
                    return p;
                }
                let p = profile_gen::build_profile(config.policy.default);
                let _ = nvram_io::save_profile(&p);
                menu::draw_transition(
                    "Generated default profile",
                    "No cache existed — created fresh from config.policy.default.",
                );
                return p;
            }
            menu::MenuChoice::GenerateFresh(policy) | menu::MenuChoice::SwitchPolicy(policy) => {
                let p = profile_gen::build_profile(policy);
                match nvram_io::save_profile(&p) {
                    Ok(()) => sprintln!("[prof] generated + cached: policy={:?}", policy),
                    Err(e) => sprintln!("[prof] generated, NVRAM save failed: {:?}", e),
                }
                menu::draw_transition(
                    "Profile regenerated and cached to NVRAM",
                    "New random identity fields under the selected policy.",
                );
                return p;
            }
            menu::MenuChoice::WipeAndDefault => {
                let _ = nvram_io::delete_profile();
                let p = profile_gen::build_profile(config.policy.default);
                let _ = nvram_io::save_profile(&p);
                cached_now = Some(p);
                // Loop back to cached menu so the user sees the new cache.
            }
            menu::MenuChoice::Advanced => {
                let mut cfg = *config;
                menu::run_advanced(&mut cfg);
                // Loop back — Config editor lands in batch 1c.
            }
            menu::MenuChoice::LoadToml => {
                // Generate the policy template + RDRAND identity, then
                // overlay any fields the operator set in profile.toml.
                let mut p = profile_gen::build_profile(config.policy.default);
                let mut tbuf = [0u8; 4096];
                match esp_io::load_into(esp_io::PROFILE_TOML_PATH, &mut tbuf) {
                    Ok(n) => {
                        let mut warns = 0u32;
                        let applied = toml::apply_profile(&tbuf[..n], &mut p, &mut warns);
                        sprintln!(
                            "[prof] profile.toml: {} fields applied, {} warnings",
                            applied, warns
                        );
                    }
                    Err(e) => {
                        sprintln!("[prof] profile.toml load failed: {:?}", e);
                    }
                }
                match nvram_io::save_profile(&p) {
                    Ok(()) => sprintln!("[prof] generated + ESP overlay + cached"),
                    Err(e) => sprintln!("[prof] save failed: {:?}", e),
                }
                menu::draw_transition(
                    "profile.toml loaded and cached",
                    "ESP overrides applied over the policy template.",
                );
                return p;
            }
        }
    }
}
