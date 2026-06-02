# veneer

> *veneer (n.) — a thin facing layer applied to a surface, defining what observers see.*

A minimal **Type-1 hypervisor** in Rust. It boots before the guest OS, runs the
guest (OVMF firmware → Windows / Linux), and presents a fully synthetic,
host-independent PC identity — CPU, SMBIOS, disk, NIC, TPM, ACPI — driven by a
`Profile`, with no observable footprint from inside.

It is also the research substrate for the anti-cheat work: sitting at L1 (below
the guest OS), veneer can read, translate, and intercept guest memory beneath
in-guest defenses (PatchGuard, HVCI) to study `vgk` / `vgc` and feed `fake_vgc`.

```
+--------------------------------------------------+
|  guest OS (L2)  — sees a synthetic "real PC"     |
+--------------------------------------------------+
|  veneer (L1) Type-1 hypervisor                   |
+--------------------------------------------------+
|  VMware Workstation (L0, nested) or bare-metal   |
+--------------------------------------------------+
```

## Structure

A Cargo workspace of three crates (split on the `no_std` / `std` axis):

| crate | kind | role |
|---|---|---|
| `veneer-profile` | no_std lib | shared synthetic-PC schema + TOML parser |
| `veneer-uefi` | no_std bin | the hypervisor (`.efi`, loaded by firmware) |
| `host/veneer-probe` | std bin | host-side pre-flight: `inspect` / `plan` / `profile-check` |

The hypervisor is organized into domain folders: `boot/ svm/ vmexit/
devices/{irq,bus,storage,tpm} acpi/ clock/ identity/ config/ debug/ introspect/
hook/`. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full map and design.

## Status (2026-06-02)

Boots OVMF firmware and runs Windows (tiny11) deep into kernel init. Working:
AMD SVM bring-up, NPT, full intercept set, multi-vCPU; emulated LAPIC / IO-APIC /
PIC / PIT / HPET / RTC, PCI / NVMe / AHCI / xHCI / VGA / NIC, ACPI / SMBIOS /
fw_cfg / TPM(CRB); profile-driven identity persisted in NVRAM; a VMI +
stealth-hook research engine; a TPM 2.0 crypto foundation.

**Blocked** on a `KxWaitForSpinLockAndAcquire` spinlock deadlock during Windows
kernel init. Outstanding work: [TODO.md](TODO.md).

Runs nested under VMware Workstation (AMD SVM, `vhv=true`) for development.

## Build

```bash
# hypervisor (.efi)
cd crates/veneer-uefi && cargo build --release
#   → target/x86_64-unknown-uefi/release/veneer-uefi.efi
python tools/make_disk.py            # from repo root: build the bootable ESP disk

# host tool
cd crates/host/veneer-probe && cargo build
veneer inspect                       # probe host CPU capability
veneer plan                          # which backend (SVM/VMX) is viable
veneer profile-check <profile.toml>  # validate a profile against the schema
```

To boot: the ESP disk built by `make_disk.py` places `veneer-uefi.efi` at
`\EFI\BOOT\BOOTX64.EFI`; firmware runs it, veneer enables SVM and launches the
guest. (`assets/shellx64.efi` can be swapped in to drop to a UEFI shell for
diagnosis.)

## License

MIT.
