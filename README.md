# veneer

> *veneer (n.) — a thin facing layer applied to a surface, defining what observers see.*

A minimal **Type-1 hypervisor** in Rust. It boots before the guest OS, runs the
guest (OVMF firmware → Windows / Linux), and presents a fully synthetic,
host-independent PC identity — CPU, SMBIOS, disk, NIC, TPM, ACPI — driven by a
`Profile`, with no observable footprint from inside.

It doubles as the research substrate for anti-cheat work: sitting at L1 (below
the guest OS), veneer reads, translates, and intercepts guest memory beneath
in-guest defenses (PatchGuard, HVCI) to study `vgk` / `vgc` and feed `fake_vgc`.

> This project was fully generated with AI assistance (Claude, Anthropic).

```
+--------------------------------------------------+
|  guest OS (L2)  — sees a synthetic "real PC"     |
+--------------------------------------------------+
|  veneer (L1) Type-1 hypervisor                   |
+--------------------------------------------------+
|  VMware Workstation (L0, nested) or bare-metal   |
+--------------------------------------------------+
```

## Build & run

```bash
cd crates/veneer-uefi && cargo build --release   # → target/x86_64-unknown-uefi/release/veneer-uefi.efi
python tools/make_disk.py                         # from repo root: build the bootable ESP disk
```

veneer boots as a UEFI app: firmware runs `\EFI\BOOT\BOOTX64.EFI`, veneer
enables AMD SVM and chain-loads the guest. Producing the disk, configuring the
VMware VM (the required `.vmx` settings), and the development boot loop are in
**[SETUP.md](SETUP.md)**.

## Architecture

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the full design: the SVM boot /
VMEXIT flow, NPT layout, the device-emulation set (LAPIC / IO-APIC / PIC / PIT /
HPET / RTC, PCI / NVMe / AHCI / xHCI / VGA / NIC, ACPI / SMBIOS / fw_cfg / TPM),
profile-driven identity, and the VMI + stealth-hook engine. Open work lives in
**[TODO.md](TODO.md)**.

## Project structure

A Cargo workspace of three crates, split on the `no_std` / `std` axis:

| crate | kind | role |
|---|---|---|
| `veneer-profile` | no_std lib | shared synthetic-PC schema + TOML parser |
| `veneer-uefi` | no_std bin | the hypervisor (`.efi`, loaded by firmware) |
| `host/veneer-probe` | std bin | host-side pre-flight (`inspect` / `plan` / `profile-check`) |

`veneer-uefi` is organized into role-based layers — `infra/` → `hypervisor/` →
`hardware/` → `guest/` → `introspect/` / `diag/` (a DAG). The full module map is
in ARCHITECTURE.md.

## Requirements

A UEFI host with AMD SVM + nested paging. For development it runs nested under
VMware Workstation with `vhv.enable = "TRUE"` (AMD-V/RVI exposed to the guest).

## License

MIT.
