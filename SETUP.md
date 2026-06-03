# veneer — setup (build & boot)

Building the hypervisor, producing a bootable disk, configuring a VMware
Workstation VM, and the development boot loop. veneer boots as a UEFI
application, so "running" it means handing firmware a disk whose
`\EFI\BOOT\BOOTX64.EFI` is `veneer-uefi.efi`, then letting it chain-load a guest.

## 1. Build the hypervisor

```bash
cd crates/veneer-uefi && cargo build --release
#   → target/x86_64-unknown-uefi/release/veneer-uefi.efi
```

Optional host pre-flight (a separate `std` crate) to check the real CPU before
deploying:

```bash
cd crates/host/veneer-probe && cargo build
veneer inspect          # vendor, SVM/VMX, NPT, MSRs
veneer plan             # which backend is viable + per-guest memory needs
```

## 2. Build a bootable disk

`make_disk.py` (primary) writes a UEFI-spec VMDK — protective MBR + GPT + a
FAT32 ESP with `veneer-uefi.efi` at `\EFI\BOOT\BOOTX64.EFI`:

```bash
python tools/make_disk.py
#   → target/veneer-esp.vmdk        (descriptor)
#   → target/veneer-esp-flat.vmdk   (extent)
```

- `make_iso.py` — alternative that produces a UEFI-bootable ISO (ISO 9660 +
  Joliet + Rock Ridge) for firmware/setups that prefer CD boot.
- `make_esp_via_diskpart.ps1` — builds the ESP with Windows' own formatter
  (avoids hand-rolling FAT/GPT), then copies the image into the extent.

## 3. Configure the VM

Create a VM in the Workstation wizard (any guest-OS choice), then overlay the
settings veneer needs:

```bash
python tools/patch_vmx.py "C:\path\to\my-vm\My VM.vmx"
```

It forces only the minimum and attaches `veneer-esp.vmdk` on the first writable
controller slot (nvme0:0 → sata0:0 → scsi0:0 → ide0:0):

| setting | value | why |
|---|---|---|
| `firmware` | `efi` | UEFI boot |
| `guestOS` | `windows9-64` | the only family whose VMware UEFI fallback-path scan boots our ESP |
| `uefi.secureBoot.enabled` | `FALSE` | the `.efi` is unsigned |
| `vhv.enable` | `TRUE` | expose AMD-V / RVI (nested SVM) to the guest |
| `serial0` → file | `D:\veneer-serial.log` | capture veneer's COM1 log |

Add the guest install media (e.g. a Windows ISO) as a CD-ROM on a SATA slot,
and a second writable disk as the install target.

Development-stability extras (optional, from host experience under nested virt):

| setting | value | why |
|---|---|---|
| `mks.enable3d` | `FALSE` | the 3D-render path triggered a host NVIDIA-driver `0x3B` BSOD |
| `sched.cpu.affinity` | e.g. `0,1,2,3` | pin vCPUs so a guest busy-spin can't starve the host |
| `serial1` → pipe `\\.\pipe\veneer-kd` | — | optional WinDbg KD transport on COM2 |

## 4. Boot / development loop

Start the VM from VMware, or use the one-shot dev helper:

```bash
python tools/boot_cycle.py --vm tiny11 --timeout 200
```

`boot_cycle.py` truncates the serial log, starts the VM headless, polls the log,
and prints a tail when the boot stalls or the timeout elapses. Its `--vm`
targets are hardcoded dev-machine paths — pass `--vmx <path>` to point at your
own VM.

To drop to a UEFI shell for diagnosis instead of booting veneer, build a shell
disk with `swap_efi_to_shell.ps1` (places `assets/shellx64.efi` as `BOOTX64.EFI`).

## Diagnostic Linux path (optional)

For inspecting what veneer's synthetic firmware/PCI looks like from inside a
guest, the `build_alpine_overlay.py` / `*_initramfs.py` / `*_init.py` scripts
append an auto-inspection `/init` to an Alpine initramfs that dumps firmware/PCI
state over serial. Not part of the normal Windows boot path.
