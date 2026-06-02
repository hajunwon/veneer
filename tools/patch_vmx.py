"""Patch an arbitrary VMware Workstation .vmx so it boots veneer-uefi.efi.

The user is free to create the VM via the Workstation wizard with any guest
OS choice they want (Windows 10, Windows 11, a specific Insider build, etc).
This patcher then overlays the minimum settings veneer needs and leaves
everything else alone:

  - firmware           = "efi"          (required for UEFI boot)
  - guestOS            = "windows9-64"  (only OS family whose UEFI fallback
                                          path policy works with our setup;
                                          see facts/vmware_uefi_guest_quirks)
  - uefi.secureBoot.enabled = "FALSE"   (unsigned .efi)
  - vhv.enable         = "TRUE"         (expose AMD-V / VT-x to guest)
  - serial0            = D:\\veneer-serial.log  (capture COM1)

It will attach veneer-esp.vmdk on the first writable controller slot it
finds among (in order): nvme0:0, sata0:0, scsi0:0, ide0:0. Existing
disks/CD-ROMs on other slots are left alone.

Usage:
    python tools/patch_vmx.py "C:\\path\\to\\my-vm\\My VM.vmx"
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ESP_VMDK = REPO_ROOT / "target" / "veneer-esp.vmdk"
SERIAL_LOG = r"D:\veneer-serial.log"

# Only this exact guestOS string gives VMware UEFI the fallback-path scan
# behaviour we need. See facts/vmware_uefi_guest_quirks.md for the trail.
GUEST_OS = "windows9-64"

# Settings we always force, regardless of what's currently in the file.
FORCED = {
    "firmware":                  "efi",
    "guestOS":                   GUEST_OS,
    "uefi.secureBoot.enabled":   "FALSE",
    "vhv.enable":                "TRUE",
    "serial0.present":           "TRUE",
    "serial0.fileType":          "file",
    "serial0.fileName":          SERIAL_LOG,
    "serial0.tryNoRxLoss":       "TRUE",
}

# Controllers we try in this order. Each tuple is (controller-key, slot).
CONTROLLER_PREF: list[tuple[str, str]] = [
    ("nvme0",  "nvme0:0"),
    ("sata0",  "sata0:0"),
    ("scsi0",  "scsi0:0"),
    ("ide0",   "ide0:0"),
]


def parse_vmx(path: Path) -> dict[str, str]:
    """Return key->value (as string-literal, quotes stripped) for top-level
    `key = "value"` lines. Comments and blank lines are dropped."""
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([A-Za-z0-9_.:]+)\s*=\s*"(.*)"\s*$', line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def pick_slot(existing: dict[str, str]) -> tuple[str, str]:
    """Return (controller_key, disk_slot) for the first slot whose disk
    slot is empty in the existing .vmx. Falls back to nvme0:0."""
    for ctrl, slot in CONTROLLER_PREF:
        if f"{slot}.fileName" not in existing:
            return ctrl, slot
    # If every preferred controller is taken, override nvme0:0.
    return "nvme0", "nvme0:0"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    vmx = Path(argv[1])
    if not vmx.exists():
        print(f"ERROR: {vmx} not found", file=sys.stderr)
        return 1
    if not ESP_VMDK.exists():
        print(
            f"ERROR: {ESP_VMDK} not found. Build the disk first:\n"
            f"  python tools/make_disk.py",
            file=sys.stderr,
        )
        return 1

    existing = parse_vmx(vmx)
    ctrl, slot = pick_slot(existing)

    forced = dict(FORCED)
    forced[f"{ctrl}.present"]      = "TRUE"
    forced[f"{slot}.present"]      = "TRUE"
    forced[f"{slot}.fileName"]     = str(ESP_VMDK)
    forced[f"{slot}.deviceType"]   = "disk"

    # Backup once.
    backup = vmx.with_suffix(vmx.suffix + ".veneer.bak")
    if not backup.exists():
        backup.write_text(vmx.read_text(encoding="utf-8", errors="replace"),
                          encoding="utf-8")
        print(f"[vmx] backup: {backup}")

    # Read original, replace any line whose key is in `forced`, append the rest.
    seen: set[str] = set()
    out_lines: list[str] = []
    for raw in vmx.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r'^([A-Za-z0-9_.:]+)\s*=\s*"(.*)"\s*$', raw)
        if m and m.group(1) in forced:
            key = m.group(1)
            out_lines.append(f'{key} = "{forced[key]}"')
            seen.add(key)
        else:
            out_lines.append(raw)
    # Append any keys not already present.
    appended = []
    for key, val in forced.items():
        if key not in seen:
            appended.append(f'{key} = "{val}"')
    if appended:
        out_lines.append("")
        out_lines.append("# --- veneer hypervisor boot settings (added by patch_vmx.py) ---")
        out_lines.extend(appended)

    vmx.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    print(f"[vmx] patched : {vmx}")
    print(f"[vmx] controller chosen: {ctrl}  →  {slot}")
    print(f"[vmx] disk    : {ESP_VMDK}")
    print(f"[vmx] serial  : {SERIAL_LOG}")
    print(f"[vmx] guestOS forced to: {GUEST_OS}  "
          f"(only one whose UEFI fallback path scan works — see "
          f"facts/vmware_uefi_guest_quirks)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
