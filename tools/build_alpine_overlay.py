"""Build an initramfs overlay that hijacks /init to print veneer-visible
firmware/PCI state over serial then poweroff.

Approach:
  - Linux initramfs extractor reads concatenated cpio.gz archives in
    order. If a later record has the same path as an earlier one, the
    later wins. So we just need a 1-file overlay (/init) appended after
    the stock Alpine initramfs.

Output:
  D:/dev/alpine_extract/initramfs-lts.combined
    = stock Alpine /boot/initramfs-lts  +  our overlay (cpio.gz)
"""
from __future__ import annotations

import gzip
import io
import struct
import sys
from pathlib import Path

ALPINE_ISO_EXTRACT = Path("D:/dev/alpine_extract")
STOCK_INITRAMFS = ALPINE_ISO_EXTRACT / "boot" / "initramfs-lts"
COMBINED = ALPINE_ISO_EXTRACT / "initramfs-lts.combined"

INIT_SCRIPT = b"""#!/bin/sh
# veneer external validator -- Alpine guest probe
# Runs as PID 1 inside the Alpine initramfs after EFI-stub boot.

BB=/bin/busybox

$BB mkdir -p /proc /sys /dev /tmp 2>/dev/null
$BB mount -t proc proc /proc 2>/dev/null
$BB mount -t sysfs sys /sys 2>/dev/null
$BB mount -t devtmpfs dev /dev 2>/dev/null

# Diagnostic beacon: /dev/kmsg goes through the kernel printk path so it
# always reaches every active console regardless of /dev/console binding.
# If this line never appears, our /init never ran (cpio overlay didn't
# take effect). If it appears but the echo lines below don't, exec
# redirect is the problem.
printf "<veneer-val> /init PID=$$ uname=%s mounts=ok\n" "$($BB uname -srm)" > /dev/kmsg 2>/dev/null
printf "<veneer-val> /init reached, dev_ttyS0_stat:%s\n" "$($BB stat -c %F /dev/ttyS0 2>&1)" > /dev/kmsg 2>/dev/null

# Route all our stdout/stderr through /dev/kmsg (kernel printk path).
# Direct writes to /dev/ttyS0 mysteriously vanish (probably some line
# discipline / termios drop in the serial8250 driver under VMware's
# serial passthrough), but /dev/kmsg always reaches every active
# console, so every echo below shows up in veneer-serial.log with a
# kernel timestamp prefix.
exec > /dev/kmsg 2>&1
printf "<veneer-val> exec redirect to /dev/kmsg done\n"

# Force kernel printk to console so dmesg shows up live
echo 8 > /proc/sys/kernel/printk 2>/dev/null

banner() {
    echo
    echo "============================================================"
    echo "[veneer-val] $1"
    echo "============================================================"
}

banner "Alpine guest probe START"
echo "[veneer-val] uname: $($BB uname -a)"

banner "/proc/cpuinfo (first processor)"
$BB awk '/^processor/{n++} n<2' /proc/cpuinfo

banner "Hypervisor / CPU vendor"
$BB grep -E "vendor_id|model name|flags" /proc/cpuinfo | $BB head -3
echo "[veneer-val] hypervisor flag present?"
$BB grep -o hypervisor /proc/cpuinfo | $BB head -1 || echo "  (none, bare-metal-looking)"

banner "/sys/firmware/dmi/id (SMBIOS string view)"
for f in /sys/class/dmi/id/*; do
    [ -f "$f" ] || continue
    n=$($BB basename "$f")
    case "$n" in
        *_raw|*power) continue ;;
    esac
    v=$($BB cat "$f" 2>/dev/null)
    [ -n "$v" ] && echo "  $n = $v"
done

banner "/sys/firmware/dmi/tables/DMI (first 512 bytes raw)"
$BB hexdump -C /sys/firmware/dmi/tables/DMI 2>/dev/null | $BB head -32

banner "/sys/firmware/acpi/tables/ listing"
$BB ls -la /sys/firmware/acpi/tables/ 2>/dev/null

banner "ACPI table headers (first 64 bytes of each)"
for t in /sys/firmware/acpi/tables/*; do
    [ -f "$t" ] || continue
    n=$($BB basename "$t")
    echo "--- $n ---"
    $BB hexdump -C "$t" 2>/dev/null | $BB head -4
done

banner "PCI devices (sysfs enum)"
for d in /sys/bus/pci/devices/*; do
    addr=$($BB basename "$d")
    v=$($BB cat "$d/vendor" 2>/dev/null)
    p=$($BB cat "$d/device" 2>/dev/null)
    c=$($BB cat "$d/class" 2>/dev/null)
    ss_v=$($BB cat "$d/subsystem_vendor" 2>/dev/null)
    ss_d=$($BB cat "$d/subsystem_device" 2>/dev/null)
    echo "  $addr  $v:$p  class=$c  subsys=$ss_v:$ss_d"
done

banner "PCI config space dump (256 B per device)"
for d in /sys/bus/pci/devices/*; do
    addr=$($BB basename "$d")
    if [ -f "$d/config" ]; then
        echo "--- $addr config (256B) ---"
        $BB dd if="$d/config" bs=256 count=1 2>/dev/null | $BB hexdump -C
    fi
done

banner "PCI BAR resources (file list + raw MMIO probe)"
for d in /sys/bus/pci/devices/*; do
    addr=$($BB basename "$d")
    [ -f "$d/resource" ] || continue
    echo "--- $addr resource map ---"
    $BB cat "$d/resource" | $BB head -6
    # Probe BAR0 only (256 bytes) -- this is what fires our MMIO emulator
    if [ -f "$d/resource0" ]; then
        sz=$($BB stat -c %s "$d/resource0" 2>/dev/null)
        echo "  resource0 size=$sz"
        $BB dd if="$d/resource0" bs=256 count=1 2>/dev/null | $BB hexdump -C | $BB head -8
    fi
done

banner "/proc/iomem"
$BB cat /proc/iomem

banner "/proc/ioports (truncated)"
$BB head -50 /proc/ioports

banner "/proc/interrupts (IOAPIC/MSI dispatch)"
$BB cat /proc/interrupts

banner "Clocksource (was HPET picked?)"
$BB cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null
echo "available:"
$BB cat /sys/devices/system/clocksource/clocksource0/available_clocksource 2>/dev/null

banner "Storage (NVMe / SATA) + Network + TPM"
echo "/sys/class/nvme/:"
$BB ls -la /sys/class/nvme/ 2>/dev/null
echo "/sys/class/block/ (first 20):"
$BB ls -la /sys/class/block/ 2>/dev/null | $BB head -20
echo "/sys/class/net/:"
$BB ls /sys/class/net/ 2>/dev/null
echo "/sys/class/tpm/:"
$BB ls -la /sys/class/tpm/ 2>/dev/null
echo "/dev/tpm0 stat:"
$BB ls -la /dev/tpm0 2>/dev/null || echo "  (no /dev/tpm0)"

banner "EFI runtime + variables"
$BB ls -la /sys/firmware/efi/ 2>/dev/null
echo "efivars:"
$BB ls /sys/firmware/efi/efivars/ 2>/dev/null | $BB head -10

banner "CPUID HV leaf (0x40000000) -- should be ERASED by veneer"
$BB modprobe cpuid 2>/dev/null
if [ -e /dev/cpu/0/cpuid ]; then
    echo "  raw 16 bytes @ 0x40000000:"
    $BB dd if=/dev/cpu/0/cpuid bs=16 count=1 skip=0x4000000 2>/dev/null | $BB hexdump -C
else
    echo "  (cpuid module not in initramfs)"
fi

banner "MSR access"
$BB modprobe msr 2>/dev/null
if [ -e /dev/cpu/0/msr ]; then
    echo "  /dev/cpu/0/msr present"
else
    echo "  (msr module not in initramfs)"
fi

banner "dmesg tail (last 120 lines)"
$BB dmesg | $BB tail -120

banner "Alpine guest probe DONE -- powering off in 3s"
$BB sync
$BB sleep 3
$BB poweroff -f 2>/dev/null
# Fallback: sysrq
echo o > /proc/sysrq-trigger 2>/dev/null
# Last resort
while true; do $BB sleep 60; done
"""


def cpio_newc_entry(name: str, data: bytes, mode: int, ino: int) -> bytes:
    """Build one cpio newc-format record (header + name + pad + data + pad)."""
    name_bytes = name.encode("ascii") + b"\x00"
    namesize = len(name_bytes)
    filesize = len(data)

    # 110-byte ASCII header, 13 fields x 8 hex chars + 6-byte magic
    fields = [
        ino,        # c_ino
        mode,       # c_mode
        0,          # c_uid
        0,          # c_gid
        1,          # c_nlink
        0,          # c_mtime
        filesize,   # c_filesize
        0, 0,       # c_devmajor, c_devminor
        0, 0,       # c_rdevmajor, c_rdevminor
        namesize,   # c_namesize
        0,          # c_check (always 0 for newc)
    ]
    header = b"070701" + b"".join(f"{v:08X}".encode() for v in fields)
    assert len(header) == 110

    # Pad (header + name) to 4-byte boundary
    chunk = header + name_bytes
    chunk += b"\x00" * ((4 - len(chunk) % 4) % 4)

    # Append data, pad to 4
    chunk += data
    chunk += b"\x00" * ((4 - len(chunk) % 4) % 4)
    return chunk


def build_overlay_cpio() -> bytes:
    """Return raw cpio (newc) with just /init + trailer."""
    out = io.BytesIO()
    out.write(cpio_newc_entry("init", INIT_SCRIPT, mode=0o100755, ino=1))
    # TRAILER!!! sentinel record
    out.write(cpio_newc_entry("TRAILER!!!", b"", mode=0, ino=0))
    return out.getvalue()


def main() -> int:
    if not STOCK_INITRAMFS.exists():
        print(f"ERROR: {STOCK_INITRAMFS} missing -- extract Alpine ISO first.", file=sys.stderr)
        return 1

    cpio_raw = build_overlay_cpio()
    overlay_gz = gzip.compress(cpio_raw, compresslevel=9, mtime=0)

    stock = STOCK_INITRAMFS.read_bytes()
    COMBINED.write_bytes(stock + overlay_gz)

    print(f"[overlay] stock initramfs : {len(stock):,} bytes")
    print(f"[overlay] our overlay     : {len(overlay_gz):,} bytes ({len(cpio_raw):,} uncompressed)")
    print(f"[overlay] combined        : {COMBINED}  ({len(stock) + len(overlay_gz):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
