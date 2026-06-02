"""Append a gzip-wrapped cpio archive containing our auto-inspection
/init to the active Alpine initramfs. Linux's `populate_rootfs` walks
every concatenated archive and lets later entries overwrite earlier
ones, so our /init replaces Alpine's standard one without rebuilding
the rest of the image.

Run this whenever the standard initramfs has been reset (e.g. after
re-extracting from the ISO) or when the probe script needs to be
updated. It rewrites D:/dev/alpine_extract/initramfs-lts.combined
in place; rerun `tools/make_disk.py` afterwards to refresh the VMDK.
"""
import gzip
from pathlib import Path

SRC = Path(r"D:/dev/alpine_extract/initramfs-lts.combined")

# The script that becomes guest PID 1 once Linux unpacks our cpio
# overlay over the standard Alpine one.
INIT_SCRIPT = r"""#!/bin/sh
# /init -- veneer auto-probe (PID 1 inside guest)
# Linux opens FDs 0/1/2 to /dev/console for us before exec'ing init,
# so plain echo/printf lands on the serial console. We avoid an
# `exec >...` redirect because if /dev/console is not yet mknod'd in
# our embedded rootfs the redirect aborts the shell with exit 1 and
# the kernel panics ("Attempted to kill init").
set +e

echo
echo '##################################################'
echo '# veneer auto-probe START'
echo '##################################################'
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null

banner(){ printf '\n===== %s =====\n' "$1"; }

banner '/proc/cpuinfo (first 30 lines)'
sed -n '1,30p' /proc/cpuinfo

banner 'CPU identity rows'
grep -E '^(vendor_id|cpu family|model|model name|stepping|microcode)' /proc/cpuinfo | head -10

banner 'CPU flags: hypervisor / paravirt stealth check'
grep -E '^flags' /proc/cpuinfo | head -1 | tr ' ' '\n' | grep -iE 'hyper|kvm|svm|vmx|paravirt' || echo '(none of these flags present)'

banner '/sys/class/dmi/id - SMBIOS exposure to userspace'
for f in /sys/class/dmi/id/*; do
  [ -f "$f" ] || continue
  v=$(cat "$f" 2>/dev/null)
  echo "$(basename $f)=$v"
done

banner '/proc/version'
cat /proc/version

banner '/sys/hypervisor'
ls /sys/hypervisor 2>/dev/null
for f in /sys/hypervisor/type /sys/hypervisor/version; do
  [ -f "$f" ] && echo "$f=$(cat $f 2>/dev/null)"
done

banner 'dmesg | hypervisor/kvm/vmware/paravirt references'
dmesg | grep -iE 'hyper|kvm|vmware|virtual|paravirt|microsoft|xen|vmm|nested' | head -40

banner 'dmesg | ACPI tables veneer published'
dmesg | grep -E 'ACPI: (RSDP|XSDT|FACP|DSDT|MADT|MCFG|HPET|SPCR|WSMT|TPM2)' | head -20

banner 'PCI devices (fake bus veneer publishes)'
for d in /sys/bus/pci/devices/*; do
  [ -d "$d" ] || continue
  ven=$(cat "$d/vendor" 2>/dev/null)
  dev=$(cat "$d/device" 2>/dev/null)
  cls=$(cat "$d/class" 2>/dev/null)
  echo "  $(basename $d) vendor=$ven device=$dev class=$cls"
done

banner '/proc/iomem (first 40 lines)'
head -40 /proc/iomem

banner 'dmesg tail (60 lines)'
dmesg | tail -60

echo
echo '##################################################'
echo '# veneer auto-probe DONE - halting in 3s'
echo '##################################################'
sleep 3
sync
# Try every shutdown path in turn. SysRq has to be enabled by hand
# because Alpine's default initramfs leaves it disabled.
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null
echo o > /proc/sysrq-trigger 2>/dev/null
poweroff -f 2>/dev/null
halt -f 2>/dev/null
reboot -f 2>/dev/null
# If none of those returned control we `exec` into a long sleep so
# this script's shell goes away and PID 1 becomes /bin/sleep. That
# avoids the fork-storm an `while :; do sleep 5; done` busy-wait
# triggered earlier (every iteration forked a sleep process and the
# guest OOM'd at iter ~5M).
exec /bin/sleep 600
"""


def cpio_newc(name: bytes, mode: int, content: bytes = b"") -> bytes:
    """One cpio newc entry. Layout per linux/scripts/gen_initramfs.sh."""
    namelen = len(name) + 1
    filesize = len(content)
    fields = (0, mode, 0, 0, 1, 0, filesize, 0, 0, 0, 0, namelen, 0)
    hdr = b"070701" + b"".join(f"{v:08x}".encode() for v in fields)
    nameblock = name + b"\x00"
    pad1 = (4 - (len(hdr) + len(nameblock)) % 4) % 4
    pad2 = (4 - filesize % 4) % 4
    return hdr + nameblock + b"\x00" * pad1 + content + b"\x00" * pad2


def build_archive() -> bytes:
    archive = cpio_newc(b"init", 0o100755, INIT_SCRIPT.encode("ascii"))
    archive += cpio_newc(b"TRAILER!!!", 0)
    pad = (512 - len(archive) % 512) % 512
    archive += b"\x00" * pad
    # Gzip wrapping makes Linux's gzip-aware unpack_to_rootfs find this
    # archive even if the preceding gzip stream ended on a non-512
    # boundary inside the original Alpine image.
    return gzip.compress(archive)


def main() -> None:
    archive_gz = build_archive()
    orig = SRC.read_bytes()
    pad_before = (512 - len(orig) % 512) % 512
    combined = orig + b"\x00" * pad_before + archive_gz
    SRC.write_bytes(combined)
    print(
        f"appended probe overlay: orig={len(orig)} "
        f"pad={pad_before} archive_gz={len(archive_gz)} total={len(combined)}"
    )


if __name__ == "__main__":
    main()
