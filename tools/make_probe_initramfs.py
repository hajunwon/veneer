"""Append a tiny cpio archive containing a custom /init to the existing
Alpine initramfs. Linux's `populate_rootfs` walks every concatenated
archive and lets later entries overwrite earlier ones, so our /init
replaces the standard Alpine init without rebuilding the whole image.

Result: PID 1 inside the guest runs our auto-inspection script, dumps
everything we care about to ttyS0 (which veneer forwards to
D:\\veneer-serial.log), then power-offs. No console interaction needed.
"""
import os

# ───── Auto-inspection script that becomes guest PID 1 ─────────────
INIT_SCRIPT = b'''#!/bin/sh
# /init — veneer auto-inspection (overrides Alpine standard init)
# Output goes to ttyS0 which veneer forwards to D:\\veneer-serial.log.
exec >/dev/ttyS0 2>&1 </dev/null

banner() { printf "\\n===== %s =====\\n" "$1"; }

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null

echo
echo "##################################################"
echo "# veneer auto-probe START"
echo "##################################################"

banner "/proc/cpuinfo (first 25 lines)"
sed -n "1,25p" /proc/cpuinfo

banner "CPU brand / vendor / family / model"
grep -E "^(vendor_id|cpu family|model|model name|stepping|microcode)" /proc/cpuinfo | head -10

banner "CPU flags (hypervisor bit should be CLEAR for stealth)"
grep -E "^flags" /proc/cpuinfo | head -1 | tr " " "\\n" | grep -iE "hyper|kvm|svm|vmx|paravirt"
echo "--- raw flags head ---"
grep -E "^flags" /proc/cpuinfo | head -1 | cut -c1-200

banner "/sys/class/dmi/id (SMBIOS exposure to userspace)"
for f in /sys/class/dmi/id/*; do
  [ -f "$f" ] || continue
  v=$(cat "$f" 2>/dev/null)
  echo "$(basename $f) = $v"
done

banner "/proc/version"
cat /proc/version

banner "/sys/hypervisor (paravirt interface)"
ls /sys/hypervisor 2>/dev/null
for f in /sys/hypervisor/type /sys/hypervisor/version; do
  [ -f "$f" ] && echo "$f = $(cat $f 2>/dev/null)"
done

banner "dmesg hypervisor / KVM / VMware references"
dmesg | grep -iE "hyper|kvm|vmware|virtual|paravirt|microsoft|xen|vmm|nested" | head -40

banner "dmesg ACPI tables"
dmesg | grep -E "ACPI: (RSDP|XSDT|FACP|DSDT|MADT|MCFG|HPET|SPCR|WSMT|TPM2)" | head -20

banner "PCI device list"
ls /sys/bus/pci/devices/ 2>/dev/null
for d in /sys/bus/pci/devices/*; do
  [ -d "$d" ] || continue
  ven=$(cat "$d/vendor" 2>/dev/null)
  dev=$(cat "$d/device" 2>/dev/null)
  cls=$(cat "$d/class" 2>/dev/null)
  bdf=$(basename "$d")
  echo "  $bdf  vendor=$ven device=$dev class=$cls"
done

banner "MSR / model identification"
[ -d /dev/cpu/0 ] && ls /dev/cpu/0 2>/dev/null
[ -r /sys/devices/system/cpu/cpu0/topology/thread_siblings ] && \\
  echo "cpu0 thread_siblings: $(cat /sys/devices/system/cpu/cpu0/topology/thread_siblings)"

banner "/proc/iomem (memory regions guest can see)"
head -40 /proc/iomem

banner "dmesg last 80 lines"
dmesg | tail -80

echo
echo "##################################################"
echo "# veneer auto-probe DONE — halting in 5s"
echo "##################################################"
sleep 5
sync
# Try multiple power-off paths so we don\\'t leave the guest spinning.
poweroff -f 2>/dev/null
halt -f 2>/dev/null
echo o > /proc/sysrq-trigger 2>/dev/null
# Last resort — busy halt loop (veneer detects HLT).
while :; do
  echo "[veneer-probe] requested halt — looping" > /dev/ttyS0
  sleep 5
done
'''


def cpio_newc(name: bytes, mode: int, content: bytes = b'') -> bytes:
    """Build one cpio "new ASCII" (newc) entry. Used both for /init and
    the TRAILER!!! sentinel."""
    namelen = len(name) + 1
    filesize = len(content)
    hdr_fields = (
        0,            # c_ino
        mode,         # c_mode
        0,            # c_uid
        0,            # c_gid
        1,            # c_nlink
        0,            # c_mtime
        filesize,     # c_filesize
        0,            # c_devmajor
        0,            # c_devminor
        0,            # c_rdevmajor
        0,            # c_rdevminor
        namelen,      # c_namesize
        0,            # c_check (unused for newc)
    )
    hdr = b'070701' + b''.join(f'{v:08x}'.encode() for v in hdr_fields)
    name_block = name + b'\x00'
    # Padding to 4-byte after header+name and after file data.
    pad_after_name = (4 - (len(hdr) + len(name_block)) % 4) % 4
    pad_after_data = (4 - filesize % 4) % 4
    return (
        hdr
        + name_block
        + b'\x00' * pad_after_name
        + content
        + b'\x00' * pad_after_data
    )


def main():
    src = r'D:\dev\alpine_extract\initramfs-lts.combined'
    dst = r'D:\dev\alpine_extract\initramfs-lts.combined.probe'

    with open(src, 'rb') as f:
        original = f.read()

    archive = b''
    archive += cpio_newc(b'init', 0o100755, INIT_SCRIPT)
    archive += cpio_newc(b'TRAILER!!!', 0o0)
    # Pad to 512-byte block — kernel cpio reader expects this between
    # concatenated archives.
    block_pad = (512 - len(archive) % 512) % 512
    archive += b'\x00' * block_pad

    combined = original + archive
    with open(dst, 'wb') as f:
        f.write(combined)
    print(f'wrote {dst}: {len(combined)} bytes (original {len(original)} + probe {len(archive)})')

    # Replace active initramfs.
    os.replace(dst, src)
    print(f'replaced active initramfs at {src}')


if __name__ == '__main__':
    main()
