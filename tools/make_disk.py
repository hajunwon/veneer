"""Build a UEFI-bootable virtual hard disk (VMDK) for VMware Workstation.

Layout (UEFI-spec compliant):

  LBA 0          : Protective MBR (one entry, type 0xEE, covers whole disk)
  LBA 1          : Primary GPT header
  LBA 2..33      : Primary partition entries (128 × 128 B = 32 sectors)
  LBA 34..2047   : padding to 1 MiB alignment
  LBA 2048..N    : FAT16 partition (the EFI System Partition, ESP)
                    /EFI/BOOT/BOOTX64.EFI inside
  ...
  LBA last-33..-1: Backup partition entries
  LBA last       : Backup GPT header

Why this and not "FAT directly at LBA 0":
  VMware Workstation's UEFI firmware boots a virtual hard disk only when
  the disk has a GPT partition table with a partition that has the
  ESP type GUID. Whole-disk FAT (no MBR/GPT) parses as raw data and the
  firmware reports "No compatible bootloader found", which is exactly
  what we saw in vmware.log.
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EFI_PATH = REPO_ROOT / "target" / "x86_64-unknown-uefi" / "release" / "veneer-uefi.efi"
TARGET_DIR = REPO_ROOT / "target"
FLAT_PATH = TARGET_DIR / "veneer-esp-flat.vmdk"
DESC_PATH = TARGET_DIR / "veneer-esp.vmdk"

SECTOR = 512
DISK_BYTES = 128 * 1024 * 1024
TOTAL_SECTORS = DISK_BYTES // SECTOR              # 262144
PART_START_LBA = 2048                              # 1 MiB-aligned
GPT_ENTRIES = 128
GPT_ENTRY_SIZE = 128
GPT_ENTRY_SECTORS = (GPT_ENTRIES * GPT_ENTRY_SIZE) // SECTOR  # 32
PART_END_LBA = TOTAL_SECTORS - GPT_ENTRY_SECTORS - 1 - 1  # leave room for backup
FIRST_USABLE_LBA = 2 + GPT_ENTRY_SECTORS           # 34
LAST_USABLE_LBA = TOTAL_SECTORS - GPT_ENTRY_SECTORS - 2

# ESP partition type (UEFI spec)
ESP_TYPE_GUID = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
DISK_GUID = "11112222-3333-4444-5555-66778899AABB"
PART_GUID = "AABBCCDD-EEFF-1122-3344-556677889900"


def guid_to_bytes(s: str) -> bytes:
    """Encode a GUID string as 16 bytes in mixed endian (Microsoft style):
    first three fields little-endian, last two big-endian."""
    s = s.replace("-", "")
    raw = bytes.fromhex(s)
    return (
        raw[0:4][::-1]
        + raw[4:6][::-1]
        + raw[6:8][::-1]
        + raw[8:10]
        + raw[10:16]
    )


def build_fat16_partition(efi_bytes: bytes, total_part_sectors: int,
                          partition_first_lba: int) -> bytes:
    """Build the FAT16 partition contents. `total_part_sectors` is the
    partition size in 512 B sectors. `partition_first_lba` is the absolute
    LBA where this partition begins on the disk (goes into BPB hidden_sectors).
    """
    img = bytearray(total_part_sectors * SECTOR)

    # 128 MiB ESP: 8 sectors/cluster = 4 KiB clusters keeps cluster
    # count under FAT16's 65525-entry limit (128 MiB / 4 KiB = 32K).
    sec_per_cluster = 8
    cluster_size = sec_per_cluster * SECTOR
    reserved = 1
    n_fats = 2
    root_entries = 512
    root_dir_sectors = (root_entries * 32) // SECTOR  # 32
    fat_sectors = 128                                  # holds 32768 entries — plenty for ~32K clusters

    # BPB
    img[0:3] = b"\xEB\x3C\x90"
    img[3:11] = b"MSWIN4.1"
    struct.pack_into("<H", img, 11, SECTOR)
    img[13] = sec_per_cluster
    struct.pack_into("<H", img, 14, reserved)
    img[16] = n_fats
    struct.pack_into("<H", img, 17, root_entries)
    struct.pack_into("<H", img, 19, 0)               # use 32-bit field
    img[21] = 0xF8                                    # hard-disk media
    struct.pack_into("<H", img, 22, fat_sectors)
    struct.pack_into("<H", img, 24, 63)
    struct.pack_into("<H", img, 26, 16)
    struct.pack_into("<I", img, 28, partition_first_lba)  # hidden_sectors!
    struct.pack_into("<I", img, 32, total_part_sectors)
    img[36] = 0x80
    img[37] = 0
    img[38] = 0x29
    struct.pack_into("<I", img, 39, 0xCAFEBABE)
    img[43:54] = b"VENEER ESP "
    img[54:62] = b"FAT16   "
    img[510:512] = b"\x55\xAA"

    data_start = reserved + n_fats * fat_sectors + root_dir_sectors  # 1+256+32 = 289

    def dir_entry(name8: bytes, attr: int, cluster: int, size: int) -> bytes:
        e = bytearray(32)
        e[0:11] = name8
        e[11] = attr
        struct.pack_into("<H", e, 26, cluster)
        struct.pack_into("<I", e, 28, size)
        return bytes(e)

    def cluster_offset(cluster: int) -> int:
        return (data_start + (cluster - 2) * sec_per_cluster) * SECTOR

    # Root directory
    root_off = (reserved + n_fats * fat_sectors) * SECTOR
    img[root_off : root_off + 32] = dir_entry(b"EFI        ", 0x10, 2, 0)

    # /EFI (cluster 2)
    efi_off = cluster_offset(2)
    img[efi_off + 0  : efi_off + 32 ] = dir_entry(b".          ", 0x10, 2, 0)
    img[efi_off + 32 : efi_off + 64 ] = dir_entry(b"..         ", 0x10, 0, 0)
    img[efi_off + 64 : efi_off + 96 ] = dir_entry(b"BOOT       ", 0x10, 3, 0)

    # /EFI/BOOT (cluster 3)
    boot_off = cluster_offset(3)
    efi_size = len(efi_bytes)
    img[boot_off + 0  : boot_off + 32 ] = dir_entry(b".          ", 0x10, 3, 0)
    img[boot_off + 32 : boot_off + 64 ] = dir_entry(b"..         ", 0x10, 2, 0)
    # Long File Name entry for "BOOTX64.EFI" — some UEFI firmware looks for it.
    img[boot_off + 64 : boot_off + 96 ] = build_lfn_entry("BOOTX64.EFI", short_8_3=b"BOOTX64 EFI")
    img[boot_off + 96 : boot_off + 128] = dir_entry(b"BOOTX64 EFI", 0x20, 4, efi_size)

    # /EFI/BOOT/BOOTX64.EFI (cluster 4..)
    file_off = cluster_offset(4)
    img[file_off : file_off + efi_size] = efi_bytes
    n_file_clusters = (efi_size + cluster_size - 1) // cluster_size

    # Optional TOML overlays — same parent directory as BOOTX64.EFI so
    # veneer can find them via UEFI File Protocol relative paths.
    next_cluster = 4 + n_file_clusters
    next_dir_off = 128

    tomls = []  # (short_name_11, lfn_name, bytes)
    profile_toml = REPO_ROOT / "assets" / "profiles" / "amd_desktop.toml"
    config_toml = REPO_ROOT / "assets" / "config" / "veneer.toml"
    if profile_toml.exists():
        tomls.append((b"PROFILE TOM", "profile.toml", profile_toml.read_bytes()))
    if config_toml.exists():
        tomls.append((b"CONFIG  TOM", "config.toml", config_toml.read_bytes()))

    # Alpine Linux for external validation (chain-loaded by veneer
    # after the intercept-coverage loop). The kernel is EFI-stub +
    # initramfs overlay whose /init hijacks PID 1 to dump
    # sysfs/PCI/ACPI/SMBIOS/MMIO state to ttyS0, then poweroff.
    #
    # Built artifacts come from:
    #   1) 7z x of /d/dev/alpine-standard-3.23.4-x86_64.iso
    #      -> /d/dev/alpine_extract/boot/{vmlinuz-lts}
    #   2) python tools/build_alpine_overlay.py
    #      -> /d/dev/alpine_extract/initramfs-lts.combined
    #
    # Both files land at root of ESP. chain_load.rs opens \vmlinuz-lts
    # and passes `initrd=\initramfs-lts` in the kernel cmdline.
    alpine_dir = Path("D:/dev/alpine_extract")
    vmlinux_elf = alpine_dir / "vmlinux.elf"        # decompressor 우회용 raw ELF
    initramfs = alpine_dir / "initramfs-lts.combined"
    # Root-level entries (cluster slot in root dir, not /EFI/BOOT)
    # are placed AFTER /EFI in the root directory.
    root_extras = []  # (short_name_11, lfn_name, bytes)
    if vmlinux_elf.exists():
        root_extras.append((b"VMLINUX ELF", "vmlinux.elf", vmlinux_elf.read_bytes()))
    if initramfs.exists():
        root_extras.append((b"INITRAMFLTS", "initramfs-lts", initramfs.read_bytes()))

    # OVMF guest firmware (CODE + VARS) -> ESP root, read by enter_ovmf_guest
    # as \OVMFCODE.FD and \OVMFVARS.FD. Use plain 8.3 names (<=11 chars) so a
    # single LFN entry suffices; the source filenames (OVMF_CODE_4M.fd, 15
    # chars) would need two LFN slots, which build_lfn_entry doesn't emit, so
    # UEFI couldn't match them and veneer saw "not found".
    ovmf_dir = REPO_ROOT / "assets" / "firmware"
    ovmf_code = ovmf_dir / "OVMF_CODE_4M.fd"
    ovmf_vars = ovmf_dir / "OVMF_VARS_4M.fd"
    # 8.3 short name = 8-byte base + 3-byte ext, space-padded ("OVMFCODE"+"FD ").
    if ovmf_code.exists():
        root_extras.append((b"OVMFCODEFD ", "OVMFCODE.FD", ovmf_code.read_bytes()))
    if ovmf_vars.exists():
        root_extras.append((b"OVMFVARSFD ", "OVMFVARS.FD", ovmf_vars.read_bytes()))

    toml_extents = []  # (cluster_start, n_clusters)
    for short_name, lfn, data in tomls:
        img[boot_off + next_dir_off      : boot_off + next_dir_off + 32]  = \
            build_lfn_entry(lfn, short_8_3=short_name)
        img[boot_off + next_dir_off + 32 : boot_off + next_dir_off + 64]  = \
            dir_entry(short_name, 0x20, next_cluster, len(data))
        next_dir_off += 64

        data_off = cluster_offset(next_cluster)
        img[data_off : data_off + len(data)] = data
        n_clusters = (len(data) + cluster_size - 1) // cluster_size
        toml_extents.append((next_cluster, n_clusters))
        next_cluster += n_clusters

    # Root-directory extras (Alpine vmlinuz + initramfs). Sit alongside
    # the /EFI directory entry so chain_load.rs sees them at \vmlinuz-lts
    # and Linux EFI-stub sees them at \initramfs-lts.
    root_dir_extents = []  # (cluster_start, n_clusters)
    root_next_off = 32     # /EFI entry already at offset 0
    for short_name, lfn, data in root_extras:
        img[root_off + root_next_off      : root_off + root_next_off + 32] = \
            build_lfn_entry(lfn, short_8_3=short_name)
        img[root_off + root_next_off + 32 : root_off + root_next_off + 64] = \
            dir_entry(short_name, 0x20, next_cluster, len(data))
        root_next_off += 64

        data_off = cluster_offset(next_cluster)
        img[data_off : data_off + len(data)] = data
        n_clusters = (len(data) + cluster_size - 1) // cluster_size
        root_dir_extents.append((next_cluster, n_clusters))
        next_cluster += n_clusters

    # FAT16 table
    fat = bytearray(fat_sectors * SECTOR)

    def set_fat16(idx: int, val: int) -> None:
        struct.pack_into("<H", fat, idx * 2, val & 0xFFFF)

    set_fat16(0, 0xFFF8)
    set_fat16(1, 0xFFFF)
    set_fat16(2, 0xFFFF)
    set_fat16(3, 0xFFFF)
    for i in range(n_file_clusters):
        c = 4 + i
        set_fat16(c, 0xFFFF if i == n_file_clusters - 1 else c + 1)
    for (start, count) in toml_extents:
        for i in range(count):
            c = start + i
            set_fat16(c, 0xFFFF if i == count - 1 else c + 1)
    for (start, count) in root_dir_extents:
        for i in range(count):
            c = start + i
            set_fat16(c, 0xFFFF if i == count - 1 else c + 1)

    fat1_off = reserved * SECTOR
    fat2_off = (reserved + fat_sectors) * SECTOR
    img[fat1_off : fat1_off + fat_sectors * SECTOR] = fat
    img[fat2_off : fat2_off + fat_sectors * SECTOR] = fat

    return bytes(img)


def build_lfn_entry(name: str, short_8_3: bytes) -> bytes:
    """One Long File Name slot for the 8.3 entry that follows. Only valid for
    names ≤ 13 chars (one slot covers 13 UTF-16 chars). The LFN checksum is
    computed from the short 8.3 name bytes."""
    assert len(short_8_3) == 11
    checksum = 0
    for b in short_8_3:
        checksum = ((checksum >> 1) | ((checksum & 1) << 7)) & 0xFF
        checksum = (checksum + b) & 0xFF

    # Pad UTF-16LE name to 13 chars: real chars, NUL, then 0xFFFF...
    utf16 = name.encode("utf-16-le")
    if len(utf16) < 13 * 2:
        utf16 += b"\x00\x00"            # NUL terminator
        utf16 += b"\xFF\xFF" * (13 - (len(utf16) // 2))

    e = bytearray(32)
    e[0] = 0x41                          # sequence: last (0x40) + first (1)
    e[1:11]   = utf16[0:10]              # chars 1-5
    e[11]     = 0x0F                     # attr = LFN
    e[12]     = 0
    e[13]     = checksum
    e[14:26]  = utf16[10:22]             # chars 6-11
    e[26:28]  = b"\x00\x00"              # cluster (always 0 in LFN)
    e[28:32]  = utf16[22:26]             # chars 12-13
    return bytes(e)


def build_protective_mbr() -> bytes:
    mbr = bytearray(512)
    # Boot code area is left zero — UEFI ignores it.
    # Partition entry 0 (offset 446):
    #   status, CHS first (3B), type, CHS last (3B), LBA first (4B), sectors (4B)
    mbr[446 + 0] = 0x00                              # not bootable
    mbr[446 + 1:446 + 4] = b"\x00\x02\x00"           # CHS first (LBA 1)
    mbr[446 + 4] = 0xEE                              # GPT protective
    mbr[446 + 5:446 + 8] = b"\xFF\xFF\xFF"           # CHS last
    struct.pack_into("<I", mbr, 446 + 8, 1)          # first LBA
    struct.pack_into("<I", mbr, 446 + 12,
                     min(TOTAL_SECTORS - 1, 0xFFFFFFFF))  # total sectors covered
    mbr[510:512] = b"\x55\xAA"
    return bytes(mbr)


def build_partition_entries() -> bytes:
    """One ESP entry, rest zeros. Returns GPT_ENTRY_SECTORS * SECTOR bytes."""
    entries = bytearray(GPT_ENTRY_SECTORS * SECTOR)

    e = bytearray(GPT_ENTRY_SIZE)
    e[0:16] = guid_to_bytes(ESP_TYPE_GUID)
    e[16:32] = guid_to_bytes(PART_GUID)
    struct.pack_into("<Q", e, 32, PART_START_LBA)
    struct.pack_into("<Q", e, 40, PART_END_LBA)
    struct.pack_into("<Q", e, 48, 0)                 # attributes
    # Partition name in UTF-16 LE, 36 chars
    name = "EFI System Partition".encode("utf-16-le")
    e[56:56 + len(name)] = name

    entries[0:GPT_ENTRY_SIZE] = e
    return bytes(entries)


def build_gpt_header(is_backup: bool, my_lba: int, alt_lba: int,
                     entries_lba: int, entries_crc: int) -> bytes:
    hdr = bytearray(SECTOR)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<I", hdr, 8, 0x00010000)       # revision
    struct.pack_into("<I", hdr, 12, 92)              # header size
    # bytes 16-19 = header CRC, fill last
    struct.pack_into("<I", hdr, 20, 0)               # reserved
    struct.pack_into("<Q", hdr, 24, my_lba)
    struct.pack_into("<Q", hdr, 32, alt_lba)
    struct.pack_into("<Q", hdr, 40, FIRST_USABLE_LBA)
    struct.pack_into("<Q", hdr, 48, LAST_USABLE_LBA)
    hdr[56:72] = guid_to_bytes(DISK_GUID)
    struct.pack_into("<Q", hdr, 72, entries_lba)
    struct.pack_into("<I", hdr, 80, GPT_ENTRIES)
    struct.pack_into("<I", hdr, 84, GPT_ENTRY_SIZE)
    struct.pack_into("<I", hdr, 88, entries_crc)

    # Compute header CRC (over first 92 bytes, with CRC field set to 0)
    crc = zlib.crc32(hdr[0:92]) & 0xFFFFFFFF
    struct.pack_into("<I", hdr, 16, crc)
    return bytes(hdr)


def main() -> int:
    if not EFI_PATH.exists():
        print(f"ERROR: {EFI_PATH} not found.", file=sys.stderr)
        return 1
    efi = EFI_PATH.read_bytes()
    print(f"[disk] read {len(efi):,} bytes from {EFI_PATH.name}")

    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    disk = bytearray(DISK_BYTES)

    # Protective MBR @ LBA 0
    disk[0 : SECTOR] = build_protective_mbr()

    # Partition entries (primary copy) @ LBA 2..33
    entries = build_partition_entries()
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF
    primary_entries_off = 2 * SECTOR
    disk[primary_entries_off : primary_entries_off + len(entries)] = entries

    # Primary GPT header @ LBA 1
    primary_hdr = build_gpt_header(
        is_backup=False,
        my_lba=1,
        alt_lba=TOTAL_SECTORS - 1,
        entries_lba=2,
        entries_crc=entries_crc,
    )
    disk[SECTOR : 2 * SECTOR] = primary_hdr

    # Backup partition entries @ LBA last-32..last-1
    backup_entries_lba = TOTAL_SECTORS - GPT_ENTRY_SECTORS - 1
    backup_entries_off = backup_entries_lba * SECTOR
    disk[backup_entries_off : backup_entries_off + len(entries)] = entries

    # Backup GPT header @ LBA last
    backup_hdr = build_gpt_header(
        is_backup=True,
        my_lba=TOTAL_SECTORS - 1,
        alt_lba=1,
        entries_lba=backup_entries_lba,
        entries_crc=entries_crc,
    )
    disk[(TOTAL_SECTORS - 1) * SECTOR : TOTAL_SECTORS * SECTOR] = backup_hdr

    # FAT16 partition @ LBA 2048
    part_sectors = PART_END_LBA - PART_START_LBA + 1
    fat_part = build_fat16_partition(efi, part_sectors, PART_START_LBA)
    part_off = PART_START_LBA * SECTOR
    disk[part_off : part_off + len(fat_part)] = fat_part

    # IMPORTANT: We no longer write the descriptor (DESC_PATH). The descriptor
    # is created by `vmware-vdiskmanager.exe` (see README), and overwriting it
    # would replace VMware's correctly-formed descriptor (virtual hardware
    # version, content ID, UUID, etc.) with our handcrafted one — which
    # VMware Workstation's UEFI firmware has so far refused to boot from.
    # We only update the raw extent file in place.
    if not FLAT_PATH.exists():
        print(
            f"ERROR: {FLAT_PATH} does not exist. Create the VMDK pair first:\n"
            f'  "C:\\Program Files (x86)\\VMware\\VMware Workstation\\'
            f'vmware-vdiskmanager.exe" -c -s 64MB -a ide -t 2 '
            f'"{DESC_PATH}"',
            file=sys.stderr,
        )
        return 1
    existing_size = FLAT_PATH.stat().st_size
    if existing_size < DISK_BYTES:
        print(
            f"ERROR: {FLAT_PATH} is {existing_size:,} bytes, smaller than "
            f"the {DISK_BYTES:,} bytes we need. Recreate it with vmware-vdiskmanager.",
            file=sys.stderr,
        )
        return 1

    # VMware Workstation sometimes rewrites the descriptor / extends the
    # flat extent (e.g. after a snapshot or 'commit'). Rather than refuse
    # to run, overwrite the first DISK_BYTES in place and leave any extra
    # bytes alone — they live past our backup GPT and the firmware only
    # ever reads the primary GPT at LBA 1.
    with open(FLAT_PATH, "r+b") as f:
        f.seek(0)
        f.write(disk)
    if existing_size == DISK_BYTES:
        print(f"[disk] overwrote {FLAT_PATH} ({DISK_BYTES // (1024*1024)} MiB)")
    else:
        print(
            f"[disk] overwrote first {DISK_BYTES // (1024*1024)} MiB of {FLAT_PATH} "
            f"(file is {existing_size:,} bytes)"
        )
    print(
        f"[disk]   GPT primary @ LBA 1, ESP @ LBA {PART_START_LBA}..{PART_END_LBA} "
        f"({part_sectors} sectors, ~{part_sectors * SECTOR // (1024*1024)} MiB)"
    )
    print(f"[disk]   descriptor {DESC_PATH.name} left untouched (made by vmware-vdiskmanager)")
    return 0


def write_vmdk_descriptor(path: Path, flat_name: str, sectors: int) -> None:
    cyl = sectors // (16 * 63)
    path.write_text(
        f"""# Disk DescriptorFile
version=1
encoding="UTF-8"
CID=cafebabe
parentCID=ffffffff
isNativeSnapshot="no"
createType="monolithicFlat"

# Extent description
RW {sectors} FLAT "{flat_name}" 0

# The Disk Data Base
#DDB

ddb.adapterType = "ide"
ddb.geometry.cylinders = "{cyl}"
ddb.geometry.heads = "16"
ddb.geometry.sectors = "63"
ddb.longContentID = "deadbeefcafebabe1234567890abcdef"
ddb.uuid = "60 00 c2 9d ab cd ef 12-34 56 78 9a bc de f0 12"
ddb.virtualHWVersion = "22"
""",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    sys.exit(main())
