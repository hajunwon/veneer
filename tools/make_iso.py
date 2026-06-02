"""Build a UEFI-bootable ISO containing veneer-uefi.efi.

Design (working layout for VMware Workstation 22 UEFI firmware):
  - ISO 9660 + Joliet + Rock Ridge.
  - A FAT12 1.44 MB image is embedded; it contains /EFI/BOOT/BOOTX64.EFI.
  - El Torito boot record:
      * platform_id = 0xEF (EFI)
      * media_type  = 0x02 (1.44 MB floppy emulation)
      * boot file   = the FAT image
  - The .efi is ALSO dropped at /EFI/BOOT/BOOTX64.EFI in the ISO 9660 tree
    as a fallback for any firmware that prefers a filesystem scan.

Why floppy emulation: VMware UEFI does not load the El Torito boot file
as a flat PE binary. It expects to *mount* the file as a FAT filesystem
and then locate /EFI/BOOT/BOOTX64.EFI inside it. media_type=0 (no-emul)
caused "Status upon boot failure: No Media" — firmware found the boot
record but couldn't get any code out of it.
"""
from __future__ import annotations

import io
import struct
import sys
from pathlib import Path

import pycdlib


REPO_ROOT = Path(__file__).resolve().parent.parent
EFI_PATH = REPO_ROOT / "target" / "x86_64-unknown-uefi" / "release" / "veneer-uefi.efi"
OUT_ISO = REPO_ROOT / "target" / "veneer.iso"


def build_fat_image(efi_bytes: bytes) -> bytes:
    """Make a FAT12 image (1.44 MiB floppy size) holding
    /EFI/BOOT/BOOTX64.EFI. Returns the raw image bytes.
    """
    sectors = 2880
    sector_size = 512
    img = bytearray(sectors * sector_size)

    # BPB
    img[0:3] = b"\xEB\x3C\x90"
    img[3:11] = b"MSWIN4.1"
    struct.pack_into("<H", img, 11, sector_size)
    img[13] = 1
    struct.pack_into("<H", img, 14, 1)
    img[16] = 2
    struct.pack_into("<H", img, 17, 224)
    struct.pack_into("<H", img, 19, sectors)
    img[21] = 0xF0
    struct.pack_into("<H", img, 22, 9)
    struct.pack_into("<H", img, 24, 18)
    struct.pack_into("<H", img, 26, 2)
    struct.pack_into("<I", img, 28, 0)
    struct.pack_into("<I", img, 32, 0)
    img[36] = 0x00
    img[38] = 0x29
    struct.pack_into("<I", img, 39, 0xCAFEC0DE)
    img[43:54] = b"VENEER     "
    img[54:62] = b"FAT12   "
    img[510:512] = b"\x55\xAA"

    reserved = 1
    fat_size = 9
    n_fats = 2
    root_entries = 224
    root_dir_sectors = (root_entries * 32) // sector_size
    data_start = reserved + n_fats * fat_size + root_dir_sectors

    def dir_entry(name8: bytes, attr: int, cluster: int, size: int) -> bytes:
        e = bytearray(32)
        e[0:11] = name8
        e[11] = attr
        struct.pack_into("<H", e, 26, cluster)
        struct.pack_into("<I", e, 28, size)
        return bytes(e)

    root_dir_offset = (reserved + n_fats * fat_size) * sector_size
    img[root_dir_offset : root_dir_offset + 32] = dir_entry(b"EFI        ", 0x10, 2, 0)

    efi_cluster_off = data_start * sector_size
    img[efi_cluster_off : efi_cluster_off + 32] = dir_entry(b".          ", 0x10, 2, 0)
    img[efi_cluster_off + 32 : efi_cluster_off + 64] = dir_entry(b"..         ", 0x10, 0, 0)
    img[efi_cluster_off + 64 : efi_cluster_off + 96] = dir_entry(b"BOOT       ", 0x10, 3, 0)

    boot_cluster_off = (data_start + 1) * sector_size
    img[boot_cluster_off : boot_cluster_off + 32] = dir_entry(b".          ", 0x10, 3, 0)
    img[boot_cluster_off + 32 : boot_cluster_off + 64] = dir_entry(b"..         ", 0x10, 2, 0)
    efi_size = len(efi_bytes)
    img[boot_cluster_off + 64 : boot_cluster_off + 96] = dir_entry(
        b"BOOTX64 EFI", 0x20, 4, efi_size
    )

    file_cluster_off = (data_start + 2) * sector_size
    img[file_cluster_off : file_cluster_off + efi_size] = efi_bytes

    n_file_clusters = (efi_size + sector_size - 1) // sector_size

    fat = bytearray(fat_size * sector_size)

    def set_fat12(fat_buf: bytearray, idx: int, val: int) -> None:
        offset = (idx * 3) // 2
        if idx & 1 == 0:
            fat_buf[offset] = val & 0xFF
            fat_buf[offset + 1] = (fat_buf[offset + 1] & 0xF0) | ((val >> 8) & 0x0F)
        else:
            fat_buf[offset] = (fat_buf[offset] & 0x0F) | ((val << 4) & 0xF0)
            fat_buf[offset + 1] = (val >> 4) & 0xFF

    set_fat12(fat, 0, 0xFF0)
    set_fat12(fat, 1, 0xFFF)
    set_fat12(fat, 2, 0xFFF)
    set_fat12(fat, 3, 0xFFF)
    for i in range(n_file_clusters):
        cluster_idx = 4 + i
        if i == n_file_clusters - 1:
            set_fat12(fat, cluster_idx, 0xFFF)
        else:
            set_fat12(fat, cluster_idx, cluster_idx + 1)

    fat1_off = reserved * sector_size
    fat2_off = (reserved + fat_size) * sector_size
    img[fat1_off : fat1_off + fat_size * sector_size] = fat
    img[fat2_off : fat2_off + fat_size * sector_size] = fat

    return bytes(img)


def main() -> int:
    if not EFI_PATH.exists():
        print(f"ERROR: {EFI_PATH} not found.", file=sys.stderr)
        return 1

    efi_bytes = EFI_PATH.read_bytes()
    print(f"[iso] read {len(efi_bytes):,} bytes from {EFI_PATH.name}")

    fat_img = build_fat_image(efi_bytes)
    print(f"[iso] built FAT12 boot image: {len(fat_img):,} bytes")

    iso = pycdlib.PyCdlib()
    iso.new(joliet=3, rock_ridge="1.09")

    # 1) FAT image as the El Torito boot file
    iso.add_fp(
        io.BytesIO(fat_img),
        len(fat_img),
        iso_path="/EFIBOOT.IMG;1",
        rr_name="efiboot.img",
        joliet_path="/efiboot.img",
    )
    iso.add_eltorito(
        bootfile_path="/EFIBOOT.IMG;1",
        bootcatfile="/BOOT.CAT;1",
        media_name="floppy",   # 1.44 MB floppy emulation
        efi=True,
    )

    # 2) Also expose the .efi at the conventional UEFI path (filesystem fallback)
    iso.add_directory("/EFI", rr_name="EFI", joliet_path="/EFI")
    iso.add_directory("/EFI/BOOT", rr_name="BOOT", joliet_path="/EFI/BOOT")
    iso.add_fp(
        io.BytesIO(efi_bytes),
        len(efi_bytes),
        iso_path="/EFI/BOOT/BOOTX64.EFI;1",
        rr_name="BOOTX64.EFI",
        joliet_path="/EFI/BOOT/BOOTX64.EFI",
    )

    OUT_ISO.parent.mkdir(parents=True, exist_ok=True)
    iso.write(str(OUT_ISO))
    iso.close()

    size = OUT_ISO.stat().st_size
    print(f"[iso] wrote {OUT_ISO} ({size:,} bytes)")

    patch_eltorito(OUT_ISO)
    return 0


def patch_eltorito(iso_path: Path) -> None:
    """pycdlib does not set platform_id=0xEF reliably. Patch:
       - validation entry byte 1 -> 0xEF
       - recompute validation checksum
       - default entry media_type -> 0x02 (1.44 MB floppy emulation)
    """
    with open(iso_path, "r+b") as f:
        f.seek(17 * 2048 + 71)
        cat_lba = struct.unpack("<I", f.read(4))[0]

        f.seek(cat_lba * 2048)
        cat = bytearray(f.read(64))

        assert cat[0] == 0x01, "not a valid El Torito validation entry"

        cat[1] = 0xEF
        cat[28] = 0
        cat[29] = 0
        s = 0
        for i in range(0, 32, 2):
            s += cat[i] | (cat[i + 1] << 8)
        chk = (-s) & 0xFFFF
        cat[28] = chk & 0xFF
        cat[29] = (chk >> 8) & 0xFF

        # Default entry: media_type at byte 33 (= cat[32+1])
        # 0x02 = 1.44 MB floppy emulation. pycdlib's media_name="floppy"
        # should already set this, but make sure.
        cat[33] = 0x02

        f.seek(cat_lba * 2048)
        f.write(cat)
    print(f"[iso] patched El Torito: platform_id=0xEF, media_type=0x02 (1.44MB floppy emul)")


if __name__ == "__main__":
    sys.exit(main())
