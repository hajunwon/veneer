"""Diagnostic: rebuild initramfs-lts.combined as a SINGLE gzip stream
whose /init is Alpine's stock init with `set -x` tracing prepended.

Why a single gzip stream: install_probe_init.py appended a *second*
gzip member after zero padding, which Linux's unpack_to_rootfs does not
splice in (the trailing zeros sit between two compressed members and the
overlay never gets unpacked). Here we decompress the stock initramfs,
concatenate our cpio segment in the *uncompressed* domain -- the kernel
cpio parser resyncs on the next "070701" magic after a TRAILER -- then
gzip the whole thing once. No compressed-member concatenation involved.

The traced /init emits a known marker on its very first line, then
`set -x`. If the marker reaches the serial log, fd 1/2 are wired to the
console and the xtrace that follows pinpoints the failing command. If it
does NOT reach the log, the console fds themselves are the problem.
"""
import gzip
from pathlib import Path

ISO_INITRAMFS = Path(r"D:/dev/alpine_extract/alpine_iso_tmp2/boot/initramfs-lts")
STOCK_INIT = Path(r"D:/dev/alpine_extract/initramfs_root/init")
OUT = Path(r"D:/dev/alpine_extract/initramfs-lts.combined")

MARKER = "VENEER-TRACE-MARK init-entered"


def traced_init() -> bytes:
    raw = STOCK_INIT.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines(keepends=True)
    shebang, rest = lines[0], "".join(lines[1:])
    # echo to both fd1 (console) and /dev/kmsg so we learn which path works.
    inject = (
        f'echo "{MARKER}"\n'
        f'echo "{MARKER}" > /dev/kmsg 2>/dev/null\n'
        "set -x\n"
    )
    return (shebang + inject + rest).encode("utf-8")


def cpio_newc(name: bytes, mode: int, content: bytes = b"") -> bytes:
    namelen = len(name) + 1
    filesize = len(content)
    fields = (0, mode, 0, 0, 1, 0, filesize, 0, 0, 0, 0, namelen, 0)
    hdr = b"070701" + b"".join(f"{v:08x}".encode() for v in fields)
    nameblock = name + b"\x00"
    pad1 = (4 - (len(hdr) + len(nameblock)) % 4) % 4
    pad2 = (4 - filesize % 4) % 4
    return hdr + nameblock + b"\x00" * pad1 + content + b"\x00" * pad2


def main() -> None:
    stock_gz = ISO_INITRAMFS.read_bytes()
    cpio = gzip.decompress(stock_gz)
    # align to 4 before our segment (cpio headers are 4-aligned)
    pad = (4 - len(cpio) % 4) % 4
    segment = cpio_newc(b"init", 0o100755, traced_init())
    segment += cpio_newc(b"TRAILER!!!", 0)
    seg_pad = (512 - len(segment) % 512) % 512
    segment += b"\x00" * seg_pad
    merged = cpio + b"\x00" * pad + segment
    out = gzip.compress(merged, compresslevel=6)
    OUT.write_bytes(out)
    print(
        f"stock cpio={len(cpio)} +pad={pad} +segment={len(segment)} "
        f"-> merged={len(merged)} gz={len(out)} written to {OUT.name}"
    )


if __name__ == "__main__":
    main()
