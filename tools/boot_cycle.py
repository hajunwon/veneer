"""One-shot boot cycle helper for veneer.

Steps:
  1. Truncate the serial log so we only read this boot's output.
  2. `vmrun start` the veneer VM.
  3. Tail the serial log and watch for terminal markers
     (probe-DONE, iteration-cap, VMRUN-halting, "panic", VMware
     exception). Bail with a force-stop on overall timeout.
  4. `vmrun stop` for safety.
  5. Print a short summary + the last few hundred lines of log so
     the next iteration of the dev loop can read it directly.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path


VMRUN = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
VMX = r"F:\03_VMWare\machines\alpine-test\alpine-test.vmx"
LOG = r"D:\veneer-serial.log"

# Console kernel debugger (same engine as WinDbg). Used by --attach-kd to
# break into the running guest and run a fixed command list, capturing the
# output. Launched via subprocess (a list argv) so the pipe path and the
# quoted -c command reach kd verbatim — neither git-bash MSYS path conversion
# nor PowerShell argument splitting mangles them.
KD = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe"
KD_PIPE = r"\\.\pipe\veneer-kd"   # VMware serial1 named pipe (endPoint=server)
KD_SYMPATH = r"srv*C:\Symbols*https://msdl.microsoft.com/download/symbols"

# Known VM targets — pick with `--vm <name>` instead of typing the path.
VMX_TARGETS = {
    "alpine": r"F:\03_VMWare\machines\alpine-test\alpine-test.vmx",
    "tiny11": r"F:\03_VMWare\machines\tiny11-test\tiny11-test.vmx",
}

# Markers we look for in the streamed log to decide we're done.
# Each entry is (marker substring, classification).
TERMINAL_MARKERS: list[tuple[str, str]] = [
    ("[veneer-probe] DONE",              "probe-complete"),
    ("[veneer-probe] auto-probe DONE",   "probe-complete"),
    ("iteration cap reached",            "iter-cap-reached"),
    ("VMRUN loop returned",              "vmrun-halted"),
    ("guest HLT",                        "guest-halted"),
    ("Kernel panic - not syncing",       "kernel-panic"),
    ("!!!! X64 Exception",               "vmware-firmware-exception"),
    ("The firmware encountered",         "vmware-firmware-exception"),
]


def run_vmrun(*args: str, capture: bool = True) -> tuple[int, str]:
    """Invoke vmrun and return (rc, stdout+stderr)."""
    cmd = [VMRUN, "-T", "ws", *args]
    res = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = (res.stdout or "") + (res.stderr or "")
    return res.returncode, out.strip()


def power_state(vmx: str) -> str:
    """Best-effort read of `vmrun checkPowerState`. Returns a short
    string; caller treats anything containing "off" as terminal."""
    rc, out = run_vmrun("checkPowerState", vmx)
    if rc != 0:
        return f"(check failed rc={rc}: {out})"
    return out.strip().lower()


def truncate_log() -> None:
    """Delete the serial log so VMware opens a fresh file instead of popping
    the "<file> already exists, replace?" dialog, which blocks power-on until
    someone clicks it. Falls back to truncating in place if the file is locked
    (a stale vmware-vmx still holding the handle)."""
    try:
        Path(LOG).unlink(missing_ok=True)
    except OSError as e:
        print(f"[cycle] could not delete {LOG} ({e}); truncating in place")
        try:
            Path(LOG).write_bytes(b"")
        except OSError:
            pass


def tail_lines(n: int = 80) -> str:
    try:
        data = Path(LOG).read_bytes()
    except FileNotFoundError:
        return "(log missing)"
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    return "\n".join(lines[-n:])


def classify_log() -> tuple[str | None, int]:
    """Return (marker classification, log size) by scanning the
    accumulated serial log. None if no terminal marker fired yet."""
    try:
        data = Path(LOG).read_bytes()
    except FileNotFoundError:
        return None, 0
    size = len(data)
    text = data.decode("utf-8", errors="replace")
    # Walk markers in priority order so probe-complete wins over a
    # generic VMRUN-loop-returned line that follows it.
    for needle, label in TERMINAL_MARKERS:
        if needle in text:
            return label, size
    return None, size


def attach_kd(commands: str, pipe: str, sympath: str, timeout_s: float,
              out_path: str, settle_s: float) -> None:
    """Break into the running guest over the COM2 KD pipe and run `commands`,
    capturing the output. `-b` forces a break-in on connect (the guest need
    not be at a bugcheck), so the fixed command list runs against whatever the
    guest is currently executing. Bounded by `timeout_s` — on overrun kd is
    killed and the partial output kept. The VM is NOT touched here; the caller
    decides whether to stop it (use --no-stop / --kd to keep it for re-attach)."""
    if settle_s > 0:
        print(f"[kd] settling {settle_s:.0f}s before break-in")
        time.sleep(settle_s)
    conn = f"com:port={pipe},baud=115200,pipe,reconnect"
    cmds = commands.strip().rstrip(";").strip()
    if not cmds.endswith("q"):
        cmds += "; q"
    # `.reload /f` first so symbols resolve; then the caller's commands.
    full = f".reload /f; {cmds}"
    argv = [KD, "-b", "-k", conn, "-y", sympath, "-c", full]
    print(f"[kd] {' '.join(argv)}")
    try:
        res = subprocess.run(argv, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=timeout_s)
        out = (res.stdout or "") + (res.stderr or "")
        print(f"[kd] exited rc={res.returncode}")
    except subprocess.TimeoutExpired as e:
        so = e.stdout if isinstance(e.stdout, str) else (e.stdout.decode("utf-8", "replace") if e.stdout else "")
        out = so + f"\n[kd] TIMEOUT after {timeout_s:.0f}s — killed"
        print(f"[kd] TIMEOUT after {timeout_s:.0f}s")
    try:
        Path(out_path).write_text(out, encoding="utf-8", errors="replace")
        print(f"[kd] capture saved → {out_path}")
    except OSError as e:
        print(f"[kd] could not save capture: {e}")
    enc = sys.stdout.encoding or "utf-8"
    print("[kd] --- capture ---")
    print(out.encode(enc, errors="replace").decode(enc, errors="replace"))
    print("[kd] --- end capture ---")


def boot_cycle(vmx: str, gui: bool, timeout_s: float, poll_s: float,
               quiet_tail: int, stall_after: float, stall_grace: float,
               no_stop: bool = False, no_stall: bool = False,
               no_truncate: bool = False, attach_kd_cmds: str | None = None,
               kd_pipe: str = KD_PIPE, kd_sympath: str = KD_SYMPATH,
               kd_timeout: float = 90.0, kd_out: str = r"F:\02_Dev\temp\kd_capture.log",
               kd_settle: float = 5.0) -> int:
    if no_truncate:
        print(f"[cycle] keeping existing {LOG} (--no-truncate)")
    else:
        truncate_log()
        print(f"[cycle] reset {LOG}")
    print(f"[cycle] target {vmx} ({'gui' if gui else 'nogui'})")

    rc, out = run_vmrun("start", vmx, "gui" if gui else "nogui")
    if rc != 0:
        print(f"[cycle] vmrun start failed (rc={rc}):\n{out}")
        return 2
    print(f"[cycle] VM started")

    started = time.monotonic()
    last_size = -1
    last_growth = started
    while True:
        marker, size = classify_log()
        elapsed = time.monotonic() - started

        if size != last_size:
            last_size = size
            last_growth = time.monotonic()

        if marker is not None:
            print(f"[cycle] terminal marker after {elapsed:0.1f}s: {marker} (log={size}B)")
            break

        if elapsed >= timeout_s:
            print(f"[cycle] overall timeout {timeout_s:.0f}s elapsed - forcing stop (log={size}B)")
            break

        # If the log hasn't grown in `stall_grace`s and we're past the
        # `stall_after` mark, the guest is probably hung deeper than our
        # markers reach. Bail so we don't burn the whole timeout. The
        # `stall_after` window must outlast any manual keypress the boot
        # waits on (cdboot's "press any key").
        # Stall watchdog. Disabled by --no-stall (e.g. KD sessions, where a
        # debugger break-in or breakpoint legitimately freezes the serial log
        # while you inspect — that's NOT a hang and must not trip a stop).
        if (not no_stall and elapsed >= stall_after
                and time.monotonic() - last_growth >= stall_grace):
            print(f"[cycle] log stalled {stall_grace:.0f}s past {stall_after:.0f}s mark - assuming hang (log={size}B)")
            break

        time.sleep(poll_s)

    # Optional KD capture: break into the (still-running) guest and dump.
    if attach_kd_cmds:
        attach_kd(attach_kd_cmds, kd_pipe, kd_sympath, kd_timeout, kd_out, kd_settle)

    # Force-stop on exit — unless --no-stop, which leaves the VM running so a
    # debugger (WinDbg/kd over the COM2 pipe) can stay attached. The default
    # (stop) suits unattended boot iteration; --no-stop suits KD sessions.
    if no_stop:
        state = power_state(vmx)
        print(f"[cycle] --no-stop: leaving VM running ({state}); stop it yourself when done")
    else:
        state = power_state(vmx)
        if "off" not in state:
            rc, out = run_vmrun("stop", vmx, "hard")
            print(f"[cycle] vmrun stop hard (rc={rc}): {out.strip()}")
        else:
            print(f"[cycle] VM already powered off ({state})")

    final_marker, final_size = classify_log()
    print(f"[cycle] final log size = {final_size}B, marker = {final_marker}")
    if quiet_tail > 0:
        # Console encoding on Windows-KO is cp949, which can't render
        # the kernel log's em-dashes / box-drawing chars. Re-encode to
        # the console codepage and replace anything unsupported.
        tail = tail_lines(quiet_tail)
        enc = sys.stdout.encoding or "utf-8"
        safe = tail.encode(enc, errors="replace").decode(enc, errors="replace")
        print(f"[cycle] --- last {quiet_tail} log lines ---")
        print(safe)
        print(f"[cycle] --- end log ---")

    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vm", choices=sorted(VMX_TARGETS), default="alpine",
                    help="named VM target")
    ap.add_argument("--vmx", default=None,
                    help="explicit .vmx path (overrides --vm)")
    ap.add_argument("--gui", action="store_true",
                    help="start with a window so the guest can take keystrokes")
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="overall wall-clock limit before force stop (s)")
    ap.add_argument("--poll", type=float, default=2.0,
                    help="seconds between log polls")
    ap.add_argument("--tail", type=int, default=80,
                    help="number of trailing log lines to print on exit")
    ap.add_argument("--stall-after", type=float, default=60.0,
                    help="don't treat a no-growth gap as a hang until this many s in")
    ap.add_argument("--stall-grace", type=float, default=25.0,
                    help="no-growth gap that counts as a hang past --stall-after "
                         "(the guest heartbeats every ~1-3s when alive, so 25s "
                         "no-growth reliably means a real wedge)")
    ap.add_argument("--no-stop", action="store_true",
                    help="leave the VM running on exit (don't vmrun stop). For "
                         "KD/WinDbg sessions where you attach a debugger.")
    ap.add_argument("--no-stall", action="store_true",
                    help="disable the stall-hang watchdog. Required for KD "
                         "sessions: a debugger break-in freezes the serial log "
                         "but the VM is not hung.")
    ap.add_argument("--no-truncate", action="store_true",
                    help="keep the existing serial log (don't wipe it at start). "
                         "Use when attaching to an already-running VM.")
    ap.add_argument("--marker", action="append", default=[], metavar="SUBSTR",
                    help="extra serial-log substring that ends the watch loop "
                         "(repeatable). E.g. --marker '[inject] hpet' to stop "
                         "watching once the guest reaches a known point.")
    ap.add_argument("--kd", action="store_true",
                    help="KD-session preset: implies --gui --no-stop --no-stall "
                         "and a long timeout. Boots the VM and watches without "
                         "ever killing it, so you can attach WinDbg/kd to the "
                         "COM2 pipe.")
    ap.add_argument("--attach-kd", metavar="CMDS", default=None,
                    help="after the watch loop, break into the guest over the "
                         "COM2 KD pipe and run these debugger commands (e.g. "
                         "'r; kb; u @rip L30; lm m nt'), capturing the output. "
                         "'.reload /f' is prepended and 'q' appended. Forces a "
                         "break-in (-b) so the guest need not be at a bugcheck. "
                         "Implies --no-stall; pair with --kd to keep the VM up.")
    ap.add_argument("--kd-timeout", type=float, default=90.0,
                    help="seconds to allow the --attach-kd capture before "
                         "killing kd (keeps partial output)")
    ap.add_argument("--kd-settle", type=float, default=5.0,
                    help="seconds to wait after the watch loop before breaking "
                         "in (lets the guest settle into its current state)")
    ap.add_argument("--kd-out", default=r"F:\02_Dev\temp\kd_capture.log",
                    help="file to save the --attach-kd capture to")
    ap.add_argument("--pipe", default=KD_PIPE,
                    help="KD named pipe path (VMware serial1)")
    ap.add_argument("--sympath", default=KD_SYMPATH,
                    help="debugger symbol path for --attach-kd")
    args = ap.parse_args()

    gui = args.gui
    no_stop = args.no_stop
    no_stall = args.no_stall
    timeout = args.timeout
    if args.kd:
        gui = True
        no_stop = True
        no_stall = True
        if timeout == 120.0:  # not overridden — KD sessions run long
            timeout = 1800.0
    # A break-in freezes the serial log; never let the stall watchdog fire
    # while we intend to attach a debugger.
    if args.attach_kd:
        no_stall = True

    # User-supplied markers extend the built-in terminal-marker set.
    for m in args.marker:
        TERMINAL_MARKERS.append((m, "custom-marker"))

    vmx = args.vmx or VMX_TARGETS[args.vm]
    return boot_cycle(vmx, gui, timeout, args.poll, args.tail,
                      args.stall_after, args.stall_grace,
                      no_stop=no_stop, no_stall=no_stall,
                      no_truncate=args.no_truncate,
                      attach_kd_cmds=args.attach_kd, kd_pipe=args.pipe,
                      kd_sympath=args.sympath, kd_timeout=args.kd_timeout,
                      kd_out=args.kd_out, kd_settle=args.kd_settle)


if __name__ == "__main__":
    sys.exit(main())
