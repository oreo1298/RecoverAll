"""Formatting, sizes and small system helpers used everywhere (no Qt)."""

from __future__ import annotations

import os
import re
import select
import shutil
import signal
import subprocess
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

KB, MB, GB, TB = 1000, 1000 ** 2, 1000 ** 3, 1000 ** 4
KiB, MiB, GiB, TiB = 1024, 1024 ** 2, 1024 ** 3, 1024 ** 4

# fsck, sfdisk, losetup and friends live in sbin, which isn't on every user's PATH (Debian).
_EXTRA_PATHS = ("/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin", "/bin")

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def which(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for d in _EXTRA_PATHS:
        p = Path(d) / name
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return None


def _env(extra: dict | None = None) -> dict:
    env = dict(os.environ)
    env.update({"LC_ALL": "C", "LANG": "C"})
    path = env.get("PATH", "")
    for d in _EXTRA_PATHS:
        if d not in path.split(":"):
            path = f"{path}:{d}" if path else d
    env["PATH"] = path
    if extra:
        env.update(extra)
    return env


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    missing: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def error_text(self, limit: int = 600) -> str:
        text = (self.stderr or "").strip() or (self.stdout or "").strip()
        return text[-limit:] if text else f"exit status {self.returncode}"


def run(cmd: list[str], timeout: float = 60.0, input_text: str | None = None,
        env: dict | None = None) -> RunResult:
    """Run a command without a shell. Never raises for the command failing, timing out or missing."""
    exe = which(cmd[0]) if not os.path.isabs(cmd[0]) else cmd[0]
    if exe is None:
        return RunResult(127, "", f"{cmd[0]}: not found", missing=True)
    try:
        proc = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, timeout=timeout,
                              input=input_text, env=_env(env), errors="replace",
                              stdin=None if input_text is not None else subprocess.DEVNULL)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return RunResult(124, out, f"{cmd[0]}: timed out after {timeout:g} s", timed_out=True)
    except OSError as exc:
        return RunResult(126, "", f"{cmd[0]}: {exc.strerror or exc}")
    return RunResult(proc.returncode, proc.stdout, proc.stderr)


def detach_loop(loop: str, timeout: float = 5.0) -> bool:
    """Detach the loop device LOOP and wait until it is gone. While something still has it open (udev probes
    every new loop device; a tool that used it may still be exiting) losetup -d either fails, or succeeds and
    the kernel only detaches it at the last close, so it stays attached for a moment."""
    backing = f"/sys/block/{os.path.basename(loop)}/loop/backing_file"
    end = time.monotonic() + timeout
    detached = False
    while True:
        if not detached:
            rr = run(["losetup", "-d", loop], timeout=30)
            if rr.missing:
                return False
            detached = rr.ok or "No such device" in rr.stderr
        if detached and not os.path.exists(backing):
            return True
        if time.monotonic() > end:
            return False
        time.sleep(0.1)


def stream(cmd: list[str], on_line: Callable[[str], None] | None = None,
           cancelled: Callable[[], bool] | None = None, input_text: str | None = None,
           env: dict | None = None, timeout: float | None = None, kill_grace: float = 15.0) -> RunResult:
    """Run a long command, handing every output line (split on CR and LF, ANSI codes removed) to
    ``on_line`` as it arrives. ``cancelled()`` is polled; when it turns true the process group gets
    SIGTERM (ddrescue saves its mapfile), then SIGKILL after ``kill_grace`` seconds.

    stdout and stderr are merged; the result's ``stdout`` holds the last 200 lines.
    """
    exe = which(cmd[0]) if not os.path.isabs(cmd[0]) else cmd[0]
    if exe is None:
        return RunResult(127, "", f"{cmd[0]}: not found", missing=True)
    try:
        proc = subprocess.Popen([exe, *cmd[1:]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                                env=_env(env), start_new_session=True)
    except OSError as exc:
        return RunResult(126, "", f"{cmd[0]}: {exc.strerror or exc}")
    if input_text is not None:
        try:
            proc.stdin.write(input_text.encode())
            proc.stdin.close()
        except OSError:
            pass
    tail: deque[str] = deque(maxlen=200)
    buf = b""
    fd = proc.stdout.fileno()
    start = time.monotonic()
    killed_at: float | None = None
    timed_out = False

    def emit(raw: bytes) -> None:
        line = _ANSI.sub("", raw.decode(errors="replace")).rstrip()
        if not line.strip():
            return
        tail.append(line)
        if on_line is not None:
            on_line(line)

    while True:
        if killed_at is None and ((cancelled is not None and cancelled()) or
                                  (timeout is not None and time.monotonic() - start > timeout)):
            timed_out = not (cancelled is not None and cancelled())
            _signal_group(proc, signal.SIGTERM)
            killed_at = time.monotonic()
        elif killed_at is not None and time.monotonic() - killed_at > kill_grace and proc.poll() is None:
            _signal_group(proc, signal.SIGKILL)
        ready, _, _ = select.select([fd], [], [], 0.25)
        if ready:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            buf += chunk
            parts = re.split(rb"[\r\n]", buf)
            buf = parts.pop()
            for part in parts:
                emit(part)
        elif proc.poll() is not None:
            # drain whatever is left
            rest = proc.stdout.read() or b""
            buf += rest
            break
    for part in re.split(rb"[\r\n]", buf):
        emit(part)
    proc.stdout.close()
    code = proc.wait()
    out = "\n".join(tail)
    if timed_out:
        return RunResult(124, out, f"{cmd[0]}: timed out", timed_out=True)
    return RunResult(code, out, "" if code == 0 else out)


def _signal_group(proc: subprocess.Popen, sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError):
        try:
            proc.send_signal(sig)
        except ProcessLookupError:
            pass


def read_text(path: str | Path, default: str | None = None) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return default


def read_int(path: str | Path, default: int | None = None) -> int | None:
    text = read_text(path)
    if not text:
        return default
    try:
        return int(text.split()[0])
    except (ValueError, IndexError):
        return default


def clean(text: str | None) -> str:
    """Collapse runs of whitespace (sysfs and SCSI INQUIRY strings are space padded)."""
    if not text:
        return ""
    return " ".join(str(text).replace("\x00", " ").replace("\\x20", " ").split())


def safe_name(text: str, limit: int = 80) -> str:
    """A string usable in a file name."""
    name = re.sub(r"[^A-Za-z0-9._+-]+", "_", text.strip()).strip("._")
    return name[:limit] or "disk"


_BAD_FILE_CHARS = re.compile(r'[\x00-\x1f/]')


def safe_filename(name: str, limit: int = 240) -> str:
    """A recovered file's name made safe for any Linux filesystem: no slashes or control characters, not
    "." or "..", at most LIMIT bytes in UTF-8 (the extension is kept when shortening)."""
    name = _BAD_FILE_CHARS.sub("_", name or "").strip()
    if name in ("", ".", ".."):
        name = "_" + name.strip(".") if name else "unnamed"
    if len(name.encode("utf-8", "surrogateescape")) <= limit:
        return name
    stem, dot, ext = name.rpartition(".")
    if not dot or len(ext) > 16:
        stem, ext = name, ""
    ext = ("." + ext) if ext else ""
    budget = limit - len(ext.encode("utf-8", "surrogateescape"))
    out = stem.encode("utf-8", "surrogateescape")[:budget].decode("utf-8", "ignore")
    return out + ext


# ---------------------------------------------------------------------- sizes
def align_up(n: int, a: int) -> int:
    return -(-n // a) * a


def align_down(n: int, a: int) -> int:
    return (n // a) * a


_SIZE = re.compile(r"^\s*([0-9]+(?:\.[0-9]*)?)\s*([kKmMgGtTpP]?)(i?)([bB]?)\s*$")


def parse_size(text: str | int | float, default_unit: str = "") -> int:
    """'100G' / '100 GB' → 100·10⁹; '100GiB' / '100Gi' → 100·2³⁰; plain numbers are bytes
    (or ``default_unit``). Raises ValueError."""
    if isinstance(text, (int, float)):
        return int(text)
    m = _SIZE.match(text)
    if not m:
        raise ValueError(f"not a size: {text!r}")
    value, unit, binary, _b = m.groups()
    unit = unit or default_unit
    if not unit:
        return int(float(value))
    power = "kmgtp".index(unit.lower()) + 1
    base = 1024 if binary else 1000
    return int(float(value) * base ** power)


# ---------------------------------------------------------------------- formatting
def _thin(n: float, digits: int) -> str:
    return f"{n:,.{digits}f}".replace(",", " ")


def fmt_bytes(n: float | None, binary: bool = False, digits: int | None = None) -> str:
    """2.00 TB, 512 GB, 31.9 MB  (binary: 1.82 TiB)."""
    if n is None:
        return "—"
    n = float(n)
    base = 1024.0 if binary else 1000.0
    units = (["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"] if binary
             else ["B", "kB", "MB", "GB", "TB", "PB", "EB"])
    i = 0
    while abs(n) >= base and i < len(units) - 1:
        n /= base
        i += 1
    if i == 0:
        return f"{int(n)} B"
    if digits is None:
        digits = 2 if abs(n) < 10 else (1 if abs(n) < 100 else 0)
    return f"{n:.{digits}f} {units[i]}"


def fmt_capacity(n: int | None) -> str:
    """Capacity the way vendors print it: 2 TB, 500 GB, 256 GB, 15.5 GB."""
    if not n:
        return "—"
    for unit, size in (("TB", TB), ("GB", GB), ("MB", MB)):
        if n >= size * 0.995:
            v = n / size
            if abs(v - round(v)) < 0.02 * max(1.0, v / 10):
                return f"{round(v):d} {unit}"
            return f"{v:.1f} {unit}" if v < 100 else f"{v:.0f} {unit}"
    return fmt_bytes(n)


def fmt_rate(bps: float | None) -> str:
    if bps is None:
        return "—"
    if bps >= GB:
        return f"{bps / GB:.2f} GB/s"
    v = bps / MB
    return f"{_thin(v, 2 if v < 10 else (1 if v < 100 else 0))} MB/s"


def fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    s = int(max(0, seconds))
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d} d {h} h"
    if h:
        return f"{h} h {m:02d} min"
    if m:
        return f"{m} min {s:02d} s"
    return f"{s} s"


def fmt_int(n: float | None) -> str:
    return "—" if n is None else _thin(n, 0)


def fmt_when(ts: float | None) -> str:
    if not ts:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


# ---------------------------------------------------------------------- the user behind pkexec / sudo
def caller_ids() -> tuple[int, int] | None:
    """The (uid, gid) of the desktop user who started us through pkexec or sudo, if any."""
    for var in ("PKEXEC_UID", "SUDO_UID"):
        value = os.environ.get(var)
        if value and value.isdigit() and int(value) != 0:
            uid = int(value)
            gid = os.environ.get("SUDO_GID")
            if gid and gid.isdigit():
                return uid, int(gid)
            try:
                import pwd
                return uid, pwd.getpwuid(uid).pw_gid
            except (KeyError, ImportError):
                return uid, uid
    return None


def give_to_caller(path: str | Path) -> None:
    """Files root writes into a user's folder (recovered files, images, mapfiles) should belong to that user."""
    ids = caller_ids()
    if ids is None or os.geteuid() != 0:
        return
    try:
        # only in folders that belong to the user (their home, a stick mounted for them), not /mnt/backups
        if os.stat(Path(path).resolve().parent).st_uid != ids[0]:
            return
        os.chown(path, *ids)
    except OSError:
        pass
