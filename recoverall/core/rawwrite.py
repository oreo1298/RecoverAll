"""Writing sectors safely: back up first, write synchronously, read back, and be able to undo.

Every change RecoverAll makes to a disk outside a filesystem tool (a partition table, a boot sector copied
from its backup, a FAT copied over the other) goes through here:

1. :func:`check_not_busy` refuses when the disk, or a partition on it, is mounted, used as swap, or held by
   LVM, RAID or encryption (also for image files attached to a loop device or mounted through FUSE).
2. :func:`backup_ranges` saves every byte range about to change into one file: a JSON header line (the
   device, its identity — size and a hash of its first 4 KiB, plus serial and model for real disks — and
   each range with its SHA-256), then the raw bytes.
3. :func:`write_at` writes with O_SYNC, flushes, and reads the bytes back to compare.
4. :func:`restore` (Undo) checks the backup's hashes and that it is the same disk, saves what is there now
   (so the undo can itself be undone), and writes the old bytes back.

Backups live in root's state folder (``config.backups_dir()``); they hold raw sectors of the user's disk,
so they are created readable by root only.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import time
from pathlib import Path

from .errors import RallError, UnsafeOperation
from .util import read_text, safe_name

FORMAT = "rall-raw-backup"
EXTENSION = ".rallbak"
IDENTITY_BYTES = 4096
MAX_BACKUP = 1024 * 1024 * 1024        # a backup bigger than this is a bug, not a partition table
_CHUNK = 4 * 1024 * 1024


# ---------------------------------------------------------------------- is anything using the disk?
def _unescape(field: str) -> str:
    """/proc/self/mounts escapes spaces and friends as octal (\\040)."""
    out, i = [], 0
    while i < len(field):
        if field[i] == "\\" and i + 3 < len(field) and field[i + 1:i + 4].isdigit():
            out.append(chr(int(field[i + 1:i + 4], 8)))
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def _mounts() -> list[tuple[str, str]]:
    """(source, mount point) of every mount, sources resolved to real paths."""
    out = []
    try:
        with open("/proc/self/mounts", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2:
                    src = _unescape(parts[0])
                    out.append((os.path.realpath(src) if src.startswith("/") else src, _unescape(parts[1])))
    except OSError:
        pass
    return out


def _swaps() -> set[str]:
    out = set()
    try:
        with open("/proc/swaps", encoding="utf-8", errors="replace") as fh:
            for line in fh.readlines()[1:]:
                if line.split():
                    out.add(os.path.realpath(_unescape(line.split()[0])))
    except OSError:
        pass
    return out


def _sys_block(name: str) -> Path:
    return Path("/sys/class/block") / name


def _partitions_of(name: str) -> list[tuple[str, int, int]]:
    """(name, start, size) in bytes of the kernel's partitions of the block device NAME."""
    out = []
    base = _sys_block(name)
    try:
        children = list(base.iterdir())
    except OSError:
        return out
    for child in children:
        if not (child / "partition").exists():
            continue
        start = read_text(child / "start")
        size = read_text(child / "size")
        try:
            out.append((child.name, int(start or 0) * 512, int(size or 0) * 512))
        except ValueError:
            out.append((child.name, 0, 1 << 62))
    return out


def _holders(name: str) -> list[str]:
    try:
        return sorted(p.name for p in (_sys_block(name) / "holders").iterdir())
    except OSError:
        return []


def _loops_backing(path: str) -> list[tuple[str, int]]:
    """Loop devices attached to the file PATH, with their offset."""
    real = os.path.realpath(path)
    out = []
    try:
        loops = list(Path("/sys/block").glob("loop*"))
    except OSError:
        return out
    for lp in loops:
        backing = read_text(lp / "loop" / "backing_file")
        if not backing:
            continue
        if backing.endswith(" (deleted)"):
            continue
        if os.path.realpath(backing) == real:
            try:
                off = int(read_text(lp / "loop" / "offset") or 0)
            except ValueError:
                off = 0
            out.append((lp.name, off))
    return out


def _overlaps(a: int, alen: int | None, b: int, blen: int) -> bool:
    if alen is None:
        return True
    return a < b + blen and b < a + alen


def busy_reasons(device: str, offset: int | None = None, length: int | None = None,
                 _depth: int = 0) -> list[str]:
    """Why writing [OFFSET, OFFSET+LENGTH) of DEVICE (the whole device when OFFSET is None) is unsafe now:
    plain sentences, empty when nothing uses it."""
    reasons: list[str] = []
    real = os.path.realpath(device)
    try:
        st = os.stat(real)
    except OSError as exc:
        raise RallError(f"Can't open {device}: {exc.strerror or exc}") from exc
    mounts = _mounts()
    swaps = _swaps()
    rng_off = 0 if offset is None else offset
    rng_len = None if offset is None else (length or 1)
    if stat.S_ISBLK(st.st_mode):
        name = os.path.basename(real)
        targets = [(name, 0, None)]
        for pname, pstart, psize in _partitions_of(name):
            if _overlaps(rng_off, rng_len, pstart, psize):
                targets.append((pname, pstart, psize))
        for tname, _s, _n in targets:
            dev = f"/dev/{tname}"
            for src, mnt in mounts:
                if src == dev:
                    reasons.append(f"{dev} is mounted on {mnt}")
            if dev in swaps:
                reasons.append(f"{dev} is used as swap")
            holders = _holders(tname)
            if holders:
                reasons.append(f"{dev} is in use by {', '.join(holders)} (LVM, RAID or encryption)")
    else:
        for src, mnt in mounts:
            if src == real:
                reasons.append(f"{device} is mounted on {mnt}")
        if real in swaps:
            reasons.append(f"{device} is used as a swap file")
        if _depth == 0:
            for loop, loff in _loops_backing(real):
                sub_off = None if offset is None else max(0, rng_off - loff)
                for r in busy_reasons(f"/dev/{loop}", sub_off, length, _depth + 1):
                    reasons.append(f"{r} (attached to {device})")
    return reasons


def check_not_busy(device: str, offset: int | None = None, length: int | None = None, what: str = "Writing") -> None:
    """Raise UnsafeOperation when something uses DEVICE (or the part of it that would be written)."""
    reasons = busy_reasons(device, offset, length)
    if reasons:
        raise UnsafeOperation(f"{what} was refused: {reasons[0]}. Unmount it (and stop whatever uses it) first."
                              + (f" Also: {'; '.join(reasons[1:3])}." if len(reasons) > 1 else ""))


# ---------------------------------------------------------------------- reading and identity
def device_size(path: str) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return os.lseek(fd, 0, os.SEEK_END)
    finally:
        os.close(fd)


def _read(fd: int, offset: int, length: int) -> bytes:
    out = bytearray()
    while len(out) < length:
        piece = os.pread(fd, min(_CHUNK, length - len(out)), offset + len(out))
        if not piece:
            break
        out += piece
    return bytes(out)


def _head_hash(fd: int) -> str:
    return hashlib.sha256(_read(fd, 0, IDENTITY_BYTES)).hexdigest()


def _sys_identity(path: str) -> dict:
    """Serial and model of a real disk (its partition's disk for a partition), when the kernel knows them."""
    real = os.path.realpath(path)
    try:
        if not stat.S_ISBLK(os.stat(real).st_mode):
            return {}
    except OSError:
        return {}
    base = _sys_block(os.path.basename(real))
    if (base / "partition").exists():
        base = base.resolve().parent
    out = {}
    for key, rel in (("serial", "device/serial"), ("model", "device/model"), ("wwid", "device/wwid"),
                     ("serial", "serial")):
        v = read_text(base / rel)
        if v and key not in out:
            out[key] = " ".join(v.split())
    return out


def identity(path: str) -> dict:
    """What tells this disk apart from another one: size, hash of the first 4 KiB, serial and model."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
        head = _head_hash(fd)
    finally:
        os.close(fd)
    return {"size": size, "head_sha256": head, **_sys_identity(path)}


# ---------------------------------------------------------------------- backups
def _merge_ranges(ranges, size: int) -> list[tuple[int, int]]:
    rs = []
    for off, n in ranges:
        off, n = int(off), int(n)
        if n <= 0 or off >= size:
            continue
        off = max(0, off)
        n = min(n, size - off)
        rs.append((off, off + n))
    rs.sort()
    out: list[list[int]] = []
    for s, e in rs:
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [(s, e - s) for s, e in out]


def _write_file(path: Path, header: dict, payload_parts) -> None:
    """Write a backup file atomically (temporary file in the same folder, fsync, rename), root-only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=EXTENSION, dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), 0o600)
            fh.write(json.dumps(header, sort_keys=True).encode() + b"\n")
            for part in payload_parts:
                fh.write(part)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def backup_ranges(device_path: str, ranges, backup_dir: str, label: str) -> str:
    """Save the bytes of RANGES ([(offset, length)], merged and clipped to the device) of DEVICE_PATH into a
    new backup file in BACKUP_DIR; returns its path. Nothing is written to the device."""
    fd = os.open(device_path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
        merged = _merge_ranges(ranges, size)
        if not merged:
            raise RallError("Nothing to back up: the ranges are outside the device")
        total = sum(n for _o, n in merged)
        if total > MAX_BACKUP:
            raise RallError(f"Refusing to back up {total} bytes at once")
        blobs, entries = [], []
        for off, n in merged:
            data = _read(fd, off, n)
            if len(data) != n:
                raise RallError(f"Couldn't read {n} bytes at offset {off} of {device_path} for the backup")
            blobs.append(data)
            entries.append({"offset": off, "length": n, "sha256": hashlib.sha256(data).hexdigest()})
        ident = {"size": size, "head_sha256": _head_hash(fd), **_sys_identity(device_path)}
    finally:
        os.close(fd)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    name = f"{safe_name(os.path.basename(device_path))}-{safe_name(label, 40)}-{stamp}"
    folder = Path(backup_dir)
    path = folder / f"{name}{EXTENSION}"
    n = 1
    while path.exists():
        n += 1
        path = folder / f"{name}-{n}{EXTENSION}"
    header = {"format": FORMAT, "version": 1, "device": os.path.abspath(device_path), "label": label,
              "created": time.time(), "identity": ident, "ranges": entries, "after": None}
    _write_file(path, header, blobs)
    return str(path)


def read_backup(path: str, with_data: bool = True) -> tuple[dict, list[bytes]]:
    """The header of a backup file and (WITH_DATA) the saved bytes of each range, checked against their
    hashes. Raises RallError for a file that isn't a backup or is damaged."""
    try:
        with open(path, "rb") as fh:
            line = fh.readline(1024 * 1024)
            try:
                header = json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise RallError(f"{path} is not a RecoverAll backup") from exc
            if not isinstance(header, dict) or header.get("format") != FORMAT:
                raise RallError(f"{path} is not a RecoverAll backup")
            blobs = []
            if with_data:
                for r in header.get("ranges") or []:
                    data = fh.read(int(r["length"]))
                    if len(data) != int(r["length"]) or hashlib.sha256(data).hexdigest() != r.get("sha256"):
                        raise RallError(f"The backup {os.path.basename(path)} is damaged (its saved data doesn't "
                                        "match its checksums)")
                    blobs.append(data)
    except OSError as exc:
        raise RallError(f"Can't read {path}: {exc.strerror or exc}") from exc
    return header, blobs


def note_written(backup_path: str) -> None:
    """Record, in the backup, what the device looks like after the change (its first 4 KiB and the new
    content of every range): Undo then knows it is still the same disk even when the change touched the
    sectors that identify it."""
    header, blobs = read_backup(backup_path)
    device = header["device"]
    fd = os.open(device, os.O_RDONLY | os.O_CLOEXEC)
    try:
        after = {"head_sha256": _head_hash(fd), "ranges": [
            hashlib.sha256(_read(fd, int(r["offset"]), int(r["length"]))).hexdigest() for r in header["ranges"]],
            "time": time.time()}
    finally:
        os.close(fd)
    header["after"] = after
    _write_file(Path(backup_path), header, blobs)


def list_backups(backup_dir: str) -> list[dict]:
    """The backups in BACKUP_DIR, newest first: path, device, label, created, ranges, bytes, size."""
    out = []
    try:
        files = list(Path(backup_dir).glob(f"*{EXTENSION}"))
    except OSError:
        return out
    for f in files:
        if f.name.startswith(".tmp-"):
            continue
        try:
            header, _ = read_backup(str(f), with_data=False)
        except RallError:
            continue
        ranges = header.get("ranges") or []
        out.append({"path": str(f), "device": header.get("device"), "label": header.get("label") or "",
                    "created": header.get("created"), "ranges": len(ranges),
                    "bytes": sum(int(r.get("length") or 0) for r in ranges),
                    "size": (header.get("identity") or {}).get("size"), "written": bool(header.get("after"))})
    out.sort(key=lambda d: d.get("created") or 0, reverse=True)
    return out


# ---------------------------------------------------------------------- writing
def reread_partitions(device: str) -> None:
    """Tell the kernel a whole disk's partition table changed (best effort; nothing to do for files)."""
    real = os.path.realpath(device)
    try:
        if not stat.S_ISBLK(os.stat(real).st_mode) or (_sys_block(os.path.basename(real)) / "partition").exists():
            return
    except OSError:
        return
    from .util import run
    rr = run(["partx", "-u", real], timeout=60)
    if not rr.ok:
        run(["blockdev", "--rereadpt", real], timeout=60)
    run(["udevadm", "settle", "--timeout=10"], timeout=20)


def write_at(device_path: str, offset: int, data: bytes, verify: bool = True) -> None:
    """Write DATA at OFFSET of DEVICE_PATH synchronously and read it back. Never extends a file: writing
    past the end of the device is refused."""
    if offset < 0:
        raise RallError("Negative offset")
    fd = os.open(device_path, os.O_RDWR | os.O_SYNC | os.O_CLOEXEC)
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
        if offset + len(data) > size:
            raise RallError(f"Refusing to write past the end of {device_path}")
        mv = memoryview(data)
        done = 0
        while done < len(data):
            n = os.pwrite(fd, mv[done:done + _CHUNK], offset + done)
            if n <= 0:
                raise RallError(f"Writing to {device_path} failed at offset {offset + done}")
            done += n
        os.fsync(fd)
        if verify:
            pos = 0
            while pos < len(data):
                n = min(_CHUNK, len(data) - pos)
                if os.pread(fd, n, offset + pos) != bytes(mv[pos:pos + n]):
                    raise RallError(f"What was written at offset {offset + pos} of {device_path} doesn't read back "
                                    "the same: the disk may be failing")
                pos += n
    except OSError as exc:
        raise RallError(f"Writing to {device_path} failed: {exc.strerror or exc}") from exc
    finally:
        os.close(fd)


def restore(backup_path: str, device_path: str | None = None, verify_identity: bool = True) -> dict:
    """Undo: write the saved bytes of BACKUP_PATH back to its device (or DEVICE_PATH). What is there now is
    saved first, next to the backup. Refused when the disk is in use, or (VERIFY_IDENTITY) when it doesn't
    look like the disk the backup was made of."""
    header, blobs = read_backup(backup_path)
    device = device_path or header["device"]
    check_not_busy(device, what="Undo")
    ident = header.get("identity") or {}
    if verify_identity:
        now = identity(device)
        if int(ident.get("size") or -1) != now["size"]:
            raise UnsafeOperation(f"{device} isn't the disk this backup was made of (its size differs)")
        for key in ("serial", "wwid"):
            if ident.get(key) and now.get(key) and ident[key] != now[key]:
                raise UnsafeOperation(f"{device} isn't the disk this backup was made of (its {key} differs)")
        known = {ident.get("head_sha256"), (header.get("after") or {}).get("head_sha256")}
        if now["head_sha256"] not in known:
            raise UnsafeOperation(f"The start of {device} changed since this backup was made (something else "
                                  "was written there): Undo was refused so it doesn't destroy newer data")
    ranges = [(int(r["offset"]), int(r["length"])) for r in header["ranges"]]
    folder = os.path.dirname(os.path.abspath(backup_path))
    current = backup_ranges(device, ranges, folder, f"before-undo-{header.get('label') or 'change'}")
    for (off, _n), data in zip(ranges, blobs):
        write_at(device, off, data)
    try:
        note_written(current)
    except RallError:
        pass
    reread_partitions(device)
    return {"ok": True, "device": device, "restored": [list(r) for r in ranges],
            "bytes": sum(n for _o, n in ranges), "backup": current, "restored_from": backup_path}
