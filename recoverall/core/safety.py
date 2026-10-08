"""The rules that keep recovery from making things worse.

* Recovered files never go onto the disk they are recovered from: every file written there could land on
  the clusters of a deleted file that is still waiting to be recovered.
* Writing a partition table or repairing a filesystem needs the disk unmounted and the user's typed
  confirmation (the disk's serial number, or its model), and everything overwritten is backed up first.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import UnsafeOperation


def disks_of_path(path: str) -> set[str]:
    """The whole disks (/dev/sdX) under the file or folder PATH: one for a plain partition, several for
    RAID/LVM, none for network or virtual filesystems."""
    p = Path(path)
    while not p.exists() and p != p.parent:
        p = p.parent
    try:
        st = os.stat(p)
    except OSError:
        return set()
    dev = st.st_rdev if stat.S_ISBLK(st.st_mode) else st.st_dev
    try:
        real = Path(f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}").resolve()
    except OSError:
        return set()
    if not real.exists():
        return set()
    out: set[str] = set()
    todo = [real]
    seen = set()
    while todo and len(seen) < 64:
        cur = todo.pop()
        if cur in seen:
            continue
        seen.add(cur)
        if (cur / "partition").exists():
            todo.append(cur.parent)
            continue
        slaves = list((cur / "slaves").glob("*")) if (cur / "slaves").exists() else []
        if slaves:
            todo.extend(s.resolve() for s in slaves)
            continue
        out.add(f"/dev/{cur.name}")
    return out


def disk_of_path(path: str) -> str | None:
    disks = sorted(disks_of_path(path))
    return disks[0] if disks else None


def whole_disks(device: str) -> set[str]:
    """The whole disks behind a device path (a partition → its disk; md/dm → their members' disks)."""
    return disks_of_path(device) if os.path.exists(device) else set()


def source_paths(spec) -> list[str]:
    """Device or file paths a source spec reads from (RAID members included)."""
    if isinstance(spec, dict):
        raid = spec.get("raid") if spec.get("raid") else (spec if spec.get("type") == "raid" else None)
        if raid:
            return [m.get("path") if isinstance(m, dict) else m for m in raid.get("members") or [] if m]
        return [spec.get("path")] if spec.get("path") else []
    return [str(spec)] if spec else []


def check_destination(source_spec, dest_dir: str) -> None:
    """Refuse to write recovered files onto a disk that is being recovered from."""
    if not dest_dir:
        raise UnsafeOperation("Choose a folder to save the recovered files in")
    dest = os.path.realpath(dest_dir)
    dest_disks = disks_of_path(dest)
    for path in source_paths(source_spec):
        if not path:
            continue
        real = os.path.realpath(path)
        try:
            st = os.stat(real)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode):
            if dest == real or dest.startswith(real + "/"):
                raise UnsafeOperation("The recovered files can't be saved inside the image file")
            continue
        src_disks = whole_disks(real)
        common = src_disks & dest_disks
        if common:
            raise UnsafeOperation(
                f"{dest_dir} is on {', '.join(sorted(common))}, the disk you are recovering from. Saving there "
                "could overwrite the very files you want back: choose a folder on another disk (a USB drive, "
                "another internal disk, or a network share).")


def mounted_on(device: str) -> list[str]:
    """Mount points of DEVICE and of everything on it (partitions, loop devices of image files on it)."""
    real = os.path.realpath(device)
    targets = {real}
    disks = whole_disks(real) if os.path.exists(real) and not os.path.isfile(real) else set()
    out = []
    try:
        with open("/proc/self/mounts", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    for line in lines:
        parts = line.split()
        if len(parts) < 2 or not parts[0].startswith("/"):
            continue
        dev = os.path.realpath(parts[0])
        mp = parts[1].replace("\\040", " ")
        if dev in targets:
            out.append(mp)
            continue
        if disks and os.path.exists(dev) and not os.path.isfile(dev):
            if whole_disks(dev) & disks:
                out.append(mp)
        elif os.path.isfile(real) and dev.startswith("/dev/loop"):
            backing = _loop_backing(dev)
            if backing and os.path.realpath(backing) == real:
                out.append(mp)
    return out


def _loop_backing(loopdev: str) -> str | None:
    name = os.path.basename(loopdev)
    try:
        return Path(f"/sys/block/{name}/loop/backing_file").read_text().strip() or None
    except OSError:
        return None


def check_unmounted(device: str, what: str = "This") -> None:
    mps = mounted_on(device)
    if mps:
        raise UnsafeOperation(f"{what} needs {device} unmounted; it is mounted on {', '.join(mps[:4])}. "
                              "Unmount it first (or eject it in your file manager).")


def confirm_token(disk: dict) -> str:
    """What the user types to confirm writing to DISK: its serial number, or its model, or its name."""
    return (disk.get("serial") or disk.get("model") or disk.get("name") or os.path.basename(disk.get("path", ""))
            or "yes").strip()


def check_confirmation(disk: dict, typed: str | None) -> None:
    if disk.get("is_image"):
        return
    want = confirm_token(disk)
    if (typed or "").strip().lower() != want.lower():
        raise UnsafeOperation(f"Type “{want}” to confirm writing to {disk.get('display_name') or disk.get('path')}")
