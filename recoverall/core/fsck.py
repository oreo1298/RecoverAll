"""Checking and repairing filesystems with the distribution's own tools.

RecoverAll reads damaged filesystems by itself, but putting one back in order — so that it mounts again —
is the job of the filesystem's own checker: e2fsck, fsck.fat, fsck.exfat, ntfsfix, xfs_repair, btrfs
check/rescue, fsck.hfsplus, fsck.f2fs (and jfs_fsck, reiserfsck when installed). This module knows, for each
filesystem, which actions those tools offer, how risky each one is, which package has the program on each
distribution family, and how to read what the program says (exit codes and messages) into a plain answer.

Risk levels:

======  ==============================================================================================
safe    a read-only check: nothing is written
normal  a repair: the usual fixes; damaged files may end up in lost+found (or FSCK*.REC on FAT)
risky   a last resort that may lose data (zeroing a log, rebuilding trees): recover the files first
======  ==============================================================================================

Nothing runs on a mounted filesystem, not even a check: a mounted filesystem changes under the checker,
which then reports damage that isn't there (and a repair would really cause some). Image files are checked
in place — every tool here accepts a regular file — except for the few that only work on block devices,
which get a loop device (read-only for checks).

Recover the files you need *before* repairing: a repair rewrites the metadata that RecoverAll uses to find
deleted files, and what a repair "fixes" by clearing it is gone.
"""

from __future__ import annotations

import contextlib
import errno
import os
import re
import shlex
import stat
import struct
from collections import deque
from pathlib import Path

from .errors import Cancelled, NotPermitted, NotSupported, RallError, ToolMissing, UnsafeOperation
from .fs.base import NULL_CONTROL, Control
from .util import detach_loop, read_text, run, stream, which

RISKS = ("safe", "normal", "risky")
RISK_NAMES = {"safe": "Read-only", "normal": "Repair", "risky": "Last resort"}

# fstype (as blkid or the probes name it) → action family
FAMILY = {"ext2": "ext", "ext3": "ext", "ext4": "ext", "ext4dev": "ext", "ext": "ext",
          "vfat": "fat", "fat": "fat", "fat12": "fat", "fat16": "fat", "fat32": "fat", "msdos": "fat",
          "exfat": "exfat", "ntfs": "ntfs", "ntfs3": "ntfs", "xfs": "xfs", "btrfs": "btrfs",
          "hfsplus": "hfsplus", "hfs+": "hfsplus", "f2fs": "f2fs", "jfs": "jfs", "reiserfs": "reiserfs"}
FS_NAMES = {"ext": "ext", "fat": "FAT", "exfat": "exFAT", "ntfs": "NTFS", "xfs": "XFS", "btrfs": "Btrfs",
            "hfsplus": "HFS+", "f2fs": "F2FS", "jfs": "JFS", "reiserfs": "ReiserFS"}

# program → package per distribution family
PACKAGES: dict[str, dict[str, str]] = {
    "e2fsck": dict.fromkeys(("arch", "debian", "fedora", "opensuse"), "e2fsprogs"),
    "fsck.fat": dict.fromkeys(("arch", "debian", "fedora", "opensuse"), "dosfstools"),
    "fsck.exfat": dict.fromkeys(("arch", "debian", "fedora", "opensuse"), "exfatprogs"),
    "ntfsfix": {"arch": "ntfs-3g", "debian": "ntfs-3g", "fedora": "ntfsprogs", "opensuse": "ntfsprogs"},
    "xfs_repair": dict.fromkeys(("arch", "debian", "fedora", "opensuse"), "xfsprogs"),
    "btrfs": {"arch": "btrfs-progs", "debian": "btrfs-progs", "fedora": "btrfs-progs", "opensuse": "btrfsprogs"},
    "fsck.hfsplus": {"arch": "hfsprogs (AUR)", "debian": "hfsprogs", "fedora": "hfsplus-tools",
                     "opensuse": "hfsplus-tools"},
    "fsck.f2fs": dict.fromkeys(("arch", "debian", "fedora", "opensuse"), "f2fs-tools"),
    "jfs_fsck": dict.fromkeys(("arch", "debian", "fedora", "opensuse"), "jfsutils"),
    "reiserfsck": {"arch": "reiserfsprogs", "debian": "reiserfsprogs", "fedora": "reiserfs-utils",
                   "opensuse": "reiserfs"},
    "losetup": {"arch": "util-linux", "debian": "mount", "fedora": "util-linux", "opensuse": "util-linux"},
}
FAMILY_NAMES = {"arch": "Arch", "debian": "Debian/Ubuntu", "fedora": "Fedora", "opensuse": "openSUSE"}

_NTFS_NOTE = ("ntfsfix only fixes the most common problems and asks Windows to check the volume at its next "
              "start; a full NTFS repair needs Windows chkdsk (chkdsk /f).")


def _a(id: str, title: str, detail: str, risk: str, program: str, args: list[str], tool: str,
       writes: bool = True, **more) -> dict:
    return {"id": id, "title": title, "detail": detail, "risk": risk, "program": program, "args": args,
            "tool": tool, "writes": writes, **more}


# Every action: what the user sees (title, detail, risk) and how to run it. "{device}" is the filesystem
# (device or image file); "{superblock}"/"{block_size}" are asked for (or found) for ext backups.
ACTIONS: dict[str, list[dict]] = {
    "ext": [
        _a("check", "Check (read-only)",
           "Checks the whole filesystem and lists what is wrong. Nothing is written.",
           "safe", "e2fsck", ["-f", "-n", "{device}"], "e2fsck", writes=False),
        _a("repair", "Repair safe problems",
           "Fixes what e2fsck can fix without a decision (counts, bitmaps, checksums). It stops when a fix "
           "would need one: then use “Repair everything”.",
           "normal", "e2fsck", ["-f", "-p", "{device}"], "e2fsck"),
        _a("repair_all", "Repair everything",
           "Answers yes to every question e2fsck asks. Files whose folder is lost go to lost+found; badly "
           "damaged files may be cleared.",
           "normal", "e2fsck", ["-f", "-y", "{device}"], "e2fsck"),
        _a("backup_superblock", "Repair using a backup superblock",
           "When the main superblock is damaged and the filesystem can't be opened: e2fsck starts from a "
           "backup copy (found automatically, or the one you give), repairs everything and writes the main "
           "superblock back. The backup is older, so recent changes to the counts are redone.",
           "normal", "e2fsck", ["-f", "-y", "-b", "{superblock}", "-B", "{block_size}", "{device}"], "e2fsck",
           needs=["superblock", "block_size"]),
    ],
    "fat": [
        _a("check", "Check (read-only)",
           "Checks the boot sector, both copies of the FAT and every folder. Nothing is written.",
           "safe", "fsck.fat", ["-n", "-v", "{device}"], "fat", writes=False),
        _a("repair", "Repair",
           "Fixes the FAT and the folders automatically: lost chains are freed, wrong file sizes corrected, "
           "the second FAT made equal to the first.",
           "normal", "fsck.fat", ["-a", "-w", "{device}"], "fat"),
        _a("salvage", "Repair and keep lost data",
           "Like Repair, but saves lost cluster chains as FSCK0000.REC files in the root folder instead of "
           "freeing them: pieces of files whose entries are gone.",
           "normal", "fsck.fat", ["-a", "-w", "-f", "{device}"], "fat"),
        _a("verify", "Repair and verify",
           "Repairs, then checks the filesystem a second time to confirm that nothing is left.",
           "normal", "fsck.fat", ["-y", "-w", "-V", "{device}"], "fat"),
    ],
    "exfat": [
        _a("check", "Check (read-only)",
           "Checks the boot region, the allocation bitmap and every folder. Nothing is written.",
           "safe", "fsck.exfat", ["-n", "{device}"], "exfat", writes=False),
        _a("repair", "Repair",
           "Fixes what fsck.exfat finds, answering yes to every question (a damaged boot region is restored "
           "from its backup copy).",
           "normal", "fsck.exfat", ["-y", "{device}"], "exfat"),
        _a("restore_boot", "Restore the boot sector from its backup",
           "For a card or stick that says it isn't formatted: when the boot sector is gone, exFAT's backup "
           "boot region (sectors 12–23) is copied back and the filesystem repaired.",
           "normal", "fsck.exfat", ["-b", "-y", "{device}"], "exfat", requires_option="-b"),
    ],
    "ntfs": [
        _a("check", "Check (read-only)",
           "Checks the boot sectors, $MFT and its mirror and the journal state. Nothing is written. "
           + _NTFS_NOTE,
           "safe", "ntfsfix", ["-n", "{device}"], "ntfsfix", writes=False),
        _a("repair", "Fix common problems",
           "Repairs $MFTMirr from $MFT, fixes the boot sector, empties the journal ($LogFile) so Linux can "
           "mount the volume, and marks it for chkdsk. " + _NTFS_NOTE,
           "normal", "ntfsfix", ["{device}"], "ntfsfix"),
        _a("clear_dirty", "Clear the “dirty” flag",
           "Fixes the common problems, then clears the flag that makes Windows run chkdsk and some Linux "
           "drivers refuse to mount. Only when Windows isn't available to run chkdsk.",
           "normal", "ntfsfix", ["-d", "{device}"], "ntfsfix"),
        _a("clear_badsectors", "Clear the bad-sector list",
           "Empties $BadClus, the list of clusters NTFS never uses. For a volume copied from a failing disk "
           "onto a healthy one (the bad sectors stayed behind).",
           "normal", "ntfsfix", ["-b", "{device}"], "ntfsfix"),
    ],
    "xfs": [
        _a("check", "Check (read-only)",
           "Checks every allocation group, the inodes and the folders. Nothing is written.",
           "safe", "xfs_repair", ["-n", "{device}"], "xfs", writes=False),
        _a("repair", "Repair",
           "Rebuilds the allocation trees and fixes inodes and folders; disconnected files go to lost+found. "
           "Refuses if the journal holds changes: mount and unmount the filesystem once to replay it.",
           "normal", "xfs_repair", ["{device}"], "xfs"),
        _a("zero_log", "Repair and discard the journal",
           "When the journal can't be replayed (the filesystem won't mount): throws the journal away and "
           "repairs. Changes that were only in the journal are lost; files written just before the crash "
           "may be damaged.",
           "risky", "xfs_repair", ["-L", "{device}"], "xfs"),
    ],
    "btrfs": [
        _a("check", "Check (read-only)",
           "Checks every tree of the filesystem. Nothing is written.",
           "safe", "btrfs", ["check", "--readonly", "{device}"], "btrfs-check", writes=False),
        _a("super_recover", "Restore the superblock from a copy",
           "When the main superblock is damaged: copies a good superblock copy over the bad ones.",
           "normal", "btrfs", ["rescue", "super-recover", "-y", "{device}"], "btrfs-super"),
        _a("zero_log", "Clear the log tree",
           "When mounting fails while replaying the log tree (after a crash): clears it. The last few "
           "seconds of writes before the crash are lost.",
           "normal", "btrfs", ["rescue", "zero-log", "{device}"], "btrfs-zero-log"),
        _a("chunk_recover", "Rebuild the chunk tree",
           "When the chunk tree is damaged: reads the whole device to find the chunks again. Slow (hours on "
           "a big disk).",
           "risky", "btrfs", ["rescue", "chunk-recover", "-y", "{device}"], "btrfs-rescue"),
        _a("repair", "Repair (btrfs check --repair)",
           "btrfs check --repair. The Btrfs developers warn that it can make things worse: copy your files "
           "off first (RecoverAll, or mount with -o ro,rescue=all), and use it only when nothing else works. "
           "It waits 10 seconds before starting.",
           "risky", "btrfs", ["check", "--repair", "{device}"], "btrfs-check"),
    ],
    "hfsplus": [
        _a("check", "Check (read-only)",
           "Checks the catalog, the extents and attributes files and the volume bitmap. Nothing is written.",
           "safe", "fsck.hfsplus", ["-f", "-n", "{device}"], "hfsplus", writes=False),
        _a("repair", "Repair",
           "Fixes what fsck.hfsplus finds, answering yes to every question.",
           "normal", "fsck.hfsplus", ["-f", "-y", "{device}"], "hfsplus"),
        _a("rebuild_catalog", "Rebuild the catalog",
           "Rebuilds the catalog B-tree (the folder structure) from its leaf records. For a catalog the "
           "normal repair can't fix; entries in damaged nodes are lost.",
           "risky", "fsck.hfsplus", ["-f", "-y", "-r", "{device}"], "hfsplus"),
    ],
    "f2fs": [
        _a("check", "Check (read-only)",
           "Checks the checkpoints, the node and segment tables and every file. Nothing is written.",
           "safe", "fsck.f2fs", ["--dry-run", "{device}"], "f2fs", writes=False),
        _a("repair", "Repair",
           "Checks everything and fixes what it finds.",
           "normal", "fsck.f2fs", ["-f", "{device}"], "f2fs"),
    ],
    "jfs": [
        _a("check", "Check (read-only)",
           "Checks the filesystem without replaying the journal. Nothing is written.",
           "safe", "jfs_fsck", ["-n", "{device}"], "fsck", writes=False, block_only=True),
        _a("repair", "Repair",
           "Replays the journal, then checks and repairs everything.",
           "normal", "jfs_fsck", ["-f", "{device}"], "fsck", block_only=True),
    ],
    "reiserfs": [
        _a("check", "Check (read-only)",
           "Checks the tree and the bitmaps. Nothing is written.",
           "safe", "reiserfsck", ["--check", "--yes", "{device}"], "fsck", writes=False, block_only=True,
           input="Yes\n"),
        _a("repair", "Fix what can be fixed",
           "Fixes the problems reiserfsck can fix without rebuilding the tree.",
           "normal", "reiserfsck", ["--fix-fixable", "--yes", "{device}"], "fsck", block_only=True,
           input="Yes\n"),
        _a("rebuild_tree", "Rebuild the tree",
           "Rebuilds the whole tree from the leaves found on the disk. Files may come back in lost+found, "
           "old deleted files may reappear, and an interruption leaves the filesystem unusable.",
           "risky", "reiserfsck", ["--rebuild-tree", "--yes", "{device}"], "fsck", block_only=True,
           input="Yes\n"),
    ],
}


# ---------------------------------------------------------------------- distributions and packages
_DISTRO: list[str] = []


def distro_family() -> str:
    """"arch", "debian", "fedora", "opensuse", or "" (from /etc/os-release ID and ID_LIKE)."""
    if _DISTRO:
        return _DISTRO[0]
    text = read_text("/etc/os-release", "") or ""
    ids: list[str] = []
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key in ("ID", "ID_LIKE"):
            ids += value.strip().strip('"').lower().split()
    family = ""
    for i in ids:
        if i in ("arch", "manjaro", "endeavouros", "cachyos", "garuda", "artix"):
            family = "arch"
        elif i in ("debian", "ubuntu", "linuxmint", "pop", "raspbian", "kali", "elementary", "zorin"):
            family = "debian"
        elif i in ("fedora", "rhel", "centos", "rocky", "almalinux", "nobara"):
            family = "fedora"
        elif i.startswith("opensuse") or i in ("suse", "sles", "sled"):
            family = "opensuse"
        if family:
            break
    _DISTRO.append(family)
    return family


def package_for(program: str, family: str | None = None) -> str:
    """The package with PROGRAM on this system's distribution, or a hint naming the differences."""
    names = PACKAGES.get(program)
    if not names:
        return program
    family = distro_family() if family is None else family
    if family in names:
        return names[family]
    values = list(names.values())
    common = max(values, key=values.count)       # the first of the most common names
    others = [f"{FAMILY_NAMES[f]}: {p}" for f, p in names.items() if p != common]
    return common + (f" ({'; '.join(others)})" if others else "")


# ---------------------------------------------------------------------- what can run here
def family_of(fstype: str | None) -> str:
    return FAMILY.get((fstype or "").lower(), "")


_HELP: dict[str, str] = {}


def _help_text(program: str) -> str:
    if program not in _HELP:
        rr = run([program, "--help"], timeout=15)
        _HELP[program] = (rr.stdout or "") + (rr.stderr or "")
    return _HELP[program]


def _supports(program: str, option: str) -> bool:
    """The installed PROGRAM lists OPTION in its --help (exfatprogs gained -b in 1.2.0)."""
    return re.search(rf"(^|[\s|,\[]){re.escape(option)}\b", _help_text(program), re.M) is not None


def _find(fstype: str, action_id: str) -> tuple[str, dict]:
    fam = family_of(fstype)
    if not fam:
        raise NotSupported(f"RecoverAll can't check or repair {fstype or 'this'} filesystems")
    for spec in ACTIONS[fam]:
        if spec["id"] == action_id:
            return fam, spec
    raise NotSupported(f"Unknown action “{action_id}” for {FS_NAMES[fam]}")


def actions_for(fstype: str | None) -> list[dict]:
    """The actions for FSTYPE, for the UI: each with "available" and, when it isn't, "missing_program" and
    "package" (what to install), or "unavailable" (why not, e.g. an exfatprogs without -b)."""
    fam = family_of(fstype)
    out = []
    for spec in ACTIONS.get(fam, []):
        a = {k: v for k, v in spec.items() if k not in ("args", "input")}
        a["fstype"] = fstype
        a["command"] = " ".join([spec["program"], *spec["args"]]).replace("{device}", "<device>") \
            .replace("{superblock}", "<superblock>").replace("{block_size}", "<block size>")
        a["package"] = package_for(spec["program"])
        a["packages"] = dict(PACKAGES.get(spec["program"], {}))
        a["missing_program"] = None
        a["available"] = True
        if which(spec["program"]) is None:
            a["available"] = False
            a["missing_program"] = spec["program"]
            a["unavailable"] = f"{spec['program']} is not installed (package: {a['package']})"
        elif spec.get("requires_option") and not _supports(spec["program"], spec["requires_option"]):
            a["available"] = False
            a["unavailable"] = (f"the installed {spec['program']} has no {spec['requires_option']} option "
                                f"(update {a['package']})")
        if fam == "ntfs":
            a["note"] = _NTFS_NOTE
        out.append(a)
    return out


# ---------------------------------------------------------------------- safety: nothing mounted
def _unescape(field: str) -> str:
    """/proc/self/mounts escapes spaces, tabs, newlines and backslashes as octal."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def _sysfs_dir(rdev: int) -> Path | None:
    p = Path(f"/sys/dev/block/{os.major(rdev)}:{os.minor(rdev)}")
    try:
        return p.resolve(strict=True)
    except OSError:
        return None


def _dev_number(sysdir: Path) -> int | None:
    text = read_text(sysdir / "dev")
    if not text or ":" not in text:
        return None
    major, _, minor = text.partition(":")
    try:
        return os.makedev(int(major), int(minor))
    except ValueError:
        return None


def _related_blockdevs(rdev: int, seen: set[int] | None = None, depth: int = 0) -> set[int]:
    """RDEV, its partitions and whatever is stacked on them (device-mapper, RAID, loop partitions)."""
    seen = set() if seen is None else seen
    if rdev in seen or depth > 6:
        return seen
    seen.add(rdev)
    sysdir = _sysfs_dir(rdev)
    if sysdir is None:
        return seen
    with contextlib.suppress(OSError):
        for child in sysdir.iterdir():
            if (child / "partition").exists():
                n = _dev_number(child)
                if n is not None:
                    _related_blockdevs(n, seen, depth + 1)
    with contextlib.suppress(OSError):
        for holder in (sysdir / "holders").iterdir():
            n = _dev_number(holder.resolve())
            if n is not None:
                _related_blockdevs(n, seen, depth + 1)
    return seen


def _loops_backed_by(st: os.stat_result) -> list[int]:
    """Device numbers of the loop devices whose backing file is the file with stat ST."""
    out = []
    for bf in Path("/sys/block").glob("loop*/loop/backing_file"):
        name = (read_text(bf) or "").removesuffix(" (deleted)")
        try:
            bst = os.stat(name)
        except OSError:
            continue
        if (bst.st_dev, bst.st_ino) == (st.st_dev, st.st_ino):
            n = _dev_number(bf.parent.parent)
            if n is not None:
                out.append(n)
    return out


def _file_holders(st: os.stat_result) -> list[str]:
    """Names of the other processes that have the file with stat ST open (FUSE drivers mounting it)."""
    names = []
    me = str(os.getpid())
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or proc.name == me:
            continue
        try:
            fds = list((proc / "fd").iterdir())
        except OSError:
            continue
        for fd in fds:
            try:
                fst = os.stat(fd)
            except OSError:
                continue
            if (fst.st_dev, fst.st_ino) == (st.st_dev, st.st_ino):
                names.append(read_text(proc / "comm", proc.name) or proc.name)
                break
    return names


def in_use(device: str) -> list[str]:
    """Why DEVICE (a disk, a partition or an image file) can't be checked now: the places where it, or
    something on it, is mounted, and other users (swap, LVM/RAID/encryption, a FUSE driver). [] if none."""
    real = os.path.realpath(device)
    try:
        st = os.stat(real)
    except OSError as exc:
        raise RallError(f"Can't open {device}: {exc.strerror}") from exc
    devs: set[int] = set()
    is_file = stat.S_ISREG(st.st_mode)
    if stat.S_ISBLK(st.st_mode):
        devs = _related_blockdevs(st.st_rdev)
    elif is_file:
        for loop in _loops_backed_by(st):
            devs |= _related_blockdevs(loop)
    reasons: list[str] = []
    fuse_guess = []
    for line in (read_text("/proc/self/mounts", "") or "").splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        src, mnt, fstype = _unescape(fields[0]), _unescape(fields[1]), fields[2]
        hit = False
        if src.startswith("/"):
            try:
                sst = os.stat(src)
            except OSError:
                sst = None
            if sst is not None:
                if stat.S_ISBLK(sst.st_mode) and sst.st_rdev in devs:
                    hit = True
                elif (sst.st_dev, sst.st_ino) == (st.st_dev, st.st_ino):
                    hit = True       # a FUSE driver mounting the image file itself (ntfs-3g img /mnt)
        elif is_file and fstype.startswith("fuse") and os.path.basename(src) == os.path.basename(real):
            fuse_guess.append(mnt)   # fuse2fs keeps the path as typed: confirm below
        if hit and f"mounted at {mnt}" not in reasons:
            reasons.append(f"mounted at {mnt}")
    if fuse_guess and _file_holders(st):
        reasons += [f"mounted at {m}" for m in fuse_guess]
    swaps = read_text("/proc/swaps", "") or ""
    for line in swaps.splitlines()[1:]:
        name = _unescape(line.split()[0]) if line.split() else ""
        with contextlib.suppress(OSError):
            sst = os.stat(name)
            if (stat.S_ISBLK(sst.st_mode) and sst.st_rdev in devs) or \
                    (sst.st_dev, sst.st_ino) == (st.st_dev, st.st_ino):
                reasons.append("used as swap")
    if not reasons and stat.S_ISBLK(st.st_mode):
        # the kernel knows best: an exclusive open fails while anything holds the device
        try:
            fd = os.open(real, os.O_RDONLY | os.O_EXCL | os.O_CLOEXEC)
            os.close(fd)
        except OSError as exc:
            if exc.errno == errno.EBUSY:
                reasons.append("busy (mounted, swap, LVM, RAID or encryption)")
    return reasons


def check_unmounted(device: str) -> None:
    """Raise UnsafeOperation when DEVICE or anything on it is in use."""
    reasons = in_use(device)
    if reasons:
        raise UnsafeOperation(f"{device} is {'; '.join(reasons)}. Unmount it first: a check of a mounted "
                              "filesystem reports damage that isn't there, and a repair would cause some.")


# ---------------------------------------------------------------------- ext backup superblocks
def _backup_groups(limit: int) -> list[int]:
    """Groups that hold a backup superblock with sparse_super: 1 and the powers of 3, 5 and 7."""
    out = {1}
    for base in (3, 5, 7):
        g = base
        while g < limit:
            out.add(g)
            g *= base
    return sorted(g for g in out if g < limit)


def ext_backup_superblocks(device: str, limit: int = 8) -> list[dict]:
    """The backup superblocks of the ext filesystem on DEVICE that look intact, as
    [{"superblock": block number, "block_size": bytes, "group": n}] (what e2fsck -b/-B want). Works when
    the main superblock is gone: every usual block size is tried at the standard backup places."""
    try:
        fd = os.open(device, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        raise RallError(f"Can't open {device}: {exc.strerror}") from exc
    found: list[dict] = []
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
        primary = os.pread(fd, 1024, 1024)
        geometries = []
        if len(primary) == 1024 and struct.unpack_from("<H", primary, 56)[0] == 0xEF53:
            log_bs = struct.unpack_from("<I", primary, 24)[0]
            bpg = struct.unpack_from("<I", primary, 32)[0]
            if log_bs <= 6 and 0 < bpg <= 8 * (1024 << log_bs):
                geometries.append((1024 << log_bs, bpg))
        for bs in (4096, 1024, 2048, 65536):
            if (bs, 8 * bs) not in geometries:
                geometries.append((bs, 8 * bs))
        for bs, bpg in geometries:
            first = 1 if bs == 1024 else 0
            groups = max(1, size // (bpg * bs) + 1)
            for g in _backup_groups(groups):
                block = g * bpg + first
                off = block * bs
                if off + 1024 > size:
                    break
                sb = os.pread(fd, 1024, off)
                if len(sb) < 1024 or struct.unpack_from("<H", sb, 56)[0] != 0xEF53:
                    continue
                if (1024 << min(struct.unpack_from("<I", sb, 24)[0], 16)) != bs or \
                        struct.unpack_from("<I", sb, 32)[0] != bpg:
                    continue
                if struct.unpack_from("<H", sb, 90)[0] not in (g, 0):     # s_block_group_nr
                    continue
                found.append({"superblock": block, "block_size": bs, "group": g})
                if len(found) >= limit:
                    return found
            if found:
                break
    finally:
        os.close(fd)
    return found


# ---------------------------------------------------------------------- loop devices
@contextlib.contextmanager
def _loop_for(path: str, readonly: bool, ctl: Control):
    """A loop device showing the image file PATH (read-only for checks), detached afterwards."""
    if os.geteuid() != 0:
        raise NotPermitted("Checking this image file needs a loop device: start RecoverAll as administrator")
    if which("losetup") is None:
        raise ToolMissing(f"losetup is not installed (package: {package_for('losetup')})")
    rr = run(["losetup", "--find", "--show", *(["--read-only"] if readonly else []), path], timeout=60)
    if not rr.ok or not rr.stdout.strip().startswith("/dev/"):
        raise RallError(f"Can't set up a loop device for {path}: {rr.error_text()}")
    loop = rr.stdout.strip().splitlines()[0]
    ctl.log(f"Using {loop} for {path}")
    try:
        yield loop
    finally:
        detach_loop(loop, timeout=10)


# ---------------------------------------------------------------------- running an action
_PROGRESS = [
    (re.compile(r"^Pass (\d)[A-E]?:"), 5),        # e2fsck
    (re.compile(r"^Phase (\d) "), 7),             # xfs_repair
    (re.compile(r"^\[(\d)/(\d)\]"), 0),           # btrfs check
]
_MAX_LINES = 5000


def run_action(device: str, fstype: str, action_id: str, ctl: Control = NULL_CONTROL,
               superblock: int | None = None, block_size: int | None = None,
               use_loop: bool | None = None) -> dict:
    """Run action ACTION_ID (from actions_for) on DEVICE, a disk, partition or image file holding an FSTYPE
    filesystem. Every output line goes to ctl.log as it arrives; ctl.cancelled stops the program.

    Returns {"ok", "problems_found", "changed", "errors_left", "summary", "output", "command", "exit_code"}:
    ok — the action did its job (a check ran to the end, whatever it found; after a repair the tool reports
    no errors left); problems_found — damage was found (or fixed); changed — something was written.
    USE_LOOP forces (True) or avoids (False) a loop device for an image file; None: only when the tool
    needs a block device.
    """
    fam, spec = _find(fstype, action_id)
    program = spec["program"]
    if which(program) is None:
        raise ToolMissing(f"{program} is not installed (package: {package_for(program)})")
    if spec.get("requires_option") and not _supports(program, spec["requires_option"]):
        raise NotSupported(f"The installed {program} can't do this (no {spec['requires_option']} option): "
                           f"update {package_for(program)}")
    if not os.path.exists(device):
        raise RallError(f"{device} doesn't exist")
    check_unmounted(device)
    if not os.access(device, os.W_OK if spec["writes"] else os.R_OK):
        raise NotPermitted(f"{'Repairing' if spec['writes'] else 'Checking'} {device} needs administrator "
                           "rights")
    if "superblock" in spec.get("needs", ()):
        if superblock is None:
            backups = ext_backup_superblocks(device, limit=1)
            if not backups:
                raise RallError("No intact backup superblock was found at the usual places. If the "
                                "filesystem was made with unusual settings, enter the block number of a "
                                "backup superblock (mke2fs -n shows them for the same size and options).")
            superblock = backups[0]["superblock"]
            block_size = block_size or backups[0]["block_size"]
            ctl.log(f"Using the backup superblock at block {superblock} ({block_size}-byte blocks)")
        elif block_size is None:
            block_size = next((b["block_size"] for b in ext_backup_superblocks(device)
                               if b["superblock"] == superblock), None)
    is_file = stat.S_ISREG(os.stat(device).st_mode)
    loop = spec.get("block_only", False) if use_loop is None else use_loop
    loop = loop and is_file

    with contextlib.ExitStack() as stack:
        target = stack.enter_context(_loop_for(device, not spec["writes"], ctl)) if loop else device
        values = {"device": target, "superblock": str(superblock), "block_size": str(block_size)}
        args = list(spec["args"])
        if block_size is None and "{block_size}" in args:
            # e2fsck tries every block size with -b alone
            i = args.index("{block_size}")
            del args[i - 1:i + 1]
        args = [a.format(**values) if "{" in a else a for a in args]
        if program == "xfs_repair" and is_file and not loop:
            args.insert(0, "-f")        # older xfs_repair needs to be told the "device" is an image file
        cmd = [program, *args]
        command = shlex.join(cmd)
        ctl.log(f"$ {command}")
        ctl.progress(0.0, spec["title"])
        head: list[str] = []
        tail: deque[str] = deque(maxlen=_MAX_LINES)
        dropped = [0]

        def on_line(line: str) -> None:
            if len(head) < _MAX_LINES:
                head.append(line)
            else:
                if len(tail) == tail.maxlen:
                    dropped[0] += 1
                tail.append(line)
            ctl.log(line)
            for rx, total in _PROGRESS:
                m = rx.match(line)
                if m:
                    n = int(m.group(1))
                    t = total or int(m.group(2))
                    ctl.progress(max(0.0, min(1.0, (n - 1) / t)), line.strip())
                    break

        rr = stream(cmd, on_line=on_line, cancelled=lambda: bool(ctl.cancelled), input_text=spec.get("input"))
        if ctl.cancelled:
            raise Cancelled(f"Cancelled: {program} was stopped. Run a check before using the filesystem.")
        if rr.missing:
            raise ToolMissing(f"{program} is not installed (package: {package_for(program)})")
    lines = head + ([f"… {dropped[0]} lines left out …"] if dropped[0] else []) + list(tail)
    output = "\n".join(lines)
    verdict = interpret(fam, spec, output, rr.returncode)
    # the summary names the image by its file name, not its whole path
    short = output.replace(target, os.path.basename(target)) if target.startswith("/") else output
    summary = summarize(fstype, short, rr.returncode, action_id)
    ctl.progress(1.0, summary)
    return {**verdict, "summary": summary, "output": output, "command": command, "exit_code": rr.returncode,
            "action": action_id, "fstype": fstype, "risk": spec["risk"]}


# ---------------------------------------------------------------------- reading the output
_FATAL = {
    "ntfsfix": re.compile(r"NTFS signature is missing|Failed to startup volume|not a valid NTFS|Cannot handle this "
                          r"yet|Volume is corrupt|Permission denied|No such file|busy|Refusing to operate|"
                          r"Failed to read bootsector|Error opening", re.I),
    "xfs": re.compile(r"could not find valid secondary superblock|Exiting now|couldn't|can't open|"
                      r"Permission denied|No such file", re.I),
    "btrfs": re.compile(r"No valid Btrfs found|cannot open file system|could not open|Permission denied|"
                        r"No such file", re.I),
    "hfsplus": re.compile(r"not an HFS|Permission denied|No such file|can't open|could not be (?:verified|"
                          r"repaired) completely|unable to|Invalid volume header", re.I),
}
_RESULT_PROBLEMS = {
    "hfsplus": re.compile(r"found corrupt|needs to be repaired|could not be repaired", re.I),
    "f2fs": re.compile(r"\[Fail\]|\[FIX\]|error|invalid|corrupt", re.I),
    "btrfs": re.compile(r"error\(s\) found|ERROR:|errors found", re.I),
}


def interpret(fam: str, spec: dict, output: str, code: int) -> dict:
    """Turn a tool's exit code and messages into {"ok", "problems_found", "changed", "errors_left"}."""
    tool = spec["tool"]
    writes = spec["writes"]
    ok = problems = changed = left = False
    keys = key_lines(tool, output)
    if tool in ("e2fsck", "exfat", "fsck"):
        # the fsck convention: 1 corrected, 2 corrected (reboot), 4 left uncorrected, 8 operational error,
        # 16 usage, 32 cancelled, 128 library error
        if code & ~7 or code < 0:
            ok = False
            problems = bool(keys) and code & 8 != 0
            left = problems
        elif writes:
            changed = bool(code & 3) or "FILE SYSTEM WAS MODIFIED" in output
            left = bool(code & 4)
            problems = changed or left
            ok = not left
        else:
            problems = bool(code & 7)
            ok = True
    elif tool == "fat":
        if code in (0, 1):
            ok = True
            problems = code == 1
            changed = writes and code == 1 and "Leaving filesystem unchanged" not in output
        else:
            problems = bool(keys)
    elif tool == "ntfsfix":
        fatal = _FATAL["ntfsfix"].search(output) is not None
        problems = bool(keys) or code != 0
        if writes:
            ok = code == 0
            changed = code == 0
            left = code != 0
        else:
            ok = code == 0 or not fatal
    elif tool == "xfs":
        fatal = _FATAL["xfs"].search(output) is not None
        if writes:
            ok = code == 0
            changed = code == 0 and bool(keys)
            problems = bool(keys) or code != 0
            left = code != 0
        else:
            problems = code != 0
            ok = code in (0, 1) and not fatal
    elif tool == "btrfs-check":
        fatal = _FATAL["btrfs"].search(output) is not None
        problems = code != 0 or _RESULT_PROBLEMS["btrfs"].search(output) is not None
        if writes:
            ok = code == 0
            changed = code == 0 and bool(keys)
            left = code != 0
        else:
            ok = not fatal
    elif tool == "btrfs-super":
        # 0 all superblocks valid, 2 recovered, 1 usage, 3 failed, 4 aborted
        ok = code in (0, 2)
        changed = problems = code == 2
        left = not ok
    elif tool == "btrfs-zero-log":
        ok = code == 0
        changed = problems = ok and re.search(r"previous log_root 0\b", output) is None
    elif tool == "btrfs-rescue":
        ok = changed = code == 0
        problems = True
        left = not ok
    elif tool == "hfsplus":
        bad = _RESULT_PROBLEMS["hfsplus"].search(output) is not None
        fatal = _FATAL["hfsplus"].search(output) is not None
        if writes:
            ok = code == 0 and "could not be repaired" not in output
            changed = re.search(r"repaired successfully|Repairing volume|Rebuilding", output) is not None
            problems = changed or bad or code != 0
            left = not ok
        else:
            problems = code != 0 or bad
            ok = code == 0 or (bad and not fatal)
    elif tool == "f2fs":
        bad = _RESULT_PROBLEMS["f2fs"].search("\n".join(keys)) is not None
        if writes:
            ok = code in (0, 1)
            changed = code == 1 or re.search(r"\[FIX\]|Fixed", output) is not None
            problems = changed or bad
            left = not ok
        else:
            problems = code != 0 or bad
            ok = code in (0, 1, 4) or bad
    else:
        ok = code == 0
        problems = code != 0
    return {"ok": bool(ok), "problems_found": bool(problems), "changed": bool(changed and writes),
            "errors_left": bool(left)}


# lines that are progress or banners, never a finding
_NOISE: dict[str, list[re.Pattern]] = {
    "e2fsck": [re.compile(p) for p in (
        r"^e2fsck \d", r"^\s*Using EXT2FS Library", r"^Pass \d", r"^\S+: \d+/\d+ files", r"^\S+: clean,",
        r"FILE SYSTEM WAS MODIFIED", r"WARNING: Filesystem still has errors", r"^Restarting e2fsck",
        r"^\s*(Fix|Clear|Create|Allocate|Relocate|Salvage|Recreate|Abort|Ignore error|Optimize|Expand|"
        r"Split|Truncate|Connect to /lost\+found|Clone multiply-claimed blocks|Delete file|Clear inode|"
        r"Clear HTree index|Recover|Rebuild)\?\s*(yes|no)?\s*$",
        r"^\s*\(i\.e\., without -a or -p options\)", r"^\s*$", r"^Checking all file systems",
        r"^\s*Running additional passes", r"^\s*\d+ inodes? used", r"^\s*\d+ (non-contiguous|extent|regular|"
        r"directories|character|block device|fifo|link|symbolic|socket|file)", r"^-+$",
        r"Warning: skipping journal recovery because doing a read-only filesystem check",
        r"^This doesn't bode well, but we'll try to go on", r"^\s*(FIXED|CLEARED|IGNORED|NOT CLEARED)\.\s*$",
    )],
    "fat": [re.compile(p) for p in (
        r"^fsck\.fat \d", r"^dosfsck \d", r"^\S+: \d+ files, \d+/\d+ clusters", r"Leaving filesystem unchanged",
        r"^Checking ", r"^Boot sector contents", r"^System ID", r"^Media byte", r"^\s*\d+ bytes per",
        r"^\s*\d+ reserved sectors", r"^First FAT starts", r"^\s*\d+ FATs, \d+ bit entries", r"^Root directory",
        r"^Data area starts", r"^\s*\d+ data clusters", r"^\s*\d+ sectors/track", r"^\s*\d+ hidden sectors",
        r"^\s*\d+ sectors total", r"^Starting (check/repair|verification) pass", r"^This is mostly harmless",
        r"^\s*,?\s*\d+:[0-9a-f]{2}/[0-9a-f]{2}", r"Not automatically fixing this", r"^Performing changes",
        r"^Reclaiming unconnected clusters", r"^Volume label", r"^\s*(Using|Copying|Truncating|Dropping|"
        r"Freeing|Reclaimed|Setting|Fixing)\b",
    )],
    "exfat": [re.compile(p) for p in (r"^exfatprogs version", r"^\S+: clean\.", r"^\S+: corrected\.",
                                      r"^\S+: checking stopped", r"^\s*$")],
    "ntfsfix": [re.compile(p) for p in (
        r"^Mounting volume\.\.\. OK", r"^Processing of \$MFT and \$MFTMirr completed successfully",
        r"^Checking the alternate boot sector\.\.\. OK", r"^NTFS volume version is", r"was processed successfully",
        r"^Attempting to correct errors", r"^Processing \$MFT and \$MFTMirr", r"^Reading \$MFT(Mirr)?\.\.\. OK",
        r"^FAILED$", r"^Setting required flags on partition", r"^Going to empty the journal",
        r"^Remount failed", r"^Comparing \$MFTMirr to \$MFT", r"^Correcting differences in \$MFT",
        r"^ntfsfix v", r"^Checking for self-located MFT segment\.\.\. OK", r"^Checking file system overflow",
        r"^The alternate bootsector is usable", r"^Trying the alternate boot sector",
        r"^Mounting volume\.\.\. $", r"^OK$", r"^Going to un-mark the bad clusters",
    )],
    "xfs": [re.compile(p) for p in (
        r"^Phase \d", r"^\s*- ", r"^Cannot get host filesystem geometry", r"^Repair may fail if there is a sector",
        r"^the image and the host filesystem", r"^No modify flag set", r"^done$", r"^\s*$",
        r"^Maximum metadata LSN", r"^Note - quota info will be regenerated", r"^\s*agno = \d",
        r"^xfs_repair version",
    )],
    "btrfs": [re.compile(p) for p in (
        r"^\[\d+/\d+\]", r"^Opening filesystem to check", r"^Checking filesystem on", r"^UUID:",
        r"bytes used, no error found", r"^total ", r"^btree space waste", r"^file data blocks allocated",
        r"^\s*referenced", r"^cache and super generation", r"^Starting repair", r"^enabling repair mode",
        r"^WARNING:\s*$", r"^\s+(Do not use|or an experienced|fsck successfully|some software|The operation will|"
        r"Use Ctrl-C)", r"^[\d ]+$", r"^All supers are valid", r"^Make sure this is a btrfs disk",
        r"^Clearing log on .*previous log_root 0,", r"bytes used, error\(s\) found", r"^\s*$",
        r"^ERROR: errors found in fs roots", r"^found \d+ bytes used",
    )],
    "hfsplus": [re.compile(p) for p in (
        r"^\*\* (Checking|The volume .* (appears to be OK|was found corrupt|was repaired successfully)|"
        r"Repairing volume|Rechecking volume|\S+( \(NO WRITE\))?$)",
        r"^\s+Executing fsck_hfs", r"^\s+The volume name is", r"^QUICKCHECK ONLY", r"^\s*$",
    )],
    "f2fs": [re.compile(p) for p in (r"^Info:", r"\[Ok\.\.\]", r"^Done:", r"^\s*$", r"^\[FSCK\] .*\[0x0\]$",
                                     r"^\s*\[FSCK\] (Max image size|Unreachable|SIT valid|Hard link|valid_block|"
                                     r"valid_node|valid_inode|free segment|other corrupted bugs).*\[Ok")],
    "fsck": [re.compile(p) for p in (r"^\s*$", r"^(jfs_fsck|reiserfsck) version", r"^\S+ version \d")],
}
_STRIP = {
    "e2fsck": [re.compile(r"\s+(Fix|Clear|Create|Allocate|Relocate|Salvage|Recreate|Ignore error|Optimize|Expand|"
                          r"Split|Truncate|Delete file|Clear inode|Clear HTree index|Recover|Rebuild)\?\s*(yes|no)?\s*$"),
               re.compile(r"\s+(FIXED|CLEARED|IGNORED|NOT CLEARED)\.\s*$"),
               re.compile(r"^[^\s:]{1,64}: (?=\S)")],
    "exfat": [re.compile(r"\s*\. ?Fix \(y/N\)\?\s*[yn]?\s*$"), re.compile(r"\s*Fix \(y/N\)\?\s*[yn]?\s*$")],
    "ntfsfix": [re.compile(r"^Mounting volume\.\.\. ")],
    "btrfs": [re.compile(r"^ERROR: ")],
    "xfs": [re.compile(r"^\.+")],
    "hfsplus": [re.compile(r"^\*\* ")],
}


def key_lines(tool: str, output: str) -> list[str]:
    """The lines of OUTPUT that say what is wrong (or what was fixed): banners and progress removed,
    answers to the tool's questions stripped, duplicates dropped."""
    group = {"btrfs-check": "btrfs", "btrfs-super": "btrfs", "btrfs-zero-log": "btrfs",
             "btrfs-rescue": "btrfs"}.get(tool, tool)
    noise = _NOISE.get(group, [])
    strips = _STRIP.get(group, [])
    out: list[str] = []
    seen: set[str] = set()
    for raw in output.splitlines():
        if any(rx.search(raw) for rx in noise):
            continue
        indented = raw[:1] in (" ", "\t")
        line = raw.strip()
        for rx in strips:
            line = rx.sub("", line).strip()
        if not line or line.startswith("…"):
            continue
        if out and indented and group == "hfsplus" and line.startswith("("):
            out[-1] = f"{out[-1]} {line}"        # "Invalid volume free block count" + "(It should be …)"
            continue
        if out and indented and group == "fat" and out[-1].startswith("/"):
            out[-1] = f"{out[-1]}: {line}"       # "/DIR/FILE" + "  File size is …"
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
        if len(out) > 2000:
            break
    return out


def _infer_action(fam: str, output: str) -> dict:
    """The action that most likely produced OUTPUT (summarize() without an action id)."""
    wrote = re.search(r"FILE SYSTEM WAS MODIFIED|repaired successfully|Correcting differences|"
                      r"Recovered bad superblocks|Performing changes|Clearing log on|Fix \(y/N\)\? y|"
                      r"Chunk tree recovered", output)
    for spec in ACTIONS[fam]:
        if spec["writes"] == bool(wrote):
            return spec
    return ACTIONS[fam][0]


def _shorten(text: str, limit: int = 110) -> str:
    text = " ".join(text.split()).rstrip(".")
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def _listing(keys: list[str], n: int = 3) -> str:
    shown = "; ".join(_shorten(k[:1].upper() + k[1:]) for k in keys[:n])
    more = len(keys) - n
    return shown + (f" (and {more} more)" if more > 0 else "")


def summarize(fstype: str, output: str, exit_code: int, action: str | None = None) -> str:
    """One plain sentence about what a check or repair found or did ("No problems found.", "Repaired 3
    problems: …", "Problems found: …"), with a few key lines from the tool's output."""
    fam = family_of(fstype)
    if not fam:
        return "Finished." if exit_code == 0 else f"Finished with exit status {exit_code}."
    spec = _find(fstype, action)[1] if action else _infer_action(fam, output)
    v = interpret(fam, spec, output, exit_code)
    keys = key_lines(spec["tool"], output)
    name = FS_NAMES[fam]
    n = len(keys)
    plural = "problem" if n == 1 else "problems"
    tail = ""
    if fam == "ntfs" and spec["writes"] and v["ok"]:
        tail = " Windows checks the volume (chkdsk) at its next start; only chkdsk can repair NTFS fully."
    if spec["tool"] == "xfs" and exit_code == 2:
        return ("The journal holds changes that must be replayed first: mount the filesystem once and unmount "
                "it, then repair again (if it won't mount, use “Repair and discard the journal”).")
    if "UNEXPECTED INCONSISTENCY" in output:
        return (f"Some problems need a decision ({_listing(keys)}): use “Repair everything”." if keys else
                "Some problems need a decision: use “Repair everything”.")
    if not v["ok"] and not v["changed"]:
        if not v["problems_found"]:
            detail = keys[-1] if keys else f"exit status {exit_code}"
            return f"{spec['program']} failed: {_shorten(detail)}."
        if not spec["writes"]:
            return f"The {name} filesystem can't be read: {_listing(keys, 2)}." if keys else \
                f"The {name} filesystem can't be read ({spec['program']} exit status {exit_code})."
        return f"The repair failed: {_listing(keys)}." if keys else \
            f"The repair failed ({spec['program']} exit status {exit_code})."
    if not spec["writes"]:
        if not v["problems_found"]:
            note = ""
            if "differences between boot sector and its backup" in output:
                note = " (the backup boot sector differs from the boot sector, which is mostly harmless)"
            return f"No problems found{note}."
        return f"Problems found: {_listing(keys)}." if keys else \
            f"Problems found ({spec['program']} exit status {exit_code})."
    if v["changed"]:
        if v["errors_left"]:
            return (f"Repaired some problems, but some are left: {_listing(keys)}." if keys else
                    "Repaired some problems, but some are left.") + tail
        if spec["tool"] == "btrfs-super":
            return "Restored the damaged superblock copies from a good one."
        if spec["tool"] == "btrfs-zero-log":
            return "Cleared the log tree."
        if spec["id"] == "rebuild_catalog" and not v["errors_left"]:
            return "Rebuilt the catalog B-tree."
        if fam == "ntfs" and not n:
            what = {"clear_dirty": " and cleared the dirty flag",
                    "clear_badsectors": " and cleared the bad-sector list"}.get(spec["id"], "")
            return (f"No damage found; ntfsfix emptied the journal{what}, so Linux can mount the volume." +
                    ("" if spec["id"] == "clear_dirty" else tail))
        if n:
            return f"Repaired {n} {plural}: {_listing(keys)}.{tail}"
        return f"Repaired the filesystem.{tail}"
    if v["errors_left"]:
        return f"Problems are left: {_listing(keys)}." if keys else "Problems are left."
    if spec["tool"] == "btrfs-zero-log":
        return "The log tree was already empty; nothing was changed."
    if spec["tool"] == "btrfs-super":
        return "All superblock copies are intact; nothing was changed."
    return "No problems found; nothing needed fixing."
