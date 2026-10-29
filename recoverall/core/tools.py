"""The programs RecoverAll can use, which package has them, and what they add.

None of them is needed to find and recover files: the filesystem readers, the signature search and the
partition search are RecoverAll's own. The tools add imaging of failing disks (GNU ddrescue), filesystem
repair (fsck tools), partition-table writing (sfdisk), disk health (smartctl), encrypted volumes
(cryptsetup), Btrfs (btrfs-progs) and a second engine for rarer filesystems (The Sleuth Kit).
"""

from __future__ import annotations

from .util import run, which

# program → (package hint, what it's for, group)
PROGRAMS: dict[str, tuple[str, str, str]] = {
    "lsblk": ("util-linux", "list disks", "basics"),
    "blkid": ("util-linux", "identify filesystems", "basics"),
    "sfdisk": ("util-linux (Debian/Ubuntu: fdisk)", "write recovered partition tables", "partitions"),
    "losetup": ("util-linux (Debian/Ubuntu: mount)", "expose image files to repair tools", "basics"),
    "pkexec": ("polkit", "the app's administrator access", "basics"),
    "ddrescue": ("ddrescue (Debian/Ubuntu/openSUSE: gddrescue)", "image failing disks (the best imager)", "imaging"),
    "smartctl": ("smartmontools", "disk health warnings", "imaging"),
    "e2fsck": ("e2fsprogs", "check and repair ext2/3/4", "repair"),
    "fsck.fat": ("dosfstools", "check and repair FAT", "repair"),
    "fsck.exfat": ("exfatprogs", "check and repair exFAT", "repair"),
    "ntfsfix": ("ntfs-3g (Fedora/openSUSE: ntfsprogs)", "fix common NTFS problems", "repair"),
    "xfs_repair": ("xfsprogs", "check and repair XFS", "repair"),
    "btrfs": ("btrfs-progs (openSUSE: btrfsprogs)", "read and repair Btrfs", "repair"),
    "fsck.hfsplus": ("hfsprogs (Fedora: hfsplus-tools)", "check and repair HFS+", "repair"),
    "fsck.f2fs": ("f2fs-tools", "check and repair F2FS", "repair"),
    "jfs_fsck": ("jfsutils", "check and repair JFS", "repair"),
    "reiserfsck": ("reiserfsprogs", "check and repair ReiserFS", "repair"),
    "cryptsetup": ("cryptsetup", "unlock LUKS and BitLocker volumes", "volumes"),
    "mdadm": ("mdadm", "read Linux software-RAID members", "volumes"),
    "ffmpeg": ("ffmpeg (Fedora: ffmpeg-free)", "pictures from found videos; checking repaired videos", "engines"),
    "fls": ("sleuthkit", "second engine: APFS, UFS, HFS", "engines"),
    "icat": ("sleuthkit", "second engine: read files", "engines"),
}

GROUPS = {"basics": "Basics", "imaging": "Imaging and health", "repair": "Filesystem repair",
          "partitions": "Partitions", "volumes": "RAID and encryption", "engines": "Extra engines"}


def have(*names: str) -> bool:
    return all(which(n) is not None for n in names)


def inventory() -> list[dict]:
    """Every program with its path (for `recoverctl doctor` and the Settings dialog)."""
    return [{"name": name, "path": which(name), "package": pkg, "use": use, "group": group}
            for name, (pkg, use, group) in PROGRAMS.items()]


def capabilities() -> dict:
    """What the optional parts of the app can use. Cheap."""
    return {
        "ddrescue": have("ddrescue"),
        "smartctl": have("smartctl"),
        "sfdisk": have("sfdisk"),
        "tsk": have("fls", "icat"),
        "btrfs": have("btrfs"),
        "cryptsetup": have("cryptsetup"),
        "ffmpeg": have("ffmpeg"),
        "fsck": {fs: have(prog) for fs, prog in (("ext", "e2fsck"), ("fat", "fsck.fat"), ("exfat", "fsck.exfat"),
                                                  ("ntfs", "ntfsfix"), ("xfs", "xfs_repair"), ("btrfs", "btrfs"),
                                                  ("hfsplus", "fsck.hfsplus"), ("f2fs", "fsck.f2fs"))},
    }


def version(name: str) -> str:
    flags = {"ddrescue": ["--version"], "smartctl": ["--version"], "e2fsck": ["-V"], "fls": ["-V"]}
    rr = run([name, *flags.get(name, ["--version"])], timeout=10)
    text = (rr.stdout or rr.stderr).strip().splitlines()
    return text[0] if text else ""
