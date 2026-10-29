"""Filesystem readers: which module reads which filesystem type, loaded on demand.

Native readers (pure Python, read-only, find deleted files): NTFS, FAT12/16/32, exFAT, ext2/3/4, XFS, HFS+,
ISO 9660. External engines: The Sleuth Kit (APFS, UFS, HFS, and a second opinion on the others) and
btrfs-progs (Btrfs).
"""

from __future__ import annotations

import importlib
import logging

from .base import (  # noqa: F401 - re-exported
    CHANCE_FAIR,
    CHANCE_GOOD,
    CHANCE_NAMES,
    CHANCE_POOR,
    CHANCE_UNKNOWN,
    Control,
    Detector,
    Entry,
    FsReader,
    read_content,
    read_head,
)

log = logging.getLogger(__name__)

# fstype (as fsdetect names it) → (module, class)
READERS: dict[str, tuple[str, str]] = {
    "ntfs": ("ntfs", "NtfsReader"),
    "fat12": ("fat", "FatReader"),
    "fat16": ("fat", "FatReader"),
    "fat32": ("fat", "FatReader"),
    "vfat": ("fat", "FatReader"),
    "exfat": ("exfat", "ExfatReader"),
    "ext2": ("ext", "ExtReader"),
    "ext3": ("ext", "ExtReader"),
    "ext4": ("ext", "ExtReader"),
    "xfs": ("xfs", "XfsReader"),
    "hfsplus": ("hfsplus", "HfsPlusReader"),
    "hfsx": ("hfsplus", "HfsPlusReader"),
    "iso9660": ("iso9660", "Iso9660Reader"),
    "btrfs": ("btrfs", "BtrfsReader"),
    "apfs": ("tsk", "TskReader"),
    "ufs": ("tsk", "TskReader"),
    "ufs1": ("tsk", "TskReader"),
    "ufs2": ("tsk", "TskReader"),
    "hfs": ("hfsplus", "HfsPlusReader"),          # an HFS wrapper around HFS+ (classic HFS alone: not readable)
}

NAMES = {"ntfs": "NTFS", "fat12": "FAT12", "fat16": "FAT16", "fat32": "FAT32", "vfat": "FAT", "exfat": "exFAT",
         "ext2": "ext2", "ext3": "ext3", "ext4": "ext4", "xfs": "XFS", "btrfs": "Btrfs", "hfsplus": "HFS+",
         "hfsx": "HFSX", "hfs": "HFS", "apfs": "APFS", "iso9660": "ISO 9660", "udf": "UDF", "refs": "ReFS",
         "f2fs": "F2FS", "ufs": "UFS", "ufs1": "UFS1", "ufs2": "UFS2", "zfs_member": "ZFS", "jfs": "JFS",
         "reiserfs": "ReiserFS", "swap": "swap", "crypto_luks": "LUKS", "bitlocker": "BitLocker",
         "lvm2_member": "LVM", "linux_raid_member": "RAID member", "squashfs": "SquashFS", "erofs": "EROFS",
         "nilfs2": "NILFS2", "minix": "Minix", "carved": "Files found by signature",
         "thumbnails": "Thumbnails from caches"}

# Order in which readers are tried on a volume nobody identified (cheap probes first).
PROBE_ORDER = ("ntfs", "exfat", "fat32", "ext4", "xfs", "hfsplus", "iso9660", "btrfs")


def fs_name(fstype: str | None) -> str:
    return NAMES.get(fstype or "", fstype or "unknown")


def reader_class(fstype: str):
    """The reader class for FSTYPE, or None when there is none (or its module failed to import)."""
    spec = READERS.get(fstype)
    if spec is None:
        return None
    mod, cls = spec
    try:
        m = importlib.import_module(f"{__package__}.{mod}")
    except ImportError as exc:
        log.warning("reader %s unavailable: %s", mod, exc)
        return None
    return getattr(m, cls, None)


def open_reader(src, fstype: str | None = None, info: dict | None = None):
    """A reader for the filesystem at the start of SRC (probing if FSTYPE is not given), or None."""
    candidates = [fstype] if fstype else list(PROBE_ORDER)
    for t in candidates:
        cls = reader_class(t)
        if cls is None:
            continue
        probed = None
        try:
            probed = cls.probe(src)
        except Exception as exc:  # noqa: BLE001 - damaged boot sectors must not stop anything
            log.debug("probe %s failed: %s", t, exc)
        if probed is None and info is None:
            continue
        merged = dict(probed or {})
        merged.update(info or {})
        try:
            return cls(src, merged)
        except Exception as exc:  # noqa: BLE001
            log.debug("open %s failed: %s", t, exc)
    return None
