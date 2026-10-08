"""ext2, ext3 and ext4: existing files, and deleted ones from what the kernel and the journal leave behind.

On-disk format, briefly. The volume is cut into block groups. The superblock (at byte 1024, with backup copies
at the start of some groups) gives the geometry; the group descriptors that follow it say where each group
keeps its block bitmap, inode bitmap and inode table. Every file is an inode (mode, size, times, flags, and 60
bytes that describe the content): an extent tree on ext4 (header 0xF30A, any depth), a map of 12 direct +
indirect/double/triple indirect block pointers on ext2/ext3, the bytes themselves for small files with
``inline_data`` and for short ("fast") symlinks. A folder is a file of variable-length entries (inode, record
length, name); big folders add an htree index whose nodes hide inside fake entries, so reading every block
linearly still finds every name. ext3 and ext4 log metadata changes in a jbd2 journal (inode 8): descriptor
blocks list which filesystem block each following log block is a copy of, commit blocks close a transaction.

What can be recovered:

* every existing file and folder (hard links once per name, symlinks, sparse files, inline data, >2 TiB
  geometry, bigalloc, meta_bg); inodes in use that no folder reaches any more are listed under "Lost files".
  A filesystem that wasn't unmounted cleanly is read as Linux would see it after replaying its journal
  (in memory: nothing is written);
* deleted files on ext3/ext4: the kernel clears the block map and (since Linux 5.9) wipes the folder entry,
  but the journal usually still holds older copies of the inode table blocks and folder blocks. Names come
  from those folder copies, content from the newest inode copy that still had a valid map (flag F_JOURNAL).
  Inode numbers are reused, so each name is matched with the life of its inode that existed when the journal
  saw the name (generation numbers tell lives apart), and a deleted file whose blocks a later deleted file
  used too is rated POOR even though the blocks are free again. Deleted folders bring their deleted children
  back. Deleted inodes whose name is gone are listed under "Lost files" as "inode N";
* deleted files that kept their block map on the disk (deleted by e2fsprogs/debugfs, or by Linux before 2.6
  on ext2): the name is still in the slack of the previous folder entry.

What can't: deleted files whose inode copies left the journal (it is circular and gets overwritten as the
filesystem is used), files deleted from an ext2 (or an ext4 without journal) by a current kernel (map and name
are both wiped: only carving finds them), files deleted from a filesystem whose journal lives on another device,
and blocks reused since (chance POOR). Encrypted (fscrypt) files and names are copied as stored.
"""

from __future__ import annotations

import base64
import bisect
import struct
from collections import deque
from typing import Callable, Iterator

from ..blockio import CachedSource, Source
from ..errors import FormatError
from .base import (
    CHANCE_GOOD,
    CHANCE_POOR,
    F_ENCRYPTED,
    F_HARDLINK,
    F_JOURNAL,
    F_ORPHAN,
    F_PARTIAL,
    F_RESIDENT,
    F_SPARSE,
    F_SYMLINK,
    F_SYSTEM,
    NULL_CONTROL,
    Control,
    Entry,
    FsReader,
    merge_runs,
)

SB_OFFSET = 1024
SB_MAGIC = 0xEF53

# superblock feature bits
COMPAT_HAS_JOURNAL = 0x4
COMPAT_SPARSE_SUPER2 = 0x200
INCOMPAT_FILETYPE = 0x2
INCOMPAT_RECOVER = 0x4
INCOMPAT_JOURNAL_DEV = 0x8
INCOMPAT_META_BG = 0x10
INCOMPAT_EXTENTS = 0x40
INCOMPAT_64BIT = 0x80
INCOMPAT_FLEX_BG = 0x200
INCOMPAT_CSUM_SEED = 0x2000
INCOMPAT_LARGEDIR = 0x4000
INCOMPAT_INLINE_DATA = 0x8000
INCOMPAT_ENCRYPT = 0x10000
RO_COMPAT_SPARSE_SUPER = 0x1
RO_COMPAT_LARGE_FILE = 0x2
RO_COMPAT_BTREE_DIR = 0x4
RO_COMPAT_GDT_CSUM = 0x10
RO_COMPAT_BIGALLOC = 0x200
RO_COMPAT_METADATA_CSUM = 0x400

# what ext3 understands; anything beyond makes it ext4 (the same rule blkid uses)
_EXT3_INCOMPAT = INCOMPAT_FILETYPE | INCOMPAT_RECOVER | INCOMPAT_META_BG
_EXT3_RO_COMPAT = RO_COMPAT_SPARSE_SUPER | RO_COMPAT_LARGE_FILE | RO_COMPAT_BTREE_DIR

_FEATURE_NAMES = {
    "compat": {0x1: "dir_prealloc", 0x2: "imagic_inodes", 0x4: "has_journal", 0x8: "ext_attr", 0x10: "resize_inode",
               0x20: "dir_index", 0x40: "lazy_bg", 0x200: "sparse_super2", 0x400: "fast_commit",
               0x800: "stable_inodes", 0x1000: "orphan_file"},
    "incompat": {0x1: "compression", 0x2: "filetype", 0x4: "needs_recovery", 0x8: "journal_dev", 0x10: "meta_bg",
                 0x40: "extent", 0x80: "64bit", 0x100: "mmp", 0x200: "flex_bg", 0x400: "ea_inode",
                 0x1000: "dirdata", 0x2000: "metadata_csum_seed", 0x4000: "large_dir", 0x8000: "inline_data",
                 0x10000: "encrypt", 0x20000: "casefold"},
    "ro_compat": {0x1: "sparse_super", 0x2: "large_file", 0x4: "btree_dir", 0x8: "huge_file", 0x10: "uninit_bg",
                  0x20: "dir_nlink", 0x40: "extra_isize", 0x100: "quota", 0x200: "bigalloc",
                  0x400: "metadata_csum", 0x1000: "read-only", 0x2000: "project", 0x8000: "verity",
                  0x10000: "orphan_present"},
}

# group descriptor flags
BG_INODE_UNINIT = 0x1
BG_BLOCK_UNINIT = 0x2

# inode flags
EXT4_ENCRYPT_FL = 0x800
EXT4_INDEX_FL = 0x1000
EXT4_HUGE_FILE_FL = 0x40000
EXT4_EXTENTS_FL = 0x80000
EXT4_EA_INODE_FL = 0x200000
EXT4_INLINE_DATA_FL = 0x10000000

S_IFMT = 0xF000
S_IFSOCK, S_IFLNK, S_IFREG, S_IFBLK, S_IFDIR, S_IFCHR, S_IFIFO = (0xC000, 0xA000, 0x8000, 0x6000, 0x4000, 0x2000,
                                                                  0x1000)
_SPECIAL = {S_IFSOCK: "socket", S_IFBLK: "block device", S_IFCHR: "character device", S_IFIFO: "fifo"}
_VALID_TYPES = (S_IFSOCK, S_IFLNK, S_IFREG, S_IFBLK, S_IFDIR, S_IFCHR, S_IFIFO)

EXT_MAGIC = 0xF30A
ROOT_INO = 2
JOURNAL_INO = 8

# jbd2 (all big-endian)
JBD2_MAGIC = 0xC03B3998
_JBD2_MAGIC_BYTES = struct.pack(">I", JBD2_MAGIC)
JBD2_DESCRIPTOR, JBD2_COMMIT, JBD2_SB_V1, JBD2_SB_V2, JBD2_REVOKE = 1, 2, 3, 4, 5
JBD2_COMPAT_CHECKSUM = 0x1
JBD2_INCOMPAT_REVOKE = 0x1
JBD2_INCOMPAT_64BIT = 0x2
JBD2_INCOMPAT_CSUM_V2 = 0x8
JBD2_INCOMPAT_CSUM_V3 = 0x10
JBD2_INCOMPAT_FAST_COMMIT = 0x20
JBD2_FLAG_ESCAPE = 0x1
JBD2_FLAG_SAME_UUID = 0x2
JBD2_FLAG_LAST_TAG = 0x8

# hard limits that keep damaged metadata from running away
MAX_EXTENTS = 4_000_000
MAX_DIR_BLOCKS = 1 << 18          # 1 GiB of 4 KiB folder blocks
MAX_DEPTH = 5
READ_CHUNK = 4 * 1024 * 1024

_DAMAGE = (struct.error, ValueError, IndexError, OverflowError)     # what garbage metadata can raise

_INODE = struct.Struct("<HHIIIIIHHII")       # mode uid size_lo atime ctime mtime dtime gid links blocks_lo flags
_DIRENT = struct.Struct("<IHBB")
_EXT_HDR = struct.Struct("<HHHHI")
_EXT_LEAF = struct.Struct("<IHHI")
_EXT_IDX = struct.Struct("<IIHH")


# ---------------------------------------------------------------------- crc32c (metadata_csum)
def _crc32c_table() -> list[int]:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        table.append(c)
    return table


_CRC32C = _crc32c_table()


def crc32c(data: bytes, crc: int = 0xFFFFFFFF) -> int:
    """The raw CRC32c update (no final inversion), chained the way ext4 and jbd2 do it. Pure Python: only used on
    the few small structures whose owner we need to prove (inode copies from the journal)."""
    t = _CRC32C
    for b in data:
        crc = t[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


# ---------------------------------------------------------------------- superblock
def _uuid_str(b: bytes) -> str:
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _cstr(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode("utf-8", "replace").strip()


def _features(sb: dict) -> list[str]:
    out = []
    for kind in ("compat", "incompat", "ro_compat"):
        v = sb["feature_" + kind]
        for bit, name in _FEATURE_NAMES[kind].items():
            if v & bit:
                out.append(name)
    return out


def parse_superblock(buf: bytes) -> dict | None:
    """The fields of an ext2/3/4 superblock (the 1024 bytes at offset 1024 of the volume, or a backup copy at the
    start of a block group), or None when BUF isn't one or its geometry is absurd.

    ``block_group_nr`` tells which group a backup copy belongs to: the volume starts
    ``block_group_nr * blocks_per_group + first_data_block`` blocks before it (the partition search uses that to
    place a volume whose primary superblock is gone)."""
    if len(buf) < 1024:
        return None
    if struct.unpack_from("<H", buf, 0x38)[0] != SB_MAGIC:
        return None
    (inodes, blocks_lo, r_blocks_lo, free_blocks_lo, free_inodes, first_data_block, log_bs, log_cs, bpg, cpg,
     ipg, mtime, wtime) = struct.unpack_from("<13I", buf, 0)
    state, errors, minor_rev = struct.unpack_from("<HHH", buf, 0x3A)
    rev_level = struct.unpack_from("<I", buf, 0x4C)[0]
    first_ino, inode_size, group_nr = struct.unpack_from("<IHH", buf, 0x54)
    f_compat, f_incompat, f_ro = struct.unpack_from("<III", buf, 0x5C)
    reserved_gdt = struct.unpack_from("<H", buf, 0xCE)[0]
    journal_inum, journal_dev, last_orphan = struct.unpack_from("<III", buf, 0xE0)
    def_hash, jnl_backup_type, desc_size = struct.unpack_from("<BBH", buf, 0xFC)
    first_meta_bg, mkfs_time = struct.unpack_from("<II", buf, 0x104)
    blocks_hi, r_blocks_hi, free_blocks_hi = struct.unpack_from("<III", buf, 0x150)
    min_extra, want_extra = struct.unpack_from("<HH", buf, 0x15C)
    log_gpf = buf[0x174]
    quota = struct.unpack_from("<II", buf, 0x240) + struct.unpack_from("<I", buf, 0x26C)
    backup_bgs = struct.unpack_from("<II", buf, 0x24C)
    csum_seed = struct.unpack_from("<I", buf, 0x270)[0]
    orphan_file = struct.unpack_from("<I", buf, 0x280)[0]

    if log_bs > 6:
        return None
    bs = 1024 << log_bs
    is64 = bool(f_incompat & INCOMPAT_64BIT)
    blocks = blocks_lo | ((blocks_hi << 32) if is64 else 0)
    if f_ro & RO_COMPAT_BIGALLOC:
        if log_cs < log_bs or log_cs - log_bs > 16 or not (0 < cpg <= 8 * bs):
            return None
        cluster_bits = log_cs - log_bs
        if bpg != cpg << cluster_bits:
            bpg = cpg << cluster_bits
    else:
        cluster_bits = 0
        cpg = bpg
    if not (8 <= cpg <= 8 * bs) or not (0 < ipg <= 8 * bs):
        return None
    if first_data_block > 1 or blocks <= first_data_block + 1:
        return None
    if rev_level == 0:
        inode_size, first_ino = 128, 11
    if inode_size < 128 or inode_size > bs or inode_size & (inode_size - 1):
        return None
    if not (11 <= first_ino < 1 << 31):
        return None
    if is64:
        if desc_size < 32 or desc_size > 1024 or desc_size & (desc_size - 1):
            return None
    else:
        desc_size = 32
    groups = (blocks - first_data_block + bpg - 1) // bpg
    if groups <= 0 or groups > (1 << 32):
        return None
    if inodes > groups * ipg or inodes == 0:
        return None
    if f_incompat & INCOMPAT_JOURNAL_DEV:
        kind = "jbd2"                    # an external journal device, not a filesystem
    elif f_incompat & ~_EXT3_INCOMPAT or f_ro & ~_EXT3_RO_COMPAT:
        kind = "ext4"
    elif f_compat & COMPAT_HAS_JOURNAL:
        kind = "ext3"
    else:
        kind = "ext2"
    sb = {
        "fstype": kind,
        "inodes_count": inodes, "blocks_count": blocks,
        "r_blocks_count": r_blocks_lo | ((r_blocks_hi << 32) if is64 else 0),
        "free_blocks": free_blocks_lo | ((free_blocks_hi << 32) if is64 else 0),
        "free_inodes": free_inodes, "first_data_block": first_data_block,
        "block_size": bs, "cluster_bits": cluster_bits, "cluster_size": bs << cluster_bits,
        "blocks_per_group": bpg, "clusters_per_group": cpg, "inodes_per_group": ipg,
        "mtime": mtime, "wtime": wtime, "mkfs_time": mkfs_time, "state": state, "errors": errors,
        "rev_level": rev_level, "minor_rev_level": minor_rev,
        "first_ino": first_ino, "inode_size": inode_size, "block_group_nr": group_nr,
        "feature_compat": f_compat, "feature_incompat": f_incompat, "feature_ro_compat": f_ro,
        "uuid_bytes": bytes(buf[0x68:0x78]), "uuid": _uuid_str(bytes(buf[0x68:0x78])),
        "label": _cstr(buf[0x78:0x88]), "last_mounted": _cstr(buf[0x88:0xC8]),
        "reserved_gdt_blocks": reserved_gdt,
        "journal_uuid": _uuid_str(bytes(buf[0xD0:0xE0])) if any(buf[0xD0:0xE0]) else "",
        "journal_inum": journal_inum, "journal_dev": journal_dev, "last_orphan": last_orphan,
        "def_hash_version": def_hash, "jnl_backup_type": jnl_backup_type, "jnl_blocks": bytes(buf[0x10C:0x150]),
        "desc_size": desc_size, "first_meta_bg": first_meta_bg,
        "min_extra_isize": min_extra, "want_extra_isize": want_extra, "log_groups_per_flex": log_gpf,
        "backup_bgs": backup_bgs, "checksum_seed": csum_seed,
        "system_inodes": tuple(i for i in quota + (orphan_file,) if i),     # quota files, the orphan file
        "groups": groups, "size": blocks * bs,
    }
    sb["features"] = _features(sb)
    return sb


def superblock_offset(sb: dict) -> int:
    """Where this superblock copy sits inside its volume: byte 1024 for the main one, the first block of group
    ``block_group_nr`` for a backup. A copy found at device offset X belongs to a volume that starts at
    ``X - superblock_offset(sb)``, which ExtReader opens with ``info={"sb_offset": superblock_offset(sb)}``."""
    g = sb["block_group_nr"]
    if g == 0:
        return SB_OFFSET
    return (sb["first_data_block"] + g * sb["blocks_per_group"]) * sb["block_size"]


def group_has_super(sb: dict, group: int) -> bool:
    """Whether GROUP holds a superblock backup (and a copy of the group descriptors)."""
    if group == 0:
        return True
    if sb["feature_compat"] & COMPAT_SPARSE_SUPER2:
        return group in sb["backup_bgs"]
    if not sb["feature_ro_compat"] & RO_COMPAT_SPARSE_SUPER or group == 1:
        return True
    if group & 1 == 0:
        return False
    for base in (3, 5, 7):
        n = base
        while n < group:
            n *= base
        if n == group:
            return True
    return False


# ---------------------------------------------------------------------- small helpers
def _time(sec: int, extra: int | None) -> float | None:
    """An inode timestamp: signed 32-bit seconds, plus 2 epoch bits and nanoseconds when the inode is large."""
    if sec == 0 and not extra:
        return None
    s = sec - (1 << 32) if sec & 0x80000000 else sec
    if extra is None:
        return float(s)
    return s + ((extra & 3) << 32) + (extra >> 2) / 1e9


def _decode_name(raw: bytes, encrypted: bool = False) -> str:
    """A folder entry name (bytes on disk) as text. Names that aren't UTF-8 keep their bytes as surrogate escapes
    (os.fsencode restores them); encrypted names are shown the way fscrypt shows them without the key."""
    if encrypted:
        text = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return "~enc~" + (text if len(text) <= 160 else text[:150] + f"~{len(raw)}")
    try:
        name = raw.decode("utf-8")
    except UnicodeDecodeError:
        name = raw.decode("utf-8", "surrogateescape")
    if "/" in name or "\0" in name:
        name = name.replace("/", "_").replace("\0", "_")
    return name


def _plausible_name(raw: bytes) -> bool:
    """For names found in slack space: real names are UTF-8 without control characters, never '.' or '..'."""
    if not raw or raw in (b".", b"..") or b"/" in raw or b"\0" in raw:
        return False
    if min(raw) < 0x20 or 0x7F in raw:
        return False
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


_MAGIC_EXT = (
    (0, b"\xff\xd8\xff", ".jpg"), (0, b"\x89PNG\r\n\x1a\n", ".png"), (0, b"GIF8", ".gif"), (0, b"%PDF-", ".pdf"),
    (0, b"PK\x03\x04", ".zip"), (0, b"\x1f\x8b", ".gz"), (0, b"BZh", ".bz2"), (0, b"\xfd7zXZ\x00", ".xz"),
    (0, b"7z\xbc\xaf\x27\x1c", ".7z"), (0, b"Rar!\x1a\x07", ".rar"), (0, b"ID3", ".mp3"), (0, b"OggS", ".ogg"),
    (0, b"fLaC", ".flac"), (0, b"SQLite format 3\x00", ".sqlite"), (0, b"\xd0\xcf\x11\xe0", ".doc"),
    (0, b"II*\x00", ".tif"), (0, b"MM\x00*", ".tif"), (0, b"BM", ".bmp"), (4, b"ftyp", ".mp4"),
    (0, b"\x28\xb5\x2f\xfd", ".zst"), (0, b"ustar", ""), (257, b"ustar", ".tar"),
)


def guess_extension(head: bytes) -> str:
    """A file name extension for a nameless file, from its first bytes (only the obvious cases)."""
    for off, magic, ext in _MAGIC_EXT:
        if head[off:off + len(magic)] == magic:
            if magic == b"RIFF":
                break
            return ext
    if head[:4] == b"RIFF" and len(head) >= 12:
        return {b"WAVE": ".wav", b"AVI ": ".avi", b"WEBP": ".webp"}.get(head[8:12], "")
    if head[:2] == b"#!":
        return ".sh"
    sample = head[:512]
    if sample and all(32 <= b < 127 or b in (9, 10, 13) for b in sample):
        return ".txt"
    return ""


class _Inode:
    """The parts of an on-disk inode the reader needs (parsed once, from the disk or from a journal copy)."""

    __slots__ = ("ino", "mode", "uid", "gid", "size", "atime", "ctime", "mtime", "crtime", "dtime", "links",
                 "flags", "iblock", "gen", "file_acl", "extra_isize", "blocks", "raw", "age")

    def __init__(self, ino: int, raw: bytes, large_dirs: bool):
        (mode, uid, size_lo, atime, ctime, mtime, dtime, gid, links, blocks_lo,
         flags) = _INODE.unpack_from(raw, 0)
        gen, acl_lo, size_hi = struct.unpack_from("<III", raw, 0x64)
        blocks_hi, acl_hi, uid_hi, gid_hi = struct.unpack_from("<HHHH", raw, 0x74)
        self.ino = ino
        self.raw = raw
        self.mode = mode
        self.uid = uid | (uid_hi << 16)
        self.gid = gid | (gid_hi << 16)
        kind = mode & S_IFMT
        self.size = size_lo | (size_hi << 32) if kind != S_IFDIR or large_dirs else size_lo
        self.dtime = dtime
        self.links = links
        self.flags = flags
        self.iblock = raw[0x28:0x64]
        self.gen = gen
        self.file_acl = acl_lo | (acl_hi << 32)
        self.blocks = blocks_lo | (blocks_hi << 32)
        self.age: int | None = None        # set on journal copies (newer copies have a bigger age)
        extra = 0
        if len(raw) > 128:
            extra = struct.unpack_from("<H", raw, 0x80)[0]
            if extra & 3 or 128 + extra > len(raw):
                extra = 0
        self.extra_isize = extra

        def x(off: int) -> int | None:
            return struct.unpack_from("<I", raw, off)[0] if extra >= off - 128 + 4 else None

        self.ctime = _time(ctime, x(0x84))
        self.mtime = _time(mtime, x(0x88))
        self.atime = _time(atime, x(0x8C))
        cr = x(0x90)
        self.crtime = _time(cr, x(0x94)) if cr else None

    @property
    def kind(self) -> int:
        return self.mode & S_IFMT

    def is_dir(self) -> bool:
        return self.mode & S_IFMT == S_IFDIR


class _Group:
    __slots__ = ("block_bitmap", "inode_bitmap", "inode_table", "flags", "itable_unused", "ok", "stale")

    def __init__(self, bb: int, ib: int, it: int, flags: int, unused: int, ok: bool, stale: bool):
        self.block_bitmap = bb
        self.inode_bitmap = ib
        self.inode_table = it
        self.flags = flags                   # BG_*_UNINIT (only with uninit_bg / metadata_csum)
        self.itable_unused = unused          # inodes at the end of the table never used
        self.ok = ok                         # the descriptor points inside the volume
        self.stale = stale                   # from a backup copy: flags and counters date from mkfs


class _DirInfo:
    """What the walk remembers about a folder to look for its deleted entries afterwards."""

    __slots__ = ("key", "ino", "gen", "blocks", "live", "dead", "encrypted", "inline")

    def __init__(self, key, inode: _Inode, blocks: list[tuple[int, int]], live: set, dead: list):
        self.key = key                   # the folder's entry key (its children's parent)
        self.ino = inode.ino
        self.gen = inode.gen
        self.blocks = blocks             # (logical, physical) blocks whose journal copies may hold old names
        self.live = live                 # {(name, inode)} it has now
        self.dead = dead                 # old entries already found on the disk [(inode, name, type)]
        self.encrypted = bool(inode.flags & EXT4_ENCRYPT_FL)
        self.inline = bool(inode.flags & EXT4_INLINE_DATA_FL)   # its entries live in the inode itself


# ---------------------------------------------------------------------- the reader
class ExtReader(FsReader):
    """ext2/ext3/ext4 reader. Keys are inode numbers for existing files (root 2), "h<inode>.<n>" for further
    names of a hard-linked inode, "d<inode>" and "d<inode>.<n>" for deleted entries."""

    fstype = "ext4"
    name = "ext4"
    root_key = ROOT_INO
    deleted_support = True

    def __init__(self, src: Source, info: dict | None = None):
        super().__init__(src, info)
        sb_off = int(self.info.get("sb_offset") or SB_OFFSET)
        sb = parse_superblock(src.read(sb_off, 1024))
        if sb is None and "sb_offset" not in self.info:
            sb_off, sb = self.find_backup(src)
        if sb is None or sb["fstype"] == "jbd2":
            raise FormatError("No ext2/ext3/ext4 superblock")
        self.sb = sb
        self.sb_offset = sb_off
        self.stale = sb_off != SB_OFFSET          # a backup: its descriptors' flags and counters are from mkfs time
        if self.stale:
            self.warn(f"The main superblock is damaged: the filesystem was opened through the backup in group "
                      f"{sb['block_group_nr']}.")
        self.fstype = sb["fstype"]
        self.name = sb["fstype"]
        self.bs = sb["block_size"]
        self.block_size = self.bs
        self.label = sb["label"]
        self.blocks_count = sb["blocks_count"]
        self.inodes_count = sb["inodes_count"]
        self.ipg = sb["inodes_per_group"]
        self.bpg = sb["blocks_per_group"]
        self.isize = sb["inode_size"]
        self.first_ino = sb["first_ino"]
        inc, ro = sb["feature_incompat"], sb["feature_ro_compat"]
        self.filetype = bool(inc & INCOMPAT_FILETYPE)
        self.large_dirs = bool(inc & INCOMPAT_LARGEDIR)
        self.csum = bool(ro & RO_COMPAT_METADATA_CSUM)
        self.gdt_csum = bool(ro & (RO_COMPAT_GDT_CSUM | RO_COMPAT_METADATA_CSUM))
        if self.csum:
            self.csum_seed = sb["checksum_seed"] if inc & INCOMPAT_CSUM_SEED else crc32c(sb["uuid_bytes"])
        else:
            self.csum_seed = 0
        if sb["size"] > src.size + self.bs:
            self.warn(f"The volume is smaller than the filesystem it holds ({src.size} of {sb['size']} bytes): "
                      f"files at the end are cut short.")
        self.vsrc: Source = src                 # metadata as the kernel would see it (see _replay)
        self.meta = CachedSource(src, block=64 * 1024, blocks=1024)
        self.itable_blocks = (self.ipg * self.isize + self.bs - 1) // self.bs
        self._setup_groups()
        self._bitmaps: dict[int, int] = {}
        self._ibitmaps: dict[int, bytes] = {}
        self._live = bytearray(self.inodes_count // 8 + 1)     # inodes listed so far (bit per inode)
        self._links: dict[int, int] = {}
        self._count = 0
        self.journal: _Journal | None = None    # set by entries() when deleted files are looked for
        self._log: _Journal | None = None
        if sb["feature_compat"] & COMPAT_HAS_JOURNAL and 0 < sb["journal_inum"] < self.first_ino:
            self._log = _Journal(self)
            if self._log.ok and self._log.start:
                self._replay()

    def _setup_groups(self) -> None:
        self.groups = self._read_groups()
        self.inodes_count = min(self.sb["inodes_count"], len(self.groups) * self.ipg)
        self._it_index = sorted((g.inode_table, g.inode_table + self.itable_blocks, i)
                                for i, g in enumerate(self.groups) if g.ok)
        self._it_starts = [t[0] for t in self._it_index]

    def _replay(self) -> None:
        """The filesystem wasn't unmounted cleanly: the journal holds committed changes that never reached their
        place. Read metadata as the kernel would see it after replaying them (nothing is written)."""
        log = self._log
        log.scan(NULL_CONTROL)
        blocks = log.replay()
        if not blocks:
            return
        self.vsrc = _Replayed(self.src, self.bs, log, blocks)
        self.meta = CachedSource(self.vsrc, block=64 * 1024, blocks=1024)
        self._setup_groups()                 # the descriptors may have changed too
        self.warn(f"The filesystem wasn't unmounted cleanly: {len(blocks)} metadata block(s) were read from the "
                  f"journal, as Linux would replay them.")

    # ------------------------------------------------------------------ probing
    @classmethod
    def probe(cls, src: Source) -> dict | None:
        sb = parse_superblock(src.read(SB_OFFSET, 1024))
        if sb is None or sb["fstype"] == "jbd2" or sb["block_group_nr"] != 0:
            return None
        return cls._info(sb)

    @staticmethod
    def _info(sb: dict) -> dict:
        bs = sb["block_size"]
        free = min(sb["free_blocks"], sb["blocks_count"]) * bs
        return {
            "fstype": sb["fstype"], "label": sb["label"], "uuid": sb["uuid"], "size": sb["size"],
            "block_size": bs, "cluster_size": sb["cluster_size"], "free": free, "used": sb["size"] - free,
            "version": sb["fstype"], "last_mount": sb["last_mounted"], "features": sb["features"],
            "inodes": sb["inodes_count"], "free_inodes": sb["free_inodes"], "inode_size": sb["inode_size"],
            "groups": sb["groups"], "journal": bool(sb["feature_compat"] & COMPAT_HAS_JOURNAL),
            "clean": bool(sb["state"] & 1) and not sb["feature_incompat"] & INCOMPAT_RECOVER,
            "created": sb["mkfs_time"] or None, "written": sb["wtime"] or None,
        }

    @classmethod
    def find_backup(cls, src: Source) -> tuple[int, dict | None]:
        """Look for the superblock copy of group 1 at the places mke2fs puts it for the usual block sizes:
        (offset, superblock) or (1024, None)."""
        for bs in (4096, 1024, 2048, 8192, 16384, 32768, 65536):
            first = 1 if bs == 1024 else 0
            off = (8 * bs + first) * bs
            if off + 1024 > src.size:
                continue
            sb = parse_superblock(src.read(off, 1024))
            if sb and sb["block_size"] == bs and sb["block_group_nr"] == 1 and sb["fstype"] != "jbd2":
                return off, sb
        return SB_OFFSET, None

    # ------------------------------------------------------------------ geometry
    def _group_first_block(self, g: int) -> int:
        return self.sb["first_data_block"] + g * self.bpg

    def _gdt_location(self, nr: int, base: int) -> int:
        """Block of descriptor block NR (meta_bg spreads them over the volume)."""
        sb = self.sb
        if not sb["feature_incompat"] & INCOMPAT_META_BG or nr < sb["first_meta_bg"]:
            return base + nr
        per_block = self.bs // sb["desc_size"]
        bg = per_block * nr
        has = 1 if group_has_super(sb, bg) else 0
        if self.bs == 1024 and nr == 0 and sb["first_data_block"] == 0:
            has += 1
        return self._group_first_block(bg) + has

    def _parse_desc(self, d: bytes) -> tuple[int, int, int, int, int]:
        bb, ib, it = struct.unpack_from("<III", d, 0)
        flags = struct.unpack_from("<H", d, 0x12)[0]
        unused = struct.unpack_from("<H", d, 0x1C)[0]
        if self.sb["desc_size"] >= 64 and self.sb["feature_incompat"] & INCOMPAT_64BIT:
            bbh, ibh, ith = struct.unpack_from("<III", d, 0x20)
            bb |= bbh << 32
            ib |= ibh << 32
            it |= ith << 32
            unused |= struct.unpack_from("<H", d, 0x32)[0] << 16
        return bb, ib, it, flags, unused

    def _desc_ok(self, bb: int, ib: int, it: int) -> bool:
        lo, hi = self.sb["first_data_block"], self.blocks_count
        return lo <= bb < hi and lo <= ib < hi and lo <= it and it + self.itable_blocks <= hi

    def _read_groups(self) -> list[_Group]:
        sb = self.sb
        n = sb["groups"]
        # groups that start past the end of the volume can't be read anyway (a truncated image, or a damaged
        # block count): don't let them cost gigabytes of descriptors
        n = min(n, (self.src.size // self.bs - sb["first_data_block"]) // self.bpg + 1)
        ds = sb["desc_size"]
        per_block = self.bs // ds
        nblocks = (n + per_block - 1) // per_block
        base = self.sb_offset // self.bs + 1
        meta_bg = bool(sb["feature_incompat"] & INCOMPAT_META_BG)
        if not meta_bg:
            raw = self.vsrc.read(base * self.bs, nblocks * self.bs)
        else:
            raw = b"".join(self.meta.read(self._gdt_location(nr, base) * self.bs, self.bs) for nr in range(nblocks))
        groups: list[_Group] = []
        bad = 0
        for g in range(n):
            bb, ib, it, flags, unused = self._parse_desc(raw[g * ds:(g + 1) * ds])
            if not self.gdt_csum:
                flags, unused = 0, 0
            ok = self._desc_ok(bb, ib, it)
            stale = self.stale
            if not ok and not meta_bg:
                alt = self._backup_desc(g, base)
                if alt is not None:
                    bb, ib, it = alt
                    ok, stale = True, True
            if not ok:
                bad += 1
            if stale:
                flags &= BG_BLOCK_UNINIT
                unused = 0
            if unused > self.ipg:
                unused = 0
            groups.append(_Group(bb, ib, it, flags, unused, ok, stale))
        if bad:
            self.warn(f"{bad} block group descriptor(s) are damaged: the files whose inodes live there are missing.")
        return groups

    def _backup_desc(self, g: int, primary: int) -> tuple[int, int, int] | None:
        """Descriptor G from the backup copies (groups 1, 3, 5, 7, 9...) when the primary one is garbage."""
        ds = self.sb["desc_size"]
        nr, idx = divmod(g * ds, self.bs)
        tried = 0
        for bg in range(1, self.sb["groups"]):
            if not group_has_super(self.sb, bg):
                continue
            loc = self._group_first_block(bg) + 1 + nr
            if loc == primary + nr:
                continue
            d = self.meta.read(loc * self.bs + idx, ds)
            bb, ib, it, _f, _u = self._parse_desc(d)
            if self._desc_ok(bb, ib, it):
                return bb, ib, it
            tried += 1
            if tried >= 4:
                break
        return None

    # ------------------------------------------------------------------ inodes
    def _inode_pos(self, ino: int) -> int | None:
        if not 1 <= ino <= self.inodes_count:
            return None
        g, idx = divmod(ino - 1, self.ipg)
        if g >= len(self.groups) or not self.groups[g].ok:
            return None
        return self.groups[g].inode_table * self.bs + idx * self.isize

    def _inode_block(self, ino: int) -> tuple[int, int] | None:
        """(filesystem block, offset in it) of inode INO."""
        pos = self._inode_pos(ino)
        return None if pos is None else divmod(pos, self.bs)

    def read_inode(self, ino: int) -> _Inode | None:
        pos = self._inode_pos(ino)
        if pos is None:
            return None
        return _Inode(ino, self.meta.read(pos, self.isize), self.large_dirs)

    def _inode_bitmap(self, g: int) -> bytes | None:
        bm = self._ibitmaps.get(g)
        if bm is None:
            grp = self.groups[g]
            if grp.flags & BG_INODE_UNINIT:
                bm = bytes((self.ipg + 7) // 8)
            else:
                bm = self.meta.read(grp.inode_bitmap * self.bs, (self.ipg + 7) // 8)
            if len(self._ibitmaps) > 4096:
                self._ibitmaps.clear()
            self._ibitmaps[g] = bm
        return bm

    def _mark(self, ino: int) -> None:
        if 0 < ino <= self.inodes_count:
            self._live[ino >> 3] |= 1 << (ino & 7)

    def _marked(self, ino: int) -> bool:
        return 0 < ino <= self.inodes_count and bool(self._live[ino >> 3] & (1 << (ino & 7)))

    def _inode_csum_ok(self, ino: int, raw: bytes) -> bool:
        """metadata_csum: does this inode image carry a valid checksum for inode number INO? (Proves that a copy
        found in the journal really is that inode, and isn't torn.)"""
        gen = struct.unpack_from("<I", raw, 0x64)[0]
        seed = crc32c(struct.pack("<I", gen), crc32c(struct.pack("<I", ino), self.csum_seed))
        c = crc32c(raw[:0x7C], seed)
        c = crc32c(b"\0\0", c)
        c = crc32c(raw[0x7E:128], c)
        stored = struct.unpack_from("<H", raw, 0x7C)[0]
        size = len(raw)
        if size > 128:
            extra = struct.unpack_from("<H", raw, 0x80)[0]
            c = crc32c(raw[128:0x82], c)
            if extra >= 4:
                c = crc32c(b"\0\0", c)
                c = crc32c(raw[0x84:size], c)
                stored |= struct.unpack_from("<H", raw, 0x82)[0] << 16
                return c == stored
            c = crc32c(raw[0x82:size], c)
        return c & 0xFFFF == stored

    # ------------------------------------------------------------------ metadata blocks
    def _block_ok(self, pblk: int, n: int = 1) -> bool:
        return self.sb["first_data_block"] <= pblk and pblk + n <= self.blocks_count

    def _meta_block(self, pblk: int, check: Callable[[bytes], bool], age: int | None) -> bytes | None:
        """A metadata block (extent node, indirect block) that passes CHECK. Existing files read it from the disk.
        A file rebuilt from a journal copy of its inode (AGE set) prefers the copies of the block that the
        journal logged up to that moment, then the disk, then later copies."""
        if not self._block_ok(pblk):
            return None
        if age is None or self.journal is None:
            b = self.meta.read(pblk * self.bs, self.bs)
            return b if check(b) else None
        copies = self.journal.copies.get(pblk, [])
        for a, jpos, esc in copies:
            if a <= age:
                b = self.journal.read(jpos, esc)
                if check(b):
                    return b
        b = self.meta.read(pblk * self.bs, self.bs)
        if check(b):
            return b
        for a, jpos, esc in copies:
            if a > age:
                b = self.journal.read(jpos, esc)
                if check(b):
                    return b
        return None

    # ------------------------------------------------------------------ content maps
    def _extents(self, inode: _Inode, strict: bool) -> list[tuple[int, int, int, bool]] | None:
        """The extent tree of INODE as (logical block, physical block, count, uninitialised), sorted. None when the
        tree is unusable. STRICT (deleted files) rejects trees with a damaged part instead of skipping it."""
        root = inode.iblock
        magic, entries, mx, depth, _gen = _EXT_HDR.unpack_from(root, 0)
        if magic != EXT_MAGIC or depth > MAX_DEPTH or mx > 4 or entries > mx:
            return None
        out: list[tuple[int, int, int, bool]] = []
        visited: set[int] = set()
        per_block = (self.bs - 12) // 12
        damaged = False

        def check_for(level: int) -> Callable[[bytes], bool]:
            def check(b: bytes) -> bool:
                m, e, x, d, _g = _EXT_HDR.unpack_from(b, 0)
                return m == EXT_MAGIC and d == level and 0 < x <= per_block and e <= x and (e > 0 or not strict)
            return check

        stack: list[tuple[bytes, int, int]] = [(root, entries, depth)]
        while stack:
            buf, n, level = stack.pop()
            if level == 0:
                for i in range(n):
                    lblk, ln, hi, lo = _EXT_LEAF.unpack_from(buf, 12 + 12 * i)
                    uninit = ln > 32768
                    if uninit:
                        ln -= 32768
                    pblk = (hi << 32) | lo
                    if ln == 0:
                        continue
                    if not self._block_ok(pblk, ln):
                        damaged = True
                        continue
                    out.append((lblk, pblk, ln, uninit))
                    if len(out) > MAX_EXTENTS:
                        return None
                continue
            children = []
            for i in range(n):
                _lb, lo, hi, _u = _EXT_IDX.unpack_from(buf, 12 + 12 * i)
                child = (hi << 32) | lo
                if child in visited or len(visited) > MAX_EXTENTS // 16:
                    damaged = True
                    continue
                visited.add(child)
                b = self._meta_block(child, check_for(level - 1), inode.age)
                if b is None:
                    damaged = True
                    continue
                e = _EXT_HDR.unpack_from(b, 0)[1]
                children.append((b, e, level - 1))
            stack.extend(reversed(children))
        if damaged:
            if strict:
                return None
            self.warn(f"The extent tree of inode {inode.ino} is damaged: parts of the file are missing.")
        out.sort()
        clean: list[tuple[int, int, int, bool]] = []
        end = 0
        for ext in out:                      # drop overlapping extents (corruption)
            if ext[0] >= end:
                clean.append(ext)
                end = ext[0] + ext[2]
        return clean

    def _blockmap(self, inode: _Inode, nblocks: int, strict: bool) -> list[tuple[int, int, int, bool]] | None:
        """The classic ext2/ext3 block map (12 direct pointers, then indirect, double and triple indirect blocks)
        as extents. A zero pointer is a hole. The walk visits blocks in logical order, so neighbours are joined
        on the way (a 2 TiB file doesn't become half a billion pairs)."""
        ptrs = struct.unpack_from("<15I", inode.iblock, 0)
        per = self.bs // 4
        nblocks = min(nblocks, 12 + per + per * per + per * per * per)
        out: list[tuple[int, int, int, bool]] = []
        cur = [0, 0, 0]                          # the extent being built: logical, physical, count
        damaged = False
        hi = self.blocks_count
        lo = self.sb["first_data_block"]
        unpack = struct.Struct(f"<{per}I").unpack_from

        def ind_check(b: bytes) -> bool:
            m = max(unpack(b, 0))
            return m < hi and (m > 0 or not strict)

        def add(lb: int, pb: int) -> None:
            if cur[2] and cur[0] + cur[2] == lb and cur[1] + cur[2] == pb:
                cur[2] += 1
                return
            if cur[2]:
                out.append((cur[0], cur[1], cur[2], False))
            cur[0], cur[1], cur[2] = lb, pb, 1

        for i in range(min(12, nblocks)):
            p = ptrs[i]
            if p:
                if lo <= p < hi:
                    add(i, p)
                else:
                    damaged = True
        visited: set[int] = set()
        base = 12
        for level, root in ((1, ptrs[12]), (2, ptrs[13]), (3, ptrs[14])):
            if base >= nblocks:
                break
            if root:
                stack = [(root, level, base)]
                while stack:
                    blk, lev, start = stack.pop()
                    if blk in visited or not lo <= blk < hi:
                        damaged = True
                        continue
                    visited.add(blk)
                    b = self._meta_block(blk, ind_check, inode.age)
                    if b is None:
                        damaged = True
                        continue
                    vals = unpack(b, 0)
                    if lev == 1:
                        for i in range(min(per, nblocks - start)):
                            p = vals[i]
                            if p:
                                add(start + i, p)
                        if len(out) > MAX_EXTENTS:
                            return None
                    else:
                        sub = per ** (lev - 1)
                        for i in range(min(per, (nblocks - start + sub - 1) // sub) - 1, -1, -1):
                            if vals[i]:
                                stack.append((vals[i], lev - 1, start + i * sub))
            base += per ** level
        if cur[2]:
            out.append((cur[0], cur[1], cur[2], False))
        if damaged:
            if strict:
                return None
            self.warn(f"The block map of inode {inode.ino} is damaged: parts of the file are missing.")
        return out

    def _map(self, inode: _Inode, strict: bool = False) -> list[tuple[int, int, int, bool]] | None:
        nblocks = (inode.size + self.bs - 1) // self.bs
        if inode.flags & EXT4_EXTENTS_FL:
            return self._extents(inode, strict)
        if self.sb["feature_incompat"] & INCOMPAT_EXTENTS and _EXT_HDR.unpack_from(inode.iblock, 0)[0] == EXT_MAGIC:
            return self._extents(inode, strict)
        return self._blockmap(inode, nblocks, strict)

    def _runs(self, extents: list[tuple[int, int, int, bool]], size: int) -> tuple[list[tuple[int, int]], bool]:
        """Extents → (byte runs for ``size`` bytes, has holes). Gaps and uninitialised extents read as zeros."""
        bs = self.bs
        runs: list[tuple[int, int]] = []
        pos = 0
        sparse = False
        nblocks = (size + bs - 1) // bs
        for lblk, pblk, n, uninit in extents:
            if lblk >= nblocks:
                break
            if lblk > pos:
                runs.append((-1, (lblk - pos) * bs))
                sparse = True
            n = min(n, nblocks - lblk)
            if uninit:
                runs.append((-1, n * bs))
                sparse = True
            else:
                runs.append((pblk * bs, n * bs))
            pos = lblk + n
        if pos < nblocks:
            runs.append((-1, (nblocks - pos) * bs))
            sparse = True
        return merge_runs(runs), sparse

    def _inline_data(self, inode: _Inode) -> bytes:
        """inline_data: the first 60 bytes live in i_block, the rest in the "system.data" extended attribute
        stored in the inode's extra space."""
        return bytes(inode.iblock) + self._ibody_xattr(inode.raw, inode.extra_isize, 7, b"data")

    def _ibody_xattr(self, raw: bytes, extra_isize: int, index: int, name: bytes) -> bytes:
        start = 128 + extra_isize
        if start + 4 > len(raw) or struct.unpack_from("<I", raw, start)[0] != 0xEA020000:
            return b""
        first = start + 4
        o = first
        end = len(raw)
        for _ in range(64):
            if o + 16 > end or struct.unpack_from("<I", raw, o)[0] == 0:
                break
            nlen, nidx, voff, vinum, vsize = struct.unpack_from("<BBHII", raw, o)
            ename = raw[o + 16:o + 16 + nlen]
            if nidx == index and ename == name and not vinum:
                if first + voff + vsize <= end:
                    return bytes(raw[first + voff:first + voff + vsize])
                return b""
            o += (16 + nlen + 3) & ~3
        return b""

    def _content(self, inode: _Inode, strict: bool = False) -> dict | None:
        """How to read a file: {"size", "runs" | "data", "flags", "blocks": used extents}. None when nothing usable
        is left (deleted files)."""
        kind = inode.kind
        flags = 0
        if inode.flags & EXT4_ENCRYPT_FL:
            flags |= F_ENCRYPTED
        size = inode.size
        if kind == S_IFLNK:
            flags |= F_SYMLINK
            if strict and not size:
                return None
            if inode.flags & EXT4_INLINE_DATA_FL:
                return {"size": size, "data": self._inline_data(inode)[:size], "flags": flags | F_RESIDENT,
                        "blocks": []}
            acl_blocks = (self.bs >> 9) if inode.file_acl else 0
            fast = size < 60 and not inode.flags & EXT4_EXTENTS_FL and inode.blocks - acl_blocks <= 0
            if fast or (size < 60 and inode.blocks == 0):
                return {"size": size, "data": bytes(inode.iblock[:size]), "flags": flags | F_RESIDENT, "blocks": []}
            ext = self._map(inode, strict)
            if not ext:
                return None if strict else {"size": 0, "data": b"", "flags": flags | F_PARTIAL, "blocks": []}
            runs, _sp = self._runs(ext, min(size, 65536))
            data = b"".join(self.meta.read(o, n) if o >= 0 else bytes(n) for o, n in runs)[:size]
            return {"size": len(data), "data": data, "flags": flags, "blocks": ext}
        if kind != S_IFREG:
            return {"size": 0, "flags": flags, "blocks": []}
        if inode.flags & EXT4_INLINE_DATA_FL:
            if strict and not size:
                return None
            data = self._inline_data(inode)[:size]
            if len(data) < size:                 # the extended attribute holding the rest is damaged
                flags |= F_PARTIAL
            return {"size": len(data), "data": data, "flags": flags | F_RESIDENT, "blocks": []}
        if size == 0:
            return None if strict else {"size": 0, "runs": [], "flags": flags, "blocks": []}
        ext = self._map(inode, strict)
        if ext is None:
            if strict:
                return None
            return {"size": size, "runs": [], "flags": flags | F_PARTIAL, "blocks": []}
        if strict and not any(not u for _l, _p, _n, u in ext):
            return None
        runs, sparse = self._runs(ext, size)
        if sparse:
            flags |= F_SPARSE
        return {"size": size, "runs": runs, "flags": flags, "blocks": ext}

    # ------------------------------------------------------------------ folders
    def _dir_blocks(self, inode: _Inode, strict: bool = False) -> list[tuple[int, int]]:
        """(logical, physical) blocks of a folder, in logical order."""
        ext = self._map(inode, strict)
        if not ext:
            return []
        nblocks = (inode.size + self.bs - 1) // self.bs if inode.size else 0
        if nblocks <= 0 or nblocks > MAX_DIR_BLOCKS:
            nblocks = MAX_DIR_BLOCKS
        out: list[tuple[int, int]] = []
        for lblk, pblk, n, uninit in ext:
            if uninit:
                continue
            for k in range(n):
                if lblk + k >= nblocks:
                    break
                out.append((lblk + k, pblk + k))
            if len(out) >= MAX_DIR_BLOCKS:
                break
        return out

    def _read_blocks(self, blocks: list[tuple[int, int]]) -> Iterator[tuple[int, int, bytes]]:
        """(logical, physical, data) for BLOCKS, reading neighbours together."""
        bs = self.bs
        i = 0
        while i < len(blocks):
            j = i + 1
            while (j < len(blocks) and blocks[j][1] == blocks[j - 1][1] + 1 and (j - i) * bs < READ_CHUNK):
                j += 1
            if j - i == 1:
                data = self.meta.read(blocks[i][1] * bs, bs)
            else:
                data = self.vsrc.read(blocks[i][1] * bs, (j - i) * bs)
            for k in range(i, j):
                o = (k - i) * bs
                yield blocks[k][0], blocks[k][1], data[o:o + bs]
            i = j

    def _is_dx_node(self, buf: bytes) -> bool:
        """An htree interior node: one fake empty entry covering the block, then the index."""
        ino, rl, nl, ft = _DIRENT.unpack_from(buf, 0)
        if ino or nl or self._rec_len(rl) != len(buf):
            return False
        limit, count = struct.unpack_from("<HH", buf, 8)
        return limit in ((len(buf) - 8) // 8, (len(buf) - 16) // 8) and 0 < count <= limit

    def _rec_len(self, rl: int) -> int:
        if self.bs < 65536:
            return rl
        if rl in (0, 65535):
            return self.bs
        return (rl & 65532) | ((rl & 3) << 16)

    def _dirents(self, buf: bytes, live: list, dead: list | None, block0: bool = False) -> None:
        """Parse one folder block: entries in use go to LIVE as (inode, name bytes, file type); when DEAD is a
        list, plausible old entries found in the slack space go there too."""
        n = len(buf)
        if n < 12 or self._is_dx_node(buf):
            return
        end = n
        if n >= 12 and buf[n - 12:n - 8] == b"\0\0\0\0" and buf[n - 8:n - 4] == b"\x0c\x00\x00\xde":
            end = n - 12                     # metadata_csum tail
        o = 0
        icount = self.inodes_count
        while o + 8 <= end:
            ino, rl, nl, ft = _DIRENT.unpack_from(buf, o)
            if not self.filetype:
                nl |= ft << 8
                ft = 0
            rl = self._rec_len(rl)
            if rl < 8 or rl & 3 or o + rl > n or 8 + nl > rl:
                if dead is not None:
                    self._scan_slack(buf, o, end, dead)
                return
            if ino and nl:
                if ino <= icount:
                    live.append((ino, bytes(buf[o + 8:o + 8 + nl]), ft))
            need = (8 + nl + 3) & ~3
            if dead is not None and rl - need >= 12:
                dx_root = (block0 and o == 12 and nl == 2 and buf[o + 8:o + 10] == b".." and o + 32 <= n
                           and struct.unpack_from("<I", buf, 24)[0] == 0 and buf[29] == 8)
                if not dx_root:
                    self._scan_slack(buf, o + need, min(o + rl, end), dead)
            o += rl

    def _scan_slack(self, buf: bytes, start: int, end: int, out: list) -> None:
        """Old entries in the unused tail of an entry (where a deleted neighbour's entry was merged)."""
        p = (start + 3) & ~3
        icount = self.inodes_count
        ft_ok = self.filetype
        while p + 12 <= end:
            ino, rl, nl, ft = _DIRENT.unpack_from(buf, p)
            if not ft_ok:
                nl |= ft << 8
                ft = 0
            if (0 < ino <= icount and 0 < nl and p + 8 + nl <= end and rl >= ((8 + nl + 3) & ~3)
                    and rl & 3 == 0 and rl <= len(buf) and (not ft_ok or 1 <= ft <= 7)):
                name = bytes(buf[p + 8:p + 8 + nl])
                if _plausible_name(name):
                    out.append((ino, name, ft))
                    p += (8 + nl + 3) & ~3
                    continue
            p += 4

    def _inline_dirents(self, inode: _Inode, live: list, dead: list | None) -> int:
        """An inline_data folder: the parent's inode number, then entries in i_block and in system.data."""
        parent = struct.unpack_from("<I", inode.iblock, 0)[0]
        for stream in (bytes(inode.iblock[4:]), self._ibody_xattr(inode.raw, inode.extra_isize, 7, b"data")):
            o = 0
            while o + 8 <= len(stream):
                ino, rl, nl, ft = _DIRENT.unpack_from(stream, o)
                if not self.filetype:
                    nl |= ft << 8
                    ft = 0
                if rl < 8 or rl & 3 or o + rl > len(stream) or 8 + nl > rl:
                    break
                if ino and nl and ino <= self.inodes_count:
                    live.append((ino, bytes(stream[o + 8:o + 8 + nl]), ft))
                need = (8 + nl + 3) & ~3
                if dead is not None and rl - need >= 12:
                    self._scan_slack(stream, o + need, o + rl, dead)
                o += rl
        return parent

    def _list_dir(self, inode: _Inode, slack: bool, strict: bool = False
                  ) -> tuple[list, list, list[tuple[int, int]]]:
        """(entries in use, old entries from slack space, blocks) of a folder inode."""
        live: list = []
        dead: list | None = [] if slack and not inode.flags & EXT4_ENCRYPT_FL else None
        if inode.flags & EXT4_INLINE_DATA_FL:
            self._inline_dirents(inode, live, dead)
            return live, dead or [], []
        blocks = self._dir_blocks(inode, strict)
        for lblk, _pblk, buf in self._read_blocks(blocks):
            self._dirents(buf, live, dead, block0=lblk == 0)
        return live, dead or [], blocks

    # ------------------------------------------------------------------ entries
    def _make_entry(self, key, parent, name: str, inode: _Inode, deleted: bool = False, flags: int = 0,
                    content: dict | None = None) -> Entry:
        is_dir = inode.is_dir()
        e = Entry(key=key, parent=parent, name=name, is_dir=is_dir, deleted=deleted,
                  mtime=inode.mtime, ctime=inode.ctime, atime=inode.atime, crtime=inode.crtime,
                  chance=CHANCE_GOOD, flags=flags,
                  extra={"inode": inode.ino, "mode": inode.mode, "uid": inode.uid, "gid": inode.gid,
                         "links": inode.links})
        if inode.flags & EXT4_ENCRYPT_FL:
            e.flags |= F_ENCRYPTED
        if is_dir:
            return e
        kind = inode.kind
        if kind in _SPECIAL:
            e.extra["special"] = _SPECIAL[kind]
            if kind in (S_IFBLK, S_IFCHR):
                e.extra["rdev"] = struct.unpack_from("<I", inode.iblock, 0)[0] or struct.unpack_from(
                    "<I", inode.iblock, 4)[0]
            return e
        if content is None:
            content = self._content(inode)
        if content is None:
            return e
        e.size = content.get("size", 0)
        e.flags |= content.get("flags", 0)
        if content.get("data") is not None:
            e.data = content["data"]
        else:
            e.runs = content.get("runs") or []
        return e

    def entries(self, ctl: Control = NULL_CONTROL, deleted: bool = True) -> Iterator[Entry]:
        sb = self.sb
        self._live = bytearray(self.inodes_count // 8 + 1)
        self._links = {}
        self._count = 0
        self.journal = None
        for ino in list(range(1, self.first_ino)) + list(sb["system_inodes"]):
            self._mark(ino)                      # reserved inodes, quota files: never user files
        root = self.read_inode(ROOT_INO)
        if root is None or not root.is_dir():
            self.warn("The root folder's inode is damaged: its files are listed under \"Lost files\".")
            yield Entry(key=ROOT_INO, parent=None, name="", is_dir=True, chance=CHANCE_GOOD)
            root = None
        else:
            yield self._safe_entry(ROOT_INO, None, "", root)
        has_journal = bool(sb["feature_compat"] & COMPAT_HAS_JOURNAL)
        if deleted and has_journal:
            if self._log is not None:
                ctl.progress(0.0, "Reading the journal")
                self._log.scan(ctl)
                self.journal = self._log if self._log.ok else None
            elif sb["journal_uuid"]:
                self.warn("This filesystem keeps its journal on another device: deleted files that only the "
                          "journal remembers can't be recovered.")
        jnum = sb["journal_inum"]
        if has_journal and self.first_ino > jnum > 0:
            jinode = self.read_inode(jnum)
            if jinode is not None and jinode.kind == S_IFREG and jinode.size:
                yield self._safe_entry(jnum, ROOT_INO, ".journal", jinode, flags=F_SYSTEM)

        dirinfos: list[_DirInfo] = []
        used = max(1, self.inodes_count - sb["free_inodes"])
        # 1. the tree, from the root
        if root is not None:
            self._mark(ROOT_INO)
            ctl.progress(0.0, "Reading folders")
            yield from self._walk([(ROOT_INO, root)], ctl, deleted, dirinfos, used)
        # 2. inodes in use that no folder reaches; deleted inodes that kept their block map (ext2)
        disk_cands: dict[int, _Inode] = {}
        yield from self._scan_inodes(ctl, deleted, dirinfos, disk_cands, used)
        if not deleted:
            return
        # 3. deleted entries: names from slack space and from journal copies of folder blocks, content from the
        #    inode on disk or from its newest usable copy in the journal
        ctl.progress(0.9, "Looking for deleted files")
        yield from _Undelete(self, ctl, dirinfos, disk_cands).run()
        ctl.progress(1.0, None)

    def _walk(self, start: list[tuple[int, _Inode]], ctl: Control, deleted: bool, dirinfos: list,
              used: int) -> Iterator[Entry]:
        """Breadth-first walk of existing folders from START [(key, inode)]."""
        queue = deque(start)
        journal = self.journal
        while queue:
            dkey, dinode = queue.popleft()
            try:
                live, dead, blocks = self._list_dir(dinode, slack=deleted)
            except (struct.error, ValueError, IndexError, OverflowError) as exc:
                self.warn(f"Folder inode {dinode.ino} is unreadable ({exc}).")
                continue
            encrypted = bool(dinode.flags & EXT4_ENCRYPT_FL)
            names = set()
            for ino, raw, _ft in live:
                if raw in (b".", b".."):
                    continue
                self._count += 1
                if self._count % 256 == 0:
                    ctl.check()
                    ctl.progress(min(0.6, 0.6 * self._count / used), None)
                names.add((raw, ino))
                name = _decode_name(raw, encrypted)
                if self._marked(ino):
                    if ino < self.first_ino:
                        continue                 # a reserved inode (or the root) listed in a folder
                    inode = self.read_inode(ino)
                    if inode is None or inode.is_dir() or inode.mode == 0:
                        continue                 # a folder reached twice: a loop in damaged metadata
                    n = self._links.get(ino, 0) + 1
                    self._links[ino] = n
                    yield self._safe_entry(f"h{ino}.{n}", dkey, name, inode, flags=F_HARDLINK)
                    continue
                inode = self.read_inode(ino)
                if inode is None or inode.mode == 0 or inode.kind not in _VALID_TYPES:
                    self.warn(f"The folder entry \"{name}\" points to an unusable inode ({ino}).")
                    continue
                self._mark(ino)
                yield self._safe_entry(ino, dkey, name, inode)
                if inode.is_dir():
                    queue.append((ino, inode))
            if deleted:
                jblocks = [(lb, pb) for lb, pb in blocks if journal is not None and pb in journal.copies]
                if dinode.flags & EXT4_INLINE_DATA_FL and journal is not None and journal.inode_copies(dinode.ino):
                    jblocks = [(-1, -1)]
                if dead or jblocks:
                    dirinfos.append(_DirInfo(dkey, dinode, jblocks, names, dead))

    def _safe_entry(self, key, parent, name: str, inode: _Inode, flags: int = 0) -> Entry:
        """An existing file's entry; a damaged map gives an entry without content instead of an exception."""
        try:
            return self._make_entry(key, parent, name, inode, flags=flags)
        except (struct.error, ValueError, IndexError, OverflowError) as exc:
            self.warn(f"The map of inode {inode.ino} is unreadable ({exc}).")
            e = Entry(key=key, parent=parent, name=name, is_dir=inode.is_dir(), mtime=inode.mtime,
                      ctime=inode.ctime, atime=inode.atime, crtime=inode.crtime, chance=CHANCE_POOR,
                      flags=flags | F_PARTIAL, extra={"inode": inode.ino, "mode": inode.mode})
            return e

    def _scan_inodes(self, ctl: Control, deleted: bool, dirinfos: list, disk_cands: dict,
                     used: int) -> Iterator[Entry]:
        """Read every inode table: in-use inodes that the walk didn't reach become lost files (a folder brings its
        subtree), deleted inodes that still have a usable block map become recovery candidates."""
        bs, isize, ipg = self.bs, self.isize, self.ipg
        orphans: list[_Inode] = []
        ng = len(self.groups)
        per_read = max(1, READ_CHUNK // isize)
        for g, grp in enumerate(self.groups):
            if g % 8 == 0:
                ctl.check()
                ctl.progress(0.6 + 0.3 * g / ng, "Reading the inode tables")
            if not grp.ok or grp.flags & BG_INODE_UNINIT:
                continue
            n = min(ipg - grp.itable_unused, self.inodes_count - g * ipg)
            if n <= 0:
                continue
            bm = self._inode_bitmap(g)
            base = grp.inode_table * bs
            for first in range(0, n, per_read):
                cnt = min(per_read, n - first)
                table = self.vsrc.read(base + first * isize, cnt * isize)
                ino0 = g * ipg + first + 1
                for k in range(cnt):
                    o = k * isize
                    if table[o] == 0 and table[o + 1] == 0:
                        continue                 # mode 0: never used, or wiped
                    ino = ino0 + k
                    if self._marked(ino):
                        continue
                    idx = first + k
                    in_use = bool(bm[idx >> 3] & (1 << (idx & 7)))
                    inode = _Inode(ino, table[o:o + isize], self.large_dirs)
                    if inode.kind not in _VALID_TYPES:
                        continue
                    if in_use and inode.links > 0:
                        orphans.append(inode)
                    elif deleted and inode.kind in (S_IFREG, S_IFDIR, S_IFLNK):
                        try:
                            if self._usable(inode):
                                disk_cands[ino] = inode
                        except (struct.error, ValueError, IndexError, OverflowError):
                            continue
        if orphans:
            if len(orphans) > 16:
                self.warn(f"{len(orphans)} files in use are in no folder (damaged folders?): they are listed "
                          f"under \"Lost files\".")
            yield from self._orphans(orphans, ctl, deleted, dirinfos, used)

    def _usable(self, inode: _Inode) -> bool:
        """Does this deleted inode (or inode copy) still say where its content is?"""
        if inode.is_dir():
            if inode.flags & EXT4_INLINE_DATA_FL:
                return True
            return bool(self._dir_blocks(inode, strict=True))
        if not inode.size:
            return False
        return self._content(inode, strict=True) is not None

    def _orphans(self, orphans: list[_Inode], ctl: Control, deleted: bool, dirinfos: list,
                 used: int) -> Iterator[Entry]:
        """In-use inodes no folder names: folders whose parent is lost too are reached through that parent."""
        dirs = {i.ino: i for i in orphans if i.is_dir()}
        roots = []
        for ino, inode in dirs.items():
            if self._parent_of(inode) in dirs and self._parent_of(inode) != ino:
                continue
            roots.append(inode)
        for inode in roots + [i for i in orphans if not i.is_dir()] + list(dirs.values()):
            if self._marked(inode.ino):
                continue
            self._mark(inode.ino)
            yield self._safe_entry(inode.ino, None, f"inode {inode.ino}", inode, flags=F_ORPHAN)
            if inode.is_dir():
                yield from self._walk([(inode.ino, inode)], ctl, deleted, dirinfos, used)

    def _parent_of(self, inode: _Inode) -> int:
        """The ".." entry of a folder (0 if unknown)."""
        try:
            if inode.flags & EXT4_INLINE_DATA_FL:
                return struct.unpack_from("<I", inode.iblock, 0)[0]
            blocks = self._dir_blocks(inode)
            if not blocks or blocks[0][0] != 0:
                return 0
            buf = self._meta_block(blocks[0][1], lambda b: True, inode.age)
            if buf is None:
                return 0
            ino, rl, nl, _ft = _DIRENT.unpack_from(buf, 0)
            if ino != inode.ino or rl != 12 or nl & 0xFF != 1 or rl + 12 > len(buf):
                return 0
            pino, _rl, pnl, _pft = _DIRENT.unpack_from(buf, 12)
            return pino if pnl & 0xFF == 2 and buf[20:22] == b".." else 0
        except (struct.error, ValueError, IndexError):
            return 0

    def _dirblock_owner(self, buf: bytes, ino: int, gen: int) -> bool | None:
        """metadata_csum: does this folder block's checksum say it belongs to inode INO (generation GEN)? None when
        the block has no checksum tail (no metadata_csum, or an htree node)."""
        n = len(buf)
        if not self.csum or buf[n - 12:n - 8] != b"\0\0\0\0" or buf[n - 8:n - 4] != b"\x0c\x00\x00\xde":
            return None
        seed = crc32c(struct.pack("<I", gen), crc32c(struct.pack("<I", ino), self.csum_seed))
        return crc32c(buf[:n - 12], seed) == struct.unpack_from("<I", buf, n - 4)[0]

    # ------------------------------------------------------------------ allocation
    def _block_bitmap(self, g: int) -> int | None:
        """Group G's block (cluster) bitmap as an integer, bit i = cluster i of the group. None if unknown."""
        bm = self._bitmaps.get(g)
        if bm is not None:
            return bm
        grp = self.groups[g]
        if not grp.ok:
            return None
        cpg = self.sb["clusters_per_group"]
        nbytes = (cpg + 7) // 8
        if grp.flags & BG_BLOCK_UNINIT:
            raw = self.meta.read(grp.block_bitmap * self.bs, nbytes) if grp.stale else b""
            bm = int.from_bytes(raw, "little") if raw and any(raw) else self._uninit_bitmap(g)
        else:
            bm = int.from_bytes(self.meta.read(grp.block_bitmap * self.bs, nbytes), "little")
        if len(self._bitmaps) > 8192:
            self._bitmaps.clear()
        self._bitmaps[g] = bm
        return bm

    def _uninit_bitmap(self, g: int) -> int:
        """What the kernel assumes for a group whose bitmap was never written: only its own metadata is used."""
        sb = self.sb
        cb = sb["cluster_bits"]
        start = self._group_first_block(g)
        per_block = self.bs // sb["desc_size"]
        meta = 0
        if group_has_super(sb, g):
            meta = 1
            if sb["feature_incompat"] & INCOMPAT_META_BG:
                meta += sb["first_meta_bg"]
            else:
                meta += (sb["groups"] + per_block - 1) // per_block + sb["reserved_gdt_blocks"]
        if sb["feature_incompat"] & INCOMPAT_META_BG and g // per_block >= sb["first_meta_bg"]:
            if g % per_block in (0, 1, per_block - 1):
                meta += 1                        # this meta group's descriptor block (or a backup of it)
        used = (1 << (((meta - 1) >> cb) + 1)) - 1 if meta else 0
        grp = self.groups[g]
        end = start + self.bpg
        for blk, n in ((grp.block_bitmap, 1), (grp.inode_bitmap, 1), (grp.inode_table, self.itable_blocks)):
            for b in range(max(blk, start), min(blk + n, end)):
                used |= 1 << ((b - start) >> cb)
        return used

    def _used_blocks(self, pblk: int, n: int) -> int | None:
        """How many of blocks [pblk, pblk+n) the block bitmaps mark as used (in clusters for bigalloc)."""
        fdb = self.sb["first_data_block"]
        cb = self.sb["cluster_bits"]
        cpg = self.sb["clusters_per_group"]
        first = (pblk - fdb) >> cb
        last = (pblk + n - 1 - fdb) >> cb
        total = 0
        c = first
        while c <= last:
            g, bit = divmod(c, cpg)
            if g >= len(self.groups):
                return None
            take = min(cpg - bit, last - c + 1)
            bm = self._block_bitmap(g)
            if bm is None:
                return None
            total += ((bm >> bit) & ((1 << take) - 1)).bit_count()
            c += take
        return total

    def _chance(self, extents: list) -> int:
        for _l, p, n, uninit in extents:
            if uninit:
                continue
            used = self._used_blocks(p, n)
            if used is None or used:
                return CHANCE_POOR
        return CHANCE_GOOD

    def free_extents(self, ctl: Control = NULL_CONTROL) -> list[tuple[int, int]] | None:
        sb = self.sb
        cb = sb["cluster_bits"]
        cpg = sb["clusters_per_group"]
        fdb = sb["first_data_block"]
        csize = self.bs << cb
        total_clusters = (self.blocks_count - fdb + (1 << cb) - 1) >> cb
        out: list[tuple[int, int]] = []
        for g in range(len(self.groups)):
            if g % 64 == 0:
                ctl.check()
            bm = self._block_bitmap(g)
            self._bitmaps.pop(g, None)
            if bm is None:
                continue
            nbits = min(cpg, total_clusters - g * cpg)
            if nbits <= 0:
                break
            free = ~bm & ((1 << nbits) - 1)
            pos = 0
            while free >> pos:
                rest = free >> pos
                start = pos + ((rest & -rest).bit_length() - 1)
                used_after = bm >> start
                if used_after:
                    end = start + ((used_after & -used_after).bit_length() - 1)
                    end = min(end, nbits)
                else:
                    end = nbits
                c0 = g * cpg + start
                off = (fdb + (c0 << cb)) * self.bs
                length = (end - start) * csize
                if out and out[-1][0] + out[-1][1] == off:
                    out[-1] = (out[-1][0], out[-1][1] + length)
                else:
                    out.append((off, length))
                pos = end
        limit = min(self.src.size, self.blocks_count * self.bs)
        return [(o, min(n, limit - o)) for o, n in out if o < limit]


class _Replayed(Source):
    """The volume with the blocks a journal replay would write taken from the log (read-only: nothing is
    replayed on the disk)."""

    def __init__(self, inner: Source, bs: int, log: _Journal, blocks: dict[int, tuple[int, bool]]):
        Source.__init__(self)
        self.inner = inner
        self.bs = bs
        self.log = log
        self.blocks = blocks
        self.sorted = sorted(blocks)
        self.size = inner.size
        self.sector_size = inner.sector_size
        self.name = inner.name
        self.path = inner.path
        self.base = inner.base
        self.bad = inner.bad

    def _read(self, offset: int, length: int) -> bytes:
        data = self.inner.read(offset, length)
        bs = self.bs
        i = bisect.bisect_left(self.sorted, offset // bs)
        last = (offset + length - 1) // bs
        if i >= len(self.sorted) or self.sorted[i] > last:
            return data
        buf = bytearray(data)
        while i < len(self.sorted) and self.sorted[i] <= last:
            blk = self.sorted[i]
            jpos, esc = self.blocks[blk]
            p = self.log.fs_block(jpos)
            if p is not None:
                copy = self.inner.read(p * bs, bs)
                if esc:
                    copy = _JBD2_MAGIC_BYTES + copy[4:]
                s0 = max(blk * bs, offset)
                e0 = min((blk + 1) * bs, offset + length)
                buf[s0 - offset:e0 - offset] = copy[s0 - blk * bs:e0 - blk * bs]
            i += 1
        return bytes(buf)


# ---------------------------------------------------------------------- the jbd2 journal
class _Journal:
    """The jbd2 log, indexed by the filesystem block each logged copy belongs to.

    The log is circular and newer transactions overwrite older ones, but whatever hasn't been overwritten yet is
    still readable after a clean unmount. Every descriptor block found anywhere in the log claims the log blocks
    that follow it for its transaction; a log block belongs to the newest transaction that claims it, so copies
    whose place was taken by a later transaction are dropped. Ages are transaction numbers relative to the
    journal superblock's sequence (negative: written before the last checkpoint)."""

    def __init__(self, rd: ExtReader):
        self.rd = rd
        self.ok = False                  # located, with a sane superblock
        self.scanned = False
        self.copies: dict[int, list[tuple[int, int, bool]]] = {}   # fs block → [(age, log block, escaped)], newest 1st
        self.map: list[tuple[int, int, int]] = []                    # (log block, fs block, count)
        self._starts: list[int] = []
        self.start = 0                   # s_start: not 0 when the log holds changes not written to their place yet
        self.committed: set[int] = set()
        self.revokes: list[tuple[int, list[int]]] = []
        try:
            self._locate()
        except _DAMAGE as exc:
            rd.warn(f"The journal is damaged ({exc}): deleted files on ext3/ext4 can't be traced through it.")
            self.ok = False

    def fs_block(self, jblk: int) -> int | None:
        i = bisect.bisect_right(self._starts, jblk) - 1
        if i < 0:
            return None
        l0, p0, n = self.map[i]
        if jblk >= l0 + n:
            return None
        return p0 + jblk - l0

    def read(self, jblk: int, escaped: bool = False) -> bytes:
        p = self.fs_block(jblk)
        if p is None:
            return bytes(self.rd.bs)
        data = self.rd.meta.read(p * self.rd.bs, self.rd.bs)
        if escaped:
            data = _JBD2_MAGIC_BYTES + data[4:]
        return data

    def _locate(self) -> None:
        rd = self.rd
        sb = rd.sb
        bs = rd.bs
        jinode = rd.read_inode(sb["journal_inum"])
        ext = rd._map(jinode) if jinode is not None and jinode.kind == S_IFREG else None
        if not ext and sb["jnl_backup_type"] == 1:
            # the superblock keeps a copy of the journal inode's block map
            raw = bytearray(max(rd.isize, 160))
            raw[0:2] = struct.pack("<H", S_IFREG | 0o600)
            raw[0x28:0x64] = sb["jnl_blocks"][:60]
            size_hi, size_lo = struct.unpack_from("<II", sb["jnl_blocks"], 60)
            raw[4:8] = struct.pack("<I", size_lo)
            raw[0x6C:0x70] = struct.pack("<I", size_hi)
            if sb["feature_incompat"] & INCOMPAT_EXTENTS and struct.unpack_from("<H", raw, 0x28)[0] == EXT_MAGIC:
                raw[0x20:0x24] = struct.pack("<I", EXT4_EXTENTS_FL)
            ext = rd._map(_Inode(sb["journal_inum"], bytes(raw), False))
            if ext:
                rd.warn("The journal's inode is damaged: its location was taken from the superblock's copy.")
        if not ext:
            rd.warn("The journal can't be located: deleted files on ext3/ext4 can't be traced through it.")
            return
        self.map = [(lb, pb, n) for lb, pb, n, _u in ext]
        self._starts = [m[0] for m in self.map]
        jsb = self.read(0)
        magic, btype, _seq = struct.unpack_from(">III", jsb, 0)
        jbs, maxlen, first, sequence, start = struct.unpack_from(">IIIII", jsb, 12)
        if magic != JBD2_MAGIC or btype not in (JBD2_SB_V1, JBD2_SB_V2) or jbs != bs or maxlen < 16 \
                or not 0 < first < maxlen:
            rd.warn("The journal's superblock is damaged: deleted files on ext3/ext4 can't be traced through it.")
            return
        incompat = struct.unpack_from(">I", jsb, 0x28)[0] if btype == JBD2_SB_V2 else 0
        last = maxlen
        if incompat & JBD2_INCOMPAT_FAST_COMMIT:
            fc = struct.unpack_from(">I", jsb, 0x54)[0] or 256
            if fc < maxlen - first:
                last = maxlen - fc       # the fast-commit area at the end isn't part of the circular log
        last = min(last, sum(n for _l, _p, n in self.map))
        if last <= first:
            return
        self.first, self.last, self.sequence = first, last, sequence
        self.start = start if first <= start < last else 0
        self.is64 = bool(incompat & JBD2_INCOMPAT_64BIT)
        self.csum3 = bool(incompat & JBD2_INCOMPAT_CSUM_V3)
        csum2 = bool(incompat & JBD2_INCOMPAT_CSUM_V2)
        self.tag_size = 16 if self.csum3 else 12 + (2 if csum2 else 0) - (0 if self.is64 else 4)
        self.tail = 4 if (csum2 or self.csum3) else 0
        self.ok = True

    def scan(self, ctl: Control) -> None:
        """Read the whole log once (in big pieces) and index every logged copy."""
        if self.scanned or not self.ok:
            return
        self.scanned = True
        try:
            self._scan(ctl)
        except _DAMAGE as exc:
            self.rd.warn(f"The journal is damaged ({exc}): deleted files on ext3/ext4 can't be traced through it.")
            self.copies = {}

    def _scan(self, ctl: Control) -> None:
        rd = self.rd
        bs = rd.bs
        first, last, sequence = self.first, self.last, self.sequence
        span = last - first

        def age(seq: int) -> int:
            return ((seq - sequence + (1 << 31)) & 0xFFFFFFFF) - (1 << 31)

        descriptors: list[tuple[int, int, list[tuple[int, int]]]] = []
        owner: dict[int, int] = {}
        committed = self.committed

        def claim(pos: int, a: int) -> None:
            if owner.get(pos, -(1 << 40)) < a:
                owner[pos] = a

        for lb, pb, n in self.map:
            pos = max(lb, first)
            hi = min(lb + n, last)
            while pos < hi:
                ctl.check()
                cnt = min(hi - pos, READ_CHUNK // bs)
                chunk = rd.src.read((pb + pos - lb) * bs, cnt * bs)
                for k in range(cnt):
                    o = k * bs
                    if chunk[o:o + 4] != _JBD2_MAGIC_BYTES:
                        continue
                    btype, seq = struct.unpack_from(">II", chunk, o + 4)
                    jpos = pos + k
                    a = age(seq)
                    if btype == JBD2_DESCRIPTOR:
                        tags = self._tags(chunk[o:o + bs], self.tag_size, self.tail, self.is64, self.csum3)
                        tags = tags[:span - 1]
                        descriptors.append((jpos, a, tags))
                        claim(jpos, a)
                        for i in range(len(tags)):
                            claim(first + (jpos + 1 + i - first) % span, a)
                    elif btype == JBD2_COMMIT:
                        claim(jpos, a)
                        committed.add(a)
                    elif btype == JBD2_REVOKE:
                        claim(jpos, a)
                        self.revokes.append((a, self._revoked(chunk[o:o + bs])))
                pos += cnt
        if not descriptors or not committed:
            return
        newest_commit = max(committed)
        own = sorted((p, p + n) for _l, p, n in self.map)
        own_starts = [o[0] for o in own]

        def in_log(blk: int) -> bool:          # a tag naming a block of the log itself is garbage
            i = bisect.bisect_right(own_starts, blk) - 1
            return i >= 0 and blk < own[i][1]

        copies: dict[int, list[tuple[int, int, bool]]] = {}
        for jpos, a, tags in descriptors:
            if a > newest_commit and a not in committed:
                continue                         # the transaction being written when the system stopped
            for i, (blk, flags) in enumerate(tags):
                dpos = first + (jpos + 1 + i - first) % span
                if owner.get(dpos) != a or not rd._block_ok(blk) or in_log(blk):
                    continue
                copies.setdefault(blk, []).append((a, dpos, bool(flags & JBD2_FLAG_ESCAPE)))
        for lst in copies.values():
            lst.sort(reverse=True)
        self.copies = copies

    def _revoked(self, buf: bytes) -> list[int]:
        count = min(struct.unpack_from(">I", buf, 12)[0], len(buf))
        size = 8 if self.is64 else 4
        fmt = ">Q" if self.is64 else ">I"
        return [struct.unpack_from(fmt, buf, o)[0] for o in range(16, count - size + 1, size)]

    def replay(self) -> dict[int, tuple[int, bool]]:
        """{fs block: (log block, escaped)} that recovery would write: the newest copy of each block from the
        committed transactions since the last checkpoint (stopping at the first missing one), unless a later
        revoke record cancels it."""
        if not self.start:
            return {}
        valid = set()
        for a in sorted(a for a in self.committed if a >= 0):
            if a != len(valid):
                break
            valid.add(a)
        revoked: dict[int, int] = {}
        for a, blocks in self.revokes:
            if a in valid:
                for b in blocks:
                    revoked[b] = max(revoked.get(b, -1), a)
        out = {}
        for blk, lst in self.copies.items():
            for a, jpos, esc in lst:
                if a in valid and revoked.get(blk, -1) < a:
                    out[blk] = (jpos, esc)
                    break
        return out

    @staticmethod
    def _tags(buf: bytes, tag_size: int, tail: int, is64: bool, csum3: bool) -> list[tuple[int, int]]:
        tags = []
        o = 12
        end = len(buf) - tail
        while o + tag_size <= end:
            if csum3:
                blk, flags, hi = struct.unpack_from(">III", buf, o)
            else:
                blk, _cs, flags = struct.unpack_from(">IHH", buf, o)
                hi = struct.unpack_from(">I", buf, o + 8)[0] if is64 else 0
            if is64:
                blk |= hi << 32
            o += tag_size
            if not flags & JBD2_FLAG_SAME_UUID:
                o += 16
            tags.append((blk, flags))
            if flags & JBD2_FLAG_LAST_TAG:
                break
        return tags

    def inode_copies(self, ino: int) -> list[tuple[int, bytes]]:
        """(age, raw inode) for every logged copy of inode INO, newest first."""
        loc = self.rd._inode_block(ino)
        if loc is None:
            return []
        blk, off = loc
        out = []
        for age, jpos, esc in self.copies.get(blk, ()):
            out.append((age, self.read(jpos, esc)[off:off + self.rd.isize]))
        return out

    def inode_table_copies(self) -> Iterator[tuple[int, int, int, bool]]:
        """(first inode number, age, log block, escaped) for every logged copy of an inode table block."""
        rd = self.rd
        per_block = rd.bs // rd.isize
        for blk, lst in self.copies.items():
            i = bisect.bisect_right(rd._it_starts, blk) - 1
            if i < 0:
                continue
            start, end, g = rd._it_index[i]
            if blk >= end:
                continue
            first = g * rd.ipg + (blk - start) * per_block + 1
            for a, jpos, esc in lst:
                yield first, a, jpos, esc


# ---------------------------------------------------------------------- deleted files
class _Life:
    """One life of an inode number: the file that had it between an allocation and a deletion. The journal can
    hold copies of several lives of the same inode number (inodes are reused); their generation numbers tell
    them apart, and the ages of their copies say when each one existed."""

    __slots__ = ("ino", "gen", "first", "last", "inode", "content", "live", "journal", "names", "overwritten")

    def __init__(self, ino: int, gen: int, live: bool = False, journal: bool = True):
        self.ino = ino
        self.gen = gen
        self.first: int | None = None      # age of its oldest and newest copy in the journal
        self.last: int | None = None
        self.inode: _Inode | None = None   # the copy (or the on-disk inode) it is rebuilt from
        self.content: dict | None = None
        self.live = live                   # the life going on today: only its time span matters
        self.journal = journal             # known from the journal (else: a deleted inode on the disk)
        self.names = 0
        self.overwritten = False           # a later life reused some of its blocks

    def seen(self, age: int) -> None:
        if self.first is None:
            self.first = self.last = age
        else:
            self.first = min(self.first, age)
            self.last = max(self.last, age)

    def distance(self, age: int) -> int:
        if self.first is None:
            return 1 << 40
        if self.first <= age <= self.last:
            return 0
        return min(abs(age - self.first), abs(age - self.last))


class _Undelete:
    """Puts names and content of deleted files together, once the existing tree was listed (so that an old name
    whose file still exists is known to be a rename, not a deletion)."""

    def __init__(self, rd: ExtReader, ctl: Control, dirinfos: list[_DirInfo], disk_cands: dict[int, _Inode]):
        self.rd = rd
        self.ctl = ctl
        self.queue: deque[_DirInfo] = deque(dirinfos)
        self.lives: dict[int, list[_Life]] = {}
        for ino, inode in disk_cands.items():        # deleted inodes that kept their map on the disk (ext2)
            life = _Life(ino, inode.gen, journal=False)
            life.inode = inode
            life.content = self._rebuild(inode)
            if life.content is not None:
                self.lives.setdefault(ino, []).append(life)
        self.keys: dict[int, int] = {}               # inode number → entries given (keys stay unique)
        self.dirs_done: set[int] = set()
        self.count = 0

    def run(self) -> Iterator[Entry]:
        rd = self.rd
        self._journal_lives()
        self._find_overwritten()
        yield from self._drain()
        # what has content but no name: "Lost files", folders first so that their children get names
        lost = [life for ino in sorted(self.lives) for life in self.lives[ino]
                if not life.live and life.inode is not None and life.content is not None
                and (life.inode.is_dir() or life.content.get("size") or life.content.get("data"))]
        dirs = [life for life in lost if life.inode.is_dir()]
        dir_inos = {life.ino for life in dirs}
        roots = [life for life in dirs if rd._parent_of(life.inode) not in dir_inos]
        for life in roots + dirs:
            if not life.names:
                yield from self._emit(None, None, life.ino, 2, life)
                yield from self._drain()
        for life in lost:
            if not life.names:
                yield from self._emit(None, None, life.ino, 1, life)

    def _drain(self) -> Iterator[Entry]:
        rd = self.rd
        while self.queue:
            info = self.queue.popleft()
            self.ctl.check()
            try:
                names = self._old_names(info)
            except _DAMAGE as exc:
                rd.warn(f"Old entries of folder inode {info.ino} are unreadable ({exc}).")
                continue
            for ino, raw, ft, age in names:
                life = self._pick(ino, age)
                if rd._marked(ino) and (life is None or life.live):
                    continue                     # it still exists: renamed or moved
                yield from self._emit(info.key, _decode_name(raw, info.encrypted), ino, ft, life)

    # ------------------------------------------------------------------ content
    def _rebuild(self, inode: _Inode, empty_ok: bool = False) -> dict | None:
        """Content of a deleted inode image ({"blocks": extents, ...} as _content gives it), None if unusable.
        EMPTY_OK: a journal copy of a file in use that was empty is an empty file, not a wiped inode."""
        rd = self.rd
        if inode.kind not in (S_IFREG, S_IFDIR, S_IFLNK):
            return None
        try:
            if inode.is_dir():
                if inode.flags & EXT4_INLINE_DATA_FL:
                    return {"blocks": [], "dir_blocks": []}
                blocks = rd._dir_blocks(inode, strict=True)
                if not blocks:
                    return None
                return {"blocks": rd._map(inode, strict=True) or [], "dir_blocks": blocks}
            if not inode.size:
                if empty_ok and inode.kind == S_IFREG and not inode.flags & EXT4_INLINE_DATA_FL:
                    return {"size": 0, "runs": [], "flags": 0, "blocks": []}
                return None
            return rd._content(inode, strict=True)
        except _DAMAGE:
            return None

    def _journal_lives(self) -> None:
        """Every life the journal's copies of inode table blocks remember. Each deleted life is rebuilt from its
        newest usable copy (one with links > 0 if there is one: later copies are the deletion itself)."""
        rd = self.rd
        j = rd.journal
        if j is None:
            return
        per_block = rd.bs // rd.isize
        isize = rd.isize
        found: dict[tuple[int, int], _Life | None] = {}
        live_gen: dict[int, int | None] = {}
        for n, (first, age, jpos, esc) in enumerate(j.inode_table_copies()):
            if n % 64 == 0:
                self.ctl.check()
            buf = j.read(jpos, esc)
            for k in range(per_block):
                ino = first + k
                if ino < rd.first_ino or ino > rd.inodes_count:
                    continue
                o = k * isize
                if buf[o] == 0 and buf[o + 1] == 0:
                    continue
                raw = buf[o:o + isize]
                gen = struct.unpack_from("<I", raw, 0x64)[0]
                key = (ino, gen)
                life = found.get(key, False)
                if life is None:
                    continue                     # not something a file can be rebuilt from
                checked = False
                if life is False:
                    if struct.unpack_from("<H", raw, 0)[0] & S_IFMT not in (S_IFREG, S_IFDIR, S_IFLNK):
                        found[key] = None
                        continue
                    live = False
                    if rd._marked(ino):
                        if ino not in live_gen:
                            cur = rd.read_inode(ino)
                            live_gen[ino] = cur.gen if cur is not None and cur.mode and cur.links else None
                        live = live_gen[ino] == gen
                    if not live:
                        if rd.csum and not rd._inode_csum_ok(ino, raw):
                            continue             # torn, or not really this inode
                        checked = True
                    life = _Life(ino, gen, live=live)
                    found[key] = life
                    self.lives.setdefault(ino, []).append(life)
                life.seen(age)
                if life.live:
                    continue
                links = struct.unpack_from("<H", raw, 0x1A)[0]
                if life.inode is not None and (life.inode.links > 0 or links == 0):
                    continue                     # a newer usable copy was found already
                if rd.csum and not checked and not rd._inode_csum_ok(ino, raw):
                    continue
                inode = _Inode(ino, raw, rd.large_dirs)
                inode.age = age
                content = self._rebuild(inode, empty_ok=inode.links > 0)
                if content is not None:
                    life.inode, life.content = inode, content

    def _find_overwritten(self) -> None:
        """A deleted life whose blocks a later life used too was overwritten, even if the blocks are free again
        now (both deleted). Journal lives are ordered by the ages of their copies, on-disk ones by deletion time."""
        for from_journal in (True, False):
            spans = []
            for lives in self.lives.values():
                for life in lives:
                    if life.live or life.inode is None or life.content is None or life.journal != from_journal:
                        continue
                    if from_journal:
                        order = (life.last, life.first)
                    else:
                        order = (life.inode.dtime, life.inode.ctime or 0)
                    for _l, p, n, uninit in life.content.get("blocks") or ():
                        if not uninit:
                            spans.append((p, p + n, order, life))
            spans.sort(key=lambda s: s[0])
            active: list = []
            for start, end, order, life in spans:
                active = [a for a in active if a[1] > start]
                for _s, _e, aorder, alife in active:
                    if alife is life or aorder == order:
                        continue
                    (alife if aorder < order else life).overwritten = True
                active.append((start, end, order, life))

    def _pick(self, ino: int, age: int | None) -> _Life | None:
        """The life of inode INO that a name seen at AGE (in a journal copy of its folder; None: on the disk)
        belonged to."""
        lives = self.lives.get(ino)
        if not lives:
            return None
        journal = [life for life in lives if life.journal and life.first is not None]
        disk = [life for life in lives if not life.journal]
        if age is None:
            if self.rd._marked(ino):
                return None                      # undated, and the number is in use today: can't tell
            if disk:
                return disk[0]
            return max(journal, key=lambda life: life.last) if journal else None
        if not journal:
            return disk[0] if disk else None
        best = min(journal, key=lambda life: (life.distance(age), -life.last))
        if self.rd._marked(ino) and best.distance(age) and not any(life.live for life in journal):
            return None                          # today's file isn't in the journal: assume the name is its own
        return best

    # ------------------------------------------------------------------ names
    def _old_names(self, info: _DirInfo) -> list[tuple[int, bytes, int, int | None]]:
        """Entries a folder had and doesn't have any more, as (inode, name, type, age of the newest journal copy
        that shows it in use, or None): from the slack space of its blocks, and from the journal's copies."""
        rd = self.rd
        found: dict[tuple[bytes, int], tuple[int, int | None]] = {}

        def add(entries: list, age: int | None) -> None:
            for ino, raw, ft in entries:
                k = (raw, ino)
                prev = found.get(k)
                if prev is None or (age is not None and (prev[1] is None or age > prev[1])):
                    found[k] = (ft, age)

        add(info.dead, None)
        j = rd.journal
        if j is not None and info.inline:
            for age, raw in j.inode_copies(info.ino):
                old = _Inode(info.ino, raw, rd.large_dirs)
                if old.gen != info.gen or not old.is_dir() or not old.flags & EXT4_INLINE_DATA_FL:
                    continue
                live: list = []
                dead: list = []
                rd._inline_dirents(old, live, None if info.encrypted else dead)
                add(live, age)
                add(dead, None)
        elif j is not None:
            for lblk, pblk in info.blocks:
                for age, jpos, esc in j.copies.get(pblk, ()):
                    buf = j.read(jpos, esc)
                    if lblk == 0 and _DIRENT.unpack_from(buf, 0)[0] != info.ino:
                        continue                 # the block belonged to something else then
                    if rd._dirblock_owner(buf, info.ino, info.gen) is False:
                        continue
                    live = []
                    dead = []
                    rd._dirents(buf, live, None if info.encrypted else dead, block0=lblk == 0)
                    add(live, age)
                    add(dead, None)              # deleted before that copy: its age says little
        out = []
        for (raw, ino), (ft, age) in found.items():
            if raw in (b".", b"..") or (raw, ino) in info.live or ino < rd.first_ino:
                continue
            out.append((ino, raw, ft, age))
        return out

    # ------------------------------------------------------------------ entries
    def _emit(self, parent, name: str | None, ino: int, ft: int, life: _Life | None) -> Iterator[Entry]:
        rd = self.rd
        self.count += 1
        if self.count % 128 == 0:
            self.ctl.check()
        n = self.keys.get(ino, 0)
        self.keys[ino] = n + 1
        key = f"d{ino}" if n == 0 else f"d{ino}.{n}"
        flags = F_ORPHAN if parent is None else 0
        if life is None or life.inode is None or life.content is None:
            if life is not None:
                life.names += 1
            yield self._name_only(key, parent, name, ino, ft, flags)
            return
        life.names += 1
        if life.names > 1:
            flags |= F_HARDLINK
        if life.journal:
            flags |= F_JOURNAL
        inode = life.inode
        content = life.content
        try:
            if inode.is_dir():
                if name is None:
                    name = self._lost_name(life, "")
                yield from self._deleted_dir(key, parent, name, life, flags)
                return
            if name is None:
                ext = guess_extension(self._head(content)) if inode.kind == S_IFREG else ""
                name = self._lost_name(life, ext)
            e = rd._make_entry(key, parent, name, inode, deleted=True, flags=flags, content=content)
        except _DAMAGE:
            yield self._name_only(key, parent, name, ino, ft, flags)
            return
        if content.get("flags", 0) & F_PARTIAL or life.overwritten:
            e.chance = CHANCE_POOR
        else:
            e.chance = rd._chance(content.get("blocks") or [])
        yield e

    def _lost_name(self, life: _Life, ext: str) -> str:
        """"inode N" (+ a letter for older lives of a reused inode number, so names don't clash)."""
        older = sum(1 for other in self.lives.get(life.ino, ()) if other.names and other is not life)
        return f"inode {life.ino}{'-' + chr(ord('a') + older - 1) if 0 < older <= 26 else ''}{ext}"

    def _head(self, content: dict) -> bytes:
        if "data" in content:
            return content["data"][:512]
        for off, n in content.get("runs") or ():
            if off >= 0:
                return self.rd.src.read(off, min(512, n, content["size"]))
            break
        return b""

    def _name_only(self, key, parent, name: str | None, ino: int, ft: int, flags: int) -> Entry:
        """A deleted name whose content is gone: listed (with the times the wiped inode kept) so the user knows."""
        rd = self.rd
        e = Entry(key=key, parent=parent, name=name or f"inode {ino}", is_dir=ft == 2, deleted=True,
                  chance=CHANCE_POOR, flags=flags, extra={"inode": ino, "note": "content not found"})
        cur = rd.read_inode(ino)
        if cur is not None and cur.mode and cur.kind in _VALID_TYPES and not rd._marked(ino):
            e.is_dir = cur.is_dir()
            e.mtime, e.ctime, e.atime, e.crtime = cur.mtime, cur.ctime, cur.atime, cur.crtime
            e.extra["mode"] = cur.mode
        return e

    def _deleted_dir(self, key, parent, name: str, life: _Life, flags: int) -> Iterator[Entry]:
        """A deleted folder, then (through the queue) whatever its blocks, on the disk and in the journal, still
        name: its deleted children."""
        rd = self.rd
        inode = life.inode
        blocks = life.content.get("dir_blocks") or []
        e = rd._make_entry(key, parent, name, inode, deleted=True, flags=flags)
        e.chance = CHANCE_POOR if life.overwritten else rd._chance(life.content.get("blocks") or [])
        yield e
        if life.names > 1 or id(life) in self.dirs_done:
            return
        self.dirs_done.add(id(life))
        encrypted = bool(inode.flags & EXT4_ENCRYPT_FL)
        live: list = []
        dead: list | None = None if encrypted else []
        if inode.flags & EXT4_INLINE_DATA_FL:
            rd._inline_dirents(inode, live, dead)
        elif not life.overwritten:
            for lblk, _pblk, buf in rd._read_blocks(blocks):
                if lblk == 0 and _DIRENT.unpack_from(buf, 0)[0] != inode.ino:
                    continue                     # reused since
                if rd._dirblock_owner(buf, inode.ino, inode.gen) is False:
                    continue
                rd._dirents(buf, live, dead, block0=lblk == 0)
        self.queue.append(_DirInfo(key, inode, blocks, set(), live + (dead or [])))
