"""XFS (v4 and v5/CRC): files, folders and what is left of deleted files, read straight from the metadata.

On-disk layout (everything big-endian). The volume is cut into allocation groups (AGs) of ``agblocks``
blocks; each starts with a copy of the superblock ("XFSB"), the free-space header (AGF, "XAGF") and the
inode header (AGI, "XAGI") in its first sectors. Block numbers in file maps are *filesystem* block numbers:
the AG number in the high bits (``agno << agblklog``) and the block inside the AG in the low bits, so the
byte offset is ``(agno * agblocks + agbno) * blocksize`` — not ``fsb * blocksize``, because an AG needn't
be a power of two long. Inode numbers are built the same way (AG, block in the AG, slot in the block).

- Inodes live in chunks of 64, listed by each AG's inode B+tree (IABT/IAB3; the free-inode B+tree
  FIBT/FIB3 is the fallback); a record carries a bitmap of the free ones and, with sparse inodes, a hole
  mask.
- An inode ("IN") is a core (mode, size, times, link count) and a data fork: local (a short-form folder or
  a symlink target), extents (packed 128-bit records: logical block, filesystem block, length, unwritten
  flag) or btree (the root of a block-map B+tree whose blocks are BMAP/BMA3).
- Folders are short-form (inside the inode) or data blocks (XD2B/XDB3 for a one-block folder, XD2D/XDD3
  for bigger ones) below 32 GiB of the folder's own logical space; above that are hash and free-space
  indexes this reader doesn't need.
- Free space: each AG's by-block free-space B+tree (ABTB/AB3B; the by-size one as a fallback).

What a delete leaves behind (Linux): the folder entry becomes an "unused" region whose first four bytes
(the high half of the inode number) are overwritten by a free tag and a length — the name and the low half
of the inode number usually survive, and the inode number is completed against the inode chunks. In a
short-form folder the entries after it are slid down, so only bytes past the folder's new end survive. The
inode is marked free and its mode, size and extent count are zeroed, but the extent records themselves stay
in the inode (nothing rewrites them): that is what xfs_undelete relies on, and what this reader uses. So
deleted files come back with their content (sized to whole blocks, since the real size is gone), with their
name when a folder still holds it, otherwise under "Lost files". When all 64 inodes of a chunk are freed,
XFS frees the chunk too; those inodes (and freed folder blocks, which name their folder on v5) can only be
found by searching the free space, which is done when it is small or when ``info["scan_free_space"]`` asks.
Not read: the content of files on a realtime device (they are listed), extended attributes, special files
(devices, FIFOs, sockets), and changes still only in the log of a filesystem that wasn't cleanly unmounted.
"""

from __future__ import annotations

import bisect
import re
import struct
import uuid as _uuid
from collections import deque
from typing import Iterator

from ..blockio import CachedSource, Source
from ..errors import FormatError
from .base import (
    CHANCE_FAIR,
    CHANCE_GOOD,
    CHANCE_POOR,
    F_DIR_RECOVERED,
    F_HARDLINK,
    F_ORPHAN,
    F_PARTIAL,
    F_SPARSE,
    F_SYMLINK,
    F_SYSTEM,
    NULL_CONTROL,
    Control,
    Entry,
    ExtentMap,
    FsReader,
    be16,
    be32,
    be64,
    merge_runs,
)

SB_MAGIC = b"XFSB"
NULLFSINO = 0xFFFFFFFFFFFFFFFF

# superblock feature bits
_VERSION_MOREBITS = 0x8000
_VERSION2_FTYPE = 0x0200          # features2 (v4): folder entries carry the file type
_RO_FINOBT, _RO_RMAPBT, _RO_REFLINK, _RO_INOBTCNT = 1, 2, 4, 8
_IN_FTYPE, _IN_SPINODES, _IN_META_UUID, _IN_BIGTIME, _IN_NEEDSREPAIR, _IN_NREXT64 = 1, 2, 4, 8, 16, 32

# inode
_S_IFMT, _S_IFDIR, _S_IFREG, _S_IFLNK = 0o170000, 0o040000, 0o100000, 0o120000
_FMT_LOCAL, _FMT_EXTENTS, _FMT_BTREE = 1, 2, 3
_DIFLAG_REALTIME = 0x1
_DIFLAG2_BIGTIME, _DIFLAG2_NREXT64, _DIFLAG2_METADATA = 1 << 3, 1 << 4, 1 << 5
_BIGTIME_EPOCH = 1 << 31            # bigtime counts nanoseconds from 1901-12-13 (the old minimum)
_CORE = struct.Struct(">2sHBBHIIIHHQIIIIIIQQIIHBbIHHII")
_REC = struct.Struct(">QQ")

# B+tree block magics (v4, v5)
_BNO_MAGICS = (b"ABTB", b"AB3B")
_CNT_MAGICS = (b"ABTC", b"AB3C")
_INO_MAGICS = (b"IABT", b"IAB3")
_FINO_MAGICS = (b"FIBT", b"FIB3")
_BMAP_MAGICS = (b"BMAP", b"BMA3")

# folders
_DIR_BLOCK_MAGICS = {b"XD2B": 16, b"XDB3": 64}       # one-block folder (entries + hash leaf in the tail)
_DIR_DATA_MAGICS = {b"XD2D": 16, b"XDD3": 64}        # data block of a bigger folder
_DIR_MAGICS = {**_DIR_BLOCK_MAGICS, **_DIR_DATA_MAGICS}
_DIR_LEAF_OFFSET = 1 << 35                           # 32 GiB: hash leaves and free indexes start there
_FREE_TAG = 0xFFFF
_FTYPE_DIR, _FTYPE_SYMLINK = 2, 7

_MAX_BTREE_BLOCKS = 1 << 22         # per tree walk (cycles and garbage pointers)
_MAX_DELETED_NAMES = 2_000_000
_MAX_STALE_EXTENTS = 64
_MAX_STALE_LOGICAL = 1 << 47        # bytes: a stale extent past 128 TiB of a file is garbage
_SCAN_FREE_AUTO = 1 << 30           # search the free space for freed inode chunks when it's at most this big
_SCAN_PIECE = 4 * 1024 * 1024
_INODE_RE = re.compile(rb"IN[\x00-\xff]{2}[\x01-\x03][\x00-\x03]", re.DOTALL)
_DIRBLK_RE = re.compile(rb"XD2B|XDB3|XD2D|XDD3")

_SYSTEM_INODES = (("rbmino", "$rtbitmap"), ("rsumino", "$rtsummary"), ("uquotino", "$uquota"),
                  ("gquotino", "$gquota"), ("pquotino", "$pquota"))


# ---------------------------------------------------------------------- superblock
def parse_superblock(buf: bytes) -> dict | None:
    """The geometry in an XFS superblock (the first sector of the volume or of any AG), or None when BUF
    isn't one or holds absurd values. Used by the reader and by the partition search."""
    if len(buf) < 264 or buf[:4] != SB_MAGIC:
        return None
    versionnum = be16(buf, 100)
    version = versionnum & 0xF
    if version not in (4, 5):
        return None
    bs = be32(buf, 4)
    blocklog, sectlog, inodelog, inopblog, agblklog = buf[120], buf[121], buf[122], buf[123], buf[124]
    if not 9 <= blocklog <= 16 or bs != 1 << blocklog:
        return None
    sectsize = be16(buf, 102)
    if not 9 <= sectlog <= 15 or sectsize != 1 << sectlog or sectsize > bs:
        return None
    isize = be16(buf, 104)
    if not 8 <= inodelog <= 11 or isize != 1 << inodelog or isize > bs:
        return None
    inopblock = be16(buf, 106)
    if inopblock != bs // isize or inopblock != 1 << inopblog:
        return None
    dblocks, agblocks, agcount = be64(buf, 8), be32(buf, 84), be32(buf, 88)
    if agblocks < 16 or agcount == 0 or not 1 <= agblklog <= 31:
        return None
    if not (1 << (agblklog - 1)) < agblocks <= 1 << agblklog:
        return None
    if not (agcount - 1) * agblocks < dblocks <= agcount * agblocks:
        return None
    rootino = be64(buf, 56)
    agino_log = agblklog + inopblog
    if rootino == 0 or rootino >> agino_log >= agcount:
        return None
    dirblklog = buf[192]
    if blocklog + dirblklog > 16:
        return None
    features2 = be32(buf, 200) if versionnum & _VERSION_MOREBITS else 0
    ro_compat = be32(buf, 212) if version == 5 else 0
    incompat = be32(buf, 216) if version == 5 else 0
    ftype = bool(incompat & _IN_FTYPE) if version == 5 else bool(features2 & _VERSION2_FTYPE)
    uid = str(_uuid.UUID(bytes=bytes(buf[32:48])))
    # metadata blocks and v5 inodes carry this UUID (the user-visible one can be changed later)
    meta_uuid = bytes(buf[248:264]) if incompat & _IN_META_UUID else bytes(buf[32:48])
    label = bytes(buf[108:120]).split(b"\0", 1)[0].decode("utf-8", "replace")
    fdblocks = be64(buf, 144)
    size = dblocks * bs
    features = []
    for flag, name in ((version == 5, "crc"), (ftype, "ftype"), (ro_compat & _RO_FINOBT, "finobt"),
                       (incompat & _IN_SPINODES, "sparse"), (ro_compat & _RO_RMAPBT, "rmapbt"),
                       (ro_compat & _RO_REFLINK, "reflink"), (incompat & _IN_BIGTIME, "bigtime"),
                       (ro_compat & _RO_INOBTCNT, "inobtcount"), (incompat & _IN_NREXT64, "nrext64"),
                       (incompat & _IN_NEEDSREPAIR, "needsrepair"), (be64(buf, 16), "realtime")):
        if flag:
            features.append(name)
    info = {
        "fstype": "xfs",
        "label": label,
        "uuid": uid,
        "size": size,
        "block_size": bs,
        "sector_size": sectsize,
        "version": version,
        "dblocks": dblocks,
        "ag_count": agcount,
        "ag_blocks": agblocks,
        "ag_blklog": agblklog,
        "inode_size": isize,
        "inopblog": inopblog,
        "root_ino": rootino,
        "dirblklog": dirblklog,
        "dir_block_size": bs << dirblklog,
        "log_start": be64(buf, 48),
        "log_blocks": be32(buf, 96),
        "rt_blocks": be64(buf, 16),
        "icount": be64(buf, 128),
        "ifree": be64(buf, 136),
        "inoalignmt": be32(buf, 180),
        "spino_align": be32(buf, 228) if version == 5 else 0,
        "features": features,
        "crc": version == 5,
        "ftype": ftype,
        "finobt": bool(ro_compat & _RO_FINOBT),
        "sparse_inodes": bool(incompat & _IN_SPINODES),
        "reflink": bool(ro_compat & _RO_REFLINK),
        "bigtime": bool(incompat & _IN_BIGTIME),
        "nrext64": bool(incompat & _IN_NREXT64),
        "in_progress": bool(buf[126]),
        "meta_uuid": meta_uuid.hex(),
    }
    for key, _name in _SYSTEM_INODES:
        off = {"rbmino": 64, "rsumino": 72, "uquotino": 160, "gquotino": 168, "pquotino": 232}[key]
        v = be64(buf, off)
        info[key] = v if v not in (0, NULLFSINO) and (key != "pquotino" or version == 5) else 0
    if fdblocks <= dblocks:
        info["free"] = fdblocks * bs
        info["used"] = size - fdblocks * bs
    return info


# ---------------------------------------------------------------------- small decoders
def _ts(sec: int, nsec: int, big: bool) -> float | None:
    """An XFS timestamp: seconds + nanoseconds (signed 32-bit seconds), or a 64-bit nanosecond count
    from 1901 with the bigtime feature."""
    if big:
        ns = (sec << 32) | nsec
        return ns / 1e9 - _BIGTIME_EPOCH if ns else None
    if not sec and not nsec:
        return None
    if sec >= 1 << 31:
        sec -= 1 << 32
    if nsec >= 1_000_000_000:
        nsec = 0
    return sec + nsec / 1e9


def _extents(buf, off: int, n: int) -> list[tuple[int, int, int, int]]:
    """N packed extent records at OFF: (logical block, filesystem block, block count, unwritten)."""
    out = []
    for l0, l1 in _REC.iter_unpack(bytes(buf[off:off + 16 * n])):
        out.append(((l0 >> 9) & ((1 << 54) - 1), ((l0 & 0x1FF) << 43) | (l1 >> 21), l1 & 0x1FFFFF, l0 >> 63))
    return out


def _name_ok(name: bytes, strict: bool = False) -> bool:
    if not name or b"\0" in name or b"/" in name or name in (b".", b".."):
        return False
    if strict:
        try:
            text = name.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return text.isprintable()
    return True


def _dir_label(dir_key) -> str:
    """How warnings name a folder: by inode number (keys of deleted ones carry a letter)."""
    text = str(dir_key)
    return f"inode {text.lstrip('dr')}" if text[:1] in "dr" or text.isdigit() else "(unknown)"


def _name(raw: bytes) -> str:
    return raw.decode("utf-8", "replace").replace("/", "_").replace("\0", "")


class _Inode:
    """The parts of an on-disk inode the reader uses."""

    __slots__ = ("ino", "raw", "mode", "version", "fmt", "nlink", "uid", "gid", "size", "nblocks", "nextents",
                 "forkoff", "flags", "flags2", "atime", "mtime", "ctime", "crtime", "di_ino", "lit")

    def fork(self) -> bytes:
        """The data fork bytes (up to the attribute fork)."""
        end = self.lit + self.forkoff * 8 if self.forkoff else len(self.raw)
        return self.raw[self.lit:min(end, len(self.raw))]

    @property
    def kind(self) -> int:
        return self.mode & _S_IFMT


def _decode_inode(raw: bytes, ino: int) -> _Inode | None:
    """Decode an inode; None if it has no "IN" magic or a version/format no XFS writes."""
    if len(raw) < 100 or raw[:2] != b"IN":
        return None
    (_m, mode, version, fmt, onlink, uid, gid, nlink, _p0, _p1, big_next, at_s, at_ns, mt_s, mt_ns, ct_s, ct_ns,
     size, nblocks, _extsz, nextents, _anext, forkoff, _afmt, _dmev, _dmst, flags, _gen, _unl) = _CORE.unpack_from(raw)
    if version not in (1, 2, 3) or fmt > 5:
        return None
    n = _Inode()
    n.ino = ino
    n.raw = raw
    n.mode = mode
    n.version = version
    n.fmt = fmt
    n.nlink = onlink if version == 1 else nlink
    n.uid, n.gid = uid, gid
    n.size = size
    n.nblocks = nblocks
    n.flags = flags
    n.forkoff = forkoff
    n.lit = 176 if version == 3 else 100
    if n.lit >= len(raw) or (forkoff and n.lit + forkoff * 8 > len(raw)):
        return None
    flags2 = be64(raw, 120) if version == 3 and len(raw) >= 176 else 0
    n.flags2 = flags2
    n.nextents = big_next if flags2 & _DIFLAG2_NREXT64 else nextents
    big = bool(flags2 & _DIFLAG2_BIGTIME)
    n.atime, n.mtime, n.ctime = _ts(at_s, at_ns, big), _ts(mt_s, mt_ns, big), _ts(ct_s, ct_ns, big)
    if version == 3:
        n.crtime = _ts(be32(raw, 144), be32(raw, 148), big)
        n.di_ino = be64(raw, 152)
    else:
        n.crtime = None
        n.di_ino = None
    return n


class _Deleted:
    """A deleted inode (or the remains of one) waiting for a name."""

    __slots__ = ("ino", "kind", "size", "exts", "data", "node", "parent_hint", "times", "found_in")

    def __init__(self, ino: int, kind: str):
        self.ino = ino
        self.kind = kind            # "file", "dir", "symlink"
        self.size = 0
        self.exts: list = []
        self.data: bytes | None = None
        self.node: _Inode | None = None
        self.parent_hint: int | None = None
        self.times: tuple = (None, None, None, None)
        self.found_in = "inode B+tree"


# ---------------------------------------------------------------------- the reader
class XfsReader(FsReader):
    fstype = "xfs"
    name = "XFS"
    root_key = 128
    deleted_support = True

    def __init__(self, src: Source, info: dict | None = None):
        super().__init__(src, info)
        if not self.info.get("ag_blocks"):
            sb = parse_superblock(src.read(0, 512))
            if sb is None:
                raise FormatError("This isn't an XFS volume (no superblock)")
            sb.update(self.info)
            self.info = sb
        i = self.info
        self.bs = int(i["block_size"])
        self.block_size = self.bs
        self.sectsize = int(i.get("sector_size") or 512)
        self.agblocks = int(i["ag_blocks"])
        self.agcount = int(i["ag_count"])
        self.agblklog = int(i["ag_blklog"])
        self.dblocks = int(i.get("dblocks") or self.agcount * self.agblocks)
        self.isize = int(i["inode_size"])
        self.inopblog = int(i["inopblog"])
        self.inopb = 1 << self.inopblog
        self.agino_log = self.agblklog + self.inopblog
        self.v5 = int(i.get("version") or 4) == 5
        self.ftype = bool(i.get("ftype"))
        self.sparse = bool(i.get("sparse_inodes"))
        self.dirbs = int(i.get("dir_block_size") or self.bs)
        self.root_key = int(i.get("root_ino") or 128)
        self.label = i.get("label") or ""
        self._agmask = (1 << self.agblklog) - 1
        self._leaf_blk = _DIR_LEAF_OFFSET // self.bs
        self._max_hi = ((self.agcount << self.agino_log) - 1) >> 32
        self.meta = CachedSource(src, block=64 * 1024, blocks=1024)
        log_start, log_blocks = int(i.get("log_start") or 0), int(i.get("log_blocks") or 0)
        self._log = None
        if log_start and log_blocks:
            off = self._fsb_off(log_start)
            if off is not None:
                self._log = (off, log_blocks * self.bs)
        self._chunks: dict[int, tuple[int, int, int, int]] | None = None   # first ino → (agno, agino, holes, free)
        self._chunk_starts: list[int] = []
        self._free: list[tuple[int, int]] | None = None
        self._free_map: ExtentMap | None = None
        self._found_inodes: dict[int, _Deleted] = {}
        try:
            self._meta_uuid = bytes.fromhex(i.get("meta_uuid") or "")
        except ValueError:
            self._meta_uuid = b""

    @classmethod
    def probe(cls, src: Source) -> dict | None:
        info = parse_superblock(src.read(0, 512))
        if info is None:
            return None
        if info["size"] > src.size:
            info["truncated"] = True
        return info

    # ------------------------------------------------------------------ geometry
    def _aglen(self, agno: int) -> int:
        return min(self.agblocks, self.dblocks - agno * self.agblocks)

    def _agoff(self, agno: int, agbno: int) -> int:
        return (agno * self.agblocks + agbno) * self.bs

    def _fsb_ok(self, fsb: int, count: int = 1) -> bool:
        agno, agbno = fsb >> self.agblklog, fsb & self._agmask
        return agno < self.agcount and count > 0 and agbno + count <= self._aglen(agno)

    def _fsb_off(self, fsb: int) -> int | None:
        if not self._fsb_ok(fsb):
            return None
        return self._agoff(fsb >> self.agblklog, fsb & self._agmask)

    def _ino_off(self, ino: int) -> int | None:
        agno = ino >> self.agino_log
        agino = ino & ((1 << self.agino_log) - 1)
        agbno = agino >> self.inopblog
        if agno >= self.agcount or agbno >= self._aglen(agno):
            return None
        return self._agoff(agno, agbno) + (agino & (self.inopb - 1)) * self.isize

    def _off_ino(self, off: int) -> int | None:
        """The inode number an inode at byte offset OFF would have."""
        agsize = self.agblocks * self.bs
        agno, rel = divmod(off, agsize)
        if agno >= self.agcount or rel % self.isize:
            return None
        agbno, inblk = divmod(rel, self.bs)
        return (agno << self.agino_log) | (agbno << self.inopblog) | (inblk // self.isize)

    # ------------------------------------------------------------------ AG headers and short B+trees
    def _agf(self, agno: int) -> dict | None:
        b = self.meta.read(self._agoff(agno, 0) + self.sectsize, 64)
        if b[:4] != b"XAGF" or be32(b, 8) != agno:
            self.warn(f"The free-space header of allocation group {agno} is damaged.")
            return None
        return {"bno_root": be32(b, 16), "cnt_root": be32(b, 20), "bno_level": be32(b, 28),
                "cnt_level": be32(b, 32), "freeblks": be32(b, 52)}

    def _agi(self, agno: int) -> dict | None:
        b = self.meta.read(self._agoff(agno, 0) + 2 * self.sectsize, 344)
        if b[:4] != b"XAGI" or be32(b, 8) != agno:
            self.warn(f"The inode header of allocation group {agno} is damaged.")
            return None
        return {"count": be32(b, 16), "root": be32(b, 20), "level": be32(b, 24), "freecount": be32(b, 28),
                "free_root": be32(b, 328) if self.info.get("finobt") else 0,
                "free_level": be32(b, 332) if self.info.get("finobt") else 0}

    def _sbtree(self, agno: int, root: int, levels: int, magics: tuple, rec_len: int, key_len: int,
                what: str, ctl: Control) -> Iterator[tuple[bytes, int, int]]:
        """Leaf blocks of a short-pointer B+tree of AG AGNO: (block, first record offset, record count).
        Damaged blocks are skipped with a warning."""
        hdr = 56 if self.v5 else 16
        aglen = self._aglen(agno)
        if not 0 < root < aglen or not 1 <= levels <= 10:
            self.warn(f"The {what} of allocation group {agno} has no valid root.")
            return
        stack = [(root, levels - 1)]
        seen: set[int] = set()
        while stack:
            agbno, level = stack.pop()
            if agbno in seen or not 0 < agbno < aglen or len(seen) > _MAX_BTREE_BLOCKS:
                self.warn(f"The {what} of allocation group {agno} points outside the group or loops.")
                continue
            seen.add(agbno)
            if len(seen) % 256 == 0:
                ctl.check()
            blk = self.meta.read(self._agoff(agno, agbno), self.bs)
            if blk[:4] not in magics or be16(blk, 4) != level:
                self.warn(f"A block of the {what} of allocation group {agno} is damaged.")
                continue
            n = be16(blk, 6)
            if level == 0:
                yield blk, hdr, min(n, (self.bs - hdr) // rec_len)
            else:
                maxr = (self.bs - hdr) // (key_len + 4)
                n = min(n, maxr)
                ptrs = struct.unpack_from(f">{n}I", blk, hdr + maxr * key_len)
                stack.extend((p, level - 1) for p in reversed(ptrs))

    def _load_chunks(self, ctl: Control) -> dict[int, tuple[int, int, int, int]]:
        """Every inode chunk from the inode B+trees: first inode → (agno, first agino, hole mask, free mask).
        Hole and free masks have one bit per inode (bit i = inode i of the chunk). Chunks start on a block
        (or cluster) boundary, so their first inode needn't be a multiple of 64."""
        if self._chunks is not None:
            return self._chunks
        chunks: dict[int, tuple[int, int, int, int]] = {}
        for agno in range(self.agcount):
            ctl.check()
            agi = self._agi(agno)
            if agi is None:
                continue
            before = len(self.warnings)
            found = self._chunk_records(agno, agi["root"], agi["level"], _INO_MAGICS, "inode B+tree", ctl)
            if len(self.warnings) != before and agi["free_root"]:
                # the free-inode B+tree lists every chunk that still has free inodes: the deleted ones
                found.update({k: v for k, v in self._chunk_records(agno, agi["free_root"], agi["free_level"],
                                                                   _FINO_MAGICS, "free-inode B+tree", ctl).items()
                              if k not in found})
            chunks.update(found)
            if self.agcount > 8:
                ctl.progress((agno + 1) / self.agcount, "Reading the inode B+trees")
        self._chunks = chunks
        self._chunk_starts = sorted(chunks)
        return chunks

    def _chunk_of(self, ino: int) -> int | None:
        """The first inode of the known chunk holding INO."""
        i = bisect.bisect_right(self._chunk_starts, ino) - 1
        if i >= 0 and ino - self._chunk_starts[i] < 64:
            return self._chunk_starts[i]
        return None

    def _chunk_records(self, agno: int, root: int, levels: int, magics: tuple, what: str,
                       ctl: Control) -> dict[int, tuple[int, int, int, int]]:
        out: dict[int, tuple[int, int, int, int]] = {}
        base = agno << self.agino_log
        maxagino = self._aglen(agno) << self.inopblog
        for blk, off, n in self._sbtree(agno, root, levels, magics, 16, 4, what, ctl):
            for k in range(n):
                p = off + 16 * k
                agino = be32(blk, p)
                if self.sparse:
                    holemask, _count, _freecount, free = struct.unpack_from(">HBBQ", blk, p + 4)
                    holes = 0
                    for bit in range(16):
                        if holemask >> bit & 1:
                            holes |= 0xF << (4 * bit)
                else:
                    free = be64(blk, p + 8)
                    holes = 0
                if agino % min(64, self.inopb) or agino + 64 > maxagino:
                    self.warn(f"The {what} of allocation group {agno} has a damaged record.")
                    continue
                out[base | agino] = (agno, agino, holes, free)
        return out

    # ------------------------------------------------------------------ free space
    def free_extents(self, ctl: Control = NULL_CONTROL) -> list[tuple[int, int]] | None:
        if self._free is None:
            out: list[tuple[int, int]] = []
            for agno in range(self.agcount):
                ctl.check()
                agf = self._agf(agno)
                if agf is None:
                    continue
                before = len(self.warnings)
                recs = self._free_records(agno, agf["bno_root"], agf["bno_level"], _BNO_MAGICS, ctl)
                if len(self.warnings) != before:
                    # the by-size tree holds the same extents: use it when the by-block one is damaged
                    alt = self._free_records(agno, agf["cnt_root"], agf["cnt_level"], _CNT_MAGICS, ctl)
                    if len(alt) > len(recs):
                        recs = alt
                out.extend(recs)
            out.sort()
            self._free = merge_runs(out)
            self._free_map = ExtentMap(self._free)
        return list(self._free)

    def _free_records(self, agno: int, root: int, levels: int, magics: tuple, ctl: Control):
        out = []
        aglen = self._aglen(agno)
        what = "free-space B+tree"
        for blk, off, n in self._sbtree(agno, root, levels, magics, 8, 8, what, ctl):
            for start, count in struct.iter_unpack(">II", bytes(blk[off:off + 8 * n])):
                if count and start + count <= aglen:
                    out.append((self._agoff(agno, start), count * self.bs))
        return out

    def _all_free(self, runs: list[tuple[int, int]]) -> bool:
        if self._free_map is None:
            self.free_extents()
        fm = self._free_map
        return all(off < 0 or fm.overlap(off, n) == n for off, n in runs)

    # ------------------------------------------------------------------ inodes and file maps
    def _inode(self, ino: int) -> _Inode | None:
        off = self._ino_off(ino)
        if off is None:
            return None
        node = _decode_inode(self.meta.read(off, self.isize), ino)
        if node is None or (node.di_ino is not None and node.di_ino != ino):
            return None
        return node

    def _map(self, node: _Inode, stale: bool = False) -> list[tuple[int, int, int, int]] | None:
        """The extent list of NODE's data fork (sorted by logical block), None if it can't be read."""
        fork = node.fork()
        if node.fmt == _FMT_EXTENTS:
            n = min(node.nextents, len(fork) // 16)
            if n < node.nextents:
                self.warn(f"Inode {node.ino} claims more extents than fit in it.")
            exts = _extents(fork, 0, n)
        elif node.fmt == _FMT_BTREE:
            exts = self._bmbt(node.ino, fork, stale)
            if exts is None:
                return None
        else:
            return []
        exts.sort()
        return exts

    def _bmbt(self, ino: int, root: bytes, stale: bool = False) -> list | None:
        """The leaf records of a block-map B+tree whose root (bmdr) sits in an inode fork."""
        if len(root) < 20:
            return None
        level, n = be16(root, 0), be16(root, 2)
        maxr = (len(root) - 4) // 16
        if not 1 <= level <= 9 or not 1 <= n <= maxr:
            if not stale:
                self.warn(f"The block map root of inode {ino} is damaged.")
            return None
        hdr = 72 if self.v5 else 24
        stack = [(p, level - 1) for p in reversed(struct.unpack_from(f">{n}Q", root, 4 + maxr * 8))]
        seen: set[int] = set()
        out: list = []
        while stack:
            fsb, lvl = stack.pop()
            off = self._fsb_off(fsb)
            if fsb in seen or off is None or len(seen) > _MAX_BTREE_BLOCKS:
                if stale:
                    return None
                self.warn(f"The block map of inode {ino} points outside the volume or loops.")
                continue
            seen.add(fsb)
            blk = self.meta.read(off, self.bs)
            if (blk[:4] not in _BMAP_MAGICS or be16(blk, 4) != lvl
                    or (blk[:4] == b"BMA3" and be64(blk, 56) != ino)):
                if stale:
                    return None             # reused since: don't guess
                self.warn(f"A block of the block map of inode {ino} is damaged.")
                continue
            h = 72 if blk[:4] == b"BMA3" else 24
            if h != hdr and not stale:
                self.warn(f"The block map of inode {ino} mixes old and new block formats.")
            cnt = be16(blk, 6)
            if lvl == 0:
                out.extend(_extents(blk, h, min(cnt, (self.bs - h) // 16)))
            else:
                maxr2 = (self.bs - h) // 16
                cnt = min(cnt, maxr2)
                stack.extend((p, lvl - 1) for p in reversed(struct.unpack_from(f">{cnt}Q", blk, h + maxr2 * 8)))
        return out

    def _runs(self, exts: list, size: int) -> tuple[list[tuple[int, int]], bool, bool]:
        """Content runs of SIZE bytes from an extent list: (runs, has holes, has bad extents)."""
        bs = self.bs
        limit = -(-size // bs)
        runs: list[tuple[int, int]] = []
        pos = 0
        holes = bad = False
        for start, fsb, cnt, unwritten in exts:
            if start >= limit:
                break
            if start < pos:                      # overlapping records: keep the first mapping
                skip = pos - start
                if skip >= cnt:
                    continue
                start, fsb, cnt = pos, fsb + skip, cnt - skip
            if start > pos:
                runs.append((-1, (start - pos) * bs))
                holes = True
            cnt = min(cnt, limit - start)
            off = self._fsb_off(fsb) if self._fsb_ok(fsb, cnt) else None
            if unwritten:
                runs.append((-1, cnt * bs))      # allocated but never written: reads as zeros
            elif off is None:
                runs.append((-1, cnt * bs))
                bad = True
            else:
                runs.append((off, cnt * bs))
            pos = start + cnt
        if pos < limit:
            runs.append((-1, (limit - pos) * bs))
            holes = True
        return merge_runs(runs), holes, bad

    def _symlink_target(self, node: _Inode) -> bytes | None:
        size = node.size
        if size > 4096:
            return None
        if node.fmt == _FMT_LOCAL:
            fork = node.fork()
            return bytes(fork[:size]) if size <= len(fork) else None
        exts = self._map(node)
        if not exts:
            return None
        out = bytearray()
        for start, fsb, cnt, _unw in exts:
            for k in range(min(cnt, 16)):
                off = self._fsb_off(fsb + k)
                if off is None:
                    return None
                blk = self.meta.read(off, self.bs)
                if blk[:4] == b"XSLM":           # v5 remote symlink blocks start with a header
                    n = min(be32(blk, 8), self.bs - 56)
                    out += blk[56:56 + n]
                else:
                    out += blk
                if len(out) >= size:
                    return bytes(out[:size])
        return bytes(out[:size])

    def _entry(self, node: _Inode, key, parent, name: str, flags: int = 0, deleted: bool = False) -> Entry | None:
        """An Entry for a live (or not yet flushed deleted) inode; None for special files."""
        e = Entry(key=key, parent=parent, name=name, mtime=node.mtime, atime=node.atime, ctime=node.ctime,
                  crtime=node.crtime, chance=CHANCE_GOOD, flags=flags, deleted=deleted,
                  extra={"inode": node.ino, "mode": node.mode & 0o7777, "uid": node.uid, "gid": node.gid,
                         "nlink": node.nlink})
        if node.flags2 & _DIFLAG2_METADATA:
            e.flags |= F_SYSTEM                 # the hidden metadata folder tree of newer filesystems
        kind = node.kind
        if kind == _S_IFDIR:
            e.is_dir = True
        elif kind == _S_IFLNK:
            target = self._symlink_target(node)
            e.flags |= F_SYMLINK
            if target is None:
                self.warn(f"The target of symlink {name!r} (inode {node.ino}) can't be read.")
                e.data = b""
                e.flags |= F_PARTIAL
            else:
                e.data = target
                e.size = len(target)
        elif kind == _S_IFREG:
            e.size = node.size
            if node.flags & _DIFLAG_REALTIME:
                self.warn("Some files are on the realtime device, which this reader can't read.")
                e.flags |= F_PARTIAL
                e.runs = [(-1, node.size)] if node.size else []
                e.chance = CHANCE_POOR
                return e
            if node.fmt == _FMT_LOCAL:          # never written by Linux for files, but cheap to honour
                e.data = bytes(node.fork()[:node.size])
                return e
            exts = self._map(node)
            if exts is None:
                e.flags |= F_PARTIAL
                e.chance = CHANCE_POOR
                exts = []
            e.runs, holes, bad = self._runs(exts, node.size)
            if holes:
                e.flags |= F_SPARSE
            if bad:
                e.flags |= F_PARTIAL
                e.chance = CHANCE_POOR
                self.warn(f"Part of the block map of {name!r} (inode {node.ino}) points outside the volume.")
            if deleted:
                e.chance = CHANCE_GOOD if self._all_free(e.runs) else CHANCE_POOR
        else:
            return None
        return e

    # ------------------------------------------------------------------ folders
    def _dir_blocks(self, node: _Inode) -> Iterator[bytes]:
        """The data blocks of a block/leaf/node folder (its logical space below 32 GiB)."""
        exts = self._map(node)
        if not exts:
            return
        bs, dbs = self.bs, self.dirbs
        per = dbs // bs
        if per == 1:
            for start, fsb, cnt, unwritten in exts:
                if unwritten or start >= self._leaf_blk:
                    continue
                cnt = min(cnt, self._leaf_blk - start)
                if not self._fsb_ok(fsb, cnt):
                    self.warn(f"The block map of folder inode {node.ino} points outside the volume.")
                    continue
                off = self._fsb_off(fsb)
                done = 0
                while done < cnt:
                    k = min(cnt - done, 256)
                    buf = self.src.read(off + done * bs, k * bs) if k > 16 else self.meta.read(off + done * bs, k * bs)
                    for j in range(k):
                        yield buf[j * bs:(j + 1) * bs]
                    done += k
            return
        # folder blocks of several filesystem blocks: assemble each from the map (it may span extents)
        want: dict[int, dict[int, int]] = {}
        for start, fsb, cnt, unwritten in exts:
            if unwritten:
                continue
            for k in range(min(cnt, max(0, self._leaf_blk - start), 1 << 20)):
                lb = start + k
                want.setdefault(lb // per, {})[lb % per] = fsb + k
        for db in sorted(want):
            parts = want[db]
            buf = bytearray()
            for j in range(per):
                off = self._fsb_off(parts[j]) if j in parts else None
                buf += self.meta.read(off, bs) if off is not None else bytes(bs)
            yield bytes(buf)

    def _dir_entries(self, node: _Inode, dir_key, dele: list | None) -> tuple[list, int | None]:
        """Live entries of folder NODE as (name bytes, inode, ftype), and its parent from "..". Deleted
        entries found on the way are appended to DELE as (folder key, name, inode, partial, ftype)."""
        live: list[tuple[bytes, int, int]] = []
        parent = None
        if node.fmt == _FMT_LOCAL:
            parent = self._parse_sf(node.fork(), node.size, live, dele, dir_key)
            return live, parent
        for blk in self._dir_blocks(node):
            dotdot = self._parse_dir_block(blk, live, dele, dir_key)
            if dotdot is not None:
                parent = dotdot
        return live, parent

    def _parse_sf(self, b: bytes, size: int, live: list, dele: list | None, dir_key) -> int | None:
        """A short-form folder: header (count, i8count, parent) and packed entries. Bytes past SIZE are
        what earlier versions of the folder left behind: deleted entries, when they still parse."""
        if len(b) < 6:
            return None
        size = min(size, len(b))
        count, i8 = b[0], b[1]
        isz = 8 if i8 else 4
        parent = int.from_bytes(b[2:2 + isz], "big")
        ft = 1 if self.ftype else 0
        p = 2 + isz
        for _ in range(count):
            if p + 4 > size:
                self.warn(f"Short folder {_dir_label(dir_key)} is damaged.")
                break
            n = b[p]
            end = p + 3 + n + ft + isz
            if not n or end > size:
                self.warn(f"Short folder {_dir_label(dir_key)} is damaged.")
                break
            live.append((bytes(b[p + 3:p + 3 + n]), int.from_bytes(b[end - isz:end], "big"), b[p + 3 + n] if ft else 0))
            p = end
        if dele is not None:
            self._stale_sf(b, max(p, size), isz, dele, dir_key)
        return parent

    def _stale_sf(self, b: bytes, p: int, isz: int, dele: list, dir_key) -> None:
        """Entries left past the end of a short-form folder (or in a freed folder inode)."""
        ft = 1 if self.ftype else 0
        hdr = 64 if self.v5 else 16
        end = len(b)
        while p + 4 + ft + isz <= end:
            n = b[p]
            e = p + 3 + n + ft + isz
            if n and e <= end:
                offset = be16(b, p + 1)
                name = bytes(b[p + 3:p + 3 + n])
                ftype = b[p + 3 + n] if ft else 0
                ino = int.from_bytes(b[e - isz:e], "big")
                if (offset % 8 == 0 and hdr <= offset < self.dirbs and _name_ok(name, strict=True)
                        and (not ft or 1 <= ftype <= 7) and self._ino_off(ino) is not None):
                    if len(dele) < _MAX_DELETED_NAMES:
                        dele.append((dir_key, name, ino, False, ftype))
                    p = e
                    continue
            p += 1

    def _parse_dir_block(self, blk: bytes, live: list | None, dele: list | None, dir_key) -> int | None:
        """One folder data block. Returns the inode of "..", if it is in this block."""
        magic = bytes(blk[:4])
        hdr = _DIR_MAGICS.get(magic)
        if hdr is None:
            self.warn(f"A block of folder {_dir_label(dir_key)} is damaged.")
            return None
        dbs = len(blk)
        end = dbs
        if magic in _DIR_BLOCK_MAGICS:
            count = be32(blk, dbs - 8)
            end = dbs - 8 - count * 8 if count * 8 <= dbs - 8 - hdr else dbs - 8
        ft = 1 if self.ftype else 0
        parent = None
        p = hdr
        bad = 0
        while p + 8 <= end:
            if be16(blk, p) == _FREE_TAG:
                length = be16(blk, p + 2)
                if length >= 8 and length % 8 == 0 and p + length <= end and be16(blk, p + length - 2) == p:
                    if dele is not None:
                        self._unused_region(blk, p, p + length, dele, dir_key)
                    p += length
                    continue
                bad += 1
                p += 8
                continue
            n = blk[p + 8] if p + 8 < end else 0
            size = (11 + n + ft + 7) & ~7
            if n and p + size <= end and be16(blk, p + size - 2) == p:
                name = bytes(blk[p + 9:p + 9 + n])
                ino = be64(blk, p)
                ftype = blk[p + 9 + n] if ft else 0
                if name == b"..":
                    parent = ino
                elif name != b"." and live is not None:
                    live.append((name, ino, ftype))
                elif name != b"." and dele is not None and _name_ok(name) and len(dele) < _MAX_DELETED_NAMES:
                    dele.append((dir_key, name, ino, False, ftype))     # a freed block: everything is deleted
                p += size
                continue
            bad += 1
            p += 8
        if bad:
            self.warn(f"A block of folder {_dir_label(dir_key)} is partly damaged.")
        return parent

    def _unused_region(self, blk: bytes, s: int, e: int, dele: list, dir_key) -> None:
        """Deleted entries inside an unused region of a folder block. Each entry ends with a tag holding its
        own offset, which tells real leftovers from noise. The first four bytes of the region (the high
        half of the first entry's inode number) hold the free tag and length; entries merged into an
        earlier free region keep their whole inode number."""
        ft = 1 if self.ftype else 0
        p = s
        while p + 16 <= e:
            n = blk[p + 8]
            size = (11 + n + ft + 7) & ~7
            if n and p + size <= e:
                tag = be16(blk, p + size - 2)
                name = bytes(blk[p + 9:p + 9 + n])
                ftype = blk[p + 9 + n] if ft else 0
                if ((tag == p or (p + size == e and tag == s)) and _name_ok(name, strict=True)
                        and (not ft or 1 <= ftype <= 7)):
                    if be16(blk, p) == _FREE_TAG:
                        ino, partial = be32(blk, p + 4), True
                    else:
                        ino, partial = be64(blk, p), False
                        if not self._ino_known(ino):
                            ino, partial = ino & 0xFFFFFFFF, True
                    if len(dele) < _MAX_DELETED_NAMES:
                        dele.append((dir_key, name, ino, partial, ftype))
                    p += size
                    continue
            p += 8

    def _ino_known(self, ino: int) -> bool:
        """Is INO in an inode chunk we know of (from the inode B+trees or the free-space search)?"""
        return self._chunk_of(ino) is not None or ino in self._found_inodes

    # ------------------------------------------------------------------ the scan
    def entries(self, ctl: Control = NULL_CONTROL, deleted: bool = True) -> Iterator[Entry]:
        self._found_inodes = {}
        chunks = self._load_chunks(ctl)
        if not chunks:
            self.warn("No inode chunks could be read: only what the folders reach is listed.")
        total = sum(64 - bin(free | holes).count("1") for _a, _i, holes, free in chunks.values()) or 1
        reached: dict[int, int] = {}            # ino >> 6 → bitmask of inodes already listed (a sparse bitset)
        live_dirs: set[int] = set()
        dele: list | None = [] if deleted else None
        names_seen: dict[int, int] = {}         # inodes listed more than once (hard links)
        system = {int(self.info[k]): label for k, label in _SYSTEM_INODES if self.info.get(k)}

        root = self._inode(self.root_key)
        if root is None or root.kind != _S_IFDIR:
            self.warn("The root folder's inode is damaged: files are listed under Lost files.")
        yield Entry(key=self.root_key, parent=None, name="", is_dir=True, chance=CHANCE_GOOD,
                    mtime=root.mtime if root else None, ctime=root.ctime if root else None,
                    atime=root.atime if root else None, crtime=root.crtime if root else None)
        self._mark(reached, self.root_key)
        count = 0

        def walk(start: int, start_node: _Inode) -> Iterator[Entry]:
            nonlocal count
            queue = deque([(start, start_node)])
            while queue:
                dino, dnode = queue.popleft()
                live, _parent = self._dir_entries(dnode, dino, dele)
                for raw_name, cino, _ftype in live:
                    count += 1
                    if count % 256 == 0:
                        ctl.check()
                        ctl.progress(min(1.0, count / total), "Reading folders")
                    if not _name_ok(raw_name):
                        self.warn(f"Folder inode {dino} has an entry with an impossible name.")
                        continue
                    node = self._inode(cino)
                    if node is None or node.mode == 0:
                        self.warn(f"An entry of folder inode {dino} points to a free or damaged inode ({cino}).")
                        continue
                    name = _name(raw_name)
                    if self._is_marked(reached, cino):
                        if node.kind == _S_IFDIR:
                            self.warn(f"Folder inode {cino} is listed twice: the second one is ignored.")
                            continue
                        k = names_seen.get(cino, 0) + 1
                        names_seen[cino] = k
                        e = self._entry(node, f"h{cino}:{k}", dino, name, F_HARDLINK)
                    else:
                        self._mark(reached, cino)
                        e = self._entry(node, cino, dino, name)
                        if node.kind == _S_IFDIR:
                            live_dirs.add(cino)
                            queue.append((cino, node))
                    if e is not None:
                        yield e

        if root is not None and root.kind == _S_IFDIR:
            live_dirs.add(self.root_key)
            yield from walk(self.root_key, root)

        # inodes in use that no folder reached: system inodes, folders whose parent is damaged, open files
        orphans = list(self._chunk_inodes(chunks, ctl, free=False, skip=reached))
        for node in orphans:
            if node.kind != _S_IFDIR or self._is_marked(reached, node.ino):
                continue
            # climb to the top of an unreached folder tree, so that it is listed whole
            top, seen = node, {node.ino}
            while True:
                up = self._dir_parent(top)
                if not up or up in seen or self._is_marked(reached, up):
                    break
                upn = self._inode(up)
                if upn is None or upn.kind != _S_IFDIR or not upn.nlink:
                    break
                seen.add(up)
                top = upn
            if self._is_marked(reached, top.ino):
                continue
            self._mark(reached, top.ino)
            live_dirs.add(top.ino)
            if top.flags2 & _DIFLAG2_METADATA:
                yield Entry(key=top.ino, parent=self.root_key, name=f"$metadir-{top.ino}", is_dir=True,
                            chance=CHANCE_GOOD, flags=F_SYSTEM)
            else:
                # its ".." may still name a folder we listed; otherwise it goes to Lost files
                up = self._dir_parent(top)
                parent = up if up in live_dirs and up != top.ino else None
                yield Entry(key=top.ino, parent=parent, name=f"inode {top.ino}", is_dir=True, chance=CHANCE_GOOD,
                            flags=0 if parent is not None else F_ORPHAN, mtime=top.mtime, ctime=top.ctime,
                            atime=top.atime, crtime=top.crtime, extra={"inode": top.ino, "mode": top.mode & 0o7777})
            yield from walk(top.ino, top)
        for node in orphans:
            if self._is_marked(reached, node.ino):
                continue
            self._mark(reached, node.ino)
            if node.ino in system or node.flags2 & _DIFLAG2_METADATA:
                e = self._entry(node, node.ino, self.root_key, system.get(node.ino, f"$meta-{node.ino}"), F_SYSTEM)
            elif node.nlink == 0:
                # unlinked while still open (or the system stopped before XFS freed it): its blocks are intact
                e = self._entry(node, f"d{node.ino}", None, f"inode {node.ino}", F_ORPHAN, deleted=True)
                if e is not None:
                    e.chance = CHANCE_GOOD
            else:
                e = self._entry(node, node.ino, None, f"inode {node.ino}", F_ORPHAN)
            if e is not None:
                yield e

        if deleted:
            yield from self._deleted(ctl, chunks, reached, live_dirs, dele or [])

    def _dir_parent(self, node: _Inode) -> int | None:
        """The parent a folder names for itself (the short-form header, or its ".." entry)."""
        if node.fmt == _FMT_LOCAL:
            fork = node.fork()
            if len(fork) < 6:
                return None
            return int.from_bytes(fork[2:2 + (8 if fork[1] else 4)], "big")
        for blk in self._dir_blocks(node):
            if bytes(blk[:4]) in _DIR_MAGICS:
                return self._parse_dir_block(blk, [], None, node.ino)
            break
        return None

    @staticmethod
    def _mark(reached: dict[int, int], ino: int) -> None:
        reached[ino >> 6] = reached.get(ino >> 6, 0) | (1 << (ino & 63))

    @staticmethod
    def _is_marked(reached: dict[int, int], ino: int) -> bool:
        return bool(reached.get(ino >> 6, 0) >> (ino & 63) & 1)

    @staticmethod
    def _bits(reached: dict[int, int], start: int) -> int:
        """The 64 bits of REACHED for inodes START .. START+63."""
        sh = start & 63
        lo = reached.get(start >> 6, 0) >> sh
        if sh:
            lo |= reached.get((start >> 6) + 1, 0) << (64 - sh)
        return lo & 0xFFFFFFFFFFFFFFFF

    def _chunk_inodes(self, chunks: dict, ctl: Control, free: bool, skip: dict[int, int]) -> Iterator[_Inode]:
        """Allocated (FREE False) or free (FREE True) inodes of every chunk but those marked in SKIP, read in
        big batches. Free inodes are decoded even with a zero mode; inodes whose self-number (v5)
        disagrees are skipped."""
        span = 64 * self.isize
        order = []
        for key, (agno, agino, holes, freemask) in chunks.items():
            want = (freemask if free else ~freemask) & ~holes & ~self._bits(skip, key) & 0xFFFFFFFFFFFFFFFF
            if not want:
                continue
            off = self._agoff(agno, agino >> self.inopblog) + (agino & (self.inopb - 1)) * self.isize
            order.append((off, key, want))
        order.sort()
        i = 0
        done = 0
        while i < len(order):
            j = i + 1
            while (j < len(order) and order[j][0] == order[j - 1][0] + span
                   and order[j][0] + span - order[i][0] <= _SCAN_PIECE):
                j += 1
            base = order[i][0]
            buf = self.src.read(base, order[j - 1][0] + span - base)
            for off, key, want in order[i:j]:
                rel = off - base
                for slot in range(64):
                    if not want >> slot & 1:
                        continue
                    o = rel + slot * self.isize
                    if buf[o:o + 2] != b"IN":
                        continue
                    ino = key + slot
                    node = _decode_inode(buf[o:o + self.isize], ino)
                    if node is None or (node.di_ino is not None and node.di_ino != ino):
                        continue
                    yield node
            done += j - i
            ctl.check()
            if len(order) > 64:
                ctl.progress(done / len(order), "Reading inodes" if not free else "Looking for deleted files")
            i = j

    # ------------------------------------------------------------------ deleted files
    def _deleted(self, ctl: Control, chunks: dict, reached: dict[int, int], live_dirs: set[int],
                 dele: list) -> Iterator[Entry]:
        found = self._found_inodes
        for node in self._chunk_inodes(chunks, ctl, free=True, skip=reached):
            d = self._examine_free(node, live_dirs)
            if d is not None:
                found[node.ino] = d
        free = self.free_extents(ctl) or []
        free_bytes = sum(n for _o, n in free)
        want_scan = self.info.get("scan_free_space")
        if want_scan is None:
            want_scan = free_bytes <= _SCAN_FREE_AUTO
        if want_scan:
            quiet = len(self.warnings)
            self._scan_free_space(ctl, free, live_dirs, dele)
            del self.warnings[quiet:]            # what lies in free space is expected to be half overwritten
        elif free_bytes:
            ctl.log("The free space wasn't searched for freed inode chunks (it is large); a deep scan does that.")

        # deleted folders found in inodes: their leftover entries name more deleted files
        for d in list(found.values()):
            if d.kind != "dir":
                continue
            key = f"d{d.ino}"
            if d.node is not None and d.node.fmt != _FMT_LOCAL:
                # its blocks may have been reused since: damage there is expected, not worth a warning
                quiet = len(self.warnings)
                live, _p = self._dir_entries(d.node, key, dele)
                del self.warnings[quiet:]
                dele.extend((key, raw, ino, False, ft) for raw, ino, ft in live if _name_ok(raw))
            elif d.data is not None and len(d.data) >= 6:
                isz = 8 if d.data[1] else 4
                self._stale_sf(d.data, 2 + isz, isz, dele, key)

        # give names to deleted inodes: entries of live folders first, then of deleted ones
        named: dict[int, tuple] = {}
        for dir_key, raw, ino, partial, ftype in dele:
            target = self._resolve(ino, partial, ftype)
            if target is None or target in named:
                continue
            d = found[target]
            if (ftype == _FTYPE_DIR) != (d.kind == "dir") and ftype:
                continue
            named[target] = (dir_key, raw)

        def parent_key(dk):
            if isinstance(dk, int):
                if dk in live_dirs:
                    return dk
                dk = f"d{dk}"
            if isinstance(dk, str) and dk[1:].isdigit():
                if dk[0] == "d":
                    d = found.get(int(dk[1:]))
                    return dk if d is not None and d.kind == "dir" else None
                if dk[0] == "r":
                    return dk                    # a folder known only from its blocks in free space
            return None

        parents: dict[int, object] = {}
        for ino, d in found.items():
            p = parent_key(named[ino][0]) if ino in named else None
            if p is None and d.parent_hint is not None:
                p = parent_key(d.parent_hint)
            parents[ino] = p if p != f"d{ino}" else None
        self._break_cycles(parents)
        for dk in sorted({p for p in parents.values() if isinstance(p, str) and p[0] == "r"}):
            yield Entry(key=dk, parent=None, name=f"inode {dk[1:]}", is_dir=True, deleted=True, chance=CHANCE_FAIR,
                        flags=F_ORPHAN | F_DIR_RECOVERED, extra={"inode": int(dk[1:])})
        count = 0
        for ino, d in found.items():
            count += 1
            if count % 256 == 0:
                ctl.check()
            parent = parents.get(ino)
            name = _name(named[ino][1]) if ino in named else f"inode {ino}"
            flags = 0 if parent is not None else F_ORPHAN
            e = self._deleted_entry(d, f"d{ino}", parent, name, flags)
            if e is not None:
                yield e

    def _break_cycles(self, parents: dict[int, object]) -> None:
        """Deleted folders whose parents lead back to themselves are moved to Lost files."""
        for ino in list(parents):
            seen = {ino}
            p = parents[ino]
            steps = 0
            while isinstance(p, str) and p.startswith("d") and steps < 10_000:
                q = int(p[1:])
                if q in seen:
                    parents[ino] = None
                    break
                seen.add(q)
                p = parents.get(q)
                steps += 1

    def _resolve(self, ino: int, partial: bool, ftype: int) -> int | None:
        """The deleted inode a leftover entry points to. A partial number has only its low 32 bits: the high
        bits are completed from the inodes that could match."""
        found = self._found_inodes
        if not partial:
            return ino if ino in found else None
        cands = [(h << 32) | ino for h in range(self._max_hi + 1)]
        hits = [c for c in cands if c in found]
        if len(hits) > 1 and ftype:
            want = "dir" if ftype == _FTYPE_DIR else "symlink" if ftype == _FTYPE_SYMLINK else "file"
            hits = [c for c in hits if found[c].kind == want] or hits
        return hits[0] if hits else None

    def _examine_free(self, node: _Inode, live_dirs: set[int]) -> _Deleted | None:
        """What a free inode still holds: a file's extent list, a folder's short-form leftovers, a symlink
        target — or nothing worth listing."""
        ino = node.ino
        times = (node.mtime, node.atime, node.ctime, node.crtime)
        if node.mode:
            # freed in the B+tree but the inode itself was never rewritten: it is whole
            d = _Deleted(ino, "dir" if node.kind == _S_IFDIR else "symlink" if node.kind == _S_IFLNK else "file")
            if node.kind not in (_S_IFDIR, _S_IFLNK, _S_IFREG):
                return None
            d.node = node
            d.times = times
            if node.kind == _S_IFDIR:
                quiet = len(self.warnings)
                d.parent_hint = self._dir_parent(node)
                del self.warnings[quiet:]
                if node.fmt == _FMT_LOCAL:
                    d.data = bytes(node.fork())
            return d
        lit = node.raw[node.lit:]
        if not any(lit[:32]):
            return None
        size = node.size
        # a symlink keeps its size and target; a folder keeps its size and short-form header
        if 0 < size <= len(lit) and size <= 1024:
            text = bytes(lit[:size])
            if b"\0" not in text and _name_ok(text.replace(b"/", b"x"), strict=True):
                d = _Deleted(ino, "symlink")
                d.data = text
                d.size = size
                d.times = times
                return d
        if 6 <= size <= len(lit):
            i8 = lit[1]
            isz = 8 if i8 else 4
            parent = int.from_bytes(lit[2:2 + isz], "big")
            if i8 <= lit[0] and parent != ino and (parent in live_dirs or self._ino_known(parent)):
                d = _Deleted(ino, "dir")
                d.data = bytes(lit)
                d.parent_hint = parent
                d.times = times
                return d
        exts = self._stale_extents(node)
        if not exts:
            return None
        if self.v5 and len(exts) == 1 and exts[0][2] <= 2 and exts[0][0] == 0:
            target = self._remote_symlink(ino, exts[0])
            if target is not None:
                d = _Deleted(ino, "symlink")
                d.data = target
                d.size = len(target)
                d.times = times
                return d
        d = _Deleted(ino, "file")
        d.exts = exts
        written = [x for x in exts if not x[3]]
        last = written[-1] if written else exts[-1]
        d.size = (last[0] + last[2]) * self.bs
        if 0 < size <= d.size:
            d.size = size                       # freed without being truncated (an older kernel, a crash)
        d.times = times
        return d

    def _remote_symlink(self, ino: int, ext: tuple) -> bytes | None:
        """The target of a deleted v5 symlink kept in blocks: each block has an XSLM header naming its owner."""
        out = bytearray()
        for k in range(ext[2]):
            off = self._fsb_off(ext[1] + k)
            blk = self.meta.read(off, self.bs) if off is not None else b""
            if blk[:4] != b"XSLM" or be64(blk, 32) != ino or be32(blk, 4) != len(out):
                return None
            n = be32(blk, 8)
            if not 0 < n <= self.bs - 56:
                return None
            out += blk[56:56 + n]
        return bytes(out) if out and b"\0" not in out else None

    def _stale_extents(self, node: _Inode) -> list | None:
        """Extent records (or a block-map root) left in a freed inode; None unless they look real."""
        lit = node.raw[node.lit:]
        level = be16(lit, 0)
        if 1 <= level <= 5:
            exts = self._bmbt(node.ino, bytes(lit), stale=True)
            if exts:
                exts.sort()
                return self._plausible(exts)
        n = min(len(lit) // 16, _MAX_STALE_EXTENTS)
        out = []
        for rec in _extents(lit, 0, n):
            if rec[2] == 0 and rec[0] == 0 and rec[1] == 0:
                break
            out.append(rec)
        return self._plausible(out)

    def _plausible(self, exts: list) -> list | None:
        """The leading records that could belong to one file: in order, inside one AG each, not in the AG
        headers or the log, at a sane logical offset."""
        good = []
        pos = 0
        for start, fsb, cnt, unwritten in exts:
            if not cnt or start < pos or (start + cnt) * self.bs > _MAX_STALE_LOGICAL or not self._fsb_ok(fsb, cnt):
                break
            off = self._fsb_off(fsb)
            if (fsb & self._agmask) * self.bs < 4 * self.sectsize:
                break
            if self._log and off < self._log[0] + self._log[1] and off + cnt * self.bs > self._log[0]:
                break
            good.append((start, fsb, cnt, unwritten))
            pos = start + cnt
        return good or None

    def _deleted_entry(self, d: _Deleted, key: str, parent, name: str, flags: int) -> Entry | None:
        mtime, atime, ctime, crtime = d.times
        if d.node is not None:                   # a whole inode (mode still set)
            e = self._entry(d.node, key, parent, name, flags, deleted=True)
            if e is not None and e.is_dir:
                e.chance = CHANCE_FAIR
            if e is not None and d.found_in != "inode B+tree":
                e.extra["found_in"] = d.found_in
            return e
        e = Entry(key=key, parent=parent, name=name, deleted=True, flags=flags, mtime=mtime, atime=atime,
                  ctime=ctime, crtime=crtime, extra={"inode": d.ino})
        if d.found_in != "inode B+tree":
            e.extra["found_in"] = d.found_in
        if d.kind == "dir":
            e.is_dir = True
            e.chance = CHANCE_FAIR
        elif d.kind == "symlink":
            e.flags |= F_SYMLINK
            e.data = d.data
            e.size = d.size
            e.chance = CHANCE_FAIR
        else:
            e.size = d.size
            e.runs, _holes, bad = self._runs(d.exts, d.size)
            e.extra["size_from_blocks"] = True       # XFS zeroes the size: it is rounded up to whole blocks
            e.chance = CHANCE_GOOD if not bad and self._all_free(e.runs) else CHANCE_POOR
        return e

    # ------------------------------------------------------------------ searching the free space
    def _scan_free_space(self, ctl: Control, free: list, live_dirs: set[int], dele: list) -> None:
        """Inodes of freed chunks and freed folder blocks, found by their signatures in the free space. On v5
        both carry the filesystem's UUID, which keeps out what an earlier filesystem left on the disk."""
        found = self._found_inodes
        total = sum(n for _o, n in free) or 1
        done = 0
        bs, isize = self.bs, self.isize
        for off, length in free:
            pos = off
            end = off + length
            while pos < end:
                n = min(_SCAN_PIECE, end - pos)
                buf = self.src.read(pos, n)
                for m in _INODE_RE.finditer(buf):
                    rel = m.start()
                    at = pos + rel
                    if at % isize:
                        continue
                    ino = self._off_ino(at)
                    if ino is None or self._chunk_of(ino) is not None or ino in found:
                        continue
                    node = _decode_inode(buf[rel:rel + isize] if rel + isize <= n else self.src.read(at, isize), ino)
                    if node is None or (node.di_ino is not None and node.di_ino != ino):
                        continue
                    if node.di_ino is None and (node.version != 2 or node.nlink > 1 << 20):
                        continue
                    if node.di_ino is not None and self._meta_uuid and node.raw[160:176] != self._meta_uuid:
                        continue
                    d = self._examine_free(node, live_dirs)
                    if d is not None:
                        d.found_in = "free space"
                        found[ino] = d
                for m in _DIRBLK_RE.finditer(buf):
                    rel = m.start()
                    at = pos + rel
                    if at % bs:
                        continue
                    blk = buf[rel:rel + self.dirbs] if rel + self.dirbs <= n else self.src.read(at, self.dirbs)
                    owner = be64(blk, 40) if blk[:4] in (b"XDB3", b"XDD3") else None
                    if owner is not None and (self._ino_off(owner) is None
                                              or (self._meta_uuid and blk[24:40] != self._meta_uuid)):
                        continue
                    if owner is None:
                        dir_key = None
                    elif owner in live_dirs:
                        dir_key = owner
                    else:
                        dir_key = f"r{owner}"
                    names: list = []
                    self._parse_dir_block(blk, None, names, dir_key)
                    for item in names:
                        if len(dele) < _MAX_DELETED_NAMES:
                            dele.append(item)
                pos += n
                done += n
                ctl.check()
                ctl.progress(done / total, "Searching the free space for deleted inodes")
        # a deleted folder whose own inode was found: its blocks' names belong to it
        for k, item in enumerate(dele):
            dk = item[0]
            if isinstance(dk, str) and dk[0] == "r":
                d = found.get(int(dk[1:]))
                if d is not None and d.kind == "dir":
                    dele[k] = (f"d{dk[1:]}",) + tuple(item[1:])
