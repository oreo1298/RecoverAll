"""XFS reader: real mkfs.xfs images (v5 and v4, built from prototype files: the kernel here can't mount XFS),
cross-checked with xfs_db, plus deletions simulated byte for byte the way Linux performs them.

What a simulated deletion does (see :func:`delete_file`), following fs/xfs in Linux 6.x:

- the folder entry is removed: in a short-form folder the later entries slide down and the size shrinks
  (xfs_dir2_sf_removename; the bytes past the new end are left as they were); in a folder block the entry
  becomes an unused region merged with free neighbours (xfs_dir2_data_make_free: free tag + length over
  the first 4 bytes, a tag at the end), the best-free table is updated and its hash-leaf entry is marked
  stale;
- the inode is freed (xfs_inactive_truncate + xfs_ifree): mode, link count, block and extent counts and
  the fork offset are zeroed, the format becomes "extents", the generation is bumped; regular files (and
  remote symlinks) get size 0, folders and inline symlinks keep theirs; the extent records in the literal
  area are NOT touched (the kernel only copies live extents into it when it flushes the inode);
- the inode's bit is set in the inode B+tree and the free-inode B+tree record (free count + 1);
- the file's extents are inserted into the by-block free-space B+tree.

When a whole chunk is freed (test_deleted_folder_freed_chunk) its inode B+tree record is removed and its
blocks become free space, while the inodes keep their last flushed state (xfs_ifree_cluster marks the
buffers stale, so the freed versions never reach the disk).

Not simulated (the reader doesn't use them): the by-size free-space tree, the reverse-map tree, the AGF/AGI
and superblock counters, and the leaf/free index blocks of big folders. CRCs are recomputed so xfs_db still
reads the image.
"""

from __future__ import annotations

import os
import random
import struct
from pathlib import Path

import pytest
from imagekit import MiB, need, payload, sh

from recoverall.core.blockio import BytesSource, FileSource
from recoverall.core.fs import base as fsbase
from recoverall.core.fs.base import (
    CHANCE_GOOD,
    CHANCE_POOR,
    F_DIR_RECOVERED,
    F_HARDLINK,
    F_ORPHAN,
    F_SYMLINK,
    F_SYSTEM,
    read_content,
)
from recoverall.core.fs.xfs import XfsReader, parse_superblock

# mkfs.xfs refuses filesystems under 300 MB unless it runs under fstests: these make small test images possible
SMALL_ENV = {"TEST_DIR": "/tmp", "TEST_DEV": "/dev/null", "QA_CHECK_FS": "xfs"}


# ---------------------------------------------------------------------- building images
class Proto:
    """A mkfs.xfs prototype file: the tree to create, with the content of every file."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.src = tmp / "proto-src"
        self.src.mkdir(exist_ok=True)
        self.lines = ["/dev/null", "0 0", "d--755 0 0"]
        self.files: dict[str, bytes] = {}
        self.links: dict[str, str] = {}
        self.dirs: list[str] = []
        self.path: list[str] = []
        self.n = 0

    def file(self, name: str, data: bytes) -> str:
        self.n += 1
        p = self.src / f"f{self.n}"
        p.write_bytes(data)
        self.lines.append(" " * (len(self.path) + 1) + f"{name} ---644 0 0 {p}")
        rel = "/".join(self.path + [name])
        self.files[rel] = data
        return rel

    def symlink(self, name: str, target: str) -> None:
        self.lines.append(" " * (len(self.path) + 1) + f"{name} l--777 0 0 {target}")
        self.links["/".join(self.path + [name])] = target

    def mkdir(self, name: str) -> None:
        self.lines.append(" " * (len(self.path) + 1) + f"{name} d--755 0 0")
        self.path.append(name)
        self.dirs.append("/".join(self.path))

    def up(self) -> None:
        self.lines.append(" " * len(self.path) + "$")
        self.path.pop()

    def build(self, img: Path, size: int = 64 * MiB, opts: tuple = (), label: str = "TEST") -> Path:
        need("mkfs.xfs", "xfs_db")
        while self.path:
            self.up()
        text = "\n".join(self.lines + ["$"]) + "\n"
        proto = self.tmp / f"{img.name}.proto"
        proto.write_text(text)
        for attempt_size in (size, max(size, 320 * MiB)):
            with open(img, "wb") as fh:
                fh.truncate(attempt_size)
            try:
                sh("mkfs.xfs", "-q", "-f", "-L", label, *opts, "-p", proto, img, env=SMALL_ENV)
                return img
            except RuntimeError as exc:
                if "300MB" not in str(exc) and "larger than" not in str(exc):
                    if "crc=0" in " ".join(opts) or "V4" in str(exc):
                        pytest.skip(f"this mkfs.xfs can't make that filesystem: {exc}")
                    raise
        pytest.skip("mkfs.xfs refuses small filesystems")


def xdb(img: Path, *cmds: str, expert: bool = False) -> str:
    args = ["xfs_db", "-x" if expert else "-r"]
    for c in cmds:
        args += ["-c", c]
    return sh(*args, img)


def sb_values(img: Path) -> dict:
    out = {}
    for line in xdb(img, "sb 0", "print").splitlines():
        if " = " in line:
            k, v = line.split(" = ", 1)
            out[k.strip()] = v.strip()
    return out


def entries_of(img: Path, **info):
    src = FileSource(str(img))
    r = XfsReader(src, {**(XfsReader.probe(src) or {}), **info})
    return src, r, list(r.entries())


def paths(es) -> dict[str, object]:
    """'folder/name' → Entry, following parent keys (entries in Lost files start with '?/')."""
    by = {e.key: e for e in es}
    root = es[0].key
    out = {}
    for e in es:
        if e.key == root:
            continue
        parts = []
        p = e
        guard = 0
        while p is not None and p.key != root and guard < 100:
            parts.append(p.name)
            p = by.get(p.parent) if p.parent is not None else None
            guard += 1
        if p is None:
            parts.append("?")
        out["/".join(reversed(parts))] = e
    return out


def content(src, e) -> bytes:
    return b"".join(read_content(src, e))


# ---------------------------------------------------------------------- simulating Linux's unlink
_T = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _T.append(_c)


def crc32c(data: bytes) -> int:
    c = 0xFFFFFFFF
    for b in data:
        c = _T[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


class Img:
    """Raw read/write access to an XFS image with the geometry from xfs_db (not from the reader under test)."""

    def __init__(self, path: Path):
        self.path = path
        sb = sb_values(path)
        self.bs = int(sb["blocksize"])
        self.agblocks = int(sb["agblocks"])
        self.agblklog = int(sb["agblklog"])
        self.isize = int(sb["inodesize"])
        self.inopblog = int(sb["inopblog"])
        self.sectsize = int(sb["sectsize"])
        self.v5 = (int(sb["versionnum"], 16) & 0xF) == 5
        self.ftype = self.v5 and bool(int(sb["features_incompat"], 16) & 1) or \
            (not self.v5 and bool(int(sb["features2"], 16) & 0x200))
        self.sparse = self.v5 and bool(int(sb["features_incompat"], 16) & 2)
        self.fh = open(path, "r+b")

    def close(self):
        self.fh.close()

    def read(self, off: int, n: int) -> bytearray:
        self.fh.seek(off)
        return bytearray(self.fh.read(n))

    def write(self, off: int, data: bytes) -> None:
        self.fh.seek(off)
        self.fh.write(data)

    def agoff(self, agno: int, agbno: int = 0) -> int:
        return (agno * self.agblocks + agbno) * self.bs

    def fsb(self, fsb: int) -> int:
        return self.agoff(fsb >> self.agblklog, fsb & ((1 << self.agblklog) - 1))

    def ino(self, ino: int) -> int:
        agino_log = self.agblklog + self.inopblog
        agno, agino = ino >> agino_log, ino & ((1 << agino_log) - 1)
        return self.agoff(agno, agino >> self.inopblog) + (agino & ((1 << self.inopblog) - 1)) * self.isize

    # -- checksummed writes
    def put_inode(self, ino: int, raw: bytearray) -> None:
        if self.v5:
            raw[100:104] = b"\0" * 4
            raw[100:104] = struct.pack("<I", crc32c(bytes(raw)))
        self.write(self.ino(ino), raw)

    def put_block(self, off: int, blk: bytearray, crc_off: int | None) -> None:
        if self.v5 and crc_off is not None:
            blk[crc_off:crc_off + 4] = b"\0" * 4
            blk[crc_off:crc_off + 4] = struct.pack("<I", crc32c(bytes(blk)))
        self.write(off, blk)

    # -- reading an inode
    def inode(self, ino: int) -> bytearray:
        return self.read(self.ino(ino), self.isize)

    def lit(self) -> int:
        return 176 if self.v5 else 100

    def extents(self, ino: int) -> list[tuple[int, int, int]]:
        raw = self.inode(ino)
        assert raw[5] == 2, "only extent-format inodes here"
        n = struct.unpack_from(">I", raw, 76)[0]
        out = []
        for k in range(n):
            l0, l1 = struct.unpack_from(">QQ", raw, self.lit() + 16 * k)
            out.append(((l0 >> 9) & ((1 << 54) - 1), ((l0 & 0x1FF) << 43) | (l1 >> 21), l1 & 0x1FFFFF))
        return out

    # -- the operations Linux performs on unlink
    def free_inode(self, ino: int, clear: bool = True) -> None:
        """Mark INO free in the inode B+trees; with CLEAR, zero the inode core the way xfs_ifree does. Only
        regular files and remote symlinks are truncated (size 0): folders and inline symlinks keep it."""
        if clear:
            raw = self.inode(ino)
            mode = struct.unpack_from(">H", raw, 2)[0] & 0o170000
            keep_size = mode == 0o040000 or (mode == 0o120000 and raw[5] == 1)
            struct.pack_into(">H", raw, 2, 0)            # mode
            raw[5] = 2                                   # format: extents
            struct.pack_into(">I", raw, 16, 0)           # nlink
            if not keep_size:
                struct.pack_into(">Q", raw, 56, 0)       # size
            struct.pack_into(">Q", raw, 64, 0)           # nblocks
            struct.pack_into(">I", raw, 76, 0)           # nextents
            raw[82] = 0                                  # forkoff
            struct.pack_into(">H", raw, 90, 0)           # flags
            struct.pack_into(">I", raw, 92, struct.unpack_from(">I", raw, 92)[0] + 1)
            self.put_inode(ino, raw)
        agino_log = self.agblklog + self.inopblog
        agno, agino = ino >> agino_log, ino & ((1 << agino_log) - 1)
        agi = self.read(self.agoff(agno) + 2 * self.sectsize, self.sectsize)
        roots = [(struct.unpack_from(">I", agi, 20)[0], struct.unpack_from(">I", agi, 24)[0])]
        if self.v5:
            roots.append((struct.unpack_from(">I", agi, 328)[0], struct.unpack_from(">I", agi, 332)[0]))
        hdr = 56 if self.v5 else 16
        for root, level in roots:
            assert level == 1, "test images have one-block inode B+trees"
            off = self.agoff(agno, root)
            blk = self.read(off, self.bs)
            n = struct.unpack_from(">H", blk, 6)[0]
            for k in range(n):
                p = hdr + 16 * k
                start = struct.unpack_from(">I", blk, p)[0]
                if start <= agino < start + 64:
                    bit = 1 << (agino - start)
                    free = struct.unpack_from(">Q", blk, p + 8)[0]
                    assert not free & bit
                    struct.pack_into(">Q", blk, p + 8, free | bit)
                    if self.sparse:
                        blk[p + 7] += 1
                    else:
                        struct.pack_into(">I", blk, p + 4, struct.unpack_from(">I", blk, p + 4)[0] + 1)
                    break
            else:
                raise AssertionError(f"no inode B+tree record for {ino}")
            self.put_block(off, blk, 52)

    def fix_remote_symlink(self, ino: int) -> None:
        """Give a v5 remote symlink block the XSLM header the kernel writes (xfsprogs 6.6 protofiles leave it
        out, which xfs_repair would reject)."""
        raw = self.inode(ino)
        size = struct.unpack_from(">Q", raw, 56)[0]
        [(_l, fsb, cnt)] = self.extents(ino)
        assert cnt == 1 and size <= self.bs - 56
        off = self.fsb(fsb)
        blk = self.read(off, self.bs)
        if blk[:4] == b"XSLM":
            return
        target = bytes(blk[:size])
        uuid = bytes.fromhex(sb_values(self.path)["uuid"].replace("-", ""))
        new = bytearray(self.bs)
        struct.pack_into(">4sIII16sQQQ", new, 0, b"XSLM", 0, size, 0, uuid, ino, off // 512, 0)
        new[56:56 + size] = target
        self.put_block(off, new, 12)

    def free_extent(self, fsb: int, count: int) -> None:
        """Insert [fsb, fsb+count) into the by-block free-space B+tree (merging with neighbours)."""
        agno, agbno = fsb >> self.agblklog, fsb & ((1 << self.agblklog) - 1)
        agf = self.read(self.agoff(agno) + self.sectsize, self.sectsize)
        root, level = struct.unpack_from(">I", agf, 16)[0], struct.unpack_from(">I", agf, 28)[0]
        assert level == 1
        off = self.agoff(agno, root)
        blk = self.read(off, self.bs)
        hdr = 56 if self.v5 else 16
        n = struct.unpack_from(">H", blk, 6)[0]
        recs = [struct.unpack_from(">II", blk, hdr + 8 * k) for k in range(n)]
        recs.append((agbno, count))
        recs.sort()
        merged: list[list[int]] = []
        for s, c in recs:
            if merged and merged[-1][0] + merged[-1][1] == s:
                merged[-1][1] += c
            else:
                assert not merged or merged[-1][0] + merged[-1][1] < s, "extent already free"
                merged.append([s, c])
        struct.pack_into(">H", blk, 6, len(merged))
        for k, (s, c) in enumerate(merged):
            struct.pack_into(">II", blk, hdr + 8 * k, s, c)
        self.put_block(off, blk, 52)

    def sf_remove(self, dir_ino: int, name: bytes) -> None:
        """xfs_dir2_sf_removename: slide the later entries down, shrink the size; the tail is not cleared."""
        raw = self.inode(dir_ino)
        assert raw[5] == 1
        lit = self.lit()
        size = struct.unpack_from(">Q", raw, 56)[0]
        sf = raw[lit:lit + size]
        isz = 8 if sf[1] else 4
        ft = 1 if self.ftype else 0
        p = 2 + isz
        for _ in range(sf[0]):
            n = sf[p]
            esize = 3 + n + ft + isz
            if bytes(sf[p + 3:p + 3 + n]) == name:
                sf[p:size - esize] = sf[p + esize:size]
                sf[0] -= 1
                raw[lit:lit + size - esize] = sf[:size - esize]
                struct.pack_into(">Q", raw, 56, size - esize)
                self.put_inode(dir_ino, raw)
                return
            p += esize
        raise AssertionError(f"{name!r} not in folder {dir_ino}")

    def block_remove(self, dir_ino: int, name: bytes) -> None:
        """xfs_dir2_data_make_free on the entry NAME of a block/leaf folder, and its leaf entry made stale."""
        hdr = 64 if self.v5 else 16
        ft = 1 if self.ftype else 0
        for lblk, fsb, cnt in self.extents(dir_ino):
            for k in range(cnt):
                if lblk + k >= (1 << 35) // self.bs:
                    continue
                off = self.fsb(fsb + k)
                blk = self.read(off, self.bs)
                magic = bytes(blk[:4])
                if magic not in (b"XD2B", b"XDB3", b"XD2D", b"XDD3"):
                    continue
                end = self.bs
                block_form = magic in (b"XD2B", b"XDB3")
                if block_form:
                    end = self.bs - 8 - 8 * struct.unpack_from(">I", blk, self.bs - 8)[0]
                p = hdr
                while p < end:
                    if struct.unpack_from(">H", blk, p)[0] == 0xFFFF:
                        p += struct.unpack_from(">H", blk, p + 2)[0]
                        continue
                    n = blk[p + 8]
                    size = (11 + n + ft + 7) & ~7
                    if bytes(blk[p + 9:p + 9 + n]) == name:
                        self._make_free(blk, p, size, end)
                        self._best_free(blk, hdr, end)
                        if block_form:
                            cnt_leaf = struct.unpack_from(">I", blk, self.bs - 8)[0]
                            for j in range(cnt_leaf):
                                lp = end + 8 * j
                                if struct.unpack_from(">I", blk, lp + 4)[0] == p >> 3:
                                    struct.pack_into(">I", blk, lp + 4, 0)
                                    struct.pack_into(">I", blk, self.bs - 4,
                                                     struct.unpack_from(">I", blk, self.bs - 4)[0] + 1)
                        self.put_block(off, blk, 4)
                        return
                    p += size
        raise AssertionError(f"{name!r} not in folder {dir_ino}")

    def _best_free(self, blk: bytearray, hdr: int, end: int) -> None:
        """The block header's table of its three biggest unused regions (xfs_db checks it)."""
        regions = []
        p = hdr
        ft = 1 if self.ftype else 0
        while p < end:
            if struct.unpack_from(">H", blk, p)[0] == 0xFFFF:
                n = struct.unpack_from(">H", blk, p + 2)[0]
                regions.append((n, p))
                p += n
            else:
                p += (11 + blk[p + 8] + ft + 7) & ~7
        regions.sort(key=lambda r: (-r[0], r[1]))
        bf = 48 if self.v5 else 4
        for k in range(3):
            n, off = regions[k] if k < len(regions) else (0, 0)
            struct.pack_into(">HH", blk, bf + 4 * k, off, n)

    @staticmethod
    def _make_free(blk: bytearray, off: int, length: int, end: int) -> None:
        def free_at(p):
            return p < end and struct.unpack_from(">H", blk, p)[0] == 0xFFFF

        prev = struct.unpack_from(">H", blk, off - 2)[0]
        prevdup = prev if free_at(prev) and prev < off else None
        postdup = off + length if free_at(off + length) else None
        if prevdup is not None and postdup is not None:
            total = struct.unpack_from(">H", blk, prevdup + 2)[0] + length + struct.unpack_from(">H", blk, postdup + 2)[0]
            struct.pack_into(">H", blk, prevdup + 2, total)
            struct.pack_into(">H", blk, prevdup + total - 2, prevdup)
        elif prevdup is not None:
            total = struct.unpack_from(">H", blk, prevdup + 2)[0] + length
            struct.pack_into(">H", blk, prevdup + 2, total)
            struct.pack_into(">H", blk, prevdup + total - 2, prevdup)
        elif postdup is not None:
            total = length + struct.unpack_from(">H", blk, postdup + 2)[0]
            struct.pack_into(">HH", blk, off, 0xFFFF, total)
            struct.pack_into(">H", blk, off + total - 2, off)
        else:
            struct.pack_into(">HH", blk, off, 0xFFFF, length)
            struct.pack_into(">H", blk, off + length - 2, off)


def ino_of(img: Path, folder: str, name: str) -> int:
    for line in xdb(img, f"ls /{folder}" if folder else "ls /").splitlines():
        parts = line.split()
        if len(parts) >= 6 and " ".join(parts[5:-1]) == name:
            return int(parts[1])
    raise AssertionError(f"{folder}/{name} not found")


def delete_file(img: Path, folder: str, name: str, folder_ino: int, shortform: bool,
                free_blocks: bool = True, clear_inode: bool = True) -> int:
    """Delete FOLDER/NAME the way Linux does (see the module docstring). Returns its inode number."""
    ino = ino_of(img, folder, name)
    im = Img(img)
    try:
        exts = im.extents(ino) if im.inode(ino)[5] == 2 else []
        if shortform:
            im.sf_remove(folder_ino, name.encode())
        else:
            im.block_remove(folder_ino, name.encode())
        im.free_inode(ino, clear=clear_inode)
        if free_blocks:
            for _l, fsb, cnt in exts:
                im.free_extent(fsb, cnt)
    finally:
        im.close()
    return ino


# ---------------------------------------------------------------------- fixtures
def rich_proto(tmp: Path) -> Proto:
    p = Proto(tmp)
    p.file("big.bin", payload(5_000_000, 7))
    p.file("small.txt", b"hello xfs\n")
    p.file("empty", b"")
    p.symlink("lnk", "small.txt")
    p.symlink("longlnk", "/very/long/" + "x" * 600)
    p.mkdir("blockdir")
    for i in range(30):
        p.file(f"b{i:03d}.dat", payload(100 + 37 * i, 1000 + i))
    p.up()
    p.mkdir("leafdir")
    for i in range(150):
        p.file(f"leaf_file_{i:04d}.dat", payload(50 + i, 2000 + i))
    p.up()
    p.mkdir("nodedir")          # enough entries for a node folder whose block map is a B+tree
    for i in range(2600):
        p.file(f"node_file_number_{i:05d}.dat", payload(10 + i % 50, 3000 + i))
    p.up()
    p.mkdir("uni")
    p.file("héllo_wörld_日本語.txt", payload(3000, 5))
    p.file("L" * 255, payload(5000, 6))
    p.mkdir("deep")
    p.mkdir("deeper")
    p.file("bottom.bin", payload(20000, 8))
    return p


@pytest.fixture(scope="module")
def rich(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("xfsrich")
    p = rich_proto(tmp)
    img = p.build(tmp / "rich.img", 96 * MiB, label="RICH")
    return img, p


# ---------------------------------------------------------------------- tests: the superblock
def test_probe_v5(rich):
    img, _p = rich
    sb = sb_values(img)
    src = FileSource(str(img))
    info = XfsReader.probe(src)
    assert info["fstype"] == "xfs" and info["label"] == "RICH" and info["version"] == 5
    assert info["uuid"] == sb["uuid"]
    assert info["block_size"] == int(sb["blocksize"]) and info["sector_size"] == int(sb["sectsize"])
    assert info["ag_count"] == int(sb["agcount"]) and info["ag_blocks"] == int(sb["agblocks"])
    assert info["ag_blklog"] == int(sb["agblklog"]) and info["inode_size"] == int(sb["inodesize"])
    assert info["root_ino"] == int(sb["rootino"]) and info["size"] == int(sb["dblocks"]) * int(sb["blocksize"])
    assert info["free"] == int(sb["fdblocks"]) * int(sb["blocksize"])
    incompat, ro = int(sb["features_incompat"], 16), int(sb["features_ro_compat"], 16)
    assert info["crc"] and info["ftype"]
    assert info["bigtime"] == bool(incompat & 8) and info["reflink"] == bool(ro & 4)
    assert info["sparse_inodes"] == bool(incompat & 2) and info["finobt"] == bool(ro & 1)
    # the backup superblock of AG 1 parses the same way (the partition search uses it)
    backup = src.read(info["ag_blocks"] * info["block_size"], 512)
    binfo = parse_superblock(backup)
    assert binfo and binfo["ag_count"] == info["ag_count"] and binfo["uuid"] == info["uuid"]
    assert parse_superblock(bytes(512)) is None
    bad = bytearray(src.read(0, 512))
    struct.pack_into(">I", bad, 4, 3000)          # a block size that isn't a power of two
    assert parse_superblock(bytes(bad)) is None
    assert XfsReader.probe(BytesSource(bytes(4096))) is None


# ---------------------------------------------------------------------- tests: what exists
def check_tree(img: Path, p: Proto, es, src) -> dict:
    ps = paths(es)
    assert es[0].parent is None and es[0].is_dir and es[0].name == ""
    keys = [e.key for e in es]
    assert len(keys) == len(set(keys))
    for rel, data in p.files.items():
        assert rel in ps, rel
        e = ps[rel]
        assert not e.deleted and e.chance == CHANCE_GOOD and not e.is_dir
        assert e.size == len(data), rel
        assert content(src, e) == data, rel
    for rel, target in p.links.items():
        e = ps[rel]
        assert e.flags & F_SYMLINK and e.data == target.encode()
    for rel in p.dirs:
        assert ps[rel].is_dir, rel
    return ps


def test_live_tree_v5(rich):
    img, p = rich
    src, r, es = entries_of(img)
    ps = check_tree(img, p, es, src)
    assert r.warnings == []
    assert not any(e.deleted for e in es)
    # folder formats really are the ones this test means to cover (local, extents, and here a B+tree
    # map for the big folder — other mkfs versions may place its blocks contiguously)
    for folder, fmts in (("blockdir", "2"), ("nodedir", "23"), ("uni", "1")):
        fmt = xdb(img, f"path /{folder}", "print core.format").split("=")[1].split()[0]
        assert fmt in fmts, folder
    # xfs_db agrees on the listing of a big folder and on inode numbers
    listed = {}
    for line in xdb(img, "ls /leafdir").splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[5] not in (".", ".."):
            listed[parts[5]] = int(parts[1])
    assert listed == {e.name: e.key for e in es if e.parent == ps["leafdir"].key}
    # every (inode, path) pair xfs_db finds is ours too
    pairs = set()
    for line in xdb(img, "blockget -n", "ncheck").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            pairs.add((int(parts[0]), parts[1].removesuffix("/.")))       # folders are listed as "name/."
    assert len(pairs) > 2700
    assert pairs == {(e.key, path) for path, e in ps.items() if not e.flags & F_SYSTEM}
    # times: mkfs stamps files with the current time; bigtime decodes to the same thing
    mt = ps["big.bin"].mtime
    assert mt and abs(mt - os.path.getmtime(img)) < 3600
    # the realtime bitmap/summary inodes are listed as system files under the root
    sysf = [e for e in es if e.flags & F_SYSTEM]
    assert {e.name for e in sysf} == {"$rtbitmap", "$rtsummary"} and all(e.parent == r.root_key for e in sysf)


@pytest.mark.parametrize("opts", [("-m", "crc=0"), ("-m", "crc=0", "-n", "ftype=0"),
                                  ("-b", "size=1024", "-n", "size=8192"), ("-i", "nrext64=1,sparse=0")],
                         ids=["v4", "v4-noftype", "1k-blocks-8k-dirs", "nrext64"])
def test_other_formats(tmp_path, opts):
    p = Proto(tmp_path)
    p.file("a.bin", payload(70_000, 1))
    p.symlink("s", "a.bin")
    p.symlink("long", "/" + "y" * 400)
    p.mkdir("d")
    for i in range(400):
        p.file(f"file-with-a-longish-name-{i:04d}", payload(i, 100 + i))
    p.up()
    p.mkdir("sf")
    p.file("x", b"x")
    img = p.build(tmp_path / "o.img", 64 * MiB, opts)
    src, r, es = entries_of(img)
    info = XfsReader.probe(src)
    assert info["version"] == (4 if "crc=0" in opts else 5)
    assert info["ftype"] == ("ftype=0" not in opts)
    check_tree(img, p, es, src)
    assert r.warnings == []


def test_btree_file(tmp_path):
    """A file whose block map is a B+tree, crafted with xfs_db's help: protofiles always get contiguous
    space. Its 4 KiB pieces are shuffled on disk, one is a hole and one is unwritten (reads as zeros)."""
    p = Proto(tmp_path)
    data = payload(64 * 4096 + 1234, 9)
    p.file("other", payload(10, 1))
    p.file("frag.bin", data)            # the root's last entry: its name survives the delete
    img = p.build(tmp_path / "b.img", 64 * MiB)
    ino = ino_of(img, "", "frag.bin")
    im = Img(img)
    try:
        [(lblk, fsb, cnt)] = im.extents(ino)
        assert cnt == 65
        rng = random.Random(5)
        order = list(range(cnt))
        rng.shuffle(order)
        blocks = [im.read(im.fsb(fsb + k), im.bs) for k in range(cnt)]
        recs = []
        expected = bytearray(data + bytes(65 * 4096 - len(data)))
        for k in range(cnt):
            im.write(im.fsb(fsb + order[k]), blocks[k])
            if k == 10:
                expected[k * 4096:(k + 1) * 4096] = bytes(4096)        # a hole: no record
                continue
            flag = 1 if k == 20 else 0                                 # unwritten
            if flag:
                expected[k * 4096:(k + 1) * 4096] = bytes(4096)
            recs.append((flag, k, fsb + order[k], 1))
        # the B+tree leaf goes in a free block of AG 0 (taken from the free-space tree's last record)
        agf = im.read(im.agoff(0) + im.sectsize, im.sectsize)
        bno_root = struct.unpack_from(">I", agf, 16)[0]
        bblk = im.read(im.agoff(0, bno_root), im.bs)
        n = struct.unpack_from(">H", bblk, 6)[0]
        start, length = struct.unpack_from(">II", bblk, 56 + 8 * (n - 1))
        leaf_fsb = start + length - 1                                   # AG 0: agbno == fsb
        struct.pack_into(">II", bblk, 56 + 8 * (n - 1), start, length - 1)
        im.put_block(im.agoff(0, bno_root), bblk, 52)
        uuid = bytes.fromhex(sb_values(img)["uuid"].replace("-", ""))
        leaf = bytearray(im.bs)
        leaf[:4] = b"BMA3"
        struct.pack_into(">HHQQQQ", leaf, 4, 0, len(recs), 2 ** 64 - 1, 2 ** 64 - 1, im.fsb(leaf_fsb) // 512, 0)
        leaf[40:56] = uuid
        struct.pack_into(">Q", leaf, 56, ino)
        for k, (flag, lo, pb, c) in enumerate(recs):
            l0 = (flag << 63) | (lo << 9) | (pb >> 43)
            l1 = ((pb & ((1 << 43) - 1)) << 21) | c
            struct.pack_into(">QQ", leaf, 72 + 16 * k, l0, l1)
        im.put_block(im.fsb(leaf_fsb), leaf, 64)
        raw = im.inode(ino)
        raw[5] = 3
        struct.pack_into(">I", raw, 76, len(recs))
        struct.pack_into(">Q", raw, 64, len(recs) + 1)
        lit = bytearray(im.isize - 176)
        maxr = (len(lit) - 4) // 16
        struct.pack_into(">HH", lit, 0, 1, 1)
        struct.pack_into(">Q", lit, 4, 0)
        struct.pack_into(">Q", lit, 4 + 8 * maxr, leaf_fsb)
        raw[176:] = lit
        im.put_inode(ino, raw)
    finally:
        im.close()
    bmap = xdb(img, f"inode {ino}", "bmap")
    assert bmap.count("data offset") == 64 and "flag 1" in bmap
    src, r, es = entries_of(img)
    e = paths(es)["frag.bin"]
    assert content(src, e) == bytes(expected[:len(data)])
    assert r.warnings == []

    # deleted, its block map root stays in the inode and its B+tree block in free space: still readable
    root_ino = int(sb_values(img)["rootino"])
    delete_file(img, "", "frag.bin", root_ino, shortform=True, free_blocks=False)
    im = Img(img)
    try:
        for flag, lo, pb, c in recs:
            im.free_extent(pb, c)
        im.free_extent(leaf_fsb, 1)
    finally:
        im.close()
    src, r, es = entries_of(img)
    [d] = [e for e in es if e.deleted]
    assert d.name == "frag.bin" and d.chance == CHANCE_GOOD and d.size == 65 * 4096
    assert content(src, d)[:len(data)] == bytes(expected[:len(data)])


# ---------------------------------------------------------------------- tests: deleted files
def small_proto(tmp: Path) -> Proto:
    p = Proto(tmp)
    p.file("keep.txt", b"keep me\n")
    p.mkdir("photos")
    for i in range(40):
        p.file(f"IMG_{i:04d}.JPG", payload(9000 + 1000 * i, 50 + i))
    p.up()
    p.mkdir("docs")                    # short-form folder
    p.file("a.txt", payload(5000, 1))
    p.file("report.pdf", payload(70_000, 2))
    p.file("zlast.doc", payload(12_345, 3))
    p.up()
    p.file("movie.mkv", payload(2_000_000, 4))
    return p


@pytest.mark.parametrize("opts", [(), ("-m", "crc=0", "-n", "ftype=0")], ids=["v5", "v4-noftype"])
def test_deleted_files(tmp_path, opts):
    p = small_proto(tmp_path)
    img = p.build(tmp_path / "d.img", 64 * MiB, opts)
    root = int(sb_values(img)["rootino"])
    photos = ino_of(img, "", "photos")
    docs = ino_of(img, "", "docs")
    # a block folder: one lone entry (low half of its inode number left), then two neighbours (the second
    # merges into the first's free region and keeps its whole inode number)
    i7 = delete_file(img, "photos", "IMG_0007.JPG", photos, shortform=False)
    i20 = delete_file(img, "photos", "IMG_0020.JPG", photos, shortform=False)
    i21 = delete_file(img, "photos", "IMG_0021.JPG", photos, shortform=False)
    # a short-form folder: the last entry survives past the new end of the folder; one in the middle doesn't
    izl = delete_file(img, "docs", "zlast.doc", docs, shortform=True)
    ia = delete_file(img, "docs", "a.txt", docs, shortform=True)
    # a big file in the root whose blocks are then reused by another file (not freed here: "in use")
    imv = delete_file(img, "", "movie.mkv", root, shortform=True, free_blocks=False)
    assert "IMG_0007.JPG" not in xdb(img, "ls /photos") and "zlast.doc" not in xdb(img, "ls /docs")

    src, r, es = entries_of(img)
    live = check_tree(img, _without(p, {"photos/IMG_0007.JPG", "photos/IMG_0020.JPG", "photos/IMG_0021.JPG",
                                        "docs/zlast.doc", "docs/a.txt", "movie.mkv"}), [e for e in es if not e.deleted], src)
    dels = {e.extra["inode"]: e for e in es if e.deleted}
    assert set(dels) == {i7, i20, i21, izl, ia, imv}
    bs = r.bs
    for ino, rel, parent in ((i7, "photos/IMG_0007.JPG", photos), (i20, "photos/IMG_0020.JPG", photos),
                             (i21, "photos/IMG_0021.JPG", photos), (izl, "docs/zlast.doc", docs)):
        e = dels[ino]
        data = p.files[rel]
        assert e.name == rel.split("/")[1] and e.parent == parent and not e.flags & F_ORPHAN, rel
        assert e.key == f"d{ino}" and e.chance == CHANCE_GOOD
        assert e.size == -(-len(data) // bs) * bs and e.extra.get("size_from_blocks")
        got = content(src, e)
        assert got[:len(data)] == data and not any(got[len(data):]), rel
    # no name left for a.txt: Lost files, but the content is whole
    e = dels[ia]
    assert e.parent is None and e.flags & F_ORPHAN and e.name == f"inode {ia}"
    assert content(src, e)[:5000] == p.files["docs/a.txt"]
    # the movie's blocks were never given back to the free space: poor chance; it was the root's last entry
    assert dels[imv].chance == CHANCE_POOR and dels[imv].name == "movie.mkv" and dels[imv].parent == root
    assert content(src, dels[imv])[:2_000_000] == p.files["movie.mkv"]
    # deleted=False hides them, and nothing else changes
    r2 = XfsReader(src, XfsReader.probe(src))
    assert [e.key for e in r2.entries(deleted=False)] == [e.key for e in es if not e.deleted]
    assert live


def _without(p: Proto, gone: set[str]) -> Proto:
    q = Proto.__new__(Proto)
    q.files = {k: v for k, v in p.files.items() if k not in gone}
    q.links = dict(p.links)
    q.dirs = list(p.dirs)
    return q


def test_deleted_short_folder_and_symlinks(tmp_path):
    """rm -rf of a short-form folder (its entries removed one by one, then the folder itself) and of two
    symlinks, one inline and one in a block (XSLM)."""
    p = Proto(tmp_path)
    p.file("keep.txt", b"keep me\n")
    p.mkdir("links")
    p.symlink("lnk", "keep.txt")
    p.symlink("rlnk", "/far/away/" + "q" * 600)
    p.up()
    p.mkdir("docs")
    p.file("a.txt", payload(5000, 1))
    p.file("report.pdf", payload(70_000, 2))
    p.file("zlast.doc", payload(12_345, 3))
    p.up()
    img = p.build(tmp_path / "s.img", 64 * MiB)
    root = int(sb_values(img)["rootino"])
    docs, links = ino_of(img, "", "docs"), ino_of(img, "", "links")
    im = Img(img)
    try:
        im.fix_remote_symlink(ino_of(img, "links", "rlnk"))
    finally:
        im.close()
    assert "q" * 100 in xdb(img, f"inode {ino_of(img, 'links', 'rlnk')}", "dblock 0", "type symlink", "print")
    src, r, es = entries_of(img)
    assert paths(es)["links/rlnk"].data == p.links["links/rlnk"].encode()
    gone = {name: delete_file(img, "docs", name, docs, shortform=True) for name in ("a.txt", "report.pdf", "zlast.doc")}
    gone["rlnk"] = delete_file(img, "links", "rlnk", links, shortform=True)
    gone["lnk"] = delete_file(img, "links", "lnk", links, shortform=True)
    im = Img(img)
    try:
        im.sf_remove(root, b"docs")
        im.free_inode(docs)
    finally:
        im.close()
    assert "docs" not in xdb(img, "ls /") and "lnk" not in xdb(img, "ls /links")

    src, r, es = entries_of(img)
    dels = {e.extra["inode"]: e for e in es if e.deleted}
    assert set(dels) == set(gone.values()) | {docs}
    folder = dels[docs]
    assert folder.is_dir and folder.name == "docs" and folder.parent == root and folder.key == f"d{docs}"
    # entries slid down over each other: the last file's name survives inside the freed folder inode
    z = dels[gone["zlast.doc"]]
    assert z.name == "zlast.doc" and z.parent == folder.key
    for name in ("a.txt", "report.pdf", "zlast.doc"):
        e = dels[gone[name]]
        data = p.files[f"docs/{name}"]
        assert e.chance == CHANCE_GOOD and content(src, e)[:len(data)] == data, name
        if name != "zlast.doc":
            assert e.parent is None and e.flags & F_ORPHAN
    lnk, rlnk = dels[gone["lnk"]], dels[gone["rlnk"]]
    assert lnk.flags & F_SYMLINK and lnk.data == b"keep.txt" and lnk.name == "lnk" and lnk.parent == links
    assert rlnk.flags & F_SYMLINK and rlnk.data == p.links["links/rlnk"].encode() and rlnk.name == "rlnk"


def test_deleted_folder_freed_chunk(tmp_path):
    """rm -rf of a whole folder: when every inode of a chunk is free, XFS frees the chunk (its inode
    B+tree record goes away and its blocks become free space). The inode cluster buffers are marked stale
    and never rewritten, so the inodes keep their last flushed state. The reader finds them in free space."""
    p = Proto(tmp_path)
    p.file("keep.txt", b"keep\n")
    p.mkdir("other")
    p.file("o.txt", b"o")
    p.up()
    p.mkdir("trip")                     # lands in its own AG and inode chunk (mkfs spreads folders)
    for i in range(30):
        p.file(f"P{i:03d}.raw", payload(3000 + 777 * i, 900 + i))
    p.up()
    img = p.build(tmp_path / "c.img", 64 * MiB)
    root = int(sb_values(img)["rootino"])
    trip = ino_of(img, "", "trip")
    inos = [ino_of(img, "trip", f"P{i:03d}.raw") for i in range(30)]
    im = Img(img)
    agino_log = im.agblklog + im.inopblog
    assert all(i >> 6 == trip >> 6 for i in inos) and trip >> agino_log != root >> agino_log
    try:
        agno = trip >> agino_log
        # the folder's block and the files' extents go back to the free space
        for ino in [trip] + inos:
            for _l, fsb, cnt in im.extents(ino):
                im.free_extent(fsb, cnt)
        # the chunk record leaves the inode B+trees; its blocks become free space
        agi = im.read(im.agoff(agno) + 2 * im.sectsize, im.sectsize)
        for root_off in (20, 328):
            broot = struct.unpack_from(">I", agi, root_off)[0]
            blk = im.read(im.agoff(agno, broot), im.bs)
            n = struct.unpack_from(">H", blk, 6)[0]
            recs = [bytes(blk[56 + 16 * k:72 + 16 * k]) for k in range(n)]
            keep = [rec for rec in recs if not struct.unpack_from(">I", rec, 0)[0] <= (trip & ((1 << agino_log) - 1)) < struct.unpack_from(">I", rec, 0)[0] + 64]
            assert len(keep) == len(recs) - 1
            struct.pack_into(">H", blk, 6, len(keep))
            blk[56:56 + 16 * n] = b"".join(keep) + bytes(16 * (n - len(keep)))
            im.put_block(im.agoff(agno, broot), blk, 52)
        agino0 = struct.unpack_from(">I", [rec for rec in recs if rec not in keep][0], 0)[0]
        im.free_extent((agno << im.agblklog) | (agino0 >> im.inopblog), 64 * im.isize // im.bs)
        im.sf_remove(root, b"trip")
    finally:
        im.close()
    assert "trip" not in xdb(img, "ls /")

    src, r, es = entries_of(img)
    dels = [e for e in es if e.deleted]
    ps = paths(es)
    folder = [e for e in dels if e.is_dir]
    # "trip" was the root's last entry: its name survives past the root folder's new end
    assert len(folder) == 1 and folder[0].key == f"d{trip}" and folder[0].parent == root
    assert folder[0].name == "trip"
    for i in range(30):
        e = ps[f"trip/P{i:03d}.raw"]
        data = p.files[f"trip/P{i:03d}.raw"]
        assert e.deleted and e.size == len(data) and e.chance == CHANCE_GOOD
        assert e.extra.get("found_in") == "free space"
        assert content(src, e) == data
    # without the free-space search those are out of reach
    src, r, es = entries_of(img, scan_free_space=False)
    assert not [e for e in es if e.deleted]


def test_freed_folder_blocks_name_files(tmp_path):
    """A v5 folder block found in free space names its folder (its owner): the leftovers of a deleted
    folder whose inode is gone still give names, under a rebuilt folder."""
    p = Proto(tmp_path)
    p.mkdir("gone")
    for i in range(30):
        p.file(f"n{i:02d}.bin", payload(5000 + i, 70 + i))
    p.up()
    p.file("z.txt", b"z")
    img = p.build(tmp_path / "f.img", 64 * MiB)
    gone = ino_of(img, "", "gone")
    victim = delete_file(img, "gone", "n05.bin", gone, shortform=False)
    im = Img(img)
    try:
        [(_l, dfsb, dcnt)] = im.extents(gone)
        # the folder's inode is reused by a file: only its freed block remains
        raw = im.inode(gone)
        raw[176:] = bytes(len(raw) - 176)
        struct.pack_into(">H", raw, 2, 0o100644)
        struct.pack_into(">I", raw, 76, 0)
        struct.pack_into(">Q", raw, 56, 0)
        im.put_inode(gone, raw)
        im.free_extent(dfsb, dcnt)
    finally:
        im.close()
    src, r, es = entries_of(img)
    [d] = [e for e in es if e.deleted and not e.is_dir]
    assert d.extra["inode"] == victim and d.name == "n05.bin" and d.chance == CHANCE_GOOD
    assert content(src, d)[:5005] == p.files["gone/n05.bin"]
    par = {e.key: e for e in es}[d.parent]
    assert par.flags & F_DIR_RECOVERED and par.name == f"inode {gone}" and par.parent is None
    # the other files of that folder are still allocated: Lost files
    assert len([e for e in es if e.flags & F_ORPHAN and not e.deleted]) == 29


def test_damaged_folder_files_go_to_lost_files(tmp_path):
    p = small_proto(tmp_path)
    img = p.build(tmp_path / "x.img", 64 * MiB)
    photos = ino_of(img, "", "photos")
    im = Img(img)
    try:
        [(_l, fsb, _c)] = im.extents(photos)
        im.write(im.fsb(fsb), b"JUNK")
    finally:
        im.close()
    src, r, es = entries_of(img)
    ps = paths(es)
    lost = [e for e in es if e.flags & F_ORPHAN and not e.deleted]
    assert len(lost) == 40 and all(e.parent is None and e.name.startswith("inode ") for e in lost)
    for e in lost:
        assert e.size and content(src, e)[:4] == next(d for d in p.files.values() if len(d) == e.size)[:4]
    assert ps["docs/report.pdf"].size == 70_000
    assert any("damaged" in w for w in r.warnings)


def test_hard_link_and_open_unlinked(tmp_path):
    """A second name for an inode (made by hand: protofiles can't) and an inode unlinked while open."""
    p = small_proto(tmp_path)
    img = p.build(tmp_path / "h.img", 64 * MiB)
    keep = ino_of(img, "", "keep.txt")
    a = ino_of(img, "docs", "a.txt")
    docs = ino_of(img, "", "docs")
    im = Img(img)
    try:
        # rename docs' "a.txt" entry in place to point at keep.txt's inode (same name length → "b.txt")
        raw = im.inode(docs)
        lit = raw[176:]
        k = bytes(lit).index(b"a.txt")
        lit[k] = ord("b")
        struct.pack_into(">I", lit, k + 5 + 1, keep)
        raw[176:] = lit
        im.put_inode(docs, raw)
        # a.txt: no name any more, link count 0 but still allocated (an open file at the time of a crash)
        raw = im.inode(a)
        struct.pack_into(">I", raw, 16, 0)
        im.put_inode(a, raw)
    finally:
        im.close()
    src, r, es = entries_of(img)
    ps = paths(es)
    assert ps["docs/b.txt"].flags & F_HARDLINK and ps["docs/b.txt"].key != keep
    assert content(src, ps["docs/b.txt"]) == b"keep me\n" and ps["keep.txt"].key == keep
    e = ps[f"?/inode {a}"]
    assert e.deleted and e.chance == CHANCE_GOOD and e.size == 5000
    assert content(src, e) == p.files["docs/a.txt"]


def test_free_extents_match_xfs_db(rich):
    img, _p = rich
    src = FileSource(str(img))
    r = XfsReader(src, XfsReader.probe(src))
    free = r.free_extents()
    want = []
    sb = sb_values(img)
    bs, agb = int(sb["blocksize"]), int(sb["agblocks"])
    for agno in range(int(sb["agcount"])):
        out = xdb(img, f"agf {agno}", "addr bnoroot", "print recs")
        for line in out.splitlines():
            line = line.strip()
            if line[:1].isdigit() and ":[" in line:
                s, c = line.split(":[")[1].rstrip("]").split(",")
                want.append(((agno * agb + int(s)) * bs, int(c) * bs))
    assert fsbase.merge_runs(sorted(want)) == free
    freeblks = sum(int(xdb(img, f"agf {agno}", "print freeblks").split("=")[1]) for agno in range(int(sb["agcount"])))
    assert sum(n for _o, n in free) == freeblks * bs


# ---------------------------------------------------------------------- robustness
def test_fuzz_does_not_raise(tmp_path):
    p = small_proto(tmp_path)
    img = p.build(tmp_path / "z.img", 64 * MiB)
    delete_file(img, "photos", "IMG_0003.JPG", ino_of(img, "", "photos"), shortform=False)
    raw = bytearray(img.read_bytes()[:24 * MiB])
    meta = [k * 4096 for k in range(len(raw) // 4096) if raw[k * 4096:k * 4096 + 4] in
            (b"XFSB", b"XAGF", b"XAGI", b"IAB3", b"FIB3", b"AB3B", b"AB3C", b"XDB3", b"XDD3", b"BMA3")
            or raw[k * 4096:k * 4096 + 2] == b"IN"]
    assert meta
    rng = random.Random(1234)
    for _round in range(25):
        buf = bytearray(raw)
        for _ in range(rng.randint(1, 60)):
            blk = rng.choice(meta)
            pos = blk + rng.randrange(4096)
            buf[pos] = rng.randrange(256)
        if rng.random() < 0.3:
            blk = rng.choice(meta)
            buf[blk:blk + 4096] = os.urandom(4096) if rng.random() < 0.5 else bytes(4096)
        src = BytesSource(bytes(buf))
        info = XfsReader.probe(src)
        if info is None:
            continue
        r = XfsReader(src, {**info, "scan_free_space": True})
        n = 0
        for e in r.entries():
            n += 1
            if e.runs and not e.is_dir and n % 5 == 0:
                fsbase.read_head(src, e, 4096)
        r.free_extents()
