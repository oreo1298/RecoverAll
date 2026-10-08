"""Btrfs engine tests on images made by ``mkfs.btrfs --rootdir`` (no mount needed: the kernel here has no
Btrfs).

Deleted files: Btrfs never changes a tree block in place; deleting a file writes a new copy of the leaf
without it, a new copy of the root tree pointing to that leaf, and a new superblock. The test does exactly
that by hand (new FS-tree leaf and root-tree leaf written into free space of the metadata chunk, checksums
fixed, superblock pointed at them, generation + 1), so the previous root tree — with the files — is still
on disk for btrfs-find-root to find.
"""

from __future__ import annotations

import hashlib
import os
import struct
import subprocess
from pathlib import Path

import imagekit
import pytest
from imagekit import MiB, blank, need, payload, sh

from recoverall.core.blockio import BytesSource, FileSource
from recoverall.core.errors import NotSupported
from recoverall.core.fs.base import (
    CHANCE_GOOD,
    F_COMPRESSED,
    F_HARDLINK,
    F_SYMLINK,
    read_content,
)
from recoverall.core.fs.btrfs import (
    BtrfsReader,
    crc32c,
    older_roots,
    parse_superblock,
    path_regex,
)

pytestmark = pytest.mark.skipif(not (os.path.exists("/usr/bin/btrfs") or os.path.exists("/usr/sbin/btrfs") or
                                     os.path.exists("/bin/btrfs")), reason="btrfs-progs is not installed")


def paths(entries):
    by = {e.key: e for e in entries}
    out = {}
    for e in entries:
        parts, cur, guard = [], e, 0
        while cur is not None and cur.parent is not None and guard < 64:
            parts.append(cur.name)
            cur = by.get(cur.parent)
            guard += 1
        out["/".join(reversed(parts))] = e
    return out


def content(src, e) -> bytes:
    return b"".join(read_content(src, e))


FILES = {"hello.txt": b"hello\n", "dir1/big.bin": payload(300_000, 1), "dir1/sub/deep.txt": b"deep\n",
         "small.bin": payload(1500, 2), "sparse.bin": None, "weird name [1] (x).txt": b"regex chars\n",
         "Ünïcødé/café.txt": "café\n".encode(), "gone.bin": payload(200_000, 3), "olddir/inner.bin":
         payload(50_000, 4), "olddir/tiny.txt": b"tiny\n"}


def make_image(tmp: Path, size=200 * MiB) -> tuple[Path, dict]:
    need("mkfs.btrfs")
    root = tmp / "src"
    want = {}
    for rel, data in FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if data is None:                                      # 1 MiB with one byte in the middle
            with open(p, "wb") as fh:
                fh.truncate(1 << 20)
                fh.seek(500_000)
                fh.write(b"X")
            data = bytes(500_000) + b"X" + bytes((1 << 20) - 500_001)
        else:
            p.write_bytes(data)
        want[rel] = data
    os.symlink("dir1/big.bin", root / "link")
    os.link(root / "hello.txt", root / "dir1" / "hello_again.txt")
    want["dir1/hello_again.txt"] = want["hello.txt"]
    (root / "empty").mkdir()
    img = blank(tmp / "b.img", size)
    sh("mkfs.btrfs", "-q", "-f", "-L", "RECOV", "--rootdir", root, img)
    return img, want


@pytest.fixture(scope="module")
def image(tmp_path_factory):
    return make_image(tmp_path_factory.mktemp("btrfs"))


def test_superblock(image):
    img, _want = image
    raw = Path(img).read_bytes()
    sb = parse_superblock(raw[0x10000:0x11000])
    assert sb["label"] == "RECOV" and sb["bytenr"] == 0x10000 and sb["csum_ok"] is True
    assert sb["sectorsize"] == 4096 and sb["nodesize"] == 16384 and sb["num_devices"] == 1
    mirror = parse_superblock(raw[0x4000000:0x4001000])
    assert mirror and mirror["bytenr"] == 0x4000000 and mirror["fsid"] == sb["fsid"]
    assert parse_superblock(bytes(4096)) is None
    out = sh("btrfs", "inspect-internal", "dump-super", img)
    assert sb["fsid"] in out and f"generation\t\t{sb['generation']}" in out
    info = BtrfsReader.probe(FileSource(str(img)))
    assert info["fstype"] == "btrfs" and info["uuid"] == sb["fsid"] and info["size"] == 200 * MiB


def test_listing_and_content(image):
    img, want = image
    src = FileSource(str(img))
    r = BtrfsReader(src, BtrfsReader.probe(src))
    es = list(r.entries(deleted=False))
    assert es[0].key == r.root_key and es[0].parent is None
    assert len({e.key for e in es}) == len(es)
    p = paths(es)
    for rel, data in want.items():
        assert rel in p, rel
        assert p[rel].size == len(data), rel
        assert content(src, p[rel]) == data, rel
        assert p[rel].chance == CHANCE_GOOD and not p[rel].deleted
    assert p["link"].flags & F_SYMLINK and p["link"].data == b"dir1/big.bin"
    assert p["empty"].is_dir and p["dir1/sub"].is_dir
    assert (p["hello.txt"].flags | p["dir1/hello_again.txt"].flags) & F_HARDLINK
    assert p["dir1/big.bin"].runs and not p["dir1/big.bin"].flags & F_COMPRESSED
    assert p["dir1/big.bin"].extra["mode"] == 0o100644 and p["dir1/big.bin"].mtime
    assert not r.warnings


def test_restore_decoder(image):
    """The decoder used for compressed files (mkfs can't compress): btrfs restore of one file."""
    img, want = image
    src = FileSource(str(img))
    for rel in ("dir1/big.bin", "weird name [1] (x).txt", "Ünïcødé/café.txt", "sparse.bin"):
        e = {"size": len(want[rel]), "extra": {"decoder": "btrfs", "subvol": 5, "path": rel.split("/")}}
        assert content(src, e) == want[rel], rel
    e = {"size": 4, "extra": {"decoder": "btrfs", "subvol": 5, "path": ["no such file"]}}
    with pytest.raises(Exception) as exc:
        content(src, e)
    assert "btrfs restore" in str(exc.value)
    assert path_regex(["a", "b.c"]) == "^/(|a(|/b[.]c))$"


@pytest.mark.root
def test_volume_inside_disk_image(image, tmp_path):
    """A partition inside a disk image: btrfs-progs get a read-only loop device, detached afterwards."""
    img, want = image
    disk = blank(tmp_path / "disk.img", 210 * MiB)
    imagekit.embed(disk, img, MiB)
    src = FileSource(str(disk)).region(MiB, 200 * MiB)
    r = BtrfsReader(src, BtrfsReader.probe(src))
    p = paths(list(r.entries()))
    assert content(src, p["dir1/big.bin"]) == want["dir1/big.bin"]
    e = {"size": len(want["olddir/inner.bin"]), "extra": {"decoder": "btrfs", "subvol": 5,
                                                         "path": ["olddir", "inner.bin"]}}
    assert content(src, e) == want["olddir/inner.bin"]
    loops = subprocess.run(["losetup", "-j", str(disk)], capture_output=True, text=True).stdout
    assert loops.strip() == ""


def test_virtual_source_refused(image):
    img, _want = image
    with pytest.raises(NotSupported):
        BtrfsReader(BytesSource(Path(img).read_bytes()[:128 * MiB]))


# ---------------------------------------------------------------------- deleted files from an older root
ITEM = struct.Struct("<QBQII")             # key (objectid, type, offset), data offset, data size
INODE_ITEM, INODE_REF, DIR_ITEM, DIR_INDEX, EXTENT_DATA, ROOT_ITEM = 1, 12, 84, 96, 108, 132


def chunk_map(img) -> list[tuple[int, int, int, str]]:
    out = sh("btrfs", "inspect-internal", "dump-tree", "-t", "chunk", img)
    chunks, cur = [], None
    for line in out.splitlines():
        line = line.strip()
        if "CHUNK_ITEM" in line and line.startswith("item"):
            cur = [int(line.split("CHUNK_ITEM ")[1].split(")")[0]), 0, 0, ""]
            chunks.append(cur)
        elif cur and line.startswith("length"):
            cur[1] = int(line.split()[1])
            cur[3] = line.split("type ")[1]
        elif cur and line.startswith("stripe 0"):
            cur[2] = int(line.split("offset ")[1])
    return [tuple(c) for c in chunks]


def phys(chunks, logical):
    for start, length, off, _kind in chunks:
        if start <= logical < start + length:
            return off + logical - start
    raise AssertionError(logical)


def leaf_items(block: bytes):
    n = struct.unpack_from("<I", block, 96)[0]
    items = []
    for i in range(n):
        oid, typ, off, doff, dsize = ITEM.unpack_from(block, 101 + i * 25)
        items.append(((oid, typ, off), bytes(block[101 + doff:101 + doff + dsize])))
    return items


def build_leaf(old: bytes, items, bytenr: int, generation: int) -> bytes:
    ns = len(old)
    b = bytearray(ns)
    b[:101] = old[:101]
    struct.pack_into("<Q", b, 48, bytenr)
    struct.pack_into("<Q", b, 80, generation)
    struct.pack_into("<I", b, 96, len(items))
    end = ns - 101
    for i, ((oid, typ, off), data) in enumerate(items):
        end -= len(data)
        ITEM.pack_into(b, 101 + i * 25, oid, typ, off, end, len(data))
        b[101 + end:101 + end + len(data)] = data
    struct.pack_into("<I", b, 0, crc32c(bytes(b[32:])))
    b[4:32] = bytes(28)
    return bytes(b)


def delete_cow(img: Path, names: set[bytes]) -> int:
    """Remove the top-level entries NAMES (and everything below them) the copy-on-write way. Returns the
    old root tree's logical address."""
    raw = bytearray(img.read_bytes())
    sb = parse_superblock(bytes(raw[0x10000:0x11000]))
    ns, gen = sb["nodesize"], sb["generation"] + 1
    chunks = chunk_map(img)
    old_root = sb["root"]
    root_leaf = bytes(raw[phys(chunks, old_root):phys(chunks, old_root) + ns])
    assert root_leaf[100] == 0, "the root tree is a single leaf in these small images"
    ritems = leaf_items(root_leaf)
    fs_key = next(k for k, _d in ritems if k[0] == 5 and k[1] == ROOT_ITEM)
    fs_item = dict(ritems)[fs_key]
    fs_bytenr = struct.unpack_from("<Q", fs_item, 176)[0]
    fs_leaf = bytes(raw[phys(chunks, fs_bytenr):phys(chunks, fs_bytenr) + ns])
    assert fs_leaf[100] == 0
    items = leaf_items(fs_leaf)
    # inodes to drop: the named ones and everything inside them
    gone: set[int] = set()
    for (oid, typ, off), data in items:
        if typ == INODE_REF and off == 256 and data[10:10 + struct.unpack_from("<H", data, 8)[0]] in names:
            gone.add(oid)
    changed = True
    while changed:
        changed = False
        for (oid, typ, off), _data in items:
            if typ == INODE_REF and off in gone and oid not in gone:
                gone.add(oid)
                changed = True
    keep = []
    for (oid, typ, off), data in items:
        if oid in gone:
            continue
        if typ in (DIR_ITEM, DIR_INDEX) and struct.unpack_from("<Q", data, 0)[0] in gone:
            continue
        keep.append(((oid, typ, off), data))
    # two free tree blocks at the end of the metadata chunk
    meta = next(c for c in chunks if c[3].startswith("METADATA"))
    free = []
    logical = meta[0] + meta[1] - ns
    while len(free) < 2:
        p = phys(chunks, logical)
        if not any(raw[p:p + ns]):
            free.append(logical)
        logical -= ns
    new_fs, new_root = free
    leaf = build_leaf(fs_leaf, keep, new_fs, gen)
    raw[phys(chunks, new_fs):phys(chunks, new_fs) + ns] = leaf
    fs_item = bytearray(fs_item)
    struct.pack_into("<Q", fs_item, 160, gen)                 # root item: generation
    struct.pack_into("<Q", fs_item, 176, new_fs)              # bytenr
    struct.pack_into("<Q", fs_item, 239, gen)                 # generation_v2
    ritems = [(k, bytes(fs_item) if k == fs_key else d) for k, d in ritems]
    raw[phys(chunks, new_root):phys(chunks, new_root) + ns] = build_leaf(root_leaf, ritems, new_root, gen)
    sbuf = bytearray(raw[0x10000:0x11000])
    struct.pack_into("<Q", sbuf, 0x48, gen)
    struct.pack_into("<Q", sbuf, 0x50, new_root)
    struct.pack_into("<I", sbuf, 0, crc32c(bytes(sbuf[0x20:])))
    raw[0x10000:0x11000] = sbuf
    img.write_bytes(bytes(raw))
    return old_root


@pytest.fixture(scope="module")
def deleted_image(tmp_path_factory):
    img, want = make_image(tmp_path_factory.mktemp("btrfsdel"))
    old_root = delete_cow(img, {b"gone.bin", b"olddir"})
    return img, want, old_root


def test_cow_deletion_is_valid_btrfs(deleted_image):
    img, _want, old_root = deleted_image
    out = sh("btrfs", "inspect-internal", "dump-tree", "-t", "5", img)
    assert "hello.txt" in out and "gone.bin" not in out and "olddir" not in out
    roots = older_roots(FileSource(str(img)))
    assert any(r["bytenr"] == old_root and not r["current"] for r in roots)
    assert roots[0]["current"] and roots[0]["generation"] > roots[1]["generation"]


def test_deleted_files_from_older_root(deleted_image):
    img, want, _old = deleted_image
    src = FileSource(str(img))
    r = BtrfsReader(src, BtrfsReader.probe(src))
    es = list(r.entries())
    assert len({e.key for e in es}) == len(es)
    p = paths(es)
    live = {k for k, e in p.items() if not e.deleted}
    assert "gone.bin" not in live and "hello.txt" in live
    for rel in ("gone.bin", "olddir/inner.bin", "olddir/tiny.txt"):
        e = p[rel]
        assert e.deleted and str(e.key).startswith("d"), rel
        assert content(src, e) == want[rel], rel
    assert p["olddir"].is_dir and p["olddir"].deleted
    assert p["gone.bin"].chance == CHANCE_GOOD           # nothing uses its extent now
    assert not [e for e in es if e.deleted and e.name in ("hello.txt", "big.bin")]
    # without the deleted-files scan: only what exists
    assert not [e for e in r.entries(deleted=False) if e.deleted]


def test_older_version_and_restore_t(deleted_image):
    """A reader opened on an older root (what the scanner offers as an older version), and btrfs restore -t
    for a file that only exists there."""
    img, want, old_root = deleted_image
    src = FileSource(str(img))
    info = dict(BtrfsReader.probe(src), tree_root=old_root)
    p = paths(list(BtrfsReader(src, info).entries(deleted=False)))
    assert not p["gone.bin"].deleted and content(src, p["gone.bin"]) == want["gone.bin"]
    e = {"size": len(want["olddir/inner.bin"]), "extra": {"decoder": "btrfs", "subvol": 5, "tree_root": old_root,
                                                         "path": ["olddir", "inner.bin"]}}
    assert hashlib.sha256(content(src, e)).digest() == hashlib.sha256(want["olddir/inner.bin"]).digest()


def test_backup_superblock(image, tmp_path):
    """A wiped primary superblock: the 64 MiB copy is found; listing falls back to btrfs restore -u 1."""
    img, want = image
    raw = bytearray(Path(img).read_bytes())
    raw[0x10000:0x11000] = bytes(4096)
    bad = tmp_path / "bad.img"
    bad.write_bytes(bytes(raw))
    src = FileSource(str(bad))
    info = BtrfsReader.probe(src)
    assert info and info["super_mirror"] == 1
    r = BtrfsReader(src, info)
    es = list(r.entries())
    p = paths(es)
    assert "dir1/big.bin" in p and p["dir1"].is_dir
    assert content(src, p["dir1/big.bin"]) == want["dir1/big.bin"]
    assert r.warnings


def test_parsers_survive_garbage(image):
    import random

    from recoverall.core.fs.btrfs import _parse_tree
    img, _want = image
    good = Path(img).read_bytes()[0x10000:0x11000]
    rnd = random.Random(3)
    for _ in range(200):
        b = bytearray(good)
        for _k in range(40):
            b[rnd.randrange(len(b))] = rnd.randrange(256)
        b[0x40:0x48] = b"_BHRfS_M"
        sb = parse_superblock(bytes(b))
        assert sb is None or sb["csum_ok"] is not True        # damaged: never taken as valid
    dump = sh("btrfs", "inspect-internal", "dump-tree", "-t", "5", img).encode().split(b"\n")
    for _ in range(20):
        lines = list(dump)
        for _k in range(30):
            i = rnd.randrange(len(lines))
            lines[i] = bytes(rnd.randrange(256) for _ in range(rnd.randrange(80)))
        rnd.shuffle(lines[: len(lines) // 3])
        for ino in _parse_tree(iter(lines)):
            assert ino.ino >= 256
