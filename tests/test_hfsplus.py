"""HFS+ reader tests.

Linux can't write HFS+ here (no kernel driver, hfsprogs only makes empty volumes), so the images come from:

* xorriso (``-as mkisofs -hfsplus``): a real HFS+ volume with real files inside an ISO (found through its
  Apple partition map). Deletions are simulated the way macOS does them: a record is removed from its leaf
  node (later records are shifted down over it, so only the last record of a node survives in the node's
  free space), or a whole leaf node is unlinked from the chain and marked free in the B-tree map; the
  files' blocks are cleared in the allocation bitmap.
* an empty journaled volume from mkfs.hfsplus, into which the test writes catalog, attributes and extents
  overflow nodes (built below) to get what neither tool makes: hard links, decmpfs-compressed files, a
  resource fork, a file with more than 8 fragments, and an old copy of a catalog node in the journal that
  still holds a deleted file.
"""

from __future__ import annotations

import os
import random
import shutil
import struct
import subprocess
import time
import unicodedata
import zlib
from pathlib import Path

import pytest
from imagekit import MiB, blank, need, payload, sh

from recoverall.core.blockio import BytesSource, FileSource
from recoverall.core.errors import NotSupported
from recoverall.core.fs.base import (
    CHANCE_GOOD,
    F_ADS,
    F_COMPRESSED,
    F_DIR_RECOVERED,
    F_HARDLINK,
    F_JOURNAL,
    F_ORPHAN,
    F_SYMLINK,
    F_SYSTEM,
    read_content,
)
from recoverall.core.fs.hfsplus import (
    HFS_EPOCH,
    HfsPlusReader,
    decode_decmpfs,
    parse_volume_header,
)


# ---------------------------------------------------------------------- helpers
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


def build_iso(tmp: Path, files: dict[str, bytes], symlinks: dict[str, str] | None = None, label="MACVOL"):
    """An ISO with an HFS+ volume holding FILES; returns (iso path, volume offset, volume size)."""
    need("xorriso")
    root = tmp / "src"
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    for rel, target in (symlinks or {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, p)
    iso = tmp / "hfs.iso"
    sh("xorriso", "-as", "mkisofs", "-input-charset", "UTF-8", "-output-charset", "UTF-8", "-hfsplus",
       "-V", label, "-o", iso, root)
    raw = iso.read_bytes()
    assert raw[0:2] == b"ER"
    blk = struct.unpack_from(">H", raw, 2)[0]
    i = 1
    while raw[i * blk:i * blk + 2] == b"PM":
        e = raw[i * blk:(i + 1) * blk]
        start, count = struct.unpack_from(">II", e, 8)
        if e[48:57] == b"Apple_HFS":
            return iso, start * blk, count * blk
        i += 1
    raise AssertionError("no Apple_HFS partition")


class Vol:
    """A raw HFS+ volume in a bytearray, with just enough knowledge to edit it like macOS would."""

    def __init__(self, data: bytes):
        self.b = bytearray(data)
        self.vh = parse_volume_header(bytes(self.b[1024:1536]))
        self.bs = self.vh["block_size"]

    def fork_off(self, name: str) -> int:
        ext = self.vh["forks"][name]["extents"]
        assert len(ext) == 1, "the test images have contiguous special files"
        return ext[0][0] * self.bs

    def tree_header(self, name: str) -> dict:
        off = self.fork_off(name)
        depth, root, leafs, first, last, ns, maxk, total, free = struct.unpack_from(">HIIIIHHII", self.b, off + 14)
        return {"off": off, "depth": depth, "root": root, "leaf_records": leafs, "first": first, "last": last,
                "ns": ns, "total": total, "free": free}

    def node(self, name: str, i: int) -> bytearray:
        h = self.tree_header(name)
        return self.b[h["off"] + i * h["ns"]:h["off"] + (i + 1) * h["ns"]]

    def put_node(self, name: str, i: int, data: bytes) -> None:
        h = self.tree_header(name)
        assert len(data) == h["ns"]
        self.b[h["off"] + i * h["ns"]:h["off"] + (i + 1) * h["ns"]] = data

    def set_header(self, name: str, **fields) -> None:
        h = self.tree_header(name)
        h.update(fields)
        struct.pack_into(">HIIIIH", self.b, h["off"] + 14, h["depth"], h["root"], h["leaf_records"], h["first"],
                         h["last"], h["ns"])
        struct.pack_into(">I", self.b, h["off"] + 14 + 26, h["free"])

    def map_bit(self, name: str, i: int, used: bool) -> None:
        h = self.tree_header(name)
        node = self.node(name, 0)
        offs = offsets(node)
        pos = h["off"] + offs[2] + i // 8
        if used:
            self.b[pos] |= 0x80 >> (i % 8)
        else:
            self.b[pos] &= ~(0x80 >> (i % 8)) & 0xFF

    def leaves(self, name: str = "catalog") -> list[int]:
        h = self.tree_header(name)
        out, n = [], h["first"]
        while n and n not in out:
            out.append(n)
            n = struct.unpack_from(">I", self.node(name, n), 0)[0]
        return out

    def set_blocks(self, start: int, count: int, used: bool) -> None:
        off = self.fork_off("allocation")
        for blk in range(start, start + count):
            if used:
                self.b[off + blk // 8] |= 0x80 >> (blk % 8)
            else:
                self.b[off + blk // 8] &= ~(0x80 >> (blk % 8)) & 0xFF


def offsets(node) -> list[int]:
    ns = len(node)
    n = struct.unpack_from(">H", node, 10)[0]
    return list(struct.unpack_from(f">{n + 1}H", node, ns - 2 * (n + 1)))[::-1]


def remove_record(node: bytearray, index: int) -> bytes:
    """Delete record INDEX the way the HFS+ B-tree code does: shift the later records down, fix the offsets.
    Returns the removed record."""
    ns = len(node)
    offs = offsets(node)
    n = len(offs) - 1
    a, b = offs[index], offs[index + 1]
    rec = bytes(node[a:b])
    tail = bytes(node[b:offs[-1]])
    node[a:a + len(tail)] = tail
    new = offs[:index] + [o - (b - a) for o in offs[index + 1:]]
    struct.pack_into(">H", node, 10, n - 1)
    struct.pack_into(">H", node, ns - 2 * (n + 1), 0)       # the slot that is no longer part of the table
    struct.pack_into(f">{n}H", node, ns - 2 * n, *new[::-1])
    return rec


def record_key(node, i) -> tuple[int, str, int]:
    offs = offsets(node)
    a = offs[i]
    klen, parent, nlen = struct.unpack_from(">HIH", node, a)
    name = unicodedata.normalize("NFC", bytes(node[a + 8:a + 8 + 2 * nlen]).decode("utf-16-be"))
    rtype = struct.unpack_from(">h", node, a + 2 + klen)[0]
    return parent, name, rtype


# ---------------------------------------------------------------------- record and node builders
NOW = int(time.time()) + HFS_EPOCH


def cat_key(parent: int, name: str) -> bytes:
    u = name.encode("utf-16-be")
    return struct.pack(">HIH", 6 + len(u), parent, len(u) // 2) + u


def fork(size: int, extents: list[tuple[int, int]], blocks: int | None = None) -> bytes:
    ext = list(extents)[:8] + [(0, 0)] * (8 - min(8, len(extents)))
    total = blocks if blocks is not None else sum(c for _s, c in extents)
    return struct.pack(">QII", size, 0, total) + b"".join(struct.pack(">II", s, c) for s, c in ext)


def file_rec(cnid, data=b"\x00" * 80, rsrc=b"\x00" * 80, mode=0o100644, fdtype=b"\x00" * 4, creator=b"\x00" * 4,
             special=0, owner_flags=0, flags=0x0002) -> bytes:
    r = struct.pack(">hHII", 2, flags, 0, cnid) + struct.pack(">IIIII", NOW, NOW, NOW, NOW, 0)
    r += struct.pack(">IIBBHI", 501, 20, 0, owner_flags, mode, special)
    r += fdtype + creator + bytes(8) + bytes(16) + struct.pack(">II", 0, 0)
    r += data + rsrc
    assert len(r) == 248
    return r


def folder_rec(cnid, valence=0) -> bytes:
    r = struct.pack(">hHII", 1, 0, valence, cnid) + struct.pack(">IIIII", NOW, NOW, NOW, NOW, 0)
    r += struct.pack(">IIBBHI", 501, 20, 0, 0, 0o040755, 0) + bytes(16) + bytes(16) + bytes(8)
    assert len(r) == 88
    return r


def thread_rec(rtype: int, parent: int, name: str) -> bytes:
    u = name.encode("utf-16-be")
    return struct.pack(">hHIH", rtype, 0, parent, len(u) // 2) + u


def make_node(kind: int, height: int, records: list[bytes], ns: int, flink=0, blink=0) -> bytes:
    node = bytearray(ns)
    struct.pack_into(">IIbBH", node, 0, flink, blink, kind, height, len(records))
    offs = [14]
    pos = 14
    for r in records:
        node[pos:pos + len(r)] = r
        pos += len(r)
        offs.append(pos)
    assert pos <= ns - 2 * len(offs), "records don't fit in the node"
    struct.pack_into(f">{len(offs)}H", node, ns - 2 * len(offs), *offs[::-1])
    return bytes(node)


def catalog_records(items) -> list[bytes]:
    """[(parent, name, record bytes)] sorted the way the catalog orders keys (ASCII names here; HFS+ case
    folding sorts NUL after everything, which puts the private folder last)."""
    return [cat_key(p, n) + rec for p, n, rec in sorted(items, key=lambda x: (x[0], x[1].lower().replace("\x00",
                                                                                                       "\uffff")))]


def write_tree(v: Vol, name: str, records: list[bytes]) -> list[bytes]:
    """Lay RECORDS out as leaf nodes 1..n (plus an index node when there are several) of tree NAME."""
    h = v.tree_header(name)
    ns = h["ns"]
    leaves: list[list[bytes]] = [[]]
    used = 14
    for r in records:
        if used + len(r) + 2 * (len(leaves[-1]) + 2) > ns:
            leaves.append([])
            used = 14
        leaves[-1].append(r)
        used += len(r)
    nodes = []
    for i, recs in enumerate(leaves):
        idx = i + 1
        nodes.append(make_node(-1, 1, recs, ns, flink=idx + 1 if i + 1 < len(leaves) else 0, blink=i))
        v.put_node(name, idx, nodes[-1])
        v.map_bit(name, idx, True)
    depth, root = 1, 1
    if len(leaves) > 1:
        index = []
        for i, recs in enumerate(leaves):
            klen = struct.unpack_from(">H", recs[0], 0)[0]
            index.append(recs[0][:2 + klen] + struct.pack(">I", i + 1))
        root = len(leaves) + 1
        v.put_node(name, root, make_node(0, 2, index, ns))
        v.map_bit(name, root, True)
        depth = 2
    v.set_header(name, depth=depth, root=root, leaf_records=len(records), first=1, last=len(leaves),
                 free=h["total"] - 1 - len(leaves) - (1 if depth == 2 else 0))
    return nodes


# ---------------------------------------------------------------------- xorriso images
@pytest.fixture(scope="module")
def iso_case(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("hfsiso")
    files = {"hello.txt": b"hello\n", "Photos/big.bin": payload(300_000, 1),
             "Photos/2023/Sommer/strand.jpg": payload(70_000, 2), "Ünïcødé/naïve café.txt": b"caf\xc3\xa9\n",
             "empty.dat": b""}
    for i in range(150):                                   # enough records for a two-level catalog B-tree
        files[f"many/document_with_a_rather_long_name_{i:03d}.txt"] = payload(100 + i, 100 + i)
    iso, off, size = build_iso(tmp, files, {"Ünïcødé/link": "../hello.txt"})
    return iso, off, size, files


def test_probe_and_listing(iso_case):
    iso, off, size, files = iso_case
    src = FileSource(str(iso)).region(off, size)
    info = HfsPlusReader.probe(src)
    assert info["fstype"] == "hfsplus" and info["label"] == "MACVOL"
    assert info["size"] == size and info["block_size"] == 2048 and info["header"] == "primary"
    r = HfsPlusReader(src, info)
    es = list(r.entries(deleted=False))
    assert es[0].key == 2 and es[0].parent is None and es[0].is_dir
    assert len({e.key for e in es}) == len(es)
    p = paths(es)
    for rel, data in files.items():
        assert rel in p, rel
        assert p[rel].size == len(data) and content(src, p[rel]) == data, rel
        assert p[rel].chance == CHANCE_GOOD and not p[rel].deleted
    assert p["Photos/2023/Sommer"].is_dir and p["many"].is_dir
    link = p["Ünïcødé/link"]
    assert link.flags & F_SYMLINK and link.data == b"../hello.txt"
    assert p["$CatalogFile"].flags & F_SYSTEM
    assert r.catalog.depth >= 2
    assert abs(p["hello.txt"].mtime - time.time()) < 3600
    assert not r.warnings


def test_tsk_agrees(iso_case):
    need("fls")
    iso, off, size, files = iso_case
    out = sh("fls", "-r", "-p", "-f", "hfs", "-o", str(off // 512), iso)
    names = {unicodedata.normalize("NFC", line.split("\t", 1)[1]) for line in out.splitlines() if "\t" in line}
    names = {n for n in names if not n.startswith("$")}
    src = FileSource(str(iso)).region(off, size)
    ours = {k for k, e in paths(list(HfsPlusReader(src).entries(deleted=False))).items()
            if k and not e.flags & F_SYSTEM}
    assert ours == names


def test_alternate_header(iso_case, tmp_path):
    iso, off, size, files = iso_case
    vol = bytearray(Path(iso).read_bytes()[off:off + size])
    vol[1024:1536] = bytes(512)                          # the primary header is gone
    src = BytesSource(bytes(vol))
    info = HfsPlusReader.probe(src)
    assert info is not None and info["header"] == "alternate" and info["label"] == "MACVOL"
    r = HfsPlusReader(src, info)
    p = paths(list(r.entries(deleted=False)))
    assert content(src, p["Photos/big.bin"]) == files["Photos/big.bin"]
    assert any("alternate" in w for w in r.warnings)


def test_deleted_last_record_and_freed_node(iso_case):
    """Two deletions as macOS leaves them: (1) the last record of a leaf node removed (it stays in the node's
    free space), and a record in the middle removed (shifted over: gone); (2) the last leaf node unlinked from
    the chain and marked free, after its folder's record was removed from another node."""
    iso, off, size, files = iso_case
    v = Vol(Path(iso).read_bytes()[off:off + size])
    leaves = v.leaves()
    assert len(leaves) >= 3
    # (1) a node with file records: drop its last record and one in the middle
    target = None
    for n in leaves:
        node = v.node("catalog", n)
        cnt = struct.unpack_from(">H", node, 10)[0]
        if record_key(node, cnt - 1)[2] == 2 and record_key(node, 1)[2] == 2:
            target = n
            break
    assert target is not None
    node = v.node("catalog", target)
    cnt = struct.unpack_from(">H", node, 10)[0]
    last_parent, last_name, _t = record_key(node, cnt - 1)
    mid_parent, mid_name, _t = record_key(node, 1)
    last = remove_record(node, cnt - 1)
    mid = remove_record(node, 1)
    v.put_node("catalog", target, bytes(node))
    for rec in (last, mid):
        klen = struct.unpack_from(">H", rec, 0)[0]
        d = 2 + klen
        size_, _clump, _blocks = struct.unpack_from(">QII", rec, d + 88)
        for k in range(8):
            s, c = struct.unpack_from(">II", rec, d + 88 + 16 + 8 * k)
            if c:
                v.set_blocks(s, c, False)
    h = v.tree_header("catalog")
    removed = 2
    # (2) the last leaf node: unlink it, mark it free; remove its folder's record from the first leaf
    lastleaf = leaves[-1]
    prev = leaves[-2]
    node = v.node("catalog", lastleaf)
    cnt_last = struct.unpack_from(">H", node, 10)[0]
    in_last = [record_key(node, i) for i in range(cnt_last)]
    pnode = v.node("catalog", prev)
    struct.pack_into(">I", pnode, 0, 0)
    v.put_node("catalog", prev, bytes(pnode))
    v.map_bit("catalog", lastleaf, False)
    removed += cnt_last
    lost_folder = None
    folder_ids = {p for p, _n, t in in_last if t == 3}          # folder threads in the freed node
    first = v.node("catalog", leaves[0])
    fo = offsets(first)
    for i in range(len(fo) - 1):
        parent, name, rtype = record_key(first, i)
        a = fo[i]
        klen = struct.unpack_from(">H", first, a)[0]
        if rtype == 1 and struct.unpack_from(">I", first, a + 2 + klen + 8)[0] in folder_ids and parent == 2:
            lost_folder = name
            remove_record(first, i)
            removed += 1
            break
    v.put_node("catalog", leaves[0], bytes(first))
    v.set_header("catalog", leaf_records=h["leaf_records"] - removed, last=prev)
    src = BytesSource(bytes(v.b))
    r = HfsPlusReader(src, HfsPlusReader.probe(src))
    es = list(r.entries())
    assert len({e.key for e in es}) == len(es)
    live = paths([e for e in es if not e.deleted])
    p = paths(es)
    by = {e.key: e for e in es}
    gone = [e for e in es if e.deleted]
    names = {e.name for e in gone}
    assert last_name in names and mid_name not in names
    e = next(e for e in gone if e.name == last_name)
    rel = next(k for k, x in p.items() if x is e)
    assert rel in files and e.parent == last_parent and e.chance == CHANCE_GOOD
    assert content(src, e) == files[rel]
    # every file record of the freed node comes back, below its folder
    for parent, name, rtype in in_last:
        if rtype != 2:
            continue
        e = next(x for x in gone if x.name == name)
        rel = next(k for k, x in p.items() if x is e)
        if rel == "Ünïcødé/link":
            assert e.flags & F_SYMLINK and e.data == b"../hello.txt"
        else:
            assert content(src, e) == files[rel], rel
        assert e.chance in (1, 3)
    if lost_folder:
        d = next(x for x in gone if x.name == lost_folder and x.is_dir)
        assert d.key == f"d{d.extra['cnid']}" and d.parent == 2
        assert lost_folder not in live
        assert any(by.get(x.parent) is d for x in gone)
    # no garbage: every deleted entry matches a real file or folder
    real = set(files) | {"Ünïcødé/link"}
    for x in gone:
        rel = next(k for k, y in p.items() if y is x)
        assert x.is_dir or rel in real, rel


def test_lost_folder_records(iso_case):
    """A folder record is lost (removed from its node): the folder comes back from its thread record. When
    the thread is gone too, its content goes to "Lost files"."""
    iso, off, size, files = iso_case
    v = Vol(Path(iso).read_bytes()[off:off + size])
    many = paths_cnid(v, "many")

    def drop(pred) -> bool:
        for n in v.leaves():
            node = v.node("catalog", n)
            for i in range(struct.unpack_from(">H", node, 10)[0]):
                if pred(*record_key(node, i)):
                    remove_record(node, i)
                    v.put_node("catalog", n, bytes(node))
                    return True
        return False

    assert drop(lambda p, nm, t: t == 1 and nm == "2023")
    assert drop(lambda p, nm, t: t == 1 and nm == "many")
    assert drop(lambda p, nm, t: t == 3 and p == many)
    removed = 3
    h = v.tree_header("catalog")
    v.set_header("catalog", leaf_records=h["leaf_records"] - removed)
    src = BytesSource(bytes(v.b))
    r = HfsPlusReader(src, HfsPlusReader.probe(src))
    es = list(r.entries(deleted=False))
    assert len({e.key for e in es}) == len(es)
    p = paths(es)
    assert p["Photos/2023"].is_dir and p["Photos/2023"].flags & F_DIR_RECOVERED
    assert content(src, p["Photos/2023/Sommer/strand.jpg"]) == files["Photos/2023/Sommer/strand.jpg"]
    lost = [e for e in es if e.parent is None and e.key != 2]
    assert len(lost) == 150 and all(e.flags & F_ORPHAN for e in lost)


def paths_cnid(v: Vol, name: str) -> int:
    """The folder ID of a folder of the root, from its record."""
    for n in v.leaves():
        node = v.node("catalog", n)
        offs = offsets(node)
        for i in range(len(offs) - 1):
            parent, nm, rtype = record_key(node, i)
            if parent == 2 and nm == name and rtype == 1:
                klen = struct.unpack_from(">H", node, offs[i])[0]
                return struct.unpack_from(">I", node, offs[i] + 2 + klen + 8)[0]
    return -1


def test_damaged_catalog_header(iso_case):
    """The catalog's header node is wiped: the node size is guessed and every leaf node is found by scanning."""
    iso, off, size, files = iso_case
    v = Vol(Path(iso).read_bytes()[off:off + size])
    cat = v.fork_off("catalog")
    v.b[cat:cat + 512] = bytes(512)
    src = BytesSource(bytes(v.b))
    r = HfsPlusReader(src, HfsPlusReader.probe(src))
    es = list(r.entries())
    p = paths(es)
    for rel, data in files.items():
        assert rel in p and not p[rel].deleted and content(src, p[rel]) == data, rel
    assert not [e for e in es if e.deleted]
    assert any("header node" in w for w in r.warnings)


def test_fuzz_does_not_raise(iso_case):
    iso, off, size, files = iso_case
    good = Path(iso).read_bytes()[off:off + size]
    v = Vol(good)
    cat = v.fork_off("catalog")
    rnd = random.Random(7)
    for round_ in range(12):
        b = bytearray(good)
        for _ in range(60):
            pos = rnd.randrange(cat, cat + v.vh["forks"]["catalog"]["size"]) if round_ % 2 else \
                rnd.randrange(0, len(b))
            b[pos] = rnd.randrange(256)
        src = BytesSource(bytes(b))
        info = HfsPlusReader.probe(src)
        if info is None:
            continue
        try:
            r = HfsPlusReader(src, info)
        except Exception as exc:  # noqa: BLE001 - only our own error type is acceptable
            assert type(exc).__name__ == "FormatError"
            continue
        for e in r.entries():
            if not e.is_dir and e.size < 1_000_000:
                try:
                    content(src, e)
                except Exception as exc:  # noqa: BLE001
                    assert type(exc).__name__ in ("FormatError", "NotSupported")
        r.free_extents()


# ---------------------------------------------------------------------- synthetic volume (hfsprogs + nodes)
@pytest.fixture(scope="module")
def synth(tmp_path_factory):
    """An empty journaled HFS+ volume (mkfs.hfsplus -J) with records written into its B-trees."""
    need("mkfs.hfsplus")
    tmp = tmp_path_factory.mktemp("hfssynth")
    img = blank(tmp / "j.img", 16 * MiB)
    sh("mkfs.hfsplus", "-J", "-v", "SYNTH", img)
    v = Vol(img.read_bytes())
    bs = v.bs
    cat = v.node("catalog", 1)
    base = [(record_key(cat, i), bytes(cat[a:b])) for i, (a, b) in enumerate(zip(offsets(cat), offsets(cat)[1:]))]
    nxt = [700]                                            # free blocks for the data

    def alloc(data: bytes) -> list[tuple[int, int]]:
        n = max(1, -(-len(data) // bs))
        s = nxt[0]
        nxt[0] += n + 1                                     # a gap: files aren't contiguous
        v.b[s * bs:s * bs + len(data)] = data
        v.set_blocks(s, n, True)
        return [(s, n)]

    want: dict[str, bytes] = {}
    items = []
    # docs/ (18) with a plain file (19) and a file with a resource fork (26)
    items += [(2, "docs", folder_rec(18, 3)), (18, "", thread_rec(3, 2, "docs"))]
    want["docs/plain.txt"] = payload(10_000, 19)
    items += [(18, "plain.txt", file_rec(19, fork(10_000, alloc(want["docs/plain.txt"])))),
              (19, "", thread_rec(4, 18, "plain.txt"))]
    want["docs/withrsrc"] = b"data fork\n"
    want["docs/withrsrc/rsrc"] = payload(5000, 26)
    items += [(18, "withrsrc", file_rec(26, fork(10, alloc(want["docs/withrsrc"])),
                                        fork(5000, alloc(want["docs/withrsrc/rsrc"])))),
              (26, "", thread_rec(4, 18, "withrsrc"))]
    # z3.txt (20): zlib inside the decmpfs attribute; z4.bin (21): zlib chunks in the resource fork
    want["z3.txt"] = b"compress me " * 300
    items += [(2, "z3.txt", file_rec(20, owner_flags=0x20, flags=0x0006)), (20, "", thread_rec(4, 2, "z3.txt"))]
    want["z4.bin"] = (b"chunky " * 20000)[:140_000]
    chunks = [zlib.compress(want["z4.bin"][:65536]), b"\xff" + want["z4.bin"][65536:131072],
              zlib.compress(want["z4.bin"][131072:])]
    table = struct.pack("<I", len(chunks))
    pos = 4 + 8 * len(chunks)
    for c in chunks:
        table += struct.pack("<II", pos, len(c))
        pos += len(c)
    body = table + b"".join(chunks)
    rsrc = struct.pack(">IIII", 0x100, 0x100 + 4 + len(body), 4 + len(body), 50) + bytes(0x100 - 16)
    rsrc += struct.pack(">I", len(body)) + body + bytes(50)
    items += [(2, "z4.bin", file_rec(21, rsrc=fork(len(rsrc), alloc(rsrc)), owner_flags=0x20, flags=0x0006)),
              (21, "", thread_rec(4, 2, "z4.bin"))]
    # hard links: the private folder (22) holds iNode23; docs/link_a (24) and link_b (25) point to it
    want["docs/link_a"] = want["link_b"] = payload(3000, 23)
    priv = "\x00\x00\x00\x00HFS+ Private Data"
    items += [(2, priv, folder_rec(22, 1)), (22, "", thread_rec(3, 2, priv)),
              (22, "iNode23", file_rec(23, fork(3000, alloc(want["link_b"])), special=2)),
              (23, "", thread_rec(4, 22, "iNode23"))]
    for cnid, parent, name in ((24, 18, "link_a"), (25, 2, "link_b")):
        items += [(parent, name, file_rec(cnid, fdtype=b"hlnk", creator=b"hfs+", special=23)),
                  (cnid, "", thread_rec(4, parent, name))]
    # frag.bin (27): 10 fragments, the last two in the extents overflow B-tree
    want["frag.bin"] = payload(10 * bs - 100, 27)
    frags = []
    for k in range(10):
        frags += alloc(want["frag.bin"][k * bs:(k + 1) * bs])
    items += [(2, "frag.bin", file_rec(27, fork(len(want["frag.bin"]), frags[:8], 10))),
              (27, "", thread_rec(4, 2, "frag.bin"))]
    # deleted.txt (30), in docs: only an old copy of the catalog node in the journal remembers it
    deleted = payload(6000, 30)
    dext = alloc(deleted)
    v.set_blocks(dext[0][0], dext[0][1], False)
    gone = [(18, "deleted.txt", file_rec(30, fork(6000, dext))), (30, "", thread_rec(4, 18, "deleted.txt"))]

    old_items = [(p, n, rec[2 + struct.unpack_from(">H", rec, 0)[0]:]) for (p, n, _t), rec in base]
    before = write_tree(v, "catalog", catalog_records(old_items + items + gone))
    j_info = struct.unpack_from(">QQ", v.b, v.vh["journal_info_block"] * bs + 36)
    jpos = j_info[0] + 8192
    for k, nd in enumerate(before):
        v.b[jpos + k * len(nd):jpos + (k + 1) * len(nd)] = nd
    for i in range(1, 8):                                  # the new layout replaces the old one
        v.put_node("catalog", i, bytes(len(before[0])))
        v.map_bit("catalog", i, False)
    write_tree(v, "catalog", catalog_records(old_items + items))
    # the extents overflow record of frag.bin
    ext_key = struct.pack(">HBBII", 10, 0, 0, 27, 8)
    ext_rec = b"".join(struct.pack(">II", s, c) for s, c in frags[8:]) + bytes(8 * 6)
    write_tree(v, "extents", [ext_key + ext_rec])
    # the decmpfs attributes
    attrs = []
    name = "com.apple.decmpfs".encode("utf-16-be")
    for cnid, data in ((20, b"fpmc" + struct.pack("<IQ", 3, len(want["z3.txt"])) + zlib.compress(want["z3.txt"])),
                       (21, b"fpmc" + struct.pack("<IQ", 4, len(want["z4.bin"])))):
        key = struct.pack(">HHIIH", 12 + len(name), 0, cnid, 0, len(name) // 2) + name
        rec = struct.pack(">IIII", 0x10, 0, 0, len(data)) + data + (b"\x00" if len(data) & 1 else b"")
        attrs.append(key + rec)
    write_tree(v, "attributes", attrs)
    struct.pack_into(">I", v.b, 1024 + 64, 40)              # next catalog ID
    bm = v.fork_off("allocation")
    total = v.vh["total_blocks"]
    free = sum(1 for blk in range(total) if not v.b[bm + blk // 8] & (0x80 >> (blk % 8)))
    struct.pack_into(">I", v.b, 1024 + 48, free)            # free blocks
    img.write_bytes(bytes(v.b))
    return img, want, deleted


def test_synthetic_volume(synth):
    img, want, deleted = synth
    src = FileSource(str(img))
    info = HfsPlusReader.probe(src)
    assert info["label"] == "SYNTH" and info["journaled"] and info["uuid"]
    r = HfsPlusReader(src, info)
    es = list(r.entries())
    assert len({e.key for e in es}) == len(es)
    p = paths(es)
    for rel, data in want.items():
        assert rel in p, rel
        assert content(src, p[rel]) == data, rel
        assert p[rel].size == len(data)
    assert p["z3.txt"].flags & F_COMPRESSED and p["z4.bin"].flags & F_COMPRESSED
    assert "z4.bin/rsrc" not in p                          # the compressed data isn't a separate stream
    assert p["docs/withrsrc/rsrc"].flags & F_ADS
    assert p["docs/link_a"].flags & F_HARDLINK and p["link_b"].flags & F_HARDLINK
    assert p["HFS+ Private Data"].flags & F_SYSTEM and p["HFS+ Private Data/iNode23"].flags & F_SYSTEM
    assert p[".journal"].flags & F_SYSTEM
    d = p["docs/deleted.txt"]
    assert d.deleted and d.flags & F_JOURNAL and d.chance == CHANCE_GOOD and d.key == "d30"
    assert content(src, d) == deleted
    assert sum(1 for e in es if e.deleted) == 1
    # free space: the bitmap's free blocks, the deleted file's included
    free = r.free_extents()
    bs = info["block_size"]
    assert sum(n for _o, n in free) == info["free"]
    run = d.runs[0]
    assert any(o <= run[0] and run[0] + run[1] <= o + n for o, n in free)
    assert not any(o < 700 * bs + 10_000 and o + n > 700 * bs for o, n in free)


def test_synthetic_volume_tsk(synth):
    need("fls")
    img, want, deleted = synth
    out = sh("fls", "-r", "-p", "-f", "hfs", img)
    names = {line.split("\t", 1)[1] for line in out.splitlines() if "\t" in line}
    for rel in ("docs/plain.txt", "z3.txt", "z4.bin", "frag.bin", "docs/link_a", "link_b"):
        assert rel in names, rel
    need("icat")
    for rel, cnid in (("z4.bin", 21), ("frag.bin", 27), ("z3.txt", 20)):
        data = subprocess.run(["icat", "-f", "hfs", str(img), str(cnid)], capture_output=True).stdout
        assert data == want[rel], rel


def test_embedded_in_hfs_wrapper(iso_case):
    """An HFS+ volume inside a classic HFS wrapper (old Macs): the reader finds and reads it."""
    iso, off, size, files = iso_case
    inner = Path(iso).read_bytes()[off:off + size]
    alloc, first = 4096, 8                                 # wrapper: 4 KiB blocks from sector 8
    start_blk = 2
    wrapper = bytearray(first * 512 + start_blk * alloc + len(inner) + alloc)
    mdb = bytearray(512)
    mdb[0:2] = b"BD"
    struct.pack_into(">I", mdb, 0x14, alloc)
    struct.pack_into(">H", mdb, 0x1C, first)
    mdb[0x7C:0x7E] = b"H+"
    struct.pack_into(">HH", mdb, 0x7E, start_blk, len(inner) // alloc + 1)
    wrapper[1024:1536] = mdb
    pos = first * 512 + start_blk * alloc
    wrapper[pos:pos + len(inner)] = inner
    src = BytesSource(bytes(wrapper))
    info = HfsPlusReader.probe(src)
    assert info and info["embedded_offset"] == pos and info["label"] == "MACVOL"
    p = paths(list(HfsPlusReader(src, info).entries(deleted=False)))
    assert content(src, p["Photos/big.bin"]) == files["Photos/big.bin"]


# ---------------------------------------------------------------------- decmpfs decoder alone
def test_decoder_unit():
    plain = b"abc" * 50_000
    raw = b"fpmc" + struct.pack("<IQ", 3, 9) + b"\xff" + b"stored!!!"
    src = BytesSource(b"\x00" * 100 + raw)
    e = {"size": 9, "extra": {"decoder": "hfs-compressed", "ctype": 3, "xattr_runs": [[100, len(raw)]]}}
    assert b"".join(decode_decmpfs(src, e)) == b"stored!!!"
    assert b"".join(read_content(src, e)) == b"stored!!!"
    e = {"size": len(plain), "extra": {"decoder": "hfs-compressed", "ctype": 7, "xattr_runs": [[0, 16]]}}
    with pytest.raises(NotSupported):
        b"".join(decode_decmpfs(src, e))
    # a damaged chunk table must give a clear error, not garbage
    rs = bytearray(struct.pack(">IIII", 0x100, 0, 0, 0) + bytes(0x100 - 16) + struct.pack(">I", 8)
                   + struct.pack("<I", 1) + struct.pack("<II", 1 << 30, 10))
    src = BytesSource(bytes(rs))
    e = {"size": 10, "runs": [(0, len(rs))], "extra": {"decoder": "hfs-compressed", "ctype": 4,
                                                       "rsrc_size": len(rs)}}
    with pytest.raises(Exception) as exc:
        b"".join(decode_decmpfs(src, e))
    assert type(exc.value).__name__ == "FormatError"


def test_not_hfs():
    assert HfsPlusReader.probe(BytesSource(bytes(64 * 1024))) is None
    assert HfsPlusReader.probe(BytesSource(b"\xff" * 8192)) is None


@pytest.mark.skipif(shutil.which("mkfs.hfsplus") is None and not os.path.exists("/usr/sbin/mkfs.hfsplus"),
                    reason="hfsprogs is not installed")
def test_empty_hfsx(tmp_path):
    img = blank(tmp_path / "x.img", 8 * MiB)
    sh("mkfs.hfsplus", "-s", "-v", "CaseSens", img)
    src = FileSource(str(img))
    info = HfsPlusReader.probe(src)
    assert info["fstype"] == "hfsx" and info["label"] == "CaseSens"
    r = HfsPlusReader(src, info)
    es = list(r.entries())
    assert es[0].key == 2 and not any(e.deleted for e in es)
    assert sum(n for _o, n in r.free_extents()) == info["free"]
