"""ISO 9660 reader: images made by genisoimage (and xorriso when present) with Rock Ridge, Joliet or plain
names, cross-checked with isoinfo, blkid and The Sleuth Kit; a multi-extent file is crafted by hand."""

from __future__ import annotations

import os
import random
import shutil
import struct
from pathlib import Path

import pytest
from imagekit import need, payload, sh

from recoverall.core.blockio import BytesSource, FileSource
from recoverall.core.fs import base as fsbase
from recoverall.core.fs.base import CHANCE_GOOD, F_SYMLINK, read_content
from recoverall.core.fs.iso9660 import Iso9660Reader, parse_descriptors

STAMP = 1_600_000_000            # 2020-09-13 12:26:40 UTC


def tree(root: Path) -> dict[str, bytes]:
    """A source tree: deep folders (relocated by Rock Ridge), long and non-ASCII names, symlinks."""
    files = {
        "README": b"hello iso\n",
        "docs/manual.pdf": payload(70_000, 1),
        "docs/notes.txt": payload(3000, 2),
        "big.bin": payload(1_500_000, 3),
        "empty.dat": b"",
        "héllo wörld 日本語.txt": payload(1234, 4),
        "a/b/c/d/e/f/g/h/i/j/deep.txt": payload(500, 5),
        ("L" * 200) + ".dat": payload(2049, 6),
        "Mixed Case/Some File.TXT": payload(10, 7),
    }
    for i in range(300):                 # a folder spanning many sectors
        files[f"many/file_{i:04d}_with_a_long_enough_name.bin"] = payload(i * 3, 100 + i)
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        os.utime(p, (STAMP, STAMP + 60))
    os.symlink("docs/manual.pdf", root / "rel-link")
    os.symlink("/usr/share/" + "z" * 300, root / "abs-long-link")
    os.symlink("../../README", root / "docs" / "up-link")
    os.symlink("/", root / "root-link")
    return files


LINKS = {"rel-link": "docs/manual.pdf", "abs-long-link": "/usr/share/" + "z" * 300,
         "docs/up-link": "../../README", "root-link": "/"}


@pytest.fixture(scope="module")
def srctree(tmp_path_factory):
    root = tmp_path_factory.mktemp("isosrc") / "t"
    root.mkdir()
    files = tree(root)
    return root, files


def mkiso(out: Path, src: Path, *opts: str) -> Path:
    need("genisoimage")
    sh("genisoimage", "-quiet", "-input-charset", "utf-8", "-V", "My Disc", *opts, "-o", out, src)
    return out


def read_all(img: Path):
    src = FileSource(str(img))
    info = Iso9660Reader.probe(src)
    r = Iso9660Reader(src, info)
    es = list(r.entries())
    return src, info, r, es


def paths(es) -> dict:
    by = {e.key: e for e in es}
    out = {}
    for e in es[1:]:
        parts, p = [], e
        while p is not None and p.parent is not None:
            parts.append(p.name)
            p = by.get(p.parent)
        out["/".join(reversed(parts))] = e
    return out


def data_of(src, e) -> bytes:
    return b"".join(read_content(src, e))


# ---------------------------------------------------------------------- tests
def test_probe(srctree, tmp_path):
    root, _files = srctree
    img = mkiso(tmp_path / "rj.iso", root, "-J", "-R")
    src = FileSource(str(img))
    info = Iso9660Reader.probe(src)
    assert info["fstype"] == "iso9660" and info["label"] == "My Disc" and info["block_size"] == 2048
    assert info["size"] == os.path.getsize(img) and info["joliet"] == 3 and info["rock_ridge"]
    assert info["created"] and abs(info["created"] - os.path.getmtime(img)) < 120
    if shutil.which("blkid") or os.path.exists("/usr/sbin/blkid") or os.path.exists("/sbin/blkid"):
        blk = sh("blkid", "-p", "-o", "value", "-s", "UUID", img).strip()
        assert info["uuid"] == blk
    assert Iso9660Reader.probe(BytesSource(bytes(64 * 1024))) is None
    assert parse_descriptors(BytesSource(bytes(40000) + b"\x01CD001" + bytes(3000))) is None


def test_rock_ridge(srctree, tmp_path):
    root, files = srctree
    img = mkiso(tmp_path / "rr.iso", root, "-J", "-R")
    src, info, r, es = read_all(img)
    assert not r.use_joliet and r.rock_ridge
    ps = paths(es)
    keys = [e.key for e in es]
    assert len(keys) == len(set(keys)) and es[0].key == r.root_key and es[0].is_dir
    for rel, data in files.items():
        e = ps[rel]
        assert e.size == len(data) and e.chance == CHANCE_GOOD and not e.deleted, rel
        assert data_of(src, e) == data, rel
        assert e.mtime == STAMP + 60, rel                 # Rock Ridge TF keeps the real time
        assert e.extra["mode"] == 0o644
    for rel, target in LINKS.items():
        e = ps[rel]
        assert e.flags & F_SYMLINK and e.data == target.encode() and e.size == len(target), rel
    # the deep folder is relocated to rr_moved on disc, but listed where it belongs
    assert ps["a/b/c/d/e/f/g/h"].is_dir and not [p for p in ps if p.startswith("rr_moved/")]
    assert r.warnings == []
    # isoinfo agrees on the names (it shows relocated folders under rr_moved, so leave those out)
    if shutil.which("isoinfo"):
        listed = {line.strip().lstrip("/") for line in sh("isoinfo", "-R", "-f", "-i", img).splitlines()}
        moved = "a/b/c/d/e/f/g/h"
        listed = {p for p in listed if p and not p.startswith("rr_moved") and p != moved}
        assert listed == {p for p in ps if not p.startswith(("rr_moved", moved))}


def test_joliet(srctree, tmp_path):
    root, files = srctree
    img = mkiso(tmp_path / "j.iso", root, "-J", "-joliet-long", "-D")
    src, info, r, es = read_all(img)
    assert r.use_joliet and not r.rock_ridge
    ps = paths(es)
    assert ps["héllo wörld 日本語.txt"].size == 1234
    assert data_of(src, ps["Mixed Case/Some File.TXT"]) == files["Mixed Case/Some File.TXT"]
    assert data_of(src, ps["a/b/c/d/e/f/g/h/i/j/deep.txt"]) == files["a/b/c/d/e/f/g/h/i/j/deep.txt"]
    # Joliet names stop at 103 characters
    long = [p for p in ps if p.startswith("LLLL")]
    assert len(long) == 1 and len(long[0]) == 103
    assert data_of(src, ps[long[0]]) == files[("L" * 200) + ".dat"]
    for rel, data in files.items():
        if not rel.startswith("LLLL"):
            assert data_of(src, ps[rel]) == data, rel
    # TSK reads the Joliet tree too: same names
    if shutil.which("fls"):
        out = sh("fls", "-r", "-p", "-f", "iso9660", img)
        tsk = {line.split("\t", 1)[1] for line in out.splitlines() if "\t" in line and "$Orphan" not in line}
        assert tsk == set(ps)


def test_plain_names(srctree, tmp_path):
    root, files = srctree
    img = mkiso(tmp_path / "p.iso", root, "-D")
    src, info, r, es = read_all(img)
    ps = paths(es)
    assert not r.use_joliet and not r.rock_ridge
    assert "README" in ps and "DOCS/MANUAL.PDF" in ps and ps["DOCS"].is_dir
    assert not any(";" in p for p in ps)
    assert data_of(src, ps["DOCS/MANUAL.PDF"]) == files["docs/manual.pdf"]
    assert data_of(src, ps["BIG.BIN"]) == files["big.bin"]
    assert ps["EMPTY.DAT"].size == 0


def test_xorriso(srctree, tmp_path):
    need("xorriso")
    root, files = srctree
    # libisofs refuses symlink targets over 255 bytes: leave that one out
    copy = tmp_path / "t"
    shutil.copytree(root, copy, symlinks=True)
    (copy / "abs-long-link").unlink()
    img = tmp_path / "x.iso"
    sh("xorriso", "-as", "mkisofs", "-quiet", "-J", "-R", "-V", "XORR", "-o", img, copy)
    src, info, r, es = read_all(img)
    assert info["label"] == "XORR" and r.rock_ridge
    ps = paths(es)
    for rel, data in files.items():
        assert data_of(src, ps[rel]) == data, rel
    for rel, target in LINKS.items():
        if rel != "abs-long-link":
            assert ps[rel].data == target.encode(), rel


def test_multi_extent(tmp_path):
    """A file of several extents (what files over 4 GiB look like), made by splitting a file's directory
    record in two: the first flagged multi-extent, the second for the rest."""
    src_dir = tmp_path / "m"
    src_dir.mkdir()
    data = payload(5 * 2048 + 77, 11)
    (src_dir / "SPLIT.BIN").write_bytes(data)
    (src_dir / "Z.TXT").write_bytes(b"z")
    img = mkiso(tmp_path / "m.iso", src_dir)
    raw = bytearray(img.read_bytes())
    info = parse_descriptors(BytesSource(bytes(raw)))
    root = info["root_lba"] * 2048
    pos = root
    while raw[pos]:
        n = raw[pos]
        if raw[pos + 33:pos + 33 + raw[pos + 32]].startswith(b"SPLIT.BIN"):
            break
        pos += n
    else:
        raise AssertionError("record not found")
    rec = bytes(raw[pos:pos + raw[pos]])
    lba = struct.unpack_from("<I", rec, 2)[0]
    first, second = bytearray(rec), bytearray(rec)
    for buf, off, value in ((first, 10, 2 * 2048), (second, 2, lba + 2), (second, 10, len(data) - 2 * 2048)):
        struct.pack_into("<I", buf, off, value)          # both-endian numbers
        struct.pack_into(">I", buf, off + 4, value)
    first[25] |= 0x80
    tail_end = pos
    while tail_end < root + 2048 and raw[tail_end]:
        tail_end += raw[tail_end]
    tail = bytes(raw[pos + len(rec):tail_end])
    assert tail_end + len(rec) <= root + 2048
    raw[pos:pos + len(rec) * 2 + len(tail)] = bytes(first) + bytes(second) + tail
    s = BytesSource(bytes(raw))
    r = Iso9660Reader(s, Iso9660Reader.probe(s))
    es = list(r.entries())
    [e] = [e for e in es if e.name == "SPLIT.BIN"]
    assert e.size == len(data) and data_of(s, e) == data
    assert [x.name for x in es].count("Z.TXT") == 1


def test_fuzz_does_not_raise(srctree, tmp_path):
    root, _files = srctree
    img = mkiso(tmp_path / "f.iso", root, "-J", "-R")
    raw = bytearray(img.read_bytes())
    info = parse_descriptors(BytesSource(bytes(raw)))
    # folder sectors and the volume descriptors are what the reader parses
    meta = [16 + k for k in range(4)] + list(range(info["root_lba"], info["root_lba"] + 40))
    rng = random.Random(77)
    for _ in range(150):
        buf = bytearray(raw)
        for _ in range(rng.randint(1, 40)):
            sec = rng.choice(meta)
            buf[sec * 2048 + rng.randrange(2048)] = rng.randrange(256)
        if rng.random() < 0.2:
            sec = rng.choice(meta)
            buf[sec * 2048:(sec + 1) * 2048] = os.urandom(2048)
        s = BytesSource(bytes(buf))
        info2 = Iso9660Reader.probe(s)
        if info2 is None:
            continue
        r = Iso9660Reader(s, info2)
        keys = set()
        for e in r.entries():
            assert e.key not in keys
            keys.add(e.key)
            if not e.is_dir:
                fsbase.read_head(s, e, 4096)
        assert r.free_extents() == []
