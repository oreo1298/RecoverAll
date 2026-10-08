"""The FAT12/16/32 reader against images made by mkfs.fat and mtools: live, deleted, damaged and quick-formatted."""

from __future__ import annotations

import os
import random
import struct

import imagekit
import pytest
from imagekit import MiB, mkfs, mtools_copy, mtools_delete, mtools_rmdir, payload

from recoverall.core.blockio import BytesSource, FileSource
from recoverall.core.fs.base import CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, F_DIR_RECOVERED, F_ORPHAN, read_content
from recoverall.core.fs.fat import FatReader, lfn_checksum, lfn_first_char, parse_boot

SIZES = {"fat12": 8 * MiB, "fat16": 32 * MiB, "fat32": 64 * MiB}


@pytest.fixture(autouse=True)
def _utf8(monkeypatch):
    # mtools converts long names with the locale's charset: without UTF-8 it mangles non-ASCII names
    monkeypatch.setenv("LC_ALL", "C.UTF-8")
    monkeypatch.setenv("TZ", "UTC")


def make(tmp_path, fstype, name="fat.img"):
    img = tmp_path / name
    mkfs(img, fstype, size=SIZES[fstype], label="TEST", extra=["-i", "1234ABCD"])
    return img


def open_reader(img, **info):
    src = FileSource(str(img))
    probed = FatReader.probe(src)
    assert probed is not None
    probed.update(info)
    return src, FatReader(src, probed)


def listing(reader, ctl=None, **kw):
    """(entries, {key: path}); orphans' paths start with "<lost>"."""
    args = (ctl,) if ctl is not None else ()
    ents = list(reader.entries(*args, **kw))
    keys = [e.key for e in ents]
    assert len(keys) == len(set(keys)), "duplicate keys"
    assert ents[0].key == reader.root_key and ents[0].parent is None and ents[0].is_dir
    byk = {e.key: e for e in ents}
    paths = {}
    for e in ents:
        parts = []
        x = e
        for _ in range(300):
            if x.key == reader.root_key:
                break
            parts.append(x.name)
            if x.parent is None:
                parts.append("<lost>")
                break
            x = byk[x.parent]
        else:
            raise AssertionError("parent loop")
        paths[e.key] = "/".join(reversed(parts))
    return ents, paths


def by_path(ents, paths, deleted=None):
    out = {}
    for e in ents:
        if e.key == 0 or (deleted is not None and e.deleted != deleted):
            continue
        out[paths[e.key]] = e
    return out


def content(src, e) -> bytes:
    return b"".join(read_content(src, e))


def tsk_paths(img) -> tuple[set[str], set[str]] | None:
    """(live, deleted) file and folder paths as The Sleuth Kit's fls lists them (None when it's missing)."""
    if not imagekit.shutil.which("fls"):
        return None
    out = imagekit.sh("fls", "-r", "-p", img)
    live, dead = set(), set()
    for line in out.splitlines():
        head, _sep, path = line.partition(":\t")
        if not path or path.startswith("$") or "(Volume Label Entry)" in path or "(realloc)" in head:
            continue
        (dead if "*" in head else live).add(path)
    return live, dead


def files_for(cs: int, big: int) -> dict[str, bytes]:
    return {
        "empty.txt": b"",
        "one.bin": payload(1, 1),
        "readme.txt": payload(cs - 1, 2),
        "Exactly one cluster.dat": payload(cs, 3),
        "UPPER.TXT": payload(cs + 1, 4),
        "Ünïcødé – файл 名前.txt": payload(777, 5),
        "Documents/Projects/2024/A rather long file name, with spaces and punctuation!.pdf": payload(5000, 6),
        "Documents/notes.md": payload(12345, 7),
        "DCIM/100CANON/IMG_0001.JPG": payload(big, 8),
        "DCIM/100CANON/IMG_0002.JPG": payload(big // 3, 9),
    }


# ---------------------------------------------------------------------- pieces
def test_lfn_checksum_inverse():
    name = b"LONGFI~1BIN"
    chk = lfn_checksum(name)
    assert lfn_first_char(b"\xe5" + name[1:], chk) == ord("L")
    rnd = random.Random(3)
    for _ in range(200):
        n = bytes(rnd.randrange(0x21, 0x7F) for _ in range(11))
        assert lfn_first_char(b"\xe5" + n[1:], lfn_checksum(n)) == n[0]


def test_parse_boot_rejects_junk():
    assert parse_boot(bytes(512)) is None
    assert parse_boot(b"\xeb\x52\x90NTFS    " + bytes(500)) is None
    rnd = random.Random(1)
    for _ in range(200):
        junk = bytearray(rnd.randbytes(512))
        junk[510:512] = b"\x55\xaa"
        info = parse_boot(bytes(junk))
        if info is not None:                 # rare: then it must at least be self-consistent
            assert info["data_offset"] < info["size"] and info["clusters"] >= 1


# ---------------------------------------------------------------------- live files
@pytest.mark.parametrize("fstype", ["fat12", "fat16", "fat32"])
def test_probe(tmp_path, fstype):
    img = make(tmp_path, fstype)
    src = FileSource(str(img))
    info = FatReader.probe(src)
    assert info["fstype"] == fstype and info["label"] == "TEST" and info["uuid"] == "1234-ABCD"
    assert info["size"] == SIZES[fstype] or info["size"] <= SIZES[fstype]
    assert info["block_size"] == info["cluster_size"] and info["boot"] == "main"
    assert info["free"] > 0 and info["used"] >= 0
    r = FatReader(src, info)
    assert r.fstype == fstype and r.name == fstype.upper()


@pytest.mark.parametrize("fstype", ["fat12", "fat16", "fat32"])
def test_live_files(tmp_path, fstype):
    img = make(tmp_path, fstype)
    cs = FatReader.probe(FileSource(str(img)))["cluster_size"]
    files = files_for(cs, 2 * MiB if fstype == "fat12" else 5 * MiB + 321)
    mtools_copy(img, files, tmp_path)
    src, r = open_reader(img)
    ents, paths = listing(r)
    live = by_path(ents, paths, deleted=False)
    for rel, data in files.items():
        e = live[rel]
        assert not e.is_dir and e.size == len(data) and e.chance == CHANCE_GOOD
        assert content(src, e) == data, rel
        assert e.mtime is not None and e.crtime is not None
    for d in ("Documents", "Documents/Projects", "Documents/Projects/2024", "DCIM", "DCIM/100CANON"):
        assert live[d].is_dir and live[d].size == 0 and live[d].runs is None
    assert live["readme.txt"].extra["short_name"] == "readme.txt"      # lowercase via the case flags
    assert not any(e.deleted for e in ents)
    tsk = tsk_paths(img)
    if tsk is not None:
        assert set(live) == tsk[0]
    # free space doesn't overlap any file
    free = r.free_extents()
    assert sum(n for _o, n in free) == r.info["free"]
    for e in live.values():
        for off, n in e.runs or []:
            assert not any(o < off + n and off < o + m for o, m in free), e.name


def test_timestamps(tmp_path):
    img = make(tmp_path, "fat32")
    f = tmp_path / "stamp.txt"
    f.write_bytes(b"x" * 100)
    when = 1_700_000_000                        # 2023-11-14 22:13:20 UTC (even seconds)
    os.utime(f, (when, when))
    imagekit.sh("mcopy", "-m", "-i", img, f, "::/stamp.txt", env={"TZ": "UTC"})
    src, r = open_reader(img)
    ents, paths = listing(r)
    e = by_path(ents, paths)["stamp.txt"]
    assert e.mtime == when and e.crtime is not None
    assert e.atime == when - when % 86400       # FAT keeps only the date of the last access


def test_fragmented_live_file(tmp_path):
    img = make(tmp_path, "fat16")
    a, b, c = payload(3000, 1), payload(5000, 2), payload(40000, 3)
    mtools_copy(img, {"A.BIN": a, "B.BIN": b}, tmp_path)
    mtools_delete(img, "A.BIN")
    mtools_copy(img, {"C.BIN": c}, tmp_path)          # fills A's hole, then goes on after B
    src, r = open_reader(img)
    ents, paths = listing(r)
    e = by_path(ents, paths, deleted=False)["C.BIN"]
    assert len(e.runs) >= 2 and e.chance == CHANCE_GOOD
    assert content(src, e) == c


# ---------------------------------------------------------------------- deleted files
@pytest.mark.parametrize("fstype", ["fat12", "fat16", "fat32"])
def test_deleted_files_and_tree(tmp_path, fstype):
    img = make(tmp_path, fstype)
    cs = FatReader.probe(FileSource(str(img)))["cluster_size"]
    files = files_for(cs, 1 * MiB + 77)
    files["keep.txt"] = payload(100, 99)
    mtools_copy(img, files, tmp_path)
    for rel in ("one.bin", "readme.txt", "UPPER.TXT", "Ünïcødé – файл 名前.txt", "Exactly one cluster.dat"):
        mtools_delete(img, rel)
    mtools_rmdir(img, "DCIM")
    mtools_rmdir(img, "Documents")
    src, r = open_reader(img)
    ents, paths = listing(r)
    dead = by_path(ents, paths, deleted=True)
    live = by_path(ents, paths, deleted=False)
    assert set(live) == {"empty.txt", "keep.txt"}
    # names without a long name lose their first character ("_"), like every FAT undelete shows them
    pdf = "Documents/Projects/_024/A rather long file name, with spaces and punctuation!.pdf"
    expect = {
        "one.bin": "_ne.bin", "readme.txt": "_eadme.txt", "UPPER.TXT": "_PPER.TXT",
        "Ünïcødé – файл 名前.txt": "Ünïcødé – файл 名前.txt", "Exactly one cluster.dat": "Exactly one cluster.dat",
        "DCIM/100CANON/IMG_0001.JPG": "_CIM/_00CANON/_MG_0001.JPG",
        "DCIM/100CANON/IMG_0002.JPG": "_CIM/_00CANON/_MG_0002.JPG",
        "Documents/notes.md": "Documents/_otes.md",
        "Documents/Projects/2024/A rather long file name, with spaces and punctuation!.pdf": pdf,
    }
    for rel, shown in expect.items():
        e = dead[shown]
        assert e.size == len(files[rel]) and e.chance == CHANCE_GOOD, shown
        assert content(src, e) == files[rel], shown
        assert e.mtime is not None
    for d in ("_CIM", "_CIM/_00CANON", "Documents", "Documents/Projects", "Documents/Projects/_024"):
        assert dead[d].is_dir and dead[d].deleted
    assert not r.warnings
    assert {e.key for e in r.entries(deleted=False)} == {0} | {e.key for e in live.values()}
    tsk = tsk_paths(img)
    if tsk is not None:
        assert set(live) == tsk[0] and set(dead) == tsk[1]


def test_deleted_chances(tmp_path):
    img = make(tmp_path, "fat16")
    x, y = payload(10 * 2048, 1), payload(2 * 2048, 2)
    mtools_copy(img, {"D/X.BIN": x, "W.BIN": payload(5000, 3)}, tmp_path)
    mtools_delete(img, "D/X.BIN")
    src, r = open_reader(img)
    ents, paths = listing(r)
    e = by_path(ents, paths, deleted=True)["D/_.BIN"]
    assert e.chance == CHANCE_GOOD and content(src, e) == x
    first = e.extra["cluster"]
    # someone now uses the third cluster of X: the clusters around it are taken instead (FAIR)
    raw = bytearray(img.read_bytes())
    info = r.info
    for k in range(info["fats"]):
        struct.pack_into("<H", raw, info["fat_offset"] + k * info["fat_bytes"] + 2 * (first + 2), 0xFFFF)
    src2 = BytesSource(bytes(raw))
    r2 = FatReader(src2, FatReader.probe(src2))
    e2 = [e for e in r2.entries() if e.name == "_.BIN"][0]
    assert e2.chance == CHANCE_FAIR
    clusters = []
    for off, n in e2.runs:
        c = (off - info["data_offset"]) // 2048 + 2
        clusters += range(c, c + -(-n // 2048))
    assert first + 2 not in clusters and clusters[0] == first and len(clusters) == 10
    # a new file (in another folder, so X's entry stays) took its first cluster: POOR
    mtools_copy(img, {"Y.BIN": y}, tmp_path)
    src3, r3 = open_reader(img)
    e3 = [e for e in r3.entries() if e.deleted and e.size == len(x)]
    assert e3 and e3[0].chance == CHANCE_POOR


def test_deleted_folder_with_zeroed_high_word(tmp_path):
    img = make(tmp_path, "fat32")                                 # 512-byte clusters: 129022 of them
    mtools_copy(img, {"filler.bin": payload(34 * MiB, 1)}, tmp_path)   # pushes what follows past 65535
    files = {"Holiday/IMG_0001.JPG": payload(9000, 2), "Holiday/a long name.txt": payload(700, 3)}
    mtools_copy(img, files, tmp_path)
    mtools_rmdir(img, "Holiday")
    src, r = open_reader(img)
    ents, paths = listing(r)
    d = by_path(ents, paths, deleted=True)["Holiday"]
    assert d.extra["cluster"] > 0xFFFF
    # Windows zeroes the high half of a deleted entry's first cluster on FAT32
    raw = bytearray(img.read_bytes())
    raw[d.key + 20:d.key + 22] = b"\x00\x00"
    src2 = BytesSource(bytes(raw))
    r2 = FatReader(src2, FatReader.probe(src2))
    ents2, paths2 = listing(r2)
    dead = by_path(ents2, paths2, deleted=True)
    assert dead["Holiday"].extra["cluster"] == d.extra["cluster"]
    assert content(src2, dead["Holiday/_MG_0001.JPG"]) == files["Holiday/IMG_0001.JPG"]
    assert content(src2, dead["Holiday/a long name.txt"]) == files["Holiday/a long name.txt"]


# ---------------------------------------------------------------------- damage
def test_backup_boot_sector(tmp_path):
    img = make(tmp_path, "fat32")
    files = {"DCIM/100CANON/IMG_0001.JPG": payload(70000, 1), "Long name document.txt": payload(3000, 2)}
    mtools_copy(img, files, tmp_path)
    with open(img, "r+b") as fh:
        fh.write(bytes(512))
    src = FileSource(str(img))
    info = FatReader.probe(src)
    assert info is not None and info["boot"] == "backup" and info["fstype"] == "fat32"
    r = FatReader(src, info)
    ents, paths = listing(r)
    live = by_path(ents, paths, deleted=False)
    for rel, data in files.items():
        assert content(src, live[rel]) == data


@pytest.mark.parametrize("fstype,damage", [("fat16", "zeros"), ("fat32", "random"), ("fat32", "partial")])
def test_damaged_first_fat(tmp_path, fstype, damage):
    img = make(tmp_path, fstype)
    files = {f"DIR{i}/FILE{j}.BIN": payload(3000 * (i + 1) + j, i * 10 + j) for i in range(3) for j in range(4)}
    mtools_copy(img, files, tmp_path)
    info = FatReader.probe(FileSource(str(img)))
    raw = bytearray(img.read_bytes())
    start, length = info["fat_offset"], info["fat_bytes"]
    rnd = random.Random(5)
    if damage == "zeros":
        raw[start:start + length] = bytes(length)
    elif damage == "random":
        raw[start:start + length] = rnd.randbytes(length)
    else:
        raw[start + 512:start + 1024] = rnd.randbytes(512)
    src = BytesSource(bytes(raw))
    r = FatReader(src, FatReader.probe(src))
    ents, paths = listing(r)
    live = by_path(ents, paths, deleted=False)
    assert r.fat_copy == 2 and any("second copy" in w for w in r.warnings)
    for rel, data in files.items():
        assert content(src, live[rel]) == data
    # forcing the damaged copy must not break anything either
    forced = FatReader(src, dict(FatReader.probe(src), fat_copy=1))
    listing(forced)
    assert forced.fat_copy == 1


# ---------------------------------------------------------------------- quick format
@pytest.mark.parametrize("fstype", ["fat16", "fat32"])
def test_quick_format_lost_folders(tmp_path, fstype, ctl):
    img = make(tmp_path, fstype)
    files = {f"DCIM/100CANON/IMG_{i:04d}.JPG": payload(20000 + 7919 * i, i) for i in range(1, 9)}
    files.update({f"DCIM/101CANON/IMG_{i:04d}.JPG": payload(50000 + i, 100 + i) for i in range(1, 4)})
    files["Documents/Long folder name/report final.docx"] = payload(33333, 200)
    files["Documents/todo.txt"] = payload(10, 201)
    mtools_copy(img, files, tmp_path)
    # quick format: same parameters, the data area isn't touched
    imagekit.sh("mkfs.fat", "-F", fstype[3:], "-n", "TEST", "-i", "1234ABCD", img)
    src, r = open_reader(img)
    ents, _paths = listing(r)
    assert len(ents) == 1                              # an empty filesystem, as far as its folders go
    src, r = open_reader(img, scan_lost_dirs=True)
    ents, paths = listing(r, ctl)
    assert "Looking for lost folders" in ctl.messages
    found = by_path(ents, paths)
    tops = [e for e in ents if e.flags & F_ORPHAN]
    assert tops and all(e.is_dir and e.parent is None and e.flags & F_DIR_RECOVERED for e in tops)
    assert all(e.name.startswith("Folder ") for e in tops)
    for rel, data in files.items():
        top, rest = rel.split("/", 1)
        hits = [p for p in found if p.endswith("/" + rest) and p.startswith("<lost>/Folder ")]
        assert len(hits) == 1, rel
        e = found[hits[0]]
        assert e.size == len(data) and e.chance == CHANCE_GOOD and content(src, e) == data, rel
    # the same through lost_directories()
    src2, r2 = open_reader(img)
    lost = list(r2.lost_directories())
    assert {e.key for e in lost} == {e.key for e in ents[1:]}


def test_destroyed_root_lost_folders(tmp_path):
    img = make(tmp_path, "fat32")
    files = {"Music/Album/01 Track.mp3": payload(60000, 1), "Music/Album/02 Track.mp3": payload(61000, 2),
             "Work/plan.txt": payload(2000, 3)}
    mtools_copy(img, files, tmp_path)
    info = FatReader.probe(FileSource(str(img)))
    raw = bytearray(img.read_bytes())
    root = info["data_offset"] + (info["root_cluster"] - 2) * info["cluster_size"]
    raw[root:root + info["cluster_size"]] = bytes(info["cluster_size"])       # the root folder is wiped
    src = BytesSource(bytes(raw))
    r = FatReader(src, dict(FatReader.probe(src), scan_lost_dirs=True))
    ents, paths = listing(r)
    found = by_path(ents, paths)
    for rel, data in files.items():
        hits = [p for p in found if p.endswith("/" + rel.split("/", 1)[1]) and p.startswith("<lost>/Folder ")]
        assert len(hits) == 1, rel
        e = found[hits[0]]
        # the FAT is intact: these are existing files whose folder is lost, read through their chains
        assert not e.deleted and e.chance == CHANCE_GOOD and content(src, e) == data


# ---------------------------------------------------------------------- fuzz
@pytest.mark.parametrize("fstype", ["fat12", "fat32"])
def test_fuzz_never_raises(tmp_path, fstype):
    img = make(tmp_path, fstype)
    files = {f"D{i}/sub folder {i}/file number {j}.bin": payload(1500 * j + 1, i * 7 + j)
             for i in range(3) for j in range(3)}
    files["root file with a long name.txt"] = payload(4000, 50)
    mtools_copy(img, files, tmp_path)
    mtools_delete(img, "D1/sub folder 1/file number 2.bin")
    mtools_rmdir(img, "D2")
    base = img.read_bytes()
    info = FatReader.probe(BytesSource(base))
    meta_end = info["data_offset"] + 64 * info["cluster_size"]       # FATs, root and the first folders
    rnd = random.Random(1234)
    for _round in range(25):
        raw = bytearray(base)
        for _ in range(rnd.choice((5, 50, 400))):
            pos = rnd.randrange(info["fat_offset"], min(meta_end, len(raw)))
            raw[pos] = rnd.randrange(256)
        if rnd.random() < 0.3:                            # a whole sector of garbage
            pos = rnd.randrange(info["fat_offset"], min(meta_end, len(raw)) - 512) & ~511
            raw[pos:pos + 512] = rnd.randbytes(512)
        src = BytesSource(bytes(raw))
        probed = FatReader.probe(src) or info
        r = FatReader(src, dict(probed, scan_lost_dirs=rnd.random() < 0.5))
        ents, _paths = listing(r)
        for e in ents[:40]:
            if not e.is_dir:
                content(src, e)
        r.free_extents()
