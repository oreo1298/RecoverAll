"""The exFAT reader against images made by mkfs.exfat and filled through exfat-fuse: live, deleted, fragmented,
contiguous (NoFatChain) and damaged."""

from __future__ import annotations

import contextlib
import os
import random
import shutil
import struct
import subprocess
import time

import imagekit
import pytest
from imagekit import MiB, mkfs, payload

from recoverall.core.blockio import BytesSource, FileSource
from recoverall.core.fs.base import CHANCE_GOOD, F_SYSTEM, read_content
from recoverall.core.fs.exfat import (
    BitmapMap,
    ExfatReader,
    boot_checksum,
    entry_set_checksum,
    exfat_time,
    parse_boot,
)


@pytest.fixture(autouse=True)
def _utc(monkeypatch):
    monkeypatch.setenv("TZ", "UTC")


@contextlib.contextmanager
def mounted(img, mnt):
    """exfat-fuse on IMG. As root it insists on a block device ("fuseblk"), so it goes through a loop device."""
    exe = shutil.which("mount.exfat-fuse") or shutil.which("exfat-fuse") or (
        "/usr/sbin/mount.exfat-fuse" if os.path.exists("/usr/sbin/mount.exfat-fuse") else None)
    if not exe or not os.path.exists("/dev/fuse"):
        pytest.skip("exfat-fuse is not installed")
    if os.geteuid() != 0:
        with imagekit.fuse_mount(img, "exfat", mnt):
            yield mnt
        return
    p = subprocess.run(["losetup", "-f", "--show", str(img)], capture_output=True, text=True)
    if p.returncode != 0:
        pytest.skip(f"no loop device for exfat-fuse: {p.stderr.strip()}")
    dev = p.stdout.strip()
    try:
        mnt.mkdir(parents=True, exist_ok=True)
        try:
            imagekit.sh(exe, dev, mnt)
        except RuntimeError as exc:
            pytest.skip(f"exfat-fuse can't mount here: {exc}")
        try:
            yield mnt
        finally:
            os.sync()
            for _ in range(20):
                if subprocess.run(["umount", str(mnt)], capture_output=True).returncode == 0:
                    break
                time.sleep(0.2)
    finally:
        subprocess.run(["losetup", "-d", dev], capture_output=True)


def make(tmp_path, size=32 * MiB):
    img = tmp_path / "exfat.img"
    mkfs(img, "exfat", size=size, label="TEST")
    return img


def write_files(root, files: dict[str, bytes], stamp: float | None = None) -> None:
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        if stamp is not None:
            os.utime(p, (stamp, stamp))


def open_reader(img_or_bytes, **info):
    src = BytesSource(img_or_bytes) if isinstance(img_or_bytes, (bytes, bytearray)) else FileSource(str(img_or_bytes))
    probed = ExfatReader.probe(src)
    assert probed is not None
    probed.update(info)
    return src, ExfatReader(src, probed)


def listing(reader):
    ents = list(reader.entries())
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
            x = byk[x.parent]
        else:
            raise AssertionError("parent loop")
        paths[e.key] = "/".join(reversed(parts))
    return ents, paths


def by_path(ents, paths, deleted=None):
    return {paths[e.key]: e for e in ents[1:] if (deleted is None or e.deleted == deleted)
            and not e.flags & F_SYSTEM}


def content(src, e) -> bytes:
    return b"".join(read_content(src, e))


def tsk_paths(img):
    if not shutil.which("fls"):
        return None
    live, dead = set(), set()
    for line in imagekit.sh("fls", "-r", "-p", img).splitlines():
        head, _sep, path = line.partition(":\t")
        if not path or path.startswith("$") or "(Volume Label Entry)" in path or "(realloc)" in head:
            continue
        (dead if "*" in head else live).add(path)
    return live, dead


# ---------------------------------------------------------------------- pieces
def test_time_and_checksums():
    ts = (43 << 25) | (11 << 21) | (14 << 16) | (22 << 11) | (13 << 5) | 10      # 2023-11-14 22:13:20
    assert exfat_time(ts) == 1_700_000_000
    assert exfat_time(ts, 137) == 1_700_000_001.37
    assert exfat_time(ts, 0, 0x80 | 4) == 1_700_000_000 - 3600          # written at UTC+1
    assert exfat_time(ts, 0, 0x80 | 0x7C) == 1_700_000_000 + 3600        # UTC-1
    assert entry_set_checksum(bytes(64)) == 0
    assert parse_boot(bytes(512)) is None
    rnd = random.Random(2)
    junk = bytearray(rnd.randbytes(512))
    junk[3:11] = b"EXFAT   "
    assert parse_boot(bytes(junk)) is None            # the must-be-zero area isn't
    assert boot_checksum(bytes(11 * 512), 512) == 0


def test_bitmap_map_matches_naive():
    rnd = random.Random(7)
    for count in (1, 7, 8, 9, 64, 1000, 4099):
        for density in (0.0, 0.05, 0.5, 0.95, 1.0):
            bits = [rnd.random() < density for _ in range(count)]
            bm = bytearray((count + 7) // 8)
            for k, b in enumerate(bits):
                if b:
                    bm[k >> 3] |= 1 << (k & 7)
            m = BitmapMap(bytes(bm), count)
            runs, k = [], 0
            while k < count:
                if bits[k]:
                    k += 1
                    continue
                j = k
                while j < count and not bits[j]:
                    j += 1
                runs.append((k + 2, j - k))
                k = j
            assert list(m.free_runs()) == runs
            assert m.free_count() == bits.count(False)
            for _ in range(50):
                c = rnd.randrange(2, count + 2)
                n = rnd.randrange(1, count + 3 - c)
                assert m.count_used(c, n) == sum(bits[c - 2:c - 2 + n])
                assert m.all_free(c, n) == (not any(bits[c - 2:c - 2 + n]))
                assert m.is_free(c) == (not bits[c - 2])


def test_probe_and_backup_boot(tmp_path):
    img = make(tmp_path)
    src = FileSource(str(img))
    info = ExfatReader.probe(src)
    assert info["fstype"] == "exfat" and info["label"] == "TEST" and info["boot"] == "main" and info["checksum_ok"]
    assert info["size"] == 32 * MiB and info["block_size"] == info["cluster_size"]
    assert info["free"] > 0 and info["used"] > 0
    if shutil.which("blkid"):
        assert info["uuid"] == imagekit.sh("blkid", "-o", "value", "-s", "UUID", img).strip()
    r = ExfatReader(src, info)
    ents, paths = listing(r)
    system = {e.name for e in ents if e.flags & F_SYSTEM}
    assert system == {"$AllocationBitmap", "$UpcaseTable"}
    assert sum(n for _o, n in r.free_extents()) == info["free"]
    raw = bytearray(img.read_bytes())
    # a damaged main boot region (one byte in an extended boot sector breaks its checksum): the backup is used
    raw[600] ^= 0xFF
    src2, r2 = open_reader(bytes(raw))
    assert r2.info["boot"] == "backup" and r2.info["checksum_ok"] and r2.label == "TEST"
    # no main boot sector at all
    raw[0:512] = bytes(512)
    src3, r3 = open_reader(bytes(raw))
    assert r3.info["boot"] == "backup" and len(listing(r3)[0]) == len(ents)


def test_live_and_deleted(tmp_path):
    img = make(tmp_path)
    cs = ExfatReader.probe(FileSource(str(img)))["cluster_size"]
    long_name = "A really long file name " + "x" * 180 + ".txt"
    files = {
        "empty.txt": b"",
        "one.bin": payload(1, 1),
        "almost.bin": payload(cs - 1, 2),
        "exact.bin": payload(cs, 3),
        "over.bin": payload(cs + 1, 4),
        "Ünïcødé – файл 名前.txt": payload(777, 5),
        long_name: payload(3000, 6),
        "Documents/Projects/2024/report final (v2).pdf": payload(5000, 7),
        "DCIM/100CANON/IMG_0001.JPG": payload(3 * MiB + 5, 8),
        "DCIM/100CANON/IMG_0002.JPG": payload(200_000, 9),
        "DCIM/101CANON/IMG_0101.JPG": payload(123_456, 10),
        "keep/kept.txt": payload(10, 11),
    }
    stamp = 1_700_000_000
    with mounted(img, tmp_path / "mnt") as mnt:
        write_files(mnt, files, stamp)
    src, r = open_reader(img)
    ents, paths = listing(r)
    live = by_path(ents, paths, deleted=False)
    for rel, data in files.items():
        e = live[rel]
        assert e.size == len(data) and e.chance == CHANCE_GOOD and content(src, e) == data, rel
        assert e.mtime == stamp and e.crtime is not None, rel
    for d in ("Documents/Projects/2024", "DCIM/100CANON", "keep"):
        assert live[d].is_dir and live[d].size == 0 and live[d].runs is None
    tsk = tsk_paths(img)
    if tsk is not None:
        assert set(live) == tsk[0]

    gone = ["one.bin", "over.bin", "Ünïcødé – файл 名前.txt", long_name]
    with mounted(img, tmp_path / "mnt") as mnt:
        for rel in gone:
            (mnt / rel).unlink()
        shutil.rmtree(mnt / "DCIM")
        shutil.rmtree(mnt / "Documents")
    src, r = open_reader(img)
    ents, paths = listing(r)
    live = by_path(ents, paths, deleted=False)
    dead = by_path(ents, paths, deleted=True)
    assert set(live) == {"empty.txt", "almost.bin", "exact.bin", "keep", "keep/kept.txt"}
    for rel in gone + [k for k in files if k.startswith(("DCIM/", "Documents/"))]:
        e = dead[rel]
        assert e.size == len(files[rel]) and e.chance == CHANCE_GOOD, rel
        assert content(src, e) == files[rel], rel
        assert e.mtime == stamp
    for d in ("DCIM", "DCIM/100CANON", "DCIM/101CANON", "Documents/Projects/2024"):
        assert dead[d].is_dir and dead[d].deleted
    assert not any(e.deleted for e in r.entries(deleted=False))
    if tsk is not None:
        assert (set(live), set(dead)) == tsk_paths(img)


def test_fragmented_and_contiguous(tmp_path):
    img = make(tmp_path)
    a, b, c = payload(5000, 1), payload(70000, 2), payload(50000, 3)
    with mounted(img, tmp_path / "mnt") as mnt:
        write_files(mnt, {"a.bin": a, "b.bin": b})
        (mnt / "a.bin").unlink()
        write_files(mnt, {"c.bin": c})                 # fills a's hole, then goes on after b: a FAT chain
    src, r = open_reader(img)
    ents, paths = listing(r)
    live = by_path(ents, paths, deleted=False)
    assert live["b.bin"].extra["contiguous"] and not live["c.bin"].extra["contiguous"]
    assert len(live["c.bin"].runs) >= 2
    assert content(src, live["b.bin"]) == b and content(src, live["c.bin"]) == c

    # delete c the way Windows does (in-use bits and bitmap cleared, FAT chain kept): the chain is followed
    e = live["c.bin"]
    raw = bytearray(img.read_bytes())
    secondary = raw[e.key + 1]
    for k in range(secondary + 1):
        raw[e.key + 32 * k] &= 0x7F
    bm = next(x for x in ents if x.name == "$AllocationBitmap")
    for off, n in e.runs:
        for k in range(-(-n // r.cs)):
            c_no = (off - r.heap_offset) // r.cs + 2 + k
            raw[bm.runs[0][0] + (c_no - 2) // 8] &= ~(1 << ((c_no - 2) % 8)) & 0xFF
    src2, r2 = open_reader(bytes(raw))
    ents2, paths2 = listing(r2)
    d = by_path(ents2, paths2, deleted=True)["c.bin"]
    assert d.chance == CHANCE_GOOD and d.extra["checksum_ok"] and content(src2, d) == c

    # exfat-fuse zeroes the chain when it deletes: then the guess runs into b's clusters and says so
    with mounted(img, tmp_path / "mnt") as mnt:
        (mnt / "c.bin").unlink()
    src3, r3 = open_reader(img)
    ents3, paths3 = listing(r3)
    d3 = by_path(ents3, paths3, deleted=True)["c.bin"]
    assert d3.chance != CHANCE_GOOD


def test_valid_data_length(tmp_path):
    img = make(tmp_path)
    data = payload(20000, 4)
    with mounted(img, tmp_path / "mnt") as mnt:
        write_files(mnt, {"v.bin": data})
    raw = bytearray(img.read_bytes())
    src, r = open_reader(bytes(raw))
    e = by_path(*listing(r))["v.bin"]
    # pretend only the first 6000 bytes were ever written: the rest must read as zeros
    struct.pack_into("<Q", raw, e.key + 32 + 8, 6000)
    src2, r2 = open_reader(bytes(raw))
    e2 = by_path(*listing(r2))["v.bin"]
    assert content(src2, e2) == data[:6000] + bytes(14000)


def test_fuzz_never_raises(tmp_path):
    img = make(tmp_path)
    files = {f"D{i}/sub folder {i}/file number {j}.bin": payload(1500 * j + 1, i * 7 + j)
             for i in range(3) for j in range(3)}
    with mounted(img, tmp_path / "mnt") as mnt:
        write_files(mnt, files)
        shutil.rmtree(mnt / "D1")
    base = img.read_bytes()
    info = ExfatReader.probe(BytesSource(base))
    lo = info["fat_offset"]
    hi = info["heap_offset"] + 40 * info["cluster_size"]       # FAT, bitmap, up-case table, root, folders
    rnd = random.Random(99)
    for _round in range(25):
        raw = bytearray(base)
        for _ in range(rnd.choice((5, 50, 400))):
            raw[rnd.randrange(lo, hi)] = rnd.randrange(256)
        if rnd.random() < 0.3:
            pos = rnd.randrange(lo, hi - 512) & ~511
            raw[pos:pos + 512] = rnd.randbytes(512)
        src = BytesSource(bytes(raw))
        r = ExfatReader(src, ExfatReader.probe(src) or info)
        ents, _paths = listing(r)
        for e in ents[:40]:
            if not e.is_dir:
                content(src, e)
        r.free_extents()
