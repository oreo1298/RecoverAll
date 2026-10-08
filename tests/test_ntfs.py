"""NTFS reader tests against images written by mkfs.ntfs and ntfs-3g (existing, deleted, compressed, fragmented,
sparse files, streams, links), plus the boot-sector-less reconstruction and a little fuzzing."""

from __future__ import annotations

import contextlib
import os
import random
import shutil
import struct
import subprocess
import time
from pathlib import Path

import imagekit
import pytest
from imagekit import MiB, payload
from test_ntfs_codecs import wof_stream

from recoverall.core.blockio import BytesSource, FileSource
from recoverall.core.fs import base as fsbase
from recoverall.core.fs.base import (
    CHANCE_GOOD,
    CHANCE_POOR,
    F_ADS,
    F_COMPRESSED,
    F_HARDLINK,
    F_ORPHAN,
    F_RESIDENT,
    F_SPARSE,
    F_SYMLINK,
    F_SYSTEM,
    read_content,
    read_head,
)
from recoverall.core.fs.ntfs import (
    MftDetector,
    NtfsReader,
    bitmap_free_runs,
    parse_boot,
)

# ---------------------------------------------------------------------- building the test volume


@contextlib.contextmanager
def ntfs3g(img: Path, mnt: Path, options: str = "compression,streams_interface=windows"):
    """Mount IMG with ntfs-3g and OPTIONS (imagekit.fuse_mount takes no options), or skip."""
    imagekit.need("ntfs-3g")
    if not os.path.exists("/dev/fuse"):
        pytest.skip("no /dev/fuse")
    mnt.mkdir(parents=True, exist_ok=True)
    try:
        imagekit.sh("ntfs-3g", "-o", options, img, mnt)
    except RuntimeError as exc:
        pytest.skip(f"ntfs-3g can't mount here: {exc}")
    try:
        yield mnt
    finally:
        os.sync()
        for _ in range(25):
            if subprocess.run(["umount", str(mnt)], capture_output=True).returncode == 0:
                break
            if subprocess.run(["fusermount", "-u", str(mnt)], capture_output=True).returncode == 0:
                break
            time.sleep(0.2)
        time.sleep(0.1)


def text(n: int, word: str = "line") -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += f"{word} {i} of a compressible text file, more or less the same every time\n".encode()
        i += 1
    return bytes(out[:n])


def write(root: Path, rel: str, data: bytes) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


class Volume:
    def __init__(self, img: Path):
        self.img = img
        self.files: dict[str, bytes] = {}        # existing regular files (and streams "file:stream")
        self.deleted: dict[str, bytes] = {}
        self.deleted_dirs: list[str] = []
        self.chess: dict[str, bytes] = {}         # deleted, some of them overwritten since


FRAG1 = "frag1 " + "with a long name " * 14 + ".bin"
FRAG2 = "frag2 " + "with a long name " * 14 + ".bin"


def fill(path: Path, keep: int = 0) -> int:
    """Write zeros to PATH until the volume is full, then give back KEEP bytes. Returns the file's size."""
    n = 0
    with open(path, "wb", buffering=0) as fh:
        for piece in (1 << 20, 1 << 16, 4096):
            z = bytes(piece)
            while True:
                try:
                    fh.write(z)
                except OSError:
                    break
                n += piece
        n = max(0, n - keep)
        os.ftruncate(fh.fileno(), n)
    return n


def prepare_fragments(m: Path, vol: Volume) -> None:
    """Fill the volume (leaving a little room) and create many files: the MFT has to grow into that room, a
    second extent. Before that, a striped area of one-cluster files; then fill the rest."""
    for i in range(400):
        write(m, f"chess/c{i:03d}", payload(4096, 1000 + i))
        vol.files[f"chess/c{i:03d}"] = payload(4096, 1000 + i)
    vol.files["filler.bin"] = bytes(fill(m / "filler.bin", keep=2 * MiB))
    for i in range(150):
        write(m, f"many/f{i:03d}.txt", f"small file {i}\n".encode())
        vol.files[f"many/f{i:03d}.txt"] = f"small file {i}\n".encode()
    vol.files["filler2.bin"] = bytes(fill(m / "filler2.bin", keep=16 * 4096))


def fragment(m: Path, vol: Volume, holes: list[str]) -> None:
    """Free every other cluster of the striped area (HOLES, chosen by cluster order) and write two files in
    turns, 4 KiB at a time, so they land in the single-cluster holes. Their long names leave little room in the
    MFT record, so the runlists spill into extension records ($ATTRIBUTE_LIST). The striped files that were
    deleted are partly overwritten by them (POOR chance)."""
    for rel in holes:
        os.unlink(m / rel)
        vol.chess[rel] = vol.files.pop(rel)
    fa = os.open(m / FRAG1, os.O_WRONLY | os.O_CREAT)
    fb = os.open(m / FRAG2, os.O_WRONLY | os.O_CREAT)
    a, b = payload(80 * 4096, 10), payload(80 * 4096, 11)
    for i in range(80):
        os.write(fa, a[i * 4096:(i + 1) * 4096])
        os.write(fb, b[i * 4096:(i + 1) * 4096])
    os.close(fa)
    os.close(fb)
    vol.files[FRAG1] = a
    vol.files[FRAG2] = b


def build(tmp: Path) -> Volume:
    img = tmp / "ntfs.img"
    imagekit.mkfs(img, "ntfs", size=64 * MiB, label="RallTest")
    vol = Volume(img)
    f = vol.files
    d = vol.deleted
    with ntfs3g(img, tmp / "mnt") as m:
        f["empty.txt"] = b""
        f["tiny.txt"] = b"tiny resident file\n"
        f["Docs/Résumé 履歴書.txt"] = payload(3000, 2)
        f["Ünïcödé/файл 😀.bin"] = payload(50_000, 3)
        f["big.bin"] = payload(3 * MiB, 4)
        f["Docs/Sub/deep.txt"] = payload(1234, 5)
        f["Compressed/text.txt"] = text(600_000)
        f["Compressed/random.bin"] = payload(150_000, 9)
        f["Compressed/mixed.bin"] = bytes(200_000) + text(70_000, "mixed")
        d["Compressed/del.txt"] = text(100_000, "deleted")
        f["ads.txt"] = b"main content"
        d["Docs/deleteme.bin"] = payload(500_000, 12)
        d["tiny_deleted.txt"] = b"short and deleted"
        d["DelFolder/a.txt"] = payload(20_000, 13)
        d["DelFolder/sub/b.bin"] = payload(100_000, 14)
        d["DelFolder/sub/c.txt"] = b"resident in a deleted folder"
        (m / "Compressed").mkdir()
        os.setxattr(m / "Compressed", "system.ntfs_attrib_be", struct.pack(">I", 0x800))
        for rel, data in list(f.items()) + list(d.items()):
            write(m, rel, data)
        # alternate data streams (streams_interface=windows: "file:stream" opens the stream)
        f["ads.txt:small"] = b"small stream"
        f["ads.txt:big"] = payload(200_000, 8)
        (m / "ads.txt:small").write_bytes(f["ads.txt:small"])
        (m / "ads.txt:big").write_bytes(f["ads.txt:big"])
        # a sparse file: data, a 3 MiB hole, data
        with open(m / "sparse.bin", "wb") as fh:
            fh.write(payload(65536, 6))
            fh.seek(3 * MiB)
            fh.write(payload(65536, 7))
        f["sparse.bin"] = payload(65536, 6) + bytes(3 * MiB - 65536) + payload(65536, 7)
        os.symlink("tiny.txt", m / "link_to_tiny")
        os.link(m / "Docs/Sub/deep.txt", m / "Ünïcödé/deep-link.txt")
        f["Ünïcödé/deep-link.txt"] = f["Docs/Sub/deep.txt"]
        prepare_fragments(m, vol)
    # which striped files to delete: every other one in cluster order (ntfs-3g spreads new files over two zones)
    stripes = sorted((e.runs[0][0], e.name) for e in NtfsReader(FileSource(str(img))).entries()
                     if len(e.name) == 4 and e.name[0] == "c" and e.name[1:].isdigit() and not e.deleted)
    holes = [f"chess/{name}" for _off, name in stripes[::2]]
    with ntfs3g(img, tmp / "mnt") as m:
        fragment(m, vol, holes)
        os.sync()
        # deletions last, so nothing reuses their clusters
        for rel in ("Compressed/del.txt", "Docs/deleteme.bin", "tiny_deleted.txt"):
            os.unlink(m / rel)
        shutil.rmtree(m / "DelFolder")
        vol.deleted_dirs = ["DelFolder", "DelFolder/sub"]
    return vol


@pytest.fixture(scope="module")
def vol(tmp_path_factory) -> Volume:
    imagekit.need("mkfs.ntfs", "ntfs-3g")
    return build(tmp_path_factory.mktemp("ntfs"))


def listing(reader: NtfsReader, deleted: bool = True):
    ents = list(reader.entries(deleted=deleted))
    by = {e.key: e for e in ents}

    def path(e):
        parts = []
        for _ in range(64):
            if e.parent is None:
                break
            parts.append(e.name)
            e = by[e.parent]
        return "/".join(reversed(parts))

    paths: dict[tuple[str, bool], object] = {}
    for e in ents:
        if e.key == reader.root_key:
            continue
        if e.parent is not None:
            assert e.parent in by, f"{e.name}: parent {e.parent} isn't listed"
        p = path(e) if e.parent is not None else "?/" + e.name
        paths[(p, e.deleted)] = e
    return ents, paths


def content(src, e) -> bytes:
    return b"".join(read_content(src, e))


# ---------------------------------------------------------------------- tests on the real image
def test_probe_and_listing(vol):
    src = FileSource(str(vol.img))
    info = NtfsReader.probe(src)
    assert info["fstype"] == "ntfs" and info["boot"] == "primary"
    assert info["label"] == "RallTest"
    assert info["size"] == 64 * MiB
    assert info["cluster_size"] == 4096 and info["record_size"] == 1024
    assert info["version"] == "3.1"
    assert 0 < info["used"] < info["size"] and info["used"] + info["free"] <= info["size"]
    r = NtfsReader(src, info)
    ents, paths = listing(r)
    keys = [e.key for e in ents]
    assert ents[0].key == 5 and ents[0].parent is None and ents[0].is_dir and ents[0].name == ""
    assert len(keys) == len(set(keys))
    for rel, data in vol.files.items():
        e = paths.get((rel, False))
        assert e is not None, rel
        assert e.size == len(data), rel
        assert e.chance == CHANCE_GOOD, rel
        assert content(src, e) == data, rel
    for d in ("Docs", "Docs/Sub", "Ünïcödé", "Compressed", "many"):
        assert paths[(d, False)].is_dir
    assert not r.warnings, r.warnings


def test_deleted_files(vol):
    src = FileSource(str(vol.img))
    r = NtfsReader(src)
    _ents, paths = listing(r)
    for rel, data in vol.deleted.items():
        e = paths.get((rel, True))
        assert e is not None, rel
        assert e.deleted and e.size == len(data), rel
        assert e.chance == CHANCE_GOOD, rel
        assert content(src, e) == data, rel
    for rel in vol.deleted_dirs:
        assert paths[(rel, True)].is_dir
    # the striped files: some of their clusters went to the fragmented files since
    chess = [(e, vol.chess[rel]) for (rel, dele), e in paths.items() if dele and rel in vol.chess]
    assert len(chess) > 20
    assert any(e.chance == CHANCE_POOR for e, _d in chess)
    for e, data in chess:
        assert e.chance == CHANCE_POOR or content(src, e) == data, e.name
    # nothing that exists is listed as deleted (and the other way round)
    assert not any(p in vol.files for (p, dele) in paths if dele)
    # existing-only listing
    _e2, live = listing(NtfsReader(src), deleted=False)
    assert not any(dele for (_p, dele) in live)
    assert ("Docs/deleteme.bin", True) not in live


def test_special_files(vol):
    src = FileSource(str(vol.img))
    r = NtfsReader(src)
    _ents, paths = listing(r)
    comp = paths[("Compressed/text.txt", False)]
    assert comp.flags & F_COMPRESSED and comp.extra["decoder"] == "lznt1"
    assert sum(n for o, n in comp.runs if o >= 0) < len(vol.files["Compressed/text.txt"]) // 2
    assert paths[("Compressed/del.txt", True)].flags & F_COMPRESSED
    assert paths[("sparse.bin", False)].flags & F_SPARSE
    assert paths[("tiny.txt", False)].flags & F_RESIDENT
    small = paths[("ads.txt:small", False)]
    assert small.flags & F_ADS and small.key == f"{paths[('ads.txt', False)].key}:small"
    link = paths[("link_to_tiny", False)]
    assert link.flags & F_SYMLINK and content(src, link) == b"tiny.txt"
    a = paths[("Docs/Sub/deep.txt", False)]
    b = paths[("Ünïcödé/deep-link.txt", False)]
    assert (a.flags ^ b.flags) & F_HARDLINK
    hard = a if a.flags & F_HARDLINK else b
    first = b if hard is a else a
    assert hard.key == f"{first.key}#1"
    frag = paths[(FRAG1, False)]
    assert len(frag.runs) > 40
    assert r.record(frag.key).alist is not None, "the test file should need an attribute list"
    assert r.record(paths[(FRAG2, False)].key).alist is not None
    mft = paths[("$MFT", False)]
    assert mft.flags & F_SYSTEM and mft.key == 0 and len(mft.runs) >= 2, "the MFT should have grown"
    assert paths[("$Extend/$Quota", False)].flags & F_SYSTEM
    assert not paths[("big.bin", False)].flags & F_SYSTEM


def test_matches_sleuthkit(vol):
    imagekit.need("fls")
    out = imagekit.sh("fls", "-r", "-p", "-l", vol.img)
    tsk = {}
    for line in out.splitlines():
        kind, _, rest = line.partition(":\t")
        cols = rest.split("\t")
        if not kind.startswith("r/r") or "*" in kind or len(cols) < 6 or "$" in cols[0]:
            continue
        tsk[cols[0]] = int(cols[5])
    _ents, paths = listing(NtfsReader(FileSource(str(vol.img))))
    ours = {p: e.size for (p, dele), e in paths.items()
            if not dele and not e.is_dir and not e.flags & (F_SYSTEM | F_SYMLINK)}
    assert ours == {p: n for p, n in tsk.items() if p != "link_to_tiny"}


def test_free_extents(vol):
    src = FileSource(str(vol.img))
    r = NtfsReader(src)
    free = r.free_extents()
    info = NtfsReader.probe(src)
    assert sum(n for _o, n in free) == info["free"]
    ents, _paths = listing(r, deleted=False)
    used = fsbase.ExtentMap([run for e in ents for run in (e.runs or []) if run[0] >= 0])
    assert all(used.overlap(o, n) == 0 for o, n in free)


def test_backup_boot_sector(vol, tmp_path):
    img = tmp_path / "noboot.img"
    shutil.copy(vol.img, img)
    with open(img, "r+b") as fh:
        fh.write(bytes(512))
    primary = parse_boot(FileSource(str(vol.img)).read(0, 512))
    src = FileSource(str(img))
    assert parse_boot(src.read(0, 512)) is None
    info = NtfsReader.probe(src)
    assert info["boot"] == "backup"
    for k in ("cluster_size", "record_size", "mft_offset", "mftmirr_offset", "size", "serial"):
        assert info[k] == primary[k], k
    _ents, paths = listing(NtfsReader(src, info))
    assert ("big.bin", False) in paths and ("Docs/deleteme.bin", True) in paths


def test_overwritten_clusters_are_poor(vol, tmp_path):
    """Mark a deleted file's clusters as in use in $Bitmap: as if another file had taken them."""
    src = FileSource(str(vol.img))
    r = NtfsReader(src)
    _ents, paths = listing(r)
    victim = paths[("Docs/deleteme.bin", True)]
    bm = paths[("$Bitmap", False)]
    cs = r.cs
    img = tmp_path / "reused.img"
    shutil.copy(vol.img, img)
    lcn = victim.runs[0][0] // cs
    assert bm.runs[0][1] > lcn // 8
    with open(img, "r+b") as fh:
        boff = bm.runs[0][0] + lcn // 8
        fh.seek(boff)
        b = fh.read(1)[0]
        fh.seek(boff)
        fh.write(bytes([b | (1 << (lcn % 8))]))
    _e2, p2 = listing(NtfsReader(FileSource(str(img))))
    assert p2[("Docs/deleteme.bin", True)].chance == CHANCE_POOR
    assert p2[("tiny_deleted.txt", True)].chance == CHANCE_GOOD


def test_windows_style_deletion(vol, tmp_path):
    """Windows deletes a file by clearing the in-use flag of its records (extension records too), bumping the
    sequence number and freeing its clusters; the attributes stay. (ntfs-3g also strips the names, so this is
    done by hand here.) A fragmented file deleted that way comes back whole, with its name."""
    src = FileSource(str(vol.img))
    r = NtfsReader(src)
    _ents, paths = listing(r)
    e = paths[(FRAG2, False)]
    base = r.record(e.key)
    ext = sorted({ref for _t, _n, _v, ref, _s, _a in r._alist_entries(base.alist) if ref != e.key})
    assert ext
    bm = paths[("$Bitmap", False)]
    img = tmp_path / "windel.img"
    shutil.copy(vol.img, img)
    with open(img, "r+b") as fh:
        for num in [e.key] + ext:
            off = r.record_offset(num)
            fh.seek(off + 0x10)
            seq, _links, _aofs, flags = struct.unpack("<HHHH", fh.read(8))
            fh.seek(off + 0x10)
            fh.write(struct.pack("<H", seq + 1 if num == e.key else seq))
            fh.seek(off + 0x16)
            fh.write(struct.pack("<H", flags & ~1))
        for o, n in e.runs:
            for lcn in range(o // r.cs, (o + n) // r.cs):
                fh.seek(bm.runs[0][0] + lcn // 8)
                b = fh.read(1)[0]
                fh.seek(-1, 1)
                fh.write(bytes([b & ~(1 << (lcn % 8))]))
    s2 = FileSource(str(img))
    _e2, p2 = listing(NtfsReader(s2))
    d = p2[(FRAG2, True)]
    assert d.chance == CHANCE_GOOD and content(s2, d) == vol.files[FRAG2]
    assert (FRAG2, False) not in p2


def _volume_without_boot(vol, tmp_path) -> tuple[Path, int, int]:
    """The volume with both boot sectors zeroed, inside a bigger disk image at an odd (but sector-aligned)
    offset."""
    size = vol.img.stat().st_size
    offset = 1 * MiB + 63 * 512
    disk = tmp_path / "disk.img"
    imagekit.blank(disk, offset + size + 3 * MiB)
    imagekit.embed(disk, vol.img, offset)
    with open(disk, "r+b") as fh:
        fh.seek(offset)
        fh.write(bytes(512))
        fh.seek(offset + size - 512)
        fh.write(bytes(512))
    return disk, offset, size


def test_mft_detector_reconstructs_volume(vol, tmp_path):
    disk, offset, size = _volume_without_boot(vol, tmp_path)
    src = FileSource(str(disk))
    assert NtfsReader.probe(src.region(offset, size)) is None
    det = MftDetector()
    for pos, buf in src.read_into_chunks(0, chunk=3 * MiB + 512 * 7):
        det.feed(pos, buf)
    cands = sorted(det.finish(), key=lambda c: -c["score"])
    assert cands, "no candidate"
    best = cands[0]
    assert best["offset"] == offset and best["fstype"] == "ntfs"
    assert best["label"] == "RallTest"
    assert size - 4096 <= best["size"] <= size
    assert best["score"] >= 70
    info = best["info"]
    assert info["reconstructed"] and info["cluster_size"] == 4096 and info["record_size"] == 1024
    assert len({c["offset"] for c in cands}) == len(cands)
    vsrc = src.region(best["offset"], best["size"])
    r = NtfsReader(vsrc, info)
    _ents, paths = listing(r)
    for rel, data in list(vol.files.items())[:20] + list(vol.deleted.items()):
        e = paths.get((rel, False)) or paths.get((rel, True))
        assert e is not None, rel
        assert content(vsrc, e) == data, rel


def test_detector_with_only_the_mirror(vol, tmp_path):
    """Boot sectors and the MFT's first 16 records destroyed: the $MFTMirr copy of record 0 still places the
    volume, and the reader finds the MFT through it."""
    disk, offset, size = _volume_without_boot(vol, tmp_path)
    info = NtfsReader.probe(FileSource(str(vol.img)))
    with open(disk, "r+b") as fh:
        fh.seek(offset + info["mft_offset"])
        fh.write(bytes(16 * info["record_size"]))
    src = FileSource(str(disk))
    det = MftDetector()
    for pos, buf in src.read_into_chunks(0, chunk=4 * MiB):
        det.feed(pos, buf)
    best = max(det.finish(), key=lambda c: c["score"])
    assert best["offset"] == offset
    vsrc = src.region(offset, best["size"])
    r = NtfsReader(vsrc, best["info"])
    _ents, paths = listing(r)
    assert any("$MFTMirr" in w for w in r.warnings)
    assert content(vsrc, paths[("big.bin", False)]) == vol.files["big.bin"]
    assert content(vsrc, paths[("Docs/deleteme.bin", True)]) == vol.deleted["Docs/deleteme.bin"]


def test_detector_chunking_is_irrelevant(vol):
    """Record 0 near a chunk boundary: the look-ahead is carried over to the next chunk."""
    data = vol.img.read_bytes()
    src = BytesSource(data)
    info = NtfsReader.probe(src)
    for split in (info["mft_offset"] + 1024, info["mft_offset"] + 512 * 3):
        det = MftDetector()
        det.feed(0, data[:split])
        det.feed(split, data[split:])
        best = max(det.finish(), key=lambda c: c["score"])
        assert best["offset"] == 0 and best["info"]["mft_offset"] == info["mft_offset"]


def test_corrupted_mft_never_raises(vol):
    data = bytearray(vol.img.read_bytes())
    info = NtfsReader.probe(BytesSource(bytes(data)))
    start = info["mft_offset"]
    span = 256 * 1024
    for seed in range(6):
        rnd = random.Random(seed)
        buf = bytearray(data)
        if seed % 2:
            for _ in range(4000):
                buf[start + rnd.randrange(span)] = rnd.randrange(256)
        else:
            for _ in range(40):               # whole records of garbage, with a FILE signature kept
                p = start + rnd.randrange(span // 1024) * 1024
                buf[p:p + 1024] = b"FILE" + rnd.randbytes(1020)
        src = BytesSource(bytes(buf))
        r = NtfsReader(src, info)
        ents = list(r.entries())
        keys = [e.key for e in ents]
        assert len(keys) == len(set(keys))
        for e in ents:
            read_head(src, e, 4096)
        det = MftDetector()
        det.feed(0, bytes(buf[:start + span]))
        det.finish()


# ---------------------------------------------------------------------- a second volume: 512-byte clusters
def test_small_clusters(tmp_path):
    """Clusters smaller than an MFT record (each record spans two clusters); compression units of 8 KiB."""
    imagekit.need("mkfs.ntfs", "ntfs-3g")
    img = tmp_path / "c512.img"
    imagekit.mkfs(img, "ntfs", size=16 * MiB, label="Small", extra=["-c", "512"])
    files = {"a.bin": payload(70_000, 21), "Comp/t.txt": text(90_000), "Comp/r.bin": payload(40_000, 22)}
    gone = {"x.bin": payload(30_000, 23), "Comp/gone.txt": text(50_000, "gone")}
    with ntfs3g(img, tmp_path / "m") as m:
        (m / "Comp").mkdir()
        os.setxattr(m / "Comp", "system.ntfs_attrib_be", struct.pack(">I", 0x800))
        for rel, data in list(files.items()) + list(gone.items()):
            write(m, rel, data)
        for i in range(80):
            write(m, f"n/{i}", b"x" * i)
        os.sync()
        for rel in gone:
            os.unlink(m / rel)
    src = FileSource(str(img))
    r = NtfsReader(src)
    assert r.cs == 512 and r.rs == 1024
    _ents, paths = listing(r)
    for rel, data in files.items():
        assert content(src, paths[(rel, False)]) == data, rel
    for rel, data in gone.items():
        e = paths[(rel, True)]
        assert e.chance == CHANCE_GOOD and content(src, e) == data, rel
    assert paths[("Comp/t.txt", False)].extra["cu"] == 16


# ---------------------------------------------------------------------- format details without images
def test_parse_boot_fields():
    b = bytearray(512)
    b[3:11] = b"NTFS    "
    struct.pack_into("<HB", b, 0x0B, 512, 0xF7)                 # 2**9 sectors: 256 KiB clusters
    struct.pack_into("<QQQ", b, 0x28, 2 ** 30 - 1, 12, 2)
    b[0x40] = 0xF6                                               # -10: 1024-byte records
    b[0x44] = 1                                                  # one cluster per index record
    struct.pack_into("<Q", b, 0x48, 0x1122334455667788)
    b[510:512] = b"\x55\xaa"
    info = parse_boot(bytes(b))
    assert info["cluster_size"] == 256 * 1024 and info["record_size"] == 1024
    assert info["index_size"] == 256 * 1024 and info["size"] == 2 ** 30 * 512
    assert info["mft_offset"] == 12 * 256 * 1024 and info["uuid"] == "1122334455667788"
    for bad in ((0x0B, b"\x00\x03"), (0x0D, b"\x03"), (510, b"\x00\x00"), (0x40, b"\x00")):
        c = bytearray(b)
        c[bad[0]:bad[0] + len(bad[1])] = bad[1]
        assert parse_boot(bytes(c)) is None


def test_bitmap_free_runs():
    bm = bytes([0b11110000, 0x00, 0x00, 0b00000001, 0xFF, 0b10111101])
    runs = bitmap_free_runs(bm, 46)
    bits = "".join(f"{b:08b}"[::-1] for b in bm)[:46]
    expect = []
    i = 0
    while i < 46:
        if bits[i] == "0":
            j = i
            while j < 46 and bits[j] == "0":
                j += 1
            expect.append((i, j - i))
            i = j
        else:
            i += 1
    assert runs == expect


def test_garbage_is_not_ntfs():
    assert NtfsReader.probe(BytesSource(bytes(1 << 20))) is None
    assert NtfsReader.probe(BytesSource(random.Random(3).randbytes(1 << 16))) is None
    det = MftDetector()
    det.feed(0, random.Random(4).randbytes(4 * MiB))
    assert det.finish() == []


def test_orphans_and_reused_parents(vol, tmp_path):
    """A deleted file whose folder record was reused by something else is an orphan with its name kept."""
    src = FileSource(str(vol.img))
    r = NtfsReader(src)
    _ents, paths = listing(r)
    folder = paths[("DelFolder/sub", True)]
    img = tmp_path / "reused.img"
    shutil.copy(vol.img, img)
    # bump the folder record's sequence number (at 0x10) by 5: as if the record now held another folder
    off = r._mft_runs[0][0] + folder.key * r.rs
    assert r._mft_runs[0][1] > folder.key * r.rs
    with open(img, "r+b") as fh:
        fh.seek(off + 0x10)
        seq = struct.unpack("<H", fh.read(2))[0]
        fh.seek(off + 0x10)
        fh.write(struct.pack("<H", seq + 5))
    _e2, p2 = listing(NtfsReader(FileSource(str(img))))
    b = p2[("?/b.bin", True)]
    assert b.flags & F_ORPHAN and b.parent is None
    assert content(src, b) == vol.deleted["DelFolder/sub/b.bin"]


# ---------------------------------------------------------------------- hand-made MFT records
def _attr(atype: int, value: bytes = b"", name: str = "", aid: int = 0, runs: bytes | None = None, size: int = 0,
          alloc: int = 0, flags: int = 0, vcn: int = 0, last: int | None = None) -> bytes:
    """One attribute: resident with VALUE, or non-resident with the runlist RUNS."""
    nb = name.encode("utf-16-le")
    if runs is None:
        noff = 24
        voff = (noff + len(nb) + 7) & ~7
        total = (voff + len(value) + 7) & ~7
        b = bytearray(total)
        struct.pack_into("<IIBBHHH", b, 0, atype, total, 0, len(name), noff, flags, aid)
        struct.pack_into("<IH", b, 16, len(value), voff)
        b[voff:voff + len(value)] = value
    else:
        noff = 0x40
        roff = (noff + len(nb) + 7) & ~7
        total = (roff + len(runs) + 1 + 7) & ~7
        b = bytearray(total)
        clusters = alloc // 4096
        struct.pack_into("<IIBBHHH", b, 0, atype, total, 1, len(name), noff, flags, aid)
        struct.pack_into("<QQHH4xQQQ", b, 16, vcn, clusters - 1 if last is None else last, roff, 0, alloc, size,
                         size)
        b[roff:roff + len(runs)] = runs
    b[noff:noff + len(nb)] = nb
    return bytes(b)


def _runlist(runs: list[tuple[int, int]]) -> bytes:
    out = bytearray()
    prev = 0
    for lcn, n in runs:
        ln = (n.bit_length() + 7) // 8
        if lcn < 0:
            out += bytes([ln]) + n.to_bytes(ln, "little")
            continue
        delta = lcn - prev
        lo = 1
        while not -(1 << (8 * lo - 1)) <= delta < (1 << (8 * lo - 1)):
            lo += 1
        out += bytes([ln | lo << 4]) + n.to_bytes(ln, "little") + delta.to_bytes(lo, "little", signed=True)
        prev = lcn
    return bytes(out + b"\0")


def _file_name(name: str, parent: int, pseq: int, ns: int = 1, flags: int = 0) -> bytes:
    nb = name.encode("utf-16-le")
    t = 133_000_000_000_000_000
    return struct.pack("<QQQQQQQIIBB", parent | pseq << 48, t, t, t, t, 0, 0, flags, 0, len(name), ns) + nb


def _record(num: int, attrs: list[bytes], flags: int = 1, seq: int = 1, rs: int = 1024, base: int = 0) -> bytes:
    b = bytearray(rs)
    body = b"".join(attrs) + b"\xff\xff\xff\xff\0\0\0\0"
    struct.pack_into("<4sHHQHHHHIIQHHI", b, 0, b"FILE", 0x30, rs // 512 + 1, 0, seq, 1, 0x38, flags,
                     0x38 + len(body), rs, base, len(attrs) + 1, 0, num)
    b[0x38:0x38 + len(body)] = body
    usn = b"\x07\x00"
    b[0x30:0x32] = usn
    for i in range(1, rs // 512 + 1):
        b[0x30 + 2 * i:0x32 + 2 * i] = b[i * 512 - 2:i * 512]
        b[i * 512 - 2:i * 512] = usn
    return bytes(b)


SI = _attr(0x10, struct.pack("<QQQQI", *([133_000_000_000_000_000] * 4), 0x20) + bytes(12))


def _reparse(tag: int, data: bytes) -> bytes:
    return _attr(0xC0, struct.pack("<IHH", tag, len(data), 0) + data)


def _link_data(tag: int, subst: str, printed: str, relative: bool = False) -> bytes:
    s, p = subst.encode("utf-16-le"), printed.encode("utf-16-le")
    head = struct.pack("<HHHH", 0, len(s), len(s), len(p))
    if tag == 0xA000000C:
        head += struct.pack("<I", 1 if relative else 0)
    return head + s + p


def test_hand_made_records(vol, tmp_path):
    """Reparse points (Windows compression, junction, symlinks), a DOS name alias, an orphan and a parent cycle,
    written into the MFT's unused reserved records."""
    src = FileSource(str(vol.img))
    r = NtfsReader(src)
    _ents, paths = listing(r)
    slots = [n for n in range(16, 24) if (x := r.record(n)) is None or (not x.in_use and not x.names)]
    if len(slots) < 8:
        pytest.skip("not enough unused reserved MFT records in this image")
    tiny = paths[("tiny.txt", False)].key
    # the compressed stream goes into free clusters
    wof_data = text(9000, "wof") + payload(2000, 31)
    stream = wof_stream(wof_data)
    free_off, free_len = next((o, n) for o, n in r.free_extents() if n >= len(stream) + 8192)
    lcn = free_off // r.cs
    nclus = -(-len(stream) // r.cs)
    a, b = slots[6], slots[7]
    recs = {
        slots[0]: [SI, _attr(0x30, _file_name("wof.txt", 5, 5)),
                   _attr(0x80, runs=_runlist([(-1, 3)]), size=len(wof_data), alloc=3 * 4096, flags=0x8000, aid=2),
                   _attr(0x80, name="WofCompressedData", runs=_runlist([(lcn, nclus)]), size=len(stream),
                         alloc=nclus * 4096, aid=3),
                   _reparse(0x80000017, struct.pack("<IIII", 1, 2, 1, 0))],
        slots[1]: [SI, _attr(0x30, _file_name("junction", 5, 5)),
                   _reparse(0xA0000003, _link_data(0xA0000003, "\\??\\C:\\Target", "C:\\Target"))],
        slots[2]: [SI, _attr(0x30, _file_name("relative link", 5, 5)),
                   _reparse(0xA000000C, _link_data(0xA000000C, "..\\x\\y", "..\\x\\y", relative=True))],
        slots[3]: [SI, _attr(0x30, _file_name("wsl link", 5, 5)),
                   _reparse(0xA000001D, struct.pack("<I", 2) + b"/usr/bin/x")],
        slots[4]: [SI, _attr(0x30, _file_name("LONGFI~1.TXT", 5, 5, ns=2)),
                   _attr(0x30, _file_name("Long File Name.txt", 5, 5, ns=1)), _attr(0x80, b"hello")],
        slots[5]: [SI, _attr(0x30, _file_name("lost.txt", tiny, 0)), _attr(0x80, b"lost")],
        a: [SI, _attr(0x30, _file_name("cycle A", b, 1))],
        b: [SI, _attr(0x30, _file_name("cycle B", a, 1))],
    }
    img = tmp_path / "planted.img"
    shutil.copy(vol.img, img)
    with open(img, "r+b") as fh:
        for num, attrs in recs.items():
            fh.seek(r.record_offset(num))
            fh.write(_record(num, attrs, flags=3 if num in (slots[1], a, b) else 1))
        fh.seek(lcn * r.cs)
        fh.write(stream)
    s2 = FileSource(str(img))
    r2 = NtfsReader(s2)
    ents, p2 = listing(r2)
    by = {e.key: e for e in ents}
    wof = p2[("wof.txt", False)]
    assert wof.flags & F_COMPRESSED and wof.extra["decoder"] == "xpress"
    assert wof.size == len(wof_data) and content(s2, wof) == wof_data
    assert ("wof.txt:WofCompressedData", False) not in p2
    for name, target in (("junction", b"C:\\Target"), ("relative link", b"../x/y"), ("wsl link", b"/usr/bin/x")):
        e = p2[(name, False)]
        assert e.flags & F_SYMLINK and not e.is_dir and content(s2, e) == target, name
    assert content(s2, p2[("Long File Name.txt", False)]) == b"hello"
    assert not any("LONGFI" in p for p, _d in p2)
    lost = by[slots[5]]
    assert lost.parent is None and lost.flags & F_ORPHAN and lost.name == "lost.txt"
    # the cycle is cut: walking up from either folder ends
    for k in (a, b):
        seen = set()
        e = by[k]
        while e.parent is not None:
            assert e.key not in seen
            seen.add(e.key)
            e = by[e.parent]
        assert e.flags & F_ORPHAN


def test_mft_with_an_attribute_list():
    """A tiny hand-made volume whose MFT is in two pieces, the second one described by an extension record
    (record 16, in the first piece as NTFS keeps it) found through record 0's $ATTRIBUTE_LIST."""
    cs, rs = 4096, 1024
    vol = bytearray(64 * cs)
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<HB", boot, 0x0B, 512, 8)
    struct.pack_into("<QQQ", boot, 0x28, 64 * 8 - 1, 4, 2)
    boot[0x40] = 0xF6
    boot[0x44] = 1
    boot[510:512] = b"\x55\xaa"
    vol[0:512] = boot
    alist = b""
    for atype, vcn, ref, aid in ((0x10, 0, 0, 0), (0x30, 0, 0, 1), (0x80, 0, 0, 2), (0x80, 6, 16, 0)):
        alist += struct.pack("<IHBBQQH", atype, 32, 0, 26, vcn, ref | (1 << 48), aid) + bytes(6)
    mft_size = 32 * rs
    rec0 = _record(0, [SI, _attr(0x20, alist), _attr(0x30, _file_name("$MFT", 5, 5)),
                       _attr(0x80, runs=_runlist([(4, 6)]), size=mft_size, alloc=mft_size, aid=2, last=5)])
    rec16 = _record(16, [_attr(0x80, runs=_runlist([(20, 2)]), size=0, alloc=0, vcn=6, last=7)],
                    base=1 << 48)
    bitmap = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0])
    recs = {0: rec0,
            5: _record(5, [SI, _attr(0x30, _file_name(".", 5, 5)), _attr(0x90, b"\0" * 32, name="$I30")],
                       flags=3, seq=5),
            6: _record(6, [SI, _attr(0x30, _file_name("$Bitmap", 5, 5)), _attr(0x80, bitmap)]),
            16: rec16,
            26: _record(26, [SI, _attr(0x30, _file_name("far.txt", 5, 5)), _attr(0x80, b"far away")]),
            27: _record(27, [SI, _attr(0x30, _file_name("gone.bin", 5, 5)),
                             _attr(0x80, runs=_runlist([(40, 2)]), size=5000, alloc=2 * cs)], flags=0),
            # deleted, its name stripped (ntfs-3g does that): only the content is left
            28: _record(28, [SI, _attr(0x80, runs=_runlist([(40, 2)]), size=5000, alloc=2 * cs)], flags=0)}
    for num, raw in recs.items():
        off = 4 * cs + num * rs if num < 24 else 20 * cs + (num - 24) * rs
        vol[off:off + rs] = raw
    vol[40 * cs:40 * cs + 5000] = payload(5000, 77)
    src = BytesSource(bytes(vol))
    r = NtfsReader(src)
    ents, paths = listing(r)
    assert r._mft_runs == [(4 * cs, 6 * cs), (20 * cs, 2 * cs)]
    assert content(src, paths[("far.txt", False)]) == b"far away"
    gone = paths[("gone.bin", True)]
    assert gone.chance == CHANCE_GOOD and content(src, gone) == payload(5000, 77)
    mft = paths[("$MFT", False)]
    assert mft.size == mft_size and mft.runs == [(4 * cs, 6 * cs), (20 * cs, 2 * cs)]
    assert 16 not in {e.key for e in ents}
    nameless = paths[("?/MFT record 28", True)]
    assert nameless.flags & F_ORPHAN and content(src, nameless) == payload(5000, 77)
    assert not r.warnings, r.warnings
