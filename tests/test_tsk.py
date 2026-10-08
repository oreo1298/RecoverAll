"""The Sleuth Kit engine: listings and content of real images (FAT via mtools, ext4 through a loop mount, NTFS
through ntfs-3g, UFS1 via makefs, an empty APFS container via mkapfs), compared with what was written."""

from __future__ import annotations

import contextlib
import os
import subprocess
import time
from pathlib import Path

import imagekit
import pytest
from imagekit import MiB, blank, mkfs, mount_loop, mtools_copy, mtools_delete, need, payload, sh

from recoverall.core.blockio import BytesSource, ConcatSource, FileSource, open_source
from recoverall.core.errors import NotSupported
from recoverall.core.fs.base import (
    CHANCE_FAIR,
    CHANCE_GOOD,
    F_ADS,
    F_ORPHAN,
    F_SYMLINK,
    F_SYSTEM,
    read_content,
    read_head,
)
from recoverall.core.fs.tsk import TskReader, available, parse_body_line

pytestmark = pytest.mark.skipif(not available(), reason="The Sleuth Kit is not installed")


def paths(entries):
    by = {e.key: e for e in entries}
    out = {}
    for e in entries:
        parts, cur = [], e
        while cur is not None and cur.parent is not None:
            parts.append(cur.name)
            cur = by.get(cur.parent)
        out["/".join(reversed(parts))] = e
    return out


def content(src, e) -> bytes:
    return b"".join(read_content(src, e))


def check_tree(es):
    keys = [e.key for e in es]
    assert len(keys) == len(set(keys))
    assert es[0].key == "root" and es[0].parent is None
    known = set(keys)
    for e in es[1:]:
        assert e.parent is None or e.parent in known, e
        assert e.parent is not None or e.flags & F_ORPHAN


def test_body_line_parsing():
    rec = parse_body_line("0|/a|b c.txt|12|r/rrw-r--r--|0|0|4|1|2|3|4")
    assert rec["name"] == "/a|b c.txt" and rec["inode"] == "12" and rec["size"] == 4 and rec["crtime"] == 4
    assert parse_body_line("0|/new") is None
    assert parse_body_line("0|/x|65-128-2|r/rrwxrwxrwx|48|0|30000|1|2|3|4")["inode"] == "65-128-2"


def test_fat_with_deleted_file(tmp_path, ctl):
    img = mkfs(tmp_path / "fat.img", "fat16", size=32 * MiB, label="TSKFAT")
    files = {"DCIM/IMG_0001.JPG": payload(70_000, 1), "notes.txt": b"some notes\n", "DCIM/IMG_0002.JPG":
             payload(20_000, 2)}
    mtools_copy(img, files)
    mtools_delete(img, "DCIM/IMG_0002.JPG")
    src = FileSource(str(img))
    info = TskReader.probe(src)
    assert info["fstype"] == "fat16" and info["label"] == "TSKFAT" and info["block_size"] == 2048
    r = TskReader(src, info)
    es = list(r.entries(ctl))
    check_tree(es)
    p = paths(es)
    assert content(src, p["DCIM/IMG_0001.JPG"]) == files["DCIM/IMG_0001.JPG"]
    assert content(src, p["notes.txt"]) == files["notes.txt"]
    gone = [e for e in es if e.deleted]
    assert len(gone) == 1 and gone[0].name.endswith("MG_0002.JPG") and gone[0].chance == CHANCE_FAIR
    assert by_parent_name(es, gone[0]) == "DCIM"
    assert content(src, gone[0]) == files["DCIM/IMG_0002.JPG"]      # contiguous: icat -r gets it back
    assert p["$FAT1"].flags & F_SYSTEM
    assert not [e for e in r.entries(deleted=False) if e.deleted]


def by_parent_name(es, e):
    by = {x.key: x for x in es}
    return by[e.parent].name


@pytest.mark.root
def test_ext4_names_links_and_deleted(tmp_path):
    img = mkfs(tmp_path / "e.img", "ext4", size=32 * MiB, label="TSKEXT")
    files = {"d/a.bin": payload(150_000, 3), "we|ird name.txt": b"pipe\n", "new\nline": b"nl\n",
             "trailing ": b"space\n", "Ünï/café.txt": b"utf8\n"}
    with mount_loop(img, tmp_path / "m") as m:
        for rel, data in files.items():
            (m / rel).parent.mkdir(parents=True, exist_ok=True)
            (m / rel).write_bytes(data)
        os.symlink("d/a.bin", m / "sl")
        (m / "gone.bin").write_bytes(payload(9000, 4))
        os.sync()
        (m / "gone.bin").unlink()
    src = open_source(str(img))
    r = TskReader(src, TskReader.probe(src))
    es = list(r.entries())
    check_tree(es)
    p = paths(es)
    for rel, data in files.items():
        rel = rel.replace("\n", "^")                      # fls prints control characters as "^"
        assert rel in p, rel
        assert content(src, p[rel]) == data, rel
    assert p["sl"].flags & F_SYMLINK and p["sl"].data == b"d/a.bin"
    assert p["d"].is_dir and p["lost+found"].is_dir
    assert p["d/a.bin"].mtime and abs(p["d/a.bin"].mtime - time.time()) < 3600
    assert p["d/a.bin"].extra["mode"] == 0o100644
    # ext4 wipes a deleted inode's size and extents: TSK only finds an orphan inode
    assert any(e.deleted and e.flags & F_ORPHAN for e in es)


def test_ntfs_streams_and_deleted(tmp_path):
    need("ntfs-3g", "mkfs.ntfs")
    if not os.path.exists("/dev/fuse"):
        pytest.skip("no FUSE")
    img = mkfs(tmp_path / "n.img", "ntfs", size=32 * MiB, label="TSKNTFS")
    data = payload(300_000, 5)
    with contextlib.ExitStack() as stack:
        try:
            m = stack.enter_context(imagekit.fuse_mount(img, "ntfs", tmp_path / "m"))
        except RuntimeError as exc:
            pytest.skip(f"ntfs-3g can't mount here: {exc}")
        (m / "dir").mkdir()
        (m / "dir" / "x.bin").write_bytes(data)
        (m / "dir" / "x.bin:ads").write_bytes(b"stream data\n")
        (m / "small.txt").write_bytes(b"resident\n")
        (m / "gone.bin").write_bytes(payload(50_000, 6))
        os.sync()
        (m / "gone.bin").unlink()
    src = FileSource(str(img))
    info = TskReader.probe(src)
    assert info["fstype"] == "ntfs" and info["label"] == "TSKNTFS"
    es = list(TskReader(src, info).entries())
    check_tree(es)
    p = paths(es)
    assert content(src, p["dir/x.bin"]) == data
    assert p["dir/x.bin:ads"].flags & F_ADS and content(src, p["dir/x.bin:ads"]) == b"stream data\n"
    assert content(src, p["small.txt"]) == b"resident\n"
    assert p["$MFT"].flags & F_SYSTEM
    g = p["gone.bin"]
    assert g.deleted and g.chance == CHANCE_FAIR and content(src, g) == payload(50_000, 6)
    assert not any("($FILE_NAME)" in k for k in p)


def test_ufs_from_makefs(tmp_path):
    need("makefs")
    srcdir = tmp_path / "src"
    (srcdir / "d").mkdir(parents=True)
    (srcdir / "d" / "a.bin").write_bytes(payload(100_000, 7))
    (srcdir / "h.txt").write_bytes(b"hi\n")
    img = tmp_path / "u.img"
    sh("makefs", "-t", "ffs", "-B", "le", "-o", "version=1", "-s", "16m", img, srcdir)
    # inside a disk image at an offset, like a partition
    disk = blank(tmp_path / "disk.img", 20 * MiB)
    imagekit.embed(disk, img, MiB)
    src = FileSource(str(disk)).region(MiB, 16 * MiB)
    info = TskReader.probe(src)
    assert info is not None and info["fstype"] == "ufs1"
    p = paths(list(TskReader(src, info).entries()))
    assert content(src, p["d/a.bin"]) == payload(100_000, 7)
    assert content(src, p["h.txt"]) == b"hi\n"


def test_apfs_container(tmp_path):
    need("mkapfs")
    img = blank(tmp_path / "a.img", 600 * MiB)
    sh("mkapfs", "-L", "MacData", img)
    src = FileSource(str(img))
    info = TskReader.probe(src)
    assert info["fstype"] == "apfs" and info["label"] == "MacData"
    assert info["apfs_volumes"][0]["block"] > 0
    es = list(TskReader(src, info).entries())
    assert es[0].key == "root" and not TskReader(src, info).warnings


def test_icat_is_stopped_early(tmp_path):
    img = mkfs(tmp_path / "fat.img", "fat32", size=64 * MiB, label="BIG")
    mtools_copy(img, {"big.bin": payload(8 * MiB, 8)})
    src = FileSource(str(img))
    e = paths(list(TskReader(src, TskReader.probe(src)).entries()))["big.bin"]
    assert read_head(src, e, 1000) == payload(1000, 8)
    gen = read_content(src, e)
    next(gen)
    gen.close()                                          # the icat process must be gone, not left behind
    out = subprocess.run(["pgrep", "-f", f"icat.*{img}"], capture_output=True, text=True).stdout
    assert out.strip() == ""


def test_virtual_sources_are_refused(tmp_path):
    assert TskReader.probe(BytesSource(bytes(1 << 20))) is None
    img = mkfs(tmp_path / "fat.img", "fat16", size=32 * MiB)
    f = FileSource(str(img))
    with pytest.raises(NotSupported):
        TskReader(ConcatSource([(f, 0, f.size)]), {"fstype": "fat16"})
    with pytest.raises(NotSupported):
        TskReader(BytesSource(Path(img).read_bytes()), {"fstype": "fat16"})
    e = {"size": 10, "extra": {"decoder": "tsk", "inode": "4", "tsk_type": "fat16"}}
    with pytest.raises(NotSupported):
        content(ConcatSource([(f, 0, f.size)]), e)


def test_not_a_filesystem(tmp_path):
    img = blank(tmp_path / "zero.img", 8 * MiB)
    assert TskReader.probe(FileSource(str(img))) is None
    r = TskReader(FileSource(str(img)), {"fstype": "ext4"})
    with pytest.raises(Exception) as exc:
        list(r.entries())
    assert "Sleuth Kit" in str(exc.value)
    assert r.root_key == "root" and CHANCE_GOOD
