"""The ext2/ext3/ext4 reader against images that mke2fs and the Linux kernel wrote.

Each scenario builds a filesystem, fills it through a loop mount, checks every existing entry byte for byte,
deletes files and a folder (with the kernel for ext3/ext4, so the journal is the only source; with debugfs for
ext2, which keeps block pointers and names like old kernels did), and checks that they come back.
"""

from __future__ import annotations

import os
import random
import shutil
import struct
import subprocess
import time
from pathlib import Path

import pytest
from imagekit import MiB, mkfs, mount_loop, need, payload, sh

from recoverall.core.blockio import BytesSource, FileSource
from recoverall.core.fs import base
from recoverall.core.fs.base import (
    CHANCE_GOOD,
    F_ENCRYPTED,
    F_HARDLINK,
    F_JOURNAL,
    F_ORPHAN,
    F_SYMLINK,
    F_SYSTEM,
    read_content,
)
from recoverall.core.fs.ext import (
    ExtReader,
    crc32c,
    group_has_super,
    guess_extension,
    parse_superblock,
    superblock_offset,
)

SLOW_TARGET = "a/b/c/" + "long-target-" * 10
UNICODE = "docs/Ünïcödé — 文件.txt"
DELETE = ["big.bin", "photos/IMG_0001.jpg", "a", "many/file_0007.dat", "many/file_0150.dat", "sparse.bin",
          UNICODE, "slow_link"]
DELETE_EXT2 = [d.replace("0150", "0050") for d in DELETE]       # that scenario has 60 files in many/


def sparse_bytes() -> bytes:
    out = bytearray(13 * MiB)
    for k in range(12):
        out[k * MiB:k * MiB + 4096] = payload(4096, 50 + k)
    return bytes(out)


def populate(mnt: Path, many: int = 300, big: int = 3 * MiB) -> dict:
    """A tree with what tends to break readers; returns {"files": {path: bytes}, "dirs": set, "links": {...}}."""
    files: dict[str, bytes] = {}

    def w(rel: str, data: bytes) -> None:
        p = mnt / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        files[rel] = data

    w("docs/one.txt", b"x")
    w("docs/empty.txt", b"")
    w(UNICODE, payload(1000, 2))
    w("photos/IMG_0001.jpg", b"\xff\xd8\xff\xe0" + payload(300_000, 3))
    w("photos/keep.png", b"\x89PNG\r\n\x1a\n" + payload(20_000, 8))
    w("big.bin", payload(big, 4))
    w("a/b/c/deep.txt", payload(5000, 5))
    w("a/b/mid.bin", payload(70_000, 6))
    w("a/top.txt", payload(123, 7))
    for i in range(many):
        w(f"many/file_{i:04d}.dat", payload(100 + i, 100 + i))
    data = sparse_bytes()
    with open(mnt / "sparse.bin", "wb") as fh:
        for k in range(12):
            fh.seek(k * MiB)
            fh.write(data[k * MiB:k * MiB + 4096])
        fh.truncate(len(data))
    files["sparse.bin"] = data
    os.symlink("docs/one.txt", mnt / "fast_link")
    os.symlink(SLOW_TARGET, mnt / "slow_link")
    os.link(mnt / "photos/keep.png", mnt / "docs/keep-hard.png")
    files["docs/keep-hard.png"] = files["photos/keep.png"]
    os.sync()
    dirs = {"docs", "photos", "a", "a/b", "a/b/c", "many", "lost+found"}
    stats = {}
    for rel in list(files) + ["fast_link", "slow_link"] + sorted(dirs - {"lost+found"}):
        st = os.lstat(mnt / rel)
        stats[rel] = st.st_mtime_ns / 1e9
    return {"files": files, "dirs": dirs, "links": {"fast_link": "docs/one.txt", "slow_link": SLOW_TARGET},
            "mtime": stats}


def read_all(img: Path, info: dict | None = None, deleted: bool = True):
    src = FileSource(str(img))
    if info is None:
        info = ExtReader.probe(src)
    rd = ExtReader(src, info)
    ents = list(rd.entries(deleted=deleted))
    return src, rd, ents


def paths(ents) -> dict:
    """{(path, deleted): entry}; entries under "Lost files" get "<lost>/" paths."""
    by_key = {e.key: e for e in ents}
    out = {}
    for e in ents:
        parts = []
        cur = e
        seen = set()
        while cur is not None and cur.key not in seen:
            seen.add(cur.key)
            if cur.parent is None:
                break
            parts.append(cur.name)
            cur = by_key.get(cur.parent)
        if cur is None or cur.key in seen and cur.parent is not None:
            continue
        if cur.flags & F_ORPHAN:
            parts.append("<lost>/" + cur.name)
        p = "/".join(reversed(parts))
        out.setdefault((p, e.deleted), e)
    return out


def content(src, e) -> bytes:
    return b"".join(read_content(src, e))


def check_live(src, ents, tree: dict) -> dict:
    keys = [e.key for e in ents]
    assert len(keys) == len(set(keys)), "duplicate keys"
    assert ents[0].key == 2 and ents[0].parent is None and ents[0].is_dir
    p = paths(ents)
    for rel, data in tree["files"].items():
        e = p.get((rel, False))
        assert e is not None, rel
        assert not e.is_dir and e.size == len(data), rel
        assert content(src, e) == data, rel
        assert e.chance == CHANCE_GOOD
        assert abs(e.mtime - tree["mtime"][rel]) < 1e-6, rel
    for d in tree["dirs"]:
        assert p[(d, False)].is_dir, d
    for rel, target in tree["links"].items():
        e = p[(rel, False)]
        assert e.flags & F_SYMLINK and content(src, e) == target.encode(), rel
    hard = [p[("photos/keep.png", False)], p[("docs/keep-hard.png", False)]]
    assert sum(1 for e in hard if e.flags & F_HARDLINK) == 1
    assert len({e.key for e in hard}) == 2
    journal = [e for e in ents if e.flags & F_SYSTEM]
    assert all(e.name == ".journal" for e in journal)
    return p


def delete_with_kernel(img: Path, mnt: Path, fstype: str, delete: list[str] = DELETE) -> None:
    with mount_loop(img, mnt, fstype):
        for rel in delete:
            t = mnt / rel
            if t.is_dir() and not t.is_symlink():
                shutil.rmtree(t)
            else:
                t.unlink()
        os.sync()


def check_deleted(src, ents, tree: dict, journal: bool, delete: list[str] = DELETE) -> None:
    p = paths(ents)
    expect = {}
    for rel, data in tree["files"].items():
        for d in delete:
            if rel == d or rel.startswith(d + "/"):
                expect[rel] = data
    for rel, data in expect.items():
        e = p.get((rel, True))
        assert e is not None, f"deleted {rel} not found"
        assert e.size == len(data), rel
        assert content(src, e) == data, rel
        assert e.chance == CHANCE_GOOD, rel
        if journal:
            assert e.flags & F_JOURNAL, rel
        assert (rel, False) not in p
    for d in ("a", "a/b", "a/b/c"):
        assert p[(d, True)].is_dir
    link = p.get(("slow_link", True))
    assert link is not None and content(src, link) == SLOW_TARGET.encode()
    # everything that wasn't deleted is still there, unchanged
    for rel, data in tree["files"].items():
        if rel not in expect:
            assert content(src, p[(rel, False)]) == data, rel
    keys = [e.key for e in ents]
    assert len(keys) == len(set(keys))


def build(tmp: Path, fstype: str, extra: list[str] | None = None, size: int = 64 * MiB, **kw):
    img = mkfs(tmp / f"{fstype}.img", fstype, size=size, label="RALL" + fstype.upper(), extra=extra)
    mnt = tmp / "mnt"
    with mount_loop(img, mnt, fstype):
        tree = populate(mnt, **kw)
    return img, mnt, tree


# ---------------------------------------------------------------------- unit-level
def test_superblock_rejects_garbage():
    assert parse_superblock(bytes(1024)) is None
    assert parse_superblock(b"\xff" * 1024) is None
    assert ExtReader.probe(BytesSource(bytes(8192))) is None


def test_crc32c_known_value():
    # RFC 3720 test vector: 32 bytes of zeros → 0x8A9136AA (after the final inversion)
    assert crc32c(bytes(32)) ^ 0xFFFFFFFF == 0x8A9136AA


def test_sparse_super_groups():
    sb = {"feature_compat": 0, "feature_ro_compat": 1}
    assert [g for g in range(60) if group_has_super(sb, g)] == [0, 1, 3, 5, 7, 9, 25, 27, 49]


def test_guess_extension():
    assert guess_extension(b"\xff\xd8\xff\xe0abc") == ".jpg"
    assert guess_extension(b"hello world\n") == ".txt"
    assert guess_extension(b"\x00\x01\x02") == ""


# ---------------------------------------------------------------------- real filesystems
@pytest.mark.root
def test_ext4_tree_and_journal_undelete(tmp_path):
    need("mkfs.ext4")
    img, mnt, tree = build(tmp_path, "ext4")
    src, rd, ents = read_all(img)
    assert rd.fstype == "ext4" and rd.info["label"] == "RALLEXT4"
    check_live(src, ents, tree)
    assert not [e for e in ents if e.deleted]
    many = [e for e in ents if e.parent == paths(ents)[("many", False)].key]
    assert len(many) == 300                      # an htree folder, read linearly
    delete_with_kernel(img, mnt, "ext4")
    src, rd, ents = read_all(img)
    check_deleted(src, ents, tree, journal=True)
    # the live tree alone, without the deleted-file passes
    src, rd, live = read_all(img, deleted=False)
    assert not [e for e in live if e.deleted]
    check_with_tsk(img, ents)
    check_lost_files(img, tree)
    fuzz(img, tmp_path, tree)


@pytest.mark.root
def test_ext3_block_maps_and_journal(tmp_path):
    need("mkfs.ext3")
    img, mnt, tree = build(tmp_path, "ext3")
    src, rd, ents = read_all(img)
    assert rd.fstype == "ext3"
    check_live(src, ents, tree)
    delete_with_kernel(img, mnt, "ext3")
    src, rd, ents = read_all(img)
    check_deleted(src, ents, tree, journal=True)


@pytest.mark.root
def test_ext2_1k_blocks_deleted_by_debugfs(tmp_path):
    """ext2 with 1 KiB blocks: indirect, double and triple indirect maps; deleted the classic way (the inode
    keeps its block pointers, the name stays in the folder block's slack)."""
    need("mkfs.ext2", "debugfs")
    img, mnt, tree = build(tmp_path, "ext2", extra=["-b", "1024"], many=60, big=1 * MiB)
    with mount_loop(img, mnt, "ext2"):
        with open(mnt / "triple.bin", "wb") as fh:    # past 64 MiB of 1 KiB blocks: triple indirect
            fh.seek(70 * MiB)
            fh.write(payload(3000, 77))
        os.sync()
        tree["files"]["triple.bin"] = bytes(70 * MiB) + payload(3000, 77)
        tree["mtime"]["triple.bin"] = os.lstat(mnt / "triple.bin").st_mtime_ns / 1e9
    src, rd, ents = read_all(img)
    assert rd.fstype == "ext2" and rd.bs == 1024
    check_live(src, ents, tree)
    cmds = []
    for rel in DELETE_EXT2:
        if rel == "a":
            cmds += ["rm /a/b/c/deep.txt", "rmdir /a/b/c", "rm /a/b/mid.bin", "rmdir /a/b", "rm /a/top.txt",
                     "rmdir /a"]
        else:
            cmds.append(f"rm \"/{rel}\"")
    script = tmp_path / "cmds"
    script.write_text("\n".join(cmds) + "\n")
    sh("debugfs", "-w", "-f", script, img)
    src, rd, ents = read_all(img)
    check_deleted(src, ents, tree, journal=False, delete=DELETE_EXT2)
    gone = {rel for rel in list(tree["files"]) + ["slow_link", "a", "a/b", "a/b/c"]
            if any(rel == d or rel.startswith(d + "/") for d in DELETE_EXT2)}
    check_with_tsk(img, ents, deleted=gone)


@pytest.mark.root
def test_ext4_inline_data(tmp_path):
    need("mkfs.ext4")
    img = mkfs(tmp_path / "inline.img", "ext4", size=32 * MiB, extra=["-O", "inline_data"])
    mnt = tmp_path / "mnt"
    small = {f"tiny/t{i}.txt": payload(i * 7 + 1, 300 + i) for i in range(20)}
    with mount_loop(img, mnt, "ext4"):
        for rel, data in small.items():
            (mnt / rel).parent.mkdir(exist_ok=True)
            (mnt / rel).write_bytes(data)
        (mnt / "sub").mkdir()
        (mnt / "sub/x").write_bytes(b"inline folder")
        os.sync()
    src, rd, ents = read_all(img)
    p = paths(ents)
    for rel, data in small.items():
        assert content(src, p[(rel, False)]) == data, rel
    assert content(src, p[("sub/x", False)]) == b"inline folder"
    with mount_loop(img, mnt, "ext4"):
        for i in (3, 4, 17):
            (mnt / f"tiny/t{i}.txt").unlink()
        shutil.rmtree(mnt / "sub")
        os.sync()
    src, rd, ents = read_all(img)
    p = paths(ents)
    for i in (3, 4, 17):
        e = p[(f"tiny/t{i}.txt", True)]
        assert content(src, e) == small[f"tiny/t{i}.txt"] and e.chance == CHANCE_GOOD
    assert content(src, p[("sub/x", True)]) == b"inline folder"


@pytest.mark.root
def test_ext4_32bit_descriptors_2k_blocks(tmp_path):
    """No 64bit, no metadata_csum (gdt checksums, 32-byte descriptors), 2 KiB blocks, several groups."""
    need("mkfs.ext4")
    img, mnt, tree = build(tmp_path, "ext4", extra=["-b", "2048", "-O", "^64bit,^metadata_csum,uninit_bg",
                                                    "-g", "4096"], many=50, big=1 * MiB)
    src, rd, ents = read_all(img)
    assert rd.sb["desc_size"] == 32 and len(rd.groups) > 4
    check_live(src, ents, tree)
    check_free_space(img, rd)
    delete = [d for d in DELETE if "0150" not in d]
    delete_with_kernel(img, mnt, "ext4", delete)
    src, rd, ents = read_all(img)
    check_deleted(src, ents, tree, journal=True, delete=delete)


@pytest.mark.root
def test_backup_superblock(tmp_path):
    need("mkfs.ext4")
    img, mnt, tree = build(tmp_path, "ext4", many=10, big=200_000, size=160 * MiB)    # 2 groups
    src = FileSource(str(img))
    info = ExtReader.probe(src)
    off = 32768 * 4096
    sb1 = parse_superblock(src.read(off, 1024))
    assert sb1 and sb1["block_group_nr"] == 1 and sb1["uuid"] == info["uuid"]
    assert superblock_offset(sb1) == off and superblock_offset(parse_superblock(src.read(1024, 1024))) == 1024
    src.close()
    with open(img, "r+b") as fh:                 # wipe the main superblock
        fh.seek(1024)
        fh.write(bytes(1024))
    src = FileSource(str(img))
    assert ExtReader.probe(src) is None
    for rd in (ExtReader(src, {"sb_offset": off}), ExtReader(src)):
        ents = list(rd.entries())
        assert rd.warnings and "backup" in rd.warnings[0]
        p = paths(ents)
        for rel, data in tree["files"].items():
            assert content(src, p[(rel, False)]) == data, rel


@pytest.mark.root
def test_unclean_filesystem_is_replayed(tmp_path):
    """A filesystem that wasn't unmounted (a crash, a pulled USB disk) keeps its latest changes in the journal
    only: the reader sees what Linux sees after replaying it, without writing anything."""
    need("mkfs.ext4")
    img = mkfs(tmp_path / "crash.img", "ext4", size=32 * MiB)
    mnt = tmp_path / "mnt"
    snap = tmp_path / "snap.img"
    with mount_loop(img, mnt, "ext4", options="commit=1"):
        (mnt / "old.bin").write_bytes(payload(50_000, 1))
        os.sync()
        (mnt / "newdir").mkdir()
        for i in range(3):
            (mnt / f"newdir/f{i}").write_bytes(payload(1000, i))
        (mnt / "old.bin").rename(mnt / "newdir/moved.bin")
        time.sleep(2.2)                          # committed to the journal, not yet written in place
        shutil.copyfile(img, snap)               # what a crash leaves behind
    before = snap.read_bytes()
    src = FileSource(str(snap))
    rd = ExtReader(src)
    if rd._log is None or not rd._log.start:
        pytest.skip("the kernel had already written everything in place")
    ents = list(rd.entries())
    assert snap.read_bytes() == before           # nothing was written
    ours = {p: e.size for (p, dele), e in paths(ents).items()
            if not dele and p and not e.is_dir and not e.flags & F_SYSTEM}
    kernel = tmp_path / "kernel.img"
    shutil.copyfile(snap, kernel)
    with mount_loop(kernel, mnt, "ext4"):        # the kernel replays the journal of its copy
        theirs = {str(f.relative_to(mnt)): f.stat().st_size for f in mnt.rglob("*") if f.is_file()}
    assert ours == theirs
    assert "newdir/moved.bin" in ours and content(src, paths(ents)[("newdir/moved.bin", False)]) == payload(50_000, 1)


@pytest.mark.root
def test_encrypted_folder(tmp_path):
    """fscrypt: names are ciphertext (shown the way Linux shows them without the key), content is copied as
    stored and flagged."""
    need("mkfs.ext4", "e4crypt")
    img = mkfs(tmp_path / "enc.img", "ext4", size=32 * MiB, extra=["-O", "encrypt"])
    mnt = tmp_path / "mnt"
    with mount_loop(img, mnt, "ext4"):
        (mnt / "secret").mkdir()
        p = subprocess.run(["e4crypt", "add_key", "-S", "0x1234567890abcdef", str(mnt / "secret")],
                           input=b"passw0rd\n", capture_output=True)
        if p.returncode != 0 or b"applied" not in p.stdout:
            pytest.skip("can't set up an fscrypt key here")
        for i in range(3):
            (mnt / f"secret/file_{i}.txt").write_bytes(b"hello secret %d" % i)
        (mnt / "plain.txt").write_bytes(b"in the clear")
        os.sync()
    src, rd, ents = read_all(img)
    p = paths(ents)
    secret = p[("secret", False)]
    kids = [e for e in ents if e.parent == secret.key]
    assert len(kids) == 3 and all(e.flags & F_ENCRYPTED and e.name.startswith("~enc~") for e in kids)
    assert all(e.size == len(b"hello secret 0") for e in kids)
    assert content(src, p[("plain.txt", False)]) == b"in the clear"


# ---------------------------------------------------------------------- helpers shared by the scenarios
def check_lost_files(img: Path, tree: dict) -> None:
    """Without its folder's journal copies a deleted file has no name: it is listed under "Lost files" as
    "inode N" with an extension from its first bytes. Live files whose folder block is gone are lost files too."""
    data = bytearray(Path(img).read_bytes())
    src = BytesSource(bytes(data))
    rd = ExtReader(src)
    ents = list(rd.entries())
    p = paths(ents)
    photos = rd.read_inode(p[("photos", False)].key)
    docs = rd.read_inode(p[("docs", False)].key)
    bs = rd.bs
    for _lb, pb in rd._dir_blocks(photos):
        for _age, jpos, _esc in rd.journal.copies.get(pb, []):
            off = rd.journal.fs_block(jpos) * bs
            data[off:off + bs] = bytes(bs)
    for _lb, pb in rd._dir_blocks(docs):
        data[pb * bs:(pb + 1) * bs] = bytes(bs)
    src = BytesSource(bytes(data))
    rd = ExtReader(src)
    ents = list(rd.entries())
    p = paths(ents)
    jpg = [e for (path, dele), e in p.items() if dele and path.startswith("<lost>/inode ") and path.endswith(".jpg")]
    assert len(jpg) == 1 and jpg[0].flags & F_ORPHAN and jpg[0].parent is None
    assert content(src, jpg[0]) == tree["files"]["photos/IMG_0001.jpg"]
    assert ("photos/IMG_0001.jpg", True) not in p
    lost_live = {content(src, e) for (path, dele), e in p.items() if not dele and path.startswith("<lost>/")}
    assert tree["files"]["docs/one.txt"] in lost_live and b"" in lost_live
    assert ("docs/one.txt", False) not in p


def check_free_space(img: Path, rd: ExtReader) -> None:
    """free_extents() against dumpe2fs's per-group "Free blocks:" lists."""
    need("dumpe2fs")
    out = sh("dumpe2fs", img)
    want = 0
    for line in out.splitlines():
        if line.startswith("  Free blocks:"):          # the per-group lines (the header has a total)
            for part in line.split(":", 1)[1].split(","):
                part = part.strip()
                if not part:
                    continue
                a, _, b = part.partition("-")
                want += int(b or a) - int(a) + 1
    got = sum(n for _o, n in rd.free_extents()) // rd.bs
    assert got == want


def check_with_tsk(img: Path, ents, deleted: set[str] | None = None) -> None:
    """The Sleuth Kit's fls lists the same existing paths; for an ext2 whose files were deleted the classic way,
    the deleted names it finds are found here too. (fls also reads htree index data as deleted entries with
    random names, so only the paths that really were deleted are compared.)"""
    if not shutil.which("fls"):
        return
    p = subprocess.run(["fls", "-r", "-p", "-f", "ext", str(img)], capture_output=True, text=True)
    if p.returncode != 0:
        return
    ours = {path for (path, dele) in paths(ents) if not dele and not path.startswith("<lost>")}
    ours.discard("")
    ours.discard(".journal")
    tsk_live = set()
    tsk_del = set()
    for line in p.stdout.splitlines():
        meta, _, name = line.partition("\t")
        if name.startswith("$OrphanFiles"):
            continue
        (tsk_del if " * " in meta else tsk_live).add(name)
    assert tsk_live == ours
    if deleted:
        ours_del = {path for (path, dele) in paths(ents) if dele and not path.startswith("<lost>")}
        assert tsk_del & deleted <= ours_del     # what fls finds of what was deleted, we find too
        assert deleted <= ours_del


def fuzz(img: Path, tmp: Path, tree: dict, rounds: int = 12) -> None:
    """Random damage to inode tables, folder blocks and the journal must never make entries() raise."""
    src = FileSource(str(img))
    rd = ExtReader(src)
    targets = []
    for g in rd.groups:
        targets.append((g.inode_table * rd.bs, rd.itable_blocks * rd.bs))
    for e in rd.entries():
        if e.is_dir and isinstance(e.key, int):
            inode = rd.read_inode(e.key)
            for _l, pb in rd._dir_blocks(inode)[:4]:
                targets.append((pb * rd.bs, rd.bs))
    if rd.journal:
        for lb, pb, n in rd.journal.map:
            targets.append((pb * rd.bs, n * rd.bs))
    data = bytearray(Path(img).read_bytes())
    src.close()
    rng = random.Random(1234)
    for r in range(rounds):
        buf = bytearray(data)
        for _ in range(200):
            off, n = rng.choice(targets)
            pos = off + rng.randrange(n)
            if rng.random() < 0.3:
                k = rng.randrange(1, 64)
                buf[pos:pos + k] = bytes(rng.randrange(256) for _ in range(k))[:len(buf) - pos]
            else:
                buf[pos] = rng.randrange(256)
        bsrc = BytesSource(bytes(buf))
        rd = ExtReader(bsrc, ExtReader.probe(bsrc))
        for e in rd.entries():
            if not e.is_dir and e.size < 8 * MiB:
                for _chunk in base.read_content(bsrc, e):
                    pass
        assert isinstance(rd.free_extents(), list)
    # a damaged superblock field set: probe must refuse or cope, never raise
    for r in range(40):
        buf = bytearray(data[:64 * 1024])
        for _ in range(8):
            pos = 1024 + rng.randrange(1024)
            buf[pos] = rng.randrange(256)
        bsrc = BytesSource(bytes(buf) + bytes(len(data) - len(buf)))
        info = ExtReader.probe(bsrc)
        if info:
            try:
                rd = ExtReader(bsrc, info)
            except Exception as exc:          # noqa: BLE001 - only FormatError is allowed
                assert type(exc).__name__ == "FormatError"
                continue
            for _e in rd.entries():
                pass


def test_struct_sizes():
    assert struct.calcsize("<HHIIIIIHHII") == 36
