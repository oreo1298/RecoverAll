"""Virtual RAID: every level and layout against an independent striper (written from the Linux md driver's
raid5_compute_sector), degraded reads, definitions, and the md-superblock route."""

import os
import random

import pytest

from recoverall.core.blockio import BytesSource
from recoverall.core.errors import RallError
from recoverall.core.raid import RaidSource, describe_definition, from_md, save_definition


def stripe(data: bytes, n: int, chunk: int, level: str, layout: str = "left-symmetric") -> list[bytearray]:
    """Write DATA across N members the way md does (reference implementation, per chunk)."""
    nchunks = len(data) // chunk
    if level == "0":
        rows = -(-nchunks // n)
    elif level == "5":
        rows = -(-nchunks // (n - 1))
    else:
        rows = -(-nchunks // (n - 2))
    members = [bytearray(rows * chunk) for _ in range(n)]
    for k in range(nchunks):
        piece = data[k * chunk:(k + 1) * chunk]
        if level == "0":
            members[k % n][(k // n) * chunk:(k // n + 1) * chunk] = piece
            continue
        data_disks = n - 1 if level == "5" else n - 2
        stripe_no, dd = divmod(k, data_disks)
        if layout.startswith("left"):
            pd = data_disks - stripe_no % n if level == "5" else n - 1 - stripe_no % n
        else:
            pd = stripe_no % n
        if level == "5":
            if layout.endswith("asymmetric"):
                if dd >= pd:
                    dd += 1
            else:
                dd = (pd + 1 + dd) % n
        else:
            dd = (pd + 2 + dd) % n
        members[dd][stripe_no * chunk:(stripe_no + 1) * chunk] = piece
    if level in ("5", "6"):
        for r in range(rows):
            data_disks = n - 1 if level == "5" else n - 2
            pd = (data_disks - r % n if level == "5" else n - 1 - r % n) if layout.startswith("left") else r % n
            qd = (pd + 1) % n if level == "6" else None
            acc = 0
            for j in range(n):
                if j not in (pd, qd):
                    acc ^= int.from_bytes(members[j][r * chunk:(r + 1) * chunk], "little")
            members[pd][r * chunk:(r + 1) * chunk] = acc.to_bytes(chunk, "little")
    return members


@pytest.mark.parametrize("level,n,layout", [("0", 3, ""), ("5", 3, "left-symmetric"), ("5", 4, "left-asymmetric"),
                                            ("5", 4, "right-symmetric"), ("5", 5, "right-asymmetric"),
                                            ("6", 5, "left-symmetric"), ("6", 4, "right-symmetric")])
def test_levels_and_layouts(level, n, layout):
    chunk = 4096
    data_disks = {"0": n, "5": n - 1, "6": n - 2}[level]
    data = random.Random(n).randbytes(chunk * data_disks * 9)
    members = stripe(data, n, chunk, level, layout or "left-symmetric")
    src = RaidSource([BytesSource(bytes(m)) for m in members], level, chunk, layout or "left-symmetric")
    assert src.size == len(data)
    assert src.read(0, len(data)) == data
    assert src.read(chunk - 100, 300) == data[chunk - 100:chunk + 200]
    if level in ("5", "6"):
        for missing in range(n):
            deg = [None if i == missing else BytesSource(bytes(m)) for i, m in enumerate(members)]
            d = RaidSource(deg, level, chunk, layout)
            assert d.read(0, len(data)) == data, f"member {missing} missing"


def test_mirror_jbod_raid10():
    a = os.urandom(8192)
    assert RaidSource([None, BytesSource(a)], "1", 4096).read(0, 8192) == a
    j = RaidSource([BytesSource(b"x" * 100), BytesSource(b"y" * 50)], "jbod")
    assert j.size == 150 and j.read(95, 10) == b"x" * 5 + b"y" * 5
    chunk = 512
    data = os.urandom(chunk * 8)
    # md near-2 over 4 disks: chunk k on disks (2k)%4 and (2k+1)%4, row (2k)//4
    members = [bytearray(chunk * 4) for _ in range(4)]
    for k in range(8):
        for c in range(2):
            idx = (2 * k + c) % 4
            row = (2 * k + c) // 4
            members[idx][row * chunk:(row + 1) * chunk] = data[k * chunk:(k + 1) * chunk]
    r10 = RaidSource([BytesSource(bytes(m)) for m in members], "10", chunk)
    assert r10.read(0, len(data)) == data
    r10d = RaidSource([None] + [BytesSource(bytes(m)) for m in members[1:]], "10", chunk)
    assert r10d.read(0, len(data)) == data


def test_refusals_and_definitions(tmp_path):
    with pytest.raises(RallError):
        RaidSource([BytesSource(b"a" * 4096), None], "0", 512)
    with pytest.raises(RallError):
        RaidSource([BytesSource(b"a" * 4096), None, None], "5", 512)
    imgs = []
    for i in range(3):
        p = tmp_path / f"m{i}.img"
        p.write_bytes(os.urandom(64 * 1024))
        imgs.append(str(p))
    d = {"name": "NAS", "level": "5", "chunk": 4096, "layout": "left-symmetric",
         "members": [{"path": imgs[0], "offset": 0}, None, {"path": imgs[2], "offset": 0}]}
    assert "1 missing" in describe_definition(d)
    path = save_definition(d, str(tmp_path / "nas.rallraid"))
    from recoverall.core.blockio import open_source
    src = open_source(path)
    assert src.size == 2 * 64 * 1024
    src.close()


def test_from_md():
    members = [{"path": f"/dev/sd{c}", "md": {"uuid": "abc", "level": "raid5", "raid_disks": 3, "chunk": 524288,
                                             "layout": 2, "data_offset": 262144 * 512 if c else 1048576, "role": i}}
               for i, c in enumerate("bcd")]
    d = from_md(members)
    assert d["level"] == "5" and d["chunk"] == 524288 and d["layout"] == "left-symmetric"
    assert [m["path"] for m in d["members"]] == ["/dev/sdb", "/dev/sdc", "/dev/sdd"]


# ---------------------------------------------------------------------- finding the parameters
def _jpg(seed: int, kb: int) -> bytes:
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + random.Random(seed).randbytes(kb * 1024) + b"\xff\xd9"


@pytest.fixture(scope="module")
def nas_volume(tmp_path_factory):
    """A FAT32 volume full of photos and documents, as a NAS share would hold."""
    from imagekit import MiB, mkfs, mtools_copy
    d = tmp_path_factory.mktemp("nas")
    files = {f"DCIM/IMG_{i:04d}.JPG": _jpg(i, 120 + 11 * i) for i in range(24)}
    files.update({f"Docs/report{i}.pdf": b"%PDF-1.4\n" + random.Random(i).randbytes(90_000) + b"\n%%EOF\n"
                  for i in range(8)})
    img = mkfs(d / "vol.img", "fat32", size=96 * MiB, label="NAS", extra=["-s", "8"])
    mtools_copy(img, files, d)
    return img.read_bytes()


@pytest.mark.parametrize("level,n,chunk,layout,lost", [
    ("5", 3, 65536, "left-symmetric", None), ("5", 3, 65536, "left-symmetric", 2),
    ("5", 4, 32768, "right-symmetric", 1), ("5", 4, 131072, "left-asymmetric", None), ("0", 3, 16384, "", None)])
def test_detect_finds_the_geometry(tmp_path, nas_volume, level, n, chunk, layout, lost):
    from recoverall.core.raid import detect
    paths = []
    for i, m in enumerate(stripe(nas_volume, n, chunk, level, layout or "left-symmetric")):
        p = tmp_path / f"disk{i}.img"
        p.write_bytes(bytes(m))
        paths.append(str(p))
    given = [paths[i] for i in (2, 0, 1, 3)[:n] if i != lost]       # members in the wrong order, one maybe lost
    best = detect(given, missing=1 if lost is not None else 0)[0]
    assert (best["level"], best["chunk"]) == (level, chunk)
    if layout:
        assert best["layout"] == layout
    assert [m["path"] if m else None for m in best["members"]] == [None if i == lost else p
                                                                   for i, p in enumerate(paths)]
    src = RaidSource.from_definition(best)
    assert src.read(0, len(nas_volume)) == nas_volume
    src.close()
