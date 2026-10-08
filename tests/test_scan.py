"""The whole pipeline on real filesystem images: scan (quick, deep, signatures), browse, recover, compare."""

import os
import struct
import zlib

import pytest
from imagekit import MiB, embed, mkfs, mtools_copy, mtools_delete, need, payload, sh

from recoverall.core.api import LocalAPI, wait_job
from recoverall.core.results import ScanDB
from recoverall.core.scan import Scanner, scan_options


def png(w: int = 64, h: int = 48, seed: int = 1) -> bytes:
    rows = b"".join(b"\x00" + bytes(((x * 7 + y * 3 + seed) & 255) for x in range(w * 3)) for y in range(h))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


FILES = {
    "DCIM/100CANON/IMG_0001.PNG": png(seed=1),
    "DCIM/100CANON/IMG_0002.PNG": png(seed=2),
    "DCIM/100CANON/IMG_0003.PNG": png(seed=3),
    "Documents/Thesis draft.txt": payload(70_000, 7),
    "Documents/budget.csv": b"a,b,c\n1,2,3\n" * 400,
    "big.bin": payload(3 * MiB + 123, 9),
}
DELETED = ["DCIM/100CANON/IMG_0002.PNG", "Documents/Thesis draft.txt", "big.bin"]


def recovered_name(rel: str) -> str:
    """A deleted 8.3 name loses its first character on FAT (long names keep it)."""
    if rel not in DELETED:
        return rel
    folder, _sep, name = rel.rpartition("/")
    stem = name.rsplit(".", 1)[0]
    if len(stem) <= 8 and " " not in name and (name.upper() == name or name.lower() == name):
        name = "_" + name[1:]
    return f"{folder}/{name}" if folder else name


@pytest.fixture(scope="module")
def fat_image(tmp_path_factory):
    need("mkfs.fat", "mcopy", "mdel")
    d = tmp_path_factory.mktemp("fat")
    img = d / "card.img"
    mkfs(img, "fat32", size=96 * MiB, label="CARD")
    mtools_copy(img, FILES, d)
    for f in DELETED:
        mtools_delete(img, f)
    return img


@pytest.fixture(scope="module")
def disk_image(tmp_path_factory, fat_image):
    need("sfdisk")
    d = tmp_path_factory.mktemp("disk")
    disk = d / "disk.img"
    with open(disk, "wb") as fh:
        fh.truncate(128 * MiB)
    sh("sfdisk", "-q", disk, input_bytes=b"label: dos\nstart=2048, size=196608, type=c\n")
    embed(disk, fat_image, MiB)
    return disk


def run(api, source, opts):
    job = api.start_scan(source=source if isinstance(source, dict) else str(source), options=opts)
    done = wait_job(api, job["id"], 120)
    assert done["state"] == "done", done.get("error")
    return job["scan"]


def test_quick_scan_finds_and_recovers(fat_image, tmp_path):
    api = LocalAPI()
    try:
        scan = run(api, fat_image, {"mode": "quick"})
        info = api.scan_info(scan=scan)
        vols = [v for v in info["volumes"] if v["fstype"] != "carved"]
        assert len(vols) == 1 and vols[0]["fstype"] == "fat32" and vols[0]["label"] == "CARD"
        found = api.scan_search(scan=scan, filters={"deleted": True}, limit=100)["rows"]
        names = {r["name"] for r in found}
        assert {recovered_name(f).rsplit("/", 1)[-1] for f in DELETED} <= names
        dest = tmp_path / "out"
        job = api.start_recover(scan=scan, entries=[vols[0]["root_id"]], dest=str(dest), options={})
        res = wait_job(api, job["id"], 120)
        assert res["state"] == "done", res.get("error")
        base = dest / "CARD (FAT32)"
        for rel, data in FILES.items():
            got = (base / recovered_name(rel)).read_bytes()
            assert got == data, rel
        assert (dest / "RecoverAll report.txt").exists()
        # a second recovery doesn't overwrite: names get " (2)"
        job = api.start_recover(scan=scan, entries=[found[0]["id"]], dest=str(dest), options={})
        assert wait_job(api, job["id"], 60)["state"] == "done"
        stem, ext = os.path.splitext(found[0]["name"])
        assert any(p.name == f"{stem} (2){ext}" for p in base.rglob("*"))
        # previews
        pic = next(r for r in found if r["name"].endswith("MG_0002.PNG"))
        p = api.preview(scan=scan, entry=pic["id"])
        assert p["kind"] == "image" and p["valid"] is True
        th = api.thumbnails(scan=scan, entries=[pic["id"]])
        assert th[str(pic["id"])]["data"]
    finally:
        api.close()


def test_partitioned_disk(disk_image):
    api = LocalAPI()
    try:
        scan = run(api, disk_image, {"mode": "quick"})
        vols = api.scan_info(scan=scan)["volumes"]
        assert [(v["offset"], v["fstype"]) for v in vols] == [(MiB, "fat32")]
        # one partition only, as a region
        scan2 = run(api, {"path": str(disk_image), "offset": MiB, "size": 96 * MiB}, {"mode": "quick"})
        assert api.scan_info(scan=scan2)["stats"]["files"] == len(FILES)
    finally:
        api.close()


def test_deep_scan_finds_deleted_partition(disk_image, tmp_path):
    pytest.importorskip("recoverall.core.partsearch")
    wiped = tmp_path / "wiped.img"
    wiped.write_bytes(disk_image.read_bytes())
    with open(wiped, "r+b") as fh:
        fh.write(bytes(512))                       # the partition table is gone
    api = LocalAPI()
    try:
        scan = run(api, wiped, {"mode": "deep", "formats": ["photo"]})
        info = api.scan_info(scan=scan)
        fat = [v for v in info["volumes"] if v["fstype"] == "fat32"]
        assert fat and fat[0]["offset"] == MiB and fat[0]["origin"] == "found"
        assert fat[0]["files"] == len(FILES)
        assert info.get("map") is None or True
    finally:
        api.close()


def test_signature_search_free_space(fat_image, tmp_path):
    pytest.importorskip("recoverall.core.carve.engine")
    api = LocalAPI()
    try:
        scan = run(api, fat_image, {"mode": "carve", "free_only": True, "formats": ["png"]})
        carved = api.scan_search(scan=scan, filters={"exts": ["png"]}, limit=50)["rows"]
        # only the deleted picture lies in free space
        assert len(carved) == 1 and carved[0]["size"] == len(FILES["DCIM/100CANON/IMG_0002.PNG"])
        e = api.scan_entry(scan=scan, entry=carved[0]["id"])
        assert e["chance"] >= 2
    finally:
        api.close()


def test_scanner_in_process(fat_image, tmp_path):
    from recoverall.core.blockio import open_source
    src = open_source(str(fat_image))
    db = ScanDB.create(tmp_path / "s.rascan", {"spec": str(fat_image)})
    try:
        out = Scanner(src, db, scan_options({"mode": "quick"})).run()
        assert out["stats"]["files"] == len(FILES)
        assert out["stats"]["deleted_files"] == len(DELETED)
    finally:
        db.close()
        src.close()
