"""Thumbnails of photos from system thumbnail caches (media/thumbcache.py).

Each cache is written here following its published layout — Windows thumbcache_*.db (Windows 7 and 10
entries), Windows XP Thumbs.db (an OLE compound file with a Catalog stream), Android .thumbdata, a Linux
desktop thumbnail (PNG with Thumb::URI) and macOS QuickLook (index.sqlite + thumbnails.data) — around real
pictures made with ffmpeg; the thumbnails, names, paths and dates must come back, and damaged caches must
never raise."""

from __future__ import annotations

import plistlib
import random
import sqlite3
import struct
import zlib

import pytest
from mediakit import decode_check, make_photo, need_ffmpeg

from recoverall.core.media import jpegdec, thumbcache
from recoverall.core.media.thumbcache import extract, kind_of


@pytest.fixture(scope="module")
def pics(tmp_path_factory):
    need_ffmpeg("mjpeg", "png")
    d = tmp_path_factory.mktemp("thumbs")
    return {
        "a": make_photo(d / "a.jpg", "256x192", ("-q:v", "4")).read_bytes(),
        "b": make_photo(d / "b.jpg", "96x96", ("-q:v", "6", "-huffman", "default")).read_bytes(),
        "c": make_photo(d / "c.jpg", "120x90", ("-q:v", "5")).read_bytes(),
        "png": make_photo(d / "p.png", "128x96").read_bytes(),
        "bmp": make_photo(d / "p.bmp", "32x24").read_bytes(),
    }


def jpeg_ok(data: bytes) -> bool:
    return jpegdec.decode_check(data).ok


# ---------------------------------------------------------------------- Windows thumbcache_*.db
def thumbcache_db(entries: list[tuple[str, bytes]], version: int = 32) -> bytes:
    """A thumbcache file: the header, then for each (identifier, picture) an entry ("CMMM", size, hash,
    identifier size, padding size, data size, [width, height, unknown], checksums, identifier, padding,
    data). Version 21: Windows 7 entries; 30 and up: Windows 8-11 ones."""
    out = bytearray(b"CMMM" + struct.pack("<IIIII", version, 1, 0, 24, 24 + 1))
    out += bytes(24 - len(out))
    for i, (ident, pic) in enumerate(entries):
        name = ident.encode("utf-16-le")
        pad = (-len(name)) % 8
        if version >= 30:
            head = struct.pack("<4sIQIIIIIIQQ", b"CMMM", 0, 0x1000 + i, len(name), pad, len(pic), 96, 96, 0, 0, 0)
        else:
            head = struct.pack("<4sIQIIIIQQ", b"CMMM", 0, 0x1000 + i, len(name), pad, len(pic), 0, 0, 0)
        entry = bytearray(head + name + bytes(pad) + pic)
        struct.pack_into("<I", entry, 4, len(entry))
        out += entry
    return bytes(out)


def test_windows_thumbcache(pics):
    pictures = [("a1b2c3d4e5f60718", pics["a"]), ("00ff00ff00ff00ff", pics["png"]), ("1234567890abcdef", pics["bmp"])]
    for version in (21, 32):
        db = thumbcache_db(pictures, version)
        assert kind_of("thumbcache_96.db", db[:64]) == "thumbcache"
        got = extract(db, "thumbcache")
        want = [(n, e, p) for (n, p), e in zip(pictures, ("jpg", "png", "bmp"))]
        assert [(t.name, t.ext, t.data) for t in got] == want
        assert got[0].width == 256 and got[0].height == 192 and got[0].original_path is None
    # an entry overwritten in the middle: the others still come out
    db = bytearray(thumbcache_db(pictures, 32))
    at = db.index(pics["png"])
    db[at - 40:at + 100] = bytes(140)
    got = extract(bytes(db), "thumbcache")
    assert [t.name for t in got] == ["a1b2c3d4e5f60718", "1234567890abcdef"]


# ---------------------------------------------------------------------- Windows XP Thumbs.db
def cfb(streams: dict[str, bytes]) -> bytes:
    """An OLE compound file (version 3: 512-byte sectors, a mini stream for the small streams) holding
    STREAMS as children of the root."""
    ss, mss = 512, 64
    small = {n: d for n, d in streams.items() if len(d) < 4096}
    big = {n: d for n, d in streams.items() if len(d) >= 4096}
    mini, minifat, starts = bytearray(), [], {}
    for n, d in small.items():
        count = max(1, -(-len(d) // mss))
        starts[n] = len(minifat)
        minifat += [len(minifat) + k + 1 for k in range(count - 1)] + [0xFFFFFFFE]
        mini += d + bytes(count * mss - len(d))
    entries = [("Root Entry", 5)] + [(n, 2) for n in streams]
    nsec = {"dir": -(-len(entries) // 4), "minifat": -(-len(minifat) * 4 // ss), "mini": -(-len(mini) // ss)}
    big_secs = {n: -(-len(d) // ss) for n, d in big.items()}
    data_secs = sum(nsec.values()) + sum(big_secs.values())
    nfat = 1
    while nfat * (ss // 4) < data_secs + nfat:
        nfat += 1
    fat, chain_start = [0xFFFFFFFD] * nfat, {}

    def chain(count: int) -> int:
        first = len(fat)
        fat.extend(first + k + 1 for k in range(count - 1))
        fat.append(0xFFFFFFFE)
        return first
    for key in ("dir", "minifat", "mini"):
        chain_start[key] = chain(nsec[key]) if nsec[key] else 0xFFFFFFFE
    for n, count in big_secs.items():
        chain_start[n] = chain(count)
    fat += [0xFFFFFFFF] * (nfat * (ss // 4) - len(fat))
    dirs = bytearray()
    for i, (n, typ) in enumerate(entries):
        name = n.encode("utf-16-le") + b"\0\0"
        right = i + 1 if 0 < i < len(entries) - 1 else 0xFFFFFFFF
        child = 1 if i == 0 and len(entries) > 1 else 0xFFFFFFFF
        if typ == 5:
            start, size = chain_start["mini"], len(mini)
        elif n in small:
            start, size = starts[n], len(small[n])
        else:
            start, size = chain_start[n], len(big[n])
        dirs += name.ljust(64, b"\0") + struct.pack("<HBBIII", len(name), typ, 1, 0xFFFFFFFF, right, child) + \
            bytes(16 + 4 + 16) + struct.pack("<IQ", start, size)
    dirs += bytes(nsec["dir"] * ss - len(dirs))
    head = bytearray(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(16) + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6))
    head += bytes(6) + struct.pack("<IIIIIIIII", 0, nfat, chain_start["dir"], 0, 4096,
                                   chain_start["minifat"] if minifat else 0xFFFFFFFE, nsec["minifat"], 0xFFFFFFFE, 0)
    head += struct.pack("<109I", *(list(range(nfat)) + [0xFFFFFFFF] * (109 - nfat)))
    body = struct.pack(f"<{len(fat)}I", *fat) + dirs
    mf = struct.pack(f"<{len(minifat)}I", *minifat)
    body += mf + b"\xff" * (nsec["minifat"] * ss - len(mf)) + mini + bytes(nsec["mini"] * ss - len(mini))
    for n, d in big.items():
        body += d + bytes(big_secs[n] * ss - len(d))
    return bytes(head) + body


def thumbs_db(files: list[tuple[int, str, int, bytes]]) -> bytes:
    """Thumbs.db: a Catalog record per (index, name, FILETIME, JPEG) and a stream named after the index's
    digits reversed with a 12-byte header and the JPEG."""
    cat = bytearray(struct.pack("<HHIII", 16, 7, len(files), 96, 96))
    streams = {}
    for index, name, ft, jpeg in files:
        raw = name.encode("utf-16-le") + b"\0\0"
        rec = struct.pack("<IIQ", 16 + len(raw) + 4, index, ft) + raw + bytes(4)
        cat += rec
        streams[str(index)[::-1]] = struct.pack("<III", 12, 1, len(jpeg)) + jpeg
    return cfb({"Catalog": bytes(cat), **streams})


def without_tables(jpeg: bytes) -> bytes:
    """The JPEG with its Huffman tables left out (as some Thumbs.db writers did)."""
    out, pos = bytearray(jpeg[:2]), 2
    while True:
        mk, n = jpeg[pos + 1], struct.unpack_from(">H", jpeg, pos + 2)[0]
        if mk != 0xC4:
            out += jpeg[pos:pos + 2 + n]
        pos += 2 + n
        if mk == 0xDA:
            return bytes(out) + jpeg[pos:]


def test_windows_xp_thumbs_db(pics):
    ft = (1_600_000_000 + 11644473600) * 10_000_000
    files = [(1, "IMG_0001.JPG", ft, pics["a"]), (2, "holiday photo.jpg", ft + 10_000_000, pics["c"]),
             (12, "scan.jpg", 0, without_tables(pics["b"]))]
    db = thumbs_db(files)
    assert kind_of("Thumbs.db", db[:512]) == "thumbsdb" and kind_of("", db[:4096]) == "thumbsdb"
    got = {t.name: t for t in extract(db, "thumbsdb")}
    assert set(got) == {"IMG_0001", "holiday photo", "scan"}
    assert got["IMG_0001"].data == pics["a"] and got["IMG_0001"].mtime == 1_600_000_000
    assert got["IMG_0001"].original_path == "IMG_0001.JPG" and got["holiday photo"].mtime == 1_600_000_001
    assert got["holiday photo"].data == pics["c"] and got["holiday photo"].width == 120   # a big stream
    assert jpeg_ok(got["scan"].data) and got["scan"].data != pics["b"]     # the standard tables put back
    assert got["scan"].mtime is None


# ---------------------------------------------------------------------- Android
def test_android_thumbdata(pics):
    slot = 32768
    data = b""
    for i, pic in enumerate((pics["a"], pics["c"], b"", pics["b"])):
        body = b"\x01" + struct.pack(">QI", 0xABC0 + i, len(pic)) + pic if pic else b""
        data += body + bytes(slot - len(body))
    assert kind_of("DCIM/.thumbnails/.thumbdata4--1967290299", data[:64]) == "thumbdata"
    got = extract(data, "thumbdata")
    assert [t.data for t in got] == [pics["a"], pics["c"], pics["b"]]
    assert [t.ext for t in got] == ["jpg"] * 3 and got[0].width == 256
    assert kind_of("/sdcard/DCIM/.thumbnails/1700000000000.jpg", pics["c"][:16]) == "android_thumbnail"


# ---------------------------------------------------------------------- Linux desktops
def png_chunk(t: bytes, d: bytes) -> bytes:
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)


def freedesktop(png: bytes, uri: str, mtime: int) -> bytes:
    """A freedesktop.org thumbnail: the PNG with Thumb::URI and Thumb::MTime after its IHDR chunk."""
    text = png_chunk(b"tEXt", b"Thumb::URI\0" + uri.encode())
    text += png_chunk(b"tEXt", b"Thumb::MTime\0" + str(mtime).encode())
    text += png_chunk(b"zTXt", b"Software\0\0" + zlib.compress(b"GNOME::ThumbnailFactory"))
    return png[:33] + text + png[33:]


def test_linux_thumbnails(pics, tmp_path):
    uri = "file:///home/ann/Pictures/Holiday%202023/IMG_0042.JPG"
    thumb = freedesktop(pics["png"], uri, 1_690_000_000)
    path = "/home/ann/.cache/thumbnails/large/0123456789abcdef0123456789abcdef.png"
    assert kind_of(path, thumb) == "freedesktop" and kind_of("x.png", thumb) == "freedesktop"
    assert kind_of(path, pics["png"]) == "freedesktop" and kind_of("x.png", pics["png"]) is None
    (t,) = extract(thumb, "freedesktop")
    assert t.original_path == "/home/ann/Pictures/Holiday 2023/IMG_0042.JPG" and t.name == "IMG_0042"
    assert t.mtime == 1_690_000_000 and t.ext == "png" and (t.width, t.height) == (128, 96) and t.data == thumb
    assert thumbcache.png_text(thumb)["Software"] == "GNOME::ThumbnailFactory"
    p = tmp_path / "t.png"
    p.write_bytes(t.data)
    ok, errors = decode_check(p)
    assert ok, errors


# ---------------------------------------------------------------------- macOS QuickLook
def quicklook(tmp_path, items: list[tuple[str, str, int, int, bytes]]) -> tuple[bytes, bytes]:
    """index.sqlite and thumbnails.data for (folder, name, width, height, RGBA pixels) items: the bitmaps one
    after the other, each row padded to a multiple of 64 bytes."""
    db = tmp_path / "index.sqlite"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE files (rowid INTEGER PRIMARY KEY AUTOINCREMENT, folder TEXT, file_name TEXT, "
                "version BLOB, fs_id BLOB, UNIQUE(folder, file_name))")
    con.execute("CREATE TABLE thumbnails (rowid INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER, size INTEGER, "
                "width INTEGER, height INTEGER, bitspercomponent INTEGER, bitsperpixel INTEGER, bytesperrow INTEGER, "
                "hit_count INTEGER, last_hit_date INTEGER, bitmapdata_location INTEGER, bitmapdata_length INTEGER)")
    data = bytearray()
    for i, (folder, name, w, h, px) in enumerate(items):
        version = plistlib.dumps({"date": 700_000_000.0 + i, "size": 12345, "gen": 1}, fmt=plistlib.FMT_BINARY)
        cur = con.execute("INSERT INTO files (folder, file_name, version) VALUES (?, ?, ?)", (folder, name, version))
        bpr = -(-w * 4 // 64) * 64
        bitmap = b"".join(px[y * w * 4:(y + 1) * w * 4].ljust(bpr, b"\0") for y in range(h))
        con.execute("INSERT INTO thumbnails (file_id, size, width, height, bitspercomponent, bitsperpixel, "
                    "bytesperrow, bitmapdata_location, bitmapdata_length) VALUES (?, 128, ?, ?, 8, 32, ?, ?, ?)",
                    (cur.lastrowid, w, h, bpr, len(data), len(bitmap)))
        data += bitmap
    con.commit()
    con.close()
    return db.read_bytes(), bytes(data)


def png_pixels(png: bytes) -> tuple[int, int, bytes]:
    w, h = struct.unpack_from(">II", png, 16)
    pos, idat = 8, b""
    while pos < len(png):
        n, t = struct.unpack_from(">I4s", png, pos)
        if t == b"IDAT":
            idat += png[pos + 8:pos + 8 + n]
        pos += 12 + n
    raw = zlib.decompress(idat)
    stride = w * 4 + 1
    assert all(raw[y * stride] == 0 for y in range(h))
    return w, h, b"".join(raw[y * stride + 1:(y + 1) * stride] for y in range(h))


def test_macos_quicklook(tmp_path):
    rng = random.Random(3)
    a = rng.randbytes(40 * 30 * 4)
    b = bytes([200, 100, 50, 255]) * (17 * 9)
    index, data = quicklook(tmp_path, [("/Users/ann/Pictures", "IMG_1.HEIC", 40, 30, a),
                                       ("/Users/ann/Desktop/", "plan.jpg", 17, 9, b)])
    assert kind_of("Library/Caches/com.apple.QuickLook.thumbnailcache/index.sqlite", index[:100]) == "quicklook_index"
    assert kind_of("/private/var/folders/x/C/com.apple.QuickLook.thumbnailcache/thumbnails.data", data[:16]) == \
        "quicklook_data"
    for got in (extract(index, "quicklook_index", companion=data), extract(data, "quicklook_data", companion=index)):
        assert [(t.name, t.original_path, t.ext, t.width, t.height) for t in got] == [
            ("IMG_1", "/Users/ann/Pictures/IMG_1.HEIC", "png", 40, 30),
            ("plan", "/Users/ann/Desktop/plan.jpg", "png", 17, 9)]
        assert png_pixels(got[0].data) == (40, 30, a) and png_pixels(got[1].data) == (17, 9, b)
        assert got[0].mtime == 700_000_000 + 978307200
    assert extract(index, "quicklook_index") == []                      # no pictures without thumbnails.data
    got = extract(index, "quicklook_index", companion=data[:192 * 30 + 100])   # the second bitmap cut off
    assert [t.name for t in got] == ["IMG_1"]                            # the bitmap past the end is skipped


# ---------------------------------------------------------------------- damage
def test_damaged_caches_never_raise(pics, tmp_path):
    index, data = quicklook(tmp_path, [("/a", "b.jpg", 8, 8, bytes(256))])
    samples = {
        "thumbcache": thumbcache_db([("a", pics["a"]), ("b", pics["png"])]),
        "thumbsdb": thumbs_db([(1, "a.jpg", 0, pics["a"]), (2, "b.jpg", 0, pics["c"])]),
        "thumbdata": pics["a"] + pics["c"],
        "freedesktop": freedesktop(pics["png"], "file:///x/y.jpg", 1),
        "quicklook_index": index,
    }
    rng = random.Random(9)
    for kind, sample in samples.items():
        for k in range(60):
            bad = bytearray(sample)
            if k % 3 == 0:
                bad = bad[:rng.randrange(len(bad))]
            for _ in range(rng.randrange(1, 40)):
                bad[rng.randrange(len(bad))] = rng.randrange(256)
            got = extract(bytes(bad), kind, companion=data)
            assert isinstance(got, list) and all(isinstance(t.data, bytes) for t in got)
            kind_of("thumbs.db", bytes(bad[:64]))
    assert extract(b"", "thumbsdb") == [] and extract(b"CMMM", "thumbcache") == [] and extract(b"x", "nope") == []


def test_thumbnails_appear_in_scan_results(pics, tmp_path):
    """A scan finds the thumbnail caches on a disk and lists their thumbnails in a volume of their own, a folder
    per cache; Linux thumbnails carry the original file's name."""
    from imagekit import MiB, mkfs, mtools_copy, need

    from recoverall.core.api import LocalAPI, wait_job
    need("mkfs.fat", "mcopy")
    img = mkfs(tmp_path / "disk.img", "fat32", size=64 * MiB, label="PC")
    files = {
        "Users/ann/AppData/Local/Microsoft/Windows/Explorer/thumbcache_256.db":
            thumbcache_db([("6a1f8e2c9d3b4a5f", pics["a"]), ("77aa0b1c2d3e4f50", pics["c"])]),
        "home/ann/.cache/thumbnails/normal/0123456789abcdef0123456789abcdef.png":
            freedesktop(pics["png"], "file:///home/ann/Pictures/IMG_0042.JPG", 1_690_000_000),
        "Pictures/keep.txt": b"not a cache",
    }
    mtools_copy(img, files, tmp_path)
    api = LocalAPI()
    try:
        job = api.start_scan(source=str(img), options={"mode": "quick"})
        scan = wait_job(api, job["id"], 120)["result"]["scan"]
        vols = [v for v in api.scan_info(scan=scan)["volumes"] if v["fstype"] == "thumbnails"]
        assert len(vols) == 1 and vols[0]["name"] == "Thumbnails of deleted photos" and vols[0]["files"] == 3
        folders = {r["name"]: r for r in api.scan_children(scan=scan, parent=vols[0]["root_id"])["rows"]}
        win = next(r for n, r in folders.items() if n.startswith("thumbcache_256.db ("))
        assert "Explorer" in win["name"] and "Linux desktop thumbnails" in folders
        rows = api.scan_children(scan=scan, parent=folders["Linux desktop thumbnails"]["id"])["rows"]
        assert [r["name"] for r in rows] == ["IMG_0042.png"]
        e = api.scan_entry(scan=scan, entry=rows[0]["id"])
        assert e["extra"]["original"] == "/home/ann/Pictures/IMG_0042.JPG"
        pics_found = api.scan_children(scan=scan, parent=win["id"])["rows"]
        out = tmp_path / "out"
        job = api.start_recover(scan=scan, entries=[r["id"] for r in pics_found], dest=str(out), options={})
        assert wait_job(api, job["id"], 60)["state"] == "done"
        got = sorted(p.read_bytes() for p in out.rglob("*.jpg"))
        assert got == sorted([pics["a"], pics["c"]])
    finally:
        api.close()
