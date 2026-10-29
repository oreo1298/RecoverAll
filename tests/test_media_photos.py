"""Photos: the JPEG decoder used as a check (media/jpegdec.py), the JPEG repairs built on it (filerepair) and the
previews of camera RAW files (media/rawpreview.py).

The photos are real ones made with ffmpeg (restart markers come from its slice threads); progressive ones are
re-encoded with Pillow or ImageMagick when either is there. The repaired copies are judged by decoding them
with ffmpeg. The RAW files are built here: TIFF structures laid out like a camera's (IFDs first, then the
preview JPEGs and the sensor data), a CR3 of ISO media boxes, a RAF and a HEIC with an EXIF thumbnail."""

from __future__ import annotations

import io
import random
import shutil
import struct
import subprocess
import time

import pytest
from mediakit import decode_check, make_photo, need_ffmpeg

from recoverall.core import filerepair as fr
from recoverall.core.media import jpegdec, rawpreview


def rnd(n: int, seed: int = 1) -> bytes:
    return random.Random(seed).randbytes(n)


TEXT = (b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et "
        b"dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.\n") * 200


def progressive(src, dst):
    """DST: SRC re-encoded as a progressive JPEG (Pillow, else ImageMagick; skips without either)."""
    try:
        from PIL import Image
    except ImportError:
        Image = None
    if Image is not None:
        Image.open(src).save(dst, quality=90, progressive=True)
    elif shutil.which("convert"):
        subprocess.run(["convert", str(src), "-interlace", "JPEG", "-quality", "90", str(dst)], check=True)
    else:
        pytest.skip("neither Pillow nor ImageMagick is installed")
    return dst.read_bytes()


@pytest.fixture(scope="module")
def photos(tmp_path_factory):
    need_ffmpeg("mjpeg")
    d = tmp_path_factory.mktemp("photos")
    noisy = ("-vf", "noise=alls=12:allf=t", "-q:v", "3")
    out = {
        "base": make_photo(d / "base.jpg", "640x480", noisy).read_bytes(),
        "std": make_photo(d / "std.jpg", "480x320", ("-q:v", "4", "-huffman", "default")).read_bytes(),
        "rst": make_photo(d / "rst.jpg", "640x480", noisy + ("-threads", "4", "-slices", "8")).read_bytes(),
        "444": make_photo(d / "444.jpg", "320x240", ("-q:v", "3", "-pix_fmt", "yuvj444p")).read_bytes(),
        "422": make_photo(d / "422.jpg", "322x242", ("-q:v", "3", "-pix_fmt", "yuvj422p")).read_bytes(),
        "thumb": make_photo(d / "thumb.jpg", "160x120", ("-q:v", "5",)).read_bytes(),
        "big": make_photo(d / "big.jpg", "1600x1200", ("-q:v", "4")).read_bytes(),
    }
    out["dir"] = d
    return out


@pytest.fixture(scope="module")
def prog(photos):
    return progressive(photos["dir"] / "base.jpg", photos["dir"] / "prog.jpg")


def segments(data: bytes) -> list[tuple[int, int, int]]:
    pos, out = 2, []
    while True:
        m, length = data[pos + 1], struct.unpack_from(">H", data, pos + 2)[0]
        out.append((m, pos, pos + 2 + length))
        if m == 0xDA:
            return out
        pos += 2 + length


def pixels(path) -> tuple[int, int, bytes]:
    """(width, height, 8-bit grey pixels) of the picture, decoded by ffmpeg."""
    p = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=width,height",
                        "-of", "csv=p=0", str(path)], capture_output=True, text=True)
    w, h = map(int, p.stdout.strip().split(",")[:2])
    raw = subprocess.run(["ffmpeg", "-v", "quiet", "-i", str(path), "-f", "rawvideo", "-pix_fmt", "gray", "-"],
                         capture_output=True).stdout
    return w, h, raw


def fix(tmp_path, name: str, data: bytes, **kw):
    p = tmp_path / name
    p.write_bytes(data)
    a = fr.analyze(p)
    out = tmp_path / ("out-" + name)
    r = fr.repair(p, out, **kw)
    return a, r, (out.read_bytes() if r["out"] else None), out


# ---------------------------------------------------------------------- decoding
def test_decodes_every_kind_of_photo(photos, prog):
    for key in ("base", "std", "rst", "444", "422", "thumb", "big"):
        data = photos[key]
        res = jpegdec.decode_check(data)
        assert res.ok and res.error == "" and res.eoi_offset == len(data) - 2, (key, res.error, res.error_offset)
        assert res.mcus_decoded == res.mcus_total > 0 and res.fraction == 1.0
    assert jpegdec.decode_check(photos["rst"]).restart_interval > 0
    assert jpegdec.decode_check(photos["rst"]).restarts > 0
    f = jpegdec.decode_check(photos["422"]).frame
    assert (f.width, f.height) == (322, 242) and f.mcux == -(-322 // (8 * f.hmax)) and f.mcuy == -(-242 // (8 * f.vmax))
    assert [(c.h, c.v) for c in f.comps] != [(1, 1)] * 3          # chroma subsampled
    res = jpegdec.decode_check(prog)
    assert res.ok and res.progressive and len(res.scans) > 2 and res.complete_scans == len(res.scans)


def test_mjpeg_frame_without_tables(photos):
    data = photos["std"]                         # made with the standard tables: they can be left out
    segs = segments(data)
    bare = data[:2] + b"".join(data[s:e] for m, s, e in segs if m != 0xC4) + data[segs[-1][2]:]
    assert jpegdec.decode_check(bare).ok


def test_finds_where_the_data_stops_being_valid(photos):
    data = photos["base"]
    start = jpegdec.decode_check(data).header_end
    at = (start + len(data)) // 2 // 512 * 512
    res = jpegdec.decode_check(data[:at])
    assert not res.ok and res.error == jpegdec.ERR_CUT and res.error_reason
    assert start < res.good_end <= at and 0 < res.mcus_decoded < res.mcus_total
    for fill in (rnd(4096), TEXT[:4096], photos["big"][20000:24096]):
        res = jpegdec.decode_check(data[:at] + fill + data[at + 4096:])
        assert not res.ok and res.error != jpegdec.ERR_CUT
        assert at <= res.error_offset < at + 4096 + 512, (res.error, res.error_offset - at)
        assert res.good_end <= res.error_offset
    res = jpegdec.decode_check(data[:at] + b"\xff\xd8" + data[at:])
    assert res.error == jpegdec.ERR_MARKER and res.error_offset == at
    # a restart marker out of turn
    rst = bytearray(photos["rst"])
    i = rst.index(b"\xff\xd3")
    rst[i + 1] = 0xD5
    res = jpegdec.decode_check(bytes(rst))
    assert res.error == jpegdec.ERR_RESTART and res.error_offset == i


def test_checkpoint_probe_and_resume(photos, prog):
    for data in (photos["base"], photos["rst"], prog):
        start = jpegdec.decode_check(data).header_end
        x = (start + len(data)) * 2 // 3 // 4096 * 4096
        gap = rnd(8192, x)
        img = data[:x] + gap + data[x:]
        res = jpegdec.decode_check(img)
        assert not res.ok and res.error_offset >= x
        cp = res.checkpoint(x)
        assert cp is not None and cp.offset <= x and cp.scan == len(res.scans) - 1
        head = img[cp.offset:x]
        right = res.probe(cp, head + data[x:x + 8192], 32, 6000 * 8)
        assert right.mcus >= 32 and right.error in ("", jpegdec.ERR_CUT)
        wrong = [res.probe(cp, head + img[x + k:x + k + 8192], 32, 6000 * 8) for k in range(512, 8192, 512)]
        assert all(w.error not in ("", jpegdec.ERR_CUT) for w in wrong)
        res = res.resume(cp, img[:x] + img[x + 8192:], cp.offset)
        assert res.ok and res.mcus_decoded == res.mcus_total


def test_grey_mcus_use_the_photos_own_tables(photos, tmp_path):
    for key in ("base", "rst", "444"):
        data = photos[key]
        res = jpegdec.decode_check(data)
        grey = res.grey(res.scans[0].total)
        assert grey is not None
        out = data[:res.header_end] + grey + b"\xff\xd9"
        if res.restart_interval:                # one interval for the whole picture would be wrong: no DRI
            out = out.replace(b"\xff\xdd\x00\x04", b"\xff\xfe\x00\x04", 1)
        assert jpegdec.decode_check(out).ok
        p = tmp_path / f"grey-{key}.jpg"
        p.write_bytes(out)
        ok, errors = decode_check(p)
        assert ok, errors
        _w, _h, px = pixels(p)
        assert px and min(px) >= 120 and max(px) <= 136


def test_speed(photos):
    data = photos["big"]
    res = jpegdec.decode_check(data)
    t = time.perf_counter()
    res = jpegdec.decode_check(data)
    dt = time.perf_counter() - t
    rate = res.mcus_total / dt
    print(f"\njpegdec: {res.mcus_total} MCUs of a 1600×1200 photo ({len(data) // 1024} KiB) in {dt * 1000:.0f} ms: "
          f"{rate:,.0f} MCUs/s, {len(data) / dt / 1e6:.1f} MB/s")
    assert res.ok and rate > 2000


def test_never_raises_on_garbage(photos, prog):
    r = random.Random(5)
    for data in (photos["base"], photos["rst"], prog):
        for k in range(40):
            bad = bytearray(data)
            for _ in range(r.randrange(1, 30)):
                bad[r.randrange(len(bad))] = r.randrange(256)
            if k % 3 == 0:
                bad = bad[:r.randrange(len(bad))]
            res = jpegdec.decode_check(bytes(bad))
            assert isinstance(res.ok, bool)
            if res.scans:
                cp = res.checkpoint(len(bad) // 2)
                if cp is not None:
                    res.probe(cp, bytes(bad[cp.offset:cp.offset + 4096]), 16, 8000)
    for junk in (b"", b"\xff\xd8", b"\xff\xd8\xff\xc4\x00\x02", rnd(5000), b"\xff\xd8" + rnd(5000)):
        assert not jpegdec.decode_check(junk).ok


# ---------------------------------------------------------------------- repairs
def test_repair_cut_short_says_how_much_is_missing(photos, tmp_path):
    data = photos["base"]
    a, r, out, _p = fix(tmp_path, "cut.jpg", data[:len(data) * 6 // 10])
    assert "cut short" in a["problems"][0] and "% of the photo is missing" in a["problems"][0]
    assert 0.4 < a["info"]["shown"] < 0.75
    assert out == data[:len(data) * 6 // 10] + b"\xff\xd9"


def test_repair_damage_without_restart_markers(photos, tmp_path):
    data = photos["base"]
    at = len(data) // 2 // 512 * 512
    a, r, out, p = fix(tmp_path, "mid.jpg", data[:at] + rnd(4096, 3) + data[at + 4096:])
    assert a["repairable"] and "damaged from byte" in a["problems"][0] and "%" in a["problems"][0]
    ok, errors = decode_check(p)
    assert ok, errors                            # grey MCUs fill the rest: a whole, valid photo
    (tmp_path / "ref.jpg").write_bytes(data)
    w, h, good = pixels(tmp_path / "ref.jpg")
    _w, _h, got = pixels(p)
    shown = a["info"]["shown"]
    rows = int(h * shown) // 16 * 16 - 16        # the MCU rows that decoded are the original's
    assert rows > 0 and got[:rows * w] == good[:rows * w]
    assert set(got[-w * 16:]) <= set(range(124, 133))   # the bottom is grey


def test_repair_skips_damaged_restart_intervals(photos, tmp_path):
    data = photos["rst"]
    res = jpegdec.decode_check(data)
    at = (res.header_end + len(data)) // 2 // 4096 * 4096
    a, r, out, p = fix(tmp_path, "rst.jpg", data[:at] + rnd(4096, 4) + data[at + 4096:])
    assert a["repairable"] and "restart intervals" in a["problems"][0]
    ok, errors = decode_check(p)
    assert ok, errors
    (tmp_path / "ref.jpg").write_bytes(data)
    w, h, good = pixels(tmp_path / "ref.jpg")
    _w, _h, got = pixels(p)
    same = [got[y * w:(y + 1) * w] == good[y * w:(y + 1) * w] for y in range(h)]
    assert all(same[:16]) and all(same[-32:])    # the top and, in its place, the bottom are the original's
    assert 0 < same.count(False) < h // 3        # only the damaged stretch is grey
    assert 0.6 < a["info"]["shown"] < 1


def test_repair_progressive_cut_short(prog, tmp_path):
    a, r, out, p = fix(tmp_path, "prog.jpg", prog[:len(prog) * 2 // 3])
    assert "progressively" in a["problems"][0] and "less sharp" in a["actions"][0]
    ok, errors = decode_check(p)
    assert ok, errors
    res = jpegdec.decode_check(out)
    assert res.ok and res.mcus_decoded == res.mcus_total and out.endswith(b"\xff\xd9")


def test_repair_header_with_garbage_and_broken_tables(photos, tmp_path):
    data = photos["base"]
    segs = segments(data)
    sof = next(s for m, s, e in segs if m == 0xC0)
    a, r, out, _p = fix(tmp_path, "gap.jpg", data[:sof] + rnd(300, 6) + data[sof:])
    assert "between the parts of the photo's header" in a["problems"][0] and out == data
    # a damaged Huffman table: a reference photo from the same camera has the same tables
    dht = next(s for m, s, e in segs if m == 0xC4)
    bad = bytearray(data)
    bad[dht + 25:dht + 35] = rnd(10, 7)
    a, r, out, _p = fix(tmp_path, "dht.jpg", bytes(bad))
    assert "tables" in a["problems"][0] and not r["ok"] and a["info"].get("needs_reference")
    ref = tmp_path / "ref.jpg"
    ref.write_bytes(data)
    a, r, out, _p = fix(tmp_path, "dht2.jpg", bytes(bad), reference=ref)
    assert r["ok"] and out == data and "header of ref.jpg" in r["actions_done"][-1]


def exif_with_thumbnail(thumb: bytes) -> bytes:
    """An APP1 EXIF segment whose IFD1 holds THUMB, like a camera's."""
    ifd1 = 8 + 2 + 12 + 4
    at = ifd1 + 2 + 2 * 12 + 4
    tiff = b"II*\0" + struct.pack("<I", 8) + struct.pack("<H", 1) + struct.pack("<HHII", 0x112, 3, 1, 1) + \
        struct.pack("<I", ifd1) + struct.pack("<H", 2) + struct.pack("<HHII", 0x201, 4, 1, at) + \
        struct.pack("<HHII", 0x202, 4, 1, len(thumb)) + struct.pack("<I", 0) + thumb
    body = b"Exif\0\0" + tiff
    return b"\xff\xe1" + struct.pack(">H", len(body) + 2) + body


def test_repair_saves_the_embedded_preview(photos, tmp_path):
    data, thumb = photos["base"], photos["thumb"]
    app1 = exif_with_thumbnail(thumb)
    photo = data[:2] + app1 + data[2:]
    (tmp_path / "ok.jpg").write_bytes(photo)
    assert fr.analyze(tmp_path / "ok.jpg")["problems"] == []
    tables = 2 + len(app1)
    gone = photo[:tables] + bytes(800) + photo[tables + 800:]       # the tables and the SOS overwritten
    a, r, out, p = fix(tmp_path, "gone.jpg", gone)
    assert r["ok"] and out == thumb and r["info"]["output"] == "preview"
    assert "preview" in r["actions_done"][0] and a["info"]["needs_reference"]
    ok, errors = decode_check(p)
    assert ok, errors
    a, r, out, _p = fix(tmp_path, "header.jpg", photo[:tables + 200])     # cut short after the tables
    assert out == thumb and "cut short" in a["problems"][0]


# ---------------------------------------------------------------------- camera RAW files
class B:
    """A reference to the offset (or, with length=True, the length) of blob I of a Tiff."""
    def __init__(self, i: int, length: bool = False):
        self.i, self.length = i, length


class Ifd:
    """A reference to the offset of IFD K of a Tiff."""
    def __init__(self, k: int):
        self.k = k


class Tiff:
    """A TIFF structure laid out like a camera's: the header, the IFDs with their values, then the blobs
    (preview JPEGs, sensor data). Entry values: ints, tuples, str, bytes, or B/Ifd references."""

    def __init__(self, order: str = "<", head: bytes | None = None, ifd0_at: int = 4):
        self.o = order
        self.head = head or ((b"II*\0" if order == "<" else b"MM\0*") + bytes(4))
        self.ifd0_at = ifd0_at
        self.ifds: list[tuple[list, int | None]] = []
        self.blobs: list[bytes] = []

    def blob(self, data: bytes) -> int:
        self.blobs.append(data)
        return len(self.blobs) - 1

    def ifd(self, entries: list, nxt: int | None = None) -> int:
        self.ifds.append((entries, nxt))
        return len(self.ifds) - 1

    def _raw(self, typ: int, v) -> bytes:
        if isinstance(v, str):
            return v.encode() + b"\0"
        if isinstance(v, bytes):
            return v
        vals = v if isinstance(v, tuple) else (v,)
        return struct.pack(f"{self.o}{len(vals)}{'H' if typ == 3 else 'I'}", *(self._val(x) for x in vals))

    def _val(self, x):
        if isinstance(x, B):
            return len(self.blobs[x.i]) if x.length else self.blob_at[x.i]
        if isinstance(x, Ifd):
            return self.ifd_at[x.k]
        return x

    def build(self) -> bytes:
        o = self.o
        pos = len(self.head)
        self.ifd_at, sizes = [], []
        for entries, _nxt in self.ifds:
            pos += pos & 1
            self.ifd_at.append(pos)
            extra = sum(len(r) + (len(r) & 1) for r in (self._size(t, v) for _tag, t, v in entries) if len(r) > 4)
            sizes.append(2 + 12 * len(entries) + 4 + extra)
            pos += sizes[-1]
        self.blob_at = []
        for b in self.blobs:
            pos += pos & 1
            self.blob_at.append(pos)
            pos += len(b)
        out = bytearray(self.head)
        struct.pack_into(o + "I", out, self.ifd0_at, self.ifd_at[0])
        for k, (entries, nxt) in enumerate(self.ifds):
            out += bytes(self.ifd_at[k] - len(out))
            extra_at = self.ifd_at[k] + 2 + 12 * len(entries) + 4
            body, extra = bytearray(struct.pack(o + "H", len(entries))), bytearray()
            for tag, typ, v in sorted(entries, key=lambda e: e[0]):
                raw = self._raw(typ, v)
                count = len(raw) // {3: 2, 4: 4}.get(typ, 1)
                if len(raw) <= 4:
                    body += struct.pack(o + "HHI", tag, typ, count) + raw.ljust(4, b"\0")
                else:
                    body += struct.pack(o + "HHII", tag, typ, count, extra_at + len(extra))
                    extra += raw + bytes(len(raw) & 1)
            body += struct.pack(o + "I", self.ifd_at[nxt] if nxt is not None else 0)
            out += body + extra
        for i, b in enumerate(self.blobs):
            out += bytes(self.blob_at[i] - len(out)) + b
        return bytes(out)

    def _size(self, typ: int, v) -> bytes:
        if isinstance(v, (str, bytes)):
            return self._raw(typ, v)
        n = len(v) if isinstance(v, tuple) else 1
        return bytes(n * (2 if typ == 3 else 4))


def nef(full: bytes, thumb: bytes) -> bytes:
    """Nikon: IFD0 holds a thumbnail as its strip, sub-IFD 1 the full-size preview, sub-IFD 2 the sensor data."""
    t = Tiff(">")
    j, s, raw = t.blob(full), t.blob(thumb), t.blob(rnd(300_000, 9))
    t.ifd([(0xFE, 4, 1), (0x100, 4, 160), (0x101, 4, 120), (0x103, 3, 6), (0x10F, 2, "NIKON CORPORATION"),
           (0x110, 2, "NIKON D750"), (0x111, 4, B(s)), (0x117, 4, B(s, True)), (0x14A, 4, (Ifd(1), Ifd(2))),
           (0x8769, 4, Ifd(3))])
    t.ifd([(0xFE, 4, 1), (0x103, 3, 6), (0x201, 4, B(j)), (0x202, 4, B(j, True))])
    t.ifd([(0xFE, 4, 0), (0x100, 4, 4000), (0x101, 4, 3000), (0x103, 3, 34713), (0x106, 3, 32803),
           (0x111, 4, B(raw)), (0x117, 4, B(raw, True))])
    t.ifd([(0x9003, 2, "2024:05:06 07:08:09")])
    return t.build()


def cr2(full: bytes, thumb: bytes) -> bytes:
    """Canon CR2: the full-size preview is IFD0's strip, the thumbnail in IFD1, lossless-JPEG sensor data in IFD3."""
    t = Tiff("<", b"II*\0\0\0\0\0CR\x02\0\0\0\0\0")
    j, s, raw = t.blob(full), t.blob(thumb), t.blob(b"\xff\xd8\xff\xc4" + rnd(300_000, 8))
    t.ifd([(0x100, 4, 1600), (0x101, 4, 1200), (0x103, 3, 6), (0x10F, 2, "Canon"), (0x110, 2, "Canon EOS 5D"),
           (0x111, 4, B(j)), (0x117, 4, B(j, True))], nxt=1)
    t.ifd([(0x103, 3, 6), (0x201, 4, B(s)), (0x202, 4, B(s, True))], nxt=2)
    t.ifd([(0x103, 3, 6), (0x111, 4, B(raw)), (0x117, 4, B(raw, True)), (0xC640, 3, (1, 2000, 2000))])
    return t.build()


def dng(full: bytes, thumb: bytes) -> bytes:
    """DNG: a thumbnail in IFD0, the sensor data and a JPEG preview (compression 7, YCbCr) in sub-IFDs."""
    t = Tiff("<")
    s, j, raw = t.blob(thumb), t.blob(full), t.blob(rnd(200_000, 7))
    t.ifd([(0xFE, 4, 1), (0x103, 3, 7), (0x106, 3, 6), (0x111, 4, B(s)), (0x117, 4, B(s, True)),
           (0x10F, 2, "Google"), (0xC612, 1, b"\x01\x04\x00\x00"), (0x14A, 4, (Ifd(1), Ifd(2)))])
    t.ifd([(0xFE, 4, 0), (0x103, 3, 7), (0x106, 3, 32803), (0x111, 4, B(raw)), (0x117, 4, B(raw, True))])
    t.ifd([(0xFE, 4, 1), (0x103, 3, 7), (0x106, 3, 6), (0x111, 4, B(j)), (0x117, 4, B(j, True))])
    return t.build()


def rw2(full: bytes) -> bytes:
    """Panasonic RW2: its own TIFF magic, the preview as a JPEG inside tag 0x2E."""
    t = Tiff("<", b"IIU\0\x08\0\0\0")
    raw = t.blob(rnd(200_000, 6))
    t.ifd([(0x02, 3, 4000), (0x03, 3, 3000), (0x10F, 2, "Panasonic"), (0x2E, 7, full), (0x118, 4, B(raw))])
    return t.build()


def box(typ: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + typ + payload


def cr3(full: bytes, preview: bytes, thumb: bytes) -> bytes:
    """Canon CR3: THMB in the moov's Canon box, PRVW in its own uuid box, the full-size JPEG in mdat."""
    canon = bytes.fromhex("85c0b687820f11e08111f4ce462b6a48")
    prvw_uuid = bytes.fromhex("eaf42b5e1c984b88b9fbb7dc406e4d16")
    cmt1 = box(b"CMT1", b"II*\0" + struct.pack("<I", 8) + struct.pack("<H", 1) +
               struct.pack("<HHII", 0x10F, 2, 4, int.from_bytes(b"Can\0", "little")) + bytes(4))
    thmb = box(b"THMB", bytes(4) + struct.pack(">HHI", 160, 120, len(thumb)) + bytes(4) + thumb)
    moov = box(b"moov", box(b"uuid", canon + cmt1 + thmb) + box(b"trak", bytes(64)))
    prvw = box(b"uuid", prvw_uuid + bytes(8) + box(b"PRVW", bytes(6) + struct.pack(">HH", 1600, 1200) +
                                                    bytes(2) + struct.pack(">I", len(preview)) + preview))
    return box(b"ftyp", b"crx " + bytes(4) + b"crx isom") + moov + prvw + box(b"mdat", full + rnd(200_000, 5))


def raf(full: bytes) -> bytes:
    """Fujifilm RAF: the header says where the JPEG and the sensor data are."""
    head = bytearray(b"FUJIFILMCCD-RAW 0201FF383501" + b"X-T4".ljust(32, b"\0"))
    head += bytes(160 - len(head))
    raw_at = 160 + len(full)
    struct.pack_into(">6I", head, 84, 160, len(full), raw_at, 64, raw_at + 64, 200_000)
    return bytes(head) + full + rnd(200_064, 4)


def test_raw_previews(photos):
    full, thumb = photos["big"], photos["thumb"]
    small = photos["base"]
    cases = {"nef": nef(full, thumb), "cr2": cr2(full, thumb), "dng": dng(full, thumb), "rw2": rw2(full),
             "cr3": cr3(full, small, thumb), "raf": raf(full)}
    for ext, data in cases.items():
        found = rawpreview.previews(data)
        assert found and found[0].width == 1600 and found[0].height == 1200, (ext, found)
        best = rawpreview.best_preview(data)
        assert best.valid and data[best.offset:best.end] == full, ext
        if ext in ("nef", "cr2", "dng", "cr3"):
            assert any(p.width == 160 and p.kind == "thumbnail" for p in found), (ext, found)
        plan = rawpreview.plan_raw(data, f"IMG_0001.{ext}")
        assert not plan.problems and plan.info["preview"]["width"] == 1600, (ext, plan.problems)
    labels = {p.source for p in rawpreview.previews(cases["cr3"])}
    assert {"CR3 preview (PRVW)", "CR3 thumbnail (THMB)"} <= labels
    # the lossless JPEG of a CR2's sensor data isn't a preview
    assert all(p.offset != cases["cr2"].rfind(b"\xff\xd8\xff\xc4") for p in rawpreview.previews(cases["cr2"]))
    # a HEIC has no JPEG inside, but its EXIF thumbnail is one
    heic = box(b"ftyp", b"heic" + bytes(4) + b"mif1heic") + box(b"meta", bytes(64)) + \
        box(b"mdat", struct.pack(">I", 0) + exif_with_thumbnail(thumb)[4:] + rnd(5000, 3))
    found = rawpreview.previews(heic)
    assert len(found) == 1 and found[0].source == "EXIF thumbnail" and found[0].width == 160


def test_damaged_raw_files_give_their_preview(photos, tmp_path):
    full, thumb = photos["big"], photos["thumb"]
    for ext, data in (("nef", nef(full, thumb)), ("cr2", cr2(full, thumb)), ("dng", dng(full, thumb)),
                      ("cr3", cr3(full, photos["base"], thumb)), ("raf", raf(full))):
        cut = data[:len(data) - 150_000]                         # the end of the sensor data is gone
        plan = rawpreview.plan_raw(cut, f"x.{ext}")
        assert plan.problems and "cut short" in plan.problems[0], (ext, plan.problems)
        assert plan.repairable and plan.info["output_ext"] == "jpg" and "preview" in plan.actions[0]
        out = b"".join(cut[p[0]:p[1]] if isinstance(p, tuple) else p for p in plan.build())
        assert out == full, ext
        p = tmp_path / f"preview-{ext}.jpg"
        p.write_bytes(out)
        ok, errors = decode_check(p)
        assert ok, errors
    # the header gone too: the preview is still found by its signature
    data = nef(full, thumb)
    plan = rawpreview.plan_raw(bytes(64) + data[64:], "x.nef")      # the header and IFD0
    out = b"".join(data[p[0]:p[1]] if isinstance(p, tuple) else p for p in plan.build())
    assert plan.repairable and out == full
    # the preview itself cut short: what decodes of it, with an end marker
    at = data.index(full)
    cut = data[:at + len(full) * 3 // 4]
    plan = rawpreview.plan_raw(cut, "x.nef")
    out = b"".join(cut[p[0]:p[1]] if isinstance(p, tuple) else p for p in plan.build())
    assert plan.repairable and out.endswith(b"\xff\xd9") and out.startswith(full[:len(full) // 2])
    for junk in (b"", rnd(10_000), b"II*\0" + rnd(10_000), b"\x00\x00\x00\x18ftypcrx " + rnd(1000)):
        rawpreview.plan_raw(junk, "x.cr2")
        rawpreview.previews(junk)


def test_jpeg_previews_of_a_photo(photos):
    data, thumb = photos["base"], photos["thumb"]
    photo = data[:2] + exif_with_thumbnail(thumb) + data[2:]
    found = rawpreview.previews(photo)
    assert [p.width for p in found] == [160] and found[0].source == "EXIF thumbnail"
    assert photo[found[0].offset:found[0].end] == thumb
    assert rawpreview.best_preview(io.BytesIO(photo).getvalue()).valid
