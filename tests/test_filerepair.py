"""File repair: damage files in the usual ways (cut short, start overwritten, garbage around them, wrong sizes,
wrong checksums) and check that the repaired copies parse — and that the damaged input is never touched."""

import base64
import bz2
import gzip
import hashlib
import io
import lzma
import random
import re
import struct
import wave
import zipfile
import zlib

import pytest

from recoverall.core import filerepair as fr
from recoverall.core.errors import UnsafeOperation


def rnd(n, seed=1):
    r = random.Random(seed)
    return bytes(r.randrange(256) for _ in range(n))


def put(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def fix(tmp_path, name, data, **kw):
    """analyze + repair a file made of DATA; checks the input stays untouched. Returns (analysis, result,
    output bytes or None)."""
    p = put(tmp_path, name, data)
    before = hashlib.sha256(data).hexdigest()
    a = fr.analyze(p)
    out = tmp_path / ("out-" + fr.output_name(p, a["type"]))
    r = fr.repair(p, out, **kw)
    assert hashlib.sha256(p.read_bytes()).hexdigest() == before          # never modified
    assert set(r) >= {"ok", "type", "actions_done", "message", "out"}
    assert r["message"]
    return a, r, (out.read_bytes() if r["out"] else None)


# ---------------------------------------------------------------------- format checkers used by the tests
def jpeg_walk(data):
    """Walk SOI … SOS, the entropy data, … EOI; returns (width, height). The file must end at its EOI."""
    assert data[:2] == b"\xff\xd8"
    pos = 2
    size = None
    while True:
        assert data[pos] == 0xFF, f"no marker at {pos}"
        marker = data[pos + 1]
        length = struct.unpack_from(">H", data, pos + 2)[0]
        if marker in (0xC0, 0xC1, 0xC2):
            size = struct.unpack_from(">HH", data, pos + 5)[::-1]
        pos += 2 + length
        if marker == 0xDA:
            break
    while True:
        m = re.compile(rb"\xff([^\x00\xd0-\xd7\xff])").search(data, pos)
        assert m, "no EOI"
        if m.group(1) == b"\xd9":
            assert m.end() == len(data), "data after EOI"
            return size
        length = struct.unpack_from(">H", data, m.start() + 2)[0]
        assert m.group(1)[0] in (0xC4, 0xDA, 0xDB, 0xDD), f"unexpected marker {m.group(1).hex()}"
        pos = m.start() + 2 + length


def png_walk(data):
    """Signature, chunks with good CRCs, IHDR first, IEND last; returns (width, height, raw pixel data)."""
    assert data[:8] == fr.PNG_SIG
    pos = 8
    idat = b""
    chunks = []
    while pos < len(data):
        length = struct.unpack_from(">I", data, pos)[0]
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        assert struct.unpack_from(">I", data, pos + 8 + length)[0] == zlib.crc32(ctype + body) & 0xFFFFFFFF
        chunks.append(ctype)
        if ctype == b"IHDR":
            w, h = struct.unpack_from(">II", body)
        if ctype == b"IDAT":
            idat += body
        pos += 12 + length
    assert chunks[0] == b"IHDR" and chunks[-1] == b"IEND" and pos == len(data)
    return w, h, zlib.decompress(idat)


def pdf_xref_ok(data):
    """startxref → "xref"; every in-use entry points at "N G obj" with its own number. Returns the count."""
    x = int(re.findall(rb"startxref\s+(\d+)", data)[-1])
    assert data[x:x + 4] == b"xref"
    assert data.rstrip().endswith(b"%%EOF")
    pos = x + 4
    n = 0
    while True:
        m = re.compile(rb"\s*(\d+) (\d+)\n").match(data, pos)
        if not m:
            break
        first, count = int(m.group(1)), int(m.group(2))
        pos = m.end()
        for k in range(count):
            entry = data[pos:pos + 20]
            assert len(entry) == 20 and entry.endswith(b" \n")
            if entry[17:18] == b"n":
                off = int(entry[:10])
                om = re.match(rb"(\d+) (\d+) obj", data[off:off + 30])
                assert om and int(om.group(1)) == first + k, (first + k, data[off:off + 30])
                n += 1
            pos += 20
    assert data[pos:].lstrip().startswith(b"trailer")
    return n


def zip_ok(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert z.testzip() is None
        return z.namelist()


def riff_walk(data, big=False):
    """The outer size matches the file and the chunks tile it exactly; returns [(id, offset, size)]."""
    word = ">I" if big else "<I"
    assert struct.unpack_from(word, data, 4)[0] == len(data) - 8
    pos = 12
    out = []
    while pos < len(data):
        cid = data[pos:pos + 4]
        size = struct.unpack_from(word, data, pos + 4)[0]
        assert pos + 8 + size <= len(data), cid
        out.append((cid, pos, size))
        pos += 8 + size + (size & 1)
    assert pos == len(data) or pos == len(data) + 1
    return out


def decoded(data):
    """The photo decoded by Pillow, when it is installed (CI doesn't need it); else None."""
    try:
        from PIL import Image
    except ImportError:
        return None
    im = Image.open(io.BytesIO(data))
    im.load()
    return im


# ---------------------------------------------------------------------- detection and the API
def test_detect_and_names(tmp_path):
    assert fr.detect(b"\xff\xd8\xff\xe0" + bytes(60)) == "jpg"
    assert fr.detect(fr.PNG_SIG + bytes(20)) == "png"
    assert fr.detect(b"RIFF\0\0\0\0WAVEfmt ") == "wav"
    assert fr.detect(b"RIFF\0\0\0\0AVI LIST") == "avi"
    assert fr.detect(b"FORM\0\0\0\0AIFFCOMM") == "aiff"
    assert fr.detect(bytes(100), "x.docx") == "docx"
    assert fr.detect(bytes(100), "IMG_1.JPG") == "jpg"
    assert fr.detect(rnd(300) + fr.PNG_SIG + bytes(20), "x.bin") == "png"
    assert fr.detect(bytes(50), "x.bin") == ""
    assert fr.output_name("IMG_0001.JPG", "jpg") == "IMG_0001 (repaired).JPG"
    assert fr.output_name("notes.txt.gz", "gz") == "notes (recovered).txt"
    assert fr.output_name("backup.tgz", "gz") == "backup (recovered).tar"
    assert fr.output_name("data.gz", "gz") == "data (recovered)"
    assert fr.output_name("README", "zip") == "README (repaired)"
    a = fr.analyze(put(tmp_path, "x.bin", rnd(500)))
    assert not a["supported"] and not a["repairable"] and a["problems"]


def test_refuses_to_overwrite_input(tmp_path):
    p = put(tmp_path, "a.jpg", photo()[:5000])
    with pytest.raises(UnsafeOperation):
        fr.repair(p, p)
    with pytest.raises(UnsafeOperation):
        fr.repair(p, tmp_path / "." / "a.jpg")


def test_repair_many(tmp_path, ctl):
    paths = [put(tmp_path, "IMG_1.jpg", photo()[:6000]), put(tmp_path, "notes.txt.gz", gzip.compress(rnd(5000))[:2000]),
             put(tmp_path, "fine.jpg", photo()), put(tmp_path, "x.bin", rnd(100))]
    other = tmp_path / "other"
    other.mkdir()
    paths.append(put(other, "IMG_1.jpg", rnd(50) + photo()))
    out = tmp_path / "out"
    results = fr.repair_many(paths, out, ctl=ctl)
    assert [r["path"] for r in results] == [str(p) for p in paths]
    assert results[0]["ok"] and results[0]["out"].endswith("IMG_1 (repaired).jpg")
    assert results[1]["ok"] and results[1]["out"].endswith("notes (recovered).txt")
    assert results[2]["ok"] and results[2]["out"] is None          # nothing wrong
    assert not results[3]["ok"]
    assert results[4]["ok"] and results[4]["out"].endswith("IMG_1 (repaired) 2.jpg")
    assert (out / "IMG_1 (repaired) 2.jpg").read_bytes() == photo()
    assert ctl.warnings and ctl.messages[-1].startswith("3 of 5 files repaired")


# ---------------------------------------------------------------------- JPEG
def photo():
    return base64.b64decode("".join(PHOTO_B64))


def thumb():
    return base64.b64decode("".join(THUMB_B64))


def segments(data):
    pos, out = 2, []
    while True:
        m, length = data[pos + 1], struct.unpack_from(">H", data, pos + 2)[0]
        out.append((m, pos, pos + 2 + length))
        if m == 0xDA:
            return out
        pos += 2 + length


def with_exif_thumbnail(data):
    app1 = b"Exif\x00\x00" + bytes(64) + thumb() + bytes(32)
    return data[:2] + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1 + data[2:]


def test_jpeg_samples_are_fine(tmp_path):
    assert jpeg_walk(photo()) == (96, 72)
    assert jpeg_walk(thumb()) == (32, 24)
    for name, data in (("p.jpg", photo()), ("t.jpg", with_exif_thumbnail(photo())), ("mpf.jpg", photo() + thumb())):
        a = fr.analyze(put(tmp_path, name, data))
        assert a["type"] == "jpg" and a["problems"] == [], (name, a)


def test_jpeg_garbage_around(tmp_path):
    a, r, out = fix(tmp_path, "lead.jpg", rnd(1000) + photo())
    assert a["repairable"] and "before the start" in a["problems"][0]
    assert out == photo()
    _a, r, out = fix(tmp_path, "trail.jpg", photo() + rnd(3000))
    assert out == photo() and r["actions_done"]
    _a, r, out = fix(tmp_path, "zeros.jpg", photo() + bytes(4096))
    assert out == photo() and "zeros" in r["problems"][0]


def test_jpeg_cut_short(tmp_path):
    a, r, out = fix(tmp_path, "cut.jpg", photo()[:6000])
    assert "cut short" in a["problems"][0]
    assert out == photo()[:6000] + b"\xff\xd9"
    assert jpeg_walk(out) == (96, 72)
    # a cut-short file padded with zeros (the rest of its last cluster): the zeros go
    _a, _r, out = fix(tmp_path, "cut0.jpg", photo()[:6000] + bytes(4096))
    assert out == photo()[:6000] + b"\xff\xd9"
    # another photo starts where this one's data stops
    a, _r, out = fix(tmp_path, "two.jpg", photo()[:6000] + thumb())
    assert "another file" in a["problems"][0]
    assert out == photo()[:6000] + b"\xff\xd9"
    im = decoded(out)
    assert im is None or im.size == (96, 72)


def test_jpeg_missing_huffman_tables(tmp_path):
    p = photo()
    segs = segments(p)
    assert sum(1 for m, _s, _e in segs if m == 0xC4) == 4
    mjpeg = p[:2] + b"".join(p[s:e] for m, s, e in segs if m != 0xC4) + p[segs[-1][2]:]
    a, _r, out = fix(tmp_path, "frame.jpg", mjpeg)
    assert "Huffman" in a["problems"][0] and a["repairable"]
    assert jpeg_walk(out) == (96, 72)
    assert out.count(b"\xff\xc4") == 1 and fr.standard_dht() in out
    if decoded(p) is not None:                   # made with the standard tables: identical pixels
        assert decoded(p).tobytes() == decoded(out).tobytes()


def test_jpeg_damaged_header_rebuilt_from_tables(tmp_path):
    p = with_exif_thumbnail(photo())
    bad = bytearray(p)
    bad[4:6] = b"\x00\x05"                       # the EXIF segment's length is wrong
    a, r, out = fix(tmp_path, "exif.jpg", bytes(bad))
    assert a["repairable"] and "header" in a["problems"][0]
    assert jpeg_walk(out) == (96, 72)            # the main photo, not the thumbnail
    assert out.endswith(photo()[segments(photo())[1][1]:])
    # the start marker and the beginning of the EXIF block overwritten with zeros
    bad = bytearray(p)
    bad[:300] = bytes(300)
    _a, r, out = fix(tmp_path, "zero.jpg", bytes(bad))
    assert r["ok"] and jpeg_walk(out) == (96, 72)
    if decoded(out) is not None:
        assert decoded(out).tobytes() == decoded(photo()).tobytes()


def test_jpeg_header_transplant(tmp_path):
    ref = put(tmp_path, "ref.jpg", photo())
    # the header is gone, the image data after its SOS is intact
    p = photo()
    sos = segments(p)[-1]
    bad = bytes(sos[1]) + p[sos[1]:]              # zeros up to the SOS
    bad = bytes(sos[1] + 12) + p[sos[1] + 12:]     # ... and the SOS itself
    a, r, _out = fix(tmp_path, "nohdr.jpg", bad)
    assert not a["repairable"] and "reference" in a["note"] and not r["ok"]
    # the first 4 KiB overwritten: header and the start of the image data are lost
    bad = bytes(4096) + p[4096:]
    a, r, out = fix(tmp_path, "over.jpg", bad, reference=ref)
    assert not a["repairable"]
    assert r["ok"] and "guess" in r["message"]
    assert jpeg_walk(out) == (96, 72)
    start = r["info"]["data_offset"]
    assert start >= 4096 and p[start - 2:start - 1] == b"\xff" and 0xD0 <= p[start - 1] <= 0xD7   # after a restart marker
    assert out == p[:sos[2]] + p[start:]
    im = decoded(out)
    assert im is None or im.size == (96, 72)
    # the user knows better where the data starts
    _a, r, out = fix(tmp_path, "over2.jpg", bad, reference=ref, data_offset=5000)
    assert out == p[:sos[2]] + p[5000:]
    # a reference that is no photo
    _a, r, _out = fix(tmp_path, "over3.jpg", bad, reference=put(tmp_path, "notjpeg.jpg", rnd(3000)))
    assert not r["ok"] and "reference" in r["message"]


def test_jpeg_nothing_left(tmp_path):
    a, r, _out = fix(tmp_path, "hdr.jpg", photo()[:400])
    assert not a["repairable"] and not r["ok"]
    a, r, _out = fix(tmp_path, "zero.jpg", bytes(5000))
    assert not a["repairable"] and not r["ok"]


# ---------------------------------------------------------------------- PNG
def chunk(t, d):
    return fr.png_chunk(t, d)


def make_png(w=40, h=30, color=2, seed=3):
    channels = {0: 1, 2: 3, 6: 4}[color]
    r = random.Random(seed)
    raw = b"".join(b"\x00" + bytes(r.randrange(256) for _ in range(w * channels)) for _ in range(h))
    data = fr.PNG_SIG + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, color, 0, 0, 0)) + \
        chunk(b"tEXt", b"Comment\x00made for a test")
    z = zlib.compress(raw)
    for i in range(0, len(z), 1000):             # several IDAT chunks, like real encoders
        data += chunk(b"IDAT", z[i:i + 1000])
    return data + chunk(b"IEND", b""), raw


def test_png_checksums_and_garbage(tmp_path):
    png, raw = make_png()
    assert fr.analyze(put(tmp_path, "ok.png", png))["problems"] == []
    bad = bytearray(png)
    t = png.index(b"tEXt")
    crc_at = t + 4 + struct.unpack_from(">I", png, t - 4)[0]
    bad[crc_at] ^= 0x55                          # a wrong checksum on the text chunk
    i = png.index(b"IDAT")
    bad[i + 4 + 1000] ^= 0x55                    # ... and on the first IDAT (its CRC field)
    a, _r, out = fix(tmp_path, "crc.png", bytes(bad))
    assert "checksum" in a["problems"][0]
    assert out == png
    a, _r, out = fix(tmp_path, "trail.png", png + rnd(777))
    assert out == png and "777 bytes" in a["problems"][0]
    a, _r, out = fix(tmp_path, "lead.png", rnd(300) + png)
    assert out == png
    bad = bytearray(png)
    bad[4:6] = b"\n\n"                           # a text-mode transfer mangled the signature
    _a, _r, out = fix(tmp_path, "sig.png", bytes(bad))
    assert out == png


@pytest.mark.parametrize("color", [2, 6, 0])
def test_png_cut_short(tmp_path, color):
    png, raw = make_png(color=color)
    a, r, out = fix(tmp_path, "cut.png", png[:len(png) * 2 // 3])
    assert a["repairable"] and any("rows" in p for p in a["problems"])
    w, h, pixels = png_walk(out)
    assert (w, h) == (40, 30) and len(pixels) == len(raw)
    good = r["info"]["rows"]
    stride = len(raw) // 30
    assert 5 < good < 30
    assert pixels[:good * stride] == raw[:good * stride]
    assert pixels[good * stride:] == bytes(len(raw) - good * stride)


def test_png_damaged_data(tmp_path):
    png, raw = make_png()
    bad = bytearray(png)
    i = png.index(b"IDAT")
    for k in range(1500, 1600):
        bad[i + k] = 0xFF                        # a damaged stretch inside the second IDAT
    _a, r, out = fix(tmp_path, "dmg.png", bytes(bad))
    w, h, pixels = png_walk(out)
    good = r["info"]["rows"]
    stride = len(raw) // 30
    assert pixels[:good * stride] == raw[:good * stride] and len(pixels) == len(raw)


def test_png_interlaced_cut(tmp_path):
    r = random.Random(5)
    w, h = 17, 11
    rows = fr._png_rows(w, h, 8, 2, 1)
    raw = b"".join(b"\x00" + bytes(r.randrange(256) for _ in range(n - 1)) for _s, n in rows)
    png = fr.PNG_SIG + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 1)) + \
        chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
    _a, res, out = fix(tmp_path, "il.png", png[:len(png) // 2])
    ww, hh, pixels = png_walk(out)
    assert (ww, hh) == (w, h) and len(pixels) == len(raw)
    good = res["info"]["rows"]
    end = rows[good - 1][0] + rows[good - 1][1]
    assert pixels[:end] == raw[:end]


# ---------------------------------------------------------------------- GIF
def make_gif(blocks=5):
    lsd = struct.pack("<HHBBB", 8, 8, 0x80, 0, 0) + b"\x00\x00\x00\xff\xff\xff"
    gce = b"\x21\xf9\x04\x00\x00\x00\x00\x00"
    data = b"".join(bytes([50]) + rnd(50, seed=k) for k in range(blocks))
    image = b"\x2c" + struct.pack("<HHHHB", 0, 0, 8, 8, 0) + b"\x02" + data + b"\x00"
    return b"GIF89a" + lsd + gce + image + b"\x3b"


def test_gif(tmp_path):
    gif = make_gif()
    assert fr.analyze(put(tmp_path, "ok.gif", gif))["problems"] == []
    _a, _r, out = fix(tmp_path, "trail.gif", gif + rnd(99))
    assert out == gif
    a, _r, out = fix(tmp_path, "cut.gif", gif[:-60])        # cut inside the image data
    assert "frame 1" in a["problems"][0]
    keep = len(gif) - 2 - 2 * 51                             # the three complete sub-blocks
    assert out == gif[:keep] + b"\x00\x3b"
    _a, _r, out = fix(tmp_path, "notrailer.gif", gif[:-1])
    assert out == gif


# ---------------------------------------------------------------------- ZIP family
def make_zip(n=6, seed=2):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(n):
            z.writestr(f"dir/file{i}.txt", (f"hello {i} " * 300).encode() + rnd(2000, seed + i))
        z.writestr("stored.bin", rnd(3000, seed), compress_type=zipfile.ZIP_STORED)
        z.writestr("bz.txt", b"bzip2 " * 500, compress_type=zipfile.ZIP_BZIP2)
    return b.getvalue()


def test_zip_cut_short(tmp_path):
    data = make_zip()
    assert fr.analyze(put(tmp_path, "ok.zip", data))["problems"] == []
    a, r, out = fix(tmp_path, "cut.zip", data[:len(data) * 2 // 3])
    assert a["repairable"] and any("table of contents" in p for p in a["problems"])
    names = zip_ok(out)
    assert "dir/file0.txt" in names and len(names) >= 3
    with zipfile.ZipFile(io.BytesIO(data)) as z, zipfile.ZipFile(io.BytesIO(out)) as y:
        for n in names:
            assert y.read(n) == z.read(n)


def test_zip_damaged_member_and_garbage(tmp_path):
    data = make_zip()
    bad = bytearray(data)
    at = data.index(b"dir/file2.txt") + 60
    bad[at:at + 30] = bytes(30)
    a, _r, out = fix(tmp_path, "crc.zip", bytes(bad))
    assert "dir/file2.txt" in a["problems"][0] and a["info"]["lost"] == ["dir/file2.txt"]
    names = zip_ok(out)
    assert "dir/file2.txt" not in names and len(names) == 7
    _a, _r, out = fix(tmp_path, "trail.zip", data + rnd(500))
    assert len(zip_ok(out)) == 8
    _a, _r, out = fix(tmp_path, "lead.zip", rnd(700) + data)
    assert len(zip_ok(out)) == 8
    a, _r, out = fix(tmp_path, "start.zip", bytes(4096) + data[4096:])      # the first members overwritten
    assert a["info"]["lost"] and len(zip_ok(out)) == 8 - len(a["info"]["lost"])


def test_zip_data_descriptors(tmp_path):
    class Stream(io.RawIOBase):           # not seekable: zipfile writes data descriptors
        def __init__(self):
            self.data = bytearray()

        def writable(self):
            return True

        def write(self, b):
            self.data += b
            return len(b)

    s = Stream()
    with zipfile.ZipFile(s, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(5):
            with z.open(f"s{i}.txt", "w") as f:
                f.write((f"stream {i} " * 300).encode() + rnd(1500, i))
    data = bytes(s.data)
    assert struct.unpack_from("<H", data, 6)[0] & 8
    _a, _r, out = fix(tmp_path, "desc.zip", data[:len(data) * 3 // 4])
    names = zip_ok(out)
    assert names[:3] == ["s0.txt", "s1.txt", "s2.txt"]


def test_zip_stored_archive_inside(tmp_path):
    inner = make_zip(2, seed=9)
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("a.txt", b"outer " * 100)
        z.writestr("inner.zip", inner)                     # stored: its headers are visible in the outer file
        z.writestr("b.txt", b"more " * 100)
    data = b.getvalue()
    _a, _r, out = fix(tmp_path, "nest.zip", data[:-30])
    assert zip_ok(out) == ["a.txt", "inner.zip", "b.txt"]


def test_docx_and_odt(tmp_path):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        z.writestr("_rels/.rels", "<Relationships/>")
        z.writestr("word/document.xml", "<w:document>" + "text " * 2000 + "</w:document>")
        z.writestr("word/styles.xml", "<w:styles/>" * 100)
        z.writestr("docProps/core.xml", "<cp:coreProperties/>")
    data = b.getvalue()
    a, r, out = fix(tmp_path, "report.docx", bytes(40) + data[40:])      # the first member's header is gone
    assert a["type"] == "docx"
    assert "[Content_Types].xml" in " ".join(a["problems"]) and r["ok"]
    names = zip_ok(out)
    assert "[Content_Types].xml" in names and "word/document.xml" in names
    with zipfile.ZipFile(io.BytesIO(out)) as z:
        ct = z.read("[Content_Types].xml").decode()
    assert 'PartName="/word/document.xml"' in ct and "wordprocessingml.document.main+xml" in ct
    assert 'PartName="/docProps/core.xml"' in ct

    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("content.xml", "<office:document-content/>" * 50)
        z.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        z.writestr("META-INF/manifest.xml", "<manifest/>")
    _a, _r, out = fix(tmp_path, "letter.odt", b.getvalue() + rnd(20))
    with zipfile.ZipFile(io.BytesIO(out)) as z:
        first = z.infolist()[0]
        assert first.filename == "mimetype" and first.compress_type == zipfile.ZIP_STORED
        assert z.read("mimetype") == b"application/vnd.oasis.opendocument.text"
    assert out[30:38] == b"mimetype"


# ---------------------------------------------------------------------- PDF
def make_pdf(objs, header=b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"):
    out = header
    offsets = {}
    for n, body in objs:
        offsets[n] = len(out)
        out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
    x = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % offsets[n] for n, _ in objs)
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, x)
    return out


def sample_pdf():
    content = b"BT /F1 24 Tf 72 720 Td (Hello, endobj 7 0 obj inside a stream) Tj ET"
    return make_pdf([(1, b"<< /Type /Catalog /Pages 2 0 R >>"), (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
                     (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>"),
                     (4, b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream"),
                     (5, b"<< /Producer (RecoverAll test) /Title (A test) >>"),
                     (6, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")])


def test_pdf_xref_rebuilt(tmp_path):
    pdf = sample_pdf()
    assert pdf_xref_ok(pdf) == 6
    assert fr.analyze(put(tmp_path, "ok.pdf", pdf))["problems"] == []
    a, _r, out = fix(tmp_path, "noxref.pdf", pdf[:pdf.index(b"xref")])
    assert a["repairable"] and "missing" in a["problems"][0]
    assert pdf_xref_ok(out) == 6
    assert out.startswith(pdf[:pdf.index(b"xref")])
    assert re.search(rb"/Root 1 0 R", out) and re.search(rb"/Info 5 0 R", out)
    # a partial object at the end
    cut = pdf[:pdf.index(b"6 0 obj") + 20]
    a, _r, out = fix(tmp_path, "cut.pdf", cut)
    assert any("incomplete" in p for p in a["problems"])
    assert pdf_xref_ok(out) == 5 and b"6 0 obj" not in out


def test_pdf_wrong_offsets_and_header(tmp_path):
    pdf = sample_pdf()
    x = int(re.findall(rb"startxref\s+(\d+)", pdf)[-1])
    first = re.search(rb"(\d{10}) 00000 n", pdf[x:])
    bad = pdf[:x] + pdf[x:].replace(first.group(0), b"%010d 00000 n" % (int(first.group(1)) + 5), 1)
    a, _r, out = fix(tmp_path, "shift.pdf", bad)
    assert "wrong places" in a["problems"][0]
    assert pdf_xref_ok(out) == 6
    # the start of the file (the header) overwritten
    start = pdf.index(b"1 0 obj")
    a, _r, out = fix(tmp_path, "nohdr.pdf", bytes(start) + pdf[start:pdf.index(b"xref")])
    assert any("header" in p for p in a["problems"])
    assert out.startswith(b"%PDF-") and pdf_xref_ok(out) == 6
    # the catalog is found again when no trailer says where it is
    noroot = pdf[:pdf.index(b"xref")].replace(b"/Type /Catalog", b"/Type  /Catalog")
    _a, _r, out = fix(tmp_path, "noroot.pdf", noroot)
    assert b"/Root 1 0 R" in out


def test_pdf_xref_stream(tmp_path):
    """A PDF 1.5 cross-reference stream (FlateDecode, PNG Up predictor) is checked, not rebuilt."""
    out = b"%PDF-1.5\n"
    offs = {}
    for n, body in [(1, b"<< /Type /Catalog /Pages 2 0 R >>"), (2, b"<< /Type /Pages /Kids [] /Count 0 >>")]:
        offs[n] = len(out)
        out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
    offs[3] = len(out)
    rows = [b"\x00\x00\x00\xff"] + [b"\x01" + offs[n].to_bytes(2, "big") + b"\x00" for n in (1, 2, 3)]
    prev = bytes(4)
    data = b""
    for row in rows:
        data += b"\x02" + bytes((a - b) & 0xFF for a, b in zip(row, prev))
        prev = row
    comp = zlib.compress(data)
    out += b"3 0 obj\n<< /Type /XRef /Size 4 /W [1 2 1] /Root 1 0 R /Filter /FlateDecode /DecodeParms " \
           b"<< /Predictor 12 /Columns 4 >> /Length %d >>\nstream\n" % len(comp) + comp + b"\nendstream\nendobj\n"
    out += b"startxref\n%d\n%%%%EOF\n" % offs[3]
    assert fr.analyze(put(tmp_path, "x15.pdf", out))["problems"] == []
    bad = out.replace(b"/Count 0 >>", b"/Count 0  >>")       # object 3 moves: the stream points wrong
    bad = bad.replace(b"startxref\n%d" % offs[3], b"startxref\n%d" % (offs[3] + 1))
    a, _r, fixed = fix(tmp_path, "x15b.pdf", bad)
    assert a["problems"] and pdf_xref_ok(fixed) == 3


# ---------------------------------------------------------------------- RIFF and AIFF
def make_wav(frames=4000):
    b = io.BytesIO()
    with wave.open(b, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(8000)
        w.writeframes(rnd(frames * 4, 7))
    return b.getvalue()


def wav_frames(data):
    with wave.open(io.BytesIO(data)) as w:
        n = w.getnframes()
        assert len(w.readframes(n + 10)) == n * 4
        return n


def test_wav(tmp_path):
    wav = make_wav()
    assert fr.analyze(put(tmp_path, "ok.wav", wav))["problems"] == []
    a, _r, out = fix(tmp_path, "cut.wav", wav[:10001])
    assert "cut short" in a["problems"][0] and len(a["problems"]) == 1
    assert wav_frames(out) == (10001 - 44) // 4 and riff_walk(out)
    assert out == wav[:44 - 8] + struct.pack("<I", 9956) + wav[40 + 4:44 + 9956] or \
        out[44:] == wav[44:44 + 9956]
    for size in (b"\x00\x00\x00\x00", b"\xff\xff\xff\xff"):  # a recording that was never finished
        bad = bytearray(wav)
        bad[4:8] = size
        bad[40:44] = size
        a, _r, out = fix(tmp_path, "unfinished.wav", bytes(bad))
        assert "unfinished" in a["problems"][0]
        assert out == wav
    a, _r, out = fix(tmp_path, "trail.wav", wav + rnd(301))
    assert out == wav


def make_avi(frames=6):
    jpeg = photo()
    movi = b"".join(b"00dc" + struct.pack("<I", len(jpeg)) + jpeg + (b"\0" if len(jpeg) & 1 else b"")
                    for _ in range(frames))
    movi_list = b"LIST" + struct.pack("<I", len(movi) + 4) + b"movi" + movi
    avih = b"avih" + struct.pack("<I", 56) + struct.pack("<14I", 200000, 0, 0, 0x10, frames, 0, 1, 0, 96, 72, 0, 0,
                                                         0, 0)
    strh = b"strh" + struct.pack("<I", 56) + b"vidsMJPG" + bytes(48)
    strl = b"LIST" + struct.pack("<I", 4 + len(strh)) + b"strl" + strh
    hdrl = b"LIST" + struct.pack("<I", 4 + len(avih) + len(strl)) + b"hdrl" + avih + strl
    idx, _n = fr._avi_index(b"RIFF\0\0\0\0AVI " + hdrl + movi_list, 12 + len(hdrl), 12 + len(hdrl) + len(movi_list))
    body = b"AVI " + hdrl + movi_list + idx
    return b"RIFF" + struct.pack("<I", len(body)) + body


def test_avi(tmp_path):
    avi = make_avi()
    chunks = riff_walk(avi)
    assert [c[0] for c in chunks] == [b"LIST", b"LIST", b"idx1"]
    assert fr.analyze(put(tmp_path, "ok.avi", avi))["problems"] == []
    a, _r, out = fix(tmp_path, "cut.avi", avi[:len(avi) * 2 // 3])
    assert any("index" in p for p in a["problems"])
    chunks = riff_walk(out)
    assert [c[0] for c in chunks] == [b"LIST", b"LIST", b"idx1"]
    _id, idx_at, idx_size = chunks[-1]
    movi = chunks[1][1] + 8
    frames = 0
    for k in range(idx_size // 16):
        cid, flags, off, size = struct.unpack_from("<4sIII", out, idx_at + 8 + 16 * k)
        assert out[movi + off:movi + off + 4] == cid == b"00dc"
        assert struct.unpack_from("<I", out, movi + off + 4)[0] == size
        assert jpeg_walk(out[movi + off + 8:movi + off + 8 + size]) == (96, 72)
        frames += 1
    assert frames == len(avi) * 2 // 3 // len(photo())
    assert struct.unpack_from("<I", out, out.index(b"avih") + 24)[0] == frames


def test_webp_and_aiff(tmp_path):
    vp8 = b"VP8 " + struct.pack("<I", 1000) + rnd(1000)
    webp = b"RIFF" + struct.pack("<I", 4 + len(vp8)) + b"WEBP" + vp8
    _a, _r, out = fix(tmp_path, "img.webp", webp + rnd(64))
    assert out == webp
    bad = webp[:4] + struct.pack("<I", 123456) + webp[8:]
    _a, _r, out = fix(tmp_path, "img2.webp", bad)
    assert out == webp

    frames = 3000
    comm = b"COMM" + struct.pack(">IHIH", 18, 2, frames, 16) + b"\x40\x0e\xac\x44" + bytes(6)
    ssnd = b"SSND" + struct.pack(">III", 8 + frames * 4, 0, 0) + rnd(frames * 4)
    aiff = b"FORM" + struct.pack(">I", 4 + len(comm) + len(ssnd)) + b"AIFF" + comm + ssnd
    assert fr.analyze(put(tmp_path, "ok.aiff", aiff))["problems"] == []
    a, _r, out = fix(tmp_path, "cut.aiff", aiff[:7003])
    assert "cut short" in a["problems"][0]
    chunks = riff_walk(out, big=True)
    ssnd_size = chunks[-1][2]
    kept = (ssnd_size - 8) // 4
    assert kept == (7003 - 12 - 26 - 16) // 4
    assert struct.unpack_from(">I", out, 12 + 8 + 2)[0] == kept      # COMM numSampleFrames


# ---------------------------------------------------------------------- compressed files
TEXT = b"".join(b"line %d of a long text file\n" % i for i in range(20000))


def test_gzip(tmp_path):
    gz = gzip.compress(TEXT)
    assert fr.analyze(put(tmp_path, "ok.txt.gz", gz))["problems"] == []
    a, r, out = fix(tmp_path, "notes.txt.gz", gz[:len(gz) // 2])
    assert a["repairable"] and "cut short" in a["problems"][0]
    assert r["out"].endswith("notes (recovered).txt")
    assert len(out) > len(TEXT) // 4 and TEXT.startswith(out)
    assert len(out) == a["info"]["readable"]
    bad = bytearray(gz)
    bad[len(gz) // 2] ^= 0xFF
    a, _r, out = fix(tmp_path, "dmg.txt.gz", bytes(bad))
    assert "damaged" in a["problems"][0]
    good = len(TEXT) // 4
    assert len(out) > good and out[:good] == TEXT[:good]
    # two members, the second cut short
    a, _r, out = fix(tmp_path, "two.gz", gz + gzip.compress(rnd(5000))[:1000])
    assert "cut short" in a["problems"][0] and out.startswith(TEXT) and len(out) > len(TEXT)


def test_bz2_xz(tmp_path):
    data = rnd(250000, 4)
    bz = bz2.compress(data, 1)                   # 100 kB blocks: the complete ones can be read
    a, _r, out = fix(tmp_path, "x.bin.bz2", bz[:len(bz) * 3 // 4])
    assert a["repairable"] and len(out) >= 90000 and data.startswith(out)
    xz = lzma.compress(TEXT)
    _a, _r, out = fix(tmp_path, "x.txt.xz", xz[:len(xz) // 2])
    assert len(out) > 1000 and TEXT.startswith(out)


# ---------------------------------------------------------------------- MP3 and MP4
def mp3_sizes(n=60):
    """MPEG-1 Layer III, 128 kbit/s, 44.1 kHz: 417 bytes, 418 with padding."""
    return [144 * 128000 // 44100 + (1 if i % 3 == 0 else 0) for i in range(n)]


def mp3_frames(n=60):
    out = b""
    for i, size in enumerate(mp3_sizes(n)):
        pad = size - 417
        out += bytes([0xFF, 0xFB, 0x90 | (pad << 1), 0x64]) + rnd(size - 4, i)
    return out


def test_mp3(tmp_path):
    frames = mp3_frames()
    id3 = b"ID3\x03\x00\x00" + bytes([0, 0, 0, 20]) + bytes(20)
    tag = b"TAG" + b"A title".ljust(125, b"\0")
    mp3 = id3 + frames + tag
    assert fr.analyze(put(tmp_path, "ok.mp3", mp3))["problems"] == []
    _a, _r, out = fix(tmp_path, "lead.mp3", rnd(999) + frames + tag)
    assert out == frames + tag
    _a, _r, out = fix(tmp_path, "trail.mp3", id3 + frames + rnd(5000))
    assert out == id3 + frames
    _a, _r, out = fix(tmp_path, "tagged.mp3", id3 + frames + rnd(300) + tag)
    assert out == id3 + frames + tag
    a, _r, out = fix(tmp_path, "cut.mp3", id3 + frames[:-100])
    assert "last frame" in a["problems"][0]
    assert out == id3 + frames[:sum(mp3_sizes(59))]
    # a damaged stretch in the middle
    first20, first25 = sum(mp3_sizes(20)), sum(mp3_sizes(25))
    bad = id3 + frames[:first20] + bytes(first25 - first20) + frames[first25:] + tag
    a, _r, out = fix(tmp_path, "mid.mp3", bad)
    assert "damaged stretch" in a["problems"][0]
    assert out == id3 + frames[:first20] + frames[first25:] + tag


def box(t, body):
    return struct.pack(">I", 8 + len(body)) + t + body


def test_mp4(tmp_path):
    ftyp = box(b"ftyp", b"isom\0\0\x02\0isomiso2mp41")
    mdat = box(b"mdat", rnd(5000))
    moov = box(b"moov", box(b"mvhd", bytes(100)))
    mp4 = ftyp + mdat + moov
    assert fr.analyze(put(tmp_path, "ok.mp4", mp4))["problems"] == []
    _a, _r, out = fix(tmp_path, "trail.mp4", mp4 + rnd(77))
    assert out == mp4
    a, r, _out = fix(tmp_path, "nomoov.mp4", ftyp + mdat)
    assert not a["repairable"] and "moov" in a["problems"][0] and "reference" in a["note"]
    assert not r["ok"] and r["out"] is None
    a, _r, out = fix(tmp_path, "cut.mp4", ftyp + moov + mdat[:3000])
    assert out == ftyp + moov + struct.pack(">I", 3000) + mdat[4:3000]


# ---------------------------------------------------------------------- robustness
def test_fuzz_never_raises(tmp_path):
    png, _raw = make_png(20, 10)
    samples = {"a.jpg": with_exif_thumbnail(photo()), "b.png": png, "c.zip": make_zip(3), "d.pdf": sample_pdf(),
               "e.wav": make_wav(500), "f.avi": make_avi(2), "g.gif": make_gif(), "h.txt.gz": gzip.compress(TEXT[:20000]),
               "i.mp3": mp3_frames(10), "j.mp4": box(b"ftyp", b"isom") + box(b"mdat", rnd(500)) + box(b"moov", b"")}
    r = random.Random(11)
    for name, data in samples.items():
        for k in range(12):
            bad = bytearray(data)
            what = k % 4
            if what == 0:
                bad = bad[:r.randrange(1, len(bad))]
            elif what == 1:
                for _ in range(20):
                    bad[r.randrange(len(bad))] = r.randrange(256)
            elif what == 2:
                at = r.randrange(len(bad))
                bad[at:at + 512] = rnd(512, k)
            else:
                at = r.randrange(len(bad))
                bad = bad[:at] + rnd(r.randrange(1, 3000), k) + bad[at:]
            p = put(tmp_path, f"{k}-{name}", bytes(bad))
            a = fr.analyze(p)
            assert isinstance(a["problems"], list)
            res = fr.repair(p, tmp_path / f"out-{k}-{name}", reference=put(tmp_path, "ref.jpg", photo()))
            assert res["ok"] in (True, False)
            if res["out"]:
                assert (tmp_path / f"out-{k}-{name}").exists()


# ---------------------------------------------------------------------- sample photos
# Made with Pillow: 96×72, quality 85, no chroma subsampling, the standard Huffman tables and a restart marker
# after every row of blocks; and a 32×24 one used as an EXIF thumbnail.
PHOTO_B64 = (
    "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"
    "vZLuzhs9Ssb2PTWu7a1M5ilafzFj2hXUkNGi7kjJDPCzpkeWnBGtgq8vZ0pKVCTvyrljLWUVKUWlP2l9aii5QUoKai6ji5LxaOEnQjSlFKMU"
    "pOUW1Tm21bmcbw5VBNpR9yKakk+S05//1uRay8MO0dpcRPbXWoyPBCfsfniJdqxxDDKjyttd5NykPl42YSNtNenif7XxGKjh8RafsKajUXPG"
    "9Tnkmm06klGXOoRqL3VFRlyVYqUUvnMNi8bRcqkqkW4crbckm2uaU1JxlNQV4+zfNdNKShy+8lPqDaBeG3GpNLbWUVzJb/2YYBbfYnYAzNzC"
    "WldHeMGI9134VG2ryRjmlOnXq4adGTmvflKMfaSau4qS9+nThJ8t5tqKaUJSjX5pP0MuWYYFJ0V78krzbUuflTVKLSlFpSipWk0lJNRcnJKT"
    "n1mSbxFHY/avOeO7iSCxubyZ7tzCk372WJlWMGRsDAZBK4TadrPGr+PXeEp1a1SldVHyzdrvWUZNQk3Uqe5FNJTUoqLirxXvzj61CosJWd6f"
    "8NuU1FqOrj7t1eVktbyUlBXTjflbhmJdW+p+JYLiKfSrCx0x3uJBYRywR7yHkPlxyOsu7CBFIK9IkUqNpGNNUpYeXtIO9R7uza1jFJzSenW0"
    "nJx9+bveV/rKNOVDCSSUnNxcff5ZafAldJxaSbla3vRu5JtNLofA+t6/pq2a+bCljfzNCnlq1zMFiTYEQsHGcsGVG4DhThUfnlxeXYOtOoqa"
    "alTjd6RgvebfM1Hle1k9L25teaKaMZleX4qnNuk+aF3duKi5T95uSW8VGNpTWsoptOU1p02mX8kNjJPqc+nQv5oksDMAYYPMb/j6ihmcySjd"
    "HGRIoyGnnYh9pB7aOXRc1SpJyivdk46uy/5duUUlHWVmtNIUleK1WdPA0a9T6vSi0rPmStsvsSklyJu7TjF29yKvD3LUdUubm6/s/VwbC0ab"
    "U7i6sZBbKDcTMFgWQq+Y4xviPmbpCwLbyCVTPqYKjh6KqU23O0Yqet11m43iuZu0vdaXvWcdpNHt4XLsLJvD+/OFOEYtOUrJNyfvcrTl8TUU"
    "6ajZcqaleMSw8WR28Ep0rWNQttTupjHa2izHyrsbD5MeCikMWMcWYlUhIyq+WQGHs1Mmo1JRqVYKUIxTbsuaFtZTvzae7715Sd5WvzJpLyc6"
    "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"
    "HdtP/9k="
)
THUMB_B64 = (
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAoHBwgHBgoICAgLCgoLDhgQDg0NDh0VFhEYIx8lJCIfIiEmKzcvJik0KSEiMEExNDk7Pj4+JS5E"
    "SUM8SDc9Pjv/2wBDAQoLCw4NDhwQEBw7KCIoOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozv/wAAR"
    "CAAYACADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEG"
    "E1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWG"
    "h4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEB"
    "AQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYk"
    "NOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0"
    "tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDzaDTunFaUGnf7NbEGnf7NaMGncDj8a5Pb"
    "mOCzDbUx4NO6fLWjFppZSBlSRgEDp+dbMGnf7NaEWmK67WQFWGCCMgiqVc+vwmP03K8GndOK0YNO6ccUUV46mz8dwdafc0YNO9q0oNO9v0oo"
    "qlNn2ODrT7n/2Q=="
)
