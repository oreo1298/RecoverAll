"""Tests for the document formats of the signature engine (recoverall/core/carve/documents.py): PDFs with
incremental updates and xref streams, OLE2 compound files built here (and two made by LibreOffice), RTF,
PostScript, DjVu, CHM, MOBI, Write, HTML, XML, scripts and text: exact lengths, the right kind of file,
titles and dates; damaged files cut or marked poor; random data with a planted magic turned down."""

import base64
import calendar
import random
import struct
import zlib

import pytest

from recoverall.core.blockio import BytesSource
from recoverall.core.carve import archives, documents
from recoverall.core.carve.base import CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, Reader
from recoverall.core.carve.engine import Carver

# A Writer document and a Calc workbook saved by LibreOffice 24.2 as Word 97 / Excel 97 (title "Tiny Note",
# author "Dana Tester", modified 2020-05-07 10:11:12); zlib-compressed, base64.
SAMPLES = {
    "doc": (
        "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"
    ),
    "xls": (
        "eNrtV11sFFUUPnf2h9ltaaelVSxSh4pLoVtD5cEaxBZaUB6gm7IGYkhkuk7r0u2u2W6jPBiHIg8mkmgw8YVESfpiNIqaqAkmtgkP"
        "PGgkJCXoU/HFEH0YjMaQ0I7nnLkD49qNu2ujUfdszr13v7k/597zc8+99HXTwtkP265BEW2HACw5EQj7MIGsen80AEViS47jeLBT"
        "o38VLcqadBhE/YWQSeerpF4jsq7Rf5OGIYe/AuiwG7JY5+EYVEJ3ocX45ytnzFKZ/cql2vrVr0/xm+J4ALnY/ynWk/9HkeuQ65FX"
        "IzcgN7pXADQhNyOvQW5BbmWbALgbeS3yPXK9dbImbsf2fci6xDpqMeYfo4iKWgyH4PzqL0nlrPtraBHngnNsF98hH4bnyDYGjExK"
        "/7toF8tgCJJhFo10B7YEnEG0AT5g9HMud7D1IfWD3ist+pDSz7Kf4rKDywag8Z/ymG8Z6YE2uEje89Jr0glCYifGvzQYkCn+Civ3"
        "tT1YDzPkX4+bWTNvZBbYb2bgF0f3+eisTjgNZ/zn8nClQhz+d/gMnt1y59zl9reL8c0l8HgJfEsJPPIH/LSCPmWBQ7VmBbhussJc"
        "N1tBrtdYq7husULOEfaAkzjT0aBr5wdeRbcU+JsTKjJA8pSAH+ApCs72MC8TtikIk/d6ybqft0GdTe7zBYZ6FY4LDPbqrOjHsh/a"
        "b2huuFcx7KsYztVfMeLfwkvAN0OPg5eDCtuD7uWQUluR7xxuq6wVukHcSKP9LtLUo1jPoLi0syYWUcPpbr1z4/K+kUTf04xbd94c"
        "8IDibv04fpkLbuERXVxOc98W2AgbAGIDsY5kesKc1Pebz+vDuQkjGx82x6YyRr4j1vNQbGcr6jX2p/0SxpipxxIneIGXuYyhMNuY"
        "rvdt8rU7sX2i++p091W7b7OvfRbDTwS3KPg3DXERF94YrxbwJM6twot8hiBeqWuUx9Zw+4qWjy9F89oSbIRFvp7dCxngR0jQcdpP"
        "uEdpq974IPUI2Fu5Z9DuZDxia8ukBwpEeRyNoXTgMaUZPgm7MRbgUdwN0XqaD3wCAoyhmYyp/omEl5JES+UiAm/+QNTNYTRVcX3D"
        "/bSHcoZ96VQ+N5kbLei7X0iZGf2Rh7uTxoiZyZhsQLvSo6O9fyV3Eq5nVE1LDs2hLDcvLJx866ebQ89q776uQtemj7+hw78kcyr6"
        "npC51yGZe2VkzmXJPm/Ig3tb5l/vyRzsM5mHXZDjry8CtMu+yXT2mL4/VzDBxaj/oJE19KQ5WTDzJTGaZ6tUsUfFbevy92un7r8i"
        "GD/y0fzBjVdEqf0Tosx/NX/mwXXa6Tdx//Gb7w/STViEHZZ5ohdUNN+eSuE1Wjlayfcf66nIh5cbQ2FjVsaJg7h6HsZhhOUYr1j+"
        "ZrQKRfqPU8G7ajzs+ekArjuBGe4QynC0qvUDvjdYOWPakPfejhND6Pdm1fqL4vqVvv/ulW81zkzhAEzh/icwNyXd70UrGGWdEFLA"
        "nDWHSGnqlOuHKjj/9b5LIwSDuEKKZTDZAiuTp7eK/WOGgDPV3v9EvwGtUTLZ"
    ),
}


T2020 = calendar.timegm((2020, 5, 7, 10, 11, 12))
EPOCH_FT = 116444736000000000


def sample(name: str) -> bytes:
    return zlib.decompress(base64.b64decode("".join(SAMPLES[name])))


def noise(n: int, seed: int = 0) -> bytes:
    return random.Random(seed).randbytes(n)


def parse(fn, data: bytes, tail: bytes | None = None):
    blob = data + (noise(4096, len(data)) if tail is None else tail)
    return fn(Reader(BytesSource(blob), 0))


def exact(fn, data: bytes, ext: str | None = None, **kw):
    hit = parse(fn, data, **kw)
    assert hit is not None, fn.__name__
    assert hit.length == len(data), (fn.__name__, hit.length, len(data))
    assert hit.chance == CHANCE_GOOD, (fn.__name__, hit.chance)
    if ext:
        assert hit.ext == ext, hit.ext
    return hit


# ---------------------------------------------------------------------- PDF
CATALOG = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
           b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
           # "%%EOF" inside a page's text must not end the file
           b"<< /Length 45 >>\nstream\nBT /F1 24 Tf 72 712 Td (Hello %%EOF) Tj ET\nendstream"]
INFO = b"<< /Title (Quarterly \\(Q1\\) Report) /Author (Bob Smith) /Creator (Writer) /Producer (TestPDF 1.0) " \
       b"/CreationDate (D:20200102030405+01'00') >>"


def _pdf(objs: list[bytes], info: int | None = None, eol: bytes = b"\n") -> bytes:
    out = b"%PDF-1.4" + eol + b"%\xe2\xe3\xcf\xd3" + eol
    offs = []
    for i, body in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj" % i + eol + body + eol + b"endobj" + eol
    xref = len(out)
    out += b"xref" + eol + b"0 %d" % (len(objs) + 1) + eol + b"0000000000 65535 f\r\n"
    out += b"".join(b"%010d 00000 n\r\n" % o for o in offs)
    out += b"trailer" + eol + b"<< /Size %d /Root 1 0 R%s >>" % (len(objs) + 1, b" /Info %d 0 R" % info if info else b"")
    return out + eol + b"startxref" + eol + b"%d" % xref + eol + b"%%EOF" + eol


def _update(base: bytes, num: int, body: bytes, info: int | None = None) -> bytes:
    """An incremental update of BASE that adds (or replaces) object NUM."""
    prev = int(base.rsplit(b"startxref", 1)[1].split()[0])
    out = base
    off = len(out)
    out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 1\n0000000000 65535 f\r\n%d 1\n%010d 00000 n\r\n" % (num, off)
    out += b"trailer\n<< /Size %d /Root 1 0 R /Prev %d%s >>\n" % (num + 1, prev, b" /Info %d 0 R" % info if info else b"")
    return out + b"startxref\n%d\n%%%%EOF\n" % xref


@pytest.mark.parametrize("eol", [b"\n", b"\r\n", b"\r"])
def test_pdf_with_info(eol):
    data = _pdf(CATALOG + [INFO], info=5, eol=eol)
    hit = exact(documents.parse_pdf, data, "pdf")
    assert hit.name == "Quarterly (Q1) Report"
    assert hit.info["author"] == "Bob Smith" and hit.info["application"] == "Writer"
    assert hit.mtime == calendar.timegm((2020, 1, 2, 2, 4, 5))


def test_pdf_incremental_updates():
    base = _pdf(CATALOG + [INFO], info=5)
    title = b"<FEFF" + "Nouveau r\u00e9sum\u00e9".encode("utf-16-be").hex().upper().encode() + b">"
    data = _update(base, 6, b"<< /Title " + title + b" /ModDate (D:20210101120000Z) >>", info=6)
    data = _update(data, 7, b"<< /Annotation (later) >>", info=6)
    hit = exact(documents.parse_pdf, data, "pdf")
    assert hit.name == "Nouveau r\u00e9sum\u00e9"
    assert hit.mtime == calendar.timegm((2021, 1, 1, 12, 0, 0))
    # the first revision alone is a complete PDF too: what follows its %%EOF decides
    hit = parse(documents.parse_pdf, base, tail=b"\0" * 4096)
    assert hit.length == len(base)


def test_pdf_xref_stream_and_linearized_start():
    objs = CATALOG + [INFO]
    out = b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n"
    # a linearized file ends its first section with an %%EOF: the rest follows at once
    out += b"9 0 obj\n<< /Linearized 1 >>\nendobj\nxref\n9 1\n0000000015 00000 n\r\ntrailer\n<< /Size 10 >>\n" \
           b"startxref\n0\n%%EOF\n"
    for i, body in enumerate(objs, 1):
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xs = len(out)
    out += b"6 0 obj\n<< /Type /XRef /Size 7 /W [1 2 1] /Root 1 0 R /Info 5 0 R /Length 4 >>\nstream\n\x01\x00\x0f\x00" \
           b"\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n" % xs
    hit = exact(documents.parse_pdf, out, "pdf")
    assert hit.name == "Quarterly (Q1) Report"


def test_pdf_damaged():
    data = _pdf(CATALOG + [INFO], info=5)
    # no end marker: open-ended (the engine ends it where the next file starts)
    hit = parse(documents.parse_pdf, data[:len(data) - 60])
    assert hit.length is None and hit.chance == CHANCE_POOR
    # fragmented: the start of one PDF, then another PDF (at a block boundary) whose %%EOF comes first
    other = _pdf(CATALOG[:3] + [b"<< /Length 0 >>\nstream\n\nendstream"])
    first = data[:200] + noise(312)
    hit = parse(documents.parse_pdf, first + other)
    assert hit.length is None and hit.chance == CHANCE_POOR
    # an encrypted PDF keeps its secrets
    enc = _pdf(CATALOG + [INFO], info=5).replace(b"/Root 1 0 R /Info", b"/Root 1 0 R /Encrypt 9 0 R /Info")
    hit = exact(documents.parse_pdf, enc)
    assert hit.name is None and hit.info["encrypted"]


def test_illustrator():
    objs = list(CATALOG)
    objs[2] = b"<< /Type /Page /Parent 2 0 R /PieceInfo << /Illustrator 6 0 R >> >>"
    objs += [INFO, b"<< /Private 7 0 R >>", b"<< /AIPrivateData1 8 0 R >>", b"<< /Length 3 >>\nstream\nabc\nendstream"]
    hit = exact(documents.parse_pdf, _pdf(objs, info=5), "ai")
    assert hit.category == "photo"


# ---------------------------------------------------------------------- OLE2
ENDOFCHAIN, FREESECT, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF


def _cfb(streams: dict[str, bytes], clsid: bytes = bytes(16), v4: bool = False) -> bytes:
    """A compound file with STREAMS at the top level (those under 4096 bytes in the mini stream)."""
    ss = 4096 if v4 else 512
    sectors: list[bytes] = []
    fat: list[int] = []

    def alloc(data: bytes) -> int:
        if not data:
            return ENDOFCHAIN
        start = len(sectors)
        n = -(-len(data) // ss)
        for i in range(n):
            sectors.append(data[i * ss:(i + 1) * ss].ljust(ss, b"\0"))
            fat.append(start + i + 1 if i < n - 1 else ENDOFCHAIN)
        return start

    mini = bytearray()
    minifat: list[int] = []
    rows = []
    for name, data in streams.items():
        if len(data) < 4096:
            n = -(-len(data) // 64)
            base = len(mini) // 64
            minifat += [base + i + 1 if i < n - 1 else ENDOFCHAIN for i in range(n)]
            mini += data.ljust(n * 64, b"\0")
            rows.append((name, 2, base if n else ENDOFCHAIN, len(data)))
        else:
            rows.append((name, 2, alloc(data), len(data)))
    root_start = alloc(bytes(mini))
    minifat_raw = b"".join(struct.pack("<I", x) for x in minifat)
    minifat_start = alloc(minifat_raw)
    rows = [("Root Entry", 5, root_start, len(mini))] + rows
    dirdata = b""
    for i, (name, typ, start, size) in enumerate(rows):
        nb = name.encode("utf-16-le") + b"\0\0"
        child = 1 if i == 0 and len(rows) > 1 else NOSTREAM
        right = i + 1 if 0 < i < len(rows) - 1 else NOSTREAM
        dirdata += nb.ljust(64, b"\0") + struct.pack("<HBBIII", len(nb), typ, 1, NOSTREAM, right, child)
        dirdata += (clsid if i == 0 else bytes(16)) + struct.pack("<IQQIQ", 0, 0, 0, start, size)
    while len(dirdata) % ss:
        dirdata += bytes(66) + struct.pack("<BBIII", 0, 0, NOSTREAM, NOSTREAM, NOSTREAM) + bytes(48)
    dir_start = alloc(dirdata)
    per = ss // 4
    nfat = 1
    while len(sectors) + nfat > nfat * per:
        nfat += 1
    first_fat = len(sectors)
    fat += [FATSECT] * nfat
    table = fat + [FREESECT] * (nfat * per - len(fat))
    for k in range(nfat):
        sectors.append(struct.pack(f"<{per}I", *table[k * per:(k + 1) * per]))
    difat = [first_fat + k for k in range(nfat)] + [FREESECT] * (109 - nfat)
    header = documents.OLE_MAGIC + bytes(16) + struct.pack("<HHHHH", 0x3E, 4 if v4 else 3, 0xFFFE, 12 if v4 else 9, 6)
    header += bytes(6) + struct.pack("<9I", len(dirdata) // ss if v4 else 0, nfat, dir_start, 0, 4096, minifat_start,
                                     -(-len(minifat_raw) // ss), ENDOFCHAIN, 0)
    header += struct.pack("<109I", *difat)
    return header.ljust(ss, b"\0") + b"".join(sectors)


def _summary(title=None, subject=None, author=None, app=None, created=None, saved=None) -> bytes:
    """A SummaryInformation property set."""
    def lpstr(s):
        raw = s.encode("cp1252") + b"\0"
        return struct.pack("<II", 0x1E, len(raw)) + raw + bytes(-len(raw) % 4)

    def ft(t):
        return struct.pack("<IQ", 0x40, int(t * 10 ** 7) + EPOCH_FT)

    props = [(1, struct.pack("<Ih", 2, 1252) + b"\0\0")]
    for pid, value, enc in ((2, title, lpstr), (3, subject, lpstr), (4, author, lpstr), (0x0C, created, ft),
                            (0x0D, saved, ft), (0x12, app, lpstr)):
        if value is not None:
            props.append((pid, enc(value)))
    head = 8 + 8 * len(props)
    body = b""
    pairs = b""
    for pid, value in props:
        pairs += struct.pack("<II", pid, head + len(body))
        body += value
    section = struct.pack("<II", head + len(body), len(props)) + pairs + body
    return struct.pack("<HHI", 0xFFFE, 0, 0x20006) + bytes(16) + struct.pack("<I", 1) + \
        bytes.fromhex("e0859ff2f94f6810ab9108002b27b3d9") + struct.pack("<I", 48) + section


SUMMARY = _summary("Annual report", None, "Erin", "Microsoft Office Word", calendar.timegm((2019, 1, 2, 3, 4, 5)),
                   calendar.timegm((2019, 2, 3, 4, 5, 6)))


@pytest.mark.parametrize("v4", [False, True])
def test_ole_word_document(v4):
    data = _cfb({"WordDocument": b"\xec\xa5\xc1\x00" + noise(9000), "1Table": noise(1500),
                 "\x05SummaryInformation": SUMMARY, "\x01CompObj": noise(100)}, v4=v4)
    hit = exact(documents.parse_ole, data, "doc")
    assert hit.category == "document" and hit.name == "Annual report"
    assert hit.info["author"] == "Erin" and hit.info["application"] == "Microsoft Office Word"
    assert hit.mtime == calendar.timegm((2019, 2, 3, 4, 5, 6))


@pytest.mark.parametrize("streams, clsid, ext, category", [
    ({"Workbook": noise(5000)}, bytes(16), "xls", "document"),
    ({"PowerPoint Document": noise(5000), "Current User": noise(60)}, bytes(16), "ppt", "document"),
    ({"VisioDocument": noise(5000)}, bytes(16), "vsd", "document"),
    ({"䡀㼿䕷": noise(300), "\x05SummaryInformation": _summary("Installation Database", "Super App")},
     bytes.fromhex("84100c0000000000c000000000000046"), "msi", "executable"),
    ({"EncryptionInfo": noise(200), "EncryptedPackage": noise(6000)}, bytes(16), "docx", "document"),
    ({"Catalog": noise(300), "1": noise(2000), "2": noise(2000)}, bytes(16), "db", "other"),
    ({"Something": noise(300)}, bytes(16), "ole", "document"),
])
def test_ole_kinds(streams, clsid, ext, category):
    hit = exact(documents.parse_ole, _cfb(streams, clsid), ext)
    assert hit.category == category
    if ext == "msi":
        assert hit.name == "Super App"


def test_outlook_message():
    props = bytes(32) + struct.pack("<IIQ", 0x00390040, 6, int(calendar.timegm((2022, 3, 4, 5, 6, 7)) * 1e7) + EPOCH_FT)
    data = _cfb({"__substg1.0_0037001F": "Lunch on Friday?".encode("utf-16-le"),
                 "__substg1.0_0C1A001F": "Frank".encode("utf-16-le"), "__substg1.0_1000001F": noise(5000),
                 "__properties_version1.0": props})
    hit = exact(documents.parse_ole, data, "msg")
    assert hit.category == "email" and hit.name == "Lunch on Friday?" and hit.info["from"] == "Frank"
    assert hit.mtime == calendar.timegm((2022, 3, 4, 5, 6, 7))


@pytest.mark.parametrize("name, ext", [("doc", "doc"), ("xls", "xls")])
def test_ole_made_by_libreoffice(name, ext):
    hit = exact(documents.parse_ole, sample(name), ext)
    assert hit.name == "Tiny Note" and hit.info["author"] == "Dana Tester" and hit.mtime == T2020


def test_ole_truncated():
    data = _cfb({"WordDocument": noise(20000), "\x05SummaryInformation": SUMMARY})
    hit = documents.parse_ole(Reader(BytesSource(data[:len(data) - 2000]), 0))
    assert hit.chance == CHANCE_POOR and (hit.length is None or hit.length <= len(data) - 2000)
    # the directory is overwritten: still a (damaged) document, open-ended
    bad = bytearray(data)
    dir_at = (struct.unpack_from("<I", data, 48)[0] + 1) * 512
    bad[dir_at:dir_at + 512] = noise(512)
    hit = parse(documents.parse_ole, bytes(bad))
    assert hit.length is None and hit.chance == CHANCE_POOR


# ---------------------------------------------------------------------- RTF, PostScript, EPS
RTF = (b"{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Arial;}}{\\info{\\title Notes about \\{braces\\} caf\\'e9}"
       b"{\\author Carol}{\\creatim\\yr2019\\mo5\\dy6\\hr7\\min8}{\\revtim\\yr2019\\mo6\\dy7\\hr8\\min9}}"
       b"{\\*\\generator Msftedit 5.41.21.2510;}\\f0 Hello \\{ world \\} \\\\ {\\b bold}"
       b"{\\pict\\bin6 }}}{{{}{ more}\\par}\r\n")


def test_rtf():
    hit = exact(documents.parse_rtf, RTF, "rtf")
    assert hit.name == "Notes about {braces} café" and hit.info["author"] == "Carol"
    assert hit.mtime == calendar.timegm((2019, 6, 7, 8, 9, 0))
    assert hit.info["application"] == "Msftedit 5.41.21.2510"
    # cut before the closing brace: what is there is kept, end unknown
    hit = parse(documents.parse_rtf, RTF[:100], tail=bytes(4096))
    assert hit.length is None and hit.chance == CHANCE_POOR


PS = (b"%!PS-Adobe-3.0\n%%Title: (Test page)\n%%Creator: hand\n%%CreationDate: Tue Jun 15 12:34:56 2021\n"
      b"%%Pages: 1\n%%EndComments\n%%BeginDocument: inner.eps\n%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 10 10\n"
      b"0 0 moveto 10 10 lineto stroke\n%%EOF\n%%EndDocument\nshowpage\n%%Trailer\n%%EOF\n")


def test_postscript():
    hit = exact(documents.parse_ps, PS, "ps")
    assert hit.name == "Test page" and hit.mtime == calendar.timegm((2021, 6, 15, 12, 34, 56))
    eps = b"%!PS-Adobe-3.0 EPSF-3.0\n%%Creator: Adobe Illustrator(R) 8.0\n%%BoundingBox: 0 0 1 1\n%%EOF\r\n"
    hit = exact(documents.parse_ps, eps, "ai")
    # no %%EOF at all: the text ends where the file did
    hit = parse(documents.parse_ps, PS.replace(b"%%EOF", b"%%XXX"), tail=bytes(4096))
    assert hit.length == len(PS) and hit.chance == CHANCE_FAIR


def test_eps_with_preview():
    ps = b"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 10 10\nshowpage\n%%EOF\n"
    tiff = b"II*\x00" + noise(500)
    data = struct.pack("<4s6IH", b"\xc5\xd0\xd3\xc6", 30, len(ps), 0, 0, 30 + len(ps), len(tiff), 0xFFFF) + ps + tiff
    hit = exact(documents.parse_eps_dos, data, "eps")
    assert hit.info["preview"] == "TIFF"


# ---------------------------------------------------------------------- DjVu, CHM, WordPerfect, MOBI, Write
def test_djvu():
    info = struct.pack(">HHBBHBB", 640, 480, 24, 0, 300, 22, 1)
    form = b"DJVU" + b"INFO" + struct.pack(">I", len(info)) + info + b"Sjbz" + struct.pack(">I", 100) + noise(100)
    data = b"AT&TFORM" + struct.pack(">I", len(form)) + form
    hit = exact(documents.parse_djvu, data, "djvu")
    assert hit.info["width"] == 640 and hit.info["height"] == 480


def _chm(size: int = 5000) -> bytes:
    guid = bytes.fromhex("10fd017caa7bd0119e0c00a0c922e6ec")
    head = b"ITSF" + struct.pack("<IIII", 3, 0x60, 1, 0x12345678) + struct.pack("<I", 0x409)
    head += guid + guid[:1].replace(b"\x10", b"\x11") + guid[1:] + struct.pack("<QQQQQ", 0x60, 0x18, 0x78, 0x54, 0xCC)
    sec0 = struct.pack("<IIQQ", 0x1FE, 0, size, 0)
    return (head + sec0 + b"ITSP" + noise(size - 0x7C, 4))[:size]


def test_chm():
    data = _chm()
    hit = exact(documents.parse_chm, data, "chm")
    assert hit.info["language"] == 0x409


def test_wordperfect_has_no_length():
    data = b"\xffWPC" + struct.pack("<IBBBBH", 0x200, 1, 0x0A, 2, 1, 0) + bytes(2) + noise(2000)
    hit = parse(documents.parse_wpd, data)
    assert hit.ext == "wpd" and hit.length is None and hit.chance == CHANCE_FAIR


def _mobi(eof_record: bool = True) -> bytes:
    nrec = 4
    head = b"My_Kindle_Book".ljust(32, b"\0") + struct.pack(">HHIIIIII", 0, 0, 1600000000, 1600000000, 0, 0, 0, 0)
    head += b"BOOKMOBI" + struct.pack(">IIH", 0, 0, nrec)
    first = len(head) + nrec * 8 + 2
    rec0 = bytes(16) + b"MOBI" + struct.pack(">IIIII", 232, 2, 65001, 1, 6) + bytes(200)
    recs = [rec0, noise(3000, 1), noise(2000, 2), b"\xe9\x8e\r\n" if eof_record else noise(100, 3)]
    offs = []
    pos = first
    for rec in recs:
        offs.append(pos)
        pos += len(rec)
    table = b"".join(struct.pack(">II", o, i) for i, o in enumerate(offs))
    return head + table + b"\0\0" + b"".join(recs)


def test_mobi():
    data = _mobi()
    hit = exact(documents.parse_mobi, data, "mobi")
    assert hit.name == "My Kindle Book" and hit.mtime == 1600000000
    hit = parse(documents.parse_mobi, _mobi(False))
    assert hit.length is None and hit.chance == CHANCE_FAIR


def test_write():
    text = b"Dear Sir,\r\n" * 30
    fcmac = 128 + len(text)
    pages = -(-fcmac // 128) + 2
    head = struct.pack("<HHHHHHHI", 0xBE31, 0, 0xAB00, 0, 0, 0, 0, fcmac) + struct.pack("<6H", 3, 3, 3, 3, 3, 3)
    head = head.ljust(0x60, b"\0") + struct.pack("<H", pages)
    data = (head.ljust(128, b"\0") + text).ljust(pages * 128, b"\0")
    exact(documents.parse_wri, data, "wri")


# ---------------------------------------------------------------------- HTML, XML, scripts, text
BODY = "".join(f"<p>Paragraph {i}: some words in a web page.</p>\n" for i in range(200)).encode()


def test_html():
    page = b'<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8"><title>Caf\xc3\xa9 &amp; Menu</title>' \
           b"</head><body>\n" + BODY + b"</body></html>\n"
    hit = exact(documents.parse_html, page, "html")
    assert hit.name == "Café & Menu"
    # no closing tag: the text ends where the file did (fair)
    hit = parse(documents.parse_html, page[:-8], tail=bytes(4096))
    assert hit.length == len(page) - 8 and hit.chance == CHANCE_FAIR
    # a closing tag, then the slack of the last block: the file is cut at the tag
    hit = parse(documents.parse_html, page + b"stale text from an older file", tail=bytes(100))
    assert hit.length == len(page)


def test_xml():
    doc = b"<?xml version='1.0' encoding='utf-8'?>\n<!-- notes -->\n<!DOCTYPE note [<!ENTITY a 'b'>]>\n" \
          b"<note><title>Shopping</title><item>milk</item><note>nested</note></note>\n"
    hit = exact(documents.parse_xml, doc, "xml")
    assert hit.info["root"] == "note" and hit.name == "Shopping"
    kml = b'<?xml version="1.0" encoding="UTF-8"?>\n<kml xmlns="http://www.opengis.net/kml/2.2"><Document/></kml>\n'
    hit = exact(documents.parse_xml, kml, "kml")
    assert hit.category == "other"
    xhtml = b'<?xml version="1.0"?>\n<html xmlns="http://www.w3.org/1999/xhtml"><body/></html>'
    exact(documents.parse_xml, xhtml, "html")
    # SVG and property lists belong to other formats
    assert parse(documents.parse_xml, b'<?xml version="1.0"?>\n<svg width="1"/>\n') is None
    assert parse(documents.parse_xml, b'<?xml version="1.0"?>\n<!DOCTYPE plist>\n<plist/>\n') is None


@pytest.mark.parametrize("line, ext", [(b"#!/bin/sh", "sh"), (b"#!/usr/bin/env python3", "py"),
                                       (b"#! /usr/bin/perl -w", "pl"), (b"#!/usr/bin/node", "js")])
def test_scripts(line, ext):
    data = line + b"\n" + b"echo hello world\n" * 40
    hit = parse(documents.parse_script, data, tail=bytes(512))
    assert hit.ext == ext and hit.length == len(data)


def test_plain_text_is_off_by_default():
    fmt = next(f for f in documents.FORMATS if f.key == "txt")
    assert not fmt.enabled
    text = ("Dear diary, today the disk died. " * 60 + "\n").encode() * 3
    hit = parse(documents.parse_txt, text, tail=bytes(4096))
    assert hit.ext == "txt" and hit.length == len(text)
    assert parse(documents.parse_txt, b"short text\n", tail=bytes(4096)) is None
    assert parse(documents.parse_txt, noise(8192)) is None


# ---------------------------------------------------------------------- robustness
ALL = documents.FORMATS


@pytest.mark.parametrize("fmt", ALL, ids=[f.key for f in ALL])
def test_random_data_with_planted_magic_is_rejected(fmt):
    magics = fmt.magic if len(fmt.magic) < 20 else fmt.magic[::25]
    for seed in range(30):
        for off, magic in magics:
            blob = bytearray(noise(64 * 1024, seed * 7 + off))
            blob[off:off + len(magic)] = magic
            hit = fmt.parse(Reader(BytesSource(bytes(blob)), 0))
            assert hit is None, (fmt.key, seed, magic, hit)


def _samples():
    return [(documents.parse_pdf, _update(_pdf(CATALOG + [INFO], info=5), 6, b"<< /Title (x) >>", info=6)),
            (documents.parse_ole, _cfb({"WordDocument": noise(5000), "\x05SummaryInformation": SUMMARY})),
            (documents.parse_ole, sample("xls")), (documents.parse_rtf, RTF), (documents.parse_ps, PS),
            (documents.parse_djvu, b"AT&TFORM\x00\x00\x00\x14DJVUINFO\x00\x00\x00\x08" + bytes(8)),
            (documents.parse_chm, _chm()), (documents.parse_mobi, _mobi()),
            (documents.parse_html, b"<html><head><title>x</title></head><body>" + BODY + b"</body></html>"),
            (documents.parse_xml, b'<?xml version="1.0"?><a><b>' + BODY + b"</b></a>")]


def test_damaged_samples_never_raise():
    rnd = random.Random(9)
    for fn, data in _samples():
        assert parse(fn, data) is not None, fn.__name__
        for _ in range(60):
            bad = bytearray(data)
            for _ in range(rnd.randint(1, 8)):
                bad[rnd.randrange(len(bad))] = rnd.randrange(256)
            if rnd.random() < 0.3:
                bad = bad[:rnd.randrange(1, len(bad))]
            hit = parse(fn, bytes(bad))
            assert hit is None or hit.length is None or hit.length > 0


# ---------------------------------------------------------------------- through the engine
def test_carver_finds_documents_in_random_data():
    page = b"<!DOCTYPE html>\n<html><head><title>Page</title></head><body>" + BODY + b"</body></html>\n"
    planted = [("pdf", _update(_pdf(CATALOG + [INFO], info=5), 6, b"<< /Title (Two) >>", info=6), "pdf"),
               ("ole", sample("doc"), "doc"), ("ole", sample("xls"), "xls"),
               ("ole", _cfb({"__substg1.0_0037001F": "Hi".encode("utf-16-le")}), "msg"),
               ("rtf", RTF, "rtf"), ("ps", PS, "ps"), ("chm", _chm(), "chm"), ("mobi", _mobi(), "mobi"),
               ("html", page, "html"), ("xml", b'<?xml version="1.0"?>\n<a>' + BODY + b"</a>\n", "xml")]
    img = bytearray()
    where = []
    for i, (key, data, ext) in enumerate(planted):
        img += noise(512 * (2 + i % 4), 200 + i)
        where.append((len(img), len(data), key, ext))
        img += data
        img += noise(-len(img) % 512, 300 + i)
    img += noise(4096, 77)
    formats = [f for f in documents.FORMATS + archives.FORMATS if f.enabled]
    found = {(f.offset, f.length, f.key, f.ext): f for f in Carver(BytesSource(bytes(img)), formats).scan()}
    for off, n, key, ext in where:
        assert (off, n, key, ext) in found, (off, n, key, ext, sorted(found))
    doc = found[where[1]]
    assert doc.name == "Tiny Note" and doc.category == "document" and doc.chance == CHANCE_GOOD
