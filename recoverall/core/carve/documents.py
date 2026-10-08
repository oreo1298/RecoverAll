"""Documents for the signature engine: PDF (and Illustrator), Office 97-2003 and the other OLE2 compound
files (Word, Excel, PowerPoint, Outlook messages, Windows Installer packages, Visio, Publisher, thumbnail
caches, Hangul), RTF, PostScript and EPS, DjVu, CHM help files, WordPerfect, MOBI/AZW e-books, Windows
Write, HTML, XML, scripts and plain text.

The newer Office, OpenDocument and EPUB formats are ZIP files: archives.py finds them and names them after
what is inside.

How the end of each file is found:

===========  ==========================================================================================
PDF          the last ``%%EOF``: after each one, more PDF syntax (an incremental update, the rest of a
             linearized file) means the file goes on. The final ``startxref`` must point at the
             cross-reference table, otherwise the end is only a guess.
OLE2         the allocation table (FAT) says which sectors are in use: the file ends after the last one.
RTF          the brace that closes the first one.
PostScript   the ``%%EOF`` that isn't inside an embedded document; DOS EPS files list their sections.
DjVu, CHM    a size in the header. Windows Write: a page count in the header.
MOBI         the end-of-file record after the last record (else unknown).
HTML, XML    the closing ``</html>`` or root element tag, else the end of the text.
WordPerfect  unknown: the file ends where the next one starts.
===========  ==========================================================================================

Titles, authors and dates come from the document properties when they aren't compressed or encrypted.
Plain text has no signature at all: its format is off by default (it would turn every text fragment on
the disk into a file).
"""

from __future__ import annotations

import calendar
import html
import re
import struct
import time

from ..fs.base import filetime
from .base import CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, Format, GiB, Hit, KiB, MiB, Reader

PDF_MAX = 4 * GiB
OLE_MAX = 4 * GiB
RTF_MAX = 1 * GiB
PS_MAX = 2 * GiB
TEXT_MAX = 64 * MiB
HTML_MAX = 256 * MiB


# ---------------------------------------------------------------------- helpers (archives.py uses them too)
class Peek:
    """Small reads anywhere in a candidate file, through a little cache of 64 KiB pieces. Walking headers
    that lie far apart (big ZIP members, scattered OLE2 sectors) must not pull a 1 MiB window for each."""

    def __init__(self, r: Reader, piece: int = 64 * KiB, keep: int = 32):
        self.r = r
        self.piece = piece
        self.keep = keep
        self._cache: dict[int, bytes] = {}

    def read(self, offset: int, length: int) -> bytes:
        r = self.r
        if offset < 0 or length <= 0 or offset >= r.limit:
            return b""
        length = min(length, r.limit - offset)
        if length > self.piece:
            return r.src.read(r.start + offset, length)
        first = offset // self.piece
        last = (offset + length - 1) // self.piece
        buf = self._get(first) if first == last else self._get(first) + self._get(last)
        rel = offset - first * self.piece
        return buf[rel:rel + length]

    def _get(self, index: int) -> bytes:
        buf = self._cache.get(index)
        if buf is None:
            if len(self._cache) >= self.keep:
                self._cache.pop(next(iter(self._cache)))
            off = index * self.piece
            n = min(self.piece, self.r.limit - off)
            buf = self.r.src.read(self.r.start + off, n) if n > 0 else b""
            self._cache[index] = buf
        return buf


# Bytes that never appear in a text file: where the text stops, the file (or what is left of it) stops.
_BINARY = re.compile(rb"[\x00-\x08\x0e-\x1a\x1c-\x1f]")


def text_end(r: Reader, start: int = 0, cap: int = TEXT_MAX) -> int:
    """Offset of the first byte from START that can't be part of a text file (or CAP / the end)."""
    cap = min(cap, r.limit)
    pos = start
    while pos < cap:
        buf = r.read(pos, min(256 * KiB, cap - pos))
        if not buf:
            return pos
        m = _BINARY.search(buf)
        if m:
            return pos + m.start()
        pos += len(buf)
    return cap


def plausible(t: float | None) -> float | None:
    """T if it is a believable file date (1980-2100), else None."""
    if t is None or not 315532800 <= t <= 4102444800:
        return None
    return float(t)


def clean_title(text: str | None, limit: int = 100) -> str | None:
    """A document title made fit for a file name (one line, trimmed), or None."""
    if not text:
        return None
    text = " ".join(re.sub(r"[\x00-\x1f\x7f]+", " ", text).split()).strip(" .")
    return text[:limit].rstrip() or None


_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,]\d+)?)?)?\s*(Z|[+-]\d{2}:?\d{2})?")


def iso_date(text: str | None) -> float | None:
    """An ISO 8601 date ("2021-03-04T05:06:07Z", "2021-03-04") → Unix time."""
    m = _ISO.search(text or "")
    if not m:
        return None
    y, mo, d, hh, mm, ss = (int(g) if g else 0 for g in m.groups()[:6])
    try:
        t = calendar.timegm((y, mo, d, hh, mm, ss, 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    tz = m.group(7)
    if tz and tz != "Z":
        sign = -1 if tz[0] == "-" else 1
        digits = tz[1:].replace(":", "")
        t -= sign * (int(digits[:2]) * 3600 + int(digits[2:4]) * 60)
    return plausible(t)


def xml_text(xml: str, *names: str) -> str | None:
    """The text of the first element called one of NAMES ("dc:title": any namespace prefix), unescaped."""
    for name in names:
        local = re.escape(name.split(":")[-1])
        m = re.search(r"<(?:[\w.-]+:)?%s(?:\s[^>]*)?>(.*?)</(?:[\w.-]+:)?%s\s*>" % (local, local), xml, re.S)
        if m:
            text = html.unescape(re.sub(r"<[^>]*>", " ", m.group(1))).strip()
            if text:
                return " ".join(text.split())
    return None


def _decode(raw: bytes, codepage: str = "cp1252") -> str:
    try:
        return raw.decode(codepage)
    except (UnicodeDecodeError, LookupError):
        return raw.decode("latin-1")


# ---------------------------------------------------------------------- PDF
_PDF_HEAD = re.compile(rb"%PDF-([12])\.(\d)")
_PDF_OBJ = re.compile(rb"\d+[ \t\r\n\f\x00]+\d+[ \t\r\n\f\x00]+obj\b")
# what may follow an %%EOF inside a PDF: an incremental update, or the rest of a linearized file
_PDF_MORE = re.compile(rb"[ \t\r\n\f]*(?:\d+[ \t\r\n]+\d+[ \t\r\n]+obj\b|xref\b|startxref\b|trailer\b)")
_PDF_STARTXREF = re.compile(rb"startxref\s+(\d+)\s*$")
_PDF_INFO = re.compile(rb"/Info\s+(\d+)\s+(\d+)\s+R")
_PDF_DATE = re.compile(rb"D:(\d{4})(\d\d)?(\d\d)?(\d\d)?(\d\d)?(\d\d)?([Zz+-])?(\d\d)?'?(\d\d)?")


def parse_pdf(r: Reader) -> Hit | None:
    head = r.read(0, 4096)
    m = _PDF_HEAD.match(head)
    if not m or not _PDF_OBJ.search(head):         # the first object always follows the header closely
        return None
    version = f"{m.group(1).decode()}.{m.group(2).decode()}"
    cap = min(r.limit, PDF_MAX)
    pos = 8
    end = last_eof = None
    unfinished = False                             # PDF syntax after the last %%EOF found, but no %%EOF after it
    for _ in range(100000):
        e, is_end = _next_marker(r, b"%%EOF", b"%PDF-", pos, cap)
        unfinished = end is not None and not is_end
        if not is_end:
            break                                  # nothing more, or the next PDF starts: the file ended
        if not _PDF_STARTXREF.search(r.read(max(0, e - 64), min(e, 64))):
            pos = e + 5                            # "%%EOF" inside a stream or a string, not the end marker
            continue
        after = r.read(e + 5, 2048)
        k = 2 if after[:2] == b"\r\n" else 1 if after[:1] in (b"\r", b"\n") else 0
        end = e + 5 + k
        last_eof = e
        if not _PDF_MORE.match(after, k):
            break
        pos = end
    info: dict = {"version": version}
    if end is None:
        # no end marker: overwritten or fragmented; what is there may still open in a forgiving viewer
        return Hit("pdf", None, CHANCE_POOR, info=info)
    tail = r.read(max(0, last_eof - 1024), min(last_eof, 1024))
    sm = _PDF_STARTXREF.search(tail)
    startxref = int(sm.group(1)) if sm else -1
    # The cross-reference table must be where the file says; if it isn't, the writer was sloppy or this
    # %%EOF belongs to another file that took the place of the rest of this one (fragmented).
    ok = 0 < startxref < end and _pdf_xref_at(r, startxref) and not unfinished
    hit = Hit("pdf", end, CHANCE_GOOD if ok else CHANCE_FAIR, info=info)
    _pdf_meta(r, hit, end, startxref, head)
    if _pdf_is_illustrator(r, end):
        hit.ext, hit.category, hit.description = "ai", "photo", "Adobe Illustrator artwork"
    return hit


def _next_marker(r: Reader, marker: bytes, header: bytes, pos: int, cap: int, align: int = 512) -> tuple[int, bool]:
    """(offset, True) of the next MARKER from POS; (offset, False) if a block-aligned HEADER comes first (the
    next file of the same kind: this one can't go past it); (-1, False) if neither is found before CAP."""
    over = max(len(marker), len(header)) - 1
    while pos < cap:
        n = min(4 * MiB, cap - pos)
        buf = r.read(pos, n + over if pos + n < cap else n)
        e = buf.find(marker, 0, n + len(marker) - 1)
        h = buf.find(header, 0, n + len(header) - 1)
        while h >= 0 and (pos + h) % align:
            h = buf.find(header, h + 1, n + len(header) - 1)
        if e >= 0 and (h < 0 or e < h):
            return pos + e, True
        if h >= 0:
            return pos + h, False
        pos += n
    return -1, False


def _pdf_xref_at(r: Reader, offset: int) -> bool:
    b = r.read(offset, 64)
    return bool(re.match(rb"\s*xref\b", b) or re.match(rb"\s*\d+\s+\d+\s+obj\b", b))


def _pdf_is_illustrator(r: Reader, end: int) -> bool:
    """Illustrator files are PDFs carrying Illustrator's own copy of the artwork (AIPrivateData)."""
    head = r.read(0, min(end, 256 * KiB))
    if b"/Illustrator" not in head and b"Adobe Illustrator" not in head:
        return False
    lo = max(0, end - 4 * MiB)
    return r.find(b"/AIPrivateData", lo, end) >= 0 or b"/AIPrivateData" in head


def _pdf_meta(r: Reader, hit: Hit, end: int, startxref: int, head: bytes) -> None:
    """Title, author, application and dates from the Info dictionary (when it isn't compressed)."""
    tail = r.read(max(0, end - 8192), min(end, 8192))
    if b"/Encrypt" in tail:
        hit.info["encrypted"] = True
        return                                     # the strings are encrypted too
    refs = _PDF_INFO.findall(tail) or _PDF_INFO.findall(r.read(0, 16 * KiB))
    if not refs:
        return
    num, gen = int(refs[-1][0]), int(refs[-1][1])
    obj = re.compile(rb"(?<![0-9])%d\s+%d\s+obj\b" % (num, gen))
    body = b""
    off = _pdf_xref_lookup(r, startxref, num, end) if startxref > 0 else None
    if off is not None:
        body = r.read(off, 8192)
        if not obj.match(body.lstrip()):
            body = b""
    if not body:
        # an xref stream (compressed): look for the object near the ends of the file, where writers put it
        for lo in (max(0, end - MiB), 0):
            chunk = r.read(lo, min(MiB, end - lo))
            m = None
            for m in obj.finditer(chunk):
                pass
            if m:
                body = chunk[m.start():m.start() + 8192]
                break
    if not body:
        return
    body = body[:body.find(b"endobj")] if b"endobj" in body else body
    title = clean_title(_pdf_value(body, b"Title"))
    author = _pdf_value(body, b"Author")
    creator = _pdf_value(body, b"Creator")
    producer = _pdf_value(body, b"Producer")
    if title:
        hit.name = title
        hit.info["title"] = title
    if author:
        hit.info["author"] = author.strip()
    app = creator or producer
    if app:
        hit.info["application"] = app.strip()
    if producer and producer != app:
        hit.info["producer"] = producer.strip()
    for key in (b"ModDate", b"CreationDate"):
        t = _pdf_date(_pdf_value(body, key))
        if t:
            hit.mtime = t
            break


def _pdf_xref_lookup(r: Reader, x: int, num: int, end: int) -> int | None:
    """The offset of object NUM from the classic cross-reference tables (following /Prev), or None."""
    seen = set()
    for _ in range(64):
        if x in seen or not 0 < x < end:
            return None
        seen.add(x)
        m = re.match(rb"\s*xref\s*", r.read(x, 64))
        if not m:
            return None                            # an xref stream: compressed
        p = x + m.end()
        for _ in range(100000):
            sub = re.match(rb"(\d+) +(\d+)[ \t]*(?:\r\n|\r|\n)", r.read(p, 64))
            if not sub:
                break                              # "trailer"
            start, count = int(sub.group(1)), int(sub.group(2))
            p += sub.end()
            if start <= num < start + count:
                ent = re.match(rb"(\d{10}) (\d{5}) ([nf])", r.read(p + (num - start) * 20, 20))
                if ent and ent.group(3) == b"n":
                    return int(ent.group(1))
                return None
            p += count * 20
        prev = re.search(rb"/Prev\s+(\d+)", r.read(p, 4096))
        if not prev:
            return None
        x = int(prev.group(1))
    return None


def _pdf_value(body: bytes, key: bytes) -> str | None:
    m = re.search(rb"/" + key + rb"\s*([(<])", body)
    if not m:
        return None
    i = m.start(1)
    if body[i:i + 1] == b"(":
        raw = _pdf_literal(body, i)
    else:
        if body[i + 1:i + 2] == b"<":
            return None                            # a dictionary, not a string
        j = body.find(b">", i)
        if j < 0:
            return None
        hexs = re.sub(rb"\s", b"", body[i + 1:j])
        if len(hexs) % 2:
            hexs += b"0"
        try:
            raw = bytes.fromhex(hexs.decode("ascii"))
        except ValueError:
            return None
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", "replace")
    return raw.decode("latin-1")


_PDF_ESC = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}


def _pdf_literal(body: bytes, i: int) -> bytes:
    """A (literal string) starting at BODY[i] == '(' (nested parentheses, escapes, octal codes)."""
    out = bytearray()
    depth = 0
    n = len(body)
    while i < n and len(out) < 4096:
        c = body[i]
        if c == 0x5C:                              # backslash
            i += 1
            if i >= n:
                break
            c = body[i]
            if c in _PDF_ESC:
                out.append(_PDF_ESC[c])
            elif 0x30 <= c <= 0x37:
                j = i
                while j < min(n, i + 3) and 0x30 <= body[j] <= 0x37:
                    j += 1
                out.append(int(body[i:j], 8) & 0xFF)
                i = j - 1
            elif c in (0x0D, 0x0A):                # a line continuation
                if c == 0x0D and body[i + 1:i + 2] == b"\n":
                    i += 1
            else:
                out.append(c)
        elif c == 0x28:
            if depth:
                out.append(c)
            depth += 1
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                break
            out.append(c)
        else:
            out.append(c)
        i += 1
    return bytes(out)


def _pdf_date(text: str | None) -> float | None:
    if not text:
        return None
    m = _PDF_DATE.search(text.encode("latin-1", "replace"))
    if not m:
        return None
    g = m.groups()
    y, mo, d = int(g[0]), int(g[1] or 1), int(g[2] or 1)
    hh, mm, ss = int(g[3] or 0), int(g[4] or 0), int(g[5] or 0)
    try:
        t = calendar.timegm((y, mo, d, hh, mm, ss, 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    if g[6] in (b"+", b"-"):
        sign = -1 if g[6] == b"-" else 1
        t -= sign * (int(g[7] or 0) * 3600 + int(g[8] or 0) * 60)
    return plausible(t)


# ---------------------------------------------------------------------- OLE2 compound files
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_FREESECT, _ENDOFCHAIN = 0xFFFFFFFF, 0xFFFFFFFE
_MAXREGSECT = 0xFFFFFFFA
_CLSID_MSI = bytes.fromhex("84100c0000000000c000000000000046")
_CLSID_MSP = bytes.fromhex("86100c0000000000c000000000000046")
_CLSID_MST = bytes.fromhex("82100c0000000000c000000000000046")

# (ext, category, description) of what an OLE2 file holds
_OLE_KINDS = {
    "doc": ("doc", "document", "Word 97-2003 document"),
    "xls": ("xls", "document", "Excel 97-2003 workbook"),
    "ppt": ("ppt", "document", "PowerPoint 97-2003 presentation"),
    "msg": ("msg", "email", "Outlook message"),
    "msi": ("msi", "executable", "Windows Installer package"),
    "msp": ("msp", "executable", "Windows Installer patch"),
    "mst": ("mst", "executable", "Windows Installer transform"),
    "vsd": ("vsd", "document", "Visio drawing"),
    "pub": ("pub", "document", "Publisher document"),
    "db": ("db", "other", "Windows thumbnail cache (Thumbs.db)"),
    "hwp": ("hwp", "document", "Hangul word processor document"),
    "encrypted": ("docx", "document", "Encrypted Office document (Word, Excel or PowerPoint)"),
    "ole": ("ole", "document", "OLE2 compound file"),
}


class _Bad(Exception):
    """A structure that doesn't hold together: not this format, or too damaged to use."""


class _Cfb:
    """Just enough of a Compound File Binary reader: the FAT, the directory and small streams."""

    def __init__(self, r: Reader):
        self.r = r
        self.peek = Peek(r)
        h = r.read(0, 512)
        if len(h) < 512 or h[:8] != OLE_MAGIC:
            raise _Bad
        major, bom, sshift, mshift = struct.unpack_from("<HHHH", h, 26)
        if bom != 0xFFFE or (major, sshift) not in ((3, 9), (4, 12)) or mshift != 6 or any(h[34:40]):
            raise _Bad
        self.ss = ss = 1 << sshift
        ndir, nfat, self.dir_start, _txn, cutoff, self.minifat_start, nminifat, difat, ndifat = \
            struct.unpack_from("<9I", h, 40)
        if cutoff != 4096 or not 1 <= nfat <= (64 * MiB) // ss or (major == 3 and ndir) or nminifat > 1 << 20:
            raise _Bad
        if self.dir_start > _MAXREGSECT:
            raise _Bad
        per = ss // 4
        heads = struct.unpack_from("<109I", h, 76)
        fat_secs = list(heads[:nfat])
        if any(s != _FREESECT for s in heads[nfat:]) or any(s > _MAXREGSECT for s in fat_secs):
            raise _Bad
        seen = set()
        while len(fat_secs) < nfat:
            if difat > _MAXREGSECT or difat in seen or len(seen) > ndifat + 1:
                raise _Bad
            seen.add(difat)
            blk = self.peek.read((difat + 1) * ss, ss)
            if len(blk) < ss:
                raise _Bad
            vals = struct.unpack(f"<{per}I", blk)
            fat_secs.extend(vals[:per - 1][:nfat - len(fat_secs)])
            difat = vals[-1]
        self.fat: list[int] = []
        self.truncated = False
        top = -1
        for k, s in enumerate(fat_secs):
            if s > _MAXREGSECT:
                raise _Bad
            blk = self.peek.read((s + 1) * ss, ss)
            if len(blk) < ss:
                self.truncated = True
                blk = blk + b"\xff" * (ss - len(blk))
            used = blk.rstrip(b"\xff")
            if used:
                top = k * per + (len(used) - 1) // 4
            self.fat.extend(struct.unpack(f"<{per}I", blk))
        if top < 0:
            raise _Bad
        self.top = top                              # the highest sector in use
        self.length = (top + 2) * ss
        self.entries = self._directory()
        self._mini: list[int] | None = None
        self._minifat: list[int] | None = None

    def chain(self, start: int, table: list[int] | None = None, limit: int = 1 << 22) -> list[int]:
        table = self.fat if table is None else table
        out: list[int] = []
        seen = set()
        s = start
        while s <= _MAXREGSECT and len(out) < limit:
            if s in seen or s >= len(table):
                break
            seen.add(s)
            out.append(s)
            s = table[s]
        return out

    def _directory(self) -> list[tuple]:
        ss = self.ss
        out = []
        for s in self.chain(self.dir_start, limit=65536):
            blk = self.peek.read((s + 1) * ss, ss)
            if len(blk) < ss:
                break
            for i in range(0, ss, 128):
                e = blk[i:i + 128]
                nlen, typ = struct.unpack_from("<HB", e, 64)
                if typ == 0:
                    out.append(None)
                    continue
                if typ not in (1, 2, 5) or not 2 <= nlen <= 64 or nlen % 2:
                    out.append(None)
                    continue
                name = e[:nlen - 2].decode("utf-16-le", "replace")
                left, right, child = struct.unpack_from("<III", e, 68)
                start = struct.unpack_from("<I", e, 116)[0]
                size = struct.unpack_from("<Q", e, 120)[0]
                if ss == 512:
                    size &= 0xFFFFFFFF
                mtime = struct.unpack_from("<Q", e, 108)[0]
                out.append((name, typ, left, right, child, e[80:96], start, size, mtime))
        if not out or out[0] is None or out[0][1] != 5:
            raise _Bad
        return out

    def top_level(self) -> list[tuple]:
        """The entries directly under the root storage (a walk of its sibling tree)."""
        out = []
        stack = [self.entries[0][4]]
        seen = set()
        while stack and len(out) < 10000:
            i = stack.pop()
            if i > _MAXREGSECT or i in seen or i >= len(self.entries):
                continue
            seen.add(i)
            e = self.entries[i]
            if e is None:
                continue
            out.append(e)
            stack.extend((e[2], e[3]))
        return out

    def stream(self, entry: tuple, cap: int = MiB) -> bytes:
        size = min(entry[7], cap)
        ss = self.ss
        out = bytearray()
        if entry[7] < 4096:
            if self._mini is None:
                root = self.entries[0]
                self._mini = self.chain(root[6], limit=(min(root[7], 64 * MiB) + ss - 1) // ss)
                raw = b"".join(self.peek.read((s + 1) * ss, ss) for s in self.chain(self.minifat_start, limit=4096))
                self._minifat = list(struct.unpack(f"<{len(raw) // 4}I", raw[:len(raw) // 4 * 4]))
            for ms in self.chain(entry[6], self._minifat, limit=(size + 63) // 64):
                k, rel = divmod(ms * 64, ss)
                if k >= len(self._mini):
                    break
                out += self.peek.read((self._mini[k] + 1) * ss + rel, 64)
        else:
            for s in self.chain(entry[6], limit=(size + ss - 1) // ss):
                out += self.peek.read((s + 1) * ss, ss)
        return bytes(out[:size])


def parse_ole(r: Reader) -> Hit | None:
    try:
        cfb = _Cfb(r)
    except (_Bad, struct.error):
        h = r.read(0, 512)
        if len(h) == 512 and h[:8] == OLE_MAGIC and h[28:34] in (b"\xfe\xff\x09\x00\x06\x00",
                                                                b"\xfe\xff\x0c\x00\x06\x00"):
            # a sound header, but the allocation table or the directory is gone (overwritten, cut short)
            return Hit("doc", None, CHANCE_POOR, description="Damaged Office 97-2003 document")
        return None
    top = cfb.top_level()
    names = {e[0] for e in top}
    kind = _ole_kind(cfb, names, top)
    ext, category, description = _OLE_KINDS[kind]
    chance = CHANCE_POOR if cfb.truncated or cfb.length > r.limit else CHANCE_GOOD
    hit = Hit(ext, min(cfb.length, r.limit), chance, category=category, description=description,
              info={"sector_size": cfb.ss})
    if kind == "encrypted":
        hit.info["encrypted"] = True
    try:
        if kind == "msg":
            _msg_meta(cfb, top, hit)
        else:
            _ole_summary(cfb, top, hit, kind)
    except (struct.error, IndexError, ValueError):
        pass                                        # the properties are a bonus
    return hit


def _ole_kind(cfb: _Cfb, names: set[str], top: list[tuple]) -> str:
    if "WordDocument" in names:
        return "doc"
    if "Workbook" in names or "Book" in names:
        return "xls"
    if "PowerPoint Document" in names:
        return "ppt"
    if "__properties_version1.0" in names or any(n.startswith("__substg1.0_") for n in names):
        return "msg"
    clsid = cfb.entries[0][5]
    if clsid == _CLSID_MSI or any(n[:1] == "\u4840" for n in names):
        return "msi"
    if clsid == _CLSID_MSP:
        return "msp"
    if clsid == _CLSID_MST:
        return "mst"
    if "VisioDocument" in names:
        return "vsd"
    if "Quill" in names:
        return "pub"
    if "FileHeader" in names and ("BodyText" in names or "DocInfo" in names):
        return "hwp"
    if "EncryptedPackage" in names and "EncryptionInfo" in names:
        return "encrypted"
    if "Catalog" in names and any(n.isdigit() for n in names):
        return "db"
    return "ole"


def ole_properties(data: bytes) -> dict[int, object]:
    """The first section of an OLE property set stream (SummaryInformation): {property id: value}."""
    if len(data) < 48 or data[:2] != b"\xfe\xff":
        return {}
    off = struct.unpack_from("<I", data, 44)[0]
    if off + 8 > len(data):
        return {}
    count = min(struct.unpack_from("<I", data, off + 4)[0], 1000)
    raw: dict[int, tuple[int, object]] = {}
    for i in range(count):
        q = off + 8 + i * 8
        if q + 8 > len(data):
            break
        pid, poff = struct.unpack_from("<II", data, q)
        p = off + poff
        if p + 8 > len(data):
            continue
        vt = struct.unpack_from("<I", data, p)[0] & 0xFFFF
        if vt == 2:
            raw[pid] = (vt, struct.unpack_from("<h", data, p + 4)[0])
        elif vt == 3:
            raw[pid] = (vt, struct.unpack_from("<i", data, p + 4)[0])
        elif vt == 0x1E:
            n = struct.unpack_from("<I", data, p + 4)[0]
            raw[pid] = (vt, data[p + 8:p + 8 + min(n, 4096)])
        elif vt == 0x1F:
            n = struct.unpack_from("<I", data, p + 4)[0]
            raw[pid] = (vt, data[p + 8:p + 8 + min(n, 2048) * 2].decode("utf-16-le", "replace"))
        elif vt == 0x40 and p + 12 <= len(data):
            raw[pid] = (vt, struct.unpack_from("<Q", data, p + 4)[0])
    cp = raw.get(1, (0, 1252))[1]
    codepage = {1200: "utf-16-le", 65001: "utf-8", 10000: "mac_roman"}.get(cp, f"cp{cp & 0xFFFF}")
    out: dict[int, object] = {}
    for pid, (vt, val) in raw.items():
        if vt == 0x1E:
            val = _decode(val, codepage).split("\x00")[0]
        elif vt == 0x1F:
            val = val.split("\x00")[0]
        out[pid] = val
    return out


def _ole_summary(cfb: _Cfb, top: list[tuple], hit: Hit, kind: str) -> None:
    ent = next((e for e in top if e[0] == "\x05SummaryInformation" and e[1] == 2), None)
    if ent is None:
        return
    props = ole_properties(cfb.stream(ent, 64 * KiB))
    title = props.get(3 if kind in ("msi", "msp", "mst") else 2)       # an installer's product is its subject
    if isinstance(title, str) and clean_title(title):
        hit.name = clean_title(title)
        hit.info["title"] = hit.name
    author = props.get(4)
    if isinstance(author, str) and author.strip():
        hit.info["author"] = author.strip()
    app = props.get(0x12)
    if isinstance(app, str) and app.strip():
        hit.info["application"] = app.strip()
    for pid in (0x0D, 0x0C):                        # last saved, created
        v = props.get(pid)
        if isinstance(v, int) and plausible(filetime(v)):
            hit.mtime = plausible(filetime(v))
            break


def _msg_meta(cfb: _Cfb, top: list[tuple], hit: Hit) -> None:
    """An Outlook message: its subject names the file, its sending time dates it."""
    by_name = {e[0]: e for e in top}
    subject = None
    for name, enc in (("__substg1.0_0037001F", "utf-16-le"), ("__substg1.0_0037001E", "cp1252")):
        e = by_name.get(name)
        if e is not None:
            subject = _decode(cfb.stream(e, 8 * KiB), enc).split("\x00")[0]
            break
    if subject and clean_title(subject):
        hit.name = clean_title(subject)
        hit.info["subject"] = hit.name
    e = by_name.get("__substg1.0_0C1A001F")
    if e is not None:
        sender = cfb.stream(e, 1024).decode("utf-16-le", "replace").split("\x00")[0].strip()
        if sender:
            hit.info["from"] = sender
    e = by_name.get("__properties_version1.0")
    if e is not None:
        data = cfb.stream(e, 64 * KiB)
        times = {}
        for q in range(32, len(data) - 15, 16):
            tag, _flags, value = struct.unpack_from("<IIQ", data, q)
            if tag in (0x00390040, 0x0E060040):     # PR_CLIENT_SUBMIT_TIME, PR_MESSAGE_DELIVERY_TIME
                times[tag] = value
        for tag in (0x00390040, 0x0E060040):
            if tag in times and plausible(filetime(times[tag])):
                hit.mtime = plausible(filetime(times[tag]))
                break


# ---------------------------------------------------------------------- RTF
_RTF_HEAD = re.compile(rb"\{\\rtf(?:1|\\)")
_RTF_TOKENS = re.compile(rb"\\bin(-?\d{1,10}) ?|\\[\\{}]|[{}]|\x00")
_RTF_GROUP = re.compile(rb"\{\\(title|author|operator|subject)\s?((?:\\.|[^{}\\])*)\}")
_RTF_TIME = re.compile(rb"\{\\(creatim|revtim)((?:\\[a-z]+-?\d*\s?)+)\}")


def parse_rtf(r: Reader) -> Hit | None:
    head = r.read(0, 4096)
    if not _RTF_HEAD.match(head) or _BINARY.search(head[:256].split(b"\x00")[0]) or b"\x00" in head[:32]:
        return None
    cap = min(r.limit, RTF_MAX)
    depth = 0
    pos = 0
    end = None
    while pos < cap and end is None:
        buf = r.read(pos, min(MiB, cap - pos))
        if not buf:
            break
        safe = len(buf) - 32 if pos + len(buf) < cap else len(buf)
        resume = pos + safe
        for m in _RTF_TOKENS.finditer(buf):
            if m.start() >= safe:
                break
            t = m.group()
            resume = max(resume, pos + m.end())
            if t == b"{":
                depth += 1
            elif t == b"}":
                depth -= 1
                if depth <= 0:
                    end = pos + m.end()
                    break
            elif t == b"\x00":
                # the text stops before the document closes: overwritten or fragmented
                return _rtf_hit(r, head, None, CHANCE_POOR)
            elif t.startswith(b"\\bin"):
                n = int(m.group(1))
                if n > 0:                          # raw binary data: braces inside don't count
                    resume = pos + m.end() + n
                    break
        pos = resume
    if end is None:
        return _rtf_hit(r, head, None, CHANCE_POOR)
    tail = r.read(end, 2)
    end += 2 if tail == b"\r\n" else 1 if tail[:1] in (b"\r", b"\n") else 0
    return _rtf_hit(r, head, end, CHANCE_GOOD)


_RTF_TEXT = re.compile(rb"\\'([0-9a-fA-F]{2})|\\u(-?\d+)\??|\\([{}\\])|\\[a-zA-Z]+-?\d* ?|([^\\]+)")


def _rtf_text(raw: bytes) -> str:
    """The text of an RTF group: hex escapes (Windows-1252), Unicode escapes, control words dropped."""
    out = []
    for m in _RTF_TEXT.finditer(raw):
        if m.group(1):
            out.append(bytes([int(m.group(1), 16)]).decode("cp1252", "replace"))
        elif m.group(2):
            out.append(chr(int(m.group(2)) & 0xFFFF))
        elif m.group(3):
            out.append(m.group(3).decode())
        elif m.group(4):
            out.append(m.group(4).decode("cp1252", "replace"))
    return "".join(out)


def _rtf_hit(r: Reader, head: bytes, length: int | None, chance: int) -> Hit:
    hit = Hit("rtf", length, chance, info={})
    meta = r.read(0, 64 * KiB)
    for m in _RTF_GROUP.finditer(meta):
        key, text = m.group(1).decode(), clean_title(_rtf_text(m.group(2)))
        if not text:
            continue
        if key == "title":
            hit.name = text
            hit.info["title"] = text
        elif key in ("author", "operator") and "author" not in hit.info:
            hit.info["author"] = text
    times = {}
    for m in _RTF_TIME.finditer(meta):
        parts = dict((k.decode(), int(v)) for k, v in re.findall(rb"\\([a-z]+)(-?\d+)", m.group(2)))
        try:
            t = calendar.timegm((parts.get("yr", 0), parts.get("mo", 1), parts.get("dy", 1), parts.get("hr", 0),
                                 parts.get("min", 0), parts.get("sec", 0), 0, 0, 0))
        except (ValueError, OverflowError):
            continue
        times[m.group(1).decode()] = plausible(t)
    hit.mtime = times.get("revtim") or times.get("creatim")
    g = re.search(rb"\{\\\*\\generator\s*([^;{}]{1,100})", meta)
    if g:
        hit.info["application"] = g.group(1).decode("latin-1").strip()
    return hit


# ---------------------------------------------------------------------- PostScript, EPS
_PS_MARKS = re.compile(rb"%%(EOF|BeginDocument|EndDocument)")


def parse_ps(r: Reader) -> Hit | None:
    head = r.read(0, 4096)
    first = head.split(b"\n")[0].split(b"\r")[0]
    if not first.startswith(b"%!PS") or len(first) > 128 or _BINARY.search(first):
        return None
    if not re.match(rb"%!PS(?:-Adobe-\d\.\d)?(?:\s|$)", first + b"\n"):
        return None
    eps = b"EPSF" in first
    cap = min(r.limit, PS_MAX)
    depth = 0
    pos = 0
    end = None
    while pos < cap and end is None:
        buf = r.read(pos, min(4 * MiB, cap - pos))
        if not buf:
            break
        safe = len(buf) - 16 if pos + len(buf) < cap else len(buf)
        nxt = buf.find(b"%!PS", 1 if pos == 0 else 0, safe)
        while nxt >= 0 and (pos + nxt) % 512:
            nxt = buf.find(b"%!PS", nxt + 1, safe)
        if nxt >= 0:                               # the next PostScript file starts there: stop looking
            safe = nxt
            cap = pos + nxt
        resume = pos + safe
        for m in _PS_MARKS.finditer(buf, 0, safe + 16 if nxt < 0 else safe):
            if m.start() >= safe:
                break
            resume = pos + m.end()
            word = m.group(1)
            if word == b"BeginDocument":
                depth += 1
            elif word == b"EndDocument":
                depth = max(0, depth - 1)
            elif depth == 0:
                end = pos + m.end()
                break
        pos = resume
    chance = CHANCE_GOOD
    if end is None:
        end, chance = text_end(r, 0, cap), CHANCE_FAIR    # no %%EOF: the text runs out where the file did
        if end < 64:
            return None
    else:
        tail = r.read(end, 3)
        k = 2 if tail[:2] == b"\r\n" else 1 if tail[:1] in (b"\r", b"\n") else 0
        k += 1 if tail[k:k + 1] == b"\x04" else 0  # the Ctrl-D printer drivers append
        end += k
    hit = Hit("eps" if eps else "ps", end, chance, info={}, description="Encapsulated PostScript" if eps else None)
    dsc = r.read(0, min(end, 16 * KiB))
    fields = dict((k.decode(), v.decode("latin-1").strip(" ()"))
                  for k, v in re.findall(rb"^%%(Title|Creator|CreationDate|For):[ \t]*([^\r\n]*)", dsc, re.M))
    if clean_title(fields.get("Title")):
        hit.name = clean_title(fields["Title"])
        hit.info["title"] = hit.name
    if fields.get("Creator"):
        hit.info["application"] = fields["Creator"]
        if "Illustrator" in fields["Creator"]:
            hit.ext, hit.category, hit.description = "ai", "photo", "Adobe Illustrator artwork"
    if fields.get("For"):
        hit.info["author"] = fields["For"]
    hit.mtime = _loose_date(fields.get("CreationDate"))
    return hit


def _loose_date(text: str | None) -> float | None:
    """The free-form dates of PostScript comments ("Mon Jan  2 15:04:05 2006", "2006-01-02 15:04", ...)."""
    if not text:
        return None
    t = iso_date(text) or _pdf_date(text)
    if t:
        return t
    for fmt in ("%a %b %d %H:%M:%S %Y", "%b %d %H:%M:%S %Y", "%d/%m/%Y %H:%M", "%m/%d/%y %H:%M"):
        try:
            return plausible(calendar.timegm(time.strptime(" ".join(text.split()), fmt)))
        except ValueError:
            continue
    return None


def parse_eps_dos(r: Reader) -> Hit | None:
    """The DOS EPS binary header: a PostScript section plus a WMF or TIFF preview, all listed in the header."""
    h = r.read(0, 30)
    if len(h) < 30 or h[:4] != b"\xc5\xd0\xd3\xc6":
        return None
    ps_off, ps_len, wmf_off, wmf_len, tif_off, tif_len = struct.unpack_from("<6I", h, 4)
    if ps_off < 30 or ps_len < 16 or r.read(ps_off, 4) != b"%!PS":
        return None
    end = ps_off + ps_len
    for off, n in ((wmf_off, wmf_len), (tif_off, tif_len)):
        if off and n:
            if off < 30:
                return None
            end = max(end, off + n)
    chance = CHANCE_GOOD if end <= r.limit else CHANCE_POOR
    return Hit("eps", min(end, r.limit), chance, description="Encapsulated PostScript (with preview)",
               info={"preview": "TIFF" if tif_len else "WMF" if wmf_len else None})


# ---------------------------------------------------------------------- DjVu, CHM, WordPerfect, MOBI, Write
def parse_djvu(r: Reader) -> Hit | None:
    h = r.read(0, 32)
    if len(h) < 24 or h[:8] != b"AT&TFORM" or h[12:16] not in (b"DJVU", b"DJVM", b"DJVI", b"THUM"):
        return None
    size = struct.unpack_from(">I", h, 8)[0]
    if size < 12 or h[16:20] not in (b"INFO", b"DIRM", b"INCL", b"Djbz", b"ANTa", b"ANTz", b"TH44", b"Sjbz"):
        return None
    info = {}
    if h[16:20] == b"INFO" and len(h) >= 28:
        info = {"width": struct.unpack_from(">H", h, 24)[0], "height": struct.unpack_from(">H", h, 26)[0]}
    if h[12:16] == b"DJVM":
        info["pages"] = "several"
    end = 12 + size
    return Hit("djvu", min(end, r.limit), CHANCE_GOOD if end <= r.limit else CHANCE_POOR, info=info)


_CHM_GUID = bytes.fromhex("10fd017caa7bd0119e0c00a0c922e6ec")


def parse_chm(r: Reader) -> Hit | None:
    h = r.read(0, 0x60)
    if len(h) < 0x58 or h[:4] != b"ITSF":
        return None
    version, hlen = struct.unpack_from("<II", h, 4)
    if version not in (2, 3) or hlen not in (0x58, 0x60) or h[0x18:0x28] != _CHM_GUID:
        return None
    sec0_off, sec0_len, sec1_off, sec1_len = struct.unpack_from("<QQQQ", h, 0x38)
    if not hlen <= sec0_off < 1 << 32 or sec0_len < 24 or sec1_off < sec0_off:
        return None
    sec0 = r.read(sec0_off, 24)
    info = {"language": struct.unpack_from("<I", h, 0x14)[0]}
    if len(sec0) == 24 and struct.unpack_from("<I", sec0, 0)[0] == 0x1FE:
        size = struct.unpack_from("<Q", sec0, 8)[0]
        if sec1_off + sec1_len <= size < 1 << 34:
            return Hit("chm", min(size, r.limit), CHANCE_GOOD if size <= r.limit else CHANCE_POOR, info=info)
    return Hit("chm", None, CHANCE_FAIR, info=info)


def parse_wpd(r: Reader) -> Hit | None:
    h = r.read(0, 16)
    if len(h) < 16 or h[:4] != b"\xffWPC":
        return None
    docptr = struct.unpack_from("<I", h, 4)[0]
    product, ftype, major = h[8], h[9], h[10]
    if product != 1 or ftype != 0x0A or major > 3 or not 16 <= docptr < 64 * MiB:
        return None
    version = {0: "5.x", 1: "5.x", 2: "6 or later"}.get(major, str(major))
    return Hit("wpd", None, CHANCE_FAIR, info={"version": version, "encrypted": bool(struct.unpack_from("<H", h, 12)[0])})


_PDB_EPOCH = 2082844800                            # 1904-01-01 → 1970-01-01


def parse_mobi(r: Reader) -> Hit | None:
    h = r.read(0, 78)
    if len(h) < 78 or h[60:68] not in (b"BOOKMOBI", b"TEXtREAd"):
        return None
    name = h[:32].split(b"\x00")[0]
    if not name or _BINARY.search(name):
        return None
    nrec = struct.unpack_from(">H", h, 76)[0]
    if not 1 <= nrec <= 65000:
        return None
    table = r.read(78, nrec * 8)
    if len(table) < nrec * 8:
        return None
    offsets = [struct.unpack_from(">I", table, i * 8)[0] for i in range(nrec)]
    if offsets[0] < 78 + nrec * 8 or any(b < a for a, b in zip(offsets, offsets[1:])):
        return None
    rec0 = r.read(offsets[0], 0x30)
    if h[60:68] == b"BOOKMOBI" and rec0[16:20] != b"MOBI":
        return None
    ext = "mobi" if h[60:68] == b"BOOKMOBI" else "pdb"
    if ext == "mobi" and len(rec0) >= 0x28 and struct.unpack_from(">I", rec0, 0x24)[0] == 8:
        ext = "azw3"                               # Kindle Format 8
    last = offsets[-1]
    length = last + 4 if r.read(last, 4) == b"\xe9\x8e\r\n" else None   # the end-of-file record
    ctime = struct.unpack_from(">I", h, 36)[0]
    t = ctime - _PDB_EPOCH if ctime & 0x80000000 else ctime
    hit = Hit(ext, length, CHANCE_GOOD if length else CHANCE_FAIR, mtime=plausible(t), info={"records": nrec})
    title = clean_title(name.decode("latin-1").replace("_", " "))
    if title:
        hit.name = title
        hit.info["title"] = title
    return hit


def parse_wri(r: Reader) -> Hit | None:
    """Windows Write (and Word for DOS): the header counts the file's 128-byte pages."""
    h = r.read(0, 128)
    if len(h) < 128 or h[:2] not in (b"\x31\xbe", b"\x32\xbe") or h[2:6] != b"\x00\x00\x00\xab" or any(h[6:14]):
        return None
    fcmac = struct.unpack_from("<I", h, 14)[0]
    pnmac = struct.unpack_from("<H", h, 0x60)[0]
    if fcmac < 128 or pnmac * 128 < fcmac or any(h[0x1E:0x60]):
        return None
    end = pnmac * 128
    return Hit("wri", min(end, r.limit), CHANCE_GOOD if end <= r.limit else CHANCE_POOR)


# ---------------------------------------------------------------------- HTML, XML, scripts, text
_HTML_START = re.compile(rb"(?:\xef\xbb\xbf)?\s*(?:<!doctype\s+html|<html)[\s>]", re.I)
_HTML_TAG = re.compile(rb"<(?:head|body|title|meta|html)[\s>]", re.I)
_HTML_END = re.compile(rb"</html\s*>", re.I)


def _closing(r: Reader, pattern: re.Pattern, end: int) -> int | None:
    """End of the first PATTERN match in [0, end), chunk by chunk."""
    pos = 0
    while pos < end:
        n = min(4 * MiB, end - pos)
        buf = r.read(pos, n + 64 if pos + n < end else n)
        m = pattern.search(buf)
        if m and pos + m.end() <= end:
            return pos + m.end()
        pos += n
    return None


def _element_end(r: Reader, name: bytes, start: int, stop: int) -> int | None:
    """End of the element NAME whose start tag is at START (elements of the same name inside it counted)."""
    tag = re.compile(rb"<(/?)" + re.escape(name) + rb"(?=[\s/>])[^<>]*>")
    depth = 0
    pos = start
    while pos < stop:
        n = min(4 * MiB, stop - pos)
        buf = r.read(pos, n)
        safe = n - 64 * KiB if pos + n < stop else n      # a tag across the boundary is read next time
        resume = pos + safe
        for m in tag.finditer(buf):
            if m.start() >= safe:
                break
            resume = max(resume, pos + m.end())
            if m.group(1):
                depth -= 1
            elif not m.group().endswith(b"/>"):
                depth += 1
            if depth <= 0:
                return pos + m.end()
        pos = resume
    return None


def _eol(r: Reader, end: int, limit: int) -> int:
    tail = r.read(end, 2)
    k = 2 if tail == b"\r\n" else 1 if tail[:1] in (b"\r", b"\n") else 0
    return min(end + k, limit)


def parse_html(r: Reader) -> Hit | None:
    head = r.read(0, 4096)
    if not _HTML_START.match(head):
        return None
    stop = text_end(r, 0, HTML_MAX)
    head = head[:stop]
    if stop < 32 or not _HTML_TAG.search(head, 5):
        return None
    close = _closing(r, _HTML_END, stop)
    if close is None:
        if stop < 64:
            return None
        hit = Hit("html", stop, CHANCE_FAIR)
    else:
        hit = Hit("html", _eol(r, close, stop), CHANCE_GOOD)
    m = re.search(rb"<title[^>]*>([^<]{1,300})</title", head, re.I)
    if m:
        cs = re.search(rb"charset=[\"']?([\w-]+)", head, re.I)
        title = clean_title(html.unescape(_decode(m.group(1), cs.group(1).decode() if cs else "utf-8")))
        if title:
            hit.name = title
            hit.info = {"title": title}
    return hit


_XML_DECL = re.compile(rb"(?:\xef\xbb\xbf)?<\?xml\s+version\s*=\s*[\"']1\.[01][\"'][^>]{0,200}\?>")
_XML_SKIP = re.compile(rb"\s*(?:<!--.*?-->|<\?.*?\?>|<!DOCTYPE[^\[>]*(?:\[.*?\])?\s*>)", re.S)
_XML_ROOT = re.compile(rb"<([A-Za-z_][\w.:-]{0,100})[\s/>]")
# root elements that name another kind of file; None: another module's format handles it
_XML_KINDS = {
    "svg": None, "plist": None,
    "html": ("html", "document", "XHTML page"), "kml": ("kml", "other", "Google Earth placemarks"),
    "gpx": ("gpx", "other", "GPS track"), "rss": ("rss", "document", "RSS feed"),
    "feed": ("atom", "document", "Atom feed"), "x:xmpmeta": ("xmp", "other", "XMP metadata"),
    "xsl:stylesheet": ("xsl", "document", "XSLT stylesheet"), "xs:schema": ("xsd", "document", "XML schema"),
    "COLLADA": ("dae", "other", "COLLADA 3D model"), "office:document": ("fodt", "document", "Flat OpenDocument"),
}


def parse_xml(r: Reader) -> Hit | None:
    head = r.read(0, 64 * KiB)
    m = _XML_DECL.match(head)
    if not m:
        return None
    stop = text_end(r, 0, HTML_MAX)
    head = head[:stop]
    if stop < 32:
        return None
    pos = m.end()
    for _ in range(64):
        s = _XML_SKIP.match(head, pos)
        if not s or s.end() == pos:
            break
        pos = s.end()
    while pos < len(head) and head[pos:pos + 1].isspace():
        pos += 1
    root = _XML_ROOT.match(head, pos)
    if not root:
        return None
    name = root.group(1).decode("ascii", "replace")
    kind = _XML_KINDS.get(name, ("xml", "document", None))
    if kind is None:
        return None
    if name == "office:document":
        mime = re.search(rb'office:mimetype="application/vnd\.oasis\.opendocument\.(\w+)', head)
        kind = ({"spreadsheet": "fods", "presentation": "fodp", "graphics": "fodg"}.get(
            mime.group(1).decode() if mime else "", "fodt"), kind[1], kind[2])
    close = _element_end(r, root.group(1), pos, stop)
    if close is None and stop < 64:
        return None
    hit = Hit(kind[0], _eol(r, close, stop) if close else stop, CHANCE_GOOD if close else CHANCE_FAIR,
              description=kind[2], category=kind[1], info={"root": name})
    title = re.search(rb"<(?:\w+:)?title[^>]*>([^<]{1,300})</", head)
    if title:
        t = clean_title(html.unescape(_decode(title.group(1), "utf-8")))
        if t:
            hit.name = t
    if name == "office:document":                  # flat OpenDocument: the same properties as in meta.xml
        meta = _decode(head[:head.find(b"</office:meta>")] if b"</office:meta>" in head else b"", "utf-8")
        author = xml_text(meta, "meta:initial-creator", "dc:creator")
        if author:
            hit.info["author"] = author
        hit.mtime = iso_date(xml_text(meta, "dc:date") or "") or iso_date(xml_text(meta, "meta:creation-date") or "")
    return hit


_SHEBANG = re.compile(rb"#!\s?(/[\w./+-]{1,100})(?:[ \t]+([\w.+-]{1,40}))?[^\r\n]{0,100}\r?\n")
_INTERPRETERS = {
    "sh": "sh", "bash": "sh", "dash": "sh", "zsh": "sh", "ksh": "sh", "ash": "sh", "csh": "csh", "tcsh": "csh",
    "python": "py", "perl": "pl", "ruby": "rb", "node": "js", "nodejs": "js", "php": "php", "lua": "lua",
    "awk": "awk", "gawk": "awk", "tclsh": "tcl", "wish": "tcl", "Rscript": "r", "pwsh": "ps1", "fish": "fish",
}


def parse_script(r: Reader) -> Hit | None:
    m = _SHEBANG.match(r.read(0, 512))
    if not m:
        return None
    prog = m.group(1).decode().rsplit("/", 1)[-1]
    if prog == "env" and m.group(2):
        prog = m.group(2).decode()
    base = re.sub(r"[\d.]+$", "", prog)            # python3.11 → python
    ext = _INTERPRETERS.get(base) or _INTERPRETERS.get(prog)
    if ext is None:
        return None
    end = text_end(r, 0, TEXT_MAX)
    if end < m.end() + 8:
        return None
    return Hit(ext, end, CHANCE_FAIR, info={"interpreter": prog})


def _texty(buf: bytes) -> bool:
    """Whether BUF reads as text: no control bytes, valid UTF-8 (or mostly ASCII), many letters."""
    if not buf or _BINARY.search(buf):
        return False
    try:
        text = buf.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start < len(buf) - 4:
            text = buf.decode("latin-1")
            if sum(c > 0x7F for c in buf) > len(buf) // 10:
                return False
        else:
            text = buf[:exc.start].decode("utf-8")
    letters = sum(ch.isalnum() or ch.isspace() for ch in text)
    return letters >= len(text) * 0.75


def parse_txt(r: Reader) -> Hit | None:
    head = r.read(0, 2048)
    if head[:1] in (b"<", b"{", b"%") or head[:2] == b"#!":
        return None                                 # HTML/XML, RTF/JSON, PDF/PostScript, scripts: own formats
    if len(head) < 512 or _BINARY.search(head, 0, 512) or not _texty(head.split(b"\x00")[0]):
        return None
    end = text_end(r, 0, TEXT_MAX)
    if end < 512:
        return None
    return Hit("txt", end, CHANCE_FAIR)


# ---------------------------------------------------------------------- the formats
# Text has no signature: every block that starts with a character that can start a text is a candidate
# (that is why the format is off unless asked for).
_TEXT_MAGIC = tuple((0, bytes([c])) for c in b"\t\n\r" + bytes(range(0x20, 0x7F)) + bytes(range(0xC2, 0xF5))
                    if c not in b"<{%") + ((0, b"\xef\xbb\xbf"),)
_HTML_MAGIC = tuple((0, bom + tag) for bom in (b"", b"\xef\xbb\xbf")
                    for tag in (b"<!DOCTYPE html", b"<!DOCTYPE HTML", b"<!doctype html", b"<!Doctype html",
                                b"<html", b"<HTML"))

FORMATS: list[Format] = [
    Format("pdf", "PDF document", "document", ("pdf", "ai"), ((0, b"%PDF-"),), parse_pdf, max_size=PDF_MAX,
           min_size=64),
    Format("ole", "Office 97-2003 document (OLE2)", "document",
           ("doc", "xls", "ppt", "msg", "msi", "msp", "mst", "vsd", "pub", "db", "hwp", "ole"),
           ((0, OLE_MAGIC),), parse_ole, max_size=OLE_MAX, min_size=1024,
           aliases=("doc", "xls", "ppt", "msg", "msi", "vsd", "pub", "cfb", "office")),
    Format("rtf", "Rich Text document", "document", ("rtf",), ((0, b"{\\rtf"),), parse_rtf, max_size=RTF_MAX,
           min_size=16),
    Format("ps", "PostScript document", "document", ("ps", "eps", "ai"), ((0, b"%!PS"),), parse_ps,
           max_size=PS_MAX, min_size=64, aliases=("postscript",)),
    Format("eps", "EPS image with preview", "document", ("eps",), ((0, b"\xc5\xd0\xd3\xc6"),), parse_eps_dos,
           max_size=PS_MAX, min_size=64),
    Format("djvu", "DjVu document", "document", ("djvu",), ((0, b"AT&TFORM"),), parse_djvu, min_size=32),
    Format("chm", "Compiled HTML help", "document", ("chm",), ((0, b"ITSF"),), parse_chm, max_size=GiB,
           min_size=0x60),
    Format("wpd", "WordPerfect document", "document", ("wpd",), ((0, b"\xffWPC"),), parse_wpd, max_size=256 * MiB,
           min_size=32, aliases=("wordperfect",)),
    Format("mobi", "Kindle / Mobipocket e-book", "document", ("mobi", "azw3", "azw", "pdb"),
           ((60, b"BOOKMOBI"), (60, b"TEXtREAd")), parse_mobi, max_size=GiB, min_size=128, aliases=("azw", "azw3")),
    Format("wri", "Windows Write document", "document", ("wri",), ((0, b"\x31\xbe\x00\x00\x00\xab"),
           (0, b"\x32\xbe\x00\x00\x00\xab")), parse_wri, max_size=64 * MiB, min_size=256),
    Format("html", "Web page", "document", ("html",), _HTML_MAGIC, parse_html, max_size=HTML_MAX, min_size=32,
           aliases=("htm",)),
    Format("xml", "XML document", "document", ("xml", "html", "kml", "gpx", "rss", "atom", "xmp", "xsl", "xsd",
                                              "dae", "fodt", "fods", "fodp", "fodg"),
           ((0, b"<?xml "), (0, b"\xef\xbb\xbf<?xml ")), parse_xml, max_size=HTML_MAX, min_size=32),
    Format("script", "Script", "document", ("sh", "py", "pl", "rb", "js", "php", "lua", "awk", "tcl", "r", "ps1",
                                           "csh", "fish"),
           ((0, b"#!/"), (0, b"#! /")), parse_script, max_size=TEXT_MAX, min_size=16),
    Format("txt", "Plain text", "document", ("txt",), _TEXT_MAGIC, parse_txt, max_size=TEXT_MAX, min_size=512,
           enabled=False, aliases=("text",)),
]
