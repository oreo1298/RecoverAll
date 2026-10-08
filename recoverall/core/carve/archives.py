"""Archives and compressed files for the signature engine: ZIP (and everything built on it: Office and
OpenDocument files, EPUB books, Java and Android packages...), RAR, 7-Zip, gzip, bzip2, xz, Zstandard, LZ4,
lzip, tar, cabinet, cpio, ar/deb, RPM, xar, ARJ, LHA, SquashFS, WIM and ISO 9660 images.

Archives are the friendliest files to carve: almost all of them say how long they are, either in a header
(cabinet, 7-Zip, SquashFS, WIM, ISO, RPM) or through a chain of headers that can be walked without unpacking
anything (ZIP, RAR, tar, cpio, ar, ARJ, LHA, xz, Zstandard, LZ4). Plain compressed streams have no length
field, so they are followed to their end: gzip and lzip by unpacking them (which also proves the data is
intact), bzip2 by finding its bit-aligned block markers and checking the stream checksum.

A ZIP file is named after what is inside: a .docx has ``word/document.xml``, an .odt or .epub says so in its
``mimetype`` member, a .jar has a Java manifest, an .apk an Android one. Office and OpenDocument files give
their title, author and dates from their properties, without unpacking more than those few kilobytes.

A file that stops making sense half-way (overwritten, or fragmented on the disk) is cut where the last good
piece ends and gets a poor chance. Multi-volume RAR and ZIP parts are recognised and flagged.
"""

from __future__ import annotations

import bz2
import calendar
import lzma
import re
import struct
import zlib
from dataclasses import dataclass

from ..fs.base import dos_datetime
from .base import CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, Format, GiB, Hit, KiB, MiB, Reader
from .documents import Peek, clean_title, iso_date, plausible, xml_text

ZIP_MAX = 64 * GiB
STREAM_MAX = 16 * GiB          # gzip/bzip2/lzip are unpacked or scanned to find their end: cap the work
BIG_MAX = 64 * GiB


class _Bad(Exception):
    """A structure that doesn't hold together."""


def _vint(b: bytes, i: int) -> tuple[int, int]:
    """A little-endian base-128 number (RAR 5, xz) at B[i] → (value, next index)."""
    v = 0
    shift = 0
    while i < len(b) and shift <= 63:
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        if not c & 0x80:
            return v, i
        shift += 7
    raise _Bad


def _dos(stamp: int) -> float | None:
    """A DOS date and time packed in 32 bits (date in the high half)."""
    return plausible(dos_datetime(stamp >> 16, stamp & 0xFFFF))


def _ending(r: Reader, end: int, align: int, chance: int = CHANCE_GOOD) -> tuple[int, int]:
    """END grown over the zero padding some writers add up to a multiple of ALIGN (tar records, SquashFS),
    as (length, chance); and the chance lowered when the file runs past the end of the disk."""
    if end > r.limit:
        return r.limit, CHANCE_POOR
    padded = -(-end // align) * align
    if padded > end and padded <= r.limit and not any(r.read(end, padded - end)):
        end = padded
    return end, chance


@dataclass(slots=True)
class _Inflated:
    end: int | None        # just past the deflate stream; None when it broke or ran out
    error: bool            # the data isn't deflate (or is damaged), as opposed to cut short
    crc: int
    size: int              # bytes unpacked
    head: bytes            # the first bytes unpacked (to recognise a .tar.gz)


def _inflate(r: Reader, start: int, cap: int, wbits: int = -15, want_crc: bool = False,
             keep_head: int = 0) -> _Inflated:
    """Unpack a deflate stream starting at START only to learn where it ends (the output is dropped)."""
    d = zlib.decompressobj(wbits)
    pos = start
    end = min(r.limit, start + cap)
    crc = size = 0
    head = b""
    while pos < end:
        chunk = r.read(pos, min(MiB, end - pos))
        if not chunk:
            break
        data = chunk
        while data:
            try:
                out = d.decompress(data, 4 * MiB)
            except zlib.error:
                return _Inflated(None, True, crc, size, head)
            size += len(out)
            if want_crc:
                crc = zlib.crc32(out, crc)
            if len(head) < keep_head:
                head += out[:keep_head - len(head)]
            if d.eof:
                return _Inflated(pos + len(chunk) - len(d.unused_data), False, crc, size, head)
            data = d.unconsumed_tail
        pos += len(chunk)
    return _Inflated(None, False, crc, size, head)


# ---------------------------------------------------------------------- ZIP
_LOCAL, _CENTRAL, _EOCD = b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06"
_EOCD64, _LOC64, _DESC = b"PK\x06\x06", b"PK\x06\x07", b"PK\x07\x08"
_ZIP_METHODS = frozenset({0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 14, 16, 18, 19, 20, 93, 94, 95, 96, 97, 98, 99})
_ZIP_SIGS = re.compile(rb"PK(?:\x07\x08|\x03\x04|\x01\x02|\x05\x06|\x06\x06)")
_ZIP_BADNAME = re.compile(rb"[\x00-\x1f]")
_APK_SIG_BLOCK = b"APK Sig Block 42"
_ZIP_DESC_SEARCH = GiB         # how far to look for the data descriptor of a streamed member


@dataclass(slots=True)
class _Member:
    name: str
    offset: int            # of the local header
    data: int              # of the (compressed) data
    csize: int
    method: int
    flags: int
    when: float | None


def _zip_extra(extra: bytes) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    i = 0
    while i + 4 <= len(extra):
        hid, n = struct.unpack_from("<HH", extra, i)
        out.setdefault(hid, extra[i + 4:i + 4 + n])
        i += 4 + n
    return out


def _zip_local(p: Peek, pos: int) -> _Member | None:
    h = p.read(pos, 30)
    if len(h) < 30 or h[:4] != _LOCAL:
        return None
    ver, flags, method, tm, dt, _crc, csize, usize, nlen, xlen = struct.unpack_from("<HHHHHIIIHH", h, 4)
    if (ver & 0xFF) > 99 or method not in _ZIP_METHODS or flags & 0xD780 or not 1 <= nlen <= 4096:
        return None
    raw = p.read(pos + 30, nlen + xlen)
    if len(raw) < nlen + xlen or _ZIP_BADNAME.search(raw[:nlen]):
        return None
    if method == 0 and not flags & 9 and csize != usize and csize != 0xFFFFFFFF:
        return None                                # stored, unencrypted: both sizes are the same
    extra = _zip_extra(raw[nlen:])
    z64 = extra.get(0x0001)
    if z64 and (csize == 0xFFFFFFFF or usize == 0xFFFFFFFF):
        vals = [struct.unpack_from("<Q", z64, i)[0] for i in range(0, len(z64) - 7, 8)]
        if len(vals) >= 2:
            csize = vals[1]                        # a local header carries both sizes, in this order
        elif vals and usize != 0xFFFFFFFF:
            csize = vals[0]
    when = None
    ut = extra.get(0x5455)                         # "UT": Unix times, in UTC
    if ut and len(ut) >= 5 and ut[0] & 1:
        when = plausible(struct.unpack_from("<I", ut, 1)[0])
    if when is None:
        when = plausible(dos_datetime(dt, tm))
    name = raw[:nlen].decode("utf-8" if flags & 0x800 else "cp437", "replace")
    return _Member(name, pos, pos + 30 + nlen + xlen, csize, method, flags, when)


def _zip_desc_at(p: Peek, data: int, q: int) -> int | None:
    """End of the data descriptor at Q, if one that matches data starting at DATA is there."""
    size = q - data
    b = p.read(q, 28)
    if b[:4] == _DESC:
        if len(b) >= 16 and struct.unpack_from("<I", b, 8)[0] == size:
            return q + 16
        if len(b) >= 24 and struct.unpack_from("<Q", b, 8)[0] == size:
            return q + 24
        return None
    if len(b) >= 16 and struct.unpack_from("<I", b, 4)[0] == size and b[12:14] == b"PK":
        return q + 12
    if len(b) >= 24 and struct.unpack_from("<Q", b, 4)[0] == size and b[20:22] == b"PK":
        return q + 20
    return None


def _zip_desc_search(r: Reader, p: Peek, data: int, span: int = _ZIP_DESC_SEARCH) -> tuple[int, int] | None:
    """(data end, descriptor end) for a member whose sizes come after its data: the first signature
    within SPAN bytes after the data whose descriptor gives the right compressed size."""
    pos = data
    cap = min(r.limit, data + span)
    step = 4 * MiB
    while pos < cap:
        buf = r.read(pos, min(step, cap - pos) + 32)
        for m in _ZIP_SIGS.finditer(buf):
            q = pos + m.start()
            if q >= pos + step:
                break
            if m.group() == _DESC:
                end = _zip_desc_at(p, data, q)
                if end:
                    return q, end
                continue
            for dlen, fmt, n in ((12, "<I", 4), (20, "<Q", 8)):    # a descriptor without its signature
                s = q - dlen
                if s >= data and struct.unpack(fmt, p.read(s + 4, n).ljust(n, b"\0"))[0] == s - data:
                    return s, q
        pos += step
    return None


def _zip_after(r: Reader, p: Peek, m: _Member) -> tuple[int, int] | None:
    """(data end, member end) of a member: from its header, or by finding its data descriptor."""
    if not m.flags & 8:
        return m.data + m.csize, m.data + m.csize
    if m.csize not in (0, 0xFFFFFFFF):
        end = _zip_desc_at(p, m.data, m.data + m.csize)
        if end:
            return m.data + m.csize, end
    if m.method == 8 and not m.flags & 1:
        res = _inflate(r, m.data, _ZIP_DESC_SEARCH)
        if res.end is not None:
            end = _zip_desc_at(p, m.data, res.end)
            if end:
                return res.end, end
        # damaged data (bad sectors read as zeros?): the descriptor may still be found nearby
        return _zip_desc_search(r, p, m.data, 64 * MiB)
    return _zip_desc_search(r, p, m.data)


def _zip_central(p: Peek, cd: int) -> tuple | None:
    """Walk the central directory at CD to the end record: (end, entries, lines_up, disk, comment) with
    entries [(name, local header offset, time)], or None if it doesn't end in an end record."""
    pos = cd
    entries = []
    while len(entries) < 4_000_000:
        h = p.read(pos, 46)
        if len(h) < 46 or h[:4] != _CENTRAL:
            break
        tm, dt = struct.unpack_from("<HH", h, 12)
        nlen, xlen, clen = struct.unpack_from("<HHH", h, 28)
        lho = struct.unpack_from("<I", h, 42)[0]
        raw = p.read(pos + 46, nlen + xlen)
        if lho == 0xFFFFFFFF:
            # the ZIP64 field holds the sizes first, but only those that didn't fit in 32 bits
            z64 = _zip_extra(raw[nlen:]).get(0x0001, b"")
            csize, usize = struct.unpack_from("<II", h, 20)
            skip = 8 * ((usize == 0xFFFFFFFF) + (csize == 0xFFFFFFFF))
            if len(z64) >= skip + 8:
                lho = struct.unpack_from("<Q", z64, skip)[0]
        entries.append((raw[:nlen].decode("utf-8", "replace"), lho, plausible(dos_datetime(dt, tm))))
        pos += 46 + nlen + xlen + clen
    cd_end = pos
    if p.read(pos, 4) == b"PK\x05\x05":            # digital signature
        pos += 6 + struct.unpack("<H", p.read(pos + 4, 2).ljust(2, b"\0"))[0]
    z64 = None
    if p.read(pos, 4) == _EOCD64:
        rec = p.read(pos, 56)
        if len(rec) < 56:
            return None
        size, = struct.unpack_from("<Q", rec, 4)
        total, cdsize, cdoff = struct.unpack_from("<QQQ", rec, 32)
        z64 = (total, cdsize, cdoff)
        pos += 12 + size
        if p.read(pos, 4) == _LOC64:
            pos += 20
    e = p.read(pos, 22)
    if len(e) < 22 or e[:4] != _EOCD:
        return None
    disk, _cddisk, _nd, total, cdsize, cdoff, clen = struct.unpack_from("<HHHHIIH", e, 4)
    if z64:
        total = z64[0] if total == 0xFFFF else total
        cdsize = z64[1] if cdsize == 0xFFFFFFFF else cdsize
        cdoff = z64[2] if cdoff == 0xFFFFFFFF else cdoff
    lines_up = cdoff == cd and cdsize == cd_end - cd and total & 0xFFFF == len(entries) & 0xFFFF
    comment = p.read(pos + 22, min(clen, 1024)).decode("cp437", "replace").strip()
    return pos + 22 + clen, entries, lines_up, disk, comment


def _zip_eocd_near(r: Reader, p: Peek, start: int, span: int) -> tuple | None:
    """An end record within SPAN bytes after START whose central directory lines up with it."""
    pos = start
    end = min(r.limit, start + span)
    while pos < end:
        e = r.find(_EOCD, pos, end)
        if e < 0:
            return None
        rec = p.read(e, 22)
        if len(rec) == 22:
            cdsize, cdoff = struct.unpack_from("<II", rec, 12)
            cd = cdoff
            if cdoff == 0xFFFFFFFF and p.read(e - 20, 4) == _LOC64:
                loc = struct.unpack_from("<Q", p.read(e - 12, 8))[0]
                rec64 = p.read(loc, 56)
                if rec64[:4] == _EOCD64 and len(rec64) == 56:
                    cd = struct.unpack_from("<Q", rec64, 48)[0]
            if cd < e and p.read(cd, 4) == _CENTRAL:
                tail = _zip_central(p, cd)
                if tail and tail[0] - 22 - struct.unpack_from("<H", rec, 20)[0] == e and tail[2]:
                    return tail
        pos = e + 1
    return None


def parse_zip(r: Reader) -> Hit | None:
    p = Peek(r)
    first = _zip_local(p, 0)
    if first is None:
        return None
    members: list[_Member] = []
    pos = 0
    tail = None
    chance = CHANCE_GOOD
    while len(members) < 2_000_000:
        sig = p.read(pos, 4)
        if sig == _LOCAL:
            m = _zip_local(p, pos)
            after = _zip_after(r, p, m) if m else None
            if after is None:
                break
            m.csize = after[0] - m.data
            members.append(m)
            pos = after[1]
            if pos > r.limit:
                break
        elif sig == _CENTRAL:
            tail = _zip_central(p, pos)
            break
        elif sig == b"PK\x06\x08":                 # archive extra data record
            pos += 8 + struct.unpack("<I", p.read(pos + 4, 4).ljust(4, b"\0"))[0]
        else:
            # The APK signature block sits between the last member and the central directory.
            size = struct.unpack("<Q", p.read(pos, 8).ljust(8, b"\0"))[0]
            if 32 <= size < GiB and p.read(pos + 8 + size - 16, 16) == _APK_SIG_BLOCK:
                pos += 8 + size
                continue
            break
    if not members:
        return None
    if tail is None:
        # The walk broke: a damaged or unusual member. If an end record lines up a little further on,
        # the archive is whole; otherwise it was cut (overwritten or fragmented) after the last good member.
        tail = _zip_eocd_near(r, p, min(pos, r.limit), MiB)
        chance = CHANCE_FAIR
    if tail is not None:
        end, entries, lines_up, disk, comment = tail
        if not lines_up:
            chance = CHANCE_FAIR
        elif chance == CHANCE_GOOD and {e[1] for e in entries} != {m.offset for m in members}:
            chance = CHANCE_FAIR
    else:
        end, entries, disk, comment = min(pos, r.limit), [], 0, ""
        chance = CHANCE_POOR
    if end > r.limit:
        end, chance = r.limit, CHANCE_POOR
    return _zip_hit(r, members, entries, end, chance, disk, comment)


# What a ZIP is, from its members: (ext, category, description)
_ZIP_MIME = {
    "application/vnd.oasis.opendocument.text": ("odt", "document", "OpenDocument text"),
    "application/vnd.oasis.opendocument.text-template": ("ott", "document", "OpenDocument text template"),
    "application/vnd.oasis.opendocument.text-master": ("odm", "document", "OpenDocument master document"),
    "application/vnd.oasis.opendocument.spreadsheet": ("ods", "document", "OpenDocument spreadsheet"),
    "application/vnd.oasis.opendocument.spreadsheet-template": ("ots", "document", "OpenDocument spreadsheet "
                                                                                     "template"),
    "application/vnd.oasis.opendocument.presentation": ("odp", "document", "OpenDocument presentation"),
    "application/vnd.oasis.opendocument.presentation-template": ("otp", "document", "OpenDocument presentation "
                                                                                       "template"),
    "application/vnd.oasis.opendocument.graphics": ("odg", "document", "OpenDocument drawing"),
    "application/vnd.oasis.opendocument.graphics-template": ("otg", "document", "OpenDocument drawing template"),
    "application/vnd.oasis.opendocument.formula": ("odf", "document", "OpenDocument formula"),
    "application/vnd.oasis.opendocument.chart": ("odc", "document", "OpenDocument chart"),
    "application/vnd.oasis.opendocument.database": ("odb", "database", "OpenDocument database"),
    "application/vnd.sun.xml.writer": ("sxw", "document", "OpenOffice.org 1 text"),
    "application/vnd.sun.xml.calc": ("sxc", "document", "OpenOffice.org 1 spreadsheet"),
    "application/vnd.sun.xml.impress": ("sxi", "document", "OpenOffice.org 1 presentation"),
    "application/vnd.sun.xml.draw": ("sxd", "document", "OpenOffice.org 1 drawing"),
    "application/epub+zip": ("epub", "document", "EPUB e-book"),
    "application/x-krita": ("kra", "photo", "Krita painting"),
    "image/openraster": ("ora", "photo", "OpenRaster image"),
    "application/vnd.adobe.indesign-idml-package": ("idml", "document", "InDesign markup"),
}
_ZIP_KINDS = {
    "docx": ("document", "Word document"), "docm": ("document", "Word macro-enabled document"),
    "dotx": ("document", "Word template"), "dotm": ("document", "Word macro-enabled template"),
    "xlsx": ("document", "Excel workbook"), "xlsm": ("document", "Excel macro-enabled workbook"),
    "xltx": ("document", "Excel template"), "xltm": ("document", "Excel macro-enabled template"),
    "xlsb": ("document", "Excel binary workbook"), "xlam": ("document", "Excel add-in"),
    "pptx": ("document", "PowerPoint presentation"), "pptm": ("document", "PowerPoint macro-enabled presentation"),
    "ppsx": ("document", "PowerPoint slide show"), "ppsm": ("document", "PowerPoint macro-enabled slide show"),
    "potx": ("document", "PowerPoint template"), "potm": ("document", "PowerPoint macro-enabled template"),
    "vsdx": ("document", "Visio drawing"), "vsdm": ("document", "Visio macro-enabled drawing"),
    "xps": ("document", "XPS document"), "oxps": ("document", "OpenXPS document"),
    "3mf": ("other", "3D Manufacturing model"), "nupkg": ("archive", "NuGet package"),
    "appx": ("executable", "Windows app package"), "appxbundle": ("executable", "Windows app bundle"),
    "pages": ("document", "Pages document"), "numbers": ("document", "Numbers spreadsheet"),
    "key": ("document", "Keynote presentation"),
    "apk": ("executable", "Android app"), "aab": ("executable", "Android app bundle"),
    "aar": ("executable", "Android library"), "ipa": ("executable", "iOS app"),
    "jar": ("executable", "Java archive"), "war": ("executable", "Java web application"),
    "ear": ("executable", "Java enterprise application"), "xpi": ("executable", "Firefox extension"),
    "vsix": ("executable", "Visual Studio extension"), "whl": ("archive", "Python wheel"),
    "egg": ("archive", "Python egg"), "kmz": ("other", "Google Earth placemarks"),
    "sketch": ("photo", "Sketch design"), "zip": ("archive", "ZIP archive"),
}


def _zip_kind(names: list[str], mime: str | None, ct: str) -> tuple[str, str, str]:
    if mime:
        mime = mime.strip()
        if mime in _ZIP_MIME:
            return _ZIP_MIME[mime]
        if mime.startswith("application/vnd.oasis.opendocument."):
            return "odt", "document", "OpenDocument file"
    has = set(names)

    def prefixed(prefix: str) -> bool:
        return any(n.startswith(prefix) for n in names)

    ext = "zip"
    if "[Content_Types].xml" in has:
        if prefixed("word/"):
            ext = "dotm" if "macroenabledtemplate" in ct else "dotx" if "wordprocessingml.template" in ct else \
                "docm" if "macroenabled" in ct or "word/vbaProject.bin" in has else "docx"
        elif prefixed("xl/"):
            ext = "xlsb" if "sheet.binary" in ct or "xl/workbook.bin" in has else \
                "xlam" if "addin.macroenabled" in ct else "xltm" if "template.macroenabled" in ct else \
                "xltx" if "spreadsheetml.template" in ct else \
                "xlsm" if "macroenabled" in ct or "xl/vbaProject.bin" in has else "xlsx"
        elif prefixed("ppt/"):
            ext = "ppsm" if "slideshow.macroenabled" in ct else "potm" if "template.macroenabled" in ct else \
                "pptm" if "macroenabled" in ct or "ppt/vbaProject.bin" in has else \
                "ppsx" if "presentationml.slideshow" in ct else "potx" if "presentationml.template" in ct else "pptx"
        elif prefixed("visio/"):
            ext = "vsdm" if "macroenabled" in ct else "vsdx"
        elif any(n.endswith(".fdseq") for n in names):
            ext = "xps"
        elif "3D/3dmodel.model" in has or prefixed("3D/"):
            ext = "3mf"
        elif "AppxMetadata/AppxBundleManifest.xml" in has:
            ext = "appxbundle"
        elif "AppxManifest.xml" in has:
            ext = "appx"
        elif any(n.endswith(".nuspec") and "/" not in n for n in names):
            ext = "nupkg"
    if ext == "zip":
        if "AndroidManifest.xml" in has and (prefixed("classes") or "resources.arsc" in has):
            ext = "apk"
        elif "BundleConfig.pb" in has and "base/manifest/AndroidManifest.xml" in has:
            ext = "aab"
        elif "AndroidManifest.xml" in has and "classes.jar" in has:
            ext = "aar"
        elif any(n.startswith("Payload/") and ".app/" in n for n in names):
            ext = "ipa"
        elif "Index/Document.iwa" in has or prefixed("Index/") and any(n.endswith(".iwa") for n in names):
            ext = "numbers" if "Index/CalculationEngine.iwa" in has else \
                "key" if prefixed("Index/Slide") or prefixed("Index/MasterSlide") else "pages"
        elif "META-INF/MANIFEST.MF" in has or prefixed("META-INF/") and any(n.endswith(".class") for n in names):
            ext = "war" if prefixed("WEB-INF/") else "ear" if "META-INF/application.xml" in has else "jar"
        elif "install.rdf" in has or "manifest.json" in has and prefixed("META-INF/mozilla"):
            ext = "xpi"
        elif "extension.vsixmanifest" in has:
            ext = "vsix"
        elif any(n.endswith(".dist-info/WHEEL") for n in names):
            ext = "whl"
        elif "EGG-INFO/PKG-INFO" in has:
            ext = "egg"
        elif "doc.kml" in has:
            ext = "kmz"
        elif "document.json" in has and "meta.json" in has:
            ext = "sketch"
    category, description = _ZIP_KINDS[ext]
    return ext, category, description


def _zip_read(r: Reader, m: _Member, cap: int = 256 * KiB) -> bytes:
    """The content of a small member (stored or deflated), for its properties; b"" if that isn't possible."""
    if m.flags & 1 or m.csize > 8 * MiB:
        return b""
    raw = r.read(m.data, m.csize)
    if m.method == 0:
        return raw[:cap]
    if m.method == 8:
        try:
            return zlib.decompressobj(-15).decompress(raw, cap)
        except zlib.error:
            return b""
    return b""


def _zip_hit(r: Reader, members: list[_Member], entries: list, end: int, chance: int, disk: int,
             comment: str) -> Hit:
    names = [m.name for m in members]
    if len(entries) > len(members):
        seen = set(names)
        names += [e[0] for e in entries if e[0] not in seen]
    by_name = {m.name: m for m in members}
    first = members[0]
    mime = None
    if first.name == "mimetype" and first.method == 0 and first.csize <= 200:
        mime = r.read(first.data, first.csize).decode("ascii", "replace")
    ct = ""
    if "[Content_Types].xml" in by_name:
        ct = _zip_read(r, by_name["[Content_Types].xml"]).decode("utf-8", "replace").lower()
    ext, category, description = _zip_kind(names, mime, ct)
    info: dict = {"files": max(len(entries), len(members))}
    if any(m.flags & 1 for m in members):
        info["encrypted"] = True
    if disk:
        info["volume"] = disk + 1                 # the last part of a split archive
        chance = min(chance, CHANCE_FAIR)
    if comment:
        info["comment"] = comment[:200]
    hit = Hit(ext, end, chance, info=info, category=category, description=description)
    try:
        _zip_meta(r, hit, by_name, names)
    except (UnicodeDecodeError, ValueError, struct.error):
        pass
    if hit.mtime is None:
        times = [m.when for m in members if m.when] + [e[2] for e in entries if e[2]]
        if times:
            hit.mtime = max(times)
    return hit


def _zip_meta(r: Reader, hit: Hit, by_name: dict[str, _Member], names: list[str]) -> None:
    """Title, author, application and dates from the document properties inside the ZIP."""
    def text(name: str) -> str:
        m = by_name.get(name)
        return _zip_read(r, m).decode("utf-8", "replace") if m else ""

    title = author = app = None
    when = None
    if hit.ext in ("odt", "ott", "odm", "ods", "ots", "odp", "otp", "odg", "otg", "odf", "odc", "odb", "sxw", "sxc",
                   "sxi", "sxd"):
        meta = text("meta.xml")
        title = xml_text(meta, "dc:title")
        author = xml_text(meta, "meta:initial-creator", "dc:creator")
        app = xml_text(meta, "meta:generator")
        when = iso_date(xml_text(meta, "dc:date") or "") or iso_date(xml_text(meta, "meta:creation-date") or "")
    elif hit.ext == "epub":
        opf = next((n for n in names if n.endswith(".opf")), None)
        meta = text(opf) if opf else ""
        title = xml_text(meta, "dc:title")
        author = xml_text(meta, "dc:creator")
        mod = re.search(r'property="dcterms:modified"[^>]*>([^<]+)<', meta)
        when = iso_date(mod.group(1) if mod else "") or iso_date(xml_text(meta, "dc:date") or "")
    elif "docProps/core.xml" in by_name:
        core = text("docProps/core.xml")
        title = xml_text(core, "dc:title")
        author = xml_text(core, "dc:creator", "cp:lastModifiedBy")
        when = iso_date(xml_text(core, "dcterms:modified") or "") or iso_date(xml_text(core, "dcterms:created")
                                                                             or "")
        app = xml_text(text("docProps/app.xml"), "Application")
        if hit.ext == "xps" and "openxps" in text("_rels/.rels").lower():
            hit.ext, hit.description = "oxps", "OpenXPS document"
    elif hit.ext in ("jar", "war", "ear"):
        mf = text("META-INF/MANIFEST.MF")
        fields = dict(re.findall(r"^([\w-]+):\s*(.+?)\s*$", mf, re.M))
        title = fields.get("Implementation-Title") or fields.get("Bundle-Name")
        app = fields.get("Created-By")
    elif hit.ext == "whl":
        meta = next((n for n in names if n.endswith(".dist-info/METADATA")), None)
        fields = dict(re.findall(r"^(Name|Version):\s*(.+?)\s*$", text(meta) if meta else "", re.M))
        if fields.get("Name"):
            title = "-".join(filter(None, (fields.get("Name"), fields.get("Version"))))
    title = clean_title(title)
    if title:
        hit.name = title
        hit.info["title"] = title
    if author:
        hit.info["author"] = author
    if app:
        hit.info["application"] = app
    if when:
        hit.mtime = when


# ---------------------------------------------------------------------- RAR
def parse_rar(r: Reader) -> Hit | None:
    h = r.read(0, 8)
    try:
        if h == b"Rar!\x1a\x07\x01\x00":
            return _rar5(r)
        if h[:7] == b"Rar!\x1a\x07\x00":
            return _rar4(r)
    except (_Bad, struct.error):
        return None
    return None


def _rar_hit(r: Reader, end: int | None, done: bool, files: int, info: dict, newest: float | None) -> Hit | None:
    if not files and not done:
        return None
    if end is None:
        return Hit("rar", None, CHANCE_FAIR, info=info, mtime=newest)
    chance = CHANCE_GOOD if done else CHANCE_FAIR
    if done and info.get("more_volumes"):
        end, chance = _ending(r, end, 512, chance)   # rar pads a volume to the size asked for
    if end > r.limit:
        end, chance = r.limit, CHANCE_POOR
    if info.get("volume"):
        chance = min(chance, CHANCE_FAIR)
    info["files"] = files
    return Hit("rar", end, chance, info=info, mtime=newest)


def _rar4(r: Reader) -> Hit | None:
    """RAR 1.5-4: blocks with a 16-bit header checksum; the end-of-archive block (0x7B) closes it."""
    p = Peek(r)
    pos = 7
    files = 0
    newest = None
    info: dict = {"version": 4}
    done = False
    for n in range(2_000_000):
        h = p.read(pos, 7)
        if len(h) < 7:
            break
        crc, typ, flags, size = struct.unpack("<HBHH", h)
        if size < 7 or not 0x73 <= typ <= 0x7B or (n == 0 and typ != 0x73):
            if n == 0:
                return None
            break
        hdr = p.read(pos, size)
        if len(hdr) < size or zlib.crc32(hdr[2:]) & 0xFFFF != crc:
            if n == 0:
                return None
            break
        add = 0
        if typ in (0x74, 0x7A):
            if size < 32:
                break
            add = struct.unpack_from("<I", hdr, 7)[0]
            if flags & 0x100 and size >= 40:
                add += struct.unpack_from("<I", hdr, 32)[0] << 32
        elif flags & 0x8000:
            add = struct.unpack_from("<I", hdr, 7)[0]
        if typ == 0x73:
            if flags & 0x0001:
                info["volume"] = "first" if flags & 0x0100 else "next"
            if flags & 0x0008:
                info["solid"] = True
            if flags & 0x0080:                     # the headers are encrypted: nothing more to read
                info["encrypted"] = True
                return _rar_hit(r, None, False, 1, info, None)
        elif typ == 0x74:
            files += 1
            when = _dos(struct.unpack_from("<I", hdr, 20)[0])
            if when and (newest is None or when > newest):
                newest = when
            if flags & 0x04:
                info["encrypted"] = True
        pos += size + add
        if typ == 0x7B:
            done = True
            if flags & 0x0001:
                info["volume"] = info.get("volume") or "next"
                info["more_volumes"] = True
            break
    return _rar_hit(r, pos, done, files, info, newest)


def _rar5(r: Reader) -> Hit | None:
    """RAR 5: headers with a CRC32 and variable-length numbers; the end-of-archive header (type 5) closes it."""
    p = Peek(r)
    pos = 8
    files = 0
    newest = None
    info: dict = {"version": 5}
    done = False
    for n in range(2_000_000):
        h = p.read(pos, 16)
        if len(h) < 7:
            break
        crc = struct.unpack_from("<I", h, 0)[0]
        hsize, i = _vint(h, 4)
        if not 3 <= hsize <= 2 * MiB or i > 7:
            if n == 0:
                return None
            break
        hdr = p.read(pos + 4, i - 4 + hsize)
        if len(hdr) < i - 4 + hsize or zlib.crc32(hdr) != crc:
            if n == 0:
                return None
            break
        q = i - 4
        typ, q = _vint(hdr, q)
        hflags, q = _vint(hdr, q)
        data = 0
        if hflags & 1:
            _extra, q = _vint(hdr, q)
        if hflags & 2:
            data, q = _vint(hdr, q)
        if n == 0 and typ not in (1, 4):
            return None
        if typ == 4:                               # the headers are encrypted
            info["encrypted"] = True
            return _rar_hit(r, None, False, 1, info, None)
        if typ == 1:
            aflags, q = _vint(hdr, q)
            if aflags & 1:
                volnum = _vint(hdr, q)[0] if aflags & 2 else 0
                info["volume"] = "first" if volnum == 0 else volnum + 1
            if aflags & 4:
                info["solid"] = True
        elif typ == 2:
            files += 1
            fflags, q = _vint(hdr, q)
            _usize, q = _vint(hdr, q)
            _attrs, q = _vint(hdr, q)
            if fflags & 2:
                when = plausible(struct.unpack_from("<I", hdr, q)[0])
                if when and (newest is None or when > newest):
                    newest = when
        pos += 4 + (i - 4) + hsize + data
        if typ == 5:
            done = True
            if _vint(hdr, q)[0] & 1:
                info.setdefault("volume", "next")
                info["more_volumes"] = True
            break
    return _rar_hit(r, pos, done, files, info, newest)


# ---------------------------------------------------------------------- 7-Zip
def parse_7z(r: Reader) -> Hit | None:
    h = r.read(0, 32)
    if len(h) < 32 or h[:6] != b"7z\xbc\xaf\x27\x1c" or h[6] != 0 or h[7] > 4:
        return None
    if zlib.crc32(h[12:32]) != struct.unpack_from("<I", h, 8)[0]:
        return None
    off, size, crc = struct.unpack_from("<QQI", h, 12)
    if size == 0 or size > GiB or off > BIG_MAX:
        return None                                # empty, or never finished (its header is written last)
    end = 32 + off + size
    if end > r.limit:
        return Hit("7z", r.limit, CHANCE_POOR)
    chance = CHANCE_GOOD
    if size <= 64 * MiB:
        nh = r.read(32 + off, size)
        if zlib.crc32(nh) != crc or nh[:1] not in (b"\x01", b"\x17"):
            chance = CHANCE_POOR                   # the directory at the end isn't this archive's
    return Hit("7z", end, chance, info={"encoded_header": r.read(32 + off, 1) == b"\x17"})


# ---------------------------------------------------------------------- gzip
def _gz_header(p: Peek, pos: int) -> tuple[int, str | None, int] | None:
    """(data offset, original name, mtime) of a gzip member header at POS."""
    h = p.read(pos, 10)
    if len(h) < 10 or h[:3] != b"\x1f\x8b\x08":
        return None
    flg, mtime, xfl, os_ = h[3], struct.unpack_from("<I", h, 4)[0], h[8], h[9]
    if flg & 0xE0 or xfl not in (0, 2, 4) or (os_ > 13 and os_ != 255):
        return None
    q = pos + 10
    if flg & 4:
        xlen = p.read(q, 2)
        if len(xlen) < 2:
            return None
        q += 2 + struct.unpack("<H", xlen)[0]
    name = None
    if flg & 8:
        b = p.read(q, 1024)
        i = b.find(b"\x00")
        if i < 0:
            return None
        name = b[:i].decode("latin-1")
        q += i + 1
    if flg & 16:
        b = p.read(q, 64 * KiB)
        i = b.find(b"\x00")
        if i < 0:
            return None
        q += i + 1
    if flg & 2:
        q += 2
    return q, name, mtime


def _gz_end(r: Reader, p: Peek, pos: int, cap: int) -> tuple[int | None, bool, bytes, bool]:
    """(end, crc_ok, first bytes unpacked, junk) of the gzip members starting at POS (pigz and BGZF write
    many). END is None when the first member is broken or cut short; JUNK when it isn't deflate at all."""
    hdr = _gz_header(p, pos)
    if hdr is None:
        return None, False, b"", True
    good = True
    head = b""
    members = 0
    while hdr is not None and members < 1_000_000:
        res = _inflate(r, hdr[0], cap - hdr[0], want_crc=True, keep_head=512 if not members else 0)
        if not members:
            head = res.head
        trailer = p.read(res.end, 8) if res.end is not None else b""
        if len(trailer) < 8:
            if not members:
                return None, False, head, res.error and res.size < 1024
            return pos, False, head, False         # a later member is broken: keep the good ones
        crc, isize = struct.unpack("<II", trailer)
        if crc != res.crc or isize != res.size & 0xFFFFFFFF:
            good = False
        pos = res.end + 8
        members += 1
        if pos >= cap or p.read(pos, 3) != b"\x1f\x8b\x08":
            break
        hdr = _gz_header(p, pos)
    return pos, good, head, False


def parse_gz(r: Reader) -> Hit | None:
    p = Peek(r)
    hdr = _gz_header(p, 0)
    if hdr is None:
        return None
    end, ok, head, junk = _gz_end(r, p, 0, min(r.limit, STREAM_MAX))
    if junk:
        return None
    ext, category, description = "gz", None, None
    if head[257:262] == b"ustar":
        ext, description = "tar.gz", "Compressed tar archive"
    elif head[:4] == b"BAM\x01":
        ext, category, description = "bam", "other", "BAM sequence alignment"
    name = hdr[1]
    if name:
        name = clean_title(name.replace("\\", "/").rsplit("/", 1)[-1])
        if name and ext == "tar.gz" and name.lower().endswith(".tar"):
            name = name[:-4]
    chance = CHANCE_GOOD if end is not None and ok else CHANCE_POOR
    info = {"original_name": hdr[1]} if hdr[1] else {}
    return Hit(ext, end, chance, name=name or None, mtime=plausible(hdr[2]) if hdr[2] else None, info=info,
               category=category, description=description)


# ---------------------------------------------------------------------- bzip2
_BZ_BLOCK, _BZ_EOS = 0x314159265359, 0x177245385090


def _bz_patterns() -> list[tuple]:
    """For each magic and each of the 8 bit positions it can start at: the whole bytes to search for, and
    masks to check the partial bytes around them."""
    out = []
    for magic, kind in ((_BZ_BLOCK, 0), (_BZ_EOS, 1)):
        for s in range(8):
            w = (magic << (8 - s)).to_bytes(7, "big")
            if s == 0:
                out.append((w[:6], 0, 0, 0, 0, 0, kind))
            else:
                pm, qm = (1 << (8 - s)) - 1, (0xFF << (8 - s)) & 0xFF
                out.append((w[1:6], s, pm, w[0] & pm, qm, w[6] & qm, kind))
    return out


_BZ_PATTERNS = _bz_patterns()


def _bz_markers(buf: bytes, pos: int, n: int) -> list[tuple[int, int]]:
    """(bit position, kind) of the block (0) and end-of-stream (1) markers that start in the first N bytes
    of BUF (which holds the bytes from POS on, plus a few more), in order."""
    found = []
    for key, s, pm, pv, qm, qv, kind in _BZ_PATTERNS:
        i = buf.find(key, 1 if s else 0)
        while i >= 0:
            if s == 0:
                if i < n:
                    found.append(((pos + i) * 8, kind))
            elif i + 5 < len(buf) and i - 1 < n and buf[i - 1] & pm == pv and buf[i + 5] & qm == qv:
                found.append(((pos + i - 1) * 8 + s, kind))
            i = buf.find(key, i + 1)
    found.sort()
    return found


def _bits32(r: Reader, bit: int) -> int:
    b = r.read(bit // 8, 5).ljust(5, b"\0")
    return (int.from_bytes(b, "big") >> (8 - bit % 8)) & 0xFFFFFFFF


def _bz2_stream(r: Reader, start: int, cap: int) -> tuple[int | None, bool]:
    """(end, crc_ok) of the bzip2 stream at START. The blocks aren't byte-aligned, so their markers are
    searched at every bit position; consecutive markers must be closer than a block can grow, and the
    stream checksum (combined from the block checksums) must match."""
    h = r.read(start, 10)
    if len(h) < 10 or h[:3] != b"BZh" or not 0x31 <= h[3] <= 0x39:
        return None, False
    first = int.from_bytes(h[4:10], "big")
    if first == _BZ_EOS:
        return start + 14, _bits32(r, (start + 10) * 8) == 0
    if first != _BZ_BLOCK:
        return None, False
    gap = ((h[3] - 0x30) * 250_000 + 65536) * 8    # bits: a block can't grow longer than that
    cur = (start + 4) * 8
    combined = _bits32(r, cur + 48)
    pos = start + 5
    step = 256 * KiB
    while pos < cap and pos * 8 <= cur + gap:
        n = min(step, cap - pos)
        buf = r.read(pos, n + 8)
        if not buf:
            break
        for bit, kind in _bz_markers(buf, pos, n):
            if bit <= cur:
                continue
            if bit - cur > gap:
                return None, False
            crc = _bits32(r, bit + 48)
            if kind == 1:
                return (bit + 48 + 32 + 7) // 8, crc == combined
            combined = (((combined << 1) | (combined >> 31)) & 0xFFFFFFFF) ^ crc
            cur = bit
        pos += n
        step = min(step * 2, 8 * MiB)
    return None, False


def parse_bz2(r: Reader) -> Hit | None:
    cap = min(r.limit, STREAM_MAX)
    end, ok = _bz2_stream(r, 0, cap)
    if end is None:
        h = r.read(0, 10)
        if int.from_bytes(h[4:10], "big") != _BZ_BLOCK:
            return None
        return Hit("bz2", None, CHANCE_POOR)       # starts well, but its end is gone
    streams = 1
    while ok and end < cap and streams < 100_000 and r.read(end, 3) == b"BZh":   # pbzip2 writes several
        nxt, ok2 = _bz2_stream(r, end, cap)
        if nxt is None or not ok2:
            break
        end, streams = nxt, streams + 1
    head = _bz_head(r)
    ext = "tar.bz2" if head[257:262] == b"ustar" else "bz2"
    return Hit(ext, end, CHANCE_GOOD if ok else CHANCE_POOR, description="Compressed tar archive"
               if ext == "tar.bz2" else None)


def _bz_head(r: Reader) -> bytes:
    try:
        d = bz2.BZ2Decompressor()
        return d.decompress(r.read(0, 64 * KiB), 512)
    except (OSError, EOFError, ValueError):
        return b""


# ---------------------------------------------------------------------- xz, lzip
_XZ_MAGIC = b"\xfd7zXZ\x00"
_XZ_CHECK = {0: 0, 1: 4, 4: 8, 10: 32}


def _lzma2_end(p: Peek, pos: int, cap: int) -> int | None:
    """End of the LZMA2 chunks at POS (each chunk header gives its packed size: nothing to unpack)."""
    while pos < cap:
        h = p.read(pos, 6)
        if not h:
            return None
        c = h[0]
        if c == 0:
            return pos + 1
        if c in (1, 2):
            if len(h) < 3:
                return None
            pos += 3 + struct.unpack_from(">H", h, 1)[0] + 1
        elif c >= 0x80:
            if len(h) < 5:
                return None
            pos += (6 if (c >> 5) & 3 >= 2 else 5) + struct.unpack_from(">H", h, 3)[0] + 1
        else:
            return None
    return None


def _xz_stream(p: Peek, start: int, cap: int) -> int | None:
    """End of the xz stream at START: walk the block headers (and their LZMA2 chunks), the index and the
    footer, checking their CRCs."""
    h = p.read(start, 12)
    if len(h) < 12 or h[:6] != _XZ_MAGIC or h[6] or h[7] & 0xF0 or zlib.crc32(h[6:8]) != struct.unpack_from(
            "<I", h, 8)[0]:
        return None
    check = h[7]
    csize = _XZ_CHECK.get(check, 4 << ((check - 1) // 3) if check else 0)
    pos = start + 12
    blocks = 0
    while pos < cap:
        b = p.read(pos, 1)
        if not b:
            return None
        if b[0] == 0:
            break                                  # the index
        hsize = (b[0] + 1) * 4
        hdr = p.read(pos, hsize)
        if len(hdr) < hsize or zlib.crc32(hdr[:-4]) != struct.unpack_from("<I", hdr, hsize - 4)[0]:
            return None
        bflags = hdr[1]
        if bflags & 0x3C:
            return None
        q = 2
        packed = None
        if bflags & 0x40:
            packed, q = _vint(hdr, q)
        if bflags & 0x80:
            _usize, q = _vint(hdr, q)
        last = None
        for _ in range((bflags & 3) + 1):
            last, q = _vint(hdr, q)
            psize, q = _vint(hdr, q)
            q += psize
        data = pos + hsize
        if packed is not None:
            end = data + packed
        elif last == 0x21:
            end = _lzma2_end(p, data, cap)
            if end is None:
                return None
        else:
            return None
        end = start + -(-(end - start) // 4) * 4 + csize
        pos = end
        blocks += 1
    # the index: indicator, record count, records, padding, CRC32
    idx = p.read(pos, 64 * KiB)
    try:
        count, q = _vint(idx, 1)
        if count != blocks:
            return None
        if count > 4096:
            idx = p.read(pos, min(32 * MiB, 1 + 10 + count * 20 + 8))
        for _ in range(count):
            _, q = _vint(idx, q)
            _, q = _vint(idx, q)
    except _Bad:
        return None
    q = -(-q // 4) * 4
    if q + 4 > len(idx) or zlib.crc32(idx[:q]) != struct.unpack_from("<I", idx, q)[0]:
        return None
    foot_at = pos + q + 4
    foot = p.read(foot_at, 12)
    if len(foot) < 12 or foot[10:12] != b"YZ" or foot[8:10] != h[6:8]:
        return None
    if zlib.crc32(foot[4:10]) != struct.unpack_from("<I", foot, 0)[0]:
        return None
    if (struct.unpack_from("<I", foot, 4)[0] + 1) * 4 != q + 4:
        return None
    return foot_at + 12


def parse_xz(r: Reader) -> Hit | None:
    p = Peek(r)
    cap = min(r.limit, BIG_MAX)
    end = _xz_stream(p, 0, cap)
    if end is None:
        h = r.read(0, 12)
        if len(h) < 12 or zlib.crc32(h[6:8]) != struct.unpack_from("<I", h, 8)[0]:
            return None
        return Hit("xz", None, CHANCE_POOR)        # a real header, but the rest is damaged or cut
    for _ in range(10000):                         # concatenated streams, with optional zero padding
        pad = 0
        while pad < 64 * KiB and r.read(end + pad, 4) == b"\0\0\0\0":
            pad += 4
        if r.read(end + pad, 6) != _XZ_MAGIC:
            break
        nxt = _xz_stream(p, end + pad, cap)
        if nxt is None:
            break
        end = nxt
    head = b""
    try:
        head = lzma.LZMADecompressor(lzma.FORMAT_XZ).decompress(r.read(0, 64 * KiB), 512)
    except lzma.LZMAError:
        pass
    ext = "tar.xz" if head[257:262] == b"ustar" else "xz"
    return Hit(ext, end, CHANCE_GOOD, description="Compressed tar archive" if ext == "tar.xz" else None)


def _lzma_raw_end(r: Reader, pos: int, cap: int, dict_size: int) -> tuple[int | None, int]:
    """(end, bytes unpacked) of LZMA data with an end marker (lzip's), unpacking it."""
    d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "dict_size": dict_size,
                                                         "lc": 3, "lp": 0, "pb": 2}])
    size = 0
    try:
        while pos < cap:
            chunk = r.read(pos, min(MiB, cap - pos))
            if not chunk:
                break
            data = chunk
            while data:
                size += len(d.decompress(data, 4 * MiB))
                if d.eof:
                    return pos + len(chunk) - len(d.unused_data), size
                data = d.unconsumed_tail
            pos += len(chunk)
    except lzma.LZMAError:
        pass
    return None, size


def parse_lzip(r: Reader) -> Hit | None:
    """lzip: LZMA data with an end marker, then a trailer that repeats the member size."""
    pos = 0
    cap = min(r.limit, STREAM_MAX)
    members = 0
    while pos < cap and members < 10000:
        h = r.read(pos, 6)
        if len(h) < 6 or h[:4] != b"LZIP" or h[4] != 1:
            break
        ds = 1 << (h[5] & 0x1F)
        ds -= (ds // 16) * (h[5] >> 5)
        if not 4 * KiB <= ds <= 512 * MiB:
            break
        end, size = _lzma_raw_end(r, pos + 6, cap, ds)
        if end is None:
            if not members and size >= 1024:
                return Hit("lz", None, CHANCE_POOR)     # real data, but cut short or damaged
            break
        trailer = r.read(end, 20)
        if len(trailer) < 20 or struct.unpack_from("<Q", trailer, 12)[0] != end + 20 - pos:
            break
        pos = end + 20
        members += 1
    if not members:
        return None
    return Hit("lz", pos, CHANCE_GOOD)


# ---------------------------------------------------------------------- Zstandard, LZ4
def _zstd_block_ok(b: bytes, bsize: int) -> bool:
    """A sanity check of a compressed block's literals and sequences headers (B: its first bytes; random
    data rarely passes)."""
    if not b:
        return False
    ltype, sf = b[0] & 3, (b[0] >> 2) & 3
    if ltype in (0, 1):                            # raw or RLE literals
        hl = 1 if sf in (0, 2) else 2 if sf == 1 else 3
        if len(b) < hl:
            return False
        n = b[0] >> 3 if hl == 1 else (b[0] >> 4) + (b[1] << 4) if hl == 2 else (b[0] >> 4) + (b[1] << 4) + (
            b[2] << 12)
        lit_end = hl + (n if ltype == 0 else 1)
    else:                                          # compressed or treeless literals
        hl = 3 if sf < 2 else 4 if sf == 2 else 5
        if len(b) < hl:
            return False
        v = int.from_bytes(b[:hl], "little") >> 4
        bits = 10 if sf < 2 else 14 if sf == 2 else 18
        regen, comp = v & ((1 << bits) - 1), v >> bits
        if regen > 128 * KiB or comp > regen + 1024 or comp == 0:
            return False
        lit_end = hl + comp
    if lit_end > bsize:
        return False
    if lit_end == bsize:
        return False                               # the sequences section needs at least one byte
    nb = b[lit_end] if lit_end < len(b) else None
    if nb is None:
        return True
    if nb == 0:
        return lit_end + 1 == bsize                # no sequences: the block ends right there
    k = lit_end + (1 if nb < 128 else 2 if nb < 255 else 3)
    if k + 1 > bsize:
        return False
    return k >= len(b) or b[k] & 3 == 0            # the reserved bits of the compression modes


def _zstd_frame(p: Peek, pos: int) -> int | None:
    """End of the Zstandard (or skippable) frame at POS."""
    h = p.read(pos, 18)
    if len(h) < 8:
        return None
    magic = struct.unpack_from("<I", h, 0)[0]
    if 0x184D2A50 <= magic <= 0x184D2A5F:
        return pos + 8 + struct.unpack_from("<I", h, 4)[0]
    if magic != 0xFD2FB528:
        return None
    fhd = h[4]
    if fhd & 0x08:
        return None
    single = fhd & 0x20
    q = 5
    window = None
    if not single:
        exp = (h[q] >> 3) + 10
        if exp > 31:
            return None
        window = 1 << exp
        q += 1
    q += (0, 1, 2, 4)[fhd & 3]
    fcs_len = (1 if single else 0, 2, 4, 8)[fhd >> 6]
    fcs = int.from_bytes(h[q:q + fcs_len], "little") + (256 if fcs_len == 2 else 0) if fcs_len else None
    q += fcs_len
    bmax = min(window or (fcs if fcs is not None else 128 * KiB), 128 * KiB)
    pos += q
    least = most = 0                               # how much the blocks can unpack to
    for _ in range(10_000_000):
        b = p.read(pos, 3)
        if len(b) < 3:
            return None
        v = int.from_bytes(b, "little")
        last, btype, bsize = v & 1, (v >> 1) & 3, v >> 3
        if btype == 3 or bsize > max(bmax, 1):
            return None
        if btype == 2:
            if bsize == 0 or not _zstd_block_ok(p.read(pos + 3, min(bsize, 16)), bsize):
                return None
            most += bmax
        else:
            least += bsize
            most += bsize
        pos += 3 + (1 if btype == 1 else bsize)
        if last:
            break
    else:
        return None
    if fcs is not None and not least <= fcs <= most:
        return None                                # the content size in the header can't be right
    return pos + (4 if fhd & 4 else 0)


def parse_zst(r: Reader) -> Hit | None:
    p = Peek(r)
    end = _zstd_frame(p, 0)
    if end is None:
        return None
    frames = 1
    cap = min(r.limit, BIG_MAX)
    while end < cap and frames < 1_000_000:
        nxt = r.read(end, 4)
        if len(nxt) < 4 or not (nxt == b"\x28\xb5\x2f\xfd" or nxt[1:] == b"\x2a\x4d\x18" and nxt[0] & 0xF0 == 0x50):
            break
        e = _zstd_frame(p, end)
        if e is None:
            break
        end, frames = e, frames + 1
    if end > r.limit:
        return Hit("zst", r.limit, CHANCE_POOR)
    return Hit("zst", end, CHANCE_GOOD, info={"frames": frames})


_P1, _P2, _P3, _P4, _P5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
_M32 = 0xFFFFFFFF


def _xxh32_short(data: bytes, seed: int = 0) -> int:
    """xxHash32 of fewer than 16 bytes (the LZ4 frame descriptor checksum)."""
    acc = (seed + _P5 + len(data)) & _M32
    i = 0
    while i + 4 <= len(data):
        acc = (acc + struct.unpack_from("<I", data, i)[0] * _P3) & _M32
        acc = (((acc << 17) | (acc >> 15)) & _M32) * _P4 & _M32
        i += 4
    while i < len(data):
        acc = (acc + data[i] * _P5) & _M32
        acc = (((acc << 11) | (acc >> 21)) & _M32) * _P1 & _M32
        i += 1
    acc ^= acc >> 15
    acc = acc * _P2 & _M32
    acc ^= acc >> 13
    acc = acc * _P3 & _M32
    acc ^= acc >> 16
    return acc


def parse_lz4(r: Reader) -> Hit | None:
    p = Peek(r)
    pos = 0
    frames = 0
    cap = min(r.limit, BIG_MAX)
    while pos < cap and frames < 100_000:
        h = p.read(pos, 19)
        if len(h) < 7 or h[:4] != b"\x04\x22\x4d\x18":
            break
        flg, bd = h[4], h[5]
        if flg >> 6 != 1 or flg & 2 or bd & 0x8F or not 4 <= (bd >> 4) & 7 <= 7:
            break
        q = 6 + (8 if flg & 8 else 0) + (4 if flg & 1 else 0)
        if len(h) <= q or (_xxh32_short(h[4:q]) >> 8) & 0xFF != h[q]:
            break
        bmax = 1 << (8 + 2 * ((bd >> 4) & 7))
        q = pos + q + 1
        while True:
            b = p.read(q, 4)
            if len(b) < 4:
                return Hit("lz4", None, CHANCE_POOR) if not frames else Hit("lz4", pos, CHANCE_FAIR)
            size = struct.unpack("<I", b)[0]
            if size == 0:
                q += 4 + (4 if flg & 4 else 0)
                break
            if size & 0x7FFFFFFF > bmax:
                return None if not frames else Hit("lz4", pos, CHANCE_FAIR)
            q += 4 + (size & 0x7FFFFFFF) + (4 if flg & 0x10 else 0)
        pos = q
        frames += 1
    if not frames:
        return None
    if pos > r.limit:
        return Hit("lz4", r.limit, CHANCE_POOR)
    return Hit("lz4", pos, CHANCE_GOOD)


# ---------------------------------------------------------------------- tar
_ZERO_BLOCK = bytes(512)


def _tar_num(field: bytes) -> int | None:
    if field[:1] in (b"\x80", b"\xff"):           # GNU base-256 for big numbers
        v = int.from_bytes(field[1:], "big")
        return -v if field[0] == 0xFF else v
    s = field.split(b"\x00")[0].strip()
    if not s:
        return 0
    try:
        return int(s, 8)
    except ValueError:
        return None


def _tar_header(b: bytes) -> tuple[int, int, int] | None:
    """(size, mtime, type) of a ustar header block, or None if it isn't one (checksum, magic)."""
    if len(b) < 512 or b[257:262] != b"ustar":
        return None
    chk = _tar_num(b[148:156])
    total = sum(b[:148]) + 256 + sum(b[156:512])
    if chk != total and chk != total - 256 * sum(c > 127 for c in b[:148] + b[156:512]):   # signed sums
        return None
    size = _tar_num(b[124:136])
    mtime = _tar_num(b[136:148])
    if size is None or size < 0 or mtime is None:
        return None
    return size, mtime, b[156]


def parse_tar(r: Reader) -> Hit | None:
    p = Peek(r)
    pos = 0
    files = 0
    newest = None
    next_size = next_name = None
    first_name = None
    cap = min(r.limit, BIG_MAX)
    end = None
    chance = CHANCE_GOOD
    while pos < cap and files < 10_000_000:
        b = p.read(pos, 512)
        if len(b) < 512:
            end, chance = pos, CHANCE_POOR
            break
        if b == _ZERO_BLOCK:
            if p.read(pos + 512, 512) == _ZERO_BLOCK:
                end = pos + 1024
            else:
                end, chance = pos + 512, CHANCE_FAIR
            break
        h = _tar_header(b)
        if h is None:
            if not files:
                return None
            end, chance = pos, CHANCE_POOR        # no end marker: cut after the last good member
            break
        size, mtime, typ = h
        if next_size is not None:
            size, next_size = next_size, None
        if typ == ord("x"):                       # pax extended header: may carry the real size and name
            pax = p.read(pos + 512, min(size, 64 * KiB))
            m = re.search(rb"(?:^|\n)\d+ size=(\d+)\n", pax)
            if m:
                next_size = int(m.group(1))
            m = re.search(rb"(?:^|\n)\d+ path=([^\n]*)\n", pax)
            if m:
                next_name = m.group(1)
        elif typ == ord("L"):                     # GNU long name
            next_name = p.read(pos + 512, min(size, 4096)).split(b"\x00")[0]
        elif typ not in b"Kg":
            files += 1
            if first_name is None:
                prefix = b[345:500].split(b"\x00")[0] if b[257:263] == b"ustar\x00" else b""   # POSIX only
                raw = next_name or (prefix + b"/" if prefix else b"") + b[:100].split(b"\x00")[0]
                first_name = raw.decode("utf-8", "replace")
            next_name = None
            when = plausible(mtime)
            if when and (newest is None or when > newest):
                newest = when
        data = 0 if typ in b"123456" else size
        pos += 512 + -(-data // 512) * 512
    if end is None:
        end, chance = min(pos, cap), CHANCE_POOR
    if end <= 0 or (not files and chance != CHANCE_GOOD):
        return None
    if chance == CHANCE_GOOD:
        end, chance = _ending(r, end, 10240)       # the record padding tar writers add
    elif end > r.limit:
        end = r.limit
    info = {"files": files}
    if first_name:
        info["first_file"] = first_name
    return Hit("tar", end, chance, mtime=newest, info=info)


# ---------------------------------------------------------------------- cpio
def parse_cpio(r: Reader) -> Hit | None:
    p = Peek(r)
    magic = p.read(0, 6)
    if magic in (b"070701", b"070702"):
        walk = _cpio_newc
    elif magic == b"070707":
        walk = _cpio_odc
    elif magic[:2] in (b"\xc7\x71", b"\x71\xc7"):
        walk = _cpio_bin
    else:
        return None
    pos = 0
    files = 0
    newest = None
    cap = min(r.limit, BIG_MAX)
    while pos < cap and files < 10_000_000:
        e = walk(p, pos)
        if e is None:
            if not files or walk is _cpio_bin:
                return None                       # the binary format's 2-byte magic needs a whole walk
            return Hit("cpio", min(pos, r.limit), CHANCE_POOR, mtime=newest, info={"files": files})
        nxt, name, mtime = e
        if name == "TRAILER!!!":
            end, chance = _ending(r, nxt, 512)    # cpio writes whole 512-byte blocks
            return Hit("cpio", end, chance, mtime=newest, info={"files": files})
        files += 1
        when = plausible(mtime)
        if when and (newest is None or when > newest):
            newest = when
        pos = nxt
    return None


def _cpio_newc(p: Peek, pos: int) -> tuple[int, str, int] | None:
    h = p.read(pos, 110)
    if len(h) < 110 or h[:6] not in (b"070701", b"070702"):
        return None
    try:
        f = [int(h[6 + i * 8:14 + i * 8], 16) for i in range(13)]
    except ValueError:
        return None
    mtime, fsize, nsize = f[5], f[6], f[11]
    if not 1 <= nsize <= 4096:
        return None
    name = p.read(pos + 110, nsize)
    if len(name) < nsize or name[-1:] != b"\x00":
        return None
    q = pos + -(-(110 + nsize) // 4) * 4
    return q + -(-fsize // 4) * 4, name[:-1].decode("utf-8", "replace"), mtime


def _cpio_odc(p: Peek, pos: int) -> tuple[int, str, int] | None:
    h = p.read(pos, 76)
    if len(h) < 76 or h[:6] != b"070707":
        return None
    try:
        mtime, nsize, fsize = int(h[48:59], 8), int(h[59:65], 8), int(h[65:76], 8)
    except ValueError:
        return None
    if not 1 <= nsize <= 4096:
        return None
    name = p.read(pos + 76, nsize)
    if len(name) < nsize or name[-1:] != b"\x00":
        return None
    return pos + 76 + nsize + fsize, name[:-1].decode("utf-8", "replace"), mtime


def _cpio_bin(p: Peek, pos: int) -> tuple[int, str, int] | None:
    h = p.read(pos, 26)
    if len(h) < 26:
        return None
    order = "<" if h[:2] == b"\xc7\x71" else ">" if h[:2] == b"\x71\xc7" else None
    if order is None:
        return None
    f = struct.unpack(order + "13H", h)
    mode, mtime, nsize, fsize = f[3], (f[8] << 16) | f[9], f[10], (f[11] << 16) | f[12]
    if not 1 <= nsize <= 1024 or mode >> 12 not in (1, 2, 4, 6, 8, 10, 12, 0) or (mode == 0 and fsize):
        return None
    name = p.read(pos + 26, nsize)
    if len(name) < nsize or name[-1:] != b"\x00" or re.search(rb"[\x00-\x1f]", name[:-1]):
        return None
    q = pos + 26 + nsize + (nsize & 1)
    return q + fsize + (fsize & 1), name[:-1].decode("utf-8", "replace"), mtime


# ---------------------------------------------------------------------- ar / deb
_AR_HEAD = re.compile(rb"[^\x00-\x1f]{16}[\d ]{12}[\d ]{6}[\d ]{6}[0-7 ]{8}[\d ]{10}`\n")


def _ar_num(field: bytes) -> int | None:
    m = re.fullmatch(rb" *(\d+) *", field)
    return int(m.group(1)) if m else None


def parse_ar(r: Reader) -> Hit | None:
    p = Peek(r)
    if p.read(0, 8) != b"!<arch>\n":
        return None
    pos = 8
    names = []
    newest = None
    cap = min(r.limit, BIG_MAX)
    deb_done = False
    while pos < cap and len(names) < 1_000_000:
        h = p.read(pos, 60)
        size = _ar_num(h[48:58])
        if len(h) < 60 or not _AR_HEAD.fullmatch(h) or size is None:
            break
        name = h[:16].decode("latin-1").rstrip()
        names.append(name)
        when = plausible(_ar_num(h[16:28]))
        if when and (newest is None or when > newest):
            newest = when
        pos += 60 + size
        if size & 1 and p.read(pos, 1) == b"\n":
            pos += 1
        if names[0].rstrip("/") == "debian-binary" and name.startswith("data.tar"):
            deb_done = True
            break
    if not names:
        return None
    if names[0].rstrip("/") == "debian-binary":
        chance = CHANCE_GOOD if deb_done else CHANCE_POOR
        if pos > r.limit:
            pos, chance = r.limit, CHANCE_POOR
        return Hit("deb", pos, chance, mtime=newest, category="executable", description="Debian package",
                   info={"members": len(names)})
    chance = CHANCE_FAIR                           # ar has no end marker: the walk stops at the first non-member
    if pos > r.limit:
        pos, chance = r.limit, CHANCE_POOR
    return Hit("a" if names[0] in ("/", "//", "__.SYMDEF", "__.SYMDEF SORTED") else "ar", pos, chance,
               mtime=newest, info={"members": len(names)})


# ---------------------------------------------------------------------- RPM
def _rpm_header(p: Peek, pos: int) -> tuple[int, dict[int, tuple[int, int, int]], bytes] | None:
    """(length, {tag: (type, offset, count)}, data store) of an RPM header structure at POS."""
    h = p.read(pos, 16)
    if len(h) < 16 or h[:4] != b"\x8e\xad\xe8\x01" or any(h[4:8]):
        return None
    il, dl = struct.unpack_from(">II", h, 8)
    if not 1 <= il <= 100_000 or dl > 256 * MiB:
        return None
    index = p.read(pos + 16, il * 16)
    if len(index) < il * 16:
        return None
    tags = {}
    for i in range(il):
        tag, typ, off, count = struct.unpack_from(">IIII", index, i * 16)
        if off > dl:
            return None
        tags.setdefault(tag, (typ, off, count))
    store = p.read(pos + 16 + il * 16, min(dl, 4 * MiB))
    return 16 + il * 16 + dl, tags, store


def _rpm_value(hdr: tuple, tag: int):
    _length, tags, store = hdr
    if tag not in tags:
        return None
    typ, off, count = tags[tag]
    try:
        if typ == 4:
            return struct.unpack_from(">I", store, off)[0]
        if typ == 5:
            return struct.unpack_from(">Q", store, off)[0]
        if typ in (6, 8, 9):
            return store[off:store.find(b"\x00", off)].decode("utf-8", "replace")
    except struct.error:
        return None
    return None


def parse_rpm(r: Reader) -> Hit | None:
    p = Peek(r)
    lead = p.read(0, 96)
    if len(lead) < 96 or lead[:4] != b"\xed\xab\xee\xdb" or lead[4] not in (3, 4):
        return None
    rtype, _arch = struct.unpack_from(">HH", lead, 6)
    sigtype = struct.unpack_from(">H", lead, 78)[0]
    if rtype > 1 or sigtype != 5:
        return None
    sig = _rpm_header(p, 96)
    if sig is None:
        return None
    hdr_at = 96 + sig[0] + (-sig[0] % 8)
    hdr = _rpm_header(p, hdr_at)
    if hdr is None:
        return None
    size = _rpm_value(sig, 270) or _rpm_value(sig, 1000)   # LONGSIZE, SIZE: header + payload
    chance = CHANCE_GOOD
    if size and size >= hdr[0]:
        end = hdr_at + size
    else:
        end = _rpm_payload_end(r, p, hdr_at + hdr[0], _rpm_value(hdr, 1125) or "gzip")
        chance = CHANCE_FAIR
    name = "-".join(str(v) for v in (_rpm_value(hdr, 1000), _rpm_value(hdr, 1001), _rpm_value(hdr, 1002)) if v)
    arch = _rpm_value(hdr, 1022)
    built = _rpm_value(hdr, 1006)
    if end is not None and end > r.limit:
        end, chance = r.limit, CHANCE_POOR
    if not name:
        name = lead[10:76].split(b"\x00")[0].decode("utf-8", "replace")
    return Hit("srpm" if rtype == 1 else "rpm", end, chance if end else CHANCE_POOR,
               name=clean_title(f"{name}.{arch}" if arch and rtype == 0 else name),
               mtime=plausible(built) if isinstance(built, int) else None,
               category="executable", description="Source RPM package" if rtype == 1 else "RPM package",
               info={"package": name, "arch": arch})


def _rpm_payload_end(r: Reader, p: Peek, pos: int, compressor: str) -> int | None:
    """The end of an RPM's compressed payload when the signature doesn't give the size."""
    cap = min(r.limit, STREAM_MAX)
    if compressor == "gzip":
        return _gz_end(r, p, pos, cap)[0]
    if compressor == "xz":
        return _xz_stream(p, pos, cap)
    if compressor == "zstd":
        return _zstd_frame(p, pos)
    if compressor == "bzip2":
        return _bz2_stream(r, pos, cap)[0]
    return None


# ---------------------------------------------------------------------- cabinet, xar
def parse_cab(r: Reader) -> Hit | None:
    p = Peek(r)
    h = p.read(0, 36)
    if len(h) < 36 or h[:4] != b"MSCF":
        return None
    res1, size, res2, coff, res3, vminor, vmajor, nfolders, nfiles, flags = struct.unpack_from("<IIIIIBBHHH", h, 4)
    if res1 or res2 or res3 or (vmajor, vminor) != (1, 3) or not nfolders or not nfiles or flags & ~7:
        return None
    if not 36 <= coff < size or size < 44:
        return None
    files = []
    newest = None
    pos = coff
    for _ in range(min(nfiles, 65535)):
        e = p.read(pos, 16 + 256)
        if len(e) < 17:
            break
        date, tm = struct.unpack_from("<HH", e, 10)
        i = e.find(b"\x00", 16)
        if i < 0 or i == 16:
            break
        files.append(e[16:i].decode("latin-1"))
        when = plausible(dos_datetime(date, tm))
        if when and (newest is None or when > newest):
            newest = when
        pos += i + 1
    if not files:
        return None
    info = {"files": nfiles}
    if flags & 3:
        info["volume"] = "part of a cabinet set"
    chance = CHANCE_GOOD if size <= r.limit else CHANCE_POOR
    return Hit("cab", min(size, r.limit), chance, mtime=newest, info=info)


def parse_xar(r: Reader) -> Hit | None:
    h = r.read(0, 28)
    if len(h) < 28 or h[:4] != b"xar!":
        return None
    hsize, version, toc_c, toc_u, alg = struct.unpack_from(">HHQQI", h, 4)
    if hsize < 28 or version != 1 or not 0 < toc_c <= 64 * MiB or not 0 < toc_u <= 256 * MiB or alg > 4:
        return None
    try:
        toc = zlib.decompressobj().decompress(r.read(hsize, toc_c), toc_u + 1)
    except zlib.error:
        return None
    if len(toc) != toc_u or b"<xar" not in toc[:512]:
        return None
    text = toc.decode("utf-8", "replace")
    heap = 0                                       # the heap ends with the last piece the TOC points at
    for tag, field in (("data", "length"), ("checksum", "size"), ("signature", "size"), ("x-signature", "size")):
        for block in re.findall(r"<%s\b[^>]*>(.*?)</%s>" % (tag, tag), text, re.S):
            off = re.search(r"<offset>(\d+)</offset>", block)
            n = re.search(r"<%s>(\d+)</%s>" % (field, field), block)
            if off and n:
                heap = max(heap, int(off.group(1)) + int(n.group(1)))
    end = hsize + toc_c + heap
    ext = "pkg" if "<name>Distribution</name>" in text else "xar"
    chance = CHANCE_GOOD if end <= r.limit else CHANCE_POOR
    return Hit(ext, min(end, r.limit), chance, description="macOS installer package" if ext == "pkg" else None)


# ---------------------------------------------------------------------- ARJ, LHA
def parse_arj(r: Reader) -> Hit | None:
    p = Peek(r)
    pos = 0
    files = 0
    newest = None
    name = None
    cap = min(r.limit, BIG_MAX)
    while pos < cap and files < 1_000_000:
        h = p.read(pos, 4)
        if len(h) < 4 or h[:2] != b"\x60\xea":
            break
        size = struct.unpack_from("<H", h, 2)[0]
        if size == 0:
            if pos == 0:
                return None
            return Hit("arj", pos + 4, CHANCE_GOOD, name=name, mtime=newest, info={"files": files})
        if size > 2600:
            break
        hdr = p.read(pos + 4, size + 4)
        if len(hdr) < size + 4 or zlib.crc32(hdr[:size]) != struct.unpack_from("<I", hdr, size)[0]:
            break
        first = hdr[0]
        if not 30 <= first <= size or (pos == 0 and hdr[6] != 2):
            break
        q = pos + 4 + size + 4
        for _ in range(64):                         # extended headers
            n = p.read(q, 2)
            if len(n) < 2:
                break
            q += 2
            n = struct.unpack("<H", n)[0]
            if not n:
                break
            q += n + 4
        if pos == 0:
            name = clean_title(hdr[first:hdr.find(b"\x00", first)].decode("latin-1")) if b"\x00" in hdr[first:] \
                else None
            if name and name.lower().endswith(".arj"):
                name = name[:-4]
        else:
            files += 1
            stamp = struct.unpack_from("<I", hdr, 8)[0]
            when = plausible(stamp) if hdr[3] in (2, 8) else _dos(stamp)   # made on Unix: a Unix time
            if when and (newest is None or when > newest):
                newest = when
            q += struct.unpack_from("<I", hdr, 12)[0]
        pos = q
    if pos == 0:
        return None
    return Hit("arj", min(pos, r.limit), CHANCE_POOR, name=name, mtime=newest, info={"files": files})


_LZH_METHOD = re.compile(rb"-(?:lh[0-7dx]|lz[s45]|pm[0-2])-")


def parse_lzh(r: Reader) -> Hit | None:
    p = Peek(r)
    pos = 0
    files = 0
    newest = None
    cap = min(r.limit, BIG_MAX)
    while pos < cap and files < 1_000_000:
        h = p.read(pos, 27)
        if h[:1] == b"\x00" and files:
            return Hit("lzh", pos + 1, CHANCE_GOOD, mtime=newest, info={"files": files})
        if len(h) < 27 or not _LZH_METHOD.fullmatch(h[2:7]):
            break
        level = h[20]
        csize, stamp = struct.unpack_from("<II", h, 7)[0], struct.unpack_from("<I", h, 15)[0]
        if level in (0, 1):
            size = h[0]
            hdr = p.read(pos + 2, size)
            if size < 22 or len(hdr) < size or sum(hdr) & 0xFF != h[1]:
                break
            pos += 2 + size + csize
            when = _dos(stamp)
        elif level == 2:
            size = struct.unpack_from("<H", h, 0)[0]
            if size < 26:
                break
            pos += size + csize
            when = plausible(stamp)
        else:
            break
        files += 1
        if when and (newest is None or when > newest):
            newest = when
    if not files:
        return None
    return Hit("lzh", min(pos, r.limit), CHANCE_POOR, mtime=newest, info={"files": files})


# ---------------------------------------------------------------------- SquashFS, WIM, ISO 9660
def parse_squashfs(r: Reader) -> Hit | None:
    h = r.read(0, 96)
    if len(h) < 96 or h[:4] != b"hsqs":
        return None
    inodes, mkfs, bsize, _frags, comp, blog, _flags, _ids, major, minor = struct.unpack_from("<IIIIHHHHHH", h, 4)
    used = struct.unpack_from("<Q", h, 40)[0]
    if (major, minor) != (4, 0) or bsize != 1 << blog or not 12 <= blog <= 20 or not 1 <= comp <= 6:
        return None
    tables = struct.unpack_from("<6Q", h, 48)
    if used < 96 or not inodes or any(t != 0xFFFFFFFFFFFFFFFF and t > used for t in tables):
        return None
    end, chance = _ending(r, used, 4096)          # mksquashfs pads the image to 4 KiB
    comp_name = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}[comp]
    return Hit("squashfs", end, chance, mtime=plausible(mkfs), info={"inodes": inodes, "compression": comp_name})


_WIM_VERSIONS = {0x10D00, 0x10B00, 0x10A00, 0x10900, 0xE00}


def parse_wim(r: Reader) -> Hit | None:
    h = r.read(0, 208)
    if len(h) < 208 or h[:8] != b"MSWIM\x00\x00\x00":
        return None
    size, version, _flags, _chunk = struct.unpack_from("<IIII", h, 8)
    part, parts, images = struct.unpack_from("<HHI", h, 40)
    if size != 208 or version not in _WIM_VERSIONS or not 1 <= part <= parts or images > 100_000:
        return None
    end = 208
    for at in (48, 72, 96, 124):
        rsize = int.from_bytes(h[at:at + 7], "little")
        off = struct.unpack_from("<Q", h, at + 8)[0]
        if rsize:
            if off < 208 or off > BIG_MAX:
                return None
            end = max(end, off + rsize)
    if end == 208:
        return None
    chance = CHANCE_GOOD if end <= r.limit else CHANCE_POOR
    info = {"images": images}
    if parts > 1:
        info["volume"] = f"part {part} of {parts}"
    return Hit("swm" if parts > 1 else "wim", min(end, r.limit), chance, info=info)


def _iso_time(b: bytes) -> float | None:
    m = re.fullmatch(rb"(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)\d\d", b[:16])
    if not m:
        return None
    try:
        t = calendar.timegm(tuple(int(g) for g in m.groups()) + (0, 0, 0))
    except (ValueError, OverflowError):
        return None
    tz = b[16] - 256 if b[16] > 127 else b[16]
    return plausible(t - tz * 15 * 60)


def parse_iso(r: Reader) -> Hit | None:
    pvd = None
    for sector in range(16, 48):
        d = r.read(sector * 2048, 2048)
        if len(d) < 2048 or d[1:6] != b"CD001" or d[6] != 1:
            return None
        if d[0] == 1 and pvd is None:
            pvd = d
        elif d[0] == 255:
            break
    else:
        return None
    if pvd is None:
        return None
    space_le, space_be = struct.unpack_from("<I", pvd, 80)[0], struct.unpack_from(">I", pvd, 84)[0]
    bs_le, bs_be = struct.unpack_from("<H", pvd, 128)[0], struct.unpack_from(">H", pvd, 130)[0]
    if space_le != space_be or bs_le != bs_be or bs_le not in (512, 1024, 2048) or space_le < 18 or pvd[156] != 34:
        return None
    end = space_le * bs_le
    label = clean_title(pvd[40:72].decode("latin-1").strip())
    chance = CHANCE_GOOD if end <= r.limit else CHANCE_POOR
    return Hit("iso", min(end, r.limit), chance, name=label, mtime=_iso_time(pvd[813:830]),
               info={"label": label} if label else {})


# ---------------------------------------------------------------------- the formats
FORMATS: list[Format] = [
    Format("zip", "ZIP archive", "archive",
           ("zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "xltx", "potx", "ppsx", "xlsb", "vsdx",
            "odt", "ods", "odp", "odg", "odf", "odb", "ott", "ots", "otp", "sxw", "sxc", "sxi", "sxd", "epub", "xps",
            "oxps", "3mf", "pages", "numbers", "key", "apk", "aab", "aar", "ipa", "jar", "war", "ear", "xpi", "vsix",
            "whl", "egg", "nupkg", "appx", "kmz", "sketch", "kra", "ora", "idml"),
           ((0, _LOCAL),), parse_zip, max_size=ZIP_MAX, min_size=22,
           aliases=("docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "jar", "apk", "office")),
    Format("rar", "RAR archive", "archive", ("rar",), ((0, b"Rar!\x1a\x07"),), parse_rar, max_size=BIG_MAX,
           min_size=20),
    Format("7z", "7-Zip archive", "archive", ("7z",), ((0, b"7z\xbc\xaf\x27\x1c"),), parse_7z, max_size=BIG_MAX,
           min_size=32, aliases=("7zip",)),
    Format("gz", "gzip compressed file", "archive", ("gz", "tar.gz", "bam"), ((0, b"\x1f\x8b\x08"),), parse_gz,
           max_size=STREAM_MAX, min_size=18, aliases=("gzip", "tgz")),
    Format("bz2", "bzip2 compressed file", "archive", ("bz2", "tar.bz2"), ((0, b"BZh"),), parse_bz2,
           max_size=STREAM_MAX, min_size=14, aliases=("bzip2",)),
    Format("xz", "xz compressed file", "archive", ("xz", "tar.xz"), ((0, _XZ_MAGIC),), parse_xz, max_size=BIG_MAX,
           min_size=32),
    Format("zst", "Zstandard compressed file", "archive", ("zst",), ((0, b"\x28\xb5\x2f\xfd"),), parse_zst,
           max_size=BIG_MAX, min_size=9, aliases=("zstd",)),
    Format("lz4", "LZ4 compressed file", "archive", ("lz4",), ((0, b"\x04\x22\x4d\x18"),), parse_lz4,
           max_size=BIG_MAX, min_size=11),
    Format("lzip", "lzip compressed file", "archive", ("lz",), ((0, b"LZIP\x01"),), parse_lzip, max_size=STREAM_MAX,
           min_size=36, aliases=("lz",)),
    Format("tar", "tar archive", "archive", ("tar",), ((257, b"ustar"),), parse_tar, max_size=BIG_MAX,
           min_size=1024),
    Format("cab", "Windows cabinet", "archive", ("cab",), ((0, b"MSCF\x00\x00\x00\x00"),), parse_cab,
           max_size=4 * GiB, min_size=44),
    Format("cpio", "cpio archive", "archive", ("cpio",), ((0, b"070701"), (0, b"070702"), (0, b"070707"),
                                                         (0, b"\xc7\x71"), (0, b"\x71\xc7")), parse_cpio,
           max_size=BIG_MAX, min_size=26),
    Format("ar", "ar archive / Debian package", "archive", ("ar", "a", "deb"), ((0, b"!<arch>\n"),), parse_ar,
           max_size=BIG_MAX, min_size=68, aliases=("deb",)),
    Format("rpm", "RPM package", "executable", ("rpm", "srpm"), ((0, b"\xed\xab\xee\xdb"),), parse_rpm,
           max_size=BIG_MAX, min_size=200),
    Format("xar", "xar archive / macOS package", "archive", ("xar", "pkg"), ((0, b"xar!"),), parse_xar,
           max_size=BIG_MAX, min_size=28),
    Format("arj", "ARJ archive", "archive", ("arj",), ((0, b"\x60\xea"),), parse_arj, max_size=4 * GiB,
           min_size=40),
    Format("lzh", "LHA archive", "archive", ("lzh",), tuple((2, m) for m in (b"-lh", b"-lz", b"-pm")), parse_lzh,
           max_size=4 * GiB, min_size=24, aliases=("lha",)),
    Format("squashfs", "SquashFS image", "archive", ("squashfs",), ((0, b"hsqs"),), parse_squashfs,
           max_size=BIG_MAX, min_size=4096, aliases=("sqsh",)),
    Format("wim", "Windows imaging (WIM)", "archive", ("wim", "swm"), ((0, b"MSWIM\x00\x00\x00"),), parse_wim,
           max_size=BIG_MAX, min_size=208, aliases=("esd",)),
    Format("iso", "CD/DVD image (ISO 9660)", "archive", ("iso",), ((32769, b"CD001"),), parse_iso,
           max_size=BIG_MAX, min_size=36864),
]
