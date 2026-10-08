"""Signatures for fonts, Flash movies, torrents, calendars and contacts, certificates and keys, Windows
shortcuts, Blender scenes, medical (DICOM) and astronomy (FITS) images, binary property lists and
virtual-machine disks (part two of the engine's "misc" formats; e-mail, databases and programs are in
:mod:`.misc`).

How each one's end is found (all exact, except where noted):

- fonts: TrueType / OpenType / collections end after their furthest table (the head table's checksum and
  the directory's search fields are checked); WOFF and WOFF2 store their length.
- Flash: FWS stores its length (checked by walking the tags to End); CWS is inflated to find the end of
  its zlib stream; ZWS stores its compressed size.
- torrents are bencode, walked to the closing "e"; shortcuts (.lnk) structure by structure; Blender files
  block by block to "ENDB"; DICOM element by element (explicit and implicit VR, sequences of undefined
  length, encapsulated pixel data); FITS header by header (each data size follows from BITPIX and NAXISn);
  binary plists object by object, until their trailer turns up right after the offset table.
- calendars (.ics), contacts (.vcf), PEM certificates and keys, PuTTY keys: text ending with an END line.
- virtual disks (off by default: huge, and rare on memory cards): VDI from its allocated block count, VHD
  from its block table, VHDX from its region and block tables, QCOW2 from its refcount table, sparse VMDK
  from its grain tables or stream markers. Only the image file itself is carved: a disk split into
  several extent files, or one with a parent, needs its other files too.
"""

from __future__ import annotations

import calendar
import quopri
import re
import struct
import uuid
import zlib

from .base import CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, Format, GiB, Hit, KiB, MiB, Reader
from .common import clean_name
from .misc import (
    Short,
    align,
    be16,
    be32,
    be64,
    finish,
    guarded,
    is_pow2,
    plausible,
    text_end,
    u16,
    u32,
    u64,
    walk_buffered,
)

try:
    import lzma
except ImportError:                        # Python built without liblzma
    lzma = None


# ====================================================================== fonts
_SFNT_VERSIONS = {b"\x00\x01\x00\x00": "ttf", b"OTTO": "otf", b"true": "ttf", b"typ1": "ttf"}
_TAG = re.compile(rb"[!-~][ -~]{3}")


def _table_sum(data: bytes) -> int:
    data += b"\0" * (-len(data) % 4)
    return sum(struct.unpack(f">{len(data) // 4}I", data)) & 0xFFFFFFFF


def _sfnt(r: Reader, off: int, collection: bool = False) -> tuple[int, dict, bool] | None:
    """The font whose table directory is at OFF: (end of its furthest table, {tag: (offset, length)}, whether
    the directory's search fields and the head table's checksum are right), or None if it isn't one."""
    h = r.read(off, 12)
    if len(h) < 12 or h[:4] not in _SFNT_VERSIONS:
        return None
    n, search, selector, shift = struct.unpack_from(">HHHH", h, 4)
    if not 1 <= n <= 300:
        return None
    d = r.read(off + 12, 16 * n)
    if len(d) < 16 * n:
        return None
    first = 12 if collection else 12 + 16 * n
    tables = {}
    end = off + 12 + 16 * n
    for i in range(n):
        tag, csum, toff, tlen = struct.unpack_from(">4sIII", d, 16 * i)
        if not _TAG.fullmatch(tag) or toff < first or tlen > 256 * MiB:
            return None
        tables[tag] = (toff, tlen, csum)
        end = max(end, toff + tlen)
    head = tables.get(b"head") or tables.get(b"bhed")
    if head is None or not 54 <= head[1] <= 1024:
        return None
    hd = r.read(head[0], head[1])
    if len(hd) < 54 or be32(hd, 12) != 0x5F0F3CF5:
        return None
    p = 1 << (n.bit_length() - 1)
    good = search == 16 * p and selector == p.bit_length() - 1 and shift == 16 * n - search
    good = good and _table_sum(hd[:8] + b"\0\0\0\0" + hd[12:]) == head[2]
    return end, {t: v[:2] for t, v in tables.items()}, good


def _font_name(data: bytes) -> str | None:
    """The full name (or family name) from a font's name table, preferring the Windows English record."""
    if len(data) < 6:
        return None
    count, stroff = be16(data, 2), be16(data, 4)
    best = None
    for i in range(min(count, 1024)):
        o = 6 + 12 * i
        if o + 12 > len(data):
            break
        pid, _eid, lid, nid, ln, so = struct.unpack_from(">HHHHHH", data, o)
        if nid not in (1, 4):
            continue
        raw = data[stroff + so:stroff + so + ln]
        if not raw:
            continue
        text = raw.decode("utf-16-be", "replace") if pid in (0, 3) else raw.decode("mac_roman", "replace")
        rank = (nid == 4, pid == 3 and lid == 0x409, pid in (0, 3))
        if best is None or rank > best[0]:
            best = (rank, text)
    return clean_name(best[1]) if best else None


def _pad4(r: Reader, end: int) -> int:
    """Fonts are padded to 4 bytes; keep the zeros of the last table's padding."""
    pad = -end % 4
    return end + pad if pad and r.read(end, pad) == b"\0" * pad else end


@guarded
def parse_font(r: Reader) -> Hit | None:
    """TrueType / OpenType font or font collection, named after the font's full name."""
    h = r.read(0, 12)
    if len(h) < 12:
        return None
    if h[:4] == b"ttcf":
        major, minor, nfonts = struct.unpack_from(">HHI", h, 4)
        if major not in (1, 2) or minor or not 1 <= nfonts <= 1024:
            return None
        offs = r.read(12, 4 * nfonts)
        if len(offs) < 4 * nfonts:
            return None
        end, good, name = 12 + 4 * nfonts, True, None
        for i in range(nfonts):
            res = _sfnt(r, be32(offs, 4 * i), collection=True)
            if res is None:
                return None
            end, good = max(end, res[0]), good and res[2]
            if name is None and b"name" in res[1] and res[1][b"name"][1] <= MiB:
                name = _font_name(r.read(*res[1][b"name"]))
        if major == 2:
            tail = r.read(12 + 4 * nfonts, 12)
            if len(tail) == 12 and tail[:4] == b"DSIG" and be32(tail, 4):
                end = max(end, be32(tail, 8) + be32(tail, 4))
        return finish(r, "ttc", _pad4(r, end), CHANCE_GOOD if good else CHANCE_FAIR, name=name,
                      info={"fonts": nfonts})
    res = _sfnt(r, 0)
    if res is None:
        return None
    end, tables, good = res
    name = _font_name(r.read(*tables[b"name"])) if b"name" in tables and tables[b"name"][1] <= MiB else None
    return finish(r, _SFNT_VERSIONS[h[:4]], _pad4(r, end), CHANCE_GOOD if good else CHANCE_FAIR, name=name,
                  info={"tables": len(tables)})


@guarded
def parse_woff(r: Reader) -> Hit | None:
    """Web font (WOFF 1 or 2): the header stores the total length; the table directory is checked."""
    h = r.read(0, 48)
    if len(h) < 48:
        return None
    if h[:4] == b"wOFF":
        (flavor, length, n, reserved, _sfnt_size, _maj, _min, meta_off, meta_len, _meta_orig, priv_off,
         priv_len) = struct.unpack_from(">4sIHHIHHIIIII", h, 4)
        dir_end = 44 + 20 * n
    elif h[:4] == b"wOF2":
        (flavor, length, n, reserved, _sfnt_size, comp, _maj, _min, meta_off, meta_len, _meta_orig, priv_off,
         priv_len) = struct.unpack_from(">4sIHHIIHHIIIII", h, 4)
        dir_end = 48 + n + comp
    else:
        return None
    if flavor not in _SFNT_VERSIONS and flavor != b"ttcf" or reserved or not 1 <= n <= 300:
        return None
    if not dir_end <= length <= 256 * MiB:
        return None
    for off, ln in ((meta_off, meta_len), (priv_off, priv_len)):
        if ln and (off < dir_end or off + ln > length):
            return None
    name = None
    if h[:4] == b"wOFF":
        d = r.read(44, 20 * n)
        if len(d) < 20 * n:
            return None
        for i in range(n):
            tag, off, clen, olen, _csum = struct.unpack_from(">4sIIII", d, 20 * i)
            if not _TAG.fullmatch(tag) or off < dir_end or off + clen > length or clen > olen:
                return None
            if tag == b"name" and olen <= MiB:
                data = r.read(off, clen)
                name = _font_name(zlib.decompress(data, 15, olen) if clen < olen else data)
    return finish(r, "woff" if h[:4] == b"wOFF" else "woff2", length, CHANCE_GOOD, name=name)


# ====================================================================== Flash
_SWF_MAX_TAG = 120                         # the highest tag code in use is 93
def _swf_rect(b: bytes) -> tuple[int, int, int] | None:
    """(width, height in pixels, header bytes) from the frame-size RECT, frame rate and frame count that
    follow the 8-byte SWF header."""
    if not b:
        return None
    nbits = b[0] >> 3
    total = 5 + 4 * nbits
    nbytes = (total + 7) // 8
    if not nbits or len(b) < nbytes + 4:
        return None
    v = int.from_bytes(b[:nbytes], "big") >> (8 * nbytes - total)
    vals = []
    for k in range(4):
        x = (v >> (nbits * (3 - k))) & ((1 << nbits) - 1)
        vals.append(x - (1 << nbits) if x >> (nbits - 1) else x)
    xmin, xmax, ymin, ymax = vals
    w, h = (xmax - xmin) // 20, (ymax - ymin) // 20
    if not (0 < w <= 32768 and 0 < h <= 32768):
        return None
    return w, h, nbytes + 4


@guarded
def parse_swf(r: Reader) -> Hit | None:
    """Flash movie: FWS (plain), CWS (zlib) or ZWS (LZMA). The header stores the uncompressed length."""
    h = r.read(0, 64)
    if len(h) < 30 or h[1:3] != b"WS" or h[0:1] not in b"FCZ" or not 1 <= h[3] <= 60:
        return None
    full = u32(h, 4)
    if not 21 <= full <= GiB:
        return None
    if h[0:1] == b"F":
        rect = _swf_rect(h[8:])
        if rect is None or full < 8 + rect[2]:
            return None
        pos = 8 + rect[2]
        tags = 0
        for _ in range(1 << 22):           # the tags must lead exactly to the length in the header
            t = r.read(pos, 6)
            if len(t) < 2 or (t[0] & 0x3F == 0x3F and len(t) < 6):
                break
            code, ln = u16(t, 0) >> 6, u16(t, 0) & 0x3F
            if code > _SWF_MAX_TAG:
                return None
            if ln == 0x3F:
                ln, pos = u32(t, 2), pos + 4
            pos += 2 + ln
            tags += 1
            if code == 0 or pos >= full:
                break
        if pos != full:
            if full > r.limit and pos + 6 > r.limit and tags >= 3:   # cut off by the end of the disk
                return Hit("swf", r.limit, CHANCE_POOR, info={"width": rect[0], "height": rect[1]})
            return None
        return finish(r, "swf", full, CHANCE_GOOD, info={"width": rect[0], "height": rect[1], "version": h[3]})
    if h[0:1] == b"C":
        if h[8] & 0x0F != 8 or (h[8] << 8 | h[9]) % 31:     # a zlib header
            return None
        d = zlib.decompressobj()
        pos, total, head = 8, 0, b""
        while True:
            chunk = r.read(pos, MiB)
            if not chunk:
                return Hit("swf", r.limit, CHANCE_POOR) if total else None
            pos += len(chunk)
            data = chunk
            while True:
                out = d.decompress(data, 4 * MiB)
                total += len(out)
                head += out[:64 - len(head)]
                data = d.unconsumed_tail
                if d.eof or not data:
                    break
            if d.eof:
                break
            if total > full - 8:
                return None
        rect = _swf_rect(head)
        if rect is None:
            return None
        return finish(r, "swf", pos - len(d.unused_data), CHANCE_GOOD if total == full - 8 else CHANCE_FAIR,
                      info={"width": rect[0], "height": rect[1], "version": h[3]})
    # ZWS: compressed length at 8, then the 5 LZMA property bytes and the LZMA data
    clen, props, dict_size = u32(h, 8), h[12:17], u32(h, 13)
    if props[0] >= 225 or not 5 <= clen <= GiB or dict_size > 1 << 30:
        return None
    if lzma is None:                       # can't look inside: trust the header
        return finish(r, "swf", 17 + clen, CHANCE_FAIR, info={"version": h[3]})
    try:
        dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{
            "id": lzma.FILTER_LZMA1, "dict_size": max(4096, dict_size),
            "lc": props[0] % 9, "lp": props[0] // 9 % 5, "pb": props[0] // 45}])
        head = dec.decompress(r.read(17, min(clen, 64 * KiB)), 64)
    except (lzma.LZMAError, ValueError, MemoryError):
        return None
    rect = _swf_rect(head)
    if rect is None:
        return None
    return finish(r, "swf", 17 + clen, CHANCE_GOOD, info={"width": rect[0], "height": rect[1], "version": h[3]})


# ====================================================================== torrents (bencode)
def _bdecode(buf: bytes, pos: int, depth: int = 0):
    """The bencoded value at POS → (value, end). Long strings come back empty (only names are needed)."""
    if pos >= len(buf):
        raise Short
    c = buf[pos]
    if c == 0x69:                          # i<digits>e
        e = buf.find(b"e", pos + 1, pos + 40)
        if e < 0:
            if len(buf) - pos < 40:
                raise Short
            raise ValueError("bad integer")
        if not re.fullmatch(rb"-?\d+", buf[pos + 1:e]):
            raise ValueError("bad integer")
        return int(buf[pos + 1:e]), e + 1
    if 0x30 <= c <= 0x39:                  # <length>:<bytes>
        colon = buf.find(b":", pos, pos + 12)
        if colon < 0:
            if len(buf) - pos < 12:
                raise Short
            raise ValueError("bad string")
        if not buf[pos:colon].isdigit():
            raise ValueError("bad string")
        end = colon + 1 + int(buf[pos:colon])
        if end > len(buf):
            raise Short
        return (buf[colon + 1:end] if end - colon <= 4096 else b""), end
    if c in (0x6C, 0x64):                  # l...e, d...e
        if depth > 64:
            raise ValueError("too deep")
        pos += 1
        out: list | dict = [] if c == 0x6C else {}
        while True:
            if pos >= len(buf):
                raise Short
            if buf[pos] == 0x65:
                return out, pos + 1
            if c == 0x6C:
                v, pos = _bdecode(buf, pos, depth + 1)
                out.append(v)
            else:
                if not 0x30 <= buf[pos] <= 0x39:
                    raise ValueError("dictionary key is not a string")
                k, pos = _bdecode(buf, pos, depth + 1)
                v, pos = _bdecode(buf, pos, depth + 1)
                out[k] = v
    raise ValueError("not bencode")


@guarded
def parse_torrent(r: Reader) -> Hit | None:
    """BitTorrent metainfo: one bencoded dictionary with an "info" dictionary inside. Named after the
    torrent's name, dated by its creation date."""
    try:
        meta, end = walk_buffered(r, lambda buf, _complete: _bdecode(buf, 0), first=256 * KiB, cap=256 * MiB)
    except Short:
        return None
    if not isinstance(meta, dict):
        return None
    info = meta.get(b"info")
    if not isinstance(info, dict) or not ({b"name", b"pieces"} & info.keys()):
        return None
    name = info.get(b"name")
    files = info.get(b"files")
    created = meta.get(b"creation date")
    extra = {"files": len(files) if isinstance(files, list) else 1}
    if isinstance(meta.get(b"announce"), bytes) and meta[b"announce"]:
        extra["tracker"] = meta[b"announce"].decode("utf-8", "replace")[:200]
    return finish(r, "torrent", end, CHANCE_GOOD, name=clean_name(name) if isinstance(name, bytes) else None,
                  mtime=plausible(created) if isinstance(created, int) else None, info=extra)


# ====================================================================== calendars, contacts (text)
_PROPERTY = re.compile(rb"[A-Za-z][A-Za-z0-9-]*[;:]")


def _text_objects(r: Reader, begin: bytes, end: bytes, cap: int) -> tuple[int, int, bool]:
    """The run of BEGIN … END objects at the start of the file (vCards one after another): (where it ends,
    how many, complete). An object without its END line runs to the end of the text."""
    limit = text_end(r, 0, cap)
    pos, count = 0, 0
    while True:
        e = r.find(b"\n" + end, pos, limit)
        if e < 0:
            return (limit, count, False) if not count else (pos, count, True)
        pos = e + 1 + len(end)
        tail = r.read(pos, 64)
        stripped = tail.lstrip(b" \t")
        pos += len(tail) - len(stripped)
        pos += 2 if stripped[:2] == b"\r\n" else 1 if stripped[:1] in (b"\n", b"\r") else 0
        count += 1
        nxt = r.read(pos, 64 + len(begin))
        skip = len(nxt) - len(nxt.lstrip(b"\r\n \t"))
        if nxt[skip:skip + len(begin)] != begin or pos + skip >= limit:
            return pos, count, True
        pos += skip


def _text_value(head: bytes, prop: bytes) -> str | None:
    """The value of the first PROP line in HEAD (folded lines and quoted-printable undone)."""
    m = re.search(rb"(?:^|\n)" + prop + rb"((?:;[^:\r\n]*)?):([^\r\n]*(?:\r?\n[ \t][^\r\n]*)*)", head)
    if not m:
        return None
    value = re.sub(rb"\r?\n[ \t]", b"", m.group(2))
    if b"QUOTED-PRINTABLE" in m.group(1).upper():
        value = quopri.decodestring(value)
    value = value.replace(b"\\,", b",").replace(b"\\;", b";").replace(b"\\n", b" ")
    return clean_name(value.decode("utf-8", "replace"))


def _begin(r: Reader, marker: bytes) -> bytes | None:
    """The first 64 KiB of a text file starting with MARKER (after an optional UTF-8 BOM) followed by a
    property line, or None."""
    head = r.read(0, 64 * KiB)
    body = head[3:] if head.startswith(b"\xef\xbb\xbf") else head
    m = re.match(re.escape(marker) + rb"[ \t]*\r?\n", body)
    if not m or not _PROPERTY.match(body, m.end()):
        return None
    return head


@guarded
def parse_ics(r: Reader) -> Hit | None:
    """iCalendar file: BEGIN:VCALENDAR … END:VCALENDAR, named after the calendar's name."""
    head = _begin(r, b"BEGIN:VCALENDAR")
    if head is None:
        return None
    end, count, complete = _text_objects(r, b"BEGIN:VCALENDAR", b"END:VCALENDAR", 256 * MiB)
    name = _text_value(head, b"X-WR-CALNAME")
    return Hit("ics", end, CHANCE_GOOD if complete else CHANCE_POOR, name=name,
               info={"events": head.count(b"BEGIN:VEVENT")} if end <= len(head) else None)


@guarded
def parse_vcf(r: Reader) -> Hit | None:
    """vCard file: one or more BEGIN:VCARD … END:VCARD in a row; a single card is named after the person."""
    head = _begin(r, b"BEGIN:VCARD")
    if head is None:
        return None
    end, count, complete = _text_objects(r, b"BEGIN:VCARD", b"END:VCARD", 256 * MiB)
    name = _text_value(head, b"FN") if count == 1 else None
    return Hit("vcf", end, CHANCE_GOOD if complete else CHANCE_POOR, name=name, info={"contacts": count})


# ====================================================================== certificates and keys (text)
_PEM_BEGIN = re.compile(rb"-----BEGIN ([A-Z0-9][A-Z0-9 ]{0,60})-----\r?\n")
_PEM_BODY = re.compile(rb"(?:[A-Za-z0-9+/=]*\r?\n|[A-Za-z][A-Za-z-]*: [^\r\n]*\r?\n)*")


def _pem_ext(label: bytes) -> str:
    if label in (b"CERTIFICATE", b"TRUSTED CERTIFICATE", b"X509 CERTIFICATE"):
        return "crt"
    if label.endswith(b"CERTIFICATE REQUEST"):
        return "csr"
    if label == b"X509 CRL":
        return "crl"
    if label.endswith(b"PRIVATE KEY"):
        return "key"
    if label.startswith(b"PGP "):
        return "asc"
    return "pem"


@guarded
def parse_pem(r: Reader) -> Hit | None:
    """PEM certificate, key or request (and ASCII-armored PGP keys and messages): base64 between BEGIN and
    END lines. A bundle of blocks one after another is kept together."""
    limit = text_end(r, 0, 64 * MiB)
    pos, first, count = 0, None, 0
    while count < 100_000:
        m = _PEM_BEGIN.match(r.read(pos, 80))
        if not m:
            break
        label = m.group(1)
        first = first or label
        endline = b"-----END " + label + b"-----"
        e = r.find(endline, pos + m.end(), limit)
        if e < 0:
            if not count:
                return None
            break
        body = r.read(pos + m.end(), e - pos - m.end())
        if _PEM_BODY.fullmatch(body) is None:
            if not count:
                return None
            break
        pos = e + len(endline)
        pos += 2 if r.read(pos, 2) == b"\r\n" else 1 if r.read(pos, 1) == b"\n" else 0
        count += 1
        nxt = r.read(pos, 256)
        skip = len(nxt) - len(nxt.lstrip(b"\r\n \t"))
        if not nxt[skip:].startswith(b"-----BEGIN "):
            break
        pos += skip
    if not count:
        return None
    return Hit(_pem_ext(first), pos, CHANCE_GOOD, info={"type": first.decode().lower(), "blocks": count})


@guarded
def parse_ppk(r: Reader) -> Hit | None:
    """PuTTY private key: text ending with its Private-MAC line; named after the key comment."""
    head = r.read(0, 64 * KiB)
    if not re.match(rb"PuTTY-User-Key-File-[1-3]: [!-~]{3,64}\r?\n", head):
        return None
    m = re.search(rb"\nPrivate-(?:MAC|Hash): [0-9a-fA-F]{20,128}(\r?\n)?", head)
    if not m:
        return None
    return Hit("ppk", m.end(), CHANCE_GOOD, name=_text_value(head, b"Comment"))


# ====================================================================== Windows shortcuts (.lnk)
_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")


@guarded
def parse_lnk(r: Reader) -> Hit | None:
    """Windows shortcut: header, target ID list, link info, strings and extra data blocks, walked to the
    terminal block. Named after the target."""
    h = r.read(0, 0x4C)
    if len(h) < 0x4C or u32(h, 0) != 0x4C or h[4:20] != _LNK_CLSID:
        return None
    flags = u32(h, 0x14)
    if flags >> 27 or u32(h, 0x3C) > 11 or any(h[0x42:0x4C]):
        return None
    pos, target = 0x4C, None
    if flags & 0x1:                        # LinkTargetIDList
        size = u16(r.read(pos, 2), 0)
        ids = r.read(pos + 2, size)
        p = 0
        while p + 2 <= len(ids):
            n = u16(ids, p)
            if n == 0:
                p += 2
                break
            if n < 2:
                return None
            p += n
        if p != size:
            return None
        pos += 2 + size
    if flags & 0x2:                        # LinkInfo
        li = r.read(pos, 0x24)
        size, hsize = u32(li, 0), u32(li, 4)
        if hsize not in (0x1C, 0x24) or not hsize <= size <= 64 * KiB:
            return None
        info = r.read(pos, size)
        base_off = u32(info, 16)
        if u32(info, 8) & 1 and hsize <= base_off < size:
            raw = info[base_off:].split(b"\0")[0]
            suffix_off = u32(info, 24)
            if hsize <= suffix_off < size:
                raw += info[suffix_off:].split(b"\0")[0]
            target = raw.decode("cp1252", "replace")
        pos += size
    unicode = flags & 0x80
    strings = []
    for bit in (0x4, 0x8, 0x10, 0x20, 0x40):     # name, relative path, working dir, arguments, icon
        if flags & bit:
            n = u16(r.read(pos, 2), 0)
            raw = r.read(pos + 2, n * (2 if unicode else 1))
            strings.append((bit, raw.decode("utf-16-le" if unicode else "cp1252", "replace")))
            pos += 2 + n * (2 if unicode else 1)
    for _ in range(256):                   # extra data blocks, ending with a block size below 4
        b = r.read(pos, 8)
        if len(b) < 4:
            raise Short
        size = u32(b, 0)
        if size < 4:
            pos += 4
            break
        if len(b) < 8 or not 0xA0000001 <= u32(b, 4) <= 0xA000000F or size > MiB:
            return None
        pos += size
    else:
        return None
    if target is None:
        target = next((s for bit, s in strings if bit == 0x8), None)
    name = None
    if target:
        name = clean_name(re.sub(r"\.[A-Za-z0-9]{1,4}$", "", target.replace("/", "\\").rstrip("\\")
                                 .rsplit("\\", 1)[-1]))
    return finish(r, "lnk", pos, CHANCE_GOOD, name=name, info={"target": target[:260]} if target else None)


# ====================================================================== Blender
_BLEND_CODE = re.compile(rb"[A-Z][A-Z0-9]([A-Z0-9]{2}|[A-Z0-9]\0|\0\0)")


@guarded
def parse_blend(r: Reader) -> Hit | None:
    """Blender scene (uncompressed; compressed ones are gzip or zstd files): file blocks walked to ENDB."""
    h = r.read(0, 17)
    if len(h) < 12 or h[:7] != b"BLENDER":
        return None
    if h[7:10] == b"17-" and h[12:13] in (b"v", b"V") and h[10:12].isdigit() and h[13:17].isdigit():
        pos, bo, version = 17, "<" if h[12:13] == b"v" else ">", h[13:17]      # Blender 5.0+ header
        fmt, hsize = "4siQqq", 32                           # code, SDNA, old pointer, length, count
    elif h[7:8] in (b"_", b"-") and h[8:9] in (b"v", b"V") and h[9:12].isdigit():
        pos, bo, version = 12, "<" if h[8:9] == b"v" else ">", h[9:12]
        fmt, hsize = ("4siIii", 20) if h[7:8] == b"_" else ("4siQii", 24)  # code, length, old pointer, ...
    else:
        return None
    for _ in range(10_000_000):
        b = r.read(pos, hsize)
        if len(b) < hsize:
            return Hit("blend", r.limit, CHANCE_POOR)
        f = struct.unpack_from(bo + fmt, b)
        code, length = f[0], f[3] if hsize == 32 else f[1]
        if not _BLEND_CODE.fullmatch(code) or length < 0:
            return None
        pos += hsize + length
        if code == b"ENDB":
            v = version.decode().lstrip("0") or "0"
            return finish(r, "blend", pos, CHANCE_GOOD, info={"version": f"{v[:-2] or 0}.{v[-2:]}"})
    return None


# ====================================================================== DICOM
_DCM_VRS = frozenset(b"AE AS AT CS DA DS DT FL FD IS LO LT OB OD OF OL OV OW PN SH SL SQ SS ST SV TM UC UI UL UN "
                     b"UR US UT UV".split())
_DCM_LONG = frozenset(b"OB OD OF OL OV OW SQ SV UC UN UR UT UV".split())
_UNDEF = 0xFFFFFFFF


class _Dicom:
    """Walks DICOM data elements; every length is skipped arithmetically (pixel data isn't read)."""

    def __init__(self, r: Reader):
        self.r = r
        self.count = 0
        self.pixels = False
        self.values: dict[int, bytes] = {}

    def element(self, pos: int, explicit: bool, bo: str):
        """(tag, VR or None if invalid, value length, header length) at POS, or None past the data."""
        b = self.r.read(pos, 12)
        if len(b) < 8:
            return None
        g, e = struct.unpack_from(bo + "HH", b)
        tag = g << 16 | e
        if g == 0xFFFE or not explicit:
            return tag, b"", struct.unpack_from(bo + "I", b, 4)[0], 8
        vr = b[4:6]
        if vr not in _DCM_VRS:
            return tag, None, 0, 8
        if vr in _DCM_LONG:
            if len(b) < 12:
                return None
            return tag, vr, struct.unpack_from(bo + "I", b, 8)[0], 12
        return tag, vr, struct.unpack_from(bo + "H", b, 6)[0], 8

    def items(self, pos: int, explicit: bool, bo: str, depth: int) -> int:
        """The items of a sequence of undefined length (or the fragments of encapsulated pixel data) from POS
        to just after the sequence delimiter."""
        while True:
            self.count += 1
            if self.count > 2_000_000:
                raise ValueError("too many elements")
            el = self.element(pos, False, bo)
            if el is None:
                raise Short
            tag, _vr, vlen, _h = el
            if tag == 0xFFFEE0DD:
                return pos + 8
            if tag != 0xFFFEE000:
                raise ValueError("not an item")
            pos = self.dataset(pos + 8, explicit, bo, depth + 1) if vlen == _UNDEF else pos + 8 + vlen

    def dataset(self, pos: int, explicit: bool, bo: str, depth: int) -> int:
        """The elements of an item of undefined length, to just after its delimiter."""
        if depth > 32:
            raise ValueError("too deep")
        while True:
            self.count += 1
            if self.count > 2_000_000:
                raise ValueError("too many elements")
            el = self.element(pos, explicit, bo)
            if el is None:
                raise Short
            tag, vr, vlen, hl = el
            if tag == 0xFFFEE00D:
                return pos + 8
            if vr is None:
                raise ValueError("bad VR")
            pos = self.value_end(pos, tag, vr, vlen, hl, explicit, bo, depth)

    def value_end(self, pos: int, tag: int, vr: bytes, vlen: int, hl: int, explicit: bool, bo: str,
                  depth: int) -> int:
        if vlen != _UNDEF:
            return pos + hl + vlen
        if vr == b"UN":                    # an unknown sequence: implicit VR little endian inside
            return self.items(pos + hl, False, "<", depth)
        if vr in (b"SQ", b"") or (vr in (b"OB", b"OW") and tag == 0x7FE00010):
            return self.items(pos + hl, explicit, bo, depth)
        raise ValueError("undefined length on a plain value")

    def top(self, pos: int, explicit: bool, bo: str, prev: int, stop: int | None = None,
            group: int | None = None) -> tuple[int, int, bool]:
        """Top-level elements from POS (tags strictly ascending): (end, last tag, ended cleanly). The data set
        ends where the elements stop making sense (the next file, zeros), at STOP, or (for the file meta
        information) where GROUP ends."""
        while stop is None or pos < stop:
            self.count += 1
            if self.count > 2_000_000:
                return pos, prev, False
            el = self.element(pos, explicit, bo)
            if el is None:
                return pos, prev, pos >= self.r.limit
            tag, vr, vlen, hl = el
            g = tag >> 16
            if group is not None and g != group:
                return pos, prev, True
            if vr is None or tag <= prev or g == 0xFFFE or (g > 0x7FE0 and tag not in (0xFFFAFFFA, 0xFFFCFFFC)):
                return pos, prev, True
            try:
                end = self.value_end(pos, tag, vr, vlen, hl, explicit, bo, 0)
            except ValueError:
                return pos, prev, False
            if end > self.r.limit:
                raise Short
            if tag == 0x7FE00010:
                self.pixels = True
            elif tag in (0x00020010, 0x00080060, 0x00280010, 0x00280011, 0x00080020) and vlen <= 64:
                self.values[tag] = self.r.read(pos + hl, vlen)
            pos, prev = end, tag
        return pos, prev, True


_DCM_IMPLICIT, _DCM_BIG, _DCM_DEFLATE = b"1.2.840.10008.1.2", b"1.2.840.10008.1.2.2", b"1.2.840.10008.1.2.1.99"


@guarded
def parse_dicom(r: Reader) -> Hit | None:
    """DICOM medical image: a 128-byte preamble, "DICM", the file meta group (explicit VR little endian),
    then the data set in the transfer syntax the meta group names, walked to its last element."""
    if r.read(128, 4) != b"DICM":
        return None
    w = _Dicom(r)
    first = w.element(132, True, "<")
    if first is None or first[0] >> 16 != 2 or first[1] is None:
        return None
    meta_end = None
    if first[0] == 0x00020000 and first[1] == b"UL" and first[2] == 4:
        meta_end = 132 + 12 + u32(r.read(144, 4), 0)
    try:
        pos, prev, _clean = w.top(132, True, "<", -1, meta_end, group=2)
        ts = w.values.get(0x00020010, b"").rstrip(b"\0 ")
        if not ts:
            return None
        if ts == _DCM_DEFLATE:              # the whole data set is one raw deflate stream
            d = zlib.decompressobj(-15)
            start = pos
            while True:
                chunk = r.read(pos, MiB)
                if not chunk:
                    return Hit("dcm", r.limit, CHANCE_POOR)
                pos += len(chunk)
                while chunk:
                    d.decompress(chunk, 16 * MiB)
                    chunk = d.unconsumed_tail
                    if d.eof:
                        break
                if d.eof:
                    break
                if pos - start > 4 * GiB:
                    return None
            end, clean = pos - len(d.unused_data), True
            w.pixels = True
        else:
            explicit, bo = ts != _DCM_IMPLICIT, ">" if ts == _DCM_BIG else "<"
            end, prev, clean = w.top(pos, explicit, bo, prev)
    except Short:
        return Hit("dcm", r.limit, CHANCE_POOR)
    info = {}
    if 0x00080060 in w.values:
        info["modality"] = w.values[0x00080060].decode("ascii", "replace").strip("\0 ")
    for tag, key in ((0x00280011, "width"), (0x00280010, "height")):
        v = w.values.get(tag)
        if v is not None and len(v) == 2:
            info[key] = struct.unpack(("<" if ts != _DCM_BIG else ">") + "H", v)[0]
    mtime = None
    date = w.values.get(0x00080020, b"").strip(b"\0 ")
    if re.fullmatch(rb"\d{8}", date):
        try:
            mtime = plausible(calendar.timegm((int(date[:4]), int(date[4:6]), int(date[6:8]), 0, 0, 0)))
        except (ValueError, OverflowError):
            mtime = None
    chance = CHANCE_GOOD if clean and w.pixels else CHANCE_FAIR
    return finish(r, "dcm", end, chance, mtime=mtime, info=info or None)


# ====================================================================== FITS
_PRINTABLE = bytes(range(0x20, 0x7F))


def _fits_header(r: Reader, pos: int) -> tuple[dict[bytes, bytes], int] | None:
    """The cards of the FITS header at POS ({keyword: value field}) and where its data starts."""
    cards: dict[bytes, bytes] = {}
    for blk in range(2000):
        b = r.read(pos + 2880 * blk, 2880)
        if len(b) < 2880:
            raise Short
        if b.translate(None, _PRINTABLE):
            return None
        for i in range(0, 2880, 80):
            key = b[i:i + 8].rstrip()
            if key == b"END":
                return cards, pos + 2880 * (blk + 1)
            if not re.fullmatch(rb"[A-Z0-9_-]*", key):
                return None
            if b[i + 8:i + 10] == b"= ":
                cards.setdefault(key, b[i + 10:i + 80])
    return None


def _fits_int(cards: dict, key: bytes, default: int | None = None) -> int:
    v = cards.get(key)
    if v is None:
        if default is None:
            raise ValueError(f"no {key!r}")
        return default
    return int(v.split(b"/")[0].strip())


def _fits_str(cards: dict, key: bytes) -> str | None:
    m = re.match(rb"\s*'((?:[^']|'')*)'", cards.get(key, b""))
    return m.group(1).replace(b"''", b"'").decode("ascii", "replace").strip() if m else None


def _fits_data(cards: dict, primary: bool) -> int:
    """The size of the data that follows a header (padded to 2880 bytes)."""
    bitpix, naxis = _fits_int(cards, b"BITPIX"), _fits_int(cards, b"NAXIS")
    if bitpix not in (8, 16, 32, 64, -32, -64) or not 0 <= naxis <= 999:
        raise ValueError("bad BITPIX/NAXIS")
    dims = [_fits_int(cards, b"NAXIS%d" % i) for i in range(1, naxis + 1)]
    if primary and dims and dims[0] == 0 and cards.get(b"GROUPS", b"").strip()[:1] == b"T":
        dims = dims[1:]                    # random groups
    n = 1
    for d in dims:
        if d < 0:
            raise ValueError("negative axis")
        n *= d
    if not dims:
        n = 0
    size = abs(bitpix) // 8 * _fits_int(cards, b"GCOUNT", 1) * (_fits_int(cards, b"PCOUNT", 0) + n)
    if size < 0 or size > 1 << 42:
        raise ValueError("absurd size")
    return -(-size // 2880) * 2880


@guarded
def parse_fits(r: Reader) -> Hit | None:
    """FITS image or table (astronomy): 2880-byte header blocks of 80-character cards, data sized by BITPIX
    and NAXISn, then any extensions (XTENSION headers). Named after OBJECT, dated by DATE-OBS / DATE."""
    first = r.read(0, 80)
    if not re.match(rb"SIMPLE  = {20}T", first):
        return None
    try:
        res = _fits_header(r, 0)
        if res is None:
            return None
        cards, pos = res
        primary = cards
        pos += _fits_data(cards, True)
        hdus = 1
        while hdus < 10000 and r.read(pos, 10) == b"XTENSION= ":
            res = _fits_header(r, pos)
            if res is None:
                break
            cards, data = res
            pos = data + _fits_data(cards, False)
            hdus += 1
    except Short:
        return Hit("fits", r.limit, CHANCE_POOR)
    mtime = None
    for key in (b"DATE-OBS", b"DATE"):
        m = re.match(r"(\d{4})-(\d\d)-(\d\d)(?:T(\d\d):(\d\d):(\d\d))?", _fits_str(primary, key) or "")
        if m:
            try:
                mtime = plausible(calendar.timegm(tuple(int(x or 0) for x in m.groups())))
            except (ValueError, OverflowError):
                mtime = None
            break
    info = {"hdus": hdus}
    if _fits_int(primary, b"NAXIS", 0) >= 2:
        info["width"], info["height"] = _fits_int(primary, b"NAXIS1", 0), _fits_int(primary, b"NAXIS2", 0)
    return finish(r, "fits", pos, CHANCE_GOOD, name=clean_name(_fits_str(primary, b"OBJECT")), mtime=mtime,
                  info=info)


# ====================================================================== binary property lists
def _int_size(v: int) -> int:
    return 1 if v < 1 << 8 else 2 if v < 1 << 16 else 4 if v < 1 << 32 else 8


def _bplist_size(b: bytes, refsize: int) -> int | None:
    """The size of the object whose marker starts B (a few bytes of it), or None if it isn't one."""
    m = b[0]
    hi, lo = m >> 4, m & 0xF
    if hi == 0:
        return 1 if lo in (0, 8, 9, 0xF) else None
    if hi == 1:
        return 1 + (1 << lo) if lo <= 4 else None
    if hi == 2:
        return 1 + (1 << lo) if lo in (2, 3) else None
    if hi == 3:
        return 9 if lo == 3 else None
    if hi == 8:
        return 2 + lo
    if hi not in (4, 5, 6, 0xA, 0xB, 0xC, 0xD):
        return None
    head, count = 1, lo
    if lo == 0xF:                          # the count follows as an int object
        if len(b) < 2 or b[1] >> 4 != 1 or b[1] & 0xF > 3:
            return None
        k = 1 << (b[1] & 0xF)
        if len(b) < 2 + k:
            return None
        head, count = 2 + k, int.from_bytes(b[2:2 + k], "big")
    each = {4: 1, 5: 1, 6: 2, 0xD: 2 * refsize}.get(hi, refsize)
    return head + count * each


def _bplist_end(r: Reader, refsize: int, cap: int) -> tuple[int, int] | None:
    """Walk the objects (written one after another from offset 8) assuming references of REFSIZE bytes;
    after each one, see whether the offset table and the trailer could follow. → (end, object count)."""
    pos, n, last = 8, 0, 8
    while pos < cap and n < 4_000_000:
        if n:
            for osize in {_int_size(last), _int_size(pos)}:        # writers size it for one or the other
                t = pos + n * osize
                tr = r.read(t, 32)
                if (len(tr) == 32 and tr[6] == osize and tr[7] == refsize and be64(tr, 8) == n
                        and be64(tr, 24) == pos and be64(tr, 16) < n and not any(tr[:5])):
                    return t + 32, n
        b = r.read(pos, 10)
        if not b:
            return None
        size = _bplist_size(b, refsize)
        if size is None:
            return None
        last, pos, n = pos, pos + size, n + 1
    return None


@guarded
def parse_bplist(r: Reader) -> Hit | None:
    """Apple binary property list: objects one after another, an offset table, and a 32-byte trailer (object
    count, reference size, where the offset table is). The objects are walked until the trailer turns up
    right where it should; the reference size isn't known until then, so 1, 2 and 4 bytes are tried."""
    if r.read(0, 8) != b"bplist00":
        return None
    cap = min(r.limit, 256 * MiB)
    for refsize in (1, 2, 4):
        res = _bplist_end(r, refsize, cap)
        if res is not None:
            return finish(r, "plist", res[0], CHANCE_GOOD, info={"objects": res[1]})
    return None


# ====================================================================== virtual-machine disks
@guarded
def parse_vdi(r: Reader) -> Hit | None:
    """VirtualBox disk image: the data starts at offData and holds every allocated block."""
    h = r.read(0, 0x190)
    if len(h) < 0x190 or u32(h, 0x40) != 0xBEDA107F or u32(h, 0x44) not in (0x00010001, 0x00010000):
        return None
    if b"VirtualBox" not in h[:0x40] and b"VM" not in h[:0x40]:
        return None
    itype, off_blocks, off_data = u32(h, 0x4C), u32(h, 0x154), u32(h, 0x158)
    disk, block, extra, blocks, allocated = u64(h, 0x170), u32(h, 0x178), u32(h, 0x17C), u32(h, 0x180), \
        u32(h, 0x184)
    if itype not in (1, 2, 3, 4) or not is_pow2(block) or allocated > blocks or not off_blocks < off_data:
        return None
    if blocks * block < disk or off_blocks + 4 * blocks > off_data:
        return None
    return finish(r, "vdi", off_data + allocated * (block + extra), CHANCE_GOOD,
                  info={"virtual_size": disk, "kind": "fixed" if itype == 2 else "dynamic"})


def _vhd_checksum(b: bytes, at: int, size: int) -> bool:
    data = b[:at] + b"\0\0\0\0" + b[at + 4:size]
    return (~sum(data)) & 0xFFFFFFFF == be32(b, at)


@guarded
def parse_vhd(r: Reader) -> Hit | None:
    """Virtual PC / Hyper-V dynamic or differencing disk (.vhd): a copy of the footer at the start, the
    dynamic header, the block table, the blocks and the footer. Fixed disks have only the trailing footer
    and are carved as whatever filesystem they hold."""
    f = r.read(0, 512)
    if len(f) < 512 or f[:8] != b"conectix" or be32(f, 12) != 0x00010000 or be32(f, 60) not in (3, 4):
        return None
    if not _vhd_checksum(f, 64, 512):
        return None
    dyn_off = be64(f, 16)
    d = r.read(dyn_off, 1024)
    if len(d) < 1024 or d[:8] != b"cxsparse" or not _vhd_checksum(d, 36, 1024):
        return None
    bat, entries, block = be64(d, 16), be32(d, 28), be32(d, 32)
    if not is_pow2(block) or entries > 1 << 24 or bat < 512:
        return None
    table = r.read(bat, 4 * entries)
    if len(table) < 4 * entries:
        return Hit("vhd", r.limit, CHANCE_POOR)
    bitmap = max(512, align(block // 4096, 512))     # one bit per sector, in whole sectors
    used = [s for s in struct.unpack(f">{entries}I", table) if s != 0xFFFFFFFF]
    end = max(bat + -(-4 * entries // 512) * 512, dyn_off + 1024)
    if used:
        end = max(end, max(used) * 512 + bitmap + block)
    chance = CHANCE_GOOD if r.read(end, 8) == b"conectix" else CHANCE_FAIR
    return finish(r, "vhd", end + 512, chance, info={"virtual_size": be64(f, 48), "blocks": len(used)})


_VHDX_BAT = uuid.UUID("2DC27766-F623-4200-9D64-115E9BFD4A08").bytes_le
_VHDX_META = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E").bytes_le
_VHDX_PARAMS = uuid.UUID("CAA16737-FA36-4D43-B3B6-33F0AA44E76B").bytes_le
_VHDX_SECTOR = uuid.UUID("8141BF1D-A96F-4709-BA47-F233A8FAAB5F").bytes_le


@guarded
def parse_vhdx(r: Reader) -> Hit | None:
    """Hyper-V disk (.vhdx): the region table locates the block table (BAT) and the metadata (block size,
    sector size); the file ends after the furthest region, log or block."""
    if r.read(0, 8) != b"vhdxfile":
        return None
    heads = [r.read(o, 80) for o in (64 * KiB, 128 * KiB)]
    heads = [h for h in heads if len(h) == 80 and h[:4] == b"head"]
    if not heads:
        return None
    head = max(heads, key=lambda h: u64(h, 8))
    end = max(1024 * KiB, u64(head, 72) + u32(head, 68))     # log offset + length
    rt = r.read(192 * KiB, 64 * KiB)
    if len(rt) < 16 or rt[:4] != b"regi" or u32(rt, 8) > 2047:
        return None
    regions = {}
    for i in range(u32(rt, 8)):
        o = 16 + 32 * i
        guid, off, length = rt[o:o + 16], u64(rt, o + 16), u32(rt, o + 24)
        regions[guid] = (off, length)
        end = max(end, off + length)
    if _VHDX_BAT not in regions or _VHDX_META not in regions:
        return None
    moff, mlen = regions[_VHDX_META]
    meta = r.read(moff, min(mlen, MiB))
    if meta[:8] != b"metadata":
        return None
    items = {}
    for i in range(min(u16(meta, 10), 2047)):
        o = 32 + 32 * i
        items[meta[o:o + 16]] = (u32(meta, o + 16), u32(meta, o + 20))
    io, _ = items[_VHDX_PARAMS]
    block = u32(meta, io)
    so, _ = items.get(_VHDX_SECTOR, (None, 0))
    sector = u32(meta, so) if so is not None else 512
    if not is_pow2(block) or not MiB <= block <= 256 * MiB or sector not in (512, 4096):
        return None
    chunk = (1 << 23) * sector // block       # payload blocks per sector-bitmap block
    boff, blen = regions[_VHDX_BAT]
    bat = r.read(boff, min(blen, 256 * MiB))
    for i, (e,) in enumerate(struct.iter_unpack("<Q", bat[:len(bat) // 8 * 8])):
        if e & 7 in (6, 7):
            bitmap = (i + 1) % (chunk + 1) == 0
            end = max(end, (e >> 20) * MiB + (MiB if bitmap else block))
    return finish(r, "vhdx", end, CHANCE_GOOD, info={"block_size": block})


@guarded
def parse_qcow2(r: Reader) -> Hit | None:
    """QEMU disk image (qcow2): the file ends after the last cluster with a non-zero reference count."""
    h = r.read(0, 104)
    if len(h) < 72 or h[:4] != b"QFI\xfb" or be32(h, 4) not in (2, 3):
        return None
    bits, crypt = be32(h, 20), be32(h, 32)
    if not 9 <= bits <= 21 or crypt > 2:
        return None
    cs = 1 << bits
    l1_off, rt_off, rt_clusters = be64(h, 40), be64(h, 48), be32(h, 56)
    order = be32(h, 96) if be32(h, 4) == 3 and len(h) >= 104 else 4
    if l1_off % cs or rt_off % cs or not rt_off or not 1 <= rt_clusters <= 1 << 16 or order > 6:
        return None
    rbits = 1 << order
    per_block = cs * 8 // rbits
    table = r.read(rt_off, rt_clusters * cs)
    entries = [e & ~0x1FF for (e,) in struct.iter_unpack(">Q", table[:len(table) // 8 * 8])]
    for i in range(len(entries) - 1, -1, -1):
        if not entries[i]:
            continue
        blk = r.read(entries[i], cs).rstrip(b"\0")
        if not blk:
            continue
        if rbits >= 8:
            idx = (len(blk) - 1) // (rbits // 8)
        else:
            last, per_byte = blk[-1], 8 // rbits
            idx = (len(blk) - 1) * per_byte + max(k for k in range(per_byte) if (last >> (k * rbits)) &
                                                  ((1 << rbits) - 1))
        end = (i * per_block + idx + 1) * cs
        return finish(r, "qcow2", end, CHANCE_GOOD, info={"virtual_size": be64(h, 24), "cluster_size": cs})
    return Hit("qcow2", None, CHANCE_FAIR, info={"virtual_size": be64(h, 24)})


@guarded
def parse_vmdk(r: Reader) -> Hit | None:
    """VMware disk: a sparse extent ("KDMV": the end follows from its grain tables, or from the stream
    markers of a stream-optimized disk), or a descriptor file (text)."""
    h = r.read(0, 512)
    if h.startswith(b"# Disk DescriptorFile"):
        end = text_end(r, 0, 64 * KiB)
        if not re.match(rb"# Disk DescriptorFile\r?\n(?:#[^\n]*\n|\w+\s*=[^\n]*\n)*createType\s*=", r.read(0, end)):
            return None
        return Hit("vmdk", end, CHANCE_GOOD)
    if len(h) < 80 or h[:4] != b"KDMV" or not 1 <= u32(h, 4) <= 3 or h[73:77] != b"\n \r\n":
        return None
    flags, capacity, grain, gtes, gd, overhead = u32(h, 8), u64(h, 12), u64(h, 20), u32(h, 44), u64(h, 56), \
        u64(h, 64)
    if not is_pow2(grain) or grain > 2048 or gtes != 512 or not capacity:
        return None
    info = {"virtual_size": capacity * 512}
    if flags & 0x10000 or gd == 0xFFFFFFFFFFFFFFFF:          # stream-optimized: walk the markers
        pos = overhead * 512
        for _ in range(1 << 24):
            m = r.read(pos, 16)
            if len(m) < 16:
                return Hit("vmdk", r.limit, CHANCE_POOR, info=info)
            sectors, size = u64(m, 0), u32(m, 8)
            if size:                       # a compressed grain
                pos += -(-(12 + size) // 512) * 512
                continue
            kind = u32(m, 12)
            if kind == 0:                  # end of stream
                return finish(r, "vmdk", pos + 512, CHANCE_GOOD, info=info)
            if kind not in (1, 2, 3) or sectors > 1 << 24:
                return Hit("vmdk", None, CHANCE_FAIR, info=info)
            pos += 512 + sectors * 512
        return None
    grains = -(-capacity // grain)
    ngd = -(-grains // gtes)                 # grain directory entries
    if ngd > 1 << 22:
        return None
    end = max(overhead, gd + -(-4 * ngd // 512)) * 512
    gd_entries = struct.unpack(f"<{ngd}I", r.read(gd * 512, 4 * ngd).ljust(4 * ngd, b"\0"))
    for gt in gd_entries:
        if not gt:
            continue
        table = r.read(gt * 512, 2048)
        end = max(end, gt * 512 + 2048)
        if len(table) == 2048:
            top = max(struct.unpack("<512I", table))
            if top:
                end = max(end, (top + grain) * 512)
    return finish(r, "vmdk", end, CHANCE_GOOD, info=info)


# ====================================================================== the formats
_TORRENT_KEYS = (b"announce", b"announce-list", b"comment", b"created by", b"creation date", b"encoding", b"info")

FORMATS: list[Format] = [
    Format("ttf", "Font", "other", ("ttf", "otf", "ttc"),
           ((0, b"\x00\x01\x00\x00"), (0, b"OTTO"), (0, b"true"), (0, b"typ1"), (0, b"ttcf")), parse_font,
           max_size=512 * MiB, min_size=64, aliases=("otf", "ttc", "font")),
    Format("woff", "Web font", "other", ("woff", "woff2"), ((0, b"wOFF"), (0, b"wOF2")), parse_woff,
           max_size=256 * MiB, min_size=48, aliases=("woff2",)),
    Format("swf", "Flash movie", "other", ("swf",), ((0, b"FWS"), (0, b"CWS"), (0, b"ZWS")), parse_swf,
           max_size=GiB, min_size=21, aliases=("flash",)),
    Format("torrent", "BitTorrent file", "other", ("torrent",),
           tuple((0, b"d%d:%s" % (len(k), k)) for k in _TORRENT_KEYS), parse_torrent,
           max_size=256 * MiB, min_size=32),
    Format("ics", "Calendar", "other", ("ics",), ((0, b"BEGIN:VCALENDAR"), (0, b"\xef\xbb\xbfBEGIN:VCALENDAR")),
           parse_ics, max_size=256 * MiB, min_size=30, aliases=("ical", "calendar")),
    Format("vcf", "Contacts (vCard)", "other", ("vcf",), ((0, b"BEGIN:VCARD"), (0, b"\xef\xbb\xbfBEGIN:VCARD")),
           parse_vcf, max_size=256 * MiB, min_size=24, aliases=("vcard", "contacts")),
    Format("pem", "Certificate or key", "other", ("pem", "crt", "key", "csr", "crl", "asc"),
           ((0, b"-----BEGIN "),), parse_pem, max_size=64 * MiB, min_size=40, aliases=("crt", "cer", "key", "asc")),
    Format("ppk", "PuTTY private key", "other", ("ppk",), ((0, b"PuTTY-User-Key-File-"),), parse_ppk,
           max_size=MiB, min_size=64),
    Format("lnk", "Windows shortcut", "other", ("lnk",), ((0, b"\x4c\x00\x00\x00\x01\x14\x02\x00"),), parse_lnk,
           max_size=16 * MiB, min_size=0x4C + 4, aliases=("shortcut",)),
    Format("blend", "Blender scene", "other", ("blend",), ((0, b"BLENDER"),), parse_blend,
           max_size=16 * GiB, min_size=32, aliases=("blender",)),
    Format("dcm", "DICOM medical image", "photo", ("dcm",), ((128, b"DICM"),), parse_dicom,
           max_size=16 * GiB, min_size=132 + 12, aliases=("dicom",)),
    Format("fits", "FITS image", "photo", ("fits",), ((0, b"SIMPLE  ="),), parse_fits,
           max_size=64 * GiB, min_size=2880, aliases=("fit", "fts")),
    Format("plist", "Property list (binary)", "other", ("plist",), ((0, b"bplist00"),), parse_bplist,
           max_size=256 * MiB, min_size=40, aliases=("bplist",)),
    Format("vdi", "VirtualBox disk", "other", ("vdi",), ((0x40, b"\x7f\x10\xda\xbe"),), parse_vdi,
           max_size=16 << 40, min_size=512, enabled=False),
    Format("vhd", "Virtual PC disk", "other", ("vhd",), ((0, b"conectix"),), parse_vhd,
           max_size=16 << 40, min_size=2048, enabled=False),
    Format("vhdx", "Hyper-V disk", "other", ("vhdx",), ((0, b"vhdxfile"),), parse_vhdx,
           max_size=64 << 40, min_size=MiB, enabled=False),
    Format("qcow2", "QEMU disk", "other", ("qcow2",), ((0, b"QFI\xfb"),), parse_qcow2,
           max_size=64 << 40, min_size=512, enabled=False, aliases=("qcow",)),
    Format("vmdk", "VMware disk", "other", ("vmdk",), ((0, b"KDMV"), (0, b"# Disk DescriptorFile")), parse_vmdk,
           max_size=64 << 40, min_size=20, enabled=False),
]
