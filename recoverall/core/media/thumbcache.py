"""Thumbnails of photos from the caches operating systems keep: a deleted photo is often gone while the small
picture the system made of it is still there, sometimes with the photo's name and folder (forensic tools
read these caches for the same reason).

* Windows Vista to 11, ``thumbcache_<size>.db``: a header ("CMMM", format version: 20 Vista, 21 Windows 7,
  30 and up Windows 8 to 11; cache type) and entries one after the other, each starting with "CMMM": its
  size, a 64-bit hash of the original file, the sizes of an identifier string (UTF-16, the cache id: the
  original's name is kept in the search index, not here), of padding and of the data, then (Windows 8 and
  up) the picture's width and height, two checksums, the identifier, the padding and the picture itself (a
  JPEG, PNG or BMP). Vista also has the file extension in the entry, Windows 7 neither it nor the size.
* Windows XP, ``Thumbs.db`` in every folder of pictures: an OLE compound file. Its "Catalog" stream lists the
  thumbnails: each record has its size, an index, the original file's modification time (FILETIME) and its
  name (UTF-16). The thumbnail of record N is the stream whose name is N's digits reversed ("123" → "321"),
  a short header and a JPEG — some written without Huffman tables (the standard ones are put in).
* Android, ``DCIM/.thumbnails/.thumbdata3--<id>`` and the like: JPEGs one after another in fixed-size slots
  (the same folder also holds plain JPEG thumbnails, which are photos like any other).
* Linux desktops (freedesktop.org), ``~/.cache/thumbnails/{normal,large,x-large,xx-large}/<md5 of the
  URI>.png``: PNG files whose text chunks "Thumb::URI" and "Thumb::MTime" give the original file's location
  and modification time — so the deleted photo's full path is known.
* macOS QuickLook, ``com.apple.QuickLook.thumbnailcache``: ``index.sqlite`` lists the files (folder, name, a
  property list with their date) and, for each thumbnail, its size, the layout of its bitmap and where that is
  in ``thumbnails.data``: raw RGBA pixels, written out here as PNG files.

    kind = kind_of("thumbcache_256.db", head)       # "thumbcache", "thumbsdb", ... or None
    for t in extract(data, kind, companion=None):    # the other file of a pair (index.sqlite + thumbnails.data)
        t.name, t.original_path, t.ext, t.width, t.height, t.mtime, t.data

Everything is read defensively: a damaged or partly overwritten cache gives fewer thumbnails, never an error.
"""

from __future__ import annotations

import os
import plistlib
import re
import sqlite3
import struct
import tempfile
import urllib.parse
import zlib
from dataclasses import dataclass

KINDS = {
    "thumbcache": "Windows thumbnail cache",
    "thumbsdb": "Windows XP thumbnail file (Thumbs.db)",
    "thumbdata": "Android thumbnail cache",
    "android_thumbnail": "Android thumbnail",
    "freedesktop": "Linux desktop thumbnail",
    "quicklook_index": "macOS QuickLook thumbnail cache (index)",
    "quicklook_data": "macOS QuickLook thumbnail cache (pictures)",
}
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_PNG = b"\x89PNG\r\n\x1a\n"
_SOI = re.compile(rb"\xff\xd8\xff[\xc0-\xfe]")
_HEX_PNG = re.compile(r"^[0-9a-f]{32}\.png$")
_FILETIME_EPOCH = 11644473600
_MAC_EPOCH = 978307200                          # 2001-01-01 (Core Data / CFAbsoluteTime)
_LIMIT = 100_000                                # entries at most


@dataclass
class Thumbnail:
    """A thumbnail found in a cache. ``name`` is the original file's name when the cache records it (else the
    cache's own id for it); ``data`` is the picture as a file of type ``ext``."""
    name: str
    original_path: str | None
    data: bytes
    ext: str
    width: int = 0
    height: int = 0
    mtime: float | None = None                  # the original file's modification time, when recorded
    source: str = ""                            # where in the cache it was

    @property
    def filename(self) -> str:
        return f"{self.name}.{self.ext}"


# ---------------------------------------------------------------------- which cache
def kind_of(name: str, head: bytes) -> str | None:
    """Which thumbnail cache a file is, from its name (or path) and first bytes (a few KiB are enough for a
    freedesktop thumbnail's text chunks); None if it isn't one."""
    path = str(name or "").replace("\\", "/")
    base = path.rsplit("/", 1)[-1].lower()
    parts = [p.lower() for p in path.split("/")]
    head = bytes(head[:65536])
    if head[:4] == b"CMMM" and len(head) >= 8 and 20 <= struct.unpack_from("<I", head, 4)[0] <= 64:
        return "thumbcache"
    if head[:8] == _OLE and base in ("thumbs.db", "ehthumbs.db", "ehthumbs_vista.db", ""):
        return "thumbsdb" if base or b"C\x00a\x00t\x00a\x00l\x00o\x00g" in head else None
    if base.startswith(".thumbdata"):
        return "thumbdata"
    if head[:8] == _PNG and (b"Thumb::URI" in head or _HEX_PNG.match(base) and "thumbnails" in parts):
        return "freedesktop"
    in_ql = any(p.startswith("com.apple.quicklook.thumbnailcache") for p in parts)
    if base == "index.sqlite" and head[:16] == b"SQLite format 3\x00" and (in_ql or not path.count("/")):
        return "quicklook_index"
    if base == "thumbnails.data" and in_ql:
        return "quicklook_data"
    if ".thumbnails" in parts[:-1] and (head[:3] == b"\xff\xd8\xff" or head[:8] == _PNG):
        return "android_thumbnail"
    return None


def extract(data, kind: str, companion=None) -> list[Thumbnail]:
    """The thumbnails in DATA, a cache of KIND (see :func:`kind_of`). COMPANION is the other file of a
    QuickLook pair (thumbnails.data for an index.sqlite, or the other way round)."""
    fn = {"thumbcache": _thumbcache, "thumbsdb": _thumbsdb, "thumbdata": _thumbdata,
          "android_thumbnail": _single, "freedesktop": _freedesktop}.get(kind)
    out: list[Thumbnail] = []
    try:
        if fn is not None:
            fn(data, out)
        elif kind == "quicklook_index" and companion is not None:
            _quicklook(data, companion, out)
        elif kind == "quicklook_data" and companion is not None:
            _quicklook(companion, data, out)
    except (struct.error, IndexError, ValueError, OverflowError, UnicodeError, zlib.error, sqlite3.Error,
            MemoryError, plistlib.InvalidFileException):
        pass                                    # damaged further on: what was found so far
    return out


# ---------------------------------------------------------------------- pictures
def _picture(blob: bytes) -> tuple[str, int, int] | None:
    """(extension, width, height) of the JPEG, PNG or BMP at the start of BLOB."""
    if blob[:3] == b"\xff\xd8\xff":
        w, h = _jpeg_size(blob)
        return "jpg", w, h
    if blob[:8] == _PNG and len(blob) >= 24:
        w, h = struct.unpack_from(">II", blob, 16)
        return "png", w, h
    if blob[:2] == b"BM" and len(blob) >= 26:
        w, h = struct.unpack_from("<ii", blob, 18)
        return "bmp", abs(w), abs(h)
    return None


def _jpeg_size(blob: bytes) -> tuple[int, int]:
    pos = 2
    for _ in range(256):
        if pos + 9 > len(blob) or blob[pos] != 0xFF:
            break
        mk = blob[pos + 1]
        if mk in (0xC0, 0xC1, 0xC2, 0xC3):
            h, w = struct.unpack_from(">HH", blob, pos + 5)
            return w, h
        if mk == 0xDA:
            break
        pos += 2 + ((blob[pos + 2] << 8) | blob[pos + 3])
    return 0, 0


def _jpeg_end(data, at: int, limit: int) -> int:
    """Where the JPEG at AT ends (after its end marker), or -1."""
    from ..carve.common import BytesReader
    from ..carve.images import _tail_end, walk_jpeg
    r = BytesReader(data)
    st = walk_jpeg(r, at, meta=False)
    if st and st["blank"] and st["ranges"]:   # zeros: perhaps a dark area of the picture (optimised tables)
        end = _tail_end(r, st["ranges"][-1][0], blanks=False)
        return end if r.read(end - 2, 2) == b"\xff\xd9" and end <= limit else -1
    if not st or not st["complete"] or st["end"] > limit:
        return -1
    return st["end"]


def _fix_jpeg(blob: bytes) -> bytes:
    """A thumbnail's JPEG made standard: a start marker when it lacks one, the Huffman tables of JPEG Annex K
    when it has none (some writers leave them out, like MJPEG frames)."""
    if blob[:2] != b"\xff\xd8" and blob[:1] == b"\xff" and blob[1:2] in (b"\xdb", b"\xc0", b"\xc4", b"\xe0"):
        blob = b"\xff\xd8" + blob
    if b"\xff\xc4" not in blob[:blob.find(b"\xff\xda") if b"\xff\xda" in blob else len(blob)]:
        sos = blob.find(b"\xff\xda")
        if sos > 0:
            from ..filerepair import standard_dht
            blob = blob[:sos] + standard_dht() + blob[sos:]
    return blob


def png(width: int, height: int, rows) -> bytes:
    """A PNG file (8-bit RGBA) from ROWS: one bytes object of width × 4 bytes per row."""
    raw = b"".join(b"\x00" + bytes(r) for r in rows)

    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return _PNG + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)) + \
        chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b"")


# ---------------------------------------------------------------------- Windows thumbcache_*.db
# entry layouts: (header size, offset of the identifier size, of the padding size, of the data size, of the
# width and height or -1)
_TC_LAYOUTS = {"vista": (56, 24, 28, 32, -1), "7": (48, 16, 20, 24, -1), "8": (56, 16, 20, 24, 28)}


def _thumbcache(data, out: list[Thumbnail]) -> None:
    size = len(data)
    if size < 24 or bytes(data[:4]) != b"CMMM":
        return
    version = struct.unpack_from("<I", data, 4)[0]
    order = ["vista", "7", "8"] if version == 20 else ["7", "vista", "8"] if version == 21 else ["8", "7", "vista"]
    pos = 24
    seen = 0
    while pos + 48 <= size and seen < _LIMIT:
        at = 0 if bytes(data[pos:pos + 4]) == b"CMMM" else bytes(data[pos:pos + (1 << 20) + 3]).find(b"CMMM")
        if at < 0:
            pos += 1 << 20
            continue
        pos += at
        if pos + 48 > size:
            break
        seen += 1
        entry_size = struct.unpack_from("<I", data, pos + 4)[0]
        got = None
        for name in order:
            hsize, ids, pads, dsz, wh = _TC_LAYOUTS[name]
            if pos + hsize > size:
                continue
            id_len, pad, n = (struct.unpack_from("<I", data, pos + o)[0] for o in (ids, pads, dsz))
            start = pos + hsize + id_len + pad
            if id_len > 4096 or id_len & 1 or pad > 1 << 20 or start + n > size:
                continue
            if n == 0 or _picture(bytes(data[start:start + min(n, 32)])) is not None:
                got = (name, hsize, id_len, start, n, wh)
                break
        if got is None:
            pos += 4
            continue
        name, hsize, id_len, start, n, wh = got
        order.remove(name)
        order.insert(0, name)                   # the next entries most likely have the same layout
        if n:
            blob = bytes(data[start:start + n])
            ident = bytes(data[pos + hsize:pos + hsize + id_len]).decode("utf-16-le", "replace").strip("\x00")
            ext, w, h = _picture(blob)
            if wh >= 0:
                w = w or struct.unpack_from("<I", data, pos + wh)[0]
                h = h or struct.unpack_from("<I", data, pos + wh + 4)[0]
            entry_hash = struct.unpack_from("<Q", data, pos + 8)[0]
            out.append(Thumbnail(ident or f"{entry_hash:016x}", None, blob, ext, w, h, None,
                                 f"entry {entry_hash:016x} at byte {pos}"))
        pos = max(start + n, pos + (entry_size if hsize <= entry_size < 1 << 26 else 4))


# ---------------------------------------------------------------------- OLE compound files (Thumbs.db)
class _Cfb:
    """Just enough of an OLE compound file to read its streams, tolerant of damage: chains that loop, run
    out of the file or point nowhere end there."""

    def __init__(self, data):
        self.data = data
        h = bytes(data[:512])
        if len(h) < 512 or h[:8] != _OLE:
            raise ValueError("not a compound file")
        self.ss = 1 << struct.unpack_from("<H", h, 30)[0]
        self.mss = 1 << struct.unpack_from("<H", h, 32)[0]
        if self.ss not in (512, 4096) or self.mss > self.ss:
            raise ValueError("odd sector sizes")
        nfat, dir_start = struct.unpack_from("<II", h, 44)
        self.cutoff, minifat_start, nminifat, difat, ndifat = struct.unpack_from("<IIIII", h, 56)
        fat_secs = [s for s in struct.unpack_from("<109I", h, 76)[:min(nfat, 109)] if s < 0xFFFFFFFA]
        per = self.ss // 4
        seen = set()
        while difat < 0xFFFFFFFA and len(fat_secs) < nfat and difat not in seen and len(seen) <= ndifat:
            seen.add(difat)
            blk = self.sector(difat)
            if len(blk) < self.ss:
                break
            vals = struct.unpack(f"<{per}I", blk)
            fat_secs += [s for s in vals[:-1] if s < 0xFFFFFFFA]
            difat = vals[-1]
        self.fat: list[int] = []
        for s in fat_secs[:nfat]:
            blk = self.sector(s).ljust(self.ss, b"\xff")
            self.fat.extend(struct.unpack(f"<{per}I", blk))
        self.minifat: list[int] = []
        for s in self.chain(minifat_start, self.fat)[:max(nminifat, 0) or 1 << 16]:
            blk = self.sector(s).ljust(self.ss, b"\xff")
            self.minifat.extend(struct.unpack(f"<{per}I", blk))
        self.entries = self._directory(dir_start)
        root = next((e for e in self.entries if e[1] == 5), None)
        self.ministream = self._read_chain(root[2], root[3], self.fat, self.ss) if root else b""

    def sector(self, n: int) -> bytes:
        off = (n + 1) * self.ss
        return bytes(self.data[off:off + self.ss])

    def chain(self, start: int, table: list[int], limit: int = 1 << 20) -> list[int]:
        out, seen, s = [], set(), start
        while s < 0xFFFFFFFA and s < len(table) and s not in seen and len(out) < limit:
            seen.add(s)
            out.append(s)
            s = table[s]
        return out

    def _read_chain(self, start: int, size: int, table: list[int], unit: int) -> bytes:
        parts = []
        for s in self.chain(start, table, size // unit + 2):
            if table is self.fat:
                parts.append(self.sector(s))
            else:
                parts.append(self.ministream[s * unit:(s + 1) * unit])
        return b"".join(parts)[:size]

    def _directory(self, start: int) -> list[tuple[str, int, int, int]]:
        out = []
        for s in self.chain(start, self.fat, 1 << 16):
            blk = self.sector(s)
            for i in range(0, len(blk) - 127, 128):
                e = blk[i:i + 128]
                nlen, typ = struct.unpack_from("<HB", e, 64)
                if typ not in (1, 2, 5) or not 2 <= nlen <= 64:
                    continue
                name = e[:nlen - 2].decode("utf-16-le", "replace")
                first, size = struct.unpack_from("<IQ", e, 116)
                if self.ss == 512:
                    size &= 0xFFFFFFFF
                out.append((name, typ, first, size))
        return out

    def stream(self, name: str) -> bytes | None:
        for n, typ, first, size in self.entries:
            if typ == 2 and n == name:
                if size < self.cutoff:
                    return self._read_chain(first, size, self.minifat, self.mss)
                return self._read_chain(first, size, self.fat, self.ss)
        return None


def _thumbsdb(data, out: list[Thumbnail]) -> None:
    cfb = _Cfb(data)
    names: dict[int, tuple[str, float | None]] = {}
    cat = cfb.stream("Catalog") or b""
    if len(cat) >= 16:
        hsize, _ver, count = struct.unpack_from("<HHI", cat, 0)
        pos = hsize if 8 <= hsize <= 64 else 16
        while pos + 16 <= len(cat) and len(names) < min(count or _LIMIT, _LIMIT):
            rsize, index, ft = struct.unpack_from("<IIQ", cat, pos)
            if rsize < 18 or pos + rsize > len(cat):
                break
            raw = cat[pos + 16:pos + rsize]
            end = next((i for i in range(0, len(raw) - 1, 2) if raw[i:i + 2] == b"\x00\x00"), len(raw) & ~1)
            name = raw[:end].decode("utf-16-le", "replace")
            mtime = ft / 1e7 - _FILETIME_EPOCH if ft else None
            names[index] = (name, mtime if mtime and mtime > 0 else None)
            pos += rsize
    done = set()
    for sname, typ, _first, _size in cfb.entries:
        if typ != 2 or not sname.isdigit():
            continue
        index = int(sname[::-1])
        if index in done:
            continue
        blob = cfb.stream(sname) or b""
        m = _SOI.search(blob, 0, 128) or re.search(rb"\xff[\xdb\xc0\xc4\xe0]", blob[:128])
        if m is None:
            continue
        jpeg = _fix_jpeg(blob[m.start():])
        end = _jpeg_end(jpeg, 0, len(jpeg))
        jpeg = jpeg[:end] if end > 0 else jpeg
        pic = _picture(jpeg)
        if pic is None:
            continue
        done.add(index)
        name, mtime = names.get(index, (f"thumbnail {index}", None))
        base = name.replace("\\", "/").rsplit("/", 1)[-1] or f"thumbnail {index}"
        stem = base.rsplit(".", 1)[0] if "." in base else base
        out.append(Thumbnail(stem, name if index in names else None, jpeg, "jpg", pic[1], pic[2], mtime,
                             f"stream {sname}"))


# ---------------------------------------------------------------------- Android
def _thumbdata(data, out: list[Thumbnail]) -> None:
    size = len(data)
    pos = 0
    k = 0
    while k < _LIMIT:
        m = _SOI.search(data, pos)
        if m is None:
            break
        at = m.start()
        end = _jpeg_end(data, at, size)
        if end < 0:
            pos = at + 4
            continue
        blob = bytes(data[at:end])
        pic = _picture(blob)
        k += 1
        out.append(Thumbnail(f"thumbdata {k:05d}", None, blob, "jpg", pic[1] if pic else 0, pic[2] if pic else 0,
                             None, f"at byte {at}"))
        pos = end


def _single(data, out: list[Thumbnail]) -> None:
    blob = bytes(data)
    pic = _picture(blob)
    if pic:
        out.append(Thumbnail("thumbnail", None, blob, pic[0], pic[1], pic[2], None, "the file itself"))


# ---------------------------------------------------------------------- freedesktop.org (Linux desktops)
def png_text(data) -> dict[str, str]:
    """The text chunks (tEXt, zTXt, iTXt) of a PNG file: {keyword: text}."""
    out: dict[str, str] = {}
    pos = 8
    size = len(data)
    for _ in range(10000):
        if pos + 8 > size:
            break
        n, typ = struct.unpack_from(">I4s", data, pos)
        if n > size - pos - 12 or typ == b"IEND":
            break
        if typ in (b"tEXt", b"zTXt", b"iTXt"):
            body = bytes(data[pos + 8:pos + 8 + n])
            key, _, rest = body.partition(b"\x00")
            try:
                if typ == b"tEXt":
                    text = rest.decode("latin-1")
                elif typ == b"zTXt":
                    text = zlib.decompress(rest[1:]).decode("latin-1")
                else:
                    flag, _method = rest[0], rest[1]
                    _lang, _, rest = rest[2:].partition(b"\x00")
                    _tkey, _, rest = rest.partition(b"\x00")
                    text = (zlib.decompress(rest) if flag else rest).decode("utf-8", "replace")
                out[key.decode("latin-1")] = text
            except (zlib.error, IndexError):
                pass
        pos += 12 + n
    return out


def _freedesktop(data, out: list[Thumbnail]) -> None:
    blob = bytes(data)
    pic = _picture(blob)
    if pic is None or pic[0] != "png" or pic[1] <= 1 and pic[2] <= 1:
        return                                  # not a PNG, or the 1×1 marker of a failed thumbnail
    text = png_text(blob)
    uri = text.get("Thumb::URI", "")
    path = None
    if uri:
        parsed = urllib.parse.urlparse(uri)
        path = urllib.parse.unquote(parsed.path) if parsed.scheme in ("file", "") else uri
    mtime = None
    try:
        mtime = float(text["Thumb::MTime"]) if "Thumb::MTime" in text else None
    except ValueError:
        pass
    base = (path or "").rstrip("/").rsplit("/", 1)[-1]
    stem = base.rsplit(".", 1)[0] if "." in base else base
    out.append(Thumbnail(stem or "thumbnail", path, blob, "png", pic[1], pic[2], mtime, "Thumb::URI" if uri else ""))


# ---------------------------------------------------------------------- macOS QuickLook
def _sqlite(data) -> sqlite3.Connection:
    """An in-memory copy of the SQLite database in DATA."""
    blob = bytes(data)
    con = sqlite3.connect(":memory:")
    if hasattr(con, "deserialize"):
        con.deserialize(blob)
        return con
    con.close()
    with tempfile.TemporaryDirectory() as tmp:            # Python 3.10: through a file
        p = os.path.join(tmp, "index.sqlite")
        with open(p, "wb") as f:
            f.write(blob)
        disk = sqlite3.connect(p)
        con = sqlite3.connect(":memory:")
        disk.backup(con)
        disk.close()
    return con


def _plist_date(blob) -> float | None:
    if not blob:
        return None
    try:
        v = plistlib.loads(bytes(blob))
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError, KeyError, IndexError):
        return None
    d = v.get("date") if isinstance(v, dict) else None
    if isinstance(d, (int, float)):
        return float(d) + _MAC_EPOCH
    if hasattr(d, "timestamp"):
        try:
            import calendar
            return float(calendar.timegm(d.utctimetuple()))
        except (ValueError, OverflowError):
            return None
    return None


def _quicklook(index, pictures, out: list[Thumbnail]) -> None:
    con = _sqlite(index)
    try:
        files = {}
        for rowid, folder, name, version in con.execute("SELECT rowid, folder, file_name, version FROM files"):
            files[rowid] = (folder or "", name or "", _plist_date(version))
        rows = con.execute("SELECT file_id, width, height, bitspercomponent, bitsperpixel, bytesperrow, "
                           "bitmapdata_location, bitmapdata_length FROM thumbnails ORDER BY rowid").fetchall()
    finally:
        con.close()
    size = len(pictures)
    for file_id, w, h, bpc, bpp, bpr, loc, length in rows[:_LIMIT]:
        if not (isinstance(w, int) and isinstance(h, int) and 0 < w <= 4096 and 0 < h <= 4096):
            continue
        bpr = bpr or w * 4
        if (bpc or 8) != 8 or (bpp or 32) != 32 or bpr < w * 4 or not isinstance(loc, int) or loc < 0:
            continue
        need = bpr * (h - 1) + w * 4
        if loc + need > size or (length and length < need):
            continue
        raw = bytes(pictures[loc:loc + bpr * h])
        rows_px = [raw[y * bpr:y * bpr + w * 4] for y in range(h)]
        folder, name, mtime = files.get(file_id, ("", "", None))
        path = (folder.rstrip("/") + "/" + name) if name else None
        stem = name.rsplit(".", 1)[0] if "." in name else name
        out.append(Thumbnail(stem or f"thumbnail {file_id}", path, png(w, h, rows_px), "png", w, h, mtime,
                             f"bitmap at byte {loc}"))
