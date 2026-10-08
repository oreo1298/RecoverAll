"""Parsing helpers shared by the format modules of the signature engine.

* TIFF and EXIF (photos, camera RAW files, the EXIF block inside JPEG/PNG/WebP/HEIC): :func:`parse_tiff`,
  :func:`parse_exif`, :func:`read_ifd`, :func:`photo_meta`.
* ISO base media boxes (MP4, MOV, 3GP, M4A, HEIC, AVIF, CR3, JPEG 2000 and JPEG XL containers):
  :func:`box_header`, :func:`iter_boxes`, :func:`bmff_walk`, :func:`bmff_kind`.
* RIFF and IFF chunks (WAV, AVI, WebP, AIFF): :func:`iter_chunks`.
* EBML (Matroska, WebM): :func:`ebml_id`, :func:`ebml_size`, :func:`iter_ebml`.
* ASF (WMV, WMA): :func:`parse_asf`.
* The tags music files carry: :func:`id3v2_info`, :func:`skip_tags`, :func:`vorbis_comments`.
* Dates and names: :func:`exif_time`, :func:`time_name`, :func:`plausible_time`, :func:`clean_name`,
  :func:`camera_name`, :func:`music_name`.
* :func:`memo`: share one parse between the formats whose signatures matched the same block.

Everything reads through a :class:`~.base.Reader` (or a :class:`BytesReader` over bytes already in memory),
never trusts a number it reads, and answers None instead of raising on damaged data. Other format modules
import these functions: their names, arguments and results are kept stable.
"""

from __future__ import annotations

import calendar
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Iterator

# Seconds between 1904-01-01 (QuickTime, AIFF, HFS) and 1970-01-01.
MAC_EPOCH = 2082844800
# Seconds between 2001-01-01 (Matroska DateUTC) and 1970-01-01.
MKV_EPOCH = 978307200


class BytesReader:
    """The :class:`~.base.Reader` interface over bytes already in memory (an EXIF block inside a JPEG
    segment, a box payload): helpers accept either."""

    def __init__(self, data: bytes, start: int = 0):
        self.data = data
        self.start = start
        self.limit = len(data)

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0 or offset >= self.limit:
            return b""
        return self.data[offset:offset + length]

    def find(self, pattern: bytes, start: int = 0, end: int | None = None) -> int:
        return self.data.find(pattern, start, self.limit if end is None else end)


def memo(r, key: str, fn: Callable):
    """``fn(r)``, computed once per candidate. The engine hands every format whose signature matched the
    same block the same Reader, so formats that share a structure (the TIFF-based RAW files, the ISO media
    family) parse it once."""
    cache = r.__dict__.setdefault("_memo", {})
    if key not in cache:
        cache[key] = fn(r)
    return cache[key]


# ---------------------------------------------------------------------- dates and names
def exif_time(text) -> float | None:
    """An EXIF/TIFF date ("2023:07:14 18:22:05", also with "-" and "T") → Unix time. Cameras store local
    time without a zone: it is taken as UTC, which keeps the clock reading the photographer saw."""
    if isinstance(text, bytes):
        text = text.split(b"\0", 1)[0].decode("ascii", "replace")
    if not text or len(text) < 19:
        return None
    t = text.strip()
    try:
        y, mo, d = int(t[0:4]), int(t[5:7]), int(t[8:10])
        h, mi, s = int(t[11:13]), int(t[14:16]), int(t[17:19])
    except ValueError:
        return None
    if not (1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 61 and y >= 1900):
        return None
    try:
        value = float(calendar.timegm((y, mo, d, h, mi, min(s, 59), 0, 0, 0)))
    except (ValueError, OverflowError):
        return None
    return value if plausible_time(value) else None


def plausible_time(t: float | None) -> bool:
    """A date a file could really carry: after 1980 and not more than a year in the future (cameras with
    an unset clock write 0000:00:00 or 1904/1970 dates)."""
    return t is not None and 315532800 <= t <= time.time() + 366 * 86400


def time_name(t: float) -> str:
    """The name recovered photos and videos get: "2023-07-14 18.22.05" (sorts by date, no colons)."""
    return time.strftime("%Y-%m-%d %H.%M.%S", time.gmtime(t))


def clean_name(text, limit: int = 100) -> str | None:
    """A title or artist turned into something usable in a file name (None if nothing is left)."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    if not text:
        return None
    out = "".join(" " if (ord(c) < 32 or c in '/\\:*?"<>|') else c for c in text)
    out = " ".join(out.split()).strip(" .")
    return out[:limit].rstrip(" .") or None


def camera_name(make: str | None, model: str | None) -> str | None:
    """"Canon" + "Canon EOS 5D" → "Canon EOS 5D"; "NIKON CORPORATION" + "D750" → "NIKON D750"."""
    make = " ".join((make or "").split())
    model = " ".join((model or "").split())
    if not make and not model:
        return None
    if not model:
        return make
    first = make.split(" ")[0] if make else ""
    if not first or model.lower().startswith(first.lower()):
        return model
    return f"{first} {model}"


# ---------------------------------------------------------------------- TIFF / EXIF
# bytes per value of each TIFF field type (16-18: BigTIFF's 64-bit integers and IFD offsets)
TIFF_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4,
                  16: 8, 17: 8, 18: 8}
_TIFF_INT_FMT = {1: "B", 3: "H", 4: "I", 6: "b", 8: "h", 9: "i", 13: "I", 16: "Q", 17: "q", 18: "Q"}

# tags whose values parse_tiff decodes (everything else only counts towards the file's extent)
T_WIDTH, T_HEIGHT, T_COMPRESSION, T_PHOTOMETRIC = 0x100, 0x101, 0x103, 0x106
T_MAKE, T_MODEL, T_STRIPS, T_STRIP_COUNTS, T_DATETIME = 0x10F, 0x110, 0x111, 0x117, 0x132
T_TILES, T_TILE_COUNTS, T_SUBIFDS = 0x144, 0x145, 0x14A
T_JPEG_OFFSET, T_JPEG_LENGTH = 0x201, 0x202
T_EXIF_IFD, T_GPS_IFD, T_INTEROP_IFD = 0x8769, 0x8825, 0xA005
T_DATETIME_ORIGINAL, T_PIXEL_X, T_PIXEL_Y = 0x9003, 0xA002, 0xA003
T_DNG_VERSION, T_DNG_PRIVATE = 0xC612, 0xC634
T_SR2_OFFSET, T_SR2_LENGTH = 0x7200, 0x7201
T_RW2_RAW_OFFSET = 0x118
_WANTED = {T_WIDTH, T_HEIGHT, T_COMPRESSION, T_PHOTOMETRIC, T_MAKE, T_MODEL, T_STRIPS, T_STRIP_COUNTS,
           T_DATETIME, T_TILES, T_TILE_COUNTS, T_SUBIFDS, T_JPEG_OFFSET, T_JPEG_LENGTH, T_EXIF_IFD, T_GPS_IFD,
           T_INTEROP_IFD, T_DATETIME_ORIGINAL, T_PIXEL_X, T_PIXEL_Y, T_DNG_VERSION, T_DNG_PRIVATE, T_SR2_OFFSET,
           T_SR2_LENGTH, T_RW2_RAW_OFFSET, 0x0002, 0x0003}
# (offset tag, length tag) pairs that point at image data
_DATA_PAIRS = ((T_STRIPS, T_STRIP_COUNTS), (T_TILES, T_TILE_COUNTS), (T_JPEG_OFFSET, T_JPEG_LENGTH),
               (T_SR2_OFFSET, T_SR2_LENGTH))
# compression / photometric values only camera RAW data uses
RAW_COMPRESSIONS = {32767, 32769, 32770, 32772, 34713, 65000, 65535, 34316}
RAW_PHOTOMETRICS = {32803, 34892}


@dataclass
class IfdEntry:
    tag: int
    type: int
    count: int
    offset: int          # where the value is (inline values: inside the entry itself)
    size: int            # count * size of the type
    inline: bool


def read_ifd(r, offset: int, order: str, big: bool = False, max_entries: int = 4096
             ) -> tuple[list[IfdEntry], int, int] | None:
    """The entries of the IFD at OFFSET, the offset of the next IFD and the IFD's end, or None when it
    isn't a plausible IFD (bad count, unknown field types)."""
    if big:
        head = r.read(offset, 8)
        if len(head) < 8:
            return None
        n = struct.unpack(order + "Q", head)[0]
        esize, first, ptr = 20, offset + 8, 8
    else:
        head = r.read(offset, 2)
        if len(head) < 2:
            return None
        n = struct.unpack(order + "H", head)[0]
        esize, first, ptr = 12, offset + 2, 4
    if n == 0 or n > max_entries:
        return None
    raw = r.read(first, n * esize + ptr)
    if len(raw) < n * esize:
        return None
    entries: list[IfdEntry] = []
    bad = 0
    for i in range(n):
        p = i * esize
        if big:
            tag, typ, count = struct.unpack_from(order + "HHQ", raw, p)
            vpos = p + 12
            room = 8
        else:
            tag, typ, count = struct.unpack_from(order + "HHI", raw, p)
            vpos = p + 8
            room = 4
        tsize = TIFF_TYPE_SIZE.get(typ)
        if tsize is None or (not big and typ > 13):
            bad += 1
            continue
        size = tsize * count
        if size <= room:
            entries.append(IfdEntry(tag, typ, count, first + vpos, size, True))
        else:
            voff = struct.unpack_from(order + ("Q" if big else "I"), raw, vpos)[0]
            entries.append(IfdEntry(tag, typ, count, voff, size, False))
    if bad * 4 > n or not entries:      # mostly garbage: not an IFD
        return None
    nxt = 0
    if len(raw) >= n * esize + ptr:
        nxt = struct.unpack_from(order + ("Q" if big else "I"), raw, n * esize)[0]
    return entries, nxt, first + n * esize + ptr


def ifd_value(r, e: IfdEntry, order: str, max_count: int = 1 << 20):
    """The value of an entry: a tuple of ints, a str (ASCII), or bytes (UNDEFINED); None if unreadable."""
    if e.count > max_count:
        return None
    data = r.read(e.offset, e.size)
    if len(data) < e.size:
        return None
    if e.type == 2:
        return data.split(b"\0", 1)[0].decode("latin-1").strip()
    fmt = _TIFF_INT_FMT.get(e.type)
    if fmt:
        return struct.unpack(f"{order}{e.count}{fmt}", data)
    if e.type in (5, 10):
        vals = struct.unpack(f"{order}{e.count * 2}{'I' if e.type == 5 else 'i'}", data)
        return tuple(vals[i] / vals[i + 1] if vals[i + 1] else 0.0 for i in range(0, len(vals), 2))
    return data


@dataclass
class TiffInfo:
    """What :func:`parse_tiff` learnt. ``end`` is where the last structure or image data ends (the file's
    length when it is a stand-alone TIFF or RAW file)."""

    order: str                                  # "<" (II) or ">" (MM)
    magic: int                                  # 42, 43 (BigTIFF), 0x4F52/0x5352 (Olympus), 0x55 (Panasonic)
    header: bytes                               # the first 16 bytes ("CR" at 8 marks a Canon CR2)
    end: int
    ifds: list[dict] = field(default_factory=list)   # decoded wanted tags of every IFD walked
    make: str | None = None
    model: str | None = None
    date: float | None = None                   # DateTimeOriginal, else DateTime
    date_original: bool = False
    width: int = 0                              # of the largest image
    height: int = 0
    dng: bool = False
    raw: bool = False                           # some IFD holds sensor data (CFA / linear raw / RAW compression)
    open_end: bool = False                      # image data whose length isn't recorded (Panasonic)
    damaged: bool = False                       # pointers outside the medium or unreadable IFDs

    @property
    def camera(self) -> str | None:
        return camera_name(self.make, self.model)


_TIFF_MAGICS = {42, 43, 0x4F52, 0x5352, 0x55}


def parse_tiff(r, max_ifds: int = 96, max_end: int = 1 << 40) -> TiffInfo | None:
    """Walk a TIFF structure that starts at offset 0 of R: IFD0 and its chain, sub-IFDs, the EXIF, GPS and
    interoperability IFDs and Sony's SR2 private IFD, accounting for every value and image strip or tile.
    None when the header or IFD0 isn't valid."""
    head = r.read(0, 16)
    if len(head) < 8:
        return None
    if head[:2] == b"II":
        order = "<"
    elif head[:2] == b"MM":
        order = ">"
    else:
        return None
    magic = struct.unpack_from(order + "H", head, 2)[0]
    if magic not in _TIFF_MAGICS:
        return None
    big = magic == 43
    if big:
        if len(head) < 16 or struct.unpack_from(order + "HH", head, 4) != (8, 0):
            return None
        ifd0 = struct.unpack_from(order + "Q", head, 8)[0]
        end = 16
    else:
        ifd0 = struct.unpack_from(order + "I", head, 4)[0]
        end = 8
    limit = r.limit
    if ifd0 < 8 or ifd0 >= limit:
        return None
    info = TiffInfo(order, magic, head, end)
    queue: list[tuple[int, str]] = [(ifd0, "ifd0")]
    seen: set[int] = set()
    best_area = 0
    while queue and len(seen) < max_ifds:
        off, kind = queue.pop(0)
        if off in seen or off < 8 or off >= limit:
            if off >= limit and kind != "next":
                info.damaged = True
            continue
        seen.add(off)
        got = read_ifd(r, off, order, big)
        if got is None:
            if kind == "ifd0":
                return None
            info.damaged = True
            continue
        entries, nxt, ifd_end = got
        if kind == "ifd0" and not _plausible_ifd0(entries):
            return None
        info.end = max(info.end, ifd_end)
        tags: dict = {"_kind": kind}
        for e in entries:
            if not e.inline:
                if e.offset < 8 or e.offset + e.size > max_end:
                    info.damaged = True
                    continue
                if e.offset + e.size > limit:
                    info.damaged = True
                info.end = max(info.end, e.offset + e.size)
            if e.tag in _WANTED:
                v = ifd_value(r, e, order)
                if v is not None:
                    tags[e.tag] = v
        info.ifds.append(tags)
        # image data
        for otag, ltag in _DATA_PAIRS:
            offs, lens = tags.get(otag), tags.get(ltag)
            if not isinstance(offs, tuple):
                continue
            if not isinstance(lens, tuple) or not any(lens):
                if otag == T_STRIPS and offs:
                    info.open_end = True        # strips without byte counts (Panasonic): length unknown
                    info.end = max(info.end, max(offs))
                continue
            for o, n in zip(offs, lens):
                if n and o >= 8:
                    if o + n > max_end:
                        info.damaged = True
                        continue
                    if o + n > limit:
                        info.damaged = True
                    info.end = max(info.end, o + n)
        raw_off = tags.get(T_RW2_RAW_OFFSET)
        counts = tags.get(T_STRIP_COUNTS)
        if isinstance(raw_off, tuple) and raw_off and info.magic == 0x55 and not (isinstance(counts, tuple)
                                                                                  and any(counts)):
            info.open_end = True                # Panasonic: where the sensor data starts, not how long it is
            info.end = max(info.end, raw_off[0])
        # what it says about the picture
        w, h = _first(tags.get(T_WIDTH)), _first(tags.get(T_HEIGHT))
        if kind == "exif":
            w, h = _first(tags.get(T_PIXEL_X)) or w, _first(tags.get(T_PIXEL_Y)) or h
        if info.magic == 0x55 and kind == "ifd0":
            w, h = w or _first(tags.get(0x0002)), h or _first(tags.get(0x0003))
        if w and h and w * h > best_area and w < 1 << 20 and h < 1 << 20:
            best_area, info.width, info.height = w * h, w, h
        if _first(tags.get(T_COMPRESSION)) in RAW_COMPRESSIONS or _first(tags.get(T_PHOTOMETRIC)) in RAW_PHOTOMETRICS:
            info.raw = True
        if T_DNG_VERSION in tags:
            info.dng = True
        if isinstance(tags.get(T_MAKE), str) and not info.make:
            info.make = tags[T_MAKE]
        if isinstance(tags.get(T_MODEL), str) and not info.model:
            info.model = tags[T_MODEL]
        if isinstance(tags.get(T_DATETIME_ORIGINAL), str):
            t = exif_time(tags[T_DATETIME_ORIGINAL])
            if t is not None:
                info.date, info.date_original = t, True
        if isinstance(tags.get(T_DATETIME), str) and info.date is None:
            info.date = exif_time(tags[T_DATETIME])
        # where to go next
        for tag, sub in ((T_SUBIFDS, "sub"), (T_EXIF_IFD, "exif"), (T_GPS_IFD, "gps"), (T_INTEROP_IFD, "interop")):
            v = tags.get(tag)
            if isinstance(v, tuple):
                queue.extend((int(x), sub) for x in v[:32])
        v = tags.get(T_DNG_PRIVATE)
        if isinstance(v, tuple) and len(v) == 1 and (info.make or "").upper().startswith("SONY"):
            queue.append((int(v[0]), "sr2"))
        if nxt and kind in ("ifd0", "next", "sub"):
            queue.append((nxt, "next" if kind != "sub" else "sub"))
    return info


def _first(v) -> int:
    if isinstance(v, tuple) and v and isinstance(v[0], int):
        return v[0]
    return 0


def _plausible_ifd0(entries: list[IfdEntry]) -> bool:
    """IFD0 of a real TIFF has a few well-known tags; random bytes that happen to start with II*\\0 don't."""
    tags = {e.tag for e in entries}
    known = tags & {T_WIDTH, T_HEIGHT, T_COMPRESSION, T_PHOTOMETRIC, T_MAKE, T_MODEL, T_STRIPS, 0x112, 0x11A,
                    0x11B, 0x128, T_DATETIME, T_SUBIFDS, T_EXIF_IFD, T_DNG_VERSION, 0xFE, 0x102, 0x115, 0x116,
                    T_STRIP_COUNTS, T_TILES, 0x0002, 0x0003, T_RW2_RAW_OFFSET, 0x0001, 0x0017, 0x2E}
    return len(known) >= 2 or (len(entries) == 1 and bool(known))


def parse_exif(data: bytes) -> TiffInfo | None:
    """The EXIF block of a JPEG APP1 segment ("Exif\\0\\0" + TIFF), a PNG eXIf chunk or a HEIC Exif item
    (bare TIFF)."""
    if data[:6] == b"Exif\0\0":
        data = data[6:]
    elif data[:4] == b"Exif":
        data = data[4:]
    if data[:2] not in (b"II", b"MM"):
        return None
    return parse_tiff(BytesReader(data))


def photo_meta(t: TiffInfo | None, width: int = 0, height: int = 0) -> tuple[str | None, float | None, dict]:
    """(name, mtime, info) for a photo: named after the moment it was taken when the camera recorded it."""
    info: dict = {}
    name = mtime = None
    if t is not None:
        cam = t.camera
        if cam:
            info["camera"] = cam
        if t.date is not None:
            mtime = t.date
            if t.date_original:
                name = time_name(t.date)
            info["taken"] = time_name(t.date)
        width, height = width or t.width, height or t.height
    if width and height:
        info["width"], info["height"] = width, height
    return name, mtime, info


# ---------------------------------------------------------------------- ISO base media (MP4, MOV, HEIC...)
@dataclass
class Box:
    type: bytes
    offset: int                 # of the box header
    header: int                 # header size (8, or 16 with a 64-bit size)
    size: int | None            # whole box; None: it runs to the end of the medium (size 0)

    @property
    def data(self) -> int:
        return self.offset + self.header

    @property
    def end(self) -> int | None:
        return None if self.size is None else self.offset + self.size


def box_header(r, offset: int) -> Box | None:
    """The box at OFFSET, or None if its header is unreadable or impossible."""
    h = r.read(offset, 16)
    if len(h) < 8:
        return None
    size, typ = struct.unpack_from(">I4s", h)
    if size == 1:
        if len(h) < 16:
            return None
        size = struct.unpack_from(">Q", h, 8)[0]
        if size < 16:
            return None
        return Box(typ, offset, 16, size)
    if size == 0:
        return Box(typ, offset, 8, None)
    if size < 8:
        return None
    return Box(typ, offset, 8, size)


def _is_fourcc(t: bytes) -> bool:
    return len(t) == 4 and all(32 <= c < 127 or c == 0xA9 for c in t)


def iter_boxes(r, start: int, end: int, max_boxes: int = 10000) -> Iterator[Box]:
    """The child boxes in [start, end) (stops at the first impossible header)."""
    pos = start
    n = 0
    while pos + 8 <= end and n < max_boxes:
        b = box_header(r, pos)
        if b is None or not _is_fourcc(b.type):
            return
        if b.size is None:
            b.size = end - pos
        if pos + b.size > end:
            return
        yield b
        pos += b.size
        n += 1


# Boxes that may appear at the top level of an ISO media / QuickTime file.
BMFF_TOP = frozenset({b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"pnot", b"uuid", b"moof", b"mfra",
                      b"meta", b"styp", b"sidx", b"ssix", b"prft", b"pdin", b"emsg", b"junk", b"PICT"})
_ONCE = frozenset({b"ftyp", b"moov", b"meta", b"mfra", b"pnot"})


@dataclass
class BmffInfo:
    boxes: list[Box]
    end: int | None             # None: the last box runs to the end of the medium
    brand: bytes = b""
    compat: tuple[bytes, ...] = ()
    truncated: bool = False     # the last box goes past the end of the medium

    def first(self, typ: bytes) -> Box | None:
        for b in self.boxes:
            if b.type == typ:
                return b
        return None

    def has(self, typ: bytes) -> bool:
        return self.first(typ) is not None


def bmff_walk(r, known: frozenset = BMFF_TOP, max_boxes: int = 1_000_000, ftyp_at: int = 0) -> BmffInfo | None:
    """The top-level boxes of an ISO media file starting at offset 0 of R. The walk stops at the first box
    that isn't a known top-level type (where the next file or old data begins), at a second ftyp/moov
    (another file), or at a box that runs to the end. FTYP_AT is the only place an ftyp box may be (JPEG
    2000 and JPEG XL put a signature box first). None if the first box isn't valid."""
    boxes: list[Box] = []
    seen: set[bytes] = set()
    pos = 0
    end: int | None = 0
    truncated = False
    while len(boxes) < max_boxes:
        b = box_header(r, pos)
        if b is None or b.type not in known:
            break
        if b.type in _ONCE and b.type in seen:
            break
        if b.type == b"ftyp" and len(boxes) != ftyp_at:
            break
        seen.add(b.type)
        boxes.append(b)
        if b.size is None:
            end = None
            break
        pos += b.size
        end = pos
        if pos > r.limit:
            truncated = True
            break
    if not boxes:
        return None
    info = BmffInfo(boxes, end, truncated=truncated)
    ft = boxes[ftyp_at] if len(boxes) > ftyp_at else boxes[0]
    if ft.type in (b"ftyp", b"styp"):
        if not ft.size or not 16 <= ft.size <= 4096:
            return None
        data = r.read(ft.data, ft.size - ft.header)
        info.brand = data[:4]
        info.compat = tuple(data[i:i + 4] for i in range(8, len(data) - 3, 4))
        if not _is_fourcc(info.brand):
            return None
    return info


_AUDIO_BRANDS = {b"M4A ", b"M4B ", b"M4P ", b"F4A ", b"F4B "}
_HEIC_BRANDS = {b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"hevm", b"hevs"}
_AVIF_BRANDS = {b"avif", b"avis"}
_HEIF_BRANDS = {b"mif1", b"msf1", b"mif2"}


def bmff_kind(brand: bytes, compat: tuple[bytes, ...] = ()) -> tuple[str, str]:
    """(category, extension) an ISO media file's brands point to: ("photo", "heic"), ("audio", "m4a"),
    ("video", "mov"), ... Files without an ftyp box are QuickTime movies."""
    if not brand:
        return "video", "mov"
    if brand == b"crx ":
        return "photo", "cr3"
    if brand in _AVIF_BRANDS:
        return "photo", "avif"
    if brand in _HEIC_BRANDS:
        return "photo", "heic"
    if brand in _HEIF_BRANDS:
        if any(c in _HEIC_BRANDS for c in compat):
            return "photo", "heic"
        if any(c in _AVIF_BRANDS for c in compat):
            return "photo", "avif"
        return "photo", "heif"
    if brand in _AUDIO_BRANDS:
        return "audio", "m4b" if brand == b"M4B " else "m4a"
    if brand == b"qt  ":
        return "video", "mov"
    if brand.startswith(b"3g2"):
        return "video", "3g2"
    if brand.startswith((b"3gp", b"3ge", b"3gg", b"3gs")):
        return "video", "3gp"
    if brand.startswith(b"M4V"):
        return "video", "m4v"
    if brand in (b"F4V ", b"F4P "):
        return "video", "f4v"
    return "video", "mp4"


def moov_info(r, moov: Box) -> dict:
    """What a movie box says: {"ctime" (Unix time or None), "duration" (s), "width", "height", "video",
    "audio" (it has such tracks), "tags" (iTunes-style title/artist/album)}."""
    out: dict = {"ctime": None, "duration": None, "width": 0, "height": 0, "video": False, "audio": False,
                 "tags": {}}
    if moov.size is None or moov.size > 256 * 1024 * 1024:
        return out
    for c in iter_boxes(r, moov.data, moov.end):
        if c.type == b"mvhd":
            d = r.read(c.data, 32)
            if len(d) >= 20 and d[0] == 0:
                ct, _mt, scale, dur = struct.unpack_from(">IIII", d, 4)
            elif len(d) >= 32 and d[0] == 1:
                ct, _mt, scale, dur = struct.unpack_from(">QQIQ", d, 4)
            else:
                continue
            if ct > MAC_EPOCH and plausible_time(ct - MAC_EPOCH):
                out["ctime"] = float(ct - MAC_EPOCH)
            if scale:
                out["duration"] = dur / scale
        elif c.type == b"trak":
            for t in iter_boxes(r, c.data, c.end):
                if t.type == b"tkhd" and t.size in (92, 104):
                    d = r.read(t.end - 8, 8)
                    if len(d) < 8:
                        continue
                    w, h = struct.unpack(">II", d)
                    if (w >> 16) * (h >> 16) > out["width"] * out["height"]:
                        out["width"], out["height"] = w >> 16, h >> 16
                elif t.type == b"mdia":
                    for m in iter_boxes(r, t.data, t.end):
                        if m.type == b"hdlr":
                            kind = r.read(m.data + 8, 4)
                            if kind == b"vide":
                                out["video"] = True
                            elif kind == b"soun":
                                out["audio"] = True
        elif c.type == b"udta":
            for u in iter_boxes(r, c.data, c.end):
                if u.type == b"meta":
                    for ilst in iter_boxes(r, u.data + 4, u.end):
                        if ilst.type == b"ilst" and ilst.size < 1024 * 1024:
                            out["tags"] = _ilst(r, ilst)
    return out


_MOOV_CHILDREN = frozenset({b"mvhd", b"cmov", b"iods", b"trak", b"udta", b"meta", b"mvex", b"prfl", b"clip", b"ctab",
                            b"rmra", b"free", b"skip", b"uuid", b"pssh", b"htka", b"wide"})


def bmff_movie(r) -> dict | None:
    """A movie (MP4, MOV, 3GP, M4A...) at offset 0 of R: {"walk" (BmffInfo), "moov" (moov_info), "ext",
    "audio_only"}; None if it isn't a playable movie (no movie box) or is a picture (HEIC, CR3). The video
    and the audio formats share it (computed once per candidate)."""
    b = memo(r, "bmff", bmff_walk)
    if b is None:
        return None
    moov = b.first(b"moov")
    if moov is None:
        return None
    first = box_header(r, moov.data)              # a real movie box starts with one of its usual children
    if first is None or first.type not in _MOOV_CHILDREN or (moov.size is not None and first.size is not None
                                                             and first.size > moov.size - moov.header):
        return None
    cat, ext = bmff_kind(b.brand, b.compat)
    if cat == "photo":
        return None
    mi = memo(r, "moov", lambda r: moov_info(r, moov))
    audio_only = cat == "audio" or (mi["audio"] and not mi["video"])
    return {"walk": b, "moov": mi, "ext": ext, "audio_only": audio_only}


_ILST = {b"\xa9nam": "title", b"\xa9ART": "artist", b"aART": "artist", b"\xa9alb": "album", b"\xa9day": "date"}


def _ilst(r, ilst: Box) -> dict:
    out: dict = {}
    for item in iter_boxes(r, ilst.data, ilst.end):
        key = _ILST.get(item.type)
        if key is None or key in out:
            continue
        for d in iter_boxes(r, item.data, item.end):
            if d.type == b"data" and d.size < 4096:
                raw = r.read(d.data, d.size - d.header)
                if raw[:4] == b"\0\0\0\x01":
                    out[key] = raw[8:].decode("utf-8", "replace").strip()
                break
    return out


# ---------------------------------------------------------------------- RIFF / IFF chunks
def iter_chunks(r, start: int, end: int, big_endian: bool = False, max_chunks: int = 100000
                ) -> Iterator[tuple[bytes, int, int]]:
    """(id, data offset, data size) of the RIFF (little-endian) or IFF (big-endian) chunks in [start, end);
    chunks are padded to an even length. Stops at an id that isn't four printable characters."""
    pos = start
    fmt = ">4sI" if big_endian else "<4sI"
    n = 0
    while pos + 8 <= end and n < max_chunks:
        h = r.read(pos, 8)
        if len(h) < 8:
            return
        cid, size = struct.unpack(fmt, h)
        if not all(32 <= c < 127 for c in cid):
            return
        yield cid, pos + 8, size
        pos += 8 + size + (size & 1)
        n += 1


# ---------------------------------------------------------------------- EBML (Matroska, WebM)
def ebml_id(buf: bytes, pos: int) -> tuple[int, int] | None:
    """(element id with its length marker, its length in bytes) at POS of BUF."""
    if pos >= len(buf):
        return None
    b = buf[pos]
    if b >= 0x80:
        n = 1
    elif b >= 0x40:
        n = 2
    elif b >= 0x20:
        n = 3
    elif b >= 0x10:
        n = 4
    else:
        return None
    if pos + n > len(buf):
        return None
    return int.from_bytes(buf[pos:pos + n], "big"), n


def ebml_size(buf: bytes, pos: int) -> tuple[int | None, int] | None:
    """(data size or None for "unknown", length of the size field) at POS of BUF."""
    if pos >= len(buf):
        return None
    b = buf[pos]
    if b == 0:
        return None
    n = 9 - b.bit_length()
    if pos + n > len(buf):
        return None
    v = int.from_bytes(buf[pos:pos + n], "big") & ((1 << (7 * n)) - 1)
    if v == (1 << (7 * n)) - 1:
        return None, n
    return v, n


def iter_ebml(buf: bytes, start: int = 0, end: int | None = None) -> Iterator[tuple[int, int, int | None]]:
    """(id, data offset, data size) of the elements in BUF[start:end] (sizes may be None: unknown)."""
    pos = start
    end = len(buf) if end is None else min(end, len(buf))
    while pos < end:
        i = ebml_id(buf, pos)
        if i is None:
            return
        s = ebml_size(buf, pos + i[1])
        if s is None:
            return
        data = pos + i[1] + s[1]
        yield i[0], data, s[0]
        if s[0] is None:
            return
        pos = data + s[0]


def ebml_uint(data: bytes) -> int:
    return int.from_bytes(data[:8], "big") if data else 0


# ---------------------------------------------------------------------- ASF (WMV, WMA)
def _guid(text: str) -> bytes:
    return uuid.UUID(text).bytes_le


ASF_HEADER = _guid("75B22630-668E-11CF-A6D9-00AA0062CE6C")
ASF_DATA = _guid("75B22636-668E-11CF-A6D9-00AA0062CE6C")
ASF_FILE_PROPERTIES = _guid("8CABDCA1-A947-11CF-8EE4-00C00C205365")
ASF_STREAM_PROPERTIES = _guid("B7DC0791-A9B7-11CF-8EE6-00C00C205365")
ASF_CONTENT_DESCRIPTION = _guid("75B22633-668E-11CF-A6D9-00AA0062CE6C")
ASF_AUDIO_MEDIA = _guid("F8699E40-5B4D-11CF-A8FD-00805F5C442B")
ASF_VIDEO_MEDIA = _guid("BC19EFC0-5B4D-11CF-A8FD-00805F5C442B")
_ASF_TOP = {ASF_DATA, _guid("33000890-E5B1-11CF-89F4-00A0C90349CB"), _guid("D6E229D3-35DA-11D1-9034-00A0C90349BE"),
            _guid("FEB103F8-12AD-4C64-840F-2A1D2F7AD48C"), _guid("3CB73FD0-0C4A-4803-953D-EDF7B6228F0C")}


def parse_asf(r) -> dict | None:
    """The layout of an ASF file (Windows Media): {"end", "exact", "audio", "video", "ctime", "duration",
    "title", "author"}. The File Properties object records the file size; when it doesn't (broadcast
    files), the top-level objects are walked."""
    h = r.read(0, 30)
    if len(h) < 30 or h[:16] != ASF_HEADER:
        return None
    hsize, nobj = struct.unpack_from("<QI", h, 16)
    if hsize < 30 + 24 or hsize > 64 * 1024 * 1024 or not 1 <= nobj <= 1000 or h[28] != 1 or h[29] != 2:
        return None
    out: dict = {"audio": False, "video": False, "ctime": None, "duration": None, "title": None, "author": None}
    file_size = 0
    broadcast = True
    packets = packet_size = 0
    pos = 30
    seen_props = False
    for _ in range(nobj):
        o = r.read(pos, 24)
        if len(o) < 24:
            return None
        guid, size = o[:16], struct.unpack_from("<Q", o, 16)[0]
        if size < 24 or pos + size > hsize:
            return None
        if guid == ASF_FILE_PROPERTIES and size >= 104:
            d = r.read(pos, 104)
            if len(d) < 104:
                return None
            file_size, ctime, packets, duration = struct.unpack_from("<QQQQ", d, 40)
            preroll = struct.unpack_from("<Q", d, 80)[0]
            flags, pmin, pmax = struct.unpack_from("<III", d, 88)
            broadcast = bool(flags & 1)
            packet_size = pmin if pmin == pmax else 0
            from ..fs.base import filetime
            out["ctime"] = filetime(ctime)
            if duration:
                out["duration"] = max(0.0, duration / 1e7 - preroll / 1000.0)
            seen_props = True
        elif guid == ASF_STREAM_PROPERTIES and size >= 40:
            st = r.read(pos + 24, 16)
            if st == ASF_AUDIO_MEDIA:
                out["audio"] = True
            elif st == ASF_VIDEO_MEDIA:
                out["video"] = True
        elif guid == ASF_CONTENT_DESCRIPTION and 34 <= size <= 65536:
            d = r.read(pos, size)
            if len(d) < 34:
                return None
            lens = struct.unpack_from("<5H", d, 24)
            p = 34
            texts = []
            for n in lens[:2]:
                texts.append(d[p:p + n].decode("utf-16-le", "replace").rstrip("\0").strip())
                p += n
            out["title"], out["author"] = texts[0] or None, texts[1] or None
        pos += size
    if not seen_props:
        return None
    # walk the top-level objects that follow the header
    end = hsize
    data_seen = False
    for _ in range(64):
        o = r.read(end, 24)
        if len(o) < 24 or o[:16] not in _ASF_TOP:
            break
        size = struct.unpack_from("<Q", o, 16)[0]
        if o[:16] == ASF_DATA:
            data_seen = True
            if size == 0 and packets and packet_size:     # broadcast: the size is unknown while recording
                size = 50 + packets * packet_size
        if size < 24:
            break
        end += size
    if not data_seen:
        return None
    exact = True
    if not broadcast and file_size >= hsize + 50:
        if file_size != end:
            exact = file_size > end     # trust the recorded size, unless the walk found more
            end = max(end, file_size)
    out["end"] = end
    out["exact"] = exact
    return out


# ---------------------------------------------------------------------- music tags
def syncsafe(b: bytes) -> int | None:
    """An ID3v2 28-bit "syncsafe" integer (None if a byte has its top bit set)."""
    if len(b) < 4 or any(c & 0x80 for c in b[:4]):
        return None
    return (b[0] << 21) | (b[1] << 14) | (b[2] << 7) | b[3]


def _id3_text(data: bytes) -> str | None:
    if not data:
        return None
    enc, body = data[0], data[1:]
    try:
        if enc == 0:
            s = body.decode("latin-1")
        elif enc == 1:
            s = body.decode("utf-16")
        elif enc == 2:
            s = body.decode("utf-16-be")
        elif enc == 3:
            s = body.decode("utf-8", "replace")
        else:
            return None
    except UnicodeDecodeError:
        return None
    s = s.split("\0", 1)[0].strip()
    return s or None


_ID3_FIELDS = {b"TIT2": "title", b"TPE1": "artist", b"TALB": "album", b"TYER": "year", b"TDRC": "year",
               b"TT2": "title", b"TP1": "artist", b"TAL": "album", b"TYE": "year"}


def id3v2_info(r, offset: int = 0) -> tuple[int, dict] | None:
    """(total size of the ID3v2 tag at OFFSET, {"title", "artist", "album", "year"}) or None."""
    h = r.read(offset, 10)
    if len(h) < 10 or h[:3] != b"ID3" or h[3] not in (2, 3, 4) or h[4] == 0xFF:
        return None
    size = syncsafe(h[6:10])
    if size is None:
        return None
    flags = h[5]
    if flags & 0x0F and h[3] >= 3:        # undefined flag bits
        return None
    total = 10 + size + (10 if (flags & 0x10 and h[3] == 4) else 0)
    meta: dict = {}
    if flags & 0x80 and h[3] < 4:         # whole-tag unsynchronisation: don't bother with the text
        return total, meta
    data = r.read(offset + 10, min(size, 256 * 1024))
    pos = 0
    if flags & 0x40 and h[3] >= 3 and len(data) >= 4:  # extended header
        ext = syncsafe(data[:4]) if h[3] == 4 else struct.unpack_from(">I", data)[0] + 4
        pos = ext or 0
    v22 = h[3] == 2
    hdr = 6 if v22 else 10
    for _ in range(512):
        if pos + hdr > len(data) or data[pos] == 0:
            break
        if v22:
            fid = data[pos:pos + 3]
            fsize = int.from_bytes(data[pos + 3:pos + 6], "big")
        else:
            fid = data[pos:pos + 4]
            fsize = (syncsafe(data[pos + 4:pos + 8]) if h[3] == 4 else struct.unpack_from(">I", data, pos + 4)[0])
            if fsize is None:
                break
        if not all(48 <= c <= 57 or 65 <= c <= 90 for c in fid):
            break
        key = _ID3_FIELDS.get(fid)
        if key and key not in meta and fsize < 4096:
            text = _id3_text(data[pos + hdr:pos + hdr + fsize])
            if text:
                meta[key] = text[:4] if key == "year" else text
        pos += hdr + fsize
    return total, meta


def skip_tags(r, end: int, max_rounds: int = 4) -> int:
    """END moved past the tags music files carry after their audio: APEv2, Lyrics3 v2 and ID3v1."""
    for _ in range(max_rounds):
        h = r.read(end, 32)
        if h[:8] == b"APETAGEX" and len(h) == 32:
            size, _items, flags = struct.unpack_from("<III", h, 12)
            if size < 32 or size > 16 * 1024 * 1024:
                break
            # a tag that starts with a header: header (32) + items + footer (size includes the footer)
            end += size + (32 if flags & (1 << 31) else 0)
            continue
        if h[:11] == b"LYRICSBEGIN":
            stop = r.find(b"LYRICS200", end, end + 1024 * 1024)
            if stop < 0:
                break
            end = stop + 9
            continue
        if h[:3] == b"TAG":
            nxt = r.read(end + 128, 3)
            end += 128
            if nxt != b"TAG":
                break
            continue
        break
    return end


def vorbis_comments(data: bytes) -> dict:
    """{"title", "artist", "album", "date"} from a Vorbis comment block (FLAC, Ogg Vorbis/Opus)."""
    out: dict = {}
    try:
        n = struct.unpack_from("<I", data)[0]
        pos = 4 + n
        count = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        for _ in range(min(count, 1000)):
            ln = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if ln > len(data) - pos:
                break
            k, _, v = data[pos:pos + ln].decode("utf-8", "replace").partition("=")
            pos += ln
            k = k.lower()
            if k in ("title", "artist", "album", "date") and k not in out and v.strip():
                out[k] = v.strip()
    except struct.error:
        pass
    return out


def music_name(meta: dict) -> str | None:
    """"Artist - Title" (or just the title) from tag fields."""
    title = clean_name(meta.get("title"))
    artist = clean_name(meta.get("artist"))
    if title and artist:
        return clean_name(f"{artist} - {title}")
    return title
