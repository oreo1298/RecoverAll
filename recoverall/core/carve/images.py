"""Photos and pictures for the signature engine: JPEG (and MPO), PNG, GIF, BMP, TIFF, the camera RAW formats,
HEIC/HEIF/AVIF, WebP, Photoshop, JPEG 2000, JPEG XL, OpenEXR, GIMP, icons and SVG.

Every parser checks the file's structure (random data that happens to start with a signature is rejected)
and measures the file exactly where the format allows it:

* JPEG: the segments are walked one by one and the compressed data is scanned for the next marker, through
  every scan of a progressive picture, up to the end-of-image marker. A JPEG cut short keeps what was found
  (poor chance). An MPO (3D or multi-frame) file, and a JPEG that carries a preview image after its own end,
  is kept whole when its MP extension (APP2 "MPF") lists the other pictures.
* PNG, GIF, PSD, WebP, BMP: chunk/block/section walks or recorded sizes.
* TIFF and the RAW files built on it (CR2, NEF/NRW, ARW/SR2/SRF, DNG, ORF, RW2, PEF, SRW and other makers'):
  the end of the last IFD, value or image strip/tile. Panasonic RW2 doesn't record the length of its sensor
  data: those files end where the next file starts.
* HEIC/HEIF/AVIF and Canon CR3 (ISO media boxes), JPEG 2000 (boxes, or the codestream's tile parts), JPEG XL
  in its box container, single-part scan-line OpenEXR: exact. GIMP XCF, tiled OpenEXR and bare JPEG XL
  codestreams don't record their length: they end where the next file starts.

Photos are named after the moment they were taken (EXIF DateTimeOriginal: "2023-07-14 18.22.05") and the
camera model and picture size are shown in the preview.
"""

from __future__ import annotations

import re
import struct
import zlib

from .base import CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, Format, GiB, Hit, KiB, MiB, Reader
from .common import (
    BytesReader,
    TiffInfo,
    bmff_kind,
    bmff_walk,
    camera_name,
    exif_time,
    ifd_value,
    iter_boxes,
    iter_chunks,
    memo,
    parse_exif,
    parse_tiff,
    photo_meta,
    read_ifd,
    time_name,
)

# ---------------------------------------------------------------------- JPEG
_MARKER = re.compile(rb"\xff[^\x00\xd0-\xd7\xff]")
_SOF = frozenset(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}
_PROGRESSIVE = frozenset({0xC2, 0xC6, 0xCA, 0xCE})
_STANDALONE = frozenset(range(0xD0, 0xD8)) | {0x01}
_FIRST_MARKERS = frozenset(range(0xE0, 0xF0)) | _SOF | {0xC4, 0xDB, 0xDD, 0xFE}
_SCAN_STEP = 1024 * 1024
_BLANK_RUNS = (bytes(4096), b"\xff" * 4096)
JPEG_MAX = 512 * MiB


def _next_marker(r, pos: int, stop: int = JPEG_MAX) -> int:
    """Offset of the first marker (0xFF not followed by 0x00, a restart marker or a fill byte) at or after
    POS: where the entropy-coded data of a scan ends. A run of 4 KiB of zeros or 0xFF (compressed data
    never has one: the rest of the picture was wiped, or the flash memory erased) or the end of the medium
    before STOP give -1 - (where the data ends)."""
    stop = min(stop, r.limit)
    while pos < stop:
        data = r.read(pos, _SCAN_STEP + 1)
        m = _MARKER.search(data)
        hi = m.start() if m else len(data)
        z = min((i for i in (data.find(run, 0, hi + 4096) for run in _BLANK_RUNS) if 0 <= i <= hi), default=-1)
        if z >= 0:
            return -1 - (pos + z)
        if m:
            return pos + m.start()
        if len(data) <= _SCAN_STEP:
            return -1 - (pos + len(data))
        pos += _SCAN_STEP
    return -1 - stop


def _dht_ok(d: bytes) -> bool:
    p = 0
    while p < len(d):
        if p + 17 > len(d) or d[p] >> 4 > 1 or d[p] & 15 > 3:
            return False
        p += 17 + sum(d[p + 1:p + 17])
    return p == len(d)


def _dqt_ok(d: bytes) -> bool:
    p = 0
    while p < len(d):
        if d[p] >> 4 > 1 or d[p] & 15 > 3:
            return False
        p += 1 + 64 * (1 + (d[p] >> 4))
    return p == len(d)


def walk_jpeg(r, base: int = 0, meta: bool = True, entropy: bool = True) -> dict | None:
    """Walk the JPEG starting at BASE: {"end", "complete" (EOI reached), "sof" (width, height), "scans",
    "progressive", "exif" (TiffInfo), "mpf" (offset of its TIFF header, bytes)}. With ENTROPY False it stops
    at the first scan (enough for the EXIF block). None if it doesn't start like a JPEG."""
    h = r.read(base, 4)
    if len(h) < 4 or h[:3] != b"\xff\xd8\xff" or h[3] not in _FIRST_MARKERS:
        return None
    st: dict = {"end": None, "complete": False, "sof": None, "scans": 0, "progressive": False, "exif": None,
                "mpf": None, "corrupt": False}
    pos = base + 2
    for _ in range(200000):
        m = r.read(pos, 4)
        if len(m) < 2:
            break                                   # the medium ends: truncated
        if m[0] != 0xFF:
            st["corrupt"] = True
            break
        mk = m[1]
        if mk == 0xFF:
            pos += 1
            continue
        if mk == 0xD9:
            st["end"], st["complete"] = pos + 2, True
            return st
        if mk in _STANDALONE:
            pos += 2
            continue
        if mk < 0xC0 or mk == 0xD8 or len(m) < 4:
            st["corrupt"] = True
            break
        seglen = (m[2] << 8) | m[3]
        if seglen < 2:
            st["corrupt"] = True
            break
        if mk == 0xDA:
            ns = r.read(pos + 4, 1)
            if not st["sof"] or not ns or not 1 <= ns[0] <= 4 or seglen != 6 + 2 * ns[0]:
                st["corrupt"] = True
                break
            st["scans"] += 1
            if not entropy:
                st["end"] = pos
                return st
            nxt = _next_marker(r, pos + 2 + seglen, base + JPEG_MAX)
            if nxt < 0:                             # cut short: keep what is there
                pos = -1 - nxt
                break
            pos = nxt
            continue
        if mk in _SOF:
            d = r.read(pos + 4, 6)
            if len(d) < 6:
                break
            prec, y, x, nf = struct.unpack(">BHHB", d)
            if not 1 <= nf <= 4 or seglen != 8 + 3 * nf or x == 0 or not 2 <= prec <= 16:
                st["corrupt"] = True
                break
            if st["sof"] is None:
                st["sof"] = (x, y)
                st["progressive"] = mk in _PROGRESSIVE
        elif mk == 0xC4:
            if not _dht_ok(r.read(pos + 4, seglen - 2)):
                st["corrupt"] = True
                break
        elif mk == 0xDB:
            if not _dqt_ok(r.read(pos + 4, seglen - 2)):
                st["corrupt"] = True
                break
        elif mk == 0xDD and seglen != 4:
            st["corrupt"] = True
            break
        elif mk == 0xE1 and meta and st["exif"] is None and seglen > 14:
            d = r.read(pos + 4, seglen - 2)
            if d[:6] == b"Exif\0\0":
                st["exif"] = parse_exif(d) or False
        elif mk == 0xE2 and st["mpf"] is None and seglen > 16:
            d = r.read(pos + 4, seglen - 2)
            if d[:4] == b"MPF\0":
                st["mpf"] = (pos + 8, d[4:])
        pos += 2 + seglen
    st["end"] = min(pos, r.limit)
    return st


def _mpf_images(blob: bytes) -> list[tuple[int, int, int]]:
    """(attribute, size, offset) of every picture an MP extension lists (offsets are relative to its TIFF
    header; the first picture's is 0)."""
    br = BytesReader(blob)
    order = "<" if blob[:2] == b"II" else ">" if blob[:2] == b"MM" else ""
    if not order or len(blob) < 8:
        return []
    got = read_ifd(br, struct.unpack_from(order + "I", blob, 4)[0], order)
    if got is None:
        return []
    out = []
    for e in got[0]:
        if e.tag == 0xB002:
            raw = ifd_value(br, e, order)
            if isinstance(raw, tuple):          # declared as LONGs by some writers
                raw = struct.pack(f"{order}{len(raw)}I", *raw)
            if isinstance(raw, bytes):
                for i in range(0, min(len(raw), 16 * 64) - 15, 16):
                    attr, size, off = struct.unpack_from(order + "III", raw, i)
                    out.append((attr, size, off))
    return out


def parse_jpg(r: Reader) -> Hit | None:
    st = walk_jpeg(r)
    if st is None or not st["sof"] or not st["scans"]:
        return None
    end = st["end"]
    chance = CHANCE_GOOD if st["complete"] else CHANCE_POOR
    ext = "jpg"
    images = 1
    if st["complete"] and st["mpf"]:
        tiff_at, blob = st["mpf"]
        mp = _mpf_images(blob)
        if len(mp) >= 2:
            total, multi = end, False
            for attr, size, off in mp[1:]:
                at = tiff_at + off
                if off == 0 or at < end or size < 64:
                    break
                sub = walk_jpeg(r, at, meta=False)
                if sub is None or not sub["complete"]:
                    break
                total = max(total, sub["end"])
                multi = multi or (attr & 0xFFFFFF) in (0x020001, 0x020002, 0x020003)
            else:
                end, images = total, len(mp)
                ext = "mpo" if multi else "jpg"
    exif = st["exif"] or None
    name, mtime, info = photo_meta(exif, *st["sof"])
    if st["progressive"]:
        info["progressive"] = True
    if images > 1:
        info["images"] = images
    return Hit(ext, end, chance, name=name, mtime=mtime, info=info,
               description="MPO image (3D / multi-picture)" if ext == "mpo" else None)


# ---------------------------------------------------------------------- PNG
_PNG_SIG = b"\x89PNG\r\n\x1a\n"


def parse_png(r: Reader) -> Hit | None:
    h = r.read(0, 33)
    if len(h) < 33 or h[8:16] != b"\0\0\0\rIHDR" or zlib.crc32(h[12:29]) != struct.unpack_from(">I", h, 29)[0]:
        return None
    w, ht, depth, color, comp, filt, inter = struct.unpack_from(">IIBBBBB", h, 16)
    if not (0 < w < 1 << 31 and 0 < ht < 1 << 31 and depth in (1, 2, 4, 8, 16) and color in (0, 2, 3, 4, 6)
            and comp == 0 and filt == 0 and inter in (0, 1)):
        return None
    pos, idat, exif, mtime = 33, False, None, None
    end, chance = None, CHANCE_POOR
    for _ in range(10_000_000):
        c = r.read(pos, 8)
        if len(c) < 8:
            break
        n, typ = struct.unpack(">I4s", c)
        if n > 0x7FFFFFFF or not all(65 <= x <= 90 or 97 <= x <= 122 for x in typ):
            break
        if typ == b"IEND":
            end, chance = pos + 12 + n, CHANCE_GOOD
            break
        if typ == b"IDAT":
            idat = True
        elif typ == b"eXIf" and n < 1 << 20 and exif is None:
            exif = parse_exif(r.read(pos + 8, n))
        elif typ == b"tIME" and n == 7:
            d = r.read(pos + 8, 7)
            if len(d) == 7:
                y, mo, dd, hh, mi, ss = struct.unpack(">HBBBBB", d)
                mtime = exif_time(f"{y:04d}:{mo:02d}:{dd:02d} {hh:02d}:{mi:02d}:{ss:02d}")
        pos += 12 + n
        if pos > r.limit:
            break
    if end is None:
        if not idat:
            return None
        end = min(pos, r.limit)
    name, t, info = photo_meta(exif, w, ht)
    return Hit("png", end, chance, name=name, mtime=t or mtime, info=info)


# ---------------------------------------------------------------------- GIF
def _skip_subblocks(r, pos: int) -> int:
    """Past a chain of GIF data sub-blocks (each: a length byte and that many bytes; 0 ends): -1 if the
    medium ends first."""
    while True:
        chunk = r.read(pos, 65536)
        if not chunk:
            return -1
        i = 0
        n = len(chunk)
        while i < n:
            size = chunk[i]
            if size == 0:
                return pos + i + 1
            i += size + 1
        pos += i


def parse_gif(r: Reader) -> Hit | None:
    h = r.read(0, 13)
    if len(h) < 13 or h[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    w, ht, flags = struct.unpack_from("<HHB", h, 6)
    if not w or not ht:
        return None
    pos = 13 + ((3 << ((flags & 7) + 1)) if flags & 0x80 else 0)
    frames = 0
    for _ in range(1_000_000):
        b = r.read(pos, 1)
        if not b:
            break
        if b == b";":
            if not frames:
                return None
            return Hit("gif", pos + 1, CHANCE_GOOD, info={"width": w, "height": ht, **({"frames": frames}
                                                                                       if frames > 1 else {})})
        if b == b",":
            d = r.read(pos + 1, 10)
            if len(d) < 10:
                break
            fx, fy, fw, fh, fl, lzw = struct.unpack("<HHHHBB", d)
            if fl & 0x80:
                lct = 3 << ((fl & 7) + 1)
                lzw = r.read(pos + 10 + lct, 1)
                lzw = lzw[0] if lzw else 0
                pos += lct
            if not 2 <= lzw <= 11 or fw == 0 or fh == 0 or fx + fw > w or fy + fh > ht:
                break
            nxt = _skip_subblocks(r, pos + 11)
            frames += 1
        elif b == b"!":
            lbl = r.read(pos + 1, 1)
            if not lbl or lbl[0] not in (0x01, 0xF9, 0xFE, 0xFF):
                break
            nxt = _skip_subblocks(r, pos + 2)
        else:
            break
        if nxt < 0:
            pos = r.limit
            break
        pos = nxt
    if not frames:
        return None
    return Hit("gif", min(pos, r.limit), CHANCE_POOR, info={"width": w, "height": ht})


# ---------------------------------------------------------------------- BMP
_DIB_SIZES = {12, 16, 40, 52, 56, 64, 108, 124}


def parse_bmp(r: Reader) -> Hit | None:
    h = r.read(0, 138)
    if len(h) < 26:
        return None
    size, _res, off, dib = struct.unpack_from("<IIII", h, 2)
    if dib not in _DIB_SIZES:
        return None
    if dib == 12:
        w, ht, planes, bpp = struct.unpack_from("<HHHH", h, 18)
        comp = 0
    else:
        if len(h) < 54:
            return None
        w, ht, planes, bpp, comp, isize = struct.unpack_from("<iiHHII", h, 18)
    ht = abs(ht)
    if planes != 1 or bpp not in (1, 2, 4, 8, 16, 24, 32, 64) or not 0 < w <= 100000 or not 0 < ht <= 100000:
        return None
    if comp not in (0, 1, 2, 3, 4, 5, 6, 11, 12, 13) or off < 14 + dib or off > 14 + dib + 1024 * 4 + 1024:
        return None
    row = ((w * bpp + 31) // 32) * 4
    expected = off + row * ht
    slack = 4096
    if dib == 124 and len(h) >= 138:      # a V5 header may put a colour profile after the pixels
        poff, psize = struct.unpack_from("<II", h, 14 + 112)
        if psize < 16 * MiB and poff:
            expected = max(expected, 14 + poff + psize)
    info = {"width": w, "height": ht, "bits": bpp}
    if comp in (0, 3, 6, 11):             # uncompressed: the size follows from the dimensions
        if size and expected <= size <= expected + slack:
            return Hit("bmp", size, CHANCE_GOOD, info=info)
        return Hit("bmp", expected, CHANCE_FAIR, info=info)       # the recorded size is wrong
    if size <= off or size > expected + 1024:
        return None
    return Hit("bmp", size, CHANCE_GOOD, info=info)


# ---------------------------------------------------------------------- TIFF and camera RAW
_MAKER_EXT = (("NIKON", "nef"), ("SONY", "arw"), ("PENTAX", "pef"), ("RICOH", "pef"), ("SAMSUNG", "srw"),
              ("HASSELBLAD", "3fr"), ("KODAK", "dcr"), ("EASTMAN KODAK", "dcr"), ("LEAF", "mos"),
              ("MAMIYA", "mef"), ("PHASE ONE", "iiq"), ("SEIKO EPSON", "erf"), ("EPSON", "erf"))


def tiff_kind(t: TiffInfo) -> str:
    """The extension a TIFF-structured file should get: "cr2", "nef", "dng", ... or "tif"."""
    if t.magic in (0x4F52, 0x5352):
        return "orf"
    if t.magic == 0x55:
        return "rwl" if (t.make or "").upper().startswith("LEICA") else "rw2"
    if t.dng:
        return "dng"
    if t.header[8:10] == b"CR" and t.order == "<":
        return "cr2"
    if not t.raw:
        return "tif"
    make = (t.make or "").upper()
    model = (t.model or "").upper()
    for prefix, ext in _MAKER_EXT:
        if make.startswith(prefix):
            if ext == "nef" and "COOLPIX" in model:
                return "nrw"
            if ext == "arw":
                return "sr2" if "DSC-R1" in model else "srf" if "DSC-F828" in model else "arw"
            return ext
    return "tif"


_RAW_DESC = "Camera RAW image"


def _tiff_parser(exts: tuple[str, ...]):
    def parse(r: Reader) -> Hit | None:
        t = memo(r, "tiff", parse_tiff)
        if t is None:
            return None
        ext = tiff_kind(t)
        if ext not in exts:
            return None
        if not t.ifds or (ext == "tif" and not (t.width and t.height)):
            return None
        name, mtime, info = photo_meta(t)
        length = None if t.open_end else t.end
        chance = CHANCE_POOR if t.damaged else CHANCE_GOOD
        desc = _RAW_DESC if exts[0] == "tif" and ext != "tif" else None
        return Hit(ext, length, chance, name=name, mtime=mtime, info=info, description=desc)
    return parse


def _tiff_ifd_tags(data: bytes) -> dict:
    """Tag → value of the first IFD of a TIFF block (no plausibility checks: CR3's CMT boxes)."""
    if data[:2] not in (b"II", b"MM") or len(data) < 8:
        return {}
    order = "<" if data[:2] == b"II" else ">"
    br = BytesReader(data)
    got = read_ifd(br, struct.unpack_from(order + "I", data, 4)[0], order)
    if got is None:
        return {}
    out = {}
    for e in got[0]:
        if e.tag in (0x10F, 0x110, 0x132, 0x9003):
            v = ifd_value(br, e, order)
            if v is not None:
                out[e.tag] = v
    return out


def jpeg_exif(r, base: int) -> TiffInfo | None:
    """The EXIF block of the JPEG at BASE (a RAW file's embedded preview), without scanning its image."""
    st = walk_jpeg(r, base, entropy=False)
    return (st or {}).get("exif") or None


def parse_raf(r: Reader) -> Hit | None:
    h = r.read(0, 108)
    if len(h) < 108 or h[:16] != b"FUJIFILMCCD-RAW " or not h[16:20].isdigit():
        return None
    pairs = struct.unpack_from(">6I", h, 84)
    jpeg_off, jpeg_len = pairs[0], pairs[1]
    end = 0
    for i in range(0, 6, 2):
        off, n = pairs[i], pairs[i + 1]
        if n:
            if off < 84:
                return None
            end = max(end, off + n)
    if not jpeg_len or end <= 108:
        return None
    model = h[28:60].split(b"\0", 1)[0].decode("latin-1").strip()
    t = jpeg_exif(r, jpeg_off)
    name, mtime, info = photo_meta(t)
    if model and "camera" not in info:
        info["camera"] = camera_name("FUJIFILM", model)
    return Hit("raf", end, CHANCE_GOOD, name=name, mtime=mtime, info=info)


# ---------------------------------------------------------------------- HEIC / AVIF / CR3 (ISO media)
_CANON_UUID = bytes.fromhex("85c0b687820f11e08111f4ce462b6a48")


def _meta_items(r, meta) -> dict:
    """Width/height (largest ispe) and the EXIF block of a HEIF meta box."""
    out: dict = {}
    if meta.size is None or meta.size > 4 * MiB:
        return out
    items: dict[int, bytes] = {}
    locs: dict[int, list[tuple[int, int]]] = {}
    idat_at = None
    for b in iter_boxes(r, meta.data + 4, meta.end):
        if b.type == b"iinf":
            d = r.read(b.data, b.size - b.header)
            if len(d) < 6:
                continue
            p = 6 if d[0] == 0 else 8
            for e in iter_boxes(BytesReader(d), p, len(d), 4096):
                ed = d[e.data:e.end]
                if len(ed) >= 12 and ed[0] >= 2:
                    if ed[0] == 2:
                        iid, typ = struct.unpack_from(">H", ed, 4)[0], ed[8:12]
                    else:
                        iid, typ = struct.unpack_from(">I", ed, 4)[0], ed[10:14]
                    items[iid] = typ
        elif b.type == b"iloc":
            locs = _iloc(r.read(b.data, b.size - b.header))
        elif b.type == b"idat":
            idat_at = b.data
        elif b.type == b"iprp":
            for c in iter_boxes(r, b.data, b.end):
                if c.type == b"ipco":
                    for p in iter_boxes(r, c.data, c.end, 4096):
                        d = r.read(p.data + 4, 8) if p.type == b"ispe" and p.size == 20 else b""
                        if len(d) == 8:
                            w, ht = struct.unpack(">II", d)
                            if w * ht > out.get("width", 0) * out.get("height", 0):
                                out["width"], out["height"] = w, ht
    for iid, typ in items.items():
        if typ == b"Exif" and iid in locs:
            ext = locs[iid]
            if len(ext) == 1 and ext[0][1] < 1 * MiB:
                off, n = ext[0]
                if off < 0:
                    if idat_at is None:
                        continue
                    off = idat_at + (-off - 1)
                d = r.read(off, n)
                if len(d) > 10:
                    skip = struct.unpack_from(">I", d)[0]
                    out["exif"] = parse_exif(d[4 + skip:]) if skip < len(d) else None
            break
    return out


def _iloc(d: bytes) -> dict[int, list[tuple[int, int]]]:
    """Item id → [(offset, length)] from an iloc box payload (idat-relative offsets come back as -1-offset)."""
    out: dict[int, list[tuple[int, int]]] = {}
    try:
        ver = d[0]
        osz, lsz = d[4] >> 4, d[4] & 15
        bsz, isz = d[5] >> 4, (d[5] & 15 if ver in (1, 2) else 0)
        p = 6
        if ver < 2:
            count = struct.unpack_from(">H", d, p)[0]
            p += 2
        else:
            count = struct.unpack_from(">I", d, p)[0]
            p += 4

        def num(size: int) -> int:
            nonlocal p
            v = int.from_bytes(d[p:p + size], "big") if size else 0
            p += size
            return v
        for _ in range(min(count, 4096)):
            iid = num(4 if ver == 2 else 2)
            method = num(2) & 15 if ver in (1, 2) else 0
            num(2)
            base = num(bsz)
            n = num(2)
            exts = []
            for _ in range(min(n, 4096)):
                if isz:
                    num(isz)
                off, ln = num(osz), num(lsz)
                exts.append((base + off, ln) if method == 0 else (-1 - (base + off), ln) if method == 1
                            else (0, 0))
            if p > len(d):
                break
            out[iid] = exts
    except (IndexError, struct.error):
        pass
    return out


def parse_heif(r: Reader) -> Hit | None:
    b = memo(r, "bmff", bmff_walk)
    if b is None or not b.brand:
        return None
    cat, ext = bmff_kind(b.brand, b.compat)
    if ext not in ("heic", "heif", "avif"):
        return None
    meta = b.first(b"meta")
    if meta is None or b.boxes[0].type != b"ftyp":
        return None
    m = _meta_items(r, meta)
    name, mtime, info = photo_meta(m.get("exif"), m.get("width", 0), m.get("height", 0))
    chance = CHANCE_POOR if b.truncated else CHANCE_GOOD
    return Hit(ext, b.end, chance, name=name, mtime=mtime, info=info)


def parse_cr3(r: Reader) -> Hit | None:
    b = memo(r, "bmff", bmff_walk)
    if b is None or b.brand != b"crx ":
        return None
    moov = b.first(b"moov")
    if moov is None or not b.has(b"mdat"):
        return None
    tags: dict = {}
    if moov.size and moov.size < 64 * MiB:
        for c in iter_boxes(r, moov.data, moov.end):
            if c.type == b"uuid" and r.read(c.data, 16) == _CANON_UUID:
                for cmt in iter_boxes(r, c.data + 16, c.end):
                    if cmt.type in (b"CMT1", b"CMT2") and cmt.size < 1 * MiB:
                        tags.update(_tiff_ifd_tags(r.read(cmt.data, cmt.size - cmt.header)))
                break
    when = exif_time(tags.get(0x9003)) if isinstance(tags.get(0x9003), str) else None
    if when is None and isinstance(tags.get(0x132), str):
        when = exif_time(tags[0x132])
    info: dict = {}
    cam = camera_name(tags.get(0x10F) if isinstance(tags.get(0x10F), str) else None,
                      tags.get(0x110) if isinstance(tags.get(0x110), str) else None)
    if cam:
        info["camera"] = cam
    name = time_name(when) if when is not None and 0x9003 in tags else None
    chance = CHANCE_POOR if b.truncated else CHANCE_GOOD
    return Hit("cr3", b.end, chance, name=name, mtime=when, info=info)


# ---------------------------------------------------------------------- WebP
def parse_webp(r: Reader) -> Hit | None:
    h = r.read(0, 30)
    if len(h) < 30 or h[:4] != b"RIFF" or h[8:12] != b"WEBP":
        return None
    size = struct.unpack_from("<I", h, 4)[0]
    kind = h[12:16]
    w = ht = 0
    if kind == b"VP8 ":
        if h[23:26] != b"\x9d\x01\x2a":
            return None
        w, ht = struct.unpack_from("<HH", h, 26)
        w, ht = w & 0x3FFF, ht & 0x3FFF
    elif kind == b"VP8L":
        if h[20] != 0x2F:
            return None
        bits = int.from_bytes(h[21:25], "little")
        w, ht = (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    elif kind == b"VP8X":
        w = int.from_bytes(h[24:27], "little") + 1
        ht = int.from_bytes(h[27:30], "little") + 1
    else:
        return None
    if size < 12 or size & 1:
        return None
    exif = None
    if kind == b"VP8X":
        for cid, off, n in iter_chunks(r, 12, min(8 + size, 12 + 64 * MiB)):
            if cid == b"EXIF" and n < 1 * MiB:
                exif = parse_exif(r.read(off, n))
                break
    name, mtime, info = photo_meta(exif, w, ht)
    return Hit("webp", 8 + size, CHANCE_GOOD, name=name, mtime=mtime, info=info)


# ---------------------------------------------------------------------- Photoshop
def parse_psd(r: Reader) -> Hit | None:
    h = r.read(0, 26)
    if len(h) < 26 or h[:4] != b"8BPS":
        return None
    ver, res, ch, ht, w, depth, mode = struct.unpack(">H6sHIIHH", h[4:26])
    if ver not in (1, 2) or res != b"\0" * 6 or not 1 <= ch <= 56 or depth not in (1, 8, 16, 32) or mode > 9:
        return None
    cap = 30000 if ver == 1 else 300000
    if not 0 < w <= cap or not 0 < ht <= cap:
        return None
    pos = 26
    for wide in (False, False, ver == 2):           # colour mode data, image resources, layers and masks
        d = r.read(pos, 8 if wide else 4)
        if len(d) < (8 if wide else 4):
            return None
        n = int.from_bytes(d, "big")
        pos += len(d) + n
        if pos > r.limit + 1:
            return Hit("psb" if ver == 2 else "psd", pos, CHANCE_POOR, info={"width": w, "height": ht})
    comp = r.read(pos, 2)
    if len(comp) < 2:
        return None
    comp = struct.unpack(">H", comp)[0]
    rows = ch * ht
    ext = "psb" if ver == 2 else "psd"
    info = {"width": w, "height": ht, "bits": depth}
    if comp == 0:
        return Hit(ext, pos + 2 + rows * ((w * depth + 7) // 8), CHANCE_GOOD, info=info)
    if comp == 1:
        cs = 4 if ver == 2 else 2
        table = r.read(pos + 2, rows * cs)
        if len(table) < rows * cs:
            return Hit(ext, pos + 2 + rows * cs, CHANCE_POOR, info=info)
        total = sum(struct.unpack(f">{rows}{'I' if cs == 4 else 'H'}", table))
        return Hit(ext, pos + 2 + rows * cs + total, CHANCE_GOOD, info=info)
    if comp in (2, 3):
        return Hit(ext, None, CHANCE_FAIR, info=info)
    return None


# ---------------------------------------------------------------------- JPEG 2000
_JP2_SIG = b"\x00\x00\x00\x0cjP  \r\n\x87\n"
_JP2_BOXES = frozenset({b"jP  ", b"ftyp", b"jp2h", b"jp2c", b"jp2i", b"xml ", b"uuid", b"uinf", b"res ", b"rreq",
                        b"asoc", b"jpch", b"jplh", b"cgrp", b"dtbl", b"ftbl", b"nlst", b"lbl ", b"free", b"mhdr",
                        b"page", b"lobj", b"objc", b"sdat", b"pclr", b"cmap", b"cdef", b"drep", b"comp", b"copt",
                        b"roid", b"chck", b"mp7b", b"jxpl", b"jumb", b"ihdr", b"colr"})


def walk_j2k(r, base: int) -> tuple[int, bool, tuple[int, int] | None] | None:
    """(end, exact, (width, height)) of the JPEG 2000 codestream at BASE (SOC SIZ ... tile parts ... EOC)."""
    h = r.read(base, 4)
    if h != b"\xff\x4f\xff\x51":
        return None
    siz = r.read(base + 4, 38)
    if len(siz) < 38:
        return None
    lsiz, _rsiz, xs, ys, xo, yo = struct.unpack_from(">HHIIII", siz)
    csiz = struct.unpack_from(">H", siz, 36)[0]
    if lsiz != 38 + 3 * csiz or not 1 <= csiz <= 16384 or xs <= xo or ys <= yo:
        return None
    dims = (xs - xo, ys - yo)
    pos = base + 4 + lsiz
    for _ in range(4096):                    # main header segments up to the first tile part
        m = r.read(pos, 4)
        if len(m) < 4 or m[0] != 0xFF:
            return None
        if m[1] == 0x90:
            break
        if m[1] < 0x30:
            return None
        pos += 2 + struct.unpack_from(">H", m, 2)[0]
    else:
        return None
    for _ in range(1_000_000):               # tile parts: SOT Lsot Isot Psot TPsot TNsot
        m = r.read(pos, 12)
        if len(m) >= 2 and m[:2] == b"\xff\xd9":
            return pos + 2, True, dims
        if len(m) < 12 or m[:2] != b"\xff\x90" or struct.unpack_from(">H", m, 2)[0] != 10:
            return (min(pos, r.limit), False, dims) if pos > base else None
        psot = struct.unpack_from(">I", m, 6)[0]
        if psot == 0:                        # the last tile part runs to the EOC marker
            e = r.find(b"\xff\xd9", pos + 12, pos + 64 * MiB)
            return (e + 2, False, dims) if e >= 0 else None
        if psot < 14:
            return min(pos, r.limit), False, dims
        pos += psot
    return None


def parse_jp2(r: Reader) -> Hit | None:
    head = r.read(0, 12)
    if head[:4] == b"\xff\x4f\xff\x51":
        got = walk_j2k(r, 0)
        if got is None:
            return None
        end, exact, dims = got
        return Hit("j2k", end, CHANCE_GOOD if exact else CHANCE_FAIR, info={"width": dims[0], "height": dims[1]},
                   description="JPEG 2000 codestream")
    if head != _JP2_SIG:
        return None
    b = bmff_walk(r, _JP2_BOXES, ftyp_at=1)
    if b is None or len(b.boxes) < 3 or b.boxes[1].type != b"ftyp":
        return None
    ext = {b"jpx ": "jpx", b"jpm ": "jpm"}.get(b.brand, "jp2")
    info: dict = {}
    jp2h = b.first(b"jp2h")
    if jp2h is not None and jp2h.size:
        for c in iter_boxes(r, jp2h.data, jp2h.end):
            d = r.read(c.data, 8) if c.type == b"ihdr" else b""
            if len(d) == 8:
                ht, w = struct.unpack(">II", d)
                info = {"width": w, "height": ht}
    end = b.end
    chance = CHANCE_POOR if b.truncated else CHANCE_GOOD
    last = b.boxes[-1]
    if end is None and last.type == b"jp2c":           # the codestream runs to the end: measure it
        got = walk_j2k(r, last.data)
        if got is not None:
            end, exact, _dims = got
            chance = CHANCE_GOOD if exact else CHANCE_FAIR
    if not b.has(b"jp2c") and ext == "jp2":
        return None
    return Hit(ext, end, chance, info=info)


# ---------------------------------------------------------------------- JPEG XL
_JXL_SIG = b"\x00\x00\x00\x0cJXL \r\n\x87\n"
_JXL_BOXES = frozenset({b"JXL ", b"ftyp", b"jxll", b"jxlc", b"jxlp", b"jbrd", b"Exif", b"xml ", b"jumb", b"brob",
                        b"jxli", b"free", b"skip", b"uuid"})


def parse_jxl(r: Reader) -> Hit | None:
    if r.read(0, 12) != _JXL_SIG:
        return None
    b = bmff_walk(r, _JXL_BOXES, ftyp_at=1)
    if b is None or len(b.boxes) < 3 or b.brand != b"jxl " or not (b.has(b"jxlc") or b.has(b"jxlp")):
        return None
    exif = None
    ex = b.first(b"Exif")
    if ex is not None and ex.size and ex.size < 1 * MiB:
        d = r.read(ex.data, ex.size - ex.header)
        if len(d) > 8:
            skip = struct.unpack_from(">I", d)[0]
            exif = parse_exif(d[4 + skip:]) if skip < len(d) else None
    name, mtime, info = photo_meta(exif)
    chance = CHANCE_POOR if b.truncated else CHANCE_GOOD
    return Hit("jxl", b.end, chance, name=name, mtime=mtime, info=info)


class _Bits:
    """LSB-first bit reader (JPEG XL headers)."""

    def __init__(self, data: bytes):
        self.v = int.from_bytes(data, "little")
        self.n = len(data) * 8
        self.p = 0

    def u(self, n: int) -> int:
        if self.p + n > self.n:
            raise ValueError("short")
        x = (self.v >> self.p) & ((1 << n) - 1)
        self.p += n
        return x


def _jxl_size(bits: _Bits) -> tuple[int, int]:
    small = bits.u(1)
    if small:
        h = (bits.u(5) + 1) * 8
    else:
        h = [lambda: bits.u(9), lambda: bits.u(13), lambda: bits.u(18), lambda: bits.u(30)][bits.u(2)]() + 1
    ratio = bits.u(3)
    if ratio == 0:
        if small:
            w = (bits.u(5) + 1) * 8
        else:
            w = [lambda: bits.u(9), lambda: bits.u(13), lambda: bits.u(18), lambda: bits.u(30)][bits.u(2)]() + 1
    else:
        num, den = ((1, 1), (12, 10), (4, 3), (3, 2), (16, 9), (5, 4), (2, 1))[ratio - 1]
        w = h * num // den
    return w, h


def parse_jxl_codestream(r: Reader) -> Hit | None:
    d = r.read(0, 32)
    if len(d) < 32 or d[:2] != b"\xff\x0a":
        return None
    try:
        bits = _Bits(d[2:])
        w, h = _jxl_size(bits)
        all_default = bits.u(1)
        if not all_default:
            extra = bits.u(1)
            if extra:
                if bits.u(3) > 7:
                    return None
    except ValueError:
        return None
    if not (8 <= w <= 65536 and 8 <= h <= 65536) or d[8:32] == bytes(24):
        return None
    return Hit("jxl", None, CHANCE_FAIR, info={"width": w, "height": h})


# ---------------------------------------------------------------------- OpenEXR
_EXR_LINES = {0: 1, 1: 1, 2: 1, 3: 16, 4: 32, 5: 16, 6: 32, 7: 32, 8: 32, 9: 256}


def parse_exr(r: Reader) -> Hit | None:
    h = r.read(0, 8)
    if len(h) < 8 or h[:4] != b"\x76\x2f\x31\x01":
        return None
    version = h[4]
    flags = int.from_bytes(h[5:8], "little")
    if version != 2 or flags & ~0x1E:
        return None
    hdr = r.read(8, 65536)
    attrs: dict = {}
    p = 0
    for _ in range(256):
        if p >= len(hdr):
            return None
        if hdr[p] == 0:
            p += 1
            break
        e1 = hdr.find(b"\0", p, p + 256)
        e2 = hdr.find(b"\0", e1 + 1, e1 + 257)
        if e1 < 0 or e2 < 0 or e2 + 5 > len(hdr):
            return None
        name = hdr[p:e1]
        n = struct.unpack_from("<I", hdr, e2 + 1)[0]
        if n > len(hdr):
            return None
        attrs[name] = hdr[e2 + 5:e2 + 5 + n]
        p = e2 + 5 + n
    else:
        return None
    if b"channels" not in attrs or b"dataWindow" not in attrs or len(attrs[b"dataWindow"]) != 16:
        return None
    x0, y0, x1, y1 = struct.unpack("<4i", attrs[b"dataWindow"])
    if x1 < x0 or y1 < y0:
        return None
    info = {"width": x1 - x0 + 1, "height": y1 - y0 + 1}
    comp = attrs.get(b"compression", b"\0")[:1]
    lines = _EXR_LINES.get(comp[0] if comp else 0)
    if flags & 0x1A or lines is None:              # tiled, deep or multi-part: no simple chunk count
        return Hit("exr", None, CHANCE_FAIR, info=info)
    chunks = -(-(y1 - y0 + 1) // lines)
    table_at = 8 + p
    raw = r.read(table_at, chunks * 8)
    if len(raw) < chunks * 8:
        return Hit("exr", None, CHANCE_POOR, info=info)
    offs = struct.unpack(f"<{chunks}Q", raw)
    last = max(offs)
    if min(offs) < table_at + chunks * 8:
        return None
    c = r.read(last, 8)
    if len(c) < 8:
        return Hit("exr", None, CHANCE_POOR, info=info)
    _y, n = struct.unpack("<iI", c)
    return Hit("exr", last + 8 + n, CHANCE_GOOD, info=info)


# ---------------------------------------------------------------------- GIMP, icons, SVG
def parse_xcf(r: Reader) -> Hit | None:
    h = r.read(0, 26)
    if len(h) < 26 or h[:9] != b"gimp xcf " or h[13] != 0:
        return None
    if h[9:13] != b"file" and not (h[9:10] == b"v" and h[10:13].isdigit()):
        return None
    w, ht, base = struct.unpack_from(">III", h, 14)
    if not 0 < w <= 524288 or not 0 < ht <= 524288 or base > 2:
        return None
    return Hit("xcf", None, CHANCE_FAIR, info={"width": w, "height": ht})


def parse_ico(r: Reader) -> Hit | None:
    h = r.read(0, 6)
    if len(h) < 6:
        return None
    res, typ, n = struct.unpack("<HHH", h)
    if res != 0 or typ not in (1, 2) or not 1 <= n <= 64:
        return None
    d = r.read(6, 16 * n)
    if len(d) < 16 * n:
        return None
    end = 6 + 16 * n
    w0 = h0 = 0
    for i in range(n):
        w, ht, _colors, rsv, _planes, _bpp, size, off = struct.unpack_from("<BBBBHHII", d, 16 * i)
        if rsv not in (0, 255) or size < 40 or size > 16 * MiB or off < 6 + 16 * n:
            return None
        head = r.read(off, 8)
        if head != b"\x89PNG\r\n\x1a\n" and head[:4] != b"\x28\0\0\0":
            return None
        end = max(end, off + size)
        if i == 0:
            w0, h0 = w or 256, ht or 256
    return Hit("ico" if typ == 1 else "cur", end, CHANCE_GOOD, info={"width": w0, "height": h0, "images": n})


def parse_svg(r: Reader) -> Hit | None:
    head = r.read(0, 4096)
    i = head.find(b"<svg")
    if i < 0 or b"\0" in head[:i] or (i > 0 and not head.startswith((b"<?xml", b"<!--", b"<!DOCTYPE", b"\xef\xbb\xbf"))):
        return None
    pos, e = i, -1
    while pos < 32 * MiB:                           # text up to </svg>; a NUL byte means the drawing is gone
        chunk = r.read(pos, 65536 + 5)
        e = chunk.find(b"</svg>")
        nul = chunk.find(b"\0", 0, e if e >= 0 else len(chunk))
        if nul >= 0 or len(chunk) < 6:
            return None
        if e >= 0:
            e += pos
            break
        pos += 65536
    if e < 0:
        return None
    end = e + 6
    tail = r.read(end, 2)
    end += len(tail) - len(tail.lstrip(b"\r\n"))
    return Hit("svg", end, CHANCE_GOOD)


FORMATS = [
    Format("jpg", "JPEG image", "photo", ("jpg", "mpo"), ((0, b"\xff\xd8\xff"),), parse_jpg,
           max_size=512 * MiB, min_size=128, aliases=("jpeg", "jpe", "jfif", "mpo")),
    Format("png", "PNG image", "photo", ("png",), ((0, _PNG_SIG),), parse_png, max_size=1 * GiB, min_size=57,
           aliases=("apng",)),
    Format("gif", "GIF image", "photo", ("gif",), ((0, b"GIF87a"), (0, b"GIF89a")), parse_gif,
           max_size=512 * MiB, min_size=26),
    Format("bmp", "Windows bitmap", "photo", ("bmp",), ((0, b"BM"),), parse_bmp, max_size=2 * GiB, min_size=60,
           aliases=("dib",)),
    Format("tif", "TIFF image", "photo", ("tif", "tiff", "3fr", "dcr", "kdc", "mos", "mef", "iiq", "erf"),
           ((0, b"II*\0"), (0, b"MM\0*"), (0, b"II+\0"), (0, b"MM\0+")), _tiff_parser(
               ("tif", "3fr", "dcr", "kdc", "mos", "mef", "iiq", "erf")), max_size=4 * GiB, aliases=("tiff",)),
    Format("cr2", "Canon RAW image (CR2)", "photo", ("cr2",), ((0, b"II*\0\x10\0\0\0CR"),),
           _tiff_parser(("cr2",)), max_size=512 * MiB, min_size=16 * KiB),
    Format("cr3", "Canon RAW image (CR3)", "photo", ("cr3",), ((4, b"ftypcrx "),), parse_cr3, max_size=1 * GiB,
           min_size=16 * KiB),
    Format("nef", "Nikon RAW image", "photo", ("nef", "nrw"), ((0, b"MM\0*"), (0, b"II*\0")),
           _tiff_parser(("nef", "nrw")), max_size=512 * MiB, min_size=16 * KiB, aliases=("nrw",)),
    Format("arw", "Sony RAW image", "photo", ("arw", "srf", "sr2"), ((0, b"II*\0"), (0, b"MM\0*")),
           _tiff_parser(("arw", "srf", "sr2")), max_size=512 * MiB, min_size=16 * KiB, aliases=("srf", "sr2")),
    Format("dng", "Digital negative (DNG)", "photo", ("dng",), ((0, b"II*\0"), (0, b"MM\0*")),
           _tiff_parser(("dng",)), max_size=1 * GiB, min_size=4 * KiB),
    Format("orf", "Olympus RAW image", "photo", ("orf",), ((0, b"IIRO"), (0, b"IIRS"), (0, b"MMOR")),
           _tiff_parser(("orf",)), max_size=512 * MiB, min_size=16 * KiB),
    Format("rw2", "Panasonic RAW image", "photo", ("rw2", "rwl"), ((0, b"IIU\0"),), _tiff_parser(("rw2", "rwl")),
           max_size=256 * MiB, min_size=16 * KiB, aliases=("rwl",)),
    Format("raf", "Fujifilm RAW image", "photo", ("raf",), ((0, b"FUJIFILMCCD-RAW "),), parse_raf,
           max_size=512 * MiB, min_size=16 * KiB),
    Format("pef", "Pentax RAW image", "photo", ("pef",), ((0, b"MM\0*"), (0, b"II*\0")), _tiff_parser(("pef",)),
           max_size=512 * MiB, min_size=16 * KiB),
    Format("srw", "Samsung RAW image", "photo", ("srw",), ((0, b"II*\0"), (0, b"MM\0*")), _tiff_parser(("srw",)),
           max_size=512 * MiB, min_size=16 * KiB),
    Format("heic", "HEIC/HEIF image", "photo", ("heic", "heif", "avif"),
           ((4, b"ftypheic"), (4, b"ftypheix"), (4, b"ftypmif1"), (4, b"ftypmsf1"), (4, b"ftypavif"),
            (4, b"ftypavis"), (4, b"ftyphevc"), (4, b"ftyphevx")), parse_heif, max_size=1 * GiB,
           aliases=("heif", "avif")),
    Format("webp", "WebP image", "photo", ("webp",), ((8, b"WEBPVP8"),), parse_webp, max_size=1 * GiB),
    Format("psd", "Photoshop image", "photo", ("psd", "psb"), ((0, b"8BPS\0\x01"), (0, b"8BPS\0\x02")), parse_psd,
           max_size=16 * GiB, aliases=("psb",)),
    Format("jp2", "JPEG 2000 image", "photo", ("jp2", "jpx", "jpm", "j2k"),
           ((0, _JP2_SIG), (0, b"\xff\x4f\xff\x51")), parse_jp2, max_size=1 * GiB,
           aliases=("jpx", "j2k", "j2c", "jpf")),
    Format("jxl", "JPEG XL image", "photo", ("jxl",), ((0, _JXL_SIG),), parse_jxl, max_size=1 * GiB),
    # A bare JPEG XL codestream starts with only two signature bytes and doesn't record its length: off by
    # default, or every 65536th block of compressed data would start a bogus picture.
    Format("jxl-codestream", "JPEG XL codestream", "photo", ("jxl",), ((0, b"\xff\x0a"),), parse_jxl_codestream,
           max_size=64 * MiB, min_size=64, enabled=False, aliases=("jxlc",)),
    Format("exr", "OpenEXR image", "photo", ("exr",), ((0, b"\x76\x2f\x31\x01\x02"),), parse_exr,
           max_size=4 * GiB),
    Format("xcf", "GIMP image", "photo", ("xcf",), ((0, b"gimp xcf "),), parse_xcf, max_size=4 * GiB),
    Format("ico", "Windows icon", "photo", ("ico", "cur"), ((0, b"\0\0\x01\0"), (0, b"\0\0\x02\0")), parse_ico,
           max_size=16 * MiB, enabled=False, aliases=("cur",)),
    Format("svg", "SVG drawing", "photo", ("svg",), ((0, b"<svg"), (0, b"<?xml")), parse_svg, max_size=32 * MiB,
           enabled=False),
]
