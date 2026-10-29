"""The JPEG pictures stored inside camera RAW files (and inside photos), found and checked: any program can
show them, while the sensor data needs a RAW converter — and a damaged RAW file usually can't be developed
at all, but its full-size preview often survives.

* TIFF-based RAW files — Canon CR2, Nikon NEF/NRW, Sony ARW/SR2/SRF, Olympus ORF, Panasonic RW2, Pentax PEF,
  Adobe DNG, Samsung SRW, Hasselblad 3FR, Epson ERF, Kodak KDC/DCR, Leaf MOS, Phase One IIQ — are chains of
  IFDs (tag directories) with sub-IFDs. A preview is referenced by JPEGInterchangeFormat and its length (tags
  0x201/0x202), or it is an IFD's image strip when the IFD's compression is JPEG (6 or 7) and its pixels
  aren't sensor data; Panasonic keeps one as a JPEG in tag 0x2E. Canon CR2 has the full-size preview in IFD0,
  Nikon in the first sub-IFD, DNG in whichever sub-IFD is a JPEG.
* Canon CR3 (ISO media boxes): a small thumbnail in the THMB box, a 1620×1080 preview in the PRVW box and the
  full-size JPEG as the sample of the first track.
* Fujifilm RAF: the header records where its JPEG is.
* HEIC/AVIF photos are HEVC/AV1 pictures with no JPEG inside, but their EXIF block may carry a JPEG
  thumbnail; so may a JPEG photo (IFD1 of its EXIF block), which may also carry large previews listed by its
  MP extension (APP2 "MPF").

On top of what the structures say, the file is searched for JPEG start markers, so previews are found in a
file whose IFDs or boxes are damaged (and in makers' notes nobody documents). Every candidate is measured
(segments, then compressed data up to the end marker); the best preview is the largest that decodes
completely (media/jpegdec.py).

    for p in previews(data): p.offset, p.length, p.width, p.height, p.kind, p.source
    best = best_preview(data)          # or None
    plan = plan_raw(data, "IMG_0001.CR2")   # filerepair: a damaged RAW file → its preview as a JPEG
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

from ..carve.common import BytesReader, ifd_value, parse_tiff, read_ifd
from ..fs.base import NULL_CONTROL, Control

RAW_EXTS = frozenset({"cr2", "cr3", "crw", "nef", "nrw", "arw", "sr2", "srf", "orf", "rw2", "rwl", "pef", "dng",
                      "srw", "3fr", "erf", "kdc", "dcr", "mos", "iiq", "raf", "mef", "mrw", "x3f"})
_SOI = re.compile(rb"\xff\xd8\xff[\xc0-\xfe]")
_TIFF_HEADS = (b"II*\x00", b"MM\x00*", b"IIRO", b"IIRS", b"MMOR", b"IIU\x00")
_HEIF_BRANDS = (b"heic", b"heix", b"mif1", b"msf1", b"avif", b"avis", b"hevc", b"hevx")
_RAW_PHOTOMETRIC = {32803, 34892}           # CFA, linear raw: sensor data
_MAX_CANDIDATES = 256


@dataclass
class Preview:
    """A JPEG picture inside the file: ``length`` bytes from ``offset``."""
    offset: int
    length: int
    width: int
    height: int
    kind: str                   # "full-size", "preview" or "thumbnail"
    source: str                 # where it was found: "IFD0", "sub-IFD 1", "EXIF thumbnail", "RAF header", ...
    complete: bool              # its end marker is in the file
    valid: bool | None = None   # decodes completely (None: not checked)

    @property
    def end(self) -> int:
        return self.offset + self.length

    def describe(self) -> dict:
        return {"offset": self.offset, "length": self.length, "width": self.width, "height": self.height,
                "kind": self.kind, "source": self.source, "complete": self.complete}


# ---------------------------------------------------------------------- measuring a JPEG
def _measure(br: BytesReader, at: int) -> tuple[int, bool, int, int] | None:
    """(length, complete, width, height) of the JPEG at AT; None if it isn't one a viewer shows (lossless
    and arithmetic-coded JPEG — the sensor data of CR2 and DNG files — doesn't count)."""
    from ..carve.images import _tail_end, walk_jpeg
    st = walk_jpeg(br, at, meta=False)
    if st is None or not st["sof"] or not st["scans"] or st["end"] is None:
        return None
    if _sof_marker(br, at) not in (0xC0, 0xC1, 0xC2):
        return None
    end, complete = st["end"], st["complete"]
    if st["blank"]:                         # zeros: perhaps a dark area of the picture (optimised tables)
        end = _tail_end(br, st["ranges"][-1][0], blanks=False)
        complete = br.read(end - 2, 2) == b"\xff\xd9"
    return end - at, complete, st["sof"][0], st["sof"][1]


def _sof_marker(br: BytesReader, at: int) -> int:
    pos = at + 2
    for _ in range(512):
        h = br.read(pos, 4)
        if len(h) < 4 or h[0] != 0xFF:
            return 0
        if 0xC0 <= h[1] <= 0xCF and h[1] not in (0xC4, 0xC8, 0xCC):
            return h[1]
        if h[1] == 0xDA:
            return 0
        pos += 2 + ((h[2] << 8) | h[3])
    return 0


# ---------------------------------------------------------------------- what the structures say
def file_kind(buf) -> str:
    """"tiff" (and the RAW files built on it), "cr3", "raf", "heif", "jpeg" or ""."""
    head = bytes(buf[:16])
    if head[:4] in _TIFF_HEADS or head[:4] in (b"II+\x00", b"MM\x00+"):
        return "tiff"
    if head[:16] == b"FUJIFILMCCD-RAW ":
        return "raf"
    if head[4:12] == b"ftypcrx ":
        return "cr3"
    if head[4:8] == b"ftyp" and head[8:12] in _HEIF_BRANDS:
        return "heif"
    if head[:3] == b"\xff\xd8\xff":
        return "jpeg"
    return ""


def _first(v) -> int:
    return v[0] if isinstance(v, tuple) and v and isinstance(v[0], int) else 0


def _tiff_refs(buf, base: int = 0, limit_ifds: int = 64) -> list[tuple[int, int, str]]:
    """(offset, length, source) of the JPEG pictures the IFDs of the TIFF structure at BASE point at."""
    head = bytes(buf[base:base + 8])
    if len(head) < 8:
        return []
    order = "<" if head[:2] == b"II" else ">" if head[:2] == b"MM" else ""
    if not order:
        return []
    br = BytesReader(bytes(buf[base:]) if base else buf)       # offsets count from the TIFF header
    out: list[tuple[int, int, str]] = []
    queue: list[tuple[int, str]] = [(struct.unpack_from(order + "I", head, 4)[0], "IFD0")]
    seen: set[int] = set()
    nth = 0
    while queue and len(seen) < limit_ifds:
        off, name = queue.pop(0)
        if off < 8 or off in seen or off >= br.limit:
            continue
        seen.add(off)
        got = read_ifd(br, off, order)
        if got is None:
            continue
        entries, nxt, _end = got
        tags = {}
        for e in entries:
            if e.tag in (0x103, 0x106, 0x111, 0x117, 0x201, 0x202, 0x14A, 0x8769, 0xC640):
                tags[e.tag] = ifd_value(br, e, order)
            elif e.tag == 0x2E and e.type == 7 and e.size > 1024:            # Panasonic JpgFromRaw
                out.append((base + e.offset, e.size, "Panasonic preview"))
        a, n = _first(tags.get(0x201)), _first(tags.get(0x202))
        if a and n:
            out.append((base + a, n, name if name != "IFD1" else "EXIF thumbnail"))
        comp, phot = _first(tags.get(0x103)), _first(tags.get(0x106))
        strips, counts = tags.get(0x111), tags.get(0x117)
        if comp in (6, 7) and phot not in _RAW_PHOTOMETRIC and 0xC640 not in tags and \
                isinstance(strips, tuple) and isinstance(counts, tuple) and strips and len(strips) == len(counts):
            if all(strips[i] + counts[i] == strips[i + 1] for i in range(len(strips) - 1)):
                out.append((base + strips[0], sum(counts), name))
        subs = tags.get(0x14A)
        if isinstance(subs, tuple):
            queue.extend((int(s), f"sub-IFD {k + 1}") for k, s in enumerate(subs[:16]))
        if isinstance(tags.get(0x8769), tuple):
            queue.append((_first(tags[0x8769]), "EXIF"))
        if nxt and name.startswith("IFD"):
            nth += 1
            queue.append((nxt, f"IFD{nth}"))
    return out


def _jpeg_refs(buf) -> list[tuple[int, int, str]]:
    """The EXIF thumbnail and the MP extension's pictures of the JPEG photo in BUF."""
    out: list[tuple[int, int, str]] = []
    pos = 2
    end = min(len(buf), 1 << 20)
    for _ in range(64):
        if pos + 4 > end or buf[pos] != 0xFF:
            break
        mk = buf[pos + 1]
        length = (buf[pos + 2] << 8) | buf[pos + 3]
        if mk == 0xDA or length < 2:
            break
        body = pos + 4
        if mk == 0xE1 and bytes(buf[body:body + 6]) == b"Exif\x00\x00":
            for a, n, src in _tiff_refs(buf, body + 6, 8):
                if src == "EXIF thumbnail" and a + n <= body + length:
                    out.append((a, n, src))
        elif mk == 0xE2 and bytes(buf[body:body + 4]) == b"MPF\x00":
            from ..carve.images import _mpf_images
            tiff_at = body + 4
            for k, (_attr, size, off) in enumerate(_mpf_images(bytes(buf[tiff_at:body + length - 2]))):
                if off and size >= 64:
                    out.append((tiff_at + off, size, f"MPF picture {k + 1}"))
        pos += 2 + length
    return out


def _raf_refs(buf) -> list[tuple[int, int, str]]:
    if len(buf) < 92:
        return []
    off, n = struct.unpack_from(">II", buf, 84)
    return [(off, n, "RAF header")] if off >= 92 and n else []


def _heif_refs(buf) -> list[tuple[int, int, str]]:
    """The thumbnail of a HEIC photo's EXIF block (the photo itself is HEVC-coded: no JPEG)."""
    i = bytes(buf[:4 << 20]).find(b"Exif\x00\x00")
    if i < 0:
        return []
    return [(a, n, src) for a, n, src in _tiff_refs(buf, i + 6, 8) if src == "EXIF thumbnail"]


def _labels(buf, at: int) -> str:
    """CR3: which box the JPEG at AT is in."""
    before = bytes(buf[max(0, at - 32):at])
    if b"PRVW" in before:
        return "CR3 preview (PRVW)"
    if b"THMB" in before:
        return "CR3 thumbnail (THMB)"
    return "found by its signature"


# ---------------------------------------------------------------------- the API
def previews(buf) -> list[Preview]:
    """Every JPEG picture found in the file in BUF (a RAW file, a HEIC or a JPEG photo — not counting the
    JPEG photo itself), the most useful first: complete ones, then by size."""
    kind = file_kind(buf)
    refs: list[tuple[int, int, str]] = []
    try:
        if kind == "tiff":
            refs = _tiff_refs(buf)
        elif kind == "raf":
            refs = _raf_refs(buf)
        elif kind == "jpeg":
            refs = _jpeg_refs(buf)
        elif kind == "heif":
            refs = _heif_refs(buf)
    except (struct.error, IndexError, ValueError, OverflowError):
        refs = []
    br = BytesReader(buf)
    found: dict[int, Preview] = {}
    size = len(buf)
    for a, n, src in refs:
        if not 0 < a < size or a in found or bytes(buf[a:a + 3]) != b"\xff\xd8\xff":
            continue
        got = _measure(br, a)
        if got is None:
            continue
        length, complete, w, h = got
        if not complete and n:
            length = min(n, size - a)               # cut short: as much as the structure says is there
        found[a] = Preview(a, length, w, h, "", src, complete)
    for i, m in enumerate(_SOI.finditer(buf)):
        if i >= _MAX_CANDIDATES:
            break
        a = m.start()
        if a == 0 and kind == "jpeg" or a in found:
            continue
        got = _measure(br, a)
        if got is None or got[0] < 128:
            continue
        length, complete, w, h = got
        found[a] = Preview(a, length, w, h, "", _labels(buf, a) if kind == "cr3" else "found by its signature",
                           complete)
    out = [p for p in found.values() if not any(q.offset < p.offset < q.end and q.complete and q.width * q.height >
                                                 p.width * p.height and _inside_app(buf, q, p) for q in found.values())]
    biggest = max((p.width * p.height for p in out), default=0)
    sensor = _sensor_area(buf, kind)
    for p in out:
        area = p.width * p.height
        if area >= max(biggest, 1) * 0.9 and (not sensor or area * 4 >= sensor):
            p.kind = "full-size"
        elif max(p.width, p.height) <= 320:
            p.kind = "thumbnail"
        else:
            p.kind = "preview"
    out.sort(key=lambda p: (p.complete, p.width * p.height, p.length), reverse=True)
    return out


def _inside_app(buf, outer: Preview, inner: Preview) -> bool:
    """INNER is the EXIF thumbnail inside OUTER's header (it is listed for OUTER, not on its own)."""
    from ..carve.images import walk_jpeg
    st = walk_jpeg(BytesReader(buf), outer.offset, meta=False, entropy=False)
    return bool(st) and st["end"] is not None and inner.offset < st["end"]


def _sensor_area(buf, kind: str) -> int:
    if kind != "tiff":
        return 0
    try:
        t = parse_tiff(BytesReader(buf), max_ifds=32)
    except (struct.error, IndexError, ValueError):
        return 0
    return t.width * t.height if t else 0


def best_preview(buf, validate: bool = True) -> Preview | None:
    """The largest preview that decodes completely (VALIDATE False: the largest complete one, not decoded);
    failing that, the largest that decodes at least half-way (cut short: it needs an end marker)."""
    from . import jpegdec
    cands = previews(buf)
    if not validate:
        return next((p for p in cands if p.complete), cands[0] if cands else None)
    partial: tuple[float, Preview] | None = None
    for p in cands[:12]:
        res = jpegdec.decode_check(buf, p.offset, p.end)
        p.valid = res.ok
        if res.ok:
            return p
        frac = res.fraction
        if res.supported and frac >= 0.5 and (partial is None or frac * p.width * p.height >
                                              partial[0] * partial[1].width * partial[1].height):
            p.length = max(16, res.good_end - p.offset)       # up to the damage (an end marker is added)
            partial = (frac, p)
    return partial[1] if partial else None


# ---------------------------------------------------------------------- damage
def _raw_damage(buf, kind: str) -> list[str]:
    """What is wrong with the RAW file's structure, in plain sentences ([] when it looks whole)."""
    size = len(buf)
    if kind == "tiff":
        try:
            t = parse_tiff(BytesReader(buf))
        except (struct.error, IndexError, ValueError, OverflowError):
            t = None
        if t is None:
            return ["The RAW file's header or first directory is damaged"]
        if t.end > size:
            return [f"The RAW file is cut short: {_mb(t.end - size)} of its data are missing"]
        if t.damaged:
            return ["The RAW file's directories are damaged (they point outside the file)"]
        return []
    if kind == "raf":
        if size < 108:
            return ["The RAW file is cut short inside its header"]
        pairs = struct.unpack_from(">6I", buf, 84)
        need = max((pairs[i] + pairs[i + 1] for i in range(0, 6, 2) if pairs[i + 1]), default=0)
        return [f"The RAW file is cut short: {_mb(need - size)} of its data are missing"] if need > size else []
    if kind == "cr3":
        pos, boxes = 0, []
        while pos + 8 <= size and len(boxes) < 10000:
            n, typ = struct.unpack_from(">I4s", buf, pos)
            if n == 1 and pos + 16 <= size:
                n = struct.unpack_from(">Q", buf, pos + 8)[0]
            elif n == 0:
                n = size - pos
            if n < 8:
                return ["The RAW file's structure is damaged"]
            boxes.append(typ)
            if pos + n > size:
                return [f"The RAW file is cut short inside its “{typ.decode('latin-1')}” box: "
                        f"{_mb(pos + n - size)} are missing"]
            pos += n
        if b"moov" not in boxes or b"mdat" not in boxes:
            return ["The RAW file's structure is damaged (its index or its data is missing)"]
        return []
    return []


def _mb(n: int) -> str:
    return f"{n / 1e6:.1f} MB" if n >= 100_000 else f"{n} bytes"


def plan_raw(buf, path, reference=None, data_offset=None, ctl: Control = NULL_CONTROL):
    """The file-repair handler for camera RAW files: an intact one has no problems (``info["preview"]``
    describes its best preview); a damaged or cut-short one is "repaired" into its full-size preview, saved
    as a JPEG (``info["output_ext"]`` "jpg", ``info["output"]`` "preview")."""
    from ..filerepair import Plan
    ext = Path(str(path)).suffix.lower().lstrip(".")
    kind = file_kind(buf)
    plan = Plan(ext if ext in RAW_EXTS else "raw")
    if len(buf) < 16 or not kind or kind == "jpeg":
        plan.problem("The file doesn't start like a camera RAW file")
        plan.note = "Its header is damaged or missing: no preview picture can be found by its structure."
        pv = best_preview(buf) if len(buf) >= 16 else None
        if pv is not None:
            _use_preview(plan, pv)
        return plan
    damage = _raw_damage(buf, kind)
    pv = best_preview(buf, validate=bool(damage))
    if pv is not None:
        plan.info["preview"] = pv.describe()
    if not damage:
        return plan
    for d in damage:
        plan.problem(d)
    if pv is None:
        plan.note = "No intact preview picture was found in it: there is nothing that can be saved."
        return plan
    _use_preview(plan, pv)
    return plan


def _use_preview(plan, pv: Preview) -> None:
    what = "full-size preview" if pv.kind == "full-size" else "preview" if pv.kind == "preview" else "thumbnail"
    plan.actions.append(f"Save the {what} ({pv.width}×{pv.height}) as a JPEG")
    plan.note = ("A damaged RAW file can't be developed: the repaired copy is the JPEG picture the camera stored "
                 "with it, not the RAW image." + ("" if pv.valid is not False else
                                                   " The preview is damaged too: its lower part shows grey."))
    plan.info.update(preview=pv.describe(), output_ext="jpg", output="preview")
    plan.repairable = True
    pieces = [(pv.offset, pv.end)] + ([] if pv.valid is not False else [b"\xff\xd9"])
    plan.build = lambda: pieces
