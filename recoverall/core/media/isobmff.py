"""ISO base media files (MP4, MOV, 3GP, M4V, M4A, HEIF): boxes, and the movie box's tracks and sample tables.

A file is a sequence of boxes: a 32-bit big-endian size (1: a 64-bit size follows the type; 0: up to the end
of the file), a four-character type, then the payload; container boxes (moov, trak, mdia, minf, stbl, ...)
hold more boxes. The movie box (moov) describes every track; the samples themselves (video frames, audio
frames) lie in media data boxes (mdat), located by the sample tables:

=======  ==================================================================================================
stsd     the sample description: the codec ("avc1", "hvc1", "mp4a", "sowt"...) and its configuration
stts     decoding time to sample: runs of (count, duration)
ctts     composition offsets (B-frames): runs of (count, offset)
stss     sync samples (key frames), 1-based; absent: every sample is a key frame
stsz     sample sizes (or one size for all); stz2 is the compact form
stsc     sample to chunk: runs of (first chunk, samples per chunk, description index)
stco     chunk offsets (32-bit); co64 the 64-bit form
=======  ==================================================================================================

Fragmented files (recorded for streaming, and by some cameras) keep an empty sample table and put the samples
in movie fragments instead: a moof box (track fragment headers with defaults, and track runs listing each
sample's size, duration, flags and composition offset) before the mdat that holds them.

Everything here reads from anything that slices like bytes (bytes, bytearray, mmap) and never raises on a
damaged file: what can't be read is left out, and :attr:`Box.truncated` says when a box runs past the data.
For writing there are the box builders (:func:`box`, :func:`full_box`), the sample tables from lists
(:func:`stts_box`, :func:`stco_box`, ...), edit lists, header fields with a new duration, and :func:`rewrite`,
which rebuilds a box tree with some boxes replaced (the media repair uses it to shorten or replace tables).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator

# boxes that only hold other boxes (what walk() descends into)
CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"dinf", b"edts", b"udta", b"mvex", b"moof", b"traf",
              b"mfra", b"skip", b"tref", b"sinf", b"schi", b"gmhd", b"tapt", b"iprp", b"ipco", b"meco", b"strk",
              b"strd"}
# a "meta" box is a full box (version and flags first) in ISO files, a plain container in QuickTime
FULL_CONTAINERS = {b"meta"}
TOP_LEVEL = {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"pnot", b"uuid", b"meta", b"moof", b"mfra",
             b"sidx", b"styp", b"pdin", b"prft", b"emsg", b"junk", b"PICT", b"ssix", b"mdia"}


def be16(b, o: int) -> int:
    return (b[o] << 8) | b[o + 1]


def be32(b, o: int) -> int:
    return struct.unpack_from(">I", b, o)[0]


def be64(b, o: int) -> int:
    return struct.unpack_from(">Q", b, o)[0]


def is_fourcc(t: bytes) -> bool:
    """Printable box type (letters, digits, space, a few marks; QuickTime uses ©)."""
    return len(t) == 4 and all(32 <= c < 127 or c == 0xA9 for c in t)


@dataclass
class Box:
    """A box: TYPE at START; its payload is [START + header, END). SIZE is what the box says (END is clipped
    to the data, TRUNCATED when it was)."""
    type: bytes
    start: int
    header: int
    size: int
    end: int
    truncated: bool = False

    @property
    def payload(self) -> int:
        return self.start + self.header

    @property
    def name(self) -> str:
        return self.type.decode("latin-1")


def iter_boxes(buf, start: int = 0, end: int | None = None, strict: bool = True) -> Iterator[Box]:
    """The boxes one after the other in [START, END). STRICT stops at a type that isn't four printable
    characters (garbage, or the end of the real boxes)."""
    end = len(buf) if end is None else min(end, len(buf))
    pos = start
    while pos + 8 <= end:
        size = be32(buf, pos)
        btype = bytes(buf[pos + 4:pos + 8])
        if strict and not is_fourcc(btype):
            return
        header = 8
        if size == 1:
            if pos + 16 > end:
                return
            size = be64(buf, pos + 8)
            header = 16
        elif size == 0:
            size = end - pos
        if size < header:
            return
        stop = pos + size
        yield Box(btype, pos, header, size, min(stop, end), stop > end)
        if stop > end:
            return
        pos = stop


def children(buf, box: Box) -> Iterator[Box]:
    """The boxes inside a container box (a full container skips its version/flags)."""
    skip = 4 if box.type in FULL_CONTAINERS and _meta_is_full(buf, box) else 0
    if box.type == b"stsd":
        skip = 8                                   # version/flags, entry count
    yield from iter_boxes(buf, box.payload + skip, box.end)


def _meta_is_full(buf, box: Box) -> bool:
    # ISO "meta" starts with 4 bytes of version/flags, QuickTime's "meta" directly with a box (usually hdlr)
    p = box.payload
    return not (p + 8 <= box.end and bytes(buf[p + 4:p + 8]) in (b"hdlr", b"keys", b"ilst"))


def walk(buf, start: int = 0, end: int | None = None, depth: int = 0) -> Iterator[tuple[int, Box]]:
    """Every box with its depth, descending into containers."""
    for b in iter_boxes(buf, start, end):
        yield depth, b
        if (b.type in CONTAINERS or b.type in FULL_CONTAINERS) and depth < 16:
            skip = 4 if b.type in FULL_CONTAINERS and _meta_is_full(buf, b) else 0
            yield from walk(buf, b.payload + skip, b.end, depth + 1)


def find(buf, path: str, start: int = 0, end: int | None = None) -> Box | None:
    """The first box at PATH ("moov/trak/mdia/mdhd") below [START, END)."""
    return next(find_all(buf, path, start, end), None)


def find_all(buf, path: str, start: int = 0, end: int | None = None) -> Iterator[Box]:
    parts = [p.encode("latin-1") for p in path.split("/") if p]
    if not parts:
        return

    def rec(boxes: Iterator[Box], i: int):
        for b in boxes:
            if b.type != parts[i]:
                continue
            if i == len(parts) - 1:
                yield b
            else:
                yield from rec(children(buf, b), i + 1)
    yield from rec(iter_boxes(buf, start, end), 0)


def top_level(buf) -> list[Box]:
    """The top-level boxes of a file, in order (up to the first garbage)."""
    return list(iter_boxes(buf, 0, len(buf)))


# ---------------------------------------------------------------------- writing boxes
def box(btype: bytes | str, *payload: bytes) -> bytes:
    """A box: size, type, payload (a 64-bit size when it needs one)."""
    t = btype.encode("latin-1") if isinstance(btype, str) else btype
    body = b"".join(payload)
    n = 8 + len(body)
    if n > 0xFFFFFFFF:
        return struct.pack(">I", 1) + t + struct.pack(">Q", n + 8) + body
    return struct.pack(">I", n) + t + body


def full_box(btype: bytes | str, version: int, flags: int, *payload: bytes) -> bytes:
    return box(btype, struct.pack(">I", (version << 24) | (flags & 0xFFFFFF)), *payload)


# ---------------------------------------------------------------------- the movie box
@dataclass
class Track:
    """One track of a movie, with its sample tables expanded where that is cheap (sizes, chunk offsets) and
    kept as runs where it isn't (times)."""
    id: int = 0
    handler: str = ""                     # "vide", "soun", "tmcd", "meta", "text", "sbtl", "hint"...
    timescale: int = 0                    # of the media (mdhd)
    duration: int = 0                     # in the media timescale
    language: str = ""
    codec: str = ""                       # the sample entry type: "avc1", "hvc1", "mp4a", "sowt", "mp4v"...
    stsd: bytes = b""                     # the whole stsd box (codec configuration), to copy into a new movie
    entry: bytes = b""                    # the first sample entry's payload (after its type)
    width: int = 0
    height: int = 0
    channels: int = 0
    sample_rate: int = 0
    sample_bits: int = 0
    tkhd: bytes = b""                     # whole boxes kept to copy into a rebuilt movie
    mdhd: bytes = b""
    hdlr: bytes = b""
    minf_header: bytes = b""              # vmhd / smhd / gmhd / nmhd
    dinf: bytes = b""
    edts: bytes = b""
    tref: bytes = b""
    udta: bytes = b""
    sizes: list[int] = field(default_factory=list)        # one per sample
    chunk_offsets: list[int] = field(default_factory=list)
    stsc: list[tuple[int, int, int]] = field(default_factory=list)   # (first chunk, samples per chunk, desc)
    stts: list[tuple[int, int]] = field(default_factory=list)        # (count, duration)
    ctts: list[tuple[int, int]] = field(default_factory=list)        # (count, offset), offsets may be signed
    ctts_version: int = 0
    stss: list[int] | None = None                              # 1-based sync samples, None: all are
    problems: list[str] = field(default_factory=list)

    @property
    def samples(self) -> int:
        return len(self.sizes)

    def chunks(self) -> Iterator[tuple[int, int, int]]:
        """(file offset of the chunk, first sample index, number of samples) for every chunk."""
        runs = self.stsc or [(1, 1, 1)]
        sample = 0
        n_chunks = len(self.chunk_offsets)
        for i, (first, per, _desc) in enumerate(runs):
            last = runs[i + 1][0] - 1 if i + 1 < len(runs) else n_chunks
            for c in range(first - 1, min(last, n_chunks)):
                if sample >= len(self.sizes):
                    return
                n = min(per, len(self.sizes) - sample)
                yield self.chunk_offsets[c], sample, n
                sample += n

    def sample_offsets(self) -> list[int]:
        """The file offset of every sample."""
        out = [0] * len(self.sizes)
        for off, first, n in self.chunks():
            for k in range(first, first + n):
                out[k] = off
                off += self.sizes[k]
        return out

    def durations(self) -> list[int]:
        """The decoding duration of every sample."""
        out: list[int] = []
        for count, d in self.stts:
            out.extend([d] * count)
        return out[:len(self.sizes)]

    def keyframes(self) -> set[int]:
        """0-based indexes of the sync samples."""
        if self.stss is None:
            return set(range(len(self.sizes)))
        return {k - 1 for k in self.stss}

    def config(self, kind: bytes) -> bytes | None:
        """The payload of a box inside the sample entry ("avcC", "hvcC", "esds", "dOps", "glbl"...)."""
        for start in _entry_box_starts(self):
            for b in iter_boxes(self.entry, start, len(self.entry), strict=False):
                if b.type == kind:
                    return bytes(self.entry[b.payload:b.end])
                if b.type == b"wave":                         # QuickTime audio: esds inside a wave box
                    for c in iter_boxes(self.entry, b.payload, b.end, strict=False):
                        if c.type == kind:
                            return bytes(self.entry[c.payload:c.end])
        return None


def _entry_box_starts(t: Track) -> list[int]:
    """Where the boxes after a sample entry's fixed fields may start (the layout depends on the kind)."""
    if t.handler == "vide":
        return [78]
    if t.handler == "soun":
        version = be16(t.entry, 8) if len(t.entry) >= 10 else 0
        return [{1: 44, 2: 64}.get(version, 28), 28]
    return [8, 16, 24]


@dataclass
class Movie:
    timescale: int = 0
    duration: int = 0
    mvhd: bytes = b""
    tracks: list[Track] = field(default_factory=list)
    udta: bytes = b""
    meta: bytes = b""
    other: list[bytes] = field(default_factory=list)       # other boxes of moov, kept as they are
    fragmented: bool = False                               # an mvex box: the samples are in moof fragments

    def track(self, handler: str) -> Track | None:
        return next((t for t in self.tracks if t.handler == handler), None)


def parse_moov(buf, moov: Box) -> Movie:
    """The movie described by the moov box MOOV of BUF. Damaged parts are left out (and noted in the tracks'
    problems)."""
    m = Movie()
    for b in children(buf, moov):
        raw = bytes(buf[b.start:b.end])
        if b.type == b"mvhd":
            m.mvhd = raw
            p = b.payload
            v = buf[p]
            if v == 1 and b.end >= p + 32:
                m.timescale, m.duration = be32(buf, p + 20), be64(buf, p + 24)
            elif b.end >= p + 20:
                m.timescale, m.duration = be32(buf, p + 12), be32(buf, p + 16)
        elif b.type == b"trak":
            t = _parse_trak(buf, b)
            if t is not None:
                m.tracks.append(t)
        elif b.type == b"udta":
            m.udta = raw
        elif b.type == b"meta":
            m.meta = raw
        elif b.type == b"mvex":
            m.fragmented = True
            m.other.append(raw)
        elif b.type not in (b"free", b"skip"):
            m.other.append(raw)
    return m


def _parse_trak(buf, trak: Box) -> Track | None:
    t = Track()
    for b in children(buf, trak):
        raw = bytes(buf[b.start:b.end])
        if b.type == b"tkhd":
            t.tkhd = raw
            p = b.payload
            v = buf[p] if p < b.end else 0
            idoff = p + (20 if v == 1 else 12)
            if idoff + 4 <= b.end:
                t.id = be32(buf, idoff)
            wh = b.end - 8
            if wh >= p:
                t.width, t.height = be32(buf, wh) >> 16, be32(buf, wh + 4) >> 16
        elif b.type == b"edts":
            t.edts = raw
        elif b.type == b"tref":
            t.tref = raw
        elif b.type == b"udta":
            t.udta = raw
        elif b.type == b"mdia":
            _parse_mdia(buf, b, t)
    return t if t.handler or t.sizes else None


def _parse_mdia(buf, mdia: Box, t: Track) -> None:
    for b in children(buf, mdia):
        raw = bytes(buf[b.start:b.end])
        p = b.payload
        if b.type == b"mdhd":
            t.mdhd = raw
            v = buf[p] if p < b.end else 0
            if v == 1 and b.end >= p + 32:
                t.timescale, t.duration = be32(buf, p + 20), be64(buf, p + 24)
                lang = be16(buf, p + 32) if b.end >= p + 34 else 0
            elif b.end >= p + 20:
                t.timescale, t.duration = be32(buf, p + 12), be32(buf, p + 16)
                lang = be16(buf, p + 20) if b.end >= p + 22 else 0
            else:
                lang = 0
            if lang and lang < 0x8000:
                t.language = "".join(chr(((lang >> s) & 31) + 0x60) for s in (10, 5, 0))
        elif b.type == b"hdlr":
            t.hdlr = raw
            if b.end >= p + 12:
                t.handler = bytes(buf[p + 8:p + 12]).decode("latin-1")
        elif b.type == b"minf":
            for c in children(buf, b):
                craw = bytes(buf[c.start:c.end])
                if c.type in (b"vmhd", b"smhd", b"gmhd", b"nmhd", b"hmhd", b"sthd"):
                    t.minf_header = craw
                elif c.type == b"dinf":
                    t.dinf = craw
                elif c.type == b"stbl":
                    _parse_stbl(buf, c, t)


def _parse_stbl(buf, stbl: Box, t: Track) -> None:
    for b in children(buf, stbl):
        p, e = b.payload, b.end
        try:
            if b.type == b"stsd":
                t.stsd = bytes(buf[b.start:b.end])
                entries = list(iter_boxes(buf, p + 8, e, strict=False))
                if entries:
                    ent = entries[0]
                    t.codec = ent.name
                    t.entry = bytes(buf[ent.payload:ent.end])
                    _entry_fields(t)
            elif b.type == b"stsz":
                size, count = be32(buf, p + 4), be32(buf, p + 8)
                count = min(count, max(0, (e - p - 12) // 4) if size == 0 else count)
                t.sizes = [size] * count if size else list(struct.unpack_from(f">{count}I", buf, p + 12))
            elif b.type == b"stz2":
                bits, count = buf[p + 7], be32(buf, p + 8)
                q = p + 12
                if bits == 16:
                    count = min(count, (e - q) // 2)
                    t.sizes = list(struct.unpack_from(f">{count}H", buf, q))
                elif bits == 8:
                    t.sizes = list(buf[q:q + min(count, e - q)])
                elif bits == 4:
                    out = []
                    for i in range(min(count, (e - q) * 2)):
                        byte = buf[q + i // 2]
                        out.append(byte >> 4 if i % 2 == 0 else byte & 15)
                    t.sizes = out
            elif b.type in (b"stco", b"co64"):
                count = be32(buf, p + 4)
                w = 4 if b.type == b"stco" else 8
                count = min(count, (e - p - 8) // w)
                t.chunk_offsets = list(struct.unpack_from(f">{count}{'I' if w == 4 else 'Q'}", buf, p + 8))
            elif b.type == b"stsc":
                count = min(be32(buf, p + 4), (e - p - 8) // 12)
                t.stsc = [struct.unpack_from(">III", buf, p + 8 + 12 * i) for i in range(count)]
            elif b.type == b"stts":
                count = min(be32(buf, p + 4), (e - p - 8) // 8)
                t.stts = [struct.unpack_from(">II", buf, p + 8 + 8 * i) for i in range(count)]
            elif b.type == b"ctts":
                t.ctts_version = buf[p]
                count = min(be32(buf, p + 4), (e - p - 8) // 8)
                fmt = ">Ii" if t.ctts_version == 1 else ">II"
                t.ctts = [struct.unpack_from(fmt, buf, p + 8 + 8 * i) for i in range(count)]
            elif b.type == b"stss":
                count = min(be32(buf, p + 4), (e - p - 8) // 4)
                t.stss = list(struct.unpack_from(f">{count}I", buf, p + 8))
        except (struct.error, IndexError):
            t.problems.append(f"The {b.name} table is damaged")


def _entry_fields(t: Track) -> None:
    e = t.entry
    try:
        if t.handler == "vide" and len(e) >= 28:
            t.width, t.height = be16(e, 24), be16(e, 26)
        elif t.handler == "soun" and len(e) >= 28:
            t.channels, t.sample_bits = be16(e, 16), be16(e, 18)
            t.sample_rate = be32(e, 24) >> 16
            if be16(e, 8) == 2 and len(e) >= 64:            # QuickTime sound description v2
                t.sample_rate = int(struct.unpack_from(">d", e, 32)[0])
                t.channels = be32(e, 40)
                t.sample_bits = be32(e, 48)
    except (struct.error, IndexError):
        pass


def movie_of(buf) -> tuple[Movie | None, list[Box]]:
    """The movie of a whole file (None without a moov box) and its top-level boxes."""
    boxes = top_level(buf)
    moov = next((b for b in boxes if b.type == b"moov" and not b.truncated), None)
    return (parse_moov(buf, moov) if moov is not None else None), boxes


def describe(buf) -> dict:
    """What a movie is, for previews: {"has_index", "duration" (s), "width", "height", "video", "audio",
    "fps", "frames", "channels", "sample_rate", "tracks", "fragmented"}. BUF is the file's bytes (anything that
    slices like bytes) or its path. A file whose index is missing gives {"has_index": False, "fragmented"};
    {} when it isn't an ISO media file at all."""
    if isinstance(buf, str) or hasattr(buf, "__fspath__"):
        import mmap
        import os
        with open(buf, "rb") as f:
            if not os.fstat(f.fileno()).st_size:
                return {}
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                return describe(m)
    m, boxes = movie_of(buf)
    if m is None:
        kinds = {b.type for b in boxes}
        if kinds & {b"mdat", b"moof", b"ftyp"}:
            return {"has_index": False, "fragmented": b"moof" in kinds}
        return {}
    out: dict = {"has_index": True, "tracks": len(m.tracks), "fragmented": m.fragmented}
    if m.timescale:
        out["duration"] = round(m.duration / m.timescale, 3)
    v = m.track("vide")
    if v is not None:
        out.update(video=v.codec, width=v.width, height=v.height, frames=v.samples)
        if v.timescale and v.samples and v.duration:
            out["fps"] = round(v.samples * v.timescale / v.duration, 3)
    a = m.track("soun")
    if a is not None:
        out.update(audio=a.codec, channels=a.channels, sample_rate=a.sample_rate)
    return out


# ---------------------------------------------------------------------- edit lists and header fields
def parse_elst(edts: bytes) -> list[tuple[int, int, float]]:
    """The entries of the edit list in an edts box: (segment duration in the movie timescale, media time in the
    media timescale or -1 for an empty edit, rate)."""
    out: list[tuple[int, int, float]] = []
    b = find(edts, "edts/elst")
    if b is None:
        return out
    p = b.payload
    try:
        v = edts[p]
        count = be32(edts, p + 4)
        q = p + 8
        for _ in range(min(count, 4096)):
            if v == 1:
                d, t = struct.unpack_from(">Qq", edts, q)
                q += 16
            else:
                d, t = struct.unpack_from(">Ii", edts, q)
                q += 8
            rate = struct.unpack_from(">i", edts, q)[0] / 65536
            q += 4
            out.append((d, t, rate))
    except (struct.error, IndexError):
        pass
    return out


def edts_box(entries: list[tuple[int, int, float]]) -> bytes:
    """An edts box holding an edit list of ENTRIES (as parse_elst returns them)."""
    v = 1 if any(d > 0xFFFFFFFF or not -0x80000000 <= t <= 0x7FFFFFFF for d, t, _r in entries) else 0
    body = [struct.pack(">I", len(entries))]
    for d, t, rate in entries:
        body.append(struct.pack(">Qq" if v else ">Ii", d, t) + struct.pack(">i", int(round(rate * 65536))))
    return box("edts", full_box("elst", v, 0, *body))


# where version 0 / version 1 full boxes keep their times and duration: (creation, modification, duration)
_TIME_FIELDS = {b"mvhd": ((4, 8, 16, 4), (4, 12, 24, 8)), b"mdhd": ((4, 8, 16, 4), (4, 12, 24, 8)),
                b"tkhd": ((4, 8, 20, 4), (4, 12, 28, 8))}


def with_duration(raw: bytes, duration: int, clear_times: bool = False) -> bytes:
    """A copy of the mvhd, tkhd or mdhd box RAW with DURATION (and creation/modification times 0 when
    CLEAR_TIMES); a version 0 box becomes version 1 when the duration doesn't fit 32 bits."""
    t = bytes(raw[4:8])
    if t not in _TIME_FIELDS or len(raw) < 32:
        return bytes(raw)
    v = raw[8]
    if v == 0 and duration > 0xFFFFFFFF:
        raw = _to_version1(raw)
        v = 1
    c, m, d, w = _TIME_FIELDS[t][1 if v == 1 else 0]
    out = bytearray(raw)
    base = 8
    if base + d + w > len(out):
        return bytes(raw)
    out[base + d:base + d + w] = duration.to_bytes(w, "big")
    if clear_times:
        tw = 8 if v == 1 else 4
        out[base + c:base + c + tw] = bytes(tw)
        out[base + m:base + m + tw] = bytes(tw)
    return bytes(out)


def _to_version1(raw: bytes) -> bytes:
    """A version 0 mvhd/tkhd/mdhd box rewritten as version 1 (64-bit times and duration)."""
    t = bytes(raw[4:8])
    p = bytes(raw[12:])                                   # after size, type, version/flags
    if t == b"tkhd":
        creation, mod, tid, res, dur = struct.unpack_from(">IIIII", p, 0)
        body = struct.pack(">QQIIQ", creation, mod, tid, res, dur) + p[20:]
    else:
        creation, mod, scale, dur = struct.unpack_from(">IIII", p, 0)
        body = struct.pack(">QQIQ", creation, mod, scale, dur) + p[16:]
    return full_box(t, 1, struct.unpack(">I", raw[8:12])[0] & 0xFFFFFF, body)


def track_id_of(tkhd: bytes) -> int:
    """The track ID in a tkhd box (or in a trak box that starts with its tkhd)."""
    try:
        if tkhd[4:8] == b"trak":
            tkhd = tkhd[8:]
        return be32(tkhd, 28 if tkhd[8] == 1 else 20)
    except (struct.error, IndexError):
        return 0


# ---------------------------------------------------------------------- sample tables
def runs(values) -> list[tuple[int, int]]:
    """Run-length (count, value) pairs."""
    out: list[list[int]] = []
    for v in values:
        if out and out[-1][1] == v:
            out[-1][0] += 1
        else:
            out.append([1, v])
    return [(c, v) for c, v in out]


def stts_box(run_list: list[tuple[int, int]]) -> bytes:
    """stts from (count, duration) runs."""
    return full_box("stts", 0, 0, struct.pack(">I", len(run_list)),
                    b"".join(struct.pack(">II", c, d) for c, d in run_list))


def ctts_box(run_list: list[tuple[int, int]]) -> bytes:
    """ctts from (count, offset) runs; version 1 when an offset is negative."""
    v = 1 if any(o < 0 for _c, o in run_list) else 0
    return full_box("ctts", v, 0, struct.pack(">I", len(run_list)),
                    b"".join(struct.pack(">Ii" if v else ">II", c, o) for c, o in run_list))


def stss_box(sync: list[int]) -> bytes:
    """stss from 0-based sync sample indexes."""
    return full_box("stss", 0, 0, struct.pack(">I", len(sync)), struct.pack(f">{len(sync)}I", *(k + 1 for k in sync)))


def stsz_box(sizes, count: int | None = None, const: int = 0) -> bytes:
    """stsz: one size for all COUNT samples (CONST), or a table of SIZES."""
    if const:
        return full_box("stsz", 0, 0, struct.pack(">II", const, count or 0))
    if sizes and min(sizes) == max(sizes):
        return full_box("stsz", 0, 0, struct.pack(">II", sizes[0], len(sizes)))
    return full_box("stsz", 0, 0, struct.pack(">II", 0, len(sizes)), struct.pack(f">{len(sizes)}I", *sizes))


def stsc_box(chunk_counts) -> bytes:
    """stsc from the number of samples in every chunk (all with sample description 1)."""
    entries = []
    last = None
    for i, n in enumerate(chunk_counts):
        if n != last:
            entries.append(struct.pack(">III", i + 1, n, 1))
            last = n
    return full_box("stsc", 0, 0, struct.pack(">I", len(entries)), b"".join(entries))


def stco_box(offsets) -> bytes:
    """stco, or co64 when an offset needs more than 32 bits."""
    big = bool(offsets) and max(offsets) > 0xFFFFFFFF
    return full_box("co64" if big else "stco", 0, 0, struct.pack(">I", len(offsets)),
                    struct.pack(f">{len(offsets)}{'Q' if big else 'I'}", *offsets))


# ---------------------------------------------------------------------- rewriting box trees
REWRITE_CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"mvex", b"moof", b"traf"}


def rewrite(buf, b: Box, edit, path: tuple = ()) -> bytes:
    """Box B rebuilt: EDIT(path, box) returns replacement bytes (b"" drops the box) or None to keep it; the
    containers of REWRITE_CONTAINERS are rebuilt from their (edited) children, with new sizes. Boxes cut short
    are left out (a cut-short container keeps its complete children)."""
    p = path + (b.type,)
    r = edit(p, b)
    if r is not None:
        return r
    if b.type in REWRITE_CONTAINERS:
        kids = list(children(buf, b))
        if kids:
            head = bytes(buf[b.payload:kids[0].start])
            tail = bytes(buf[kids[-1].end:b.end]) if not b.truncated else b""
            return box(b.type, head, *(rewrite(buf, c, edit, p) for c in kids), tail)
    if b.truncated:
        return b""                              # a box cut short (a damaged file): left out
    return bytes(buf[b.start:b.end])


# ---------------------------------------------------------------------- fragments
@dataclass
class FragTrack:
    """The samples of one track found in the movie fragments (moof boxes) of a file."""
    id: int
    offsets: list[int] = field(default_factory=list)
    sizes: list[int] = field(default_factory=list)
    durations: list[int] = field(default_factory=list)
    cts: list[int] = field(default_factory=list)
    keys: list[bool] = field(default_factory=list)
    runs: list[tuple[int, int, int]] = field(default_factory=list)    # (data offset, first sample, count)


def trex_defaults(buf, moov: Box | None) -> dict[int, tuple[int, int, int, int]]:
    """{track id: (description index, duration, size, flags)} from the mvex/trex boxes."""
    out: dict[int, tuple[int, int, int, int]] = {}
    if moov is None:
        return out
    for b in find_all(buf, "mvex/trex", moov.payload, moov.end):
        p = b.payload
        if b.end >= p + 24:
            out[be32(buf, p + 4)] = struct.unpack_from(">IIII", buf, p + 8)
    return out


def parse_moof(buf, moof: Box, trex: dict, tracks: dict[int, FragTrack], strict_end: int | None = None) -> bool:
    """Add the samples of the movie fragment MOOF to TRACKS {id: FragTrack}. False when the fragment is
    damaged or its samples run past STRICT_END (then nothing is added)."""
    found: list[tuple[int, list]] = []
    end_limit = len(buf) if strict_end is None else strict_end
    prev_end = moof.start
    try:
        for traf in children(buf, moof):
            if traf.type != b"traf":
                continue
            tfhd = next((c for c in children(buf, traf) if c.type == b"tfhd"), None)
            if tfhd is None:
                return False
            p = tfhd.payload
            flags = be32(buf, p) & 0xFFFFFF
            tid = be32(buf, p + 4)
            q = p + 8
            _d_idx, d_dur, d_size, d_flags = trex.get(tid, (1, 0, 0, 0))
            base = moof.start if flags & 0x020000 or not found else prev_end
            if flags & 0x01:
                base = be64(buf, q)
                q += 8
            if flags & 0x02:
                q += 4
            if flags & 0x08:
                d_dur = be32(buf, q)
                q += 4
            if flags & 0x10:
                d_size = be32(buf, q)
                q += 4
            if flags & 0x20:
                d_flags = be32(buf, q)
                q += 4
            samples: list = []
            pos = base
            for trun in children(buf, traf):
                if trun.type != b"trun":
                    continue
                r = trun.payload
                v, tflags = buf[r], be32(buf, r) & 0xFFFFFF
                count = be32(buf, r + 4)
                r += 8
                if tflags & 0x01:
                    pos = base + struct.unpack_from(">i", buf, r)[0]
                    r += 4
                first_flags = None
                if tflags & 0x04:
                    first_flags = be32(buf, r)
                    r += 4
                per = 4 * bin(tflags & 0xF00).count("1")
                if r + per * count > trun.end:
                    return False
                for i in range(count):
                    dur, size, sflags, cts = d_dur, d_size, d_flags, 0
                    if tflags & 0x100:
                        dur = be32(buf, r)
                        r += 4
                    if tflags & 0x200:
                        size = be32(buf, r)
                        r += 4
                    if tflags & 0x400:
                        sflags = be32(buf, r)
                        r += 4
                    elif i == 0 and first_flags is not None:
                        sflags = first_flags
                    if tflags & 0x800:
                        cts = struct.unpack_from(">i" if v else ">I", buf, r)[0]
                        r += 4
                    samples.append((pos, size, dur, cts, not sflags & 0x10000))
                    pos += size
                prev_end = pos
            found.append((tid, samples))
    except (struct.error, IndexError):
        return False
    for _tid, samples in found:
        for pos, size, _d, _c, _k in samples:
            if pos < 0 or pos + size > end_limit:
                return False
    for tid, samples in found:
        t = tracks.setdefault(tid, FragTrack(tid))
        if samples:
            t.runs.append((samples[0][0], len(t.sizes), len(samples)))
        for pos, size, dur, cts, key in samples:
            t.offsets.append(pos)
            t.sizes.append(size)
            t.durations.append(dur)
            t.cts.append(cts)
            t.keys.append(key)
    return True


def fragments_of(buf, boxes: list[Box], moov: Box | None) -> dict[int, FragTrack]:
    """The samples of every track in the complete movie fragments of a file."""
    trex = trex_defaults(buf, moov)
    tracks: dict[int, FragTrack] = {}
    for b in boxes:
        if b.type == b"moof" and not b.truncated:
            parse_moof(buf, b, trex, tracks)
    return tracks
