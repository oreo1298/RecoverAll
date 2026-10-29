"""Finding MP4 / MOV recordings by what their media data looks like: for the signature search (carve/video.py)
and for the repairs.

A movie's index, the movie box (moov), says how big every sample (a video frame, a run of sound) is and where it
lies in the file. The media data box (mdat) has no structure of its own, but the samples do: an H.264 or H.265
frame is a run of NAL units, each led by its length (4 bytes, usually) and a header whose bits must make sense,
and the lengths add up exactly to the size of the frame; a ProRes frame starts with its size and "icpf"; a
Motion JPEG frame is a JPEG picture. Inside a NAL unit the bytes 00 00 00, 00 00 01 and 00 00 02 never occur
(the encoder escapes them), and inside the compressed data of a JPEG a 0xFF byte is only followed by 0x00 or a
restart marker: data that doesn't belong there shows. Comparing the samples with the index tells whether the
file found on the disk is really in one piece, and where it goes on when it isn't:

* **Fragmented files** (:func:`assemble`). The samples are checked in file order. While they fit, the data is
  where the index says. At the first one that doesn't, the file went on somewhere else on the disk: the bytes
  that sample (or one of the next few) must begin with are known (its first NAL length, or what the samples
  checked so far had in front of it), so they are searched for ahead, at the same position within a disk block
  (the pieces of a file start and end on cluster boundaries, multiples of 512 bytes), and the samples there must
  fit too. Where the first piece ended lies between the last byte that was seen to fit and the first that
  didn't, on a block boundary: every candidate is scored by how well the bytes around it fit (NAL units that
  chain, no forbidden bytes inside them, sound that looks like sound, the start of another file just after the
  cut) and the best one is taken; ties go to the cut that is aligned like the gap between the pieces. This
  repeats for every piece (up to 64). A movie box at the end of the file is placed the same way: it is found by
  searching for its header.
  A ProRes frame lists where each of its slices begins, so a piece that holds only the middle of a frame is
  found by its slice headers. The sound after the last frame of a file whose movie box comes first is checked
  too (AAC frames from one encoder nearly all start with the same byte). A cut that other block boundaries fit
  just as well (inside one big frame, with random-looking data in between) can't be told apart: it is counted
  in :attr:`Assembly.uncertain`.
* **Unfinished recordings** (:func:`scan_media`). A camera that loses power, an app that crashes, a card pulled
  out while recording: the media data is there but the index was never written. The media data is walked from
  its first byte: NAL units as long as their lengths chain, then a stretch that isn't video (the sound between
  two video chunks) is skipped when the next valid video frame starts within a bounded distance, until the data
  stops being video. The file ends where the last frame stops being valid (the recording stopped inside it),
  else one chunk of sound later (the typical gap; PCM sound is followed block by block), short of blank space
  or another file, or where the media data box says when it was given a size. Old data after the end is often
  an older recording of the same camera: H.264 frame numbers that stop following on mark it.
* **The movie box elsewhere** (:func:`find_moovs`). A movie box found apart from its media data, ahead of it or
  behind it, is tried against the media data: it belongs to it when the first samples fit where it says they
  are, and its own piece is placed like any other.

Offsets are relative to the candidate (the first byte of the file); negative ones reach back before it. Nothing
here raises on damaged data: what doesn't fit is left out, and every search is bounded.
"""

from __future__ import annotations

import bisect
import re
import struct
import sys
from array import array
from dataclasses import dataclass, field
from operator import sub
from statistics import median
from typing import Callable

from .bits import BitReader, BitsError

KiB, MiB = 1024, 1024 ** 2
BLOCK = 512                     # disk clusters are multiples of it: pieces start and end on block boundaries
SEARCH_WINDOW = 512 * MiB       # how far ahead the rest of a fragmented file is looked for
BACK_WINDOW = 64 * MiB          # how far back a movie box is looked for
MAX_FRAGMENTS = 64
MAX_MOOV = 64 * MiB
GAP_FIRST = 4 * MiB             # unfinished recordings: the longest stretch of sound skipped before any was seen
GAP_MAX = 8 * MiB
_STEP = 4 * MiB                 # read size of the searches
_MAX_NAL = 32 * MiB
INSIDE_WINDOW = 64 * MiB        # how far ahead the rest of a frame cut by a fragment is looked for (ProRes)
_SLICE_HDR = re.compile(rb"[\x30\x38\x40]")             # the first byte of a ProRes slice header

Getter = Callable[[int, int], bytes]

_TRIPLET = re.compile(rb"\x00\x00[\x00-\x02]")           # never inside an H.264 / H.265 NAL unit
_JMARK = re.compile(rb"\xff[^\x00\xd0-\xd7]")             # never inside the compressed data of a JPEG
_ZRUN = re.compile(rb"\x00\x00+")
_ZEROS64 = bytes(64)                                       # not in compressed data (JPEG, AAC) either
# where a NAL unit may start (lookaheads: every position, overlapping ones too)
_H264_START = re.compile(rb"(?=\x00[\x00-\x7f]..[\x01-\x7f])", re.DOTALL)
_HEVC_START = re.compile(rb"(?=\x00[\x00-\x7f]..[\x00-\x7e][\x01-\x07])", re.DOTALL)
_MOOV_FIRST = frozenset({b"mvhd", b"trak", b"iods", b"udta", b"meta", b"mvex", b"prfl", b"cmov", b"free",
                         b"skip", b"uuid", b"clip", b"ctab", b"htka", b"wide"})

VIDEO_KINDS = {"avc1": "h264", "avc2": "h264", "avc3": "h264", "avc4": "h264", "dva1": "h264", "dvav": "h264",
               "hvc1": "hevc", "hev1": "hevc", "dvh1": "hevc", "dvhe": "hevc",
               "apch": "prores", "apcn": "prores", "apcs": "prores", "apco": "prores", "ap4h": "prores",
               "ap4x": "prores", "jpeg": "mjpeg", "mjpa": "mjpeg", "AVDJ": "mjpeg", "dmb1": "mjpeg",
               "mp4v": "mpeg4", "s263": "h263", "h263": "h263"}


def _be32(b, o: int = 0) -> int:
    return struct.unpack_from(">I", b, o)[0]


def _up(x: int, step: int = BLOCK) -> int:
    return -(-x // step) * step


def _tz(x: int) -> int:
    """Trailing zero bits of X (how aligned it is)."""
    return (x & -x).bit_length() - 1 if x else 64


# ---------------------------------------------------------------------- reading around a candidate
class Around:
    """Reads relative to the candidate of a signature-engine Reader; negative offsets reach back before it."""

    def __init__(self, r):
        self.r = r
        self.base = getattr(r, "start", 0)
        self.limit = r.limit
        self._src = getattr(r, "src", None)

    def read(self, off: int, n: int) -> bytes:
        if n <= 0 or off >= self.limit:
            return b""
        if off >= 0:
            return self.r.read(off, n)
        if self._src is None or self.base + off < 0:
            return b""
        head = self._src.read(self.base + off, min(n, -off))
        return head + self.r.read(0, n + off) if n > -off else head

    def direct(self, off: int, n: int) -> bytes:
        """A small read without filling the Reader's read-ahead window (scattered checks)."""
        if self._src is None or off < 0 or off + n > self.limit:
            return self.read(off, n)
        return self._src.read(self.base + off, n)


class _Window:
    """Sequential reads through a large window (walking media data)."""

    def __init__(self, r, size: int = 4 * MiB):
        self.r = r
        self.size = size
        self.at = 0
        self.buf = b""

    def read(self, p: int, n: int) -> bytes:
        rel = p - self.at
        if 0 <= rel and rel + n <= len(self.buf):
            return self.buf[rel:rel + n]
        if n > self.size // 2:
            return self.r.read(p, n)
        self.buf = self.r.read(p, self.size)
        self.at = p
        return self.buf[:n]


# ---------------------------------------------------------------------- NAL units
def _h264_classes() -> bytes:
    """What an H.264 NAL header byte is in a sample: 0 impossible, 1 another unit, 2 a slice, 3 a slice of an
    IDR picture."""
    t = bytearray(256)
    for b in range(128):
        typ, ref = b & 31, b >> 5
        if typ in (1, 2, 3, 4, 20):
            t[b] = 2
        elif typ == 5 and ref:
            t[b] = 3
        elif (typ in (6, 9, 10, 11, 12) and not ref) or (typ in (7, 8, 13, 15) and ref) or typ in (14, 19):
            t[b] = 1
    return bytes(t)


def _hevc_classes() -> bytes:
    """The same for the first byte of an H.265 header (the second byte is checked apart)."""
    t = bytearray(256)
    for b in range(0, 128, 2):                      # forbidden bit 0, top bit of the layer id 0
        typ = b >> 1
        if typ <= 9:
            t[b] = 2
        elif 16 <= typ <= 21:
            t[b] = 3
        elif 32 <= typ <= 40 or typ >= 62:          # parameter sets, AUD, SEI; 62/63: Dolby Vision
            t[b] = 1
    return bytes(t)


H264_CLASS = _h264_classes()
HEVC_CLASS = _hevc_classes()


def nal_class(h, i: int, hevc: bool) -> int:
    """The class (see _h264_classes) of the NAL header at H[i]: 0 when it can't be one."""
    if hevc:
        if i + 1 >= len(h):
            return 0
        b1 = h[i + 1]
        return HEVC_CLASS[h[i]] if b1 & 7 and b1 >> 3 <= 7 else 0
    return H264_CLASS[h[i]] if i < len(h) else 0


def first_slice(payload: bytes, hevc: bool) -> bool:
    """Whether a slice NAL unit (its bytes, header included) begins a picture."""
    if hevc:
        return len(payload) > 2 and bool(payload[2] & 0x80)
    return len(payload) > 1 and bool(payload[1] & 0x80)        # first_mb_in_slice = 0: ue(v) "1"


def slice_header(payload: bytes, hevc: bool) -> tuple[int, int] | None:
    """(slice type or -1, picture parameter set id) of the first slice of a picture, None if impossible."""
    try:
        if hevc:
            br = BitReader(payload[:16], 16)
            if not br.u1():
                return None
            if 16 <= (payload[0] >> 1) & 63 <= 23:
                br.u1()                                           # no_output_of_prior_pics_flag
            pps = br.ue()
            return (-1, pps) if pps <= 63 else None
        br = BitReader(payload[:16], 8)
        if br.ue() != 0:
            return None
        st, pps = br.ue(), br.ue()
        if st > 9 or pps > 255 or (payload[0] & 31 == 5 and st % 5 not in (2, 4)):
            return None
        return st, pps
    except BitsError:
        return None


def walk_nals(get: Getter, off: int, size: int, ls: int, hevc: bool) -> tuple[int, list[tuple[int, int]]]:
    """The NAL units of a sample: (-1, [(offset, length)]) when their lengths chain to fill it exactly and one of
    them is a slice; otherwise (offset where it stops fitting, [])."""
    hl = 2 if hevc else 1
    p, end = off, off + size
    vcl = False
    nals: list[tuple[int, int]] = []
    while p < end:
        h = get(p, ls + hl + 1)
        if len(h) < ls + hl:
            return p, []
        n = int.from_bytes(h[:ls], "big")
        if n < hl or p + ls + n > end:
            return p, []
        c = nal_class(h, ls, hevc)
        if not c:
            return p, []
        if c >= 2 and not vcl:                   # a sample is a picture: its first slice starts it
            if n > hl and len(h) > ls + hl and not first_slice(h[ls:], hevc):
                return p, []
            vcl = True
        nals.append((p, n))
        p += ls + n
        if len(nals) > 4096:
            return p, []
    return (-1, nals) if vcl else (off, [])


# ---------------------------------------------------------------------- checking samples
def video_kind(codec: str) -> str | None:
    return VIDEO_KINDS.get(codec)


def length_size(kind: str, entry: bytes) -> int:
    """The size of the NAL length fields, from the avcC / hvcC box of the sample entry (4 when unreadable)."""
    for name, at in ((b"avcC", 4), (b"hvcC", 21)):
        i = entry.find(name)
        if i >= 4 and i + 4 + at < len(entry):
            return (entry[i + 4 + at] & 3) + 1
    return 4


def prores_slices(get: Getter, off: int, size: int) -> list[tuple[int, int]] | None:
    """(offset, size) of the slices of the ProRes frame at OFF, from its picture headers and slice tables;
    None when they don't fill the frame exactly."""
    h = get(off, 10)
    if len(h) < 10:
        return None
    p, end = off + 8 + struct.unpack_from(">H", h, 8)[0], off + size
    out: list[tuple[int, int]] = []
    for _pic in range(2):                                 # interlaced frames hold two pictures
        ph = get(p, 8)
        if len(ph) < 8:
            return None
        hs, psize, n = ph[0] >> 3, _be32(ph, 1), struct.unpack_from(">H", ph, 5)[0]
        if hs < 8 or not n or psize < hs + 2 * n or p + psize > end:
            return None
        tab = get(p + hs, 2 * n)
        if len(tab) < 2 * n:
            return None
        q = p + hs + 2 * n
        for s in struct.unpack(f">{n}H", tab):
            out.append((q, s))
            q += s
        if q != p + psize:
            return None
        p += psize
        if p == end:
            return out
    return None


def prores_slice_ok(h: bytes, size: int) -> bool:
    """Whether a ProRes slice header (its first 8 bytes) fits a slice of SIZE bytes."""
    if len(h) < 6 or h[0] & 7:
        return False
    hs = h[0] >> 3
    if not 6 <= hs <= 8 or not 1 <= h[1] <= 224:
        return False
    y, u = struct.unpack_from(">HH", h, 2)
    v = struct.unpack_from(">H", h, 6)[0] if hs > 7 and len(h) >= 8 else 0
    return hs + y + u + v <= size


class VideoCheck:
    """Checks the samples of a video track against the bytes found where they should be, and learns what the
    samples look like to search for the ones that aren't there."""

    def __init__(self, kind: str, ls: int = 4):
        self.kind = kind
        self.nal = kind in ("h264", "hevc")
        self.hevc = kind == "hevc"
        self.ls = ls
        self.hl = 2 if self.hevc else 1
        self.leads: dict[int, int] = {}
        self.common: bytes | None = None          # what the samples seen so far begin with
        self.seen = 0

    def walk(self, get: Getter, off: int, size: int) -> tuple[int, list[tuple[int, int]], int]:
        """(-1 or where the sample stops fitting, the stretches of compressed data inside it, the end of the
        bytes that were actually seen to fit)."""
        if size <= 0:
            return -1, [], off
        if self.nal:
            fail, nals = walk_nals(get, off, size, self.ls, self.hevc)
            if fail >= 0:
                return fail, [], off
            pays = [(p + self.ls + self.hl, p + self.ls + n) for p, n in nals]
            return -1, pays, nals[-1][0] + self.ls + self.hl
        h = get(off, 24)
        if len(h) < min(24, size):
            return off, [], off
        if self.kind == "prores":
            if size < 28 or _be32(h) != size or h[4:8] != b"icpf" or not 20 <= struct.unpack_from(">H", h, 8)[0] < 512:
                return off, [], off
            return -1, [], off + 24
        if self.kind == "mjpeg":
            return self._jpeg(get, off, size)
        if self.kind == "mpeg4":
            ok = h[:3] == b"\0\0\x01" and (h[3] in (0xB0, 0xB3, 0xB5, 0xB6) or h[3] <= 0x2F)
        else:                                                    # h263: picture start code
            ok = h[:2] == b"\0\0" and h[2] & 0xFC == 0x80
        return (-1, [], off + 4) if ok else (off, [], off)

    @staticmethod
    def _jpeg_head(get: Getter, off: int, size: int) -> tuple[int, int]:
        """(-1 or where the markers of a JPEG frame stop fitting, where its compressed data begins)."""
        end = off + size
        if get(off, 3) != b"\xff\xd8\xff":
            return off, off
        p = off + 2
        for _ in range(64):
            m = get(p, 4)
            if len(m) < 4 or m[0] != 0xFF or m[1] in (0xD8, 0xD9) or m[1] < 0xC0:
                return p, off
            n = (m[2] << 8) | m[3]
            if n < 2 or p + 2 + n > end:
                return p, off
            p += 2 + n
            if m[1] == 0xDA:
                return -1, p
        return p, off

    def _jpeg(self, get: Getter, off: int, size: int) -> tuple[int, list[tuple[int, int]], int]:
        end = off + size
        fail, p = self._jpeg_head(get, off, size)
        if fail >= 0:
            return fail, [], off
        tail = get(max(p, end - 64), min(64, end - p))
        e = tail.rfind(b"\xff\xd9")
        if e < 0:
            return end - len(tail), [], off
        eoi = end - len(tail) + e
        return -1, [(p, eoi)], end

    def check(self, get: Getter, off: int, size: int, strict: bool = False) -> int:
        """-1 if the sample at OFF fits, else the offset where it stops fitting. STRICT also looks at the
        compressed data (reads the whole sample)."""
        if not strict and self.kind == "mjpeg":               # the quick look: where the picture starts and ends
            if size < 128 or get(off, 3) != b"\xff\xd8\xff":
                return off
            return -1 if b"\xff\xd9" in get(off + size - 64, 64) else off + size - 64
        if not strict or self.kind not in ("h264", "hevc", "mjpeg", "prores"):
            return self.walk(get, off, size)[0]
        data = get(off, size)
        if len(data) < size:
            return off + len(data)
        local = lambda p, n: data[p - off:p - off + n]          # noqa: E731
        fail, pays, _v = self.walk(local, off, size)
        if fail >= 0:
            return fail
        if self.kind == "prores":
            slices = prores_slices(local, off, size)
            if slices is None:
                return off
            bad = next((q for q, n in slices if not prores_slice_ok(data[q - off:q - off + 8], n)), -1)
            return bad
        bad = _JMARK if self.kind == "mjpeg" else _TRIPLET
        for s, e in pays:
            m = bad.search(data, s - off, e - off)
            if m:
                return off + m.start()
            if self.kind == "mjpeg":
                z = data.find(_ZEROS64, s - off, e - off)
                if z >= 0:
                    return off + z
        return -1

    def prefix(self, get: Getter, off: int, size: int) -> tuple[int, int]:
        """(how many independent structures fit, where the sample stops fitting: OFF + SIZE when all of it
        does) for a sample that may be cut short by the next fragment: ProRes slices, NAL units, 256-byte
        stretches of JPEG data before the first byte that can't be theirs."""
        data = get(off, size)
        local = lambda p, n: data[p - off:p - off + n]          # noqa: E731
        end = off + len(data)
        if self.kind == "prores":
            if self.walk(local, off, size)[0] >= 0:
                return 0, off
            sl = prores_slices(local, off, size)
            if sl is None:
                return 0, off + 24
            for i, (q, n) in enumerate(sl):
                if q + 8 > end or not prores_slice_ok(data[q - off:q - off + 8], n):
                    return i, q
            return len(sl), off + size if end == off + size else end
        if self.nal:
            p, units, hl = off, 0, self.ls + self.hl
            while p + hl <= end:
                h = data[p - off:p - off + hl + 1]
                n = int.from_bytes(h[:self.ls], "big")
                if n < self.hl or p + self.ls + n > off + size or not nal_class(h, self.ls, self.hevc):
                    return units, p
                m = _TRIPLET.search(data, p - off + hl, min(end, p + self.ls + n) - off)
                if m:
                    return units, off + m.start()
                units += 1
                p += self.ls + n
                if p == off + size:
                    return units, p
            return units, min(p, end)
        if self.kind == "mjpeg":
            fail, s0 = self._jpeg_head(local, off, size)
            if fail >= 0:
                return 0, off
            m = _JMARK.search(data, s0 - off)
            z = data.find(_ZEROS64, s0 - off)
            bad = min((x for x in (m.start() if m else -1, z) if x >= 0), default=-1)
            if bad >= 0 and data[bad:bad + 2] == b"\xff\xd9" and off + bad + 64 >= off + size:
                return (bad + off - s0) // 256 + 1, off + size          # the end of the picture
            if bad < 0:
                return (len(data) + off - s0) // 256, end
            return (off + bad - s0) // 256, off + bad
        fail = self.walk(local, off, size)[0]
        return (1, off + size) if fail < 0 else (0, off)

    @staticmethod
    def slices_fit(get: Getter, off: int, size: int) -> tuple[int, int]:
        """ProRes: (-1 or the first slice whose header doesn't fit, the end of the last one that does). Every
        few slices are looked at (a 4K frame has thousands), all of them where one doesn't fit."""
        sl = prores_slices(get, off, size)
        if sl is None:
            return off, off
        step = max(1, len(sl) // 64)
        ok_upto = 0                                       # slices before this index fit
        for i in list(range(0, len(sl), step)) + [len(sl) - 1]:
            q, n = sl[i]
            if prores_slice_ok(get(q, 8), n):
                ok_upto = i + 1
                continue
            for j in range(ok_upto, i + 1):               # the first one that doesn't, in between
                q, n = sl[j]
                if not prores_slice_ok(get(q, 8), n):
                    return q, sl[j - 1][0] + 8 if j else sl[0][0]
            return sl[i][0], sl[i - 1][0] + 8 if i else sl[0][0]
        return -1, sl[-1][0] + 8

    def evidence(self, get: Getter, off: int, size: int) -> int:
        """How many independent structures a sample that fits has (ProRes slices, NAL units after the first,
        256-byte stretches of JPEG data): how much its fitting proves."""
        if self.kind == "prores":
            sl = prores_slices(get, off, size)
            return len(sl) if sl else 0
        fail, pays, _v = self.walk(get, off, size)
        if fail >= 0:
            return 0
        if self.kind == "mjpeg":
            return sum(e - s for s, e in pays) // 256
        return len(pays) - 1 if self.nal else 0

    def learn(self, get: Getter, off: int, size: int) -> None:
        """Remember what a sample that fits looks like (what leads its last NAL unit; its first bytes)."""
        self.seen += 1
        if self.nal:
            fail, nals = walk_nals(get, off, size, self.ls, self.hevc)
            if fail < 0:
                lead = nals[-1][0] - off
                if lead <= 512:
                    self.leads[lead] = self.leads.get(lead, 0) + 1
            return
        head = get(off, 16)
        if self.common is None:
            self.common = head
        else:
            n = 0
            while n < min(len(head), len(self.common)) and head[n] == self.common[n]:
                n += 1
            self.common = self.common[:n]

    def patterns(self, size: int) -> list[tuple[int, bytes]]:
        """What a sample of SIZE bytes must contain: [(offset in the sample, bytes)], the likeliest first."""
        if self.nal:
            lead = max(self.leads, key=self.leads.get) if self.leads else 0
            out = []
            for t in dict.fromkeys((lead, 0)):
                n = size - t - self.ls
                if n >= self.hl and n < 1 << (8 * self.ls):
                    out.append((t, n.to_bytes(self.ls, "big")))
            return out
        if self.kind == "prores":
            return [(0, size.to_bytes(4, "big") + b"icpf")]
        if self.common and len(self.common) >= 4:
            return [(0, self.common)]
        if self.kind == "mjpeg":
            return [(0, b"\xff\xd8\xff")]
        if self.kind == "mpeg4":
            return [(0, b"\0\0\x01\xb6")]
        return []


class AudioCheck:
    """What the chunks of a sound track look like. A weak check (compressed sound has no structure to speak
    of): it only helps to decide where a piece of the file ends."""

    def __init__(self, table: Table):
        c = table.codec
        self.kind: str | None = None
        self.channels = max(1, min(table.channels or 2, 16))
        if c == "mp4a":                         # the esds object type: 0x69 / 0x6B MPEG audio, else AAC
            self.kind = "mp3" if b"\x69\x15" in table.entry or b"\x6b\x15" in table.entry else "aac"
        elif c in ("sowt", "twos", "lpcm") and table.bits in (0, 16):
            self.kind = "pcm16be" if c == "twos" else "pcm16le"
        elif c in ("samr", "sawb"):
            self.kind = "amr"
        self.ids: set[int] | None = None
        self.lead: int | None = None

    def learn(self, first_bytes: list[int]) -> None:
        """AAC: the syntax elements its frames start with (stereo: a channel pair; the first one a fill), and
        the element and instance tag (the top 7 bits) nearly all of them start with, when there is one."""
        if self.kind == "aac" and len(first_bytes) >= 3:
            ids = {b >> 5 for b in first_bytes}
            self.ids = ids if len(ids) <= 3 and 7 not in ids else None
            rest = [b >> 1 for b in first_bytes[1:]]
            top = max(set(rest), key=rest.count)
            usual = rest.count(top) * 4 >= len(rest) * 3 and len(rest) >= 6
            self.lead = top if usual and top else None    # (0 would match blank space)

    def frames_fit(self, get: Getter, starts: list[int]) -> bool:
        """Whether most frames of a chunk start like this track's frames (AAC with a usual first element)."""
        if self.lead is None or not starts:
            return True
        bad = sum(not (b := get(x, 1)) or b[0] >> 1 != self.lead for x in starts)
        return bad * 2 <= len(starts)

    def block(self, blk: bytes) -> int:
        """16-bit PCM: 0 for a silent (all-zero) block, 2 for one that jumps around like noise (compressed
        data) instead of sound, 1 for sound."""
        if not blk.strip(b"\0"):
            return 0
        return 2 if self.rough(blk) else 1

    def rough(self, blk: bytes) -> bool:
        """16-bit PCM: whether a block jumps around like noise (compressed data) instead of sound."""
        return pcm_rough(blk, self.channels, self.kind == "pcm16be")


def pcm_rough(blk: bytes, channels: int, big: bool) -> bool:
    """Whether BLK, read as 16-bit PCM, jumps around like noise (compressed or random data) instead of sound."""
    a = array("h")
    a.frombytes(blk[:len(blk) & ~1])
    if big == (sys.byteorder == "little"):
        a.byteswap()
    total = n = 0
    for ch in range(channels):
        x = a[ch::channels]
        total += sum(map(abs, map(sub, x[1:], x[:-1])))
        n += max(0, len(x) - 1)
    return n > 0 and total / n > 12000


def sounds_like_pcm(blk: bytes) -> bool:
    """Whether a block reads as 16-bit PCM sound (mono or stereo, either byte order)."""
    return any(not pcm_rough(blk, c, big) for c in (2, 1) for big in (False, True))


# ---------------------------------------------------------------------- the movie's tables
@dataclass
class Table:
    """The sample tables of one track as the movie box has them, read lazily: sizes and chunk offsets stay
    packed (a sound track can have millions of samples)."""

    handler: str = ""
    codec: str = ""
    entry: bytes = b""
    count: int = 0
    const: int = 0
    packed: bytes = b""
    co: bytes = b""                   # chunk offsets, packed
    cow: int = 4                      # their width (stco 4, co64 8)
    nchunks: int = 0
    stsc: list[tuple[int, int, int]] = field(default_factory=list)
    channels: int = 0
    bits: int = 0

    def size(self, i: int) -> int:
        return self.const or _be32(self.packed, 4 * i)

    def sizes(self, first: int, n: int) -> list[int]:
        if self.const:
            return [self.const] * n
        return list(struct.unpack_from(f">{n}I", self.packed, 4 * first))

    def offset(self, c: int) -> int:
        return struct.unpack_from(">I" if self.cow == 4 else ">Q", self.co, c * self.cow)[0]

    @property
    def offsets(self) -> tuple[int, ...]:
        return struct.unpack_from(f">{self.nchunks}{'I' if self.cow == 4 else 'Q'}", self.co)

    def chunks(self):
        """(file offset, first sample, number of samples) of every chunk."""
        runs = self.stsc or [(1, 1, 1)]
        sample, nch = 0, self.nchunks
        offsets = self.offsets
        for k, (first, per, _d) in enumerate(runs):
            last = min(runs[k + 1][0] - 1 if k + 1 < len(runs) else nch, nch)
            if per <= 0:
                return
            for c in range(max(0, first - 1), last):
                if sample >= self.count:
                    return
                n = min(per, self.count - sample)
                yield offsets[c], sample, n
                sample += n

    def last_chunk(self) -> tuple[int, int, int] | None:
        """(file offset, first sample, number of samples) of the last chunk, without walking the others."""
        runs = self.stsc or [(1, 1, 1)]
        sample, nch = 0, self.nchunks
        for k, (first, per, _d) in enumerate(runs):
            last = min(runs[k + 1][0] - 1 if k + 1 < len(runs) else nch, nch)
            if per <= 0 or first < 1:
                return None
            if k + 1 == len(runs) or last >= nch:
                n = last - first + 1
                if n <= 0:
                    return None
                s0 = sample + (n - 1) * per
                return (self.offset(last - 1), s0, min(per, self.count - s0)) if s0 < self.count else None
            sample += max(0, last - first + 1) * per
        return None

    def locate(self, i: int) -> tuple[int, int] | None:
        """(file offset, size) of sample I, without walking every chunk."""
        return self.locate_all([i]).get(i)

    def locate_all(self, wanted: list[int]) -> dict[int, tuple[int, int]]:
        """{sample: (file offset, size)} for the samples WANTED (sorted), in one pass over the sample-to-chunk
        runs."""
        out: dict[int, tuple[int, int]] = {}
        runs = self.stsc or [(1, 1, 1)]
        sample, nch, w = 0, self.nchunks, 0
        wanted = [i for i in wanted if 0 <= i < self.count]
        for k, (first, per, _d) in enumerate(runs):
            if w >= len(wanted):
                break
            last = min(runs[k + 1][0] - 1 if k + 1 < len(runs) else nch, nch)
            if per <= 0 or first < 1:
                break
            span = max(0, last - first + 1) * per
            while w < len(wanted) and wanted[w] < sample + span:
                i = wanted[w]
                c = (i - sample) // per
                s0 = sample + c * per
                out[i] = (self.offset(first - 1 + c) + (self.const * (i - s0) if self.const else
                                                       sum(self.sizes(s0, i - s0)))), self.size(i)
                w += 1
            sample += span
        return out


def _kids(buf: bytes, start: int, end: int) -> list[tuple[bytes, int, int]]:
    """(type, payload offset, end) of the boxes in [start, end) of BUF (a lean walk for the hot path)."""
    out = []
    p = start
    end = min(end, len(buf))
    while p + 8 <= end:
        size, typ = struct.unpack_from(">I4s", buf, p)
        hdr = 8
        if size == 1:
            if p + 16 > end:
                break
            size, hdr = struct.unpack_from(">Q", buf, p + 8)[0], 16
        elif size == 0:
            size = end - p
        if size < hdr or p + size > end:
            break
        out.append((typ, p + hdr, p + size))
        p += size
    return out


def read_tables(moov: bytes, video_only: bool = False) -> list[Table]:
    """The tracks of the movie box at the start of MOOV that have sample tables (VIDEO_ONLY: up to the first
    video track, skipping the tables of the others)."""
    out: list[Table] = []
    top = _kids(moov, 0, 16 + len(moov))[:1]
    if not top or top[0][0] != b"moov":
        return out
    for typ, tp, te in _kids(moov, top[0][1], top[0][2]):
        if typ != b"trak":
            continue
        t = Table()
        for mt, mp, me in _kids(moov, tp, te):
            if mt != b"mdia":
                continue
            for bt, bp, be in _kids(moov, mp, me):
                if bt == b"hdlr" and be >= bp + 12:
                    t.handler = moov[bp + 8:bp + 12].decode("latin-1")
                elif bt == b"minf" and not (video_only and t.handler and t.handler != "vide"):
                    for ct, cp, ce in _kids(moov, bp, be):
                        if ct == b"stbl":
                            _read_stbl(moov, cp, ce, t)
        if t.count and t.nchunks:
            out.append(t)
            if video_only and t.handler == "vide" and video_kind(t.codec):
                break
    return out


def _read_stbl(buf: bytes, start: int, end: int, t: Table) -> None:
    for typ, p, e in _kids(buf, start, end):
        try:
            if typ == b"stsd":
                ent = _kids(buf, p + 8, e)[:1]
                if ent:
                    t.codec = ent[0][0].decode("latin-1")
                    t.entry = buf[ent[0][1]:ent[0][2]]
                    if len(t.entry) >= 20:
                        t.channels, t.bits = struct.unpack_from(">HH", t.entry, 16)
            elif typ == b"stsz":
                size, count = struct.unpack_from(">II", buf, p + 4)
                if size:
                    t.const, t.count = size, count
                else:
                    t.count = min(count, max(0, (e - p - 12) // 4))
                    t.packed = buf[p + 12:p + 12 + 4 * t.count]
            elif typ in (b"stco", b"co64"):
                t.cow = 4 if typ == b"stco" else 8
                t.nchunks = min(_be32(buf, p + 4), max(0, (e - p - 8) // t.cow))
                t.co = buf[p + 8:p + 8 + t.nchunks * t.cow]
            elif typ == b"stsc":
                count = min(_be32(buf, p + 4), max(0, (e - p - 8) // 12))
                t.stsc = list(struct.iter_unpack(">III", buf[p + 8:p + 8 + 12 * count]))
        except (struct.error, IndexError):
            pass


def video_table(tables: list[Table]) -> tuple[Table, VideoCheck] | None:
    for t in tables:
        k = video_kind(t.codec) if t.handler == "vide" else None
        if k:
            return t, VideoCheck(k, length_size(k, t.entry) if k in ("h264", "hevc") else 0)
    return None


# ---------------------------------------------------------------------- the quick check
def quick_check(r, moov: bytes, moov_at: int, moov_first: bool = False, samples: int = 9) -> str:
    """How the data where the index puts it compares with the index, from nine video samples: "ok", "failed"
    (the first samples fit, a later one doesn't: the file is fragmented or damaged), "bad" (not even the first
    one fits), "stray" (a movie box on its own at the candidate: its samples would lie inside it) or "unknown"
    (nothing to check with). MOOV_FIRST: the movie box comes before the media data, so the file ends with
    media data and the sound at its end is checked too."""
    tables = read_tables(moov, video_only=not moov_first)
    vt = video_table(tables)
    if vt is None:
        return "unknown"
    t, chk = vt
    if moov_at == 0 and t.offset(0) < len(moov):
        return "stray"
    src = Around(r)
    if moov_first and not _sound_ends_right(src, tables):
        return "failed"                        # the file ends with sound the frames don't cover: it moved
    n = t.count
    idx = sorted({0, 1, n - 2, n - 1} | {n * k // (samples - 3) for k in range(1, samples - 3)})
    results = []
    for _i, (off, size) in sorted(t.locate_all(idx).items()):
        if size:
            results.append(chk.check(src.direct, off, size) < 0)
    if not results:
        return "unknown"
    if all(results):
        return "ok"
    return "failed" if results[0] else "bad"


def _sound_ends_right(src: Around, tables: list[Table]) -> bool:
    """Whether the last chunk of an AAC track starts its frames like its first chunk does."""
    for t in tables:
        if t.handler != "soun" or t.codec != "mp4a" or t.nchunks < 2:
            continue
        ac = AudioCheck(t)
        first: list[int] = []
        for off, f0, n in t.chunks():
            for size in t.sizes(f0, min(n, 24)):
                first.extend(src.direct(off, 1))
                off += size
            if len(first) >= 12:
                break
        ac.learn(first)
        lc = t.last_chunk()
        if lc is None or ac.lead is None:
            continue
        off, f0, n = lc
        starts = []
        for size in t.sizes(f0, min(n, 64)):
            starts.append(off)
            off += size
        if len(starts) >= 3 and not ac.frames_fit(src.direct, starts):
            return False
    return True


# ---------------------------------------------------------------------- putting a fragmented file together
class Pieces:
    """Where the file's bytes are: piece i holds the file offsets [starts[i], starts[i+1]) and begins at the
    source offset srcs[i] (relative to the candidate)."""

    def __init__(self, src: Around):
        self.src = src
        self.starts = [0]
        self.srcs = [0]

    @property
    def delta(self) -> int:
        return self.srcs[-1] - self.starts[-1]

    def read(self, x: int, n: int) -> bytes:
        out = []
        while n > 0:
            i = max(0, bisect.bisect_right(self.starts, x) - 1)
            stop = self.starts[i + 1] if i + 1 < len(self.starts) else None
            k = n if stop is None else min(n, stop - x)
            b = self.src.read(self.srcs[i] + x - self.starts[i], k)
            out.append(b)
            if len(b) < k:
                break
            x += k
            n -= k
        return b"".join(out)

    def add(self, f: int, p: int) -> None:
        self.starts.append(f)
        self.srcs.append(p)

    def runs(self, size: int) -> list[tuple[int, int]]:
        out = []
        for i, (f, p) in enumerate(zip(self.starts, self.srcs)):
            e = min(self.starts[i + 1] if i + 1 < len(self.starts) else size, size)
            if e > f:
                out.append((p, e - f))
        return out


@dataclass
class Assembly:
    runs: list[tuple[int, int]]      # the file's pieces in order: (offset from the candidate, length)
    complete: bool                   # every video sample was found
    fragments: int
    damaged: int = 0                 # samples that fit nowhere (left as they are)
    uncertain: int = 0               # cuts that other block boundaries fit as well (inside a big frame, with
    #                                  data in between that looks just like it): a frame there may be damaged


@dataclass(slots=True)
class _Item:
    off: int
    size: int
    kind: int                        # 0 video sample, 1 sound chunk
    check: object
    first: int = 0                   # sound: the chunk's first sample and their number
    count: int = 0
    table: Table | None = None

    @property
    def end(self) -> int:
        return self.off + self.size


class _Index:
    """Where a buffer holds what can't be inside compressed data: zero runs (H.264/H.265) or markers (JPEG)."""

    def __init__(self, buf: bytes, jpeg: bool):
        self.s: list[int] = []
        self.e: list[int] = []
        self.zs: list[int] = []
        self.ze: list[int] = []
        n = len(buf)
        for m in _ZRUN.finditer(buf):
            s, e = m.span()
            if e - s >= 64:
                self.zs.append(s)
                self.ze.append(e)
            if not jpeg:
                te = e - 2 + (1 if e < n and buf[e] in (1, 2) else 0)
                if te > s:
                    self.s.append(s)
                    self.e.append(te)
        if jpeg:
            for m in _JMARK.finditer(buf):
                self.s.append(m.start())
                self.e.append(m.start() + 1)
        self.width = 2 if jpeg else 3

    def bad(self, lo: int, hi: int) -> bool:
        """Whether a forbidden sequence lies wholly inside [lo, hi) (JPEG: a marker or 64 zero bytes)."""
        if hi - lo < self.width:
            return False
        i = bisect.bisect_right(self.e, lo)
        if i < len(self.s) and max(self.s[i], lo) <= hi - self.width:
            return True
        return self.width == 2 and self.zeros(lo, hi)

    def zeros(self, lo: int, hi: int) -> bool:
        """Whether 64 zero bytes in a row lie inside [lo, hi)."""
        i = bisect.bisect_right(self.ze, lo)
        while i < len(self.zs) and self.zs[i] < hi:
            if min(self.ze[i], hi) - max(self.zs[i], lo) >= 64:
                return True
            i += 1
        return False


_FOREIGN = (b"\xff\xd8\xff", b"\x89PNG", b"RIFF", b"PK\x03\x04", b"%PDF", b"OggS", b"fLaC", b"\x1a\x45\xdf\xa3",
            b"ID3", b"GIF8", b"\x00\x00\x01\xba", b"BM")


def foreign(blk: bytes, jpeg_ok: bool = False) -> bool:
    """Whether a block starts like another file (or is blank)."""
    if len(blk) < 8:
        return False
    if blk[4:8] in (b"ftyp", b"moov"):
        return True
    for sig in _FOREIGN:
        if blk.startswith(sig) and not (jpeg_ok and sig == b"\xff\xd8\xff"):
            return True
    return False


class _Assembler:
    def __init__(self, r, tables: list[Table], size: int, start_ok: int):
        self.moov: tuple[int, int, int] | None = None
        self.uncertain = 0
        self.learned_audio = False
        self.src = Around(r)
        self.P = Pieces(self.src)
        self.size = size
        self.start_ok = start_ok
        self.items: list[_Item] = []
        self.video: list[_Item] = []
        vt = video_table(tables)
        self.vcheck = vt[1] if vt else None
        if vt is None:
            return
        vtab = vt[0]
        for off, first, n in vtab.chunks():
            for s in vtab.sizes(first, n):
                if s:
                    self.video.append(_Item(off, s, 0, self.vcheck))
                off += s
        for t in tables:
            if t.handler != "soun":
                continue
            ac = AudioCheck(t)
            if ac.kind is None:
                continue
            for off, first, n in t.chunks():
                nbytes = t.const * n if t.const else sum(t.sizes(first, n))
                if nbytes:
                    self.items.append(_Item(off, nbytes, 1, ac, first, n, t))
        self.items.extend(self.video)
        self.items.sort(key=lambda it: it.off)
        self.offs = [it.off for it in self.items]
        self.longest = max((it.size for it in self.items), default=0)

    # ---------------------------------------------------------------- the walk
    def run(self, need_start: bool, moov: tuple[int, int, int] | None) -> Assembly | None:
        vids, chk, P = self.video, self.vcheck, self.P
        if not vids or chk is None:
            return None
        self.moov = moov
        last = self.start_ok
        complete, damaged, checked = True, 0, 0
        k = 0
        retried = -1
        while k < len(vids):
            it = vids[k]
            fail, _pays, seen = chk.walk(P.read, it.off, it.size)
            if fail < 0 and chk.kind == "prores":        # every slice: a piece may end inside a frame
                fail, seen = chk.slices_fit(P.read, it.off, it.size)
            if fail < 0:
                if chk.seen < 256:
                    chk.learn(P.read, it.off, it.size)
                last = max(last, seen)
                checked += 1
                k += 1
                continue
            if checked == 0 and need_start:
                return None
            if checked and k + 2 < len(vids) and all(
                    chk.walk(P.read, vids[k + t].off, vids[k + t].size)[0] < 0 for t in (1, 2)):
                damaged += 1                                   # one damaged sample among good ones
                k += 1
                continue
            if (retried == k and fail <= P.starts[-1]) or len(P.starts) >= MAX_FRAGMENTS:
                complete = False                 # no progress: the piece just added didn't help
                break
            cut = self._continuation(k, last, fail)
            if cut is None:
                complete = False
                break
            f, d = cut
            P.add(f, f + d)
            retried = k
        if need_start and checked < min(3, len(vids)):
            return None
        if complete and moov is not None:
            complete = self._place_moov(last, *moov)
        elif complete:                           # the file ends with media data: its last sound too
            complete = self._tail_sound(last)
        if damaged > max(8, len(vids) // 100):
            complete = False
        return Assembly(P.runs(self.size), complete, len(P.starts), damaged, self.uncertain)

    def _learn_audio(self, upto: int) -> None:
        """Learn what the AAC frames start with from the chunks before UPTO (the data seen to fit so far),
        through the pieces found so far. Once, when there are enough of them."""
        if self.learned_audio:
            return
        seen: dict[int, list[int]] = {}
        checks = {}
        for it in self.items:
            if it.end > upto:
                break
            if it.kind != 1 or it.check.kind != "aac":
                continue
            lst = seen.setdefault(id(it.check), [])
            checks[id(it.check)] = it.check
            if len(lst) < 24:
                for x in self._starts(it):
                    lst.extend(self.P.read(x, 1))
        if not seen or min(len(v) for v in seen.values()) < 12:
            return
        for key, lst in seen.items():
            checks[key].learn(lst)
        self.learned_audio = True

    def _starts(self, it: _Item) -> list[int]:
        out, x = [], it.off
        for n in it.table.sizes(it.first, min(it.count, 64)):
            out.append(x)
            x += n
        return out

    def _tail_sound(self, last: int) -> bool:
        """The sound after the last video frame (the last fragment may hold only that and the frame's end):
        where it is, or found by the byte its frames start with. False when it is neither."""
        end = self.video[-1].end
        self._learn_audio(last)
        if not self.learned_audio:
            return True
        for it in [x for x in self.items if x.kind == 1 and x.off >= end][:8]:
            ac: AudioCheck = it.check
            starts = self._starts(it)
            if ac.frames_fit(self.P.read, starts) or len(starts) < 3:
                continue
            if len(self.P.starts) >= MAX_FRAGMENTS:
                return False
            d = self.P.delta
            dd = self._find_sound(ac, starts, d)
            f = None if dd is None else self._cut(max(last, self.P.starts[-1] + 1), it.off, d, dd)
            if f is None:
                return False
            self.P.add(f, f + dd)
        return True

    def _find_sound(self, ac: AudioCheck, starts: list[int], d: int) -> int | None:
        """The nearest place ahead (block-aligned like the chunk) where every frame of a chunk starts right."""
        src, x0 = self.src, starts[0]
        pos = max(x0 + d + BLOCK, -src.base)
        stop = min(src.limit, pos + INSIDE_WINDOW)
        lead = re.compile(b"[\\x%02x\\x%02x]" % (ac.lead << 1, ac.lead << 1 | 1))    # either value of the 8th bit
        while pos < stop:
            n = min(_STEP, stop - pos)
            buf = src.read(pos, n + starts[-1] - x0 + 1)
            first = (x0 - pos) % BLOCK
            for m in lead.finditer(buf[first:n:BLOCK]):
                rel = first + m.start() * BLOCK
                if all(len(buf) > rel + s - x0 and buf[rel + s - x0] >> 1 == ac.lead for s in starts):
                    return pos + rel - x0
            pos += n
        return None

    def _place_moov(self, last: int, at: int, size: int, found: int) -> bool:
        """The movie box belongs at file offset AT; it was found at FOUND."""
        h = self.P.read(at, 8)
        if len(h) == 8 and _be32(h) == size and h[4:8] == b"moov":
            return True
        d = found - at
        if d % BLOCK or len(self.P.starts) >= MAX_FRAGMENTS:
            return False
        f = self._cut(max(last, self.P.starts[-1] + 1), at, self.P.delta, d)
        if f is None:
            return False
        self.P.add(f, f + d)
        return True

    # ---------------------------------------------------------------- finding where the file goes on
    def _continuation(self, k: int, last: int, fail: int) -> tuple[int, int] | None:
        vids, chk = self.video, self.vcheck
        d = self.P.delta
        lo = max(last, self.P.starts[-1] + 1)
        hi = fail + 8
        if chk.kind == "prores" and fail > vids[k].off:
            cut = self._inside_frame(k, lo, fail, d)
            if cut is not None:
                return cut
        if self.moov is not None and len(vids) - k <= 16:
            cut = self._with_moov(k, lo, hi, d)
            if cut is not None:
                return cut
        groups: dict[bytes, list[tuple[int, int]]] = {}
        for j in range(k, min(len(vids), k + 8)):
            for t, pat in chk.patterns(vids[j].size):
                groups.setdefault(pat, []).append((t, j))
        if not groups:
            return None
        start = _up(lo + d) - BLOCK
        stop = start + SEARCH_WINDOW + (vids[min(len(vids), k + 8) - 1].off - lo)
        tried = 0
        weak = None
        for q, j in self._hits(groups, start, stop):
            dd = q - vids[j].off
            if dd <= d or dd % BLOCK:
                continue
            tried += 1
            if tried > 4096:
                break
            fit = self._fits(k, j, dd, min(hi, vids[j].off) // BLOCK * BLOCK)
            if not fit:
                continue
            if fit == 1:                         # only that sample: kept in case nothing better turns up
                weak = weak or (j, dd)
                continue
            f = self._cut(lo, min(hi, vids[j].off), d, dd)
            if f is not None:
                return f, dd
        if weak is not None:
            j, dd = weak
            f = self._cut(lo, min(hi, vids[j].off), d, dd)
            if f is not None:
                return f, dd
        return None

    def _inside_frame(self, k: int, lo: int, fail: int, d: int) -> tuple[int, int] | None:
        """ProRes: the frame K goes on in another piece from the slice at FAIL: its slice table says where the
        next slices are, so the place is searched where their headers fit (a piece may hold no frame start)."""
        it = self.video[k]
        sl = prores_slices(self.P.read, it.off, it.size)
        if sl is None:
            return None
        i0 = next((i for i, (q, _n) in enumerate(sl) if q >= fail), None)
        if i0 is None:
            return None
        need = sl[i0:i0 + 6]
        q0 = need[0][0]
        src = self.src
        pos = max(q0 + d + BLOCK, -src.base)
        stop = min(src.limit, q0 + d + INSIDE_WINDOW)
        while pos < stop:
            n = min(_STEP, stop - pos)
            buf = src.read(pos, n + BLOCK)
            if not buf:
                return None
            first = (q0 - pos) % BLOCK                  # where the slice header would sit in each block
            col = buf[first:n:BLOCK]
            for m in _SLICE_HDR.finditer(col):
                at = pos + first + m.start() * BLOCK
                dd = at - q0
                if dd <= d:
                    continue
                if all(prores_slice_ok(src.read(q + dd, 8), size) for q, size in need):
                    f = self._cut(lo, q0, d, dd)
                    if f is not None:
                        return f, dd
            pos += n
        return None

    def _with_moov(self, k: int, lo: int, hi: int, d: int) -> tuple[int, int] | None:
        """The last samples in the piece that holds the movie box (found apart, at the end of the file)."""
        at, _size, found = self.moov
        dd = found - at                          # the movie box's piece may lie before the others
        if dd == d or dd % BLOCK:
            return None
        vids, chk = self.video, self.vcheck

        def get(x: int, n: int) -> bytes:
            return self.src.read(x + dd, n)
        first = k if vids[k].off >= hi // BLOCK * BLOCK else k + 1
        if any(chk.check(get, it.off, it.size, strict=True) >= 0 for it in vids[first:]):
            return None
        f = self._cut(lo, hi, d, dd)
        return None if f is None else (f, dd)

    def _hits(self, groups: dict[bytes, list[tuple[int, int]]], start: int, stop: int):
        """(position of a sample's first byte, which sample) where the patterns of the next samples are found,
        nearest first, at the right place within a block."""
        vids = self.video
        longest = max(len(p) + t for p, tj in groups.items() for t, _j in tj)
        pos = max(start, -self.src.base)
        stop = min(stop, self.src.limit)
        while pos < stop:
            n = min(_STEP, stop - pos)
            buf = self.src.read(pos, n + longest)
            if not buf:
                return
            found = []
            for pat, tj in groups.items():
                i = buf.find(pat)
                while 0 <= i < n and len(found) < 20000:
                    for t, j in tj:
                        q = pos + i - t
                        if (q - vids[j].off) % BLOCK == 0:
                            found.append((q, j))
                    i = buf.find(pat, i + 1)
            found.sort()
            yield from found
            pos += n

    def _fits(self, k: int, j: int, d: int, cut_max: int) -> int:
        """How well the samples fit when the file's data from sample K on is taken to be D bytes further on
        (the piece ends at CUT_MAX at the latest): 0 not at all; 2 the samples after K up to J and the one
        after J fit (that one may be cut by the next fragment: its first bytes are enough, or J holding enough
        structure of its own: ProRes slices, JPEG data, several NAL units); 1 only the samples up to J fit."""
        def get(x: int, n: int) -> bytes:
            return self.src.read(x + d, n)
        vids, chk = self.video, self.vcheck
        first = k if vids[k].off >= cut_max else k + 1          # sample K can't hold the cut: it moved too
        for it in vids[first:j]:
            if chk.check(get, it.off, it.size, strict=True) >= 0:
                return 0
        ev, until = chk.prefix(get, vids[j].off, vids[j].size)
        if until < vids[j].end:                  # J itself is cut short: the next fragment begins inside it
            return 2 if ev >= 4 else (1 if ev and chk.walk(get, vids[j].off, vids[j].size)[0] < 0 else 0)
        if j + 1 >= len(vids):
            return 2
        nxt = vids[j + 1]
        if chk.check(get, nxt.off, nxt.size, strict=True) < 0:
            return 2
        if any(get(nxt.off + t, len(pat)) == pat for t, pat in chk.patterns(nxt.size)):
            return 2
        return 2 if chk.evidence(get, vids[j].off, vids[j].size) >= 4 else 1

    def _overlapping(self, a: int, b: int) -> list[_Item]:
        i = bisect.bisect_right(self.offs, b)
        out = []
        for j in range(i - 1, -1, -1):
            it = self.items[j]
            if it.end > a:
                out.append(it)
            elif it.off < a - self.longest:
                break
        return out

    def _cut(self, lo: int, hi: int, d: int, dd: int) -> int | None:
        """Where the current piece ends (a block boundary in [lo, hi]) when the file goes on DD bytes further
        on in the source (it was D bytes up to there): the cut where the bytes fit best."""
        a, b = _up(lo), hi // BLOCK * BLOCK
        if a > b:
            return None
        self._learn_audio(lo)
        step = BLOCK
        while (b - a) // step > 1024:
            step *= 2
        a = _up(a, step)
        if a > b:
            a = b
        cands = range(a, b + 1, step)
        gap = min(_tz(dd - d), 24)
        items = self._overlapping(a, b + 1)
        if not items:
            return min(cands, key=lambda f: (-min(_tz(f), gap), f))
        u0 = min(it.off for it in items)
        u1 = max(it.end for it in items)
        A = self.P.read(u0, u1 - u0)
        B = self.src.read(u0 + dd, u1 - u0)
        if len(A) < u1 - u0 or len(B) < u1 - u0:
            A, B = A.ljust(u1 - u0, b"\0"), B.ljust(u1 - u0, b"\0")
        jpeg = self.vcheck.kind == "mjpeg"
        ia, ib = _Index(A, jpeg), _Index(B, jpeg)
        best = None
        cache: dict = {}
        keys = []
        for f in cands:
            hard, content, soft = self._penalty(f, items, A, B, u0, ia, ib, cache)
            if foreign(self.P.read(f, 16), jpeg):
                soft -= 1
            key = (hard, content, soft, -min(_tz(f), gap), f)
            keys.append(key)
            if best is None or key < best[0]:
                best = (key, f)
        if best is None or best[0][0]:
            return None                          # some frame doesn't fit whatever the cut
        # other cuts on a plausible cluster boundary (4 KiB or more) fit as well: the bytes can't tell them apart
        # (the likeliest alignment was taken)
        if any(k[:3] == best[0][:3] and k[4] != best[1] and (_tz(k[4]) >= 12 or k[3] == best[0][3]) for k in keys):
            self.uncertain += 1
        return best[1]

    def _penalty(self, f: int, items: list[_Item], A: bytes, B: bytes, u0: int, ia: _Index, ib: _Index,
                 cache: dict) -> tuple[int, int, int]:
        """(frames that don't fit, frames with bytes that can't be theirs, sound that doesn't look like it) when
        the piece ends at F."""
        f0 = f - u0

        def get(x: int, n: int) -> bytes:
            r0 = x - u0
            if r0 + n <= f0:
                return A[r0:r0 + n]
            if r0 >= f0:
                return B[r0:r0 + n]
            return A[r0:f0] + B[f0:r0 + n]

        chk = self.vcheck
        bad_re = _JMARK if chk.kind == "mjpeg" else _TRIPLET
        hard = content = soft = 0
        for it in items:
            if it.kind == 0:
                fail, pays, _v = chk.walk(get, it.off, it.size)
                if fail >= 0:
                    hard += 1
                    continue
                if chk.kind == "prores":
                    content += self._prores_bad(it, f, u0, get, A, B, cache)
                    continue
                for s, e in pays:
                    if (s < f and ia.bad(s - u0, min(e, f) - u0)) or (e > f and ib.bad(max(s, f) - u0, e - u0)):
                        content += 1
                        break
                    if s < f < e:
                        x = max(s, f - 2)
                        if bad_re.search(get(x, min(e, f + 2) - x)):
                            content += 1
                            break
            else:
                soft += self._audio_penalty(it, f, u0, get, A, B, ia, ib, cache)
        return hard, content, soft

    def _prores_bad(self, it: _Item, f: int, u0: int, get: Getter, A: bytes, B: bytes, cache: dict) -> int:
        """1 when a slice of a ProRes frame doesn't fit with the piece ending at F (its slice table says where
        every slice starts: the slices are checked once on each side, then counted per cut)."""
        def side(buf: bytes) -> Getter:
            return lambda x, n: buf[x - u0:x - u0 + n]
        lay = {}
        for k, buf in (("A", A), ("B", B)):
            key = ("prores", k, it.off)
            if key not in cache:
                sl = prores_slices(side(buf), it.off, it.size)
                if sl is None:
                    cache[key] = None
                else:
                    pos = [q for q, _n in sl]
                    oka = [not prores_slice_ok(A[q - u0:q - u0 + 8], n) for q, n in sl]
                    okb = [not prores_slice_ok(B[q - u0:q - u0 + 8], n) for q, n in sl]
                    pa, pb = [0], [0]
                    for x, y in zip(oka, okb):
                        pa.append(pa[-1] + x)
                        pb.append(pb[-1] + y)
                    cache[key] = (pos, pa, pb, sl)
            lay[k] = cache[key]
        la = lay["A"]
        tables_end = la[0][0] if la else it.end
        if f >= tables_end:
            got = la
        elif f <= it.off:
            got = lay["B"]
        else:
            sl = prores_slices(get, it.off, it.size)
            return int(sl is None or any(not prores_slice_ok(get(q, 8), n) for q, n in sl))
        if got is None:
            return 1
        pos, pa, pb, sl = got
        i = bisect.bisect_right(pos, f - 8)               # slices whose header lies wholly before F
        j = bisect.bisect_left(pos, f)                    # the first wholly after
        bad = pa[i] + (pb[-1] - pb[j])
        bad += sum(not prores_slice_ok(get(q, 8), n) for q, n in sl[i:j])
        return int(bad > 0)

    def _audio_penalty(self, it: _Item, f: int, u0: int, get: Getter, A: bytes, B: bytes, ia: _Index,
                       ib: _Index, cache: dict) -> int:
        ac: AudioCheck = it.check
        pen = 0
        if ac.kind in ("aac", "mp3", "amr"):
            if (it.off < f and ia.zeros(it.off - u0, min(it.end, f) - u0)) or \
                    (it.end > f and ib.zeros(max(it.off, f) - u0, it.end - u0)):
                pen += 4
            if ac.kind == "aac" and ac.ids and it.count <= 4096:
                s = it.off
                for n in it.table.sizes(it.first, it.count):
                    b = get(s, 1)
                    if b and b[0] >> 5 not in ac.ids:
                        pen += 1
                    s += n
        elif ac.kind and ac.kind.startswith("pcm"):
            blank = sound = 0
            for x in range(it.off, it.end - BLOCK + 1, BLOCK):      # blocks on the chunk's sample grid
                if x < f < x + BLOCK:
                    kind = ac.block(get(x, BLOCK))
                else:
                    side, buf = (0, A) if x < f else (1, B)
                    kind = cache.get((side, x))
                    if kind is None:
                        kind = cache[(side, x)] = ac.block(buf[x - u0:x - u0 + BLOCK])
                pen += kind == 2
                blank += kind == 0
                sound += kind == 1
            if blank and sound:                  # silence in the middle of sound: more likely blank disk space
                pen += blank
        return pen


def assemble(r, tables: list[Table], size: int, start_ok: int, moov: tuple[int, int, int] | None = None,
             need_start: bool = False) -> Assembly | None:
    """Put the file described by TABLES (a movie box's tracks) back together from the source around the
    candidate R. SIZE: the file's length; START_OK: the bytes before it are known to be in place (the boxes
    before the media data); MOOV: (where the movie box belongs in the file, its size, where it was found) for a
    movie box at the end. NEED_START: the first samples must be in place (pairing a movie box found apart).
    None when there is nothing to check with (or, with NEED_START, the samples don't fit)."""
    try:
        a = _Assembler(r, tables, size, start_ok)
        return a.run(need_start, moov)
    except (struct.error, IndexError, ValueError, OverflowError, MemoryError):
        return None


def tables_fit(tables: list[Table], lo: int, hi: int) -> bool:
    """Whether every chunk of every track lies inside [lo, hi) (a movie box tried against media data)."""
    for t in tables:
        last = t.last_chunk()
        if last is None or min(t.offsets) < lo:
            return False
        off, first, n = last
        if off + (t.const * n if t.const else sum(t.sizes(first, n))) > hi:
            return False
    return True


# ---------------------------------------------------------------------- movie boxes found apart
def find_moovs(r, start: int, stop: int, back: int = 0, limit: int = 64) -> list[int]:
    """Where movie boxes begin in [start, stop) (nearest first), then in the BACK bytes before the candidate
    (nearest first): a "moov" header of a plausible size whose first child is one a movie box starts with."""
    src = Around(r)
    out: list[int] = []

    def ok(buf: bytes, i: int) -> bool:
        if i < 4 or i + 12 > len(buf):
            return False
        size = _be32(buf, i - 4)
        return 24 <= size <= MAX_MOOV and buf[i + 8:i + 12] in _MOOV_FIRST and _be32(buf, i + 4) >= 8

    pos, stop = max(start, -src.base), min(stop, src.limit)
    while pos < stop and len(out) < limit:
        n = min(_STEP, stop - pos)
        buf = src.read(pos - 4, n + 16)
        i = buf.find(b"moov", 4)
        while 0 <= i < n + 4 and len(out) < limit:
            if ok(buf, i):
                out.append(pos - 4 + i - 4)
            i = buf.find(b"moov", i + 1)
        pos += n
    hi = 0
    lo_end = -min(back, src.base)
    while hi > lo_end and len(out) < limit:
        lo = max(lo_end, hi - _STEP)
        b0 = max(lo - 4, -src.base)
        buf = src.read(b0, hi + 16 - b0)
        found = []
        i = buf.find(b"moov", 4)
        while i >= 0 and b0 + i - 4 < hi:
            if b0 + i - 4 >= lo and ok(buf, i):
                found.append(b0 + i - 4)
            i = buf.find(b"moov", i + 1)
        out.extend(sorted((x for x in found if x < 0), reverse=True)[:limit - len(out)])
        hi = lo
    return out


def read_moov(r, at: int) -> tuple[bytes, list[Table]] | None:
    """The movie box at AT (relative to the candidate) and its tracks."""
    src = Around(r)
    h = src.read(at, 8)
    if len(h) < 8 or h[4:8] != b"moov":
        return None
    size = _be32(h)
    if not 24 <= size <= MAX_MOOV:
        return None
    buf = src.read(at, size)
    if len(buf) < size:
        return None
    return buf, read_tables(buf)


# ---------------------------------------------------------------------- unfinished recordings
@dataclass
class MediaScan:
    """What a media data box without an index holds, walked from its first byte."""

    video: str                  # "h264", "hevc", "prores", "mjpeg"
    start: int                  # where the media data begins (relative to the candidate)
    end: int                    # where the file is taken to end
    video_end: int              # the end of the last video frame
    frames: int = 0
    keyframes: int = 0
    gaps: list[int] = field(default_factory=list)    # the stretches between video runs (interleaved sound)
    moovs: list[int] = field(default_factory=list)   # movie boxes met on the way
    stopped: str = ""           # why the walk ended: "limit", "data", "file", "blank", "moov", "partial" (inside
    #                             a frame that stops being valid: the recording stopped there)
    sound: str | None = None    # what lies between the frames: "pcm", "compressed", None (nothing)


class _Walk:
    """State of the walk through media data: gap statistics bound the search for the next video frame."""

    def __init__(self, r, start: int, stop: int, jpeg: bool = False):
        self.w = _Window(r)
        self.base = getattr(r, "start", 0)
        self.start, self.stop = start, stop
        self.jpeg = jpeg
        self.gaps: list[int] = []
        self.frames = self.keys = 0
        self.max_unit = 0
        self.moovs: list[int] = []
        self.partial: list[tuple[int, int]] = []     # a frame that starts right but stops being valid
        self.blocked_at = stop
        self.gap_at: list[int] = []                  # where the first stretches of sound begin
        self._pcm: bool | None = None

    def gap(self, at: int, n: int) -> None:
        self.gaps.append(n)
        if len(self.gap_at) < 4 and n >= BLOCK:
            self.gap_at.append(at)

    def bound(self) -> int:
        if not self.gaps:
            return GAP_FIRST
        return min(GAP_MAX, max(512 * KiB, 4 * max(self.gaps)))

    def single(self) -> int:
        """How far a frame that isn't followed by another may be accepted (sound must lie in between)."""
        if not self.gaps:
            return 0 if self.frames >= 10 else 1 * MiB
        return 4 * max(self.gaps) + 4 * KiB

    def blocked(self, lo: int, hi: int) -> tuple[int, str] | None:
        """The first block boundary in [lo, hi) where another file starts or blank space begins (also kept in
        blocked_at)."""
        b = self._blocked(lo, hi)
        if b is not None:
            self.blocked_at = b[0]
        return b

    def _blocked(self, lo: int, hi: int) -> tuple[int, str] | None:
        x = _up(lo + self.base) - self.base
        blank_at, blanks = -1, 0
        while x < hi:
            blk = self.w.read(x, BLOCK)
            if len(blk) < 16:
                return x, "limit"
            if blk.count(0) == len(blk) or blk.count(255) == len(blk):
                if blanks == 0:
                    blank_at = x
                blanks += 1
                if blanks >= 256:
                    return blank_at, "blank"
            else:
                blanks = 0
                if blk[4:8] == b"moov" and 24 <= _be32(blk) <= MAX_MOOV:
                    self.moovs.append(x)
                    return x, "moov"
                if foreign(blk, self.jpeg):
                    return x, "file"
            x += BLOCK
        return None

    def tail(self, end: int) -> int:
        """Where the file ends after its last video frame: one typical stretch of sound later, short of blank
        space or another file (and, for PCM sound, of the first block that isn't sound)."""
        if not self.gaps:
            return end
        t = int(median(self.gaps))
        b = self.blocked(end, end + t)
        stop = min(end + t, self.stop, b[0] if b else end + t)
        if self.pcm:
            x, sound = end, False
            while x + BLOCK <= stop:
                blk = self.w.read(x, BLOCK)
                silent = not blk.strip(b"\0")
                if (silent and sound) or not (silent or sounds_like_pcm(blk)):
                    return x                     # noise, or blank space right after sound
                sound = not silent
                x += BLOCK
        return stop

    @property
    def sound(self) -> str | None:
        return None if not self.gap_at else "pcm" if self.pcm else "compressed"

    @property
    def pcm(self) -> bool:
        """Whether the sound between the frames is PCM (from the first stretches skipped)."""
        if self._pcm is None and self.gap_at and (len(self.gap_at) >= 2 or len(self.gaps) >= 2):
            votes = [sounds_like_pcm(self.w.read(x, BLOCK)) for x in self.gap_at[:4]]
            self._pcm = sum(votes) * 2 > len(votes)
        return bool(self._pcm)


def media_kind(r, start: int) -> str | None:
    """What the media data at START begins with: "prores", "mjpeg", "hevc", "h264" (4-byte NAL lengths)."""
    h = r.read(start, 64 * KiB)
    if len(h) < 16:
        return None
    if h[4:8] == b"icpf" and 28 <= _be32(h) <= 256 * MiB:
        return "prores"
    if h[:3] == b"\xff\xd8\xff":
        return "mjpeg"
    best, kind = 0, None
    for hevc in (False, True):
        p, units, vcl = 0, 0, False
        while p + 6 <= len(h) and units < 16:
            n = _be32(h, p)
            c = nal_class(h, p + 4, hevc)
            if not c or n < 2 or n > _MAX_NAL or (hevc and h[p + 5] >> 3):
                break
            if c >= 2 and not vcl:
                if not first_slice(h[p + 4:p + 8], hevc) or slice_header(h[p + 4:p + 24], hevc) is None:
                    break
                vcl = True
            units += 1
            p += 4 + n
        if vcl and units > best:                 # the same lengths chain either way: the headers decide
            best, kind = units, "hevc" if hevc else "h264"
    return kind


def scan_media(r, start: int, stop: int) -> MediaScan | None:
    """Walk the media data that begins at START (up to STOP) as far as it stays video: None when it doesn't
    begin with video at all."""
    stop = min(stop, r.limit)
    try:
        kind = media_kind(r, start)
        if kind in ("h264", "hevc"):
            return _scan_nals(r, start, stop, kind == "hevc")
        if kind == "prores":
            return _scan_frames(r, start, stop, "prores")
        if kind == "mjpeg":
            return _scan_frames(r, start, stop, "mjpeg")
    except (struct.error, IndexError, ValueError, BitsError, OverflowError):
        return None
    return None


def _scan_nals(r, start: int, stop: int, hevc: bool) -> MediaScan | None:
    wk = _Walk(r, start, stop)
    w = wk.w
    hl = 2 if hevc else 1
    pos, video_end = start, start
    units = 0
    pps = None
    stopped = "limit"
    pattern = _HEVC_START if hevc else _H264_START

    def unit(p: int, lmax: int, check: Callable[[int, bytes], bool] | None = None, cut: list | None = None
             ) -> tuple[int, int, bytes] | None:
        """(length, class, its bytes) of the NAL unit at P; CHECK sees the first bytes before it is read. A
        unit that starts right but whose bytes stop being valid (the recording stopped inside it) goes to
        CUT as (P, where its data stops)."""
        h = w.read(p, 24)
        if len(h) < 4 + hl + 1:
            return None
        n = _be32(h)
        if n < hl or n > lmax or h[4:8] == b"moov":
            return None
        c = nal_class(h, 4, hevc)
        if not c or (check is not None and not check(c, h[4:])):
            return None
        data = w.read(p + 4, min(n, stop - p - 4))
        m = _TRIPLET.search(data, hl)
        if m or len(data) < n:
            if cut is not None and c >= 2:
                cut.append((p, p + 4 + (m.start() if m else len(data))))
            return None
        return n, c, data

    order = None if hevc else _FrameNums()
    while pos < stop:
        wk.partial = []
        u = unit(pos, _MAX_NAL, cut=wk.partial)
        if u is not None:
            n, c, data = u
            if c >= 2 and first_slice(data, hevc):
                if pps is None:
                    sh = slice_header(data, hevc)
                    pps = sh[1] if sh else None
                if order is not None and not order.add(data):
                    stopped = "stream"                   # another recording's frames from here on
                    break
                wk.frames += 1
                wk.keys += c == 3
            units += 1
            wk.max_unit = max(wk.max_unit, n)
            pos += 4 + n
            video_end = pos
            continue
        if w.read(pos + 4, 4) == b"moov":
            wk.moovs.append(pos)
            stopped = "moov"
            break
        if units == 0:
            return None
        q, why = _resync_nal(wk, pos, unit, pattern, hevc, pps)
        if q is None:
            stopped = why
            if wk.partial and (why not in ("file", "moov") or wk.partial[0][0] < wk.blocked_at):
                video_end = max(video_end, min(wk.partial[0][1], wk.blocked_at))
                stopped = "partial"                     # the recording stopped inside that frame
            break
        wk.gap(pos, q - pos)
        pos = q
    if wk.frames == 0 or (units < 2 and video_end - start < 4096):
        return None
    end = _media_end(wk, video_end, stopped)
    return MediaScan("hevc" if hevc else "h264", start, end, video_end, wk.frames, wk.keys, wk.gaps, wk.moovs,
                     stopped, wk.sound)


class _FrameNums:
    """H.264 frame_num continuity: every picture's frame_num is the previous reference picture's, plus one (0
    for an IDR picture). Its width is in the sequence parameter set (in the missing index), so every width is
    tried on the first pictures; once one fits them all, a picture that breaks the rule starts another
    recording (old data after the end of an unfinished one is often an older video of the same camera)."""

    LEARN = 12

    def __init__(self):
        self.seen: list[tuple[int, bool, bool]] = []    # (16 bits after pps_id, reference, IDR)
        self.width: int | None = None
        self.prev_ref = 0
        self.dead = False                                # no width fits: don't judge

    @staticmethod
    def _fields(nal: bytes) -> tuple[int, bool, bool] | None:
        try:
            br = BitReader(nal[:24], 8)
            br.ue()
            br.ue()
            br.ue()
            return br.peek(16) if br.left >= 16 else None, bool(nal[0] & 0x60), nal[0] & 31 == 5
        except BitsError:
            return None

    @staticmethod
    def _fits(seq: list[tuple[int, bool, bool]], w: int) -> bool:
        prev, mod = None, 1 << w
        for raw, ref, idr in seq:
            fn = raw >> (16 - w)
            if idr:
                if fn:
                    return False
            elif prev is not None and fn not in (prev, (prev + 1) % mod):
                return False
            if ref or idr:
                prev = fn
        return True

    def add(self, nal: bytes) -> bool:
        """Note the first slice of a picture; False when it can't follow the pictures before it."""
        f = self._fields(nal)
        if f is None or f[0] is None or self.dead:
            return True
        if self.width is None:
            self.seen.append(f)
            if len(self.seen) >= self.LEARN:
                fit = [w for w in range(4, 17) if self._fits(self.seen, w)]
                if not fit:
                    self.dead = True
                    return True
                self.width = max(fit)            # a narrower one reads only its high bits: it fits anyway
                prev = None
                for raw, ref, idr in self.seen:
                    if ref or idr:
                        prev = raw >> (16 - self.width)
                self.prev_ref = prev or 0
            return True
        raw, ref, idr = f
        fn = raw >> (16 - self.width)
        if idr:
            ok = fn == 0
        else:
            ok = fn in (self.prev_ref, (self.prev_ref + 1) % (1 << self.width))
        if ok and (ref or idr):
            self.prev_ref = fn
        return ok


def _resync_nal(wk: _Walk, pos: int, unit, pattern: re.Pattern, hevc: bool, pps: int | None
                ) -> tuple[int | None, str]:
    """The next place after POS where a video frame starts, within the bound of a sound stretch."""
    end = min(wk.stop, pos + wk.bound())
    single_until = pos + wk.single()
    lmax = min(8 * MiB, max(64 * KiB, 8 * wk.max_unit))
    checked = pos
    p = pos + 1

    def starts_picture(c: int, head: bytes) -> bool:
        if c < 2:
            return True                                           # SEI / AUD / parameter set: must chain
        if not first_slice(head, hevc):
            return False
        sh = slice_header(head, hevc)
        return sh is not None and (pps is None or sh[1] == pps)

    while p < end:
        n = min(1 * MiB, end - p)
        buf = wk.w.read(p, n + 16)
        if not buf:
            break
        mv = _moov_in(buf, n)
        for m in pattern.finditer(buf, 0, min(n, mv if mv is not None else n) + 5):
            q = p + m.start()
            if q >= end:
                break
            u = unit(q, lmax, starts_picture, None if wk.partial or q >= single_until else wk.partial)
            if u is None:
                continue
            ln, c, _data = u
            nxt = unit(q + 4 + ln, _MAX_NAL)
            if nxt is None and (c < 2 or q >= single_until):
                continue
            b = wk.blocked(checked, q)
            if b is not None:
                return None, b[1]
            return q, ""
        if mv is not None:
            b = wk.blocked(checked, p + mv)
            if b is not None:
                return None, b[1]
            wk.moovs.append(p + mv)
            return None, "moov"
        b = wk.blocked(checked, p + n)
        if b is not None:
            return None, b[1]
        checked = p + n
        p += n
    return None, "limit" if end >= wk.stop else "data"


def _media_end(wk: _Walk, video_end: int, stopped: str) -> int:
    """Where the media data ends: at the movie box the walk met, where the last frame stops being valid, else
    one stretch of sound after the last frame (short of blank space or another file)."""
    if stopped == "moov" and wk.moovs and wk.moovs[-1] >= video_end:
        return wk.moovs[-1]
    if stopped == "partial":
        return video_end
    return wk.tail(video_end) if video_end < wk.stop else video_end


def _moov_in(buf: bytes, n: int) -> int | None:
    """Where a movie box header begins in the first N bytes of BUF."""
    i = buf.find(b"moov", 4)
    while 0 <= i < n + 4:
        if i + 12 <= len(buf) and 24 <= _be32(buf, i - 4) <= MAX_MOOV and buf[i + 8:i + 12] in _MOOV_FIRST:
            return i - 4
        i = buf.find(b"moov", i + 1)
    return None


def _jpeg_end(w: _Window, pos: int, stop: int) -> tuple[int, bytes, bool] | None:
    """(end, SOF fields, complete) of the JPEG picture at POS: complete when it reaches its end marker, else
    the end is where its compressed data stops being valid (a stray marker, 64 zero bytes: the recording
    stopped inside it). None if it doesn't start like a picture."""
    if w.read(pos, 3) != b"\xff\xd8\xff":
        return None
    p, sof = pos + 2, b""
    for _ in range(256):
        m = w.read(p, 4)
        if len(m) < 4 or m[0] != 0xFF:
            return (p, sof, False) if sof else None
        mk = m[1]
        if mk == 0xD9:
            return p + 2, sof, True
        if mk < 0xC0 or mk == 0xD8:
            return (p, sof, False) if sof else None
        n = (m[2] << 8) | m[3]
        if n < 2:
            return None
        if 0xC0 <= mk <= 0xCF and mk not in (0xC4, 0xC8, 0xCC):
            sof = w.read(p + 4, 6)
        p += 2 + n
        if mk == 0xDA:
            q = p
            while True:
                buf = w.read(q, 1 * MiB)
                if len(buf) < 2:
                    return (q, sof, False) if sof else None
                mm = _JMARK.search(buf)
                z = buf.find(_ZEROS64, 0, mm.start() if mm else len(buf))
                if z >= 0:
                    return (q + z, sof, False) if sof else None
                if mm is None:
                    q += len(buf) - 1
                    if q - p > 64 * MiB or q >= stop:
                        return (min(q, stop), sof, False) if sof else None
                    continue
                if buf[mm.start() + 1] != 0xD9:      # a Motion JPEG frame has one scan: only its end follows
                    return (q + mm.start(), sof, False) if sof else None
                return q + mm.start() + 2, sof, True
    return None


def _scan_frames(r, start: int, stop: int, kind: str) -> MediaScan | None:
    """ProRes and Motion JPEG: frames that say (or show) where they end, with sound between them."""
    wk = _Walk(r, start, stop, jpeg=kind == "mjpeg")
    w = wk.w
    pos = video_end = start
    ident: bytes | None = None
    stopped = "limit"

    def frame(p: int) -> int | None:
        nonlocal ident
        if kind == "prores":
            h = w.read(p, 20)
            if len(h) < 20 or h[4:8] != b"icpf":
                return None
            n = _be32(h)
            if n < 28 or n > 256 * MiB or p + n > stop or (ident is not None and h[16:20] != ident):
                return None
            ident = ident or h[16:20]
            return p + n
        j = _jpeg_end(w, p, stop)
        if j is None or j[0] > stop or (ident is not None and j[1] != ident):
            return None
        if not j[2]:                                     # starts right, stops being valid: maybe the last
            if not partial and p < single_until:
                partial.append((p, j[0]))
            return None
        ident = ident or j[1]
        return j[0]

    sig = b"icpf" if kind == "prores" else b"\xff\xd8\xff"
    back = 4 if kind == "prores" else 0
    partial: list[tuple[int, int]] = []
    last = None
    single_until = stop
    while pos < stop:
        partial.clear()
        single_until = pos + 1
        e = frame(pos)
        if e is not None:
            wk.frames += 1
            wk.max_unit = max(wk.max_unit, e - pos)
            last = pos
            pos = video_end = e
            continue
        single_until = pos + max(wk.single(), BLOCK)
        if wk.frames == 0:
            return None
        bound = min(stop, pos + wk.bound())
        q = mv = None
        x = pos
        while x < bound and q is None and mv is None:
            n = min(1 * MiB, bound - x)
            buf = w.read(x, n + 16)
            if not buf:
                break
            m = _moov_in(buf, n)
            mv = None if m is None else x + m
            i = buf.find(sig, 0)
            while i >= 0 and x + i - back < min(bound, mv if mv is not None else bound):
                if x + i - back > pos and frame(x + i - back) is not None:
                    q = x + i - back
                    break
                i = buf.find(sig, i + 1)
            x += n
        if q is None:
            stopped = "data"
            if mv is not None and wk.blocked(pos, mv) is None:
                wk.moovs.append(mv)
                stopped = "moov"
            elif partial and wk.blocked(pos, partial[0][0]) is None:
                video_end, stopped = min(partial[0][1], wk.blocked_at), "partial"    # it stopped inside
            break
        b = wk.blocked(pos, q)
        if b is not None:
            stopped = b[1]
            break
        wk.gap(pos, q - pos)
        pos = q
    if wk.frames < 2 and video_end - start < 4096:
        return None
    if kind == "prores" and last is not None and stopped != "partial":
        fail, _seen = VideoCheck("prores").slices_fit(w.read, last, video_end - last)
        if fail >= 0:                                    # the last frame stops being valid inside
            video_end, stopped = fail, "partial"
    end = _media_end(wk, video_end, stopped)
    return MediaScan(kind, start, end, video_end, wk.frames, wk.frames, wk.gaps, wk.moovs, stopped, wk.sound)
