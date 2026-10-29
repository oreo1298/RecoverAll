"""Repairing MP4, MOV, 3GP and M4V videos, above all recordings whose index was never written.

A camera or phone writes the pictures and the sound into the media data box (mdat) while it records, and the
index (the movie box, moov, whose sample tables say where every frame is and when it is shown) only when the
recording stops. When the battery dies, the app crashes or the card is pulled out, the index is missing and no
player opens the file, although every frame is still there. The repair finds the frames again:

* With a reference video (a good recording from the same camera with the same settings) the tracks, the codec
  configuration (the whole sample description), the frame and sound timing and the way the camera interleaves
  pictures and sound are learned from the reference's index. Then the media data is walked from its start and
  cut into frames: H.264/H.265 frames by their NAL units (each says its length; slice headers say where a new
  picture starts, whether it is a key frame and in which order the pictures are shown, which gives the
  B-frames their composition offsets); MPEG-4 Part 2 and H.263 frames by their start codes; MJPEG frames by
  their JPEG markers; ProRes frames by their frame header; AAC frames by parsing them (raw AAC has no header);
  AMR, AC-3 and MP3 frames by their headers; PCM sound by the reference's chunk sizes; timecode and GoPro
  metadata (GPMF) tracks too. At every position the track the reference's interleaving makes most likely is
  tried first, then every other one (the ones with the most telling structure first). A damaged stretch is
  skipped: the walk carries on at the next frame that parses, and the pictures up to the next key frame are
  dropped because they can't be decoded. The repaired file is the media data as it is, then a new index.
* Without a reference, a recording whose camera repeats the parameter sets (SPS/PPS) in the stream can still
  be rebuilt, as video only; otherwise analyze() asks for a reference video.
* A file whose index is intact but that is cut short keeps the frames that are complete, with the sample
  tables shortened to them; when the index comes first ("fast start") it keeps its place. A fragmented file
  loses its incomplete last fragment (or, without its first part, gets the reference's). An index that points
  to the wrong places (a file that lost its first bytes) is shifted to where the frames are.

Standard library only. The media data is never read into memory as a whole: the repaired file is written as
pieces (ranges of the damaged file and new bytes), so recordings of many gigabytes are fine.
"""

from __future__ import annotations

import math
import re
import struct
from array import array
from dataclasses import dataclass, field
from pathlib import Path

from . import h264, hevc
from . import isobmff as I
from .bits import BitReader, BitsError
from .isobmff import Box, Movie, Track, box, full_box

try:
    from . import aac
except ImportError:                                     # written by another part of the project
    aac = None
try:
    from . import audioframes
except ImportError:
    audioframes = None

KiB, MiB = 1024, 1024 * 1024
PREWALK = 48 * MiB                    # analyze() walks this much of a recording without index

AVC = {"avc1", "avc2", "avc3", "avc4", "dvav", "dva1"}
HEVC = {"hvc1", "hev1", "dvhe", "dvh1"}
MP4V = {"mp4v"}
H263 = {"s263", "h263", "H263"}
JPEG = {"jpeg", "mjpa", "AVDJ", "MJPG", "dmb1"}
PRORES = {"apch", "apcn", "apcs", "apco", "ap4h", "ap4x", "aprn", "aprh"}
PCM_WIDTH = {"sowt": 0, "twos": 0, "raw ": 1, "NONE": 0, "lpcm": 0, "ipcm": 0, "fpcm": 0, "in24": 3, "in32": 4,
             "fl32": 4, "fl64": 8, "ulaw": 1, "alaw": 1}
AMR = {"samr": "nb", "sawb": "wb"}
HANDLERS = {"vide": "video", "soun": "sound", "tmcd": "timecode", "meta": "metadata", "text": "text",
            "sbtl": "subtitle", "subt": "subtitle", "hint": "hint", "data": "data"}
NAMES = {"avc": "H.264", "hevc": "H.265", "mp4v": "MPEG-4", "h263": "H.263", "jpeg": "Motion JPEG", "prores": "ProRes",
         "aac": "AAC", "pcm": "PCM", "amr": "AMR", "ac3": "AC-3", "eac3": "E-AC-3", "mp3": "MP3", "tmcd": "timecode",
         "gpmd": "GoPro metadata", "const": "data"}


def _mode(values) -> int:
    """The most common value (the smallest of equally common ones); 0 for none."""
    counts: dict[int, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    return min(counts, key=lambda v: (-counts[v], v)) if counts else 0


def _plural(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}".replace(",", " ")


# ---------------------------------------------------------------------- frames of other codecs
def ac3_frame(buf, pos: int, end: int) -> tuple[int, int, int] | None:
    """An AC-3 or E-AC-3 sync frame at POS: (length, audio blocks, stream type: 0 independent, 1 dependent, 2
    AC-3), or None."""
    h = audioframes.ac3_header(buf, pos) if audioframes is not None else None
    if h is None or h["length"] < 8 or pos + h["length"] > end:
        return None
    return h["length"], h["blocks"], (buf[pos + 2] >> 6) if h["eac3"] else 2


def amr_frame(buf, pos: int, end: int, wide: bool) -> int:
    """The length of the AMR (or AMR-WB) frame at POS in storage format, 0 if none."""
    return (audioframes.amr_frame_length(buf, pos, end, wide) or 0) if audioframes is not None else 0


def mp3_frame(buf, pos: int, end: int) -> int:
    """The length of the MPEG audio frame at POS, 0 if none."""
    return (audioframes.mpa_frame_length(buf, pos, end) or 0) if audioframes is not None else 0


_JPEG_NEXT = re.compile(rb"\xff[\x01-\xcf\xd8-\xfe]")


def jpeg_end(buf, pos: int, end: int) -> int:
    """The end of the JPEG image that starts at POS (after its EOI marker), 0 if it isn't one or is cut."""
    if pos + 4 > end or buf[pos] != 0xFF or buf[pos + 1] != 0xD8 or buf[pos + 2] != 0xFF:
        return 0
    p = pos + 2
    while p + 4 <= end:
        if buf[p] != 0xFF:
            return 0
        m = buf[p + 1]
        if m == 0xFF:
            p += 1
            continue
        if m == 0xD9:
            return p + 2
        if 0xD0 <= m <= 0xD7 or m == 0x01:
            p += 2
            continue
        n = (buf[p + 2] << 8) | buf[p + 3]
        if n < 2:
            return 0
        p += 2 + n
        if m == 0xDA:                                    # entropy-coded data up to the next marker
            hit = _JPEG_NEXT.search(buf, p, end)
            if hit is None:
                return 0
            p = hit.start()
    return 0


def prores_frame(buf, pos: int, end: int) -> int:
    """The length of the ProRes frame at POS (its size field, then "icpf"), 0 if none."""
    if pos + 28 > end or bytes(buf[pos + 4:pos + 8]) != b"icpf":
        return 0
    n = I.be32(buf, pos)
    hdr = (buf[pos + 8] << 8) | buf[pos + 9]
    if n < 28 or pos + n > end or not 20 <= hdr <= 512:
        return 0
    return n


def gpmf_sample(buf, pos: int, end: int) -> int:
    """The length of a GoPro metadata sample at POS: DEVC key-length-value structures, 0 if none."""
    p = pos
    while p + 8 <= end and bytes(buf[p:p + 4]) == b"DEVC" and buf[p + 4] == 0:
        n = buf[p + 5] * ((buf[p + 6] << 8) | buf[p + 7])
        n = (n + 3) & ~3
        if n == 0 or p + 8 + n > end:
            break
        p += 8 + n
    return p - pos


def pcm_bytes_per_frame(t: Track) -> int:
    """The bytes of one PCM sample frame (all channels) of a QuickTime/ISO sound track, 0 if unknown."""
    if audioframes is None:
        return 0
    return audioframes.pcm_frame_bytes(t.codec, t.channels, t.sample_bits, t.entry) or 0


# ---------------------------------------------------------------------- what a sample read gave
@dataclass
class Hit:
    size: int
    key: bool = True
    info: object = None                    # the codec's own details (an access unit)
    cut: bool = False                      # the data ends inside this frame
    open_end: bool = False                 # no length of its own: it may end earlier (start-code codecs)
    at_end: bool = False                   # ... and nothing of its own kind follows it


# ---------------------------------------------------------------------- tracks being rebuilt
class TrackRebuild:
    """One track of the rebuilt movie: how its samples are recognised (learned from the reference, or from the
    stream) and the samples found, kept as chunks (runs of samples one after the other in the file)."""

    kind = ""
    strong = False                      # telling structure: tried first, and the walk can resynchronise on it
    video = False

    def __init__(self, ref: Track, dur: int):
        self.ref = ref
        self.dur = max(1, dur)          # a sample's duration in the media timescale
        self.chunk_offsets: list[int] = []
        self.chunk_counts: list[int] = []
        self._chunk_end = -1
        self.count = 0
        self.const_size = 0             # every sample this size: SIZES isn't kept
        self.sizes = array("I")
        self.extra: dict[int, int] = {}  # sample index -> extra duration after it (a gap in the recording)
        self.lead = 0                   # duration missing before the first sample
        self.data_end = 0
        self.max_size = 0               # of the reference's samples
        self.chunk_bytes: list[int] = []  # the reference's chunk sizes in bytes, most common first
        self.max_chunk = 0
        self.media_start = 0            # where the reference's edit list starts showing it (encoder delay)
        self.shift = 0                  # composition shift (B-frames), set with the composition offsets

    @property
    def name(self) -> str:
        return NAMES.get(self.kind, self.kind)

    def add(self, pos: int, size: int, n: int = 1) -> None:
        """Samples (N of them, SIZE bytes in all) at POS."""
        if pos == self._chunk_end and self.chunk_counts:
            self.chunk_counts[-1] += n
        else:
            self.chunk_offsets.append(pos)
            self.chunk_counts.append(n)
        self._chunk_end = pos + size
        self.count += n
        if not self.const_size:
            self.sizes.append(size)
        self.data_end = max(self.data_end, pos + size)

    def gap(self, duration: int) -> None:
        """DURATION (media timescale) of this track is missing at the current place."""
        if duration <= 0:
            return
        if self.count:
            self.extra[self.count - 1] = self.extra.get(self.count - 1, 0) + duration
        else:
            self.lead += duration

    def after_gap(self) -> None:
        """The walk skipped damaged data."""
        self._chunk_end = -1

    # strong tracks
    def quick(self, buf, pos: int, end: int) -> bool:
        return False

    def match(self, buf, pos: int, end: int, learn: bool = True) -> Hit | None:
        return None

    def take(self, pos: int, hit: Hit) -> None:
        self.add(pos, hit.size)

    def candidates(self) -> re.Pattern | None:
        """Where a sample may start, for resynchronising."""
        return None

    # weak tracks
    def stretch(self, walk: Walk, pos: int) -> int | None:
        """Take this track's samples from POS on; the position after them, or None when none is there."""
        return None

    def tail(self, walk: Walk, lo: int, q: int, expected: float | None = None) -> int | None:
        """The start S (>= LO) of a run of this track's samples that ends exactly at Q, or None. EXPECTED is
        about how many samples the run should have (to keep this track in step with the video)."""
        return None

    # the sample tables
    def durations(self) -> list[int]:
        d = [self.dur] * self.count
        for k, extra in self.extra.items():
            if k < len(d):
                d[k] += extra
        return d

    def stts_runs(self) -> list[tuple[int, int]]:
        if not self.extra:
            return [(self.count, self.dur)] if self.count else []
        return I.runs(self.durations())

    def ctts_runs(self) -> list[tuple[int, int]]:
        return []

    def sync_samples(self) -> list[int] | None:
        return None

    def media_duration(self) -> int:
        return self.count * self.dur + sum(self.extra.values())


class VideoRebuild(TrackRebuild):
    video = True
    strong = True

    def __init__(self, ref: Track, dur: int):
        super().__init__(ref, dur)
        self.keys: list[int] = []
        self.need_key = True            # at the start and after damage: drop pictures up to a key frame
        self.dropped = 0
        self.all_keys = True

    def take(self, pos: int, hit: Hit) -> None:
        if self.need_key and not hit.key:
            self.dropped += 1
            self.gap(self.dur)
            return
        self.need_key = False
        if hit.key:
            self.keys.append(self.count)
        else:
            self.all_keys = False
        self.add(pos, hit.size)

    def after_gap(self) -> None:
        super().after_gap()
        self.need_key = True

    def sync_samples(self) -> list[int] | None:
        return None if self.all_keys and len(self.keys) == self.count else self.keys


class NalVideo(VideoRebuild):
    """H.264 or H.265 in MP4 samples: length-prefixed NAL units; the picture order gives the composition
    offsets of B-frames."""

    def __init__(self, ref: Track, dur: int, reader, kind: str, start_bytes: set[int] | None = None,
                 delay: int | None = None):
        super().__init__(ref, dur)
        self.kind = kind
        self.reader = reader
        self.poc_state = h264.PocState() if kind == "avc" else hevc.PocState()
        self.pocs = array("i")
        self.period = array("I")        # the picture order resets at every IDR: which run a picture is in
        self._period = 0
        self.delay = delay              # the reference's reorder delay (in durations), if it had B-frames
        self.start_bytes = start_bytes
        self.reorder = 0
        self._pattern: re.Pattern | None = None
        self.rasl_skip = False
        self.seen_max = 0               # the largest picture so far

    def quick(self, buf, pos: int, end: int) -> bool:
        return self.reader.first_ok(buf, pos, end)

    def match(self, buf, pos: int, end: int, learn: bool = True) -> Hit | None:
        rd = self.reader
        if not rd.first_ok(buf, pos, end):
            return None
        au = rd.read(buf, pos, end, learn)
        if au is None:
            return None
        q = pos + au.size
        biggest = max(self.max_size, self.seen_max) or MiB
        near_end = end - q <= 2 * biggest + 4 * KiB             # a frame can only be cut where the data ends
        return Hit(au.size, au.key, au, cut=near_end and _nal_cut(self.kind, rd, buf, q, end, au, 2 * biggest))

    def take(self, pos: int, hit: Hit) -> None:
        au = hit.info
        self.seen_max = max(self.seen_max, hit.size)
        if self.kind == "avc":
            if au.header.idr:
                self._period += 1
            poc = self.poc_state.poc(au.header, au.sps)
            if au.second_field is not None:
                poc = min(poc, self.poc_state.poc(au.second_field, au.sps))
            if au.sps is not None and au.sps.max_num_reorder_frames:
                self.reorder = max(self.reorder, au.sps.max_num_reorder_frames)
        else:
            h = au.header
            if h.irap and h.nal_type < hevc.CRA:      # IDR or BLA: the picture order starts again
                self._period += 1
            poc = self.poc_state.poc(h, au.sps)
            if au.eos:
                self.poc_state.end_of_sequence()
            if au.sps is not None:
                self.reorder = max(self.reorder, au.sps.max_num_reorder)
            if self.need_key and h.irap:
                self.rasl_skip = True
            elif h.irap:
                self.rasl_skip = False
            if self.rasl_skip and h.rasl:
                self.dropped += 1
                self.gap(self.dur)
                return
        kept = not (self.need_key and not hit.key)
        super().take(pos, hit)
        if kept:
            self.pocs.append(poc)
            self.period.append(self._period)

    def after_gap(self) -> None:
        super().after_gap()
        self._period += 1
        if self.kind == "hevc":
            self.poc_state.end_of_sequence()

    def candidates(self) -> re.Pattern | None:
        if self._pattern is None:
            ls = self.reader.length_size
            first = sorted(self.start_bytes) if self.start_bytes else \
                [b for b in range(256) if (h264.HEADER_OK[b] and b & 31 in (1, 5, 6, 7, 8, 9))] \
                if self.kind == "avc" else [t << 1 for t in (*range(10), *range(16, 22), 32, 33, 34, 35, 39)]
            cls = b"[" + b"".join(re.escape(bytes([b])) for b in first) + b"]"
            lead = b"\\x00" + b"[\\x00-\\xff]" * (ls - 1) if ls == 4 else b"[\\x00-\\xff]" * ls
            tail = b"[\\x01-\\x07]" if self.kind == "hevc" else b""
            self._pattern = re.compile(lead + cls + tail, re.S)
        return self._pattern

    def ctts_runs(self) -> list[tuple[int, int]]:
        """Composition offsets from the picture order: within a run between IDR pictures, a picture is shown
        (POC - the run's lowest POC) / the POC step frames after the run starts; a missing picture leaves its
        place empty. When the POCs aren't evenly spaced, the pictures just take the run's times in POC order."""
        n = self.count
        if n == 0:
            return []
        dts = [0] * n
        t = 0
        for i, d in enumerate(self.durations()):
            dts[i] = t
            t += d
        runs = []
        a = 0
        while a < n:
            b = a
            while b < n and self.period[b] == self.period[a]:
                b += 1
            runs.append((a, b))
            a = b
        steps = []
        for a, b in runs[:200]:
            ps = sorted(set(self.pocs[a:b]))
            d = min((y - x for x, y in zip(ps, ps[1:])), default=0)
            if d > 0:
                steps.append(d)
        step = _mode(steps)
        pts = [0] * n
        for a, b in runs:
            lo = min(self.pocs[a:b])
            spaced = step > 0 and all((self.pocs[i] - lo) % step == 0 for i in range(a, b)) and \
                (max(self.pocs[a:b]) - lo) // step < 2 * (b - a) + 16
            if spaced:
                for i in range(a, b):
                    pts[i] = dts[a] + (self.pocs[i] - lo) // step * self.dur
            else:
                order = sorted(range(a, b), key=lambda i: (self.pocs[i], i))
                for r, i in enumerate(order):
                    pts[i] = dts[a + r]
        shift = max(dts[i] - pts[i] for i in range(n))
        hint = self.delay if self.delay is not None else self.reorder
        if hint and hint * self.dur >= shift:
            shift = hint * self.dur
        if shift == 0 and all(pts[i] == dts[i] for i in range(n)):
            self.shift = 0
            return []
        self.shift = shift
        return I.runs(pts[i] - dts[i] + shift for i in range(n))


def _nal_cut(kind: str, rd, buf, p: int, end: int, au, longest: int) -> bool:
    """Does the data end inside the picture that ends at P (its next slice, at most LONGEST bytes, runs past
    the end)?"""
    ls = rd.length_size
    if p + ls + 3 > end:
        return False
    n = int.from_bytes(buf[p:p + ls], "big")
    if p + ls + n <= end or n > min(rd.max_nal, longest) or n < 2:
        return False
    a = p + ls
    if not h264.payload_ok(buf, a, end):
        return False
    if kind == "avc":
        h = buf[a]
        if not h264.HEADER_OK[h]:
            return False
        t = h & 31
        if t in (h264.SLICE, h264.IDR):
            parsed = h264.parse_slice_header(buf[a:min(end, a + 64)], rd.params)
            return parsed is not None and au.header is not None and not h264.new_picture(au.header, parsed[0],
                                                                                          parsed[1])
        return t in (h264.DPB, h264.DPC)
    b0, b1 = buf[a], buf[a + 1]
    if not hevc.header_ok(b0, b1, rd.layers):
        return False
    t = (b0 >> 1) & 63
    if t in hevc.VCL_TYPES:
        parsed = hevc.parse_slice_header(buf[a:min(end, a + 64)], rd.params)
        return parsed is not None and not parsed[0].first_in_pic
    return t == hevc.SUFFIX_SEI


class StartCodeVideo(VideoRebuild):
    """MPEG-4 Part 2 (VOP start codes 00 00 01 B6) and H.263 (picture start codes 00 00 8x): a frame runs to
    the next start code, less the other tracks' samples that may come before it."""

    def __init__(self, ref: Track, dur: int, kind: str, time_bits: int = 0, formats: set[int] | None = None):
        super().__init__(ref, dur)
        self.kind = kind
        self.time_bits = time_bits      # MPEG-4: bits of vop_time_increment (from the VOL header)
        self.formats = formats or set()  # H.263: the source formats seen
        self.min_size = 8

    _MP4V = re.compile(rb"\x00\x00\x01[\xb0\xb3\xb5\xb6\x00-\x2f]")
    _H263 = re.compile(rb"\x00\x00[\x80-\x83]")

    def _vop_ok(self, buf, pos: int, end: int) -> bool | None:
        """A plausible VOP header at POS (after 00 00 01 B6): True for an I-VOP, False for others, None if
        it isn't one."""
        try:
            r = BitReader(bytes(buf[pos + 4:min(end, pos + 16)]))
            kind = r.u(2)
            n = 0
            while r.u1():
                n += 1
                if n > 60:
                    return None
            if not r.u1():
                return None
            if self.time_bits:
                r.skip(self.time_bits)
                if not r.u1():
                    return None
            return kind == 0
        except ValueError:
            return None

    def quick(self, buf, pos: int, end: int) -> bool:
        if pos + 6 > end or buf[pos] or buf[pos + 1]:
            return False
        if self.kind == "h263":
            return buf[pos + 2] & 0xFC == 0x80
        return buf[pos + 2] == 1 and (buf[pos + 3] in (0xB0, 0xB3, 0xB5, 0xB6) or buf[pos + 3] <= 0x2F)

    def match(self, buf, pos: int, end: int, learn: bool = True) -> Hit | None:
        if not self.quick(buf, pos, end):
            return None
        if self.kind == "h263":
            key = self._h263_key(buf, pos, end)
            if key is None:
                return None
            nxt = self._H263.search(buf, pos + 3, end)
        else:
            vop = buf.find(b"\x00\x00\x01\xb6", pos, min(end, pos + 64 * KiB))
            if vop < 0:
                return None
            key = self._vop_ok(buf, vop, end)
            if key is None:
                return None
            nxt = self._MP4V.search(buf, vop + 4, end)
        q = nxt.start() if nxt is not None else end
        return Hit(q - pos, bool(key), open_end=True, at_end=nxt is None)

    def _h263_key(self, buf, pos: int, end: int) -> bool | None:
        if pos + 6 > end:
            return None
        bits = int.from_bytes(buf[pos:pos + 6], "big")      # PSC(22) TR(8) PTYPE...
        ptype = (bits >> 10) & 0xFF                         # the first 8 bits of PTYPE, after TR
        if not ptype & 0x80 or ptype & 0x40:
            return None
        fmt = ptype & 7
        if fmt == 0 or (self.formats and fmt not in self.formats):
            return None
        if fmt == 7:
            return True
        return not (bits >> 9) & 1

    def candidates(self) -> re.Pattern | None:
        return self._H263 if self.kind == "h263" else re.compile(rb"\x00\x00\x01[\xb0\xb3\xb6]")


class JpegVideo(VideoRebuild):
    kind = "jpeg"

    def __init__(self, ref: Track, dur: int, images: int = 1):
        super().__init__(ref, dur)
        self.images = images            # images per sample (2 for interlaced Motion-JPEG A)

    def quick(self, buf, pos: int, end: int) -> bool:
        return pos + 4 <= end and buf[pos] == 0xFF and buf[pos + 1] == 0xD8 and buf[pos + 2] == 0xFF

    def match(self, buf, pos: int, end: int, learn: bool = True) -> Hit | None:
        if not self.quick(buf, pos, end):
            return None
        p = pos
        for _ in range(self.images):
            q = jpeg_end(buf, p, end)
            if not q:                           # cut short where the data ends, else damaged
                return Hit(end - pos, cut=True) if end - p <= 2 * self.max_size + 64 * KiB else None
            p = q
        return Hit(p - pos)

    def candidates(self) -> re.Pattern | None:
        return re.compile(rb"\xff\xd8\xff")


class ProResVideo(VideoRebuild):
    kind = "prores"

    def quick(self, buf, pos: int, end: int) -> bool:
        return pos + 8 <= end and bytes(buf[pos + 4:pos + 8]) == b"icpf"

    def match(self, buf, pos: int, end: int, learn: bool = True) -> Hit | None:
        if not self.quick(buf, pos, end):
            return None
        n = prores_frame(buf, pos, end)
        if not n:
            whole = I.be32(buf, pos) if pos + 4 <= end else 0
            return Hit(end - pos, cut=True) if pos + whole > end and whole < 64 * MiB else None
        return Hit(n)

    def candidates(self):
        return re.compile(rb"icpf"), 4


class GpmfTrack(TrackRebuild):
    kind = "gpmd"
    strong = True

    def quick(self, buf, pos: int, end: int) -> bool:
        return pos + 8 <= end and bytes(buf[pos:pos + 4]) == b"DEVC"

    def match(self, buf, pos: int, end: int, learn: bool = True) -> Hit | None:
        n = gpmf_sample(buf, pos, end) if self.quick(buf, pos, end) else 0
        return Hit(n) if n else None

    def candidates(self) -> re.Pattern | None:
        return re.compile(rb"DEVC\x00")


class Ac3Track(TrackRebuild):
    strong = True

    def __init__(self, ref: Track, dur: int, kind: str):
        super().__init__(ref, dur)
        self.kind = kind

    def quick(self, buf, pos: int, end: int) -> bool:
        return pos + 7 <= end and buf[pos] == 0x0B and buf[pos + 1] == 0x77

    def match(self, buf, pos: int, end: int, learn: bool = True) -> Hit | None:
        f = ac3_frame(buf, pos, end)
        if f is None:
            return None
        n, blocks, _kind = f
        if self.kind == "eac3":                          # a sample is 6 blocks of the independent stream
            p = pos + n
            while blocks < 6:
                g = ac3_frame(buf, p, end)
                if g is None:
                    return None
                p += g[0]
                if g[2] != 1:
                    blocks += g[1]
            while True:                                  # dependent substreams belong to the same sample
                g = ac3_frame(buf, p, end)
                if g is None or g[2] != 1:
                    break
                p += g[0]
            n = p - pos
        return Hit(n)

    def candidates(self) -> re.Pattern | None:
        return re.compile(rb"\x0b\x77")


class FramedAudio(TrackRebuild):
    """Sound whose frames are found one after the other (no structure telling enough to resynchronise on):
    AAC (by parsing each raw frame), AMR, MP3."""

    def __init__(self, ref: Track, dur: int, kind: str, asc=None, frames_per_sample: int = 1):
        super().__init__(ref, dur)
        self.kind = kind
        self.asc = asc
        self.frames_per_sample = max(1, frames_per_sample)
        self.first_bits: set[int] | None = None      # AAC: the first 3 bits of the reference's frames
        self.strict = False             # AAC: zero padding and exactly the expected elements, as the reference

    def frame(self, buf, pos: int, end: int) -> int:
        if self.kind == "aac":
            if self.first_bits is not None and pos < end and buf[pos] >> 5 not in self.first_bits:
                return 0
            return aac.frame_length(buf, pos, end, self.asc, strict=self.strict) or 0
        if self.kind == "mp3":
            return mp3_frame(buf, pos, end)
        return amr_frame(buf, pos, end, AMR.get(self.ref.codec) == "wb")

    def sample(self, buf, pos: int, end: int) -> int:
        p = pos
        for _ in range(self.frames_per_sample):
            n = self.frame(buf, p, end)
            if not n:
                return 0 if p == pos else p - pos
            p += n
        return p - pos

    def quick(self, buf, pos: int, end: int) -> bool:
        if self.kind == "aac":
            if self.first_bits is not None and (pos >= end or buf[pos] >> 5 not in self.first_bits):
                return False
            return aac.is_frame(buf, pos, end, self.asc, strict=self.strict)
        return bool(self.frame(buf, pos, end))

    def stretch(self, walk: Walk, pos: int) -> int | None:
        buf, end, stop = walk.buf, walk.end, walk.stop
        p = pos
        got = 0
        if self.kind == "aac" and self.frames_per_sample == 1 and \
                (self.first_bits is None or pos < end and buf[pos] >> 5 in self.first_bits):
            # a run of frames in one go (each parsed once); it ends where the next video frame starts
            reach = min(end, pos + max(16 * KiB, 2 * self.max_chunk + 2 * self.max_size))
            for n in aac.split_frames(buf, pos, reach, self.asc, 4096, strict=self.strict or None):
                if p >= stop or got and walk.strong_at(p):
                    break
                self.add(p, n)
                p += n
                got += 1
            if got and p >= reach and reach < end and p < stop and not walk.strong_at(p):
                q = self.stretch(walk, p)              # a longer run than the reference's chunks
                return q if q is not None else p
            return p if got else None
        while p < stop:
            if got and walk.strong_at(p):
                break
            n = self.sample(buf, p, end)
            if not n:
                break
            self.add(p, n)
            p += n
            got += 1
        return p if got else None

    def tail(self, walk: Walk, lo: int, q: int, expected: float | None = None) -> int | None:
        buf = walk.buf
        window = max(4 * KiB, int(self.max_chunk * 1.5) + 2 * self.max_size)
        runs = {q: 0}                   # start -> samples from there to Q
        for x in range(q - 1, max(lo, q - window) - 1, -1):
            if self.first_bits is not None and buf[x] >> 5 not in self.first_bits:
                continue
            n = self.sample(buf, x, q)
            if n and x + n in runs:
                runs[x] = runs[x + n] + 1
        del runs[q]
        if not runs:
            return None
        # several starts can chain up to Q (a frame-like bit of the video in front of the real first frame):
        # take the run that keeps the sound in step with the pictures, else the longest
        if expected is None:
            best = min(runs)
        else:
            best = min(runs, key=lambda x: (abs(runs[x] - expected), -runs[x]))
        p = best
        while p < q:
            n = self.sample(buf, p, q)
            self.add(p, n)
            p += n
        return best


class PcmAudio(TrackRebuild):
    """Uncompressed sound: no structure at all, so its chunks are the stretches between the other tracks'
    samples; QuickTime keeps one sample per sound frame."""

    kind = "pcm"

    def __init__(self, ref: Track, dur: int, bpf: int, const_size: int, packet: int = 1):
        super().__init__(ref, dur)
        self.bpf = bpf
        self.const_size = const_size or bpf
        self.packet = max(1, packet)    # sound frames per packet of the encoder (chunks hold whole packets)

    def frames(self, nbytes: int) -> int:
        return nbytes // self.bpf

    def put(self, pos: int, nbytes: int) -> None:
        n = self.frames(nbytes)
        if n:
            self.add(pos, n * self.bpf, n)

    def stretch(self, walk: Walk, pos: int) -> int | None:
        end = walk.end
        for c in self.chunk_bytes[:8]:
            q = pos + c
            if q <= end and (q >= walk.stop or walk.strong_at(q)):
                self.put(pos, c)
                return q
        limit = pos + max(self.max_chunk * 2, 64 * KiB)
        q = walk.next_strong(pos + self.bpf, limit)
        if q is None:
            if walk.end > limit and walk.strong:
                return None                     # no picture comes after it: damage, not sound
            q = min(walk.end, limit)
        n = self.frames(q - pos)
        if not n:
            return None
        self.put(pos, n * self.bpf)
        return pos + n * self.bpf

    def tail(self, walk: Walk, lo: int, q: int, expected: float | None = None) -> int | None:
        sizes = [c for c in self.chunk_bytes[:8] if q - c >= lo]
        if not sizes:
            return None
        if expected is not None:                # whole packets of the sound encoder start before the frame
            expected = math.ceil(expected / self.packet - 1e-6) * self.packet
        c = sizes[0] if expected is None else min(sizes, key=lambda c: abs(c / self.bpf - expected))
        self.put(q - c, c)
        return q - c


class ConstTrack(TrackRebuild):
    """Samples of one size (timecode: 4 bytes; other tracks whose reference samples are all alike)."""

    def __init__(self, ref: Track, dur: int, size: int, per_chunk: int, kind: str = "const"):
        super().__init__(ref, dur)
        self.kind = kind
        self.const_size = size
        self.per_chunk = max(1, per_chunk)

    def stretch(self, walk: Walk, pos: int) -> int | None:
        n = self.const_size * self.per_chunk
        q = pos + n
        if q <= walk.end and (q >= walk.stop or walk.strong_at(q)):
            self.add(pos, n, self.per_chunk)
            return q
        return None

    def tail(self, walk: Walk, lo: int, q: int, expected: float | None = None) -> int | None:
        n = self.const_size * self.per_chunk
        if q - n >= lo:
            self.add(q - n, n, self.per_chunk)
            return q - n
        return None


# ---------------------------------------------------------------------- walking the media data
class Walk:
    """Cuts the media data [START, END) into the tracks' samples. TRANS {previous track slot (-1: the start):
    {next track slot: count}} is the reference's interleaving: the most likely next track is tried first.
    Walking stops at STOP (where analyze() stops looking) or where nothing matches any more."""

    def __init__(self, buf, start: int, end: int, tracks: list[TrackRebuild], trans: dict, ctl=None,
                 stop: int | None = None, exact_end: bool = False, other: int | None = None):
        self.buf = buf
        self.start = start
        self.end = end
        self.stop = end if stop is None else min(stop, end)
        self.tracks = tracks
        for i, t in enumerate(tracks):
            t.slot = i
        self.strong = [t for t in tracks if t.strong]
        self.weak = [t for t in tracks if not t.strong]
        self.trans = trans
        self.ctl = ctl
        self.gaps: list[tuple[int, int, list[int]]] = []    # (start, end, every track's sample count there)
        self.cut = False                # the data ends inside a frame
        self.exact_end = exact_end      # END is where the media data really ends (a sane mdat size)
        # tracks left out of the rebuild have chunks of up to OTHER bytes (-1: of any size): a stretch that
        # matches nothing and isn't longer is one of those, not damage
        self.other = other
        self.other_bytes = 0
        self.other_runs: list[tuple[int, int]] = []
        self.stopped_at = start
        self._hit: tuple[int, TrackRebuild | None, Hit | None] = (-1, None, None)
        self._orders: dict = {}

    def order(self, last: TrackRebuild | None, group: list[TrackRebuild]) -> list[TrackRebuild]:
        key = (-1 if last is None else last.slot, group is self.strong)
        o = self._orders.get(key)
        if o is None:
            counts = self.trans.get(key[0], {})
            o = self._orders[key] = sorted(group, key=lambda t: -counts.get(t.slot, 0))
        return o

    def _strong_here(self, pos: int, last) -> tuple[TrackRebuild | None, Hit | None]:
        if self._hit[0] == pos:
            return self._hit[1], self._hit[2]
        buf, end = self.buf, self.end
        for t in self.order(last, self.strong):
            if t.quick(buf, pos, end):
                h = t.match(buf, pos, end)
                if h is not None:
                    return t, h
        return None, None

    def strong_at(self, pos: int) -> bool:
        """Does a sample of a strong track start at POS? (The answer is kept for the walk's next step.)"""
        if self._hit[0] == pos:
            return self._hit[1] is not None
        t, h = self._strong_here(pos, None)
        self._hit = (pos, t, h)
        return t is not None

    def run(self) -> Walk:
        stop, ctl = self.stop, self.ctl
        pos = self.start
        last: TrackRebuild | None = None
        steps = 0
        span = max(1, stop - self.start)
        while pos < stop:
            steps += 1
            if ctl is not None and steps % 512 == 0:
                ctl.check()
                ctl.progress((pos - self.start) / span, "Finding the frames in the recording")
            t, h = self._strong_here(pos, last)
            if t is not None:
                if h.cut:
                    self.cut = True
                    break
                q = pos + h.size
                if h.open_end:
                    if h.at_end and not self.exact_end:
                        self.cut = True                # the last frame, with part of what came after it
                        break
                    s, w = self._split_open(t, pos, h)
                    h.size = s - pos
                    t.take(pos, h)
                    last = w or t
                else:
                    t.take(pos, h)
                    last = t
                pos = q
                continue
            q, w = None, None
            for w in self.order(last, self.weak):
                q = w.stretch(self, pos)
                if q is not None and q > pos:
                    break
                q = None
            if q is not None:
                pos, last = q, w
                continue
            nxt = self.resync(pos + 1)
            if nxt is None:
                break
            if self.other is not None and (self.other < 0 or nxt - pos <= self.other * 3 // 2 + 64):
                self.other_bytes += nxt - pos           # a chunk of a track the rebuild leaves out
                if len(self.other_runs) < 400:
                    self.other_runs.append((pos, nxt))
                last = None
                pos = nxt
                continue
            for x in self.tracks:
                x.after_gap()
            counts = [x.count for x in self.tracks]
            t_next, _h = self._strong_here(nxt, None)
            back = nxt
            for w in self.order(t_next, self.weak) if t_next is not None else ():
                if isinstance(w, FramedAudio):     # the sound frames between the damage and the resync point
                    got = w.tail(self, pos + 1, nxt)
                    if got is not None:
                        back = got
                        break
            self.gaps.append((pos, back, counts))
            last = None
            pos = nxt
        self.stopped_at = pos
        return self

    def _split_open(self, t: TrackRebuild, pos: int, h: Hit) -> tuple[int, TrackRebuild | None]:
        q = pos + h.size
        for w in self.order(t, self.weak):
            s = w.tail(self, pos + getattr(t, "min_size", 8), q, self._expected(t, w))
            if s is not None:
                return s, w
        return q, None

    @staticmethod
    def _expected(t: TrackRebuild, w: TrackRebuild) -> float | None:
        """How many of W's samples start before video track T's next frame (muxers interleave by time)."""
        if not t.ref.timescale or not w.ref.timescale:
            return None
        video = (t.media_duration() + t.lead + t.dur - t.media_start) / t.ref.timescale
        sound = (w.media_duration() + w.lead - w.media_start) / w.ref.timescale
        return float(max(0, math.ceil((video - sound) * w.ref.timescale / w.dur - 1e-6)))

    def _confirm(self, p: int) -> bool:
        if p >= self.stop or self.other is not None:
            return True                 # (with tracks left out of the rebuild, anything may follow)
        if self.strong_at(p):
            return True
        return any(w.kind == "pcm" or w.quick(self.buf, p, self.end) for w in self.weak)

    def resync(self, p0: int, limit: int | None = None) -> int | None:
        """The next position from P0 where a strong track's sample starts and is followed by something that
        fits (the end, or another sample)."""
        hi_all = self.stop if limit is None else min(limit, self.stop)
        best = None
        buf, end = self.buf, self.end
        for t in self.strong:
            cand = t.candidates()
            if cand is None:
                continue
            pat, back = cand if isinstance(cand, tuple) else (cand, 0)
            hi = hi_all if best is None else best
            x = p0 + back
            stop = min(end, hi + back + 8)
            while True:                     # (overlapping candidates: search again from the next byte)
                m = pat.search(buf, x, stop)
                if m is None:
                    break
                c = m.start() - back
                if c >= hi:
                    break
                x = m.start() + 1
                h = t.match(buf, c, end, learn=False)
                if h is None or h.cut:
                    continue
                if self._confirm(c + h.size):
                    # a frame's length field (00 00 0x yy) can pass for a NAL header a few bytes before it:
                    # when a frame also starts a little later, that is the real one
                    for k in range(1, 5):
                        h2 = t.match(buf, c + k, end, learn=False)
                        if h2 is not None and not h2.cut and self._confirm(c + k + h2.size):
                            c = c + k
                    best = c
                    break
        if best is None and not self.strong:
            best = self._weak_resync(p0, hi_all)
        return best

    def next_strong(self, p0: int, limit: int) -> int | None:
        return self.resync(p0, limit) if self.strong else None

    def _weak_resync(self, p0: int, hi: int) -> int | None:
        framed = [w for w in self.weak if isinstance(w, FramedAudio)]
        buf, end = self.buf, self.end
        for x in range(p0, min(hi, p0 + 256 * KiB)):
            for w in framed:
                p = x
                for _ in range(4):
                    n = w.sample(buf, p, end)
                    if not n:
                        break
                    p += n
                else:
                    return x
        return None

    def finish(self) -> None:
        """Give the damaged stretches a duration (from the data rate of the rest)."""
        if not self.gaps:
            return
        ref = next((t for t in self.tracks if t.video and t.count), None) or \
            next((t for t in self.tracks if t.count), None)
        if ref is None or not ref.ref.timescale:
            return
        seconds = ref.media_duration() / ref.ref.timescale
        damaged = sum(b - a for a, b, _c in self.gaps)
        covered = max(1, self.stopped_at - self.start - damaged)
        if seconds <= 0:
            return
        rate = covered / seconds
        for a, b, counts in self.gaps:
            secs = (b - a) / rate
            for t, n in zip(self.tracks, counts):
                if not t.ref.timescale:
                    continue
                frames = round(secs * t.ref.timescale / t.dur)
                if frames <= 0:
                    continue
                if n:
                    t.extra[n - 1] = t.extra.get(n - 1, 0) + frames * t.dur
                else:
                    t.lead += frames * t.dur


# ---------------------------------------------------------------------- learning from a reference
@dataclass
class RefSamples:
    """A reference track's samples: from its sample tables, or from the movie fragments."""
    offsets: list[int]
    sizes: list[int]
    durations: list[int]
    cts: list[int] | None
    chunks: list[tuple[int, int, int]]        # (offset, first sample, count)


def ref_samples(buf, movie: Movie, frags: dict[int, I.FragTrack]) -> list[RefSamples]:
    out = []
    for t in movie.tracks:
        f = frags.get(t.id)
        if t.sizes and t.chunk_offsets:
            cts = []
            for c, o in t.ctts:
                cts.extend([o] * c)
            chunks = list(t.chunks())
            n = sum(c[2] for c in chunks)          # (a cut-off table may have sizes for samples past its chunks)
            out.append(RefSamples(t.sample_offsets()[:n], list(t.sizes[:n]), t.durations()[:n],
                                  cts[:n] or None, chunks))
        elif f is not None and f.sizes:
            out.append(RefSamples(f.offsets, f.sizes, f.durations, f.cts if any(f.cts) else None, f.runs))
        else:                                   # a cut-off table: what it says about sizes and timing
            out.append(RefSamples([], list(t.sizes), t.durations() if t.stts else [], None, []))
    return out


def _typical(durations: list[int]) -> int:
    """The duration to give every sample: the common one, or the mean when they vary (phones)."""
    d = durations[:-1] if len(durations) > 2 else durations
    if not d:
        return 0
    m = _mode(d)
    if sum(1 for x in d if x == m) >= 0.9 * len(d):
        return m
    return max(1, round(sum(d) / len(d)))


def esds_info(payload: bytes) -> tuple[int, bytes]:
    """(objectTypeIndication, DecoderSpecificInfo) of an esds payload (version/flags first); (0, b"")."""
    p = 4
    oti, dsi = 0, b""

    def desc(pos: int) -> tuple[int, int, int]:
        tag = payload[pos]
        pos += 1
        n = 0
        for _ in range(4):
            b = payload[pos]
            pos += 1
            n = (n << 7) | (b & 0x7F)
            if not b & 0x80:
                break
        return tag, pos, n
    try:
        tag, p, n = desc(p)
        if tag == 3:
            flags = payload[p + 2]
            p += 3
            if flags & 0x80:
                p += 2
            if flags & 0x40:
                p += 1 + payload[p]
            if flags & 0x20:
                p += 2
            tag, p, n = desc(p)
        if tag == 4:
            oti = payload[p]
            end4 = p + n
            p += 13
            if p < end4:
                tag, p, n = desc(p)
                if tag == 5:
                    dsi = bytes(payload[p:p + n])
    except IndexError:
        pass
    return oti, dsi


def vol_time_bits(dsi: bytes) -> int:
    """The bits of vop_time_increment from an MPEG-4 Part 2 VOL header, 0 if not found."""
    i = dsi.find(b"\x00\x00\x01\x20")
    if i < 0:
        j = re.search(rb"\x00\x00\x01[\x20-\x2f]", dsi)
        if j is None:
            return 0
        i = j.start()
    try:
        r = BitReader(dsi[i + 4:])
        r.skip(9)
        if r.u1():
            r.skip(7)
        if r.u(4) == 15:
            r.skip(16)
        if r.u1():
            r.skip(3)
            if r.u1():
                r.skip(79)
        r.skip(2)
        if not r.u1():
            return 0
        res = r.u(16)
        return max(1, (res - 1).bit_length()) if res else 0
    except BitsError:
        return 0


@dataclass
class Recipe:
    """What a reference video (or the stream itself) says about a recording: how to make its tracks, how they
    interleave, and the boxes to copy into the new movie."""
    makers: list                              # functions that make a fresh TrackRebuild per track
    slots: list[int]                          # the reference track index of every maker
    trans: dict
    movie: Movie
    traks: list[bytes]                        # the reference's trak boxes, by reference track index
    ftyp: bytes = b""
    skipped: list[str] = field(default_factory=list)
    source: str = "reference"
    elst: list = field(default_factory=list)  # per reference track: its edit list
    ctts_shift: list = field(default_factory=list)   # per reference track: the composition shift its edits undo
    udta: bytes = b""
    iods: bytes = b""
    init_moov: bytes = b""                    # the reference's whole moov (the init segment of fragments)
    video_lost: str = ""                      # why a video track of the reference can't be followed
    other: int | None = None                  # the largest chunk of the tracks left out (-1: unknown)

    def make(self) -> list[TrackRebuild]:
        out = []
        for slot, mk in zip(self.slots, self.makers):
            t = mk()
            t.ref_slot = slot
            edits = [mt for _d, mt, _r in (self.elst[slot] if slot < len(self.elst) else []) if mt >= 0]
            t.media_start = edits[0] if edits and not t.video else 0     # e.g. the AAC encoder delay
            out.append(t)
        return out


def _sample_nals(buf, off: int, size: int, ls: int, hevc_: bool) -> list[tuple[int, int, int]]:
    """(type, first header byte, layer) of the NAL units of a sample."""
    out = []
    for a, b in h264.iter_nals(buf, off, off + size, ls):
        b0 = buf[a]
        if hevc_:
            out.append(((b0 >> 1) & 63, b0, ((b0 & 1) << 5) | (buf[a + 1] >> 3) if a + 1 < b else 0))
        else:
            out.append((b0 & 31, b0, 0))
    return out


def _test_ids(n: int) -> list[int]:
    """Which samples of N the self-test reads: the first ones and some spread over the rest."""
    first = list(range(min(n, 40)))
    if n > 40:
        first += list(range(40, n, max(1, (n - 40) // 40)))[:40]
    return first


def learn(buf, movie: Movie, boxes: list[Box], frags: dict | None = None, check: bool = True) -> Recipe:
    """The recipe for rebuilding recordings like the movie MOVIE of BUF (a reference video). With CHECK, each
    track's way of finding samples is tried on the reference's own samples: a track that doesn't come out
    right is left out (said in Recipe.skipped)."""
    frags = frags or {}
    video_lost = ""
    other = None
    samples = ref_samples(buf, movie, frags)
    makers, slots, skipped = [], [], []
    elst, shifts = [], []
    traks = [b""] * len(movie.tracks)
    moov = next((b for b in boxes if b.type == b"moov"), None)
    if moov is not None:
        i = 0
        for b in I.children(buf, moov):
            if b.type == b"trak":
                t = I._parse_trak(buf, b)
                if t is not None and i < len(traks):
                    traks[i] = bytes(buf[b.start:b.end])
                    i += 1
    for i, (t, rs) in enumerate(zip(movie.tracks, samples)):
        entries = I.parse_elst(t.edts) if t.edts else []
        elst.append(entries)
        shifts.append(rs.cts[0] if rs.cts and rs.cts[0] > 0 else 0)
        mk, why = _maker(buf, t, rs, check)
        if mk is None:
            if why:
                skipped.append(why)
            if rs.sizes:
                biggest = max((sum(rs.sizes[f:f + n]) for _o, f, n in rs.chunks[:5000]), default=0)
                other = max(other or 0, biggest)
            if t.handler == "vide":
                video_lost = why or "its video can't be rebuilt"
            continue
        makers.append(mk)
        slots.append(i)
    # the interleaving: which track's chunk follows which
    order = sorted((off, i) for i, rs in enumerate(samples) if i in slots for off, _f, _n in rs.chunks)
    slot_of = {s: k for k, s in enumerate(slots)}
    trans: dict[int, dict[int, int]] = {}
    prev = -1
    for _off, i in order[:20000]:
        k = slot_of[i]
        trans.setdefault(prev, {})
        trans[prev][k] = trans[prev].get(k, 0) + 1
        prev = k
    ftyp = next((bytes(buf[b.start:b.end]) for b in boxes if b.type == b"ftyp" and not b.truncated), b"")
    udta = movie.udta
    iods = next((o for o in movie.other if o[4:8] == b"iods"), b"")
    r = Recipe(makers, slots, trans, movie, traks, ftyp, skipped, "reference", elst, shifts, udta, iods)
    r.video_lost = video_lost
    r.other = other
    return r


def _chunk_stats(t: TrackRebuild, rs: RefSamples) -> None:
    """The reference's sample and chunk sizes, which some tracks go by."""
    if rs.sizes:
        t.max_size = max(rs.sizes)
    sizes = []
    for _off, first, n in rs.chunks[:5000]:
        sizes.append(sum(rs.sizes[first:first + n]))
    if sizes:
        counts: dict[int, int] = {}
        for s in sizes:
            counts[s] = counts.get(s, 0) + 1
        t.chunk_bytes = sorted(counts, key=lambda s: (-counts[s], -s))
        t.max_chunk = max(sizes)


def _default_duration(t: Track) -> int:
    """A sample's duration when the table that says it is lost (a cut-off index): what the codec's frames last,
    or for video what the stream's timing information says."""
    if t.handler == "soun":
        esds = t.config(b"esds")
        oti = esds_info(esds)[0] if esds else 0
        if t.codec in (".mp3", "mp3 ") or oti in (0x69, 0x6B):
            return 1152
        return {"mp4a": 1024, "ac-3": 1536, "ec-3": 1536, "samr": 160, "sawb": 320}.get(t.codec,
                                                                                        1 if t.codec in PCM_WIDTH else 0)
    if t.handler == "vide":
        fps = None
        if t.codec in AVC:
            cfg = h264.parse_avcc(t.config(b"avcC") or b"")
            fps = next((s.fps for s in cfg.params().sps.values() if s.fps), None) if cfg else None
        elif t.codec in HEVC:
            cfg = hevc.parse_hvcc(t.config(b"hvcC") or b"")
            fps = cfg.params().fps() if cfg else None
        if fps:
            return max(1, round(t.timescale * fps[1] / fps[0]))
    return 0


def _maker(buf, t: Track, rs: RefSamples, check: bool):
    """A function making the TrackRebuild for reference track T, or (None, why it can't be rebuilt)."""
    codec = t.codec
    name = f"the {HANDLERS.get(t.handler, t.handler or 'unknown')} track ({codec.strip() or '?'})"
    if not t.stsd or not t.timescale:
        return None, f"{name[0].upper()}{name[1:]} has no codec configuration"
    dur = _typical(rs.durations) or _default_duration(t)
    if not dur:
        return None, f"{name[0].upper()}{name[1:]} can't be rebuilt: its timing is unknown"
    ids = _test_ids(len(rs.offsets))
    end = len(buf)

    def tested(make, kind_ok=None) -> tuple:
        if not check or not rs.offsets:
            return make, ""
        probe = make()
        _chunk_stats(probe, rs)
        good = 0
        for k in ids:
            off, size = rs.offsets[k], rs.sizes[k]
            if kind_ok is not None:
                good += kind_ok(probe, off, size)
                continue
            h = probe.match(buf, off, end)
            good += h is not None and h.size == size
        if good >= 0.8 * len(ids):
            return make, ""
        return None, (f"{name[0].upper()}{name[1:]} can't be rebuilt: its frames don't come out right "
                      f"({good} of {len(ids)} in the reference)")

    def with_stats(cls_make):
        def make():
            obj = cls_make()
            _chunk_stats(obj, rs)
            return obj
        return make

    if t.handler == "vide" and (codec in AVC or codec in HEVC):
        is_hevc = codec in HEVC
        raw = t.config(b"hvcC" if is_hevc else b"avcC")
        cfg = (hevc.parse_hvcc(raw) if is_hevc else h264.parse_avcc(raw)) if raw else None
        if cfg is None:
            return None, f"{name[0].upper()}{name[1:]} has no usable codec configuration"
        types: set[int] = set()
        first: set[int] = set()
        layers: set[int] = {0}
        for k in ids[:60]:
            nals = _sample_nals(buf, rs.offsets[k], rs.sizes[k], cfg.length_size, is_hevc)
            if nals:
                first.add(nals[0][1])
            for typ, _b0, layer in nals:
                types.add(typ)
                layers.add(layer)
        max_nal = min(64 * MiB, max(MiB, 4 * max(rs.sizes))) if rs.sizes else 16 * MiB
        delay = None
        if rs.cts:
            delay = rs.cts[0] // dur if dur and rs.cts[0] > 0 else 0
        if is_hevc:
            allowed = frozenset(types | hevc.VCL_TYPES | {hevc.VPS_NAL, hevc.SPS_NAL, hevc.PPS_NAL})

            def make():
                ps = hevc.ParamSets()
                for typ in (hevc.VPS_NAL, hevc.SPS_NAL, hevc.PPS_NAL):
                    for n in cfg.nals(typ):
                        ps.add(n)
                rd = hevc.HevcReader(ps, cfg.length_size, max_nal, allowed, frozenset(layers))
                return NalVideo(t, dur, rd, "hevc", first or None, delay)
        else:
            allowed = frozenset(types | {h264.SLICE, h264.IDR, h264.SPS_NAL, h264.PPS_NAL})

            def make():
                rd = h264.AvcReader(cfg.params(), cfg.length_size, max_nal, allowed)
                return NalVideo(t, dur, rd, "avc", first or None, delay)
        return tested(with_stats(make))
    if t.handler == "vide" and codec in PRORES:
        return tested(with_stats(lambda: ProResVideo(t, dur)))
    if t.handler == "vide" and codec in JPEG:
        images = 0
        p = rs.offsets[0] if rs.offsets else 0
        stop = p + rs.sizes[0] if rs.offsets else 0
        while p < stop and images < 4:
            q = jpeg_end(buf, p, stop)
            if not q:
                break
            images += 1
            p = q
        return tested(with_stats(lambda: JpegVideo(t, dur, max(1, images))))
    if t.handler == "vide" and (codec in MP4V or codec in H263):
        if codec in H263:
            formats = set()
            for k in ids[:20]:
                off = rs.offsets[k]
                if off + 6 <= end:
                    formats.add((int.from_bytes(buf[off:off + 6], "big") >> 10) & 7)
            make = with_stats(lambda: StartCodeVideo(t, dur, "h263", formats=formats))
        else:
            esds = t.config(b"esds") or b""
            bits = vol_time_bits(esds_info(esds)[1] if esds else b"") or (vol_time_bits(
                bytes(buf[rs.offsets[0]:rs.offsets[0] + min(rs.sizes[0], 256)])) if rs.offsets else 0)
            make = with_stats(lambda: StartCodeVideo(t, dur, "mp4v", time_bits=bits))

        def ok(probe, off, size):
            # the frame's start is found; its end may be followed by other tracks' samples in the reference
            h = probe.match(buf, off, end)
            return h is not None and h.size >= size
        return tested(make, ok)
    if t.handler == "soun":
        esds = t.config(b"esds")
        oti = esds_info(esds)[0] if esds else 0
        if codec == "mp4a" and oti in (0x69, 0x6B) or codec in (".mp3", "mp3 ", "ms\x00U"):
            make = with_stats(lambda: FramedAudio(t, dur, "mp3"))
            return tested(make, lambda p, off, size: p.sample(buf, off, end) == size)
        if codec == "mp4a":
            if aac is None:
                return None, "The sound (AAC) can't be rebuilt by this version"
            asc = aac.parse_esds(esds) if esds else None
            if asc is None:
                return None, f"{name[0].upper()}{name[1:]} has no usable codec configuration"
            bits = {buf[o] >> 5 for o, s in zip(rs.offsets[:200], rs.sizes[:200]) if s and o < end}
            strict = bool(rs.offsets) and all(aac.frame_length(buf, o, end, asc, strict=True) == s
                                              for o, s in zip(rs.offsets[1:60], rs.sizes[1:60]))

            def make_aac():
                a = FramedAudio(t, dur, "aac", asc)
                a.first_bits = bits or None
                a.strict = strict
                _chunk_stats(a, rs)
                return a
            return tested(make_aac, lambda p, off, size: p.sample(buf, off, end) == size)
        if codec in AMR:
            damr = t.config(b"damr")
            fps = damr[8] if damr and len(damr) > 8 and damr[8] else 1
            make = with_stats(lambda: FramedAudio(t, dur, "amr", frames_per_sample=fps))
            return tested(make, lambda p, off, size: p.sample(buf, off, end) == size)
        if codec in ("ac-3", "ec-3"):
            return tested(with_stats(lambda: Ac3Track(t, dur, "ac3" if codec == "ac-3" else "eac3")))
        if codec in PCM_WIDTH:
            bpf = pcm_bytes_per_frame(t)
            const = (rs.sizes[0] if min(rs.sizes) == max(rs.sizes) else 0) if rs.sizes else bpf
            if const > 1 and const != bpf:
                bpf = const                     # stsz says the bytes per frame (ipcm's pcmC may not)
            if not bpf or not const:
                return None, f"{name[0].upper()}{name[1:]} can't be rebuilt: its frame size is unknown"

            packet = 0
            for _off, _first, n in rs.chunks[:-1][:5000]:
                packet = math.gcd(packet, n)

            def make_pcm():
                p = PcmAudio(t, dur, bpf, const, packet)
                _chunk_stats(p, rs)
                counts: dict[int, int] = {}
                for _off, _first, n in rs.chunks[:5000]:
                    counts[n * bpf] = counts.get(n * bpf, 0) + 1
                p.chunk_bytes = sorted(counts, key=lambda c: (-counts[c], -c))
                p.max_chunk = max(counts) if counts else 0
                return p
            return make_pcm, ""
        return None, f"The sound track ({codec.strip()}) can't be rebuilt: RecoverAll doesn't know its frames"
    if codec == "gpmd":
        return tested(with_stats(lambda: GpmfTrack(t, dur)))
    if rs.sizes and min(rs.sizes) == max(rs.sizes) and t.handler not in ("vide", "soun"):
        per = _mode(n for _o, _f, n in rs.chunks) or 1
        kind = "tmcd" if codec == "tmcd" else "const"

        def make_const():
            c = ConstTrack(t, dur, rs.sizes[0], per, kind)
            c.spans = len(rs.sizes) == 1
            return c
        return make_const, ""
    return None, f"{name[0].upper()}{name[1:]} can't be rebuilt: RecoverAll doesn't know its samples"


# ---------------------------------------------------------------------- writing the new movie box
DEFAULT_FTYP = box("ftyp", b"isom", struct.pack(">I", 512), b"isomiso2avc1mp41")
_PRIVATE_UDTA = {b"\xa9xyz", b"loci", b"\xa9day", b"date"}       # where and when the reference was recorded
_MATRIX = struct.pack(">9i", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000)


def _udta(raw: bytes) -> bytes:
    """A movie's udta box without the reference recording's place and date."""
    if not raw:
        return b""
    top = next(I.iter_boxes(raw), None)
    if top is None:
        return b""
    kids = [c for c in I.iter_boxes(raw, top.payload, top.end, strict=False)]
    keep = [raw[c.start:c.end] for c in kids if c.type not in _PRIVATE_UDTA]
    return box("udta", *keep) if keep else b""


def _edits(recipe: Recipe, t: TrackRebuild, movie_ts: int) -> tuple[bytes, int]:
    """The new track's edit list (b"" for none) and its duration in the movie timescale."""
    media_ts = t.ref.timescale or 1
    total = t.media_duration()
    shift = t.shift

    def to_movie(x: int) -> int:
        return (x * movie_ts + media_ts // 2) // media_ts
    ref_entries = recipe.elst[t.ref_slot] if t.ref_slot < len(recipe.elst) else []
    empty = 0
    main = None
    for d, mt, rate in ref_entries:
        if mt == -1 and main is None:
            empty += d
            continue
        if mt != -1:
            main = [mt, rate]
            break
    ref_shift = recipe.ctts_shift[t.ref_slot] if t.ref_slot < len(recipe.ctts_shift) else 0
    if main is None and shift:
        main = [shift, 1.0]
    elif main is not None and t.video and main[0] == ref_shift:
        main[0] = shift                     # the reference's edit undid its B-frame delay: undo ours
    empty += to_movie(t.lead)
    if main is None and not empty:
        return b"", to_movie(total)
    entries = []
    if empty:
        entries.append((empty, -1, 1.0))
    if main is None:
        entries.append((to_movie(total), 0, 1.0))
    else:
        mt, rate = main
        entries.append((max(0, to_movie(total + shift - mt)), mt, rate))
    return I.edts_box(entries), sum(d for d, _m, _r in entries)


def _stbl(t: TrackRebuild, delta: int) -> bytes:
    ct = t.ctts_runs()
    parts = [t.ref.stsd, I.stts_box(t.stts_runs())]
    if ct:
        parts.append(I.ctts_box(ct))
    sync = t.sync_samples()
    if sync is not None:
        parts.append(I.stss_box(sync))
    parts.append(I.stsz_box(None, t.count, t.const_size) if t.const_size else I.stsz_box(t.sizes))
    parts.append(I.stsc_box(t.chunk_counts))
    parts.append(I.stco_box([o + delta for o in t.chunk_offsets]))
    return box("stbl", *parts)


def _trak(recipe: Recipe, t: TrackRebuild, delta: int, movie_ts: int, ids: set[int]) -> tuple[bytes, int]:
    raw = recipe.traks[t.ref_slot]
    stbl = _stbl(t, delta)                  # first: it works out the composition shift the edits need
    edts, tk_dur = _edits(recipe, t, movie_ts)
    md_dur = t.media_duration()
    top = next(I.iter_boxes(raw))

    def edit(path, b):
        if path == (b"trak", b"tkhd"):
            return I.with_duration(raw[b.start:b.end], tk_dur, True) + edts
        if path == (b"trak", b"edts"):
            return b""
        if path == (b"trak", b"mdia", b"mdhd"):
            return I.with_duration(raw[b.start:b.end], md_dur, True)
        if path == (b"trak", b"mdia", b"minf", b"stbl"):
            return stbl
        if path == (b"trak", b"tref"):
            refs = [I.be32(raw, p) for c in I.iter_boxes(raw, b.payload, b.end, strict=False)
                    for p in range(c.payload, c.end - 3, 4)]
            return None if all(r in ids for r in refs) else b""
        return None
    return I.rewrite(raw, top, edit), tk_dur


def build_moov(recipe: Recipe, tracks: list[TrackRebuild], delta: int) -> bytes:
    """The movie box for the rebuilt TRACKS (chunk offsets moved by DELTA)."""
    movie_ts = recipe.movie.timescale or 1000
    ids = {I.track_id_of(recipe.traks[t.ref_slot]) for t in tracks}
    out: dict[int, bytes] = {}
    mv_dur = 0
    spanning = [t for t in tracks if getattr(t, "spans", False) and t.count == 1]
    for t in tracks:
        if t in spanning:
            continue
        raw, d = _trak(recipe, t, delta, movie_ts, ids)
        out[t.ref_slot] = raw
        mv_dur = max(mv_dur, d)
    for t in spanning:                      # a timecode track's one sample lasts as long as the movie
        t.dur = max(1, mv_dur * (t.ref.timescale or 1) // movie_ts)
        out[t.ref_slot], _d = _trak(recipe, t, delta, movie_ts, ids)
    mvhd = I.with_duration(recipe.movie.mvhd, mv_dur, True)
    return box("moov", mvhd, recipe.iods, *(out[k] for k in sorted(out)), _udta(recipe.udta))


def _assemble(buf, lay: Layout, recipe: Recipe, tracks: list[TrackRebuild]) -> list:
    """The pieces of the rebuilt file: file type, the media data as it is, the new movie box."""
    tracks = [t for t in tracks if t.count]
    start = lay.data_start
    stop = max(t.data_end for t in tracks)
    head = (lay.ftyp or recipe.ftyp or DEFAULT_FTYP) + lay.keep
    n = 8 + stop - start
    hdr = struct.pack(">I4s", n, b"mdat") if n <= 0xFFFFFFFF else struct.pack(">I4sQ", 1, b"mdat", n + 8)
    delta = len(head) + len(hdr) - start
    return [head + hdr, (start, stop), build_moov(recipe, tracks, delta)]


# ---------------------------------------------------------------------- a movie for a stream without reference
def _sample_entry(codec: str, config: bytes, width: int, height: int) -> bytes:
    """A visual sample entry (avc1, hvc1, ...) with its configuration box."""
    name = b"\x00" * 32
    return box(codec, bytes(6), struct.pack(">H", 1), bytes(16),
               struct.pack(">HHIIIH", width, height, 0x480000, 0x480000, 0, 1), name,
               struct.pack(">Hh", 0x18, -1), config)


def synthetic_movie(codec: str, config: bytes, width: int, height: int, timescale: int) -> tuple[Movie, bytes]:
    """A one-track movie (and its trak box, tables empty) for a video stream: what the rebuild copies when
    there is no reference."""
    entry = _sample_entry(codec, config, width, height)
    stsd = full_box("stsd", 0, 0, struct.pack(">I", 1), entry)
    tkhd = full_box("tkhd", 0, 3, struct.pack(">IIIII", 0, 0, 1, 0, 0), bytes(8), struct.pack(">hhhh", 0, 0, 0, 0),
                    _MATRIX, struct.pack(">II", width << 16, height << 16))
    mdhd = full_box("mdhd", 0, 0, struct.pack(">IIIIHH", 0, 0, timescale, 0, 0x55C4, 0))
    hdlr = full_box("hdlr", 0, 0, struct.pack(">I4s", 0, b"vide"), bytes(12), b"VideoHandler\x00")
    vmhd = full_box("vmhd", 0, 1, bytes(8))
    dinf = box("dinf", full_box("dref", 0, 0, struct.pack(">I", 1), full_box("url ", 0, 1)))
    trak = box("trak", tkhd, box("mdia", mdhd, hdlr, box("minf", vmhd, dinf, box("stbl", stsd))))
    mvhd = full_box("mvhd", 0, 0, struct.pack(">IIIIIH", 0, 0, 1000, 0, 0x10000, 0x100), bytes(10), _MATRIX,
                    bytes(24), struct.pack(">I", 2))
    t = Track(id=1, handler="vide", timescale=timescale, codec=codec, stsd=stsd, entry=entry[8:], width=width,
              height=height, tkhd=tkhd, mdhd=mdhd, hdlr=hdlr)
    return Movie(timescale=1000, mvhd=mvhd, tracks=[t]), trak


def _timing(fps: tuple[int, int] | None) -> tuple[int, int, bool]:
    """(timescale, frame duration, guessed) for a frame rate NUM/DEN (30 fps when unknown)."""
    from math import gcd
    guessed = fps is None or not fps[0] or not fps[1] or not 1 <= fps[0] / fps[1] <= 480
    num, den = (30, 1) if guessed else fps
    g = gcd(num, den)
    num, den = num // g, den // g
    if (90000 * den) % num == 0:
        return 90000, 90000 * den // num, guessed
    return num, den, guessed


_AAC_RATES = (96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000)
# sampling rates whose band tables are the same, so that their frames read alike: the frame count per second
# of video tells them apart
_RATE_GROUPS = ((48000, 44100), (32000,), (24000, 22050), (16000, 12000, 11025), (96000, 88200), (64000,), (8000,))


def _asc_bytes(rate: int, channels: int) -> bytes:
    """An AudioSpecificConfig for AAC LC."""
    return ((2 << 11) | (_AAC_RATES.index(rate) << 7) | (channels << 3)).to_bytes(2, "big")


def guess_aac(buf, runs: list[tuple[int, int]]) -> tuple[tuple[int, ...], int, bool] | None:
    """The AAC LC layout ((rates alike, channels, strict)) under which the stretches RUNS (the data between a
    stream's pictures) split exactly into frames, or None when none does for most of them. Strict parsing
    (exactly the channel elements of the layout, zero padding) tells mono from stereo; encoders that pad
    otherwise are tried leniently after."""
    if aac is None or len(runs) < 3:
        return None
    sample = runs[:40]
    for strict in (True, None):
        best = (0, None, 0)
        for group in _RATE_GROUPS:
            for channels in (2, 1):
                asc = aac.parse_asc(_asc_bytes(group[0], channels))
                exact = 0
                for i, (a, b) in enumerate(sample):
                    exact += sum(aac.split_frames(buf, a, b, asc, strict=strict)) == b - a
                    if i == 5 and exact == 0:
                        break
                if exact > best[0]:
                    best = (exact, group, channels)
        exact, group, channels = best
        if group is not None and exact >= max(3, 0.6 * len(sample)):
            return group, channels, bool(strict)
    return None


def synthetic_sound(rate: int, channels: int, track_id: int) -> tuple[Track, bytes]:
    """An AAC LC sound track (and its trak box, tables empty)."""
    def desc(tag: int, body: bytes) -> bytes:
        return bytes([tag, len(body)]) + body
    dcd = desc(4, bytes([0x40, 0x15]) + bytes(3) + struct.pack(">II", 0, 0) + desc(5, _asc_bytes(rate, channels)))
    esds = full_box("esds", 0, 0, desc(3, struct.pack(">HB", track_id, 0) + dcd + desc(6, b"\x02")))
    entry = box("mp4a", bytes(6), struct.pack(">H", 1), bytes(8),
                struct.pack(">HHHHI", channels, 16, 0, 0, (rate if rate < 65536 else 0) << 16), esds)
    stsd = full_box("stsd", 0, 0, struct.pack(">I", 1), entry)
    tkhd = full_box("tkhd", 0, 3, struct.pack(">IIIII", 0, 0, track_id, 0, 0), bytes(8),
                    struct.pack(">hhhh", 0, 1, 0x100, 0), _MATRIX, bytes(8))
    mdhd = full_box("mdhd", 0, 0, struct.pack(">IIIIHH", 0, 0, rate, 0, 0x55C4, 0))
    hdlr = full_box("hdlr", 0, 0, struct.pack(">I4s", 0, b"soun"), bytes(12), b"SoundHandler\x00")
    smhd = full_box("smhd", 0, 0, bytes(4))
    dinf = box("dinf", full_box("dref", 0, 0, struct.pack(">I", 1), full_box("url ", 0, 1)))
    trak = box("trak", tkhd, box("mdia", mdhd, hdlr, box("minf", smhd, dinf, box("stbl", stsd))))
    t = Track(id=track_id, handler="soun", timescale=rate, codec="mp4a", stsd=stsd, entry=entry[8:],
              channels=channels, sample_rate=rate, sample_bits=16, tkhd=tkhd, mdhd=mdhd, hdlr=hdlr)
    return t, trak


def with_guessed_sound(buf, recipe: Recipe, walk: Walk, lay: Layout, ctl):
    """A stream recipe with an AAC track added when the data between the pictures is AAC: (recipe, the walk
    with it, a description of the sound), or None."""
    found = guess_aac(buf, walk.other_runs)
    if found is None:
        return None
    group, channels, strict = found

    def attempt(rate: int):
        t, trak = synthetic_sound(rate, channels, 2)
        asc = aac.parse_asc(_asc_bytes(rate, channels))

        def make_sound(t=t, asc=asc):
            a = FramedAudio(t, 1024, "aac", asc)
            a.max_chunk = max((b - a_ for a_, b in walk.other_runs), default=0)
            a.strict = strict
            return a
        mvhd = recipe.movie.mvhd[:-4] + struct.pack(">I", 3)
        movie = Movie(timescale=recipe.movie.timescale, mvhd=mvhd, tracks=[recipe.movie.tracks[0], t])
        r = Recipe([recipe.makers[0], make_sound], [0, 1], {}, movie, [recipe.traks[0], trak], recipe.ftyp, [],
                   "stream", [[], []], [0, 0], other=-1)
        w = Walk(buf, lay.data_start, lay.data_end, r.make(), r.trans, ctl, walk.stop, lay.exact, -1).run()
        return r, w
    r, w = attempt(group[0])
    video, sound = w.tracks
    if not sound.count or not video.count:
        return None
    if len(group) > 1 and video.ref.timescale:
        seconds = video.media_duration() / video.ref.timescale
        rate = sound.count * 1024 / seconds if seconds else group[0]
        best = min(group, key=lambda g: abs(g - rate))
        if best != group[0]:
            r, w = attempt(best)
    rate = r.movie.tracks[1].timescale
    return r, w, f"AAC, {rate / 1000:g} kHz, {'stereo' if channels == 2 else 'mono'}"


def stream_recipe(buf, start: int, end: int) -> tuple[Recipe | None, str]:
    """A recipe from the stream itself, when it carries its parameter sets (SPS/PPS, and VPS for H.265): a
    video-only movie. (None, "") when it doesn't."""
    for ls in (4, 2, 1):
        ps = h264.find_params(buf, start, end, ls)
        if ps:
            sps = [s.raw for s in ps.sps.values()]
            pps = [p.raw for p in ps.pps.values()]
            first = next(iter(ps.sps.values()))
            config = box("avcC", h264.build_avcc(sps, pps, ls))
            ts, dur, guessed = _timing(first.fps)
            movie, trak = synthetic_movie("avc1", config, first.width, first.height, ts)

            def make(ps=ps, ls=ls, movie=movie, dur=dur):
                rd = h264.AvcReader(ps.copy(), ls, 16 * MiB)
                return NalVideo(movie.tracks[0], dur, rd, "avc")
            r = Recipe([make], [0], {}, movie, [trak], b"", [], "stream", [[]], [0], other=-1)
            return r, ("guessed" if guessed else "")
        hp = hevc.find_params(buf, start, end, ls)
        if hp and hp.vps:
            vps = [v.raw for v in hp.vps.values()]
            sps = [s.raw for s in hp.sps.values()]
            pps = [p.raw for p in hp.pps.values()]
            first = next(iter(hp.sps.values()))
            config = box("hvcC", hevc.build_hvcc(vps, sps, pps, ls))
            ts, dur, guessed = _timing(hp.fps())
            movie, trak = synthetic_movie("hev1", config, first.width, first.height, ts)

            def make_h(hp=hp, ls=ls, movie=movie, dur=dur):
                ps = hevc.ParamSets()
                ps.vps, ps.sps, ps.pps = dict(hp.vps), dict(hp.sps), dict(hp.pps)
                return NalVideo(movie.tracks[0], dur, hevc.HevcReader(ps, ls, 16 * MiB), "hevc")
            r = Recipe([make_h], [0], {}, movie, [trak], b"", [], "stream", [[]], [0], other=-1)
            return r, ("guessed" if guessed else "")
    return None, ""


# ---------------------------------------------------------------------- where the media data is
@dataclass
class Layout:
    data_start: int
    data_end: int
    ftyp: bytes = b""
    keep: bytes = b""                         # complete boxes before the media data worth keeping
    mdat: Box | None = None
    partial_moov: Box | None = None
    exact: bool = False                       # DATA_END is the end the mdat box says (and a box follows)


_KEEP_BEFORE = {b"uuid", b"udta", b"meta", b"pdin", b"prfl", b"XMP_"}


def find_layout(buf, boxes: list[Box], data_offset: int | None = None) -> Layout:
    """Where the media data of a file without (usable) index starts and may end: after the mdat header (whose
    size may be 0, a placeholder or garbage), else after the boxes that parse (ftyp, free, wide...)."""
    end = len(buf)
    lay = Layout(0, end)
    keep = []
    pos = 0
    for b in boxes:
        if b.type == b"ftyp" and not b.truncated and not lay.ftyp:
            lay.ftyp = bytes(buf[b.start:b.end])
        elif b.type == b"moov" and b.truncated:
            lay.partial_moov = b
        elif b.type in _KEEP_BEFORE and not b.truncated and lay.mdat is None:
            keep.append(bytes(buf[b.start:b.end]))
        if b.type == b"mdat" and lay.mdat is None:
            lay.mdat = b
            lay.data_start = b.payload
            lay.data_end = end
            if not b.truncated and b.size > b.header and b.end < end and _box_at(buf, b.end):
                lay.data_end = b.end                  # a sane size, and a box after it
                lay.exact = True
            break
        pos = b.end
    else:
        # no mdat box: a header the box walk refused (size 1 with a 64-bit 0), or the data right after the boxes
        lay.data_end = end
        lay.data_start = pos
        if pos + 16 <= end and bytes(buf[pos + 4:pos + 8]) == b"mdat":
            lay.data_start = pos + (16 if I.be32(buf, pos) == 1 else 8)
        elif boxes and boxes[-1].truncated and boxes[-1].type not in (b"mdat",):
            lay.data_start = boxes[-1].end if boxes[-1].type != b"moov" else end
    last = boxes[-1] if boxes else None
    if last is not None and last.type == b"moov" and last.truncated:
        lay.partial_moov = last                       # the index at the end, cut off
        if lay.mdat is not None and lay.data_end > last.start:
            lay.data_end = last.start
    if data_offset is not None and 0 <= data_offset < end:
        lay.data_start, lay.data_end = data_offset, end
    lay.keep = b"".join(keep)
    return lay


def _box_at(buf, pos: int) -> bool:
    """Does a box start at POS (a box type, and a size that can be one)?"""
    if pos + 8 > len(buf):
        return False
    size, kind = I.be32(buf, pos), bytes(buf[pos + 4:pos + 8])
    return I.is_fourcc(kind) and (size >= 8 or size in (0, 1) and kind in I.TOP_LEVEL)


def load_reference(reference) -> tuple[Recipe | None, str]:
    """The recipe of a reference video file, or (None, why it can't be used)."""
    import mmap
    name = Path(str(reference)).name
    try:
        with open(reference, "rb") as f:
            size = f.seek(0, 2)
            if size < 16:
                return None, f"The reference video {name} is empty"
            m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                boxes = I.top_level(m)
                if not boxes or boxes[0].type not in (b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip"):
                    return None, f"The reference {name} isn't an MP4 or MOV video"
                movie, boxes = I.movie_of(m)
                if movie is None:
                    return None, f"The reference video {name} has no index itself: choose a complete recording"
                frags = I.fragments_of(m, boxes, next((b for b in boxes if b.type == b"moov"), None)) \
                    if movie.fragmented else {}
                recipe = learn(m, movie, boxes, frags)
                moov = next((b for b in boxes if b.type == b"moov" and not b.truncated), None)
                if moov is not None:
                    recipe.init_moov = bytes(m[moov.start:moov.end])
            finally:
                m.close()
    except OSError as exc:
        return None, f"The reference video {name} can't be read: {exc.strerror or exc}"
    except (struct.error, IndexError, ValueError, OverflowError) as exc:
        return None, f"The reference video {name} is damaged ({type(exc).__name__})"
    if not recipe.makers or recipe.video_lost:
        why = recipe.video_lost or ("; ".join(recipe.skipped) if recipe.skipped else "it has no tracks")
        return None, f"The reference video {name} can't be used: {why[:1].lower()}{why[1:]}"
    recipe.source = name
    return recipe, ""


def _summary(tracks: list[TrackRebuild]) -> str:
    video = sum(t.count for t in tracks if t.video)
    sound = sum(t.count for t in tracks if t.ref.handler == "soun" and not isinstance(t, PcmAudio))
    pcm = [t for t in tracks if isinstance(t, PcmAudio) and t.count]
    parts = []
    if video:
        parts.append(_plural(video, "video frame"))
    if sound:
        parts.append(_plural(sound, "sound frame"))
    for t in pcm:
        secs = t.count / (t.ref.timescale or 1) * t.dur
        parts.append(f"{secs:.1f} s of sound")
    return ", ".join(parts)


# ---------------------------------------------------------------------- the plans
NEEDS_REFERENCE = ("Add a reference video: a good recording from the same camera or phone, with the same settings "
                   "(resolution, frame rate), and repair again.")
MISSING = "The recording's index (the moov box) is missing: it wasn't finished (battery, crash, card removed)"


def _rebuild(plan, buf, lay: Layout, recipe: Recipe, ctl, how: str, guessed: str = "") -> str:
    """Plan the rebuild of a recording without index with RECIPE: the start of the data is walked now (to see
    that the recipe fits), the whole data when the repair is written. Returns "" when the plan is made, else why
    the recipe doesn't fit (the plan is left as it was)."""
    tracks = recipe.make()
    stop = lay.data_start + PREWALK
    walk = Walk(buf, lay.data_start, lay.data_end, tracks, recipe.trans, ctl, stop, lay.exact, recipe.other).run()
    sound = ""
    if recipe.source == "stream" and walk.other_runs:
        more = with_guessed_sound(buf, recipe, walk, lay, ctl)    # the sound between the pictures may be AAC
        if more is not None:
            recipe, walk, sound = more
            tracks = walk.tracks
    found = [t for t in tracks if t.count]
    videos = [t for t in tracks if t.video]
    if not found or (videos and not any(t.count for t in videos)):
        if recipe.source == "stream":
            return NEEDS_REFERENCE
        if recipe.source.startswith("the file's own"):
            return "What is left of the file's own index doesn't fit its frames"
        plan.info["reference_mismatch"] = True
        return (f"The reference video {recipe.source} doesn't fit this recording: none of its frames could be read "
                "with the reference's settings. Choose a recording made with the same camera and settings")
    if sound:
        how = "from the video stream and the sound"
    action = f"Rebuild the index {how}"
    plan.problem(MISSING, action)
    plan.repairable = True
    plan.info.update(rebuild=recipe.source,
                     tracks=[f"{t.name} {HANDLERS.get(t.ref.handler, t.ref.handler)}" for t in tracks])
    raw = [SALVAGE_EXT[t.kind] for t in found if t.kind in SALVAGE_EXT]
    if raw:
        plan.info["salvage"] = raw              # salvage() can also write these as raw streams
    notes = []
    if guessed:
        notes.append("The frame rate isn't stored in the stream: 30 frames per second was assumed.")
    if sound:
        notes.append(f"The sound's settings were worked out from the sound itself ({sound}); with a reference video "
                     "from the same camera its start would be exact.")
    elif recipe.source == "stream":
        notes.append("Only the picture could be rebuilt: the sound needs a reference video from the same camera.")
    notes += [s + "." for s in recipe.skipped]
    plan.note = " ".join(notes)
    whole = walk.stop >= walk.end

    def build():
        w = walk if whole else Walk(buf, lay.data_start, lay.data_end, recipe.make(), recipe.trans, ctl,
                                    exact_end=lay.exact, other=recipe.other).run()
        w.finish()
        done = [t for t in w.tracks if t.count]
        text = f"{action} ({_summary(done)})"
        plan.actions[plan.actions.index(action)] = text
        if w.gaps:
            bad = sum(b - a for a, b, _c in w.gaps)
            stretches = f"{len(w.gaps)} damaged stretch{'es were' if len(w.gaps) > 1 else ' was'}"
            plan.note = (f"{stretches} skipped ({_plural(bad, 'byte')}): the picture jumps there. " + plan.note).strip()
        plan.info.update(frames={t.name: t.count for t in done}, damaged=len(w.gaps))
        return _assemble(buf, lay, recipe, w.tracks)
    plan.build = build
    if whole:
        plan.info["frames"] = {t.name: t.count for t in found}
    return ""


def _missing_index(plan, buf, boxes: list[Box], reference, data_offset, ctl):
    """A recording without index: rebuilt from the reference video, else from what is left of its own index,
    else from the stream itself (when it carries its parameter sets)."""
    lay = find_layout(buf, boxes, data_offset)
    if lay.data_end - lay.data_start < 16:
        plan.problem(MISSING if lay.mdat is not None else "The file's structure is damaged")
        plan.note = "There is no recording in it to rebuild."
        return plan
    failed: list[str] = []
    if reference is not None:
        recipe, why = load_reference(reference)
        if recipe is not None:
            why = _rebuild(plan, buf, lay, recipe, ctl, f"from the reference video {recipe.source}")
        if why:
            failed.append(why)
    if not plan.repairable and lay.partial_moov is not None:
        own = learn(buf, I.parse_moov(buf, lay.partial_moov), boxes, check=True)
        if own.makers and not own.video_lost:
            own.source = "the file's own damaged index"
            why = _rebuild(plan, buf, lay, own, ctl, "from what is left of it")
            if why:
                failed.append(why)
    if not plan.repairable:
        recipe, guessed = stream_recipe(buf, lay.data_start, lay.data_end)
        if recipe is not None:
            _rebuild(plan, buf, lay, recipe, ctl, "from the video stream (picture only)", guessed)
    if plan.repairable:
        if failed:                              # what was tried first and didn't work
            plan.note = " ".join(f"{w}." for w in failed) + (" " + plan.note if plan.note else "")
        return plan
    plan.problem(MISSING if lay.mdat is not None or lay.ftyp else "The file's structure is damaged")
    if not plan.info.get("reference_mismatch"):
        plan.info["needs_reference"] = True
    reasons = [w for w in failed if w != NEEDS_REFERENCE]
    plan.note = " ".join(f"{w}." for w in reasons) if reasons else NEEDS_REFERENCE
    if reasons and not plan.info.get("reference_mismatch"):
        plan.note += " " + NEEDS_REFERENCE
    return plan


def plan(buf, path, reference=None, data_offset=None, ctl=None):
    """What is wrong with the MP4/MOV/3GP/M4V file in BUF and how to repair it: a filerepair.Plan."""
    from ..filerepair import Plan, _mp4_like, detect
    t = _mp4_like(bytes(buf[:12])) or detect(buf, path)
    p = Plan(t if t in ("mp4", "mov") else "mp4")
    boxes = I.top_level(buf)
    moov = next((b for b in boxes if b.type == b"moov" and not b.truncated), None)
    if moov is None:
        hidden = _hidden_moov(buf, boxes)
        if hidden is not None:
            result = _found_moov(p, buf, boxes, hidden)
            if result is not None:
                return result
    if moov is None or (reference is not None and not I.parse_moov(buf, moov).tracks and
                        any(b.type == b"mdat" for b in boxes)):
        if any(b.type == b"moof" for b in boxes):
            return _fragments(p, buf, boxes, None, reference, ctl)
        return _missing_index(p, buf, boxes, reference, data_offset, ctl)
    movie = I.parse_moov(buf, moov)
    if movie.fragmented or any(b.type == b"moof" for b in boxes):
        return _fragments(p, buf, boxes, moov, reference, ctl)
    return _indexed(p, buf, boxes, moov, movie, ctl)


# ---------------------------------------------------------------------- an intact index
def _expand(run_list) -> list[int]:
    out: list[int] = []
    for c, v in run_list:
        out.extend([v] * c)
    return out


def _clip_edits(entries, media_end: int, media_ts: int, movie_ts: int) -> list:
    """An edit list cut to media that ends at MEDIA_END (media timescale)."""
    out = []
    for d, mt, rate in entries:
        if mt == -1:
            out.append((d, mt, rate))
            continue
        if media_end <= mt:
            break
        avail = (media_end - mt) * movie_ts // max(1, media_ts)
        out.append((min(d, avail), mt, rate))
        if avail < d:
            break
    return out


def subset_trak(buf, trak: Box, t: Track, first: int, last: int, shift, movie_ts: int,
                delay: int = 0) -> tuple[bytes, int]:
    """The trak box with only samples [FIRST, LAST) of track T; SHIFT(offset) gives a chunk's new offset. A
    track that loses its first samples starts DELAY (movie timescale) after the others. Returns the box and the
    track's duration in the movie timescale."""
    sizes = t.sizes[first:last]
    chunk_offsets, chunk_counts = [], []
    for off, a, n in t.chunks():
        lo, hi = max(a, first), min(a + n, last)
        if lo >= hi:
            continue
        chunk_offsets.append(shift(off + sum(t.sizes[a:lo])))
        chunk_counts.append(hi - lo)
    durs = t.durations()[first:last]
    cts = _expand(t.ctts)[first:last] if t.ctts else []
    media_end = 0
    tdts = 0
    for i, d in enumerate(durs):
        media_end = max(media_end, tdts + (cts[i] if i < len(cts) else 0) + d)
        tdts += d
    md_dur = sum(durs)
    entries = I.parse_elst(t.edts) if t.edts else []
    entries = _clip_edits(entries, media_end, t.timescale, movie_ts) if entries else []
    if first:
        start = 0
        if cts:
            acc, start = 0, None
            for i, d in enumerate(durs):
                start = acc + cts[i] if start is None else min(start, acc + cts[i])
                acc += d
        entries = [(delay, -1, 1.0)] if delay else []
        if start or delay:
            entries.append(((media_end - start) * movie_ts // max(1, t.timescale), start, 1.0))
    tk_dur = sum(d for d, _m, _r in entries) if entries else md_dur * movie_ts // max(1, t.timescale)
    parts = {
        b"stts": I.stts_box(I.runs(durs)),
        b"ctts": I.ctts_box(I.runs(cts)) if cts else b"",
        b"stss": I.stss_box([k - 1 - first for k in t.stss if first < k <= last]) if t.stss is not None else b"",
        b"stsz": I.stsz_box(sizes),
        b"stz2": I.stsz_box(sizes),
        b"stsc": I.stsc_box(chunk_counts),
        b"stco": I.stco_box(chunk_offsets),
        b"co64": I.stco_box(chunk_offsets),
    }
    drop = {b"subs", b"saiz", b"saio", b"cslg", b"stps", b"padb", b"stdp", b"stsh", b"sbgp"}

    def edit(path, b):
        name = path[-1]
        if path == (b"trak", b"tkhd"):
            return I.with_duration(bytes(buf[b.start:b.end]), tk_dur)
        if path == (b"trak", b"edts"):
            return I.edts_box(entries) if entries else b""
        if path == (b"trak", b"mdia", b"mdhd"):
            return I.with_duration(bytes(buf[b.start:b.end]), md_dur)
        if len(path) == 5 and path[3] == b"stbl":
            if name in parts:
                return parts[name]
            if name == b"sdtp":                   # version and flags, then one byte per sample
                q = b.payload + 4
                return box("sdtp", bytes(buf[b.payload:q]), bytes(buf[q + first:q + last]))
            if name in drop:
                return b""
        return None
    return I.rewrite(buf, trak, edit), tk_dur


def _complete_samples(t: Track, end: int) -> int:
    """How many of T's samples, from the first, lie wholly in the first END bytes. (Pictures decoded before
    B-frames that are lost keep their times from the composition offsets: they stay.)"""
    n = 0
    for o, s in zip(t.sample_offsets(), t.sizes):
        if o + s > end:
            break
        n += 1
    return n


def _indexed(p, buf, boxes: list[Box], moov: Box, movie: Movie, ctl):
    from ..filerepair import _n, _patched
    end = len(buf)
    last = boxes[-1]
    real_end = last.end
    keep = [_complete_samples(t, end) for t in movie.tracks]
    lost = [t.samples - k for t, k in zip(movie.tracks, keep)]
    if any(lost):
        return _cut_short(p, buf, boxes, moov, movie, keep)
    patches: dict[int, bytes] = {}
    if last.truncated:
        if last.type == b"mdat":
            p.problem("The video data (mdat) is cut short", "Set the size of the video data to what is there")
            patches[last.start] = struct.pack(">I", end - last.start) if last.header == 8 else \
                struct.pack(">I4sQ", 1, b"mdat", end - last.start)
        else:
            real_end = last.start
            p.problem(f"The file is cut short inside its “{last.name}” box",
                      f"Cut the incomplete “{last.name}” box at the end")
    elif real_end < end:
        p.problem(f"{_n(end - real_end)} of other data come after the end", f"Cut the {_n(end - real_end)} at the end")
    shifted = _moved_data(p, buf, boxes, moov, movie)
    if shifted is not None:
        return shifted
    if not p.problems:
        return p
    pieces = _patched(0, real_end if not last.truncated or last.type != b"mdat" else end, patches)
    p.repairable = True
    p.build = lambda: pieces
    return p


def _cut_short(p, buf, boxes: list[Box], moov: Box, movie: Movie, keep: list[int]):
    """The index is there but the file ends early: keep the complete samples."""
    movie_ts = movie.timescale or 1000
    vid = next((i for i, t in enumerate(movie.tracks) if t.handler == "vide"), None)
    main = vid if vid is not None else 0
    t0 = movie.tracks[main]
    p.problem(f"The file is cut short: {_plural(t0.samples - keep[main], 'frame')} of {t0.samples:,} are missing"
              .replace(",", " ") if vid is not None else "The file is cut short: the end of the recording is missing",
              f"Keep the {_plural(keep[main], 'complete frame')} and shorten the index to them"
              if vid is not None else "Keep the complete part and shorten the index to it")
    if keep[main] == 0:
        p.note = "Nothing of the recording is left in the file."
        return p
    data_end = 0
    for t, k in zip(movie.tracks, keep):
        if k:
            offs = t.sample_offsets()
            data_end = max(data_end, max(o + s for o, s in zip(offs[:k], t.sizes[:k])))

    def make_moov(shift_by: int) -> bytes:
        def shift(off: int) -> int:
            return off + shift_by if off >= moov.end else off
        parts = []
        mv_dur = 0
        ti = 0
        for b in I.children(buf, moov):
            if b.type == b"trak":
                t = I._parse_trak(buf, b)
                if t is None:
                    parts.append(bytes(buf[b.start:b.end]))
                    continue
                k = keep[ti] if ti < len(keep) else 0
                ti += 1
                raw, d = subset_trak(buf, b, t, 0, k, shift, movie_ts)
                parts.append(raw)
                mv_dur = max(mv_dur, d)
            elif b.type == b"mvhd":
                parts.append(None)
            else:
                parts.append(bytes(buf[b.start:b.end]))
        mvhd = I.with_duration(movie.mvhd, mv_dur)
        return box("moov", *(mvhd if x is None else x for x in parts))
    old = moov.end - moov.start
    data_after = data_end > moov.end
    new = make_moov(0)
    pad = 0
    if data_after:
        diff = old - len(new)
        if 0 < diff < 8 or diff < 0:
            s = 8 - diff if diff > 0 else -diff
            new = make_moov(s)
            diff = old + s - len(new)
        pad = diff
    pieces: list = []
    for b in boxes:
        if b.start >= data_end and b.type != b"moov":
            break
        if b.type == b"moov" and b.start == moov.start:
            pieces.append(new + (box("free", bytes(pad - 8)) if pad >= 8 else b""))
        elif b.type == b"mdat" and (b.truncated or b.end > data_end):
            size = data_end - b.start               # the media data up to the last complete sample
            hdr = struct.pack(">I4s", size, b"mdat") if b.header == 8 else struct.pack(">I4sQ", 1, b"mdat", size)
            pieces += [hdr, (b.payload, data_end)]
            break
        elif b.truncated:
            break
        else:
            pieces.append((b.start, b.end))
    p.repairable = True
    p.build = lambda: pieces
    p.info["kept"] = keep
    return p


def _moved_data(p, buf, boxes: list[Box], moov: Box, movie: Movie):
    """The index is intact but its frames aren't where it says (a file that got extra bytes at the start, or
    lost some): the plan that moves the index to them, or None when the frames are where they should be (or
    it can't be told)."""
    found = _data_shift(buf, movie, boxes, 0, moov.start if moov.start > len(buf) // 2 else len(buf))
    if found is None or found[0] == 0:
        return None
    return _relayout(p, buf, boxes, moov, movie, found[0])


def _shift_model(buf, movie: Movie, boxes: list[Box]):
    """A video track's model, made from the movie's own configuration without trusting where its samples are:
    (track index, model) or None."""
    recipe = learn(buf, movie, boxes, check=False)
    for slot, t in zip(recipe.slots, recipe.make()):
        if t.video and not isinstance(t, StartCodeVideo):     # (whose frames don't say their length)
            if isinstance(t, NalVideo):
                t.start_bytes = None
                t.reader.types = None
            return slot, t
    return None


def _data_shift(buf, movie: Movie, boxes: list[Box], lo: int, hi: int) -> tuple[int, int] | None:
    """How far the video frames are from where the index says: (shift, video track index); (0, i) when they
    are where it says, None when that can't be told (no video track, or no frames found)."""
    got = _shift_model(buf, movie, boxes)
    if got is None:
        return None
    slot, model = got
    t = movie.tracks[slot]
    offs, sizes = t.sample_offsets(), t.sizes
    end = len(buf)
    inside = [k for k in range(len(sizes)) if lo <= offs[k] and offs[k] + sizes[k] <= hi]
    test = [inside[i] for i in range(0, len(inside), max(1, len(inside) // 12))][:12]

    def fits(k: int, d: int) -> bool:
        o = offs[k] + d
        if not lo <= o or o + sizes[k] > hi:
            return False
        h = model.match(buf, o, end, learn=False)
        return h is not None and h.size == sizes[k]
    if test and sum(fits(k, 0) for k in test) * 2 >= len(test):
        return 0, slot
    by_size: dict[int, list[int]] = {}
    for k, n in enumerate(sizes):
        by_size.setdefault(n, []).append(k)
    cand = model.candidates()
    if cand is None:
        return None
    pat, back = cand if isinstance(cand, tuple) else (cand, 0)
    x = lo + back
    stop = min(hi, lo + 16 * MiB)
    tries = 0
    while tries < 20000:
        m = pat.search(buf, x, stop)
        if m is None:
            return None
        c = m.start() - back
        x = m.start() + 1
        h = model.match(buf, c, end, learn=False)
        if h is None:
            continue
        tries += 1
        for k in by_size.get(h.size, [])[:50]:
            d = c - offs[k]
            nxt = list(range(k + 1, min(len(sizes), k + 9)))
            if nxt and sum(fits(j, d) for j in nxt) >= max(1, len(nxt) - 2):
                return d, slot
    return None


def _hidden_moov(buf, boxes: list[Box]) -> Box | None:
    """A movie box that isn't among the top-level boxes: behind an mdat whose size is wrong (0, a placeholder),
    or at the end of a file that lost its first bytes. The last one that parses wins."""
    end = len(buf)
    lo = max(0, end - 256 * MiB)
    i = buf.rfind(b"moov", lo, end)
    while i >= 4:
        start = i - 4
        size = I.be32(buf, start)
        if 16 <= size <= end - start:
            b = Box(b"moov", start, 8, size, start + size)
            kids = [c.type for c in I.children(buf, b)]
            if b"mvhd" in kids and b"trak" in kids:
                return b
        i = buf.rfind(b"moov", lo, i)
    return None


def _found_moov(p, buf, boxes: list[Box], moov: Box):
    """The file's index was found outside the top-level boxes."""
    from ..filerepair import _n
    movie = I.parse_moov(buf, moov)
    found = _data_shift(buf, movie, boxes, 0, moov.start)
    if found is None:
        return None
    d, _slot = found
    mdat = next((b for b in boxes if b.type == b"mdat"), None)
    if d == 0 and mdat is not None and mdat.start < moov.start:
        # an mdat that runs over the index (size 0, or a placeholder the camera never corrected)
        p.problem("The size of the video data box (mdat) is wrong, so players can't find the index after it",
                  "Correct the size of the video data box")
        size = moov.start - mdat.start
        hdr = struct.pack(">I4s", size, b"mdat") if mdat.header == 8 and size <= 0xFFFFFFFF else \
            struct.pack(">I4sQ", 1, b"mdat", size) if mdat.header == 16 else None
        if hdr is None:
            return _relayout(p, buf, boxes, moov, movie, 0)
        pieces = [(0, mdat.start), hdr, (mdat.payload, moov.end)]
        if moov.end < len(buf):
            p.problem(f"{_n(len(buf) - moov.end)} of other data come after the end",
                      f"Cut the {_n(len(buf) - moov.end)} at the end")
        p.repairable = True
        p.build = lambda: pieces
        return p
    return _relayout(p, buf, boxes, moov, movie, d)


def _relayout(p, buf, boxes: list[Box], moov: Box, movie: Movie, d: int):
    """A new file around the frames that are there: the index's samples are D bytes from where it says."""
    from ..filerepair import _n
    end = len(buf)
    hi_limit = moov.start if moov.start > end // 2 else end
    lo_limit = moov.end if moov.end <= end // 2 else 0
    ranges = []
    for t in movie.tracks:
        offs = t.sample_offsets()
        k0 = 0
        while k0 < t.samples and offs[k0] + d < lo_limit:
            k0 += 1
        if t.handler == "vide" and t.stss is not None:
            keys = t.keyframes()
            while k0 < t.samples and k0 not in keys:
                k0 += 1
        k1 = k0
        while k1 < t.samples and offs[k1] + d + t.sizes[k1] <= hi_limit:
            k1 += 1
        ranges.append((k0, k1, offs))
    if not any(k1 > k0 for k0, k1, _o in ranges):
        return None
    lo = min(offs[k0] + d for k0, k1, offs in ranges if k1 > k0)
    hi = max(offs[k1 - 1] + d + t.sizes[k1 - 1] for (k0, k1, offs), t in zip(ranges, movie.tracks) if k1 > k0)
    kept = sum(k1 - k0 for k0, k1, _o in ranges)
    total = sum(t.samples for t in movie.tracks)
    if d < 0:
        p.problem(f"The file lost its first {_n(-d)}: the index points {_n(-d)} past where the frames are",
                  "Move the index to where the frames are")
    elif d > 0:
        p.problem(f"The index points {_n(d)} before where the frames are (other data came in front of them)",
                  "Move the index to where the frames are")
    else:
        p.problem("The file's structure is damaged, but its index is intact", "Rebuild the file around its index")
    if kept < total:
        p.problem(f"{_plural(total - kept, 'frame')} of the recording are missing",
                  f"Keep the {_plural(kept, 'frame')} that are there")
    ftyp = next((bytes(buf[b.start:b.end]) for b in boxes if b.type == b"ftyp" and not b.truncated), DEFAULT_FTYP)
    n = 8 + hi - lo
    hdr = struct.pack(">I4s", n, b"mdat") if n <= 0xFFFFFFFF else struct.pack(">I4sQ", 1, b"mdat", n + 8)
    new_start = len(ftyp) + len(hdr)
    movie_ts = movie.timescale or 1000
    starts = []
    for (k0, k1, _o), t in zip(ranges, movie.tracks):
        starts.append(sum(t.durations()[:k0]) / (t.timescale or 1) if k1 > k0 else None)
    first = min(x for x in starts if x is not None)
    parts = []
    mv_dur = 0
    ti = 0
    for b in I.children(buf, moov):
        if b.type == b"trak":
            t = I._parse_trak(buf, b)
            if t is None:
                continue
            k0, k1, _o = ranges[ti]
            delay = round((starts[ti] - first) * movie_ts) if starts[ti] is not None else 0
            ti += 1
            if k1 <= k0:
                continue
            raw, dur = subset_trak(buf, b, t, k0, k1, lambda off: off + d - lo + new_start, movie_ts, delay)
            parts.append(raw)
            mv_dur = max(mv_dur, dur)
        elif b.type == b"mvhd":
            parts.append(None)
        else:
            parts.append(bytes(buf[b.start:b.end]))
    new_moov = box("moov", *(I.with_duration(movie.mvhd, mv_dur) if x is None else x for x in parts))
    pieces = [ftyp + hdr, (lo, hi), new_moov]
    p.repairable = True
    p.build = lambda: pieces
    return p


# ---------------------------------------------------------------------- fragmented files
def _fragments(p, buf, boxes: list[Box], moov: Box | None, reference, ctl):
    """Fragmented MP4 (moof + mdat pairs after a moov with mvex): cut an incomplete last fragment, drop a
    damaged fragment index (mfra); without the moov, take the reference's."""
    from ..filerepair import _n
    end = len(buf)
    trex = I.trex_defaults(buf, moov) if moov is not None else {}
    init_moov = bytes(buf[moov.start:moov.end]) if moov is not None else b""
    if moov is None:
        recipe, why = load_reference(reference) if reference is not None else (None, "")
        p.problem("The start of the fragmented recording (its moov box) is missing")
        if recipe is None or not recipe.movie.fragmented:
            p.info["needs_reference"] = True
            p.note = (f"{why}. " if why else "") + ("Add a reference video: a good recording from the same camera "
                                                    "or app, recorded the same way, and repair again.")
            return p
        init_moov = recipe.init_moov
        trex = I.trex_defaults(init_moov, next(I.iter_boxes(init_moov)))
    good_end = None
    first_frag = None
    frames: dict[int, I.FragTrack] = {}
    i = 0
    incomplete = False
    while i < len(boxes):
        b = boxes[i]
        if b.type == b"moof":
            if first_frag is None:
                first_frag = b.start
            nxt = boxes[i + 1] if i + 1 < len(boxes) else None
            if b.truncated or nxt is None or nxt.type != b"mdat" or nxt.truncated or \
                    not I.parse_moof(buf, b, trex, frames, strict_end=nxt.end) and moov is not None:
                incomplete = True
                break
            good_end = nxt.end
            i += 2
            continue
        if b.type == b"mfra":
            if b.truncated or not _mfra_ok(buf, b):
                p.problem("The fragment index at the end (mfra) is damaged", "Drop the fragment index")
                break
            good_end = b.end
        elif b.truncated:
            incomplete = True
            break
        elif good_end is not None:
            good_end = b.end
        i += 1
    if incomplete:
        p.problem("The last movie fragment is incomplete: the file is cut short", "Cut off the incomplete last fragment")
    if good_end is None:
        if first_frag is None:
            p.note = "There is no complete movie fragment in the file."
            return p
        good_end = first_frag
    if moov is not None and good_end < end and not p.problems:
        p.problem(f"{_n(end - good_end)} of other data come after the end", f"Cut the {_n(end - good_end)} at the end")
    if not p.problems:
        return p
    if moov is not None:
        patches = {}
        for b in boxes:
            if b.type == b"sidx" and b.end <= good_end and _sidx_past(buf, b, good_end):
                patches[b.start] = struct.pack(">I4s", b.end - b.start, b"free")
        from ..filerepair import _patched
        pieces = _patched(0, good_end, patches)
        p.repairable = good_end > moov.end
        if not p.repairable:
            p.note = "There is no complete movie fragment in the file."
        p.build = lambda: pieces
        return p
    # the init segment from the reference, the fragments with their base offsets moved along
    head = (next((bytes(buf[b.start:b.end]) for b in boxes if b.type == b"ftyp" and not b.truncated), b"")
            or recipe.ftyp or DEFAULT_FTYP) + init_moov
    if first_frag is None:
        p.note = "There is no complete movie fragment in the file."
        return p
    shift = len(head) - first_frag
    pieces = [head] + _moved_fragments(buf, boxes, first_frag, good_end, shift)
    p.problem(p.problems[0], f"Use the start of the reference video {recipe.source}")
    p.repairable = True
    p.build = lambda: pieces
    return p


def _mfra_ok(buf, mfra: Box) -> bool:
    """Do the fragment index's entries point at moof boxes?"""
    for tfra in I.children(buf, mfra):
        if tfra.type != b"tfra":
            continue
        q = tfra.payload
        try:
            v = buf[q]
            sizes = I.be32(buf, q + 8)
            count = I.be32(buf, q + 12)
            q += 16
            w = 16 if v == 1 else 8
            extra = ((sizes >> 4) & 3) + ((sizes >> 2) & 3) + (sizes & 3) + 3
            for _ in range(min(count, 50)):
                off = I.be64(buf, q + 8) if v == 1 else I.be32(buf, q + 4)
                if bytes(buf[off + 4:off + 8]) != b"moof":
                    return False
                q += w + extra
        except (struct.error, IndexError):
            return False
    return True


def _sidx_past(buf, sidx: Box, good_end: int) -> bool:
    """Does the segment index refer to more than what is left?"""
    try:
        q = sidx.payload
        v = buf[q]
        first = I.be64(buf, q + 20) if v == 1 else I.be32(buf, q + 16)
        q += 28 if v == 1 else 20
        count = I.be16(buf, q + 2)
        q += 4
        total = sum(I.be32(buf, q + 12 * k) & 0x7FFFFFFF for k in range(count))
        return sidx.end + first + total > good_end
    except (struct.error, IndexError):
        return True


def _moved_fragments(buf, boxes: list[Box], start: int, stop: int, shift: int) -> list:
    """The fragments in [START, STOP) as pieces, moved by SHIFT bytes: absolute base data offsets in their track
    fragment headers are rewritten. They were written for the original file, which may have had more (or less)
    before the first fragment than this one: that difference comes from the first fragment, whose base offset
    is its own start."""
    pieces: list = []
    pos = start
    lost = None
    for b in boxes:
        if b.start < start or b.end > stop or b.type != b"moof":
            continue
        for traf in I.children(buf, b):
            if traf.type != b"traf":
                continue
            for tfhd in I.children(buf, traf):
                if tfhd.type == b"tfhd" and I.be32(buf, tfhd.payload) & 1:
                    at = tfhd.payload + 8
                    base = I.be64(buf, at)
                    if lost is None:
                        lost = base - b.start
                    pieces += [(pos, at), struct.pack(">Q", max(0, base - lost + shift))]
                    pos = at + 8
    pieces.append((pos, stop))
    return pieces


# ---------------------------------------------------------------------- raw streams
SALVAGE_EXT = {"avc": "h264", "hevc": "hevc", "aac": "aac"}


def _samples(t: TrackRebuild):
    """(offset, size) of every sample of a rebuilt track, in order."""
    k = 0
    for off, n in zip(t.chunk_offsets, t.chunk_counts):
        for _ in range(n):
            size = t.const_size or t.sizes[k]
            yield off, size
            off += size
            k += 1


def _video_params(t: NalVideo) -> list[bytes]:
    """The parameter sets (SPS, PPS; VPS first for H.265) of a video track, as NAL units."""
    if t.kind == "avc":
        ps = t.reader.params
        return [s.raw for s in ps.sps.values()] + [p.raw for p in ps.pps.values()]
    ps = t.reader.params
    return [v.raw for v in ps.vps.values()] + [s.raw for s in ps.sps.values()] + [p.raw for p in ps.pps.values()]


def salvage(path, out_dir, reference=None, ctl=None) -> list[Path]:
    """Write the video of a recording whose index is missing as a raw stream that players open without any
    index: H.264/H.265 in Annex B form (.h264, .hevc; parameter sets before every key frame), AAC sound with
    ADTS headers (.aac). For when a rebuilt MP4 won't play somewhere, or to feed another tool. Uses what the
    rebuild uses (the reference, the file's own damaged index, or the stream); returns the files written."""
    import mmap
    path, out_dir = Path(path), Path(out_dir)
    with open(path, "rb") as f:
        if not f.seek(0, 2):
            return []
        buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            boxes = I.top_level(buf)
            lay = find_layout(buf, boxes)
            recipe = load_reference(reference)[0] if reference is not None else None
            if recipe is None and lay.partial_moov is not None:
                recipe = learn(buf, I.parse_moov(buf, lay.partial_moov), boxes)
            if recipe is None:
                recipe = stream_recipe(buf, lay.data_start, lay.data_end)[0]
            if recipe is None:
                return []
            walk = Walk(buf, lay.data_start, lay.data_end, recipe.make(), recipe.trans, ctl, exact_end=lay.exact,
                        other=recipe.other).run()
            out_dir.mkdir(parents=True, exist_ok=True)
            written = []
            for t in walk.tracks:
                if not t.count or t.kind not in SALVAGE_EXT:
                    continue
                target = out_dir / f"{path.stem}.{SALVAGE_EXT[t.kind]}"
                if any(w.name == target.name for w in written):
                    target = out_dir / f"{path.stem} {t.ref.id}.{SALVAGE_EXT[t.kind]}"
                with open(target, "wb") as out:
                    if isinstance(t, NalVideo):
                        params = b"".join(b"\x00\x00\x00\x01" + n for n in _video_params(t))
                        keys = set(t.keys)
                        ls = t.reader.length_size
                        for k, (off, size) in enumerate(_samples(t)):
                            if ctl is not None and k % 256 == 0:
                                ctl.check()
                            if k in keys:
                                out.write(params)
                            for a, b in h264.iter_nals(buf, off, off + size, ls):
                                out.write(b"\x00\x00\x00\x01")
                                out.write(buf[a:b])
                    else:
                        for off, size in _samples(t):
                            out.write(aac.adts_header(t.asc, size))
                            out.write(buf[off:off + size])
                written.append(target)
            return written
        finally:
            buf.close()

