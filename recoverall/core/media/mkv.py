"""Matroska and WebM (MKV, WEBM, MKA, MK3D, WEBA): checking the container and repairing it.

A Matroska file is EBML elements (see ebml.py): an EBML header naming the kind of document ("matroska",
"webm"), then one Segment holding everything else. At the start of the Segment: a SeekHead (where the other
top-level parts are, as offsets from the start of the Segment's data), Info (the timestamp scale, normally a
millisecond, and the duration), Tracks (each track's number, kind, codec and the codec's settings, e.g. the
H.264 parameter sets), Tags, Chapters, Attachments. Then the recording itself as Clusters: each Cluster has a
Timestamp and blocks (SimpleBlock, or a Block inside a BlockGroup) of a track number, a 16-bit timecode
relative to the Cluster's, flags (key frame) and one or more frames. Cues, usually at the end, list where the
key frames are, for seeking. ffmpeg puts a CRC-32 element first in every top-level part of a .mkv.

What is checked, and repaired in a new copy:

=====================  ==========================================================================================
cut short              the Cluster the file ends in is cut at its last complete block and its size corrected;
                       the Segment size is set to what is there, the duration to the last block's end, and the
                       seeking index (Cues), which was at the end, is rebuilt from the video's key frames.
damage in the middle   a stretch that doesn't parse (overwritten, zeroed) is dropped: the walk picks up again
                       at the next block of the same Cluster, or at the next Cluster whose Timestamp and first
                       blocks parse; blocks whose Cluster header was lost get a new Cluster. The video's frames
                       up to its next key frame are dropped too (they can't be decoded without the frames that
                       were lost); the sound goes on.
other data at the end  cut.
Cues, SeekHead         Cues pointing past the end or at parts that moved are rebuilt; the SeekHead is rewritten
                       in its place with what is really there.
Duration               missing (an unfinished recording) or wrong: set to the last block's end; the DURATION
                       tags ffmpeg writes per track are corrected too.
the start lost         with a REFERENCE recording from the same camera or program with the same settings: its
                       EBML header and Segment head (Info, Tracks with the codec settings, Tags) are put in
                       front of the Clusters that survived.
=====================  ==========================================================================================

Checksums (CRC-32) of the parts that change are recomputed. A Cluster whose own checksum doesn't match has
damaged pictures or sound inside it: that is reported, it can't be undone.
"""

from __future__ import annotations

import bisect
import mmap
import re
import struct
import zlib
from dataclasses import dataclass, field

from ..filerepair import Plan, _merge, _n
from ..fs.base import NULL_CONTROL, Control
from . import ebml as E
from .ebml import Element, element_at

EBML_HEADER = 0x1A45DFA3
SEGMENT = 0x18538067
SEEKHEAD, INFO, TRACKS, CUES, CLUSTER = 0x114D9B74, 0x1549A966, 0x1654AE6B, 0x1C53BB6B, 0x1F43B675
TAGS, CHAPTERS, ATTACHMENTS = 0x1254C367, 0x1043A770, 0x1941A469
VOID, CRC32 = 0xEC, 0xBF
TOP = frozenset({SEEKHEAD, INFO, TRACKS, CUES, CLUSTER, TAGS, CHAPTERS, ATTACHMENTS, VOID, CRC32})
TIMESTAMP, SIMPLEBLOCK, BLOCKGROUP, BLOCK, POSITION, PREVSIZE = 0xE7, 0xA3, 0xA0, 0xA1, 0xA7, 0xAB
CLUSTER_CHILDREN = frozenset({TIMESTAMP, SIMPLEBLOCK, BLOCKGROUP, POSITION, PREVSIZE, VOID, CRC32, 0x5854, 0xAF})
GROUP_CHILDREN = frozenset({BLOCK, 0x9B, 0xFB, 0xFA, 0x75A1, 0x75A2, 0xA4, 0x8E, 0xC8, 0xA2, VOID, CRC32})
SEEK, SEEK_ID, SEEK_POSITION = 0x4DBB, 0x53AB, 0x53AC
CUE_POINT, CUE_TIME, CUE_TRACK_POSITIONS, CUE_TRACK, CUE_CLUSTER_POSITION, CUE_RELATIVE_POSITION = \
    0xBB, 0xB3, 0xB7, 0xF7, 0xF1, 0xF0
TIMESTAMP_SCALE, DURATION = 0x2AD7B1, 0x4489
TRACK_ENTRY, TRACK_NUMBER, TRACK_UID, TRACK_TYPE, CODEC_ID, DEFAULT_DURATION = \
    0xAE, 0xD7, 0x73C5, 0x83, 0x86, 0x23E383
TAG, TARGETS, TAG_TRACK_UID, SIMPLE_TAG, TAG_NAME, TAG_STRING = 0x7373, 0x63C0, 0x63C5, 0x67C8, 0x45A3, 0x4487
DOCTYPE = 0x4282

_CLUSTER_MAGIC = b"\x1f\x43\xb6\x75"
_BLOCK_START = re.compile(rb"[\xa0\xa3]")
_KINDS = {1: "video", 2: "sound", 3: "video+sound", 16: "logo", 17: "subtitles", 18: "buttons", 32: "control",
          33: "metadata"}
_SEEK_ORDER = (CUES, INFO, TRACKS, TAGS, CHAPTERS, ATTACHMENTS)
_MAX_HEAD = 64 * 1024 * 1024


def detect_mkv(head: bytes) -> bool:
    """True when HEAD starts with an EBML header (Matroska, WebM)."""
    return bytes(head[:4]) == b"\x1a\x45\xdf\xa3"


@dataclass
class Track:
    number: int
    uid: int = 0
    kind: int = 0
    codec: str = ""
    default_duration: int = 0          # ns per frame, 0 unknown

    def describe(self) -> str:
        return f"{self.number}: {_KINDS.get(self.kind, 'track')} {self.codec}".strip()


@dataclass
class _Block:
    start: int
    end: int
    track: int
    time: int                          # ticks (TimestampScale), absolute
    key: bool
    dur: int = 0                       # ticks, 0 unknown
    keep: bool = True


@dataclass
class _Cluster:
    start: int                         # input offset of the Cluster id
    data: int                          # input offset of its payload
    size_len: int
    declared: int | None
    timestamp: int
    items: list = field(default_factory=list)     # _Block or (start, end) of the other children, in order
    crc: Element | None = None
    stop: int = 0                      # where its kept children end in the input
    changed: bool = False              # children dropped or its size wrong: size and checksum rewritten
    new_ts: bytes = b""                # a new Cluster for blocks whose Cluster header was lost

    def blocks(self) -> list[_Block]:
        return [b for b in self.items if isinstance(b, _Block)]


# ---------------------------------------------------------------------- the head: EBML header, Info, Tracks
def _ebml_header(buf, end: int) -> tuple[Element, str] | None:
    el = element_at(buf, 0, end)
    if el is None or el.id != EBML_HEADER or el.size is None or el.size > 512 or el.end > end:
        return None
    doctype = ""
    for c in E.children(buf, el.data, el.end):
        if c.id == DOCTYPE:
            doctype = E.text(buf, c)
    return (el, doctype) if doctype in ("matroska", "webm") else None


def _tracks(buf, el: Element) -> dict[int, Track]:
    out: dict[int, Track] = {}
    for te in E.children(buf, el.data, el.end):
        if te.id != TRACK_ENTRY or te.size is None or te.end > el.end:
            continue
        t = Track(0)
        for c in E.children(buf, te.data, te.end):
            if c.id == TRACK_NUMBER:
                t.number = E.uint(buf, c, 0)
            elif c.id == TRACK_UID:
                t.uid = E.uint(buf, c, 0)
            elif c.id == TRACK_TYPE:
                t.kind = E.uint(buf, c, 0)
            elif c.id == CODEC_ID:
                t.codec = E.text(buf, c)
            elif c.id == DEFAULT_DURATION:
                t.default_duration = E.uint(buf, c, 0)
        if 0 < t.number < 128:
            out[t.number] = t
    return out


@dataclass
class _Head:
    """The EBML header and the Segment's parts before its first Cluster, in BUF (the file, or a copy of the
    reference's head)."""
    buf: object
    ebml: Element
    doctype: str
    segment: Element
    seg_id_len: int
    elements: list                     # level-1 elements before the first Cluster
    tracks: dict
    scale: int = 1_000_000
    info: Element | None = None
    duration: float | None = None      # seconds, as Info says
    first_cluster: int | None = None
    damaged_at: int | None = None      # where the head stops parsing (no Cluster reached)


def _parse_head(buf, end: int) -> _Head | None:
    h = _ebml_header(buf, end)
    if h is None:
        return None
    ebml, doctype = h
    pos = ebml.end
    seg = None
    for _ in range(16):                                    # Voids may come before the Segment
        el = element_at(buf, pos, end)
        if el is None:
            return None
        if el.id == SEGMENT:
            seg = el
            break
        if el.id != VOID or el.size is None:
            return None
        pos = el.end
    if seg is None:
        return None
    head = _Head(buf, ebml, doctype, seg, E.read_id(buf, seg.start, end)[1], [], {})
    pos = seg.data
    for _ in range(100000):
        el = element_at(buf, pos, end)
        if el is None or el.id not in TOP:
            head.damaged_at = pos
            break
        if el.id == CLUSTER:
            head.first_cluster = pos
            break
        if el.size is None or el.end > end:
            head.damaged_at = pos
            break
        head.elements.append(el)
        if el.id == INFO and head.info is None:
            head.info = el
            head.scale = E.uint(buf, E.child(buf, el, TIMESTAMP_SCALE), 1_000_000) or 1_000_000
            d = E.float_value(buf, E.child(buf, el, DURATION))
            if d is not None and d == d and 0 <= d < 1e15:
                head.duration = d * head.scale / 1e9
        elif el.id == TRACKS and not head.tracks:
            head.tracks = _tracks(buf, el)
        pos = el.end
    return head


def _crc_fixed(payload: bytes) -> bytes:
    """PAYLOAD with its leading CRC-32 element (if any) recomputed."""
    if payload[:2] == b"\xbf\x84" and len(payload) >= 6:
        return payload[:2] + struct.pack("<I", zlib.crc32(payload[6:])) + payload[6:]
    return payload


def _patch_element(buf, el: Element, patches: dict[int, bytes], append: bytes = b"") -> bytes:
    """Element EL with same-length replacements PATCHES {offset: bytes} and APPEND added to its payload; its
    CRC-32 is recomputed."""
    payload = bytearray(buf[el.data:el.end])
    for off, data in patches.items():
        payload[off - el.data:off - el.data + len(data)] = data
    payload = _crc_fixed(bytes(payload) + append)
    size_len = el.header - E.read_id(buf, el.start, el.data)[1]
    try:
        size = E.encode_size(len(payload), size_len)
    except ValueError:
        size = E.encode_size(len(payload))
    return E.encode_id(el.id) + size + payload


def _fmt_duration(ns: int, width: int) -> bytes:
    """A DURATION tag value "HH:MM:SS.nnnnnnnnn", zero-padded to WIDTH bytes."""
    s, frac = divmod(max(0, ns), 1_000_000_000)
    text = f"{s // 3600:02d}:{s // 60 % 60:02d}:{s % 60:02d}.{frac:09d}".encode()
    return text + bytes(width - len(text)) if len(text) <= width else b""


def _tag_patches(buf, el: Element, ends: dict[int, int], uids: dict[int, int]) -> dict[int, bytes]:
    """New values for the DURATION tags in the Tags element EL: {offset: bytes} (same lengths). ENDS: track
    number → end time in ns; UIDS: track uid → number."""
    patches: dict[int, bytes] = {}
    for tag in E.children(buf, el.data, el.end):
        if tag.id != TAG or tag.size is None:
            continue
        track = None
        for c in E.children(buf, tag.data, tag.end):
            if c.id == TARGETS and c.size is not None:
                uid = E.uint(buf, E.child(buf, c, TAG_TRACK_UID))
                track = uids.get(uid) if uid is not None else None
            elif c.id == SIMPLE_TAG and c.size is not None and track in ends:
                name, value = E.child(buf, c, TAG_NAME), E.child(buf, c, TAG_STRING)
                if name is not None and value is not None and E.text(buf, name) == "DURATION":
                    new = _fmt_duration(ends[track], value.size)
                    if new:
                        patches[value.data] = new
    return patches


# ---------------------------------------------------------------------- walking the Clusters
class _Walk:
    """One pass over the Clusters: what is kept, what was damaged."""

    def __init__(self, buf, end: int, tracks: dict[int, Track], ctl: Control, scale: int = 1_000_000):
        self.buf, self.end, self.tracks, self.ctl = buf, end, tracks, ctl
        self.jump = 300_000_000_000 // max(1, scale)         # five minutes in ticks
        self.items: list = []              # _Cluster and level-1 Elements, in order
        self.blocks: list[_Block] = []     # every block kept by the walk, in order
        self.events: list[int] = []        # indexes into blocks where a damaged stretch was dropped
        self.damage: list[tuple[int, int]] = []
        self.cut_at: int | None = None     # the file ends inside a Cluster / another part
        self.cut_in = ""
        self.trailing_from: int | None = None
        self.last_ts = -1
        self.steps = 0
        self.orphans = 0
        self.cue_map: dict[int, tuple[int, int | None]] = {}   # Cluster offset → (cue time, block's offset)
        self.cue_starts: list[int] = []                        # its keys, in order
        self.last_cluster = -1                                 # where the last Cluster walked starts

    def _tick(self, pos: int) -> None:
        self.steps += 1
        if self.steps % 1024 == 0:
            self.ctl.check()
            self.ctl.progress(pos / max(1, self.end), "Checking the clusters")

    def _track_ok(self, n: int) -> bool:
        return n in self.tracks if self.tracks else 0 < n < 128

    def block(self, ch: Element, ts: int) -> _Block | None:
        """The block CH (SimpleBlock or BlockGroup) in a Cluster with timestamp TS; None when damaged."""
        buf = self.buf
        if ch.id == SIMPLEBLOCK:
            h = E.block_header(buf, ch.data, ch.end)
            if h is None or not self._track_ok(h[0]):
                return None
            return _Block(ch.start, ch.end, h[0], ts + h[1], bool(h[2] & 0x80))
        if ch.id != BLOCKGROUP:
            return None
        blk, dur, ref, p = None, 0, False, ch.data
        while p < ch.end:
            g = element_at(buf, p, ch.end)
            if g is None or g.id not in GROUP_CHILDREN or g.size is None or g.end > ch.end:
                return None
            if g.id == BLOCK:
                blk = g
            elif g.id == 0x9B:
                dur = E.uint(buf, g, 0)
            elif g.id == 0xFB:
                ref = True
            p = g.end
        h = E.block_header(buf, blk.data, blk.end) if blk is not None else None
        if h is None or not self._track_ok(h[0]):
            return None
        return _Block(ch.start, ch.end, h[0], ts + h[1], not ref, dur)

    def cluster_ok(self, q: int) -> bool:
        """A plausible Cluster at Q: its Timestamp and first blocks parse, and its time doesn't go back (nor jump
        far ahead, unless the next Cluster goes on from there: a damaged Timestamp would hide all that follows)."""
        ts = self.cluster_time(q)
        if ts is None or ts < self.last_ts:
            return False
        el = element_at(self.buf, q, self.end)
        nxt = self.cluster_time(el.end) if el.size is not None and el.end < self.end else None
        if nxt is not None and self.last_ts <= nxt < ts:
            return False                                     # the next one goes on from before: this one is off
        if self.last_ts < 0 or ts <= self.last_ts + self.jump:
            return True
        return nxt is not None and ts <= nxt <= ts + self.jump

    def cluster_time(self, q: int) -> int | None:
        """The Timestamp of the Cluster at Q when it and its first blocks parse."""
        buf, end = self.buf, self.end
        el = element_at(buf, q, end)
        if el is None or el.id != CLUSTER or (el.size is not None and el.size < 3):
            return None
        limit = min(el.end, end) if el.size is not None else end
        ts, p, blocks = None, el.data, 0
        for n in range(5):
            if p >= limit:
                break
            ch = element_at(buf, p, end)
            if ch is None or ch.size is None or ch.id not in CLUSTER_CHILDREN:
                return ts if ts is not None and blocks > 0 and ch is not None and ch.id == CLUSTER else None
            if ch.id == CRC32 and (n or ch.size != 4):
                return None
            if ch.id == TIMESTAMP:
                ts = E.uint(buf, ch) if ch.end <= end else None
                if ts is None:
                    return None
            elif ch.id in (SIMPLEBLOCK, BLOCKGROUP):
                if ts is None:
                    return None
                if ch.end > end:
                    break                                    # cut short right there
                if self.block(ch, ts) is None:
                    return None
                blocks += 1
            if ch.end > limit:
                return None
            p = ch.end
        return ts

    def find_cluster(self, pos: int, stop: int) -> int | None:
        buf = self.buf
        while True:
            q = buf.find(_CLUSTER_MAGIC, pos, stop)
            if q < 0:
                return None
            if self.cluster_ok(q):
                return q
            pos = q + 1
            self._tick(q)

    def chain(self, p: int, stop: int) -> tuple[list[_Block], int]:
        """The blocks that follow one another from P (timed as if their Cluster's timestamp were 0), and where
        they stop."""
        found = []
        while p < stop:
            ch = element_at(self.buf, p, self.end)
            if ch is None or ch.size is None or ch.end > stop:
                break
            b = self.block(ch, 0)
            if b is None:
                break
            found.append(b)
            p = ch.end
        return found, p

    def find_blocks(self, start: int, stop: int, exact: bool) -> tuple[int, list[_Block], int] | None:
        """The first offset in [START, STOP) from which valid blocks follow one another: up to STOP exactly
        when EXACT; else at least three of them, or up to STOP or the next Cluster. Returns (offset, the
        blocks, where they stop)."""
        buf = self.buf
        pos = start
        while pos < stop:
            m = _BLOCK_START.search(buf, pos, stop)
            if m is None:
                return None
            q = m.start()
            found, p = self.chain(q, stop)
            if found and (p == stop or (not exact and (len(found) >= 3 or (
                    bytes(buf[p:p + 4]) == _CLUSTER_MAGIC and self.cluster_ok(p))))):
                return q, found, p
            self._tick(q)
            pos = p if found else q + 1         # a run of blocks that stops short: what follows starts after it
        return None

    def _children(self, c: _Cluster, pos: int, limit: int) -> tuple[int, str]:
        """Walk Cluster C's children from POS: (where it stopped, why: "" at LIMIT, "next" a top-level part
        follows early, "cut" the file ends inside a child, "damaged")."""
        buf, end = self.buf, self.end
        while pos < limit:
            self._tick(pos)
            ch = element_at(buf, pos, end)
            if ch is None:
                return pos, "cut" if end - pos < 12 else "damaged"
            if ch.id not in CLUSTER_CHILDREN:
                if ch.id in TOP and (ch.id != CLUSTER or self.cluster_ok(pos)):
                    return pos, "next"
                return pos, "damaged"
            if ch.size is None:
                return pos, "damaged"
            if ch.end > limit:
                return pos, "cut" if limit == end else "damaged"
            if ch.id == CRC32 and pos == c.data and ch.size == 4:
                c.crc = ch
            elif ch.id == TIMESTAMP and c.timestamp < 0:
                c.timestamp = E.uint(buf, ch, 0)
                c.items.append((ch.start, ch.end))
                self.last_ts = max(self.last_ts, c.timestamp)
            elif ch.id in (SIMPLEBLOCK, BLOCKGROUP):
                b = self.block(ch, c.timestamp) if c.timestamp >= 0 else None
                if b is None:
                    return pos, "damaged"
                c.items.append(b)
                self.blocks.append(b)
            elif ch.id != CRC32:
                c.items.append((ch.start, ch.end))
            pos = ch.end
        return pos, ""

    def cluster(self, el: Element, stop: int) -> tuple[_Cluster, int, str]:
        """Walk the Cluster EL (damaged stretches inside it are skipped): (cluster, where the walk stopped,
        why: "" at its end, "next" a top-level part follows early, "cut", "damaged" up to its end)."""
        c = _Cluster(el.start, el.data, el.header - 4, el.size, -1)
        self.items.append(c)
        self.last_cluster = el.start
        limit = min(el.end, stop) if el.size is not None else stop
        pos, why = self._children(c, el.data, limit)
        while why == "damaged" and c.timestamp >= 0:
            c.changed = True
            dropped_from = pos
            if c.items and isinstance(c.items[-1], _Block) and c.items[-1].end == pos:
                dropped_from = c.items.pop().start           # the damage may start inside the last block
                self.blocks.pop()
            search_to = limit if el.size is not None else min(self.end, pos + (64 << 20))
            found = self.find_blocks(pos + 1, search_to, exact=False)
            if found is None:
                c.stop = dropped_from
                return c, dropped_from, "damaged"
            self.damage.append((dropped_from, found[0]))
            self.events.append(len(self.blocks))
            pos, why = self._children(c, found[0], limit)
        c.stop = pos
        if why == "cut" or (el.size is not None and pos != el.end):
            c.changed = True                                 # cut short, or its size is wrong
        return c, pos, why

    def _gap(self, track: int, more: list[_Block]) -> int:
        """The usual time between two blocks of TRACK (ticks), from the last ones walked and MORE."""
        times = sorted([b.time for b in self.blocks[-256:] if b.track == track][-32:])
        extra = sorted(b.time for b in more if b.track == track)
        gaps = sorted(y - x for t in (times, extra) for x, y in zip(t, t[1:]) if y > x)
        return gaps[len(gaps) // 2] if gaps else 0

    def _orphan_base(self, orphans: list[_Block], n: int | None, at: int, q: int) -> int:
        """A timestamp for a new Cluster holding ORPHANS (blocks from Q whose Cluster header was lost in the
        damage from AT; the next Cluster is at N). A track that goes on in the next Cluster pins it: its
        frames follow one another at even steps (sound most of all); else the bytes lost tell the time lost."""
        last: dict[int, int] = {}
        for b in self.blocks[-512:]:
            last[b.track] = max(last.get(b.track, b.time), b.time)
        low = max([self.last_ts, 0] + [last[b.track] - b.time + 1 for b in orphans if b.track in last and
                                        self.tracks.get(b.track, Track(0)).kind != 1])
        if n is not None:
            nxt = element_at(self.buf, n, self.end)
            ts = E.uint(self.buf, E.child(self.buf, nxt, TIMESTAMP, self.end), 0) if nxt is not None else 0
            following, _p = self.chain(next((c.start for c in E.children(self.buf, nxt.data, nxt.end or self.end)
                                             if c.id in (SIMPLEBLOCK, BLOCKGROUP)), n), nxt.end or self.end)
            firsts: dict[int, int] = {}
            for b in following[:64]:
                firsts.setdefault(b.track, ts + b.time)
            order = sorted({b.track for b in orphans} & set(firsts),
                           key=lambda t: (self.tracks.get(t, Track(t)).kind != 2, t))
            for track in order:
                gap = self._gap(track, orphans)
                if gap:
                    r_last = max(b.time for b in orphans if b.track == track)
                    return max(low, firsts[track] - gap - r_last)
            gap = self._gap(orphans[-1].track, orphans)
            return max(low, ts - gap - max(b.time for b in orphans))
        kept = [b for b in self.blocks[-4096:] if b.keep]
        if len(kept) < 2:
            return low
        first = orphans[0]
        anchor_time, anchor_pos = max(b.time for b in kept), kept[-1].end
        prev = self.last_cluster
        k = bisect.bisect_left(self.cue_starts, q) - 1
        if k >= 0 and self.cue_starts[k] > prev:   # the old Cues say where and when the lost Cluster's key frame was
            p = self.cue_starts[k]
            time, rel = self.cue_map[p]
            for b in orphans:
                if rel is not None and p + 5 <= b.start - rel <= p + 12:
                    return max(low, time - b.time)
            base = time                            # as if the key frame came first in its Cluster
        else:
            span = max(b.time for b in kept) - min(b.time for b in kept)
            size = sum(b.end - b.start for b in kept)
            base = anchor_time + round((first.start - anchor_pos) * span / size if size else 0) - first.time
        audio = [b for b in orphans if self.tracks.get(b.track, Track(0)).kind == 2 and b.track in last]
        if audio:                                  # sound frames come at even steps: snap to them
            a = audio[0]
            gap = self._gap(a.track, orphans)
            if gap:
                steps = round((base + a.time - last[a.track]) / gap)
                base = last[a.track] + max(1, steps) * gap - a.time
        return max(low, base)

    def skip_damage(self, at: int, stop: int) -> int | None:
        """A damaged stretch from AT: find the next Cluster; the blocks before it whose own Cluster header was
        lost go in a new Cluster. Returns where to go on, or None (nothing more that can be read)."""
        n = self.find_cluster(at + 1, stop)
        found = self.find_blocks(at, n if n is not None else stop, exact=n is not None)
        if found is None:
            if n is None:
                self.trailing_from = at
                return None
            self.events.append(len(self.blocks))
            self.damage.append((at, n))
            return n
        q, orphans, p = found
        if n is None:
            orphans, p = self.chain(q, stop)
        self.events.append(len(self.blocks))
        base = self._orphan_base(orphans, n, at, q)
        for b in orphans:
            b.time += base
        c = _Cluster(-1, -1, 0, None, base, items=list(orphans), changed=True, stop=p,
                     new_ts=E.uint_element(TIMESTAMP, base))
        self.items.append(c)
        self.blocks.extend(orphans)
        self.damage.append((at, q))
        self.orphans += len(orphans)
        self.last_ts = max(self.last_ts, base)
        return n if n is not None else p

    def walk(self, start: int, stop: int) -> None:
        buf, end = self.buf, self.end
        pos = start
        while pos < stop:
            self._tick(pos)
            el = element_at(buf, pos, end)
            if el is not None and el.id == CLUSTER and self.cluster_ok(pos):
                c, at, why = self.cluster(el, stop)
                if why in ("", "next"):
                    pos = at
                    continue
                if why == "cut":
                    self.cut_at, self.cut_in = at, "cluster"
                    return
                pos = self.skip_damage(at, stop)
                if pos is None:
                    return
                continue
            if el is not None and el.id in TOP and el.id != CLUSTER and el.size is not None:
                if el.end <= stop:
                    self.items.append(el)
                    pos = el.end
                    continue
                if el.end > end:
                    self.cut_at, self.cut_in = pos, "element"
                    return
            if el is not None and el.id == EBML_HEADER:
                self.trailing_from = pos                     # another file follows
                return
            pos = self.skip_damage(pos, stop)
            if pos is None:
                return

    def drop_until_key(self) -> int:
        """After each damaged stretch, drop each video track's frames up to its next key frame (they can't be
        decoded without the frames that were lost). Returns how many were dropped."""
        video = {n for n, t in self.tracks.items() if t.kind == 1}
        keys = {b.track for b in self.blocks if b.key}
        deltas = {b.track for b in self.blocks if not b.key}
        dropped = 0
        for n in video & keys & deltas:
            key_at = [i for i, b in enumerate(self.blocks) if b.track == n and b.key]
            done = 0                                         # blocks before this are handled
            for e in sorted(set(self.events)):
                k = bisect.bisect_left(key_at, e)
                stop = key_at[k] if k < len(key_at) else len(self.blocks)
                for i in range(max(e, done), stop):
                    b = self.blocks[i]
                    if b.track == n and b.keep:
                        b.keep = False
                        dropped += 1
                done = max(done, stop)
        return dropped


# ---------------------------------------------------------------------- building the copy
def _crc_of(buf, pieces: list) -> int:
    crc = 0
    for p in pieces:
        if isinstance(p, tuple):
            for x in range(p[0], p[1], 4 << 20):
                crc = zlib.crc32(buf[x:min(p[1], x + (4 << 20))], crc)
        else:
            crc = zlib.crc32(p, crc)
    return crc


def _cluster_pieces(buf, c: _Cluster) -> tuple[list, int, list[tuple[_Block, int]]]:
    """The pieces of Cluster C in the copy, their length, and each kept block with its offset in the payload."""
    if not c.changed and c.start >= 0 and (c.declared is None or c.stop == c.data + c.declared) and \
            all(b.keep for b in c.blocks()):
        return [(c.start, c.stop)], c.stop - c.start, [(b, b.start - c.data) for b in c.blocks()]
    body: list = [c.new_ts] if c.new_ts else []
    offsets = []
    pos = (6 if c.crc is not None else 0) + len(c.new_ts)
    for it in c.items:
        if isinstance(it, _Block):
            if not it.keep:
                continue
            offsets.append((it, pos))
            a, b = it.start, it.end
        else:
            a, b = it
        body.append((a, b))
        pos += b - a
    body = _merge(body)
    if c.crc is not None:
        body.insert(0, b"\xbf\x84" + struct.pack("<I", _crc_of(buf, body)))
    if c.declared is None and not c.new_ts:
        size = E.encode_size(None, c.size_len)
    else:
        try:
            size = E.encode_size(pos, c.size_len or 8)
        except ValueError:
            size = E.encode_size(pos, 8)
    head = E.encode_id(CLUSTER) + size
    return [head] + body, len(head) + pos, offsets


def _seekhead(entries: list[tuple[int, int]], length: int | None, crc: bool) -> bytes | None:
    """A SeekHead listing ENTRIES [(id, position)], filling LENGTH bytes with a Void after it (None: as short
    as it is, positions written in 8 bytes). Entries at the end are left out when they don't fit."""
    for keep in range(len(entries), -1, -1):
        seeks = b"".join(E.element(SEEK, E.element(SEEK_ID, E.encode_id(i)) +
                                   E.element(SEEK_POSITION, E.encode_uint(p, 8 if length is None else 0)))
                         for i, p in entries[:keep])
        body = (b"\xbf\x84" + struct.pack("<I", zlib.crc32(seeks)) + seeks) if crc else seeks
        el = E.element(SEEKHEAD, body)
        if length is None or len(el) == length:
            return el
        if len(el) + 2 <= length:
            return el + E.void(length - len(el))
        if len(el) + 1 == length:
            return E.element(SEEKHEAD, body, E.size_length(len(body)) + 1)
    return None


def _cues(track: int, clusters: list[tuple[int, list[tuple[_Block, int]]]], per_cluster: bool) -> bytes:
    """Cues for TRACK: a CuePoint per key frame (PER_CLUSTER: for the first one of each Cluster)."""
    points = []
    for pos, offsets in clusters:
        for b, rel in offsets:
            if b.track != track or not b.key or not b.keep:
                continue
            tp = (E.uint_element(CUE_TRACK, track) + E.uint_element(CUE_CLUSTER_POSITION, pos) +
                  E.uint_element(CUE_RELATIVE_POSITION, rel))
            points.append(E.element(CUE_POINT, E.uint_element(CUE_TIME, max(0, b.time)) +
                                    E.element(CUE_TRACK_POSITIONS, tp)))
            if per_cluster:
                break
    return E.element(CUES, b"".join(points)) if points else b""


def _cues_valid(buf, el: Element, seg_data: int, starts: set[int]) -> bool:
    """Every Cue of EL points at a Cluster that is there (STARTS: where the kept Clusters start)."""
    n = 0
    for cp in E.children(buf, el.data, el.end):
        if cp.id != CUE_POINT or cp.size is None:
            continue
        for tp in E.children(buf, cp.data, cp.end):
            if tp.id == CUE_TRACK_POSITIONS and tp.size is not None:
                pos = E.uint(buf, E.child(buf, tp, CUE_CLUSTER_POSITION))
                if pos is None or seg_data + pos not in starts:
                    return False
                n += 1
    return n > 0


def _cue_map(buf, head: _Head, end: int) -> dict[int, tuple[int, int | None]]:
    """What the Cues the SeekHead points at say: {Cluster offset: (time of its first cued block, that block's
    offset in the Cluster's payload or None)}; {} when they aren't there."""
    seg_data = head.segment.data
    out: dict[int, tuple[int, int | None]] = {}
    for sh in (el for el in head.elements if el.id == SEEKHEAD):
        for s in E.children(buf, sh.data, sh.end):
            sid = E.child(buf, s, SEEK_ID) if s.id == SEEK and s.size is not None else None
            if sid is None or bytes(buf[sid.data:sid.end]) != E.encode_id(CUES):
                continue
            pos = E.uint(buf, E.child(buf, s, SEEK_POSITION))
            cues = element_at(buf, seg_data + pos, end) if pos is not None else None
            if cues is None or cues.id != CUES or cues.size is None or cues.end > end:
                continue
            for cp in E.children(buf, cues.data, cues.end):
                if cp.id != CUE_POINT or cp.size is None:
                    continue
                time = E.uint(buf, E.child(buf, cp, CUE_TIME))
                tp = E.child(buf, cp, CUE_TRACK_POSITIONS)
                cpos = E.uint(buf, E.child(buf, tp, CUE_CLUSTER_POSITION)) if tp is not None else None
                if time is not None and cpos is not None:
                    out.setdefault(seg_data + cpos, (time, E.uint(buf, E.child(buf, tp, CUE_RELATIVE_POSITION))))
    return out


def _seeks_valid(buf, el: Element, seg_data: int, end: int) -> bool:
    """Every entry of the SeekHead EL points at an intact part of its kind."""
    for s in E.children(buf, el.data, el.end):
        if s.id != SEEK or s.size is None:
            continue
        sid = E.child(buf, s, SEEK_ID)
        pos = E.uint(buf, E.child(buf, s, SEEK_POSITION))
        if sid is None or pos is None:
            return False
        target = element_at(buf, seg_data + pos, end)
        if target is None or E.encode_id(target.id) != bytes(buf[sid.data:sid.end]) or \
                (target.size is not None and target.end > end):
            return False
    return True


def _reference_head(reference) -> tuple[_Head | None, str]:
    """The reference video's head (a copy of everything before its first Cluster), or None and why not."""
    try:
        with open(reference, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                h = _parse_head(m, len(m))
                if h is None or h.first_cluster is None or not h.tracks:
                    return None, "it isn't a readable Matroska / WebM video"
                if h.first_cluster > _MAX_HEAD:
                    return None, "its start is too large"
                data = bytes(m[:h.first_cluster])
    except (OSError, ValueError) as exc:
        return None, getattr(exc, "strerror", None) or str(exc)
    head = _parse_head(data, len(data))
    if head is None:
        return None, "it isn't a readable Matroska / WebM video"
    head.first_cluster = len(data)
    return head, ""


def _plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def _track_ends(w: _Walk, tracks: dict[int, Track], scale: int) -> dict[int, int]:
    """Each track's end in ticks: its last block's time plus that block's duration (BlockDuration, the track's
    DefaultDuration, or the usual gap between its blocks)."""
    last: dict[int, _Block] = {}
    times: dict[int, list[int]] = {}
    for b in w.blocks:
        if b.keep:
            if b.track not in last or b.time >= last[b.track].time:
                last[b.track] = b
            times.setdefault(b.track, []).append(b.time)
    ends = {}
    for n, b in last.items():
        tr = tracks.get(n)
        dur = b.dur or (round(tr.default_duration / scale) if tr and tr.default_duration else 0)
        if not dur:
            t = sorted(times[n][-48:])
            g = sorted(y - x for x, y in zip(t, t[1:]) if y > x)
            dur = g[len(g) // 2] if g else 0
        ends[n] = b.time + dur
    return ends


# ---------------------------------------------------------------------- the handler
def plan_mkv(buf, path="", reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    """Check a Matroska / WebM file and plan its repair (see the module docstring)."""
    end = len(buf)
    head = _parse_head(buf, end)
    ext = str(path).lower().rsplit(".", 1)[-1] if "." in str(path) else ""
    t = "webm" if head is not None and head.doctype == "webm" and ext not in ("weba",) else ext
    plan = Plan(t if t in ("mkv", "webm", "mka", "mk3d", "weba") else "mkv")
    if end < 16:
        plan.problem("The file is too short to be a video" if end else "The file is empty")
        plan.note = "There is nothing to repair."
        return plan
    from_reference = False
    extra_tracks: set[int] = set()
    if head is None or not head.tracks or (head.first_cluster is None and head.damaged_at is not None and
                                           head.damaged_at >= end - 12):
        what = ("The start of the file (the EBML header) is missing or overwritten" if head is None else
                "The file ends before its first cluster" if head.damaged_at is not None and head.damaged_at >= end - 12
                else "The start of the file (the track list) is damaged")
        if reference is None:
            plan.problem(what)
            plan.note = ("The start of the file is overwritten and no reference was given: the track list and the "
                         "codec settings were there. Repair it with a reference video recorded with the same "
                         "camera or program and the same settings.")
            return plan
        ref, why = _reference_head(reference)
        if ref is None:
            plan.problem(what)
            plan.note = f"The reference video can't be used: {why}."
            return plan
        # which tracks the surviving Clusters hold (a walk that takes any track number)
        probe_walk = _Walk(buf, end, {}, NULL_CONTROL)
        found: set[int] = set()
        q = probe_walk.find_cluster(max(0, min(end, int(data_offset or 0))), min(end, 256 * 1024 * 1024))
        for _ in range(8):
            if q is None:
                break
            el = element_at(buf, q, end)
            blocks, _p = probe_walk.chain(next((c.start for c in E.children(buf, el.data, el.end or end)
                                                if c.id in (SIMPLEBLOCK, BLOCKGROUP)), q), el.end or end)
            found |= {b.track for b in blocks}
            q = probe_walk.find_cluster(q + 4, min(end, q + 64 * 1024 * 1024))
        if found and not found & set(ref.tracks):
            plan.problem(what)
            plan.problem("The reference video's tracks don't match the ones in this file")
            plan.note = ("The tracks of the reference video (" + ", ".join(map(str, sorted(ref.tracks))) + ") aren't "
                         "the ones in this file (" + ", ".join(map(str, sorted(found))) + "): use a reference "
                         "recorded with the same camera or program and the same settings.")
            return plan
        plan.problem(what, "Put the reference video's header and track list in front of what survived")
        head, from_reference = ref, True
        extra_tracks = found - set(ref.tracks)
        if extra_tracks:
            plan.note = ("Some tracks of this file aren't in the reference video (" +
                         ", ".join(map(str, sorted(found - set(ref.tracks)))) + "): they are left out. ")
    hbuf, tracks, scale = head.buf, head.tracks, head.scale
    w = _Walk(buf, end, tracks, ctl, scale)
    if from_reference and extra_tracks:
        w.tracks = {**{n: Track(n) for n in extra_tracks}, **tracks}     # parsed, then left out
    if from_reference:
        start = max(0, min(end, int(data_offset or 0)))
        w.events.append(0)                                 # the video can only start at a key frame
        first = start if w.cluster_ok(start) else w.skip_damage(start, end)
        if w.damage and w.damage[0][0] == start:
            plan.info["skipped_bytes"] = w.damage[0][1] - start
            del w.damage[0]
        if first is not None:
            w.walk(first, end)
        seg_data_in = None
    else:
        seg = head.segment
        seg_data_in = seg.data
        seg_stop = min(seg.end, end) if seg.size is not None else end
        if seg.size is not None and seg.end < end:
            nxt = element_at(buf, seg.end, end)
            if nxt is not None and nxt.id in (CLUSTER, CUES, TAGS) and (nxt.id != CLUSTER or w.cluster_ok(seg.end)):
                seg_stop = end                                 # its size is too small: more of it follows
        w.cue_map = _cue_map(buf, head, end)
        w.cue_starts = sorted(w.cue_map)
        # a part of the head after the track list may be damaged: the walk picks up at the first Cluster
        w.walk(next((x for x in (head.first_cluster, head.damaged_at) if x is not None), end), seg_stop)
        if w.trailing_from is None and w.cut_at is None and seg_stop < end:
            w.trailing_from = seg_stop
    clusters = [c for c in w.items if isinstance(c, _Cluster)]
    if not w.blocks:
        plan.problem("No readable frames were found in the file")
        plan.note = "The video data is missing or damaged everywhere."
        return plan
    if from_reference and extra_tracks:
        for b in w.blocks:
            b.keep = b.keep and b.track in tracks
    dropped_frames = w.drop_until_key() if w.events else 0
    ends_ticks = _track_ends(w, tracks, scale)
    end_ticks = max(ends_ticks.values(), default=0)
    first_ticks = min((b.time for b in w.blocks if b.keep), default=0)
    duration = end_ticks * scale / 1e9
    kept = sum(1 for b in w.blocks if b.keep)
    plan.info.update(duration=round(duration, 3), tracks=[tr.describe() for tr in tracks.values()],
                     clusters=len(clusters), frames=kept, doctype=head.doctype)
    if dropped_frames:
        plan.info["frames_dropped"] = dropped_frames
    if w.orphans:
        plan.info["frames_regrouped"] = w.orphans

    # ---- the problems
    if w.cut_at is not None:
        missing = ""
        if not from_reference and head.segment.size is not None and head.segment.end > end:
            missing = f"the last {_n(head.segment.end - end)} are missing, "
        where = "in the middle of a cluster" if w.cut_in == "cluster" else "inside its last part"
        plan.problem(f"The file is cut short: {missing}it ends {where}", "Cut the video after its last complete frame")
    if w.damage:
        lost = sum(b - a for a, b in w.damage)
        plan.problem(f"{_plural(len(w.damage), 'damaged stretch', 'damaged stretches')} in the video ({_n(lost)})",
                     "Drop the damaged stretches (the picture skips to the next key frame there)")
        plan.info["damaged_bytes"] = lost
    if w.trailing_from is not None:
        trailing = end - w.trailing_from
        plan.problem(f"{_n(trailing)} of other data come after the end of the video",
                     f"Cut the {_n(trailing)} at the end")
    if not from_reference and head.segment.size is not None and w.cut_at is None and \
            head.segment.end != (w.trailing_from if w.trailing_from is not None else end):
        plan.problem("The size of the Segment is wrong", "Correct the Segment size")
    if not (w.cut_at is not None or w.damage) and any(c.changed for c in clusters):
        plan.problem("The size of a cluster is wrong", "Correct the cluster sizes")
    moved = bool(w.damage or w.cut_at is not None or from_reference or any(c.changed for c in clusters))
    kept_starts = {c.start for c in clusters if c.start >= 0}
    old_cues = None if from_reference else next(
        (el for el in list(head.elements) + w.items if isinstance(el, Element) and el.id == CUES), None)
    video = next((n for n, tr in tracks.items() if tr.kind == 1), None)
    cue_track = video if video is not None else (min(tracks) if tracks else None)
    seg_data = seg_data_in if seg_data_in is not None else 0
    cues_ok = old_cues is not None and _cues_valid(buf, old_cues, seg_data, kept_starts)
    if old_cues is None and not from_reference and cue_track is not None and len(clusters) > 1:
        plan.problem("The seeking index (Cues) is missing", "Rebuild the seeking index from the key frames")
    elif old_cues is not None and not cues_ok:
        plan.problem("The seeking index (Cues) points at parts that are missing",
                     "Rebuild the seeking index from the key frames")
    seekheads = [el for el in head.elements if el.id == SEEKHEAD]
    if not from_reference and seekheads and not moved and not _seeks_valid(buf, seekheads[0], seg_data, end):
        plan.problem("The list of the file's parts (SeekHead) points at parts that aren't there",
                     "Rewrite the list of the file's parts")
    if head.duration is None:
        plan.problem("The duration is missing (the recording wasn't finished)", f"Set the duration ({duration:.1f} s)")
    elif not from_reference and abs(head.duration - duration) > max(1.0, 0.02 * duration):
        plan.problem(f"The duration is wrong ({head.duration:.1f} s instead of {duration:.1f} s)",
                     f"Set the duration ({duration:.1f} s)")
    bad_crc = 0
    for c in clusters:
        if c.crc is not None and not c.changed and c.start >= 0:
            if struct.unpack("<I", bytes(buf[c.crc.data:c.crc.end]))[0] != _crc_of(buf, [(c.crc.end, c.stop)]):
                bad_crc += 1
            ctl.check()
    if bad_crc:
        plan.problem(f"The checksums of {_plural(bad_crc, 'cluster')} don't match: the pictures or sound inside "
                     f"{'it are' if bad_crc == 1 else 'them are'} damaged (they play with glitches there)")
        plan.info["damaged_clusters"] = bad_crc
    if from_reference and first_ticks > 0:
        plan.note += (f"The first {first_ticks * scale / 1e9:.1f} s of the recording were lost: the video starts "
                      "late (players show its first picture until then).")
    structural = [p for p in plan.problems if not p.startswith("The checksums")]
    if not structural:
        if bad_crc:
            plan.note = "RecoverAll can't restore damaged pictures or sound."
        return plan
    if moved or not cues_ok:
        for action in (["Rebuild the seeking index from the key frames"] if cue_track is not None else []) + \
                [f"Set the duration ({duration:.1f} s)"]:
            if action not in plan.actions:
                plan.actions.append(action)

    # ---- the copy
    uids = {tr.uid: n for n, tr in tracks.items() if tr.uid}
    ends_ns = {n: round(v * scale) for n, v in ends_ticks.items()}

    def head_piece(a: int, b: int):
        return (a, b) if hbuf is buf else bytes(hbuf[a:b])

    def patched_tags(src, el: Element) -> tuple[list, int]:
        p = _tag_patches(src, el, ends_ns, uids)
        if not p:
            return ([head_piece(el.start, el.end)] if src is hbuf else [(el.start, el.end)]), el.end - el.start
        data = _patch_element(src, el, p)
        return [data], len(data)

    def build() -> list:
        parts: list[list] = []            # [id, pieces, length]
        elements = list(head.elements)
        region, crc_in_seekhead, i = 0, False, 0
        while i < len(elements) and (elements[i].id == VOID or
                                      (elements[i].id == SEEKHEAD and not any(e.id == SEEKHEAD for e in elements[:i]))):
            el = elements[i]
            if el.id == SEEKHEAD:
                first_child = element_at(hbuf, el.data, el.end)
                crc_in_seekhead = first_child is not None and first_child.id == CRC32
            region += el.end - el.start
            i += 1
        parts.append([SEEKHEAD, None, region or None])
        for el in elements[i:]:
            if el.id == INFO:
                patches: dict[int, bytes] = {}
                append = b""
                dur_el = E.child(hbuf, el, DURATION)
                if dur_el is not None and dur_el.size in (4, 8):
                    patches[dur_el.data] = struct.pack(">d" if dur_el.size == 8 else ">f", float(end_ticks))
                else:
                    v11 = next((c for c in E.children(hbuf, el.data, el.end)
                                if c.id == VOID and c.end - c.start == 11), None)
                    if v11 is not None:
                        patches[v11.start] = E.float_element(DURATION, float(end_ticks))
                    else:
                        append = E.float_element(DURATION, float(end_ticks))
                data = _patch_element(hbuf, el, patches, append)
                parts.append([INFO, [data], len(data)])
            elif el.id == TAGS:
                parts.append([TAGS, *patched_tags(hbuf, el)])
            elif el.id in (CUES, SEEKHEAD):                  # Cues at the front are rewritten at the end
                parts.append([VOID, [E.void(el.end - el.start)], el.end - el.start])
            else:
                parts.append([el.id, [head_piece(el.start, el.end)], el.end - el.start])
        clusters_at: list[tuple[int, list]] = []          # (index into parts, block offsets)
        for it in w.items:
            if isinstance(it, _Cluster):
                if any(b.keep for b in it.blocks()):
                    pieces, length, offsets = _cluster_pieces(buf, it)
                    clusters_at.append((len(parts), offsets))
                    parts.append([CLUSTER, pieces, length, it.start])
            elif it.id in (CUES, SEEKHEAD, VOID, CRC32):
                continue
            elif it.id == TAGS:
                parts.append([TAGS, *patched_tags(buf, it)])
            else:
                parts.append([it.id, [(it.start, it.end)], it.end - it.start])
        cues_at = (clusters_at[-1][0] + 1) if clusters_at else len(parts)
        parts.insert(cues_at, [CUES, None, 0])
        clusters_at = [(k + (k >= cues_at), o) for k, o in clusters_at]
        if parts[0][2] is None:
            n_entries = len({p[0] for p in parts if p[0] in _SEEK_ORDER})
            parts[0][2] = len(_seekhead([(INFO, 0)] * n_entries, None, False))
        # lay the parts out (offsets from the start of the Segment's data); Cues come after the Clusters
        offsets: list[int] = []
        pos = 0
        for k, part in enumerate(parts):
            offsets.append(pos)
            if part[0] == CUES and part[1] is None:
                same = all(p[3] - seg_data == offsets[j] for j, p in enumerate(parts[:k]) if p[0] == CLUSTER) \
                    if seg_data_in is not None else False
                if cues_ok and same and old_cues is not None:
                    part[1] = [(old_cues.start, old_cues.end)]
                    part[2] = old_cues.end - old_cues.start
                elif cue_track is not None:
                    per_cluster = tracks[cue_track].kind != 1
                    data = _cues(cue_track, [(offsets[j], o) for j, o in clusters_at], per_cluster)
                    part[1], part[2] = [data], len(data)
                else:
                    part[1] = []
            pos += part[2]
        entries = []
        for eid in _SEEK_ORDER:
            k = next((k for k, p in enumerate(parts) if p[0] == eid and p[2]), None)
            if k is not None:
                entries.append((eid, offsets[k]))
        sh = _seekhead(entries, region or None, crc_in_seekhead)
        parts[0][1] = [sh if sh is not None else (E.void(region) if region >= 2 else b"")]
        out: list = [head_piece(head.ebml.start, head.ebml.end)]
        if head.segment.start > head.ebml.end:
            out.append(head_piece(head.ebml.end, head.segment.start))
        size_len = head.segment.header - head.seg_id_len
        if head.segment.size is None and not from_reference:
            seg_size = E.encode_size(None, size_len)
        else:
            try:
                seg_size = E.encode_size(pos, size_len)
            except ValueError:
                seg_size = E.encode_size(None, size_len)
        out.append(E.encode_id(SEGMENT) + seg_size)
        for part in parts:
            out.extend(part[1])
        return _merge(out)

    plan.repairable = True
    plan.build = build
    return plan
