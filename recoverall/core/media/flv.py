"""Flash video (FLV, and F4V files written as FLV): checking the file and repairing it.

An FLV file is a 9-byte header ("FLV", version 1, flags: 4 = has sound, 1 = has video, the header's size),
then a 4-byte zero, then tags one after the other, each followed by its own size (PreviousTagSize, 11 + the
data size): a tag is its type (8 sound, 9 video, 18 script data), the data size (24 bits), the timestamp in
milliseconds (24 bits plus 8 high bits), a stream id that is always 0, and the data. The first tag is usually
the script tag "onMetaData", an AMF0 list of values: duration, filesize, width, height, codec ids... H.264 and
AAC need their settings before the first frame: a video tag with AVCPacketType 0 (the decoder configuration)
and a sound tag with AACPacketType 0.

What is checked, and repaired in a new copy:

=====================  ==========================================================================================
cut short              cut after the last complete tag.
damage in the middle   the walk picks up again at the next place where a tag header is plausible and the
                       PreviousTagSize after it matches; the damaged stretch is dropped, and the video up to its
                       next key frame (it can't be decoded without the frames that were lost).
other data at the end  cut.
onMetaData             a wrong duration or file size (or none: the recording wasn't finished) is corrected:
                       the AMF0 numbers keep their length, so they are overwritten in place.
the start lost         a new header; H.264/AAC settings and onMetaData come from a REFERENCE video (made by the
                       same camera or program with the same settings) when the file lost its own.
=====================  ==========================================================================================
"""

from __future__ import annotations

import bisect
import re
import struct

from ..filerepair import Plan, _merge, _n
from ..fs.base import NULL_CONTROL, Control

AUDIO, VIDEO, SCRIPT = 8, 9, 18
_TAG = re.compile(rb"(?=[\x08\x09\x12][\s\S]{7}\x00\x00\x00)")
_MAX_TAG = 16 * 1024 * 1024
_VIDEO_CODECS = {2: "Sorenson H.263", 3: "Screen video", 4: "VP6", 5: "VP6 alpha", 6: "Screen video 2", 7: "H.264",
                 12: "H.265"}
_AUDIO_CODECS = {0: "PCM", 1: "ADPCM", 2: "MP3", 3: "PCM", 4: "Nellymoser", 5: "Nellymoser", 6: "Nellymoser",
                 7: "G.711", 8: "G.711", 10: "AAC", 11: "Speex", 14: "MP3", 15: "device-specific"}


def detect_flv(head: bytes) -> bool:
    """True when HEAD starts with an FLV header."""
    return bytes(head[:4]) == b"FLV\x01"


def _be24(b, o: int) -> int:
    return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]


def _tag_at(buf, p: int, end: int) -> tuple[int, int, int] | None:
    """(type, data size, timestamp) of a plausible tag header at P (its PreviousTagSize is not checked)."""
    if p + 11 > end:
        return None
    t = buf[p]
    if t not in (AUDIO, VIDEO, SCRIPT) or buf[p + 8] or buf[p + 9] or buf[p + 10]:
        return None
    size = _be24(buf, p + 1)
    if size == 0 and t != VIDEO or size > _MAX_TAG:
        return None
    return t, size, _be24(buf, p + 4) | (buf[p + 7] << 24)


def _complete(buf, p: int, end: int) -> tuple[int, int, int] | None:
    """The tag at P when its header is plausible and the PreviousTagSize after it matches."""
    tag = _tag_at(buf, p, end)
    if tag is None or p + 15 + tag[1] > end:
        return None
    return tag if struct.unpack_from(">I", buf, p + 11 + tag[1])[0] == 11 + tag[1] else None


def _is_config(buf, p: int, tag: tuple[int, int, int]) -> bool:
    """A tag with codec settings: the H.264/H.265 decoder configuration, the AAC AudioSpecificConfig."""
    t, size, _ts = tag
    if size < 2:
        return False
    first = buf[p + 11]
    if t == VIDEO:
        return (first & 0x0F) in (7, 12) and buf[p + 12] == 0
    return t == AUDIO and first >> 4 == 10 and buf[p + 12] == 0


def _is_key(buf, p: int, tag: tuple[int, int, int]) -> bool:
    return tag[0] == VIDEO and tag[1] > 0 and buf[p + 11] >> 4 in (1, 5)


# ---------------------------------------------------------------------- AMF0
def _amf_skip(b: bytes, p: int, depth: int = 0) -> int:
    """The offset just after the AMF0 value at P (ValueError when it doesn't parse)."""
    if p >= len(b) or depth > 32:
        raise ValueError("AMF0 value past the end")
    t = b[p]
    p += 1
    if t == 0:
        return p + 8
    if t == 1:
        return p + 1
    if t in (2, 4):                     # string, movie clip
        return p + 2 + struct.unpack_from(">H", b, p)[0]
    if t in (3, 8, 16):                 # object, ECMA array, typed object
        if t == 8:
            p += 4
        elif t == 16:
            p += 2 + struct.unpack_from(">H", b, p)[0]
        for _ in range(100000):
            n = struct.unpack_from(">H", b, p)[0]
            if n == 0 and b[p + 2] == 9:
                return p + 3
            p = _amf_skip(b, p + 2 + n, depth + 1)
        raise ValueError("AMF0 object too long")
    if t in (5, 6, 13):                 # null, undefined, unsupported
        return p
    if t == 7:                          # reference
        return p + 2
    if t == 10:                         # strict array
        count = struct.unpack_from(">I", b, p)[0]
        p += 4
        for _ in range(min(count, 1000000)):
            p = _amf_skip(b, p, depth + 1)
        return p
    if t == 11:                         # date
        return p + 10
    if t in (12, 15):                   # long string, XML
        return p + 4 + struct.unpack_from(">I", b, p)[0]
    raise ValueError(f"AMF0 type {t}")


def metadata(blob: bytes) -> dict[str, tuple[int, float]] | None:
    """The numbers of an onMetaData script tag's data BLOB: {name: (offset of the 8-byte double, value)};
    None when BLOB isn't onMetaData."""
    try:
        if blob[:13] != b"\x02\x00\x0aonMetaData":
            return None
        p = 13
        t = blob[p]
        if t not in (3, 8):
            return None
        p += 5 if t == 8 else 1
        out: dict[str, tuple[int, float]] = {}
        for _ in range(10000):
            n = struct.unpack_from(">H", blob, p)[0]
            if n == 0 and blob[p + 2] == 9:
                break
            name = blob[p + 2:p + 2 + n].decode("utf-8", "replace")
            p += 2 + n
            if blob[p] == 0 and p + 9 <= len(blob):
                out[name] = (p + 1, struct.unpack_from(">d", blob, p + 1)[0])
            p = _amf_skip(blob, p)
        return out
    except (ValueError, IndexError, struct.error):
        return None


def keyframe_index(blob: bytes) -> tuple[list[int], list[int]] | None:
    """The key frame index some writers put in onMetaData ("keyframes": "filepositions" and "times"): the
    offsets in BLOB of the 8-byte doubles of each array; None when there is none."""
    try:
        at = blob.find(b"\x00\x09keyframes\x03", 13)
        if at < 0:
            return None
        p = at + 12
        arrays: dict[str, list[int]] = {}
        for _ in range(64):
            n = struct.unpack_from(">H", blob, p)[0]
            if n == 0 and blob[p + 2] == 9:
                break
            name = blob[p + 2:p + 2 + n].decode("latin-1")
            p += 2 + n
            if blob[p] == 10:
                count = struct.unpack_from(">I", blob, p + 1)[0]
                q, offsets = p + 5, []
                for _ in range(min(count, 1000000)):
                    if blob[q] != 0:
                        break
                    offsets.append(q + 1)
                    q += 9
                arrays[name] = offsets
            p = _amf_skip(blob, p)
        pos, times = arrays.get("filepositions"), arrays.get("times")
        return (pos, times) if pos is not None and times is not None and len(pos) == len(times) else None
    except (ValueError, IndexError, struct.error):
        return None


# ---------------------------------------------------------------------- walking the tags
class _Walk:
    def __init__(self, buf, end: int, ctl: Control):
        self.buf, self.end, self.ctl = buf, end, ctl
        self.tags: list[list] = []        # [start, end (incl. PreviousTagSize), type, timestamp, keep, key, config]
        self.damage: list[tuple[int, int]] = []
        self.events: list[int] = []       # indexes into tags where a damaged stretch was dropped
        self.cut_at: int | None = None
        self.trailing_from: int | None = None
        self.last_ts = -1
        self.missing_prev = False         # the file ends just after a tag, without its PreviousTagSize

    def resync(self, pos: int) -> int | None:
        """The next offset from POS where a complete tag starts that is followed by another (or the end), its
        time not going back."""
        buf, end = self.buf, self.end
        for n, m in enumerate(_TAG.finditer(buf, pos, end)):
            q = m.start()
            tag = _complete(buf, q, end)
            if tag is not None and (self.last_ts < 0 or self.last_ts - 1000 <= tag[2] <= self.last_ts + 600000):
                nxt = q + 15 + tag[1]
                if nxt >= end - 4 or _tag_at(buf, nxt, end) is not None:
                    return q
            if n % 4096 == 0:
                self.ctl.check()
        return None

    def walk(self, pos: int) -> None:
        buf, end = self.buf, self.end
        for n in range(100_000_000):
            if pos >= end:
                return
            if n % 4096 == 0:
                self.ctl.check()
                self.ctl.progress(pos / max(1, end), "Checking the tags")
            tag = _tag_at(buf, pos, end)
            if tag is not None and pos + 11 + tag[1] > end - 4:
                if pos + 11 + tag[1] <= end and pos + 11 + tag[1] + 4 > end:
                    self.missing_prev = True                 # only the last PreviousTagSize is cut off
                    self._add(pos, pos + 11 + tag[1], tag)
                    if pos + 11 + tag[1] < end:
                        self.cut_at = pos + 11 + tag[1]
                    return
                if self.resync(pos + 1) is None:
                    self.cut_at = pos                        # the file ends inside this tag
                    return
            elif tag is None and end - pos < 11 and not any(buf[pos:end]):
                self.trailing_from = pos
                return
            elif tag is None and end - pos < 11:
                self.cut_at = pos
                return
            if tag is not None and _complete(buf, pos, end) is not None:
                nxt = pos + 15 + tag[1]
                if tag[0] != SCRIPT and self.last_ts >= 0 and not self.last_ts - 5000 <= tag[2] <= self.last_ts + 10000 \
                        and self._old_timeline(nxt):
                    self.damage.append((pos, nxt))           # its time stamp is damaged
                    self.events.append(len(self.tags))
                    pos = nxt
                    continue
                self._add(pos, nxt, tag)
                pos = nxt
                continue
            # damaged here: the tag before may be damaged at its end too when this one is garbage
            start = pos
            q = self.resync(pos + 1)
            if q is None:
                self.trailing_from = start
                return
            self.damage.append((start, q))
            self.events.append(len(self.tags))
            pos = q

    def _old_timeline(self, pos: int) -> bool:
        """The media tags from POS go on near the time before (so a tag that jumped away is damaged)."""
        for _ in range(4):
            tag = _complete(self.buf, pos, self.end)
            if tag is None:
                return False
            if tag[0] != SCRIPT:
                return abs(tag[2] - self.last_ts) <= 10000
            pos += 15 + tag[1]
        return False

    def _add(self, a: int, b: int, tag: tuple[int, int, int]) -> None:
        self.tags.append([a, b, tag[0], tag[2], True, _is_key(self.buf, a, tag), _is_config(self.buf, a, tag)])
        if tag[0] != SCRIPT:
            self.last_ts = max(self.last_ts, tag[2])

    def drop_until_key(self) -> int:
        """After each damaged stretch, drop the video up to its next key frame. Returns how many tags."""
        if not any(t[2] == VIDEO and t[5] for t in self.tags) or all(t[5] for t in self.tags if t[2] == VIDEO):
            return 0
        dropped = 0
        for e in self.events:
            for t in self.tags[e:]:
                if t[2] != VIDEO or t[6]:
                    continue
                if t[5]:
                    break
                if t[4]:
                    t[4] = False
                    dropped += 1
        return dropped


def _codecs(buf, tags: list) -> tuple[int | None, int | None]:
    """The video codec id and the sound format of the first media tags."""
    v = a = None
    for t in tags[:400]:
        if t[1] - t[0] <= 15:
            continue
        if t[2] == VIDEO and v is None:
            v = buf[t[0] + 11] & 0x0F
        elif t[2] == AUDIO and a is None:
            a = buf[t[0] + 11] >> 4
    return v, a


def _duration(tags: list) -> float:
    """Seconds: the last media tag's time plus the usual step between tags of its kind."""
    best = 0.0
    for kind in (VIDEO, AUDIO):
        times = sorted(t[3] for t in tags if t[2] == kind and t[4])
        if not times:
            continue
        steps = sorted(y - x for x, y in zip(times[-64:], times[-63:]) if y > x)
        best = max(best, (times[-1] + (steps[len(steps) // 2] if steps else 0)) / 1000)
    return best


def _reference(reference) -> tuple[bytes, bytes | None, list[bytes], str]:
    """The reference video's header (with its first PreviousTagSize), its onMetaData tag and its codec settings
    tags (each with its PreviousTagSize, time set to 0); "" or why it can't be used."""
    try:
        with open(reference, "rb") as f:
            data = f.read(64 * 1024 * 1024)
    except OSError as exc:
        return b"", None, [], exc.strerror or str(exc)
    if not detect_flv(data) or len(data) < 13:
        return b"", None, [], "it isn't an FLV video"
    hsize = struct.unpack_from(">I", data, 5)[0]
    if not 9 <= hsize <= 64:
        return b"", None, [], "its header is damaged"
    header = data[:9] + b"\x00\x00\x00\x00"
    pos, meta, config = hsize + 4, None, []
    for _ in range(1000):
        tag = _complete(data, pos, len(data))
        if tag is None:
            break
        unit = data[pos:pos + 15 + tag[1]]
        if tag[0] == SCRIPT and meta is None and metadata(unit[11:11 + tag[1]]) is not None:
            meta = unit
        elif _is_config(data, pos, tag) and not any(c[0] == unit[0] for c in config):
            config.append(unit[:4] + b"\x00\x00\x00\x00" + unit[8:])
        pos += 15 + tag[1]
    return header, meta, config, ""


def plan_flv(buf, path="", reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    """Check an FLV file and plan its repair (see the module docstring)."""
    plan = Plan("flv")
    end = len(buf)
    header_ok = end >= 13 and detect_flv(buf) and 9 <= struct.unpack_from(">I", buf, 5)[0] <= 64 and \
        not buf[4] & 0xFA
    w = _Walk(buf, end, ctl)
    if header_ok:
        data_start = struct.unpack_from(">I", buf, 5)[0] + 4
        w.walk(data_start)
    else:
        start = max(0, min(end, int(data_offset or 0)))
        first = start if _complete(buf, start, end) else w.resync(start)
        if first is None:
            plan.problem("No FLV header and no intact tags were found")
            plan.note = "The video data is missing or damaged everywhere."
            return plan
        plan.info["skipped_bytes"] = first - start
        w.events.append(0)
        w.walk(first)
    media = [t for t in w.tags if t[2] != SCRIPT]
    if not media:
        plan.problem("No video or sound tags were found" if header_ok else "No FLV header and no intact tags were found")
        plan.note = "The video data is missing or damaged everywhere."
        return plan
    dropped = w.drop_until_key() if w.events else 0
    vcodec, acodec = _codecs(buf, w.tags)
    duration = _duration(w.tags)
    first_ts = min(t[3] for t in media)
    plan.info.update(duration=round(duration, 3), tags=sum(1 for t in w.tags if t[4]),
                     video=_VIDEO_CODECS.get(vcodec, str(vcodec)) if vcodec is not None else None,
                     sound=_AUDIO_CODECS.get(acodec, str(acodec)) if acodec is not None else None)
    if dropped:
        plan.info["frames_dropped"] = dropped

    # ---- the start
    head: list = []
    meta_src = None                       # (buffer, tag start, tag data size) of the onMetaData tag to patch
    ref_config: list[bytes] = []
    has_config = {buf[t[0]] for t in w.tags if t[6]}
    needs = {VIDEO} if vcodec in (7, 12) else set()
    needs |= {AUDIO} if acodec == 10 else set()
    if header_ok:
        head = [(0, data_start)]
    else:
        missing = needs - has_config
        plan.problem("The start of the file (the FLV header) is missing or overwritten",
                     "Write a new FLV header" if reference is None else
                     "Put the reference video's header and settings in front of what survived")
        if reference is not None:
            rhead, rmeta, rconfig, why = _reference(reference)
            if why:
                plan.note = f"The reference video can't be used: {why}."
                return plan
            head = [rhead]
            if rmeta is not None:
                meta_src = (rmeta, 0, len(rmeta) - 15)
            ref_config = [c for c in rconfig if c[0] in missing]
            if missing - {c[0] for c in ref_config}:
                plan.note = "The reference video has no settings for this file's codecs. "
                return plan
        elif missing:
            what = " and ".join(("the H.264 settings" if vcodec == 7 else "the H.265 settings") if k == VIDEO
                                else "the AAC settings" for k in sorted(missing, reverse=True))
            plan.note = (f"The start of the file is overwritten and no reference was given: {what} were there. "
                         "Repair it with a reference video made by the same camera or program with the same "
                         "settings.")
            return plan
        if not head:
            flags = (4 if any(t[2] == AUDIO for t in w.tags) else 0) | (1 if any(t[2] == VIDEO for t in w.tags) else 0)
            head = [b"FLV\x01" + bytes([flags]) + struct.pack(">I", 9) + b"\x00\x00\x00\x00"]
        if first_ts > 0:
            plan.note += (f"The first {first_ts / 1000:.1f} s of the recording were lost: the video starts late "
                          "(players show its first picture until then).")
    if meta_src is None:
        for t in w.tags[:8]:
            if t[2] == SCRIPT and metadata(bytes(buf[t[0] + 11:t[1] - 4])) is not None:
                meta_src = (buf, t[0], t[1] - t[0] - 15)
                break

    # ---- the problems
    if w.cut_at is not None:
        plan.problem("The file is cut short: it ends in the middle of a tag", "Cut the video after its last complete tag")
    elif w.missing_prev:
        plan.problem("The file is cut short just after its last tag", "Add the last tag's size")
    if w.damage:
        lost = sum(b - a for a, b in w.damage)
        k = len(w.damage)
        plan.problem(f"{k} damaged stretch{'es' if k > 1 else ''} in the video ({_n(lost)})",
                     "Drop the damaged stretches (the picture skips to the next key frame there)")
        plan.info["damaged_bytes"] = lost
    if w.trailing_from is not None:
        n = end - w.trailing_from
        plan.problem(f"{_n(n)} of other data come after the end of the video", f"Cut the {_n(n)} at the end")
    values = None
    if meta_src is not None:
        src, at, size = meta_src
        values = metadata(bytes(src[at + 11:at + 11 + size]))
    if header_ok and values is not None:
        old = values.get("duration", (0, None))[1]
        if old is not None and old <= 0:
            plan.problem("The duration isn't recorded in the metadata (the recording wasn't finished)",
                         f"Set the duration ({duration:.1f} s)")
        elif old is not None and abs(old - duration) > max(1.0, 0.02 * duration) and not plan.problems:
            plan.problem(f"The duration in the metadata is wrong ({old:.1f} s instead of {duration:.1f} s)",
                         f"Set the duration ({duration:.1f} s)")
        size_now = values.get("filesize", (0, None))[1]
        if not plan.problems and size_now not in (None, 0.0, float(end)):
            plan.problem("The file size in the metadata is wrong", "Correct the file size in the metadata")
    if not plan.problems:
        return plan
    if values is not None:
        action = f"Set the duration ({duration:.1f} s) and the file size in the metadata"
        if not any(a.startswith("Set the duration") for a in plan.actions):
            plan.actions.append(action)

    # ---- the copy
    kept = [t for t in w.tags if t[4]]
    pieces: list = list(head) + ref_config + [(t[0], t[1]) for t in kept]
    if w.missing_prev and kept:
        pieces.append(struct.pack(">I", kept[-1][1] - kept[-1][0]))
    meta_from_reference = meta_src is not None and meta_src[0] is not buf
    if meta_from_reference:
        pieces.insert(1, meta_src[0])
    out_size = sum(p[1] - p[0] if isinstance(p, tuple) else len(p) for p in pieces)
    patches: dict[int, bytes] = {}
    if values is not None:
        src, at, size = meta_src
        want = {"duration": round(duration, 3), "filesize": float(out_size)}
        if "lasttimestamp" in values:
            want["lasttimestamp"] = max(t[3] for t in kept if t[2] != SCRIPT) / 1000
        for name, value in want.items():
            if name in values:
                patches[at + 11 + values[name][0]] = struct.pack(">d", value)
        # the key frame index: each entry points at the kept key frame at or after its time
        blob = bytes(src[at + 11:at + 11 + size])
        index = keyframe_index(blob)
        if index is not None:
            out_at: dict[int, int] = {}
            pos = 0
            for p in pieces:
                if isinstance(p, tuple):
                    out_at[p[0]] = pos
                pos += p[1] - p[0] if isinstance(p, tuple) else len(p)
            keys = sorted((t[3], out_at[t[0]]) for t in kept if t[5] and not t[6] and t[0] in out_at)
            times = [k[0] for k in keys]
            if keys:
                for po, to in zip(*index):
                    when = struct.unpack_from(">d", blob, to)[0] * 1000
                    ts, where = keys[min(len(keys) - 1, bisect.bisect_left(times, when - 1))]
                    patches[at + 11 + po] = struct.pack(">d", float(where))
                    patches[at + 11 + to] = struct.pack(">d", ts / 1000)
        if meta_from_reference:
            blob = bytearray(src)
            for o, v in patches.items():
                blob[o:o + 8] = v
            pieces[1] = bytes(blob)
            patches = {}
    final: list = []
    for p in pieces:
        final.extend(_split(p, patches) if isinstance(p, tuple) and patches else [p])
    final = _merge(final)
    plan.repairable = True
    plan.build = lambda: final
    return plan


def _split(rng: tuple[int, int], patches: dict[int, bytes]) -> list:
    a, b = rng
    out: list = []
    for off in sorted(patches):
        if a <= off and off + len(patches[off]) <= b:
            out += [(a, off), patches[off]]
            a = off + len(patches[off])
    out.append((a, b))
    return out
