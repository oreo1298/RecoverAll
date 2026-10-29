"""MPEG program streams (MPG, MPEG, M2P; VOB from DVDs; MOD from JVC/Panasonic/Canon camcorders): checking the
stream and repairing it.

A program stream is a run of packs. A pack starts with a pack header (00 00 01 BA: the system clock and the
mux rate; 12 bytes in MPEG-1, 14 plus stuffing in MPEG-2), may have a system header (00 00 01 BB), then PES
packets: 00 00 01, a stream id (E0-EF video, C0-DF MPEG audio, BD private stream 1 with AC-3, DTS, LPCM and DVD
subtitles, BE padding, BF private stream 2 with the DVD navigation data) and a 16-bit length. The program end
code 00 00 01 B9 closes the stream. Inside the video's PES packets is an MPEG-1/2 video stream: a sequence
header (00 00 01 B3: picture size, frame rate, quantizer matrices) must come before the first picture (00 00 01
00); camcorders, DVDs and ffmpeg repeat it before each group of pictures (00 00 01 B8).

What is checked, and repaired in a new copy:

=====================  ==========================================================================================
other data             before the first pack, between packs (the walk picks up at the next pack header whose
                       markers are right and that a valid packet follows) and after the end: dropped; the pack the
                       damage started in is dropped too.
cut short              cut after the last complete packet, and the video after its last complete picture; the
                       program end code is added.
start lost             the video before the first picture that can be decoded on its own (an I picture) is
                       dropped, and a sequence header is put in front of it when it has none: the first one found
                       later in the stream, or a REFERENCE recording's (same camera, same settings).
=====================  ==========================================================================================
"""

from __future__ import annotations

import bisect
import re
import struct

from ..filerepair import Plan, _merge, _mp3_frame_at, _n
from ..fs.base import NULL_CONTROL, Control

END_CODE = b"\x00\x00\x01\xb9"
_PACK = re.compile(rb"\x00\x00\x01\xba")
_START = re.compile(rb"\x00\x00\x01([\x00\xb3\xb5\xb8])")
_SLICE = re.compile(rb"\x00\x00\x01([\x01-\xaf])")
_MPA_SYNC = re.compile(rb"\xff[\xe0-\xff]")
AUDIO_IDS = range(0xC0, 0xE0)
VIDEO_IDS = range(0xE0, 0xF0)
_ES_LIMIT = 8 * 1024 * 1024


def pack_length(buf, p: int, end: int) -> int:
    """The length of a pack header at P whose marker bits are right (0: not one)."""
    if p + 12 > end or buf[p + 3] != 0xBA:
        return 0
    b4 = buf[p + 4]
    if b4 & 0xC4 == 0x44:                               # MPEG-2
        if p + 14 > end or not (buf[p + 6] & 4 and buf[p + 8] & 4 and buf[p + 9] & 1 and buf[p + 12] & 3 == 3):
            return 0
        return 14 + (buf[p + 13] & 7)
    if b4 & 0xF1 == 0x21:                               # MPEG-1
        if not (buf[p + 6] & 1 and buf[p + 8] & 1 and buf[p + 9] & 0x80 and buf[p + 11] & 1):
            return 0
        return 12
    return 0


def unit_length(buf, p: int, end: int) -> int:
    """The length of the pack header, system header, PES packet or end code at P (0: none there)."""
    if p + 4 > end or buf[p] or buf[p + 1] or buf[p + 2] != 1:
        return 0
    sid = buf[p + 3]
    if sid == 0xBA:
        return pack_length(buf, p, end)
    if sid == 0xB9:
        return 4
    if sid >= 0xBB and p + 6 <= end:
        n = (buf[p + 4] << 8) | buf[p + 5]
        return 6 + n if n or sid in VIDEO_IDS else 0
    return 0


def find_pack(buf, pos: int, end: int) -> int | None:
    """The next pack header from POS that has a valid packet (or another pack) right after it."""
    for m in _PACK.finditer(buf, pos, end):
        p = m.start()
        n = pack_length(buf, p, end)
        if n and (p + n >= end or unit_length(buf, p + n, end)):
            return p
    return None


_UNIT = re.compile(rb"\x00\x00\x01[\xba-\xff]")


def _stuffing(buf, p: int, end: int) -> int:
    """The length of the zero bytes at P that end a sector before the next start code (VCD, SVCD); 0 when
    there are none."""
    run = bytes(buf[p:min(end, p + 4096)])
    zeros = len(run) - len(run.lstrip(b"\x00"))
    if 2 < zeros < len(run) and run[zeros] == 1 and unit_length(buf, p + zeros - 2, end):
        return zeros - 2
    return 0


def find_unit(buf, pos: int, end: int) -> int | None:
    """The next pack header or packet from POS that two more follow (or the end of the data)."""
    for m in _UNIT.finditer(buf, pos, end):
        p = m.start()
        ok = True
        for _ in range(3):
            n = unit_length(buf, p, end)
            if not n or buf[p + 3] == 0xB9:
                ok = n > 0
                break
            p += n
            if p >= end:
                break
            p += _stuffing(buf, p, end) if buf[p] == 0 else 0
        if ok:
            return m.start()
    return None


def detect_mpegps(head: bytes) -> bool:
    """True when HEAD starts with an MPEG-1/2 pack header."""
    head = bytes(head[:64])
    return head[:4] == b"\x00\x00\x01\xba" and pack_length(head, 0, len(head)) > 0


def _pes_payload(buf, p: int, end: int) -> tuple[int, int, bool] | None:
    """(payload start, payload end, has a PTS) of the PES packet at P (MPEG-1 or MPEG-2 header)."""
    length = (buf[p + 4] << 8) | buf[p + 5]
    stop = min(end, p + 6 + length)
    q = p + 6
    if q < stop and buf[q] & 0xC0 == 0x80:              # MPEG-2
        if q + 3 > stop:
            return None
        return q + 3 + buf[q + 2], stop, bool(buf[q + 1] & 0x80)
    for _ in range(17):                                 # MPEG-1: stuffing
        if q < stop and buf[q] == 0xFF:
            q += 1
        else:
            break
    if q + 1 < stop and buf[q] & 0xC0 == 0x40:          # STD buffer
        q += 2
    if q >= stop:
        return None
    flag = buf[q] & 0xF0
    if flag == 0x20:
        return q + 5, stop, True
    if flag == 0x30:
        return q + 10, stop, True
    if buf[q] == 0x0F:
        return q + 1, stop, False
    return None


def _pts(buf, p: int, end: int) -> int | None:
    """The presentation time (90 kHz) of the PES packet at P."""
    stop = min(end, p + 6 + ((buf[p + 4] << 8) | buf[p + 5]))
    q = p + 6
    if q + 8 < stop and buf[q] & 0xC0 == 0x80:          # MPEG-2
        if not buf[q + 1] & 0x80:
            return None
        q += 3
    else:
        while q < stop and buf[q] == 0xFF:
            q += 1
        if q + 1 < stop and buf[q] & 0xC0 == 0x40:
            q += 2
        if q + 5 > stop or buf[q] & 0xE0 != 0x20:
            return None
    b = bytes(buf[q:q + 5])
    if len(b) < 5:
        return None
    return ((b[0] >> 1) & 7) << 30 | b[1] << 22 | (b[2] >> 1) << 15 | b[3] << 7 | b[4] >> 1


class _Walk:
    def __init__(self, buf, end: int, ctl: Control):
        self.buf, self.end, self.ctl = buf, end, ctl
        self.units: list[list] = []        # [start, end, stream id, keep]
        self.damage: list[tuple[int, int]] = []
        self.gaps: list[int] = []          # indexes into units where a damaged stretch was dropped
        self.cut_at: int | None = None
        self.trailing_from: int | None = None
        self.end_code = False
        self.mpeg2 = False
        self.first_pack: int | None = None
        self.system_header: tuple[int, int] | None = None
        self.pts: dict[int, list[int]] = {}   # stream id → [first, last, count]
        self.seqs: list[int] | None = None    # offsets of the video's sequence headers

    def walk(self, pos: int) -> None:
        buf, end = self.buf, self.end
        n = 0
        while pos < end:
            n += 1
            if n % 4096 == 0:
                self.ctl.check()
                self.ctl.progress(pos / max(1, end), "Checking the packs")
            length = unit_length(buf, pos, end)
            if length and pos + length > end:
                self.cut_at = pos
                return
            if length:
                sid = buf[pos + 3]
                if sid == 0xBA and self.first_pack is None:
                    self.first_pack = pos
                    self.mpeg2 = buf[pos + 4] & 0xC0 == 0x40
                elif sid == 0xBB and self.system_header is None:
                    self.system_header = (pos, pos + length)
                if sid == 0xB9:
                    self.end_code = True
                    rest = pos + 4
                    if rest < end and find_unit(buf, rest, min(end, rest + 4096)) == rest:
                        self.units.append([pos, rest, sid, False])     # another program follows: drop this end
                        pos = rest
                        continue
                    if rest < end and (any(bytes(buf[rest:min(end, rest + 65536)])) or end - rest > 65536):
                        self.trailing_from = rest
                    self.units.append([pos, rest, sid, True])
                    return
                self.units.append([pos, pos + length, sid, True])
                if sid in VIDEO_IDS or sid in AUDIO_IDS or sid == 0xBD:
                    t = _pts(buf, pos, end)
                    if t is not None:
                        v = self.pts.get(sid)
                        if v is None:
                            self.pts[sid] = [t, t, 1]
                        else:
                            v[0], v[1], v[2] = min(v[0], t), max(v[1], t), v[2] + 1
                pos += length
                continue
            stuffing = _stuffing(buf, pos, end) if buf[pos] == 0 else 0
            if stuffing:                                  # zeros that end a sector (VCD, SVCD)
                self.units.append([pos, pos + stuffing, 0, True])
                pos += stuffing
                continue
            tail = bytes(buf[pos:min(end, pos + 16)])
            if end - pos < 4096 and not any(bytes(buf[pos:end])):
                self.units.append([pos, end, 0, True])    # the last sector's stuffing
                return
            if end - pos < 16 and (tail.startswith(b"\x00\x00\x01") or b"\x00\x00\x01".startswith(tail)):
                self.cut_at = pos                         # the file ends inside a packet header
                return
            q = find_unit(buf, pos + 1, end)
            if q is None:
                self.trailing_from = pos                  # other data (or damage) up to the end
                return
            start = pos
            k = len(self.units)
            if k and self.units[-1][2] >= 0xBC:           # the damage may have started inside the last packet
                k -= 1
                while k and self.units[k - 1][2] in (0xBA, 0xBB):
                    k -= 1
            for u in self.units[k:]:
                u[3] = False
            if k < len(self.units):
                start = self.units[k][0]
            self.damage.append((start, q))
            self.gaps.append(len(self.units))
            pos = q


def _video_es(w: _Walk, buf, first: int, last: int) -> list[tuple[int, int, int]]:
    """The video's PES payloads of units FIRST..LAST: [(unit index, payload start, payload end)]."""
    out = []
    for i in range(first, last):
        u = w.units[i]
        if u[2] in VIDEO_IDS and u[3]:
            p = _pes_payload(buf, u[0], u[1])
            if p is not None and p[1] > p[0]:
                out.append((i, p[0], p[1]))
    return out


def _start_codes(buf, es: list[tuple[int, int, int]], limit: int = _ES_LIMIT):
    """(code, unit index, file offset of the 00 00 01, picture type for pictures) of the sequence headers,
    GOPs and pictures in the video payloads ES (a start code split over two payloads is missed)."""
    total = 0
    for i, a, b in es:
        for m in _START.finditer(buf, a, b):
            code = m.group(1)[0]
            at = m.start()
            ptype = (buf[at + 5] >> 3) & 7 if code == 0 and at + 6 <= b else 0
            yield code, i, at, ptype
        total += b - a
        if total > limit:
            return


def _sequence_header(buf, es, limit: int = _ES_LIMIT) -> bytes | None:
    """The first sequence header in the video payloads ES with its extensions (up to the next GOP or picture)."""
    codes = list(_start_codes(buf, es, limit))
    for k, (code, i, at, _t) in enumerate(codes):
        if code == 0xB3:
            for code2, i2, at2, _t2 in codes[k + 1:]:
                if code2 in (0x00, 0xB8, 0xB3):
                    if i2 == i:
                        return bytes(buf[at:at2])
                    break
            return None
    return None


def _reference_sequence_header(reference) -> tuple[bytes | None, str]:
    try:
        with open(reference, "rb") as f:
            data = f.read(16 * 1024 * 1024)
    except OSError as exc:
        return None, exc.strerror or str(exc)
    first = find_unit(data, 0, len(data))
    if first is None:
        return None, "it isn't an MPEG program stream"
    w = _Walk(data, len(data), NULL_CONTROL)
    w.walk(first)
    seq = _sequence_header(data, _video_es(w, data, 0, len(w.units)))
    return (seq, "") if seq else (None, "it has no video sequence header either")


def _entry(w: _Walk, buf, g: int, stop: int) -> tuple[int, int, bool, int | None] | None:
    """Where the video can start again from unit G (before unit STOP): the first I picture, with the GOP
    header and sequence header right before it: (unit index, offset, a sequence header is there, offset of the
    GOP header)."""
    es = _video_es(w, buf, g, min(stop, g + 40000))
    codes = list(_start_codes(buf, es))
    for k, (code, _i, _at, ptype) in enumerate(codes):
        if code != 0x00 or ptype != 1:
            continue
        j, gop = k, None
        if j > 0 and codes[j - 1][0] == 0xB8:
            j -= 1
            gop = codes[j][2]
        has_seq = False
        if j > 1 and codes[j - 1][0] == 0xB5 and codes[j - 2][0] == 0xB3:
            j -= 2
            has_seq = True
        elif j > 0 and codes[j - 1][0] == 0xB3:
            j -= 1
            has_seq = True
        if any(c[1] != codes[j][1] for c in codes[j:k + 1]):
            j, has_seq, gop = k, False, None             # split over packets: start at the picture itself
        return codes[j][1], codes[j][2], has_seq, gop
    return None


def _frames(buf, a: int, b: int) -> tuple[int | None, int]:
    """MPEG audio frames in the payload [A, B): (where the first one starts, where the first one that runs
    past B starts — B when the last one ends exactly there)."""
    for m in _MPA_SYNC.finditer(buf, a, b):
        f = m.start()
        n = _mp3_frame_at(buf, f)
        if not n or (f + n < b and not _mp3_frame_at(buf, f + n)):
            continue
        first = f
        while n and f + n <= b:
            f += n
            n = _mp3_frame_at(buf, f) if f < b else 0
        return first, min(f, b)
    return None, b


_AC3_KBPS = (32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640)


def _ac3_frame_at(buf, p: int, end: int) -> int:
    """The length of the AC-3 frame at P (0: none there)."""
    if p + 5 > end or buf[p] != 0x0B or buf[p + 1] != 0x77:
        return 0
    fscod, code = buf[p + 4] >> 6, buf[p + 4] & 0x3F
    if fscod == 3 or code >= 38 or buf[p + 5 if p + 5 < end else p] >> 3 > 10:
        return 0
    kbps = _AC3_KBPS[code >> 1]
    words = (kbps * 2, kbps * 96000 // 44100 + (code & 1), kbps * 3)[fscod]
    return words * 2


def _ac3_frames(buf, a: int, b: int) -> tuple[int | None, int, int]:
    """AC-3 frames in [A, B): (where the first one starts, where the first one that runs past B starts — B
    when the last one ends there —, how many start in between)."""
    p = buf.find(b"\x0b\x77", a, b)
    while p >= 0:
        n = _ac3_frame_at(buf, p, b + 8)
        if n and (p + n >= b or _ac3_frame_at(buf, p + n, b + 8)):
            first, count = p, 0
            while n and p + n <= b:
                p += n
                count += 1
                n = _ac3_frame_at(buf, p, b + 8) if p < b else 0
            return first, min(p, b), count + (1 if p < b else 0)
        p = buf.find(b"\x0b\x77", p + 1, b)
    return None, b, 0


def _shortened_ac3(buf, u: list, payload: tuple, cut: int, keep_head: bool, frames: int) -> list:
    """The DVD AC-3 packet U cut at CUT (keeping what is before it when KEEP_HEAD, else what follows), with
    its substream header (frame count, first access unit pointer) set to match."""
    start, stop = payload[0], payload[1]
    head = bytearray(buf[u[0]:start])
    sub = bytearray(buf[start:start + 4])
    if keep_head:
        sub[1] = max(0, frames - 1) if cut < stop else frames
        body = (start + 4, cut)
    else:
        sub[1] = frames
        sub[2:4] = b"\x00\x01"                       # the first frame starts right after the header
        body = (cut, stop)
    struct.pack_into(">H", head, 4, len(head) - 6 + 4 + body[1] - body[0])
    return [bytes(head) + bytes(sub), body] if body[1] > body[0] else []


def _sequence_headers(w: _Walk, buf) -> list[int]:
    """The offsets of every sequence header in the video packets (worked out once)."""
    if w.seqs is None:
        w.seqs = []
        for i, a, b in _video_es(w, buf, 0, len(w.units)):
            k = buf.find(b"\x00\x00\x01\xb3", a, b)
            while 0 <= k and k + 12 <= b:
                w.seqs.append(k)
                k = buf.find(b"\x00\x00\x01\xb3", k + 4, b)
    return w.seqs


def _rows(w: _Walk, buf, picture_at: int) -> int | None:
    """The macroblock rows of the MPEG-2 picture at PICTURE_AT, from the last sequence header
    before it and the picture's coding extension; None for MPEG-1 or when unknown."""
    seqs = _sequence_headers(w, buf)
    k = bisect.bisect_left(seqs, picture_at) - 1
    seq = seqs[k] if k >= 0 else None
    if seq is None or buf.find(b"\x00\x00\x01\xb5", seq, seq + 160) < 0:
        return None
    ext = buf.find(b"\x00\x00\x01\xb5", seq, seq + 160)
    if buf[ext + 4] >> 4 != 1:
        return None
    height = ((buf[seq + 5] & 0x0F) << 8) | buf[seq + 6]
    progressive = buf[ext + 5] & 0x08
    rows = (height + 15) // 16 if progressive else 2 * ((height + 31) // 32)
    pext = buf.find(b"\x00\x00\x01\xb5", picture_at, picture_at + 64)
    if pext >= 0 and buf[pext + 4] >> 4 == 8 and buf[pext + 6] & 3 in (1, 2):
        rows //= 2                                     # a field picture
    return rows


def _last_slice(buf, es, after: int) -> int | None:
    """The row of the last slice start code in ES after offset AFTER."""
    for _i, a, b in reversed(es):
        if b <= after:
            break
        last = None
        for m in _SLICE.finditer(buf, max(a, after), b):
            last = m.group(1)[0]
        if last is not None:
            return last
    return None


def _pes_bytes(mpeg2: bool, sid: int, payload: bytes) -> bytes:
    """A PES packet of stream SID with PAYLOAD and no time stamps."""
    head = b"\x81\x00\x00" if mpeg2 else b"\x0f"
    return b"\x00\x00\x01" + bytes([sid]) + struct.pack(">H", len(head) + len(payload)) + head + payload


def _shortened(buf, u: list, cut: int, keep_head: bool, gop: int | None = None) -> list:
    """The PES packet U with its payload cut at CUT: keeping [payload start, CUT) when KEEP_HEAD, else
    [CUT, end) (the header and its time stamps stay). GOP: the offset of a GOP header in the kept part, marked
    as a broken link (its first B pictures refer to pictures that are gone) unless it is closed."""
    p = _pes_payload(buf, u[0], u[1])
    if p is None:
        return []
    start = p[0]
    head = bytearray(buf[u[0]:start])
    if keep_head:
        n = cut - u[0] - 6
        struct.pack_into(">H", head, 4, n)
        return [bytes(head), (start, cut)] if cut > start else []
    n = u[1] - cut + (start - u[0] - 6)
    struct.pack_into(">H", head, 4, n)
    if gop is not None and gop + 8 <= u[1] and not buf[gop + 7] & 0x40:
        return [bytes(head), (cut, gop + 7), bytes([buf[gop + 7] | 0x20]), (gop + 8, u[1])]
    return [bytes(head), (cut, u[1])]


def plan_mpegps(buf, path="", reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    """Check an MPEG program stream and plan its repair (see the module docstring)."""
    end = len(buf)
    ext = str(path).lower().rsplit(".", 1)[-1] if "." in str(path) else ""
    plan = Plan(ext if ext in ("mpg", "mpeg", "vob", "mod", "m2p", "mpe", "vro", "evo") else "mpg")
    start = max(0, min(end, int(data_offset or 0)))
    first = find_unit(buf, start, min(end, start + 16 * 1024 * 1024)) \
        if find_pack(buf, start, min(end, start + 16 * 1024 * 1024)) is not None else None
    if first is None:
        from . import mpegts
        if mpegts.find_layout(buf, start, end) is not None:
            return mpegts.plan_mpegts(buf, path, reference, data_offset, ctl)
        plan.problem("No MPEG pack headers were found" if end else "The file is empty")
        plan.note = "The file isn't an MPEG program stream, or its data is damaged everywhere."
        return plan
    w = _Walk(buf, end, ctl)
    w.walk(first)
    kept_units = [u for u in w.units if u[3]]
    if not any(u[2] >= 0xBC for u in kept_units):
        plan.problem("No intact packets were found")
        plan.note = "The stream is damaged everywhere."
        return plan
    duration = 0.0
    timed = [v for sid, v in w.pts.items() if v[2] > 1]
    if timed:
        main = max(timed, key=lambda v: v[2])
        span = main[1] - main[0]
        if 0 < span < 90000 * 86400:
            duration = (span + span / (main[2] - 1)) / 90000
    plan.info.update(duration=round(duration, 3), packs=sum(1 for u in kept_units if u[2] == 0xBA),
                     mpeg="MPEG-2" if w.mpeg2 else "MPEG-1",
                     streams=sorted({f"{u[2]:#x}" for u in kept_units if u[2] >= 0xBC and u[2] not in (0xBE, 0xBF)}))
    if first > start:
        plan.problem(f"{_n(first - start)} of other data come before the first pack", f"Cut the {_n(first - start)}")
    if w.damage:
        lost = sum(b - a for a, b in w.damage)
        k = len(w.damage)
        plan.problem(f"{k} damaged stretch{'es' if k > 1 else ''} in the stream ({_n(lost)})",
                     "Drop the damaged stretches (the picture skips there)")
        plan.info["damaged_bytes"] = lost
    if w.cut_at is not None:
        plan.problem("The file is cut short: it ends in the middle of a packet",
                     "Cut it after the last complete packet and picture")
    if w.trailing_from is not None:
        n = end - w.trailing_from
        plan.problem(f"{_n(n)} of other data come after the end of the stream", f"Cut the {_n(n)} at the end")

    # ---- a cut at a pack boundary: the last MPEG-2 picture's slices don't reach its last row
    es_end = _video_es(w, buf, max(0, len(w.units) - 400), len(w.units))
    codes_end = list(_start_codes(buf, es_end))
    last_pic = next(((i, at) for code, i, at, _t in reversed(codes_end) if code == 0x00), None)
    end_incomplete = False
    if last_pic is not None and not w.end_code:
        rows = _rows(w, buf, last_pic[1])
        last = _last_slice(buf, es_end, last_pic[1])
        if rows is not None and last is not None and last < rows:
            end_incomplete = True
            if w.cut_at is None and w.trailing_from is None:
                plan.problem("The file is cut short: its last picture is incomplete", "Drop the incomplete last picture")

    # ---- the video can only start at an I picture (with its GOP and sequence header): at the start, after gaps
    edits: dict[int, list] = {}            # unit index → its replacement pieces
    front: list[bytes] = []
    es0 = _video_es(w, buf, 0, min(len(w.units), 20000))
    codes0 = list(_start_codes(buf, es0))
    seq_first = next((at for code, _i, at, _t in codes0 if code == 0xB3), None)
    pic_first = next((at for code, _i, at, _t in codes0 if code == 0x00), None)
    resume = list(w.gaps)
    lost_start = pic_first is not None and (seq_first is None or seq_first > pic_first)
    lead = bytes(buf[es0[0][1]:min(es0[0][2], es0[0][1] + 256)]) if es0 else b""
    zeros = len(lead) - len(lead.lstrip(b"\x00"))
    if es0 and not (zeros >= 2 and lead[zeros:zeros + 1] == b"\x01"):
        lost_start = True                  # the first video packet starts in the middle of a picture
    if lost_start:
        resume.insert(0, 0)
    for n, g in enumerate(resume):
        stop = resume[n + 1] if n + 1 < len(resume) else len(w.units)
        e = _entry(w, buf, g, stop)
        if e is None:
            if g == 0:
                plan.problem("The video has no picture that can be decoded on its own")
            else:                          # no picture to start from before the next gap or the end
                for i, _a, _b in _video_es(w, buf, g, stop):
                    w.units[i][3] = False
            continue
        ti, tat, has_seq, gop = e
        for i, _a, _b in _video_es(w, buf, g, ti):
            w.units[i][3] = False
        edits[ti] = _shortened(buf, w.units[ti], tat, keep_head=False, gop=gop)
        if g == 0:
            plan.problem("The start of the video was lost: it begins in the middle of a group of pictures",
                         "Drop the video before its first complete group of pictures")
            if not has_seq:
                seq = _sequence_header(buf, _video_es(w, buf, 0, len(w.units)))
                if seq is None and reference is not None:
                    seq, why = _reference_sequence_header(reference)
                    if seq is None:
                        plan.note = f"The reference recording can't be used: {why}. "
                if seq is None:
                    plan.problem("The video's sequence header is missing")
                    plan.note = plan.note or ("The start of the recording, with the video's sequence header, is lost "
                                              "and no reference was given: repair it with a reference recording made "
                                              "by the same camera with the same settings.")
                else:
                    plan.actions.append("Put a sequence header in front of the video")
                    pack = bytes(buf[w.first_pack:w.first_pack + pack_length(buf, w.first_pack, end)]) \
                        if w.first_pack is not None else b""
                    front = [pack, _pes_bytes(w.mpeg2, w.units[ti][2], seq)]

    # ---- the video before each gap and at a cut-short end: drop its incomplete last picture
    cut_end = w.cut_at is not None or end_incomplete or (w.trailing_from is not None and not w.end_code)
    stops = list(w.gaps) + ([len(w.units)] if cut_end else [])
    for g in stops:
        es = _video_es(w, buf, max(0, g - 400), g)
        codes = list(_start_codes(buf, es))
        k = max((n for n, c in enumerate(codes) if c[0] == 0x00), default=None)
        if k is None:
            continue
        rows = _rows(w, buf, codes[k][2])
        last = _last_slice(buf, es, codes[k][2])
        if rows is not None and last is not None and last >= rows:
            continue                       # it is complete
        if k > 0 and codes[k - 1][0] == 0xB8:
            k -= 1
        if k > 1 and codes[k - 1][0] == 0xB5 and codes[k - 2][0] == 0xB3:
            k -= 2
        elif k > 0 and codes[k - 1][0] == 0xB3:
            k -= 1
        ci, cat = codes[k][1], codes[k][2]
        for i, _a, _b in es:
            if i > ci:
                w.units[i][3] = False
        if ci not in edits:
            edits[ci] = _shortened(buf, w.units[ci], cat, keep_head=True)

    # ---- the sound around each gap: whole frames only (MPEG audio; AC-3 in DVD private streams)
    def sound(i: int):
        u = w.units[i]
        if not u[3] or not (u[2] in AUDIO_IDS or u[2] == 0xBD):
            return None
        p = _pes_payload(buf, u[0], u[1])
        if p is None or p[1] <= p[0]:
            return None
        if u[2] == 0xBD:
            return (0xBD, buf[p[0]], p) if 0x80 <= buf[p[0]] <= 0x87 and p[1] - p[0] > 4 else None
        return (u[2], None, p)

    for g in stops:
        seen: set = set()
        for i in range(g - 1, max(-1, g - 400), -1):
            s_ = sound(i)
            if s_ is None or s_[:2] in seen or i in edits:
                continue
            seen.add(s_[:2])
            p = s_[2]
            if s_[1] is None:
                _first, cut = _frames(buf, p[0], p[1])
                if cut < p[1]:
                    edits[i] = _shortened(buf, w.units[i], cut, keep_head=True)
            else:
                first, cut, count = _ac3_frames(buf, p[0] + 4, p[1])
                if cut < p[1]:
                    edits[i] = _shortened_ac3(buf, w.units[i], p, cut, keep_head=True, frames=count)
    for g in resume:
        seen = set()
        for i in range(g, min(len(w.units), g + 400)):
            s_ = sound(i)
            if s_ is None or s_[:2] in seen:
                continue
            seen.add(s_[:2])
            if i in edits:
                continue
            p = s_[2]
            if s_[1] is None:
                first, _cut = _frames(buf, p[0], p[1])
                if first is None:
                    w.units[i][3] = False
                elif first > p[0]:
                    edits[i] = _shortened(buf, w.units[i], first, keep_head=False)
            else:
                first, _cut, count = _ac3_frames(buf, p[0] + 4, p[1])
                if first is None:
                    w.units[i][3] = False
                elif first > p[0] + 4:
                    edits[i] = _shortened_ac3(buf, w.units[i], p, first, keep_head=False, frames=count)
    structural = [p for p in plan.problems if p not in ("The video's sequence header is missing",
                                                         "The video has no picture that can be decoded on its own")]
    if not structural:
        return plan

    # ---- the copy
    pieces: list = list(front)
    last_kept = None
    for i, u in enumerate(w.units):
        if not u[3]:
            continue
        if i in edits:
            pieces.extend(edits[i])
        else:
            pieces.append((u[0], u[1]))
        last_kept = u
    if (last_kept is None or last_kept[2] != 0xB9) and (cut_end or w.trailing_from is not None):
        pieces.append(END_CODE)
    final = _merge(pieces)
    plan.repairable = True
    plan.build = lambda: final
    return plan
