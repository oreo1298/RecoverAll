"""Windows Media (WMV, WMA, ASF, DVR-MS): checking the file and repairing it.

An ASF file is objects, each a GUID, a 64-bit size and the payload. The Header Object comes first and holds
other objects: File Properties (the file size, the number of data packets, the play and send durations in
100-nanosecond units, the preroll in milliseconds, flags, the data packet size), one Stream Properties object
per stream (its kind, number and codec settings), a Header Extension. The Data Object follows: a 50-byte head
(with the number of packets) and the data packets, all of the same size. Each packet starts with its payload
parsing information (flags, the send time in milliseconds, the duration, padding) and holds one or more
payloads: fragments of media objects (frames) with the stream number, a key-frame flag, the object number,
the fragment's offset in the object, and "replicated data" (the object's size and presentation time). After
the data come the index objects (Simple Index: for each second, the packet a key frame starts in).

What is checked, and repaired in a new copy:

=====================  ==========================================================================================
cut short              the complete data packets are kept; the Data Object's size and packet count, and the File
                       Properties' file size, packet count and durations (from the last frames' presentation
                       times) are set to what is there; the index, which was at the end, is rebuilt.
damage in the middle   packets that don't parse are dropped and the counts corrected; the video's frames up to
                       its next key frame are taken out of the packets (they can't be decoded without the frames
                       that were lost); the index is rebuilt.
other data at the end  cut.
index objects          an index that points past the end is dropped; a Simple Index is rebuilt from the video's
                       key frames.
the start lost         with a REFERENCE file from the same camera or program with the same settings (the same
                       packet size): its Header Object, a new Data Object head, and the packets that survived.
=====================  ==========================================================================================
"""

from __future__ import annotations

import re
import struct
import uuid

from ..filerepair import Plan, _merge, _n
from ..fs.base import NULL_CONTROL, Control


def _guid(text: str) -> bytes:
    return uuid.UUID(text).bytes_le


HEADER = _guid("75B22630-668E-11CF-A6D9-00AA0062CE6C")
DATA = _guid("75B22636-668E-11CF-A6D9-00AA0062CE6C")
FILE_PROPERTIES = _guid("8CABDCA1-A947-11CF-8EE4-00C00C205365")
STREAM_PROPERTIES = _guid("B7DC0791-A9B7-11CF-8EE6-00C00C205365")
HEADER_EXTENSION = _guid("5FBF03B5-A92E-11CF-8EE3-00C00C205365")
EXTENDED_STREAM_PROPERTIES = _guid("14E6A5CB-C672-4332-8399-A96952065B5A")
SIMPLE_INDEX = _guid("33000890-E5B1-11CF-89F4-00A0C90349CB")
INDEX = _guid("D6E229D3-35DA-11D1-9034-00A0C90349BE")
MEDIA_OBJECT_INDEX = _guid("FEB103F8-12AD-4C64-840F-2A1D2F7AD48C")
TIMECODE_INDEX = _guid("3CB73FD0-0C4A-4803-953D-EDF7B6228F0C")
AUDIO_MEDIA = _guid("F8699E40-5B4D-11CF-A8FD-00805F5C442B")
VIDEO_MEDIA = _guid("BC19EFC0-5B4D-11CF-A8FD-00805F5C442B")
INDEXES = {SIMPLE_INDEX, INDEX, MEDIA_OBJECT_INDEX, TIMECODE_INDEX}
_INTERVAL = 10_000_000                    # the Simple Index's step: one second


def detect_asf(head: bytes) -> bool:
    """True when HEAD starts with an ASF Header Object (WMV, WMA, ASF, DVR-MS)."""
    return bytes(head[:16]) == HEADER


def _u(buf, p: int, kind: int) -> tuple[int, int]:
    """A field of length type KIND (0 none, 1 byte, 2 word, 3 dword) at P: (value, its length)."""
    if kind == 0:
        return 0, 0
    n = (0, 1, 2, 4)[kind]
    return int.from_bytes(buf[p:p + n], "little"), n


class _Header:
    """What the Header Object says."""

    def __init__(self):
        self.size = 0
        self.fp: int | None = None                    # offset of the File Properties object
        self.packet_size = 0
        self.packets = 0
        self.preroll = 0
        self.play = 0
        self.broadcast = False
        self.file_size = 0
        self.streams: dict[int, str] = {}             # number → "video" / "audio" / "other"
        self.file_id = bytes(16)


def _parse_header(buf, end: int) -> _Header | None:
    if end < 30 or bytes(buf[:16]) != HEADER:
        return None
    size, count = struct.unpack_from("<QI", buf, 16)
    if size < 30 + 104 or size > end or not 1 <= count <= 10000:
        return None
    h = _Header()
    h.size = size
    pos = 30
    for _ in range(count):
        if pos + 24 > size:
            break
        guid, osize = bytes(buf[pos:pos + 16]), struct.unpack_from("<Q", buf, pos + 16)[0]
        if osize < 24 or pos + osize > size:
            return None
        if guid == FILE_PROPERTIES and osize >= 104:
            h.fp = pos
            h.file_id = bytes(buf[pos + 24:pos + 40])
            h.file_size, _ctime, h.packets, h.play, _send, h.preroll = struct.unpack_from("<QQQQQQ", buf, pos + 40)
            flags, pmin, pmax = struct.unpack_from("<III", buf, pos + 88)
            h.broadcast = bool(flags & 1)
            h.packet_size = pmin if pmin == pmax else 0
        elif guid == STREAM_PROPERTIES and osize >= 78:
            kind = bytes(buf[pos + 24:pos + 40])
            number = struct.unpack_from("<H", buf, pos + 72)[0] & 0x7F
            h.streams[number] = "video" if kind == VIDEO_MEDIA else "audio" if kind == AUDIO_MEDIA else "other"
        elif guid == HEADER_EXTENSION and osize >= 46:
            q, stop = pos + 46, pos + osize
            while q + 24 <= stop:
                g, n = bytes(buf[q:q + 16]), struct.unpack_from("<Q", buf, q + 16)[0]
                if n < 24 or q + n > stop:
                    break
                if g == EXTENDED_STREAM_PROPERTIES and n >= 88:
                    number = struct.unpack_from("<H", buf, q + 72)[0] & 0x7F
                    h.streams.setdefault(number, "other")
                    names, payload_ext = struct.unpack_from("<HH", buf, q + 84)
                    r = q + 88
                    for _ in range(names):                # stream names, then payload extension systems
                        if r + 4 > q + n:
                            break
                        r += 4 + struct.unpack_from("<H", buf, r + 2)[0]
                    for _ in range(payload_ext):
                        if r + 22 > q + n:
                            break
                        r += 22 + struct.unpack_from("<I", buf, r + 18)[0]
                    if r + 24 <= q + n and bytes(buf[r:r + 16]) == STREAM_PROPERTIES:
                        kind = bytes(buf[r + 24:r + 40])
                        h.streams[number] = "video" if kind == VIDEO_MEDIA else "audio" if kind == AUDIO_MEDIA \
                            else "other"
                q += n
        pos += osize
    return h if h.fp is not None and h.packet_size else None


class _Packet:
    __slots__ = ("send", "duration", "payloads", "ec", "props")

    def __init__(self, send: int, duration: int, payloads: list, ec: int, props: int):
        self.send, self.duration, self.payloads, self.ec, self.props = send, duration, payloads, ec, props


def parse_packet(buf, p: int, size: int, streams) -> _Packet | None:
    """The data packet of SIZE bytes at P; None when it doesn't parse. Payloads: (stream, key, object number,
    offset in the object, object size, presentation time ms, data start, data end, header start, header end
    before the payload length)."""
    stop = p + size
    q = p
    ec = buf[q]
    if ec & 0x80:
        if ec & 0x70 or q + 1 + (ec & 0x0F) > stop:
            return None
        q += 1 + (ec & 0x0F)
    else:
        ec = 0
    if q + 2 > stop:
        return None
    flags, props = buf[q], buf[q + 1]
    if (props >> 6) & 3 != 1:                           # stream numbers are always one byte
        return None
    q += 2
    pkt_len, n1 = _u(buf, q, (flags >> 5) & 3)
    _seq, n2 = _u(buf, q + n1, (flags >> 1) & 3)
    pad, n3 = _u(buf, q + n1 + n2, (flags >> 3) & 3)
    q += n1 + n2 + n3
    if q + 6 > stop:
        return None
    send, duration = struct.unpack_from("<IH", buf, q)
    q += 6
    if (flags >> 5) & 3:
        if pkt_len > size or pkt_len < q - p:
            return None
        pad += size - pkt_len
    data_end = stop - pad
    if data_end < q:
        return None
    rep_t, off_t, obj_t = props & 3, (props >> 2) & 3, (props >> 4) & 3
    payloads = []
    count, plen_t = 1, 0
    multiple = flags & 1
    if multiple:
        count, plen_t = buf[q] & 0x3F, buf[q] >> 6
        q += 1
        if count == 0 or plen_t == 0:
            return None
    for _ in range(count):
        h = q
        if q + 1 > data_end:
            return None
        sb = buf[q]
        stream = sb & 0x7F
        if streams and stream not in streams or stream == 0:
            return None
        q += 1
        obj, a = _u(buf, q, obj_t)
        off, b = _u(buf, q + a, off_t)
        rep, c = _u(buf, q + a + b, rep_t)
        q += a + b + c
        if rep not in (0, 1) and rep < 8 or q + rep > data_end:
            return None
        obj_size = pres = 0
        if rep >= 8:
            obj_size, pres = struct.unpack_from("<II", buf, q)
        elif rep == 1:
            pres = off                                 # compressed payloads: the offset field is the time
        q += rep
        if rep == 1:
            q += 1                                     # presentation time delta
        meta_end = q
        if multiple:
            length, d = _u(buf, q, plen_t)
            q += d
        else:
            length = data_end - q
        if q + length > data_end or length < 0:
            return None
        if rep >= 8 and (off + length > obj_size or obj_size == 0):
            return None
        payloads.append((stream, bool(sb & 0x80), obj, off, obj_size, pres, q, q + length, h, meta_end))
        q += length
    return _Packet(send, duration, payloads, ec, props)


def _rewrite(buf, p: int, size: int, pkt: _Packet, keep: list) -> bytes | None:
    """Packet PKT at P with only the payloads KEEP, in the several-payloads form with word lengths, padded to
    SIZE; None when they don't fit."""
    body = b"".join(bytes(buf[pl[8]:pl[9]]) + struct.pack("<H", pl[7] - pl[6]) + bytes(buf[pl[6]:pl[7]])
                    for pl in keep)
    ec = bytes(buf[p:p + 1 + (pkt.ec & 0x0F)]) if pkt.ec else b""
    pad = size - (len(ec) + 11) - len(body)
    if pad < 0 or not 0 < len(keep) < 64:
        return None
    return ec + bytes([0x11, pkt.props]) + struct.pack("<HIH", pad, pkt.send, pkt.duration) + \
        bytes([0x80 | len(keep)]) + body + bytes(pad)


def _object_at(buf, pos: int, end: int) -> tuple[bytes, int] | None:
    if pos + 24 > end:
        return None
    return bytes(buf[pos:pos + 16]), struct.unpack_from("<Q", buf, pos + 16)[0]


def _simple_index(file_id: bytes, keys: list[tuple[int, int, int]], total_ms: int) -> bytes:
    """A Simple Index Object with one entry per second: the packet (and how many packets) of the latest key
    frame at or before that time. KEYS: (presentation time ms, packet number, packet count)."""
    entries = []
    count = max(1, -(-total_ms // 1000))
    k = 0
    best = keys[0] if keys else (0, 0, 1)
    for i in range(count):
        while k < len(keys) and keys[k][0] <= i * 1000:
            best = keys[k]
            k += 1
        entries.append(struct.pack("<IH", best[1], min(0xFFFF, best[2])))
    body = file_id + struct.pack("<QII", _INTERVAL, max(min(0xFFFF, kk[2]) for kk in keys) if keys else 1,
                                 len(entries)) + b"".join(entries)
    return SIMPLE_INDEX + struct.pack("<Q", 24 + len(body)) + body


def _signature(buf, h: _Header) -> re.Pattern:
    """What the start of this file's data packets looks like: the error correction byte and data, any
    length flags, the property flags (learned from its first packet)."""
    p = h.size + 50
    if p + h.packet_size <= len(buf):
        pkt = parse_packet(buf, p, h.packet_size, h.streams)
        if pkt is not None:
            if pkt.ec:
                return re.compile(re.escape(bytes([pkt.ec])) + rb"[\s\S]{%d}[\x00-\x7f]" % (pkt.ec & 0x0F) +
                                  re.escape(bytes([pkt.props])))
            return re.compile(rb"[\x00-\x7f]" + re.escape(bytes([pkt.props])))
    return re.compile(rb"(?:\x82\x00\x00)?[\x00-\x7f][\x40-\x7f]")


def _find_packets(buf, start: int, end: int, size: int, streams, sig: re.Pattern, need: int = 3) -> int | None:
    """The first offset from START where NEED data packets of SIZE parse one after the other."""
    for m in sig.finditer(buf, start, min(end, start + 64 * 1024 * 1024)):
        p = m.start()
        if all(parse_packet(buf, p + k * size, size, streams) is not None for k in range(need)
               if p + (k + 1) * size <= end) and p + size <= end:
            return p
    return None


def plan_asf(buf, path="", reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    """Check a Windows Media file and plan its repair (see the module docstring)."""
    end = len(buf)
    ext = str(path).lower().rsplit(".", 1)[-1] if "." in str(path) else ""
    h = _parse_header(buf, end)
    plan = Plan(ext if ext in ("wmv", "wma", "asf", "dvr-ms") else "wmv")
    head_bytes = None
    if h is None:
        plan.problem("The start of the file (the ASF header) is missing or damaged")
        if reference is None:
            plan.note = ("The start of the file is overwritten and no reference was given: the stream settings were "
                         "there. Repair it with a reference file made by the same camera or program with the same "
                         "settings.")
            return plan
        try:
            with open(reference, "rb") as f:
                rdata = f.read(16 * 1024 * 1024)
        except OSError as exc:
            plan.note = f"The reference file can't be used: {exc.strerror or exc}."
            return plan
        h = _parse_header(rdata, len(rdata))
        if h is None:
            plan.note = "The reference file can't be used: it isn't a readable Windows Media file."
            return plan
        head_bytes = bytearray(rdata[:h.size])
        start = max(0, min(end, int(data_offset or 0)))
        first = _find_packets(buf, start, end, h.packet_size, h.streams, _signature(rdata, h))
        if first is None:
            plan.note = ("No data packets of the reference's size were found: use a reference made with the same "
                         "settings.")
            return plan
        plan.actions.append("Put the reference file's header in front of the packets that survived")
        data_obj, packets_from, declared_end, declared_packets = None, first, end, None
        plan.info["skipped_bytes"] = first - start
    else:
        obj = _object_at(buf, h.size, end)
        if obj is None or obj[0] != DATA:
            plan.problem("The data part of the file is missing or damaged")
            plan.note = "The header is there but the data that should follow it isn't."
            return plan
        data_obj = h.size
        packets_from = h.size + 50
        declared_end = h.size + obj[1] if obj[1] >= 50 else None
        declared_packets = struct.unpack_from("<Q", buf, h.size + 40)[0] if h.size + 50 <= end else 0
    size = h.packet_size
    streams = set(h.streams)
    video = {n for n, k in h.streams.items() if k == "video"}

    # ---- the packets
    stop = end
    if declared_end is not None and declared_end <= end and (declared_end - packets_from) % size == 0:
        stop = declared_end
    good: list[tuple[int, _Packet]] = []
    bad: list[int] = []
    p = packets_from
    n = 0
    while p + size <= stop:
        if bytes(buf[p:p + 16]) in INDEXES and parse_packet(buf, p, size, streams) is None:
            stop = p                               # the index objects after the data
            break
        n += 1
        if n % 4096 == 0:
            ctl.check()
            ctl.progress(p / max(1, end), "Checking the data packets")
        pkt = parse_packet(buf, p, size, streams)
        if pkt is not None and good and not good[-1][1].send - 10000 <= pkt.send <= good[-1][1].send + 10000:
            # a send time far from the last one: real when the next packet goes on from it, else damaged
            nxt = parse_packet(buf, p + size, size, streams) if p + 2 * size <= stop else None
            if nxt is None or not pkt.send - 10000 <= nxt.send <= pkt.send + 10000:
                pkt = None
        if pkt is not None and good and (pkt.props != good[0][1].props or pkt.ec != good[0][1].ec):
            pkt = None
        if pkt is None:
            bad.append(p)
        else:
            good.append((p, pkt))
        p += size
    if not good:
        plan.problem("No intact data packets were found")
        plan.note = "The data is damaged everywhere."
        return plan
    partial = stop - p if stop == end and p < end and bytes(buf[p:p + 16]) not in INDEXES else 0
    # trailing bad packets at the end of a cut file are more likely the cut or other data than damage
    while bad and bad[-1] > good[-1][0]:
        bad.pop()
        partial += size
    after = p if stop != end or partial == 0 else end

    # ---- the frames: presentation times, key frames, objects cut by dropped packets
    gaps = sorted(bad)
    events = []                                    # indexes into good after which packets were dropped
    gi = 0
    for i, (q, _pkt) in enumerate(good):
        while gi < len(gaps) and gaps[gi] < q:
            if not events or events[-1] != i:
                events.append(i)
            gi += 1
    if head_bytes is not None:
        events.insert(0, 0)
    drop: dict[int, set[int]] = {}                 # packet index → payload indexes to take out
    for e in events:
        waiting = set(video)
        for i in range(e, min(len(good), e + 100000)):
            pkt = good[i][1]
            for j, pl in enumerate(pkt.payloads):
                if pl[0] in waiting:
                    if pl[1] and pl[3] == 0:
                        waiting.discard(pl[0])
                    else:
                        drop.setdefault(i, set()).add(j)
            if not waiting:
                break
    last_end: dict[int, int] = {}
    times: dict[int, list[int]] = {}
    keys: list[tuple[int, int, int]] = []
    open_key: dict[int, list] = {}
    for i, (q, pkt) in enumerate(good):
        for j, pl in enumerate(pkt.payloads):
            if j in drop.get(i, ()):
                continue
            stream, key, obj, off, _osize, pres = pl[:6]
            if off == 0:
                times.setdefault(stream, []).append(pres)
                last_end[stream] = max(last_end.get(stream, 0), pres)
                if stream in video and key:
                    entry = [pres, i, 1]
                    keys.append(entry)
                    open_key[stream] = [obj, entry]
            elif stream in open_key and open_key[stream][0] == obj:
                open_key[stream][1][2] = i - open_key[stream][1][1] + 1
    end_ms = 0
    for stream, t in times.items():
        tt = sorted(t[-64:])
        steps = sorted(y - x for x, y in zip(tt, tt[1:]) if y > x)
        end_ms = max(end_ms, last_end[stream] + (steps[len(steps) // 2] if steps else 0))
    duration = max(0.0, (end_ms - h.preroll) / 1000)
    kept_packets = len(good)
    plan.info.update(packets=kept_packets, packet_size=size, duration=round(duration, 3),
                     streams=[f"{k} {n}" for n, k in sorted(h.streams.items())])

    # ---- the problems
    if partial or (declared_end is not None and declared_end > end):
        plan.problem("The file is cut short: it ends in the middle of a data packet" if partial else
                     "The file is cut short", "Keep the complete data packets")
    if bad:
        k = 1 + sum(1 for a, b in zip(gaps, gaps[1:]) if b - a > size)
        plan.problem(f"{k} damaged stretch{'es' if k > 1 else ''} in the video ({len(bad)} packet"
                     f"{'s' if len(bad) > 1 else ''}, {_n(len(bad) * size)})",
                     "Drop the damaged packets (the picture skips to the next key frame there)")
        plan.info["dropped_packets"] = len(bad)
    if drop:
        plan.info["frames_dropped"] = sum(len(v) for v in drop.values())
    # what follows the data: index objects, other data
    tail: list[tuple[int, int, bytes]] = []        # (start, end, guid) of intact objects after the data
    pos = after
    trailing = 0
    while pos < end:
        obj = _object_at(buf, pos, end)
        if obj is None or obj[1] < 24 or pos + obj[1] > end or obj[0] not in INDEXES:
            trailing = end - pos
            break
        tail.append((pos, pos + obj[1], obj[0]))
        pos += obj[1]
    if trailing and not partial:
        plan.problem(f"{_n(trailing)} of other data come after the end", f"Cut the {_n(trailing)} at the end")
    if data_obj is not None and declared_packets not in (None, kept_packets + len(bad)) and not partial and \
            declared_end is not None and declared_end <= end:
        plan.problem("The number of data packets in the Data Object is wrong", "Correct the packet count")
    if not h.broadcast and data_obj is not None and h.packets != kept_packets + len(bad) and not partial and \
            declared_end is not None and declared_end <= end:
        plan.problem("The number of data packets in the file's properties is wrong", "Correct the packet count")
    if not h.broadcast and data_obj is not None and h.file_size != end and not (partial or trailing) and \
            declared_end is not None and declared_end <= end:
        plan.problem("The file size in the file's properties is wrong", "Correct the file size")
    play_ms = h.play / 10000 - h.preroll if h.play else 0
    if data_obj is not None and not h.broadcast and h.play and abs(play_ms / 1000 - duration) > max(1.0, 0.02 * duration) \
            and not plan.problems:
        plan.problem(f"The duration in the file's properties is wrong ({play_ms / 1000:.1f} s instead of "
                     f"{duration:.1f} s)", f"Set the duration ({duration:.1f} s)")
    simple = [t for t in tail if t[2] == SIMPLE_INDEX]
    for a, b, _g in simple:
        if b - a >= 56:
            count = struct.unpack_from("<I", buf, a + 52)[0]
            if 56 + 6 * count > b - a or any(struct.unpack_from("<I", buf, a + 56 + 6 * k)[0] >= h.packets
                                             for k in range(min(count, 100000))):
                plan.problem("The seeking index points past the end of the data", "Rebuild the seeking index")
    if video and not tail and not h.broadcast and not plan.problems and len(keys) > 1:
        plan.problem("The seeking index is missing (players can't jump to a time)",
                     "Rebuild the seeking index from the key frames")
    if not plan.problems:
        return plan
    changed = bool(bad or drop or partial or head_bytes is not None or (declared_end is not None and
                                                                        declared_end > end))
    rebuild_index = bool(video) and (changed or not simple or
                                     "Rebuild the seeking index" in plan.actions)
    if rebuild_index and "Rebuild the seeking index" not in plan.actions:
        plan.actions.append("Rebuild the seeking index from the key frames")
    plan.actions.append(f"Set the packet counts, the file size and the duration ({duration:.1f} s)")

    # ---- the copy
    rewrites: dict[int, bytes] = {}
    for i, js in drop.items():
        q, pkt = good[i]
        keep = [pl for j, pl in enumerate(pkt.payloads) if j not in js]
        new = _rewrite(buf, q, size, pkt, keep) if keep else None
        if new is None and keep:
            continue
        rewrites[i] = new if new is not None else b""
    kept = [(i, q) for i, (q, _pkt) in enumerate(good) if rewrites.get(i, None) != b""]
    total = len(kept)
    index = b""
    if rebuild_index:
        renum = {i: k for k, (i, _q) in enumerate(kept)}
        ks = [(t, renum[i], c) for t, i, c in keys if i in renum]
        index = _simple_index(h.file_id, ks, end_ms)
    elif not changed:
        index = b"".join(bytes(buf[a:b]) for a, b, _g in tail)
    if head_bytes is None:
        header = bytearray(buf[:h.size])
    else:
        header = head_bytes
    data_size = 50 + total * size
    file_size = len(header) + data_size + len(index)
    fp = h.fp
    struct.pack_into("<Q", header, fp + 40, file_size)
    struct.pack_into("<Q", header, fp + 56, total)
    play = round(end_ms * 10000)
    struct.pack_into("<QQ", header, fp + 64, play, max(0, play - h.preroll * 10000))
    data_head = DATA + struct.pack("<Q", data_size) + h.file_id + struct.pack("<Q", total) + b"\x01\x01"
    pieces: list = [bytes(header), data_head]
    for i, q in kept:
        pieces.append(rewrites[i] if i in rewrites else (q, q + size))
    if index:
        pieces.append(index)
    final = _merge(pieces)
    plan.repairable = True
    plan.build = lambda: final
    return plan
