"""MPEG transport streams (TS; M2TS and MTS from AVCHD camcorders and Blu-ray; TS with Reed-Solomon bytes; JVC
TOD): checking the stream and repairing it.

A transport stream is a run of packets of 188 bytes, each starting with the sync byte 0x47: a 13-bit packet id
(PID), a flag marking the start of a payload unit, a transport-error flag, a 4-bit continuity counter that goes
up by one with each packet of its PID, an optional adaptation field (clock references, random-access flag),
then the payload. AVCHD and Blu-ray put a 4-byte arrival time before each packet (192-byte units); some
broadcast captures keep the 16 Reed-Solomon bytes after each packet (204). PID 0 carries the PAT, which lists
the programs' tables (PMT); a PMT lists the program's streams (video, sound, subtitles) and their PIDs. The
streams' data are PES packets (with presentation times) cut into the payloads.

What is checked, and repaired in a new copy (in the file's own packet size):

=====================  ==========================================================================================
other data             before the first packet, between packets (the walk finds the packets again by their
                       sync bytes, one packet size apart) and after the last one: dropped.
damaged packets        a broken sync byte, an impossible header, the transport-error flag, a PID that appears
                       nowhere else: dropped and counted.
cut short              the incomplete last packet is dropped.
PAT/PMT missing        at the start (the start of the recording was lost): the first PAT and PMT found later are
                       copied to the front, or taken from a REFERENCE recording when there are none.
continuity gaps        reported as damaged stretches; players skip over them, lost packets can't come back.
=====================  ==========================================================================================

A stream that starts in the middle of a group of pictures is fine for players: it isn't cut.
"""

from __future__ import annotations

import bisect

from ..filerepair import Plan, _merge, _n
from ..fs.base import NULL_CONTROL, Control

SIZES = (188, 192, 204)
STREAM_TYPES = {0x01: "MPEG-1 video", 0x02: "MPEG-2 video", 0x03: "MPEG audio", 0x04: "MPEG audio",
                0x0F: "AAC", 0x10: "MPEG-4 video", 0x11: "AAC (LATM)", 0x1B: "H.264", 0x24: "H.265",
                0x42: "AVS video", 0x80: "LPCM", 0x81: "AC-3", 0x82: "DTS", 0x83: "TrueHD", 0x84: "E-AC-3",
                0x85: "DTS-HD", 0x86: "DTS-HD", 0x87: "E-AC-3", 0x90: "PGS subtitles", 0xEA: "VC-1",
                0x06: "private data"}
VIDEO_TYPES = {0x01, 0x02, 0x10, 0x1B, 0x24, 0x42, 0xEA}
_NEED = 6                                  # sync bytes in a row that make a packet stream


def _lead(size: int) -> int:
    return 4 if size == 192 else 0


def _synced(buf, p: int, size: int, end: int, need: int = _NEED) -> bool:
    """Sync bytes at P and NEED - 1 more packets on (fewer when the data ends first, but at least two)."""
    n = 0
    for k in range(need):
        q = p + k * size
        if q >= end:
            break
        if buf[q] != 0x47:
            return False
        n += 1
    return n >= min(need, 2) and (n == need or p + n * size >= end)


def find_layout(buf, start: int = 0, end: int | None = None, limit: int = 4 * 1024 * 1024) \
        -> tuple[int, int] | None:
    """The packet size and the offset of the first complete packet unit (for 192-byte units, of the arrival
    time before the sync byte), searching from START; None when there is no packet stream there."""
    end = len(buf) if end is None else end
    stop = min(end, start + limit)
    pos = start
    while pos < stop:
        p = buf.find(b"G", pos, stop)
        if p < 0:
            return None
        for size in SIZES:
            if _synced(buf, p, size, end, need=_NEED if end - p > _NEED * size else 3):
                unit = p - _lead(size)
                if unit < start:
                    unit += size
                return size, unit
        pos = p + 1
    return None


def detect_mpegts(head: bytes) -> bool:
    """True when HEAD (at least 1 KiB of the start) is a transport stream (188, 192 or 204-byte packets)."""
    head = bytes(head[:8192])
    layout = find_layout(head, 0, len(head), limit=len(head)) if len(head) >= 600 else None
    return layout is not None and layout[1] < 1024


def _sections(payload: bytes, pusi: bool) -> bytes:
    """The table section at the start of a PSI payload (after its pointer field)."""
    if not pusi or not payload:
        return b""
    return payload[1 + payload[0]:]


def parse_pat(section: bytes) -> dict[int, int]:
    """{program number: PMT PID} of a PAT section."""
    if len(section) < 12 or section[0] != 0x00:
        return {}
    length = ((section[1] & 0x0F) << 8) | section[2]
    out = {}
    body = section[8:min(len(section), 3 + length - 4)]
    for i in range(0, len(body) - 3, 4):
        prog = (body[i] << 8) | body[i + 1]
        pid = ((body[i + 2] & 0x1F) << 8) | body[i + 3]
        if prog:
            out[prog] = pid
    return out


def parse_pmt(section: bytes) -> tuple[int | None, dict[int, int]]:
    """(PCR PID, {elementary PID: stream type}) of a PMT section."""
    if len(section) < 16 or section[0] != 0x02:
        return None, {}
    length = ((section[1] & 0x0F) << 8) | section[2]
    stop = min(len(section), 3 + length - 4)
    pcr = ((section[8] & 0x1F) << 8) | section[9]
    p = 12 + (((section[10] & 0x0F) << 8) | section[11])
    out = {}
    while p + 5 <= stop:
        st = section[p]
        pid = ((section[p + 1] & 0x1F) << 8) | section[p + 2]
        es_len = ((section[p + 3] & 0x0F) << 8) | section[p + 4]
        out[pid] = st
        p += 5 + es_len
    return pcr, out


def _payload(pkt: bytes) -> bytes:
    """The payload of the 188-byte packet PKT (after the adaptation field)."""
    afc = (pkt[3] >> 4) & 3
    p = 4
    if afc & 2:
        p += 1 + pkt[4]
    return pkt[p:] if afc & 1 and p < 188 else b""


def _pts(payload: bytes) -> int | None:
    """The presentation time (90 kHz) of the PES packet starting PAYLOAD."""
    if len(payload) < 14 or payload[:3] != b"\x00\x00\x01" or payload[3] < 0xBC:
        return None
    if payload[6] & 0xC0 == 0x80 and payload[7] & 0x80:
        b = payload[9:14]
        return ((b[0] >> 1) & 7) << 30 | b[1] << 22 | (b[2] >> 1) << 15 | b[3] << 7 | b[4] >> 1
    return None


class _Walk:
    """One pass over the packets: which are kept, what was dropped, the tables and times seen."""

    def __init__(self, buf, end: int, size: int, ctl: Control):
        self.buf, self.end, self.size, self.lead, self.ctl = buf, end, size, _lead(size), ctl
        self.kept: list[tuple[int, int]] = []    # runs of good packet units [start, end)
        self.bad: list[int] = []                 # packets dropped one by one (in step with the others)
        self.junk: list[tuple[int, int]] = []    # stretches without packets in step
        self.pid_count: dict[int, int] = {}
        self.pid_first: dict[int, int] = {}      # PID → offset of its first packet
        self.pat: tuple[int, dict] | None = None # (offset, {program: PMT PID})
        self.pmts: dict[int, tuple[int, dict]] = {}
        self.pcr_pids: set[int] = set()
        self.cc_errors: list[int] = []           # packet offsets where a continuity counter jumps
        self.pts: dict[int, list[int]] = {}      # PID → [first PTS, last PTS, PES count]
        self.rai_pids: set[int] = set()          # PIDs whose key frames are marked (random access indicator)
        self.partial: int | None = None          # offset of an incomplete last packet
        self.trailing_from: int | None = None

    def _resync(self, pos: int) -> int | None:
        """The next unit start from POS where packets are in step again."""
        buf, end, size, lead = self.buf, self.end, self.size, self.lead
        p = pos + lead
        while True:
            q = buf.find(b"G", p, end)
            if q < 0:
                return None
            if _synced(buf, q, size, end):
                return q - lead
            p = q + 1

    def walk(self, pos: int) -> None:
        buf, end, size, lead = self.buf, self.end, self.size, self.lead
        last_cc: dict[int, int] = {}
        run_start = pos
        chunk_units = 32768
        n = 0
        while pos + size <= end:
            n += 1
            if n % 64 == 0:
                self.ctl.check()
                self.ctl.progress(pos / max(1, end), "Checking the packets")
            count = min(chunk_units, (end - pos) // size)
            chunk = bytes(buf[pos:pos + count * size])
            i = 0
            while i < count:
                o = i * size + lead
                b1, b2, b3 = chunk[o + 1], chunk[o + 2], chunk[o + 3]
                afc = (b3 >> 4) & 3
                ok = chunk[o] == 0x47 and not b1 & 0x80 and afc and \
                    (not afc & 2 or chunk[o + 4] <= (183 if afc == 2 else 182))
                at = pos + i * size
                if ok:
                    pid = ((b1 & 0x1F) << 8) | b2
                    self.pid_count[pid] = self.pid_count.get(pid, 0) + 1
                    if pid not in self.pid_first:
                        self.pid_first[pid] = at
                    if afc & 1 and pid != 0x1FFF:
                        cc = b3 & 0x0F
                        prev = last_cc.get(pid)
                        disc = afc & 2 and chunk[o + 4] and chunk[o + 5] & 0x80
                        if prev is not None and cc != (prev + 1) & 15 and cc != prev and not disc:
                            self.cc_errors.append(at)
                        last_cc[pid] = cc
                    if b1 & 0x40:
                        if afc & 2 and chunk[o + 4] and chunk[o + 5] & 0x40:
                            self.rai_pids.add(pid)
                        self._unit_start(pid, chunk[o:o + 188], at)
                    i += 1
                    continue
                # a bad packet: in step with the rest (damaged in place), or the stream is out of step here
                self.kept.append((run_start, at))
                nxt = at + size
                if (chunk[o] == 0x47 or nxt >= end or _synced(buf, nxt + lead, size, end, 3)) and nxt <= end:
                    self.bad.append(at)
                    run_start = nxt
                    i += 1
                    continue
                q = self._resync(at)
                if q is None:
                    self._finish(at)
                    return
                self.junk.append((at, q))
                run_start = q
                pos = q
                break
            else:
                pos += count * size
        self.kept.append((run_start, pos))
        self._finish(pos)

    def _finish(self, pos: int) -> None:
        if pos < self.end:
            sync = pos + self.lead
            if self.end - pos < self.size and sync < self.end and self.buf[sync] == 0x47:
                self.partial = pos
            else:
                self.trailing_from = pos
        self.kept = [(a, b) for a, b in self.kept if b > a]

    def _unit_start(self, pid: int, pkt: bytes, at: int) -> None:
        payload = _payload(pkt)
        if pid == 0:
            if self.pat is None:
                pat = parse_pat(_sections(payload, True))
                if pat:
                    self.pat = (at, pat)
            return
        if self.pat is not None and pid in self.pat[1].values():
            if pid not in self.pmts:
                pcr, streams = parse_pmt(_sections(payload, True))
                if streams:
                    self.pmts[pid] = (at, streams)
                    if pcr is not None:
                        self.pcr_pids.add(pcr)
            return
        t = _pts(payload)
        if t is not None:
            v = self.pts.get(pid)
            if v is None:
                self.pts[pid] = [t, t, 1, t]
            else:
                v[0] = min(v[0], t)
                v[1] = max(v[1], t)
                v[2] += 1
                v[3] = t

    def streams(self) -> dict[int, int]:
        out: dict[int, int] = {}
        for _at, s in self.pmts.values():
            out.update(s)
        return out


class _Packets:
    """The kept packet units (runs of [start, end)) one by one, forwards or backwards from an offset."""

    def __init__(self, buf, kept: list[tuple[int, int]], size: int):
        self.buf, self.kept, self.size, self.lead = buf, kept, size, _lead(size)
        self.starts = [a for a, _b in kept]

    def forward(self, pos: int, limit: int):
        i = max(0, bisect.bisect_right(self.starts, pos) - 1)
        n = 0
        for a, b in self.kept[i:]:
            at = max(a, pos)
            at = a + (at - a + self.size - 1) // self.size * self.size
            while at < b:
                yield at
                at += self.size
                n += 1
                if n >= limit:
                    return

    def backward(self, pos: int, limit: int):
        i = bisect.bisect_left(self.starts, pos)
        n = 0
        for a, b in reversed(self.kept[:i]):
            at = a + (min(b, pos) - a) // self.size * self.size - self.size
            while at >= a:
                yield at
                at -= self.size
                n += 1
                if n >= limit:
                    return

    def header(self, at: int) -> tuple[int, bool, int, bool]:
        """(PID, payload unit start, payload length, random access) of the packet unit at AT."""
        o = at + self.lead
        b = self.buf
        afc = (b[o + 3] >> 4) & 3
        alen = 1 + b[o + 4] if afc & 2 else 0
        rai = bool(afc & 2 and b[o + 4] and b[o + 5] & 0x40)
        return ((b[o + 1] & 0x1F) << 8) | b[o + 2], bool(b[o + 1] & 0x40), \
            (184 - alen if afc & 1 else 0), rai

    def pes_length(self, at: int) -> int:
        """The length a PES packet starting in the packet at AT declares (0: unbounded, -1: no PES there)."""
        o = at + self.lead
        b = self.buf
        afc = (b[o + 3] >> 4) & 3
        p = o + 4 + (1 + b[o + 4] if afc & 2 else 0)
        if p + 6 > o + 188 or bytes(b[p:p + 3]) != b"\x00\x00\x01":
            return -1
        return (b[p + 4] << 8) | b[p + 5]


_TRIM_WINDOW = 60000


def _trim_after(pk: _Packets, pos: int, es: set[int], video: set[int], rai: set[int], drop: set[int]) -> None:
    """After a gap at POS: drop each stream's packets until its next PES start (for video marked with key
    frames: the next key frame, or the end); a stream that doesn't start again within the window (far from
    the end) keeps its packets."""
    pending = set(es)
    mine: dict[int, list[int]] = {}
    seen = 0
    for at in pk.forward(pos, _TRIM_WINDOW):
        seen += 1
        if at in drop:
            continue
        pid, pusi, _n, key = pk.header(at)
        if pid not in pending:
            continue
        if pusi and (pid not in video or pid not in rai or key):
            pending.discard(pid)
            if not pending:
                break
            continue
        mine.setdefault(pid, []).append(at)
    for pid, ats in mine.items():
        if pid not in pending or seen < _TRIM_WINDOW:
            drop.update(ats)


def _trim_before(pk: _Packets, pos: int, es: set[int], drop: set[int], unbounded_too: bool) -> int:
    """Before a gap at POS: drop each stream's PES packet that the gap cut off (a PES that says its length and
    is all there stays; one that doesn't say it is dropped when UNBOUNDED_TOO). Returns how many PESs."""
    pending = set(es)
    mine: dict[int, list[int]] = {}
    got: dict[int, int] = {}
    cut = 0
    for at in pk.backward(pos, _TRIM_WINDOW):
        if at in drop:
            continue
        pid, pusi, n, _key = pk.header(at)
        if pid not in pending:
            continue
        mine.setdefault(pid, []).append(at)
        got[pid] = got.get(pid, 0) + n
        if pusi:
            pending.discard(pid)
            length = pk.pes_length(at)
            if (length > 0 and got[pid] < 6 + length) or (length == 0 and unbounded_too):
                drop.update(mine[pid])
                cut += 1
            if not pending:
                break
    return cut


def _reference_tables(reference) -> tuple[list[bytes], dict[int, int], str]:
    """The first PAT packet and its PMT packets of the REFERENCE recording (188 bytes each), its streams, and
    "" or why it can't be used."""
    try:
        with open(reference, "rb") as f:
            data = f.read(32 * 1024 * 1024)
    except OSError as exc:
        return [], {}, exc.strerror or str(exc)
    layout = find_layout(data)
    if layout is None:
        return [], {}, "it isn't an MPEG transport stream"
    size, first = layout
    w = _Walk(data, len(data), size, NULL_CONTROL)
    w.walk(first)
    if w.pat is None or not w.pmts:
        return [], {}, "it has no program tables either"
    lead = _lead(size)
    pkts = [data[w.pat[0] + lead:w.pat[0] + lead + 188]]
    for pid in w.pat[1].values():
        if pid in w.pmts:
            at = w.pmts[pid][0]
            pkts.append(data[at + lead:at + lead + 188])
    return pkts, w.streams(), ""


def _span(pts: dict[int, list[int]], streams: dict[int, int]) -> float:
    """Seconds from the first to the last presentation time of the main stream (video if there is one)."""
    pids = [p for p in pts if pts[p][2] > 1]
    if not pids:
        return 0.0
    video = [p for p in pids if streams.get(p) in VIDEO_TYPES]
    pid = max(video or pids, key=lambda p: pts[p][2])
    first, last, count, _ = pts[pid]
    span = last - first
    if span < 0 or span > 90000 * 86400:
        return 0.0
    return (span + span / max(1, count - 1)) / 90000


def plan_mpegts(buf, path="", reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    """Check an MPEG transport stream and plan its repair (see the module docstring)."""
    end = len(buf)
    ext = str(path).lower().rsplit(".", 1)[-1] if "." in str(path) else ""
    plan = Plan(ext if ext in ("ts", "m2ts", "mts", "m2t", "tod", "trp", "tp") else "ts")
    start = max(0, min(end, int(data_offset or 0)))
    layout = find_layout(buf, start, end)
    if layout is None:
        layout = find_layout(buf, start, end, limit=64 * 1024 * 1024)
    if layout is None:
        from . import mpegps
        if mpegps.find_pack(buf, start, min(end, start + 4 * 1024 * 1024)) is not None:
            return mpegps.plan_mpegps(buf, path, reference, data_offset, ctl)
        plan.problem("No MPEG transport stream packets were found" if end else "The file is empty")
        plan.note = "The file isn't a transport stream, or its data is damaged everywhere."
        return plan
    size, first = layout
    lead = _lead(size)
    w = _Walk(buf, end, size, ctl)
    w.walk(first)
    streams = w.streams()
    ref_tables: tuple[list[bytes], dict[int, int], str] | None = None
    if (w.pat is None or not w.pmts) and reference is not None:
        ref_tables = _reference_tables(reference)
        if not ref_tables[2] and set(ref_tables[1]) & set(w.pid_count):
            streams = ref_tables[1]
    # packets of a PID found nowhere else, among damaged ones: junk that happened to have a sync byte
    known = {0, 0x1FFF} | set(streams) | set(w.pmts) | w.pcr_pids | set(range(0x10, 0x20))
    if w.pat is not None:
        known |= set(w.pat[1].values())
    stray = {pid for pid, c in w.pid_count.items() if c <= 2 and pid not in known}
    pk = _Packets(buf, w.kept, size)
    stray_packets: set[int] = set()
    if stray:
        for at in sorted(set(w.bad) | {a for a, _b in w.junk}):
            for q in pk.forward(max(0, at - 64 * size), 192):
                if pk.header(q)[0] in stray:
                    stray_packets.add(q)
    drop = set(stray_packets)
    # the frames the gaps cut into: at the start, around each damaged stretch, at a cut-short end
    es = set(streams) or {pid for pid in w.pts}
    video = {pid for pid, st in streams.items() if st in VIDEO_TYPES}
    gaps = sorted([(at, at + size) for at in set(w.bad) | stray_packets] + w.junk)
    trimmed = 0
    if w.kept:
        before = len(drop)
        _trim_after(pk, w.kept[0][0], es, video, w.rai_pids, drop)
        trimmed += len(drop) - before
    for a, b in gaps:
        before = len(drop)
        _trim_before(pk, a, es, drop, True)
        _trim_after(pk, b, es, video, w.rai_pids, drop)
        trimmed += len(drop) - before
    end_cut = 0
    if w.kept:
        before = len(drop)
        end_cut = _trim_before(pk, w.kept[-1][1], es, drop, w.partial is not None)
        trimmed += len(drop) - before
    kept = w.kept
    if drop:
        order = sorted(drop)
        new: list[tuple[int, int]] = []
        j = 0
        for a, b in kept:
            s = a
            while j < len(order) and order[j] < a:
                j += 1
            while j < len(order) and order[j] < b:
                new.append((s, order[j]))
                s = order[j] + size
                j += 1
            new.append((s, b))
        kept = [(a, b) for a, b in new if b > a]
    packets = sum((b - a) // size for a, b in kept)
    duration = _span(w.pts, streams)
    plan.info.update(packet_size=size, packets=packets, duration=round(duration, 3),
                     streams=[f"{pid:#x}: {STREAM_TYPES.get(st, f'type {st:#x}')}" for pid, st in sorted(streams.items())])
    if packets == 0:
        plan.problem("No intact packets were found")
        plan.note = "The stream is damaged everywhere."
        return plan

    # ---- the problems
    if first > start:
        plan.problem(f"{_n(first - start)} of other data come before the first packet", f"Cut the {_n(first - start)}")
    drops = gaps
    stretches: list[list[int]] = []
    for a, b in drops:
        if stretches and a - stretches[-1][1] < 64 * size:
            stretches[-1][1] = max(stretches[-1][1], b)
        else:
            stretches.append([a, b])
    if stretches:
        lost = sum(b - a for a, b in drops)
        k = len(stretches)
        plan.problem(f"{k} damaged stretch{'es' if k > 1 else ''} in the stream ({_n(lost)})",
                     "Drop the damaged packets (players skip over the gap)")
        plan.info.update(dropped_packets=len(w.bad) + len(stray_packets), dropped_bytes=lost)
    if w.partial is not None:
        plan.problem("The file is cut short in its last packet", "Drop the incomplete last packet and frames")
    elif end_cut and w.trailing_from is None:
        plan.problem("The file is cut short: its last frames are incomplete", "Drop the incomplete last frames")
    if trimmed:
        plan.info["trimmed_packets"] = trimmed
    if w.trailing_from is not None:
        n = end - w.trailing_from
        plan.problem(f"{_n(n)} of other data come after the last packet", f"Cut the {_n(n)} at the end")
    gaps = 0
    last = -1 << 40
    for at in sorted(set(w.cc_errors)):
        if any(0 <= at - b <= 4096 * size for _a, b in stretches):
            continue                               # the packets dropped above
        if at - last > 64 * size:
            gaps += 1
        last = at
    if gaps:
        plan.problem(f"Packets are missing in {gaps} place{'s' if gaps > 1 else ''} (players skip over them)")
        plan.info["gaps"] = gaps
    front: list = []
    es = [pid for pid in streams if pid in w.pid_first]
    first_es = min((w.pid_first[p] for p in es), default=None)
    if w.pat is not None and w.pmts:
        late = first_es is not None and (w.pat[0] > first_es or min(at for at, _s in w.pmts.values()) > first_es)
        if late:
            plan.problem("The program tables (PAT/PMT) don't come first: the start of the recording was lost",
                         "Copy the program tables to the front")
            front = [(w.pat[0] + lead, w.pat[0] + lead + 188)]
            for pid in w.pat[1].values():
                if pid in w.pmts:
                    at = w.pmts[pid][0]
                    front.append((at + lead, at + lead + 188))
    else:
        found = {pid for pid in w.pid_count if pid not in (0, 0x1FFF) and pid >= 0x20}
        if reference is None:
            plan.problem("The program tables (PAT/PMT) are missing: players may not find the video and sound")
            plan.note = ("The start of the recording, where the program tables were, is lost and no reference was "
                         "given: repair it with a reference recording made by the same camera with the same "
                         "settings. ")
        else:
            pkts, ref_streams, why = ref_tables or ([], {}, "")
            if why:
                plan.problem("The program tables (PAT/PMT) are missing: players may not find the video and sound")
                plan.note = f"The reference recording can't be used: {why}. "
            elif not set(ref_streams) & found:
                plan.problem("The program tables (PAT/PMT) are missing: players may not find the video and sound")
                plan.note = ("The reference recording's streams (" + ", ".join(f"{p:#x}" for p in sorted(ref_streams))
                             + ") aren't the ones in this file: use a reference made by the same camera with the "
                             "same settings. ")
            else:
                plan.problem("The program tables (PAT/PMT) are missing",
                             "Put the reference recording's program tables in front")
                front = pkts
                streams = ref_streams
                plan.info["streams"] = [f"{pid:#x}: {STREAM_TYPES.get(st, f'type {st:#x}')}"
                                        for pid, st in sorted(streams.items())]
    fixable = [p for p in plan.problems if not p.startswith("Packets are missing") and not
               p.startswith("The program tables (PAT/PMT) are missing:")]
    if not fixable:
        if plan.problems and not plan.note:
            plan.note = "RecoverAll can't bring back lost packets."
        return plan

    # ---- the copy
    pieces: list = []
    if front:
        first_unit = kept[0][0]
        for p in front:
            pkt = bytes(buf[p[0]:p[1]]) if isinstance(p, tuple) else p
            if size == 192:
                pieces.append(bytes(buf[first_unit:first_unit + 4]) + pkt)
            elif size == 204:
                pieces.append(pkt + (bytes(buf[p[1]:p[1] + 16]) if isinstance(p, tuple) else bytes(16)))
            else:
                pieces.append(pkt)
    pieces += kept
    final = _merge(pieces)
    plan.repairable = True
    plan.build = lambda: final
    return plan
