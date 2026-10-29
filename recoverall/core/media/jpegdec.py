"""JPEG picture data decoded far enough to check it: where the data stops being valid, and how much of the
photo decoded. Nothing is turned into pixels.

A JPEG file is a header and then one or more scans of entropy-coded data. The header holds the quantisation
tables (DQT), the Huffman tables (DHT), the frame (SOF: the picture size and, for every colour component, its
sampling factors) and the restart interval (DRI). The picture is cut into 8×8 blocks per component, grouped
into MCUs (minimum coded units: four luma blocks and one block of each chroma component for 4:2:0
subsampling). For every block the scan holds Huffman codes: the difference of its DC coefficient from the
previous block's of the same component, then the AC coefficients as (run of zeros, size) codes each followed
by that many value bits, up to an end-of-block code. Every 0xFF byte of the data is followed by a stuffed
0x00, and with a restart interval the encoder ends every N MCUs at a byte boundary, writes a marker RST0..RST7
(cycling) and starts the DC prediction afresh. A baseline photo has one scan with every component; a
progressive photo has several: first the DC coefficients of every block, then bands of AC coefficients, then
refinement bits, with runs of empty blocks coded at once (EOB runs).

Decoding validates the data: random or foreign data soon gives a code that isn't in the tables, more than 63
coefficients in a block, a DC value no 8×8 block can have, or a restart marker out of turn.
:func:`decode_check` says where the data stops being valid, why, and how far decoding got. To be fast in
pure Python the codes are looked up 16 bits at a time in tables that also hold the value bits (DC) or the
next code (AC), the value bits of AC coefficients are skipped rather than read, and the bit stream is read
through 32-bit words at every other byte.

    res = decode_check(data)
    res.ok, res.mcus_decoded, res.mcus_total, res.error_offset, res.error_reason

A fragmented photo is put back together with checkpoints: :meth:`Result.checkpoint` is the decoder's state
at the last MCU that starts before a byte (its bit position, the DC predictors, the restart counter and the
EOB run), :meth:`Result.probe` decodes other bytes from such a state for a number of MCUs (does the photo
go on in this cluster?) and :meth:`Result.resume` carries on decoding from it over new data.
"""

from __future__ import annotations

import re
import struct
import time
from array import array
from dataclasses import dataclass, field
from functools import lru_cache

# why decoding stopped
ERR_HUFFMAN = "huffman"
ERR_INDEX = "index"
ERR_RANGE = "range"
ERR_RESTART = "restart"
ERR_MARKER = "marker"
ERR_CUT = "cut"
ERR_EARLY_END = "early-end"
ERR_EXTRA = "extra"
ERR_HEADER = "header"
ERR_UNSUPPORTED = "unsupported"
_PAUSE = "pause"

REASONS = {
    ERR_HUFFMAN: "a code that isn't in the Huffman tables",
    ERR_INDEX: "more than 64 coefficients in a block",
    ERR_RANGE: "a value no 8×8 block can have",
    ERR_RESTART: "a restart marker missing or out of turn",
    ERR_MARKER: "another marker in the middle of the picture data",
    ERR_CUT: "the data ends before the picture does",
    ERR_EARLY_END: "the end-of-image marker comes before the end of the picture",
    ERR_EXTRA: "more data than the picture needs",
    ERR_HEADER: "the header is damaged",
    ERR_UNSUPPORTED: "a kind of JPEG that isn't checked (arithmetic coding, lossless or hierarchical)",
}

_NOT_STUFFED = re.compile(rb"\xff(?!\x00)")
_WINDOW = 256 * 1024             # bytes of unstuffed data turned into words at a time
_SLACK = 8 * 1024                # an MCU that starts inside the window may run this far past it
_PAD = bytes(64)                 # zeros after the data (an MCU that runs further is cut: IndexError)
_INVALID = 256 << 5              # an AC table entry for a code that isn't there
_SOF_SUPPORTED = {0xC0: False, 0xC1: False, 0xC2: True}       # marker: progressive
_SOF_OTHER = {0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}

# The standard Huffman tables of JPEG Annex K.3 (what MJPEG frames leave out): (class<<4 | id, bits, values).
STANDARD_TABLES = (
    (0x00, bytes((0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0)), bytes(range(12))),
    (0x10, bytes((0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7D)), bytes.fromhex(
        "01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a"
        "3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a9293"
        "9495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7"
        "e8e9eaf1f2f3f4f5f6f7f8f9fa")),
    (0x01, bytes((0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0)), bytes(range(12))),
    (0x11, bytes((0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77)), bytes.fromhex(
        "000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a2627"
        "28292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a"
        "92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7"
        "e8e9eaf2f3f4f5f6f7f8f9fa")),
)


# ---------------------------------------------------------------------- the picture's structure
@dataclass(slots=True)
class Component:
    cid: int
    h: int                      # sampling factors
    v: int
    tq: int                     # quantisation table
    bw: int = 0                 # blocks across and down (what a scan of this component alone holds)
    bh: int = 0


@dataclass(slots=True)
class Frame:
    marker: int                 # 0xC0 baseline, 0xC1 extended, 0xC2 progressive
    precision: int
    width: int
    height: int
    comps: list[Component]
    hmax: int = 1
    vmax: int = 1
    mcux: int = 0               # MCUs across and down
    mcuy: int = 0

    @property
    def progressive(self) -> bool:
        return self.marker == 0xC2

    @property
    def mcus(self) -> int:
        return self.mcux * self.mcuy


@dataclass(slots=True)
class ScanInfo:
    """One scan: its SOS header at ``offset``, its data from ``data`` to ``end`` (the marker after it, or
    where decoding stopped). ``total`` MCUs (blocks for a scan of one component), ``decoded`` of them valid."""
    offset: int
    data: int
    end: int
    comps: tuple[int, ...]
    ss: int
    se: int
    ah: int
    al: int
    total: int
    decoded: int = 0
    complete: bool = False


@dataclass(slots=True)
class Checkpoint:
    """The decoder's state at the start of MCU ``mcu`` of scan ``scan``: its first bit is bit ``bit``
    (0 = the most significant) of the byte at ``offset``."""
    scan: int
    mcu: int
    offset: int
    bit: int
    preds: tuple[int, ...]
    eobrun: int


@dataclass
class Probe:
    """What decoding other data from a checkpoint gave: ``mcus`` valid MCUs, ending at bit ``end_bit`` of the
    data (or the error at ``error_bit``); ``dc`` is the luma DC value after each of them (sequential scans)."""
    mcus: int
    end_bit: int
    error: str
    error_bit: int
    dc: list[int] = field(default_factory=list)
    scan_done: bool = False
    preds: tuple[int, ...] = ()           # the DC predictors after the valid MCUs
    dcs: list[tuple[int, ...]] = field(default_factory=list)    # every component's DC after each MCU


@dataclass
class Result:
    """What :func:`decode_check` found. Offsets are in the decoded buffer."""
    ok: bool = False                      # every scan valid and complete, up to the end-of-image marker
    supported: bool = True
    frame: Frame | None = None
    mcus_total: int = 0                   # MCUs of the picture
    mcus_decoded: int = 0                 # valid MCUs of the scan decoding stopped in (the picture, if baseline)
    error: str = ""                       # one of the ERR_ codes, "" when ok
    error_offset: int | None = None       # where the data stops being valid
    eoi_offset: int | None = None         # the end-of-image marker, when reached
    good_end: int = 0                     # the last valid MCU ends at bit good_bit of the byte at good_end
    good_bit: int = 0
    scans: list[ScanInfo] = field(default_factory=list)
    complete_scans: int = 0
    restart_interval: int = 0
    restarts: int = 0                     # restart markers passed
    header_end: int = 0                   # where the first scan's data starts
    dc_jumps: int = 0                     # MCUs whose luma DC jumps by more than a quarter of its range
    preds: tuple[int, ...] = ()           # the DC predictors after the last valid MCU
    seconds: float = 0.0
    _dec: _Decoder | None = field(default=None, repr=False)

    @property
    def error_reason(self) -> str:
        return REASONS.get(self.error, "")

    @property
    def progressive(self) -> bool:
        return bool(self.frame and self.frame.progressive)

    @property
    def fraction(self) -> float:
        """How much of the picture decoded (baseline: the share of its MCUs; 1.0 when ok)."""
        if self.ok:
            return 1.0
        if not self.scans or not self.mcus_total:
            return 0.0
        s = self.scans[-1]
        return s.decoded / s.total if s.total else 0.0

    def checkpoint(self, offset: int) -> Checkpoint | None:
        """The state at the last MCU of the scan decoding stopped in that starts before byte OFFSET, or None
        (OFFSET isn't in that scan's data)."""
        return self._dec.checkpoint(offset) if self._dec else None

    def probe(self, cp: Checkpoint, data, limit: int = 64, bits: int = 0) -> Probe:
        """Decode DATA (bytes that start with the checkpoint's byte) from checkpoint CP for LIMIT MCUs —
        and on until BITS bits of data are used (EOB runs code many blocks in a few bits) —, without
        changing this result."""
        return self._dec.probe(cp, data, limit, bits) if self._dec else Probe(0, 0, ERR_HEADER, 0)

    def resume(self, cp: Checkpoint, buf, start: int, end: int | None = None) -> Result:
        """Go back to checkpoint CP and carry on decoding BUF from byte START (where CP's byte now is): the
        decoder's view is "the data up to CP, then BUF from START". Returns this result, updated."""
        if self._dec is None:
            return self
        return self._dec.resume(cp, buf, start, len(buf) if end is None else end)

    def grey(self, mcus: int, preds: tuple[int, ...] | None = None, prefix: tuple[int, int] = (0, 0)) -> bytes | None:
        """MCUs of flat mid-grey for the first scan, Huffman-coded with the photo's own tables, padded and
        stuffed (None when its tables can't code them). PREDS: the DC predictors to start from; PREFIX:
        (value, number of bits) already in the first byte (grey that continues a cut MCU stream)."""
        return self._dec.grey(mcus, preds, prefix) if self._dec else None


# ---------------------------------------------------------------------- Huffman tables
def _codes(bits: bytes, vals: bytes) -> list[tuple[int, int, int]] | None:
    """(length, code, symbol) of a canonical Huffman table; None if the counts don't make a prefix code."""
    out = []
    code = 0
    k = 0
    for length in range(1, 17):
        for _ in range(bits[length - 1]):
            if code >= 1 << length or k >= len(vals):
                return None
            out.append((length, code, vals[k]))
            code += 1
            k += 1
        code <<= 1
    return out


@lru_cache(maxsize=64)
def _dc_lut(bits: bytes, vals: bytes, maxs: int) -> list[int] | None:
    """16-bit lookahead → (bits used | (difference + 32768) << 5) for a DC code and its value bits; a
    negative entry -(code length | size << 5) when they don't fit in 16 bits; 0 for no code."""
    codes = _codes(bits, vals)
    if codes is None:
        return None
    lut = [0] * 65536
    for length, code, s in codes:
        if s > maxs:
            continue
        if length + s <= 16:
            free = 16 - length - s
            for v in range(1 << s):
                diff = v if s == 0 or v >> (s - 1) else v - (1 << s) + 1
                a = ((code << s) | v) << free
                lut[a:a + (1 << free)] = [(length + s) | ((diff + 0x8000) << 5)] * (1 << free)
        else:
            a = code << (16 - length)
            lut[a:a + (1 << (16 - length))] = [-(length | (s << 5))] * (1 << (16 - length))
    return lut


@lru_cache(maxsize=64)
def _ac_lut(bits: bytes, vals: bytes, maxs: int) -> list[int] | None:
    """16-bit lookahead → an AC code of a sequential scan, and the next one when both fit: bits used
    (0-4), how far the coefficient index moves (5-13: run + 1, 16 for sixteen zeros, 128 for end of block,
    256 for no code), and the same two for the first code alone (14-18, 19-27)."""
    codes = _codes(bits, vals)
    if codes is None:
        return None
    lut = [_INVALID] * 65536

    def single(length: int, sym: int) -> tuple[int, int]:
        r, s = sym >> 4, sym & 15
        if sym == 0:
            return length, 128
        if s == 0:
            return (length, 16) if r == 15 else (0, 256)
        if s > maxs:
            return 0, 256
        return length + s, r + 1

    singles = [(length, code, *single(length, sym)) for length, code, sym in codes]
    usable = [(length, code, c, a) for length, code, c, a in singles if a != 256]
    for length, code, c1, a1 in usable:
        a = code << (16 - length)
        lut[a:a + (1 << (16 - length))] = [c1 | (a1 << 5) | (c1 << 14) | (a1 << 19)] * (1 << (16 - length))
        if a1 == 128 or c1 > 14:
            continue
        rem = 16 - c1
        for v in range(1 << (c1 - length)):
            prefix = ((code << (c1 - length)) | v) << rem
            for length2, code2, c2, a2 in usable:
                if c2 > rem:
                    continue
                b = prefix | (code2 << (rem - length2))
                n = 1 << (rem - length2)
                lut[b:b + n] = [(c1 + c2) | ((a1 + a2) << 5) | (c1 << 14) | (a1 << 19)] * n
    return lut


@lru_cache(maxsize=64)
def _sym_lut(bits: bytes, vals: bytes) -> list[int] | None:
    """16-bit lookahead → code length | symbol << 5 (0: no code), for progressive AC scans."""
    codes = _codes(bits, vals)
    if codes is None:
        return None
    lut = [0] * 65536
    for length, code, sym in codes:
        a = code << (16 - length)
        lut[a:a + (1 << (16 - length))] = [length | (sym << 5)] * (1 << (16 - length))
    return lut


def _encoder(bits: bytes, vals: bytes) -> dict[int, tuple[int, int]]:
    """symbol → (code length, code)."""
    return {sym: (length, code) for length, code, sym in (_codes(bits, vals) or [])}


def _words(u) -> list[int]:
    """The 32-bit big-endian word at every even byte of U (zero padded): bit P is in word P >> 4."""
    pad = bytes(u) + _PAD
    m = len(pad) // 4 - 1
    w = [0] * (2 * m)
    w[0::2] = struct.unpack_from(f">{m}I", pad, 0)
    w[1::2] = struct.unpack_from(f">{m}I", pad, 2)
    return w


# ---------------------------------------------------------------------- the decoding loops
# Each decodes up to N MCUs from bit P of 32-bit words W (NBITS bits of data), recording every MCU's first bit
# (and the DC predictors or the EOB run there), and pauses at an MCU boundary at or past bit STOP. They return
# (MCUs decoded, bit where the last good one ends, bit of the error, "" / an error code / _PAUSE).
def _seq(W, nbits, p, n, stop, plan, preds, rec_p, rec_d):
    """A sequential (baseline or extended) scan."""
    done = 0
    nd = len(rec_d)
    while done < n:
        start = p
        rec_p.append(p)
        for i in range(nd):
            rec_d[i].append(preds[i])
        for dc, ac, ci, lim in plan:
            e = dc[(W[p >> 4] >> (16 - (p & 15))) & 0xFFFF]
            if e > 0:
                p += e & 31
                v = preds[ci] + (e >> 5) - 0x8000
            elif e < 0:
                e = -e
                p += e & 31
                s = e >> 5
                b = ((W[p >> 4] >> (16 - (p & 15))) & 0xFFFF) >> (16 - s)
                p += s
                v = preds[ci] + (b if b >> (s - 1) else b - (1 << s) + 1)
            else:
                return done, start, p, ERR_HUFFMAN
            if not -lim <= v <= lim:
                return done, start, p, ERR_RANGE
            preds[ci] = v
            k = 1
            while k < 64:
                e = ac[(W[p >> 4] >> (16 - (p & 15))) & 0xFFFF]
                p += e & 31
                k += (e >> 5) & 511
            if k != 64:
                k1 = k - ((e >> 5) & 511) + ((e >> 19) & 511)
                if k1 >= 64:                        # the first code of the pair ended the block
                    p -= (e & 31) - ((e >> 14) & 31)
                    k = k1
                if k >= 257:
                    return done, start, p, ERR_HUFFMAN
                if k < 128 and k != 64:
                    return done, start, p, ERR_INDEX
        if p > nbits:
            return done, start, nbits, ERR_CUT
        done += 1
        if p >= stop:
            return done, p, p, _PAUSE
    return done, p, p, ""


def _dc_first(W, nbits, p, n, stop, plan, preds, rec_p, rec_d):
    """The first pass of a progressive DC scan: _seq without the AC codes."""
    done = 0
    nd = len(rec_d)
    while done < n:
        start = p
        rec_p.append(p)
        for i in range(nd):
            rec_d[i].append(preds[i])
        for dc, ci, lim in plan:
            e = dc[(W[p >> 4] >> (16 - (p & 15))) & 0xFFFF]
            if e > 0:
                p += e & 31
                v = preds[ci] + (e >> 5) - 0x8000
            elif e < 0:
                e = -e
                p += e & 31
                s = e >> 5
                b = ((W[p >> 4] >> (16 - (p & 15))) & 0xFFFF) >> (16 - s)
                p += s
                v = preds[ci] + (b if b >> (s - 1) else b - (1 << s) + 1)
            else:
                return done, start, p, ERR_HUFFMAN
            if not -lim <= v <= lim:
                return done, start, p, ERR_RANGE
            preds[ci] = v
        if p > nbits:
            return done, start, nbits, ERR_CUT
        done += 1
        if p >= stop:
            return done, p, p, _PAUSE
    return done, p, p, ""


def _ac_first(W, nbits, p, n, stop, lut, ss, se, maxs, hist, hb, eobrun, rec_p, rec_e):
    """The first pass of a progressive AC scan (one component, a block per MCU). HIST[HB] is the current
    block's mask of nonzero coefficients (bit k: coefficient k); every coefficient that becomes nonzero is
    added. Also returns the EOB run left."""
    done = 0
    while done < n:
        start = p
        rec_p.append(p)
        rec_e.append(eobrun)
        if eobrun:
            eobrun -= 1
        else:
            k = ss
            m = hist[hb]
            while k <= se:
                e = lut[(W[p >> 4] >> (16 - (p & 15))) & 0xFFFF]
                if not e:
                    return done, start, p, ERR_HUFFMAN, eobrun
                p += e & 31
                r = e >> 9
                s = (e >> 5) & 15
                if s:
                    k += r
                    if k > se:
                        return done, start, p, ERR_INDEX, eobrun
                    if s > maxs:
                        return done, start, p, ERR_RANGE, eobrun
                    p += s
                    m |= 1 << k
                    k += 1
                elif r == 15:
                    k += 16
                    if k > se + 1:
                        return done, start, p, ERR_INDEX, eobrun
                else:
                    if r:
                        eobrun = (1 << r) + (((W[p >> 4] >> (16 - (p & 15))) & 0xFFFF) >> (16 - r)) - 1
                        p += r
                    break
            hist[hb] = m
        hb += 1
        if p > nbits:
            return done, start, nbits, ERR_CUT, eobrun
        done += 1
        if p >= stop:
            return done, p, p, _PAUSE, eobrun
    return done, p, p, "", eobrun


def _ac_refine(W, nbits, p, n, stop, lut, ss, se, hist, hb, eobrun, rec_p, rec_e):
    """A progressive AC refinement scan: a correction bit for every coefficient that is already nonzero, and
    new coefficients of ±1 placed among the zero ones (HIST as for _ac_first)."""
    done = 0
    band = ((1 << (se + 1)) - 1) ^ ((1 << ss) - 1)
    while done < n:
        start = p
        rec_p.append(p)
        rec_e.append(eobrun)
        k = ss
        m = hist[hb]
        if not eobrun:
            while k <= se:
                e = lut[(W[p >> 4] >> (16 - (p & 15))) & 0xFFFF]
                if not e:
                    return done, start, p, ERR_HUFFMAN, eobrun
                p += e & 31
                r = e >> 9
                s = (e >> 5) & 15
                if s:
                    if s != 1:
                        return done, start, p, ERR_RANGE, eobrun
                    p += 1
                elif r != 15:
                    eobrun = 1 << r
                    if r:
                        eobrun += ((W[p >> 4] >> (16 - (p & 15))) & 0xFFFF) >> (16 - r)
                        p += r
                    break
                # past r zero coefficients (a correction bit for each nonzero one met) to the (r+1)-th zero
                x = (~m & band) >> k
                for _ in range(r):
                    x &= x - 1
                if not x:
                    if s:
                        return done, start, p, ERR_INDEX, eobrun
                    p += ((m & band) >> k).bit_count()
                    k = se + 1
                    break
                low = x & -x
                p += ((m >> k) & (low - 1)).bit_count()
                k += low.bit_length() - 1
                if s:
                    m |= 1 << k
                k += 1
        if eobrun:
            if k <= se:
                p += ((m & band) >> k).bit_count()
            eobrun -= 1
        hist[hb] = m
        hb += 1
        if p > nbits:
            return done, start, nbits, ERR_CUT, eobrun
        done += 1
        if p >= stop:
            return done, p, p, _PAUSE, eobrun
    return done, p, p, "", eobrun


# ---------------------------------------------------------------------- the decoder
class _Scan:
    """A scan's decoding context and state. ``segs``: the stretches of data decoded so far (one per restart
    interval, and one more per resume), as (buffer offset, its end, first MCU, bit of the first MCU)."""

    __slots__ = ("info", "kind", "plan", "lut", "comp", "total", "ri", "per_mcu", "mcu", "preds", "eobrun",
                 "rec_p", "rec_d", "rec_e", "segs", "maxs", "snapshot", "hist", "hbase", "next_p")

    def __init__(self, info: ScanInfo, kind: str, ncomp: int):
        self.info = info
        self.kind = kind                    # "seq", "dc", "dcr" (DC refinement), "ac", "acr" (AC refinement)
        self.plan: list = []
        self.lut = None
        self.comp = -1                      # the component of a one-component AC scan
        self.total = info.total
        self.ri = 0
        self.per_mcu = 1                    # bits per MCU of a DC refinement scan
        self.mcu = 0
        self.preds = [0] * ncomp
        self.eobrun = 0
        self.rec_p = array("q")             # every MCU's first bit, in its segment's unstuffed data
        self.rec_d = [array("i") for _ in range(ncomp)] if kind in ("seq", "dc") else []
        self.rec_e = array("i")
        self.segs: list[tuple[int, int, int, int]] = []
        self.maxs = 10
        self.snapshot: list[int] | None = None      # an AC scan's component history before this scan
        self.hist: list[int] | None = None          # per block, the mask of its nonzero coefficients
        self.hbase = 0                      # the block HIST[0] belongs to
        self.next_p = 0                     # the bit where the next MCU starts, in the last segment

    def fork(self, cp: Checkpoint, blocks: int) -> _Scan:
        """A copy at CP for trying out other data for up to BLOCKS MCUs (the history is copied)."""
        t = _Scan.__new__(_Scan)
        for name in _Scan.__slots__:
            setattr(t, name, getattr(self, name))
        t.info = ScanInfo(*(getattr(self.info, f) for f in ScanInfo.__slots__))
        t.mcu = cp.mcu
        t.preds = list(cp.preds) if cp.preds else [0] * len(self.preds)
        t.eobrun = cp.eobrun
        t.rec_p, t.rec_e = array("q"), array("i")
        t.rec_d = [array("i") for _ in self.rec_d]
        t.segs = []
        if self.hist is not None:
            lo, hi = cp.mcu, cp.mcu + blocks + 1
            src = self.snapshot if self.snapshot is not None else self.hist
            t.hist = src[lo:hi]
            t.hist.extend([0] * (hi - lo - len(t.hist)))
            t.hbase = cp.mcu
        return t


class _Decoder:
    def __init__(self):
        self.frame: Frame | None = None
        self.dc: dict[int, tuple[bytes, bytes]] = {}
        self.ac: dict[int, tuple[bytes, bytes]] = {}
        self.q: dict[int, tuple[int, ...]] = {}
        self.ri = 0
        self.had_dht = False
        self.hist: list[list[int]] = []
        self.scans: list[_Scan] = []
        self.res = Result(_dec=self)
        self.buf = b""
        self.first_tables: tuple | None = None

    def _fail(self, code: str, offset: int | None) -> Result:
        r = self.res
        r.error, r.error_offset, r.ok = code, offset, False
        if code == ERR_UNSUPPORTED:
            r.supported = False
        return r

    # ------------------------------------------------------------------ segments
    def segments(self, buf, pos: int, end: int, first: bool) -> tuple[int, str]:
        """Read segments from POS up to and including an SOS: (the offset after it, ""), (the EOI's offset,
        "eoi"), or (where, an error code). FIRST: the header before the first scan."""
        for _ in range(10000):
            while pos + 1 < end and buf[pos] == 0xFF and buf[pos + 1] == 0xFF:
                pos += 1
            if pos + 2 > end:
                return pos, ERR_CUT
            if buf[pos] != 0xFF:
                return pos, ERR_HEADER if first else ERR_MARKER
            mk = buf[pos + 1]
            if mk == 0xD9:
                return pos, "eoi"
            if first and (mk == 0xD8 or mk == 0x01 or 0xD0 <= mk <= 0xD7):
                pos += 2                                 # a second start marker, a stray restart marker
                continue
            if mk < 0xC0 or 0xD0 <= mk <= 0xD8:
                return pos, ERR_HEADER if first else ERR_MARKER
            if pos + 4 > end:
                return pos, ERR_CUT
            length = (buf[pos + 2] << 8) | buf[pos + 3]
            if length < 2:
                return pos, ERR_HEADER if first else ERR_MARKER
            if pos + 2 + length > end:
                return pos, ERR_CUT
            body = bytes(buf[pos + 4:pos + 2 + length])
            if mk == 0xC4:
                if not self._dht(body):
                    return pos, ERR_HEADER
            elif mk == 0xDB:
                if not self._dqt(body):
                    return pos, ERR_HEADER
            elif mk == 0xDD:
                if len(body) != 2:
                    return pos, ERR_HEADER
                self.ri = (body[0] << 8) | body[1]
            elif mk in _SOF_SUPPORTED or mk in _SOF_OTHER:
                if self.frame is not None:
                    return pos, ERR_HEADER if first else ERR_MARKER
                if mk in _SOF_OTHER:
                    return pos, ERR_UNSUPPORTED
                err = self._sof(mk, body)
                if err:
                    return pos, err
            elif mk == 0xDA:
                err = self._sos(pos, body, pos + 2 + length)
                return (pos + 2 + length, "") if not err else (pos, err)
            elif mk in (0xDC, 0xCC):                     # DNL, arithmetic conditioning
                return pos, ERR_UNSUPPORTED
            pos += 2 + length
        return pos, ERR_HEADER

    def _dht(self, body: bytes) -> bool:
        p = 0
        while p < len(body):
            if p + 17 > len(body):
                return False
            tc, th = body[p] >> 4, body[p] & 15
            bits = bytes(body[p + 1:p + 17])
            n = sum(bits)
            if tc > 1 or th > 3 or n > 256 or p + 17 + n > len(body):
                return False
            vals = bytes(body[p + 17:p + 17 + n])
            if _codes(bits, vals) is None:
                return False
            (self.ac if tc else self.dc)[th] = (bits, vals)
            self.had_dht = True
            p += 17 + n
        return True

    def _dqt(self, body: bytes) -> bool:
        p = 0
        while p < len(body):
            pq, tq = body[p] >> 4, body[p] & 15
            size = 64 * (1 + pq)
            if pq > 1 or tq > 3 or p + 1 + size > len(body):
                return False
            self.q[tq] = struct.unpack_from(">64H", body, p + 1) if pq else tuple(body[p + 1:p + 65])
            p += 1 + size
        return True

    def _sof(self, mk: int, body: bytes) -> str:
        if len(body) < 6:
            return ERR_HEADER
        prec, y, x, nf = struct.unpack_from(">BHHB", body)
        if prec not in (8, 12) or x == 0 or not 1 <= nf <= 4 or len(body) < 6 + 3 * nf:
            return ERR_HEADER
        if y == 0:
            return ERR_UNSUPPORTED                   # the height comes after the first scan (DNL)
        comps = []
        for i in range(nf):
            cid, hv, tq = body[6 + 3 * i:9 + 3 * i]
            h, v = hv >> 4, hv & 15
            if not 1 <= h <= 4 or not 1 <= v <= 4 or tq > 3:
                return ERR_HEADER
            comps.append(Component(cid, h, v, tq))
        if nf > 1 and sum(c.h * c.v for c in comps) > 10:
            return ERR_HEADER
        f = Frame(mk, prec, x, y, comps)
        f.hmax = max(c.h for c in comps)
        f.vmax = max(c.v for c in comps)
        f.mcux = -(-x // (8 * f.hmax))
        f.mcuy = -(-y // (8 * f.vmax))
        for c in comps:
            c.bw = -(-(-(-x * c.h // f.hmax)) // 8)
            c.bh = -(-(-(-y * c.v // f.vmax)) // 8)
        self.frame = f
        self.hist = [[] for _ in comps]
        self.res.frame = f
        self.res.mcus_total = f.mcus
        return ""

    def _tables(self, cls: int, th: int):
        """Huffman table TH of class CLS (0 DC, 1 AC); a photo without any DHT gets the standard ones."""
        t = (self.ac if cls else self.dc).get(th)
        if t is None and not self.had_dht and th < 2:
            std = STANDARD_TABLES[2 * th + cls]
            t = (std[1], std[2])
        return t

    def _lim(self, comp: Component) -> int:
        """The largest quantised DC value an 8×8 block of this component can have."""
        q = self.q.get(comp.tq)
        if not q or not q[0]:
            return 1 << 20
        return (1 << (self.frame.precision + 2)) // q[0] + 2

    def _sos(self, at: int, body: bytes, data: int) -> str:
        f = self.frame
        if f is None or len(body) < 1:
            return ERR_HEADER
        ns = body[0]
        if not 1 <= ns <= 4 or len(body) != 4 + 2 * ns:
            return ERR_HEADER
        idx: list[int] = []
        tabs = []
        for i in range(ns):
            cid, t = body[1 + 2 * i], body[2 + 2 * i]
            ci = next((j for j, c in enumerate(f.comps) if c.cid == cid), -1)
            if ci < 0 or ci in idx:
                return ERR_HEADER
            idx.append(ci)
            tabs.append((t >> 4, t & 15))
        ss, se, a = body[1 + 2 * ns], body[2 + 2 * ns], body[3 + 2 * ns]
        ah, al = a >> 4, a & 15
        if not f.progressive:
            if ss != 0 or se != 63 or a != 0:
                return ERR_HEADER
            kind = "seq"
        elif ss == 0:
            if se != 0:
                return ERR_HEADER
            kind = "dcr" if ah else "dc"
        else:
            if se < ss or se > 63 or ns != 1:
                return ERR_HEADER
            kind = "acr" if ah else "ac"
        if al > 13 or ah > 13:
            return ERR_HEADER
        if ns == 1:
            c = f.comps[idx[0]]
            total = c.bw * c.bh
        else:
            total = f.mcus
        info = ScanInfo(at, data, data, tuple(idx), ss, se, ah, al, total)
        sc = _Scan(info, kind, len(f.comps))
        sc.ri = self.ri
        sc.maxs = f.precision + 2
        if kind == "dcr":
            sc.per_mcu = 0
        for (td, ta), ci in zip(tabs, idx):
            c = f.comps[ci]
            nblk = c.h * c.v if ns > 1 else 1
            if kind == "dcr":
                sc.per_mcu += nblk
                continue
            if kind in ("ac", "acr"):
                at_ = self._tables(1, ta)
                sc.lut = _sym_lut(*at_) if at_ else None
                if sc.lut is None:
                    return ERR_HEADER
                continue
            dt = self._tables(0, td)
            lut = _dc_lut(*dt, f.precision + 3) if dt else None
            if lut is None:
                return ERR_HEADER
            lim = (self._lim(c) >> al) + 1
            if kind == "seq":
                at_ = self._tables(1, ta)
                alut = _ac_lut(*at_, sc.maxs) if at_ else None
                if alut is None:
                    return ERR_HEADER
                sc.plan += [(lut, alut, ci, lim)] * nblk
            else:
                sc.plan += [(lut, ci, lim)] * nblk
        if kind in ("ac", "acr"):
            sc.comp = idx[0]
            h = self.hist[sc.comp]
            if len(h) < total:
                h.extend([0] * (total - len(h)))
            sc.hist = h
            sc.snapshot = list(h)
        if not self.scans:
            self.first_tables = (tuple(tabs), tuple(idx))
        self.scans.append(sc)
        self.res.scans.append(info)
        return ""

    # ------------------------------------------------------------------ running
    def run(self, buf, pos: int, end: int, bit: int = 0) -> Result:
        """Decode from POS (bit BIT): the current scan's data, or the segments before the next scan."""
        t0 = time.perf_counter()
        self.buf = buf
        r = self.res
        r.ok, r.error, r.error_offset = False, "", None
        try:
            while True:
                sc = self.scans[-1] if self.scans else None
                if sc is not None and sc.mcu < sc.total:
                    pos, bit, err = self._scan(buf, sc, pos, end, bit, sc.total, True)
                    bit = 0
                    if err:
                        self._fail(err, pos)
                        break
                    sc.info.complete = True
                    r.complete_scans += 1
                    pos = self._after_scan(buf, pos, end)
                pos, what = self.segments(buf, pos, end, first=not self.scans)
                if what == "eoi":
                    r.eoi_offset = pos
                    if self.scans and self._covered():
                        r.ok = True
                        r.mcus_decoded = r.mcus_total
                    else:
                        self._fail(ERR_CUT if self.scans else ERR_HEADER, pos)
                    break
                if what:
                    self._fail(what, pos)
                    break
                if not r.header_end:
                    r.header_end = pos
                info = self.scans[-1].info
                info.data = info.end = pos
        except (IndexError, struct.error, ValueError, OverflowError, MemoryError):
            self._fail(ERR_HEADER, pos)
        r.restart_interval = self.ri
        r.seconds += time.perf_counter() - t0
        return r

    def _covered(self) -> bool:
        """Every component got its DC coefficients (sequential: all its data) from some scan."""
        seen: set[int] = set()
        for s in self.scans:
            if s.kind in ("seq", "dc"):
                seen.update(s.info.comps)
        return len(seen) == len(self.frame.comps)

    @staticmethod
    def _after_scan(buf, pos: int, end: int) -> int:
        """Past a restart marker right after a scan's last MCU (some encoders write one)."""
        if pos + 3 < end and buf[pos] == 0xFF and 0xD0 <= buf[pos + 1] <= 0xD7 and buf[pos + 2] == 0xFF and \
                buf[pos + 3] not in (0, 0xFF) and not 0xD0 <= buf[pos + 3] <= 0xD7:
            return pos + 2
        return pos

    def _scan(self, buf, sc: _Scan, pos: int, end: int, bit: int, upto: int, main: bool) -> tuple[int, int, str]:
        """Decode scan SC from POS (bit BIT) until MCU UPTO (or the end of the scan). Returns (the offset after
        its data — or where it stopped being valid —, the bit there, "" or an error code). MAIN: the decoder's
        own scan (else a fork trying out data: the result isn't touched)."""
        r = self.res
        upto = min(upto, sc.total)
        while sc.mcu < upto:
            m = _NOT_STUFFED.search(buf, pos, end)
            seg_end = m.start() if m else end
            want = upto - sc.mcu
            if sc.ri:
                want = min(want, sc.ri - sc.mcu % sc.ri)
            raw = bytes(buf[pos:seg_end])
            u = raw.replace(b"\xff\x00", b"\xff") if b"\xff" in raw else raw
            sc.segs.append((pos, seg_end, sc.mcu, bit))
            got, good, errbit, err = self._segment(sc, u, bit, want)
            sc.next_p = good
            sc.info.decoded = sc.mcu
            good_at = self._offset(pos, raw, u, good)
            if main:
                r.mcus_decoded = sc.mcu
                r.good_end, r.good_bit = good_at, good & 7
                r.preds = tuple(sc.preds)
            if err == ERR_CUT:
                # out of data: the end of the medium (perhaps between a 0xFF and its stuffed 0x00), or a
                # marker before the MCU was finished
                if seg_end >= end - 1:
                    sc.info.end = seg_end
                    return seg_end, 0, ERR_CUT
                mk = buf[seg_end + 1] if seg_end + 1 < end else 0
                sc.info.end = seg_end
                if mk == 0xD9:                       # the end-of-image marker comes too early: MCUs are missing
                    if main:
                        r.eoi_offset = seg_end
                    return seg_end, 0, ERR_EARLY_END
                return seg_end, 0, ERR_RESTART if 0xD0 <= mk <= 0xD7 else ERR_MARKER
            if err:
                at = self._offset(pos, raw, u, errbit)
                sc.info.end = at
                return at, 0, err
            if len(u) * 8 - good >= 8 and (sc.mcu == sc.total or sc.ri and sc.mcu % sc.ri == 0):
                at = self._offset(pos, raw, u, good + 7)        # data left over after the MCUs
                sc.info.end = at
                return at, 0, ERR_EXTRA
            sc.info.end = seg_end
            if sc.mcu >= sc.total:
                return seg_end, 0, ""
            if sc.mcu >= upto and not (sc.ri and sc.mcu % sc.ri == 0):
                return good_at, good & 7, ""
            # the restart marker that ends the interval
            p2 = seg_end
            while p2 + 1 < end and buf[p2] == 0xFF and buf[p2 + 1] == 0xFF:
                p2 += 1
            if p2 + 2 > end:
                return p2, 0, ERR_CUT
            if not sc.ri:
                return p2, 0, ERR_MARKER
            if buf[p2 + 1] != 0xD0 + (sc.mcu // sc.ri - 1) % 8:
                return p2, 0, ERR_RESTART
            if main:
                r.restarts += 1
            pos, bit = p2 + 2, 0
            sc.preds = [0] * len(sc.preds)
            sc.eobrun = 0
        return pos, bit, ""

    def _segment(self, sc: _Scan, u: bytes, bit: int, want: int) -> tuple[int, int, int, str]:
        """Decode WANT MCUs of one stretch U of unstuffed data from bit BIT, a window of words at a time."""
        if sc.kind == "dcr":                          # a bit per block, nothing to check
            per = sc.per_mcu
            nbits = len(u) * 8
            got = min(want, max(0, (nbits - bit) // per))
            sc.rec_p.extend(range(bit, bit + got * per, per))
            sc.mcu += got
            end = bit + got * per
            return got, end, end, "" if got == want else ERR_CUT
        nbytes = len(u)
        base = 0
        p = bit
        total = 0
        while True:
            w = _words(u[base:base + _WINDOW + _SLACK])
            nbits = (nbytes - base) * 8
            stop = min(nbits, _WINDOW * 8)
            first = len(sc.rec_p)
            n = want - total
            try:
                if sc.kind == "seq":
                    got, good, errbit, err = _seq(w, nbits, p, n, stop, sc.plan, sc.preds, sc.rec_p, sc.rec_d)
                elif sc.kind == "dc":
                    got, good, errbit, err = _dc_first(w, nbits, p, n, stop, sc.plan, sc.preds, sc.rec_p,
                                                       sc.rec_d)
                elif sc.kind == "ac":
                    got, good, errbit, err, sc.eobrun = _ac_first(
                        w, nbits, p, n, stop, sc.lut, sc.info.ss, sc.info.se, sc.maxs, sc.hist,
                        sc.mcu - sc.hbase, sc.eobrun, sc.rec_p, sc.rec_e)
                else:
                    got, good, errbit, err, sc.eobrun = _ac_refine(
                        w, nbits, p, n, stop, sc.lut, sc.info.ss, sc.info.se, sc.hist, sc.mcu - sc.hbase,
                        sc.eobrun, sc.rec_p, sc.rec_e)
            except IndexError:                       # an MCU ran far past the end of the data
                got = len(sc.rec_p) - first - 1
                good, errbit, err = sc.rec_p[-1], nbits, ERR_CUT
            if err and err != _PAUSE and errbit > nbits:
                err, errbit = ERR_CUT, nbits         # the zeros after the data didn't decode: it ends too soon
            keep = first + got                       # forget the MCU that didn't decode (its state is restored)
            if len(sc.rec_p) > keep:
                for i, d in enumerate(sc.rec_d):
                    sc.preds[i] = d[keep]
                if len(sc.rec_e) > keep:
                    sc.eobrun = sc.rec_e[keep]
            del sc.rec_p[keep:]
            for d in sc.rec_d:
                del d[keep:]
            del sc.rec_e[keep:]
            if base:
                for i in range(first, keep):
                    sc.rec_p[i] += base * 8
            if sc.kind in ("seq", "dc") and got > 1 and sc is self.scans[-1]:
                self._jumps(sc, first, keep)
            sc.mcu += got
            total += got
            if err == _PAUSE and total < want:
                shift = (good >> 4) * 2              # slide the window on to the next MCU (an even byte)
                base += shift
                p = good - shift * 8
                continue
            return total, good + base * 8, errbit + base * 8, "" if err == _PAUSE else err

    def _jumps(self, sc: _Scan, first: int, keep: int) -> None:
        d = sc.rec_d[sc.info.comps[0]]
        lim = sc.plan[0][-1]
        thr = max(8, lim // 2)
        prev = d[first]
        jumps = 0
        for v in d[first + 1:keep]:
            if v - prev > thr or prev - v > thr:
                jumps += 1
            prev = v
        self.res.dc_jumps += jumps

    @staticmethod
    def _offset(pos: int, raw: bytes, u: bytes, ubit: int) -> int:
        """The buffer offset of the byte that holds bit UBIT of the unstuffed data U (RAW at POS)."""
        i = min(len(u), max(0, ubit >> 3))
        return pos + i + (u.count(b"\xff", 0, i) if len(raw) != len(u) else 0)

    # ------------------------------------------------------------------ checkpoints
    def checkpoint(self, offset: int) -> Checkpoint | None:
        if not self.scans:
            return None
        si = len(self.scans) - 1
        sc = self.scans[si]
        for k in range(len(sc.segs) - 1, -1, -1):
            start, seg_end, first_mcu, first_bit = sc.segs[k]
            if start * 8 + first_bit >= offset * 8:
                continue
            last = k == len(sc.segs) - 1
            hi = sc.mcu if last else sc.segs[k + 1][2]
            raw = bytes(self.buf[start:seg_end])
            rel = min(offset, seg_end) - start
            ubit = (rel - raw.count(b"\xff\x00", 0, rel)) * 8
            if offset > seg_end:
                ubit = 1 << 62
            # the last MCU of this segment that starts before UBIT (the one being decoded, if it does)
            if last and sc.next_p < ubit and sc.mcu < sc.total and not (sc.ri and sc.mcu % sc.ri == 0):
                m, pb = sc.mcu, sc.next_p
            else:
                lo, hi2 = first_mcu, min(hi, len(sc.rec_p))
                while lo < hi2:
                    mid = (lo + hi2) // 2
                    if sc.rec_p[mid] < ubit:
                        lo = mid + 1
                    else:
                        hi2 = mid
                m = lo - 1
                if m < first_mcu:
                    continue
                pb = sc.rec_p[m]
            ub = pb >> 3
            u = raw.replace(b"\xff\x00", b"\xff")
            off = start + ub + u.count(b"\xff", 0, ub)
            if m == sc.mcu:
                preds, eob = tuple(sc.preds), sc.eobrun
            else:
                preds = tuple(d[m] for d in sc.rec_d) if sc.rec_d else ()
                eob = sc.rec_e[m] if m < len(sc.rec_e) else 0
            return Checkpoint(si, m, off, pb & 7, preds, eob)
        return None

    def _restore(self, cp: Checkpoint) -> _Scan:
        """Make CP the current state: what was decoded after it is forgotten."""
        r = self.res
        for later in reversed(self.scans[cp.scan + 1:]):     # their changes to the coefficient history undone
            if later.snapshot is not None:
                later.hist[:] = later.snapshot
        del self.scans[cp.scan + 1:]
        del r.scans[cp.scan + 1:]
        sc = self.scans[cp.scan]
        if sc.info.complete:
            sc.info.complete = False
            r.complete_scans -= 1
        sc.mcu = cp.mcu
        sc.preds = list(cp.preds) if cp.preds else [0] * len(sc.preds)
        sc.eobrun = cp.eobrun
        del sc.rec_p[cp.mcu:]
        for d in sc.rec_d:
            del d[cp.mcu:]
        del sc.rec_e[cp.mcu:]
        while sc.segs and sc.segs[-1][2] >= cp.mcu:
            sc.segs.pop()
        if sc.snapshot is not None:
            sc.hist[cp.mcu:] = sc.snapshot[cp.mcu:]
        sc.info.decoded = cp.mcu
        r.eoi_offset = None
        return sc

    def resume(self, cp: Checkpoint, buf, start: int, end: int) -> Result:
        self._restore(cp)
        return self.run(buf, start, end, cp.bit)

    def probe(self, cp: Checkpoint, data, limit: int, bits: int) -> Probe:
        sc = self.scans[cp.scan]
        rounds = 1 + (bits > 0) * 15
        t = sc.fork(cp, limit * rounds)
        upto = cp.mcu
        pos, bit, err = 0, cp.bit, ""
        try:
            for _ in range(rounds):
                upto = min(sc.total, upto + limit)
                pos, bit, err = self._scan(data, t, pos, len(data), bit, upto, False)
                if err or t.mcu >= sc.total or pos * 8 + bit - cp.bit >= bits:
                    break
        except (IndexError, struct.error, ValueError):
            err = ERR_HEADER
        got = t.mcu - cp.mcu
        dc: list[int] = []
        dcs: list[tuple[int, ...]] = []
        if t.rec_d and got:
            d = t.rec_d[sc.info.comps[0]]
            dc = (list(d[1:]) + [t.preds[sc.info.comps[0]]])[:got]
            dcs = (list(zip(*(r[1:] for r in t.rec_d))) + [tuple(t.preds)])[:got]
        if t.segs:
            s0, s1, _m, _b = t.segs[-1]
            raw = bytes(data[s0:s1])
            u = raw.replace(b"\xff\x00", b"\xff")
            end_bit = self._offset(s0, raw, u, t.next_p) * 8 + (t.next_p & 7)
        else:
            end_bit = cp.bit
        return Probe(got, end_bit, err, pos * 8 if err else end_bit, dc, t.mcu >= sc.total, tuple(t.preds), dcs)

    # ------------------------------------------------------------------ grey MCUs
    def grey(self, mcus: int, preds: tuple[int, ...] | None, prefix: tuple[int, int]) -> bytes | None:
        """MCUs of the first scan in which every block is mid-grey: the DC difference that brings the
        predictor back to 0, then an end-of-block code."""
        if not self.scans or self.scans[0].kind != "seq" or self.first_tables is None:
            return None
        f = self.frame
        tabs, idx = self.first_tables
        enc = []
        for (td, ta), ci in zip(tabs, idx):
            dt, at = self._tables(0, td), self._tables(1, ta)
            if not dt or not at:
                return None
            de, ae = _encoder(*dt), _encoder(*at)
            if 0 not in ae:
                return None
            enc.append((ci, de, ae[0], f.comps[ci].h * f.comps[ci].v if len(idx) > 1 else 1))
        cur = list(preds) if preds else [0] * len(f.comps)
        acc, nb = prefix
        out = bytearray()
        for _ in range(mcus):
            for ci, de, eob, nblk in enc:
                for _b in range(nblk):
                    diff = -cur[ci]
                    s = abs(diff).bit_length()
                    if s not in de:
                        return None
                    length, code = de[s]
                    val = diff if diff >= 0 else diff + (1 << s) - 1
                    acc = (acc << (length + s)) | (code << s) | (val & ((1 << s) - 1))
                    acc = (acc << eob[0]) | eob[1]
                    nb += length + s + eob[0]
                    cur[ci] = 0
                    while nb >= 8:
                        nb -= 8
                        b = (acc >> nb) & 0xFF
                        out.append(b)
                        if b == 0xFF:
                            out.append(0)
                    acc &= (1 << nb) - 1
        if nb:
            b = ((acc << (8 - nb)) | ((1 << (8 - nb)) - 1)) & 0xFF
            out.append(b)
            if b == 0xFF:
                out.append(0)
        return bytes(out)


# ---------------------------------------------------------------------- the API
def decode_check(buf, start: int = 0, end: int | None = None, header: bytes | None = None) -> Result:
    """Decode the JPEG in BUF from START (its start marker) to END. With HEADER (a JPEG's start marker up
    to and including its SOS segment), the picture data is taken from BUF at START instead: a header from
    another photo, or rebuilt. Never raises on damaged data."""
    end = len(buf) if end is None else min(end, len(buf))
    dec = _Decoder()
    r = dec.res
    if header is not None:
        hdr = bytes(header)
        if hdr[:2] != b"\xff\xd8":
            return dec._fail(ERR_HEADER, 0)
        try:
            pos, what = dec.segments(hdr, 2, len(hdr), first=True)
        except (IndexError, struct.error, ValueError):
            pos, what = 0, ERR_HEADER
        if what or pos != len(hdr):
            return dec._fail(what or ERR_HEADER, start)
        r.header_end = start
        dec.scans[-1].info.data = dec.scans[-1].info.end = start
        return dec.run(buf, start, end)
    if end - start < 4 or buf[start] != 0xFF or buf[start + 1] != 0xD8:
        return dec._fail(ERR_HEADER, start)
    return dec.run(buf, start + 2, end)


def tables_of(buf, start: int = 0, end: int | None = None) -> dict:
    """The Huffman and quantisation tables of the JPEG header at START: {"dht": {(class, id): (bits,
    values)}, "dqt": {id: values}, "sof": Frame or None, "dri": the restart interval}."""
    end = len(buf) if end is None else min(end, len(buf))
    dec = _Decoder()
    try:
        dec.segments(buf, start + 2, end, first=True)
    except (IndexError, struct.error, ValueError):
        pass
    dht = {(0, k): v for k, v in dec.dc.items()}
    dht.update({(1, k): v for k, v in dec.ac.items()})
    return {"dht": dht, "dqt": dict(dec.q), "sof": dec.frame, "dri": dec.ri}
