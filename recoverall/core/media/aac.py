"""AAC audio (ISO/IEC 14496-3, subpart 4): the configuration, and where one raw frame ends.

An MP4/MOV file stores AAC as bare frames: each sample is one ``raw_data_block`` with no header and no length,
so the end of a frame is known only by reading it to its end. A raw data block is a sequence of syntax
elements, each starting with a 3-bit id: SCE (one channel), CPE (a channel pair), CCE (a coupling channel),
LFE (the bass channel), DSE (data bytes), PCE (a program configuration), FIL (fill bytes, which also carry SBR
and PS for HE-AAC) and finally END, then padding bits up to the next byte. The channel elements hold an
``individual_channel_stream`` per channel:

* ``ics_info``: the window sequence (one long window, or eight short ones grouped into window groups), the
  number of scale factor bands coded (max_sfb), and prediction (AAC Main) or long-term prediction (AAC LTP);
* ``section_data``: runs of bands sharing a Huffman codebook (0: all zero, 1-11: spectral books, 13: noise
  substitution, 14/15: intensity stereo; 12 is reserved), with lengths that must add up to max_sfb (an empty
  section, which no encoder writes, is refused);
* ``scale_factor_data``: one Huffman-coded difference per non-zero band (the first noise energy is a 9-bit
  number); the scale factors have to stay within 0..255;
* pulse data (long windows only), TNS filters (with an order the profile allows) and gain control (AAC SSR);
* ``spectral_data``: per section, Huffman codewords for 4-tuples (books 1-4) or pairs (5-11) of spectral
  lines, a sign bit for every non-zero value in the unsigned books, and for book 11 an escape (N ones, a zero,
  N+4 bits) for each value of 16 or more.

:func:`frame_length` follows all of this bit by bit (it does not dequantize anything) and checks the
things a wrong starting position gets wrong: the elements a channel configuration needs, in order; band
counts within the table of the sampling rate; section lengths adding up exactly; scale factors in range; TNS
orders; and a frame that ends before the data does, within twice the standard's 6144 bits per channel
(encoders overshoot it at low sampling rates). Two things encoders do that the standard doesn't require are
checked in STRICT mode (the default of :func:`is_frame`, which tells audio from other data): zero bits after
ID_END, and exactly the channel elements of the configuration (leniently, mono streams coded as a CPE and stereo
ones as one SCE, both seen in the wild, are taken too). :func:`split_frames` takes its first frame leniently and
holds the frames after it to what that one did. The Huffman codebooks and band tables are in :mod:`aac_tables`
(converted from the Apache-licensed VisualOn encoder).

ADTS (``.aac`` files, MPEG transport streams) puts a 7- or 9-byte header with the frame length before each
raw data block: :func:`parse_adts` reads one, :func:`adts_header` writes one to save salvaged frames.

The ER (error resilient) object types (17, 19, 20, 23, ...) use a different frame syntax and are not
measured; their configuration is still read.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .aac_tables import SAMPLE_RATES, SCALEFACTOR, SPECTRAL, SWB_LONG, SWB_SHORT
from .bits import BitReader, BitsError

# syntax element ids
ID_SCE, ID_CPE, ID_CCE, ID_LFE, ID_DSE, ID_PCE, ID_FIL, ID_END = range(8)
# window sequences
ONLY_LONG, LONG_START, EIGHT_SHORT, LONG_STOP = range(4)

OBJECT_TYPES = {1: "AAC Main", 2: "AAC LC", 3: "AAC SSR", 4: "AAC LTP", 5: "SBR", 6: "AAC Scalable",
                17: "ER AAC LC", 19: "ER AAC LTP", 20: "ER AAC Scalable", 22: "ER BSAC", 23: "ER AAC LD",
                29: "PS", 39: "ER AAC ELD", 42: "USAC"}
SUPPORTED = (1, 2, 3, 4)                     # object types whose frames frame_length() measures
AAC_OTI = (0x40, 0x66, 0x67, 0x68)           # MPEG-4 audio; MPEG-2 AAC Main, LC, SSR (esds objectTypeIndication)

# the channel elements of each channel configuration, in bitstream order (1-7 of the 2005 edition, 11, 12, 14
# of the later ones); and the number of channels
CONFIG_ELEMENTS = {1: (ID_SCE,), 2: (ID_CPE,), 3: (ID_SCE, ID_CPE), 4: (ID_SCE, ID_CPE, ID_SCE),
                   5: (ID_SCE, ID_CPE, ID_CPE), 6: (ID_SCE, ID_CPE, ID_CPE, ID_LFE),
                   7: (ID_SCE, ID_CPE, ID_CPE, ID_CPE, ID_LFE), 11: (ID_SCE, ID_CPE, ID_CPE, ID_SCE, ID_LFE),
                   12: (ID_SCE, ID_CPE, ID_CPE, ID_CPE, ID_LFE), 14: (ID_SCE, ID_CPE, ID_CPE, ID_LFE, ID_CPE)}
CONFIG_CHANNELS = {k: sum(2 if e == ID_CPE else 1 for e in v) for k, v in CONFIG_ELEMENTS.items()}

# the highest band AAC Main prediction covers, per sampling-frequency index
PRED_SFB_MAX = (33, 33, 38, 40, 40, 40, 41, 41, 37, 37, 37, 34, 34)
MAX_LTP_LONG_SFB = 40
MAX_FRAME_BITS = 6144                        # per channel: the decoder input buffer of the standard ...
FRAME_BITS_LIMIT = 2 * MAX_FRAME_BITS        # ... which encoders overshoot at low rates (ffmpeg at 7350 Hz)


@dataclass
class ProgramConfig:
    """A program_config_element: which channel elements make up the program (when the channel configuration
    is 0) and their instance tags."""
    tag: int = 0
    object_type: int = 0                      # the profile field: object type - 1
    sample_rate_index: int = 0
    front: list[tuple[bool, int]] = field(default_factory=list)    # (is a CPE, instance tag)
    side: list[tuple[bool, int]] = field(default_factory=list)
    back: list[tuple[bool, int]] = field(default_factory=list)
    lfe: list[int] = field(default_factory=list)
    assoc_data: list[int] = field(default_factory=list)
    cc: list[tuple[bool, int]] = field(default_factory=list)       # (independently switched, tag)
    mono_mixdown: int | None = None
    stereo_mixdown: int | None = None
    matrix_mixdown: tuple[int, int] | None = None                  # (index, pseudo surround)
    comment: bytes = b""

    @property
    def channels(self) -> int:
        return sum(2 if cpe else 1 for cpe, _t in self.front + self.side + self.back) + len(self.lfe)

    def elements(self) -> list[tuple[int, int]]:
        """(element id, instance tag) of the channel elements, front to back, then the LFEs."""
        out = [(ID_CPE if cpe else ID_SCE, t) for cpe, t in self.front + self.side + self.back]
        return out + [(ID_LFE, t) for t in self.lfe]


@dataclass
class AudioSpecificConfig:
    """The decoder configuration of an AAC stream (what an MP4 file keeps in its "esds" box)."""
    object_type: int        # 2 = AAC LC (also 1 Main, 3 SSR, 4 LTP; 5/29 = SBR/PS signalled → core object type
    #                         here, sbr/ps flags set)
    sample_rate: int        # the core (AAC) rate
    sample_rate_index: int  # 0..12 (15 = explicit rate)
    channel_config: int     # 0..7 (0: a PCE describes the channels)
    channels: int           # coded channels (with PS the output is stereo from one coded channel)
    frame_length: int       # 1024, or 960 (frameLengthFlag)
    sbr: bool = False
    ps: bool = False
    ext_sample_rate: int = 0   # output rate with SBR
    pce: object | None = None  # parsed program config element when channel_config == 0

    @property
    def name(self) -> str:
        n = OBJECT_TYPES.get(self.object_type, f"object type {self.object_type}")
        return "HE-AAC v2" if self.ps else "HE-AAC" if self.sbr else n


# ---------------------------------------------------------------------- configuration
def rate_index(rate: int) -> int:
    """The sampling-frequency index whose tables a rate uses (an explicit rate maps to the nearest one)."""
    for i, low in enumerate((92017, 75132, 55426, 46009, 37566, 27713, 23004, 18783, 13856, 11502, 9391)):
        if rate >= low:
            return i
    return 11


def _object_type(r: BitReader) -> int:
    t = r.u(5)
    return 32 + r.u(6) if t == 31 else t


def _rate(r: BitReader) -> tuple[int, int]:
    i = r.u(4)
    if i == 15:
        return r.u(24), 15
    if i > 12:
        raise ValueError("reserved sampling-frequency index")
    return SAMPLE_RATES[i], i


def read_pce(r, comment: bool = True) -> ProgramConfig:
    """A program_config_element from a reader with u(n), skip(n) and align() (raises BitsError when cut short);
    the comment bytes are skipped unless COMMENT."""
    pce = ProgramConfig(tag=r.u(4), object_type=r.u(2), sample_rate_index=r.u(4))
    nf, ns, nb, nl, na, nc = r.u(4), r.u(4), r.u(4), r.u(2), r.u(3), r.u(4)
    if r.u(1):
        pce.mono_mixdown = r.u(4)
    if r.u(1):
        pce.stereo_mixdown = r.u(4)
    if r.u(1):
        pce.matrix_mixdown = (r.u(2), r.u(1))
    for lst, n in ((pce.front, nf), (pce.side, ns), (pce.back, nb)):
        for _ in range(n):
            v = r.u(5)
            lst.append((bool(v >> 4), v & 15))
    pce.lfe = [r.u(4) for _ in range(nl)]
    pce.assoc_data = [r.u(4) for _ in range(na)]
    for _ in range(nc):
        v = r.u(5)
        pce.cc.append((bool(v >> 4), v & 15))
    r.align()
    n = r.u(8)
    if comment:
        pce.comment = bytes(r.u(8) for _ in range(n))
    else:
        r.skip(8 * n)
    return pce


def parse_asc(data: bytes) -> AudioSpecificConfig | None:
    """An AudioSpecificConfig (the decoder configuration of an MP4 "esds" box or of Matroska's CodecPrivate);
    None unless it describes AAC (an object type with a GASpecificConfig) at a valid rate and channel layout."""
    try:
        r = BitReader(bytes(data))
        aot = _object_type(r)
        rate, index = _rate(r)
        chcfg = r.u(4)
        sbr = ps = False
        ext_rate = 0
        if aot in (5, 29):                                  # explicit hierarchical SBR / PS signalling
            sbr, ps = True, aot == 29
            ext_rate = _rate(r)[0]
            aot = _object_type(r)
            if aot == 22:
                r.u(4)
        if aot not in (1, 2, 3, 4, 6, 7, 17, 19, 20, 21, 22, 23):
            return None
        frame = 960 if r.u(1) else 1024                     # GASpecificConfig
        if r.u(1):                                          # dependsOnCoreCoder
            r.u(14)
        ext_flag = r.u(1)
        pce = None
        if chcfg == 0:
            pce = read_pce(r)
            channels = pce.channels
        elif chcfg in CONFIG_CHANNELS:
            channels = CONFIG_CHANNELS[chcfg]
        else:
            return None
        if aot in (6, 20):
            r.u(3)                                          # layerNr
        if ext_flag:
            if aot == 22:
                r.u(16)
            if aot in (17, 19, 20, 23):
                r.u(3)
            r.u(1)
        if channels <= 0:
            return None
        asc = AudioSpecificConfig(aot, rate, index, chcfg, channels, frame, sbr, ps, ext_rate, pce)
    except (BitsError, IndexError, ValueError):
        return None
    try:                                                    # backward-compatible SBR / PS signalling
        if 17 <= aot <= 27:
            r.u(2)                                          # epConfig
        if not sbr and r.left >= 16 and r.u(11) == 0x2B7:
            ext = _object_type(r)
            if ext == 5 and r.u(1):
                asc.sbr = True
                asc.ext_sample_rate = _rate(r)[0]
                if r.left >= 12 and r.u(11) == 0x548:
                    asc.ps = bool(r.u(1))
    except (BitsError, IndexError, ValueError):
        pass
    return asc


def _descriptors(data: bytes, pos: int, end: int):
    """(tag, payload start, payload end) of the MPEG-4 descriptors in [POS, END)."""
    while pos + 2 <= end:
        tag = data[pos]
        pos += 1
        size = 0
        for _ in range(4):
            if pos >= end:
                return
            b = data[pos]
            pos += 1
            size = (size << 7) | (b & 0x7F)
            if not b & 0x80:
                break
        stop = min(end, pos + size)
        yield tag, pos, stop
        pos = stop


def _decoder_specific(data: bytes, pos: int, end: int, depth: int = 0) -> tuple[int, bytes] | None:
    """(objectTypeIndication, DecoderSpecificInfo) of the first DecoderConfigDescriptor in [POS, END)."""
    for tag, p, e in _descriptors(data, pos, end):
        if tag == 3 and depth < 3 and e - p >= 3:          # ES_Descriptor
            flags = data[p + 2]
            q = p + 3
            if flags & 0x80:
                q += 2
            if flags & 0x40 and q < e:
                q += 1 + data[q]
            if flags & 0x20:
                q += 2
            found = _decoder_specific(data, q, e, depth + 1)
            if found:
                return found
        elif tag == 4 and e - p >= 13:                     # DecoderConfigDescriptor
            oti = data[p]
            for t, q, f in _descriptors(data, p + 13, e):
                if t == 5:
                    return oti, data[q:f]
            return oti, b""
    return None


def parse_esds(payload: bytes) -> AudioSpecificConfig | None:
    """The AAC configuration in the payload of an "esds" box (version and flags, then an ES_Descriptor holding
    a DecoderConfigDescriptor and its DecoderSpecificInfo); None unless the stream is AAC (objectTypeIndication
    0x40 MPEG-4 audio, or 0x66-0x68 MPEG-2 AAC) with a readable AudioSpecificConfig."""
    data = bytes(payload)
    try:
        found = None
        if len(data) > 4 and data[4] in (3, 4):
            found = _decoder_specific(data, 4, len(data))
        if found is None and data[:1] in (b"\x03", b"\x04"):    # without the version and flags
            found = _decoder_specific(data, 0, len(data))
    except IndexError:
        return None
    if not found or found[0] not in AAC_OTI or not found[1]:
        return None
    asc = parse_asc(found[1])
    if asc is not None and found[0] != 0x40 and asc.object_type not in (1, 2, 3):
        return None
    return asc


# ---------------------------------------------------------------------- ADTS
def adts_header(asc: AudioSpecificConfig, frame_len: int) -> bytes:
    """A 7-byte ADTS header (MPEG-4, no CRC, variable bitrate) for one raw data block of FRAME_LEN bytes."""
    total = frame_len + 7
    if frame_len < 0 or total > 0x1FFF:
        raise ValueError(f"an ADTS frame can't hold {frame_len} bytes")
    profile = asc.object_type - 1 if 1 <= asc.object_type <= 4 else 1
    index = asc.sample_rate_index if asc.sample_rate_index <= 12 else rate_index(asc.sample_rate)
    ch = asc.channel_config if asc.channel_config <= 7 else 0
    bits = (0xFFF << 44) | (1 << 40) | (profile << 38) | (index << 34) | (ch << 30) | (total << 13) | (0x7FF << 2)
    return bits.to_bytes(7, "big")


def parse_adts(buf, pos: int) -> tuple[AudioSpecificConfig, int, int] | None:
    """The ADTS header at POS: (configuration, header length, frame length including the header)."""
    try:
        if pos < 0 or pos + 7 > len(buf):
            return None
        b = bytes(buf[pos:pos + 7])
        if b[0] != 0xFF or (b[1] & 0xF6) != 0xF0:
            return None
        index = (b[2] >> 2) & 15
        if index > 12:
            return None
        ch = ((b[2] & 1) << 2) | (b[3] >> 6)
        length = ((b[3] & 3) << 11) | (b[4] << 3) | (b[5] >> 5)
        blocks = b[6] & 3
        header = 7 if b[1] & 1 else 9 + 2 * blocks
        if length <= header:
            return None
        asc = AudioSpecificConfig((b[2] >> 6) + 1, SAMPLE_RATES[index], index, ch, CONFIG_CHANNELS.get(ch, 0), 1024)
        return asc, header, length
    except IndexError:
        return None


# ---------------------------------------------------------------------- Huffman decoding tables
# The bits are read from a list of 64-bit words, D[k] = bytes 4k..4k+8 of the data, so any field of up to 32
# bits at bit position p is (D[p >> 5] >> (64 - n - (p & 31))) & mask: one index, two shifts, one mask.
# A spectral book's table is indexed by its longest codeword's length worth of bits and holds what the
# codeword at that position costs: its length plus its sign bits (positive), or for book 11 with escapes
# -(length + sign bits + 256 * number of escapes).

def _spectral_tables():
    tables: list = [None] * 12
    for book, (lengths, codes) in SPECTRAL.items():
        dim = 4 if book <= 4 else 2
        signed = book in (1, 2, 5, 6)
        lav = {1: 1, 2: 1, 3: 2, 4: 2, 5: 4, 6: 4, 7: 7, 8: 7, 9: 12, 10: 12, 11: 16}[book]
        mod = 2 * lav + 1 if signed else lav + 1
        width = max(lengths)
        table = [0] * (1 << width)
        for i, (n, code) in enumerate(zip(lengths, codes)):
            values = []
            k = i
            for _ in range(dim):
                values.append(k % mod - (lav if signed else 0))
                k //= mod
            cost = n + (0 if signed else sum(1 for v in values if v))
            escapes = sum(1 for v in values if v == 16) if book == 11 else 0
            entry = -(cost + 256 * escapes) if escapes else cost
            lo = code << (width - n)
            table[lo:lo + (1 << (width - n))] = [entry] * (1 << (width - n))
        tables[book] = (table, 64 - width, (1 << width) - 1, 2 if dim == 4 else 1)
    return tables


SCF_BITS = 12


def _scalefactor_tables():
    lengths, codes = SCALEFACTOR
    short = [0] * (1 << SCF_BITS)
    long: dict[tuple[int, int], int] = {}
    for i, (n, code) in enumerate(zip(lengths, codes)):
        entry = n | (i << 5)
        if n <= SCF_BITS:
            lo = code << (SCF_BITS - n)
            short[lo:lo + (1 << (SCF_BITS - n))] = [entry] * (1 << (SCF_BITS - n))
        else:
            long[(n, code)] = entry
    return short, long


def _escape_table():
    # 9 bits after a book-11 codeword's sign bits: N leading ones, a zero, then N + 4 bits: 2N + 5 bits in all
    out = []
    for v in range(512):
        n = 0
        while n < 9 and v & (256 >> n):
            n += 1
        out.append(2 * n + 5 if n < 9 else -1)
    return out


def _groups_table():
    out = []
    for bits in range(128):
        g = [1]
        for k in range(6, -1, -1):
            if bits >> k & 1:
                g[-1] += 1
            else:
                g.append(1)
        out.append(tuple(g))
    return out


_SPEC = _spectral_tables()
_SCF, _SCF_LONG = _scalefactor_tables()
_ESC = _escape_table()
_GROUPS = _groups_table()


class _Bad(Exception):
    """Not a valid frame (internal)."""


def _words(buf, start: int, stop: int, pad: bool = True) -> list[int]:
    """D for the bytes [START, STOP) of BUF, with zero bytes after them (PAD), or else only the words that lie
    wholly inside them, so that reading past STOP raises IndexError."""
    data = bytes(buf[start:stop])
    if pad:
        k = (len(data) + 3) // 4 + 2
        data += bytes(4 * k + 16 - len(data))
    else:
        k = max(0, (len(data) - 8) // 4 + 1)
        data += bytes(8)
    out = [0] * k
    out[0::2] = struct.unpack_from(f">{(k + 1) // 2}Q", data, 0)
    out[1::2] = struct.unpack_from(f">{k // 2}Q", data, 4)
    return out


def _bits(D, p: int, n: int) -> int:
    return (D[p >> 5] >> (64 - n - (p & 31))) & ((1 << n) - 1)


def _scf_slow(D, p: int) -> int:
    for n in range(SCF_BITS + 1, 20):
        e = _SCF_LONG.get((n, _bits(D, p, n)))
        if e:
            return e
    raise _Bad


class _Reader:
    """BitReader's u()/skip()/align() over D, for the program config elements inside frames."""
    __slots__ = ("D", "pos")

    def __init__(self, D, pos: int):
        self.D, self.pos = D, pos

    def u(self, n: int) -> int:
        v = _bits(self.D, self.pos, n)
        self.pos += n
        return v

    def skip(self, n: int) -> None:
        self.pos += n

    def align(self) -> None:
        self.pos = (self.pos + 7) & ~7


# ---------------------------------------------------------------------- frames
class _Config:
    """What the frame parser needs to know about a configuration, computed once."""
    __slots__ = ("aot", "index", "swb_long", "swb_short", "nswb_long", "nswb_short", "pred_max", "tns_max",
                 "orders", "strict_orders", "pce_elements", "max_bytes", "max_elements", "first_ids",
                 "strict_first_ids")

    def __init__(self, asc: AudioSpecificConfig):
        self.aot = asc.object_type
        self.index = asc.sample_rate_index if asc.sample_rate_index <= 12 else rate_index(asc.sample_rate)
        n = asc.frame_length
        self.swb_long = tuple(o for o in SWB_LONG[self.index] if o < n) + (n,)
        s = n // 8
        self.swb_short = tuple(o for o in SWB_SHORT[self.index] if o < s) + (s,)
        self.nswb_long, self.nswb_short = len(self.swb_long) - 1, len(self.swb_short) - 1
        self.pred_max = PRED_SFB_MAX[self.index]
        self.tns_max = 20 if self.aot == 1 else 12
        order = CONFIG_ELEMENTS.get(asc.channel_config)
        # the element sequences a frame may have; mono as a CPE and stereo as one SCE occur in the wild
        self.orders = None if order is None else {(ID_SCE,), (ID_CPE,)} if len(order) == 1 else {order}
        self.strict_orders = None if order is None else {order}
        pce = asc.pce if isinstance(asc.pce, ProgramConfig) else None
        self.pce_elements = sorted(pce.elements()) if pce is not None and asc.channel_config == 0 else None
        if order:
            channels, n_el = CONFIG_CHANNELS[asc.channel_config], len(order)
        elif self.pce_elements:
            channels, n_el = pce.channels, len(self.pce_elements)
        else:
            channels, n_el = 8, 8                           # a PCE in the frames will tell
        self.max_bytes = FRAME_BITS_LIMIT // 8 * max(2, channels)
        self.max_elements = 2 * n_el + 16
        if self.orders:
            first = {o[0] for o in self.orders}
        elif self.pce_elements:
            first = {e for e, _t in self.pce_elements}
        else:
            first = {ID_SCE, ID_CPE, ID_LFE}
        self.first_ids = frozenset(first | {ID_CCE, ID_DSE, ID_PCE, ID_FIL})
        self.strict_first_ids = frozenset({order[0]} | {ID_CCE, ID_DSE, ID_PCE, ID_FIL}) if order else self.first_ids


_CONFIGS: dict = {}


def _config(asc) -> _Config | None:
    if not isinstance(asc, AudioSpecificConfig) or asc.object_type not in SUPPORTED:
        return None
    if asc.frame_length not in (1024, 960) or not (0 <= asc.sample_rate_index <= 12 or asc.sample_rate_index == 15):
        return None
    pce = asc.pce if isinstance(asc.pce, ProgramConfig) else None
    if asc.channel_config not in CONFIG_ELEMENTS and asc.channel_config != 0:
        return None
    key = (asc.object_type, asc.sample_rate_index, asc.sample_rate if asc.sample_rate_index == 15 else 0,
           asc.channel_config, asc.frame_length, tuple(pce.elements()) if pce is not None else None)
    c = _CONFIGS.get(key)
    if c is None:
        if len(_CONFIGS) > 256:
            _CONFIGS.clear()
        c = _CONFIGS[key] = _Config(asc)
    return c


def _ltp(D, p: int, max_sfb: int) -> int:
    # ltp_data of a long window: lag (11 bits), coefficient (3), one "used" flag per band up to 40
    return p + 14 + min(max_sfb, MAX_LTP_LONG_SFB)


def _ics_info(D, p: int, c: _Config, common: bool):
    v = _bits(D, p, 4)                                      # reserved bit, window sequence, window shape
    p += 4
    if v & 8:
        raise _Bad
    ws = v >> 1
    if ws == EIGHT_SHORT:
        v = _bits(D, p, 11)                                 # max_sfb (4), scale_factor_grouping (7)
        p += 11
        max_sfb = v >> 7
        if max_sfb > c.nswb_short:
            raise _Bad
        return p, (EIGHT_SHORT, max_sfb, _GROUPS[v & 127])
    v = _bits(D, p, 7)                                      # max_sfb (6), predictor_data_present
    p += 7
    max_sfb = v >> 1
    if max_sfb > c.nswb_long:
        raise _Bad
    if v & 1:
        if c.aot == 1:                                      # AAC Main prediction
            if _bits(D, p, 1):
                g = _bits(D, p + 1, 5)                      # predictor_reset_group_number 1..30
                if not 0 < g <= 30:
                    raise _Bad
                p += 6
            else:
                p += 1
            p += min(max_sfb, c.pred_max)
        elif c.aot == 4:                                    # long-term prediction, per channel
            p += 1
            if _bits(D, p - 1, 1):
                p = _ltp(D, p, max_sfb)
            if common:
                p += 1
                if _bits(D, p - 1, 1):
                    p = _ltp(D, p, max_sfb)
        else:
            raise _Bad                                      # no prediction in LC and SSR
    return p, (ws, max_sfb, (1,))


def _tns(D, p: int, short: bool, max_order: int) -> int:
    if short:
        for _ in range(8):
            if not _bits(D, p, 1):                          # n_filt (1 bit)
                p += 1
                continue
            v = _bits(D, p + 1, 8)                          # coef_res, length (4), order (3)
            p += 9
            order = v & 7
            if order:
                comp = _bits(D, p + 1, 1)                   # direction, coef_compress
                p += 2 + order * (3 + (v >> 7) - comp)
        return p
    n = _bits(D, p, 2)
    p += 2
    if n:
        res = _bits(D, p, 1)
        p += 1
        for _ in range(n):
            v = _bits(D, p, 11)                             # length (6), order (5)
            p += 11
            order = v & 31
            if order > max_order:
                raise _Bad
            if order:
                comp = _bits(D, p + 1, 1)
                p += 2 + order * (3 + res - comp)
    return p


def _gain_control(D, p: int, ws: int) -> int:
    bands = _bits(D, p, 2)
    p += 2
    loc = ((5,), (4, 2), (2,) * 8, (4, 5))[ws]
    for _ in range(bands):
        for bits in loc:
            n = _bits(D, p, 3)                              # adjust_num, then (alevcode 4, aloccode) each
            p += 3 + n * (4 + bits)
    return p


def _ics(D, p: int, c: _Config, info):
    """One individual_channel_stream at bit P; (end, ics info, [(codebook, bands)] of the non-zero sections)."""
    gain = (D[p >> 5] >> (56 - (p & 31))) & 255
    p += 8
    if info is None:
        p, info = _ics_info(D, p, c, False)
    ws, max_sfb, groups = info
    if ws == EIGHT_SHORT:
        swb, sbits, esc = c.swb_short, 3, 7
    else:
        swb, sbits, esc = c.swb_long, 5, 31

    # section_data: (codebook 4 bits, length with escapes) until the bands of each window group add up
    secs = []
    spec = []
    head, hmask, lshift = 60 - sbits, (16 << sbits) - 1, 64 - sbits
    for gl in groups:
        k = 0
        while k < max_sfb:
            v = (D[p >> 5] >> (head - (p & 31))) & hmask
            p += 4 + sbits
            cb = v >> sbits
            n = v & esc
            if n == esc:
                total = 0
                while n == esc:
                    total += esc
                    if total > max_sfb:
                        raise _Bad
                    n = (D[p >> 5] >> (lshift - (p & 31))) & esc
                    p += sbits
                n += total
            k2 = k + n
            if not n or cb == 12 or k2 > max_sfb:
                raise _Bad
            if cb:
                secs.append((cb, n))
                if cb < 12:
                    spec.append((cb, gl * (swb[k2] - swb[k])))
            k = k2

    # scale_factor_data: a Huffman-coded difference per non-zero band
    SCF = _SCF
    sf = gain
    noise = False
    for cb, n in secs:
        if cb < 12:
            for _ in range(n):
                e = SCF[(D[p >> 5] >> (52 - (p & 31))) & 4095] or _scf_slow(D, p)
                p += e & 31
                sf += (e >> 5) - 60
                if sf < 0 or sf > 255:
                    raise _Bad
        else:
            for _ in range(n):
                if cb == 13 and not noise:
                    noise = True                            # the first noise energy: 9 bits
                    p += 9
                    continue
                e = SCF[(D[p >> 5] >> (52 - (p & 31))) & 4095] or _scf_slow(D, p)
                p += e & 31

    # pulse_data, tns_data, gain_control_data
    if _bits(D, p, 1):
        if ws == EIGHT_SHORT:
            raise _Bad
        v = _bits(D, p + 1, 8)                              # number_pulse (2), pulse_start_sfb (6)
        p += 9
        start = v & 63
        if start >= c.nswb_long:
            raise _Bad
        k = swb[start]
        for _ in range((v >> 6) + 1):
            k += _bits(D, p, 5)                             # pulse_offset (5), pulse_amp (4)
            p += 9
            if k >= swb[-1]:
                raise _Bad
    else:
        p += 1
    p += 1
    if _bits(D, p - 1, 1):
        p = _tns(D, p, ws == EIGHT_SHORT, c.tns_max)
    p += 1
    if _bits(D, p - 1, 1):
        if c.aot != 3:
            raise _Bad
        p = _gain_control(D, p, ws)

    # spectral_data: codewords (plus sign bits and escapes) for every line of the spectral sections
    ESC = _ESC
    for cb, lines in spec:
        T, sh, mask, dim = _SPEC[cb]
        for _ in range(lines >> dim):
            e = T[(D[p >> 5] >> (sh - (p & 31))) & mask]
            if e > 0:
                p += e
                continue
            e = -e                                          # book 11 with one or two escapes
            p += e & 255
            for _ in range(e >> 8):
                n = ESC[(D[p >> 5] >> (55 - (p & 31))) & 511]
                if n < 0:
                    raise _Bad
                p += n
    return p, info, secs


def _cce(D, p: int, c: _Config) -> int:
    v = _bits(D, p, 8)                                      # tag (4), ind_sw_cce_flag, num_coupled_elements (3)
    p += 8
    ind_sw = v & 8
    lists = 0
    for _ in range((v & 7) + 1):
        lists += 1
        t = _bits(D, p, 5)                                  # cc_target_is_cpe, cc_target_tag_select
        p += 5
        if t & 16:
            lr = _bits(D, p, 2)
            p += 2
            if lr == 3:
                lists += 1
    p += 4                                                  # cc_domain, gain_element_sign, gain_element_scale
    p, _info, secs = _ics(D, p, c, None)
    bands = sum(n for _cb, n in secs)
    for _ in range(1, lists):
        if ind_sw:
            common = 1
        else:
            common = _bits(D, p, 1)
            p += 1
        for _ in range(1 if common else bands):
            e = _SCF[(D[p >> 5] >> (52 - (p & 31))) & 4095] or _scf_slow(D, p)
            p += e & 31
    return p


def _frame(D, p: int, limit: int, c: _Config, orders=None) -> tuple[int, int, tuple]:
    """The raw_data_block at bit P (a byte boundary) of D, ending by bit LIMIT: (end bit, value of the padding
    bits after ID_END or -1 without any, the channel element ids). ORDERS: the element sequences allowed (the
    configuration's). Raises _Bad (or IndexError) when it isn't one."""
    start = p
    seen: list[tuple[int, int]] = []
    count = 0
    pce_elements = None
    while True:
        eid = (D[p >> 5] >> (61 - (p & 31))) & 7
        p += 3
        if eid == ID_END:
            break
        count += 1
        if count > c.max_elements:
            raise _Bad
        if eid == ID_CPE:
            v = _bits(D, p, 5)                              # tag, common_window
            p += 5
            if v & 1:
                p, info = _ics_info(D, p, c, True)
                ms = _bits(D, p, 2)
                p += 2
                if ms == 3:
                    raise _Bad
                if ms == 1:
                    p += len(info[2]) * info[1]             # ms_used per window group and band
                p = _ics(D, p, c, info)[0]
                p = _ics(D, p, c, info)[0]
            else:
                p = _ics(D, p, c, None)[0]
                p = _ics(D, p, c, None)[0]
            seen.append((ID_CPE, v >> 1))
        elif eid == ID_SCE or eid == ID_LFE:
            tag = _bits(D, p, 4)
            p = _ics(D, p + 4, c, None)[0]
            seen.append((eid, tag))
        elif eid == ID_FIL:
            n = _bits(D, p, 4)
            p += 4
            if n == 15:
                n += _bits(D, p, 8) - 1
                p += 8
            p += 8 * n
        elif eid == ID_DSE:
            v = _bits(D, p, 13)                             # tag (4), data_byte_align_flag, count (8)
            p += 13
            n = v & 255
            if n == 255:
                n += _bits(D, p, 8)
                p += 8
            if v & 256:
                p = (p + 7) & ~7
            p += 8 * n
        elif eid == ID_PCE:                                 # for this rate, and the configuration's elements
            if _bits(D, p + 6, 4) != c.index:
                raise _Bad
            r = _Reader(D, p)
            pce = read_pce(r, comment=False)
            p = r.pos
            pce_elements = sorted(pce.elements())
            if not pce_elements or c.orders is not None and tuple(e for e, _t in pce.elements()) not in c.orders:
                raise _Bad
        else:                                               # ID_CCE
            p = _cce(D, p, c)
        if p > limit:
            raise _Bad

    # the channel elements the configuration needs, each instance once
    if len(set(seen)) != len(seen) or not seen:
        raise _Bad
    types = tuple(e for e, _t in seen)
    if c.orders is not None:
        if types not in (orders or c.orders):
            raise _Bad
    else:
        want = c.pce_elements or pce_elements
        if want is not None and sorted(seen) != want:
            raise _Bad
        if p - start > FRAME_BITS_LIMIT * sum(2 if e == ID_CPE else 1 for e, _t in seen):
            raise _Bad
    pad = -p & 7
    value = _bits(D, p, pad) if pad else -1
    p += pad
    if p > limit:
        raise _Bad
    return p, value, types


FIRST_TRY = 320                              # bytes read for a first attempt (most frames, and most rejections)


def _measure(buf, pos: int, end: int, asc, strict: bool) -> int | None:
    c = _config(asc)
    if c is None or pos < 0:
        return None
    end = min(end, len(buf))
    stop = min(end, pos + c.max_bytes)
    if stop <= pos:
        return None
    limit = (stop - pos) * 8
    orders = c.strict_orders if strict else None
    try:
        try:
            if pos + FIRST_TRY + 8 >= stop:
                raise IndexError
            bits, pad, _types = _frame(_words(buf, pos, pos + FIRST_TRY + 8, pad=False), 0, limit, c, orders)
        except IndexError:                                  # longer: again with all the bytes it may have
            bits, pad, _types = _frame(_words(buf, pos, stop), 0, limit, c, orders)
    except (_Bad, IndexError, BitsError, ValueError):
        return None
    if strict and pad > 0:
        return None
    return bits >> 3


def _ics_info_ok(v: int, at: int, c: _Config, common: bool) -> bool:
    """Whether the ics_info at bit AT (from the top) of the 32-bit number V is plausible (and, after a
    common one, the M/S mask mode)."""
    f = v << at
    if f & 0x80000000:                                      # reserved bit
        return False
    if (f >> 29) & 3 == EIGHT_SHORT:
        return (f >> 24) & 15 <= c.nswb_short and not (common and (f >> 15) & 3 == 3)
    if (f >> 22) & 63 > c.nswb_long:
        return False
    if (f >> 21) & 1:
        return c.aot in (1, 4)
    return not (common and (f >> 19) & 3 == 3)


def _plausible(buf, pos: int, c: _Config, strict: bool) -> bool:
    """Cheap checks on the first element of a frame at POS (its id, and the ics_info of a channel element)."""
    head = bytes(buf[pos:pos + 4])
    v = int.from_bytes(head + bytes(4 - len(head)), "big")
    eid = v >> 29
    if eid not in (c.strict_first_ids if strict else c.first_ids):
        return False
    if eid == ID_SCE or eid == ID_LFE:
        return _ics_info_ok(v, 15, c, False)
    if eid == ID_CPE:
        return _ics_info_ok(v, 8, c, True) if v & 0x01000000 else _ics_info_ok(v, 16, c, False)
    if eid == ID_PCE:
        return (v >> 19) & 15 == c.index
    return True


def frame_length(buf, pos: int, end: int, asc: AudioSpecificConfig, *, strict: bool = False) -> int | None:
    """Bytes of the raw_data_block starting at POS (it must end by END), None when the bits there are not a
    valid AAC frame for ASC. STRICT also wants zero padding bits after ID_END and exactly the channel elements
    of the configuration (what encoders write; the standard doesn't require the first, and some encoders code
    mono as a CPE or stereo as one SCE)."""
    return _measure(buf, pos, end, asc, strict)


def is_frame(buf, pos: int, end: int, asc: AudioSpecificConfig, *, strict: bool = True) -> bool:
    """Whether a valid AAC frame for ASC starts at POS and ends by END (STRICT as for frame_length()): cheap
    checks of the first element first, then the whole frame."""
    c = _config(asc)
    if c is None or not 0 <= pos < min(end, len(buf)) or not _plausible(buf, pos, c, strict):
        return False
    return _measure(buf, pos, end, asc, strict) is not None


CHUNK = 1 << 20


def split_frames(buf, start: int, end: int, asc, limit: int | None = None, *,
                 strict: bool | None = None) -> list[int]:
    """The lengths of the consecutive frames from START while they parse: stops at the first invalid frame, at
    END, or after LIMIT frames. Every frame must have the channel elements of the first one, and with STRICT None
    the first one that has padding bits decides: if they are zero (as encoders write them), a frame whose
    padding isn't ends the run. STRICT True holds every frame to frame_length(strict=True), False to none of
    the padding."""
    out: list[int] = []
    c = _config(asc)
    end = min(end, len(buf))
    if c is None or start < 0:
        return out
    pos = start
    orders = c.strict_orders if strict else None
    zero_padding = strict
    window = 1 << 14                                        # read in growing pieces, up to CHUNK
    while pos < end and (limit is None or len(out) < limit):
        if limit is not None:
            window = min(window, (limit - len(out)) * c.max_bytes)
        stop = min(end, pos + window + c.max_bytes)
        window = min(CHUNK, 4 * window)
        D = _words(buf, pos, stop)
        base = pos
        while pos < end and (limit is None or len(out) < limit):
            lim = min(end, pos + c.max_bytes)
            if lim > stop:
                break                                       # the next frame may run past these words
            try:
                bits, pad, types = _frame(D, (pos - base) * 8, (lim - base) * 8, c, orders)
            except (_Bad, IndexError, BitsError, ValueError):
                return out
            orders = orders or {types}
            if pad >= 0:
                if zero_padding is None:
                    zero_padding = pad == 0
                elif zero_padding and pad:
                    return out
            n = (bits >> 3) - (pos - base)
            out.append(n)
            pos += n
    return out
