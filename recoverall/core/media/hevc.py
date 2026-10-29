"""H.265 (HEVC) bitstreams: NAL units, parameter sets, slice segment headers, picture order and access units.

Like H.264, an HEVC stream is a sequence of NAL units, length-prefixed in MP4/MOV (the hvcC box says how many
bytes the length takes) and separated by start codes elsewhere. The NAL header is two bytes: a forbidden zero
bit, six bits of type, six bits of layer (0 except in multi-layer streams such as MV-HEVC 3D video) and three
bits of temporal id plus one. Types 0-31 carry slice segments (VCL), 32 and up parameter sets and extras:

=======  =================================================  =====  ==============================
0-9      trailing, TSA, STSA, RADL, RASL pictures           32     video parameter set (VPS)
16-21    IRAP pictures (key frames): BLA, IDR, CRA          33/34  sequence / picture parameter sets
                                                            35     access unit delimiter
                                                            39/40  prefix / suffix SEI
=======  =================================================  =====  ==============================

A picture's first slice segment has first_slice_segment_in_pic_flag set: that is where a new access unit (an MP4
sample) begins, unless parameter sets, a delimiter or prefix SEI come first. The picture order count (POC)
comes from slice_pic_order_cnt_lsb and the previous picture of temporal layer 0 (8.3.1); IDR pictures reset it.
RASL pictures after a CRA (open GOP) refer to pictures before it and can't be shown when decoding starts there.

Everything here works on anything that slices like bytes and never raises on damaged data: parsers return None.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .bits import BitReader, BitsError, unescape
from .h264 import payload_ok

TRAIL_N, TRAIL_R, TSA_N, TSA_R, STSA_N, STSA_R, RADL_N, RADL_R, RASL_N, RASL_R = range(10)
BLA_W_LP, BLA_W_RADL, BLA_N_LP, IDR_W_RADL, IDR_N_LP, CRA = range(16, 22)
VPS_NAL, SPS_NAL, PPS_NAL, AUD, EOS, EOB, FD, PREFIX_SEI, SUFFIX_SEI = range(32, 41)

VCL_TYPES = frozenset(range(10)) | frozenset(range(16, 22))
IRAP = frozenset(range(16, 24))
IDR_TYPES = frozenset({IDR_W_RADL, IDR_N_LP})
RASL = frozenset({RASL_N, RASL_R})
AU_START = frozenset({VPS_NAL, SPS_NAL, PPS_NAL, AUD, PREFIX_SEI}) | frozenset(range(41, 45)) | \
    frozenset(range(48, 56))
AFTER_VCL = frozenset({EOS, EOB, FD, SUFFIX_SEI}) | frozenset(range(45, 48)) | frozenset(range(56, 64))
KNOWN_TYPES = VCL_TYPES | frozenset(range(32, 41))


def nal_type(b0: int) -> int:
    return (b0 >> 1) & 63


def header_ok(b0: int, b1: int, layers: frozenset = frozenset({0})) -> bool:
    """A plausible two-byte NAL header: forbidden bit 0, temporal id plus one not 0, a known layer."""
    return not b0 & 0x80 and b1 & 7 != 0 and (((b0 & 1) << 5) | (b1 >> 3)) in layers


def _rbsp(nal, limit: int | None = None) -> bytes:
    return unescape(bytes(nal[2:2 + limit] if limit else nal[2:]))


# ---------------------------------------------------------------------- parameter sets
def _profile_tier_level(r: BitReader, max_sub_layers_minus1: int) -> bytes:
    """Read profile_tier_level(1, ...); return its general part (12 bytes, as hvcC copies it)."""
    general = bytes(r.u(8) for _ in range(12))
    sub_profile, sub_level = [], []
    for _ in range(max_sub_layers_minus1):
        sub_profile.append(r.u1())
        sub_level.append(r.u1())
    if max_sub_layers_minus1 > 0:
        r.skip(2 * (8 - max_sub_layers_minus1))
    for i in range(max_sub_layers_minus1):
        if sub_profile[i]:
            r.skip(88)
        if sub_level[i]:
            r.skip(8)
    return general


@dataclass
class VPS:
    id: int = 0
    max_sub_layers: int = 1
    num_units_in_tick: int = 0
    time_scale: int = 0
    raw: bytes = b""


def parse_vps(nal) -> VPS | None:
    if len(nal) < 6 or nal_type(nal[0]) != VPS_NAL:
        return None
    v = VPS(raw=bytes(nal))
    try:
        r = BitReader(_rbsp(nal, 512))
        v.id = r.u(4)
        r.skip(8)                                         # base layer flags, vps_max_layers_minus1
        v.max_sub_layers = r.u(3) + 1
        r.skip(17)
        _profile_tier_level(r, v.max_sub_layers - 1)
        present = r.u1()
        for _ in range(0 if present else v.max_sub_layers - 1, v.max_sub_layers):
            r.ue()
            r.ue()
            r.ue()
        max_layer_id = r.u(6)
        sets = r.ue() + 1
        if sets > 1024:
            return v
        r.skip((sets - 1) * (max_layer_id + 1))
        if r.u1():
            v.num_units_in_tick, v.time_scale = r.u(32), r.u(32)
    except BitsError:
        pass
    return v


@dataclass
class SPS:
    id: int = 0
    vps_id: int = 0
    max_sub_layers: int = 1
    general: bytes = b""                  # general profile/tier/level (12 bytes)
    chroma_format: int = 1
    separate_colour_plane: bool = False
    width: int = 0
    height: int = 0
    bit_depth_luma: int = 8
    bit_depth_chroma: int = 8
    log2_max_poc_lsb: int = 4
    max_num_reorder: int = 0
    log2_ctb: int = 4
    pic_width_in_ctbs: int = 0
    pic_height_in_ctbs: int = 0
    num_units_in_tick: int = 0
    time_scale: int = 0
    raw: bytes = b""

    @property
    def pic_size_in_ctbs(self) -> int:
        return self.pic_width_in_ctbs * self.pic_height_in_ctbs

    @property
    def fps(self) -> tuple[int, int] | None:
        if self.num_units_in_tick and self.time_scale:
            return self.time_scale, self.num_units_in_tick
        return None


def _skip_scaling_list_data(r: BitReader) -> None:
    for size_id in range(4):
        for _matrix in range(0, 6, 3 if size_id == 3 else 1):
            if not r.u1():
                r.ue()
            else:
                n = min(64, 1 << (4 + (size_id << 1)))
                if size_id > 1:
                    r.se()
                for _ in range(n):
                    r.se()


def _st_ref_pic_set(r: BitReader, idx: int, sets: list[tuple[list[int], list[int]]]) -> tuple[list[int], list[int]]:
    """st_ref_pic_set(idx) of an SPS: the (negative, positive) delta POCs, needed to read the next sets."""
    if idx and r.u1():                                    # inter_ref_pic_set_prediction_flag
        sign, abs_delta = r.u1(), r.ue() + 1
        delta_rps = (1 - 2 * sign) * abs_delta
        neg, pos = sets[idx - 1]
        ref = neg + pos                                    # the reference set's delta POCs (S0 then S1)
        use = []
        for _ in range(len(ref) + 1):
            used = r.u1()
            use.append(1 if used else r.u1())
        new_neg, new_pos = [], []
        for d, u in zip(ref + [0], use):
            dpoc = d + delta_rps
            if u and dpoc:
                (new_neg if dpoc < 0 else new_pos).append(dpoc)
        new_neg.sort(reverse=True)
        new_pos.sort()
        return new_neg, new_pos
    n_neg, n_pos = r.ue(), r.ue()
    if n_neg > 16 or n_pos > 16:
        raise BitsError("bad reference picture set")
    neg, pos = [], []
    poc = 0
    for _ in range(n_neg):
        poc -= r.ue() + 1
        r.skip(1)
        neg.append(poc)
    poc = 0
    for _ in range(n_pos):
        poc += r.ue() + 1
        r.skip(1)
        pos.append(poc)
    return neg, pos


def parse_sps(nal) -> SPS | None:
    """The sequence parameter set in NAL (its two header bytes included), or None."""
    if len(nal) < 16 or nal_type(nal[0]) != SPS_NAL:
        return None
    s = SPS(raw=bytes(nal))
    try:
        r = BitReader(_rbsp(nal, 1024))
        s.vps_id = r.u(4)
        s.max_sub_layers = r.u(3) + 1
        r.skip(1)
        s.general = _profile_tier_level(r, s.max_sub_layers - 1)
        s.id = r.ue()
        if s.id > 15:
            return None
        s.chroma_format = r.ue()
        if s.chroma_format > 3:
            return None
        if s.chroma_format == 3:
            s.separate_colour_plane = bool(r.u1())
        w, h = r.ue(), r.ue()
        if not 0 < w <= 16888 or not 0 < h <= 16888:
            return None
        crop = (r.ue(), r.ue(), r.ue(), r.ue()) if r.u1() else (0, 0, 0, 0)
        sub_w = 2 if s.chroma_format in (1, 2) and not s.separate_colour_plane else 1
        sub_h = 2 if s.chroma_format == 1 and not s.separate_colour_plane else 1
        s.width, s.height = w - sub_w * (crop[0] + crop[1]), h - sub_h * (crop[2] + crop[3])
        s.bit_depth_luma, s.bit_depth_chroma = r.ue() + 8, r.ue() + 8
        s.log2_max_poc_lsb = r.ue() + 4
        if s.log2_max_poc_lsb > 16 or s.bit_depth_luma > 16:
            return None
        present = r.u1()
        for _ in range(0 if present else s.max_sub_layers - 1, s.max_sub_layers):
            r.ue()
            s.max_num_reorder = r.ue()
            r.ue()
        log2_min_cb = r.ue() + 3
        s.log2_ctb = log2_min_cb + r.ue()
        if s.log2_ctb > 6 or log2_min_cb > 6:
            return None
        ctb = 1 << s.log2_ctb
        s.pic_width_in_ctbs, s.pic_height_in_ctbs = -(-w // ctb), -(-h // ctb)
        for _ in range(4):
            r.ue()
        if r.u1() and r.u1():
            _skip_scaling_list_data(r)
        r.skip(2)                                         # amp, sample_adaptive_offset
        if r.u1():                                        # pcm_enabled_flag
            r.skip(8)
            r.ue()
            r.ue()
            r.skip(1)
        n_sets = r.ue()
        if n_sets > 64:
            return s
        sets: list[tuple[list[int], list[int]]] = []
        for i in range(n_sets):
            sets.append(_st_ref_pic_set(r, i, sets))
        if r.u1():                                        # long_term_ref_pics_present_flag
            for _ in range(r.ue()):
                r.skip(s.log2_max_poc_lsb + 1)
        r.skip(2)                                         # temporal mvp, strong intra smoothing
        if r.u1():
            _parse_vui(r, s)
    except BitsError:
        if not s.width:
            return None
    return s


def _parse_vui(r: BitReader, s: SPS) -> None:
    try:
        if r.u1():
            if r.u(8) == 255:
                r.skip(32)
        if r.u1():
            r.skip(1)
        if r.u1():
            r.skip(4)
            if r.u1():
                r.skip(24)
        if r.u1():
            r.ue()
            r.ue()
        r.skip(3)
        if r.u1():
            for _ in range(4):
                r.ue()
        if r.u1():
            s.num_units_in_tick, s.time_scale = r.u(32), r.u(32)
    except BitsError:
        pass


@dataclass
class PPS:
    id: int = 0
    sps_id: int = 0
    dependent_slice_segments: bool = False
    output_flag_present: bool = False
    num_extra_slice_header_bits: int = 0
    raw: bytes = b""


def parse_pps(nal) -> PPS | None:
    if len(nal) < 3 or nal_type(nal[0]) != PPS_NAL:
        return None
    p = PPS(raw=bytes(nal))
    try:
        r = BitReader(_rbsp(nal, 64))
        p.id, p.sps_id = r.ue(), r.ue()
        if p.id > 63 or p.sps_id > 15:
            return None
        p.dependent_slice_segments = bool(r.u1())
        p.output_flag_present = bool(r.u1())
        p.num_extra_slice_header_bits = r.u(3)
    except BitsError:
        return None
    return p


class ParamSets:
    """The VPSs, SPSs and PPSs of a stream by id."""

    def __init__(self):
        self.vps: dict[int, VPS] = {}
        self.sps: dict[int, SPS] = {}
        self.pps: dict[int, PPS] = {}

    def add(self, nal) -> bool:
        t = nal_type(nal[0]) if len(nal) else -1
        if t == VPS_NAL:
            v = parse_vps(nal)
            if v is not None:
                self.vps[v.id] = v
                return True
        elif t == SPS_NAL:
            s = parse_sps(nal)
            if s is not None:
                self.sps[s.id] = s
                return True
        elif t == PPS_NAL:
            p = parse_pps(nal)
            if p is not None and p.sps_id in self.sps:
                self.pps[p.id] = p
                return True
        return False

    def __bool__(self) -> bool:
        return bool(self.sps and self.pps)

    def fps(self) -> tuple[int, int] | None:
        for s in self.sps.values():
            if s.fps:
                return s.fps
        for v in self.vps.values():
            if v.num_units_in_tick and v.time_scale:
                return v.time_scale, v.num_units_in_tick
        return None


# ---------------------------------------------------------------------- hvcC
@dataclass
class HevcConfig:
    length_size: int = 4
    arrays: list[tuple[int, list[bytes]]] = field(default_factory=list)    # (NAL type, NAL units)

    def nals(self, t: int) -> list[bytes]:
        return [n for typ, ns in self.arrays if typ == t for n in ns]

    def params(self) -> ParamSets:
        ps = ParamSets()
        for t in (VPS_NAL, SPS_NAL, PPS_NAL):
            for n in self.nals(t):
                ps.add(n)
        return ps


def parse_hvcc(payload) -> HevcConfig | None:
    """The HEVC decoder configuration record (the payload of an hvcC box)."""
    try:
        if len(payload) < 23:
            return None
        c = HevcConfig(length_size=(payload[21] & 3) + 1)
        pos = 23
        for _ in range(payload[22]):
            t = payload[pos] & 63
            count = struct.unpack_from(">H", payload, pos + 1)[0]
            pos += 3
            nals = []
            for _ in range(count):
                n = struct.unpack_from(">H", payload, pos)[0]
                nals.append(bytes(payload[pos + 2:pos + 2 + n]))
                pos += 2 + n
            c.arrays.append((t, nals))
        if c.length_size == 3:
            return None
        return c
    except (struct.error, IndexError):
        return None


def build_hvcc(vps: list[bytes], sps: list[bytes], pps: list[bytes], length_size: int = 4,
               sei: list[bytes] = ()) -> bytes:
    """An hvcC payload for the parameter sets (NAL units with their two header bytes)."""
    s = parse_sps(sps[0]) if sps else None
    general = s.general if s is not None else bytes(12)
    out = bytearray([1]) + general[:1] + general[1:5] + general[5:11] + general[11:12]
    out += struct.pack(">HBBBBH", 0xF000, 0xFC, 0xFC | (s.chroma_format if s else 1),
                       0xF8 | ((s.bit_depth_luma - 8) if s else 0), 0xF8 | ((s.bit_depth_chroma - 8) if s else 0), 0)
    layers = s.max_sub_layers if s else 1
    out.append(((layers & 7) << 3) | (1 << 2) | (length_size - 1))
    arrays = [(VPS_NAL, list(vps)), (SPS_NAL, list(sps)), (PPS_NAL, list(pps)), (PREFIX_SEI, list(sei))]
    arrays = [a for a in arrays if a[1]]
    out.append(len(arrays))
    for t, nals in arrays:
        out += struct.pack(">BH", 0x80 | t, len(nals))
        for n in nals:
            out += struct.pack(">H", len(n)) + n
    return bytes(out)


# ---------------------------------------------------------------------- slice segment headers
@dataclass
class SliceHeader:
    nal_type: int = 0
    layer: int = 0
    temporal_id: int = 0
    first_in_pic: bool = False
    pps_id: int = 0
    dependent: bool = False
    address: int = 0
    slice_type: int = 2                    # 0 B, 1 P, 2 I
    poc_lsb: int = 0

    @property
    def irap(self) -> bool:
        return self.nal_type in IRAP

    @property
    def idr(self) -> bool:
        return self.nal_type in IDR_TYPES

    @property
    def rasl(self) -> bool:
        return self.nal_type in RASL

    @property
    def sub_layer_non_ref(self) -> bool:
        return self.nal_type <= 14 and self.nal_type % 2 == 0


def parse_slice_header(nal, params: ParamSets) -> tuple[SliceHeader, SPS, PPS] | None:
    """The slice segment header up to slice_pic_order_cnt_lsb, checked against the parameter sets."""
    if len(nal) < 3:
        return None
    h = SliceHeader(nal_type=nal_type(nal[0]), layer=((nal[0] & 1) << 5) | (nal[1] >> 3),
                    temporal_id=(nal[1] & 7) - 1)
    try:
        r = BitReader(_rbsp(nal, 48))
        h.first_in_pic = bool(r.u1())
        if h.irap:
            if h.temporal_id != 0:
                return None
            r.skip(1)
        h.pps_id = r.ue()
        pps = params.pps.get(h.pps_id)
        if pps is None:
            return None
        sps = params.sps.get(pps.sps_id)
        if sps is None:
            return None
        if not h.first_in_pic:
            if pps.dependent_slice_segments:
                h.dependent = bool(r.u1())
            n = sps.pic_size_in_ctbs
            h.address = r.u(max(1, (n - 1).bit_length()))
            if h.address >= n:
                return None
        if not h.dependent:
            r.skip(pps.num_extra_slice_header_bits)
            h.slice_type = r.ue()
            if h.slice_type > 2 or (h.irap and h.layer == 0 and h.slice_type != 2):
                return None
            if pps.output_flag_present:
                r.skip(1)
            if sps.separate_colour_plane:
                r.skip(2)
            if not h.idr:
                h.poc_lsb = r.u(sps.log2_max_poc_lsb)
    except BitsError:
        return None
    return h, sps, pps


class PocState:
    """Picture order counts (8.3.1) of one stream's pictures, fed in decoding order."""

    def __init__(self):
        self.prev_tid0 = 0
        self.first = True

    def poc(self, h: SliceHeader, sps: SPS) -> int:
        max_lsb = 1 << sps.log2_max_poc_lsb
        if h.irap and (h.nal_type < CRA or self.first):
            msb = 0                                      # IDR, BLA, or the stream starts here
        else:
            prev_lsb = self.prev_tid0 & (max_lsb - 1)
            prev_msb = self.prev_tid0 - prev_lsb
            lsb = h.poc_lsb
            if lsb < prev_lsb and prev_lsb - lsb >= max_lsb // 2:
                msb = prev_msb + max_lsb
            elif lsb > prev_lsb and lsb - prev_lsb > max_lsb // 2:
                msb = prev_msb - max_lsb
            else:
                msb = prev_msb
        poc = msb + h.poc_lsb
        self.first = False
        if h.temporal_id == 0 and not (h.nal_type in (RADL_N, RADL_R, RASL_N, RASL_R) or h.sub_layer_non_ref):
            self.prev_tid0 = poc
        return poc

    def end_of_sequence(self) -> None:
        self.first = True


# ---------------------------------------------------------------------- access units
@dataclass
class AccessUnit:
    size: int = 0
    nals: int = 0
    header: SliceHeader | None = None     # the base layer's first slice segment header
    sps: SPS | None = None
    params: bool = False
    eos: bool = False                     # ends with an end of sequence / bitstream NAL unit
    types: tuple = ()

    @property
    def key(self) -> bool:
        return self.header is not None and self.header.irap

    @property
    def idr(self) -> bool:
        return self.header is not None and self.header.nal_type in IDR_TYPES


class HevcReader:
    """Reads access units from length-prefixed HEVC data (MP4 samples); see h264.AvcReader."""

    def __init__(self, params: ParamSets, length_size: int = 4, max_nal: int = 64 << 20,
                 types: frozenset | None = None, layers: frozenset = frozenset({0})):
        self.params = params
        self.length_size = length_size
        self.max_nal = max_nal
        self.types = types
        self.layers = layers

    def first_ok(self, buf, pos: int, end: int) -> bool:
        ls = self.length_size
        if pos + ls + 3 > end:
            return False
        n = int.from_bytes(buf[pos:pos + ls], "big")
        if n < 3 or n > self.max_nal or pos + ls + n > end:
            return False
        b0, b1 = buf[pos + ls], buf[pos + ls + 1]
        t = (b0 >> 1) & 63
        return header_ok(b0, b1, self.layers) and (t in KNOWN_TYPES if self.types is None else t in self.types)

    def read(self, buf, pos: int, end: int, learn: bool = True) -> AccessUnit | None:
        ls = self.length_size
        max_nal = self.max_nal
        types = self.types
        layers = self.layers
        params = self.params
        au = AccessUnit()
        p = pos
        seen_vcl = False
        tlist: list[int] = []
        while p + ls + 2 < end:
            n = int.from_bytes(buf[p:p + ls], "big")
            if n < 2 or n > max_nal or p + ls + n > end:
                break
            a = p + ls
            b0, b1 = buf[a], buf[a + 1]
            if not header_ok(b0, b1, layers):
                break
            t = (b0 >> 1) & 63
            if types is not None and t not in types:
                break
            layer = ((b0 & 1) << 5) | (b1 >> 3)
            if not payload_ok(buf, a, a + n):
                return None                                   # damaged
            if t in VCL_TYPES:
                parsed = parse_slice_header(buf[a:a + min(n, 64)], params)
                if parsed is None:
                    break
                sh, sps, _pps = parsed
                if layer == 0:
                    if au.header is None:
                        if not sh.first_in_pic:
                            return None                       # the middle of a picture
                        au.header, au.sps = sh, sps
                    elif sh.first_in_pic:
                        break                                 # the next picture
                elif au.header is None:
                    return None
                seen_vcl = True
            elif t in AU_START or (22 <= t <= 31):
                if (seen_vcl and layer == 0) or t in range(22, 32):
                    break
                if t in (VPS_NAL, SPS_NAL, PPS_NAL):
                    nal = bytes(buf[a:a + n])
                    if learn:
                        ok = params.add(nal)
                    else:
                        ok = {VPS_NAL: parse_vps, SPS_NAL: parse_sps, PPS_NAL: parse_pps}[t](nal) is not None
                    if not ok:
                        break
                    au.params = True
                elif t == AUD and tlist:
                    break
            elif t in AFTER_VCL:
                if not seen_vcl:
                    break
                if t in (EOS, EOB):
                    tlist.append(t)
                    p += ls + n
                    au.eos = True
                    break
            else:
                break
            tlist.append(t)
            p += ls + n
        if not seen_vcl:
            return None
        au.size = p - pos
        au.nals = len(tlist)
        au.types = tuple(tlist)
        return au


def find_params(buf, start: int, end: int, length_size: int = 4, limit: int = 1 << 20) -> ParamSets:
    """The parameter sets that a camera repeats in the stream, within the first LIMIT bytes of length-prefixed
    data from START: a VPS, SPS and PPS right after each other. Else an empty ParamSets."""
    ps = ParamSets()
    stop = min(end, start + limit)
    ls = length_size
    i = buf.find(b"\x40\x01", start + ls, stop)
    while i >= 0:
        chain = []
        p = i
        for want in (VPS_NAL, SPS_NAL, PPS_NAL):
            n = int.from_bytes(buf[p - ls:p], "big")
            if not 3 <= n < 8192 or p + n > end or nal_type(buf[p]) != want or buf[p + 1] != 1:
                break
            chain.append(bytes(buf[p:p + n]))
            p += n + ls
        if len(chain) == 3:
            trial = ParamSets()
            if all(trial.add(nal) for nal in chain):
                ps.vps.update(trial.vps)
                ps.sps.update(trial.sps)
                ps.pps.update(trial.pps)
        i = buf.find(b"\x40\x01", i + 1, stop)
    return ps
