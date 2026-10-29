"""H.264 (AVC) bitstreams: NAL units, parameter sets, slice headers, picture order and access units.

An H.264 stream is a sequence of NAL units. In MP4/MOV files every NAL unit is preceded by its length (1, 2 or 4
bytes, as the avcC box says: "AVCC" or length-prefixed form); in raw .h264 files and MPEG-TS they are separated by
start codes 00 00 01 ("Annex B"). The first byte of a NAL unit is its header: a forbidden zero bit, two bits of
nal_ref_idc (0: nothing refers to this picture) and five bits of type:

====  ===============================================  ====  ======================================
1     slice of a non-IDR picture                       7     sequence parameter set (SPS)
2-4   slice data partitions A, B, C                    8     picture parameter set (PPS)
5     slice of an IDR picture (a key frame)            9     access unit delimiter (AUD)
6     SEI (extra information: recovery points, ...)   10/11 end of sequence / end of stream
12    filler data                                      13-21 SPS extension, SVC/MVC extensions
====  ===============================================  ====  ======================================

One coded picture (a frame, or a field pair) is an access unit: in MP4 files that is one sample. Its slices
start with a slice header whose first fields (first_mb_in_slice, slice_type, the PPS used, frame_num, the field
flags, idr_pic_id and the picture order count) tell where a new picture begins (7.4.1.2.4) and in which order
pictures are shown: B-frames are decoded after the later frames they refer to, and the picture order count (POC)
puts them back in place. The SPS gives the bit widths of those fields (log2_max_frame_num, the POC type and its
parameters, frame_mbs_only) and the picture size; the PPS links a slice to its SPS.

Everything here works on anything that slices like bytes and never raises on damaged data: parsers return None.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Iterator

from .bits import BitReader, BitsError, unescape

SLICE, DPA, DPB, DPC, IDR, SEI, SPS_NAL, PPS_NAL, AUD, END_SEQ, END_STREAM, FILLER = range(1, 13)
SPS_EXT, PREFIX, SUBSET_SPS, DPS, AUX_SLICE, SLICE_EXT, SLICE_EXT_3D = 13, 14, 15, 16, 19, 20, 21

VCL = frozenset({SLICE, DPA, IDR})                 # NAL units that start a picture's coded data
# NAL units that begin a new access unit when they follow the last slice of a picture (7.4.1.2.3)
AU_START = frozenset({SEI, SPS_NAL, PPS_NAL, AUD, PREFIX, SUBSET_SPS, DPS, 17, 18})
HIGH_PROFILES = frozenset({100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135})
SLICE_TYPES = "PBIpi"                              # slice_type % 5: P, B, I, SP, SI


def _header_table() -> bytes:
    """For every possible first byte: 1 if it is a plausible NAL header (forbidden bit 0, a defined type, a
    nal_ref_idc the type allows)."""
    ok = bytearray(256)
    for b in range(128):
        ref, t = b >> 5, b & 31
        if t == 0 or 22 <= t:
            continue
        if t == IDR and ref == 0:
            continue
        if t in (SEI, AUD, END_SEQ, END_STREAM, FILLER) and ref != 0:
            continue
        ok[b] = 1
    return bytes(ok)


HEADER_OK = _header_table()


def header_ok(h: int) -> bool:
    return bool(HEADER_OK[h & 0xFF])


# ---------------------------------------------------------------------- NAL units
def iter_nals(buf, start: int, end: int, length_size: int = 4) -> Iterator[tuple[int, int]]:
    """The NAL units of length-prefixed data in [START, END): (payload start, payload end). Stops at a length
    that runs past END or is zero."""
    pos = start
    while pos + length_size < end:
        n = int.from_bytes(buf[pos:pos + length_size], "big")
        if n == 0 or pos + length_size + n > end:
            return
        yield pos + length_size, pos + length_size + n
        pos += length_size + n


def iter_annexb(buf, start: int = 0, end: int | None = None) -> Iterator[tuple[int, int]]:
    """The NAL units of an Annex B stream (start codes 00 00 01 / 00 00 00 01): (start, end) without the
    start codes and the trailing zero bytes."""
    end = len(buf) if end is None else min(end, len(buf))
    find = buf.find
    pos = find(b"\x00\x00\x01", start, end)
    while 0 <= pos:
        a = pos + 3
        nxt = find(b"\x00\x00\x01", a, end)
        b = end if nxt < 0 else nxt
        while b > a and buf[b - 1] == 0:
            b -= 1
        if b > a:
            yield a, b
        pos = nxt


_FORBIDDEN = re.compile(rb"\x00\x00[\x00-\x02]")
ZERO_TAIL = 64                        # zero bytes an encoder may leave at the end of a NAL unit


def payload_ok(buf, start: int, end: int) -> bool:
    """Can [START, END) be a NAL unit's bytes? Inside one, 00 00 00/01/02 never occurs (emulation prevention
    escapes it), so finding it means damage (a zeroed or overwritten stretch) - except a short run of zero
    bytes at the end, which some encoders leave."""
    m = _FORBIDDEN.search(buf, start, end)
    if m is None:
        return True
    p = m.start()
    return end - p <= ZERO_TAIL and not bytes(buf[p:end]).strip(b"\x00")


def annexb(nals) -> bytes:
    """NAL units (bytes) joined with 4-byte start codes."""
    return b"".join(b"\x00\x00\x00\x01" + bytes(n) for n in nals)


def _rbsp(nal, limit: int | None = None, header: int = 1) -> bytes:
    """The NAL unit's payload after its header, emulation-prevention bytes removed (only the first LIMIT bytes,
    which is enough for headers)."""
    data = bytes(nal[header:header + limit] if limit else nal[header:])
    return unescape(data)


# ---------------------------------------------------------------------- parameter sets
@dataclass
class SPS:
    id: int = 0
    profile: int = 0
    constraints: int = 0
    level: int = 0
    chroma_format: int = 1
    separate_colour_plane: bool = False
    bit_depth_luma: int = 8
    bit_depth_chroma: int = 8
    log2_max_frame_num: int = 4
    poc_type: int = 0
    log2_max_poc_lsb: int = 4
    delta_pic_order_always_zero: bool = False
    offset_for_non_ref_pic: int = 0
    offset_for_top_to_bottom_field: int = 0
    offsets_for_ref_frame: list[int] = field(default_factory=list)
    max_num_ref_frames: int = 0
    width_mbs: int = 0
    height_map_units: int = 0
    frame_mbs_only: bool = True
    mbaff: bool = False
    width: int = 0
    height: int = 0
    sar: tuple[int, int] = (1, 1)
    num_units_in_tick: int = 0
    time_scale: int = 0
    fixed_frame_rate: bool = False
    max_num_reorder_frames: int | None = None
    raw: bytes = b""

    @property
    def pic_size_in_mbs(self) -> int:
        return self.width_mbs * self.height_map_units * (1 if self.frame_mbs_only else 2)

    @property
    def fps(self) -> tuple[int, int] | None:
        """The frame rate from the VUI timing (time_scale / (2 · num_units_in_tick)) as (num, den)."""
        if self.num_units_in_tick and self.time_scale:
            return self.time_scale, 2 * self.num_units_in_tick
        return None


def _skip_scaling_list(r: BitReader, size: int) -> None:
    last = nxt = 8
    for _ in range(size):
        if nxt:
            nxt = (last + r.se() + 256) % 256
        last = nxt or last


def _skip_hrd(r: BitReader) -> None:
    count = r.ue() + 1
    if count > 32:
        raise BitsError("bad HRD")
    r.skip(8)
    for _ in range(count):
        r.ue()
        r.ue()
        r.skip(1)
    r.skip(20)


_SAR = {1: (1, 1), 2: (12, 11), 3: (10, 11), 4: (16, 11), 5: (40, 33), 6: (24, 11), 7: (20, 11), 8: (32, 11),
        9: (80, 33), 10: (18, 11), 11: (15, 11), 12: (64, 33), 13: (160, 99), 14: (4, 3), 15: (3, 2), 16: (2, 1)}


def parse_sps(nal) -> SPS | None:
    """The sequence parameter set in the NAL unit NAL (header byte included), or None when it isn't one."""
    if len(nal) < 4 or nal[0] & 0x9F != SPS_NAL:
        return None
    s = SPS(raw=bytes(nal))
    try:
        r = BitReader(_rbsp(nal, 512))
        s.profile, s.constraints, s.level = r.u(8), r.u(8), r.u(8)
        s.id = r.ue()
        if s.id > 31:
            return None
        if s.profile in HIGH_PROFILES:
            s.chroma_format = r.ue()
            if s.chroma_format > 3:
                return None
            if s.chroma_format == 3:
                s.separate_colour_plane = bool(r.u1())
            s.bit_depth_luma, s.bit_depth_chroma = r.ue() + 8, r.ue() + 8
            if s.bit_depth_luma > 14 or s.bit_depth_chroma > 14:
                return None
            r.skip(1)
            if r.u1():
                for i in range(8 if s.chroma_format != 3 else 12):
                    if r.u1():
                        _skip_scaling_list(r, 16 if i < 6 else 64)
        s.log2_max_frame_num = r.ue() + 4
        s.poc_type = r.ue()
        if s.log2_max_frame_num > 16 or s.poc_type > 2:
            return None
        if s.poc_type == 0:
            s.log2_max_poc_lsb = r.ue() + 4
            if s.log2_max_poc_lsb > 16:
                return None
        elif s.poc_type == 1:
            s.delta_pic_order_always_zero = bool(r.u1())
            s.offset_for_non_ref_pic = r.se()
            s.offset_for_top_to_bottom_field = r.se()
            n = r.ue()
            if n > 255:
                return None
            s.offsets_for_ref_frame = [r.se() for _ in range(n)]
        s.max_num_ref_frames = r.ue()
        r.skip(1)                                        # gaps_in_frame_num_value_allowed_flag
        s.width_mbs, s.height_map_units = r.ue() + 1, r.ue() + 1
        if s.width_mbs > 1024 or s.height_map_units > 1024 or s.max_num_ref_frames > 32:
            return None
        s.frame_mbs_only = bool(r.u1())
        if not s.frame_mbs_only:
            s.mbaff = bool(r.u1())
        r.skip(1)                                        # direct_8x8_inference_flag
        crop = (0, 0, 0, 0)
        if r.u1():
            crop = (r.ue(), r.ue(), r.ue(), r.ue())
        mono = s.chroma_format == 0 or s.separate_colour_plane
        cx = 1 if mono or s.chroma_format == 3 else 2
        cy = (1 if mono or s.chroma_format != 1 else 2) * (2 - s.frame_mbs_only)
        s.width = s.width_mbs * 16 - cx * (crop[0] + crop[1])
        s.height = s.height_map_units * 16 * (2 - s.frame_mbs_only) - cy * (crop[2] + crop[3])
        if r.left > 0 and r.u1():
            _parse_vui(r, s)
    except BitsError:
        if not s.width_mbs:
            return None
    return s


def _parse_vui(r: BitReader, s: SPS) -> None:
    try:
        if r.u1():
            idc = r.u(8)
            s.sar = (r.u(16), r.u(16)) if idc == 255 else _SAR.get(idc, (1, 1))
        if r.u1():
            r.skip(1)
        if r.u1():
            r.skip(4)
            if r.u1():
                r.skip(24)
        if r.u1():
            r.ue()
            r.ue()
        if r.u1():
            s.num_units_in_tick, s.time_scale = r.u(32), r.u(32)
            s.fixed_frame_rate = bool(r.u1())
        nal_hrd = r.u1()
        if nal_hrd:
            _skip_hrd(r)
        vcl_hrd = r.u1()
        if vcl_hrd:
            _skip_hrd(r)
        if nal_hrd or vcl_hrd:
            r.skip(1)
        r.skip(1)                                        # pic_struct_present_flag
        if r.u1():
            r.skip(1)
            for _ in range(4):
                r.ue()
            s.max_num_reorder_frames = r.ue()
    except BitsError:
        pass


@dataclass
class PPS:
    id: int = 0
    sps_id: int = 0
    entropy_coding_mode: bool = False
    bottom_field_pic_order_in_frame_present: bool = False
    num_slice_groups: int = 1
    redundant_pic_cnt_present: bool = False
    raw: bytes = b""


def parse_pps(nal) -> PPS | None:
    """The picture parameter set in NAL (header byte included), or None."""
    if len(nal) < 2 or nal[0] & 0x9F != PPS_NAL:
        return None
    p = PPS(raw=bytes(nal))
    try:
        r = BitReader(_rbsp(nal, 256))
        p.id, p.sps_id = r.ue(), r.ue()
        if p.id > 255 or p.sps_id > 31:
            return None
        p.entropy_coding_mode = bool(r.u1())
        p.bottom_field_pic_order_in_frame_present = bool(r.u1())
        p.num_slice_groups = r.ue() + 1
        if p.num_slice_groups > 8:
            return None
        if p.num_slice_groups > 1:
            kind = r.ue()
            if kind == 0:
                for _ in range(p.num_slice_groups):
                    r.ue()
            elif kind == 2:
                for _ in range(p.num_slice_groups - 1):
                    r.ue()
                    r.ue()
            elif kind in (3, 4, 5):
                r.skip(1)
                r.ue()
            elif kind == 6:
                n = r.ue() + 1
                bits = (p.num_slice_groups - 1).bit_length()
                r.skip(n * bits)
            elif kind > 6:
                return None
        if r.ue() > 31 or r.ue() > 31:                   # num_ref_idx_l0/l1_default_active_minus1
            return None
        r.skip(3)                                        # weighted_pred_flag, weighted_bipred_idc
        r.se()
        r.se()
        r.se()                                           # pic_init_qp/qs, chroma_qp_index_offset
        r.skip(2)                                        # deblocking_filter_control, constrained_intra_pred
        p.redundant_pic_cnt_present = bool(r.u1())
    except BitsError:
        return None
    return p


class ParamSets:
    """The SPSs and PPSs of a stream by id, as found in avcC or in the stream itself."""

    def __init__(self):
        self.sps: dict[int, SPS] = {}
        self.pps: dict[int, PPS] = {}

    def add(self, nal) -> bool:
        """Remember NAL when it is an SPS or PPS that parses; True when it was one."""
        t = nal[0] & 31 if len(nal) else 0
        if t == SPS_NAL:
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

    def copy(self) -> ParamSets:
        c = ParamSets()
        c.sps, c.pps = dict(self.sps), dict(self.pps)
        return c

    def __bool__(self) -> bool:
        return bool(self.sps and self.pps)


# ---------------------------------------------------------------------- avcC
@dataclass
class AvcConfig:
    length_size: int = 4
    profile: int = 0
    compat: int = 0
    level: int = 0
    sps: list[bytes] = field(default_factory=list)
    pps: list[bytes] = field(default_factory=list)

    def params(self) -> ParamSets:
        ps = ParamSets()
        for n in self.sps + self.pps:
            ps.add(n)
        return ps


def parse_avcc(payload) -> AvcConfig | None:
    """The AVC decoder configuration record (the payload of an avcC box)."""
    try:
        if len(payload) < 7 or payload[0] != 1:
            return None
        c = AvcConfig(length_size=(payload[4] & 3) + 1, profile=payload[1], compat=payload[2], level=payload[3])
        pos = 6
        for _ in range(payload[5] & 31):
            n = struct.unpack_from(">H", payload, pos)[0]
            c.sps.append(bytes(payload[pos + 2:pos + 2 + n]))
            pos += 2 + n
        count = payload[pos]
        pos += 1
        for _ in range(count):
            n = struct.unpack_from(">H", payload, pos)[0]
            c.pps.append(bytes(payload[pos + 2:pos + 2 + n]))
            pos += 2 + n
        if c.length_size == 3 or not c.sps:
            return None
        return c
    except (struct.error, IndexError):
        return None


def build_avcc(sps_list: list[bytes], pps_list: list[bytes], length_size: int = 4) -> bytes:
    """An avcC payload for the parameter sets (NAL units with their header byte)."""
    first = sps_list[0]
    out = bytearray([1, first[1], first[2], first[3], 0xFC | (length_size - 1), 0xE0 | len(sps_list)])
    for s in sps_list:
        out += struct.pack(">H", len(s)) + s
    out.append(len(pps_list))
    for p in pps_list:
        out += struct.pack(">H", len(p)) + p
    if first[1] in (100, 110, 122, 144):
        s = parse_sps(first)
        if s is not None:
            out += bytes([0xFC | s.chroma_format, 0xF8 | (s.bit_depth_luma - 8), 0xF8 | (s.bit_depth_chroma - 8), 0])
    return bytes(out)


# ---------------------------------------------------------------------- slice headers
@dataclass
class SliceHeader:
    nal_type: int = 0
    ref_idc: int = 0
    first_mb: int = 0
    slice_type: int = 0
    pps_id: int = 0
    colour_plane: int = 0
    frame_num: int = 0
    field_pic: bool = False
    bottom_field: bool = False
    idr_pic_id: int = 0
    poc_lsb: int = 0
    delta_poc_bottom: int = 0
    delta_poc: tuple[int, int] = (0, 0)
    redundant_pic_cnt: int = 0

    @property
    def idr(self) -> bool:
        return self.nal_type == IDR

    @property
    def intra(self) -> bool:
        return self.slice_type % 5 in (2, 4)


def parse_slice_header(nal, params: ParamSets) -> tuple[SliceHeader, SPS, PPS] | None:
    """The first fields of a slice header (NAL includes its header byte), checked against the parameter sets:
    None when the slice doesn't fit them (an unknown PPS, values out of range): damaged or not a slice."""
    if len(nal) < 2:
        return None
    h = SliceHeader(nal_type=nal[0] & 31, ref_idc=(nal[0] >> 5) & 3)
    try:
        r = BitReader(_rbsp(nal, 48))
        h.first_mb, h.slice_type, h.pps_id = r.ue(), r.ue(), r.ue()
        if h.slice_type > 9:
            return None
        pps = params.pps.get(h.pps_id)
        if pps is None:
            return None
        sps = params.sps.get(pps.sps_id)
        if sps is None:
            return None
        if h.idr and not h.intra:
            return None
        if sps.separate_colour_plane:
            h.colour_plane = r.u(2)
            if h.colour_plane > 2:
                return None
        h.frame_num = r.u(sps.log2_max_frame_num)
        if h.idr and h.frame_num:
            return None
        if not sps.frame_mbs_only:
            h.field_pic = bool(r.u1())
            if h.field_pic:
                h.bottom_field = bool(r.u1())
        size = sps.pic_size_in_mbs // (2 if h.field_pic else 1)
        if h.first_mb * (2 if sps.mbaff and not h.field_pic else 1) >= size:
            return None
        if h.idr:
            h.idr_pic_id = r.ue()
            if h.idr_pic_id > 65535:
                return None
        if sps.poc_type == 0:
            h.poc_lsb = r.u(sps.log2_max_poc_lsb)
            if pps.bottom_field_pic_order_in_frame_present and not h.field_pic:
                h.delta_poc_bottom = r.se()
        elif sps.poc_type == 1 and not sps.delta_pic_order_always_zero:
            d0 = r.se()
            d1 = r.se() if pps.bottom_field_pic_order_in_frame_present and not h.field_pic else 0
            h.delta_poc = (d0, d1)
        if pps.redundant_pic_cnt_present:
            h.redundant_pic_cnt = r.ue()
            if h.redundant_pic_cnt > 127:
                return None
    except BitsError:
        return None
    return h, sps, pps


def new_picture(prev: SliceHeader, cur: SliceHeader, sps: SPS) -> bool:
    """Does slice CUR start a new primary coded picture after slice PREV (7.4.1.2.4)?"""
    if cur.redundant_pic_cnt:
        return False
    if cur.first_mb == 0 and not prev.redundant_pic_cnt:
        return True
    if (cur.frame_num != prev.frame_num or cur.pps_id != prev.pps_id or cur.field_pic != prev.field_pic
            or cur.bottom_field != prev.bottom_field or (cur.ref_idc == 0) != (prev.ref_idc == 0)
            or cur.idr != prev.idr or (cur.idr and cur.idr_pic_id != prev.idr_pic_id)):
        return True
    if sps.poc_type == 0:
        return cur.poc_lsb != prev.poc_lsb or cur.delta_poc_bottom != prev.delta_poc_bottom
    if sps.poc_type == 1:
        return cur.delta_poc != prev.delta_poc
    return False


# ---------------------------------------------------------------------- SEI
def sei_messages(nal) -> list[tuple[int, bytes]]:
    """The (payload type, payload) of every message in an SEI NAL unit."""
    out: list[tuple[int, bytes]] = []
    data = _rbsp(nal, 4096)
    pos = 0
    n = len(data)
    while pos < n and data[pos] != 0x80:
        t = 0
        while pos < n and data[pos] == 0xFF:
            t += 255
            pos += 1
        if pos >= n:
            break
        t += data[pos]
        pos += 1
        size = 0
        while pos < n and data[pos] == 0xFF:
            size += 255
            pos += 1
        if pos >= n:
            break
        size += data[pos]
        pos += 1
        out.append((t, data[pos:pos + size]))
        pos += size
    return out


def recovery_frames(nal) -> int | None:
    """recovery_frame_cnt of a recovery point SEI message in the SEI NAL unit (an "open GOP" key frame: the
    pictures are right again after that many frames), or None."""
    try:
        for t, payload in sei_messages(nal):
            if t == 6 and payload:
                return BitReader(payload).ue()
    except BitsError:
        pass
    return None


# ---------------------------------------------------------------------- picture order
class PocState:
    """Picture order counts (8.2.1) of the pictures of one stream, fed in decoding order. Memory management
    operation 5 (a reset in the middle of a stream, rare outside broadcast) isn't followed."""

    def __init__(self):
        self.prev_msb = 0
        self.prev_lsb = 0
        self.prev_frame_num = 0
        self.prev_offset = 0

    def poc(self, h: SliceHeader, sps: SPS) -> int:
        """The POC of the picture (frame or field) whose first slice header is H."""
        if sps.poc_type == 0:
            if h.idr:
                self.prev_msb = self.prev_lsb = 0
            max_lsb = 1 << sps.log2_max_poc_lsb
            lsb = h.poc_lsb
            if lsb < self.prev_lsb and self.prev_lsb - lsb >= max_lsb // 2:
                msb = self.prev_msb + max_lsb
            elif lsb > self.prev_lsb and lsb - self.prev_lsb > max_lsb // 2:
                msb = self.prev_msb - max_lsb
            else:
                msb = self.prev_msb
            if h.ref_idc:
                self.prev_msb, self.prev_lsb = msb, lsb
            top = msb + lsb
            if h.field_pic:
                return top
            return min(top, top + h.delta_poc_bottom)
        max_frame_num = 1 << sps.log2_max_frame_num
        if h.idr:
            offset = 0
        elif self.prev_frame_num > h.frame_num:
            offset = self.prev_offset + max_frame_num
        else:
            offset = self.prev_offset
        self.prev_frame_num, self.prev_offset = h.frame_num, offset
        if sps.poc_type == 2:
            if h.idr:
                return 0
            return 2 * (offset + h.frame_num) - (0 if h.ref_idc else 1)
        cycle = sps.offsets_for_ref_frame
        n = len(cycle)
        absn = offset + h.frame_num if n else 0
        if h.ref_idc == 0 and absn > 0:
            absn -= 1
        expected = 0
        if absn > 0:
            cycles, within = divmod(absn - 1, n)
            expected = cycles * sum(cycle) + sum(cycle[:within + 1])
        if h.ref_idc == 0:
            expected += sps.offset_for_non_ref_pic
        top = expected + h.delta_poc[0]
        if h.field_pic:
            return top + (sps.offset_for_top_to_bottom_field if h.bottom_field else 0)
        bottom = top + sps.offset_for_top_to_bottom_field + h.delta_poc[1]
        return min(top, bottom)


# ---------------------------------------------------------------------- access units
@dataclass
class AccessUnit:
    """One coded picture found in length-prefixed data: SIZE bytes from where it was read."""
    size: int = 0
    nals: int = 0
    idr: bool = False
    intra: bool = False                     # every slice is an I (or SI) slice
    recovery: int | None = None             # recovery_frame_cnt of a recovery point SEI
    header: SliceHeader | None = None       # the first slice's header
    sps: SPS | None = None
    second_field: SliceHeader | None = None  # a field pair: the second field's first slice
    params: bool = False                    # carries an SPS or PPS
    types: tuple = ()

    @property
    def key(self) -> bool:
        return self.idr or (self.intra and self.recovery == 0)


class AvcReader:
    """Reads access units from length-prefixed H.264 data (MP4 samples) at given positions.

    PARAMS are the parameter sets (from avcC; SPS/PPS NAL units met in the data are added); MAX_NAL caps a NAL
    unit's length (anything longer is taken for garbage); TYPES limits the NAL unit types accepted (None: all
    defined types)."""

    def __init__(self, params: ParamSets, length_size: int = 4, max_nal: int = 64 << 20,
                 types: frozenset | None = None):
        self.params = params
        self.length_size = length_size
        self.max_nal = max_nal
        self.types = types

    def first_ok(self, buf, pos: int, end: int) -> bool:
        """Cheap test: could a sample start at POS (a sane length and NAL header)?"""
        ls = self.length_size
        if pos + ls + 2 > end:
            return False
        n = int.from_bytes(buf[pos:pos + ls], "big")
        if n < 2 or n > self.max_nal or pos + ls + n > end:
            return False
        h = buf[pos + ls]
        return bool(HEADER_OK[h]) and (self.types is None or (h & 31) in self.types)

    def read(self, buf, pos: int, end: int, learn: bool = True) -> AccessUnit | None:
        """The access unit that starts at POS (None when no picture starts there). It ends before the next
        picture's first NAL unit, or where the data stops looking like NAL units of this stream. LEARN: add
        the SPS/PPS met on the way to the parameter sets."""
        ls = self.length_size
        max_nal = self.max_nal
        types = self.types
        params = self.params
        au = AccessUnit()
        p = pos
        prev: SliceHeader | None = None
        seen_vcl = False
        tlist: list[int] = []
        while p + ls + 1 < end:
            n = int.from_bytes(buf[p:p + ls], "big")
            if n < 1 or n > max_nal or p + ls + n > end:
                break
            h = buf[p + ls]
            if not HEADER_OK[h]:
                break
            t = h & 31
            if types is not None and t not in types:
                break
            a = p + ls
            if not payload_ok(buf, a, a + n):
                return None                                    # damaged
            if t in VCL:
                parsed = parse_slice_header(buf[a:a + min(n, 64)], params)
                if parsed is None:
                    break
                sh, sps, _pps = parsed
                if au.header is None:
                    if sh.first_mb != 0 and not aso_allowed(sps):
                        return None                            # the middle of a picture
                    au.header, au.sps, au.idr, au.intra = sh, sps, sh.idr, sh.intra
                elif new_picture(prev, sh, sps):
                    first = au.header
                    if (au.second_field is None and first.field_pic and sh.field_pic and sh.first_mb == 0
                            and sh.bottom_field != first.bottom_field and sh.frame_num == first.frame_num):
                        au.second_field = sh                   # the other field of the same frame
                    else:
                        break
                if not sh.intra:
                    au.intra = False
                prev = sh
                seen_vcl = True
            elif t in AU_START:
                if seen_vcl or (t == AUD and tlist):
                    break
                if t in (SPS_NAL, PPS_NAL):
                    nal = bytes(buf[a:a + n])
                    ok = params.add(nal) if learn else (parse_sps(nal) if t == SPS_NAL else parse_pps(nal))
                    if not ok:
                        break                                  # a broken parameter set: not this stream
                    au.params = True
                elif t == SEI:
                    rec = recovery_frames(buf[a:a + min(n, 256)])
                    if rec is not None:
                        au.recovery = rec
            elif t in (END_SEQ, END_STREAM):
                if not seen_vcl:
                    break
                tlist.append(t)
                p += ls + n
                break
            elif t == SPS_EXT:
                if seen_vcl:
                    break
            elif t in (DPB, DPC, FILLER, AUX_SLICE, SLICE_EXT, SLICE_EXT_3D):
                if not seen_vcl:
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


def aso_allowed(sps: SPS) -> bool:
    """Arbitrary slice order (a picture's slices in any order) exists only in the Baseline profile without the
    constrained flag; elsewhere a picture's first slice starts at macroblock 0."""
    return sps.profile == 66 and not (sps.constraints & 0x40)


PROFILES = frozenset({66, 77, 88, 100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135})
LEVELS = frozenset({9, 10, 11, 12, 13, 20, 21, 22, 30, 31, 32, 40, 41, 42, 50, 51, 52, 60, 61, 62})


def plausible_sps(s: SPS | None) -> bool:
    """An SPS a real encoder could have written (a known profile and level, reserved bits zero, a sane size)."""
    return s is not None and s.profile in PROFILES and s.level in LEVELS and not s.constraints & 0x03 and \
        s.width >= 16 and s.height >= 16


def find_params(buf, start: int, end: int, length_size: int = 4, limit: int = 1 << 20) -> ParamSets:
    """The parameter sets that a camera repeats in the stream (before every key frame), within the first LIMIT
    bytes of length-prefixed data from START: an SPS followed right away by a PPS. Else an empty ParamSets."""
    ps = ParamSets()
    stop = min(end, start + limit)
    ls = length_size
    for mark in (b"\x67", b"\x27", b"\x47"):
        i = buf.find(mark, start + ls, stop)
        while i >= 0:
            n = int.from_bytes(buf[i - ls:i], "big")
            j = i + n                                     # where the next NAL unit's length is
            if 4 <= n < 4096 and j + ls < end:
                m = int.from_bytes(buf[j:j + ls], "big")
                if 2 <= m < 4096 and j + ls + m <= end and buf[j + ls] & 0x9F == PPS_NAL:
                    sps = bytes(buf[i:j])
                    if plausible_sps(parse_sps(sps)):
                        trial = ParamSets()
                        trial.add(sps)
                        if trial.add(bytes(buf[j + ls:j + ls + m])):
                            ps.sps.update(trial.sps)
                            ps.pps.update(trial.pps)
            i = buf.find(mark, i + 1, stop)
    return ps
