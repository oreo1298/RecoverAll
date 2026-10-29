"""Audio frames that say how long they are: AMR, AC-3 and E-AC-3, MPEG audio layers I-III, and PCM.

Unlike raw AAC (see :mod:`aac`), these formats start every frame with a header from which the frame's length
follows, so a run of frames can be cut apart and checked without decoding them:

* **AMR** in 3GPP files (sample entries "samr" narrowband, "sawb" wideband) uses the octet-aligned storage
  format of RFC 4867: a header byte ``P FT(4) Q P P`` (P are zero padding bits, FT the frame type, Q the quality
  bit), then the speech bits of that frame type padded with zero bits to a byte. NB has eight speech modes
  (4.75-12.2 kbit/s) and a SID frame, WB nine modes (6.6-23.85 kbit/s) and a SID frame; FT 15 (and 14 in WB,
  speech lost) carries no data. The other frame types are reserved.
* **AC-3** (ATSC A/52) frames start with the syncword 0x0B77 and a CRC; the sample rate code and the frame size
  code give the length from a table. **E-AC-3** (bsid 11-16) has the length itself: (frmsiz + 1) 16-bit words.
  Both end with a CRC-16 (polynomial 0x8005) that makes the CRC of the frame after the syncword zero.
* **MPEG audio** (MP3, MP2) frames start with 11 set bits, then the version (1, 2 or 2.5), the layer, the
  bitrate and sample rate indexes and a padding bit; the length is 144 * bitrate / rate (+ padding) for layers
  II and III (72 for layer III of MPEG-2 and 2.5), and 4 * (12 * bitrate / rate + padding) for layer I.
  Free-format streams (bitrate index 0) don't say their length and are not measured.
* **PCM** has no frames: :func:`pcm_frame_bytes` says how many bytes one sample frame (one sample of every
  channel) takes for the QuickTime and ISO PCM sample entries.

Every ``*_frame_length(buf, pos, end, ...)`` returns the length of the frame at POS (which must end by END) or
None, and every ``split_*`` the lengths of the consecutive frames from a position while they parse.
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------- AMR
# speech bytes (without the header byte) per frame type; None: reserved
AMR_NB_BYTES = (12, 13, 15, 17, 19, 20, 26, 31, 5, None, None, None, None, None, None, 0)
AMR_WB_BYTES = (17, 23, 32, 36, 40, 46, 50, 58, 60, 5, None, None, None, None, 0, 0)
# speech bits per frame type (what is left of the last byte is zero padding)
AMR_NB_BITS = (95, 103, 118, 134, 148, 159, 204, 244, 39, 0, 0, 0, 0, 0, 0, 0)
AMR_WB_BITS = (132, 177, 253, 285, 317, 365, 397, 461, 477, 40, 0, 0, 0, 0, 0, 0)
AMR_NB_MAGIC = b"#!AMR\n"
AMR_WB_MAGIC = b"#!AMR-WB\n"


def amr_frame_length(buf, pos: int, end: int, wide: bool = False, strict: bool = True) -> int | None:
    """Bytes of the AMR frame at POS (header byte included): narrowband, or wideband (WIDE). None for a
    reserved frame type, a padding bit set in the header or (STRICT) after the speech bits, or a frame past
    END."""
    end = min(end, len(buf))
    if not 0 <= pos < end:
        return None
    h = buf[pos]
    if h & 0x83:
        return None
    ft = (h >> 3) & 15
    n = (AMR_WB_BYTES if wide else AMR_NB_BYTES)[ft]
    if n is None or pos + 1 + n > end:
        return None
    if strict and n:
        pad = 8 * n - (AMR_WB_BITS if wide else AMR_NB_BITS)[ft]
        if buf[pos + n] & ((1 << pad) - 1):
            return None
    return 1 + n


def split_amr(buf, start: int, end: int, wide: bool = False, limit: int | None = None,
              strict: bool = True) -> list[int]:
    """The lengths of the consecutive AMR frames from START (a 3GPP sample holds one or more of them)."""
    out: list[int] = []
    pos = start
    while pos < end and (limit is None or len(out) < limit):
        n = amr_frame_length(buf, pos, end, wide, strict)
        if n is None:
            break
        out.append(n)
        pos += n
    return out


# ---------------------------------------------------------------------- AC-3 / E-AC-3
AC3_RATES = (48000, 44100, 32000)
AC3_BITRATES = (32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640)
EAC3_REDUCED_RATES = (24000, 22050, 16000)


def ac3_words(fscod: int, frmsizecod: int) -> int:
    """16-bit words in an AC-3 frame of the sample rate code and frame size code (A/52 table 5.18)."""
    kbps = AC3_BITRATES[frmsizecod >> 1]
    if fscod == 0:
        return 2 * kbps
    if fscod == 2:
        return 3 * kbps
    return kbps * 1000 * 1536 // (44100 * 16) + (frmsizecod & 1)


def _crc16_table() -> list[int]:
    out = []
    for i in range(256):
        c = i << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x8005) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
        out.append(c)
    return out


_CRC16 = _crc16_table()


def crc16(data, crc: int = 0) -> int:
    """CRC-16 with the polynomial 0x8005, most significant bit first (AC-3, also MPEG audio's CRC)."""
    t = _CRC16
    for b in data:
        crc = ((crc << 8) & 0xFFFF) ^ t[(crc >> 8) ^ b]
    return crc


def ac3_header(buf, pos: int) -> dict | None:
    """The AC-3 or E-AC-3 header at POS: {"eac3", "length" (bytes), "sample_rate", "channels" (with LFE),
    "bsid", "blocks" (of 256 samples)}; None if there is none."""
    try:
        if pos < 0 or pos + 8 > len(buf):
            return None
        h = bytes(buf[pos:pos + 8])
        if h[0] != 0x0B or h[1] != 0x77:
            return None
        bsid = h[5] >> 3
        if bsid <= 10:                                      # AC-3 (9 and 10: half and quarter rate)
            fscod, frmsizecod = h[4] >> 6, h[4] & 63
            if fscod == 3 or frmsizecod > 37:
                return None
            acmod = h[6] >> 5
            # lfeon follows acmod after the optional mix levels and the surround mode bits
            v = int.from_bytes(h[6:8], "big")
            skip = 3 + (2 if acmod & 1 and acmod != 1 else 0) + (2 if acmod & 4 else 0) + (2 if acmod == 2 else 0)
            lfe = (v >> (15 - skip)) & 1
            shift = max(0, bsid - 8)
            return {"eac3": False, "length": 2 * ac3_words(fscod, frmsizecod), "bsid": bsid,
                    "sample_rate": AC3_RATES[fscod] >> shift, "channels": _AC3_CHANNELS[acmod] + lfe, "blocks": 6}
        if bsid > 16:
            return None
        strmtyp = h[2] >> 6
        if strmtyp == 3:
            return None
        frmsiz = ((h[2] & 7) << 8) | h[3]
        fscod = h[4] >> 6
        if fscod == 3:
            fscod2 = (h[4] >> 4) & 3
            if fscod2 == 3:
                return None
            rate, blocks = EAC3_REDUCED_RATES[fscod2], 6
        else:
            rate, blocks = AC3_RATES[fscod], (1, 2, 3, 6)[(h[4] >> 4) & 3]
        acmod, lfe = (h[4] >> 1) & 7, h[4] & 1
        return {"eac3": True, "length": 2 * (frmsiz + 1), "bsid": bsid, "sample_rate": rate,
                "channels": _AC3_CHANNELS[acmod] + lfe, "blocks": blocks}
    except IndexError:
        return None


_AC3_CHANNELS = (2, 1, 2, 3, 3, 4, 4, 5)


def ac3_frame_length(buf, pos: int, end: int, crc: bool = False) -> int | None:
    """Bytes of the AC-3 or E-AC-3 frame at POS (it must end by END); with CRC also checked against the CRC at
    its end (slower, but then nothing else passes)."""
    h = ac3_header(buf, pos)
    if h is None:
        return None
    n = h["length"]
    if n < 8 or pos + n > min(end, len(buf)):
        return None
    if crc and crc16(buf[pos + 2:pos + n]) != 0:
        return None
    return n


def split_ac3(buf, start: int, end: int, limit: int | None = None, crc: bool = False) -> list[int]:
    """The lengths of the consecutive AC-3 / E-AC-3 frames from START."""
    out: list[int] = []
    pos = start
    while pos < end and (limit is None or len(out) < limit):
        n = ac3_frame_length(buf, pos, end, crc)
        if n is None:
            break
        out.append(n)
        pos += n
    return out


# ---------------------------------------------------------------------- MPEG audio
MPA_BITRATES = {
    (1, 1): (0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448),
    (1, 2): (0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384),
    (1, 3): (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),
    (2, 1): (0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256),
    (2, 2): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
    (2, 3): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
}
MPA_RATES = {1: (44100, 48000, 32000), 2: (22050, 24000, 16000), 2.5: (11025, 12000, 8000)}


def mpa_header(buf, pos: int) -> dict | None:
    """The MPEG audio frame header at POS: {"version" (1, 2, 2.5), "layer", "bitrate" (kbit/s), "sample_rate",
    "channels", "samples", "padding", "crc", "length" (bytes)}; None if there is none (or a free-format one)."""
    if pos < 0 or pos + 4 > len(buf):
        return None
    v = struct.unpack_from(">I", bytes(buf[pos:pos + 4]))[0]
    if v >> 21 != 0x7FF:
        return None
    version = {0: 2.5, 2: 2, 3: 1}.get((v >> 19) & 3)
    layer = 4 - ((v >> 17) & 3)
    bi, si = (v >> 12) & 15, (v >> 10) & 3
    if version is None or layer == 4 or bi in (0, 15) or si == 3 or v & 3 == 2:
        return None
    kbps = MPA_BITRATES[(1 if version == 1 else 2, layer)][bi]
    rate = MPA_RATES[version][si]
    pad = (v >> 9) & 1
    if layer == 1:
        length, samples = 4 * (12000 * kbps // rate + pad), 384
    elif layer == 2 or version == 1:
        length, samples = 144000 * kbps // rate + pad, 1152
    else:
        length, samples = 72000 * kbps // rate + pad, 576
    return {"version": version, "layer": layer, "bitrate": kbps, "sample_rate": rate,
            "channels": 1 if (v >> 6) & 3 == 3 else 2, "samples": samples, "padding": bool(pad),
            "crc": not (v >> 16) & 1, "length": length}


def mpa_frame_length(buf, pos: int, end: int) -> int | None:
    """Bytes of the MPEG audio (layer I, II or III) frame at POS (it must end by END)."""
    h = mpa_header(buf, pos)
    if h is None or pos + h["length"] > min(end, len(buf)):
        return None
    return h["length"]


def split_mpa(buf, start: int, end: int, limit: int | None = None, same_stream: bool = True) -> list[int]:
    """The lengths of the consecutive MPEG audio frames from START; SAME_STREAM stops at a frame whose version,
    layer or sample rate differ from the first one's."""
    out: list[int] = []
    pos = start
    first = None
    while pos < end and (limit is None or len(out) < limit):
        h = mpa_header(buf, pos)
        if h is None or pos + h["length"] > min(end, len(buf)):
            break
        key = (h["version"], h["layer"], h["sample_rate"])
        if first is None:
            first = key
        elif same_stream and key != first:
            break
        out.append(h["length"])
        pos += h["length"]
    return out


# ---------------------------------------------------------------------- PCM
# bytes per sample of one channel for the PCM sample entries whose sample size is fixed
PCM_SAMPLE_BYTES = {"sowt": 2, "twos": 2, "in24": 3, "in32": 4, "fl32": 4, "fl64": 8, "raw ": 1, "NONE": 1,
                    "ulaw": 1, "alaw": 1}
PCM_CODECS = frozenset(PCM_SAMPLE_BYTES) | {"lpcm", "ipcm", "fpcm"}


def _box_payload(data: bytes, kind: bytes) -> bytes | None:
    """The payload of the first box KIND found at any 4-byte-aligned or unaligned position (sample entry
    boxes follow fields whose length depends on the entry's version)."""
    i = data.find(kind)
    while i >= 4:
        size = struct.unpack_from(">I", data, i - 4)[0]
        if 8 <= size <= len(data) - i + 4:
            return data[i + 4:i - 4 + size]
        i = data.find(kind, i + 1)
    return None


def pcm_frame_bytes(codec: str, channels: int, bits: int = 0, entry: bytes | None = None) -> int | None:
    """Bytes of one sample frame (a sample of every channel) of a PCM sample entry: CODEC is the entry type
    ("sowt", "twos", "in24", "in32", "fl32", "fl64", "raw ", "ulaw", "alaw", "lpcm", "ipcm", "fpcm"), CHANNELS
    and BITS what the entry says; ENTRY the sample entry's payload (after its type), needed for "lpcm" (the
    sound description v2 says the bytes per packet) and read for v1 descriptions and the "pcmC" box of "ipcm".
    None for something else, or what can't be worked out."""
    if codec not in PCM_CODECS:
        return None
    e = bytes(entry or b"")
    version = struct.unpack_from(">H", e, 8)[0] if len(e) >= 10 else 0
    try:
        if version == 2 and len(e) >= 64:                  # QuickTime sound description v2
            channels = struct.unpack_from(">I", e, 40)[0] or channels
            bits = struct.unpack_from(">I", e, 48)[0] or bits
            per_packet, frames = struct.unpack_from(">II", e, 56)
            if codec == "lpcm" and per_packet and frames:
                return per_packet // frames if per_packet % frames == 0 else None
        elif version == 1 and len(e) >= 44 and codec != "lpcm":
            per_frame = struct.unpack_from(">I", e, 36)[0]    # v1: samples/packet, bytes/packet, bytes/frame
            if 0 < per_frame <= 64 * 8 * 8:
                return per_frame
        if codec in ("ipcm", "fpcm"):
            pcmc = _box_payload(e, b"pcmC")
            if pcmc is not None and len(pcmc) >= 6:
                bits = pcmc[5]
    except struct.error:
        return None
    if channels <= 0 or channels > 64:
        return None
    if codec in ("twos", "sowt") and bits == 8:
        return channels
    if codec in PCM_SAMPLE_BYTES:
        return PCM_SAMPLE_BYTES[codec] * channels
    if codec in ("lpcm", "ipcm", "fpcm") and bits and bits % 8 == 0:
        return bits // 8 * channels
    return None
