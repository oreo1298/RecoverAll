"""Music and audio for the signature engine: MP3, WAV, FLAC, Ogg (Vorbis, Opus, FLAC, Speex), M4A/M4B, AAC,
AIFF, WMA, AMR, MIDI, Monkey's Audio, WavPack, Sun AU and Apple CAF.

How each file's end is found:

* exact from recorded sizes: WAV/RF64, AIFF, AU, CAF, MIDI, Monkey's Audio (3.98 and later), M4A (boxes),
  WMA (ASF objects);
* by walking the stream: MP3 and AAC frames (every header checked against the first one, at least three
  in a row after an ID3 tag and more for a bare frame at a block start), Ogg pages (each page's CRC
  checked) up to the end-of-stream page, WavPack blocks, AMR frames, FLAC frames (frame headers carry a CRC
  and a running frame number; the last frame ends where its CRC-16 matches);
* tags after the audio (ID3v1, APEv2, Lyrics3) are kept with the file.

Songs are named "Artist - Title" from their tags (ID3, Vorbis comments, iTunes atoms, ASF descriptions).
"""

from __future__ import annotations

import struct
import zlib

from .base import CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, Format, GiB, Hit, KiB, MiB, Reader
from .common import bmff_movie, id3v2_info, iter_chunks, memo, music_name, parse_asf, skip_tags, vorbis_comments


def _hit(ext: str, length: int | None, chance: int, meta: dict | None = None, info: dict | None = None,
         **kw) -> Hit:
    meta = meta or {}
    info = dict(info or {})
    for k in ("title", "artist", "album"):
        if meta.get(k):
            info[k] = meta[k]
    return Hit(ext, length, chance, name=music_name(meta), info=info, **kw)


# ---------------------------------------------------------------------- MPEG audio (MP3) and ADTS (AAC)
_BR_V1 = {3: (0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448),
          2: (0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384),
          1: (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320)}
_BR_V2 = {3: (0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256),
          2: (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
          1: (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160)}
_SR = {3: (44100, 48000, 32000), 2: (22050, 24000, 16000), 0: (11025, 12000, 8000)}


def mpa_frame(b: bytes, p: int) -> tuple[int, int, int, int] | None:
    """(frame length, stream key, sample rate, samples) of the MPEG audio frame header at P, or None."""
    if p + 4 > len(b) or b[p] != 0xFF or b[p + 1] < 0xE0:
        return None
    h = int.from_bytes(b[p:p + 4], "big")
    ver = (h >> 19) & 3
    layer = (h >> 17) & 3
    bri = (h >> 12) & 15
    sri = (h >> 10) & 3
    if ver == 1 or layer == 0 or bri in (0, 15) or sri == 3 or (h & 3) == 2:
        return None
    br = (_BR_V1 if ver == 3 else _BR_V2)[layer][bri] * 1000
    sr = _SR[ver][sri]
    pad = (h >> 9) & 1
    key = (h >> 17) & 0xF | sri << 4                # version, layer, sample rate: constant in a stream
    if layer == 3:
        return (12 * br // sr + pad) * 4, key, sr, 384
    if layer == 2 or ver == 3:
        return 144 * br // sr + pad, key, sr, 1152
    return 72 * br // sr + pad, key, sr, 576


def adts_frame(b: bytes, p: int) -> tuple[int, int, int, int] | None:
    """(frame length, stream key, sample rate, samples) of the ADTS (AAC) frame header at P, or None."""
    if p + 7 > len(b) or b[p] != 0xFF or (b[p + 1] & 0xF6) != 0xF0:
        return None
    sfi = (b[p + 2] >> 2) & 15
    if sfi > 12:
        return None
    n = ((b[p + 3] & 3) << 11) | (b[p + 4] << 3) | (b[p + 5] >> 5)
    if n < (7 if b[p + 1] & 1 else 9):
        return None
    key = (b[p + 1] & 0x08) << 16 | (b[p + 2] & 0xFD) << 8 | (b[p + 3] & 0xC0)
    rates = (96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350)
    return n, key, rates[sfi], 1024 * ((b[p + 6] & 3) + 1)


def walk_frames(r, pos: int, frame, min_frames: int) -> tuple[int, int, float, int] | None:
    """Follow consecutive frames (MPEG audio or ADTS) from POS while their headers agree with the first:
    (end, frames, seconds, bytes of audio) or None if fewer than MIN_FRAMES."""
    frames = 0
    key0 = None
    samples = 0
    sr = 0
    start = pos
    buf, at = b"", pos
    for _ in range(50_000_000):
        if pos + 8 > at + len(buf):
            buf, at = r.read(pos, 256 * KiB), pos
            if len(buf) < 4:
                break
        f = frame(buf, pos - at)
        if f is None:
            break
        n, key, sr, ns = f
        if key0 is None:
            key0 = key
        elif key != key0:
            break
        if pos + n > r.limit:                   # cut short: keep it, the decoder stops there
            pos = r.limit
            frames += 1
            break
        pos += n
        frames += 1
        samples += ns
    if frames < min_frames:
        return None
    return pos, frames, (samples / sr if sr else 0.0), pos - start


def _after_id3(r, pos: int) -> int:
    """Past the zero padding some taggers leave after an ID3v2 tag (at most 64 KiB)."""
    d = r.read(pos, 64 * KiB)
    stripped = d.lstrip(b"\0")
    return pos + len(d) - len(stripped) if stripped else pos


def parse_mp3(r: Reader) -> Hit | None:
    meta: dict = {}
    pos = 0
    for _ in range(4):                          # some files carry two ID3v2 tags in a row
        got = id3v2_info(r, pos)
        if got is None:
            break
        size, m = got
        meta = meta or m
        pos = _after_id3(r, pos + size)
    if pos and r.read(pos, 4) == b"fLaC":       # FLAC with an ID3 tag in front
        return parse_flac(r, pos, meta)
    head = r.read(pos, 8)
    if adts_frame(head, 0):
        got = walk_frames(r, pos, adts_frame, 3 if pos else 16)
        if got is None:
            return None
        end = skip_tags(r, got[0])
        return _hit("aac", end, CHANCE_GOOD, meta, {"duration": round(got[2], 3)},
                    description="AAC audio")
    got = walk_frames(r, pos, mpa_frame, 3 if pos else 10)
    if got is None:
        return None
    end, frames, seconds, nbytes = got
    end = skip_tags(r, end)
    f = mpa_frame(head, 0)
    info = {"duration": round(seconds, 3)}
    if seconds:
        info["bitrate"] = int(nbytes * 8 / seconds / 1000)
    if f:
        info["sample_rate"] = f[2]
    return _hit("mp3", end, CHANCE_GOOD, meta, info)


def parse_aac(r: Reader) -> Hit | None:
    got = walk_frames(r, 0, adts_frame, 16)
    if got is None:
        return None
    return _hit("aac", skip_tags(r, got[0]), CHANCE_GOOD, None, {"duration": round(got[2], 3)})


# ---------------------------------------------------------------------- WAV / RF64
_WAVE_FORMATS = {1, 2, 3, 6, 7, 0x11, 0x16, 0x31, 0x40, 0x50, 0x55, 0x92, 0xFF, 0x161, 0x162, 0x163, 0x1610,
                 0x2000, 0xFFFE}


def parse_wav(r: Reader) -> Hit | None:
    h = r.read(0, 12)
    if len(h) < 12 or h[:4] not in (b"RIFF", b"RF64") or h[8:12] != b"WAVE":
        return None
    size = struct.unpack_from("<I", h, 4)[0]
    fmt = None
    data_size = None
    riff64 = None
    for cid, off, n in iter_chunks(r, 12, min(r.limit, 12 + 16 * MiB), max_chunks=64):
        if cid == b"ds64" and n >= 24 and len(r.read(off, 16)) == 16:
            riff64, data_size = struct.unpack("<QQ", r.read(off, 16))
        elif cid == b"fmt " and 14 <= n <= 4096:
            fmt = r.read(off, 16)
        elif cid == b"data":
            if data_size is None or n != 0xFFFFFFFF:
                data_size = n
            data_end = off + (data_size if data_size is not None else 0)
            break
    else:
        data_end = None
    if fmt is None or len(fmt) < 16:
        return None
    tag, ch, rate, byterate, align, bits = struct.unpack("<HHIIHH", fmt)
    if tag not in _WAVE_FORMATS or not 1 <= ch <= 64 or not 1000 <= rate <= 1_000_000 or bits > 64:
        return None
    info = {"channels": ch, "sample_rate": rate}
    if bits:
        info["bits"] = bits
    if data_size and byterate:
        info["duration"] = round(data_size / byterate, 3)
    if h[:4] == b"RF64":
        if riff64:
            return _hit("wav", 8 + riff64, CHANCE_GOOD, None, info)
        return _hit("wav", data_end, CHANCE_FAIR, None, info)
    if size in (0, 0xFFFFFFFF) or size < 4:
        if data_end is not None and data_size not in (None, 0, 0xFFFFFFFF):
            return _hit("wav", data_end + (data_size & 1), CHANCE_FAIR, None, info)
        return _hit("wav", None, CHANCE_FAIR, None, info)
    return _hit("wav", 8 + size + (size & 1), CHANCE_GOOD, None, info)


# ---------------------------------------------------------------------- FLAC
def _crc8_table() -> list[int]:
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = ((c << 1) ^ 0x07) & 0xFF if c & 0x80 else (c << 1) & 0xFF
        t.append(c)
    return t


def _crc16_table() -> list[int]:
    t = []
    for i in range(256):
        c = i << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x8005) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
        t.append(c)
    return t


_CRC8 = _crc8_table()
_CRC16 = _crc16_table()


def crc8(data: bytes) -> int:
    c = 0
    for b in data:
        c = _CRC8[c ^ b]
    return c


def flac_frame(b: bytes, p: int) -> tuple[int, int, int, int] | None:
    """(header length, frame or sample number, block size, blocking strategy) of the FLAC frame header at
    P (checked with its CRC-8), or None."""
    if p + 6 > len(b) or b[p] != 0xFF or (b[p + 1] & 0xFE) != 0xF8:
        return None
    bs_code, sr_code = b[p + 2] >> 4, b[p + 2] & 15
    if bs_code == 0 or sr_code == 15 or b[p + 3] >> 4 > 10 or (b[p + 3] >> 1) & 7 == 3 or b[p + 3] & 1:
        return None
    q = p + 4
    c = b[q]
    if c < 0x80:
        num, extra = c, 0
    elif 0xC0 <= c < 0xE0:
        num, extra = c & 0x1F, 1
    elif 0xE0 <= c < 0xF0:
        num, extra = c & 0x0F, 2
    elif 0xF0 <= c < 0xF8:
        num, extra = c & 0x07, 3
    elif 0xF8 <= c < 0xFC:
        num, extra = c & 0x03, 4
    elif 0xFC <= c < 0xFE:
        num, extra = c & 0x01, 5
    elif c == 0xFE:
        num, extra = 0, 6
    else:
        return None
    if q + 1 + extra + 5 > len(b):
        return None
    for i in range(extra):
        cc = b[q + 1 + i]
        if cc & 0xC0 != 0x80:
            return None
        num = (num << 6) | (cc & 0x3F)
    q += 1 + extra
    if bs_code == 6:
        bs = b[q] + 1
        q += 1
    elif bs_code == 7:
        bs = ((b[q] << 8) | b[q + 1]) + 1
        q += 2
    elif bs_code == 1:
        bs = 192
    elif bs_code <= 5:
        bs = 576 << (bs_code - 2)
    else:
        bs = 256 << (bs_code - 8)
    q += 1 if sr_code == 12 else 2 if sr_code in (13, 14) else 0
    if q >= len(b) or crc8(b[p:q]) != b[q]:
        return None
    return q + 1 - p, num, bs, b[p + 1] & 1


def _flac_last_frame_end(data: bytes, min_len: int) -> int:
    """Where the frame at the start of DATA ends: the first position whose two following bytes are the
    CRC-16 of everything before (-1 if none)."""
    crc = 0
    t = _CRC16
    n = len(data) - 1
    for i in range(n):
        if i >= min_len and crc == ((data[i] << 8) | data[i + 1]):
            return i + 2
        crc = ((crc << 8) & 0xFFFF) ^ t[(crc >> 8) ^ data[i]]
    return -1


def parse_flac(r: Reader, base: int = 0, meta: dict | None = None) -> Hit | None:
    h = r.read(base, 42)
    if len(h) < 42 or h[:4] != b"fLaC" or h[4] & 0x7F != 0 or h[5:8] != b"\0\0\x22":
        return None
    minbs, maxbs = struct.unpack_from(">HH", h, 8)
    minfs, maxfs = int.from_bytes(h[12:15], "big"), int.from_bytes(h[15:18], "big")
    packed = int.from_bytes(h[18:26], "big")
    rate = packed >> 44
    channels = ((packed >> 41) & 7) + 1
    bps = ((packed >> 36) & 31) + 1
    total = packed & ((1 << 36) - 1)
    if minbs < 16 or maxbs < minbs or not 1 <= rate <= 655350 or bps < 4 or (maxfs and minfs > maxfs):
        return None
    meta = dict(meta or {})
    pos = base + 4
    for _ in range(1024):                       # metadata blocks
        bh = r.read(pos, 4)
        if len(bh) < 4:
            return None
        last, typ, n = bh[0] & 0x80, bh[0] & 0x7F, int.from_bytes(bh[1:4], "big")
        if typ == 127 or (typ == 0 and pos != base + 4):
            return None
        if typ == 4 and n < 1 * MiB and not meta:
            meta = vorbis_comments(r.read(pos + 4, n))
        pos += 4 + n
        if last:
            break
    else:
        return None
    info = {"channels": channels, "sample_rate": rate, "bits": bps}
    if total:
        info["duration"] = round(total / rate, 3)
    span = max(maxfs + 64 if maxfs else 0, 1 * MiB)
    buf, at = r.read(pos, 4 * span), pos
    first = flac_frame(buf, 0)
    if first is None:                           # no audio where it should start: not FLAC (or nothing left)
        return None
    hlen, num, bs, strategy = first
    sync = b"\xff\xf9" if strategy else b"\xff\xf8"
    cur, samples, frames = pos, bs, 1
    step = max(minfs, hlen + 1) if minfs else hlen + 1
    for _ in range(100_000_000):
        if cur + span + 64 > at + len(buf):
            buf, at = r.read(cur, 4 * span), cur
        lo = cur - at + step
        hi = min(len(buf), cur - at + span)
        found = None
        i = buf.find(sync, lo, hi)
        while i >= 0:
            f = flac_frame(buf, i)
            if f is not None and ((strategy == 0 and f[1] == num + 1) or (strategy and f[1] == num + bs)):
                found = (i, f)
                break
            i = buf.find(sync, i + 1, hi)
        if found is None:
            break
        i, (hlen, num, bs, _s) = found
        cur = at + i
        samples += bs
        frames += 1
    # the last frame: up to the position where its CRC-16 matches
    tail = r.read(cur, maxfs + 64 if maxfs else 64 * KiB)
    n = _flac_last_frame_end(tail, max(hlen + 1, minfs - 2 if minfs else 0))
    if n < 0:
        return _hit("flac", cur + len(tail), CHANCE_POOR, meta, info)
    chance = CHANCE_GOOD if (not total or samples == total) else CHANCE_FAIR
    return _hit("flac", skip_tags(r, cur + n), chance, meta, info)


# ---------------------------------------------------------------------- Ogg
_REV8 = bytes(int(f"{i:08b}"[::-1], 2) for i in range(256))


def ogg_crc(page: bytes) -> int:
    """The CRC of an Ogg page (polynomial 0x04C11DB7, not reflected): zlib's reflected CRC-32 over the
    bit-reversed bytes, reversed back, so it runs at C speed."""
    data = (page[:22] + b"\0\0\0\0" + page[26:]).translate(_REV8)
    c = zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF
    return int(f"{c:032b}"[::-1], 2)


_OGG_CODECS = ((b"\x01vorbis", "ogg", "audio"), (b"OpusHead", "opus", "audio"), (b"\x7fFLAC", "oga", "audio"),
               (b"Speex   ", "spx", "audio"), (b"\x80theora", "ogv", "video"), (b"OVP80", "ogv", "video"),
               (b"\x80daala", "ogv", "video"), (b"fishead\0", "ogg", "index"))


def parse_ogg(r: Reader) -> Hit | None:
    pos = 0
    streams: dict[int, tuple[str, str]] = {}
    ended: set[int] = set()
    meta: dict = {}
    rate = 0
    granule = 0
    first_serial = None
    pages = 0
    complete = False
    data_seen = False
    for _ in range(50_000_000):
        h = r.read(pos, 27)
        if len(h) < 27 or h[:4] != b"OggS" or h[4] != 0:
            break
        htype = h[5]
        gran, serial, _seq, crc = struct.unpack_from("<qIII", h, 6)
        segs = r.read(pos + 27, h[26])
        size = 27 + h[26] + sum(segs)
        page = r.read(pos, size)
        if len(page) < size or ogg_crc(page) != crc:
            break
        payload = page[27 + h[26]:]
        if pages == 0 and not htype & 2:
            return None
        if htype & 2:
            if serial in streams or data_seen:
                break
            kind = next(((e, c) for sig, e, c in _OGG_CODECS if payload.startswith(sig)), ("ogg", "audio"))
            streams[serial] = kind
            if first_serial is None and kind[1] == "audio":
                first_serial = serial
                if payload.startswith(b"\x01vorbis") and len(payload) >= 16:
                    rate = struct.unpack_from("<I", payload, 12)[0]
                elif payload.startswith(b"OpusHead"):
                    rate = 48000
        elif serial not in streams:
            break
        else:
            data_seen = True
        if not meta and not htype & 2 and serial == first_serial and pages < 16:
            if payload.startswith(b"\x03vorbis"):
                meta = vorbis_comments(payload[7:])
            elif payload.startswith(b"OpusTags"):
                meta = vorbis_comments(payload[8:])
        if serial == first_serial and gran > 0:
            granule = gran
        if htype & 4:
            ended.add(serial)
        pos += size
        pages += 1
        if streams and len(ended) == len(streams):
            complete = True
            break
    if pages == 0 or not streams:
        return None
    kinds = list(streams.values())
    video = next((k for k in kinds if k[1] == "video"), None)
    ext, cat = video or kinds[0]
    if not video and first_serial is not None:
        ext = streams[first_serial][0]
    info = {}
    if rate and granule:
        info["duration"] = round(granule / rate, 3)
    return _hit(ext, pos, CHANCE_GOOD if complete else CHANCE_POOR, meta, info,
                category="video" if cat == "video" else None,
                description="Ogg video" if cat == "video" else None)


# ---------------------------------------------------------------------- M4A / M4B
def parse_m4a(r: Reader) -> Hit | None:
    m = bmff_movie(r)
    if m is None or not m["audio_only"]:
        return None
    b, mi = m["walk"], m["moov"]
    ext = m["ext"] if m["ext"] in ("m4a", "m4b", "3gp", "3g2") else "m4a"
    info = {"duration": round(mi["duration"], 3)} if mi["duration"] else {}
    return _hit(ext, b.end, CHANCE_POOR if b.truncated else CHANCE_GOOD, mi["tags"], info)


# ---------------------------------------------------------------------- WMA
def parse_wma(r: Reader) -> Hit | None:
    a = memo(r, "asf", parse_asf)
    if a is None or not a["audio"] or a["video"]:
        return None
    info = {"duration": round(a["duration"], 3)} if a["duration"] else {}
    return _hit("wma", a["end"], CHANCE_GOOD if a["exact"] else CHANCE_FAIR,
                {"title": a["title"], "artist": a["author"]}, info)


# ---------------------------------------------------------------------- AIFF
def _extended(b: bytes) -> float:
    """An 80-bit IEEE extended float (AIFF sample rates)."""
    e, m = struct.unpack(">HQ", b)
    exp = (e & 0x7FFF) - 16383
    if not m or not -64 < exp < 64:
        return 0.0
    return m * 2.0 ** (exp - 63)


def parse_aiff(r: Reader) -> Hit | None:
    h = r.read(0, 12)
    if len(h) < 12 or h[:4] != b"FORM" or h[8:12] not in (b"AIFF", b"AIFC"):
        return None
    size = struct.unpack_from(">I", h, 4)[0]
    comm = None
    for cid, off, n in iter_chunks(r, 12, min(8 + size, 12 + 16 * MiB), big_endian=True, max_chunks=64):
        if cid == b"COMM" and n >= 18:
            comm = r.read(off, 18)
            break
    if comm is None or len(comm) < 18:
        return None
    ch, frames, bits = struct.unpack_from(">HIH", comm)
    rate = _extended(comm[8:18])
    if not 1 <= ch <= 64 or not 1 <= bits <= 64 or not 1000 <= rate <= 1_000_000:
        return None
    info = {"channels": ch, "sample_rate": int(rate), "bits": bits, "duration": round(frames / rate, 3)}
    return _hit("aifc" if h[8:12] == b"AIFC" else "aiff", 8 + size + (size & 1), CHANCE_GOOD, None, info)


# ---------------------------------------------------------------------- AMR
_AMR_NB = (12, 13, 15, 17, 19, 20, 26, 31, 5, -1, -1, -1, -1, -1, -1, 0)
_AMR_WB = (17, 23, 32, 36, 40, 46, 50, 58, 60, 5, -1, -1, -1, -1, 0, 0)


def parse_amr(r: Reader) -> Hit | None:
    h = r.read(0, 9)
    if h[:6] == b"#!AMR\n":
        pos, sizes, ext, ms = 6, _AMR_NB, "amr", 20
    elif h == b"#!AMR-WB\n":
        pos, sizes, ext, ms = 9, _AMR_WB, "awb", 20
    else:
        return None
    frames = 0
    buf, at = b"", pos
    for _ in range(100_000_000):
        if pos >= at + len(buf):
            buf, at = r.read(pos, 64 * KiB), pos
            if not buf:
                break
        b = buf[pos - at]
        ft = (b >> 3) & 15
        if b & 0x83 or not b & 0x04 or sizes[ft] < 0:   # padding bits set, bad-frame flag, reserved type
            break
        pos += 1 + sizes[ft]
        frames += 1
    if frames < 2:
        return None
    return Hit(ext, min(pos, r.limit), CHANCE_GOOD, info={"duration": round(frames * ms / 1000, 3)})


# ---------------------------------------------------------------------- MIDI
def parse_mid(r: Reader) -> Hit | None:
    h = r.read(0, 14)
    if len(h) < 14 or h[:8] != b"MThd\0\0\0\x06":
        return None
    fmt, ntrk, _div = struct.unpack_from(">HHH", h, 8)
    if fmt > 2 or not 1 <= ntrk <= 1024 or (fmt == 0 and ntrk != 1):
        return None
    pos = 14
    for _ in range(ntrk):
        c = r.read(pos, 8)
        if len(c) < 8 or c[:4] != b"MTrk":
            if pos > 14:
                return Hit("mid", pos, CHANCE_POOR)
            return None
        pos += 8 + struct.unpack_from(">I", c, 4)[0]
    return Hit("mid", pos, CHANCE_GOOD, info={"tracks": ntrk})


# ---------------------------------------------------------------------- Monkey's Audio, WavPack
def parse_ape(r: Reader) -> Hit | None:
    h = r.read(0, 52)
    if len(h) < 52 or h[:4] != b"MAC ":
        return None
    ver = struct.unpack_from("<H", h, 4)[0]
    if not 3800 <= ver <= 5000:
        return None
    if ver < 3980:                              # old layout: the length isn't recorded
        level, _flags, ch, rate = struct.unpack_from("<HHHI", h, 6)
        if level not in (1000, 2000, 3000, 4000, 5000) or not 1 <= ch <= 32 or not 1000 <= rate <= 768000:
            return None
        return Hit("ape", None, CHANCE_FAIR)
    desc, hdr, seek, wav, lo, hi, term = struct.unpack_from("<7I", h, 8)
    if not 52 <= desc <= 1024 or not 24 <= hdr <= 1024 or seek > 1 << 30 or wav > 1 << 20:
        return None
    end = desc + hdr + seek + wav + (hi << 32 | lo) + term
    return Hit("ape", skip_tags(r, end), CHANCE_GOOD)


def parse_wv(r: Reader) -> Hit | None:
    pos, blocks = 0, 0
    for _ in range(50_000_000):
        h = r.read(pos, 32)
        if len(h) < 32 or h[:4] != b"wvpk":
            break
        size, ver = struct.unpack_from("<IH", h, 4)
        if not 0x402 <= ver <= 0x410 or size < 24 or size > 32 * MiB:
            break
        pos += 8 + size
        blocks += 1
    if not blocks:
        return None
    return Hit("wv", skip_tags(r, pos), CHANCE_GOOD)


# ---------------------------------------------------------------------- Sun AU, Apple CAF
def parse_au(r: Reader) -> Hit | None:
    h = r.read(0, 24)
    if len(h) < 24 or h[:4] != b".snd":
        return None
    off, size, enc, rate, ch = struct.unpack_from(">5I", h, 4)
    if not 24 <= off <= 1 * MiB or not 1 <= enc <= 27 or not 1000 <= rate <= 1_000_000 or not 1 <= ch <= 64:
        return None
    info = {"channels": ch, "sample_rate": rate}
    if size == 0xFFFFFFFF:
        return Hit("au", None, CHANCE_FAIR, info=info)
    return Hit("au", off + size, CHANCE_GOOD, info=info)


def parse_caf(r: Reader) -> Hit | None:
    h = r.read(0, 52)
    if len(h) < 52 or h[:8] != b"caff\0\x01\0\0" or h[8:12] != b"desc" or struct.unpack_from(">q", h, 12)[0] != 32:
        return None
    rate = struct.unpack_from(">d", h, 20)[0]
    if not 1000 <= rate <= 1_000_000:
        return None
    pos = 8
    for _ in range(100000):
        c = r.read(pos, 12)
        if len(c) < 12 or not all(32 <= x < 127 for x in c[:4]):
            break
        n = struct.unpack_from(">q", c, 4)[0]
        if n == -1:
            if c[:4] != b"data":
                break
            return Hit("caf", None, CHANCE_FAIR, info={"sample_rate": int(rate)})
        if n < 0:
            break
        pos += 12 + n
    return Hit("caf", pos, CHANCE_GOOD, info={"sample_rate": int(rate)})


FORMATS = [
    Format("mp3", "MP3 audio", "audio", ("mp3",),
           ((0, b"ID3"), (0, b"\xff\xfb"), (0, b"\xff\xfa"), (0, b"\xff\xf3"), (0, b"\xff\xf2"), (0, b"\xff\xe3"),
            (0, b"\xff\xe2"), (0, b"\xff\xfd"), (0, b"\xff\xfc")), parse_mp3, max_size=2 * GiB, min_size=256),
    Format("wav", "WAV audio", "audio", ("wav",), ((8, b"WAVE"),), parse_wav, max_size=16 * GiB, min_size=44,
           aliases=("wave", "rf64")),
    Format("flac", "FLAC audio", "audio", ("flac",), ((0, b"fLaC\0\0\0\x22"), (0, b"fLaC\x80\0\0\x22")), parse_flac,
           max_size=4 * GiB),
    Format("ogg", "Ogg audio", "audio", ("ogg", "opus", "oga", "spx", "ogv"), ((0, b"OggS\0\x02"),), parse_ogg,
           max_size=4 * GiB, aliases=("opus", "oga", "ogv", "spx", "vorbis")),
    Format("m4a", "M4A / AAC audio", "audio", ("m4a", "m4b"), ((4, b"ftyp"), (4, b"moov"), (4, b"mdat"),
                                                              (4, b"wide"), (4, b"free")),
           parse_m4a, max_size=8 * GiB, min_size=256, aliases=("m4b", "m4p")),
    Format("aac", "AAC audio (ADTS)", "audio", ("aac",), ((0, b"\xff\xf1"), (0, b"\xff\xf9"), (0, b"\xff\xf0"),
                                                         (0, b"\xff\xf8")), parse_aac, max_size=1 * GiB,
           min_size=256),
    Format("aiff", "AIFF audio", "audio", ("aiff", "aifc", "aif"), ((8, b"AIFF"), (8, b"AIFC")), parse_aiff,
           max_size=4 * GiB, aliases=("aif", "aifc")),
    Format("wma", "Windows Media audio", "audio", ("wma",),
           ((0, b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c"),), parse_wma, max_size=4 * GiB),
    Format("amr", "AMR voice recording", "audio", ("amr", "awb"), ((0, b"#!AMR"),), parse_amr, max_size=256 * MiB),
    Format("mid", "MIDI music", "audio", ("mid",), ((0, b"MThd\0\0\0\x06"),), parse_mid, max_size=64 * MiB,
           aliases=("midi",)),
    Format("ape", "Monkey's Audio", "audio", ("ape",), ((0, b"MAC "),), parse_ape, max_size=4 * GiB),
    Format("wv", "WavPack audio", "audio", ("wv",), ((0, b"wvpk"),), parse_wv, max_size=4 * GiB,
           aliases=("wavpack",)),
    Format("au", "Sun audio", "audio", ("au", "snd"), ((0, b".snd"),), parse_au, max_size=4 * GiB,
           aliases=("snd",)),
    Format("caf", "Apple Core Audio file", "audio", ("caf",), ((0, b"caff\0\x01"),), parse_caf, max_size=16 * GiB),
]
