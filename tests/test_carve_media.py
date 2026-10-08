"""The photo, video and audio formats of the signature engine (carve/images.py, video.py, audio.py and the
helpers in common.py).

Every sample is planted at a block boundary inside random data and must come back with its exact offset
and length, the right extension and the metadata it carries. The samples are either built here by hand
(PNG, GIF, BMP, TIFF and the camera RAW files, EXIF, MPO, HEIC, CR3, RAF, EXR, JPEG XL, WAV, AIFF, MIDI,
AMR, ...) or are tiny files made with ffmpeg / ImageMagick, stored compressed at the end of this file so
the tests need neither."""

from __future__ import annotations

import base64
import calendar
import functools
import io
import random
import struct
import time
import wave
import zlib

from recoverall.core.blockio import BytesSource
from recoverall.core.carve import FORMATS, Carver
from recoverall.core.carve.audio import ogg_crc
from recoverall.core.carve.base import CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, Reader
from recoverall.core.carve.common import exif_time, parse_exif

MINE = [f for f in FORMATS if f.parse.__module__.rsplit(".", 1)[-1] in ("images", "video", "audio")]
DEFAULT = [f for f in MINE if f.enabled]
BY_KEY = {f.key: f for f in MINE}
TAKEN = "2019:08:15 10:20:30"
TAKEN_NAME = "2019-08-15 10.20.30"
TAKEN_TS = calendar.timegm((2019, 8, 15, 10, 20, 30, 0, 0, 0))


def sample(name: str) -> bytes:
    return zlib.decompress(base64.b64decode("".join(SAMPLES[name])))


def filler(n: int, seed: int = 1) -> bytes:
    return random.Random(seed).randbytes(n)


def scan(data: bytes, formats=None, **kw):
    return list(Carver(BytesSource(data), DEFAULT if formats is None else formats, **kw).scan())


def carve_one(data: bytes, formats=None, at: int = 8192, after: bytes | None = None, **kw):
    """DATA planted at AT inside random data; the file found there (or None) and everything found."""
    tail = filler(20000, 2) if after is None else after
    image = filler(at, 3) + data + tail
    files = scan(image, formats, **kw)
    return next((f for f in files if f.offset == at), None), files


# ---------------------------------------------------------------------- building blocks
def box(typ: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + typ + payload


def fullbox(typ: bytes, version: int, flags: int, payload: bytes) -> bytes:
    return box(typ, bytes([version]) + flags.to_bytes(3, "big") + payload)


class Ref:
    """The offset of an IFD or blob of make_tiff()."""

    def __init__(self, name: str):
        self.name = name


_TIFF_FMT = {1: "B", 3: "H", 4: "I", 13: "I"}
_TIFF_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 7: 1, 13: 4}


def make_tiff(ifds: dict, blobs: dict | None = None, order: str = "<", head: bytes | None = None,
              chain: list | None = None) -> bytes:
    """A TIFF structure: IFDs (name → [(tag, type, value)]) laid out after the header, each followed by its
    values, then the blobs. Values may be Ref(name) for the offset of an IFD or blob. CHAIN lists the IFDs
    linked by next-IFD pointers (default: the first one alone)."""
    blobs = blobs or {}
    if head is None:
        head = (b"II*\0" if order == "<" else b"MM\0*") + struct.pack(order + "I", 8)
    where: dict = {}
    plan: dict = {}
    pos = len(head)
    for name, entries in ifds.items():
        where[name] = pos
        laid = []
        dpos = pos + 2 + 12 * len(entries) + 4
        for tag, typ, v in sorted(entries, key=lambda e: e[0]):
            if typ in (2, 7):
                vals = v.encode() + b"\0" if isinstance(v, str) else v
                count = len(vals)
            else:
                vals = tuple(v) if isinstance(v, (tuple, list)) else (v,)
                count = len(vals)
            size = _TIFF_SIZE[typ] * count
            if size > 4:
                laid.append((tag, typ, vals, count, dpos))
                dpos += size + (size & 1)
            else:
                laid.append((tag, typ, vals, count, None))
        plan[name] = laid
        pos = dpos
    for name, b in blobs.items():
        where[name] = pos
        pos += len(b)
    out = bytearray(pos)
    out[:len(head)] = head
    chain = chain or [next(iter(ifds))]
    for name, laid in plan.items():
        p = where[name]
        struct.pack_into(order + "H", out, p, len(laid))
        for i, (tag, typ, vals, count, dpos) in enumerate(laid):
            if isinstance(vals, bytes):
                raw = vals
            else:
                vals = tuple(where[x.name] if isinstance(x, Ref) else x for x in vals)
                raw = struct.pack(f"{order}{count}{_TIFF_FMT[typ]}", *vals)
            e = p + 2 + 12 * i
            struct.pack_into(order + "HHI", out, e, tag, typ, count)
            if dpos is None:
                out[e + 8:e + 8 + len(raw)] = raw
            else:
                struct.pack_into(order + "I", out, e + 8, dpos)
                out[dpos:dpos + len(raw)] = raw
        nxt = where[chain[chain.index(name) + 1]] if name in chain and chain.index(name) + 1 < len(chain) else 0
        struct.pack_into(order + "I", out, p + 2 + 12 * len(laid), nxt)
    for name, b in blobs.items():
        out[where[name]:where[name] + len(b)] = b
    return bytes(out)


def exif_block(make="Canon", model="Canon EOS 5D", taken=TAKEN, thumb: bytes | None = None, pad: int = 0,
               order=">") -> bytes:
    """A TIFF/EXIF block like cameras write: IFD0 (make, model, date), the EXIF IFD (date taken, size) and
    IFD1 with a JPEG thumbnail."""
    ifds = {"ifd0": [(0x10F, 2, make), (0x110, 2, model), (0x132, 2, "2020:01:01 00:00:00"),
                     (0x8769, 4, Ref("exif"))],
            "exif": [(0x9003, 2, taken), (0xA002, 4, 6000), (0xA003, 4, 4000)]}
    blobs: dict = {}
    chain = ["ifd0"]
    if thumb is not None:
        ifds["ifd1"] = [(0x103, 3, 6), (0x201, 4, Ref("thumb")), (0x202, 4, len(thumb))]
        blobs["pad"] = bytes(pad)
        blobs["thumb"] = thumb
        chain.append("ifd1")
    return make_tiff(ifds, blobs, order, chain=chain)


def with_app1(jpeg: bytes, tiff: bytes) -> bytes:
    seg = b"Exif\0\0" + tiff
    return jpeg[:2] + b"\xff\xe1" + struct.pack(">H", len(seg) + 2) + seg + jpeg[2:]


def make_mpo(j1: bytes, j2: bytes, kind: int = 0x020002) -> bytes:
    """Two pictures, the first carrying an MP extension (APP2 "MPF") that lists both."""
    def app2(size1: int, off2: int) -> bytes:
        entries = struct.pack("<IIIHH", 0x20000000 | kind, size1, 0, 0, 0) + \
            struct.pack("<IIIHH", kind, len(j2), off2, 0, 0)
        tiff = make_tiff({"mp": [(0xB000, 7, b"0100"), (0xB001, 4, 2), (0xB002, 7, entries)]}, order="<")
        seg = b"MPF\0" + tiff
        return b"\xff\xe2" + struct.pack(">H", len(seg) + 2) + seg
    size1 = len(j1) + len(app2(0, 0))
    first = j1[:2] + app2(size1, size1 - 10) + j1[2:]     # 10: SOI, APP2 marker and length, "MPF\0"
    return first + j2


def png_chunk(typ: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", zlib.crc32(typ + data))


def make_png(w: int = 7, h: int = 5, exif: bytes | None = None, end: bool = True) -> bytes:
    raw = b"".join(b"\0" + filler(w * 3, y) for y in range(h))
    out = b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    if exif:
        out += png_chunk(b"eXIf", exif)
    out += png_chunk(b"tEXt", b"Comment\0hello") + png_chunk(b"IDAT", zlib.compress(raw))
    return out + (png_chunk(b"IEND", b"") if end else b"")


def make_gif() -> bytes:
    """Two frames, a looping extension and an image whose data spans several sub-blocks."""
    out = b"GIF89a" + struct.pack("<HHBBB", 20, 10, 0x80, 0, 0) + bytes(6)
    out += b"!\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00"
    for i in range(2):
        out += b"!\xf9\x04\x04\x0a\x00\x00\x00"
        lzw = filler(300 + i, 10 + i)
        out += b"," + struct.pack("<HHHHB", 0, 0, 20, 10, 0) + b"\x02"
        out += b"\xff" + lzw[:255] + bytes([len(lzw) - 255]) + lzw[255:] + b"\x00"
    return out + b";"


def make_bmp(w: int = 5, h: int = 3, bpp: int = 24) -> bytes:
    row = ((w * bpp + 31) // 32) * 4
    pix = filler(row * h, 5)
    return b"BM" + struct.pack("<IHHI", 54 + len(pix), 0, 0, 54) + \
        struct.pack("<IiiHHIIiiII", 40, w, h, 1, bpp, 0, len(pix), 2835, 2835, 0, 0) + pix


def make_raw(make: str, model: str, *, order="<", head=None, raw_ifd="sub", compression=34713, dng=False,
             tiles=False, sr2=False, counts=True):
    """A camera RAW file: IFD0 with a small preview strip, the EXIF IFD, and the sensor data in a SubIFD
    (or IFD0) at the end of the file. Returns (bytes, expected length)."""
    preview = filler(600, 20)
    sensor = filler(20000, 21)          # RAW formats ignore anything under 16 KiB
    ifd0 = [(0xFE, 4, 1), (0x100, 4, 160), (0x101, 4, 120), (0x103, 3, 6), (0x10F, 2, make), (0x110, 2, model),
            (0x111, 4, Ref("preview")), (0x117, 4, len(preview)), (0x132, 2, "2020:02:02 02:02:02"),
            (0x8769, 4, Ref("exif"))]
    raw = [(0xFE, 4, 0), (0x100, 4, 4000), (0x101, 4, 3000), (0x103, 3, compression), (0x106, 3, 32803)]
    if tiles:
        raw += [(0x144, 4, (Ref("sensor"),)), (0x145, 4, (len(sensor),))]
    elif counts:
        raw += [(0x111, 4, Ref("sensor")), (0x117, 4, len(sensor))]
    else:                                   # Panasonic: only where the sensor data starts
        raw += [(0x111, 4, Ref("sensor")), (0x118, 4, Ref("sensor"))]
    if dng:
        ifd0.append((0xC612, 1, (1, 4, 0, 0)))
    ifds = {"ifd0": ifd0, "exif": [(0x9003, 2, TAKEN)]}
    blobs = {"preview": preview}
    if raw_ifd == "sub":
        ifd0.append((0x14A, 4, Ref("raw")))
        ifds["raw"] = raw
    else:
        ifd0[:] = [e for e in ifd0 if e[0] not in (0x111, 0x117, 0x103)] + raw[3:]
    if sr2:
        key = filler(1200, 22)
        ifd0.append((0xC634, 4, Ref("sr2")))
        ifds["sr2"] = [(0x7200, 4, Ref("sr2data")), (0x7201, 4, len(key))]
    blobs["sensor"] = sensor
    if sr2:
        blobs["sr2data"] = key
    data = make_tiff(ifds, blobs, order, head=head)
    return data, len(data)


def make_raf(jpeg: bytes) -> bytes:
    hdr = b"FUJIFILMCCD-RAW 0201FF383501" + b"X-T2".ljust(32, b"\0") + b"0100" + bytes(20)
    meta, cfa = filler(200, 30), filler(20000, 31)
    joff = 160
    moff = joff + len(jpeg)
    coff = moff + len(meta)
    hdr += struct.pack(">6I", joff, len(jpeg), moff, len(meta), coff, len(cfa))
    return hdr.ljust(joff, b"\0") + jpeg + meta + cfa


CANON_UUID = bytes.fromhex("85c0b687820f11e08111f4ce462b6a48")


def make_cr3() -> bytes:
    cmt1 = make_tiff({"ifd0": [(0x10F, 2, "Canon"), (0x110, 2, "Canon EOS R5"), (0x132, 2, TAKEN)]})
    cmt2 = make_tiff({"exif": [(0x829A, 5, (1, 100)) if False else (0x8827, 3, 100), (0x9003, 2, TAKEN)]})
    uuid = box(b"uuid", CANON_UUID + box(b"CNCV", b"CanonCR3_001/00.09.00") + box(b"CMT1", cmt1) +
               box(b"CMT2", cmt2))
    return box(b"ftyp", b"crx \0\0\0\x01crx isom") + box(b"moov", uuid) + box(b"mdat", filler(20000, 40))


def make_heic(exif: bytes, w: int = 4032, h: int = 3024, brand: bytes = b"heic") -> bytes:
    hevc = filler(700, 9)
    payload = b"\0\0\0\0" + exif

    def meta(off1: int, off2: int) -> bytes:
        hdlr = fullbox(b"hdlr", 0, 0, b"\0\0\0\0pict" + bytes(12) + b"\0")
        pitm = fullbox(b"pitm", 0, 0, struct.pack(">H", 1))
        infe1 = fullbox(b"infe", 2, 0, struct.pack(">HH", 1, 0) + b"hvc1\0")
        infe2 = fullbox(b"infe", 2, 0, struct.pack(">HH", 2, 0) + b"Exif\0")
        iinf = fullbox(b"iinf", 0, 0, struct.pack(">H", 2) + infe1 + infe2)
        iloc = fullbox(b"iloc", 0, 0, b"\x44\x00" + struct.pack(">H", 2) +
                       struct.pack(">HHHII", 1, 0, 1, off1, len(hevc)) + struct.pack(">HHHII", 2, 0, 1, off2, len(payload)))
        ipco = box(b"ipco", fullbox(b"ispe", 0, 0, struct.pack(">II", w, h)))
        ipma = fullbox(b"ipma", 0, 0, struct.pack(">IHBB", 1, 1, 1, 0x81))
        return fullbox(b"meta", 0, 0, hdlr + pitm + iinf + iloc + box(b"iprp", ipco + ipma))
    ftyp = box(b"ftyp", brand + b"\0\0\0\0mif1" + brand)
    at = len(ftyp) + len(meta(0, 0)) + 8
    return ftyp + meta(at, at + len(hevc)) + box(b"mdat", hevc + payload)


def movie(brand: bytes | None, handlers=(b"vide",), mdat_first: bool = False) -> bytes:
    """A small ISO media file with tracks of the given handler types."""
    traks = b""
    for h in handlers:
        tkhd = fullbox(b"tkhd", 0, 3, bytes(72) + struct.pack(">II", 640 << 16, 480 << 16))
        hdlr = fullbox(b"hdlr", 0, 0, b"\0\0\0\0" + h + bytes(12) + b"\0")
        traks += box(b"trak", tkhd + box(b"mdia", hdlr))
    mvhd = fullbox(b"mvhd", 0, 0, struct.pack(">IIII", 0, 0, 1000, 5000) + bytes(80))
    moov = box(b"moov", mvhd + traks)
    mdat = box(b"mdat", filler(900, 50))
    ftyp = box(b"ftyp", brand + b"\0\0\0\0" + brand + b"isom") if brand else b""
    return ftyp + (mdat + moov if mdat_first else moov + mdat)


def make_exr(w: int = 6, h: int = 4) -> bytes:
    def attr(name: bytes, typ: bytes, value: bytes) -> bytes:
        return name + b"\0" + typ + b"\0" + struct.pack("<I", len(value)) + value
    hdr = b"\x76\x2f\x31\x01\x02\0\0\0"
    hdr += attr(b"channels", b"chlist", b"Y\0" + struct.pack("<IB3xii", 1, 0, 1, 1) + b"\0")
    hdr += attr(b"compression", b"compression", b"\0")
    hdr += attr(b"dataWindow", b"box2i", struct.pack("<4i", 0, 0, w - 1, h - 1))
    hdr += attr(b"displayWindow", b"box2i", struct.pack("<4i", 0, 0, w - 1, h - 1))
    hdr += attr(b"lineOrder", b"lineOrder", b"\0")
    hdr += attr(b"pixelAspectRatio", b"float", struct.pack("<f", 1.0))
    hdr += b"\0"
    table = len(hdr) + 8 * h
    lines = b""
    offs = []
    for y in range(h):
        offs.append(table + len(lines))
        lines += struct.pack("<iI", y, 2 * w) + filler(2 * w, 60 + y)
    return hdr + struct.pack(f"<{h}Q", *offs) + lines


def make_wav(frames: int = 4000) -> bytes:
    out = io.BytesIO()
    with wave.open(out, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(22050)
        w.writeframes(filler(frames * 4, 70))
    return out.getvalue()


def make_aiff(frames: int = 3000) -> bytes:
    rate = 44100
    exp = rate.bit_length() - 1
    ext = struct.pack(">HQ", 16383 + exp, rate << (63 - exp))
    comm = struct.pack(">HIH", 1, frames, 16) + ext
    ssnd = struct.pack(">II", 0, 0) + filler(frames * 2, 71)
    body = b"AIFF" + b"COMM" + struct.pack(">I", len(comm)) + comm + b"SSND" + struct.pack(">I", len(ssnd)) + ssnd
    return b"FORM" + struct.pack(">I", len(body)) + body


def make_au() -> bytes:
    data = filler(3000, 72)
    return b".snd" + struct.pack(">5I", 24, len(data), 2, 8000, 1) + data


def make_caf(open_ended: bool = False) -> bytes:
    desc = struct.pack(">d4sIIIII", 8000.0, b"lpcm", 2, 2, 1, 1, 16)
    data = b"\0\0\0\0" + filler(2000, 73)
    return b"caff\0\x01\0\0" + b"desc" + struct.pack(">q", len(desc)) + desc + \
        b"data" + struct.pack(">q", -1 if open_ended else len(data)) + data


def make_mid() -> bytes:
    trk1 = b"\x00\xff\x51\x03\x07\xa1\x20\x00\xff\x2f\x00"
    trk2 = b"\x00\x90\x3c\x40\x60\x80\x3c\x40\x00\xff\x2f\x00"
    out = b"MThd" + struct.pack(">IHHH", 6, 1, 2, 96)
    for t in (trk1, trk2):
        out += b"MTrk" + struct.pack(">I", len(t)) + t
    return out


def make_amr(frames: int = 60) -> bytes:
    rng = random.Random(80)
    out = b"#!AMR\n"
    for i in range(frames):
        if i % 15 == 7:
            out += b"\x7c"                                  # NO_DATA frame
        else:
            out += b"\x3c" + rng.randbytes(31)               # 12.2 kbit/s speech frame
    return out


def make_ape() -> bytes:
    frames = filler(4000, 81)
    seek = struct.pack("<I", 0)
    wavhdr = filler(44, 82)
    head = struct.pack("<IHHIIII", 0, 16, 0, 44100, 0, 1, 0)[:24]
    desc = b"MAC " + struct.pack("<HH", 3990, 0) + struct.pack("<7I", 52, len(head), len(seek), len(wavhdr),
                                                             len(frames), 0, 0) + bytes(16)
    return desc + head + seek + wavhdr + frames


def mp3_frames(n: int, header: bytes = b"\xff\xfb\x90\x64", seed: int = 90) -> bytes:
    """N MPEG-1 layer III frames (128 kbit/s, 44.1 kHz: 417 bytes) with random payloads."""
    rng = random.Random(seed)
    return b"".join(header + rng.randbytes(413) for _ in range(n))


def adts_frames(n: int, seed: int = 91) -> bytes:
    rng = random.Random(seed)
    out = b""
    for _ in range(n):
        size = rng.randrange(120, 300)
        out += bytes([0xFF, 0xF1, 0x50, 0x80 | (size >> 11), (size >> 3) & 0xFF, ((size & 7) << 5) | 0x1F, 0xFC])
        out += rng.randbytes(size - 7)
    return out


def id3(title: str, artist: str) -> bytes:
    frames = b""
    for fid, text in ((b"TIT2", title), (b"TPE1", artist)):
        body = b"\x03" + text.encode()
        frames += fid + struct.pack(">I", len(body)) + b"\0\0" + body
    frames += bytes(100)                                      # padding
    n = len(frames)
    size = bytes([(n >> 21) & 0x7F, (n >> 14) & 0x7F, (n >> 7) & 0x7F, n & 0x7F])
    return b"ID3\x03\x00\x00" + size + frames


def mpeg_ps(packs: int, vob: bool = True) -> bytes:
    """An MPEG-2 program stream of 2048-byte packs (DVD style: navigation packets make it a VOB)."""
    out = bytearray()
    for i in range(packs):
        pack = b"\0\0\x01\xba\x44\x00\x04\x00\x04\x01\x01\x89\xc3\xf8"
        if vob and i % 20 == 0:
            body = b"\0\0\x01\xbf" + struct.pack(">H", 2048 - 14 - 6) + filler(2048 - 20, i)
        else:
            body = b"\0\0\x01\xe0" + struct.pack(">H", 2048 - 14 - 6) + filler(2048 - 20, i)
        out += pack + body
    return bytes(out) + b"\0\0\x01\xb9"


def mpeg1_ps(packs: int) -> bytes:
    """An MPEG-1 program stream with packs of varying size and no end code."""
    rng = random.Random(95)
    out = bytearray()
    for i in range(packs):
        out += b"\0\0\x01\xba\x21\x00\x01\x00\x01\x80\x00\x01"
        if i == 0:
            out += b"\0\0\x01\xbb" + struct.pack(">H", 6) + b"\x80\x00\x01\x04\xe1\xff"
        n = rng.randrange(200, 1500)
        out += b"\0\0\x01\xe0" + struct.pack(">H", n) + rng.randbytes(n)
    return bytes(out)


def ts_packets(n: int) -> bytes:
    out = bytearray()
    for i in range(n):
        pid = 0 if i % 100 == 0 else 0x100
        out += bytes([0x47, 0x40 if i % 100 == 0 else 0x01, pid & 0xFF, 0x10 | (i & 15)]) + filler(184, i % 7)
    return bytes(out)


def ebml(eid: int, payload: bytes, unknown: bool = False) -> bytes:
    idb = eid.to_bytes((eid.bit_length() + 7) // 8, "big")
    if unknown:
        return idb + b"\x01\xff\xff\xff\xff\xff\xff\xff" + payload
    return idb + bytes([0x10, 0, 0, 0]) + len(payload).to_bytes(4, "big")[0:0] + \
        (0x10000000 | len(payload)).to_bytes(4, "big") + payload if False else \
        idb + (0x10000000 | len(payload)).to_bytes(4, "big") + payload


def make_live_mkv() -> bytes:
    """A WebM recording that was never finalised: segment and clusters of unknown size."""
    header = ebml(0x1A45DFA3, ebml(0x4286, b"\x01") + ebml(0x4282, b"webm") + ebml(0x4287, b"\x02"))
    info = ebml(0x1549A966, ebml(0x2AD7B1, b"\x0f\x42\x40") + ebml(0x4461, struct.pack(">q", int(
        (calendar.timegm((2018, 1, 2, 3, 4, 5, 0, 0, 0)) - 978307200) * 1e9))))
    track = ebml(0xAE, ebml(0xD7, b"\x01") + ebml(0x83, b"\x01") + ebml(0x86, b"V_VP8") +
                 ebml(0xE0, ebml(0xB0, b"\x01\x40") + ebml(0xBA, b"\xf0")))
    tracks = ebml(0x1654AE6B, track)
    c1 = ebml(0x1F43B675, ebml(0xE7, b"\x00") + ebml(0xA3, b"\x81\x00\x00\x80" + filler(700, 100)), unknown=True)
    c2 = ebml(0x1F43B675, ebml(0xE7, b"\x10") + ebml(0xA3, b"\x81\x00\x00\x80" + filler(500, 101)))
    return header + ebml(0x18538067, info + tracks + c1 + c2, unknown=True)


def make_ico(png: bytes) -> bytes:
    return struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", 7, 5, 0, 0, 1, 32, len(png), 22) + png


SVG = (b'<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
       b'<rect width="10" height="10" fill="red"/></svg>\n')


# ---------------------------------------------------------------------- the samples
def jpeg_with_exif() -> bytes:
    return with_app1(sample("img.jpg"), exif_block(thumb=sample("img.jpg")))


def cases():
    """(id, data, format key, ext, expected length or None for the data's length, checks on the result)"""
    jpg = sample("img.jpg")
    nef, _ = make_raw("NIKON CORPORATION", "NIKON D750", order=">")
    out = [
        ("jpeg", jpg, "jpg", "jpg", None, {"info": {"width": 24, "height": 16}}),
        ("jpeg-progressive", sample("img_prog.jpg"), "jpg", "jpg", None, {"info": {"progressive": True}}),
        ("jpeg-exif", jpeg_with_exif(), "jpg", "jpg", None,
         {"name": TAKEN_NAME, "mtime": TAKEN_TS, "info": {"camera": "Canon EOS 5D", "width": 24, "height": 16}}),
        ("mpo", make_mpo(jpeg_with_exif(), jpg), "jpg", "mpo", None, {"info": {"images": 2}, "name": TAKEN_NAME}),
        ("jpeg-mpf-preview", make_mpo(jpg, jpg, kind=0x010001), "jpg", "jpg", None, {"info": {"images": 2}}),
        ("png", make_png(), "png", "png", None, {"info": {"width": 7, "height": 5}}),
        ("png-exif", make_png(exif=exif_block(model="iPhone 12", make="Apple")), "png", "png", None,
         {"name": TAKEN_NAME, "info": {"camera": "Apple iPhone 12"}}),
        ("gif", make_gif(), "gif", "gif", None, {"info": {"width": 20, "height": 10, "frames": 2}}),
        ("bmp", make_bmp(), "bmp", "bmp", None, {"info": {"width": 5, "height": 3}}),
        ("bmp-8bit", make_bmp(33, 7, 8), "bmp", "bmp", None, {}),
        ("tiff", make_tiff({"ifd0": [(0x100, 3, 3), (0x101, 3, 2), (0x103, 3, 1), (0x106, 3, 2),
                                     (0x111, 4, Ref("px")), (0x117, 4, 18), (0x115, 3, 3)]}, {"px": filler(18, 3)}),
         "tif", "tif", None, {"info": {"width": 3, "height": 2}}),
        ("bigtiff", sample("img_big.tif"), "tif", "tif", None, {"info": {"width": 24, "height": 16}}),
        ("scanner-tiff", make_tiff({"ifd0": [(0x100, 3, 3), (0x101, 3, 2), (0x10F, 2, "Nikon"),
                                             (0x111, 4, Ref("px")), (0x117, 4, 18)]}, {"px": filler(18, 4)}),
         "tif", "tif", None, {}),
        ("nef", nef, "nef", "nef", None,
         {"name": TAKEN_NAME, "info": {"camera": "NIKON D750", "width": 4000, "height": 3000}}),
        ("nrw", make_raw("NIKON CORPORATION", "COOLPIX P7800")[0], "nef", "nrw", None, {}),
        ("cr2", make_raw("Canon", "Canon EOS 5D Mark III", head=b"II*\0\x10\0\0\0CR\x02\0\0\0\0\0", raw_ifd="0",
                         compression=6)[0], "cr2", "cr2", None, {"info": {"camera": "Canon EOS 5D Mark III"}}),
        ("arw-sr2", make_raw("SONY", "ILCE-7M3", compression=32767, sr2=True)[0], "arw", "arw", None,
         {"info": {"camera": "SONY ILCE-7M3"}}),
        ("dng", make_raw("Google", "Pixel 7", compression=7, dng=True, tiles=True)[0], "dng", "dng", None,
         {"name": TAKEN_NAME}),
        ("orf", make_raw("OLYMPUS IMAGING CORP.", "E-M5", head=b"IIRO\x08\0\0\0", raw_ifd="0", compression=1)[0],
         "orf", "orf", None, {}),
        ("pef", make_raw("PENTAX Corporation", "PENTAX K-5", order=">", raw_ifd="0", compression=65535)[0],
         "pef", "pef", None, {}),
        ("srw", make_raw("SAMSUNG", "NX300", compression=32769)[0], "srw", "srw", None, {}),
        ("raf", make_raf(jpeg_with_exif()), "raf", "raf", None, {"name": TAKEN_NAME,
                                                                 "info": {"camera": "Canon EOS 5D"}}),
        ("cr3", make_cr3(), "cr3", "cr3", None, {"name": "2019-08-15 10.20.30", "info": {"camera": "Canon EOS R5"}}),
        ("heic", make_heic(exif_block(make="Apple", model="iPhone 13")), "heic", "heic", None,
         {"name": TAKEN_NAME, "info": {"width": 4032, "height": 3024, "camera": "Apple iPhone 13"}}),
        ("avif", sample("img.avif"), "heic", "avif", None, {"info": {"width": 16, "height": 16}}),
        ("webp", sample("img.webp"), "webp", "webp", None, {"info": {"width": 24, "height": 16}}),
        ("psd", sample("img.psd"), "psd", "psd", None, {"info": {"width": 24, "height": 16}}),
        ("jp2", sample("img.jp2"), "jp2", "jp2", None, {"info": {"width": 24, "height": 16}}),
        ("j2k", sample("img.j2k"), "jp2", "j2k", None, {"info": {"width": 24, "height": 16}}),
        ("jxl", b"\x00\x00\x00\x0cJXL \r\n\x87\n" + box(b"ftyp", b"jxl \0\0\0\0jxl ") +
         box(b"Exif", b"\0\0\0\0" + exif_block()) + box(b"jxlc", b"\xff\x0a" + filler(400, 5)), "jxl", "jxl", None,
         {"name": TAKEN_NAME}),
        ("exr", make_exr(), "exr", "exr", None, {"info": {"width": 6, "height": 4}}),
        # video
        ("mp4", sample("v.mp4"), "mp4", "mp4", None,
         {"name": "2021-05-06 07.08.09", "info": {"width": 16, "height": 16, "duration": 0.2}}),
        ("mov-moov-last", sample("v.mov"), "mp4", "mov", None, {"info": {"width": 16, "height": 16}}),
        ("qt-no-ftyp", movie(None, mdat_first=True), "mp4", "mov", None, {"info": {"width": 640, "duration": 5.0}}),
        ("m4v", movie(b"M4V "), "mp4", "m4v", None, {}),
        ("3gp", movie(b"3gp4"), "mp4", "3gp", None, {}),
        ("3g2", movie(b"3g2a"), "mp4", "3g2", None, {}),
        ("f4v", movie(b"F4V "), "mp4", "f4v", None, {}),
        ("avi", sample("v.avi"), "avi", "avi", None, {"info": {"width": 16, "height": 16}}),
        ("avi-opendml", sample("v.avi") + b"RIFF" + struct.pack("<I", 1004) + b"AVIX" + filler(1000, 6),
         "avi", "avi", None, {}),
        ("mkv", sample("v.mkv"), "mkv", "mkv", None, {"info": {"width": 16, "height": 16}}),
        ("webm", sample("v.webm"), "mkv", "webm", None, {"info": {"width": 16, "height": 16}}),
        ("webm-live", make_live_mkv(), "mkv", "webm", None,
         {"name": "2018-01-02 03.04.05", "info": {"width": 320, "height": 240}}),
        ("wmv", sample("v.wmv"), "wmv", "wmv", None, {}),
        ("flv", sample("v.flv"), "flv", "flv", None, {"info": {"width": 16, "height": 16}}),
        ("vob", mpeg_ps(150), "mpg", "vob", None, {"info": {"packs": 150}}),
        ("mpg", mpeg1_ps(30), "mpg", "mpg", None, {}),
        ("ts", sample("v.ts"), "ts", "ts", None, {}),
        ("ts-long", ts_packets(9000), "ts", "ts", None, {"info": {"packets": 9000}}),
        ("m2ts", sample("v.m2ts"), "m2ts", "m2ts", None, {}),
        ("rm", sample("v.rm"), "rm", "rm", None, {}),
        # audio
        ("mp3-id3", sample("a.mp3"), "mp3", "mp3", None, {"name": "Band - Song", "info": {"sample_rate": 8000}}),
        ("mp3-id3v1", sample("a.mp3") + b"TAG" + filler(125, 7), "mp3", "mp3", None, {}),
        ("mp3-bare", mp3_frames(40), "mp3", "mp3", None, {"info": {"sample_rate": 44100}}),
        ("mp3-tagged", id3("Title", "Artist") + mp3_frames(5), "mp3", "mp3", None, {"name": "Artist - Title"}),
        ("aac", adts_frames(40), "aac", "aac", None, {}),
        ("aac-id3", id3("T", "A") + adts_frames(6), "mp3", "aac", None, {"name": "A - T"}),
        ("flac", sample("a.flac"), "flac", "flac", None, {"name": "Band - Flac Song", "chance": CHANCE_GOOD}),
        ("flac-id3", id3("X", "Y") + sample("a.flac"), "mp3", "flac", None, {}),
        ("opus", sample("a.opus"), "ogg", "opus", None, {"name": "Band - Opus Song"}),
        ("m4a", sample("a.m4a"), "m4a", "m4a", None, {"name": "Band - M4a Song", "category": "audio"}),
        ("m4a-isom-audio-only", movie(b"isom", handlers=(b"soun",)), "m4a", "m4a", None, {}),
        ("m4b", movie(b"M4B ", handlers=(b"soun",)), "m4a", "m4b", None, {}),
        ("wma", sample("a.wma"), "wma", "wma", None, {"name": "WBand - WSong", "category": "audio"}),
        ("wav", make_wav(), "wav", "wav", None, {"info": {"channels": 2, "sample_rate": 22050}}),
        ("aiff", make_aiff(), "aiff", "aiff", None, {"info": {"sample_rate": 44100}}),
        ("au", make_au(), "au", "au", None, {}),
        ("caf", make_caf(), "caf", "caf", None, {}),
        ("amr", make_amr(), "amr", "amr", None, {}),
        ("mid", make_mid(), "mid", "mid", None, {"info": {"tracks": 2}}),
        ("ape", make_ape(), "ape", "ape", None, {}),
        ("wv", sample("a.wv"), "wv", "wv", None, {}),
    ]
    return out


def pytest_generate_tests(metafunc):
    if "case" in metafunc.fixturenames:
        metafunc.parametrize("case", all_cases(), ids=[c[0] for c in all_cases()])


@functools.lru_cache(maxsize=None)
def all_cases() -> tuple:
    return tuple(cases())


def test_sample_found_exactly(case):
    _id, data, key, ext, length, checks = case
    at = 8192 + 512 * (len(_id) % 7)
    f, files = carve_one(data, at=at, after=bytes(3000) + filler(9000, 9))
    assert f is not None, [(x.offset, x.length, x.key) for x in files]
    assert (f.key, f.ext, f.length) == (key, ext, length or len(data)), (f.key, f.ext, f.length, len(data))
    assert f.chance == checks.get("chance", CHANCE_GOOD) or f.chance >= CHANCE_FAIR
    for k, v in checks.items():
        if k == "info":
            for ik, iv in v.items():
                assert (f.info or {}).get(ik) == iv, (ik, f.info)
        elif k != "chance":
            assert getattr(f, k) == v, (k, getattr(f, k))
    # nothing else is found in the random data around it
    assert [x.offset for x in files] == [at], [(x.offset, x.length, x.key) for x in files]


def test_samples_in_random_data_with_random_after():
    """With random data (not zeros) right after each file, the lengths still come out exact."""
    for _id, data, key, ext, length, _checks in all_cases():
        if _id in ("amr",):                   # AMR frames have no sync: random bytes may pass as frames
            continue
        f, _ = carve_one(data)
        assert f is not None and f.length == (length or len(data)), (_id, f)


def test_open_ended_formats_end_at_the_next_file():
    png = make_png()
    for data, ext in ((b"gimp xcf v011\0" + struct.pack(">IIII", 100, 80, 0, 150) + filler(3000, 12), "xcf"),
                      (make_caf(open_ended=True), "caf"),
                      (make_raw("Panasonic", "DMC-GH4", head=b"IIU\0\x08\0\0\0", raw_ifd="0", compression=34316,
                                counts=False)[0], "rw2")):
        gap = 4096 * 2
        image = filler(8192, 13) + data + filler(gap - len(data) % 4096, 14) + png + filler(5000, 15)
        files = scan(image)
        assert [(x.offset, x.ext) for x in files] == [(8192, ext), (8192 + len(data) + gap - len(data) % 4096,
                                                                     "png")], files
        assert files[0].length == files[1].offset - 8192 and files[0].chance == CHANCE_FAIR


def test_disabled_formats():
    ico = make_ico(make_png())
    assert carve_one(ico)[0] is None
    f, _ = carve_one(ico, formats=MINE)
    assert (f.ext, f.length, f.info["images"]) == ("ico", len(ico), 1)
    f, _ = carve_one(SVG, formats=MINE)
    assert (f.ext, f.length) == ("svg", len(SVG))
    assert carve_one(SVG[:-8], formats=MINE, after=bytes(100) + SVG[-8:])[0] is None   # cut by binary data
    cs = b"\xff\x0a\xfa\x7f\x01\x90\x08" + filler(900, 16)       # a bare JPEG XL codestream: open-ended
    image = filler(4096, 17) + cs + filler(4096 - len(cs) % 4096, 18) + make_png()
    files = scan(image, [BY_KEY["jxl-codestream"], BY_KEY["png"]])
    assert [(x.ext, x.length, x.chance) for x in files][0] == ("jxl", files[1].offset - 4096, CHANCE_FAIR)


def test_exif_thumbnail_inside_a_jpeg():
    """A JPEG thumbnail in the EXIF block that happens to start at a block boundary is part of the photo."""
    thumb = sample("img.jpg")
    tiff = exif_block(thumb=thumb)
    pad = 512 - 12 - tiff.index(thumb)
    data = with_app1(sample("img.jpg"), exif_block(thumb=thumb, pad=pad))
    assert data.index(thumb) == 512
    _f, files = carve_one(data, at=4096)
    assert [(x.offset, x.length) for x in files] == [(4096, len(data))]
    _f, files = carve_one(data, at=4096, skip_inside=False)
    assert [(x.offset, x.length) for x in files] == [(4096, len(data)), (4608, len(thumb))]


def test_truncated_files():
    jpg = jpeg_with_exif()
    sos = jpg.rindex(b"\xff\xda")
    f, _ = carve_one(jpg[:sos + 40])                   # cut inside the compressed data, random after
    assert f is not None and f.ext == "jpg" and f.chance == CHANCE_POOR and f.length >= sos + 40
    f, _ = carve_one(make_png(end=False))
    assert f is not None and f.chance == CHANCE_POOR
    f, _ = carve_one(jpg[:100])                        # only the start of the header: not a photo
    assert f is None
    for blank in (b"\0", b"\xff"):                      # the rest was wiped / erased flash: it ends there
        f, _ = carve_one(jpg[:sos + 40], after=blank * 50000 + filler(1000))
        assert f is not None and f.chance == CHANCE_POOR and f.length == sos + 40
    mp4 = sample("v.mp4")
    files = scan(filler(4096, 19) + mp4[:-300])        # the medium ends inside the file
    assert [(x.offset, x.length, x.chance) for x in files] == [(4096, len(mp4) - 300, CHANCE_POOR)]
    opus = sample("a.opus")
    f, _ = carve_one(opus[:300])
    assert f is not None and f.chance == CHANCE_POOR and f.length < 300
    flac = sample("a.flac")
    f, _ = carve_one(flac[:-100])
    assert f is not None and f.chance <= CHANCE_FAIR


def test_planted_signatures_alone_are_rejected():
    """Every signature at many block starts of random data: no false positives."""
    rng = random.Random(23)
    data = bytearray(rng.randbytes(8 * 1024 * 1024))
    magics = [(off, m) for f in MINE if f.key != "jxl-codestream" for off, m in f.magic]
    for i in range(0, len(data) // 512 - 80):
        off, m = magics[i % len(magics)]
        p = i * 512 + off
        data[p:p + len(m)] = m
    files = scan(bytes(data), [f for f in MINE if f.key != "jxl-codestream"])
    assert files == [], [(f.offset, f.key, f.length) for f in files][:10]


def test_feed_matches_scan_on_media():
    rng = random.Random(29)
    image = bytearray()
    for _id, data, *_ in all_cases():
        image += filler(rng.randrange(1, 40) * 512, rng.randrange(1000))
        image += data
        image += bytes(-len(image) % 512)
    image = bytes(image + filler(10000, 1))
    src = BytesSource(image)
    want = [(f.offset, f.length, f.ext) for f in Carver(src, DEFAULT).scan()]
    assert len(want) >= len(all_cases()) - 2
    for chunk in (64 * 1024, 1024 * 1024):
        c = Carver(src, DEFAULT)
        got = []
        for off in range(0, len(image), chunk):
            got += c.feed(off, image[off:off + chunk])
        got += c.flush()
        assert [(f.offset, f.length, f.ext) for f in got] == want


def test_fuzzed_samples_never_raise():
    """Random damage to real files: the parsers answer (a hit or None), they never raise."""
    rng = random.Random(31)
    t0 = time.monotonic()
    for _id, data, *_ in all_cases():
        for _ in range(25):
            b = bytearray(data)
            how = rng.randrange(3)
            if how == 0:
                for _ in range(rng.randint(1, 12)):
                    b[rng.randrange(len(b))] = rng.randrange(256)
            elif how == 1:
                b = b[:rng.randrange(1, len(b))]
            else:
                i = rng.randrange(len(b))
                b[i:i + 4] = rng.choice([b"\xff\xff\xff\xff", b"\0\0\0\0", b"\x7f\xff\xff\xff", b"\0\0\0\x01"])
            src = BytesSource(bytes(b) + rng.randbytes(rng.choice([0, 700])))
            for f in MINE:
                f.parse(Reader(src, 0))
    assert time.monotonic() - t0 < 30


def test_helpers():
    assert exif_time("2019:08:15 10:20:30") == TAKEN_TS
    assert exif_time("0000:00:00 00:00:00") is None and exif_time("garbage") is None
    t = parse_exif(b"Exif\0\0" + exif_block(order="<"))
    assert (t.make, t.model, t.date, t.date_original) == ("Canon", "Canon EOS 5D", TAKEN_TS, True)
    # the Ogg CRC (computed through zlib) against a straightforward implementation
    page = sample("a.opus")[:200]

    def slow(data: bytes) -> int:
        crc = 0
        for byte in data[:22] + b"\0\0\0\0" + data[26:]:
            crc ^= byte << 24
            for _ in range(8):
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 else (crc << 1) & 0xFFFFFFFF
        return crc
    assert ogg_crc(page) == slow(page)
    n = 27 + page[26] + sum(page[27:27 + page[26]])
    assert ogg_crc(sample("a.opus")[:n]) == struct.unpack_from("<I", page, 22)[0]


# Made with ffmpeg 6 / ImageMagick 6 (see the module docstring), zlib-compressed and base64-encoded.
SAMPLES = {
    "v.mp4": (
        "eNqNVG9oW1UUvy9JZ1lnF6GVMuO43TpYZ5O+l3SxqXuQLnQrw0ll3bSjmt68d1/yzPvX927TpopGN7HgFP3QfdiHsYlURETBYZ0wyAfB"
        "wrD++aC29INDHFPGZGz9JBrPTVuTbSi+5N5zzr2/c859v3PuQwhhjRUd3bNNhHyISxhRUlAk0+mREPJ3mrZdQAgZZiGngkQrFw+M8AF7"
        "18BcQALi/9pzh3GvnUT/+fjgf4S5JA/6KMtXc/prOf+JtnCP5//JG1wfCHVQlXkgQ9TwWJ3HQs1XuGyqOgEFm+rd774brEZ09IsqOpxT"
        "DXcjT0FXaX3eY2Dbg8RSDcoxQsHULQ2UloJZDVp/zA51bS+kulSrO9SWCdfAa7oQ91jGAP1Tj3lqHWaOF+1fqOAvHUSDIAc3EK2PAz4u"
        "RmJSRBKj2NAzU9F4T51HW6UCcxegUsL+8ubKFdSaBbn8vAAE+jmLfiF5c8dzAgrkFrdy2oIO8Zz17Hy0ZJi7Tu1Mcm2gNo9Vad84JZQ7"
        "wPUWeJv6dT5CsKbctear25u+s238z4BsWoul2DU/P2+bzITKeCmPm7Qq+dNeXzYotUscx6gnLayv9cau95nNAz6skqpzlV7gTwP+pDjw"
        "J/Ju0FwKhfc7JqDgQMObGiqVoZWBXy9dXRqcP931I17aeeN3TjIOY8V2KZZAdWOS2ItjEpUSWgI2BiMA6D48NHAw3IP7j6UAqVIFNlK2"
        "UzSoxnBUFGPhqBiNwWKOMaevu3tycjLC2842iBWx3Ww3zxLJMdMAjO0w3ba8PqyQDFFkEUNryRJWacawlbws9sEPE4sYRY9yC5tUhrbH"
        "3kQGNBE7XhHgMKddVZYiIkBgwqY+RdU0j8U90i6xslSW4ljJubZJ0uAqYeZSw9A9QPRO9aoKA0UZN2FWKVGnbYvKUalLkrBGPJZ2vLzu"
        "gNN6gHEnbWuaR7kTy7ng4MGmYdt5kgMjXVvzDF2htQURW241haKbhPFj6BajrkEABOsZY8IlxbRimw6pHgi4gc+NbkEIALqEYzSXmJSH"
        "mqR6Nscc0PK0CNtydO+GmoZ7LEsi9hRqUWWCx6r6c05c6uU404qsuBo24R5QTiUYcjQWEfE4Ty+LkTioDo9TlWRKjidA8Rh15B6sO8Aq"
        "1A5I74EKjcsiKkHvCXTmZN+WMeEbFMw2D0U+PHH52dVHHnz0J/SJ9sFLUR85F/7j9CvnR18Y3bb7uxUfxh89lRiaeWP+t+vJgND2Tnso"
        "MT11q9P6vjTQ0Pn1yW2/7AvtqbyOkg+82TbQ+lX/3PYrLx6Bj1rpM9ToP3GjGZV2os1fjjUdHWrpfeKvMwHa/t6p1PWQgA4EwKf0WMR/"
        "MxjMzf45n0AP/YADDauVTcgH1+N0IFtqOvdqNi1+O5cafnr/nqvDT5ZnL85sfXepaSx0+MLPpeSOke6Ot8Ifo67tQvLzgyN7Z3ctXio3"
        "o/O3L6y+fEg8u3J7oYySUipddk69fa2yfH+58bVb+/qOLwaW4bLd138GZ1YPiX8DfHOszw=="
    ),
    "v.mov": (
        "eNqNVG9oHEUUn7271NCk6QmJxHqUSRqhrbnL7l165mIXLo1JQzFyYlqtRC9zu3O36+3ebnYnd7ko9rQVA9aiQvKhH6QtUhERBQtRoXAf"
        "CgbE+OeDmpAPlmKpUiqlzSfR880lMZco4u7OzJs3v/d7b97bGYRQc5oV7XGGMUIetDqi+oKuUoS8tqkSBvqRbXWVSmJ54JfL1xeH5mY7"
        "f8SLe279NhmOduMgViyHYglEJyKJPTgiUSmWjsHCUAgAXcOJgcPBbtx3rB+QKlVgod+yiwZNMxwWxUgwLIYjoNQYs3u7ugqFQigP3i2D"
        "5EKWk+niXkIaMw3AWDbTrZzbixWSIoosYoemZQmrNGVYSlYWe+HFJEeMokv5DJtUVnWC3YkUSCK23SLAoU86qiyFRIBAh019kqpJzsUt"
        "kg7JZagsRbGiOZZJkmAqYeZQw9BdQPRM9qgKA0EZN6FXKVGnrByVw1KnJOE0cVnSdrO6DUZrBON20kqnXcqNmOaAgQuLhmVliQaT5IbO"
        "NXSFbihEnHOqLhTdJIyHoecYdQwCINCnjAmHFJOKZdqkGhDkhjlEzwEFAB3CMWmHmJRTFaie0ZgNUpYWYVkOH1gXk6aekyURuwrNUWWC"
        "c1XteU4c6mo804qsOGlspiARPJUwkcORkIjHuXtZDEVBtDlPdSSTcjQGgsuoLXdj3YasQu0g6d1QoXFZRCWEBIFOn+ptHBO+Qf5MUyL0"
        "4ckvn1t56L6Hf0KfpD84EfaQc8HfZ185P/ri6K693y17MP7oqVhi+o25X2/GfULrhbZAbGryzr7c96WBun1fn9r188HA/srrKH7vmdaB"
        "lq/6Lu6++tKTVxAqfYrqvSdvNaHSHrT9i7GGo4nmnsf/POujbe+d7r8ZENCgD2xKj4S8t/1+beaPuRh64Afsq1upbEMeAaFZX6bUcO7V"
        "TFL89mL/yNOH9l8feaI889n0zncXG8YCw5euleLtx7s63gx+jDp3C/HPDx8/MPPgwuVyEzp/99LKy0fEd5bvzpdRXOpPlu3Tb92oLO0o"
        "179252DvMwu+JThs9/SdxamVIyKcN2RaVh5UhpnXVLTp8d6Abh5BPEKtWtiM2jqPo/98PPBloc5ZkEdZturT+y9s8/+w/D9+/WsNoQ6q"
        "MhfGADVcVmMxv2ErXDPhpIKATXXr3vfyKwmdqFQnQU01HC6YmuHkq/fUxtN4jF8dQySnGhRAwhn4IdOgb86bVdLaMDvXiVQgmnAMXEvU"
        "8Chh5G8e1KGu8gRUOBE1G2hcs+NlaXdZygD5gstctQbzNskrUm2aBgeHE9Xc8+aHdwjEoXVEy2OAj4qhiBSSxDA29BS/AWtCa63wRHQC"
        "ql84VN5euYpaMjAuvSD4efV4J8Rvtz8vIJ+2sJOn2G8T117zzlury6rlWI8IwvBxuRkir9XzFgCdskXnqVmb2vw7eZ/lyVvlUqwauw5o"
        "bRMq4yW+/3234KAdR6/AVtOwVSkKWxX/Arm2mTE="
    ),
    "v.avi": (
        "eNoL8nRzMxBnYHAM81Tw8QwOsRBiYMhIKcpJLMvMsGBgYFjQxsiwIpEBDAQ4GRiYIEwGRogIEDKAMToAmfUAKFFcUpQDxGCzyjJTit18"
        "A0yQ1YHM4YKyQWbXAfF/IIDJg2wA6k/TALI1oHYJgPVJMIDNYsa02yvUz1sCqIgFyjcwSElmGAWjYBSMglEwCkbBKBgFo2AUjIJRMApG"
        "wYgCZQVFBS5IfND4A2JcgRGJjRDHNc4BGmtgASrMT8nNAaKMHyM4XEFjPlJA2tPPzd8z2C2EDySWWJZmZqBnaKZnaGAADq0fzKMpcBSM"
        "gpFaQswC0rn5ZZmgUdk6sCjjBmAByri1UxhS5DIqMBzp7WAIZWhhEkkGcjcBy5BkYBlibAgsQ4yAApsZBNiB1DaB47fdN799ddr76Emx"
        "Rd8lvnFYpq5esG1hDDuv6NxjX1atz5X41vJyY/qSVQmBvd3eASt0nGSaDNmUYju6Gg8EbE1JcF9sVA5yBTvEFdsCHz9jyEypMFRggIwZ"
        "g8p70BhyHQNiDLkLiEHqAaoZaM4="
    ),
    "v.webm": (
        "eNqTcr2/eL5TWyOj03cg/tTI4vS5kcOpqaU8NSnXqb2Ryam1kUkiuCGdkQEEmLcK+s4u2eW7uzt4dYuo58q04DWNCyE8sZB12UDeDd/d"
        "PUCeUMjh9OA1TYyqEK5M8G6gZBPz/DcQcxgiGWgFQK7apHV9YzO/k4NvQ69PYlmamYGeoZmeoYFBuCMq36WzwyETog3k/BProK6zv97I"
        "WHy04+r/qYyzLzS/nNPIoLR1TnNpXkpHI0Nba1h8WIBFcyOj8uPmFtavDxkeTNjQKLCrUWBWI1PohpbQnY2MIN//KS5ekHygIf3ELNfF"
        "7a5+zv4urkEu7aj2FxdfSz7QnYywKf3EQmTVU4Cqk4GqjQ2Bqo0UcjKTygoqwGo6XEKDHEM8/f1c2icbGFiBkZ6RARQwyDtvK3X8/LyR"
        "YbFjbyMDQ8MHHoa5jFoCDAIMDO4cra0drS0dTExMpUmMfxjvKPxRvcf4z3GP4wHm34zXmH81/mP+wX+A/8P9R34f7Jvj10Xp/OewT9nU"
        "81/CXsD0QCnD/0l/GL+x/g1/w76G/cf2j/Kv90+cf8P+/6eGf1N/J05LnJUsd9Hgw7//b39u+q9wLJL3/Hm+NaX7Vk5pYvVV/3YzsGRD"
        "B2P/KjPJ/28vHv6Xud9Q1N3x2Mv/vyyjlj41+jP9mYJ6tkC1S3X+f+EQ9ba4fZO/3foe/0erKuv+9QvJ/n9synsP+yhEzfwgMVcuX5Fl"
        "/0n15jUbxO866mr5OS2sv8lSX7Ftv5ZAguYC13n/p0VV/y37+r7+x///iuyLCu9cqzuuufBP/fP//zu3ZJbqb/r9YoX/W/67+/+fcT2v"
        "63yz7FRFZl8N/9vY1a/XP3u4Mnul9LpzM70nzxHf2ZD+jyvQvcxG+k79v1dd+rOcJtxPaNm0U8682Pr/n44nO703qk2tX/SalXOT9tf9"
        "ar8D0///r5iwMPMnm8vH4G6fZTHvJ03J4+r4JbD4//yzEovvNTKkMAQyMTAKCDBI8AT2HYitr2r+ebBnAcNJ3QS9gATG4PDkOvvt5enJ"
        "N/1mzvirE3B0W5zpqjVv9i8Wv7iuf/7S+9VnKjhfPwyMeqrYwNy+55eCs2X635R1LNHXTcXLDBhAGW3i7v7NjQzbu4AZ+mMT47IPjcwA"
        "Lnybdw=="
    ),
    "v.mkv": (
        "eNqTcr2/eLFTWyOj03cg/tTI4vS5kcOpqSM3saQovzg70akdKNTayCQR3JDOyAACTIsFfWeXHNjfwth938R3d3fw6hZRz5VpwWsaF0J4"
        "YiHrsoG8j767e4A8oZDD6cFrmhgnQLgywbuBkk1M7W8gpjEEM1AfgNxzen9LvHtwhtb1jc38Tg6+Db0+iWVpZgZ6hmZ6hgYG4Y6o/OIl"
        "E05cvsJ9qVSW182Z67LAUuNil84Oh0yIeSAfOczc33LYZuO7dVB3d11vZCw+2tF9+vSV7zqbpec0MihtndNcmpfS0cjQ1h8W7xvg6m6i"
        "7xnsr+8YHNDcyKj8uLmF9etDhgcTNjQK7GoUmNXIFLqhJXRnI2Pou0YGWGgwMTAkL1rPwMC4ASjAuLVTGEgChRkVGI70djCEMrQwiSQD"
        "uZuAjk8GOt7YEOh4I1AQOzQC/Stvs624eEHygYb0E7NcF7e7+jn7u7gGubSj+bX4avKB7mSE29NPLEBWPRnFcIXcgtR0k/QTC10Xd7iE"
        "BjmGePr7AdUYGFiBkZ6RARQwyDtvK329v8XqiOKp540Miy83MjA0AN26mUGAHUhtEzh+233z21envY+eFFv0XeIbh2Xq6gXbFsaw84rO"
        "PfZl1fpciW8tLzemL1mVENjb7R2wQsdJpsmQTSm2o6vxQMDWlAT3xUbli7sbGVJA4bEt8PEzUFKavr+Fdd+/Tbv7NzcybO8CJuGPTUzi"
        "Hxo5AYSg9Rg="
    ),
    "v.wmv": (
        "eNozUNtU2pd2XnDZTYZVDEnncnyZGMCAFYgZmRbeWd3jvvK8YN8ThgM8CsGpGQzYQSg/lNFgd/XexrmMjFCuQ9d3MLOhRQ7Ml+GBiIMs"
        "aeCBYAU/BoatzPvj9UD2PIbYMweqX/DS5dW7QOLPIOJsDHlA0VenfxxdH13u0ZK+qsfll8+pPAaEqYwMUgzMDCxAliNDMUMBQypDMkMJ"
        "QxBDIpDMZMhniACrYSBCZSRUpcOSC5fYH18SnP6BYcHJuBUBKVDbGBk0GMIZfBn0GVyBrkoG6kgB6stjSGcIBppVAjYFxCuG+JzBB2hy"
        "GUMagxmDAYMegyGQBpEGQMjAMJH9zvbtSP5shdpx4L3kHt/o84Ir/jI0xMe4aDOE/1YIReZDgTncTSAgAMVMOgw6SFxGBgmGcN8wI6Cv"
        "MUCA8JYGh6CLbbKGFwQXLwF6lNnjmxNUzhFNnBFsFitDOUMu0ENGYDUsYJPN0BLTJh7syQWWPBgZm4BxHBvKBeKkMDQ1giU4TjJCUgqQ"
        "Fohh2pl/MUFCpOkA58ksXcf7dmItV7g3XWjMbChvYd6x7dIG6zW689Xvix3Qrn/Q96/WoElQ94Je854tCtEbCo4cEK2xXsupfiaN8cqW"
        "NX+uq21ln7CBISSCwUCHQViMIbTHYbeuoe6BWe0lV7bV2ijei14QO0/o/rQDnHdUdAvM7jRVP7PV2abQma0bHO28+7fJ/KUbz/JXM2U2"
        "CsxdkLo3/4GT5OSg+2IMAdwMrKp7dTYw+AlNY/A87XXp+uf7uoazWN4lmujaqG5+UT7tb/TShHJJ+QiBC3qnc3WbX36q2/M9evW9861z"
        "OCySJrV4Tdt0gCkz50cEg42u7aMLes+Wbg66M39VrS6H3M9+L44o7jUnJmZp15sa/vm8dN7fFZ/tGRW2H24I28Xn+pn74AJGzgoTZoN6"
        "ZgdhK8bNEin7kiZkcMQzXGDYlKG3ainDjX0ZZjoHa27FK7A3Oxh+/6s/jXEBw8+SqyHSnWwNTaKOFWWf52t2RpbqPvo9JzREioF/n5fj"
        "AoELJoxKbIe3H9jfXDpdXLw54Zz4/oM7JmQwuPyMnn81dALfhLwuxgWSMytMGGxr+qdIph683bjp16qgnwrSbBEmzKZr9s1aNV1i6dMD"
        "d4N4u/8E8CoccmAEFyscRtB8b8TQoZzTKhQT63PR5My9humLzqY8OGkhwOpdaxKn0X2w+tCHw2++S5ROMritMIfxjNuNgIspBQyjYBSM"
        "glEwCkbBKBgFo2AUUAomcDAYb3x6XrDzC6hv43k6DIe6hmkz4GxWgqYCAGhwcnM="
    ),
    "v.flv": (
        "eNpFUl1IVEEY/WZnd+6sjbu2PnQ1f9ayWqz0amE99LO7VhQaiOQmQjGLu7Y3yjXbygxy1pV+DCqDHoqomyCVSFgvGVjOkkRBDxZIERGX"
        "oB56SSPCh6Lu5kIfzMMczjnfnOHsaAghBABO64AHYBwWxgY58Y7d0UR4WzgRphZAgUaOdYUTerwDtr68lpnr4DihRxIx8GtZFYlF9QOx"
        "xH8g97geicYjlocljYJ/3bkF3NneFT4cXcDKs1z2j9sWj0Tb9Aj4sygo0Y4M1mWD3Ibw8fZarbK6trJa04C264eiR/Uey2KAZsmZGM+c"
        "YFOzdytRP1C6uOQJEocJbFPtnZ0lpkryXAS9UtFir6po3JEUSwiSOC0KKwmsV4nkOAhX7rUECDQ3ai4uKYYP5Zemhnthzlc/+0slJnfI"
        "eQ2NzHyeVdx9qNtng7pQ3q/5Mc6QqPCkZY/BnUlxhMBOlRi8CImjMM0L+lQNGYXMflfLNeRGyxQN/ynF8HELwRO7MqvdgTW9Ji96OqrC"
        "m9kzDM5pKE0zbwzaB1dJqcxPSpUGW8pWs5sBkU+5rMHQ5MImhodbie3Gv11XU/CR4Y0ak7Kmv8ynUpFLS6uErE3BF4a55ir12A1eFyz2"
        "BMTAHoZb782t3Su+Xe3urT87XX+55pgC+QERJ9CtYslJUngIMspSIBmMK+nyHmUquUZVvH4CO+xr570jeKh1rC/vfRVBL9yJx43FlY3v"
        "J9ittHCNpEVZiNn0Ti2n8H4KXpt8kVdzfOVa0U2a8yQgwtg0rE+U8mQFgdPO3ioCdbdJCkqYMvTg+6jDLdeZ08HJ/oI5n4pmeUFS7CcQ"
        "67mrosGVGLYHhNtSbDoVdJ5IBhn6Osbz92Dw7jPkhj6bcWbFeb9ckUIzW/LswwHFLGT44HDbOyuuiBVLq+DLra5sAIhkarLMqgmjtNp2"
        "53Pod/Pv7xfGhx61NrwNcf3PxcnNvp+NTc+X1jM0aA609E//cNFPFVqYXxKWMvgXCUHyEQ=="
    ),
    "v.ts": (
        "eNrV1W9MG2UcB/Dfc0f/jZb22gpMhFFbYCNxXqG4Qsg42kjbbFImphCcrOusgxl1Y2TAZrqjAgIuii2yZkO8Ro1EXwgICYsz6WI0ZKip"
        "i5kYcLYMhxhftM6QTRrPa+MLEl6ZkOg9L+5+uXvzzXOf73MWilCAKVYA6BoAi1hACVptVSJhTc0LJ93HJfXutjOtx9ykvuNl83X2/7Us"
        "FCgAJmSp7IBiUDyZNsXyY1nquOzYhDKVPQoxwJKXsde03/IgezWQojqAc1JPct8jAHRohx4keZMEiBaOco8+QaBQsWxEzM0z6kFAoOOm"
        "WRADxd0B5Oy95Js32LvVNDcg1d1xeBGdzPcY8z3ZuCIXRnGTU0qRMJu2QormUFjIVGiEQV1YpjCjsNR8QGrXDDdbM0IHDb1/xlw7bivG"
        "Lt/0QrYXHlBV479SUjAhGg/LKBc+IVoJ5ypCMihDRjH1oQUB0UUV7YaEoQc1tnaKWq1qa4taozajavdy5j2979Yd2oj6sRiFDVEJJi3K"
        "eHFGHjINyahddDMkAtm4s9i0FtJgjB67SjImoG81yobwh37+7bOpmqMzTloSyghlYpAHJMyhH6SoHw/lLrfcaHS2SKl2zJlTpWF0037b"
        "B7o+fcu8OSdfWu4U9NLKYXCsReRhGFdQp2JwUUXMCm7bDoso0S/wadYNARStcNlLuuC/+ur5OX+47HueRBVKAaihHJogcgL2FkaES0IB"
        "HXqp8K0Bp8SIraPuWqxNiR/YjfrRYp9W+HurvAOmC7muEjzuKsHjrpaWcqfkBcbzr+Rs7rUbEclyp5rbwG4kGzvTveuf6ioDtWr7w5cX"
        "zml7OmNZGWS9YFT0ntDj870zcOR8X8eD/qfej4w48B//+nrQ1/yFMLhTdzUtrs17PvHcvrzKN/U6KYqJSfE384Y9dhm2pJOPzq8OniHX"
        "y74jGM6MksdmlDw2Y6jnzIwZPNt62mw29dEhIgkrZeriFlPd3e+yy4N2m/lshbJssmbK61iKP5HZVJK+0++/YrZ1rraZrtzpLcbXClB8"
        "yXtqv0+xOG6au15F3+TMqHhsRsVjM2UNnJmP5zzb/ofa7CYeJJJ4Um6+3+JmIJj7ueR8e4eroXL19OtkZKN2YcpRe390xPJlVLP38YCv"
        "9NFLxvJHpg3pRc+O+Uc2Xl11rhdRnBk1j82oeWzmMQdn5trhbTeziUz6vjiRdJMkg7K2krnQPtzzNtsEIz9Fn+k6jhat1Ik6m6nEH3Cd"
        "HbZr+wMFlUzVKxNHxNFjQebpldP3v1Ia1w/t/xsSrgJ8"
    ),
    "v.m2ts": (
        "eNrV1m9ME2ccB/Dfc9frH3Kld6VUto7SSi1q0FwBY3FuXNuN1ugE/wTRGCw1nVTDdGQBnVs9ibJKZsTCJkYyz2RmxESDCopR42liQiSS"
        "Rs2i819V5nAx2Tk3g67xdpC92Nu9ms/vzfPL87z55MnzffLLvlA5NcizDPjlaYAuAihIAZQRLCEz0lZWNm6KrjMsizY1x9ZGOU/LF4Er"
        "yptVZPHsUJAHBqDPOOkH9ADGXtZ9qeBRc/dbG4M+1U/02Sf9MivTlCb0wUc1CY1JyWQIdQNqu9b2v5n+Yup1Z7Ca5XTVAFvp+MT9pwEE"
        "KcsDBvtxFnQ369WtkwiYHEVJ69V+wNIOCFxqNwh64NUVwKSMT5zsUZ77BLVBOc974RO0yRH3OuJ5JJMPPaQ/TPMcDGpGOd0QSmnFeU7t"
        "IVfKyARQig4spKucXXWhbGlR2c5XciTrEfPdgR9bIa8VcnN85K88DX4kkCkjHyH7dKOpfEYywhzk1fNHHE2PzwQZlt3CF02HTNkOVBvb"
        "rIuFLKEGi9MSQL7oQ+u4J3nvseBFCULmiQ4+I2oeiK2kaJL8HUa+QKiDTHceGZ7pfyI5CdFDnONEPwj3ao0d5Ds/Pz1/orJ+ICwYpGzJ"
        "SoAdOBhCt2iUIKX8hw3XasMNNP8ZEbZVOEVXf+eCH1xtnobhgM1Bl4epnYK5C2qepE0p6GX4T2XYl8MOUo8WrNbxujE4O+UaBUWjlvsj"
        "91V/yRb4v16Aw/ZHpGrGUjTPTIEFymEVpNfDbHdae0dLCdJG9ze7wgYv8QJtX0w0mcmF01EC3W4r1P4eM7VAv9uw6DSl5pfFNb/vnTk4"
        "U80vi2t+S9xfVav5LS1Vf9Cvxfh/ekX/znoUsROBn0zzCuWviRQPbC/4J87m7sWWqqkHbm4t3LFZnpLNLaN6dN9r48nkwV1rtrW1vN25"
        "/HD62xry7uur7cm6y9pDb7nOaZ4V2jdkPp5rn7/X46KRrOf0I8NlM6qMxB2XqWf4l/Zm7sWcG6zo7tzYHCxQGAXTssGKHpz9psaKSzj7"
        "yZ+KxnD2e4OMEWd/8cnxUpz9Tkd6Jc7+3N1D23D2G171HcbZ//667is4+0tuCDLO/iJfzIr1/HBsyXyc/YytPIKzX5NwJrCeH/40HMXZ"
        "P6v+2XWs54eRWy9x9lvfvVSAsz+r98iHOPsrcpPrcfaXtn7egfX88FvkFM7+vwFwiWXq"
    ),
    "v.rm": (
        "eNrTC/J1Y2BgEGKAAdaAIP8AIG0E4vgpQLAAiPMdiJmA+AQDApxiYGRgdvb3C0Exg8HXJSAISJVAeBimwMAJgZCMVIWwzJTUfIXgkqLU"
        "xFyRMhBHv0K3IE8XyM8Bc4EqlUA4zNPFPyjM0ABokAADF9gECMkBMtnFMcQR6EBtsAgTxALG3VCbmBobHVc4rmBoBorxxzUcqGxIMJB2"
        "OJDBzHhDlcWAR57FIIG5sYGf4aKOBKM8C0OCzSGBKfHvOxMOsFcoNCQo9F+dXteZevRjhEIzg5wtR/zepqCF2g8qaux//L2YcECAmcEi"
        "jofNwoBZQY6D4UBFQ4azkGPDe/kWRhUJgQcJNgdsBFzmX3WQWiEhH/jDgY39wd4YDvOHzI8/8HAwP2jjEdD4s4+h5I8Qe+vj8zufCLA/"
        "OFDWzGDGw7bBQObUwUYpNuYTCn+YHRs+sDHvkeB7+LFAkVMp9IeBXSKPBL8B/+JHDxKa3B/USAjUMzM+fav/Rfa8a/JRh3qZVzyMM9ia"
        "GTR4GB0MmBQaeNgb/kjwbUhgPjLBbqlnYYUjh4MER7STfHvqf6HjjzQcA+9XlK2W/nn8Q8MSCcb8ZsY9KyT4eP+yMR9iZrDi4fjXzHqX"
        "Zb0XD3vEF/6ABh7+/Y0NIq3fH0jwyF8wUHQ48Kc2vLH5zyJXdhbeP95TdkgwBiRYH2x4ycbg6t/YICDfzKTrYBnBrsnKtYL9YIPmDwPp"
        "G4xdW5idxNufPj1wIK+Z+fGiwPKWXSrNjM/fr2RjP8144BcwynzAEZfCwNDI6GDpYMl4CBh1jO7Nj5gfvVoaNFsk1GLhbMurn7eZHDq2"
        "/+OlnS9Dfm3/oex2aWuz6RWjiBaZ908Vip7fZFP+skIJltoAL+jf4A=="
    ),
    "a.mp3": (
        "eNrzdDFmYQAB5xDPECMgzcbAwBycn5fOEBLgagjlOyXmpTCEBAe7Avn8QL5PYlmamYGeoZmeoYEBAwL8f2xxAM7xzEvLh6hnYGdgYLrA"
        "kIYCGlDATBSwGRWcQQHPUMB/FACyF+i4ZKDjjA2RHMagwqIAYTBduH32zHIG0sD/xxJHGLg+sF3d6cjA9N+94HYCG3/zg99XOJjYFX7Y"
        "1Qs3P/il0HjE8UPtD4XX+w/LsP1V7Iv989x/91K1dovII+Z/Ul1UZRZy1zeDzOEXmOk0gXFKAEM++yv2nQyShUIF/J0Nz9wjZF8lvm/I"
        "YHLQ0uZYsOv/J8EXq1zs5KXy///kYnYKmGD6v9Ov2QvmT6A57HwZy2wY7wEdBwQ/LilKMDcIebIe0DiwRrxH/uCKQzJBPU4vC4798O0x"
        "O5hx4At/o0OcIoOBAddC1S1vL///90NoaYACyBwO3hXLdBjC9iRodoqkX5BWV59+sYPh9pzyF5XLH6yckdX0sSmAewrDJxbHBQwNIfs2"
        "Ai27/9T+//+o8/Z/DA7zGJ//2iZzFWQOD3/AvgzGGAEGz9q9ia0Vdy5ruJquY+GRmFBRfurlDt9nuhzNjV+uxWz/Zz6v8vncHrb2Bw/P"
        "JrRrvJN4qqXiaXjAWzUozhZkDiffjVczGKdEMPQc+KCTbeRZJ7FA9wNvdoNEXJCRr7xkW0Nfno/64mD7/+9NzCvUVPI/7FBT4e76/+jQ"
        "o0VXfRx9XY2BaRLsL2A69WAEJkeDULIBAKx2P3Q="
    ),
    "a.flac": (
        "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"
        "ACvJ6c/uRHVNO/b+3kzjh1/+J43iTWY="
    ),
    "a.opus": (
        "eNrzT08PZmBigALX9S4fQfTi8+//MQr7F5QWe6QmpjAyWjA6yIMV+IOUMyArZwTSzC25sxgTQMpDEtOLeYEiPollaWYGeoZmeoYGBsxA"
        "AVkgTs1Lzk9JLbIFSiYDJY0NgZJGCjmZSflAnfxABSWZJTmptiBzFILz89K5gUKJRSWZxSW2Tol5KWC7WSosEXaD3O0g+2u2AK84v7Cg"
        "oDC/ABDw8QvycTSfUnl8SCHDRG6V7wuO5VKxXTP04qNOBWpftfupeX3FRoGl2g0cC/UFnsT+vsN263fSjItrOBZaXCg3WhW286BD4zOT"
        "fDM52UtQobigiUeP62VyMx/gWOjB7HY1qPhWy7TeP2p61ReAKs79YXOz8Pet+sTfcdxzRaoMTJPvOuk4tiMnYMbOfN8ra+wmPQUmHej8"
        "3jrmzrpqMF/fvTKj2fznysN74c5wYzXwl/z+aw3cleeZOIyucCz0OWD7unAj39WIEMZlE2GG9V9xChR91FUmwdH8Y0nrwtPHHir3mm5v"
        "AAAbX6k/"
    ),
    "a.m4a": (
        "eNpjYGCQSSupLPA1cVRgYGBiANGZxfm5QGzEwMDAkVaUmgoU35+bklhyj4nBJ7Es2cxAz9hQz9DAiIHJYmnQZbd3m7/1bz8ytVxXSMVj"
        "okpz1q2ytcuBxDrjrYVzV2fOm7vR78Ya67DLIF7P00i/0C1Po327hfuOPI30cGjhcGjxdPMyWnFqqVHYlOsx69a9PcN7YylTgAEQGG4u"
        "Oq2z6bTmztRpkalT7mwCceiH9jAyzLlpK+qyS9Jlt3jKvtp99f/0//yP2/E4aqf8l7/2f+w//6l8fPZVbPpfe/tf9Z+/XpeJD11p/+XP"
        "/5f/779eW3hsuud0N40PRi+OzCl6cVROKi3HMOayz87pxmdNTqb1Touf8LdC7yBzy2LOa8WLVvUkB2S8WGTFe8Gqle2FeciXwIigbTnd"
        "1WlnW8ov6Qlu8e5+M++QtVlO159OGdHpRufKlM9bnivVDFzpNa/y+bxSv5VXrZbPq7yiHjTV5vP5TaXSL+67iuy3mr5Wo8zy49Yb5kfe"
        "yTfNedU+e1apv73Jn/uqfi4tsvK6XTKMfHM37BVN2Sucsm9RvOWf/z/qn//4vG59p9r+L9///9j/+W/V47VZ0b//f3x8//Xt8KN3T+9/"
        "v+t61LV1T7YYvTgoV/R+8Tz3008/3dysee63r07Hwja9PMNiPiWln/xTYpKehQup1OyL159+uu/wUduYQMH8lS+udi73ehGw6tBX6+UH"
        "d2xfs2b+8S4VRSHdbCWNRV0g1KUEpDo2HRVx6QAJ1CmxKKmIuge+6lqxiKNFq8o06kFI45bjUWG5apdyDe/KXgSj29/e395fd2FW8ezi"
        "mZ+sJ97pe1L6PR6I7k4vi73DKNG4pYCBgdk9Nz+/DJicc3LLMlIYUADzCwYGRh0GRgYQQgBGVFXofAcGvIAJiExLihKzgeyYkmywncyY"
        "pgHtRRJjJN1eldSUkmIgLZOaU1yC0AEylwWql3FtbkpmIpChkJuC7nd5oHG8CaFHwBzdjJScIphMcX5pHrLKYCA/xSMxLyUnFaSGMSI3"
        "My8NyBAozkUxVCUFIi6TUpSahuQFntKiHAWo42SKS5JygOys4pLiFCQ1UbkFJokY3mZkEIA5FQjMUotTisHR1tDQoAqUZAHS4g6iYEmj"
        "fSDMChRhFe0Ie8rABmQxMoG8XlwCDiZo1ICiggUWVAkg1wJdkoxkMwizQGkVoFwVkg9B4u+B+CEQPwJiViAWKS5JzkfSD4pWqeL0ghQQ"
        "pyg/JwdqL+P//2DbktILGBAyyLbNK00pAYXBtNzUElhYKCJHDDAyixILCnKQIyczExL7CivzEnOBtASwrE6EBaKvSaJCcH5eOsjilY5B"
        "ISDnIss7ASMVSKmuLMkHeUEWWQ5Y2qcBS3tDM2BpbwAA4UfiQg=="
    ),
    "a.wma": (
        "eNozUNtU2pd2XnDZTYZVDEnnctKYGMCADYgZmRbeWd3jvvK8YN8ThgM8CsGpGQzYgQQ/lNFgd/XexrmMjDDuGTaweQeO6YL5MjwQcZBg"
        "Aw8EM9QyMGxl3h+vB7LnMcQePah+wUuXV+8CiT+DiLOBRY3R3GwFVc3DADWeIZwhmCGfIY8hHcx2YkgEslOAbIclFy6xP74kOP0Dw4KT"
        "cSsCFkHVMwN1ljBkAnEOQyrULGQz+IAmlAJlM4AiRXB5hLkaQJ4vgz6DK5CfDFSTAjQLpDMYaFoJ2GQQrxgSBgw+QH1lDGkMZgwGDHoM"
        "hkAaRBoAIQPDRPY727cj+bgI6kKHeZk/fKPPC674y9AQH+OiHXD28P7+xPOC3ZuAYbDlkQIsJmSAmAMUd2BeIjAmHOQZGBaA4odRgIEL"
        "LMoIJYEQyHQIutgma3hBcPESYJgwe3xLgZrkiCbOCI43caBPM8G+zmcoB/pIAejvVLB/E4FsR2Aogdj5QHYYgwU0rhMZzdBibBMP9nQE"
        "SzeMjE3AyI+VZYfwWiEJigMkD05CjLv+OzCwBU9JlfQLnlIX6f8cRvgx/9kg/rzhv77pz597WCNu8O0oEC2o3PN9Tbp3mH1LduMRn+/n"
        "p7P0zZ/jeup2cxrn9s8/P9gfvXY4ePn5B6oGbFueV3BdYTg/+UAqA3/D/QPyjF4MdkxhDDYskxisausn1ndvfjDH+Wnuh+blb75vs9u4"
        "wbPh832Ndfz3Z29P0K5/fnSK7lPt+OXfvl97/u37nZCPF4963eX2jHa6FL/wEwRliki5sk10XBKQKSLSggxDV4YtjZqaRCxIfMDIBA+Q"
        "GHCAHAEGCPvqI1cifgQcND9Qx3yaIT791AtuiRkVfiMCMDLDA2QOOED2AgOE6ayPkEBQ+5V//+PPpx/8wW/A+EH+A/MDrQXMP38n/1h7"
        "Zb8Tl4Oa6oPhGSAs8AC5gxwgTAGa3q+MZtdm9qzuZ3zFYMf8kMGGNYrBom2bfd9d5y8LVBqS4oZngLAiyhBeUIAcBgUIy1JNRQ6HVVNm"
        "uHKwmixpCXTS2l/v637avyns7f+t2+9lbdzg8VLikUgN+zkGu8/96Sd+apf9v/3R+fkVlsteHk4CqpoGDJk6DJ6qDSZzWUOGVl5jGAWj"
        "YBSMglEwCkYBKgAA5UVYaQ=="
    ),
    "a.wv": (
        "eNrVlX000wsYx0fJW5zSTRTR8f7SzqZS6S7hNnnLS8QsMiPzlhLmpVlJdQvRIm9XaJG8bKaQMKVoWG2Rl+ZlpxqzFjuXrZ1Z9rtuuffk"
        "nG5/3HP/uc8/z1/POZ/zPc/3+8UmnIpMVQSB1q0GgYKUQV/mz62g1Qb6QB53l5fzPbpKLiF2tXyOaEGosEpVBaT0ROFq5SoQAMgiZwA2"
        "uxHAAxVigF1q0v5xQhKhkFXxPjH9otVbCkGcH4f0nsuJQdPWBb/I5vV5F0KNw+l3R7xf8W411ecSn9EyVIKYGsRuYBjT7zlf7TSiGG54"
        "qec4nH/bJ/5xop68BUapYHjK0yUl/MTegR07MJvKuQvY/W9304QldK6XvpcM/6Cj+GI3oV/3Wb0+56MbsZFXlcTZqYbIVY3vHpLYYMPv"
        "7Wyu36Ny0YgyOz9eHDvGTCZlmh+uqFqUsVlx3h7JJCv1jLRaCQxg6qognYfPn4em7wM4pSUOl+fGwQ1RWijup15jkSH5EfEKiqLU+inz"
        "WJ8nev2mSzvccjofDpFtCUKzkCTbiW4CKshfGldqsssk/1YfrOHgGo5g8Z61TJPskL9EFsyRiRORp1/Twt3UVSvr0ZFdRdcI8BKcrWXm"
        "7dssMbdjeG7LG3U9ZVMd1HT7fEAkzwmTpNdjrm0/LTGhRpWoedlfd+yqShvo4DPo4w4S8GU/zcx6fgr8SCrB98VgVYNWOmL0iIsk+s4p"
        "dnaYQVBeC3c/UNh02I6XdDb7AuFc0uI8rr3OvEUUAM5BWOkLolMeUJoTRQFW6DcQ6NRzzRiba5vj65h2Tz0SUgZLWzqN+iSHMs73eHvz"
        "gbPNjUJ4EzUbrqILHSJKI80alY0EGrUE/fRb+/BAOExuJu5hdhdFXrjIqjHryOr3VW+w1EINizMrPxuSi4ieoVCl+02O4Mnm6504cti2"
        "P9Fm8ZV1RzySA9nvywyDAoGz7GYfo2ZqzQU6QS4pZpSY1d5VI+gtCH36rEAP2cbbE/F61xX1zZcaRmtk9I1gxEtH/zXGRzzrgNRlMtcv"
        "ZCKuV8QG54mN35LFLpPNDuay4TwLRcQ3ooV7I9Z21s5c/yoa4/66+t6xM2LbgSEzUxjwt2jso3ljCyR1K5c1nPbobOtPmmSqBfqm2gZ0"
        "atTvle+rPIcNbTBavSfJCzt8H4bs1eNBIYVXIxbFrXUVuxtEuBCv6V8pW+ts872KPeZIQXmrtwnHJFJ3vjIm/ynO8trGMgGWXPnZ2vn4"
        "3hAEpJMk0HaTOAXuurtCM1uG/WPzM4xxwBV5t0z4eR6m7iw/JWKIcUifWH6rDc1SO0fcBGONINsWSJkIa9dMCaWr+BoRHnBjugxl2tr+"
        "gXHsLWHy7J3nj0PMq0VsQdPNCdqQ+LpTuUF38gPZMedo+57WNB+NdOYZrsC2zqQsQF1M2XP0HJXdXjQ3aoqbzAl9otRKDds5aZI0+Bs8"
        "r0ufztrasiSninjxZ1W5GjpMvBjGslGo4Ir+LVlokNXGwQUBFukSE8KX0u4w16Nh/nhwhXU5J+CJubL9dMu8uHRoAxN8WeqnY3GA3bFM"
        "pt+Xtj4Bx8D0us9V793so3kBEpnC8UrdYjYmTtaUP1qYMitlPIhXcWbwU3RyV9P5pQJpUzVnCBu/wgLa96MKtObRGbt1HbMeGb9aYYG+"
        "FZqZ3LB3zBRhFltyWekErEKNoVI59yUb7+9+oFVnFn26FoQDPkX0xhCFeRcsVeEjIhjRzLanZgrzg0cjC057aEDIeKpgtJqAZA/aneg5"
        "19Y886p74t0gNpTegAqmZ2+fiNPZ9aHoF0U1hzczPvgplXxLrsH2VTfuVQ3hO0b9kw2Q7NIfWGDs+Ts/uQXZzHcs8Oprbhjkz40eekst"
        "/U/NKT0ZycuKwukV/mQTXOvIZ1S8Ns5ts/AzslOCYWWygWR51uQpvQy0wrR0/DuxMfC/JJNJtioayc0vcKXUL1mrG3JzLS1ldGv0x+2B"
        "ON9uyy3G3Z9H3rk99ySSnOKYkNzxQFEY6VRP7P5+dJCVncdBbzvHg37MpSaGLTWw3NciLgMtj9ryDj2JjgkJjQW5ohJOWEPAUGswFAL5"
        "h+Nzfx3/AZf6Fjg="
    ),
    "img.avif": (
        "eNpjYGBQSCupLEgsy0xjAAIQnZuZZpibmZjm62joCBT6mZtaksgAAfoZKTlFUDZDQWZyCQMSCADyS4tSPRLzUnJSwar4CjJLcsFyjEAs"
        "l5mTnwziuID4jBBRRkUg5gCyNTIz89LgaqWAnFQmKC+xzMDQOT8nH2xmVmZBUQGQ9s4sSM4H0iKZxQWpUBcIwHBBZkUmSICZgwNkNk9i"
        "maFzowJYjXByfk5RXnJOBQMTEDI0AIXEMwtyYT4EOoyFkamZBcgSyE1JLOHisOD5f9vB2YHD6DejBNDoQ6z878IYHruodETsjEricHy7"
        "fVJB0p7VN3u/85zqm6yzZM+/4nuRayd/sv7o4eCWMHmxd1gci+b/3K19m6x9TSqqbvs+/f9vVVrAkfpDFisvKodV3nUOCvMKnHKAfxmT"
        "YcKq85ZrcspX8GbFrdrQ0X9w+TJJ3jDVTazH37eceXDBZa7R28Mv+HP5fopNfz6F2XZh8PW/1tH/lk1uXZmwo27Vv6ib88wKAjlDuRcz"
        "mck+nRK6c6EyV9NOpX3/6iacPrzRgNNmk2EyzxFuh9Yfm4TCLq+aKbb5YaripwVWrlJrivb9zPe8HPoiIEDG+miR/fV0440ND6NqQ/4t"
        "t9RZvfiFz0sZAPE4sOc="
    ),
    "img.jpg": (
        "eNr7f+P/AwYBLzdPNwZGRgYI+H+bwZmBi52dg52Ni4ODg5uLi5tPQoCPl5dPVlRMUEJZXlVFSV5JUU3bXF9N00RTUcnA0dDE0trOzk5V"
        "z8XT2cbD3NbOGmQIIxc3Nx8vn4yAgIy1hpKGNcng/wEGQQ4GAQYJZkYlBiZBRmZBxv9HGMSBToU7FgKYWNiAEooCDAxsTIysSBKMTCyC"
        "QszCIkrKjoGFQCViGFrZWNiB4vKCDIzMLMxIUiABJlYhYUVDR9H/txh4gHJMgsyCDPYMj+VsHgVvr/af0SF08T+DtubiUEVjswl1l5XX"
        "lphMTcupZzFMnrotVTfLceIyK5+/XUldF771vJY+/OvJdBnBSxdUJr38arjkpe5jBolP/NkFDEydRv9vAgDYPFU6"
    ),
    "img_prog.jpg": (
        "eNr7f+P/AwYBLzdPNwZGRgYI+H+bwZmBi52dg52Ni4ODg5uLi5tPQoCPl5dPVlRMUEJZXlVFSV5JUU3bXF9N00RTUcnA0dDE0trOzk5V"
        "z8XT2cbD3NbOGmQIIxc3Nx8vn4yAgIy1hpKGNcng/yEGQQ4GAQYJZkYlBiZBRmZBxv9HGMSBToU7FgIYmVmBEmIY4qzMbP9vMfAwMzIw"
        "CTALANU9OrKsuSCoHmSKALpqJgZGIaBqDqAoIytT/ox929JD2ObuB6qVEgSKoKplZBEQFDECK2dmZLRnVCpdNbmDoFImkFLBzEnXd4Bd"
        "wMCM6lwGAUNGqAvY7JlaIv4zAJVJCzAwMaEoZFRkEBA0DHSEOdZe0T3n6Ind3hGx7SoT12vDfMzADDLxBT/QDElBBlQjGBgFBRQNHeHu"
        "F7igYyHkeKtaHqKYGawXSbGiAFQxyAcCdpW2upsWRx0HKpYBuY6JGUUxg6JAoaFjINx5AjfXXQp8Lzt3Y0Xr7CxhE5GN3+X/3wQAM3F2"
        "1g=="
    ),
    "img.webp": (
        "eNoBpABb/1JJRkacAAAAV0VCUFZQOCCQAAAAUAUAnQEqGAAQAD6ROJdHpaMiITAIALASCWwArByJdoA/kF1Af0D0AN5e6TkDW/w8XooA"
        "AP7oud7WvNGmvs0+fTH/+SeYce/9OzHOFyRlQPxQZ858luP+RgedaOb2K9JUfqmv/0rnh8i9oTfi//aq+JzW4rIHNaNT/8j4WX+7GnB1"
        "D1xD2df4s1gplK6IkAAAZGxK1A=="
    ),
    "img.psd": (
        "eNqzcAoIZmBkgAAWIBYAYgkgycwABzwRQBzw/z9CBKoKpJ6BmQmkH0gygUiQKmYmCydP37z8otz/EKN5YNqYfAyB5P9hAhgwwKj6wax+"
        "8KabUTAKRsFQBKTm7lH1A6t+MKecUTAKRg4YXrlgtO092hcY7QuMglEw2g8YbXeP9gNGewGjYBQQBgBaNf9Z"
    ),
    "img.jp2": (
        "eNpjYGDgyQpQUODlaudiYGAQSSupLMgqMFIAshmgtD+QzgDSYpkZKUVAWgCIJRhY+NlBahj4k/NzihjBTJCEUnJKahoDC5jPyAASZwJC"
        "BgZmIASrYtoONC75v///QAYjsCoJqE4YQOWz8DMywtH/IAYesLksLCwMjP9jGAQcGjo6JsDR/xQGVQZG56LUxJLUFIWkSgX/gtQ8rwBX"
        "d4Wy1KLizPw8BSM9Uz2D/xMYuMBOMQAaMvn4Px4uxrmTP9Tf/zFBgNMexOUIXf6u/vwfAw7Gzef/ePDVP3LY/J+HsYHt223OUEFRXdar"
        "8Q3I4ixu25nm/BXVYFaNbjj+T0Ja/kdCifwPgwQePuPYywtkw6dpvq9N430yryFH4t87L9WXTf/rOe9bLl2xNsexRUnRHKYnB6gnglsr"
        "bvdyB6v1Ol53lzXzbDNluGF6TG/HwSVnpzP8uK9cEbZlnqJPN8j2uP/JrIL/XdodOF/fuHeYp6ttnROvkFnT4UrNyhnanqvz5X5/CbIV"
        "+raf5e7pyM0Jy1/mvMpfUH8uskM8Oyp+mrV3nVicwIkJTzQKGb6pn+KzjQxr0ZqXbiA2YWWb6dcd558ccu1X/FAnD7KoD2hR4X+XVgd2"
        "6wtwi+bsD3r88vpJFRvj5RvON29/8PaHdR3f/Wb5rSu7TixjLu26u3y2c2Rd8ZXQ+zfD5jT+Vd4afPaw+rbyW6qnj+ysmK4v9PQ+8zJ9"
        "oL3BzzaEzV374FZC3LXb2v/rQfb51T9yCvif2KggeSYqhjmtoOWHqfw8a4vJ/+v/1yvcldAXKGFf847Xd5uBAkhE9OtaPpu5O4FagaHo"
        "Kv8jUcT+w4EJEnkF4VLv9NRDg0Pz3EK4py2TYtu64Gr/Ww95/aP3GnwMmk5JCxw9r9MuET69wunFwSgNQemLfxpTnlVvq86+xPYof4p/"
        "eqzYwvVQk//fBABpMTR+"
    ),
    "img.j2k": (
        "eNr77/8/kMGIAQQkgFiAAQFQ+Sz8jIxw9D+IgQcoxsjAwsLCwPg/hkHAoaGjYwIc/U9hUGVgdC5KTSxJTVFIqlTwL0jN8wpwdVcoSy0q"
        "zszPUzDSM9Uz+D+BgQtkNpMB0JDJx//xcDHOnfyh/v6PCQKc9iAuR+jyd/Xn/xhwMG4+/8eDr/6Rw+b/PIwNbN9uc4YKiuqyXo1vQBZn"
        "cdvONOevqAazanTD8X8S0vI/Ekrkfxgk8PAZx15eIBs+TfN9bRrvk3kNORL/3nmpvmz6X89533LpirU5ji1KiuYwPTlAPRHcWnG7lztY"
        "rdfxurusmWebKcMN02N6Ow4uOTud4cd95YqwLfMUfbpBtsf9T2YV/O/S7sD5+sa9wzxdbeuceIXMmg5XalbO0PZcnS/3+0uQrdC3/Sx3"
        "T0duTlj+MudV/oL6c5Ed4tlR8dOsvevE4gROTHiiUcjwTf0Un21kWIvWvHQDsQkr20y/7jj/5JBrv+KHOnmQRX1Aiwr/u7Q6sFtfgFs0"
        "Z3/Q45fXT6rYGC/fcL55+4O3P6zr+O43y29d2XViGXNp193ls50j64qvhN6/GTan8a/y1uCzh9W3ld9SPX1kZ8V0faGn95mX6QPtDX62"
        "IWzu2ge3EuKu3db+Xw+yz6/+kVPA/8RGBckzUTHMaQUtP0zl51lbTP5f/79e4a6EvkAJ+5p3vL7bDBRAIqJf1/LZzN0J1AoMRVf5H4ki"
        "9h8OTJDIKwiXeqenHhocmucWwj1tmRTb1gVX+996yOsfvdfgY9B0Slrg6Hmddonw6RVOLw5GaQhKX/zTmPKselt19iW2R/lT/NNjxRau"
        "h5r8/yYAFa0lIg=="
    ),
    "img_big.tif": (
        "eNrz9NRm4GBgYBDgYQCD//8h5Cg9So/SmDS1TBt1/6j7R90/6v5R94+6f5QepQcLLcAABYzMDIxQpgRMCEkMpo4JKMYCF4NAZiR1MJoN"
        "SYwJSnNhUSfIKIBhhxAWdaJIYjD7xbC4TxzJPAZoH0cGi3maQDGYu2CidoyscLEJvBDaHijGBhVLgIoFYfEbDLS+DgSSDQyHv64AS589"
        "4wO2AEI3MED5TP2HvoKdbS61AMzXbucCUgoMALvvDfg="
    ),
}
