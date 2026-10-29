"""Previews of videos found by a scan: what the video is (length, picture size, codecs) and a picture from it.

The details come from the file's own structure: an MP4/MOV's movie box (read wherever it is, often at the
end), an AVI's main header. The picture is the first key frame:

* Motion JPEG frames are JPEG pictures already: shown as they are, no decoder needed.
* H.264 and H.265 frames in MP4/MOV are turned into a tiny raw stream (the codec configuration's parameter
  sets, then the frame with start codes instead of length prefixes) and decoded by ffmpeg when it is
  installed. That works however big the file is and wherever its index lies.
* Other formats (Matroska, AVI, MPEG, transport streams, Windows Media, Flash video) start with what a
  decoder needs: their first megabytes go to ffmpeg.

The data comes from a disk the user is recovering — untrusted. ffmpeg therefore never runs as root: it gets
the bytes on a pipe (no file access needed), runs as the desktop user (or nobody), with memory and time
limits, and its output is only accepted when it is a JPEG picture.
"""

from __future__ import annotations

import os
import struct
import subprocess

from .blockio import BytesSource, ConcatSource, Source
from .util import caller_ids, which

VIDEO_EXTS = {"mp4", "mov", "m4v", "3gp", "3g2", "f4v", "qt", "mkv", "webm", "avi", "wmv", "asf", "flv", "ts", "mts",
              "m2ts", "mpg", "mpeg", "vob", "mod", "tod", "mxf", "rm", "rmvb", "ogv", "divx", "dv", "m2v", "lrv"}
BMFF_EXTS = {"mp4", "mov", "m4v", "3gp", "3g2", "f4v", "qt", "lrv"}
MOOV_LIMIT = 64 * 1024 * 1024        # a bigger movie box is damage, not an index
HEAD_FOR_FFMPEG = 12 * 1024 * 1024   # what streamable formats get handed to ffmpeg
FRAME_LIMIT = 24 * 1024 * 1024       # a key frame bigger than this isn't decoded for a preview

VIDEO_NAMES = {"avc1": "H.264", "avc3": "H.264", "hvc1": "H.265 (HEVC)", "hev1": "H.265 (HEVC)", "dvh1": "Dolby Vision",
               "dvhe": "Dolby Vision", "mp4v": "MPEG-4", "jpeg": "Motion JPEG", "mjpa": "Motion JPEG",
               "mjpb": "Motion JPEG", "apch": "ProRes 422 HQ", "apcn": "ProRes 422", "apcs": "ProRes 422 LT",
               "apco": "ProRes 422 Proxy", "ap4h": "ProRes 4444", "ap4x": "ProRes 4444 XQ", "av01": "AV1",
               "vp09": "VP9", "vp08": "VP8", "s263": "H.263", "h263": "H.263", "mp2v": "MPEG-2", "xdvc": "XDCAM",
               "dvc ": "DV", "dvcp": "DV", "cvid": "Cinepak", "SVQ3": "Sorenson 3"}
AUDIO_NAMES = {"mp4a": "AAC", "sowt": "PCM", "twos": "PCM", "lpcm": "PCM", "in24": "PCM 24-bit", "in32": "PCM 32-bit",
               "fl32": "PCM float", "raw ": "PCM 8-bit", "ulaw": "µ-law", "alaw": "A-law", "ipcm": "PCM",
               "samr": "AMR", "sawb": "AMR-WB", "ac-3": "AC-3", "ec-3": "E-AC-3", "Opus": "Opus", "fLaC": "FLAC",
               "alac": "Apple Lossless", ".mp3": "MP3", "mp3 ": "MP3"}


class _Zeros(Source):
    """A sparse hole: reads as zeros."""

    def __init__(self, size: int):
        super().__init__()
        self.size = size

    def _read(self, offset: int, length: int) -> bytes:
        return bytes(length)


def entry_source(src: Source, entry: dict) -> Source | None:
    """A source over a found file's content (its runs on SRC, holes as zeros, or its inline data); None
    for content that needs a decoder (NTFS-compressed files and the like)."""
    if (entry.get("extra") or {}).get("decoder"):
        return None
    size = int(entry.get("size") or 0)
    data = entry.get("data")
    if data is not None:
        return BytesSource(bytes(data[:size]) if size else bytes(data))
    parts = []
    left = size
    for off, n in entry.get("runs") or []:
        if left <= 0:
            break
        n = min(int(n), left)
        parts.append((_Zeros(n), 0, n) if off < 0 else (src, int(off), n))
        left -= n
    if left > 0:
        parts.append((_Zeros(left), 0, left))
    return ConcatSource(parts, "entry") if parts else None


# ---------------------------------------------------------------------- MP4 / MOV
def _top_boxes(vs: Source, limit: int = 4096) -> list[tuple[bytes, int, int, int]]:
    """(type, start, header length, size) of the top-level boxes, read header by header."""
    out = []
    pos = 0
    while pos + 8 <= vs.size and len(out) < limit:
        h = vs.read(pos, 16)
        size = struct.unpack_from(">I", h, 0)[0]
        btype = h[4:8]
        if not all(32 <= c < 127 or c == 0xA9 for c in btype):
            break
        header = 8
        if size == 1:
            size, header = struct.unpack_from(">Q", h, 8)[0], 16
        elif size == 0:
            size = vs.size - pos
        if size < header:
            break
        out.append((btype, pos, header, size))
        pos += size
    return out


def bmff_info(vs: Source) -> dict:
    """Details of an MP4/MOV: {"duration", "width", "height", "video", "audio", "fps", "channels",
    "sample_rate", "needs_index", "poster": (codec, config, offset, size)}; {} when it isn't one."""
    from .media import isobmff
    boxes = _top_boxes(vs)
    types = [b[0] for b in boxes]
    moov = next((b for b in boxes if b[0] == b"moov" and b[3] <= MOOV_LIMIT and b[1] + b[3] <= vs.size), None)
    if moov is None:
        if b"mdat" in types or (types[:1] == [b"ftyp"] and len(types) <= 3):
            return {"needs_index": True}
        return {}
    buf = vs.read(moov[1], moov[3])
    box = next(isobmff.iter_boxes(buf, 0, len(buf)), None)
    if box is None:
        return {}
    movie = isobmff.parse_moov(buf, box)
    out: dict = {}
    if movie.timescale and movie.duration:
        out["duration"] = round(movie.duration / movie.timescale, 2)
    if movie.fragmented:
        out["fragmented"] = True
    video = movie.track("vide")
    if video is not None:
        out["video"] = VIDEO_NAMES.get(video.codec, video.codec)
        if video.width and video.height:
            out["width"], out["height"] = video.width, video.height
        if video.timescale and video.duration and video.samples:
            out["fps"] = round(video.samples * video.timescale / video.duration, 2)
        if video.samples:
            keys = video.keyframes()
            first = min(keys) if keys else 0
            offsets = video.sample_offsets()
            cfg = video.config(b"avcC") or video.config(b"hvcC") or b""
            if first < len(offsets):
                out["poster"] = (video.codec, cfg, offsets[first], video.sizes[first])
    audio = movie.track("soun")
    if audio is not None:
        out["audio"] = AUDIO_NAMES.get(audio.codec, audio.codec)
        if audio.channels:
            out["channels"] = audio.channels
        if audio.sample_rate:
            out["sample_rate"] = audio.sample_rate
    return out


def _avcc_annexb(cfg: bytes) -> tuple[bytes, int] | None:
    """The parameter sets of an avcC box as an Annex B stream, and the NAL length size."""
    if len(cfg) < 7 or cfg[0] != 1:
        return None
    nls = (cfg[4] & 3) + 1
    out = bytearray()
    pos = 5
    for count_mask in (0x1F, 0xFF):
        if pos >= len(cfg):
            break
        count = cfg[pos] & count_mask
        pos += 1
        for _ in range(count):
            if pos + 2 > len(cfg):
                return None
            n = struct.unpack_from(">H", cfg, pos)[0]
            out += b"\x00\x00\x00\x01" + cfg[pos + 2:pos + 2 + n]
            pos += 2 + n
    return bytes(out), nls


def _hvcc_annexb(cfg: bytes) -> tuple[bytes, int] | None:
    if len(cfg) < 23:
        return None
    nls = (cfg[21] & 3) + 1
    out = bytearray()
    pos = 23
    for _ in range(cfg[22]):
        if pos + 3 > len(cfg):
            return None
        count = struct.unpack_from(">H", cfg, pos + 1)[0]
        pos += 3
        for _ in range(count):
            if pos + 2 > len(cfg):
                return None
            n = struct.unpack_from(">H", cfg, pos)[0]
            out += b"\x00\x00\x00\x01" + cfg[pos + 2:pos + 2 + n]
            pos += 2 + n
    return bytes(out), nls


def _sample_annexb(sample: bytes, nls: int) -> bytes:
    out = bytearray()
    pos = 0
    while pos + nls <= len(sample):
        n = int.from_bytes(sample[pos:pos + nls], "big")
        pos += nls
        if n <= 0 or pos + n > len(sample):
            break
        out += b"\x00\x00\x00\x01" + sample[pos:pos + n]
        pos += n
    return bytes(out)


def poster(vs: Source, info: dict) -> bytes | None:
    """A JPEG picture of the first key frame, or None."""
    p = info.get("poster")
    if p:
        codec, cfg, off, size = p
        if 0 < size <= FRAME_LIMIT and off + size <= vs.size:
            sample = vs.read(off, size)
            if codec in ("jpeg", "mjpa", "mjpb") and sample[:2] == b"\xff\xd8":
                return sample
            if codec in ("avc1", "avc3", "hvc1", "hev1", "dvh1", "dvhe"):
                ps = _avcc_annexb(cfg) if codec.startswith("avc") else _hvcc_annexb(cfg)
                if ps is not None:
                    stream = ps[0] + _sample_annexb(sample, ps[1])
                    return ffmpeg_frame(stream, "h264" if codec.startswith("avc") else "hevc")
        return None
    if info.get("streamable"):
        return ffmpeg_frame(vs.read(0, min(vs.size, HEAD_FOR_FFMPEG)), None)
    return None


# ---------------------------------------------------------------------- ffmpeg, safely
def ffmpeg_available() -> bool:
    return which("ffmpeg") is not None


def _unprivileged() -> dict:
    """subprocess arguments that run the child as the desktop user (or nobody) when we are root."""
    if os.geteuid() != 0:
        return {}
    ids = caller_ids() or (65534, 65534)
    return {"user": ids[0], "group": ids[1], "extra_groups": []}


def ffmpeg_frame(data: bytes, fmt: str | None, timeout: float = 15.0) -> bytes | None:
    """The first picture of DATA (a stream ffmpeg reads from a pipe; FMT forces the demuxer) as a JPEG
    at most 480 pixels wide, or None."""
    exe = which("ffmpeg")
    if exe is None or not data:
        return None
    cmd = [exe, "-hide_banner", "-loglevel", "error", "-threads", "1"]
    if fmt:
        cmd += ["-f", fmt]
    cmd += ["-i", "pipe:0", "-frames:v", "1", "-vf", "scale='min(480,iw)':-2", "-f", "image2pipe", "-c:v", "mjpeg",
            "-q:v", "4", "pipe:1"]
    limiter = which("prlimit")
    if limiter:
        cmd = [limiter, f"--as={2 * 1024 ** 3}", f"--cpu={int(timeout) + 5}", "--nofile=64", *cmd]
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"}
    try:
        proc = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout, env=env, cwd="/",
                              **_unprivileged())
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None
    out = proc.stdout
    if proc.returncode != 0 or out[:3] != b"\xff\xd8\xff" or len(out) > 4 * 1024 * 1024:
        return None
    return out


# ---------------------------------------------------------------------- AVI and the others
def _avi_info(vs: Source) -> dict:
    h = vs.read(0, 88)
    if len(h) < 88 or h[:4] != b"RIFF" or h[8:12] != b"AVI " or h[24:28] != b"avih":
        return {}
    usec, _maxbps, _pad, _flags, frames, _init, _streams, _buf, w, ht = struct.unpack_from("<10I", h, 32)
    out: dict = {"streamable": True}
    if w and ht:
        out["width"], out["height"] = w, ht
    if usec and frames:
        out["duration"] = round(frames * usec / 1e6, 2)
        out["fps"] = round(1e6 / usec, 2)
    return out


def video_details(src: Source, entry: dict) -> tuple[dict, Source | None]:
    """The details of a video entry and a source over its content."""
    vs = entry_source(src, entry)
    if vs is None:
        return {}, None
    ext = (entry.get("ext") or "").lower()
    head = vs.read(0, 12)
    try:
        if ext in BMFF_EXTS or head[4:8] in (b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip"):
            info = bmff_info(vs)
        elif head[:4] == b"RIFF":
            info = _avi_info(vs)
        else:
            info = {"streamable": True}
    except (struct.error, IndexError, ValueError):
        info = {}
    return info, vs


def describe(info: dict) -> list[tuple[str, str]]:
    """The details as (label, text) rows for the preview."""
    rows = []
    d = info.get("duration")
    if d:
        m, s = divmod(int(round(d)), 60)
        h, m = divmod(m, 60)
        rows.append(("Length", f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"))
    if info.get("width"):
        rows.append(("Picture", f"{info['width']} × {info['height']}"
                     + (f" · {info['fps']:g} fps" if info.get("fps") else "")))
    if info.get("video"):
        rows.append(("Video", str(info["video"])))
    if info.get("audio"):
        a = str(info["audio"])
        if info.get("channels"):
            a += {1: " mono", 2: " stereo"}.get(info["channels"], f" {info['channels']} channels")
        if info.get("sample_rate"):
            a += f" · {info['sample_rate'] / 1000:g} kHz"
        rows.append(("Sound", a))
    return rows
