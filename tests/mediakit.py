"""Real test media made with ffmpeg, and ffprobe/ffmpeg as the judge of what the repairs write.

Each helper skips the test (pytest.skip) when ffmpeg, ffprobe or the encoder it needs is missing, so the suite
runs anywhere; CI installs ffmpeg.

    clip = make_video(tmp_path / "a.mp4", vcodec="libx264", acodec="aac", seconds=3)
    packets = probe_packets(clip, "v")          # [{"pts", "dts", "size", "key", "pos"}, ...]
    ok, errors = decode_check(repaired)        # decodes every frame; errors are ffmpeg's messages
"""

from __future__ import annotations

import functools
import json
import shutil
import subprocess
from pathlib import Path

import pytest


@functools.lru_cache(maxsize=None)
def _encoders() -> frozenset[str]:
    if not shutil.which("ffmpeg"):
        return frozenset()
    out = subprocess.run(["ffmpeg", "-hide_banner", "-encoders"], capture_output=True, text=True).stdout
    names = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and len(parts[0]) == 6 and parts[0][0] in "VAS":
            names.add(parts[1])
    return frozenset(names)


def need_ffmpeg(*encoders: str) -> None:
    """Skip unless ffmpeg and ffprobe are installed, with every encoder named."""
    if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
        pytest.skip("ffmpeg is not installed")
    missing = [e for e in encoders if e and e not in _encoders()]
    if missing:
        pytest.skip(f"ffmpeg has no {', '.join(missing)} encoder here")


def ffmpeg(*args: str | Path, check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(["ffmpeg", "-hide_banner", "-nostdin", "-loglevel", "error", "-y", *map(str, args)],
                       capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"ffmpeg {' '.join(map(str, args))}: {p.stderr.strip()}")
    return p


def make_video(path: Path, vcodec: str | None = "libx264", acodec: str | None = "aac", seconds: float = 2.0,
               size: str = "320x240", fps: int = 25, fmt: str | None = None, vargs: tuple = (), aargs: tuple = (),
               args: tuple = (), sample_rate: int = 48000, channels: int = 2) -> Path:
    """A clip of moving test pictures (testsrc2) and a tone, in the container PATH's extension says (or FMT).
    VARGS/AARGS go after the codec (e.g. ("-g", "12", "-bf", "2"), ("-b:a", "96k")); ARGS before the output."""
    need_ffmpeg(*(c for c in (vcodec, acodec) if c and c not in ("copy",)))
    cmd: list = []
    if vcodec:
        cmd += ["-f", "lavfi", "-i", f"testsrc2=size={size}:rate={fps}:duration={seconds}"]
    if acodec:
        cmd += ["-f", "lavfi", "-i", f"sine=frequency=440:sample_rate={sample_rate}:duration={seconds}"]
    if vcodec:
        cmd += ["-c:v", vcodec, *vargs]
        if vcodec in ("libx264", "libx265"):
            cmd += ["-pix_fmt", "yuv420p"]
    else:
        cmd += ["-vn"]
    if acodec:
        cmd += ["-c:a", acodec, "-ac", str(channels), *aargs]
    else:
        cmd += ["-an"]
    if fmt:
        cmd += ["-f", fmt]
    cmd += [*args, path]
    ffmpeg(*cmd)
    return Path(path)


def make_photo(path: Path, size: str = "640x480", args: tuple = ()) -> Path:
    """A test picture (testsrc2, one frame) in the format PATH's extension says (jpg, png, webp, bmp, tiff)."""
    need_ffmpeg()
    ffmpeg("-f", "lavfi", "-i", f"testsrc2=size={size}:rate=1:duration=1", "-frames:v", "1", *args, path)
    return Path(path)


def probe(path: Path) -> dict:
    """ffprobe's view of the file: {"format": {...}, "streams": [...]} ({} when it can't open it)."""
    need_ffmpeg()
    p = subprocess.run(["ffprobe", "-v", "error", "-of", "json", "-show_format", "-show_streams", str(path)],
                       capture_output=True, text=True)
    if p.returncode != 0:
        return {}
    return json.loads(p.stdout or "{}")


def probe_packets(path: Path, stream: str = "v") -> list[dict]:
    """The packets of the first video ("v") or audio ("a") stream: [{"pts", "dts", "size", "key", "pos"}]."""
    need_ffmpeg()
    p = subprocess.run(["ffprobe", "-v", "error", "-select_streams", f"{stream}:0", "-show_packets", "-of", "json",
                        str(path)], capture_output=True, text=True)
    out = []
    for k in json.loads(p.stdout or "{}").get("packets", []):
        out.append({"pts": k.get("pts"), "dts": k.get("dts"), "size": int(k.get("size", 0)),
                    "key": "K" in (k.get("flags") or ""), "pos": int(k["pos"]) if k.get("pos") not in (None, "N/A")
                    else None})
    return out


def decode_check(path: Path, stream: str | None = None) -> tuple[bool, list[str]]:
    """Decode the whole file (every stream, or one: "v"/"a"); (no errors, ffmpeg's error lines)."""
    need_ffmpeg()
    cmd = ["ffmpeg", "-hide_banner", "-nostdin", "-v", "error", "-i", str(path)]
    if stream:
        cmd += ["-map", f"0:{stream}"]
    cmd += ["-f", "null", "-"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    lines = [ln for ln in p.stderr.splitlines() if ln.strip()]
    return p.returncode == 0 and not lines, lines


def frame_count(path: Path, stream: str = "v") -> int:
    """How many frames (video) or packets (audio) ffmpeg decodes from the stream."""
    return len(probe_packets(path, stream))


def cut(src: Path, dst: Path, keep: int | float) -> Path:
    """DST = the first KEEP bytes of SRC (a fraction 0..1 of its size when KEEP is a float)."""
    data = Path(src).read_bytes()
    n = int(len(data) * keep) if isinstance(keep, float) else int(keep)
    Path(dst).write_bytes(data[:n])
    return Path(dst)
