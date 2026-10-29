"""The file repair dispatching to the video repairs: every container is recognised by its content (whatever
it is named), analysed and repaired through filerepair, and the copy decodes cleanly."""

import pytest
from mediakit import cut, decode_check, make_video

from recoverall.core import filerepair as F

CASES = [
    ("a.mkv", "mkv", "libx264", "aac", ()),
    ("a.webm", "webm", "libvpx-vp9", "libopus", ()),
    ("a.ts", "ts", "libx264", "aac", ("-f", "mpegts")),
    ("a.m2ts", "m2ts", "libx264", "aac", ("-f", "mpegts", "-mpegts_m2ts_mode", "1")),
    ("a.mpg", "mpg", "mpeg2video", "mp2", ("-f", "vob")),
    ("a.wmv", "wmv", "wmv2", "wmav2", ()),
    ("a.flv", "flv", "flv", "libmp3lame", ()),
]


@pytest.mark.parametrize("name,kind,vcodec,acodec,args", CASES)
def test_detect_analyze_repair(tmp_path, name, kind, vcodec, acodec, args):
    clip = make_video(tmp_path / name, vcodec, acodec, seconds=4, args=args)
    with open(clip, "rb") as fh:
        data = fh.read()
    assert F.detect(data, clip) == kind
    assert F.detect(data, tmp_path / "renamed.bin") in (kind, {"m2ts": "ts"}.get(kind), "mkv", "wmv")
    assert F.analyze(clip)["problems"] == []                      # an intact file is fine
    broken = cut(clip, tmp_path / f"broken{clip.suffix}", 0.55)
    a = F.analyze(broken)
    assert a["problems"] and a["repairable"], a
    out = tmp_path / F.output_name(broken)
    r = F.repair(broken, out)
    assert r["ok"] and r["out"], r
    ok, errors = decode_check(out)
    assert ok, errors


def test_registry():
    assert F.repairable_name("CLIP0001.MTS") and F.repairable_name("movie.mkv") and F.repairable_name("x.wmv")
    assert not F.repairable_name("notes.xyz")
    for t in ("mkv", "webm", "ts", "m2ts", "mpg", "vob", "wmv", "flv"):
        assert t in F.SUPPORTED_TYPES and F.NAMES.get(t)
        assert F._kind(t) in F._HANDLERS
