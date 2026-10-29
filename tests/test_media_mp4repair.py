"""Repairing MP4/MOV/3GP/M4V files, above all recordings whose index (moov) was never written, judged by
ffprobe/ffmpeg: the repaired file must hold the original's frames (same sizes, same order, same times, same key
frames) and decode without errors."""

import json
import os
import random
import subprocess
import time
from fractions import Fraction
from pathlib import Path

import pytest
from mediakit import cut, decode_check, make_other_video, make_video, probe, probe_packets

from recoverall.core import filerepair as fr
from recoverall.core.media import isobmff as I
from recoverall.core.media import mp4repair as M

STREAM_KINDS = {"v": "video", "a": "audio"}


def timed(path: Path, stream: str) -> list[dict]:
    """The stream's packets with their presentation time in seconds ("t")."""
    info = probe(path)
    st = next((s for s in info.get("streams", []) if s["codec_type"] == STREAM_KINDS[stream]), None)
    if st is None:
        return []
    tb = Fraction(st["time_base"])
    return [dict(p, t=float(p["pts"] * tb) if p["pts"] is not None else None) for p in probe_packets(path, stream)]


def same(p: dict, q: dict) -> bool:
    return p["size"] == q["size"] and p["key"] == q["key"] and p["t"] is not None and q["t"] is not None \
        and abs(p["t"] - q["t"]) < 1e-4


def leading(want: list[dict], got: list[dict]) -> int:
    """How many packets from the first are the same."""
    n = 0
    for p, q in zip(want, got):
        if not same(p, q):
            break
        n += 1
    return n


def available(orig: Path, stream: str, limit: int) -> list[dict]:
    """The original's packets that lie wholly in its first LIMIT bytes."""
    return [p for p in timed(orig, stream) if p["pos"] is not None and p["pos"] + p["size"] <= limit]


def without_index(data: bytes) -> bytes:
    """A recording as it is when the camera never wrote its index: everything before the moov at the end."""
    moov = next(b for b in I.top_level(data) if b.type == b"moov")
    return data[:moov.start]


# id: (extension, video codec, sound codec, video args, make_video keywords, frames that may be lost at the cut:
# MPEG-4 Part 2 and H.263 frames have no length, so the last one goes when only part of what follows it is there,
# and with it the sound that came after it)
CASES = {
    "h264-bf2-aac": (".mp4", "libx264", "aac", ("-g", "12", "-bf", "2"), {}, 0),
    "h264-nobf-mono44k": (".mp4", "libx264", "aac", ("-bf", "0", "-g", "30"), {"sample_rate": 44100, "channels": 1}, 0),
    "h264-pyramid-3gp": (".3gp", "libx264", "aac", ("-bf", "3"), {}, 0),
    "h264-m4v": (".m4v", "libx264", "aac", (), {"sample_rate": 44100}, 0),
    "h264-pcm16-mov": (".mov", "libx264", "pcm_s16le", (), {}, 0),
    "h264-pcm24-mov": (".mov", "libx264", "pcm_s24le", ("-bf", "0"), {"channels": 1}, 0),
    "h264-video-only": (".mp4", "libx264", None, ("-g", "25"), {}, 0),
    "h264-ac3": (".mp4", "libx264", "ac3", (), {}, 0),
    "h264-eac3": (".mp4", "libx264", "eac3", (), {}, 0),
    "h264-60fps-timecode-mov": (".mov", "libx264", "aac", ("-bf", "2"), {"fps": 60, "args": ("-timecode", "01:00:00:00")}, 0),
    "h264-mp3": (".mp4", "libx264", "libmp3lame", (), {"sample_rate": 44100}, 0),
    "hevc-hvc1": (".mp4", "libx265", "aac", ("-tag:v", "hvc1"), {}, 0),
    "hevc-hev1-opengop": (".mp4", "libx265", "aac", ("-g", "12"), {}, 0),
    "hevc-mov": (".mov", "libx265", "aac", ("-tag:v", "hvc1", "-x265-params", "bframes=0"), {"channels": 1}, 0),
    "mpeg4-aac": (".mp4", "mpeg4", "aac", (), {}, 1),
    "mpeg4-pcm-mov": (".mov", "mpeg4", "pcm_s16le", (), {}, 1),
    "mjpeg-pcm-mov": (".mov", "mjpeg", "pcm_s16le", (), {}, 0),
    "prores-pcm24-mov": (".mov", "prores_ks", "pcm_s24le", (), {}, 0),
    "h263-aac-3gp": (".3gp", "h263", "aac", (), {"size": "352x288"}, 1),
    "aac-only-m4a": (".m4a", None, "aac", (), {}, 0),
}


@pytest.fixture(scope="module")
def clips(tmp_path_factory):
    made: dict = {}

    def get(case: str) -> tuple[Path, Path]:
        if case not in made:
            ext, vcodec, acodec, vargs, kw, _slack = CASES[case]
            d = tmp_path_factory.mktemp(case)
            orig = make_video(d / f"orig{ext}", vcodec, acodec, seconds=4, vargs=vargs, **kw)
            ref = make_other_video(d / f"ref{ext}", vcodec, acodec, seconds=1.5, vargs=vargs, **kw)
            made[case] = orig, ref
        return made[case]
    return get


@pytest.mark.parametrize("case", list(CASES))
def test_rebuild_from_reference(tmp_path, clips, case):
    ext, vcodec, acodec, _vargs, _kw, slack = CASES[case]
    if acodec == "aac" or vcodec in ("mpeg4", "h263"):
        pytest.importorskip("recoverall.core.media.aac")
    orig, ref = clips(case)
    streams = [s for s, c in (("v", vcodec), ("a", acodec)) if c]
    for frac in (0.3, 0.6, 0.95):
        broken = cut(orig, tmp_path / f"cut{int(frac * 100)}{ext}", frac)
        assert not any(b.type == b"moov" for b in I.top_level(broken.read_bytes()))
        a = fr.analyze(broken)
        assert a["problems"] == [M.MISSING] and not a["repairable"] and a["info"]["needs_reference"]
        assert "reference video" in a["note"]
        r = fr.repair(broken, tmp_path / f"fixed{int(frac * 100)}{ext}", reference=ref)
        assert r["ok"] and r["out"], r["message"]
        assert r["actions_done"][0].startswith("Rebuild the index from the reference video ref")
        limit = broken.stat().st_size
        for s in streams:
            want, got = available(orig, s, limit), timed(Path(r["out"]), s)
            assert len(want) > 5
            n = leading(want, got)
            lost = slack if s == "v" else 2 * slack
            extra = 1 if s == "a" and acodec.startswith("pcm") else 0     # PCM: the cut-short last chunk too
            assert n >= len(want) - lost and len(want) - lost <= len(got) <= len(want) + extra, \
                (case, frac, s, n, len(want), len(got))
        ok, errors = decode_check(Path(r["out"]))
        assert ok, (case, frac, errors[:5])
        tags = [st.get("tags", {}).get("timecode") for st in probe(Path(r["out"]))["streams"]]
        assert tags == [st.get("tags", {}).get("timecode") for st in probe(orig)["streams"]]


def test_two_sound_tracks(tmp_path):
    pytest.importorskip("recoverall.core.media.aac")
    from mediakit import ffmpeg

    def make(path: Path, video: str, seconds: float) -> Path:
        ffmpeg("-f", "lavfi", "-i", f"{video}=size=320x240:rate=25:duration={seconds}",
               "-f", "lavfi", "-i", f"sine=f=440:sample_rate=48000:duration={seconds}",
               "-f", "lavfi", "-i", f"sine=f=880:sample_rate=48000:duration={seconds}",
               "-map", "0", "-map", "1", "-map", "2", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac",
               "-ac:a:0", "2", "-ac:a:1", "1", path)
        return path
    orig = make(tmp_path / "o.mp4", "testsrc2", 4)
    ref = make(tmp_path / "ref.mp4", "testsrc", 1.5)
    broken = cut(orig, tmp_path / "b.mp4", 0.6)
    r = fr.repair(broken, tmp_path / "r.mp4", reference=ref)
    assert r["ok"] and r["out"]
    limit = broken.stat().st_size

    def packets(path: Path, spec: str) -> list[tuple]:
        out = subprocess.run(["ffprobe", "-v", "error", "-select_streams", spec, "-show_packets", "-of", "json",
                              str(path)], capture_output=True, text=True, check=True).stdout
        return [(int(p["size"]), p["pts"], int(p["pos"])) for p in json.loads(out)["packets"]]
    for spec in ("v:0", "a:0", "a:1"):
        want = [(n, t) for n, t, pos in packets(orig, spec) if pos + n <= limit]
        assert len(want) > 50 and [(n, t) for n, t, _pos in packets(Path(r["out"]), spec)] == want
    assert [st["channels"] for st in probe(Path(r["out"]))["streams"][1:]] == [2, 1]
    assert decode_check(Path(r["out"]))[0]


def test_big_recordings_get_64_bit_offsets(tmp_path):
    """Past 4 GiB the chunk offsets go into co64 and the mdat gets a 64-bit size (no 4 GiB file needed)."""
    clip = make_video(tmp_path / "a.mp4", "libx264", None, seconds=1, vargs=("-x264-params", "repeat-headers=1"))
    buf = without_index(clip.read_bytes())
    lay = M.find_layout(buf, I.top_level(buf))
    recipe, _guessed = M.stream_recipe(buf, lay.data_start, lay.data_end)
    walk = M.Walk(buf, lay.data_start, lay.data_end, recipe.make(), recipe.trans, other=-1).run()
    walk.finish()
    video = walk.tracks[0]
    big = 5 << 30
    video.chunk_offsets = [o + big for o in video.chunk_offsets]  # as if the data went on for 5 GiB
    video.data_end += big
    head, (start, stop), moov = M._assemble(buf, lay, recipe, walk.tracks)
    assert head[-12:-8] == b"mdat" and I.be32(head, len(head) - 16) == 1
    assert I.be64(head, len(head) - 8) == 16 + stop - start
    movie = I.parse_moov(moov, next(I.iter_boxes(moov)))
    t = movie.tracks[0]
    assert I.find(moov, "moov/trak/mdia/minf/stbl/co64") is not None
    assert t.chunk_offsets[0] == video.chunk_offsets[0] + len(head) - start > 0xFFFFFFFF


def test_index_first_cut_short(tmp_path):
    """"Fast start" files (index first) that are cut short keep their complete frames, index in place."""
    orig = make_video(tmp_path / "o.mp4", "libx264", "aac", seconds=4, vargs=("-bf", "2"),
                      args=("-movflags", "+faststart"))
    for frac in (0.3, 0.6, 0.95):
        broken = cut(orig, tmp_path / f"b{frac}.mp4", frac)
        a = fr.analyze(broken)
        assert a["repairable"] and a["problems"][0].startswith("The file is cut short")
        r = fr.repair(broken, tmp_path / f"r{frac}.mp4")
        assert r["ok"] and r["out"]
        out = Path(r["out"]).read_bytes()
        assert [b.name for b in I.top_level(out)][:3] == ["ftyp", "moov", "free"] or \
            [b.name for b in I.top_level(out)][:2] == ["ftyp", "moov"]
        for s in ("v", "a"):
            want, got = available(orig, s, broken.stat().st_size), timed(Path(r["out"]), s)
            assert got and leading(want, got) == len(got) == len(want)
        assert decode_check(Path(r["out"]))[0]
        assert fr.analyze(Path(r["out"]))["problems"] == []


def test_fragmented(tmp_path):
    orig = make_video(tmp_path / "o.mp4", "libx264", "aac", seconds=4, vargs=("-g", "10"),
                      args=("-movflags", "frag_keyframe+empty_moov"))
    want_v, want_a = timed(orig, "v"), timed(orig, "a")
    broken = cut(orig, tmp_path / "b.mp4", 0.6)
    a = fr.analyze(broken)
    assert a["problems"] == ["The last movie fragment is incomplete: the file is cut short"] and a["repairable"]
    r = fr.repair(broken, tmp_path / "r.mp4")
    got_v, got_a = timed(Path(r["out"]), "v"), timed(Path(r["out"]), "a")
    assert got_v and leading(want_v, got_v) == len(got_v) >= len(available(orig, "v", broken.stat().st_size)) - 10
    assert leading(want_a, got_a) == len(got_a) > 0
    assert decode_check(Path(r["out"]))[0]
    # without its start (ftyp + moov): the init segment comes from a reference recorded the same way
    data = orig.read_bytes()
    first = next(b for b in I.top_level(data) if b.type == b"moof")
    headless = tmp_path / "headless.mp4"
    headless.write_bytes(data[first.start:int(len(data) * 0.8)])
    a = fr.analyze(headless)
    assert not a["repairable"] and a["info"]["needs_reference"]
    ref = make_other_video(tmp_path / "ref.mp4", "libx264", "aac", seconds=1.5, vargs=("-g", "10"),
                           args=("-movflags", "frag_keyframe+empty_moov"))
    r = fr.repair(headless, tmp_path / "r2.mp4", reference=ref)
    assert r["ok"] and r["out"], r["message"]
    got_v = timed(Path(r["out"]), "v")
    assert [p["size"] for p in got_v] == [p["size"] for p in want_v[:len(got_v)]] and len(got_v) > 50
    assert decode_check(Path(r["out"]))[0]


@pytest.mark.parametrize("vcodec,vargs,acodec,audio", [
    ("libx264", ("-x264-params", "repeat-headers=1", "-g", "25"), "aac", {"sample_rate": 48000, "channels": 2}),
    ("libx264", ("-x264-params", "repeat-headers=1", "-bf", "0"), "aac", {"sample_rate": 44100, "channels": 1}),
    ("libx265", ("-x265-params", "repeat-headers=1:keyint=25"), "aac", {"sample_rate": 32000, "channels": 2}),
    ("libx264", ("-x264-params", "repeat-headers=1"), "pcm_s16le", {}),
])
def test_without_reference_in_band_parameter_sets(tmp_path, vcodec, vargs, acodec, audio):
    """Cameras that repeat SPS/PPS in the stream: the picture is rebuilt without a reference, and AAC sound
    too, its layout worked out from the frames between the pictures and its rate from their count."""
    ext = ".mov" if acodec.startswith("pcm") else ".mp4"
    orig = make_video(tmp_path / f"o{ext}", vcodec, acodec, seconds=4, vargs=vargs, **audio)
    broken = cut(orig, tmp_path / f"b{ext}", 0.6)
    a = fr.analyze(broken)
    sound = acodec == "aac"
    if sound:
        pytest.importorskip("recoverall.core.media.aac")
        rate = f"{audio['sample_rate'] / 1000:g} kHz, {'stereo' if audio['channels'] == 2 else 'mono'}"
        assert a["actions"] == ["Rebuild the index from the video stream and the sound"] and f"AAC, {rate}" in a["note"]
    else:
        assert a["actions"] == ["Rebuild the index from the video stream (picture only)"]
        assert "sound needs a reference video" in a["note"]
    assert a["repairable"] and a["info"]["salvage"][0] == ("hevc" if vcodec == "libx265" else "h264")
    r = fr.repair(broken, tmp_path / f"r{ext}")
    assert r["ok"] and "video frames" in r["actions_done"][0]
    limit = broken.stat().st_size
    for s in ("v", "a") if sound else ("v",):
        want, got = available(orig, s, limit), timed(Path(r["out"]), s)
        first = want[0]["t"] - got[0]["t"]
        assert [(p["size"], p["key"]) for p in got] == [(p["size"], p["key"]) for p in want]
        assert all(abs(p["t"] - q["t"] - first) < 1e-3 for p, q in zip(want, got))
    if not sound:
        assert not timed(Path(r["out"]), "a")
    else:
        st = next(x for x in probe(Path(r["out"]))["streams"] if x["codec_type"] == "audio")
        assert (int(st["sample_rate"]), st["channels"]) == (audio["sample_rate"], audio["channels"])
    assert decode_check(Path(r["out"]))[0]


def test_salvage_raw_streams(tmp_path):
    """The frames found can also be written as raw streams that need no index (.h264 / .hevc, .aac)."""
    pytest.importorskip("recoverall.core.media.aac")
    orig = make_video(tmp_path / "o.mp4", "libx264", "aac", seconds=3, vargs=("-bf", "2"))
    ref = make_other_video(tmp_path / "ref.mp4", "libx264", "aac", seconds=1, vargs=("-bf", "2"))
    broken = cut(orig, tmp_path / "b.mp4", 0.6)
    files = M.salvage(broken, tmp_path / "raw", reference=ref)
    assert sorted(f.name for f in files) == ["b.aac", "b.h264"]
    limit = broken.stat().st_size
    for f in files:
        s = "a" if f.suffix == ".aac" else "v"
        assert [p["size"] for p in probe_packets(f, s)][:5] and decode_check(f)[0]
        assert len(probe_packets(f, s)) == len(available(orig, s, limit))
    orig = make_video(tmp_path / "h.mp4", "libx265", None, seconds=2, vargs=("-x265-params", "repeat-headers=1"))
    files = M.salvage(cut(orig, tmp_path / "hb.mp4", 0.7), tmp_path / "raw")
    assert [f.name for f in files] == ["hb.hevc"] and decode_check(files[0])[0]


def test_describe(tmp_path):
    clip = make_video(tmp_path / "a.mp4", "libx264", "aac", seconds=2)
    info = I.describe(clip)
    assert info["has_index"] and info["frames"] == 50 and info["width"] == 320 and info["video"] == "avc1"
    assert I.describe(cut(clip, tmp_path / "b.mp4", 0.5)) == {"has_index": False, "fragmented": False}
    assert I.describe(b"not a video at all") == {}


def test_without_reference_needs_one(tmp_path):
    orig = make_video(tmp_path / "o.mp4", "libx264", "aac", seconds=2)
    broken = cut(orig, tmp_path / "b.mp4", 0.6)
    a = fr.analyze(broken)
    assert a["problems"] == ["The recording's index (the moov box) is missing: it wasn't finished (battery, crash, "
                             "card removed)"]
    assert not a["repairable"] and a["info"]["needs_reference"] and a["note"] == M.NEEDS_REFERENCE
    r = fr.repair(broken, tmp_path / "r.mp4")
    assert not r["ok"] and r["out"] is None and "reference video" in r["message"]


@pytest.mark.parametrize("damage", ["zeros", "random"])
def test_damaged_middle(tmp_path, damage):
    pytest.importorskip("recoverall.core.media.aac")
    vargs = ("-g", "25", "-bf", "2")
    orig = make_video(tmp_path / "o.mp4", "libx264", "aac", seconds=6, size="640x360", vargs=vargs)
    ref = make_other_video(tmp_path / "ref.mp4", "libx264", "aac", seconds=2, size="640x360", vargs=vargs)
    data = bytearray(without_index(orig.read_bytes()))
    at, n = len(data) // 2, 64 * 1024
    data[at:at + n] = bytes(n) if damage == "zeros" else random.Random(4).randbytes(n)
    broken = tmp_path / "b.mp4"
    broken.write_bytes(data)
    r = fr.repair(broken, tmp_path / "r.mp4", reference=ref)
    assert r["ok"] and "damaged stretch" in r["message"], r["message"]
    out = Path(r["out"])
    for s in ("v", "a"):
        want, got = timed(orig, s), timed(out, s)
        before = [p for p in want if p["pos"] + p["size"] <= at]
        after = [p for p in want if p["pos"] >= at + n]
        if s == "v":
            after = after[next(i for i, p in enumerate(after) if p["key"]):]    # pictures from the next key frame
        # what comes before the damage is all there (a frame the damage hit may be dropped)...
        assert leading(before, got) >= len(before) - 1
        # ... and so is what comes after it, in order, its timing within a few frames of the original's
        tail = got[len(got) - len(after):]
        assert [p["size"] for p in tail] == [p["size"] for p in after]
        assert all(abs(p["t"] - q["t"]) < 0.25 for p, q in zip(tail, after))
        assert len(before) - 1 + len(after) <= len(got) <= len(before) + len(after) + 1
    if damage == "zeros":
        ok, errors = decode_check(out)
        assert ok, errors[:5]
    else:
        # random bytes inside a frame's data can't all be told from real data: only that frame may be wrong
        ok, errors = decode_check(out)
        assert ok or len(errors) < 12, errors


def test_index_present_but_misplaced(tmp_path):
    orig = make_video(tmp_path / "o.mp4", "libx264", "aac", seconds=3, vargs=("-g", "12", "-bf", "2"))
    data = orig.read_bytes()
    want_v = timed(orig, "v")
    mdat = next(b for b in I.top_level(data) if b.type == b"mdat")
    # an mdat whose size was never written (0: "up to the end") hides the index after it
    zero = tmp_path / "zero.mp4"
    zero.write_bytes(data[:mdat.start] + bytes(4) + data[mdat.start + 4:])
    a = fr.analyze(zero)
    assert a["actions"] == ["Correct the size of the video data box"]
    r = fr.repair(zero, tmp_path / "r0.mp4")
    assert Path(r["out"]).read_bytes() == data
    # other data in front of the file (a carved file that started too early)
    junk = tmp_path / "junk.mp4"
    junk.write_bytes(os.urandom(1000) + data)
    a = fr.analyze(junk)
    assert a["actions"] == ["Move the index to where the frames are"]
    r = fr.repair(junk, tmp_path / "r1.mp4")
    assert leading(want_v, timed(Path(r["out"]), "v")) == len(want_v)
    assert decode_check(Path(r["out"]))[0]
    # the first 40 kB are lost: the frames from the next key frame on are kept
    lost = tmp_path / "lost.mp4"
    lost.write_bytes(data[40000:])
    a = fr.analyze(lost)
    assert a["problems"][0].startswith("The file lost its first 40") and a["repairable"]
    r = fr.repair(lost, tmp_path / "r2.mp4")
    got = timed(Path(r["out"]), "v")
    tail = [p for p in want_v if p["pos"] >= 40000]
    tail = tail[next(i for i, p in enumerate(tail) if p["key"]):]
    assert [p["size"] for p in got] == [p["size"] for p in tail]
    assert decode_check(Path(r["out"]))[0]


def test_own_damaged_index(tmp_path):
    """The file is cut inside its index at the end: what is left of it (the codec configuration) is enough."""
    orig = make_video(tmp_path / "o.mp4", "libx264", "aac", seconds=3, vargs=("-bf", "2"))
    data = orig.read_bytes()
    moov = next(b for b in I.top_level(data) if b.type == b"moov")
    broken = tmp_path / "b.mp4"
    broken.write_bytes(data[:moov.end - 300])
    a = fr.analyze(broken)
    assert a["repairable"] and a["actions"] == ["Rebuild the index from what is left of it"]
    r = fr.repair(broken, tmp_path / "r.mp4")
    for s in ("v", "a"):
        want = timed(orig, s)
        assert leading(want, timed(Path(r["out"]), s)) == len(want)
    assert decode_check(Path(r["out"]))[0]


def test_unusable_references(tmp_path):
    orig = make_video(tmp_path / "o.mp4", "libx264", "aac", seconds=2)
    broken = cut(orig, tmp_path / "b.mp4", 0.6)
    photo = tmp_path / "ref.jpg"
    photo.write_bytes(b"\xff\xd8\xff\xe0" + bytes(100))
    r = fr.repair(broken, tmp_path / "r1.mp4", reference=photo)
    assert not r["ok"] and "isn't an MP4 or MOV video" in r["message"]
    unfinished = cut(make_other_video(tmp_path / "u.mp4", "libx264", "aac", seconds=1), tmp_path / "u2.mp4", 0.5)
    r = fr.repair(broken, tmp_path / "r2.mp4", reference=unfinished)
    assert not r["ok"] and "has no index itself" in r["message"]
    other = make_other_video(tmp_path / "hevc.mp4", "libx265", "aac", seconds=1)
    r = fr.repair(broken, tmp_path / "r3.mp4", reference=other)
    assert not r["ok"] and "doesn't fit this recording" in r["message"]
    assert r["info"].get("reference_mismatch")


def test_repair_many_passes_the_reference(tmp_path):
    orig = make_video(tmp_path / "o.mp4", "libx264", "aac", seconds=2)
    ref = make_other_video(tmp_path / "ref.mp4", "libx264", "aac", seconds=1)
    broken = cut(orig, tmp_path / "in" / "b.mp4", 0.6) if (tmp_path / "in").mkdir() is None else None
    out = fr.repair_many([broken], tmp_path / "out", reference=ref)
    assert out[0]["ok"] and out[0]["out"] and Path(out[0]["out"]).name == "b (repaired).mp4"


def test_damaged_files_never_raise(tmp_path):
    orig = make_video(tmp_path / "o.mp4", "libx264", "aac", seconds=1, vargs=("-x264-params", "repeat-headers=1"))
    ref = make_other_video(tmp_path / "ref.mp4", "libx264", "aac", seconds=1)
    data = without_index(orig.read_bytes())
    rnd = random.Random(7)
    for k in range(30):
        bad = bytearray(data)
        for _ in range(rnd.randrange(1, 40)):
            at = rnd.randrange(len(bad))
            bad[at:at + rnd.randrange(1, 300)] = rnd.randbytes(rnd.randrange(1, 300))
        if k % 3 == 0:
            bad = bad[:rnd.randrange(16, len(bad))]
        p = tmp_path / f"{k}.mp4"
        p.write_bytes(bad)
        a = fr.analyze(p)
        assert isinstance(a["problems"], list)
        r = fr.repair(p, tmp_path / f"r{k}.mp4", reference=ref if k % 2 else None)
        assert r["ok"] in (True, False)


@pytest.mark.slow
@pytest.mark.skipif(not os.environ.get("RALL_SLOW_TESTS"), reason="set RALL_SLOW_TESTS=1 to measure the speed")
def test_speed(tmp_path):
    """A 3-minute 720p recording without index: well under a minute per GB of media data."""
    vargs = ("-preset", "ultrafast", "-b:v", "20M", "-g", "30", "-bf", "2")
    orig = make_video(tmp_path / "o.mp4", "libx264", "aac", seconds=180, size="1280x720", fps=30, vargs=vargs)
    ref = make_other_video(tmp_path / "ref.mp4", "libx264", "aac", seconds=2, size="1280x720", fps=30, vargs=vargs)
    broken = tmp_path / "b.mp4"
    broken.write_bytes(without_index(orig.read_bytes()))
    t = time.perf_counter()
    r = fr.repair(broken, tmp_path / "r.mp4", reference=ref)
    seconds = time.perf_counter() - t
    size = broken.stat().st_size
    print(f"\n{size / 1e6:.0f} MB in {seconds:.1f} s: {size / 1e6 / seconds:.0f} MB/s, {r['actions_done']}")
    assert r["ok"] and seconds < 60 * size / 1e9 + 5
    assert len(timed(Path(r["out"]), "v")) == len(timed(orig, "v"))
