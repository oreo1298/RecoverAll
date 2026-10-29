"""Repairing Matroska/WebM, MPEG transport and program streams, Windows Media and Flash video, judged by
ffprobe/ffmpeg on real files that ffmpeg made and that were then damaged (cut short, junk appended, 64 KiB
overwritten with random bytes or zeros, the start lost)."""

import random
import struct
import subprocess
import zlib
from pathlib import Path

import pytest
from mediakit import decode_check, make_video, need_ffmpeg, probe, probe_packets

from recoverall.core import filerepair as F
from recoverall.core.media import asf, ebml, flv, mkv, mpegps, mpegts


def repair_with(plan_fn, path: Path, out: Path, reference=None):
    """Plan the repair of PATH with PLAN_FN and write the copy to OUT (when there is something to repair)."""
    with F._mapped(path) as buf:
        plan = plan_fn(buf, str(path), reference=reference)
        if plan.problems and plan.repairable:
            with open(out, "wb") as f:
                F._write_pieces(buf, plan.build(), f, F.NULL_CONTROL)
    return plan


# (name, file name, plan function, video codec, audio codec, extra output args, video args, audio args)
FAMILIES = {
    "mkv": ("a.mkv", mkv.plan_mkv, "libx264", "aac", (), ("-g", "25", "-b:v", "1M"), ()),
    "webm": ("a.webm", mkv.plan_mkv, "libvpx-vp9", "libopus", (),
             ("-g", "25", "-b:v", "1M", "-deadline", "realtime", "-cpu-used", "8"), ()),
    "ts": ("a.ts", mpegts.plan_mpegts, "libx264", "aac", ("-f", "mpegts"), ("-g", "25", "-b:v", "1M"), ()),
    "m2ts": ("a.m2ts", mpegts.plan_mpegts, "libx264", "aac", ("-f", "mpegts", "-mpegts_m2ts_mode", "1"),
             ("-g", "25", "-b:v", "1M"), ()),
    "vob": ("a.vob", mpegps.plan_mpegps, "mpeg2video", "mp2", ("-f", "vob"), ("-g", "12", "-b:v", "1500k"), ()),
    "mpg": ("a.mpg", mpegps.plan_mpegps, "mpeg1video", "mp2", ("-f", "mpeg"), ("-g", "12", "-b:v", "1500k"), ()),
    "wmv": ("a.wmv", asf.plan_asf, "wmv2", "wmav2", (), ("-g", "25", "-b:v", "1M"), ()),
    "flv": ("a.flv", flv.plan_flv, "flv", "libmp3lame", (), ("-g", "25", "-b:v", "1M"), ("-ar", "44100")),
    "flv264": ("h.flv", flv.plan_flv, "libx264", "aac", (), ("-g", "25", "-b:v", "1M"), ()),
}
# bytes of container overhead per frame byte, and per frame, to estimate where a frame's data ends
OVERHEAD = {"mkv": (1.0, 16), "webm": (1.0, 16), "flv": (1.0, 16), "flv264": (1.0, 16), "ts": (188 / 184, 400),
            "m2ts": (192 / 184, 400), "vob": (2048 / 2000, 2100), "mpg": (2048 / 2000, 2100),
            "wmv": (3200 / 3150, 3300)}
_clips: dict = {}


def clip(tmp_path_factory, family: str, seconds: float = 8.0) -> Path:
    """The test clip of FAMILY (made once per test session; SECONDS 3 gives the reference recording)."""
    key = (family, seconds)
    if key not in _clips:
        name, _fn, vcodec, acodec, args, vargs, aargs = FAMILIES[family]
        d = tmp_path_factory.mktemp(f"{family}{int(seconds)}")
        _clips[key] = make_video(d / name, vcodec, acodec, seconds=seconds, fps=25, args=args, vargs=vargs,
                                 aargs=aargs)
    return _clips[key]


def damage(src: Path, dst: Path, kind: str) -> tuple[Path, tuple[int, int] | None, int | None]:
    """DST = SRC damaged: (path, the overwritten / lost byte range, where the data ends)."""
    data = bytearray(src.read_bytes())
    n = len(data)
    rnd = random.Random(7)
    hole, cut_at = None, None
    if kind in ("cut50", "cut90"):
        cut_at = n // 2 + 1001 if kind == "cut50" else n * 9 // 10 + 333
        data = data[:cut_at]
    elif kind == "junk":
        data += bytes(rnd.randrange(256) for _ in range(5000))
    elif kind in ("rand", "zero"):
        a = n // 2
        data[a:a + 65536] = bytes(rnd.randrange(256) for _ in range(65536)) if kind == "rand" else bytes(65536)
        hole = (a, a + 65536)
    elif kind == "head":
        data = data[100 * 1024:]
        hole = (0, 100 * 1024)
    dst.write_bytes(bytes(data))
    return dst, hole, cut_at


def survivors(packets: list[dict], family: str, hole, cut_at, video: bool) -> int:
    """How many of the original's PACKETS a perfect repair keeps: frames that lie wholly before the cut or
    outside the damaged range; for video after a damaged range, only from the next key frame on (what comes
    before it can't be decoded)."""
    f, k = OVERHEAD[family]
    count = 0
    waiting = False
    placed, at = [], 0
    for p in packets:                        # frames that share a PES with the one before have no position
        at = p["pos"] if p["pos"] is not None else at
        placed.append((at, p))
        at += int(p["size"] * f)
    for a, p in sorted(placed, key=lambda x: x[0]):
        b = a + int(p["size"] * f) + k
        if cut_at is not None:
            count += b <= cut_at
            continue
        if hole is None:
            count += 1
            continue
        if b <= hole[0]:
            count += 1
        elif a >= hole[1]:
            if video and waiting and not p["key"]:
                continue
            waiting = False
            count += 1
        else:
            waiting = True
    return count


CASES = ["cut50", "cut90", "junk", "rand", "zero", "head"]


@pytest.mark.parametrize("family", list(FAMILIES))
def test_originals_are_fine(tmp_path_factory, family):
    src = clip(tmp_path_factory, family)
    plan_fn = FAMILIES[family][1]
    with F._mapped(src) as buf:
        plan = plan_fn(buf, str(src))
    assert plan.problems == [], plan.problems
    assert plan.info.get("duration", 0) == pytest.approx(8.0, abs=0.5)


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("family", list(FAMILIES))
def test_repair(tmp_path_factory, tmp_path, family, case):
    src = clip(tmp_path_factory, family)
    plan_fn = FAMILIES[family][1]
    ext = src.suffix
    bad, hole, cut_at = damage(src, tmp_path / f"bad{ext}", case)
    out = tmp_path / f"fixed{ext}"
    reference = clip(tmp_path_factory, family, 3.0) if case == "head" else None
    plan = repair_with(plan_fn, bad, out, reference)
    assert plan.problems, f"{family} {case}: nothing found"
    assert plan.repairable, (plan.problems, plan.note)
    assert out.exists()
    ok, errors = decode_check(out)
    assert ok, f"{family} {case}: {errors[:4]}"
    orig_dur = float(probe(src)["format"]["duration"])
    dur = float(probe(out)["format"]["duration"])
    if cut_at is not None:
        expect = orig_dur * cut_at / src.stat().st_size
        assert expect * 0.75 - 0.3 <= dur <= expect * 1.15 + 0.3, (dur, expect)
    elif case == "head" and family in ("ts", "m2ts", "vob", "mpg"):
        assert orig_dur * 0.5 <= dur <= orig_dur + 0.3, (dur, orig_dur)        # times start late
    else:
        assert orig_dur * 0.8 <= dur <= orig_dur + 0.6, (dur, orig_dur)
    for stream in ("v", "a"):
        want = survivors(probe_packets(src, stream), family, hole, cut_at, stream == "v")
        got = len(probe_packets(out, stream))
        assert got >= 0.95 * want - 1, f"{family} {case} {stream}: kept {got} of {want} frames"
        assert got <= len(probe_packets(src, stream))
    # the repaired copy is fine as far as the checker is concerned (no new damage is reported)
    with F._mapped(out) as buf:
        again = plan_fn(buf, str(out))
    assert not [p for p in again.problems if "damaged" in p or "cut short" in p], again.problems


@pytest.mark.parametrize("family", list(FAMILIES))
def test_fuzz_never_raises(tmp_path_factory, family):
    src = clip(tmp_path_factory, family, 3.0)
    plan_fn = FAMILIES[family][1]
    base = src.read_bytes()[:48 * 1024]
    rnd = random.Random(zlib.crc32(family.encode()))        # the same corruptions every run (hash() isn't)
    for i in range(200):
        data = bytearray(base)
        kind = i % 5
        if kind == 0:
            for _ in range(rnd.randrange(1, 40)):
                data[rnd.randrange(len(data))] = rnd.randrange(256)
        elif kind == 1:
            a = rnd.randrange(len(data))
            data[a:a + rnd.randrange(1, 4096)] = bytes(rnd.randrange(1, 4096))
        elif kind == 2:
            data = data[:rnd.randrange(len(data))]
        elif kind == 3:
            a = rnd.randrange(len(data))
            data[a:a] = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 600)))
        else:
            a = rnd.randrange(len(data))
            del data[a:a + rnd.randrange(1, 3000)]
            for _ in range(5):
                data[rnd.randrange(len(data))] = rnd.randrange(256)
        buf = bytes(data)
        plan = plan_fn(buf, f"x{src.suffix}", reference=src if i % 7 == 0 else None)
        if plan.repairable and plan.build is not None:
            for p in plan.build():
                if isinstance(p, tuple):
                    assert 0 <= p[0] <= p[1] <= len(buf)
                else:
                    assert isinstance(p, bytes)


# ---------------------------------------------------------------------- EBML and Matroska details
def test_ebml_coding():
    for n in (0, 1, 126, 127, 128, 16382, 16383, 2 ** 40):
        enc = ebml.encode_size(n)
        assert ebml.read_size(enc, 0, len(enc)) == (n, len(enc))
        enc8 = ebml.encode_size(n, 8)
        assert ebml.read_size(enc8, 0, 8) == (n, 8)
    assert ebml.read_size(b"\xff", 0, 1) == (None, 1)
    assert ebml.read_size(ebml.UNKNOWN_SIZE, 0, 8) == (None, 8)
    assert ebml.read_id(b"\x1a\x45\xdf\xa3", 0, 4) == (0x1A45DFA3, 4)
    assert ebml.read_id(b"\x00", 0, 1) is None
    for total in (2, 3, 100, 127, 128, 129, 20000):
        v = ebml.void(total)
        assert len(v) == total
        el = ebml.element_at(v, 0, total)
        assert el.id == 0xEC and el.end == total
    with pytest.raises(ValueError):
        ebml.encode_size(200, 1)


def _block(track: int, tc: int, flags: int, lacing: bytes, frames: list[bytes]) -> bytes:
    return bytes([0x80 | track]) + struct.pack(">h", tc) + bytes([flags]) + lacing + b"".join(frames)


def test_lacing():
    frames = [b"a" * 300, b"b" * 20, b"c" * 7]
    xiph = bytes([2, 255, 45, 20])
    blk = _block(1, 5, 0x82, xiph, frames)
    assert ebml.block_header(blk, 0, len(blk)) == (1, 5, 0x82, 4)
    assert ebml.lace_sizes(blk, 4, len(blk), 1) == ([300, 20, 7], 8)
    # EBML lacing: the first size, then signed differences
    diff = 20 - 300 + 8191                   # a two-byte signed vint: value + 8191
    ebl = bytes([2]) + ebml.encode_size(300) + (0x4000 | diff).to_bytes(2, "big")
    blk = _block(2, -3, 0x86, ebl, frames)
    assert ebml.block_header(blk, 0, len(blk))[:3] == (2, -3, 0x86)
    sizes, _first = ebml.lace_sizes(blk, 4, len(blk), 3)
    assert sizes == [300, 20, 7]
    fixed = _block(1, 0, 0x84, bytes([2]), [b"x" * 10] * 3)
    assert ebml.lace_sizes(fixed, 4, len(fixed), 2) == ([10, 10, 10], 5)
    assert ebml.block_header(_block(1, 0, 0x84, bytes([2]), [b"x" * 10] * 3)[:-1], 0, 33) is None


def test_mkv_live_recording(tmp_path):
    """A recording written to a pipe (as live tools do): no Segment size, no duration, no Cues."""
    need_ffmpeg("libx264", "aac")
    live = tmp_path / "live.mkv"
    data = subprocess.run(["ffmpeg", "-hide_banner", "-nostdin", "-loglevel", "error", "-f", "lavfi", "-i",
                           "testsrc2=size=320x240:rate=25:duration=4", "-f", "lavfi", "-i",
                           "sine=frequency=440:sample_rate=48000:duration=4", "-c:v", "libx264", "-pix_fmt",
                           "yuv420p", "-g", "25", "-c:a", "aac", "-f", "matroska", "pipe:1"],
                          capture_output=True, check=True).stdout
    live.write_bytes(data[:len(data) * 3 // 4])
    out = tmp_path / "fixed.mkv"
    plan = repair_with(mkv.plan_mkv, live, out)
    assert any("duration is missing" in p for p in plan.problems)
    assert any("Cues" in p for p in plan.problems)
    assert decode_check(out)[0]
    info = probe(out)["format"]
    assert float(info["duration"]) == pytest.approx(3.0, abs=0.4)
    with F._mapped(out) as buf:
        again = mkv.plan_mkv(buf, str(out))
    assert again.problems == [], again.problems         # it has its duration and seeking index now


def test_mkv_without_reference_says_why(tmp_path_factory, tmp_path):
    src = clip(tmp_path_factory, "mkv", 3.0)
    bad = tmp_path / "bad.mkv"
    bad.write_bytes(src.read_bytes()[50000:])
    plan = repair_with(mkv.plan_mkv, bad, tmp_path / "x.mkv")
    assert not plan.repairable and "no reference was given" in plan.note
    # a reference with other tracks is refused, with the reason
    other = make_video(tmp_path / "three.mkv", "libx264", "aac", seconds=1,
                       args=("-map", "0:v", "-map", "1:a", "-map", "1:a"))
    data = bytearray(src.read_bytes())
    head = mkv._parse_head(data, len(data))
    bad2 = tmp_path / "bad2.mkv"
    bad2.write_bytes(bytes(data[head.first_cluster + 20:]))
    plan = repair_with(mkv.plan_mkv, bad2, tmp_path / "y.mkv", reference=other)
    assert plan.repairable and "Some tracks" not in plan.note          # tracks 1 and 2 are in both
    audio_only = make_video(tmp_path / "audio.mka", None, "aac", seconds=1)       # its only track is 1: sound
    plan = repair_with(mkv.plan_mkv, bad2, tmp_path / "z.mkv", reference=audio_only)
    assert "Some tracks of this file aren't in the reference video (2)" in plan.note


def test_mkv_wrong_sizes_and_duration(tmp_path_factory, tmp_path):
    src = clip(tmp_path_factory, "mkv", 3.0)
    data = bytearray(src.read_bytes())
    head = mkv._parse_head(data, len(data))
    seg = head.segment
    struct.pack_into(">Q", data, seg.data - 8, (1 << 56) | (seg.size + 100000))          # too large
    dur = ebml.child(data, head.info, mkv.DURATION)
    struct.pack_into(">d", data, dur.data, 99000.0)                                    # 99 s
    bad = tmp_path / "bad.mkv"
    bad.write_bytes(bytes(data))
    out = tmp_path / "fixed.mkv"
    plan = repair_with(mkv.plan_mkv, bad, out)
    assert any("Segment" in p for p in plan.problems) and any("duration is wrong" in p for p in plan.problems)
    assert decode_check(out)[0]
    assert float(probe(out)["format"]["duration"]) == pytest.approx(3.0, abs=0.2)
    assert len(probe_packets(out, "v")) == len(probe_packets(src, "v"))


def test_flv_metadata_patched(tmp_path_factory, tmp_path):
    src = clip(tmp_path_factory, "flv264", 3.0)
    data = bytearray(src.read_bytes())
    values = flv.metadata(bytes(data[13 + 11:13 + 11 + 2000]))
    off = values["duration"][0]
    struct.pack_into(">d", data, 13 + 11 + off, 77.0)
    bad = tmp_path / "bad.flv"
    bad.write_bytes(bytes(data))
    out = tmp_path / "fixed.flv"
    plan = repair_with(flv.plan_flv, bad, out)
    assert any("duration in the metadata is wrong" in p for p in plan.problems)
    assert out.stat().st_size == bad.stat().st_size                    # patched in place
    fixed = flv.metadata(out.read_bytes()[13 + 11:13 + 11 + 2000])
    assert fixed["duration"][1] == pytest.approx(3.0, abs=0.15)
    assert fixed["filesize"][1] == out.stat().st_size


def test_ts_204_byte_packets_and_missing_tables(tmp_path_factory, tmp_path):
    src = clip(tmp_path_factory, "ts", 3.0)
    data = src.read_bytes()
    rs = b"".join(data[i:i + 188] + bytes(16) for i in range(0, len(data) - 187, 188))
    t204 = tmp_path / "rs.ts"
    t204.write_bytes(rs[:len(rs) * 2 // 3 + 50])
    out = tmp_path / "fixed.ts"
    plan = repair_with(mpegts.plan_mpegts, t204, out)
    assert plan.info["packet_size"] == 204 and plan.repairable
    assert out.stat().st_size % 204 == 0
    assert decode_check(out)[0]
    # no PAT/PMT anywhere: they come from the reference
    lead_less = bytearray()
    for i in range(0, len(data) - 187, 188):
        pkt = data[i:i + 188]
        pid = ((pkt[1] & 0x1F) << 8) | pkt[2]
        if pid not in (0, 0x11) and pid != 0x1000:
            lead_less += pkt
    bare = tmp_path / "bare.ts"
    bare.write_bytes(bytes(lead_less))
    plan = repair_with(mpegts.plan_mpegts, bare, tmp_path / "x.ts")
    assert not plan.repairable and "reference" in plan.note
    out2 = tmp_path / "with-tables.ts"
    plan = repair_with(mpegts.plan_mpegts, bare, out2, reference=src)
    assert plan.repairable, plan.note
    assert decode_check(out2)[0]
    assert {s["codec_type"] for s in probe(out2)["streams"]} >= {"video", "audio"}


def test_detect_helpers(tmp_path_factory):
    heads = {f: clip(tmp_path_factory, f, 3.0).read_bytes()[:8192] for f in ("mkv", "ts", "m2ts", "vob", "wmv", "flv")}
    assert mkv.detect_mkv(heads["mkv"]) and not mkv.detect_mkv(heads["ts"])
    assert mpegts.detect_mpegts(heads["ts"]) and mpegts.detect_mpegts(heads["m2ts"])
    assert not mpegts.detect_mpegts(heads["vob"]) and not mpegts.detect_mpegts(heads["mkv"])
    assert mpegps.detect_mpegps(heads["vob"]) and not mpegps.detect_mpegps(heads["ts"])
    assert asf.detect_asf(heads["wmv"]) and not asf.detect_asf(heads["flv"])
    assert flv.detect_flv(heads["flv"]) and not flv.detect_flv(heads["wmv"])


def test_ps_and_ts_hand_over(tmp_path_factory):
    """A transport stream named .mpg (or a program stream named .ts) is checked as what it is."""
    ts = clip(tmp_path_factory, "ts", 3.0).read_bytes()
    vob = clip(tmp_path_factory, "vob", 3.0).read_bytes()
    assert mpegps.plan_mpegps(ts, "x.mpg").info.get("packet_size") == 188
    assert mpegts.plan_mpegts(vob, "x.ts").info.get("mpeg") == "MPEG-2"


# ---------------------------------------------------------------------- more kinds of files
VARIANTS = [
    ("a.mka", mkv.plan_mkv, None, "aac", (), (), ()),
    ("v8.webm", mkv.plan_mkv, "libvpx", "libvorbis", (), (), ()),
    ("front-cues.mkv", mkv.plan_mkv, "libx264", "aac", ("-reserve_index_space", "4000"), (), ()),
    ("mjpeg.mkv", mkv.plan_mkv, "mjpeg", "pcm_s16le", (), (), ()),
    ("small-clusters.mkv", mkv.plan_mkv, "libx264", "aac", ("-cluster_size_limit", "20000"), (), ()),
    ("mpeg2.ts", mpegts.plan_mpegts, "mpeg2video", "mp2", ("-f", "mpegts"), (), ()),
    ("ac3.m2ts", mpegts.plan_mpegts, "libx264", "ac3", ("-f", "mpegts", "-mpegts_m2ts_mode", "1"), (), ()),
    ("sound.ts", mpegts.plan_mpegts, None, "aac", ("-f", "mpegts"), (), ()),
    ("dvd.vob", mpegps.plan_mpegps, None, None, ("-target", "pal-dvd"), (), ()),
    ("vcd.mpg", mpegps.plan_mpegps, None, None, ("-target", "pal-vcd"), (), ()),
    ("svcd.mpg", mpegps.plan_mpegps, None, None, ("-target", "pal-svcd"), (), ()),
    ("a.wma", asf.plan_asf, None, "wmav2", (), (), ()),
    ("ms.asf", asf.plan_asf, "msmpeg4", "wmav1", (), (), ()),
    ("sound.flv", flv.plan_flv, None, "libmp3lame", (), (), ("-ar", "44100")),
    ("index.flv", flv.plan_flv, "libx264", "aac", ("-flvflags", "add_keyframe_index"), (), ()),
]


def _variant(path: Path, vcodec, acodec, args, vargs, aargs, seconds: float = 3.0) -> Path:
    if vcodec is None and acodec is None:            # an ffmpeg -target preset picks the codecs
        need_ffmpeg("mpeg2video", "mp2", "ac3")
        cmd = ["ffmpeg", "-hide_banner", "-nostdin", "-loglevel", "error", "-y", "-f", "lavfi", "-i",
               f"testsrc2=size=352x288:rate=25:duration={seconds}", "-f", "lavfi", "-i",
               f"sine=frequency=440:sample_rate=48000:duration={seconds}", *args, str(path)]
        subprocess.run(cmd, check=True, capture_output=True)
        return path
    return make_video(path, vcodec, acodec, seconds=seconds, args=args, vargs=vargs, aargs=aargs)


@pytest.mark.parametrize("name,plan_fn,vcodec,acodec,args,vargs,aargs", VARIANTS, ids=[v[0] for v in VARIANTS])
def test_more_originals_are_fine(tmp_path, name, plan_fn, vcodec, acodec, args, vargs, aargs):
    src = _variant(tmp_path / name, vcodec, acodec, args, vargs, aargs)
    with F._mapped(src) as buf:
        plan = plan_fn(buf, str(src))
    assert plan.problems == [], plan.problems
    assert plan.info["duration"] == pytest.approx(float(probe(src)["format"]["duration"]), abs=0.35)


def test_dvd_with_ac3(tmp_path):
    """DVD video (MPEG-2, AC-3 sound in private stream 1): a cut at a sector boundary is found by the last
    picture's missing rows; damage is dropped with whole AC-3 frames on both sides."""
    src = _variant(tmp_path / "dvd.vob", None, None, ("-target", "pal-dvd"), (), (), seconds=8)
    data = src.read_bytes()
    _ok, baseline = decode_check(src)                # ffmpeg's own DVD output has a time stamp warning
    cut = tmp_path / "cut.vob"
    cut.write_bytes(data[:len(data) // 2 // 2048 * 2048])
    out = tmp_path / "fixed.vob"
    plan = repair_with(mpegps.plan_mpegps, cut, out)
    assert "The file is cut short: its last picture is incomplete" in plan.problems
    assert not [e for e in decode_check(out)[1] if "non monotonically" not in e]
    bad = bytearray(data)
    bad[len(data) // 3:len(data) // 3 + 70000] = bytes(random.Random(3).randrange(256) for _ in range(70000))
    dmg = tmp_path / "damaged.vob"
    dmg.write_bytes(bytes(bad))
    out2 = tmp_path / "fixed2.vob"
    plan = repair_with(mpegps.plan_mpegps, dmg, out2)
    assert plan.repairable and any("damaged stretch" in p for p in plan.problems)
    assert not [e for e in decode_check(out2)[1] if "non monotonically" not in e]
    assert len(baseline) <= 2


def test_asf_index_rebuilt_like_ffmpeg(tmp_path_factory, tmp_path):
    src = clip(tmp_path_factory, "wmv")
    data = src.read_bytes()
    h = asf._parse_header(data, len(data))
    data_end = h.size + struct.unpack_from("<Q", data, h.size + 16)[0]
    old = data[data_end:]
    assert old[:16] == asf.SIMPLE_INDEX
    bare = tmp_path / "no-index.wmv"
    bare.write_bytes(data[:data_end])
    out = tmp_path / "fixed.wmv"
    plan = repair_with(asf.plan_asf, bare, out)
    assert any("seeking index" in a for a in plan.actions)
    new = out.read_bytes()[data_end:]
    assert new[:16] == asf.SIMPLE_INDEX

    def entries(x):
        return [struct.unpack_from("<I", x, 56 + 6 * k)[0] for k in range(struct.unpack_from("<I", x, 52)[0])]
    ours, theirs = entries(new), entries(old)
    assert ours == theirs[:len(ours)] and len(ours) >= len(theirs) - 1
    assert decode_check(out)[0]


def test_flv_keyframe_index_follows_the_repair(tmp_path):
    src = make_video(tmp_path / "kf.flv", "libx264", "aac", seconds=8, vargs=("-g", "25", "-b:v", "1M"),
                     args=("-flvflags", "add_keyframe_index"))
    bad, _hole, _cut = damage(src, tmp_path / "bad.flv", "rand")
    out = tmp_path / "fixed.flv"
    plan = repair_with(flv.plan_flv, bad, out)
    assert plan.repairable
    data = out.read_bytes()
    index = flv.keyframe_index(data[24:24 + 4000])
    assert index is not None
    for po, to in zip(*index):
        at = int(struct.unpack_from(">d", data, 24 + po)[0])
        when = struct.unpack_from(">d", data, 24 + to)[0]
        assert data[at] == 9 and data[at + 11] >> 4 == 1            # a video key frame tag
        assert ((int.from_bytes(data[at + 4:at + 7], "big") | data[at + 7] << 24) / 1000) == pytest.approx(when)


def test_damaged_time_stamps_dont_hide_the_rest(tmp_path_factory, tmp_path):
    """A Cluster Timestamp or a tag time overwritten with a far-off value: what follows is still kept."""
    src = clip(tmp_path_factory, "mkv")
    data = bytearray(src.read_bytes())
    head = mkv._parse_head(data, len(data))
    pos, n = head.first_cluster, 0
    while n < 3:                                     # the fourth Cluster
        pos = ebml.element_at(data, pos, len(data)).end
        n += 1
    ts = ebml.child(data, ebml.element_at(data, pos, len(data)), mkv.TIMESTAMP)
    data[ts.data:ts.end] = b"\x7f" * ts.size
    bad = tmp_path / "ts.mkv"
    bad.write_bytes(bytes(data))
    out = tmp_path / "fixed.mkv"
    plan = repair_with(mkv.plan_mkv, bad, out)
    assert plan.repairable and decode_check(out)[0]
    for stream in ("v", "a"):
        assert len(probe_packets(out, stream)) >= 0.97 * len(probe_packets(src, stream))
    assert float(probe(out)["format"]["duration"]) == pytest.approx(8.0, abs=0.3)

    src = clip(tmp_path_factory, "flv264")
    data = bytearray(src.read_bytes())
    pos, n = 13, 0
    while n < 100:
        pos += 15 + int.from_bytes(data[pos + 1:pos + 4], "big")
        n += 1
    data[pos + 7] = 0x40                             # the time stamp's high byte: 18 hours on
    bad = tmp_path / "ts.flv"
    bad.write_bytes(bytes(data))
    out = tmp_path / "fixed.flv"
    plan = repair_with(flv.plan_flv, bad, out)
    assert any("damaged stretch" in p for p in plan.problems)
    assert decode_check(out)[0]
    assert len(probe_packets(out, "a")) >= len(probe_packets(src, "a")) - 2


def test_ebml_elements_past_the_data():
    """An element that claims to run past the data (its file cut short or damaged) never makes the readers
    read past the buffer (it once did, in the duration-tag patching of a repair with a reference)."""
    tags = bytes.fromhex("1254c367") + bytes.fromhex("01000000000000ff")      # Tags, size 255
    tag = bytes.fromhex("7373") + bytes.fromhex("8f") + bytes.fromhex("63c0") + bytes.fromhex("8a")
    buf = tags + tag
    el = ebml.element_at(buf, 0, len(buf))
    assert el is not None and el.end > len(buf)
    assert [c.id for c in ebml.children(buf, el.data, el.end)] == [0x7373]
    inner = next(ebml.children(buf, el.data, el.end))
    assert list(ebml.children(buf, inner.data, inner.end))[0].id == 0x63C0
    assert ebml.read_id(buf, len(buf), len(buf) + 100) is None
    assert ebml.read_vint(buf, len(buf) + 5, len(buf) + 100) is None
