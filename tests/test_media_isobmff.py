"""ISO media boxes and sample tables, against what ffprobe says about files ffmpeg made."""

import pytest
from mediakit import make_video, probe_packets

from recoverall.core.media import isobmff as I


@pytest.mark.parametrize("name,vcodec,acodec,args,vargs", [
    ("a.mp4", "libx264", "aac", (), ("-g", "12", "-bf", "2")),
    ("faststart.mp4", "libx264", "aac", ("-movflags", "+faststart"), ()),
    ("hevc.mp4", "libx265", "aac", (), ("-tag:v", "hvc1")),
    ("prores.mov", "prores_ks", "pcm_s16le", (), ()),
    ("mjpeg.mov", "mjpeg", "pcm_s16le", (), ()),
])
def test_sample_tables_match_ffprobe(tmp_path, name, vcodec, acodec, args, vargs):
    clip = make_video(tmp_path / name, vcodec, acodec, seconds=1.5, args=args, vargs=vargs)
    buf = clip.read_bytes()
    movie, boxes = I.movie_of(buf)
    assert movie is not None and {b.name for b in boxes} >= {"ftyp", "moov", "mdat"}
    video = movie.track("vide")
    packets = probe_packets(clip, "v")
    assert list(zip(video.sample_offsets(), video.sizes)) == [(p["pos"], p["size"]) for p in packets]
    assert video.keyframes() == {i for i, p in enumerate(packets) if p["key"]}
    assert sum(video.durations()) == video.duration
    audio = movie.track("soun")
    assert audio.channels == 2 and audio.sample_rate == 48000
    if audio.codec == "mp4a":
        assert list(zip(audio.sample_offsets(), audio.sizes)) == [(p["pos"], p["size"])
                                                                   for p in probe_packets(clip, "a")]
        assert audio.config(b"esds")
    info = I.describe(buf)
    assert info["width"] == 320 and info["height"] == 240 and info["fps"] == 25.0 and info["duration"] > 1


def test_fragmented_and_damaged(tmp_path):
    clip = make_video(tmp_path / "f.mp4", "libx264", "aac", seconds=2, args=("-movflags", "frag_keyframe+empty_moov"),
                      vargs=("-g", "10"))
    buf = clip.read_bytes()
    movie, boxes = I.movie_of(buf)
    assert movie.fragmented and [b.name for b in boxes].count("moof") >= 4
    assert movie.track("vide").config(b"avcC")
    # cut short: the last box says it is truncated, nothing raises
    cut = buf[:len(buf) // 2]
    boxes = I.top_level(cut)
    assert boxes[-1].truncated
    # garbage never raises
    import random
    rnd = random.Random(5)
    for _ in range(200):
        junk = bytearray(buf[:4096])
        for _ in range(20):
            junk[rnd.randrange(len(junk))] = rnd.randrange(256)
        m, _b = I.movie_of(bytes(junk))
        I.describe(bytes(junk))
        if m is not None:
            for t in m.tracks:
                t.sample_offsets()


def test_write_boxes():
    b = I.box("free", b"abc")
    assert b == b"\x00\x00\x00\x0bfreeabc"
    fb = I.full_box("mvhd", 1, 3, b"")
    assert fb[8:12] == b"\x01\x00\x00\x03"
    assert [x.name for x in I.iter_boxes(b + fb)] == ["free", "mvhd"]
