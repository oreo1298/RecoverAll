"""Deleted MP4/MOV videos the signature search finds although a plain walk of their boxes doesn't
(carve/video.py with media/mp4carve.py): recordings whose index was never written (found, measured, marked
needs_index), recordings fragmented on the disk (put back together with their index), and movie boxes found
apart from their media data.

The clips are real (ffmpeg: H.264 and H.265 with AAC in MP4, ProRes and Motion JPEG with PCM in MOV), planted
in disk images between other data, and what comes back is judged byte for byte and by ffprobe / ffmpeg."""

from __future__ import annotations

import random
import struct

import pytest
from mediakit import decode_check, make_photo, make_video, need_ffmpeg, probe_packets

from recoverall.core.blockio import BytesSource
from recoverall.core.carve import carve, resolve_formats
from recoverall.core.carve.base import CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, Reader
from recoverall.core.media import isobmff as I
from recoverall.core.media import mp4carve as M

KiB, MiB = 1024, 1024 * 1024
AT = 64 * KiB                                    # where the clip under test starts in the images
VIDEO = resolve_formats("video")

# name: (file, video codec, audio codec, ffmpeg output args, video args, seconds)
CLIPS = {
    "h264": ("h264.mp4", "libx264", "aac", (), (), 6),
    "h264-faststart": ("fs.mp4", "libx264", "aac", ("-movflags", "+faststart"), (), 6),
    "hevc": ("hevc.mp4", "libx265", "aac", (), ("-tag:v", "hvc1"), 6),
    "prores": ("prores.mov", "prores_ks", "pcm_s16le", (), (), 2),
    "mjpeg": ("mjpeg.mov", "mjpeg", "pcm_s16le", (), (), 2),
}
MOOV_LAST = ["h264", "hevc", "prores", "mjpeg"]


@pytest.fixture(scope="module")
def clips(tmp_path_factory):
    """clips(name) -> the clip's bytes (made once; skips the test when ffmpeg or the encoder is missing)."""
    d = tmp_path_factory.mktemp("clips")
    cache: dict[str, bytes] = {}

    def get(name: str) -> bytes:
        if name not in cache:
            fn, v, a, args, vargs, sec = CLIPS[name]
            cache[name] = make_video(d / fn, v, a, seconds=sec, args=args, vargs=vargs).read_bytes()
        return cache[name]
    return get


@pytest.fixture(scope="module")
def other(tmp_path_factory) -> bytes:
    """Another camera's video, whose middle is planted between the pieces (the same codec, other content)."""
    d = tmp_path_factory.mktemp("other")
    return make_video(d / "other.mp4", "libx264", "aac", seconds=4, size="640x360", fps=30,
                      vargs=("-b:v", "1500k")).read_bytes()


@pytest.fixture(scope="module")
def photo(tmp_path_factory) -> bytes:
    return make_photo(tmp_path_factory.mktemp("photo") / "p.jpg", size="800x600").read_bytes()


def boxes(data: bytes) -> dict[str, I.Box]:
    return {b.name: b for b in I.top_level(data)}


def video_samples(data: bytes) -> list[tuple[int, int]]:
    movie, _b = I.movie_of(data)
    v = movie.track("vide")
    return list(zip(v.sample_offsets(), v.sizes))


def found_at(img: bytes, at: int = AT):
    files = list(carve(BytesSource(bytes(img)), VIDEO))
    return next((f for f in files if f.offset == at), None), files


def recovered(img: bytes, f) -> bytes:
    return b"".join(bytes(img[o:o + n]) for o, n in f.pieces())


def judged(tmp_path, name: str, got: bytes, want: bytes) -> None:
    """GOT plays like WANT: the same video packets (sizes, times, key frames) and it decodes without errors."""
    path = tmp_path / name
    path.write_bytes(got)
    orig = tmp_path / ("orig-" + name)
    orig.write_bytes(want)
    strip = [{k: p[k] for k in ("pts", "dts", "size", "key")} for p in probe_packets(path, "v")]
    assert strip == [{k: p[k] for k in ("pts", "dts", "size", "key")} for p in probe_packets(orig, "v")]
    ok, errors = decode_check(path)
    assert ok, errors[:5]


# ---------------------------------------------------------------------- whole files, as before
@pytest.mark.parametrize("name", list(CLIPS))
def test_contiguous_clips_found_exactly(clips, name):
    data = clips(name)
    rng = random.Random(1)
    img = rng.randbytes(AT) + data + bytes(-len(data) % 4096) + rng.randbytes(64 * KiB)
    f, files = found_at(img)
    assert f is not None and f.length == len(data) and f.runs is None and f.chance == CHANCE_GOOD
    assert recovered(img, f) == data and f.ext == ("mov" if name in ("prores", "mjpeg") else "mp4")
    assert f.info["width"] == 320 and "needs_index" not in f.info and "fragments" not in f.info
    assert len(files) == 1, [(x.offset, x.length, x.description) for x in files]


def test_quiet_ending_is_not_taken_for_a_fragment(tmp_path):
    """The sound of a movie-box-first file is checked to its last chunk: a recording that ends in silence is
    still one piece, found as before. (Only the element and tag bits of the AAC frames are compared, which a
    change of gain doesn't touch.)"""
    need_ffmpeg("libx264", "aac")
    from mediakit import ffmpeg
    path = tmp_path / "quiet.mp4"
    ffmpeg("-f", "lavfi", "-i", "testsrc2=size=320x240:rate=25:duration=5", "-f", "lavfi", "-i",
           "sine=frequency=440:sample_rate=48000:duration=5", "-af", "volume=enable='gt(t,3)':volume=0",
           "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-ac", "2", "-movflags", "+faststart", path)
    data = path.read_bytes()
    rng = random.Random(2)
    img = rng.randbytes(AT) + data + rng.randbytes(64 * KiB)
    f, _files = found_at(img)
    assert f is not None and f.length == len(data) and f.runs is None and f.chance == CHANCE_GOOD


def test_lean_tables_match_isobmff(clips):
    for name in ("h264", "prores"):
        data = clips(name)
        mv = boxes(data)["moov"]
        tables = M.read_tables(data[mv.start:mv.end])
        movie, _b = I.movie_of(data)
        for t in tables:
            tr = movie.track(t.handler)
            assert t.codec == tr.codec and t.count == tr.samples
            offs = [o for off, first, n in t.chunks() for o in _offsets(t, off, first, n)]
            assert offs == tr.sample_offsets()
            assert [t.locate(i) for i in (0, t.count // 2, t.count - 1)] == \
                [(tr.sample_offsets()[i], tr.sizes[i]) for i in (0, t.count // 2, t.count - 1)]


def _offsets(t: M.Table, off: int, first: int, n: int) -> list[int]:
    out = []
    for s in t.sizes(first, n):
        out.append(off)
        off += s
    return out


# ---------------------------------------------------------------------- unfinished recordings
@pytest.mark.parametrize("name", MOOV_LAST)
@pytest.mark.parametrize("after", ["random", "zeros", "another file"])
@pytest.mark.parametrize("size_field", ["kept", "zero"])
def test_unfinished_recording(clips, name, after, size_field):
    """The camera stopped before writing the index: the media data is found, measured and marked."""
    data = clips(name)
    b = boxes(data)
    media = bytearray(data[:b["moov"].start])            # everything up to where the index would have gone
    if size_field == "zero":                             # what a camera writes before it knows the size
        media[b["mdat"].start:b["mdat"].start + 4] = bytes(4)
    rng = random.Random(len(name) + len(after))
    tail = {"random": rng.randbytes(512 * KiB), "zeros": bytes(512 * KiB),
            "another file": clips("h264-faststart")}[after]
    img = rng.randbytes(AT) + bytes(media) + bytes(-len(media) % 4096) + tail + rng.randbytes(16 * KiB)
    f, files = found_at(img)
    assert f is not None and f.chance == CHANCE_POOR and f.runs is None
    assert f.description == "Unfinished recording (index missing)"
    info = f.info
    assert info["needs_index"] is True and "reference video" in info["note"]
    assert info["video"] == {"h264": "h264", "hevc": "hevc", "prores": "prores", "mjpeg": "mjpeg"}[name]
    assert info["media_offset"] == b["mdat"].start + 8
    assert info["frames"] == len(video_samples(data))
    end = len(media)
    if size_field == "kept":
        assert f.length == end                           # the media data box says where it ends
    else:
        assert end - 4096 <= f.length <= end + 4096      # within a cluster of the true end
    assert recovered(img, f) == bytes(img[AT:AT + f.length]) and img[AT:AT + min(end, f.length)] == \
        bytes(media[:min(end, f.length)])
    if after == "another file":                          # and the next file is found as it is
        nxt = _up(AT + len(media), 4096)
        assert any(x.offset == nxt and x.length == len(tail) and x.chance == CHANCE_GOOD for x in files)


def _up(x: int, step: int) -> int:
    return -(-x // step) * step


@pytest.mark.parametrize("name", ["h264", "hevc", "prores", "mjpeg"])
def test_recording_stopped_mid_frame(clips, other, photo, name):
    """Power lost at any byte: the last frame is cut, the rest of its cluster holds old data. The file ends
    within a cluster of where the recording stopped."""
    data = clips(name)
    b = boxes(data)
    nframes = len(video_samples(data))
    for seed, old in enumerate(("random", "zeros", "video", "photo")):
        rng = random.Random(f"{name}{seed}")
        stop = rng.randrange(b["mdat"].start + 20 * KiB, b["moov"].start)
        media = bytearray(data[:stop])
        media[b["mdat"].start:b["mdat"].start + 4] = bytes(4)              # size never written
        n = 512 * KiB
        rest = {"random": rng.randbytes(n), "zeros": bytes(n), "video": other[64 * KiB:64 * KiB + n],
                "photo": photo + rng.randbytes(n)}[old]
        img = rng.randbytes(AT) + bytes(media) + rest
        f, _files = found_at(img)
        assert f is not None and f.info["needs_index"], (old, stop)
        assert stop - 4096 <= f.length, (old, stop, f.length)
        if old != "video" or name != "h264":            # (another H.264 recording: see the next test)
            assert f.length <= stop + 4096, (old, stop, f.length)
            assert 1 <= f.info["frames"] <= nframes
        assert f.info["audio"] == ("pcm" if name in ("prores", "mjpeg") else "compressed")


def test_unfinished_recording_before_an_older_one(clips, other):
    """Old data after an unfinished H.264 recording that is another H.264 recording: the walk notices that
    the frame numbers stop following on (they can line up by chance: 1 in 8 with x264's 4-bit frame_num)."""
    data = clips("h264")
    b = boxes(data)
    caught = 0
    for i in range(8):
        rng = random.Random(i)
        stop = rng.randrange(b["mdat"].start + 40 * KiB, b["moov"].start)
        media = bytearray(data[:stop])
        media[b["mdat"].start:b["mdat"].start + 4] = bytes(4)
        at = rng.randrange(64 * KiB, len(other) - 600 * KiB)
        img = rng.randbytes(AT) + bytes(media) + other[at:at + 512 * KiB]
        f, _files = found_at(img)
        assert f is not None and f.length >= stop - 4096
        caught += f.length <= stop + 4096
    assert caught >= 6


def test_unfinished_recording_without_sound(tmp_path):
    clip = make_video(tmp_path / "v.mp4", "libx264", None, seconds=2).read_bytes()
    b = boxes(clip)
    media = clip[:b["moov"].start]
    rng = random.Random(3)
    img = rng.randbytes(AT) + media + rng.randbytes(256 * KiB)
    f, _files = found_at(img)
    assert f is not None and f.info["needs_index"] and f.info["frames"] == len(video_samples(clip))
    assert f.length == len(media) and "audio" not in f.info


# ---------------------------------------------------------------------- fragmented recordings
def fragment(data: bytes, cs: int, k: int, fill: str, rng: random.Random, other: bytes, photo: bytes,
             after: int = 0) -> tuple[bytes, list[tuple[int, int]]]:
    """DATA split into K pieces at cluster boundaries inside its media data (the movie box stays whole; no cut
    before AFTER), each piece starting on a cluster, with FILL data in between; (the image, where the pieces
    are)."""
    b = boxes(data)
    samples = video_samples(data)
    lo = max(_up(b["mdat"].start + 16, cs) + cs, _up(after, cs))
    hi = samples[-1][0] // cs * cs - cs                  # the last piece holds the last frame
    places = range(lo // cs, hi // cs + 1)
    cuts = sorted(rng.sample(places, min(k - 1, len(places))))
    bounds = [0] + [c * cs for c in cuts] + [len(data)]
    img = bytearray(rng.randbytes(AT))
    where = []
    for a, e in zip(bounds, bounds[1:]):
        where.append((len(img), e - a))
        img += data[a:e]
        img += bytes(-len(img) % cs)
        n = cs * rng.randrange(1, 9)
        if fill == "random":
            img += rng.randbytes(n)
        elif fill == "zeros":
            img += bytes(n)
        elif fill == "video":                           # the middle of another camera's video
            s = rng.randrange(64 * KiB, len(other) - n)
            img += other[s:s + n]
        else:                                           # a photo (and the slack of its last cluster)
            img += (photo + rng.randbytes(n))[:max(n, _up(len(photo), cs))]
    img += rng.randbytes(64 * KiB)
    return bytes(img), where


@pytest.mark.parametrize("name", list(CLIPS))
@pytest.mark.parametrize("cs", [4096, 32768])
def test_fragmented_recording(clips, other, photo, tmp_path, name, cs):
    """2 to 5 pieces with random data, zeros, another video's middle or a photo in between: put back
    together byte for byte from the index (moov first or last)."""
    data = clips(name)
    for i, fill in enumerate(("random", "zeros", "video", "photo")):
        rng = random.Random(f"{name}{cs}{fill}")
        k = 2 + (i + len(name) + cs // 4096) % 4
        img, where = fragment(data, cs, k, fill, rng, other, photo)
        f, files = found_at(img)
        assert f is not None, (fill, where)
        assert f.pieces() == where, (fill, where, f.pieces())
        assert f.chance == CHANCE_FAIR and f.info["fragments"] == len(where) >= 2 and f.length == len(data)
        assert recovered(img, f) == data
        assert f.info["width"] == 320 and "needs_index" not in f.info and "uncertain_cuts" not in f.info
        assert not [x for x in files if x.key == "mp4" and x is not f], "a piece was taken for another file"
        if i == 0:
            judged(tmp_path, f"{name}-{cs}.{f.ext}", recovered(img, f), data)


def test_fragmented_hd_recording(tmp_path):
    """Bigger frames (1280x720): pieces of a few frames. (A cut inside the first, huge key frame can't be told
    from its neighbours when random data lies in between: that one is left out; see uncertain_cuts.)"""
    data = make_video(tmp_path / "hd.mp4", "libx264", "aac", seconds=4, size="1280x720", fps=30,
                      vargs=("-b:v", "4M")).read_bytes()
    rng = random.Random(7)
    first = video_samples(data)[0]
    img, where = fragment(data, 32768, 5, "random", rng, b"", b"", after=sum(first))
    f, _files = found_at(img)
    assert f is not None and f.pieces() == where and recovered(img, f) == data
    judged(tmp_path, "hd.mp4", recovered(img, f), data)


@pytest.mark.parametrize("name", MOOV_LAST)
def test_movie_box_in_its_own_fragment(clips, tmp_path, name):
    """The media data in one piece, the movie box (and the media data's last bytes) in another, after other
    files or before the start of the video: found and put together."""
    data = clips(name)
    b = boxes(data)
    cut = b["moov"].start // 4096 * 4096
    head, tail = data[:cut], data[cut:]
    rng = random.Random(name)
    gap = rng.randbytes(300 * KiB)
    img = rng.randbytes(AT) + head + bytes(-len(head) % 4096) + gap + tail + rng.randbytes(8 * KiB)
    f, files = found_at(img)
    tail_at = AT + _up(len(head), 4096) + len(gap)
    assert f is not None and f.pieces() == [(AT, cut), (tail_at, len(tail))], f and f.pieces()
    assert f.chance == CHANCE_FAIR and recovered(img, f) == data and len([x for x in files if x.key == "mp4"]) == 1
    # the movie box's piece lies before the start of the video on the disk
    lead = rng.randbytes(AT)
    img = lead + tail + bytes(-len(tail) % 4096) + gap + head + rng.randbytes(8 * KiB)
    start = len(lead) + _up(len(tail), 4096) + len(gap)
    f, _files = found_at(img, start)
    assert f is not None and f.pieces() == [(start, cut), (len(lead), len(tail))]
    assert recovered(img, f) == data
    judged(tmp_path, "moov-apart." + f.ext, recovered(img, f), data)


def test_movie_box_alone_is_not_a_file(clips):
    data = clips("h264")
    moov = data[boxes(data)["moov"].start:]
    rng = random.Random(9)
    img = rng.randbytes(AT) + moov + rng.randbytes(64 * KiB)
    _f, files = found_at(img)
    assert files == []


def test_damaged_recording(clips):
    """A fifth of the frames overwritten in place (nothing moved): the file is kept as it is, marked damaged,
    with a poor chance. (A dozen frames are checked: smaller damage that misses them all goes unnoticed.)"""
    for name in ("h264-faststart", "h264"):
        data = bytearray(clips(name))
        s = video_samples(bytes(data))
        a, e = s[len(s) * 2 // 5][0] // 4096 * 4096, s[len(s) * 3 // 5][0]
        data[a:e] = bytes(e - a)
        rng = random.Random(4)
        img = rng.randbytes(AT) + bytes(data) + rng.randbytes(64 * KiB)
        f, _files = found_at(img)
        assert f is not None and f.length == len(data) and f.chance == CHANCE_POOR, name
        assert "not where its index says" in f.info["note"]


# ---------------------------------------------------------------------- no false positives
def test_no_junk(tmp_path, clips):
    need_ffmpeg("libx264")
    rng = random.Random(11)
    assert list(carve(BytesSource(rng.randbytes(8 * MiB)), VIDEO)) == []
    # an H.264 elementary stream (no boxes at all), planted at block starts
    es = tmp_path / "v.h264"
    make_video(es, "libx264", None, seconds=2, fmt="h264")
    raw = es.read_bytes()
    img = bytearray(rng.randbytes(2 * MiB))
    for at in range(0, len(img) - len(raw), 512 * KiB):
        img[at:at + len(raw)] = raw
    assert list(carve(BytesSource(bytes(img)), VIDEO)) == []
    data = clips("h264")
    mdat = boxes(data)["mdat"]
    cases = [
        data[:20],                                                         # a truncated ftyp
        data[:mdat.start + 8],                                             # ftyp and mdat header only
        data[:mdat.start + 8] + rng.randbytes(64 * KiB),                   # and not video after them
        data[:mdat.start] + struct.pack(">I4s", 0, b"mdat") + bytes(64 * KiB),
        b"\0\0\0\x18ftypM4A \0\0\0\0M4A isom" + data[mdat.start:mdat.start + 32 * KiB],  # a sound file
    ]
    for i, case in enumerate(cases):
        img = rng.randbytes(AT) + case + rng.randbytes(128 * KiB)
        assert [x.description for x in carve(BytesSource(img), VIDEO)] == [], i


def test_media_checks_never_raise(clips):
    """Damaged media data and movie boxes: the checks answer, they don't raise."""
    data = clips("h264")
    rnd = random.Random(5)
    for _ in range(150):
        junk = bytearray(data)
        for _ in range(40):
            p = rnd.randrange(len(junk))
            junk[p] = rnd.randrange(256)
        src = BytesSource(bytes(junk))
        r = Reader(src, 0)
        mv = boxes(data)["moov"]
        M.quick_check(r, bytes(junk[mv.start:mv.end]), mv.start)
        M.scan_media(Reader(src, 0), 48, len(junk))
        M.assemble(Reader(src, 0), M.read_tables(bytes(junk[mv.start:mv.end])), len(junk), 48)
        list(carve(src, VIDEO))


# ---------------------------------------------------------------------- the whole pipeline
def test_scan_and_recover(clips, other, photo, tmp_path):
    """A disk image with a fragmented video, an unfinished recording and a whole one: the signature scan
    finds them, recovery writes the fragmented one back byte for byte and marks the unfinished one."""
    from recoverall.core.api import LocalAPI, wait_job

    frag = clips("hevc")
    unfinished = clips("h264")
    unfinished = unfinished[:boxes(unfinished)["moov"].start]
    whole = clips("mjpeg")
    rng = random.Random(21)
    img, where = fragment(frag, 32768, 3, "photo", rng, other, photo)
    img = bytearray(img)
    img += bytes(-len(img) % 4096) + unfinished + bytes(-len(unfinished) % 4096) + rng.randbytes(64 * KiB)
    img += bytes(-len(img) % 4096) + whole + rng.randbytes(64 * KiB)
    disk = tmp_path / "card.img"
    disk.write_bytes(bytes(img))
    api = LocalAPI()
    try:
        job = api.start_scan(source=str(disk), options={"mode": "carve", "formats": ["video"]})
        done = wait_job(api, job["id"], 120)
        assert done["state"] == "done", done.get("error")
        rows = api.scan_search(scan=job["scan"], filters={"exts": ["mp4", "mov"]}, limit=50)["rows"]
        by_size = {r["size"]: r for r in rows}
        assert len(frag) in by_size and len(unfinished) in by_size and len(whole) in by_size, rows
        e = api.scan_entry(scan=job["scan"], entry=by_size[len(frag)]["id"])
        assert e["fragments"] == 3 and e["chance"] == CHANCE_FAIR
        u = api.scan_entry(scan=job["scan"], entry=by_size[len(unfinished)]["id"])
        assert u["extra"]["info"]["needs_index"] is True and u["chance"] == CHANCE_POOR
        dest = tmp_path / "out"
        ids = [by_size[n]["id"] for n in (len(frag), len(unfinished), len(whole))]
        res = wait_job(api, api.start_recover(scan=job["scan"], entries=ids, dest=str(dest), options={})["id"], 120)
        assert res["state"] == "done", res.get("error")
        got = {p.stat().st_size: p.read_bytes() for p in dest.rglob("*") if p.suffix in (".mp4", ".mov")}
        assert got[len(frag)] == frag and got[len(whole)] == whole and got[len(unfinished)] == unfinished
        ok, errors = decode_check(next(p for p in dest.rglob("*.mp4") if p.stat().st_size == len(frag)))
        assert ok, errors[:5]
    finally:
        api.close()
