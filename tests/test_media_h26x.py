"""H.264 and H.265 bitstreams: parameter sets, slice headers, access units and picture order, against what
x264/x265 write and what ffprobe says about it."""

import random
from pathlib import Path

import pytest
from mediakit import ffmpeg, make_video, need_ffmpeg, probe_packets

from recoverall.core.media import h264, hevc
from recoverall.core.media import isobmff as I


def _ranks(pocs: list[int], resets: list[bool]) -> list[int]:
    """Showing order from the picture order counts, which start again at every IDR picture."""
    out = [0] * len(pocs)
    bounds = sorted({0, len(pocs), *(i for i, r in enumerate(resets) if r)})
    for a, b in zip(bounds, bounds[1:]):
        for r, i in enumerate(sorted(range(a, b), key=lambda i: pocs[i])):
            out[i] = a + r
    return out


def _check_stream(clip: Path, kind: str):
    buf = clip.read_bytes()
    movie, _boxes = I.movie_of(buf)
    v = movie.track("vide")
    if kind == "avc":
        cfg = h264.parse_avcc(v.config(b"avcC"))
        reader, state = h264.AvcReader(cfg.params(), cfg.length_size), h264.PocState()
    else:
        cfg = hevc.parse_hvcc(v.config(b"hvcC"))
        reader, state = hevc.HevcReader(cfg.params(), cfg.length_size), hevc.PocState()
    pocs, resets, keys = [], [], []
    for off, size in zip(v.sample_offsets(), v.sizes):
        au = reader.read(buf, off, len(buf))
        assert au is not None and au.size == size          # every sample is exactly one access unit
        poc = state.poc(au.header, au.sps)
        if kind == "avc" and au.second_field is not None:
            poc = min(poc, state.poc(au.second_field, au.sps))
        pocs.append(poc)
        resets.append(au.idr)
        keys.append(au.key)
    packets = probe_packets(clip, "v")
    shown = sorted(range(len(packets)), key=lambda i: packets[i]["pts"])
    assert sorted(range(len(pocs)), key=lambda i: _ranks(pocs, resets)[i]) == shown
    assert {i for i, k in enumerate(keys) if k} == v.keyframes()
    return reader


@pytest.mark.parametrize("vargs", [
    ("-g", "12", "-bf", "2"),
    ("-bf", "0"),                                               # picture order type 2
    ("-bf", "3", "-b_strategy", "2", "-g", "30"),               # B-pyramid
    ("-profile:v", "baseline"),
    ("-x264-params", "slices=4:repeat-headers=1"),              # several slices; SPS/PPS before key frames
    ("-x264-params", "interlaced=1", "-g", "7"),                # MBAFF
    ("-x264-params", "open-gop=1:keyint=20:min-keyint=20:scenecut=0"),   # key frames by recovery point SEI
])
def test_avc_access_units(tmp_path, vargs):
    clip = make_video(tmp_path / "a.mp4", "libx264", None, seconds=2.5, vargs=vargs)
    reader = _check_stream(clip, "avc")
    sps = next(iter(reader.params.sps.values()))
    assert (sps.width, sps.height) == (320, 240) and sps.fps == (50, 2)


@pytest.mark.parametrize("vargs", [
    ("-tag:v", "hvc1"),
    ("-g", "12"),                                               # open GOP: CRA key frames, RASL pictures
    ("-x265-params", "keyint=10:open-gop=0:bframes=4"),
    ("-x265-params", "repeat-headers=1:keyint=15"),
    ("-x265-params", "slices=3:bframes=0"),
])
def test_hevc_access_units(tmp_path, vargs):
    clip = make_video(tmp_path / "h.mp4", "libx265", None, seconds=2, vargs=vargs)
    reader = _check_stream(clip, "hevc")
    assert reader.params.fps() == (25, 1)
    sps = next(iter(reader.params.sps.values()))
    assert (sps.width, sps.height) == (320, 240)


def test_configuration_records(tmp_path):
    clip = make_video(tmp_path / "a.mp4", "libx264", None, seconds=0.5, size="640x360")
    v = I.movie_of(clip.read_bytes())[0].track("vide")
    raw = v.config(b"avcC")
    cfg = h264.parse_avcc(raw)
    assert h264.build_avcc(cfg.sps, cfg.pps, cfg.length_size) == raw
    s = h264.parse_sps(cfg.sps[0])
    assert (s.width, s.height, s.profile, s.chroma_format) == (640, 360, 100, 1)
    clip = make_video(tmp_path / "h.mp4", "libx265", None, seconds=0.5, size="640x360")
    v = I.movie_of(clip.read_bytes())[0].track("vide")
    cfg = hevc.parse_hvcc(v.config(b"hvcC"))
    vps, sps, pps = (cfg.nals(t) for t in (hevc.VPS_NAL, hevc.SPS_NAL, hevc.PPS_NAL))
    built = hevc.parse_hvcc(hevc.build_hvcc(vps, sps, pps))
    assert built.nals(hevc.SPS_NAL) == sps and built.nals(hevc.PPS_NAL) == pps and built.length_size == 4
    s = hevc.parse_sps(sps[0])
    assert (s.width, s.height, s.max_num_reorder) == (640, 360, 2)


def test_annexb(tmp_path):
    need_ffmpeg("libx264", "libx265")
    src = ["-f", "lavfi", "-i", "testsrc2=size=320x240:rate=25:duration=1"]
    ffmpeg(*src, "-c:v", "libx264", "-bf", "2", "-f", "h264", tmp_path / "a.h264")
    raw = (tmp_path / "a.h264").read_bytes()
    nals = [raw[a:b] for a, b in h264.iter_annexb(raw)]
    assert [n[0] & 31 for n in nals[:4]] == [h264.SPS_NAL, h264.PPS_NAL, h264.SEI, h264.IDR]
    assert sum(1 for n in nals if n[0] & 31 in (h264.SLICE, h264.IDR)) == 25
    assert h264.annexb(nals).replace(b"\x00\x00\x00\x01", b"") == b"".join(nals)
    ps = h264.ParamSets()
    assert ps.add(nals[0]) and ps.add(nals[1])
    ffmpeg(*src, "-c:v", "libx265", "-f", "hevc", tmp_path / "a.hevc")
    raw = (tmp_path / "a.hevc").read_bytes()
    types = [hevc.nal_type(raw[a]) for a, _b in h264.iter_annexb(raw)]
    assert types[:3] == [hevc.VPS_NAL, hevc.SPS_NAL, hevc.PPS_NAL] and hevc.IDR_N_LP in types


def test_in_band_parameter_sets(tmp_path):
    clip = make_video(tmp_path / "a.mp4", "libx264", "aac", seconds=1, vargs=("-x264-params", "repeat-headers=1"))
    buf = clip.read_bytes()
    mdat = next(b for b in I.top_level(buf) if b.type == b"mdat")
    ps = h264.find_params(buf, mdat.payload, mdat.end)
    assert ps and next(iter(ps.sps.values())).width == 320
    clip = make_video(tmp_path / "h.mp4", "libx265", "aac", seconds=1, vargs=("-x265-params", "repeat-headers=1"))
    buf = clip.read_bytes()
    mdat = next(b for b in I.top_level(buf) if b.type == b"mdat")
    ps = hevc.find_params(buf, mdat.payload, mdat.end)
    assert ps and ps.vps and ps.fps() == (25, 1)
    assert not h264.find_params(bytes(range(256)) * 64, 0, 16384)


def test_garbage_never_raises(tmp_path):
    clip = make_video(tmp_path / "a.mp4", "libx264", None, seconds=0.5)
    v = I.movie_of(clip.read_bytes())[0].track("vide")
    cfg = h264.parse_avcc(v.config(b"avcC"))
    reader = h264.AvcReader(cfg.params(), 4)
    rnd = random.Random(3)
    for _ in range(300):
        junk = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 200)))
        h264.parse_sps(b"\x67" + junk)
        h264.parse_pps(b"\x68" + junk)
        h264.parse_slice_header(b"\x65" + junk, reader.params)
        h264.sei_messages(b"\x06" + junk)
        reader.read(b"\x00\x00\x00" + bytes([len(junk)]) + junk, 0, len(junk) + 4)
        hevc.parse_sps(b"\x42\x01" + junk)
        hevc.parse_vps(b"\x40\x01" + junk)
        hevc.parse_pps(b"\x44\x01" + junk)
        hevc.parse_hvcc(junk)
        h264.parse_avcc(junk)
    # random data is not taken for pictures
    noise = bytes(rnd.randrange(256) for _ in range(200000))
    assert sum(reader.read(noise, i, len(noise)) is not None for i in range(0, 200000, 7)) == 0
