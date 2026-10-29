"""Measuring audio frames. AAC raw data blocks against what ffmpeg's encoder wrote (the lengths in its ADTS
headers, the sample tables of its MP4 files), synthetic frames using the syntax the encoder never writes (judged
by ffmpeg's decoder), wrong positions that must not pass for frames; AMR, AC-3, E-AC-3, MPEG audio and PCM."""

import random
import time
from pathlib import Path

import pytest
from mediakit import decode_check, ffmpeg, frame_count, make_video, need_ffmpeg, probe, probe_packets

from recoverall.core.media import aac, aac_tables, isobmff
from recoverall.core.media import audioframes as af


# ---------------------------------------------------------------------- AAC from ffmpeg
def _signal(rate: int, channels: int, seconds: float) -> list[str]:
    """Tones, chirps and noise bursts (the bursts make the encoder switch to short windows), different in every
    channel."""
    exprs = []
    for k in range(channels):
        exprs.append(f"0.3*sin(2*PI*{220 * (k + 1)}*t)*(1+sin(2*PI*{k + 2}*t))/2"
                     f"+0.25*random({k})*gt(mod(t+{k / 10},0.7),0.6)+0.15*sin(2*PI*(200+{1500 + 300 * k}*t)*t)")
    return ["-f", "lavfi", "-i", f"aevalsrc='{'|'.join(exprs)}':s={rate}:d={seconds}"]


def make_adts(path: Path, rate: int = 48000, channels: int = 2, args: tuple = (), seconds: float = 2.0) -> bytes:
    need_ffmpeg("aac")
    ffmpeg(*_signal(rate, channels, seconds), "-c:a", "aac", "-strict", "-2", *args, "-f", "adts", path)
    return Path(path).read_bytes()


def adts_frames(data: bytes) -> tuple[aac.AudioSpecificConfig, list[bytes]]:
    """The configuration and the raw frames of an ADTS stream, cut by its headers (the ground truth)."""
    frames, pos, asc = [], 0, None
    while pos < len(data):
        found = aac.parse_adts(data, pos)
        assert found is not None, f"no ADTS header at {pos}"
        asc, header, n = found
        frames.append(data[pos + header:pos + n])
        pos += n
    return asc, frames


def check_split(asc, frames: list[bytes]) -> int:
    raw = b"".join(frames)
    sizes = [len(f) for f in frames]
    assert aac.split_frames(raw, 0, len(raw), asc) == sizes
    pos = 0
    for n in sizes:                                         # every frame on its own, and as a frame start
        assert aac.frame_length(raw, pos, len(raw), asc, strict=True) == n
        assert aac.is_frame(raw, pos, pos + n, asc)
        pos += n
    return len(sizes)


RATES = [8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000, 64000, 88200, 96000, 7350]


@pytest.mark.parametrize("rate", RATES)
def test_aac_rates(tmp_path, rate):
    asc, frames = adts_frames(make_adts(tmp_path / "a.aac", rate, 2, ("-b:a", "96k")))
    assert asc.sample_rate == rate and asc.channels == 2
    assert check_split(asc, frames) == len(frames) > 10


@pytest.mark.parametrize("channels,bitrate", [(2, "32k"), (2, "64k"), (2, "128k"), (2, "256k"), (2, "320k"),
                                              (1, "32k"), (1, "160k"), (6, "384k")])
def test_aac_bitrates(tmp_path, channels, bitrate):
    asc, frames = adts_frames(make_adts(tmp_path / "a.aac", 48000, channels, ("-b:a", bitrate)))
    check_split(asc, frames)


@pytest.mark.parametrize("coder", ["twoloop", "fast"])
@pytest.mark.parametrize("tools", [(), ("-aac_tns", "1"), ("-aac_tns", "0"), ("-aac_is", "1"), ("-aac_is", "0"),
                                   ("-aac_pns", "1"), ("-aac_pns", "0"), ("-aac_ms", "1"), ("-aac_ms", "0")])
def test_aac_coding_tools(tmp_path, coder, tools):
    asc, frames = adts_frames(make_adts(tmp_path / "a.aac", 44100, 2, ("-aac_coder", coder, *tools, "-b:a", "96k")))
    check_split(asc, frames)


@pytest.mark.parametrize("profile,object_type", [(("-profile:a", "aac_main", "-aac_pred", "1"), 1),
                                                 (("-profile:a", "aac_ltp", "-aac_ltp", "1"), 4),
                                                 (("-profile:a", "aac_low"), 2)])
@pytest.mark.parametrize("channels", [1, 2, 6])
def test_aac_profiles(tmp_path, profile, object_type, channels):
    asc, frames = adts_frames(make_adts(tmp_path / "a.aac", 48000, channels, (*profile, "-b:a", "128k")))
    assert asc.object_type == object_type
    check_split(asc, frames)


@pytest.mark.parametrize("channels,pce", [(3, ()), (4, ()), (5, ()), (7, ()), (8, ()), (2, ("-aac_pce", "1")),
                                          (6, ("-aac_pce", "1"))])
def test_aac_channel_layouts(tmp_path, channels, pce):
    # 3 and 7 channels (and -aac_pce) have no channel configuration: the first frame carries a PCE
    asc, frames = adts_frames(make_adts(tmp_path / "a.aac", 48000, channels, ("-b:a", "256k", *pce)))
    check_split(asc, frames)


def test_aac_mono_stereo_swap(tmp_path):
    # streams that say mono but code a CPE, or stereo with one SCE, exist: such frames are taken, but a run of
    # frames keeps the channel elements of its first frame
    _asc, mono = adts_frames(make_adts(tmp_path / "m.aac", 48000, 1, ("-b:a", "64k")))
    _asc, stereo = adts_frames(make_adts(tmp_path / "s.aac", 48000, 2, ("-b:a", "96k")))
    as_stereo = aac.AudioSpecificConfig(2, 48000, 3, 2, 2, 1024)
    as_mono = aac.AudioSpecificConfig(2, 48000, 3, 1, 1, 1024)
    for cfg in (as_stereo, as_mono):
        for frames in (mono, stereo):
            raw = b"".join(frames)
            assert aac.split_frames(raw, 0, len(raw), cfg) == [len(f) for f in frames]
        mixed = b"".join(stereo[:5] + mono[5:10])
        assert aac.split_frames(mixed, 0, len(mixed), cfg) == [len(f) for f in stereo[:5]]
        mixed = b"".join(mono[:5] + stereo[5:10])
        assert aac.split_frames(mixed, 0, len(mixed), cfg) == [len(f) for f in mono[:5]]
    surround = aac.AudioSpecificConfig(2, 48000, 3, 6, 6, 1024)
    assert aac.frame_length(stereo[3], 0, len(stereo[3]), surround) is None
    # strict: only what the configuration says
    m, s = mono[3], stereo[3]
    assert aac.is_frame(m, 0, len(m), as_mono) and not aac.is_frame(m, 0, len(m), as_stereo)
    assert aac.is_frame(s, 0, len(s), as_stereo) and not aac.is_frame(s, 0, len(s), as_mono)
    assert aac.is_frame(s, 0, len(s), as_mono, strict=False)
    assert aac.frame_length(m, 0, len(m), as_stereo, strict=True) is None
    raw = b"".join(mono[:5])
    assert aac.split_frames(raw, 0, len(raw), as_stereo, strict=True) == []


def _chunks(track):
    for off, first, n in track.chunks():
        yield off, track.sizes[first:first + n]


@pytest.mark.parametrize("rate,channels,aargs", [(48000, 2, ()), (44100, 1, ("-b:a", "64k")),
                                                 (48000, 6, ("-b:a", "320k")), (48000, 2, ("-aac_pce", "1")),
                                                 (32000, 2, ("-profile:a", "aac_main", "-aac_pred", "1"))])
def test_aac_in_mp4(tmp_path, rate, channels, aargs):
    clip = make_video(tmp_path / "a.mp4", "libx264", "aac", seconds=3, sample_rate=rate, channels=channels,
                      aargs=aargs)
    buf = clip.read_bytes()
    movie, _boxes = isobmff.movie_of(buf)
    audio = movie.track("soun")
    asc = aac.parse_esds(audio.config(b"esds"))
    assert asc is not None and asc.sample_rate == rate and asc.channels == channels and asc.frame_length == 1024
    assert (asc.channel_config == 0) == bool(aargs and aargs[0] == "-aac_pce")
    verified = overrun = 0
    for off, sizes in _chunks(audio):
        assert aac.split_frames(buf, off, off + sum(sizes), asc) == sizes
        more = aac.split_frames(buf, off, len(buf), asc, limit=len(sizes) + 1)
        assert more[:len(sizes)] == sizes
        overrun += len(more) > len(sizes) and off + sum(sizes) not in set(audio.sample_offsets())
        verified += len(sizes)
    assert verified == audio.samples
    assert overrun == 0                                     # the frames end where the video begins


def test_aac_speed(tmp_path):
    asc, frames = adts_frames(make_adts(tmp_path / "a.aac", 48000, 2, ("-b:a", "128k"), seconds=12))
    raw = b"".join(frames)
    t = time.perf_counter()
    sizes = aac.split_frames(raw, 0, len(raw), asc)
    rate = len(sizes) / (time.perf_counter() - t)
    print(f"AAC 128 kb/s stereo 48 kHz: {rate:.0f} frames/s")
    assert sizes == [len(f) for f in frames]
    assert rate > 1500


# ---------------------------------------------------------------------- configuration and ADTS
def test_esds_and_asc(tmp_path):
    clip = make_video(tmp_path / "a.mp4", None, "aac", seconds=1, sample_rate=44100, channels=2)
    movie, _ = isobmff.movie_of(clip.read_bytes())
    esds = movie.track("soun").config(b"esds")
    asc = aac.parse_esds(esds)
    assert (asc.object_type, asc.sample_rate, asc.sample_rate_index, asc.channel_config, asc.channels,
            asc.frame_length, asc.sbr, asc.ps) == (2, 44100, 4, 2, 2, 1024, False, False)
    assert aac.parse_esds(esds[4:]) == asc                  # without the version and flags
    oti = _oti_offset(esds)
    assert esds[oti] == 0x40
    assert aac.parse_esds(esds[:oti] + b"\x6b" + esds[oti + 1:]) is None     # MP3
    assert aac.parse_esds(esds[:oti] + b"\x67" + esds[oti + 1:]) == asc      # MPEG-2 AAC LC

    def asc_bits(*fields) -> bytes:
        v, n = 0, 0
        for value, bits in fields:
            v, n = (v << bits) | value, n + bits
        v <<= -n % 8
        return v.to_bytes((n + 7) // 8, "big")
    he = aac.parse_asc(asc_bits((5, 5), (6, 4), (2, 4), (3, 4), (2, 5), (0, 3)))          # explicit SBR
    assert (he.object_type, he.sample_rate, he.ext_sample_rate, he.sbr, he.ps) == (2, 24000, 48000, True, False)
    assert he.name == "HE-AAC"
    v2 = aac.parse_asc(asc_bits((29, 5), (6, 4), (1, 4), (3, 4), (2, 5), (0, 3)))          # explicit PS
    assert (v2.channels, v2.sbr, v2.ps) == (1, True, True)
    bc = aac.parse_asc(asc_bits((2, 5), (6, 4), (2, 4), (0, 3), (0x2B7, 11), (5, 5), (1, 1), (3, 4),
                                (0x548, 11), (1, 1)))                                       # backward compatible
    assert (bc.object_type, bc.sbr, bc.ps, bc.ext_sample_rate) == (2, True, True, 48000)
    ex = aac.parse_asc(asc_bits((2, 5), (15, 4), (37800, 24), (1, 4), (1, 1), (0, 2)))      # explicit rate, 960
    assert (ex.sample_rate, ex.sample_rate_index, ex.frame_length, ex.channels) == (37800, 15, 960, 1)
    assert aac.parse_asc(asc_bits((2, 5), (13, 4), (2, 4), (0, 3))) is None                 # reserved rate
    assert aac.parse_asc(asc_bits((2, 5), (3, 4), (9, 4), (0, 3))) is None                  # reserved layout
    assert aac.parse_asc(b"") is None and aac.parse_asc(b"\x12") is None
    rnd = random.Random(3)
    for _ in range(2000):                                   # garbage never raises
        junk = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 12)))
        aac.parse_asc(junk)
        aac.parse_esds(b"\0\0\0\0\x03" + junk)


def _oti_offset(esds: bytes) -> int:
    """Where the objectTypeIndication is in an esds payload (an ES_Descriptor without optional fields)."""
    p = 4
    assert esds[p] == 3
    p += 1
    while esds[p] & 0x80:
        p += 1
    p += 4                                                  # the size's last byte, ES_ID, flags
    assert esds[p] == 4
    p += 1
    while esds[p] & 0x80:
        p += 1
    return p + 1


def test_asc_with_pce(tmp_path):
    clip = make_video(tmp_path / "a.mp4", None, "aac", seconds=1, channels=6, aargs=("-aac_pce", "1"))
    movie, _ = isobmff.movie_of(clip.read_bytes())
    asc = aac.parse_esds(movie.track("soun").config(b"esds"))
    assert asc.channel_config == 0 and asc.channels == 6
    pce = asc.pce
    assert isinstance(pce, aac.ProgramConfig) and pce.channels == 6 and pce.sample_rate_index == 3
    assert pce.comment.startswith(b"Lavc")
    audio = movie.track("soun")
    buf = clip.read_bytes()
    for off, sizes in _chunks(audio):                       # the frames hold the PCE's elements
        assert aac.split_frames(buf, off, off + sum(sizes), asc) == sizes
    other = aac.AudioSpecificConfig(2, 48000, 3, 0, 6, 1024, pce=aac.ProgramConfig(front=[(False, 0)] * 6))
    off = audio.sample_offsets()[3]
    assert aac.frame_length(buf, off, len(buf), other) is None


def test_adts_round_trip(tmp_path):
    data = make_adts(tmp_path / "a.aac", 44100, 2, ("-b:a", "128k"))
    asc, frames = adts_frames(data)
    assert (asc.object_type, asc.sample_rate, asc.channel_config) == (2, 44100, 2)
    found = aac.parse_adts(data, 0)
    assert found[1] == 7 and aac.adts_header(asc, len(frames[0])) == data[:7]
    # raw frames from an MP4 file, saved as an ADTS stream with our headers: ffmpeg decodes all of them
    clip = make_video(tmp_path / "a.mp4", None, "aac", seconds=2, sample_rate=32000, channels=1)
    buf = clip.read_bytes()
    audio = isobmff.movie_of(buf)[0].track("soun")
    asc = aac.parse_esds(audio.config(b"esds"))
    out = tmp_path / "salvaged.aac"
    out.write_bytes(b"".join(aac.adts_header(asc, n) + buf[o:o + n]
                             for o, n in zip(audio.sample_offsets(), audio.sizes)))
    assert frame_count(out, "a") == audio.samples
    ok, errors = decode_check(out)
    assert ok, errors
    assert probe(out)["streams"][0]["sample_rate"] == "32000"
    assert aac.parse_adts(b"\xff\xf1\x50", 0) is None and aac.parse_adts(bytes(7), 0) is None


# ---------------------------------------------------------------------- AAC: wrong positions
def test_aac_wrong_positions(tmp_path):
    clip = make_video(tmp_path / "a.mp4", "libx264", "aac", seconds=6, size="640x360", aargs=("-b:a", "128k"))
    buf = clip.read_bytes()
    movie, _ = isobmff.movie_of(buf)
    video, audio = movie.track("vide"), movie.track("soun")
    asc = aac.parse_esds(audio.config(b"esds"))
    mono = aac.AudioSpecificConfig(2, 48000, 3, 1, 1, 1024)
    rnd = random.Random(7)
    # 10 000 positions inside H.264 samples: is_frame must (nearly) never say audio
    offsets = [(o, n) for o, n in zip(video.sample_offsets(), video.sizes) if n > 16]
    positions = [o + rnd.randrange(n) for o, n in (rnd.choice(offsets) for _ in range(10000))]
    for cfg in (asc, mono):
        strict = sum(aac.is_frame(buf, p, len(buf), cfg) for p in positions)
        lenient = sum(aac.frame_length(buf, p, len(buf), cfg) is not None for p in positions)
        print(f"H.264 positions taken for AAC ({cfg.channels} ch): is_frame {strict / 100:.2f} %, "
              f"frame_length {lenient / 100:.2f} %")
        assert strict <= 10 and lenient <= 10              # < 0.1 %
    # inside audio frames (not at their start)
    starts = set(audio.sample_offsets())
    inside = [o + rnd.randrange(1, n) for o, n in zip(audio.sample_offsets(), audio.sizes) for _ in range(20)]
    hits = sum(aac.is_frame(buf, p, len(buf), asc) for p in inside if p not in starts)
    print(f"positions inside AAC frames taken for frames: {hits} of {len(inside)}")
    assert hits <= len(inside) // 1000
    # random bytes, zeros, ones; a frame cut short
    junk = rnd.randbytes(1 << 18)
    for data in (junk, bytes(4096), b"\xff" * 4096):
        assert sum(aac.frame_length(data, rnd.randrange(len(data) - 64), len(data), asc) is not None
                   for _ in range(3000)) <= 3
    o, n = audio.sample_offsets()[5], audio.sizes[5]
    assert aac.frame_length(buf, o, o + n, asc) == n and aac.frame_length(buf, o, o + n - 1, asc) is None
    assert aac.split_frames(buf, o, o + n - 1, asc) == []
    for _ in range(300):                                    # damaged frames never raise
        frame = bytearray(buf[o:o + n])
        for _ in range(rnd.randrange(1, 6)):
            frame[rnd.randrange(n)] = rnd.randrange(256)
        aac.frame_length(bytes(frame), 0, n, asc)
        aac.is_frame(frame, 0, n, asc)
    assert aac.frame_length(buf, o, o + n, aac.AudioSpecificConfig(17, 48000, 3, 2, 2, 1024)) is None   # ER


# ---------------------------------------------------------------------- AAC: synthetic frames
class BitWriter:
    def __init__(self):
        self.v = self.n = 0

    def put(self, value: int, bits: int) -> None:
        assert 0 <= value < 1 << bits or bits == 0
        self.v = (self.v << bits) | value
        self.n += bits

    def align(self) -> None:
        self.put(0, -self.n % 8)

    def data(self) -> bytes:
        return self.v.to_bytes(self.n // 8, "big")


class Synth:
    """Random but valid raw data blocks: every window sequence and grouping, all codebooks with escapes, M/S,
    intensity, noise, pulses, TNS, Main prediction, LTP, DSE and FIL elements."""

    def __init__(self, asc: aac.AudioSpecificConfig, seed: int, dse: bool = True):
        self.asc, self.rnd, self.dse = asc, random.Random(seed), dse
        self.idx = asc.sample_rate_index
        n = asc.frame_length
        self.swb_long = [o for o in aac_tables.SWB_LONG[self.idx] if o < n] + [n]
        self.swb_short = [o for o in aac_tables.SWB_SHORT[self.idx] if o < n // 8] + [n // 8]

    def scf(self, w, delta):
        lengths, codes = aac_tables.SCALEFACTOR
        w.put(codes[delta + 60], lengths[delta + 60])

    def ics_info(self, w, common, lfe=False):
        r = self.rnd
        ws = 0 if lfe else r.choice((0, 0, 1, 2, 2, 3))
        w.put(0, 1), w.put(ws, 2), w.put(r.randrange(2), 1)
        if ws == 2:
            max_sfb, grouping = r.randint(0, len(self.swb_short) - 1), r.randrange(128)
            w.put(max_sfb, 4), w.put(grouping, 7)
            groups = [1]
            for k in range(6, -1, -1):
                if grouping >> k & 1:
                    groups[-1] += 1
                else:
                    groups.append(1)
            return ws, max_sfb, groups
        max_sfb = r.randint(0, len(self.swb_long) - 1)
        w.put(max_sfb, 6)
        pred = self.asc.object_type in (1, 4) and not lfe and r.random() < 0.6
        w.put(int(pred), 1)
        if pred and self.asc.object_type == 1:
            reset = r.randrange(2)
            w.put(reset, 1)
            if reset:
                w.put(r.randint(1, 30), 5)
            for _ in range(min(max_sfb, aac.PRED_SFB_MAX[self.idx])):
                w.put(r.randrange(2), 1)
        elif pred:
            for _ in range(2 if common else 1):
                present = r.randrange(2)
                w.put(present, 1)
                if present:
                    w.put(r.randrange(2048), 11), w.put(r.randrange(8), 3)
                    for _ in range(min(max_sfb, 40)):
                        w.put(r.randrange(2), 1)
        return ws, max_sfb, [1]

    def ics(self, w, info=None, intensity=False, lfe=False):
        r = self.rnd
        gain = r.randint(100, 180)
        w.put(gain, 8)
        if info is None:
            info = self.ics_info(w, False, lfe)
        ws, max_sfb, groups = info
        swb = self.swb_short if ws == 2 else self.swb_long
        bits, esc = (3, 7) if ws == 2 else (5, 31)
        sections = []
        books = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 11, 13) + ((14, 15) if intensity else ())
        for gl in groups:
            k = 0
            while k < max_sfb:
                n = r.randint(1, max_sfb - k) if r.random() < 0.3 else r.randint(1, min(4, max_sfb - k))
                cb = r.choice(books)
                w.put(cb, 4)
                left = n
                while left >= esc:
                    w.put(esc, bits)
                    left -= esc
                w.put(left, bits)
                sections.append((gl, k, k + n, cb))
                k += n
        sf, noise, position, first = gain, gain - 90, 0, True
        for _gl, a, b, cb in sections:
            for _ in range(b - a):
                if cb in (14, 15):
                    d = r.randint(max(-5, -155 - position), min(5, 100 - position))
                    position += d
                    self.scf(w, d)
                elif cb == 13 and first:
                    first = False
                    v = r.randint(246, 266)
                    noise += v - 256
                    w.put(v, 9)
                elif cb == 13:
                    d = r.randint(max(-5, -100 - noise), min(5, 155 - noise))
                    noise += d
                    self.scf(w, d)
                elif cb:
                    d = r.randint(max(-12, -sf), min(12, 255 - sf))
                    sf += d
                    self.scf(w, d)
        if ws != 2 and not lfe and r.random() < 0.4:           # pulse_data
            w.put(1, 1)
            count, start = r.randrange(4), r.randrange(len(swb) - 4)
            w.put(count, 2), w.put(start, 6)
            k = swb[start]
            for _ in range(count + 1):
                off = r.randrange(32) if k + 31 < swb[-1] else 0
                k += off
                w.put(off, 5), w.put(r.randrange(16), 4)
        else:
            w.put(0, 1)
        if r.random() < 0.5:                                    # tns_data
            w.put(1, 1)
            for _ in range(8 if ws == 2 else 1):
                n_filt = r.randrange(2) if ws == 2 else r.randrange(4)
                w.put(n_filt, 1 if ws == 2 else 2)
                if n_filt:
                    res = r.randrange(2)
                    w.put(res, 1)
                    for _ in range(n_filt):
                        top = 7 if ws == 2 else 20 if self.asc.object_type == 1 else 12
                        order = r.randint(0, top)
                        w.put(r.randrange(16 if ws == 2 else 64), 4 if ws == 2 else 6)
                        w.put(order, 3 if ws == 2 else 5)
                        if order:
                            comp = r.randrange(2)
                            w.put(r.randrange(2), 1), w.put(comp, 1)
                            for _ in range(order):
                                w.put(r.randrange(1 << (3 + res - comp)), 3 + res - comp)
        else:
            w.put(0, 1)
        if self.asc.object_type == 3 and r.random() < 0.6:     # gain_control_data (AAC SSR)
            w.put(1, 1)
            bands = r.randrange(4)
            w.put(bands, 2)
            for _ in range(bands):
                for bits in ((5,), (4, 2), (2,) * 8, (4, 5))[ws]:   # aloccode widths per window
                    n = r.randrange(8)
                    w.put(n, 3)
                    for _ in range(n):
                        w.put(r.randrange(16), 4), w.put(r.randrange(1 << bits), bits)
        else:
            w.put(0, 1)
        for gl, a, b, cb in sections:
            if 1 <= cb <= 11:
                self.spectral(w, cb, gl * (swb[b] - swb[a]))
        return info, sum(b - a for _gl, a, b, cb in sections if cb)

    def spectral(self, w, cb, lines):
        r = self.rnd
        lengths, codes = aac_tables.SPECTRAL[cb]
        dim = 4 if cb <= 4 else 2
        signed = cb in (1, 2, 5, 6)
        lav = {1: 1, 2: 1, 3: 2, 4: 2, 5: 4, 6: 4, 7: 7, 8: 7, 9: 12, 10: 12, 11: 16}[cb]
        mod = 2 * lav + 1 if signed else lav + 1
        zero = sum(lav * mod ** k for k in range(dim)) if signed else 0
        for _ in range(lines // dim):
            i = r.randrange(len(codes)) if r.random() < 0.5 else zero
            w.put(codes[i], lengths[i])
            values, k = [], i
            for _ in range(dim):
                values.append(k % mod - (lav if signed else 0))
                k //= mod
            for v in reversed(values):
                if v and not signed:
                    w.put(r.randrange(2), 1)
            for v in reversed(values):
                if cb == 11 and v == 16:
                    e = r.randrange(16, 8192)
                    n = e.bit_length() - 5
                    w.put((1 << (n + 1)) - 2, n + 1)
                    w.put(e - (1 << (n + 4)), n + 4)

    def cpe(self, w, tag: int) -> None:
        r = self.rnd
        w.put(aac.ID_CPE, 3), w.put(tag, 4)
        common = r.random() < 0.7
        w.put(int(common), 1)
        if common:
            info = self.ics_info(w, True)
            ms = r.randrange(3)
            w.put(ms, 2)
            if ms == 1:
                for _ in range(len(info[2]) * info[1]):
                    w.put(r.randrange(2), 1)
            self.ics(w, info)
            self.ics(w, info, intensity=True)
        else:
            self.ics(w)
            self.ics(w)

    def frame(self) -> bytes:
        r, cfg = self.rnd, self.asc.channel_config
        w = BitWriter()
        if r.random() < 0.3:                                    # FIL: an EXT_FILL payload
            n = r.choice((1, 5, 14, 15, 40))
            w.put(aac.ID_FIL, 3)
            if n < 15:
                w.put(n, 4)
            else:
                w.put(15, 4), w.put(n - 14, 8)
            w.put(0, 4)
            for _ in range(2 * n - 1):
                w.put(r.randrange(16), 4)
        for k, eid in enumerate(aac.CONFIG_ELEMENTS[cfg]):
            tag = 1 if eid == aac.ID_CPE and k > 1 else 0      # instance tags as encoders number them
            if eid == aac.ID_CPE:
                self.cpe(w, tag)
            else:
                w.put(eid, 3), w.put(tag, 4)
                self.ics(w, lfe=eid == aac.ID_LFE)
            if self.dse and r.random() < 0.15:                  # DSE
                n = r.choice((0, 3, 255, 300))
                w.put(aac.ID_DSE, 3), w.put(0, 4)
                align = r.randrange(2)
                w.put(align, 1), w.put(min(n, 255), 8)
                if n >= 255:
                    w.put(n - 255, 8)
                if align:
                    w.align()
                for _ in range(n):
                    w.put(r.randrange(256), 8)
        w.put(aac.ID_END, 3)
        w.align()
        return w.data()


@pytest.mark.parametrize("object_type,rate,channels,count", [(2, 48000, 2, 60), (2, 8000, 1, 40), (1, 44100, 2, 60),
                                                             (4, 48000, 2, 60), (4, 96000, 1, 40), (2, 22050, 6, 25),
                                                             (1, 16000, 6, 20), (3, 48000, 2, 40)])
def test_aac_synthetic_frames(tmp_path, object_type, rate, channels, count):
    index = aac_tables.SAMPLE_RATES.index(rate)
    asc = aac.AudioSpecificConfig(object_type, rate, index, channels, channels, 1024)
    synth = Synth(asc, seed=object_type * 1000 + rate + channels)
    frames = []
    while len(frames) < count:
        f = synth.frame()
        if len(f) * 8 <= aac.MAX_FRAME_BITS * channels:
            frames.append(f)
    raw = b"".join(frames)
    assert aac.split_frames(raw, 0, len(raw), asc, strict=True) == [len(f) for f in frames]
    if object_type == 3:
        return                                              # ffmpeg doesn't decode AAC SSR
    # ffmpeg's decoder reads them the same way: it decodes every frame without an error
    need_ffmpeg()
    out = tmp_path / "synth.aac"
    out.write_bytes(b"".join(aac.adts_header(asc, len(f)) + f for f in frames))
    assert frame_count(out, "a") == count
    ok, errors = decode_check(out)
    assert ok, errors[:5]


def loas(asc_fields: list[tuple[int, int]], frames: list[bytes]) -> bytes:
    """A LOAS/LATM stream (what ffmpeg's "latm" muxer writes): the AudioSpecificConfig (as (value, bits)
    fields) in the first frame's StreamMuxConfig, then every frame with its length. LATM is the only way to hand
    ffmpeg frames of 960 lines: ADTS can't say so."""
    out = b""
    for k, f in enumerate(frames):
        w = BitWriter()
        w.put(int(k > 0), 1)                                # useSameStreamMux
        if k == 0:
            for v, n in ((0, 1), (1, 1), (0, 6), (0, 4), (0, 3)):   # version 0, one program, layer, subframe
                w.put(v, n)
            for v, n in asc_fields:
                w.put(v, n)
            w.put(0, 3), w.put(0xFF, 8), w.put(0, 1), w.put(0, 1)  # frame length type 0, fullness, no extras
        n = len(f)
        while n >= 255:
            w.put(255, 8)
            n -= 255
        w.put(n, 8)
        w.put(int.from_bytes(f, "big"), 8 * len(f))
        w.align()
        body = w.data()
        out += ((0x2B7 << 13) | len(body)).to_bytes(3, "big") + body
    return out


@pytest.mark.parametrize("object_type,rate,channels", [(2, 48000, 2), (2, 24000, 1), (2, 44100, 2), (2, 8000, 1),
                                                       (2, 96000, 2), (1, 32000, 2), (4, 16000, 2)])
def test_aac_960_frames(tmp_path, object_type, rate, channels):
    # frames of 960 lines (frameLengthFlag; DAB+ uses them) have their own band tables: ffmpeg's LATM decoder
    # reads synthetic ones the way we measure them (no DSEs: LATM aligns their bytes differently)
    need_ffmpeg()
    index = aac_tables.SAMPLE_RATES.index(rate)
    asc = aac.AudioSpecificConfig(object_type, rate, index, channels, channels, 960)
    synth = Synth(asc, seed=rate + channels, dse=False)
    frames = [synth.frame() for _ in range(40)]
    raw = b"".join(frames)
    assert aac.split_frames(raw, 0, len(raw), asc, strict=True) == [len(f) for f in frames]
    out = tmp_path / "a.loas"
    out.write_bytes(loas([(object_type, 5), (index, 4), (channels, 4), (1, 1), (0, 1), (0, 1)], frames))
    config = bytes([(object_type << 3) | (index >> 1), ((index & 1) << 7) | (channels << 3) | 4])
    assert aac.parse_asc(config).frame_length == 960
    assert frame_count(out, "a") == len(frames)
    ok, errors = decode_check(out)
    assert ok, errors[:5]


def _pce(w, cc_ind_sw: int) -> None:
    """A PCE at 48 kHz: one CPE (tag 0) in front and one coupling channel element (tag 0), comment "test"."""
    w.put(aac.ID_PCE, 3)
    w.put(0, 4), w.put(1, 2), w.put(3, 4)                   # tag, profile, sampling-frequency index
    for n, bits in ((1, 4), (0, 4), (0, 4), (0, 2), (0, 3), (1, 4), (0, 1), (0, 1), (0, 1)):
        w.put(n, bits)
    w.put(1, 1), w.put(0, 4)                                # front: a CPE, tag 0
    w.put(cc_ind_sw, 1), w.put(0, 4)                        # coupling: tag 0
    w.align()
    w.put(4, 8), w.put(int.from_bytes(b"test", "big"), 32)


@pytest.mark.parametrize("ind_sw", [0, 1])
def test_aac_coupling_channel_and_pce(tmp_path, ind_sw):
    # CCEs (ffmpeg's encoder never writes them) in a stream whose layout a PCE in the first frame gives, as
    # ffmpeg's ADTS muxer does it: our lengths, and ffmpeg's decoder reading the same
    need_ffmpeg()
    asc = aac.AudioSpecificConfig(2, 48000, 3, 0, 0, 1024)
    synth = Synth(aac.AudioSpecificConfig(2, 48000, 3, 2, 2, 1024), seed=11 + ind_sw)
    frames = []
    for k in range(30):
        w = BitWriter()
        if k == 0:
            _pce(w, ind_sw)
        synth.cpe(w, 0)
        w.put(aac.ID_CCE, 3), w.put(0, 4)
        w.put(ind_sw, 1), w.put(1, 3)                       # two coupled elements:
        w.put(1, 1), w.put(0, 4), w.put(3, 2)               # the CPE, both channels (two gain lists)
        w.put(1, 1), w.put(0, 4), w.put(2, 2)               # the CPE again, the left channel
        w.put(k % 2, 1), w.put(k % 2, 1), w.put(k % 4, 2)   # domain, sign, scale
        _info, bands = synth.ics(w)
        for _ in range(2):                                  # gain lists 1 and 2: a common gain, or one per band
            common = 1 if ind_sw else k % 3 == 0
            if not ind_sw:
                w.put(int(common), 1)
            for _ in range(1 if common else bands):
                synth.scf(w, synth.rnd.randint(-3, 3))
        w.put(aac.ID_END, 3)
        w.align()
        frames.append(w.data())
    raw = b"".join(frames)
    assert aac.split_frames(raw, 0, len(raw), asc) == [len(f) for f in frames]
    out = tmp_path / "cce.aac"
    out.write_bytes(b"".join(aac.adts_header(asc, len(f)) + f for f in frames))
    assert frame_count(out, "a") == len(frames)
    ok, errors = decode_check(out)
    assert ok, errors[:5]
    # the PCE: the frames' elements must be the ones it lists, at its sampling rate
    first = frames[0]
    pce = aac.ProgramConfig(front=[(True, 0)], cc=[(bool(ind_sw), 0)], sample_rate_index=3)
    for cfg in (asc, aac.AudioSpecificConfig(2, 48000, 3, 0, 2, 1024, pce=pce),
                aac.AudioSpecificConfig(2, 48000, 3, 2, 2, 1024)):
        assert aac.frame_length(first, 0, len(first), cfg) == len(first)
    assert aac.frame_length(first, 0, len(first), aac.AudioSpecificConfig(2, 44100, 4, 0, 0, 1024)) is None
    mono = aac.AudioSpecificConfig(2, 48000, 3, 0, 1, 1024, pce=aac.ProgramConfig(front=[(False, 0)]))
    assert aac.frame_length(first, 0, len(first), mono) is None
    assert aac.frame_length(first, 0, len(first), aac.AudioSpecificConfig(2, 48000, 3, 6, 6, 1024)) is None


# ---------------------------------------------------------------------- AMR
def _amr_frames(wide: bool, rnd: random.Random) -> list[bytes]:
    sizes, bits = (af.AMR_WB_BYTES, af.AMR_WB_BITS) if wide else (af.AMR_NB_BYTES, af.AMR_NB_BITS)
    out = []
    for _ in range(200):
        ft = rnd.choice([t for t, n in enumerate(sizes) if n is not None])
        n = sizes[ft]
        payload = bytearray(rnd.randrange(256) for _ in range(n))
        if n:
            payload[-1] &= 0xFF << (8 * n - bits[ft]) & 0xFF
        out.append(bytes([(ft << 3) | (rnd.randrange(2) << 2)]) + bytes(payload))
    return out


@pytest.mark.parametrize("wide", [False, True])
def test_amr_frames(wide):
    rnd = random.Random(int(wide))
    frames = _amr_frames(wide, rnd)
    data = b"".join(frames)
    assert af.split_amr(data, 0, len(data), wide) == [len(f) for f in frames]
    assert af.amr_frame_length(bytes([0x3C]) + bytes(31), 0, 32) == 32                   # NB 12.2, Q set
    assert af.amr_frame_length(b"\x44" + bytes(60), 0, 61, wide=True) == 61              # WB 23.85
    for bad_ft in ([10, 11, 12, 13] if wide else [9, 10, 11, 12, 13, 14]):
        assert af.amr_frame_length(bytes([bad_ft << 3]) + bytes(64), 0, 65, wide) is None
    assert af.amr_frame_length(b"\x84" + bytes(64), 0, 65, wide) is None                  # padding bit set
    assert af.amr_frame_length(b"\x01" + bytes(64), 0, 65, wide) is None
    long_one = next(f for f in frames if len(f) > 1)
    assert af.amr_frame_length(long_one, 0, len(long_one) - 1, wide) is None
    ft = 0
    n = (af.AMR_WB_BYTES if wide else af.AMR_NB_BYTES)[ft]
    frame = bytes([ft << 3]) + bytes(n - 1) + b"\x01"     # a speech bit in the padding
    assert af.amr_frame_length(frame, 0, len(frame), wide) is None
    assert af.amr_frame_length(frame, 0, len(frame), wide, strict=False) == n + 1


@pytest.mark.parametrize("encoder,wide", [("libopencore_amrnb", False), ("libvo_amrwbenc", True)])
def test_amr_from_encoder(tmp_path, encoder, wide):
    need_ffmpeg(encoder)
    rate = 16000 if wide else 8000
    out = tmp_path / "a.amr"
    ffmpeg(*_signal(rate, 1, 2), "-c:a", encoder, "-b:a", "12.2k" if not wide else "23.85k", out)
    data = out.read_bytes()
    magic = af.AMR_WB_MAGIC if wide else af.AMR_NB_MAGIC
    assert data.startswith(magic)
    sizes = af.split_amr(data, len(magic), len(data), wide)
    assert sum(sizes) == len(data) - len(magic) and len(sizes) == frame_count(out, "a")


# ---------------------------------------------------------------------- AC-3, E-AC-3, MPEG audio
@pytest.mark.parametrize("encoder,rate,channels,args", [("ac3", 48000, 2, ()), ("ac3", 44100, 6, ()),
                                                        ("ac3", 32000, 1, ("-b:a", "96k")), ("eac3", 48000, 2, ()),
                                                        ("eac3", 44100, 6, ()), ("eac3", 32000, 1, ())])
def test_ac3_frames(tmp_path, encoder, rate, channels, args):
    need_ffmpeg(encoder)
    out = tmp_path / f"a.{encoder}"
    ffmpeg(*_signal(rate, channels, 2), "-c:a", encoder, *args, "-f", encoder, out)
    data = out.read_bytes()
    want = [p["size"] for p in probe_packets(out, "a")]
    assert af.split_ac3(data, 0, len(data), crc=True) == want and sum(want) == len(data)
    h = af.ac3_header(data, 0)
    assert (h["eac3"], h["sample_rate"], h["channels"]) == (encoder == "eac3", rate, channels)
    damaged = bytearray(data[:want[0]])
    damaged[want[0] // 2] ^= 0x10
    assert af.ac3_frame_length(bytes(damaged), 0, len(damaged)) == want[0]
    assert af.ac3_frame_length(bytes(damaged), 0, len(damaged), crc=True) is None
    assert af.ac3_frame_length(data, 0, want[0] - 1) is None


@pytest.mark.parametrize("encoder,rate,channels,args", [("libmp3lame", 44100, 2, ("-b:a", "128k")),
                                                        ("libmp3lame", 48000, 2, ("-q:a", "0")),
                                                        ("libmp3lame", 22050, 1, ("-q:a", "4")),
                                                        ("libmp3lame", 8000, 1, ("-b:a", "16k")),
                                                        ("mp2", 48000, 2, ()), ("mp2", 24000, 1, ())])
def test_mpeg_audio_frames(tmp_path, encoder, rate, channels, args):
    need_ffmpeg(encoder)
    fmt = "mp3" if encoder == "libmp3lame" else "mp2"
    out = tmp_path / f"a.{fmt}"
    extra = ("-write_xing", "0", "-id3v2_version", "0") if fmt == "mp3" else ()
    ffmpeg(*_signal(rate, channels, 2), "-c:a", encoder, *args, *extra, "-f", fmt, out)
    data = out.read_bytes()
    want = [p["size"] for p in probe_packets(out, "a")]
    assert af.split_mpa(data, 0, len(data)) == want and sum(want) == len(data)
    h = af.mpa_header(data, 0)
    assert (h["sample_rate"], h["channels"], h["layer"]) == (rate, channels, 3 if fmt == "mp3" else 2)
    assert h["version"] == {44100: 1, 48000: 1, 22050: 2, 24000: 2, 8000: 2.5}[rate]
    assert af.mpa_frame_length(b"\xff\xfb\x00\x00" + bytes(1000), 0, 1004) is None        # free format
    assert af.mpa_frame_length(b"\xff\xfb\xf0\x00" + bytes(1000), 0, 1004) is None        # bad bitrate
    assert af.mpa_frame_length(data, 0, want[0] - 1) is None


def test_layer1_header():
    # MPEG-1 layer I, 384 kbit/s, 48 kHz, padding: 4 * (12 * 384000 / 48000 + 1) bytes
    h = af.mpa_header(bytes([0xFF, 0xFF, 0xC6, 0x00]), 0)
    assert (h["layer"], h["bitrate"], h["sample_rate"], h["samples"], h["length"]) == (1, 384, 48000, 384, 388)


# ---------------------------------------------------------------------- PCM
@pytest.mark.parametrize("ext,codec,channels,size", [("mov", "pcm_s16le", 2, 4), ("mov", "pcm_s16be", 2, 4),
                                                     ("mov", "pcm_s24le", 2, 6), ("mov", "pcm_s32le", 2, 8),
                                                     ("mov", "pcm_f32le", 2, 8), ("mov", "pcm_f64le", 1, 8),
                                                     ("mov", "pcm_u8", 2, 2), ("mov", "pcm_mulaw", 1, 1),
                                                     ("mov", "pcm_alaw", 1, 1), ("mov", "pcm_s16le", 6, 12),
                                                     ("mp4", "pcm_s16le", 2, 4), ("mp4", "pcm_f32le", 2, 8)])
def test_pcm_frame_bytes(tmp_path, ext, codec, channels, size):
    clip = make_video(tmp_path / f"a.{ext}", None, codec, seconds=0.5, channels=channels)
    buf = clip.read_bytes()
    audio = isobmff.movie_of(buf)[0].track("soun")
    n = af.pcm_frame_bytes(audio.codec, audio.channels, audio.sample_bits, audio.entry)
    assert n == size and set(audio.sizes) == {n}


def test_pcm_descriptions():
    assert af.pcm_frame_bytes("lpcm", 2, 0, b"") is None and af.pcm_frame_bytes("mp4a", 2, 16) is None
    assert af.pcm_frame_bytes("twos", 1, 8) == 1 and af.pcm_frame_bytes("in24", 6, 24) == 18
    # a sound description v2 ("lpcm"): bytes per packet / frames per packet
    v2 = bytearray(64)
    v2[8:10] = (2).to_bytes(2, "big")
    v2[40:44], v2[48:52] = (6).to_bytes(4, "big"), (24).to_bytes(4, "big")
    v2[56:64] = (18).to_bytes(4, "big") + (1).to_bytes(4, "big")
    assert af.pcm_frame_bytes("lpcm", 2, 16, bytes(v2)) == 18
