"""Fragmented JPEG photos put back together by the signature search (carve/images.py with media/jpegdec.py).

A disk image is built with real photos (made by ffmpeg, 1-2 MB, with and without restart markers; progressive
ones re-encoded by Pillow or ImageMagick) split at 4 KiB cluster boundaries into two or three pieces, with
other data between the pieces: random data, the middle of another photo, zeros, text, a whole other photo.
The carver must give each photo back byte for byte, as its pieces in order — and find photos that aren't
fragmented exactly as before."""

from __future__ import annotations

import random
import shutil
import subprocess

import pytest
from mediakit import make_photo, need_ffmpeg

from recoverall.core.blockio import BytesSource
from recoverall.core.carve import carve, images, resolve_formats
from recoverall.core.carve.base import CHANCE_FAIR, CHANCE_GOOD

CLUSTER = 4096
TEXT = (b"It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of "
        b"foolishness, it was the epoch of belief, it was the epoch of incredulity.\n") * 400


@pytest.fixture(scope="module")
def photos(tmp_path_factory):
    need_ffmpeg("mjpeg")
    d = tmp_path_factory.mktemp("frag")
    noisy = ("-vf", "noise=alls=20:allf=t", "-q:v", "3")
    out = {
        "plain": make_photo(d / "plain.jpg", "2000x1500", noisy).read_bytes(),
        "plain2": make_photo(d / "plain2.jpg", "2000x1500", ("-vf", "noise=alls=16:allf=t,hflip", "-q:v", "3"))
        .read_bytes(),
        "rst": make_photo(d / "rst.jpg", "2000x1500", noisy + ("-threads", "4", "-slices", "8")).read_bytes(),
        "small": make_photo(d / "small.jpg", "320x240", ("-q:v", "5",)).read_bytes(),
    }
    assert all(len(out[k]) > 1_000_000 for k in ("plain", "plain2", "rst"))
    out["dir"] = d
    return out


@pytest.fixture(scope="module")
def prog(photos):
    src, dst = photos["dir"] / "plain2.jpg", photos["dir"] / "prog.jpg"
    try:
        from PIL import Image
        Image.open(src).save(dst, quality=88, progressive=True)
    except ImportError:
        if not shutil.which("convert"):
            pytest.skip("neither Pillow nor ImageMagick is installed")
        subprocess.run(["convert", str(src), "-interlace", "JPEG", "-quality", "88", str(dst)], check=True)
    return dst.read_bytes()


def filler(kind: str, n: int, rng: random.Random, photos) -> bytes:
    if kind == "random":
        return rng.randbytes(n)
    if kind == "zeros":
        return bytes(n)
    if kind == "text":
        at = rng.randrange(len(TEXT) - n)
        return TEXT[at:at + n]
    if kind == "photo":                          # a whole small photo, then random data
        return (photos["small"] + rng.randbytes(n))[:max(n, -(-len(photos["small"]) // CLUSTER) * CLUSTER)]
    other = photos["plain2"] if kind == "middle" else photos["plain"]   # the middle of another photo's data
    at = rng.randrange(len(other) // 4, len(other) // 2) // CLUSTER * CLUSTER
    return other[at:at + n]


def disk(plan: list[tuple[bytes, int, list[str]]], photos, seed: int = 1) -> tuple[bytes, list]:
    """A disk image of photos, each split into PIECES pieces at cluster boundaries with FILL between them.
    Returns the image and [(photo, [(offset, length) of its pieces])]."""
    rng = random.Random(seed)
    img = bytearray(rng.randbytes(CLUSTER * 2))
    placed = []
    for data, pieces, fills in plan:
        clusters = -(-len(data) // CLUSTER)
        cuts = sorted(rng.sample(range(clusters // 5, clusters * 4 // 5), pieces - 1))
        bounds = [0] + [c * CLUSTER for c in cuts] + [len(data)]
        runs = []
        for i in range(pieces):
            part = data[bounds[i]:bounds[i + 1]]
            runs.append((len(img), len(part)))
            img += part + bytes(-len(part) % CLUSTER)
            if i < pieces - 1:
                n = CLUSTER * rng.randrange(1, 4)
                gap = filler(fills[i], n, rng, photos)
                img += gap + bytes(-len(gap) % CLUSTER)
        img += rng.randbytes(CLUSTER)
        placed.append((data, runs))
    return bytes(img), placed


def found_photos(img: bytes) -> list:
    return list(carve(BytesSource(img), resolve_formats("jpg")))


def check(img: bytes, placed: list, found: list) -> None:
    for data, runs in placed:
        f = next((f for f in found if f.offset == runs[0][0]), None)
        assert f is not None, f"no photo found at {runs[0][0]}"
        got = b"".join(img[a:a + n] for a, n in f.pieces())
        assert got == data, (len(runs), f.pieces(), runs)
        assert f.pieces() == runs and f.length == len(data)
        if len(runs) > 1:
            assert f.chance == CHANCE_FAIR and f.info["fragments"] == len(runs)


def test_fragmented_photos_come_back_whole(photos):
    plan = [(photos["plain"], 2, ["random"]),
            (photos["plain2"], 3, ["zeros", "text"]),
            (photos["rst"], 3, ["middle", "random"]),
            (photos["plain"], 2, ["photo"])]
    img, placed = disk(plan, photos)
    found = found_photos(img)
    check(img, placed, found)
    # the small photo between the pieces of the last one is found too
    small = img.find(photos["small"])
    assert any(f.offset == small and f.length == len(photos["small"]) for f in found)


def test_progressive_photo(photos, prog):
    assert len(prog) > 500_000
    img, placed = disk([(prog, 2, ["random"]), (prog, 3, ["text", "zeros"])], photos, seed=2)
    check(img, placed, found_photos(img))


def test_another_photos_clusters_inside_one(photos, monkeypatch):
    """The middle of another photo between the pieces of a photo without restart markers decodes like a
    photo's data and has no marker out of place: only decoding every photo (the thorough mode) finds it."""
    img, placed = disk([(photos["plain"], 2, ["middle"])], photos, seed=3)
    f = next(f for f in found_photos(img) if f.offset == placed[0][1][0][0])
    assert f.runs is None                        # found as before: one piece, running into the other photo
    monkeypatch.setattr(images, "FRAGMENTS_THOROUGH", True)
    check(img, placed, found_photos(img))


def test_photos_that_arent_fragmented_are_found_as_before(photos, monkeypatch):
    rng = random.Random(4)
    img = bytearray(rng.randbytes(CLUSTER))
    where = []
    for key in ("plain", "rst", "small", "plain2"):
        where.append((len(img), len(photos[key])))
        img += photos[key] + bytes(-len(photos[key]) % CLUSTER) + rng.randbytes(CLUSTER)
    cut = len(img)                                 # one cut short by the end of the medium
    img += photos["plain"][:len(photos["plain"]) // 2]
    img = bytes(img)
    on = [(f.offset, f.length, f.chance, f.info, f.runs) for f in found_photos(img)]
    monkeypatch.setattr(images, "FRAGMENTS", False)
    off = [(f.offset, f.length, f.chance, f.info, f.runs) for f in found_photos(img)]
    assert on == off
    for offset, length in where:
        assert (offset, length, CHANCE_GOOD) in [x[:3] for x in on]
    assert any(x[0] == cut and x[4] is None for x in on)


def test_the_switch_turns_it_off(photos, monkeypatch):
    img, placed = disk([(photos["plain"], 2, ["random"])], photos, seed=5)
    monkeypatch.setattr(images, "FRAGMENTS", False)
    f = next(f for f in found_photos(img) if f.offset == placed[0][1][0][0])
    assert f.runs is None and f.length < len(photos["plain"])


def test_dark_photo_is_found_whole(photos, monkeypatch):
    """A flat dark area coded with optimised Huffman tables is all zero bits: kilobytes of zero bytes inside
    the photo's data, which aren't the end of the photo."""
    d = photos["dir"]
    dark = make_photo(d / "dark.jpg", "1600x1200", ("-vf", "drawbox=x=0:y=0:w=1600:h=800:color=black:t=fill",
                                                     "-q:v", "3")).read_bytes()
    assert bytes(8192) in dark
    img = bytes(CLUSTER) + dark + bytes(-len(dark) % CLUSTER) + bytes(CLUSTER)
    (f,) = found_photos(img)
    assert (f.offset, f.length, f.chance, f.runs) == (CLUSTER, len(dark), CHANCE_GOOD, None)
    monkeypatch.setattr(images, "FRAGMENTS", False)
    (f,) = found_photos(img)
    assert f.length < len(dark)                  # without the decoder: cut at the zeros, as before
