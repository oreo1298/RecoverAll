"""The signature engine (recoverall.core.carve.engine and the registry in carve/__init__): candidate search,
exact/open lengths, skip-inside, feed()/flush() against scan(), parser failures and speed.

Most tests use small made-up formats so they check the engine alone; the real formats are tested in
test_carve_media.py."""

from __future__ import annotations

import logging
import os
import random
import struct
import time

import pytest

from recoverall.core.blockio import BytesSource
from recoverall.core.carve import (
    CATEGORIES,
    FORMATS,
    CarvedFile,
    Carver,
    UnknownFormat,
    carve,
    formats_table,
    resolve_formats,
)
from recoverall.core.carve.base import CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, Format, Hit, Reader
from recoverall.core.errors import Cancelled

MiB = 1024 * 1024


def filler(n: int, seed: int = 1) -> bytes:
    return random.Random(seed).randbytes(n)


def plant(size: int, items: dict[int, bytes], seed: int = 1) -> bytearray:
    buf = bytearray(filler(size, seed))
    for off, data in items.items():
        data = data[:size - off]
        buf[off:off + len(data)] = data
    return buf


# ---------------------------------------------------------------------- made-up formats
def parse_box(r: Reader) -> Hit | None:
    """"BOX!" + u32 length (of the whole file) + payload."""
    h = r.read(0, 8)
    if len(h) < 8:
        return None
    n = struct.unpack_from("<I", h, 4)[0]
    if n < 8:
        return None
    return Hit("box", n, CHANCE_GOOD, name="named", info={"n": n})


def parse_open(r: Reader) -> Hit | None:
    return Hit("opn", None, CHANCE_GOOD) if r.read(4, 4) == b"open" else None


def parse_crash(r: Reader) -> Hit | None:
    raise RuntimeError("parser bug")


def parse_never(r: Reader) -> Hit | None:
    return None


def parse_far(r: Reader) -> Hit | None:
    return Hit("far", 40000, CHANCE_GOOD)


BOX = Format("box", "Box file", "other", ("box",), ((0, b"BOX!"),), parse_box, max_size=64 * 1024, min_size=16)
OPEN = Format("opn", "Open file", "other", ("opn",), ((0, b"OPN:"),), parse_open, max_size=20000)
CRASH = Format("crash", "Crashing", "other", ("crs",), ((0, b"CRSH"),), parse_crash)
NEVER = Format("never", "Corrupted", "other", ("nvr",), ((0, b"NVR\x01DATA"),), parse_never)
FAR = Format("far", "Deep magic", "other", ("far",), ((32769, b"CD001"),), parse_far)
ZEROS = Format("zeros", "Zero-led", "other", ("zer",), ((0, b"\0\0\0\0\x7fZER"),), lambda r: Hit("zer", 600))
TEST_FORMATS = [BOX, OPEN, CRASH, NEVER, FAR, ZEROS]


def box(n: int, fill: int = 0x55) -> bytes:
    return b"BOX!" + struct.pack("<I", n) + bytes([fill]) * (n - 8)


def scan(data, formats=TEST_FORMATS, start=0, end=None, **kw) -> list[CarvedFile]:
    return list(Carver(BytesSource(bytes(data)), formats, **kw).scan(start, end))


def summary(files):
    return [(f.offset, f.length, f.key, f.chance) for f in files]


# ---------------------------------------------------------------------- the registry
def test_registry_keys_unique_and_sane():
    keys = [f.key for f in FORMATS]
    assert len(keys) == len(set(keys))
    for f in FORMATS:
        assert f.category in CATEGORIES, f.key
        assert f.exts and all(e == e.lower() and not e.startswith(".") for e in f.exts), f.key
        assert f.magic and all(isinstance(m, bytes) and m and off >= 0 for off, m in f.magic), f.key
        assert callable(f.parse) and f.max_size >= f.min_size >= 1
    mine = {"jpg", "png", "gif", "bmp", "tif", "cr2", "nef", "dng", "heic", "webp", "mp4", "avi", "mkv", "wmv",
            "flv", "mpg", "ts", "mp3", "wav", "flac", "ogg", "m4a", "aac", "aiff", "wma", "amr", "mid"}
    assert mine <= set(keys)


def test_formats_table():
    rows = formats_table()
    assert len(rows) == len(FORMATS)
    assert set(rows[0]) == {"key", "name", "category", "exts", "enabled"}
    order = list(CATEGORIES)
    cats = [order.index(r["category"]) for r in rows]
    assert cats == sorted(cats)
    jpg = next(r for r in rows if r["key"] == "jpg")
    assert jpg["category"] == "photo" and "jpg" in jpg["exts"] and jpg["enabled"]


def test_resolve_formats():
    enabled = [f for f in FORMATS if f.enabled]
    assert resolve_formats(None) == enabled
    assert resolve_formats("all") == enabled
    assert len(resolve_formats("everything")) == len(FORMATS)
    assert [f.key for f in resolve_formats("jpeg")] == ["jpg"]
    assert [f.key for f in resolve_formats(".JPG, mov")] == ["jpg", "mp4"]
    assert [f.key for f in resolve_formats(["mka"])] == ["mkv"]
    photos = resolve_formats("photos")
    assert photos and all(f.category == "photo" and f.enabled for f in photos)
    assert {f.key for f in resolve_formats("music")} >= {"mp3", "flac", "wav"}
    no_jpg = resolve_formats("all,-jpg")
    assert "jpg" not in {f.key for f in no_jpg} and len(no_jpg) == len(enabled) - 1
    assert {f.key for f in resolve_formats("-jpg -png")} == {f.key for f in enabled} - {"jpg", "png"}
    assert [f.key for f in resolve_formats("ico")] == ["ico"]          # off by default, but asked for
    assert resolve_formats([BOX, "png"]) == [f for f in FORMATS if f.key == "png"] + [BOX]
    with pytest.raises(UnknownFormat):
        resolve_formats("jpg,nosuchtype")
    with pytest.raises(ValueError):
        resolve_formats("nosuchtype")


# ---------------------------------------------------------------------- finding files
def test_exact_files_at_block_starts_only():
    data = plant(64 * 1024, {1024: box(3000), 8192: box(100), 777: box(50), 20000 + 3: box(64)})
    files = scan(data)
    assert summary(files) == [(1024, 3000, "box", CHANCE_GOOD), (8192, 100, "box", CHANCE_GOOD)]
    f = files[0]
    assert (f.ext, f.category, f.description, f.name, f.filename, f.info, f.end) == \
        ("box", "other", "Box file", "named", "named.box", {"n": 3000}, 4024)


def test_block_size():
    data = plant(64 * 1024, {4096: box(100), 4096 + 512: box(100), 12288: box(200)})
    assert [f.offset for f in scan(data, block_size=4096)] == [4096, 12288]
    assert [f.offset for f in scan(data, block_size=512)] == [4096, 4608, 12288]


def test_skip_inside():
    outer = bytearray(box(4096))
    outer[1024:1024 + 100] = box(100)                     # a file inside a file, at a block boundary
    data = plant(32 * 1024, {512: bytes(outer), 8192: box(64)})
    assert [f.offset for f in scan(data)] == [512, 8192]
    assert [f.offset for f in scan(data, skip_inside=False)] == [512, 1536, 8192]


def test_min_and_max_size():
    data = plant(256 * 1024, {512: box(12), 4096: box(100 * 1024), 200 * 1024: box(64)})
    files = scan(data)
    assert summary(files)[0] == (4096, 64 * 1024, "box", CHANCE_POOR)  # cut at max_size; the 12-byte one dropped
    assert files[1].offset == 200 * 1024


def test_length_past_the_end_of_the_source():
    data = plant(8192, {4096: box(10000)})
    assert summary(scan(data)) == [(4096, 4096, "box", CHANCE_POOR)]


def test_open_files_end_at_the_next_header():
    data = plant(512 * 1024, {
        1024: b"OPN:open",                # ends where the next file starts
        5120: box(512),
        8192: b"OPN:open",                # nothing follows within max_size (20000): cut there, poor
        100 * 1024: b"OPN:open",          # runs to the end of the scan: fair
    })
    files = scan(data, end=110 * 1024)
    assert summary(files) == [(1024, 4096, "opn", CHANCE_FAIR), (5120, 512, "box", CHANCE_GOOD),
                              (8192, 20000, "opn", CHANCE_POOR), (100 * 1024, 10 * 1024, "opn", CHANCE_FAIR)]


def test_open_file_ended_by_a_header_inside_skipped_area_is_not_possible():
    # an open file doesn't hide what follows it: the box inside its range is found and ends it
    data = plant(64 * 1024, {512: b"OPN:open", 2048: box(1000), 4096: b"OPN:open", 6144: box(64)})
    assert summary(scan(data)) == [(512, 1536, "opn", CHANCE_FAIR), (2048, 1000, "box", CHANCE_GOOD),
                                   (4096, 2048, "opn", CHANCE_FAIR), (6144, 64, "box", CHANCE_GOOD)]


def test_parser_exceptions_are_contained(caplog):
    data = plant(64 * 1024, {512: b"CRSH", 4096: b"CRSH", 8192: box(64)})
    with caplog.at_level(logging.WARNING):
        files = scan(data)
    assert summary(files) == [(8192, 64, "box", CHANCE_GOOD)]
    msgs = [r for r in caplog.records if "crash parser failed" in r.getMessage()]
    assert len(msgs) == 1                                # logged once per format


def test_keep_corrupted():
    data = plant(64 * 1024, {512: b"NVR\x01DATA", 4096: box(64), 8192: b"BOX!\0\0\0\0"})
    assert summary(scan(data)) == [(4096, 64, "box", CHANCE_GOOD)]
    files = scan(data, keep_corrupted=True, end=16384)
    # the damaged file is kept up to the next one; a 4-byte magic with a bad length is kept too
    assert summary(files) == [(512, 3584, "never", CHANCE_POOR), (4096, 64, "box", CHANCE_GOOD),
                              (8192, 8192, "box", CHANCE_POOR)]
    assert files[0].ext == "nvr" and files[0].info == {"corrupted": True}


def test_magic_beyond_the_block_and_common_first_bytes():
    data = plant(512 * 1024, {
        65536: b"X" * 32769 + b"CD001",                 # magic 32 KiB into the file
        4096: b"\0\0\0\0\x7fZER",                        # magic starting with zeros
    })
    data[200 * 1024:200 * 1024 + 4096] = bytes(4096)    # zero blocks are not candidates
    files = scan(data)
    assert summary(files) == [(4096, 600, "zeros", CHANCE_FAIR), (65536, 40000, "far", CHANCE_GOOD)]
    # the deep magic straddling a chunk boundary (feed mode)
    for chunk in (512, 4096, 65536 + 16384):
        c = Carver(BytesSource(bytes(data)), TEST_FORMATS)
        got = []
        for off in range(0, len(data), chunk):
            got += c.feed(off, bytes(data[off:off + chunk]))
        got += c.flush()
        assert summary(got) == summary(files), chunk


def test_feed_flush_equals_scan():
    rng = random.Random(7)
    items = {}
    pos = 512
    while pos < 3 * MiB:
        kind = rng.randrange(3)
        if kind == 0:
            items[pos] = box(rng.randrange(16, 60000))
        elif kind == 1:
            items[pos] = b"OPN:open"
        else:
            items[pos] = b"CRSH"
        pos += rng.randrange(1, 200) * 512
    data = bytes(plant(4 * MiB, items, seed=3))
    want = summary(scan(data))
    assert len(want) > 30
    for chunk in (512, 64 * 1024, 1 * MiB, 3 * MiB + 512):
        c = Carver(BytesSource(data), TEST_FORMATS)
        got = []
        for off in range(0, len(data), chunk):
            files = c.feed(off, data[off:off + chunk])
            assert all(f.offset < off + chunk for f in files)
            got += files
        got += c.flush()
        assert summary(got) == want, chunk


def test_scan_range_progress_and_cancel(ctl):
    data = plant(20 * MiB, {512: box(64), 12 * MiB: box(64), 19 * MiB: box(64)})
    src = BytesSource(bytes(data))
    assert [f.offset for f in carve(src, TEST_FORMATS, start=1024, end=19 * MiB)] == [12 * MiB]
    files = list(carve(src, TEST_FORMATS, ctl=ctl))
    assert len(files) == 3 and ctl.messages and "3 files found" in ctl.messages[-1]

    class Stop(type(ctl)):
        n = 0

        def check(self):
            self.n += 1
            if self.n > 1:
                raise Cancelled("stop")
    with pytest.raises(Cancelled):
        list(carve(src, TEST_FORMATS, ctl=Stop()))


def test_carver_accepts_a_spec():
    c = Carver(BytesSource(b"\0" * 1024), "png,jpg")
    assert [f.key for f in c.formats] == ["jpg", "png"]
    c = Carver(BytesSource(b"\0" * 1024))
    assert len(c.formats) == len([f for f in FORMATS if f.enabled])


def test_random_data_speed_and_false_positives():
    """64 MiB of random data with every format that is on by default: nothing found, quickly."""
    data = os.urandom(64 * MiB)
    src = BytesSource(data)
    carver = Carver(src)
    t0 = time.perf_counter()
    files = list(carver.scan())
    elapsed = time.perf_counter() - t0
    print(f"\n64 MiB of random data, {len(carver.formats)} formats: {elapsed:.2f} s, {len(files)} files")
    assert elapsed < 2.0
    assert len(files) <= 2          # other modules' weak signatures may very rarely match


def parse_split(r: Reader) -> Hit | None:
    """"SPLT" + u32 first-piece length + u32 gap: the rest of the file lies GAP bytes further on."""
    h = r.read(0, 12)
    first, gap = struct.unpack_from("<II", h, 4)
    return Hit("spl", None, CHANCE_FAIR, runs=[(0, first), (first + gap, 1024)])


SPLIT = Format("split", "Fragmented", "other", ("spl",), ((0, b"SPLT"),), parse_split, min_size=16)


def test_fragmented_files():
    """A parser that finds where a file's data goes on returns its pieces; they come back in order, the
    length is their sum, and only the first piece is skipped by the search."""
    head = b"SPLT" + struct.pack("<II", 1024, 4096) + bytes(1012)
    data = plant(64 * 1024, {2048: head, 2048 + 1024 + 4096: bytes(1024), 4096: box(64)})
    files = scan(data, [SPLIT, BOX])
    split = next(f for f in files if f.key == "split")
    assert split.pieces() == [(2048, 1024), (2048 + 1024 + 4096, 1024)]
    assert split.length == 2048 and split.offset == 2048
    assert any(f.key == "box" and f.offset == 4096 for f in files)     # the gap is searched
    # a piece past the end of the source is cut there
    files = scan(data[:2048 + 1024 + 4096 + 100], [SPLIT])
    assert files[0].pieces()[-1] == (2048 + 1024 + 4096, 100)
