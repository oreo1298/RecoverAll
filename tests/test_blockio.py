"""Sources: regions, concatenation, caching, split images and unreadable sectors."""

from recoverall.core.blockio import BadMap, BytesSource, CachedSource, ConcatSource, FileSource, open_source
from recoverall.core.fs.base import Entry, ExtentMap, merge_runs, read_content, read_head


def test_read_pads_and_regions():
    src = BytesSource(bytes(range(256)) * 16)
    assert len(src.read(4090, 100)) == 100
    assert src.read(4096, 10) == bytes(10)
    r = src.region(256, 512)
    assert r.read(0, 4) == bytes([0, 1, 2, 3])
    assert r.region(1, 2).read(0, 2) == bytes([1, 2])
    assert r.region(1, 2).base == 257
    assert r.read(510, 4) == bytes([254, 255, 0, 0])


def test_concat_and_map():
    a = BytesSource(b"A" * 100)
    b = BytesSource(b"B" * 100)
    c = ConcatSource([(a, 10, 20), (b, 50, 30)])
    assert c.size == 50
    assert c.read(15, 10) == b"A" * 5 + b"B" * 5
    assert c.map_range(15, 10) == [(25, 5), (50, 5)]
    one = BytesSource(bytes(1000))
    c2 = ConcatSource([(one, 0, 100), (one, 100, 100), (one, 400, 50)])
    assert c2.map_range(0, 250) == [(0, 200), (400, 50)]


def test_cache():
    src = BytesSource(bytes(range(256)) * 1024)
    c = CachedSource(src, block=4096, blocks=4)
    for off in (0, 4000, 70000, 3, 100000):
        assert c.read(off, 300) == src.read(off, 300)
    assert c.read(0, 100000) == src.read(0, 100000)


def test_badmap_merges():
    m = BadMap()
    m.add(100, 10)
    m.add(120, 10)
    m.add(105, 20)
    assert m.ranges() == [(100, 30)]
    assert m.overlaps(129, 5) and not m.overlaps(130, 5)
    assert m.total == 30


def test_files_and_split(tmp_path):
    p = tmp_path / "disk.img.001"
    p.write_bytes(b"x" * 1000)
    (tmp_path / "disk.img.002").write_bytes(b"y" * 500)
    s = open_source(str(p))
    assert s.size == 1500 and s.read(990, 20) == b"x" * 10 + b"y" * 10
    s.close()
    f = FileSource(str(tmp_path / "disk.img.002"))
    assert f.read(0, 3) == b"yyy" and f.size == 500
    f.close()


def test_read_content_runs_holes_and_data():
    src = BytesSource(b"0123456789" * 10)
    e = Entry(key=1, parent=0, name="a", size=12, runs=[(0, 4), (-1, 4), (20, 10)])
    assert b"".join(read_content(src, e)) == b"0123" + bytes(4) + b"0123"
    e2 = Entry(key=2, parent=0, name="b", size=3, data=b"abcdef")
    assert read_head(src, e2, 10) == b"abc"
    e3 = Entry(key=3, parent=0, name="c", size=8, runs=[(0, 4)])
    assert b"".join(read_content(src, e3)) == b"0123" + bytes(4)
    assert merge_runs([(0, 4), (4, 4), (-1, 2), (-1, 3), (20, 1)]) == [(0, 8), (-1, 5), (20, 1)]
    m = ExtentMap([(0, 10), (5, 10), (100, 10)])
    assert m.overlap(0, 200) == 25 and m.overlap(12, 2) == 2 and m.overlap(50, 10) == 0
