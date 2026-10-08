"""The built-in imager: copies around unreadable sectors, writes a ddrescue-format mapfile, resumes from it."""

import os

from recoverall.core.blockio import BytesSource
from recoverall.core.imaging import BAD, DONE, NON_TRIED, Imager, Mapfile

MiB = 1024 * 1024


class FlakySource(BytesSource):
    """Reads fail inside BAD ranges (like a failing disk); a read that touches one reports it."""

    def __init__(self, data: bytes, bad: list[tuple[int, int]]):
        super().__init__(data)
        self.bad_ranges = bad
        self.reads = 0

    def _read(self, offset, length):
        self.reads += 1
        out = bytearray(self.data[offset:offset + length])
        for b, n in self.bad_ranges:
            lo, hi = max(offset, b), min(offset + length, b + n)
            if lo < hi:
                out[lo - offset:hi - offset] = bytes(hi - lo)
                self.bad.add(lo, hi - lo)
        return bytes(out)


def test_mapfile_roundtrip(tmp_path):
    m = Mapfile(10 * MiB, str(tmp_path / "x.map"))
    m.set(0, MiB, DONE)
    m.set(5 * MiB, 512, BAD)
    m.set(2 * MiB, MiB, DONE)
    m.save()
    m2 = Mapfile.load(str(tmp_path / "x.map"), 10 * MiB)
    assert m2.blocks == m.blocks
    assert m2.total(BAD) == 512 and m2.total(DONE) == 2 * MiB
    assert m2.total(NON_TRIED) == 10 * MiB - 2 * MiB - 512
    cells = m2.cells(100)
    assert len(cells) == 100 and "-" in cells and "+" in cells


def test_imager_skips_bad_sectors_and_resumes(tmp_path):
    data = os.urandom(8 * MiB)
    bad = [(3 * MiB + 4096, 1024), (6 * MiB, 512)]
    src = FlakySource(data, bad)
    dest = str(tmp_path / "disk.img")
    stats = Imager(src, dest, dest + ".map", retries=1).run()
    assert stats["bad"] == 1024 + 512
    img = open(dest, "rb").read()
    assert len(img) == len(data)
    mask = bytearray(data)
    for b, n in bad:
        mask[b:b + n] = bytes(n)
    assert img == bytes(mask)
    m = Mapfile.load(dest + ".map", len(data))
    assert m.areas(BAD) == [(3 * MiB + 4096, 1024), (6 * MiB, 512)]
    # the disk "recovers": a second run only retries the bad sectors and fills them in
    src2 = FlakySource(data, [])
    Imager(src2, dest, dest + ".map", retries=1).run()
    assert open(dest, "rb").read() == data
    assert src2.reads < 10
