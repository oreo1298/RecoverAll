"""The signature engine ("file carving", like PhotoRec): finds files by the magic bytes they start with,
without any filesystem, and works out where each one ends.

    carver = Carver(src, resolve_formats("photo,video"))
    for f in carver.scan(ctl=ctl):          # standalone: reads the source itself, 8 MiB at a time
        ...f.offset, f.length, f.ext, f.name...

    # or inside the single-pass deep scan, which reads the disk once for every detector:
    for offset, buf in chunks:
        found += carver.feed(offset, buf)
    found += carver.flush()

Files start at block boundaries (512 bytes, or the filesystem's cluster size), so only the first bytes of
each block are looked at. Finding candidates is done a whole chunk at a time without a Python loop per
block: for every magic, the two rarest of its bytes are taken as anchors; the chunk is sliced with a stride
of one block at each anchor offset (``buf[k::block_size]``: one byte per block), each slice is translated
through a table that marks the bytes some magic wants there (one bit per magic), and the two marks are
ANDed as big integers. Only the blocks left over get their whole magic compared, and only then is the
format's ``parse`` asked to check the structure and measure the file.

Like PhotoRec, the blocks inside a file that was found are not searched again (``skip_inside``): the next
candidate is the first block after its end. A format that can't tell its length gives an "open" file: it
ends where the next file starts (or at the format's maximum size), and its chance is at most fair.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterable, Iterator

from ..blockio import Source
from ..fs.base import NULL_CONTROL, Control
from .base import CHANCE_FAIR, CHANCE_POOR, Format, Hit, MiB, Reader

log = logging.getLogger(__name__)

CHUNK = 8 * MiB                 # what scan() reads at a time
READER_WINDOW = 64 * 1024       # read-ahead of the Reader handed to parse() (most candidates read a few bytes)
_NONZERO = re.compile(rb"[^\x00]")


@dataclass(slots=True)
class CarvedFile:
    """A file found by its signature: ``length`` bytes from ``offset`` of the scanned source. ``name`` has
    no extension: one taken from the file (EXIF date, song title) or "f<sector number>" like PhotoRec."""

    offset: int
    length: int
    key: str                    # the Format that found it
    ext: str
    category: str
    description: str
    name: str
    mtime: float | None = None
    chance: int = CHANCE_FAIR
    info: dict | None = None

    @property
    def end(self) -> int:
        return self.offset + self.length

    @property
    def filename(self) -> str:
        return f"{self.name}.{self.ext}" if self.ext else self.name


class _ChunkView(Source):
    """The scanned source, served from the chunk already in memory where possible (parse() mostly reads
    near the candidate's start, which the engine has just read)."""

    def __init__(self, src: Source, at: int, data: bytes):
        self.src = src
        self.at = at
        self.data = data
        self.size = src.size
        self.sector_size = src.sector_size
        self.bad = src.bad
        self.name = src.name

    def read(self, offset: int, length: int) -> bytes:
        rel = offset - self.at
        if rel >= 0 and rel + length <= len(self.data):
            return self.data[rel:rel + length]
        return self.src.read(offset, length)

    def _read(self, offset: int, length: int) -> bytes:
        return self.read(offset, length)


def _rarity(b: int) -> float:
    """Roughly how often byte B starts a block on a real disk: zeros (empty space, sparse areas) and 0xFF
    are everywhere, text is common, other binary values are rare. Anchors are chosen to be rare."""
    if b == 0:
        return 0.3
    if b == 0xFF:
        return 0.05
    if b == 0x20:
        return 0.04
    if b in (0x01, 0x0A, 0x0D, 0x09, 0x02):
        return 0.015
    if 0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A:
        return 0.01
    if 0x21 <= b <= 0x7E:
        return 0.006
    return 0.004


class _Pass:
    """One step of the prefilter: up to 8 anchor byte pairs at the same two offsets, one bit each."""

    __slots__ = ("o1", "o2", "t1", "t2", "verify")

    def __init__(self, o1: int, o2: int | None, pairs: list[tuple[tuple[int, int | None], list]]):
        self.o1, self.o2 = o1, o2
        t1, t2 = bytearray(256), bytearray(256)
        self.verify: list[list[tuple[int, bytes, int]]] = []
        for bit, ((b1, b2), entries) in enumerate(pairs):
            t1[b1] |= 1 << bit
            if b2 is not None:
                t2[b2] |= 1 << bit
            self.verify.append(entries)
        self.t1, self.t2 = bytes(t1), bytes(t2)


class Carver:
    """Finds files by signature in SRC. ``formats``: a list of Format, or anything resolve_formats()
    takes (None: every format enabled by default)."""

    def __init__(self, src: Source, formats: Iterable[Format] | str | None = None, block_size: int = 512,
                 keep_corrupted: bool = False, skip_inside: bool = True):
        if formats is None or isinstance(formats, str) or not all(isinstance(f, Format) for f in formats):
            from . import resolve_formats
            formats = resolve_formats(formats)
        self.src = src
        self.formats: list[Format] = list(formats)
        self.block_size = max(1, int(block_size))
        self.keep_corrupted = keep_corrupted
        self.skip_inside = skip_inside
        self.found = 0
        self._failed: set[str] = set()
        self._build()
        self.reset()

    # ------------------------------------------------------------------ the prefilter
    def _build(self) -> None:
        groups: dict[tuple[int, int | None], dict[tuple[int, int | None], list]] = {}
        self._reach = 1
        self._strength: list[int] = []
        for fi, f in enumerate(self.formats):
            strongest = 0
            for off, magic in f.magic:
                if not magic or off < 0:
                    continue
                strongest = max(strongest, len(magic))
                self._reach = max(self._reach, off + len(magic))
                if len(magic) == 1:
                    key, val = (off, None), (magic[0], None)
                else:
                    w = [_rarity(b) for b in magic]
                    _score, i, j = min((w[i] * w[j], i, j) for i in range(len(magic))
                                       for j in range(i + 1, len(magic)))
                    key, val = (off + i, off + j), (magic[i], magic[j])
                groups.setdefault(key, {}).setdefault(val, []).append((off, magic, fi))
            self._strength.append(strongest)
        self._passes: list[_Pass] = []
        for (o1, o2), vals in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1] or -1)):
            items = sorted(vals.items(), key=lambda kv: (kv[0][0], kv[0][1] or -1))
            for i in range(0, len(items), 8):
                self._passes.append(_Pass(o1, o2, items[i:i + 8]))

    def _match(self, ext: bytes, first: int, nblocks: int) -> dict[int, list[int]]:
        """Blocks of EXT (block i starts at FIRST + i*block_size) whose bytes match a whole magic:
        {position in EXT: [format indexes, most specific magic first]}."""
        bs = self.block_size
        span = nblocks * bs
        cols: dict[int, bytes] = {}
        found: dict[int, dict[int, int]] = {}
        for p in self._passes:
            a = cols.get(p.o1)
            if a is None:
                a = cols[p.o1] = ext[first + p.o1:first + p.o1 + span:bs]
            a = a.translate(p.t1)
            if p.o2 is not None:
                b = cols.get(p.o2)
                if b is None:
                    b = cols[p.o2] = ext[first + p.o2:first + p.o2 + span:bs]
                x = int.from_bytes(a, "little") & int.from_bytes(b.translate(p.t2), "little")
                if not x:
                    continue
                a = x.to_bytes(len(a), "little")
            for m in _NONZERO.finditer(a):
                i = m.start()
                bits = a[i]
                pos = first + i * bs
                for bit in range(8):
                    if bits >> bit & 1:
                        for off, magic, fi in p.verify[bit]:
                            if ext.startswith(magic, pos + off):
                                d = found.setdefault(pos, {})
                                if len(magic) > d.get(fi, 0):
                                    d[fi] = len(magic)
        return {pos: sorted(d, key=lambda fi: (-d[fi], fi)) for pos, d in found.items()}

    # ------------------------------------------------------------------ state
    def reset(self) -> None:
        """Forget where the previous scan was (feed() after flush() starts afresh)."""
        self._skip_until = 0
        self._open: tuple[int, Format, Hit] | None = None
        self._end = 0

    # ------------------------------------------------------------------ scanning
    def scan(self, start: int = 0, end: int | None = None, ctl: Control = NULL_CONTROL) -> Iterator[CarvedFile]:
        """Every file whose first byte is in [start, end), in order."""
        end = self.src.size if end is None else min(end, self.src.size)
        self.reset()
        total = max(1, end - start)
        pos = start
        while pos < end:
            ctl.check()
            n = min(CHUNK, end - pos)
            ext = self.src.read(pos, n + self._reach + self.block_size)
            yield from self._process(pos, ext, n)
            pos += n
            ctl.progress((pos - start) / total, f"Searching for file signatures: {self.found} files found")
        self._end = end
        yield from self.flush()

    def feed(self, offset: int, buf: bytes) -> list[CarvedFile]:
        """One chunk of the deep scan (``buf == src.read(offset, len(buf))``, chunks contiguous and in
        order). Returns the files that start in BUF (they may run past it: parse() reads on through the
        source). A file that doesn't record its length is returned by the call that finds where it ends (the
        next file's start), or by flush()."""
        tail = self.src.read(offset + len(buf), self._reach + self.block_size)
        self._end = offset + len(buf)
        return self._process(offset, bytes(buf) + tail, len(buf))

    def flush(self) -> list[CarvedFile]:
        """The end of the scan: an open-ended file still waiting for the next one ends here."""
        out: list[CarvedFile] = []
        self._close_open(self._end, out)
        self._skip_until = 0
        return out

    def _process(self, base: int, ext: bytes, nbuf: int) -> list[CarvedFile]:
        out: list[CarvedFile] = []
        bs = self.block_size
        first = (-base) % bs
        if first < nbuf and self._passes:
            nblocks = (nbuf - first + bs - 1) // bs
            cands = self._match(ext, first, nblocks)
            if cands:
                view = _ChunkView(self.src, base, ext)
                for p in sorted(cands):
                    pos = base + p
                    if pos < self._skip_until:
                        continue
                    self._candidate(pos, cands[p], view, out)
        if self._open is not None:                # an open file that reached its maximum size ends there
            start, f, _hit = self._open
            if base + nbuf >= start + f.max_size:
                self._close_open(start + f.max_size, out, cut=True)
        return out

    def _candidate(self, pos: int, fis: list[int], view: Source, out: list[CarvedFile]) -> None:
        r = Reader(view, pos, window=READER_WINDOW)
        for fi in fis:
            f = self.formats[fi]
            try:
                hit = f.parse(r)
            except Exception:                     # a bug or a structure nobody expected: never stop the scan
                if f.key not in self._failed:
                    self._failed.add(f.key)
                    log.warning("The %s parser failed on the candidate at byte %d", f.key, pos, exc_info=True)
                hit = None
            if hit is None:
                continue
            if hit.length is not None and (hit.length < f.min_size or hit.length <= 0):
                continue
            self._accept(pos, f, hit, out)
            return
        if self.keep_corrupted:                   # recognised by a long signature, but damaged: keep it
            best = max(fis, key=lambda fi: (self._strength[fi], -fi))
            if self._strength[best] >= 4:
                f = self.formats[best]
                self._accept(pos, f, Hit(f.exts[0], None, CHANCE_POOR, info={"corrupted": True}), out)

    def _accept(self, pos: int, f: Format, hit: Hit, out: list[CarvedFile]) -> None:
        self._close_open(pos, out)
        if hit.length is None:
            self._open = (pos, f, hit)
            return
        length, chance = hit.length, hit.chance
        if length > f.max_size:
            length, chance = f.max_size, CHANCE_POOR
        if length > self.src.size - pos:          # runs past the end of the medium: cut short
            length, chance = self.src.size - pos, CHANCE_POOR
        out.append(self._make(pos, length, f, hit, chance))
        if self.skip_inside:
            self._skip_until = max(self._skip_until, pos + length)

    def _close_open(self, at: int, out: list[CarvedFile], cut: bool = False) -> None:
        if self._open is None:
            return
        start, f, hit = self._open
        self._open = None
        length, chance = at - start, min(hit.chance, CHANCE_FAIR)
        if cut or length > f.max_size:
            length, chance = f.max_size, CHANCE_POOR
        length = min(length, self.src.size - start)
        if length >= max(1, f.min_size):
            out.append(self._make(start, length, f, hit, chance))

    def _make(self, pos: int, length: int, f: Format, hit: Hit, chance: int) -> CarvedFile:
        self.found += 1
        return CarvedFile(pos, length, f.key, hit.ext or f.exts[0], hit.category or f.category,
                          hit.description or f.name, hit.name or f"f{pos // 512:010d}", hit.mtime, chance,
                          dict(hit.info) if hit.info else None)
