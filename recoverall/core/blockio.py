"""Read-only byte sources: disks, partitions, image files, regions of them, virtual RAIDs.

Every scanner, filesystem reader and carver reads through a :class:`Source`::

    src = open_source("/dev/sdb")              # a disk, a partition, or an image file
    vol = src.region(1048576, 500 * 10**9)     # a volume inside it (offsets are always bytes)
    data = vol.read(0, 4096)                   # always exactly 4096 bytes

``read`` never fails because of the medium: past the end, and on sectors that can't be read (a failing disk),
it returns zeros and records the unreadable range in ``src.bad`` (shared by every region of the same disk).
Nothing here can write: devices and files are opened O_RDONLY.
"""

from __future__ import annotations

import bisect
import errno
import fcntl
import os
import stat
import struct
import threading
from collections import OrderedDict
from typing import Iterable, Iterator

from .errors import RallError

BLKGETSIZE64 = 0x80081272
BLKSSZGET = 0x1268
DEFAULT_CHUNK = 4 * 1024 * 1024


class BadMap:
    """Unreadable byte ranges of one medium (merged, sorted)."""

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []
        self._lock = threading.Lock()

    def add(self, offset: int, length: int) -> None:
        if length <= 0:
            return
        with self._lock:
            s, e = offset, offset + length
            i = bisect.bisect_left(self._ends, s)
            j = i
            while j < len(self._starts) and self._starts[j] <= e:
                s = min(s, self._starts[j])
                e = max(e, self._ends[j])
                j += 1
            self._starts[i:j] = [s]
            self._ends[i:j] = [e]

    def ranges(self) -> list[tuple[int, int]]:
        with self._lock:
            return [(s, e - s) for s, e in zip(self._starts, self._ends)]

    @property
    def total(self) -> int:
        with self._lock:
            return sum(e - s for s, e in zip(self._starts, self._ends))

    def overlaps(self, offset: int, length: int) -> bool:
        with self._lock:
            i = bisect.bisect_right(self._ends, offset)
            return i < len(self._starts) and self._starts[i] < offset + length

    def __len__(self) -> int:
        return len(self._starts)


class Source:
    """A read-only, random-access byte range. Subclasses implement ``_read``."""

    size: int = 0
    sector_size: int = 512
    name: str = ""
    path: str = ""          # the device or file behind it ("" for virtual sources)
    base: int = 0           # this source's offset on the device or file behind it

    def __init__(self) -> None:
        self.bad = BadMap()

    # ------------------------------------------------------------------ reading
    def read(self, offset: int, length: int) -> bytes:
        """Exactly LENGTH bytes from OFFSET; zeros past the end and for unreadable sectors."""
        if length <= 0:
            return b""
        if offset < 0:
            raise ValueError("negative offset")
        if offset >= self.size:
            return bytes(length)
        n = min(length, self.size - offset)
        data = self._read(offset, n)
        if len(data) < length:
            data = data + bytes(length - len(data))
        return data

    def _read(self, offset: int, length: int) -> bytes:
        raise NotImplementedError

    def read_into_chunks(self, offset: int = 0, end: int | None = None,
                         chunk: int = DEFAULT_CHUNK) -> Iterator[tuple[int, bytes]]:
        """(offset, data) pieces covering [offset, end) in order (the last one may be shorter)."""
        end = self.size if end is None else min(end, self.size)
        pos = offset
        while pos < end:
            n = min(chunk, end - pos)
            yield pos, self.read(pos, n)
            pos += n

    def region(self, offset: int, size: int | None = None, name: str = "") -> Source:
        if offset < 0:
            raise ValueError("negative offset")
        if size is None:
            size = max(0, self.size - offset)
        return RegionSource(self, offset, size, name)

    def close(self) -> None:
        pass

    def describe(self) -> dict:
        return {"name": self.name, "path": self.path, "size": self.size, "sector_size": self.sector_size,
                "base": self.base}

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


class FileSource(Source):
    """A block device or an image file, opened read-only. Reads that fail (EIO) are retried sector by
    sector; sectors that still fail read as zeros and land in ``bad``."""

    def __init__(self, path: str, sector_size: int | None = None, name: str = "", direct_retry: bool = True):
        super().__init__()
        self.path = os.path.abspath(path)
        self.name = name or os.path.basename(path)
        try:
            self.fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        except PermissionError as exc:
            from .errors import NotPermitted
            raise NotPermitted(f"Reading {path} needs administrator rights") from exc
        except OSError as exc:
            raise RallError(f"Can't open {path}: {exc.strerror or exc}") from exc
        st = os.fstat(self.fd)
        self.is_device = stat.S_ISBLK(st.st_mode)
        if self.is_device:
            buf = bytearray(8)
            try:
                fcntl.ioctl(self.fd, BLKGETSIZE64, buf)
                self.size = struct.unpack("<Q", buf)[0]
            except OSError:
                self.size = os.lseek(self.fd, 0, os.SEEK_END)
            if sector_size is None:
                sb = bytearray(4)
                try:
                    fcntl.ioctl(self.fd, BLKSSZGET, sb)
                    sector_size = struct.unpack("<I", sb)[0] or 512
                except OSError:
                    sector_size = 512
        else:
            self.size = st.st_size
        self.sector_size = sector_size or 512
        self.retry = direct_retry
        self.read_errors = 0

    def _read(self, offset: int, length: int) -> bytes:
        try:
            data = os.pread(self.fd, length, offset)
            if len(data) == length:
                return data
            # a short read in the middle of a device: the rest is probably unreadable
            if not self.is_device:
                return data
            got = len(data)
            return data + self._read_slow(offset + got, length - got)
        except OSError as exc:
            if exc.errno not in (errno.EIO, errno.ENODATA, errno.EILSEQ, errno.ENXIO, errno.EBADMSG):
                raise
            self.read_errors += 1
            return self._read_slow(offset, length)

    def _read_slow(self, offset: int, length: int) -> bytes:
        """Sector by sector: what reads comes back, the rest is zeros (and recorded)."""
        ss = self.sector_size
        out = bytearray()
        pos = offset
        end = offset + length
        while pos < end:
            n = min(ss - (pos % ss), end - pos)
            try:
                piece = os.pread(self.fd, n, pos)
            except OSError:
                piece = b""
            if len(piece) < n:
                self.bad.add(pos + len(piece), n - len(piece))
                piece = piece + bytes(n - len(piece))
            out += piece
            pos += n
        return bytes(out)

    def close(self) -> None:
        if getattr(self, "fd", -1) >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1


class BytesSource(Source):
    """An in-memory source (tests, small embedded images)."""

    def __init__(self, data: bytes, sector_size: int = 512, name: str = "memory"):
        super().__init__()
        self.data = bytes(data)
        self.size = len(self.data)
        self.sector_size = sector_size
        self.name = name

    def _read(self, offset: int, length: int) -> bytes:
        return self.data[offset:offset + length]


class RegionSource(Source):
    """[offset, offset+size) of another source. Shares the parent's bad-sector map."""

    def __init__(self, parent: Source, offset: int, size: int, name: str = ""):
        Source.__init__(self)
        self.parent = parent
        self.offset = offset
        self.size = max(0, size)
        self.sector_size = parent.sector_size
        self.name = name or f"{parent.name}@{offset}"
        self.path = parent.path
        self.base = parent.base + offset
        self.bad = parent.bad

    def _read(self, offset: int, length: int) -> bytes:
        return self.parent.read(self.offset + offset, length)

    def region(self, offset: int, size: int | None = None, name: str = "") -> Source:
        if size is None:
            size = max(0, self.size - offset)
        return RegionSource(self.parent, self.offset + offset, size, name)

    def describe(self) -> dict:
        d = super().describe()
        d["offset"] = self.offset
        return d


class ConcatSource(Source):
    """Pieces of other sources (or of one source) laid end to end: [(source, offset, length), ...].

    Used to carve only the free space of a filesystem (the free extents become one continuous stream, so a
    file that was written around allocated clusters is found whole) and by the JBOD/span RAID."""

    def __init__(self, parts: Iterable[tuple[Source, int, int]], name: str = "concat"):
        super().__init__()
        self.parts: list[tuple[Source, int, int]] = [(s, o, n) for s, o, n in parts if n > 0]
        self.starts: list[int] = []
        pos = 0
        for _s, _o, n in self.parts:
            self.starts.append(pos)
            pos += n
        self.size = pos
        self.sector_size = self.parts[0][0].sector_size if self.parts else 512
        self.name = name

    def _read(self, offset: int, length: int) -> bytes:
        out = bytearray()
        i = max(0, bisect.bisect_right(self.starts, offset) - 1)
        pos = offset
        end = offset + length
        while pos < end and i < len(self.parts):
            src, base, n = self.parts[i]
            rel = pos - self.starts[i]
            take = min(n - rel, end - pos)
            out += src.read(base + rel, take)
            pos += take
            i += 1
        return bytes(out)

    def map_range(self, offset: int, length: int) -> list[tuple[int, int]]:
        """Virtual [offset, offset+length) → [(physical offset in the part's source, length), ...]."""
        out: list[tuple[int, int]] = []
        i = max(0, bisect.bisect_right(self.starts, offset) - 1)
        pos = offset
        end = min(self.size, offset + length)
        while pos < end and i < len(self.parts):
            src, base, n = self.parts[i]
            rel = pos - self.starts[i]
            take = min(n - rel, end - pos)
            phys = base + rel
            if out and out[-1][0] + out[-1][1] == phys:
                out[-1] = (out[-1][0], out[-1][1] + take)
            else:
                out.append((phys, take))
            pos += take
            i += 1
        return out


class CachedSource(Source):
    """An LRU block cache in front of another source: filesystem metadata is read in small, repeated,
    scattered pieces. Thread-safe."""

    def __init__(self, inner: Source, block: int = 64 * 1024, blocks: int = 2048):
        Source.__init__(self)
        self.inner = inner
        self.block = block
        self.capacity = blocks
        self.size = inner.size
        self.sector_size = inner.sector_size
        self.name = inner.name
        self.path = inner.path
        self.base = inner.base
        self.bad = inner.bad
        self._cache: OrderedDict[int, bytes] = OrderedDict()
        self._lock = threading.Lock()

    def _block(self, index: int) -> bytes:
        with self._lock:
            data = self._cache.get(index)
            if data is not None:
                self._cache.move_to_end(index)
                return data
        data = self.inner.read(index * self.block, self.block)
        with self._lock:
            self._cache[index] = data
            while len(self._cache) > self.capacity:
                self._cache.popitem(last=False)
        return data

    def _read(self, offset: int, length: int) -> bytes:
        if length >= self.block * 4:
            return self.inner.read(offset, length)          # big reads (file contents) bypass the cache
        first = offset // self.block
        last = (offset + length - 1) // self.block
        if first == last:
            b = self._block(first)
            rel = offset - first * self.block
            return b[rel:rel + length]
        out = bytearray()
        for i in range(first, last + 1):
            out += self._block(i)
        rel = offset - first * self.block
        return bytes(out[rel:rel + length])

    def drop(self) -> None:
        with self._lock:
            self._cache.clear()

    def close(self) -> None:
        self.inner.close()


class SplitSource(ConcatSource):
    """A raw image split into pieces (disk.img.001, .002, … or disk.aa, .ab, …)."""

    def __init__(self, paths: list[str], name: str = ""):
        files = [FileSource(p) for p in paths]
        super().__init__([(f, 0, f.size) for f in files], name or os.path.basename(paths[0]))
        self.files = files
        self.path = os.path.abspath(paths[0])

    def close(self) -> None:
        for f in self.files:
            f.close()


def split_pieces(path: str) -> list[str]:
    """The other pieces of a split image whose first piece is PATH (``x.001`` or ``x.aa``), or [PATH]."""
    import re
    m = re.match(r"^(.*\.)(\d{3})$", path)
    if m and int(m.group(2)) in (0, 1):
        n = int(m.group(2))
        out = []
        while os.path.exists(f"{m.group(1)}{n:03d}"):
            out.append(f"{m.group(1)}{n:03d}")
            n += 1
        return out or [path]
    m = re.match(r"^(.*\.)(aa)$", path)
    if m:
        out = []
        import itertools
        import string
        for a, b in itertools.product(string.ascii_lowercase, repeat=2):
            p = f"{m.group(1)}{a}{b}"
            if not os.path.exists(p):
                break
            out.append(p)
        return out or [path]
    return [path]


def open_source(spec, sector_size: int | None = None) -> Source:
    """A path (device, image file, first piece of a split image, virtual-disk or E01 image), a RAID definition
    (``{"raid": {...}}`` or a .rallraid file), or ``{"path": ..., "offset": ..., "size": ...}`` for a region of
    one."""
    if isinstance(spec, dict):
        if spec.get("raid") or spec.get("type") == "raid":
            from .raid import RaidSource
            return RaidSource.from_definition(spec.get("raid") or spec)
        src = open_source(spec["path"], sector_size or spec.get("sector_size"))
        if spec.get("offset") or spec.get("size"):
            return src.region(int(spec.get("offset") or 0), spec.get("size"), spec.get("name") or "")
        return src
    path = str(spec)
    if path.endswith(".rallraid"):
        from .raid import RaidSource
        return RaidSource.from_file(path)
    # VHD(X), VDI, VMDK, QCOW2, E01: only regular files are looked at, and only their first and last KiB
    from .vdisk import open_vdisk
    vdisk = open_vdisk(path, sector_size)
    if vdisk is not None:
        return vdisk
    pieces = split_pieces(path)
    if len(pieces) > 1:
        return SplitSource(pieces)
    return FileSource(path, sector_size)
