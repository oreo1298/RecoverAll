"""The model every filesystem reader shares.

A reader walks a filesystem's metadata — existing files *and* what's left of deleted ones — and yields
:class:`Entry` objects. It never writes and never trusts the metadata: every number read from the disk is
bounds-checked, and damaged structures are skipped (with a warning) instead of stopping the scan.

    reader = NtfsReader(volume_source)          # a Source covering just the volume (blockio.region)
    for e in reader.entries(ctl):               # ctl: progress/cancel (Control)
        ...
    for chunk in read_content(volume_source, e):  # the file's bytes
        ...

Content is described by ``runs`` — (byte offset inside the volume, byte length) pieces; offset -1 is a sparse
hole that reads as zeros — truncated to ``size``, or by ``data`` (resident/inline bytes). Formats that need
decoding (NTFS compression, files only an external tool can read) name a decoder in ``extra["decoder"]``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable, Iterator

from ..blockio import Source
from ..errors import Cancelled

# How likely the content of an entry is intact (shown as a coloured dot; recovery sorts by it).
CHANCE_UNKNOWN = 0
CHANCE_POOR = 1     # the data was (partly) overwritten or reused, or the location is a guess that failed checks
CHANCE_FAIR = 2     # the location is a reasonable guess (deleted FAT file assumed contiguous, size from footer...)
CHANCE_GOOD = 3     # existing file, or deleted with its clusters still free and its map intact

CHANCE_NAMES = {CHANCE_UNKNOWN: "unknown", CHANCE_POOR: "poor", CHANCE_FAIR: "fair", CHANCE_GOOD: "good"}

# Entry.flags
F_COMPRESSED = 1 << 0     # content needs extra["decoder"] (e.g. NTFS LZNT1)
F_ENCRYPTED = 1 << 1      # encrypted by the filesystem (EFS, ext4/f2fs fscrypt): copied as stored
F_SPARSE = 1 << 2
F_ADS = 1 << 3            # an NTFS alternate data stream, named "file:stream"
F_SYMLINK = 1 << 4        # content is the link target
F_ORPHAN = 1 << 5         # its folder is unknown: it is shown under "Lost files"
F_JOURNAL = 1 << 6        # rebuilt from a journal copy of its metadata (ext3/4)
F_SYSTEM = 1 << 7         # filesystem metadata ($MFT, journal...): hidden unless asked for
F_HARDLINK = 1 << 8       # another name of an inode that is listed elsewhere too
F_RESIDENT = 1 << 9       # the content lives in the metadata itself (data)
F_CARVED = 1 << 10        # found by its signature, not through a filesystem
F_PARTIAL = 1 << 11       # only part of the content could be located
F_DIR_RECOVERED = 1 << 12  # a folder rebuilt from orphaned entries


@dataclass(slots=True)
class Entry:
    key: int | str                       # unique inside the volume: MFT record number, inode number, ...
    parent: int | str | None             # key of the folder it is in (None: it is the root)
    name: str
    is_dir: bool = False
    size: int = 0
    deleted: bool = False
    runs: list[tuple[int, int]] | None = None    # (offset in the volume or -1 for a hole, length) in bytes
    data: bytes | None = None            # resident / inline content
    mtime: float | None = None           # Unix time, UTC
    ctime: float | None = None           # metadata change (or MFT change) time
    atime: float | None = None
    crtime: float | None = None          # creation time
    chance: int = CHANCE_UNKNOWN
    flags: int = 0
    extra: dict | None = None            # reader-specific details (mode, uid, decoder parameters, ...)

    def content_size(self) -> int:
        return self.size


class Control:
    """Progress and cancellation for long operations. The default does nothing; jobs pass a JobControl."""

    def check(self) -> None:
        """Raise Cancelled when the user stopped the operation. Call it often (every few hundred records)."""

    def progress(self, fraction: float | None = None, message: str | None = None) -> None:
        """FRACTION is 0..1 of the current phase."""

    def log(self, text: str, level: str = "info") -> None:
        pass

    def warn(self, text: str) -> None:
        self.log(text, "warning")

    @property
    def cancelled(self) -> bool:
        try:
            self.check()
        except Cancelled:
            return True
        return False


NULL_CONTROL = Control()


class FsReader:
    """Base class of the native readers (ntfs, fat, exfat, ext, xfs, hfsplus, iso9660) and the external ones
    (tsk, btrfs). Subclasses set the class attributes and implement probe() and entries()."""

    fstype = ""              # "ntfs", "fat32", "ext4", ... (the probed type)
    name = ""                # human name: "NTFS"
    root_key: int | str = 0
    deleted_support = True   # can find deleted files

    def __init__(self, src: Source, info: dict | None = None):
        self.src = src
        self.info = dict(info or {})
        self.block_size = int(self.info.get("block_size") or 4096)
        self.label = self.info.get("label") or ""
        self.warnings: list[str] = []

    @classmethod
    def probe(cls, src: Source) -> dict | None:
        """Read the boot sector/superblock at the start of SRC: an info dict (fstype, label, uuid, size in
        bytes, block_size, used if known, version, ...) or None if it isn't this filesystem."""
        raise NotImplementedError

    def entries(self, ctl: Control = NULL_CONTROL, deleted: bool = True) -> Iterator[Entry]:
        """Every file and folder, the root first (key == root_key, parent None, name "")."""
        raise NotImplementedError

    def free_extents(self, ctl: Control = NULL_CONTROL) -> list[tuple[int, int]] | None:
        """Unallocated space as (offset, length) in bytes, from the allocation bitmap; None if unknown."""
        return None

    def warn(self, text: str) -> None:
        if text not in self.warnings and len(self.warnings) < 200:
            self.warnings.append(text)


class Detector:
    """Looks at every chunk of a deep scan (the whole device, read once, in order) and proposes volumes.

    feed() gets device-relative offsets; chunks are contiguous and a multiple of 512 bytes long (the last
    one may be shorter). finish() returns candidate volumes::

        {"fstype": "ntfs", "offset": <volume start on the device>, "size": <bytes>, "evidence": "boot sector"
         | "backup boot sector" | "superblock" | "backup superblock" | "MFT records" | ...,
         "score": 0-100, "label": "...", "info": {...passed to the reader...}}
    """

    def feed(self, offset: int, buf: bytes) -> None:
        raise NotImplementedError

    def finish(self) -> list[dict]:
        return []


# ---------------------------------------------------------------------- reading content
Decoder = Callable[[Source, "Entry | dict"], Iterator[bytes]]
DECODERS: dict[str, Decoder] = {}


def register_decoder(name: str, fn: Decoder) -> None:
    DECODERS[name] = fn


def _get(entry, name, default=None):
    if isinstance(entry, dict):
        return entry.get(name, default)
    return getattr(entry, name, default)


def read_content(src: Source, entry, chunk: int = 1024 * 1024) -> Iterator[bytes]:
    """The bytes of ENTRY (an Entry, or a dict with the same fields) from its volume SRC, in pieces."""
    extra = _get(entry, "extra") or {}
    decoder = extra.get("decoder") if isinstance(extra, dict) else None
    if decoder:
        fn = DECODERS.get(decoder)
        if fn is None:
            _load_decoder(decoder)
            fn = DECODERS.get(decoder)
        if fn is None:
            raise KeyError(f"no decoder {decoder}")
        yield from fn(src, entry)
        return
    size = int(_get(entry, "size") or 0)
    data = _get(entry, "data")
    if data is not None:
        yield bytes(data[:size]) if size else bytes(data)
        return
    left = size
    for off, length in _get(entry, "runs") or []:
        if left <= 0:
            break
        n = min(length, left)
        if off < 0:
            while n > 0:
                k = min(chunk, n)
                yield bytes(k)
                n -= k
                left -= k
            continue
        pos = off
        while n > 0:
            k = min(chunk, n)
            yield src.read(pos, k)
            pos += k
            n -= k
            left -= k
    while left > 0:                      # the runs are shorter than the size: the rest is unknown
        k = min(chunk, left)
        yield bytes(k)
        left -= k


def read_head(src: Source, entry, limit: int) -> bytes:
    """The first LIMIT bytes of an entry (previews, signatures)."""
    out = bytearray()
    for piece in read_content(src, entry, chunk=min(limit, 1024 * 1024) or 1):
        out += piece
        if len(out) >= limit:
            break
    return bytes(out[:limit])


_DECODER_MODULES = {"lznt1": "ntfs", "ntfs-lznt1": "ntfs", "tsk": "tsk", "btrfs": "btrfs", "hfs-compressed": "hfsplus",
                    "xpress": "ntfs", "lzx": "ntfs"}


def _load_decoder(name: str) -> None:
    mod = _DECODER_MODULES.get(name)
    if mod:
        import importlib
        try:
            importlib.import_module(f"{__package__}.{mod}")
        except ImportError:
            pass


# ---------------------------------------------------------------------- small helpers for readers
def u8(b: bytes, o: int) -> int:
    return b[o]


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def be16(b: bytes, o: int) -> int:
    return struct.unpack_from(">H", b, o)[0]


def be32(b: bytes, o: int) -> int:
    return struct.unpack_from(">I", b, o)[0]


def be64(b: bytes, o: int) -> int:
    return struct.unpack_from(">Q", b, o)[0]


FILETIME_EPOCH = 116444736000000000      # 1601-01-01 → 1970-01-01 in 100 ns units


def filetime(v: int) -> float | None:
    """Windows FILETIME → Unix time (None for 0 or nonsense)."""
    if not v or v < FILETIME_EPOCH - 10 ** 17 or v > FILETIME_EPOCH + 10 ** 19:
        return None
    return (v - FILETIME_EPOCH) / 1e7


def dos_datetime(date: int, time_: int, tenths: int = 0, utc_offset: float = 0.0) -> float | None:
    """A FAT/exFAT date and time (local time, unknown zone: taken as UTC) → Unix time."""
    import calendar
    if not date:
        return None
    y = 1980 + (date >> 9)
    m = (date >> 5) & 15
    d = date & 31
    hh = time_ >> 11
    mm = (time_ >> 5) & 63
    ss = (time_ & 31) * 2
    if not (1 <= m <= 12 and 1 <= d <= 31 and hh < 24 and mm < 60 and ss < 60):
        return None
    try:
        return calendar.timegm((y, m, d, hh, mm, ss, 0, 0, 0)) + tenths / 100.0 - utc_offset
    except (ValueError, OverflowError):
        return None


def merge_runs(runs: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Join pieces that follow each other (holes too)."""
    out: list[tuple[int, int]] = []
    for off, n in runs:
        if n <= 0:
            continue
        if out:
            po, pn = out[-1]
            if (off < 0 and po < 0) or (off >= 0 and po >= 0 and po + pn == off):
                out[-1] = (po, pn + n)
                continue
        out.append((off, n))
    return out


class ExtentMap:
    """A sorted set of allocated byte ranges for quick "is this cluster in use?" questions (chance estimates)."""

    def __init__(self, ranges: list[tuple[int, int]] | None = None):
        import bisect
        self._bisect = bisect
        rs = sorted((o, o + n) for o, n in (ranges or []) if n > 0)
        self.starts: list[int] = []
        self.ends: list[int] = []
        for s, e in rs:
            if self.ends and s <= self.ends[-1]:
                self.ends[-1] = max(self.ends[-1], e)
            else:
                self.starts.append(s)
                self.ends.append(e)

    def overlap(self, offset: int, length: int) -> int:
        """How many bytes of [offset, offset+length) are in the set."""
        end = offset + length
        i = self._bisect.bisect_right(self.ends, offset)
        total = 0
        while i < len(self.starts) and self.starts[i] < end:
            total += min(end, self.ends[i]) - max(offset, self.starts[i])
            i += 1
        return total
