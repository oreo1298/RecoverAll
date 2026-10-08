"""The model of the signature engine ("file carving", like PhotoRec): every format it knows is a
:class:`Format` — where its magic bytes sit, and a ``parse`` function that checks a candidate and works out
how long the file is.

    def parse_png(r: Reader) -> Hit | None:
        head = r.read(0, 33)
        if head[12:16] != b"IHDR":
            return None                   # a false positive: the engine moves on
        ...walk the chunks with r.read(...) until IEND...
        return Hit("png", length=end, chance=CHANCE_GOOD, info={"width": w, "height": h})

    FORMATS = [Format("png", "PNG image", "photo", ("png",), ((0, b"\\x89PNG\\r\\n\\x1a\\n"),), parse_png)]

The engine only looks for magic bytes at the start of each block (512 bytes, or the filesystem's cluster
size): files always start at a block boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..blockio import Source

CHANCE_POOR, CHANCE_FAIR, CHANCE_GOOD = 1, 2, 3

KiB, MiB, GiB = 1024, 1024 ** 2, 1024 ** 3

# Categories, in the order the GUI shows them.
CATEGORIES = {
    "photo": "Photos and pictures",
    "video": "Videos",
    "audio": "Music and audio",
    "document": "Documents",
    "archive": "Archives",
    "email": "E-mail",
    "database": "Databases",
    "executable": "Programs",
    "other": "Other files",
}


@dataclass(slots=True)
class Hit:
    """A recognised file. ``length`` None means the format doesn't say where it ends: the engine ends it
    where the next file starts (or at the format's max_size) and lowers the chance."""

    ext: str
    length: int | None = None
    chance: int = CHANCE_FAIR
    name: str | None = None          # a name taken from the file (EXIF date, document title) without extension
    mtime: float | None = None       # a date taken from the file (EXIF DateTimeOriginal, PDF CreationDate, ...)
    info: dict | None = None         # shown in the preview: {"width": .., "height": .., "camera": .., ...}
    category: str | None = None      # overrides Format.category (a ZIP that is a .docx is a document)
    description: str | None = None   # overrides Format.name ("Word document" for a ZIP)


class Reader:
    """Random access to the candidate file: offsets are relative to its first byte. Reads past the end of
    the source return fewer bytes (never raises). ``limit`` is how many bytes are left in the source."""

    def __init__(self, src: Source, start: int, limit: int | None = None, window: int = 1024 * 1024):
        self.src = src
        self.start = start
        self.limit = (src.size - start) if limit is None else min(limit, src.size - start)
        self._win_off = -1
        self._win = b""
        self._window = window

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0 or offset >= self.limit:
            return b""
        length = min(length, self.limit - offset)
        if self._win_off <= offset and offset + length <= self._win_off + len(self._win):
            rel = offset - self._win_off
            return self._win[rel:rel + length]
        if length >= self._window:
            return self.src.read(self.start + offset, length)
        n = min(self._window, self.limit - offset)
        self._win = self.src.read(self.start + offset, n)
        self._win_off = offset
        return self._win[:length]

    def find(self, pattern: bytes, start: int = 0, end: int | None = None, step: int = 4 * 1024 * 1024) -> int:
        """Offset of the first PATTERN at or after START (before END), or -1."""
        end = self.limit if end is None else min(end, self.limit)
        pos = start
        overlap = len(pattern) - 1
        while pos < end:
            n = min(step, end - pos)
            buf = self.src.read(self.start + pos, n + overlap) if pos + n < self.limit else \
                self.src.read(self.start + pos, n)
            i = buf.find(pattern)
            if i >= 0 and pos + i + len(pattern) <= end + overlap:
                return pos + i
            pos += n
        return -1

    def rfind(self, pattern: bytes, start: int, end: int) -> int:
        """Offset of the last PATTERN in [start, end), or -1 (for footers like %%EOF)."""
        end = min(end, self.limit)
        step = 4 * 1024 * 1024
        pos = end
        while pos > start:
            lo = max(start, pos - step)
            buf = self.src.read(self.start + lo, pos - lo + len(pattern) - 1 if pos < end else pos - lo)
            i = buf.rfind(pattern)
            if i >= 0:
                return lo + i
            pos = lo
        return -1


ParseFn = Callable[[Reader], "Hit | None"]


@dataclass
class Format:
    key: str                                   # unique id ("jpg", "mp4", "zip", ...)
    name: str                                  # "JPEG image"
    category: str                              # one of CATEGORIES
    exts: tuple[str, ...]                      # the extensions it can produce, the usual one first
    magic: tuple[tuple[int, bytes], ...]       # (offset from the file start, bytes): any one matching → candidate
    parse: ParseFn
    max_size: int = 4 * GiB                    # files longer than this are cut (and get CHANCE_POOR)
    min_size: int = 1                          # shorter results are dropped as false positives
    enabled: bool = True                       # off by default (noisy formats like plain text)
    aliases: tuple[str, ...] = field(default_factory=tuple)   # other names users may type (jpeg → jpg)
