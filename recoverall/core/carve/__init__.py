"""File carving: finding files by their signatures, without a filesystem (what PhotoRec does).

    from recoverall.core.carve import carve, resolve_formats
    for f in carve(src, resolve_formats("photo,mp4,-gif"), ctl=ctl):
        print(f.offset, f.length, f.filename, f.chance)

The formats live in one module per family (images, video, audio, documents, archives, misc, misc2), each exporting
``FORMATS``; they are collected here. A module that is missing or fails to import is skipped (with a
warning in the log) so one broken parser never takes the engine down.
"""

from __future__ import annotations

import importlib
import logging
import re
from typing import Iterable, Iterator

from ..blockio import Source
from ..errors import RallError
from ..fs.base import NULL_CONTROL, Control
from .base import CATEGORIES, CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, Format, Hit, Reader
from .engine import CarvedFile, Carver

__all__ = ["CATEGORIES", "CHANCE_FAIR", "CHANCE_GOOD", "CHANCE_POOR", "FORMATS", "CarvedFile", "Carver", "Format",
           "Hit", "Reader", "UnknownFormat", "carve", "formats_table", "resolve_formats"]

log = logging.getLogger(__name__)

_MODULES = ("images", "video", "audio", "documents", "archives", "misc", "misc2")

# What users may type for a category.
_CATEGORY_WORDS = {
    "photo": "photo", "photos": "photo", "picture": "photo", "pictures": "photo", "image": "photo",
    "images": "photo", "video": "video", "videos": "video", "movie": "video", "movies": "video",
    "audio": "audio", "music": "audio", "sound": "audio", "document": "document", "documents": "document",
    "docs": "document", "archive": "archive", "archives": "archive", "email": "email", "e-mail": "email",
    "mail": "email", "database": "database", "databases": "database", "executable": "executable",
    "executables": "executable", "programs": "executable", "program": "executable", "other": "other",
}


class UnknownFormat(RallError, ValueError):
    """A file type the user asked for isn't known."""


def _collect() -> list[Format]:
    out: list[Format] = []
    seen: set[str] = set()
    for name in _MODULES:
        try:
            mod = importlib.import_module(f"{__name__}.{name}")
        except Exception as exc:                 # not written yet, or broken: carve without it
            log.warning("File carving: the %s formats are not available (%s)", name, exc)
            continue
        formats = getattr(mod, "FORMATS", None)
        if not isinstance(formats, (list, tuple)):
            log.warning("File carving: %s has no FORMATS list", name)
            continue
        for f in formats:
            if not isinstance(f, Format):
                log.warning("File carving: %s lists something that isn't a Format: %r", name, f)
                continue
            if f.key in seen:
                log.warning("File carving: format key %r of %s is already used, skipped", f.key, name)
                continue
            seen.add(f.key)
            out.append(f)
    return out


FORMATS: list[Format] = _collect()


def formats_table() -> list[dict]:
    """The formats for the file-type picker, grouped by category in the GUI's order."""
    order = {c: i for i, c in enumerate(CATEGORIES)}
    rows = [{"key": f.key, "name": f.name, "category": f.category, "exts": list(f.exts), "enabled": f.enabled}
            for f in FORMATS]
    rows.sort(key=lambda r: (order.get(r["category"], len(order)), r["name"].lower()))
    return rows


def _lookup(word: str) -> list[Format]:
    if word == "all":
        return [f for f in FORMATS if f.enabled]
    if word in ("everything", "all+"):
        return list(FORMATS)
    cat = _CATEGORY_WORDS.get(word)
    if cat is not None:
        return [f for f in FORMATS if f.category == cat and f.enabled]
    exact = [f for f in FORMATS if f.key == word]
    if exact:
        return exact
    return [f for f in FORMATS if word in f.aliases or word in f.exts]


def resolve_formats(spec: str | Iterable | None = None) -> list[Format]:
    """The formats a user's choice means. None: every format that is on by default. Otherwise keys,
    extensions, aliases ("jpeg", "mov") or category names ("photo", "videos", "music"), separated by commas
    or spaces; "all" means every format that is on by default, "everything" really all of them. A word with
    a leading "-" removes formats ("all,-txt"). Formats named explicitly are used even when off by default.
    Raises UnknownFormat for words that mean nothing."""
    if spec is None:
        return [f for f in FORMATS if f.enabled]
    words = re.split(r"[\s,;]+", spec) if isinstance(spec, str) else list(spec)
    chosen: dict[str, Format] = {}
    removed: set[str] = set()
    adds = 0
    extra: list[Format] = []
    for w in words:
        if isinstance(w, Format):
            if w.key not in chosen:
                chosen[w.key] = w
                if w not in FORMATS:
                    extra.append(w)
            adds += 1
            continue
        word = str(w).strip().lower()
        if not word:
            continue
        neg = word[0] in "-!"
        word = word.lstrip("-!").lstrip(".")
        found = _lookup(word)
        if not found:
            raise UnknownFormat(f"Unknown file type: {w}")
        if neg:
            removed.update(f.key for f in found)
            for f in found:
                chosen.pop(f.key, None)
        else:
            adds += 1
            for f in found:
                chosen[f.key] = f
    if not adds and removed:                     # only removals: start from the default set
        chosen = {f.key: f for f in FORMATS if f.enabled and f.key not in removed}
    return [f for f in FORMATS if f.key in chosen] + [f for f in extra if f.key in chosen]


def carve(src: Source, formats=None, block_size: int = 512, start: int = 0, end: int | None = None,
          ctl: Control = NULL_CONTROL, keep_corrupted: bool = False, skip_inside: bool = True
          ) -> Iterator[CarvedFile]:
    """Every file found by signature in [start, end) of SRC (see :class:`Carver`)."""
    carver = Carver(src, formats, block_size=block_size, keep_corrupted=keep_corrupted, skip_inside=skip_inside)
    yield from carver.scan(start, end, ctl)
