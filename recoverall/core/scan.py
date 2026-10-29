"""Scans: find every volume on a source and every file in them, into a scan file (results.ScanDB).

What a scan does depends on its options (the GUI's choices map to them):

* ``fs`` — read the partition table and each filesystem's metadata: existing and deleted files with their
  names and folders. Minutes, even on big disks (Quick scan).
* ``deep`` — read the whole source once, in order, and look at every sector: boot sectors and superblocks
  (and their backups) of lost and damaged filesystems, NTFS MFT records without a boot sector, and — with
  ``carve`` — the start of every known file type. Then read the metadata of every filesystem found
  (Deep scan: deleted partitions, formatted and damaged drives).
* ``carve`` — the signature search alone, like PhotoRec. With ``free_only`` it only looks at space no
  filesystem uses (faster, finds deleted files only, and finds files written around used clusters whole).

Files found by signature that a filesystem also knows (same first byte) are dropped at the end: the
filesystem's copy has the real name, folder and dates.
"""

from __future__ import annotations

import logging
import os
import time

from . import fs as fsmod
from .blockio import CachedSource, ConcatSource, Source, open_source
from .errors import Cancelled, RallError
from .fs.base import CHANCE_GOOD, F_CARVED, F_THUMBNAIL, NULL_CONTROL, Control, Entry, read_content, read_head
from .results import ScanDB
from .util import fmt_bytes, fmt_rate

log = logging.getLogger(__name__)

PRESETS = {
    "quick": {"fs": True, "deep": False, "carve": False},
    "deep": {"fs": True, "deep": True, "carve": True},
    "carve": {"fs": False, "deep": False, "carve": True, "free_only": False},
    "photos": {"fs": True, "deep": False, "carve": True, "free_only": True, "formats": ["photo", "video"]},
}

MODE_TEXT = {
    "quick": "Quick scan",
    "deep": "Deep scan",
    "carve": "Signature search",
    "photos": "Photo recovery",
}

# One character per cell of the scan map (the GUI colours them).
MAP_UNREAD, MAP_READ, MAP_FS, MAP_BAD = ".", "-", "F", "X"
MAP_CATEGORY = {"photo": "p", "video": "v", "audio": "a", "document": "d", "archive": "z", "email": "e",
                "database": "b", "executable": "x", "other": "o"}
MAP_CELLS = 1600


def scan_options(options: dict | None) -> dict:
    opts = dict(options or {})
    preset = PRESETS.get(opts.get("mode") or "quick", PRESETS["quick"])
    for k, v in preset.items():
        opts.setdefault(k, v)
    opts.setdefault("mode", "quick")
    opts.setdefault("free_only", False)
    opts.setdefault("lost_dirs", bool(opts.get("deep")))
    opts.setdefault("tsk", True)
    return opts


class ScanMap:
    """The scan map: MAP_CELLS characters for the whole source, updated as the scan reads and finds."""

    def __init__(self, size: int, cells: int = MAP_CELLS):
        self.size = max(1, size)
        self.n = cells
        self.cells = [MAP_UNREAD] * cells
        self.changed = True

    def cell(self, offset: int) -> int:
        return min(self.n - 1, max(0, offset * self.n // self.size))

    def read_up_to(self, offset: int) -> None:
        last = self.cell(offset - 1) if offset > 0 else -1
        for i in range(last + 1):
            if self.cells[i] == MAP_UNREAD:
                self.cells[i] = MAP_READ
                self.changed = True

    def mark(self, offset: int, ch: str, length: int = 0) -> None:
        first = self.cell(offset)
        last = self.cell(offset + max(0, length - 1)) if length else first
        for i in range(first, last + 1):
            cur = self.cells[i]
            # bad sectors win, then filesystem structures, then files
            if cur == MAP_BAD or (cur == MAP_FS and ch not in (MAP_BAD,)):
                continue
            self.cells[i] = ch
            self.changed = True

    def text(self) -> str:
        self.changed = False
        return "".join(self.cells)


class Scanner:
    """Runs one scan into DB. CTL is a JobControl (or any Control); JOB is used for live data (map, counts)."""

    def __init__(self, src: Source, db: ScanDB, options: dict, ctl: Control = NULL_CONTROL, job=None):
        self.src = src
        self.db = db
        self.opts = scan_options(options)
        self.ctl = ctl
        self.job = job
        self.map = ScanMap(src.size)
        self.found = {"volumes": 0, "files": 0, "deleted": 0, "carved": {}, "bad": 0}
        self.volumes: list[dict] = []          # what we know about each volume (id → db)
        self.carved_vol: int | None = None
        self.carved_folders: set[str] = set()
        self.carved_writer = None
        self.table: dict | None = None
        self._last_publish = 0.0
        self.warnings: list[str] = []

    # ------------------------------------------------------------------ reporting
    def publish(self, force: bool = False, **extra) -> None:
        if self.job is None:
            return
        now = time.monotonic()
        if not force and now - self._last_publish < 0.4:
            return
        self._last_publish = now
        data = {"found": dict(self.found, carved=dict(self.found["carved"])),
                "volumes": [{k: v.get(k) for k in ("id", "name", "fstype", "label", "offset", "size", "status",
                                                    "origin", "files", "deleted_files")} for v in self.volumes]}
        if self.map.changed or force:
            data["map"] = self.map.text()
        data.update(extra)
        self.job.update(**data)

    def warn(self, text: str) -> None:
        if text not in self.warnings:
            self.warnings.append(text)
        self.ctl.warn(text)

    # ------------------------------------------------------------------ the whole scan
    def run(self) -> dict:
        o = self.opts
        steps = ["Partition table"]
        if o["deep"]:
            steps.append("Read the whole disk" + (" (filesystems and signatures)" if o["carve"] else ""))
        if o["fs"] or o["deep"]:
            steps.append("Read the filesystems")
        if o["carve"] and not o["deep"]:
            steps.append("Search " + ("the free space" if o["free_only"] else "everything") + " for files by signature")
        steps.append("Finish")
        if self.job is not None:
            self.job.set_steps(steps)
        step = 0

        def next_step(detail: str = "") -> None:
            nonlocal step
            if self.job is not None:
                self.job.step(step, detail)
            step += 1

        next_step()
        self.read_table()
        if o["deep"]:
            next_step()
            cands = self.deep_pass()
            self.add_found_volumes(cands)
        if o["fs"] or o["deep"]:
            next_step(f"{len(self.volumes)} volume{'s' if len(self.volumes) != 1 else ''}")
            self.read_filesystems()
        if o["carve"] and not o["deep"]:
            next_step()
            self.carve_pass()
        next_step()
        return self.finish()

    # ------------------------------------------------------------------ 1. the partition table
    def read_table(self) -> None:
        src = self.src
        self.ctl.progress(0.0, "Reading the partition table…")
        try:
            from . import partitions
            self.table = partitions.read_table(src)
        except ImportError:
            self.table = {"type": "none", "partitions": [], "problems": []}
        except Exception as exc:  # noqa: BLE001 - a damaged table is what we're here for
            self.table = {"type": "none", "partitions": [], "problems": [str(exc)]}
            self.warn(f"The partition table couldn't be read: {exc}")
        t = self.table
        for p in t.get("problems") or []:
            self.warn(p)
        parts = [p for p in t.get("partitions") or [] if not _is_extended(p)]
        want = self.opts.get("volumes")
        if want:
            parts = [p for p in parts if int(p["start"]) in {int(x) for x in want}]
        if not parts and not want:
            # no table: a filesystem on the whole source ("superfloppy": cards, sticks, partition images)
            parts = [{"number": 0, "start": 0, "size": src.size, "whole": True}]
        for p in parts:
            start, size = int(p["start"]), int(p["size"])
            if start >= src.size or size <= 0:
                self.warn(f"Partition {p.get('number')} lies outside the disk")
                continue
            size = min(size, src.size - start)
            info = _identify(src, start, size)
            fstype = info.get("fstype") or ""
            if p.get("whole") and not fstype:
                continue                       # an empty or unknown disk: the deep scan may find more
            vol = {"number": p.get("number"), "offset": start, "size": size, "fstype": fstype,
                   "label": info.get("label") or p.get("name") or "", "origin": "table",
                   "status": "existing", "score": 100, "info": {}, "probe": info,
                   "name": _volume_name(p.get("number"), info.get("label") or p.get("name"), fstype, p.get("whole"))}
            if not fstype:
                vol["status"] = "unknown filesystem"
            self._register(vol)
        self.publish(force=True)

    def _register(self, vol: dict) -> dict:
        vid = self.db.add_volume(name=vol["name"], fstype=vol["fstype"], label=vol["label"], offset=vol["offset"],
                                 size=vol["size"], block_size=vol.get("block_size") or 0, origin=vol["origin"],
                                 status=vol["status"], score=vol.get("score", 0), engine="",
                                 info=vol.get("info") or {}, state="pending", note=vol.get("note") or "")
        vol["id"] = vid
        vol.setdefault("files", 0)
        vol.setdefault("deleted_files", 0)
        self.volumes.append(vol)
        self.found["volumes"] = len(self.volumes)
        self.map.mark(vol["offset"], MAP_FS)
        return vol

    # ------------------------------------------------------------------ 2. the deep pass
    def deep_pass(self) -> list[dict]:
        src = self.src
        detectors = _detectors()
        carver = self._carver(src) if self.opts["carve"] else None
        size = src.size
        chunk = 8 * 1024 * 1024
        start_t = time.monotonic()
        pos = 0
        bad_before = src.bad.total
        ctl = self.ctl
        for pos, buf in src.read_into_chunks(0, size, chunk):
            ctl.check()
            for d in list(detectors):
                try:
                    d.feed(pos, buf)
                except Exception as exc:  # noqa: BLE001 - one detector failing must not stop the scan
                    log.exception("detector %s failed", type(d).__name__)
                    self.warn(f"{type(d).__name__}: {exc}")
                    detectors.remove(d)
            if carver is not None:
                try:
                    for cf in carver.feed(pos, buf):
                        self._add_carved(cf)
                except Cancelled:
                    raise
                except Exception as exc:  # noqa: BLE001
                    log.exception("carver failed")
                    self.warn(f"The signature search stopped: {exc}")
                    carver = None
            end = pos + len(buf)
            self.map.read_up_to(end)
            if src.bad.total != bad_before:
                for off, n in src.bad.ranges():
                    if off < end and off + n > pos:
                        self.map.mark(off, MAP_BAD, n)
                self.found["bad"] = src.bad.total
            elapsed = time.monotonic() - start_t
            rate = end / elapsed if elapsed > 0.5 else None
            eta = (size - end) / rate if rate else None
            found = sum(self.found["carved"].values())
            msg = f"Reading {fmt_bytes(end)} of {fmt_bytes(size)}" + (f" · {fmt_rate(rate)}" if rate else "")
            if found:
                msg += f" · {found:,} files by signature".replace(",", " ")
            ctl.progress(end / size if size else 1.0, msg, done=end, total=size, rate=rate, eta=eta, label="Read")
            self.publish()
        if carver is not None:
            for cf in carver.flush():
                self._add_carved(cf)
        cands = []
        for d in detectors:
            try:
                cands.extend(d.finish() or [])
            except Exception as exc:  # noqa: BLE001
                log.exception("detector %s failed at the end", type(d).__name__)
                self.warn(f"{type(d).__name__}: {exc}")
        if src.bad.total:
            self.warn(f"{fmt_bytes(src.bad.total)} of the disk couldn't be read (bad sectors): they read as zeros")
        self.publish(force=True)
        return cands

    def add_found_volumes(self, cands: list[dict]) -> None:
        """Merge what the deep pass found with the partition table: new volumes for deleted partitions,
        damaged and reconstructed filesystems."""
        merged = _merge(cands, self.src.size, self.src.sector_size, self.table)
        known = {(v["offset"], v["fstype"]) for v in self.volumes}
        known_off = {v["offset"]: v for v in self.volumes}
        for c in merged:
            fstype = c.get("fstype") or ""
            off = int(c.get("offset") or 0)
            size = int(c.get("size") or 0)
            if c.get("inside") is not None or c.get("status") == "overlaps":
                continue
            if size <= 0 or off < 0 or off >= self.src.size:
                continue
            size = min(size, self.src.size - off)
            if (off, fstype) in known:
                v = known_off.get(off)
                if v and c.get("info"):
                    v.setdefault("info", {}).update(c["info"])
                continue
            if off in known_off and known_off[off]["fstype"] in ("", None):
                v = known_off[off]
                v["fstype"] = fstype
                v["info"] = dict(c.get("info") or {})
                v["status"] = "damaged" if c.get("status") == "damaged" else v["status"]
                self.db.update_volume(v["id"], fstype=fstype, info=v["info"], status=v["status"])
                continue
            if fsmod.reader_class(fstype) is None and fstype not in fsmod.READERS:
                # containers (LUKS, LVM, RAID members, swap) are shown, not read
                pass
            status = {"current": "existing", "deleted": "deleted partition", "damaged": "damaged"}.get(
                c.get("status") or "", c.get("status") or "found")
            if c.get("evidence") == "MFT records":
                status = "reconstructed"
            label = c.get("label") or ""
            vol = {"number": None, "offset": off, "size": size, "fstype": fstype, "label": label, "origin": "found",
                   "status": status, "score": int(c.get("score") or 0), "info": dict(c.get("info") or {}),
                   "evidence": c.get("evidence"), "note": c.get("evidence") or "",
                   "name": label or f"{fsmod.fs_name(fstype)} at {fmt_bytes(off)}"}
            self._register(vol)
            known.add((off, fstype))
            known_off.setdefault(off, vol)
        self.publish(force=True)

    # ------------------------------------------------------------------ 3. filesystems
    def read_filesystems(self) -> None:
        vols = [v for v in self.volumes if v["fstype"]]
        total = sum(v["size"] for v in vols) or 1
        done = 0
        for v in vols:
            self.ctl.check()
            lo = done / total
            hi = (done + v["size"]) / total
            sub = self.ctl.sub(lo, hi) if hasattr(self.ctl, "sub") else self.ctl
            self.read_volume(v, sub)
            done += v["size"]
            self.publish(force=True)

    def open_reader(self, v: dict, cached: Source):
        fstype = v["fstype"]
        info = dict(v.get("info") or {})
        if self.opts.get("lost_dirs"):
            info.setdefault("scan_lost_dirs", True)
        if self.opts.get("deep"):
            info.setdefault("scan_free_space", True)      # XFS: inodes of freed inode chunks
        reader = None
        engine = "native"
        cls = fsmod.reader_class(fstype)
        if cls is not None and fsmod.READERS.get(fstype, ("",))[0] != "tsk":
            try:
                probed = None
                if not info.get("reconstructed"):
                    try:
                        probed = cls.probe(cached)
                    except Exception:  # noqa: BLE001
                        probed = None
                merged = dict(probed or {})
                merged.update(info)
                if probed is not None or info:
                    reader = cls(cached, merged)
            except Exception as exc:  # noqa: BLE001
                log.info("native reader for %s failed: %s", fstype, exc)
                self.warn(f"{v['name']}: {exc}")
                reader = None
        if reader is None and self.opts.get("tsk"):
            try:
                from .fs import tsk
                if tsk.available() and getattr(self.src, "path", "") and not isinstance(self.src, ConcatSource):
                    region = self.src.region(v["offset"], v["size"])
                    reader = tsk.TskReader(region, {"fstype": fstype, **info})
                    engine = "The Sleuth Kit"
            except Exception as exc:  # noqa: BLE001
                log.info("TSK for %s failed: %s", fstype, exc)
                reader = None
        return reader, engine

    def read_volume(self, v: dict, ctl: Control) -> None:
        region = self.src.region(v["offset"], v["size"])
        cached = CachedSource(region)
        fstype = v["fstype"]
        name = fsmod.fs_name(fstype)
        if fstype in ("crypto_luks", "bitlocker"):
            self._note(v, "encrypted", f"{name}: unlock it (Drives → Unlock) and scan the unlocked volume")
            return
        if fstype in ("linux_raid_member", "lvm2_member", "zfs_member"):
            self._note(v, "member", f"{name}: part of a RAID/LVM set — scan the assembled volume, or build a "
                                    "virtual RAID from its members (Imaging → Virtual RAID)")
            return
        if fstype == "swap":
            self._note(v, "swap", "Swap space: no files (a signature search can still look inside)")
            return
        reader, engine = self.open_reader(v, cached)
        if reader is None:
            self._note(v, "unreadable", f"No reader for {name} here" + (
                "" if fsmod.reader_class(fstype) else " (a signature search still finds files by type)"))
            return
        self.db.update_volume(v["id"], state="reading", engine=engine)
        ctl.progress(0.0, f"Reading {v['name']} ({name})…")
        files = deleted = 0
        last = time.monotonic()
        try:
            with self.db.writer(v["id"], base=v["offset"]) as w:
                for e in reader.entries(ctl, deleted=True):
                    w.add(e)
                    if not e.is_dir:
                        files += 1
                        if e.deleted:
                            deleted += 1
                    if files & 255 == 0:
                        ctl.check()
                        now = time.monotonic()
                        if now - last > 0.5:
                            last = now
                            v["files"], v["deleted_files"] = files, deleted
                            self.found["files"] = sum(x.get("files", 0) for x in self.volumes)
                            self.found["deleted"] = sum(x.get("deleted_files", 0) for x in self.volumes)
                            ctl.progress(None, f"{v['name']}: {files:,} files, {deleted:,} deleted".replace(",", " "))
                            self.publish()
        except Cancelled:
            self.db.update_volume(v["id"], state="cancelled")
            raise
        except Exception as exc:  # noqa: BLE001 - keep what was found
            log.exception("reading %s failed", v["name"])
            self.warn(f"{v['name']}: reading stopped early ({exc})")
            v["state"] = "partial"
        vol = self.db.volume(v["id"])
        v["files"], v["deleted_files"] = vol["files"], vol["deleted_files"]
        self.found["files"] = sum(x.get("files", 0) for x in self.volumes)
        self.found["deleted"] = sum(x.get("deleted_files", 0) for x in self.volumes)
        warnings = list(getattr(reader, "warnings", []) or [])[:50]
        label = getattr(reader, "label", "") or v["label"]
        bs = int(getattr(reader, "block_size", 0) or 0)
        v["reader_block"] = bs
        self.db.update_volume(v["id"], state=v.get("state") or "done", warnings=warnings, label=label,
                              block_size=bs, name=v["name"] if v["label"] or not label else
                              _volume_name(v.get("number"), label, fstype, v["offset"] == 0 and v["size"] ==
                                           self.src.size))
        v["reader"] = reader

    def _note(self, v: dict, state: str, note: str) -> None:
        self.db.update_volume(v["id"], state=state, note=note)
        v["state"] = state

    # ------------------------------------------------------------------ 4. signatures (without a deep pass)
    def carve_pass(self) -> None:
        src = self.src
        if self.opts.get("free_only"):
            parts = self.free_space()
            if parts is None:
                stream: Source = src
                self.ctl.log("No filesystem tells which space is free: searching everything")
            else:
                stream = ConcatSource([(src, o, n) for o, n in parts], name="free space")
                self.ctl.log(f"Searching {fmt_bytes(stream.size)} of free space ({len(parts)} areas)")
        else:
            stream = src
        carver = self._carver(stream)
        if carver is None:
            return
        size = stream.size
        start_t = time.monotonic()
        mapper = stream.map_range if isinstance(stream, ConcatSource) else None
        for pos, buf in stream.read_into_chunks(0, size, 8 * 1024 * 1024):
            self.ctl.check()
            for cf in carver.feed(pos, buf):
                self._add_carved(cf, mapper)
            end = pos + len(buf)
            if mapper is None:
                self.map.read_up_to(end)
            else:
                for off, n in mapper(pos, len(buf)):
                    self.map.mark(off, MAP_READ, n)
            elapsed = time.monotonic() - start_t
            rate = end / elapsed if elapsed > 0.5 else None
            found = sum(self.found["carved"].values())
            self.ctl.progress(end / size if size else 1.0,
                              f"Searching {fmt_bytes(end)} of {fmt_bytes(size)} · {found:,} files found".replace(",", " "),
                              done=end, total=size, rate=rate, eta=(size - end) / rate if rate else None, label="Searched")
            self.publish()
        for cf in carver.flush():
            self._add_carved(cf, mapper)

    def free_space(self) -> list[tuple[int, int]] | None:
        """Unallocated areas of the source: gaps between volumes + free extents of every filesystem we can
        read. None when nothing is known (no filesystem)."""
        if not self.volumes:
            return None
        out: list[tuple[int, int]] = []
        vols = sorted(self.volumes, key=lambda v: v["offset"])
        pos = 0
        for v in vols:
            if v["offset"] > pos:
                out.append((pos, v["offset"] - pos))
            reader = v.get("reader")
            free = None
            if reader is None and v["fstype"]:
                reader, _e = self.open_reader(v, CachedSource(self.src.region(v["offset"], v["size"])))
            if reader is not None:
                try:
                    free = reader.free_extents(self.ctl)
                except Exception as exc:  # noqa: BLE001
                    self.warn(f"{v['name']}: free space unknown ({exc})")
            if free is None:
                out.append((v["offset"], v["size"]))
            else:
                out.extend((v["offset"] + o, n) for o, n in free if n > 0)
            pos = max(pos, v["offset"] + v["size"])
        if pos < self.src.size:
            out.append((pos, self.src.size - pos))
        out.sort()
        merged: list[tuple[int, int]] = []
        for o, n in out:
            if merged and merged[-1][0] + merged[-1][1] >= o:
                po, pn = merged[-1]
                merged[-1] = (po, max(po + pn, o + n) - po)
            else:
                merged.append((o, n))
        return merged

    def _carver(self, stream: Source):
        try:
            from .carve import Carver, resolve_formats
        except ImportError as exc:
            self.warn(f"The signature search isn't available: {exc}")
            return None
        formats = resolve_formats(self.opts.get("formats"))
        if not formats:
            return None
        return Carver(stream, formats=formats, block_size=int(self.opts.get("block_size") or 512),
                      keep_corrupted=bool(self.opts.get("keep_corrupted")))

    def _add_carved(self, cf, mapper=None) -> None:
        if self.carved_vol is None:
            vol = {"number": None, "offset": 0, "size": self.src.size, "fstype": "carved", "label": "",
                   "origin": "carved", "status": "carved", "score": 0, "info": {},
                   "name": "Files found by signature"}
            self._register(vol)
            self.carved_vol = vol["id"]
            self.carved_writer = self.db.writer(vol["id"], base=0)
            self.carved_writer.add(Entry(key="__root__", parent=None, name="", is_dir=True))
        w = self.carved_writer
        cat = cf.category or "other"
        catkey = f"cat:{cat}"
        if catkey not in self.carved_folders:
            from .filetypes import CATEGORY_NAMES
            w.add(Entry(key=catkey, parent="__root__", name=CATEGORY_NAMES.get(cat, cat.title()), is_dir=True))
            self.carved_folders.add(catkey)
        typekey = f"type:{cat}:{cf.ext}"
        if cf.info and cf.info.get("needs_index"):
            # recordings that were never finished: not playable until repaired with a reference video
            typekey += ":unfinished"
            if typekey not in self.carved_folders:
                w.add(Entry(key=typekey, parent=catkey, name=f"Unfinished recordings (.{cf.ext}) — repair them with "
                            "a reference video", is_dir=True))
                self.carved_folders.add(typekey)
        if typekey not in self.carved_folders:
            w.add(Entry(key=typekey, parent=catkey, name=f"{(cf.description or cf.ext.upper())} (.{cf.ext})",
                        is_dir=True))
            self.carved_folders.add(typekey)
        runs = []
        for off, n in cf.pieces():
            runs.extend(mapper(off, n) if mapper else [(off, n)])
        base = cf.name or f"f{runs[0][0] // 512:010d}"
        info = {"desc": cf.description, "format": cf.key}
        if cf.info:
            info["info"] = cf.info
        if len(runs) > 1:
            info["fragments"] = len(runs)
        w.add(Entry(key=f"c{runs[0][0]}", parent=typekey, name=f"{base}.{cf.ext}", size=cf.length, deleted=True,
                    runs=runs, mtime=cf.mtime, chance=cf.chance, flags=F_CARVED, extra=info))
        self.found["carved"][cat] = self.found["carved"].get(cat, 0) + 1
        self.map.mark(runs[0][0], MAP_CATEGORY.get(cat, "o"), min(cf.length, 1))

    # ------------------------------------------------------------------ 5. finish
    # ------------------------------------------------------------------ 4b. thumbnail caches
    THUMB_LIMIT = 512 * 1024 * 1024          # a bigger cache file isn't read
    THUMB_TOTAL = 1024 * 1024 * 1024         # thumbnails kept per scan at most

    def thumbnail_pass(self) -> None:
        """Thumbnails that thumbnail caches kept of photos (Windows thumbcache_*.db and Thumbs.db, Android
        .thumbdata, Linux desktop thumbnails, macOS QuickLook): the photo may be deleted and overwritten, its
        thumbnail often isn't. They go into a volume of their own, a folder per cache file."""
        if self.opts.get("thumbnails") is False:
            return
        try:
            from .media import thumbcache
        except ImportError:
            return
        rows = self.db.conn.execute(
            "SELECT e.id, e.vol, e.name, e.parent FROM entries e WHERE e.is_dir = 0 AND e.size > 0 AND e.size <= ? AND ("
            "lower(e.name) LIKE 'thumbcache%.db' OR lower(e.name) IN ('thumbs.db', 'ehthumbs.db', 'ehthumbs_vista.db', "
            "'index.sqlite') OR lower(e.name) LIKE '.thumbdata%' OR (lower(e.name) LIKE '%.png' AND "
            "length(e.name) = 36))", (self.THUMB_LIMIT,)).fetchall()
        vols = {v["id"]: v for v in self.volumes if v.get("origin") not in ("carved", "thumbnails")}
        regions: dict[int, Source] = {}

        def region(vid: int) -> Source:
            if vid not in regions:
                v = vols[vid]
                regions[vid] = self.src.region(int(v["offset"]), int(v["size"]) or None)
            return regions[vid]

        def content(eid: int) -> bytes:
            e = self.db.entry(eid)
            return b"".join(read_content(region(e["vol"]), e))

        writer = None
        total = 0
        caches = 0
        made: dict[str, set[str]] = {}               # folder key → the names used in it
        for eid, vid, name, parent in rows:
            if vid not in vols:
                continue
            self.ctl.check()
            try:
                path = self.db.path_of(eid)
                kind = thumbcache.kind_of(path, read_head(region(vid), self.db.entry(eid), 65536))
                if kind is None or kind in ("android_thumbnail", "quicklook_data"):
                    continue                 # plain picture files are listed already; QuickLook goes by its index
                companion = None
                if kind == "quicklook_index":
                    sib = self.db.conn.execute("SELECT id FROM entries WHERE parent = ? AND is_dir = 0 AND "
                                               "lower(name) = 'thumbnails.data'", (parent,)).fetchone()
                    if sib is None:
                        continue
                    companion = content(sib[0])
                thumbs = thumbcache.extract(content(eid), kind, companion)
            except (RallError, OSError, KeyError, ValueError) as exc:
                self.warn(f"The thumbnail cache {name} couldn't be read: {exc}")
                continue
            if not thumbs:
                continue
            if writer is None:
                vol = {"number": None, "offset": 0, "size": 0, "fstype": "thumbnails", "label": "",
                       "origin": "thumbnails", "status": "found", "score": 0, "info": {},
                       "name": "Thumbnails of deleted photos"}
                self._register(vol)
                writer = self.db.writer(vol["id"], base=0)
                writer.add(Entry(key="__root__", parent=None, name="", is_dir=True))
                thumb_vol = vol
            caches += 1
            if kind == "freedesktop":                # one PNG per photo: one folder for all of them
                fkey = "cache:freedesktop"
                if fkey not in made:
                    writer.add(Entry(key=fkey, parent="__root__", name="Linux desktop thumbnails", is_dir=True))
                    made[fkey] = set()
            else:
                fkey = f"cache:{eid}"
                writer.add(Entry(key=fkey, parent="__root__", name=f"{name} ({os.path.dirname(path) or '/'})",
                                 is_dir=True))
                made[fkey] = set()
            used = made[fkey]
            for i, t in enumerate(thumbs):
                if total + len(t.data) > self.THUMB_TOTAL:
                    self.warn("Too many thumbnails: the rest of the thumbnail caches weren't read")
                    break
                total += len(t.data)
                fname = t.filename
                k = 2
                while fname.lower() in used:
                    fname = f"{t.name} ({k}).{t.ext}"
                    k += 1
                used.add(fname.lower())
                info = {"width": t.width, "height": t.height} if t.width else {}
                writer.add(Entry(key=f"t:{eid}:{i}", parent=fkey, name=fname, size=len(t.data), data=t.data,
                                 mtime=t.mtime, deleted=True, chance=CHANCE_GOOD, flags=F_THUMBNAIL,
                                 extra={"desc": "Thumbnail", "original": t.original_path,
                                        "source": f"{thumbcache.KINDS.get(kind, kind)}: {path}", "info": info}))
            if total > self.THUMB_TOTAL:
                break
        if writer is not None:
            writer.finish()
            vol = self.db.volume(thumb_vol["id"])
            thumb_vol["files"] = vol["files"]
            self.db.update_volume(thumb_vol["id"], state="done")
            self.ctl.log(f"{vol['files']:,} thumbnails found in {caches} thumbnail cache"
                         f"{'s' if caches != 1 else ''}".replace(",", " "))

    def finish(self) -> dict:
        try:
            self.thumbnail_pass()
        except Cancelled:
            raise
        except Exception as exc:  # noqa: BLE001 - an extra: never fail a scan for it
            log.warning("thumbnail caches: %s", exc, exc_info=True)
        if self.carved_writer is not None:
            self.carved_writer.finish()
            if any(v["origin"] != "carved" and v.get("files") for v in self.volumes):
                removed = self.db.drop_duplicates(self.carved_vol)
                if removed:
                    self.ctl.log(f"{removed:,} files found by signature are also in a filesystem: "
                                 "kept the filesystem's copy (with its name)".replace(",", " "))
            vol = self.db.volume(self.carved_vol)
            for v in self.volumes:
                if v["id"] == self.carved_vol:
                    v["files"] = vol["files"]
            self.db.update_volume(self.carved_vol, state="done")
        stats = self.db.stats()
        self.db.set_meta(state="complete", finished=time.time(), stats=stats, warnings=self.warnings[:200],
                         bad=self.src.bad.ranges()[:10000], table=_table_brief(self.table))
        self.found["files"] = stats["files"]
        self.publish(force=True)
        return {"stats": stats, "volumes": len(self.volumes), "warnings": len(self.warnings)}


# ---------------------------------------------------------------------- the job
def run_scan(job, source_spec, db_path: str, options: dict | None = None, ctl: Control | None = None) -> dict:
    """The job body: scan SOURCE_SPEC (a path, a RAID definition, or {"path", "offset", "size"}) into a
    new scan file DB_PATH."""
    from .jobs import JobControl
    opts = scan_options(options)
    src = open_source(source_spec)
    try:
        region = opts.get("region")
        if region:
            src_view = src.region(int(region.get("offset") or 0), region.get("size"))
        else:
            src_view = src
        db = ScanDB.create(db_path, source=_source_meta(source_spec, src, region), options=opts)
        ctl = ctl or (JobControl(job) if job is not None else NULL_CONTROL)
        scanner = Scanner(src_view, db, opts, ctl, job)
        try:
            result = scanner.run()
        except Cancelled:
            db.set_meta(state="cancelled", finished=time.time(), stats=db.stats())
            raise
        finally:
            db.close()
        result["scan"] = db_path
        if job is not None:
            n = result["stats"]["files"]
            job.update(message=f"Found {n:,} files ({result['stats']['deleted_files']:,} deleted) on "
                               f"{result['volumes']} volume{'s' if result['volumes'] != 1 else ''}".replace(",", " "))
        return result
    finally:
        src.close()


def _source_meta(spec, src: Source, region) -> dict:
    d = {"spec": spec, "size": src.size, "sector_size": src.sector_size, "name": src.name, "region": region}
    path = spec if isinstance(spec, str) else (spec.get("path") if isinstance(spec, dict) else None)
    if path and os.path.exists(path) and not os.path.isfile(path):
        try:
            from .devices import disk_info
            disk = disk_info(path)
            d.update({k: disk.get(k) for k in ("model", "serial", "display_name", "kind", "capacity_text")})
        except (RallError, OSError):
            pass
    elif path:
        d["display_name"] = os.path.basename(path)
    return d


def source_of(db: ScanDB) -> Source:
    """The source a scan was made of (opened again: for recovering and previewing files)."""
    meta = db.meta("source") or {}
    spec = meta.get("spec")
    if spec is None:
        raise RallError("This scan doesn't say which disk it was made of")
    try:
        src = open_source(spec)
    except RallError as exc:
        raise RallError(f"The disk or image this scan was made of isn't available: {exc}") from exc
    if meta.get("size") and src.size and abs(src.size - int(meta["size"])) > 0:
        src.close()
        raise RallError("The disk or image at this path isn't the one this scan was made of (its size differs)")
    region = meta.get("region")
    if region:
        return src.region(int(region.get("offset") or 0), region.get("size"))
    return src


# ---------------------------------------------------------------------- adapters to the detection modules
def _identify(src: Source, offset: int, size: int) -> dict:
    try:
        from . import fsdetect
        return fsdetect.identify(src.region(offset, size)) or {}
    except ImportError:
        cls_info = {}
        for t in fsmod.PROBE_ORDER:
            cls = fsmod.reader_class(t)
            if cls is None:
                continue
            try:
                info = cls.probe(src.region(offset, size))
            except Exception:  # noqa: BLE001
                info = None
            if info:
                return info
        return cls_info
    except Exception:  # noqa: BLE001
        return {}


def _detectors() -> list:
    out = []
    try:
        from .partsearch import BootSectorDetector
        out.append(BootSectorDetector())
    except ImportError as exc:
        log.warning("partition search unavailable: %s", exc)
    try:
        from .fs.ntfs import MftDetector
        out.append(MftDetector())
    except ImportError as exc:
        log.warning("MFT detector unavailable: %s", exc)
    return out


def _merge(cands: list[dict], disk_size: int, sector_size: int, table: dict | None) -> list[dict]:
    try:
        from .partsearch import merge_candidates
        return merge_candidates(cands, disk_size, sector_size, table)
    except ImportError:
        return sorted(cands, key=lambda c: (c.get("offset", 0), -int(c.get("score") or 0)))


def _is_extended(p: dict) -> bool:
    t = str(p.get("type") or "").lower()
    return t in ("0x5", "0x05", "0xf", "0x0f", "0x85", "5", "f", "85")


def _volume_name(number, label: str | None, fstype: str, whole: bool | None = None) -> str:
    if label:
        return label
    if whole:
        return fsmod.fs_name(fstype) if fstype else "Whole disk"
    return f"Partition {number}" if number else fsmod.fs_name(fstype)


def _table_brief(t: dict | None) -> dict:
    if not t:
        return {}
    return {"type": t.get("type"), "problems": t.get("problems") or [],
            "partitions": [{k: p.get(k) for k in ("number", "start", "size", "type", "type_name", "name")}
                           for p in t.get("partitions") or []]}
