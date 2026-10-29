"""Copying found files out of a scan into a folder on another disk.

Folders keep their structure (``<destination>/<volume>/<path inside the volume>``), files get their dates
back, names that the destination can't store are made safe, and nothing is ever overwritten: a second
file with the same name gets " (2)". Unreadable sectors read as zeros; files that had some are listed in
the report written next to the recovered files (RecoverAll report.txt).
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from .blockio import Source
from .errors import Cancelled, RallError
from .fs.base import CHANCE_GOOD, CHANCE_NAMES, F_ADS, F_CARVED, F_SYMLINK, read_content
from .results import ScanDB
from .safety import check_destination
from .util import caller_ids, fmt_bytes, fmt_duration, fmt_rate, safe_filename

_WINDOWS_BAD = str.maketrans({c: "_" for c in '\\:*?"<>|'})
_WINDOWS_FS = ("vfat", "msdos", "exfat", "ntfs", "ntfs3", "fuseblk", "cifs", "smb3", "fat")


def dest_fstype(path: str) -> str:
    """The filesystem type of the mount holding PATH (from /proc/self/mounts)."""
    real = os.path.realpath(path)
    best, best_type = "", ""
    try:
        with open("/proc/self/mounts", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mp = parts[1].replace("\\040", " ")
                if (real == mp or real.startswith(mp.rstrip("/") + "/")) and len(mp) > len(best):
                    best, best_type = mp, parts[2]
    except OSError:
        pass
    return best_type


class Owner:
    """Files root writes into a user's folder belong to that user (the one who started the app)."""

    def __init__(self, dest: str):
        self.ids = None
        ids = caller_ids()
        if ids is not None and os.geteuid() == 0:
            try:
                p = Path(dest)
                while not p.exists() and p != p.parent:
                    p = p.parent
                if os.stat(p).st_uid == ids[0]:
                    self.ids = ids
            except OSError:
                pass

    def give(self, path: str) -> None:
        if self.ids is not None:
            try:
                os.lchown(path, *self.ids)
            except OSError:
                pass


class Recovery:
    def __init__(self, db: ScanDB, src: Source, dest: str, options: dict | None = None, ctl=None, job=None):
        self.db = db
        self.src = src
        self.dest = os.path.abspath(dest)
        self.o = dict(options or {})
        self.ctl = ctl
        self.job = job
        self.windows_names = dest_fstype(self.dest) in _WINDOWS_FS
        self.owner = Owner(self.dest)
        self.volumes = {v["id"]: v for v in db.volumes()}
        self.regions: dict[int, Source] = {}
        self.made_dirs: set[str] = set()
        self.report: list[str] = []
        self.done_bytes = 0
        self.done_files = 0
        self.failed = 0
        self.damaged = 0
        self.repaired = 0
        self.need_reference = 0
        self.written: list[tuple[dict, str]] = []     # (row, where it went), for the repair pass

    # ------------------------------------------------------------------ names and places
    def clean(self, name: str) -> str:
        name = safe_filename(name)
        if self.windows_names:
            name = name.translate(_WINDOWS_BAD).rstrip(" .") or "_"
        return name

    def volume_folder(self, vol: dict) -> str:
        from .fs import fs_name
        if vol.get("origin") == "carved":
            return self.clean("Found by signature")
        what = fs_name(vol.get("fstype"))
        name = vol.get("label") or vol.get("name") or "Volume"
        tag = {"deleted partition": ", deleted partition", "damaged": ", damaged",
               "reconstructed": ", rebuilt"}.get(vol.get("status") or "", "")
        folder = f"{name} ({what}{tag})" if name != what else f"{what}{tag}"
        if len(self.volumes) > 1 and sum(1 for v in self.volumes.values() if (v.get("label") or v.get("name")) == name) > 1:
            folder += f" at {fmt_bytes(vol.get('offset') or 0)}"
        return self.clean(folder)

    def target_path(self, e: dict) -> str:
        vol = self.volumes[e["vol"]]
        parts = [self.volume_folder(vol)] if self.o.get("volume_folders", True) else []
        if self.o.get("keep_paths", True):
            rel = self.db.path_of(e["parent"]) if e["parent"] else ""
            parts += [self.clean(p) for p in rel.split("/") if p]
        name = e["name"]
        if e["flags"] & F_ADS and ":" in name:
            base, _sep, stream = name.partition(":")
            name = f"{base} [{stream}]"
        parts.append(self.clean(name))
        return os.path.join(self.dest, *parts)

    def ensure_dir(self, folder: str) -> None:
        if folder in self.made_dirs:
            return
        missing = []
        p = folder
        while not os.path.isdir(p) and p != os.path.dirname(p):
            missing.append(p)
            p = os.path.dirname(p)
        os.makedirs(folder, exist_ok=True)
        for m in missing:
            self.owner.give(m)
        self.made_dirs.add(folder)

    @staticmethod
    def unique(path: str) -> str:
        if not os.path.lexists(path):
            return path
        stem, ext = os.path.splitext(path)
        if len(ext) > 12:
            stem, ext = path, ""
        n = 2
        while os.path.lexists(f"{stem} ({n}){ext}"):
            n += 1
        return f"{stem} ({n}){ext}"

    def region(self, vol_id: int) -> Source:
        r = self.regions.get(vol_id)
        if r is None:
            v = self.volumes[vol_id]
            r = self.src.region(int(v.get("offset") or 0), int(v.get("size") or self.src.size))
            self.regions[vol_id] = r
        return r

    # ------------------------------------------------------------------ copying
    def copy(self, e: dict) -> str | None:
        """Recover one file; returns where it went (None when it was skipped)."""
        full = self.db.entry(e["id"])
        path = self.unique(self.target_path(full))
        self.ensure_dir(os.path.dirname(path))
        if full["flags"] & F_SYMLINK and self.o.get("symlinks", True):
            target = b"".join(read_content(self.region(full["vol"]), full)).decode("utf-8", "replace")
            try:
                os.symlink(target, path)
                self.owner.give(path)
                return path
            except OSError:
                pass                       # the destination can't hold links (FAT): save the target as text
        bad_before = self.src.bad.total
        tmp = path + ".part"
        written = 0
        try:
            with open(tmp, "wb") as fh:
                for piece in read_content(self.region(full["vol"]), full):
                    if self.ctl is not None:
                        self.ctl.check()
                    fh.write(piece)
                    written += len(piece)
                    self.done_bytes += len(piece)
                    self.tick()
            os.replace(tmp, path)
        except Cancelled:
            _unlink(tmp)
            raise
        except KeyError as exc:
            _unlink(tmp)
            raise RallError(f"can't decode this file ({exc})") from exc
        except OSError as exc:
            _unlink(tmp)
            if exc.errno == 28:
                raise RallError(f"The destination is full ({self.dest})") from exc
            raise
        self.owner.give(path)
        if self.o.get("restore_times", True):
            mt = full.get("mtime")
            at = full.get("atime") or mt
            if mt:
                try:
                    os.utime(path, (at, mt), follow_symlinks=False)
                except (OSError, OverflowError, ValueError):
                    pass
        if self.src.bad.total != bad_before:
            self.damaged += 1
            self.report.append(f"DAMAGED  {path}  ({fmt_bytes(self.src.bad.total - bad_before)} unreadable, "
                               "filled with zeros)")
        elif full["deleted"] and full["chance"] <= 1:
            self.report.append(f"POOR     {path}  (parts were overwritten: it may not open)")
        return path

    def tick(self, force: bool = False) -> None:
        if self.job is None:
            return
        total = self.total_bytes or 1
        elapsed = time.monotonic() - self.t0
        rate = self.done_bytes / elapsed if elapsed > 0.5 else None
        eta = (total - self.done_bytes) / rate if rate else None
        self.job.update(progress=min(1.0, self.done_bytes / total),
                        message=f"Recovered {self.done_files:,} of {self.total_files:,} files".replace(",", " ")
                        + (f" · {fmt_rate(rate)}" if rate else ""),
                        stats={"done": self.done_bytes, "total": total, "rate": rate, "eta": eta, "label": "Recovered"},
                        force=force)

    def run(self, ids: list[int], filters: dict | None = None, exclude: list[int] | None = None) -> dict:
        """Recover IDS (files, and folders with everything under them) except what lies under EXCLUDE."""
        self.t0 = time.monotonic()
        files = self.db.selection([int(i) for i in ids], [int(i) for i in exclude or ()], filters)
        rows = []
        for fid in files:
            r = self.db.conn.execute("SELECT id, vol, parent, name, size, flags, deleted, chance FROM entries WHERE id = ?",
                                     (fid,)).fetchone()
            if r:
                rows.append({"id": r[0], "vol": r[1], "parent": r[2], "name": r[3], "size": r[4], "flags": r[5],
                             "deleted": r[6], "chance": r[7]})
        if self.o.get("skip_empty", True):
            rows = [r for r in rows if r["size"] > 0 or r["flags"] & F_SYMLINK]
        self.total_files = len(rows)
        self.total_bytes = sum(r["size"] for r in rows)
        if not rows:
            raise RallError("Nothing to recover: the selection has no files (empty files are skipped)")
        self.check_space()
        os.makedirs(self.dest, exist_ok=True)
        if self.job is not None:
            self.job.log(f"Recovering {len(rows):,} files ({fmt_bytes(self.total_bytes)}) into {self.dest}"
                         .replace(",", " "))
        # read the disk in order: much faster on hard disks than following the folder order
        rows.sort(key=lambda r: (r["vol"], r["id"]))
        for r in rows:
            if self.ctl is not None:
                self.ctl.check()
            try:
                out = self.copy(r)
                self.done_files += 1
                if out:
                    self.written.append((r, out))
            except Cancelled:
                raise
            except RallError as exc:
                if "destination is full" in str(exc):
                    raise
                self.failed += 1
                self.report.append(f"FAILED   {r['name']}: {exc}")
                if self.job is not None:
                    self.job.warn(f"{r['name']}: {exc}")
            except OSError as exc:
                self.failed += 1
                self.report.append(f"FAILED   {r['name']}: {exc.strerror or exc}")
                if self.job is not None:
                    self.job.warn(f"{r['name']}: {exc.strerror or exc}")
            self.tick()
        self.tick(force=True)
        if self.o.get("repair"):
            self.repair_pass()
        report = self.write_report(rows)
        msg = f"Recovered {self.done_files:,} files ({fmt_bytes(self.done_bytes)})".replace(",", " ")
        if self.failed:
            msg += f", {self.failed} failed"
        if self.damaged:
            msg += f", {self.damaged} with unreadable parts"
        if self.repaired:
            msg += f", {self.repaired} repaired"
        if self.need_reference:
            msg += f", {self.need_reference} need a reference file to be repaired"
        if self.job is not None:
            self.job.update(message=msg, force=True)
        return {"files": self.done_files, "bytes": self.done_bytes, "failed": self.failed, "damaged": self.damaged,
                "repaired": self.repaired, "need_reference": self.need_reference, "dest": self.dest,
                "report": report, "message": msg}

    # ------------------------------------------------------------------ repairing what came back damaged
    def _worth_checking(self, r: dict, path: str) -> bool:
        """Files that may have come back damaged: found by signature, deleted with less than a good chance,
        or with unreadable parts — of a type the file repair knows."""
        if not _repairable(path):
            return False
        return bool(r["flags"] & F_CARVED) or (r["deleted"] and r["chance"] < CHANCE_GOOD) or \
            any(path in line for line in self.report)

    def repair_pass(self) -> None:
        """Check the recovered photos, videos and documents that may be damaged, and write a repaired copy
        next to each one that needs it ("name (repaired).ext"); the original stays as it came back."""
        from . import filerepair
        from .filetypes import category
        todo = [(r, p) for r, p in self.written if self._worth_checking(r, p)]
        if not todo:
            return
        reference = self.o.get("reference") or None
        if self.job is not None:
            self.job.log(f"Checking {len(todo)} recovered file{'s' if len(todo) != 1 else ''} that may be damaged")
        for i, (r, path) in enumerate(todo):
            if self.ctl is not None:
                self.ctl.check()
            if self.job is not None and (i % 4 == 0 or i == len(todo) - 1):
                self.job.update(message=f"Checking damaged files: {i + 1} of {len(todo)}")
            ref = reference if reference and category(reference) == category(path) else None
            out = self.unique(os.path.join(os.path.dirname(path), filerepair.output_name(path)))
            try:
                res = filerepair.repair(path, out, ref, self.ctl)
            except Cancelled:
                raise
            except (RallError, OSError, ValueError) as exc:
                self.report.append(f"NOT CHECKED {path}  ({exc})")
                continue
            if res.get("out"):
                self.repaired += 1
                self.owner.give(res["out"])
                self.report.append(f"REPAIRED {path}  → {os.path.basename(res['out'])}: {res.get('message', '')}")
            elif (res.get("info") or {}).get("needs_reference"):
                self.need_reference += 1
                self.report.append(f"NEEDS A REFERENCE {path}  ({res.get('message', '')})")

    def check_space(self) -> None:
        try:
            st = os.statvfs(self.dest if os.path.exists(self.dest) else os.path.dirname(self.dest) or "/")
        except OSError:
            return
        free = st.f_bavail * st.f_frsize
        if free < self.total_bytes:
            raise RallError(f"The destination has {fmt_bytes(free)} free; the selected files need "
                            f"{fmt_bytes(self.total_bytes)}")

    def write_report(self, rows: list[dict]) -> str | None:
        if not self.o.get("report", True):
            return None
        path = self.unique(os.path.join(self.dest, "RecoverAll report.txt"))
        meta = self.db.meta("source") or {}
        lines = [
            "RecoverAll recovery report",
            f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Recovered from: {meta.get('display_name') or meta.get('name') or meta.get('spec')}",
            f"Files: {self.done_files} recovered, {self.failed} failed, {self.damaged} with unreadable parts",
            f"Size: {fmt_bytes(self.done_bytes)} in {fmt_duration(time.monotonic() - self.t0)}",
            "",
        ]
        carved = sum(1 for r in rows if r["flags"] & F_CARVED)
        if carved:
            lines.append(f"{carved} files were found by their signature: their original names and folders are "
                         "unknown, they are sorted by type.")
            lines.append("")
        chances = {}
        for r in rows:
            if r["deleted"]:
                chances[r["chance"]] = chances.get(r["chance"], 0) + 1
        if chances:
            lines.append("Deleted files by recovery chance: " + ", ".join(
                f"{CHANCE_NAMES.get(k, k)} {v}" for k, v in sorted(chances.items(), reverse=True)))
            lines.append("")
        if self.report:
            lines.append("Files that need a look:")
            lines.extend(self.report)
        else:
            lines.append("Every file was read without errors.")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            self.owner.give(path)
            return path
        except OSError:
            return None


def _repairable(path: str) -> bool:
    """Whether the file repair knows this kind of file (by its name)."""
    from . import filerepair
    check = getattr(filerepair, "repairable_name", None)
    if check is not None:
        return check(path)
    ext = Path(path).suffix.lower().lstrip(".")
    return ext in filerepair.EXTENSIONS or ext in filerepair.ZIP_TYPES


def _unlink(p: str) -> None:
    try:
        os.unlink(p)
    except OSError:
        pass


def run_recover(job, db: ScanDB, src: Source, ids: list[int], dest: str, options: dict | None = None,
                filters: dict | None = None, source_spec=None, exclude: list[int] | None = None) -> dict:
    from .jobs import JobControl
    if source_spec is not None:
        check_destination(source_spec, dest)
    rec = Recovery(db, src, dest, options, JobControl(job) if job is not None else None, job)
    return rec.run(ids, filters, exclude)
