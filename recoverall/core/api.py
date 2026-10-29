"""The API the GUI and the CLI use, in-process (root, or a user working on image files) or through the
pkexec helper (same methods over JSON lines, see :mod:`ipc`).

Every argument and return value is plain JSON. A source is a device path (/dev/sdb), an image file, a
``.rallraid`` file, ``{"path": ..., "offset": ..., "size": ...}`` for a region of one, or
``{"raid": {...}}`` for a virtual RAID. A scan is named by its scan file's path.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Callable

from . import devices, tools
from .blockio import open_source
from .config import SYSTEM_STATE_DIR, backups_dir, raid_dir, scans_dir, user_data_dir
from .errors import NotPermitted, RallError, ScanError
from .jobs import Job, JobControl, JobRunner
from .results import ScanDB
from .util import fmt_bytes, give_to_caller, run, safe_name, which

log = logging.getLogger(__name__)

READ_METHODS = {
    "hello", "list_disks", "disk_detail", "open_image", "tool_list", "formats", "scans", "scan_info", "scan_children",
    "scan_subdirs", "scan_search", "scan_counts", "scan_entry", "scan_selection", "scan_ancestors", "preview",
    "thumbnails", "read_bytes",
    "partition_table", "plan_partitions", "diagnose", "fsck_actions", "list_backups", "raid_from_md",
    "raid_describe", "file_analyze", "jobs", "job", "history", "subscribe", "unlocked",
}
WRITE_METHODS = {
    "start_scan", "open_scan", "close_scan", "save_scan", "delete_scan", "start_recover", "start_partition_search",
    "write_partitions", "undo_backup", "start_repair", "start_file_repair", "start_image", "save_raid",
    "start_raid_detect", "unlock", "lock", "cancel_job", "clear_history",
}


def _history_paths() -> list[Path]:
    out = [Path(os.environ.get("RALL_STATE_DIR") or SYSTEM_STATE_DIR) / "history.jsonl"]
    if os.geteuid() != 0 and not os.environ.get("RALL_STATE_DIR"):
        out.append(user_data_dir() / "history.jsonl")
    return out


def source_name(spec) -> str:
    if isinstance(spec, dict):
        if spec.get("raid"):
            return spec["raid"].get("name") or "Virtual RAID"
        base = os.path.basename(spec.get("path") or "")
        if spec.get("offset"):
            return f"{base} at {fmt_bytes(int(spec['offset']))}"
        return base
    return os.path.basename(str(spec))


class LocalAPI:
    def __init__(self, mode: str | None = None):
        self.mode = mode or ("root" if os.geteuid() == 0 else "local")
        self._listeners: list[Callable[[dict], None]] = []
        self._lock = threading.Lock()
        self.runner = JobRunner(emit=self._emit, on_finish=self._record)
        self._scans: dict[str, ScanDB] = {}
        self._sources: dict[str, object] = {}
        self._unlocked: dict[str, dict] = {}

    # ------------------------------------------------------------------ events
    def add_listener(self, fn: Callable[[dict], None]) -> None:
        with self._lock:
            self._listeners.append(fn)

    def remove_listener(self, fn: Callable[[dict], None]) -> None:
        with self._lock:
            if fn in self._listeners:
                self._listeners.remove(fn)

    def _emit(self, ev: dict) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for fn in listeners:
            try:
                fn(ev)
            except Exception:  # noqa: BLE001
                log.exception("listener failed")

    def subscribe(self) -> bool:
        return True

    def close(self) -> None:
        self.runner.cancel_all()
        for j in self.runner.running():
            self.runner.wait(j.id, 20)
        for db in list(self._scans.values()):
            db.close()
        self._scans.clear()
        for s in list(self._sources.values()):
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
        self._sources.clear()

    # ------------------------------------------------------------------ helpers
    @property
    def root(self) -> bool:
        return os.geteuid() == 0

    def _require_root(self, what: str) -> None:
        if not self.root:
            raise NotPermitted(f"{what} needs administrator rights: click “Grant access” (or use sudo recoverctl)")

    def _readable(self, spec) -> None:
        """Image files the user can read work without root; disks need it."""
        if self.root:
            return
        for p in _spec_paths(spec):
            if not (os.path.isfile(p) and os.access(p, os.R_OK)):
                raise NotPermitted("Reading disks needs administrator rights: click “Grant access” "
                                   "(or use sudo recoverctl)")

    def hello(self) -> dict:
        from .. import __version__
        return {"version": __version__, "mode": self.mode, "root": self.root, "caps": tools.capabilities(),
                "demo": False, "uid": os.getuid()}

    def tool_list(self) -> list[dict]:
        return tools.inventory()

    def formats(self) -> list[dict]:
        try:
            from .carve import formats_table
        except ImportError:
            return []
        return formats_table()

    # ------------------------------------------------------------------ disks
    def list_disks(self) -> list[dict]:
        out = devices.list_disks()
        out.extend(devices.list_volumes())
        return out

    def disk_detail(self, path: str) -> dict:
        disk = devices.disk_info(path)
        if self.root and not disk.get("is_image"):
            disk["health"] = devices.health(disk)
        if self.root or (disk.get("is_image") and os.access(disk["path"], os.R_OK)):
            try:
                with open_source(disk["path"]) as src:
                    from . import partitions
                    table = partitions.read_table(src)
                disk["table"] = {k: table.get(k) for k in ("type", "ok", "problems", "sector_size", "gpt")}
            except (RallError, OSError, ImportError) as exc:
                disk["table"] = {"type": None, "problems": [str(exc)]}
        from .safety import confirm_token
        disk["confirm_token"] = confirm_token(disk)
        return disk

    def open_image(self, path: str) -> dict:
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            raise RallError(f"{path} is not a file")
        return devices.image_disk(path)

    def read_bytes(self, source, offset: int, length: int) -> dict:
        """Raw bytes of a source for the sector viewer (at most 1 MiB)."""
        self._readable(source)
        length = max(0, min(int(length), 1024 * 1024))
        with open_source(source) as src:
            data = src.read(int(offset), length)
            size = src.size
            ss = src.sector_size
        import base64
        return {"offset": int(offset), "data": base64.b64encode(data).decode(), "size": size, "sector_size": ss}

    # ------------------------------------------------------------------ scans
    def _scan(self, path: str) -> ScanDB:
        path = os.path.abspath(path)
        db = self._scans.get(path)
        if db is None:
            db = ScanDB.open(path)
            self._scans[path] = db
        return db

    def _scan_source(self, path: str):
        """The (cached) source a scan was made of."""
        from .scan import source_of
        key = os.path.abspath(path)
        src = self._sources.get(key)
        if src is None:
            src = source_of(self._scan(path))
            self._sources[key] = src
        return src

    def _scan_dirs(self) -> set[Path]:
        """Where saved scans are looked for (the demo keeps its own)."""
        return {scans_dir()}

    def scans(self) -> list[dict]:
        out = []
        for d in self._scan_dirs() | {Path(os.path.dirname(p)) for p in self._scans}:
            try:
                files = sorted(Path(d).glob("*.rascan"), key=lambda p: -p.stat().st_mtime)
            except OSError:
                continue
            for f in files[:200]:
                try:
                    db = self._scan(str(f))
                    meta = db.all_meta()
                except (ScanError, Exception):  # noqa: BLE001 - a damaged scan file is just skipped
                    continue
                out.append({"path": str(f), "source": meta.get("source") or {}, "created": meta.get("created"),
                            "state": meta.get("state"), "stats": meta.get("stats") or {},
                            "mode": (meta.get("options") or {}).get("mode"), "size": f.stat().st_size})
        return out

    def scan_info(self, scan: str) -> dict:
        db = self._scan(scan)
        meta = db.all_meta()
        meta["volumes"] = db.volumes()
        meta["stats"] = db.stats()
        meta["path"] = os.path.abspath(scan)
        return meta

    def scan_children(self, scan: str, parent: int, offset: int = 0, limit: int = 500, sort: str = "name",
                      desc: bool = False, filters: dict | None = None) -> dict:
        return self._scan(scan).children(int(parent), int(offset), int(limit), sort, bool(desc), filters)

    def scan_subdirs(self, scan: str, parent: int) -> list[dict]:
        return self._scan(scan).subdirs(int(parent))

    def scan_search(self, scan: str, filters: dict | None = None, offset: int = 0, limit: int = 500,
                    sort: str = "name", desc: bool = False) -> dict:
        return self._scan(scan).search(filters, int(offset), int(limit), sort, bool(desc))

    def scan_counts(self, scan: str, filters: dict | None = None) -> dict:
        return self._scan(scan).counts(filters)

    def scan_selection(self, scan: str, include: list[int], exclude: list[int] | None = None,
                       filters: dict | None = None) -> dict:
        """Files, bytes and deleted files of a checked selection (folders count with everything in them)."""
        return self._scan(scan).selection_stats(include, exclude or [], filters)

    def scan_ancestors(self, scan: str, entries: list[int]) -> dict:
        """The folders above each entry, nearest first ({"id": [parent, grandparent, ...]})."""
        return {str(k): v for k, v in self._scan(scan).ancestors(entries).items()}

    def scan_entry(self, scan: str, entry: int) -> dict:
        db = self._scan(scan)
        e = db.entry(int(entry))
        e.pop("data", None)
        runs = e.pop("runs", [])
        vol = db.volume(e["vol"])
        e["path"] = db.path_of(e["id"])
        e["volume"] = {k: vol.get(k) for k in ("id", "name", "fstype", "label", "offset", "status")}
        e["fragments"] = len([r for r in runs if r[0] >= 0])
        e["first_offset"] = (vol.get("offset") or 0) + runs[0][0] if runs and runs[0][0] >= 0 else None
        return e

    def preview(self, scan: str, entry: int) -> dict:
        from .preview import preview
        db = self._scan(scan)
        e = db.entry(int(entry))
        vol = db.volume(e["vol"])
        src = self._scan_source(scan).region(int(vol.get("offset") or 0), int(vol.get("size") or 0) or None)
        out = preview(src, e)
        out["id"] = e["id"]
        return out

    def thumbnails(self, scan: str, entries: list[int]) -> dict:
        from .preview import thumbnail
        db = self._scan(scan)
        src = self._scan_source(scan)
        vols = {v["id"]: v for v in db.volumes()}
        out = {}
        for i in entries[:64]:
            try:
                e = db.entry(int(i))
                v = vols[e["vol"]]
                out[str(i)] = thumbnail(src.region(int(v.get("offset") or 0), int(v.get("size") or 0) or None), e)
            except Exception as exc:  # noqa: BLE001 - one bad file mustn't spoil the grid
                out[str(i)] = {"data": None, "error": str(exc)}
        return out

    def start_scan(self, source, options: dict | None = None, name: str = "") -> dict:
        self._readable(source)
        from .scan import MODE_TEXT, run_scan
        opts = dict(options or {})
        folder = Path(opts.pop("folder", "") or scans_dir())
        folder.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        label = safe_name(name or source_name(source))
        db_path = str(folder / f"{stamp}-{label}.rascan")
        title = f"{MODE_TEXT.get(opts.get('mode') or 'quick', 'Scan')} of {name or source_name(source)}"
        keys = [os.path.realpath(p) for p in _spec_paths(source)]

        def fn(job: Job):
            result = run_scan(job, source, db_path, opts)
            return result
        job = self.runner.start("scan", keys or [db_path], title, fn,
                                {"source": source, "options": opts, "scan": db_path})
        out = job.public()
        out["scan"] = db_path
        return out

    def open_scan(self, path: str) -> dict:
        db = self._scan(path)
        return {"path": os.path.abspath(path), "meta": db.all_meta()}

    def close_scan(self, scan: str) -> bool:
        key = os.path.abspath(scan)
        db = self._scans.pop(key, None)
        if db is not None:
            db.close()
        src = self._sources.pop(key, None)
        if src is not None:
            src.close()
        return True

    def save_scan(self, scan: str, dest: str) -> str:
        db = self._scan(scan)
        dest = os.path.abspath(dest)
        if not dest.endswith(".rascan"):
            dest += ".rascan"
        db.save_as(dest)
        give_to_caller(dest)
        return dest

    def delete_scan(self, scan: str) -> bool:
        path = os.path.abspath(scan)
        if not path.endswith(".rascan"):
            raise RallError("Not a scan file")
        self.close_scan(path)
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(path + suffix)
            except OSError:
                pass
        return True

    # ------------------------------------------------------------------ recovering files
    def start_recover(self, scan: str, entries: list[int], dest: str, options: dict | None = None,
                      filters: dict | None = None, exclude: list[int] | None = None) -> dict:
        """Recover ENTRIES (folders with everything in them) except what lies under EXCLUDE, through FILTERS."""
        db = self._scan(scan)
        meta = db.meta("source") or {}
        spec = meta.get("spec")
        self._readable(spec)
        from .recover import run_recover
        from .safety import check_destination
        check_destination(spec, dest)
        src = self._scan_source(scan)
        n = len(entries)
        title = f"Recover {n} item{'s' if n != 1 else ''} → {dest}"

        def fn(job: Job):
            return run_recover(job, db, src, [int(i) for i in entries], dest, options, filters, spec,
                               [int(i) for i in exclude or ()])
        job = self.runner.start("recover", [f"recover:{os.path.realpath(dest)}"], title, fn,
                                {"scan": scan, "dest": dest, "count": n, "options": options or {}})
        return job.public()

    # ------------------------------------------------------------------ partitions
    def partition_table(self, source) -> dict:
        self._readable(source)
        from . import partitions
        with open_source(source) as src:
            return partitions.read_table(src)

    def start_partition_search(self, source, mode: str = "quick") -> dict:
        self._readable(source)
        title = f"{'Deep' if mode == 'deep' else 'Quick'} partition search on {source_name(source)}"

        def fn(job: Job):
            return _partition_search(job, source, mode)
        job = self.runner.start("partitions", [os.path.realpath(p) for p in _spec_paths(source)], title, fn,
                                {"source": source, "mode": mode})
        return job.public()

    def plan_partitions(self, source, table_type: str, parts: list[dict]) -> dict:
        from . import partitions
        with open_source(source) as src:
            return partitions.plan_table(table_type, parts, src.size, src.sector_size)

    def write_partitions(self, source: str, table_type: str, parts: list[dict], confirm: str = "") -> dict:
        self._require_root("Writing a partition table")
        from . import partitions
        from .safety import check_confirmation, check_unmounted
        if not isinstance(source, str):
            raise RallError("A partition table can only be written to a disk or an image file")
        from .vdisk import check_raw_file
        check_raw_file(source, "Writing a partition table")
        disk = devices.disk_info(source)
        check_unmounted(source, "Writing a partition table")
        check_confirmation(disk, confirm)
        with open_source(source) as src:
            plan = partitions.plan_table(table_type, parts, src.size, src.sector_size)
        if not plan.get("ok"):
            raise RallError("; ".join(plan.get("problems") or ["the partition table isn't valid"]))
        backup_dir = str(backups_dir())
        os.makedirs(backup_dir, exist_ok=True)
        result = partitions.write_table(source, plan, backup_dir)
        self._record_simple("partitions", f"Wrote a {table_type.upper()} partition table on {source_name(source)}",
                            {"source": source, "backup": result.get("backup"), "partitions": parts})
        return result

    def list_backups(self) -> list[dict]:
        try:
            from .rawwrite import list_backups
        except ImportError:
            return []
        return list_backups(str(backups_dir()))

    def undo_backup(self, path: str, confirm: str = "") -> dict:
        self._require_root("Undoing a change")
        from .rawwrite import restore
        return restore(path) or {"ok": True}

    # ------------------------------------------------------------------ repair
    def diagnose(self, source, offset: int = 0, size: int | None = None, fstype: str = "") -> list[dict]:
        self._readable(source)
        from . import bootrepair
        with open_source(source) as src:
            size = int(size or (src.size - int(offset)))
            if not fstype:
                from .devices import identify
                fstype = identify(src, int(offset), size).get("fstype") or ""
            return bootrepair.diagnose(src, int(offset), size, fstype)

    def fsck_actions(self, fstype: str) -> list[dict]:
        try:
            from . import fsck
        except ImportError:
            return []
        return fsck.actions_for(fstype)

    def start_repair(self, source, action: str, offset: int = 0, size: int | None = None, fstype: str = "",
                     options: dict | None = None, confirm: str = "") -> dict:
        """ACTION: an fsck action id ("fsck:<id>") or a boot-sector fix ("boot:<name>")."""
        self._require_root("Repairing a filesystem")
        from .safety import check_confirmation, check_unmounted
        path = source if isinstance(source, str) else source.get("path")
        if not path:
            raise RallError("Repairs work on disks, partitions and image files")
        from .vdisk import check_raw_file
        check_raw_file(path, "Repairing")
        disk = devices.disk_info(path) if os.path.exists(path) and not os.path.isfile(path) else \
            {"path": path, "is_image": True, "display_name": os.path.basename(path)}
        check_unmounted(path, "Repairing")
        safe = action.startswith("fsck:") and _is_check(action, fstype)
        if not safe:
            check_confirmation(disk, confirm)
        title = f"{_action_title(action, fstype)} on {source_name(source)}"
        opts = dict(options or {})

        def fn(job: Job):
            return _repair(job, path, action, int(offset), size, fstype, opts)
        job = self.runner.start("repair", [os.path.realpath(path)], title, fn,
                                {"source": source, "action": action, "offset": offset, "fstype": fstype})
        return job.public()

    def file_analyze(self, path: str, reference: str | None = None) -> dict:
        from .filerepair import analyze
        return analyze(path, reference)

    def start_file_repair(self, paths: list[str], out_dir: str, reference: str | None = None) -> dict:
        from .filerepair import repair_many
        title = f"Repair {len(paths)} file{'s' if len(paths) != 1 else ''}"

        def fn(job: Job):
            res = repair_many(paths, out_dir, reference, JobControl(job))
            for r in res if isinstance(res, list) else res.get("files", []):
                if r.get("out"):
                    give_to_caller(r["out"])
            return res
        job = self.runner.start("filerepair", [f"filerepair:{out_dir}"], title, fn, {"paths": paths, "out": out_dir})
        return job.public()

    # ------------------------------------------------------------------ imaging and RAID
    def start_image(self, source, dest: str, options: dict | None = None) -> dict:
        self._readable(source)
        from .imaging import run_image
        from .safety import check_destination
        dest = os.path.abspath(dest)
        check_destination(source, os.path.dirname(dest))
        title = f"Image {source_name(source)} → {os.path.basename(dest)}"
        job = self.runner.start("image", [os.path.realpath(p) for p in _spec_paths(source)] + [dest], title,
                                lambda job: run_image(job, source, dest, options), {"source": source, "dest": dest})
        return job.public()

    def raid_from_md(self, paths: list[str]) -> dict | None:
        self._readable(paths[0] if paths else "")
        from . import fsdetect
        from .raid import from_md
        members = []
        for p in paths:
            try:
                with open_source(p) as src:
                    info = fsdetect.identify(src) or {}
            except RallError:
                info = {}
            if info.get("fstype") == "linux_raid_member":
                members.append({"path": p, "md": info})
        return from_md(members)

    def raid_describe(self, definition: dict) -> dict:
        from .raid import RaidSource, describe_definition
        src = RaidSource.from_definition(definition)
        try:
            return {"text": describe_definition(definition), "size": src.size, "size_text": fmt_bytes(src.size)}
        finally:
            src.close()

    def save_raid(self, definition: dict, path: str = "") -> str:
        from .raid import save_definition
        if not path:
            d = raid_dir()
            d.mkdir(parents=True, exist_ok=True)
            path = str(d / f"{safe_name(definition.get('name') or 'raid')}.rallraid")
        save_definition(definition, path)
        give_to_caller(path)
        return path

    def start_raid_detect(self, paths: list[str], levels: list[str] | None = None, missing: int = 0) -> dict:
        """Find a RAID's level, member order, chunk size and layout from its members (MISSING: how many
        members are lost)."""
        self._readable(paths[0] if paths else "")
        from .raid import detect

        def fn(job: Job):
            job.update(message="Trying member orders, chunk sizes and layouts…")
            return {"candidates": detect(paths, tuple(levels) if levels else None, missing=int(missing or 0),
                                         ctl=JobControl(job))}
        job = self.runner.start("raid", [os.path.realpath(p) for p in paths], "Find the RAID parameters", fn,
                                {"paths": paths, "missing": missing})
        return job.public()

    # ------------------------------------------------------------------ encrypted volumes
    def unlock(self, source, passphrase: str, kind: str = "auto") -> dict:
        """Open a LUKS or BitLocker volume read-only with cryptsetup; the unlocked volume is a new source."""
        self._require_root("Unlocking an encrypted volume")
        if which("cryptsetup") is None:
            raise RallError("cryptsetup is not installed (package: cryptsetup)")
        path = source if isinstance(source, str) else source.get("path")
        offset = 0 if isinstance(source, str) else int(source.get("offset") or 0)
        size = None if isinstance(source, str) else source.get("size")
        loop = None
        dev = path
        from .vdisk import check_raw_file
        check_raw_file(path, "Unlocking an encrypted volume")
        if offset or os.path.isfile(path):
            cmd = ["losetup", "-f", "--show", "-r"]
            if offset:
                cmd += ["-o", str(offset)]
            if size:
                cmd += ["--sizelimit", str(int(size))]
            rr = run([*cmd, path], timeout=60)
            if not rr.ok:
                raise RallError(f"Can't attach {path}: {rr.error_text()}")
            loop = dev = rr.stdout.strip()
        name = f"recoverall-{len(self._unlocked) + 1}-{int(time.time()) % 100000}"
        cmd = ["cryptsetup", "open", "--readonly", "--key-file=-"]
        if kind in ("luks", "bitlk", "tcrypt"):
            cmd += ["--type", kind]
        rr = run([*cmd, dev, name], timeout=120, input_text=passphrase)
        if not rr.ok:
            if loop:
                run(["losetup", "-d", loop], timeout=30)
            raise RallError("Wrong passphrase, or not a LUKS/BitLocker volume: " + rr.error_text(200))
        mapped = f"/dev/mapper/{name}"
        self._unlocked[mapped] = {"name": name, "loop": loop, "source": source}
        return {"path": mapped, "name": name}

    def lock(self, path: str) -> bool:
        info = self._unlocked.pop(path, None)
        if info is None:
            return False
        run(["cryptsetup", "close", info["name"]], timeout=60)
        if info.get("loop"):
            run(["losetup", "-d", info["loop"]], timeout=30)
        return True

    def unlocked(self) -> list[dict]:
        return [{"path": k, **v} for k, v in self._unlocked.items()]

    # ------------------------------------------------------------------ jobs and history
    def jobs(self) -> list[dict]:
        return [j.public() for j in self.runner.list()]

    def job(self, job_id: str, since: int = 0) -> dict:
        j = self.runner.get(job_id)
        if j is None:
            raise RallError("No such job")
        d = j.full()
        d["log"] = j.log_since(since)
        return d

    def cancel_job(self, job_id: str) -> bool:
        return self.runner.cancel(job_id)

    def _record(self, job: Job) -> None:
        entry = job.full()
        entry["log"] = [(t, lv, text) for _n, t, lv, text in job.log_since(0)][-400:]
        entry.pop("data", None)
        if isinstance(entry.get("result"), dict):
            entry["result"] = {k: v for k, v in entry["result"].items() if k not in ("candidates",)}
        self._append_history(entry)

    def _record_simple(self, kind: str, title: str, params: dict) -> None:
        now = time.time()
        self._append_history({"id": f"{int(now)}-{kind}", "kind": kind, "title": title, "state": "done",
                              "started": now, "finished": now, "params": params, "message": "Done", "steps": [],
                              "warnings": [], "log": []})

    def _append_history(self, entry: dict) -> None:
        paths = _history_paths()
        for path in paths[:1] if (self.root or os.environ.get("RALL_STATE_DIR")) else paths[1:]:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, default=str) + "\n")
                os.chmod(path, 0o644)
            except OSError:
                pass

    def history(self, limit: int = 200) -> list[dict]:
        out = []
        for path in _history_paths():
            try:
                with open(path, encoding="utf-8") as fh:
                    for line in fh:
                        try:
                            out.append(json.loads(line))
                        except ValueError:
                            continue
            except OSError:
                continue
        seen = set()
        uniq = []
        for e in sorted(out, key=lambda e: -(e.get("started") or 0)):
            if e.get("id") in seen:
                continue
            seen.add(e.get("id"))
            uniq.append(e)
        return uniq[:limit]

    def clear_history(self) -> bool:
        for path in _history_paths():
            try:
                path.unlink()
            except OSError:
                pass
        return True


# ---------------------------------------------------------------------- job bodies
def _spec_paths(spec) -> list[str]:
    from .safety import source_paths
    return [p for p in source_paths(spec) if p]


def _partition_search(job: Job, source, mode: str) -> dict:
    from . import partitions, partsearch
    ctl = JobControl(job)
    with open_source(source) as src:
        job.set_steps(["Read the partition table", "Search" + (" the whole disk" if mode == "deep" else ""),
                       "Check what was found"])
        job.step(0)
        table = partitions.read_table(src)
        for p in table.get("problems") or []:
            job.warn(p)
        job.step(1)
        cands = list(partsearch.quick_search(src, ctl.sub(0, 0.3 if mode == "deep" else 0.95), table) or [])
        if mode == "deep":
            det = partsearch.BootSectorDetector()
            dets = [det]
            try:
                from .fs.ntfs import MftDetector
                dets.append(MftDetector())
            except ImportError:
                pass
            sub = ctl.sub(0.3, 0.97)
            t0 = time.monotonic()
            for pos, buf in src.read_into_chunks(0, src.size, 8 * 1024 * 1024):
                job.check()
                for d in dets:
                    d.feed(pos, buf)
                end = pos + len(buf)
                el = time.monotonic() - t0
                rate = end / el if el > 0.5 else None
                sub.progress(end / src.size, f"Reading {fmt_bytes(end)} of {fmt_bytes(src.size)}", done=end,
                             total=src.size, rate=rate, eta=(src.size - end) / rate if rate else None, label="Read")
            for d in dets:
                cands.extend(d.finish() or [])
        job.step(2)
        merged = partsearch.merge_candidates(cands, src.size, src.sector_size, table)
        ttype = table.get("type") if table.get("type") in ("gpt", "dos") else (
            "gpt" if src.size > 2 * 1024 ** 4 else "dos")
        proposal = partsearch.propose_table(merged, src.size, src.sector_size, ttype)
        # list a few files of each found volume, so the user can tell which one is right
        for c in merged:
            c["preview"] = _peek_files(src, c)
        found = [c for c in merged if c.get("status") != "current"]
        job.update(message=f"{len(merged)} filesystem{'s' if len(merged) != 1 else ''} found"
                   + (f", {len(found)} not in the partition table" if found else ""), force=True)
        return {"table": table, "candidates": merged, "proposal": proposal, "table_type": ttype,
                "disk_size": src.size, "sector_size": src.sector_size}


def _peek_files(src, cand: dict, limit: int = 12) -> list[str]:
    """The first names in a found volume's root folder (TestDisk's "list files")."""
    from . import fs as fsmod
    fstype = cand.get("fstype")
    cls = fsmod.reader_class(fstype or "")
    if cls is None or fsmod.READERS.get(fstype, ("",))[0] in ("tsk", "btrfs"):
        return []
    try:
        from .blockio import CachedSource
        vol = CachedSource(src.region(int(cand["offset"]), int(cand.get("size") or 0) or None))
        info = dict(cand.get("info") or {})
        probed = None if info.get("reconstructed") else cls.probe(vol)
        reader = cls(vol, {**(probed or {}), **info})
        names = []
        root = None
        for i, e in enumerate(reader.entries(deleted=False)):
            if root is None:
                root = e.key
                continue
            if e.parent == root and not e.deleted and not (e.flags & 0x80):
                names.append(e.name + ("/" if e.is_dir else ""))
                if len(names) >= limit:
                    break
            if i > 5000:
                break
        return sorted(names, key=lambda n: (not n.endswith("/"), n.lower()))
    except Exception:  # noqa: BLE001 - a damaged volume shows no files
        return []


def _is_check(action: str, fstype: str) -> bool:
    try:
        from . import fsck
        for a in fsck.actions_for(fstype):
            if f"fsck:{a.get('id')}" == action:
                return a.get("risk") == "safe"
    except ImportError:
        pass
    return False


def _action_title(action: str, fstype: str) -> str:
    kind, _sep, name = action.partition(":")
    if kind == "fsck":
        try:
            from . import fsck
            for a in fsck.actions_for(fstype):
                if a.get("id") == name:
                    return a.get("title") or name
        except ImportError:
            pass
        return f"Filesystem check ({name})"
    return {"ntfs_boot": "Restore the NTFS boot sector", "fat_boot": "Restore the FAT boot sector",
            "fat_copy": "Copy the FAT", "exfat_boot": "Restore the exFAT boot region",
            "gpt_rebuild": "Rebuild the GPT", "mbr_signature": "Fix the MBR signature"}.get(name, name)


def _repair(job: Job, path: str, action: str, offset: int, size, fstype: str, opts: dict) -> dict:
    kind, _sep, name = action.partition(":")
    ctl = JobControl(job)
    if kind == "fsck":
        from . import fsck
        dev = path
        loop = None
        if offset:
            rr = run(["losetup", "-f", "--show", "-o", str(offset)] + (["--sizelimit", str(int(size))] if size else [])
                     + [path], timeout=60)
            if not rr.ok:
                raise RallError(f"Can't attach the partition: {rr.error_text()}")
            loop = dev = rr.stdout.strip()
        try:
            job.set_steps([_action_title(action, fstype)])
            job.step(0)
            res = fsck.run_action(dev, fstype, name, ctl, superblock=opts.get("superblock"),
                                  block_size=opts.get("block_size"))
        finally:
            if loop:
                run(["losetup", "-d", loop], timeout=30)
        job.update(message=res.get("summary") or "Done", force=True)
        if not res.get("ok") and res.get("exit_code") not in (0, 1):
            job.warn(res.get("summary") or "The tool reported a problem")
        return res
    if kind == "boot":
        from . import bootrepair
        job.set_steps([_action_title(action, fstype)])
        job.step(0)
        fn = getattr(bootrepair, name, None)
        if fn is None:
            raise RallError(f"Unknown repair {name}")
        args = dict(opts)
        if name == "gpt_rebuild":
            res = fn(path, **args)
        elif name in ("mbr_signature",):
            res = fn(path, **args)
        else:
            res = fn(path, offset, int(size or 0), **args)
        backup = res if isinstance(res, str) else (res or {}).get("backup")
        if backup:
            job.log(f"The overwritten sectors were saved to {backup}: Undo puts them back")
        job.update(message="Done" + (" (undo is possible)" if backup else ""), force=True)
        return {"backup": backup, "result": res if not isinstance(res, str) else None}
    raise RallError(f"Unknown repair {action}")


def wait_job(api, job_id: str, timeout: float | None = None) -> dict:
    """Poll until a job finishes (for the CLI and tests)."""
    end = None if timeout is None else time.monotonic() + timeout
    while True:
        j = api.job(job_id=job_id)
        if j["state"] != "running":
            return j
        if end is not None and time.monotonic() > end:
            return j
        time.sleep(0.3)


class RemoteAPI:
    """The same methods, answered by the helper over a pipe (or any ipc.Client)."""

    def __init__(self, client, mode: str = "helper"):
        self.client = client
        self.mode = mode

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)

        def call(*args, **kwargs):
            if args:
                raise TypeError("RemoteAPI methods take keyword arguments")
            timeout = 1800 if name in ("disk_detail", "diagnose", "partition_table", "scans") else None
            return self.client.call(name, timeout=timeout, **kwargs)
        return call

    def add_listener(self, fn) -> None:
        self.client.subscribe(fn)

    def remove_listener(self, fn) -> None:
        self.client.unsubscribe(fn)

    def close(self) -> None:
        self.client.close()

