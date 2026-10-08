"""A scan's results: volumes and their files in one SQLite file (a ".rascan").

A deep scan of a big disk finds millions of files, so they never live in memory: the scanner streams
entries into the database, the app pages through folders and searches with SQL, and the file *is* the saved
scan — open it again next week and recover more without scanning again (R-Studio's "scan information").

    db = ScanDB.create(path, source={...})
    vol = db.add_volume(fstype="ntfs", offset=..., size=..., origin="table", status="existing")
    with db.writer(vol) as w:
        for e in reader.entries(ctl):
            w.add(e)                       # parents are resolved by key when the writer finishes
    db.children(vol, folder_id)            # what the file browser shows
"""

from __future__ import annotations

import array
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Iterator

from .errors import ScanError
from .filetypes import EXT_CATEGORY, extension
from .fs.base import F_DIR_RECOVERED, F_ORPHAN, F_SYSTEM, Entry

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS volumes (
    id INTEGER PRIMARY KEY, name TEXT, fstype TEXT, label TEXT, offset INTEGER, size INTEGER, block_size INTEGER,
    origin TEXT, status TEXT, score INTEGER, engine TEXT, info TEXT, root_id INTEGER, lost_id INTEGER,
    files INTEGER DEFAULT 0, folders INTEGER DEFAULT 0, deleted_files INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
    deleted_bytes INTEGER DEFAULT 0, warnings TEXT, state TEXT DEFAULT 'pending', note TEXT
);
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY, vol INTEGER NOT NULL, parent INTEGER, key TEXT, pkey TEXT, name TEXT NOT NULL,
    ext TEXT, cat TEXT, is_dir INTEGER NOT NULL DEFAULT 0, size INTEGER NOT NULL DEFAULT 0,
    deleted INTEGER NOT NULL DEFAULT 0, chance INTEGER NOT NULL DEFAULT 0, flags INTEGER NOT NULL DEFAULT 0,
    mtime REAL, ctime REAL, atime REAL, crtime REAL, runs BLOB, data BLOB, extra TEXT, start INTEGER
);
CREATE INDEX IF NOT EXISTS entries_parent ON entries (parent);
CREATE INDEX IF NOT EXISTS entries_vol_key ON entries (vol, key);
CREATE INDEX IF NOT EXISTS entries_start ON entries (start);
"""

SORTS = {"name": ["e.name COLLATE NOCASE"], "size": ["e.size", "e.name COLLATE NOCASE"],
         "mtime": ["e.mtime", "e.name COLLATE NOCASE"], "chance": ["e.chance", "e.name COLLATE NOCASE"],
         "type": ["e.ext", "e.name COLLATE NOCASE"], "deleted": ["e.deleted", "e.name COLLATE NOCASE"],
         "path": ["e.parent", "e.name COLLATE NOCASE"]}


def order_by(sort: str, desc: bool = False, dirs_first: bool = True) -> str:
    parts = [c + (" DESC" if desc else "") for c in SORTS.get(sort, SORTS["name"])]
    if dirs_first:
        parts.insert(0, "e.is_dir DESC")
    return ", ".join(parts)

ROW_COLUMNS = "e.id, e.vol, e.parent, e.name, e.ext, e.cat, e.is_dir, e.size, e.deleted, e.chance, e.flags, e.mtime, " \
              "e.crtime"


def pack_runs(runs) -> bytes | None:
    if not runs:
        return None
    a = array.array("q")
    for off, n in runs:
        a.append(int(off))
        a.append(int(n))
    return a.tobytes()


def unpack_runs(blob) -> list[tuple[int, int]]:
    if not blob:
        return []
    a = array.array("q")
    a.frombytes(bytes(blob))
    return [(a[i], a[i + 1]) for i in range(0, len(a) - 1, 2)]


def _row(r) -> dict:
    return {"id": r[0], "vol": r[1], "parent": r[2], "name": r[3], "ext": r[4] or "", "cat": r[5] or "",
            "is_dir": bool(r[6]), "size": r[7], "deleted": bool(r[8]), "chance": r[9], "flags": r[10],
            "mtime": r[11], "crtime": r[12]}


class ScanDB:
    """One scan file. Thread-safe: every thread gets its own connection; writes are serialised."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._conns: list[sqlite3.Connection] = []
        self._conns_lock = threading.Lock()

    # ------------------------------------------------------------------ lifecycle
    @classmethod
    def create(cls, path: str | Path, source: dict, options: dict | None = None) -> ScanDB:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.unlink()
        db = cls(path)
        c = db.conn
        c.executescript(_SCHEMA)
        db.set_meta(schema=SCHEMA_VERSION, source=source, options=options or {}, created=time.time(),
                    state="running", app="RecoverAll")
        return db

    @classmethod
    def open(cls, path: str | Path) -> ScanDB:
        if not os.path.isfile(path):
            raise ScanError(f"{path}: no such scan file")
        db = cls(path)
        try:
            v = db.meta("schema")
        except sqlite3.DatabaseError as exc:
            raise ScanError(f"{os.path.basename(str(path))} is not a RecoverAll scan file") from exc
        if v is None:
            raise ScanError(f"{os.path.basename(str(path))} is not a RecoverAll scan file")
        if int(v) > SCHEMA_VERSION:
            raise ScanError("This scan was saved by a newer RecoverAll: update RecoverAll to open it")
        return db

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=60, check_same_thread=False)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA temp_store=MEMORY")
            c.execute("PRAGMA cache_size=-65536")
            self._local.conn = c
            with self._conns_lock:
                self._conns.append(c)
        return c

    def close(self) -> None:
        with self._conns_lock:
            conns, self._conns = self._conns, []
        for c in conns:
            try:
                c.close()
            except sqlite3.Error:
                pass
        self._local = threading.local()

    def checkpoint(self) -> None:
        """Fold the write-ahead log into the file (before copying the scan elsewhere)."""
        with self._write_lock:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def save_as(self, dest: str | Path) -> None:
        """A self-contained copy of the scan (the SQLite backup API: consistent even while it's in use)."""
        self.checkpoint()
        dest = str(dest)
        tmp = dest + ".part"
        out = sqlite3.connect(tmp)
        try:
            self.conn.backup(out)
        finally:
            out.close()
        os.replace(tmp, dest)

    # ------------------------------------------------------------------ meta
    def set_meta(self, **items) -> None:
        with self._write_lock:
            self.conn.executemany("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                                  [(k, json.dumps(v, default=str)) for k, v in items.items()])
            self.conn.commit()

    def meta(self, key: str, default=None):
        r = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return json.loads(r[0]) if r else default

    def all_meta(self) -> dict:
        return {k: json.loads(v) for k, v in self.conn.execute("SELECT key, value FROM meta")}

    # ------------------------------------------------------------------ volumes
    _VOL_FIELDS = ("name", "fstype", "label", "offset", "size", "block_size", "origin", "status", "score", "engine",
                   "info", "root_id", "lost_id", "files", "folders", "deleted_files", "bytes", "deleted_bytes",
                   "warnings", "state", "note")

    def add_volume(self, **fields) -> int:
        fields = {k: v for k, v in fields.items() if k in self._VOL_FIELDS}
        for k in ("info", "warnings"):
            if k in fields and not isinstance(fields[k], str):
                fields[k] = json.dumps(fields[k], default=str)
        cols = ", ".join(fields)
        with self._write_lock:
            cur = self.conn.execute(f"INSERT INTO volumes ({cols}) VALUES ({', '.join('?' * len(fields))})",
                                    tuple(fields.values()))
            self.conn.commit()
            return cur.lastrowid

    def update_volume(self, vol: int, **fields) -> None:
        fields = {k: v for k, v in fields.items() if k in self._VOL_FIELDS}
        if not fields:
            return
        for k in ("info", "warnings"):
            if k in fields and not isinstance(fields[k], str):
                fields[k] = json.dumps(fields[k], default=str)
        with self._write_lock:
            self.conn.execute(f"UPDATE volumes SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?",
                              (*fields.values(), vol))
            self.conn.commit()

    def volumes(self) -> list[dict]:
        cur = self.conn.execute(f"SELECT id, {', '.join(self._VOL_FIELDS)} FROM volumes ORDER BY id")
        out = []
        for r in cur:
            d = dict(zip(("id",) + self._VOL_FIELDS, r))
            for k in ("info", "warnings"):
                try:
                    d[k] = json.loads(d[k]) if d[k] else ({} if k == "info" else [])
                except ValueError:
                    d[k] = {} if k == "info" else []
            out.append(d)
        return out

    def volume(self, vol: int) -> dict:
        for v in self.volumes():
            if v["id"] == vol:
                return v
        raise ScanError(f"No volume {vol} in this scan")

    def delete_volume(self, vol: int) -> None:
        with self._write_lock:
            self.conn.execute("DELETE FROM entries WHERE vol = ?", (vol,))
            self.conn.execute("DELETE FROM volumes WHERE id = ?", (vol,))
            self.conn.commit()

    # ------------------------------------------------------------------ writing entries
    def writer(self, vol: int, base: int = 0, batch: int = 5000) -> EntryWriter:
        """BASE: the volume's offset in the scanned source (entries' runs are relative to the volume)."""
        return EntryWriter(self, vol, base, batch)

    # ------------------------------------------------------------------ reading entries
    def entry(self, eid: int) -> dict:
        r = self.conn.execute(f"SELECT {ROW_COLUMNS}, e.key, e.ctime, e.atime, e.runs, e.data, e.extra "
                              "FROM entries e WHERE e.id = ?", (eid,)).fetchone()
        if r is None:
            raise ScanError(f"No file {eid} in this scan")
        d = _row(r)
        d["key"] = r[13]
        d["ctime"], d["atime"] = r[14], r[15]
        d["runs"] = unpack_runs(r[16])
        d["data"] = bytes(r[17]) if r[17] is not None else None
        try:
            d["extra"] = json.loads(r[18]) if r[18] else {}
        except ValueError:
            d["extra"] = {}
        return d

    def path_of(self, eid: int, include_volume: bool = False) -> str:
        """The folder path of an entry inside its volume ("Users/me/Pictures/a.jpg")."""
        parts = []
        cur = eid
        seen = set()
        vol_root = None
        while cur is not None and cur not in seen:
            seen.add(cur)
            r = self.conn.execute("SELECT parent, name, vol FROM entries WHERE id = ?", (cur,)).fetchone()
            if r is None:
                break
            if vol_root is None:
                v = self.conn.execute("SELECT root_id FROM volumes WHERE id = ?", (r[2],)).fetchone()
                vol_root = v[0] if v else None
            if cur == vol_root:
                break
            parts.append(r[1])
            cur = r[0]
        return "/".join(reversed(parts))

    def _filters(self, f: dict | None, params: list) -> str:
        """SQL conditions for the browser's filters: name (wildcards * ?), cats, deleted (True/False/None),
        min/max size, after/before (mtime), chance (minimum), exts, hide_system, files_only."""
        f = f or {}
        conds = []
        name = (f.get("name") or "").strip()
        if name:
            if any(ch in name for ch in "*?"):
                conds.append("e.name LIKE ? ESCAPE '\\'")
                pat = name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%").replace("?", "_")
                params.append(pat)
            else:
                conds.append("instr(lower(e.name), ?) > 0")
                params.append(name.lower())
        cats = f.get("cats")
        if cats:
            conds.append(f"(e.is_dir = 1 OR e.cat IN ({', '.join('?' * len(cats))}))")
            params.extend(cats)
        exts = f.get("exts")
        if exts:
            conds.append(f"(e.is_dir = 1 OR e.ext IN ({', '.join('?' * len(exts))}))")
            params.extend(x.lower().lstrip(".") for x in exts)
        if f.get("deleted") is True:
            conds.append("e.deleted = 1")
        elif f.get("deleted") is False:
            conds.append("e.deleted = 0")
        if f.get("min_size"):
            conds.append("(e.is_dir = 1 OR e.size >= ?)")
            params.append(int(f["min_size"]))
        if f.get("max_size"):
            conds.append("(e.is_dir = 1 OR e.size <= ?)")
            params.append(int(f["max_size"]))
        if f.get("after"):
            conds.append("(e.is_dir = 1 OR e.mtime >= ?)")
            params.append(float(f["after"]))
        if f.get("before"):
            conds.append("(e.is_dir = 1 OR e.mtime < ?)")
            params.append(float(f["before"]))
        if f.get("chance"):
            conds.append("(e.is_dir = 1 OR e.deleted = 0 OR e.chance >= ?)")     # existing files copy fine
            params.append(int(f["chance"]))
        if f.get("hide_system", True):
            conds.append(f"(e.flags & {F_SYSTEM}) = 0")
        if f.get("files_only"):
            conds.append("e.is_dir = 0")
        if f.get("vol"):
            conds.append("e.vol = ?")
            params.append(int(f["vol"]))
        return " AND ".join(conds)

    def children(self, parent: int, offset: int = 0, limit: int = 500, sort: str = "name", desc: bool = False,
                 filters: dict | None = None) -> dict:
        """One folder's content (files filtered; folders always shown so the tree stays navigable, unless the
        filter hides empty ones — see folder_counts)."""
        params: list = [parent]
        where = self._filters(filters, params)
        sql_where = "e.parent = ?" + (f" AND {where}" if where else "")
        total = self.conn.execute(f"SELECT count(*) FROM entries e WHERE {sql_where}", params).fetchone()[0]
        order = order_by(sort, desc)
        rows = self.conn.execute(f"SELECT {ROW_COLUMNS} FROM entries e WHERE {sql_where} ORDER BY {order} "
                                 "LIMIT ? OFFSET ?", (*params, limit, offset)).fetchall()
        out = [_row(r) for r in rows]
        self._annotate_dirs(out)
        return {"rows": out, "total": total}

    def _annotate_dirs(self, rows: list[dict]) -> None:
        dirs = [r["id"] for r in rows if r["is_dir"]]
        if not dirs:
            return
        q = (f"SELECT parent, count(*), sum(is_dir) FROM entries WHERE parent IN ({', '.join('?' * len(dirs))}) "
             "GROUP BY parent")
        counts = {p: (n, d) for p, n, d in self.conn.execute(q, dirs)}
        for r in rows:
            if r["is_dir"]:
                n, d = counts.get(r["id"], (0, 0))
                r["children"] = n
                r["subdirs"] = d or 0

    def subdirs(self, parent: int) -> list[dict]:
        rows = self.conn.execute(f"SELECT {ROW_COLUMNS} FROM entries e WHERE e.parent = ? AND e.is_dir = 1 "
                                 f"AND (e.flags & {F_SYSTEM}) = 0 ORDER BY e.name COLLATE NOCASE", (parent,)).fetchall()
        out = [_row(r) for r in rows]
        self._annotate_dirs(out)
        return out

    def search(self, filters: dict | None, offset: int = 0, limit: int = 500, sort: str = "name",
               desc: bool = False) -> dict:
        """Files anywhere in the scan that match FILTERS (with their folder paths)."""
        f = dict(filters or {})
        f["files_only"] = True
        params: list = []
        where = self._filters(f, params) or "1"
        total = self.conn.execute(f"SELECT count(*) FROM entries e WHERE {where}", params).fetchone()[0]
        order = order_by(sort, desc, dirs_first=False)
        rows = self.conn.execute(f"SELECT {ROW_COLUMNS} FROM entries e WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?",
                                 (*params, limit, offset)).fetchall()
        out = [_row(r) for r in rows]
        for r in out:
            r["path"] = self.path_of(r["parent"]) if r["parent"] else ""
        return {"rows": out, "total": total}

    def counts(self, filters: dict | None = None) -> dict:
        """Files and bytes per category (and deleted ones) for the type chips and the summary."""
        f = dict(filters or {})
        f.pop("cats", None)
        f["files_only"] = True
        params: list = []
        where = self._filters(f, params) or "1"
        out = {}
        for cat, n, size, deleted in self.conn.execute(
                f"SELECT e.cat, count(*), sum(e.size), sum(e.deleted) FROM entries e WHERE {where} GROUP BY e.cat",
                params):
            out[cat or "other"] = {"files": n, "bytes": size or 0, "deleted": deleted or 0}
        return out

    def subtree(self, eid: int, filters: dict | None = None) -> Iterator[int]:
        """Every file id under folder EID (or EID itself if it's a file), filtered."""
        params: list = [eid]
        where = self._filters(filters, params)
        sql = ("WITH RECURSIVE t(id) AS (SELECT ? UNION SELECT e.id FROM entries e JOIN t ON e.parent = t.id) "
               "SELECT e.id FROM entries e JOIN t ON e.id = t.id WHERE e.is_dir = 0" + (f" AND {where}" if where else ""))
        for (i,) in self.conn.execute(sql, params):
            yield i

    def recount(self, vol: int) -> None:
        """Recompute a volume's totals (after entries were removed)."""
        c = self.conn
        with self._write_lock:
            n = c.execute(f"SELECT count(*), sum(size), sum(deleted), sum(CASE WHEN deleted THEN size ELSE 0 END) "
                          f"FROM entries WHERE vol = ? AND is_dir = 0 AND (flags & {F_SYSTEM}) = 0", (vol,)).fetchone()
            d = c.execute("SELECT count(*) FROM entries WHERE vol = ? AND is_dir = 1", (vol,)).fetchone()[0]
            c.execute("UPDATE volumes SET files = ?, bytes = ?, deleted_files = ?, deleted_bytes = ?, folders = ? "
                      "WHERE id = ?", (n[0] or 0, n[1] or 0, n[2] or 0, n[3] or 0, d, vol))
            c.commit()

    def drop_duplicates(self, vol: int, min_chance: int = 2) -> int:
        """Remove VOL's files (the signature search's) that start where a file found through a filesystem
        starts: the filesystem's copy has the name, folder and dates. Returns how many were removed."""
        c = self.conn
        with self._write_lock:
            cur = c.execute("DELETE FROM entries WHERE vol = ? AND is_dir = 0 AND start IS NOT NULL AND start IN "
                            "(SELECT start FROM entries WHERE vol != ? AND start IS NOT NULL AND chance >= ?)",
                            (vol, vol, min_chance))
            removed = cur.rowcount
            # folders left empty (type folders, then category folders)
            for _ in range(3):
                c.execute("DELETE FROM entries WHERE vol = ? AND is_dir = 1 AND parent IS NOT NULL AND id NOT IN "
                          "(SELECT DISTINCT parent FROM entries WHERE vol = ? AND parent IS NOT NULL)", (vol, vol))
            c.commit()
        self.recount(vol)
        return removed

    def stats(self) -> dict:
        r = self.conn.execute("SELECT count(*), sum(size), sum(deleted), sum(CASE WHEN deleted THEN size ELSE 0 END) "
                              f"FROM entries WHERE is_dir = 0 AND (flags & {F_SYSTEM}) = 0").fetchone()
        return {"files": r[0] or 0, "bytes": r[1] or 0, "deleted_files": r[2] or 0, "deleted_bytes": r[3] or 0}


class EntryWriter:
    """Streams a volume's entries into the database in batches; finish() links folders by key, puts entries
    whose folder is unknown (or that hang in a loop of folders) under "Lost files", and counts."""

    def __init__(self, db: ScanDB, vol: int, base: int = 0, batch: int = 5000):
        self.db = db
        self.vol = vol
        self.base = base
        self.batch = batch
        self.rows: list[tuple] = []
        self.count = 0
        self.root_key: str | None = None

    def __enter__(self) -> EntryWriter:
        return self

    def __exit__(self, exc_type, *_rest) -> None:
        self.finish()

    def add(self, e: Entry) -> None:
        name = e.name if e.name is not None else ""
        ext = "" if e.is_dir else extension(name)
        cat = "" if e.is_dir else EXT_CATEGORY.get(ext, "other")
        if e.parent is None and self.root_key is None and e.is_dir and not (e.flags & F_ORPHAN):
            self.root_key = str(e.key)
        extra = json.dumps(e.extra, default=str) if e.extra else None
        start = None
        if e.runs and not e.is_dir:
            first = e.runs[0][0]
            start = self.base + first if first >= 0 else None
        self.rows.append((self.vol, str(e.key), None if e.parent is None else str(e.parent), name, ext, cat,
                          1 if e.is_dir else 0, int(e.size or 0), 1 if e.deleted else 0, int(e.chance), int(e.flags),
                          e.mtime, e.ctime, e.atime, e.crtime, pack_runs(e.runs),
                          None if e.data is None else bytes(e.data), extra, start))
        if len(self.rows) >= self.batch:
            self.flush()

    def flush(self) -> None:
        if not self.rows:
            return
        rows, self.rows = self.rows, []
        with self.db._write_lock:
            self.db.conn.executemany(
                "INSERT INTO entries (vol, key, pkey, name, ext, cat, is_dir, size, deleted, chance, flags, mtime, "
                "ctime, atime, crtime, runs, data, extra, start) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows)
            self.db.conn.commit()
        self.count += len(rows)

    def finish(self, lost_name: str = "Lost files") -> dict:
        self.flush()
        db, vol = self.db, self.vol
        c = db.conn
        with db._write_lock:
            # the root (created when the reader didn't give one, e.g. carved volumes)
            root = None
            if self.root_key is not None:
                r = c.execute("SELECT id FROM entries WHERE vol = ? AND key = ? AND pkey IS NULL",
                              (vol, self.root_key)).fetchone()
                root = r[0] if r else None
            if root is None:
                root = c.execute("INSERT INTO entries (vol, key, pkey, name, is_dir) VALUES (?, '__root__', NULL, '', 1)",
                                 (vol,)).lastrowid
            # parents by key (folders only)
            c.execute("UPDATE entries SET parent = (SELECT p.id FROM entries p WHERE p.vol = entries.vol AND "
                      "p.key = entries.pkey AND p.is_dir = 1 AND p.id != entries.id) WHERE vol = ? AND pkey IS NOT NULL "
                      "AND parent IS NULL", (vol,))
            # everything not reachable from the root goes under "Lost files"
            lost = None

            def lost_folder() -> int:
                nonlocal lost
                if lost is None:
                    lost = c.execute("INSERT INTO entries (vol, parent, key, pkey, name, is_dir, flags) "
                                     "VALUES (?, ?, '__lost__', NULL, ?, 1, ?)",
                                     (vol, root, lost_name, F_DIR_RECOVERED)).lastrowid
                return lost

            orphans = [i for (i,) in c.execute("SELECT id FROM entries WHERE vol = ? AND parent IS NULL AND id != ?",
                                               (vol, root))]
            if orphans:
                lf = lost_folder()
                c.executemany(f"UPDATE entries SET parent = ?, flags = flags | {F_ORPHAN} WHERE id = ?",
                              [(lf, i) for i in orphans])
            # loops of folders (A in B, B in A): unreachable from the root although every entry has a parent
            reach = {i for (i,) in c.execute(
                "WITH RECURSIVE t(id) AS (SELECT ? UNION SELECT e.id FROM entries e JOIN t ON e.parent = t.id) "
                "SELECT id FROM t", (root,))}
            total = c.execute("SELECT count(*) FROM entries WHERE vol = ?", (vol,)).fetchone()[0]
            if len(reach) < total:
                parent_of = dict(c.execute("SELECT id, parent FROM entries WHERE vol = ?", (vol,)).fetchall())
                cut = []
                done: set[int] = set(reach)
                for start in list(parent_of):
                    if start in done:
                        continue
                    path = []
                    on_path = set()
                    cur = start
                    while cur is not None and cur not in done and cur not in on_path:
                        path.append(cur)
                        on_path.add(cur)
                        cur = parent_of.get(cur)
                    if cur in on_path:             # a loop: cut it at the entry where it closes
                        cut.append(cur)
                    done.update(path)
                if cut:
                    lf = lost_folder()
                    c.executemany(f"UPDATE entries SET parent = ?, flags = flags | {F_ORPHAN} WHERE id = ?",
                                  [(lf, i) for i in cut])
            c.execute("UPDATE entries SET pkey = NULL WHERE vol = ?", (vol,))
            n = c.execute(f"SELECT count(*), sum(size), sum(deleted), sum(CASE WHEN deleted THEN size ELSE 0 END), "
                          f"(SELECT count(*) FROM entries WHERE vol = ? AND is_dir = 1) FROM entries "
                          f"WHERE vol = ? AND is_dir = 0 AND (flags & {F_SYSTEM}) = 0", (vol, vol)).fetchone()
            c.execute("UPDATE volumes SET root_id = ?, lost_id = ?, files = ?, bytes = ?, deleted_files = ?, "
                      "deleted_bytes = ?, folders = ? WHERE id = ?",
                      (root, lost, n[0] or 0, n[1] or 0, n[2] or 0, n[3] or 0, n[4] or 0, vol))
            c.commit()
        return {"root": root, "lost": lost, "files": n[0] or 0, "deleted_files": n[2] or 0}
