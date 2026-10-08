"""recoverctl: recover files, partitions and photos from the command line (or over SSH).

Reading disks needs root: run it with sudo. Image files you own work without.
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import json
import os
import signal
import sys
import threading
import time

from . import __app_name__, __version__
from .core.errors import RallError
from .core.util import fmt_bytes, fmt_duration, fmt_when, parse_size

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def bold(t):
    return c(t, "1")


def dim(t):
    return c(t, "2")


def red(t):
    return c(t, "31")


def green(t):
    return c(t, "32")


def yellow(t):
    return c(t, "33")


def blue(t):
    return c(t, "34")


CHANCE = {3: ("good", green), 2: ("fair", yellow), 1: ("poor", red), 0: ("?", dim)}


# ---------------------------------------------------------------------- helpers
def get_api(args):
    from .core import session
    return session.local_api(demo=args.demo)


def resolve_disk(api, text: str) -> str:
    """sda, /dev/sda, a by-id link, the number in `recoverctl list`, part of the model/serial, an image file or a
    .rallraid file."""
    if os.path.isfile(text):
        return os.path.abspath(text)
    disks = api.list_disks()
    if text.isdigit() and 1 <= int(text) <= len(disks):
        return disks[int(text) - 1]["path"]
    cand = text if text.startswith("/dev/") else f"/dev/{text}"
    real = os.path.realpath(cand)
    for d in disks:
        if d["path"] in (cand, real) or d["name"] == text:
            return d["path"]
    hits = [d for d in disks if text.lower() in (d.get("display_name") or "").lower() or
            text.lower() in (d.get("serial") or "").lower()]
    if len(hits) == 1:
        return hits[0]["path"]
    if len(hits) > 1:
        raise RallError(f"“{text}” matches several disks: " + ", ".join(d["path"] for d in hits))
    if os.path.exists(real) and getattr(api, "mode", "") != "demo":
        return real
    raise RallError(f"No disk “{text}” (see: recoverctl list)")


def source_spec(api, text: str, partition: int | None = None):
    path = resolve_disk(api, text)
    if partition is None:
        return path
    d = api.disk_detail(path=path)
    for p in d.get("partitions") or []:
        if p.get("number") == partition:
            return {"path": path, "offset": p["start"], "size": p["size"]}
    raise RallError(f"{path} has no partition {partition}")


def print_json(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def health_text(h) -> str:
    if not h:
        return ""
    state = h.get("state")
    reasons = dim(" (" + ", ".join(h.get("reasons") or []) + ")") if h.get("reasons") else ""
    if state == "failing":
        return red("FAILING") + reasons
    if state == "warning":
        return yellow("warning") + reasons
    return green("healthy")


def fs_label(fstype: str | None) -> str:
    from .core.fs import fs_name
    return fs_name(fstype) if fstype else "—"


def follow(api, job: dict, args, verbose_log: bool = False) -> dict:
    """Print a job's steps, warnings and progress until it ends. Ctrl-C stops it cleanly. Returns the job."""
    seen = [0]
    state = {"step": -1}
    done = threading.Event()
    tty = sys.stdout.isatty() and not args.json
    last = [""]

    def clear_bar():
        if tty and last[0]:
            sys.stdout.write("\r\033[2K")
            last[0] = ""

    def on_event(ev):
        if ev.get("type") == "log" and ev.get("job") == job["id"]:
            for n, _t, level, text in ev["lines"]:
                if n <= seen[0]:
                    continue
                seen[0] = n
                if args.json or text.startswith("— ") or (level == "info" and not (args.verbose or verbose_log)):
                    continue
                clear_bar()
                print((yellow if level == "warning" else red if level == "error" else dim)("  " + text))
        elif ev.get("type") == "job" and ev["job"]["id"] == job["id"]:
            j = ev["job"]
            if args.json:
                if j["state"] != "running":
                    done.set()
                return
            if j["step"] != state["step"] and 0 <= j["step"] < len(j["steps"]):
                state["step"] = j["step"]
                clear_bar()
                s = j["steps"][j["step"]]
                print(blue("▸ ") + s["title"] + (dim(f"  {s['detail']}") if s.get("detail") else ""))
            if j["state"] != "running":
                done.set()
            elif tty:
                width = 28
                filled = int(width * j["progress"])
                st = j.get("stats") or {}
                eta = f"  {fmt_duration(st['eta'])} left" if st.get("eta") else ""
                bar = f"  [{'█' * filled}{'·' * (width - filled)}] {j['progress'] * 100:5.1f} %  {j['message']}{eta}"
                cols = os.get_terminal_size().columns
                sys.stdout.write("\r\033[2K" + bar[:cols - 1])
                sys.stdout.flush()
                last[0] = bar
    api.add_listener(on_event)
    stopping = [False]

    def on_sigint(_sig, _frm):
        if stopping[0]:
            return
        stopping[0] = True
        clear_bar()
        print(yellow("\nStopping… (what was found so far is kept)"))
        api.cancel_job(job_id=job["id"])
    old = signal.signal(signal.SIGINT, on_sigint)
    try:
        while not done.wait(0.5):
            if api.job(job_id=job["id"])["state"] != "running":
                break
    finally:
        signal.signal(signal.SIGINT, old)
        api.remove_listener(on_event)
    clear_bar()
    j = api.job(job_id=job["id"])
    if args.json:
        return j
    if j["state"] == "done":
        print(green("✓ ") + (j["message"] or "Done"))
        for w in (j.get("warnings") or [])[:20]:
            print(yellow("! " + w))
    elif j["state"] == "cancelled":
        print(yellow("■ " + (j["message"] or "Stopped")))
    else:
        print(red("✗ " + (j["error"] or j["message"] or "Failed")))
    return j


# ---------------------------------------------------------------------- disks
def cmd_list(api, args) -> int:
    disks = api.list_disks()
    if args.json:
        print_json(disks)
        return 0
    if not disks:
        print("No disks found.")
        return 0
    for i, d in enumerate(disks, start=1):
        flags = []
        if d.get("system"):
            flags.append(yellow("system"))
        h = health_text(d.get("health"))
        if h:
            flags.append(h)
        table = {"gpt": "GPT", "dos": "MBR", "apm": "Apple"}.get(d.get("pttype") or "", "no partition table")
        print(f"{i:>2}. {bold(d['display_name'])}  {d['capacity_text']}  {dim(d['path'])}  "
              f"{dim(d['kind'] + ' · ' + table)}  {' '.join(flags)}")
        for p in d.get("partitions") or []:
            if p.get("extended"):
                continue
            label = f"“{p['label']}”" if p.get("label") else ""
            mp = ", ".join(p.get("mountpoints") or [])
            print(f"  {p['number']:>3}  {fs_label(p.get('fstype')):<10} {label:<20} {fmt_bytes(p['size']):>10}  "
                  f"{dim(mp)}".rstrip())
        if not d.get("partitions") and d.get("fstype"):
            print(f"       {fs_label(d['fstype'])} {('“' + d['label'] + '”') if d.get('label') else ''} on the whole disk")
    return 0


def cmd_info(api, args) -> int:
    path = resolve_disk(api, args.disk)
    d = api.disk_detail(path=path)
    if args.json:
        print_json(d)
        return 0
    print(bold(d["display_name"]) + f"  {d['capacity_text']}  {dim(d['path'])}")
    if d.get("serial"):
        print(f"  Serial       {d['serial']}")
    print(f"  Kind         {d['kind']}  ·  sectors {d.get('logical_sector')} B")
    if d.get("health"):
        print(f"  Health       {health_text(d['health'])}")
    t = d.get("table") or {}
    print(f"  Table        {(t.get('type') or 'none').upper()}" + ("" if t.get("ok", True) else red("  damaged")))
    for p in t.get("problems") or []:
        print(yellow(f"  ! {p}"))
    for p in d.get("partitions") or []:
        if p.get("extended"):
            continue
        print(f"  {p['number']:>3}  {fs_label(p.get('fstype')):<10} {p.get('label') or '':<20} "
              f"{fmt_bytes(p['size']):>10}  at {fmt_bytes(p['start'])}")
    return 0


# ---------------------------------------------------------------------- scanning
def cmd_scan(api, args) -> int:
    spec = source_spec(api, args.source, args.partition)
    mode = "deep" if args.deep else "carve" if args.carve else "photos" if args.photos else "quick"
    opts = {"mode": mode}
    if args.types:
        opts["formats"] = [t.strip() for t in args.types.split(",") if t.strip()]
    if args.free_only:
        opts["free_only"] = True
    if args.whole:
        opts["free_only"] = False
    if args.out:
        opts["folder"] = os.path.dirname(os.path.abspath(args.out))
    job = api.start_scan(source=spec, options=opts, name=args.name or "")
    scan = job.get("scan")
    if not args.json:
        print(bold(job["title"]))
    j = follow(api, job, args)
    if args.out and scan and j["state"] in ("done", "cancelled"):
        dest = api.save_scan(scan=scan, dest=args.out)
        scan = dest
    if args.json:
        print_json({"state": j["state"], "scan": scan, "message": j.get("message"), "result": j.get("result")})
        return 0 if j["state"] == "done" else 1
    if j["state"] in ("done", "cancelled") and scan:
        print(dim(f"  Scan file: {scan}"))
        info = api.scan_info(scan=scan)
        print_volumes(info)
        print(dim(f"  Next: recoverctl ls {scan}   ·   recoverctl recover {scan} DEST --deleted"))
    return 0 if j["state"] == "done" else 1


def print_volumes(info: dict) -> None:
    for v in info.get("volumes") or []:
        status = {"existing": "", "deleted partition": yellow(" deleted partition"), "damaged": yellow(" damaged"),
                  "reconstructed": yellow(" rebuilt from MFT records"), "carved": ""}.get(v.get("status"),
                                                                                       dim(f" {v.get('status')}"))
        what = "signature search" if v.get("fstype") == "carved" else fs_label(v.get("fstype"))
        line = (f"  {bold(str(v['id'])):>3}  {v.get('name') or ''}  {dim(what)}{status}  "
                f"{v.get('files', 0):,} files, {v.get('deleted_files', 0):,} deleted".replace(",", " "))
        if v.get("note"):
            line += dim(f"  — {v['note']}")
        print(line)


def _saved_scans(api) -> list[dict]:
    return sorted(api.scans(), key=lambda s: -(s.get("created") or 0))


def resolve_scan(api, ref: str) -> str:
    """A scan file from what the user typed: its path, "last", its number in `recoverctl scans`, or part of
    its file name (the newest match)."""
    if os.path.exists(ref) or ref.endswith(".rascan") and os.sep in ref:
        return ref
    items = _saved_scans(api)
    if not items:
        raise RallError(f"{ref}: no such scan file, and there are no saved scans")
    if ref.lower() in ("last", "latest"):
        return items[0]["path"]
    if ref.isdigit():
        n = int(ref)
        if 1 <= n <= len(items):
            return items[n - 1]["path"]
        raise RallError(f"There is no scan number {n}: `recoverctl scans` lists {len(items)}")
    hits = [s for s in items if ref.lower() in os.path.basename(s["path"]).lower()]
    if not hits:
        raise RallError(f"{ref}: no such scan file, and no saved scan has that in its name (see `recoverctl scans`)")
    return hits[0]["path"]


def cmd_scans(api, args) -> int:
    items = _saved_scans(api)
    if args.json:
        print_json(items)
        return 0
    if not items:
        print("No saved scans.")
        return 0
    for i, s in enumerate(items, 1):
        st = s.get("stats") or {}
        src = s.get("source") or {}
        print(f"{i:2d}. {bold(src.get('display_name') or src.get('name') or '?')}  {dim(fmt_when(s.get('created')))}  "
              f"{s.get('mode') or ''}  {st.get('files', 0)} files ({st.get('deleted_files', 0)} deleted)  "
              f"{dim(s['path'])}")
    print(dim("\nUse a scan by its number, \"last\", part of its name or its path: recoverctl ls 1"))
    return 0


def _volume_and_folder(api, scan: str, path: str | None) -> tuple[dict, int]:
    info = api.scan_info(scan=scan)
    vols = info["volumes"]
    if not vols:
        raise RallError("This scan found no volumes")
    vid = None
    rel = path or ""
    if rel and ":" in rel.split("/")[0]:
        head, _sep, rel = rel.partition(":")
        if head.isdigit():
            vid = int(head)
    vol = next((v for v in vols if v["id"] == vid), None) if vid else (vols[0] if len(vols) == 1 or rel else None)
    if vol is None:
        raise RallError("Several volumes: say which one, e.g. 2:/Users (see recoverctl ls SCAN)")
    folder = vol["root_id"]
    for part in [p for p in rel.split("/") if p]:
        rows = api.scan_children(scan=scan, parent=folder, limit=100000, filters={"hide_system": False})["rows"]
        hit = next((r for r in rows if r["name"] == part and r["is_dir"]), None) or \
            next((r for r in rows if r["name"].lower() == part.lower() and r["is_dir"]), None)
        if hit is None:
            raise RallError(f"No folder “{part}” in {vol['name']}")
        folder = hit["id"]
    return vol, folder


def _filters(args) -> dict:
    f: dict = {}
    if getattr(args, "deleted", False):
        f["deleted"] = True
    if getattr(args, "existing", False):
        f["deleted"] = False
    if getattr(args, "name", None):
        f["name"] = args.name
    if getattr(args, "type", None):
        from .core.filetypes import CATEGORY_NAMES
        cats, exts = [], []
        for t in args.type.split(","):
            t = t.strip().lower()
            if t in CATEGORY_NAMES or t in ("photos", "videos", "documents", "archives"):
                cats.append(t.rstrip("s") if t.endswith("s") and t[:-1] in CATEGORY_NAMES else t)
            elif t:
                exts.append(t.lstrip("."))
        if cats:
            f["cats"] = cats
        if exts:
            f["exts"] = exts
    if getattr(args, "min_size", None):
        f["min_size"] = parse_size(args.min_size)
    if getattr(args, "max_size", None):
        f["max_size"] = parse_size(args.max_size)
    if getattr(args, "good", False):
        f["chance"] = 3
    if getattr(args, "system", False):
        f["hide_system"] = False
    return f


def row_line(r: dict, path: str = "") -> str:
    if r["is_dir"]:
        n = r.get("children")
        return f"  {blue(r['name'] + '/')}" + (dim(f"  {n} items") if n is not None else "") + \
            (yellow("  deleted") if r["deleted"] else "")
    ch, col = CHANCE.get(r["chance"], ("?", dim))
    state = (yellow("deleted ") + col(ch)) if r["deleted"] else ""
    when = fmt_when(r.get("mtime")) if r.get("mtime") else ""
    name = f"{path}/{r['name']}" if path else r["name"]
    return f"  {name:<48} {fmt_bytes(r['size']):>10}  {dim(when):<16}  {state}"


def cmd_ls(api, args) -> int:
    if args.path is None:
        info = api.scan_info(scan=args.scan)
        if args.json:
            print_json(info["volumes"])
            return 0
        src = info.get("source") or {}
        print(bold(src.get("display_name") or src.get("name") or "") + dim(f"  {info.get('state')}"))
        print_volumes(info)
        if len(info["volumes"]) > 1:
            print(dim("  Browse one with: recoverctl ls SCAN 2:/   (volume number, colon, path)"))
            return 0
        args.path = ""
    _vol, folder = _volume_and_folder(api, args.scan, args.path)
    res = api.scan_children(scan=args.scan, parent=folder, limit=args.limit, sort=args.sort, filters=_filters(args))
    if args.json:
        print_json(res)
        return 0
    for r in res["rows"]:
        print(row_line(r))
    if res["total"] > len(res["rows"]):
        print(dim(f"  … {res['total'] - len(res['rows'])} more (--limit)"))
    return 0


def cmd_find(api, args) -> int:
    f = _filters(args)
    res = api.scan_search(scan=args.scan, filters=f, limit=args.limit, sort=args.sort)
    if args.json:
        print_json(res)
        return 0
    for r in res["rows"]:
        print(row_line(r, r.get("path") or ""))
    print(dim(f"  {res['total']} files match" + (f" (showing {len(res['rows'])})" if res["total"] > len(res["rows"])
                                                 else "")))
    return 0


def cmd_recover(api, args) -> int:
    scan = args.scan
    info = api.scan_info(scan=scan)
    ids = []
    if args.paths:
        for p in args.paths:
            vol, folder = None, None
            head, sep, tail = p.rpartition("/")
            try:
                vol, folder = _volume_and_folder(api, scan, p)
                ids.append(folder)
                continue
            except RallError:
                pass
            vol, parent = _volume_and_folder(api, scan, head if sep else "")
            rows = api.scan_children(scan=scan, parent=parent, limit=100000, filters={"hide_system": False})["rows"]
            hits = [r["id"] for r in rows if fnmatch.fnmatch(r["name"], tail)]
            if not hits:
                raise RallError(f"Nothing matches {p}")
            ids.extend(hits)
    else:
        ids = [v["root_id"] for v in info["volumes"] if v.get("root_id")]
    opts = {"keep_paths": not args.flat, "restore_times": True, "volume_folders": not args.flat}
    job = api.start_recover(scan=scan, entries=ids, dest=os.path.abspath(args.dest), options=opts,
                            filters=_filters(args))
    if not args.json:
        print(bold(job["title"]))
    j = follow(api, job, args)
    if args.json:
        print_json({"state": j["state"], "result": j.get("result"), "message": j.get("message")})
    elif j["state"] == "done" and (j.get("result") or {}).get("report"):
        print(dim(f"  Report: {j['result']['report']}"))
    return 0 if j["state"] == "done" else 1


def cmd_photos(api, args) -> int:
    """Scan for photos and videos and recover every one found — the one-step PhotoRec."""
    spec = source_spec(api, args.source, args.partition)
    types = args.types or "photo,video"
    job = api.start_scan(source=spec, options={"mode": "photos", "formats": types.split(",")})
    scan = job["scan"]
    if not args.json:
        print(bold(job["title"]))
    j = follow(api, job, args)
    if j["state"] != "done":
        return 1
    info = api.scan_info(scan=scan)
    cats = [t for t in types.split(",") if t]
    ids = [v["root_id"] for v in info["volumes"] if v.get("root_id")]
    filt = {"cats": cats, "deleted": None if args.all else True}
    rec = api.start_recover(scan=scan, entries=ids, dest=os.path.abspath(args.dest),
                            options={"keep_paths": True, "volume_folders": True}, filters=filt)
    if not args.json:
        print(bold(rec["title"]))
    r = follow(api, rec, args)
    return 0 if r["state"] == "done" else 1


def cmd_preview(api, args) -> int:
    hits = api.scan_search(scan=args.scan, filters={"name": args.file}, limit=2)["rows"]
    if not hits:
        raise RallError(f"No file named {args.file} in this scan")
    p = api.preview(scan=args.scan, entry=hits[0]["id"])
    if args.json:
        print_json({k: v for k, v in p.items() if k not in ("data", "hex")})
        return 0
    if p.get("note"):
        print(yellow("! " + p["note"]))
    for k, v in (p.get("info") or {}).items():
        print(f"  {k:<10} {v}")
    if p.get("kind") == "text":
        print(p.get("text", "")[:4000])
    else:
        data = base64.b64decode(p.get("hex") or "")
        print(hexdump(data[:512], 0))
    return 0


# ---------------------------------------------------------------------- partitions
def cmd_partitions(api, args) -> int:
    path = resolve_disk(api, args.disk)
    job = api.start_partition_search(source=path, mode="deep" if args.deep else "quick")
    if not args.json:
        print(bold(job["title"]))
    j = follow(api, job, args)
    res = j.get("result") or {}
    if args.json:
        print_json(res)
        return 0 if j["state"] == "done" else 1
    if j["state"] != "done":
        return 1
    cands = res.get("candidates") or []
    if not cands:
        print("No filesystems found. Try --deep.")
        return 1
    print()
    for i, c in enumerate(cands, start=1):
        st = {"current": green("in the table"), "deleted": yellow("not in the table (deleted)"),
              "damaged": yellow("damaged"), "overlaps": dim("overlaps another (ignored)")}.get(c.get("status"),
                                                                                            c.get("status") or "")
        print(f"{i:>2}. {fs_label(c.get('fstype')):<8} {('“' + c['label'] + '”') if c.get('label') else '':<18} "
              f"{fmt_bytes(c.get('size')):>10} at {fmt_bytes(c.get('offset')):>10}  {st}  {dim(c.get('evidence') or '')}")
        if c.get("preview"):
            print(dim("      " + "  ".join(c["preview"][:8])))
    prop = res.get("proposal") or []
    if not args.write:
        print(dim(f"\n  To write these {len(prop)} partitions as a new {res.get('table_type', 'gpt').upper()} table: "
                  f"sudo recoverctl partitions {args.disk} {'--deep ' if args.deep else ''}--write"))
        return 0
    plan = api.plan_partitions(source=path, table_type=args.table or res.get("table_type") or "gpt", parts=prop)
    print("\n" + bold("New partition table:"))
    print(plan.get("script", ""))
    for p in plan.get("problems") or []:
        print(red("! " + p))
    if not plan.get("ok"):
        return 1
    disk = api.disk_detail(path=path)
    token = disk.get("confirm_token") or ""
    if args.yes:
        typed = token
    else:
        typed = input(f"The old table is backed up first (undo: recoverctl undo). Type “{token}” to write it: ")
    result = api.write_partitions(source=path, table_type=args.table or res.get("table_type") or "gpt",
                                  parts=prop, confirm=typed)
    print(green("✓ Written.") + dim(f"  Backup of the old sectors: {result.get('backup')}"))
    return 0


def cmd_backups(api, args) -> int:
    items = api.list_backups()
    if args.json:
        print_json(items)
        return 0
    for b in items:
        print(f"{fmt_when(b.get('created'))}  {b.get('device')}  {b.get('label') or ''}  {dim(b.get('path'))}")
    if not items:
        print("No backups: RecoverAll hasn't changed any disk yet.")
    return 0


def cmd_undo(api, args) -> int:
    res = api.undo_backup(path=args.backup)
    print(green("✓ The saved sectors were written back.") if args.json is False else json.dumps(res))
    return 0


# ---------------------------------------------------------------------- repair
def cmd_diagnose(api, args) -> int:
    path = resolve_disk(api, args.disk)
    offset, size, fstype = 0, None, ""
    if args.partition is not None:
        spec = source_spec(api, args.disk, args.partition)
        offset, size = spec["offset"], spec["size"]
    probs = api.diagnose(source=path, offset=offset, size=size, fstype=fstype)
    if args.json:
        print_json(probs)
        return 0
    if not probs:
        print(green("✓ No problems found in the boot sectors, superblocks and partition table."))
        return 0
    for p in probs:
        col = red if p.get("severity") == "error" else yellow
        print(col("! " + p["title"]))
        if p.get("detail"):
            print(dim("  " + p["detail"]))
        if p.get("fix"):
            print(dim(f"  Fix: sudo recoverctl repair {args.disk} "
                      f"{'--partition ' + str(args.partition) + ' ' if args.partition else ''}{p['fix']}"))
    return 1


def cmd_repair(api, args) -> int:
    path = resolve_disk(api, args.disk)
    offset, size = 0, None
    fstype = args.fstype or ""
    if args.partition is not None:
        spec = source_spec(api, args.disk, args.partition)
        offset, size = spec["offset"], spec["size"]
        if not fstype:
            for p in api.disk_detail(path=path).get("partitions") or []:
                if p["number"] == args.partition:
                    fstype = p.get("fstype") or ""
    else:
        fstype = fstype or api.disk_detail(path=path).get("fstype") or ""
    if not args.action:
        acts = api.fsck_actions(fstype=fstype)
        print(bold(f"Repairs for {fs_label(fstype)}:"))
        for a in acts:
            risk = {"safe": green("check only"), "normal": yellow("repairs"), "risky": red("last resort")}.get(
                a.get("risk"), "")
            avail = "" if a.get("available", True) else red(f"  (install {a.get('package') or a.get('missing_program')})")
            print(f"  fsck:{a['id']:<16} {a.get('title')}  {risk}{avail}")
            if a.get("detail"):
                print(dim(f"      {a['detail']}"))
        print(dim("  Boot-sector repairs: boot:ntfs_boot, boot:fat_boot, boot:fat_copy, boot:exfat_boot, "
                  "boot:gpt_rebuild (see recoverctl diagnose)"))
        return 0
    disk = api.disk_detail(path=path)
    token = disk.get("confirm_token") or ""
    typed = token if (args.yes or args.action.startswith("fsck:") and "check" in args.action) else ""
    if not typed and not disk.get("is_image"):
        typed = input(f"This writes to {disk['display_name']}. Type “{token}” to go on: ")
    opts = {}
    if args.superblock:
        opts["superblock"] = args.superblock
    job = api.start_repair(source=path, action=args.action, offset=offset, size=size, fstype=fstype, options=opts,
                           confirm=typed)
    if not args.json:
        print(bold(job["title"]))
    j = follow(api, job, args, verbose_log=True)
    return 0 if j["state"] == "done" else 1


def cmd_fixfile(api, args) -> int:
    paths = [os.path.abspath(p) for p in args.files]
    if args.check:
        for p in paths:
            a = api.file_analyze(path=p)
            print(bold(os.path.basename(p)) + dim(f"  {a.get('type')}"))
            for prob in a.get("problems") or []:
                print(yellow("  ! " + prob))
            if not a.get("problems"):
                print(green("  ✓ looks fine"))
        return 0
    out = os.path.abspath(args.out or os.path.dirname(paths[0]))
    job = api.start_file_repair(paths=paths, out_dir=out, reference=args.reference)
    j = follow(api, job, args, verbose_log=True)
    return 0 if j["state"] == "done" else 1


# ---------------------------------------------------------------------- imaging, RAID, misc
def cmd_image(api, args) -> int:
    spec = source_spec(api, args.source, args.partition)
    job = api.start_image(source=spec, dest=os.path.abspath(args.dest),
                          options={"retries": args.retries, "engine": args.engine})
    if not args.json:
        print(bold(job["title"]))
    j = follow(api, job, args)
    if j["state"] == "done" and not args.json:
        print(dim(f"  Scan the image: recoverctl scan {args.dest} --deep"))
    return 0 if j["state"] == "done" else 1


def cmd_raid(api, args) -> int:
    members = []
    for m in args.member or []:
        if m in ("missing", "-"):
            members.append(None)
        else:
            path, _sep, off = m.partition("@")
            members.append({"path": resolve_disk(api, path), "offset": parse_size(off) if off else 0})
    if args.detect:
        paths = [m["path"] for m in members if m]
        missing = len(members) - len(paths)
        md = api.raid_from_md(paths=paths)
        if md:
            print(green("✓ Linux software RAID found: ") + json.dumps({k: md[k] for k in ("level", "chunk", "layout")}))
            definition = md
        else:
            job = api.start_raid_detect(paths=paths, levels=[args.level] if args.level else None, missing=missing)
            j = follow(api, job, args)
            cands = (j.get("result") or {}).get("candidates") or []
            if not cands:
                print(red("✗ No layout made sense. Enter the parameters yourself (--level, --chunk, --layout)."))
                return 1
            for cnd in cands[:5]:
                print(f"  score {cnd['score']:>5}  RAID {cnd['level']}  {cnd['chunk'] // 1024} KiB  {cnd['layout']}  "
                      + " ".join(os.path.basename(x['path']) if x else "(missing)" for x in cnd['members']))
            definition = {"type": "raid", **cands[0]}
    else:
        if not args.level:
            raise RallError("Give --level (0, 1, 5, 6, 10, jbod), or use --detect")
        definition = {"type": "raid", "level": args.level, "chunk": parse_size(args.chunk or "64K"),
                      "layout": args.layout or "left-symmetric", "members": members}
    definition["name"] = args.name or definition.get("name") or "Virtual RAID"
    desc = api.raid_describe(definition=definition)
    print(f"{bold(definition['name'])}: {desc['text']}, {desc['size_text']}")
    if args.save:
        path = api.save_raid(definition=definition, path=os.path.abspath(args.save))
        print(dim(f"  Saved: {path}  (use it like a disk: recoverctl scan {path} --deep)"))
    return 0


def hexdump(data: bytes, base: int) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:012x}  {hx:<47}  {asc}")
    return "\n".join(lines)


def cmd_hexdump(api, args) -> int:
    spec = source_spec(api, args.source, args.partition)
    off = parse_size(args.offset) if args.offset else 0
    n = parse_size(args.length) if args.length else 512
    r = api.read_bytes(source=spec, offset=off, length=n)
    print(hexdump(base64.b64decode(r["data"]), off))
    return 0


def cmd_unlock(api, args) -> int:
    spec = source_spec(api, args.source, args.partition)
    import getpass
    pw = getpass.getpass("Passphrase (or BitLocker recovery key): ")
    res = api.unlock(source=spec, passphrase=pw)
    print(green(f"✓ Unlocked read-only as {res['path']}") + dim(f"   scan it: sudo recoverctl scan {res['path']}"))
    return 0


def cmd_formats(api, args) -> int:
    items = api.formats()
    if args.json:
        print_json(items)
        return 0
    from .core.filetypes import CATEGORY_NAMES
    by: dict[str, list] = {}
    for f in items:
        by.setdefault(f["category"], []).append(f)
    for cat, fs in by.items():
        print(bold(CATEGORY_NAMES.get(cat, cat)) + dim(f"  ({len(fs)})"))
        print("  " + ", ".join(f["key"] + ("" if f.get("enabled", True) else dim(" (off)")) for f in fs))
    return 0


def cmd_doctor(api, args) -> int:
    items = api.tool_list()
    if args.json:
        print_json(items)
        return 0
    from .core.tools import GROUPS
    print(bold(f"{__app_name__} {__version__}") + dim("  — every tool is optional: the recovery engines are built in"))
    group = None
    for t in sorted(items, key=lambda t: list(GROUPS).index(t["group"]) if t["group"] in GROUPS else 99):
        if t["group"] != group:
            group = t["group"]
            print(bold(GROUPS.get(group, group)))
        ok = bool(t.get("path"))
        mark = green("✓") if ok else yellow("·")
        print(f"  {mark} {t['name']:<14} {t['use']:<44} {dim(t['path'] or 'install ' + t['package'])}")
    print(dim(f"Signature formats: {len(api.formats())}"))
    return 0


def cmd_history(api, args) -> int:
    items = api.history(limit=args.limit)
    if args.json:
        print_json(items)
        return 0
    for e in items:
        mark = {"done": green("✓"), "failed": red("✗"), "cancelled": yellow("■")}.get(e.get("state"), "·")
        dur = (e.get("finished") or 0) - (e.get("started") or 0)
        print(f"{mark} {fmt_when(e.get('started'))}  {e.get('title')}  {dim(fmt_duration(dur))}")
        msg = e.get("error") or e.get("message")
        if msg:
            print(dim("    " + msg))
    return 0


# ---------------------------------------------------------------------- the parser
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="recoverctl", description=f"{__app_name__}: recover deleted files, lost "
                                 "partitions and photos. Run the commands that read disks with sudo.")
    ap.add_argument("--version", action="version", version=f"{__app_name__} {__version__}")
    ap.add_argument("--demo", action="store_true", help="simulated disks (nothing touches your hardware)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-y", "--yes", action="store_true", help="don't ask for confirmations")
    sub = ap.add_subparsers(dest="command")

    sub.add_parser("list", help="disks, partitions and volumes")
    p = sub.add_parser("info", help="details of a disk: partition table, health")
    p.add_argument("disk")

    def source_args(p):
        p.add_argument("source", help="sda, /dev/sda, a number from `list`, a model/serial, an image or .rallraid file")
        p.add_argument("--partition", "-p", type=int, help="only this partition")

    p = sub.add_parser("scan", help="find files: --quick (default), --deep, --carve (signatures) or --photos")
    source_args(p)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--quick", action="store_true", help="partitions and filesystems (minutes)")
    g.add_argument("--deep", action="store_true", help="read the whole disk: lost/damaged filesystems + signatures")
    g.add_argument("--carve", action="store_true", help="signatures only, like PhotoRec")
    g.add_argument("--photos", action="store_true", help="deleted photos and videos (filesystem + free space)")
    p.add_argument("--types", help="signature types/categories: photo,video,document,… or jpg,pdf,…")
    p.add_argument("--free-only", action="store_true", help="signatures: only the free space")
    p.add_argument("--whole", action="store_true", help="signatures: the whole disk")
    p.add_argument("--out", help="also save the scan file here")
    p.add_argument("--name", help="a name for the scan")
    sub.add_parser("scans", help="saved scans")

    def filter_args(p):
        p.add_argument("--deleted", action="store_true", help="only deleted files")
        p.add_argument("--existing", action="store_true", help="only files that weren't deleted")
        p.add_argument("--name", help="name or wildcards (*.jpg)")
        p.add_argument("--type", help="photo,video,audio,document,archive,email,database,… or extensions")
        p.add_argument("--min-size")
        p.add_argument("--max-size")
        p.add_argument("--good", action="store_true", help="only files with good recovery chances")
        p.add_argument("--system", action="store_true", help="include filesystem metadata files")

    p = sub.add_parser("ls", help="browse a scan: volumes, then folders (2:/Users/anna)")
    p.add_argument("scan", help="a scan file, \"last\", or its number or name in `recoverctl scans`")
    p.add_argument("path", nargs="?")
    p.add_argument("--limit", type=int, default=1000)
    p.add_argument("--sort", default="name", choices=("name", "size", "mtime", "chance", "type"))
    filter_args(p)
    p = sub.add_parser("find", help="search a scan")
    p.add_argument("scan", help="a scan file, \"last\", or its number or name in `recoverctl scans`")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--sort", default="name", choices=("name", "size", "mtime", "chance", "type"))
    filter_args(p)
    p = sub.add_parser("recover", help="copy files out of a scan (to another disk)")
    p.add_argument("scan", help="a scan file, \"last\", or its number or name in `recoverctl scans`")
    p.add_argument("dest")
    p.add_argument("paths", nargs="*", help="2:/Users/anna/Pictures, 1:/DCIM/*.JPG … (default: everything)")
    p.add_argument("--flat", action="store_true", help="don't recreate the folders")
    filter_args(p)
    p = sub.add_parser("photos", help="one step: find and recover deleted photos and videos")
    source_args(p)
    p.add_argument("dest")
    p.add_argument("--types", help="categories or extensions (default photo,video)")
    p.add_argument("--all", action="store_true", help="also the files that weren't deleted")
    p = sub.add_parser("preview", help="what a found file looks like (text, info, hex)")
    p.add_argument("scan", help="a scan file, \"last\", or its number or name in `recoverctl scans`")
    p.add_argument("file", help="its name")

    p = sub.add_parser("partitions", help="find lost partitions (TestDisk); --write puts them back")
    p.add_argument("disk")
    p.add_argument("--deep", action="store_true", help="read the whole disk")
    p.add_argument("--write", action="store_true", help="write the partitions found as a new table")
    p.add_argument("--table", choices=("gpt", "dos"), help="the table type to write")
    sub.add_parser("backups", help="sectors saved before RecoverAll changed a disk")
    p = sub.add_parser("undo", help="write back sectors saved before a change")
    p.add_argument("backup")

    p = sub.add_parser("diagnose", help="check boot sectors, superblocks and the partition table")
    p.add_argument("disk")
    p.add_argument("--partition", "-p", type=int)
    p = sub.add_parser("repair", help="repair a filesystem (fsck tools, boot sectors); no action: list them")
    p.add_argument("disk")
    p.add_argument("action", nargs="?", help="fsck:<id> or boot:<name>")
    p.add_argument("--partition", "-p", type=int)
    p.add_argument("--fstype")
    p.add_argument("--superblock", type=int, help="ext: use this backup superblock")
    p = sub.add_parser("fix-file", help="repair damaged files (JPEG, PNG, ZIP/Office, PDF, WAV/AVI, …)")
    p.add_argument("files", nargs="+")
    p.add_argument("--out", help="folder for the repaired copies")
    p.add_argument("--reference", help="a good file from the same camera/program (JPEG headers)")
    p.add_argument("--check", action="store_true", help="only say what's wrong")

    p = sub.add_parser("image", help="copy a disk to an image file first (failing disks!)")
    source_args(p)
    p.add_argument("dest")
    p.add_argument("--retries", type=int, default=1)
    p.add_argument("--engine", choices=("auto", "ddrescue", "builtin"), default="auto")
    p = sub.add_parser("raid", help="assemble a virtual RAID from its members (disks or images)")
    p.add_argument("--member", "-m", action="append", help="disk or image[@offset]; 'missing' for a lost member")
    p.add_argument("--level", choices=("0", "1", "5", "6", "10", "jbod"))
    p.add_argument("--chunk", help="stripe size (64K)")
    p.add_argument("--layout", choices=("left-symmetric", "left-asymmetric", "right-symmetric", "right-asymmetric"))
    p.add_argument("--detect", action="store_true", help="find the parameters (md superblocks, or by trying)")
    p.add_argument("--name")
    p.add_argument("--save", help="write the definition (.rallraid) to use as a source")
    p = sub.add_parser("hexdump", help="raw bytes of a disk")
    source_args(p)
    p.add_argument("offset", nargs="?", help="0, 1M, 0x7e00 …")
    p.add_argument("length", nargs="?")
    p = sub.add_parser("unlock", help="open a LUKS/BitLocker volume read-only")
    source_args(p)
    sub.add_parser("formats", help="the file types the signature search knows")
    sub.add_parser("doctor", help="which optional tools are installed")
    p = sub.add_parser("history", help="what ran")
    p.add_argument("--limit", type=int, default=50)
    return ap


COMMANDS = {"list": cmd_list, "info": cmd_info, "scan": cmd_scan, "scans": cmd_scans, "ls": cmd_ls, "find": cmd_find,
            "recover": cmd_recover, "photos": cmd_photos, "preview": cmd_preview, "partitions": cmd_partitions,
            "backups": cmd_backups, "undo": cmd_undo, "diagnose": cmd_diagnose, "repair": cmd_repair,
            "fix-file": cmd_fixfile, "image": cmd_image, "raid": cmd_raid, "hexdump": cmd_hexdump,
            "unlock": cmd_unlock, "formats": cmd_formats, "doctor": cmd_doctor, "history": cmd_history}


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    import logging
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.ERROR, format="%(levelname)s %(message)s")
    if args.command is None:
        args.command = "list"
    api = None
    try:
        api = get_api(args)
        if args.command in ("ls", "find", "recover", "preview"):
            args.scan = resolve_scan(api, args.scan)
        return COMMANDS[args.command](api, args)
    except RallError as exc:
        print(red(f"✗ {exc}"), file=sys.stderr)
        if "administrator" in str(exc) and os.geteuid() != 0:
            print(dim("  Run it with sudo."), file=sys.stderr)
        return 1
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0
    except OSError as exc:
        print(red(f"✗ {exc.strerror or exc}" + (f": {exc.filename}" if exc.filename else "")), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        return 130
    finally:
        if api is not None:
            try:
                api.close()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0)


if __name__ == "__main__":
    sys.exit(main())
