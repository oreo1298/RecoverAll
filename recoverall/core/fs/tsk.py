"""The Sleuth Kit as a filesystem engine.

TSK (fls, icat, fsstat, pstat) reads filesystems RecoverAll has no native reader for — APFS, UFS1/UFS2 — and
gives a second opinion on the others (NTFS, FAT, exFAT, ext2/3/4, HFS+, ISO 9660). It only works on what is
backed by a real image file or device: TSK opens the file itself, so virtual sources (a rebuilt RAID, the
free space of a volume) can't be handed to it.

* Listing: ``fls -r -m /`` prints one line per name in "body file" format
  (``md5|path|inode|mode|uid|gid|size|atime|mtime|ctime|crtime``). Names whose entry is free are marked
  "(deleted)", or "(deleted-realloc)" when their inode/MFT record now belongs to another file (whose data
  overwrote theirs). Names that contain "|" are put back together from the fixed fields.
* Content: ``icat`` streams a file's bytes (``-r`` for deleted files: TSK's own recovery, e.g. a deleted FAT
  file assumed contiguous). The decoder "tsk" runs it again whenever a file is recovered.
* APFS: the volume RecoverAll finds is the container; ``pstat`` lists the volumes inside it, and each one is
  read with ``-P apfs -B <volume superblock>``. Encrypted APFS volumes are skipped (TSK needs the password).

What TSK can't do here: classic HFS (only HFS+ inside an HFS wrapper), Btrfs, XFS, F2FS; NTFS/ext files TSK
lists without a size (ext4 zeroes a deleted inode's size and extents) come back empty. fls prints control
characters in names as "^" (the content is still found: icat goes by inode).
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from typing import Iterator

from ..blockio import CachedSource, ConcatSource, FileSource, RegionSource, Source, SplitSource
from ..errors import FormatError, NotSupported, ToolMissing
from ..util import run, which
from .base import (
    CHANCE_FAIR,
    CHANCE_GOOD,
    CHANCE_POOR,
    F_ADS,
    F_DIR_RECOVERED,
    F_ORPHAN,
    F_SYMLINK,
    F_SYSTEM,
    NULL_CONTROL,
    Control,
    Entry,
    FsReader,
    register_decoder,
)

# our fstype → TSK's -f name
TSK_TYPES = {"ntfs": "ntfs", "fat12": "fat12", "fat16": "fat16", "fat32": "fat32", "vfat": "fat", "exfat": "exfat",
             "ext2": "ext2", "ext3": "ext3", "ext4": "ext4", "ufs": "ufs", "ufs1": "ufs1", "ufs2": "ufs2",
             "hfs": "hfs", "hfsplus": "hfsp", "hfsx": "hfsp", "iso9660": "iso9660", "apfs": "apfs",
             "yaffs2": "yaffs2"}
# what fsstat -t prints → our fstype
FROM_TSK = {"ntfs": "ntfs", "fat12": "fat12", "fat16": "fat16", "fat32": "fat32", "exfat": "exfat", "ext2": "ext2",
            "ext3": "ext3", "ext4": "ext4", "ufs1": "ufs1", "ufs2": "ufs2", "hfsp": "hfsplus", "hfs": "hfsplus",
            "iso9660": "iso9660", "apfs": "apfs", "yaffs2": "yaffs2"}

_MODE = re.compile(r"^[-a-zA-Z]/[-a-zA-Z][-rwxsStTl]{9}$")
_INODE = re.compile(r"^\d+(-\d+(-\d+)?)?$")
_TIMEOUT = 120.0
_READ = 1024 * 1024


def available() -> bool:
    """True when fls and icat are installed."""
    return which("fls") is not None and which("icat") is not None


_supported: set[str] | None = None


def supported_types() -> set[str]:
    """The -f names this TSK build knows (``fls -f list``)."""
    global _supported
    if _supported is None:
        r = run(["fls", "-f", "list"], timeout=20)
        text = (r.stdout or "") + (r.stderr or "")
        _supported = {m.group(1) for m in re.finditer(r"^\s+(\w+) \(", text, re.M)}
    return _supported


def _env() -> dict:
    env = dict(os.environ)
    env.update({"LC_ALL": "C", "LANG": "C"})
    return env


def image_args(src: Source) -> tuple[list[str], int]:
    """The image file(s) behind SRC and SRC's byte offset in them. Raises NotSupported for sources TSK
    can't open (a rebuilt RAID, a concatenation of pieces, an in-memory image)."""
    s, base = src, 0
    for _ in range(32):
        if isinstance(s, RegionSource):
            base += s.offset
            s = s.parent
        elif isinstance(s, CachedSource):
            s = s.inner
        else:
            break
    if isinstance(s, SplitSource):
        return [f.path for f in s.files], base
    from ..vdisk import VDiskSource
    if isinstance(s, VDiskSource):
        raise NotSupported(f"Tools that read the image file itself (The Sleuth Kit, btrfs-progs) can't see inside "
                           f"a {s.format} image: save it as a raw image first (Imaging page, or recoverctl image) "
                           "and scan that")
    if isinstance(s, FileSource):
        return [s.path], base
    if isinstance(s, ConcatSource) or not src.path or not os.path.exists(src.path):
        raise NotSupported("The Sleuth Kit can only read a disk, a partition or an image file, not a virtual "
                           "volume (a rebuilt RAID or a joined image): save it as an image file first")
    return [src.path], src.base


def _location(src: Source) -> list[str]:
    images, base = image_args(src)
    if base % 512:
        raise NotSupported("The Sleuth Kit can't read a volume that doesn't start on a 512-byte sector")
    return ["-o", str(base // 512), *images]


# ---------------------------------------------------------------------- body file lines
def parse_body_line(line: str) -> dict | None:
    """One fls -m line → dict(name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime), or None when it
    isn't one."""
    parts = line.split("|")
    if len(parts) < 11:
        return None
    tail = parts[-9:]
    inode, mode = tail[0], tail[1]
    if not _INODE.match(inode) or not _MODE.match(mode):
        return None
    try:
        uid, gid, size, atime, mtime, ctime, crtime = (int(x) for x in tail[2:])
    except ValueError:
        return None
    return {"name": "|".join(parts[1:-9]), "inode": inode, "mode": mode, "uid": uid, "gid": gid, "size": size,
            "atime": atime, "mtime": mtime, "ctime": ctime, "crtime": crtime}


def _t(v: int) -> float | None:
    return float(v) if v > 0 else None


def _mode_bits(mode: str) -> int:
    """'r/rrw-r--r--' → 0o100644 (the permission string after the type letters)."""
    types = {"r": 0o100000, "d": 0o040000, "l": 0o120000, "c": 0o020000, "b": 0o060000, "p": 0o010000,
             "s": 0o140000}
    bits = types.get(mode[2], 0)
    perm = mode[3:12]
    for i, ch in enumerate(perm):
        if ch not in "-ST":
            bits |= 1 << (8 - i)
    if perm[2] in "sS":
        bits |= 0o4000
    if perm[5] in "sS":
        bits |= 0o2000
    if perm[8] in "tT":
        bits |= 0o1000
    return bits


# ---------------------------------------------------------------------- the reader
class TskReader(FsReader):
    fstype = "tsk"
    name = "The Sleuth Kit"
    root_key = "root"

    def __init__(self, src: Source, info: dict | None = None):
        super().__init__(src, info)
        self.fstype = self.info.get("fstype") or "tsk"
        from . import fs_name
        self.name = self.info.get("name") or fs_name(self.fstype)
        self.tsk_type = self.info.get("tsk_type") or TSK_TYPES.get(self.fstype)
        if not self.tsk_type:
            raise NotSupported(f"The Sleuth Kit can't read {self.name} volumes")
        if not available():
            raise ToolMissing("The Sleuth Kit isn't installed (install the sleuthkit package)")
        self.location = _location(src)
        self.deleted_support = True

    @classmethod
    def probe(cls, src: Source) -> dict | None:
        """Ask fsstat what the volume is (or pstat, for an APFS container)."""
        if not available():
            return None
        try:
            loc = _location(src)
        except NotSupported:
            return None
        r = run(["fsstat", "-t", *loc], timeout=60)
        t = r.stdout.strip().split("\n")[0].strip() if r.ok else ""
        info: dict = {}
        if not t:
            vols = _apfs_volumes(loc)
            if not vols:
                return None
            t = "apfs"
            info["apfs_volumes"] = vols
            info["label"] = vols[0]["name"] if len(vols) == 1 else ""
        fstype = FROM_TSK.get(t, t)
        info.update({"fstype": fstype, "tsk_type": t, "size": src.size})
        if t != "apfs":
            full = run(["fsstat", "-f", t, *loc], timeout=60)
            if full.ok:
                info.update(_fsstat_fields(full.stdout))
        info.setdefault("label", "")
        info.setdefault("uuid", "")
        info.setdefault("block_size", 4096 if t == "apfs" else 512)
        return info

    # ------------------------------------------------------------------ listing
    def _volumes(self) -> list[dict]:
        """[{block, name}] of the APFS volumes to list ([{}]: a plain filesystem)."""
        if self.tsk_type != "apfs":
            return [{}]
        vols = self.info.get("apfs_volumes")
        if self.info.get("apfs_block"):
            vols = [{"block": int(self.info["apfs_block"]), "name": self.label, "encrypted": False}]
        if not vols:
            vols = _apfs_volumes(self.location)
        if not vols:
            raise FormatError("The Sleuth Kit finds no APFS volume in this container")
        out = []
        for v in vols:
            if v.get("encrypted"):
                self.warn(f"The APFS volume {v.get('name') or v['block']} is encrypted: The Sleuth Kit can't "
                          "read it without its password.")
                continue
            out.append(v)
        return out

    def entries(self, ctl: Control = NULL_CONTROL, deleted: bool = True) -> Iterator[Entry]:
        yield Entry(key="root", parent=None, name="", is_dir=True, chance=CHANCE_GOOD)
        vols = self._volumes()
        for v in vols:
            pool = ["-P", "apfs", "-B", str(v["block"])] if v else []
            root_key, prefix = "root", ""
            if v and len(vols) > 1:
                prefix = f"v{v['block']}:"
                root_key = prefix + "/"
                yield Entry(key=root_key, parent="root", name=v.get("name") or f"Volume {v['block']}", is_dir=True,
                            chance=CHANCE_GOOD, extra={"apfs_block": v["block"]})
            yield from self._list(ctl, deleted, pool, root_key, prefix)

    def _list(self, ctl: Control, deleted: bool, pool: list[str], root_key: str, prefix: str) -> Iterator[Entry]:
        cmd = ["fls", "-r", "-m", "/", "-f", self.tsk_type, *pool]
        if not deleted:
            cmd.append("-u")
        exe = which(cmd[0])
        if exe is None:
            raise ToolMissing("The Sleuth Kit isn't installed (install the sleuthkit package)")
        err = tempfile.TemporaryFile()
        try:
            proc = subprocess.Popen([exe, *cmd[1:], *self.location], stdout=subprocess.PIPE, stderr=err,
                                    stdin=subprocess.DEVNULL, env=_env())
        except OSError as exc:
            err.close()
            raise NotSupported(f"fls: {exc.strerror or exc}") from exc
        dirs: dict[str, object] = {"": root_key, "$OrphanFiles": None}    # path → key of the folder
        keys: set = {root_key}
        made: list[Entry] = []
        n = 0
        try:
            for raw in proc.stdout:
                rec = parse_body_line(raw.decode("utf-8", "replace").rstrip("\n"))
                if rec is None:
                    continue                      # fls prints control characters in names as "^": one line each
                n += 1
                if n % 500 == 0:
                    ctl.check()
                    ctl.progress(None, f"The Sleuth Kit: {n} names listed")
                e = self._entry(rec, pool, dirs, keys, prefix, made)
                if made:
                    yield from made
                    made.clear()
                if e is not None:
                    yield e
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            proc.stdout.close()
            err.seek(0)
            errtext = err.read().decode("utf-8", "replace").strip()
            err.close()
        if proc.returncode != 0:
            msg = errtext.splitlines()[-1] if errtext else f"exit status {proc.returncode}"
            if n == 0:
                if "not supported" in msg.lower():
                    raise NotSupported(f"The Sleuth Kit can't read this volume: {msg}")
                raise FormatError(f"The Sleuth Kit can't read this volume: {msg}")
            self.warn(f"The Sleuth Kit stopped early ({msg}): the list may be incomplete.")

    def _entry(self, rec: dict, pool: list[str], dirs: dict, keys: set, prefix: str,
               made: list[Entry]) -> Entry | None:
        """The entry of one fls line (None for lines that aren't files); folders created on the way to it are
        appended to MADE."""
        inode = rec["inode"]
        parts = inode.split("-")
        if len(parts) > 1 and parts[1] == "48":
            return None                           # NTFS $FILE_NAME times: a duplicate of the file's line
        name = rec["name"]
        mode = rec["mode"]
        deleted = realloc = False
        if name.endswith(" (deleted-realloc)"):
            name, deleted, realloc = name[:-18], True, True
        elif name.endswith(" (deleted)"):
            name, deleted = name[:-10], True
        if name.endswith(" (Volume Label Entry)"):
            return None
        is_dir = mode[0] in "dV" or mode[2] == "d"
        is_link = mode[2] == "l" or mode[0] == "l"
        target = None
        if is_link and " -> " in name:
            raw = name.encode("utf-8", "surrogateescape")
            size = rec["size"]
            if 0 < size < len(raw) and raw[:-size].endswith(b" -> "):
                target = raw[-size:]
                name = raw[:-size - 4].decode("utf-8", "replace")
            else:
                name, _sep, t = name.rpartition(" -> ")
                target = t.encode("utf-8", "surrogateescape")
        path = name.lstrip("/")
        if not path or path == "$OrphanFiles":
            return None                           # TSK's folder of orphans: they go to "Lost files"
        parent_path, _sep, base = path.rpartition("/")
        flags = 0
        if mode[0] in "vV" or (not parent_path and base.startswith("$")) or parent_path.startswith("$Extend"):
            flags |= F_SYSTEM
        parent = self._dir_key(parent_path, dirs, keys, prefix, made)
        if parent is None:
            flags |= F_ORPHAN
        if self.tsk_type == "ntfs" and ":" in base and len(parts) > 1 and parts[1] == "128":
            flags |= F_ADS
        key = prefix + "/" + path
        if key in keys:
            key = f"{key}#{inode}"
            k = 1
            while key in keys:
                k += 1
                key = f"{prefix}/{path}#{inode}.{k}"
        keys.add(key)
        if is_dir and path not in dirs:
            dirs[path] = key
        if deleted:
            chance = CHANCE_POOR if (realloc or (rec["size"] == 0 and not is_dir)) else CHANCE_FAIR
        else:
            chance = CHANCE_GOOD
        extra = {"inode": inode, "uid": rec["uid"], "gid": rec["gid"], "mode": _mode_bits(mode)}
        e = Entry(key=key, parent=parent, name=base, is_dir=is_dir, deleted=deleted, chance=chance, flags=flags,
                  mtime=_t(rec["mtime"]), atime=_t(rec["atime"]), ctime=_t(rec["ctime"]), crtime=_t(rec["crtime"]),
                  extra=extra)
        if realloc:
            extra["realloc"] = True
        if is_dir:
            return e
        if target is not None:
            e.flags |= F_SYMLINK
            e.data = target
            e.size = len(target)
            return e
        e.size = rec["size"]
        extra.update({"decoder": "tsk", "tsk_type": self.tsk_type})
        if pool:
            extra["pool"] = pool
        if deleted:
            extra["deleted"] = True
        return e

    @staticmethod
    def _dir_key(path: str, dirs: dict, keys: set, prefix: str, made: list[Entry]):
        """The key of folder PATH. Folders TSK didn't print before their content (a damaged parent) are
        created on the way and appended to MADE."""
        missing = []
        p = path
        while p not in dirs:
            missing.append(p)
            p = p.rpartition("/")[0]
        parent = dirs[p]
        for p in reversed(missing):
            key = prefix + "/" + p
            while key in keys:
                key += "#"
            keys.add(key)
            dirs[p] = key
            made.append(Entry(key=key, parent=parent, name=p.rpartition("/")[2], is_dir=True, chance=CHANCE_FAIR,
                              flags=F_DIR_RECOVERED | (F_ORPHAN if parent is None else 0)))
            parent = key
        return parent


def _fsstat_fields(text: str) -> dict:
    """Label, UUID and block size from fsstat's report (every filesystem words them differently)."""
    out: dict = {}
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        if not sep:
            continue
        k, v = k.strip().lower(), v.strip()
        if k in ("volume name", "volume label (boot sector)", "volume label (root directory)", "volume label") \
                and v and not out.get("label"):
            out["label"] = v
        elif k in ("volume id", "volume serial number", "volume uuid", "volume identifier") and \
                v.strip("0x") and not out.get("uuid"):
            out["uuid"] = v
        elif k in ("block size", "cluster size", "allocation block size", "fragment size") and \
                v.split()[0].isdigit() and "block_size" not in out:
            out["block_size"] = int(v.split()[0])
    return out


def _apfs_volumes(loc: list[str]) -> list[dict]:
    """The volumes of an APFS container, from pstat: [{block, name, role, encrypted}]."""
    r = run(["pstat", *loc], timeout=60)
    if not r.ok or "APFS" not in r.stdout:
        return []
    vols: list[dict] = []
    for line in r.stdout.splitlines():
        line = line.strip("| ").strip()
        k, sep, v = line.partition(":")
        if not sep:
            continue
        k, v = k.strip(), v.strip()
        if k == "APSB Block Number" and v.isdigit():
            vols.append({"block": int(v), "name": "", "encrypted": False})
        elif vols and k == "Name (Role)":
            m = re.match(r"^(.*?)(?: \((.*)\))?$", v)
            vols[-1]["name"] = m.group(1) if m else v
            vols[-1]["role"] = (m.group(2) or "") if m else ""
        elif vols and k == "Encrypted":
            vols[-1]["encrypted"] = v.lower().startswith("yes")
    return vols


# ---------------------------------------------------------------------- the "tsk" decoder
def _field(entry, name, default=None):
    if isinstance(entry, dict):
        return entry.get(name, default)
    return getattr(entry, name, default)


def decode_tsk(src: Source, entry) -> Iterator[bytes]:
    """A file's content streamed from icat (decoder "tsk"); short output is padded with zeros to the size."""
    extra = _field(entry, "extra") or {}
    size = int(_field(entry, "size") or 0)
    exe = which("icat")
    if exe is None:
        raise ToolMissing("The Sleuth Kit isn't installed (install the sleuthkit package)")
    loc = _location(src)
    cmd = [exe, "-f", str(extra.get("tsk_type") or "auto"), *(extra.get("pool") or [])]
    if extra.get("deleted"):
        cmd.append("-r")
    cmd += [*loc, str(extra.get("inode"))]
    if cmd[2] == "auto":
        del cmd[1:3]
    err = tempfile.TemporaryFile()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err, stdin=subprocess.DEVNULL, env=_env())
    left = size
    got = 0
    try:
        while left > 0:
            piece = proc.stdout.read(min(_READ, left))
            if not piece:
                break
            left -= len(piece)
            got += len(piece)
            yield piece
        if left > 0:
            proc.wait()
            if got == 0 and proc.returncode != 0:
                err.seek(0)
                text = err.read().decode("utf-8", "replace").strip()
                raise FormatError(f"The Sleuth Kit can't read this file: {text.splitlines()[-1] if text else ''}"
                                  .rstrip(": "))
            while left > 0:
                k = min(_READ, left)
                yield bytes(k)
                left -= k
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()
        err.close()


register_decoder("tsk", decode_tsk)
