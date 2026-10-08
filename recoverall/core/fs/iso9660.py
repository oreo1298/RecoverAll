"""ISO 9660 (CD/DVD images) with Joliet and Rock Ridge: the files and folders of a disc image.

Layout: 16 sectors of system area, then volume descriptors of 2048 bytes from byte 32768 ("CD001"): the
primary one (type 1: volume name, size, block size, root folder record), supplementary ones (type 2; Joliet
when its escape sequence is %/@, %/C or %/E: names in UCS-2 big-endian), a terminator (type 255).
Everything else is folders: extents filled with variable-length records (length, extent location, data
length, recording date, flags, name) that never cross a sector boundary. Numbers are stored twice
(little- and big-endian); this reader uses the little-endian copy.

- A file bigger than 4 GiB is several records with the same name, all but the last flagged "multi-extent":
  their extents are joined in order.
- Rock Ridge (SUSP entries in each record's system-use area, possibly continued in CE areas) adds POSIX
  names (NM), modes (PX), times (TF) and symlinks (SL); folders deeper than 8 levels are moved to
  "rr_moved" (RE) and linked from their real parent (CL).
- Names: Rock Ridge > Joliet > plain ISO (the ";1" version and a trailing "." are dropped).

A mastered disc has no deleted files and no free space. UDF, zisofs-compressed files and multi-session
discs (only the session given is read) are not handled here.
"""

from __future__ import annotations

import calendar
import struct
from collections import deque
from typing import Iterator

from ..blockio import CachedSource, Source
from ..errors import FormatError
from .base import (
    CHANCE_GOOD,
    F_PARTIAL,
    F_SYMLINK,
    NULL_CONTROL,
    Control,
    Entry,
    FsReader,
    merge_runs,
    u16,
    u32,
)

VD_START = 32768
SECTOR = 2048
_JOLIET_ESCAPES = (b"%/@", b"%/C", b"%/E")
_FLAG_HIDDEN, _FLAG_DIR, _FLAG_ASSOCIATED, _FLAG_MULTI = 0x01, 0x02, 0x04, 0x80
_S_IFMT, _S_IFLNK = 0o170000, 0o120000
_MAX_DIR_BYTES = 256 * 1024 * 1024      # a folder extent bigger than this is damage
_MAX_DEPTH = 256
_MAX_CE = 32                            # continuation areas followed per record


# ---------------------------------------------------------------------- dates and names
def _date7(b: bytes) -> float | None:
    """A directory record date: years since 1900, month, day, hour, minute, second, GMT offset (15 min)."""
    if len(b) < 7 or not any(b[:6]):
        return None
    y, mo, d, h, mi, s = b[0] + 1900, b[1], b[2], b[3], b[4], b[5]
    off = struct.unpack("b", b[6:7])[0]
    if not (1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 61 and -48 <= off <= 52):
        return None
    try:
        return calendar.timegm((y, mo, d, h, mi, min(s, 59), 0, 0, 0)) - off * 900
    except (ValueError, OverflowError):
        return None


def _date17(b: bytes) -> float | None:
    """A volume descriptor date: "YYYYMMDDHHMMSScc" in ASCII and a GMT offset byte."""
    if len(b) < 17:
        return None
    try:
        text = b[:16].decode("ascii")
        if not text.isdigit() or text == "0" * 16:
            return None
        y, mo, d = int(text[0:4]), int(text[4:6]), int(text[6:8])
        h, mi, s, cs = int(text[8:10]), int(text[10:12]), int(text[12:14]), int(text[14:16])
    except (UnicodeDecodeError, ValueError):
        return None
    off = struct.unpack("b", b[16:17])[0]
    if not (1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 61 and -48 <= off <= 52):
        return None
    try:
        return calendar.timegm((y, mo, d, h, mi, min(s, 59), 0, 0, 0)) + cs / 100 - off * 900
    except (ValueError, OverflowError):
        return None


def _date17_text(b: bytes) -> str:
    """blkid's "UUID" of an ISO: its date as YYYY-MM-DD-HH-MM-SS-cc."""
    t = bytes(b[:16])
    if len(t) < 16 or not t.isdigit() or t == b"0" * 16:
        return ""
    s = t.decode()
    return f"{s[0:4]}-{s[4:6]}-{s[6:8]}-{s[8:10]}-{s[10:12]}-{s[12:14]}-{s[14:16]}"


def _strip_version(name: str) -> str:
    """'README.TXT;1' → 'README.TXT', 'FILE.;1' → 'FILE'."""
    i = name.rfind(";")
    if i > 0 and name[i + 1:].isdigit():
        name = name[:i]
    if name.endswith(".") and name not in (".", ".."):
        name = name[:-1]
    return name


def _text(raw: bytes, joliet: bool, strip: bool = True) -> str:
    """A name or label: UCS-2 for Joliet, else UTF-8 (Rock Ridge, modern discs) or Latin-1. Fixed-width
    descriptor fields are padded with spaces; Rock Ridge names are taken as they are (STRIP False)."""
    if joliet:
        text = raw[:len(raw) & ~1].decode("utf-16-be", "replace")
    else:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
    return text.rstrip("\0 ") if strip else text


def _clean(name: str) -> str:
    return name.replace("/", "_").replace("\0", "")


# ---------------------------------------------------------------------- volume descriptors
def parse_descriptors(src: Source) -> dict | None:
    """The primary (and Joliet) volume descriptors at 32 KiB, or None if this isn't ISO 9660."""
    pvd = None
    joliet = None
    joliet_level = 0
    for k in range(64):
        vd = src.read(VD_START + k * SECTOR, SECTOR)
        if vd[1:6] != b"CD001":
            if k == 0:
                return None
            break
        t = vd[0]
        if t == 1 and pvd is None:
            pvd = vd
        elif t == 2 and joliet is None and vd[88:91] in _JOLIET_ESCAPES:
            joliet = vd
            joliet_level = _JOLIET_ESCAPES.index(bytes(vd[88:91])) + 1
        elif t == 255:
            break
    if pvd is None:
        return None
    bs = u16(pvd, 128)
    blocks = u32(pvd, 80)
    if bs not in (512, 1024, 2048, 4096) or not blocks:
        return None
    root = pvd[156:190]
    if root[0] < 34:
        return None
    root_lba, root_len = u32(root, 2), u32(root, 10)
    if not root_len or not 16 < root_lba < blocks:
        return None
    label = _text(pvd[40:72], False)
    if joliet is not None:
        jlabel = _text(joliet[40:72], True)
        label = label or jlabel
    info = {
        "fstype": "iso9660",
        "label": label,
        "uuid": _date17_text(pvd[830:847]) or _date17_text(pvd[813:830]),
        "size": blocks * bs,
        "block_size": bs,
        "used": blocks * bs,
        "free": 0,
        "system_id": _text(pvd[8:40], False),
        "volume_set": _text(pvd[190:318], False),
        "publisher": _text(pvd[318:446], False),
        "preparer": _text(pvd[446:574], False),
        "application": _text(pvd[574:702], False),
        "created": _date17(pvd[813:830]),
        "modified": _date17(pvd[830:847]),
        "root_lba": root_lba,
        "root_size": root_len,
        "joliet": joliet_level,
    }
    if joliet is not None:
        jroot = joliet[156:190]
        jbs = u16(joliet, 128) or bs
        if jroot[0] >= 34 and jbs == bs:
            info["joliet_root_lba"] = u32(jroot, 2)
            info["joliet_root_size"] = u32(jroot, 10)
        else:
            info["joliet"] = 0
    return info


class _Rec:
    """One directory record (plus what its Rock Ridge entries say)."""

    __slots__ = ("pos", "lba", "size", "flags", "ear", "unit", "gap", "raw_name", "date", "nm", "mode", "times",
                 "cl", "re", "sigs", "sl", "sl_cont")

    def __init__(self):
        self.nm: list[bytes] | None = None      # NM pieces (joined: the Rock Ridge name)
        self.mode: int | None = None
        self.times: dict[str, float] = {}
        self.sl: list[str] | None = None        # symlink path components
        self.sl_cont = False                    # the last component continues in the next SL entry
        self.cl: int | None = None
        self.re = False
        self.sigs: set[bytes] = set()

    @property
    def symlink(self) -> str | None:
        if self.sl is None:
            return None
        return "/".join(self.sl) if self.sl != [""] else "/"


def _unique(key, pos: int, keys: set):
    """KEY, or another one no entry has yet: damaged folders can overlap, so the same record may be read twice."""
    if key not in keys:
        return key
    alt, n = f"x{pos}", 1
    while alt in keys:
        n += 1
        alt = f"x{pos}.{n}"
    return alt


class Iso9660Reader(FsReader):
    fstype = "iso9660"
    name = "ISO 9660"
    root_key = 0
    deleted_support = False

    def __init__(self, src: Source, info: dict | None = None):
        super().__init__(src, info)
        if not self.info.get("root_lba"):
            probed = parse_descriptors(src)
            if probed is None:
                raise FormatError("This isn't an ISO 9660 volume (no primary volume descriptor)")
            probed.update(self.info)
            self.info = probed
        self.bs = int(self.info.get("block_size") or SECTOR)
        self.block_size = self.bs
        self.label = self.info.get("label") or ""
        self.meta = CachedSource(src, block=64 * 1024, blocks=512)
        self.skip = 0                       # SUSP bytes to skip in every system-use area (from SP)
        self.rock_ridge = False
        self.joliet = int(self.info.get("joliet") or 0)
        self._detect_susp()
        # which tree to walk: the primary one carries Rock Ridge; otherwise Joliet's names are better
        if self.rock_ridge or not self.info.get("joliet_root_lba"):
            self.use_joliet = False
            self.root_lba = int(self.info["root_lba"])
            self.root_size = int(self.info["root_size"])
        else:
            self.use_joliet = True
            self.root_lba = int(self.info["joliet_root_lba"])
            self.root_size = int(self.info["joliet_root_size"])
        self.root_key = self.root_lba * self.bs

    @classmethod
    def probe(cls, src: Source) -> dict | None:
        info = parse_descriptors(src)
        if info is None:
            return None
        try:
            r = cls(src, info)
            info["rock_ridge"] = r.rock_ridge
        except Exception:  # noqa: BLE001 - probing must never fail loudly
            info["rock_ridge"] = False
        if info["size"] > src.size:
            info["truncated"] = True
        return info

    # ------------------------------------------------------------------ records
    def _detect_susp(self) -> None:
        """Rock Ridge is announced by an SP entry at the start of the root's "." record."""
        lba = int(self.info["root_lba"])
        sec = self.meta.read(lba * self.bs, SECTOR)
        n = sec[0]
        if n < 34:
            return
        lfi = sec[32]
        start = 33 + lfi + (1 - lfi % 2)
        su = sec[start:n]
        if len(su) >= 7 and su[:2] == b"SP" and su[4:6] == b"\xbe\xef":
            self.skip = su[6]
            rec = _Rec()
            self._susp(su, rec, 0)
            # SUSP alone (without Rock Ridge entries) says nothing about names
            self.rock_ridge = bool(rec.sigs & {b"RR", b"PX", b"NM", b"TF", b"SL", b"ER"})

    def _records(self, lba: int, size: int) -> list[_Rec]:
        """The records of the folder at LBA (SIZE bytes), "." and ".." excluded."""
        if size > _MAX_DIR_BYTES or lba * self.bs >= self.src.size:
            self.warn(f"A folder record points outside the image (block {lba}).")
            return []
        data = self.meta.read(lba * self.bs, size) if size <= 256 * 1024 else self.src.read(lba * self.bs, size)
        out: list[_Rec] = []
        pos = 0
        bad = False
        while pos < size:
            n = data[pos]
            if n == 0:
                pos = (pos // SECTOR + 1) * SECTOR          # the rest of this sector is padding
                continue
            if n < 34 or pos + n > size or (pos % SECTOR) + n > SECTOR:
                bad = True
                pos = (pos // SECTOR + 1) * SECTOR
                continue
            rec = data[pos:pos + n]
            lfi = rec[32]
            if 33 + lfi > n:
                bad = True
                pos += n
                continue
            raw_name = bytes(rec[33:33 + lfi])
            pos_abs = lba * self.bs + pos
            pos += n
            if raw_name in (b"\0", b"\1"):
                continue
            r = _Rec()
            r.pos = pos_abs
            r.ear = rec[1]
            r.lba = u32(rec, 2)
            r.size = u32(rec, 10)
            r.date = _date7(rec[18:25])
            r.flags = rec[25]
            r.unit, r.gap = rec[26], rec[27]
            r.raw_name = raw_name
            if self.rock_ridge and not self.use_joliet:
                start = 33 + lfi + (1 - lfi % 2) + self.skip
                if start < n:
                    self._susp(rec[start:n], r, 0)
            out.append(r)
        if bad:
            self.warn(f"A folder (block {lba}) has damaged records.")
        return out

    def _susp(self, area: bytes, r: _Rec, depth: int) -> None:
        """Rock Ridge entries of one system-use area (and of its continuation areas, CE)."""
        p = 0
        ce = None
        while p + 4 <= len(area):
            sig = bytes(area[p:p + 2])
            ln = area[p + 2]
            if ln < 4 or p + ln > len(area):
                break
            body = area[p + 4:p + ln]
            r.sigs.add(sig)
            if sig == b"ST":
                break
            if sig == b"CE" and len(body) >= 24:
                ce = (u32(body, 0), u32(body, 8), u32(body, 16))
            elif sig == b"NM" and len(body) >= 1:
                if not body[0] & 0x06:            # "." and ".." names aren't real names
                    r.nm = (r.nm or []) + [bytes(body[1:])]
            elif sig == b"PX" and len(body) >= 32:
                r.mode = u32(body, 0)
            elif sig == b"TF" and len(body) >= 1:
                self._tf(body, r)
            elif sig == b"SL" and len(body) >= 1:
                self._sl(body, r)
            elif sig == b"CL" and len(body) >= 8:
                r.cl = u32(body, 0)
            elif sig == b"RE":
                r.re = True
            p += ln
        if ce is not None and depth < _MAX_CE:
            block, off, length = ce
            if 0 < length <= 64 * 1024 and off < self.bs:
                self._susp(self.meta.read(block * self.bs + off, length), r, depth + 1)

    @staticmethod
    def _tf(body: bytes, r: _Rec) -> None:
        flags = body[0]
        long_form = bool(flags & 0x80)
        width = 17 if long_form else 7
        p = 1
        for bit, key in ((0x01, "crtime"), (0x02, "mtime"), (0x04, "atime"), (0x08, "ctime"), (0x10, "backup"),
                         (0x20, "expire"), (0x40, "effective")):
            if flags & bit:
                stamp = bytes(body[p:p + width])
                if len(stamp) < width:
                    break
                t = _date17(stamp) if long_form else _date7(stamp)
                if t is not None:
                    r.times[key] = t
                p += width

    @staticmethod
    def _sl(body: bytes, r: _Rec) -> None:
        """Symlink path components (a component may continue in the next one, even across SL entries)."""
        comps = r.sl if r.sl is not None else []
        p = 1
        while p + 2 <= len(body) and len(comps) < 4096:
            cf, ln = body[p], body[p + 1]
            if cf & 0x02:
                text = "."
            elif cf & 0x04:
                text = ".."
            elif cf & 0x08:
                text = ""                          # the root: the target starts with "/"
            else:
                text = bytes(body[p + 2:p + 2 + ln]).decode("utf-8", "replace")
            if r.sl_cont and comps:
                comps[-1] += text
            else:
                comps.append(text)
            r.sl_cont = bool(cf & 0x01)
            p += 2 + ln
        r.sl = comps

    def _name(self, r: _Rec) -> str:
        if r.nm:
            return _clean(_text(b"".join(r.nm), False, strip=False))
        return _clean(_strip_version(_text(r.raw_name, self.use_joliet)))

    def _runs(self, recs: list[_Rec]) -> tuple[list[tuple[int, int]], int, bool]:
        """Content runs of one file (several records when multi-extent): (runs, size, part outside)."""
        runs: list[tuple[int, int]] = []
        total = 0
        outside = False
        for r in recs:
            start = (r.lba + r.ear) * self.bs
            if r.unit and r.gap:
                # an interleaved file: UNIT blocks of data, GAP blocks skipped, repeated
                left = r.size
                pos = start
                while left > 0 and len(runs) < 1_000_000:
                    k = min(left, r.unit * self.bs)
                    runs.append((pos, k))
                    left -= k
                    pos += (r.unit + r.gap) * self.bs
            elif r.size:
                runs.append((start, r.size))
            if start + r.size > self.src.size and r.size:
                outside = True
            total += r.size
        return merge_runs(runs), total, outside

    # ------------------------------------------------------------------ the scan
    def entries(self, ctl: Control = NULL_CONTROL, deleted: bool = True) -> Iterator[Entry]:
        root_recs = self.meta.read(self.root_lba * self.bs, 34)
        root_time = _date7(root_recs[18:25]) if root_recs[0] >= 34 else None
        yield Entry(key=self.root_key, parent=None, name="", is_dir=True, chance=CHANCE_GOOD, mtime=root_time)
        queue = deque([(self.root_lba, self.root_size, self.root_key, 0)])
        seen = {self.root_lba}
        keys = {self.root_key}
        count = 0
        while queue:
            lba, size, key, depth = queue.popleft()
            recs = self._records(lba, size)
            i = 0
            while i < len(recs):
                group = [recs[i]]
                # a multi-extent file: records with the same name, the last one without the flag
                while group[-1].flags & _FLAG_MULTI and i + 1 < len(recs) and recs[i + 1].raw_name == group[0].raw_name:
                    i += 1
                    group.append(recs[i])
                i += 1
                r = group[0]
                count += 1
                if count % 256 == 0:
                    ctl.check()
                    ctl.progress(None, "Reading folders")
                if r.flags & _FLAG_ASSOCIATED or r.re:
                    continue                       # Mac resource forks; relocated folders (listed via CL)
                name = self._name(r)
                if not name or name in (".", ".."):
                    continue
                times = r.times
                e = Entry(key=r.pos, parent=key, name=name, chance=CHANCE_GOOD,
                          mtime=times.get("mtime", r.date), atime=times.get("atime"), ctime=times.get("ctime"),
                          crtime=times.get("crtime"), extra={"lba": r.lba})
                if r.mode is not None:
                    e.extra["mode"] = r.mode & 0o7777
                if r.flags & _FLAG_HIDDEN:
                    e.extra["hidden"] = True
                if r.flags & _FLAG_DIR or r.cl is not None:
                    dlba, dsize = r.lba, r.size
                    if r.cl is not None:
                        dlba, dsize = r.cl, self._dir_size(r.cl)
                    if dlba in seen:
                        self.warn(f"Folder {name!r} is listed twice (or loops): its second copy is skipped.")
                        continue
                    seen.add(dlba)
                    e.key = dlba * self.bs
                    e.is_dir = True
                    e.extra["lba"] = dlba
                    e.key = _unique(e.key, r.pos, keys)    # overlapping metadata: keep keys unique
                    if dsize and depth < _MAX_DEPTH:
                        queue.append((dlba, dsize, e.key, depth + 1))
                elif r.symlink is not None or (r.mode is not None and r.mode & _S_IFMT == _S_IFLNK):
                    e.flags |= F_SYMLINK
                    e.data = (r.symlink or "").encode("utf-8")
                    e.size = len(e.data)
                else:
                    e.runs, e.size, outside = self._runs(group)
                    if outside:
                        e.flags |= F_PARTIAL
                        self.warn("Some files lie past the end of the image (it is probably truncated).")
                e.key = _unique(e.key, r.pos, keys)
                keys.add(e.key)
                yield e

    def _dir_size(self, lba: int) -> int:
        """A folder's size from its own "." record (relocated folders are reached by location only)."""
        rec = self.meta.read(lba * self.bs, 34)
        if rec[0] < 34 or rec[32] != 1 or rec[33] != 0:
            self.warn(f"A relocated folder (block {lba}) is damaged.")
            return 0
        return u32(rec, 10)

    def free_extents(self, ctl: Control = NULL_CONTROL) -> list[tuple[int, int]] | None:
        """A mastered disc has no free space."""
        return []
