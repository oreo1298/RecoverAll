"""Virtual RAID: put the member disks (or images of them) of a RAID back together, read-only, without the
controller or mdadm — then scan, recover from or image the array like any disk (R-Studio's "virtual RAID").

Supported: JBOD/span, RAID 0, RAID 1, RAID 10 (near copies), RAID 5 (the four classic parity layouts) and
RAID 6 (P+Q, symmetric layouts). RAID 5 and RAID 6 work with one member missing: its data is rebuilt from
the parity of the others, on the fly.

A definition is plain JSON (saved as a ``.rallraid`` file)::

    {"type": "raid", "name": "NAS", "level": "5", "layout": "left-symmetric", "chunk": 65536,
     "members": [{"path": "/dev/sdb", "offset": 0}, null, {"path": "/dev/sdd", "offset": 0}],
     "size": 0}

``offset`` is where the data starts on each member (md 1.x arrays keep their superblock before it);
``null`` is a missing member. ``size`` 0 means as much as the members allow.
"""

from __future__ import annotations

import itertools
import json
import os
from pathlib import Path

from .blockio import BadMap, FileSource, Source, open_source
from .errors import RallError

LEVELS = {"jbod": "JBOD / span", "0": "RAID 0 (stripe)", "1": "RAID 1 (mirror)", "10": "RAID 10 (mirrored stripes)",
          "5": "RAID 5 (single parity)", "6": "RAID 6 (double parity)"}
LAYOUTS5 = ("left-symmetric", "left-asymmetric", "right-symmetric", "right-asymmetric")
LAYOUTS6 = ("left-symmetric", "right-symmetric")
CHUNKS = (4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576)


class _MembersBad(BadMap):
    """The array's unreadable bytes: the sum of its members' (enough to notice a damaged file)."""

    def __init__(self, members: list[Source | None]):
        super().__init__()
        self._members = [m for m in members if m is not None]

    @property
    def total(self) -> int:
        return sum(m.bad.total for m in self._members)


def _xor(blocks: list[bytes]) -> bytes:
    n = len(blocks[0])
    acc = int.from_bytes(blocks[0], "little")
    for b in blocks[1:]:
        acc ^= int.from_bytes(b, "little")
    return acc.to_bytes(n, "little")


class RaidSource(Source):
    """A RAID array assembled from member Sources (None for a missing member)."""

    def __init__(self, members: list[Source | None], level: str, chunk: int = 65536, layout: str = "left-symmetric",
                 offsets: list[int] | None = None, size: int = 0, copies: int = 2, name: str = "RAID"):
        super().__init__()
        self.members = list(members)
        self.level = str(level).lower().replace("raid", "")
        self.chunk = int(chunk)
        self.layout = layout
        self.copies = copies
        self.offsets = list(offsets or [0] * len(members))
        self.name = name
        self.n = len(members)
        present = [m for m in members if m is not None]
        if not present:
            raise RallError("A virtual RAID needs at least one member")
        self.sector_size = present[0].sector_size
        self.bad = _MembersBad(members)
        sizes = [m.size - o for m, o in zip(members, self.offsets) if m is not None]
        member = min(sizes)
        missing = self.n - len(present)
        lv = self.level
        if lv in ("0", "5", "6", "10") and self.chunk <= 0:
            raise RallError("The chunk (stripe) size must be positive")
        member -= member % max(1, self.chunk)
        if lv == "jbod":
            if missing:
                raise RallError("A JBOD/span can't be read with a member missing")
            total = sum(sizes)
        elif lv == "0":
            if missing:
                raise RallError("RAID 0 has no redundancy: every member is needed")
            total = member * self.n
        elif lv == "1":
            total = member
        elif lv == "10":
            total = member * self.n // self.copies
        elif lv == "5":
            if self.n < 3:
                raise RallError("RAID 5 needs at least 3 members")
            if missing > 1:
                raise RallError("RAID 5 can be read with one member missing, not more")
            total = member * (self.n - 1)
        elif lv == "6":
            if self.n < 4:
                raise RallError("RAID 6 needs at least 4 members")
            if missing > 1:
                raise RallError("RAID 6 can be read here with at most one member missing")
            total = member * (self.n - 2)
        else:
            raise RallError(f"Unknown RAID level {level}")
        self.size = min(total, size) if size else total
        self.member_size = member

    # ------------------------------------------------------------------ factories
    @classmethod
    def from_definition(cls, d: dict) -> RaidSource:
        members: list[Source | None] = []
        offsets = []
        for m in d.get("members") or []:
            if not m:
                members.append(None)
                offsets.append(0)
                continue
            path = m.get("path") if isinstance(m, dict) else str(m)
            try:
                members.append(open_source(path))
            except RallError:
                if d.get("strict"):
                    raise
                members.append(None)
            offsets.append(int(m.get("offset") or 0) if isinstance(m, dict) else 0)
        src = cls(members, str(d.get("level") or "0"), int(d.get("chunk") or 65536), d.get("layout") or "left-symmetric",
                  offsets, int(d.get("size") or 0), int(d.get("copies") or 2), d.get("name") or "Virtual RAID")
        src.path = d.get("file") or ""
        return src

    @classmethod
    def from_file(cls, path: str) -> RaidSource:
        try:
            d = json.loads(Path(path).read_text())
        except (OSError, ValueError) as exc:
            raise RallError(f"{path}: not a RAID definition ({exc})") from exc
        d["file"] = os.path.abspath(path)
        return cls.from_definition(d)

    def close(self) -> None:
        for m in self.members:
            if m is not None:
                m.close()

    def describe(self) -> dict:
        d = super().describe()
        d.update(level=self.level, chunk=self.chunk, layout=self.layout, members=self.n)
        return d

    # ------------------------------------------------------------------ reading
    def _member_read(self, idx: int, offset: int, length: int) -> bytes | None:
        m = self.members[idx]
        if m is None:
            return None
        return m.read(self.offsets[idx] + offset, length)

    def _read(self, offset: int, length: int) -> bytes:
        lv = self.level
        if lv == "jbod":
            return self._read_jbod(offset, length)
        if lv == "1":
            for i in range(self.n):
                d = self._member_read(i, offset, length)
                if d is not None:
                    return d
            return bytes(length)
        out = bytearray()
        pos = offset
        end = offset + length
        c = self.chunk
        while pos < end:
            k, rel = divmod(pos, c)
            take = min(c - rel, end - pos)
            out += self._chunk(k, rel, take)
            pos += take
        return bytes(out)

    def _read_jbod(self, offset: int, length: int) -> bytes:
        out = bytearray()
        pos = offset
        end = offset + length
        base = 0
        for i, m in enumerate(self.members):
            msize = m.size - self.offsets[i]
            if pos < base + msize and pos < end:
                rel = pos - base
                take = min(msize - rel, end - pos)
                out += m.read(self.offsets[i] + rel, take)
                pos += take
            base += msize
        return bytes(out)

    def locate(self, k: int) -> tuple[int, int, int | None, int | None]:
        """Logical chunk K → (member index, row, parity member, Q member)."""
        n = self.n
        lv = self.level
        if lv == "0":
            return k % n, k // n, None, None
        if lv == "10":
            first = k * self.copies
            return first % n, first // n, None, None
        data = n - (1 if lv == "5" else 2)
        row, i = divmod(k, data)
        left = self.layout.startswith("left")
        pd = (n - 1) - (row % n) if left else row % n
        if lv == "5":
            if self.layout.endswith("asymmetric"):
                dd = i if i < pd else i + 1
            else:
                dd = (pd + 1 + i) % n
            return dd, row, pd, None
        qd = (pd + 1) % n
        dd = (pd + 2 + i) % n
        return dd, row, pd, qd

    def _chunk(self, k: int, rel: int, take: int) -> bytes:
        dd, row, pd, qd = self.locate(k)
        moff = row * self.chunk + rel
        if self.level == "10":
            for c in range(self.copies):
                idx = (k * self.copies + c) % self.n
                r = (k * self.copies + c) // self.n
                d = self._member_read(idx, r * self.chunk + rel, take)
                if d is not None:
                    return d
            return bytes(take)
        d = self._member_read(dd, moff, take)
        if d is not None:
            return d
        if pd is None:
            return bytes(take)
        # rebuild the missing member's piece from parity: XOR of every other data chunk and P
        pieces = []
        for j in range(self.n):
            if j == dd or j == qd:
                continue
            p = self._member_read(j, moff, take)
            if p is None:
                return bytes(take)
            pieces.append(p)
        return _xor(pieces)


# ---------------------------------------------------------------------- definitions on disk
def save_definition(d: dict, path: str) -> str:
    d = dict(d)
    d["type"] = "raid"
    d.pop("file", None)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=2)
    os.replace(tmp, path)
    return path


def describe_definition(d: dict) -> str:
    lv = LEVELS.get(str(d.get("level")), f"RAID {d.get('level')}")
    n = len(d.get("members") or [])
    missing = sum(1 for m in d.get("members") or [] if not m)
    text = f"{lv}, {n} members"
    if missing:
        text += f" ({missing} missing)"
    if str(d.get("level")) not in ("1", "jbod"):
        text += f", {int(d.get('chunk') or 0) // 1024} KiB chunks"
    if str(d.get("level")) in ("5", "6"):
        text += f", {d.get('layout')}"
    return text


# ---------------------------------------------------------------------- finding the parameters
def from_md(members: list[dict]) -> dict | None:
    """A definition from Linux software-RAID (md) superblocks. MEMBERS: [{"path", "md": {...}}] where md is
    what fsdetect reports for a linux_raid_member (level, raid_disks, chunk, layout, data_offset, role,
    array uuid)."""
    groups: dict[str, list[dict]] = {}
    for m in members:
        md = m.get("md") or {}
        if md.get("uuid"):
            groups.setdefault(md["uuid"], []).append(m)
    if not groups:
        return None
    uuid, ms = max(groups.items(), key=lambda kv: len(kv[1]))
    md0 = ms[0]["md"]
    n = int(md0.get("raid_disks") or len(ms))
    slots: list[dict | None] = [None] * n
    for m in ms:
        role = m["md"].get("role")
        if isinstance(role, int) and 0 <= role < n:
            slots[role] = {"path": m["path"], "offset": int(m["md"].get("data_offset") or 0)}
    level = str(md0.get("level") or "").replace("raid", "")
    layout = {0: "left-asymmetric", 1: "right-asymmetric", 2: "left-symmetric", 3: "right-symmetric"}.get(
        md0.get("layout") if isinstance(md0.get("layout"), int) else -1, "left-symmetric")
    copies = 2
    if level == "10" and isinstance(md0.get("layout"), int):
        copies = md0["layout"] & 0xFF or 2
    return {"type": "raid", "name": md0.get("name") or f"md {uuid[:8]}", "level": level, "chunk":
            int(md0.get("chunk") or 65536), "layout": layout, "copies": copies, "members": slots,
            "size": int(md0.get("array_size") or 0), "uuid": uuid}


def _volumes(src: Source) -> list[tuple[Source, dict]]:
    """The filesystems a candidate array seems to hold: those of its partitions, or one at its start."""
    from . import fsdetect, partitions
    table = partitions.read_table(src)
    parts = [p for p in table.get("partitions") or [] if p.get("size") and not p.get("extended")]
    out = []
    for p in parts[:4] or [{"start": 0, "size": src.size}]:
        st = int(p["start"])
        if st >= src.size:
            continue
        vol = src.region(st, min(int(p["size"]), src.size - st))
        info = fsdetect.identify(vol)
        if info:
            out.append((vol, info))
    return out


def _table_score(src: Source) -> int:
    from . import partitions
    table = partitions.read_table(src)
    score = 0
    if [p for p in table.get("partitions") or [] if p.get("size")]:
        score += 20
    g = table.get("gpt") or {}
    if g.get("primary_ok") and g.get("backup_ok"):
        score += 30                     # the backup GPT sits in the array's last sector: size and end are right
    return score


def _fat_hits(vol: Source, info: dict) -> int:
    """How well the allocation table hangs together: links to the next cluster (files written in one piece
    make long runs of them, and only the right geometry keeps them in order across chunks), and blocks of
    the first FAT that equal the same blocks of the second copy, which lies far away in other chunks."""
    bps = int(info.get("sector_size") or 512)
    fat = int(info.get("fat_sectors") or 0) * bps
    bits = int(info.get("fat_bits") or 0)
    if fat <= 0 or bits not in (16, 32):
        return 0
    a0 = int(info.get("reserved_sectors") or 0) * bps
    width = bits // 8
    mask = 0x0FFFFFFF if bits == 32 else 0xFFFF
    links = equal = 0
    for pos in range(0, min(fat, 8 * 1024 * 1024), 4096):
        n = min(4096, fat - pos)
        x = vol.read(a0 + pos, n)
        if x.count(0) == n:
            continue
        first = pos // width
        for i in range(0, n - width + 1, width):
            if int.from_bytes(x[i:i + width], "little") & mask == first + i // width + 1:
                links += 1
        if int(info.get("fats") or 0) >= 2:
            equal += 1 if x == vol.read(a0 + fat + pos, n) else -1
    return min(100, links // 32) + max(0, equal)


def _ext_hits(vol: Source, info: dict) -> int:
    """Backup superblocks (same UUID) at the start of block groups, spread over the whole volume."""
    from .fsdetect import parse_ext_super
    bs = int(info.get("block_size") or 4096)
    bpg = int(info.get("blocks_per_group") or 0)
    if bpg <= 0:
        return 0
    first = 1 if bs == 1024 else 0
    hits = 0
    groups = [g for g in (1, 3, 5, 7, 9, 25, 27, 49, 81, 125, 243, 343, 625, 729, 2187, 2401)
              if (g * bpg + first) * bs + 1024 <= vol.size]
    for g in groups[:12]:
        sb = parse_ext_super(vol.read((g * bpg + first) * bs, 1024))
        if sb and sb.get("uuid") == info.get("uuid"):
            hits += 10
    return hits


def _xfs_hits(vol: Source, info: dict) -> int:
    """The headers of every allocation group: superblock, AGF and AGI."""
    raw = vol.read(0, 512)
    if raw[:4] != b"XFSB":
        return 0
    bs = int.from_bytes(raw[4:8], "big")
    agblocks = int.from_bytes(raw[84:88], "big")
    agcount = int.from_bytes(raw[88:92], "big")
    sect = int.from_bytes(raw[102:104], "big") or 512
    hits = 0
    for ag in range(1, min(agcount, 16)):
        at = ag * agblocks * bs
        if at + 3 * sect > vol.size:
            break
        hits += 4 * (vol.read(at, 4) == b"XFSB") + 3 * (vol.read(at + sect, 4) == b"XAGF") + \
            3 * (vol.read(at + 2 * sect, 4) == b"XAGI")
    return hits


def _mft_runs(data: bytes) -> int:
    """MFT records (1 KiB) whose record numbers follow each other."""
    hits = 0
    pos = data.find(b"FILE0")
    prev = None
    while pos >= 0 and hits < 2000:
        if pos % 1024 == 0 and pos + 0x30 <= len(data):
            num = int.from_bytes(data[pos + 0x2C:pos + 0x30], "little")
            if prev is not None and num == prev[1] + (pos - prev[0]) // 1024:
                hits += 1
            prev = (pos, num)
        pos = data.find(b"FILE0", pos + 1)
    return hits


def _ntfs_hits(vol: Source, info: dict) -> int:
    boot = vol.read(0, 512)
    bps = int.from_bytes(boot[11:13], "little") or 512
    spc = boot[13]
    cs = bps * (spc if spc <= 128 else 1 << (256 - spc))
    mft = int.from_bytes(boot[48:56], "little") * cs
    hits = 0
    if 0 < mft < vol.size:
        hits += _mft_runs(vol.read(mft, 4 * 1024 * 1024))
    total = int.from_bytes(boot[40:48], "little") * bps
    if 0 < total < vol.size and vol.read(total, 512)[3:11] == b"NTFS    ":
        hits += 20                      # the backup boot sector, at the other end of the volume
    return hits


def _hfs_hits(vol: Source, info: dict) -> int:
    size = int(info.get("size") or 0)
    if 2048 < size <= vol.size and vol.read(size - 1024, 2) in (b"H+", b"HX"):
        return 20                       # the alternate volume header
    return 0


_DEEP = {"fat12": _fat_hits, "fat16": _fat_hits, "fat32": _fat_hits, "ext2": _ext_hits, "ext3": _ext_hits,
         "ext4": _ext_hits, "xfs": _xfs_hits, "ntfs": _ntfs_hits, "hfsplus": _hfs_hits, "hfsx": _hfs_hits}


def _score(src: Source) -> int:
    """How much a candidate array looks like a real disk: a partition table (and its backup at the very
    end), filesystems where it says, and structures that only line up across many chunks with the right
    member order, chunk size and layout: the two FAT copies agreeing, ext and XFS backup superblocks where
    they belong, NTFS MFT records numbered in order, backup boot sectors at the end of the volume."""
    score = 0
    try:
        score += _table_score(src)
        for vol, info in _volumes(src):
            score += 40
            fn = _DEEP.get(info.get("fstype") or "")
            if fn is not None:
                try:
                    score += fn(vol, info)
                except Exception:  # noqa: BLE001 - garbage in a wrong guess
                    pass
    except Exception:  # noqa: BLE001 - a wrong guess reads garbage
        pass
    return score


def _magic_table() -> dict[str, list[tuple[int, bytes]]]:
    try:
        from .carve import FORMATS
    except ImportError:
        return {}
    out: dict[str, list[tuple[int, bytes]]] = {}
    for f in FORMATS:
        if not f.magic:
            continue
        for ext in f.exts:
            out.setdefault(ext.lower(), []).extend((int(o), bytes(m)) for o, m in f.magic)
    return out


def _content_score(src: Source, limit: int = 400) -> int:
    """Files whose first bytes match what their extension promises (JPEG, PDF, ZIP, MP4...): their content
    lies all over the array, so only the right geometry gets many of them right."""
    from .filetypes import extension
    from .fs import open_reader, read_head
    magic = _magic_table()
    score = 0
    try:
        for vol, info in _volumes(src):
            reader = open_reader(vol, info.get("fstype"))
            if reader is None:
                continue
            checked = 0
            for e in reader.entries(deleted=False):
                if e.is_dir or e.size < 64 or e.deleted:
                    continue
                sigs = magic.get(extension(e.name))
                if not sigs:
                    continue
                head = read_head(vol, e, 64)
                checked += 1
                if any(head[o:o + len(m)] == m for o, m in sigs):
                    score += 5
                if checked >= limit:
                    break
    except Exception:  # noqa: BLE001 - garbage
        pass
    return score


def _parity_holds(sources: list[Source], samples: int = 16) -> bool:
    """Whether the members XOR to zero (RAID 5 with every member present, whatever the order and layout)."""
    size = min(s.size for s in sources)
    if size < 4096 or len(sources) < 3:
        return False
    nonzero = 0
    for k in range(samples):
        at = (size // samples * k) // 4096 * 4096
        blocks = [s.read(at, 4096) for s in sources]
        if any(b.count(0) != 4096 for b in blocks):
            nonzero += 1
            if _xor(blocks).count(0) != 4096:
                return False
    return nonzero > 0


def detect(paths: list[str], levels=None, chunks=CHUNKS, missing: int = 0, max_tries: int = 6000,
           ctl=None) -> list[dict]:
    """Try member orders, chunk sizes and layouts (and, with MISSING members lost, where they were); the
    best-scoring definitions first. Works best when the array holds a partition table or NTFS, FAT, ext or
    XFS, and many files with recognizable content."""
    sources: list[Source] = [FileSource(p) for p in paths]
    n = len(sources) + missing
    if levels is None:
        levels = ("5", "6") if missing else ("0", "5", "6", "10", "1")
    results = []
    tries = 0
    try:
        parity = not missing and _parity_holds(sources)
        for level in levels:
            if missing and level not in ("5", "6"):
                continue
            if level == "6" and (n < 4 or parity):
                continue
            if level == "5" and n < 3:
                continue
            if level == "0" and parity:
                continue                 # members that XOR to zero hold parity: it isn't a plain stripe
            layouts = LAYOUTS5 if level == "5" else LAYOUTS6 if level == "6" else ("",)
            seen = set()
            for order in itertools.permutations(range(n)):
                key = tuple(i if i < len(sources) else -1 for i in order)
                if key in seen:
                    continue
                seen.add(key)
                if level == "1" and key != tuple(sorted(key)):
                    continue             # every member holds everything: the order doesn't matter
                for chunk in (chunks if level != "1" else (65536,)):
                    for layout in layouts:
                        tries += 1
                        if tries > max_tries:
                            break
                        if ctl is not None:
                            ctl.check()
                            if tries % 50 == 0:
                                ctl.progress(None, f"Tried {tries} combinations")
                        members = [sources[i] if i >= 0 else None for i in key]
                        try:
                            src = RaidSource(members, level, chunk, layout or "left-symmetric")
                        except RallError:
                            continue
                        sc = _score(src)
                        if parity and level == "5":
                            sc += 30
                        if sc > 0:
                            results.append({"score": sc, "level": level, "chunk": chunk, "layout": layout or "",
                                            "members": [{"path": paths[i], "offset": 0} if i >= 0 else None
                                                        for i in key]})
        # the files' content tells apart what the structures couldn't (only for the best ones: it's slower)
        results.sort(key=lambda r: -r["score"])
        best = results[0]["score"] if results else 0
        top = [r for r in results if r["score"] >= best * 0.75][:150]
        for r in top:
            if ctl is not None:
                ctl.check()
            members = [FileSource(m["path"]) if m else None for m in r["members"]]
            try:
                src = RaidSource(members, r["level"], r["chunk"], r["layout"] or "left-symmetric")
                r["score"] += _content_score(src, limit=80)
            except RallError:
                pass
            finally:
                for m in members:
                    if m is not None:
                        m.close()
    finally:
        for s in sources:
            s.close()
    order = {lv: i for i, lv in enumerate(("5", "6", "0", "10", "1", "jbod"))}
    lay = {lv: i for i, lv in enumerate(LAYOUTS5)}
    # ties: the smallest chunk that keeps everything consistent, the commonest layout (left-symmetric)
    results.sort(key=lambda r: (-r["score"], r["chunk"], lay.get(r["layout"], 9), order.get(r["level"], 9)))
    return results[:10]
