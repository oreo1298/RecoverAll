"""exFAT: the filesystem of SDXC cards, big USB sticks and drives shared between Windows and Macs.

On disk: a main boot region (boot sector, extended boot sectors, OEM parameters, and a checksum sector that
covers the other eleven) and an identical backup region right after it (sectors 12-23); the FAT (one 32-bit
entry per cluster, used only for files whose clusters aren't contiguous); then the cluster heap. Which clusters
are in use is kept in the allocation bitmap, a system file the root folder points at (as it does at the
up-case table and the volume label). A folder is an array of 32-byte entries, each file being an entry set: a
File entry (attributes and times with 10 ms and time-zone fields), a Stream Extension entry (first cluster,
sizes, and the NoFatChain flag that says the file is contiguous and the FAT has nothing for it), and File Name
entries of 15 UTF-16 characters each, all protected by a checksum.

Deleting a file clears the "in use" bit of each entry's type (0x85, 0xC0, 0xC1 become 0x05, 0x40, 0x41) and its
clusters' bits in the bitmap; name, size, first cluster and the NoFatChain flag stay. So a contiguous deleted
file (most files on a camera card) is found exactly; for a fragmented one the FAT chain is used when it still
matches the size, otherwise it is assumed contiguous. Chances come from the bitmap: clusters still free mean the
data is very likely intact.
"""

from __future__ import annotations

import re
import struct
import sys
from array import array
from collections import deque
from dataclasses import dataclass
from typing import Iterator

from ..blockio import CachedSource, Source
from ..errors import Cancelled, FormatError
from .base import (
    CHANCE_FAIR,
    CHANCE_GOOD,
    CHANCE_POOR,
    F_PARTIAL,
    F_SYSTEM,
    NULL_CONTROL,
    Control,
    Entry,
    FsReader,
    dos_datetime,
)

MiB = 1024 * 1024

T_BITMAP = 0x81
T_UPCASE = 0x82
T_LABEL = 0x83
T_FILE = 0x85
T_GUID = 0xA0
T_STREAM = 0xC0
T_NAME = 0xC1
IN_USE = 0x80

ATTR_DIR = 0x10
FAT_BAD = 0xFFFFFFF7
FAT_END = 0xFFFFFFF8               # 0xFFFFFFF8..0xFFFFFFFF: end of the chain
MAX_DIR_BYTES = 256 * MiB          # the format's limit for one folder
MAX_DEPTH = 256
_FAT_PAGE = 1 << 18                # FAT entries per page read on demand (1 MiB)



# ---------------------------------------------------------------------- boot region
def parse_boot(buf: bytes) -> dict | None:
    """The geometry in an exFAT boot sector (the first 512 bytes), or None when BUF isn't one."""
    if len(buf) < 512 or bytes(buf[3:11]) != b"EXFAT   ":
        return None
    if any(buf[11:64]):
        return None
    (_part_off, vol_len, fat_off, fat_len, heap_off, count, root, serial, rev, flags, bps_shift, spc_shift,
     nfats, _drive, pct) = struct.unpack_from("<QQIIIIIIHHBBBBB", buf, 64)
    if not 9 <= bps_shift <= 12 or spc_shift > 25 - bps_shift or nfats not in (1, 2):
        return None
    bps = 1 << bps_shift
    cs = bps << spc_shift
    if fat_off < 24 or not fat_len or heap_off < fat_off + fat_len * nfats or not count or not vol_len:
        return None
    count = min(count, (fat_len * bps) // 4 - 2, 0xFFFFFFF5)
    if count < 1 or not 2 <= root <= count + 1:
        return None
    if heap_off >= vol_len:
        return None
    return {
        "fstype": "exfat", "label": "", "uuid": f"{serial >> 16:04X}-{serial & 0xFFFF:04X}", "serial": serial,
        "size": vol_len * bps, "block_size": cs, "cluster_size": cs, "bytes_per_sector": bps,
        "sectors_per_cluster": 1 << spc_shift, "fat_offset": fat_off * bps, "fat_bytes": fat_len * bps,
        "heap_offset": heap_off * bps, "clusters": count, "root_cluster": root, "fats": nfats,
        "active_fat": (flags & 1) + 1 if nfats == 2 else 1, "volume_flags": flags,
        "version": f"{rev >> 8}.{rev & 0xFF:02d}", "percent_in_use": pct if pct <= 100 else None,
    }


def boot_checksum(region: bytes, bps: int) -> int:
    """The checksum of the first eleven sectors of a boot region (VolumeFlags and PercentInUse excluded)."""
    cs = 0
    data = region[:11 * bps]
    for i, b in enumerate(data):
        if i == 106 or i == 107 or i == 112:
            continue
        cs = (((cs << 31) | (cs >> 1)) + b) & 0xFFFFFFFF
    return cs


def _region_ok(src: Source, base: int, info: dict) -> bool:
    bps = info["bytes_per_sector"]
    region = src.read(base, 12 * bps)
    want = boot_checksum(region, bps)
    sums = struct.unpack_from(f"<{bps // 4}I", region, 11 * bps)
    return all(v == want for v in sums)


def entry_set_checksum(data: bytes) -> int:
    """The checksum of a directory entry set (its own field, bytes 2-3, excluded)."""
    cs = 0
    for i, b in enumerate(data):
        if i == 2 or i == 3:
            continue
        cs = (((cs << 15) | (cs >> 1)) + b) & 0xFFFF
    return cs


def exfat_time(ts: int, ms10: int = 0, utc: int = 0) -> float | None:
    """An exFAT timestamp (DOS date/time, 10 ms increments, UTC offset in 15-minute steps when bit 7 of UTC
    is set; local time of an unknown zone otherwise, taken as UTC) → Unix time."""
    offset = 0.0
    if utc & 0x80:
        v = utc & 0x7F
        if v & 0x40:
            v -= 0x80
        offset = v * 15 * 60.0
    return dos_datetime(ts >> 16, ts & 0xFFFF, ms10 if ms10 < 200 else 0, offset)


class BitmapMap:
    """Which clusters are in use, straight from the allocation bitmap (bit k = cluster k + 2): the questions
    chance estimates ask, answered with byte operations so a bitmap of hundreds of millions of clusters needs
    no more memory than itself."""

    _RUNS = re.compile(rb"\x00+|\xff+|[^\x00\xff]")

    def __init__(self, bitmap: bytes, count: int):
        nbytes = (count + 7) // 8
        bm = bytearray(bitmap[:nbytes].ljust(nbytes, b"\xff"))     # what the bitmap doesn't cover: in use
        if count % 8:
            bm[-1] |= 0xFF & ~((1 << (count % 8)) - 1)
        self.bm = bytes(bm)
        self.count = count
        self.first = 2
        self.last = count + 1

    def is_free(self, c: int) -> bool:
        k = c - 2
        return 0 <= k < self.count and not (self.bm[k >> 3] >> (k & 7)) & 1

    def _range(self, c: int, n: int) -> tuple[int, int] | None:
        if n <= 0 or c < 2 or c + n - 1 > self.last:
            return None
        return c - 2, c - 2 + n

    def count_used(self, c: int, n: int) -> int:
        c2 = min(c + n, self.last + 1)
        c = max(c, 2)
        if c2 <= c:
            return 0
        k0, k1 = c - 2, c2 - 2
        a, b = k0 >> 3, k1 >> 3
        bm = self.bm
        if a == b:
            return ((bm[a] >> (k0 & 7)) & ((1 << (k1 - k0)) - 1)).bit_count()
        used = (bm[a] >> (k0 & 7)).bit_count() + int.from_bytes(bm[a + 1:b], "little").bit_count()
        if k1 & 7:
            used += (bm[b] & ((1 << (k1 & 7)) - 1)).bit_count()
        return used

    def all_free(self, c: int, n: int) -> bool:
        r = self._range(c, n)
        if r is None:
            return False
        k0, k1 = r
        a, b = k0 >> 3, k1 >> 3
        bm = self.bm
        if a == b:
            return not (bm[a] >> (k0 & 7)) & ((1 << (k1 - k0)) - 1)
        if bm[a] >> (k0 & 7) or bm.count(0, a + 1, b) != b - a - 1:
            return False
        return not (k1 & 7) or not bm[b] & ((1 << (k1 & 7)) - 1)

    def free_runs(self) -> Iterator[tuple[int, int]]:
        """(first cluster, count) of every run of free clusters."""
        start = -1                                   # bit where the current free run began
        for m in self._RUNS.finditer(self.bm):
            a = m.start()
            v = self.bm[a]
            if v == 0:
                if start < 0:
                    start = a * 8
                continue
            if v == 0xFF:
                if start >= 0:
                    yield start + 2, a * 8 - start
                    start = -1
                continue
            for bit in range(8):
                k = a * 8 + bit
                if (v >> bit) & 1:
                    if start >= 0:
                        yield start + 2, k - start
                        start = -1
                elif start < 0:
                    start = k
        if start >= 0:
            yield start + 2, min(len(self.bm) * 8, self.count) - start

    def free_count(self) -> int:
        return self.count - self.count_used(2, self.count)


@dataclass(slots=True)
class ExRecord:
    """One file or folder (an entry set) found in a directory."""
    slot: int
    name: str
    attr: int
    cluster: int
    size: int
    valid_size: int
    no_fat_chain: bool
    deleted: bool
    checksum_ok: bool | None
    crtime: float | None
    mtime: float | None
    atime: float | None

    @property
    def is_dir(self) -> bool:
        return bool(self.attr & ATTR_DIR)


def parse_directory(buf: bytes, deleted: bool = True) -> tuple[list[ExRecord], dict]:
    """Every file and folder in the raw directory BUF (deleted ones too when DELETED), and the system entries:
    {"label", "bitmaps": [(flags, cluster, length, slot)], "upcase": (cluster, length, slot), "invalid",
    "end"}."""
    recs: list[ExRecord] = []
    facts: dict = {"label": None, "bitmaps": [], "upcase": None, "invalid": 0, "end": False}
    n = len(buf) // 32
    i = 0
    while i < n:
        o = i * 32
        t = buf[o]
        if t == 0:
            facts["end"] = True
            break
        if t == T_FILE or (t == T_FILE & 0x7F and deleted):
            rec, used = _parse_set(buf, i, n, t == T_FILE)
            if rec is None:
                facts["invalid"] += 1
                i += 1
                continue
            recs.append(rec)
            i += used
            continue
        if t == T_BITMAP:
            flags = buf[o + 1]
            first, length = struct.unpack_from("<IQ", buf, o + 20)
            facts["bitmaps"].append((flags, first, length, i))
        elif t == T_UPCASE:
            first, length = struct.unpack_from("<IQ", buf, o + 20)
            facts["upcase"] = (first, length, i)
        elif t == T_LABEL:
            k = min(buf[o + 1], 11)
            facts["label"] = bytes(buf[o + 2:o + 2 + 2 * k]).decode("utf-16-le", "replace")
        i += 1
    return recs, facts


def _parse_set(buf: bytes, i: int, n: int, live: bool) -> tuple[ExRecord | None, int]:
    """The entry set whose File entry is slot I: (record, slots used) or (None, 0) when it isn't one.

    A live set must be complete. A deleted one is taken as far as its entries are still deleted entries of
    the right types (a newer set may have overwritten its end); its checksum is checked with the in-use bits
    put back, but a mismatch doesn't reject it."""
    o = i * 32
    secondary = buf[o + 1]
    if not 2 <= secondary <= 18 or i + 1 >= n:
        return None, 0
    stream_t, name_t = (T_STREAM, T_NAME) if live else (T_STREAM & 0x7F, T_NAME & 0x7F)
    so = o + 32
    if buf[so] != stream_t:
        return None, 0
    flags = buf[so + 1]
    name_len = buf[so + 3]
    valid, = struct.unpack_from("<Q", buf, so + 8)
    first, size = struct.unpack_from("<IQ", buf, so + 20)
    if not name_len:
        return None, 0
    need = min(secondary - 1, (name_len + 14) // 15)
    chars = bytearray()
    used = 2
    while used - 2 < need and i + used < n and buf[(i + used) * 32] == name_t:
        p = (i + used) * 32
        chars += buf[p + 2:p + 32]
        used += 1
    if live and used - 2 < need:
        return None, 0
    if live:
        used = 1 + secondary if i + 1 + secondary <= n else used
    else:
        # vendor extensions may follow the name: take them too while they're deleted secondary entries
        while used < 1 + secondary and i + used < n and buf[(i + used) * 32] & 0xC0 == 0x40:
            used += 1
    name = bytes(chars[:2 * name_len]).decode("utf-16-le", "replace")
    if len(name) < name_len:
        name += "~"                       # the end of the name was overwritten
    name = name.replace("/", "_").replace("\x00", "_") or "~"
    checksum_ok = None
    if not live and used == 1 + secondary:
        raw = bytearray(buf[o:o + 32 * used])
        for k in range(used):
            raw[32 * k] |= IN_USE
        checksum_ok = entry_set_checksum(raw) == struct.unpack_from("<H", buf, o + 2)[0]
    attr, _res, cts, mts, ats, c10, m10, cutc, mutc, autc = struct.unpack_from("<HHIIIBBBBB", buf, o + 4)
    if not flags & 1:                     # no allocation: first cluster and size mean nothing
        first = 0
        if not attr & ATTR_DIR:
            size = valid = 0
    is_dir = bool(attr & ATTR_DIR)
    return ExRecord(
        slot=i, name=name, attr=attr, cluster=first, size=size, valid_size=min(valid, size),
        no_fat_chain=bool(flags & 2), deleted=not live, checksum_ok=checksum_ok,
        crtime=exfat_time(cts, c10, cutc), mtime=exfat_time(mts, m10, mutc), atime=exfat_time(ats, 0, autc),
    ) if not (is_dir and size > MAX_DIR_BYTES and live) else None, used


# ---------------------------------------------------------------------- the reader
class ExfatReader(FsReader):
    """exFAT: live and deleted files and folders; chances from the allocation bitmap."""

    fstype = "exfat"
    name = "exFAT"
    root_key = 0

    def __init__(self, src: Source, info: dict | None = None):
        super().__init__(src, info)
        if "heap_offset" not in self.info:
            probed = self.probe(src)
            if probed is None:
                raise FormatError("This isn't an exFAT filesystem, or both of its boot regions are damaged")
            probed.update(self.info)          # only overrides here: the geometry comes from the boot region
            self.info = probed
        i = self.info
        self.cs = int(i["cluster_size"])
        self.block_size = self.cs
        self.heap_offset = int(i["heap_offset"])
        self.clusters = int(i["clusters"])
        self.volume_bytes = int(i.get("size") or self.heap_offset + self.clusters * self.cs)
        fits = max(1, (src.size - self.heap_offset) // self.cs)
        if self.clusters > fits:
            # clusters past the end can't be read anyway; and a damaged boot sector mustn't make us allocate
            # gigabytes for a bitmap that isn't there
            self.warn("The filesystem is bigger than the disk or partition holding it: its end is missing.")
            self.clusters = fits
        self.max_cluster = self.clusters + 1
        self.root_cluster = int(i["root_cluster"])
        self.label = i.get("label") or ""
        active = int(i.get("active_fat") or 1)
        self.fat_base = int(i["fat_offset"]) + (active - 1) * int(i["fat_bytes"])
        self.meta = CachedSource(src, block=64 * 1024, blocks=1024)
        self._fat_pages: dict[int, memoryview | array] = {}
        self.map: BitmapMap | None = None
        self._map_loaded = False
        self._dir_clusters: set[int] = set()
        self._dir_done: set[int] = set()
        self._broken_chains = 0

    # ------------------------------------------------------------------ probing
    @classmethod
    def probe(cls, src: Source) -> dict | None:
        main = parse_boot(src.read(0, 512))
        candidates = []
        if main is not None:
            candidates.append((main, 0, "main"))
        for bps in ([main["bytes_per_sector"]] if main else []) + [512, 4096, 1024, 2048]:
            backup = parse_boot(src.read(12 * bps, 512))
            if backup is not None and backup["bytes_per_sector"] == bps:
                candidates.append((backup, 12 * bps, "backup"))
                break
        if not candidates:
            return None
        info = None
        for cand, base, which in candidates:
            if _region_ok(src, base, cand):
                info = dict(cand, boot=which, checksum_ok=True)
                break
        if info is None:
            cand, _base, which = candidates[0]
            info = dict(cand, boot=which, checksum_ok=False)
        try:
            cls._probe_root(src, info)
        except Exception:  # noqa: BLE001 - a damaged root only costs the label and usage
            pass
        return info

    @staticmethod
    def _probe_root(src: Source, info: dict) -> None:
        """Label, and used/free from the allocation bitmap when it's small (else from PercentInUse)."""
        cs = info["cluster_size"]
        root = info["root_cluster"]
        buf = src.read(info["heap_offset"] + (root - 2) * cs, min(cs, 256 * 1024))
        _recs, facts = parse_directory(buf, deleted=False)
        if facts["label"]:
            info["label"] = facts["label"]
        count = info["clusters"]
        for flags, first, length, _slot in facts["bitmaps"]:
            if flags & 1 != (info["active_fat"] - 1) or not 2 <= first <= count + 1:
                continue
            nbytes = (count + 7) // 8
            if nbytes <= 8 * MiB and length >= nbytes:
                bm = bytearray(src.read(info["heap_offset"] + (first - 2) * cs, nbytes))
                if count % 8:
                    bm[-1] &= (1 << (count % 8)) - 1
                used = int.from_bytes(bm, "little").bit_count()
                info["used"] = used * cs
                info["free"] = (count - used) * cs
                return
        if info.get("percent_in_use") is not None:
            info["used"] = count * cs * info["percent_in_use"] // 100
            info["free"] = count * cs - info["used"]

    # ------------------------------------------------------------------ FAT and bitmap
    def cluster_offset(self, c: int) -> int:
        return self.heap_offset + (c - 2) * self.cs

    def next_cluster(self, c: int) -> int:
        """The FAT entry of cluster C (read a megabyte at a time, on demand)."""
        if not 0 <= c <= self.max_cluster:
            return 0
        page = c // _FAT_PAGE
        entries = self._fat_pages.get(page)
        if entries is None:
            n = min(_FAT_PAGE, self.max_cluster + 1 - page * _FAT_PAGE)
            raw = self.src.read(self.fat_base + page * _FAT_PAGE * 4, n * 4)
            if sys.byteorder == "little" and struct.calcsize("I") == 4:
                entries = memoryview(raw).cast("I")
            else:
                entries = array("I" if struct.calcsize("I") == 4 else "L", struct.unpack(f"<{n}I", raw))
            self._fat_pages[page] = entries
        k = c - page * _FAT_PAGE
        return entries[k] if k < len(entries) else 0

    def chain(self, start: int, limit: int) -> tuple[list[list[int]], int, str]:
        """The FAT chain from START as runs [[first, count], ...] (at most LIMIT clusters), its length, and
        why it stopped: "end", "limit", "bad", "range" or "loop"."""
        runs: list[list[int]] = []
        total = 0
        c = start
        jumps = {start}
        reason = "limit"
        maxc = self.max_cluster
        while total < limit:
            if not 2 <= c <= maxc:
                reason = "range"
                break
            if runs and runs[-1][0] + runs[-1][1] == c:
                runs[-1][1] += 1
            else:
                runs.append([c, 1])
            total += 1
            nxt = self.next_cluster(c)
            if nxt >= FAT_END:
                reason = "end"
                break
            if nxt == FAT_BAD:
                reason = "bad"
                break
            if not 2 <= nxt <= maxc:
                reason = "range"
                break
            if nxt != c + 1:
                if nxt in jumps:
                    reason = "loop"
                    break
                jumps.add(nxt)
            c = nxt
        return runs, total, reason

    def _clusters_of(self, first: int, size: int, no_fat_chain: bool) -> tuple[list, str]:
        need = max(1, -(-size // self.cs))
        if no_fat_chain:
            n = min(need, self.max_cluster + 1 - first) if 2 <= first <= self.max_cluster else 0
            return ([[first, n]] if n > 0 else []), ("end" if n == need else "range")
        runs, total, reason = self.chain(first, need)
        return runs, ("end" if total >= need else reason)

    def load_bitmap(self, ctl: Control = NULL_CONTROL) -> None:
        """Read the allocation bitmap the root folder points at, for chances and free space."""
        if self._map_loaded:
            return
        self._map_loaded = True
        buf, _clusters = self._read_dir(self.root_cluster, None, False, root=True)
        _recs, facts = parse_directory(buf, deleted=False)
        if facts["label"] and not self.label:
            self.label = facts["label"]
        active = int(self.info.get("active_fat") or 1) - 1
        bitmaps = [b for b in facts["bitmaps"] if b[0] & 1 == active] or facts["bitmaps"]
        nbytes = (self.clusters + 7) // 8
        for _flags, first, length, _slot in bitmaps:
            if not 2 <= first <= self.max_cluster or length < nbytes:
                continue
            runs, how = self._clusters_of(first, nbytes, False)
            if how != "end":
                runs, how = self._clusters_of(first, nbytes, True)
            if how != "end":
                continue
            raw = bytearray()
            for c, n in runs:
                ctl.check()
                raw += self.src.read(self.cluster_offset(c), n * self.cs)
            self.map = BitmapMap(bytes(raw[:nbytes]), self.clusters)
            return
        self.warn("The allocation bitmap is missing or damaged: free space and chances are unknown.")

    def free_extents(self, ctl: Control = NULL_CONTROL) -> list[tuple[int, int]] | None:
        self.load_bitmap(ctl)
        if self.map is None:
            return None
        return [(self.cluster_offset(c), n * self.cs) for c, n in self.map.free_runs()]

    def allocated(self, offset: int, length: int) -> bool | None:
        """Whether any cluster of the byte range is in use (None when the bitmap is unknown)."""
        self.load_bitmap()
        if self.map is None or length <= 0:
            return None if self.map is None else False
        c1 = max(2, (offset - self.heap_offset) // self.cs + 2)
        c2 = (offset + length - 1 - self.heap_offset) // self.cs + 2
        return self.map.count_used(c1, c2 - c1 + 1) > 0

    # ------------------------------------------------------------------ locating content
    def _byte_runs(self, runs, rec: ExRecord) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        left = rec.valid_size
        for c, n in runs:
            if left <= 0:
                break
            length = min(n * self.cs, left)
            out.append((self.cluster_offset(c), length))
            left -= length
        if rec.valid_size < rec.size:
            out.append((-1, rec.size - rec.valid_size))   # past the valid data length: reads as zeros
        return out

    def _chance_free(self, runs, good: int) -> int:
        if self.map is None:
            return CHANCE_FAIR
        return good if all(self.map.all_free(c, n) for c, n in runs) else CHANCE_POOR

    def _locate(self, rec: ExRecord, gone: bool) -> tuple[list | None, int, int]:
        if rec.size == 0:
            return [], CHANCE_GOOD, 0
        if not 2 <= rec.cluster <= self.max_cluster:
            return None, CHANCE_POOR, F_PARTIAL
        need = -(-rec.size // self.cs)
        runs, how = self._clusters_of(rec.cluster, rec.size, rec.no_fat_chain)
        total = sum(n for _c, n in runs)
        if not gone:
            if how == "end":
                return self._byte_runs(runs, rec), CHANCE_GOOD, 0
            self._broken_chains += 1
            if not runs:
                return None, CHANCE_POOR, F_PARTIAL
            last = runs[-1][0] + runs[-1][1]
            extra = min(need - total, self.max_cluster + 1 - last)
            if extra > 0:
                runs.append([last, extra])
            flags = 0 if total + max(extra, 0) >= need else F_PARTIAL
            return self._byte_runs(runs, rec), CHANCE_FAIR, flags
        if rec.no_fat_chain:
            flags = 0 if total >= need else F_PARTIAL
            return self._byte_runs(runs, rec), self._chance_free(runs, CHANCE_GOOD), flags
        # a fragmented deleted file: its FAT chain is trusted only when it still ends exactly at its size
        if how == "end" and total == need and self.next_cluster(runs[-1][0] + runs[-1][1] - 1) >= FAT_END:
            return self._byte_runs(runs, rec), self._chance_free(runs, CHANCE_GOOD), 0
        n = min(need, self.max_cluster + 1 - rec.cluster)
        runs = [[rec.cluster, n]]
        return self._byte_runs(runs, rec), self._chance_free(runs, CHANCE_FAIR), 0 if n >= need else F_PARTIAL

    # ------------------------------------------------------------------ folders
    def _read_dir(self, first: int, size: int | None, no_fat_chain: bool,
                  root: bool = False) -> tuple[bytes, list[int]]:
        if size is None or root:
            runs, _total, reason = self.chain(first, max(1, MAX_DIR_BYTES // self.cs))
            if root and reason not in ("end", "limit") and not runs:
                self.warn("The root folder's cluster chain is damaged.")
        else:
            runs, how = self._clusters_of(first, min(size, MAX_DIR_BYTES), no_fat_chain)
            if how != "end" and not no_fat_chain:
                # a deleted folder's chain may be gone: assume it was contiguous
                runs, how = self._clusters_of(first, min(size, MAX_DIR_BYTES), True)
        clusters = [c + k for c, n in runs for k in range(n)]
        out = bytearray()
        for c, n in runs:
            out += self.meta.read(self.cluster_offset(c), n * self.cs)
        return bytes(out), clusters

    def _slot_offset(self, clusters: list[int], slot: int) -> int:
        pos = slot * 32
        return self.cluster_offset(clusters[pos // self.cs]) + pos % self.cs

    def entries(self, ctl: Control = NULL_CONTROL, deleted: bool = True) -> Iterator[Entry]:
        self.load_bitmap(ctl)
        yield Entry(key=self.root_key, parent=None, name="", is_dir=True, chance=CHANCE_GOOD,
                    extra={"cluster": self.root_cluster})
        self._dir_clusters = set()
        self._dir_done = set()
        self._broken_chains = 0
        seen = {self.root_key}
        live: deque = deque([(self.root_key, None, 0)])
        dead: deque = deque()
        count = 0
        while live or dead:
            is_dead = not live
            key, rec, depth = (dead if is_dead else live).popleft()
            try:
                if rec is None:
                    buf, clusters = self._read_dir(self.root_cluster, None, False, root=True)
                else:
                    if rec.cluster in self._dir_done or (is_dead and rec.cluster in self._dir_clusters):
                        continue
                    buf, clusters = self._read_dir(rec.cluster, rec.size, rec.no_fat_chain)
                    if is_dead and set(clusters) & self._dir_clusters:
                        clusters = clusters[:next(k for k, c in enumerate(clusters) if c in self._dir_clusters)]
                        buf = buf[:len(clusters) * self.cs]
                self._dir_done.add(clusters[0] if clusters else -1)
                self._dir_clusters.update(clusters)
                recs, facts = parse_directory(buf, deleted)
                if rec is None:
                    if facts["label"] and not self.label:
                        self.label = facts["label"]
                    yield from self._system_entries(facts, clusters, seen)
            except Cancelled:
                raise
            except Exception as exc:  # noqa: BLE001 - one damaged folder must not stop the scan
                self.warn(f"A damaged folder was skipped ({exc.__class__.__name__}).")
                continue
            for r in recs:
                count += 1
                if count % 256 == 0:
                    ctl.check()
                    ctl.progress(None, f"Reading folders: {count} entries")
                if r.size > self.volume_bytes or (is_dead and r.checksum_ok is not True):
                    # bigger than the volume, or inside a deleted folder whose clusters may hold other data
                    # now: an entry set is believed there only with a good checksum
                    continue
                ekey = self._slot_offset(clusters, r.slot)
                if ekey in seen:
                    continue
                seen.add(ekey)
                gone = is_dead or r.deleted
                try:
                    e = self._entry(r, ekey, key, gone)
                except Cancelled:
                    raise
                except Exception:  # noqa: BLE001
                    continue
                if r.is_dir and depth < MAX_DEPTH and 2 <= r.cluster <= self.max_cluster and r.size:
                    (dead if gone else live).append((ekey, r, depth + 1))
                yield e
        if self._broken_chains:
            self.warn(f"{self._broken_chains} files have broken cluster chains: their missing parts are guessed.")

    def _entry(self, r: ExRecord, key, parent, gone: bool) -> Entry:
        extra = {"attr": r.attr, "cluster": r.cluster, "contiguous": r.no_fat_chain}
        if r.checksum_ok is not None:
            extra["checksum_ok"] = r.checksum_ok
        if r.is_dir:
            chance = CHANCE_GOOD
            if gone:
                chance = self._chance_free([[r.cluster, 1]], CHANCE_GOOD) if r.cluster else CHANCE_POOR
            return Entry(key=key, parent=parent, name=r.name, is_dir=True, deleted=gone, mtime=r.mtime,
                         atime=r.atime, crtime=r.crtime, chance=chance, extra=extra)
        runs, chance, flags = self._locate(r, gone)
        return Entry(key=key, parent=parent, name=r.name, size=r.size, deleted=gone, runs=runs, mtime=r.mtime,
                     atime=r.atime, crtime=r.crtime, chance=chance, flags=flags, extra=extra)

    def _system_entries(self, facts: dict, clusters: list[int], seen: set) -> Iterator[Entry]:
        """The allocation bitmap and up-case table, as hidden system files of the root."""
        items = [("$AllocationBitmap" + (f"{k + 1}" if len(facts["bitmaps"]) > 1 else ""), b[1], b[2], b[3])
                 for k, b in enumerate(facts["bitmaps"])]
        if facts["upcase"]:
            items.append(("$UpcaseTable", *facts["upcase"]))
        for name, first, length, slot in items:
            key = self._slot_offset(clusters, slot)
            if key in seen or not 2 <= first <= self.max_cluster or length > self.clusters * self.cs:
                continue
            seen.add(key)
            runs, _total, _reason = self.chain(first, max(1, -(-length // self.cs)))
            byte_runs = []
            left = length
            for c, n in runs:
                k = min(n * self.cs, left)
                byte_runs.append((self.cluster_offset(c), k))
                left -= k
            yield Entry(key=key, parent=self.root_key, name=name, size=length, runs=byte_runs,
                        chance=CHANCE_GOOD, flags=F_SYSTEM, extra={"cluster": first})
