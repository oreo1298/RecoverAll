"""FAT12, FAT16 and FAT32: the filesystem of memory cards, USB sticks, cameras and EFI partitions.

On disk: a boot sector with the BIOS parameter block (BPB: sector and cluster size, reserved sectors, number
and size of the FATs, ...), the reserved area (FAT32 keeps its FSInfo sector and a backup copy of the boot
sector at sector 6 there), the FATs (normally two identical copies of the cluster map: one 12, 16 or 28-bit
entry per cluster holding the next cluster of the file, 0 for free, an end marker for the last one), on
FAT12/16 a fixed-size root directory, then the data area, cut into clusters numbered from 2. A folder is an
array of 32-byte entries: an 8.3 short name, attributes, times, size and first cluster, preceded by "long
file name" (VFAT) entries that hold the real name in UTF-16, 13 characters each.

Deleting a file sets the first byte of its entries to 0xE5 and zeroes its FAT chain. The rest of the entry
(size, first cluster, times, the characters of the long name) stays, so a deleted file's name, size and start
are known but not where the rest of it was: like every FAT undelete tool this reader assumes the file was
contiguous (true for most files written to a fresh card) and rates the guess by whether those clusters are
still free. A deleted file that was fragmented comes back with the wrong data after its first fragment, and
files deleted by Windows on big FAT32 volumes may have lost the high half of their first cluster number
(folders are found again by their "." entry; files can't be).

After a quick format, or when the root folder is destroyed, the old folders still sit in the data area and
every one starts with "." and ".." entries: with ``info["scan_lost_dirs"]`` the reader looks for them and
rebuilds the folder trees it finds ("Folder 1234" when the folder's own name is gone).
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
    F_DIR_RECOVERED,
    F_ORPHAN,
    F_PARTIAL,
    NULL_CONTROL,
    Control,
    Entry,
    FsReader,
    dos_datetime,
)

MiB = 1024 * 1024

ATTR_READONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME = 0x08
ATTR_DIR = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LFN = 0x0F                  # read-only + hidden + system + volume: a long-name piece

DELETED = 0xE5
DOT = b".          "
DOTDOT = b"..         "
MAX_DIR_BYTES = 65536 * 32       # FAT allows 65536 entries per folder
MAX_GUESS_DIR_CLUSTERS = 256     # a deleted folder read by guess (contiguous clusters) stops here
MAX_DEPTH = 256

# Bytes that can't appear in a short name (besides control characters).
_BAD_SHORT = b'"*+,./:;<=>?[\\]|'
_SHORT_OK = bytes(b for b in range(0x20, 256) if b not in _BAD_SHORT)
_NONZERO = bytes([0]) + bytes([1]) * 255            # translate table: 0 → 0, anything else → 1
_LOW_NIBBLE = bytes(b & 0x0F for b in range(256))    # FAT32 entries are 28 bits
_FREE_RUN = re.compile(rb"\x00+")

_SHORT = struct.Struct("<11sBBBHHHHHHHI")


# ---------------------------------------------------------------------- boot sector
def parse_boot(buf: bytes) -> dict | None:
    """The geometry in a FAT boot sector (the first 512 bytes are enough), or None when BUF isn't one.

    The FAT type comes from the number of clusters (Microsoft's rule: under 4085 FAT12, under 65525 FAT16),
    except that a BPB with a zero 16-bit FAT size is FAT32 whatever its size (Linux does the same)."""
    if len(buf) < 512:
        return None
    if buf[510:512] != b"\x55\xaa" and buf[0] not in (0xEB, 0xE9):
        return None
    oem = bytes(buf[3:11])
    if oem in (b"NTFS    ", b"EXFAT   "):
        return None
    bps, spc, reserved, nfats, root_entries, total16, media, fatsz16 = struct.unpack_from("<HBHBHHBH", buf, 11)
    hidden, total32 = struct.unpack_from("<II", buf, 28)
    if bps not in (512, 1024, 2048, 4096):
        return None
    if spc == 0 or spc & (spc - 1) or spc * bps > 256 * 1024:
        return None
    if reserved == 0 or not 1 <= nfats <= 4:
        return None
    if media != 0xF0 and media < 0xF8:
        return None
    total = total16 or total32
    fat32 = fatsz16 == 0
    fatsz = struct.unpack_from("<I", buf, 36)[0] if fat32 else fatsz16
    if not fatsz or not total:
        return None
    root_sectors = 0 if fat32 else (root_entries * 32 + bps - 1) // bps
    data_start = reserved + nfats * fatsz + root_sectors
    if data_start >= total:
        return None
    clusters = (total - data_start) // spc
    if fat32:
        bits = 32
    elif clusters < 4085:
        bits = 12
    else:
        bits = 16
        clusters = min(clusters, 65524)
    capacity = fatsz * bps * 8 // bits          # entries the FAT can hold
    if capacity < 3 or clusters < 1:
        return None
    clusters = min(clusters, capacity - 2, 0x0FFFFFF5)
    info: dict = {
        "fstype": f"fat{bits}", "bits": bits, "oem": oem.decode("ascii", "replace").strip(),
        "bytes_per_sector": bps, "sectors_per_cluster": spc, "cluster_size": bps * spc, "block_size": bps * spc,
        "reserved_sectors": reserved, "fats": nfats, "root_entries": 0 if fat32 else root_entries,
        "total_sectors": total, "fat_sectors": fatsz, "media": media, "hidden_sectors": hidden,
        "fat_offset": reserved * bps, "fat_bytes": fatsz * bps,
        "root_offset": (reserved + nfats * fatsz) * bps, "root_size": root_sectors * bps,
        "data_offset": data_start * bps, "clusters": clusters, "size": total * bps,
        "root_cluster": 0, "fsinfo_sector": 0, "backup_boot_sector": 0, "active_fat": None,
        "version": f"FAT{bits}",
    }
    if fat32:
        ext_flags, _ver, root_cluster, fsinfo, bkboot = struct.unpack_from("<HHIHH", buf, 40)
        info.update(root_cluster=root_cluster, fsinfo_sector=fsinfo, backup_boot_sector=bkboot)
        if ext_flags & 0x80:                      # mirroring off: only one FAT is up to date
            info["active_fat"] = (ext_flags & 0x0F) + 1
        sig_at, serial_at, label_at = 66, 67, 71
    else:
        sig_at, serial_at, label_at = 38, 39, 43
    label = ""
    serial = None
    if buf[sig_at] in (0x28, 0x29):
        serial = struct.unpack_from("<I", buf, serial_at)[0]
        if buf[sig_at] == 0x29:
            label = _decode_short(buf[label_at:label_at + 11]).strip()
            if label.upper() == "NO NAME":
                label = ""
    info["serial"] = serial
    info["uuid"] = f"{serial >> 16:04X}-{serial & 0xFFFF:04X}" if serial is not None else ""
    info["label"] = info["boot_label"] = label
    return info


def _decode_short(raw: bytes, codepage: str = "cp437") -> str:
    try:
        return bytes(raw).decode(codepage, "replace")
    except LookupError:
        return bytes(raw).decode("cp437", "replace")


def lfn_checksum(name11: bytes) -> int:
    """The checksum a long name's pieces carry of the short name they belong to."""
    s = 0
    for c in name11:
        s = ((((s & 1) << 7) | (s >> 1)) + c) & 0xFF
    return s


def lfn_first_char(name11: bytes, checksum: int) -> int:
    """The first byte of a short name whose other ten bytes are known and whose checksum is CHECKSUM.

    Each checksum step is a bijection of the running sum, so exactly one first byte matches: running the steps
    backwards from the checksum gives it. This is how a deleted entry (first byte overwritten with 0xE5) gets
    its real short name back from the long-name pieces in front of it."""
    s = checksum & 0xFF
    for c in reversed(name11[1:11]):
        s = (s - c) & 0xFF
        s = ((s << 1) | (s >> 7)) & 0xFF
    return s


def _lfn_chars(buf: bytes, o: int) -> bytes:
    return bytes(buf[o + 1:o + 11]) + bytes(buf[o + 14:o + 26]) + bytes(buf[o + 28:o + 32])


def _lfn_name(parts: list[bytes], strict: bool) -> str | None:
    """The long name from its pieces in name order (26 bytes each). STRICT (deleted names): only the last
    piece may hold the end marker, and what follows it must be 0xFFFF padding."""
    raw = b"".join(parts)
    end = len(raw)
    for i in range(0, len(raw) - 1, 2):
        if raw[i] == 0 and raw[i + 1] == 0:
            end = i
            break
    if strict:
        if end < 26 * (len(parts) - 1):
            return None
        tail = raw[end + 2:]
        if end < len(raw) and tail.strip(b"\xff"):
            return None
    name = raw[:end].decode("utf-16-le", "replace").rstrip("￿")
    if not name:
        return None
    return _clean_name(name)


def _clean_name(name: str) -> str:
    if "/" in name or "\x00" in name:
        name = name.replace("/", "_").replace("\x00", "_")
    return name


@dataclass(slots=True)
class DirRecord:
    """One file or folder found in a directory's entries."""
    slot: int                 # index of its short entry in the directory
    name: str
    short_name: str
    attr: int
    cluster: int
    size: int
    deleted: bool
    crtime: float | None
    mtime: float | None
    atime: float | None
    long_name: bool

    @property
    def is_dir(self) -> bool:
        return bool(self.attr & ATTR_DIR)


def parse_directory(buf: bytes, fat32: bool = True, codepage: str = "cp437",
                    deleted: bool = True) -> tuple[list[DirRecord], dict]:
    """Every file and folder in the raw directory BUF (live ones, and deleted ones when DELETED), and a few
    facts about the directory itself: {"label", "dot", "dotdot", "invalid", "slots", "end"}."""
    recs: list[DirRecord] = []
    facts: dict = {"label": None, "dot": None, "dotdot": None, "invalid": 0, "slots": 0, "end": False}
    lfn: list[tuple[int, int, bytes]] = []      # live long-name pieces (sequence, checksum, characters)
    dlfn: list[tuple[int, bytes]] = []          # deleted ones (checksum, characters), in disk order
    n = len(buf) // 32
    i = -1
    for i in range(n):
        o = i * 32
        b0 = buf[o]
        if b0 == 0:
            facts["end"] = True
            break
        attr = buf[o + 11]
        if attr & 0x3F == ATTR_LFN:
            if buf[o + 12] != 0 or buf[o + 26] or buf[o + 27]:
                lfn = []
                dlfn = []
                facts["invalid"] += 1
                continue
            chk = buf[o + 13]
            if b0 == DELETED:
                lfn = []
                if dlfn and dlfn[-1][0] != chk:
                    dlfn = []
                dlfn.append((chk, _lfn_chars(buf, o)))
                del dlfn[:-20]                  # a long name has at most 20 pieces
                continue
            dlfn = []
            seq = b0 & 0x1F
            if b0 & 0x40:
                lfn = [(seq, chk, _lfn_chars(buf, o))] if seq else []
            elif lfn and seq == lfn[-1][0] - 1 and chk == lfn[-1][1]:
                lfn.append((seq, chk, _lfn_chars(buf, o)))
            else:
                lfn = []
            continue
        name11 = bytes(buf[o:o + 11])
        is_deleted = b0 == DELETED
        pending, dpending = lfn, dlfn
        lfn = []
        dlfn = []
        if name11 == DOT or name11 == DOTDOT:
            if not is_deleted and attr & ATTR_DIR:
                lo, = struct.unpack_from("<H", buf, o + 26)
                hi, = struct.unpack_from("<H", buf, o + 20)
                facts["dot" if name11 == DOT else "dotdot"] = lo | (hi << 16 if fat32 else 0)
            continue
        rest = name11[1:] if is_deleted or b0 == 0x05 else name11
        if attr & 0xC0 or b0 == 0x20 or rest.translate(None, _SHORT_OK):
            facts["invalid"] += 1
            continue
        if attr & ATTR_VOLUME:
            if not is_deleted and attr & 0x18 == ATTR_VOLUME:
                facts["label"] = _decode_short(name11, codepage).rstrip()
            continue
        if is_deleted and not deleted:
            continue
        (_n, _a, ntres, ctms, ctime_, cdate, adate, hi, wtime, wdate, lo, size) = _SHORT.unpack_from(buf, o)
        cluster = lo | (hi << 16 if fat32 else 0)
        long_name = None
        first: int | None = 0xE5 if b0 == 0x05 else b0      # a real 0xE5 first character is stored as 0x05
        if not is_deleted:
            if pending and pending[-1][0] == 1 and lfn_checksum(name11) == pending[0][1]:
                long_name = _lfn_name([p[2] for p in reversed(pending)], strict=False)
        else:
            first = None
            if dpending:
                # the checksum gives back the lost first character; it must be one a short name can start with
                guess = lfn_first_char(name11, dpending[0][0])
                if guess > 0x20 and not bytes([guess]).translate(None, _SHORT_OK) and not 0x61 <= guess <= 0x7A:
                    for k in range(len(dpending)):         # older pieces with the same checksum may lead it
                        long_name = _lfn_name([p[1] for p in reversed(dpending[k:])], strict=True)
                        if long_name is not None:
                            first = guess
                            break
        base = _decode_short(name11[1:8], codepage).rstrip()
        base = (_decode_short(bytes([first]), codepage) if first is not None else "_") + base
        ext = _decode_short(name11[8:11], codepage).rstrip()
        if ntres & 0x08:
            base = base.lower()
        if ntres & 0x10:
            ext = ext.lower()
        short = _clean_name(base.rstrip() + ("." + ext if ext else ""))
        recs.append(DirRecord(
            slot=i, name=long_name or short, short_name=short, attr=attr, cluster=cluster,
            size=0 if attr & ATTR_DIR else size, deleted=is_deleted,
            crtime=dos_datetime(cdate, ctime_, ctms if ctms < 200 else 0), mtime=dos_datetime(wdate, wtime),
            atime=dos_datetime(adate, 0), long_name=long_name is not None))
    facts["slots"] = i + 1
    return recs, facts


def looks_like_directory(buf: bytes) -> bool:
    """Whether BUF (a cluster) holds directory entries: used to follow a deleted or lost folder into the
    clusters after its first one, where there's no "." entry to recognise it by."""
    used = 0
    bad = 0
    for o in range(0, len(buf) - 31, 32):
        b0 = buf[o]
        if b0 == 0:
            break
        used += 1
        attr = buf[o + 11]
        if attr & 0x3F == ATTR_LFN:
            if buf[o + 12] != 0 or buf[o + 26] or buf[o + 27]:
                bad += 1
            continue
        name = buf[o + 1:o + 11]
        if attr & 0xC0 or bytes(name).translate(None, _SHORT_OK) or b0 < 0x20 and b0 != 0x05:
            bad += 1
    return used > 0 and bad * 10 <= used


def used_map_from_fat(fat: bytes, bits: int, count: int) -> bytes:
    """One byte per cluster (index = cluster number, 0 = free, 1 = in use) for COUNT entries of a raw FAT.
    Done with slices and big-integer ORs so a FAT of millions of entries takes a moment, not a minute."""
    if bits == 12:
        out = bytearray(count)
        for i in range(count):
            o = i + (i >> 1)
            if o + 1 >= len(fat):
                break
            v = fat[o] | (fat[o + 1] << 8)
            out[i] = 1 if (v >> 4 if i & 1 else v & 0xFFF) else 0
        used = out
    else:
        width = bits // 8
        used = bytearray()
        step = 4 * MiB                       # entries per piece: keeps the temporary integers small
        for start in range(0, count, step):
            m = min(step, count - start)
            piece = fat[start * width:(start + m) * width]
            if len(piece) < m * width:
                piece = bytes(piece).ljust(m * width, b"\x00")
            lanes = [piece[k::width] for k in range(width)]
            if bits == 32:
                lanes[3] = lanes[3].translate(_LOW_NIBBLE)
            x = 0
            for lane in lanes:
                x |= int.from_bytes(lane, "little")
            used += x.to_bytes(m, "little").translate(_NONZERO)
    if count >= 2:
        used[0] = used[1] = 1
    return bytes(used)


class ClusterMap:
    """Which clusters are in use, one byte per cluster (0 free, 1 used), indexed by cluster number; clusters
    FIRST..LAST exist. Answers the questions chance estimates ask, without a Python loop per cluster."""

    def __init__(self, used: bytes, first: int, last: int):
        self.used = used
        self.first = first
        self.last = last

    def is_free(self, c: int) -> bool:
        return self.first <= c <= self.last and c < len(self.used) and self.used[c] == 0

    def all_free(self, c: int, n: int) -> bool:
        if c < self.first or c + n - 1 > self.last or c + n > len(self.used):
            return False
        return self.used.find(b"\x01", c, c + n) == -1

    def count_used(self, c: int, n: int) -> int:
        c2 = min(c + n, self.last + 1, len(self.used))
        c = max(c, self.first)
        return self.used.count(1, c, c2) if c2 > c else 0

    def free_runs_from(self, c: int, n: int, limit: int | None = None) -> list[tuple[int, int]]:
        """N free clusters from C on, skipping used ones: [(first cluster, count), ...] (fewer when the
        volume ends, or after looking at LIMIT clusters)."""
        out: list[tuple[int, int]] = []
        end = self.last + 1 if limit is None else min(self.last + 1, c + limit)
        end = min(end, len(self.used))
        pos = max(c, self.first)
        while n > 0 and pos < end:
            s = self.used.find(b"\x00", pos, end)
            if s < 0:
                break
            e = self.used.find(b"\x01", s, min(end, s + n))
            if e < 0:
                e = min(end, s + n)
            out.append((s, e - s))
            n -= e - s
            pos = e
        return out

    def free_runs(self) -> Iterator[tuple[int, int]]:
        for m in _FREE_RUN.finditer(self.used, self.first, min(self.last + 1, len(self.used))):
            yield m.start(), m.end() - m.start()

    def free_count(self) -> int:
        return self.used.count(0, self.first, min(self.last + 1, len(self.used)))


# ---------------------------------------------------------------------- the reader
class FatReader(FsReader):
    """FAT12/16/32: live files through the FAT, deleted ones by the contiguous guess, lost folders on request.

    info overrides: "fat_copy" (1 or 2: which FAT to trust), "scan_lost_dirs" (look for folders the
    directory tree doesn't reach: after a quick format or a destroyed root), "codepage" (short names; cp437)."""

    fstype = "fat32"
    name = "FAT"
    root_key = 0

    def __init__(self, src: Source, info: dict | None = None):
        super().__init__(src, info)
        if "data_offset" not in self.info:
            probed = self.probe(src)
            if probed is None:
                raise FormatError("This isn't a FAT filesystem, or its boot sector is damaged")
            probed.update(self.info)          # only overrides here: the geometry comes from the boot sector
            self.info = probed
        i = self.info
        self.bits = int(i.get("bits") or {"fat12": 12, "fat16": 16}.get(i.get("fstype") or "", 32))
        self.fstype = f"fat{self.bits}"
        self.name = f"FAT{self.bits}"
        self.cs = int(i["cluster_size"])
        self.block_size = self.cs
        self.data_offset = int(i["data_offset"])
        self.clusters = int(i["clusters"])
        self.volume_bytes = int(i.get("size") or self.data_offset + self.clusters * self.cs)
        fits = max(1, (src.size - self.data_offset) // self.cs)
        if self.clusters > fits:
            # clusters past the end can't be read anyway; and a damaged boot sector mustn't make us allocate
            # gigabytes for a FAT that isn't there
            self.warn("The filesystem is bigger than the disk or partition holding it: its end is missing.")
            self.clusters = fits
        self.max_cluster = self.clusters + 1
        self.root_cluster = int(i.get("root_cluster") or 0)
        self.codepage = i.get("codepage") or "cp437"
        self.label = i.get("label") or ""
        self.meta = CachedSource(src, block=64 * 1024, blocks=1024)
        self.fat: array | memoryview | None = None
        self.map: ClusterMap | None = None
        self.fat_copy = 0
        if self.bits == 12:
            self.eoc, self.bad = 0xFF8, 0xFF7
        elif self.bits == 16:
            self.eoc, self.bad = 0xFFF8, 0xFFF7
        else:
            self.eoc, self.bad = 0x0FFFFFF8, 0x0FFFFFF7
        self._mask = {12: 0xFFF, 16: 0xFFFF}.get(self.bits, 0x0FFFFFFF)
        # what the walk found: first cluster of a folder → its key; every cluster of a walked folder
        self._dir_key: dict[int, int | str] = {}
        self._dir_clusters: set[int] = set()
        self._walked = False
        self._seen: set = set()
        self._broken_chains = 0

    # ------------------------------------------------------------------ probing
    @classmethod
    def probe(cls, src: Source) -> dict | None:
        info = parse_boot(src.read(0, 512))
        boot = "main"
        if info is None:
            # FAT32 keeps a copy of its boot sector at sector 6: a damaged sector 0 doesn't lose the volume
            for bps in (512, 4096, 1024, 2048):
                cand = parse_boot(src.read(6 * bps, 512))
                if (cand and cand["bits"] == 32 and cand["backup_boot_sector"] == 6
                        and cand["bytes_per_sector"] == bps):
                    info, boot = cand, "backup"
                    break
        if info is None:
            return None
        info["boot"] = boot
        try:
            label = _root_label(src, info)
        except Exception:  # noqa: BLE001 - a damaged root only costs the label
            label = None
        if label is not None:
            info["label"] = "" if label.upper() == "NO NAME" else label
        cls._probe_usage(src, info)
        return info

    @staticmethod
    def _probe_usage(src: Source, info: dict) -> None:
        """used/free: counted from the FAT when it's small, from FAT32's FSInfo sector otherwise."""
        cs, clusters, bits = info["cluster_size"], info["clusters"], info["bits"]
        free = None
        width = {12: 1.5, 16: 2, 32: 4}[bits]
        if (clusters + 2) * width <= 8 * MiB:
            raw = src.read(info["fat_offset"], int((clusters + 2) * width) + 2)
            free = used_map_from_fat(raw, bits, clusters + 2).count(0, 2)
        elif bits == 32 and info.get("fsinfo_sector"):
            fs = src.read(info["fsinfo_sector"] * info["bytes_per_sector"], 512)
            if fs[0:4] == b"RRaA" and fs[484:488] == b"rrAa":
                n = struct.unpack_from("<I", fs, 488)[0]
                if n <= clusters:
                    free = n
        if free is not None:
            info["free"] = free * cs
            info["used"] = (clusters - free) * cs

    # ------------------------------------------------------------------ the FAT
    def cluster_offset(self, c: int) -> int:
        return self.data_offset + (c - 2) * self.cs

    def _read_fat_copy(self, k: int, ctl: Control) -> bytearray:
        i = self.info
        n = self.clusters + 2
        nbytes = (n * 3 + 1) // 2 + 1 if self.bits == 12 else n * self.bits // 8
        nbytes = min(nbytes, int(i["fat_bytes"]))
        base = int(i["fat_offset"]) + k * int(i["fat_bytes"])
        out = bytearray()
        pos = 0
        step = 8 * MiB
        while pos < nbytes:
            ctl.check()
            m = min(step, nbytes - pos)
            out += self.src.read(base + pos, m)
            pos += m
            if nbytes > 4 * step:
                ctl.progress(pos / nbytes, "Reading the FAT")
        return out

    def _decode(self, raw: bytearray) -> array | memoryview:
        """The FAT as something indexable by cluster number. FAT16/32 on a little-endian machine: a view of
        the raw bytes (no copy: a FAT32 FAT can be hundreds of megabytes)."""
        n = self.clusters + 2
        if self.bits == 12:
            a = array("H", bytes(2 * n))
            raw = bytes(raw).ljust((n * 3 + 1) // 2 + 2, b"\x00")
            for c in range(n):
                o = c + (c >> 1)
                v = raw[o] | (raw[o + 1] << 8)
                a[c] = v >> 4 if c & 1 else v & 0xFFF
            return a
        width = self.bits // 8
        if len(raw) < n * width:
            raw.extend(bytes(n * width - len(raw)))
        code = "H" if self.bits == 16 else "I"
        if sys.byteorder == "little" and struct.calcsize(code) == width:
            return memoryview(raw)[:n * width].cast(code)
        return array(code if struct.calcsize(code) == width else "L",
                     [int.from_bytes(raw[k:k + width], "little") for k in range(0, n * width, width)])

    def _fat_damage(self, a) -> int:
        """How damaged a decoded FAT copy looks (0 = fine): entry 0 must hold the media byte, and entries
        must point inside the volume (a sample of them is checked)."""
        score = 0
        media = int(self.info.get("media") or 0xF8)
        e0 = a[0] & self._mask
        if e0 & 0xFF != media or (e0 | 0xFF) != self._mask:
            score += 1000
        n = min(len(a), self.clusters + 2)
        step = max(1, n // 65536)
        mask, maxc, bad = self._mask, self.max_cluster, self.bad
        for v in a[2:n:step]:
            v &= mask
            if v == 1 or maxc < v < bad:
                score += 1
        return score

    def load_fat(self, ctl: Control = NULL_CONTROL) -> None:
        """Read the FAT (the first copy, unless it looks damaged and the second looks better, or
        info["fat_copy"] says which) and build the cluster map."""
        if self.fat is not None:
            return
        nfats = int(self.info.get("fats") or 1)
        try:
            force = int(self.info.get("fat_copy") or self.info.get("active_fat") or 0)
        except (TypeError, ValueError):
            force = 0
        if 1 <= force <= nfats:
            chosen = force - 1
            raw = self._read_fat_copy(chosen, ctl)
            fat = self._decode(raw)
        else:
            chosen = 0
            raw = self._read_fat_copy(0, ctl)
            fat = self._decode(raw)
            damage = self._fat_damage(fat)
            if damage and nfats >= 2:
                raw2 = self._read_fat_copy(1, ctl)
                if raw2 != raw:
                    fat2 = self._decode(raw2)
                    if self._fat_damage(fat2) < damage:
                        self.warn("The first copy of the FAT is damaged: using the second copy.")
                        raw, fat, chosen = raw2, fat2, 1
                    del fat2
                del raw2
            if chosen == 0 and damage >= 1000:
                self.warn("The FAT looks damaged: files may come back incomplete.")
        self.fat_copy = chosen + 1
        self.fat = fat
        self.map = ClusterMap(used_map_from_fat(raw, self.bits, self.clusters + 2), 2, self.max_cluster)

    def next_cluster(self, c: int) -> int:
        return self.fat[c] & self._mask if self.fat is not None and 0 <= c < len(self.fat) else 0

    def chain(self, start: int, limit: int) -> tuple[list[list[int]], int, str]:
        """The cluster chain from START as runs [[first, count], ...] (at most LIMIT clusters), its length,
        and why it stopped: "end", "limit", "free", "bad", "range" or "loop"."""
        fat = self.fat
        mask, eoc, bad, maxc = self._mask, self.eoc, self.bad, self.max_cluster
        runs: list[list[int]] = []
        total = 0
        c = start
        jumps = {start}            # a loop must jump back somewhere: remembering jump targets finds it
        reason = "limit"
        while total < limit:
            if not 2 <= c <= maxc:
                reason = "range"
                break
            if runs and runs[-1][0] + runs[-1][1] == c:
                runs[-1][1] += 1
            else:
                runs.append([c, 1])
            total += 1
            nxt = fat[c] & mask
            if nxt >= eoc:
                reason = "end"
                break
            if nxt == bad:
                reason = "bad"
                break
            if nxt == 0:
                reason = "free"
                break
            if nxt != c + 1:
                if nxt in jumps:
                    reason = "loop"
                    break
                jumps.add(nxt)
            c = nxt
        return runs, total, reason

    def _byte_runs(self, runs, size: int) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        left = size
        for c, n in runs:
            if left <= 0:
                break
            length = min(n * self.cs, left)
            out.append((self.cluster_offset(c), length))
            left -= length
        return out

    def allocated(self, offset: int, length: int) -> bool:
        """Whether any cluster of the byte range [offset, offset+length) of the data area is in use."""
        self.load_fat()
        if length <= 0:
            return False
        c1 = max(2, (offset - self.data_offset) // self.cs + 2)
        c2 = (offset + length - 1 - self.data_offset) // self.cs + 2
        return self.map.count_used(c1, c2 - c1 + 1) > 0

    def free_extents(self, ctl: Control = NULL_CONTROL) -> list[tuple[int, int]] | None:
        self.load_fat(ctl)
        return [(self.cluster_offset(c), n * self.cs) for c, n in self.map.free_runs()]

    # ------------------------------------------------------------------ locating content
    def _locate_live(self, cluster: int, size: int) -> tuple[list | None, int, int]:
        """(runs, chance, flags) of an existing file, through its FAT chain."""
        if size == 0:
            return [], CHANCE_GOOD, 0
        need = -(-size // self.cs)
        runs, total, reason = self.chain(cluster, need)
        if total >= need:
            return self._byte_runs(runs, size), CHANCE_GOOD, 0
        self._broken_chains += 1
        if not runs:
            return None, CHANCE_POOR, F_PARTIAL
        # the chain breaks off early: guess the rest follows on contiguously, like a deleted file
        last = runs[-1][0] + runs[-1][1]
        extra = min(need - total, self.max_cluster + 1 - last)
        if extra > 0:
            runs.append([last, extra])
        flags = 0 if total + max(extra, 0) >= need else F_PARTIAL
        return self._byte_runs(runs, size), CHANCE_FAIR, flags

    def _locate_deleted(self, cluster: int, size: int, marked: bool) -> tuple[list | None, int, int]:
        """(runs, chance, flags) of a deleted file. Its FAT chain is gone, so it's assumed contiguous from its
        first cluster: GOOD when all those clusters are free, FAIR when some are used now (the free clusters
        after the start are taken instead), POOR when the first one is used. MARKED is False for an entry that
        isn't marked deleted itself (inside a deleted or lost folder): its chain is used when it still fits."""
        if size == 0:
            return [], CHANCE_GOOD, 0
        need = -(-size // self.cs)
        if not 2 <= cluster <= self.max_cluster:
            return None, CHANCE_POOR, F_PARTIAL
        if not marked and self.next_cluster(cluster):
            runs, total, reason = self.chain(cluster, need)
            if total >= need and (reason == "end" or reason == "limit"):
                return self._byte_runs(runs, size), CHANCE_GOOD, 0
        avail = min(need, self.max_cluster + 1 - cluster)
        flags = 0 if avail >= need else F_PARTIAL
        if self.map.all_free(cluster, avail):
            return self._byte_runs([(cluster, avail)], size), CHANCE_GOOD if not flags else CHANCE_FAIR, flags
        if not self.map.is_free(cluster):
            return self._byte_runs([(cluster, avail)], size), CHANCE_POOR, flags
        runs = self.map.free_runs_from(cluster, need, limit=need * 4 + 65536)
        got = sum(n for _c, n in runs)
        if got < need:
            flags |= F_PARTIAL
        return self._byte_runs(runs, size), CHANCE_FAIR, flags

    # ------------------------------------------------------------------ reading folders
    def _read_runs(self, runs) -> bytes:
        out = bytearray()
        for c, n in runs:
            out += self.meta.read(self.cluster_offset(c), n * self.cs)
        return bytes(out)

    def _slot_offset(self, clusters: list[int] | None, slot: int) -> int:
        pos = slot * 32
        if clusters is None:
            return int(self.info["root_offset"]) + pos
        return self.cluster_offset(clusters[pos // self.cs]) + pos % self.cs

    def _dots(self, c: int, cached: bool = True) -> tuple[int, int] | None:
        """The clusters in the "." and ".." entries at the start of cluster C (a folder's first cluster)."""
        if not 2 <= c <= self.max_cluster:
            return None
        head = (self.meta if cached else self.src).read(self.cluster_offset(c), 64)
        if head[0:11] != DOT or not head[11] & ATTR_DIR or head[32:43] != DOTDOT:
            return None
        lo, hi, plo, phi = (struct.unpack_from("<H", head, k)[0] for k in (26, 20, 58, 52))
        if self.bits != 32:
            hi = phi = 0
        return lo | (hi << 16), plo | (phi << 16)

    def _live_dir(self, first: int) -> tuple[bytes, list[int] | None, str]:
        if first == 0 and self.bits != 32:
            size = int(self.info.get("root_size") or 0)
            return self.meta.read(int(self.info["root_offset"]), size), None, "end"
        limit = max(1, MAX_DIR_BYTES // self.cs)
        runs, _total, reason = self.chain(first, limit)
        clusters = [c + k for c, n in runs for k in range(n)]
        return self._read_runs(runs), clusters, reason

    def _guess_dir(self, first: int, use_chain: bool = True) -> tuple[bytes, list[int]]:
        """A deleted or lost folder's clusters: its chain when the FAT still has it, else the clusters after
        its first one for as long as they hold directory entries."""
        if use_chain and self.next_cluster(first):
            runs, _t, reason = self.chain(first, max(1, MAX_DIR_BYTES // self.cs))
            clusters = [c + k for c, n in runs for k in range(n)]
            if reason in ("end", "limit") and not (set(clusters[1:]) & self._dir_clusters):
                return self._read_runs(runs), clusters
        clusters = []
        out = bytearray()
        c = first
        while len(clusters) < MAX_GUESS_DIR_CLUSTERS and 2 <= c <= self.max_cluster:
            if c in self._dir_clusters:
                break
            data = self.meta.read(self.cluster_offset(c), self.cs)
            if clusters and (data[0:11] == DOT or not looks_like_directory(data)):
                break
            clusters.append(c)
            out += data
            if 0 in data[0::32]:            # the folder's end marker: no need to look further
                break
            c += 1
        return bytes(out), clusters

    def _find_deleted_dir(self, cluster: int, parent: int) -> int | None:
        """Where a deleted folder's first cluster really is: CLUSTER if it still starts with a "." entry
        pointing at itself. On big FAT32 volumes Windows zeroes the high half of a deleted entry's cluster
        number, so the clusters that differ only there are tried too, and the one whose ".." entry names the
        PARENT folder's cluster is taken."""
        dots = self._dots(cluster)
        if dots and dots[0] == cluster and cluster not in self._dir_clusters:
            return cluster
        if self.bits == 32 and cluster <= 0xFFFF and self.max_cluster > 0xFFFF:
            parents = {parent, 0} if parent == self.root_cluster else {parent}
            for hi in range(1, min(self.max_cluster >> 16, 256) + 1):
                c = (hi << 16) | cluster
                if c > self.max_cluster:
                    break
                if c in self._dir_clusters:
                    continue
                dots = self._dots(c, cached=False)
                if dots and dots[0] == c and dots[1] in parents:
                    return c
        return None

    # ------------------------------------------------------------------ the walk
    def _entry(self, rec: DirRecord, key, parent, deleted: bool) -> Entry:
        extra = {"short_name": rec.short_name, "attr": rec.attr, "cluster": rec.cluster}
        if rec.is_dir:
            return Entry(key=key, parent=parent, name=rec.name, is_dir=True, deleted=deleted,
                         mtime=rec.mtime, atime=rec.atime, crtime=rec.crtime, chance=CHANCE_GOOD, extra=extra)
        if not deleted:
            runs, chance, flags = self._locate_live(rec.cluster, rec.size)
        else:
            runs, chance, flags = self._locate_deleted(rec.cluster, rec.size, rec.deleted)
        return Entry(key=key, parent=parent, name=rec.name, size=rec.size, deleted=deleted, runs=runs,
                     mtime=rec.mtime, atime=rec.atime, crtime=rec.crtime, chance=chance, flags=flags,
                     extra=extra)

    def entries(self, ctl: Control = NULL_CONTROL, deleted: bool = True) -> Iterator[Entry]:
        self.load_fat(ctl)
        root_first = self.root_cluster if self.bits == 32 else 0
        yield Entry(key=self.root_key, parent=None, name="", is_dir=True, chance=CHANCE_GOOD,
                    extra={"cluster": root_first})
        self._dir_key = {0: self.root_key}            # ".." holds 0 when the parent is the root
        self._dir_clusters = set()
        self._seen = {self.root_key}
        self._broken_chains = 0
        yield from self._walk(ctl, deleted, root_first)
        self._walked = True
        if self._broken_chains:
            self.warn(f"{self._broken_chains} files have broken cluster chains: their missing parts are guessed.")
        if self.info.get("scan_lost_dirs"):
            yield from self._lost(ctl, deleted)

    def _walk(self, ctl: Control, deleted: bool, root_first: int) -> Iterator[Entry]:
        # every live folder first, so a cluster now used by a live folder is never read as a deleted one's
        live: deque = deque([(self.root_key, root_first, 0)])
        dead: deque = deque()
        if root_first:
            self._dir_key[root_first] = self.root_key
        count = 0
        while live or dead:
            is_dead = not live
            key, first, depth = (dead if is_dead else live).popleft()
            try:
                if is_dead:
                    if first in self._dir_clusters or first in self._dir_key:
                        continue                 # a live folder (or another deleted one) took its place
                    self._dir_key[first] = key
                    buf, clusters = self._guess_dir(first)
                else:
                    if first and first in self._dir_clusters:
                        self.warn("Two folders share the same clusters (cross-linked): one was skipped.")
                        continue
                    buf, clusters, reason = self._live_dir(first)
                    if first and reason in ("free", "bad", "range", "loop"):
                        self.warn("A folder's cluster chain is damaged: part of it may be missing.")
                if clusters:
                    self._dir_clusters.update(clusters)
                recs, facts = parse_directory(buf, self.bits == 32, self.codepage, deleted)
                if facts["label"] and key == self.root_key and not self.label:
                    self.label = facts["label"]
                if facts["invalid"] > 8 and facts["invalid"] * 2 > facts["slots"]:
                    self.warn("Some folders are damaged: their unreadable entries were skipped.")
            except Cancelled:
                raise
            except Exception as exc:  # noqa: BLE001 - one damaged folder must not stop the scan
                self.warn(f"A damaged folder was skipped ({exc.__class__.__name__}).")
                continue
            for rec in recs:
                count += 1
                if count % 256 == 0:
                    ctl.check()
                    ctl.progress(None, f"Reading folders: {count} entries")
                if rec.size > self.volume_bytes:
                    continue                     # bigger than the volume: not a real entry
                ekey = self._slot_offset(clusters, rec.slot)
                if ekey in self._seen:
                    continue
                self._seen.add(ekey)
                gone = is_dead or rec.deleted
                try:
                    e = self._entry(rec, ekey, key, gone)
                    if rec.is_dir and depth < MAX_DEPTH:
                        if not gone:
                            if 2 <= rec.cluster <= self.max_cluster and rec.cluster not in self._dir_key:
                                self._dir_key[rec.cluster] = ekey
                                live.append((ekey, rec.cluster, depth + 1))
                        else:
                            real = self._find_deleted_dir(rec.cluster, first) if rec.cluster >= 2 else None
                            if real is not None:
                                e.extra["cluster"] = real
                                dead.append((ekey, real, depth + 1))
                            else:
                                e.chance = CHANCE_POOR      # its clusters were reused: its contents are gone
                except Cancelled:
                    raise
                except Exception:  # noqa: BLE001
                    continue
                yield e

    # ------------------------------------------------------------------ lost folders
    def lost_directories(self, ctl: Control = NULL_CONTROL, deleted: bool = True) -> Iterator[Entry]:
        """Folders the folder tree doesn't reach (after a quick format, or a destroyed root), found by their
        "." and ".." entries, with everything in them. Runs the normal walk first if it hasn't run."""
        if not self._walked:
            for _e in self.entries(ctl, deleted):
                pass
            if self.info.get("scan_lost_dirs"):
                return                     # entries() just looked for them
        yield from self._lost(ctl, deleted)

    def find_directory_clusters(self, ctl: Control = NULL_CONTROL) -> dict[int, int]:
        """{first cluster: parent cluster} of every folder start in the data area (a "." entry pointing at its
        own cluster, then a ".." entry) that the walk didn't reach. Reads the whole data area in big pieces;
        only the clusters whose first byte is a "." get a closer look."""
        found: dict[int, int] = {}
        cs = self.cs
        per = max(1, (8 * MiB) // cs)
        c0 = 2
        last = self.max_cluster
        total = max(1, last - 1)
        while c0 <= last and len(found) < 1_000_000:
            ctl.check()
            n = min(per, last + 1 - c0)
            buf = self.src.read(self.cluster_offset(c0), n * cs)
            firsts = buf[0::cs]
            i = firsts.find(b".")
            while i != -1:
                o = i * cs
                if (buf[o:o + 11] == DOT and buf[o + 11] & ATTR_DIR and buf[o + 32:o + 43] == DOTDOT
                        and buf[o + 43] & ATTR_DIR):
                    c = c0 + i
                    lo, hi, plo, phi = (struct.unpack_from("<H", buf, o + k)[0] for k in (26, 20, 58, 52))
                    if self.bits != 32:
                        hi = phi = 0
                    if lo | (hi << 16) == c and c not in self._dir_clusters and c not in self._dir_key:
                        found[c] = plo | (phi << 16)
                i = firsts.find(b".", i + 1)
            c0 += n
            ctl.progress((c0 - 2) / total, "Looking for lost folders")
        return found

    def _lost(self, ctl: Control, deleted: bool) -> Iterator[Entry]:
        found = self.find_directory_clusters(ctl)
        # read every lost folder (in cluster order; a guessed folder stops at the next "." cluster anyway)
        listing: dict[int, tuple[list[DirRecord], list[int]]] = {}
        for c in sorted(found):
            ctl.check()
            if c in self._dir_clusters:
                continue                       # swallowed by an earlier folder's chain
            try:
                buf, clusters = self._guess_dir(c)
                if not clusters:
                    continue
                self._dir_clusters.update(clusters)
                recs, _facts = parse_directory(buf, self.bits == 32, self.codepage, True)
            except Cancelled:
                raise
            except Exception:  # noqa: BLE001
                continue
            listing[c] = (recs, clusters)
        if not listing:
            return
        # a lost folder's parent: the lost folder that lists it (which also gives its name), else the one its
        # ".." entry names
        named: dict[int, tuple[int, DirRecord, int]] = {}     # cluster → (parent cluster, record, entry key)
        for c, (recs, clusters) in listing.items():
            for rec in recs:
                if rec.is_dir and rec.cluster in listing and rec.cluster != c:
                    prev = named.get(rec.cluster)
                    if prev is None or (prev[1].deleted and not rec.deleted):
                        named[rec.cluster] = (c, rec, self._slot_offset(clusters, rec.slot))
        parent_of: dict[int, int | None] = {}
        for c in listing:
            if c in named:
                parent_of[c] = named[c][0]
            else:
                p = found.get(c, 0)
                parent_of[c] = p if p in listing and p != c else None
        for c in listing:                      # a damaged disk can make folders point at each other in a circle
            seen = {c}
            p = parent_of[c]
            while p is not None:
                if p in seen:
                    parent_of[c] = None
                    named.pop(c, None)
                    break
                seen.add(p)
                p = parent_of[p]
        named_keys = {v[2] for v in named.values()}
        gone = {c: self.next_cluster(c) == 0 or (c in named and named[c][1].deleted) for c in listing}
        shown = {c for c in listing if deleted or not gone[c]}
        keys = {c: (named[c][2] if c in named else f"lost{c}") for c in listing}
        n_top = 0
        for c in sorted(shown):
            recs, clusters = listing[c]
            pc = parent_of[c]
            if c in named and pc in shown:
                e = self._entry(named[c][1], keys[c], keys[pc], gone[c])
                e.extra["cluster"] = c
            else:
                parent_cluster = found.get(c, 0)
                if pc in shown:
                    pkey = keys[pc]
                else:
                    pkey = self._dir_key.get(parent_cluster) if parent_cluster else None
                    if pkey == self.root_key:
                        pkey = None            # its name is gone from the root: show it with the lost files
                    n_top += pkey is None
                flags = F_DIR_RECOVERED | (F_ORPHAN if pkey is None else 0)
                e = Entry(key=keys[c], parent=pkey, name=f"Folder {c}", is_dir=True, deleted=gone[c],
                          chance=CHANCE_GOOD, flags=flags, extra={"cluster": c, "parent_cluster": parent_cluster})
            if e.key in self._seen:
                continue
            self._seen.add(e.key)
            yield e
            for rec in recs:
                key = self._slot_offset(clusters, rec.slot)
                if key in self._seen or key in named_keys or rec.size > self.volume_bytes:
                    continue                   # (a lost folder of its own: listed above)
                lost = rec.deleted or gone[c] or bool(rec.size and not rec.is_dir and
                                                     self.next_cluster(rec.cluster) == 0)
                if lost and not deleted:
                    continue
                self._seen.add(key)
                try:
                    child = self._entry(rec, key, e.key, lost)
                except Cancelled:
                    raise
                except Exception:  # noqa: BLE001
                    continue
                if rec.is_dir:
                    child.chance = CHANCE_POOR         # its own first cluster no longer looks like a folder
                yield child
        if n_top:
            self.warn(f"Found {n_top} lost folders that the folder tree no longer reaches.")


def _root_label(src: Source, info: dict) -> str | None:
    """The volume label entry of the root folder (what Windows shows), or None."""
    if info["bits"] == 32:
        c = info["root_cluster"]
        if not 2 <= c <= info["clusters"] + 1:
            return None
        buf = src.read(info["data_offset"] + (c - 2) * info["cluster_size"], min(info["cluster_size"], 65536))
    else:
        buf = src.read(info["root_offset"], min(info["root_size"], 65536))
    _recs, facts = parse_directory(buf, info["bits"] == 32, deleted=False)
    return facts["label"]
