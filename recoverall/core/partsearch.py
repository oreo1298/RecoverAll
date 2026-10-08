"""Finding lost partitions: TestDisk's Quick Search, the deep scan's boot-sector detector, and turning what
was found into a partition table.

Quick Search (:func:`quick_search`)
    Probes the places where partitions usually start — every 1 MiB (2048 sectors), the 63-sector track
    and the 255×63 cylinder boundaries of old DOS layouts, sector 34/40 of old GPT and Mac layouts, the
    partitions of the current table and of the backup GPT — in ascending order (kind to hard disks), with
    one read of 68 KiB per probe (close probes share a read). When a filesystem whose size is known is
    found, the search jumps to its end, so only the gaps between filesystems are probed densely. The
    sector just before each probe is checked for an NTFS backup boot sector (a volume ending there whose
    main boot sector is damaged), and sectors 6 and 12 of each probe for the FAT32/exFAT backup boot
    sectors. On huge disks the empty stretches are sampled more coarsely and the user is told so.

Deep detector (:class:`BootSectorDetector`)
    Sees every sector of the disk once. Signatures are found with strided slices (``buf[k::512]``):
    each condition "byte k of a sector is one of these values" becomes a 0/1 byte per sector, and the
    conditions are AND-ed as big integers — no Python loop over sectors. It finds main structures and
    their backups (NTFS backup boot sector, FAT32 backup at sector 6, exFAT backup boot region, ext
    backup superblocks, XFS allocation-group copies, Btrfs mirrors, HFS+ alternate header, LUKS2 second
    header, JFS/F2FS second superblocks…) and works out each volume's start from the backup's own fields
    (the ext group number, the Btrfs bytenr, the NTFS sector count). Cheap side marks (MFT record 0, the
    first sector of a FAT, HFS+ B-tree header nodes, XFS AGF headers) confirm which interpretation of a
    lone boot sector is right.

Merging (:func:`merge_candidates`)
    Duplicates are combined (a main structure confirmed by its backup is the strongest evidence); a
    filesystem inside another one (a disk image file, the inside of a RAID member) is marked "inside";
    overlapping candidates are resolved by choosing the set of non-overlapping volumes with the most
    total support (weighted interval scheduling), so one stale big filesystem can't hide three real
    partitions. Each candidate gets a status: "current" (it is in the partition table), "deleted" (it
    isn't), or "damaged" (only backup copies or metadata were found: the boot sector needs repair).
"""

from __future__ import annotations

import bisect
import logging
import math
import struct

from . import fsdetect
from .blockio import BytesSource, Source
from .fs.base import NULL_CONTROL, Control, Detector
from .util import MiB, fmt_bytes

log = logging.getLogger(__name__)

CYLINDER = 255 * 63 * 512
HEAD = fsdetect.HEAD
BEFORE = 4096                  # read before each probe: the last sector of a volume ending there
BATCH = MiB                    # probes closer than this share one read
DENSE_SPAN = 256 * MiB         # probed every MiB after the start of the disk and after each volume found
QUICK_MAX_PROBES = 200_000

# Scores: how sure a candidate is (0-100)
S_PAIR = 95          # the main structure and its backup agree
S_CHECKED = 85       # the main structure, confirmed by a checksum or by other metadata
S_MAIN = 75          # the main structure alone
S_BACKUP_OK = 65     # only a backup, confirmed by other metadata
S_BACKUP = 50        # only a backup
S_WEAK = 40          # a guess

FAMILY = {"fat12": "fat", "fat16": "fat", "fat32": "fat", "vfat": "fat", "ext2": "ext", "ext3": "ext", "ext4": "ext",
          "hfsplus": "hfs", "hfsx": "hfs", "hfs": "hfs", "iso9660": "optical", "udf": "optical", "ufs1": "ufs",
          "ufs2": "ufs"}
# Volumes whose inside never holds partitions of this disk: what is found there is "inside" them
CONTAINERS = {"linux_raid_member", "lvm2_member", "crypto_luks", "bitlocker", "zfs_member"}
_BACKUP_WORDS = ("backup", "copy", "mirror", "alternate", "secondary")
_META_WORDS = ("mft", "metadata", "records", "inode", "journal", "directory", "agf")


def family(fstype: str | None) -> str:
    return FAMILY.get(fstype or "", fstype or "")


def _cand(fstype: str, offset: int, size: int | None, evidences: list[str], score: int, info: dict | None = None,
          primary: bool | None = True, label: str = "", uuid: str = "") -> dict:
    info = dict(info or {})
    return {"fstype": fstype, "offset": int(offset), "size": int(size) if size else None,
            "evidence": ", ".join(evidences), "evidences": list(evidences), "score": int(score),
            "label": label or info.get("label") or "", "uuid": uuid or info.get("uuid") or "", "info": info,
            "primary": primary}


# ====================================================================== Quick Search
class _Grid:
    """The probe positions, in ascending order: the next one at or after POS."""

    def __init__(self, disk: int, ss: int, hints, max_probes: int):
        self.disk = disk
        self.ss = ss
        self.hints = sorted(h for h in hints if 0 <= h < disk)
        mib = max(1, disk // MiB)
        budget = max(1, max_probes // 2)
        self.coarse = MiB if mib <= budget else MiB << math.ceil(math.log2(mib / budget))
        self.dense_until = DENSE_SPAN
        early = {0, 34 * ss, 40 * ss, 256 * ss, 2048 * ss}
        if ss == 512:
            early.add(63 * 512)
        self.specials = sorted(x for x in early if x < disk)
        self.cylinders = ss == 512
        self.sampled = False

    def jumped(self, end: int) -> None:
        """A volume ends at END: probe densely after it, and at the usual distances from it."""
        self.dense_until = max(self.dense_until, end + DENSE_SPAN)
        for k in (0, 63, 2048):
            x = end + k * self.ss
            if x < self.disk:
                bisect.insort(self.specials, x)

    def next(self, pos: int) -> int | None:
        dense = pos < self.dense_until
        step = MiB if dense else self.coarse
        if not dense and self.coarse > MiB:
            self.sampled = True
        best = -(-pos // step) * step
        if dense and self.cylinders:
            best = min(best, -(-pos // CYLINDER) * CYLINDER, -(-(pos - 63 * 512) // CYLINDER) * CYLINDER + 63 * 512)
        for lst in (self.specials, self.hints):
            i = bisect.bisect_left(lst, pos)
            if i < len(lst):
                best = min(best, lst[i])
        return best if best < self.disk else None


class _Windows:
    """Reads [x - BEFORE, x + HEAD) around probe positions; a probe close to the previous one is served from
    the same read (the read is stretched to cover the next probe when it is near)."""

    def __init__(self, src: Source):
        self.src = src
        self.off = 0
        self.buf = b""

    def get(self, x: int, upcoming: int | None) -> bytes:
        lo, hi = x - BEFORE, x + HEAD
        if lo >= self.off and hi <= self.off + len(self.buf):
            return self.buf[lo - self.off:hi - self.off]
        end = hi
        if upcoming is not None and upcoming > x and upcoming + HEAD - lo <= BATCH:
            end = upcoming + HEAD
        start = max(0, lo)
        data = self.src.read(start, end - start)
        if lo < 0:
            data = bytes(-lo) + data
        self.off, self.buf = lo, data
        return data[:hi - lo]


def _same_ntfs(a: dict | None, b: dict) -> bool:
    return bool(a) and a["serial"] == b["serial"] and a["total_sectors"] == b["total_sectors"]


def _confirm(src: Source, x: int, info: dict, head: bytes) -> dict:
    """A candidate for the volume INFO found at X, with its backup structure checked where there is one."""
    fstype = info["fstype"]
    ev = [fsdetect.evidence_of(fstype)]
    score = S_MAIN
    size = info.get("size")

    def at(off: int, n: int) -> bytes:
        return head[off:off + n] if off + n <= len(head) else src.read(x + off, n)
    try:
        if fstype == "ntfs":
            bp = fsdetect.parse_ntfs_boot(at(info["total_sectors"] * info["sector_size"], 512))
            if _same_ntfs(bp, info):
                ev.append("backup boot sector")
                score = S_PAIR
        elif fstype == "fat32":
            bk, bps = int(info.get("backup_boot_sector") or 0), info["sector_size"]
            if 0 < bk < info["reserved_sectors"]:
                bp = fsdetect.parse_fat_bpb(at(bk * bps, 512))
                if bp and bp["serial"] == info["serial"] and bp["total_sectors"] == info["total_sectors"]:
                    ev.append("backup boot sector")
                    score = S_PAIR
        elif fstype == "exfat":
            bp = fsdetect.parse_exfat_boot(at(12 * info["sector_size"], 512))
            if bp and bp["serial"] == info["serial"]:
                ev.append("backup boot sector")
                score = S_PAIR
        elif fstype in ("ext2", "ext3", "ext4"):
            bs, bpg = info["block_size"], info["blocks_per_group"]
            if info["blocks"] > bpg + info["first_data_block"]:
                sb = fsdetect.parse_ext_super(at((info["first_data_block"] + bpg) * bs, 1024))
                if sb and sb["uuid"] == info["uuid"] and sb["group"] == 1:
                    ev.append("backup superblock")
                    score = S_PAIR
        elif fstype == "xfs" and info.get("ag_count", 1) > 1:
            sb = fsdetect.parse_xfs_super(at(info["ag_blocks"] * info["block_size"], 512))
            if sb and sb["uuid"] == info["uuid"]:
                ev.append("superblock copy")
                score = S_PAIR
        elif fstype in ("hfsplus", "hfsx") and size:
            alt = fsdetect.parse_hfsplus_header(src.read(x + size - 1024, 512))
            if alt and alt["create_date"] == info.get("create_date") and alt["total_blocks"] == info.get("total_blocks"):
                ev.append("alternate volume header")
                score = S_PAIR
        elif fstype == "btrfs":
            score = S_CHECKED if info.get("checksum_ok") else S_MAIN
            mirror = 64 * MiB
            if size and size > mirror + 4096:
                sb = fsdetect.parse_btrfs_super(src.read(x + mirror, 4096))
                if sb and sb["uuid"] == info["uuid"] and sb["bytenr"] == mirror:
                    ev.append("superblock copy")
                    score = S_PAIR
        elif info.get("checksum_ok"):
            score = S_CHECKED
        elif fstype in ("fat12", "fat16", "minix", "zfs_member", "squashfs"):
            score = S_MAIN - 5
    except (KeyError, TypeError, struct.error, IndexError):
        pass
    return _cand(fstype, x, size, ev, score, info)


def _backups_in_head(x: int, head: bytes) -> list[dict]:
    """Nothing was recognized at X: maybe the main boot sector is damaged but its backup a few sectors
    further (FAT32 sector 6, exFAT sector 12) is fine; or X is inside a filesystem, where a copy of its
    superblock tells where it starts (ext backup superblocks, XFS allocation groups)."""
    out = []
    for rel in (0, 1024):
        sb = fsdetect.parse_ext_super(head[rel:rel + 1024])
        if sb and 0 < sb["group"] < 0xFFFF:
            start = x + rel - (sb["first_data_block"] + sb["group"] * sb["blocks_per_group"]) * sb["block_size"]
            if start >= 0:
                info = dict(sb, reconstructed=True, superblock_offset=x + rel - start)
                out.append(_cand(sb["fstype"], start, sb["size"], ["backup superblock"], S_BACKUP, info, primary=False))
    xs = fsdetect.parse_xfs_super(head[:512])
    if xs:
        agf = head[xs["sector_size"]:xs["sector_size"] + 16]
        if agf[0:4] == b"XAGF":
            n = struct.unpack_from(">I", agf, 8)[0]
            start = x - n * xs["ag_blocks"] * xs["block_size"]
            if 0 < n < xs["ag_count"] and start >= 0:
                out.append(_cand("xfs", start, xs["size"], ["superblock copy", "AG headers"], S_BACKUP,
                                 dict(xs, fstype="xfs", reconstructed=True), primary=False))
    for bps in (512, 4096):
        p = fsdetect.parse_fat_bpb(head[6 * bps:6 * bps + 512])
        if p and p["fat_bits"] == 32 and p["sector_size"] == bps and p.get("backup_boot_sector") == 6:
            fat = head[p["reserved_sectors"] * bps:p["reserved_sectors"] * bps + 4]
            ok = len(fat) == 4 and fat[1:3] == b"\xff\xff" and fat[0] == p["media"]
            info = dict(p, fstype="fat32", reconstructed=True, block_size=p["cluster_size"], label=p["bpb_label"])
            out.append(_cand("fat32", x, p["size"], ["backup boot sector"] + (["FAT"] if ok else []),
                             S_BACKUP_OK if ok else S_BACKUP, info, primary=False))
        e = fsdetect.parse_exfat_boot(head[12 * bps:12 * bps + 512])
        if e and e["sector_size"] == bps:
            info = dict(e, fstype="exfat", reconstructed=True, block_size=e["cluster_size"])
            out.append(_cand("exfat", x, e["size"], ["backup boot sector"], S_BACKUP_OK, info, primary=False))
    return out


def _ntfs_ending_here(src: Source, x: int, w: bytes, ss: int, done: set) -> list[dict]:
    """An NTFS volume that ends at X keeps its backup boot sector in the sector before X."""
    out = []
    for bss in sorted({ss, 512}):
        if x - bss < 0 or BEFORE < bss:
            continue
        p = fsdetect.parse_ntfs_boot(w[BEFORE - bss:BEFORE - bss + 512])
        if not p or p["sector_size"] != bss:
            continue
        start = x - bss - p["total_sectors"] * bss
        if start < 0 or (start, "ntfs") in done:
            continue
        done.add((start, "ntfs"))
        rec = src.read(start + p["mft_offset"], 4) == b"FILE" or src.read(start + p["mftmirr_offset"], 4) == b"FILE"
        info = dict(p, fstype="ntfs", reconstructed=True, block_size=p["cluster_size"],
                    uuid=f"{p['serial']:016X}")
        if rec:
            info["label"], info["version"] = fsdetect.ntfs_label(src, start, p)
        out.append(_cand("ntfs", start, p["size"], ["backup boot sector"] + (["MFT"] if rec else []),
                         S_BACKUP_OK if rec else S_BACKUP, info, primary=False))
    return out


def _table_candidate(p: dict, evidence: str, score: int) -> dict:
    part = {k: p.get(k) for k in ("number", "start", "size", "type", "type_name", "name", "guid", "bootable", "logical",
                                  "attrs")}
    c = _cand("unknown", p["start"], p["size"], [evidence], score, {}, primary=None, label=p.get("name") or "")
    c["partition"] = part
    c["from_table"] = evidence
    return c


def _backup_gpt(src: Source, sizes) -> list[dict]:
    from .partitions import _gpt_partitions, gpt_header
    for ss in sizes:
        hdr = gpt_header(src, src.size // ss - 1, ss)
        if hdr and hdr["header_ok"] and hdr["entries_ok"]:
            return _gpt_partitions(hdr, ss, src.size, [])
    return []


def quick_search(src: Source, ctl: Control = NULL_CONTROL, table: dict | None = None,
                 max_probes: int = QUICK_MAX_PROBES) -> list[dict]:
    """TestDisk's Quick Search: the volumes found at the usual partition starts, merged and classified
    (see merge_candidates). TABLE is the current partition table (read when not given)."""
    from .partitions import read_table
    disk = src.size
    if table is None:
        table = read_table(src)
    ss = int(table.get("sector_size") or src.sector_size or 512)
    cands: list[dict] = []
    hints: set[int] = set()
    for p in table.get("partitions") or []:
        if p.get("extended") or not p.get("size"):
            continue
        hints.add(int(p["start"]))
        cands.append(_table_candidate(p, "partition table", 30))
    g = table.get("gpt") or {}
    if table.get("type") != "gpt" or (not g.get("primary_ok") and g.get("used_copy") != "backup"):
        for p in _backup_gpt(src, (ss, 512, 4096)):      # a wiped main GPT: its backup lists the partitions
            hints.add(int(p["start"]))
            cands.append(_table_candidate(p, "backup GPT", 45))
    grid = _Grid(disk, ss, hints, max_probes)
    win = _Windows(src)
    probed: set[int] = set()
    backups_seen: set = set()
    pos, probes = 0, 0
    ctl.progress(0.0, "Quick Search")
    while True:
        x = grid.next(pos)
        if x is None:
            break
        pos = x + ss
        if x in probed:
            continue
        if probes >= max_probes:
            ctl.warn(f"Quick Search stopped after {probes} probes at {fmt_bytes(x)}: run a Deep Search to search "
                     "the rest of the disk.")
            break
        probes += 1
        if probes % 64 == 0:
            ctl.check()
        if probes % 512 == 0:
            ctl.progress(x / disk, f"Quick Search: {fmt_bytes(x)} of {fmt_bytes(disk)}")
        probed.add(x)
        w = win.get(x, grid.next(pos))
        found = _probe_at(src, x, w, ss, backups_seen)
        cands.extend(found)
        main = next((c for c in found if c["offset"] == x and c["primary"] and c["size"]), None)
        if main:
            end = -(-(x + main["size"]) // ss) * ss
            if pos < end <= disk + ss:
                pos = end
                grid.jumped(end)
    for h in sorted(hints):                     # table entries inside a volume we jumped over
        if h not in probed and h < disk:
            probed.add(h)
            cands.extend(_probe_at(src, h, win.get(h, None), ss, backups_seen))
    if grid.sampled:
        ctl.warn(f"Large empty areas were sampled every {fmt_bytes(grid.coarse, binary=True)}; a Deep Search reads "
                 "every sector.")
    ctl.progress(1.0, f"Quick Search: {probes} places checked")
    return merge_candidates(cands, disk, ss, table)


def _probe_at(src: Source, x: int, w: bytes, ss: int, backups_seen: set) -> list[dict]:
    """Every candidate the bytes around X show: what starts at X, or its backup boot sector, and an NTFS
    volume that ends at X."""
    head = w[BEFORE:]
    out: list[dict] = []
    info = fsdetect.identify_at(src, x, head=head)
    if info:
        out.append(_confirm(src, x, info, head))
    else:
        out.extend(_backups_in_head(x, head))
    out.extend(_ntfs_ending_here(src, x, w, ss, backups_seen))
    return out


# ====================================================================== the deep scan's detector
def _table(values) -> bytes:
    t = bytearray(256)
    for v in values:
        t[v] = 1
    return bytes(t)


_MEDIA = {0xF0} | set(range(0xF8, 0x100))
_POW2 = {1, 2, 4, 8, 16, 32, 64, 128}

# Byte conditions on a 512-byte sector: [(position, allowed values)], the rarest first.
_PATTERNS: dict[str, list[tuple[int, set[int]]]] = {
    "fat": [(511, {0xAA}), (510, {0x55}), (11, {0}), (12, {2, 4, 8, 16}), (16, {1, 2}), (21, _MEDIA), (13, _POW2),
            (0, {0xEB, 0xE9})],
    "ext": [(57, {0xEF}), (56, {0x53}), (25, {0}), (26, {0}), (27, {0}), (24, set(range(7))), (77, {0}), (78, {0}),
            (79, {0}), (76, {0, 1})],
    "mft0": [(0, {0x46}), (1, {0x49}), (2, {0x4C}), (3, {0x45}), (44, {0}), (45, {0}), (46, {0}), (47, {0}),
             (22, set(range(1, 256, 2)))],
    "fatmark": [(1, {0xFF}), (2, {0xFF}), (0, {0xF0} | set(range(0xF8, 0xFF)))],
    "btree": [(8, {1}), (11, {3}), (32, {2, 4, 8, 16, 32, 64, 128}), (33, {0}), (9, {0}), (10, {0}), (12, {0}),
              (13, {0}), (4, {0}), (5, {0}), (6, {0}), (7, {0})],
    "nilfs2": [(6, {0x34}), (7, {0x34}), (0, {2}), (1, {0}), (2, {0}), (3, {0})],
    "zfs": [(11, {1}), (0, {1}), (1, {0, 1}), (2, {0}), (3, {0}), (4, {0}), (5, {0}), (6, {0}), (7, {0}), (8, {0}),
            (9, {0}), (10, {0})],
}

# Magic strings at a fixed position in a sector: (kind, magic, position in the sector)
_MAGICS: tuple[tuple[str, bytes, int], ...] = (
    ("ntfs", b"NTFS    ", 3), ("exfat", b"EXFAT   ", 3), ("refs", b"ReFS\x00\x00\x00\x00", 3),
    ("bitlocker", b"-FVE-FS-", 3), ("xfs", b"XFSB", 0), ("xagf", b"XAGF", 0), ("btrfs", b"_BHRfS_M", 64),
    ("hfsplus", b"H+\x00\x04", 0), ("hfsplus", b"HX\x00\x05", 0), ("apfs", b"NXSB", 32),
    ("luks", b"LUKS\xba\xbe", 0), ("luks", b"SKUL\xba\xbe", 0), ("lvm", b"LABELONE", 0), ("md", b"\xfc\x4e\x2b\xa9", 0),
    ("swap", b"SWAPSPACE2", 502), ("swap", b"SWAP-SPACE", 502), ("swap", b"S1SUSPEND", 502),
    ("swap", b"S2SUSPEND", 502), ("swap", b"ULSUSPEND", 502), ("swap", b"LINHIB0001", 502),
    ("iso9660", b"\x01CD001\x01", 0), ("f2fs", b"\x10\x20\xf5\xf2", 0), ("jfs", b"JFS1", 0),
    ("reiserfs", b"ReIsEr", 52), ("squashfs", b"hsqs", 0), ("erofs", b"\xe2\xe1\xf5\xe0", 0),
    ("ufs", b"\x54\x19\x01\x00", 348), ("ufs", b"\x19\x01\x54\x19", 348), ("ufs", b"\x00\x01\x19\x54", 348),
    ("ufs", b"\x19\x54\x01\x19", 348),
)

# Bytes needed around a hit (before its sector, from its sector on) to parse it
_NEEDS = {"ntfs": (0, 512), "fat": (0, 512), "exfat": (0, 512), "refs": (0, 512), "bitlocker": (0, 512),
          "ext": (0, 1024), "xfs": (0, 512), "xagf": (0, 512), "btrfs": (0, 4096), "hfsplus": (0, 512),
          "apfs": (0, 4096), "luks": (0, 4096), "lvm": (0, 512), "md": (0, 4096), "swap": (65536 - 512, 512),
          "iso9660": (32768, 32768 + 2048), "f2fs": (1024, 1024), "jfs": (32768, 512), "reiserfs": (65536, 512),
          "squashfs": (0, 512), "erofs": (1024, 512), "ufs": (65536 + 1024, 1536), "nilfs2": (1024, 1024),
          "zfs": (0, 16384)}

# Probe used for the kinds parsed in place (the structure's offset from the volume start)
_GENERIC = {"refs": ("refs", 0), "bitlocker": ("bitlocker", 0), "swap": ("swap", None), "iso9660": ("iso9660", 32768),
            "f2fs": ("f2fs", 1024), "jfs": ("jfs", 32768), "reiserfs": ("reiserfs", 65536),
            "squashfs": ("squashfs", 0), "erofs": ("erofs", 1024), "nilfs2": ("nilfs2", 1024)}


class _Matcher:
    """Finds the sectors of a buffer that satisfy byte conditions, all sectors at once."""

    def __init__(self) -> None:
        self.tables: dict[frozenset, bytes] = {}
        self.patterns = {k: [(pos, self._tab(vals)) for pos, vals in conds] for k, conds in _PATTERNS.items()}
        self.magics = [(kind, [(at + i, self._tab({ch})) for i, ch in enumerate(magic)], magic, at)
                       for kind, magic, at in _MAGICS]

    def _tab(self, vals) -> bytes:
        key = frozenset(vals)
        t = self.tables.get(key)
        if t is None:
            t = self.tables[key] = _table(vals)
        return t

    @staticmethod
    def match(buf: bytes, nsec: int, conds, cache: dict, limit: int = 4) -> list[int]:
        """Sector indexes where every (position, table) condition holds. The first LIMIT conditions are
        AND-ed column-wise; candidates are then checked one by one against the rest."""
        acc = None
        for pos, tab in conds[:limit]:
            key = (pos, tab)
            v = cache.get(key)
            if v is None:
                v = cache[key] = int.from_bytes(buf[pos:nsec * 512:512].translate(tab), "big")
            acc = v if acc is None else acc & v
            if not acc:
                return []
        if acc is None:
            return []
        flags = acc.to_bytes(nsec, "big")
        out = []
        i = flags.find(1)
        rest = conds[limit:]
        while i >= 0:
            base = i * 512
            if all(tab[buf[base + pos]] for pos, tab in rest):
                out.append(i)
            i = flags.find(1, i + 1)
        return out


class BootSectorDetector(Detector):
    """Finds boot sectors, superblocks and their backups in a whole-disk deep scan (see the module
    docstring). SRC, when given, is used in finish() to read labels the scan couldn't see (NTFS volume
    name, FAT root-folder label...)."""

    TAIL = 192 * 1024

    def __init__(self, src: Source | None = None, max_hits: int = 100_000):
        self.src = src
        self.max_hits = max_hits
        self.m = _Matcher()
        self._tail = b""
        self._tail_off = 0
        self._next: int | None = None
        self._pending: list[tuple[int, str]] = []
        self.hits: dict[str, list] = {}
        self.marks: dict[str, set[int]] = {"mft0": set(), "fatmark": set(), "btree": set()}
        self.agf: list[tuple[int, int, int, str]] = []
        self.capped: set[str] = set()

    # ------------------------------------------------------------------ feeding
    def feed(self, offset: int, buf: bytes) -> None:
        if not isinstance(buf, (bytes, bytearray)):
            buf = bytes(buf)
        if self._next is not None and offset != self._next:
            self._drain()
            self._tail = b""
        if self._pending:
            pending, self._pending = self._pending, []
            for pos, kind in pending:
                self._handle(pos, kind, offset, buf, final=False)
        nsec = len(buf) // 512
        if nsec:
            cache: dict = {}
            for kind, conds in self.m.patterns.items():
                idx = self.m.match(buf, nsec, conds, cache)
                if not idx:
                    continue
                if kind in self.marks:
                    marks = self.marks[kind]
                    for i in idx:
                        if len(marks) >= self.max_hits:
                            self.capped.add(kind)
                            break
                        marks.add(offset + i * 512)
                else:
                    for i in idx:
                        self._handle(offset + i * 512, kind, offset, buf)
            for kind, conds, _magic, _at in self.m.magics:
                for i in self.m.match(buf, nsec, conds, cache, limit=len(conds)):
                    self._handle(offset + i * 512, kind, offset, buf)
        if len(buf) >= self.TAIL:
            self._tail = bytes(buf[-self.TAIL:])
            self._tail_off = offset + len(buf) - self.TAIL
        else:
            joined = self._tail + bytes(buf)
            self._tail = joined[-self.TAIL:]
            self._tail_off = offset + len(buf) - len(self._tail)
        self._next = offset + len(buf)

    def _window(self, lo: int, hi: int, offset: int, buf: bytes, final: bool) -> bytes | None:
        """Bytes [lo, hi) from the tail of the previous chunks and the current one; None when they aren't
        all here yet (unless FINAL: then what's missing is zeros)."""
        cur_hi = offset + len(buf)
        if hi > cur_hi and not final:
            return None
        if lo >= offset:
            piece = buf[lo - offset:hi - offset]
            return bytes(piece) + bytes(hi - lo - len(piece))
        out = bytearray(hi - lo)
        t_lo, t_hi = self._tail_off, self._tail_off + len(self._tail)
        a, b = max(lo, t_lo), min(hi, t_hi, offset if buf else t_hi)
        if a < b:
            out[a - lo:b - lo] = self._tail[a - t_lo:b - t_lo]
        a, b = max(lo, offset), min(hi, cur_hi)
        if a < b and buf:
            out[a - lo:b - lo] = buf[a - offset:b - offset]
        return bytes(out)

    def _handle(self, pos: int, kind: str, offset: int, buf: bytes, final: bool = False) -> None:
        before, after = _NEEDS[kind]
        data = self._window(pos - before, pos + after, offset, buf, final)
        if data is None:
            if len(self._pending) < 10000:
                self._pending.append((pos, kind))
            return
        lst = self.hits.setdefault(kind, [])
        if len(lst) >= self.max_hits:
            self.capped.add(kind)
            return
        try:
            getattr(self, "_hit_" + kind, self._hit_generic)(pos, data, before, kind)
        except (struct.error, IndexError, ValueError, KeyError, TypeError) as exc:
            log.debug("%s hit at %d: %s", kind, pos, exc)

    def _drain(self) -> None:
        pending, self._pending = self._pending, []
        for pos, kind in pending:
            self._handle(pos, kind, self._next or 0, b"", final=True)

    # ------------------------------------------------------------------ parsing hits
    def _add(self, kind: str, item) -> None:
        self.hits.setdefault(kind, []).append(item)

    def _hit_ntfs(self, pos, d, before, kind):
        p = fsdetect.parse_ntfs_boot(d[:512])
        if p:
            self._add(kind, (pos, p))

    def _hit_fat(self, pos, d, before, kind):
        s = d[:512]
        if s[3:11] == b"MSWIN4.1" and s[424:440] == fsdetect._BDE_GUID:
            self._add("bitlocker", (pos, {"fstype": "bitlocker", "version": "to_go", "size": None}))
            return
        p = fsdetect.parse_fat_bpb(s)
        if p:
            self._add(kind, (pos, p))

    def _hit_exfat(self, pos, d, before, kind):
        p = fsdetect.parse_exfat_boot(d[:512])
        if p:
            self._add(kind, (pos, p))

    def _hit_ext(self, pos, d, before, kind):
        p = fsdetect.parse_ext_super(d[:1024])
        if p:
            self._add(kind, (pos, p))

    def _hit_xfs(self, pos, d, before, kind):
        p = fsdetect.parse_xfs_super(d[:512])
        if p:
            self._add(kind, (pos, p))

    def _hit_xagf(self, pos, d, before, kind):
        seqno, length = struct.unpack_from(">II", d, 8)
        uuid = fsdetect._uuid(d[64:80]) if struct.unpack_from(">I", d, 4)[0] == 1 else ""
        if len(self.agf) < self.max_hits:
            self.agf.append((pos, seqno, length, uuid))

    def _hit_btrfs(self, pos, d, before, kind):
        p = fsdetect.parse_btrfs_super(d[:4096])
        if p and p["checksum_ok"] is not False and p["bytenr"] in (65536, 64 * MiB, 256 * 1024 ** 3, 1024 ** 5):
            self._add(kind, (pos, p))

    def _hit_hfsplus(self, pos, d, before, kind):
        p = fsdetect.parse_hfsplus_header(d[:512])
        if p:
            self._add(kind, (pos, p))

    def _hit_apfs(self, pos, d, before, kind):
        p = fsdetect.parse_apfs_super(d[:4096])
        if p and p["checksum_ok"] is not False:
            self._add(kind, (pos, p))

    def _hit_luks(self, pos, d, before, kind):
        ver = struct.unpack_from(">H", d, 6)[0]
        if ver not in (1, 2):
            return
        hdr_off = struct.unpack_from(">Q", d, 256)[0] if ver == 2 else 0
        if d[0:4] == b"SKUL" and (ver != 2 or not hdr_off):
            return
        if hdr_off > pos or hdr_off % 4096:
            return
        label = fsdetect._cstr(d[24:72], "utf-8") if ver == 2 else ""
        self._add(kind, (pos - hdr_off, {"version": str(ver), "uuid": fsdetect._cstr(d[168:208]), "label": label,
                                         "secondary": d[0:4] == b"SKUL"}))

    def _hit_lvm(self, pos, d, before, kind):
        if d[24:32] != b"LVM2 001":
            return
        sector = struct.unpack_from("<Q", d, 8)[0]
        off = struct.unpack_from("<I", d, 20)[0]
        if sector > 3 or not 32 <= off <= 512 - 40 or sector * 512 > pos:
            return
        crc_ok = fsdetect.crc32_raw(0xF597A6CF, d[20:512]) == struct.unpack_from("<I", d, 16)[0]
        uuid = fsdetect._lvm_uuid(d[off:off + 32])
        size = struct.unpack_from("<Q", d, off + 32)[0]
        self._add(kind, (pos - sector * 512, {"uuid": uuid, "size": size or None, "checksum_ok": crc_ok}))

    def _hit_md(self, pos, d, before, kind):
        p = fsdetect.parse_md_super1(d[:4096])
        if p and p["checksum_ok"] is not False and p["super_offset"] <= pos:
            start = pos - p["super_offset"]
            version = {0: "1.1", 4096: "1.2"}.get(p["super_offset"], "1.0")
            size = (p["data_offset"] + p["data_size"]) if version != "1.0" else p["super_offset"] + 8192
            self._add(kind, (start, dict(p, metadata=version, size=size)))
            return
        p = fsdetect.parse_md_super090(d[:4096])
        if p and p["data_size"] <= pos and pos % 65536 == 0:
            start = pos - p["data_size"]
            self._add(kind, (start, dict(p, metadata="0.90", size=p["data_size"] + 65536)))

    def _hit_zfs(self, pos, d, before, kind):
        nv, _ = fsdetect._xdr_nvlist(d[:16384], 4)
        if "pool_guid" not in nv and "guid" not in nv:
            return
        tree = nv.get("vdev_tree") if isinstance(nv.get("vdev_tree"), dict) else {}
        self._add(kind, (pos, {"pool_guid": nv.get("pool_guid"), "guid": nv.get("guid"), "name": nv.get("name") or "",
                               "asize": tree.get("asize"), "txg": nv.get("txg")}))

    def _hit_ufs(self, pos, d, before, kind):
        magic = d[before + 348:before + 352]
        sb_rel = before - 1024                                  # the superblock starts 2 sectors before the magic
        primary = 65536 if magic in (b"\x19\x01\x54\x19", b"\x19\x54\x01\x19") else 8192
        start_rel = sb_rel - primary
        if start_rel < 0 or pos - before + start_rel < 0:
            return
        info = fsdetect.probe_with("ufs", BytesSource(d), start_rel)
        if info:
            self._add(kind, (pos - before + start_rel, info))

    def _hit_generic(self, pos, d, before, kind):
        name, so = _GENERIC[kind]
        if kind == "swap":
            for page in (4096, 8192, 16384, 65536):
                rel = before + 512 - page
                if rel < 0 or pos + 512 - page < 0:
                    continue
                info = fsdetect.probe_with("swap", BytesSource(d), rel)
                if info and info.get("page_size") == page:
                    self._add(kind, (pos + 512 - page, info))
                    return
            return
        rel = before - so
        if pos - so < 0:
            return
        info = fsdetect.probe_with(name, BytesSource(d), rel)
        if info:
            self._add(kind, (pos - so, info))

    # ------------------------------------------------------------------ results
    def finish(self) -> list[dict]:
        self._drain()
        out: list[dict] = []
        for name in ("ntfs", "fat", "exfat", "ext", "xfs", "btrfs", "hfsplus", "apfs", "luks", "lvm", "md", "zfs",
                     "pairs", "single"):
            try:
                out.extend(getattr(self, "_finish_" + name)())
            except (KeyError, TypeError, ValueError, struct.error, IndexError) as exc:
                log.warning("partition search: couldn't use the %s structures found: %s", name, exc)
        if self.capped:
            log.info("partition search: too many %s structures; only the first ones were used", ", ".join(self.capped))
        if self.src is not None:
            for c in out:
                _refine(self.src, c)
        return out

    def _finish_ntfs(self) -> list[dict]:
        hits = self.hits.get("ntfs") or []
        by_pos = {pos: p for pos, p in hits}
        mft = self.marks["mft0"]
        used: set[int] = set()
        out = []
        for pos, p in sorted(hits, key=lambda h: h[0]):
            if pos in used:
                continue
            span = p["total_sectors"] * p["sector_size"]
            back = by_pos.get(pos + span)

            def mft_at(start: int, p=p) -> bool:
                return start + p["mft_offset"] in mft or start + p["mftmirr_offset"] in mft
            info = dict(p, fstype="ntfs", block_size=p["cluster_size"], uuid=f"{p['serial']:016X}")
            if _same_ntfs(back, p):
                used.update((pos, pos + span))
                score = S_PAIR if mft_at(pos) else S_CHECKED
                out.append(_cand("ntfs", pos, p["size"], ["boot sector", "backup boot sector"], score, info))
                continue
            main_ok = mft_at(pos)
            start_b = pos - span
            back_ok = start_b >= 0 and mft_at(start_b)
            if back_ok and not main_ok:
                used.add(pos)
                out.append(_cand("ntfs", start_b, p["size"], ["backup boot sector", "MFT"], S_BACKUP_OK,
                                 dict(info, reconstructed=True), primary=False))
            else:
                out.append(_cand("ntfs", pos, p["size"], ["boot sector"] + (["MFT"] if main_ok else []),
                                 S_CHECKED if main_ok else S_MAIN - 10, info))
        return out

    def _finish_fat(self) -> list[dict]:
        hits = self.hits.get("fat") or []
        by_pos = {pos: p for pos, p in hits}
        fat = self.marks["fatmark"]
        used: set[int] = set()
        out = []
        for pos, p in sorted(hits, key=lambda h: h[0]):
            if pos in used:
                continue
            bps = p["sector_size"]
            fstype = f"fat{p['fat_bits']}"
            info = dict(p, fstype=fstype, block_size=p["cluster_size"], label=p["bpb_label"])
            if p["fat_bits"] != 32:
                ok = pos + p["reserved_sectors"] * bps in fat
                out.append(_cand(fstype, pos, p["size"], ["boot sector"] + (["FAT"] if ok else []),
                                 S_CHECKED if ok else S_MAIN - 15, info))
                continue
            bk = p.get("backup_boot_sector") or 0
            back = by_pos.get(pos + bk * bps) if bk else None
            if back and back["serial"] == p["serial"] and back["total_sectors"] == p["total_sectors"]:
                used.update((pos, pos + bk * bps))
                out.append(_cand(fstype, pos, p["size"], ["boot sector", "backup boot sector"], S_PAIR, info))
                continue
            main_ok = pos + p["reserved_sectors"] * bps in fat
            start_b = pos - bk * bps if bk else -1
            back_ok = start_b >= 0 and start_b + p["reserved_sectors"] * bps in fat
            if back_ok and not main_ok:
                used.add(pos)
                out.append(_cand(fstype, start_b, p["size"], ["backup boot sector", "FAT"], S_BACKUP_OK,
                                 dict(info, reconstructed=True), primary=False))
            else:
                out.append(_cand(fstype, pos, p["size"], ["boot sector"] + (["FAT"] if main_ok else []),
                                 S_CHECKED if main_ok else S_MAIN - 15, info))
        return out

    def _finish_exfat(self) -> list[dict]:
        hits = self.hits.get("exfat") or []
        by_pos = {pos: p for pos, p in hits}
        fat = self.marks["fatmark"]
        used: set[int] = set()
        out = []
        for pos, p in sorted(hits, key=lambda h: h[0]):
            if pos in used:
                continue
            bps = p["sector_size"]
            info = dict(p, fstype="exfat", block_size=p["cluster_size"])
            back = by_pos.get(pos + 12 * bps)
            if back and back["serial"] == p["serial"]:
                used.update((pos, pos + 12 * bps))
                out.append(_cand("exfat", pos, p["size"], ["boot sector", "backup boot sector"], S_PAIR, info))
                continue
            main_ok = pos + p["fat_offset"] * bps in fat
            start_b = pos - 12 * bps
            back_ok = start_b >= 0 and start_b + p["fat_offset"] * bps in fat
            if back_ok and not main_ok:
                used.add(pos)
                out.append(_cand("exfat", start_b, p["size"], ["backup boot sector", "FAT"], S_BACKUP_OK,
                                 dict(info, reconstructed=True), primary=False))
            else:
                out.append(_cand("exfat", pos, p["size"], ["boot sector"] + (["FAT"] if main_ok else []),
                                 S_CHECKED if main_ok else S_MAIN - 10, info))
        return out

    def _finish_ext(self) -> list[dict]:
        groups: dict[tuple, dict] = {}
        for pos, p in self.hits.get("ext") or []:
            g = p["group"]
            if g == 0:
                start = pos - 1024
            elif g < 0xFFFF:
                start = pos - (p["first_data_block"] + g * p["blocks_per_group"]) * p["block_size"]
            else:
                continue
            if start < 0:
                continue
            e = groups.setdefault((p["uuid"], start, p["block_size"]), {"primary": None, "backups": []})
            if g == 0:
                e["primary"] = (pos, p)
            else:
                e["backups"].append((pos, p))
        out = []
        for (_uuid, start, _bs), e in groups.items():
            nb = len(e["backups"])
            pos, p = e["primary"] or e["backups"][0]
            fstype = p["fstype"]
            info = {k: v for k, v in p.items() if k != "fstype"}
            info["fstype"] = fstype
            if e["primary"]:
                ev = ["superblock"] + (["backup superblock"] if nb else [])
                out.append(_cand(fstype, start, p["size"], ev, S_PAIR if nb else S_MAIN, info))
            else:
                info.update(reconstructed=True, superblock_offset=pos - start)
                out.append(_cand(fstype, start, p["size"], [f"backup superblock{'s' if nb > 1 else ''}"],
                                 S_BACKUP_OK if nb > 1 else S_BACKUP, info, primary=False))
        return out

    def _finish_xfs(self) -> list[dict]:
        groups: dict[str, list] = {}
        for pos, p in self.hits.get("xfs") or []:
            groups.setdefault(p["uuid"], []).append((pos, p))
        out = []
        for uuid, hits in groups.items():
            hits.sort(key=lambda h: h[0])
            p = hits[0][1]
            d = p["ag_blocks"] * p["block_size"]
            positions = {pos for pos, _ in hits}
            votes: dict[int, int] = {}
            for apos, seqno, _length, auuid in self.agf:
                if auuid and auuid != uuid or seqno >= p["ag_count"]:
                    continue
                s = apos - p["sector_size"] - seqno * d
                if s >= 0 and any((x - s) % d == 0 and 0 <= (x - s) // d < p["ag_count"] for x in positions):
                    votes[s] = votes.get(s, 0) + 1
            start = max(votes, key=lambda s: (votes[s], -s)) if votes else hits[0][0]
            primary = start in positions
            copies = sum(1 for x in positions if x != start and (x - start) % d == 0)
            info = dict(p, fstype="xfs")
            if primary:
                ev = ["superblock"] + (["superblock copy"] if copies else [])
                out.append(_cand("xfs", start, p["size"], ev, S_PAIR if copies else S_MAIN, info))
            else:
                ev = ["superblock copy"] + (["AG headers"] if votes else [])
                out.append(_cand("xfs", start, p["size"], ev, S_BACKUP_OK if votes else S_BACKUP,
                                 dict(info, reconstructed=True), primary=False))
        return out

    def _finish_btrfs(self) -> list[dict]:
        groups: dict[tuple, list] = {}
        for pos, p in self.hits.get("btrfs") or []:
            start = pos - p["bytenr"]
            if start >= 0:
                groups.setdefault((p["uuid"], p["devid"], start), []).append(p)
        out = []
        for (_uuid, _devid, start), ps in groups.items():
            main = next((p for p in ps if p["bytenr"] == 65536), None)
            p = main or max(ps, key=lambda q: q["generation"])
            info = dict(p, fstype="btrfs", size=p["dev_size"] or p["total_bytes"], block_size=p["sector_size"])
            if main:
                ev = ["superblock"] + (["superblock copy"] if len(ps) > 1 else [])
                out.append(_cand("btrfs", start, info["size"], ev, S_PAIR if len(ps) > 1 else S_CHECKED, info))
            else:
                out.append(_cand("btrfs", start, info["size"], ["superblock copy"], S_BACKUP_OK, info, primary=False))
        return out

    def _finish_hfsplus(self) -> list[dict]:
        hits = sorted(self.hits.get("hfsplus") or [], key=lambda h: h[0])
        btree = self.marks["btree"]
        used: set[int] = set()
        out = []
        by_key: dict[tuple, list[int]] = {}
        for pos, p in hits:
            by_key.setdefault((p["create_date"], p["total_blocks"], p["block_size"]), []).append(pos)
        for pos, p in hits:
            if pos in used:
                continue
            bs, size = p["block_size"], p["size"]
            cat = p["catalog_extents"][0][0] * bs
            info = dict(p, fstype=p["fstype"], volume_id=p["volume_id"].hex(), catalog_extents=None)
            twins = [q for q in by_key[(p["create_date"], p["total_blocks"], bs)] if q > pos and q not in used]
            alt = next((q for q in twins if size <= q + 1024 - (pos - 1024) < size + bs + 1024), None)
            if alt is not None:
                used.update((pos, alt))
                out.append(_cand(p["fstype"], pos - 1024, alt + 1024 - (pos - 1024),
                                 ["volume header", "alternate volume header"], S_PAIR, info))
                continue
            main_ok = (pos - 1024 + cat) in btree
            start_alt = None
            for slack in range(0, bs + 1024, 512):
                s = pos + 1024 - size - slack
                if s >= 0 and s + cat in btree:
                    start_alt = s
                    break
            if start_alt is not None and not main_ok:
                used.add(pos)
                out.append(_cand(p["fstype"], start_alt, pos + 1024 - start_alt, ["alternate volume header", "catalog"],
                                 S_BACKUP_OK, dict(info, reconstructed=True), primary=False))
            elif pos >= 1024:
                out.append(_cand(p["fstype"], pos - 1024, size, ["volume header"] + (["catalog"] if main_ok else []),
                                 S_CHECKED if main_ok else S_MAIN - 10, info))
        return out

    def _finish_apfs(self) -> list[dict]:
        groups: dict[str, list] = {}
        for pos, p in self.hits.get("apfs") or []:
            groups.setdefault(p["uuid"], []).append((pos, p))
        out = []
        for _uuid, hits in groups.items():
            hits.sort(key=lambda h: h[0])
            copies: set[int] = set()
            for pos, p in hits:
                lo = pos + p["xp_desc_base"] * p["block_size"]
                hi = lo + p["xp_desc_blocks"] * p["block_size"]
                copies.update(q for q, _ in hits if lo <= q < hi)
            for pos, p in hits:
                if pos in copies:
                    continue
                n = sum(1 for q in copies if q > pos)
                info = dict(p, fstype="apfs")
                out.append(_cand("apfs", pos, p["size"], ["container superblock"] + (["checkpoint copies"] if n else []),
                                 S_PAIR if n else S_CHECKED, info))
        return out

    def _finish_luks(self) -> list[dict]:
        groups: dict[tuple, list] = {}
        for start, p in self.hits.get("luks") or []:
            groups.setdefault((start, p["uuid"]), []).append(p)
        out = []
        for (start, _uuid), ps in groups.items():
            main = next((p for p in ps if not p["secondary"]), None)
            p = main or ps[0]
            info = {"fstype": "crypto_luks", "version": p["version"], "uuid": p["uuid"], "label": p["label"]}
            if main:
                ev = ["LUKS header"] + (["second LUKS header"] if len(ps) > 1 else [])
                out.append(_cand("crypto_luks", start, None, ev, S_PAIR if len(ps) > 1 else S_MAIN, info))
            else:
                out.append(_cand("crypto_luks", start, None, ["second LUKS header"], S_BACKUP_OK,
                                 dict(info, primary_header_damaged=True), primary=False))
        return out

    def _finish_lvm(self) -> list[dict]:
        seen = set()
        out = []
        for start, p in self.hits.get("lvm") or []:
            if (start, p["uuid"]) in seen:
                continue
            seen.add((start, p["uuid"]))
            info = dict(p, fstype="lvm2_member")
            out.append(_cand("lvm2_member", start, p["size"], ["LVM label"], S_CHECKED if p["checksum_ok"] else S_MAIN - 15,
                             info))
        return out

    def _finish_md(self) -> list[dict]:
        seen = set()
        out = []
        for start, p in self.hits.get("md") or []:
            key = (start, p["uuid"], p.get("uuid_sub"))
            if key in seen:
                continue
            seen.add(key)
            info = dict(p, fstype="linux_raid_member", label=p.get("name") or "")
            score = S_CHECKED if p.get("checksum_ok") else S_MAIN - 10
            out.append(_cand("linux_raid_member", start, p["size"], ["RAID superblock"], score, info))
        return out

    def _finish_zfs(self) -> list[dict]:
        groups: dict[tuple, list] = {}
        for pos, p in self.hits.get("zfs") or []:
            groups.setdefault((p["pool_guid"], p["guid"]), []).append((pos, p))
        out = []
        for _key, hits in groups.items():
            positions = sorted({pos for pos, _ in hits})
            pairs = [x for x in positions if x + 262144 in positions]
            p = hits[0][1]
            info = {"fstype": "zfs_member", "label": p["name"], "uuid": str(p["pool_guid"] or ""),
                    "uuid_sub": str(p["guid"] or ""), "asize": p["asize"], "txg": p["txg"]}
            if not pairs:
                continue
            start = pairs[0] - 16384
            size = None
            if len(pairs) > 1 and pairs[-1] - pairs[0] >= 512 * 1024:
                size = pairs[-1] - 16384 + 524288 - start
            elif isinstance(p["asize"], int) and p["asize"] > 0:
                size = p["asize"] + 4 * MiB + 512 * 1024
                info["size_estimated"] = True
            if start >= 0:
                out.append(_cand("zfs_member", start, size, ["ZFS labels"], S_CHECKED if len(pairs) > 1 else S_MAIN,
                                 info))
        return out

    def _finish_pairs(self) -> list[dict]:
        """F2FS and JFS keep a second superblock at a fixed distance: a pair fixes the start."""
        out = []
        for kind, fstype, gap in (("f2fs", "f2fs", 4096), ("jfs", "jfs", 61440 - 32768)):
            hits = sorted(self.hits.get(kind) or [], key=lambda h: h[0])
            starts = {s for s, _ in hits}
            done: set[int] = set()
            for start, info in hits:
                if start in done:
                    continue
                if start + gap in starts:
                    done.update((start, start + gap))
                    out.append(_cand(fstype, start, info.get("size"), ["superblock", "superblock copy"], S_PAIR, info))
                elif start - gap in starts:
                    continue
                else:
                    out.append(_cand(fstype, start, info.get("size"), ["superblock"], S_MAIN - 10, info))
        return out

    def _finish_single(self) -> list[dict]:
        out = []
        seen = set()
        for kind in ("refs", "bitlocker", "swap", "iso9660", "reiserfs", "squashfs", "erofs", "nilfs2", "ufs"):
            for start, info in self.hits.get(kind) or []:
                fstype = info.get("fstype") or kind
                key = (fstype, start, info.get("uuid"))
                if key in seen:
                    continue
                seen.add(key)
                score = S_CHECKED if info.get("checksum_ok") else S_MAIN
                if kind in ("ufs",):
                    if any(k[0] == "ufs" and k[2] == info.get("uuid") and k[1] < start for k in seen if k != key):
                        continue                        # a cylinder-group copy of a volume already found
                out.append(_cand(fstype, start, info.get("size"), [fsdetect.evidence_of(fstype)], score, info))
        return out


def _refine(src: Source, c: dict) -> None:
    """Fill in what the deep scan couldn't see in a sector (labels, versions) by probing the volume."""
    if c["fstype"] == "ntfs" and not c.get("primary") and not c.get("label"):
        label, version = fsdetect.ntfs_label(src, c["offset"], c["info"])
        if label:
            c["label"] = c["info"]["label"] = label
        if version:
            c["info"]["version"] = version
    if not c.get("primary"):
        return
    try:
        info = fsdetect.identify_at(src, c["offset"])
    except Exception:  # noqa: BLE001
        return
    if not info or family(info.get("fstype")) != family(c["fstype"]):
        return
    for k in ("label", "uuid"):
        if info.get(k) and not c.get(k):
            c[k] = info[k]
    for k, v in info.items():
        c["info"].setdefault(k, v)
    if info.get("label"):
        c["info"]["label"] = info["label"]


# ====================================================================== merging
def _is_primary(c: dict) -> bool | None:
    if "primary" in c:
        return c["primary"]
    ev = " ".join(c.get("evidences") or [c.get("evidence") or ""]).lower()
    if not ev or ev in ("partition table", "backup gpt"):
        return None
    if any(w in ev for w in _BACKUP_WORDS + _META_WORDS) and not any(
            w in ev for w in ("boot sector", "superblock", "volume header")) or ev.startswith(_BACKUP_WORDS):
        return False
    return True


def _normalize(c: dict, disk_size: int) -> dict | None:
    if not isinstance(c, dict):
        return None
    try:
        off = int(c.get("offset"))
    except (TypeError, ValueError):
        return None
    if off < 0 or off >= disk_size:
        return None
    try:
        size = int(c.get("size") or 0) or None
    except (TypeError, ValueError):
        size = None
    if size is not None and size <= 0:
        size = None
    evs = list(c.get("evidences") or ([e.strip() for e in str(c["evidence"]).split(",")] if c.get("evidence") else []))
    return {"fstype": c.get("fstype") or "unknown", "offset": off, "size": size, "evidences": evs,
            "base_score": int(c.get("base_score", c.get("score")) or 0), "label": c.get("label") or "",
            "uuid": c.get("uuid") or "", "info": dict(c.get("info") or {}), "primary": _is_primary(c),
            "partition": c.get("partition"), "from_table": c.get("from_table")}


def _same_size(a: int | None, b: int | None, ss: int) -> bool:
    if a is None or b is None:
        return True
    return abs(a - b) <= max(4 * ss, min(a, b) // 1000)


def _absorb(a: dict, b: dict) -> None:
    for e in b["evidences"]:
        if e not in a["evidences"]:
            a["evidences"].append(e)
    a["base_score"] = max(a["base_score"], b["base_score"])
    if a["primary"] is True or b["primary"] is True:
        a["primary"] = True
    elif a["primary"] is False or b["primary"] is False:
        a["primary"] = False
    if a["fstype"] == "unknown" and b["fstype"] != "unknown":
        a["fstype"], a["size"], a["info"] = b["fstype"], b["size"] or a["size"], dict(b["info"])
    if not a["size"] and b["size"]:
        a["size"] = b["size"]
    for k in ("label", "uuid"):
        if not a[k] and b[k]:
            a[k] = b[k]
    for k, v in b["info"].items():
        a["info"].setdefault(k, v)
    if b.get("partition") and (not a.get("partition") or b.get("from_table") == "partition table"):
        a["partition"] = b["partition"]
        a["from_table"] = b.get("from_table") or a.get("from_table")


def _partition_aligned(off: int, ss: int) -> bool:
    return off % MiB == 0 or (ss == 512 and off % (63 * 512) == 0)


def _select(items: list[dict], ss: int) -> set[int]:
    """Weighted interval scheduling: the indexes of the non-overlapping candidates with the most support."""
    iv = []
    for i, it in enumerate(items):
        end = it["offset"] + (it["size"] or ss)
        w = it["score"] * 100 + (1000 if it["in_table"] else 0) + (300 if it["primary"] else 0) \
            + (0 if it["fstype"] == "unknown" else 50)
        iv.append((end, it["offset"], w, i))
    iv.sort()
    ends = [e for e, _s, _w, _i in iv]
    best = [0] * (len(iv) + 1)
    take = [False] * len(iv)
    for k, (_e, start, w, _i) in enumerate(iv):
        j = bisect.bisect_right(ends, start, 0, k)
        with_k = w + best[j]
        if with_k > best[k]:
            best[k + 1] = with_k
            take[k] = True
        else:
            best[k + 1] = best[k]
    chosen: set[int] = set()
    k = len(iv) - 1
    while k >= 0:
        if take[k]:
            chosen.add(iv[k][3])
            k = bisect.bisect_right(ends, iv[k][1], 0, k) - 1
        else:
            k -= 1
    return chosen


def merge_candidates(cands, disk_size: int, sector_size: int = 512, table: dict | None = None) -> list[dict]:
    """Combine the candidates of every detector into one list sorted by offset, each with: fstype, offset,
    size, evidence (and evidences), score, label, uuid, info, status ("current", "deleted", "damaged"),
    in_table (partition number), partition (its table entry), inside (offset of the volume it lies in),
    overlaps (offsets of the chosen volumes it conflicts with), truncated, size_guessed and proposed (part
    of the suggested table)."""
    ss = int(sector_size or 512)
    items = [n for n in (_normalize(c, disk_size) for c in cands or []) if n]
    by_off: dict[int, list[dict]] = {}
    for it in items:
        by_off.setdefault(it["offset"], []).append(it)
    merged: list[dict] = []
    for _off, group in sorted(by_off.items()):
        # a volume rebuilt from scattered metadata (MFT records) has a size rounded to its clusters: the
        # boot sector's exact size wins when both are found
        known = sorted((g for g in group if g["fstype"] != "unknown"),
                       key=lambda g: (bool(g["info"].get("reconstructed")), -g["base_score"], g["primary"] is not True))
        unknown = [g for g in group if g["fstype"] == "unknown"]
        clusters: list[dict] = []
        for it in known:
            for cl in clusters:
                if family(cl["fstype"]) == family(it["fstype"]) and _same_size(cl["size"], it["size"], ss):
                    _absorb(cl, it)
                    break
            else:
                clusters.append(it)
        if unknown:
            target = clusters[0] if clusters else unknown[0]
            for u in unknown:
                if u is not target:
                    _absorb(target, u)
            if not clusters:
                clusters.append(target)
        merged.extend(clusters)

    tparts = {int(p["start"]): p for p in (table or {}).get("partitions") or [] if not p.get("extended")}
    for m in merged:
        evs = [e for e in m["evidences"] if e not in ("partition table", "backup GPT")]
        score = m["base_score"] + 5 * max(0, len(set(evs)) - 1)
        if m["primary"] is True and any(any(w in e.lower() for w in _BACKUP_WORDS) for e in evs):
            score = max(score, S_PAIR)
        m["score"] = min(100, score)
        if m["primary"] is True:
            m["info"].pop("reconstructed", None)
        p = tparts.get(m["offset"])
        m["in_table"] = p["number"] if p else None
        m["table_size"] = p["size"] if p else None
        if p:
            m["partition"] = {k: p.get(k) for k in ("number", "start", "size", "type", "type_name", "name", "guid",
                                                    "bootable", "logical", "attrs")}
        if m["fstype"] != "unknown" and m["primary"] is False:
            m["status"] = "damaged"
        elif p:
            m["status"] = "current"
        else:
            m["status"] = "deleted"
        m["truncated"] = bool(m["size"] and m["offset"] + m["size"] > disk_size + ss)
        m["inside"] = None
        m["overlaps"] = []
        m["size_guessed"] = False
        m["proposed"] = False

    # nesting: inside a container, or at a place no partition starts inside a well-identified volume
    active: list[dict] = []                 # volumes still open at the current offset
    for b in sorted(merged, key=lambda m: (m["offset"], -(m["size"] or 0))):
        active = [a for a in active if a["offset"] + a["size"] > b["offset"]]
        if not b["in_table"]:
            b_end = b["offset"] + (b["size"] or ss)
            best = None
            for a in active:
                if a["offset"] < b["offset"] and b_end <= a["offset"] + a["size"] and (
                        a["fstype"] in CONTAINERS or (a["primary"] is True and a["fstype"] != "unknown"
                                                      and not _partition_aligned(b["offset"], ss))):
                    if best is None or a["size"] < best["size"]:
                        best = a
            if best is not None:
                b["inside"] = best["offset"]
        if b["size"] and not b["truncated"] and len(active) < 1000:
            active.append(b)

    eligible = [m for m in merged if m["inside"] is None and not m["truncated"]]
    chosen = _select(eligible, ss)
    selected = sorted((eligible[i] for i in chosen), key=lambda m: m["offset"])
    for m in selected:
        m["proposed"] = True
    for k, m in enumerate(selected):
        if m["size"] is None:
            nxt = selected[k + 1]["offset"] if k + 1 < len(selected) else disk_size
            m["size"] = max(ss, (nxt - m["offset"]) // ss * ss)
            m["size_guessed"] = True
    for m in eligible:
        if m["proposed"]:
            continue
        end = m["offset"] + (m["size"] or ss)
        m["overlaps"] = [s["offset"] for s in selected if s["offset"] < end and m["offset"] < s["offset"] + s["size"]]

    out = []
    for m in sorted(merged, key=lambda m: (m["offset"], -m["score"])):
        out.append({"fstype": m["fstype"], "offset": m["offset"], "size": m["size"],
                    "end": m["offset"] + m["size"] if m["size"] else None, "evidence": ", ".join(m["evidences"]),
                    "evidences": m["evidences"], "score": m["score"], "base_score": m["base_score"],
                    "label": m["label"] or m["info"].get("label") or "", "uuid": m["uuid"] or m["info"].get("uuid") or "",
                    "info": m["info"], "primary": m["primary"], "status": m["status"], "in_table": m["in_table"],
                    "table_size": m["table_size"], "partition": m.get("partition"), "from_table": m.get("from_table"),
                    "inside": m["inside"], "overlaps": m["overlaps"], "truncated": m["truncated"],
                    "size_guessed": m["size_guessed"], "proposed": m["proposed"]})
    return out


# ====================================================================== proposing a table
def _role(c: dict) -> str | None:
    t = str((c.get("partition") or {}).get("type") or "").upper()
    from .partitions import BIOS_BOOT, EFI_SYSTEM, MS_RESERVED, WIN_RECOVERY
    for guid, role in ((EFI_SYSTEM, "esp"), (MS_RESERVED, "msr"), (WIN_RECOVERY, "recovery"), (BIOS_BOOT, "bios_boot")):
        if t == guid:
            return role
    if t.lower() in ("0xef",):
        return "esp"
    if c.get("fstype") in ("fat12", "fat16", "fat32") and (c.get("label") or "").upper() in ("EFI", "ESP", "SYSTEM",
                                                                                            "EFI SYSTEM"):
        return "esp"
    return None


def propose_table(merged: list[dict], disk_size: int, sector_size: int = 512, table_type: str = "gpt") -> list[dict]:
    """The partitions of a table that holds every proposed volume, ready for partitions.plan_table:
    [{"start", "size", "type", "name", "guid", "bootable", "logical", "fstype", "label", "status"}]. Sizes are
    the filesystem's (rounded up to a sector) or the old table's when that was bigger; GPT names come from
    the old entries or the volume labels; MBR tables get logical partitions when more than 4 are needed."""
    from .partitions import _gpt_layout, is_extended, type_for
    ss = int(sector_size or 512)
    sel = sorted((c for c in merged if c.get("proposed")), key=lambda c: c["offset"])
    first, last = _gpt_layout(disk_size, ss)
    parts: list[dict] = []
    for k, c in enumerate(sel):
        start = c["offset"]
        if start % ss:
            continue
        if table_type == "gpt" and start < first * ss:
            continue
        if table_type == "dos" and start < ss:
            continue
        size = -(-int(c["size"] or 0) // ss) * ss
        tp = c.get("partition") or {}
        if tp.get("size") and int(tp["start"]) == start and int(tp["size"]) >= size:
            size = int(tp["size"])
        limit = sel[k + 1]["offset"] if k + 1 < len(sel) else (
            (last + 1) * ss if table_type == "gpt" else disk_size // ss * ss)
        size = min(size, limit - start)
        if size <= 0:
            continue
        t = tp.get("type")
        role = _role(c)
        ok_type = t and ((table_type == "gpt" and len(str(t)) == 36) or (table_type == "dos" and len(str(t)) != 36
                                                                          and not is_extended(t)))
        if not ok_type or c["fstype"] != "unknown" and _type_conflicts(str(t), c["fstype"]):
            t = type_for(c["fstype"] if c["fstype"] != "unknown" else "", table_type, role)
        name = tp.get("name") or (c.get("label") or "") if table_type == "gpt" else ""
        parts.append({"start": start, "size": size, "type": t, "name": name,
                      "guid": tp.get("guid") or "" if table_type == "gpt" else "",
                      "bootable": bool(tp.get("bootable")) if table_type == "dos" else False,
                      "attrs": int(tp.get("attrs") or 0) if table_type == "gpt" else 0,
                      "logical": bool(tp.get("logical")), "fstype": c["fstype"], "label": c.get("label") or "",
                      "status": c.get("status")})
    if table_type == "dos":
        _choose_logicals(parts, ss)
    else:
        for p in parts:
            p["logical"] = False
    return parts


def _type_conflicts(t: str, fstype: str) -> bool:
    """The old table's type clearly doesn't fit what is there now (e.g. a Linux type over NTFS)."""
    from .partitions import LINUX_FS, LINUX_SWAP, MS_BASIC_DATA, norm_mbr_type
    windows = fstype in ("ntfs", "exfat", "refs", "bitlocker", "fat12", "fat16", "fat32")
    linux = fstype in ("ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs", "nilfs2")
    if len(t) == 36:
        tu = t.upper()
        return (windows and tu in (LINUX_FS, LINUX_SWAP)) or (linux and tu == MS_BASIC_DATA) or \
            (fstype == "swap" and tu != LINUX_SWAP and tu in (LINUX_FS, MS_BASIC_DATA))
    b = norm_mbr_type(t)
    return (windows and b in ("0x83", "0x82", "0x8e", "0xfd")) or (linux and b in ("0x07", "0x0b", "0x0c", "0x0e",
                                                                                       "0x06", "0x01", "0x04")) or \
        (fstype == "swap" and b in ("0x83", "0x07"))


def _choose_logicals(parts: list[dict], ss: int) -> None:
    """Mark which partitions become logical ones so that an MBR can hold them all."""
    n = len(parts)

    def room_before(i: int) -> bool:
        prev_end = parts[i - 1]["start"] + parts[i - 1]["size"] if i else ss
        return parts[i]["start"] - prev_end >= ss

    def valid(lo: int, hi: int) -> bool:          # parts[lo:hi] logical
        if hi - lo <= 0:
            return n <= 4
        if n - (hi - lo) > 3:
            return False
        return all(room_before(i) for i in range(lo, hi))

    flags = [p["logical"] for p in parts]
    if any(flags):
        lo = flags.index(True)
        hi = n - flags[::-1].index(True)
        if all(flags[lo:hi]) and valid(lo, hi):
            return
    if n <= 4:
        for p in parts:
            p["logical"] = False
        return
    for lo in (3, 2, 1, 0):
        for after in range(0, 4 - lo):
            hi = n - after
            if hi - lo >= 1 and valid(lo, hi):
                for i, p in enumerate(parts):
                    p["logical"] = lo <= i < hi
                return
    for i, p in enumerate(parts):          # no valid layout: let plan_table explain why
        p["logical"] = i >= 3
