"""Boot sector and partition-table repairs (TestDisk's "Advanced" menu): find what is damaged, and put it
right from the copy every format keeps.

What is checked (:func:`diagnose`)
    NTFS     the boot sector and its backup (the sector after the volume): missing, damaged, different.
    FAT32    the boot sector and its backup (usually sector 6), the FSInfo sector; on every FAT, whether
             the two copies of the allocation table agree (and which one looks right).
    exFAT    the main and backup boot regions (12 sectors each, protected by a checksum sector).
    ext      a damaged main superblock: the backup superblocks that are intact, for ``e2fsck -b N -B bs``
             (run by the filesystem-check module; this one only finds and reports them).
    GPT      the main and backup headers and partition lists (CRC-32s), the backup's place at the end of
             the disk, the protective MBR.
    MBR      the 55 AA signature.

Every fix first saves what it overwrites (:mod:`rawwrite`, so Undo works), refuses a mounted or busy
target, writes synchronously and reads back. Fixes return {"backup": path, "written": [[offset, length]]}.
"""

from __future__ import annotations

import logging
import struct
import zlib

from . import rawwrite
from .blockio import FileSource, Source
from .errors import RallError, UnsafeOperation
from .fsdetect import (
    exfat_boot_checksum,
    parse_exfat_boot,
    parse_ext_super,
    parse_fat_bpb,
    parse_ntfs_boot,
)
from .util import MiB

log = logging.getLogger(__name__)

FAT_COMPARE_LIMIT = 64 * MiB      # larger FATs are compared on their first 64 MiB


def _problem(pid: str, title: str, detail: str, severity: str, fixes: list[tuple[str, dict, str]] | None = None,
             **extra) -> dict:
    """A problem as the GUI and CLI show it: FIX is the recommended action ("boot:<function>" or
    "fsck:<id>") with FIX_OPTIONS for it, FIXES every possible one."""
    fl = [{"action": a, "options": o, "title": t} for a, o, t in fixes or []]
    d = {"id": pid, "title": title, "detail": detail, "severity": severity,
         "fix": fl[0]["action"] if fl else None, "fix_options": fl[0]["options"] if fl else {}, "fixes": fl}
    d.update(extra)
    return d


def _backup_dir(backup_dir: str | None) -> str:
    if backup_dir:
        return backup_dir
    from .config import backups_dir
    return str(backups_dir())


# ====================================================================== diagnosis
def diagnose(src: Source, offset: int = 0, size: int | None = None, fstype: str = "") -> list[dict]:
    """The problems found in the boot structures of the volume at [OFFSET, OFFSET+SIZE) of SRC (a whole disk
    or an image); with OFFSET 0 on a whole disk, the partition table too. FSTYPE may be empty (the volume
    wasn't recognized — its boot sector may be the damaged part)."""
    size = int(size or (src.size - offset))
    vol = src.region(offset, size)
    fstype = (fstype or "").lower()
    out: list[dict] = []
    if offset == 0 and (fstype in ("", "gpt", "dos", "mbr", "disk", "table") or size == src.size):
        try:
            out.extend(_diag_table(src))
        except (RallError, struct.error, IndexError, ValueError) as exc:
            log.debug("table diagnosis failed: %s", exc)
    if fstype in ("gpt", "dos", "mbr", "disk", "table"):
        return out
    checks = []
    if fstype in ("", "ntfs"):
        checks.append(_diag_ntfs)
    if fstype in ("", "fat12", "fat16", "fat32", "vfat"):
        checks.append(_diag_fat)
    if fstype in ("", "exfat"):
        checks.append(_diag_exfat)
    if fstype in ("", "ext2", "ext3", "ext4"):
        checks.append(_diag_ext)
    for fn in checks:
        try:
            out.extend(fn(vol, size, fstype))
        except (RallError, struct.error, IndexError, ValueError, KeyError) as exc:
            log.debug("%s failed: %s", fn.__name__, exc)
    return out


# ---------------------------------------------------------------------- NTFS
def _ntfs_backup(vol: Source, size: int, p0: dict | None) -> tuple[int | None, dict | None, bytes]:
    """Where the backup boot sector is (relative to the volume), what it holds, and its raw bytes."""
    places = []
    if p0:
        places.append(p0["total_sectors"] * p0["sector_size"])
    for bps in (512, 4096):
        if size >= 2 * bps:
            places.append(size - bps)
    for loc in places:
        if loc + 512 > size and loc != places[0]:
            continue
        raw = vol.read(loc, 512)
        p = parse_ntfs_boot(raw)
        if p and (p0 is None or loc == p["total_sectors"] * p["sector_size"] or loc == size - p["sector_size"]):
            return loc, p, vol.read(loc, p["sector_size"])
    return (places[0] if places else None), None, b""


def _diag_ntfs(vol: Source, size: int, fstype: str) -> list[dict]:
    b0 = vol.read(0, 512)
    p0 = parse_ntfs_boot(b0)
    loc, pb, braw = _ntfs_backup(vol, size, p0)
    if p0 is None and pb is None:
        if fstype == "ntfs":
            return [_problem("ntfs_boot_lost", "Both NTFS boot sectors are damaged",
                             "Neither the boot sector nor its backup at the end of the partition can be read. A deep "
                             "search can still find the files through the MFT.", "error")]
        return []
    to_primary = ("boot:ntfs_boot", {"direction": "backup_to_primary"}, "Copy the backup boot sector over the first one")
    to_backup = ("boot:ntfs_boot", {"direction": "primary_to_backup"}, "Copy the boot sector over its backup")
    if p0 is None:
        what = "is empty" if not any(b0) else "is damaged"
        return [_problem("ntfs_boot_damaged", "The NTFS boot sector is damaged",
                         f"The first sector of the volume {what}, but the backup boot sector at the end of the "
                         "partition is intact: copying it back makes the volume readable again.", "error",
                         [to_primary], backup_offset=loc)]
    if pb is None:
        return [_problem("ntfs_backup_damaged", "The NTFS backup boot sector is missing",
                         "The boot sector is fine but its backup (in the sector after the volume) is missing or "
                         "damaged; Windows' chkdsk complains about this. Writing a fresh copy is safe.", "warning",
                         [to_backup], backup_offset=p0["total_sectors"] * p0["sector_size"])]
    bps = p0["sector_size"]
    if vol.read(0, bps)[11:0x54] != braw[11:0x54]:
        return [_problem("ntfs_boot_mismatch", "The NTFS boot sector and its backup differ",
                         "Both look valid but describe the volume differently (size, cluster size or MFT place). "
                         "The one that matches the partition is usually right; TestDisk asks the same.", "warning",
                         [to_primary, to_backup], backup_offset=loc)]
    return []


# ---------------------------------------------------------------------- FAT
def _fat_main(vol: Source) -> tuple[dict | None, bytes]:
    b0 = vol.read(0, 512)
    if b0[3:11] in (b"NTFS    ", b"EXFAT   ", b"-FVE-FS-"):
        return None, b0
    return parse_fat_bpb(b0), b0


def _fat_backup(vol: Source, p0: dict | None) -> tuple[int, dict | None]:
    """(backup sector number, its parse) for FAT32."""
    if p0:
        if p0["fat_bits"] != 32:
            return 0, None
        bk = p0.get("backup_boot_sector") or 0
        if not 0 < bk < p0["reserved_sectors"]:
            return 0, None
        return bk, parse_fat_bpb(vol.read(bk * p0["sector_size"], 512))
    for bps in (512, 4096):
        p = parse_fat_bpb(vol.read(6 * bps, 512))
        if p and p["fat_bits"] == 32 and p["sector_size"] == bps and p.get("backup_boot_sector") == 6:
            return 6, p
    return 6, None


def _fsinfo_ok(sec: bytes) -> bool:
    return sec[0:4] == b"RRaA" and sec[484:488] == b"rrAa" and sec[508:512] == b"\x00\x00\x55\xaa"


def _fat_entries_bad(data: bytes, bits: int, clusters: int, first_index: int) -> int:
    """How many entries of this piece of a FAT point nowhere sensible."""
    top = clusters + 2
    bad = 0
    if bits == 32:
        for i, (v,) in enumerate(struct.iter_unpack("<I", data[:len(data) // 4 * 4])):
            v &= 0x0FFFFFFF
            if (first_index + i) >= 2 and v != 0 and not 2 <= v < top and v < 0x0FFFFFF7:
                bad += 1
    elif bits == 16:
        for i, (v,) in enumerate(struct.iter_unpack("<H", data[:len(data) // 2 * 2])):
            if (first_index + i) >= 2 and v != 0 and not 2 <= v < top and v < 0xFFF7:
                bad += 1
    return bad


def _fat_entry(vol: Source, at: int, bits: int, index: int) -> int | None:
    """Entry INDEX of the FAT starting at AT (FAT16 and FAT32 only)."""
    if bits == 32:
        raw = vol.read(at + 4 * index, 4)
        return struct.unpack("<I", raw)[0] & 0x0FFFFFFF if len(raw) == 4 else None
    if bits == 16:
        raw = vol.read(at + 2 * index, 2)
        return struct.unpack("<H", raw)[0] if len(raw) == 2 else None
    return None


def _root_starts(vol: Source, p: dict, limit: int = 512) -> list[int]:
    """The first clusters of the files and folders in the root folder (its first sectors for FAT32)."""
    bps = p["sector_size"]
    if p["fat_bits"] == 32:
        at = (p["first_data_sector"] + (p.get("root_cluster", 2) - 2) * (p["cluster_size"] // bps)) * bps
        raw = vol.read(at, min(p["cluster_size"], limit * 32))
    else:
        at = (p["reserved_sectors"] + p["fats"] * p["fat_sectors"]) * bps
        raw = vol.read(at, min(p.get("root_entries", 0) * 32, limit * 32))
    out = []
    for i in range(0, len(raw) - 31, 32):
        e = raw[i:i + 32]
        if e[0] == 0:
            break
        if e[0] == 0xE5 or e[11] & 0x0F == 0x0F or e[11] & 0x08 or e[0:2] in (b". ", b".."):
            continue
        first = struct.unpack_from("<H", e, 26)[0] | (struct.unpack_from("<H", e, 20)[0] << 16 if p["fat_bits"] == 32
                                                      else 0)
        if 2 <= first < p["clusters"] + 2:
            out.append(first)
    return out


def _compare_fats(vol: Source, p: dict) -> tuple[int, int, int, bool]:
    """(differing sectors, faults in FAT 1, in FAT 2, whole FAT compared). A fault is an entry that points
    nowhere sensible, a link to a cluster the same copy calls free, or a file of the root folder whose
    first cluster that copy calls free: a copy that lost its chains (zeroed) only shows the last two."""
    bps = p["sector_size"]
    bits = p["fat_bits"]
    fat_bytes = p["fat_sectors"] * bps
    limit = min(fat_bytes, FAT_COMPARE_LIMIT)
    a0 = p["reserved_sectors"] * bps
    a1 = a0 + fat_bytes
    starts = (a0, a1)
    diff = 0
    faults = [0, 0]
    pos = 0
    entry = {32: 4, 16: 2}.get(bits, 0)
    links_checked = 0
    top = p["clusters"] + 2
    while pos < limit:
        n = min(4 * MiB, limit - pos)
        x, y = vol.read(a0 + pos, n), vol.read(a1 + pos, n)
        if x != y:
            for s in range(0, n, bps):
                if x[s:s + bps] == y[s:s + bps]:
                    continue
                diff += 1
                if not entry:
                    continue
                first = (pos + s) // entry
                for k, sec in enumerate((x[s:s + bps], y[s:s + bps])):
                    faults[k] += _fat_entries_bad(sec, bits, p["clusters"], first)
                    fmt = "<I" if bits == 32 else "<H"
                    for (v,) in struct.iter_unpack(fmt, sec[:len(sec) // entry * entry]):
                        v &= 0x0FFFFFFF
                        if 2 <= v < top and links_checked < 20000:
                            links_checked += 1
                            if _fat_entry(vol, starts[k], bits, v) == 0:
                                faults[k] += 1
        pos += n
    if diff and entry:
        try:
            for c in _root_starts(vol, p):
                for k in (0, 1):
                    if _fat_entry(vol, starts[k], bits, c) == 0:
                        faults[k] += 1
        except (KeyError, struct.error, ValueError):
            pass
    return diff, faults[0], faults[1], limit == fat_bytes


def _diag_fat(vol: Source, size: int, fstype: str) -> list[dict]:
    out: list[dict] = []
    p0, _b0 = _fat_main(vol)
    bk, pb = _fat_backup(vol, p0)
    to_primary = ("boot:fat_boot", {"direction": "backup_to_primary"}, "Copy the backup boot sector over the first one")
    to_backup = ("boot:fat_boot", {"direction": "primary_to_backup"}, "Copy the boot sector over its backup")
    if p0 is None:
        if pb is not None:
            out.append(_problem("fat_boot_damaged", "The FAT32 boot sector is damaged",
                                f"The first sector of the volume isn't a valid FAT boot sector, but its backup in "
                                f"sector {bk} is intact: copying it back makes the volume readable again.", "error",
                                [to_primary], backup_sector=bk))
        elif fstype.startswith("fat"):
            out.append(_problem("fat_boot_lost", "The FAT boot sector is damaged",
                                "The boot sector can't be read and there is no usable backup (FAT12 and FAT16 don't "
                                "keep one). A deep search can still find the files.", "error"))
        p = pb
    else:
        p = p0
        if p0["fat_bits"] == 32:
            if pb is None:
                out.append(_problem("fat_backup_damaged", "The FAT32 backup boot sector is damaged",
                                    f"The boot sector is fine but its backup (sector {bk or 6}) is missing or damaged. "
                                    "Writing a fresh copy is safe.", "warning", [to_backup], backup_sector=bk or 6))
            elif _b0[11:90] != vol.read(bk * p0["sector_size"], 512)[11:90]:
                out.append(_problem("fat_boot_mismatch", "The FAT32 boot sector and its backup differ",
                                    "Both look valid but describe the volume differently.", "warning",
                                    [to_primary, to_backup], backup_sector=bk))
    if p is None:
        return out
    bps = p["sector_size"]
    if p["fat_bits"] == 32 and p0 is not None:
        fsi = p.get("fsinfo_sector") or 0
        if 0 < fsi < p["reserved_sectors"] and not _fsinfo_ok(vol.read(fsi * bps, 512)):
            out.append(_problem("fat_fsinfo_damaged", "The FAT32 FSInfo sector is damaged",
                                "It only holds the free-space count (a hint), but some systems refuse the volume "
                                "without it. It can be rebuilt; the next check recounts the free space.", "warning",
                                [("boot:fat_fsinfo", {}, "Rebuild the FSInfo sector")]))
    if p["fats"] >= 2:
        diff, bad0, bad1, whole = _compare_fats(vol, p)
        if diff:
            better = 0 if bad0 <= bad1 else 1
            other = 1 - better
            fixes = [("boot:fat_copy", {"from_index": better, "to_index": other},
                      f"Copy FAT #{better + 1} over FAT #{other + 1}"),
                     ("boot:fat_copy", {"from_index": other, "to_index": better},
                      f"Copy FAT #{other + 1} over FAT #{better + 1}")]
            out.append(_problem("fat_copies_differ", "The two copies of the FAT differ",
                                f"{diff} sector{'s' if diff != 1 else ''} of FAT #1 and FAT #2 differ"
                                f"{'' if whole else ' (in the first 64 MiB)'}; FAT #{better + 1} looks more consistent "
                                f"({min(bad0, bad1)} broken links against {max(bad0, bad1)}). This happens when a "
                                "card or stick is removed while writing. Before copying, recover the files you need: the "
                                "copy decides which version of the last changes survives.", "warning", fixes,
                                differing_sectors=diff, bad_entries=[bad0, bad1]))
    return out


# ---------------------------------------------------------------------- exFAT
def _exfat_region(vol: Source, at: int, bps: int) -> tuple[dict | None, bool, bytes]:
    region = vol.read(at, 12 * bps)
    p = parse_exfat_boot(region[:512])
    if p is None or p["sector_size"] != bps:
        return None, False, region
    csum = exfat_boot_checksum(region, bps)
    stored = region[11 * bps:12 * bps]
    ok = stored == struct.pack("<I", csum) * (bps // 4)
    return p, ok, region


def _diag_exfat(vol: Source, size: int, fstype: str) -> list[dict]:
    p0 = parse_exfat_boot(vol.read(0, 512))
    sizes = [p0["sector_size"]] if p0 else [512, 4096]
    for bps in sizes:
        m, m_ok, _mr = _exfat_region(vol, 0, bps)
        b, b_ok, _br = _exfat_region(vol, 12 * bps, bps)
        if not (m or b):
            continue
        to_primary = ("boot:exfat_boot", {"direction": "backup_to_primary"},
                      "Copy the backup boot region over the main one")
        to_backup = ("boot:exfat_boot", {"direction": "primary_to_backup"}, "Copy the main boot region over its backup")
        if not (m and m_ok) and b and b_ok:
            return [_problem("exfat_boot_damaged", "The exFAT boot region is damaged",
                             "The main boot region (first 12 sectors) is damaged or fails its checksum, but the "
                             "backup region right after it is intact.", "error", [to_primary])]
        if m and m_ok and not (b and b_ok):
            return [_problem("exfat_backup_damaged", "The exFAT backup boot region is damaged",
                             "The main boot region is fine but its backup (sectors 12-23) is missing or damaged. "
                             "Writing a fresh copy is safe.", "warning", [to_backup])]
        if m and b and m_ok and b_ok and _mr[11 * bps:11 * bps + 4] != _br[11 * bps:11 * bps + 4]:
            return [_problem("exfat_boot_mismatch", "The exFAT boot region and its backup differ",
                             "Both are valid but differ.", "warning", [to_primary, to_backup])]
        if m and not m_ok and not b_ok:
            return [_problem("exfat_boot_checksum", "The exFAT boot region fails its checksum",
                             "Both copies fail their checksum; Windows refuses such a volume. A deep search can still "
                             "read it.", "error")]
        return []
    if fstype == "exfat":
        return [_problem("exfat_boot_lost", "Both exFAT boot regions are damaged",
                         "Neither copy of the boot region can be read.", "error")]
    return []


# ---------------------------------------------------------------------- ext
def _sparse_groups(count: int) -> list[int]:
    out = {1}
    for base in (3, 5, 7):
        x = base
        while x < count:
            out.add(x)
            x *= base
    return sorted(g for g in out if g < count)


def backup_superblocks(src: Source, offset: int = 0, size: int | None = None, limit: int = 8) -> list[dict]:
    """The intact backup superblocks of the ext filesystem at OFFSET of SRC, as [{"superblock": block number,
    "block_size", "group", "offset" (bytes from the volume start), "uuid", "blocks"}] — the numbers
    ``e2fsck -b <superblock> -B <block_size>`` wants. Works when the main superblock is gone: the usual block
    sizes are tried at the standard places."""
    vol = src.region(offset, size) if (offset or size) else src
    vsize = vol.size
    found: list[dict] = []
    primary = parse_ext_super(vol.read(1024, 1024))
    if primary and primary["group"] == 0:
        geoms = [(primary["block_size"], primary["blocks_per_group"], primary["first_data_block"], primary)]
    else:
        geoms = [(bs, 8 * bs, 1 if bs == 1024 else 0, None) for bs in (4096, 1024, 2048)]
    for bs, bpg, first, prim in geoms:
        total_blocks = prim["blocks"] if prim else vsize // bs
        ngroups = max(1, -(-(total_blocks - first) // bpg))
        if prim and not prim["ro_compat"] & 1:                      # no sparse_super: every group has one
            groups = list(range(1, min(ngroups, 64)))
        elif prim and prim["compat"] & 0x200:                       # sparse_super2: two chosen groups
            groups = [g for g in prim["backup_bgs"] if 0 < g < ngroups]
        else:
            groups = _sparse_groups(ngroups)
        misses = 0
        for g in groups:
            loc = (first + g * bpg) * bs
            if loc + 1024 > vsize:
                break
            sb = parse_ext_super(vol.read(loc, 1024))
            if sb and sb["group"] == g and sb["block_size"] == bs and (prim is None or sb["uuid"] == prim["uuid"]):
                found.append({"superblock": first + g * bpg, "block_size": bs, "group": g, "offset": loc,
                              "uuid": sb["uuid"], "blocks": sb["blocks"]})
                misses = 0
                if len(found) >= limit:
                    return found
            else:
                misses += 1
                if prim is None and misses >= 3 and not any(f["block_size"] == bs for f in found):
                    break
        if found and prim is None:
            break
    return found


def _diag_ext(vol: Source, size: int, fstype: str) -> list[dict]:
    sb = parse_ext_super(vol.read(1024, 1024))
    if sb and sb["group"] == 0:
        if sb["state"] & 2:
            return [_problem("ext_errors", "The ext filesystem has recorded errors",
                             "The kernel noticed inconsistencies and marked the filesystem; a check (e2fsck) "
                             "should be run before writing to it.", "warning")]
        return []
    backups = backup_superblocks(vol, 0, size, limit=6)
    if not backups:
        if fstype.startswith("ext"):
            return [_problem("ext_superblock_lost", "The ext superblock is damaged",
                             "The main superblock can't be read and no backup superblock was found at the usual "
                             "places (the filesystem may use unusual settings: mke2fs -n with the same options "
                             "lists where its backups are).", "error")]
        return []
    b = backups[0]
    places = ", ".join(str(x["superblock"]) for x in backups)
    return [_problem("ext_superblock_damaged", "The ext superblock is damaged",
                     f"The main superblock is damaged, but backup superblocks are intact at blocks {places} "
                     f"({b['block_size']}-byte blocks). e2fsck can rebuild the main one from a backup: "
                     f"e2fsck -b {b['superblock']} -B {b['block_size']} <device>.", "error",
                     [("fsck:backup_superblock", {"superblock": b["superblock"], "block_size": b["block_size"]},
                       f"Repair with the backup superblock at block {b['superblock']}")], backups=backups)]


# ---------------------------------------------------------------------- partition table
def _diag_table(src: Source) -> list[dict]:
    from .partitions import read_table
    t = read_table(src)
    out: list[dict] = []
    if t["type"] == "gpt":
        g = t["gpt"] or {}
        last = t["disk_size"] // t["sector_size"] - 1
        from_backup = ("boot:gpt_rebuild", {"from_": "backup"}, "Rebuild the main GPT from the backup")
        from_primary = ("boot:gpt_rebuild", {"from_": "primary"}, "Rebuild the backup GPT from the main one")
        if not g.get("primary_ok") and g.get("backup_ok"):
            out.append(_problem("gpt_primary_damaged", "The main GPT is damaged",
                                "The partition table at the start of the disk is damaged, but its backup at the end "
                                "is intact: the main copy can be rebuilt from it.", "error", [from_backup]))
        elif g.get("primary_ok") and not g.get("backup_ok"):
            out.append(_problem("gpt_backup_damaged", "The backup GPT is damaged or missing",
                                "The main partition table is fine but the backup copy at the end of the disk is "
                                "missing or damaged (or the disk was enlarged). It can be rewritten from the main "
                                "one.", "warning", [from_primary]))
        elif g.get("primary_ok") and g.get("backup_ok"):
            if g.get("backup_lba") != last:
                out.append(_problem("gpt_backup_misplaced", "The backup GPT isn't at the end of the disk",
                                    "The disk was enlarged (or cloned to a bigger one): the backup GPT should move to "
                                    "the last sector.", "warning", [from_primary]))
            elif any("differ" in p for p in t["problems"]):
                out.append(_problem("gpt_copies_differ", "The two copies of the GPT differ",
                                    "Both are valid but list different partitions.", "warning",
                                    [from_primary, from_backup]))
        else:
            out.append(_problem("gpt_lost", "Both copies of the GPT are damaged",
                                "Search for the partitions (Quick or Deep Search) and write a new table.", "error"))
        mbr = t.get("mbr") or {}
        if not any(e.get("type") in ("0xee",) for e in mbr.get("entries") or []):
            fixes = [("boot:gpt_protective_mbr", {}, "Write a protective MBR")] if not mbr.get("entries") else []
            out.append(_problem("gpt_no_protective_mbr", "The protective MBR is missing",
                                "Sector 0 of a GPT disk should hold an MBR with one protective entry; without it some "
                                "systems and tools don't see the partitions.", "warning", fixes))
    elif t["type"] == "dos" and not (t.get("mbr") or {}).get("signature"):
        out.append(_problem("mbr_no_signature", "The MBR signature is missing",
                            "The partition entries in sector 0 look right but its last two bytes (55 AA) are wrong, "
                            "so systems ignore the table. Writing the signature fixes it.", "error",
                            [("boot:mbr_signature", {}, "Write the MBR signature")]))
    return out


# ====================================================================== fixes
def _apply(device: str, writes: list[tuple[int, bytes]], label: str, backup_dir: str | None) -> dict:
    """Back up every range WRITES will change, then write them (synchronously, read back)."""
    if not writes:
        raise RallError("Nothing to write")
    for off, data in writes:
        rawwrite.check_not_busy(device, off, len(data), what="The repair")
    backup = rawwrite.backup_ranges(device, [(off, len(data)) for off, data in writes], _backup_dir(backup_dir), label)
    for off, data in writes:
        rawwrite.write_at(device, off, data)
    try:
        rawwrite.note_written(backup)
    except RallError as exc:
        log.warning("couldn't note the new state in %s: %s", backup, exc)
    return {"backup": backup, "written": [[off, len(data)] for off, data in writes]}


def _direction(direction: str) -> bool:
    if direction not in ("backup_to_primary", "primary_to_backup"):
        raise RallError(f"Unknown direction {direction!r}")
    return direction == "backup_to_primary"


def ntfs_boot(device: str, offset: int, size: int = 0, direction: str = "backup_to_primary",
              backup_dir: str | None = None) -> dict:
    """Copy the NTFS backup boot sector over the boot sector (or the other way round)."""
    to_primary = _direction(direction)
    with FileSource(device) as src:
        vsize = int(size or (src.size - offset))
        vol = src.region(offset, vsize)
        p0 = parse_ntfs_boot(vol.read(0, 512))
        loc, pb, braw = _ntfs_backup(vol, vsize, p0)
        if to_primary:
            if pb is None:
                raise RallError("The NTFS backup boot sector isn't usable either: nothing to copy")
            writes = [(offset, braw)]
        else:
            if p0 is None:
                raise RallError("The NTFS boot sector isn't valid: it can't be copied over its backup")
            bps = p0["sector_size"]
            place = p0["total_sectors"] * bps
            if place + bps > vsize:
                place = vsize - bps
            writes = [(offset + place, vol.read(0, bps))]
    return _apply(device, writes, "ntfs-boot", backup_dir)


def fat_boot(device: str, offset: int, size: int = 0, direction: str = "backup_to_primary",
             backup_dir: str | None = None) -> dict:
    """FAT32: copy the backup boot record (boot sector, FSInfo, boot code: 3 sectors) over the main one, or
    the other way round."""
    to_primary = _direction(direction)
    with FileSource(device) as src:
        vol = src.region(offset, int(size or (src.size - offset)))
        p0, _ = _fat_main(vol)
        bk, pb = _fat_backup(vol, p0)
        p = pb if to_primary else p0
        if p is None or p["fat_bits"] != 32 or not bk:
            raise RallError("There is no usable " + ("backup boot sector" if to_primary else "FAT32 boot sector")
                            + " to copy")
        bps = p["sector_size"]
        n = min(3, bk)
        src_at, dst_at = (bk * bps, 0) if to_primary else (0, bk * bps)
        data = vol.read(src_at, n * bps)
    return _apply(device, [(offset + dst_at, data)], "fat-boot", backup_dir)


def fat_boot_from_backup(device: str, offset: int, size: int = 0, backup_dir: str | None = None) -> dict:
    return fat_boot(device, offset, size, "backup_to_primary", backup_dir)


def fat_backup_from_boot(device: str, offset: int, size: int = 0, backup_dir: str | None = None) -> dict:
    return fat_boot(device, offset, size, "primary_to_backup", backup_dir)


def fat_fsinfo(device: str, offset: int, size: int = 0, backup_dir: str | None = None) -> dict:
    """Rebuild the FAT32 FSInfo sector: from its backup when that one is valid, else with "unknown" counts."""
    with FileSource(device) as src:
        vol = src.region(offset, int(size or (src.size - offset)))
        p, _ = _fat_main(vol)
        if p is None or p["fat_bits"] != 32:
            raise RallError("This isn't a FAT32 volume with a valid boot sector")
        bps = p["sector_size"]
        fsi = p.get("fsinfo_sector") or 1
        bk = p.get("backup_boot_sector") or 0
        data = None
        if bk and bk + fsi < p["reserved_sectors"]:
            cand = vol.read((bk + fsi) * bps, bps)
            if _fsinfo_ok(cand):
                data = cand
        if data is None:
            sec = bytearray(bps)
            sec[0:4] = b"RRaA"
            sec[484:488] = b"rrAa"
            struct.pack_into("<II", sec, 488, 0xFFFFFFFF, 0xFFFFFFFF)
            sec[508:512] = b"\x00\x00\x55\xaa"
            data = bytes(sec)
    return _apply(device, [(offset + fsi * bps, data)], "fat-fsinfo", backup_dir)


def fat_copy(device: str, offset: int, size: int = 0, *, from_index: int = 0, to_index: int = 1,
             backup_dir: str | None = None) -> dict:
    """Copy FAT number FROM_INDEX (0-based) over FAT number TO_INDEX. The overwritten FAT is backed up."""
    if from_index == to_index:
        raise RallError("Copying a FAT onto itself")
    with FileSource(device) as src:
        vol = src.region(offset, int(size or (src.size - offset)))
        p, _ = _fat_main(vol)
        if p is None:
            _bk, p = _fat_backup(vol, None)
        if p is None:
            raise RallError("No valid boot sector says where the FATs are")
        if not (0 <= from_index < p["fats"] and 0 <= to_index < p["fats"]):
            raise RallError(f"This volume has {p['fats']} FAT{'s' if p['fats'] != 1 else ''}")
        bps = p["sector_size"]
        fat_bytes = p["fat_sectors"] * bps
        a_from = (p["reserved_sectors"] * bps) + from_index * fat_bytes
        a_to = (p["reserved_sectors"] * bps) + to_index * fat_bytes
        data = vol.read(a_from, fat_bytes)
    return _apply(device, [(offset + a_to, data)], f"fat-copy-{from_index + 1}-to-{to_index + 1}", backup_dir)


def exfat_boot(device: str, offset: int, size: int = 0, direction: str = "backup_to_primary",
               backup_dir: str | None = None) -> dict:
    """Copy the exFAT backup boot region (sectors 12-23) over the main one (0-11), or the other way round."""
    to_primary = _direction(direction)
    with FileSource(device) as src:
        vol = src.region(offset, int(size or (src.size - offset)))
        for bps in (512, 1024, 2048, 4096):
            m, m_ok, mraw = _exfat_region(vol, 0, bps)
            b, b_ok, braw = _exfat_region(vol, 12 * bps, bps)
            if to_primary and b and b_ok:
                return _apply(device, [(offset, braw)], "exfat-boot", backup_dir)
            if not to_primary and m and m_ok:
                return _apply(device, [(offset + 12 * bps, mraw)], "exfat-boot", backup_dir)
    raise RallError("There is no intact " + ("backup" if to_primary else "main") + " exFAT boot region to copy")


def exfat_boot_from_backup(device: str, offset: int, size: int = 0, backup_dir: str | None = None) -> dict:
    return exfat_boot(device, offset, size, "backup_to_primary", backup_dir)


def _gpt_header_bytes(hdr: dict, ss: int, my_lba: int, alt_lba: int, entries_lba: int) -> bytes:
    raw = bytearray(hdr["raw"][:hdr["header_size"]])
    struct.pack_into("<QQ", raw, 24, my_lba, alt_lba)
    struct.pack_into("<Q", raw, 72, entries_lba)
    struct.pack_into("<I", raw, 16, 0)
    struct.pack_into("<I", raw, 16, zlib.crc32(bytes(raw)) & 0xFFFFFFFF)
    return bytes(raw) + bytes(ss - len(raw))


def gpt_rebuild(device: str, from_: str = "backup", backup_dir: str | None = None) -> dict:
    """Rebuild one copy of the GPT from the other: the partition list is copied and a header written with
    the right own/other/list positions and checksums. From the main copy, the backup goes to the disk's
    current last sector (which also fixes a disk that was enlarged)."""
    from .partitions import gpt_header, read_table
    if from_ not in ("backup", "primary"):
        raise RallError(f"Unknown GPT copy {from_!r}")
    with FileSource(device) as src:
        t = read_table(src)
        if t["type"] != "gpt":
            raise RallError("This disk has no GPT")
        ss = t["sector_size"]
        last = src.size // ss - 1
        prim = gpt_header(src, 1, ss)
        back = None
        if prim and prim["header_ok"] and 0 < prim["alternate_lba"] <= last:
            back = gpt_header(src, prim["alternate_lba"], ss)
        if not (back and back["header_ok"]):
            back = gpt_header(src, last, ss) or back
        good = back if from_ == "backup" else prim
        if not (good and good["header_ok"] and good["entries_ok"]):
            raise RallError(f"The {'backup' if from_ == 'backup' else 'main'} GPT isn't intact: it can't be the source")
        entries = good["entries"]
        esec = -(-len(entries) // ss)
        padded = entries + bytes(esec * ss - len(entries))
        writes: list[tuple[int, bytes]] = []
        if from_ == "backup":
            if 2 + esec > good["first_usable"]:
                raise RallError("The partition list doesn't fit before the first partition")
            writes.append((2 * ss, padded))
            writes.append((ss, _gpt_header_bytes(good, ss, 1, good["lba"], 2)))
        else:
            elba = last - esec
            if good["last_usable"] >= elba:
                raise RallError("The last partition reaches the place of the backup GPT (the disk is smaller than "
                                "the table says)")
            writes.append((elba * ss, padded))
            writes.append((last * ss, _gpt_header_bytes(good, ss, last, 1, elba)))
            if good["alternate_lba"] != last:
                writes.append((ss, _gpt_header_bytes(good, ss, 1, last, good["entries_lba"])))
    res = _apply(device, writes, f"gpt-from-{from_}", backup_dir)
    with FileSource(device) as src:
        t = read_table(src)
    res["table_ok"] = bool((t.get("gpt") or {}).get("primary_ok") and (t.get("gpt") or {}).get("backup_ok"))
    return res


def gpt_protective_mbr(device: str, backup_dir: str | None = None) -> dict:
    """Write the protective MBR entry of a GPT disk (boot code and disk signature are kept)."""
    from .partitions import read_table
    with FileSource(device) as src:
        sec = bytearray(src.read(0, 512))
        t = read_table(src)
    if t["type"] != "gpt":
        raise RallError("This disk has no GPT to protect")
    if any(sec[446 + 16 * i + 4] for i in range(4)):
        raise UnsafeOperation("Sector 0 holds MBR partitions (a hybrid MBR?): it wasn't replaced")
    sectors = t["disk_size"] // t["sector_size"] - 1
    entry = bytearray(16)
    entry[1:4] = b"\x00\x02\x00"
    entry[4] = 0xEE
    entry[5:8] = b"\xff\xff\xff"
    struct.pack_into("<II", entry, 8, 1, min(sectors, 0xFFFFFFFF))
    sec[446:462] = entry
    sec[510:512] = b"\x55\xaa"
    return _apply(device, [(0, bytes(sec))], "protective-mbr", backup_dir)


def mbr_signature(device: str, backup_dir: str | None = None) -> dict:
    """Write the 55 AA signature at the end of sector 0."""
    return _apply(device, [(510, b"\x55\xaa")], "mbr-signature", backup_dir)
