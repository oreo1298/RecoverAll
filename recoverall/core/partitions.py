"""Partition tables: reading MBR (with the extended chain), GPT (both copies, checked) and Apple Partition
Maps, planning a new table, and writing it with sfdisk after backing up every sector that changes.

MBR ("dos")
    Sector 0 holds four 16-byte entries (status, type byte, first sector, sector count). An extended
    partition (types 0x05, 0x0F, 0x85) holds a chain of EBRs: each describes one logical partition
    (relative to the EBR) and points to the next EBR (relative to the extended partition's start). The
    chain is followed with loop protection. 32-bit sector numbers limit MBR disks to 2 TiB (512-byte
    sectors).
GPT
    LBA 0 is a protective MBR (one 0xEE entry), LBA 1 the header, then the entry array (usually 128
    entries of 128 bytes); a backup entry array and header sit at the end of the disk. Header and entries
    have CRC-32s. When the main copy is damaged the backup is used (and the problem reported). The sector
    size of an image file isn't known: 512 and 4096 are tried.
APM
    Apple Partition Map (older Macs, some optical images): "ER" in block 0, "PM" entries from block 1.

Writing goes through ``sfdisk`` (it knows every detail of both formats); before it runs, the sectors it
may change — MBR and EBRs, both GPT copies — are saved with :mod:`rawwrite` so :func:`undo` can put them
back byte for byte.
"""

from __future__ import annotations

import logging
import os
import stat
import struct
import zlib

from .blockio import FileSource, Source
from .errors import NotPermitted, RallError
from .fsdetect import guid_le, identify_at
from .util import MiB, TiB, detach_loop, run

log = logging.getLogger(__name__)

EXTENDED_TYPES = (0x05, 0x0F, 0x85)
GPT_ENTRIES = 128
GPT_ENTRY_SIZE = 128
MBR_LIMIT_SECTORS = 1 << 32

# ---------------------------------------------------------------------- type GUIDs and bytes
EFI_SYSTEM = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
MS_RESERVED = "E3C9E316-0B5C-4DB8-817D-F92DF00215AE"
MS_BASIC_DATA = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
WIN_RECOVERY = "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC"
LINUX_FS = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
LINUX_SWAP = "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F"
LINUX_LVM = "E6D6D379-F507-44C2-A23C-238F2A3DF928"
LINUX_RAID = "A19D880F-05FC-4D3B-A006-743F0F84911E"
LINUX_LUKS = "CA7D7CCB-63ED-4C53-861C-1742536059CC"
LINUX_XBOOTLDR = "BC13C2FF-59E6-4262-A352-B275FD6F7172"
BIOS_BOOT = "21686148-6449-6E6F-744E-656564454649"
APPLE_HFS = "48465300-0000-11AA-AA11-00306543ECAC"
APPLE_APFS = "7C3457EF-0000-11AA-AA11-00306543ECAC"
ZFS = "6A898CC3-1DD2-11B2-99A6-080020736631"
FREEBSD_UFS = "516E7CB6-6ECF-11D6-8FF8-00022D09712B"

TYPE_NAMES: dict[str, str] = {
    EFI_SYSTEM: "EFI System", MS_RESERVED: "Microsoft reserved", MS_BASIC_DATA: "Microsoft basic data",
    WIN_RECOVERY: "Windows recovery environment", "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "Microsoft LDM metadata",
    "AF9B60A0-1431-4F62-BC68-3311714A69AD": "Microsoft LDM data",
    "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D": "Microsoft Storage Spaces",
    LINUX_FS: "Linux filesystem", LINUX_SWAP: "Linux swap", LINUX_LVM: "Linux LVM", LINUX_RAID: "Linux RAID",
    LINUX_LUKS: "Linux LUKS", "7FFEC5C9-2D00-49B7-8941-3EA10A5586B7": "Linux dm-crypt",
    "933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "Linux home", "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "Linux root (x86-64)",
    "44479540-F297-41B2-9AF7-D131D5F0458A": "Linux root (x86)", "B921B045-1DF0-41C3-AF44-4C6F280D3FAE": "Linux root (ARM64)",
    "3B8F8425-20E0-4F3B-907F-1A25A76F98E8": "Linux server data", LINUX_XBOOTLDR: "Linux extended boot",
    "8DA63339-0007-60C0-C436-083AC8230908": "Linux reserved", BIOS_BOOT: "BIOS boot",
    APPLE_HFS: "Apple HFS/HFS+", APPLE_APFS: "Apple APFS", "426F6F74-0000-11AA-AA11-00306543ECAC": "Apple boot",
    "5265636F-7665-11AA-AA11-00306543ECAC": "Apple TV recovery", "55465300-0000-11AA-AA11-00306543ECAC": "Apple UFS",
    ZFS: "Solaris /usr & Apple ZFS", FREEBSD_UFS: "FreeBSD UFS", "516E7CB5-6ECF-11D6-8FF8-00022D09712B": "FreeBSD swap",
    "516E7CBA-6ECF-11D6-8FF8-00022D09712B": "FreeBSD ZFS", "83BD6B9D-7F41-11DC-BE0B-001560B84F0F": "FreeBSD boot",
    "024DEE41-33E7-11D3-9D69-0008C781F39F": "MBR partition scheme", "9E1A2D38-C612-4316-AA26-8B49521E5A8B": "PowerPC PReP boot",
    "0x00": "Empty", "0x01": "FAT12", "0x04": "FAT16 <32M", "0x05": "Extended", "0x06": "FAT16",
    "0x07": "NTFS/exFAT/HPFS", "0x0b": "W95 FAT32", "0x0c": "W95 FAT32 (LBA)", "0x0e": "W95 FAT16 (LBA)",
    "0x0f": "W95 Extended (LBA)", "0x11": "Hidden FAT12", "0x12": "Compaq diagnostics", "0x14": "Hidden FAT16 <32M",
    "0x16": "Hidden FAT16", "0x17": "Hidden NTFS/exFAT", "0x1b": "Hidden W95 FAT32", "0x1c": "Hidden W95 FAT32 (LBA)",
    "0x1e": "Hidden W95 FAT16 (LBA)", "0x27": "Hidden NTFS WinRE", "0x42": "Windows dynamic (LDM)",
    "0x82": "Linux swap / Solaris", "0x83": "Linux", "0x84": "Hibernation", "0x85": "Linux extended",
    "0x8e": "Linux LVM", "0xa0": "Hibernation", "0xa5": "FreeBSD", "0xa6": "OpenBSD", "0xa8": "Darwin UFS",
    "0xa9": "NetBSD", "0xab": "Darwin boot", "0xaf": "HFS / HFS+", "0xbe": "Solaris boot", "0xbf": "Solaris",
    "0xde": "Dell utility", "0xee": "GPT protective", "0xef": "EFI (FAT-12/16/32)", "0xfb": "VMware VMFS",
    "0xfc": "VMware VMKCORE", "0xfd": "Linux RAID autodetect",
}

_WINDOWS = ("ntfs", "exfat", "refs", "bitlocker")
_LINUX = ("ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs", "nilfs2", "erofs", "squashfs", "minix",
          "iso9660", "udf")


def type_for(fstype: str | None, table_type: str, role: str | None = None) -> str:
    """The partition type to write for a FSTYPE volume: a GUID for GPT, "0xNN" for MBR. ROLE (esp, msr,
    recovery, bios_boot, xbootldr) wins over the filesystem."""
    fstype = fstype or ""
    gpt = table_type == "gpt"
    if role == "esp":
        return EFI_SYSTEM if gpt else "0xef"
    if role == "msr" and gpt:
        return MS_RESERVED
    if role == "recovery":
        return WIN_RECOVERY if gpt else "0x27"
    if role == "bios_boot" and gpt:
        return BIOS_BOOT
    if role == "xbootldr" and gpt:
        return LINUX_XBOOTLDR
    if gpt:
        if fstype in _WINDOWS or fstype in ("fat12", "fat16", "fat32", "vfat"):
            return MS_BASIC_DATA
        return {"swap": LINUX_SWAP, "lvm2_member": LINUX_LVM, "linux_raid_member": LINUX_RAID,
                "crypto_luks": LINUX_LUKS, "hfsplus": APPLE_HFS, "hfsx": APPLE_HFS, "hfs": APPLE_HFS,
                "apfs": APPLE_APFS, "zfs_member": ZFS, "ufs": FREEBSD_UFS}.get(fstype, LINUX_FS)
    if fstype in _WINDOWS:
        return "0x07"
    return {"fat12": "0x01", "fat16": "0x0e", "fat32": "0x0c", "vfat": "0x0c", "swap": "0x82",
            "lvm2_member": "0x8e", "linux_raid_member": "0xfd", "crypto_luks": "0x83", "hfsplus": "0xaf",
            "hfsx": "0xaf", "hfs": "0xaf", "apfs": "0xaf", "zfs_member": "0xbf", "ufs": "0xa5"}.get(fstype, "0x83")


def type_name(t: str | None) -> str:
    if not t:
        return ""
    key = t.upper() if len(t) == 36 else norm_mbr_type(t)
    return TYPE_NAMES.get(key, t)


def norm_mbr_type(t) -> str:
    """"7", "0x7", 7, "07" → "0x07"."""
    if isinstance(t, int):
        return f"0x{t & 0xFF:02x}"
    s = str(t).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    try:
        return f"0x{int(s, 16) & 0xFF:02x}"
    except ValueError:
        return str(t)


def is_extended(t) -> bool:
    if t is None or (isinstance(t, str) and len(t) == 36):
        return False
    try:
        return int(norm_mbr_type(t), 16) in EXTENDED_TYPES
    except ValueError:
        return False


# ---------------------------------------------------------------------- reading
def _mbr_entries(sec: bytes) -> list[dict]:
    out = []
    for i in range(4):
        e = sec[446 + 16 * i:446 + 16 * (i + 1)]
        status, ptype = e[0], e[4]
        start, count = struct.unpack_from("<II", e, 8)
        out.append({"index": i, "status": status, "type": ptype, "start": start, "sectors": count})
    return out


def gpt_header(src: Source, lba: int, ss: int) -> dict | None:
    """The GPT header at LBA (sector size SS) with its entry array, both checked; None without the
    "EFI PART" signature."""
    if lba < 0 or (lba + 1) * ss > src.size:
        return None
    raw = src.read(lba * ss, ss)
    if raw[:8] != b"EFI PART":
        return None
    hsize = struct.unpack_from("<I", raw, 12)[0]
    hdr = {"lba": lba, "raw": raw, "header_ok": False, "entries_ok": False, "entries": b""}
    if not 92 <= hsize <= ss:
        return hdr
    crc = struct.unpack_from("<I", raw, 16)[0]
    calc = zlib.crc32(raw[:16] + b"\x00\x00\x00\x00" + raw[20:hsize]) & 0xFFFFFFFF
    my_lba, alt_lba, first, last = struct.unpack_from("<QQQQ", raw, 24)
    entries_lba, n, esz, ecrc = struct.unpack_from("<QIII", raw, 72)
    hdr.update({"header_size": hsize, "revision": struct.unpack_from("<I", raw, 8)[0], "my_lba": my_lba,
                "alternate_lba": alt_lba, "first_usable": first, "last_usable": last,
                "disk_guid": guid_le(raw[56:72]), "entries_lba": entries_lba, "num_entries": n,
                "entry_size": esz, "entries_crc": ecrc,
                "header_ok": crc == calc and my_lba == lba and first <= last + 1})
    if 128 <= esz <= 4096 and esz % 8 == 0 and 0 < n * esz <= 4 * MiB and (entries_lba + 1) * ss <= src.size:
        ent = src.read(entries_lba * ss, n * esz)
        hdr["entries"] = ent
        hdr["entries_ok"] = (zlib.crc32(ent) & 0xFFFFFFFF) == ecrc
    return hdr


def _gpt_partitions(hdr: dict, ss: int, disk: int, problems: list[str]) -> list[dict]:
    out = []
    ent, esz = hdr.get("entries") or b"", hdr.get("entry_size") or GPT_ENTRY_SIZE
    for i in range(min(hdr.get("num_entries") or 0, len(ent) // esz)):
        e = ent[i * esz:(i + 1) * esz]
        if not any(e[0:16]):
            continue
        first, last, attrs = struct.unpack_from("<QQQ", e, 32)
        name = e[56:128].decode("utf-16-le", "replace").split("\x00", 1)[0]
        if last < first:
            problems.append(f"Partition {i + 1} ends before it starts (sector {first} to {last}): ignored.")
            continue
        t = guid_le(e[0:16])
        p = {"number": i + 1, "start": first * ss, "size": (last - first + 1) * ss, "type": t,
             "type_name": TYPE_NAMES.get(t, t), "name": name, "guid": guid_le(e[16:32]), "bootable": bool(attrs & 4),
             "logical": False, "attrs": attrs}
        if first < hdr["first_usable"] or last > hdr["last_usable"]:
            problems.append(f"Partition {i + 1} lies outside the area the GPT allows for partitions.")
        if (last + 1) * ss > disk:
            problems.append(f"Partition {i + 1} ends past the end of the disk (the disk is smaller than it was?).")
        out.append(p)
    return out


def _ebr_chain(src: Source, ss: int, ext_lba: int, disk_sectors: int, problems: list[str]) -> tuple[list[dict], list[int]]:
    logicals: list[dict] = []
    ebrs: list[int] = []
    cur = ext_lba
    seen: set[int] = set()
    number = 5
    while cur and len(seen) < 256:
        if cur in seen:
            problems.append("The chain of logical partitions loops back on itself; it was cut there.")
            break
        seen.add(cur)
        if cur >= disk_sectors:
            problems.append(f"A logical partition's table (EBR) points past the end of the disk (sector {cur}).")
            break
        sec = src.read(cur * ss, 512)
        if sec[510:512] != b"\x55\xaa":
            problems.append(f"The table of a logical partition (EBR at sector {cur}) is damaged or missing; the "
                            "logical partitions after it can't be read from the table.")
            break
        ebrs.append(cur * ss)
        e1, e2 = _mbr_entries(sec)[:2]
        if e1["type"] and e1["sectors"]:
            start = cur + e1["start"]
            t = norm_mbr_type(e1["type"])
            logicals.append({"number": number, "start": start * ss, "size": e1["sectors"] * ss, "type": t,
                             "type_name": TYPE_NAMES.get(t, t), "name": "", "guid": "", "bootable": e1["status"] == 0x80,
                             "logical": True, "attrs": 0, "ebr": cur * ss})
            if start + e1["sectors"] > disk_sectors:
                problems.append(f"Logical partition {number} ends past the end of the disk.")
            number += 1
        if e2["type"] in EXTENDED_TYPES and e2["sectors"]:
            cur = ext_lba + e2["start"]
        else:
            break
    return logicals, ebrs


def _mbr_plausible(entries: list[dict], disk_sectors: int) -> bool:
    used = [e for e in entries if e["type"]]
    if not used:
        return False
    for e in used:
        if e["status"] not in (0x00, 0x80) or e["sectors"] == 0 or e["start"] == 0 and e["type"] != 0xEE:
            return False
        if e["type"] != 0xEE and e["start"] >= disk_sectors:
            return False
    return True


def _probe_starts(src: Source, parts: list[dict], ss: int) -> int:
    """How many partitions (at sector size SS) start with a recognizable filesystem."""
    hits = 0
    for p in parts[:4]:
        off = p["start_lba"] * ss
        if 0 < off < src.size and identify_at(src, off):
            hits += 1
    return hits


def _apm(src: Source, problems: list[str]) -> list[dict] | None:
    b0 = src.read(0, 512)
    if b0[0:2] != b"ER":
        return None
    blk = struct.unpack_from(">H", b0, 2)[0] or 512
    for stride in (512, blk):
        e1 = src.read(stride, 512)
        if e1[0:2] == b"PM":
            break
    else:
        return None
    count = min(struct.unpack_from(">I", e1, 4)[0], 128)
    out = []
    for i in range(count):
        e = src.read(stride * (1 + i), 512)
        if e[0:2] != b"PM":
            problems.append(f"Entry {i + 1} of the Apple partition map is damaged.")
            break
        start, size = struct.unpack_from(">II", e, 8)
        name = e[16:48].split(b"\x00", 1)[0].decode("mac_roman", "replace")
        ptype = e[48:80].split(b"\x00", 1)[0].decode("ascii", "replace")
        if ptype == "Apple_Free" or size == 0:
            continue
        out.append({"number": i + 1, "start": start * stride, "size": size * stride, "type": ptype, "type_name": ptype,
                    "name": name, "guid": "", "bootable": False, "logical": False, "attrs": 0,
                    "map": ptype == "Apple_partition_map"})
    return out


def _overlap_problems(parts: list[dict], problems: list[str]) -> None:
    items = sorted((p for p in parts if not p.get("extended")), key=lambda p: p["start"])
    for a, b in zip(items, items[1:]):
        if b["start"] < a["start"] + a["size"]:
            problems.append(f"Partitions {a['number']} and {b['number']} overlap.")


def read_table(src: Source) -> dict:
    """The partition table of SRC (a whole disk or a disk image): type "gpt", "dos", "apm" or "none",
    sector_size, disk_size, ok, problems (plain sentences), gpt details, and the partitions with byte
    offsets. Never raises for damaged tables: what can be read is returned with problems."""
    disk = src.size
    is_dev = bool(getattr(src, "is_device", False))
    dev_ss = src.sector_size or 512
    res: dict = {"type": "none", "sector_size": dev_ss, "disk_size": disk, "ok": True, "problems": [], "gpt": None,
                 "partitions": [], "mbr": None, "ebrs": []}
    if disk < 1024:
        return res
    problems: list[str] = res["problems"]
    sizes = [dev_ss] + [s for s in (512, 4096) if s != dev_ss]

    mbr_sec = src.read(0, 512)
    mbr_sig = mbr_sec[510:512] == b"\x55\xaa"
    entries = _mbr_entries(mbr_sec)
    has_ee = any(e["type"] == 0xEE for e in entries)
    res["mbr"] = {"signature": mbr_sig, "protective": has_ee and sum(1 for e in entries if e["type"]) == 1,
                  "hybrid": has_ee and sum(1 for e in entries if e["type"]) > 1,
                  "disk_signature": f"0x{struct.unpack_from('<I', mbr_sec, 440)[0]:08x}",
                  "entries": [{**e, "type": norm_mbr_type(e["type"])} for e in entries if e["type"]]}

    # ---- GPT: the main header at LBA 1, else the backup at the last LBA
    gpt = None
    for ss in sizes:
        last_lba = disk // ss - 1
        prim = gpt_header(src, 1, ss)
        back = None
        if prim and prim.get("header_ok") and 0 < prim["alternate_lba"] <= last_lba:
            back = gpt_header(src, prim["alternate_lba"], ss)
        if back is None or not back.get("header_ok"):
            back = gpt_header(src, last_lba, ss) or back
        if prim or back:
            gpt = (ss, prim, back)
            if (prim and prim["header_ok"]) or (back and back["header_ok"]):
                break
    mbr_parts = [e for e in entries if e["type"] and e["type"] != 0xEE]
    if gpt and not (mbr_parts and not has_ee and mbr_sig):
        ss, prim, back = gpt
        res["type"] = "gpt"
        res["sector_size"] = ss
        p_ok = bool(prim and prim["header_ok"] and prim["entries_ok"])
        b_ok = bool(back and back["header_ok"] and back["entries_ok"])
        use = prim if p_ok else back if b_ok else (prim if prim and prim["header_ok"] else back if back and
                                                  back["header_ok"] else None)
        last_lba = disk // ss - 1
        info = {"primary_ok": p_ok, "backup_ok": b_ok, "disk_guid": "", "first_usable": None, "last_usable": None,
                "entries": GPT_ENTRIES, "backup_lba": back["lba"] if back else None,
                "primary_header_ok": bool(prim and prim["header_ok"]), "backup_header_ok": bool(back and back["header_ok"])}
        if use:
            info.update({"disk_guid": use["disk_guid"], "first_usable": use["first_usable"],
                         "last_usable": use["last_usable"], "entries": use["num_entries"],
                         "entry_size": use["entry_size"], "used_copy": "primary" if use is prim else "backup"})
            res["partitions"] = _gpt_partitions(use, ss, disk, problems)
        res["gpt"] = info
        if not p_ok:
            if prim is None:
                problems.append("The main GPT header (sector 1) is missing" + ("; the backup copy at the end of the "
                                "disk is intact and was used." if b_ok else "."))
            elif not prim["header_ok"]:
                problems.append("The main GPT header is damaged (its checksum is wrong)" + (
                    "; the backup copy at the end of the disk is intact and was used." if b_ok else "."))
            else:
                problems.append("The main GPT partition list is damaged (its checksum is wrong)" + (
                    "; the backup copy is intact and was used." if b_ok else "."))
        if not b_ok:
            if back is None:
                problems.append("The backup GPT at the end of the disk is missing (the disk may have been "
                                "enlarged, or an image is incomplete).")
            else:
                problems.append("The backup GPT at the end of the disk is damaged.")
        elif back and back["lba"] != last_lba:
            problems.append("The backup GPT isn't in the last sector of the disk (the disk was enlarged).")
        if p_ok and b_ok and prim["entries"] != back["entries"]:
            problems.append("The two copies of the GPT list different partitions.")
        if use is None:
            problems.append("Neither copy of the GPT can be read.")
        if not has_ee:
            problems.append("The protective MBR in sector 0 is missing: some systems won't see the GPT.")
        if ss != dev_ss and is_dev:
            problems.append(f"The GPT was written for {ss}-byte sectors but the disk now reports {dev_ss}-byte "
                            "sectors (a USB adapter can do this).")
        _overlap_problems(res["partitions"], problems)
        res["ok"] = not problems
        return res
    if gpt and mbr_parts:
        problems.append("A leftover GPT signature was found, but the MBR (without a protective entry) is what "
                        "systems use.")

    # ---- Apple Partition Map
    apm = _apm(src, problems)
    if apm is not None:
        res.update({"type": "apm", "sector_size": 512, "partitions": apm})
        res["ok"] = not problems
        return res

    # ---- a filesystem in sector 0 ("superfloppy"): no partition table at all
    whole = identify_at(src, 0)
    if whole and whole.get("fstype") in ("ntfs", "fat12", "fat16", "fat32", "exfat", "refs", "bitlocker"):
        res["filesystem"] = whole
        return res

    # ---- MBR
    disk_sectors_512 = disk // 512
    if not _mbr_plausible(entries, disk_sectors_512 if dev_ss == 512 else disk // dev_ss):
        if mbr_sig and not any(e["type"] for e in entries):
            res["type"] = "dos"                    # an empty MBR table
            return res
        if whole:
            res["filesystem"] = whole
        return res
    ss = dev_ss
    lba_parts = [{"start_lba": e["start"], "sectors": e["sectors"]} for e in mbr_parts]
    if not is_dev and dev_ss == 512 and lba_parts:
        fits4k = all((p["start_lba"] + p["sectors"]) * 4096 <= disk for p in lba_parts)
        if fits4k and _probe_starts(src, lba_parts, 4096) > _probe_starts(src, lba_parts, 512):
            ss = 4096
    res.update({"type": "dos", "sector_size": ss})
    if not mbr_sig:
        problems.append("The MBR's signature (55 AA at the end of sector 0) is missing: most systems ignore "
                        "this partition table until it is fixed.")
    disk_sectors = disk // ss
    parts: list[dict] = []
    for e in entries:
        if not e["type"] or e["type"] == 0xEE:
            continue
        t = norm_mbr_type(e["type"])
        p = {"number": e["index"] + 1, "start": e["start"] * ss, "size": e["sectors"] * ss, "type": t,
             "type_name": TYPE_NAMES.get(t, t), "name": "", "guid": "", "bootable": e["status"] == 0x80,
             "logical": False, "attrs": 0}
        if e["start"] + e["sectors"] > disk_sectors:
            problems.append(f"Partition {p['number']} ends past the end of the disk.")
        if e["type"] in EXTENDED_TYPES:
            p["extended"] = True
            parts.append(p)
            logicals, ebrs = _ebr_chain(src, ss, e["start"], disk_sectors, problems)
            for lp in logicals:
                if not (p["start"] <= lp["start"] and lp["start"] + lp["size"] <= p["start"] + p["size"]):
                    problems.append(f"Logical partition {lp['number']} lies outside its extended partition.")
            parts.extend(logicals)
            res["ebrs"].extend(ebrs)
        else:
            parts.append(p)
    if sum(1 for e in entries if e["type"] in EXTENDED_TYPES) > 1:
        problems.append("There is more than one extended partition.")
    res["partitions"] = sorted(parts, key=lambda p: p["number"])
    _overlap_problems(res["partitions"], problems)
    res["ok"] = not problems
    return res


# ---------------------------------------------------------------------- planning
def _gpt_layout(disk_size: int, ss: int, entries: int = GPT_ENTRIES) -> tuple[int, int]:
    """First and last usable LBA of a standard GPT on a disk of DISK_SIZE bytes."""
    array = -(-entries * GPT_ENTRY_SIZE // ss)
    total = disk_size // ss
    return 2 + array, total - 2 - array


def _attrs_text(attrs: int) -> str:
    names = []
    if attrs & 1:
        names.append("RequiredPartition")
    if attrs & 2:
        names.append("NoBlockIOProtocol")
    if attrs & 4:
        names.append("LegacyBIOSBootable")
    bits = [str(b) for b in range(48, 64) if attrs >> b & 1]
    if bits:
        names.append("GUID:" + ",".join(bits))
    return ",".join(names)


def _clean_name(name: str) -> str:
    name = "".join(c for c in (name or "") if c.isprintable() and c not in '"\\')
    out, units = "", 0
    for c in name:
        n = 2 if ord(c) > 0xFFFF else 1
        if units + n > 36:
            break
        out += c
        units += n
    return out


def plan_table(table_type: str, partitions: list[dict], disk_size: int, sector_size: int = 512,
               label_id: str | None = None) -> dict:
    """Check a new partition table and write the sfdisk script for it.

    PARTITIONS: [{"start": bytes, "size": bytes, "type": GUID or "0xNN" (or "fstype" to choose one), "name",
    "guid", "bootable", "logical", "attrs"}]. For MBR, logical partitions go in an extended partition
    (given explicitly with an extended type, or made to fit around the logical ones). Returns {"ok",
    "problems", "script", "table_type", "sector_size", "disk_size", "partitions", "ebr_offsets"}."""
    ss = int(sector_size or 512)
    problems: list[str] = []
    out: dict = {"ok": False, "problems": problems, "script": "", "table_type": table_type, "sector_size": ss,
                 "disk_size": disk_size, "partitions": [], "ebr_offsets": [], "ebr_ranges": [], "label_id": label_id}
    if table_type not in ("gpt", "dos"):
        problems.append(f"Unknown partition table type {table_type!r} (gpt or dos).")
        return out
    total = disk_size // ss
    norm: list[dict] = []
    for i, p in enumerate(partitions):
        try:
            start, size = int(p["start"]), int(p["size"])
        except (KeyError, TypeError, ValueError):
            problems.append(f"Partition {i + 1} has no valid start or size.")
            continue
        n = p.get("number") or i + 1
        if start % ss or size % ss:
            problems.append(f"Partition {n} isn't aligned to the {ss}-byte sectors.")
        if size <= 0:
            problems.append(f"Partition {n} has no size.")
            continue
        t = p.get("type") or type_for(p.get("fstype"), table_type, p.get("role"))
        if table_type == "gpt":
            if is_extended(t):
                continue                       # an MBR extended container has no place in a GPT
            if len(str(t)) != 36:
                t = type_for(p.get("fstype"), "gpt", p.get("role"))
            t = str(t).upper()
        else:
            if len(str(t)) == 36:
                t = type_for(p.get("fstype"), "dos", p.get("role"))
            t = norm_mbr_type(t)
        norm.append({"start": start, "size": size, "type": t, "name": _clean_name(p.get("name") or ""),
                     "guid": (p.get("guid") or "").upper(), "bootable": bool(p.get("bootable")),
                     "logical": bool(p.get("logical")) and table_type == "dos", "attrs": int(p.get("attrs") or 0),
                     "extended": table_type == "dos" and is_extended(t), "fstype": p.get("fstype") or "",
                     "label": p.get("label") or ""})
    norm.sort(key=lambda p: (p["start"], not p["extended"]))
    for p in norm:
        if p["start"] + p["size"] > total * ss:
            problems.append(f"The partition at {p['start'] // ss} ends past the end of the disk.")
    real = [p for p in norm if not p["extended"]]
    for a, b in zip(real, real[1:]):
        if b["start"] < a["start"] + a["size"]:
            problems.append(f"The partitions at sectors {a['start'] // ss} and {b['start'] // ss} overlap.")
    lines: list[str] = []
    if table_type == "gpt":
        first, last = _gpt_layout(disk_size, ss)
        if len(real) > GPT_ENTRIES:
            problems.append(f"A GPT holds at most {GPT_ENTRIES} partitions.")
        for p in real:
            if p["start"] // ss < first or (p["start"] + p["size"]) // ss - 1 > last:
                problems.append(f"The partition at sector {p['start'] // ss} is outside the area a GPT allows "
                                f"(sectors {first} to {last}).")
        head = ["label: gpt"]
        if label_id:
            head.append(f"label-id: {label_id.upper()}")
        head += ["unit: sectors", f"first-lba: {first}", f"last-lba: {last}", ""]
        for p in real:
            fields = [f"start={p['start'] // ss}", f"size={p['size'] // ss}", f"type={p['type']}"]
            if p["guid"] and len(p["guid"]) == 36:
                fields.append(f"uuid={p['guid']}")
            if p["name"]:
                fields.append(f'name="{p["name"]}"')
            attrs = p["attrs"] | (4 if p["bootable"] and not p["attrs"] & 4 else 0)
            if attrs:
                fields.append(f'attrs="{_attrs_text(attrs)}"')
            lines.append(", ".join(fields))
        out["partitions"] = [dict(p, number=i + 1) for i, p in enumerate(real)]
    else:
        ext = [p for p in norm if p["extended"]]
        logicals = [p for p in real if p["logical"]]
        primaries = [p for p in real if not p["logical"]]
        if len(ext) > 1:
            problems.append("An MBR can hold only one extended partition.")
        if logicals and not ext:
            first_l = logicals[0]
            prev_end = max((p["start"] + p["size"] for p in primaries if p["start"] < first_l["start"]), default=ss)
            gap = first_l["start"] - prev_end
            if gap < ss:
                problems.append(f"There is no free sector before the logical partition at sector "
                                f"{first_l['start'] // ss} for its table (EBR).")
            start = first_l["start"] - min(max(gap, ss), MiB if MiB % ss == 0 else ss)
            start -= start % ss
            end = max(p["start"] + p["size"] for p in logicals)
            ext = [{"start": start, "size": end - start, "type": "0x0f" if end > 8 * 1024 ** 3 else "0x05",
                    "extended": True, "logical": False, "bootable": False, "name": "", "guid": "", "attrs": 0,
                    "fstype": "", "label": ""}]
        if ext:
            e = ext[0]
            for p in logicals:
                if not (e["start"] < p["start"] and p["start"] + p["size"] <= e["start"] + e["size"]):
                    problems.append(f"The logical partition at sector {p['start'] // ss} isn't inside the extended "
                                    "partition.")
            for p in primaries:
                if p["start"] < e["start"] + e["size"] and e["start"] < p["start"] + p["size"]:
                    problems.append(f"The primary partition at sector {p['start'] // ss} overlaps the extended "
                                    "partition.")
            # the first EBR is the extended partition's first sector; sfdisk puts each later one in the free
            # space before its logical partition (1 MiB before it, or the sector before it when the gap is
            # smaller): that space must exist, and all of it is backed up before writing
            prev_end = e["start"]
            for k, p in enumerate(logicals):
                if k == 0:
                    if p["start"] <= e["start"]:
                        problems.append(f"There is no free sector before the logical partition at sector "
                                        f"{p['start'] // ss} for its table (EBR).")
                    out["ebr_offsets"].append(e["start"])
                    out["ebr_ranges"].append((e["start"], ss))
                else:
                    gap = p["start"] - prev_end
                    if gap < ss:
                        problems.append(f"There is no free sector before the logical partition at sector "
                                        f"{p['start'] // ss} for its table (EBR).")
                    else:
                        out["ebr_offsets"].append(p["start"] - (MiB if gap >= MiB else ss))
                        out["ebr_ranges"].append((p["start"] - min(gap, MiB), min(gap, MiB)))
                prev_end = p["start"] + p["size"]
        if len(primaries) + len(ext) > 4:
            problems.append("An MBR holds at most 4 primary partitions (or 3 and an extended one with logical "
                            "partitions inside).")
        for p in primaries + ext + logicals:
            if (p["start"] + p["size"]) // ss > MBR_LIMIT_SECTORS - 1:
                limit = f"{MBR_LIMIT_SECTORS * ss // TiB} TiB"
                problems.append(f"The partition at sector {p['start'] // ss} goes past {limit}, the limit of an MBR "
                                "partition table: use GPT.")
                break
        if any(p["start"] < ss for p in primaries + ext):
            problems.append("A partition can't start in sector 0 (it holds the MBR).")
        head = ["label: dos"]
        if label_id and str(label_id).lower().startswith("0x"):
            head.append(f"label-id: {label_id}")
        head += ["unit: sectors", f"grain: {ss}", ""]
        ordered = sorted(primaries + ext, key=lambda p: p["start"])
        numbered = []
        for p in ordered:
            fields = [f"start={p['start'] // ss}", f"size={p['size'] // ss}", f"type={p['type'][2:]}"]
            if p["bootable"]:
                fields.append("bootable")
            lines.append(", ".join(fields))
            numbered.append(dict(p, number=len(numbered) + 1))
            if p["extended"]:
                for k, lp in enumerate(logicals):
                    fields = [f"start={lp['start'] // ss}", f"size={lp['size'] // ss}", f"type={lp['type'][2:]}"]
                    if lp["bootable"]:
                        fields.append("bootable")
                    lines.append(", ".join(fields))
        out["partitions"] = numbered + [dict(lp, number=5 + k) for k, lp in enumerate(logicals)]
    out["script"] = "\n".join(head + lines) + "\n"
    out["ok"] = not problems
    return out


# ---------------------------------------------------------------------- writing
def _ranges_to_save(old: dict, plan: dict, size: int, ss: int) -> list[tuple[int, int]]:
    ranges = [(0, 34 * ss), (max(0, size - 33 * ss), 33 * ss)]
    for off in list(old.get("ebrs") or []) + list(plan.get("ebr_offsets") or []):
        ranges.append((int(off), ss))
    for off, n in plan.get("ebr_ranges") or []:
        ranges.append((int(off), int(n)))
    g = old.get("gpt") or {}
    if g.get("backup_lba"):
        ranges.append((int(g["backup_lba"]) * int(old.get("sector_size") or ss) - 32 * ss, 33 * ss))
    return ranges


def _keep_identity(plan: dict, old: dict) -> dict:
    """Rewriting the table of the same disk keeps its identity when the plan doesn't set one: the MBR disk
    signature or GPT disk GUID, and the GUIDs of GPT partitions that start where they did (Windows finds
    its boot partition through them)."""
    ttype = plan["table_type"]
    label_id = plan.get("label_id")
    parts = [dict(p) for p in plan["partitions"]]
    changed = False
    if not label_id:
        if ttype == "gpt" and old.get("type") == "gpt" and (old.get("gpt") or {}).get("disk_guid"):
            label_id = old["gpt"]["disk_guid"]
        elif ttype == "dos" and old.get("type") == "dos":
            sig = (old.get("mbr") or {}).get("disk_signature")
            if sig and sig != "0x00000000":
                label_id = sig
        changed = bool(label_id)
    if ttype == "gpt" and old.get("type") == "gpt":
        by_start = {p["start"]: p for p in old.get("partitions") or [] if p.get("guid")}
        for p in parts:
            if not p.get("guid") and p["start"] in by_start:
                p["guid"] = by_start[p["start"]]["guid"]
                changed = True
    if not changed:
        return plan
    new = plan_table(ttype, parts, plan["disk_size"], plan["sector_size"], label_id)
    return new if new["ok"] else plan


def _attach_loop(path: str, ss: int) -> str:
    if os.geteuid() != 0:
        raise NotPermitted(f"Writing a partition table with {ss}-byte sectors to an image file needs a loop "
                           "device (administrator rights)")
    rr = run(["losetup", "--sector-size", str(ss), "--show", "-f", path], timeout=60)
    if not rr.ok or not rr.stdout.strip():
        raise RallError(f"Can't attach {path} as a {ss}-byte-sector loop device: {rr.error_text()}")
    return rr.stdout.strip()


def write_table(device: str, plan: dict, backup_dir: str) -> dict:
    """Write PLAN (from plan_table) to DEVICE (a disk or an image file). Everything that may change is saved
    first; the table is re-read and compared afterwards. Returns {"backup", "table", "verified",
    "problems"}. Refused (UnsafeOperation) when the disk or one of its partitions is in use."""
    from . import rawwrite
    if not plan.get("ok"):
        raise RallError("The new partition table has problems: " + "; ".join(plan.get("problems") or ["unknown"]))
    rawwrite.check_not_busy(device, what="Writing the partition table")
    st = os.stat(os.path.realpath(device))
    is_blk = stat.S_ISBLK(st.st_mode)
    ss = int(plan.get("sector_size") or 512)
    with FileSource(device) as src:
        size = src.size
        if is_blk and src.sector_size != ss:
            raise RallError(f"The plan uses {ss}-byte sectors but {device} has {src.sector_size}-byte sectors")
        if size != int(plan.get("disk_size") or size):
            raise RallError("The plan was made for a disk of another size")
        old = read_table(src)
    plan = _keep_identity(plan, old)
    ranges = _ranges_to_save(old, plan, size, ss)
    backup = rawwrite.backup_ranges(device, ranges, backup_dir, f"partition-table-{plan['table_type']}")
    target, loop = device, None
    if not is_blk and ss != 512:
        loop = target = _attach_loop(device, ss)
    try:
        cmd = ["sfdisk", "--wipe", "never", "--wipe-partitions", "never"]
        if not is_blk or loop:
            cmd += ["--no-reread", "--no-tell-kernel"]
        rr = run(cmd + [target], timeout=120, input_text=plan["script"])
    finally:
        if loop:
            detach_loop(loop, timeout=10)
    if not rr.ok:
        raise RallError(f"sfdisk couldn't write the table: {rr.error_text()} (nothing to undo if it wrote nothing; "
                        f"the old sectors are saved in {backup})")
    # a GPT left behind under a new MBR would confuse some tools: clear its two headers (they are saved)
    if plan["table_type"] == "dos" and old.get("type") == "gpt":
        oss = int(old.get("sector_size") or ss)
        for lba in {1, (old.get("gpt") or {}).get("backup_lba") or size // oss - 1}:
            try:
                with open(device, "rb") as fh:
                    fh.seek(lba * oss)
                    if fh.read(8) == b"EFI PART":
                        rawwrite.write_at(device, lba * oss, bytes(oss))
            except OSError:
                pass
    try:
        rawwrite.note_written(backup)
    except RallError as exc:
        log.warning("couldn't note the new state in %s: %s", backup, exc)
    if is_blk:
        rawwrite.reread_partitions(device)
    with FileSource(device, sector_size=None if is_blk else ss) as src:
        table = read_table(src)
    problems = []
    want = sorted((p["start"], p["size"]) for p in plan["partitions"] if not p.get("extended"))
    got = sorted((p["start"], p["size"]) for p in table["partitions"] if not p.get("extended"))
    if table["type"] != plan["table_type"]:
        problems.append(f"The disk now shows a {table['type']} table instead of {plan['table_type']}.")
    if want != got:
        problems.append("The partitions read back differ from the plan.")
    saved = [(off, off + n) for off, n in ranges]
    for ebr in table.get("ebrs") or []:
        if not any(a <= ebr and ebr + 512 <= b for a, b in saved):
            problems.append(f"The table of a logical partition was written at byte {ebr}, outside the saved "
                            "sectors: Undo can't restore that one sector.")
    return {"backup": backup, "table": table, "verified": not problems, "problems": problems}


def undo(backup_path: str) -> dict:
    """Put back the sectors saved before a write_table (or any other change)."""
    from . import rawwrite
    res = rawwrite.restore(backup_path)
    try:
        with FileSource(res["device"]) as src:
            res["table"] = read_table(src)
    except (RallError, OSError):
        pass
    return res
