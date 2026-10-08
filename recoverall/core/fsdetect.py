"""What is at the start of a volume: filesystems, encrypted containers, LVM and RAID members, swap.

:func:`identify` looks at the first sectors of a volume (and its last ones, for RAID superblocks kept at
the end) and answers with a small dict::

    {"fstype": "ext4", "label": "data", "uuid": "…", "size": <filesystem size in bytes>, "block_size": 4096,
     "version": "1.0", ...type-specific fields...}

Only light header parsing is done here, without the full filesystem readers: a boot sector, a superblock,
sometimes one more block (the NTFS $Volume record and the FAT/exFAT root folder for the label, the HFS+
catalog's first leaf). Every number read from the disk is checked before it is used and a damaged or
unknown structure gives None, never an exception, so the partition search can call this on millions of
candidate offsets. The first 68 KiB of the volume are read in one go: every primary signature we know
lives there (Btrfs and ReiserFS at 64 KiB are the furthest).

"size" is what the filesystem says it occupies, which is what a recovered partition needs at least: for
NTFS it includes the backup boot sector (the sector after the volume), like the partitions Windows makes.
Encrypted containers (LUKS, BitLocker without its metadata) and ZFS members don't record their size: it is
None then. The fstype names are those of ``recoverall.core.fs.NAMES``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import struct
import uuid as uuidlib
import zlib
from typing import Callable, NamedTuple

log = logging.getLogger(__name__)

HEAD = 68 * 1024                # read in one piece at every probed offset
MAX_READ = 16 * 1024 * 1024     # no single structure read here is bigger than this

# ---------------------------------------------------------------------- where the signatures are
class Signature(NamedTuple):
    fstype: str
    struct_offset: int          # where the structure starts, from the start of the volume
    magic_offset: int           # where the magic is inside the structure
    magic: bytes
    what: str                   # "boot sector", "superblock", ... (plain words for the evidence column)
    copies: str = ""            # where the backup copies are, if any


SIGNATURES: tuple[Signature, ...] = (
    Signature("ntfs", 0, 3, b"NTFS    ", "boot sector", "a backup in the sector after the volume"),
    Signature("exfat", 0, 3, b"EXFAT   ", "boot sector", "a backup boot region at sector 12"),
    Signature("fat32", 0, 510, b"\x55\xaa", "boot sector", "a backup boot sector, usually at sector 6"),
    Signature("fat16", 0, 510, b"\x55\xaa", "boot sector"),
    Signature("fat12", 0, 510, b"\x55\xaa", "boot sector"),
    Signature("refs", 0, 3, b"ReFS\x00\x00\x00\x00", "boot sector"),
    Signature("bitlocker", 0, 3, b"-FVE-FS-", "boot sector"),
    Signature("ext4", 1024, 56, b"\x53\xef", "superblock", "backups at the start of block groups 1, 3, 5, 7, 9, …"),
    Signature("xfs", 0, 0, b"XFSB", "superblock", "a copy at the start of every allocation group"),
    Signature("btrfs", 65536, 64, b"_BHRfS_M", "superblock", "copies at 64 MiB and 256 GiB"),
    Signature("hfsplus", 1024, 0, b"H+\x00\x04", "volume header", "an alternate header 1 KiB before the end"),
    Signature("hfsx", 1024, 0, b"HX\x00\x05", "volume header", "an alternate header 1 KiB before the end"),
    Signature("hfs", 1024, 0, b"BD", "master directory block"),
    Signature("apfs", 0, 32, b"NXSB", "container superblock", "copies in the checkpoint area"),
    Signature("f2fs", 1024, 0, b"\x10\x20\xf5\xf2", "superblock", "a copy in the second 4 KiB block"),
    Signature("iso9660", 32768, 1, b"CD001", "volume descriptor"),
    Signature("udf", 32768, 1, b"NSR0", "volume recognition sequence", "anchors at sector 256 and at the end"),
    Signature("jfs", 32768, 0, b"JFS1", "superblock", "a copy at 60 KiB"),
    Signature("reiserfs", 65536, 52, b"ReIsEr", "superblock"),
    Signature("squashfs", 0, 0, b"hsqs", "superblock"),
    Signature("erofs", 1024, 0, b"\xe2\xe1\xf5\xe0", "superblock"),
    Signature("ufs", 65536, 1372, b"\x19\x01\x54\x19", "superblock", "copies in every cylinder group"),
    Signature("ufs", 8192, 1372, b"\x54\x19\x01\x00", "superblock", "copies in every cylinder group"),
    Signature("nilfs2", 1024, 6, b"\x34\x34", "superblock", "a copy near the end"),
    Signature("minix", 1024, 16, b"\x8f\x13", "superblock"),
    Signature("swap", 4086, 0, b"SWAPSPACE2", "swap header"),
    Signature("crypto_luks", 0, 0, b"LUKS\xba\xbe", "LUKS header", "LUKS2 keeps a second header after the first"),
    Signature("lvm2_member", 512, 0, b"LABELONE", "LVM label"),
    Signature("linux_raid_member", 4096, 0, b"\xfc\x4e\x2b\xa9", "RAID superblock",
              "metadata 1.1 at the start, 1.2 at 4 KiB, 0.90 and 1.0 at the end"),
    Signature("zfs_member", 16384, 0, b"\x01\x01\x00\x00", "ZFS label", "four labels: two at the start, two at the end"),
)

# ---------------------------------------------------------------------- small helpers
_u16 = struct.Struct("<H").unpack_from
_u32 = struct.Struct("<I").unpack_from
_u64 = struct.Struct("<Q").unpack_from
_b16 = struct.Struct(">H").unpack_from
_b32 = struct.Struct(">I").unpack_from
_b64 = struct.Struct(">Q").unpack_from


def u16(b: bytes, o: int) -> int:
    return _u16(b, o)[0]


def u32(b: bytes, o: int) -> int:
    return _u32(b, o)[0]


def u64(b: bytes, o: int) -> int:
    return _u64(b, o)[0]


def be16(b: bytes, o: int) -> int:
    return _b16(b, o)[0]


def be32(b: bytes, o: int) -> int:
    return _b32(b, o)[0]


def be64(b: bytes, o: int) -> int:
    return _b64(b, o)[0]


def _pow2(n: int) -> bool:
    return n > 0 and n & (n - 1) == 0


def _cstr(raw: bytes, encoding: str = "latin-1") -> str:
    """A NUL-terminated (or padded) string."""
    return raw.split(b"\x00", 1)[0].decode(encoding, "replace").strip()


def _utf16(raw: bytes, be: bool = False) -> str:
    raw = raw[:len(raw) // 2 * 2]
    text = raw.decode("utf-16-be" if be else "utf-16-le", "replace")
    return text.split("\x00", 1)[0].strip()


def _uuid(raw: bytes) -> str:
    """A Linux-style UUID (bytes in order); empty for all zeros."""
    if len(raw) != 16 or not any(raw):
        return ""
    return str(uuidlib.UUID(bytes=bytes(raw)))


def guid_le(raw: bytes) -> str:
    """A Microsoft GUID (first three fields little-endian), upper case as Windows and sfdisk print it."""
    if len(raw) != 16:
        return ""
    return str(uuidlib.UUID(bytes_le=bytes(raw))).upper()


def _serial(v: int) -> str:
    return f"{v >> 16 & 0xFFFF:04X}-{v & 0xFFFF:04X}"


def _info(fstype: str, size: int | None = None, label: str = "", uuid: str = "", block_size: int | None = None,
          version: str = "", extra: dict | None = None, **kw) -> dict:
    """The common answer; EXTRA/KW add type-specific fields (they never replace the common ones)."""
    d = {"fstype": fstype, "label": label or "", "uuid": uuid or "", "size": size, "block_size": block_size,
         "version": version or ""}
    for k, v in {**(extra or {}), **kw}.items():
        d.setdefault(k, v)
    return d


_CRC32C: list[int] | None = None


def crc32c(data: bytes, crc: int = 0) -> int:
    """CRC-32C (Castagnoli), as Btrfs, ext4 metadata_csum and XFS v5 use it. Only for small structures."""
    global _CRC32C
    if _CRC32C is None:
        table = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
            table.append(c)
        _CRC32C = table
    t = _CRC32C
    crc ^= 0xFFFFFFFF
    for b in data:
        crc = t[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def crc32_raw(seed: int, data: bytes) -> int:
    """The CRC-32 update without the final inversion (LVM labels, NILFS2): seed in, raw state out."""
    return (~zlib.crc32(data, ~seed & 0xFFFFFFFF)) & 0xFFFFFFFF


def fletcher64(block: bytes) -> int:
    """The APFS object checksum of BLOCK (its first 8 bytes are the stored checksum and are skipped)."""
    words = struct.unpack_from(f"<{(len(block) - 8) // 4}I", block, 8)
    mod = 0xFFFFFFFF
    n = len(words)
    s1 = sum(words) % mod
    s2 = sum((n - i) * w for i, w in enumerate(words)) % mod
    c1 = mod - ((s1 + s2) % mod)
    c2 = mod - ((s1 + c1) % mod)
    return (c2 << 32) | c1


# ---------------------------------------------------------------------- reading
class _Reader:
    """Reads relative to BASE in SRC; the first HEAD bytes come from one read (or from HEAD given by a caller
    that read a bigger piece already, e.g. the partition search batching its reads)."""

    __slots__ = ("src", "base", "size", "_head")

    def __init__(self, src, base: int = 0, head: bytes | None = None, size: int | None = None):
        self.src = src
        self.base = base
        self.size = max(0, src.size - base) if size is None else size
        self._head = head

    def head(self) -> bytes:
        if self._head is None or len(self._head) < HEAD:
            have = self._head or b""
            self._head = have + self.src.read(self.base + len(have), HEAD - len(have))
        return self._head

    def read(self, off: int, n: int) -> bytes:
        if off < 0 or n <= 0:
            return bytes(max(0, n))
        n = min(n, MAX_READ)
        h = self._head
        if h is not None and off + n <= len(h):
            return h[off:off + n]
        if off + n <= HEAD:
            h = self.head()
            return h[off:off + n]
        return self.src.read(self.base + off, n)


# ---------------------------------------------------------------------- Microsoft: NTFS, FAT, exFAT, ReFS, BitLocker
def ntfs_fixup(rec: bytes) -> bytes | None:
    """Undo the NTFS update-sequence protection of an MFT record (None if it is torn or not a record)."""
    if len(rec) < 512 or rec[:4] != b"FILE":
        return None
    usa_ofs, usa_cnt = u16(rec, 4), u16(rec, 6)
    if usa_cnt < 2 or usa_ofs + usa_cnt * 2 > len(rec) or (usa_cnt - 1) * 512 > len(rec):
        return None
    buf = bytearray(rec)
    usn = rec[usa_ofs:usa_ofs + 2]
    for i in range(1, usa_cnt):
        end = i * 512 - 2
        if buf[end:end + 2] != usn:
            return None
        buf[end:end + 2] = rec[usa_ofs + 2 * i:usa_ofs + 2 * i + 2]
    return bytes(buf)


def parse_ntfs_boot(b: bytes) -> dict | None:
    """The geometry in an NTFS boot sector (also used for the backup boot sector), or None."""
    if len(b) < 512 or b[3:11] != b"NTFS    ":
        return None
    bps = u16(b, 11)
    if bps not in (256, 512, 1024, 2048, 4096):
        return None
    spc_raw = b[13]
    spc = spc_raw if spc_raw <= 0x80 else 1 << (256 - spc_raw)
    if not _pow2(spc):
        return None
    cs = bps * spc
    if cs > 2 * 1024 * 1024:
        return None
    total = u64(b, 0x28)
    mft, mirr = u64(b, 0x30), u64(b, 0x38)
    if total == 0 or total > 1 << 48:
        return None
    clusters = total * bps // cs
    if mft >= clusters and mirr >= clusters:
        return None
    cpr = struct.unpack_from("<b", b, 0x40)[0]
    rs = cpr * cs if cpr > 0 else 1 << (-cpr)
    if not 256 <= rs <= 65536:
        return None
    cpi = struct.unpack_from("<b", b, 0x44)[0]
    return {"sector_size": bps, "cluster_size": cs, "total_sectors": total, "mft_offset": mft * cs,
            "mftmirr_offset": mirr * cs, "record_size": rs, "index_size": cpi * cs if cpi > 0 else 1 << (-cpi),
            "serial": u64(b, 0x48), "hidden_sectors": u32(b, 0x1C), "signature_ok": b[510:512] == b"\x55\xaa",
            "size": (total + 1) * bps}


def _probe_ntfs(r: _Reader) -> dict | None:
    b = r.read(0, 512)
    p = parse_ntfs_boot(b)
    if p is None:
        return None
    label, version = "", ""
    try:
        rec = ntfs_fixup(r.read(p["mft_offset"] + 3 * p["record_size"], p["record_size"]))
        if rec is not None:
            label, version = _ntfs_volume(rec)
    except (struct.error, IndexError, ValueError):
        pass
    return _info("ntfs", p["size"], label, f"{p['serial']:016X}", p["cluster_size"], version, p)


def ntfs_label(src, start: int, geometry: dict) -> tuple[str, str]:
    """The volume name and NTFS version of the NTFS volume at START of SRC, read from its $Volume record
    with GEOMETRY (from parse_ntfs_boot, e.g. of the backup boot sector)."""
    try:
        rs = geometry["record_size"]
        for mft in (geometry["mft_offset"], geometry["mftmirr_offset"]):
            rec = ntfs_fixup(src.read(start + mft + 3 * rs, rs))
            if rec is not None:
                return _ntfs_volume(rec)
    except (KeyError, struct.error, IndexError, ValueError):
        pass
    return "", ""


def _ntfs_volume(rec: bytes) -> tuple[str, str]:
    """The volume name and NTFS version from the $Volume record."""
    pos = u16(rec, 0x14)
    label = version = ""
    for _ in range(64):
        if pos + 24 > len(rec):
            break
        atype = u32(rec, pos)
        if atype == 0xFFFFFFFF:
            break
        alen = u32(rec, pos + 4)
        if alen < 16 or pos + alen > len(rec):
            break
        if rec[pos + 8] == 0:
            vlen, voff = u32(rec, pos + 16), u16(rec, pos + 20)
            if voff + vlen <= alen:
                val = rec[pos + voff:pos + voff + vlen]
                if atype == 0x60:
                    label = val.decode("utf-16-le", "replace")
                elif atype == 0x70 and len(val) >= 10:
                    version = f"{val[8]}.{val[9]}"
        pos += alen
    return label, version


def parse_fat_bpb(b: bytes) -> dict | None:
    """The BIOS parameter block of a FAT12/16/32 boot sector, checked for sanity, or None."""
    if len(b) < 512:
        return None
    if b[0] not in (0xEB, 0xE9) and not (b[0] == 0 and b"FAT" in b[54:90]):
        return None
    bps, spc, rsvd, nfats, root_ent, tot16, media, fatsz16 = struct.unpack_from("<HBHBHHBH", b, 11)
    tot32 = u32(b, 32)
    if bps not in (512, 1024, 2048, 4096) or not _pow2(spc) or spc > 128:
        return None
    if rsvd == 0 or nfats not in (1, 2, 3, 4) or (media != 0xF0 and media < 0xF8):
        return None
    total = tot16 or tot32
    fat32 = fatsz16 == 0
    fatsz = u32(b, 36) if fat32 else fatsz16
    if total == 0 or fatsz == 0 or (fat32 and root_ent != 0):
        return None
    root_sectors = (root_ent * 32 + bps - 1) // bps
    first_data = rsvd + nfats * fatsz + root_sectors
    if first_data >= total:
        return None
    clusters = (total - first_data) // spc
    bits = 32 if fat32 else (12 if clusters < 4085 else 16)
    if fatsz * bps * 8 // bits < clusters + 2:
        return None                      # the FAT can't map the volume: not a real BPB
    if fat32:
        ext_sig, serial, blabel = b[66], u32(b, 67), b[71:82]
    else:
        ext_sig, serial, blabel = b[38], u32(b, 39), b[43:54]
    has_ext = ext_sig in (0x28, 0x29)
    label = blabel.decode("latin-1", "replace").strip() if ext_sig == 0x29 else ""
    if label.upper() == "NO NAME":
        label = ""
    out = {"fat_bits": bits, "sector_size": bps, "cluster_size": bps * spc, "reserved_sectors": rsvd,
           "fats": nfats, "fat_sectors": fatsz, "root_entries": root_ent, "total_sectors": total,
           "first_data_sector": first_data, "clusters": clusters, "media": media,
           "serial": serial if has_ext else 0, "bpb_label": label, "hidden_sectors": u32(b, 28),
           "signature_ok": b[510:512] == b"\x55\xaa", "size": total * bps}
    if fat32:
        out.update({"root_cluster": u32(b, 44), "fsinfo_sector": u16(b, 48), "backup_boot_sector": u16(b, 50),
                    "fat_flags": u16(b, 40)})
    return out


def _fat_dir_label(d: bytes) -> str | None:
    """The volume label entry of a FAT folder (the root), None if there is none in this piece."""
    for pos in range(0, len(d) - 31, 32):
        first = d[pos]
        if first == 0:
            return None
        attr = d[pos + 11]
        if first != 0xE5 and attr != 0x0F and attr & 0x08 and not attr & 0x10:
            return d[pos:pos + 11].decode("latin-1", "replace").strip()
    return None


def _probe_fat(r: _Reader) -> dict | None:
    b = r.read(0, 512)
    if b[3:11] in (b"NTFS    ", b"EXFAT   ", b"-FVE-FS-") or b[3:7] == b"ReFS":
        return None
    p = parse_fat_bpb(b)
    if p is None or not p["signature_ok"] and b[0] != 0xEB:
        return None
    bps = p["sector_size"]
    label = p["bpb_label"]
    try:
        if p["fat_bits"] == 32:
            rc = p["root_cluster"]
            if 2 <= rc < p["clusters"] + 2:
                off = (p["first_data_sector"] + (rc - 2) * p["cluster_size"] // bps) * bps
                found = _fat_dir_label(r.read(off, min(p["cluster_size"], 65536)))
                if found is not None:
                    label = found
        else:
            off = (p["reserved_sectors"] + p["fats"] * p["fat_sectors"]) * bps
            found = _fat_dir_label(r.read(off, min(p["root_entries"] * 32, 16384)))
            if found is not None:
                label = found
    except (struct.error, IndexError):
        pass
    if label.upper() == "NO NAME":
        label = ""
    fstype = f"fat{p['fat_bits']}"
    return _info(fstype, p["size"], label, _serial(p["serial"]) if p["serial"] else "", p["cluster_size"],
                 f"FAT{p['fat_bits']}", p)


def parse_exfat_boot(b: bytes) -> dict | None:
    if len(b) < 512 or b[3:11] != b"EXFAT   " or any(b[11:64]):
        return None
    bps_shift, spc_shift, nfats = b[108], b[109], b[110]
    if not 9 <= bps_shift <= 12 or bps_shift + spc_shift > 25 or nfats not in (1, 2):
        return None
    bps = 1 << bps_shift
    vol_len, fat_off, fat_len, heap_off, count, root = struct.unpack_from("<QIIIII", b, 72)
    if vol_len == 0 or fat_off < 24 or fat_len == 0 or heap_off < fat_off or count == 0:
        return None
    if heap_off + (count << spc_shift) > vol_len + (1 << spc_shift):
        return None
    rev = u16(b, 104)
    return {"sector_size": bps, "cluster_size": bps << spc_shift, "total_sectors": vol_len, "fat_offset": fat_off,
            "fat_sectors": fat_len, "heap_offset": heap_off, "clusters": count, "root_cluster": root,
            "serial": u32(b, 100), "revision": f"{rev >> 8}.{rev & 0xFF}", "fats": nfats,
            "volume_flags": u16(b, 106), "signature_ok": b[510:512] == b"\x55\xaa", "size": vol_len * bps}


def exfat_boot_checksum(region: bytes, bps: int) -> int:
    """The checksum of an exFAT boot region (sectors 0-10), stored repeated in sector 11."""
    data = region[:11 * bps]
    s = 0
    for i, byte in enumerate(data):
        if i in (106, 107, 112):
            continue
        s = ((s >> 1) | ((s & 1) << 31)) + byte
        s &= 0xFFFFFFFF
    return s


def _probe_exfat(r: _Reader) -> dict | None:
    p = parse_exfat_boot(r.read(0, 512))
    if p is None:
        return None
    label = ""
    try:
        rc = p["root_cluster"]
        if 2 <= rc < p["clusters"] + 2:
            off = p["heap_offset"] * p["sector_size"] + (rc - 2) * p["cluster_size"]
            d = r.read(off, min(p["cluster_size"], 65536))
            for pos in range(0, len(d) - 31, 32):
                t = d[pos]
                if t == 0:
                    break
                if t == 0x83:
                    n = min(d[pos + 1], 11)
                    label = d[pos + 2:pos + 2 + 2 * n].decode("utf-16-le", "replace")
                    break
    except (struct.error, IndexError):
        pass
    return _info("exfat", p["size"], label, _serial(p["serial"]), p["cluster_size"], p["revision"], p)


def _probe_refs(r: _Reader) -> dict | None:
    b = r.read(0, 512)
    if b[3:11] != b"ReFS\x00\x00\x00\x00" or b[16:20] != b"FSRS":
        return None
    sectors, bps, spc = u64(b, 0x18), u32(b, 0x20), u32(b, 0x24)
    if bps not in (512, 1024, 2048, 4096) or not _pow2(spc) or sectors == 0:
        return None
    serial = u64(b, 0x38)
    return _info("refs", sectors * bps, "", f"{serial:016X}", bps * spc, f"{b[0x28]}.{b[0x29]}",
                 sector_size=bps, total_sectors=sectors, serial=serial)


_BDE_GUID = bytes.fromhex("3bd66749292ed84a8399f6a339e3d001")


def _probe_bitlocker(r: _Reader) -> dict | None:
    b = r.read(0, 512)
    if b[3:11] == b"-FVE-FS-":
        kind = "vista" if b[0:3] == b"\xeb\x52\x90" else "win7"
        fve = u64(b, 56) if kind == "vista" else u64(b, 176)
    elif b[3:11] == b"MSWIN4.1" and b[424:440] == _BDE_GUID:
        kind = "to_go"
        fve = u64(b, 440)
    else:
        return None
    info = _info("bitlocker", None, "", "", 512, kind, sector_size=u16(b, 11) or 512, fve_metadata_offset=fve)
    if 0 < fve < r.size or (r.size == 0 and fve):
        m = r.read(fve, 512)
        if m[:8] == b"-FVE-FS-":
            ver = u16(m, 10)
            info["version"] = str(ver)
            if ver >= 2:
                vs = u64(m, 16)
                if vs:
                    info["size"] = vs
            vid = m[64 + 16:64 + 32]
            if any(vid):
                info["uuid"] = guid_le(vid).lower()
    return info


# ---------------------------------------------------------------------- Linux: ext, XFS, Btrfs, F2FS, swap...
_EXT3_INCOMPAT = 0x0002 | 0x0004 | 0x0010     # filetype, recover, meta_bg
_EXT3_RO_COMPAT = 0x0001 | 0x0002 | 0x0004   # sparse_super, large_file, btree_dir


def parse_ext_super(sb: bytes) -> dict | None:
    """An ext2/3/4 superblock (1024 bytes) checked for sanity, or None."""
    if len(sb) < 1024 or sb[56:58] != b"\x53\xef":
        return None
    inodes, blocks_lo, _r, free_lo, free_inodes, first_data, log_bs = struct.unpack_from("<IIIIIII", sb, 0)
    bpg, ipg = u32(sb, 32), u32(sb, 40)
    rev = u32(sb, 76)
    if log_bs > 6 or rev > 1 or bpg == 0 or ipg == 0 or inodes == 0 or first_data > 1:
        return None
    bs = 1024 << log_bs
    if bpg > bs * 8 or (bs > 1024 and first_data != 0):
        return None
    compat, incompat, ro_compat = u32(sb, 92), u32(sb, 96), u32(sb, 100)
    blocks = blocks_lo
    if incompat & 0x80:                                   # 64bit
        blocks |= u32(sb, 0x150) << 32
    if blocks == 0 or blocks <= first_data:
        return None
    if ipg > bs * 8 or inodes > ipg * ((blocks - first_data + bpg - 1) // bpg) + ipg:
        return None
    if incompat & ~_EXT3_INCOMPAT & 0xFFFF or ro_compat & ~_EXT3_RO_COMPAT & 0xFFFF:
        fstype = "ext4"
    elif compat & 0x4:                                    # has_journal
        fstype = "ext3"
    else:
        fstype = "ext2"
    return {"fstype": fstype, "block_size": bs, "blocks": blocks, "free_blocks": free_lo, "first_data_block": first_data,
            "blocks_per_group": bpg, "inodes_per_group": ipg, "inodes": inodes, "group": u16(sb, 90),
            "rev": rev, "minor_rev": u16(sb, 62), "state": u16(sb, 58), "compat": compat, "incompat": incompat, "ro_compat": ro_compat,
            "uuid": _uuid(sb[104:120]), "label": _cstr(sb[120:136], "utf-8"), "inode_size": u16(sb, 88) if rev else 128,
            "backup_bgs": (u32(sb, 0x24C), u32(sb, 0x250)), "size": blocks * bs,
            "journal_device": bool(incompat & 0x8)}


def _probe_ext(r: _Reader) -> dict | None:
    p = parse_ext_super(r.read(1024, 1024))
    if p is None or p["group"] != 0:
        return None                     # a backup superblock copied here: not the start of a filesystem
    used = (p["blocks"] - p["free_blocks"]) * p["block_size"] if p["free_blocks"] <= p["blocks"] else None
    return _info(p["fstype"], p["size"], p["label"], p["uuid"], p["block_size"], f"{p['rev']}.{p['minor_rev']}", p,
                 used=used)


def parse_xfs_super(b: bytes) -> dict | None:
    if len(b) < 512 or b[0:4] != b"XFSB":
        return None
    bs, dblocks = be32(b, 4), be64(b, 8)
    agblocks, agcount = be32(b, 84), be32(b, 88)
    versionnum, sectsize = be16(b, 100), be16(b, 102)
    if not _pow2(bs) or not 512 <= bs <= 65536 or not _pow2(sectsize) or not 512 <= sectsize <= 32768:
        return None
    if agcount == 0 or agblocks == 0 or dblocks == 0:
        return None
    if dblocks > agcount * agblocks or dblocks <= (agcount - 1) * agblocks:
        return None
    return {"block_size": bs, "blocks": dblocks, "ag_blocks": agblocks, "ag_count": agcount, "sector_size": sectsize,
            "version": str(versionnum & 0xF), "uuid": _uuid(b[32:48]), "label": _cstr(b[108:120], "utf-8"),
            "inode_size": be16(b, 104), "free_blocks": be64(b, 144), "size": dblocks * bs}


def _probe_xfs(r: _Reader) -> dict | None:
    p = parse_xfs_super(r.read(0, 512))
    if p is None:
        return None
    agf = r.read(p["sector_size"], 16)
    if agf[0:4] == b"XAGF" and be32(agf, 8) != 0:
        return None                     # the superblock copy of a later allocation group
    used = (p["blocks"] - p["free_blocks"]) * p["block_size"] if p["free_blocks"] <= p["blocks"] else None
    return _info("xfs", p["size"], p["label"], p["uuid"], p["block_size"], p["version"], p, used=used)


def parse_btrfs_super(sb: bytes) -> dict | None:
    """A Btrfs superblock (4096 bytes) or None; checksum_ok tells whether its CRC-32C matched."""
    if len(sb) < 4096 or sb[64:72] != b"_BHRfS_M":
        return None
    sectorsize, nodesize = u32(sb, 0x90), u32(sb, 0x94)
    if not _pow2(sectorsize) or not 512 <= sectorsize <= 65536 or not _pow2(nodesize):
        return None
    csum_type = u16(sb, 0xC4)
    ok = None
    if csum_type == 0:
        ok = crc32c(sb[32:4096]) == u32(sb, 0)
    elif csum_type == 2:
        ok = hashlib.sha256(sb[32:4096]).digest() == sb[0:32]
    elif csum_type == 3:
        ok = hashlib.blake2b(sb[32:4096], digest_size=32).digest() == sb[0:32]
    dev = 0xC9
    return {"uuid": _uuid(sb[32:48]), "bytenr": u64(sb, 0x30), "generation": u64(sb, 0x48),
            "total_bytes": u64(sb, 0x70), "bytes_used": u64(sb, 0x78), "num_devices": u64(sb, 0x88),
            "sector_size": sectorsize, "node_size": nodesize, "devid": u64(sb, dev),
            "dev_size": u64(sb, dev + 8), "uuid_sub": _uuid(sb[dev + 66:dev + 82]),
            "label": _cstr(sb[0x12B:0x12B + 256], "utf-8"), "checksum_ok": ok}


def _probe_btrfs(r: _Reader) -> dict | None:
    p = parse_btrfs_super(r.read(65536, 4096))
    if p is None or p["bytenr"] != 65536 or p["checksum_ok"] is False:
        return None
    size = p["dev_size"] or p["total_bytes"]
    used = p["bytes_used"] if p["num_devices"] == 1 else None
    return _info("btrfs", size, p["label"], p["uuid"], p["sector_size"], "", p, used=used)


def _probe_f2fs(r: _Reader) -> dict | None:
    for off in (1024, 4096 + 1024):
        b = r.read(off, 1024)
        if u32(b, 0) != 0xF2F52010:
            continue
        log_ss, log_spb, log_bs = u32(b, 8), u32(b, 12), u32(b, 16)
        if not 9 <= log_ss <= 12 or log_bs != 12 or log_ss + log_spb != log_bs:
            continue
        blocks = u64(b, 36)
        if blocks == 0:
            continue
        return _info("f2fs", blocks << log_bs, _utf16(b[124:124 + 512]), _uuid(b[108:124]), 1 << log_bs,
                     f"{u16(b, 4)}.{u16(b, 6)}", blocks=blocks, backup_superblock=off != 1024)
    return None


def _probe_swap(r: _Reader) -> dict | None:
    for page in (4096, 8192, 16384, 65536):
        sig = r.read(page - 10, 10)
        if sig in (b"SWAPSPACE2", b"SWAP-SPACE"):
            hdr = r.read(1024, 512)
            if sig == b"SWAP-SPACE":
                return _info("swap", None, "", "", page, "0", page_size=page)
            ver, last = u32(hdr, 0), u32(hdr, 4)
            if ver != 1:
                ver, last = be32(hdr, 0), be32(hdr, 4)
                if ver != 1:
                    continue
            if last < 9:
                continue
            return _info("swap", (last + 1) * page, _cstr(hdr[28:44], "utf-8"), _uuid(hdr[12:28]), page, "1",
                         page_size=page, last_page=last)
        if sig[:9] in (b"S1SUSPEND", b"S2SUSPEND", b"ULSUSPEND") or sig == b"LINHIB0001" or sig[:6] == b"\xedWHIB":
            hdr = r.read(1024, 512)
            last = u32(hdr, 4)
            return _info("swap", (last + 1) * page if 9 <= last < 1 << 40 else None, _cstr(hdr[28:44], "utf-8"),
                         _uuid(hdr[12:28]), page, "1", page_size=page, hibernated=True)
    return None


def _probe_squashfs(r: _Reader) -> dict | None:
    b = r.read(0, 96)
    if b[0:4] == b"hsqs":
        u, q = u32, u64
        unpack16 = u16
    elif b[0:4] == b"sqsh":
        u, q = be32, be64
        unpack16 = be16
    else:
        return None
    major, minor = unpack16(b, 28), unpack16(b, 30)
    if major not in (1, 2, 3, 4):
        return None
    block = u(b, 12)
    used = q(b, 40) if major == 4 else u(b, 8)
    if not _pow2(block) or used == 0:
        return None
    size = (used + 4095) // 4096 * 4096
    return _info("squashfs", size, "", "", block, f"{major}.{minor}", bytes_used=used)


def _probe_erofs(r: _Reader) -> dict | None:
    b = r.read(1024, 128)
    if u32(b, 0) != 0xE0F5E1E2:
        return None
    bits = b[12]
    if not 9 <= bits <= 16:
        return None
    blocks = u32(b, 36)
    return _info("erofs", blocks << bits if blocks else None, _cstr(b[64:80], "utf-8"), _uuid(b[48:64]), 1 << bits,
                 "", blocks=blocks)


def _probe_nilfs(r: _Reader) -> dict | None:
    b = r.read(1024, 1024)
    if u16(b, 6) != 0x3434:
        return None
    rev, nbytes = u32(b, 0), u16(b, 8)
    log_bs = u32(b, 20)
    if rev not in (1, 2) or not 256 <= nbytes <= 1024 or log_bs > 6:
        return None
    dev_size = u64(b, 32)
    seed = u32(b, 12)
    crc = crc32_raw(seed, b[:16])
    crc = crc32_raw(crc, b"\x00\x00\x00\x00")
    crc = crc32_raw(crc, b[20:nbytes])
    return _info("nilfs2", dev_size or None, _cstr(b[168:248], "utf-8"), _uuid(b[152:168]), 1024 << log_bs,
                 f"{rev}.{u16(b, 4)}", checksum_ok=crc == u32(b, 16))


def _probe_minix(r: _Reader) -> dict | None:
    b = r.read(1024, 64)
    magic = u16(b, 16)
    v3 = u16(b, 24) == 0x4D5A
    if magic not in (0x137F, 0x138F, 0x2468, 0x2478) and not v3:
        return None
    ninodes, nzones, imap, zmap, firstdata, logzone = struct.unpack_from("<HHHHHH", b, 0)
    if v3:
        ninodes = u32(b, 0)
        imap, zmap, firstdata, logzone = struct.unpack_from("<HHHH", b, 6)
    if ninodes == 0 or imap == 0 or zmap == 0 or logzone != 0 or firstdata == 0:
        return None
    if imap * 1024 * 8 < ninodes + 1:
        return None
    if v3:
        bs = u16(b, 28)
        if bs not in (1024, 2048, 4096, 8192):
            return None
        zones, version = u32(b, 20), "3"
    elif magic in (0x2468, 0x2478):
        bs, zones, version = 1024, u32(b, 20), "2"
    else:
        bs, zones, version = 1024, nzones, "1"
    if zones == 0 or zones <= firstdata or zmap * bs * 8 < zones - firstdata + 1:
        return None
    return _info("minix", zones * bs, "", "", bs, version)


# ---------------------------------------------------------------------- Apple: HFS, HFS+, APFS
_HFS_UUID_NS = bytes.fromhex("b3e20f39f29211d697a400306543ecac")


def hfs_uuid(volume_id: bytes) -> str:
    """The UUID blkid shows for HFS/HFS+: an MD5 name-based UUID of the 64-bit volume id."""
    if not any(volume_id):
        return ""
    h = bytearray(hashlib.md5(_HFS_UUID_NS + bytes(volume_id)).digest())
    h[6] = 0x30 | (h[6] & 0x0F)
    h[8] = 0x80 | (h[8] & 0x3F)
    return str(uuidlib.UUID(bytes=bytes(h)))


def parse_hfsplus_header(vh: bytes) -> dict | None:
    """An HFS+/HFSX volume header (512 bytes) or None."""
    if len(vh) < 512 or vh[0:2] not in (b"H+", b"HX"):
        return None
    ver = be16(vh, 2)
    if (vh[0:2] == b"H+" and ver != 4) or (vh[0:2] == b"HX" and ver != 5):
        return None
    bs, total, free = be32(vh, 40), be32(vh, 44), be32(vh, 48)
    if not _pow2(bs) or bs < 512 or total == 0 or free > total:
        return None
    extents = [struct.unpack_from(">II", vh, 288 + 8 * i) for i in range(8)]
    return {"fstype": "hfsx" if vh[0:2] == b"HX" else "hfsplus", "block_size": bs, "total_blocks": total,
            "free_blocks": free, "attributes": be32(vh, 4), "create_date": be32(vh, 16),
            "volume_id": bytes(vh[104:112]), "catalog_extents": extents, "size": total * bs,
            "journaled": bool(be32(vh, 4) & 0x2000)}


def _hfs_catalog_label(r: _Reader, base: int, p: dict) -> str:
    """The volume name: the key of the first record of the catalog's first leaf (the root folder)."""
    bs = p["block_size"]
    ext = [(s, n) for s, n in p["catalog_extents"] if n]
    if not ext:
        return ""
    node0 = r.read(base + ext[0][0] * bs, 512)
    node_size = be16(node0, 14 + 18)
    first_leaf = be32(node0, 14 + 10)
    if not _pow2(node_size) or not 512 <= node_size <= 32768 or node0[8] != 1:
        return ""
    want = first_leaf * node_size
    pos = 0
    for start, count in ext:
        length = count * bs
        if want < pos + length:
            node = r.read(base + start * bs + (want - pos), node_size)
            break
        pos += length
    else:
        return ""
    if node[8] != 0xFF or be16(node, 10) == 0:
        return ""
    rec = be16(node, node_size - 2)
    if rec + 8 > node_size:
        return ""
    if be32(node, rec + 2) != 1:
        return ""
    n = be16(node, rec + 6)
    if n > 255 or rec + 8 + 2 * n > node_size:
        return ""
    return node[rec + 8:rec + 8 + 2 * n].decode("utf-16-be", "replace")


def _probe_hfs(r: _Reader) -> dict | None:
    vh = r.read(1024, 512)
    if vh[0:2] == b"BD":
        # classic HFS master directory block, possibly a wrapper around an HFS+ volume
        nblocks, absize, clump, alst = be16(vh, 18), be32(vh, 20), be32(vh, 24), be16(vh, 28)
        if not absize or absize % 512 or nblocks == 0 or clump % 512:
            return None
        if vh[124:126] == b"H+":
            start_block, count = be16(vh, 126), be16(vh, 128)
            off = alst * 512 + start_block * absize
            sub = parse_hfsplus_header(r.read(off + 1024, 512))
            if sub:
                label = _safe(lambda: _hfs_catalog_label(r, off, sub))
                return _info(sub["fstype"], alst * 512 + nblocks * absize + 1024, label, hfs_uuid(sub["volume_id"]),
                             sub["block_size"], "wrapped", embedded_offset=off, embedded_blocks=count)
        n = vh[36]
        if n > 27:
            return None
        label = vh[37:37 + n].decode("mac_roman", "replace")
        return _info("hfs", alst * 512 + nblocks * absize + 1024, label, hfs_uuid(vh[116:124]), absize, "")
    p = parse_hfsplus_header(vh)
    if p is None:
        return None
    label = _safe(lambda: _hfs_catalog_label(r, 0, p))
    used = (p["total_blocks"] - p["free_blocks"]) * p["block_size"]
    return _info(p["fstype"], p["size"], label, hfs_uuid(p["volume_id"]), p["block_size"],
                 "5" if p["fstype"] == "hfsx" else "4", used=used, total_blocks=p["total_blocks"],
                 journaled=p["journaled"], create_date=p["create_date"])


def parse_apfs_super(b: bytes, verify: bool = True) -> dict | None:
    if len(b) < 4096 or b[32:36] != b"NXSB" or u32(b, 24) & 0xFFFF != 1:
        return None
    bs, count = u32(b, 36), u64(b, 40)
    if not _pow2(bs) or not 4096 <= bs <= 65536 or count == 0:
        return None
    ok = None
    if verify and len(b) >= bs:
        ok = fletcher64(b[:bs]) == u64(b, 0)
    return {"block_size": bs, "blocks": count, "uuid": _uuid(b[72:88]), "xid": u64(b, 16),
            "xp_desc_base": u64(b, 104), "xp_desc_blocks": u32(b, 136) & 0x7FFFFFFF, "checksum_ok": ok,
            "size": bs * count}


def _probe_apfs(r: _Reader) -> dict | None:
    head = r.read(0, 4096)
    if head[32:36] != b"NXSB":
        return None
    bs = u32(head, 36)
    b = head if bs <= 4096 else r.read(0, min(bs, 65536))
    p = parse_apfs_super(b)
    if p is None or p["checksum_ok"] is False:
        return None
    return _info("apfs", p["size"], "", p["uuid"], p["block_size"], "", blocks=p["blocks"], xid=p["xid"])


# ---------------------------------------------------------------------- optical, BSD, IBM, ReiserFS, ZFS
def _iso_date(raw: bytes) -> str:
    """blkid's UUID for ISO 9660: the volume creation time."""
    t = raw[:16]
    if not t.isdigit() or t == b"0" * 16:
        return ""
    s = t.decode()
    return f"{s[0:4]}-{s[4:6]}-{s[6:8]}-{s[8:10]}-{s[10:12]}-{s[12:14]}-{s[14:16]}"


def _probe_iso(r: _Reader) -> dict | None:
    pvd = r.read(32768, 2048)
    if pvd[0] != 1 or pvd[1:6] != b"CD001" or pvd[6] != 1:
        return None
    space, lbs = u32(pvd, 80), u16(pvd, 128)
    if lbs not in (512, 1024, 2048, 4096) or space == 0:
        return None
    label = _cstr(pvd[40:72])
    joliet = boot = False
    for i in range(1, 16):
        d = r.read(32768 + i * 2048, 2048)
        if d[1:6] != b"CD001" or d[0] == 255:
            break
        if d[0] == 0 and d[7:30].startswith(b"EL TORITO"):
            boot = True
        if d[0] == 2 and d[88:91] in (b"%/@", b"%/C", b"%/E"):
            jl = _utf16(d[40:72], be=True)
            if jl:
                label = jl
            joliet = True
    return _info("iso9660", space * lbs, label, _iso_date(pvd[813:830]), lbs, "Joliet" if joliet else "",
                 bootable=boot, volume_set=_cstr(pvd[190:318]))


def _udf_dstring(raw: bytes) -> str:
    if not raw or raw[0] not in (8, 16):
        return ""
    n = raw[-1]
    body = raw[1:max(1, min(n, len(raw) - 1))]
    return (body.decode("latin-1", "replace") if raw[0] == 8 else _utf16(body, be=True)).strip("\x00 ")


def _probe_udf(r: _Reader) -> dict | None:
    nsr = None
    for i in range(0, 64):
        d = r.read(32768 + i * 2048, 8)
        ident = d[1:6]
        if ident in (b"NSR02", b"NSR03"):
            nsr = ident.decode()
            break
        if ident not in (b"BEA01", b"CD001", b"CDW02", b"BOOT2", b"TEA01") and i > 0:
            break
        if i == 0 and ident not in (b"BEA01", b"CD001", b"CDW02", b"BOOT2"):
            return None
    if nsr is None:
        return None
    info = _info("udf", None, "", "", 2048, nsr)
    for bs in (2048, 512, 4096, 1024):
        avdp = r.read(256 * bs, 512)
        if u16(avdp, 0) != 2 or u32(avdp, 12) != 256:
            continue
        info["block_size"] = bs
        vds_len, vds_loc = u32(avdp, 16), u32(avdp, 20)
        part_end = 0
        for k in range(min(vds_len // bs, 64)):
            d = r.read((vds_loc + k) * bs, 512)
            tag = u16(d, 0)
            if tag == 6:
                info["label"] = _udf_dstring(d[84:84 + 128])
            elif tag == 1 and not info["label"]:
                info["label"] = _udf_dstring(d[24:24 + 32])
            elif tag == 5:
                part_end = max(part_end, u32(d, 188) + u32(d, 192))
            elif tag == 8:
                break
        if part_end:
            info["size"] = part_end * bs
        break
    return info


def _probe_jfs(r: _Reader) -> dict | None:
    b = r.read(32768, 512)
    if b[0:4] != b"JFS1":
        return None
    size, bsize, pbsize = u64(b, 8), u32(b, 16), u32(b, 24)
    if bsize not in (512, 1024, 2048, 4096) or pbsize not in (512, 1024, 2048, 4096) or size == 0:
        return None
    return _info("jfs", size * pbsize, _cstr(b[152:168], "utf-8"), _uuid(b[136:152]), bsize, str(u32(b, 4)))


def _probe_reiserfs(r: _Reader) -> dict | None:
    for off in (65536, 8192):
        b = r.read(off, 512)
        magic = b[52:62]
        if not magic.startswith(b"ReIsEr"):
            continue
        if magic.startswith(b"ReIsErFs"):
            version = "3.5"
        elif magic.startswith(b"ReIsEr2Fs"):
            version = "3.6"
        elif magic.startswith(b"ReIsEr3Fs"):
            version = "JR"
        else:
            continue
        blocks, bsize = u32(b, 0), u16(b, 44)
        if bsize not in (512, 1024, 2048, 4096, 8192) or blocks == 0:
            continue
        label = uuid = ""
        if version != "3.5":
            label, uuid = _cstr(b[100:116], "utf-8"), _uuid(b[84:100])
        return _info("reiserfs", blocks * bsize, label, uuid, bsize, version, superblock_offset=off)
    return None


_UFS_MAGICS = {0x00011954: "1", 0x19540119: "2"}


def _probe_ufs(r: _Reader) -> dict | None:
    for off in (65536, 8192, 0, 262144):
        b = r.read(off, 1536)
        for endian in ("<", ">"):
            magic = struct.unpack_from(endian + "I", b, 1372)[0]
            version = _UFS_MAGICS.get(magic)
            if version is None:
                continue
            bsize, fsize = struct.unpack_from(endian + "ii", b, 48)
            if not _pow2(bsize) or not _pow2(fsize) or not 512 <= fsize <= bsize <= 65536:
                continue
            if version == "2":
                frags = struct.unpack_from(endian + "q", b, 1080)[0]
                label = _cstr(b[680:712], "utf-8")
            else:
                frags = struct.unpack_from(endian + "i", b, 36)[0]
                label = ""
            if frags <= 0:
                continue
            fid = struct.unpack_from(endian + "II", b, 144)
            return _info("ufs", frags * fsize, label, f"{fid[0]:08x}{fid[1]:08x}" if any(fid) else "", fsize, version,
                         superblock_offset=off, block_size_big=bsize, big_endian=endian == ">")
    return None


def _xdr_nvlist(data: bytes, pos: int, depth: int = 0) -> tuple[dict, int]:
    """A ZFS label nvlist (XDR encoded): {name: value} for uint64, string and nested nvlist pairs."""
    out: dict = {}
    pos += 8                                  # version, flags
    for _ in range(256):
        if pos + 8 > len(data):
            break
        esize = be32(data, pos)
        if esize == 0:
            pos += 8
            break
        if esize < 16 or pos + esize > len(data):
            break
        nlen = be32(data, pos + 8)
        if nlen > 256:
            break
        name = data[pos + 12:pos + 12 + nlen].decode("ascii", "replace")
        p = pos + 12 + (nlen + 3) // 4 * 4
        dtype, _nelem = be32(data, p), be32(data, p + 4)
        p += 8
        if dtype == 8:                        # uint64
            out[name] = be64(data, p)
        elif dtype == 9:                      # string
            slen = be32(data, p)
            out[name] = data[p + 4:p + 4 + min(slen, 1024)].decode("utf-8", "replace")
        elif dtype == 19 and depth < 3:       # nvlist
            out[name], _ = _xdr_nvlist(data[:pos + esize], p, depth + 1)
        pos += esize
    return out, pos


def _probe_zfs(r: _Reader) -> dict | None:
    for label_off in (0, 262144):
        data = r.read(label_off + 16384, 112 * 1024)
        if data[0] != 1 or data[1] not in (0, 1) or be32(data, 4) != 0:
            continue
        try:
            nv, _ = _xdr_nvlist(data, 4)
        except (struct.error, IndexError):
            continue
        if "pool_guid" not in nv and "guid" not in nv:
            continue
        tree = nv.get("vdev_tree") if isinstance(nv.get("vdev_tree"), dict) else {}
        asize = tree.get("asize")
        ashift = tree.get("ashift")
        return _info("zfs_member", None, str(nv.get("name") or ""), str(nv.get("pool_guid") or ""),
                     1 << ashift if isinstance(ashift, int) and 9 <= ashift <= 16 else None,
                     str(nv.get("version") or ""), uuid_sub=str(nv.get("guid") or ""), txg=nv.get("txg"),
                     asize=asize, state=nv.get("state"), label_offset=label_off)
    return None


# ---------------------------------------------------------------------- containers: LUKS, LVM, md RAID
def _probe_luks(r: _Reader) -> dict | None:
    b = r.read(0, 4096)
    if b[0:6] == b"LUKS\xba\xbe":
        return _luks(r, b, 0)
    # the LUKS2 secondary header survives when the first 4 KiB were wiped
    for off in (16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304):
        if off >= r.size > 0:
            break
        h = r.read(off, 4096)
        if h[0:6] == b"SKUL\xba\xbe" and be16(h, 6) == 2 and be64(h, 256) == off:
            info = _luks(r, h, off)
            if info:
                info["primary_header_damaged"] = True
            return info
    return None


def _luks(r: _Reader, b: bytes, at: int) -> dict | None:
    ver = be16(b, 6)
    if ver == 1:
        payload = be32(b, 104) * 512
        return _info("crypto_luks", None, "", _cstr(b[168:208]), 512, "1", cipher=_cstr(b[8:40]),
                     cipher_mode=_cstr(b[40:72]), hash=_cstr(b[72:104]), payload_offset=payload,
                     key_bytes=be32(b, 108))
    if ver != 2:
        return None
    hdr_size = be64(b, 8)
    info = _info("crypto_luks", None, _cstr(b[24:72], "utf-8"), _cstr(b[168:208]), 512, "2",
                 subsystem=_cstr(b[208:256], "utf-8"), header_size=hdr_size)
    if 16384 <= hdr_size <= 4 * 1024 * 1024:
        try:
            text = r.read(at + 4096, hdr_size - 4096).split(b"\x00", 1)[0]
            meta = json.loads(text.decode("utf-8"))
            segs = meta.get("segments") or {}
            seg = segs.get("0") or (next(iter(segs.values())) if segs else {})
            if seg:
                off = int(seg.get("offset") or 0)
                info["payload_offset"] = off
                size = seg.get("size")
                if size not in (None, "dynamic"):
                    info["size"] = off + int(size)
                enc = seg.get("encryption")
                if enc:
                    info["cipher"] = enc
                info["block_size"] = int(seg.get("sector_size") or 512)
        except (ValueError, TypeError, AttributeError, StopIteration):
            pass
    return info


def _lvm_uuid(raw: bytes) -> str:
    s = raw.decode("ascii", "replace")
    if len(s) != 32:
        return s
    parts, pos = [], 0
    for n in (6, 4, 4, 4, 4, 4, 6):
        parts.append(s[pos:pos + n])
        pos += n
    return "-".join(parts)


def _probe_lvm(r: _Reader) -> dict | None:
    for sector in range(4):
        s = r.read(sector * 512, 512)
        if s[0:8] != b"LABELONE" or s[24:32] != b"LVM2 001":
            continue
        if u64(s, 8) != sector:
            continue
        crc_ok = crc32_raw(0xF597A6CF, s[20:512]) == u32(s, 16)
        off = u32(s, 20)
        if not 32 <= off <= 512 - 40:
            continue
        pv = r.read(sector * 512 + off, 1024)
        uuid = _lvm_uuid(pv[0:32])
        dev_size = u64(pv, 32)
        areas: list[list[tuple[int, int]]] = [[], []]
        pos, which = 40, 0
        for _ in range(32):
            if pos + 16 > len(pv):
                break
            o, n = u64(pv, pos), u64(pv, pos + 8)
            pos += 16
            if o == 0 and n == 0:
                which += 1
                if which > 1:
                    break
                continue
            areas[which].append((o, n))
        info = _info("lvm2_member", dev_size or None, "", uuid, 512, "LVM2 001", label_sector=sector,
                     checksum_ok=crc_ok, data_areas=areas[0], metadata_areas=areas[1])
        vg = _safe(lambda: _lvm_vg_name(r, areas[1]))
        if vg:
            info["vg_name"] = vg
        return info
    return None


def _lvm_vg_name(r: _Reader, mdas: list[tuple[int, int]]) -> str:
    for off, size in mdas[:2]:
        h = r.read(off, 512)
        if h[4:20] != b" LVM2 x[5A%r0N*>":
            continue
        loc_off, loc_size = u64(h, 40), u64(h, 48)
        if not 0 < loc_off < size or not 0 < loc_size <= 1024 * 1024:
            continue
        text = r.read(off + loc_off, min(loc_size, 256))
        name = text.split(b"{", 1)[0].strip().decode("utf-8", "replace")
        if name and " " not in name:
            return name
    return ""


_MD_LEVELS = {-4: "multipath", -1: "linear", 0: "0", 1: "1", 4: "4", 5: "5", 6: "6", 10: "10"}


def parse_md_super1(sb: bytes, expected_sector: int | None = None) -> dict | None:
    """An md metadata 1.x superblock (at least 1024 bytes) or None."""
    if len(sb) < 1024 or u32(sb, 0) != 0xA92B4EFC or u32(sb, 4) != 1:
        return None
    super_offset = u64(sb, 144)
    if expected_sector is not None and super_offset != expected_sector:
        return None
    max_dev = u32(sb, 220)
    if max_dev > 1920:
        return None
    level = struct.unpack_from("<i", sb, 72)[0]
    raid_disks = u32(sb, 92)
    if raid_disks == 0 or raid_disks > 4096 or level not in _MD_LEVELS:
        return None
    data_offset, data_size = u64(sb, 128), u64(sb, 136)
    dev_number = u32(sb, 160)
    roles_end = 256 + 2 * max_dev
    role_raw = u16(sb, 256 + 2 * dev_number) if dev_number < max_dev and 256 + 2 * dev_number + 2 <= len(sb) else 0xFFFF
    csum_ok = None
    if roles_end <= len(sb):
        data = bytearray(sb[:roles_end])
        data[216:220] = b"\x00\x00\x00\x00"
        if len(data) % 4:
            data += bytes(4 - len(data) % 4)
        total = sum(struct.unpack_from(f"<{len(data) // 4}I", data))
        csum_ok = ((total & 0xFFFFFFFF) + (total >> 32)) & 0xFFFFFFFF == u32(sb, 216)
    per_dev = u64(sb, 80) * 512
    lvl = _MD_LEVELS[level]
    data_disks = {"0": raid_disks, "1": 1, "4": raid_disks - 1, "5": raid_disks - 1, "6": raid_disks - 2,
                  "linear": raid_disks, "multipath": 1}.get(lvl)
    layout = u32(sb, 76)
    if lvl == "10":
        copies = (layout & 0xFF) * ((layout >> 8) & 0xFF) or 2
        data_disks = max(1, raid_disks // copies)
    return {"level": lvl, "raid_disks": raid_disks, "layout": layout, "chunk": u32(sb, 88) * 512,
            "data_offset": data_offset * 512, "data_size": data_size * 512, "super_offset": super_offset * 512,
            "uuid": _uuid(sb[16:32]), "uuid_sub": _uuid(sb[168:184]), "name": _cstr(sb[32:64], "utf-8"),
            "events": u64(sb, 200), "dev_number": dev_number,
            "role": role_raw if role_raw < 0xFF00 else None,
            "role_name": {0xFFFF: "spare", 0xFFFE: "faulty", 0xFFFD: "journal"}.get(role_raw, "active"),
            "array_size": per_dev * data_disks if data_disks else None, "checksum_ok": csum_ok,
            "feature_map": u32(sb, 8)}


def parse_md_super090(sb: bytes) -> dict | None:
    """An md metadata 0.90 superblock (4096 bytes, host-endian: little first) or None."""
    if len(sb) < 4096:
        return None
    for e in ("<", ">"):
        w = struct.unpack_from(e + "1024I", sb)
        if w[0] != 0xA92B4EFC or w[1] != 0 or w[2] != 90:
            continue
        level = struct.unpack_from(e + "i", sb, 28)[0]
        if level not in _MD_LEVELS or w[10] == 0 or w[10] > 27:
            continue
        raw_uuid = struct.pack(">IIII", w[5], w[13], w[14], w[15])      # as mdadm and blkid print it
        per_dev = w[8] * 1024
        n = w[10]
        lvl = _MD_LEVELS[level]
        data_disks = {"0": n, "1": 1, "4": n - 1, "5": n - 1, "6": n - 2, "linear": n, "multipath": 1}.get(lvl, n)
        role = w[992 + 3]
        return {"level": lvl, "raid_disks": n, "layout": w[64], "chunk": w[65], "data_offset": 0,
                "data_size": per_dev, "uuid": _uuid(raw_uuid), "uuid_sub": "", "name": "",
                "events": (w[40] << 32) | w[39] if e == "<" else (w[39] << 32) | w[40],
                "role": role if role < n else None, "role_name": "active" if role < n else "spare",
                "array_size": per_dev * data_disks, "md_minor": w[11], "checksum_ok": None, "big_endian": e == ">"}
    return None


def _probe_md_start(r: _Reader) -> dict | None:
    for at, sector, version in ((0, 0, "1.1"), (4096, 8, "1.2")):
        b = r.read(at, 4096)
        if u32(b, 0) != 0xA92B4EFC:
            continue
        p = parse_md_super1(b, sector)
        if p is None or p["checksum_ok"] is False:
            continue
        return _md_info(p, version, (p["data_offset"] + p["data_size"]) or None)
    return None


def _probe_md_end(r: _Reader) -> dict | None:
    size = r.size
    if size < 128 * 1024:
        return None
    sectors = size // 512
    sb1 = ((sectors - 16) & ~7) * 512                      # metadata 1.0: 8-12 KiB before the end
    b = r.read(sb1, 4096)
    if u32(b, 0) == 0xA92B4EFC:
        p = parse_md_super1(b, sb1 // 512)
        if p and p["checksum_ok"] is not False:
            return _md_info(p, "1.0", size)
    sb0 = ((sectors & ~127) - 128) * 512                   # metadata 0.90: the last 64 KiB-aligned 64 KiB
    b = r.read(sb0, 4096)
    if b[0:4] in (b"\xfc\x4e\x2b\xa9", b"\xa9\x2b\x4e\xfc"):
        p = parse_md_super090(b)
        if p:
            return _md_info(p, "0.90", size, super_offset=sb0)
    return None


def _md_info(p: dict, version: str, size: int | None, **extra) -> dict:
    # the label is the array name ("host:name" as mdadm writes it), the UUID the array's (blkid does the same)
    info = _info("linux_raid_member", size, p.get("name") or "", p["uuid"], 512, version, p, metadata=version)
    info.update(extra)
    return info


# ---------------------------------------------------------------------- the dispatcher
def _safe(fn: Callable[[], str]) -> str:
    try:
        return fn() or ""
    except (struct.error, IndexError, ValueError, KeyError, UnicodeDecodeError, OverflowError):
        return ""


# Order matters where old signatures can survive under a newer format: RAID and encryption first (blkid's
# order), FAT last of the boot-sector types (it has no magic), ZFS and Minix at the very end (weak).
PROBES: tuple[tuple[str, Callable[[_Reader], dict | None]], ...] = (
    ("linux_raid_member", _probe_md_start),
    ("crypto_luks", _probe_luks),
    ("bitlocker", _probe_bitlocker),
    ("lvm2_member", _probe_lvm),
    ("ntfs", _probe_ntfs),
    ("exfat", _probe_exfat),
    ("refs", _probe_refs),
    ("xfs", _probe_xfs),
    ("btrfs", _probe_btrfs),
    ("ext", _probe_ext),
    ("hfs", _probe_hfs),
    ("apfs", _probe_apfs),
    ("f2fs", _probe_f2fs),
    ("squashfs", _probe_squashfs),
    ("erofs", _probe_erofs),
    ("jfs", _probe_jfs),
    ("reiserfs", _probe_reiserfs),
    ("udf", _probe_udf),
    ("iso9660", _probe_iso),
    ("ufs", _probe_ufs),
    ("nilfs2", _probe_nilfs),
    ("swap", _probe_swap),
    ("fat", _probe_fat),
    ("zfs_member", _probe_zfs),
    ("minix", _probe_minix),
)


def _run(r: _Reader, with_end: bool) -> dict | None:
    if with_end:
        try:
            info = _probe_md_end(r)
        except Exception as exc:  # noqa: BLE001 - garbage must never stop a scan
            log.debug("md end probe failed: %s", exc)
            info = None
        if info:
            inner = _run(r, False)
            if inner and inner.get("fstype") != "linux_raid_member":
                info["contains"] = {k: inner.get(k) for k in ("fstype", "label", "uuid", "size")}
            return info
    for name, fn in PROBES:
        try:
            info = fn(r)
        except Exception as exc:  # noqa: BLE001 - garbage must never stop a scan
            log.debug("probe %s failed: %s", name, exc)
            continue
        if info:
            return info
    return None


def identify(src) -> dict | None:
    """What is at offset 0 of SRC (a Source covering the volume; its size is used for the RAID superblocks
    kept at the end and to flag filesystems bigger than the volume). None when nothing is recognized."""
    if src is None or src.size <= 0:
        return None
    info = _run(_Reader(src, 0, None, src.size), True)
    if info and info.get("size") and info["size"] > src.size:
        info["truncated"] = True
    return info


def identify_at(src, offset: int, head: bytes | None = None) -> dict | None:
    """What starts at OFFSET of SRC (a whole disk, say), without knowing where it ends: the RAID metadata
    kept at the end of a member (0.90, 1.0) can't be seen this way. HEAD may hold bytes already read from
    OFFSET (any length; the rest of the first 68 KiB is read as needed)."""
    if offset < 0 or offset >= src.size:
        return None
    return _run(_Reader(src, offset, head, src.size - offset), False)


_PROBE_BY_NAME = dict(PROBES)


def probe_with(name: str, src, offset: int = 0, size: int | None = None) -> dict | None:
    """Run the one probe NAME (a key of PROBES: "ntfs", "fat", "ext", "hfs", "swap", ...) on what starts at
    OFFSET of SRC. Used by the deep scan on the bytes around a signature it found."""
    fn = _PROBE_BY_NAME.get(name)
    if fn is None or offset < 0:
        return None
    try:
        return fn(_Reader(src, offset, None, size if size is not None else max(0, src.size - offset)))
    except Exception as exc:  # noqa: BLE001 - garbage must never stop a scan
        log.debug("probe %s failed: %s", name, exc)
        return None


def evidence_of(fstype: str) -> str:
    """The plain name of the structure that identified FSTYPE ("boot sector", "superblock", ...)."""
    for s in SIGNATURES:
        if s.fstype == fstype:
            return s.what
    if fstype in ("ext2", "ext3"):
        return "superblock"
    return "header"
