"""Disks and partitions: discovery with lsblk and sysfs (works without root), raw disk image files, and the
volumes the kernel assembled (RAID arrays, LVM logical volumes, opened LUKS/BitLocker containers).

A disk is a plain dict (it travels to the GUI over IPC)::

    {"path": "/dev/sda", "name": "sda", "size": 1000204886016, "logical_sector": 512, "kind": "ssd",
     "model": ..., "serial": ..., "transport": "sata", "pttype": "gpt", "ptuuid": ..., "is_image": False,
     "system": True, "in_use": [...], "partitions": [part, ...], ...}

and a partition::

    {"number": 2, "path": "/dev/sda2", "start": 1048576, "size": 536870912, "end": ..., "parttype": ...,
     "role": "esp", "fstype": "vfat", "label": ..., "uuid": ..., "partuuid": ..., "mountpoints": [...],
     "in_use": "", "logical": False, "extended": False, ...}

Offsets and sizes are always in bytes. Everything here only reads.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from .errors import RallError
from .util import clean, fmt_capacity, read_int, read_text, run, which

SYS_BLOCK = Path("/sys/class/block")

_LSBLK_COLUMNS = ["NAME", "KNAME", "PATH", "TYPE", "SIZE", "MAJ:MIN", "MOUNTPOINTS", "MOUNTPOINT", "LOG-SEC",
                  "PHY-SEC", "PTTYPE", "PTUUID", "PARTTYPE", "PARTTYPENAME", "PARTUUID", "PARTLABEL",
                  "PARTFLAGS", "FSTYPE", "FSVER", "LABEL", "UUID", "MODEL", "SERIAL", "VENDOR", "TRAN", "ROTA",
                  "RM", "RO", "HOTPLUG", "FSUSED", "FSSIZE", "WWN", "REV"]
_supported_columns: list[str] | None = None

# GPT partition type GUIDs and MBR type bytes → role
GPT_ROLES = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "esp",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "msr",
    "21686148-6449-6e6f-744e-656564454649": "bios_boot",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "recovery",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "swap",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "lvm",
    "a19d880f-05fc-4d3b-a006-743f0f84911e": "raid",
    "ca7d7ccb-63ed-4c53-861c-1742536059cc": "crypt",
    "bc13c2ff-59e6-4262-a352-b275fd6f7172": "boot",
}
DOS_ROLES = {0xef: "esp", 0x27: "recovery", 0x82: "swap", 0x8e: "lvm", 0xfd: "raid", 0x05: "extended",
             0x0f: "extended", 0x85: "extended"}
ROLE_NAMES = {"esp": "EFI system", "msr": "Microsoft reserved", "bios_boot": "BIOS boot", "recovery": "Recovery",
              "swap": "Swap", "lvm": "LVM", "raid": "RAID", "crypt": "Encrypted", "boot": "Boot",
              "extended": "Extended", "data": "Data", "free": "Unallocated"}
SYSTEM_MOUNTS = ("/", "/boot", "/boot/efi", "/efi", "/usr", "/var", "/home", "/nix", "/opt")


# ---------------------------------------------------------------------- lsblk
def _lsblk(args: list[str]) -> dict:
    """lsblk -J -b with as many of our columns as this util-linux knows (older ones lack some)."""
    global _supported_columns
    cols = list(_supported_columns or _LSBLK_COLUMNS)
    for _ in range(len(_LSBLK_COLUMNS)):
        rr = run(["lsblk", "-J", "-b", "-o", ",".join(cols), *args], timeout=30)
        if rr.ok:
            _supported_columns = cols
            try:
                return json.loads(rr.stdout or "{}")
            except ValueError as exc:
                raise RallError(f"lsblk printed something unexpected: {exc}") from exc
        m = re.search(r"unknown column: (\S+)", rr.stderr)
        if not m:
            if rr.missing:
                raise RallError("lsblk is not installed (package: util-linux)")
            if args and ("not a block device" in rr.stderr or "No such file" in rr.stderr):
                return {"blockdevices": []}
            raise RallError(f"lsblk failed: {rr.error_text()}")
        bad = m.group(1).upper()
        cols = [c for c in cols if c != bad]
    raise RallError("lsblk failed")


def _mountpoints(dev: dict) -> list[str]:
    mps = dev.get("mountpoints")
    if mps is None:
        mps = [dev.get("mountpoint")]
    return [m for m in mps if m]


def _active_swaps() -> set[str]:
    out = set()
    text = read_text("/proc/swaps", "") or ""
    for line in text.splitlines()[1:]:
        if line.split():
            dev = line.split()[0]
            out.add(os.path.realpath(dev))
    return out


def _by_id() -> dict[str, str]:
    """/dev/sdX → the most stable /dev/disk/by-id link (ata-…, nvme-…, usb-…; wwn-… last)."""
    links: dict[str, list[str]] = {}
    base = Path("/dev/disk/by-id")
    try:
        entries = list(base.iterdir())
    except OSError:
        return {}
    for e in entries:
        try:
            links.setdefault(os.path.realpath(e), []).append(str(e))
        except OSError:
            continue

    def rank(p: str) -> tuple:
        n = os.path.basename(p)
        return (n.startswith("wwn-") or n.startswith("nvme-eui") or n.startswith("dm-"), "_1" in n, len(n), n)
    return {dev: sorted(names, key=rank)[0] for dev, names in links.items()}


def _kind(dev: dict, name: str) -> str:
    tran = (dev.get("tran") or "").lower()
    if name.startswith("loop"):
        return "loop"
    if name.startswith("nvme") or tran == "nvme":
        return "nvme"
    if name.startswith("mmcblk"):
        removable = read_int(SYS_BLOCK / name / "removable", 0)
        typ = read_text(SYS_BLOCK / name / "device" / "type", "") or ""
        return "emmc" if typ == "MMC" and not removable else "sd"
    if name.startswith(("vd", "xvd")):
        return "virtual"
    if name.startswith("sr"):
        return "optical"
    if tran == "usb":
        return "usb-flash" if _truthy(dev.get("rm")) and not _truthy(dev.get("rota")) else "usb-disk"
    if _truthy(dev.get("rota")):
        return "hdd"
    return "ssd"


def _truthy(v) -> bool:
    return v in (True, 1, "1", "true")


def role_of(parttype: str | None, fstype: str | None = None) -> str:
    pt = (parttype or "").lower()
    if pt in GPT_ROLES:
        return GPT_ROLES[pt]
    if pt.startswith("0x"):
        try:
            code = int(pt, 16)
        except ValueError:
            code = -1
        if code in DOS_ROLES:
            return DOS_ROLES[code]
    fs = (fstype or "").lower()
    if fs == "swap":
        return "swap"
    if fs == "lvm2_member":
        return "lvm"
    if fs == "crypto_luks":
        return "crypt"
    if fs == "linux_raid_member":
        return "raid"
    return "data"


def _descendants(dev: dict) -> list[dict]:
    out = []
    for c in dev.get("children") or []:
        out.append(c)
        out.extend(_descendants(c))
    return out


def _part_from_lsblk(dev: dict, disk: dict, swaps: set[str]) -> dict:
    kname = dev.get("kname") or dev.get("name")
    sysdir = SYS_BLOCK / kname
    start = (read_int(sysdir / "start", 0) or 0) * 512
    size = int(dev.get("size") or (read_int(sysdir / "size", 0) or 0) * 512)
    number = read_int(sysdir / "partition", 0) or _number_from_name(kname)
    path = dev.get("path") or f"/dev/{kname}"
    mps = _mountpoints(dev)
    holders = []
    for c in _descendants(dev):
        cm = _mountpoints(c)
        holders.append({"name": c.get("name"), "type": c.get("type"), "fstype": c.get("fstype"), "mountpoints": cm})
        mps += [f"{m} (via {c.get('name')})" for m in cm]
    in_use = ""
    if os.path.realpath(path) in swaps:
        in_use = "active swap"
    elif any(os.path.realpath(f"/dev/{h['name']}") in swaps for h in holders):
        in_use = "active swap (inside)"
    elif mps:
        in_use = "mounted"
    elif any(h.get("type") in ("crypt", "lvm", "raid0", "raid1", "raid4", "raid5", "raid6", "raid10", "md",
                               "dm", "part") for h in holders):
        in_use = "in use by " + ", ".join(h.get("name") or "" for h in holders)
    parttype = (dev.get("parttype") or "").lower()
    pttype = disk.get("pttype")
    if pttype == "dos":
        parttype = norm_dos_type(parttype)
    extended = parttype in ("0x5", "0xf", "0x85")
    p = {
        "number": number, "name": kname, "path": path, "start": start, "size": size, "end": start + size,
        "parttype": parttype, "parttype_name": dev.get("parttypename") or "",
        "partuuid": (dev.get("partuuid") or "").lower(), "partlabel": dev.get("partlabel") or "",
        "partflags": dev.get("partflags") or "",
        "fstype": (dev.get("fstype") or "").lower(), "fsver": dev.get("fsver") or "", "label": dev.get("label") or "",
        "uuid": dev.get("uuid") or "", "mountpoints": mps, "in_use": in_use, "holders": holders,
        "fssize": _int_or_none(dev.get("fssize")), "fsused": _int_or_none(dev.get("fsused")),
        "extended": extended, "logical": pttype == "dos" and number > 4,
    }
    p["role"] = "extended" if extended else role_of(parttype, p["fstype"])
    if extended:
        p["fstype"] = ""
    return p


def norm_dos_type(t: str | None) -> str:
    """'83', '0x83', '0X0c' → '0x83', '0xc' (lsblk and sfdisk spell MBR types differently)."""
    t = (t or "").strip().lower()
    if not t:
        return ""
    try:
        return f"0x{int(t, 16):x}"
    except ValueError:
        return t


def _int_or_none(v) -> int | None:
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _number_from_name(name: str) -> int:
    m = re.search(r"(\d+)$", name)
    return int(m.group(1)) if m else 0


def _disk_from_lsblk(dev: dict, swaps: set[str], by_id: dict[str, str]) -> dict:
    name = dev.get("kname") or dev.get("name")
    path = dev.get("path") or f"/dev/{name}"
    sysdir = SYS_BLOCK / name
    size = int(dev.get("size") or 0)
    disk = {
        "path": path, "name": name, "size": size, "is_image": False,
        "logical_sector": int(dev.get("log-sec") or read_int(sysdir / "queue" / "logical_block_size", 512) or 512),
        "physical_sector": int(dev.get("phy-sec") or read_int(sysdir / "queue" / "physical_block_size", 512) or 512),
        "model": clean(dev.get("model")) or clean(read_text(sysdir / "device" / "model", "")),
        "serial": clean(dev.get("serial")), "vendor": clean(dev.get("vendor")),
        "transport": (dev.get("tran") or "").lower(), "rotational": _truthy(dev.get("rota")),
        "removable": _truthy(dev.get("rm")) or _truthy(dev.get("hotplug")), "readonly": _truthy(dev.get("ro")),
        "pttype": (dev.get("pttype") or "") or None, "ptuuid": (dev.get("ptuuid") or "").lower(),
        "wwn": dev.get("wwn") or "", "firmware": clean(dev.get("rev")),
        "by_id": by_id.get(os.path.realpath(path), ""),
    }
    disk["kind"] = _kind(dev, name)
    if disk["kind"] == "loop":
        backing = read_text(sysdir / "loop" / "backing_file", "") or ""
        disk["model"] = disk["model"] or (f"Loop device ({os.path.basename(backing)})" if backing else "Loop device")
        disk["backing_file"] = backing
    parts = []
    whole_mps = _mountpoints(dev)
    for child in dev.get("children") or []:
        if child.get("type") == "part":
            parts.append(_part_from_lsblk(child, disk, swaps))
    if not parts:
        # a filesystem straight on the disk ("superfloppy"), or LVM/LUKS on the whole disk
        disk["fstype"] = (dev.get("fstype") or "").lower()
        disk["label"] = dev.get("label") or ""
        disk["uuid"] = dev.get("uuid") or ""
        for c in _descendants(dev):
            whole_mps += [f"{m} (via {c.get('name')})" for m in _mountpoints(c)]
    parts.sort(key=lambda p: p["start"])
    disk["partitions"] = parts
    finish_disk(disk, whole_mps, swaps)
    return disk


def finish_disk(disk: dict, whole_mps: list[str] | None = None, swaps: set[str] | None = None) -> None:
    """Derived fields: display name, capacity text, in-use reasons, system disk."""
    swaps = swaps if swaps is not None else _active_swaps()
    whole_mps = whole_mps or []
    reasons = []
    mounted = list(whole_mps)
    for p in disk.get("partitions", []):
        mounted += p.get("mountpoints") or []
        if p.get("in_use") and p.get("in_use") != "mounted":
            reasons.append(f"{p['name']}: {p['in_use']}")
    if os.path.realpath(disk["path"]) in swaps:
        reasons.append("active swap")
    disk["mountpoints"] = mounted
    plain = [m.split(" (via ")[0] for m in mounted]
    disk["system"] = any(m in SYSTEM_MOUNTS for m in plain) or any("swap" in r for r in reasons)
    if mounted:
        reasons.insert(0, "mounted: " + ", ".join(plain[:4]) + ("…" if len(plain) > 4 else ""))
    disk["in_use"] = reasons
    disk["capacity_text"] = fmt_capacity(disk["size"])
    name = disk.get("model") or ""
    vendor = disk.get("vendor") or ""
    if name and vendor and vendor.lower() not in name.lower() and vendor.upper() != "ATA" \
            and not vendor.lower().startswith("0x"):
        name = f"{vendor} {name}"
    if not name:
        name = {"virtual": "Virtual disk", "nvme": "NVMe disk", "sd": "Memory card", "emmc": "eMMC",
                "usb-flash": "USB flash drive"}.get(disk.get("kind", ""), "Disk") + f" {disk.get('name', '')}"
    disk["display_name"] = name
    disk["key"] = disk["path"]
    used = sum(p["size"] for p in disk.get("partitions", []) if not p.get("extended"))
    disk["allocated"] = used


def list_disks(include_loops: bool | None = None) -> list[dict]:
    """Every whole disk on the machine (not partitions, RAID or LVM volumes, optical drives or zram)."""
    if include_loops is None:
        include_loops = os.environ.get("RALL_SHOW_LOOPS") == "1"
    data = _lsblk([])
    swaps = _active_swaps()
    by_id = _by_id()
    out = []
    for dev in data.get("blockdevices") or []:
        typ = dev.get("type")
        name = dev.get("kname") or dev.get("name") or ""
        if name.startswith(("zram", "ram", "fd")):
            continue
        if name.startswith("sr"):
            if not int(dev.get("size") or 0):
                continue        # no disc in the drive
            out.append(_disk_from_lsblk(dev, swaps, by_id))
            continue
        if typ == "loop":
            if not include_loops or not int(dev.get("size") or 0):
                continue
        elif typ != "disk":
            continue
        if not int(dev.get("size") or 0):
            continue            # empty card reader
        out.append(_disk_from_lsblk(dev, swaps, by_id))
    out.sort(key=lambda d: (d["kind"] == "loop", d["name"]))
    return out


def disk_info(path: str) -> dict:
    """One disk, by device path (or /dev/disk/by-id link), or a raw disk image file."""
    real = os.path.realpath(path)
    try:
        st = os.stat(real)
    except OSError as exc:
        raise RallError(f"{path}: {exc.strerror}") from exc
    if stat.S_ISREG(st.st_mode):
        return image_disk(real)
    if not stat.S_ISBLK(st.st_mode):
        raise RallError(f"{path} is neither a disk nor a disk image file")
    data = _lsblk([real])
    devs = data.get("blockdevices") or []
    if not devs:
        raise RallError(f"{path}: no such disk")
    if devs[0].get("type") not in ("disk", "loop", "rom"):
        return volume_info(devs[0])
    return _disk_from_lsblk(devs[0], _active_swaps(), _by_id())


# ---------------------------------------------------------------------- image files
def sfdisk_json(path: str) -> dict | None:
    """The partition table as sfdisk sees it (needs read access to the device), or None."""
    rr = run(["sfdisk", "--json", path], timeout=30)
    if not rr.ok or not rr.stdout.strip():
        return None
    try:
        return json.loads(rr.stdout).get("partitiontable")
    except ValueError:
        return None


def blkid_probe(path: str, offset: int = 0, size: int | None = None) -> dict:
    """Low-level probe of a filesystem at OFFSET of a file or device (TYPE, UUID, LABEL, VERSION, FSSIZE)."""
    cmd = ["blkid", "-p", "-o", "export"]
    if offset:
        cmd += ["-O", str(offset)]
    if size:
        cmd += ["-S", str(size)]
    rr = run([*cmd, path], timeout=30)
    out = {}
    for line in rr.stdout.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            out[k] = v
    return out


def identify(src, offset: int = 0, size: int | None = None) -> dict:
    """What filesystem is at OFFSET of a Source: our own detector (no root, works on any source)."""
    try:
        from . import fsdetect
        region = src.region(offset, size) if (offset or size) else src
        return fsdetect.identify(region) or {}
    except Exception:  # noqa: BLE001 - a damaged boot sector is not an error here
        return {}


def source_partitions(src, disk: dict) -> list[dict]:
    """Partitions of any Source (image file, RAID, region) from its partition table, read in Python."""
    from . import partitions as ptable
    try:
        table = ptable.read_table(src)
    except Exception:  # noqa: BLE001
        return []
    disk["pttype"] = None if table.get("type") in (None, "none") else table["type"]
    disk["table_problems"] = table.get("problems") or []
    if table.get("sector_size"):
        disk["logical_sector"] = int(table["sector_size"])
    parts = []
    base = os.path.basename(disk["path"])
    for e in table.get("partitions") or []:
        number = int(e.get("number") or len(parts) + 1)
        start, size = int(e["start"]), int(e["size"])
        ptype = str(e.get("type") or "").lower()
        if table.get("type") == "dos":
            ptype = norm_dos_type(ptype)
        extended = table.get("type") == "dos" and ptype in ("0x5", "0xf", "0x85")
        info = {} if extended else identify(src, start, size)
        p = {
            "number": number, "name": f"{base}{'p' if base[-1:].isdigit() else ''}{number}",
            "path": "", "start": start, "size": size, "end": start + size, "parttype": ptype,
            "parttype_name": e.get("type_name") or "", "partuuid": str(e.get("guid") or "").lower(),
            "partlabel": e.get("name") or "", "partflags": e.get("attrs") or "", "bootable": bool(e.get("bootable")),
            "fstype": (info.get("fstype") or "").lower(), "fsver": str(info.get("version") or ""),
            "label": info.get("label") or "", "uuid": info.get("uuid") or "", "mountpoints": [], "in_use": "",
            "holders": [], "fssize": _int_or_none(info.get("size")), "fsused": _int_or_none(info.get("used")),
            "extended": extended, "logical": bool(e.get("logical")),
        }
        p["role"] = "extended" if extended else role_of(ptype, p["fstype"])
        parts.append(p)
    parts.sort(key=lambda p: p["start"])
    return parts


def image_disk(path: str, sector: int | None = None) -> dict:
    """A disk image (dd, ddrescue, a VM's raw disk, a split image's first piece, a VHD/VHDX/VDI/VMDK/QCOW2
    virtual disk, an E01 forensic image, a .rallraid virtual RAID) seen as a disk, with its partitions read
    straight from the file (no root, no loop devices). ``format`` says which: "raw", "VHDX", "E01", "RAID", …"""
    from .blockio import open_source
    real = os.path.realpath(path)
    src = open_source(real, sector)
    raid = real.endswith(".rallraid")
    try:
        disk = {
            "path": real, "name": os.path.basename(real), "size": src.size, "is_image": True,
            "logical_sector": src.sector_size, "physical_sector": src.sector_size,
            "model": os.path.basename(real), "serial": "", "vendor": "", "transport": "", "rotational": False,
            "removable": False, "readonly": True, "kind": "raid" if raid else "image",
            "format": getattr(src, "format", "") or ("RAID" if raid else "raw"),
            "pttype": None, "ptuuid": "", "wwn": "", "firmware": "", "by_id": "",
        }
        disk["partitions"] = source_partitions(src, disk)
        if not disk["partitions"]:
            info = identify(src)
            disk["fstype"] = (info.get("fstype") or "").lower()
            disk["label"] = info.get("label") or ""
            disk["uuid"] = info.get("uuid") or ""
    finally:
        src.close()
    finish_disk(disk, [], set())
    if disk["kind"] == "raid":
        disk["display_name"] = "RAID: " + os.path.basename(real)
    elif disk["format"] != "raw":
        disk["display_name"] = f"Image ({disk['format']}): {os.path.basename(real)}"
    else:
        disk["display_name"] = "Image: " + os.path.basename(real)
    return disk


# ---------------------------------------------------------------------- RAID arrays, LVM, opened containers
VOLUME_TYPES = ("raid0", "raid1", "raid4", "raid5", "raid6", "raid10", "md", "lvm", "crypt", "dm", "mpath")


def volume_info(dev: dict) -> dict:
    """A kernel volume (md array, LVM logical volume, opened LUKS/BitLocker) as a disk-like source."""
    name = dev.get("kname") or dev.get("name") or ""
    path = dev.get("path") or f"/dev/{name}"
    typ = dev.get("type") or "dm"
    model = {"crypt": "Unlocked volume", "lvm": "LVM volume"}.get(typ, "RAID array" if typ.startswith(("raid", "md"))
                                                                  else "Volume")
    dm_name = read_text(SYS_BLOCK / name / "dm" / "name", "") or ""
    disk = {
        "path": path, "name": name, "size": int(dev.get("size") or 0), "is_image": False, "is_volume": True,
        "logical_sector": int(dev.get("log-sec") or 512), "physical_sector": int(dev.get("phy-sec") or 512),
        "model": f"{model} {dm_name or name}", "serial": "", "vendor": "", "transport": "", "rotational": False,
        "removable": False, "readonly": _truthy(dev.get("ro")), "kind": "raid" if typ.startswith(("raid", "md"))
        else "volume", "pttype": (dev.get("pttype") or "") or None, "ptuuid": "", "wwn": "", "firmware": "",
        "by_id": "", "fstype": (dev.get("fstype") or "").lower(), "label": dev.get("label") or "",
        "uuid": dev.get("uuid") or "", "volume_type": typ,
    }
    disk["partitions"] = [_part_from_lsblk(c, disk, _active_swaps()) for c in dev.get("children") or []
                          if c.get("type") == "part"]
    finish_disk(disk, _mountpoints(dev))
    return disk


def list_volumes() -> list[dict]:
    """RAID arrays, LVM logical volumes and unlocked encrypted volumes the kernel set up (each one appears
    once, even when it sits on several disks)."""
    try:
        data = _lsblk([])
    except RallError:
        return []
    seen: dict[str, dict] = {}
    for dev in data.get("blockdevices") or []:
        for c in _descendants(dev):
            if (c.get("type") or "") in VOLUME_TYPES and int(c.get("size") or 0):
                key = c.get("kname") or c.get("name")
                if key not in seen:
                    seen[key] = volume_info(c)
    return sorted(seen.values(), key=lambda d: d["name"])


def refresh_table(disk: dict) -> dict:
    """Re-read the partition table with sfdisk (root) for what lsblk doesn't show (attrs, bootable flags,
    table length, first/last usable LBA) and merge it into the disk dict."""
    table = sfdisk_json(disk["path"])
    if not table:
        return disk
    disk["table"] = {k: table.get(k) for k in ("label", "id", "firstlba", "lastlba", "sectorsize", "table-length")
                     if table.get(k) is not None}
    ss = int(table.get("sectorsize") or disk.get("logical_sector") or 512)
    by_start = {int(e["start"]) * ss: e for e in table.get("partitions") or []}
    for p in disk.get("partitions", []):
        e = by_start.get(p["start"])
        if not e:
            continue
        p["partflags"] = e.get("attrs") or p.get("partflags") or ""
        p["bootable"] = bool(e.get("bootable"))
        if e.get("name") and not p.get("partlabel"):
            p["partlabel"] = e["name"]
        if e.get("uuid") and not p.get("partuuid"):
            p["partuuid"] = str(e["uuid"]).lower()
    return disk


def partition_path(disk_path: str, number: int) -> str:
    """/dev/sda + 2 → /dev/sda2; /dev/nvme0n1 + 2 → /dev/nvme0n1p2."""
    sep = "p" if disk_path[-1:].isdigit() else ""
    return f"{disk_path}{sep}{number}"


def kernel_partition(disk_path: str, start: int, size: int) -> str | None:
    """The kernel's node for the partition of DISK at START with SIZE (bytes), if the kernel has one."""
    name = os.path.basename(os.path.realpath(disk_path))
    try:
        entries = list(Path(f"/sys/block/{name}").iterdir())
    except OSError:
        return None
    for e in entries:
        if not e.name.startswith(name) or not (e / "partition").exists():
            continue
        s = read_int(e / "start")
        n = read_int(e / "size")
        if s is None or n is None:
            continue
        if s * 512 == start and n * 512 == size:
            node = f"/dev/{e.name}"
            if os.path.exists(node):
                return node
    return None


# ---------------------------------------------------------------------- health
def health(disk: dict) -> dict | None:
    """A quick health hint (smartctl -H -A): "ok", "warning" or "failing" with reasons. Never wakes a
    sleeping disk. A failing disk should be imaged before anything else reads it."""
    if disk.get("is_image") or disk.get("is_volume") or disk.get("kind") in ("loop", "virtual", "optical") \
            or which("smartctl") is None:
        return None
    rr = run(["smartctl", "-H", "-A", "-n", "standby", "-j", disk["path"]], timeout=30)
    try:
        data = json.loads(rr.stdout or "{}")
    except ValueError:
        return None
    if rr.returncode & 2 and not data.get("smart_status"):
        return None
    reasons = []
    state = "ok"
    st = data.get("smart_status") or {}
    if st.get("passed") is False:
        state = "failing"
        reasons.append("the drive's own health check failed")
    table = (data.get("ata_smart_attributes") or {}).get("table") or []
    raw = {a.get("id"): (a.get("raw") or {}).get("value", 0) for a in table}
    for aid, what in ((5, "reallocated sectors"), (197, "pending sectors"), (198, "uncorrectable sectors"),
                      (187, "reported uncorrectable errors")):
        v = raw.get(aid) or 0
        if v:
            reasons.append(f"{v} {what}")
            if aid in (197, 198) or v > 50:
                state = "failing"
            elif state == "ok":
                state = "warning"
    nv = data.get("nvme_smart_health_information_log") or {}
    if nv.get("critical_warning"):
        state = "failing"
        reasons.append("NVMe critical warning")
    if nv.get("media_errors"):
        reasons.append(f"{nv['media_errors']} media errors")
        state = "failing"
    if (nv.get("percentage_used") or 0) >= 100:
        reasons.append("rated endurance used up")
        if state == "ok":
            state = "warning"
    return {"state": state, "reasons": reasons}
