"""Demo mode: six simulated disks with the classic recovery cases, and simulated jobs, so every page can be
tried without touching a disk:

* a camera's SD card with deleted photos and videos (and a deleted folder),
* a Windows NVMe disk (deleted documents, the recycle bin, orphaned files),
* a 2 TB hard disk whose partitions were deleted (found again by the partition search),
* a USB stick that was quick-formatted (its folders come back as "lost folders"),
* a failing hard disk (image it first),
* the Linux system disk.

Scans produce real scan files (the browsing, filtering and searching are the real ones); the file contents,
previews and thumbnails are generated. Jobs run on a virtual clock: the speeds and times shown are
realistic, the wall-clock time is short (``RALL_DEMO_PACE`` scales it; the tests use 0.02).
"""

from __future__ import annotations

import base64
import calendar
import math
import os
import random
import struct
import tempfile
import time
import zlib

from .api import LocalAPI
from .errors import NotSupported, RallError, UnsafeOperation
from .fs.base import (
    CHANCE_FAIR,
    CHANCE_GOOD,
    CHANCE_POOR,
    F_CARVED,
    F_DIR_RECOVERED,
    F_ORPHAN,
    F_SYSTEM,
    Entry,
)
from .jobs import Job
from .results import ScanDB
from .safety import confirm_token
from .util import GB, MB, TB, MiB, fmt_bytes, fmt_capacity, fmt_rate

ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
MSR = "e3c9e316-0b5c-4db8-817d-f92df00215ae"
BASIC = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
RECOVERY = "de94bba4-06d1-4d40-a16a-bfd50179d6ac"
LINUX = "0fc63daf-8483-4772-8e79-3d69d8477de4"
SWAP = "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f"


def _part(n, start, size, fstype, parttype, label="", name="", mps=None, used=None, logical=False):
    return {"number": n, "name": name, "path": f"/dev/{name}", "start": start, "size": size, "end": start + size,
            "parttype": parttype, "parttype_name": "", "partuuid": f"{n:08x}-5e1f-4c2a-9d3b-{zlib.crc32(name.encode()):012d}",
            "partlabel": "", "partflags": "", "fstype": fstype, "fsver": "", "label": label, "uuid": "",
            "mountpoints": mps or [], "in_use": "mounted" if mps else "", "holders": [], "fssize": size,
            "fsused": used, "extended": False, "logical": logical, "role": "esp" if parttype == ESP else "data"}


def _disk(path, model, serial, size, kind, transport, pttype, parts, health=None, system=False, rotational=False,
          removable=False, problems=None):
    d = {"path": path, "name": os.path.basename(path), "size": size, "is_image": False, "logical_sector": 512,
         "physical_sector": 4096 if kind == "hdd" else 512, "model": model, "serial": serial, "vendor": "",
         "transport": transport, "rotational": rotational, "removable": removable, "readonly": False,
         "pttype": pttype, "ptuuid": "", "wwn": "", "firmware": "", "by_id": "", "kind": kind, "partitions": parts,
         "mountpoints": [m for p in parts for m in p["mountpoints"]], "system": system,
         "in_use": ["mounted: /, /home"] if system else [], "capacity_text": fmt_capacity(size), "display_name": model,
         "key": path, "allocated": sum(p["size"] for p in parts), "health": health,
         "table": {"type": pttype, "ok": not problems, "problems": problems or []}}
    d["confirm_token"] = confirm_token(d)
    return d


def demo_disks() -> list[dict]:
    out = []
    size = 1000204886016
    out.append(_disk("/dev/nvme0n1", "Samsung SSD 970 EVO Plus 1TB", "S4EWNX0R123456K", size, "nvme", "nvme", "gpt", [
        _part(1, MiB, 260 * MiB, "vfat", ESP, "SYSTEM", "nvme0n1p1", used=34 * MB),
        _part(2, 261 * MiB, 16 * MiB, "", MSR, "", "nvme0n1p2"),
        _part(3, 277 * MiB, size - 277 * MiB - 751 * MiB, "ntfs", BASIC, "Windows", "nvme0n1p3", used=412 * GB),
        _part(4, size - 750 * MiB, 749 * MiB, "ntfs", RECOVERY, "Recovery", "nvme0n1p4", used=540 * MB),
    ], health={"state": "ok", "reasons": []}))
    out.append(_disk("/dev/sda", "WDC WD20EZRZ-00Z5HB0", "WD-WCC4M5KX1234", 2000398934016, "hdd", "sata", "gpt", [],
                     health={"state": "warning", "reasons": ["12 reallocated sectors"]}, rotational=True,
                     problems=["The GPT has no partitions, although the disk holds data"]))
    out.append(_disk("/dev/sdb", "ST1000DM010-2EP102", "Z9A1B2C3", 1000204886016, "hdd", "sata", "dos", [
        _part(1, MiB, 1000204886016 - MiB, "ntfs", "0x7", "Projects", "sdb1", used=612 * GB),
    ], health={"state": "failing", "reasons": ["184 pending sectors", "37 uncorrectable sectors"]}, rotational=True))
    out.append(_disk("/dev/mmcblk0", "SanDisk Extreme SD card", "0x9c4e2a11", 127865454592, "sd", "", "dos", [
        _part(1, 4 * MiB, 127865454592 - 4 * MiB, "exfat", "0x7", "EOS_DIGITAL", "mmcblk0p1", used=18 * GB),
    ], removable=True))
    out.append(_disk("/dev/sdc", "Kingston DataTraveler 3.0", "60A44C3FAE21E2A1", 30943995904, "usb-flash", "usb", "dos", [
        _part(1, MiB, 30943995904 - MiB, "vfat", "0xc", "KINGSTON", "sdc1", used=2 * MB),
    ], removable=True))
    size = 250059350016
    out.append(_disk("/dev/nvme1n1", "KINGSTON SNV2S250G", "50026B7785A1B2C3", size, "nvme", "nvme", "gpt", [
        _part(1, MiB, 512 * MiB, "vfat", ESP, "ESP", "nvme1n1p1", ["/boot"], used=96 * MB),
        _part(2, 513 * MiB, size - 513 * MiB - 8 * GB, "ext4", LINUX, "arch", "nvme1n1p2", ["/", "/home"], used=96 * GB),
        _part(3, size - 8 * GB, 8 * GB - MiB, "swap", SWAP, "", "nvme1n1p3"),
    ], health={"state": "ok", "reasons": []}, system=True))
    return out


# ---------------------------------------------------------------------- generated pictures
def _png(w: int, h: int, rows: list[bytes]) -> bytes:
    def chunk(t: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + t + data + struct.pack(">I", zlib.crc32(t + data) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + r for r in rows)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


_PALETTES = [  # sky top, sky bottom, far hills, near hills, ground/water
    ((38, 76, 152), (250, 180, 120), (96, 70, 120), (52, 44, 80), (30, 30, 52)),        # dusk
    ((70, 140, 220), (190, 225, 250), (110, 150, 120), (60, 110, 70), (70, 130, 190)),   # lake
    ((20, 24, 60), (230, 110, 80), (70, 40, 70), (40, 24, 46), (24, 16, 30)),            # sunset
    ((120, 180, 235), (225, 240, 250), (150, 160, 175), (95, 110, 120), (230, 235, 240)),  # snow
    ((60, 130, 200), (170, 215, 240), (90, 140, 80), (50, 100, 50), (200, 180, 120)),    # meadow
]


def scene(seed: int, w: int = 480, h: int = 320) -> bytes:
    """A small landscape "photo" (PNG) for previews and the photo grid."""
    rnd = random.Random(seed)
    top, bot, far, near, ground = _PALETTES[seed % len(_PALETTES)]
    sun_x, sun_y, sun_r = rnd.uniform(0.2, 0.8) * w, rnd.uniform(0.25, 0.45) * h, h * rnd.uniform(0.06, 0.1)
    p1, p2, p3 = rnd.uniform(0, 6), rnd.uniform(0, 6), rnd.uniform(0, 6)
    horizon = int(h * rnd.uniform(0.66, 0.76))
    far_y = [int(h * 0.48 + h * 0.08 * math.sin(x / w * 5 + p1) + h * 0.04 * math.sin(x / w * 13 + p2)) for x in range(w)]
    near_y = [int(h * 0.6 + h * 0.07 * math.sin(x / w * 3 + p3) + h * 0.03 * math.sin(x / w * 17 + p1))
              for x in range(w)]
    rows = []
    sky_rows = []
    for y in range(h):
        t = y / max(1, horizon)
        sky_rows.append(bytes(int(top[i] + (bot[i] - top[i]) * min(1.0, t)) for i in range(3)))
    gnd = bytes(ground)
    farb = bytes(far)
    nearb = bytes(near)
    r2 = sun_r * sun_r
    for y in range(h):
        row = bytearray(sky_rows[y] * w)
        dy2 = (y - sun_y) ** 2
        if dy2 < r2 * 4:
            for x in range(max(0, int(sun_x - 2 * sun_r)), min(w, int(sun_x + 2 * sun_r))):
                d2 = (x - sun_x) ** 2 + dy2
                if d2 < r2:
                    row[3 * x:3 * x + 3] = b"\xff\xf4\xd6"
                elif d2 < r2 * 4:
                    a = 1 - (d2 - r2) / (r2 * 3)
                    for i in range(3):
                        row[3 * x + i] = int(row[3 * x + i] + (255 - row[3 * x + i]) * a * 0.35)
        for x in range(w):
            if y >= horizon:
                shade = 0.85 + 0.15 * math.sin(y * 0.9 + x * 0.05) if ground[2] > 150 else 1.0
                row[3 * x:3 * x + 3] = bytes(min(255, int(c * shade)) for c in gnd)
            elif y >= near_y[x]:
                row[3 * x:3 * x + 3] = nearb
            elif y >= far_y[x]:
                row[3 * x:3 * x + 3] = farb
        rows.append(bytes(row))
    return _png(w, h, rows)


# ---------------------------------------------------------------------- generated scans
def _ts(y, mo, d, hh=12, mm=0, ss=0) -> float:
    return float(calendar.timegm((y, mo, d, hh, mm, ss, 0, 0, 0)))


class _Tree:
    """Builds a volume's entries with keys and parents."""

    def __init__(self, rnd: random.Random):
        self.rnd = rnd
        self.entries: list[Entry] = [Entry("root", None, "", is_dir=True)]
        self.n = 0

    def folder(self, parent, name, deleted=False, flags=0, mtime=None) -> str:
        self.n += 1
        key = f"d{self.n}"
        self.entries.append(Entry(key, parent, name, is_dir=True, deleted=deleted, flags=flags, mtime=mtime))
        return key

    def file(self, parent, name, size, mtime, deleted=False, chance=CHANCE_GOOD, flags=0, seed=None) -> str:
        self.n += 1
        key = f"f{self.n}"
        extra = {"demo_seed": seed if seed is not None else self.n}
        self.entries.append(Entry(key, parent, name, size=size, deleted=deleted, chance=chance, flags=flags,
                                  mtime=mtime, crtime=mtime, runs=[(self.n * 65536, size)], extra=extra))
        return key

    def chance(self, deleted: bool) -> int:
        if not deleted:
            return CHANCE_GOOD
        r = self.rnd.random()
        return CHANCE_GOOD if r < 0.78 else CHANCE_FAIR if r < 0.93 else CHANCE_POOR


DOC_NAMES = ["Budget 2026", "Quarterly report Q2", "Meeting notes", "Thesis draft", "Invoice 1042", "Tax return 2025",
             "CV Anna Novak", "Project plan", "Trip itinerary", "Recipe collection", "Insurance policy", "Lease contract",
             "Presentation sales", "Research summary", "Grocery list", "Training schedule", "Wedding guest list"]


def build_sd_card(tree: _Tree) -> None:
    rnd = tree.rnd
    dcim = tree.folder("root", "DCIM")
    c100 = tree.folder(dcim, "100CANON")
    t = _ts(2026, 7, 14, 9, 12)
    for i in range(301, 461):
        deleted = i < 412
        t += rnd.uniform(20, 900)
        tree.file(c100, f"IMG_{i:04d}.JPG", rnd.randint(4_200_000, 9_800_000), t, deleted, tree.chance(deleted),
                  seed=i)
        if i % 3 == 0:
            tree.file(c100, f"IMG_{i:04d}.CR3", rnd.randint(24_000_000, 31_000_000), t, deleted, tree.chance(deleted),
                      seed=i)
        if i % 37 == 0:
            tree.file(c100, f"MVI_{i:04d}.MP4", rnd.randint(80_000_000, 900_000_000), t + 30, deleted,
                      tree.chance(deleted), seed=i)
    c101 = tree.folder(dcim, "101CANON", deleted=True, mtime=_ts(2026, 8, 2))
    t = _ts(2026, 8, 2, 10, 4)
    for i in range(1, 58):
        t += rnd.uniform(30, 600)
        tree.file(c101, f"IMG_{i:04d}.JPG", rnd.randint(4_000_000, 9_000_000), t, True, tree.chance(True), seed=1000 + i)
    misc = tree.folder("root", "MISC")
    tree.file(misc, "AUTXFER.CFG", 512, t)


def build_windows(tree: _Tree) -> None:
    rnd = tree.rnd
    users = tree.folder("root", "Users")
    anna = tree.folder(users, "Anna")
    docs = tree.folder(anna, "Documents")
    for i, n in enumerate(DOC_NAMES):
        ext = rnd.choice(["docx", "xlsx", "pdf", "pptx", "docx", "odt"])
        deleted = i % 4 == 1
        tree.file(docs, f"{n}.{ext}", rnd.randint(18_000, 4_500_000), _ts(2026, rnd.randint(1, 9), rnd.randint(1, 28)),
                  deleted, tree.chance(deleted), seed=200 + i)
    work = tree.folder(docs, "Work")
    for i in range(24):
        deleted = i % 5 == 0
        tree.file(work, f"Report {2026 - i // 12}-{(i % 12) + 1:02d}.docx", rnd.randint(40_000, 900_000),
                  _ts(2026 - i // 12, (i % 12) + 1, 28), deleted, tree.chance(deleted), seed=300 + i)
    pics = tree.folder(anna, "Pictures")
    hol = tree.folder(pics, "Holiday 2025")
    t = _ts(2025, 8, 3, 8)
    for i in range(1, 86):
        t += rnd.uniform(60, 5000)
        deleted = 30 < i < 52
        tree.file(hol, f"IMG_2025080{i % 9 + 1}_{i:04d}.jpg", rnd.randint(2_500_000, 6_500_000), t, deleted,
                  tree.chance(deleted), seed=500 + i)
    shots = tree.folder(pics, "Screenshots")
    for i in range(18):
        tree.file(shots, f"Screenshot 2026-0{i % 9 + 1}-1{i % 9}.png", rnd.randint(200_000, 1_400_000),
                  _ts(2026, i % 9 + 1, 10 + i % 9), i % 6 == 0, tree.chance(i % 6 == 0), seed=700 + i)
    music = tree.folder(anna, "Music")
    for i, n in enumerate(["Morning run", "Evening jazz", "Focus", "Roadtrip", "Piano"]):
        tree.file(music, f"{n}.mp3", rnd.randint(3_000_000, 11_000_000), _ts(2024, 5, i + 1), False, seed=800 + i)
    desk = tree.folder(anna, "Desktop")
    tree.file(desk, "passwords.kdbx", 48_211, _ts(2026, 9, 1), True, CHANCE_GOOD, seed=900)
    tree.file(desk, "Notes.txt", 2_114, _ts(2026, 9, 21), False, seed=901)
    dl = tree.folder(anna, "Downloads")
    for i, n in enumerate(["setup.exe", "photos.zip", "manual.pdf", "song.flac", "archive.7z", "movie.mkv"]):
        tree.file(dl, n, rnd.randint(1_000_000, 900_000_000), _ts(2026, 6, i + 2), i % 2 == 0,
                  tree.chance(i % 2 == 0), seed=950 + i)
    rb = tree.folder("root", "$Recycle.Bin")
    sid = tree.folder(rb, "S-1-5-21-3623811015-3361044348-30300820-1013")
    for i in range(14):
        tree.file(sid, f"$R{rnd.randint(100000, 999999):X}.{rnd.choice(['jpg', 'docx', 'pdf', 'xlsx'])}",
                  rnd.randint(50_000, 5_000_000), _ts(2026, 9, 2 + i), True, tree.chance(True), seed=1100 + i)
    win = tree.folder("root", "Windows")
    sys32 = tree.folder(win, "System32")
    for i in range(160):
        tree.file(sys32, f"{rnd.choice(['nt', 'win', 'kern', 'user', 'shell', 'mf', 'd3d'])}{i:03d}.dll",
                  rnd.randint(20_000, 4_000_000), _ts(2025, 11, 12))
    pf = tree.folder("root", "Program Files")
    for app in ("Mozilla Firefox", "LibreOffice", "7-Zip", "VideoLAN"):
        a = tree.folder(pf, app)
        for i in range(12):
            tree.file(a, f"{app.split()[0].lower()}{i}.dll", rnd.randint(30_000, 9_000_000), _ts(2026, 3, 1))
    for name in ("$MFT", "$MFTMirr", "$LogFile", "$Volume", "$Bitmap", "$Boot"):
        tree.file("root", name, rnd.randint(4096, 300_000_000), _ts(2024, 1, 5), flags=F_SYSTEM)
    for i in range(9):
        tree.file(None, f"{rnd.choice(DOC_NAMES)} (old).{rnd.choice(['docx', 'jpg', 'pdf'])}",
                  rnd.randint(30_000, 3_000_000), _ts(2023, i + 1, 3), True, tree.chance(True), flags=F_ORPHAN,
                  seed=1200 + i)


def build_backup_ntfs(tree: _Tree) -> None:
    rnd = tree.rnd
    photos = tree.folder("root", "Photos")
    for y in range(2018, 2026):
        yf = tree.folder(photos, str(y))
        for i in range(rnd.randint(30, 70)):
            tree.file(yf, f"IMG_{y}{rnd.randint(1, 12):02d}{rnd.randint(1, 28):02d}_{i:04d}.jpg",
                      rnd.randint(2_000_000, 8_000_000), _ts(y, rnd.randint(1, 12), rnd.randint(1, 28)), seed=y * 100 + i)
    docs = tree.folder("root", "Documents")
    for i, n in enumerate(DOC_NAMES):
        tree.file(docs, f"{n}.{rnd.choice(['docx', 'pdf', 'xlsx'])}", rnd.randint(30_000, 3_000_000),
                  _ts(2022, i % 12 + 1, 5), seed=3000 + i)
    vids = tree.folder("root", "Videos")
    for i in range(14):
        tree.file(vids, f"Family {2019 + i % 6} part {i}.mp4", rnd.randint(300_000_000, 4_000_000_000),
                  _ts(2019 + i % 6, 12, 24), seed=3100 + i)


def build_media_ext4(tree: _Tree) -> None:
    rnd = tree.rnd
    music = tree.folder("root", "Music")
    for a in ("Daft Punk", "Radiohead", "Nina Simone", "Miles Davis", "Björk"):
        af = tree.folder(music, a)
        for i in range(rnd.randint(8, 16)):
            tree.file(af, f"{i + 1:02d} Track {i + 1}.flac", rnd.randint(18_000_000, 60_000_000), _ts(2021, 3, 1),
                      seed=4000 + i)
    movies = tree.folder("root", "Movies")
    for i, m in enumerate(["Holiday 2019.mkv", "Birthday.mkv", "Concert.mp4", "Graduation.mkv"]):
        tree.file(movies, m, rnd.randint(900_000_000, 8_000_000_000), _ts(2020, i + 1, 1), seed=4100 + i)


def build_usb_formatted(tree: _Tree) -> None:
    rnd = tree.rnd
    for idx, (name, files) in enumerate((("School", ["Essay history", "Math homework", "Biology notes", "Thesis"]),
                                         ("Photos", None), ("Music", None))):
        f = tree.folder(None, f"Folder {8241 + idx * 977}", flags=F_DIR_RECOVERED | F_ORPHAN)
        if files:
            for i, n in enumerate(files):
                tree.file(f, f"{n}.{rnd.choice(['docx', 'pdf', 'odt'])}", rnd.randint(30_000, 2_000_000),
                          _ts(2026, 5, i + 3), True, tree.chance(True), seed=5000 + i)
        elif name == "Photos":
            for i in range(40):
                tree.file(f, f"IMG-20260{i % 9 + 1}0{i % 9 + 1}-WA{i:04d}.jpg", rnd.randint(90_000, 400_000),
                          _ts(2026, i % 9 + 1, i % 27 + 1), True, tree.chance(True), seed=5100 + i)
        else:
            for i in range(12):
                tree.file(f, f"song{i + 1:02d}.mp3", rnd.randint(3_000_000, 9_000_000), _ts(2025, 1, i + 1), True,
                          tree.chance(True), seed=5200 + i)


def build_projects(tree: _Tree) -> None:
    rnd = tree.rnd
    for p in ("Website redesign", "Kitchen renovation", "Client Hartmann", "Archive 2023"):
        pf = tree.folder("root", p)
        for i in range(rnd.randint(10, 30)):
            ext = rnd.choice(["psd", "jpg", "docx", "pdf", "dwg", "xlsx", "png", "ai"])
            deleted = rnd.random() < 0.2
            tree.file(pf, f"{p.split()[0].lower()}_{i:03d}.{ext}", rnd.randint(100_000, 120_000_000),
                      _ts(2024, rnd.randint(1, 12), rnd.randint(1, 28)), deleted, tree.chance(deleted), seed=6000 + i)


def carved(tree: _Tree, rnd: random.Random, counts: dict[str, int]) -> None:
    from .filetypes import CATEGORY_NAMES
    names = {"jpg": ("photo", "JPEG image"), "png": ("photo", "PNG image"), "cr3": ("photo", "Canon RAW (CR3)"),
             "mp4": ("video", "MPEG-4 video"), "mov": ("video", "QuickTime video"), "mp3": ("audio", "MP3 audio"),
             "pdf": ("document", "PDF document"), "docx": ("document", "Word document"),
             "xlsx": ("document", "Excel workbook"), "zip": ("archive", "ZIP archive"),
             "sqlite": ("database", "SQLite database"), "exe": ("executable", "Windows program")}
    cats: dict[str, str] = {}
    for ext, n in counts.items():
        cat, desc = names[ext]
        if cat not in cats:
            cats[cat] = tree.folder("root", CATEGORY_NAMES[cat])
        tf = tree.folder(cats[cat], f"{desc} (.{ext})")
        for i in range(n):
            off = rnd.randint(1, 3_000_000) * 512
            dated = ext in ("jpg", "cr3", "mp4") and rnd.random() < 0.7
            t = rnd.uniform(_ts(2019, 1, 1), _ts(2026, 9, 30))
            name = time.strftime("%Y-%m-%d %H.%M.%S", time.gmtime(t)) if dated else f"f{off // 512:010d}"
            size = {"jpg": rnd.randint(800_000, 7_000_000), "mp4": rnd.randint(20_000_000, 600_000_000)}.get(
                ext, rnd.randint(20_000, 9_000_000))
            tree.file(tf, f"{name}.{ext}", size, t if dated else None, True, tree.chance(True), flags=F_CARVED,
                      seed=7000 + i * 7 + len(ext))


SCENARIOS = {
    "/dev/mmcblk0": [("EOS_DIGITAL", "exfat", 4 * MiB, 127865454592 - 4 * MiB, "table", "existing", build_sd_card)],
    "/dev/nvme0n1": [("SYSTEM", "vfat", MiB, 260 * MiB, "table", "existing", None),
                     ("Windows", "ntfs", 277 * MiB, 1000204886016 - 1028 * MiB, "table", "existing", build_windows),
                     ("Recovery", "ntfs", 1000204886016 - 750 * MiB, 749 * MiB, "table", "existing", None)],
    "/dev/sda": [("Backup", "ntfs", MiB, 1_200_000_000_000, "found", "deleted partition", build_backup_ntfs),
                 ("media", "ext4", 1_200_001_048_576, 798_000_000_000, "found", "deleted partition", build_media_ext4)],
    "/dev/sdb": [("Projects", "ntfs", MiB, 1000204886016 - MiB, "table", "existing", build_projects)],
    "/dev/sdc": [("KINGSTON", "fat32", MiB, 30943995904 - MiB, "table", "existing", build_usb_formatted)],
    "/dev/nvme1n1": [("ESP", "fat32", MiB, 512 * MiB, "table", "existing", None),
                     ("arch", "ext4", 513 * MiB, 240 * GB, "table", "existing", None)],
}


def build_scan(path: str, disk: dict, options: dict) -> ScanDB:
    """A scan file like the real scan of DISK would produce."""
    rnd = random.Random(zlib.crc32(disk["path"].encode()))
    db = ScanDB.create(path, source={"spec": disk["path"], "size": disk["size"], "sector_size": 512,
                                     "display_name": disk["display_name"], "model": disk["model"],
                                     "serial": disk.get("serial"), "kind": disk["kind"], "demo": True},
                       options=options)
    mode = options.get("mode") or "quick"
    for label, fstype, off, size, origin, status, builder in SCENARIOS.get(disk["path"], []):
        if origin == "found" and mode not in ("deep",):
            continue
        if mode == "carve":
            continue
        vid = db.add_volume(name=label, fstype=fstype, label=label, offset=off, size=size, block_size=4096,
                            origin=origin, status=status, score=100 if origin == "table" else 92,
                            engine="native", info={}, state="done")
        tree = _Tree(rnd)
        if builder:
            builder(tree)
        with db.writer(vid, base=off) as w:
            for e in tree.entries:
                w.add(e)
    if mode in ("deep", "carve", "photos"):
        counts = {"jpg": 140, "png": 30, "cr3": 12, "mp4": 9, "mov": 3, "mp3": 20, "pdf": 14, "docx": 18,
                  "xlsx": 6, "zip": 5, "sqlite": 3, "exe": 7}
        if mode == "photos":
            counts = {"jpg": 96, "cr3": 14, "mp4": 6, "mov": 2}
        if disk["path"] == "/dev/mmcblk0" and mode != "photos":
            counts = {k: v for k, v in counts.items() if k in ("jpg", "cr3", "mp4", "mov")}
        vid = db.add_volume(name="Files found by signature", fstype="carved", label="", offset=0, size=disk["size"],
                            block_size=512, origin="carved", status="carved", score=0, engine="native", info={},
                            state="done")
        tree = _Tree(rnd)
        carved(tree, rnd, counts)
        with db.writer(vid) as w:
            for e in tree.entries:
                w.add(e)
    db.set_meta(state="complete", finished=time.time(), stats=db.stats(), warnings=[], bad=[],
                table={"type": disk.get("pttype"), "problems": (disk.get("table") or {}).get("problems") or []})
    return db


# ---------------------------------------------------------------------- the API
class DemoAPI(LocalAPI):
    def __init__(self):
        super().__init__("demo")
        self.disks = demo_disks()
        self.pace = float(os.environ.get("RALL_DEMO_PACE") or 1.0)
        self.folder = os.path.join(tempfile.gettempdir(), f"recoverall-demo-{os.getuid()}")
        os.makedirs(self.folder, exist_ok=True)
        self._history = _demo_history()
        self._images: dict[str, dict] = {}

    def _scan_dirs(self):
        from pathlib import Path
        return {Path(self.folder)}

    @property
    def root(self) -> bool:
        return True

    def hello(self) -> dict:
        from .. import __version__
        return {"version": __version__, "mode": "demo", "root": True, "demo": True, "uid": os.getuid(),
                "caps": {"ddrescue": True, "smartctl": True, "sfdisk": True, "tsk": True, "btrfs": True,
                         "cryptsetup": True, "fsck": {k: True for k in ("ext", "fat", "exfat", "ntfs", "xfs", "btrfs",
                                                                        "hfsplus", "f2fs")}}}

    def tool_list(self) -> list[dict]:
        items = super().tool_list()
        for t in items:
            t["path"] = t["path"] or f"/usr/bin/{t['name']}"
        return items

    def close(self) -> None:
        super().close()

    # ------------------------------------------------------------------ disks
    def list_disks(self) -> list[dict]:
        return [dict(d) for d in self.disks] + list(self._images.values())

    def _find(self, path: str) -> dict:
        for d in self.disks + list(self._images.values()):
            if d["path"] == path:
                return d
        raise RallError(f"No disk {path} (demo)")

    def disk_detail(self, path: str) -> dict:
        return dict(self._find(path))

    def open_image(self, path: str) -> dict:
        if path in self._images:
            return self._images[path]
        d = _disk(path, os.path.basename(path), "", 64 * GB, "image", "", "dos", [
            _part(1, MiB, 64 * GB - MiB, "ntfs", "0x7", "OLDLAPTOP", os.path.basename(path) + "1", used=41 * GB)])
        d.update(is_image=True, display_name=f"Image: {os.path.basename(path)}", health=None)
        self._images[path] = d
        return d

    def read_bytes(self, source, offset: int, length: int) -> dict:
        path = source if isinstance(source, str) else source.get("path")
        disk = self._find(path)
        length = max(0, min(int(length), 1024 * 1024))
        rnd = random.Random(int(offset) // 4096)
        data = bytearray(rnd.getrandbits(8) for _ in range(length))
        if int(offset) == 0 and length >= 512:
            data[:512] = bytes(512)
            data[446:462] = bytes([0, 0x20, 0x21, 0, 0xEE, 0xFE, 0xFF, 0xFF, 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF])
            data[510:512] = b"\x55\xaa"
        return {"offset": int(offset), "data": base64.b64encode(bytes(data)).decode(), "size": disk["size"],
                "sector_size": 512}

    # ------------------------------------------------------------------ scans
    def _wait(self, job: Job, seconds: float) -> None:
        job.sleep(max(0.0, seconds * self.pace))

    def start_scan(self, source, options: dict | None = None, name: str = "") -> dict:
        path = source if isinstance(source, str) else source.get("path")
        disk = self._find(path)
        opts = dict(options or {})
        from .scan import MODE_TEXT, scan_options
        opts = scan_options(opts)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        db_path = os.path.join(self.folder, f"{stamp}-{disk['name']}-{opts['mode']}.rascan")
        title = f"{MODE_TEXT.get(opts['mode'], 'Scan')} of {name or disk['display_name']}"

        def fn(job: Job):
            return self._sim_scan(job, disk, opts, db_path)
        job = self.runner.start("scan", [path], title, fn, {"source": source, "options": opts, "scan": db_path})
        out = job.public()
        out["scan"] = db_path
        return out

    def _sim_scan(self, job: Job, disk: dict, opts: dict, db_path: str) -> dict:
        from .scan import MAP_CATEGORY, MAP_CELLS, MAP_FS, MAP_READ, MAP_UNREAD
        steps = ["Partition table"]
        deep = opts["deep"]
        if deep:
            steps.append("Read the whole disk (filesystems and signatures)")
        if opts["fs"] or deep:
            steps.append("Read the filesystems")
        if opts["carve"] and not deep:
            steps.append("Search the free space for files by signature")
        steps.append("Finish")
        job.set_steps(steps)
        cells = [MAP_UNREAD] * MAP_CELLS
        scen = SCENARIOS.get(disk["path"], [])
        for _l, _f, off, _s, origin, _st, _b in scen:
            if origin == "table" or deep:
                cells[min(MAP_CELLS - 1, off * MAP_CELLS // disk["size"])] = MAP_FS
        found = {"volumes": 0, "files": 0, "deleted": 0, "carved": {}, "bad": 0}
        vols = []
        i = 0
        job.step(i)
        self._wait(job, 0.6)
        for label, fstype, off, size, origin, status, _b in scen:
            if origin == "table":
                vols.append({"name": label, "fstype": fstype, "label": label, "offset": off, "size": size,
                             "status": status, "origin": origin, "files": 0, "deleted_files": 0})
        found["volumes"] = len(vols)
        job.update(found=found, volumes=vols, map="".join(cells), force=True)
        i += 1
        rnd = random.Random(7)
        if deep:
            job.step(i)
            size = disk["size"]
            rate = 172 * MB if disk["kind"] == "hdd" else 480 * MB if disk["kind"] != "sd" else 88 * MB
            n = 120
            virtual = size / rate
            for k in range(n + 1):
                done = size * k // n
                upto = done * MAP_CELLS // size
                for c in range(upto):
                    if cells[c] == MAP_UNREAD:
                        cells[c] = MAP_READ
                if k and rnd.random() < 0.55:
                    cat = rnd.choice(["photo", "photo", "photo", "video", "document", "audio", "archive"])
                    found["carved"][cat] = found["carved"].get(cat, 0) + rnd.randint(1, 9)
                    cells[min(MAP_CELLS - 1, max(0, upto - 1))] = MAP_CATEGORY[cat]
                if deep and k == n // 2 and disk["path"] == "/dev/sda":
                    for label, fstype, off, sz, origin, status, _b in scen:
                        if origin == "found":
                            vols.append({"name": label, "fstype": fstype, "label": label, "offset": off, "size": sz,
                                         "status": status, "origin": origin, "files": 0, "deleted_files": 0})
                    found["volumes"] = len(vols)
                eta = virtual * (n - k) / n
                total_found = sum(found["carved"].values())
                job.update(progress=k / n * 0.85, message=f"Reading {fmt_bytes(done)} of {fmt_bytes(size)} · "
                           f"{fmt_rate(rate)} · {total_found} files by signature",
                           stats={"done": done, "total": size, "rate": rate, "eta": eta, "label": "Read"},
                           found=found, volumes=vols, map="".join(cells))
                self._wait(job, 0.12)
            i += 1
        if opts["fs"] or deep:
            job.step(i, f"{len(vols)} volume{'s' if len(vols) != 1 else ''}")
            for v in vols:
                for k in range(5):
                    v["files"] += rnd.randint(100, 900)
                    v["deleted_files"] += rnd.randint(10, 90)
                    found["files"] = sum(x["files"] for x in vols)
                    found["deleted"] = sum(x["deleted_files"] for x in vols)
                    job.update(progress=0.85 + 0.1 * k / 5, message=f"{v['name']}: {v['files']} files, "
                               f"{v['deleted_files']} deleted", found=found, volumes=vols)
                    self._wait(job, 0.15)
            i += 1
        if opts["carve"] and not deep:
            job.step(i)
            size = disk["size"]
            rate = 172 * MB if disk["kind"] == "hdd" else 480 * MB if disk["kind"] != "sd" else 88 * MB
            n = 120
            virtual = size / rate
            for k in range(n + 1):
                done = size * k // n
                upto = done * MAP_CELLS // size
                for c in range(upto):
                    if cells[c] == MAP_UNREAD:
                        cells[c] = MAP_READ
                if k and rnd.random() < 0.55:
                    cat = rnd.choice(["photo", "photo", "photo", "video", "document", "audio", "archive"])
                    found["carved"][cat] = found["carved"].get(cat, 0) + rnd.randint(1, 9)
                    cells[min(MAP_CELLS - 1, max(0, upto - 1))] = MAP_CATEGORY[cat]
                if deep and k == n // 2 and disk["path"] == "/dev/sda":
                    for label, fstype, off, sz, origin, status, _b in scen:
                        if origin == "found":
                            vols.append({"name": label, "fstype": fstype, "label": label, "offset": off, "size": sz,
                                         "status": status, "origin": origin, "files": 0, "deleted_files": 0})
                    found["volumes"] = len(vols)
                eta = virtual * (n - k) / n
                total_found = sum(found["carved"].values())
                job.update(progress=k / n * 0.85, message=f"Reading {fmt_bytes(done)} of {fmt_bytes(size)} · "
                           f"{fmt_rate(rate)} · {total_found} files by signature",
                           stats={"done": done, "total": size, "rate": rate, "eta": eta, "label": "Read"},
                           found=found, volumes=vols, map="".join(cells))
                self._wait(job, 0.12)
            i += 1
        job.step(i)
        db = build_scan(db_path, disk, opts)
        stats = db.stats()
        for v in db.volumes():
            for x in vols:
                if x["name"] == v["name"]:
                    x["files"], x["deleted_files"] = v["files"], v["deleted_files"]
        db.close()
        found["files"] = stats["files"]
        found["deleted"] = stats["deleted_files"]
        job.update(progress=1.0, message=f"Found {stats['files']} files ({stats['deleted_files']} deleted)",
                   found=found, volumes=vols, map="".join(c if c != MAP_UNREAD or not deep else MAP_READ for c in cells),
                   force=True)
        return {"stats": stats, "volumes": len(vols), "scan": db_path}

    def _scan_source(self, path: str):
        raise NotSupported("demo")

    def preview(self, scan: str, entry: int) -> dict:
        db = self._scan(scan)
        e = db.entry(int(entry))
        seed = (e.get("extra") or {}).get("demo_seed", e["id"])
        ext = e.get("ext") or ""
        out = {"kind": "none", "size": e["size"], "ext": ext, "info": {}, "valid": True, "id": e["id"]}
        rnd = random.Random(seed)
        out["hex"] = base64.b64encode(bytes(rnd.getrandbits(8) for _ in range(1024))).decode()
        if e["chance"] == CHANCE_POOR and e["deleted"]:
            out["valid"] = False
            out["note"] = f"The content doesn't start like a .{ext} file: it was probably overwritten."
            out["kind"] = "hex"
            return out
        if e.get("cat") == "photo":
            out.update(kind="image", data=base64.b64encode(scene(seed)).decode())
            out["info"] = {"width": 6000, "height": 4000, "make": "Canon", "model": "Canon EOS R6",
                           "date": time.strftime("%Y:%m:%d %H:%M:%S", time.gmtime(e["mtime"] or 0))} \
                if ext in ("jpg", "cr3") else {"width": 1920, "height": 1080}
            return out
        if e.get("cat") == "document" or ext in ("txt", "kdbx"):
            title = os.path.splitext(e["name"])[0]
            text = (f"{title}\n\n" + "\n\n".join(
                rnd.choice(["The figures for the second quarter show steady growth across all regions.",
                            "Please find attached the updated schedule for the next three months.",
                            "Action items: confirm the venue, send invitations, order the catering.",
                            "Total due: 1 240,00 € — payable within 30 days of the invoice date.",
                            "Chapter 3 discusses the method and the limits of the measurements.",
                            "Remember to back up the photos to the NAS every Sunday evening."])
                for _ in range(6)))
            out.update(kind="text", text=text)
            return out
        out["kind"] = "hex"
        return out

    def thumbnails(self, scan: str, entries: list[int]) -> dict:
        db = self._scan(scan)
        out = {}
        for i in entries[:64]:
            e = db.entry(int(i))
            seed = (e.get("extra") or {}).get("demo_seed", e["id"])
            if e["chance"] == CHANCE_POOR and e["deleted"]:
                out[str(i)] = {"data": None, "error": "overwritten"}
            else:
                out[str(i)] = {"data": base64.b64encode(scene(seed, 192, 128)).decode(), "embedded": True}
        return out

    def start_recover(self, scan: str, entries: list[int], dest: str, options=None, filters=None) -> dict:
        db = self._scan(scan)
        ids = []
        for i in entries:
            ids.extend(db.subtree(int(i), filters))
        ids = list(dict.fromkeys(ids))
        total = 0
        for i in ids:
            total += db.entry(i)["size"]
        if not ids:
            raise RallError("Nothing to recover: the selection has no files")
        meta = db.meta("source") or {}
        if dest.startswith(("/run/media/demo/" + "SD", "/mnt/sd")) or meta.get("spec") in dest:
            raise UnsafeOperation("That folder is on the disk you are recovering from")
        n = len(ids)

        def fn(job: Job):
            job.set_steps(["Recover the files", "Write the report"])
            job.step(0, f"{n} files, {fmt_bytes(total)}")
            rate = 145 * MB
            steps = 40
            for k in range(steps + 1):
                done = total * k // steps
                job.update(progress=k / steps, message=f"Recovered {n * k // steps} of {n} files · {fmt_rate(rate)}",
                           stats={"done": done, "total": total, "rate": rate, "eta": (total - done) / rate,
                                  "label": "Recovered"})
                self._wait(job, 0.1)
            job.step(1)
            job.log(f"Report: {dest}/RecoverAll report.txt")
            job.update(message=f"Recovered {n} files ({fmt_bytes(total)}) into {dest} (demo: nothing was written)",
                       force=True)
            return {"files": n, "bytes": total, "failed": 0, "damaged": 0, "dest": dest}
        job = self.runner.start("recover", [f"recover:{dest}"], f"Recover {n} items → {dest}", fn,
                                {"scan": scan, "dest": dest, "count": n})
        return job.public()

    # ------------------------------------------------------------------ partitions
    def partition_table(self, source) -> dict:
        disk = self._find(source if isinstance(source, str) else source["path"])
        return {"type": disk.get("pttype") or "none", "sector_size": 512, "disk_size": disk["size"],
                "ok": not (disk.get("table") or {}).get("problems"),
                "problems": (disk.get("table") or {}).get("problems") or [],
                "partitions": [{"number": p["number"], "start": p["start"], "size": p["size"], "type": p["parttype"],
                                "type_name": "", "name": p.get("partlabel") or "", "guid": p.get("partuuid"),
                                "bootable": False, "logical": p.get("logical", False)} for p in disk["partitions"]]}

    def start_partition_search(self, source, mode: str = "quick") -> dict:
        path = source if isinstance(source, str) else source["path"]
        disk = self._find(path)

        def fn(job: Job):
            job.set_steps(["Read the partition table", "Search" + (" the whole disk" if mode == "deep" else ""),
                           "Check what was found"])
            job.step(0)
            self._wait(job, 0.4)
            job.step(1)
            size = disk["size"]
            n = 40 if mode == "deep" else 12
            rate = 170 * MB
            for k in range(n + 1):
                done = size * k // n
                job.update(progress=k / n * 0.95, message=f"Reading {fmt_bytes(done)} of {fmt_bytes(size)}",
                           stats={"done": done, "total": size, "rate": rate if mode == "deep" else None,
                                  "eta": (size - done) / rate if mode == "deep" else None, "label": "Searched"})
                self._wait(job, 0.12)
            job.step(2)
            cands = []
            for label, fstype, off, sz, origin, status, _b in SCENARIOS.get(path, []):
                cands.append({"fstype": fstype, "offset": off, "size": sz, "label": label,
                              "status": "current" if origin == "table" else "deleted", "score": 96,
                              "evidence": "boot sector + backup boot sector" if fstype == "ntfs" else
                              "superblock + 9 backup superblocks" if fstype.startswith("ext") else "boot sector",
                              "preview": _peek(label)})
            if path == "/dev/sda":
                cands.append({"fstype": "ntfs", "offset": 512 * MiB, "size": 64 * GB, "label": "",
                              "status": "overlaps", "score": 31, "evidence": "backup boot sector only",
                              "preview": []})
            job.update(message=f"{len(cands)} filesystems found", force=True)
            ttype = disk.get("pttype") or "gpt"
            prop = [{"number": i + 1, "start": c["offset"], "size": c["size"], "fstype": c["fstype"],
                     "name": c["label"], "type": BASIC if c["fstype"] == "ntfs" else LINUX}
                    for i, c in enumerate(x for x in cands if x["status"] != "overlaps")]
            return {"table": self.partition_table(path), "candidates": cands, "proposal": prop, "table_type": ttype,
                    "disk_size": size, "sector_size": 512}
        job = self.runner.start("partitions", [path], f"{'Deep' if mode == 'deep' else 'Quick'} partition search on "
                                f"{disk['display_name']}", fn, {"source": source, "mode": mode})
        return job.public()

    def plan_partitions(self, source, table_type: str, parts: list[dict]) -> dict:
        problems = []
        last = 0
        for p in sorted(parts, key=lambda p: p["start"]):
            if p["start"] < last:
                problems.append(f"Partition at {fmt_bytes(p['start'])} overlaps the one before it")
            last = p["start"] + p["size"]
        lines = [f"label: {table_type}"] + [f"start={p['start'] // 512}, size={p['size'] // 512}, type={p.get('type')}"
                                            for p in parts]
        return {"ok": not problems, "problems": problems, "script": "\n".join(lines)}

    def write_partitions(self, source, table_type: str, parts: list[dict], confirm: str = "") -> dict:
        disk = self._find(source)
        if (confirm or "").strip().lower() != confirm_token(disk).lower():
            raise UnsafeOperation(f"Type “{confirm_token(disk)}” to confirm writing to {disk['display_name']}")
        new = []
        for i, p in enumerate(sorted(parts, key=lambda p: p["start"]), start=1):
            new.append(_part(i, p["start"], p["size"], p.get("fstype") or "", p.get("type") or BASIC,
                             p.get("name") or "", f"{disk['name']}{i}"))
        disk["partitions"] = new
        disk["pttype"] = table_type
        disk["table"] = {"type": table_type, "ok": True, "problems": []}
        backup = f"/var/lib/recoverall/backups/{disk['name']}-{time.strftime('%Y%m%d-%H%M%S')}.rallbak"
        self._history.insert(0, {"id": f"{int(time.time())}-pt", "kind": "partitions", "state": "done",
                                 "title": f"Wrote a {table_type.upper()} partition table on {disk['display_name']}",
                                 "started": time.time(), "finished": time.time(), "message": f"Backup: {backup}",
                                 "steps": [], "warnings": [], "log": []})
        return {"backup": backup, "table": self.partition_table(source)}

    def list_backups(self) -> list[dict]:
        return [{"path": "/var/lib/recoverall/backups/sda-20260930-141502.rallbak", "device": "/dev/sda",
                 "created": time.time() - 8 * 86400, "label": "partition table", "ranges": 2, "bytes": 34 * 512 * 2}]

    def undo_backup(self, path: str, confirm: str = "") -> dict:
        return {"ok": True, "restored": path}

    # ------------------------------------------------------------------ repair
    def diagnose(self, source, offset: int = 0, size=None, fstype: str = "") -> list[dict]:
        path = source if isinstance(source, str) else source["path"]
        if path == "/dev/sdb":
            return [{"id": "ntfs-boot-differs", "title": "The NTFS boot sector differs from its backup",
                     "detail": "The backup boot sector at the end of the partition looks right; the first one has "
                               "damaged fields (cluster size 0).", "severity": "error", "fix": "boot:ntfs_boot"}]
        if path == "/dev/sdc":
            return [{"id": "fat-mirror", "title": "The two copies of the FAT differ",
                     "detail": "FAT #1 and FAT #2 differ in 1 214 entries: the stick was removed while writing.",
                     "severity": "warning", "fix": "boot:fat_copy"}]
        return []

    def fsck_actions(self, fstype: str) -> list[dict]:
        acts = super().fsck_actions(fstype)
        for a in acts:
            a["available"] = True
        return acts

    def start_repair(self, source, action: str, offset: int = 0, size=None, fstype: str = "", options=None,
                     confirm: str = "") -> dict:
        path = source if isinstance(source, str) else source["path"]
        disk = self._find(path)

        def fn(job: Job):
            job.set_steps([action.split(":", 1)[-1].replace("_", " ").capitalize()])
            job.step(0)
            lines = {"fsck": ["Checking the filesystem…", "Pass 1: Checking inodes, blocks, and sizes",
                              "Pass 2: Checking directory structure", "Pass 3: Checking directory connectivity",
                              "Pass 4: Checking reference counts", "Pass 5: Checking group summary information"],
                     "boot": ["Backing up the boot sector to /var/lib/recoverall/backups/", "Copying the backup boot "
                              "sector over the first one", "Verifying: OK"]}[action.split(":")[0]]
            for k, ln in enumerate(lines):
                job.log(ln)
                job.update(progress=(k + 1) / len(lines), message=ln)
                self._wait(job, 0.4)
            job.update(message="No problems found" if "check" in action else "Repaired", force=True)
            return {"ok": True, "summary": "Repaired"}
        job = self.runner.start("repair", [path], f"{action} on {disk['display_name']}", fn, {"source": source})
        return job.public()

    def start_file_repair(self, paths: list[str], out_dir: str, reference=None) -> dict:
        def fn(job: Job):
            job.set_steps([f"Repair {os.path.basename(p)}" for p in paths])
            for k, p in enumerate(paths):
                job.step(k)
                self._wait(job, 0.5)
                job.log(f"{os.path.basename(p)}: added the missing end marker, cut 3.1 kB of garbage")
            return {"files": [{"path": p, "ok": True, "out": os.path.join(out_dir, os.path.basename(p))} for p in paths]}
        job = self.runner.start("filerepair", [f"filerepair:{out_dir}"], f"Repair {len(paths)} files", fn,
                                {"paths": paths})
        return job.public()

    def file_analyze(self, path: str) -> dict:
        return {"type": os.path.splitext(path)[1].lstrip(".").lower() or "jpg",
                "problems": ["The file ends in the middle of the picture data (no end marker)"], "repairable": True,
                "actions": ["Add the missing end marker"]}

    # ------------------------------------------------------------------ imaging, RAID, unlocking
    def start_image(self, source, dest: str, options=None) -> dict:
        path = source if isinstance(source, str) else source.get("path")
        disk = self._find(path)

        def fn(job: Job):
            from .imaging import BAD, DONE, MAP_CELLS, NON_TRIED, NON_TRIMMED
            size = disk["size"]
            job.set_steps(["Copy what reads easily", "Read the bad areas", "Done"])
            job.step(0, f"RecoverAll imager → {dest}")
            cells = [NON_TRIED] * MAP_CELLS
            bad = {int(MAP_CELLS * f) for f in (0.31, 0.312, 0.58, 0.581, 0.582, 0.77)} if disk.get("health") and \
                disk["health"].get("state") == "failing" else set()
            rate = 140 * MB
            n = 80
            for k in range(n + 1):
                upto = MAP_CELLS * k // n
                for c in range(upto):
                    if cells[c] == NON_TRIED:
                        cells[c] = NON_TRIMMED if c in bad else DONE
                done = size * k // n
                st = {"done": done, "nontried": size - done, "nontrimmed": len(bad) * size // MAP_CELLS
                      if k > n * 0.8 else 0, "nonscraped": 0, "bad": 0, "bad_areas": 0, "size": size}
                job.update(progress=done / size, message=f"Copying: {100 * done / size:.2f} % copied · {fmt_rate(rate)}",
                           stats={"done": done, "total": size, "rate": rate, "eta": (size - done) / rate, "label": "Copied"},
                           imaging={"cells": "".join(cells), "phase": "Copying", "errors": len(bad), **st})
                self._wait(job, 0.1)
            job.step(1)
            for c in bad:
                cells[c] = BAD
            job.update(progress=1.0, imaging={"cells": "".join(cells), "phase": "Finished", "size": size, "done": size,
                                              "bad": len(bad) * 4096, "bad_areas": len(bad), "nontried": 0,
                                              "nontrimmed": 0, "nonscraped": 0}, force=True)
            job.step(2)
            msg = f"Imaged {fmt_bytes(size)}" + (f"; {fmt_bytes(len(bad) * 4096)} unreadable" if bad else "")
            job.update(message=msg, force=True)
            return {"image": dest, "mapfile": dest + ".map", "bad": len(bad) * 4096}
        job = self.runner.start("image", [path, dest], f"Image {disk['display_name']} → {os.path.basename(dest)}", fn,
                                {"source": source, "dest": dest})
        return job.public()

    def raid_from_md(self, paths: list[str]) -> dict | None:
        return None

    def raid_describe(self, definition: dict) -> dict:
        from .raid import describe_definition
        sizes = []
        for m in definition.get("members") or []:
            if m:
                try:
                    sizes.append(self._find(m["path"] if isinstance(m, dict) else m)["size"])
                except RallError:
                    sizes.append(TB)
        n = len(definition.get("members") or [])
        lv = str(definition.get("level"))
        unit = min(sizes) if sizes else 0
        total = {"0": unit * n, "1": unit, "5": unit * (n - 1), "6": unit * (n - 2), "10": unit * n // 2,
                 "jbod": sum(sizes)}.get(lv, 0)
        return {"text": describe_definition(definition), "size": total, "size_text": fmt_bytes(total)}

    def save_raid(self, definition: dict, path: str = "") -> str:
        path = path or os.path.join(self.folder, f"{definition.get('name') or 'raid'}.rallraid")
        d = _disk(path, definition.get("name") or "Virtual RAID", "", self.raid_describe(definition)["size"], "raid",
                  "", "gpt", [])
        d.update(is_image=True, display_name=f"RAID: {definition.get('name') or 'Virtual RAID'}", health=None)
        self._images[path] = d
        return path

    def start_raid_detect(self, paths: list[str], levels=None, missing: int = 0) -> dict:
        def fn(job: Job):
            for k in range(20):
                job.update(progress=k / 20, message=f"Trying {k * 37} combinations…")
                self._wait(job, 0.1)
            return {"candidates": [{"score": 1840, "level": "5", "chunk": 65536, "layout": "left-symmetric",
                                    "members": [{"path": p, "offset": 0} for p in paths]},
                                   {"score": 220, "level": "5", "chunk": 131072, "layout": "left-asymmetric",
                                    "members": [{"path": p, "offset": 0} for p in reversed(paths)]}]}
        job = self.runner.start("raid", list(paths), "Find the RAID parameters", fn, {"paths": paths})
        return job.public()

    def unlock(self, source, passphrase: str, kind: str = "auto") -> dict:
        if passphrase != "demo":
            raise RallError("Wrong passphrase (in the demo it's “demo”)")
        return {"path": "/dev/mapper/recoverall-1", "name": "recoverall-1"}

    # ------------------------------------------------------------------ history
    def _record(self, job) -> None:
        entry = job.full()
        entry["log"] = [(t, lv, text) for _n, t, lv, text in job.log_since(0)][-400:]
        entry.pop("data", None)
        entry.pop("result", None)
        self._history.insert(0, entry)

    def history(self, limit: int = 200) -> list[dict]:
        return self._history[:limit]

    def clear_history(self) -> bool:
        self._history = []
        return True


def _peek(label: str) -> list[str]:
    return {"Backup": ["Documents/", "Photos/", "Videos/", "desktop.ini"],
            "media": ["Movies/", "Music/", "lost+found/"],
            "EOS_DIGITAL": ["DCIM/", "MISC/"], "Windows": ["Program Files/", "Users/", "Windows/", "pagefile.sys"],
            "Projects": ["Archive 2023/", "Client Hartmann/", "Kitchen renovation/", "Website redesign/"],
            "KINGSTON": []}.get(label, [])


def _demo_history() -> list[dict]:
    now = time.time()

    def entry(i, kind, title, state, ago, dur, msg, warnings=(), steps=()):
        st = now - ago
        return {"id": f"demo-{i}", "kind": kind, "title": title, "state": state, "started": st, "finished": st + dur,
                "message": msg, "error": msg if state == "failed" else "", "warnings": list(warnings),
                "steps": [{"title": t, "state": s, "detail": d} for t, s, d in steps],
                "log": [(st, "info", f"— {t}") for t, _s, _d in steps] + [(st + dur, "info", msg)]}
    return [
        entry(1, "recover", "Recover 412 items → /run/media/demo/Backup/Recovered", "done", 3 * 86400, 1260,
              "Recovered 412 files (3.81 GB)", (), [("Recover the files", "done", "412 files, 3.81 GB"),
                                                   ("Write the report", "done", "")]),
        entry(2, "scan", "Deep scan of WDC WD20EZRZ-00Z5HB0", "done", 3 * 86400 + 14000, 12100,
              "Found 18 433 files (2 115 deleted) on 3 volumes", (),
              [("Partition table", "done", ""), ("Read the whole disk (filesystems and signatures)", "done", ""),
               ("Read the filesystems", "done", "3 volumes"), ("Finish", "done", "")]),
        entry(3, "image", "Image ST1000DM010-2EP102 → sdb.img", "done", 9 * 86400, 7400,
              "Imaged 1.00 TB; 151 kB unreadable (37 areas, zeros in the image)",
              ("37 unreadable areas: the files there have holes",),
              [("Copy what reads easily", "done", ""), ("Read the bad areas", "done", ""), ("Done", "done", "")]),
        entry(4, "partitions", "Quick partition search on Kingston DataTraveler 3.0", "done", 21 * 86400, 64,
              "1 filesystem found", (), [("Read the partition table", "done", ""), ("Search", "done", ""),
                                         ("Check what was found", "done", "")]),
    ]
