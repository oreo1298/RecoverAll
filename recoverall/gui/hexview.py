"""The sector viewer: the raw bytes of a disk, a partition or an image, page by page, with the boot sectors,
partition tables and superblocks it recognises spelled out. Read-only."""

from __future__ import annotations

import base64
import struct

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QSplitter,
    QVBoxLayout,
)

from ..core.util import fmt_bytes, parse_size
from .theme import mono_font
from .widgets import Card, KeyValueGrid, icon_button

PAGE = 4096


def interpret(data: bytes, offset: int) -> tuple[str, list[tuple[str, str]]]:
    """What the first sector of DATA is, and its main fields."""
    s = data[:512]
    if len(s) < 512:
        return "", []
    if s[3:11] == b"NTFS    ":
        bps, spc = struct.unpack_from("<HB", s, 11)
        cs = bps * (spc if spc <= 128 else 1 << (256 - spc))
        total = struct.unpack_from("<Q", s, 40)[0]
        mft = struct.unpack_from("<Q", s, 48)[0]
        return "NTFS boot sector", [("Bytes per sector", str(bps)), ("Cluster size", fmt_bytes(cs)),
                                    ("Volume size", fmt_bytes(total * bps)), ("MFT at cluster", f"{mft:,}"),
                                    ("Serial", f"{struct.unpack_from('<Q', s, 72)[0]:016X}"),
                                    ("Signature", "55 AA" if s[510:512] == b"\x55\xaa" else "missing")]
    if s[3:11] == b"EXFAT   ":
        vol = struct.unpack_from("<Q", s, 72)[0]
        bps = 1 << s[108]
        return "exFAT boot sector", [("Volume size", fmt_bytes(vol * bps)), ("Bytes per sector", str(bps)),
                                     ("Cluster size", fmt_bytes(bps << s[109])),
                                     ("Serial", f"{struct.unpack_from('<I', s, 100)[0]:08X}")]
    if s[510:512] == b"\x55\xaa" and (s[54:59] == b"FAT12" or s[54:59] == b"FAT16" or s[82:87] == b"FAT32"):
        bps, spc, res, nf = struct.unpack_from("<HBHB", s, 11)
        total = struct.unpack_from("<H", s, 19)[0] or struct.unpack_from("<I", s, 32)[0]
        kind = "FAT32" if s[82:87] == b"FAT32" else s[54:59].decode()
        label = (s[71:82] if kind == "FAT32" else s[43:54]).decode("latin-1").strip()
        return f"{kind} boot sector", [("Bytes per sector", str(bps)), ("Cluster size", fmt_bytes(bps * spc)),
                                       ("Reserved sectors", str(res)), ("FATs", str(nf)),
                                       ("Volume size", fmt_bytes(total * bps)), ("Label", label)]
    if s[:8] == b"EFI PART":
        cur, bak, first, last = struct.unpack_from("<QQQQ", s, 24)
        entries, n, size = struct.unpack_from("<QII", s, 72)
        return "GPT header", [("This header at LBA", str(cur)), ("Other copy at LBA", str(bak)),
                              ("Usable LBAs", f"{first} – {last}"), ("Entries at LBA", str(entries)),
                              ("Entries", f"{n} × {size} bytes")]
    if s[510:512] == b"\x55\xaa" and offset % 512 == 0:
        rows = []
        for i in range(4):
            e = s[446 + 16 * i:462 + 16 * i]
            if e[4]:
                start, count = struct.unpack_from("<II", e, 8)
                rows.append((f"Entry {i + 1}", f"type 0x{e[4]:02X}{' boot' if e[0] == 0x80 else ''} · "
                             f"start {start} · {fmt_bytes(count * 512)}"))
        if rows:
            return "Partition table (MBR / EBR)", rows
    if len(data) >= 1024 + 64 and data[1024 + 56:1024 + 58] == b"\x53\xef":
        sb = data[1024:2048]
        blocks, = struct.unpack_from("<I", sb, 4)
        bs = 1024 << struct.unpack_from("<I", sb, 24)[0]
        label = sb[120:136].split(b"\0")[0].decode("utf-8", "replace")
        return "ext2/3/4 superblock (at +1024)", [("Block size", fmt_bytes(bs)), ("Size", fmt_bytes(blocks * bs)),
                                                  ("Label", label), ("Group of this copy", str(struct.unpack_from("<H", sb, 90)[0]))]
    if s[:4] == b"XFSB":
        bs, = struct.unpack_from(">I", s, 4)
        blocks, = struct.unpack_from(">Q", s, 8)
        return "XFS superblock", [("Block size", fmt_bytes(bs)), ("Size", fmt_bytes(blocks * bs)),
                                  ("Label", s[108:120].split(b"\0")[0].decode("latin-1"))]
    if s[:4] == b"FILE":
        return "NTFS MFT record", [("Record number", str(struct.unpack_from("<I", s, 0x2C)[0])),
                                   ("In use", "yes" if struct.unpack_from("<H", s, 0x16)[0] & 1 else "no (deleted)"),
                                   ("Folder", "yes" if struct.unpack_from("<H", s, 0x16)[0] & 2 else "no")]
    if s[:6] == b"LUKS\xba\xbe":
        return "LUKS header (encrypted volume)", [("Version", str(struct.unpack_from(">H", s, 6)[0]))]
    if s[3:11] == b"-FVE-FS-":
        return "BitLocker volume", []
    return "", []


def hexdump(data: bytes, base: int) -> str:
    lines = []
    for i in range(0, len(data), 16):
        if i and (base + i) % 512 == 0:
            lines.append(f"{'':-<12}  sector {(base + i) // 512:,}".replace(",", " "))
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk[:8]) + "  " + " ".join(f"{b:02x}" for b in chunk[8:])
        asc = "".join(chr(b) if 32 <= b < 127 else "·" for b in chunk)
        lines.append(f"{base + i:012x}  {hx:<48}  {asc}")
    return "\n".join(lines)


class HexDialog(QDialog):
    def __init__(self, bridge, disk: dict, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.disk = disk
        self.size = int(disk.get("size") or 0)
        self.offset = 0
        self.setWindowTitle(f"Sectors of {disk.get('display_name') or disk.get('path')}")
        self.resize(1080, 720)
        lay = QVBoxLayout(self)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Offset"))
        self.edit = QLineEdit("0")
        self.edit.setToolTip("Bytes (1048576, 0x100000, 1M) or a sector: s2048")
        self.edit.returnPressed.connect(self._go)
        self.edit.setMaximumWidth(200)
        bar.addWidget(self.edit)
        for text, icon, delta in (("", "chevron_left", -PAGE), ("", "chevron_right", PAGE)):
            b = icon_button(text, icon, "ghost", "Previous page" if delta < 0 else "Next page")
            b.clicked.connect(lambda _c=False, d=delta: self.show_at(self.offset + d))
            bar.addWidget(b)
        b = icon_button("Start", "up", "ghost")
        b.clicked.connect(lambda: self.show_at(0))
        bar.addWidget(b)
        b = icon_button("End", "down", "ghost")
        b.clicked.connect(lambda: self.show_at(max(0, self.size - PAGE)))
        bar.addWidget(b)
        self.jump = QComboBox()
        self.jump.addItem("Jump to…", None)
        self.jump.addItem("Partition table (sector 0)", 0)
        self.jump.addItem("GPT header (sector 1)", 512)
        for p in disk.get("partitions") or []:
            self.jump.addItem(f"Partition {p['number']} start ({p.get('label') or p.get('fstype') or ''})", p["start"])
            if p.get("size"):
                self.jump.addItem(f"Partition {p['number']} last sector (backup boot)", p["start"] + p["size"] - 512)
        self.jump.activated.connect(self._jump)
        bar.addWidget(self.jump)
        bar.addStretch(1)
        self.where = QLabel("")
        self.where.setObjectName("Muted")
        bar.addWidget(self.where)
        lay.addLayout(bar)
        split = QSplitter(Qt.Horizontal)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setObjectName("Log")
        self.text.setFont(mono_font(9.5))
        self.text.setLineWrapMode(QPlainTextEdit.NoWrap)
        split.addWidget(self.text)
        side = Card("What this is", "info")
        self.kind = QLabel("")
        self.kind.setWordWrap(True)
        side.add(self.kind)
        self.grid = KeyValueGrid()
        side.add(self.grid)
        side.body().addStretch(1)
        side.setMinimumWidth(280)
        split.addWidget(side)
        split.setSizes([760, 300])
        lay.addWidget(split, 1)
        self.show_at(0)

    def _jump(self, i: int) -> None:
        off = self.jump.itemData(i)
        if off is not None:
            self.show_at(int(off))
        self.jump.setCurrentIndex(0)

    def _go(self) -> None:
        t = self.edit.text().strip().lower().replace(" ", "")
        try:
            if t.startswith("s"):
                off = int(t[1:], 0) * 512
            elif t.startswith("0x"):
                off = int(t, 16)
            else:
                off = parse_size(t.upper().replace("B", "") if t[-1:].isalpha() else t)
        except ValueError:
            self.bridge.message.emit("Not an offset: try 1048576, 0x100000, 1M or s2048", "warning")
            return
        self.show_at(off)

    def show_at(self, off: int) -> None:
        off = max(0, min(int(off), max(0, self.size - 1)))
        off -= off % 16
        self.offset = off

        def got(r):
            data = base64.b64decode(r.get("data") or "")
            self.size = int(r.get("size") or self.size)
            self.text.setPlainText(hexdump(data, off))
            self.edit.setText(str(off))
            self.where.setText(f"sector {off // 512:,} of {self.size // 512:,} · {fmt_bytes(off)}".replace(",", " "))
            kind, rows = interpret(data, off)
            self.kind.setText(f"<b>{kind}</b>" if kind else "Nothing RecoverAll recognises at the start of this page.")
            self.grid.set_rows(rows)
        self.bridge.call("read_bytes", done=got, source=self.disk["path"], offset=off, length=PAGE)
