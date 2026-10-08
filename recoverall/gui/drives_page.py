"""The Drives page: every disk, card, stick, image and virtual RAID with its partition map, its health, and
what you can do with it; its partitions fold out with a "Scan" button each."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QLabel, QScrollArea, QToolButton, QVBoxLayout, QWidget

from ..core.devices import ROLE_NAMES
from ..core.fs import fs_name
from ..core.util import fmt_bytes
from .diskmap import DiskMap
from .widgets import (
    ElidedLabel,
    badge,
    bind_icon,
    clear_layout,
    disk_subtitle,
    fs_color,
    health_badge,
    icon_button,
    kind_icon,
    more_button,
    scaled_font,
    set_object_name,
)

ENCRYPTED = ("crypto_luks", "bitlocker")


class DriveCard(QFrame):
    """One disk: name and health, its map, the main action (recover files — or image it first when it's
    failing) and the others in the ⋯ menu."""

    action = Signal(str, object)        # action, path or {"path", "number"}

    def __init__(self, disk: dict):
        super().__init__()
        self.setObjectName("DiskCard")
        self.path = disk["path"]
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 12)
        lay.setSpacing(10)
        top = QHBoxLayout()
        top.setSpacing(12)
        self.icon = QLabel()
        self._ic = bind_icon(self.icon, kind_icon(disk.get("kind", "")), "accent", 30)
        top.addWidget(self.icon, 0, Qt.AlignVCenter)
        col = QVBoxLayout()
        col.setSpacing(1)
        head = QHBoxLayout()
        head.setSpacing(8)
        self.name = ElidedLabel()
        self.name.setObjectName("Heading")
        self.name.setFont(scaled_font(self.name, 1.12, bold=True))
        head.addWidget(self.name, 1)
        self.badges = QHBoxLayout()
        self.badges.setSpacing(6)
        head.addLayout(self.badges)
        col.addLayout(head)
        self.sub = QLabel()
        self.sub.setObjectName("Muted")
        self.sub.setFont(scaled_font(self.sub, 0.88))
        col.addWidget(self.sub)
        top.addLayout(col, 1)
        self.btn_photos = icon_button("Photos…", "camera", "ghost", "Find deleted photos and videos")
        self.btn_photos.clicked.connect(lambda: self.action.emit("photos", self.path))
        top.addWidget(self.btn_photos, 0, Qt.AlignVCenter)
        self.btn_main = icon_button("Recover files…", "trash_restore", "primary", "Find deleted and lost files")
        self.btn_main.clicked.connect(lambda: self.action.emit(self._main, self.path))
        self._main = "recover"
        top.addWidget(self.btn_main, 0, Qt.AlignVCenter)
        self.btn_more = more_button([
            ("Recover files…", "trash_restore", lambda: self.action.emit("recover", self.path)),
            ("Recover photos and videos…", "camera", lambda: self.action.emit("photos", self.path)),
            ("Find lost partitions…", "partition", lambda: self.action.emit("partitions", self.path)),
            ("Check and repair…", "wrench", lambda: self.action.emit("repair", self.path)),
            ("Create a disk image…", "copy", lambda: self.action.emit("image", self.path)),
            None,
            ("View sectors…", "hex", lambda: self.action.emit("hex", self.path)),
            ("Read again", "refresh", lambda: self.action.emit("refresh", self.path)),
        ], "Recover, find partitions, repair, image, view sectors")
        top.addWidget(self.btn_more, 0, Qt.AlignVCenter)
        lay.addLayout(top)
        self.map = DiskMap(height=58)
        self.map.empty_text = "No partitions: a deep scan or a partition search finds lost ones"
        lay.addWidget(self.map)
        self.note = QLabel()
        self.note.setObjectName("Faint")
        self.note.setWordWrap(True)
        self.note.hide()
        lay.addWidget(self.note)
        self.toggle = QToolButton()
        self.toggle.setObjectName("Disclosure")
        self.toggle.setCheckable(True)
        self.toggle.setCursor(Qt.PointingHandCursor)
        self.toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self._tg = bind_icon(self.toggle, "chevron_right", "text_muted", 14)
        self.toggle.toggled.connect(self._fold)
        self.details = QWidget()
        self.parts = QGridLayout(self.details)
        self.parts.setContentsMargins(0, 2, 0, 0)
        self.parts.setHorizontalSpacing(16)
        self.parts.setVerticalSpacing(5)
        self.details.hide()
        lay.addWidget(self.toggle, 0, Qt.AlignLeft)
        lay.addWidget(self.details)
        self.update_disk(disk)

    def _fold(self, on: bool) -> None:
        self.details.setVisible(on)
        self._tg.set_name("chevron_down" if on else "chevron_right")

    def update_disk(self, disk: dict, detail: dict | None = None) -> None:
        d = dict(disk)
        if detail:
            d.update({k: v for k, v in detail.items() if v is not None})
        self.name.setText(d.get("display_name") or d["path"])
        self.name.setToolTip(f"{d.get('model', '')}\n{d.get('serial', '')}\n{d.get('path')}")
        self.sub.setText(disk_subtitle(d) + (f" · serial {d['serial']}" if d.get("serial") else ""))
        clear_layout(self.badges)
        hb = health_badge(d.get("health"))
        if hb is not None:
            self.badges.addWidget(hb)
        if d.get("system"):
            b = badge("SYSTEM DISK", "BadgeInfo")
            b.setToolTip("The running system is on this disk. Recovering from it works, but save the recovered "
                         "files on another disk — and the longer the system runs, the more deleted files it "
                         "overwrites.")
            self.badges.addWidget(b)
        table = d.get("table") or {}
        if table.get("problems"):
            b = badge("TABLE DAMAGED", "BadgeWarn")
            b.setToolTip("\n".join(table["problems"]))
            self.badges.addWidget(b)
        self.map.set_disk(d)
        failing = (d.get("health") or {}).get("state") == "failing"
        self._main = "image" if failing else "recover"
        self.btn_main.setText("Image it first…" if failing else "Recover files…")
        self.btn_main.setToolTip("Copy this failing disk to an image file, then recover from the image" if failing
                                 else "Find deleted and lost files")
        self.btn_main._binder.set_name("copy" if failing else "trash_restore")
        self.btn_photos.setVisible(d.get("kind") in ("sd", "usb-flash", "usb-disk", "emmc") and not failing)
        clear_layout(self.parts)
        parts = [p for p in d.get("partitions") or [] if not p.get("extended")]
        self.toggle.setVisible(bool(parts))
        self.toggle.setText(f"{len(parts)} partition{'s' if len(parts) != 1 else ''}")
        heads = ["", "Partition", "Filesystem", "Size", "Used", "Mounted", ""]
        for c, h in enumerate(heads):
            lab = QLabel(h)
            lab.setObjectName("Faint")
            lab.setFont(scaled_font(lab, 0.8, bold=True))
            if parts:
                self.parts.addWidget(lab, 0, c)
        for r, p in enumerate(parts, start=1):
            sw = QLabel()
            sw.setFixedSize(10, 10)
            sw.setStyleSheet(f"background: {fs_color(p.get('fstype'))}; border-radius: 3px;")
            self.parts.addWidget(sw, r, 0, Qt.AlignVCenter)
            title = f"{p['number']}"
            if p.get("label"):
                title += f"  {p['label']}"
            elif p.get("role") not in (None, "data"):
                title += f"  {ROLE_NAMES.get(p['role'], p['role'])}"
            self.parts.addWidget(QLabel(title), r, 1)
            self.parts.addWidget(QLabel(fs_name(p.get("fstype")) if p.get("fstype") else "—"), r, 2)
            self.parts.addWidget(QLabel(fmt_bytes(p["size"])), r, 3)
            used = p.get("fsused")
            ut = fmt_bytes(used) if used is not None and p.get("fstype") not in ("swap", "") else "—"
            self.parts.addWidget(QLabel(ut), r, 4)
            mp = QLabel(", ".join(p.get("mountpoints") or []))
            mp.setObjectName("Muted")
            self.parts.addWidget(mp, r, 5)
            row = QHBoxLayout()
            row.setSpacing(4)
            if p.get("fstype") in ENCRYPTED:
                b = icon_button("Unlock…", "unlock", "ghost", "Open it read-only with its passphrase")
                b.clicked.connect(lambda _c=False, n=p["number"]: self.action.emit("unlock", {"path": self.path,
                                                                                             "number": n}))
                row.addWidget(b)
            b = icon_button("Scan", "scan", "ghost", "Find deleted files on this partition only")
            b.clicked.connect(lambda _c=False, n=p["number"]: self.action.emit("recover_part", {"path": self.path,
                                                                                                "number": n}))
            row.addWidget(b)
            holder = QWidget()
            holder.setLayout(row)
            self.parts.addWidget(holder, r, 6, Qt.AlignRight)
        self.parts.setColumnStretch(5, 1)
        notes = []
        if failing:
            notes.append("<b>This disk is failing</b> (" + ", ".join(d["health"].get("reasons") or []) + "). Copy it "
                         "to an image file first and recover from the image: every extra read can make it worse.")
        elif d.get("system"):
            notes.append("The running system is on this disk: deleted files get overwritten as it runs. Recover "
                         "soon, and save to another disk.")
        if table.get("problems") and not failing:
            notes.append("Its partition table looks damaged: “Find lost partitions” in the ⋯ menu searches for the "
                         "filesystems on it.")
        self.note.setText(" ".join(notes))
        set_object_name(self.note, "BannerBad" if failing else "BannerWarn" if notes else "Faint")
        self.note.setVisible(bool(notes))


class DrivesPage(QWidget):
    action = Signal(str, object)

    def __init__(self, bridge, parent=None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.bridge = bridge
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        head = QHBoxLayout()
        head.setContentsMargins(4, 0, 6, 0)
        self.summary = QLabel("")
        self.summary.setObjectName("Muted")
        head.addWidget(self.summary, 1)
        self.btn_scans = icon_button("Saved scans…", "folder_search", "ghost", "Open an earlier scan without scanning "
                                                                               "again")
        self.btn_scans.clicked.connect(lambda: self.action.emit("open_scan", ""))
        self.btn_open = icon_button("Open disk image…", "file_image", "ghost", "Use a disk image (dd, ddrescue, a VM's "
                                                                                "raw disk) as a source")
        self.btn_open.clicked.connect(lambda: self.action.emit("open_image", ""))
        self.btn_raid = icon_button("Virtual RAID…", "raid", "ghost", "Put a RAID's members back together")
        self.btn_raid.clicked.connect(lambda: self.action.emit("raid", ""))
        self.btn_refresh = icon_button("Refresh", "refresh", "ghost", "Look for disks again (F5)")
        self.btn_refresh.clicked.connect(lambda: self.action.emit("refresh_all", ""))
        for b in (self.btn_scans, self.btn_open, self.btn_raid, self.btn_refresh):
            head.addWidget(b)
        lay.addLayout(head)
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.NoFrame)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        holder = QWidget()
        self.list = QVBoxLayout(holder)
        self.list.setContentsMargins(0, 0, 6, 0)
        self.list.setSpacing(10)
        self.empty = QLabel("Looking for disks…")
        self.empty.setObjectName("Empty")
        self.empty.setAlignment(Qt.AlignCenter)
        self.list.addWidget(self.empty)
        self.list.addStretch(1)
        area.setWidget(holder)
        lay.addWidget(area, 1)
        self.cards: dict[str, DriveCard] = {}

    def set_disks(self, disks: list[dict]) -> None:
        keep = {d["path"] for d in disks}
        for p in list(self.cards):
            if p not in keep:
                self.cards.pop(p).deleteLater()
        for i, d in enumerate(disks):
            card = self.cards.get(d["path"])
            if card is None:
                card = DriveCard(d)
                card.action.connect(self.action.emit)
                self.cards[d["path"]] = card
            card.update_disk(d, self.bridge.details.get(d["path"]))
            self.list.insertWidget(i, card)
        self.empty.setVisible(not disks)
        if not disks:
            self.empty.setText("No disks found")
        self._summary()

    def set_detail(self, d: dict) -> None:
        card = self.cards.get(d["path"])
        base = next((x for x in self.bridge.disks if x["path"] == d["path"]), d)
        if card is not None:
            card.update_disk(base, d)
        self._summary()

    def _summary(self) -> None:
        disks = [self.bridge.details.get(d["path"], d) for d in self.bridge.disks]
        failing = [d for d in disks if (d.get("health") or {}).get("state") == "failing"]
        text = "Pick the disk, card or stick the files were on. Nothing is written to it."
        if failing:
            names = ", ".join(d.get("display_name") or d["path"] for d in failing)
            text = f"<b>{names}</b> {'is' if len(failing) == 1 else 'are'} failing: image it first, then recover " \
                   "from the image."
        self.summary.setText(text)
