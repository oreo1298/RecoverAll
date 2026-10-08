"""The Imaging page: copy a disk into an image file (the first thing to do with a failing disk), and put a
RAID's members back together as a virtual RAID — both then work like any other disk."""

from __future__ import annotations

import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QScrollArea,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.util import fmt_bytes, fmt_duration, parse_size
from .cellmap import image_legend, image_map
from .common import OperationPage, SourcePicker, hint
from .widgets import Card, SegmentedControl, StatTile, clear_layout, icon_button, scaled_font

CHUNKS = ["4K", "8K", "16K", "32K", "64K", "128K", "256K", "512K", "1M"]
LEVELS = [("0", "RAID 0 (stripe)"), ("1", "RAID 1 (mirror)"), ("5", "RAID 5 (parity)"), ("6", "RAID 6 (double parity)"),
          ("10", "RAID 10"), ("jbod", "JBOD / span")]
LAYOUTS = ["left-symmetric", "left-asymmetric", "right-symmetric", "right-asymmetric"]


class ImageProgress(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        card = Card("Disk map", "map")
        self.map = image_map()
        card.add(self.map, 1)
        card.add(image_legend())
        tiles = QHBoxLayout()
        self.t_bad = StatTile("Unreadable", "error")
        self.t_areas = StatTile("Bad areas", "warning")
        self.t_left = StatTile("Still to try", "clock")
        self.t_since = StatTile("Since the last good read", "activity")
        for t in (self.t_bad, self.t_areas, self.t_left, self.t_since):
            tiles.addWidget(t, 1)
        card.add_layout(tiles)
        lay.addWidget(card)

    def reset(self) -> None:
        self.map.clear()
        for t in (self.t_bad, self.t_areas, self.t_left, self.t_since):
            t.set("—")

    def update_job(self, job: dict) -> None:
        im = (job.get("data") or {}).get("imaging") or {}
        if not im:
            return
        self.map.set_map(im.get("cells") or "", int(im.get("size") or 0))
        self.t_bad.set(fmt_bytes(im.get("bad") or 0))
        self.t_areas.set(str(im.get("bad_areas") or 0), sub=f"{im.get('errors') or 0} read errors")
        left = (im.get("nontried") or 0) + (im.get("nontrimmed") or 0) + (im.get("nonscraped") or 0)
        self.t_left.set(fmt_bytes(left))
        since = im.get("since_good_read")
        self.t_since.set(fmt_duration(since) if since is not None else "—",
                         sub="the disk may have stopped answering" if since and since > 60 else "")


class ImagingPage(OperationPage):
    use_source = Signal(str)          # an image or .rallraid to open as a source and scan

    def __init__(self, bridge, gs, parent=None):
        self.progress_view = ImageProgress()
        super().__init__(bridge, self.progress_view, parent)
        self.gs = gs
        self.dest = ""
        self.job_kind = ""
        self._build()

    def _build(self) -> None:
        area = QScrollArea(self.setup)
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.NoFrame)
        outer = QVBoxLayout(self.setup)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(area)
        body = QWidget()
        area.setWidget(body)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(0, 0, 6, 0)
        lay.setSpacing(12)
        self.tabs = SegmentedControl()
        self.tabs.add("Disk image", "image", "Copy a disk or partition into an image file")
        self.tabs.add("Virtual RAID", "raid", "Assemble a RAID from its member disks or their images")
        self.tabs.set_value("image")
        row = QHBoxLayout()
        row.addWidget(self.tabs)
        row.addStretch(1)
        lay.addLayout(row)
        self.stack = QStackedWidget()
        self.stack.addWidget(self._image_view())
        self.stack.addWidget(self._raid_view())
        self.tabs.changed.connect(lambda v: self.stack.setCurrentIndex(0 if v == "image" else 1))
        lay.addWidget(self.stack)
        lay.addStretch(1)

    # ------------------------------------------------------------------ disk image
    def _image_view(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)
        why = QLabel("<b>Image a failing disk before anything else reads it.</b> The copy reads the easy parts first "
                     "and skips around damaged areas, then comes back for them sector by sector; you scan and "
                     "recover from the image afterwards, as often as you like, without touching the disk again.")
        why.setWordWrap(True)
        why.setObjectName("Banner")
        lay.addWidget(why)
        c = Card("Copy", "copy")
        self.source = SourcePicker(self.bridge)
        self.source.changed.connect(self._suggest)
        c.add(self.source)
        drow = QHBoxLayout()
        drow.addWidget(QLabel("Save as"))
        self.dest_edit = QLineEdit()
        self.dest_edit.setPlaceholderText("/run/media/you/BigDisk/disk.img (on another disk)")
        b = icon_button("", "open", "", "Choose where")
        b.clicked.connect(self._browse)
        drow.addWidget(self.dest_edit, 1)
        drow.addWidget(b)
        c.add_layout(drow)
        orow = QHBoxLayout()
        orow.addWidget(QLabel("Engine"))
        self.engine = QComboBox()
        self.engine.addItem("Automatic (GNU ddrescue when installed)", "auto")
        self.engine.addItem("GNU ddrescue", "ddrescue")
        self.engine.addItem("RecoverAll's own imager", "builtin")
        orow.addWidget(self.engine)
        orow.addSpacing(16)
        orow.addWidget(QLabel("Retries of bad sectors"))
        self.retries = QSpinBox()
        self.retries.setRange(0, 10)
        self.retries.setValue(1)
        orow.addWidget(self.retries)
        orow.addStretch(1)
        c.add_layout(orow)
        self.space = QLabel("")
        self.space.setObjectName("Muted")
        self.space.setWordWrap(True)
        c.add(self.space)
        c.add(hint("A mapfile is saved next to the image (.map): stop any time, and starting again with the same "
                   "image continues where it stopped — also with more retries later."))
        brow = QHBoxLayout()
        brow.addStretch(1)
        self.btn_start = icon_button("Create the image", "play", "primary")
        self.btn_start.setMinimumHeight(38)
        self.btn_start.clicked.connect(self.start_image)
        brow.addWidget(self.btn_start)
        c.add_layout(brow)
        lay.addWidget(c)
        return w

    def set_disks(self, disks: list[dict]) -> None:
        self.source.set_disks(disks)
        self._disks = disks

    def set_detail(self, _d: dict) -> None:
        pass

    def start_with(self, path: str) -> None:
        if self.running():
            return
        self.outer.setCurrentIndex(0)
        self.tabs.set_value("image")
        self.stack.setCurrentIndex(0)
        self.source.select(path)

    def _suggest(self) -> None:
        d = self.source.current_disk()
        p = self.source.current_part()
        if not d:
            return
        size = (p or d).get("size") or 0
        self.space.setText(f"The image needs up to {fmt_bytes(size)} (less where the disk holds zeros: the image is "
                           "sparse).")
        if not self.dest_edit.text().strip() or self.dest_edit.text().endswith(".img"):
            base = self.gs.image_folder or os.path.expanduser("~")
            name = (d.get("model") or d.get("name") or "disk").replace(" ", "_")
            if p:
                name += f"-part{p.get('number')}"
            self.dest_edit.setText(os.path.join(base, f"{name}.img"))

    def _browse(self) -> None:
        p, _f = QFileDialog.getSaveFileName(self, "Save the image as", self.dest_edit.text(), "Disk images (*.img)")
        if p:
            self.dest_edit.setText(p)
            self.gs.image_folder = os.path.dirname(p)
            self.gs.save()

    def start_image(self) -> None:
        spec = self.source.spec()
        dest = self.dest_edit.text().strip()
        if not spec or not dest:
            self.bridge.message.emit("Choose the disk and where to save the image", "warning")
            return
        self.dest = dest

        def go():
            self.bridge.call("start_image", done=self._started, source=spec, dest=dest,
                             options={"engine": self.engine.currentData(), "retries": self.retries.value()})
        d = self.source.current_disk() or {}
        if self.bridge.privileged or d.get("is_image"):
            go()
        else:
            self.bridge.ensure_access(go)

    def _started(self, job: dict) -> None:
        self.job_kind = "image"
        self.progress_view.reset()
        self.jobview.t_done.caption.setText("Copied")
        self.run_job(job)

    def job_data(self, job: dict) -> None:
        if self.job_kind == "image":
            self.progress_view.update_job(job)

    def finish_run(self) -> None:
        job = self.jobview.job or {}
        self.job_id = None
        self.outer.setCurrentIndex(0)
        if self.job_kind == "image" and job.get("state") == "done" and self.dest:
            self.bridge.message.emit("Image ready: it's on the Drives page now, scan it from there", "success")
            self.use_source.emit(self.dest)
        elif self.job_kind == "raid" and job.get("state") == "done":
            self.bridge.call("job", done=self._detected, job_id=job["id"])

    # ------------------------------------------------------------------ virtual RAID
    def _raid_view(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)
        intro = QLabel("A NAS or a RAID controller died, but its disks are fine? Connect the disks (or images of "
                       "them), add them here in order, and RecoverAll reads them as the array they were — RAID 5 and "
                       "6 even with one disk missing.")
        intro.setWordWrap(True)
        intro.setObjectName("Banner")
        lay.addWidget(intro)
        c = Card("Members", "raid")
        self.members = QTableWidget(0, 3)
        self.members.setHorizontalHeaderLabels(["#", "Disk or image", "Data starts at"])
        self.members.verticalHeader().hide()
        self.members.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.members.setShowGrid(False)
        self.members.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.members.setMinimumHeight(170)
        self.members.itemChanged.connect(lambda _i: self._describe())
        c.add(self.members)
        row = QHBoxLayout()
        self.btn_add = icon_button("Add disk", "plus", "ghost")
        self.btn_add.clicked.connect(self._add_disk_menu)
        b2 = icon_button("Add image file…", "file_image", "ghost")
        b2.clicked.connect(self._add_image)
        b3 = icon_button("Add a missing member", "minus", "ghost", "A disk that's dead or lost (RAID 5/6: one may be "
                                                                   "missing)")
        b3.clicked.connect(lambda: self._add_member(None))
        up = icon_button("", "up", "ghost", "Move up")
        up.clicked.connect(lambda: self._move(-1))
        dn = icon_button("", "down", "ghost", "Move down")
        dn.clicked.connect(lambda: self._move(1))
        rm = icon_button("", "trash", "ghost", "Remove")
        rm.clicked.connect(self._remove)
        for x in (self.btn_add, b2, b3):
            row.addWidget(x)
        row.addStretch(1)
        for x in (up, dn, rm):
            row.addWidget(x)
        c.add_layout(row)
        lay.addWidget(c)
        c2 = Card("Layout", "sliders")
        grid = QHBoxLayout()
        grid.addWidget(QLabel("Level"))
        self.level = QComboBox()
        for v, t in LEVELS:
            self.level.addItem(t, v)
        self.level.setCurrentIndex(2)
        grid.addWidget(self.level)
        grid.addSpacing(12)
        grid.addWidget(QLabel("Chunk"))
        self.chunk = QComboBox()
        for ch in CHUNKS:
            self.chunk.addItem(ch, ch)
        self.chunk.setCurrentIndex(4)
        grid.addWidget(self.chunk)
        grid.addSpacing(12)
        grid.addWidget(QLabel("Parity"))
        self.layout_ = QComboBox()
        for ly in LAYOUTS:
            self.layout_.addItem(ly, ly)
        grid.addWidget(self.layout_)
        grid.addSpacing(12)
        grid.addWidget(QLabel("Name"))
        self.name = QLineEdit("NAS")
        grid.addWidget(self.name, 1)
        c2.add_layout(grid)
        for cb in (self.level, self.chunk, self.layout_):
            cb.currentIndexChanged.connect(lambda _i: self._describe())
        self.desc = QLabel("")
        self.desc.setFont(scaled_font(self.desc, 1.02, bold=True))
        c2.add(self.desc)
        self.candidates = QVBoxLayout()
        c2.add_layout(self.candidates)
        brow = QHBoxLayout()
        self.btn_detect = icon_button("Find the layout", "search", "ghost", "Read Linux RAID superblocks, or try the "
                                                                            "usual layouts and keep what makes sense")
        self.btn_detect.clicked.connect(self._detect)
        brow.addWidget(self.btn_detect)
        brow.addStretch(1)
        self.btn_save = icon_button("Save and use", "check", "primary")
        self.btn_save.clicked.connect(self._save_raid)
        brow.addWidget(self.btn_save)
        c2.add_layout(brow)
        lay.addWidget(c2)
        return w

    def _add_disk_menu(self) -> None:
        m = QMenu(self)
        for d in getattr(self, "_disks", []):
            m.addAction(f"{d.get('display_name')} · {d.get('capacity_text')} · {d['path']}",
                        lambda p=d["path"]: self._add_member(p))
        m.exec(self.btn_add.mapToGlobal(self.btn_add.rect().bottomLeft()))

    def _add_image(self) -> None:
        paths, _f = QFileDialog.getOpenFileNames(self, "Member images", os.path.expanduser("~"),
                                                 "Disk images (*.img *.dd *.raw *.bin *.001 *.vhd *.vhdx *.vdi *.vmdk "
                                                 "*.qcow2 *.qcow *.E01 *.e01);;All files (*)")
        for p in paths:
            self._add_member(p)

    def _add_member(self, path: str | None, offset: int = 0) -> None:
        self.members.blockSignals(True)
        r = self.members.rowCount()
        self.members.insertRow(r)
        n = QTableWidgetItem(str(r + 1))
        n.setFlags(Qt.ItemIsEnabled)
        self.members.setItem(r, 0, n)
        it = QTableWidgetItem(path or "(missing)")
        it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        it.setData(Qt.UserRole, path)
        self.members.setItem(r, 1, it)
        self.members.setItem(r, 2, QTableWidgetItem(fmt_bytes(offset) if offset else "0"))
        self.members.blockSignals(False)
        self._describe()

    def _rows(self) -> list[dict | None]:
        out = []
        for r in range(self.members.rowCount()):
            path = self.members.item(r, 1).data(Qt.UserRole)
            if not path:
                out.append(None)
                continue
            text = (self.members.item(r, 2).text() or "0").replace(" ", "")
            try:
                off = parse_size(text.replace("kB", "K").replace("MB", "M").replace("GB", "G")) if text else 0
            except ValueError:
                off = 0
            out.append({"path": path, "offset": off})
        return out

    def _move(self, delta: int) -> None:
        r = self.members.currentRow()
        rows = self._rows()
        j = r + delta
        if r < 0 or not 0 <= j < len(rows):
            return
        rows[r], rows[j] = rows[j], rows[r]
        self._set_rows(rows)
        self.members.selectRow(j)

    def _remove(self) -> None:
        r = self.members.currentRow()
        if r >= 0:
            rows = self._rows()
            rows.pop(r)
            self._set_rows(rows)

    def _set_rows(self, rows: list) -> None:
        self.members.setRowCount(0)
        for m in rows:
            self._add_member(m["path"] if m else None, m.get("offset", 0) if m else 0)

    def definition(self) -> dict:
        return {"type": "raid", "name": self.name.text().strip() or "Virtual RAID", "level": self.level.currentData(),
                "chunk": parse_size(self.chunk.currentData()), "layout": self.layout_.currentData(),
                "members": self._rows()}

    def _describe(self) -> None:
        d = self.definition()
        self.layout_.setEnabled(d["level"] in ("5", "6"))
        self.chunk.setEnabled(d["level"] not in ("1", "jbod"))
        if not any(d["members"]):
            self.desc.setText("Add the members in their original order (slot 1 first).")
            return
        self.bridge.call("raid_describe", done=lambda r: self.desc.setText(f"{r['text']} → {r['size_text']}"),
                         error=lambda e: self.desc.setText(str(e)), definition=d)

    def _detect(self) -> None:
        rows = self._rows()
        paths = [m["path"] for m in rows if m]
        missing = len(rows) - len(paths)
        if len(paths) < 2:
            self.bridge.message.emit("Add at least two members first", "warning")
            return

        def md(defn):
            if defn:
                self._apply(defn)
                self.bridge.message.emit("Linux software RAID found: its layout is filled in", "success")
                return

            def started(job):
                self.job_kind = "raid"
                self.progress_view.reset()
                self.run_job(job)
            self.bridge.call("start_raid_detect", done=started, paths=paths, missing=missing)
        self.bridge.ensure_access(lambda: self.bridge.call("raid_from_md", done=md, paths=paths))

    def _detected(self, job: dict) -> None:
        cands = (job.get("result") or {}).get("candidates") or []
        clear_layout(self.candidates)
        if not cands:
            lab = QLabel("No layout made sense: enter the level, chunk size and order yourself (the NAS's settings or "
                         "manual help).")
            lab.setWordWrap(True)
            lab.setObjectName("BannerWarn")
            self.candidates.addWidget(lab)
            return
        for cnd in cands[:4]:
            row = QHBoxLayout()
            order = " → ".join(os.path.basename(m["path"]) if m else "(missing)" for m in cnd["members"])
            row.addWidget(QLabel(f"RAID {cnd['level']} · {cnd['chunk'] // 1024} KiB · {cnd.get('layout') or ''} · "
                                 f"{order}  (score {cnd['score']})"), 1)
            b = icon_button("Use", "check", "ghost")
            b.clicked.connect(lambda _c=False, c=cnd: self._apply(c))
            row.addWidget(b)
            self.candidates.addLayout(row)

    def _apply(self, d: dict) -> None:
        self._set_rows(d.get("members") or [])
        i = self.level.findData(str(d.get("level")))
        if i >= 0:
            self.level.setCurrentIndex(i)
        ch = int(d.get("chunk") or 65536)
        label = f"{ch // 1048576}M" if ch >= 1048576 else f"{ch // 1024}K"
        i = self.chunk.findData(label)
        if i >= 0:
            self.chunk.setCurrentIndex(i)
        i = self.layout_.findData(d.get("layout") or "left-symmetric")
        if i >= 0:
            self.layout_.setCurrentIndex(i)
        if d.get("name"):
            self.name.setText(d["name"])
        self._describe()

    def _save_raid(self) -> None:
        d = self.definition()
        if sum(1 for m in d["members"] if m) < 1:
            self.bridge.message.emit("Add the members first", "warning")
            return

        def saved(path):
            self.bridge.message.emit(f"Virtual RAID saved: {path}", "success")
            self.use_source.emit(path)
        self.bridge.call("save_raid", done=saved, definition=d)
