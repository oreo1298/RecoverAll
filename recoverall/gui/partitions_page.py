"""The Partitions page (TestDisk's job): find the filesystems on a disk whose partitions were deleted or whose
partition table is damaged, check each one by its files, and write them back as a new partition table —
or just recover the files from them, which never writes to the disk."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.fs import fs_name
from ..core.util import fmt_bytes, fmt_when
from .common import ChoiceCard, ChoiceGroup, OperationPage, SourcePicker, hint
from .dialogs import confirm_change
from .diskmap import DiskMap
from .widgets import Card, SegmentedControl, badge, clear_layout, icon_button, scaled_font

STATUS = {"current": ("IN THE TABLE", "BadgeOk"), "deleted": ("DELETED", "BadgeWarn"),
          "damaged": ("DAMAGED", "BadgeWarn"), "overlaps": ("OVERLAPS", "BadgeIdle")}


class PartitionsPage(OperationPage):
    scan_region = Signal(str, int, int)        # path, offset, size: recover files from a found partition

    def __init__(self, bridge, gs, parent=None):
        super().__init__(bridge, None, parent)
        self.gs = gs
        self.result: dict = {}
        self.path = ""
        self._build_setup()
        self._build_results()

    # ------------------------------------------------------------------ setup
    def _build_setup(self) -> None:
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
        c1 = Card("Disk", "hdd")
        self.source = SourcePicker(self.bridge, partitions=False)
        self.source.changed.connect(self._source_changed)
        c1.add(self.source)
        self.map = DiskMap(height=54)
        self.map.empty_text = "No partitions in the table"
        c1.add(self.map)
        self.table_text = QLabel()
        self.table_text.setWordWrap(True)
        self.table_text.setObjectName("Muted")
        c1.add(self.table_text)
        lay.addWidget(c1)
        c2 = Card("Search", "search")
        self.mode = ChoiceGroup()
        self.mode.add(ChoiceCard("quick", "bolt", "Quick search",
                                 "Looks where partitions usually start (every MiB, every track) and follows one "
                                 "filesystem to the next. Finds deleted partitions in a minute or two."))
        self.mode.add(ChoiceCard("deep", "folder_search", "Deep search",
                                 "Reads every sector: also finds filesystems whose first sector is damaged, from "
                                 "their backup boot sectors and superblocks, and NTFS from its MFT."))
        self.mode.set_value("quick")
        c2.add(self.mode)
        lay.addWidget(c2)
        row = QHBoxLayout()
        row.addWidget(hint("Searching only reads the disk. Nothing is written until you choose to write a new "
                           "partition table — and the old one is backed up first.", faint=False), 1)
        self.btn_start = icon_button("Search", "search", "primary")
        self.btn_start.setMinimumHeight(38)
        self.btn_start.clicked.connect(self.start)
        row.addWidget(self.btn_start)
        lay.addLayout(row)
        c3 = Card("Undo", "undo")
        self.backups = QVBoxLayout()
        self.backups.setSpacing(6)
        c3.add_layout(self.backups)
        self.no_backups = hint("Every sector RecoverAll overwrites (partition tables, boot sectors) is saved first; "
                               "the copies appear here and can be written back.")
        c3.add(self.no_backups)
        lay.addWidget(c3)
        lay.addStretch(1)

    def set_disks(self, disks: list[dict]) -> None:
        self.source.set_disks([d for d in disks if not d.get("is_volume")])

    def set_detail(self, _d: dict) -> None:
        self._source_changed()

    def shown(self) -> None:
        self.bridge.call("list_backups", done=self._got_backups, error=lambda e: None)

    def start_with(self, path: str) -> None:
        if self.running():
            return
        self.outer.setCurrentIndex(0)
        self.source.select(path)

    def _source_changed(self) -> None:
        d = self.source.current_disk()
        self.map.set_disk(d)
        if not d:
            self.table_text.setText("")
            return
        t = d.get("table") or {}
        kind = {"gpt": "GPT", "dos": "MBR", "apm": "Apple"}.get(d.get("pttype") or t.get("type") or "",
                                                              "No partition table")
        n = len([p for p in d.get("partitions") or [] if not p.get("extended")])
        text = f"{kind} · {n} partition{'s' if n != 1 else ''} · {fmt_bytes(d.get('size'))}"
        if t.get("problems"):
            text += "<br><span style='color:#f5b945'>" + "<br>".join(t["problems"]) + "</span>"
        self.table_text.setText(text)

    def _got_backups(self, items: list) -> None:
        clear_layout(self.backups)
        self.no_backups.setVisible(not items)
        for b in items or []:
            row = QHBoxLayout()
            lab = QLabel(f"<b>{b.get('device')}</b> · {b.get('label') or 'saved sectors'} · "
                         f"{fmt_when(b.get('created'))}")
            row.addWidget(lab, 1)
            btn = icon_button("Undo…", "undo", "ghost", "Write these sectors back")
            btn.clicked.connect(lambda _c=False, b=b: self._undo(b))
            row.addWidget(btn)
            self.backups.addLayout(row)

    def _undo(self, b: dict) -> None:
        disk = next((d for d in self.bridge.disks if d["path"] == b.get("device")), {"path": b.get("device"),
                                                                                    "is_image": True})
        typed = confirm_change(self, disk, "Write the saved sectors back?", "Undo",
                               "The partition table and boot sectors saved before the change are written back; "
                               "anything changed on the disk since then in those sectors is lost.")
        if typed is None:
            return
        self.bridge.call("undo_backup", success="The saved sectors were written back",
                         done=lambda _r: self.bridge.fetch_disks(), path=b["path"], confirm=typed)

    def start(self) -> None:
        d = self.source.current_disk()
        if not d:
            return
        self.path = d["path"]
        mode = self.mode.value()

        def go():
            self.bridge.call("start_partition_search", done=self.run_job, source=self.path, mode=mode)
        if self.bridge.privileged or d.get("is_image"):
            go()
        else:
            self.bridge.ensure_access(go)

    def finish_run(self) -> None:
        job = self.jobview.job or {}
        self.job_id = None
        if job.get("kind") == "partitions" and job.get("state") == "done":
            self.bridge.call("job", done=self._got_result, job_id=job["id"])
        else:
            self.outer.setCurrentIndex(0)

    # ------------------------------------------------------------------ results
    def _build_results(self) -> None:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        top = Card("What was found", "partition")
        self.r_title = QLabel("")
        self.r_title.setFont(scaled_font(self.r_title, 1.15, bold=True))
        top.add(self.r_title)
        self.r_map = DiskMap(height=58)
        self.r_map.empty_text = "No filesystems found"
        top.add(self.r_map)
        lay.addWidget(top)
        split = QSplitter(Qt.Horizontal)
        tc = Card("Filesystems", "list")
        self.tbl = QTableWidget(0, 7)
        self.tbl.setHorizontalHeaderLabels(["Use", "Filesystem", "Label", "Starts at", "Size", "State", "Found by"])
        self.tbl.verticalHeader().hide()
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl.setShowGrid(False)
        self.tbl.horizontalHeader().setStretchLastSection(True)
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(5, QHeaderView.Fixed)
        self.tbl.setColumnWidth(5, 132)
        self.tbl.itemChanged.connect(lambda _i: self._update_map())
        self.tbl.currentCellChanged.connect(lambda r, *_a: self._show(r))
        tc.add(self.tbl, 1)
        split.addWidget(tc)
        side = Card("Files on it", "folder")
        self.s_title = QLabel("Choose a filesystem")
        self.s_title.setFont(scaled_font(self.s_title, 1.05, bold=True))
        self.s_title.setWordWrap(True)
        side.add(self.s_title)
        self.s_files = QLabel("")
        self.s_files.setWordWrap(True)
        self.s_files.setTextFormat(Qt.RichText)
        self.s_files.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        side.add(self.s_files, 1)
        self.btn_browse = icon_button("Recover files from it…", "trash_restore", "primary",
                                      "Scan just this filesystem and recover its files — nothing is written to the disk")
        self.btn_browse.clicked.connect(self._browse)
        side.add(self.btn_browse)
        split.addWidget(side)
        split.setSizes([820, 380])
        lay.addWidget(split, 1)
        bottom = QFrame()
        bottom.setObjectName("Card")
        bl = QHBoxLayout(bottom)
        bl.setContentsMargins(14, 8, 14, 8)
        b = icon_button("Search again", "search", "ghost")
        b.clicked.connect(lambda: self.outer.setCurrentIndex(0))
        bl.addWidget(b)
        bl.addStretch(1)
        bl.addWidget(QLabel("New table:"))
        self.ttype = SegmentedControl()
        self.ttype.add("GPT", "gpt", "Modern disks, UEFI, more than 4 partitions, disks over 2 TB")
        self.ttype.add("MBR", "dos", "Older PCs (BIOS), cards and sticks")
        bl.addWidget(self.ttype)
        self.btn_write = icon_button("Write partition table…", "save", "danger")
        self.btn_write.clicked.connect(self._write)
        bl.addWidget(self.btn_write)
        lay.addWidget(bottom)
        self.outer.addWidget(page)

    def _got_result(self, job: dict) -> None:
        self.result = job.get("result") or {}
        cands = self.result.get("candidates") or []
        found = [c for c in cands if c.get("status") != "current"]
        self.r_title.setText(f"{len(cands)} filesystem{'s' if len(cands) != 1 else ''} found"
                             + (f" — {len(found)} not in the partition table" if found else
                                " — all of them are in the partition table"))
        self.ttype.set_value(self.result.get("table_type") or "gpt")
        self.tbl.blockSignals(True)
        self.tbl.setRowCount(0)
        for c in cands:
            r = self.tbl.rowCount()
            self.tbl.insertRow(r)
            use = QTableWidgetItem()
            use.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            use.setCheckState(Qt.Checked if c.get("status") in ("current", "deleted", "damaged") else Qt.Unchecked)
            use.setData(Qt.UserRole, c)
            self.tbl.setItem(r, 0, use)
            self.tbl.setItem(r, 1, QTableWidgetItem(fs_name(c.get("fstype"))))
            self.tbl.setItem(r, 2, QTableWidgetItem(c.get("label") or ""))
            self.tbl.setItem(r, 3, QTableWidgetItem(fmt_bytes(c.get("offset"))))
            self.tbl.setItem(r, 4, QTableWidgetItem(fmt_bytes(c.get("size"))))
            text, kind = STATUS.get(c.get("status") or "", (str(c.get("status") or "").upper(), "BadgeIdle"))
            holder = QWidget()
            hl = QHBoxLayout(holder)
            hl.setContentsMargins(4, 0, 4, 0)
            hl.addWidget(badge(text, kind))
            hl.addStretch(1)
            self.tbl.setCellWidget(r, 5, holder)
            ev = QTableWidgetItem(c.get("evidence") or "")
            ev.setToolTip(c.get("evidence") or "")
            self.tbl.setItem(r, 6, ev)
        self.tbl.blockSignals(False)
        self.outer.setCurrentIndex(2)
        self._update_map()
        if cands:
            self.tbl.selectRow(0)
            self._show(0)

    def _checked(self) -> list[dict]:
        out = []
        for r in range(self.tbl.rowCount()):
            it = self.tbl.item(r, 0)
            if it and it.checkState() == Qt.Checked:
                out.append(it.data(Qt.UserRole))
        return out

    def _update_map(self) -> None:
        size = self.result.get("disk_size") or 0
        parts = []
        for i, c in enumerate(sorted(self._checked(), key=lambda c: c.get("offset") or 0), start=1):
            parts.append({"number": i, "start": c.get("offset") or 0, "size": c.get("size") or 0,
                          "fstype": c.get("fstype"), "label": c.get("label") or "", "role": "data",
                          "found": c.get("status") != "current"})
        self.r_map.set_disk({"size": size}, parts)
        self.btn_write.setEnabled(bool(parts))

    def _show(self, row: int) -> None:
        it = self.tbl.item(row, 0) if row >= 0 else None
        c = it.data(Qt.UserRole) if it else None
        if not c:
            return
        self.s_title.setText(f"{fs_name(c.get('fstype'))} {('“' + c['label'] + '”') if c.get('label') else ''} · "
                             f"{fmt_bytes(c.get('size'))}")
        files = c.get("preview") or []
        if files:
            import html
            self.s_files.setText("<br>".join(f"<b>{html.escape(f)}</b>" if f.endswith("/") else html.escape(f)
                                             for f in files[:18]))
        else:
            self.s_files.setText("<span style='color:gray'>No file list (an encrypted volume, a filesystem RecoverAll "
                                 "lists through another engine, or a damaged root folder). “Recover files from it” "
                                 "still scans it.</span>")
        self._current = c

    def _browse(self) -> None:
        c = getattr(self, "_current", None)
        if c:
            self.scan_region.emit(self.path, int(c.get("offset") or 0), int(c.get("size") or 0))

    def _write(self) -> None:
        chosen = {int(c.get("offset") or 0) for c in self._checked()}
        prop = [p for p in self.result.get("proposal") or [] if int(p.get("start") or p.get("offset") or 0) in chosen]
        if not prop:
            prop = [{"start": c.get("offset"), "size": c.get("size"), "fstype": c.get("fstype"),
                     "name": c.get("label") or ""} for c in self._checked()]
        ttype = self.ttype.value() or "gpt"

        def planned(plan):
            if not plan.get("ok"):
                QMessageBox.warning(self, "Can't write this table", "\n".join(plan.get("problems") or []))
                return
            disk = self.source.current_disk() or {"path": self.path}
            typed = confirm_change(self, disk, "Write a new partition table?", "Write",
                                   f"The disk gets a new {ttype.upper()} partition table with {len(prop)} "
                                   "partition(s). The data inside them isn't touched, and the old table is backed up "
                                   "first (Undo on this page puts it back).")
            if typed is None:
                return
            self.bridge.call("write_partitions", done=self._written, source=self.path, table_type=ttype, parts=prop,
                             confirm=typed)
        self.bridge.call("plan_partitions", done=planned, source=self.path, table_type=ttype, parts=prop)

    def _written(self, res: dict) -> None:
        self.bridge.message.emit("The new partition table is written. The old one is saved: Undo puts it back.",
                                 "success")
        self.bridge.fetch_disks()
        self.outer.setCurrentIndex(0)
        self.shown()
