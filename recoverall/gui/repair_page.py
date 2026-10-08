"""The Repair page: diagnose a partition's boot sectors and superblocks (and fix them from their backups),
check and repair a filesystem with its own tools, and repair damaged files (photos, Office documents, PDFs,
archives, sound and video containers).

Recover first, repair second: a repair writes to the disk, and a failed one can make recovery harder."""

from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..core.fs import fs_name
from .common import OperationPage, SourcePicker, hint
from .dialogs import confirm_change
from .widgets import Card, badge, bind_icon, clear_layout, icon_button, scaled_font

RISK = {"safe": ("CHECK ONLY", "BadgeOk"), "normal": ("REPAIRS", "BadgeWarn"), "risky": ("LAST RESORT", "BadgeBad")}
SEVERITY_ICON = {"error": ("error", "danger"), "warning": ("warning", "warning"), "info": ("info", "accent")}


class RepairPage(OperationPage):
    def __init__(self, bridge, gs, parent=None):
        super().__init__(bridge, None, parent)
        self.gs = gs
        self.fstype = ""
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
        banner = QLabel("<b>Recover your files first, repair afterwards.</b> Repairs write to the disk; on a damaged "
                        "filesystem a repair can also throw away what the recovery would have found. Everything "
                        "RecoverAll itself overwrites is backed up first (Partitions → Undo).")
        banner.setWordWrap(True)
        banner.setObjectName("BannerWarn")
        lay.addWidget(banner)

        c1 = Card("What to check", "stethoscope")
        self.source = SourcePicker(self.bridge)
        self.source.changed.connect(self._source_changed)
        c1.add(self.source)
        row = QHBoxLayout()
        self.fs_label = QLabel("")
        self.fs_label.setObjectName("Muted")
        row.addWidget(self.fs_label, 1)
        self.btn_diag = icon_button("Diagnose", "stethoscope", "primary", "Read the boot sectors, superblocks and the "
                                                                         "partition table (nothing is written)")
        self.btn_diag.clicked.connect(self.diagnose)
        row.addWidget(self.btn_diag)
        c1.add_layout(row)
        self.problems = QVBoxLayout()
        self.problems.setSpacing(6)
        c1.add_layout(self.problems)
        lay.addWidget(c1)

        c2 = Card("Check and repair the filesystem", "wrench")
        self.actions = QVBoxLayout()
        self.actions.setSpacing(6)
        c2.add_layout(self.actions)
        self.no_actions = hint("Choose a partition with a filesystem.")
        c2.add(self.no_actions)
        lay.addWidget(c2)

        c3 = Card("Repair damaged files", "file")
        c3.add(hint("Photos that open grey or half, Office documents and archives that “are corrupt”, PDFs that "
                    "won't open, WAV/AVI files that stop early. The originals are never changed: repaired copies are "
                    "written next to them (or into the folder below).", faint=False))
        self.files = QListWidget()
        self.files.setMinimumHeight(110)
        self.files.setSelectionMode(QListWidget.ExtendedSelection)
        c3.add(self.files)
        row = QHBoxLayout()
        b = icon_button("Add files…", "plus", "ghost")
        b.clicked.connect(self._add_files)
        r = icon_button("Remove", "minus", "ghost")
        r.clicked.connect(lambda: [self.files.takeItem(self.files.row(i)) for i in self.files.selectedItems()])
        row.addWidget(b)
        row.addWidget(r)
        row.addStretch(1)
        c3.add_layout(row)
        frow = QHBoxLayout()
        frow.addWidget(QLabel("Reference"))
        self.ref = QLineEdit()
        self.ref.setPlaceholderText("optional: a good photo from the same camera (rebuilds damaged JPEG headers)")
        rb = icon_button("", "open", "", "Choose the reference file")
        rb.clicked.connect(self._ref)
        frow.addWidget(self.ref, 1)
        frow.addWidget(rb)
        c3.add_layout(frow)
        orow = QHBoxLayout()
        orow.addWidget(QLabel("Save in"))
        self.out = QLineEdit()
        self.out.setPlaceholderText("next to each file")
        ob = icon_button("", "open", "", "Choose a folder")
        ob.clicked.connect(self._out)
        orow.addWidget(self.out, 1)
        orow.addWidget(ob)
        c3.add_layout(orow)
        brow = QHBoxLayout()
        brow.addStretch(1)
        self.btn_check = icon_button("What's wrong?", "search", "ghost")
        self.btn_check.clicked.connect(self._analyze)
        self.btn_fix = icon_button("Repair copies", "wrench", "primary")
        self.btn_fix.clicked.connect(self._repair_files)
        brow.addWidget(self.btn_check)
        brow.addWidget(self.btn_fix)
        c3.add_layout(brow)
        self.analysis = QLabel("")
        self.analysis.setWordWrap(True)
        self.analysis.setTextFormat(Qt.RichText)
        c3.add(self.analysis)
        lay.addWidget(c3)
        lay.addStretch(1)

    # ------------------------------------------------------------------ disks
    def set_disks(self, disks: list[dict]) -> None:
        self.source.set_disks(disks)

    def set_detail(self, _d: dict) -> None:
        self._source_changed()

    def start_with(self, path: str, number: int | None = None) -> None:
        if self.running():
            return
        self.outer.setCurrentIndex(0)
        self.source.select(path, number)

    def _source_changed(self) -> None:
        d = self.source.current_disk()
        p = self.source.current_part()
        fstype = (p or {}).get("fstype") or ((d or {}).get("fstype") if p is None else "") or ""
        self.fstype = fstype
        if p is None and d and d.get("partitions"):
            self.fs_label.setText("The whole disk: checks the partition table. Choose a partition to check its "
                                  "filesystem.")
        else:
            self.fs_label.setText(f"Filesystem: {fs_name(fstype)}" if fstype else "No filesystem recognised here")
        clear_layout(self.problems)
        self._load_actions()

    def _load_actions(self) -> None:
        clear_layout(self.actions)
        if not self.fstype:
            self.no_actions.show()
            return
        self.no_actions.hide()
        self.bridge.call("fsck_actions", done=self._got_actions, error=lambda e: None, fstype=self.fstype)

    def _got_actions(self, acts: list) -> None:
        clear_layout(self.actions)
        if not acts:
            self.no_actions.setText(f"No repair tool is known for {fs_name(self.fstype)}.")
            self.no_actions.show()
            return
        for a in acts:
            frame = QFrame()
            frame.setObjectName("Finding")
            fl = QHBoxLayout(frame)
            fl.setContentsMargins(12, 8, 12, 8)
            col = QVBoxLayout()
            col.setSpacing(2)
            t = QLabel(a.get("title") or a["id"])
            t.setFont(scaled_font(t, 1.0, bold=True))
            d = QLabel(a.get("detail") or "")
            d.setWordWrap(True)
            d.setObjectName("Muted")
            col.addWidget(t)
            col.addWidget(d)
            if not a.get("available", True):
                m = QLabel(f"Needs {a.get('missing_program') or 'a tool'} (package {a.get('package') or '?'})")
                m.setObjectName("Faint")
                col.addWidget(m)
            fl.addLayout(col, 1)
            text, kind = RISK.get(a.get("risk") or "", ("", "BadgeIdle"))
            if text:
                fl.addWidget(badge(text, kind), 0, Qt.AlignTop)
            b = icon_button("Run", "play", "primary" if a.get("risk") == "safe" else "danger")
            b.setEnabled(bool(a.get("available", True)))
            b.clicked.connect(lambda _c=False, a=a: self.run_action(f"fsck:{a['id']}", a.get("risk") == "safe",
                                                                    a.get("title") or a["id"]))
            fl.addWidget(b, 0, Qt.AlignVCenter)
            self.actions.addWidget(frame)

    # ------------------------------------------------------------------ diagnose / fix
    def _where(self) -> tuple[str, int, int | None]:
        d = self.source.current_disk() or {}
        p = self.source.current_part()
        if p is None:
            return d.get("path", ""), 0, None
        return d.get("path", ""), int(p["start"]), int(p["size"])

    def diagnose(self) -> None:
        path, off, size = self._where()
        if not path:
            return
        clear_layout(self.problems)
        wait = QLabel("Reading…")
        wait.setObjectName("Muted")
        self.problems.addWidget(wait)

        def go():
            self.bridge.call("diagnose", done=self._got_problems, error=self._diag_failed, source=path, offset=off,
                             size=size, fstype=self.fstype)
        d = self.source.current_disk() or {}
        if self.bridge.privileged or d.get("is_image"):
            go()
        else:
            self.bridge.ensure_access(go)

    def _diag_failed(self, e) -> None:
        clear_layout(self.problems)
        lab = QLabel(str(e))
        lab.setObjectName("BannerBad")
        lab.setWordWrap(True)
        self.problems.addWidget(lab)

    def _got_problems(self, probs: list) -> None:
        clear_layout(self.problems)
        if not probs:
            ok = QLabel("✓  The boot sectors, superblocks and the partition table look right.")
            ok.setObjectName("Muted")
            self.problems.addWidget(ok)
            return
        for pr in probs:
            frame = QFrame()
            frame.setObjectName("Finding")
            fl = QHBoxLayout(frame)
            fl.setContentsMargins(12, 8, 12, 8)
            ic = QLabel()
            name, token = SEVERITY_ICON.get(pr.get("severity") or "warning", SEVERITY_ICON["warning"])
            frame._ic = bind_icon(ic, name, token, 20)
            fl.addWidget(ic, 0, Qt.AlignTop)
            col = QVBoxLayout()
            t = QLabel(pr.get("title") or "")
            t.setFont(scaled_font(t, 1.0, bold=True))
            t.setWordWrap(True)
            d = QLabel(pr.get("detail") or "")
            d.setWordWrap(True)
            d.setObjectName("Muted")
            col.addWidget(t)
            col.addWidget(d)
            fl.addLayout(col, 1)
            fix = pr.get("fix")
            if fix:
                b = icon_button("Fix…", "wrench", "danger")
                b.clicked.connect(lambda _c=False, fix=fix, pr=pr: self.run_action(fix, False, pr.get("title") or fix,
                                                                                   pr.get("fix_options") or {}))
                fl.addWidget(b, 0, Qt.AlignVCenter)
            self.problems.addWidget(frame)

    def run_action(self, action: str, safe: bool, title: str, options: dict | None = None) -> None:
        path, off, size = self._where()
        d = self.source.current_disk() or {"path": path}
        typed = ""
        if not safe:
            typed = confirm_change(self, d, f"{title}?", "Repair",
                                   "This writes to the disk. If you still need files from it, recover them first.")
            if typed is None:
                return

        def go():
            self.bridge.call("start_repair", done=self.run_job, source=path, action=action, offset=off, size=size,
                             fstype=self.fstype, options=options or {}, confirm=typed)
        self.bridge.ensure_access(go)

    def finish_run(self) -> None:
        self.job_id = None
        self.outer.setCurrentIndex(0)
        self.bridge.fetch_disks()
        if self.source.current_disk():
            self.diagnose()

    # ------------------------------------------------------------------ files
    def _add_files(self) -> None:
        paths, _f = QFileDialog.getOpenFileNames(self, "Damaged files", self.gs.recover_folder or os.path.expanduser("~"))
        for p in paths:
            if not self.files.findItems(p, Qt.MatchExactly):
                self.files.addItem(QListWidgetItem(p))

    def _ref(self) -> None:
        p, _f = QFileDialog.getOpenFileName(self, "A good file from the same camera or program", os.path.expanduser("~"))
        if p:
            self.ref.setText(p)

    def _out(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Save the repaired copies in", os.path.expanduser("~"))
        if d:
            self.out.setText(d)

    def _paths(self) -> list[str]:
        return [self.files.item(i).text() for i in range(self.files.count())]

    def _analyze(self) -> None:
        paths = self._paths()
        if not paths:
            return
        self.analysis.setText("Checking…")
        results: dict[str, dict] = {}

        def got(p, a):
            results[p] = a
            if len(results) == len(paths):
                rows = []
                for q in paths:
                    r = results[q]
                    probs = r.get("problems") or []
                    rows.append(f"<b>{os.path.basename(q)}</b> ({r.get('type') or '?'}): " +
                                ("; ".join(probs) if probs else "looks fine") +
                                ("" if r.get("repairable", True) or not probs else " — can't be repaired here"))
                self.analysis.setText("<br>".join(rows))
        for p in paths:
            self.bridge.call("file_analyze", done=lambda a, p=p: got(p, a),
                             error=lambda e, p=p: got(p, {"problems": [str(e)], "repairable": False}), path=p)

    def _repair_files(self) -> None:
        paths = self._paths()
        if not paths:
            self.bridge.message.emit("Add the damaged files first", "warning")
            return
        out = self.out.text().strip() or os.path.dirname(paths[0])
        self.bridge.call("start_file_repair", done=self.run_job, paths=paths, out_dir=out,
                         reference=self.ref.text().strip() or None)
