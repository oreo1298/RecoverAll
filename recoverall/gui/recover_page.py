"""The Recover files page: choose what to scan and how (quick, deep, signatures), watch the scan map fill
in, then browse what was found and recover it."""

from __future__ import annotations

import os

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..core.fs import fs_name
from ..core.util import fmt_bytes, fmt_duration, fmt_when
from .cellmap import scan_legend, scan_map
from .common import ChoiceCard, ChoiceGroup, OperationPage, SourcePicker, hint, section_label
from .dialogs import RecoverDialog, TypeChips
from .results_view import ResultsView
from .widgets import Card, StatTile, badge, clear_layout, icon_button


class ScanProgress(QWidget):
    """Beside the job view while a scan runs: the scan map, what was found so far, the volumes."""

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)
        card = Card("Scan map", "map")
        self.map = scan_map()
        card.add(self.map, 1)
        card.add(scan_legend())
        tiles = QHBoxLayout()
        tiles.setSpacing(10)
        self.t_vol = StatTile("Volumes found", "partition")
        self.t_files = StatTile("Files", "file")
        self.t_del = StatTile("Deleted or lost", "trash_restore")
        self.t_sig = StatTile("By signature", "search")
        for t in (self.t_vol, self.t_files, self.t_del, self.t_sig):
            tiles.addWidget(t, 1)
        card.add_layout(tiles)
        lay.addWidget(card, 3)
        vc = Card("Volumes", "layers")
        self.vol_list = QVBoxLayout()
        self.vol_list.setSpacing(4)
        vc.add_layout(self.vol_list)
        self.vol_empty = hint("Filesystems appear here as they are found.")
        vc.add(self.vol_empty)
        lay.addWidget(vc, 1)
        self._vols_key = ""

    def reset(self) -> None:
        self.map.clear()
        for t in (self.t_vol, self.t_files, self.t_del, self.t_sig):
            t.set("—")
        clear_layout(self.vol_list)
        self.vol_empty.show()
        self._vols_key = ""

    def update_job(self, job: dict) -> None:
        data = job.get("data") or {}
        st = job.get("stats") or {}
        if data.get("map"):
            self.map.set_map(data["map"], int(st.get("total") or 0) or 1)
        found = data.get("found") or {}
        if found:
            carved = sum((found.get("carved") or {}).values())
            self.t_vol.set(f"{found.get('volumes', 0)}")
            self.t_files.set(f"{found.get('files', 0):,}".replace(",", " "))
            self.t_del.set(f"{found.get('deleted', 0):,}".replace(",", " "))
            self.t_sig.set(f"{carved:,}".replace(",", " "),
                           sub=", ".join(f"{k} {v}" for k, v in sorted((found.get("carved") or {}).items(),
                                                                         key=lambda kv: -kv[1])[:3]))
            if found.get("bad"):
                self.t_files.set(self.t_files.value.text(), sub=f"{fmt_bytes(found['bad'])} unreadable")
        vols = data.get("volumes") or []
        key = repr([(v.get("name"), v.get("status"), v.get("files")) for v in vols])
        if vols and key != self._vols_key:
            self._vols_key = key
            clear_layout(self.vol_list)
            self.vol_empty.hide()
            for v in vols:
                row = QHBoxLayout()
                what = "signature search" if v.get("fstype") == "carved" else fs_name(v.get("fstype"))
                lab = QLabel(f"<b>{v.get('name') or what}</b>  ·  {what}  ·  {fmt_bytes(v.get('size'))}")
                row.addWidget(lab, 1)
                if v.get("status") not in ("existing", "carved", None):
                    row.addWidget(badge(str(v["status"]).upper(), "BadgeWarn"))
                if v.get("files"):
                    n = QLabel(f"{v['files']:,} files, {v.get('deleted_files', 0):,} deleted".replace(",", " "))
                    n.setObjectName("Muted")
                    row.addWidget(n)
                self.vol_list.addLayout(row)


class RecoverPage(OperationPage):
    open_image = Signal()

    def __init__(self, bridge, gs, parent=None):
        self.progress_view = ScanProgress()
        super().__init__(bridge, self.progress_view, parent)
        self.gs = gs
        self.scan_path = ""
        self.job_kind = ""
        self.results = ResultsView(bridge, gs)
        self.outer.addWidget(self.results)
        self.results.recover.connect(self.recover)
        self.results.new_scan.connect(lambda: self.outer.setCurrentIndex(0))
        self.results.save_scan.connect(self.save_scan)
        self._build_setup()

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

        c1 = Card("1  What to scan", "hdd")
        self.source = SourcePicker(self.bridge)
        self.source.changed.connect(self._source_changed)
        self.source.open_image.connect(self.open_image.emit)
        c1.add(self.source)
        self.src_note = QLabel()
        self.src_note.setWordWrap(True)
        self.src_note.hide()
        c1.add(self.src_note)
        lay.addWidget(c1)

        c2 = Card("2  How to scan", "scan")
        self.mode = ChoiceGroup()
        self.mode.add(ChoiceCard("quick", "bolt", "Quick scan",
                                 "Deleted files in the filesystems that are there: names, folders and dates. "
                                 "Try this first."))
        self.mode.add(ChoiceCard("deep", "folder_search", "Deep scan",
                                 "Reads the whole disk: deleted partitions, formatted and damaged drives, lost "
                                 "folders, plus every file type it recognises (R-Studio / GetDataBack)."))
        self.mode.add(ChoiceCard("carve", "search", "Signature search",
                                 "Only file types, like PhotoRec: works however damaged the disk is, but files get "
                                 "numbers instead of names."))
        self.mode.changed.connect(self._mode_changed)
        c2.add(self.mode)
        self.opts = QWidget()
        ol = QVBoxLayout(self.opts)
        ol.setContentsMargins(0, 4, 0, 0)
        ol.setSpacing(6)
        ol.addWidget(section_label("File types to look for by signature"))
        self.types = TypeChips(self.gs.carve_types)
        ol.addWidget(self.types)
        self.free_only = QCheckBox("Only the free space (faster; finds deleted files only, and files written "
                                   "around used clusters come back whole)")
        self.free_only.setChecked(True)
        ol.addWidget(self.free_only)
        c2.add(self.opts)
        lay.addWidget(c2)

        row = QHBoxLayout()
        self.estimate = QLabel()
        self.estimate.setObjectName("Muted")
        row.addWidget(self.estimate, 1)
        self.btn_start = icon_button("Start scan", "play", "primary")
        self.btn_start.setMinimumHeight(38)
        self.btn_start.clicked.connect(self.start)
        row.addWidget(self.btn_start)
        lay.addLayout(row)

        c3 = Card("Earlier scans", "clock")
        b = c3.add_header_widget(icon_button("Open a scan file…", "open", "ghost"))
        b.clicked.connect(self.open_scan_file)
        self.scans_list = QVBoxLayout()
        self.scans_list.setSpacing(6)
        c3.add_layout(self.scans_list)
        self.scans_empty = hint("Scans are kept: open one again to recover more without scanning again.")
        c3.add(self.scans_empty)
        lay.addWidget(c3)
        lay.addStretch(1)
        self.mode.set_value(self.gs.scan_mode if self.gs.scan_mode in ("quick", "deep", "carve") else "quick")

    def shown(self) -> None:
        if self.outer.currentIndex() == 0:
            self.refresh_scans()

    def set_disks(self, disks: list[dict]) -> None:
        self.source.set_disks(disks)

    def set_detail(self, _d: dict) -> None:
        self._source_changed()

    def start_with(self, path: str, number: int | None = None, mode: str | None = None) -> None:
        if self.running():
            return
        self.outer.setCurrentIndex(0)
        self.source.select(path, number)
        if mode:
            self.mode.set_value(mode)
        self.refresh_scans()

    def start_region(self, path: str, offset: int, size: int, label: str = "") -> None:
        """Scan one filesystem found by the partition search (it isn't in the partition table)."""
        if self.running():
            return
        self.outer.setCurrentIndex(0)
        self.source.select(path)
        self._region = {"path": path, "offset": int(offset), "size": int(size)}
        self.mode.set_value("quick")
        self.src_note.setText(f"Scanning the filesystem {label + ' ' if label else ''}found at {fmt_bytes(offset)} "
                              f"({fmt_bytes(size)}) — it isn't in the partition table, nothing is written to the disk.")
        self.src_note.setObjectName("Banner")
        self.src_note.style().unpolish(self.src_note)
        self.src_note.style().polish(self.src_note)
        self.src_note.show()

    def _mode_changed(self, mode) -> None:
        self.opts.setVisible(mode in ("deep", "carve"))
        self.free_only.setVisible(mode == "carve")
        self._estimate()

    def _source_changed(self) -> None:
        self._region = None
        d = self.source.current_disk()
        note = ""
        kind = ""
        if d:
            h = (d.get("health") or {}).get("state")
            if h == "failing":
                note = ("<b>This disk is failing.</b> A deep scan reads all of it, which can be its last read: "
                        "create an image first (Imaging page) and scan the image.")
                kind = "BannerBad"
            elif d.get("system"):
                note = ("The running system is on this disk: keep it as idle as you can, and save what you recover "
                        "on another disk.")
                kind = "BannerWarn"
            elif (d.get("table") or {}).get("problems") and self.source.current_part() is None:
                note = ("Its partition table looks damaged or empty: a <b>deep scan</b> finds the filesystems that "
                        "were on it.")
                kind = "BannerWarn"
        self.src_note.setText(note)
        if kind:
            self.src_note.setObjectName(kind)
            self.src_note.style().unpolish(self.src_note)
            self.src_note.style().polish(self.src_note)
        self.src_note.setVisible(bool(note))
        self._estimate()

    def _estimate(self) -> None:
        d = self.source.current_disk()
        p = self.source.current_part()
        mode = self.mode.value()
        if not d:
            self.estimate.setText("")
            return
        size = (p or d).get("size") or 0
        rate = {"hdd": 150e6, "usb-flash": 60e6, "sd": 70e6, "usb-disk": 110e6}.get(d.get("kind"), 400e6)
        if mode == "quick":
            self.estimate.setText("Usually a few minutes.")
        else:
            self.estimate.setText(f"Reads {fmt_bytes(size)}: about {fmt_duration(size / rate)} at "
                                  f"{fmt_bytes(rate)}/s. You can stop it any time and keep what was found.")

    def refresh_scans(self) -> None:
        self.bridge.call("scans", done=self._got_scans, error=lambda e: None)

    def _got_scans(self, items: list) -> None:
        clear_layout(self.scans_list)
        self.scans_empty.setVisible(not items)
        from ..core.scan import MODE_TEXT
        for s in (items or [])[:8]:
            src = s.get("source") or {}
            st = s.get("stats") or {}
            row = QHBoxLayout()
            lab = QLabel(f"<b>{src.get('display_name') or src.get('name') or '?'}</b> · "
                         f"{MODE_TEXT.get(s.get('mode') or '', 'Scan')} · {fmt_when(s.get('created'))} · "
                         f"{st.get('files', 0):,} files, {st.get('deleted_files', 0):,} deleted".replace(",", " ")
                         + ("" if s.get("state") == "complete" else f" · {s.get('state')}"))
            row.addWidget(lab, 1)
            b = icon_button("Open", "open", "ghost")
            b.clicked.connect(lambda _c=False, p=s["path"]: self.show_results(p))
            row.addWidget(b)
            d = icon_button("", "trash", "ghost", "Delete this scan file")
            d.clicked.connect(lambda _c=False, p=s["path"]: self._delete_scan(p))
            row.addWidget(d)
            self.scans_list.addLayout(row)

    def _delete_scan(self, path: str) -> None:
        if QMessageBox.question(self, "Delete the scan", "Delete this scan file? The disk isn't touched; you'd have "
                                "to scan again to see its results.") != QMessageBox.Yes:
            return
        self.bridge.call("delete_scan", done=lambda _r: self.refresh_scans(), scan=path)

    # ------------------------------------------------------------------ running
    def start(self) -> None:
        spec = getattr(self, "_region", None) or self.source.spec()
        if spec is None:
            self.bridge.message.emit("Choose a disk first", "warning")
            return
        mode = self.mode.value() or "quick"
        opts = {"mode": mode}
        if mode in ("deep", "carve"):
            opts["formats"] = self.types.value() or None
            self.gs.carve_types = self.types.value()
        if mode == "carve":
            opts["free_only"] = self.free_only.isChecked()
        self.gs.scan_mode = mode
        self.gs.save()
        d = self.source.current_disk() or {}
        p = self.source.current_part()
        name = d.get("display_name") or ""
        if p:
            name += f" partition {p.get('number')}"

        def go():
            self.bridge.call("start_scan", done=self._started, source=spec, options=opts, name=name)
        if self.bridge.privileged or d.get("is_image"):
            go()                    # image files you can read need no administrator rights
        else:
            self.bridge.ensure_access(go)

    def _started(self, job: dict) -> None:
        self.scan_path = job.get("scan") or ""
        self.job_kind = "scan"
        self.progress_view.reset()
        self.jobview.t_done.caption.setText("Read")
        self.run_job(job)

    def job_data(self, job: dict) -> None:
        if self.job_kind == "scan":
            self.progress_view.update_job(job)

    def finish_run(self) -> None:
        job = self.jobview.job or {}
        self.job_id = None
        if self.job_kind == "scan" and job.get("state") in ("done", "cancelled") and self.scan_path:
            self.show_results(self.scan_path)
        elif self.job_kind == "recover" and self.results.scan:
            self.outer.setCurrentIndex(2)
        else:
            self.outer.setCurrentIndex(0)
            self.refresh_scans()

    def show_results(self, scan: str) -> None:
        self.scan_path = scan
        self.outer.setCurrentIndex(2)

        def opened(_r):
            self.results.set_scan(scan)
        self.bridge.call("open_scan", done=opened, path=scan)

    def open_scan_file(self) -> None:
        path, _f = QFileDialog.getOpenFileName(self, "Open a scan", os.path.expanduser("~"),
                                               "RecoverAll scans (*.rascan);;All files (*)")
        if path:
            self.show_results(path)

    def save_scan(self, scan: str) -> None:
        src = os.path.splitext(os.path.basename(scan))[0]
        dest, _f = QFileDialog.getSaveFileName(self, "Save the scan", os.path.join(os.path.expanduser("~"),
                                                                                    src + ".rascan"),
                                               "RecoverAll scans (*.rascan)")
        if dest:
            self.bridge.call("save_scan", success="Scan saved", scan=scan, dest=dest)

    # ------------------------------------------------------------------ recovering
    def recover(self, ids: list, filters: dict, what: str, exclude: list | None = None) -> None:
        if not ids:
            return
        info = self.results.info or {}
        src = (info.get("source") or {}).get("display_name") or ""
        dlg = RecoverDialog(self.gs, f"Recover {what}", src, self)
        if not dlg.exec():
            return
        dest, opts = dlg.value()
        if not dest:
            return

        def started(job):
            self.job_kind = "recover"
            self.jobview.t_done.caption.setText("Recovered")
            self.run_job(job)
        self.bridge.call("start_recover", done=started, scan=self.results.scan, entries=[int(i) for i in ids],
                         dest=dest, options=opts, filters=filters, exclude=[int(i) for i in exclude or ()])

    def after_run(self) -> None:
        pass

