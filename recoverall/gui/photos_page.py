"""The Photos page: the simple way to get photos and videos back from a camera card, a phone's card or a
stick. Pick the card, pick what to look for, and the deleted pictures come back as a grid of thumbnails to
choose from (deleted files from the filesystem plus a signature search of the free space)."""

from __future__ import annotations

import base64

from PySide6.QtCore import QAbstractListModel, QModelIndex, QRect, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QImage, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListView,
    QScrollArea,
    QSplitter,
    QStyle,
    QStyledItemDelegate,
    QVBoxLayout,
    QWidget,
)

from ..core.util import fmt_bytes, fmt_capacity
from . import icons
from .common import ChoiceCard, OperationPage, hint
from .dialogs import RecoverDialog
from .recover_page import ScanProgress
from .results_view import CHANCE_HELP, PreviewPanel
from .theme import theme
from .widgets import CHANCE_TOKENS, Card, chip, clear_layout, icon_button, kind_icon, scaled_font

TILE = QSize(184, 168)
THUMB_H = 122
PAGE = 120

KINDS = [("photo", "Photos and RAW", "photo"), ("video", "Videos", "film"), ("audio", "Music", "music"),
         ("document", "Documents", "file_text")]
FOUND_WORDS = {"photo": "photos", "video": "videos", "audio": "songs and recordings", "document": "documents"}


class GalleryModel(QAbstractListModel):
    checked_changed = Signal()
    loaded = Signal(int)

    def __init__(self, bridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.scan = ""
        self.filters: dict = {}
        self.rows: list[dict] = []
        self.total = 0
        self.thumbs: dict[int, QPixmap | None] = {}
        self.checked: set[int] = set()
        self._gen = 0
        self._loading = False

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.rows)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self.rows):
            return None
        r = self.rows[index.row()]
        if role == Qt.DisplayRole:
            return r["name"]
        if role == Qt.UserRole:
            return r
        if role == Qt.CheckStateRole:
            return Qt.Checked if r["id"] in self.checked else Qt.Unchecked
        if role == Qt.ToolTipRole:
            return f"{r['name']}\n{fmt_bytes(r['size'])}\n{CHANCE_HELP.get(r['chance'], '')}"
        return None

    def flags(self, index):
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable

    def load(self, scan: str, filters: dict) -> None:
        self.scan = scan
        self.filters = dict(filters)
        self._gen += 1
        self.beginResetModel()
        self.rows = []
        self.total = 0
        self.endResetModel()
        self._fetch(0)

    def _fetch(self, offset: int) -> None:
        gen = self._gen
        self._loading = True

        def got(res):
            if gen != self._gen:
                return
            self._loading = False
            rows = res.get("rows") or []
            self.total = res.get("total") or 0
            if rows:
                self.beginInsertRows(QModelIndex(), len(self.rows), len(self.rows) + len(rows) - 1)
                self.rows.extend(rows)
                self.endInsertRows()
                self._thumbs([r["id"] for r in rows], gen)
            self.loaded.emit(self.total)
        self.bridge.call("scan_search", done=got, error=lambda e: setattr(self, "_loading", False), scan=self.scan,
                         filters=self.filters, offset=offset, limit=PAGE, sort="mtime", desc=True)

    def _thumbs(self, ids: list[int], gen: int) -> None:
        for i in range(0, len(ids), 24):
            batch = ids[i:i + 24]

            def got(res, batch=batch):
                if gen != self._gen:
                    return
                for k, v in (res or {}).items():
                    pm = None
                    if v.get("data"):
                        img = QImage.fromData(base64.b64decode(v["data"]))
                        if not img.isNull():
                            pm = QPixmap.fromImage(img.scaled(TILE.width() * 2, THUMB_H * 2, Qt.KeepAspectRatio,
                                                              Qt.SmoothTransformation))
                    self.thumbs[int(k)] = pm
                first = min((n for n, r in enumerate(self.rows) if r["id"] in set(batch)), default=0)
                self.dataChanged.emit(self.index(first, 0), self.index(len(self.rows) - 1, 0))
            self.bridge.call("thumbnails", done=got, error=lambda e: None, scan=self.scan, entries=batch)

    def canFetchMore(self, parent=QModelIndex()) -> bool:  # noqa: N802
        return not parent.isValid() and not self._loading and len(self.rows) < self.total

    def fetchMore(self, parent=QModelIndex()) -> None:  # noqa: N802
        if self.canFetchMore(parent):
            self._fetch(len(self.rows))

    def toggle(self, index) -> None:
        r = self.rows[index.row()]
        if r["id"] in self.checked:
            self.checked.discard(r["id"])
        else:
            self.checked.add(r["id"])
        self.dataChanged.emit(index, index)
        self.checked_changed.emit()

    def check_all(self, on: bool) -> None:
        if on:
            self.checked.update(r["id"] for r in self.rows)
        else:
            self.checked.clear()
        if self.rows:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.rows) - 1, 0))
        self.checked_changed.emit()


class TileDelegate(QStyledItemDelegate):
    """A photo tile: the thumbnail (or a type icon), the name, a check box and the recovery-chance dot."""

    def __init__(self, model: GalleryModel, parent=None):
        super().__init__(parent)
        self.model = model

    def sizeHint(self, option, index) -> QSize:  # noqa: N802
        return TILE

    def paint(self, p: QPainter, option, index) -> None:
        pal = theme.palette
        r = index.data(Qt.UserRole)
        if r is None:
            return
        p.save()
        p.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(option.rect.adjusted(4, 4, -4, -4))
        sel = bool(option.state & QStyle.State_Selected)
        checked = r["id"] in self.model.checked
        path = QPainterPath()
        path.addRoundedRect(rect, 10, 10)
        p.fillPath(path, QColor(pal.surface_alt))
        p.setPen(QPen(QColor(pal.accent if (sel or checked) else pal.border), 2 if (sel or checked) else 1))
        p.drawPath(path)
        thumb = QRectF(rect.left() + 6, rect.top() + 6, rect.width() - 12, THUMB_H - 8)
        pm = self.model.thumbs.get(r["id"])
        if pm is not None:
            scaled = pm.scaled(int(thumb.width()) * 2, int(thumb.height()) * 2, Qt.KeepAspectRatioByExpanding,
                               Qt.SmoothTransformation)
            scaled.setDevicePixelRatio(2.0)
            sw, sh = scaled.width() / 2, scaled.height() / 2
            clip = QPainterPath()
            clip.addRoundedRect(thumb, 7, 7)
            p.setClipPath(clip)
            p.drawPixmap(QRectF(thumb.center().x() - sw / 2, thumb.center().y() - sh / 2, sw, sh), scaled,
                         QRectF(0, 0, scaled.width(), scaled.height()))
            p.setClipping(False)
        else:
            inner = QPainterPath()
            inner.addRoundedRect(thumb, 7, 7)
            p.fillPath(inner, QColor(pal.raised))
            ic = {"video": "film", "audio": "music", "document": "file_text"}.get(r.get("cat") or "", "photo")
            px = icons.pixmap(ic, pal.text_faint, 40)
            p.drawPixmap(QRect(int(thumb.center().x() - 20), int(thumb.center().y() - 20), 40, 40), px)
            if r["id"] in self.model.thumbs and r.get("cat") == "photo":
                p.setPen(QColor(pal.text_faint))
                f = QFont(option.font)
                f.setPointSizeF(max(7.0, f.pointSizeF() * 0.8))
                p.setFont(f)
                p.drawText(thumb.adjusted(4, 0, -4, -6), Qt.AlignBottom | Qt.AlignHCenter, "no preview")
        # check box
        cb = QRectF(thumb.left() + 6, thumb.top() + 6, 18, 18)
        p.setPen(QPen(QColor("#ffffff") if not checked else QColor(pal.accent), 1.6))
        p.setBrush(QColor(pal.accent) if checked else QColor(0, 0, 0, 90))
        p.drawRoundedRect(cb, 5, 5)
        if checked:
            p.setPen(QPen(QColor(pal.accent_text), 2.2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            from PySide6.QtCore import QPointF
            p.drawPolyline([QPointF(cb.left() + 4.5, cb.center().y()), QPointF(cb.left() + 7.8, cb.bottom() - 4.5),
                            QPointF(cb.right() - 4, cb.top() + 4.5)])
        # chance dot
        if r["deleted"]:
            dot = QRectF(thumb.right() - 18, thumb.top() + 8, 11, 11)
            p.setPen(QPen(QColor("#ffffff"), 1.5))
            p.setBrush(QColor(getattr(pal, CHANCE_TOKENS.get(r["chance"], "text_faint"))))
            p.drawEllipse(dot)
        if r.get("cat") == "video":
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(0, 0, 0, 140))
            tag = QRectF(thumb.left() + 6, thumb.bottom() - 22, 46, 16)
            p.drawRoundedRect(tag, 4, 4)
            p.setPen(QColor("#ffffff"))
            f = QFont(option.font)
            f.setPointSizeF(max(6.5, f.pointSizeF() * 0.72))
            f.setBold(True)
            p.setFont(f)
            p.drawText(tag, Qt.AlignCenter, "VIDEO")
        # name and size
        f = QFont(option.font)
        f.setPointSizeF(max(7.0, f.pointSizeF() * 0.86))
        p.setFont(f)
        p.setPen(QColor(pal.text))
        name_r = QRectF(rect.left() + 8, rect.top() + THUMB_H + 2, rect.width() - 16, 18)
        p.drawText(name_r, Qt.AlignLeft | Qt.AlignVCenter, p.fontMetrics().elidedText(r["name"], Qt.ElideMiddle,
                                                                                        int(name_r.width())))
        p.setPen(QColor(pal.text_muted))
        sub_r = QRectF(rect.left() + 8, rect.top() + THUMB_H + 19, rect.width() - 16, 16)
        p.drawText(sub_r, Qt.AlignLeft | Qt.AlignVCenter, fmt_bytes(r["size"]) + ("  · deleted" if r["deleted"] else ""))
        p.restore()

    def editorEvent(self, event, model, option, index) -> bool:  # noqa: N802
        from PySide6.QtCore import QEvent
        if event.type() == QEvent.MouseButtonRelease and event.button() == Qt.LeftButton:
            rect = option.rect.adjusted(4, 4, -4, -4)
            cb = QRect(rect.left() + 6, rect.top() + 6, 30, 30)
            if cb.contains(event.position().toPoint()):
                self.model.toggle(index)
                return True
        if event.type() == QEvent.MouseButtonDblClick:
            self.model.toggle(index)
            return True
        return False


class PhotosPage(OperationPage):
    def __init__(self, bridge, gs, parent=None):
        self.progress_view = ScanProgress()
        super().__init__(bridge, self.progress_view, parent)
        self.gs = gs
        self.scan_path = ""
        self.job_kind = ""
        self.selected_path: str | None = None
        self.cards: dict[str, ChoiceCard] = {}
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
        hero = QFrame()
        hero.setObjectName("Card")
        hl = QHBoxLayout(hero)
        hl.setContentsMargins(18, 16, 18, 16)
        hl.setSpacing(16)
        ic = QLabel()
        ic.setPixmap(icons.pixmap("camera", theme.palette.accent, 44))
        theme.changed.connect(lambda pal: ic.setPixmap(icons.pixmap("camera", pal.accent, 44)))
        hl.addWidget(ic, 0, Qt.AlignTop)
        col = QVBoxLayout()
        t = QLabel("Get deleted photos and videos back")
        t.setObjectName("Hero")
        t.setFont(scaled_font(t, 1.45, bold=True))
        d = QLabel("From a camera's memory card, a phone's SD card, a USB stick or any disk — also after a "
                   "“format”. Don't take new pictures with the card until you're done: they would land on the "
                   "space the deleted ones still occupy.")
        d.setWordWrap(True)
        d.setObjectName("Muted")
        col.addWidget(t)
        col.addWidget(d)
        hl.addLayout(col, 1)
        lay.addWidget(hero)

        c1 = Card("1  Where were they?", "sdcard")
        self.grid_holder = QWidget()
        self.grid = QGridLayout(self.grid_holder)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(10)
        c1.add(self.grid_holder)
        self.no_disks = hint("Insert the card or stick: it appears here.")
        c1.add(self.no_disks)
        lay.addWidget(c1)

        c2 = Card("2  What should come back?", "photo")
        row = QHBoxLayout()
        row.setSpacing(8)
        self.kinds = {}
        for key, name, _ic in KINDS:
            c = chip(name, key in ("photo", "video"))
            self.kinds[key] = c
            row.addWidget(c)
        row.addStretch(1)
        c2.add_layout(row)
        lay.addWidget(c2)
        row = QHBoxLayout()
        note = QLabel("Nothing is written to the card. You choose where the pictures are saved afterwards.")
        note.setObjectName("Muted")
        row.addWidget(note, 1)
        self.btn_start = icon_button("Find them", "search", "primary")
        self.btn_start.setMinimumHeight(38)
        self.btn_start.clicked.connect(self.start)
        row.addWidget(self.btn_start)
        lay.addLayout(row)
        lay.addStretch(1)

    def set_disks(self, disks: list[dict]) -> None:
        clear_layout(self.grid)
        self.cards = {}
        order = {"sd": 0, "usb-flash": 1, "usb-disk": 2, "emmc": 3, "image": 4}
        disks = sorted(disks, key=lambda d: (order.get(d.get("kind"), 9), d.get("system", False)))
        for i, d in enumerate(disks):
            sub = f"{fmt_capacity(d.get('size'))}"
            parts = [p for p in d.get("partitions") or [] if p.get("label")]
            if parts:
                sub += " · " + ", ".join(p["label"] for p in parts[:2])
            if (d.get("health") or {}).get("state") == "failing":
                sub += " · failing: image it first"
            card = ChoiceCard(d["path"], kind_icon(d.get("kind", "")), d.get("display_name") or d["path"], sub)
            card.clicked.connect(self._pick)
            self.grid.addWidget(card, i // 3, i % 3)
            self.cards[d["path"]] = card
        self.no_disks.setVisible(not disks)
        if self.selected_path not in self.cards:
            self.selected_path = next(iter(self.cards), None)
        self._pick(self.selected_path)

    def _pick(self, path) -> None:
        self.selected_path = path
        for p, c in self.cards.items():
            c.set_selected(p == path)

    def start_with(self, path: str) -> None:
        if self.running():
            return
        self.outer.setCurrentIndex(0)
        self._pick(path)

    def start(self) -> None:
        if not self.selected_path:
            self.bridge.message.emit("Choose the card or disk first", "warning")
            return
        cats = [k for k, c in self.kinds.items() if c.isChecked()] or ["photo"]
        self.cats = cats
        disk = next((d for d in self.bridge.disks if d["path"] == self.selected_path), {})

        def go():
            self.bridge.call("start_scan", done=self._started, source=self.selected_path,
                             options={"mode": "photos", "formats": cats}, name=disk.get("display_name") or "")
        if self.bridge.privileged or disk.get("is_image"):
            go()
        else:
            self.bridge.ensure_access(go)

    def _started(self, job: dict) -> None:
        self.scan_path = job.get("scan") or ""
        self.job_kind = "scan"
        self.progress_view.reset()
        self.jobview.t_done.caption.setText("Searched")
        self.run_job(job)

    def job_data(self, job: dict) -> None:
        if self.job_kind == "scan":
            self.progress_view.update_job(job)

    def finish_run(self) -> None:
        job = self.jobview.job or {}
        self.job_id = None
        if self.job_kind == "scan" and job.get("state") in ("done", "cancelled") and self.scan_path:
            self.show_results()
        elif self.job_kind == "recover":
            self.outer.setCurrentIndex(2)
        else:
            self.outer.setCurrentIndex(0)

    # ------------------------------------------------------------------ results
    def _build_results(self) -> None:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        head = QFrame()
        head.setObjectName("Card")
        hl = QHBoxLayout(head)
        hl.setContentsMargins(14, 10, 14, 10)
        self.r_title = QLabel("")
        self.r_title.setFont(scaled_font(self.r_title, 1.2, bold=True))
        hl.addWidget(self.r_title, 1)
        self.only_deleted = QCheckBox("Only deleted ones")
        self.only_deleted.setChecked(True)
        self.only_deleted.toggled.connect(lambda _o: self.reload())
        self.hide_small = QCheckBox("Hide small images (icons, thumbnails)")
        self.hide_small.setChecked(True)
        self.hide_small.toggled.connect(lambda _o: self.reload())
        hl.addWidget(self.only_deleted)
        hl.addWidget(self.hide_small)
        b = icon_button("Search again", "scan", "ghost")
        b.clicked.connect(lambda: self.outer.setCurrentIndex(0))
        hl.addWidget(b)
        lay.addWidget(head)
        split = QSplitter(Qt.Horizontal)
        gal = Card("Found", "grid")
        self.btn_all = gal.add_header_widget(icon_button("Select all", "check", "ghost"))
        self.btn_all.clicked.connect(lambda: self.model.check_all(True))
        self.btn_none = gal.add_header_widget(icon_button("None", "close", "ghost"))
        self.btn_none.clicked.connect(lambda: self.model.check_all(False))
        self.model = GalleryModel(self.bridge, self)
        self.view = QListView()
        self.view.setViewMode(QListView.IconMode)
        self.view.setResizeMode(QListView.Adjust)
        self.view.setMovement(QListView.Static)
        self.view.setUniformItemSizes(True)
        self.view.setSpacing(4)
        self.view.setModel(self.model)
        self.view.setItemDelegate(TileDelegate(self.model, self.view))
        self.view.setSelectionMode(QListView.SingleSelection)
        self.view.selectionModel().currentChanged.connect(self._current)
        gal.add(self.view, 1)
        self.legend = QLabel("Dots: green = should open fine, amber = probably fine, red = partly overwritten. "
                             "Click the box (or double-click) to choose.")
        self.legend.setObjectName("Faint")
        self.legend.setWordWrap(True)
        gal.add(self.legend)
        split.addWidget(gal)
        self.preview = PreviewPanel(self.bridge)
        self.preview.recover.connect(lambda i: self.recover([i], "this file"))
        split.addWidget(self.preview)
        split.setSizes([900, 380])
        lay.addWidget(split, 1)
        bottom = QFrame()
        bottom.setObjectName("Card")
        bl = QHBoxLayout(bottom)
        bl.setContentsMargins(14, 8, 14, 8)
        self.sel = QLabel("")
        self.sel.setObjectName("Muted")
        bl.addWidget(self.sel, 1)
        self.btn_rec_all = icon_button("Recover all shown…", "trash_restore", "ghost")
        self.btn_rec_all.clicked.connect(self._recover_all)
        self.btn_rec = icon_button("Recover selected…", "trash_restore", "primary")
        self.btn_rec.clicked.connect(lambda: self.recover(sorted(self.model.checked),
                                                          f"{len(self.model.checked)} files"))
        bl.addWidget(self.btn_rec_all)
        bl.addWidget(self.btn_rec)
        lay.addWidget(bottom)
        self.outer.addWidget(page)
        self.model.loaded.connect(self._loaded)
        self.model.checked_changed.connect(self._sel)
        self._sel()

    def show_results(self) -> None:
        self.outer.setCurrentIndex(2)
        self.bridge.call("open_scan", done=lambda _r: self.reload(), path=self.scan_path)

    def _filters(self) -> dict:
        f = {"cats": getattr(self, "cats", ["photo", "video"])}
        if self.only_deleted.isChecked():
            f["deleted"] = True
        if self.hide_small.isChecked():
            f["min_size"] = 50_000
        return f

    def reload(self) -> None:
        self.preview.clear()
        self.model.check_all(False)
        self.model.load(self.scan_path, self._filters())

    def _loaded(self, total: int) -> None:
        words = [FOUND_WORDS[k] for k, _n, _i in KINDS if k in getattr(self, "cats", ["photo"])]
        what = ", ".join(words[:-1]) + " and " + words[-1] if len(words) > 1 else (words[0] if words else "files")
        self.r_title.setText(f"{total:,} {what} found".replace(",", " ") if total else
                             "Nothing found with these filters")

    def _current(self, cur, _prev=None) -> None:
        r = self.model.data(cur, Qt.UserRole) if cur.isValid() else None
        if r:
            self.preview.show_entry(self.scan_path, r)

    def _sel(self) -> None:
        n = len(self.model.checked)
        size = sum(r["size"] for r in self.model.rows if r["id"] in self.model.checked)
        self.sel.setText(f"{n} selected ({fmt_bytes(size)})" if n else "Choose the files to recover, or recover all")
        self.btn_rec.setEnabled(bool(n))

    def _recover_all(self) -> None:
        def got(info):
            ids = [v["root_id"] for v in info.get("volumes") or [] if v.get("root_id")]
            self.recover(ids, f"all {self.model.total} files shown", self._filters())
        self.bridge.call("scan_info", done=got, scan=self.scan_path)

    def recover(self, ids: list[int], what: str, filters: dict | None = None) -> None:
        if not ids:
            return
        disk = next((d for d in self.bridge.disks if d["path"] == self.selected_path), {})
        dlg = RecoverDialog(self.gs, f"Recover {what}", disk.get("display_name") or "", self)
        if not dlg.exec():
            return
        dest, opts = dlg.value()

        def started(job):
            self.job_kind = "recover"
            self.jobview.t_done.caption.setText("Recovered")
            self.run_job(job)
        self.bridge.call("start_recover", done=started, scan=self.scan_path, entries=[int(i) for i in ids], dest=dest,
                         options=opts, filters=filters or {"cats": getattr(self, "cats", ["photo", "video"])})
