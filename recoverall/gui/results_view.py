"""The results of a scan, the way R-Studio and GetDataBack show them: the volumes found and their folders on
the left, the files of the chosen folder (or of a search) in the middle with checkboxes, and a preview on
the right. Everything is fetched page by page from the scan file, so millions of files are no problem."""

from __future__ import annotations

import base64
import time

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QImage, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QSplitter,
    QStackedWidget,
    QTableView,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.filetypes import CATEGORY_NAMES
from ..core.fs import fs_name
from ..core.util import fmt_bytes, fmt_when
from . import icons
from .theme import mono_font, theme
from .widgets import (
    CAT_ICONS,
    CAT_TOKENS,
    CHANCE_TEXT,
    CHANCE_TOKENS,
    Card,
    ElidedLabel,
    KeyValueGrid,
    SegmentedControl,
    badge,
    bind_icon,
    chip,
    icon_button,
    scaled_font,
    set_badge,
)

PAGE = 400
F_SYSTEM = 1 << 7
F_CARVED = 1 << 10
F_THUMBNAIL = 1 << 13
F_ORPHAN = 1 << 5

CHANCE_HELP = {3: "Its data is all there: it should open fine.",
               2: "Where its data is was worked out (a deleted file assumed to be in one piece, or its end found "
                  "by its content): it usually opens.",
               1: "Newer files were written over parts of it: it may not open, or only partly.",
               0: "Unknown."}
STATUS_TEXT = {"existing": "", "deleted partition": "deleted partition", "damaged": "damaged",
               "reconstructed": "rebuilt", "carved": "", "unknown filesystem": "unknown", "found": "found"}

SIZE_FILTERS = [("Any size", 0), ("Over 10 kB", 10_000), ("Over 100 kB", 100_000), ("Over 1 MB", 1_000_000),
                ("Over 10 MB", 10_000_000), ("Over 100 MB", 100_000_000)]
DATE_FILTERS = [("Any time", 0), ("Last 7 days", 7), ("Last 30 days", 30), ("Last 12 months", 365),
                ("Before this year", -1)]


def hexdump(data: bytes, base: int = 0) -> str:
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "·" for b in chunk)
        out.append(f"{base + i:08x}  {hx:<47}  {asc}")
    return "\n".join(out)


class Selection(QObject):
    """What is checked for recovery, the way R-Studio marks files: checking a folder takes everything in it,
    subfolders too, and unchecking something inside a checked folder leaves just that out.

    Only what the user marked is kept: INCLUDE (checked) and EXCLUDE (unchecked inside a checked folder),
    each with the folders above it (nearest first). That is enough to show every row and folder as
    checked, unchecked or partly checked without asking the scan, and the recovery gets the same two lists."""

    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.include: dict[int, dict] = {}
        self.exclude: dict[int, dict] = {}
        self.chains: dict[int, tuple[int, ...]] = {}
        self._on_below: dict[int, int] = {}     # folder → marked-checked entries under it
        self._off_below: dict[int, int] = {}    # folder → marked-unchecked entries under it

    def __bool__(self) -> bool:
        return bool(self.include)

    def clear(self) -> None:
        if self.include or self.exclude:
            self.include.clear()
            self.exclude.clear()
            self.chains.clear()
            self._on_below.clear()
            self._off_below.clear()
            self.changed.emit()

    def _inherited(self, chain) -> bool:
        for a in chain:
            if a in self.include:
                return True
            if a in self.exclude:
                return False
        return False

    def is_checked(self, eid: int, chain) -> bool:
        if eid in self.include:
            return True
        if eid in self.exclude:
            return False
        return self._inherited(chain)

    def state(self, eid: int, chain) -> Qt.CheckState:
        on = self.is_checked(eid, chain)
        if (self._off_below if on else self._on_below).get(eid):
            return Qt.PartiallyChecked
        return Qt.Checked if on else Qt.Unchecked

    def _unmark(self, eid: int) -> None:
        on = self.include.pop(eid, None) is not None
        off = self.exclude.pop(eid, None) is not None
        below = self._on_below if on else self._off_below if off else None
        for a in self.chains.pop(eid, ()):
            if below is not None:
                below[a] -= 1
                if not below[a]:
                    del below[a]

    def set(self, items, on: bool) -> None:
        """Check (ON) or uncheck each (row, chain) of ITEMS. A folder takes everything under it: what was
        checked or unchecked inside it before no longer counts."""
        for row, chain in items:
            eid = int(row["id"])
            if row.get("is_dir"):
                inside = [m for m, ch in self.chains.items() if eid in ch]
                for m in inside:
                    self._unmark(m)
            self._unmark(eid)
            chain = tuple(int(a) for a in chain)
            if on != self._inherited(chain):
                (self.include if on else self.exclude)[eid] = row
                self.chains[eid] = chain
                below = self._on_below if on else self._off_below
                for a in chain:
                    below[a] = below.get(a, 0) + 1
        self.changed.emit()


class FileModel(QAbstractTableModel):
    """The files of one folder (or a search), loaded in pages through the bridge."""

    COLS = ["Name", "Size", "Modified", "Type", "State"]
    loaded = Signal(int)                     # total

    def __init__(self, bridge, selection: Selection, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.sel = selection
        self.scan = ""
        self.rows: list[dict] = []
        self.total = 0
        self.mode = "folder"
        self.parent_id: int | None = None
        self.chain: tuple[int, ...] = ()           # folder mode: the shown folder and the folders above it
        self.anc: dict[int, tuple[int, ...]] = {}  # search mode: the folders above each row
        self.filters: dict = {}
        self.sort_key = "name"
        self.desc = False
        self._gen = 0
        self._loading = False
        theme.changed.connect(lambda _p: self._refresh_view())

    def _refresh_view(self) -> None:
        if self.rows:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.rows) - 1, self.columnCount() - 1))

    def refresh_checks(self) -> None:
        if self.rows:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.rows) - 1, 0), [Qt.CheckStateRole])

    def row_chain(self, r: dict) -> tuple[int, ...]:
        """The folders above row R, nearest first."""
        if self.mode == "folder":
            return self.chain
        got = self.anc.get(r["id"])
        if got is not None:
            return got
        return (r["parent"],) if r.get("parent") is not None else ()

    def set_chain(self, chain) -> None:
        self.chain = tuple(chain)
        self.refresh_checks()

    def _ancestors(self, rows: list[dict]) -> None:
        """Search results come from anywhere: ask which folders are above them (to show checks inherited
        from a checked folder)."""
        want = [r["id"] for r in rows if r["id"] not in self.anc]
        if not want:
            return
        gen = self._gen

        def got(res):
            if gen != self._gen:
                return
            for k, v in (res or {}).items():
                self.anc[int(k)] = tuple(v)
            self.refresh_checks()
        self.bridge.call("scan_ancestors", done=got, error=lambda e: None, scan=self.scan, entries=want)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return len(self.COLS) + (1 if self.mode == "search" else 0)

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.rows)

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            cols = self.COLS + (["Folder"] if self.mode == "search" else [])
            return cols[section]
        return None

    def load(self, scan: str, mode: str, parent_id: int | None, filters: dict, sort: str | None = None,
             desc: bool | None = None, chain=None) -> None:
        if scan != self.scan:
            self.anc = {}
        self.scan = scan
        self.mode = mode
        self.parent_id = parent_id
        if chain is not None:
            self.chain = tuple(chain)
        self.filters = dict(filters)
        if sort is not None:
            self.sort_key = sort
        if desc is not None:
            self.desc = desc
        self._gen += 1
        self.beginResetModel()
        self.rows = []
        self.total = 0
        self.endResetModel()
        self._fetch(0)

    def _fetch(self, offset: int) -> None:
        if not self.scan:
            return
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
                if self.mode == "search":
                    self._ancestors(rows)
            self.loaded.emit(self.total)

        def fail(e):
            self._loading = False
            self.bridge.message.emit(str(e), "error")
        if self.mode == "search":
            self.bridge.call("scan_search", done=got, error=fail, scan=self.scan, filters=self.filters,
                             offset=offset, limit=PAGE, sort=self.sort_key, desc=self.desc)
        elif self.parent_id is not None:
            self.bridge.call("scan_children", done=got, error=fail, scan=self.scan, parent=self.parent_id,
                             offset=offset, limit=PAGE, sort=self.sort_key, desc=self.desc, filters=self.filters)

    def canFetchMore(self, parent=QModelIndex()) -> bool:  # noqa: N802
        return not parent.isValid() and not self._loading and len(self.rows) < self.total

    def fetchMore(self, parent=QModelIndex()) -> None:  # noqa: N802
        if self.canFetchMore(parent):
            self._fetch(len(self.rows))

    def sort_by(self, column: int, order) -> None:
        key = {0: "name", 1: "size", 2: "mtime", 3: "type", 4: "chance", 5: "path"}.get(column, "name")
        self.load(self.scan, self.mode, self.parent_id, self.filters, key, order == Qt.DescendingOrder)

    def flags(self, index):
        f = Qt.ItemIsEnabled | Qt.ItemIsSelectable
        if index.column() == 0:
            f |= Qt.ItemIsUserCheckable
        return f

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self.rows):
            return None
        r = self.rows[index.row()]
        col = index.column()
        pal = theme.palette
        if role == Qt.DisplayRole:
            if col == 0:
                return r["name"] or "(no name)"
            if col == 1:
                return "" if r["is_dir"] else fmt_bytes(r["size"])
            if col == 2:
                return fmt_when(r.get("mtime")) if r.get("mtime") else ""
            if col == 3:
                if r["is_dir"]:
                    n = r.get("children")
                    return f"Folder · {n} item{'s' if n != 1 else ''}" if n is not None else "Folder"
                return (r.get("ext") or "").upper() or CATEGORY_NAMES.get(r.get("cat") or "", "File")
            if col == 4:
                if r["is_dir"]:
                    return "Deleted" if r["deleted"] else ""
                if r["flags"] & F_THUMBNAIL:
                    return "Thumbnail from a cache"
                if r["flags"] & F_CARVED:
                    return f"Found by signature · {CHANCE_TEXT.get(r['chance'], '')}"
                if r["deleted"]:
                    return f"Deleted · {CHANCE_TEXT.get(r['chance'], '')}"
                return "Existing"
            if col == 5:
                return r.get("path") or ""
        elif role == Qt.DecorationRole:
            if col == 0:
                name = "folder" if r["is_dir"] else CAT_ICONS.get(r.get("cat") or "other", "file")
                token = "text_muted" if r["is_dir"] else CAT_TOKENS.get(r.get("cat") or "other", "text_muted")
                if r["deleted"] and r["is_dir"]:
                    token = "warning"
                return icons.icon(name, getattr(pal, token))
            if col == 4 and not r["is_dir"] and (r["deleted"] or r["flags"] & F_CARVED):
                return _dot(getattr(pal, CHANCE_TOKENS.get(r["chance"], "text_faint")))
        elif role == Qt.CheckStateRole and col == 0:
            return self.sel.state(r["id"], self.row_chain(r))
        elif role == Qt.ForegroundRole:
            if r["deleted"] and col == 0:
                return QColor(pal.text)
            if col in (2, 3, 5):
                return QColor(pal.text_muted)
            if col == 4 and r["deleted"]:
                return QColor(getattr(pal, CHANCE_TOKENS.get(r["chance"], "text_muted")))
        elif role == Qt.FontRole and col == 0 and r["deleted"]:
            f = QFont()
            f.setItalic(True)
            return f
        elif role == Qt.TextAlignmentRole and col == 1:
            return int(Qt.AlignRight | Qt.AlignVCenter)
        elif role == Qt.ToolTipRole and col == 4 and not r["is_dir"]:
            return CHANCE_HELP.get(r["chance"]) if (r["deleted"] or r["flags"] & F_CARVED) else "Not deleted"
        elif role == Qt.UserRole:
            return r
        return None

    def setData(self, index, value, role=Qt.EditRole) -> bool:  # noqa: N802
        if role == Qt.CheckStateRole and index.column() == 0:
            r = self.rows[index.row()]
            on = value in (Qt.Checked, Qt.Checked.value, 2)
            self.sel.set([(r, self.row_chain(r))], on)
            return True
        return False

    def all_rows(self, done, limit: int = 50_000) -> None:
        """Every row of this listing (pages not loaded yet are fetched, and in a search the folders above
        each row), then DONE(rows); DONE(None) when there are more than LIMIT."""
        if self.total > limit:
            done(None)
            return
        gen = self._gen

        def finish():
            need = [r["id"] for r in self.rows if r["id"] not in self.anc] if self.mode == "search" else []
            if not need:
                done(list(self.rows))
                return

            def anc(res):
                if gen != self._gen:
                    return
                for k, v in (res or {}).items():
                    self.anc[int(k)] = tuple(v)
                done(list(self.rows))
            self.bridge.call("scan_ancestors", done=anc, scan=self.scan, entries=need)

        def got(res):
            if gen != self._gen:
                return
            rest = res.get("rows") or []
            if rest:
                self.beginInsertRows(QModelIndex(), len(self.rows), len(self.rows) + len(rest) - 1)
                self.rows.extend(rest)
                self.endInsertRows()
            finish()
        n = self.total - len(self.rows)
        if n <= 0:
            finish()
        elif self.mode == "search":
            self.bridge.call("scan_search", done=got, scan=self.scan, filters=self.filters, offset=len(self.rows),
                             limit=n, sort=self.sort_key, desc=self.desc)
        elif self.parent_id is not None:
            self.bridge.call("scan_children", done=got, scan=self.scan, parent=self.parent_id, offset=len(self.rows),
                             limit=n, sort=self.sort_key, desc=self.desc, filters=self.filters)


_DOTS: dict[str, QPixmap] = {}


def _dot(color: str) -> QPixmap:
    px = _DOTS.get(color)
    if px is None:
        from PySide6.QtGui import QPainter
        px = QPixmap(20, 20)
        px.setDevicePixelRatio(2.0)
        px.fill(Qt.transparent)
        p = QPainter(px)
        p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(QColor(color))
        p.setPen(Qt.NoPen)
        p.drawEllipse(2, 3, 6, 6)
        p.end()
        _DOTS[color] = px
    return px


def _exif_date(text: str) -> str:
    """EXIF writes "2021:10:21 12:00:00"; show it like the other dates ("2021-10-21 12:00")."""
    t = text.strip()
    if len(t) >= 16 and t[4] == ":" and t[7] == ":":
        return f"{t[:4]}-{t[5:7]}-{t[8:10]} {t[11:16]}"
    return t


class PreviewPanel(Card):
    """What the selected file is, how likely it is to come back, and what it looks like."""

    recover = Signal(int)

    def __init__(self, bridge, parent=None):
        super().__init__("Preview", "eye", parent)
        self.bridge = bridge
        self.scan = ""
        self.entry: dict | None = None
        self._gen = 0
        self.setMinimumWidth(300)
        self.badge = self.add_header_widget(badge("", "BadgeIdle"))
        self.badge.hide()
        self.title = ElidedLabel("Choose a file")
        self.title.setFont(scaled_font(self.title, 1.12, bold=True))
        self.add(self.title)
        self.path = ElidedLabel("")
        self.path.setObjectName("Faint")
        self.add(self.path)
        self.stack = QStackedWidget()
        self.image = QLabel()
        self.image.setAlignment(Qt.AlignCenter)
        self.image.setMinimumHeight(180)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setObjectName("Log")
        self.hex = QPlainTextEdit()
        self.hex.setReadOnly(True)
        self.hex.setObjectName("Log")
        self.hex.setFont(mono_font(8.5))
        self.hex.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.empty = QLabel("Point at a file to preview it")
        self.empty.setObjectName("Empty")
        self.empty.setAlignment(Qt.AlignCenter)
        self.empty.setWordWrap(True)
        for w in (self.empty, self.image, self.text, self.hex):
            self.stack.addWidget(w)
        self.add(self.stack, 1)
        self.note = QLabel()
        self.note.setWordWrap(True)
        self.note.setObjectName("BannerWarn")
        self.note.hide()
        self.add(self.note)
        self.grid = KeyValueGrid()
        self.add(self.grid)
        self.chance = QLabel()
        self.chance.setWordWrap(True)
        self.chance.setObjectName("Muted")
        self.add(self.chance)
        row = QHBoxLayout()
        self.btn_hex = icon_button("Hex", "hex", "ghost", "Show the first bytes")
        self.btn_hex.setCheckable(True)
        self.btn_hex.toggled.connect(self._toggle_hex)
        self.btn_recover = icon_button("Recover this file…", "trash_restore", "primary")
        self.btn_recover.clicked.connect(lambda: self.entry and self.recover.emit(self.entry["id"]))
        self.btn_recover.setEnabled(False)
        row.addWidget(self.btn_hex)
        row.addStretch(1)
        row.addWidget(self.btn_recover)
        self.add_layout(row)
        self._pix: QPixmap | None = None
        self._kind = "empty"

    def clear(self) -> None:
        self.entry = None
        self.title.setText("Choose a file")
        self.path.setText("")
        self.stack.setCurrentWidget(self.empty)
        self.grid.clear()
        self.chance.setText("")
        self.note.hide()
        self.badge.hide()
        self.btn_recover.setEnabled(False)

    def show_entry(self, scan: str, row: dict) -> None:
        self.scan = scan
        self.entry = row
        self._gen += 1
        gen = self._gen
        self.title.setText(row["name"] or "(no name)")
        self.btn_recover.setEnabled(True)
        self.btn_recover.setText("Recover this folder…" if row["is_dir"] else "Recover this file…")
        self.note.hide()
        if row["is_dir"]:
            self.stack.setCurrentWidget(self.empty)
            self.empty.setText(f"Folder with {row.get('children', '?')} items")
        else:
            self.empty.setText("Loading the preview…")
            self.stack.setCurrentWidget(self.empty)
        if row["is_dir"]:
            set_badge(self.badge, "DELETED FOLDER" if row["deleted"] else "FOLDER",
                      "BadgeWarn" if row["deleted"] else "BadgeIdle")
        elif row["flags"] & F_THUMBNAIL:
            set_badge(self.badge, "THUMBNAIL", "BadgeInfo")
        elif row["flags"] & F_CARVED:
            set_badge(self.badge, "FOUND BY SIGNATURE", "BadgeInfo")
        elif row["deleted"]:
            set_badge(self.badge, "DELETED", "BadgeWarn")
        else:
            set_badge(self.badge, "EXISTING", "BadgeOk")
        self.badge.show()
        self.bridge.call("scan_entry", done=lambda e: gen == self._gen and self._details(e), error=lambda e: None,
                         scan=scan, entry=row["id"])
        if not row["is_dir"]:
            self.bridge.call("preview", done=lambda p: gen == self._gen and self._preview(p),
                             error=lambda e: gen == self._gen and self._failed(e), scan=scan, entry=row["id"])

    def _details(self, e: dict) -> None:
        vol = e.get("volume") or {}
        self.path.setText(f"{vol.get('name') or ''}/{e.get('path') or ''}")
        self.path.setToolTip(self.path.full_text())
        rows = [("Size", fmt_bytes(e.get("size")) if not e.get("is_dir") else "")]
        if e.get("mtime"):
            rows.append(("Modified", fmt_when(e["mtime"])))
        if e.get("crtime"):
            rows.append(("Created", fmt_when(e["crtime"])))
        what = "the signature search" if e.get("flags", 0) & F_CARVED or vol.get("fstype") == "carved" else \
            f"{fs_name(vol.get('fstype'))} metadata" + (" (no folder known)" if e.get("flags", 0) & F_ORPHAN else "")
        extra = e.get("extra") or {}
        if e.get("flags", 0) & F_THUMBNAIL:
            what = extra.get("source") or "a thumbnail cache"
        rows.append(("Found through", what))
        if extra.get("original"):
            rows.append(("Thumbnail of", extra["original"]))
        if extra.get("desc"):
            rows.append(("Type", extra["desc"]))
        info = extra.get("info") or {}
        if info.get("width"):
            rows.append(("Picture", f"{info['width']} × {info['height']}"))
        if info.get("camera") or info.get("model"):
            rows.append(("Camera", info.get("camera") or info.get("model")))
        if e.get("fragments", 0) > 1:
            rows.append(("Pieces", f"{e['fragments']} fragments"))
        if e.get("first_offset") is not None:
            rows.append(("Starts at", f"{fmt_bytes(e['first_offset'])} (sector {e['first_offset'] // 512:,})".replace(
                ",", " ")))
        self.grid.set_rows(rows)
        if e.get("is_dir"):
            self.chance.setText("Recovering a folder recovers everything in it, subfolders too.")
        elif e.get("flags", 0) & F_THUMBNAIL:
            self.chance.setText("A small copy of a photo that Windows, Linux, macOS or Android kept for the file "
                                "browser. It comes back whole, even when the photo itself is gone.")
        elif e.get("deleted") or e.get("flags", 0) & F_CARVED:
            self.chance.setText(f"<b>Recovery chance: {CHANCE_TEXT.get(e.get('chance'), '?').lower()}.</b> "
                                f"{CHANCE_HELP.get(e.get('chance'), '')}")
        else:
            self.chance.setText("Not deleted: it copies as it is.")

    def _preview(self, p: dict) -> None:
        self._hex = base64.b64decode(p.get("hex") or "")
        if p.get("note"):
            self.note.setText(p["note"])
            self.note.show()
        info = p.get("info") or {}
        if info:
            extra = []
            if info.get("width"):
                extra.append(("Picture", f"{info['width']} × {info['height']}"))
            cam = " ".join(x for x in (info.get("make"), info.get("model")) if x)
            if cam and not (info.get("model") and info.get("make") and info["make"] in info["model"]):
                extra.append(("Camera", cam))
            elif info.get("model"):
                extra.append(("Camera", info["model"]))
            if info.get("date"):
                extra.append(("Taken", _exif_date(str(info["date"]))))
            for k in ("title", "author", "pages", "members"):
                if info.get(k):
                    extra.append((k.title(), str(info[k])))
            for k, v in extra:
                self.grid.add_row(k, v)
        for k, v in p.get("details") or []:
            self.grid.add_row(k, v)
        kind = p.get("kind")
        if kind == "video":
            if not p.get("data"):
                self._kind = "empty"
                self.stack.setCurrentWidget(self.empty)
                self.empty.setText("No picture from this video" if not p.get("note") else "")
                return
            kind = "image"
        self._kind = kind
        if kind == "image" and p.get("data"):
            img = QImage.fromData(base64.b64decode(p["data"]))
            if not img.isNull():
                self._pix = QPixmap.fromImage(img)
                self._fit()
                self.stack.setCurrentWidget(self.image)
                return
            self.note.setText((self.note.text() + " " if self.note.isVisible() else "") +
                              "The picture data doesn't decode: it is damaged (Repair can sometimes help).")
            self.note.show()
            kind = "hex"
        if kind == "text":
            self.text.setPlainText(p.get("text") or "")
            self.stack.setCurrentWidget(self.text)
            return
        self.hex.setPlainText(hexdump(self._hex[:4096]))
        self.stack.setCurrentWidget(self.hex if kind == "hex" else self.empty)
        if kind not in ("hex",):
            self.empty.setText("No preview for this type")

    def _failed(self, e) -> None:
        self.empty.setText(f"No preview: {e}")
        self.stack.setCurrentWidget(self.empty)

    def _toggle_hex(self, on: bool) -> None:
        if on:
            self.hex.setPlainText(hexdump(getattr(self, "_hex", b"")[:4096]))
            self.stack.setCurrentWidget(self.hex)
        elif self._kind == "image" and self._pix is not None:
            self.stack.setCurrentWidget(self.image)
        elif self._kind == "text":
            self.stack.setCurrentWidget(self.text)

    def _fit(self) -> None:
        if self._pix is None:
            return
        size = self.image.size() - QSize(8, 8)
        if size.width() < 50 or size.height() < 50:
            size = QSize(360, 260)
        self.image.setPixmap(self._pix.scaled(size, Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def resizeEvent(self, e) -> None:  # noqa: N802
        super().resizeEvent(e)
        if self._kind == "image":
            QTimer.singleShot(0, self._fit)


class ResultsView(QWidget):
    """The browser. Signals: recover(ids, filters, what, exclude) and new_scan()."""

    recover = Signal(list, dict, str, list)
    new_scan = Signal()
    save_scan = Signal(str)

    def __init__(self, bridge, gs, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.gs = gs
        self.scan = ""
        self.info: dict = {}
        self.folder: int | None = None
        self.folder_name = ""
        self._suppress = False
        self.sel = Selection(self)
        self.sel.changed.connect(self._sel_changed)
        self._sel_stats: dict | None = None
        self._sel_gen = 0
        self._count_timer = QTimer(self, singleShot=True, interval=250)
        self._count_timer.timeout.connect(self._count)
        self._tree_busy = False
        self._chains: dict[int, tuple[int, ...]] = {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)

        # ---------------------------------------------------------- header
        head = QFrame()
        head.setObjectName("Card")
        hl = QHBoxLayout(head)
        hl.setContentsMargins(14, 10, 14, 10)
        hl.setSpacing(12)
        ic = QLabel()
        self._hic = bind_icon(ic, "folder_search", "accent", 26)
        hl.addWidget(ic)
        col = QVBoxLayout()
        col.setSpacing(1)
        self.h_title = ElidedLabel("")
        self.h_title.setFont(scaled_font(self.h_title, 1.15, bold=True))
        self.h_sub = QLabel("")
        self.h_sub.setObjectName("Muted")
        col.addWidget(self.h_title)
        col.addWidget(self.h_sub)
        hl.addLayout(col, 1)
        self.btn_save = icon_button("Save scan…", "save", "ghost", "Keep these results in a file to come back later "
                                                                    "without scanning again")
        self.btn_save.clicked.connect(lambda: self.save_scan.emit(self.scan))
        self.btn_new = icon_button("New scan", "scan", "ghost")
        self.btn_new.clicked.connect(self.new_scan.emit)
        hl.addWidget(self.btn_save)
        hl.addWidget(self.btn_new)
        lay.addWidget(head)

        # ---------------------------------------------------------- filters
        fbar = QHBoxLayout()
        fbar.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search all found files: name, or *.jpg, IMG_2025*…")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(280)
        self._search_timer = QTimer(self, singleShot=True, interval=350)
        self._search_timer.timeout.connect(self.reload)
        self.search.textChanged.connect(lambda _t: self._search_timer.start())
        fbar.addWidget(self.search, 2)
        self.state = SegmentedControl()
        self.state.add("All", None, "Deleted and existing files")
        self.state.add("Deleted", True, "Only deleted and lost files")
        self.state.add("Existing", False, "Only files that weren't deleted")
        self.state.set_value(None)
        self.state.changed.connect(lambda _v: self.reload())
        fbar.addWidget(self.state)
        self.good = chip("Good chances only")
        self.good.toggled.connect(lambda _o: self.reload())
        fbar.addWidget(self.good)
        self.more = QToolButton()
        self.more.setObjectName("Chip")
        self.more.setText("More filters")
        self.more.setPopupMode(QToolButton.InstantPopup)
        menu = QMenu(self.more)
        self.size_actions = []
        sm = menu.addMenu("Size")
        for label, v in SIZE_FILTERS:
            a = sm.addAction(label)
            a.setCheckable(True)
            a.setChecked(v == 0)
            a.triggered.connect(lambda _c=False, v=v: self._set_size(v))
            self.size_actions.append((a, v))
        dm = menu.addMenu("Modified")
        self.date_actions = []
        for label, v in DATE_FILTERS:
            a = dm.addAction(label)
            a.setCheckable(True)
            a.setChecked(v == 0)
            a.triggered.connect(lambda _c=False, v=v: self._set_date(v))
            self.date_actions.append((a, v))
        menu.addSeparator()
        self.act_system = menu.addAction("Show filesystem metadata files")
        self.act_system.setCheckable(True)
        self.act_system.setChecked(gs.show_system)
        self.act_system.toggled.connect(lambda _o: (self.reload(), self._selection()))
        self.more.setMenu(menu)
        fbar.addWidget(self.more)
        lay.addLayout(fbar)
        cats = QHBoxLayout()
        cats.setSpacing(6)
        self.cat_chips: dict[str, QToolButton] = {}
        self.cat_all = chip("All types", True)
        self.cat_all.clicked.connect(self._all_types)
        cats.addWidget(self.cat_all)
        for key, name in CATEGORY_NAMES.items():
            c = chip(name)
            c.clicked.connect(self._cat_clicked)
            self.cat_chips[key] = c
            cats.addWidget(c)
        cats.addStretch(1)
        lay.addLayout(cats)
        self.min_size = 0
        self.days = 0

        # ---------------------------------------------------------- tree | table | preview
        split = QSplitter(Qt.Horizontal)
        left = Card("Found", "layers")
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setIconSize(QSize(18, 18))
        self.tree.itemExpanded.connect(self._expand)
        self.tree.currentItemChanged.connect(self._tree_select)
        self.tree.itemChanged.connect(self._tree_checked)
        left.add(self.tree, 1)
        self.legend = QLabel()
        self.legend.setObjectName("Faint")
        self.legend.setWordWrap(True)
        left.add(self.legend)
        left.setMinimumWidth(240)
        split.addWidget(left)

        mid = Card("Files", "list")
        self.where = mid.add_header_widget(QLabel(""))
        self.where.setObjectName("Muted")
        self.btn_all = mid.add_header_widget(icon_button("Check all", "check", "ghost",
                                                         "Check everything shown (a folder with all it holds)"))
        self.btn_all.clicked.connect(self._check_all)
        self.btn_none = mid.add_header_widget(icon_button("None", "close", "ghost", "Uncheck everything"))
        self.btn_none.clicked.connect(self.sel.clear)
        self.model = FileModel(bridge, self.sel, self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(False)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSortIndicator(0, Qt.AscendingOrder)
        self.table.horizontalHeader().sortIndicatorChanged.connect(self.model.sort_by)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table.setColumnWidth(0, 330)
        self.table.setColumnWidth(1, 90)
        self.table.setColumnWidth(2, 130)
        self.table.setColumnWidth(3, 110)
        self.table.setIconSize(QSize(18, 18))
        self.table.setWordWrap(False)
        self.table.doubleClicked.connect(self._open)
        self.table.selectionModel().currentRowChanged.connect(self._row)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        mid.add(self.table, 1)
        self.model.loaded.connect(self._loaded)
        split.addWidget(mid)

        self.preview = PreviewPanel(bridge)
        self.preview.recover.connect(lambda i: self.recover.emit([i], self._sel_filters(), "this file", []))
        split.addWidget(self.preview)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 5)
        split.setStretchFactor(2, 3)
        split.setSizes([280, 760, 380])
        lay.addWidget(split, 1)

        # ---------------------------------------------------------- bottom
        bottom = QFrame()
        bottom.setObjectName("Card")
        bl = QHBoxLayout(bottom)
        bl.setContentsMargins(14, 8, 14, 8)
        self.sel_text = QLabel("Check the files and folders to recover, or recover everything shown.")
        self.sel_text.setObjectName("Muted")
        bl.addWidget(self.sel_text, 1)
        self.btn_shown = icon_button("Recover everything shown…", "trash_restore", "ghost",
                                     "Every file in this folder (and its subfolders) that the filters let through")
        self.btn_shown.clicked.connect(self._recover_shown)
        self.btn_rec = icon_button("Recover checked…", "trash_restore", "primary",
                                   "The checked files, and everything in the checked folders (subfolders too)")
        self.btn_rec.clicked.connect(self._recover_checked)
        self.btn_rec.setEnabled(False)
        bl.addWidget(self.btn_shown)
        bl.addWidget(self.btn_rec)
        lay.addWidget(bottom)

    # ------------------------------------------------------------------ loading a scan
    def set_scan(self, scan: str) -> None:
        self.scan = scan
        self.sel.clear()
        self._chains.clear()
        self.preview.clear()
        self.bridge.call("scan_info", done=self._got_info, scan=scan)

    def _got_info(self, info: dict) -> None:
        self.info = info
        src = info.get("source") or {}
        st = info.get("stats") or {}
        mode = (info.get("options") or {}).get("mode") or "quick"
        from ..core.scan import MODE_TEXT
        self.h_title.setText(f"{src.get('display_name') or src.get('name') or 'Scan'}")
        state = {"complete": "", "cancelled": " · stopped early", "running": " · running"}.get(info.get("state"), "")
        self.h_sub.setText(f"{MODE_TEXT.get(mode, 'Scan')} · {fmt_when(info.get('created'))}{state} · "
                           f"{st.get('files', 0):,} files ({fmt_bytes(st.get('bytes'))}), "
                           f"{st.get('deleted_files', 0):,} deleted or lost".replace(",", " "))
        self.tree.clear()
        first = None
        first_score = (False, -1, -1)
        for v in info.get("volumes") or []:
            if not v.get("root_id"):
                continue
            item = QTreeWidgetItem()
            what = "Found by signature" if v.get("fstype") == "carved" else fs_name(v.get("fstype"))
            status = STATUS_TEXT.get(v.get("status") or "", v.get("status") or "")
            name = v.get("name") or what
            text = name if v.get("fstype") == "carved" or name == what else f"{name} · {what}"
            if status:
                text += f" · {status}"
            item.setText(0, text)
            item.setToolTip(0, f"{text}\n{fmt_bytes(v.get('size'))} at {fmt_bytes(v.get('offset'))}\n"
                               f"{v.get('files', 0)} files, {v.get('deleted_files', 0)} deleted"
                            + (f"\n{v['note']}" if v.get("note") else ""))
            token = {"deleted partition": "warning", "damaged": "warning", "reconstructed": "warning"}.get(
                v.get("status") or "", "accent")
            item.setIcon(0, theme.icon("search" if v.get("fstype") == "carved" else "partition", token))
            item.setData(0, Qt.UserRole, {"id": v["root_id"], "volume": v["id"], "name": text, "vol": True})
            item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(0, self.sel.state(v["root_id"], ()))
            self._tree_busy = True
            self.tree.addTopLevelItem(item)
            self._tree_busy = False
            # open on the volume with the most deleted files (not an empty EFI partition)
            score = (v.get("fstype") != "carved", v.get("deleted_files") or 0, v.get("files") or 0)
            if first is None or score > first_score:
                first, first_score = item, score
        for v in info.get("volumes") or []:
            if not v.get("root_id") and v.get("note"):
                item = QTreeWidgetItem()
                item.setText(0, f"{v.get('name')} · {fs_name(v.get('fstype'))}")
                item.setToolTip(0, v["note"])
                item.setIcon(0, theme.icon("lock" if "encrypt" in (v.get("state") or "") else "info", "text_faint"))
                item.setDisabled(True)
                self.tree.addTopLevelItem(item)
        self.legend.setText("Deleted partitions and damaged filesystems are listed as volumes; files whose folder is "
                            "unknown are in “Lost files”.")
        if first is not None:
            self.tree.setCurrentItem(first)
            first.setExpanded(True)
        self._counts()

    def _expand(self, item: QTreeWidgetItem) -> None:
        data = item.data(0, Qt.UserRole) or {}
        if data.get("loaded"):
            return
        data["loaded"] = True
        self._tree_busy = True
        item.setData(0, Qt.UserRole, data)
        self._tree_busy = False

        def got(rows):
            for r in rows:
                child = QTreeWidgetItem()
                n = r.get("children") or 0
                child.setText(0, r["name"] or "(no name)")
                child.setToolTip(0, f"{r['name']}\n{n} items" + ("\ndeleted folder" if r["deleted"] else ""))
                token = "warning" if r["deleted"] else ("accent" if r["flags"] & (1 << 12) else "text_muted")
                child.setIcon(0, theme.icon("folder", token))
                child.setData(0, Qt.UserRole, {"id": r["id"], "name": r["name"]})
                if r.get("subdirs"):
                    child.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
                else:
                    child.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
                child.setFlags(child.flags() | Qt.ItemIsUserCheckable)
                child.setCheckState(0, self.sel.state(r["id"], (data["id"],) + self._item_chain(item)))
                self._tree_busy = True
                item.addChild(child)
                self._tree_busy = False
            if not rows:
                item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
        self.bridge.call("scan_subdirs", done=got, scan=self.scan, parent=data["id"])

    def _tree_select(self, cur: QTreeWidgetItem | None, _prev=None) -> None:
        if cur is None:
            return
        data = cur.data(0, Qt.UserRole) or {}
        if "id" not in data:
            return
        self.folder = data["id"]
        self.folder_name = data.get("name") or ""
        if self.search.text().strip():
            self._suppress = True
            self.search.clear()
            self._suppress = False
        self.reload()

    # ------------------------------------------------------------------ filters
    def _file_filters(self) -> dict:
        f: dict = {}
        v = self.state.value()
        if v is not None:
            f["deleted"] = v
        if self.good.isChecked():
            f["chance"] = 3
        cats = [k for k, c in self.cat_chips.items() if c.isChecked()]
        if cats:
            f["cats"] = cats
        if self.min_size:
            f["min_size"] = self.min_size
        if self.days > 0:
            f["after"] = time.time() - self.days * 86400
        elif self.days < 0:
            f["before"] = time.mktime((time.localtime().tm_year, 1, 1, 0, 0, 0, 0, 0, -1))
        f["hide_system"] = not self.act_system.isChecked()
        return f

    def _set_size(self, v: int) -> None:
        self.min_size = v
        for a, x in self.size_actions:
            a.setChecked(x == v)
        self.more.setText("More filters" + (" •" if v or self.days else ""))
        self.reload()

    def _set_date(self, v: int) -> None:
        self.days = v
        for a, x in self.date_actions:
            a.setChecked(x == v)
        self.more.setText("More filters" + (" •" if v or self.min_size else ""))
        self.reload()

    def _all_types(self) -> None:
        for c in self.cat_chips.values():
            c.setChecked(False)
        self.cat_all.setChecked(True)
        self.reload()

    def _cat_clicked(self) -> None:
        any_on = any(c.isChecked() for c in self.cat_chips.values())
        self.cat_all.setChecked(not any_on)
        self.reload()

    def reload(self) -> None:
        if self._suppress or not self.scan:
            return
        f = self._file_filters()
        text = self.search.text().strip()
        if text:
            f["name"] = text
            self.model.load(self.scan, "search", None, f)
            self.where.setText(f"Search: {text}")
        elif self.folder is not None:
            self.model.load(self.scan, "folder", self.folder, f, chain=self._folder_chain(self.folder))
            self.where.setText(self.folder_name)
        self.table.horizontalHeader().setStretchLastSection(True)
        self._counts()

    def _counts(self) -> None:
        f = self._file_filters()
        f.pop("cats", None)

        def got(counts):
            total = 0
            for key, c in self.cat_chips.items():
                n = (counts.get(key) or {}).get("files", 0)
                total += n
                c.setText(f"{CATEGORY_NAMES[key]}  {n:,}".replace(",", " ") if n else CATEGORY_NAMES[key])
                c.setVisible(bool(n) or c.isChecked())
            self.cat_all.setText(f"All types  {total:,}".replace(",", " "))
        if self.scan:
            self.bridge.call("scan_counts", done=got, error=lambda e: None, scan=self.scan, filters=f)

    def _loaded(self, total: int) -> None:
        mode = self.model.mode
        if mode == "search":
            self.where.setText(f"{total:,} files match".replace(",", " "))
        else:
            self.where.setText(f"{self.folder_name} · {total:,} items".replace(",", " ") if self.folder_name else
                               f"{total:,} items".replace(",", " "))
        if self.table.selectionModel().currentIndex().row() < 0 and self.model.rows:
            self.table.selectRow(0)

    # ------------------------------------------------------------------ rows
    def _row(self, cur, _prev=None) -> None:
        r = self.model.data(cur, Qt.UserRole) if cur.isValid() else None
        if r:
            self.preview.show_entry(self.scan, r)

    def _open(self, index) -> None:
        r = self.model.data(index, Qt.UserRole)
        if not r or not r["is_dir"]:
            return
        self._select_folder(r["id"], r["name"])

    def _select_folder(self, fid: int, name: str) -> None:
        cur = self.tree.currentItem()
        if cur is not None:
            cur.setExpanded(True)
            for i in range(cur.childCount()):
                ch = cur.child(i)
                if (ch.data(0, Qt.UserRole) or {}).get("id") == fid:
                    self.tree.setCurrentItem(ch)
                    return
        self.folder = fid
        self.folder_name = name
        self.search.clear()
        self.reload()

    def _menu(self, pos) -> None:
        idx = self.table.indexAt(pos)
        r = self.model.data(idx, Qt.UserRole) if idx.isValid() else None
        m = QMenu(self)
        rows = self._selected_rows()
        if rows:
            m.addAction(theme.icon("trash_restore"), f"Recover {len(rows)} selected…",
                        lambda: self.recover.emit([x["id"] for x in rows], self._sel_filters(),
                                                  f"{len(rows)} selected items", []))
            m.addAction(theme.icon("check"), "Check the selected", lambda: self._check_rows(rows, True))
            m.addAction(theme.icon("close"), "Uncheck the selected", lambda: self._check_rows(rows, False))
        if r and r["is_dir"]:
            m.addAction(theme.icon("open"), "Open the folder", lambda: self._select_folder(r["id"], r["name"]))
        m.exec(self.table.viewport().mapToGlobal(pos))

    def _selected_rows(self) -> list[dict]:
        out = []
        for idx in self.table.selectionModel().selectedRows():
            r = self.model.data(idx, Qt.UserRole)
            if r:
                out.append(r)
        return out

    def _check_rows(self, rows: list[dict], on: bool) -> None:
        self.sel.set([(r, self.model.row_chain(r)) for r in rows], on)

    def _check_all(self) -> None:
        def got(rows):
            if rows is None:
                self.bridge.message.emit("Too many to check one by one: “Recover everything shown” takes them all",
                                         "warning")
                return
            self.sel.set([(r, self.model.row_chain(r)) for r in rows], True)
        self.model.all_rows(got)

    # ------------------------------------------------------------------ the checked selection
    def _sel_filters(self) -> dict:
        """What a checked selection goes through: only the metadata-files switch (checked is checked,
        whatever the view filters show)."""
        return {"hide_system": not self.act_system.isChecked()}

    def _item_chain(self, item: QTreeWidgetItem) -> tuple[int, ...]:
        """The folders above a tree item, nearest first."""
        out = []
        p = item.parent()
        while p is not None:
            d = p.data(0, Qt.UserRole) or {}
            if "id" in d:
                out.append(d["id"])
            p = p.parent()
        return tuple(out)

    def _folder_chain(self, fid: int) -> tuple[int, ...]:
        """The shown folder and the folders above it, for its rows' check marks: from the tree when the
        folder is there, else asked once from the scan."""
        cur = self.tree.currentItem()
        if cur is not None and (cur.data(0, Qt.UserRole) or {}).get("id") == fid:
            self._chains[fid] = self._item_chain(cur)
        if fid in self._chains:
            return (fid,) + self._chains[fid]

        def got(res):
            self._chains[fid] = tuple((res or {}).get(str(fid)) or ())
            if self.model.mode == "folder" and self.model.parent_id == fid:
                self.model.set_chain((fid,) + self._chains[fid])
        self.bridge.call("scan_ancestors", done=got, error=lambda e: None, scan=self.scan, entries=[fid])
        return (fid,)

    def _tree_checked(self, item: QTreeWidgetItem, column: int) -> None:
        if self._tree_busy or column != 0:
            return
        d = item.data(0, Qt.UserRole) or {}
        if "id" not in d:
            return
        # itemChanged also fires for text, icon and data changes: only a box that now differs from the
        # selection is the user's click (a click on a partly checked box checks it)
        chain = self._item_chain(item)
        new = item.checkState(0)
        if new == Qt.PartiallyChecked or new == self.sel.state(d["id"], chain):
            return
        self.sel.set([({"id": d["id"], "name": d.get("name") or "", "is_dir": True, "size": 0}, chain)],
                     new == Qt.Checked)

    def _refresh_tree(self) -> None:
        self._tree_busy = True
        try:
            def walk(item: QTreeWidgetItem, chain: tuple[int, ...]) -> None:
                d = item.data(0, Qt.UserRole) or {}
                if "id" in d:
                    st = self.sel.state(d["id"], chain)
                    if item.checkState(0) != st:
                        item.setCheckState(0, st)
                    chain = (d["id"],) + chain
                for i in range(item.childCount()):
                    walk(item.child(i), chain)
            for i in range(self.tree.topLevelItemCount()):
                walk(self.tree.topLevelItem(i), ())
        finally:
            self._tree_busy = False

    def _sel_changed(self) -> None:
        self.model.refresh_checks()
        self._refresh_tree()
        self._selection()

    def _selection(self) -> None:
        self._sel_gen += 1
        self._sel_stats = None
        if not self.sel:
            self._count_timer.stop()
            self.sel_text.setText("Check the files and folders to recover, or recover everything shown.")
            self.btn_rec.setEnabled(False)
            return
        self.sel_text.setText("Checked: counting…")
        self.btn_rec.setEnabled(True)
        self._count_timer.start()

    def _count(self) -> None:
        if not self.sel or not self.scan:
            return
        gen = self._sel_gen

        def got(st):
            if gen != self._sel_gen:
                return
            self._sel_stats = st
            n = st.get("files") or 0
            if not n:
                self.sel_text.setText("Checked: no files (the checked folders are empty, or hold only empty files)")
                self.btn_rec.setEnabled(False)
                return
            text = f"{n:,} file{'s' if n != 1 else ''} ({fmt_bytes(st.get('bytes'))})".replace(",", " ")
            d = st.get("deleted") or 0
            extra = f" · {d:,} deleted".replace(",", " ") if d else ""
            if self.sel.exclude:
                k = len(self.sel.exclude)
                extra += f" · {k} item{'s' if k != 1 else ''} left out"
            self.sel_text.setText(f"Checked: {text}{extra}")
            self.btn_rec.setEnabled(True)

        def fail(e):
            if gen == self._sel_gen:
                self.sel_text.setText("Checked: (couldn't count them)")
        self.bridge.call("scan_selection", done=got, error=fail, scan=self.scan, include=list(self.sel.include),
                         exclude=list(self.sel.exclude), filters=self._sel_filters())

    def _recover_checked(self) -> None:
        if not self.sel:
            return
        st = self._sel_stats
        if st:
            n = st.get("files") or 0
            what = f"{n:,} file{'s' if n != 1 else ''} ({fmt_bytes(st.get('bytes'))})".replace(",", " ")
        else:
            what = "the checked files and folders"
        self.recover.emit(list(self.sel.include), self._sel_filters(), what, list(self.sel.exclude))

    def _recover_shown(self) -> None:
        f = self._file_filters()
        if self.model.mode == "search":
            # every volume, through the same filters as the search (the name too)
            f["name"] = self.search.text().strip()
            ids = [v["root_id"] for v in self.info.get("volumes") or [] if v.get("root_id")]
            self.recover.emit(ids, f, f"the {self.model.total:,} files the search found".replace(",", " "), [])
        elif self.folder is not None:
            self.recover.emit([self.folder], f, f"everything in {self.folder_name or 'this folder'}", [])

    def clear(self) -> None:
        self.scan = ""
        self.tree.clear()
        self.model.load("", "folder", None, {})
        self.preview.clear()
