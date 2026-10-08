"""Maps of a whole disk as a grid of cells (like ddrescueview and R-Studio's scan view): the scan map
(what has been read, where filesystems and files were found, bad sectors) and the imaging map (copied,
still to try, failed, unreadable). One character per cell; a legend names the colours."""

from __future__ import annotations

import math

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QHBoxLayout, QLabel, QSizePolicy, QToolTip, QWidget

from ..core.util import fmt_bytes
from .theme import theme
from .widgets import scaled_font

# scan map (core.scan): . unread, - read, F filesystem structures, X bad, category letters for found files
SCAN_TOKENS = {".": "raised", "-": "text_faint@120", "F": "accent", "X": "danger", "p": "c2", "v": "c5", "a": "c6",
               "d": "c3", "z": "orange", "e": "c1", "b": "c1", "x": "c4", "o": "text_faint"}
SCAN_NAMES = {".": "Not read yet", "-": "Read", "F": "Filesystem found", "X": "Unreadable (bad sectors)",
              "p": "Photos", "v": "Videos", "a": "Music", "d": "Documents", "z": "Archives", "e": "E-mail",
              "b": "Databases", "x": "Programs", "o": "Other files"}

# imaging map (core.imaging, ddrescue's states)
IMAGE_TOKENS = {"+": "success", "?": "border_strong", "*": "warning", "/": "orange", "-": "danger"}
IMAGE_NAMES = {"+": "Copied", "?": "Not tried yet", "*": "Failed (trimmed next)", "/": "Failed (read sector by sector "
               "next)", "-": "Unreadable"}


def _color(pal, token: str) -> QColor:
    """A palette colour; "token@alpha" makes it translucent."""
    name, _sep, alpha = token.partition("@")
    c = QColor(getattr(pal, name))
    if alpha:
        c.setAlpha(int(alpha))
    return c


class CellMap(QWidget):
    def __init__(self, tokens: dict[str, str], names: dict[str, str], empty_text: str = "", parent=None):
        super().__init__(parent)
        self.tokens = tokens
        self.names = names
        self.cells = ""
        self.size = 0
        self.pos = -1
        self._cell = 8.0
        self._cols = 1
        self.empty_text = empty_text
        self.setMouseTracking(True)
        self.setMinimumHeight(180)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        theme.changed.connect(lambda _p: self.update())

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(640, 300)

    def set_map(self, cells: str, size: int, pos: int = -1) -> None:
        self.cells = cells or ""
        self.size = size
        self.pos = pos
        self.update()

    def clear(self) -> None:
        self.set_map("", 0)

    def _layout(self) -> tuple[int, float]:
        n = max(1, len(self.cells))
        w, h = max(1, self.width() - 4), max(1, self.height() - 4)
        cell = math.sqrt(w * h / n)
        cols = max(1, int(w // cell))
        while cols * cell > w or math.ceil(n / cols) * cell > h:
            cell *= 0.97
            cols = max(1, int(w // cell))
        return cols, cell

    def paintEvent(self, _event) -> None:  # noqa: N802
        pal = theme.palette
        p = QPainter(self)
        if not self.cells:
            p.setPen(QColor(pal.text_faint))
            p.drawText(self.rect(), Qt.AlignCenter | Qt.TextWordWrap, self.empty_text)
            return
        cols, cell = self._layout()
        self._cols, self._cell = cols, cell
        p.setRenderHint(QPainter.Antialiasing, cell >= 6)
        gap = 1.0 if cell >= 5 else 0.0
        rad = min(2.2, cell * 0.2)
        brushes = {k: _color(pal, t) for k, t in self.tokens.items()}
        default = QColor(pal.raised)
        p.setPen(Qt.NoPen)
        for i, st in enumerate(self.cells):
            r, c = divmod(i, cols)
            rect = QRectF(2 + c * cell, 2 + r * cell, cell - gap, cell - gap)
            p.setBrush(brushes.get(st, default))
            if rad > 0.6:
                p.drawRoundedRect(rect, rad, rad)
            else:
                p.drawRect(rect)
        if self.pos >= 0 and self.size > 0:
            i = min(len(self.cells) - 1, int(self.pos / self.size * len(self.cells)))
            r, c = divmod(i, cols)
            p.setPen(QPen(QColor(pal.text), 1.6))
            p.setBrush(Qt.NoBrush)
            p.drawRoundedRect(QRectF(2 + c * cell - 0.5, 2 + r * cell - 0.5, cell, cell), rad, rad)

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        if not self.cells or not self.size:
            return
        x, y = event.position().x() - 2, event.position().y() - 2
        c, r = int(x // self._cell), int(y // self._cell)
        i = r * self._cols + c
        if 0 <= c < self._cols and 0 <= i < len(self.cells):
            span = self.size / len(self.cells)
            st = self.cells[i]
            QToolTip.showText(event.globalPosition().toPoint(),
                              f"{fmt_bytes(i * span)} – {fmt_bytes((i + 1) * span)}\n{self.names.get(st, '')}", self)


class Legend(QWidget):
    """A row of coloured squares with names."""

    def __init__(self, items: list[tuple[str, str]], parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)
        self._labels = []
        for token, name in items:
            sw = QLabel()
            sw.setFixedSize(12, 12)
            lab = QLabel(name)
            lab.setObjectName("Muted")
            lab.setFont(scaled_font(lab, 0.86))
            row = QHBoxLayout()
            row.setSpacing(6)
            row.addWidget(sw)
            row.addWidget(lab)
            lay.addLayout(row)
            self._labels.append((sw, token))
        lay.addStretch(1)
        theme.changed.connect(self._retheme)
        self._retheme(theme.palette)

    def _retheme(self, pal) -> None:
        for sw, token in self._labels:
            c = _color(pal, token)
            sw.setStyleSheet(f"background: rgba({c.red()}, {c.green()}, {c.blue()}, {c.alpha()}); border-radius: 3px;")


def scan_map() -> CellMap:
    return CellMap(SCAN_TOKENS, SCAN_NAMES, "The disk appears here as a map while it is read")


def scan_legend() -> Legend:
    return Legend([("raised", "Not read yet"), ("text_faint@120", "Read"), ("accent", "Filesystem"), ("c2", "Photos"), ("c5", "Videos"),
                   ("c3", "Documents"), ("c6", "Music"), ("orange", "Archives"), ("text_faint", "Other"),
                   ("danger", "Unreadable")])


def image_map() -> CellMap:
    return CellMap(IMAGE_TOKENS, IMAGE_NAMES, "The disk appears here as a map while it is copied")


def image_legend() -> Legend:
    return Legend([("success", "Copied"), ("border_strong", "Not tried yet"), ("warning", "Failed, to trim"),
                   ("orange", "Failed, to scrape"), ("danger", "Unreadable")])
