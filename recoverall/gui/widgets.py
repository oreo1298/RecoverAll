"""Reusable widgets: the suite's cards, key/value grids, tiles, toasts and theme-aware buttons, plus
the disk-specific ones (progress ring, meters, disk icons, partition colours, file-type icons)."""

from __future__ import annotations

from PySide6.QtCore import (
    QEasingCurve,
    QObject,
    QPointF,
    QPropertyAnimation,
    QRect,
    QRectF,
    QSize,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFrame,
    QGraphicsOpacityEffect,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMenu,
    QSizePolicy,
    QStyle,
    QStyledItemDelegate,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from . import icons
from .theme import theme


def scaled_font(widget: QWidget, factor: float, bold: bool = False) -> QFont:
    font = widget.font()
    font.setPointSizeF(max(6.0, font.pointSizeF() * factor))
    if bold:
        font.setBold(True)
    return font


class Card(QFrame):
    """A rounded surface with an optional uppercase title, icon and trailing widgets."""

    def __init__(self, title: str | None = None, icon: str | None = None, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(14, 12, 14, 14)
        self._layout.setSpacing(9)
        self.header = QHBoxLayout()
        self.header.setSpacing(8)
        self._icon_name = icon
        self.icon_label = QLabel()
        self.title_label = QLabel((title or "").upper())
        self.title_label.setObjectName("CardTitle")
        self.title_label.setFont(scaled_font(self.title_label, 0.82, bold=True))
        if title:
            if icon:
                self.header.addWidget(self.icon_label)
            self.header.addWidget(self.title_label)
            self.header.addStretch(1)
            self._layout.addLayout(self.header)
        theme.changed.connect(self._retheme)
        self._retheme(theme.palette)

    def _retheme(self, palette) -> None:
        if self._icon_name:
            self.icon_label.setPixmap(icons.pixmap(self._icon_name, palette.text_muted, 16))

    def set_title(self, title: str) -> None:
        self.title_label.setText(title.upper())

    def add_header_widget(self, widget: QWidget) -> QWidget:
        self.header.addWidget(widget)
        return widget

    def body(self) -> QVBoxLayout:
        return self._layout

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self._layout.addWidget(widget, stretch)
        return widget

    def add_layout(self, layout, stretch: int = 0) -> None:
        self._layout.addLayout(layout, stretch)


class KeyValueGrid(QWidget):
    """Label/value rows (in one or more column pairs)."""

    def __init__(self, columns: int = 1, parent=None):
        super().__init__(parent)
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(14)
        self.grid.setVerticalSpacing(6)
        self.columns = columns
        self._count = 0

    def clear(self) -> None:
        while self.grid.count():
            item = self.grid.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
        self._count = 0

    def add_row(self, label: str, value: str = "—", tooltip: str = "") -> QLabel:
        row, col = divmod(self._count, self.columns)
        k = QLabel(label)
        k.setObjectName("Muted")
        k.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        v = QLabel(value if value not in (None, "") else "—")
        v.setObjectName("Value")
        v.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v.setWordWrap(True)
        if tooltip:
            v.setToolTip(tooltip)
            k.setToolTip(tooltip)
        self.grid.addWidget(k, row, col * 2)
        self.grid.addWidget(v, row, col * 2 + 1)
        self.grid.setColumnStretch(col * 2 + 1, 1)
        self._count += 1
        return v

    def set_rows(self, rows: list[tuple[str, str]]) -> None:
        self.clear()
        for r in rows:
            if r[1] not in (None, ""):
                self.add_row(*r)


class StatTile(QFrame):
    """A compact value-over-caption tile with an optional icon."""

    def __init__(self, caption: str, icon: str | None = None, parent=None):
        super().__init__(parent)
        self.setObjectName("Inset")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 9, 12, 9)
        lay.setSpacing(2)
        top = QHBoxLayout()
        top.setSpacing(6)
        if icon:
            ic = QLabel()
            self._binder = bind_icon(ic, icon, "text_muted", 14)
            top.addWidget(ic)
        self.caption = QLabel(caption)
        self.caption.setObjectName("Muted")
        self.caption.setFont(scaled_font(self.caption, 0.85))
        top.addWidget(self.caption, 1)
        lay.addLayout(top)
        self.value = QLabel("—")
        self.value.setObjectName("Value")
        self.value.setFont(scaled_font(self.value, 1.18, bold=True))
        self.value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(self.value)
        self.sub = QLabel(" ")
        self.sub.setObjectName("Faint")
        self.sub.setFont(scaled_font(self.sub, 0.8))
        lay.addWidget(self.sub)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

    def set(self, value: str, tooltip: str = "", sub: str = "") -> None:
        self.value.setText(value)
        self.setToolTip(tooltip)
        self.sub.setText(sub or " ")


class WrapLabel(QLabel):
    """A word-wrapped label as tall as its text at its real width (layouts otherwise size it for a narrow one
    and leave a gap)."""

    def __init__(self, text: str = "", parent=None):
        super().__init__(text, parent)
        self.setWordWrap(True)
        self._fit = -1

    def sizeHint(self):
        s = super().sizeHint()
        if self.width() > 0:
            s.setHeight(self.heightForWidth(self.width()))
        return s

    def resizeEvent(self, e) -> None:
        super().resizeEvent(e)
        h = self.heightForWidth(self.width())
        if h != self._fit:
            self._fit = h
            self.updateGeometry()

    def setText(self, text: str) -> None:
        super().setText(text)
        self._fit = -1
        self.updateGeometry()


class ElidedLabel(QLabel):
    """A label that shortens its text with … instead of growing (full text in the tooltip)."""

    def __init__(self, text: str = "", parent=None):
        super().__init__(parent)
        self._full = text
        self.setMinimumWidth(30)
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.setText(text)

    def setText(self, text: str) -> None:  # noqa: N802
        self._full = text
        self._elide()

    def full_text(self) -> str:
        return self._full

    def _elide(self) -> None:
        fm = self.fontMetrics()
        super().setText(fm.elidedText(self._full, Qt.ElideRight, max(10, self.width())))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._elide()


class StatusDot(QWidget):
    """A small filled circle with an optional soft halo."""

    def __init__(self, size: int = 10, parent=None):
        super().__init__(parent)
        self._color = QColor("#888")
        self._halo = True
        self.setFixedSize(QSize(size + 8, size + 8))

    def set_color(self, color: str, halo: bool = True) -> None:
        self._color = QColor(color)
        self._halo = halo
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = self.rect()
        if self._halo:
            halo = QColor(self._color)
            halo.setAlpha(55)
            p.setBrush(halo)
            p.setPen(Qt.NoPen)
            p.drawEllipse(r)
        inner = r.adjusted(4, 4, -4, -4)
        p.setBrush(self._color)
        p.setPen(Qt.NoPen)
        p.drawEllipse(inner)


class Toast(QWidget):
    """A transient notification floating near the bottom right of its parent."""

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self._icon = QLabel()
        self._text = QLabel()
        self._text.setWordWrap(True)
        self._text.setMaximumWidth(460)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 10, 16, 10)
        lay.setSpacing(10)
        lay.addWidget(self._icon, 0, Qt.AlignTop)
        lay.addWidget(self._text, 1)
        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._anim = QPropertyAnimation(self._effect, b"opacity", self)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self._timer = QTimer(self, singleShot=True)
        self._timer.timeout.connect(self._fade_out)
        self._accent = QColor("#5b8cff")
        self._fading = False
        self._anim.finished.connect(self._on_anim_finished)
        self.hide()

    def _on_anim_finished(self) -> None:
        if self._fading:
            self._fading = False
            self.hide()

    def show_message(self, text: str, kind: str = "success", timeout_ms: int = 3800) -> None:
        pal = theme.palette
        color = {"success": pal.success, "warning": pal.warning, "error": pal.danger,
                 "info": pal.accent}.get(kind, pal.accent)
        name = {"success": "check", "warning": "warning", "error": "error"}.get(kind, "info")
        self._accent = QColor(color)
        self._icon.setPixmap(icons.pixmap(name, color, 18))
        self._text.setText(text)
        self.adjustSize()
        self._place()
        self.raise_()
        self.show()
        self._anim.stop()
        self._fading = False
        self._anim.setDuration(180)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.start()
        self._timer.start(timeout_ms)

    def _fade_out(self) -> None:
        self._anim.stop()
        self._fading = True
        self._anim.setDuration(400)
        self._anim.setStartValue(1.0)
        self._anim.setEndValue(0.0)
        self._anim.start()

    def _place(self) -> None:
        parent = self.parentWidget()
        if parent is None:
            return
        size = self.sizeHint()
        x = parent.width() - size.width() - 22
        y = parent.height() - size.height() - 24
        self.setGeometry(QRect(x, y, size.width(), size.height()))

    def mousePressEvent(self, _event) -> None:  # noqa: N802
        self._timer.stop()
        self._fade_out()

    def paintEvent(self, _event) -> None:  # noqa: N802
        pal = theme.palette
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(1, 1, -1, -1)
        path = QPainterPath()
        path.addRoundedRect(rect, 10, 10)
        p.fillPath(path, QColor(pal.raised))
        p.setPen(QColor(pal.border_strong))
        p.drawPath(path)
        bar = QPainterPath()
        bar.addRoundedRect(rect.adjusted(0, 0, -(rect.width() - 4), 0), 2, 2)
        p.fillPath(bar, self._accent)


class SegmentedControl(QFrame):
    """A row of mutually exclusive toggle buttons."""

    changed = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Segmented")
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(3, 3, 3, 3)
        self._layout.setSpacing(2)
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._values: list[object] = []
        self._group.idClicked.connect(lambda i: self.changed.emit(self._values[i]))

    def add(self, label: str, value: object, tooltip: str = "") -> QToolButton:
        btn = QToolButton()
        btn.setObjectName("Segment")
        btn.setText(label)
        btn.setToolTip(tooltip)
        btn.setCheckable(True)
        btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        btn.setCursor(Qt.PointingHandCursor)
        self._group.addButton(btn, len(self._values))
        self._values.append(value)
        self._layout.addWidget(btn)
        return btn

    def value(self) -> object:
        i = self._group.checkedId()
        return self._values[i] if i >= 0 else None

    def set_value(self, value: object) -> None:
        if value in self._values:
            self._group.button(self._values.index(value)).setChecked(True)

    def set_enabled_value(self, value: object, enabled: bool) -> None:
        if value in self._values:
            self._group.button(self._values.index(value)).setEnabled(enabled)


class _IconBinder(QObject):
    """Re-tints a widget's icon whenever the theme changes (lives as the widget's child)."""

    def __init__(self, target, name: str, token: str, size: int | None = None):
        super().__init__(target)
        self._target = target
        self.name = name
        self.token = token
        self.size = size
        theme.changed.connect(self.apply)
        self.apply(theme.palette)

    def set_name(self, name: str, token: str | None = None) -> None:
        self.name = name
        if token:
            self.token = token
        self.apply(theme.palette)

    def apply(self, _palette=None) -> None:
        try:
            if isinstance(self._target, QLabel):
                p = theme.palette
                self._target.setPixmap(icons.pixmap(self.name, getattr(p, self.token), self.size or 18))
            else:
                self._target.setIcon(theme.icon(self.name, self.token))
        except RuntimeError:
            pass        # the widget was deleted


def bind_icon(widget, name: str, token: str = "text", size: int | None = None) -> _IconBinder:
    return _IconBinder(widget, name, token, size)


def tool_button(text: str, icon: str, tooltip: str = "", checkable: bool = False,
                under: bool = True, icon_size: int = 22) -> QToolButton:
    btn = QToolButton()
    btn.setText(text)
    btn.setToolTip(tooltip or text)
    btn.setCheckable(checkable)
    btn.setCursor(Qt.PointingHandCursor)
    btn.setIconSize(QSize(icon_size, icon_size))
    btn.setToolButtonStyle(Qt.ToolButtonTextUnderIcon if under else
                           (Qt.ToolButtonTextBesideIcon if text else Qt.ToolButtonIconOnly))
    btn._binder = bind_icon(btn, icon)
    return btn


def flat_button(icon: str, tooltip: str, checkable: bool = False, size: int = 18) -> QToolButton:
    btn = QToolButton()
    btn.setObjectName("Flat")
    btn.setToolTip(tooltip)
    btn.setCheckable(checkable)
    btn.setCursor(Qt.PointingHandCursor)
    btn.setIconSize(QSize(size, size))
    btn._binder = bind_icon(btn, icon, "text_muted")
    return btn


def icon_button(text: str, icon: str, variant: str = "", tooltip: str = ""):
    from PySide6.QtWidgets import QPushButton
    btn = QPushButton(text)
    btn.setCursor(Qt.PointingHandCursor)
    if variant:
        btn.setProperty("variant", variant)
    btn.setToolTip(tooltip)
    btn.setIconSize(QSize(16, 16))
    token = {"primary": "accent_text", "danger": "danger", "ghost": "accent"}.get(variant, "text")
    btn._binder = bind_icon(btn, icon, token)
    return btn


def chip(text: str, checked: bool = False) -> QToolButton:
    btn = QToolButton()
    btn.setObjectName("Chip")
    btn.setText(text)
    btn.setCheckable(True)
    btn.setChecked(checked)
    btn.setCursor(Qt.PointingHandCursor)
    return btn


def set_prop(widget: QWidget, name: str, value) -> None:
    """Set a dynamic property used by the style sheet and re-polish the widget."""
    widget.setProperty(name, value)
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def set_object_name(widget: QWidget, name: str) -> None:
    if widget.objectName() != name:
        widget.setObjectName(name)
        widget.style().unpolish(widget)
        widget.style().polish(widget)


def badge(text: str = "", kind: str = "BadgeIdle") -> QLabel:
    lb = QLabel(text)
    lb.setObjectName(kind)
    lb.setFont(scaled_font(lb, 0.72, bold=True))
    lb.setAlignment(Qt.AlignCenter)
    return lb


def set_badge(label: QLabel, text: str, kind: str) -> None:
    label.setText(text)
    set_object_name(label, kind)


def h_line() -> QFrame:
    f = QFrame()
    f.setObjectName("Divider")
    return f


# ---------------------------------------------------------------------- disk-specific
KIND_ICONS = {"hdd": "hdd", "ssd": "ssd", "nvme": "nvme", "usb-flash": "flash", "sd": "sdcard", "emmc": "chip",
              "virtual": "virtual", "usb-disk": "hdd", "loop": "file_image", "image": "file_image", "unknown": "hdd",
              "raid": "raid", "volume": "layers", "optical": "target"}
KIND_LABELS = {"hdd": "HDD", "ssd": "SSD", "nvme": "NVMe", "usb-flash": "USB flash", "sd": "Memory card",
               "emmc": "eMMC", "virtual": "Virtual", "usb-disk": "USB disk", "loop": "Loop device",
               "image": "Image file", "unknown": "Disk", "raid": "RAID", "volume": "Volume", "optical": "Optical disc"}
FS_TOKENS = {"ntfs": "c1", "ext2": "c2", "ext3": "c2", "ext4": "c2", "vfat": "c3", "fat12": "c3", "fat16": "c3",
             "fat32": "c3", "exfat": "c3", "btrfs": "c5", "xfs": "c6", "swap": "orange", "crypto_luks": "c4",
             "bitlocker": "c4", "lvm2_member": "c4", "linux_raid_member": "c4", "f2fs": "c6", "hfsplus": "c4",
             "apfs": "c4", "iso9660": "c5", "refs": "c1", "carved": "orange"}
CAT_ICONS = {"photo": "photo", "video": "film", "audio": "music", "document": "file_text", "archive": "box",
             "email": "mail", "database": "database", "executable": "app", "other": "file", "": "folder"}
CAT_TOKENS = {"photo": "c2", "video": "c5", "audio": "c6", "document": "c3", "archive": "orange", "email": "c1",
              "database": "c1", "executable": "c4", "other": "text_muted"}
CHANCE_TOKENS = {3: "success", 2: "warning", 1: "danger", 0: "text_faint"}
CHANCE_TEXT = {3: "Good", 2: "Fair", 1: "Poor", 0: "Unknown"}


def kind_icon(kind: str) -> str:
    return KIND_ICONS.get(kind, "hdd")


def fs_color(fstype: str | None, palette=None) -> str:
    p = palette or theme.palette
    token = FS_TOKENS.get(fstype or "")
    return getattr(p, token) if token else p.text_faint


def health_color(state: str | None, palette=None) -> str:
    p = palette or theme.palette
    return {"ok": p.success, "warning": p.warning, "failing": p.danger}.get(state or "", p.text_faint)


def health_badge(health: dict | None) -> QLabel | None:
    if not health:
        return None
    state = health.get("state")
    text, kind = {"ok": ("HEALTHY", "BadgeOk"), "warning": ("WARNING", "BadgeWarn"),
                  "failing": ("FAILING", "BadgeBad")}.get(state, ("", ""))
    if not text:
        return None
    b = badge(text, kind)
    if health.get("reasons"):
        b.setToolTip("\n".join(health["reasons"]))
    return b


class Ring(QWidget):
    """A circular gauge: arc filled to VALUE %, the number in the middle and a caption below."""

    def __init__(self, caption: str = "", size: int = 132, parent=None):
        super().__init__(parent)
        self.caption = caption
        self.value: float | None = None
        self.text = "—"
        self.color = "#888"
        self.sub = ""
        self._size = size
        self.setFixedSize(size, size + 4)
        theme.changed.connect(self._repaint)

    def _repaint(self, _palette=None) -> None:
        self.update()

    def set_value(self, value: float | None, color: str | None = None, text: str | None = None,
                  sub: str = "") -> None:
        self.value = value
        self.text = text if text is not None else ("—" if value is None else f"{value:.0f}")
        self.color = color or theme.palette.accent
        self.sub = sub
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802
        pal = theme.palette
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        s = self._size
        pen_w = max(8.0, s * 0.075)
        r = QRectF(pen_w / 2 + 2, pen_w / 2 + 2, s - pen_w - 4, s - pen_w - 4)
        start = 225 * 16
        span = -270 * 16
        track = QPen(QColor(pal.raised), pen_w)
        track.setCapStyle(Qt.RoundCap)
        p.setPen(track)
        p.drawArc(r, start, span)
        if self.value is not None:
            pen = QPen(QColor(self.color), pen_w)
            pen.setCapStyle(Qt.RoundCap)
            p.setPen(pen)
            p.drawArc(r, start, int(span * max(0.0, min(100.0, self.value)) / 100.0))
        f = QFont(self.font())
        f.setPointSizeF(max(10.0, s * 0.17))
        f.setBold(True)
        p.setFont(f)
        p.setPen(QColor(pal.text))
        big = QRectF(0, s * 0.27, s, s * 0.3)
        txt = self.text + (" %" if self.value is not None and self.text[-1:].isdigit() else "")
        p.drawText(big, Qt.AlignCenter, txt)
        f2 = QFont(self.font())
        f2.setPointSizeF(max(7.0, s * 0.072))
        f2.setBold(True)
        p.setFont(f2)
        p.setPen(QColor(pal.text_muted))
        p.drawText(QRectF(0, s * 0.56, s, s * 0.14), Qt.AlignCenter, self.caption.upper())
        if self.sub:
            f3 = QFont(self.font())
            f3.setPointSizeF(max(7.0, s * 0.068))
            p.setFont(f3)
            p.setPen(QColor(self.color if self.value is not None else pal.text_faint))
            p.drawText(QRectF(0, s * 0.80, s, s * 0.16), Qt.AlignCenter, self.sub)


class Meter(QWidget):
    """A slim horizontal bar (0–100)."""

    def __init__(self, height: int = 6, parent=None):
        super().__init__(parent)
        self.value: float | None = None
        self.color = "#888"
        self.setFixedHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        theme.changed.connect(self._repaint)

    def _repaint(self, _palette=None) -> None:
        self.update()

    def set_value(self, value: float | None, color: str | None = None) -> None:
        self.value = value
        self.color = color or theme.palette.accent
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect())
        rad = r.height() / 2
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(theme.palette.raised))
        p.drawRoundedRect(r, rad, rad)
        if self.value is not None and self.value > 0:
            w = max(r.height(), r.width() * min(100.0, self.value) / 100.0)
            p.setBrush(QColor(self.color))
            p.drawRoundedRect(QRectF(r.left(), r.top(), w, r.height()), rad, rad)


class Sparkline(QWidget):
    """A tiny line chart of recent values."""

    def __init__(self, parent=None, color_token: str = "accent"):
        super().__init__(parent)
        self.values: list[float | None] = []
        self.token = color_token
        self.setMinimumHeight(26)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        theme.changed.connect(self._repaint)

    def _repaint(self, _palette=None) -> None:
        self.update()

    def set_values(self, values) -> None:
        self.values = list(values)[-360:]
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802
        vals = [v for v in self.values if v is not None]
        if len(vals) < 2:
            return
        lo, hi = min(vals), max(vals)
        if hi - lo < 2:
            mid = (hi + lo) / 2
            lo, hi = mid - 1, mid + 1
        w, h = self.width(), self.height()
        n = len(self.values)
        path = QPainterPath()
        started = False
        for i, v in enumerate(self.values):
            if v is None:
                started = False
                continue
            pt = QPointF(i * (w - 2) / max(1, n - 1) + 1, h - 3 - (v - lo) / (hi - lo) * (h - 6))
            if started:
                path.lineTo(pt)
            else:
                path.moveTo(pt)
                started = True
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        pen = QPen(QColor(getattr(theme.palette, self.token)), 1.8)
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        p.setPen(pen)
        p.drawPath(path)


def clear_layout(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        w = item.widget()
        if w is not None:
            w.deleteLater()
        elif item.layout() is not None:
            clear_layout(item.layout())


# ---------------------------------------------------------------------- disk pickers and menus
def disk_subtitle(d: dict) -> str:
    table = {"gpt": "GPT", "dos": "MBR", "apm": "Apple"}.get(d.get("pttype") or "", "no partition table")
    parts = [d.get("capacity_text") or "", KIND_LABELS.get(d.get("kind", ""), "Disk"), table]
    if not d.get("is_image"):
        parts.append(d.get("path", ""))
    return " · ".join(p for p in parts if p)


_SUB_ROLE = Qt.UserRole + 1
_TONE_ROLE = Qt.UserRole + 2


class _DiskItemDelegate(QStyledItemDelegate):
    """Two lines per disk in the drop-down list: the name (and a note), then size, kind and path."""

    def sizeHint(self, option, index):  # noqa: N802
        return QSize(option.rect.width(), 46)

    def paint(self, painter: QPainter, option, index) -> None:
        pal = theme.palette
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        r = option.rect.adjusted(2, 1, -2, -1)
        hot = bool(option.state & (QStyle.State_Selected | QStyle.State_MouseOver))
        if hot:
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(pal.accent))
            painter.drawRoundedRect(QRectF(r), 7, 7)
        tone = index.data(_TONE_ROLE) or "text_muted"
        ic = index.data(Qt.UserRole + 3)
        if ic:
            pm = icons.pixmap(ic, pal.accent_text if hot else getattr(pal, tone), 20)
            painter.drawPixmap(r.left() + 8, r.top() + (r.height() - 20) // 2, 20, 20, pm)
        x = r.left() + 38
        f = QFont(option.font)
        f.setBold(True)
        painter.setFont(f)
        painter.setPen(QColor(pal.accent_text if hot else pal.text))
        top = QRect(x, r.top() + 4, r.right() - x - 8, r.height() // 2)
        painter.drawText(top, Qt.AlignLeft | Qt.AlignVCenter, painter.fontMetrics().elidedText(
            index.data(Qt.DisplayRole) or "", Qt.ElideRight, top.width()))
        f2 = QFont(option.font)
        f2.setPointSizeF(max(7.0, f2.pointSizeF() * 0.86))
        painter.setFont(f2)
        painter.setPen(QColor(pal.accent_text if hot else pal.text_muted))
        bottom = QRect(x, r.top() + r.height() // 2, r.right() - x - 8, r.height() // 2 - 4)
        painter.drawText(bottom, Qt.AlignLeft | Qt.AlignVCenter, painter.fontMetrics().elidedText(
            index.data(_SUB_ROLE) or "", Qt.ElideRight, bottom.width()))
        painter.restore()


class DiskCombo(QComboBox):
    """A drop-down of disks: icon, name, size and a note (failing, in use, smaller…); the list shows each
    disk's kind, partition table and path underneath. currentData() is the disk's path."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setItemDelegate(_DiskItemDelegate(self))
        self.setIconSize(QSize(18, 18))
        self.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.setMinimumContentsLength(20)
        self._tones: list[tuple[str, str]] = []
        theme.changed.connect(self._retheme)

    def set_disks(self, disks: list[dict], notes: dict[str, str] | None = None, keep: str | None = None) -> None:
        """Fill the list (signals blocked) and keep KEEP (or the current disk) selected when it's still there."""
        notes = notes or {}
        cur = self.currentData() if keep is None else keep
        self.blockSignals(True)
        self.clear()
        self._tones = []
        for d in disks:
            health = (d.get("health") or {}).get("state")
            note = notes.get(d["path"], "")
            if not note and health == "failing":
                note = "failing"
            text = f"{d.get('display_name') or d['path']} · {d.get('capacity_text') or ''}".rstrip(" ·")
            if note:
                text += f" — {note}"
            tone = "danger" if health == "failing" else "warning" if health == "warning" else "text_muted"
            ic = kind_icon(d.get("kind", ""))
            self.addItem(theme.icon(ic, tone), text, d["path"])
            i = self.count() - 1
            self.setItemData(i, disk_subtitle(d) + (f" · serial {d['serial']}" if d.get("serial") else ""),
                             _SUB_ROLE)
            self.setItemData(i, tone, _TONE_ROLE)
            self.setItemData(i, ic, Qt.UserRole + 3)
            self.setItemData(i, disk_subtitle(d), Qt.ToolTipRole)
            self._tones.append((ic, tone))
        self.setCurrentIndex(max(0, self.findData(cur)))
        self.blockSignals(False)

    def _retheme(self, _palette=None) -> None:
        for i, (ic, tone) in enumerate(self._tones):
            if i < self.count():
                self.setItemIcon(i, theme.icon(ic, tone))


class _MenuIcons(QObject):
    """Re-tints a menu's icons when the theme changes (a child of the menu, so it goes with it)."""

    def __init__(self, menu: QMenu):
        super().__init__(menu)
        self._menu = menu
        theme.changed.connect(self.apply)
        self.apply()

    def apply(self, _palette=None) -> None:
        for a in self._menu.actions():
            if a.data():
                a.setIcon(theme.icon(a.data(), "text"))


def more_button(items: list, tooltip: str = "More") -> QToolButton:
    """A ⋯ button with a menu. ITEMS: (text, icon, callback) or None for a separator."""
    btn = flat_button("more", tooltip, size=18)
    btn.setPopupMode(QToolButton.InstantPopup)
    menu = QMenu(btn)
    for item in items:
        if item is None:
            menu.addSeparator()
            continue
        text, icon, fn = item
        act = menu.addAction(text)
        act.setData(icon)
        act.triggered.connect(lambda _c=False, fn=fn: fn())

    btn._menu_icons = _MenuIcons(menu)
    btn.setMenu(menu)
    btn.menu_ref = menu
    return btn
