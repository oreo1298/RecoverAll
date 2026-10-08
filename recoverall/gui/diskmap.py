"""The partition map: a disk drawn as a bar of partitions, each tinted by its filesystem with its used space
filled in, unallocated space hatched. Partitions can be selectable or checkable; found partitions that aren't
in the table are drawn dashed."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QFontMetrics, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

from ..core.devices import ROLE_NAMES
from ..core.fs import fs_name
from ..core.util import GiB, fmt_bytes
from .theme import theme
from .widgets import fs_color, scaled_font


def segments_of(disk: dict, parts: list[dict] | None = None) -> list[dict]:
    """Partitions plus unallocated gaps, in disk order (extended containers left out)."""
    size = int(disk.get("size") or 0)
    parts = parts if parts is not None else disk.get("partitions") or []
    real = sorted((p for p in parts if not p.get("extended") and p.get("role") != "extended"), key=lambda p: p["start"])
    if not real and disk.get("fstype"):
        fs = disk.get("fs") or {}
        return [{"kind": "part", "number": 0, "start": 0, "size": size, "fstype": disk.get("fstype"),
                 "label": disk.get("label") or "", "used": fs.get("used") if not fs.get("used_unknown") else None,
                 "role": "data"}]
    out = []
    pos = 0
    min_gap = max(16 * 1024 * 1024, size // 200)
    for p in real:
        if p["start"] - pos >= min_gap:
            out.append({"kind": "free", "start": pos, "size": p["start"] - pos})
        fs = p.get("fs") or {}
        used = p.get("used")
        if used is None and fs and not fs.get("used_unknown"):
            used = fs.get("used")
        if used is None and p.get("fsused") is not None:
            used = p["fsused"]
        seg = dict(p)
        seg.update({"kind": "part", "used": used})
        out.append(seg)
        pos = max(pos, p["start"] + p["size"])
    if size - pos >= min_gap:
        out.append({"kind": "free", "start": pos, "size": size - pos})
    return out


def part_title(seg: dict) -> str:
    if seg.get("kind") == "free":
        return "Unallocated"
    if seg.get("label"):
        return seg["label"]
    role = seg.get("role") or "data"
    if role != "data":
        return ROLE_NAMES.get(role, role)
    return fs_name(seg.get("fstype")) if seg.get("fstype") else f"Partition {seg.get('number')}"


class DiskMap(QWidget):
    selected = Signal(int)                # partition number
    toggled = Signal(int, bool)

    def __init__(self, parent=None, height: int = 62, checkable: bool = False, selectable: bool = False):
        super().__init__(parent)
        self.segments: list[dict] = []
        self.size = 0
        self.checkable = checkable
        self.selectable = selectable
        self.checked: set[int] = set()
        self.current: int | None = None
        self.plan_mode = False
        self.dim = False
        self._rects: list[tuple[QRectF, dict]] = []
        self._hover = -1
        self.empty_text = "No partitions"
        self.setMinimumHeight(height)
        self.setMaximumHeight(height + 20)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMouseTracking(True)
        if checkable or selectable:
            self.setCursor(Qt.PointingHandCursor)
        theme.changed.connect(self._repaint)

    def _repaint(self, _palette=None) -> None:
        self.update()

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(600, self.minimumHeight())

    def set_disk(self, disk: dict | None, parts: list[dict] | None = None, plan: bool = False) -> None:
        if not disk:
            self.segments, self.size = [], 0
        else:
            self.size = int(disk.get("size") or disk.get("target_size") or 0)
            self.segments = segments_of({"size": self.size, **({k: disk[k] for k in ("fstype", "label", "fs")
                                                                 if k in disk})}, parts if parts is not None
                                        else disk.get("partitions"))
        self.plan_mode = plan
        self.update()

    def set_checked(self, numbers) -> None:
        self.checked = set(numbers)
        self.update()

    # -------------------------------------------------------------- layout
    def _widths(self, total_w: float) -> list[float]:
        n = len(self.segments)
        if not n:
            return []
        gap = 4.0
        avail = total_w - gap * (n - 1)
        mins = [30.0 if s["kind"] == "free" else (92.0 if total_w > 700 else 58.0) for s in self.segments]
        sizes = [max(1, s["size"]) for s in self.segments]
        widths = [0.0] * n
        fixed: set[int] = set()
        for _ in range(n + 1):
            rest = avail - sum(mins[i] for i in fixed)
            flex = [i for i in range(n) if i not in fixed]
            tot = sum(sizes[i] for i in flex) or 1
            changed = False
            for i in flex:
                w = rest * sizes[i] / tot
                if w < mins[i]:
                    fixed.add(i)
                    changed = True
            if not changed:
                for i in flex:
                    widths[i] = rest * sizes[i] / tot
                break
        for i in fixed:
            widths[i] = mins[i]
        scale = avail / (sum(widths) or 1)
        if scale < 1:
            widths = [w * scale for w in widths]
        return widths

    def paintEvent(self, _event) -> None:  # noqa: N802
        pal = theme.palette
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        self._rects = []
        if not self.segments:
            path = QPainterPath()
            path.addRoundedRect(r, 9, 9)
            p.fillPath(path, QColor(pal.surface_alt))
            p.setPen(QPen(QColor(pal.border_strong), 1, Qt.DashLine))
            p.drawPath(path)
            p.setPen(QColor(pal.text_faint))
            p.drawText(r, Qt.AlignCenter, self.empty_text)
            return
        widths = self._widths(r.width())
        x = r.left()
        f_title = scaled_font(self, 0.9, bold=True)
        f_sub = scaled_font(self, 0.78)
        fm_t = QFontMetrics(f_title)
        fm_s = QFontMetrics(f_sub)
        for i, (seg, w) in enumerate(zip(self.segments, widths)):
            rect = QRectF(x, r.top(), w, r.height())
            self._rects.append((rect, seg))
            x += w + 4
            path = QPainterPath()
            path.addRoundedRect(rect, 8, 8)
            if seg["kind"] == "free":
                p.fillPath(path, QColor(pal.surface_alt))
                brush = QBrush(QColor(pal.border_strong), Qt.BDiagPattern)
                p.fillPath(path, brush)
                p.setPen(QPen(QColor(pal.border_strong), 1))
                p.drawPath(path)
                if w > 70:
                    p.setFont(f_sub)
                    p.setPen(QColor(pal.text_muted))
                    p.drawText(rect.adjusted(8, 0, -6, 0), Qt.AlignVCenter | Qt.AlignLeft,
                               fm_s.elidedText(f"Unallocated · {fmt_bytes(seg['size'])}", Qt.ElideRight,
                                               int(rect.width() - 14)))
                continue
            col = QColor(fs_color(seg.get("fstype"), pal))
            if not seg.get("fstype"):
                col = QColor(pal.text_faint)
            soft = QColor(col)
            soft.setAlpha(46 if pal.dark else 38)
            if self.dim or (self.checkable and seg.get("number") not in self.checked):
                soft.setAlpha(18)
            p.fillPath(path, QColor(pal.surface_alt))
            p.fillPath(path, soft)
            used = seg.get("used")
            if used is not None and seg["size"] > 0 and seg.get("fstype") not in ("swap",):
                frac = max(0.0, min(1.0, used / seg["size"]))
                if frac > 0:
                    fill = QColor(col)
                    fill.setAlpha(150 if not (self.checkable and seg.get("number") not in self.checked) else 50)
                    p.save()
                    p.setClipPath(path)
                    p.fillRect(QRectF(rect.left(), rect.bottom() - 6, rect.width() * frac, 6), fill)
                    p.restore()
            border = QColor(col)
            border.setAlpha(200)
            pen_w = 1.2
            style = Qt.DashLine if seg.get("found") else Qt.SolidLine
            if self.selectable and seg.get("number") == self.current:
                border = QColor(pal.accent)
                pen_w = 2.4
            elif i == self._hover and (self.selectable or self.checkable):
                border = QColor(pal.text_muted)
            p.setPen(QPen(border, pen_w, style))
            p.drawPath(path)
            # colour tab on the left
            tab = QPainterPath()
            tab.addRoundedRect(QRectF(rect.left() + 1, rect.top() + 1, 4, rect.height() - 2), 2, 2)
            p.fillPath(tab, col)
            # text
            inner = rect.adjusted(11, 6, -8, -9)
            title = part_title(seg)
            sub = fmt_bytes(seg["size"])
            if seg.get("fstype") and seg.get("label") or (seg.get("role") not in (None, "data") and seg.get("fstype")):
                sub += f" · {fs_name(seg['fstype'])}"
            elif not seg.get("fstype") and seg.get("role") == "data":
                sub += " · unformatted"
            if used is not None and seg.get("fstype") not in ("swap", None, ""):
                sub += f" · {fmt_bytes(used)} used"
            if self.plan_mode and seg.get("src_size"):
                if seg["size"] < seg["src_size"] - 1024 * 1024:
                    sub = f"↓ {fmt_bytes(seg['size'])} (was {fmt_bytes(seg['src_size'])})"
                elif seg["size"] > seg["src_size"] + 1024 * 1024:
                    sub = f"↑ {fmt_bytes(seg['size'])} (was {fmt_bytes(seg['src_size'])})"
            num = seg.get("number")
            prefix = f"{num}  " if num else ""
            check_w = 0
            if self.checkable:
                check_w = 20
                c = QRectF(rect.right() - 22, rect.top() + 7, 15, 15)
                on = num in self.checked
                p.setPen(QPen(QColor(pal.accent if on else pal.border_strong), 1.4))
                p.setBrush(QColor(pal.accent) if on else Qt.NoBrush)
                p.drawRoundedRect(c, 4, 4)
                if on:
                    p.setPen(QPen(QColor(pal.accent_text), 2.0, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
                    pts = [QPointF(c.left() + 3.5, c.center().y()), QPointF(c.left() + 6.5, c.bottom() - 4),
                           QPointF(c.right() - 3.2, c.top() + 4)]
                    p.drawPolyline(pts)
                p.setBrush(Qt.NoBrush)
            if inner.width() > 18:
                p.setFont(f_title)
                p.setPen(QColor(pal.text))
                avail = int(inner.width() - check_w)
                p.drawText(QRectF(inner.left(), inner.top(), avail, fm_t.height()), Qt.AlignLeft | Qt.AlignTop,
                           fm_t.elidedText(prefix + title, Qt.ElideRight, avail))
                if inner.height() > fm_t.height() + fm_s.height() - 2:
                    p.setFont(f_sub)
                    p.setPen(QColor(pal.text_muted))
                    p.drawText(QRectF(inner.left(), inner.top() + fm_t.height() + 1, inner.width(), fm_s.height()),
                               Qt.AlignLeft | Qt.AlignTop, fm_s.elidedText(sub, Qt.ElideRight, int(inner.width())))

    # -------------------------------------------------------------- mouse
    def _at(self, pos) -> int:
        for i, (rect, _seg) in enumerate(self._rects):
            if rect.contains(pos):
                return i
        return -1

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        i = self._at(event.position())
        if i != self._hover:
            self._hover = i
            self.update()
        if i < 0:
            QToolTip.hideText()
            return
        seg = self._rects[i][1]
        if seg["kind"] == "free":
            text = f"Unallocated\n{fmt_bytes(seg['size'])} at {fmt_bytes(seg['start'])}"
        else:
            lines = [f"Partition {seg.get('number')}: {part_title(seg)}" if seg.get("number") else part_title(seg),
                     f"{fs_name(seg.get('fstype')) if seg.get('fstype') else 'No filesystem'} · "
                     f"{fmt_bytes(seg['size'])} ({seg['size'] / GiB:.2f} GiB)",
                     f"Starts at {fmt_bytes(seg['start'])}"]
            if seg.get("used") is not None and seg.get("fstype") not in ("swap",):
                lines.append(f"{fmt_bytes(seg['used'])} used")
            mps = [m for m in seg.get("mountpoints") or []]
            if mps:
                lines.append("Mounted: " + ", ".join(mps))
            if seg.get("method_name"):
                lines.append(seg["method_name"])
            text = "\n".join(lines)
        QToolTip.showText(event.globalPosition().toPoint(), text, self)

    def leaveEvent(self, _event) -> None:  # noqa: N802
        self._hover = -1
        self.update()

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        if event.button() != Qt.LeftButton:
            return
        i = self._at(event.position())
        if i < 0:
            return
        seg = self._rects[i][1]
        if seg["kind"] != "part" or seg.get("number") is None:
            return
        n = seg["number"]
        if self.checkable:
            on = n not in self.checked
            if on:
                self.checked.add(n)
            else:
                self.checked.discard(n)
            self.update()
            self.toggled.emit(n, on)
        if self.selectable:
            self.current = n
            self.update()
            self.selected.emit(n)


def legend_font(widget) -> QFont:
    return scaled_font(widget, 0.82)
