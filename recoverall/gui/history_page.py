"""The History page: every scan, recovery, partition search, repair and image, with its steps and log."""

from __future__ import annotations

import html

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..core.util import fmt_duration, fmt_when
from .theme import mono_font, theme
from .widgets import Card, badge, bind_icon, clear_layout, icon_button, scaled_font, set_badge, set_object_name

KIND_ICONS = {"scan": "scan", "recover": "trash_restore", "partitions": "partition", "image": "copy",
              "repair": "wrench", "filerepair": "wrench", "raid": "raid"}
STATE = {"done": ("FINISHED", "BadgeOk"), "failed": ("FAILED", "BadgeBad"), "cancelled": ("STOPPED", "BadgeWarn"),
         "running": ("RUNNING", "BadgeInfo")}


class HistoryItem(QFrame):
    clicked = Signal(str)

    def __init__(self, e: dict):
        super().__init__()
        self.id = e.get("id")
        self.setObjectName("Choice")
        self.setCursor(Qt.PointingHandCursor)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(10)
        ic = QLabel()
        self._ic = bind_icon(ic, KIND_ICONS.get(e.get("kind"), "activity"), "text_muted", 22)
        lay.addWidget(ic, 0, Qt.AlignTop)
        col = QVBoxLayout()
        col.setSpacing(2)
        t = QLabel(e.get("title") or "")
        t.setWordWrap(True)
        t.setFont(scaled_font(t, 0.95, bold=True))
        col.addWidget(t)
        dur = (e.get("finished") or 0) - (e.get("started") or 0)
        s = QLabel(f"{fmt_when(e.get('started'))} · {fmt_duration(dur) if dur > 0 else ''}")
        s.setObjectName("Faint")
        s.setFont(scaled_font(s, 0.84))
        col.addWidget(s)
        lay.addLayout(col, 1)
        text, kind = STATE.get(e.get("state"), ("", "BadgeIdle"))
        lay.addWidget(badge(text, kind), 0, Qt.AlignTop)

    def set_selected(self, on: bool) -> None:
        set_object_name(self, "ChoiceSelected" if on else "Choice")

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.id)


class HistoryPage(QWidget):
    goto = Signal(int)

    def __init__(self, bridge, parent=None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.bridge = bridge
        self.entries: list[dict] = []
        self.items: dict[str, HistoryItem] = {}
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)
        left = Card("History", "clock")
        left.setMinimumWidth(380)
        left.setMaximumWidth(460)
        self.btn_clear = left.add_header_widget(icon_button("Clear", "trash", "ghost"))
        self.btn_clear.clicked.connect(self._clear)
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.NoFrame)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        holder = QWidget()
        self.list = QVBoxLayout(holder)
        self.list.setContentsMargins(0, 0, 4, 0)
        self.list.setSpacing(6)
        self.list.addStretch(1)
        area.setWidget(holder)
        left.add(area, 1)
        lay.addWidget(left)

        right = Card("Details", "report")
        self.d_badge = right.add_header_widget(badge("", "BadgeIdle"))
        self.d_title = QLabel("Choose an entry")
        self.d_title.setFont(scaled_font(self.d_title, 1.25, bold=True))
        self.d_title.setWordWrap(True)
        right.add(self.d_title)
        self.d_meta = QLabel()
        self.d_meta.setObjectName("Muted")
        self.d_meta.setWordWrap(True)
        right.add(self.d_meta)
        self.d_steps = QLabel()
        self.d_steps.setWordWrap(True)
        self.d_steps.setTextFormat(Qt.RichText)
        right.add(self.d_steps)
        self.d_warn = QLabel()
        self.d_warn.setObjectName("BannerWarn")
        self.d_warn.setWordWrap(True)
        self.d_warn.hide()
        right.add(self.d_warn)
        self.log = QPlainTextEdit()
        self.log.setObjectName("Log")
        self.log.setReadOnly(True)
        self.log.setFont(mono_font(9.0))
        right.add(self.log, 1)
        lay.addWidget(right, 1)

    def shown(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        self.bridge.call("history", done=self._got, error=lambda e: None, limit=200)

    def _got(self, entries: list) -> None:
        self.entries = entries or []
        clear_layout(self.list)
        self.items = {}
        for e in self.entries:
            it = HistoryItem(e)
            it.clicked.connect(self.show_entry)
            self.list.addWidget(it)
            self.items[e.get("id")] = it
        if not self.entries:
            empty = QLabel("Nothing yet: scans, recoveries, partition searches, repairs and images appear here.")
            empty.setObjectName("Empty")
            empty.setWordWrap(True)
            self.list.addWidget(empty)
        self.list.addStretch(1)
        if self.entries:
            self.show_entry(self.entries[0].get("id"))

    def show_entry(self, eid: str) -> None:
        e = next((x for x in self.entries if x.get("id") == eid), None)
        if not e:
            return
        for k, it in self.items.items():
            it.set_selected(k == eid)
        pal = theme.palette
        text, kind = STATE.get(e.get("state"), ("", "BadgeIdle"))
        set_badge(self.d_badge, text, kind)
        self.d_title.setText(e.get("title") or "")
        dur = (e.get("finished") or 0) - (e.get("started") or 0)
        meta = f"Started {fmt_when(e.get('started'))} · took {fmt_duration(dur)}"
        msg = e.get("error") or e.get("message")
        if msg:
            meta += f"<br>{html.escape(msg, quote=False)}"
        self.d_meta.setText(meta)
        icons = {"done": ("✓", pal.success), "failed": ("✗", pal.danger), "cancelled": ("■", pal.warning),
                 "skipped": ("–", pal.text_faint), "pending": ("·", pal.text_faint), "running": ("▸", pal.accent)}
        rows = []
        for s in e.get("steps") or []:
            mark, col = icons.get(s.get("state"), ("·", pal.text_faint))
            rows.append(f"<span style='color:{col}'>{mark}</span> {html.escape(s.get('title', ''), quote=False)}"
                        + (f" <span style='color:{pal.text_faint}'>— {html.escape(s['detail'], quote=False)}</span>"
                           if s.get("detail") else ""))
        self.d_steps.setText("<br>".join(rows))
        ws = e.get("warnings") or []
        self.d_warn.setText("<br>".join(html.escape(w, quote=False) for w in ws))
        self.d_warn.setVisible(bool(ws))
        lines = []
        for item in e.get("log") or []:
            text = item[-1] if isinstance(item, (list, tuple)) else str(item)
            lines.append(text)
        self.log.setPlainText("\n".join(lines))

    def _clear(self) -> None:
        if QMessageBox.question(self, "Clear history", "Remove every entry and its log?") != QMessageBox.Yes:
            return
        self.bridge.call("clear_history", done=lambda _r: self.refresh())
