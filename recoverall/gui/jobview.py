"""The progress view every operation shares: a progress ring, speed and time left, the steps, warnings
and the log, with Stop while it runs and Done afterwards."""

from __future__ import annotations

import html
import time

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication, QTextCursor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..core.util import fmt_bytes, fmt_duration, fmt_rate
from .theme import mono_font, theme
from .widgets import Card, Ring, StatTile, badge, bind_icon, clear_layout, icon_button, scaled_font, set_badge

STATE_BADGE = {"running": ("RUNNING", "BadgeInfo"), "done": ("FINISHED", "BadgeOk"),
               "failed": ("FAILED", "BadgeBad"), "cancelled": ("STOPPED", "BadgeWarn")}
STEP_ICONS = {"pending": ("clock", "text_faint"), "running": ("play", "accent"), "done": ("check", "success"),
              "failed": ("error", "danger"), "cancelled": ("stop", "warning"), "skipped": ("minus", "text_faint")}


class StepRow(QFrame):
    def __init__(self, step: dict):
        super().__init__()
        self.setObjectName("JobStep")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 6, 8, 6)
        lay.setSpacing(10)
        self.icon = QLabel()
        self.icon.setFixedWidth(20)
        self._b = bind_icon(self.icon, "clock", "text_faint", 16)
        lay.addWidget(self.icon, 0, Qt.AlignTop)
        col = QVBoxLayout()
        col.setSpacing(1)
        self.title = QLabel()
        self.title.setWordWrap(True)
        self.detail = QLabel()
        self.detail.setObjectName("Faint")
        self.detail.setFont(scaled_font(self.detail, 0.85))
        self.detail.setWordWrap(True)
        col.addWidget(self.title)
        col.addWidget(self.detail)
        lay.addLayout(col, 1)
        self.set(step)

    def set(self, step: dict) -> None:
        state = step.get("state", "pending")
        name, token = STEP_ICONS.get(state, STEP_ICONS["pending"])
        self._b.set_name(name, token)
        self.title.setText(step.get("title", ""))
        f = self.title.font()
        f.setBold(state == "running")
        self.title.setFont(f)
        self.title.setObjectName("" if state in ("running", "done") else "Muted")
        self.title.style().unpolish(self.title)
        self.title.style().polish(self.title)
        self.detail.setText(step.get("detail") or "")
        self.detail.setVisible(bool(step.get("detail")))
        name = "JobStepActive" if state == "running" else "JobStep"
        if self.objectName() != name:
            self.setObjectName(name)
            self.style().unpolish(self)
            self.style().polish(self)


class JobView(QWidget):
    stop_requested = Signal(str)
    done = Signal()

    def __init__(self, extra: QWidget | None = None, parent=None):
        super().__init__(parent)
        self.job: dict | None = None
        self._last_line = 0
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        top = Card("Progress", "activity")
        self.state_badge = top.add_header_widget(badge("RUNNING", "BadgeInfo"))
        row = QHBoxLayout()
        row.setSpacing(18)
        self.ring = Ring("done", 148)
        row.addWidget(self.ring, 0, Qt.AlignTop)
        col = QVBoxLayout()
        col.setSpacing(6)
        self.title = QLabel("—")
        self.title.setObjectName("Hero")
        self.title.setFont(scaled_font(self.title, 1.35, bold=True))
        self.title.setWordWrap(True)
        self.message = QLabel("")
        self.message.setObjectName("Muted")
        self.message.setWordWrap(True)
        col.addWidget(self.title)
        col.addWidget(self.message)
        tiles = QHBoxLayout()
        tiles.setSpacing(10)
        self.t_done = StatTile("Copied", "layers")
        self.t_rate = StatTile("Speed", "speed")
        self.t_left = StatTile("Time left", "clock")
        self.t_elapsed = StatTile("Elapsed", "activity")
        for t in (self.t_done, self.t_rate, self.t_left, self.t_elapsed):
            tiles.addWidget(t, 1)
        col.addLayout(tiles)
        col.addStretch(1)
        row.addLayout(col, 1)
        top.add_layout(row)
        self.warn_label = QLabel()
        self.warn_label.setObjectName("BannerWarn")
        self.warn_label.setWordWrap(True)
        self.warn_label.hide()
        top.add(self.warn_label)
        self.error_label = QLabel()
        self.error_label.setObjectName("BannerBad")
        self.error_label.setWordWrap(True)
        self.error_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.error_label.hide()
        top.add(self.error_label)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.btn_copy = icon_button("Copy log", "copy", "ghost")
        self.btn_copy.clicked.connect(self._copy_log)
        self.btn_stop = icon_button("Stop", "stop", "danger")
        self.btn_stop.clicked.connect(lambda: self.job and self.stop_requested.emit(self.job["id"]))
        self.btn_done = icon_button("Done", "check", "primary")
        self.btn_done.clicked.connect(self.done.emit)
        self.btn_done.hide()
        buttons.addWidget(self.btn_copy)
        buttons.addWidget(self.btn_stop)
        buttons.addWidget(self.btn_done)
        top.add_layout(buttons)
        lay.addWidget(top)

        steps = Card("Steps", "list")
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.NoFrame)
        holder = QWidget()
        self.steps_layout = QVBoxLayout(holder)
        self.steps_layout.setContentsMargins(0, 0, 4, 0)
        self.steps_layout.setSpacing(2)
        self.steps_layout.addStretch(1)
        area.setWidget(holder)
        steps.add(area, 1)
        logc = Card("Log", "log")
        self.log = QPlainTextEdit()
        self.log.setObjectName("Log")
        self.log.setReadOnly(True)
        self.log.setFont(mono_font(9.0))
        self.log.setMaximumBlockCount(6000)
        self.log.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        logc.add(self.log, 1)
        if extra is None:
            lower = QHBoxLayout()
            lower.setSpacing(12)
            steps.setMinimumWidth(320)
            lower.addWidget(steps, 2)
            lower.addWidget(logc, 3)
            lay.addLayout(lower, 1)
        else:
            # a live map (the rescue) gets the room it needs; the steps and the log stack beside it
            side = QVBoxLayout()
            side.setSpacing(12)
            side.addWidget(steps, 2)
            side.addWidget(logc, 3)
            row2 = QHBoxLayout()
            row2.setSpacing(12)
            row2.addWidget(extra, 3)
            row2.addLayout(side, 2)
            lay.addLayout(row2, 1)
        self._step_rows: list[StepRow] = []
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._tick)

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(900, 700)

    # -------------------------------------------------------------- state
    def reset(self, title: str = "") -> None:
        self.job = None
        self._last_line = 0
        self.title.setText(title or "Starting…")
        self.message.setText("")
        self.ring.set_value(0, theme.palette.accent, "0")
        for t in (self.t_done, self.t_rate, self.t_left, self.t_elapsed):
            t.set("—")
            t.show()
        self.log.clear()
        self.warn_label.hide()
        self.error_label.hide()
        clear_layout(self.steps_layout)
        self.steps_layout.addStretch(1)
        self._step_rows = []
        self.btn_stop.show()
        self.btn_stop.setEnabled(True)
        self.btn_done.hide()
        self.t_elapsed.caption.setText("Elapsed")
        set_badge(self.state_badge, "STARTING", "BadgeIdle")

    def set_job(self, job: dict) -> None:
        first = self.job is None or self.job.get("id") != job.get("id")
        self.job = job
        if first:
            self.title.setText(job.get("title") or "")
            self.timer.start()
        pal = theme.palette
        state = job.get("state", "running")
        text, kind = STATE_BADGE.get(state, ("", "BadgeIdle"))
        set_badge(self.state_badge, text, kind)
        pct = 100.0 * (job.get("progress") or 0)
        color = {"done": pal.success, "failed": pal.danger, "cancelled": pal.warning}.get(state, pal.accent)
        self.ring.set_value(pct if state != "done" else 100.0, color, f"{pct:.0f}" if state != "done" else "100")
        self.message.setText(job.get("message") or "")
        st = job.get("stats") or {}
        if st.get("total"):
            self.t_done.caption.setText(st.get("label") or "Copied")
            self.t_done.set(fmt_bytes(st.get("done")), sub=f"of {fmt_bytes(st.get('total'))}")
        rate = st.get("rate")
        self.t_rate.set(fmt_rate(rate) if rate else "—")
        self.t_left.set(fmt_duration(st.get("eta")) if st.get("eta") is not None and state == "running" else "—")
        self._tick()
        steps = job.get("steps") or []
        if len(steps) != len(self._step_rows):
            clear_layout(self.steps_layout)
            self._step_rows = [StepRow(s) for s in steps]
            for r in self._step_rows:
                self.steps_layout.addWidget(r)
            self.steps_layout.addStretch(1)
        else:
            for r, s in zip(self._step_rows, steps):
                r.set(s)
        warnings = job.get("warnings") or []
        if warnings:
            self.warn_label.setText("<b>Warnings</b><br>" + "<br>".join(html.escape(w, quote=False) for w in warnings[-8:]))
            self.warn_label.show()
        if state != "running":
            self.timer.stop()
            self.btn_stop.hide()
            self.btn_done.show()
            if state == "failed":
                self.error_label.setText(f"<b>Failed:</b> {html.escape(job.get('error') or job.get('message') or '', quote=False)}")
                self.error_label.show()
            self.t_rate.hide()             # speed and time left only mean something while it runs
            self.t_left.hide()
            self.t_elapsed.caption.setText("Took")

    def _tick(self) -> None:
        j = self.job
        if not j or not j.get("started"):
            return
        end = j.get("finished") or time.time()
        self.t_elapsed.set(fmt_duration(end - j["started"]))

    def append_log(self, lines: list) -> None:
        pal = theme.palette
        cur = self.log.textCursor()
        at_end = self.log.verticalScrollBar().value() >= self.log.verticalScrollBar().maximum() - 4
        for item in lines:
            n, _t, level, text = item if len(item) == 4 else (0, *item)
            if n and n <= self._last_line:
                continue
            self._last_line = max(self._last_line, n)
            esc = html.escape(text, quote=False)
            if level == "error":
                self.log.appendHtml(f'<span style="color:{pal.danger}">{esc}</span>')
            elif level == "warning":
                self.log.appendHtml(f'<span style="color:{pal.warning}">{esc}</span>')
            elif text.startswith("— "):
                self.log.appendHtml(f'<b style="color:{pal.accent}">{esc}</b>')
            elif text.startswith("$ "):
                self.log.appendHtml(f'<span style="color:{pal.text_muted}">{esc}</span>')
            else:
                self.log.appendHtml(f'<span style="color:{pal.text}">{esc}</span>')
        del cur
        if at_end:
            self.log.moveCursor(QTextCursor.End)
            self.log.ensureCursorVisible()

    def _copy_log(self) -> None:
        QGuiApplication.clipboard().setText(self.log.toPlainText())

    def running(self) -> bool:
        return bool(self.job) and self.job.get("state") == "running"


def spacer(h: int = 8) -> QWidget:
    w = QWidget()
    w.setFixedHeight(h)
    w.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    return w
