"""Pieces several pages share: the wizard stepper and the setup/progress page pattern."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QStackedWidget, QVBoxLayout, QWidget

from .jobview import JobView
from .widgets import scaled_font, set_object_name


class Stepper(QFrame):
    """① Source ── ② Destination ── ③ Layout ── ④ Start"""

    clicked = Signal(int)

    def __init__(self, titles: list[str], parent=None):
        super().__init__(parent)
        self.setObjectName("Step")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(4, 2, 4, 2)
        lay.setSpacing(10)
        self.nums: list[QLabel] = []
        self.titles: list[QLabel] = []
        self.index = 0
        self.reachable = 0
        for i, t in enumerate(titles):
            n = QLabel(str(i + 1))
            n.setFixedSize(24, 24)
            n.setAlignment(Qt.AlignCenter)
            n.setObjectName("StepNum")
            n.setFont(scaled_font(n, 0.9, bold=True))
            lab = QLabel(t)
            lab.setObjectName("StepTitle")
            n.mousePressEvent = lambda _e, i=i: self.clicked.emit(i)
            lab.mousePressEvent = lambda _e, i=i: self.clicked.emit(i)
            lay.addWidget(n)
            lay.addWidget(lab)
            self.nums.append(n)
            self.titles.append(lab)
            if i < len(titles) - 1:
                line = QFrame()
                line.setObjectName("StepLine")
                line.setMinimumWidth(30)
                lay.addWidget(line, 1)
        self.set_index(0)

    def set_index(self, index: int, reachable: int | None = None) -> None:
        self.index = index
        if reachable is not None:
            self.reachable = reachable
        for i, (n, t) in enumerate(zip(self.nums, self.titles)):
            set_object_name(n, "StepNumActive" if i == index else "StepNumDone" if i < index else "StepNum")
            n.setText("✓" if i < index else str(i + 1))
            set_object_name(t, "StepTitleActive" if i == index else "StepTitle")
            cursor = Qt.PointingHandCursor if i <= max(self.reachable, index) and i != index else Qt.ArrowCursor
            n.setCursor(cursor)
            t.setCursor(cursor)


class OperationPage(QWidget):
    """A page with a setup view and a progress view for the job it started."""

    goto = Signal(int)

    def __init__(self, bridge, extra: QWidget | None = None, parent=None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.bridge = bridge
        self.job_id: str | None = None
        self.outer = QStackedWidget()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.outer)
        self.setup = QWidget()
        self.outer.addWidget(self.setup)
        self.jobview = JobView(extra)
        self.outer.addWidget(self.jobview)
        self.jobview.stop_requested.connect(self._stop)
        self.jobview.done.connect(self.finish_run)
        bridge.job_changed.connect(self._job)
        bridge.job_log.connect(self._log)

    def run_job(self, job: dict) -> None:
        self.job_id = job["id"]
        self.jobview.reset(job.get("title", ""))
        self.jobview.set_job(job)
        self.outer.setCurrentIndex(1)
        known = self.bridge.jobs.get(job["id"])
        if known and known.get("state") != "running":
            self.jobview.set_job(known)
        self.bridge.call("job", job_id=job["id"], done=self._catch_up, error=lambda e: None)

    def _catch_up(self, full: dict) -> None:
        if full and full.get("id") == self.job_id:
            self.jobview.append_log(full.get("log") or [])
            self.jobview.set_job(full)
            self.job_data(full)

    def _job(self, job: dict) -> None:
        if job.get("id") == self.job_id:
            self.jobview.set_job(job)
            self.job_data(job)

    def job_data(self, job: dict) -> None:
        """Pages with live data (the rescue map) override this."""

    def _log(self, job_id: str, lines: list) -> None:
        if job_id == self.job_id:
            self.jobview.append_log(lines)

    def _stop(self, job_id: str) -> None:
        self.jobview.btn_stop.setEnabled(False)
        self.bridge.call("cancel_job", job_id=job_id)

    def finish_run(self) -> None:
        self.outer.setCurrentIndex(0)
        self.job_id = None
        self.after_run()

    def after_run(self) -> None:
        pass

    def running(self) -> bool:
        return self.job_id is not None and self.jobview.running()


def section_label(text: str) -> QLabel:
    lab = QLabel(text.upper())
    lab.setObjectName("CardTitle")
    lab.setFont(scaled_font(lab, 0.82, bold=True))
    return lab


def hint(text: str, faint: bool = True) -> QLabel:
    lab = QLabel(text)
    lab.setWordWrap(True)
    lab.setObjectName("Faint" if faint else "Muted")
    return lab


def vbox(*widgets, spacing: int = 8, margins=(0, 0, 0, 0)) -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(*margins)
    lay.setSpacing(spacing)
    for x in widgets:
        if isinstance(x, QWidget):
            lay.addWidget(x)
        else:
            lay.addLayout(x)
    return w


def set_row_visible(form, field: QWidget, visible: bool) -> None:
    """Show or hide a QFormLayout row (its label too)."""
    if hasattr(form, "setRowVisible"):
        form.setRowVisible(field, visible)
        return
    field.setVisible(visible)
    label = form.labelForField(field)
    if label is not None:
        label.setVisible(visible)


class ChoiceCard(QFrame):
    """A big selectable option: icon, title, a sentence, and a faint note (time estimate…)."""

    clicked = Signal(object)

    def __init__(self, value, icon: str, title: str, detail: str, note: str = "", parent=None):
        super().__init__(parent)
        from .widgets import bind_icon
        self.value = value
        self.setObjectName("Choice")
        self.setCursor(Qt.PointingHandCursor)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(12)
        ic = QLabel()
        self._ic = bind_icon(ic, icon, "accent", 28)
        lay.addWidget(ic, 0, Qt.AlignTop)
        col = QVBoxLayout()
        col.setSpacing(3)
        t = QLabel(title)
        t.setFont(scaled_font(t, 1.05, bold=True))
        d = QLabel(detail)
        d.setWordWrap(True)
        d.setObjectName("Muted")
        self.note = QLabel(note)
        self.note.setObjectName("Faint")
        self.note.setWordWrap(True)
        self.note.setFont(scaled_font(self.note, 0.88))
        self.note.setVisible(bool(note))
        col.addWidget(t)
        col.addWidget(d)
        col.addWidget(self.note)
        lay.addLayout(col, 1)

    def set_note(self, text: str) -> None:
        self.note.setText(text)
        self.note.setVisible(bool(text))

    def set_selected(self, on: bool) -> None:
        set_object_name(self, "ChoiceSelected" if on else "Choice")

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.value)
        super().mouseReleaseEvent(event)


class ChoiceGroup(QWidget):
    """ChoiceCards side by side (or stacked); one is selected."""

    changed = Signal(object)

    def __init__(self, vertical: bool = False, parent=None):
        super().__init__(parent)
        self.lay = QVBoxLayout(self) if vertical else QHBoxLayout(self)
        self.lay.setContentsMargins(0, 0, 0, 0)
        self.lay.setSpacing(10)
        self.cards: list[ChoiceCard] = []
        self._value = None

    def add(self, card: ChoiceCard) -> ChoiceCard:
        self.cards.append(card)
        self.lay.addWidget(card, 1)
        card.clicked.connect(self.set_value)
        return card

    def value(self):
        return self._value

    def set_value(self, value) -> None:
        self._value = value
        for c in self.cards:
            c.set_selected(c.value == value)
        self.changed.emit(value)

    def card(self, value) -> ChoiceCard | None:
        return next((c for c in self.cards if c.value == value), None)


def part_text(p: dict) -> str:
    from ..core.fs import fs_name
    from ..core.util import fmt_bytes
    bits = [f"{p.get('number')}"]
    if p.get("label"):
        bits.append(p["label"])
    bits.append(fs_name(p.get("fstype")) if p.get("fstype") else "no filesystem")
    bits.append(fmt_bytes(p.get("size")))
    return " · ".join(bits)


class SourcePicker(QWidget):
    """A disk (or image, or virtual RAID) and, optionally, one of its partitions."""

    changed = Signal()
    open_image = Signal()

    def __init__(self, bridge, partitions: bool = True, parent=None):
        super().__init__(parent)
        from PySide6.QtWidgets import QComboBox

        from .widgets import DiskCombo, icon_button
        self.bridge = bridge
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        self.disk = DiskCombo()
        self.disk.setMinimumContentsLength(30)
        lay.addWidget(self.disk, 3)
        self.part = QComboBox()
        self.part.setMinimumContentsLength(22)
        self.part.setVisible(partitions)
        lay.addWidget(self.part, 2)
        self.btn_image = icon_button("", "file_image", "", "Open a disk image file")
        self.btn_image.clicked.connect(self.open_image.emit)
        lay.addWidget(self.btn_image)
        self.disk.currentIndexChanged.connect(self._disk_changed)
        self.part.currentIndexChanged.connect(lambda _i: self.changed.emit())
        self.with_parts = partitions
        self.disks: list[dict] = []

    def set_disks(self, disks: list[dict], keep: str | None = None) -> None:
        self.disks = disks
        notes = {}
        for d in disks:
            if (d.get("health") or {}).get("state") == "failing":
                notes[d["path"]] = "failing: image it first"
        self.disk.set_disks(disks, notes, keep)
        self._disk_changed()

    def select(self, path: str, number: int | None = None) -> None:
        i = self.disk.findData(path)
        if i >= 0:
            self.disk.setCurrentIndex(i)
        self._disk_changed()
        if number is not None:
            j = self.part.findData(number)
            if j >= 0:
                self.part.setCurrentIndex(j)

    def current_disk(self) -> dict | None:
        path = self.disk.currentData()
        d = next((x for x in self.disks if x["path"] == path), None)
        if d is not None and path in self.bridge.details:
            d = {**d, **self.bridge.details[path]}
        return d

    def current_part(self) -> dict | None:
        d = self.current_disk()
        n = self.part.currentData()
        if d is None or n in (None, 0):
            return None
        return next((p for p in d.get("partitions") or [] if p.get("number") == n), None)

    def spec(self):
        d = self.current_disk()
        if d is None:
            return None
        p = self.current_part()
        if p is None:
            return d["path"]
        return {"path": d["path"], "offset": p["start"], "size": p["size"]}

    def _disk_changed(self, _i=None) -> None:
        d = self.current_disk()
        self.part.blockSignals(True)
        self.part.clear()
        self.part.addItem("The whole disk", 0)
        for p in (d or {}).get("partitions") or []:
            if not p.get("extended"):
                self.part.addItem(f"Partition {part_text(p)}", p.get("number"))
        self.part.blockSignals(False)
        self.part.setEnabled(self.part.count() > 1)
        self.changed.emit()
