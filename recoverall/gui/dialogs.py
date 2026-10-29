"""Settings, About, the "type the serial number" confirmation, the recovery destination and unlocking."""

from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import __app_name__, __version__
from ..core.filetypes import CATEGORY_NAMES
from ..core.util import fmt_bytes
from .theme import theme
from .widgets import SegmentedControl, bind_icon, chip, icon_button, scaled_font

MODE_TEXT = {"helper": "Administrator access granted for this session.",
             "local": "Running as your user: image files you own can be scanned; disks need administrator rights.",
             "root": "Running as root.", "demo": "Demo mode: simulated disks, nothing touches your hardware."}


class ConfirmDialog(QDialog):
    """Type the disk's serial number (or model) to confirm a change to it."""

    def __init__(self, disk: dict, token: str, title: str, action: str, what: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(560)
        self.token = (token or "").strip()
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        top = QHBoxLayout()
        ic = QLabel()
        self._b = bind_icon(ic, "warning", "warning", 40)
        top.addWidget(ic, 0, Qt.AlignTop)
        head = QLabel(title)
        head.setWordWrap(True)
        head.setFont(scaled_font(head, 1.25, bold=True))
        top.addWidget(head, 1)
        lay.addLayout(top)
        info = QLabel(f"<b>{disk.get('display_name') or ''}</b><br>{disk.get('model') or ''} · "
                      f"{fmt_bytes(disk.get('size'))} · {disk.get('path')}"
                      + (f"<br>Serial {disk['serial']}" if disk.get("serial") else ""))
        info.setWordWrap(True)
        info.setObjectName("BannerWarn")
        lay.addWidget(info)
        if what:
            w = QLabel(what)
            w.setWordWrap(True)
            lay.addWidget(w)
        ask = QLabel(f"To continue, type the disk's {'serial number' if disk.get('serial') else 'model'}: "
                     f"<b>{self.token}</b>")
        ask.setWordWrap(True)
        ask.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(ask)
        self.edit = QLineEdit()
        self.edit.setPlaceholderText(self.token)
        lay.addWidget(self.edit)
        bb = QDialogButtonBox(QDialogButtonBox.Cancel)
        self.ok = bb.addButton(action, QDialogButtonBox.AcceptRole)
        self.ok.setProperty("variant", "danger")
        self.ok.setEnabled(False)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self.edit.textChanged.connect(lambda t: self.ok.setEnabled(t.strip().lower() == self.token.lower()))

    def text(self) -> str:
        return self.edit.text().strip()


def confirm_change(parent, disk: dict, title: str, action: str, what: str = "") -> str | None:
    """The typed confirmation, "" for image files (no confirmation needed), or None when cancelled."""
    if disk.get("is_image"):
        return ""
    dlg = ConfirmDialog(disk, disk.get("confirm_token") or disk.get("serial") or disk.get("model") or "",
                        title, action, what, parent)
    return dlg.text() if dlg.exec() else None


class RecoverDialog(QDialog):
    """Where the recovered files go, and how."""

    def __init__(self, gs, summary: str, source_name: str = "", parent=None):
        super().__init__(parent)
        self.gs = gs
        self.setWindowTitle("Recover files")
        self.setMinimumWidth(600)
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        head = QLabel(summary)
        head.setFont(scaled_font(head, 1.15, bold=True))
        head.setWordWrap(True)
        lay.addWidget(head)
        warn = QLabel("Save them on <b>another disk</b> than " + (f"<b>{source_name}</b>" if source_name else
                      "the one you recover from") + ": writing there could overwrite the files you want back.")
        warn.setWordWrap(True)
        warn.setObjectName("BannerWarn")
        lay.addWidget(warn)
        f = QFormLayout()
        f.setVerticalSpacing(10)
        row = QHBoxLayout()
        self.folder = QLineEdit(gs.recover_folder or os.path.join(os.path.expanduser("~"), "Recovered"))
        b = icon_button("", "open", "", "Choose a folder")
        b.clicked.connect(self._browse)
        row.addWidget(self.folder, 1)
        row.addWidget(b)
        f.addRow("Save in", row)
        self.keep = QCheckBox("Keep the folders (a folder per volume, then the original folders)")
        self.keep.setChecked(gs.keep_paths)
        f.addRow("", self.keep)
        self.times = QCheckBox("Give the files their original dates")
        self.times.setChecked(gs.restore_times)
        f.addRow("", self.times)
        self.report = QCheckBox("Write a report (which files had unreadable parts)")
        self.report.setChecked(gs.write_report)
        f.addRow("", self.report)
        self.repair = QCheckBox("Repair damaged photos and videos afterwards (as copies named “… (repaired)”)")
        self.repair.setToolTip("Files found by signature, and deleted files with less than a good chance, are "
                               "checked; the ones that are damaged get a repaired copy next to them.")
        self.repair.setChecked(gs.repair_after)
        f.addRow("", self.repair)
        ref_row = QHBoxLayout()
        self.reference = QLineEdit()
        self.reference.setPlaceholderText("Optional: a good video or photo from the same camera")
        self.reference.setToolTip("Unfinished recordings (the camera stopped before writing the video's index) can "
                                  "only be repaired with a good recording from the same camera with the same "
                                  "settings. A photo from the same camera helps photos whose header is lost.")
        rb = icon_button("", "open", "", "Choose the reference file")
        rb.clicked.connect(self._browse_reference)
        ref_row.addWidget(self.reference, 1)
        ref_row.addWidget(rb)
        self.ref_label = QLabel("Reference")
        f.addRow(self.ref_label, ref_row)
        self.repair.toggled.connect(lambda on: (self.reference.setEnabled(on), rb.setEnabled(on)))
        self.reference.setEnabled(self.repair.isChecked())
        rb.setEnabled(self.repair.isChecked())
        lay.addLayout(f)
        note = QLabel("Nothing is overwritten: a second file with the same name gets “ (2)”. Names the destination "
                      "can't store (FAT/NTFS sticks) are made safe.")
        note.setObjectName("Faint")
        note.setWordWrap(True)
        lay.addWidget(note)
        bb = QDialogButtonBox(QDialogButtonBox.Cancel)
        self.ok = bb.addButton("Recover", QDialogButtonBox.AcceptRole)
        self.ok.setProperty("variant", "primary")
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _browse(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Save the recovered files in", self.folder.text())
        if d:
            self.folder.setText(d)

    def _browse_reference(self) -> None:
        p, _f = QFileDialog.getOpenFileName(self, "A good file from the same camera", os.path.expanduser("~"),
                                            "Videos and photos (*.mp4 *.mov *.m4v *.3gp *.mkv *.mts *.m2ts *.avi "
                                            "*.jpg *.jpeg);;All files (*)")
        if p:
            self.reference.setText(p)

    def value(self) -> tuple[str, dict]:
        dest = self.folder.text().strip()
        self.gs.recover_folder = dest
        self.gs.keep_paths = self.keep.isChecked()
        self.gs.restore_times = self.times.isChecked()
        self.gs.write_report = self.report.isChecked()
        self.gs.repair_after = self.repair.isChecked()
        self.gs.save()
        opts = {"keep_paths": self.keep.isChecked(), "volume_folders": self.keep.isChecked(),
                "restore_times": self.times.isChecked(), "report": self.report.isChecked(),
                "repair": self.repair.isChecked()}
        ref = self.reference.text().strip()
        if self.repair.isChecked() and ref:
            opts["reference"] = ref
        return dest, opts


class UnlockDialog(QDialog):
    def __init__(self, what: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Unlock an encrypted volume")
        self.setMinimumWidth(480)
        lay = QVBoxLayout(self)
        t = QLabel(f"<b>{what}</b> is encrypted. Enter its passphrase — for BitLocker, the password or the 48-digit "
                   "recovery key. It is opened read-only.")
        t.setWordWrap(True)
        lay.addWidget(t)
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.Password)
        lay.addWidget(self.edit)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)


class TypeChips(QWidget):
    """Chips for the file categories the signature search looks for."""

    def __init__(self, selected: list[str] | None = None, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        sel = set(selected or CATEGORY_NAMES)
        self.chips = {}
        for key, name in CATEGORY_NAMES.items():
            c = chip(name, key in sel)
            self.chips[key] = c
            lay.addWidget(c)
        lay.addStretch(1)

    def value(self) -> list[str]:
        return [k for k, c in self.chips.items() if c.isChecked()]

    def set_value(self, cats: list[str]) -> None:
        for k, c in self.chips.items():
            c.setChecked(k in cats)


class SettingsDialog(QDialog):
    def __init__(self, bridge, gs, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(640)
        self.bridge = bridge
        self.gs = gs
        lay = QVBoxLayout(self)
        tabs = QTabWidget()
        lay.addWidget(tabs)

        app = QWidget()
        f = QFormLayout(app)
        f.setVerticalSpacing(10)
        self.theme = QComboBox()
        for v, label in (("system", "Follow the system"), ("dark", "Dark"), ("light", "Light")):
            self.theme.addItem(label, v)
        self.theme.setCurrentIndex(max(0, self.theme.findData(gs.theme)))
        f.addRow("Theme", self.theme)
        self.notify = QCheckBox("Flash the window when a scan or a recovery finishes in the background")
        self.notify.setChecked(gs.notify)
        f.addRow("", self.notify)
        row = QHBoxLayout()
        self.folder = QLineEdit(gs.recover_folder)
        self.folder.setPlaceholderText("Ask every time")
        b = icon_button("", "open", "", "Choose a folder")
        b.clicked.connect(self._browse)
        row.addWidget(self.folder, 1)
        row.addWidget(b)
        f.addRow("Recover into", row)
        self.mode = SegmentedControl()
        for v, label in (("quick", "Quick"), ("deep", "Deep"), ("carve", "Signatures")):
            self.mode.add(label, v)
        self.mode.set_value(gs.scan_mode)
        f.addRow("Default scan", self.mode)
        self.types = TypeChips(gs.carve_types)
        f.addRow("Signature search", self.types)
        self.system = QCheckBox("Show filesystem metadata files ($MFT, journals…) in the results")
        self.system.setChecked(gs.show_system)
        f.addRow("", self.system)
        tabs.addTab(app, "App")

        acc = QWidget()
        a = QVBoxLayout(acc)
        mode = QLabel(MODE_TEXT.get(bridge.mode, bridge.mode))
        mode.setWordWrap(True)
        mode.setFont(scaled_font(mode, 1.0, bold=True))
        a.addWidget(mode)
        expl = QLabel("Reading whole disks needs root. RecoverAll runs a small helper with administrator rights "
                      "(through polkit/pkexec) for as long as the app is open; the app itself runs as you, and the "
                      "files it recovers belong to you. Disks are only ever opened read-only, except when you write "
                      "a partition table or run a repair — and those are backed up first.")
        expl.setWordWrap(True)
        expl.setObjectName("Muted")
        a.addWidget(expl)
        btn = icon_button("Grant access for this session", "unlock", "primary")
        btn.setEnabled(not bridge.privileged)
        btn.clicked.connect(lambda: (bridge.ensure_access(), self.accept()))
        row2 = QHBoxLayout()
        row2.addWidget(btn)
        row2.addStretch(1)
        a.addLayout(row2)
        a.addStretch(1)
        tabs.addTab(acc, "Access")

        tl = QWidget()
        t = QVBoxLayout(tl)
        self.tools_label = QLabel("Checking…")
        self.tools_label.setWordWrap(True)
        self.tools_label.setTextFormat(Qt.RichText)
        t.addWidget(self.tools_label)
        t.addStretch(1)
        tabs.addTab(tl, "Tools")
        bridge.call("tool_list", done=self._tools, error=lambda e: self.tools_label.setText(str(e)))

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _browse(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Recover into", self.folder.text())
        if d:
            self.folder.setText(d)

    def _tools(self, items: list) -> None:
        pal = theme.palette
        rows = ["<p>None of these is needed to find and recover files: the engines are built in. They add "
                "imaging of failing disks, repairs, encrypted volumes and a second engine.</p><table>"]
        for t in items or []:
            ok = bool(t.get("path"))
            mark = "✓" if ok else "·"
            color = pal.success if ok else pal.text_faint
            rows.append(f"<tr><td style='color:{color}; padding-right:8px'>{mark}</td><td><b>{t['name']}</b></td>"
                        f"<td style='padding-left:12px'>{t.get('use', '')}</td>"
                        f"<td style='padding-left:12px; color:{pal.text_muted}'>{t.get('path') or 'install ' + t['package']}"
                        f"</td></tr>")
        self.tools_label.setText("".join(rows) + "</table>")

    def accept(self) -> None:
        gs = self.gs
        gs.theme = self.theme.currentData()
        gs.notify = self.notify.isChecked()
        gs.recover_folder = self.folder.text().strip()
        gs.scan_mode = self.mode.value() or "quick"
        gs.carve_types = self.types.value()
        gs.show_system = self.system.isChecked()
        gs.save()
        super().accept()


class AboutDialog(QDialog):
    def __init__(self, parent=None, app_icon=None, bridge=None):
        super().__init__(parent)
        self.setWindowTitle(f"About {__app_name__}")
        self.setMinimumWidth(540)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        top = QHBoxLayout()
        logo = QLabel()
        if app_icon is not None and not app_icon.isNull():
            logo.setPixmap(app_icon.pixmap(72, 72))
        top.addWidget(logo, 0, Qt.AlignTop)
        col = QVBoxLayout()
        name = QLabel(__app_name__)
        name.setFont(scaled_font(name, 1.7, bold=True))
        col.addWidget(name)
        ver = QLabel(f"Version {__version__}")
        ver.setObjectName("Muted")
        col.addWidget(ver)
        desc = QLabel("Recover deleted files from every popular filesystem, rebuild lost and damaged ones, put "
                      "deleted partitions back, get photos off memory cards, repair damaged files, image failing "
                      "disks and read RAIDs without their controller. For Linux.")
        desc.setWordWrap(True)
        col.addWidget(desc)
        top.addLayout(col, 1)
        lay.addLayout(top)
        credits = QLabel("Its own readers for NTFS, FAT, exFAT, ext2/3/4, XFS, HFS+ and ISO 9660, its own partition "
                         "search and signature search. Optionally uses <b>GNU ddrescue</b>, <b>The Sleuth Kit</b>, "
                         "<b>btrfs-progs</b>, <b>cryptsetup</b> and the filesystems' own repair tools. Not affiliated "
                         "with R-Studio, GetDataBack, TestDisk or PhotoRec.<br><br>MIT License · "
                         "<a href='https://github.com/oreo1298/RecoverAll'>github.com/oreo1298/RecoverAll</a>")
        credits.setWordWrap(True)
        credits.setOpenExternalLinks(True)
        credits.setObjectName("Muted")
        lay.addWidget(credits)
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(self.reject)
        bb.accepted.connect(self.accept)
        lay.addWidget(bb)
