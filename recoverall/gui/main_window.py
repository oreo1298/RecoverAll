"""The main window: toolbar navigation, the seven pages, the access banner, status bar and toasts."""

from __future__ import annotations

import base64
import os

from PySide6.QtCore import QByteArray, QSize, Qt, QTimer
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QSizePolicy,
    QStackedWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from .. import __app_name__, __version__
from .dialogs import AboutDialog, SettingsDialog, UnlockDialog
from .drives_page import DrivesPage
from .theme import theme
from .widgets import StatusDot, Toast, bind_icon, flat_button, icon_button, scaled_font, tool_button

PAGES = (("Drives", "hdd", "Every disk, card, stick and image (Ctrl+1)"),
         ("Recover files", "trash_restore", "Find deleted and lost files and recover them (Ctrl+2)"),
         ("Photos", "camera", "Get deleted photos and videos back, the simple way (Ctrl+3)"),
         ("Partitions", "partition", "Find deleted partitions and put them back (Ctrl+4)"),
         ("Repair", "wrench", "Fix boot sectors and filesystems, repair damaged files (Ctrl+5)"),
         ("Imaging", "copy", "Image a failing disk; assemble a virtual RAID (Ctrl+6)"),
         ("History", "clock", "Everything that ran, with its log (Ctrl+7)"))

MODE_SHORT = {"helper": "administrator access", "local": "limited (no root)", "root": "running as root",
              "demo": "demo"}


class MainWindow(QMainWindow):
    def __init__(self, bridge, gui_settings, app_icon=None):
        super().__init__()
        self.bridge = bridge
        self.gs = gui_settings
        self.app_icon = app_icon
        self._quitting = False
        self.images: dict[str, dict] = {}
        self.setWindowTitle(__app_name__)
        self.resize(1480, 940)
        self.setMinimumSize(QSize(1160, 720))
        self._build_toolbar()

        central = QWidget()
        vl = QVBoxLayout(central)
        vl.setContentsMargins(12, 12, 12, 12)
        vl.setSpacing(10)
        self.banner = self._build_banner()
        vl.addWidget(self.banner)
        self.stack = QStackedWidget()
        vl.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        from .history_page import HistoryPage
        from .imaging_page import ImagingPage
        from .partitions_page import PartitionsPage
        from .photos_page import PhotosPage
        from .recover_page import RecoverPage
        from .repair_page import RepairPage
        self.drives = DrivesPage(bridge)
        self.recover = RecoverPage(bridge, gui_settings)
        self.photos = PhotosPage(bridge, gui_settings)
        self.partitions = PartitionsPage(bridge, gui_settings)
        self.repair = RepairPage(bridge, gui_settings)
        self.imaging = ImagingPage(bridge, gui_settings)
        self.history = HistoryPage(bridge)
        self.pages = [self.drives, self.recover, self.photos, self.partitions, self.repair, self.imaging, self.history]
        for p in self.pages:
            self.stack.addWidget(p)
        self._build_statusbar()
        self.toast = Toast(self)

        self.drives.action.connect(self._action)
        self.recover.open_image.connect(lambda: self._action("open_image", ""))
        self.partitions.scan_region.connect(self._scan_region)
        self.imaging.use_source.connect(self._use_source)
        bridge.disks_changed.connect(self._disks)
        bridge.detail_ready.connect(self._detail)
        bridge.message.connect(self.show_message)
        bridge.mode_changed.connect(lambda _m: self._update_mode())
        bridge.job_changed.connect(lambda _j: self._update_mode())
        bridge.job_finished.connect(self._job_finished)
        bridge.access_needed.connect(self._access_needed)
        for p in self.pages:
            if hasattr(p, "goto"):
                p.goto.connect(self.show_page)
        self._shortcuts()
        self._restore()
        self._update_mode()
        QTimer.singleShot(0, self._reopen_images)

    # ------------------------------------------------------------------ chrome
    def _build_toolbar(self) -> None:
        bar = QToolBar("Main")
        bar.setMovable(False)
        bar.setFloatable(False)
        bar.setIconSize(QSize(22, 22))
        bar.setContextMenuPolicy(Qt.PreventContextMenu)
        self.addToolBar(Qt.TopToolBarArea, bar)
        ident = QWidget()
        il = QHBoxLayout(ident)
        il.setContentsMargins(4, 0, 14, 0)
        il.setSpacing(10)
        logo = QLabel()
        if self.app_icon is not None and not self.app_icon.isNull():
            logo.setPixmap(self.app_icon.pixmap(34, 34))
        else:
            self._logo = bind_icon(logo, "trash_restore", "accent", 30)
        il.addWidget(logo)
        names = QVBoxLayout()
        names.setSpacing(0)
        app = QLabel(__app_name__)
        app.setObjectName("AppName")
        app.setFont(scaled_font(app, 1.28, bold=True))
        sub = QLabel("Recover files, partitions and photos")
        sub.setObjectName("Faint")
        sub.setFont(scaled_font(sub, 0.8))
        names.addWidget(app)
        names.addWidget(sub)
        il.addLayout(names)
        bar.addWidget(ident)
        bar.addSeparator()
        self.nav = QButtonGroup(self)
        self.nav.setExclusive(True)
        self.nav_buttons = []
        for i, (label, icon, tip) in enumerate(PAGES):
            b = tool_button(label, icon, tip, checkable=True)
            self.nav.addButton(b, i)
            bar.addWidget(b)
            self.nav_buttons.append(b)
        self.nav_buttons[0].setChecked(True)
        self.nav.idClicked.connect(self.show_page)
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        bar.addWidget(spacer)
        pill = QWidget()
        pl = QHBoxLayout(pill)
        pl.setContentsMargins(0, 0, 6, 0)
        pl.setSpacing(4)
        self.pill_dot = StatusDot(8)
        self.pill = QLabel("Looking for disks…")
        pl.addWidget(self.pill_dot)
        pl.addWidget(self.pill)
        bar.addWidget(pill)
        self.btn_theme = flat_button("sun", "Switch between dark and light", size=20)
        self.btn_theme.clicked.connect(self.toggle_theme)
        bar.addWidget(self.btn_theme)
        self.btn_settings = flat_button("settings", "Settings (Ctrl+,)", size=20)
        self.btn_settings.clicked.connect(self.open_settings)
        bar.addWidget(self.btn_settings)
        self.btn_about = flat_button("info", f"About {__app_name__}", size=20)
        self.btn_about.clicked.connect(lambda: AboutDialog(self, self.app_icon, self.bridge).exec())
        bar.addWidget(self.btn_about)
        theme.changed.connect(self._theme_icon)
        self._theme_icon(theme.palette)

    def _theme_icon(self, palette) -> None:
        self.btn_theme._binder.set_name("sun" if palette.dark else "moon", "text_muted")

    def _build_banner(self) -> QFrame:
        f = QFrame()
        f.setObjectName("Card")
        lay = QHBoxLayout(f)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(12)
        ic = QLabel()
        self._banner_icon = bind_icon(ic, "unlock", "warning", 22)
        lay.addWidget(ic)
        self.banner_text = QLabel("<b>Reading disks needs administrator rights.</b> You can look around and open image "
                                  "files you own; RecoverAll asks for your password when it needs it.")
        self.banner_text.setWordWrap(True)
        lay.addWidget(self.banner_text, 1)
        self.btn_grant = icon_button("Grant access", "unlock", "primary")
        self.btn_grant.clicked.connect(lambda: self.bridge.ensure_access())
        lay.addWidget(self.btn_grant)
        f.hide()
        return f

    def _build_statusbar(self) -> None:
        sb = self.statusBar()
        sb.setSizeGripEnabled(False)
        self.status_text = QLabel("Ready")
        sb.addWidget(self.status_text, 1)
        self.status_right = QLabel(f"{__app_name__} {__version__}")
        self.status_right.setObjectName("Muted")
        sb.addPermanentWidget(self.status_right)

    def _shortcuts(self) -> None:
        def sc(key, fn):
            s = QShortcut(QKeySequence(key), self)
            s.activated.connect(fn)
            return s
        for i in range(len(PAGES)):
            sc(f"Ctrl+{i + 1}", lambda i=i: self.show_page(i))
        sc("F5", lambda: self._action("refresh_all", ""))
        sc("Ctrl+O", lambda: self._action("open_image", ""))
        sc("Ctrl+,", self.open_settings)
        sc("Ctrl+Q", self.quit)

    # ------------------------------------------------------------------ navigation
    def show_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        self.nav_buttons[index].setChecked(True)
        page = self.pages[index]
        if hasattr(page, "shown"):
            page.shown()

    def all_disks(self) -> list[dict]:
        seen = {d["path"] for d in self.bridge.disks}
        return list(self.bridge.disks) + [d for p, d in self.images.items() if p not in seen]

    def _disks(self, _disks: list | None = None) -> None:
        disks = self.all_disks()
        self.drives.set_disks(disks)
        for p in self.pages[1:]:
            if hasattr(p, "set_disks"):
                p.set_disks(disks)
        self._update_mode()
        if self.bridge.privileged:
            QTimer.singleShot(200, self._fetch_details)

    def _fetch_details(self) -> None:
        for d in self.bridge.disks:
            if d["path"] not in self.bridge.details and not d.get("is_volume"):
                self.bridge.fetch_detail(d["path"])

    def _detail(self, d: dict) -> None:
        self.drives.set_detail(d)
        for p in self.pages[1:]:
            if hasattr(p, "set_detail"):
                p.set_detail(d)
        self._update_mode()

    def _update_mode(self) -> None:
        pal = theme.palette
        disks = self.all_disks()
        n = len(disks)
        failing = [d for d in (self.bridge.details.get(x["path"], x) for x in disks)
                   if (d.get("health") or {}).get("state") == "failing"]
        running = self.bridge.running_jobs()
        text = f"{n} drive{'s' if n != 1 else ''}" if n else "No drives"
        if failing:
            text += f" · {len(failing)} failing"
        if running:
            text += f" · {len(running)} job{'s' if len(running) != 1 else ''} running"
        self.pill.setText(text)
        self.pill_dot.set_color(pal.accent if running else pal.danger if failing else pal.success)
        self.status_right.setText(f"{MODE_SHORT.get(self.bridge.mode, self.bridge.mode)} · {__app_name__} {__version__}")
        self.banner.setVisible(not self.bridge.privileged)

    # ------------------------------------------------------------------ actions from the Drives page
    def _action(self, action: str, arg) -> None:
        path = arg if isinstance(arg, str) else (arg or {}).get("path", "")
        number = arg.get("number") if isinstance(arg, dict) else None
        if action == "recover":
            self.recover.start_with(path)
            self.show_page(1)
        elif action == "recover_part":
            self.recover.start_with(path, number)
            self.show_page(1)
        elif action == "photos":
            self.photos.start_with(path)
            self.show_page(2)
        elif action == "partitions":
            self.partitions.start_with(path)
            self.show_page(3)
        elif action == "repair":
            self.repair.start_with(path, number)
            self.show_page(4)
        elif action == "image":
            self.imaging.start_with(path)
            self.show_page(5)
        elif action == "raid":
            self.imaging.tabs.set_value("raid")
            self.imaging.stack.setCurrentIndex(1)
            self.show_page(5)
        elif action == "hex":
            self._hex(path)
        elif action == "unlock":
            self._unlock(path, number)
        elif action == "refresh":
            if self.bridge.privileged:
                self.bridge.fetch_detail(path, refresh=True)
            else:
                self.bridge.ensure_access(lambda: self.bridge.fetch_detail(path, refresh=True))
        elif action == "refresh_all":
            self.bridge.details.clear()
            self.bridge._disks_json = ""
            self.bridge.fetch_disks()
        elif action == "open_image":
            path, _f = QFileDialog.getOpenFileName(
                self, "Open a disk image", os.path.expanduser("~"),
                "Disk images and virtual RAIDs (*.img *.dd *.raw *.bin *.iso *.001 *.aa *.vhd *.vhdx *.vdi *.vmdk "
                "*.qcow2 *.qcow *.E01 *.e01 *.rallraid);;All files (*)")
            if path:
                self._use_source(path)
        elif action == "open_scan":
            self.show_page(1)
            self.recover.open_scan_file()

    def _use_source(self, path: str) -> None:
        def opened(d: dict) -> None:
            self.images[d["path"]] = d
            if d["path"] not in self.gs.recent_images:
                self.gs.recent_images = ([d["path"]] + self.gs.recent_images)[:8]
                self.gs.save()
            self._disks()
            self.show_page(0)
            self.show_message(f"{d.get('display_name')} is on the Drives page: scan it like a disk", "success")
        self.bridge.call("open_image", done=opened, path=path)

    def _reopen_images(self) -> None:
        for p in list(self.gs.recent_images):
            if os.path.exists(p):
                self.bridge.call("open_image", done=lambda d: (self.images.__setitem__(d["path"], d), self._disks()),
                                 error=lambda e: None, path=p)

    def _scan_region(self, path: str, offset: int, size: int) -> None:
        self.recover.start_region(path, offset, size)
        self.show_page(1)

    def _hex(self, path: str) -> None:
        from .hexview import HexDialog
        disk = next((d for d in self.all_disks() if d["path"] == path), {"path": path})
        disk = {**disk, **self.bridge.details.get(path, {})}

        def show():
            HexDialog(self.bridge, disk, self).exec()
        if self.bridge.privileged or disk.get("is_image"):
            show()
        else:
            self.bridge.ensure_access(show)

    def _unlock(self, path: str, number: int | None) -> None:
        disk = next((d for d in self.all_disks() if d["path"] == path), {})
        part = next((p for p in disk.get("partitions") or [] if p.get("number") == number), None)
        what = f"Partition {number}" + (f" ({part.get('label')})" if part and part.get("label") else "")
        dlg = UnlockDialog(what, self)
        if not dlg.exec():
            return
        source = {"path": path, "offset": part["start"], "size": part["size"]} if part else path
        pw = dlg.edit.text()

        def done(r):
            self.show_message(f"Unlocked read-only as {r['path']}: it's on the Drives page", "success")
            self.bridge.fetch_disks()
        self.bridge.ensure_access(lambda: self.bridge.call("unlock", done=done, source=source, passphrase=pw))

    def _access_needed(self) -> None:
        self.banner.show()
        self.show_message("This needs administrator rights: click “Grant access”", "warning")

    def _job_finished(self, job: dict) -> None:
        kind = {"done": "success", "failed": "error", "cancelled": "warning"}.get(job.get("state"), "info")
        text = job.get("title", "")
        if job.get("state") == "failed":
            text += f": {job.get('error') or job.get('message')}"
        else:
            text += f": {job.get('message') or job.get('state')}"
        self.show_message(text, kind)
        self.history.refresh()
        if not self.isActiveWindow() and self.gs.notify:
            QApplication.alert(self, 0)

    def show_message(self, text: str, kind: str = "info") -> None:
        self.status_text.setText(text)
        self.toast.show_message(text, kind)

    # ------------------------------------------------------------------ settings / theme
    def toggle_theme(self) -> None:
        mode = theme.toggle(QApplication.instance())
        self.gs.theme = mode
        self.gs.save()

    def open_settings(self) -> None:
        old = self.gs.theme
        dlg = SettingsDialog(self.bridge, self.gs, self)
        if dlg.exec() and self.gs.theme != old:
            theme.apply(QApplication.instance(), self.gs.theme)

    # ------------------------------------------------------------------ persistence
    def _restore(self) -> None:
        w = self.gs.window
        try:
            if w.get("geometry"):
                self.restoreGeometry(QByteArray(base64.b64decode(w["geometry"])))
        except (ValueError, TypeError):
            pass

    def quit(self) -> None:
        self._quitting = True
        self.close()

    def closeEvent(self, event) -> None:  # noqa: N802
        running = self.bridge.running_jobs()
        if running:
            answer = QMessageBox.warning(
                self, f"Quit {__app_name__}",
                f"{len(running)} operation(s) are still running ({', '.join(j['title'] for j in running)}).\n\n"
                "Quitting stops them. A scan keeps what it found so far (open it from “Earlier scans”), a recovery "
                "keeps the files copied so far, and an image can be continued from its mapfile.\n\nStop and quit?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                event.ignore()
                return
            for j in running:
                self.bridge.call("cancel_job", job_id=j["id"])
        self.gs.window = {"geometry": base64.b64encode(bytes(self.saveGeometry())).decode()}
        self.gs.save()
        self.bridge.close()
        super().closeEvent(event)
        QApplication.instance().quit()
