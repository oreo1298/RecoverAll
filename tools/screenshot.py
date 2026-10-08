#!/usr/bin/env python3
"""Render the GUI in demo mode and save screenshots of every page.

Usage: tools/screenshot.py OUTPUT_DIR [--theme dark|light] [--size 1480x940] [--pages drives,results,...]
"""

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("XDG_CONFIG_HOME", tempfile.mkdtemp(prefix="rall-shot-"))
os.environ.setdefault("XDG_DATA_HOME", tempfile.mkdtemp(prefix="rall-shot-data-"))
os.environ.setdefault("XDG_CACHE_HOME", tempfile.mkdtemp(prefix="rall-shot-cache-"))
os.environ.setdefault("RALL_DEMO_PACE", "0.5")

from PySide6.QtCore import QCoreApplication, Qt  # noqa: E402
from PySide6.QtGui import QFont, QFontDatabase  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from recoverall.core.session import local_api  # noqa: E402
from recoverall.gui.app import _app_icon  # noqa: E402
from recoverall.gui.bridge import Bridge  # noqa: E402
from recoverall.gui.main_window import MainWindow  # noqa: E402
from recoverall.gui.settings import GuiSettings  # noqa: E402
from recoverall.gui.theme import theme  # noqa: E402

ALL = ("drives", "scan", "results", "photos", "partitions", "repair", "imaging", "history")


def pump(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        QCoreApplication.processEvents()
        time.sleep(0.01)


def wait_for(cond, timeout: float = 60.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end and not cond():
        pump(0.05)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    ap.add_argument("--theme", default="dark")
    ap.add_argument("--size", default="1480x940")
    ap.add_argument("--pages", default=",".join(ALL))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    w, h = (int(v) for v in args.size.split("x"))
    app = QApplication([])
    if "Noto Sans" in QFontDatabase.families():
        app.setFont(QFont("Noto Sans", 10))
    theme.apply(app, args.theme)
    api = local_api(demo=True)
    bridge = Bridge(api, poll_ms=1000)
    gs = GuiSettings(recover_folder="/run/media/demo/Backup/Recovered", image_folder="/run/media/demo/Backup/Images")
    win = MainWindow(bridge, gs, _app_icon())
    win.resize(w, h)
    bridge.start()
    win.show()
    pump(1.5)
    pages = args.pages.split(",")

    def shot(name):
        pump(0.5)
        win.toast.hide()
        win.grab().save(str(args.out / f"{name}-{args.theme}.png"))
        print("saved", name)

    def done(page):
        wait_for(lambda: page.jobview.job is not None and page.jobview.job.get("state") != "running")
        pump(0.3)
        page.jobview.btn_done.click()
        pump(0.8)

    if "drives" in pages:
        win.show_page(0)
        shot("drives")
    if "scan" in pages or "results" in pages:
        win._action("recover", "/dev/sda")
        pump(0.3)
        win.recover.mode.set_value("deep")
        win.recover.start()
        if "scan" in pages:
            pump(8.0 * float(os.environ["RALL_DEMO_PACE"]))
            shot("scan")
        done(win.recover)
        res = win.recover.results
        wait_for(lambda: res.model.total > 0)
        # open Photos/2021 of the deleted "Backup" partition and preview a picture
        top = res.tree.currentItem()
        top.setExpanded(True)
        wait_for(lambda: top.childCount() > 0)
        photos = next((top.child(i) for i in range(top.childCount()) if top.child(i).text(0) == "Photos"), None)
        if photos is not None:
            res.tree.setCurrentItem(photos)
            photos.setExpanded(True)
            wait_for(lambda: photos.childCount() > 0)
            res.tree.setCurrentItem(photos.child(3))
            wait_for(lambda: res.model.total > 0)
            pump(0.5)
            for i in (1, 2, 4):
                res.model.setData(res.model.index(i, 0), Qt.Checked, Qt.CheckStateRole)
            res.table.selectRow(2)
        pump(1.2)
        if "results" in pages:
            shot("results")
    if "photos" in pages:
        win._action("photos", "/dev/mmcblk0")
        pump(0.3)
        win.photos.start()
        done(win.photos)
        wait_for(lambda: len(win.photos.model.thumbs) > 30)
        win.photos.view.setCurrentIndex(win.photos.model.index(5, 0))
        for i in (0, 1, 2, 5, 7, 8):
            win.photos.model.toggle(win.photos.model.index(i, 0))
        pump(1.2)
        shot("photos")
    if "partitions" in pages:
        win._action("partitions", "/dev/sda")
        pump(0.3)
        win.partitions.mode.set_value("deep")
        win.partitions.start()
        done(win.partitions)
        win.partitions.tbl.selectRow(0)
        pump(0.5)
        shot("partitions")
    if "repair" in pages:
        win._action("repair", "/dev/sdb")
        pump(0.3)
        win.repair.source.part.setCurrentIndex(1)
        pump(0.3)
        win.repair.diagnose()
        pump(1.0)
        shot("repair")
    if "imaging" in pages:
        win._action("image", "/dev/sdb")
        pump(0.3)
        win.imaging.start_image()
        pump(5.5 * float(os.environ["RALL_DEMO_PACE"]))
        shot("imaging")
        done(win.imaging)
    if "history" in pages:
        win.show_page(6)
        pump(0.8)
        shot("history")
    win._quitting = True
    for j in list(bridge.jobs.values()):
        if j.get("state") == "running":
            api.cancel_job(j["id"])
    pump(0.5)
    bridge.jobs.clear()
    win.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
