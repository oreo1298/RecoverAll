"""The app with the simulated disks, headless: every page renders, and the scan → browse → recover, photo,
partition, repair and imaging flows run through to the end."""

import time

import pytest

pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtCore import QCoreApplication, Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog  # noqa: E402


def pump(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        QCoreApplication.processEvents()
        time.sleep(0.01)


def wait_for(cond, timeout: float = 30.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        pump(0.05)
        if cond():
            return True
    return False


@pytest.fixture(scope="module")
def app():
    a = QApplication.instance() or QApplication([])
    from recoverall.gui.theme import theme
    theme.apply(a, "dark")
    return a


@pytest.fixture
def window(app, monkeypatch, tmp_path):
    from recoverall.core.demo import DemoAPI
    from recoverall.gui import dialogs, partitions_page, repair_page
    from recoverall.gui.bridge import Bridge
    from recoverall.gui.main_window import MainWindow
    from recoverall.gui.settings import GuiSettings

    def confirm(_parent, disk, *_a, **_k):
        return disk.get("confirm_token") or ""
    monkeypatch.setattr(partitions_page, "confirm_change", confirm)
    monkeypatch.setattr(repair_page, "confirm_change", confirm)
    monkeypatch.setattr(dialogs.RecoverDialog, "exec", lambda self: QDialog.Accepted)
    api = DemoAPI()
    bridge = Bridge(api, poll_ms=500)
    win = MainWindow(bridge, GuiSettings(recover_folder=str(tmp_path / "out")))
    bridge.start()
    win.show()
    assert wait_for(lambda: len(win.drives.cards) == 6, 10)
    yield win
    win._quitting = True
    for j in list(bridge.jobs.values()):
        if j.get("state") == "running":
            api.cancel_job(j["id"])
    pump(0.3)
    bridge.jobs.clear()
    win.close()


def finish(page, timeout=30):
    assert wait_for(lambda: page.jobview.job is not None and page.jobview.job.get("state") != "running", timeout)
    state = page.jobview.job.get("state")
    page.jobview.btn_done.click()
    pump(0.6)
    return state


def test_every_page_renders(window):
    for i in range(7):
        window.show_page(i)
        pump(0.15)
    assert "6 drives" in window.pill.text() and "failing" in window.pill.text()
    window.toggle_theme()
    pump(0.2)
    from recoverall.gui.theme import theme
    assert theme.palette.name == "light"
    window.toggle_theme()


def test_scan_browse_recover(window):
    window._action("recover", "/dev/nvme0n1")
    page = window.recover
    pump(0.3)
    page.mode.set_value("quick")
    page.start()
    assert finish(page) == "done"
    assert page.outer.currentIndex() == 2
    res = page.results
    assert wait_for(lambda: res.tree.topLevelItemCount() >= 2, 10)
    assert wait_for(lambda: res.model.total > 0, 10)
    # search across volumes, filters, preview
    res.search.setText("*.docx")
    assert wait_for(lambda: res.model.mode == "search" and res.model.total > 5, 10)
    res.state.set_value(True)
    res.reload()
    assert wait_for(lambda: res.model.total > 0 and all(r["deleted"] for r in res.model.rows), 10)
    res.table.selectRow(0)
    assert wait_for(lambda: res.preview.entry is not None, 5)
    # check two files and recover them
    for i in range(2):
        res.model.setData(res.model.index(i, 0), Qt.Checked, Qt.CheckStateRole)
    assert res.btn_rec.isEnabled()
    res._recover_checked()
    assert finish(page) == "done"
    assert page.outer.currentIndex() == 2          # back to the results


def test_checking_a_folder_checks_everything_in_it(window):
    window._action("recover", "/dev/sda")
    page = window.recover
    pump(0.3)
    page.mode.set_value("deep")
    page.start()
    assert finish(page) == "done"
    res = page.results
    assert wait_for(lambda: res.model.total > 0, 10)
    db = window.bridge.api._scan(res.scan)

    def state(i):
        return res.model.data(res.model.index(i, 0), Qt.CheckStateRole)

    def counted():
        return res.sel_text.text().startswith("Checked: ") and "counting" not in res.sel_text.text()
    i = next(k for k, r in enumerate(res.model.rows) if r["name"] == "Photos")
    photos = res.model.rows[i]
    res.model.setData(res.model.index(i, 0), Qt.Checked, Qt.CheckStateRole)
    n = len(list(db.subtree(photos["id"], {"hide_system": True})))
    assert wait_for(counted, 5) and f"Checked: {n} files" in res.sel_text.text()
    # inside the checked folder everything shows checked; one subfolder unchecked is left out
    res._open(res.model.index(i, 0))
    assert wait_for(lambda: res.model.parent_id == photos["id"] and res.model.rows, 10)
    assert all(state(k) == Qt.Checked for k in range(len(res.model.rows)))
    j = next(k for k, r in enumerate(res.model.rows) if r["name"] == "2019")
    res.model.setData(res.model.index(j, 0), Qt.Unchecked, Qt.CheckStateRole)
    left_out = len(list(db.subtree(res.model.rows[j]["id"], {"hide_system": True})))
    assert wait_for(lambda: counted() and f"Checked: {n - left_out} files" in res.sel_text.text(), 5)
    top = res.tree.topLevelItem(0)
    tree_photos = next(top.child(k) for k in range(top.childCount()) if top.child(k).text(0) == "Photos")
    assert tree_photos.checkState(0) == Qt.PartiallyChecked and top.checkState(0) == Qt.PartiallyChecked
    excluded = dict(res.sel.exclude)
    tree_photos.setExpanded(True)                      # loads its subfolders: the selection must not change
    assert wait_for(lambda: tree_photos.childCount() > 0, 10)
    pump(0.3)
    assert res.sel.exclude == excluded and photos["id"] in res.sel.include
    tree_2019 = next(tree_photos.child(k) for k in range(tree_photos.childCount())
                     if tree_photos.child(k).text(0) == "2019")
    assert tree_2019.checkState(0) == Qt.Unchecked
    # checking in the tree works too, and a search shows what a checked folder holds as checked
    docs = next(top.child(k) for k in range(top.childCount()) if top.child(k).text(0) == "Documents")
    docs.setCheckState(0, Qt.Checked)
    assert docs.data(0, Qt.UserRole)["id"] in res.sel.include
    res.search.setText("IMG_2021")
    assert wait_for(lambda: res.model.mode == "search" and res.model.rows and state(0) == Qt.Checked, 10)
    res.search.setText("IMG_2019")
    assert wait_for(lambda: res.model.mode == "search" and res.model.rows and state(0) == Qt.Unchecked, 10)
    # what is recovered is exactly what was counted
    want = db.selection(list(res.sel.include), list(res.sel.exclude), {"hide_system": True})
    assert wait_for(counted, 5) and f"Checked: {len(want)} files" in res.sel_text.text()
    res._recover_checked()
    assert wait_for(lambda: page.jobview.job is not None and page.jobview.job.get("kind") == "recover"
                    and page.jobview.job.get("state") != "running", 30)
    assert window.bridge.api.job(job_id=page.jobview.job["id"])["result"]["files"] == len(want)
    page.jobview.btn_done.click()
    res.btn_none.click()
    assert not res.sel and res.btn_rec.isEnabled() is False


def test_photos(window):
    window._action("photos", "/dev/mmcblk0")
    page = window.photos
    pump(0.3)
    page.start()
    assert finish(page) == "done"
    assert wait_for(lambda: page.model.total > 50, 10)
    assert wait_for(lambda: len(page.model.thumbs) > 10, 10)
    page.model.check_all(True)
    assert page.btn_rec.isEnabled()


def test_partitions_and_repair(window):
    window._action("partitions", "/dev/sda")
    page = window.partitions
    pump(0.3)
    page.mode.set_value("deep")
    page.start()
    assert finish(page) == "done"
    assert wait_for(lambda: page.tbl.rowCount() == 3, 10)
    page._write()
    assert wait_for(lambda: page.outer.currentIndex() == 0, 10)
    assert wait_for(lambda: any(d["path"] == "/dev/sda" and d["partitions"] for d in window.bridge.disks), 10)
    window._action("repair", "/dev/sdb")
    rp = window.repair
    pump(0.3)
    rp.source.part.setCurrentIndex(1)
    rp.diagnose()
    assert wait_for(lambda: rp.problems.count() >= 1, 5)
    rp.run_action("boot:ntfs_boot", False, "Restore the NTFS boot sector")
    assert finish(rp) == "done"


def test_imaging_and_raid(window):
    window._action("image", "/dev/sdb")
    page = window.imaging
    pump(0.3)
    page.start_image()
    assert finish(page) == "done"
    window._action("raid", "")
    for p in ("/dev/sda", "/dev/sdb", "/dev/nvme0n1"):
        page._add_member(p)
    page._describe()
    assert wait_for(lambda: "RAID 5" in page.desc.text(), 5)
    page._save_raid()
    assert wait_for(lambda: any(d.get("kind") == "raid" for d in window.all_disks()), 5)


def test_exif_dates_read_like_other_dates():
    from recoverall.gui.results_view import _exif_date
    assert _exif_date("2021:10:21 12:00:00") == "2021-10-21 12:00"
    assert _exif_date("2021-10-21") == "2021-10-21"
