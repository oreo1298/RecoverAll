"""The scan file: folders by key, orphans and folder loops under "Lost files", filters, search, counts,
duplicates of carved files, save-as."""

from recoverall.core.fs.base import F_CARVED, F_SYSTEM, Entry
from recoverall.core.results import ScanDB, pack_runs, unpack_runs


def build(tmp_path):
    db = ScanDB.create(tmp_path / "x.rascan", {"spec": "/dev/x"})
    v = db.add_volume(name="C:", fstype="ntfs", offset=1048576, size=10 ** 9, origin="table", status="existing")
    with db.writer(v, base=1048576) as w:
        w.add(Entry(5, None, "", is_dir=True))
        w.add(Entry(30, 5, "Users", is_dir=True))
        w.add(Entry(31, 30, "photo.jpg", size=100, runs=[(4096, 100)], deleted=True, chance=3, mtime=1.7e9))
        w.add(Entry(33, 30, "notes.txt", size=10, data=b"0123456789", mtime=1.6e9))
        w.add(Entry(32, 999, "orphan.docx", size=10, runs=[(8192, 10)], deleted=True, chance=1))
        w.add(Entry(40, 41, "loopA", is_dir=True))
        w.add(Entry(41, 40, "loopB", is_dir=True))
        w.add(Entry(42, 41, "inloop.txt", size=5))
        w.add(Entry(0, 5, "$MFT", size=5, flags=F_SYSTEM))
    c = db.add_volume(name="Files found by signature", fstype="carved", offset=0, size=10 ** 9, origin="carved")
    with db.writer(c) as w:
        w.add(Entry("__root__", None, "", is_dir=True))
        w.add(Entry("cat:photo", "__root__", "Photos", is_dir=True))
        w.add(Entry("c1", "cat:photo", "f1.jpg", size=100, runs=[(1048576 + 4096, 100)], flags=F_CARVED, deleted=True,
                    chance=2))
        w.add(Entry("c2", "cat:photo", "f2.jpg", size=100, runs=[(5 * 1048576, 100)], flags=F_CARVED, deleted=True,
                    chance=2))
    return db, v, c


def test_tree_and_lost_files(tmp_path):
    db, v, _c = build(tmp_path)
    vol = db.volume(v)
    assert vol["files"] == 4 and vol["deleted_files"] == 2
    top = db.children(vol["root_id"])["rows"]
    assert [r["name"] for r in top] == ["Lost files", "Users"]      # folders first, system files hidden
    lost = db.children(vol["lost_id"])["rows"]
    assert {r["name"] for r in lost} == {"loopA", "orphan.docx"}
    loop_a = next(r for r in lost if r["name"] == "loopA")
    assert [r["name"] for r in db.children(loop_a["id"])["rows"]] == ["loopB"]
    assert db.path_of(db.search({"name": "photo.jpg"})["rows"][0]["id"]) == "Users/photo.jpg"
    assert len(db.children(vol["root_id"], filters={"hide_system": False})["rows"]) == 3


def test_filters_search_counts(tmp_path):
    db, v, _c = build(tmp_path)
    assert db.search({"deleted": True, "vol": v})["total"] == 2
    assert db.search({"name": "*.TXT"})["total"] == 2                 # wildcards, case-insensitive
    assert db.search({"cats": ["photo"]})["total"] == 3
    assert db.search({"chance": 3})["total"] == 3                     # existing files + the good deleted one
    assert db.search({"min_size": 50})["total"] == 3
    assert db.search({"after": 1.65e9, "files_only": True})["total"] == 1
    counts = db.counts()
    assert counts["photo"]["files"] == 3 and counts["document"]["files"] == 3
    rows = db.search({}, sort="size", desc=True)["rows"]
    assert rows[0]["size"] >= rows[-1]["size"]
    vol = db.volume(v)
    ids = set(db.subtree(vol["root_id"], {"deleted": True}))
    assert len(ids) == 2


def test_duplicates_and_save(tmp_path):
    db, _v, c = build(tmp_path)
    removed = db.drop_duplicates(c, min_chance=1)
    assert removed == 1                                               # f1.jpg = photo.jpg (same first byte)
    assert db.volume(c)["files"] == 1
    db.save_as(tmp_path / "copy.rascan")
    db2 = ScanDB.open(tmp_path / "copy.rascan")
    assert db2.stats()["files"] == db.stats()["files"]
    e = db2.entry(db2.search({"name": "notes.txt"})["rows"][0]["id"])
    assert e["data"] == b"0123456789"


def test_runs_pack():
    runs = [(0, 10), (-1, 4096), (2 ** 40, 7)]
    assert unpack_runs(pack_runs(runs)) == runs
    assert unpack_runs(None) == []


def test_checked_selection(tmp_path):
    """Checking a folder takes everything under it; unchecking inside it leaves just that out; something
    checked again inside the left-out part still counts."""
    db = ScanDB.create(tmp_path / "s.rascan", {"spec": "/dev/x"})
    v = db.add_volume(name="D:", fstype="ntfs", offset=0, size=10 ** 9, origin="table", status="existing")
    with db.writer(v) as w:
        w.add(Entry(5, None, "", is_dir=True))
        w.add(Entry(10, 5, "Photos", is_dir=True))
        w.add(Entry(11, 10, "2019", is_dir=True))
        w.add(Entry(12, 11, "a.jpg", size=100, runs=[(4096, 100)], deleted=True, chance=3))
        w.add(Entry(13, 11, "keep.jpg", size=200, runs=[(8192, 200)]))
        w.add(Entry(14, 10, "2020", is_dir=True))
        w.add(Entry(15, 14, "b.jpg", size=300, runs=[(12288, 300)]))
        w.add(Entry(16, 14, "empty.txt", size=0))
        w.add(Entry(17, 10, "top.jpg", size=400, runs=[(16384, 400)]))
        w.add(Entry(18, 5, "$Bitmap", size=50, data=bytes(50), flags=F_SYSTEM))
    ids = dict(db.conn.execute("SELECT name, id FROM entries WHERE name != ''").fetchall())
    photos = ids["Photos"]
    root = db.volume(v)["root_id"]
    names = lambda sel: sorted(db.entry(i)["name"] for i in sel)          # noqa: E731

    assert names(db.selection([photos])) == ["a.jpg", "b.jpg", "empty.txt", "keep.jpg", "top.jpg"]
    # 2019 unchecked inside the checked Photos folder, then keep.jpg checked again inside 2019
    assert names(db.selection([photos], [ids["2019"]])) == ["b.jpg", "empty.txt", "top.jpg"]
    assert names(db.selection([photos, ids["keep.jpg"]], [ids["2019"]])) == ["b.jpg", "empty.txt", "keep.jpg",
                                                                             "top.jpg"]
    # metadata files only with hide_system off; empty files aren't counted (recovery skips them)
    assert "$Bitmap" not in names(db.selection([root], [], {"hide_system": True}))
    assert "$Bitmap" in names(db.selection([root], [], {"hide_system": False}))
    st = db.selection_stats([photos], [ids["2019"]])
    assert st == {"files": 2, "bytes": 700, "deleted": 0}
    assert db.selection_stats([]) == {"files": 0, "bytes": 0, "deleted": 0}
    # the folders above an entry, nearest first
    anc = db.ancestors([ids["a.jpg"], photos, root])
    assert anc == {ids["a.jpg"]: [ids["2019"], photos, root], photos: [root], root: []}
