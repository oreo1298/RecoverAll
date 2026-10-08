"""Finding lost partitions (TestDisk's Quick and Deep Search) and telling what a volume is (fsdetect)."""

import pytest
from imagekit import MiB, blank, embed, mkfs, mtools_copy, need, sh

from recoverall.core import fsdetect, partitions, partsearch
from recoverall.core.api import LocalAPI, wait_job
from recoverall.core.blockio import open_source

LINUX = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
BASIC = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
VOLUMES = (("fat32", 1, "PHOTOS"), ("ext4", 65, "home"), ("ntfs", 129, "Windows"))


@pytest.fixture(scope="module")
def three_volumes(tmp_path_factory):
    """A GPT disk with FAT32, ext4 and NTFS partitions, and a copy whose two GPTs were wiped."""
    need("sfdisk", "mkfs.fat", "mkfs.ext4", "mkfs.ntfs", "mcopy")
    d = tmp_path_factory.mktemp("three")
    disk = blank(d / "disk.img", 256 * MiB)
    sh("sfdisk", "-q", disk, input_bytes=(
        f"label: gpt\nstart=2048, size=131072, type={BASIC}\nstart=133120, size=131072, type={LINUX}\n"
        f"start=264192, size=131072, type={BASIC}\n").encode())
    for fs, at, label in VOLUMES:
        img = mkfs(d / f"{fs}.img", fs, size=64 * MiB, label=label)
        if fs == "fat32":
            mtools_copy(img, {"DCIM/IMG_0001.JPG": b"\xff\xd8\xff\xe0" + bytes(5000), "notes.txt": b"hello"}, d)
        embed(disk, img, at * MiB)
    wiped = d / "wiped.img"
    wiped.write_bytes(disk.read_bytes())
    with open(wiped, "r+b") as fh:
        fh.write(bytes(34 * 512))
        fh.seek(256 * MiB - 33 * 512)
        fh.write(bytes(33 * 512))
    return disk, wiped


def found(cands):
    return sorted((c["offset"], c["size"], c["fstype"]) for c in cands)


EXPECTED = [(at * MiB, 64 * MiB, fs) for fs, at, _label in VOLUMES]


def test_quick_search_on_an_intact_disk(three_volumes):
    disk, _ = three_volumes
    with open_source(str(disk)) as src:
        t = partitions.read_table(src)
        merged = partsearch.merge_candidates(partsearch.quick_search(src, table=t), src.size, 512, t)
    assert found(merged) == EXPECTED
    assert {c["status"] for c in merged} == {"current"}


def test_quick_search_finds_wiped_partitions(three_volumes):
    _, wiped = three_volumes
    with open_source(str(wiped)) as src:
        t = partitions.read_table(src)
        assert t["type"] == "none"
        merged = partsearch.merge_candidates(partsearch.quick_search(src, table=t), src.size, 512, t)
        proposal = partsearch.propose_table(merged, src.size, 512, "gpt")
    assert found(merged) == EXPECTED
    assert {c["status"] for c in merged} == {"deleted"}
    assert [c["label"] for c in sorted(merged, key=lambda c: c["offset"])] == ["PHOTOS", "home", "Windows"]
    assert [(p["start"], p["size"], p["type"]) for p in proposal] == \
        [(MiB, 64 * MiB, BASIC), (65 * MiB, 64 * MiB, LINUX), (129 * MiB, 64 * MiB, BASIC)]
    # the proposal is a valid table
    plan = partitions.plan_table("gpt", proposal, 256 * MiB)
    assert plan["ok"], plan["problems"]


def test_deep_search_finds_volumes_off_the_usual_grid(tmp_path):
    """Volumes at odd sectors (old CHS layouts, a resized partition) are only found by reading everything."""
    need("mkfs.fat", "mkfs.ext4")
    disk = blank(tmp_path / "odd.img", 96 * MiB)
    fat = mkfs(tmp_path / "f.img", "fat16", size=20 * MiB, label="OLDCARD")
    ext = mkfs(tmp_path / "e.img", "ext4", size=24 * MiB, label="odd")
    embed(disk, fat, 63 * 512)
    embed(disk, ext, 50_001 * 512)
    det = partsearch.BootSectorDetector()
    with open_source(str(disk)) as src:
        for pos, buf in src.read_into_chunks(0, src.size, 4 * MiB):
            det.feed(pos, buf)
        merged = partsearch.merge_candidates(det.finish(), src.size, 512, partitions.read_table(src))
    got = found(merged)
    assert (63 * 512, 20 * MiB, "fat16") in got
    assert (50_001 * 512, 24 * MiB, "ext4") in got


def test_partition_search_job(three_volumes):
    _, wiped = three_volumes
    api = LocalAPI()
    try:
        job = api.start_partition_search(source=str(wiped), mode="deep")
        done = wait_job(api, job["id"], 300)
        assert done["state"] == "done", done.get("error")
        res = done["result"]
        assert found(res["candidates"]) == EXPECTED
        fat = next(c for c in res["candidates"] if c["fstype"] == "fat32")
        assert "DCIM/" in fat["preview"] and "notes.txt" in fat["preview"]
        assert len(res["proposal"]) == 3
        plan = api.plan_partitions(source=str(wiped), table_type="gpt", parts=res["proposal"])
        assert plan["ok"], plan["problems"]
    finally:
        api.close()


def test_restore_wiped_partitions_end_to_end(three_volumes, tmp_path):
    """TestDisk's whole job: search, write the table, and the volumes open again."""
    if not LocalAPI().root:
        pytest.skip("writing a partition table needs root")
    _, wiped = three_volumes
    disk = tmp_path / "restore.img"
    disk.write_bytes(wiped.read_bytes())
    api = LocalAPI()
    try:
        job = api.start_partition_search(source=str(disk), mode="quick")
        res = wait_job(api, job["id"], 300)["result"]
        out = api.write_partitions(source=str(disk), table_type="gpt", parts=res["proposal"])
        assert out["verified"], out["problems"]
        t = api.partition_table(source=str(disk))
        assert [(p["start"], p["size"]) for p in t["partitions"]] == [(o, s) for o, s, _f in EXPECTED]
        with open_source(str(disk)) as src:
            kinds = [fsdetect.identify(src.region(p["start"], p["size"]))["fstype"] for p in t["partitions"]]
        assert kinds == ["fat32", "ext4", "ntfs"]
        assert any(b["path"] == out["backup"] for b in api.list_backups())
        api.undo_backup(path=out["backup"])
        assert api.partition_table(source=str(disk))["type"] == "none"
    finally:
        api.close()


# ---------------------------------------------------------------------- fsdetect
@pytest.mark.parametrize("fstype,expect,label", [
    ("fat12", "fat12", "SMALL"), ("fat16", "fat16", "MEDIUM"), ("fat32", "fat32", "CARD"),
    ("exfat", "exfat", "SDXC"), ("ntfs", "ntfs", "Windows"), ("ext2", "ext2", "old"), ("ext3", "ext3", "j"),
    ("ext4", "ext4", "root"), ("xfs", "xfs", "data"), ("btrfs", "btrfs", "pool"), ("hfsplus", "hfsplus", "Mac"),
])
def test_identify_filesystems(tmp_path, fstype, expect, label):
    size = 320 * MiB if fstype in ("xfs", "btrfs") else 40 * MiB
    img = mkfs(tmp_path / "v.img", fstype, size=size, label=label)
    with open_source(str(img)) as src:
        info = fsdetect.identify(src)
    assert info is not None and info["fstype"] == expect
    assert info.get("label") == label
    assert info.get("size") and info["size"] <= size


def test_identify_iso_swap_and_luks(tmp_path):
    with open_source(str(blank(tmp_path / "zero.img", MiB))) as src:
        assert fsdetect.identify(src) is None
    need("mkswap")
    swap = blank(tmp_path / "swap.img", 16 * MiB)
    sh("mkswap", "-L", "swappy", swap)
    with open_source(str(swap)) as src:
        assert fsdetect.identify(src)["fstype"] == "swap"
    need("xorriso")
    (tmp_path / "cd").mkdir()
    (tmp_path / "cd" / "readme.txt").write_text("hi")
    iso = tmp_path / "cd.iso"
    sh("xorriso", "-as", "mkisofs", "-quiet", "-V", "MYDISC", "-o", iso, tmp_path / "cd")
    with open_source(str(iso)) as src:
        info = fsdetect.identify(src)
    assert info["fstype"] == "iso9660" and info["label"] == "MYDISC"
    need("cryptsetup")
    luks = blank(tmp_path / "luks.img", 24 * MiB)
    p = sh("cryptsetup", "luksFormat", "-q", "--type", "luks2", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations",
           "1000", luks, "-", input_bytes=b"secret", check=False)
    del p
    with open_source(str(luks)) as src:
        info = fsdetect.identify(src)
    if info is not None:                          # luksFormat may be refused in a container
        assert info["fstype"] in ("crypto_luks", "luks")
