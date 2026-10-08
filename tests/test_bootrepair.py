"""Boot-sector and table repairs (TestDisk's Advanced menu), and the backups that make every write undoable."""

import os

import pytest
from imagekit import MiB, blank, mkfs, mount_loop, mtools_copy, need, sh

from recoverall.core import bootrepair, fsdetect, partitions, rawwrite
from recoverall.core.api import LocalAPI, wait_job
from recoverall.core.blockio import open_source
from recoverall.core.errors import RallError, UnsafeOperation


def problems(path, fstype=""):
    with open_source(str(path)) as src:
        return bootrepair.diagnose(src, 0, src.size, fstype)


def identify(path):
    with open_source(str(path)) as src:
        return fsdetect.identify(src)


@pytest.mark.parametrize("fstype", ["fat32", "ntfs", "exfat"])
def test_boot_sector_restored_from_its_backup(tmp_path, fstype):
    img = mkfs(tmp_path / "v.img", fstype, size=64 * MiB, label="VOL")
    good = img.read_bytes()
    assert problems(img, fstype) == []
    with open(img, "r+b") as fh:
        fh.write(bytes(512))                         # the boot sector is gone
    assert identify(img) is None
    found = problems(img)
    family = "fat" if fstype.startswith("fat") else fstype
    assert [p["id"] for p in found] == [f"{family}_boot_damaged"]
    fix = found[0]
    assert fix["severity"] == "error" and fix["fix"] == f"boot:{family}_boot"
    fn = getattr(bootrepair, fix["fix"].split(":")[1])
    res = fn(str(img), 0, 0, backup_dir=str(tmp_path / "b"), **fix["fix_options"])
    assert identify(img)["fstype"] == fstype
    assert problems(img, fstype) == []
    assert img.read_bytes()[:512] == good[:512]
    # undo puts the damage back
    rawwrite.restore(res["backup"])
    assert identify(img) is None


@pytest.mark.parametrize("fstype,damaged", [("fat16", 0), ("fat16", 1), ("fat32", 0)])
def test_fat_tables_that_disagree(tmp_path, fstype, damaged):
    need("mcopy")
    img = mkfs(tmp_path / "f.img", fstype, size=40 * MiB, label="CARD")
    mtools_copy(img, {"a.txt": b"x" * 9000, "b.txt": b"y" * 9000, "c/d.txt": b"z" * 5000}, tmp_path)
    info = identify(img)
    at = (info["reserved_sectors"] + damaged * info["fat_sectors"]) * 512
    with open(img, "r+b") as fh:
        fh.seek(at + 12)
        fh.write(bytes(48))                          # one copy of the FAT lost its chains
    found = {p["id"]: p for p in problems(img, fstype)}
    assert "fat_copies_differ" in found
    p = found["fat_copies_differ"]
    assert p["fix"] == "boot:fat_copy"
    assert p["fix_options"] == {"from_index": 1 - damaged, "to_index": damaged}     # the intact copy is the source
    bootrepair.fat_copy(str(img), 0, 0, backup_dir=str(tmp_path / "b"), **p["fix_options"])
    assert "fat_copies_differ" not in {q["id"] for q in problems(img, fstype)}


def test_ext_backup_superblocks(tmp_path):
    img = mkfs(tmp_path / "e.img", "ext4", size=64 * MiB, extra=["-b", "1024"])
    with open(img, "r+b") as fh:
        fh.seek(1024)
        fh.write(bytes(1024))
    found = problems(img)
    assert [p["id"] for p in found] == ["ext_superblock_damaged"]
    assert found[0]["fix"] == "fsck:backup_superblock"
    assert found[0]["fix_options"] == {"superblock": 8193, "block_size": 1024}
    with open_source(str(img)) as src:
        backups = bootrepair.backup_superblocks(src)
    assert [b["superblock"] for b in backups][:3] == [8193, 24577, 40961]


def test_ext_superblock_repair_job(tmp_path):
    need("e2fsck")
    api = LocalAPI()
    if not api.root:
        pytest.skip("repairs need root")
    img = mkfs(tmp_path / "e.img", "ext4", size=64 * MiB, extra=["-b", "1024"])
    with open(img, "r+b") as fh:
        fh.seek(1024)
        fh.write(bytes(1024))
    try:
        p = api.diagnose(source=str(img), fstype="ext4")[0]
        job = api.start_repair(source=str(img), action=p["fix"], fstype="ext4", options=p["fix_options"])
        done = wait_job(api, job["id"], 120)
        assert done["state"] == "done", done.get("error")
        assert identify(img)["fstype"] == "ext4"
    finally:
        api.close()


@pytest.fixture
def gpt_disk(tmp_path):
    need("sfdisk")
    disk = blank(tmp_path / "gpt.img", 64 * MiB)
    sh("sfdisk", "-q", disk, input_bytes=b"label: gpt\nstart=2048, size=40960, type=L, name=root\n")
    return disk


@pytest.mark.parametrize("damage,source", [((512, 512), "backup"), ((64 * MiB - 512, 512), "primary")])
def test_gpt_rebuilt_from_the_other_copy(gpt_disk, tmp_path, damage, source):
    good = gpt_disk.read_bytes()
    with open(gpt_disk, "r+b") as fh:
        fh.seek(damage[0])
        fh.write(bytes(damage[1]))
    found = problems(gpt_disk)
    assert len(found) == 1 and found[0]["fix"] == "boot:gpt_rebuild"
    assert found[0]["fix_options"] == {"from_": source}
    res = bootrepair.gpt_rebuild(str(gpt_disk), backup_dir=str(tmp_path / "b"), **found[0]["fix_options"])
    assert res["table_ok"]
    assert problems(gpt_disk) == []
    assert gpt_disk.read_bytes() == good


def test_protective_mbr_and_signature(gpt_disk, tmp_path):
    with open(gpt_disk, "r+b") as fh:
        fh.write(bytes(512))
    ids = {p["id"] for p in problems(gpt_disk)}
    assert ids, "a GPT without its protective MBR is reported"
    bootrepair.gpt_protective_mbr(str(gpt_disk), backup_dir=str(tmp_path / "b"))
    with open_source(str(gpt_disk)) as src:
        t = partitions.read_table(src)
    assert t["mbr"]["protective"] and t["mbr"]["signature"]
    with open(gpt_disk, "r+b") as fh:
        fh.seek(510)
        fh.write(b"\0\0")
    bootrepair.mbr_signature(str(gpt_disk), backup_dir=str(tmp_path / "b"))
    assert gpt_disk.read_bytes()[510:512] == b"\x55\xaa"


def test_boot_repair_job_through_the_api(tmp_path):
    api = LocalAPI()
    if not api.root:
        pytest.skip("repairs need root")
    img = mkfs(tmp_path / "v.img", "fat32", size=64 * MiB)
    with open(img, "r+b") as fh:
        fh.write(bytes(512))
    try:
        p = api.diagnose(source=str(img))[0]
        job = api.start_repair(source=str(img), action=p["fix"], fstype="", options=p["fix_options"])
        done = wait_job(api, job["id"], 60)
        assert done["state"] == "done", done.get("error")
        assert done["result"]["backup"]
        assert identify(img)["fstype"] == "fat32"
        assert any(b["path"] == done["result"]["backup"] for b in api.list_backups())
    finally:
        api.close()


# ---------------------------------------------------------------------- rawwrite
def test_backup_write_restore_roundtrip(tmp_path):
    dev = tmp_path / "dev.img"
    original = os.urandom(64 * 1024)
    dev.write_bytes(original)
    folder = tmp_path / "backups"
    bk = rawwrite.backup_ranges(str(dev), [(0, 512), (4096, 1024), (4500, 1000), (10**9, 10)], str(folder), "test")
    header, blobs = rawwrite.read_backup(bk)
    assert [(r["offset"], r["length"]) for r in header["ranges"]] == [(0, 512), (4096, 1404)]
    assert oct(os.stat(bk).st_mode & 0o777) == "0o600"
    rawwrite.write_at(str(dev), 0, b"A" * 512)
    rawwrite.write_at(str(dev), 4096, b"B" * 1404)
    rawwrite.note_written(bk)
    with pytest.raises(RallError):
        rawwrite.write_at(str(dev), 64 * 1024 - 10, b"C" * 20)       # never past the end
    assert len(dev.read_bytes()) == 64 * 1024
    res = rawwrite.restore(bk)
    assert res["ok"] and dev.read_bytes() == original
    assert len(rawwrite.list_backups(str(folder))) == 2              # the undo was saved too
    # a damaged backup is refused
    raw = bytearray(open(bk, "rb").read())
    raw[-1] ^= 0xFF
    bad = folder / "bad.rallbak"
    bad.write_bytes(bytes(raw))
    with pytest.raises(RallError):
        rawwrite.restore(str(bad))


def test_restore_refuses_another_disk(tmp_path):
    dev = tmp_path / "a.img"
    dev.write_bytes(os.urandom(32 * 1024))
    bk = rawwrite.backup_ranges(str(dev), [(512, 512)], str(tmp_path / "b"), "t")
    other = tmp_path / "other.img"
    other.write_bytes(os.urandom(16 * 1024))
    with pytest.raises(UnsafeOperation):
        rawwrite.restore(bk, str(other))
    # the start of the disk was rewritten by something else since: refused
    with open(dev, "r+b") as fh:
        fh.write(os.urandom(512))
    with pytest.raises(UnsafeOperation):
        rawwrite.restore(bk)
    assert rawwrite.read_backup(bk)[0]["ranges"][0]["offset"] == 512


def test_busy_targets_are_refused(tmp_path):
    img = mkfs(tmp_path / "m.img", "fat32", size=40 * MiB)
    assert rawwrite.busy_reasons(str(img)) == []
    with mount_loop(img, tmp_path / "mnt"):          # mounted through a loop device: hands off
        assert rawwrite.busy_reasons(str(img))
        with pytest.raises(UnsafeOperation):
            rawwrite.check_not_busy(str(img))
        with pytest.raises(UnsafeOperation):
            bootrepair.mbr_signature(str(img), backup_dir=str(tmp_path / "b"))
    assert rawwrite.busy_reasons(str(img)) == []
