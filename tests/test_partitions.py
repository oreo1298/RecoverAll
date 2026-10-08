"""Partition tables: reading GPT and MBR (with logical partitions), planning new ones, writing and undoing."""

import pytest
from imagekit import MiB, blank, need, sh

from recoverall.core import partitions, rawwrite
from recoverall.core.blockio import open_source

LINUX = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
BASIC = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"


def table_of(path) -> dict:
    with open_source(str(path)) as src:
        return partitions.read_table(src)


@pytest.fixture
def gpt_disk(tmp_path):
    need("sfdisk")
    disk = blank(tmp_path / "gpt.img", 64 * MiB)
    sh("sfdisk", "-q", disk, input_bytes=(
        f"label: gpt\nstart=2048, size=40960, type={BASIC}, name=\"Photos\"\n"
        f"start=43008, size=40960, type={LINUX}, name=Home\n").encode())
    return disk


@pytest.fixture
def mbr_disk(tmp_path):
    need("sfdisk")
    disk = blank(tmp_path / "mbr.img", 64 * MiB)
    sh("sfdisk", "-q", disk, input_bytes=(
        b"label: dos\nstart=2048, size=20480, type=c, bootable\nstart=22528, size=100000, type=5\n"
        b"start=24576, size=20480, type=83\nstart=47104, size=20480, type=7\n"))
    return disk


def test_read_gpt(gpt_disk):
    t = table_of(gpt_disk)
    assert t["type"] == "gpt" and t["ok"] and not t["problems"]
    got = [(p["number"], p["start"], p["size"], p["type"], p["name"]) for p in t["partitions"]]
    assert got == [(1, MiB, 20 * MiB, BASIC, "Photos"), (2, 21 * MiB, 20 * MiB, LINUX, "Home")]
    assert t["gpt"]["primary_ok"] and t["gpt"]["backup_ok"]
    assert t["mbr"]["protective"]


def test_read_mbr_with_logical_partitions(mbr_disk):
    t = table_of(mbr_disk)
    assert t["type"] == "dos" and not t["problems"]
    parts = t["partitions"]
    primary = [p for p in parts if not p.get("logical") and not p.get("extended")]
    logical = [p for p in parts if p.get("logical")]
    assert [(p["start"], p["size"]) for p in primary] == [(MiB, 10 * MiB)]
    assert primary[0]["bootable"]
    assert [(p["start"] // 512, p["size"] // 512) for p in logical] == [(24576, 20480), (47104, 20480)]
    assert [p["number"] for p in logical] == [5, 6]
    assert len(t["ebrs"]) == 2
    assert any(p.get("extended") for p in parts)


def test_damaged_main_gpt_falls_back_to_the_backup(gpt_disk):
    with open(gpt_disk, "r+b") as fh:
        fh.seek(512)
        fh.write(bytes(512))
    t = table_of(gpt_disk)
    assert t["type"] == "gpt"
    assert t["gpt"]["used_copy"] == "backup"
    assert t["problems"] and "backup" in t["problems"][0]
    assert [p["start"] for p in t["partitions"]] == [MiB, 21 * MiB]


def test_overlapping_partitions_are_reported(tmp_path):
    need("sfdisk")
    disk = blank(tmp_path / "bad.img", 32 * MiB)
    # write two overlapping entries by hand: sfdisk refuses to
    sh("sfdisk", "-q", disk, input_bytes=b"label: dos\nstart=2048, size=20480, type=83\n")
    with open(disk, "r+b") as fh:
        fh.seek(446 + 16)
        entry = bytearray(16)
        entry[4] = 0x83
        entry[8:12] = (10240).to_bytes(4, "little")
        entry[12:16] = (20480).to_bytes(4, "little")
        fh.write(entry)
    t = table_of(disk)
    assert any("overlap" in p for p in t["problems"])


def test_plan_table_checks_and_scripts():
    size = 64 * MiB
    ok = partitions.plan_table("gpt", [{"start": MiB, "size": 20 * MiB, "fstype": "ntfs", "name": "Data"},
                                       {"start": 21 * MiB, "size": 20 * MiB, "fstype": "ext4"}], size)
    assert ok["ok"], ok["problems"]
    assert "label: gpt" in ok["script"]
    assert BASIC in ok["script"] and LINUX in ok["script"]
    assert [p["type"] for p in ok["partitions"]] == [BASIC, LINUX]

    overlap = partitions.plan_table("dos", [{"start": MiB, "size": 20 * MiB, "type": "0x83"},
                                           {"start": 10 * MiB, "size": 20 * MiB, "type": "0x83"}], size)
    assert not overlap["ok"] and overlap["problems"]
    unaligned = partitions.plan_table("gpt", [{"start": MiB + 100, "size": MiB, "type": LINUX}], size)
    assert not unaligned["ok"]
    too_big = partitions.plan_table("gpt", [{"start": MiB, "size": 128 * MiB, "type": LINUX}], size)
    assert not too_big["ok"]
    assert not partitions.plan_table("sun", [], size)["ok"]


def test_plan_mbr_logical_partitions():
    size = 64 * MiB
    plan = partitions.plan_table("dos", [{"start": MiB, "size": 10 * MiB, "type": "0x0c"},
                                         {"start": 12 * MiB, "size": 10 * MiB, "type": "0x83", "logical": True},
                                         {"start": 24 * MiB, "size": 10 * MiB, "type": "0x07", "logical": True}], size)
    assert plan["ok"], plan["problems"]
    assert "label: dos" in plan["script"]
    assert "type=05" in plan["script"]           # the extended partition is made around the logical ones


def test_write_table_then_undo(gpt_disk, tmp_path):
    original = table_of(gpt_disk)
    before = gpt_disk.read_bytes()
    with open(gpt_disk, "r+b") as fh:                 # the table is lost: both copies are gone
        fh.write(bytes(34 * 512))
        fh.seek(64 * MiB - 33 * 512)
        fh.write(bytes(33 * 512))
    assert table_of(gpt_disk)["type"] == "none"
    wiped = gpt_disk.read_bytes()
    parts = [{"start": p["start"], "size": p["size"], "type": p["type"], "name": p["name"]}
             for p in original["partitions"]]
    plan = partitions.plan_table("gpt", parts, 64 * MiB)
    assert plan["ok"], plan["problems"]
    backups = tmp_path / "backups"
    res = partitions.write_table(str(gpt_disk), plan, str(backups))
    assert res["verified"], res["problems"]
    t = table_of(gpt_disk)
    assert [(p["start"], p["size"], p["type"], p["name"]) for p in t["partitions"]] == \
        [(p["start"], p["size"], p["type"], p["name"]) for p in original["partitions"]]
    assert t["gpt"]["primary_ok"] and t["gpt"]["backup_ok"]
    # nothing outside the table was touched
    after = gpt_disk.read_bytes()
    assert after[34 * 512:64 * MiB - 33 * 512] == before[34 * 512:64 * MiB - 33 * 512]
    listed = rawwrite.list_backups(str(backups))
    assert len(listed) == 1 and listed[0]["written"]
    undone = partitions.undo(res["backup"])
    assert undone["ok"] and gpt_disk.read_bytes() == wiped
    assert undone["table"]["type"] == "none"


def test_write_mbr_table(tmp_path):
    need("sfdisk")
    disk = blank(tmp_path / "new.img", 64 * MiB)
    plan = partitions.plan_table("dos", [{"start": MiB, "size": 10 * MiB, "type": "0x0c", "bootable": True},
                                         {"start": 12 * MiB, "size": 10 * MiB, "type": "0x83", "logical": True}],
                                 64 * MiB)
    res = partitions.write_table(str(disk), plan, str(tmp_path / "b"))
    assert res["verified"], res["problems"]
    t = res["table"]
    assert t["type"] == "dos"
    assert [(p["start"], p.get("logical", False)) for p in t["partitions"] if not p.get("extended")] == \
        [(MiB, False), (12 * MiB, True)]
