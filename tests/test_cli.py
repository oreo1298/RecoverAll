"""recoverctl in demo mode: every command runs and says what it should; and on a real image file."""

import json

import pytest

from recoverall.cli import main


def run(capsys, *args) -> tuple[int, str]:
    code = main(list(args))
    out = capsys.readouterr()
    return code, out.out + out.err


def test_list_info_doctor(capsys):
    code, out = run(capsys, "--demo", "list")
    assert code == 0 and "SanDisk Extreme" in out and "FAILING" in out
    code, out = run(capsys, "--demo", "info", "sda")
    assert code == 0 and "GPT" in out and "no partitions" in out
    code, out = run(capsys, "doctor")
    assert code == 0 and "ddrescue" in out


def test_scan_ls_find_recover(capsys, tmp_path):
    code, out = run(capsys, "--demo", "--json", "scan", "mmcblk0", "--photos")
    assert code == 0
    scan = json.loads(out)["scan"]
    code, out = run(capsys, "--demo", "ls", scan)
    assert code == 0 and "EOS_DIGITAL" in out
    code, out = run(capsys, "--demo", "ls", scan, "1:/DCIM/101CANON", "--limit", "3")
    assert code == 0 and "IMG_0001.JPG" in out and "deleted" in out
    code, out = run(capsys, "--demo", "find", scan, "--type", "video", "--deleted")
    assert code == 0 and "files match" in out
    code, out = run(capsys, "--demo", "recover", scan, str(tmp_path / "out"), "1:/DCIM/101CANON")
    assert code == 0 and "Recovered" in out
    code, out = run(capsys, "--demo", "preview", scan, "IMG_0005.JPG")
    assert code == 0
    # a scan by "last", its number in `scans`, or part of its name
    code, out = run(capsys, "--demo", "scans")
    assert code == 0 and " 1. " in out and "mmcblk0" in out
    for ref in ("last", "1", "mmcblk0-photos"):
        code, out = run(capsys, "--demo", "ls", ref)
        assert code == 0 and "EOS_DIGITAL" in out, ref
    code, out = run(capsys, "--demo", "ls", "999")
    assert code != 0 and "no scan number 999" in out


def test_partitions_image_raid(capsys, tmp_path):
    code, out = run(capsys, "--demo", "partitions", "sda", "--deep")
    assert code == 0 and "Backup" in out and "deleted" in out
    code, out = run(capsys, "--demo", "-y", "partitions", "sda", "--write")
    assert code == 0 and "Written" in out
    code, out = run(capsys, "--demo", "image", "sdb", str(tmp_path / "sdb.img"))
    assert code == 0 and "Imaged" in out
    code, out = run(capsys, "--demo", "raid", "-m", "sda", "-m", "sdb", "-m", "missing", "--level", "5")
    assert code == 0 and "1 missing" in out
    code, out = run(capsys, "--demo", "diagnose", "sdb")
    assert "NTFS boot sector" in out


def test_real_image(capsys, tmp_path):
    from imagekit import MiB, mkfs, mtools_copy, mtools_delete, need, payload
    need("mkfs.fat", "mcopy")
    img = tmp_path / "stick.img"
    mkfs(img, "fat16", size=32 * MiB, label="STICK")
    data = payload(200_000, 3)
    mtools_copy(img, {"report final.docx": data, "keep.txt": b"keep"})
    mtools_delete(img, "report final.docx")
    code, out = run(capsys, "--json", "scan", str(img))
    assert code == 0, out
    scan = json.loads(out)["scan"]
    code, out = run(capsys, "recover", scan, str(tmp_path / "out"), "--deleted")
    assert code == 0, out
    got = list((tmp_path / "out").rglob("report final.docx"))
    assert got and got[0].read_bytes() == data
    code, out = run(capsys, "hexdump", str(img), "0", "64")
    assert code == 0 and "000000000000" in out
    code, out = run(capsys, "--json", "partitions", str(img))
    assert code == 0
    res = json.loads(out)
    assert any(c["fstype"] == "fat16" for c in res["candidates"])


@pytest.mark.parametrize("cmd", ["formats", "history", "scans", "backups"])
def test_misc_commands(capsys, cmd):
    code, _out = run(capsys, "--demo", cmd)
    assert code == 0
