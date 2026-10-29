"""Filesystem check and repair: every filesystem's checker against images made by mkfs and damaged in a known way
(check finds it, repair fixes it, a second check is clean); refusing mounted filesystems; reading tool output."""

import os
import shutil
import struct
import subprocess

import pytest
from imagekit import MiB, fuse_mount, mkfs, mount_loop

from recoverall.core import fsck
from recoverall.core.errors import Cancelled, NotSupported, ToolMissing, UnsafeOperation


def run(img, fstype, action, ctl, **kw):
    r = fsck.run_action(str(img), fstype, action, ctl, **kw)
    assert set(r) >= {"ok", "problems_found", "changed", "summary", "output", "command", "exit_code"}
    assert r["summary"] and r["summary"].endswith(".") and "\n" not in r["summary"]
    return r


def check_cycle(img, fstype, repair, ctl, **kw):
    """check → problems; REPAIR → changed; check → clean."""
    before = run(img, fstype, "check", ctl)
    assert before["problems_found"], before["output"]
    assert not before["changed"]
    assert "No problems" not in before["summary"]
    fixed = run(img, fstype, repair, ctl, **kw)
    assert fixed["ok"], fixed["output"]
    assert fixed["changed"] and fixed["problems_found"], fixed["output"]
    after = run(img, fstype, "check", ctl)
    assert after["ok"] and not after["problems_found"], after["output"]
    assert after["summary"].startswith("No problems found")
    return before, fixed, after


# ---------------------------------------------------------------------- the action table
def test_actions_table():
    for fstype in ("ext4", "ext2", "vfat", "fat32", "exfat", "ntfs", "xfs", "btrfs", "hfsplus", "f2fs", "jfs",
                   "reiserfs"):
        acts = fsck.actions_for(fstype)
        assert acts, fstype
        assert acts[0]["id"] == "check" and acts[0]["risk"] == "safe" and not acts[0]["writes"]
        ids = [a["id"] for a in acts]
        assert len(ids) == len(set(ids))
        for a in acts:
            assert a["risk"] in fsck.RISKS
            assert a["title"] and a["detail"] and a["package"]
            assert "<device>" in a["command"]
            assert a["available"] == ("unavailable" not in a)
            assert a["missing_program"] in (None, a["program"])
            if a["risk"] == "safe":
                assert not a["writes"]
    assert fsck.actions_for("zfs") == [] and fsck.actions_for(None) == []
    risky = {a["id"] for a in fsck.actions_for("btrfs") if a["risk"] == "risky"}
    assert {"repair", "chunk_recover"} <= risky
    assert "dangerous" in fsck.actions_for("btrfs")[-1]["detail"] or "worse" in fsck.actions_for("btrfs")[-1]["detail"]
    assert any(a["id"] == "zero_log" and a["risk"] == "risky" for a in fsck.actions_for("xfs"))
    assert "chkdsk" in fsck.actions_for("ntfs")[1]["note"]


def test_packages():
    assert fsck.package_for("ntfsfix", "fedora") == "ntfsprogs"
    assert fsck.package_for("ntfsfix", "debian") == "ntfs-3g"
    assert fsck.package_for("btrfs", "opensuse") == "btrfsprogs"
    assert fsck.package_for("e2fsck", "") == "e2fsprogs"
    hint = fsck.package_for("reiserfsck", "")
    assert hint.startswith("reiserfsprogs") and "Fedora: reiserfs-utils" in hint


def test_missing_tool(monkeypatch, tmp_path, ctl):
    monkeypatch.setattr(fsck, "which", lambda _name: None)
    acts = fsck.actions_for("ext4")
    assert not any(a["available"] for a in acts)
    assert acts[0]["missing_program"] == "e2fsck" and acts[0]["package"] == "e2fsprogs"
    img = tmp_path / "x.img"
    img.write_bytes(bytes(4096))
    with pytest.raises(ToolMissing, match="e2fsprogs"):
        fsck.run_action(str(img), "ext4", "check", ctl)
    with pytest.raises(NotSupported):
        fsck.run_action(str(img), "zfs", "check", ctl)


# ---------------------------------------------------------------------- reading the output (no tools needed)
E2_CLEAN = """e2fsck 1.47.0 (5-Feb-2023)
Pass 1: Checking inodes, blocks, and sizes
Pass 2: Checking directory structure
Pass 5: Checking group summary information
TEST: 11/40960 files (0.0% non-contiguous), 6708/40960 blocks"""

E2_FIXED = """e2fsck 1.47.0 (5-Feb-2023)
Pass 1: Checking inodes, blocks, and sizes
Root inode is not a directory.  Clear? yes

Pass 5: Checking group summary information
Block bitmap differences:  +(0--20) +22
Fix? yes

Free blocks count wrong for group #0 (4294967294, counted=30180).
Fix? yes


TEST: ***** FILE SYSTEM WAS MODIFIED *****
TEST: 11/40960 files (0.0% non-contiguous), 2609/40960 blocks"""


def test_summaries():
    assert fsck.summarize("ext4", E2_CLEAN, 0) == "No problems found."
    s = fsck.summarize("ext4", E2_FIXED, 1, "repair_all")
    assert s.startswith("Repaired 3 problems: Root inode is not a directory") and "Fix?" not in s
    assert fsck.summarize("ext4", E2_FIXED, 1).startswith("Repaired 3 problems")      # inferred: a repair
    s = fsck.summarize("ext4", E2_FIXED.replace("yes", "no"), 4, "check")
    assert s.startswith("Problems found: Root inode is not a directory")
    s = fsck.summarize("ext4", "e2fsck 1.47.0\next2fs_open2: Bad magic number in super-block\n"
                       "e2fsck: Superblock invalid, trying backup blocks...", 8, "check")
    assert s.startswith("The ext filesystem can't be read: Bad magic number")
    s = fsck.summarize("ext4", "TEST: Inode 12 has a bad extent.\n\nTEST: UNEXPECTED INCONSISTENCY; RUN fsck "
                       "MANUALLY.\n\t(i.e., without -a or -p options)", 4, "repair")
    assert "Repair everything" in s
    s = fsck.summarize("xfs", "Phase 1 - find and verify superblock...\nERROR: The filesystem has valuable "
                       "metadata changes in a log", 2, "repair")
    assert "journal" in s and "mount" in s
    s = fsck.summarize("ntfs", "Mounting volume... $MFTMirr does not match $MFT (record 1).\nFAILED\n"
                       "Attempting to correct errors...\nComparing $MFTMirr to $MFT... FAILED\nRemount failed", 1,
                       "check")
    assert s == "Problems found: $MFTMirr does not match $MFT (record 1)."
    s = fsck.summarize("vfat", "fsck.fat 4.2\nFATs differ but appear to be intact.\n  Using first FAT.\n"
                       "/DCIM/IMG_0001.JPG\n  File size is 1000 bytes, cluster chain length is 0 bytes.\n"
                       "  Truncating file to 0 bytes.\nfa.img: 1 files, 1/129022 clusters", 1, "repair")
    assert s.startswith("Repaired 2 problems: FATs differ but appear to be intact; /DCIM/IMG_0001.JPG: File size")
    s = fsck.summarize("hfsplus", "** Checking volume information.\n   Invalid volume free block count\n"
                       "   (It should be 15997 instead of 15897)\n** The volume X was found corrupt and needs to "
                       "be repaired.", 8, "check")
    assert s == "Problems found: Invalid volume free block count (It should be 15997 instead of 15897)."
    many = "\n".join(f"Inode {i} has illegal blocks.  Clear? no" for i in range(20))
    assert "(and 17 more)" in fsck.summarize("ext3", many, 4, "check")


def test_backup_groups():
    assert fsck._backup_groups(100) == [1, 3, 5, 7, 9, 25, 27, 49, 81]


# ---------------------------------------------------------------------- real filesystems
def test_ext4_group_descriptor(tmp_path, ctl):
    img = mkfs(tmp_path / "ext4.img", "ext4", size=160 * MiB)
    clean = run(img, "ext4", "check", ctl)
    assert clean["ok"] and not clean["problems_found"] and clean["exit_code"] == 0
    with open(img, "r+b") as f:          # the second group descriptor (4 KiB blocks, 64-byte descriptors)
        f.seek(4096 + 64)
        f.write(bytes(64))
    before, fixed, _after = check_cycle(img, "ext4", "repair_all", ctl)
    assert before["exit_code"] == 4 and "descriptor" in before["summary"].lower()
    assert fixed["exit_code"] in (1, 2) and fixed["summary"].startswith("Repaired")
    assert any("Pass 1" in m for m in ctl.messages)          # progress from the pass lines


def test_ext4_backup_superblock(tmp_path, ctl):
    img = mkfs(tmp_path / "ext4.img", "ext4", size=160 * MiB)
    assert fsck.ext_backup_superblocks(str(img))[0] == {"superblock": 32768, "block_size": 4096, "group": 1}
    with open(img, "r+b") as f:
        f.seek(1024)
        f.write(bytes(1024))             # the main superblock is gone
    backups = fsck.ext_backup_superblocks(str(img))
    assert backups and backups[0]["superblock"] == 32768 and backups[0]["block_size"] == 4096
    _before, fixed, _after = check_cycle(img, "ext4", "backup_superblock", ctl)
    assert "-b 32768 -B 4096" in fixed["command"]
    # a superblock the user gives: its block size is found, or left to e2fsck
    again = run(img, "ext4", "backup_superblock", ctl, superblock=32768)
    assert again["ok"] and "-b 32768 -B 4096" in again["command"]
    wrong = run(img, "ext4", "backup_superblock", ctl, superblock=12345)
    assert "-b 12345 " in wrong["command"] and "-B" not in wrong["command"]
    assert not wrong["ok"] and not wrong["changed"]
    with open(img, "rb") as f:
        f.seek(1024 + 56)
        assert f.read(2) == b"\x53\xef"


def test_fat32_media_byte(tmp_path, ctl):
    img = mkfs(tmp_path / "fat.img", "fat32", size=64 * MiB)
    with open(img, "rb") as f:
        boot = f.read(512)
    reserved = struct.unpack_from("<H", boot, 14)[0]
    with open(img, "r+b") as f:          # FAT[0]'s low byte must repeat the media byte (0xF8)
        f.seek(reserved * 512)
        f.write(b"\xf0")
    before, fixed, _after = check_cycle(img, "fat32", "repair", ctl)
    assert "FATs differ" in before["summary"]
    assert fixed["exit_code"] == 1


def test_exfat_boot_region(tmp_path, ctl):
    img = mkfs(tmp_path / "exfat.img", "exfat", size=64 * MiB)
    pristine = img.read_bytes()[:512 * 12]
    with open(img, "r+b") as f:          # one flipped byte: the boot checksum no longer matches
        f.seek(100)
        f.write(b"\x01")
    check_cycle(img, "exfat", "repair", ctl)
    assert img.read_bytes()[:512 * 12] == pristine

    acts = {a["id"]: a for a in fsck.actions_for("exfat")}
    if not acts["restore_boot"]["available"]:
        pytest.skip("this exfatprogs can't restore the boot sector (no -b)")
    with open(img, "r+b") as f:          # the boot sector is gone: "not formatted"
        f.write(bytes(512))
    gone = run(img, "exfat", "check", ctl)
    assert not gone["ok"] and gone["problems_found"]
    assert "can't be read" in gone["summary"]
    fixed = run(img, "exfat", "restore_boot", ctl)
    assert fixed["ok"] and fixed["changed"], fixed["output"]
    assert run(img, "exfat", "check", ctl)["summary"] == "No problems found."


def test_ntfs_mft_mirror(tmp_path, ctl):
    img = mkfs(tmp_path / "ntfs.img", "ntfs", size=64 * MiB)
    with open(img, "r+b") as f:
        boot = f.read(512)
        bps, spc = struct.unpack_from("<HB", boot, 11)
        mirr = struct.unpack_from("<Q", boot, 0x38)[0]
        off = mirr * bps * spc + 1024 + 0x100           # record 1 ($MFTMirr) in the mirror
        f.seek(off)
        b = f.read(1)
        f.seek(off)
        f.write(bytes([b[0] ^ 0xFF]))
    before, fixed, _after = check_cycle(img, "ntfs", "repair", ctl)
    assert "$MFTMirr" in before["summary"]
    assert "chkdsk" in fixed["summary"]


def test_xfs_secondary_superblock(tmp_path, ctl):
    img = mkfs(tmp_path / "xfs.img", "xfs", size=320 * MiB)
    with open(img, "r+b") as f:
        sb = f.read(512)
        bs, agblocks = struct.unpack_from(">I", sb, 4)[0], struct.unpack_from(">I", sb, 84)[0]
        f.seek(agblocks * bs)            # AG 1's superblock copy
        f.write(bytes(512))
    before, fixed, _after = check_cycle(img, "xfs", "repair", ctl)
    assert before["exit_code"] == 1 and "superblock" in before["summary"]
    assert fixed["exit_code"] == 0


def test_btrfs_superblock(tmp_path, ctl):
    img = mkfs(tmp_path / "btrfs.img", "btrfs", size=128 * MiB)
    assert run(img, "btrfs", "check", ctl)["summary"] == "No problems found."
    with open(img, "r+b") as f:
        f.seek(65536 + 0x100)
        f.write(b"\xff" * 16)            # the main superblock's checksum no longer matches
    before = run(img, "btrfs", "check", ctl)
    assert before["problems_found"] and not before["ok"]
    fixed = run(img, "btrfs", "super_recover", ctl)
    assert fixed["ok"] and fixed["changed"] and fixed["exit_code"] == 2
    after = run(img, "btrfs", "check", ctl)
    assert after["ok"] and not after["problems_found"]
    again = run(img, "btrfs", "super_recover", ctl)
    assert again["ok"] and not again["changed"]


def test_hfsplus_free_count(tmp_path, ctl):
    img = mkfs(tmp_path / "hfs.img", "hfsplus", size=32 * MiB)
    if shutil.which("fsck.hfsplus") is None and not os.path.exists("/usr/sbin/fsck.hfsplus"):
        pytest.skip("fsck.hfsplus is not installed")
    with open(img, "r+b") as f:
        f.seek(1024)
        hdr = bytearray(f.read(512))
        free = struct.unpack_from(">I", hdr, 0x30)[0]
        struct.pack_into(">I", hdr, 0x30, free - 100)
        f.seek(1024)
        f.write(hdr)
    before, _fixed, _after = check_cycle(img, "hfsplus", "repair", ctl)
    assert "free block count" in before["summary"]


# ---------------------------------------------------------------------- safety, loop devices, cancelling
@pytest.mark.root
def test_refuses_mounted(tmp_path, ctl):
    img = mkfs(tmp_path / "ext4.img", "ext4", size=32 * MiB)
    assert fsck.in_use(str(img)) == []
    with mount_loop(img, tmp_path / "mnt", "ext4", "ro"):
        reasons = fsck.in_use(str(img))
        assert any(str(tmp_path / "mnt") in r for r in reasons)
        for action in ("check", "repair_all"):
            with pytest.raises(UnsafeOperation, match="Unmount it first"):
                fsck.run_action(str(img), "ext4", action, ctl)
    assert fsck.in_use(str(img)) == []


@pytest.mark.root
def test_refuses_fuse_mounted(tmp_path, ctl):
    img = mkfs(tmp_path / "ntfs.img", "ntfs", size=32 * MiB)
    with fuse_mount(img, "ntfs", tmp_path / "mnt"):
        with pytest.raises(UnsafeOperation):
            fsck.run_action(str(img), "ntfs", "check", ctl)


@pytest.mark.root
def test_loop_device_for_image(tmp_path, ctl):
    if shutil.which("losetup") is None and not os.path.exists("/usr/sbin/losetup"):
        pytest.skip("losetup is not installed")
    img = mkfs(tmp_path / "ext4.img", "ext4", size=32 * MiB)
    r = run(img, "ext4", "check", ctl, use_loop=True)
    assert r["ok"] and "/dev/loop" in r["command"]
    assert not r["problems_found"]
    out = subprocess.run(["losetup", "-j", str(img)], capture_output=True, text=True).stdout
    assert out.strip() == ""             # detached again


@pytest.mark.root
def test_loop_detach_waits_for_the_last_user(tmp_path):
    """While something has a loop device open (udev probes every new one), losetup -d succeeds but the kernel
    only detaches it at the last close: detach_loop waits for that, and gives up when it never comes."""
    import threading

    from recoverall.core.util import detach_loop
    if shutil.which("losetup") is None and not os.path.exists("/usr/sbin/losetup"):
        pytest.skip("losetup is not installed")
    img = tmp_path / "l.img"
    img.write_bytes(bytes(MiB))

    def attach():
        r = subprocess.run(["losetup", "-r", "-f", "--show", str(img)], capture_output=True, text=True)
        if r.returncode:
            pytest.skip(f"no loop devices here: {r.stderr.strip()}")
        return r.stdout.strip()

    def listed():
        return subprocess.run(["losetup", "-j", str(img)], capture_output=True, text=True).stdout.strip()
    loop = attach()
    fd = os.open(loop, os.O_RDONLY)
    threading.Timer(0.3, os.close, (fd,)).start()
    assert detach_loop(loop) and listed() == ""
    loop = attach()
    fd = os.open(loop, os.O_RDONLY)
    try:
        assert not detach_loop(loop, timeout=0.5)
    finally:
        os.close(fd)
    assert detach_loop(loop) and listed() == ""


def test_cancel_and_live_log(tmp_path, ctl):
    img = mkfs(tmp_path / "ext4.img", "ext4", size=32 * MiB)

    class Stop(type(ctl)):
        @property
        def cancelled(self):
            return True

    with pytest.raises(Cancelled):
        fsck.run_action(str(img), "ext4", "check", Stop())

    lines = []

    class Logging(type(ctl)):
        def log(self, text, level="info"):
            lines.append(text)

    run(img, "ext4", "check", Logging())
    assert any(line.startswith("Pass 5") for line in lines)
    assert lines[0].startswith("$ e2fsck -f -n ")


def test_missing_device(ctl, tmp_path):
    with pytest.raises(Exception, match="doesn't exist"):
        fsck.run_action(str(tmp_path / "nope.img"), "ext4", "check", ctl)
