"""Build small filesystem images with real tools, to test the readers against what Linux and mkfs write.

Each helper skips the test (pytest.skip) when the tool it needs is missing, so the suite runs anywhere;
CI installs the tools. Nothing here needs root unless it says so (mount_loop).

    img = tmp_path / "fat.img"
    mkfs(img, "fat32", size=64 * MiB)
    mtools_copy(img, {"DCIM/IMG_0001.JPG": data})
    mtools_delete(img, "DCIM/IMG_0001.JPG")
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

MiB = 1024 * 1024


def need(*tools: str) -> None:
    for t in tools:
        if not (shutil.which(t) or os.path.exists(f"/usr/sbin/{t}") or os.path.exists(f"/sbin/{t}")):
            pytest.skip(f"{t} is not installed")


def sh(*cmd, input_bytes: bytes | None = None, check: bool = True, env: dict | None = None) -> str:
    e = dict(os.environ)
    e["PATH"] = e.get("PATH", "") + ":/usr/sbin:/sbin"
    e["MTOOLS_SKIP_CHECK"] = "1"
    if env:
        e.update(env)
    p = subprocess.run([str(c) for c in cmd], input=input_bytes, capture_output=True, env=e)
    if check and p.returncode != 0:
        raise RuntimeError(f"{cmd}: {p.stderr.decode(errors='replace')}{p.stdout.decode(errors='replace')}")
    return p.stdout.decode(errors="replace")


def blank(path: Path, size: int) -> Path:
    with open(path, "wb") as fh:
        fh.truncate(size)
    return path


def mkfs(path: Path, fstype: str, size: int = 64 * MiB, label: str = "TEST", extra: list[str] | None = None) -> Path:
    blank(path, size)
    extra = extra or []
    if fstype in ("fat12", "fat16", "fat32"):
        need("mkfs.fat")
        sh("mkfs.fat", "-F", fstype[3:], "-n", label, *extra, path)
    elif fstype == "exfat":
        need("mkfs.exfat")
        sh("mkfs.exfat", "-L", label, *extra, path)
    elif fstype == "ntfs":
        need("mkfs.ntfs")
        sh("mkfs.ntfs", "-F", "-f", "-q", "-L", label, *extra, path)
    elif fstype in ("ext2", "ext3", "ext4"):
        need("mkfs." + fstype)
        sh("mkfs." + fstype, "-q", "-F", "-L", label, *extra, path)
    elif fstype == "xfs":
        need("mkfs.xfs")
        # xfsprogs ≥ 6.5 refuses filesystems under 300 MB, except for fstests
        sh("mkfs.xfs", "-q", "-f", "-L", label[:12], *extra, path,
           env={"TEST_DIR": "/tmp", "TEST_DEV": "/dev/null", "QA_CHECK_FS": "xfs"})
    elif fstype == "btrfs":
        need("mkfs.btrfs")
        sh("mkfs.btrfs", "-q", "-f", "-L", label, *extra, path)
    elif fstype == "hfsplus":
        need("mkfs.hfsplus")
        sh("mkfs.hfsplus", "-v", label, *extra, path)
    else:
        raise ValueError(fstype)
    return path


# ---------------------------------------------------------------------- FAT without mounting
def mtools_copy(img: Path, files: dict[str, bytes], tmp: Path | None = None) -> None:
    """Copy FILES (path inside the image → content) into a FAT image with mcopy (folders are created)."""
    need("mcopy", "mmd")
    tmp = Path(tmp or img.parent)
    made = set()
    for rel, data in files.items():
        parts = rel.split("/")
        for i in range(1, len(parts)):
            d = "/".join(parts[:i])
            if d not in made:
                sh("mmd", "-i", img, "::/" + d, check=False)
                made.add(d)
        src = tmp / ("_mt_" + parts[-1])
        src.write_bytes(data)
        sh("mcopy", "-o", "-i", img, src, "::/" + rel)
        src.unlink()


def mtools_delete(img: Path, rel: str) -> None:
    need("mdel")
    sh("mdel", "-i", img, "::/" + rel)


def mtools_rmdir(img: Path, rel: str) -> None:
    need("mdeltree")
    sh("mdeltree", "-i", img, "::/" + rel)


# ---------------------------------------------------------------------- FUSE (no root needed on most systems)
@contextlib.contextmanager
def fuse_mount(img: Path, fstype: str, mnt: Path):
    """Mount IMG with a FUSE driver (ntfs-3g, exfat-fuse/mount.exfat-fuse, fuse2fs)."""
    mnt.mkdir(parents=True, exist_ok=True)
    loops: list[str] = []
    if fstype == "ntfs":
        need("ntfs-3g")
        sh("ntfs-3g", img, mnt)
    elif fstype == "exfat":
        exe = shutil.which("mount.exfat-fuse") or shutil.which("exfat-fuse")
        if not exe or not os.path.exists("/dev/fuse"):
            pytest.skip("exfat-fuse is not installed")
        if os.geteuid() == 0:
            # as root, exfat-fuse only mounts block devices
            loop = sh("losetup", "-f", "--show", img).strip()
            try:
                sh(exe, loop, mnt)
            except RuntimeError:
                sh("losetup", "-d", loop, check=False)
                raise
            loops.append(loop)
        else:
            sh(exe, img, mnt)
    elif fstype in ("ext2", "ext3", "ext4"):
        need("fuse2fs")
        sh("fuse2fs", "-o", "fakeroot", img, mnt)
    else:
        raise ValueError(fstype)
    try:
        yield mnt
    finally:
        os.sync()
        for _ in range(20):
            p = subprocess.run(["umount", str(mnt)], capture_output=True)
            if p.returncode == 0:
                break
            p = subprocess.run(["fusermount", "-u", str(mnt)], capture_output=True)
            if p.returncode == 0:
                break
            time.sleep(0.2)
        time.sleep(0.1)
        for loop in loops:
            subprocess.run(["losetup", "-d", loop], capture_output=True)


@contextlib.contextmanager
def mount_loop(img: Path, mnt: Path, fstype: str | None = None, options: str = ""):
    """Mount IMG through a loop device (root and kernel support for the filesystem, else skip)."""
    if os.geteuid() != 0:
        pytest.skip("needs root")
    mnt.mkdir(parents=True, exist_ok=True)
    cmd = ["mount", "-o", "loop" + ("," + options if options else "")]
    if fstype:
        cmd += ["-t", fstype]
    p = subprocess.run(cmd + [str(img), str(mnt)], capture_output=True)
    if p.returncode != 0:
        pytest.skip(f"can't mount {fstype or ''} here: {p.stderr.decode(errors='replace').strip()}")
    try:
        yield mnt
    finally:
        os.sync()
        subprocess.run(["umount", str(mnt)], capture_output=True)


def payload(n: int, seed: int = 1) -> bytes:
    """N bytes that don't repeat (so a misplaced cluster is caught)."""
    import hashlib
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}:{i}".encode()).digest()
        i += 1
    return bytes(out[:n])


def embed(disk: Path, part_img: Path, offset: int) -> None:
    """Copy a filesystem image into a bigger disk image at OFFSET (to build partitioned disks)."""
    with open(part_img, "rb") as src, open(disk, "r+b") as dst:
        dst.seek(offset)
        shutil.copyfileobj(src, dst, 4 * MiB)
