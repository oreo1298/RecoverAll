"""Btrfs, read through btrfs-progs.

On-disk format, briefly: the superblock sits at 64 KiB (copies at 64 MiB and 256 GiB; each copy records its
own position in ``bytenr``) and points to the root tree and the chunk tree. Everything else is a
copy-on-write B-tree of (objectid, type, offset) keys addressed by *logical* byte numbers, which the chunk
tree maps to devices (single, DUP, RAID profiles). Each subvolume (the top one is tree 5) has its own tree
of inodes: INODE_ITEM (size, mode, times), INODE_REF (name in a folder), EXTENT_DATA (inline data, or a
logical extent possibly compressed with zlib/LZO/zstd).

How this engine reads it:

* Listing: ``btrfs inspect-internal dump-tree`` prints the trees as text; the inodes, their names, sizes,
  times and extents are parsed from it. (``btrfs restore --dry-run`` only prints paths: it is used only when
  the primary superblock is damaged, through a backup copy.) Subvolumes and snapshots appear as folders.
* Content: plain extents and uncompressed inline data are read directly (the chunk map gives where they are
  on this device). Compressed files, and anything the map doesn't cover (several devices), go through the
  decoder "btrfs": ``btrfs restore --path-regex`` writes that one file into a temporary folder, which is
  streamed and deleted.
* Deleted files: Btrfs never overwrites metadata in place, so older copies of the trees survive until their
  blocks are reused. ``btrfs-find-root`` finds older tree roots; :func:`older_roots` lists them (the scanner
  offers them as older versions, opened with ``info["tree_root"]``), and a deleted-files scan compares the
  newest few with the current tree: files only found in an older tree are deleted entries (chance good when
  none of their extents are used by a current file, poor otherwise).

btrfs-progs need a device or image file: a volume inside a disk image is attached as a read-only loop device
(root only), detached afterwards. Free space (for carving) isn't computed here.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import uuid as uuidlib
from typing import Iterator

from ..blockio import Source
from ..errors import FormatError, NotSupported, ToolMissing
from ..util import detach_loop, run, which
from .base import (
    CHANCE_FAIR,
    CHANCE_GOOD,
    CHANCE_POOR,
    F_COMPRESSED,
    F_HARDLINK,
    F_ORPHAN,
    F_SYMLINK,
    NULL_CONTROL,
    Control,
    Entry,
    ExtentMap,
    FsReader,
    merge_runs,
    register_decoder,
    u16,
    u32,
    u64,
)

MAGIC = b"_BHRfS_M"
SUPER_OFFSETS = (0x10000, 0x4000000, 0x4000000000)        # 64 KiB, 64 MiB, 256 GiB
FS_TREE = 5
FIRST_FREE_OBJECTID = 256
HEADER_SIZE = 101                                          # struct btrfs_header
FILE_EXTENT_INLINE_DATA = 21                               # inline data offset in a file extent item
CSUM_TYPES = {0: "crc32c", 1: "xxhash64", 2: "sha256", 3: "blake2b"}
COMPRESSION = {0: "none", 1: "zlib", 2: "lzo", 3: "zstd"}

# symbolic objectids dump-tree prints instead of numbers
_OBJECTIDS = {"ROOT_TREE": 1, "EXTENT_TREE": 2, "CHUNK_TREE": 3, "DEV_TREE": 4, "FS_TREE": 5, "ROOT_TREE_DIR": 6,
              "CSUM_TREE": 7, "QUOTA_TREE": 8, "UUID_TREE": 9, "FREE_SPACE_TREE": 10, "BLOCK_GROUP_TREE": 11,
              "RAID_STRIPE_TREE": 12, "FIRST_CHUNK_TREE": 256, "DEV_ITEMS": 1}

_MAX_OLDER = 3                    # older roots compared with the current tree by a deleted-files scan
_MAX_SNAPSHOTS = 8                # snapshots listed as folders (the newest; each one is a whole tree to read)


# ---------------------------------------------------------------------- superblock
_CRC_TABLE: list[int] | None = None


def crc32c(data: bytes, crc: int = 0) -> int:
    """CRC-32C (Castagnoli), as btrfs checksums its blocks."""
    global _CRC_TABLE
    if _CRC_TABLE is None:
        table = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
            table.append(c)
        _CRC_TABLE = table
    t = _CRC_TABLE
    crc ^= 0xFFFFFFFF
    for b in data:
        crc = t[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _csum_ok(buf: bytes, csum_type: int) -> bool | None:
    import hashlib
    body = buf[0x20:0x1000]
    if csum_type == 0:
        return crc32c(body).to_bytes(4, "little") == buf[:4]
    if csum_type == 2:
        return hashlib.sha256(body).digest() == buf[:32]
    if csum_type == 3:
        return hashlib.blake2b(body, digest_size=32).digest() == buf[:32]
    return None                                            # xxhash64: not in the standard library


def parse_superblock(buf: bytes) -> dict | None:
    """Parse a btrfs superblock (BUF starts at the superblock: 64 KiB into the volume, or a mirror). The
    superblock's own ``bytenr`` says where this copy lives on the device. None if it isn't one."""
    if len(buf) < 0x1000 or buf[0x40:0x48] != MAGIC:
        return None
    bytenr, flags = u64(buf, 0x30), u64(buf, 0x38)
    generation, root, chunk_root, log_root = u64(buf, 0x48), u64(buf, 0x50), u64(buf, 0x58), u64(buf, 0x60)
    total_bytes, bytes_used, root_dir, num_devices = u64(buf, 0x70), u64(buf, 0x78), u64(buf, 0x80), u64(buf, 0x88)
    sectorsize, nodesize, _leaf, stripesize = u32(buf, 0x90), u32(buf, 0x94), u32(buf, 0x98), u32(buf, 0x9C)
    sys_array = u32(buf, 0xA0)
    csum_type = u16(buf, 0xC4)
    root_level, chunk_level = buf[0xC6], buf[0xC7]
    for v in (sectorsize, nodesize):
        if v < 512 or v > 65536 or v & (v - 1):
            return None
    if num_devices == 0 or num_devices > 1024 or sys_array > 2048 or total_bytes == 0:
        return None
    dev = 0xC9
    devid, dev_total, dev_used = u64(buf, dev), u64(buf, dev + 8), u64(buf, dev + 16)
    label = buf[0x12B:0x12B + 256].split(b"\x00", 1)[0].decode("utf-8", "replace")
    return {"bytenr": bytenr, "flags": flags, "fsid": str(uuidlib.UUID(bytes=bytes(buf[0x20:0x30]))),
            "generation": generation, "root": root, "chunk_root": chunk_root, "log_root": log_root,
            "total_bytes": total_bytes, "bytes_used": bytes_used, "root_dir": root_dir, "num_devices": num_devices,
            "sectorsize": sectorsize, "nodesize": nodesize, "stripesize": stripesize, "csum_type": csum_type,
            "csum": CSUM_TYPES.get(csum_type, str(csum_type)), "root_level": root_level,
            "chunk_root_level": chunk_level, "devid": devid, "dev_total_bytes": dev_total,
            "dev_bytes_used": dev_used, "dev_uuid": str(uuidlib.UUID(bytes=bytes(buf[dev + 66:dev + 82]))),
            "label": label, "csum_ok": _csum_ok(buf, csum_type), "incompat_flags": u64(buf, 0xBC)}


def available() -> bool:
    return which("btrfs") is not None


# ---------------------------------------------------------------------- devices for btrfs-progs
class _Device:
    """A path btrfs-progs can open for SRC: the image file or device itself, or a read-only loop device over
    the volume when it starts inside a bigger image/disk (root only)."""

    def __init__(self, src: Source):
        from .tsk import image_args
        images, base = image_args(src)
        if len(images) != 1:
            raise NotSupported("btrfs-progs can't read a split image: join its pieces into one file first")
        self.image, self.base, self.size = images[0], base, src.size
        self.path: str | None = None
        self.loop: str | None = None

    def __enter__(self) -> str:
        return self.open()

    def __exit__(self, *_exc) -> None:
        self.close()

    def open(self) -> str:
        if self.path:
            return self.path
        if self.base == 0:
            self.path = self.image
            return self.path
        if os.geteuid() != 0:
            raise NotSupported("Reading a Btrfs volume inside a disk image needs administrator rights (it is "
                               "attached as a read-only loop device for btrfs-progs)")
        if which("losetup") is None:
            raise ToolMissing("losetup isn't installed (util-linux)")
        r = run(["losetup", "-r", "-o", str(self.base), "--sizelimit", str(self.size), "-f", "--show", self.image],
                timeout=60)
        dev = r.stdout.strip()
        if not r.ok or not dev.startswith("/dev/"):
            raise NotSupported(f"Can't attach the Btrfs volume as a loop device: {r.error_text()}")
        self.loop = self.path = dev
        return dev

    def close(self) -> None:
        if self.loop:
            detach_loop(self.loop)
            self.loop = None
        self.path = None


def _need_tools() -> None:
    if not available():
        raise ToolMissing("btrfs-progs isn't installed (install the btrfs-progs package)")


def _env() -> dict:
    env = dict(os.environ)
    env.update({"LC_ALL": "C", "LANG": "C"})
    return env


def _lines(cmd: list[str], ctl: Control | None = None, errors: list[str] | None = None) -> Iterator[bytes]:
    """The output lines of a long command (bytes, without the newline); stops it when the reader stops."""
    exe = which(cmd[0])
    if exe is None:
        raise ToolMissing(f"{cmd[0]} isn't installed (install the btrfs-progs package)")
    err = tempfile.TemporaryFile()
    proc = subprocess.Popen([exe, *cmd[1:]], stdout=subprocess.PIPE, stderr=err, stdin=subprocess.DEVNULL,
                            env=_env())
    n = 0
    try:
        for raw in proc.stdout:
            n += 1
            if ctl is not None and n % 4096 == 0:
                ctl.check()
            yield raw[:-1] if raw.endswith(b"\n") else raw
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()
        if errors is not None:
            err.seek(0)
            errors.extend(x for x in err.read().decode("utf-8", "replace").splitlines() if x.strip())
            if proc.returncode not in (0, None):
                errors.append(f"{cmd[0]}: exit status {proc.returncode}")
        err.close()


def older_roots(src: Source) -> list[dict]:
    """Older copies of the root tree that btrfs-find-root finds: [{bytenr, generation, level, current}],
    newest first. Opening a reader with ``info["tree_root"] = bytenr`` lists the filesystem as it was."""
    _need_tools()
    with _Device(src) as dev:
        r = run(["btrfs-find-root", "-a", dev], timeout=3600)
    text = (r.stdout or "") + "\n" + (r.stderr or "")
    found: dict[int, dict] = {}
    for m in re.finditer(r"(?:Found tree root at|Well block) (\d+)\s*\(?\s*gen:? (\d+) level:? (\d+)\)?(.*)", text):
        bytenr, gen, level = int(m.group(1)), int(m.group(2)), int(m.group(3))
        current = "matches superblock" in m.group(4) or m.group(0).startswith("Found")
        if bytenr not in found:
            found[bytenr] = {"bytenr": bytenr, "generation": gen, "level": level, "current": current}
    return sorted(found.values(), key=lambda d: (-d["generation"], d["bytenr"]))


# ---------------------------------------------------------------------- dump-tree parsing
_ITEM = re.compile(rb"^\titem \d+ key \((\S+) (\S+) (-?\d+)\) itemoff (\d+) itemsize (\d+)")
_BLOCK = re.compile(rb"^(leaf|node) (\d+) ")
_GEN_SIZE = re.compile(rb"^\t\tgeneration \d+ transid \d+ size (\d+) nbytes (\d+)")
_MODE = re.compile(rb"^\t\tblock group \d+ mode (\d+) links (\d+) uid (\d+) gid (\d+) rdev (\d+)")
_FLAGS = re.compile(rb"^\t\tsequence \d+ flags (0x[0-9a-fA-F]+)")
_TIME = re.compile(rb"^\t\t([acmo])time (-?\d+)\.(\d+)")
_REF = re.compile(rb"^\t\tindex \d+ namelen (\d+) name: ")
_EXTREF = re.compile(rb"^\t\tindex \d+ parent (\d+) namelen (\d+) name: ")
_LOCATION = re.compile(rb"^\t\tlocation key \((\S+) (\S+) (-?\d+)\) type (\S+)")
_NAME_LEN = re.compile(rb"^\t\ttransid \d+ data_len \d+ name_len (\d+)")
_DIRNAME = re.compile(rb"^\t\tname: ")
_EXT_TYPE = re.compile(rb"^\t\tgeneration \d+ type (\d+)")
_INLINE = re.compile(rb"^\t\tinline extent data size (\d+) ram_bytes (\d+) compression (\d+)")
_DISK = re.compile(rb"^\t\textent data disk byte (\d+) nr (\d+)")
_OFFSET = re.compile(rb"^\t\textent data offset (\d+) nr (\d+) ram (\d+)")
_COMPRESS = re.compile(rb"^\t\textent compression (\d+)")
_ROOT_ITEM = re.compile(rb"^\t\tgeneration (\d+) root_dirid (\d+) bytenr (\d+) byte_limit \d+ bytes_used \d+")
_ROOT_REFS = re.compile(rb"^\t\tlast_snapshot (\d+) flags (0x[0-9a-fA-F]+)\S* refs (\d+)")
_PARENT_UUID = re.compile(rb"^\t\tparent_uuid (\S+)")
_CHUNK = re.compile(rb"^\t\tlength (\d+) owner \d+ stripe_len \d+ type (\S+)")
_STRIPE = re.compile(rb"^\t\t\tstripe (\d+) devid (\d+) offset (\d+)")


def _objectid(tok: bytes) -> int | None:
    try:
        return int(tok)
    except ValueError:
        return _OBJECTIDS.get(tok.decode("ascii", "replace"))


class _Inode:
    __slots__ = ("ino", "size", "mode", "links", "uid", "gid", "flags", "times", "refs", "extents", "subvols")

    def __init__(self, ino: int):
        self.ino = ino
        self.size = 0
        self.mode = -1
        self.links = 0
        self.uid = self.gid = 0
        self.flags = 0
        self.times: dict[str, float] = {}
        self.refs: list[tuple[int, bytes]] = []              # (parent folder inode, name)
        self.extents: list[list] = []
        self.subvols: list[tuple[int, bytes]] = []           # subvolumes linked in this folder: (tree, name)


def _parse_tree(lines: Iterator[bytes]) -> Iterator[_Inode]:
    """Inodes (with names, extents and subvolume links) from dump-tree's output of one FS tree, in order."""
    cur: _Inode | None = None
    item_type = b""
    item_off = 0
    leaf = 0
    pending: list | None = None          # a name that continues on the next line: [bytes, wanted length, sink]
    ext: list | None = None
    loc: tuple | None = None
    for line in lines:
        if pending is not None:
            got, want, sink = pending
            got = got + b"\n" + line
            if len(got) >= want or len(got) > 4096:
                sink(got[:want])
                pending = None
            else:
                pending[0] = got
            continue
        m = _ITEM.match(line)
        if m:
            oid = _objectid(m.group(1))
            item_type = m.group(2)
            item_off = int(m.group(4))
            ext = None
            if oid is None or oid < FIRST_FREE_OBJECTID:
                item_type = b""
                continue
            if cur is None or cur.ino != oid:
                if cur is not None:
                    yield cur
                cur = _Inode(oid)
            if item_type == b"EXTENT_DATA":
                ext = [int(m.group(3)), -1, 0, 0, 0, 0, 0, 0, leaf, item_off]
                # [file offset, type, disk bytenr, disk nr, offset, nr, ram, compression, leaf, itemoff]
                cur.extents.append(ext)
            elif item_type == b"INODE_REF":
                cur_parent = int(m.group(3))
                item_off = cur_parent
            continue
        m = _BLOCK.match(line)
        if m:
            leaf = int(m.group(2))
            item_type = b""
            continue
        if cur is None or not item_type or not line.startswith(b"\t\t"):
            continue
        if item_type == b"INODE_ITEM":
            m = _GEN_SIZE.match(line)
            if m:
                cur.size = int(m.group(1))
                continue
            m = _MODE.match(line)
            if m:
                cur.mode = int(m.group(1), 8)
                cur.links, cur.uid, cur.gid = int(m.group(2)), int(m.group(3)), int(m.group(4))
                continue
            m = _FLAGS.match(line)
            if m:
                cur.flags = int(m.group(1), 16)
                continue
            m = _TIME.match(line)
            if m:
                cur.times[m.group(1).decode()] = int(m.group(2)) + int(m.group(3)) / 1e9
        elif item_type in (b"INODE_REF", b"INODE_EXTREF"):
            parent = item_off
            m = _REF.match(line) if item_type == b"INODE_REF" else None
            if m:
                want = int(m.group(1))
            else:
                m = _EXTREF.match(line)
                if not m:
                    continue
                parent, want = int(m.group(1)), int(m.group(2))
            name = line[m.end():]
            node = cur

            def sink(nm, node=node, parent=parent):
                node.refs.append((parent, nm))
            if len(name) < want:
                pending = [name, want, sink]
            else:
                sink(name[:want])
        elif item_type == b"DIR_INDEX":
            m = _LOCATION.match(line)
            if m:
                loc = (m.group(2), _objectid(m.group(1)))
                continue
            m = _NAME_LEN.match(line)
            if m and loc is not None:
                loc = (*loc[:2], int(m.group(1)))
                continue
            m = _DIRNAME.match(line)
            if m and loc is not None and len(loc) == 3 and loc[0] == b"ROOT_ITEM" and loc[1]:
                name = line[m.end():]
                node, tree, want = cur, loc[1], loc[2]

                def sink(nm, node=node, tree=tree):
                    node.subvols.append((tree, nm))
                if len(name) < want:
                    pending = [name, want, sink]
                else:
                    sink(name[:want])
                loc = None
        elif item_type == b"EXTENT_DATA" and ext is not None:
            m = _EXT_TYPE.match(line)
            if m:
                ext[1] = int(m.group(1))
                continue
            m = _INLINE.match(line)
            if m:
                ext[3], ext[6], ext[7] = int(m.group(1)), int(m.group(2)), int(m.group(3))
                continue
            m = _DISK.match(line)
            if m:
                ext[2], ext[3] = int(m.group(1)), int(m.group(2))
                continue
            m = _OFFSET.match(line)
            if m:
                ext[4], ext[5], ext[6] = int(m.group(1)), int(m.group(2)), int(m.group(3))
                continue
            m = _COMPRESS.match(line)
            if m:
                ext[7] = int(m.group(1))
    if cur is not None:
        yield cur


# ---------------------------------------------------------------------- the reader
class BtrfsReader(FsReader):
    fstype = "btrfs"
    name = "Btrfs"
    root_key = FIRST_FREE_OBJECTID

    def __init__(self, src: Source, info: dict | None = None):
        super().__init__(src, info)
        _need_tools()
        self.device = _Device(src)           # raises NotSupported for virtual sources
        sb = None
        for i, off in enumerate(SUPER_OFFSETS):
            if off + 0x1000 > src.size:
                break
            sb = parse_superblock(src.read(off, 0x1000))
            if sb is not None and sb["bytenr"] == off:
                self.mirror = i
                break
            sb = None
        if sb is None:
            raise FormatError("No Btrfs superblock (neither the primary nor a backup copy)")
        if self.mirror:
            self.warn("The primary superblock is damaged: a backup copy was used.")
        self.sb = sb
        self.block_size = sb["sectorsize"]
        self.label = sb["label"]
        self.tree_root = int(self.info["tree_root"]) if self.info.get("tree_root") else None
        self.chunks: list[tuple[int, int, str, list[tuple[int, int]]]] = []
        self._starts: list[int] = []

    @classmethod
    def probe(cls, src: Source) -> dict | None:
        sb, mirror = None, 0
        for i, off in enumerate(SUPER_OFFSETS):
            if off + 0x1000 > src.size:
                break
            sb = parse_superblock(src.read(off, 0x1000))
            if sb is not None and sb["bytenr"] == off and sb["csum_ok"] is not False:
                mirror = i
                break
            sb = None
        if sb is None:
            return None
        info = {"fstype": "btrfs", "label": sb["label"], "uuid": sb["fsid"], "size": sb["dev_total_bytes"] or
                sb["total_bytes"], "block_size": sb["sectorsize"], "used": sb["bytes_used"],
                "free": max(0, sb["total_bytes"] - sb["bytes_used"]), "total_bytes": sb["total_bytes"],
                "nodesize": sb["nodesize"], "generation": sb["generation"], "root": sb["root"],
                "chunk_root": sb["chunk_root"], "num_devices": sb["num_devices"], "devid": sb["devid"],
                "dev_uuid": sb["dev_uuid"], "csum": sb["csum"], "version": f"generation {sb['generation']}"}
        if mirror:
            info["super_mirror"] = mirror
            info["header"] = "backup"
        if sb["num_devices"] > 1:
            info["note"] = f"one of {sb['num_devices']} devices"
        return info

    def close(self) -> None:
        self.device.close()

    def older_roots(self) -> list[dict]:
        return older_roots(self.src)

    # ------------------------------------------------------------------ chunk map
    def _load_chunks(self, dev: str, ctl: Control) -> None:
        errors: list[str] = []
        chunks = []
        cur = None
        for line in _lines(["btrfs", "inspect-internal", "dump-tree", "-t", "chunk", dev], ctl, errors):
            m = _ITEM.match(line)
            if m:
                cur = None
                if m.group(2) == b"CHUNK_ITEM":
                    cur = [int(m.group(3)), 0, "", []]
                    chunks.append(cur)
                continue
            if cur is None:
                continue
            m = _CHUNK.match(line)
            if m:
                cur[1], cur[2] = int(m.group(1)), m.group(2).decode("ascii", "replace")
                continue
            m = _STRIPE.match(line)
            if m:
                cur[3].append((int(m.group(2)), int(m.group(3))))
        chunks.sort()
        self.chunks = [tuple(c) for c in chunks]
        self._starts = [c[0] for c in self.chunks]
        if not self.chunks:
            self.warn("The chunk tree couldn't be read: every file is read through btrfs restore.")

    def _phys(self, logical: int, length: int) -> int | None:
        """Where [logical, logical+length) is on this device, if it is in one single/DUP chunk here."""
        import bisect
        if self.sb["num_devices"] != 1:
            return None
        i = bisect.bisect_right(self._starts, logical) - 1
        if i < 0:
            return None
        start, size, kind, stripes = self.chunks[i]
        if logical + length > start + size or not stripes:
            return None
        profile = kind.split("|")[-1].lower() if "|" in kind else "single"
        if profile not in ("single", "dup"):
            return None
        devid, off = stripes[0]
        if devid != self.sb["devid"]:
            return None
        phys = off + logical - start
        return phys if phys + length <= self.src.size else None

    # ------------------------------------------------------------------ trees
    def _fs_trees(self, dev: str, ctl: Control) -> list[dict]:
        """The subvolume trees (5 first): [{id, bytenr, snapshot, refs}] from the current or an older root
        tree."""
        if self.tree_root:
            cmd = ["btrfs", "inspect-internal", "dump-tree", "-b", str(self.tree_root), "--follow", dev]
        else:
            cmd = ["btrfs", "inspect-internal", "dump-tree", "-t", "root", dev]
        errors: list[str] = []
        trees: dict[int, dict] = {}
        cur = None
        for line in _lines(cmd, ctl, errors):
            m = _ITEM.match(line)
            if m:
                cur = None
                oid = _objectid(m.group(1))
                if m.group(2) == b"ROOT_ITEM" and oid is not None and (oid == FS_TREE or oid >= 256):
                    cur = trees.setdefault(oid, {"id": oid, "bytenr": 0, "snapshot": False, "refs": 1,
                                                 "generation": 0})
                continue
            if cur is None:
                continue
            m = _ROOT_ITEM.match(line)
            if m:
                cur["generation"], cur["bytenr"] = int(m.group(1)), int(m.group(3))
                continue
            m = _ROOT_REFS.match(line)
            if m:
                cur["refs"] = int(m.group(3))
                continue
            m = _PARENT_UUID.match(line)
            if m:
                cur["snapshot"] = m.group(1).strip(b"0-") != b""
        if FS_TREE not in trees:
            msg = errors[-1] if errors else "no filesystem tree"
            raise FormatError(f"btrfs-progs can't read this filesystem's trees: {msg}")
        out = [trees[FS_TREE]] + [trees[k] for k in sorted(trees) if k != FS_TREE]
        return [t for t in out if t["bytenr"]]

    def _tree_lines(self, dev: str, tree: dict, ctl: Control, errors: list[str]) -> Iterator[bytes]:
        if self.tree_root:
            cmd = ["btrfs", "inspect-internal", "dump-tree", "-b", str(tree["bytenr"]), "--follow", dev]
        else:
            cmd = ["btrfs", "inspect-internal", "dump-tree", "-t", str(tree["id"]), dev]
        return _lines(cmd, ctl, errors)

    @staticmethod
    def key(tree: int, ino: int):
        return ino if tree == FS_TREE else f"{tree}:{ino}"

    # ------------------------------------------------------------------ entries
    def entries(self, ctl: Control = NULL_CONTROL, deleted: bool = True) -> Iterator[Entry]:
        try:
            dev = self.device.open()
            ctl.progress(None, "Reading the Btrfs chunk tree")
            self._load_chunks(dev, ctl)
            try:
                trees = self._fs_trees(dev, ctl)
            except FormatError:
                if self.mirror or not self.chunks:
                    yield from self._restore_listing(dev, ctl)
                    return
                raise
            used: list[tuple[int, int]] = []
            present: set[int] = set()
            yield from self._list_trees(dev, trees, ctl, used, present, None)
            if deleted and not self.tree_root and not self.info.get("no_older_roots"):
                yield from self._older_trees(dev, ctl, used, present)
        finally:
            self.device.close()

    def _list_trees(self, dev, trees, ctl, used, present, older, skip: set | None = None) -> Iterator[Entry]:
        """Entries of every subvolume tree. OLDER: None for the current trees, or (generation, tree root) of
        an older root (then only inodes missing from PRESENT and SKIP are yielded, as deleted)."""
        links: dict[int, tuple] = {}            # subvolume tree → (parent key, name)
        limit = int(self.info.get("max_snapshots", _MAX_SNAPSHOTS))
        snaps = sorted((t for t in trees if t.get("snapshot")), key=lambda t: -t["generation"])
        if len(snaps) > limit:
            drop = {t["id"] for t in snaps[limit:]}
            trees = [t for t in trees if t["id"] not in drop]
            if older is None:
                self.warn(f"{len(drop)} older snapshots aren't listed (only the {limit} newest are): open them "
                          "as older versions if you need them.")
        known = {t["id"] for t in trees}
        root_done = older is not None
        n = 0
        for tree in trees:
            tid = tree["id"]
            if tree["refs"] == 0 and older is None:
                continue                         # a deleted subvolume being cleaned up
            errors: list[str] = []
            dirs: dict[int, tuple[int, bytes]] = {}
            deferred: list[tuple[Entry, int, int, bytes]] = []
            for ino in _parse_tree(self._tree_lines(dev, tree, ctl, errors)):
                n += 1
                if n % 500 == 0:
                    ctl.check()
                    ctl.progress(None, f"Btrfs: {n} files listed")
                if ino.mode < 0:
                    continue                     # names without an inode item (a damaged leaf)
                ident = (tid << 64) | ino.ino
                if older is not None and (ident in present or (skip is not None and ident in skip)):
                    continue
                for e, path_parent, name in self._inode_entries(tree, ino, links, dirs, older):
                    if older is None:
                        present.add(ident)
                        if e.runs:
                            used.extend((o, n_) for o, n_ in e.runs if o >= 0)
                    if e.key == self.root_key and older is None:
                        root_done = True
                    elif not root_done and older is None:
                        yield Entry(key=self.root_key, parent=None, name="", is_dir=True, chance=CHANCE_GOOD)
                        root_done = True
                    if e.extra and e.extra.get("decoder") == "btrfs":
                        deferred.append((e, tid, path_parent, name))
                        continue
                    yield e
                for sub, name in ino.subvols:
                    if sub in known:
                        links[sub] = (self.root_key if (tid, ino.ino) == (FS_TREE, FIRST_FREE_OBJECTID)
                                      else self.key(tid, ino.ino), name)
            for e, tid_, parent_ino, name in deferred:
                e.extra["path"] = self._path(dirs, parent_ino, name)
                yield e
            if errors and any("ERROR" in x or "exit status" in x for x in errors):
                what = "the current" if older is None else f"an older (generation {older[0]})"
                self.warn(f"Parts of {what} tree of subvolume {tid} couldn't be read: some files may be missing.")
        if not root_done:
            yield Entry(key=self.root_key, parent=None, name="", is_dir=True, chance=CHANCE_GOOD)

    def _key(self, tree: int, ino: int, older):
        k = self.key(tree, ino)
        return k if older is None else f"d{older[0]}:{k}"

    def _inode_entries(self, tree: dict, ino: _Inode, links: dict, dirs: dict, older) -> Iterator[tuple]:
        """The entries of one inode (one per name): (entry, parent inode, name)."""
        tid = tree["id"]
        fmt = ino.mode & 0o170000
        is_dir = fmt == 0o040000
        refs = [(p, nm) for p, nm in ino.refs if not (p == ino.ino and nm == b"..")]
        t = ino.times
        common = {"mtime": t.get("m"), "atime": t.get("a"), "ctime": t.get("c"), "crtime": t.get("o") or None}
        if is_dir and refs:
            dirs[ino.ino] = refs[0]
        if ino.ino == FIRST_FREE_OBJECTID:
            # the root folder of a subvolume (tree 5: the volume's root)
            if tid == FS_TREE:
                if older is not None:
                    return
                yield Entry(key=self.root_key, parent=None, name="", is_dir=True, chance=CHANCE_GOOD,
                            extra={"inode": ino.ino, "mode": ino.mode, "uid": ino.uid, "gid": ino.gid,
                                   "subvol": tid}, **common), 0, b""
                return
            parent, name = links.get(tid, (None, f"subvolume {tid}".encode()))
            e = Entry(key=self._key(tid, ino.ino, older), parent=parent, name=_text(name), is_dir=True,
                      chance=CHANCE_GOOD if older is None else CHANCE_FAIR, deleted=older is not None,
                      flags=0 if parent is not None else F_ORPHAN,
                      extra={"inode": ino.ino, "subvol": tid, "snapshot": tree.get("snapshot", False)}, **common)
            yield e, 0, b""
            return
        if not refs:
            refs = [(None, f"inode {ino.ino}".encode())]
        extra_base = {"inode": ino.ino, "mode": ino.mode, "uid": ino.uid, "gid": ino.gid, "subvol": tid}
        content = None if is_dir else self._content(ino, tid, older)
        for i, (parent_ino, name) in enumerate(refs):
            key = self._key(tid, ino.ino, older)
            if i:
                key = f"{key}#{i}"
            if parent_ino is None:
                parent = None
            elif parent_ino == FIRST_FREE_OBJECTID and tid == FS_TREE:
                parent = self.root_key
            else:
                parent = self.key(tid, parent_ino)
            e = Entry(key=key, parent=parent, name=_text(name), is_dir=is_dir, deleted=older is not None,
                      chance=CHANCE_GOOD, extra=dict(extra_base), **common)
            if parent is None:
                e.flags |= F_ORPHAN
            if i:
                e.flags |= F_HARDLINK
            if not is_dir and content is not None:
                kind, value, flags, xtra = content
                e.size = ino.size if kind != "symlink" else len(value)
                e.flags |= flags
                if kind == "runs":
                    e.runs = value
                elif kind in ("data", "symlink"):
                    e.data = value
                if xtra:
                    e.extra.update(xtra)
                    if older is not None and xtra.get("decoder") == "btrfs":
                        e.extra["tree_root"] = older[1]
            yield e, parent_ino if parent_ino is not None else 0, name

    def _content(self, ino: _Inode, tid: int, older) -> tuple:
        """("runs", runs, flags, extra) when every extent can be read directly, ("symlink", target, ...), or
        ("decoder", None, F_COMPRESSED, extra) for btrfs restore."""
        fmt = ino.mode & 0o170000
        decoder = ("decoder", None, F_COMPRESSED, {"decoder": "btrfs", "subvol": tid})
        if self.tree_root:
            decoder[3]["tree_root"] = self.tree_root
        if self.mirror:
            decoder[3]["super_mirror"] = self.mirror
        if fmt == 0o120000:
            for ext in ino.extents:
                if ext[1] == 0 and ext[7] == 0:
                    pos = self._phys(ext[8], self.sb["nodesize"])
                    if pos is not None:
                        off = pos + HEADER_SIZE + ext[9] + FILE_EXTENT_INLINE_DATA
                        n = min(ino.size or ext[6], ext[6] or ino.size, 4095)
                        return "symlink", self.src.read(off, n).rstrip(b"\x00"), F_SYMLINK, None
            return decoder[0], None, F_COMPRESSED | F_SYMLINK, decoder[3]
        if fmt not in (0o100000, 0):
            return "runs", [], 0, None           # devices, fifos, sockets: no content
        runs: list[tuple[int, int]] = []
        pos = 0
        compressed = False
        for ext in sorted(ino.extents, key=lambda x: x[0]):
            foff, kind = ext[0], ext[1]
            if foff > pos:
                runs.append((-1, foff - pos))
                pos = foff
            if kind == 0:                        # inline
                if ext[7]:
                    compressed = True
                    break
                leaf = self._phys(ext[8], self.sb["nodesize"])
                if leaf is None:
                    return decoder
                runs.append((leaf + HEADER_SIZE + ext[9] + FILE_EXTENT_INLINE_DATA, ext[6]))
                pos = foff + ext[6]
            elif kind in (1, 2):
                if ext[7]:
                    compressed = True
                    break
                n = ext[5]
                if kind == 2 or ext[2] == 0:
                    runs.append((-1, n))
                else:
                    phys = self._phys(ext[2] + ext[4], n)
                    if phys is None:
                        return decoder
                    runs.append((phys, n))
                pos = foff + n
            else:
                return decoder
        if compressed:
            d = decoder[3]
            d["method"] = COMPRESSION.get(ext[7], str(ext[7]))
            return decoder
        return "runs", merge_runs(runs), 0, None

    @staticmethod
    def _path(dirs: dict, parent_ino: int, name: bytes) -> list[str]:
        parts = [name]
        seen = set()
        cur = parent_ino
        while cur and cur != FIRST_FREE_OBJECTID and cur in dirs and cur not in seen and len(parts) < 4096:
            seen.add(cur)
            p, nm = dirs[cur]
            parts.append(nm)
            cur = p
        return [os.fsdecode(p) for p in reversed(parts)]

    # ------------------------------------------------------------------ deleted files from older roots
    @staticmethod
    def _older_chance(e: Entry, used: ExtentMap) -> int:
        """Good when no current file uses the deleted file's extents; inline data lived in an old tree block
        (fair: metadata blocks are reused quickly)."""
        if e.is_dir or not e.runs:
            return CHANCE_FAIR
        if any(used.overlap(o, n) for o, n in e.runs if o >= 0):
            return CHANCE_POOR
        return CHANCE_GOOD if e.size > 0 else CHANCE_FAIR

    def _older_trees(self, dev: str, ctl: Control, used: list, present: set) -> Iterator[Entry]:
        ctl.progress(None, "Looking for older copies of the Btrfs trees")
        try:
            roots = [r for r in older_roots(self.src) if r["generation"] < self.sb["generation"]]
        except (NotSupported, FormatError) as exc:
            self.warn(f"Older copies of the trees couldn't be searched: {exc}")
            return
        limit = int(self.info.get("older_roots_limit") or _MAX_OLDER)
        used_map = ExtentMap(used)
        older_seen: set[int] = set()            # inodes already yielded from a newer older root
        seen_gen = set()
        done = tried = 0
        yielded: set = set()
        for r in roots:
            if done >= limit or tried >= 4 * limit:
                break
            if r["generation"] in seen_gen:
                continue
            seen_gen.add(r["generation"])
            tried += 1
            saved = self.tree_root
            self.tree_root = r["bytenr"]
            try:
                trees = self._fs_trees(dev, ctl)
            except FormatError:
                continue
            finally:
                self.tree_root = saved
            done += 1
            older = (r["generation"], r["bytenr"])
            self.tree_root, saved = r["bytenr"], self.tree_root
            try:
                batch = list(self._list_trees(dev, trees, ctl, used, present, older, older_seen))
            finally:
                self.tree_root = saved
            keys = {e.key for e in batch}
            for e in batch:
                if e.key == self.root_key or e.key in yielded:
                    continue
                if e.parent is not None and e.parent != self.root_key:
                    # the folder still exists (its current key), or was deleted too (listed in this older tree)
                    old_key = f"d{r['generation']}:{e.parent}"
                    if not self._is_present(e.parent, present):
                        if old_key in keys:
                            e.parent = old_key
                        else:
                            e.parent = None
                            e.flags |= F_ORPHAN
                e.chance = self._older_chance(e, used_map)
                yielded.add(e.key)
                older_seen.update(self._idents(e))
                yield e

    @staticmethod
    def _ident(key) -> int | None:
        if isinstance(key, int):
            return (FS_TREE << 64) | key
        m = re.match(r"^(\d+):(\d+)$", str(key))
        return (int(m.group(1)) << 64) | int(m.group(2)) if m else None

    def _is_present(self, key, present: set) -> bool:
        ident = self._ident(key)
        return ident is not None and ident in present

    def _idents(self, e: Entry) -> list[int]:
        extra = e.extra or {}
        if "inode" in extra and "subvol" in extra:
            return [(int(extra["subvol"]) << 64) | int(extra["inode"])]
        return []

    # ------------------------------------------------------------------ fallback: btrfs restore --dry-run
    def _restore_listing(self, dev: str, ctl: Control) -> Iterator[Entry]:
        """Paths only (the trees can't be dumped: a damaged primary superblock). Sizes are unknown until a
        file is recovered."""
        self.warn("The file list comes from btrfs restore (a backup superblock): sizes and dates are unknown.")
        cmd = ["btrfs", "restore", "-D", "-vv", "-i"]
        if self.mirror:
            cmd += ["-u", str(self.mirror)]
        if self.tree_root:
            cmd += ["-t", str(self.tree_root)]
        tmp = tempfile.mkdtemp(prefix="rall-btrfs-")
        try:
            r = run([*cmd, dev, tmp], timeout=3600, input_text="a\n" * 64)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        yield Entry(key=self.root_key, parent=None, name="", is_dir=True, chance=CHANCE_GOOD)
        restoring, done = [], set()
        for line in (r.stdout or "").splitlines():
            if line.startswith("Restoring "):
                rel = line[len("Restoring "):]
                rel = rel[len(tmp):] if rel.startswith(tmp) else rel.split("/", 1)[1] if "/" in rel else rel
                restoring.append(rel.strip("/"))
            elif line.startswith("Done searching "):
                done.add(line[len("Done searching "):].strip("/"))
        dirs = done | {p.rpartition("/")[0] for p in restoring}
        keys: dict[str, object] = {"": self.root_key}
        for rel in restoring:
            if not rel or rel in keys:
                continue
            parent_rel, _sep, name = rel.rpartition("/")
            key = f"p:{rel}"
            keys[rel] = key
            is_dir = rel in dirs
            e = Entry(key=key, parent=keys.get(parent_rel), name=name, is_dir=is_dir, chance=CHANCE_FAIR)
            if e.parent is None:
                e.flags |= F_ORPHAN
            if not is_dir:
                e.flags |= F_COMPRESSED
                e.extra = {"decoder": "btrfs", "subvol": FS_TREE, "path": rel.split("/"), "size_unknown": True}
                if self.mirror:
                    e.extra["super_mirror"] = self.mirror
                if self.tree_root:
                    e.extra["tree_root"] = self.tree_root
            yield e


def _text(name: bytes) -> str:
    return name.decode("utf-8", "surrogateescape")


# ---------------------------------------------------------------------- the "btrfs" decoder
def _field(entry, name, default=None):
    if isinstance(entry, dict):
        return entry.get(name, default)
    return getattr(entry, name, default)


def _ere(text: str) -> str:
    """TEXT as a literal inside a POSIX extended regular expression (btrfs restore --path-regex)."""
    out = []
    for ch in text:
        if ch in ".[()*+?{}|$":
            out.append(f"[{ch}]")
        elif ch == "]":
            out.append("[]]")
        elif ch == "^":
            out.append("\\^")
        elif ch == "\\":
            out.append("[\\]")
        else:
            out.append(ch)
    return "".join(out)


def path_regex(parts: list[str]) -> str:
    """The --path-regex that makes btrfs restore walk down to one file: ^/(|a(|/b(|/c)))$."""
    inner = ""
    for p in reversed(parts):
        inner = _ere(p) + (f"(|/{inner})" if inner else "")
    return f"^/(|{inner})$"


def decode_btrfs(src: Source, entry) -> Iterator[bytes]:
    """A file restored by btrfs restore into a temporary folder, streamed, then deleted (decoder "btrfs")."""
    extra = _field(entry, "extra") or {}
    size = int(_field(entry, "size") or 0)
    parts = [str(p) for p in extra.get("path") or []]
    if not parts:
        raise FormatError("This Btrfs file's path is unknown: btrfs restore can't find it")
    _need_tools()
    cmd = ["btrfs", "restore", "-i", "-S"]
    if extra.get("tree_root"):
        cmd += ["-t", str(extra["tree_root"])]
    if extra.get("subvol") and int(extra["subvol"]) != FS_TREE:
        cmd += ["-r", str(extra["subvol"])]
    if extra.get("super_mirror"):
        cmd += ["-u", str(extra["super_mirror"])]
    device = _Device(src)
    tmp = tempfile.mkdtemp(prefix="rall-btrfs-")
    try:
        dev = device.open()
        r = run([*cmd, "--path-regex", path_regex(parts), dev, tmp], timeout=600 + size / 5e6,
                input_text="a\n" * 1000)
        out = os.path.join(tmp, *parts)
        if not os.path.lexists(out):
            raise FormatError(f"btrfs restore couldn't recover this file: {r.error_text(300)}")
        if os.path.islink(out):
            yield os.fsencode(os.readlink(out))
            return
        unknown = bool(extra.get("size_unknown"))
        left = size
        with open(out, "rb") as fh:
            while unknown or left > 0:
                piece = fh.read(1024 * 1024 if unknown else min(1024 * 1024, left))
                if not piece:
                    break
                left -= len(piece)
                yield piece
        while not unknown and left > 0:
            k = min(left, 1024 * 1024)
            yield bytes(k)
            left -= k
    finally:
        device.close()
        shutil.rmtree(tmp, ignore_errors=True)


register_decoder("btrfs", decode_btrfs)
