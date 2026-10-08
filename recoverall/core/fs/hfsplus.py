"""HFS+ and HFSX (Mac OS Extended), read natively.

On-disk format (Apple TN1150, everything big-endian):

* The volume header sits 1024 bytes into the volume ("H+" version 4, or "HX" version 5 for the case-sensitive
  HFSX); a copy (the alternate header) sits 1024 bytes before the end. It describes the allocation block size
  and five special files by their fork data (size + the first 8 extents): the allocation bitmap, the extents
  overflow B-tree, the catalog B-tree, the attributes B-tree and the startup file. An old-style HFS volume can
  wrap an HFS+ volume ("BD" header with an embedded "H+" extent): the embedded volume is read.
* B-trees are made of fixed-size nodes: a 14-byte descriptor (forward link, kind, height, record count), the
  records, and a table of record offsets at the end of the node. Node 0 is the header node (tree depth, root,
  first leaf, node size, node count, and the bitmap of nodes in use). Leaf nodes are chained by their
  forward link.
* Catalog keys are (parent folder ID, name in UTF-16). Leaf records are folders (type 1), files (type 2, with
  the data and resource fork data) and threads (types 3/4: folder ID → parent and name). The root folder has
  ID 2 and its thread gives the volume name. Files with more than 8 fragments continue in the extents
  overflow B-tree, keyed by (file ID, fork, first block).
* Files compressed by macOS (decmpfs) keep a "com.apple.decmpfs" attribute in the attributes B-tree: small
  files are zlib-compressed inside the attribute itself, larger ones in the resource fork in 64 KiB chunks.

What can be recovered:

* Every existing file and folder, resource forks (as "name/rsrc"), symbolic links, hard links (resolved to
  their shared "iNode" file), directory hard links (Time Machine; the first link gets the folder, further
  links become symbolic links to it), zlib-compressed files.
* Deleted files: macOS removes the catalog records, but copies survive in the unused space at the end of
  catalog nodes, in catalog nodes that were freed, and in the journal (copies of catalog nodes written
  before the change). Every such remnant that parses cleanly and whose ID isn't in use any more becomes a
  deleted entry. Its chance is good when all its blocks are still free in the allocation bitmap, poor
  otherwise. Deleted files with more than 8 fragments are only partly located (their overflow records are
  gone too).

What can't: LZVN/LZFSE-compressed files (macOS 10.9+ uses them for system files; listed, but the content
can't be decoded here), a journal that still holds changes that were never written (the volume is read as
it is on disk), and encrypted volumes (FileVault 2 is CoreStorage: decrypt it first).
"""

from __future__ import annotations

import bisect
import hashlib
import re
import struct
import unicodedata
import zlib
from typing import Iterator

from ..blockio import CachedSource, Source
from ..errors import FormatError, NotSupported
from .base import (
    CHANCE_FAIR,
    CHANCE_GOOD,
    CHANCE_POOR,
    F_ADS,
    F_COMPRESSED,
    F_DIR_RECOVERED,
    F_HARDLINK,
    F_JOURNAL,
    F_ORPHAN,
    F_PARTIAL,
    F_SYMLINK,
    F_SYSTEM,
    NULL_CONTROL,
    Control,
    Entry,
    FsReader,
    merge_runs,
    register_decoder,
)

HFS_EPOCH = 2082844800            # 1904-01-01 → 1970-01-01 in seconds

# Catalog node IDs with a fixed meaning
ROOT_PARENT_ID = 1
ROOT_FOLDER_ID = 2
EXTENTS_FILE_ID = 3
CATALOG_FILE_ID = 4
BAD_BLOCKS_FILE_ID = 5
ALLOCATION_FILE_ID = 6
STARTUP_FILE_ID = 7
ATTRIBUTES_FILE_ID = 8
FIRST_USER_ID = 16

REC_FOLDER, REC_FILE, REC_FOLDER_THREAD, REC_FILE_THREAD = 1, 2, 3, 4
KIND_LEAF, KIND_INDEX, KIND_HEADER, KIND_MAP = -1, 0, 1, 2

VOL_JOURNALED = 1 << 13
VOL_UNMOUNTED = 1 << 8
UF_COMPRESSED = 0x20               # BSD owner flag: the content is in a decmpfs attribute / the resource fork
S_IFMT, S_IFDIR, S_IFREG, S_IFLNK = 0o170000, 0o040000, 0o100000, 0o120000

PRIVATE_DATA = "\x00\x00\x00\x00HFS+ Private Data"            # holds the "iNode<n>" files of hard links
PRIVATE_DIR_DATA = ".HFS+ Private Directory Data\r"             # holds the "dir_<n>" folders of directory links
SYSTEM_NAMES = {".journal", ".journal_info_block", PRIVATE_DATA, PRIVATE_DIR_DATA, ".HFS+ Private Directory Data"}

DECMPFS_MAGIC = b"fpmc"            # "cmpf" stored little-endian
DECMPFS_ATTR = "com.apple.decmpfs"
COMPRESSION_NAMES = {3: "zlib", 4: "zlib", 7: "LZVN", 8: "LZVN", 11: "LZFSE", 12: "LZFSE", 13: "LZBITMAP",
                     14: "LZBITMAP"}
CHUNK = 65536                      # decmpfs resource-fork chunk size

# blkid derives a 128-bit UUID from the 64-bit volume ID stored in the Finder info (MD5, this namespace)
_UUID_NAMESPACE = bytes.fromhex("b3e20f39f29211d697a400306543ecac")
_MIN_DATE = 2398377600             # 1980-01-01 in HFS time: older dates on a remnant mean it's garbage

_SPECIAL_FILES = ((EXTENTS_FILE_ID, "extents", "$ExtentsFile"), (CATALOG_FILE_ID, "catalog", "$CatalogFile"),
                  (ALLOCATION_FILE_ID, "allocation", "$AllocationFile"),
                  (ATTRIBUTES_FILE_ID, "attributes", "$AttributesFile"), (STARTUP_FILE_ID, "startup", "$StartupFile"))

# A file record: type 2, flags (high byte small), and the rest is checked by _parse_file. A folder thread:
# key length 6, folder ID, empty name, type 3, reserved 0.
_FILE_PAT = re.compile(rb"\x00\x02[\x00-\x0f]", re.S)
_FOLDER_PAT = re.compile(rb"\x00\x01[\x00-\x0f]", re.S)
_THREAD_PAT = re.compile(rb"\x00\x06[\x00-\xff]{4}\x00\x00\x00\x03\x00\x00", re.S)

_MAX_CANDIDATES = 2_000_000


def hfs_time(v: int) -> float | None:
    """HFS+ date (seconds since 1904, GMT) → Unix time; None for 0."""
    return float(v - HFS_EPOCH) if v else None


def _fork_data(b: bytes, o: int) -> dict:
    """An HFSPlusForkData: logical size, total blocks and the first 8 extents (empty ones dropped)."""
    size, clump, blocks = struct.unpack_from(">QII", b, o)
    ext = []
    for k in range(8):
        start, count = struct.unpack_from(">II", b, o + 16 + 8 * k)
        if count == 0:
            break
        ext.append((start, count))
    return {"size": size, "blocks": blocks, "extents": ext}


def volume_uuid(volume_id: bytes) -> str:
    """The UUID blkid/lsblk show for an HFS+ volume (derived from the 64-bit ID in the Finder info)."""
    if len(volume_id) != 8 or not any(volume_id):
        return ""
    d = bytearray(hashlib.md5(_UUID_NAMESPACE + volume_id).digest())
    d[6] = 0x30 | (d[6] & 0x0F)
    d[8] = 0x80 | (d[8] & 0x3F)
    h = d.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def parse_volume_header(buf: bytes) -> dict | None:
    """Parse an HFS+/HFSX volume header. BUF starts at the header: 1024 bytes into the volume (primary) or
    1024 bytes before its end (alternate). None when it isn't a plausible header."""
    if len(buf) < 512:
        return None
    sig, version, attrs, last_mounted, journal_block = struct.unpack_from(">2sHIII", buf, 0)
    if (sig, version) not in ((b"H+", 4), (b"HX", 5)):
        return None
    created, modified, backup, checked, files, folders, bs, total, free = struct.unpack_from(">IIIIIIIII", buf, 16)
    next_alloc, rsrc_clump, data_clump, next_cnid, write_count = struct.unpack_from(">IIIII", buf, 52)
    if bs < 512 or bs > (1 << 24) or bs & (bs - 1) or total == 0 or free > total:
        return None
    forks = {name: _fork_data(buf, 112 + 80 * i)
             for i, name in enumerate(("allocation", "extents", "catalog", "attributes", "startup"))}
    cat = forks["catalog"]
    if not cat["size"] or not cat["extents"] or not forks["extents"]["extents"]:
        return None
    for f in forks.values():
        if any(s + c > total for s, c in f["extents"]):
            return None
    finder = buf[80:112]
    return {"signature": sig.decode(), "version": version, "attributes": attrs,
            "last_mounted": buf[8:12].decode("latin-1"), "journal_info_block": journal_block,
            "created": created, "modified": modified, "backup": backup, "checked": checked,
            "file_count": files, "folder_count": folders, "block_size": bs, "total_blocks": total,
            "free_blocks": free, "next_cnid": next_cnid, "write_count": write_count,
            "finder_info": finder, "volume_id": finder[24:32], "forks": forks}


def parse_hfs_wrapper(buf: bytes) -> tuple[int, int] | None:
    """An HFS (classic) master directory block wrapping an HFS+ volume: (offset, size) of the embedded volume
    inside the wrapper, or None. BUF starts at the MDB (1024 bytes into the volume)."""
    if len(buf) < 0x82 or buf[0:2] != b"BD" or buf[0x7C:0x7E] != b"H+":
        return None
    alloc_size = struct.unpack_from(">I", buf, 0x14)[0]
    first_sector = struct.unpack_from(">H", buf, 0x1C)[0]
    start, count = struct.unpack_from(">HH", buf, 0x7E)
    if alloc_size < 512 or alloc_size % 512 or count == 0:
        return None
    return first_sector * 512 + start * alloc_size, count * alloc_size


def _name(raw: bytes) -> str | None:
    """A catalog name (UTF-16BE, decomposed) as a display name; None if it doesn't decode."""
    try:
        s = raw.decode("utf-16-be")
    except UnicodeDecodeError:
        return None
    return unicodedata.normalize("NFC", s)


def _display(name: str) -> str:
    """Names may contain "/" (shown as ":" by macOS on Unix paths) and the private folders contain NULs."""
    if name == PRIVATE_DATA:
        return "HFS+ Private Data"
    if name == PRIVATE_DIR_DATA:
        return ".HFS+ Private Directory Data"
    return name.replace("/", ":").replace("\x00", "")


# ---------------------------------------------------------------------- forks and B-trees
class _Fork:
    """A fork (a file's data) as one continuous byte range, mapped onto the volume through its extents."""

    def __init__(self, src: Source, block_size: int, size: int, extents: list[tuple[int, int]]):
        self.src = src
        self.size = size
        self.starts: list[int] = []
        self.pieces: list[tuple[int, int]] = []        # (volume offset, length)
        pos = 0
        for start, count in extents:
            self.starts.append(pos)
            self.pieces.append((start * block_size, count * block_size))
            pos += count * block_size
        self.mapped = pos

    def runs(self, offset: int, length: int) -> list[tuple[int, int]]:
        """[offset, offset+length) of the fork → volume (offset, length) pieces (only the mapped part)."""
        out: list[tuple[int, int]] = []
        end = min(offset + length, self.mapped)
        i = max(0, bisect.bisect_right(self.starts, offset) - 1)
        pos = offset
        while pos < end and i < len(self.pieces):
            voff, n = self.pieces[i]
            rel = pos - self.starts[i]
            if rel >= n:
                i += 1
                continue
            take = min(n - rel, end - pos)
            out.append((voff + rel, take))
            pos += take
            i += 1
        return out

    def on(self, src: Source) -> _Fork:
        """The same fork read through another source (big sequential reads bypass the metadata cache)."""
        f = _Fork(src, 1, self.size, [])
        f.starts, f.pieces, f.mapped = self.starts, self.pieces, self.mapped
        return f

    def read(self, offset: int, length: int) -> bytes:
        out = bytearray()
        for voff, n in self.runs(offset, length):
            out += self.src.read(voff, n)
        if len(out) < length:
            out += bytes(length - len(out))
        return bytes(out)


def _offsets(node: bytes, node_size: int) -> list[int] | None:
    """The record offsets of a node plus the start of its free space, or None when the table is damaged."""
    n = struct.unpack_from(">H", node, 10)[0]
    table = node_size - 2 * (n + 1)
    if n == 0 or table < 14:
        return None
    offs = list(struct.unpack_from(f">{n + 1}H", node, table))[::-1]
    if offs[0] != 14:
        return None
    for a, b in zip(offs, offs[1:]):
        if b <= a:
            return None
    if offs[-1] > table:
        return None
    return offs


class _BTree:
    """One of the volume's B-trees (catalog, extents overflow, attributes), read through its fork."""

    def __init__(self, fork: _Fork, name: str):
        self.fork = fork
        self.name = name
        head = fork.read(0, 512)
        if struct.unpack_from(">b", head, 8)[0] != KIND_HEADER:
            raise FormatError(f"The {name} B-tree's header node is damaged")
        (self.depth, self.root, self.leaf_records, self.first_leaf, self.last_leaf, self.node_size,
         self.max_key, total, self.free_nodes) = struct.unpack_from(">HIIIIHHII", head, 14)
        self.key_compare = head[14 + 37]
        ns = self.node_size
        if ns < 512 or ns > 65536 or ns & (ns - 1):
            raise FormatError(f"The {name} B-tree's node size ({ns}) is impossible")
        self.total_nodes = min(total, fork.mapped // ns)
        self.truncated = self.total_nodes < total

    @classmethod
    def headerless(cls, fork: _Fork, name: str) -> _BTree:
        """A tree whose header node is damaged: the node size is guessed from nodes that look valid, and
        the leaf chain is unknown (every leaf node is found by scanning)."""
        best, best_score = 0, 0
        for ns in (4096, 8192, 16384, 32768, 2048, 1024, 512):
            score = 0
            for i in range(1, min(64, fork.mapped // ns)):
                node = fork.read(i * ns, ns)
                if struct.unpack_from(">b", node, 8)[0] in (KIND_LEAF, KIND_INDEX) and _offsets(node, ns):
                    score += 1
            if score > best_score:
                best, best_score = ns, score
        if not best:
            raise FormatError(f"The {name} B-tree is damaged beyond use")
        t = cls.__new__(cls)
        t.fork, t.name = fork, name
        t.depth = t.root = t.first_leaf = t.last_leaf = t.free_nodes = 0
        t.leaf_records = 1 << 62                 # unknown: the chain is never complete
        t.node_size, t.max_key, t.key_compare = best, 516, 0
        t.total_nodes = fork.mapped // best
        t.truncated = False
        return t

    def node(self, i: int) -> bytes | None:
        if i < 0 or i >= self.total_nodes:
            return None
        return self.fork.read(i * self.node_size, self.node_size)

    @staticmethod
    def kind(node: bytes) -> int:
        return struct.unpack_from(">b", node, 8)[0]

    def offsets(self, node: bytes) -> list[int] | None:
        return _offsets(node, self.node_size)

    def node_map(self) -> bytes | None:
        """The bitmap of nodes in use (header node map record + map nodes), or None when unreadable."""
        head = self.node(0)
        offs = self.offsets(head) if head else None
        if not offs or len(offs) < 4:
            return None
        out = bytearray(head[offs[2]:offs[3]])
        nxt = struct.unpack_from(">I", head, 0)[0]
        seen = {0}
        while nxt and nxt not in seen and len(out) * 8 < self.total_nodes:
            seen.add(nxt)
            node = self.node(nxt)
            if node is None or self.kind(node) != KIND_MAP:
                break
            o = self.offsets(node)
            if not o:
                break
            out += node[o[0]:o[1]]
            nxt = struct.unpack_from(">I", node, 0)[0]
        return bytes(out)

    def leftmost_leaf(self) -> int:
        """Descend from the root through the first record of each index node (when first_leaf is damaged)."""
        n = self.root
        for _ in range(16):
            node = self.node(n)
            if node is None:
                return 0
            k = self.kind(node)
            if k == KIND_LEAF:
                return n
            o = self.offsets(node)
            if k != KIND_INDEX or not o:
                return 0
            klen = struct.unpack_from(">H", node, o[0])[0]
            p = o[0] + 2 + klen
            if p + 4 > o[1]:
                return 0
            n = struct.unpack_from(">I", node, p)[0]
        return 0

    def leaves(self, ctl: Control, visited: set[int] | None = None) -> Iterator[tuple[int, bytes]]:
        """The leaf nodes in key order, following the forward links (cycles and bad links end the walk)."""
        visited = set() if visited is None else visited
        n = self.first_leaf
        first = self.node(n) if n else None
        if first is None or self.kind(first) != KIND_LEAF:
            n = self.leftmost_leaf()
        count = 0
        while n and n not in visited:
            node = self.node(n)
            if node is None or self.kind(node) != KIND_LEAF:
                break
            visited.add(n)
            yield n, node
            count += 1
            if count % 256 == 0:
                ctl.check()
                ctl.progress(min(1.0, count / max(1, self.total_nodes)), f"Reading the {self.name}")
            n = struct.unpack_from(">I", node, 0)[0]

    def records(self, ctl: Control) -> Iterator[tuple[bytes, int, int]]:
        """(node, record offset, record end) of every leaf record."""
        for _n, node in self.leaves(ctl):
            offs = self.offsets(node)
            if not offs:
                continue
            for a, b in zip(offs, offs[1:]):
                yield node, a, b


# ---------------------------------------------------------------------- catalog records
def _key(b: bytes, off: int, end: int) -> tuple[int, str, int] | None:
    """A catalog key at OFF: (parent ID, name, offset of the record data) or None."""
    if off + 8 > end:
        return None
    klen, parent, nlen = struct.unpack_from(">HIH", b, off)
    if klen < 6 or klen > 516 or 6 + 2 * nlen > klen or off + 2 + klen > end:
        return None
    name = _name(b[off + 8:off + 8 + 2 * nlen])
    if name is None:
        return None
    data = off + 2 + klen
    data += data & 1
    return parent, name, data


def _plausible_fork(f: dict, total_blocks: int, bs: int) -> bool:
    used = 0
    for s, c in f["extents"]:
        if s + c > total_blocks:
            return False
        used += c
    if used > f["blocks"] or f["blocks"] > total_blocks:
        return False
    return f["size"] <= f["blocks"] * bs


def _parse_common(b: bytes, o: int) -> dict:
    flags, = struct.unpack_from(">H", b, o + 2)
    cnid, created, modified, attr_mod, accessed = struct.unpack_from(">IIIII", b, o + 8)
    uid, gid, admin_flags, owner_flags, mode, special = struct.unpack_from(">IIBBHI", b, o + 32)
    return {"flags": flags, "cnid": cnid, "created": created, "modified": modified, "attr_mod": attr_mod,
            "accessed": accessed, "uid": uid, "gid": gid, "owner_flags": owner_flags, "mode": mode,
            "special": special}


def _parse_folder(b: bytes, o: int, end: int) -> dict | None:
    if o + 88 > end or struct.unpack_from(">h", b, o)[0] != REC_FOLDER:
        return None
    r = _parse_common(b, o)
    r["valence"] = struct.unpack_from(">I", b, o + 4)[0]
    r["type"] = REC_FOLDER
    return r


def _parse_file(b: bytes, o: int, end: int) -> dict | None:
    if o + 248 > end or struct.unpack_from(">h", b, o)[0] != REC_FILE:
        return None
    r = _parse_common(b, o)
    r["type"] = REC_FILE
    r["fdtype"] = b[o + 48:o + 52]
    r["creator"] = b[o + 52:o + 56]
    r["data"] = _fork_data(b, o + 88)
    r["rsrc"] = _fork_data(b, o + 168)
    return r


def _parse_thread(b: bytes, o: int, end: int) -> tuple[int, int, str] | None:
    """A thread record: (type, parent ID, name)."""
    if o + 10 > end:
        return None
    rtype, _res, parent, nlen = struct.unpack_from(">hHIH", b, o)
    if rtype not in (REC_FOLDER_THREAD, REC_FILE_THREAD) or nlen > 255 or o + 10 + 2 * nlen > end:
        return None
    name = _name(b[o + 10:o + 10 + 2 * nlen])
    return None if name is None else (rtype, parent, name)


def _plausible_record(r: dict, vh: dict) -> bool:
    """Checks for a remnant found by pattern (a live record is trusted more)."""
    if r["cnid"] < FIRST_USER_ID or r["cnid"] >= 0x7FFFFFFF:
        return False
    if not (vh["attributes"] & (1 << 12)) and vh["next_cnid"] > FIRST_USER_ID and r["cnid"] >= vh["next_cnid"]:
        return False                       # IDs aren't reused unless the volume says so (bit 12)
    if max(r["created"], r["modified"]) < _MIN_DATE:
        return False
    if (r["mode"] & S_IFMT) not in (0, S_IFREG, S_IFDIR, S_IFLNK, 0o020000, 0o060000, 0o010000, 0o140000):
        return False
    if r["type"] == REC_FILE:
        tb, bs = vh["total_blocks"], vh["block_size"]
        if not _plausible_fork(r["data"], tb, bs) or not _plausible_fork(r["rsrc"], tb, bs):
            return False
    return True


# ---------------------------------------------------------------------- the reader
class HfsPlusReader(FsReader):
    fstype = "hfsplus"
    name = "HFS+"
    root_key = ROOT_FOLDER_ID

    def __init__(self, src: Source, info: dict | None = None):
        super().__init__(src, info)
        self.base = int(self.info.get("embedded_offset") or 0)
        vol = src.region(self.base, self.info.get("embedded_size")) if self.base else src
        self.vol = vol
        self.meta = CachedSource(vol, block=64 * 1024, blocks=1024)
        vh, where = self._header()
        if vh is None:
            raise FormatError("No HFS+ volume header (neither the primary nor the alternate copy)")
        self.vh = vh
        self.header_used = where
        self.fstype = "hfsx" if vh["signature"] == "HX" else "hfsplus"
        self.name = "HFSX" if self.fstype == "hfsx" else "HFS+"
        self.bs = vh["block_size"]
        self.block_size = self.bs
        self.total_blocks = vh["total_blocks"]
        self._overflow: dict[tuple[int, int], list[tuple[int, list[tuple[int, int]]]]] | None = None
        self._catalog: _BTree | None = None
        self._alloc: _Fork | None = None
        self._decmpfs: dict[int, tuple] | None = None
        self._attr_tree: _BTree | None = None

    # ------------------------------------------------------------------ volume header
    def _header(self) -> tuple[dict | None, str]:
        vh = parse_volume_header(self.meta.read(1024, 512))
        if vh is not None and self.info.get("header") != "alternate":
            return vh, "primary"
        ends = []
        if self.info.get("size"):
            ends.append(int(self.info["size"]))
        ends.append(self.vol.size)
        for end in ends:
            if end >= 2048:
                alt = parse_volume_header(self.meta.read(end - 1024, 512))
                if alt is not None:
                    if vh is None:
                        self.warn("The volume header is damaged: its alternate copy at the end of the volume "
                                  "was used.")
                    return alt, "alternate"
        return vh, "primary"

    @classmethod
    def probe(cls, src: Source) -> dict | None:
        head = src.read(1024, 512)
        vh = parse_volume_header(head)
        where, base, esize = "primary", 0, None
        if vh is None:
            emb = parse_hfs_wrapper(head)
            if emb is not None:
                base, esize = emb
                vh = parse_volume_header(src.read(base + 1024, 512))
                where = "embedded"
        if vh is None and src.size >= 4096:
            vh = parse_volume_header(src.read(src.size - 1024, 512))
            where = "alternate"
        if vh is None:
            return None
        bs = vh["block_size"]
        fstype = "hfsx" if vh["signature"] == "HX" else "hfsplus"
        info = {"fstype": fstype, "label": "", "uuid": volume_uuid(vh["volume_id"]),
                "size": vh["total_blocks"] * bs, "block_size": bs,
                "used": (vh["total_blocks"] - vh["free_blocks"]) * bs, "free": vh["free_blocks"] * bs,
                "version": f"{'HFSX' if fstype == 'hfsx' else 'HFS+'} {vh['version']}",
                "journaled": bool(vh["attributes"] & VOL_JOURNALED),
                "clean": bool(vh["attributes"] & VOL_UNMOUNTED),
                "created": hfs_time(vh["created"]), "modified": hfs_time(vh["modified"]),
                "file_count": vh["file_count"], "folder_count": vh["folder_count"], "header": where}
        if base:
            info["embedded_offset"] = base
            info["embedded_size"] = esize
            info["wrapper"] = "HFS"
        try:
            vol = src.region(base, esize) if base else src
            info["label"] = _volume_name(vol, vh) or ""
        except Exception:  # noqa: BLE001 - a damaged catalog must not hide the volume
            pass
        return info

    # ------------------------------------------------------------------ forks, extents overflow
    def _fork(self, fork: dict, extents: list[tuple[int, int]] | None = None, src: Source | None = None) -> _Fork:
        return _Fork(src or self.meta, self.bs, fork["size"], fork["extents"] if extents is None else extents)

    def _overflow_map(self) -> dict:
        if self._overflow is not None:
            return self._overflow
        self._overflow = {}
        ext = self.vh["forks"]["extents"]
        if not ext["size"]:
            return self._overflow
        try:
            tree = _BTree(self._fork(ext), "extents overflow file")
        except FormatError as exc:
            self.warn(f"{exc}: files with many fragments may be incomplete.")
            return self._overflow
        n = 0
        for node, a, b in tree.records(NULL_CONTROL):
            if a + 12 + 64 > b:
                continue
            klen, fork_type, _pad, file_id, start_block = struct.unpack_from(">HBBII", node, a)
            if klen != 10:
                continue
            exts = []
            for k in range(8):
                s, c = struct.unpack_from(">II", node, a + 12 + 8 * k)
                if c == 0:
                    break
                exts.append((s, c))
            self._overflow.setdefault((file_id, fork_type), []).append((start_block, exts))
            n += 1
            if n > 10_000_000:
                break
        for v in self._overflow.values():
            v.sort()
        return self._overflow

    def _extents(self, cnid: int, fork_type: int, fork: dict) -> tuple[list[tuple[int, int]], bool]:
        """All extents of a fork (the 8 in the record + overflow records), and whether they cover it."""
        ext = list(fork["extents"])
        have = sum(c for _s, c in ext)
        if have < fork["blocks"]:
            for start, more in self._overflow_map().get((cnid, fork_type), ()):
                if start != have:
                    continue
                for s, c in more:
                    if s + c > self.total_blocks:
                        break
                    ext.append((s, c))
                    have += c
                if have >= fork["blocks"]:
                    break
        return ext, have >= fork["blocks"]

    def _runs(self, extents: list[tuple[int, int]], size: int) -> list[tuple[int, int]]:
        """Volume extents → runs relative to the reader's source, truncated to SIZE."""
        out = []
        left = size
        for s, c in extents:
            if left <= 0:
                break
            n = min(c * self.bs, left)
            out.append((self.base + s * self.bs, n))
            left -= n
        return merge_runs(out)

    @property
    def catalog(self) -> _BTree:
        if self._catalog is None:
            fork = self.vh["forks"]["catalog"]
            ext, complete = self._extents(CATALOG_FILE_ID, 0, fork)
            if not complete:
                self.warn("The catalog file's extents are incomplete: part of the file list may be missing.")
            try:
                self._catalog = _BTree(self._fork(fork, ext), "catalog")
            except FormatError as exc:
                self.warn(f"{exc}: the file list is rebuilt from the catalog's leaf nodes.")
                self._catalog = _BTree.headerless(self._fork(fork, ext), "catalog")
            if self._catalog.truncated:
                self.warn("The catalog file is shorter than its header says: part of the file list may be "
                          "missing.")
        return self._catalog

    # ------------------------------------------------------------------ allocation bitmap
    def _alloc_fork(self) -> _Fork | None:
        if self._alloc is None:
            fork = self.vh["forks"]["allocation"]
            if not fork["size"]:
                return None
            ext, _complete = self._extents(ALLOCATION_FILE_ID, 0, fork)
            self._alloc = self._fork(fork, ext)
        return self._alloc

    def _blocks_free(self, extents: list[tuple[int, int]]) -> bool | None:
        """True when every block of EXTENTS is free in the allocation bitmap (None: no bitmap)."""
        alloc = self._alloc_fork()
        if alloc is None:
            return None
        for s, c in extents:
            if c <= 0:
                continue
            first, last = s // 8, (s + c - 1) // 8
            bits = alloc.read(first, last - first + 1)
            if len(bits) > 2:
                if bits[1:-1].strip(b"\x00"):
                    return False
            for blk in (range(s, min(s + c, (first + 1) * 8)), range(max(s, last * 8), s + c)):
                for i in blk:
                    if bits[i // 8 - first] & (0x80 >> (i % 8)):
                        return False
        return True

    def free_extents(self, ctl: Control = NULL_CONTROL) -> list[tuple[int, int]] | None:
        alloc = self._alloc_fork()
        if alloc is None:
            return None
        total = self.total_blocks
        nbytes = (total + 7) // 8
        out: list[tuple[int, int]] = []
        run_start = -1
        step = 4 * 1024 * 1024
        pat = re.compile(rb"\x00+|\xff+|[\x01-\xfe]")
        for pos in range(0, nbytes, step):
            ctl.check()
            ctl.progress(pos / max(1, nbytes), "Reading the allocation bitmap")
            chunk = alloc.read(pos, min(step, nbytes - pos))
            for m in pat.finditer(chunk):
                first = (pos + m.start()) * 8
                v = chunk[m.start()]
                if v == 0:
                    if run_start < 0:
                        run_start = first
                elif v == 0xFF:
                    if run_start >= 0:
                        out.append((run_start, first - run_start))
                        run_start = -1
                else:
                    for bit in range(8):
                        blk = first + bit
                        if v & (0x80 >> bit):
                            if run_start >= 0:
                                out.append((run_start, blk - run_start))
                                run_start = -1
                        elif run_start < 0:
                            run_start = blk
        if run_start >= 0:
            out.append((run_start, nbytes * 8 - run_start))
        res = []
        for s, n in out:
            n = min(n, total - s)
            if n > 0:
                res.append((self.base + s * self.bs, n * self.bs))
        return res

    # ------------------------------------------------------------------ compression (decmpfs)
    def _decmpfs_map(self) -> dict[int, tuple]:
        """File ID → (compression type, uncompressed size, attribute node, data offset, attribute size)."""
        if self._decmpfs is not None:
            return self._decmpfs
        self._decmpfs = {}
        fork = self.vh["forks"]["attributes"]
        if not fork["size"]:
            return self._decmpfs
        ext, _complete = self._extents(ATTRIBUTES_FILE_ID, 0, fork)
        try:
            tree = _BTree(self._fork(fork, ext), "attributes file")
        except FormatError as exc:
            self.warn(f"{exc}: compressed files can't be decoded.")
            return self._decmpfs
        self._attr_tree = tree
        target = DECMPFS_ATTR.encode("utf-16-be")
        for n, node in tree.leaves(NULL_CONTROL):
            offs = tree.offsets(node)
            if not offs:
                continue
            for a, b in zip(offs, offs[1:]):
                if a + 14 > b:
                    continue
                klen, _pad, file_id, _start, nlen = struct.unpack_from(">HHIIH", node, a)
                if nlen != len(DECMPFS_ATTR) or node[a + 14:a + 14 + 2 * nlen] != target:
                    continue
                d = a + 2 + klen
                d += d & 1
                if d + 16 > b or struct.unpack_from(">I", node, d)[0] != 0x10:
                    continue
                size = struct.unpack_from(">I", node, d + 12)[0]
                p = d + 16
                if size < 16 or p + size > b or node[p:p + 4] != DECMPFS_MAGIC:
                    continue
                ctype, usize = struct.unpack_from("<IQ", node, p + 4)
                self._decmpfs[file_id] = (ctype, usize, n, p, size)
        return self._decmpfs

    def _compressed(self, r: dict, e: Entry, cnid: int) -> bool:
        """Turn E into a compressed entry when R is a decmpfs file (True if done)."""
        if not (r["owner_flags"] & UF_COMPRESSED):
            return False
        info = self._decmpfs_map().get(cnid)
        if info is None:
            return False
        ctype, usize, node_no, p, size = info
        tree = self._attr_tree
        e.size = usize
        e.flags |= F_COMPRESSED
        extra = e.extra if e.extra is not None else {}
        extra.update({"decoder": "hfs-compressed", "ctype": ctype,
                      "method": COMPRESSION_NAMES.get(ctype, f"type {ctype}")})
        xattr_runs = [(self.base + o, n) for o, n in tree.fork.runs(node_no * tree.node_size + p, size)]
        extra["xattr_runs"] = [list(x) for x in xattr_runs]
        if ctype in (4, 8, 10, 12, 14):
            rs = r["rsrc"]
            ext, complete = self._extents(cnid, 0xFF, rs)
            extra["rsrc_size"] = rs["size"]
            e.runs = self._runs(ext, rs["size"])
            if not complete:
                e.flags |= F_PARTIAL
        else:
            e.runs = None
        e.extra = extra
        if ctype not in (1, 3, 4):
            self.warn(f"Some files are compressed with {COMPRESSION_NAMES.get(ctype, f'type {ctype}')}, which "
                      "RecoverAll can't decode: they are listed, but recovering them gives an error.")
        return True

    # ------------------------------------------------------------------ entries
    def _times(self, r: dict) -> dict:
        return {"mtime": hfs_time(r["modified"]), "ctime": hfs_time(r["attr_mod"]),
                "atime": hfs_time(r["accessed"]), "crtime": hfs_time(r["created"])}

    def _extra(self, r: dict) -> dict:
        x = {"cnid": r["cnid"]}
        if r["mode"]:
            x.update({"mode": r["mode"], "uid": r["uid"], "gid": r["gid"]})
        if r.get("fdtype") and any(r["fdtype"]):
            x["type"] = r["fdtype"].decode("mac-roman", "replace")
            x["creator"] = r["creator"].decode("mac-roman", "replace")
        return x

    def _folder_entry(self, r: dict, key, parent, name: str, deleted: bool = False) -> Entry:
        flags = F_SYSTEM if (parent == ROOT_FOLDER_ID and name in SYSTEM_NAMES) else 0
        return Entry(key=key, parent=parent, name=_display(name), is_dir=True, deleted=deleted,
                     chance=CHANCE_FAIR if deleted else CHANCE_GOOD, flags=flags, extra=self._extra(r),
                     **self._times(r))

    def _file_entries(self, r: dict, key, parent, name: str, deleted: bool = False, content: dict | None = None,
                      flags: int = 0) -> list[Entry]:
        """The entry of a file record (and of its resource fork). CONTENT: the record holding the data (the
        iNode file of a hard link)."""
        c = content or r
        cnid = c["cnid"]
        if parent == ROOT_FOLDER_ID and name in SYSTEM_NAMES:
            flags |= F_SYSTEM
        e = Entry(key=key, parent=parent, name=_display(name), deleted=deleted, flags=flags, extra=self._extra(r),
                  **self._times(r))
        out = [e]
        if not deleted and self._compressed(c, e, cnid):
            e.chance = CHANCE_GOOD
            return out
        df = c["data"]
        if deleted:
            ext, complete = list(df["extents"]), sum(n for _s, n in df["extents"]) >= df["blocks"]
            if not complete:
                more, complete = self._extents(cnid, 0, df)
                if len(more) > len(ext):
                    ext = more
        else:
            ext, complete = self._extents(cnid, 0, df)
        e.size = df["size"]
        e.runs = self._runs(ext, df["size"])
        if not complete or sum(n for _o, n in e.runs) < df["size"]:
            e.flags |= F_PARTIAL
            if not deleted:
                self.warn("Some files have fragments that the extents overflow file doesn't describe any more: "
                          "they are only partly recovered.")
        e.chance = self._chance(ext, complete) if deleted else CHANCE_GOOD
        if (c["mode"] & S_IFMT) == S_IFLNK and 0 < df["size"] <= 4096 and not (e.flags & F_PARTIAL):
            data = b"".join(self.vol.read(o - self.base, n) for o, n in e.runs)[:df["size"]]
            e.flags |= F_SYMLINK
            e.data = data
            e.runs = None
            e.size = len(data)
        if deleted and (c["owner_flags"] & UF_COMPRESSED) and not df["size"] and c["rsrc"]["size"]:
            self._deleted_compressed(c, e)
            if e.flags & F_COMPRESSED:
                return out
        rs = c["rsrc"]
        if rs["size"] and not (e.flags & F_COMPRESSED):
            rext, rcomplete = (list(rs["extents"]), sum(n for _s, n in rs["extents"]) >= rs["blocks"]) if deleted \
                else self._extents(cnid, 0xFF, rs)
            re_ = Entry(key=f"{key}r", parent=parent, name=_display(name) + "/rsrc", size=rs["size"], deleted=deleted,
                        runs=self._runs(rext, rs["size"]), flags=(flags & ~F_SYMLINK) | F_ADS,
                        extra={"cnid": cnid, "fork": "resource"}, **self._times(r))
            re_.chance = self._chance(rext, rcomplete) if deleted else CHANCE_GOOD
            if not rcomplete:
                re_.flags |= F_PARTIAL
            out.append(re_)
        return out

    def _chance(self, extents: list[tuple[int, int]], complete: bool) -> int:
        if not complete:
            return CHANCE_POOR
        free = self._blocks_free(extents)
        if free is None:
            return CHANCE_FAIR
        return CHANCE_GOOD if free else CHANCE_POOR

    def _deleted_compressed(self, r: dict, e: Entry) -> None:
        """A deleted file whose compressed data is in its resource fork: its decmpfs attribute is gone, so the
        size comes from the resource fork's chunk table (the last chunk is decompressed to measure it)."""
        rs = r["rsrc"]
        if any(n for _s, n in rs["extents"]) and sum(n for _s, n in rs["extents"]) >= rs["blocks"]:
            runs = self._runs(rs["extents"], rs["size"])
            entry = {"size": 0, "runs": runs, "extra": {"rsrc_size": rs["size"]}}
            try:
                table = _rsrc_table(self.src, entry)
            except (NotSupported, FormatError, zlib.error):
                return
            if not table:
                return
            base, chunks = table
            off, n = chunks[-1]
            last = _rsrc_read(self.src, runs, rs["size"], base + off, n)
            try:
                tail = _inflate_chunk(last)
            except zlib.error:
                return
            e.size = (len(chunks) - 1) * CHUNK + len(tail)
            e.runs = runs
            e.chance = self._chance(rs["extents"], True)
            e.flags |= F_COMPRESSED
            e.extra = dict(e.extra or {}, decoder="hfs-compressed", ctype=4, method="zlib",
                           rsrc_size=rs["size"])

    def _special_entries(self) -> Iterator[Entry]:
        for cnid, fork_name, name in _SPECIAL_FILES:
            fork = self.vh["forks"][fork_name]
            if not fork["size"]:
                continue
            ext, complete = self._extents(cnid, 0, fork)
            yield Entry(key=cnid, parent=ROOT_FOLDER_ID, name=name, size=fork["size"],
                        runs=self._runs(ext, fork["size"]), chance=CHANCE_GOOD,
                        flags=F_SYSTEM | (0 if complete else F_PARTIAL))

    def entries(self, ctl: Control = NULL_CONTROL, deleted: bool = True) -> Iterator[Entry]:
        vh = self.vh
        yield Entry(key=ROOT_FOLDER_ID, parent=None, name="", is_dir=True, chance=CHANCE_GOOD,
                    crtime=hfs_time(vh["created"]), mtime=hfs_time(vh["modified"]))
        yield from self._special_entries()
        cat = self.catalog
        ns = cat.node_size
        live: set[int] = set()
        folders: dict[int, tuple[int, str]] = {ROOT_FOLDER_ID: (ROOT_PARENT_ID, "")}
        links: list[tuple[dict, int, str]] = []            # file hard links, resolved at the end
        dir_links: list[tuple[dict, int, str]] = []        # directory hard links
        inodes: dict[int, dict] = {}                       # iNode number → record of the iNode file
        dir_targets: dict[int, tuple[dict, str]] = {}      # dir_<n> folders, held back until links are known
        private = {"file": -1, "dir": -1}
        visited: set[int] = set()
        stale: list[tuple] = []                            # remnants of deleted records
        waiting: list[Entry] = []                          # entries whose folder hasn't been seen yet
        threads: dict[int, tuple[int, str]] = {}           # folder ID → (parent, name) from folder threads
        n_records = 0
        ctl.progress(0.0, "Reading the catalog")
        for idx, node in cat.leaves(ctl, visited):
            offs = cat.offsets(node)
            if not offs:
                self.warn("A catalog node is damaged: the files listed in it are missing.")
                if deleted:
                    self._remnants(node, 14, ns, "catalog", stale)
                continue
            n_records += len(offs) - 1
            if deleted:
                self._remnants(node, offs[-1], ns - 2 * len(offs), "catalog", stale)
            for a, b in zip(offs, offs[1:]):
                k = _key(node, a, b)
                if k is None:
                    continue
                parent, name, d = k
                if d + 2 > b:
                    continue
                rtype = struct.unpack_from(">h", node, d)[0]
                if rtype == REC_FOLDER_THREAD and not name and parent >= FIRST_USER_ID:
                    t = _parse_thread(node, d, b)
                    if t is not None:
                        threads[parent] = (t[1], t[2])
                elif rtype == REC_FOLDER:
                    r = _parse_folder(node, d, b)
                    if r is None or r["cnid"] in live:
                        continue
                    cnid = r["cnid"]
                    live.add(cnid)
                    folders[cnid] = (parent, name)
                    if cnid == ROOT_FOLDER_ID:
                        continue
                    if parent == ROOT_FOLDER_ID and name == PRIVATE_DATA:
                        private["file"] = cnid
                    elif parent == ROOT_FOLDER_ID and name == PRIVATE_DIR_DATA:
                        private["dir"] = cnid
                    if parent == private["dir"] and name.startswith("dir_") and name[4:].isdigit():
                        dir_targets[int(name[4:])] = (r, name)
                        continue
                    yield from _settle([self._folder_entry(r, cnid, parent, name)], folders, waiting)
                elif rtype == REC_FILE:
                    r = _parse_file(node, d, b)
                    if r is None or r["cnid"] in live:
                        continue
                    cnid = r["cnid"]
                    live.add(cnid)
                    if r["fdtype"] == b"hlnk" and r["creator"] == b"hfs+":
                        links.append((r, parent, name))
                        continue
                    if r["fdtype"] == b"fdrp" and r["creator"] == b"MACS":
                        dir_links.append((r, parent, name))
                        continue
                    flags = 0
                    if parent == private["file"] and private["file"] > 0:
                        flags = F_SYSTEM | F_HARDLINK
                        if name.startswith("iNode") and name[5:].isdigit():
                            inodes[int(name[5:])] = r
                    yield from _settle(self._file_entries(r, cnid, parent, name, flags=flags), folders, waiting)
        chain_ok = n_records >= cat.leaf_records
        if not chain_ok:
            self.warn("The catalog's chain of leaf nodes is broken: the rest of the file list was rebuilt from "
                      "the nodes found.")
        yield from _settle(list(self._resolve_links(links, dir_links, inodes, dir_targets, folders, private)),
                           folders, waiting)
        if not deleted and chain_ok:
            yield from self._settle_rest(folders, waiting, threads, live)
            return
        # ---- second pass: every other catalog node, the free space of the live ones, the journal
        found_live: list[tuple] = []
        self._scan_catalog(ctl, visited, chain_ok, deleted, stale, found_live)
        for kind, r, parent, name in found_live:            # records of leaf nodes the broken chain skipped
            cnid = r["cnid"]
            if cnid in live:
                continue
            live.add(cnid)
            if kind == REC_FOLDER:
                folders[cnid] = (parent, name)
                yield from _settle([self._folder_entry(r, cnid, parent, name)], folders, waiting)
            else:
                yield from _settle(self._file_entries(r, cnid, parent, name), folders, waiting)
        yield from self._settle_rest(folders, waiting, threads, live)
        if not deleted:
            return
        self._scan_journal(ctl, stale)
        yield from self._deleted_entries(ctl, stale, live, folders)

    # ------------------------------------------------------------------ hard links
    def _resolve_links(self, links, dir_links, inodes, dir_targets, folders, private) -> Iterator[Entry]:
        for r, parent, name in links:
            target = inodes.get(r["special"])
            if target is None:
                self.warn("Some hard links point to a file that is missing from the private folder: they are "
                          "listed empty.")
                yield Entry(key=r["cnid"], parent=parent, name=_display(name), chance=CHANCE_POOR,
                            flags=F_HARDLINK | F_PARTIAL, extra=self._extra(r), **self._times(r))
                continue
            yield from self._file_entries(r, r["cnid"], parent, name, content=target, flags=F_HARDLINK)
        adopted: dict[int, int] = {}                       # dir_<n> → the link that got the folder
        for r, parent, name in dir_links:
            num = r["special"]
            target = dir_targets.get(num)
            if target is None:
                continue
            if num not in adopted:
                adopted[num] = r["cnid"]
                tr = target[0]
                folders[tr["cnid"]] = (parent, name)
                e = self._folder_entry(tr, tr["cnid"], parent, name)
                e.flags |= F_HARDLINK
                yield e
            else:
                path = self._path(dir_targets[num][0]["cnid"], folders)
                yield Entry(key=r["cnid"], parent=parent, name=_display(name), size=len(path), data=path,
                            chance=CHANCE_GOOD, flags=F_SYMLINK | F_HARDLINK, extra=self._extra(r),
                            **self._times(r))
        for num, (tr, name) in dir_targets.items():
            if num not in adopted:
                yield self._folder_entry(tr, tr["cnid"], private["dir"], name)

    def _settle_rest(self, folders: dict, waiting: list[Entry], threads: dict, live: set[int]) -> Iterator[Entry]:
        """The entries still waiting for their folder: a folder whose record is lost but whose thread record
        survives is rebuilt from it; the rest go to "Lost files"."""
        for e in waiting:
            p = e.parent
            made = []
            while p not in folders and p in threads and len(made) < 256:
                parent, name = threads[p]
                folders[p] = (parent, name)
                live.add(p)
                made.append(Entry(key=p, parent=parent, name=_display(name), is_dir=True, chance=CHANCE_GOOD,
                                  flags=F_DIR_RECOVERED, extra={"cnid": p}))
                p = parent
            if made:
                self.warn("Some folders' catalog records are damaged: they were rebuilt from their thread "
                          "records.")
            for f in made:
                if f.parent not in folders:
                    f.parent = None
                    f.flags |= F_ORPHAN
                yield f
            if e.parent not in folders:
                e.parent = None
                e.flags |= F_ORPHAN
            yield e
        waiting.clear()

    @staticmethod
    def _path(cnid: int, folders: dict[int, tuple[int, str]]) -> bytes:
        parts = []
        seen = set()
        while cnid in folders and cnid != ROOT_FOLDER_ID and cnid not in seen:
            seen.add(cnid)
            parent, name = folders[cnid]
            parts.append(_display(name))
            cnid = parent
        return ("/" + "/".join(reversed(parts))).encode("utf-8", "surrogateescape")

    # ------------------------------------------------------------------ deleted records
    def _remnants(self, buf: bytes, lo: int, hi: int, source: str, out: list) -> None:
        """Look for catalog records in BUF[lo:hi] (unused space: offsets unknown) and append the plausible
        ones to OUT as (kind, record, parent, name, source)."""
        if hi - lo < 16 or not buf[lo:hi].strip(b"\x00"):
            return
        words = None
        vh = self.vh
        for pat, parse in ((_FILE_PAT, _parse_file), (_FOLDER_PAT, _parse_folder)):
            for m in pat.finditer(buf, lo, hi):
                p = m.start()
                if p & 1 or p - lo < 8:
                    continue
                if words is None:
                    words = struct.unpack_from(f">{len(buf) // 2}H", buf, 0)
                r = parse(buf, p, hi)
                if r is None or not _plausible_record(r, vh):
                    continue
                i = p // 2
                for n in range(min(255, (p - lo - 8) // 2) + 1):
                    if words[i - 1 - n] == n and words[i - 4 - n] == 6 + 2 * n:
                        k = _key(buf, p - 8 - 2 * n, p)
                        if k is not None and k[1] and "\x00" not in k[1] and k[0] >= ROOT_PARENT_ID:
                            out.append((r["type"], r, k[0], k[1], source))
                            break
                if len(out) > _MAX_CANDIDATES:
                    return
        for m in _THREAD_PAT.finditer(buf, lo, hi):
            p = m.start()
            if p & 1:
                continue
            cnid = struct.unpack_from(">I", buf, p + 2)[0]
            t = _parse_thread(buf, p + 8, hi)
            if t is None or not t[2] or cnid < FIRST_USER_ID or t[1] < ROOT_PARENT_ID:
                continue
            out.append((REC_FOLDER_THREAD, {"cnid": cnid}, t[1], t[2], source))

    def _leaf_records(self, node: bytes, offs: list[int], source: str, out: list) -> None:
        """The records of a leaf node that isn't part of the live tree (freed, or a journal copy)."""
        vh = self.vh
        for a, b in zip(offs, offs[1:]):
            k = _key(node, a, b)
            if k is None:
                continue
            parent, name, d = k
            if d + 2 > b:
                continue
            rtype = struct.unpack_from(">h", node, d)[0]
            if rtype == REC_FILE:
                r = _parse_file(node, d, b)
            elif rtype == REC_FOLDER:
                r = _parse_folder(node, d, b)
            elif rtype == REC_FOLDER_THREAD and not name:
                t = _parse_thread(node, d, b)
                if t is not None and t[2] and parent >= FIRST_USER_ID:
                    out.append((REC_FOLDER_THREAD, {"cnid": parent}, t[1], t[2], source))
                continue
            else:
                continue
            if r is not None and name and _plausible_record(r, vh):
                out.append((r["type"], r, parent, name, source))

    def _scan_catalog(self, ctl, visited, chain_ok, deleted, stale, found_live) -> None:
        """Every catalog node the leaf chain didn't visit: freed leaf nodes (records of deleted files), live
        leaf nodes a broken chain skipped, and remnants in the unused space of any node."""
        cat = self.catalog
        ns = cat.node_size
        nmap = cat.node_map()
        total = cat.total_nodes
        step = max(ns, (4 * 1024 * 1024 // ns) * ns)
        bulk = cat.fork.on(self.vol)
        map_nodes = set()
        head = cat.node(0)
        nxt = struct.unpack_from(">I", head, 0)[0] if head else 0
        while nxt and nxt not in map_nodes and len(map_nodes) < total:
            map_nodes.add(nxt)
            mn = cat.node(nxt)
            nxt = struct.unpack_from(">I", mn, 0)[0] if mn else 0
        for pos in range(ns, total * ns, step):
            ctl.check()
            ctl.progress(pos / max(1, total * ns), "Looking for deleted files in the catalog")
            chunk = bulk.read(pos, min(step, total * ns - pos))
            for k in range(0, len(chunk), ns):
                idx = (pos + k) // ns
                if idx in visited or idx in map_nodes:
                    continue
                node = chunk[k:k + ns]
                if not node.strip(b"\x00"):
                    continue
                kind = struct.unpack_from(">b", node, 8)[0]
                offs = _offsets(node, ns) if kind in (KIND_LEAF, KIND_INDEX) else None
                in_use = bool(nmap[idx // 8] & (0x80 >> (idx % 8))) if nmap and idx // 8 < len(nmap) else None
                if kind == KIND_LEAF and offs and node[9] == 1:
                    if not chain_ok and in_use is not False:
                        # a live leaf node the chain didn't reach
                        recs: list = []
                        self._leaf_records(node, offs, "catalog", recs)
                        found_live.extend((t, r, p, n) for t, r, p, n, _s in recs if t in (REC_FILE, REC_FOLDER))
                        stale.extend(x for x in recs if x[0] == REC_FOLDER_THREAD)
                    elif deleted:
                        self._leaf_records(node, offs, "catalog", stale)
                    if deleted:
                        self._remnants(node, offs[-1], ns - 2 * len(offs), "catalog", stale)
                elif deleted:
                    if kind == KIND_INDEX and offs and in_use:
                        self._remnants(node, offs[-1], ns - 2 * len(offs), "catalog", stale)
                    else:
                        self._remnants(node, 14, ns, "catalog", stale)

    def _scan_journal(self, ctl: Control, stale: list) -> None:
        """Old copies of catalog leaf nodes in the journal (written before each change)."""
        jib = self.vh["journal_info_block"]
        if not (self.vh["attributes"] & VOL_JOURNALED) or not jib or jib >= self.total_blocks:
            return
        b = self.meta.read(jib * self.bs, 512)
        flags, = struct.unpack_from(">I", b, 0)
        offset, size = struct.unpack_from(">QQ", b, 36)
        if not (flags & 1) or not size or offset + size > self.total_blocks * self.bs or size > 1 << 31:
            return
        ns = self.catalog.node_size
        step = 8 * 1024 * 1024
        for pos in range(0, size, step):
            ctl.check()
            ctl.progress(pos / size, "Looking for deleted files in the journal")
            buf = self.vol.read(offset + pos, min(step + ns, size - pos))
            kinds = buf[8::512]
            i = kinds.find(b"\xff")
            while i >= 0:
                p = i * 512
                if p >= step:
                    break
                if p + ns <= len(buf) and buf[p + 9] == 1:
                    node = buf[p:p + ns]
                    offs = _offsets(node, ns)
                    if offs:
                        self._leaf_records(node, offs, "journal", stale)
                        self._remnants(node, offs[-1], ns - 2 * len(offs), "journal", stale)
                i = kinds.find(b"\xff", i + 1)

    def _deleted_entries(self, ctl: Control, stale: list, live: set[int],
                         folders: dict[int, tuple[int, str]]) -> Iterator[Entry]:
        dirs: dict[int, tuple[dict | None, int, str, str]] = {}      # deleted folder ID → record, parent, name
        files: dict[int, tuple[dict, int, str, str]] = {}
        for kind, r, parent, name, source in stale:
            cnid = r["cnid"]
            if cnid in live:
                continue
            if kind == REC_FILE:
                if cnid not in files or (files[cnid][3] == "journal" and source == "catalog"):
                    files[cnid] = (r, parent, name, source)
            elif kind == REC_FOLDER:
                if cnid not in dirs or dirs[cnid][0] is None:
                    dirs[cnid] = (r, parent, name, source)
            elif kind == REC_FOLDER_THREAD and cnid not in dirs:
                dirs[cnid] = (None, parent, name, source)
        dirs = {c: v for c, v in dirs.items() if c not in files}

        def parent_key(p: int):
            if p in folders:
                return p
            if p in dirs:
                return f"d{p}"
            return None

        dir_parent = {c: parent_key(v[1]) for c, v in dirs.items()}
        for c in dirs:                                    # deleted folders must not end up inside each other
            seen = {c}
            cur = c
            for _ in range(len(dirs) + 1):
                pk = dir_parent.get(cur)
                if not isinstance(pk, str):
                    break
                nxt = int(pk[1:])
                if nxt in seen:
                    dir_parent[cur] = None
                    break
                seen.add(nxt)
                cur = nxt
        n = 0
        for cnid, (r, parent, name, source) in dirs.items():
            pk = dir_parent[cnid]
            flags = (F_JOURNAL if source == "journal" else 0) | (0 if pk is not None else F_ORPHAN)
            if r is None:
                e = Entry(key=f"d{cnid}", parent=pk, name=_display(name), is_dir=True, deleted=True,
                          chance=CHANCE_FAIR, flags=flags, extra={"cnid": cnid})
            else:
                e = self._folder_entry(r, f"d{cnid}", pk, name, deleted=True)
                e.parent = pk
                e.flags |= flags
            yield e
        for cnid, (r, parent, name, source) in files.items():
            n += 1
            if n % 256 == 0:
                ctl.check()
            pk = parent_key(parent)
            flags = (F_JOURNAL if source == "journal" else 0) | (0 if pk is not None else F_ORPHAN)
            for e in self._file_entries(r, f"d{cnid}", pk, name, deleted=True, flags=flags):
                e.parent = pk
                yield e


def _settle(entries: list[Entry], folders: dict, waiting: list[Entry]) -> Iterator[Entry]:
    """Entries whose folder is known go out now; the others wait (a moved folder's record comes after the
    records of its content in catalog order)."""
    for e in entries:
        if e.parent in folders:
            yield e
        else:
            waiting.append(e)


def _volume_name(vol: Source, vh: dict) -> str | None:
    """The root folder's name, from its thread record (key: parent 2, empty name) in the catalog."""
    fork = vh["forks"]["catalog"]
    tree = _BTree(_Fork(vol, vh["block_size"], fork["size"], fork["extents"]), "catalog")
    candidates = [tree.first_leaf] if tree.first_leaf else []
    # descend from the root towards the key (2, "")
    n = tree.root
    for _ in range(16):
        node = tree.node(n)
        if node is None or tree.kind(node) != KIND_INDEX:
            break
        offs = tree.offsets(node)
        if not offs:
            break
        child = None
        for a, b in zip(offs, offs[1:]):
            klen = struct.unpack_from(">H", node, a)[0]
            if a + 8 > b or a + 2 + klen + 4 > b:
                break
            parent, nlen = struct.unpack_from(">IH", node, a + 2)
            if parent > ROOT_FOLDER_ID or (parent == ROOT_FOLDER_ID and nlen > 0):
                break
            child = struct.unpack_from(">I", node, a + 2 + klen)[0]
        if child is None:
            break
        n = child
    candidates.append(n)
    for n in candidates:
        node = tree.node(n)
        if node is None or tree.kind(node) != KIND_LEAF:
            continue
        offs = tree.offsets(node)
        if not offs:
            continue
        for a, b in zip(offs, offs[1:]):
            k = _key(node, a, b)
            if k is None or k[0] != ROOT_FOLDER_ID or k[1]:
                continue
            t = _parse_thread(node, k[2], b)
            if t is not None and t[0] == REC_FOLDER_THREAD:
                return _display(t[2])
    return None


# ---------------------------------------------------------------------- decmpfs decoder
def _field(entry, name, default=None):
    if isinstance(entry, dict):
        return entry.get(name, default)
    return getattr(entry, name, default)


def _read_runs(src: Source, runs, offset: int, length: int) -> bytes:
    """Bytes [offset, offset+length) of the stream described by RUNS ((offset, length) on SRC)."""
    out = bytearray()
    pos = 0
    end = offset + length
    for off, n in runs or []:
        if pos >= end:
            break
        if pos + n > offset:
            a = max(offset, pos)
            b = min(end, pos + n)
            out += bytes(b - a) if off < 0 else src.read(off + a - pos, b - a)
        pos += n
    if len(out) < length:
        out += bytes(length - len(out))
    return bytes(out)


def _rsrc_read(src: Source, runs, rsrc_size: int, offset: int, length: int) -> bytes:
    if offset < 0 or length < 0 or offset + length > rsrc_size:
        raise FormatError("The compressed data points outside the resource fork")
    return _read_runs(src, runs, offset, length)


def _rsrc_table(src: Source, entry) -> tuple[int, list[tuple[int, int]]] | None:
    """The chunk table of a zlib-compressed resource fork: (table base, [(offset, length), ...])."""
    extra = _field(entry, "extra") or {}
    runs = _field(entry, "runs") or []
    size = int(extra.get("rsrc_size") or 0)
    head = _rsrc_read(src, runs, size, 0, 16)
    data_off = struct.unpack_from(">I", head, 0)[0]
    if data_off < 16 or data_off + 8 > size:
        raise FormatError("The compressed file's resource fork header is damaged")
    base = data_off + 4
    count = struct.unpack_from("<I", _rsrc_read(src, runs, size, base, 4), 0)[0]
    if count == 0:
        return base, []
    if count > (size // 8) + 1:
        raise FormatError("The compressed file's chunk table is damaged")
    raw = _rsrc_read(src, runs, size, base + 4, 8 * count)
    chunks = [struct.unpack_from("<II", raw, 8 * i) for i in range(count)]
    for off, n in chunks:
        if base + off + n > size:
            raise FormatError("The compressed file's chunk table points outside the resource fork")
    return base, chunks


def _inflate_chunk(raw: bytes) -> bytes:
    """A zlib chunk; a first byte with the low nibble 0xF marks a chunk stored uncompressed."""
    if raw and (raw[0] & 0x0F) == 0x0F:
        return raw[1:]
    return zlib.decompress(raw)


def decode_decmpfs(src: Source, entry) -> Iterator[bytes]:
    """The content of an HFS+ compressed file (decoder "hfs-compressed"): zlib inside the decmpfs attribute
    (type 3), zlib chunks in the resource fork (type 4), or stored uncompressed in the attribute (type 1)."""
    extra = _field(entry, "extra") or {}
    ctype = int(extra.get("ctype") or 0)
    size = int(_field(entry, "size") or 0)
    if ctype in (1, 3):
        xruns = [tuple(x) for x in extra.get("xattr_runs") or []]
        total = sum(n for _o, n in xruns)
        attr = _read_runs(src, xruns, 0, total)
        if len(attr) < 16 or attr[:4] != DECMPFS_MAGIC:
            raise FormatError("The compressed file's decmpfs attribute is damaged")
        body = attr[16:]
        if ctype == 1:
            data = body
        else:
            try:
                data = _inflate_chunk(body)
            except zlib.error as exc:
                raise FormatError(f"The compressed file is damaged (zlib: {exc})") from exc
        data = data[:size]
        yield data + bytes(size - len(data))
        return
    if ctype == 4:
        runs = _field(entry, "runs") or []
        rsize = int(extra.get("rsrc_size") or 0)
        table = _rsrc_table(src, entry)
        base, chunks = table
        left = size
        for off, n in chunks:
            if left <= 0:
                break
            raw = _rsrc_read(src, runs, rsize, base + off, n)
            try:
                piece = _inflate_chunk(raw)
            except zlib.error as exc:
                raise FormatError(f"The compressed file is damaged (zlib: {exc})") from exc
            piece = piece[:left]
            left -= len(piece)
            yield piece
        while left > 0:
            k = min(left, 1 << 20)
            yield bytes(k)
            left -= k
        return
    method = COMPRESSION_NAMES.get(ctype, f"type {ctype}")
    raise NotSupported(f"This file is compressed with {method} (macOS), which RecoverAll can't decode")


register_decoder("hfs-compressed", decode_decmpfs)
