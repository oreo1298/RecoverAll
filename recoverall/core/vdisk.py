"""Virtual-disk and forensic image files, read natively (no qemu-nbd, no ewfmount): Hyper-V and Virtual PC
(VHD, VHDX), VirtualBox (VDI), VMware (VMDK), QEMU (QCOW2 and the original QCOW) and EnCase/libewf (E01).
Each one opens as a :class:`~recoverall.core.blockio.Source` over the disk the guest saw, so it is scanned,
browsed and recovered from like a raw disk image, as R-Studio does::

    src = open_source("server.vhdx")       # open_source tries open_vdisk on every regular file
    src.format, src.size                   # "VHDX", the virtual disk's size
    src.read(0, 512)                       # the guest's sector 0

:func:`detect` recognizes a format by its magic bytes (the first 4 KiB and the last sector of the file), so a
raw image costs two small reads before it is opened as before.

Damage is handled the way a failing disk is: data that isn't there — an image cut short by a partial download,
a missing segment or extent file, an unreadable sector under the image file, a compressed chunk that doesn't
inflate — reads as zeros and is recorded in ``src.bad``, so a scan goes on and recovered files that touch it are
flagged. Unallocated blocks read as zeros. A QCOW2 image's backing file is followed. What can't be read on its
own is refused with a message that says what to do instead: differencing disks and snapshots (VHD, VHDX, VDI,
VMDK), encrypted QCOW2, QCOW2 with extended L2 entries, EWF2 (.Ex01) and logical evidence files (.L01).

Nothing here writes. :func:`check_raw_file` refuses the operations that work on the image file itself (repairs,
writing a partition table, attaching it as a loop device): in these formats the sectors aren't stored in order.
"""

from __future__ import annotations

import bisect
import os
import re
import stat
import string
import struct
import threading
import uuid
import zlib
from collections import OrderedDict

from .blockio import BadMap, CachedSource, FileSource, RegionSource, Source
from .errors import FormatError, NotSupported, RallError

MiB = 1024 * 1024

# where a block's data is (what _locate answers)
DATA = 0        # (DATA, file, offset): stored as is
SOFT = 1        # (SOFT, file, offset): stale data of a discarded block: read it, but missing bytes aren't damage
ZERO = 2        # (ZERO,): reads as zeros
LOST = 3        # (LOST,): should be there and isn't (cut short, unreadable table): zeros, recorded in ``bad``
PACKED = 4      # (PACKED, ...): stored compressed; ``_unpack`` decodes it
BACKING = 5     # (BACKING,): not in this image: read from the backing file at the same offset
_ZERO = (ZERO,)
_LOST = (LOST,)
_BACKING = (BACKING,)

EWF1 = b"EVF\x09\x0d\x0a\xff\x00"
EWF1_LOGICAL = b"LVF\x09\x0d\x0a\xff\x00"
EWF2 = b"EVF2\x0d\x0a\x81\x00"
EWF2_LOGICAL = b"LEF2\x0d\x0a\x81\x00"
VDI_SIGNATURE = 0xBEDA107F
GD_AT_END = 0xFFFFFFFFFFFFFFFF

FORMAT_NAMES = {"VHD": "Virtual PC / Hyper-V disk", "VHDX": "Hyper-V disk", "VDI": "VirtualBox disk",
                "VMDK": "VMware disk", "QCOW2": "QEMU disk", "QCOW": "QEMU disk (QCOW 1)",
                "E01": "EnCase forensic image"}


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def _u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def _be32(b: bytes, o: int) -> int:
    return struct.unpack_from(">I", b, o)[0]


def _be64(b: bytes, o: int) -> int:
    return struct.unpack_from(">Q", b, o)[0]


def _pow2(n: int) -> bool:
    return n > 0 and n & (n - 1) == 0


def _inflate(data: bytes, limit: int, wbits: int = zlib.MAX_WBITS) -> bytes:
    """Up to LIMIT bytes inflated from DATA (as much as came out when the data ends early; b"" when it's not
    deflate data at all)."""
    d = zlib.decompressobj(wbits)
    try:
        return d.decompress(data, limit)
    except zlib.error:
        return b""


def _differencing(fmt: str, parent: str, what: str = "differencing disk") -> str:
    of = f" of “{parent}”" if parent else ""
    return (f"This {fmt} is a {what}{of}: it holds only what changed after its parent disk was made. Open the "
            "parent disk instead, or merge the two into one disk first (Hyper-V's Edit Disk, VBoxManage "
            "clonemedium or qemu-img convert) and open that")


class _LRU:
    """A small thread-safe LRU of decoded tables and blocks, bounded by count and by bytes."""

    def __init__(self, items: int, nbytes: int):
        self.items = items
        self.nbytes = nbytes
        self._d: OrderedDict = OrderedDict()
        self._bytes = 0
        self._lock = threading.Lock()

    def get(self, key, make):
        with self._lock:
            v = self._d.get(key)
            if v is not None:
                self._d.move_to_end(key)
                return v
        v = make()
        with self._lock:
            if key not in self._d:
                self._d[key] = v
                self._bytes += len(v)
                while len(self._d) > 1 and (len(self._d) > self.items or self._bytes > self.nbytes):
                    _k, old = self._d.popitem(last=False)
                    self._bytes -= len(old)
        return v


# ====================================================================== the common part
class VDiskSource(Source):
    """A disk stored in container files, read block by block. Subclasses set ``block`` (the allocation unit:
    a VHD block, a VMDK grain, a QCOW2 cluster, an EWF chunk), ``size`` and ``format`` in ``_setup``, and
    implement ``_locate`` (where a block is) and ``_unpack`` (for blocks stored compressed)."""

    format = ""
    block = MiB

    def __init__(self, path: str, **opts):
        super().__init__()
        self.path = os.path.abspath(path)
        self.name = os.path.basename(path)
        self.files: list[Source] = []          # what close() closes: container files, extents, backing file
        self.backing: Source | None = None
        self.bad_base = 0                      # where this disk starts in the BadMap it records into
        self._tables = _LRU(512, 64 * MiB)
        self._blocks = _LRU(64, 32 * MiB)
        try:
            self._setup(**opts)
        except BaseException:
            self.close()
            raise

    def _setup(self, **opts) -> None:
        raise NotImplementedError

    def _file(self, path: str) -> FileSource:
        f = FileSource(path)
        self.files.append(f)
        return f

    def _locate(self, index: int) -> tuple:
        raise NotImplementedError

    def _unpack(self, index: int, loc: tuple) -> bytes:
        raise NotImplementedError

    # ------------------------------------------------------------------ reading the container files
    def _have(self, f: FileSource, off: int, n: int) -> bytes:
        """What there is of N bytes at OFF of F: shorter when the file ends (or turns unreadable) first. For
        tables: the entries that aren't there are known to be missing."""
        data = f.read(off, n)
        have = max(0, min(n, f.size - off))
        if have and len(f.bad) and f.bad.overlaps(off, have):
            for s, ln in f.bad.ranges():
                if s + ln > off and s < off + have:
                    have = max(0, s - off)
                    break
        return data[:have]

    def _copy_bad(self, bad: BadMap, off: int, n: int, voff: int) -> None:
        """Record the unreadable part of [OFF, OFF+N) of another source's BAD map at virtual offset VOFF."""
        if not len(bad) or not bad.overlaps(off, n):
            return
        for s, ln in bad.ranges():
            a, b = max(s, off), min(s + ln, off + n)
            if a < b:
                self.bad.add(self.bad_base + voff + a - off, b - a)

    def _piece(self, f: FileSource, off: int, n: int, voff: int, mark: bool = True) -> bytes:
        """N bytes of block data at OFF of F, for virtual offset VOFF (what's missing is recorded as bad)."""
        data = f.read(off, n)
        if mark:
            have = max(0, min(n, f.size - off))
            if have < n:
                self.bad.add(self.bad_base + voff + have, n - have)
            self._copy_bad(f.bad, off, n, voff)
        return data

    # ------------------------------------------------------------------ reading the disk
    def _where(self, index: int) -> tuple:
        try:
            return self._locate(index)
        except (struct.error, IndexError, ValueError, OverflowError):
            return _LOST                       # a damaged table entry

    def _unpacked(self, index: int, loc: tuple) -> bytes:
        def make() -> bytes:
            try:
                data = self._unpack(index, loc)
            except (struct.error, IndexError, ValueError, OverflowError, zlib.error):
                data = b""
            want = max(0, min(self.block, self.size - index * self.block))
            if len(data) < want:
                self.bad.add(self.bad_base + index * self.block + len(data), want - len(data))
            if len(data) != self.block:
                data = data[:self.block].ljust(self.block, b"\0")
            return data
        return self._blocks.get(index, make)

    def _read(self, offset: int, length: int) -> bytes:
        out = bytearray()
        pos, end, bs = offset, offset + length, self.block
        while pos < end:
            index, rel = divmod(pos, bs)
            n = min(bs - rel, end - pos)
            loc = self._where(index)
            kind = loc[0]
            if kind in (DATA, SOFT):
                f, last = loc[1], loc[2]
                while pos + n < end:           # the next blocks follow in the same file: one read
                    nxt = self._where(index + 1)
                    if nxt[0] != kind or nxt[1] is not f or nxt[2] != last + bs:
                        break
                    index, last = index + 1, nxt[2]
                    n += min(bs, end - pos - n)
                out += self._piece(f, loc[2] + rel, n, pos, kind == DATA)
            elif kind == PACKED:
                out += self._unpacked(index, loc)[rel:rel + n]
            elif kind == BACKING and self.backing is not None:
                out += self.backing.read(pos, n)
                self._copy_bad(self.backing.bad, pos, n, pos)
            else:
                if kind == LOST:
                    self.bad.add(self.bad_base + pos, n)
                out += bytes(n)
            pos += n
        return bytes(out)

    def describe(self) -> dict:
        d = super().describe()
        d["format"] = self.format
        return d

    def close(self) -> None:
        for f in self.files:
            f.close()
        if self.backing is not None:
            self.backing.close()


# ====================================================================== VHD
def _vhd_footer_ok(b: bytes) -> bool:
    return (~sum(b[:64] + bytes(4) + b[68:512])) & 0xFFFFFFFF == _be32(b, 64)


def _vhd_footer(f: FileSource) -> tuple[bytes, int] | None:
    """A VHD's footer and how many bytes it takes at the end of the file: 512 (511 on the oldest Virtual PC),
    or 0 for the copy at the start of a dynamic disk (which survives a file cut short)."""
    cands = []
    if f.size >= 512:
        cands.append((f.read(f.size - 512, 512), 512))
    cands.append((f.read(0, 512), 0))
    if f.size >= 511:
        cands.append((f.read(f.size - 511, 511) + b"\0", 511))
    for footer, tail in cands:
        if footer[:8] == b"conectix" and _vhd_footer_ok(footer):
            return footer, tail
    for footer, tail in cands:                 # a bad checksum: still better than nothing
        if footer[:8] == b"conectix" and _be32(footer, 60) in (2, 3, 4):
            return footer, tail
    return None


class VhdSource(VDiskSource):
    """Virtual PC / Hyper-V generation-1 disk (.vhd): fixed (the disk as is, then a 512-byte footer) or dynamic
    (a copy of the footer, a dynamic-disk header, the block table (BAT), the blocks — each one a sector bitmap
    and the data — and the footer). The sector bitmaps aren't needed to read a dynamic disk: sectors never
    written are zeros in an allocated block."""

    format = "VHD"

    def _setup(self) -> None:
        f = self.f = self._file(self.path)
        found = _vhd_footer(f)
        if found is None:
            raise FormatError(f"{self.name}: this VHD's footer is damaged")
        footer, tail = found
        self.size = _be64(footer, 48)
        kind = _be32(footer, 60)
        self.fixed = kind == 2
        if self.fixed:
            if not tail:
                raise FormatError(f"{self.name}: this fixed VHD's footer isn't at its end")
            self.data_end = f.size - tail
            return
        if kind not in (3, 4):
            raise FormatError(f"{self.name}: unknown VHD disk type {kind}")
        dyn = f.read(_be64(footer, 16), 1024)
        if dyn[:8] != b"cxsparse":
            raise FormatError(f"{self.name}: this VHD's dynamic-disk header is missing or damaged")
        if kind == 4:
            parent = dyn[64:576].decode("utf-16-be", "replace").split("\0")[0]
            raise NotSupported(_differencing("VHD", parent))
        bat_off, entries, bs = _be64(dyn, 16), _be32(dyn, 28), _be32(dyn, 32)
        if not _pow2(bs) or not 512 <= bs <= 256 * MiB:
            raise FormatError(f"{self.name}: this VHD's block size ({bs}) isn't valid")
        self.block = bs
        self.entries = min(entries, -(-self.size // bs))
        self.bat = self._have(f, bat_off, 4 * self.entries)
        bitmap = (bs // 512 + 7) // 8          # one bit per sector, in whole sectors
        self.bitmap = max(512, (bitmap + 511) // 512 * 512)

    def _locate(self, index: int) -> tuple:
        if index >= self.entries:
            return _ZERO
        if 4 * index + 4 > len(self.bat):
            return _LOST
        sector = _be32(self.bat, 4 * index)
        if sector == 0xFFFFFFFF:
            return _ZERO
        return (DATA, self.f, sector * 512 + self.bitmap)

    def _read(self, offset: int, length: int) -> bytes:
        if not self.fixed:
            return super()._read(offset, length)
        have = max(0, min(length, self.data_end - offset))
        out = self._piece(self.f, offset, have, offset) if have else b""
        if have < length:
            self.bad.add(offset + have, length - have)
            out += bytes(length - have)
        return out


# ====================================================================== VHDX
VHDX_BAT = uuid.UUID("2DC27766-F623-4200-9D64-115E9BFD4A08").bytes_le
VHDX_METADATA = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E").bytes_le
VHDX_FILE_PARAMETERS = uuid.UUID("CAA16737-FA36-4D43-B3B6-33F0AA44E76B").bytes_le
VHDX_DISK_SIZE = uuid.UUID("2FA54224-CD1B-4876-B211-5DBED83BF4B8").bytes_le
VHDX_DISK_ID = uuid.UUID("BECA12AB-B2E6-4523-93EF-C309E000C746").bytes_le
VHDX_LOGICAL_SECTOR = uuid.UUID("8141BF1D-A96F-4709-BA47-F233A8FAAB5F").bytes_le
VHDX_PHYSICAL_SECTOR = uuid.UUID("CDA348C7-445D-4471-9CC9-E9885251C556").bytes_le
VHDX_PARENT_LOCATOR = uuid.UUID("A8D35F2D-B30B-454D-ABF7-D3D84834AB0C").bytes_le
_VHDX_KNOWN_ITEMS = (VHDX_FILE_PARAMETERS, VHDX_DISK_SIZE, VHDX_DISK_ID, VHDX_LOGICAL_SECTOR, VHDX_PHYSICAL_SECTOR,
                     VHDX_PARENT_LOCATOR)
_PAGE = 4096


class VhdxSource(VDiskSource):
    """Hyper-V disk (.vhdx): two headers and two region tables (CRC-32C), the metadata region (block size,
    disk size, sector size, whether it has a parent), and the block table (BAT): for every chunk of
    2^23 sectors, one entry per payload block followed by the entry of the chunk's sector bitmap. Blocks not
    present, zero or undefined read as zeros; a discarded (unmapped) block that still has its place in the file
    is read from there (its content is undefined: whatever was there is the best guess for recovery).

    When the VM didn't shut down cleanly, the log may hold metadata writes that never reached their place:
    they are replayed in memory, over the BAT and the metadata, without writing anything."""

    format = "VHDX"

    def _setup(self) -> None:
        from .fsdetect import crc32c
        f = self.f = self._file(self.path)
        self._patches: dict[int, bytes] = {}
        head = self._header(f, crc32c)
        regions = self._regions(f, crc32c)
        if head is not None and head["log_guid"] != bytes(16) and head["log_length"]:
            self._patches = self._replay_log(f, head, crc32c)
        moff, _mlen = regions[VHDX_METADATA]
        meta = self._mread(moff, 64 * 1024)
        if meta[:8] != b"metadata" or _u16(meta, 10) > 2047:
            raise FormatError(f"{self.name}: this VHDX's metadata table is damaged")
        items: dict[bytes, tuple[int, int]] = {}
        for i in range(_u16(meta, 10)):
            o = 32 + 32 * i
            guid = meta[o:o + 16]
            items[guid] = (moff + _u32(meta, o + 16), _u32(meta, o + 20))
            if _u32(meta, o + 24) & 4 and guid not in _VHDX_KNOWN_ITEMS:
                raise NotSupported(f"{self.name}: this VHDX needs a feature RecoverAll doesn't know "
                                   f"(metadata item {uuid.UUID(bytes_le=guid)})")

        def item(guid: bytes, n: int) -> bytes | None:
            if guid not in items:
                return None
            data = self._mread(items[guid][0], n)
            return data if len(data) == n else None

        params = item(VHDX_FILE_PARAMETERS, 8)
        size = item(VHDX_DISK_SIZE, 8)
        if params is None or size is None:
            raise FormatError(f"{self.name}: this VHDX's metadata doesn't give its block size and disk size")
        bs, flags = _u32(params, 0), _u32(params, 4)
        if flags & 2:
            raise NotSupported(_differencing("VHDX", self._parent_name(items)))
        sector = item(VHDX_LOGICAL_SECTOR, 4)
        self.sector_size = _u32(sector, 0) if sector else 512
        if not _pow2(bs) or not MiB <= bs <= 256 * MiB or self.sector_size not in (512, 4096):
            raise FormatError(f"{self.name}: this VHDX's block size ({bs}) or sector size ({self.sector_size}) "
                              "isn't valid")
        self.size = _u64(size, 0)
        self.block = bs
        self.ratio = (1 << 23) * self.sector_size // bs        # payload blocks per sector-bitmap block
        self.blocks = -(-self.size // bs)
        entries = self.blocks + (self.blocks - 1) // self.ratio if self.blocks else 0
        boff, _blen = regions[VHDX_BAT]
        self.bat = self._mread(boff, 8 * entries, have=True)

    def _header(self, f: FileSource, crc32c) -> dict | None:
        """The current header (the valid one with the higher sequence number)."""
        best = None
        for at in (64 * 1024, 128 * 1024):
            h = f.read(at, _PAGE)
            if h[:4] != b"head":
                continue
            cand = (crc32c(h[:4] + bytes(4) + h[8:]) == _u32(h, 4), _u64(h, 8), h)
            if best is None or cand[:2] > best[:2]:
                best = cand
        if best is None:
            return None
        h = best[2]
        return {"log_guid": h[48:64], "log_length": _u32(h, 68), "log_offset": _u64(h, 72)}

    def _regions(self, f: FileSource, crc32c) -> dict[bytes, tuple[int, int]]:
        tables = []
        for at in (192 * 1024, 256 * 1024):
            rt = f.read(at, 64 * 1024)
            if rt[:4] == b"regi":
                tables.append((crc32c(rt[:4] + bytes(4) + rt[8:]) != _u32(rt, 4), at, rt))
        for _bad, _at, rt in sorted(tables, key=lambda t: t[:2]):       # valid copies first
            if _u32(rt, 8) > 2047:
                continue
            regions, unknown = {}, None
            for i in range(_u32(rt, 8)):
                o = 16 + 32 * i
                guid = rt[o:o + 16]
                regions[guid] = (_u64(rt, o + 16), _u32(rt, o + 24))
                if _u32(rt, o + 28) & 1 and guid not in (VHDX_BAT, VHDX_METADATA):
                    unknown = guid
            if VHDX_BAT in regions and VHDX_METADATA in regions:
                if unknown is not None:
                    raise NotSupported(f"{self.name}: this VHDX needs a feature RecoverAll doesn't know "
                                       f"(region {uuid.UUID(bytes_le=unknown)})")
                return regions
        raise FormatError(f"{self.name}: this VHDX's region table is damaged (both copies)")

    def _parent_name(self, items: dict) -> str:
        """The parent named by a differencing disk's parent locator (for the message)."""
        if VHDX_PARENT_LOCATOR not in items:
            return ""
        off, length = items[VHDX_PARENT_LOCATOR]
        data = self._mread(off, min(length, 64 * 1024))
        kv = {}
        try:
            for i in range(min(_u16(data, 18), 256)):
                ko, vo, kl, vl = struct.unpack_from("<IIHH", data, 20 + 12 * i)
                kv[data[ko:ko + kl].decode("utf-16-le", "replace")] = data[vo:vo + vl].decode("utf-16-le", "replace")
        except struct.error:
            pass
        return kv.get("relative_path") or kv.get("absolute_win32_path") or kv.get("volume_path") or ""

    def _mread(self, off: int, n: int, have: bool = False) -> bytes:
        """Metadata or BAT bytes, with the log's pending writes laid over them."""
        data = self._have(self.f, off, n) if have else self.f.read(off, n)
        if not self._patches:
            return data
        buf = bytearray(data)
        for page in range(off // _PAGE * _PAGE, off + n, _PAGE):
            p = self._patches.get(page)
            if p is None:
                continue
            a, b = max(page, off), min(page + _PAGE, off + n)
            if a - off > len(buf):
                buf += bytes(a - off - len(buf))
            buf[a - off:b - off] = p[a - page:b - page]
        return bytes(buf)

    def _replay_log(self, f: FileSource, head: dict, crc32c) -> dict[int, bytes]:
        """{file offset: 4 KiB} written by the log's active sequence: the entries from the tail named by the
        newest valid entry up to it, each one checked (signature, log GUID, CRC-32C, sequence numbers)."""
        length, guid = head["log_length"], head["log_guid"]
        if length % _PAGE or length > 64 * MiB:
            return {}
        log = f.read(head["log_offset"], length)
        ring = log + log                       # an entry may wrap around the end of the log

        def entry(pos: int) -> dict | None:
            h = ring[pos:pos + 64]
            if h[:4] != b"loge" or h[32:48] != guid:
                return None
            elen, tail, seq, ndesc = _u32(h, 8), _u32(h, 12), _u64(h, 16), _u32(h, 24)
            if not elen or elen % _PAGE or elen > length or tail % _PAGE or tail >= length:
                return None
            if 64 + 32 * ndesc > elen:
                return None
            data = ring[pos:pos + elen]
            if crc32c(data[:4] + bytes(4) + data[8:]) != _u32(h, 4):
                return None
            return {"seq": seq, "len": elen, "tail": tail, "ndesc": ndesc, "data": data}

        best: list[dict] = []
        for start in range(0, length, _PAGE):
            e = entry(start)
            if e is None:
                continue
            seq, pos = [e], (start + e["len"]) % length
            while len(seq) < length // _PAGE:
                nxt = entry(pos)
                if nxt is None or nxt["seq"] != seq[-1]["seq"] + 1:
                    break
                seq.append(nxt)
                pos = (pos + nxt["len"]) % length
            if seq[-1]["tail"] == start and (not best or seq[-1]["seq"] > best[-1]["seq"]):
                best = seq
        patches: dict[int, bytes] = {}
        for e in best:
            data = e["data"]
            sector = -(-(64 + 32 * e["ndesc"]) // _PAGE) * _PAGE
            for i in range(e["ndesc"]):
                d = data[64 + 32 * i:96 + 32 * i]
                if d[:4] == b"zero":
                    zlen, foff = _u64(d, 8), _u64(d, 16)
                    if foff % _PAGE == 0 and zlen % _PAGE == 0 and zlen <= 256 * MiB:
                        for o in range(foff, foff + zlen, _PAGE):
                            patches[o] = bytes(_PAGE)
                elif d[:4] == b"desc":
                    s = data[sector:sector + _PAGE]
                    sector += _PAGE
                    foff = _u64(d, 16)
                    if s[:4] == b"data" and len(s) == _PAGE and foff % _PAGE == 0:
                        patches[foff] = d[8:16] + s[8:4092] + d[4:8]
        return patches

    def _locate(self, index: int) -> tuple:
        if index >= self.blocks:
            return _ZERO
        k = index + index // self.ratio
        if 8 * k + 8 > len(self.bat):
            return _LOST
        e = _u64(self.bat, 8 * k)
        state, off = e & 7, e >> 20 << 20
        if state in (6, 7):                    # fully (or, in a differencing disk, partly) present
            return (DATA, self.f, off) if off else _LOST
        if state in (3, 5) and off:            # unmapped (discarded by the guest) but still in the file
            return (SOFT, self.f, off)
        return _ZERO


# ====================================================================== VDI
class VdiSource(VDiskSource):
    """VirtualBox disk (.vdi), formats 1.0 and 1.1: a header, the block map (one 32-bit entry per block:
    where it is among the stored blocks, or free, or zero), and the blocks from ``offData`` on."""

    format = "VDI"

    def _setup(self) -> None:
        f = self.f = self._file(self.path)
        h = f.read(0, 512)
        version = _u32(h, 0x44)
        if version >> 16 != 1:
            raise NotSupported(f"{self.name}: VDI format {version >> 16}.{version & 0xFFFF} (from an early "
                               "VirtualBox) isn't supported: convert it with VBoxManage clonemedium first")
        kind = _u32(h, 0x4C)
        if kind == 4:
            raise NotSupported(_differencing("VDI", "", "differencing image (a VirtualBox snapshot)"))
        if kind not in (1, 2, 3):
            raise FormatError(f"{self.name}: unknown VDI image type {kind}")
        off_blocks, self.off_data = _u32(h, 0x154), _u32(h, 0x158)
        self.size = _u64(h, 0x170)
        bs, self.extra, self.nblocks = _u32(h, 0x178), _u32(h, 0x17C), _u32(h, 0x180)
        if not _pow2(bs) or not 512 <= bs <= 256 * MiB or self.extra > 64 * MiB:
            raise FormatError(f"{self.name}: this VDI's block size ({bs}) isn't valid")
        if _u32(h, 0x168) == 4096:
            self.sector_size = 4096
        self.block = bs
        self.map = self._have(f, off_blocks, 4 * self.nblocks)

    def _locate(self, index: int) -> tuple:
        if index >= self.nblocks:
            return _ZERO
        if 4 * index + 4 > len(self.map):
            return _LOST
        e = _u32(self.map, 4 * index)
        if e >= 0xFFFFFFFE:                    # free, or zero
            return _ZERO
        return (DATA, self.f, self.off_data + e * (self.block + self.extra) + self.extra)


# ====================================================================== VMDK
_EXTENT = re.compile(r'^(RW|RDONLY|NOACCESS)\s+(\d+)\s+(\w+)(?:\s+"([^"]*)"(?:\s+(\d+))?)?', re.IGNORECASE)


def parse_descriptor(text: str) -> tuple[dict, list[tuple[str, int, str, str, int]]]:
    """The settings (createType, parentCID, ...) and the extents (access, sectors, type, file, offset in
    sectors) of a VMDK descriptor."""
    keys: dict[str, str] = {}
    extents = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _EXTENT.match(line)
        if m:
            extents.append((m.group(1).upper(), int(m.group(2)), m.group(3).upper(), m.group(4) or "",
                            int(m.group(5) or 0)))
            continue
        k, sep, v = line.partition("=")
        if sep:
            keys[k.strip()] = v.strip().strip('"')
    return keys, extents


def _vmdk_parent(keys: dict) -> str | None:
    """The parent of a VMDK snapshot (its file name, maybe ""), or None for a disk that stands alone."""
    cid = keys.get("parentCID", "ffffffff").strip().lower()
    if cid in ("ffffffff", ""):
        return None
    return keys.get("parentFileNameHint", "")


class VmdkSparse(VDiskSource):
    """A VMware hosted sparse extent ("KDMV"): a monolithicSparse disk, a piece of a twoGbMaxExtentSparse one,
    or a streamOptimized disk (OVA/OVF exports: deflated grains behind markers, the grain directory at the
    end). Grain directory → grain tables → grains; an entry 0 is a grain never written, 1 a zeroed grain. A
    streamOptimized disk cut short (no footer, so no grain directory) is read by walking its markers."""

    format = "VMDK"

    def _setup(self, top: bool = True) -> None:
        f = self.f = self._file(self.path)
        h = f.read(0, 512)
        if h[:4] == b"COWD":
            raise NotSupported(f"{self.name}: ESX 2/3 sparse disks (COWD) aren't supported: convert it with "
                               "vmkfstools or qemu-img convert first")
        if h[:4] != b"KDMV":
            raise FormatError(f"{self.name}: not a VMDK sparse extent")
        version, flags = _u32(h, 4), _u32(h, 8)
        capacity, grain = _u64(h, 12), _u64(h, 20)
        desc_off, desc_size = _u64(h, 28), _u64(h, 36)
        self.gtes = _u32(h, 44)
        rgd, gd, overhead = _u64(h, 48), _u64(h, 56), _u64(h, 64)
        if not 1 <= version <= 3:
            raise NotSupported(f"{self.name}: VMDK sparse format version {version} isn't supported")
        if not _pow2(grain) or grain > 2048 or not 1 <= self.gtes <= 1 << 16:
            raise FormatError(f"{self.name}: this VMDK's grain size ({grain} sectors) isn't valid")
        self.size = capacity * 512
        self.block = grain * 512
        self.compressed = bool(flags & 1 << 16)
        self.grains: dict[int, int] | None = None
        if top and desc_off and desc_size:
            text = f.read(desc_off * 512, min(desc_size, 2048) * 512).split(b"\0")[0]
            keys, _extents = parse_descriptor(text.decode("utf-8", "replace"))
            parent = _vmdk_parent(keys)
            if parent is not None:
                raise NotSupported(_differencing("VMDK", parent, "snapshot (a differencing disk)"))
        if gd == GD_AT_END:
            gd = self._footer_gd()
        if gd is None:                         # a stream cut short: find the grains by their markers
            self._walk(overhead)
            return
        grains = -(-capacity // grain)
        self.ngd = -(-grains // self.gtes)       # grain directory entries
        self.gd = self._have(f, gd * 512, 4 * self.ngd)
        if len(self.gd) < 4 * self.ngd and flags & 2 and rgd:
            rg = self._have(f, rgd * 512, 4 * self.ngd)
            if len(rg) > len(self.gd):
                self.gd = rg

    def _footer_gd(self) -> int | None:
        """A streamOptimized disk's grain directory, from the copy of the header at its end."""
        f = self.f
        if f.size < 1536:
            return None
        footer = f.read(f.size - 1024, 512)
        if footer[:4] != b"KDMV":
            return None
        gd = _u64(footer, 56)
        return gd if gd != GD_AT_END and 0 < gd * 512 < f.size else None

    def _walk(self, overhead: int) -> None:
        f, bs = self.f, self.block
        grains: dict[int, int] = {}
        pos = max(overhead, 1) * 512
        top, ended = -1, False
        while pos + 16 <= f.size:
            m = f.read(pos, 16)
            val, size = _u64(m, 0), _u32(m, 8)
            if size:                           # a grain: its LBA and its compressed size
                if size > 2 * bs + 4096 or val * 512 >= self.size:
                    break
                g = val * 512 // bs
                grains[g] = pos // 512
                top = max(top, g)
                pos += -(-(12 + size) // 512) * 512
                continue
            kind = _u32(m, 12)
            if kind == 0:                      # end of stream
                ended = True
                break
            if kind not in (1, 2, 3) or val > 1 << 32:
                break
            pos += 512 + val * 512             # a grain table, the grain directory or the footer
        self.grains = grains
        self.walk_top = None if ended else top  # grains are written in order: past this, the stream is gone

    def _locate(self, index: int) -> tuple:
        if self.grains is not None:
            s = self.grains.get(index)
            if s is not None:
                return (PACKED, s)
            return _LOST if self.walk_top is not None and index > self.walk_top else _ZERO
        gde, gte = divmod(index, self.gtes)
        if gde >= self.ngd:
            return _ZERO
        if 4 * gde + 4 > len(self.gd):
            return _LOST
        gt_sector = _u32(self.gd, 4 * gde)
        if gt_sector <= 1:
            return _ZERO
        gt = self._tables.get(gt_sector, lambda: self._have(self.f, gt_sector * 512, 4 * self.gtes))
        if 4 * gte + 4 > len(gt):
            return _LOST
        s = _u32(gt, 4 * gte)
        if s <= 1:                             # 0: never written; 1: zeroed
            return _ZERO
        return (PACKED, s) if self.compressed else (DATA, self.f, s * 512)

    def _unpack(self, index: int, loc: tuple) -> bytes:
        off = loc[1] * 512
        size = _u32(self.f.read(off, 12), 8)
        if not size or size > 2 * self.block + 4096:
            return b""
        data = self._have(self.f, off + 12, size)
        return _inflate(data, self.block) or _inflate(data, self.block, -15)


def _extent_path(folder: str, name: str) -> str | None:
    """An extent's file: as named (relative to the descriptor's folder), or by its base name next to the
    descriptor (a disk copied from Windows, or from another folder)."""
    for cand in (name, name.replace("\\", "/")):
        p = cand if os.path.isabs(cand) else os.path.join(folder, cand)
        if os.path.exists(p):
            return p
    p = os.path.join(folder, os.path.basename(name.replace("\\", "/")))
    return p if name and os.path.exists(p) else None


class VmdkSource(VDiskSource):
    """A VMware disk described by a descriptor file (text) listing its extents, laid end to end: FLAT (and
    ESXi's VMFS) extents are the disk as is, from an offset of their file (monolithicFlat, twoGbMaxExtentFlat,
    the -flat.vmdk of an ESXi disk); SPARSE extents are hosted sparse files (twoGbMaxExtentSparse); ZERO
    extents read as zeros. A missing extent file reads as zeros (and as damage); if all are missing, the disk
    can't be opened."""

    format = "VMDK"

    def _setup(self) -> None:
        f = self._file(self.path)
        text = f.read(0, min(f.size, MiB)).split(b"\0")[0].decode("utf-8", "replace")
        keys, extents = parse_descriptor(text)
        parent = _vmdk_parent(keys)
        if parent is not None:
            raise NotSupported(_differencing("VMDK", parent, "snapshot (a differencing disk)"))
        if not extents:
            raise FormatError(f"{self.name}: this VMDK descriptor lists no extents")
        folder = os.path.dirname(self.path)
        self.parts: list[tuple[int, int, int, Source | None, int]] = []     # start, length, kind, source, base
        pos, missing, files = 0, [], 0
        for _access, sectors, kind, fname, offset in extents:
            length = sectors * 512
            if kind in ("FLAT", "VMFS", "SPARSE"):
                files += 1
                p = _extent_path(folder, fname)
                if p is None:
                    missing.append(fname)
                    self.parts.append((pos, length, LOST, None, 0))
                elif kind == "SPARSE":
                    sparse = VmdkSparse(p, top=False)
                    self.files.append(sparse)
                    sparse.bad, sparse.bad_base = self.bad, pos
                    self.parts.append((pos, length, PACKED, sparse, 0))
                else:
                    self.parts.append((pos, length, DATA, self._file(p), offset * 512))
            elif kind == "ZERO":
                self.parts.append((pos, length, ZERO, None, 0))
            elif kind in ("VMFSSPARSE", "SESPARSE"):
                raise NotSupported(f"{self.name}: ESXi {kind.lower()} extents (snapshots) aren't supported: "
                                   "consolidate the snapshots, or convert the disk with qemu-img convert first")
            elif kind in ("VMFSRDM", "VMFSRAW"):
                raise NotSupported(f"{self.name}: this VMDK maps a physical disk (raw device mapping): scan "
                                   "that disk itself")
            else:
                raise NotSupported(f"{self.name}: VMDK extents of type {kind} aren't supported")
            pos += length
        if files and len(missing) == files:
            raise RallError(f"{self.name}: the data file{'s' if len(missing) > 1 else ''} of this VMDK "
                            f"({', '.join(missing[:3])}{', …' if len(missing) > 3 else ''}) "
                            f"{'are' if len(missing) > 1 else 'is'} missing: put "
                            f"{'them' if len(missing) > 1 else 'it'} next to the descriptor")
        self.size = pos
        self.starts = [p[0] for p in self.parts]

    def _read(self, offset: int, length: int) -> bytes:
        out = bytearray()
        pos, end = offset, offset + length
        i = max(0, bisect.bisect_right(self.starts, pos) - 1)
        while pos < end and i < len(self.parts):
            start, n, kind, src, base = self.parts[i]
            rel = pos - start
            take = min(n - rel, end - pos)
            i += 1
            if take <= 0:
                continue
            if kind == DATA:
                out += self._piece(src, base + rel, take, pos)
            elif kind == PACKED:
                out += src.read(rel, take)
            else:
                if kind == LOST:
                    self.bad.add(pos, take)
                out += bytes(take)
            pos += take
        return bytes(out) + bytes(end - pos)


# ====================================================================== QCOW2 and QCOW
_QCOW_OFFSET = 0x00FFFFFFFFFFFE00
_QCOW_COMPRESSED = 1 << 62
_QCOW_EXT_BACKING_FORMAT = 0xE2792ACA


def _unzstd(data: bytes, limit: int) -> bytes:
    try:
        from compression import zstd  # Python 3.14
    except ImportError:
        return b""
    try:
        return zstd.ZstdDecompressor().decompress(data, limit)
    except zstd.ZstdError:
        return b""


def _have_zstd() -> bool:
    try:
        from compression import zstd  # noqa: F401
    except ImportError:
        return False
    return True


class QcowSource(VDiskSource):
    """QEMU disk image: QCOW2 (versions 2 and 3: an L1 table of L2 tables of clusters; compressed clusters are
    raw deflate, or zstd; version 3 has zero clusters) and the original QCOW. Clusters never written come from
    the backing file when the image is an overlay, else read as zeros."""

    format = "QCOW2"

    def _setup(self, depth: int = 0) -> None:
        f = self.f = self._file(self.path)
        h = f.read(0, 64 * 1024)
        self.version = _be32(h, 4)
        self.ctype = 0
        if self.version == 1:
            self.format = "QCOW"
            self.size = _be64(h, 24)
            bits, l2bits = h[32], h[33]
            if not 9 <= bits <= 16 or not 1 <= l2bits <= 16:
                raise FormatError(f"{self.name}: this QCOW image's cluster size isn't valid")
            if _be32(h, 36):
                raise NotSupported(f"{self.name}: this QCOW image is encrypted, which RecoverAll can't read: "
                                   "decrypt it with qemu-img convert first")
            l1_off = _be64(h, 40)
            self.l2_entries = 1 << l2bits
            self.l1_size = -(-self.size // ((1 << bits) * self.l2_entries))
            self.l1_mask = (1 << 63) - 1
            exts: dict[int, bytes] = {}
        elif self.version in (2, 3):
            bits = _be32(h, 20)
            if not 9 <= bits <= 21:
                raise FormatError(f"{self.name}: this QCOW2 image's cluster size isn't valid")
            self.size = _be64(h, 24)
            if _be32(h, 32):
                raise NotSupported(f"{self.name}: this QCOW2 image is encrypted, which RecoverAll can't read: "
                                   "decrypt it with qemu-img convert first")
            self.l1_size, l1_off = _be32(h, 36), _be64(h, 40)
            incompatible, ext_start = 0, 72
            if self.version == 3:
                incompatible, ext_start = _be64(h, 72), _be32(h, 100)
                if ext_start > 104:
                    self.ctype = h[104]
            if incompatible & 16:
                raise NotSupported(f"{self.name}: this QCOW2 image uses extended L2 entries (subclusters), which "
                                   "RecoverAll can't read yet: convert it with qemu-img convert first")
            if incompatible & 4:
                raise NotSupported(f"{self.name}: this QCOW2 image keeps its data in an external file, which "
                                   "RecoverAll can't follow: open that data file (a raw image) instead")
            if incompatible & ~0x1F:
                raise NotSupported(f"{self.name}: this QCOW2 image uses features RecoverAll doesn't know: "
                                   "convert it with qemu-img convert first")
            if self.ctype == 1 and not _have_zstd():
                raise NotSupported(f"{self.name}: this QCOW2 image is compressed with zstd, which needs Python "
                                   "3.14: convert it with qemu-img convert first")
            if self.ctype > 1:
                raise NotSupported(f"{self.name}: unknown QCOW2 compression type {self.ctype}")
            self.l2_entries = (1 << bits) // 8
            self.l1_mask = _QCOW_OFFSET
            exts = self._extensions(h, ext_start)
        else:
            raise NotSupported(f"{self.name}: QCOW version {self.version} isn't supported")
        self.cbits = bits
        self.block = 1 << bits
        self.l1 = self._have(f, l1_off, 8 * self.l1_size)
        backing_off, backing_len = _be64(h, 8), _be32(h, 16)
        if backing_off and backing_len:
            name = f.read(backing_off, min(backing_len, 4096)).decode("utf-8", "replace")
            fmt = exts.get(_QCOW_EXT_BACKING_FORMAT, b"").decode("ascii", "replace").strip("\0")
            self.backing = _open_backing(self.path, name, fmt, depth)
        self._hole = _BACKING if self.backing is not None else _ZERO

    @staticmethod
    def _extensions(h: bytes, pos: int) -> dict[int, bytes]:
        out: dict[int, bytes] = {}
        while pos + 8 <= len(h):
            kind, n = _be32(h, pos), _be32(h, pos + 4)
            if kind == 0:
                break
            out[kind] = h[pos + 8:pos + 8 + n]
            pos += 8 + -(-n // 8) * 8
        return out

    def _locate(self, index: int) -> tuple:
        l1i, l2i = divmod(index, self.l2_entries)
        if l1i >= self.l1_size:
            return self._hole
        if 8 * l1i + 8 > len(self.l1):
            return _LOST
        l2_off = _be64(self.l1, 8 * l1i) & self.l1_mask
        if not l2_off:
            return self._hole
        l2 = self._tables.get(l2_off, lambda: self._have(self.f, l2_off, 8 * self.l2_entries))
        if 8 * l2i + 8 > len(l2):
            return _LOST
        e = _be64(l2, 8 * l2i)
        if self.version == 1:
            if e >> 63:
                return (PACKED, e)
            return (DATA, self.f, e) if e else self._hole
        if e & _QCOW_COMPRESSED:
            return (PACKED, e)
        if self.version >= 3 and e & 1:        # a zero cluster
            return _ZERO
        off = e & _QCOW_OFFSET
        return (DATA, self.f, off) if off else self._hole

    def _unpack(self, index: int, loc: tuple) -> bytes:
        e = loc[1]
        if self.version == 1:
            shift = 63 - self.cbits
            off = e & ((1 << shift) - 1)
            size = (e >> shift) & (self.block - 1)
        else:
            shift = 62 - (self.cbits - 8)
            off = e & ((1 << shift) - 1)
            size = (((e >> shift) & ((1 << (self.cbits - 8)) - 1)) + 1) * 512 - (off & 511)
        data = self._have(self.f, off, size)
        if self.ctype == 1:
            return _unzstd(data, self.block)
        return _inflate(data, self.block, -15)


def _open_backing(path: str, name: str, fmt: str, depth: int) -> Source:
    """The backing file of a QCOW/QCOW2 overlay (relative names are relative to the overlay's folder)."""
    base = os.path.basename(path)
    if depth >= 16:
        raise FormatError(f"{base}: its chain of backing files is too long (a loop?)")
    if re.match(r"^[a-z][a-z0-9+.-]*:", name) and not os.path.exists(name):
        raise NotSupported(f"{base} is an overlay on “{name}”, which isn't a file RecoverAll can open: merge "
                           "them into one image first (qemu-img convert)")
    p = name if os.path.isabs(name) else os.path.join(os.path.dirname(path), name)
    if not os.path.isfile(p):
        raise NotSupported(f"{base} is an overlay on “{name}”, which isn't there: put the backing file where "
                           "it names it, or merge the two into one image first (qemu-img convert)")
    if fmt != "raw":
        src = open_vdisk(p, _depth=depth + 1)
        if src is not None:
            return src
    return FileSource(p)


# ====================================================================== EWF (E01)
_SEGMENT = re.compile(r"^(.*\.)([A-Za-z])(\d\d|[A-Za-z]{2})$")
_EWF_SECTIONS = {b"header", b"header2", b"volume", b"disk", b"data", b"sectors", b"table", b"table2", b"next",
                 b"done", b"hash", b"digest", b"error2", b"session", b"ltree", b"xheader", b"xhash"}


def _segment_names(letter: str):
    def case(s: str) -> str:
        return s.upper() if letter.isupper() else s.lower()
    for n in range(1, 100):
        yield case(f"{letter}{n:02d}")
    for c0 in range(ord(letter.upper()), ord("Z") + 1):
        for c1 in string.ascii_uppercase:
            for c2 in string.ascii_uppercase:
                yield case(chr(c0) + c1 + c2)


def ewf_segments(path: str) -> list[str]:
    """The segment files of the EWF image PATH belongs to (x.E01, x.E02, …, x.E99, x.EAA, …; the same for
    .s01 and lowercase names), in order, up to the first one missing. PATH may be any of them."""
    m = _SEGMENT.match(path)
    if not m:
        return [path]
    out = []
    for name in _segment_names(m.group(2)):
        p = m.group(1) + name
        if not os.path.isfile(p):
            break
        out.append(p)
    return out or [path]


class EwfSource(VDiskSource):
    """EnCase / libewf forensic image (EWF-E01, and the older SMART .s01): segment files, each a chain of
    sections. The volume section gives the media size and the chunk size (usually 64 sectors); each table
    section lists where the chunks of the sectors section before it are (bit 31: deflated, else stored with an
    Adler-32 after it); table2 is its copy; error2 lists the sectors that couldn't be read when the image was
    made (they are recorded as bad). A segment cut short keeps the chunks that made it: when its last table
    never came, they are found by inflating them one after another."""

    format = "E01"

    def _setup(self) -> None:
        paths = ewf_segments(self.path)
        self.path = os.path.abspath(paths[0])
        self.name = os.path.basename(paths[0])
        self.recs: list[dict] = []             # one per table: where its entries are, which chunk is its first
        self.firsts: list[int] = []
        self.bps = 0
        self.media = 0
        errors: list[tuple[int, int]] = []
        mapped = 0
        for n, p in enumerate(paths, start=1):
            f = self._file(p)
            hdr = f.read(0, 13)
            if hdr[:8] != EWF1:
                break
            if n == 1 and _u16(hdr, 9) != 1:
                raise RallError(f"{self.name} is segment {_u16(hdr, 9)} of an EWF image: open its first segment "
                                "(.E01), with the others next to it")
            mapped, state = self._walk(f, mapped, errors)
            if state != "next":
                break
        if not self.bps:
            raise FormatError(f"{self.name}: this EWF image has no volume section (it gives the media size)")
        self.size = self.media
        for first, count in errors:
            self.bad.add(first * self.bps, count * self.bps)

    # ------------------------------------------------------------------ the section chain
    def _walk(self, f: FileSource, first: int, errors: list) -> tuple[int, str]:
        """Follow one segment's sections: (the next chunk number, "next" | "done" | "cut")."""
        pos, seen = 13, set()
        sectors: tuple[int, int] | None = None     # data of the last sectors section
        tabled = True                              # ... and whether a table came after it
        last: dict | None = None
        while pos not in seen and pos + 76 <= f.size:
            seen.add(pos)
            d = f.read(pos, 76)
            kind = d[:16].split(b"\0")[0]
            nxt, size = _u64(d, 16), _u64(d, 24)
            if zlib.adler32(d[:72]) != _u32(d, 72) and kind not in _EWF_SECTIONS:
                break
            if kind in (b"next", b"done"):
                return first, kind.decode()
            end = pos + size if size >= 76 else nxt
            if kind in (b"volume", b"disk", b"data"):
                self._volume(f, pos + 76, end - pos - 76)
            elif kind == b"sectors":
                sectors, tabled = (pos + 76, end), False
            elif kind == b"table" and self.bps:
                rec = self._table(f, pos, end, nxt, sectors)
                if rec is None:
                    return first, "cut"        # how many chunks it had is lost: later ones can't be placed
                self.recs.append(rec)
                self.firsts.append(first)
                first += rec["count"]
                last, tabled = rec, True
            elif kind == b"table2" and last is not None and last["alt"] is None:
                last["alt"] = pos + 100
            elif kind == b"error2":
                errors.extend(self._error2(f, pos + 76))
            if nxt <= pos:
                break
            pos = nxt
        if sectors is not None and not tabled and self.bps:
            first = self._walk_chunks(f, sectors, first)
        return first, "cut"

    def _volume(self, f: FileSource, off: int, n: int) -> None:
        if self.bps:
            return
        v = f.read(off, 1052)
        chunks, spc, bps = _u32(v, 4), _u32(v, 8), _u32(v, 12)
        sectors = _u64(v, 16) if n >= 1052 else _u32(v, 16)
        if not _pow2(bps) or bps > 65536 or not 0 < spc <= 65536 or spc * bps > 64 * MiB:
            return
        self.bps = self.sector_size = bps
        self.block = spc * bps
        self.media = sectors * bps or chunks * self.block

    def _table(self, f: FileSource, pos: int, end: int, nxt: int, sectors) -> dict | None:
        th = f.read(pos + 76, 24)
        if zlib.adler32(th[:20]) != _u32(th, 20) and nxt > pos and nxt + 100 <= f.size:
            d2 = f.read(nxt, 76)
            th2 = f.read(nxt + 76, 24)
            if d2[:16].split(b"\0")[0] == b"table2" and zlib.adler32(th2[:20]) == _u32(th2, 20):
                return {"f": f, "count": _u32(th2, 0), "entries": nxt + 100, "base": _u64(th2, 8),
                        "sectors": sectors, "pos": pos, "end": end, "alt": pos + 100, "data": None}
        count = _u32(th, 0)
        if 24 + 4 * count > end - pos - 76:
            count = max(0, (end - pos - 76 - 28) // 4)
        if count > 1 << 24:
            return None
        return {"f": f, "count": count, "entries": pos + 100, "base": _u64(th, 8), "sectors": sectors, "pos": pos,
                "end": end, "alt": None, "data": None}

    def _error2(self, f: FileSource, off: int) -> list[tuple[int, int]]:
        h = f.read(off, 520)
        count = _u32(h, 0)
        if zlib.adler32(h[:516]) != _u32(h, 516) or count > 1 << 20:
            return []
        data = f.read(off + 520, 8 * count)
        return [struct.unpack_from("<II", data, 8 * i) for i in range(count)]

    def _walk_chunks(self, f: FileSource, sectors: tuple[int, int], first: int) -> int:
        """The chunks of a sectors section whose table never came (the segment was cut short): a deflated
        chunk is recognized by inflating to a whole chunk, a stored one by its Adler-32."""
        start, end = sectors[0], min(sectors[1], f.size)
        pos, c, bs = start, first, self.block
        entries = bytearray()
        while pos < end and c * bs < self.media and pos - start < 1 << 31:
            want = min(bs, self.media - c * bs)
            buf = f.read(pos, min(want + 1028, end - pos))
            step, flag = 0, 0
            if len(buf) > 2 and buf[0] & 0x0F == 8 and (buf[0] << 8 | buf[1]) % 31 == 0:
                d = zlib.decompressobj()
                try:
                    out = d.decompress(buf, want)
                    if not d.eof:
                        out += d.decompress(d.unconsumed_tail, 1)
                except zlib.error:
                    out = b""
                if d.eof and len(out) == want:
                    step, flag = len(buf) - len(d.unused_data), 0x80000000
            if not step and len(buf) >= want + 4 and zlib.adler32(buf[:want]) == _u32(buf, want):
                step = want + 4
            if not step:
                break
            entries += struct.pack("<I", (pos - start) | flag)
            pos += step
            c += 1
        if entries:
            self.recs.append({"f": f, "count": len(entries) // 4, "entries": 0, "base": start,
                              "sectors": (start, pos), "pos": pos, "end": pos, "alt": None, "data": bytes(entries)})
            self.firsts.append(first)
        return c

    # ------------------------------------------------------------------ chunks
    def _entries(self, k: int) -> bytes:
        rec = self.recs[k]
        if rec["data"] is not None:
            return rec["data"]
        return self._tables.get(k, lambda: self._load_entries(rec))

    def _load_entries(self, rec: dict) -> bytes:
        """A table's entries, checked with the Adler-32 after them (table2's copy when they don't match)."""
        n = 4 * rec["count"]
        raw = self._have(rec["f"], rec["entries"], n + 4)
        if len(raw) == n + 4 and zlib.adler32(raw[:n]) == _u32(raw, n):
            return raw[:n]
        if rec["alt"] is not None:
            alt = self._have(rec["f"], rec["alt"], n + 4)
            if len(alt) == n + 4 and zlib.adler32(alt[:n]) == _u32(alt, n):
                return alt[:n]
        return raw[:n]

    def _locate(self, index: int) -> tuple:
        k = bisect.bisect_right(self.firsts, index) - 1
        if k < 0:
            return _LOST
        rec = self.recs[k]
        j = index - self.firsts[k]
        if j >= rec["count"]:
            return _LOST                       # past the last chunk found: a missing or cut segment
        ent = self._entries(k)
        if 4 * j + 4 > len(ent):
            return _LOST
        e = _u32(ent, 4 * j)
        off = rec["base"] + (e & 0x7FFFFFFF)
        if not e >> 31:
            return (DATA, rec["f"], off)
        if 4 * j + 8 <= len(ent):
            size = rec["base"] + (_u32(ent, 4 * j + 4) & 0x7FFFFFFF) - off
        else:
            size = self._data_end(rec, off) - off
        if not 0 < size <= 2 * self.block + 1024:
            size = self.block + 1024
        return (PACKED, rec["f"], off, size)

    def _data_end(self, rec: dict, off: int) -> int:
        """Where the data of a table's last chunk ends: its sectors section's end (or, in the oldest images,
        the table section's, which holds the chunks itself)."""
        s = rec["sectors"]
        if s and s[0] <= off < s[1]:
            return s[1]
        if rec["pos"] <= off < rec["end"]:
            return rec["end"]
        return off + self.block + 1024

    def _unpack(self, index: int, loc: tuple) -> bytes:
        _kind, f, off, size = loc
        return _inflate(self._have(f, off, size), self.block)


# ====================================================================== recognizing and opening
def _is_descriptor(head: bytes, path: str, size: int) -> bool:
    text = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if text.startswith(b"# Disk DescriptorFile"):
        return True
    return (path.lower().endswith(".vmdk") and size <= MiB and b"\0" not in head.rstrip(b"\0")
            and re.search(rb"(?m)^\s*createType\s*=", head) is not None
            and re.search(rb'(?im)^\s*(RW|RDONLY|NOACCESS)\s+\d+\s+\w+', head) is not None)


def sniff(head: bytes, tail: bytes, path: str = "", size: int = 0) -> str | None:
    """The format of a file from its first 4 KiB (HEAD) and its last 512 bytes (TAIL), or None."""
    if head[:8] == b"vhdxfile":
        return "VHDX"
    if head[:8] == b"conectix" and len(head) >= 512 and _be32(head, 60) in (3, 4):
        return "VHD"
    if len(head) >= 0x48 and _u32(head, 0x40) == VDI_SIGNATURE and _u32(head, 0x44) >> 16 in (0, 1):
        return "VDI"
    if head[:4] in (b"KDMV", b"COWD") and len(head) >= 8 and 1 <= _u32(head, 4) <= 3:
        return "VMDK"
    if head[:4] == b"QFI\xfb" and len(head) >= 8 and 1 <= _be32(head, 4) <= 3:
        return "QCOW" if _be32(head, 4) == 1 else "QCOW2"
    if head[:8] == EWF1:
        return "E01"
    if head[:8] in (EWF2, EWF2_LOGICAL):
        return "Ex01"
    if head[:8] == EWF1_LOGICAL:
        return "L01"
    if _is_descriptor(head, path, size):
        return "VMDK"
    for t in (tail[-512:], tail[-511:] + b"\0"):
        if len(t) == 512 and t[:8] == b"conectix" and _vhd_footer_ok(t) and _be32(t, 60) in (2, 3, 4):
            return "VHD"
    return None


def detect(path: str) -> str | None:
    """The format of the image file PATH ("VHD", "VHDX", "VDI", "VMDK", "QCOW2", "QCOW", "E01"; "Ex01" and
    "L01" are recognized only to be refused), or None: a raw image, a device, a folder, a missing file."""
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        size = os.fstat(fd).st_size
        head = os.pread(fd, 4096, 0)
        tail = os.pread(fd, 512, size - 512) if size >= 1024 else b""
    except OSError:
        return None
    finally:
        os.close(fd)
    return sniff(head, tail, path, size)


def open_vdisk(path: str, sector_size: int | None = None, _depth: int = 0) -> VDiskSource | None:
    """PATH opened as the disk it holds when it is a virtual-disk or forensic image file, else None (a raw
    image, a device). Raises RallError for what can't be read (a differencing disk, an encrypted image) and
    FormatError when the image's own structures are beyond use."""
    fmt = detect(path)
    if fmt is None:
        return None
    base = os.path.basename(path)
    if fmt == "Ex01":
        raise NotSupported(f"{base}: EWF2 images (.Ex01) aren't supported yet: convert it to an E01 or a raw image "
                           "first (ewfexport, or FTK Imager)")
    if fmt == "L01":
        raise NotSupported(f"{base} is a logical evidence file: it holds copies of files, not a disk image")
    try:
        if fmt == "VHD":
            src: VDiskSource = VhdSource(path)
        elif fmt == "VHDX":
            src = VhdxSource(path)
        elif fmt == "VDI":
            src = VdiSource(path)
        elif fmt == "VMDK":
            with open(path, "rb") as fh:
                magic = fh.read(4)
            src = VmdkSparse(path) if magic in (b"KDMV", b"COWD") else VmdkSource(path)
        elif fmt in ("QCOW2", "QCOW"):
            src = QcowSource(path, depth=_depth)
        else:
            src = EwfSource(path)
    except (struct.error, IndexError, ValueError, OverflowError) as exc:
        raise FormatError(f"{base}: this {fmt} image is damaged ({exc})") from exc
    if sector_size:
        src.sector_size = int(sector_size)
    return src


def container_of(src: Source) -> VDiskSource | None:
    """The virtual-disk image behind SRC (through regions and caches), or None when SRC reads a device or a raw
    file directly."""
    for _ in range(64):
        if isinstance(src, VDiskSource):
            return src
        if isinstance(src, RegionSource):
            src = src.parent
        elif isinstance(src, CachedSource):
            src = src.inner
        else:
            return None
    return None


def check_raw_file(path: str, what: str) -> None:
    """Refuse WHAT (a repair, writing a partition table, unlocking) on a virtual-disk image file: tools that
    work on the file itself would hit the wrong bytes, since its sectors aren't stored in order."""
    if not path or not os.path.isfile(path):
        return
    fmt = detect(path)
    if fmt:
        raise NotSupported(f"{what} works on disks and raw image files; {os.path.basename(path)} is a {fmt} image, "
                           "which RecoverAll only reads. Save it as a raw image first (Imaging page, or "
                           "recoverctl image) and use the copy")
