"""NTFS: existing and deleted files from the Master File Table, compressed files, alternate data streams, and
volumes whose boot sectors are gone.

On disk, an NTFS volume starts with a boot sector (a copy sits in the volume's last sector) that says how big
a cluster is and where the Master File Table (MFT) starts. The MFT is a file of fixed-size records (1 KiB,
sometimes 4 KiB), one or more per file and folder: record 0 describes the MFT itself (where its pieces are),
record 1 is $MFTMirr (a copy of records 0-3), record 3 $Volume (label, version), record 5 the root folder,
record 6 $Bitmap (one bit per cluster: in use or free). A record holds attributes: times and DOS attributes
($STANDARD_INFORMATION), one name per hard link with the folder it is in ($FILE_NAME), the content ($DATA:
small files keep it inside the record, bigger ones list "runs" of clusters), alternate data streams (named
$DATA), reparse points (symlinks, junctions, Windows' own file compression). A file with too many pieces for
one record spreads its attributes over extension records, listed in its $ATTRIBUTE_LIST.

Deleting a file only clears the record's in-use flag and the file's bits in $Bitmap: the record (name, folder,
times and the list of clusters) stays until the record is reused. That is why deleted files on NTFS usually come
back whole, with their names and folders (deleted folders too), as long as their clusters weren't given to
another file since: the chance is GOOD when every cluster is still free in $Bitmap, POOR when some are in use.

Compressed content is decoded on the fly: NTFS compression (LZNT1, per compression unit) and Windows 10's file
compression (``compact /exe``: XPRESS4K/8K/16K and LZX, in a WofCompressedData stream behind a reparse point).

What it can't do: a file whose MFT record was reused is gone from the MFT (its content may still be found by
signature); EFS-encrypted files are copied as stored (still encrypted); deduplicated files (Windows Server)
live in a chunk store that isn't reassembled. A deleted file whose names were stripped from its record (ntfs-3g
does that to files with an attribute list) is listed as "MFT record N" in Lost files.

When both boot sectors are destroyed, :class:`MftDetector` finds the MFT during a deep scan and works out the
geometry (cluster size, where the volume starts, how big it is) from the MFT's own records, the way GetDataBack
does; :class:`NtfsReader` then reads the volume from that reconstructed geometry.
"""

from __future__ import annotations

import bisect
import dataclasses
import re
import struct
from array import array
from typing import Iterator

from ..blockio import CachedSource, Source
from ..errors import FormatError
from .base import (
    CHANCE_FAIR,
    CHANCE_GOOD,
    CHANCE_POOR,
    F_ADS,
    F_COMPRESSED,
    F_ENCRYPTED,
    F_HARDLINK,
    F_ORPHAN,
    F_PARTIAL,
    F_RESIDENT,
    F_SPARSE,
    F_SYMLINK,
    F_SYSTEM,
    NULL_CONTROL,
    Control,
    Detector,
    Entry,
    FsReader,
    filetime,
    merge_runs,
    read_content,
    register_decoder,
)

# attribute types
AT_STANDARD_INFORMATION = 0x10
AT_ATTRIBUTE_LIST = 0x20
AT_FILE_NAME = 0x30
AT_VOLUME_NAME = 0x60
AT_VOLUME_INFORMATION = 0x70
AT_DATA = 0x80
AT_INDEX_ROOT = 0x90
AT_REPARSE_POINT = 0xC0
AT_END = 0xFFFFFFFF

# MFT record header flags
REC_IN_USE = 0x01
REC_DIRECTORY = 0x02

# attribute header flags
ATTR_COMPRESSION_MASK = 0x00FF
ATTR_ENCRYPTED = 0x4000
ATTR_SPARSE = 0x8000

# DOS attributes ($STANDARD_INFORMATION / $FILE_NAME)
DOS_SYSTEM = 0x0004
DOS_ENCRYPTED = 0x4000

# reparse tags
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
IO_REPARSE_TAG_SYMLINK = 0xA000000C
IO_REPARSE_TAG_WOF = 0x80000017
IO_REPARSE_TAG_LX_SYMLINK = 0xA000001D
IO_REPARSE_TAG_DEDUP = 0x80000013

# file name namespaces, best first: Win32 & DOS, Win32, POSIX, DOS (8.3 aliases only)
_NS_RANK = {3: 0, 1: 1, 0: 2, 2: 3}

ROOT = 5
EXTEND = 11
FIRST_USER_RECORD = 16
REF_MASK = 0xFFFFFFFFFFFF

MAX_CLUSTER = 2 * 1024 * 1024                 # NTFS clusters go up to 2 MiB
MAX_ATTRS = 256                               # attributes per record (a 4 KiB record holds fewer)
MAX_RUNS = 1 << 20                            # runs per attribute piece
MAX_ALIST = 4 * 1024 * 1024                   # bytes of $ATTRIBUTE_LIST we are willing to read
MAX_REPARSE = 64 * 1024
MAX_FILE = 1 << 53                            # NTFS can't hold a bigger file (8 PiB)
MAX_RECORDS = 1 << 32                         # MFT record numbers are 32-bit
MAX_UNIT = 4 * 1024 * 1024                    # biggest compression unit we accept (NTFS uses 64 KiB)
BITMAP_CAP = 1 << 30                          # 1 GiB of bitmap = 32 TiB with 4 KiB clusters
BATCH = 4 * 1024 * 1024                       # MFT bytes read at once
WOF_ALGORITHMS = {0: ("xpress", 4096), 1: ("lzx", 32768), 2: ("xpress", 8192), 3: ("xpress", 16384)}

_HDR = struct.Struct("<4sHHQHHHHIIQHHI")      # FILE record header (48 bytes)
_ATTR = struct.Struct("<IIBBHHH")             # type, length, non-resident, name length, name offset, flags, id
_RESIDENT = struct.Struct("<IH")              # value length, value offset
_NONRES = struct.Struct("<QQHH4xQQQ")         # first VCN, last VCN, runs offset, compression unit, sizes
_FILE_NAME = struct.Struct("<QQQQQQQIIBB")    # parent, 4 times, allocated, size, flags, reparse, len, namespace
_STD_INFO = struct.Struct("<QQQQI")           # creation, modification, MFT change, access, DOS attributes
_ALIST = struct.Struct("<IHBBQQH")            # type, length, name length, name offset, first VCN, record, id


def _power_of_two(n: int) -> bool:
    return n > 0 and not n & (n - 1)


def _utf16(b: bytes | bytearray | memoryview) -> str:
    return bytes(b).decode("utf-16-le", "replace")


# ---------------------------------------------------------------------- boot sector
def parse_boot(buf: bytes) -> dict | None:
    """The geometry in an NTFS boot sector (primary or backup), or None if BUF isn't a plausible one.

    Sizes are in bytes. ``size`` is the whole volume including the backup boot sector in its last sector
    (the boot sector counts one sector less)."""
    if len(buf) < 512 or buf[3:11] != b"NTFS    " or buf[510:512] != b"\x55\xaa":
        return None
    bps = struct.unpack_from("<H", buf, 0x0B)[0]
    if bps < 256 or bps > 4096 or not _power_of_two(bps):
        return None
    raw = buf[0x0D]
    if 0 < raw <= 0x80 and _power_of_two(raw):
        spc = raw
    elif raw >= 0xF4:                         # big clusters: the byte is a negative power of two
        spc = 1 << (256 - raw)
    else:
        return None
    cs = bps * spc
    if cs > MAX_CLUSTER:
        return None
    total, mft_lcn, mirr_lcn = struct.unpack_from("<QQQ", buf, 0x28)
    clusters = total // spc
    if clusters < 16 or mft_lcn >= clusters or mirr_lcn >= clusters:
        return None

    def per_record(v: int) -> int:
        v = v - 256 if v >= 128 else v       # signed: n > 0 clusters, n < 0 → 2**-n bytes
        if v > 0:
            return v * cs
        if -31 <= v < 0:
            return 1 << -v
        return 0

    rs = per_record(buf[0x40])
    ixs = per_record(buf[0x44])
    if not (256 <= rs <= 65536 and _power_of_two(rs)):
        return None
    if ixs and not (256 <= ixs <= 65536 * 4 and _power_of_two(ixs)):
        ixs = 4096
    serial = struct.unpack_from("<Q", buf, 0x48)[0]
    return {"sector_size": bps, "cluster_size": cs, "sectors": total, "clusters": clusters,
            "size": (total + 1) * bps, "mft_lcn": mft_lcn, "mftmirr_lcn": mirr_lcn,
            "mft_offset": mft_lcn * cs, "mftmirr_offset": mirr_lcn * cs, "record_size": rs,
            "index_size": ixs or 4096, "serial": serial, "uuid": f"{serial:016X}"}


# ---------------------------------------------------------------------- MFT records
def apply_fixups(rec: bytearray, size: int) -> int:
    """Undo the update sequence ("fixups") of a FILE/INDX record in place.

    NTFS replaces the last two bytes of every 512-byte stride with a check value when it writes a record, so a
    torn write can be detected. Returns 0 when every stride matched, 1 when some didn't (the record is kept but
    is suspect), -1 when the update sequence array itself is nonsense."""
    usa_ofs, usa_cnt = struct.unpack_from("<HH", rec, 4)
    if usa_cnt < 2 or usa_ofs & 1 or usa_ofs < 0x28 or usa_ofs + usa_cnt * 2 > size:
        return -1
    stride = size // (usa_cnt - 1)
    if stride < 256 or stride * (usa_cnt - 1) != size:
        return -1
    usn = rec[usa_ofs:usa_ofs + 2]
    bad = 0
    for i in range(1, usa_cnt):
        p = i * stride - 2
        if rec[p:p + 2] != usn:
            bad = 1
        rec[p:p + 2] = rec[usa_ofs + 2 * i:usa_ofs + 2 * i + 2]
    return bad


def decode_runs(b: bytes | bytearray, pos: int, end: int) -> tuple[list[tuple[int, int]], bool]:
    """A runlist → [(LCN or -1 for a sparse run, clusters)], and whether it was well formed.

    Each run is a header byte (low nibble: size of the length field, high nibble: size of the offset field),
    the length, and the starting cluster as a signed delta from the previous run's (no offset: sparse)."""
    runs: list[tuple[int, int]] = []
    lcn = 0
    end = min(end, len(b))
    while pos < end:
        h = b[pos]
        if h == 0:
            return runs, True
        ln = h & 0x0F
        lo = h >> 4
        if ln == 0 or ln > 8 or lo > 8 or pos + 1 + ln + lo > end or len(runs) >= MAX_RUNS:
            return runs, False
        length = int.from_bytes(b[pos + 1:pos + 1 + ln], "little")
        if length <= 0:
            return runs, False
        if lo:
            lcn += int.from_bytes(b[pos + 1 + ln:pos + 1 + ln + lo], "little", signed=True)
            if lcn < 0:
                return runs, False
            runs.append((lcn, length))
        else:
            runs.append((-1, length))
        pos += 1 + ln + lo
    return runs, False                       # ran off the attribute without an end marker


class _Piece:
    """One $DATA (or $ATTRIBUTE_LIST, $REPARSE_POINT) attribute: resident bytes or a piece of a runlist."""

    __slots__ = ("name", "flags", "aid", "value", "vcn", "last", "runs", "ok", "alloc", "size", "init", "cu")

    def __init__(self, name: str, flags: int, aid: int):
        self.name = name
        self.flags = flags
        self.aid = aid
        self.value: bytes | None = None       # resident content
        self.vcn = 0
        self.last = -1
        self.runs: list[tuple[int, int]] | None = None
        self.ok = True
        self.alloc = self.size = self.init = 0
        self.cu = 0


class _Rec:
    """What an MFT record says about its file (only what recovery needs)."""

    __slots__ = ("num", "seq", "flags", "base", "damaged", "si", "names", "data", "reparse", "alist", "i30",
                 "volname", "volver")

    def __init__(self, num: int, seq: int, flags: int, base: int, damaged: bool):
        self.num = num
        self.seq = seq                         # bumped by one each time the record is freed
        self.flags = flags
        self.base = base                       # 0, or the base record of an extension record
        self.damaged = damaged
        self.si: tuple | None = None
        self.names: list[tuple] = []           # (parent record, parent seq, namespace, name, times, dos flags)
        self.data: list[_Piece] = []
        self.reparse: _Piece | None = None
        self.alist: _Piece | None = None
        self.i30 = False
        self.volname: str | None = None
        self.volver: str | None = None

    @property
    def in_use(self) -> bool:
        return bool(self.flags & REC_IN_USE)

    @property
    def is_dir(self) -> bool:
        return bool(self.flags & REC_DIRECTORY) or self.i30


def parse_record(buf: bytearray, size: int, num: int = -1) -> _Rec | None:
    """Parse one MFT record (BUF is modified: fixups are applied). None if it isn't a FILE record."""
    if len(buf) < size or size < 256 or buf[:4] != b"FILE":
        return None
    fix = apply_fixups(buf, size)
    if fix < 0:
        return None
    (_sig, _uo, _uc, _lsn, seq, _links, aofs, flags, used, _alloc, base, _nid, _pad,
     recnum) = _HDR.unpack_from(buf, 0)
    if aofs < 0x28 or aofs >= size or aofs & 7:
        return None
    end = used if aofs < used <= size else size
    r = _Rec(num if num >= 0 else recnum, seq, flags, base, fix > 0)
    pos = aofs
    for _ in range(MAX_ATTRS):
        if pos + 8 > end:
            break
        atype, alen = struct.unpack_from("<II", buf, pos)
        if atype == AT_END:
            break
        if alen < 16 or pos + alen > end or alen & 7:
            r.damaged = True
            break
        _t, _l, nonres, nlen, noff, aflags, aid = _ATTR.unpack_from(buf, pos)
        name = ""
        if nlen:
            if noff + 2 * nlen > alen:
                r.damaged = True
                pos += alen
                continue
            name = _utf16(buf[pos + noff:pos + noff + 2 * nlen])
        if atype not in _WANTED:
            pos += alen
            continue
        if not nonres:
            if alen < 24:
                r.damaged = True
                pos += alen
                continue
            vlen, voff = _RESIDENT.unpack_from(buf, pos + 16)
            if voff + vlen > alen:
                r.damaged = True
                pos += alen
                continue
            value = bytes(buf[pos + voff:pos + voff + vlen])
            _resident_attr(r, atype, name, aflags, aid, value)
        else:
            if alen < 0x40:
                r.damaged = True
                pos += alen
                continue
            vcn, last, roff, cu, alloc, dsize, init = _NONRES.unpack_from(buf, pos + 16)
            if atype in (AT_DATA, AT_ATTRIBUTE_LIST, AT_REPARSE_POINT) and roff < alen:
                p = _Piece(name, aflags, aid)
                p.vcn, p.last, p.cu = vcn, last, cu
                p.alloc, p.size, p.init = alloc, dsize, init
                p.runs, p.ok = decode_runs(buf, pos + roff, pos + alen)
                if atype == AT_DATA:
                    r.data.append(p)
                elif atype == AT_ATTRIBUTE_LIST:
                    r.alist = p
                else:
                    r.reparse = p
        pos += alen
    return r


_WANTED = frozenset((AT_STANDARD_INFORMATION, AT_ATTRIBUTE_LIST, AT_FILE_NAME, AT_VOLUME_NAME,
                     AT_VOLUME_INFORMATION, AT_DATA, AT_INDEX_ROOT, AT_REPARSE_POINT))


def _resident_attr(r: _Rec, atype: int, name: str, aflags: int, aid: int, value: bytes) -> None:
    if atype == AT_STANDARD_INFORMATION:
        if len(value) >= 36:
            r.si = _STD_INFO.unpack_from(value, 0)
    elif atype == AT_FILE_NAME:
        if len(value) >= 0x42:
            fn = _FILE_NAME.unpack_from(value, 0)
            nlen = fn[9]
            if nlen and 0x42 + 2 * nlen <= len(value):
                parent = fn[0]
                r.names.append((parent & REF_MASK, parent >> 48, fn[10], _utf16(value[0x42:0x42 + 2 * nlen]),
                                fn[1:5], fn[7]))
    elif atype == AT_DATA:
        p = _Piece(name, aflags, aid)
        p.value = value
        p.size = p.init = p.alloc = len(value)
        r.data.append(p)
    elif atype == AT_INDEX_ROOT:
        if name == "$I30":
            r.i30 = True
    elif atype == AT_ATTRIBUTE_LIST:
        p = _Piece(name, aflags, aid)
        p.value = value
        r.alist = p
    elif atype == AT_REPARSE_POINT:
        p = _Piece(name, aflags, aid)
        p.value = value
        r.reparse = p
    elif atype == AT_VOLUME_NAME:
        r.volname = _utf16(value).rstrip("\0")
    elif atype == AT_VOLUME_INFORMATION:
        if len(value) >= 10:
            r.volver = f"{value[8]}.{value[9]}"


def parse_attribute_list(v: bytes) -> list[tuple[int, str, int, int, int, int]]:
    """$ATTRIBUTE_LIST → [(type, name, first VCN, record, record sequence, attribute id)]."""
    out = []
    pos = 0
    while pos + _ALIST.size <= len(v) and len(out) < 1 << 20:
        atype, elen, nlen, noff, vcn, ref, aid = _ALIST.unpack_from(v, pos)
        if elen < _ALIST.size or pos + elen > len(v) or atype == 0:
            break
        name = _utf16(v[pos + noff:pos + noff + 2 * nlen]) if nlen and noff + 2 * nlen <= elen else ""
        out.append((atype, name, vcn, ref & REF_MASK, ref >> 48, aid))
        pos += elen
    return out


# ---------------------------------------------------------------------- LZNT1 (NTFS compression)
SUB_BLOCK = 4096


def _lznt1_block(src: bytes, pos: int, end: int) -> bytearray:
    """Decompress one LZNT1 chunk (the bytes between its header and END) into at most 4 KiB."""
    out = bytearray()
    while pos < end:
        tag = src[pos]
        pos += 1
        if tag == 0 and pos + 8 <= end:      # eight plain bytes: the common case in text
            out += src[pos:pos + 8]
            pos += 8
            if len(out) > SUB_BLOCK:
                break
            continue
        for bit in range(8):
            if pos >= end:
                break
            if not (tag >> bit) & 1:
                out.append(src[pos])
                pos += 1
                continue
            if pos + 1 >= end:
                return out
            pt = src[pos] | (src[pos + 1] << 8)
            pos += 2
            n = len(out)
            if n == 0 or n >= SUB_BLOCK:
                return out                   # a back-reference before any data, or past the chunk: damaged
            # the split between offset and length bits moves as the position in the chunk grows
            lg = max(0, (n - 1).bit_length() - 4)
            back = (pt >> (12 - lg)) + 1
            length = (pt & (0xFFF >> lg)) + 3
            if back > n:
                return out
            start = n - back
            if back >= length:
                out += out[start:start + length]
            else:                            # overlapping copy: the pattern repeats
                pat = bytes(out[start:])
                out += (pat * (length // back + 1))[:length]
        if len(out) > SUB_BLOCK:
            break
    return out


def lznt1_decompress(data: bytes, out_size: int) -> bytes:
    """Decompress LZNT1 data (MS-XCA 2.5) as NTFS stores it in a compression unit, into exactly OUT_SIZE bytes.

    The data is a series of chunks, each with a 2-byte header (bits 0-11: chunk size - 3, bit 15: compressed)
    and each standing for 4 KiB of output: a chunk that decodes to less is padded with zeros (as Windows and
    ntfs-3g read it); a zero header or the end of the data ends the unit, the rest of which reads as zeros."""
    data = bytes(data)
    out = bytearray()
    pos = 0
    n = len(data)
    while pos + 2 <= n and len(out) < out_size:
        h = data[pos] | (data[pos + 1] << 8)
        if h == 0:
            break
        end = min(n, pos + 3 + (h & 0x0FFF))
        if h & 0x8000:
            block = _lznt1_block(data, pos + 2, end)
        else:
            block = bytearray(data[pos + 2:end])
        if len(block) < SUB_BLOCK:
            block += bytes(SUB_BLOCK - len(block))
        out += block[:SUB_BLOCK]
        pos = end
    if len(out) < out_size:
        out += bytes(out_size - len(out))
    return bytes(out[:out_size])


def _entry_field(entry, name, default=None):
    if isinstance(entry, dict):
        return entry.get(name, default)
    return getattr(entry, name, default)


class _RunMap:
    """A run list ((byte offset or -1 for a hole, length) pieces, in file order) with an index, to read any
    part of the file without walking every run before it."""

    def __init__(self, runs):
        self.runs = [(int(o), int(n)) for o, n in runs or [] if int(n) > 0]
        self.starts: list[int] = []
        pos = 0
        for _o, n in self.runs:
            self.starts.append(pos)
            pos += n
        self.end = pos

    def pieces(self, start: int, length: int) -> Iterator[tuple[int, int]]:
        """(offset or -1, length) pieces covering [start, start+length) as far as the runs go."""
        i = max(0, bisect.bisect_right(self.starts, start) - 1)
        end = start + length
        while i < len(self.runs) and start < end:
            off, n = self.runs[i]
            rel = start - self.starts[i]
            take = min(n - rel, end - start)
            if take > 0:
                yield (off + rel if off >= 0 else -1), take
                start += take
            i += 1

    def read(self, src: Source, start: int, length: int) -> bytes:
        """[start, start+length): holes and anything past the runs read as zeros."""
        out = bytearray()
        for off, n in self.pieces(start, length):
            out += bytes(n) if off < 0 else src.read(off, n)
        if len(out) < length:
            out += bytes(length - len(out))
        return bytes(out)


def _decode_lznt1(src: Source, entry) -> Iterator[bytes]:
    """read_content() decoder for NTFS-compressed streams, one compression unit at a time.

    A unit (usually 16 clusters) whose runs are all allocated is stored as is; one that is entirely sparse is
    zeros; one with some clusters and a sparse tail holds LZNT1 data in its allocated clusters."""
    extra = _entry_field(entry, "extra") or {}
    size = int(_entry_field(entry, "size") or 0)
    cs = int(extra.get("cluster") or 4096)
    cub = cs * int(extra.get("cu") or 16)
    init = int(extra.get("init", size))
    rmap = _RunMap(extra.get("vruns"))
    pos = 0
    pending = bytearray()
    while pos < size:
        raw = bytearray()
        sparse = 0
        for off, n in rmap.pieces(pos, cub):
            if off < 0:
                sparse += n
            else:
                raw += src.read(off, n)
        if not raw:
            unit = bytes(cub)
        elif sparse == 0 and len(raw) == cub:
            unit = bytes(raw)
        else:
            unit = lznt1_decompress(raw, cub)
        take = min(cub, size - pos)
        piece = unit[:take]
        if pos + take > init:                # past the initialized size the stream reads as zeros
            keep = max(0, init - pos)
            piece = piece[:keep] + bytes(take - keep)
        pending += piece
        pos += take
        if len(pending) >= 1 << 20:
            yield bytes(pending)
            pending = bytearray()
    if pending:
        yield bytes(pending)


register_decoder("lznt1", _decode_lznt1)
register_decoder("ntfs-lznt1", _decode_lznt1)


# ---------------------------------------------------------------------- XPRESS Huffman (Windows file compression)
def _huffman_table(lengths: list[int]) -> tuple[list[int], int] | None:
    """A lookup table for a canonical Huffman code (codes assigned by length, then symbol): indexed by the next
    MAXLEN bits, each slot holds (symbol << 5) | code length. None when the code is empty or over-subscribed."""
    order = sorted((ln, sym) for sym, ln in enumerate(lengths) if ln)
    if not order:
        return None
    maxlen = order[-1][0]
    table = [0] * (1 << maxlen)
    code = 0
    prev = order[0][0]
    for ln, sym in order:
        code <<= ln - prev
        prev = ln
        span = 1 << (maxlen - ln)
        start = code * span
        if start + span > len(table):
            return None
        table[start:start + span] = [(sym << 5) | ln] * span
        code += 1
    return table, maxlen


def xpress_huffman_decompress(data: bytes, out_size: int) -> bytes:
    """Decompress XPRESS Huffman data (MS-XCA 2.2), as Windows' file compression (WOF: XPRESS4K/8K/16K) uses it.

    Each 64 KiB of output starts with a 256-byte table of 512 4-bit code lengths; the bit stream is read in
    16-bit little-endian words, most significant bit first. Symbols 0-255 are literals; 256-511 are matches
    (low 4 bits: length - 3, longer lengths follow as plain bytes; high 4 bits: number of offset bits).
    Damaged data gives zeros for what can't be decoded instead of an error."""
    data = bytes(data)
    n = len(data)
    out = bytearray()
    pos = 0
    while len(out) < out_size and pos + 260 <= n:
        lengths = []
        for b in data[pos:pos + 256]:
            lengths.append(b & 15)
            lengths.append(b >> 4)
        made = _huffman_table(lengths)
        if made is None:
            break
        table, maxlen = made
        pos += 256
        block_end = min(out_size, len(out) + 65536)
        bits = (data[pos] | data[pos + 1] << 8) << 16 | (data[pos + 2] | data[pos + 3] << 8)
        avail = 32                           # valid bits in BITS (the next ones are the most significant)
        pos += 4
        while len(out) < block_end:
            slot = table[(bits >> (avail - maxlen)) & ((1 << maxlen) - 1)]
            ln = slot & 31
            if ln == 0:
                break                        # a code that isn't in the table: damaged
            avail -= ln
            bits &= (1 << avail) - 1
            if avail < 16:
                bits = (bits << 16) | ((data[pos] | data[pos + 1] << 8) if pos + 1 < n else 0)
                avail += 16
                pos += 2
            sym = slot >> 5
            if sym < 256:
                out.append(sym)
                continue
            sym -= 256
            length = sym & 15
            obits = sym >> 4
            if length == 15:
                if pos >= n:
                    break
                length = data[pos]
                pos += 1
                if length == 255:
                    if pos + 1 >= n:
                        break
                    length = data[pos] | data[pos + 1] << 8
                    pos += 2
                    if length == 0 and pos + 3 < n:
                        length = struct.unpack_from("<I", data, pos)[0]
                        pos += 4
                    if length < 15:
                        break
                    length -= 15
                length += 15
            length += 3
            off = 1 << obits
            if obits:
                avail -= obits
                off |= bits >> avail
                bits &= (1 << avail) - 1
                if avail < 16:
                    bits = (bits << 16) | ((data[pos] | data[pos + 1] << 8) if pos + 1 < n else 0)
                    avail += 16
                    pos += 2
            if off > len(out):
                break
            start = len(out) - off
            if off >= length:
                out += out[start:start + length]
            else:                            # overlapping copy: the pattern repeats
                pat = bytes(out[start:])
                out += (pat * (length // off + 1))[:length]
        else:
            # a block ends on a 16-bit unit; the words already loaded but not used belong to the next block
            pos -= (avail // 16) * 2
            continue
        break
    if len(out) < out_size:
        out += bytes(out_size - len(out))
    return bytes(out[:out_size])


class _Bits:
    """Reads a bit stream stored as 16-bit little-endian words, most significant bit first (LZX). At least 16
    bits are always buffered, so a Huffman code (16 bits at most) can be looked up in one go."""

    __slots__ = ("data", "n", "start", "pos", "bits", "avail")

    def __init__(self, data: bytes, pos: int):
        self.data = data
        self.n = len(data)
        self.start = pos
        self.pos = pos
        self.bits = 0
        self.avail = 0
        self._word()
        self._word()

    def _word(self) -> None:
        p = self.pos
        w = (self.data[p] | self.data[p + 1] << 8) if p + 1 < self.n else 0
        self.bits = (self.bits << 16) | w
        self.avail += 16
        self.pos = p + 2

    def read(self, k: int) -> int:
        if k == 0:
            return 0
        self.avail -= k
        v = self.bits >> self.avail
        self.bits &= (1 << self.avail) - 1
        if self.avail < 16:
            self._word()
        return v

    def sym(self, code: tuple[list[int], int]) -> int:
        table, maxlen = code
        slot = table[self.bits >> (self.avail - maxlen) & ((1 << maxlen) - 1)]
        ln = slot & 31
        if ln == 0:
            raise ValueError("bad Huffman code")
        self.read(ln)
        return slot >> 5

    def aligned_pos(self) -> int:
        """The byte position after skipping to the next 16-bit boundary (16 bits when already on one)."""
        consumed = (self.pos - self.start) * 8 - self.avail
        return self.start + (consumed // 16 + 1) * 2


_LZX_EXTRA = [max(0, s // 2 - 1) for s in range(50)]
_LZX_BASE = [0]
for _s in range(49):
    _LZX_BASE.append(_LZX_BASE[-1] + (1 << _LZX_EXTRA[_s]))
del _s
LZX_E8_SIZE = 12000000                       # the "file size" WIM and Windows' file compression use for E8


def _lzx_lens(br: _Bits, lens: list[int], start: int, end: int) -> None:
    """Read code lengths [start, end) as changes to the previous block's, through the 20-symbol pretree."""
    pre = _huffman_table([br.read(4) for _ in range(20)])
    if pre is None:
        raise ValueError("empty pretree")
    i = start
    while i < end:
        p = br.sym(pre)
        if p < 17:
            lens[i] = (lens[i] - p) % 17
            i += 1
            continue
        if p == 17:
            n, v = 4 + br.read(4), 0
        elif p == 18:
            n, v = 20 + br.read(5), 0
        else:
            n = 4 + br.read(1)
            v = (lens[i] - br.sym(pre)) % 17
        n = min(n, end - i)
        lens[i:i + n] = [v] * n
        i += n


def lzx_decompress(data: bytes, out_size: int, window_order: int = 15) -> bytes:
    """Decompress one LZX chunk as WIM files and Windows' file compression (``compact /exe:lzx``) store it:
    a 2**WINDOW_ORDER window, verbatim / aligned-offset / uncompressed blocks, three repeat offsets, and the E8
    call-instruction translation undone at the end. Damaged data gives zeros for what can't be decoded."""
    data = bytes(data)
    nslots = next(i for i in range(len(_LZX_BASE)) if _LZX_BASE[i] >= 1 << window_order)
    nmain = 256 + 8 * nslots
    main_lens = [0] * nmain
    len_lens = [0] * 249
    rec = [1, 1, 1]
    out = bytearray()
    br = _Bits(data, 0)
    try:
        while len(out) < out_size:
            btype = br.read(3)
            if br.read(1):
                bsize = 32768
            else:
                bsize = br.read(16)
                if window_order >= 16:
                    bsize = (bsize << 8) | br.read(8)
            if btype not in (1, 2, 3) or bsize == 0:
                break
            bsize = min(bsize, out_size - len(out))
            if btype == 3:                   # uncompressed: new repeat offsets, then the bytes as they are
                p = br.aligned_pos()
                if p + 12 > len(data):
                    break
                rec = list(struct.unpack_from("<III", data, p))
                p += 12
                out += data[p:p + bsize]
                p += bsize + (bsize & 1)
                br = _Bits(data, p)
                continue
            aligned = None
            if btype == 2:
                aligned = _huffman_table([br.read(3) for _ in range(8)])
            _lzx_lens(br, main_lens, 0, 256)
            _lzx_lens(br, main_lens, 256, nmain)
            _lzx_lens(br, len_lens, 0, 249)
            main = _huffman_table(main_lens)
            lcode = _huffman_table(len_lens)
            if main is None:
                break
            end = len(out) + bsize
            while len(out) < end:
                sym = br.sym(main)
                if sym < 256:
                    out.append(sym)
                    continue
                sym -= 256
                length = sym & 7
                slot = sym >> 3
                if length == 7:
                    if lcode is None:
                        raise ValueError("no length code")
                    length += br.sym(lcode)
                length += 2
                if slot < 3:
                    off = rec[slot]
                    rec[slot] = rec[0]
                else:
                    extra = _LZX_EXTRA[slot]
                    off = _LZX_BASE[slot]
                    if aligned is not None and extra >= 3:
                        off += br.read(extra - 3) << 3
                        off += br.sym(aligned)
                    else:
                        off += br.read(extra)
                    off -= 2
                    rec[2] = rec[1]
                    rec[1] = rec[0]
                rec[0] = off
                if off <= 0 or off > len(out):
                    raise ValueError("match before the start")
                start = len(out) - off
                if off >= length:
                    out += out[start:start + length]
                else:
                    pat = bytes(out[start:])
                    out += (pat * (length // off + 1))[:length]
    except (ValueError, IndexError, StopIteration):
        pass
    del out[out_size:]
    _lzx_undo_e8(out)
    if len(out) < out_size:
        out += bytes(out_size - len(out))
    return bytes(out)


def _lzx_undo_e8(out: bytearray) -> None:
    """LZX compressors turn the relative targets of x86 CALL instructions (E8 xx xx xx xx) into absolute ones
    (they compress better); turn them back."""
    n = len(out)
    if n <= 10:
        return
    i = out.find(0xE8, 0, n - 10)
    while i >= 0:
        v = int.from_bytes(out[i + 1:i + 5], "little", signed=True)
        if 0 <= v < LZX_E8_SIZE:
            out[i + 1:i + 5] = (v - i).to_bytes(4, "little", signed=True)
        elif -i <= v < 0:
            out[i + 1:i + 5] = (v + LZX_E8_SIZE).to_bytes(4, "little", signed=True)
        i = out.find(0xE8, i + 5, n - 10)


def _decode_wof(src: Source, entry) -> Iterator[bytes]:
    """read_content() decoder for files compressed by Windows (WofCompressedData stream, XPRESS or LZX chunks).

    The stream starts with a table of where each compressed chunk starts (counted from the end of the table,
    the first chunk left out; 4-byte entries, 8 for files over 4 GiB), followed by the chunks. A chunk whose
    compressed size equals its plain size is stored as is."""
    extra = _entry_field(entry, "extra") or {}
    size = int(_entry_field(entry, "size") or 0)
    chunk = int(extra.get("chunk") or 4096)
    csize = int(extra.get("csize") or 0)
    lzx = extra.get("decoder") == "lzx"
    if extra.get("cdata") is not None:            # a small stream kept inside the MFT record (hex)
        resident = bytes.fromhex(extra["cdata"])
        csize = len(resident)

        def read(off: int, n: int) -> bytes:
            return resident[off:off + n].ljust(n, b"\0")
    else:
        rmap = _RunMap(extra.get("cruns"))

        def read(off: int, n: int) -> bytes:
            return rmap.read(src, off, n)
    nchunks = (size + chunk - 1) // chunk
    if nchunks == 0:
        return
    esize = 8 if size > 0xFFFFFFFF else 4
    table_len = (nchunks - 1) * esize
    body_len = csize - table_len
    if body_len < 0:
        yield bytes(size)
        return
    table = read(0, table_len)
    starts = [0] + [int.from_bytes(table[i:i + esize], "little") for i in range(0, table_len, esize)] + [body_len]
    pending = bytearray()
    for i in range(nchunks):
        plain = min(chunk, size - i * chunk)
        a, b = starts[i], starts[i + 1]
        if not (0 <= a <= b <= body_len) or b - a > chunk:
            piece = bytes(plain)                  # a damaged table: this chunk can't be found
        elif b - a == plain:
            piece = read(table_len + a, plain)
        elif lzx:
            piece = lzx_decompress(read(table_len + a, b - a), plain, max(15, chunk.bit_length() - 1))
        else:
            piece = xpress_huffman_decompress(read(table_len + a, b - a), plain)
        pending += piece
        if len(pending) >= 1 << 20:
            yield bytes(pending)
            pending = bytearray()
    if pending:
        yield bytes(pending)


register_decoder("xpress", _decode_wof)
register_decoder("lzx", _decode_wof)


# ---------------------------------------------------------------------- the reader
class _Stream:
    """A whole attribute (all its pieces joined): resident bytes or cluster runs from VCN 0."""

    __slots__ = ("size", "alloc", "init", "aflags", "cu", "runs", "data", "partial", "bad")

    def __init__(self):
        self.size = self.alloc = self.init = 0
        self.aflags = 0
        self.cu = 0
        self.runs: list[tuple[int, int]] | None = None   # (LCN or -1, clusters)
        self.data: bytes | None = None
        self.partial = False                 # pieces missing (lost extension record)
        self.bad = False                     # runs pointing outside the volume


def _bit_any(bm: bytes, start: int, n: int) -> bool:
    """Is any of bits [start, start+n) set in BM (LSB first)? Bits past the end count as set."""
    end = start + n
    if n <= 0:
        return False
    if end > len(bm) * 8:
        return True
    b0, b1 = start >> 3, (end - 1) >> 3
    if b0 == b1:
        return bool(bm[b0] & (((1 << n) - 1) << (start & 7)))
    if bm[b0] >> (start & 7):
        return True
    if bm[b1] & ((1 << (((end - 1) & 7) + 1)) - 1):
        return True
    return b1 - b0 > 1 and bm.count(0, b0 + 1, b1) != b1 - b0 - 1


def _zero_bit_runs_table() -> list[list[tuple[int, int]]]:
    table = []
    for v in range(256):
        runs = []
        i = 0
        while i < 8:
            if not (v >> i) & 1:
                j = i
                while j < 8 and not (v >> j) & 1:
                    j += 1
                runs.append((i, j - i))
                i = j
            else:
                i += 1
        table.append(runs)
    return table


_ZRUNS = _zero_bit_runs_table()
_BYTE_RUNS = re.compile(rb"\x00+|\xff+|[^\x00\xff]+")


def bitmap_free_runs(bm: bytes, nbits: int) -> list[tuple[int, int]]:
    """(first bit, count) of every run of clear bits among the first NBITS bits of BM."""
    out: list[tuple[int, int]] = []
    cur_s = cur_e = -1

    def add(s: int, e: int) -> None:
        nonlocal cur_s, cur_e
        if s == cur_e:
            cur_e = e
            return
        if cur_e > cur_s >= 0:
            out.append((cur_s, cur_e - cur_s))
        cur_s, cur_e = s, e

    nbytes = min(len(bm), (nbits + 7) // 8)
    for m in _BYTE_RUNS.finditer(bm, 0, nbytes):
        a, b = m.span()
        first = bm[a]
        if first == 0:
            add(a * 8, b * 8)
        elif first == 0xFF:
            continue
        else:
            for i in range(a, b):
                base = i * 8
                for s, n in _ZRUNS[bm[i]]:
                    add(base + s, base + s + n)
    if cur_e > cur_s >= 0:
        out.append((cur_s, cur_e - cur_s))
    # clip to NBITS
    clipped = []
    for s, n in out:
        if s >= nbits:
            break
        clipped.append((s, min(n, nbits - s)))
    return clipped


class NtfsReader(FsReader):
    """Reads an NTFS volume through its MFT: every file and folder, deleted ones included."""

    fstype = "ntfs"
    name = "NTFS"
    root_key = ROOT
    deleted_support = True

    def __init__(self, src: Source, info: dict | None = None):
        info = dict(info or {})
        if not info.get("reconstructed") and "mft_offset" not in info:
            probed = self.probe(src)
            if probed is None:
                raise FormatError("This isn't an NTFS volume (no valid boot sector)")
            probed.update(info)
            info = probed
        super().__init__(src, info)
        self.cs = int(info.get("cluster_size") or info.get("block_size") or 4096)
        self.rs = int(info.get("record_size") or 1024)
        if not (512 <= self.cs <= MAX_CLUSTER and _power_of_two(self.cs)):
            raise FormatError(f"Implausible NTFS cluster size {self.cs}")
        if not (256 <= self.rs <= 65536 and _power_of_two(self.rs)):
            raise FormatError(f"Implausible NTFS record size {self.rs}")
        self.block_size = self.cs
        self.mft_offset = int(info.get("mft_offset") or 0)
        mirr = info.get("mftmirr_offset")
        self.mirr_offset = int(mirr) if mirr is not None else None
        size = int(info.get("size") or src.size)
        self.size = size
        self.clusters = int(info.get("clusters") or size // self.cs)
        self.meta = CachedSource(src, block=64 * 1024, blocks=256)
        self._mft_runs: list[tuple[int, int]] | None = None
        self._mft_starts: list[int] = []
        self._nrec = 0
        self._bitmap: bytes | None = None
        self._bitmap_loaded = False

    # ------------------------------------------------------------------ probing
    @classmethod
    def probe(cls, src: Source) -> dict | None:
        boot = parse_boot(src.read(0, 512))
        where = "primary"
        if boot is None:
            boot = cls._find_backup(src)
            where = "backup"
        if boot is None:
            return None
        info = {"fstype": "ntfs", "label": "", "uuid": boot["uuid"], "size": boot["size"],
                "block_size": boot["cluster_size"], "boot": where}
        info.update(boot)
        try:
            cls._probe_volume(src, info)
        except Exception:  # noqa: BLE001 - the label and usage are extras: a damaged MFT mustn't fail the probe
            pass
        return info

    @staticmethod
    def _find_backup(src: Source) -> dict | None:
        """The backup boot sector sits in the volume's last sector: look in the last 8 KiB of SRC."""
        if src.size < 1024:
            return None
        span = min(8192, src.size)
        tail = src.read(src.size - span, span)
        for k in range(span - 512, -1, -512):
            if tail[k + 3:k + 11] != b"NTFS    ":
                continue
            boot = parse_boot(tail[k:k + 512])
            if boot is not None:
                return boot
        return None

    @staticmethod
    def _probe_volume(src: Source, info: dict) -> None:
        """Label and version from $Volume, used space from $Bitmap (when it is small enough to read quickly)."""
        rs = info["record_size"]
        base = info["mft_offset"]
        r = parse_record(bytearray(src.read(base + 3 * rs, rs)), rs, 3)
        if r is not None:
            if r.volname:
                info["label"] = r.volname
            if r.volver:
                info["version"] = r.volver
        r = parse_record(bytearray(src.read(base + 6 * rs, rs)), rs, 6)
        if r is None:
            return
        cs = info["cluster_size"]
        clusters = info["clusters"]
        need = (clusters + 7) // 8
        if need > 16 * 1024 * 1024:
            return
        pieces = [p for p in r.data if not p.name]
        if not pieces:
            return
        p = pieces[0]
        if p.value is not None:
            bm = p.value[:need]
        elif p.runs:
            byte_runs = [(lcn * cs if lcn >= 0 else -1, n * cs) for lcn, n in p.runs]
            bm = b"".join(read_content(src, {"size": need, "runs": byte_runs}))
        else:
            return
        used = int.from_bytes(bm[:clusters // 8], "little").bit_count()
        if clusters % 8 and len(bm) > clusters // 8:
            used += (bm[clusters // 8] & ((1 << (clusters % 8)) - 1)).bit_count()
        info["used"] = used * cs
        info["free"] = max(0, (clusters - used) * cs)

    # ------------------------------------------------------------------ the MFT
    def _set_mft_runs(self, byte_runs: list[tuple[int, int]], size: int) -> None:
        self._mft_runs = byte_runs
        self._mft_starts = []
        pos = 0
        for _off, n in byte_runs:
            self._mft_starts.append(pos)
            pos += n
        # the MFT can't be bigger than the volume (a damaged record 0 could claim anything)
        self._nrec = min(size, pos, max(self.clusters * self.cs, self.src.size), MAX_RECORDS * self.rs) // self.rs

    def _mft_read(self, vpos: int, length: int, src: Source | None = None) -> bytes:
        """LENGTH bytes at VPOS inside the MFT file (through its runs)."""
        src = src or self.meta
        out = bytearray()
        runs = self._mft_runs or []
        i = bisect.bisect_right(self._mft_starts, vpos) - 1
        while length > 0 and 0 <= i < len(runs):
            off, n = runs[i]
            rel = vpos - self._mft_starts[i]
            take = min(n - rel, length)
            if take <= 0:
                i += 1
                continue
            out += bytes(take) if off < 0 else src.read(off + rel, take)
            vpos += take
            length -= take
            i += 1
        if length > 0:
            out += bytes(length)
        return bytes(out)

    def record(self, num: int) -> _Rec | None:
        """MFT record NUM, parsed (None if it is out of range or not a FILE record)."""
        self._load_mft()
        if num < 0 or num >= self._nrec:
            return None
        return parse_record(bytearray(self._mft_read(num * self.rs, self.rs)), self.rs, num)

    def record_offset(self, num: int) -> int | None:
        """Where MFT record NUM starts in the volume (None when it is out of range or split between pieces)."""
        self._load_mft()
        if num < 0 or num >= self._nrec or not self._mft_runs:
            return None
        vpos = num * self.rs
        i = bisect.bisect_right(self._mft_starts, vpos) - 1
        off, n = self._mft_runs[i]
        rel = vpos - self._mft_starts[i]
        if off < 0 or rel + self.rs > n:
            return None
        return off + rel

    def _load_mft(self) -> None:
        """Where the MFT's pieces are: from record 0's $DATA (and its extension records when the MFT is so
        fragmented that it needs an attribute list), else from the $MFTMirr copy, else a guess."""
        if self._mft_runs is not None:
            return
        self._mft_runs = []                  # (record() below must not come back here)
        rs = self.rs
        rec0 = None
        for where, off in (("MFT", self.mft_offset), ("MFT mirror", self.mirr_offset)):
            if off is None or off < 0 or off + rs > self.src.size:
                continue
            r = parse_record(bytearray(self.meta.read(off, rs)), rs, 0)
            if r is None:
                continue
            pieces = [p for p in r.data if not p.name and p.runs]
            if any(p.vcn == 0 and p.size >= 16 * rs for p in pieces):
                rec0 = r
                if where != "MFT":
                    self.warn("The MFT's first record is damaged: its location was read from the $MFTMirr copy")
                break
        if rec0 is None:
            self._guess_mft()
            return
        pieces = [p for p in rec0.data if not p.name and p.runs is not None]
        self._apply_mft_pieces(pieces)
        if rec0.alist is not None:
            # extension records hold more of $MFT's $DATA; each found piece can reveal where the next ones are
            wanted = sorted({ref for t, name, _v, ref, _s, _a in self._alist_entries(rec0.alist)
                             if t == AT_DATA and not name and ref})
            done: set[int] = set()
            for _ in range(8):
                progress = False
                for ref in wanted:
                    if ref in done or ref >= self._nrec:
                        continue
                    x = self.record(ref)
                    done.add(ref)
                    if x is None or x.base & REF_MASK != 0:
                        continue
                    more = [p for p in x.data if not p.name and p.runs is not None]
                    if more:
                        pieces.extend(more)
                        self._apply_mft_pieces(pieces)
                        progress = True
                if not progress:
                    break
        st = self._join(pieces)
        if st is not None and st.partial:
            self.warn("Part of the MFT's map is missing: some files may not be listed")

    def _apply_mft_pieces(self, pieces: list[_Piece]) -> None:
        st = self._join(pieces)
        if st is None or not st.runs:
            return
        byte_runs = self._byte_runs(st.runs, st.size, st.size)
        self._set_mft_runs(byte_runs, st.size)

    def _guess_mft(self) -> None:
        """No usable record 0: assume the MFT is one piece starting at mft_offset and ends where the FILE
        records stop."""
        self.warn("The MFT's own record is damaged: assuming the MFT is in one piece")
        rs = self.rs
        pos = self.mft_offset
        end = self.src.size
        step = 1024 * 1024
        last = pos
        while pos < end:
            n = min(step, end - pos)
            buf = self.src.read(pos, n)
            found = [m.start() for m in re.finditer(b"FILE", buf) if m.start() % rs == 0]
            if not found:
                break
            last = pos + found[-1] + rs
            if found[-1] < n - 64 * rs:
                break
            pos += n
        self._set_mft_runs([(self.mft_offset, max(rs * 16, last - self.mft_offset))],
                           max(rs * 16, last - self.mft_offset))

    def _alist_entries(self, p: _Piece) -> list[tuple[int, str, int, int, int, int]]:
        if p.value is not None:
            return parse_attribute_list(p.value)
        if not p.runs or p.vcn != 0:
            return []
        size = min(p.size, MAX_ALIST)
        runs = self._byte_runs(p.runs, size, min(p.init, size))
        return parse_attribute_list(b"".join(read_content(self.meta, {"size": size, "runs": runs})))

    # ------------------------------------------------------------------ $Bitmap
    def _load_bitmap(self) -> bytes | None:
        if self._bitmap_loaded:
            return self._bitmap
        self._bitmap_loaded = True
        r = self.record(6)
        st = self._join([p for p in r.data if not p.name]) if r is not None else None
        need = (self.clusters + 7) // 8
        if st is None or (st.data is None and not st.runs) or need > BITMAP_CAP:
            self.warn("The cluster bitmap ($Bitmap) can't be read: chances of deleted files are estimates")
            return None
        if st.data is not None:
            bm = st.data[:need]
        else:
            n = min(st.size, need)
            bm = b"".join(read_content(self.src, {"size": n, "runs": self._byte_runs(st.runs, n, n)}))
        if len(bm) < need:
            bm += b"\xff" * (need - len(bm))
        self._bitmap = bm
        return bm

    def free_extents(self, ctl: Control = NULL_CONTROL) -> list[tuple[int, int]] | None:
        self._load_mft()
        bm = self._load_bitmap()
        if bm is None:
            return None
        cs = self.cs
        return [(s * cs, n * cs) for s, n in bitmap_free_runs(bm, self.clusters)]

    def _allocated(self, runs: list[tuple[int, int]]) -> bool | None:
        """Are any of these cluster runs in use now? None when the bitmap is unknown."""
        bm = self._load_bitmap()
        if bm is None:
            return None
        return any(lcn >= 0 and _bit_any(bm, lcn, n) for lcn, n in runs)

    # ------------------------------------------------------------------ attributes → content
    def _join(self, pieces: list[_Piece]) -> _Stream | None:
        """Join the pieces of one attribute (several when the file has an attribute list) into a _Stream."""
        if not pieces:
            return None
        st = _Stream()
        res = [p for p in pieces if p.value is not None]
        if res:
            p = res[0]
            st.data = p.value
            st.size = st.init = st.alloc = len(p.value)
            st.aflags = p.flags
            return st
        ps = sorted((p for p in pieces if p.runs is not None), key=lambda p: p.vcn)
        if not ps:
            return None
        first = ps[0]
        cs = self.cs
        runs: list[tuple[int, int]] = []
        nxt = 0
        seen_vcn = set()
        for p in ps:
            if p.vcn in seen_vcn or p.vcn < nxt:
                continue
            seen_vcn.add(p.vcn)
            if p.vcn > nxt:
                runs.append((-1, p.vcn - nxt))
                st.partial = True
                nxt = p.vcn
            for lcn, n in p.runs:
                if lcn >= 0 and lcn + n > self.clusters:
                    st.bad = True
                    lcn = -1
                runs.append((lcn, n))
                nxt += n
            if not p.ok:
                st.partial = True
        if first.vcn == 0:
            st.size, st.alloc, st.init = first.size, first.alloc, first.init
            st.aflags, st.cu = first.flags, first.cu
        else:                                 # the first piece is lost: sizes are unknown
            st.partial = True
            st.size = st.alloc = st.init = nxt * cs
            st.aflags, st.cu = first.flags, first.cu
        if st.size > st.alloc or st.size > MAX_FILE:
            # a size bigger than the space set aside for it: the record is damaged; keep what the runs cover
            st.size = min(nxt * cs, st.alloc, MAX_FILE)
            st.partial = True
        if st.init > st.size:
            st.init = st.size
        if nxt * cs < min(st.alloc, st.size):
            st.partial = True
        st.runs = runs
        return st

    def _byte_runs(self, runs: list[tuple[int, int]], size: int, init: int) -> list[tuple[int, int]]:
        """Cluster runs → (byte offset or -1, length) pieces covering SIZE bytes; past INIT reads as zeros."""
        cs = self.cs
        out: list[tuple[int, int]] = []
        v = 0
        for lcn, n in runs:
            if v >= size:
                break
            length = min(n * cs, size - v)
            if lcn < 0 or v >= init:
                out.append((-1, length))
            elif v + length <= init:
                out.append((lcn * cs, length))
            else:
                k = init - v
                out.append((lcn * cs, k))
                out.append((-1, length - k))
            v += length
        if v < size:
            out.append((-1, size - v))
        return merge_runs(out)

    def _fill(self, e: Entry, st: _Stream | None, deleted: bool, damaged: bool) -> None:
        """Set an entry's content (size, runs or data, flags, chance) from a joined $DATA stream."""
        if st is None:
            e.size = 0
            e.data = b""
            e.chance = CHANCE_GOOD
            return
        e.size = st.size
        if st.data is not None:
            e.data = st.data[:st.size]
            e.flags |= F_RESIDENT
            e.chance = CHANCE_GOOD
        else:
            runs = st.runs or []
            if st.aflags & ATTR_ENCRYPTED:
                e.flags |= F_ENCRYPTED
            compressed = bool(st.aflags & ATTR_COMPRESSION_MASK and st.cu)
            if compressed and (st.cu > 8 or self.cs << st.cu > MAX_UNIT):
                compressed = False           # an impossible compression unit: a damaged attribute
                st.partial = True
            if st.aflags & ATTR_SPARSE or (not compressed and any(lcn < 0 for lcn, _n in runs)):
                e.flags |= F_SPARSE
            if compressed:
                cs = self.cs
                e.flags |= F_COMPRESSED
                vruns = [[lcn * cs if lcn >= 0 else -1, n * cs] for lcn, n in runs]
                e.extra = {"decoder": "lznt1", "cluster": cs, "cu": 1 << st.cu, "vruns": vruns, "init": st.init}
                e.runs = merge_runs([(o, n) for o, n in vruns])
            else:
                e.runs = self._byte_runs(runs, st.size, st.init)
            e.chance = CHANCE_GOOD
            if deleted:
                used = self._allocated(runs)
                if used is None:
                    e.chance = CHANCE_FAIR
                elif used:
                    e.chance = CHANCE_POOR
        if st.partial or st.bad:
            e.flags |= F_PARTIAL
            e.chance = min(e.chance, CHANCE_POOR if deleted else CHANCE_FAIR)
        if damaged:
            e.chance = min(e.chance, CHANCE_FAIR)

    def _reparse(self, r: _Rec) -> tuple[int, bytes] | None:
        p = r.reparse
        if p is None:
            return None
        if p.value is not None:
            v = p.value
        elif p.runs and p.vcn == 0:
            n = min(p.size, MAX_REPARSE)
            v = b"".join(read_content(self.meta, {"size": n, "runs": self._byte_runs(p.runs, n, n)}))
        else:
            return None
        if len(v) < 8:
            return None
        tag, dlen = struct.unpack_from("<IH", v, 0)
        return tag, v[8:8 + dlen]

    @staticmethod
    def _link_target(tag: int, d: bytes) -> str | None:
        """The target of a symlink, junction or WSL symlink reparse point."""
        try:
            if tag in (IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT):
                so, sl, po, pl = struct.unpack_from("<HHHH", d, 0)
                base = 12 if tag == IO_REPARSE_TAG_SYMLINK else 8
                relative = tag == IO_REPARSE_TAG_SYMLINK and struct.unpack_from("<I", d, 8)[0] & 1
                printed = _utf16(d[base + po:base + po + pl]) if pl else ""
                subst = _utf16(d[base + so:base + so + sl]) if sl else ""
                target = printed or (subst[4:] if subst.startswith("\\??\\") else subst)
                if relative:
                    target = target.replace("\\", "/")
                return target or None
            if tag == IO_REPARSE_TAG_LX_SYMLINK and len(d) >= 4:
                return d[4:].decode("utf-8", "replace") or None
        except struct.error:
            return None
        return None

    # ------------------------------------------------------------------ listing
    def _times(self, r: _Rec) -> tuple:
        if r.si is not None:
            cr, m, c, a, dos = r.si
            return filetime(cr), filetime(m), filetime(c), filetime(a), dos
        if r.names:
            cr, m, c, a = r.names[0][4]
            return filetime(cr), filetime(m), filetime(c), filetime(a), r.names[0][5]
        return None, None, None, None, 0

    @staticmethod
    def _pick_names(names: list[tuple]) -> list[tuple[int, int, str]]:
        """The file's distinct names (one per hard link), best namespace first; DOS 8.3 aliases are dropped
        when a long name exists."""
        cand = [n for n in names if n[2] != 2] or list(names)
        cand.sort(key=lambda n: _NS_RANK.get(n[2], 9))
        out = []
        seen = set()
        for pref, pseq, _ns, name, _t, _f in cand:
            if not name or (pref, name) in seen:
                continue
            seen.add((pref, name))
            out.append((pref, pseq, name))
        return out

    def _root_entry(self) -> Entry:
        e = Entry(key=ROOT, parent=None, name="", is_dir=True, chance=CHANCE_GOOD)
        r = self.record(ROOT)
        if r is not None:
            e.crtime, e.mtime, e.ctime, e.atime, _dos = self._times(r)
        else:
            self.warn("The root folder's record is damaged")
        return e

    def _emit(self, r: _Rec, out: list[Entry], refs: list[tuple[int, int]]) -> None:
        """Entries for one file record: the file (or folder), its other hard links, its named streams."""
        num = r.num
        deleted = not r.in_use
        is_dir = r.is_dir
        crtime, mtime, ctime, atime, dos = self._times(r)
        flags = F_SYSTEM if num < FIRST_USER_RECORD else 0
        names = self._pick_names(r.names)
        groups: dict[str, list[_Piece]] = {}
        for p in r.data:
            groups.setdefault(p.name, []).append(p)
        main = self._join(groups.pop("", []))
        streams = {k: self._join(v) for k, v in groups.items()}
        if not names:
            # no name left (lost with an extension record): still worth listing if it has content
            if is_dir or main is None or main.size == 0:
                return
            names = [(-1, 0, f"MFT record {num}")]
        e = Entry(key=num, parent=None, name=names[0][2], is_dir=is_dir, deleted=deleted, mtime=mtime,
                  ctime=ctime, atime=atime, crtime=crtime, flags=flags)
        rp = self._reparse(r)
        tag = rp[0] if rp else 0
        target = self._link_target(tag, rp[1]) if rp else None
        if is_dir and target is None:
            e.chance = CHANCE_GOOD
        elif target is not None:
            e.is_dir = False
            e.flags |= F_SYMLINK
            e.data = target.encode("utf-8", "replace")
            e.size = len(e.data)
            e.chance = CHANCE_GOOD
            e.extra = {"reparse": tag, "target": target, "dir": is_dir}
        elif tag == IO_REPARSE_TAG_WOF and "WofCompressedData" in streams:
            self._fill_wof(e, main, streams.pop("WofCompressedData"), rp[1], deleted, r.damaged)
        else:
            self._fill(e, main, deleted, r.damaged)
            if dos & DOS_ENCRYPTED:
                e.flags |= F_ENCRYPTED
            if dos & DOS_SYSTEM and e.data is not None and e.data.startswith(b"IntxLNK\x01"):
                # a symlink made by ntfs-3g (Interix style): a system file holding the target in UTF-16
                target = _utf16(e.data[8:]).rstrip("\0")
                e.data = target.encode("utf-8", "replace")
                e.size = len(e.data)
                e.flags = (e.flags | F_SYMLINK) & ~F_RESIDENT
                e.extra = {"target": target, "interix": True}
            if tag == IO_REPARSE_TAG_DEDUP:
                e.flags |= F_PARTIAL
                e.chance = min(e.chance, CHANCE_POOR)
                e.extra = {"reparse": tag, "note": "deduplicated by Windows Server: the content is in the "
                           "volume's chunk store"}
        out.append(e)
        refs.append(names[0][:2])
        for i, (pref, pseq, name) in enumerate(names[1:], 1):
            out.append(dataclasses.replace(e, key=f"{num}#{i}", name=name, flags=e.flags | F_HARDLINK))
            refs.append((pref, pseq))
        for sname, st in streams.items():
            if not sname:
                continue
            a = Entry(key=f"{num}:{sname}", parent=None, name=f"{e.name}:{sname}", deleted=deleted, mtime=mtime,
                      ctime=ctime, atime=atime, crtime=crtime, flags=flags | F_ADS)
            self._fill(a, st, deleted, r.damaged)
            out.append(a)
            refs.append(names[0][:2])

    def _fill_wof(self, e: Entry, main: _Stream | None, comp: _Stream | None, rp: bytes, deleted: bool,
                  damaged: bool) -> None:
        """A file compressed by Windows (compact.exe / WOF): the content is in the WofCompressedData stream."""
        algo = struct.unpack_from("<I", rp, 12)[0] if len(rp) >= 16 else -1
        decoder, chunk = WOF_ALGORITHMS.get(algo, (None, 0))
        probe = Entry(key=0, parent=None, name="")
        self._fill(probe, comp, deleted, damaged)
        e.size = main.size if main is not None else 0
        e.flags |= F_COMPRESSED
        e.chance = probe.chance
        e.runs = probe.runs
        if decoder and comp is not None:
            e.extra = {"decoder": decoder, "chunk": chunk, "csize": comp.size, "cruns": probe.runs,
                       "cdata": probe.data.hex() if probe.data is not None else None}
        else:
            e.extra = {"decoder": None, "note": f"compressed by Windows with an unknown method ({algo}): "
                       "this content can't be decoded here"}
            e.flags |= F_PARTIAL
            e.chance = CHANCE_POOR

    def _with_extensions(self, r: _Rec) -> None:
        """Add the attributes that live in extension records (listed in the record's $ATTRIBUTE_LIST)."""
        wanted: dict[int, set[tuple[int, int]]] = {}
        for atype, _name, _vcn, ref, _rseq, aid in self._alist_entries(r.alist):
            if ref != r.num and atype in (AT_FILE_NAME, AT_DATA, AT_REPARSE_POINT):
                wanted.setdefault(ref, set()).add((atype, aid))
            if len(wanted) > 4096:
                break
        for ref, keys in wanted.items():
            x = self.record(ref)
            if x is None or x.base & REF_MASK != r.num:
                continue                     # lost or reused: _join() notices the missing pieces
            if r.in_use and x.base >> 48 not in (r.seq, 0):
                continue
            for p in x.data:
                if (AT_DATA, p.aid) in keys:
                    r.data.append(p)
            if any(t == AT_FILE_NAME for t, _a in keys):
                r.names.extend(x.names)
            if x.reparse is not None and any(t == AT_REPARSE_POINT for t, _a in keys):
                r.reparse = x.reparse

    def _mirror_record(self, num: int) -> _Rec | None:
        """Records 0-3 from the $MFTMirr copy (used when the MFT's own copy is damaged)."""
        if self.mirr_offset is None or not 0 <= num < 4:
            return None
        off = self.mirr_offset + num * self.rs
        if off + self.rs > self.src.size:
            return None
        return parse_record(bytearray(self.meta.read(off, self.rs)), self.rs, num)

    def entries(self, ctl: Control = NULL_CONTROL, deleted: bool = True) -> Iterator[Entry]:
        self._load_mft()
        if not self._nrec:
            self.warn("The MFT can't be found on this volume: nothing can be listed")
            yield Entry(key=ROOT, parent=None, name="", is_dir=True, chance=CHANCE_GOOD)
            return
        self._load_bitmap()
        yield self._root_entry()
        nrec = self._nrec
        rs = self.rs
        seqs = array("H", bytes(2 * nrec))
        state = bytearray(nrec)              # 1: file record, 2: in use, 4: folder
        out: list[Entry] = []
        refs: list[tuple[int, int]] = []
        later: list[_Rec] = []
        bad = 0
        num = 0
        carry = b""
        total = nrec * rs
        vpos = 0
        for off, length in self._mft_runs or []:
            if off < 0 and not carry and vpos % rs == 0 and length % rs == 0:
                k = min(length, total - vpos) // rs      # a hole in the MFT (damaged map): nothing to read
                num += k
                vpos += k * rs
                continue
            p = 0
            while p < length and vpos < total:
                n = min(BATCH, length - p, total - vpos)
                chunk = bytes(n) if off < 0 else self.src.read(off + p, n)
                p += n
                vpos += n
                buf = carry + chunk if carry else chunk
                view = memoryview(buf)
                usable = len(buf) - len(buf) % rs
                for i in range(0, usable, rs):
                    if num % 512 == 0:
                        ctl.check()
                        if num % 16384 == 0:
                            ctl.progress(num / nrec, "Reading the MFT")
                    cur = num
                    num += 1
                    r = None
                    if buf.startswith(b"FILE", i):
                        try:
                            r = parse_record(bytearray(view[i:i + rs]), rs, cur)
                        except Exception:  # noqa: BLE001 - a damaged record must not stop the listing
                            r = None
                    if r is None and cur < 4:
                        r = self._mirror_record(cur)
                    if r is None:
                        if buf.startswith(b"FILE", i) or buf.startswith(b"BAAD", i):
                            bad += 1
                        continue
                    if r.base:
                        continue             # an extension record: read through its base record's list
                    seqs[cur] = r.seq
                    state[cur] = 1 | (2 if r.in_use else 0) | (4 if r.is_dir else 0)
                    if cur == ROOT or (not r.in_use and not deleted):
                        continue
                    if r.alist is not None:
                        later.append(r)
                        continue
                    try:
                        self._emit(r, out, refs)
                    except Exception as exc:  # noqa: BLE001
                        bad += 1
                        self.warn(f"MFT record {cur} is damaged ({exc.__class__.__name__}); skipped")
                carry = buf[usable:]
        for r in later:
            ctl.check()
            try:
                self._with_extensions(r)
                self._emit(r, out, refs)
            except Exception as exc:  # noqa: BLE001
                self.warn(f"MFT record {r.num} is damaged ({exc.__class__.__name__}); skipped")
        if bad:
            self.warn(f"{bad} damaged MFT records were skipped")
        ctl.progress(1.0, "Reading the MFT")
        self._link(out, refs, seqs, state)
        yield from out

    def _link(self, out: list[Entry], refs: list[tuple[int, int]], seqs: array, state: bytearray) -> None:
        """Turn parent references into parent keys: a reference is good when it points to a folder record whose
        sequence number still matches (a deleted folder's number went up by one when it was freed) and that
        folder is listed. Anything else is an orphan. Also marks $Extend's subtree as system files and breaks
        parent cycles (only possible with corrupted references)."""
        nrec = len(state)
        listed = {e.key for e in out if e.is_dir and isinstance(e.key, int)}
        listed.add(ROOT)
        dir_parent: dict[int, int | None] = {}
        for e, (pref, pseq) in zip(out, refs):
            parent = None
            if pref == ROOT and (nrec <= ROOT or not state[ROOT] & 1):
                parent = ROOT                    # the root's record is damaged, but it is always record 5
            elif 0 <= pref < nrec and state[pref] & 4 and pref != e.key and pref in listed:
                cur = seqs[pref]
                if not pseq or cur == pseq:
                    parent = pref
                elif not state[pref] & 2 and cur == (pseq % 0xFFFF) + 1:
                    parent = pref
            e.parent = parent
            if parent is None:
                e.flags |= F_ORPHAN
            if e.is_dir and isinstance(e.key, int):
                dir_parent[e.key] = parent
        status: dict[int, int] = {ROOT: 1}       # 1: reaches the root, 2: inside $Extend, 3: lost
        for start in dir_parent:
            path: list[int] = []
            seen: set[int] = set()
            k: int | None = start
            result = 3
            while k is not None:
                if k in status:
                    result = status[k]
                    break
                if k in seen:                    # a cycle: cut it where it closes
                    dir_parent[path[-1]] = None
                    break
                seen.add(k)
                path.append(k)
                if k == EXTEND:
                    result = 2
                    break
                k = dir_parent.get(k)
            for p in path:
                status[p] = result
        for e in out:
            if e.is_dir and isinstance(e.key, int) and e.parent is not None and dir_parent.get(e.key, 0) is None:
                e.parent = None
                e.flags |= F_ORPHAN
            if e.parent is not None and status.get(e.parent) == 2:
                e.flags |= F_SYSTEM


# ---------------------------------------------------------------------- deep scan: finding lost MFTs
_REC0 = re.compile(rb"FILE0\x00.{38}\x00\x00\x00\x00", re.S)   # a FILE record whose number (at 0x2C) is 0
_LOOKAHEAD = 16 * 4096                       # records 0-15 follow record 0 in one piece


class MftDetector(Detector):
    """Finds NTFS volumes from their MFT when the boot sectors are gone.

    Record 0 ($MFT) says where the MFT is in clusters, and it was found at a byte position on the device: with
    the cluster size (the MFT's allocated size over its number of clusters) that gives where the volume starts.
    Record 1 ($MFTMirr) says where the mirror copy of records 0-3 is, which tells a copy found in the mirror
    from the real thing; $BadClus:$Bad (record 8) and $Bitmap (record 6) give the volume size, $Volume the
    label."""

    def __init__(self):
        self._pending: list[tuple[int, bytes]] = []
        self._cands: dict[int, dict] = {}
        self._end = 0

    def feed(self, offset: int, buf: bytes) -> None:
        if self._pending:
            pend, self._pending = self._pending, []
            for pos, head in pend:
                if pos + len(head) == offset:
                    head = head + bytes(buf[:_LOOKAHEAD - len(head)])
                self._look(pos, head)
        self._end = offset + len(buf)
        for m in _REC0.finditer(buf):
            p = m.start()
            if (offset + p) % 512:
                continue
            if p + _LOOKAHEAD > len(buf):
                if len(self._pending) < 64:
                    self._pending.append((offset + p, bytes(buf[p:])))
                continue
            self._look(offset + p, bytes(buf[p:p + _LOOKAHEAD]))

    def _look(self, pos: int, blob: bytes) -> None:
        try:
            self._analyze(pos, blob)
        except Exception:  # noqa: BLE001 - random bytes that look like a record must not stop the scan
            pass

    def _analyze(self, pos: int, blob: bytes) -> None:
        rs = struct.unpack_from("<I", blob, 0x1C)[0]
        if rs not in (1024, 4096, 2048, 512) or len(blob) < 2 * rs:
            return
        recs: dict[int, _Rec] = {}
        for k in range(min(16, len(blob) // rs)):
            r = parse_record(bytearray(blob[k * rs:(k + 1) * rs]), rs, k)
            if r is not None and struct.unpack_from("<I", blob, k * rs + 0x2C)[0] == k:
                recs[k] = r
        r0 = recs.get(0)
        if r0 is None or r0.base:
            return
        named = any(n[3] == "$MFT" and n[0] == ROOT for n in r0.names)
        d0 = [p for p in r0.data if not p.name and p.runs and p.vcn == 0]
        if not d0:
            return
        p0 = d0[0]
        r1 = recs.get(1)
        d1 = [p for p in r1.data if not p.name and p.runs and p.vcn == 0] if r1 else []
        # the cluster size: allocated size over clusters, from a file that is surely in one piece ($MFTMirr,
        # $Boot, $Bitmap) before $MFT itself, which may describe only its first pieces
        cs = None
        for k in (1, 7, 6, 0):
            x = recs.get(k)
            if x is None or (k == 0 and x.alist is not None):
                continue
            for p in x.data:
                if not p.name and p.runs and p.vcn == 0:
                    cs = self._cluster_size(p)
                    break
            if cs:
                break
        if cs is None or p0.runs[0][0] < 0:
            return
        mft_lcn = p0.runs[0][0]
        mirr_lcn = d1[0].runs[0][0] if d1 and d1[0].runs[0][0] >= 0 else None
        full = all(k in recs for k in (4, 5, 6))          # records past the 4 the mirror holds: the real MFT
        size = 0
        r8 = recs.get(8)
        if r8 is not None:
            bad = [p for p in r8.data if p.name == "$Bad" and p.vcn == 0 and p.runs is not None]
            if bad and bad[0].size % cs == 0:
                size = bad[0].size
        r6 = recs.get(6)
        if not size and r6 is not None:
            bm = [p for p in r6.data if not p.name and p.vcn == 0]
            if bm:
                size = bm[0].size * 8 * cs
        label = recs[3].volname if 3 in recs and recs[3].volname else ""
        base = {"cs": cs, "rs": rs, "mft_lcn": mft_lcn, "mirr_lcn": mirr_lcn, "size": size, "label": label}
        # hypothesis 1: this is the MFT itself
        start = pos - mft_lcn * cs
        if start >= 0:
            score = (60 if full else 20) + (10 if named else 0) + (10 if size else 0)
            self._add(start, base, score, "MFT", pos)
        # hypothesis 2: this is the $MFTMirr copy
        if mirr_lcn is not None and mirr_lcn != mft_lcn:
            start = pos - mirr_lcn * cs
            if start >= 0:
                self._add(start, base, 15 if full else 40, "mirror", pos)

    @staticmethod
    def _cluster_size(p: _Piece) -> int | None:
        clusters = p.last - p.vcn + 1
        total = sum(n for _l, n in p.runs or [])
        if clusters <= 0 or total != clusters or p.alloc % clusters:
            return None
        cs = p.alloc // clusters
        return cs if 512 <= cs <= MAX_CLUSTER and _power_of_two(cs) else None

    def _add(self, start: int, base: dict, score: int, kind: str, source: int) -> None:
        if start % 512:
            return
        c = self._cands.get(start)
        if c is None:
            if len(self._cands) >= 10000:
                return
            c = dict(base)
            c["score"] = 0
            c["kinds"] = set()
            c["sources"] = set()
            self._cands[start] = c
        if len(c["sources"]) < 64:
            c["sources"].add(source)
        if kind in c["kinds"]:
            c["score"] = max(c["score"], score)
        else:
            c["score"] = c["score"] + score if c["kinds"] else score
            c["kinds"].add(kind)
        for k in ("size", "label", "mirr_lcn"):
            if not c.get(k) and base.get(k):
                c[k] = base[k]

    def finish(self) -> list[dict]:
        for pos, head in self._pending:
            self._look(pos, head)
        self._pending = []
        # a copy of record 0 is read both as "the MFT" and as "the mirror": once one reading is confirmed by
        # other evidence (a strong candidate), the other reading of the same copy is dropped
        explained: set[int] = set()
        for c in self._cands.values():
            if c["score"] >= 60:
                explained |= c["sources"]
        out = []
        for start, c in sorted(self._cands.items()):
            if c["score"] < 60 and c["sources"] <= explained:
                continue
            cs, rs = c["cs"], c["rs"]
            size = c["size"] or 0
            if not size:                     # unknown: up to the end of the device
                size = max(self._end - start, max(c["mft_lcn"], c.get("mirr_lcn") or 0) * cs + 16 * rs)
            info = {"reconstructed": True, "cluster_size": cs, "mft_offset": c["mft_lcn"] * cs, "record_size": rs,
                    "size": size, "sector_size": 512, "clusters": size // cs, "label": c["label"] or "",
                    "fstype": "ntfs", "block_size": cs}
            if c.get("mirr_lcn") is not None:
                info["mftmirr_offset"] = c["mirr_lcn"] * cs
            out.append({"fstype": "ntfs", "offset": start, "size": size, "evidence": "MFT records",
                        "score": min(100, c["score"]), "label": c["label"] or "", "info": info})
        return out
