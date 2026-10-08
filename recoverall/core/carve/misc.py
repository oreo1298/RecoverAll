"""Signatures for e-mail stores, databases and programs (part one of the engine's "misc" formats; fonts,
calendars, certificates, disk images and other odds and ends are in :mod:`.misc2`).

Most of these formats say how long they are, so a carved copy ends exactly where the original did:

- Outlook PST/OST files store their size in the header (ibFileEof); Outlook Express DBX files too.
- SQLite records its page count (trusted when the "version-valid-for" counter is current), a registry hive
  the size of its hive bins, a Windows event log its chunk count, a dBase table its record count, a KeePass
  KDBX 4 database ends after its last HMAC block.
- Programs are walked: a Windows PE ends after its last section (plus the Authenticode signature and an
  NSIS installer's payload), an ELF after its furthest section or segment, a Mach-O after its furthest
  segment or link-edit data, a Java class after its last attribute, a WebAssembly module after its last
  section; Android DEX files carry their size (and an Adler-32 checksum that is verified).

Some don't: Access databases, KeePass 1 and KDBX 3 databases and ESE (.edb) databases never record where
they end, so the engine ends them where the next file starts. Mailboxes (mbox), loose messages (.eml) and
Thunderbird indexes (.msf) are text: they end where the text does (the first NUL or control byte).

Every parser validates the structure behind the magic bytes, so random data that happens to start with
"MZ" or "From " is not reported.
"""

from __future__ import annotations

import calendar
import email.header
import email.utils
import functools
import hashlib
import re
import struct
import time
import zlib

from .base import CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, Format, GiB, Hit, KiB, MiB, Reader
from .common import clean_name

# ---------------------------------------------------------------------- helpers (misc2 uses them too)
_LE16, _LE32, _LE64 = struct.Struct("<H"), struct.Struct("<I"), struct.Struct("<Q")
_BE16, _BE32, _BE64 = struct.Struct(">H"), struct.Struct(">I"), struct.Struct(">Q")


def u16(b: bytes, o: int) -> int:
    return _LE16.unpack_from(b, o)[0]


def u32(b: bytes, o: int) -> int:
    return _LE32.unpack_from(b, o)[0]


def u64(b: bytes, o: int) -> int:
    return _LE64.unpack_from(b, o)[0]


def be16(b: bytes, o: int) -> int:
    return _BE16.unpack_from(b, o)[0]


def be32(b: bytes, o: int) -> int:
    return _BE32.unpack_from(b, o)[0]


def be64(b: bytes, o: int) -> int:
    return _BE64.unpack_from(b, o)[0]


class Short(Exception):
    """A walk ran past the bytes read so far (read more, or the file is cut off)."""


def guarded(fn):
    """Damaged data must never stop a scan: a parser that trips over it simply doesn't recognise the file."""

    @functools.wraps(fn)
    def wrapper(r: Reader) -> Hit | None:
        try:
            return fn(r)
        except (struct.error, ValueError, LookupError, OverflowError, ZeroDivisionError, RecursionError,
                MemoryError, EOFError, zlib.error, Short):
            return None
    return wrapper


def finish(r: Reader, ext: str, length: int | None, chance: int = CHANCE_GOOD, **kw) -> Hit:
    """A Hit, cut to what is left of the source: a file running past the end of the disk is incomplete."""
    if length is not None and length > r.limit:
        length, chance = r.limit, CHANCE_POOR
    return Hit(ext, length, chance, **kw)


_BINARY = re.compile(rb"[\x00-\x08\x0e-\x1a\x1c-\x1f]")


def text_end(r: Reader, start: int = 0, cap: int | None = None, step: int = MiB) -> int:
    """Where the text starting at START stops: the first NUL or control byte (tab, line breaks, form feed and
    ESC are text), or CAP / the end of the source."""
    end = r.limit if cap is None else min(cap, r.limit)
    pos = start
    while pos < end:
        buf = r.read(pos, min(step, end - pos))
        if not buf:
            break
        m = _BINARY.search(buf)
        if m:
            return pos + m.start()
        pos += len(buf)
    return min(pos, end)


def walk_buffered(r: Reader, fn, first: int = 256 * KiB, cap: int = 64 * MiB):
    """Run FN(buf, complete) over the start of the file, reading four times more each time it raises
    :class:`Short`. COMPLETE says BUF already holds everything up to CAP; a Short then propagates (the file
    is cut off, or longer than CAP)."""
    want = first
    while True:
        n = min(want, cap, r.limit)
        buf = r.read(0, n)
        complete = n >= min(cap, r.limit)
        try:
            return fn(buf, complete)
        except Short:
            if complete:
                raise
            want *= 4


def plausible(t: float | None) -> float | None:
    """T (Unix time) if it could be a real file date (1980 to tomorrow), else None."""
    if t is None:
        return None
    return float(t) if 315532800 <= t <= time.time() + 86400 else None


def from_filetime(v: int) -> float | None:
    """A Windows FILETIME (100 ns ticks since 1601) as Unix time, if plausible."""
    return plausible((v - 116444736000000000) / 1e7) if v else None


def is_pow2(v: int) -> bool:
    return v > 0 and v & (v - 1) == 0


def align(v: int, a: int) -> int:
    return (v + a - 1) // a * a


# ====================================================================== e-mail
# ---------------------------------------------------------------------- Outlook PST / OST
def _weak_crc(data: bytes) -> int:
    """The CRC-32 Outlook uses in PST headers: the usual table, without the pre/post inversion."""
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF


@guarded
def parse_pst(r: Reader) -> Hit | None:
    """Outlook data file. ANSI (Outlook 97-2002) and Unicode (2003+) headers differ in layout; both carry the
    file size (ibFileEof) and a CRC of the header. "SO" in wMagicClient marks an offline store (.ost)."""
    h = r.read(0, 564)
    if len(h) < 512 or h[:4] != b"!BDN" or h[8:10] not in (b"SM", b"SO", b"AB") or h[14:16] != b"\x01\x01":
        return None
    ver = u16(h, 10)
    if ver in (14, 15):
        kind = "ANSI"
        eof, sentinel, crypt = u32(h, 168), h[460], h[461]
        crc_ok = _weak_crc(h[8:479]) == u32(h, 4)
    elif 23 <= ver <= 40 and len(h) >= 564:
        kind = "Unicode"
        eof, sentinel, crypt = u64(h, 184), h[512], h[513]
        crc_ok = _weak_crc(h[8:479]) == u32(h, 4) and _weak_crc(h[8:524]) == u32(h, 524)
    else:
        return None
    if sentinel != 0x80 or crypt not in (0, 1, 2, 0x10) or not 512 <= eof <= 256 * GiB:
        return None
    ext = "ost" if h[8:10] == b"SO" else "pst"
    return finish(r, ext, eof, CHANCE_GOOD if crc_ok else CHANCE_FAIR, info={"format": kind})


# ---------------------------------------------------------------------- Outlook Express DBX
_DBX_HEADER = 0x24BC
_DBX_CLSID_TAIL = bytes.fromhex("fd746f66e3d1119a4e00c04fa309d4")


@guarded
def parse_dbx(r: Reader) -> Hit | None:
    """Outlook Express mail folder (messages: CLSID ...C5, folder list: ...C6). Every object in the file starts
    with its own offset, which lets us check the index root the header points to."""
    h = r.read(0, 0x100)
    if len(h) < 0x100 or h[:4] != b"\xcf\xad\x12\xfe" or h[4] not in (0xC5, 0xC6) or h[5:20] != _DBX_CLSID_TAIL:
        return None
    root = u32(h, 0xE4)
    if root:
        if not _DBX_HEADER <= root < 2 * GiB or root % 4:
            return None
        obj = r.read(root, 4)
        if len(obj) == 4 and u32(obj, 0) != root:
            return None
    # The file size field (0xC4, as PhotoRec reads it; 0x7C in some descriptions): take the one that is
    # consistent with the header and the index root.
    for off in (0xC4, 0x7C):
        size = u32(h, off)
        if _DBX_HEADER <= size <= 2 * GiB and size % 4 == 0 and size > root:
            return finish(r, "dbx", size, CHANCE_FAIR)
    return Hit("dbx", None, CHANCE_FAIR)


# ---------------------------------------------------------------------- mbox / eml / msf (text)
_HEADER_NAME = re.compile(rb"[!-9;-~]{1,100}$")
_MAIL_FIELDS = frozenset((b"received", b"from", b"to", b"cc", b"date", b"subject", b"return-path", b"message-id",
                          b"delivered-to", b"mime-version", b"x-mozilla-status", b"content-type", b"reply-to",
                          b"sender", b"status", b"x-uid", b"x-gmail-labels", b"envelope-to", b"in-reply-to"))


def _mail_headers(buf: bytes, pos: int = 0) -> dict[bytes, bytes] | None:
    """The RFC 822 header block at POS of BUF ({lower-case name: first value}, folded lines joined), or None
    unless every line up to the blank line that ends it is a header line."""
    fields: dict[bytes, bytes] = {}
    last = None                            # the field a folded line continues (None: a repeated field)
    for _ in range(1000):
        nl = buf.find(b"\n", pos)
        if nl < 0:
            return None
        line = buf[pos:nl].rstrip(b"\r")
        pos = nl + 1
        if not line:
            return fields or None
        if line[:1] in (b" ", b"\t"):
            if not fields:
                return None
            if last is not None and len(fields[last]) < 4096:
                fields[last] += b" " + line.strip()
            continue
        name, sep, value = line.partition(b":")
        if not sep or not _HEADER_NAME.match(name):
            return None
        key = name.lower()
        last = None if key in fields else key
        fields.setdefault(key, value.strip())
    return None


def _mail_date(value: bytes | None) -> float | None:
    if not value:
        return None
    try:
        t = email.utils.parsedate_tz(value.decode("latin-1"))
        return plausible(email.utils.mktime_tz(t)) if t else None
    except (TypeError, ValueError, OverflowError):
        return None


def _mail_subject(value: bytes | None) -> str | None:
    if not value:
        return None
    try:
        parts = email.header.decode_header(value.decode("utf-8", "replace"))
        text = "".join(p.decode(cs or "utf-8", "replace") if isinstance(p, bytes) else p for p, cs in parts)
    except (LookupError, ValueError):
        text = value.decode("utf-8", "replace")
    return clean_name(text)


_MBOX_FROM = re.compile(rb"From \S{1,256}[ \t]+([^\r\n]{10,100})\r?\n")
_MBOX_DATE = re.compile(rb"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b.*\d{1,2}:\d{2}.*\b(?:19[7-9]\d|2\d{3})\b")


@guarded
def parse_mbox(r: Reader) -> Hit | None:
    """Unix mailbox: messages one after another, each introduced by a "From sender date" line. The first one
    must be followed by a real header block. The mailbox ends where the text does."""
    head = r.read(0, 64 * KiB)
    m = _MBOX_FROM.match(head)
    if not m or not _MBOX_DATE.search(m.group(1)):
        return None
    fields = _mail_headers(head, m.end())
    if fields is None or len(fields) < 2 or not _MAIL_FIELDS.intersection(fields):
        return None
    end = text_end(r, 0)
    if end < m.end() + 16:
        return None
    return Hit("mbox", end, CHANCE_FAIR, mtime=_mail_date(fields.get(b"date")))


@guarded
def parse_eml(r: Reader) -> Hit | None:
    """A single message saved as a file: a header block with From, Date and Subject; it ends where the text
    does. Named after its subject and dated by its Date header."""
    head = r.read(0, 64 * KiB)
    fields = _mail_headers(head)
    if not fields or not {b"from", b"date", b"subject"} <= fields.keys():
        return None
    end = text_end(r, 0)
    if end < 64:
        return None
    return Hit("eml", end, CHANCE_FAIR, name=_mail_subject(fields.get(b"subject")),
               mtime=_mail_date(fields.get(b"date")))


@guarded
def parse_msf(r: Reader) -> Hit | None:
    """Thunderbird / Mozilla summary file (Mork database, text)."""
    head = r.read(0, 64)
    if not re.match(rb'// <!-- <mdb:mork:z v="[0-9.]+"/> -->\r?\n', head):
        return None
    return Hit("msf", text_end(r, 0), CHANCE_FAIR)


# ====================================================================== databases
# ---------------------------------------------------------------------- SQLite
@guarded
def parse_sqlite(r: Reader) -> Hit | None:
    """SQLite 3 database. Its size is the page count in the header times the page size — trusted only when
    the header's "version-valid-for" number matches the change counter (SQLite 3.7.0+ keeps them in step);
    older files end where the next file starts."""
    h = r.read(0, 108)
    if len(h) < 108 or h[:16] != b"SQLite format 3\0":
        return None
    page = be16(h, 16)
    page = 65536 if page == 1 else page
    if not is_pow2(page) or not 512 <= page <= 65536 or h[18] not in (1, 2) or h[19] not in (1, 2):
        return None
    if h[21:24] != b"\x40\x20\x20" or any(h[72:92]) or be32(h, 44) > 4 or be32(h, 56) > 3:
        return None
    if h[100] not in (0x0D, 0x05):         # page 1 holds the root of the schema table
        return None
    change, pages, valid_for, version = be32(h, 24), be32(h, 28), be32(h, 92), be32(h, 96)
    info = {"page_size": page}
    if version:
        info["sqlite"] = f"{version // 1000000}.{version // 1000 % 1000}.{version % 1000}"
    if pages and change == valid_for:
        info["pages"] = pages
        return finish(r, "sqlite", pages * page, CHANCE_GOOD, info=info)
    return Hit("sqlite", None, CHANCE_FAIR, info=info)


# ---------------------------------------------------------------------- Access (Jet / ACE)
@guarded
def parse_mdb(r: Reader) -> Hit | None:
    """Microsoft Access database (.mdb: Jet 3/4, .accdb: ACE). Pages of 2 or 4 KiB; the header doesn't say
    how many, so the database ends where the next file starts."""
    h = r.read(0, 0x20)
    if len(h) < 0x20 or h[:4] != b"\x00\x01\x00\x00" or h[4:20] not in (b"Standard Jet DB\0", b"Standard ACE DB\0"):
        return None
    ver = u32(h, 0x14)
    if ver > 0x10:
        return None
    ace = h[4:20] == b"Standard ACE DB\0"
    return Hit("accdb" if ace else "mdb", None, CHANCE_FAIR,
               info={"version": {0: "Jet 3", 1: "Jet 4"}.get(ver, "ACE"), "page_size": 2048 if ver == 0 else 4096})


# ---------------------------------------------------------------------- KeePass
_KDBX_SIG = b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5"
_KDB_SIG = b"\x03\xd9\xa2\x9a\x65\xfb\x4b\xb5"


@guarded
def parse_kdbx(r: Reader) -> Hit | None:
    """KeePass 2 database. KDBX 4 stores the payload as HMAC blocks (32-byte HMAC, size, data) ending with an
    empty block, so its end is exact (and the header's SHA-256 is checked); KDBX 3 encrypts everything after
    the header, so it ends where the next file starts."""
    h = r.read(0, 64 * KiB)
    if len(h) < 12 or h[:8] != _KDBX_SIG:
        return None
    major = u16(h, 10)
    if major not in (2, 3, 4):
        return None
    pos, seen = 12, set()
    for _ in range(64):
        if major >= 4:
            fid, size, hdr = h[pos], u32(h, pos + 1), 5
        else:
            fid, size, hdr = h[pos], u16(h, pos + 1), 3
        if fid > 12 or size > 32 * KiB or pos + hdr + size > len(h):
            return None
        seen.add(fid)
        pos += hdr + size
        if fid == 0:
            break
    else:
        return None
    if not {2, 4} <= seen:                 # the cipher and the master seed are always there
        return None
    info = {"version": f"{major}.{u16(h, 8)}"}
    if major < 4:
        return Hit("kdbx", None, CHANCE_FAIR, info=info)
    if hashlib.sha256(h[:pos]).digest() != h[pos:pos + 32]:
        return Hit("kdbx", None, CHANCE_POOR, info=info)
    pos += 64                              # header SHA-256 and HMAC
    for _ in range(1 << 20):
        b = r.read(pos, 36)
        if len(b) < 36:                    # cut off by the end of the disk
            return Hit("kdbx", r.limit, CHANCE_POOR, info=info)
        n = u32(b, 32)
        if n > 256 * MiB:
            return Hit("kdbx", None, CHANCE_POOR, info=info)
        pos += 36 + n
        if n == 0:
            return finish(r, "kdbx", pos, CHANCE_GOOD, info=info)
    return None


@guarded
def parse_kdb(r: Reader) -> Hit | None:
    """KeePass 1 database: a 124-byte header (cipher flags, group and entry counts) and the encrypted
    content, whose length isn't recorded."""
    h = r.read(0, 124)
    if len(h) < 124 or h[:8] != _KDB_SIG:
        return None
    flags, ver, groups, entries, rounds = u32(h, 8), u32(h, 12), u32(h, 48), u32(h, 52), u32(h, 120)
    if ver >> 16 not in (2, 3) or not flags & 1 or flags & 0xE not in (2, 4, 8) or flags >> 4:
        return None
    if groups > 1_000_000 or entries > 10_000_000 or not rounds:
        return None
    return Hit("kdb", None, CHANCE_FAIR, info={"groups": groups, "entries": entries})


# ---------------------------------------------------------------------- Windows registry hive
@guarded
def parse_regf(r: Reader) -> Hit | None:
    """Registry hive (SYSTEM, SOFTWARE, NTUSER.DAT...): a 4 KiB base block with an XOR checksum, then the hive
    bins, whose total size the base block records. Named after the hive file name it keeps."""
    h = r.read(0, 4096 + 4)
    if len(h) < 512 or h[:4] != b"regf":
        return None
    x = 0
    for w in struct.unpack_from("<127I", h):
        x ^= w
    x = 0xFFFFFFFE if x == 0xFFFFFFFF else (x or 1)
    if x != u32(h, 508) or u32(h, 20) != 1 or u32(h, 24) > 6 or u32(h, 28) != 0 or u32(h, 32) != 1:
        return None
    size = u32(h, 40)
    if not size or size % 4096 or (len(h) >= 4100 and h[4096:4100] != b"hbin"):
        return None
    hive = h[48:112].decode("utf-16-le", "replace").split("\0")[0].rsplit("\\", 1)[-1]
    name = re.sub(r"(?i)\.dat$", "", hive)
    return finish(r, "dat", 4096 + size, name=clean_name(name), mtime=from_filetime(u64(h, 12)),
                  info={"hive": hive} if hive else None)


# ---------------------------------------------------------------------- Windows event log (.evtx)
@guarded
def parse_evtx(r: Reader) -> Hit | None:
    """Windows XML event log: a 4 KiB header (CRC-32 checked) and 64 KiB chunks ("ElfChnk"). The header's
    chunk count can be stale in a log that wasn't closed cleanly, so the chunks actually present count too."""
    h = r.read(0, 128)
    if len(h) < 128 or h[:8] != b"ElfFile\0" or u32(h, 32) != 128 or u16(h, 38) != 3 or u16(h, 40) != 4096:
        return None
    count = u16(h, 42)
    while count < 0xFFFF and r.read(4096 + count * 65536, 8) == b"ElfChnk\0":     # chunks past the count
        count += 1
    if not count:
        return None
    chance = CHANCE_GOOD if zlib.crc32(h[:120]) == u32(h, 124) else CHANCE_FAIR
    return finish(r, "evtx", 4096 + count * 65536, chance, info={"chunks": count})


# ---------------------------------------------------------------------- ESE database (.edb)
@guarded
def parse_edb(r: Reader) -> Hit | None:
    """Extensible Storage Engine database (Windows Search, Exchange, SRUM, WebCache...). The header is
    repeated one page further (the shadow header), which we check; the page count isn't recorded."""
    h = r.read(0, 240)
    if len(h) < 240 or h[4:8] != b"\xef\xcd\xab\x89":
        return None
    ver, ftype, state, page = u32(h, 8), u32(h, 12), u32(h, 52), u32(h, 236)
    if not 0x620 <= ver <= 0x623 or ftype > 1 or not 1 <= state <= 7:
        return None
    page = page or 4096
    if page not in (2048, 4096, 8192, 16384, 32768):
        return None
    shadow = r.read(page, 16)
    if len(shadow) == 16 and shadow[4:16] != h[4:16]:
        return None
    states = {1: "just created", 2: "dirty shutdown", 3: "clean shutdown", 4: "being converted", 5: "force detach"}
    return Hit("edb", None, CHANCE_FAIR, info={"page_size": page, "state": states.get(state, str(state))})


# ---------------------------------------------------------------------- dBase / FoxPro (.dbf)
_DBF_VERSIONS = frozenset((0x02, 0x03, 0x04, 0x05, 0x30, 0x31, 0x32, 0x43, 0x63, 0x83, 0x8B, 0x8E, 0xCB, 0xF5, 0xFB))
_DBF_TYPES = frozenset(b"CNFLDMBGIYT@+OVPW0QX")


@guarded
def parse_dbf(r: Reader) -> Hit | None:
    """dBase / FoxPro table: header, field descriptors (their widths must add up to the record size), then
    the records. Off by default: the magic is a single byte."""
    h = r.read(0, 32)
    if len(h) < 32 or h[0] not in _DBF_VERSIONS or not 1 <= h[2] <= 12 or not 1 <= h[3] <= 31:
        return None
    nrec, hlen, rlen = u32(h, 4), u16(h, 8), u16(h, 10)
    if hlen < 65 or rlen < 2 or h[14] > 1 or h[15] > 1 or nrec > 1 << 28:
        return None
    d = r.read(0, hlen)
    if len(d) < hlen:
        return None
    total, pos = 1, 32
    while pos < hlen and d[pos] != 0x0D:
        fd = d[pos:pos + 32]
        if len(fd) < 32:
            return None
        name = fd[:11].split(b"\0")[0]
        if not re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_]{0,10}", name) or fd[11] not in _DBF_TYPES:
            return None
        total += fd[16] + (fd[17] << 8 if fd[11] == 0x43 and h[0] in (0x30, 0x31, 0x32, 0xF5) else 0)
        pos += 32
    if pos == 32 or pos >= hlen or total != rlen:
        return None
    end = hlen + nrec * rlen
    if r.read(end, 1) == b"\x1a":
        end += 1
    try:
        mtime = plausible(calendar.timegm((1900 + h[1], h[2], h[3], 0, 0, 0)))
    except (ValueError, OverflowError):
        mtime = None
    return finish(r, "dbf", end, CHANCE_GOOD, mtime=mtime, info={"records": nrec, "fields": (pos - 32) // 32})


# ====================================================================== programs
# ---------------------------------------------------------------------- Windows PE (exe, dll, sys, efi)
_PE_MACHINES = {0x0: "unknown", 0x14C: "x86", 0x8664: "x86-64", 0xAA64: "ARM64", 0xA641: "ARM64EC", 0xA64E: "ARM64X",
                0x1C0: "ARM", 0x1C2: "ARM Thumb", 0x1C4: "ARMv7", 0x200: "Itanium", 0xEBC: "EFI byte code",
                0x5032: "RISC-V 32", 0x5064: "RISC-V 64", 0x5128: "RISC-V 128", 0x6232: "LoongArch 32",
                0x6264: "LoongArch 64", 0x162: "MIPS R3000", 0x166: "MIPS", 0x168: "MIPS R10000",
                0x169: "MIPS WCE", 0x266: "MIPS16", 0x366: "MIPS FPU", 0x466: "MIPS16 FPU", 0x1F0: "PowerPC",
                0x1F1: "PowerPC FP", 0x1A2: "SH3", 0x1A3: "SH3 DSP", 0x1A6: "SH4", 0x1A8: "SH5", 0x184: "Alpha",
                0x284: "Alpha 64", 0x1D3: "AM33", 0x9041: "M32R", 0x268: "Motorola 68000"}
_PE_SUBSYSTEMS = {1: "native", 2: "Windows GUI", 3: "console", 5: "OS/2", 7: "POSIX", 9: "Windows CE",
                  10: "EFI application", 11: "EFI boot driver", 12: "EFI runtime driver", 13: "EFI ROM",
                  14: "Xbox", 16: "boot application"}


def _pe_offset(sections: list[tuple[int, int, int, int]], headers: int, rva: int) -> int | None:
    """The file offset of virtual address RVA."""
    if rva < headers:
        return rva
    for va, vsize, rawptr, rawsize in sections:
        if va <= rva < va + max(vsize, rawsize):
            return rawptr + rva - va if rva - va < rawsize else None
    return None


@guarded
def parse_pe(r: Reader) -> Hit | None:
    """Windows program, library or driver (PE32 / PE32+). It ends after the furthest section, COFF symbol
    table or debug data; an NSIS installer's payload and an Authenticode signature that follow are kept too.
    The extension comes from the header (DLL flag, native or EFI subsystem); a library is named after its
    export name, and the link time dates the file unless the build is reproducible."""
    mz = r.read(0, 64)
    if len(mz) < 64 or mz[:2] != b"MZ":
        return None
    lfanew = u32(mz, 0x3C)
    if not 4 <= lfanew <= 0x10000:
        return None
    nt = r.read(lfanew, 24)
    if len(nt) < 24 or nt[:4] != b"PE\0\0":
        return None
    machine, nsec, stamp, symptr, nsyms, optsize, chars = struct.unpack_from("<HHIIIHH", nt, 4)
    if machine not in _PE_MACHINES or not chars & 0x0002 or nsec > 2048 or not 96 <= optsize <= 4096:
        return None
    opt = r.read(lfanew + 24, optsize)
    if len(opt) < optsize:
        return None
    magic = u16(opt, 0)
    if magic == 0x10B:
        dd, kind = 96, "PE32"
    elif magic == 0x20B:
        dd, kind = 112, "PE32+"
    else:
        return None
    if optsize < dd:
        return None
    sect_align, file_align = u32(opt, 32), u32(opt, 36)
    headers, subsystem = u32(opt, 60), u16(opt, 68)
    if not is_pow2(file_align) or not is_pow2(sect_align) or file_align > 65536 or sect_align < file_align:
        return None
    if subsystem > 20 or headers > 16 * MiB:
        return None
    nrva = min(u32(opt, dd - 4), (optsize - dd) // 8, 16)
    dirs = [struct.unpack_from("<II", opt, dd + 8 * i) for i in range(nrva)]

    table = lfanew + 24 + optsize
    sec = r.read(table, 40 * nsec)
    if len(sec) < 40 * nsec:
        return None
    end = max(headers, table + 40 * nsec)
    sections = []
    prev_va = 0
    for i in range(nsec):
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", sec, 40 * i + 8)
        if va < prev_va:                   # the loader wants them in address order
            return None
        prev_va = va
        if rawsize and rawptr:
            if rawptr + rawsize > 4 * GiB:
                return None
            end = max(end, rawptr + rawsize)
        sections.append((va, vsize, rawptr, rawsize))
    image_end = end

    # COFF symbols and their string table (MinGW and Cygwin builds keep them at the end)
    if symptr and nsyms and symptr >= headers and nsyms < 1 << 24:
        strtab = symptr + 18 * nsyms
        sz = r.read(strtab, 4)
        if len(sz) == 4 and 4 <= u32(sz, 0) <= 256 * MiB:
            end = max(end, strtab + u32(sz, 0))
    # debug data that lives outside the sections; a REPRO entry means the time stamp is a hash
    repro = False
    if nrva > 6 and dirs[6][0] and dirs[6][1]:
        off = _pe_offset(sections, headers, dirs[6][0])
        if off is not None:
            dbg = r.read(off, min(dirs[6][1], 28 * 64))
            for j in range(len(dbg) // 28):
                typ, size, _addr, ptr = struct.unpack_from("<IIII", dbg, 28 * j + 12)
                repro = repro or typ == 16
                if ptr and size and size <= 64 * MiB and headers <= ptr <= 4 * GiB:
                    end = max(end, ptr + size)
    # an NSIS installer: its compressed payload follows the program, length in its first header
    nsis = align(image_end, 512)
    fh = r.read(nsis, 28)
    if len(fh) == 28 and fh[4:20] == b"\xef\xbe\xad\xdeNullsoftInst" and 28 <= u32(fh, 24) <= 4 * GiB:
        end = max(end, nsis + u32(fh, 24))
    # the Authenticode signature: a file offset (not an address), after everything else
    if nrva > 4 and dirs[4][0] and dirs[4][1] and dirs[4][0] >= image_end and dirs[4][1] <= 64 * MiB:
        off, size = dirs[4]
        wc = r.read(off, 8)
        if len(wc) < 8 or (8 <= u32(wc, 0) <= size and u16(wc, 4) in (0x100, 0x200) and 1 <= u16(wc, 6) <= 4):
            end = max(end, off + size)

    if chars & 0x2000:
        ext = "dll"
    elif subsystem in (10, 11, 12, 13):
        ext = "efi"
    elif subsystem == 1:
        ext = "sys"
    else:
        ext = "exe"
    name = None
    if nrva > 0 and dirs[0][0] and dirs[0][1] >= 40:
        off = _pe_offset(sections, headers, dirs[0][0])
        exp = r.read(off, 40) if off is not None else b""
        noff = _pe_offset(sections, headers, u32(exp, 12)) if len(exp) == 40 and u32(exp, 12) else None
        if noff is not None:
            raw = r.read(noff, 256).split(b"\0")[0]
            if raw and re.fullmatch(rb"[ -~]+", raw):
                name = clean_name(re.sub(r"(?i)\.(dll|exe|sys|efi|drv|ocx|cpl)$", "", raw.decode("ascii")))
    info = {"format": kind, "machine": _PE_MACHINES[machine],
            "subsystem": _PE_SUBSYSTEMS.get(subsystem, str(subsystem))}
    if nrva > 14 and dirs[14][0]:
        info["dotnet"] = True
    return finish(r, ext, end, CHANCE_GOOD, name=name, mtime=None if repro else plausible(stamp), info=info)


# ---------------------------------------------------------------------- ELF
_ELF_MACHINES = {0: "none", 2: "SPARC", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC 64", 22: "S/390",
                 40: "ARM", 42: "SuperH", 43: "SPARC v9", 50: "Itanium", 62: "x86-64", 183: "ARM64",
                 243: "RISC-V", 247: "BPF", 258: "LoongArch"}
_ELF_TYPES = {1: "relocatable object", 2: "executable", 3: "shared object", 4: "core dump"}


@guarded
def parse_elf(r: Reader) -> Hit | None:
    """Linux / Unix program, library, object file or core dump (32/64-bit, either byte order). It ends at the
    furthest of: the section header table, any section's data, any segment's data."""
    h = r.read(0, 64)
    if len(h) < 52 or h[:4] != b"\x7fELF" or h[4] not in (1, 2) or h[5] not in (1, 2) or h[6] != 1 or any(h[9:16]):
        return None
    bo = "<" if h[5] == 1 else ">"
    if h[4] == 1:
        (etype, machine, version, _entry, phoff, shoff, _flags, ehsize, phentsize, phnum, shentsize, shnum,
         shstrndx) = struct.unpack_from(bo + "HHIIIIIHHHHHH", h, 16)
        eh, pe, se = 52, 32, 40
    else:
        if len(h) < 64:
            return None
        (etype, machine, version, _entry, phoff, shoff, _flags, ehsize, phentsize, phnum, shentsize, shnum,
         shstrndx) = struct.unpack_from(bo + "HHIQQQIHHHHHH", h, 16)
        eh, pe, se = 64, 56, 64
    if version != 1 or ehsize != eh or etype not in _ELF_TYPES:
        return None
    if (phnum and (phentsize != pe or phoff < eh)) or (shoff and (shentsize != se or shoff < eh)):
        return None
    if not shoff:
        shnum = 0
    elif shnum == 0 or phnum == 0xFFFF:    # extended numbering: the real counts are in section header 0
        s0 = r.read(shoff, se)
        if len(s0) == se:
            size0, info0 = struct.unpack_from(bo + "I", s0, 20)[0], struct.unpack_from(bo + "I", s0, 28)[0]
            if eh == 64:
                size0, info0 = struct.unpack_from(bo + "Q", s0, 32)[0], struct.unpack_from(bo + "I", s0, 44)[0]
            shnum = size0 if shnum == 0 else shnum
            phnum = info0 if phnum == 0xFFFF else phnum
    if shnum > 1_000_000 or phnum > 1_000_000:
        return None
    end = eh
    if phnum:
        end = max(end, phoff + phnum * pe)
    if shnum:
        end = max(end, shoff + shnum * se)
    cap = 1 << 40
    interp = False
    if phnum:
        ph = r.read(phoff, phnum * pe)
        for i in range(len(ph) // pe):
            if pe == 32:
                ptype, poff, _va, _pa, pfilesz = struct.unpack_from(bo + "IIIII", ph, i * 32)
            else:
                ptype, _pflags, poff, _va, _pa, pfilesz = struct.unpack_from(bo + "IIQQQQ", ph, i * 56)
            interp = interp or ptype == 3
            if ptype and pfilesz:
                if poff + pfilesz > cap:
                    return None
                end = max(end, poff + pfilesz)
    sections = []
    if shnum:
        sh = r.read(shoff, shnum * se)
        for i in range(len(sh) // se):
            if se == 40:
                _name, stype, _sflags, _addr, soff, ssize = struct.unpack_from(bo + "IIIIII", sh, i * 40)
            else:
                _name, stype, _sflags, _addr, soff, ssize = struct.unpack_from(bo + "IIQQQQ", sh, i * 64)
            if stype not in (0, 8) and ssize:  # NULL and NOBITS (.bss) take no room in the file
                if soff + ssize > cap:
                    return None
                end = max(end, soff + ssize)
            sections.append((soff, ssize))
    if etype == 1:
        ext = "o"
        if 0 < shstrndx < len(sections) and sections[shstrndx][1] <= MiB:
            names = r.read(*sections[shstrndx])
            if b"\0.modinfo\0" in names or b"\0.gnu.linkonce.this_module\0" in names:
                ext = "ko"
    elif etype == 3 and not interp:
        ext = "so"
    elif etype == 4:
        ext = "core"
    else:
        ext = "elf"
    kind = "kernel module" if ext == "ko" else "executable" if etype == 3 and interp else _ELF_TYPES[etype]
    info = {"machine": _ELF_MACHINES.get(machine, str(machine)), "bits": 32 if eh == 52 else 64, "type": kind}
    return finish(r, ext, end, CHANCE_GOOD, info=info)


# ---------------------------------------------------------------------- Mach-O and universal binaries
_MACHO_MAGIC = {b"\xfe\xed\xfa\xce": (">", 32), b"\xce\xfa\xed\xfe": ("<", 32),
                b"\xfe\xed\xfa\xcf": (">", 64), b"\xcf\xfa\xed\xfe": ("<", 64)}
_MACHO_CPUS = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "ARM64", 0x0200000C: "ARM64_32",
               18: "PowerPC", 0x01000012: "PowerPC 64", 6: "Motorola 68000", 14: "SPARC", 13: "Motorola 88000"}
_MACHO_EXTS = {1: "o", 2: "macho", 6: "dylib", 8: "bundle"}
_MACHO_TYPES = {1: "object", 2: "executable", 3: "fixed VM library", 4: "core dump", 5: "preloaded executable",
                6: "dynamic library", 7: "dynamic linker", 8: "bundle", 9: "library stub", 10: "debug symbols",
                11: "kernel extension", 12: "fileset"}
# load commands whose payload is (offset, size) pairs in the file
_LC_LINKEDIT = frozenset((0x1D, 0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x36, 0x80000033, 0x80000034))


def _macho(r: Reader, base: int) -> tuple[int, int, int] | None:
    """(length, file type, CPU type) of the Mach-O image at BASE, or None. Offsets in a slice of a universal
    binary are relative to the slice."""
    h = r.read(base, 32)
    if len(h) < 28 or h[:4] not in _MACHO_MAGIC:
        return None
    bo, bits = _MACHO_MAGIC[h[:4]]
    cpu, _sub, ftype, ncmds, sizeofcmds, _flags = struct.unpack_from(bo + "IIIIII", h, 4)
    if cpu not in _MACHO_CPUS or ftype not in _MACHO_TYPES or not 1 <= ncmds <= 4096:
        return None
    if not 8 * ncmds <= sizeofcmds <= 4 * MiB:
        return None
    hsize = 28 if bits == 32 else 32
    cmds = r.read(base + hsize, sizeofcmds)
    if len(cmds) < sizeofcmds:
        return None
    end = hsize + sizeofcmds
    pos = 0
    for _ in range(ncmds):
        cmd, size = struct.unpack_from(bo + "II", cmds, pos)
        if size < 8 or size % 4 or pos + size > sizeofcmds:
            return None
        if cmd == 0x1 and size >= 56:                       # LC_SEGMENT
            fileoff, filesize, _mp, _ip, nsects = struct.unpack_from(bo + "IIIII", cmds, pos + 32)
            if filesize:
                end = max(end, fileoff + filesize)
            for s in range(min(nsects, (size - 56) // 68)):
                o = pos + 56 + 68 * s
                ssize, soff, _al, reloff, nreloc, sflags = struct.unpack_from(bo + "IIIIII", cmds, o + 36)
                if soff and ssize and (sflags & 0xFF) not in (1, 12, 18):    # zero-fill sections take no room
                    end = max(end, soff + ssize)
                if nreloc:
                    end = max(end, reloff + 8 * nreloc)
        elif cmd == 0x19 and size >= 72:                    # LC_SEGMENT_64
            fileoff, filesize, _mp, _ip, nsects = struct.unpack_from(bo + "QQIII", cmds, pos + 40)
            if filesize:
                end = max(end, fileoff + filesize)
            for s in range(min(nsects, (size - 72) // 80)):
                o = pos + 72 + 80 * s
                ssize, soff, _al, reloff, nreloc, sflags = struct.unpack_from(bo + "QIIIII", cmds, o + 40)
                if soff and ssize and (sflags & 0xFF) not in (1, 12, 18):
                    end = max(end, soff + ssize)
                if nreloc:
                    end = max(end, reloff + 8 * nreloc)
        elif cmd == 0x2 and size >= 24:                     # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from(bo + "IIII", cmds, pos + 8)
            if nsyms:
                end = max(end, symoff + nsyms * (12 if bits == 32 else 16))
            if strsize:
                end = max(end, stroff + strsize)
        elif cmd == 0xB and size >= 80:                     # LC_DYSYMTAB
            f = struct.unpack_from(bo + "18I", cmds, pos + 8)
            for off, n, each in ((f[6], f[7], 8), (f[8], f[9], 52 if bits == 32 else 56), (f[10], f[11], 4),
                                 (f[12], f[13], 4), (f[14], f[15], 8), (f[16], f[17], 8)):
                if n:
                    end = max(end, off + n * each)
        elif cmd in _LC_LINKEDIT and size >= 16:            # code signature, function starts, fixups...
            off, n = struct.unpack_from(bo + "II", cmds, pos + 8)
            if n:
                end = max(end, off + n)
        elif cmd in (0x22, 0x80000022) and size >= 48:      # LC_DYLD_INFO(_ONLY)
            f = struct.unpack_from(bo + "10I", cmds, pos + 8)
            for i in range(0, 10, 2):
                if f[i + 1]:
                    end = max(end, f[i] + f[i + 1])
        pos += size
    if pos != sizeofcmds or end > 1 << 36:
        return None
    return end, ftype, cpu


@guarded
def parse_macho(r: Reader) -> Hit | None:
    """macOS / iOS program or library: the load commands give every segment, symbol table and link-edit
    blob, and the file ends after the furthest one."""
    res = _macho(r, 0)
    if res is None:
        return None
    end, ftype, cpu = res
    return finish(r, _MACHO_EXTS.get(ftype, "macho"), end, CHANCE_GOOD,
                  info={"machine": _MACHO_CPUS[cpu], "type": _MACHO_TYPES[ftype]})


@guarded
def parse_fat(r: Reader) -> Hit | None:
    """Universal ("fat") binary: a table of per-architecture Mach-O slices (or static libraries). Java class
    files share the magic: there the next bytes are a version (major 45+), here a small slice count."""
    h = r.read(0, 8)
    if len(h) < 8 or h[:4] not in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        return None
    wide = h[3] == 0xBF
    n = be32(h, 4)
    if not 1 <= n <= 30:
        return None
    esz = 32 if wide else 20
    tbl = r.read(8, n * esz)
    if len(tbl) < n * esz:
        return None
    end = 8 + n * esz
    slices = []
    for i in range(n):
        if wide:
            _cpu, _sub, off, size, al = struct.unpack_from(">IIQQI", tbl, i * esz)
        else:
            _cpu, _sub, off, size, al = struct.unpack_from(">IIIII", tbl, i * esz)
        if al > 16 or off % (1 << al) or off < 8 + n * esz or not size or off + size > 1 << 36:
            return None
        slices.append((off, size))
        end = max(end, off + size)
    slices.sort()
    for (o1, s1), (o2, _s2) in zip(slices, slices[1:]):
        if o1 + s1 > o2:
            return None
    ext, archs = None, []
    for off, size in slices:
        res = _macho(r, off)
        if res is not None:
            ext = ext or _MACHO_EXTS.get(res[1], "macho")
            archs.append(_MACHO_CPUS[res[2]])
        elif r.read(off, 8) == b"!<arch>\n":
            ext = ext or "a"
        elif off < r.limit:
            return None
    if ext is None:
        return None
    return finish(r, ext, end, CHANCE_GOOD, info={"architectures": ", ".join(archs)} if archs else None)


def parse_mach(r: Reader) -> Hit | None:
    """A Mach-O image or a universal binary."""
    return parse_macho(r) if r.read(0, 4) in _MACHO_MAGIC else parse_fat(r)


# ---------------------------------------------------------------------- Java class
def _class_walk(buf: bytes, complete: bool) -> tuple[int, str | None]:
    """Walk a class file: constant pool, fields, methods and attributes → (length, class name)."""
    def need(n: int) -> None:
        if n > len(buf):
            raise Short

    need(10)
    cnt = be16(buf, 8)
    if cnt < 3:
        raise ValueError
    tags = bytearray(cnt)
    utf8: dict[int, tuple[int, int]] = {}
    classes: dict[int, int] = {}
    pos, i = 10, 1
    while i < cnt:
        need(pos + 3)
        t = buf[pos]
        if t == 1:
            n = be16(buf, pos + 1)
            utf8[i] = (pos + 3, n)
            pos += 3 + n
        elif t in (3, 4, 9, 10, 11, 12, 17, 18):
            pos += 5
        elif t in (5, 6):
            pos += 9
        elif t == 7:
            classes[i] = be16(buf, pos + 1)
            pos += 3
        elif t in (8, 16, 19, 20):
            pos += 3
        elif t == 15:
            pos += 4
        else:
            raise ValueError
        tags[i] = t
        i += 2 if t in (5, 6) else 1

    def attributes(pos: int) -> int:
        need(pos + 2)
        n = be16(buf, pos)
        pos += 2
        for _ in range(n):
            need(pos + 6)
            ni = be16(buf, pos)
            if ni >= cnt or tags[ni] != 1:
                raise ValueError
            pos += 6 + be32(buf, pos + 2)
        return pos

    need(pos + 8)
    _access, this, sup, nif = struct.unpack_from(">HHHH", buf, pos)
    if this >= cnt or tags[this] != 7 or (sup and (sup >= cnt or tags[sup] != 7)):
        raise ValueError
    pos += 8 + 2 * nif
    for _members in range(2):                  # fields, then methods
        need(pos + 2)
        n = be16(buf, pos)
        pos += 2
        for _ in range(n):
            need(pos + 8)
            pos = attributes(pos + 6)
    pos = attributes(pos)
    need(pos)
    name = None
    ni = classes.get(this, 0)
    if ni in utf8:
        s, n = utf8[ni]
        name = buf[s:s + n].decode("utf-8", "replace").rsplit("/", 1)[-1]
    return pos, name


@guarded
def parse_class(r: Reader) -> Hit | None:
    """Compiled Java class, walked to the end of its last attribute. Named after the class."""
    h = r.read(0, 10)
    if len(h) < 10 or h[:4] != b"\xca\xfe\xba\xbe" or not 45 <= be16(h, 6) <= 100:
        return None
    major = be16(h, 6)
    java = f"1.{major - 44}" if major < 49 else str(major - 44)
    try:
        end, name = walk_buffered(r, _class_walk, first=64 * KiB, cap=64 * MiB)
    except Short:
        return Hit("class", min(r.limit, 64 * MiB), CHANCE_POOR, info={"java": java})
    return finish(r, "class", end, CHANCE_GOOD, name=clean_name(name), info={"java": java})


# ---------------------------------------------------------------------- Android DEX
@guarded
def parse_dex(r: Reader) -> Hit | None:
    """Dalvik / ART executable: the header has the file size and an Adler-32 of everything after it."""
    h = r.read(0, 0x70)
    if len(h) < 0x70 or not re.fullmatch(rb"dex\n0[0-9]{2}\0", h[:8]):
        return None
    csum, size, hsize, endian = u32(h, 8), u32(h, 32), u32(h, 36), u32(h, 40)
    map_off, data_size, data_off = u32(h, 52), u32(h, 104), u32(h, 108)
    if hsize != 0x70 or endian != 0x12345678 or not 0x70 <= size <= GiB or map_off >= size:
        return None
    if data_off + data_size > size:
        return None
    a, pos = 1, 12
    while pos < size:
        chunk = r.read(pos, min(4 * MiB, size - pos))
        if not chunk:
            break
        a = zlib.adler32(chunk, a)
        pos += len(chunk)
    chance = CHANCE_GOOD if pos >= size and a == csum else CHANCE_FAIR
    return finish(r, "dex", size, chance, info={"version": h[4:7].decode()})


# ---------------------------------------------------------------------- WebAssembly
_WASM_ORDER = {1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 13: 7, 7: 8, 8: 9, 9: 10, 12: 11, 10: 12, 11: 13}


def _leb(b: bytes, pos: int) -> tuple[int, int]:
    """An unsigned 32-bit LEB128 at POS → (value, bytes used)."""
    v = 0
    for i in range(5):
        c = b[pos + i]
        v |= (c & 0x7F) << (7 * i)
        if not c & 0x80:
            return v, i + 1
    raise ValueError("LEB128 too long")


def _wasm_first(body: bytes, sid: int) -> bool:
    """A look inside the first section (custom, types or imports, as in every real module), so random bytes
    after the magic aren't taken for a module."""
    if sid == 0:
        nlen, k = _leb(body, 0)
        return 0 < nlen <= len(body) - k and re.fullmatch(rb"[ -~]+", body[k:k + nlen]) is not None
    count, k = _leb(body, 0)
    if sid == 1:                           # function types start with 0x60 (or a GC rec/sub type)
        return count > 0 and body[k] in (0x60, 0x4E, 0x50, 0x4F, 0x5E, 0x5F)
    if sid == 2:                           # imports start with a module name
        nlen, k2 = _leb(body, k)
        return count > 0 and 0 < nlen and re.fullmatch(rb"[ -~]+", body[k + k2:k + k2 + nlen]) is not None
    return False


@guarded
def parse_wasm(r: Reader) -> Hit | None:
    """WebAssembly module: sections (id, size) in the order the standard requires; the module ends after the
    last one (custom sections must carry a valid UTF-8 name)."""
    if r.read(0, 8) != b"\0asm\x01\0\0\0":
        return None
    pos, rank, count = 8, 0, 0
    while pos < r.limit and count < 100_000:
        b = r.read(pos, 16)
        if len(b) < 2 or b[0] > 13:
            break
        try:
            size, n = _leb(b, 1)
            if not count and not _wasm_first(r.read(pos + 1 + n, min(size, 300)), b[0]):
                return None
            if b[0] == 0:
                nlen, k = _leb(b, 1 + n)
                if size < k + nlen:
                    break
                r.read(pos + 1 + n + k, nlen).decode("utf-8")
            elif _WASM_ORDER[b[0]] <= rank:
                break
            else:
                rank = _WASM_ORDER[b[0]]
        except (ValueError, IndexError):
            if not count:
                return None
            break
        pos += 1 + n + size
        count += 1
    if not count:
        return None
    return finish(r, "wasm", pos, CHANCE_GOOD, info={"sections": count})


# ====================================================================== the formats
FORMATS: list[Format] = [
    # e-mail
    Format("pst", "Outlook data file", "email", ("pst", "ost"), ((0, b"!BDN"),), parse_pst,
           max_size=256 * GiB, min_size=512, aliases=("ost", "outlook")),
    Format("dbx", "Outlook Express folder", "email", ("dbx",),
           ((0, b"\xcf\xad\x12\xfe\xc5\xfd\x74\x6f"), (0, b"\xcf\xad\x12\xfe\xc6\xfd\x74\x6f")), parse_dbx,
           max_size=2 * GiB, min_size=_DBX_HEADER),
    Format("mbox", "Mailbox", "email", ("mbox",), ((0, b"From "),), parse_mbox, max_size=16 * GiB, min_size=64),
    Format("eml", "E-mail message", "email", ("eml",),
           tuple((0, m) for m in (b"Received:", b"Return-Path:", b"From:", b"Delivered-To:", b"Message-ID:",
                                  b"MIME-Version:", b"X-Mozilla-Status:", b"Date:")),
           parse_eml, max_size=256 * MiB, min_size=64, enabled=False),
    Format("msf", "Thunderbird mail summary", "email", ("msf",), ((0, b"// <!-- <mdb:mork:z"),), parse_msf,
           max_size=GiB, min_size=32),
    # databases
    Format("sqlite", "SQLite database", "database", ("sqlite", "db", "sqlite3"), ((0, b"SQLite format 3\0"),),
           parse_sqlite, max_size=256 * GiB, min_size=512, aliases=("sqlite3", "db")),
    Format("mdb", "Access database", "database", ("mdb", "accdb"),
           ((4, b"Standard Jet DB\0"), (4, b"Standard ACE DB\0")), parse_mdb, max_size=2 * GiB, min_size=4096,
           aliases=("accdb", "access")),
    Format("kdbx", "KeePass database", "database", ("kdbx",), ((0, _KDBX_SIG),), parse_kdbx,
           max_size=GiB, min_size=100, aliases=("keepass",)),
    Format("kdb", "KeePass 1 database", "database", ("kdb",), ((0, _KDB_SIG),), parse_kdb,
           max_size=256 * MiB, min_size=124),
    Format("regf", "Windows registry hive", "database", ("dat",), ((0, b"regf"),), parse_regf,
           min_size=8192, aliases=("registry", "hive")),
    Format("evtx", "Windows event log", "other", ("evtx",), ((0, b"ElfFile\0"),), parse_evtx,
           min_size=4096 + 65536),
    Format("edb", "ESE database", "database", ("edb",), ((4, b"\xef\xcd\xab\x89"),), parse_edb,
           max_size=64 * GiB, min_size=8192, aliases=("ese",)),
    Format("dbf", "dBase table", "database", ("dbf",), tuple((0, bytes([v])) for v in sorted(_DBF_VERSIONS)),
           parse_dbf, max_size=2 * GiB, min_size=66, enabled=False, aliases=("dbase",)),
    # programs
    Format("exe", "Windows program", "executable", ("exe", "dll", "sys", "efi"), ((0, b"MZ"),), parse_pe,
           min_size=256, aliases=("dll", "pe", "sys", "efi")),
    Format("elf", "Linux program", "executable", ("elf", "so", "o", "ko", "core"), ((0, b"\x7fELF"),), parse_elf,
           max_size=64 * GiB, min_size=52, aliases=("so",)),
    Format("macho", "macOS program", "executable", ("macho", "dylib", "bundle", "o", "a"),
           tuple((0, m) for m in _MACHO_MAGIC) + ((0, b"\xca\xfe\xba\xbe"), (0, b"\xca\xfe\xba\xbf")),
           parse_mach,
           min_size=28, aliases=("dylib", "mach-o")),
    Format("class", "Java class", "executable", ("class",), ((0, b"\xca\xfe\xba\xbe"),), parse_class,
           max_size=64 * MiB, min_size=32),
    Format("dex", "Android program (DEX)", "executable", ("dex",), ((0, b"dex\n0"),), parse_dex,
           max_size=GiB, min_size=0x70),
    Format("wasm", "WebAssembly module", "executable", ("wasm",), ((0, b"\0asm\x01\0\0\0"),), parse_wasm,
           max_size=GiB, min_size=9),
]
