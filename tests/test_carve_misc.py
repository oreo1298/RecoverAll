"""Tests for the e-mail, database, program and "other" signatures (recoverall/core/carve/misc.py, misc2.py).

Every sample is built here (or taken from the system when present: fonts, ELF programs), planted at a block
boundary inside random data, and parsed through base.Reader and through the engine.
"""

import base64
import glob
import hashlib
import os
import plistlib
import random
import sqlite3
import struct
import zlib

import pytest

from recoverall.core.blockio import BytesSource
from recoverall.core.carve import misc, misc2
from recoverall.core.carve.base import CATEGORIES, CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, Hit, Reader

try:
    import lzma
except ImportError:
    lzma = None

ALL = misc.FORMATS + misc2.FORMATS
FMT = {f.key: f for f in ALL}
PAD = 2048          # what comes before a planted sample (random), in bytes: a block boundary


def noise(n: int, seed: int = 7) -> bytes:
    return random.Random(seed * 1000003 + n).randbytes(n)


def align(v: int, a: int) -> int:
    return (v + a - 1) // a * a


def plant(data: bytes, tail: str = "random", after: int = 8192) -> BytesSource:
    rest = noise(after, 99) if tail == "random" else b"\0" * after
    return BytesSource(noise(PAD, 1) + data + rest)


def parse(key: str, data: bytes, tail: str = "random", after: int = 8192) -> Hit | None:
    """Parse DATA planted at a block boundary in random data, followed by random bytes (or zeros: the slack
    after a text file)."""
    return FMT[key].parse(Reader(plant(data, tail, after), PAD))


def check(key: str, data: bytes, ext: str, tail: str = "random", length: int | None = -1,
          chance: int = CHANCE_GOOD) -> Hit:
    hit = parse(key, data, tail)
    assert hit is not None, key
    assert hit.ext == ext
    assert hit.ext in FMT[key].exts
    assert hit.length == (len(data) if length == -1 else length)
    assert hit.chance == chance
    return hit


# ====================================================================== sample builders
# ---------------------------------------------------------------------- e-mail
def weak_crc(data: bytes) -> int:
    """MS-PST ComputeCRC, bit by bit (CRC-32 polynomial, no pre/post inversion): independent of the parser."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    return crc


def make_pst(size: int = 16384, unicode: bool = True, client: bytes = b"SM") -> bytes:
    h = bytearray(564 if unicode else 512)
    h[0:4], h[8:10] = b"!BDN", client
    struct.pack_into("<HH", h, 10, 23 if unicode else 14, 19)
    h[14:16] = b"\x01\x01"
    if unicode:
        struct.pack_into("<Q", h, 184, size)
        h[512], h[513] = 0x80, 1
        struct.pack_into("<I", h, 4, weak_crc(h[8:479]))
        struct.pack_into("<I", h, 524, weak_crc(h[8:524]))
    else:
        struct.pack_into("<I", h, 168, size)
        h[460], h[461] = 0x80, 1
        struct.pack_into("<I", h, 4, weak_crc(h[8:479]))
    return bytes(h) + noise(size - len(h))


def make_dbx(size: int = 0x24BC + 0x2000) -> bytes:
    h = bytearray(0x24BC)
    h[0:20] = bytes.fromhex("cfad12fec5fd746f66e3d1119a4e00c04fa309d4")
    struct.pack_into("<I", h, 0xC4, size)
    struct.pack_into("<I", h, 0xE4, 0x24BC)
    return bytes(h) + struct.pack("<I", 0x24BC) + noise(size - 0x24BC - 4)


MAIL = (b"Return-Path: <alice@example.com>\n"
        b"Received: from mail.example.com (mail.example.com [192.0.2.1])\n"
        b"\tby mx.example.org with ESMTP id 12345\n"
        b"From: Alice <alice@example.com>\n"
        b"To: bob@example.org\n"
        b"Subject: =?utf-8?q?Holiday_photos?=\n"
        b"Date: Mon, 2 Jan 2023 10:00:00 +0000\n"
        b"Message-ID: <1234@example.com>\n"
        b"\n" + b"Hello Bob, here they are.\n" * 40)


def make_mbox() -> bytes:
    return (b"From alice@example.com Mon Jan  2 10:00:00 2023\n" + MAIL + b"\n"
            b"From - Tue Jan  3 11:00:00 2023\nX-Mozilla-Status: 0001\n" + MAIL + b"\n")


# ---------------------------------------------------------------------- databases
def make_sqlite(tmp_path, rows: int = 300, page_size: int = 4096) -> bytes:
    p = tmp_path / f"test{page_size}.db"
    con = sqlite3.connect(p)
    con.execute(f"pragma page_size = {page_size}")
    con.execute("create table t (id integer primary key, v blob)")
    con.executemany("insert into t (v) values (?)", [(noise(300, i),) for i in range(rows)])
    con.commit()
    con.close()
    return p.read_bytes()


def kdbx_field(fid: int, data: bytes, v4: bool) -> bytes:
    return bytes([fid]) + (struct.pack("<I", len(data)) if v4 else struct.pack("<H", len(data))) + data


def make_mdb(ace: bool = False) -> bytes:
    sig = b"Standard ACE DB\0" if ace else b"Standard Jet DB\0"
    return b"\x00\x01\x00\x00" + sig + struct.pack("<I", 3 if ace else 1) + noise(4096 * 3 - 24, 3)


def make_kdbx(v4: bool = True) -> bytes:
    head = misc._KDBX_SIG + struct.pack("<HH", 0 if v4 else 1, 4 if v4 else 3)
    head += kdbx_field(2, noise(16, 1), v4) + kdbx_field(3, b"\1\0\0\0", v4) + kdbx_field(4, noise(32, 2), v4)
    head += kdbx_field(7, noise(12 if v4 else 16, 3), v4)
    head += kdbx_field(11, noise(80, 4), v4) if v4 else kdbx_field(6, b"\x60\xea\0\0\0\0\0\0", v4)
    head += kdbx_field(0, b"\r\n\r\n", v4)
    if not v4:
        return head + noise(3000, 5)
    out = head + hashlib.sha256(head).digest() + noise(32, 6)
    for i, n in enumerate((1500, 700)):
        out += noise(32, 10 + i) + struct.pack("<I", n) + noise(n, 20 + i)
    return out + noise(32, 30) + struct.pack("<I", 0)


def make_regf() -> bytes:
    h = bytearray(4096)
    h[0:4] = b"regf"
    ft = (1672531200 * 10_000_000) + 116444736000000000           # 2023-01-01
    struct.pack_into("<IIQIIIIIII", h, 4, 7, 7, ft, 1, 5, 0, 1, 0x20, 8192, 1)
    name = "\\??\\C:\\Users\\bob\\NTUSER.DAT"[-31:].encode("utf-16-le")
    h[48:48 + len(name)] = name
    x = 0
    for (w,) in struct.iter_unpack("<I", h[:508]):
        x ^= w
    struct.pack_into("<I", h, 508, x)
    bins = b""
    for i in range(2):
        bins += b"hbin" + struct.pack("<II", 4096 * i, 4096) + noise(4096 - 12, i)
    return bytes(h) + bins


def make_evtx(chunks: int = 2) -> bytes:
    h = bytearray(4096)
    h[0:8] = b"ElfFile\0"
    struct.pack_into("<QQQIHHH", h, 8, 0, chunks - 1, 100, 128, 1, 3, 4096)
    struct.pack_into("<H", h, 42, chunks)
    struct.pack_into("<I", h, 124, zlib.crc32(h[:120]))
    return bytes(h) + b"".join(b"ElfChnk\0" + noise(65536 - 8, i) for i in range(chunks))


def make_edb() -> bytes:
    h = bytearray(4096)
    h[4:8] = b"\xef\xcd\xab\x89"
    struct.pack_into("<II", h, 8, 0x620, 0)
    struct.pack_into("<I", h, 52, 3)
    struct.pack_into("<I", h, 236, 4096)
    return bytes(h) + bytes(h) + noise(4096 * 4)


def make_dbf(records: int = 20) -> bytes:
    fields = [(b"NAME", b"C", 10), (b"AGE", b"N", 3)]
    hlen = 32 + 32 * len(fields) + 1
    rlen = 1 + sum(f[2] for f in fields)
    h = struct.pack("<BBBBIHH20x", 0x03, 123, 4, 5, records, hlen, rlen)
    for name, typ, ln in fields:
        h += name.ljust(11, b"\0") + typ + b"\0" * 4 + bytes([ln, 0]) + b"\0" * 14
    h += b"\x0d"
    recs = b"".join(b" " + (b"Name%06d" % i).ljust(10) + b"%3d" % (i % 100) for i in range(records))
    return h + recs + b"\x1a"


# ---------------------------------------------------------------------- programs
def make_pe(plus: bool = False, dll: bool = False, subsystem: int = 3, export: str | None = None,
            cert: bool = False, nsis: bool = False, stamp: int = 1600000000, symbols: bool = False
            ) -> tuple[bytes, int]:
    """A minimal valid PE32 / PE32+ (and where it ends without overlay data)."""
    fa, sa, lfanew = 0x200, 0x1000, 0x80
    optsize = 240 if plus else 224
    secs = [(b".text", bytearray(noise(0x300, 1))), (b".rdata", bytearray(noise(0x150, 2)))]
    if export:
        secs.append((b".edata", bytearray(40) + export.encode() + b"\0"))
    size_headers = align(lfanew + 24 + optsize + 40 * len(secs), fa)
    table, raw, va, exp_va = b"", size_headers, sa, 0
    for name, data in secs:
        if name == b".edata":
            exp_va = va
            struct.pack_into("<I", data, 12, va + 40)
        table += struct.pack("<8sIIIIIIHHI", name, len(data), va, align(len(data), fa), raw, 0, 0, 0, 0,
                             0x60000020)
        raw += align(len(data), fa)
        va += align(len(data), sa)
    image_end, size_image = raw, va
    opt = bytearray(optsize)
    struct.pack_into("<HBB", opt, 0, 0x20B if plus else 0x10B, 14, 0)
    struct.pack_into("<I", opt, 16, sa)
    if plus:
        struct.pack_into("<Q", opt, 24, 0x140000000)
    else:
        struct.pack_into("<I", opt, 28, 0x400000)
    struct.pack_into("<IIHHHHHH", opt, 32, sa, fa, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<IIIHH", opt, 56, size_image, size_headers, 0, subsystem, 0x8160)
    dd = 112 if plus else 96
    struct.pack_into("<I", opt, dd - 4, 16)
    if export:
        struct.pack_into("<II", opt, dd, exp_va, 40 + len(export) + 1)
    tail = b""
    symptr = nsyms = 0
    if symbols:                                   # MinGW keeps COFF symbols and their strings at the end
        symptr, nsyms = image_end, 3
        tail += noise(18 * nsyms, 7) + struct.pack("<I", 4 + 16) + b"a_long_symbol_n\0"
    if nsis:
        payload = noise(3000, 5)
        tail += struct.pack("<II", 0, 0xDEADBEEF) + b"NullsoftInst" + struct.pack("<II", 1000, 28 + len(payload) + 4)
        tail += payload + b"\0\0\0\0"
    if cert:
        off = image_end + len(tail)
        blob = noise(600, 6)
        struct.pack_into("<II", opt, dd + 32, off, 8 + len(blob))
        tail += struct.pack("<IHH", 8 + len(blob), 0x200, 2) + blob
    chars = 0x0022 | (0x2000 if dll else 0) | (0 if plus else 0x0100)
    coff = struct.pack("<4sHHIIIHH", b"PE\0\0", 0x8664 if plus else 0x14C, len(secs), stamp, symptr, nsyms, optsize,
                       chars)
    dos = bytearray(lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, lfanew)
    head = bytes(dos) + coff + bytes(opt) + table
    body = b"".join(bytes(d).ljust(align(len(d), fa), b"\0") for _n, d in secs)
    return head.ljust(size_headers, b"\0") + body + tail, image_end


def make_elf(bits: int = 64, little: bool = True, etype: int = 3, interp: bool = True, modinfo: bool = False
             ) -> bytes:
    bo = "<" if little else ">"
    eh, pe, se = (64, 56, 64) if bits == 64 else (52, 32, 40)
    phnum = 0 if etype == 1 else (2 if interp else 1)
    text = noise(700, 3)
    shstr = b"\0.text\0.shstrtab\0.bss\0" + (b".modinfo\0" if modinfo else b"")
    phoff = eh if phnum else 0
    text_off = eh + phnum * pe
    shstr_off = text_off + len(text)
    shoff = align(shstr_off + len(shstr), 8)
    secs = [(0, 0, 0, 0), (1, 1, text_off, len(text)), (7, 3, shstr_off, len(shstr)), (17, 8, shoff, 0x10000)]
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1 if little else 2, 1, 0]) + bytes(8)
    if bits == 64:
        hdr = ident + struct.pack(bo + "HHIQQQIHHHHHH", etype, 62, 1, 0x1000, phoff, shoff, 0, eh, pe, phnum, se,
                                  len(secs), 2)
    else:
        hdr = ident + struct.pack(bo + "HHIIIIIHHHHHH", etype, 8, 1, 0x1000, phoff, shoff, 0, eh, pe, phnum, se,
                                  len(secs), 2)
    phs = [(1, 0, text_off + len(text)), (3, text_off, 28)][:phnum]
    ph = b""
    for ptype, off, size in phs:
        if bits == 64:
            ph += struct.pack(bo + "IIQQQQQQ", ptype, 5, off, 0x400000 + off, 0, size, size, 0x1000)
        else:
            ph += struct.pack(bo + "IIIIIIII", ptype, off, 0x400000 + off, 0, size, size, 5, 0x1000)
    sh = b""
    for name, typ, off, size in secs:
        if bits == 64:
            sh += struct.pack(bo + "IIQQQQIIQQ", name, typ, 0, 0, off, size, 0, 0, 1, 0)
        else:
            sh += struct.pack(bo + "IIIIIIIIII", name, typ, 0, 0, off, size, 0, 0, 1, 0)
    return (hdr + ph + text + shstr).ljust(shoff, b"\0") + sh


def make_macho(ftype: int = 2, cpu: int = 0x01000007) -> bytes:
    seg = struct.pack("<II16sQQQQIIII", 0x19, 72 + 80, b"__TEXT", 0x100000000, 0x2000, 0, 0x1000, 5, 5, 1, 0)
    sect = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", 0x100000F00, 0x100, 0xF00, 4, 0, 0, 0x80000400,
                       0, 0, 0)
    linkedit = struct.pack("<II16sQQQQIIII", 0x19, 72, b"__LINKEDIT", 0x100002000, 0x1000, 0x1000, 0x900, 1, 1, 0, 0)
    symtab = struct.pack("<IIIIII", 0x2, 24, 0x1000, 4, 0x1040, 0x100)
    codesig = struct.pack("<IIII", 0x1D, 16, 0x1900, 0x340)
    cmds = seg + sect + linkedit + symtab + codesig
    head = struct.pack("<IIIIIIII", 0xFEEDFACF, cpu, 3, ftype, 4, len(cmds), 0x200085, 0)
    end = 0x1900 + 0x340
    return head + cmds + noise(end - len(head) - len(cmds), 4)


def make_fat() -> tuple[bytes, int]:
    a, b = make_macho(2, 0x01000007), make_macho(2, 0x0100000C)
    off1 = 0x1000
    off2 = align(off1 + len(a), 0x4000)
    head = struct.pack(">II", 0xCAFEBABE, 2) + struct.pack(">IIIII", 0x01000007, 3, off1, len(a), 12)
    head += struct.pack(">IIIII", 0x0100000C, 0, off2, len(b), 14)
    data = head.ljust(off1, b"\0") + a
    return data.ljust(off2, b"\0") + b, off2 + len(b)


def utf8(s: str) -> bytes:
    return b"\x01" + struct.pack(">H", len(s)) + s.encode()


def make_class(name: str = "com/example/Hello") -> bytes:
    cp = [utf8(name), b"\x07\x00\x01", utf8("java/lang/Object"), b"\x07\x00\x03", utf8("Code"), utf8("<init>"),
          utf8("()V"), b"\x05" + struct.pack(">q", 1234), utf8("SourceFile"), utf8("Hello.java"),
          b"\x0a\x00\x04\x00\x0d", b"\x0c\x00\x06\x00\x07"]
    count = 1 + len(cp) + 1                      # the long takes two slots
    out = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, count) + b"".join(cp)
    out += struct.pack(">HHHH", 0x21, 2, 4, 0)
    out += struct.pack(">H", 1) + struct.pack(">HHHH", 0x2, 6, 7, 0)          # one field, no attributes
    code = struct.pack(">HHI", 1, 1, 5) + b"\x2a\xb7\x00\x0b\xb1" + struct.pack(">HH", 0, 0)
    out += struct.pack(">H", 1) + struct.pack(">HHHH", 0x1, 6, 7, 1) + struct.pack(">HI", 5, len(code)) + code
    out += struct.pack(">H", 1) + struct.pack(">HIH", 10, 2, 11)
    return out


def make_dex(size: int = 0x600) -> bytes:
    d = bytearray(size)
    d[0:8] = b"dex\n035\0"
    struct.pack_into("<III", d, 32, size, 0x70, 0x12345678)
    struct.pack_into("<I", d, 52, size - 0x40)
    struct.pack_into("<II", d, 104, size - 0x100, 0x100)
    d[0x100:] = noise(size - 0x100, 8)
    d[12:32] = hashlib.sha1(d[32:]).digest()
    struct.pack_into("<I", d, 8, zlib.adler32(bytes(d[12:])))
    return bytes(d)


def make_wasm() -> bytes:
    def sec(sid: int, body: bytes) -> bytes:
        return bytes([sid, len(body)]) + body
    return (b"\0asm\x01\0\0\0" + sec(1, b"\x01\x60\x00\x01\x7f") + sec(3, b"\x01\x00")
            + sec(7, b"\x01\x04main\x00\x00") + sec(10, b"\x01\x04\x00\x41\x2a\x0b")
            + sec(0, b"\x04name" + b"\x01\x07\x01\x00\x04main"))


# ---------------------------------------------------------------------- fonts
def table_sum(data: bytes) -> int:
    data += b"\0" * (-len(data) % 4)
    return sum(x for (x,) in struct.iter_unpack(">I", data)) & 0xFFFFFFFF


def make_name_table(full: str, family: str = "Test Sans") -> bytes:
    strings = [(1, family), (2, "Bold"), (4, full), (6, full.replace(" ", "-"))]
    recs, blob = b"", b""
    for nid, s in strings:
        enc = s.encode("utf-16-be")
        recs += struct.pack(">HHHHHH", 3, 1, 0x409, nid, len(enc), len(blob))
        blob += enc
    return struct.pack(">HHH", 0, len(strings), 6 + len(recs)) + recs + blob


def make_ttf(full: str = "Test Sans Bold") -> bytes:
    head = bytearray(54)
    struct.pack_into(">IIIIHH", head, 0, 0x00010000, 0x00010000, 0, 0x5F0F3CF5, 0x000B, 1000)
    tables = {b"cmap": struct.pack(">HH", 0, 0), b"head": head, b"hhea": bytes(36),
              b"maxp": struct.pack(">IH", 0x00005000, 1), b"name": make_name_table(full),
              b"post": struct.pack(">I", 0x00030000) + bytes(28), b"OS/2": noise(78, 3)}
    n = len(tables)
    p = 1 << (n.bit_length() - 1)
    out = struct.pack(">IHHHH", 0x00010000, n, p * 16, p.bit_length() - 1, n * 16 - p * 16)
    off = 12 + 16 * n
    dirs, body = b"", b""
    for tag in sorted(tables):
        data = bytes(tables[tag])
        dirs += struct.pack(">4sIII", tag, table_sum(data), off + len(body), len(data))
        body += data + b"\0" * (-len(data) % 4)
    font = bytearray(out + dirs + body)
    head_at = struct.unpack_from(">I", dirs, 16 * sorted(tables).index(b"head") + 8)[0]
    struct.pack_into(">I", font, head_at + 8, (0xB1B0AFBA - table_sum(bytes(font))) & 0xFFFFFFFF)
    return bytes(font)


def make_woff(ttf: bytes) -> bytes:
    n = struct.unpack_from(">H", ttf, 4)[0]
    entries = [struct.unpack_from(">4sIII", ttf, 12 + 16 * i) for i in range(n)]
    off = 44 + 20 * n
    dirs, body = b"", b""
    for tag, csum, toff, tlen in entries:
        data = ttf[toff:toff + tlen]
        comp = zlib.compress(data)
        data = comp if len(comp) < len(data) else data
        dirs += struct.pack(">4sIIII", tag, off + len(body), len(data), tlen, csum)
        body += data + b"\0" * (-len(data) % 4)
    total = off + len(body)
    return struct.pack(">4s4sIHHIHHIIIII", b"wOFF", ttf[:4], total, n, 0, len(ttf), 1, 0, 0, 0, 0, 0, 0) + dirs + body


def make_woff2() -> bytes:
    comp = noise(900, 4)
    dirs = b"\x05" * 6                                     # six tables with known tags (one byte each)
    total = 48 + len(dirs) + len(comp)
    return struct.pack(">4s4sIHHIIHHIIIII", b"wOF2", b"\x00\x01\x00\x00", total, 6, 0, 4000, len(comp), 1, 0,
                       0, 0, 0, 0, 0) + dirs + comp


# ---------------------------------------------------------------------- other
def swf_tag(code: int, data: bytes, long: bool = False) -> bytes:
    if long or len(data) >= 63:
        return struct.pack("<HI", code << 6 | 0x3F, len(data)) + data
    return struct.pack("<H", code << 6 | len(data)) + data


def swf_body() -> bytes:
    nbits = 15
    bits = format(nbits, "05b") + "".join(format(v, f"0{nbits}b") for v in (0, 11000, 0, 8000))
    bits += "0" * (-len(bits) % 8)
    rect = int(bits, 2).to_bytes(len(bits) // 8, "big")
    return (rect + struct.pack("<HH", 0x1800, 1) + swf_tag(9, b"\xff\x00\x00") + swf_tag(39, noise(100, 2), True)
            + swf_tag(1, b"") + swf_tag(0, b""))


def make_swf(kind: bytes) -> bytes:
    body = swf_body()
    full = struct.pack("<I", 8 + len(body))
    if kind == b"F":
        return b"FWS\x0a" + full + body
    if kind == b"C":
        return b"CWS\x0a" + full + zlib.compress(body)
    c = lzma.compress(body, format=lzma.FORMAT_ALONE)
    return b"ZWS\x0d" + full + struct.pack("<I", len(c) - 13) + c[:5] + c[13:]


def bencode(v) -> bytes:
    if isinstance(v, int):
        return b"i%de" % v
    if isinstance(v, bytes):
        return b"%d:%s" % (len(v), v)
    if isinstance(v, list):
        return b"l" + b"".join(map(bencode, v)) + b"e"
    return b"d" + b"".join(bencode(k) + bencode(v[k]) for k in sorted(v)) + b"e"


def make_torrent() -> bytes:
    return bencode({b"announce": b"http://tracker.example.com/announce", b"creation date": 1600000000,
                    b"info": {b"name": b"holiday-video.mkv", b"piece length": 262144, b"length": 123456789,
                              b"pieces": noise(20 * 300, 9)}})


ICS = (b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Example//Cal//EN\r\nX-WR-CALNAME:Family\r\n"
       + b"".join(b"BEGIN:VEVENT\r\nUID:%d@example.com\r\nDTSTART:20230102T100000Z\r\nSUMMARY:Meeting %d\r\n"
                  b"END:VEVENT\r\n" % (i, i) for i in range(20))
       + b"END:VCALENDAR\r\n")


def vcard(name: str) -> bytes:
    return (b"BEGIN:VCARD\r\nVERSION:3.0\r\nN:%s;;;\r\nFN:%s\r\nTEL;TYPE=CELL:+1 555 0100\r\n"
            b"EMAIL:%s@example.com\r\nEND:VCARD\r\n" % (name.encode(), name.encode(), name.lower().encode()))


def pem_block(label: bytes, n: int, seed: int, headers: bytes = b"") -> bytes:
    b64 = base64.b64encode(noise(n, seed))
    lines = b"\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return b"-----BEGIN " + label + b"-----\n" + headers + lines + b"\n-----END " + label + b"-----\n"


PPK = (b"PuTTY-User-Key-File-2: ssh-rsa\r\nEncryption: none\r\nComment: backup-key\r\nPublic-Lines: 2\r\n"
       b"AAAAB3NzaC1yc2EAAAABJQAAAQEAhJ\r\nabcdef==\r\nPrivate-Lines: 1\r\nAAABAQCabc=\r\n"
       b"Private-MAC: " + b"0123456789abcdef0123456789abcdef01234567" + b"\r\n")


def make_lnk() -> bytes:
    flags = 0x1 | 0x2 | 0x8 | 0x80
    ft = 1672531200 * 10_000_000 + 116444736000000000
    hdr = struct.pack("<I16sIIQQQIiIHHII", 0x4C, misc2._LNK_CLSID, flags, 0x20, ft, ft, ft, 12345, 0, 1, 0, 0, 0, 0)
    idlist = struct.pack("<H", 20) + noise(18, 1) + b"\0\0"
    vol = struct.pack("<IIII", 0x11, 3, 0x1234, 0x10) + b"\0"
    base = b"C:\\Windows\\notepad.exe\0"
    vol_off = 0x1C
    base_off = vol_off + len(vol)
    suffix_off = base_off + len(base)
    size = suffix_off + 1
    info = struct.pack("<IIIIIII", size, 0x1C, 1, vol_off, base_off, 0, suffix_off) + vol + base + b"\0"
    rel = "..\\..\\Windows\\notepad.exe"
    strings = struct.pack("<H", len(rel)) + rel.encode("utf-16-le")
    extra = struct.pack("<II", 0x1C, 0xA000000B) + noise(0x14, 2) + b"\0\0\0\0"
    return hdr + struct.pack("<H", len(idlist)) + idlist + info + strings + extra


def make_blend(ptr8: bool = True, little: bool = True) -> bytes:
    bo = "<" if little else ">"
    out = b"BLENDER" + (b"-" if ptr8 else b"_") + (b"v" if little else b"V") + b"279"
    for i, (code, n) in enumerate(((b"REND", 72), (b"TEST", 500), (b"GLOB", 1024), (b"OB\0\0", 1300),
                                   (b"DNA1", 3000), (b"ENDB", 0))):
        out += struct.pack(bo + ("4siQii" if ptr8 else "4siIii"), code, n, 0x1000 + i, 0, 1) + noise(n, i)
    return out


LONG_VR = (b"OB", b"OW", b"SQ", b"UN", b"UT")


def dcm_el(group: int, elem: int, vr: bytes, value: bytes, bo: str = "<", explicit: bool = True) -> bytes:
    if not explicit:
        return struct.pack(bo + "HHI", group, elem, len(value)) + value
    if vr in LONG_VR:
        return struct.pack(bo + "HH2sHI", group, elem, vr, 0, len(value)) + value
    return struct.pack(bo + "HH2sH", group, elem, vr, len(value)) + value


def make_dicom(ts: bytes = b"1.2.840.10008.1.2.1", encapsulated: bool = False) -> bytes:
    tsv = ts + b"\0" * (len(ts) % 2)
    items = (dcm_el(2, 1, b"OB", b"\0\1") + dcm_el(2, 2, b"UI", b"1.2.840.10008.5.1.4.1.1.7\0")
             + dcm_el(2, 3, b"UI", b"1.2.3.4.5\0") + dcm_el(2, 0x10, b"UI", tsv))
    meta = dcm_el(2, 0, b"UL", struct.pack("<I", len(items))) + items
    implicit = ts == b"1.2.840.10008.1.2"
    bo = ">" if ts == b"1.2.840.10008.1.2.2" else "<"
    ex = not implicit

    def el(g, e, vr, value):
        return dcm_el(g, e, vr, value, bo, ex)

    undef = (struct.pack(bo + "HHI", 0x0008, 0x1140, 0xFFFFFFFF) if implicit
             else struct.pack(bo + "HH2sHI", 0x0008, 0x1140, b"SQ", 0, 0xFFFFFFFF))
    seq = (undef + struct.pack(bo + "HHI", 0xFFFE, 0xE000, 0xFFFFFFFF) + el(8, 0x1150, b"UI", b"1.2.3\0")
           + struct.pack(bo + "HHI", 0xFFFE, 0xE00D, 0) + struct.pack(bo + "HHI", 0xFFFE, 0xE0DD, 0))
    ds = el(8, 0x20, b"DA", b"20230102") + el(8, 0x60, b"CS", b"OT") + seq
    ds += el(0x28, 0x10, b"US", struct.pack(bo + "H", 4)) + el(0x28, 0x11, b"US", struct.pack(bo + "H", 6))
    if encapsulated:
        ds += struct.pack("<HH2sHI", 0x7FE0, 0x10, b"OB", 0, 0xFFFFFFFF) + struct.pack("<HHI", 0xFFFE, 0xE000, 0)
        ds += struct.pack("<HHI", 0xFFFE, 0xE000, 200) + noise(200, 3) + struct.pack("<HHI", 0xFFFE, 0xE0DD, 0)
    else:
        ds += el(0x7FE0, 0x10, b"OW", noise(4 * 6 * 2, 4))
    if ts == b"1.2.840.10008.1.2.1.99":
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        ds = c.compress(ds) + c.flush()
    return bytes(128) + b"DICM" + meta + ds


def fits_card(key: str, value=None) -> bytes:
    if value is None:
        return f"{key:<80}".encode()
    if isinstance(value, bool):
        v = f"{'T' if value else 'F':>20}"
    elif isinstance(value, int):
        v = f"{value:>20}"
    else:
        v = f"'{value:<8}'"
    return f"{key:<8}= {v}"[:80].ljust(80).encode()


def fits_header(cards: list[bytes]) -> bytes:
    data = b"".join(cards) + fits_card("END")
    return data + b" " * (-len(data) % 2880)


def make_fits() -> bytes:
    primary = fits_header([fits_card("SIMPLE", True), fits_card("BITPIX", 16), fits_card("NAXIS", 2),
                           fits_card("NAXIS1", 100), fits_card("NAXIS2", 50), fits_card("EXTEND", True),
                           fits_card("OBJECT", "M31"), fits_card("DATE-OBS", "2021-05-06T07:08:09"),
                           fits_card("HISTORY")])
    data = noise(100 * 50 * 2, 5)
    data += b"\0" * (-len(data) % 2880)
    ext = fits_header([fits_card("XTENSION", "BINTABLE"), fits_card("BITPIX", 8), fits_card("NAXIS", 2),
                       fits_card("NAXIS1", 12), fits_card("NAXIS2", 10), fits_card("PCOUNT", 0),
                       fits_card("GCOUNT", 1), fits_card("TFIELDS", 1), fits_card("TFORM1", "3J")])
    table = noise(120, 6) + b"\0" * (2880 - 120)
    return primary + data + ext + table


def make_bplist() -> bytes:
    return plistlib.dumps({"name": "Bob", "items": list(range(300)), "nested": {"a": b"\0\1\2" * 50, "b": 1.5},
                           "flag": True}, fmt=plistlib.FMT_BINARY)


# ---------------------------------------------------------------------- virtual disks
def make_vdi() -> bytes:
    h = bytearray(0x400)
    h[:0x28] = b"<<< Oracle VM VirtualBox Disk Image >>>\n"
    struct.pack_into("<IIIII", h, 0x40, 0xBEDA107F, 0x00010001, 0x190, 1, 0)
    struct.pack_into("<II", h, 0x154, 0x200, 0x400)
    struct.pack_into("<QIIII", h, 0x170, 4 * 65536, 65536, 0, 4, 2)
    struct.pack_into("<4I", h, 0x200, 0, 0xFFFFFFFF, 1, 0xFFFFFFFF)
    return bytes(h) + noise(2 * 65536, 7)


def vhd_sum(b: bytes, at: int) -> int:
    return ~sum(b[:at] + b"\0\0\0\0" + b[at + 4:]) & 0xFFFFFFFF


def make_vhd() -> bytes:
    f = bytearray(512)
    f[:8] = b"conectix"
    struct.pack_into(">IIQI4sI4sQQIII", f, 8, 2, 0x00010000, 512, 0, b"vpc ", 0x00050003, b"Wi2k", 1 << 20, 1 << 20,
                     0, 3, 0)
    struct.pack_into(">I", f, 64, vhd_sum(f, 64))
    d = bytearray(1024)
    d[:8] = b"cxsparse"
    struct.pack_into(">QQIII", d, 8, 0xFFFFFFFFFFFFFFFF, 1536, 0x00010000, 4, 65536)
    struct.pack_into(">I", d, 36, vhd_sum(d, 36))
    bat = struct.pack(">4I", 4, 0xFFFFFFFF, 4 + 1 + 128, 0xFFFFFFFF).ljust(512, b"\xff")
    blocks = (b"\xff" * 512 + noise(65536, 1)) * 2
    return bytes(f) + bytes(d) + bat + blocks + bytes(f)


def make_qcow2() -> bytes:
    cs = 4096
    h = bytearray(cs * 7)
    struct.pack_into(">4sIQIIQIIQQIIQ", h, 0, b"QFI\xfb", 3, 0, 0, 12, 1 << 20, 0, 1, cs, 2 * cs, 1, 0, 0)
    struct.pack_into(">QQQII", h, 72, 0, 0, 0, 4, 104)
    struct.pack_into(">Q", h, 2 * cs, 3 * cs)                    # refcount table → refcount block
    for i in range(7):
        struct.pack_into(">H", h, 3 * cs + 2 * i, 1)
    h[5 * cs:] = noise(2 * cs, 3)
    return bytes(h)


def make_vmdk() -> bytes:
    h = bytearray(512)
    struct.pack_into("<4sIIQQQQIQQQB4sH", h, 0, b"KDMV", 1, 3, 2048, 16, 1, 1, 512, 0, 2, 8, 0, b"\n \r\n", 0)
    desc = b"# Disk DescriptorFile\nversion=1\n".ljust(512, b"\0")
    gd = struct.pack("<I", 3).ljust(512, b"\0")
    gt = struct.pack("<512I", *([8, 0, 0, 0, 0, 24] + [0] * 506))
    return bytes(h) + desc + gd + gt + b"\0" * 512 + noise(16 * 512, 1) + noise(16 * 512, 2)


def make_vmdk_stream() -> bytes:
    h = bytearray(512)
    struct.pack_into("<4sIIQQQQIQQQB4sH", h, 0, b"KDMV", 3, 0x30001, 2048, 128, 0, 0, 512, 0, 0xFFFFFFFFFFFFFFFF, 1,
                     0, b"\n \r\n", 1)
    grain = zlib.compress(noise(65536, 4))
    out = bytes(h) + (struct.pack("<QI", 0, len(grain)) + grain).ljust(align(12 + len(grain), 512), b"\0")
    for kind, sectors in ((1, 4), (2, 1), (3, 1)):
        out += struct.pack("<QII", sectors, 0, kind).ljust(512, b"\0") + noise(512 * sectors, kind)
    return out + bytes(512)


def make_vhdx() -> bytes:
    MiB = 1 << 20
    img = bytearray(5 * MiB)
    img[:8] = b"vhdxfile"
    for i, at in enumerate((64 * 1024, 128 * 1024)):
        struct.pack_into("<4sIQ", img, at, b"head", 0, i + 1)
        struct.pack_into("<HHIQ", img, at + 64, 0, 1, MiB, MiB)
    for at in (192 * 1024, 256 * 1024):
        struct.pack_into("<4sIII", img, at, b"regi", 0, 2, 0)
        img[at + 16:at + 48] = misc2._VHDX_BAT + struct.pack("<QII", 3 * MiB, MiB, 1)
        img[at + 48:at + 80] = misc2._VHDX_META + struct.pack("<QII", 2 * MiB, MiB, 1)
    m = 2 * MiB
    img[m:m + 8] = b"metadata"
    struct.pack_into("<H", img, m + 10, 2)
    img[m + 32:m + 64] = misc2._VHDX_PARAMS + struct.pack("<IIII", 65536, 8, 0, 0)
    img[m + 64:m + 96] = misc2._VHDX_SECTOR + struct.pack("<IIII", 65536 + 8, 4, 0, 0)
    struct.pack_into("<II", img, m + 65536, MiB, 0)
    struct.pack_into("<I", img, m + 65536 + 8, 512)
    struct.pack_into("<Q", img, 3 * MiB, 6 | (4 << 20))               # block 0: fully present at 4 MiB
    img[4 * MiB:4 * MiB + 4096] = noise(4096, 2)
    return bytes(img)


# ====================================================================== per-format tests
def test_format_table():
    keys = [f.key for f in ALL]
    assert len(keys) == len(set(keys))
    for f in ALL:
        assert f.category in CATEGORIES and f.exts and f.magic and callable(f.parse)
        assert all(isinstance(m, bytes) and m and off >= 0 for off, m in f.magic)
    assert not FMT["eml"].enabled and not FMT["dbf"].enabled
    assert not any(FMT[k].enabled for k in ("vdi", "vhd", "vhdx", "qcow2", "vmdk"))
    assert FMT["evtx"].category == "other" and FMT["dcm"].category == "photo"


@pytest.mark.parametrize("unicode,client,ext", [(True, b"SM", "pst"), (False, b"SM", "pst"), (True, b"SO", "ost")])
def test_pst(unicode, client, ext):
    hit = check("pst", make_pst(unicode=unicode, client=client), ext)
    assert hit.info["format"] == ("Unicode" if unicode else "ANSI")


def test_pst_bad_crc_is_only_fair():
    data = bytearray(make_pst())
    data[200] ^= 0xFF
    check("pst", bytes(data), "pst", chance=CHANCE_FAIR)


def test_dbx():
    check("dbx", make_dbx(), "dbx", chance=CHANCE_FAIR)


def test_mbox_and_eml():
    hit = check("mbox", make_mbox(), "mbox", tail="zeros", chance=CHANCE_FAIR)
    assert hit.mtime == 1672653600
    assert parse("mbox", b"From someone who wrote a letter\nDear Sir,\n\n", tail="zeros") is None
    hit = check("eml", MAIL, "eml", tail="zeros", chance=CHANCE_FAIR)
    assert hit.name == "Holiday photos" and hit.mtime == 1672653600
    assert parse("eml", b"From: x\nnot a header line\n\n" + b"x" * 100, tail="zeros") is None
    msf = b'// <!-- <mdb:mork:z v="1.4"/> -->\n< <(a=c)> // (f=iso-8859-1)\n  (B8=Subject)(B9=From)>\n' * 3
    check("msf", msf, "msf", tail="zeros", chance=CHANCE_FAIR)


def test_sqlite(tmp_path):
    data = make_sqlite(tmp_path)
    assert len(data) > 20 * 4096
    hit = check("sqlite", data, "sqlite")
    assert hit.info["pages"] == len(data) // 4096
    big = make_sqlite(tmp_path, 400, 65536)
    hit = check("sqlite", big, "sqlite")
    assert hit.info["page_size"] == 65536 and hit.info["pages"] == len(big) // 65536
    stale = bytearray(data)
    struct.pack_into(">I", stale, 92, 1)          # "version-valid-for" no longer current: size unknown
    check("sqlite", bytes(stale), "sqlite", length=None, chance=CHANCE_FAIR)


def test_open_ended_databases():
    check("mdb", make_mdb(), "mdb", length=None, chance=CHANCE_FAIR)
    check("mdb", make_mdb(ace=True), "accdb", length=None, chance=CHANCE_FAIR)
    check("edb", make_edb(), "edb", length=None, chance=CHANCE_FAIR)
    kdb = misc._KDB_SIG + struct.pack("<II", 3, 0x00030004) + noise(32, 1) + struct.pack("<II", 3, 10)
    kdb += noise(64, 2) + struct.pack("<I", 6000) + noise(1024, 3)
    hit = check("kdb", kdb, "kdb", length=None, chance=CHANCE_FAIR)
    assert hit.info == {"groups": 3, "entries": 10}
    check("kdbx", make_kdbx(v4=False), "kdbx", length=None, chance=CHANCE_FAIR)


def test_kdbx4():
    hit = check("kdbx", make_kdbx(), "kdbx")
    assert hit.info["version"] == "4.0"


def test_regf():
    hit = check("regf", make_regf(), "dat")
    assert hit.name == "NTUSER" and hit.mtime == 1672531200
    bad = bytearray(make_regf())
    bad[100] ^= 1                                 # checksum no longer matches
    assert parse("regf", bytes(bad)) is None


def test_evtx():
    hit = check("evtx", make_evtx(), "evtx")
    assert hit.info["chunks"] == 2
    dirty = bytearray(make_evtx(3))
    struct.pack_into("<H", dirty, 42, 1)          # a stale chunk count: the chunks present count too
    check("evtx", bytes(dirty), "evtx", chance=CHANCE_FAIR)


def test_dbf():
    data = make_dbf()
    hit = check("dbf", data, "dbf")
    assert hit.info == {"records": 20, "fields": 2}
    assert hit.mtime == 1680652800                # 2023-04-05


@pytest.mark.parametrize("plus", [False, True])
def test_pe(plus):
    data, _ = make_pe(plus=plus)
    hit = check("exe", data, "exe")
    assert hit.info["format"] == ("PE32+" if plus else "PE32") and hit.mtime == 1600000000
    assert hit.info["machine"] == ("x86-64" if plus else "x86")


def test_pe_kinds_and_overlays():
    data, _ = make_pe(plus=True, dll=True, export="KERNELX.dll")
    hit = check("exe", data, "dll")
    assert hit.name == "KERNELX"
    check("exe", make_pe(subsystem=1)[0], "sys")
    check("exe", make_pe(plus=True, subsystem=10)[0], "efi")
    data, image_end = make_pe(plus=True, cert=True)
    assert len(data) > image_end
    check("exe", data, "exe")                     # the Authenticode signature is kept
    data, image_end = make_pe(nsis=True, cert=True)
    check("exe", data, "exe")                     # NSIS payload and signature
    data, image_end = make_pe(symbols=True)
    assert len(data) == image_end + 18 * 3 + 20
    check("exe", data, "exe")


def test_pe_rejects_dos_and_garbage():
    data, _ = make_pe()
    bad = bytearray(data)
    bad[0x80:0x84] = b"NE\0\0"
    assert parse("exe", bytes(bad)) is None
    bad = bytearray(data)
    struct.pack_into("<I", bad, 0x3C, 0x7FFFFFF0)
    assert parse("exe", bytes(bad)) is None


@pytest.mark.parametrize("bits,little,etype,interp,ext", [
    (64, True, 3, True, "elf"), (64, True, 3, False, "so"), (32, False, 2, False, "elf"),
    (32, True, 1, False, "o"), (64, False, 4, False, "core")])
def test_elf(bits, little, etype, interp, ext):
    data = make_elf(bits, little, etype, interp)
    hit = check("elf", data, ext)
    assert hit.info["bits"] == bits


def test_elf_kernel_module():
    check("elf", make_elf(64, True, 1, False, modinfo=True), "ko")


def test_elf_system_programs():
    found = 0
    for path in ("/bin/ls", "/bin/true", "/usr/bin/env"):
        if os.path.isfile(path):
            data = open(path, "rb").read()
            if data[:4] == b"\x7fELF":
                assert parse("elf", data).length == len(data)
                found += 1
    if not found:
        pytest.skip("no ELF programs on this system")


def test_macho():
    hit = check("macho", make_macho(), "macho")
    assert hit.info["machine"] == "x86-64"
    check("macho", make_macho(6, 0x0100000C), "dylib")
    data, end = make_fat()
    hit = check("macho", data, "macho")
    assert hit.info["architectures"] == "x86-64, ARM64"
    bad = bytearray(make_macho())
    struct.pack_into("<I", bad, 20, 0x10000)      # sizeofcmds no longer matches the commands
    assert parse("macho", bytes(bad)) is None


def test_java_class():
    data = make_class()
    hit = check("class", data, "class")
    assert hit.name == "Hello" and hit.info["java"] == "8"
    assert FMT["macho"].parse(Reader(plant(data), PAD)) is None    # same magic, not a universal binary
    assert FMT["class"].parse(Reader(plant(make_fat()[0]), PAD)) is None


def test_dex_and_wasm():
    data = make_dex()
    check("dex", data, "dex")
    bad = bytearray(data)
    bad[0x300] ^= 1                               # checksum fails: still the right size, lower chance
    check("dex", bytes(bad), "dex", chance=CHANCE_FAIR)
    check("wasm", make_wasm(), "wasm", tail="zeros")


def test_font():
    data = make_ttf()
    hit = check("ttf", data, "ttf")
    assert hit.name == "Test Sans Bold"
    otf = b"OTTO" + data[4:]
    assert parse("ttf", otf).ext == "otf"


def test_system_fonts():
    fonts = sorted(glob.glob("/usr/share/fonts/**/*.ttf", recursive=True))[:15]
    fonts += sorted(glob.glob("/usr/share/fonts/**/*.ttc", recursive=True))[:2]
    if not fonts:
        pytest.skip("no fonts installed")
    for path in fonts:
        data = open(path, "rb").read()
        hit = parse("ttf", data, tail="zeros")
        assert hit is not None and hit.length == align(len(data), 4), path
        assert hit.ext == ("ttc" if path.endswith(".ttc") else "otf" if data[:4] == b"OTTO" else "ttf")


def test_woff():
    hit = check("woff", make_woff(make_ttf("Compressed Sans Regular")), "woff")
    assert hit.name == "Compressed Sans Regular"
    check("woff", make_woff2(), "woff2")


@pytest.mark.parametrize("kind", [b"F", b"C", b"Z"])
def test_swf(kind):
    if kind == b"Z" and lzma is None:
        pytest.skip("Python without lzma")
    hit = check("swf", make_swf(kind), "swf")
    assert (hit.info["width"], hit.info["height"]) == (550, 400)


def test_torrent():
    hit = check("torrent", make_torrent(), "torrent")
    assert hit.name == "holiday-video.mkv" and hit.mtime == 1600000000


def test_calendar_and_contacts():
    hit = check("ics", ICS, "ics", tail="zeros")
    assert hit.name == "Family" and hit.info["events"] == 20
    cards = vcard("Alice") + vcard("Bob") + b"\r\n" + vcard("Carol")
    hit = check("vcf", cards, "vcf", tail="zeros")
    assert hit.info["contacts"] == 3 and hit.name is None
    hit = check("vcf", vcard("Alice Smith"), "vcf", tail="zeros")
    assert hit.name == "Alice Smith"
    # a card followed by unrelated text ends at its END line
    check("vcf", vcard("Bob"), "vcf", tail="zeros")
    hit = parse("vcf", vcard("Bob") + b"some other text that follows\n", tail="zeros")
    assert hit.length == len(vcard("Bob"))
    # no END line: the text is kept, but as damaged
    hit = parse("vcf", vcard("Bob")[:-12], tail="zeros")
    assert hit.chance == CHANCE_POOR


def test_pem():
    bundle = pem_block(b"CERTIFICATE", 900, 1) + b"\n" + pem_block(b"CERTIFICATE", 700, 2)
    hit = check("pem", bundle, "crt", tail="zeros")
    assert hit.info == {"type": "certificate", "blocks": 2}
    key = pem_block(b"RSA PRIVATE KEY", 1200, 3, b"Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00FF\n\n")
    check("pem", key, "key", tail="zeros")
    check("pem", pem_block(b"PGP PUBLIC KEY BLOCK", 500, 4, b"Version: GnuPG v2\n\n"), "asc", tail="zeros")
    hit = check("ppk", PPK, "ppk", tail="zeros")
    assert hit.name == "backup-key"
    assert parse("pem", b"-----BEGIN CERTIFICATE-----\nnot base64 at all!\n-----END CERTIFICATE-----\n") is None


def test_lnk():
    hit = check("lnk", make_lnk(), "lnk")
    assert hit.name == "notepad" and hit.info["target"] == "C:\\Windows\\notepad.exe"


@pytest.mark.parametrize("ptr8,little", [(True, True), (False, False)])
def test_blend(ptr8, little):
    hit = check("blend", make_blend(ptr8, little), "blend")
    assert hit.info["version"] == "2.79"


@pytest.mark.parametrize("ts,encapsulated", [
    (b"1.2.840.10008.1.2.1", False), (b"1.2.840.10008.1.2", False), (b"1.2.840.10008.1.2.2", False),
    (b"1.2.840.10008.1.2.4.50", True), (b"1.2.840.10008.1.2.1.99", False)])
def test_dicom(ts, encapsulated):
    hit = check("dcm", make_dicom(ts, encapsulated), "dcm")
    if ts != b"1.2.840.10008.1.2.1.99":
        assert hit.info == {"modality": "OT", "width": 6, "height": 4}
        assert hit.mtime == 1672617600


def test_fits():
    data = make_fits()
    assert len(data) == 4 * 2880 + 2880 + 2880 + 2880
    hit = check("fits", data, "fits")
    assert hit.name == "M31" and hit.mtime == 1620284889 and hit.info["hdus"] == 2


def test_bplist():
    data = make_bplist()
    check("plist", data, "plist")
    for obj in ({}, {"name": "Zoë ✓", "when": __import__("datetime").datetime(2020, 1, 2), "uid": plistlib.UID(300)},
                {f"k{i}": f"value {i}" for i in range(400)}, [f"s{i}" for i in range(70000)]):
        check("plist", plistlib.dumps(obj, fmt=plistlib.FMT_BINARY), "plist")
    assert parse("plist", b"bplist00\xd1" + noise(5000, 3)) is None


def test_virtual_disks():
    hit = check("vdi", make_vdi(), "vdi")
    assert hit.info["virtual_size"] == 4 * 65536
    check("vhd", make_vhd(), "vhd")
    check("qcow2", make_qcow2(), "qcow2")
    check("vmdk", make_vmdk(), "vmdk")
    check("vmdk", make_vmdk_stream(), "vmdk")
    desc = (b'# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType="monolithicSparse"\n'
            b'\n# Extent description\nRW 2048 SPARSE "disk-s001.vmdk"\n')
    check("vmdk", desc, "vmdk", tail="zeros")
    data = make_vhdx()
    check("vhdx", data, "vhdx")


# ====================================================================== robustness
SAMPLES = {
    "pst": lambda: make_pst(), "dbx": make_dbx, "mbox": make_mbox, "eml": lambda: MAIL, "kdbx": make_kdbx,
    "regf": make_regf, "evtx": make_evtx, "dbf": make_dbf, "exe": lambda: make_pe(plus=True, cert=True)[0],
    "elf": make_elf, "macho": lambda: make_fat()[0], "class": make_class, "dex": make_dex, "wasm": make_wasm,
    "ttf": make_ttf, "woff": lambda: make_woff(make_ttf()), "swf": lambda: make_swf(b"C"), "torrent": make_torrent,
    "ics": lambda: ICS, "vcf": lambda: vcard("Alice") + vcard("Bob"), "pem": lambda: pem_block(b"CERTIFICATE", 600, 1),
    "ppk": lambda: PPK, "lnk": make_lnk, "blend": make_blend, "dcm": make_dicom, "fits": make_fits,
    "plist": make_bplist, "vdi": make_vdi, "vhd": make_vhd, "qcow2": make_qcow2, "vmdk": make_vmdk,
}


@pytest.mark.parametrize("key", sorted(SAMPLES))
def test_truncated(key):
    """A file cut off by the end of the disk is reported as incomplete (or not at all), never longer than
    what is there."""
    data = SAMPLES[key]()
    for cut in (len(data) // 2, len(data) - 1):
        src = BytesSource(noise(PAD, 1) + data[:cut])
        hit = FMT[key].parse(Reader(src, PAD))
        if hit is not None:
            assert hit.length is None or hit.length <= cut
            text = key in ("mbox", "eml", "ics", "vcf", "pem", "ppk")
            if hit.length == cut and not text and not (key == "dbf" and cut == len(data) - 1):    # EOF mark
                assert hit.chance == CHANCE_POOR, key


@pytest.mark.parametrize("key", sorted(SAMPLES))
def test_corruption_never_raises(key):
    data = SAMPLES[key]()
    rng = random.Random(key)
    for _ in range(40):
        bad = bytearray(data)
        for _ in range(rng.randint(1, 12)):
            i = rng.randrange(min(len(bad), 4096))
            bad[i] = rng.randrange(256)
        hit = FMT[key].parse(Reader(BytesSource(bytes(bad) + noise(4096, 2)), 0))
        assert hit is None or isinstance(hit, Hit)


def test_false_positives():
    """Random data that merely starts with a format's magic bytes is not taken for a file."""
    for f in ALL:
        for off, magic in f.magic:
            for seed in range(25):
                data = bytearray(noise(64 * 1024, seed))
                data[off:off + len(magic)] = magic
                hit = f.parse(Reader(BytesSource(bytes(data)), 0))
                assert hit is None, (f.key, magic, seed, hit)


# ====================================================================== through the engine
def test_registered_in_engine():
    from recoverall.core import carve

    keys = {f.key for f in carve.FORMATS}
    assert {f.key for f in misc.FORMATS} <= keys
    if not {f.key for f in misc2.FORMATS} <= keys:
        pytest.skip("misc2 is not listed in recoverall/core/carve/__init__.py _MODULES yet")
    assert {f.key for f in carve.resolve_formats("other")} >= {"ttf", "pem", "lnk"}


def test_engine_finds_everything(tmp_path):
    from recoverall.core.carve import Carver

    samples = [("pst", make_pst(), "pst"), ("mbox", make_mbox(), "mbox"),
               ("sqlite", make_sqlite(tmp_path, 60), "sqlite"), ("regf", make_regf(), "dat"),
               ("evtx", make_evtx(1), "evtx"), ("exe", make_pe(plus=True)[0], "exe"),
               ("elf", make_elf(), "elf"), ("macho", make_fat()[0], "macho"), ("class", make_class(), "class"),
               ("dex", make_dex(), "dex"), ("wasm", make_wasm(), "wasm"), ("ttf", make_ttf(), "ttf"),
               ("woff", make_woff(make_ttf()), "woff"), ("swf", make_swf(b"F"), "swf"),
               ("torrent", make_torrent(), "torrent"), ("ics", ICS, "ics"), ("vcf", vcard("Alice"), "vcf"),
               ("pem", pem_block(b"CERTIFICATE", 600, 1), "crt"), ("lnk", make_lnk(), "lnk"),
               ("blend", make_blend(), "blend"), ("dcm", make_dicom(), "dcm"), ("fits", make_fits(), "fits"),
               ("plist", make_bplist(), "plist"), ("kdbx", make_kdbx(), "kdbx"), ("dbf", make_dbf(), "dbf"),
               ("vdi", make_vdi(), "vdi"), ("mdb", make_mdb(), "mdb")]
    image = bytearray(noise(4096, 77))
    where = []
    for i, (key, data, ext) in enumerate(samples):
        where.append((len(image), key, data, ext))
        image += data + b"\0" * (-len(data) % 512 or 512)
        image += noise(512 * (1 + i % 3), 100 + i)
    src = BytesSource(bytes(image))
    found = list(Carver(src, ALL).scan())
    by_offset = {f.offset: f for f in found}
    assert sorted(by_offset) == [w[0] for w in where], [(f.offset, f.key) for f in found]
    for i, (off, key, data, ext) in enumerate(where):
        f = by_offset[off]
        assert (f.key, f.ext, f.category) == (key, ext, FMT[key].category)
        if key == "mdb":                          # open-ended: runs to the next file (or the end)
            assert f.length == (where[i + 1][0] if i + 1 < len(where) else len(image)) - off
        else:
            assert f.length == len(data), key
    names = {f.key: f.name for f in found}
    assert names["regf"] == "NTUSER" and names["class"] == "Hello" and names["ttf"] == "Test Sans Bold"
