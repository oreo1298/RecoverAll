"""EBML, the binary format of Matroska and WebM: elements of an id, a size and a payload, nested.

An element starts with its id, a variable-length integer whose first byte says how long it is (the position of
the first set bit: 1xxxxxxx is one byte, 01xxxxxx xxxxxxxx two, up to four bytes for ids); the marker bit is
kept as part of the id (Segment is 0x18538067, Cluster 0x1F43B675, SimpleBlock 0xA3). The size follows in the
same coding, one to eight bytes, without the marker; a size with every value bit set (0xFF, 0x7FFF, ...) means
"unknown": the element runs until something appears that can't be inside it (live recordings write the
Segment and their Clusters that way). Numbers are big-endian unsigned or signed integers of 0 to 8 bytes,
floats are 4 or 8 bytes, strings are padded with zero bytes.

Matroska blocks (SimpleBlock, Block) can hold several frames ("lacing"): Xiph lacing gives each size but the
last as a run of 255s plus a final byte; EBML lacing gives the first size as a variable-length integer and the
others as signed differences; fixed lacing divides the payload into equal frames.

Everything here reads from anything that slices like bytes (bytes, mmap) and returns None instead of raising
on damaged data. Standard library only.
"""

from __future__ import annotations

import struct
from typing import Iterator

UNKNOWN_SIZE = b"\x01\xff\xff\xff\xff\xff\xff\xff"


def read_vint(buf, pos: int, end: int, max_len: int = 8) -> tuple[int, int, bool] | None:
    """The variable-length integer at POS: (value without the marker bit, length, every value bit set)."""
    if pos >= end:
        return None
    first = buf[pos]
    if first == 0:
        return None
    length = 9 - first.bit_length()
    if length > max_len or pos + length > end:
        return None
    value = first & ((1 << (8 - length)) - 1)
    for i in range(1, length):
        value = (value << 8) | buf[pos + i]
    return value, length, value == (1 << (7 * length)) - 1


def read_id(buf, pos: int, end: int) -> tuple[int, int] | None:
    """The element id at POS (marker bit kept) and its length, or None."""
    if pos >= end:
        return None
    first = buf[pos]
    if first < 0x10 or first == 0xFF:
        return None
    length = 9 - first.bit_length()
    if pos + length > end:
        return None
    return int.from_bytes(buf[pos:pos + length], "big"), length


def read_size(buf, pos: int, end: int) -> tuple[int | None, int] | None:
    """The element size at POS (None: unknown) and its length, or None."""
    v = read_vint(buf, pos, end)
    if v is None:
        return None
    return (None if v[2] else v[0]), v[1]


class Element:
    """An element: ID at START, its payload from DATA; SIZE None when unknown. END is DATA + SIZE (None when
    the size is unknown); it can lie past the data when the file is cut short."""

    __slots__ = ("id", "start", "data", "size")

    def __init__(self, eid: int, start: int, data: int, size: int | None):
        self.id, self.start, self.data, self.size = eid, start, data, size

    @property
    def end(self) -> int | None:
        return None if self.size is None else self.data + self.size

    @property
    def header(self) -> int:
        return self.data - self.start

    def __repr__(self) -> str:
        return f"Element({self.id:#x}, {self.start}, size={self.size})"


def element_at(buf, pos: int, end: int) -> Element | None:
    """The element whose header is at POS (its payload may run past END), or None."""
    i = read_id(buf, pos, end)
    if i is None:
        return None
    s = read_size(buf, pos + i[1], end)
    if s is None:
        return None
    return Element(i[0], pos, pos + i[1] + s[1], s[0])


def children(buf, start: int, end: int, limit: int = 10_000_000) -> Iterator[Element]:
    """The elements in [START, END) one after the other. Stops at the first one that doesn't parse, runs past
    END or has an unknown size (that one is still yielded)."""
    pos = start
    for _ in range(limit):
        if pos >= end:
            return
        el = element_at(buf, pos, end)
        if el is None:
            return
        yield el
        if el.size is None or el.end > end:
            return
        pos = el.end


def child(buf, el: Element, eid: int, end: int | None = None) -> Element | None:
    """The first child of EL with id EID."""
    stop = el.end if el.end is not None else (end if end is not None else len(buf))
    for c in children(buf, el.data, min(stop, len(buf))):
        if c.id == eid and c.size is not None and c.end <= stop:
            return c
    return None


def uint(buf, el: Element | None, default: int | None = None) -> int | None:
    """EL's payload as an unsigned integer (DEFAULT when EL is missing or too long)."""
    if el is None or el.size is None or el.size > 8 or el.end > len(buf):
        return default
    return int.from_bytes(buf[el.data:el.end], "big") if el.size else 0


def sint(buf, el: Element | None, default: int | None = None) -> int | None:
    if el is None or el.size is None or el.size > 8 or el.end > len(buf):
        return default
    return int.from_bytes(buf[el.data:el.end], "big", signed=True) if el.size else 0


def float_value(buf, el: Element | None) -> float | None:
    if el is None or el.size not in (4, 8) or el.end > len(buf):
        return None
    return struct.unpack(">f" if el.size == 4 else ">d", buf[el.data:el.end])[0]


def text(buf, el: Element | None) -> str:
    if el is None or el.size is None or el.end > len(buf) or el.size > 4096:
        return ""
    return bytes(buf[el.data:el.end]).rstrip(b"\x00").decode("utf-8", "replace")


# ---------------------------------------------------------------------- writing
def encode_id(eid: int) -> bytes:
    return eid.to_bytes((eid.bit_length() + 7) // 8 or 1, "big")


def size_length(n: int) -> int:
    """The shortest coding of size N (all-ones values are reserved for "unknown")."""
    for length in range(1, 9):
        if n < (1 << (7 * length)) - 1:
            return length
    raise ValueError("size too large for EBML")


def encode_size(n: int | None, length: int = 0) -> bytes:
    """Size N (None: unknown) in LENGTH bytes (0: the shortest). ValueError when it doesn't fit."""
    if n is None:
        length = length or 8
        return bytes([1 << (8 - length)]) + b"\xff" * (length - 1) if length > 1 else b"\xff"
    length = length or size_length(n)
    if not 1 <= length <= 8 or n >= (1 << (7 * length)) - 1:
        raise ValueError("size doesn't fit")
    return ((1 << (7 * length)) | n).to_bytes(length, "big")


def encode_uint(v: int, length: int = 0) -> bytes:
    length = length or max(1, (v.bit_length() + 7) // 8)
    return v.to_bytes(length, "big")


def element(eid: int, payload: bytes, size_len: int = 0) -> bytes:
    return encode_id(eid) + encode_size(len(payload), size_len) + payload


def uint_element(eid: int, v: int, length: int = 0) -> bytes:
    return element(eid, encode_uint(v, length))


def float_element(eid: int, v: float, width: int = 8) -> bytes:
    return element(eid, struct.pack(">d" if width == 8 else ">f", v))


def void(total: int) -> bytes:
    """A Void element (0xEC) exactly TOTAL bytes long (at least 2)."""
    if total < 2:
        raise ValueError("a Void element takes at least 2 bytes")
    for length in range(1, 9):
        n = total - 1 - length
        if n >= 0:
            try:
                return b"\xec" + encode_size(n, length) + bytes(n)
            except ValueError:
                continue
    raise ValueError("Void too large")


# ---------------------------------------------------------------------- blocks and lacing
def lace_sizes(buf, pos: int, end: int, lacing: int) -> tuple[list[int], int] | None:
    """The frame sizes of a laced block whose lacing header starts at POS and whose payload ends at END:
    (sizes, offset of the first frame). LACING is the flags' bits 1-2 (1 Xiph, 2 fixed, 3 EBML)."""
    if pos >= end:
        return None
    count = buf[pos] + 1
    pos += 1
    sizes: list[int] = []
    if lacing == 2:                                  # fixed: equal frames
        total = end - pos
        if total < 0 or total % count:
            return None
        return [total // count] * count, pos
    if lacing == 1:                                  # Xiph: runs of 255
        for _ in range(count - 1):
            n = 0
            while True:
                if pos >= end:
                    return None
                b = buf[pos]
                pos += 1
                n += b
                if b != 255:
                    break
            sizes.append(n)
    elif lacing == 3:                                # EBML: first size, then signed differences
        v = read_vint(buf, pos, end)
        if v is None:
            return None
        sizes.append(v[0])
        pos += v[1]
        for _ in range(count - 2):
            v = read_vint(buf, pos, end)
            if v is None:
                return None
            diff = v[0] - ((1 << (7 * v[1] - 1)) - 1)
            sizes.append(sizes[-1] + diff)
            pos += v[1]
            if sizes[-1] < 0:
                return None
    else:
        return None
    last = end - pos - sum(sizes)
    if last < 0:
        return None
    sizes.append(last)
    return sizes, pos


def block_header(buf, data: int, end: int) -> tuple[int, int, int, int] | None:
    """A (Simple)Block's header at DATA: (track number, relative timecode, flags, header length). None when
    it doesn't parse or its lacing doesn't add up to the payload ending at END."""
    v = read_vint(buf, data, end)
    if v is None or v[2] or v[0] == 0 or data + v[1] + 3 > end:
        return None
    track = v[0]
    p = data + v[1]
    tc = struct.unpack_from(">h", bytes(buf[p:p + 2]))[0]
    flags = buf[p + 2]
    lacing = (flags >> 1) & 3
    if lacing and lace_sizes(buf, p + 3, end, lacing) is None:
        return None
    return track, tc, flags, v[1] + 3
