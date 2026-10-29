"""Reading bit fields: most-significant bit first (H.264, H.265, AAC, MPEG headers), Exp-Golomb codes, and the
emulation-prevention bytes of H.264/H.265 NAL units."""

from __future__ import annotations


class BitsError(ValueError):
    """Read past the end of the data (a damaged or cut-short field)."""


class BitReader:
    """Bits of DATA from bit position POS (MSB first). Reading past the end raises BitsError."""

    __slots__ = ("data", "pos", "end")

    def __init__(self, data, pos: int = 0, end_bits: int | None = None):
        self.data = data
        self.pos = pos
        self.end = len(data) * 8 if end_bits is None else end_bits

    @property
    def left(self) -> int:
        return self.end - self.pos

    def u(self, n: int) -> int:
        """N bits as an unsigned number."""
        if n == 0:
            return 0
        pos = self.pos
        if pos + n > self.end:
            raise BitsError("read past the end")
        first = pos >> 3
        last = (pos + n - 1) >> 3
        chunk = int.from_bytes(self.data[first:last + 1], "big")
        shift = (last + 1) * 8 - (pos + n)
        self.pos = pos + n
        return (chunk >> shift) & ((1 << n) - 1)

    def u1(self) -> int:
        pos = self.pos
        if pos >= self.end:
            raise BitsError("read past the end")
        self.pos = pos + 1
        return (self.data[pos >> 3] >> (7 - (pos & 7))) & 1

    def peek(self, n: int) -> int:
        save = self.pos
        try:
            return self.u(n)
        finally:
            self.pos = save

    def skip(self, n: int) -> None:
        if self.pos + n > self.end:
            raise BitsError("skip past the end")
        self.pos += n

    def ue(self) -> int:
        """An unsigned Exp-Golomb code."""
        zeros = 0
        while self.u1() == 0:
            zeros += 1
            if zeros > 32:
                raise BitsError("Exp-Golomb code too long")
        return (1 << zeros) - 1 + self.u(zeros)

    def se(self) -> int:
        """A signed Exp-Golomb code."""
        k = self.ue()
        return (k + 1) // 2 if k & 1 else -(k // 2)

    def align(self) -> None:
        self.pos = (self.pos + 7) & ~7

    def byte_pos(self) -> int:
        return self.pos >> 3


def unescape(nal) -> bytes:
    """A NAL unit's payload with the emulation-prevention bytes (00 00 03 → 00 00) removed."""
    data = bytes(nal)
    if b"\x00\x00\x03" not in data:
        return data
    out = bytearray()
    i = 0
    n = len(data)
    zeros = 0
    while i < n:
        b = data[i]
        if zeros >= 2 and b == 3:
            zeros = 0
            i += 1
            continue
        out.append(b)
        zeros = zeros + 1 if b == 0 else 0
        i += 1
    return bytes(out)


def escape(rbsp: bytes) -> bytes:
    """The inverse of unescape(): insert 03 after two zero bytes before a byte ≤ 03."""
    out = bytearray()
    zeros = 0
    for b in rbsp:
        if zeros >= 2 and b <= 3:
            out.append(3)
            zeros = 0
        out.append(b)
        zeros = zeros + 1 if b == 0 else 0
    return bytes(out)
