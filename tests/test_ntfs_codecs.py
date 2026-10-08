"""The NTFS reader's decompressors: LZNT1 (NTFS compression), and XPRESS Huffman and LZX (Windows' file
compression, WOF). Checked against small compressors written here, against data compressed by wimlib (which
implements Microsoft's formats; the vectors at the end were made with wimcapture), and with garbage input."""

from __future__ import annotations

import base64
import random
import struct
import subprocess

import imagekit
from imagekit import payload

from recoverall.core.blockio import BytesSource
from recoverall.core.fs.base import read_content
from recoverall.core.fs.ntfs import lznt1_decompress, lzx_decompress, xpress_huffman_decompress


def text(n: int, word: str = "line") -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += f"{word} {i} of a compressible text file, more or less the same every time\n".encode()
        i += 1
    return bytes(out[:n])


def wof_decode(stream: bytes, size: int, decoder: str, chunk: int) -> bytes:
    e = {"size": size, "extra": {"decoder": decoder, "chunk": chunk, "csize": len(stream), "cdata": stream.hex()}}
    return b"".join(read_content(BytesSource(b""), e))


def lznt1_compress(data: bytes) -> bytes:
    """A small greedy LZNT1 compressor (MS-XCA 2.5) to check the decoder independently of ntfs-3g."""
    out = bytearray()
    for c in range(0, len(data), 4096):
        chunk = data[c:c + 4096]
        body = bytearray()
        pos = 0
        while pos < len(chunk):
            tag_at = len(body)
            body.append(0)
            tag = 0
            for bit in range(8):
                if pos >= len(chunk):
                    break
                lg = max(0, (pos - 1).bit_length() - 4) if pos else 0
                max_back = 1 << (4 + lg)
                max_len = (0xFFF >> lg) + 3
                best_len = best_back = 0
                for back in range(1, min(pos, max_back) + 1):
                    n = 0
                    while n < max_len and pos + n < len(chunk) and chunk[pos + n] == chunk[pos + n - back]:
                        n += 1
                    if n > best_len:
                        best_len, best_back = n, back
                    if back > 64 and best_len >= 3:
                        break
                if best_len >= 3:
                    tag |= 1 << bit
                    body += struct.pack("<H", ((best_back - 1) << (12 - lg)) | (best_len - 3))
                    pos += best_len
                else:
                    body.append(chunk[pos])
                    pos += 1
            body[tag_at] = tag
        if len(body) >= len(chunk):
            out += struct.pack("<H", 0x3000 | (len(chunk) - 1)) + chunk
        else:
            out += struct.pack("<H", 0xB000 | (len(body) - 1)) + body
    return bytes(out)


def test_lznt1_roundtrip():
    data = text(5000) + bytes(3000) + payload(500, 3) + b"abcabcabcabcabcabcabcabcabcabc" * 60
    data = data[:4096 * 3]
    packed = lznt1_compress(data)
    assert len(packed) < len(data)
    assert lznt1_decompress(packed, 4096 * 4) == data + bytes(4096 * 4 - len(data))
    # an uncompressed chunk, then the end marker
    raw = payload(4096, 4)
    assert lznt1_decompress(struct.pack("<H", 0x3FFF) + raw + b"\0\0", 8192) == raw + bytes(4096)
    # garbage must not raise
    rnd = random.Random(1)
    for _ in range(200):
        lznt1_decompress(rnd.randbytes(rnd.randrange(1, 300)), 8192)


def xpress_compress(data: bytes) -> bytes:
    """A small XPRESS Huffman compressor (one block) with a fixed but uneven code: literals 0-127 get 8-bit
    codes, 128-255 9-bit codes, match symbols 10-bit codes."""
    lengths = [8] * 128 + [9] * 128 + [10] * 256
    codes = {}
    code = 0
    for ln in range(1, 16):
        for sym, sl in enumerate(lengths):
            if sl == ln:
                codes[sym] = (code, ln)
                code += 1
        code <<= 1
    out = bytearray(b"".join(bytes([lengths[2 * i] | lengths[2 * i + 1] << 4]) for i in range(256)))
    stream = bytearray(4)
    state = {"bitbuf": 0, "count": 0, "next": 0, "next2": 2}

    def bits(v, n):
        state["bitbuf"] = (state["bitbuf"] << n) | v
        state["count"] += n
        if state["count"] > 16:
            state["count"] -= 16
            struct.pack_into("<H", stream, state["next"], (state["bitbuf"] >> state["count"]) & 0xFFFF)
            state["next"], state["next2"] = state["next2"], len(stream)
            stream.extend(b"\0\0")

    pos = 0
    while pos < len(data):
        best = (0, 0)
        for back in range(1, min(pos, 8192) + 1):
            n = 0
            while pos + n < len(data) and data[pos + n] == data[pos + n - back] and n < 70000:
                n += 1
            if n > best[0]:
                best = (n, back)
            if back > 300 and best[0] >= 3:
                break
        length, back = best
        if length >= 3:
            ml = length - 3
            lg = back.bit_length() - 1
            sym = 256 + (lg << 4) + min(ml, 15)
            bits(*codes[sym])
            if ml >= 15:
                if ml - 15 < 255:
                    stream.append(ml - 15)
                else:
                    stream.append(255)
                    stream.extend(struct.pack("<H", ml))
            if lg:
                bits(back - (1 << lg), lg)
            pos += length
        else:
            bits(*codes[data[pos]])
            pos += 1
    struct.pack_into("<H", stream, state["next"], (state["bitbuf"] << (16 - state["count"])) & 0xFFFF)
    return bytes(out + stream)


def test_xpress_roundtrip():
    for data in (b"a", text(4096), payload(3000, 5) + bytes(1096), b"xy" * 2000 + bytes(500) * 8 + payload(100, 1)):
        packed = xpress_compress(data)
        assert xpress_huffman_decompress(packed, len(data)) == data
    rnd = random.Random(2)
    for _ in range(50):
        xpress_huffman_decompress(rnd.randbytes(rnd.randrange(1, 600)), 4096)


def wof_stream(data: bytes, chunk: int = 4096) -> bytes:
    """A WofCompressedData stream: the chunk offset table, then XPRESS chunks (the second one stored as is)."""
    chunks = []
    for i in range(0, len(data), chunk):
        piece = data[i:i + chunk]
        chunks.append(piece if i // chunk == 1 else xpress_compress(piece))
    table = bytearray()
    pos = 0
    for c in chunks[:-1]:
        pos += len(c)
        table += struct.pack("<I", pos)
    return bytes(table) + b"".join(chunks)


def test_wof_decoder_without_image():
    data = text(9000) + payload(2000, 3)
    stream = wof_stream(data)
    e = {"size": len(data), "extra": {"decoder": "xpress", "chunk": 4096, "csize": len(stream), "cdata": stream.hex()}}
    assert b"".join(read_content(BytesSource(b""), e)) == data


# ---------------------------------------------------------------------- data compressed by wimlib
def sample() -> bytes:
    """What the wimlib vectors below decompress to: text, noise, zeros, x86-like code full of CALLs (E8
    translation) and 8-byte records that come back at offsets that are multiples of 8 (LZX aligned blocks)."""
    out = bytearray(text(8000)) + payload(1500, 3) + bytes(2500)
    for i in range(300):
        out += b"\x55\x48\x89\xe5\xe8" + struct.pack("<i", (i * 7919) % 100000 - 50000) + b"\x5d\xc3"
    pool = [payload(8, 100 + k) for k in range(200)]
    for i in range(2500):
        out += pool[(i * 7 + (i * i) % 13) % 200]
    return bytes(out)


def test_wimlib_vectors():
    data = sample()
    xp = base64.b64decode("".join(WIMLIB_XPRESS4K))
    assert wof_decode(xp, 16384, "xpress", 4096) == data[:16384]
    lzx = base64.b64decode("".join(WIMLIB_LZX))
    assert wof_decode(lzx, len(data), "lzx", 32768) == data


def _wim_resource(wim) -> dict[int, bytes]:
    """The resources of a WIM file by uncompressed size (a resource has the WofCompressedData layout)."""
    raw = wim.read_bytes()
    size = int.from_bytes(raw[0x30:0x37], "little")
    off = struct.unpack_from("<Q", raw, 0x38)[0]
    table = raw[off:off + size]
    out = {}
    for i in range(0, len(table) - 49, 50):
        csize = int.from_bytes(table[i:i + 7], "little")
        roff, usize = struct.unpack_from("<QQ", table, i + 8)
        out[usize] = raw[roff:roff + csize]
    return out


def test_wimlib_live(tmp_path):
    """Fresh data through wimcapture (when installed), every chunk size Windows uses."""
    imagekit.need("wimcapture")
    rnd = random.Random(7)
    data = b"".join(rnd.randbytes(rnd.randrange(50, 3000)) + text(rnd.randrange(100, 6000), str(i)) for i in range(40))
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "f").write_bytes(data)
    for comp, chunk in (("xpress", 4096), ("xpress", 8192), ("xpress", 16384), ("lzx", 32768)):
        wim = tmp_path / f"{comp}{chunk}.wim"
        p = subprocess.run(["wimcapture", str(tmp_path / "src"), str(wim), f"--compress={comp}",
                            f"--chunk-size={chunk}"], capture_output=True)
        assert p.returncode == 0, p.stderr
        stream = _wim_resource(wim)[len(data)]
        assert wof_decode(stream, len(data), comp, chunk) == data, (comp, chunk)


# ---------------------------------------------------------------------- LZX details wimlib never writes
class BitWriter:
    """16-bit little-endian words, most significant bit first (the LZX bit stream)."""

    def __init__(self):
        self.bits = ""

    def put(self, value: int, n: int) -> None:
        self.bits += format(value, f"0{n}b") if n else ""

    def flush(self) -> bytes:
        bits = self.bits + "0" * (-len(self.bits) % 16)
        return b"".join(struct.pack("<H", int(bits[i:i + 16], 2)) for i in range(0, len(bits), 16))


def test_lzx_uncompressed_blocks():
    """Two uncompressed blocks (the first one odd-sized, so a padding byte follows it), each starting on a
    16-bit boundary after the block header, with the repeat offsets in front."""
    a, b = text(99, "a").replace(b"\xe8", b"."), text(150, "b")
    out = bytearray()
    for block in (a, b):
        w = BitWriter()
        w.put(3, 3)
        w.put(0, 1)
        w.put(len(block), 16)
        out += w.flush() + struct.pack("<III", 1, 1, 1) + block + (b"\0" if len(block) & 1 else b"")
    assert lzx_decompress(bytes(out), len(a) + len(b)) == a + b


def test_lzx_verbatim_then_aligned_uncompressed():
    """A hand-made verbatim block (a main code with just "A" and "B", one bit each, its lengths sent through the
    pretree as changes from zero) that ends 12 bits into a 16-bit word, so the header of the uncompressed block
    after it ends exactly on a boundary: then 16 bits of padding come before the repeat offsets."""
    w = BitWriter()
    letters = "ABBABAABBBABAAB"                    # 15 one-bit symbols: 1005 + 15 bits end at bit 12 of a word
    w.put(1, 3)
    w.put(0, 1)
    w.put(len(letters), 16)

    def lens(values):                            # pretree: symbols 0 (no change) and 16 (0 → 1), one bit each
        for i in range(20):
            w.put(1 if i in (0, 16) else 0, 4)
        for v in values:
            w.put(1 if v else 0, 1)

    lens([1 if i in (65, 66) else 0 for i in range(256)])
    lens([0] * 240)
    lens([0] * 249)
    for c in letters:
        w.put(0 if c == "A" else 1, 1)
    assert len(w.bits) % 16 == 12
    tail = b"0123456789"
    w.put(3, 3)
    w.put(0, 1)
    w.put(len(tail), 16)
    assert len(w.bits) % 16 == 0
    raw = w.flush() + b"\0\0" + struct.pack("<III", 1, 1, 1) + tail
    assert lzx_decompress(raw, len(letters) + len(tail)) == letters.encode() + tail


def test_garbage_never_raises():
    rnd = random.Random(11)
    for _ in range(150):
        junk = rnd.randbytes(rnd.randrange(1, 2000))
        assert len(lzx_decompress(junk, 32768)) == 32768
        assert len(xpress_huffman_decompress(junk, 4096)) == 4096
        assert len(lznt1_decompress(junk, 65536)) == 65536
    # a valid stream cut short
    lzx = base64.b64decode("".join(WIMLIB_LZX))
    for cut in (10, 100, 1000, len(lzx) - 7):
        wof_decode(lzx[:cut], len(sample()), "lzx", 32768)


WIMLIB_XPRESS4K = (
    "3gEAAIEEAAD2CgAAAAAAAAAIAAAAAAAAAAAAAAQAAAAAAAgASEREiHgAAAAAAAAAAAAAAAAAAAAAAAAAcHdAB2cAZWcHZgYHdwAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAcAAAAAAAAAAAAAAAAAAABwAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAABwAAAAAAAAAGAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAB22PykuE71J5Thcj03r4TBNar5ry6lXC2PadJZmmfWWr4lNOuM3XUk/q64J1xi91beKrhUy3CsyuFgycbMybn8y9S8y"
    "/8W7uDJogzIWszM0LYozW1QztygzcFEz5aIz0kUztYszjBczGy8z4OIzGC80MF4zM2G8M8J4M4XxMwvjMxfGMy+OM14cM8A+M160NLw4M3hxM/Hi"
    "M+PFM8eLM5AXMyAvM0BeMzONvDNQl4G8NDMCeTMF8jML5DMXyDMvkjNeJDO8SDN5kTNaOzN5cTTyIjPkRTPPizMAIBYAAAmJCQkHiQkJkAkAmQgA"
    "mZAFkIgACAiZcFdnZldVB5kJAACXAJkAcJiZkICJgICIgICIUAhoAGdpmWaWmJmQkJkJAIkJiQkICICIh4iACAcAiACAAAiIAAiIAICICIAACAiI"
    "CIiAgAgAgACAAICAAIAIiACIgAiAAAiIAACAiAgICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AEAAAAAAAAAAAAAAAAAAAAAAAAAACAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADvWwqamdWX+mUW"
    "Ldex722g9sU3JVnwUZqsnUk13aric9/yun1LqQs0wPrGai/lZ8Z5HXVmSuMNWSEaCnIMKRozM8EMyQwz0QwzGA0zQYYzkgwzLxgzMxcQMwuIMwXE"
    "MwLiMwHxM4B4M0C8MyBeMxAviBczxAsz4oUz8UIzeCEzvJAzXkgzLyQzFxIzC4kzhcQzQuIzQfEzoHgzULwzKF4zFC+KFzPFCzPiBTPxgjN4QTO8"
    "oDNIPDM5hHjINDukNDsENDskNDxENB1iNDoENHBINDjGNDQcYzSOMccYNGMMNLH0NLG30Psbv3lfhjSXw5np+kubuiOT23cWMv6d5wc9UnQrt5f5"
    "eQyX5uotNf08Rb90FgfnBnPX+/XnOjHS747aCZ5Tm7PutjLtef6d/R6lBouHy8nW7BY/ylc1Rx9D7v9QQ5P/PXuvftJ2vku1Hg7NUyeX52XHhaFf"
    "k/u5dYUee70+Xg0TlDNQvZrbXKh6XX6qicsJSL7qv/s6LRbZfK8dLAZ5OnzraWpue9RhSFdT98dDvLVOs75fR39hs0U7ANAAAHeoiIiYmJd6mYmY"
    "iZmYmJmIeXmIiImYmYh4h4mIiJiIiXmXiIiYmImJiIeZiHh3h4iJmoh4mImImJiKiIiIeHiIioeIiJiXiJeHh5iJl4iIiIiIiZmHiImHiJiHmIiI"
    "iZiImIiJiImpiIh5iIeYmIiIiIeIiIiZiImZh6mImZh3CgAAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAKoKBgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACvzkU0/wi5"
    "t10mJFTDx2SmRassG23Qi3jB3zVB6RVvArtPU0us6AYd/mkxrnJ8LX4io2rtHnkH74OcvFl8KdYmLQ6ZLMSoGuGrr3wxzIwlBOW27Lz0+J8cCanX"
    "bmhrX/xzen/kQMUgbaXHgjezlMMCsLprFBUoxAUm5eXm6gKGvJZa03UeAxO2vg9jX/17pAruWSlFBgkfgjBveyAwjkD4JPoZBFONcLDePpL/Vnj+"
    "vY1nuqv+hl/KDZm/Xe7GK2S1NS9sjFvF9uH2m9noke7v2FKZZALdZoeE9anwnJvKTSFTCsxCJ7ZCK+bN7/m7K8cHvhCUuK0KqNAe8NJ07y0F0tYy"
    "raHiXYNqbMCd6S7FO91NFqKX34cL3llf27Yg3+LfG8M5c5q3JnNoZjbxa77KbZ/lD1WdEMEy/i15bMTqVuHOe5+PIhWMOpHgoScicsS9Xc28CBUv"
    "6uO7uyG6GiAZKZafNWxGOXKzd+tv2/RZV5EIiArJ1HsT7lhhi8GlDHFrM08fynfyx4yzw9SkPFB3m3Vw1HU9asL0G7rTXFooWvTaRlkFHfqGGHXU"
    "CT7iztdSTyJew3BvU1G8makaIX7F6qbS/xCOPtcsWjWyzU9lYQEyYi4KU5ms5oKraQ0ctd2w9/z6lmkFjxSeuufV1ZwrO/edzixQ0qQhE85IgOLH"
    "Uc8ghfddcJBdfcHnLYbjO1bRnDrMyF5jLDj3nS00JgZcNi7nYnw8md4TWByMyPBMDCuzD6g/7PQvSjpmd23Zihst6B8xC2NA9oz0kdD9BEb35zBd"
    "s25buZf8RE7yB7l1pcZBt17RzJOtJ9kMpYtduCV4xg++MAnA6kSxZBrWrF49RCu0Oz7TXpZVT1E5YW+V04ApAYrJJUV17lSrxbDJj0SSauAaIWVz"
    "FP30H1cxOYeDBq+JoakQWC+Bo+drlc1pUVEITOTJ9nsuNx/ZfONHVzZBeZAMucLrs04r7Si9GIMGgV+4nx6p9Dh9pzlR9G7S7B5chMXQLD5yFkli"
    "4Pqp90t869rQ5VHQCF5UIyZ1zJ4pejYqBiq1kkNRINnv4H0wt+jNVdsuwtQIBuBGnIxAyJJoJD2ubyphTnhf/TqM8AQ+3/DLiaaJtRIRlftVol81"
    "rvInwB/7oubktXnwpXF7Ga/EqgRD3G9LfeFb6zKeyiLDOrMyoFmrvlu0+eCu6FJWlCSfF3TxxLdUqZUYGoRd9cjn/JMldGQ7mJhO8dX8MVnC8vbz"
    "vvCUeiQXKyGo7Sq7jJt+GNFAaRSEc6FH/dXe452c23Vn8CdaF0C9r7uir7TezzU3jYfoRCrXYZLnWvc2NgdSM9Eu8kO9SKqpnrutUYPZKJwg8p95"
    "2VnQP4NiwNCEPWwSp8tlGT1skohxSUeBZ2W89myXiMLVDjzTApw9OaBixpTS30JUbfehlP0xo2E5pCDn3kUw3Msnl0MxR7Z9sOh5ap3xyq+4exA4"
    "zUwbzBWjSDA5gGqNlcs4TVjll9mhZzsR1qxx5w8QlgJmtn4Ptx8gnPA+UOKh3OHkqhROgEEpfkqvexd5h9u5a40rrj4W+E3cEmMclLWASETOZfGl"
    "W+b74lKKO5f8fhXYQEjYvFU2KcyOq3Z0PBPz55Eb7tKdE9fMoFraO1mEyA+9qrGps8TiFGyG9sNb5tUqzOUQtNvN/q0un2EgcW8nC8cdXhBPmK3o"
    "DYQuGjfFpRDQLLWeUd/IV20GXWUS5RbPhZ/OBcs4/sm0/8AJ6GZjG4hEt33n+oBGIeVkwECmin0Y4DDcXxsG1LzBCwRq/0DC7mk0ABCYuR4ZYID6"
    "hhjJn0e8HqA86goGB4xsq8cDAcuD3pv8pGKlAwFlIJmSAwMkmoW9AX9Y+88AAIiYeJiZioipqYiIqYmLmIgImXipipiYiImqqJmQiKqJmJmZh4mJ"
    "mYiJiIuImJh4iImIgJmICJiHmYmImIioiIiIi5iIeImYiYibiJe5eIioiZeYiJiIiImKiIiJiaiIh4mImYiJmKCImJiIi4qImomYinqYmZiImIiZ"
    "iYiYi4mZCwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsAALAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAAAAAAHAAAAAAAAAAcIAAAAAAAACAegAA"
    "AAAAAABQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACDNtvR+W2MfLfZDXD0oDl2y6GHSvkZzYcNuSTbIj5Cev9H"
    "i2yvoQc0fLA4DXrY4RNZ8DdK6nLXHx8QNNNlGnlwAZg+//zw8nqymAfc3kxaHzkEYDkq4v0DClq5NjrwYSNQzG4GONRQPCX5NYpovf49NvRwF1H2"
    "qGGDdbBJiA9T4JAMr0GHS6mwOw0exliG2niN0l+/wA8d0ihf6TnlIIPod/5MuuEORdlNhw/WYK2fHDiUEI1K+TDFxuZDG2yQgVD1rddDh9VqydYo"
    "QfP677Ahh9HwsqGGGoysTnKjoL6M8HAHHfJofH10znAH2eSMF1OB8Dr41aGH1f49l8MOzEg1X6PQ/tvdawMG5ijL/Ro2KjYDB5M3IHg+E22xoYZZ"
    "/LevByhJSt15yKC7GdDyDjsYoTPW02CjVxDmyoUHHSgoxfd10QEG5Dh1eqNAGzjhvSGGPSDhghnyCprsDky/gYbDMu9fGxvoBSnydeoKFeTI0/wr"
    "gxtA9YEHDtOd2gAbvoKCpGy+aIDDJ7S8zQ50AGXpORsOsnhTSxxmsIOi+TPCB40+3oAdUxAIJeF6gw2o7MIEM/4VCuJE69QVK0gQpctXD5GFDgAb"
    "uoIFufJ0/wrID1E/8PCBPHzb7gOUKvvEZxChOODzgMMG6tvxwEYoac7ZclBBktHEagYz3JA+WviNoiBjuK5dQYJQqL6+guBxbPH7QyuIEK1RV64g"
    "QZQuXzz0cD8qdxol7H+RDjmsWJ4ycsJhkfYMsDBphzwaP84ZfLgg+zzgvMEUJGJre8AKsmL76woVBIT19BURaxuwYQqCjOG6dQUKQqL6+Qrh2Kbi"
    "bZTg6uZ96nCDHh49rBw28usGgElnyIPhOqTNHHJo4TfnwveGlPSOwzbcCmJy++UKK8gQqXhXlOBja3vYCrJi++sKFQSE9fQVBXWPGw+xdge/HToc"
    "kMgm6OrDo1c3YMUUAOzufXWY4RTxnisHHJTOV69RwctwuuHDh76Q99pXVxDehTBpBjsU4zEbfQUFueRy1BUriAjq+yshN5z5ukMH53Bg1T42UgwH"
    "caND35HB3g46hGDLPej1ASU1HRsOs38Hmv/q/7PmrXpKxm+T1VcbzlWx/X9PF3KZtFl5ScQsar7vPFTF17WGv2Gav/tdlb/ZGfJA31/i7TAtTRlU"
    "Wr1KS7qKuF7hvxpdxnlebD1BTXWFs+k4pbgg+7GTEpVfJm5pcROzDmRPntxUYP2wnLxi1nXqJxN/8F590/0zK52605M5i/KQC5N5ycVvtcrZqnmx"
    "XGlGDfSzMr3p3SoPX7+0JR7NWtnUthnjx+7Xx6jzZeT8ri3Zsa4WjNOVE5APB6hE0DcS/hwTXWf5zS1+hAFnxor2Vj8e9wHvEoa5Jz8pjcmzlYqa"
    "Iej4wT7tRS6uoW8+tHW5Vh4/P8UhP8LRlnmy4+t/L8p7Uj1GYes3bYW4WGp5de8vuCylaRmr9TEH2596U/x4d3sY1aW5Ow/970dXTbAY5vns5nR7"
    "dBebuFXq40hEfBA6geBdrOi/d9FoamlTPw8qYCf2IyofeC3jY8bu3mGlVp9+XqOxN4kzrM5zcDvnmePER7x/qKZ3FuyP5tu3okVYX+ddcP2gXU2l"
    "HvsjIjrQq8XBUm1i0uWYWPT6SE0hdDvBUzXThOFWSZHvq/CgYuDU3TPjVPujZRkw7ZS/cAVl37xMT3TEb+yrSe89tjBLO1KEBy3DL3++o5xRjZLP"
    "Y8hu5nqnD0wMfXvlbX3j/761vrGkjpD6Q+gWgbYFgncaMkeWufO68snjuWYQd58kmUio8RbfM/bWXxl8zuuf2HFz9K1R9S1oZ7E3MnVx/9pvDDKJ"
    "G0PHYFNP44dZS22q//vEsSuMhcU65OAQgUU3R1bnZTte/nWXullrnao6g7auX7Qf+V0bKrncfLyaVbhk5312VRh0Ik1a0LO39WJqz6YfTi2XL4uE"
    "pi22sINnk1Y9kociHEKwCNc0hhqpVUr1o76m1fLStWmAYUzr0Ecft/OuuPgSxzs6BV9ScgwtVjMVc2x+o4S3k/Kflrvyt1jTOkfmJcO/4MrQIQKH"
    "DSzGNfda28uZyI+bh3RYP9lgZevNzVqDmltNzOr0ypqCjn2XhRb6bpeHqAaAtnPHkR/tEybsrOlqGVGLpVeyttAhAocNLMY1I56Di2wxj3WYjuh/"
    "Wi6FU8+qbfFMVY56wVnQooJ8p3wY3qnzUatlbCpz1KGlP2WFaAdX3TlJhA4ROGlgHa4YYz8tAOgAAA=="
)
WIMLIB_LZX = (
    "7BoAABhFzSjAsQAAUgUAFAAAMQAKCWlTXxQSFXeOUmkJoUIyKrTnWFKxrJBYVFqSsauiUKUlCKVMUmqxsSiIIgqhAIMkAGRGUEUlAAQJ8juCN4kB"
    "U4ogdaeFhEeAQUtI1Fv090GxcYJSu8C8AAAAAEQDREQPIuHXVF/8fvyIb/ziKojUiJjW5MCJaURwcvHhnFrK3Fvwi/9qxuN1NSL+lVLCgyMXl3/4"
    "I1L8f+5f/W3wOT8cqa2r0e2KQvzZv287o/8HiUOTw8QDxcHJ8OSA8kR5pDwlHvWXLrcltVuXZYnC13VZLOHiunVZS/y/LmXJ0td1WWjqoUmEJhKa"
    "SWgmoZqEaBKhSQgTRJgmwjARhIkiTBNhmAgCRREoikBQBIEiCBRFoCgCcBLBSQQnEpxJcCfBnARwEsFJhCcSnkl4J+GehHgS4UmEJxKeSoAoAaAE"
    "gBIBSgQoEqBKgCgBooSIEiFKhCgSokqIKCGihJASQUoEKRKkSpApQaQEkBJBSkwSr8vy30HCXfb6ibDLZf332C7r/8d2WfU3Ypey/nfsL+vh7Pgg"
    "fZA//nc2/PiE2y+MtKdPZzwXw50kEjrEW9TRI81jvcLs6tVZnGTNo5t6ViHPLqJeppvOUjqZRx09J2C16fFPMLL7pVuxTWc0RC75Ro2bcxdyqxYp"
    "j9q4xfq/JCHA1+si+35Cu1pfIk7hv5ygOg85hfAt4PLb5AtFcrg3Q+7qxnt6nHhcmTonesfborOV3Ts1y22bT5iNFONqp6ez4InspfMtOgm+TmtC"
    "+f4I9jach8amOUucR2adiYdluPc0TCs6Mq/PpXZDSjq7NF3d7FEzAr4HTIJLrkU2zKGoRif2veUELdmzRdnionxyl/+SwgfUPAVb92n43Vt5ZZus"
    "15RFLUeXpOtOVNGd6ZW2aXi4w1tb6NINNJIMpC+fT0Dg5veUua7JrTyEooT2WCXHs+I5w/65ni5x+je4UVLn0v4Q/iwym8WVz1OrUPtJI41xvDmy"
    "jNrkNOuHT4RKfcOWwQrZT40R+6JIK3SlUR4aCrvhRJ5mk7Vg5GbeI5OzzS1Q1F2vHG/srbGVLit7e5ZuZ00jgu1mgTzQa9W27a2UsdcpT/33fKJ9"
    "v+myZumgAU6MYR/55mntPSVqc+Pt/j5D+MzBp3b656Gr7vrlpD4jN5PB5tWP5emR1CRtGXI4P5VXjTdxD1PVJjFrNJs96WpV6U93MjpYOXSevq9q"
    "mQ6uGkhf78TEJkr0cpKr7/kXq09u7PuRbd1xVSU3uf4D084jj3qxxn+itTdUPkvQnjQ35bwbz3OyOuwRH7Lldn5J1PwBfHzvb+a065X287g5xvco"
    "FT/ZNkpZnNxyC3meBr4yVvLSS27rtr1hTz/39heWLPCRbPAraBkf23FNXhOotPoZ6/tp5G0OVwYdul2N6xdSvph6cLONoMjrZdVYLzfqSJUdU35W"
    "vm5Qs+XQfbu3JoTYhHuYNmv6jhJn+DBRE3ZQT6Xwk7vSa1X+nb70j+pJxazYUdpGtFJ2Zr2tr21LW4gIe7SIbDdbrRzCOOWKBVXRXMm//eP7aasP"
    "+P+X0zW3vvDuA45b+tRGju/V64e5tdtNRrNgfLO4W4pcdH440a5KI97Mo+LduDzq+7JFKi/YZoLrvn1ghpFs2HGycceb+7FDz2PTTmednHLeWrCn"
    "SfxW2okI9dkrnCN+89UutN2+HnZf8adNrzsr1jOrQK3rUZI8mVT5J97yki0HX6lBjCWfxlsHw5VhOUJOV9VS48u1PJp8WRneixdlHLg+Jva+dbXz"
    "PCRNR58tUyc2EVuFRUvRd1pCfD0pa8fX23gV7It0np283IYW2DlN4R83Bc2tKtlf+FfJLFf+yvj6z2zWA89S5oHjtCvTgNA3xbqVo7/umq5Kq9Tu"
    "CWuiKnPfCp9Lxx1VxJu77ziNiPuceYQJhnfGd0XfVVw+PMPTmpom5MCTRUE2jTbDVDnIKK2tz5Ri7zRStSzFjetd7HrzlzieOLW5KZpnxg9VYyNr"
    "R+lCiu5w5+yi8Lkr1vy9m1RZ3VNv5hIWw56JZbLRKrHWla/S4cz6at+NhYTK54eXip8vW/4eCMqt6f4x1z3vGKOcYe+XSnwr5qRrx8pBbOcv3vop"
    "yT5eyV0ps86Hz5rILabMv4lo5tgJTUe+Z7G8GVXz2vrFeYeGkq/qvHKEJnbuJTHxiZEzJu/CVQS9fq7Fpha/937gyrrXWPlUZhnZCk5MXfmfEB8X"
    "GrQcPL92U4LSpb8O8JGyXPL4MIsb3kYqwzIY8prhEll3dTyLBKeo0ikoFItmcLuxSEgFOQp3R1QOdGQmKrf34AKPG9uvXFER9QofEzeacKHca+3X"
    "3b0FtnYGudtfxKWJKUe1WKa706QmVw3BGUOxC8fJo68nasLj+jUeXNav8OiQsI3tmnnEBwt8VCgZdvmnzMfbOpWn57sVXVaN8XRukQl6mu3EBZPQ"
    "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"
    "5dfZRkNq5UvaikKv64M+e5AUEiyAGA=="
)
