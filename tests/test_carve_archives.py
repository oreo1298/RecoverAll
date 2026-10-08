"""Tests for the archive formats of the signature engine (recoverall/core/carve/archives.py): every parser
measures real archives exactly (built here with the standard library, embedded, or made with the archivers
when they are installed), recognises the files built on ZIP, cuts damaged files where they stop making
sense, and turns down random data that merely starts with the right magic."""

import base64
import bz2
import calendar
import gzip
import hashlib
import io
import lzma
import random
import shutil
import struct
import subprocess
import tarfile
import zipfile
import zlib

import pytest

from recoverall.core.blockio import BytesSource
from recoverall.core.carve import archives, documents
from recoverall.core.carve.base import CHANCE_GOOD, CHANCE_POOR, Reader
from recoverall.core.carve.engine import Carver

# Made with 7z, rar 7, arj, gcab, zstd, lz4, lzip, mksquashfs and wimlib from two files (readme.txt: 20
# lines, data.bin: 1 KiB) dated 2021-06-15 12:34:56 UTC; zlib-compressed, base64.
SAMPLES = {
    "7z": (
        "eNoBvwFA/jd6vK8nHAAEIn39F34BAAAAAAAAIQAAAAAAAAD3uXgr4AWjAQhdAAAAUlAKhPmbsoAhqWnWJ+A+BlpfBI1T1AS6OVcF"
        "CcFVJN6duHFZMWChn/lvSXPyyOqMuhqLKWkhgP4zg2avRm3snomKC4PwPA6Jjj/tX+eekNkc/zL0suA5UbLSFBW0xXG62wbjeZqf"
        "uzjBsACskwuqBhkDEggVW5vISPAyLv4toIfI8KTg0lHrjWdWkrJNhMXxhjHfamJbwnkt2fc8c7p0dAfYPKlWIiShZvhahF8wZ9L2"
        "S0kufyDr2/gQDpR4d8c/a++0zZXib/ZEbgbPC4Iay9t68FeNmP+QwD7mwRJBde4DKJbrE/unKMyvLNTBYSZmDFDZMSNn/y64RnPj"
        "YxXsBbEdB6RzAAAAAIEzB64P1TgslTnGZtqN8/MDo9DrgzzGrrw1I/Vy2Uulh0n7OWLmFmiH1VjH9YVI37++ZvRqRIqE89/prU/Q"
        "pIDrOGOPjqwbqr5FJxOQ38JTh6I+jOc5FXwQAatPlNSPIQrErpufLork58oAABcGgRABCW4ABwsBAAEjAwEBBV0AEAAADH4KARE1"
        "ztIAAJHbxv4="
    ),
    "rar": (
        "eNoBpwFY/lJhciEaBwEA8+GC6wsBBQcABgEBgICAAHyvxZwgAgKnAAakA6SDAnCeyGBx2Z5SgAMBCnJlYWRtZS50eHTEuiQkBCT6"
        "Qv/QpivQVgqaghoIKjf4wwLPmWhQ06K+SmC8R4I9xuAc1TarHgICmAIGgAikgwJwnshgJkwLt4ADAQhkYXRhLmJpbsuEFAEC9DP1"
        "Mytm/7QnJ+IMUogxQ/7/gACBAYICgwOEBIUFhgaHB4gIiQmKCosLjAyNDY4Ojw+QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0d"
        "nh6fH6AgoSGiIqMjpCSlJaYmpyeoKKkpqiqrK6wsrS2uLq8vsDCxMbIyszO0NLU1tja3N7g4uTm6Ors7vDy9Pb4+vz/AQMFBwkLD"
        "Q8RExUXGRsdHyEjJScpKy0vMTM1Nzk7PT9BQ0VHSUtNT1FTVVdZW11fYWNlZ2lrbW9xc3V3eXt9f4GDhYeJi42PkZOVl5mbnZ+ho"
        "6Wnqautr7Gztbe5u72/wcPFx8nLzc/R09XX2dvd3+Hj5efp6+3v8fP19/n7/fvAdd1ZRAwUEAAV1vp4="
    ),
    "arj": (
        "eNpLeKXJoMTNyCTAwNSw4dDxLBBmwADFeolFQGG995tkGBgSXlkx6IG0MDJsKJh3IkEFqGAJIwND4c15QUCWIEQLsmFFqYkpual6"
        "JRUlDAxv53UkA4XEnfJy6xdvYV5hfDZt2YM2FvvDCbp6Cnp+Oy8HTEi7MXdx//IJCa8sUOwxBNrBwMLAoObDvR27PSmJJYl6SZl5"
        "DAxh67W/MDAwMifwMxjtv9LCgBcwzrXh+FfvsP9AQsP+DwkFDRMWbDhw4cFHRkFFQ8fAxMLGiQs3Hrz48BOTkJKRU1BSUdOkRZsO"
        "XXr0mVlY2dg5OLm4efLizYcvP/7CIqJi4hKSUtIyZcmWI1eefGUVVTV1DU0tbZ26dOvRq0+/sYmpmbmFpZW1TVu27di1Z9/ZxdXN"
        "3cPTy9unL99+/PrzHxwSGhYeERkVHTNW7Dhx48VPTklNS8/IzMrOmSt3nrz58heXlJaVV1RWVdesVbtO3Xr1m1ta29o7Oru6e/bq"
        "3advv/7DI6Nj4xOTU9MzZ82eM3fe/OWV1bX1jc2t7Z27du/Zu2//8cnp2fnF5dX1zVu379y9d//55fXt/ePz6/vnr99//oL8gXrG"
        "PwmvGBgA9XfKjw=="
    ),
    "cab": (
        "eNrzDXZ2YwCCOYwMYKADoRiYGRkZmKDsBCBmBMIlUDUMDOeDYlIUGIpSE1NyU/VKKkoYGFgYoNIQqZTEkkS9pMw8BvY/23xNGJew"
        "Ontze/me0/fWLTpzMlDDU1cv0OP0Gc+nXFKiMj5NPD0+Z3TW5LyRmRNzx2ZPzR+mJqdDSouSHglNCrpktKnoE1eX1ymtVVmvpGZF"
        "3bLaVfWLrc3tmNqytGdi08KumW0r+8bX53dOb13eO7l5cffs9tX9Y2x0PKi4MPGh4MTAi4YbCz9ydnqe1FyZ+VJyZuRNy52VP1lb"
        "XY+qLk19Kjo19Krp1tKvvL2+Z3XX5r6VnRt713Zv7V9hNb9ZNqmvtrw0Tjs3yzb93Z6f3GJ6UXtSXm56qh22Lmpv2ttdX6XN8m7t"
        "SX297a112btbe9Pf7/vLzidnVfPkxcbH6n7zrGqfvdn5WVwvblfN01dbX5vn3dtV+/zd3t/8cnZVf5683PxcP25f1d9nb3d/l7er"
        "+/Xn6evt7+3r/v36+/z9/v+L/8l//e/xzZ4BANk5tfU="
    ),
    "zst": (
        "eNoBLwHQ/ii1L/0EaBUJAFQRUmVjb3ZlckFsbCB0ZXN0IGZpbGUKAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj"
        "JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1u"
        "b3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5"
        "uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/wIAAP0G"
        "VjUzojqZ0a5fsyXMj9s="
    ),
    "lz4": (
        "eNoBOwHE/gQiTRhkQKcoAQAA/wZSZWNvdmVyQWxsIHRlc3QgZmlsZQoVAP99//EAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRob"
        "HB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVm"
        "Z2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7Cx"
        "srO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8"
        "/f7/AAH//+pQ+/z9/v8AAAAAZN7NIbIPl/k="
    ),
    "lz": (
        "eNoBKAHX/kxaSVABDAApGUhnIuLpsbfDJla1P2D89D1YTsN7djZWqo2oBw5DSPGkxpxjPhDVkkT/mJzUFYDEMIUK3RaT5cSH2QxF"
        "Xq5+1jlXlAz5RYNsI+K+hlTAlF2m3DKk/HIG6cbc9wzVfXCaCJBb2/318qavT3wFJzxDRAB8d1pI+HTGnt4GaWeNA8NnR4bfp8UK"
        "LYYU5Psg/5Nuss7j6kSuZBjIX5tBJplP3FFKFX9AeiiPGTA/gYCLydqK00jCDSTQ2tOWtUuZPiraWAzfpHOS7UcyCM3H7+k4E/vo"
        "c12e8epeJWFFn9uCrt1k2aHzfvP1TqMuZ7nVqS+5L6REUKWL1vK4xCfLO3VKJc2n8oN8of//+hTBIB34KGOkBQAAAAAAACgBAAAA"
        "AAAARd6P5g=="
    ),
    "sqfs": (
        "eNrLKC4sZmZgYCiYdyKBgYGJgRHIZmQQZDgAJFmAbAcGCLBmgtDGUPo/FMxghPDPQmluqLwqlK64lZyQkpSWmJr8/MGTR88ePn0s"
        "LiAiJCYoKjx9wpRJ0yZOnRweEBIUFhgafP3ClUvXLl69bG5gYmRmaGq8fcOWTds2bt1cXlBSVFZYWvz9w5dP3z5+/czPwcPFx8nL"
        "3d/R09XX2dvt7+Hj5efp633+xJlT506ePa2voaOlp6mrvX7FmlXrVq5dnZ+Rk5WXmZv9/sWbV+9evn0936Dw0hPN4OW+8w2Lr72x"
        "LH5+Nn5DwcVHqt7TdeM3Fl19ZZp9fe39DYWXn+lGb8+9v7H4+jvb6u9v7Qs+XHio7N4va1/46cpL4/Tzc/cXfLz0VDt8fez+ws/X"
        "3lqXv79b/+HDxcfq/vNt6z9+uvraPP/+3v8fPl5+rh+/v/b/x8/X39vX//+bLvH1/4r/7hv+NwdN/nw6qFumuEjEK6jbW+SSUXHQ"
        "TjdW9qkKDKIV04SNQSGXFHHoBAML62c/lQbJEw2tjY2cnvM4fflUDp/4IKaz/+GFjzppK0Q85iq6cDIzCPpwmWuDNKU0MLhpnD1y"
        "4NyESRGTVkyfMnM5g0hq0oMUDS9fn5O+V7VXajAyxG5iN+UHKvZOaGDgduPgZWC/zjDrFzQKBcCR1sDAqvGWYSkjiwRDojA0Mlka"
        "QKQulDcKRsEoGAWjYBSMglEwCkbBKBgFo2AIAQDad+wE"
    ),
    "wim": (
        "eNrzDQ739GVgYLgAxAy8jAxNDCwMDA0MDBuXt4aUrGvO+dGW5NS0OEWBkQEEGRimMYABkxozhAHlM/xigojvYUbh0x04KIBIAbDt"
        "u9V24wAMbUCVQBVJDM9lxO7/rWXogOhm4aiVv/L9wKv59t/vs/zh4RARkJFQUdDRMDGwsXBx8PEICYiJSEnIySgpqKloaejpmDJh"
        "zowlC9as2LJhz44jB86cuHLhzo0nD968+PLh7w9WRl5OUUFZSVVFXU1TQ1tLV0dfz9DA2MjUxNzM0sLaytbG3s6pE+fOXLpw7cqt"
        "G/fuPHrw7MmrF+/efPrw7cuvH//9ZGPi4xITkpNSU9LTMjOys3Jz8vMKC4qLSkvKyyorqqtqa+rrmjZp3qxli9at2rZp365jh86d"
        "unbp3q1nj969+vbp/y92Zn5ucWF5aXVlfW1zY3trd2d/7/Dg+Oj05Pzs8uL66vbm/u7pk+fPXr54/ertm/fvPn74/Onrl+/ffv74"
        "zetvzJ+5GX5IKTA4gUJFmdmY4TLPm1bZ2RsmLBBY3PT/P8M9cGgB4RxF4f/73zPcgISfAOP7ZrupRv9t+192OGnaZRYe+VAurgBM"
        "VMC0w+ZqxrCbn114pZ+ZAfduceYZM6ZIXA0srBQSXR7H5nbCJTwpKbUuI0b06VJpJ/ZqBgEGBkmgiTMZFSY4qN+eYrL2MdvBwvpw"
        "iXqGAyCbehgaORYpO+Z8l77/XmP1rqrpf/ZOk15jvfOJTMma9xIsvz7KmHS3B9XFWs5pmbrZ7M3pA1zrdprNuhPVd87UOkfs887/"
        "G7mEmpt8rMSj+NusJvney7LoXfFCdXHqqvkfn7wK8DFrlQjYsG/FjC8RBhJSDAeOQLzHlgRN1RWMEBqSJ3SFe4oMP8t7OyyteMLG"
        "Fxk/QfrzWx+ICpYLsITJgqwjmiFtjgdvzP+9v7pvr5yaKMavK13uBlUnA7VjCYodlx2mFITE8jrON6m27Hwy3+EF753Y//9sGMIZ"
        "PBl8GewYbMC0I4M7gyuDApDtx+ACZEUw2DIoMRgCMUiFH1DeFyhqx5DJkAfk6yOJ2ADVezIEMTgz+DOEAsVDgGKGYDWY4jYMbkAx"
        "H6A+ZFEjsGpsMjZA0h+IHYEyTgyRQJYrQzDYfBMwBOnDrsKGwQMoFgR0gw/YT94osgZgnfhU2ADdEQRkOwJFPIE2+IFpmI89gGx3"
        "IBkANiEEbGIFEBsCTXNhMGUwB7oNZge6Shugff7A0EfVCwpzIyB0ZDADhgREL7o6kBg+V/kAxYOBIr5AGVDYg0LUeQB84AjWjcsH"
        "pLhSHylt4k4NlkD3muFNC/rw1A4AJxmcEg=="
    ),
}


T2021 = calendar.timegm((2021, 6, 15, 12, 34, 56))
DOS2021 = (((2021 - 1980) << 9 | 6 << 5 | 15) << 16) | (12 << 11 | 34 << 5 | 28)


def sample(name: str) -> bytes:
    return zlib.decompress(base64.b64decode("".join(SAMPLES[name])))


def noise(n: int, seed: int = 0) -> bytes:
    return random.Random(seed).randbytes(n)


def parse(fn, data: bytes, tail: bytes | None = None):
    """FN on DATA at the start of a source, with random bytes after it (what follows a file on a disk)."""
    blob = data + (noise(4096, len(data)) if tail is None else tail)
    return fn(Reader(BytesSource(blob), 0))


def exact(fn, data: bytes, ext: str | None = None, **kw):
    hit = parse(fn, data, **kw)
    assert hit is not None, fn.__name__
    assert hit.length == len(data), (fn.__name__, hit.length, len(data))
    assert hit.chance == CHANCE_GOOD, (fn.__name__, hit.chance)
    if ext:
        assert hit.ext == ext
    return hit


def tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        pytest.skip(f"{name} is not installed")
    return path


PAYLOAD = b"".join(b"line %06d of the payload, with some words to compress\n" % i for i in range(3000))


# ---------------------------------------------------------------------- ZIP
def _zip(members: dict, method=zipfile.ZIP_DEFLATED, date=(2020, 1, 2, 3, 4, 6), stream=False) -> bytes:
    """A ZIP made by zipfile; STREAM: written to an unseekable file, so with data descriptors."""
    class Unseekable(io.RawIOBase):
        def __init__(self):
            self.buf = bytearray()

        def writable(self):
            return True

        def write(self, b):
            self.buf += b
            return len(b)

    out = Unseekable() if stream else io.BytesIO()
    with zipfile.ZipFile(out, "w", method) as z:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, date)
            info.compress_type = zipfile.ZIP_STORED if name == "mimetype" else method
            z.writestr(info, data)
    return bytes(out.buf) if stream else out.getvalue()


def test_zip_plain_and_newest_date():
    data = _zip({"a.txt": PAYLOAD, "dir/b.bin": noise(5000), "empty": b""})
    hit = exact(archives.parse_zip, data, "zip")
    assert hit.category is None or hit.category == "archive"
    assert hit.info["files"] == 3
    assert hit.mtime == calendar.timegm((2020, 1, 2, 3, 4, 6))


def test_zip64(monkeypatch):
    monkeypatch.setattr(zipfile, "ZIP64_LIMIT", 100)
    monkeypatch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 1)
    data = _zip({"a.txt": PAYLOAD, "b.bin": noise(3000), "c.txt": b"x" * 500})
    assert b"PK\x06\x06" in data and b"PK\x06\x07" in data
    exact(archives.parse_zip, data, "zip")


def test_zip_data_descriptors():
    data = _zip({"a.txt": PAYLOAD, "b.bin": noise(3000), "c.txt": b""}, stream=True)
    assert struct.unpack_from("<H", data, 6)[0] & 8 and b"PK\x07\x08" in data
    exact(archives.parse_zip, data, "zip")


def _zip_by_hand(members: list[tuple[str, bytes]], signed: bool) -> bytes:
    """Stored members with bit 3 set (sizes only in a descriptor after the data), no zip tool needed."""
    out = b""
    cd = b""
    for name, data in members:
        nb = name.encode()
        crc = zlib.crc32(data)
        off = len(out)
        out += struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 8, 0, 0x6000, 0x5021, 0, 0, 0, len(nb), 0) + nb + data
        out += (b"PK\x07\x08" if signed else b"") + struct.pack("<III", crc, len(data), len(data))
        cd += struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 8, 0, 0x6000, 0x5021, crc, len(data),
                          len(data), len(nb), 0, 0, 0, 0, 0, off) + nb
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, len(members), len(members), len(cd), len(out), 5) + b"hello"
    return out + cd + eocd


@pytest.mark.parametrize("signed", [True, False])
def test_zip_stored_with_descriptors(signed):
    # the second member holds another ZIP: its signatures must not be taken for the outer one's
    inner = _zip({"x.txt": b"inner " * 100})
    data = _zip_by_hand([("one.txt", PAYLOAD[:7000]), ("inner.zip", inner), ("three", b"")], signed)
    hit = exact(archives.parse_zip, data, "zip")
    assert hit.info["comment"] == "hello"


def test_zip_apk_signing_block():
    plain = _zip({"AndroidManifest.xml": b"\x03\x00\x08\x00" + noise(400), "classes.dex": b"dex\n035\x00" + noise(900),
                  "resources.arsc": noise(300)})
    cd = struct.unpack_from("<I", plain, len(plain) - 6)[0]
    pairs = struct.pack("<QI", 4 + 64, 0x7109871A) + noise(64, 7)
    block = struct.pack("<Q", len(pairs) + 24) + pairs + struct.pack("<Q", len(pairs) + 24) + b"APK Sig Block 42"
    end = plain.rfind(b"PK\x05\x06")
    eocd = bytearray(plain[end:])
    struct.pack_into("<I", eocd, 16, cd + len(block))
    data = plain[:cd] + block + plain[cd:end] + bytes(eocd)
    hit = exact(archives.parse_zip, data, "apk")
    assert hit.category == "executable"


def _ooxml(kind: str, core: bool = True, macro: bool = False) -> dict:
    part = {"docx": "word/document.xml", "xlsx": "xl/workbook.xml", "pptx": "ppt/presentation.xml"}[kind]
    ct = {"docx": "wordprocessingml.document.main+xml", "xlsx": "spreadsheetml.sheet.main+xml",
          "pptx": "presentationml.presentation.main+xml"}[kind]
    if macro:
        ct = {"docx": "application/vnd.ms-word.document.macroEnabled.main+xml",
              "xlsx": "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
              "pptx": "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml"}[kind]
    m = {"[Content_Types].xml": f'<?xml version="1.0"?><Types><Override PartName="/{part}" '
                                f'ContentType="application/vnd.openxmlformats-officedocument.{ct}"/></Types>',
         "_rels/.rels": "<Relationships/>", part: "<x/>" * 50}
    if core:
        m["docProps/core.xml"] = (
            '<?xml version="1.0"?><cp:coreProperties xmlns:cp="c" xmlns:dc="d" xmlns:dcterms="t">'
            "<dc:title>Budget &amp; Plans 2021</dc:title><dc:creator>Ann Example</dc:creator>"
            '<dcterms:created xsi:type="dcterms:W3CDTF">2021-03-04T05:06:07Z</dcterms:created>'
            '<dcterms:modified xsi:type="dcterms:W3CDTF">2021-03-05T10:00:00+02:00</dcterms:modified>'
            "</cp:coreProperties>")
        m["docProps/app.xml"] = "<Properties><Application>Microsoft Office Word</Application></Properties>"
    if macro:
        m[part.split("/")[0] + "/vbaProject.bin"] = noise(700)
    return m


ODT_META = ('<?xml version="1.0"?><office:document-meta><office:meta><meta:generator>LibreOffice/7.3</meta:generator>'
            "<dc:title>Minutes of the meeting</dc:title><meta:initial-creator>Bob</meta:initial-creator>"
            "<meta:creation-date>2019-11-12T13:14:15</meta:creation-date><dc:date>2019-11-13T08:00:00</dc:date>"
            "</office:meta></office:document-meta>")
OPF = ('<?xml version="1.0"?><package><metadata><dc:title>A Tale of Two Files</dc:title><dc:creator>C. Dickens'
       '</dc:creator><meta property="dcterms:modified">2018-01-01T00:00:00Z</meta></metadata></package>')


@pytest.mark.parametrize("members, ext, category, title, mtime", [
    (_ooxml("docx"), "docx", "document", "Budget & Plans 2021", calendar.timegm((2021, 3, 5, 8, 0, 0))),
    (_ooxml("xlsx", macro=True), "xlsm", "document", "Budget & Plans 2021", None),
    (_ooxml("pptx", core=False), "pptx", "document", None, None),
    ({"mimetype": "application/vnd.oasis.opendocument.text", "content.xml": "<x/>" * 40, "meta.xml": ODT_META,
      "META-INF/manifest.xml": "<m/>"}, "odt", "document", "Minutes of the meeting",
     calendar.timegm((2019, 11, 13, 8, 0, 0))),
    ({"mimetype": "application/vnd.oasis.opendocument.spreadsheet", "content.xml": "<x/>"}, "ods", "document", None,
     None),
    ({"mimetype": "application/epub+zip", "META-INF/container.xml": "<container/>", "OEBPS/content.opf": OPF,
      "OEBPS/ch1.xhtml": "<html/>" * 30}, "epub", "document", "A Tale of Two Files", calendar.timegm((2018, 1, 1, 0, 0, 0))),
    ({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nCreated-By: 17 (Oracle)\r\nImplementation-Title: Tool\r\n",
      "org/example/Main.class": b"\xca\xfe\xba\xbe" + bytes(200)}, "jar", "executable", "Tool", None),
    ({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n", "WEB-INF/web.xml": "<web-app/>"}, "war", "executable",
     None, None),
    ({"AndroidManifest.xml": b"\x03\x00" + bytes(300), "classes.dex": b"dex\n035\x00" + bytes(300),
      "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"}, "apk", "executable", None, None),
    ({"Payload/Game.app/Info.plist": "<plist/>", "Payload/Game.app/Game": bytes(500)}, "ipa", "executable", None,
     None),
    ({"[Content_Types].xml": "<Types/>", "FixedDocumentSequence.fdseq": "<x/>",
      "Documents/1/FixedDocument.fdoc": "<x/>"}, "xps", "document", None, None),
    ({"[Content_Types].xml": "<Types/>", "3D/3dmodel.model": "<model/>" * 20}, "3mf", "other", None, None),
    ({"Index/Document.iwa": bytes(300), "Index/DocumentStylesheet.iwa": bytes(100)}, "pages", "document", None,
     None),
    ({"Index/Document.iwa": bytes(300), "Index/CalculationEngine.iwa": bytes(100)}, "numbers", "document", None,
     None),
    ({"doc.kml": "<kml/>" * 30}, "kmz", "other", None, None),
    ({"pkg/__init__.py": "x = 1\n", "pkg-1.0.dist-info/WHEEL": "Wheel-Version: 1.0\n",
      "pkg-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n"}, "whl", "archive", "pkg-1.0",
     None),
])
def test_zip_kinds(members, ext, category, title, mtime):
    data = _zip(members)
    hit = exact(archives.parse_zip, data, ext)
    assert (hit.category or "archive") == category
    assert hit.name == title
    if mtime is not None:
        assert hit.mtime == mtime
    if ext == "docx":
        assert hit.info["author"] == "Ann Example" and hit.info["application"] == "Microsoft Office Word"


def test_zip_odt_with_descriptors():
    # LibreOffice-style: "mimetype" stored first, the rest deflated with data descriptors
    data = _zip({"mimetype": "application/vnd.oasis.opendocument.presentation", "meta.xml": ODT_META,
                 "content.xml": "<x/>" * 400}, stream=True)
    hit = exact(archives.parse_zip, data, "odp")
    assert hit.name == "Minutes of the meeting" and hit.info["author"] == "Bob"


def test_zip_truncated_and_overwritten():
    data = _zip({"a.txt": PAYLOAD, "b.bin": noise(20000), "c.txt": PAYLOAD[:9000]})
    second = data.index(b"PK\x03\x04", 4)
    third = data.index(b"PK\x03\x04", second + 4)
    # overwritten inside the second member: the walk stops where the third should have started
    hit = parse(archives.parse_zip, data[:second + 5000], tail=noise(65536, 1))
    assert hit.length == third and hit.chance == CHANCE_POOR
    # a damaged header: what is left is the first member
    hit = parse(archives.parse_zip, data[:second + 10] + noise(30000, 2))
    assert hit.length == second and hit.chance == CHANCE_POOR
    # the central directory is gone
    cd = data.index(b"PK\x01\x02")
    hit = parse(archives.parse_zip, data[:cd])
    assert hit.length == cd and hit.chance == CHANCE_POOR
    # the source ends inside the archive
    hit = archives.parse_zip(Reader(BytesSource(data[:cd - 100]), 0))
    assert hit.chance == CHANCE_POOR and hit.length <= cd - 100


def test_zip_streamed_member_damaged_falls_back_on_the_end_record():
    data = bytearray(_zip({"a.txt": PAYLOAD, "b.txt": PAYLOAD[:20000]}, stream=True))
    second = data.index(b"PK\x03\x04", 4)
    data[second + 200:second + 260] = bytes(60)           # the deflate data of the second member is damaged
    hit = parse(archives.parse_zip, bytes(data))
    assert hit.length == len(data) and hit.chance >= 2


# ---------------------------------------------------------------------- tar, gzip, bzip2, xz, lzip
@pytest.mark.parametrize("fmt", [tarfile.GNU_FORMAT, tarfile.PAX_FORMAT, tarfile.USTAR_FORMAT])
def test_tar(fmt):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=fmt) as t:
        for i, size in enumerate((0, 1, 511, 512, 513, 30000)):
            name = (("deep/" * 15 if fmt != tarfile.USTAR_FORMAT else "deep/" * 8) + f"file{i}.txt")
            info = tarfile.TarInfo(name)
            info.size = size
            info.mtime = 1600000000 + i
            t.addfile(info, io.BytesIO(PAYLOAD[:size]))
        info = tarfile.TarInfo("adir")
        info.type = tarfile.DIRTYPE
        info.mtime = 1500000000
        t.addfile(info)
    data = out.getvalue()
    assert len(data) % 10240 == 0
    hit = exact(archives.parse_tar, data, "tar")
    assert hit.mtime == 1600000005 and hit.info["files"] == 7
    assert hit.info["first_file"].endswith("file0.txt")
    # overwritten in the middle of the big member: no end marker, cut where the next header should be
    last = tarfile.open(fileobj=io.BytesIO(data)).getmembers()[-1].offset
    cut = parse(archives.parse_tar, data[:len(data) // 2], tail=noise(65536, 1))
    assert cut.chance == CHANCE_POOR and cut.length == last


def test_tar_without_record_padding():
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as t:
        t.addfile(tarfile.TarInfo("x"), io.BytesIO())
    data = out.getvalue().rstrip(b"\0") + bytes(1024 + 512 - len(out.getvalue().rstrip(b"\0")) % 512)
    hit = parse(archives.parse_tar, data)
    assert hit.length == len(data) and hit.chance == CHANCE_GOOD


def test_gzip():
    buf = io.BytesIO()
    with gzip.GzipFile("report.txt", "wb", fileobj=buf, mtime=1600000000) as g:
        g.write(PAYLOAD)
    data = buf.getvalue()
    hit = exact(archives.parse_gz, data, "gz")
    assert hit.name == "report.txt" and hit.mtime == 1600000000
    # several members (pigz, BGZF), then a tar.gz
    multi = gzip.compress(PAYLOAD[:5000]) + gzip.compress(PAYLOAD[5000:]) + gzip.compress(b"")
    exact(archives.parse_gz, multi, "gz")
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w:gz") as t:
        info = tarfile.TarInfo("x.txt")
        info.size = 5000
        t.addfile(info, io.BytesIO(PAYLOAD[:5000]))
    exact(archives.parse_gz, tbuf.getvalue(), "tar.gz")


def test_gzip_damaged():
    data = gzip.compress(PAYLOAD)
    cut = parse(archives.parse_gz, data[:len(data) // 2])
    assert cut.length is None and cut.chance == CHANCE_POOR
    bad = bytearray(data)
    bad[-8] ^= 0xFF                                         # the CRC doesn't match
    assert parse(archives.parse_gz, bytes(bad)).chance == CHANCE_POOR


def test_bzip2():
    text = b"".join(b"%d %s\n" % (i, hashlib.sha1(b"%d" % i).hexdigest().encode()) for i in range(40000))
    data = bz2.compress(text, 1)                            # several 100k blocks
    exact(archives.parse_bz2, data, "bz2")
    exact(archives.parse_bz2, bz2.compress(b""), "bz2")
    exact(archives.parse_bz2, bz2.compress(PAYLOAD) + bz2.compress(PAYLOAD[:999]), "bz2")    # pbzip2 style
    cut = parse(archives.parse_bz2, data[:len(data) // 2])
    assert cut.length is None and cut.chance == CHANCE_POOR
    # fragmented: half of one stream, then another file's blocks; the stream checksum gives it away
    other = bz2.compress(PAYLOAD[::-1], 1)
    hit = parse(archives.parse_bz2, data[:len(data) // 2] + other)
    assert hit.chance == CHANCE_POOR or hit.length is None


def test_xz():
    data = lzma.compress(PAYLOAD)
    exact(archives.parse_xz, data, "xz")
    exact(archives.parse_xz, lzma.compress(PAYLOAD, check=lzma.CHECK_SHA256) + bytes(8) + lzma.compress(b"x"), "xz")
    cut = parse(archives.parse_xz, data[:len(data) // 2])
    assert cut.length is None and cut.chance == CHANCE_POOR


def test_xz_blocks_with_sizes(tmp_path):
    tool("xz")
    src = tmp_path / "p.bin"
    src.write_bytes(PAYLOAD * 3)
    data = subprocess.run(["xz", "-c", "-T2", "--block-size=65536", str(src)], capture_output=True,
                          check=True).stdout
    exact(archives.parse_xz, data, "xz")


def test_lzip():
    exact(archives.parse_lzip, sample("lz"), "lz")
    exact(archives.parse_lzip, sample("lz") + sample("lz"), "lz")


# ---------------------------------------------------------------------- 7z, RAR, zstd, LZ4, cab, ARJ
@pytest.mark.parametrize("name, fn, ext, sees_cut", [
    ("7z", archives.parse_7z, "7z", True), ("rar", archives.parse_rar, "rar", True),
    ("zst", archives.parse_zst, "zst", False), ("lz4", archives.parse_lz4, "lz4", False),
    ("cab", archives.parse_cab, "cab", False), ("arj", archives.parse_arj, "arj", True),
    ("lz", archives.parse_lzip, "lz", True), ("sqfs", archives.parse_squashfs, "squashfs", False),
    ("wim", archives.parse_wim, "wim", False),
])
def test_embedded_samples(name, fn, ext, sees_cut):
    data = sample(name)
    hit = exact(fn, data, ext)
    if name in ("cab", "arj", "sqfs"):
        assert abs(hit.mtime - T2021) <= 2
    if sees_cut:
        # cut short, then random data: never a good file of the full length (formats that only state
        # their length in a header can't tell without unpacking: those are measured the same either way)
        cut = parse(fn, data[:len(data) * 2 // 3])
        assert cut is None or cut.chance < CHANCE_GOOD or (cut.length or 0) <= len(data) * 2 // 3


def test_rar5_details():
    hit = exact(archives.parse_rar, sample("rar"), "rar")
    assert hit.info["version"] == 5 and hit.info["files"] == 2


def _rar4(files: list[tuple[str, bytes]]) -> bytes:
    """A RAR 4 archive of stored files, by hand (rar 7 can't write the old format any more)."""
    def block(typ, flags, body=b""):
        hdr = struct.pack("<BHH", typ, flags, 7 + len(body)) + body
        return struct.pack("<H", zlib.crc32(hdr) & 0xFFFF) + hdr

    out = b"Rar!\x1a\x07\x00" + block(0x73, 0, bytes(6))
    for name, data in files:
        nb = name.encode()
        out += block(0x74, 0x8000, struct.pack("<IIBIIBBHI", len(data), len(data), 2, zlib.crc32(data), DOS2021, 29,
                                              0x30, len(nb), 0x20) + nb) + data
    return out + block(0x7B, 0x4000)


def test_rar4(tmp_path):
    data = _rar4([("a.txt", PAYLOAD[:3000]), ("b.bin", noise(1000))])
    hit = exact(archives.parse_rar, data, "rar")
    assert hit.info["version"] == 4 and hit.info["files"] == 2 and hit.mtime == T2021
    if shutil.which("7z"):                                  # the archivers agree it is a valid archive
        (tmp_path / "x.rar").write_bytes(data)
        assert subprocess.run(["7z", "t", str(tmp_path / "x.rar")], capture_output=True).returncode == 0
    # without its end block (old RAR versions): measured to the last block, fair
    hit = parse(archives.parse_rar, data[:-7])
    assert hit.length == len(data) - 7 and hit.chance == 2


def test_made_with_installed_archivers(tmp_path):
    """Bigger archives straight from the archivers, when they are installed (skipped otherwise)."""
    src = tmp_path / "in"
    src.mkdir()
    (src / "a.txt").write_bytes(PAYLOAD)
    (src / "b.bin").write_bytes(noise(70000))
    made = 0
    for prog, args, out, fn in [
        ("7z", ["7z", "a", "-bd", "-y", "{o}", "a.txt", "b.bin"], "x.7z", archives.parse_7z),
        ("rar", ["rar", "a", "-inul", "{o}", "a.txt", "b.bin"], "x.rar", archives.parse_rar),
        ("gcab", ["gcab", "-c", "-z", "{o}", "a.txt", "b.bin"], "x.cab", archives.parse_cab),
        ("zstd", ["zstd", "-q", "a.txt", "-o", "{o}"], "x.zst", archives.parse_zst),
        ("lz4", ["lz4", "-q", "a.txt", "{o}"], "x.lz4", archives.parse_lz4),
        ("arj", ["arj", "a", "-y", "{o}", "a.txt", "b.bin"], "x.arj", archives.parse_arj),
        ("lzip", ["lzip", "-k", "-o", "{o}", "a.txt"], "x.lz", archives.parse_lzip),
    ]:
        if not shutil.which(prog):
            continue
        o = str(tmp_path / out)
        subprocess.run([a.replace("{o}", o) for a in args], cwd=src, capture_output=True, check=True)
        data = (tmp_path / out).read_bytes()
        exact(fn, data)
        made += 1
    if not made:
        pytest.skip("no archiver installed")


# ---------------------------------------------------------------------- cpio, ar/deb, RPM, xar, LHA
def _newc(entries: list[tuple[str, bytes]], magic=b"070701") -> bytes:
    out = b""
    for ino, (name, data) in enumerate(entries + [("TRAILER!!!", b"")], 1):
        nb = name.encode() + b"\0"
        mode = 0o100644 if name != "TRAILER!!!" else 0
        out += magic + b"".join(b"%08X" % v for v in (ino, mode, 0, 0, 1, 1600000000, len(data), 0, 0, 0, 0, len(nb), 0))
        out += nb + bytes(-(110 + len(nb)) % 4) + data + bytes(-len(data) % 4)
    return out + bytes(-len(out) % 512)


def _odc(entries: list[tuple[str, bytes]]) -> bytes:
    out = b""
    for ino, (name, data) in enumerate(entries + [("TRAILER!!!", b"")], 1):
        nb = name.encode() + b"\0"
        out += b"070707" + b"%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o" % (
            0, ino, 0o100644, 0, 0, 1, 0, 1600000000, len(nb), len(data)) + nb + data
    return out + bytes(-len(out) % 512)


def _bincpio(entries: list[tuple[str, bytes]]) -> bytes:
    out = b""
    for ino, (name, data) in enumerate(entries + [("TRAILER!!!", b"")], 1):
        nb = name.encode() + b"\0"
        mode = 0o100644 if name != "TRAILER!!!" else 0
        out += struct.pack("<13H", 0o70707, 0, ino, mode, 0, 0, 1, 0, 1600000000 >> 16, 1600000000 & 0xFFFF, len(nb),
                           len(data) >> 16, len(data) & 0xFFFF) + nb + bytes(len(nb) & 1) + data + bytes(len(data) & 1)
    return out + bytes(-len(out) % 512)


@pytest.mark.parametrize("build", [_newc, _odc, _bincpio])
def test_cpio(build):
    data = build([("etc/hosts", b"127.0.0.1 localhost\n"), ("bin/x", noise(3001)), ("empty", b"")])
    hit = exact(archives.parse_cpio, data, "cpio")
    assert hit.info["files"] == 3 and hit.mtime == 1600000000


def test_cpio_agrees_with_gnu_cpio(tmp_path):
    tool("cpio")
    (tmp_path / "f.txt").write_bytes(PAYLOAD[:5000])
    for fmt in ("newc", "odc", "bin", "crc"):
        data = subprocess.run(["cpio", "-o", "-H", fmt], input=b"f.txt\n", cwd=tmp_path, capture_output=True,
                              check=True).stdout
        exact(archives.parse_cpio, data, "cpio")


def _ar(members: list[tuple[str, bytes]]) -> bytes:
    out = b"!<arch>\n"
    for name, data in members:
        out += b"%-16s%-12d%-6d%-6d%-8o%-10d`\n" % (name.encode(), 1600000000, 0, 0, 0o100644, len(data))
        out += data + (b"\n" if len(data) % 2 else b"")
    return out


def test_deb_and_ar():
    control = io.BytesIO()
    with tarfile.open(fileobj=control, mode="w:gz") as t:
        info = tarfile.TarInfo("./control")
        info.size = 20
        t.addfile(info, io.BytesIO(b"Package: hello\n" + bytes(5)))
    data_tar = lzma.compress(b"\0" * 10240)
    deb = _ar([("debian-binary", b"2.0\n"), ("control.tar.gz", control.getvalue()), ("data.tar.xz", data_tar)])
    hit = exact(archives.parse_ar, deb, "deb")
    assert hit.category == "executable" and hit.mtime == 1600000000
    lib = _ar([("/", b"\0\0\0\0"), ("foo.o/", noise(1001)), ("bar.o/", noise(500))])
    hit = parse(archives.parse_ar, lib)
    assert hit.ext == "a" and hit.length == len(lib)


def _rpm_header(tags) -> bytes:
    index = store = b""
    for tag, typ, data, count in tags:
        store += bytes(-len(store) % {4: 4, 5: 8}.get(typ, 1))
        index += struct.pack(">IIII", tag, typ, len(store), count)
        store += data
    return b"\x8e\xad\xe8\x01" + bytes(4) + struct.pack(">II", len(tags), len(store)) + index + store


def _rpm(with_size: bool) -> bytes:
    lead = b"\xed\xab\xee\xdb\x03\x00" + struct.pack(">HH", 0, 1) + b"hello-1.0-1".ljust(66, b"\0") + \
        struct.pack(">HH", 1, 5) + bytes(16)
    main = _rpm_header([(1000, 6, b"hello\0", 1), (1001, 6, b"1.0\0", 1), (1002, 6, b"1\0", 1),
                        (1006, 4, struct.pack(">I", 1600000000), 1), (1022, 6, b"x86_64\0", 1),
                        (1124, 6, b"cpio\0", 1), (1125, 6, b"gzip\0", 1)])
    payload = gzip.compress(_newc([("./usr/bin/hello", noise(5000))]))
    sig = _rpm_header([(1000, 4, struct.pack(">I", len(main) + len(payload)), 1)] if with_size else
                      [(1004, 7, noise(16), 16)])
    return lead + sig + bytes(-len(sig) % 8) + main + payload


@pytest.mark.parametrize("with_size", [True, False])
def test_rpm(with_size):
    data = _rpm(with_size)
    hit = parse(archives.parse_rpm, data)
    assert hit.length == len(data) and hit.ext == "rpm" and hit.category == "executable"
    assert hit.name == "hello-1.0-1.x86_64" and hit.mtime == 1600000000


def test_xar():
    content = noise(3000)
    packed = zlib.compress(content)
    toc = (b'<?xml version="1.0" encoding="UTF-8"?>\n<xar>\n <toc>\n'
           b'  <checksum style="sha1"><offset>0</offset><size>20</size></checksum>\n'
           b'  <file id="1"><name>a.bin</name><data><length>%d</length><offset>20</offset><size>%d</size>'
           b'<encoding style="application/x-gzip"/><archived-checksum style="sha1">00</archived-checksum></data>'
           b'</file>\n </toc>\n</xar>\n' % (len(packed), len(content)))
    tocz = zlib.compress(toc)
    data = b"xar!" + struct.pack(">HHQQI", 28, 1, len(tocz), len(toc), 1) + tocz + \
        hashlib.sha1(tocz).digest() + packed
    exact(archives.parse_xar, data, "xar")


def _crc16(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def _lzh(entries: list[tuple[str, bytes]], level: int) -> bytes:
    out = b""
    for name, data in entries:
        nb = name.encode()
        if level == 0:
            body = b"-lh0-" + struct.pack("<IIIBBB", len(data), len(data), DOS2021, 0x20, 0, len(nb)) + nb + \
                struct.pack("<H", _crc16(data))
            out += bytes([len(body), sum(body) & 0xFF]) + body + data
        else:
            ext_name = bytes([1]) + nb + struct.pack("<H", 0)
            base = b"-lh0-" + struct.pack("<IIIBBHBH", len(data), len(data), T2021, 0x20, 2, _crc16(data), ord("U"),
                                          len(ext_name))
            out += struct.pack("<H", 2 + len(base) + len(ext_name)) + base + ext_name + data
    return out + b"\0"


@pytest.mark.parametrize("level", [0, 2])
def test_lzh(level, tmp_path):
    data = _lzh([("readme.txt", PAYLOAD[:2000]), ("b.bin", noise(700))], level)
    hit = exact(archives.parse_lzh, data, "lzh")
    assert hit.mtime == T2021 and hit.info["files"] == 2
    if shutil.which("lha"):                                 # lhasa lists the same files
        (tmp_path / "x.lzh").write_bytes(data)
        out = subprocess.run(["lha", "l", str(tmp_path / "x.lzh")], capture_output=True, text=True)
        assert out.returncode == 0 and "readme.txt" in out.stdout and "b.bin" in out.stdout


# ---------------------------------------------------------------------- disk images
def _iso(label: str = "TESTDISC", blocks: int = 20) -> bytes:
    pvd = bytearray(2048)
    pvd[0:7] = b"\x01CD001\x01"
    pvd[8:40] = b" " * 32
    pvd[40:72] = label.encode().ljust(32)
    pvd[80:88] = struct.pack("<I", blocks) + struct.pack(">I", blocks)
    pvd[120:128] = struct.pack("<H", 1) + struct.pack(">H", 1) + struct.pack("<H", 1) + struct.pack(">H", 1)
    pvd[128:132] = struct.pack("<H", 2048) + struct.pack(">H", 2048)
    pvd[156] = 34
    pvd[813:830] = b"2021061512345600\x00"
    pvd[881] = 1
    term = b"\xffCD001\x01" + bytes(2041)
    img = bytes(16 * 2048) + bytes(pvd) + term
    return img + noise(blocks * 2048 - len(img), 3)


def test_iso_by_hand():
    data = _iso()
    hit = exact(archives.parse_iso, data, "iso")
    assert hit.name == "TESTDISC" and hit.mtime == T2021


def test_iso_genisoimage(tmp_path):
    prog = shutil.which("genisoimage") or shutil.which("mkisofs") or tool("xorrisofs")
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "a.txt").write_bytes(PAYLOAD)
    subprocess.run([prog, "-quiet", "-V", "MY_DISC", "-o", str(tmp_path / "x.iso"), str(tmp_path / "d")],
                   capture_output=True, check=True)
    data = (tmp_path / "x.iso").read_bytes()
    hit = exact(archives.parse_iso, data, "iso")
    assert hit.name == "MY_DISC"


# ---------------------------------------------------------------------- robustness
ALL = archives.FORMATS


@pytest.mark.parametrize("fmt", ALL, ids=[f.key for f in ALL])
def test_random_data_with_planted_magic_is_rejected(fmt):
    for seed in range(40):
        for off, magic in fmt.magic:
            blob = bytearray(noise(256 * 1024, seed * 7 + off))
            blob[off:off + len(magic)] = magic
            hit = fmt.parse(Reader(BytesSource(bytes(blob)), 0))
            assert hit is None, (fmt.key, seed, magic, hit)


def _samples() -> list[tuple[object, bytes]]:
    return [(archives.parse_zip, _zip({"a.txt": PAYLOAD[:20000], "b": noise(2000)}, stream=True)),
            (archives.parse_zip, _zip(_ooxml("docx"))),
            (archives.parse_tar, tarfile_bytes()),
            (archives.parse_gz, gzip.compress(PAYLOAD[:20000])),
            (archives.parse_bz2, bz2.compress(PAYLOAD[:20000])),
            (archives.parse_xz, lzma.compress(PAYLOAD[:20000])),
            (archives.parse_rar, _rar4([("a", PAYLOAD[:999])])),
            (archives.parse_cpio, _newc([("a", b"x" * 99)])),
            (archives.parse_cpio, _bincpio([("a", b"x" * 99)])),
            (archives.parse_ar, _ar([("debian-binary", b"2.0\n"), ("data.tar", b"x" * 99)])),
            (archives.parse_rpm, _rpm(False)),
            (archives.parse_lzh, _lzh([("a", b"x" * 99)], 2)),
            (archives.parse_iso, _iso())] + [
        (fn, sample(name)) for name, fn in [("7z", archives.parse_7z), ("rar", archives.parse_rar),
                                            ("zst", archives.parse_zst), ("lz4", archives.parse_lz4),
                                            ("cab", archives.parse_cab), ("arj", archives.parse_arj),
                                            ("lz", archives.parse_lzip), ("sqfs", archives.parse_squashfs),
                                            ("wim", archives.parse_wim)]]


def tarfile_bytes() -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as t:
        info = tarfile.TarInfo("a.txt")
        info.size = 3000
        t.addfile(info, io.BytesIO(PAYLOAD[:3000]))
    return out.getvalue()


def test_damaged_samples_never_raise():
    rnd = random.Random(5)
    for fn, data in _samples():
        assert parse(fn, data) is not None, fn.__name__
        for _ in range(60):
            bad = bytearray(data)
            for _ in range(rnd.randint(1, 8)):
                i = rnd.randrange(len(bad))
                bad[i] = rnd.randrange(256)
            if rnd.random() < 0.3:
                bad = bad[:rnd.randrange(1, len(bad))]
            hit = parse(fn, bytes(bad))
            assert hit is None or hit.length is None or hit.length > 0


# ---------------------------------------------------------------------- through the engine
def test_carver_finds_archives_in_random_data():
    planted = [("zip", _zip({"a.txt": PAYLOAD[:30000], "b.bin": noise(4000)}), "zip"),
               ("zip", _zip(_ooxml("docx")), "docx"),
               ("tar", tarfile_bytes(), "tar"),
               ("gz", gzip.compress(PAYLOAD[:50000]), "gz"),
               ("bz2", bz2.compress(PAYLOAD[:50000]), "bz2"),
               ("xz", lzma.compress(PAYLOAD[:50000]), "xz"),
               ("7z", sample("7z"), "7z"), ("rar", sample("rar"), "rar"), ("rar", _rar4([("a", noise(999))]), "rar"),
               ("cab", sample("cab"), "cab"), ("zst", sample("zst"), "zst"), ("cpio", _newc([("a", noise(77))]), "cpio"),
               ("ar", _ar([("debian-binary", b"2.0\n"), ("data.tar.gz", gzip.compress(b"x"))]), "deb"),
               ("rpm", _rpm(True), "rpm"), ("iso", _iso(), "iso"), ("squashfs", sample("sqfs"), "squashfs")]
    img = bytearray()
    where = []
    for i, (key, data, ext) in enumerate(planted):
        img += noise(512 * (3 + i % 5), 100 + i)
        where.append((len(img), len(data), key, ext))
        img += data
        img += bytes(-len(img) % 512)
    img += noise(8192, 99)
    formats = [f for f in archives.FORMATS + documents.FORMATS if f.enabled]
    found = {(f.offset, f.length, f.key, f.ext) for f in Carver(BytesSource(bytes(img)), formats).scan()}
    for off, n, key, ext in where:
        assert (off, n, key, ext) in found, (off, n, key, ext, sorted(found))
