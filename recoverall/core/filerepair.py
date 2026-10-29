"""Repairing damaged files: photos, archives and Office documents, PDFs, sound and video containers.

Files that come back from a damaged disk, or that a signature search carved out of free space, are often
damaged in a few typical ways, and most of them can be put right because the format says where everything is:

=============  ===================================================================================================
JPEG           other data before the start marker (cut); data after the end marker (cut; a camera's second
               image or a motion-photo video after it is kept); cut short (the missing MCUs are coded as grey with
               the photo's own tables, restart markers included: the photo keeps its size, opens everywhere,
               and how much is missing is said); picture data damaged inside, found exactly
               by decoding it (media/jpegdec.py): with restart markers the damaged intervals are replaced by
               grey ones coded with the photo's own tables and the rest shows in its place, without them the
               photo is kept up to the last good MCU and the rest filled with grey; a progressive photo is
               ended after its last complete pass; other data between the header's segments (cut out); a
               damaged header or damaged tables (rebuilt from the intact tables just before the image data,
               or taken from a REFERENCE photo of the same camera and size); no Huffman tables (MJPEG frames
               from AVI files: the standard tables of JPEG Annex K are inserted); nothing of the photo left
               (its embedded preview — EXIF thumbnail or MPF picture — is saved instead).
RAW, HEIC      camera RAW files (CR2, CR3, NEF, ARW, RAF, ORF, RW2, PEF, DNG, SRW...) and HEIC photos that
               can't be developed: the largest embedded preview that decodes completely is saved as
               "<name> (preview).jpg" (media/rawpreview.py).
PNG            wrong checksums (recomputed), data after IEND (cut), a damaged signature (rewritten), cut-short or
               damaged image data: the readable rows are kept, the rest is black, all in one new IDAT.
GIF            cut short (the frame that is there is closed and the trailer added), data after the trailer.
ZIP family     zip, docx/xlsx/pptx, odt/ods/odp, epub, jar, apk...: every member is found by its local header,
               decompressed and checked against its CRC; a new archive is written with the good ones (ODF/EPUB
               "mimetype" first and uncompressed; a lost [Content_Types].xml or mimetype is recreated).
PDF            a new cross-reference table from the objects themselves (a partial object at the end is dropped),
               with the catalog and /Info found again. Objects inside object streams (PDF 1.5+) are reached
               through the old cross-reference stream when it survived.
WAV, AVI,      RIFF/FORM, data/movi/SSND sizes set to what is really there (unfinished recordings, cut-short
WebP, AIFF     files); data after the last complete chunk cut; a missing AVI index (idx1) rebuilt.
GZIP, BZ2, XZ  the readable beginning of the content is saved (not recompressed), with how much was readable.
MP3            other data before the first frame (or ID3 tag) and after the last frame cut; damaged stretches
               in the middle dropped.
MP4/MOV/3GP    a recording without its index (moov box: battery, crash, card removed) is rebuilt from its frames,
               learning tracks, codecs, timing and interleaving from a REFERENCE recording of the same camera (or
               from the stream alone when it repeats its parameter sets: picture only); a cut-short file keeps its
               complete frames with shortened sample tables; fragmented files lose an incomplete last fragment;
               data after the end is cut (media/mp4repair.py).
MKV, WebM      cut short, damaged in the middle, Cues/SeekHead/duration wrong or missing, the start lost (the
               REFERENCE's header) (media/mkv.py).
TS, MTS/M2TS   junk and broken packets dropped, video resumed at random-access points, PAT/PMT put in front
               (media/mpegts.py).
MPG, VOB, MOD  resync after damage, video resumed at an I picture, sound cut to whole frames, a missing sequence
               header inserted (media/mpegps.py).
WMV, WMA, ASF  damaged packets dropped, counts, sizes, durations and the index rebuilt, a lost header from the
               REFERENCE (media/asf.py).
FLV            cut at the last complete tag, resync after damage, metadata and key-frame index patched
               (media/flv.py).
=============  ===================================================================================================

The input file is never modified: repairs are written to a new file. Everything here is standard library
(zlib, bz2, lzma, struct, re); files are read through mmap and written piece by piece, so big videos and
archives don't have to fit in memory.
"""

from __future__ import annotations

import bisect
import bz2
import contextlib
import lzma
import mmap
import os
import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable

from .errors import Cancelled, RallError, UnsafeOperation
from .fs.base import NULL_CONTROL, Control
from .util import fmt_bytes, give_to_caller, safe_filename

KiB, MiB = 1024, 1024 * 1024
_CHUNK = 4 * MiB

EXTENSIONS = {
    "jpg": "jpg", "jpeg": "jpg", "jpe": "jpg", "jfif": "jpg", "png": "png", "gif": "gif", "pdf": "pdf",
    "wav": "wav", "avi": "avi", "webp": "webp", "aif": "aiff", "aiff": "aiff", "aifc": "aiff",
    "gz": "gz", "tgz": "gz", "bz2": "bz2", "tbz": "bz2", "tbz2": "bz2", "xz": "xz", "txz": "xz", "mp3": "mp3",
    "mp4": "mp4", "m4a": "mp4", "m4v": "mp4", "mov": "mov", "3gp": "mp4", "qt": "mov",
    "3g2": "mp4", "lrv": "mp4", "insv": "mp4", "mkv": "mkv", "webm": "webm", "mka": "mkv", "mk3d": "mkv",
    "weba": "webm", "ts": "ts", "m2ts": "m2ts", "mts": "m2ts", "m2t": "ts", "trp": "ts", "tp": "ts", "tod": "ts",
    "mpg": "mpg", "mpeg": "mpg", "mpe": "mpg", "m2p": "mpg", "vob": "vob", "mod": "mpg", "vro": "vob",
    "evo": "vob", "wmv": "wmv", "wma": "wma", "asf": "asf", "dvr-ms": "asf", "flv": "flv",
}
# the repair handlers that live in recoverall.core.media, loaded when first needed: kind → (module, function)
MEDIA_HANDLERS = {"mkv": ("mkv", "plan_mkv"), "ts": ("mpegts", "plan_mpegts"), "ps": ("mpegps", "plan_mpegps"),
                  "asf": ("asf", "plan_asf"), "flv": ("flv", "plan_flv"), "raw": ("rawpreview", "plan_raw")}
# camera RAW photos (and HEIC): a damaged one is "repaired" into the full-size preview it carries
RAW_TYPES = frozenset({"cr2", "cr3", "crw", "nef", "nrw", "arw", "sr2", "srf", "orf", "rw2", "rwl", "pef", "dng",
                       "srw", "3fr", "erf", "kdc", "dcr", "mos", "iiq", "raf", "mef", "mrw", "x3f", "heic", "heif"})
EXTENSIONS.update({t: t for t in RAW_TYPES})
# ISO media brands that are pictures (Canon CR3, HEIF/HEIC, AVIF), not movies
_PHOTO_BRANDS = (b"crx ", b"heic", b"heix", b"mif1", b"msf1", b"avif", b"avis", b"hevc", b"hevx")
# the kinds whose repair can use a reference file of the same camera or program
REFERENCE_KINDS = {"jpg", "mp4", "mkv", "ts", "ps", "asf", "flv"}
ZIP_TYPES = {"zip", "docx", "docm", "dotx", "xlsx", "xlsm", "xltx", "pptx", "pptm", "potx", "ppsx", "vsdx",
             "odt", "ods", "odp", "odg", "odf", "ott", "ots", "otp", "epub", "jar", "war", "apk", "aab", "xpi",
             "kmz", "cbz", "ipa", "whl", "3mf", "idml", "sxw", "sxc", "oxt", "nupkg", "appx", "msix"}
ODF_MIMETYPES = {"odt": "application/vnd.oasis.opendocument.text",
                 "ods": "application/vnd.oasis.opendocument.spreadsheet",
                 "odp": "application/vnd.oasis.opendocument.presentation",
                 "odg": "application/vnd.oasis.opendocument.graphics",
                 "odf": "application/vnd.oasis.opendocument.formula",
                 "ott": "application/vnd.oasis.opendocument.text-template",
                 "ots": "application/vnd.oasis.opendocument.spreadsheet-template",
                 "otp": "application/vnd.oasis.opendocument.presentation-template",
                 "epub": "application/epub+zip"}
OOXML = {"docx", "docm", "dotx", "xlsx", "xlsm", "xltx", "pptx", "pptm", "potx", "ppsx", "vsdx"}

NAMES = {"jpg": "JPEG photo", "png": "PNG image", "gif": "GIF image", "zip": "ZIP archive", "pdf": "PDF document",
         "wav": "WAV sound", "avi": "AVI video", "webp": "WebP image", "aiff": "AIFF sound", "gz": "gzip file",
         "bz2": "bzip2 file", "xz": "xz file", "mp3": "MP3 sound", "mp4": "MP4 video", "mov": "QuickTime video",
         "docx": "Word document", "xlsx": "Excel workbook", "pptx": "PowerPoint presentation",
         "odt": "OpenDocument text", "ods": "OpenDocument spreadsheet", "odp": "OpenDocument presentation",
         "epub": "EPUB book", "jar": "Java archive", "apk": "Android package", "mkv": "Matroska video",
         "webm": "WebM video", "ts": "MPEG transport stream", "m2ts": "AVCHD / Blu-ray video", "mpg": "MPEG video",
         "vob": "DVD video", "wmv": "Windows Media video", "wma": "Windows Media audio", "asf": "Windows Media file",
         "flv": "Flash video", "heic": "HEIC photo", "heif": "HEIF photo",
         **{t: f"{t.upper()} camera RAW photo" for t in ("cr2", "cr3", "crw", "nef", "nrw", "arw", "sr2", "srf", "orf",
                                                      "rw2", "rwl", "pef", "dng", "srw", "3fr", "erf", "kdc", "dcr",
                                                      "mos", "iiq", "raf", "mef", "mrw", "x3f")}}


@dataclass
class Plan:
    """What is wrong with a file, and how its repaired copy is made: ``build()`` returns the pieces of the
    copy — bytes, or (start, end) ranges of the input — or ``write(out, ctl)`` writes it directly."""
    type: str
    problems: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    repairable: bool = False
    build: Callable[[], list] | None = None
    write: Callable[[BinaryIO, Control], object] | None = None
    note: str = ""                         # limitations, or what would make a repair possible
    info: dict = field(default_factory=dict)

    def problem(self, text: str, action: str | None = None) -> None:
        if text not in self.problems:
            self.problems.append(text)
        if action and action not in self.actions:
            self.actions.append(action)


def _n(count: int) -> str:
    """A byte count in words: "312 bytes", "1.05 MB"."""
    return f"{count} byte{'s' if count != 1 else ''}" if count < 10000 else fmt_bytes(count)


def _be16(b, o: int) -> int:
    return (b[o] << 8) | b[o + 1]


def _ascii4(b: bytes) -> bool:
    return len(b) == 4 and all(32 <= c < 127 for c in b)


def _merge(pieces: list) -> list:
    """Drop empty pieces and join adjacent input ranges."""
    out: list = []
    for p in pieces:
        if isinstance(p, tuple):
            if p[1] <= p[0]:
                continue
            if out and isinstance(out[-1], tuple) and out[-1][1] == p[0]:
                out[-1] = (out[-1][0], p[1])
                continue
        elif not p:
            continue
        out.append(p)
    return out


def _patched(start: int, end: int, patches: dict[int, bytes]) -> list:
    """The input range [START, END) with small replacements PATCHES {offset: bytes} applied."""
    out: list = []
    pos = start
    for off in sorted(patches):
        if off < pos or off >= end:
            continue
        out += [(pos, off), patches[off]]
        pos = off + len(patches[off])
    out.append((pos, end))
    return _merge(out)


# ---------------------------------------------------------------------- type detection
_MAGIC = [
    (b"\xff\xd8\xff", "jpg"), (b"\x89PNG\r\n\x1a\n", "png"), (b"GIF87a", "gif"), (b"GIF89a", "gif"),
    (b"%PDF-", "pdf"), (b"PK\x03\x04", "zip"), (b"\x1f\x8b\x08", "gz"), (b"BZh", "bz2"),
    (b"\xfd7zXZ\x00", "xz"), (b"ID3", "mp3"),
]
_SCAN_MAGIC = re.compile(rb"\xff\xd8\xff[\xc0-\xfe]|\x89PNG\r\n\x1a\n|GIF8[79]a|%PDF-|PK\x03\x04|RIFF....(?:WAVE|AVI |"
                         rb"WEBP)|FORM....AIF[FC]|\x1f\x8b\x08|\xfd7zXZ\x00|ID3[\x02-\x04]", re.S)


def _riff_type(head: bytes) -> str | None:
    if head[:4] == b"RIFF" and len(head) >= 12:
        return {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}.get(head[8:12])
    if head[:4] == b"FORM" and head[8:12] in (b"AIFF", b"AIFC"):
        return "aiff"
    return None


def _mp4_like(head: bytes) -> str | None:
    if head[4:8] == b"ftyp" and head[8:12] in _PHOTO_BRANDS:
        return None
    if len(head) >= 12 and head[4:8] in (b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip"):
        return "mov" if head[4:8] == b"ftyp" and head[8:12] == b"qt  " else "mp4"
    return None


def _zip_subtype(buf, ext: str) -> str:
    """docx, odt, epub, apk... for a ZIP archive: its extension, else what its first members say."""
    if ext in ZIP_TYPES:
        return ext
    head = bytes(buf[:min(len(buf), 256 * KiB)])
    m = re.match(rb"mimetype(application/[\w.+-]+)", head[30:200])
    if m:
        for t, mt in ODF_MIMETYPES.items():
            if mt.encode() == m.group(1):
                return t
    for marker, t in ((b"word/", "docx"), (b"xl/", "xlsx"), (b"ppt/", "pptx"), (b"AndroidManifest.xml", "apk"),
                      (b"META-INF/MANIFEST.MF", "jar")):
        if marker in head:
            return t
    return "zip"


def detect(buf, path: str | Path = "") -> str:
    """The file's type ("jpg", "png", "docx", ...): from its first bytes, else its extension, else a signature
    near the start; "" when unknown."""
    ext = Path(str(path)).suffix.lower().lstrip(".")
    head = bytes(buf[:64])
    for magic, t in _MAGIC:
        if head.startswith(magic):
            return _zip_subtype(buf, ext) if t == "zip" else t
    t = _raw_type(head, ext) or _riff_type(head) or _mp4_like(head) or _video_type(buf, head, ext)
    if t:
        return t
    first = _mp3_frame_at(buf, 0)
    if first and _mp3_frame_at(buf, first):
        return "mp3"
    if ext in EXTENSIONS:
        return EXTENSIONS[ext]
    if ext in ZIP_TYPES:
        return ext
    m = _SCAN_MAGIC.search(buf, 0, min(len(buf), 64 * KiB))
    if m:
        found = m.group(0)
        for magic, t in _MAGIC:
            if found.startswith(magic):
                return _zip_subtype(buf, ext) if t == "zip" else t
        return _riff_type(found) or ""
    return ""


def _raw_type(head: bytes, ext: str) -> str | None:
    """A camera RAW photo or a HEIF/HEIC picture, by its first bytes (a plain TIFF isn't one)."""
    if head[:16] == b"FUJIFILMCCD-RAW ":
        return "raf"
    if head[4:8] == b"ftyp" and head[8:12] == b"crx ":
        return "cr3"
    if head[4:8] == b"ftyp" and head[8:12] in _PHOTO_BRANDS:
        return ext if ext in ("heic", "heif") else "heic"
    if head[:4] in (b"II*\x00", b"MM\x00*", b"IIRO", b"IIRS", b"MMOR", b"IIU\x00"):
        if ext in RAW_TYPES:
            return ext
        if head[8:10] == b"CR":
            return "cr2"
        if head[:4] == b"IIU\x00":
            return "rw2"
        if head[:4] in (b"IIRO", b"IIRS", b"MMOR"):
            return "orf"
    return None


def _video_type(buf, head: bytes, ext: str) -> str | None:
    """Matroska/WebM, Windows Media, Flash video, MPEG program and transport streams, by their content (the
    extension only picks the name: a transport stream named .mpg is still a transport stream)."""
    if head[:4] == b"\x1a\x45\xdf\xa3":
        return "webm" if b"webm" in head[:64] or ext in ("webm", "weba") else "mkv"
    if head[:16] == b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c":
        return {"wma": "wma", "wmv": "wmv"}.get(ext, "asf" if ext in ("asf", "dvr-ms") else "wmv")
    if head[:4] == b"FLV\x01":
        return "flv"
    if head[:4] == b"\x00\x00\x01\xba":
        from .media.mpegps import detect_mpegps
        if detect_mpegps(head):
            return "vob" if ext in ("vob", "vro", "evo") else "mpg"
    if head[:1] == b"\x47" or head[4:5] == b"\x47" or ext in ("ts", "m2ts", "mts", "m2t", "trp", "tp", "tod"):
        from .media.mpegts import detect_mpegts
        if detect_mpegts(bytes(buf[:8192])):
            return "m2ts" if ext in ("m2ts", "mts", "m2t") else "ts"
    return None


def _kind(t: str) -> str:
    if t in ZIP_TYPES:
        return "zip"
    if t in ("wav", "avi", "webp", "aiff"):
        return "riff"
    if t in ("mp4", "mov"):
        return "mp4"
    if t in ("gz", "bz2", "xz"):
        return "compressed"
    if t in ("mkv", "webm"):
        return "mkv"
    if t in ("ts", "m2ts"):
        return "ts"
    if t in ("mpg", "vob"):
        return "ps"
    if t in ("wmv", "wma", "asf"):
        return "asf"
    if t in RAW_TYPES:
        return "raw"
    return t


def _media_handler(module: str, func: str):
    """A handler from recoverall.core.media, imported when it is first used."""
    def handler(buf, path, reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
        import importlib
        fn = getattr(importlib.import_module(f"{__package__}.media.{module}"), func)
        return fn(buf, path, reference=reference, data_offset=data_offset, ctl=ctl)
    return handler


def repairable_name(path: str | Path) -> bool:
    """Whether a file of this name is a kind the repair knows."""
    ext = Path(str(path)).suffix.lower().lstrip(".")
    return ext in EXTENSIONS or ext in ZIP_TYPES


# ---------------------------------------------------------------------- JPEG
_DHT_TABLES = (
    (0x00, (0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0), bytes(range(12))),
    (0x10, (0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7D), bytes.fromhex(
        "01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a"
        "3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a9293"
        "9495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7"
        "e8e9eaf1f2f3f4f5f6f7f8f9fa")),
    (0x01, (0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0), bytes(range(12))),
    (0x11, (0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77), bytes.fromhex(
        "000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a2627"
        "28292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a"
        "92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7"
        "e8e9eaf2f3f4f5f6f7f8f9fa")),
)


def standard_dht() -> bytes:
    """A DHT segment with the four standard Huffman tables of JPEG Annex K.3 (what MJPEG frames leave out)."""
    body = b"".join(bytes([tc_th]) + bytes(bits) + vals for tc_th, bits, vals in _DHT_TABLES)
    return b"\xff\xc4" + struct.pack(">H", len(body) + 2) + body


_JPEG_MARKER = re.compile(rb"\xff+([^\x00\xd0-\xd7\xff])")
_JPEG_SOS = re.compile(rb"\xff\xda\x00[\x08\x0a\x0c\x0e]")
_JPEG_HEADER_MARK = re.compile(rb"\xff[\xc0-\xcf\xdb\xdd\xe0-\xef\xfe]")
_JPEG_SOF_MARK = re.compile(rb"\xff[\xc0-\xc3\xc5-\xc7\xc9-\xcb\xcd-\xcf]")
_JPEG_RST = re.compile(rb"\xff[\xd0-\xd7]")
_JPEG_BAD = re.compile(rb"\xff[^\x00\xd0-\xd7]")
_BETWEEN_SCANS = {0xC4, 0xDA, 0xDB, 0xDD, 0xDC, 0xFE, 0xCC}
_SOF_HUFFMAN = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7}
_SOF_ALL = _SOF_HUFFMAN | {0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


def _sos_ok(buf, at: int, end: int) -> bool:
    if at + 5 > end:
        return False
    ns = buf[at + 4]
    return 1 <= ns <= 4 and _be16(buf, at + 2) == 6 + 2 * ns and at + 8 + 2 * ns <= end


def _jpeg_walk(buf, pos: int, end: int, stop_at: int | None = None) -> tuple[list, str]:
    """Follow the segments from POS (just after SOI, or at a segment) to the first SOS. Returns the segments
    [(marker, start, end)] — the SOS last — and "" or what went wrong. With STOP_AT, the walk must land on
    the SOS at that offset exactly."""
    segs: list[tuple[int, int, int]] = []
    while pos < end and len(segs) < 4000:
        if buf[pos] != 0xFF:
            return segs, f"the header is damaged at byte {pos}"
        while pos + 1 < end and buf[pos + 1] == 0xFF:
            pos += 1
        if pos + 4 > end:
            return segs, "the file ends inside the header"
        if stop_at is not None and pos > stop_at:
            return segs, "missed the image data"
        marker = buf[pos + 1]
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker < 0xC0 or marker in (0xD8, 0xD9):
            return segs, f"the header is damaged at byte {pos}"
        length = _be16(buf, pos + 2)
        if length < 2:
            return segs, f"the header is damaged at byte {pos}"
        if pos + 2 + length > end:
            return segs, "the file ends inside the header"
        if marker == 0xDA:
            if not _sos_ok(buf, pos, end):
                return segs, f"the header is damaged at byte {pos}"
            segs.append((marker, pos, pos + 2 + length))
            if stop_at is not None and pos != stop_at:
                return segs, "missed the image data"
            return segs, ""
        if marker in _SOF_ALL and (length < 8 or not 1 <= buf[pos + 9] <= 4 or length < 8 + 3 * buf[pos + 9]):
            return segs, f"the image size information is damaged (byte {pos})"
        segs.append((marker, pos, pos + 2 + length))
        pos += 2 + length
    return segs, "no image data found"


def _jpeg_scan(buf, pos: int, end: int) -> tuple[int, bool, str]:
    """From the end of an SOS header, find where the image data ends: (end offset, EOI found, why it
    stopped: "" at the EOI, "cut" at the end of the file, "file" where another file starts, "damaged")."""
    for _ in range(100000):
        m = _JPEG_MARKER.search(buf, pos, end)
        if m is None:
            return end, False, "cut"
        marker = m.group(1)[0]
        at = m.end() - 2
        if marker == 0xD9:
            return m.end(), True, ""
        if marker in _BETWEEN_SCANS and at + 4 <= end:      # progressive photos: tables and scans follow
            length = _be16(buf, at + 2)
            if 2 <= length and at + 2 + length <= end and (marker != 0xDA or _sos_ok(buf, at, end)):
                pos = at + 2 + length
                continue
        # another file starts with a start marker; an APPn marker on its own is damage (or random data)
        return at, False, "file" if marker == 0xD8 else "damaged"
    return end, False, "cut"


def _strip_zeros(buf, start: int, end: int, keep: int = 64) -> int:
    """END moved back over a run of zero bytes (padding after a cut) when the run is longer than KEEP."""
    z = end
    while z > start:
        chunk = bytes(buf[max(start, z - 65536):z])
        stripped = chunk.rstrip(b"\x00")
        z -= len(chunk) - len(stripped)
        if stripped:
            break
    return z if end - z > keep else end


def _jpeg_main(buf, end: int, start: int = 0) -> tuple[int, int, int, bool, str] | None:
    """The main image's SOS: (SOS start, SOS end, data end, EOI found, why it stopped) — the SOS whose image
    data runs longest (an EXIF thumbnail's SOS comes first but stops at the thumbnail's EOI); from START
    (past the APPn segments, whose thumbnail isn't the photo)."""
    best = None
    covered = -1
    for i, m in enumerate(_JPEG_SOS.finditer(buf, start, min(end, 32 * MiB))):
        if i > 256:
            break
        at = m.start()
        if at < covered or not _sos_ok(buf, at, end):
            continue
        sos_end = at + 2 + _be16(buf, at + 2)
        data_end, eoi, why = _jpeg_scan(buf, sos_end, end)
        covered = data_end
        if best is None or data_end - sos_end > best[2] - best[1]:
            best = (at, sos_end, data_end, eoi, why)
    return best


def _jpeg_info(buf, segs: list) -> dict:
    info: dict = {"dqt": False, "dht": False, "sof": None, "dri": False}
    for marker, s, _e in segs:
        if marker == 0xDB:
            info["dqt"] = True
        elif marker == 0xC4:
            info["dht"] = True
        elif marker == 0xDD:
            info["dri"] = True
        elif marker in _SOF_ALL:
            info["sof"] = (marker, _be16(buf, s + 7), _be16(buf, s + 5), buf[s + 9])   # type, width, height, comps
    return info


def _jpeg_find_sof(buf, limit: int) -> tuple | None:
    """The last intact-looking frame header (SOF) before LIMIT: (type, width, height, components)."""
    found = None
    for m in _JPEG_SOF_MARK.finditer(buf, max(0, limit - 1 * MiB), limit):
        at = m.start()
        if at + 10 > limit:
            break
        length, nf = _be16(buf, at + 2), buf[at + 9]
        if buf[at + 4] in (8, 12, 16) and 1 <= nf <= 4 and length == 8 + 3 * nf and _be16(buf, at + 7):
            found = (buf[at + 1], _be16(buf, at + 7), _be16(buf, at + 5), nf)
    return found


def _entropy_start(buf, pos: int, end: int, restart: bool) -> int | None:
    """Where JPEG image data seems to start after an overwritten stretch: the first 512-byte boundary from
    which 4 KiB look like entropy-coded data (varied bytes, every 0xFF followed by 0x00 or a restart marker).
    With restart markers the data is taken from just after the next one, where the decoder can pick up."""
    off = -(-pos // 512) * 512
    while off + 4096 <= min(end, pos + 64 * MiB):
        window = bytes(buf[off:off + 4096])
        if _JPEG_BAD.search(window) is None and len(set(window)) > 160:
            if restart:
                m = _JPEG_RST.search(buf, off, min(end, off + 4 * MiB))
                if m:
                    return m.end()
            return off
        off += 512
    return None


def _jpeg_reference(reference) -> tuple[bytes | None, dict, str]:
    """The header (SOI … SOS) of the reference photo (standard tables added if it has none), its details,
    and "" or why it can't be used."""
    try:
        with open(reference, "rb") as f:
            data = f.read(64 * MiB)
    except OSError as exc:
        return None, {}, exc.strerror or str(exc)
    main = _jpeg_main(data, len(data))
    soi = data.find(b"\xff\xd8\xff", 0, 1 * MiB)
    if main is None or soi < 0:
        return None, {}, "it isn't a readable JPEG photo"
    segs, err = _jpeg_walk(data, soi + 2, len(data), stop_at=main[0])
    if err:
        return None, {}, f"its header is damaged too ({err})"
    info = _jpeg_info(data, segs)
    header = data[soi:main[0]]
    if info["sof"] and info["sof"][0] in _SOF_HUFFMAN and not info["dht"]:
        header += standard_dht()
        info["dht"] = True
    return header + data[main[0]:main[1]], info, ""


_JPEG_RST_EOI = re.compile(rb"\xff[\xd0-\xd7\xd9]")
_HIGH_BYTES = bytes(range(128, 256))


def _jpeg_bytes(buf, header: list) -> bytes:
    """The header's pieces (input ranges and bytes) joined."""
    return b"".join(bytes(buf[p[0]:p[1]]) if isinstance(p, tuple) else p for p in header)


def _jpeg_apps_end(buf) -> int:
    """Where the APPn segments (EXIF, its thumbnail inside) that follow the start marker end."""
    pos = 2
    while pos + 4 <= len(buf) and buf[pos] == 0xFF and 0xE0 <= buf[pos + 1] <= 0xEF:
        nxt = pos + 2 + _be16(buf, pos + 2)
        if nxt > len(buf):
            return len(buf)
        pos = nxt
    return pos if pos > 2 else 0


def _jpeg_segment_ok(buf, mk: int, start: int, end: int) -> bool | None:
    """Whether the table or frame segment from START to END is well formed (None: an APPn or comment,
    which can hold anything)."""
    body = bytes(buf[start + 4:end])
    p = 0
    if mk == 0xC4:
        while p < len(body):
            if p + 17 > len(body) or body[p] >> 4 > 1 or body[p] & 15 > 3 or sum(body[p + 1:p + 17]) > 256:
                return False
            p += 17 + sum(body[p + 1:p + 17])
        return p == len(body) > 0
    if mk == 0xDB:
        while p < len(body):
            if body[p] >> 4 > 1 or body[p] & 15 > 3:
                return False
            p += 1 + 64 * (1 + (body[p] >> 4))
        return p == len(body) > 0
    if mk in _SOF_ALL:
        return len(body) >= 6 and body[0] in (8, 12, 16) and 1 <= body[5] <= 4 and len(body) == 6 + 3 * body[5]
    if mk == 0xDD:
        return len(body) == 2
    return None


def _jpeg_resync(buf, soi: int, sos_at: int) -> tuple[list, int] | None:
    """A header with other data between its segments: the whole segments from the start marker at SOI to
    the SOS at SOS_AT, in order, and how many bytes lie between them. None unless that leaves one frame
    header and quantisation tables."""
    segs: list[tuple[int, int, int]] = []
    pos, skipped = soi + 2, 0
    while pos < sos_at and len(segs) < 4000:
        mk = buf[pos + 1] if pos + 1 < sos_at else 0
        if buf[pos] == 0xFF and pos + 4 <= sos_at and (mk in _SOF_ALL or mk in (0xC4, 0xDB, 0xDD, 0xFE) or
                                                     0xE0 <= mk <= 0xEF):
            nxt = pos + 2 + _be16(buf, pos + 2)
            ok = _jpeg_segment_ok(buf, mk, pos, nxt) if pos + 4 <= nxt <= sos_at else False
            if ok is None:                            # an APPn or comment: whole if a marker comes right after it
                ok = nxt == sos_at or (nxt < sos_at - 1 and buf[nxt] == 0xFF and buf[nxt + 1] not in (0, 0xFF))
            if ok:
                segs.append((mk, pos, nxt))
                pos = nxt
                continue
        m = _JPEG_HEADER_MARK.search(buf, pos + 1, sos_at)
        nxt = m.start() if m else sos_at
        if b"\xff\xd8" in bytes(buf[pos:nxt]):
            return None                               # another photo's header (an EXIF thumbnail): not this one's
        skipped += nxt - pos
        pos = nxt
    if not skipped or sum(1 for s in segs if s[0] in _SOF_ALL) != 1 or not any(s[0] == 0xDB for s in segs):
        return None
    return segs + [(0xDA, sos_at, sos_at + 2 + _be16(buf, sos_at + 2))], skipped


def _jpeg_suspect(buf, start: int, end: int, dri: int, progressive: bool, mcus: int) -> bool:
    """Cheap signs that the picture data of a photo that reaches its end marker is damaged inside: restart
    markers out of turn, too many or too few (or in a photo without a restart interval), or a 4 KiB cluster
    of text in it."""
    n = 0
    for m in _JPEG_RST.finditer(buf, start, end):
        if not dri or not progressive and buf[m.start() + 1] != 0xD0 + n % 8:
            return True
        n += 1
    if dri and not progressive and mcus and n != -(-mcus // dri) - 1:
        return True
    for i in range(start + (-start) % 4096, end - 4096, 4096):
        if buf.find(b"\xff", i, i + 4096) < 0:
            blk = bytes(buf[i:i + 4096])
            if len(blk.translate(None, _HIGH_BYTES)) * 8 >= len(blk) * 7:
                return True
    return False


def _jpeg_cut(buf, dec, good_end: int, good_bit: int, start: int, mcus: int, preds) -> list:
    """The picture data from START up to the last good MCU, which ends at bit GOOD_BIT of the byte at GOOD_END,
    then MCUS grey MCUs that carry on the bit stream from there (DC predictors PREDS), so the photo keeps its
    full size and decodes without errors. When its tables can't code grey, that last byte is just padded
    with 1 bits (and a stuffed zero follows it if it becomes 0xFF)."""
    out: list = [(start, good_end)]
    part = (buf[good_end] >> (8 - good_bit), good_bit) if good_bit and good_end < len(buf) else (0, 0)
    grey = dec.grey(max(0, mcus), preds, part)
    if grey is not None:
        return out + [grey]
    if part[1]:
        b = buf[good_end] | ((1 << (8 - good_bit)) - 1)
        out.append(bytes([b]) + (b"\x00" if b == 0xFF else b""))
    return out


def _jpeg_fill(buf, dec, start: int) -> list | None:
    """A baseline photo whose data simply stops: the data up to its last good MCU, then the rest of its MCUs as
    grey and the end marker; None when that can't be coded (progressive photos, tables without the codes)."""
    if not (dec.supported and len(dec.scans) == 1 and not dec.progressive):
        return None
    first = dec.scans[0]
    if not 0 < first.decoded < first.total:
        return None
    part = (buf[dec.good_end] >> (8 - dec.good_bit), dec.good_bit) if dec.good_bit and dec.good_end < len(buf) \
        else (0, 0)
    total, done, ri = first.total, first.decoded, dec.restart_interval
    if not ri or ri >= total:
        grey = dec.grey(total - done, dec.preds, part)
        return None if grey is None else [(start, dec.good_end), grey, b"\xff\xd9"]
    # with restart intervals: finish the interval the data stops in, then every later one after its marker
    # (the DC predictors start again from 0 in each)
    cur = (done - 1) // ri
    good = dec.good_end
    if done % ri == 0 and not dec.good_bit and bytes(buf[good - 2:good]) == bytes((0xFF, 0xD0 + cur % 8)):
        good -= 2                    # the data stops just after that interval's restart marker: it is written below
    pieces: list = [(start, good)]
    rest = min((cur + 1) * ri, total) - done
    tail = dec.grey(rest, dec.preds, part)
    if tail is None:
        return None
    pieces.append(tail)
    for k in range(cur + 1, -(-total // ri)):
        n = min(ri, total - k * ri)
        grey = dec.grey(n)
        if grey is None:
            return None
        pieces += [bytes((0xFF, 0xD0 + (k - 1) % 8)), grey]
    return pieces + [b"\xff\xd9"]


def _jpeg_interval(dec, seg: bytes, j: int):
    """SEG decoded as restart interval J of the photo: (whether all of it decodes and fits exactly, the
    jpegdec Probe)."""
    from .media import jpegdec
    sc = dec.scans[0]
    ri = dec.restart_interval
    want = min(ri, sc.total - j * ri)
    term = b"\xff\xd9" if (j + 1) * ri >= sc.total else bytes((0xFF, 0xD0 + j % 8))
    cp = jpegdec.Checkpoint(0, j * ri, 0, 0, (0,) * len(dec.frame.comps), 0)
    pr = dec.probe(cp, seg + term, want)
    return pr.mcus == want and not pr.error, pr


def _jpeg_true_end(buf, dec, start: int, end: int) -> int:
    """After damage in a photo with restart markers: just after the first end marker from START whose last
    restart interval decodes (the photo's real end), else END."""
    count = -(-dec.scans[0].total // dec.restart_interval)
    last = start
    for i, m in enumerate(_JPEG_RST_EOI.finditer(buf, start, end)):
        if i > 1_000_000:
            break
        if buf[m.start() + 1] != 0xD9:
            last = m.end()
            continue
        if _jpeg_interval(dec, bytes(buf[last:m.start()]), count - 1)[0]:
            return m.end()
        last = m.end()
    return end


def _jpeg_restarts(buf, dec, start: int, stop: int) -> tuple[list, int, int, float] | None:
    """The picture data (START to STOP) of a baseline photo with restart markers, with every restart interval
    that doesn't decode replaced by grey coded with the photo's own tables (the MCUs of a damaged interval
    that decode before the damage are kept), so the rest of the picture shows in its place, and the photo
    keeps its full size: (pieces ending with the end marker, intervals replaced, intervals in all, the share
    of the picture's MCUs kept)."""
    ri = dec.restart_interval
    total = dec.scans[0].total
    count = -(-total // ri)
    grey_mid, grey_last = dec.grey(ri), dec.grey(total - (count - 1) * ri)
    if grey_mid is None or grey_last is None:
        return None
    out: list = []
    state = {"j": 0, "replaced": 0, "kept": 0}
    damaged = 0                                       # bytes of damaged data since the last good interval
    lens: list[int] = []
    partial = None                                    # (start, probe) of the damaged interval that follows a good one

    def size(k: int) -> int:
        return min(ri, total - k * ri)

    def marker(k: int) -> bytes:
        return bytes((0xFF, 0xD0 + k % 8)) if k < count - 1 else b""

    def fill(upto: int) -> None:
        """Grey intervals up to UPTO (the first one keeps the MCUs of PARTIAL that decode)."""
        nonlocal partial
        while state["j"] < min(upto, count):
            k = state["j"]
            if partial is not None and partial[1].mcus:
                s, pr = partial
                out.extend(_jpeg_cut(buf, dec, s + pr.end_bit // 8, pr.end_bit & 7, s, size(k) - pr.mcus,
                                     pr.preds))
                state["kept"] += pr.mcus
            else:
                out.append(grey_last if k == count - 1 else grey_mid)
            out.append(marker(k))
            partial = None
            state["j"] += 1
            state["replaced"] += 1

    pos = start
    segs = []
    for m in _JPEG_RST_EOI.finditer(buf, start, stop):
        segs.append((pos, m.start(), buf[m.start() + 1]))
        pos = m.end()
    if pos < stop:
        segs.append((pos, stop, -1))
    for s, e, mk in segs:
        j = state["j"]
        if j >= count:
            break
        seg = bytes(buf[s:e])
        if mk == 0xD9 and e + 2 >= stop:              # the photo's last interval
            ok, _pr = _jpeg_interval(dec, seg, count - 1)
            if ok:
                fill(count - 1)
                out.append((s, e))
                state["kept"] += size(count - 1)
                state["j"] = count
            break
        if mk == -1:                                  # the data ends: keep what decodes of this interval
            if not damaged:
                partial = (s, _jpeg_interval(dec, seg, min(j, count - 1))[1])
            break
        ok, pr = _jpeg_interval(dec, seg, min(j, count - 2))
        if not ok or mk == 0xD9:
            if not damaged and mk != 0xD9:
                partial = (s, pr)
            damaged += e - s + 2
            continue
        idx = j
        if damaged:                                   # resynchronise on the restart marker's number
            idx = j + (mk - 0xD0 - j) % 8
            if lens:
                est = damaged / (sum(lens) / len(lens))
                idx += 8 * max(0, round((est - (idx - j)) / 8))
        if idx >= count - 1:
            damaged += e - s + 2
            continue
        fill(idx)
        out.append((s, e + 2) if mk == 0xD0 + idx % 8 else (s, e))
        if mk != 0xD0 + idx % 8:
            out.append(marker(idx))
        state["j"] = idx + 1
        state["kept"] += ri
        damaged = 0
        partial = None
        lens.append(e - s)
    fill(count)                                       # what is still missing (a cut-short photo): grey
    return out + [b"\xff\xd9"], state["replaced"], count, state["kept"] / total


def _missing(shown: float) -> str:
    """"the bottom 38 % of the photo is missing" for SHOWN (the share of the picture that decodes)."""
    if shown >= 1:
        return "its picture data is all there"
    pct = min(100, max(1, round(100 * (1 - shown))))
    return f"the bottom {pct} % of the photo is missing" if pct < 100 else "none of the picture is left"


def _jpeg_data(plan: Plan, buf, dec, data_start: int, data_end: int, eoi: bool, why: str, end: int) -> list | None:
    """What to do with picture data that DEC (its decoding) found incomplete: its pieces (ending with the end
    marker) when it is damaged inside or a progressive photo is cut short, or None to keep it as it is
    (simply cut short: plan.info["shown"] says how much of the picture is there)."""
    from .media import jpegdec
    first = dec.scans[0]
    if len(dec.scans) > 1 or dec.progressive:
        done = [s for s in dec.scans if s.complete]
        dc = {c for s in done if s.ss == 0 and s.ah == 0 for c in s.comps}
        if done and len(dc) == len(dec.frame.comps):
            k = len(done)
            cut = dec.error == jpegdec.ERR_CUT and why != "damaged"
            plan.problem(f"The photo is {'cut short' if cut else 'damaged'} in pass {k + 1} of its picture data "
                         "(it was saved progressively, in passes that each sharpen the whole picture)",
                         f"End it after its last complete pass ({k}): the whole picture shows, less sharp")
            plan.info["shown"] = 1.0
            return [(data_start, done[-1].end), b"\xff\xd9"]
    shown = first.decoded / first.total if first.total else 0.0
    plan.info["shown"] = round(shown, 3)
    clean = dec.error == jpegdec.ERR_CUT and why != "damaged" and (dec.error_offset or 0) >= data_end - 1
    if clean:
        return None
    if dec.restart_interval and dec.restart_interval < first.total and len(dec.scans) == 1 and not dec.progressive:
        stop = data_end if eoi else _jpeg_true_end(buf, dec, dec.error_offset or data_end, end)
        got = _jpeg_restarts(buf, dec, data_start, stop)
        if got is not None and got[1] < got[2]:
            pieces, replaced, count, kept = got
            plan.problem(f"The picture data is damaged in {replaced} of its {count} restart intervals (from byte "
                         f"{dec.error_offset} on)",
                         f"Replace the damaged stretch{'es' if replaced != 1 else ''} with grey: the rest of the "
                         "photo shows in its place")
            plan.info["shown"] = round(kept, 3)
            return pieces
    if not first.decoded:
        plan.problem("The picture data doesn't decode from its start: the photo's tables (its header) don't fit "
                     "its data, or the data is damaged right after them")
        return None
    plan.problem(f"The picture data is damaged from byte {dec.error_offset} on: {_missing(shown)}",
                 "Keep the picture up to the damage and fill the rest with grey")
    return _jpeg_cut(buf, dec, dec.good_end, dec.good_bit, data_start, first.total - first.decoded,
                     dec.preds) + [b"\xff\xd9"]


def _jpeg_preview(plan: Plan, buf) -> bool:
    """When the photo itself can't be saved: make its embedded preview (the EXIF thumbnail, a large preview
    of its MP extension) the repaired copy. True if it has one."""
    from .media import rawpreview
    try:
        pv = rawpreview.best_preview(buf)
    except (struct.error, IndexError, ValueError, OverflowError):
        pv = None
    if pv is None or not pv.width:
        return False
    plan.actions.append(f"Save the preview the camera stored inside the photo ({pv.width}×{pv.height}) instead: "
                        "the full-size picture can't be saved")
    plan.info.update(preview=pv.describe(), output="preview")
    pieces = [(pv.offset, pv.end)] + ([] if pv.valid is not False else [b"\xff\xd9"])
    plan.repairable = True
    plan.build = lambda: pieces
    return True


def _jpeg(buf, path, reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    plan = Plan("jpg")
    end = len(buf)
    if end < 4:
        plan.problem("The file is empty or almost empty")
        plan.note = "There is nothing to repair."
        return plan
    soi = 0 if bytes(buf[:3]) == b"\xff\xd8\xff" else buf.find(b"\xff\xd8\xff", 0, min(end, 1 * MiB))
    apps_end = _jpeg_apps_end(buf) if soi == 0 else 0
    main = _jpeg_main(buf, end, apps_end)
    if main is None and soi >= 0 and reference is None:
        _segs, err = _jpeg_walk(buf, soi + 2, end)
        if err in ("the file ends inside the header", "no image data found"):
            plan.problem("The file is cut short before the picture data starts")
            plan.note = "Only the photo's header is left: there is no picture to show."
            if _jpeg_preview(plan, buf):
                plan.note = "Only the photo's header is left, with the small preview the camera stored in it."
            return plan

    # the header: from the start marker straight to the image data, else the intact segments just before it
    header: list | None = None
    segs: list = []
    lead = 0
    from_reference = False
    if main is not None and soi >= 0:
        segs, err = _jpeg_walk(buf, soi + 2, end, stop_at=main[0])
        if not err:
            header = [(soi, main[1])]
            lead = soi
    if main is not None and header is None:
        for i, m in enumerate(_JPEG_HEADER_MARK.finditer(buf, soi + 2 if soi >= 0 else 0, main[0])):
            if i > 5000:
                break
            segs, err = _jpeg_walk(buf, m.start(), end, stop_at=main[0])
            if not err:
                found = _jpeg_info(buf, segs)
                if found["dqt"] and found["sof"]:
                    header = [b"\xff\xd8", (m.start(), main[1])]
                    break
        if header is not None:
            plan.problem("The start of the photo (its header) is damaged or overwritten",
                         "Rebuild the header from the intact tables just before the picture data (the camera "
                         "details are lost)")
        else:
            got = _jpeg_resync(buf, soi, main[0]) if soi >= 0 else None
            if got is not None:                       # other data between the header's segments
                segs, skipped = got
                header = [b"\xff\xd8", *[(s, e) for _m, s, e in segs[:-1]], (main[0], main[1])]
                lead = soi
                plan.problem(f"{_n(skipped)} of other data lie between the parts of the photo's header",
                             f"Cut out the {_n(skipped)} between them")
            else:
                segs = []
    info = _jpeg_info(buf, segs)
    if header is not None:
        if lead > 0:
            plan.problem(f"{_n(lead)} of other data come before the start of the photo",
                         f"Cut the {_n(lead)} before the photo")
        if info["sof"] and info["sof"][0] in _SOF_HUFFMAN and not info["dht"]:
            plan.problem("The photo has no Huffman tables (a video frame from an MJPEG/AVI file)",
                         "Insert the standard Huffman tables (JPEG Annex K)")
            last = header[-1]
            header = header[:-1] + [(last[0], main[0]), standard_dht(), (main[0], main[1])]
        data_start, data_end, eoi, why = main[1], main[2], main[3], main[4]
    else:
        # nothing to rebuild the header from: a reference photo's header has to do
        plan.problem("The start of the photo (its header) is missing or damaged")
        if reference is None:
            plan.note = ("Choose a reference photo taken with the same camera at the same size and quality: its "
                         "header can replace the missing one.")
            plan.info["needs_reference"] = True
            if _jpeg_preview(plan, buf):
                plan.note += " Without one, the repaired copy is the small preview the camera stored in the photo."
            return plan
        ref_header, rinfo, ref_err = _jpeg_reference(reference)
        if ref_header is None:
            plan.note = f"The reference photo can't be used: {ref_err}."
            _jpeg_preview(plan, buf)
            return plan
        ref_name = Path(str(reference)).name
        if main is not None:
            data_start, data_end, eoi, why = main[1], main[2], main[3], main[4]
            own = _jpeg_find_sof(buf, main[0])
            if own and rinfo["sof"] and own[1:3] != rinfo["sof"][1:3]:
                plan.note = (f"The reference photo is {rinfo['sof'][1]}×{rinfo['sof'][2]} but this one seems to be "
                             f"{own[1]}×{own[2]}: the result will probably look wrong.")
            plan.actions.append(f"Use the header of {ref_name} with this photo's picture data")
        else:
            start = data_offset if data_offset is not None else _entropy_start(buf, apps_end, end, rinfo["dri"])
            if start is None or not 0 <= start < end:
                plan.note = "No picture data was found in the file."
                _jpeg_preview(plan, buf)
                return plan
            data_start = start
            data_end, eoi, why = _jpeg_scan(buf, data_start, end)
            plan.actions.append(f"Use the header of {ref_name} with this photo's picture data from byte {data_start} "
                                "on (a guess: if the picture looks scrambled, the data needs another start offset)")
            plan.info["data_offset"] = data_start
        header = [ref_header]
        info = rinfo
        from_reference = True

    # the end of the picture data
    tail_keep = 0
    if eoi:
        trailing = end - data_end
        if trailing > 0:
            nxt = bytes(buf[data_end:data_end + 12])
            if nxt[:3] == b"\xff\xd8\xff" or nxt[4:8] == b"ftyp" or bytes(buf[end - 4:end]) == b"SEFT":
                tail_keep = end      # a camera's second image (MPF), a motion-photo video, a Samsung trailer
            elif trailing <= 1 * MiB and not any(bytes(buf[data_end:end])):
                plan.problem(f"The photo is followed by {_n(trailing)} of zeros", f"Cut the {_n(trailing)} of zeros")
            else:
                plan.problem(f"{_n(trailing)} of other data come after the end of the photo",
                             f"Cut the {_n(trailing)} after the end of the photo")
    else:
        data_end = _strip_zeros(buf, data_start, data_end)

    # the picture data, checked by decoding it when it has no end, could take another header, or looks damaged
    # (not when its start is a guess)
    data: list | None = None
    dec = None
    if "data_offset" not in plan.info:
        from .media import jpegdec
        hdr = _jpeg_bytes(buf, header)
        t = jpegdec.tables_of(hdr)
        frame = t["sof"]
        # the start of the data always (do the tables fit it?), all of it when there is a reason to
        head = jpegdec.decode_check(buf, data_start, min(data_end, data_start + 64 * KiB), header=hdr)
        dec = head if data_end <= data_start + 64 * KiB else None
        if dec is None and (frame is None or head.error not in ("", jpegdec.ERR_CUT) or not eoi or
                            _jpeg_suspect(buf, data_start, data_end, t["dri"], frame.progressive, frame.mcus)):
            dec = jpegdec.decode_check(buf, data_start, data_end, header=hdr)
        if dec is not None and reference is not None and not from_reference and dec.supported and \
                (dec.error == jpegdec.ERR_HEADER or dec.scans and dec.fraction < 0.5 and dec.error != jpegdec.ERR_CUT):
            ref_header, rinfo, _err = _jpeg_reference(reference)
            alt = jpegdec.decode_check(buf, data_start, data_end, header=ref_header) if ref_header else None
            if alt is not None and alt.scans and (alt.ok or alt.fraction > dec.fraction + 0.05 or
                                                  dec.error == jpegdec.ERR_HEADER and alt.error != jpegdec.ERR_HEADER):
                plan.problem("The photo's tables (in its header) are damaged: its picture data doesn't decode "
                             "with them",
                             f"Use the header of {Path(str(reference)).name}, whose tables fit this photo's data")
                header, info, dec = [ref_header], rinfo, alt
        if dec is not None and dec.error == jpegdec.ERR_HEADER:
            plan.problem("The photo's tables (in its header) are damaged")
            plan.note = ("Choose a reference photo taken with the same camera at the same size and quality: its "
                         "tables can replace the damaged ones.")
            plan.info["needs_reference"] = True
            _jpeg_preview(plan, buf)
            return plan
        if dec is not None and dec.supported and dec.scans and not dec.ok and not (
                len(dec.scans) == 1 and not dec.progressive and dec.scans[0].decoded == dec.scans[0].total):
            data = _jpeg_data(plan, buf, dec, data_start, data_end, eoi, why, end)
            if data is None and not dec.scans[0].decoded and not (dec.error == jpegdec.ERR_CUT and why != "damaged"):
                plan.note = ("Choose a reference photo taken with the same camera at the same size and quality: its "
                             "tables may fit this photo's data.")
                plan.info["needs_reference"] = True
                _jpeg_preview(plan, buf)
                return plan
    if data is None and not eoi:
        shown = plan.info.get("shown")
        if shown is not None and shown < 0.01 and _jpeg_preview(plan, buf):
            plan.problem("The photo is cut short right after its header: none of its picture is left")
            plan.note = "The repaired copy is the small preview the camera stored in the photo."
            return plan
        more = f": {_missing(shown)}" if shown is not None else ""
        # the missing part coded as grey with the photo's own tables: a complete photo every viewer opens
        grey = _jpeg_fill(buf, dec, data_start) if dec is not None else None
        filled = " and fill the missing part with grey: the photo keeps its size and opens everywhere"
        if why == "file":
            plan.problem("The photo has no end: another file starts in the middle of it" + more,
                         "End the photo where the other file starts" + (filled if grey else
                                                                         " (the missing part shows grey)"))
        elif why == "damaged":
            plan.problem(f"The picture data is damaged from byte {data_end} on" + more,
                         "Keep the picture data up to the damage" + (filled if grey else
                                                                     " and end the photo there (the rest shows grey)"))
        else:
            plan.problem("The photo is cut short (no end marker)" + more,
                         "Keep the part that is there" + (filled if grey else
                                                          ", add the end marker: the rest shows grey"))
        if grey is not None:
            data = grey
    if data is None:
        data = [(data_start, data_end), b"" if eoi else b"\xff\xd9"]
    pieces = _merge([*header, *data, (data_end, tail_keep) if tail_keep else b""])
    if info.get("sof"):
        plan.info["size"] = f"{info['sof'][1]}×{info['sof'][2]}"
    plan.repairable = True
    plan.build = lambda: pieces
    return plan


# ---------------------------------------------------------------------- PNG
PNG_SIG = b"\x89PNG\r\n\x1a\n"
_PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
_ADAM7 = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2))


def png_chunk(ctype: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF)


def _png_rows(width: int, height: int, depth: int, ctype: int, interlace: int) -> list[tuple[int, int]]:
    """(start, length with the filter byte) of every scanline of the raw image data (all Adam7 passes)."""
    bits = _PNG_CHANNELS.get(ctype, 4) * depth
    rows = []
    pos = 0
    for x0, y0, dx, dy in (_ADAM7 if interlace == 1 else ((0, 0, 1, 1),)):
        pw = (width - x0 + dx - 1) // dx if width > x0 else 0
        ph = (height - y0 + dy - 1) // dy if height > y0 else 0
        if not pw or not ph:
            continue
        stride = 1 + (pw * bits + 7) // 8
        for _ in range(ph):
            rows.append((pos, stride))
            pos += stride
    return rows


def _inflate_prefix(buf, ranges: list[tuple[int, int]], expected: int) -> tuple[bytes, bool]:
    """Decompress the zlib stream spread over RANGES of BUF as far as it goes: (data, complete)."""
    d = zlib.decompressobj()
    out = bytearray()
    for s, e in ranges:
        pos = s
        while pos < e:
            piece = bytes(buf[pos:min(e, pos + 16 * KiB)])
            pos += len(piece)
            try:
                out += d.decompress(piece)
            except zlib.error:
                return bytes(out), False
            if d.eof or len(out) > expected + 64 * MiB:
                return bytes(out), len(out) >= expected
    return bytes(out), d.eof and len(out) >= expected


def _png(buf, path, reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    plan = Plan("png")
    end = len(buf)
    start = 0
    if bytes(buf[:8]) != PNG_SIG:
        found = buf.find(PNG_SIG, 0, min(end, 1 * MiB))
        ihdr = buf.find(b"IHDR", 0, min(end, 1 * MiB))
        if found > 0:
            start = found
            plan.problem(f"{_n(found)} of other data come before the image", f"Cut the {_n(found)} before the image")
        elif ihdr >= 12:
            start = ihdr - 12
            plan.problem("The PNG signature is damaged", "Rewrite the signature")
        else:
            plan.problem("The image header (IHDR) is missing")
            plan.note = "Without its header (size and colour type) the image can't be rebuilt."
            return plan
    pos = start + 8
    chunks: list[tuple[bytes, int, int]] = []       # (type, data start, data end)
    bad_crc: list[str] = []
    iend = None
    stop = ""
    partial_idat = None
    while pos < end and len(chunks) < 1000000:
        if pos + 8 > end:
            stop = "cut"
            break
        length = struct.unpack_from(">I", buf, pos)[0]
        ctype = bytes(buf[pos + 4:pos + 8])
        if not ctype.isalpha() or not ctype.isascii() or length > 0x7FFFFFFF:
            stop = "damaged"
            break
        if pos + 12 + length > end:
            if ctype == b"IDAT":
                partial_idat = (pos + 8, end)
            stop = "cut"
            break
        data_end = pos + 8 + length
        if zlib.crc32(buf[pos + 4:data_end]) & 0xFFFFFFFF != struct.unpack_from(">I", buf, data_end)[0]:
            bad_crc.append(ctype.decode())
        chunks.append((ctype, pos + 8, data_end))
        pos = data_end + 4
        if ctype == b"IEND":
            iend = pos
            break
    if not chunks or chunks[0][0] != b"IHDR" or chunks[0][2] - chunks[0][1] != 13:
        plan.problem("The image header (IHDR) is missing or damaged")
        plan.note = "Without its header (size and colour type) the image can't be rebuilt."
        return plan
    width, height, depth, color, _comp, _filt, interlace = struct.unpack_from(">IIBBBBB", buf, chunks[0][1])
    if not (0 < width < 1 << 24 and 0 < height < 1 << 24 and color in _PNG_CHANNELS and depth in (1, 2, 4, 8, 16)):
        plan.problem("The image header (IHDR) is damaged")
        plan.note = "The image size or colour type in its header is impossible."
        return plan
    plan.info["size"] = f"{width}×{height}"
    if bad_crc:
        names = ", ".join(sorted(set(bad_crc)))
        plan.problem(f"{len(bad_crc)} part{'s' if len(bad_crc) > 1 else ''} of the image "
                     f"{'have' if len(bad_crc) > 1 else 'has'} a wrong checksum ({names})", "Recompute the checksums")
    if iend is None:
        if stop == "damaged":
            plan.problem(f"The file is damaged from byte {pos} on", "Drop the damaged end and close the image")
        else:
            plan.problem("The image is cut short (no IEND)", "Close the image with an IEND chunk")
    elif iend < end:
        plan.problem(f"{_n(end - iend)} of other data come after the end of the image",
                     f"Cut the {_n(end - iend)} after the end of the image")

    idats = [(s, e) for t, s, e in chunks if t == b"IDAT"] + ([partial_idat] if partial_idat else [])
    bad_idat = next((i for i, (s, e) in enumerate(idats) if (s, e) != partial_idat and
                     zlib.crc32(b"IDAT" + bytes(buf[s:e])) & 0xFFFFFFFF != struct.unpack_from(">I", buf, e)[0]), None)
    rows = _png_rows(width, height, depth, color, interlace)
    expected = rows[-1][0] + rows[-1][1] if rows else 0
    rebuild = False
    raw = b""
    if expected > 1024 * MiB:
        plan.note = "The image is too big to check its pixels here; only its structure was checked."
    else:
        raw, complete = _inflate_prefix(buf, idats, expected)
        rebuild = not complete
        if rebuild and bad_idat is not None:
            # stored (incompressible) data decodes even when damaged: trust only what comes before the first
            # IDAT chunk whose checksum is wrong
            raw, _ = _inflate_prefix(buf, idats[:bad_idat], expected)
    kept = 0
    if rebuild:
        good = 0
        for r_start, r_len in rows:
            if r_start + r_len > len(raw) or raw[r_start] > 4:
                break
            good += 1
        kept = rows[good - 1][0] + rows[good - 1][1] if good else 0
        what = (f"{good} of {len(rows)} interlaced scanlines" if interlace else f"the first {good} of {height} rows")
        plan.problem("The image data is missing" if not idats else
                     f"The image data is cut short or damaged: {what} can be read",
                     f"Keep {what} and fill the rest with black (or transparent) pixels")
        plan.info["rows"] = good
        if not good:
            plan.note = "None of the picture data can be read."
            return plan

    def build() -> list:
        out: list = [PNG_SIG]
        placed = False
        for t, s, e in chunks:
            if t == b"IEND":
                continue
            if t == b"IDAT" and rebuild:
                if not placed:
                    out.append(png_chunk(b"IDAT", zlib.compress(raw[:kept] + bytes(expected - kept), 6)))
                    placed = True
                continue
            if zlib.crc32(t + bytes(buf[s:e])) & 0xFFFFFFFF != struct.unpack_from(">I", buf, e)[0]:
                out.append(png_chunk(t, bytes(buf[s:e])))
            else:
                out.append((s - 8, e + 4))
        if rebuild and not placed:
            out.append(png_chunk(b"IDAT", zlib.compress(raw[:kept] + bytes(expected - kept), 6)))
        out.append(png_chunk(b"IEND", b""))
        return _merge(out)

    plan.repairable = True
    plan.build = build
    return plan


# ---------------------------------------------------------------------- GIF
def _gif_subblocks(buf, pos: int, end: int) -> tuple[int, bool]:
    """Skip a chain of sub-blocks: (position after its terminator, True), or (the end of the last complete
    sub-block, False) when the file ends or breaks first."""
    for _ in range(50000000):
        if pos >= end:
            return pos, False
        n = buf[pos]
        if n == 0:
            return pos + 1, True
        if pos + 1 + n > end:
            return pos, False
        pos += 1 + n
    return pos, False


def _gif(buf, path, reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    plan = Plan("gif")
    end = len(buf)
    start = 0
    if bytes(buf[:4]) != b"GIF8":
        m = re.compile(rb"GIF8[79]a").search(buf, 0, min(end, 1 * MiB))
        if not m:
            plan.problem("The GIF header is missing")
            plan.note = "Without its header (size and colours) the image can't be rebuilt."
            return plan
        start = m.start()
        plan.problem(f"{_n(start)} of other data come before the image", f"Cut the {_n(start)} before the image")
    if start + 13 > end:
        plan.problem("The file is cut short inside its header")
        plan.note = "There is no picture left to show."
        return plan
    flags = buf[start + 10]
    pos = start + 13 + ((3 << ((flags & 7) + 1)) if flags & 0x80 else 0)
    frames = 0
    good_end = min(pos, end)
    closing = b""
    trailer = None
    while pos < end:
        b = buf[pos]
        if b == 0x3B:
            trailer = pos + 1
            break
        if b == 0x21 and pos + 2 <= end:
            p, ok = _gif_subblocks(buf, pos + 2, end)
            if not ok:
                break
            pos = good_end = p
            continue
        if b == 0x2C and pos + 10 <= end:
            lflags = buf[pos + 9]
            p = pos + 10 + ((3 << ((lflags & 7) + 1)) if lflags & 0x80 else 0)
            if p + 1 > end:
                break
            p2, ok = _gif_subblocks(buf, p + 1, end)
            frames += 1
            if not ok:
                good_end, closing = p2, b"\x00"      # close the frame after its last complete sub-block
                plan.problem(f"The image is cut short or damaged in frame {frames}",
                             "Close the last frame and add the GIF trailer (its missing part stays empty)")
                break
            pos = good_end = p2
            continue
        break
    if trailer is None:
        if not closing:
            if pos < end:
                plan.problem(f"The file is damaged from byte {pos} on", "Drop the damaged end and add the trailer")
            else:
                plan.problem("The image is cut short (no trailer)", "Add the GIF trailer")
        pieces = _merge([(start, good_end), closing, b"\x3b"])
    else:
        if trailer < end:
            plan.problem(f"{_n(end - trailer)} of other data come after the end of the image",
                         f"Cut the {_n(end - trailer)} after the end")
        pieces = _merge([(start, trailer)])
    plan.info["frames"] = frames
    plan.repairable = frames > 0
    if not frames:
        plan.note = "No picture data is left in the file."
    plan.build = lambda: pieces
    return plan


# ---------------------------------------------------------------------- ZIP family
_LOCAL = struct.Struct("<IHHHHHIIIHH")
_CENTRAL = struct.Struct("<IHHHHHHIIIHHHHHII")
_EOCD = struct.Struct("<IHHHHIIH")
_METHODS = (0, 1, 6, 8, 9, 12, 14, 19, 93, 95, 96, 97, 98, 99)


def _extra_fields(extra: bytes) -> dict[int, bytes]:
    out = {}
    pos = 0
    while pos + 4 <= len(extra):
        hid, hlen = struct.unpack_from("<HH", extra, pos)
        out.setdefault(hid, extra[pos + 4:pos + 4 + hlen])
        pos += 4 + hlen
    return out


def _zip64_values(extra: bytes, usize: int, csize: int, offset: int = 0) -> tuple[int, int, int]:
    """Sizes and offset with the ZIP64 extra field's values for the ones saturated at 0xFFFFFFFF."""
    vals = _extra_fields(extra).get(1, b"")
    i = 0
    if usize == 0xFFFFFFFF and i + 8 <= len(vals):
        usize = struct.unpack_from("<Q", vals, i)[0]
        i += 8
    if csize == 0xFFFFFFFF and i + 8 <= len(vals):
        csize = struct.unpack_from("<Q", vals, i)[0]
        i += 8
    if offset == 0xFFFFFFFF and i + 8 <= len(vals):
        offset = struct.unpack_from("<Q", vals, i)[0]
    return usize, csize, offset


def _decode_name(raw: bytes, flags: int) -> str:
    if flags & 0x800:
        return raw.decode("utf-8", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp437", "replace")


def _zip_central(buf, end: int) -> tuple[list[dict], dict]:
    """The central directory entries, found by their signature (so it works when the end record is gone),
    and the end record: {"eocd": offset or None, "count", "cd_offset", "end"}."""
    state: dict = {"eocd": None}
    eocd = buf.rfind(b"PK\x05\x06", max(0, end - 65557), end)
    if eocd >= 0 and eocd + 22 <= end:
        _sig, _d, _cd, _n, total, cd_size, cd_off, clen = _EOCD.unpack_from(buf, eocd)
        state = {"eocd": eocd, "count": total, "cd_size": cd_size, "cd_offset": cd_off, "end": eocd + 22 + clen}
    entries = []
    if state["eocd"] is not None and bytes(buf[state["cd_offset"]:state["cd_offset"] + 4]) == b"PK\x01\x02":
        pos = state["cd_offset"]
    else:
        pos = max(0, (state["eocd"] or end) - 64 * MiB)      # the directory sits at the end
    for _ in range(5000000):
        p = buf.find(b"PK\x01\x02", pos, end)
        if p < 0 or p + 46 > end:
            break
        f = _CENTRAL.unpack_from(buf, p)
        nlen, elen, clen = f[10], f[11], f[12]
        if p + 46 + nlen + elen + clen > end:
            break
        extra = bytes(buf[p + 46 + nlen:p + 46 + nlen + elen])
        usize, csize, offset = _zip64_values(extra, f[9], f[8], f[16])
        entries.append({"name_raw": bytes(buf[p + 46:p + 46 + nlen]), "flags": f[3], "method": f[4], "crc": f[7],
                        "csize": csize, "usize": usize, "offset": offset, "made": f[1], "eattr": f[15], "at": p})
        pos = p + 46 + nlen + elen + clen
    return entries, state


def _zip_check_data(buf, start: int, csize: int | None, method: int, end: int, ctl: Control) \
        -> tuple[int, int, int, str]:
    """Decompress a member's data from START: (compressed size used, uncompressed size, CRC, "" or what is
    wrong: "damaged", "cut", "unchecked" for a method the standard library can't decode). With CSIZE None
    (a data descriptor follows) deflate and bzip2 find their own end."""
    crc = 0
    if method == 0:
        pos = start
        while pos < start + csize:
            piece = buf[pos:min(start + csize, pos + _CHUNK)]
            crc = zlib.crc32(piece, crc)
            pos += len(piece)
            ctl.check()
        return csize, csize, crc & 0xFFFFFFFF, ""
    if method == 8:
        d = zlib.decompressobj(-15)
    elif method == 12:
        d = bz2.BZ2Decompressor()
    else:
        return csize or 0, 0, 0, "unchecked"
    limit = end if csize is None else min(end, start + csize)
    pos = start
    usize = 0
    n = 0
    try:
        while pos < limit:
            piece = buf[pos:min(limit, pos + 1 * MiB)]
            pos += len(piece)
            data = d.decompress(piece)
            crc = zlib.crc32(data, crc)
            usize += len(data)
            n += 1
            if n % 32 == 0:
                ctl.check()
            if d.eof:
                break
    except (zlib.error, OSError, EOFError, ValueError):
        return pos - start, usize, crc & 0xFFFFFFFF, "damaged"
    if not d.eof:
        return pos - start, usize, crc & 0xFFFFFFFF, "cut"
    return pos - start - len(d.unused_data), usize, crc & 0xFFFFFFFF, ""


def _descriptor_len(buf, pos: int, end: int, zip64: bool) -> int:
    """Length of the data descriptor at POS (with or without its signature), 0 if there is none."""
    body = 20 if zip64 else 12
    if bytes(buf[pos:pos + 4]) == b"PK\x07\x08" and pos + 4 + body <= end:
        return 4 + body
    if pos + body <= end and (pos + body == end or bytes(buf[pos + body:pos + body + 2]) == b"PK"):
        return body
    return 0


def _stored_size(buf, start: int, end: int, zip64: bool) -> int | None:
    """The size of a stored member followed by a data descriptor: where a descriptor gives the distance
    back to START as its compressed size."""
    fmt, body = ("<IQQ", 20) if zip64 else ("<III", 12)
    pos = start
    for _ in range(100000):
        p = buf.find(b"PK\x07\x08", pos, end)
        if p < 0 or p + 4 + body > end:
            break
        _crc, csize, _usize = struct.unpack_from(fmt, buf, p + 4)
        if csize == p - start:
            return csize
        pos = p + 1
    pos = start
    for _ in range(100000):         # descriptors without a signature: just before the next header
        p = buf.find(b"PK\x03\x04", pos, end)
        if p < 0:
            p = buf.find(b"PK\x01\x02", pos, end)
        if p < 0:
            return None
        if p - body >= start and struct.unpack_from(fmt, buf, p - body)[1] == p - body - start:
            return p - body - start
        pos = p + 1
    return None


def _zip_member(buf, off: int, end: int, central: dict, ctl: Control) -> dict:
    """Parse and check the member whose local header is at OFF."""
    _sig, _ver, flags, method, mtime, mdate, crc, csize, usize, nlen, elen = _LOCAL.unpack_from(buf, off)
    m = {"offset": off, "flags": flags, "method": method, "mtime": mtime, "mdate": mdate, "ok": False, "why": ""}
    if nlen == 0 or off + 30 + nlen + elen > end:
        m["why"] = "damaged header"
        return m
    raw = bytes(buf[off + 30:off + 30 + nlen])
    extra = bytes(buf[off + 30 + nlen:off + 30 + nlen + elen])
    m.update(name_raw=raw, name=_decode_name(raw, flags))
    if b"\x00" in raw or method not in _METHODS:
        m["why"] = "damaged header"
        return m
    zip64 = 1 in _extra_fields(extra)
    usize, csize, _ = _zip64_values(extra, usize, csize)
    start = off + 30 + nlen + elen
    cd = central.get(raw)
    descriptor = bool(flags & 8)
    known: int | None = csize
    if descriptor and csize in (0, 0xFFFFFFFF):
        known = None
        if method not in (8, 12):
            known = cd["csize"] if cd else (_stored_size(buf, start, end, zip64) if method == 0 else None)
    if flags & 1:
        # encrypted: can't be checked; kept as it is when its size is known
        if known is None or start + known > end:
            m["why"] = "encrypted, size unknown"
            return m
        dlen = _descriptor_len(buf, start + known, end, zip64) if descriptor else 0
        m.update(ok=True, csize=known, usize=cd["usize"] if cd else usize, crc=cd["crc"] if cd else crc,
                 end=start + known + dlen, verified=False)
        return m
    if known is None and method not in (8, 12):
        m["why"] = "size unknown"
        return m
    if known is not None and start + known > end:
        m["why"] = "cut"
        return m
    used, real_usize, real_crc, why = _zip_check_data(buf, start, known, method, end, ctl)
    if why in ("damaged", "cut"):
        m["why"] = why
        return m
    size = known if known is not None else used
    dlen = _descriptor_len(buf, start + size, end, zip64) if descriptor else 0
    if why == "unchecked":
        m.update(ok=True, csize=size, usize=cd["usize"] if cd else usize, crc=cd["crc"] if cd else crc,
                 end=start + size + dlen, verified=False)
        return m
    want_crc, want_usize = crc, usize
    if descriptor:
        if dlen:
            p = start + size + (4 if dlen in (16, 24) else 0)
            want_crc = struct.unpack_from("<I", buf, p)[0]
            want_usize = struct.unpack_from("<Q" if zip64 else "<I", buf, p + (12 if zip64 else 8))[0]
        elif cd is not None:
            want_crc, want_usize = cd["crc"], cd["usize"]
        else:
            want_crc, want_usize = real_crc, real_usize      # nothing to compare with: the data decoded fine
    if real_crc != want_crc or real_usize != want_usize:
        m["why"] = "wrong checksum"
        return m
    m.update(ok=True, csize=size, usize=real_usize, crc=real_crc, end=start + size + dlen, verified=True,
             data_start=start)
    return m


def _zip_new_member(name: str, data: bytes, offset: int) -> tuple[bytes, dict]:
    raw = name.encode()
    crc = zlib.crc32(data) & 0xFFFFFFFF
    method, payload = 0, data
    if len(data) > 256 and name != "mimetype":
        co = zlib.compressobj(6, zlib.DEFLATED, -15)
        payload = co.compress(data) + co.flush()
        method = 8
    header = _LOCAL.pack(0x04034B50, 20, 0x800, method, 0, 0x21, crc, len(payload), len(data), len(raw), 0)
    return header + raw + payload, {"name_raw": raw, "flags": 0x800, "method": method, "mtime": 0, "mdate": 0x21,
                                    "crc": crc, "csize": len(payload), "usize": len(data), "offset": offset,
                                    "eattr": 0, "made": 20}


def _zip_directory(entries: list[dict], cd_offset: int) -> bytes:
    """A central directory and end record (ZIP64 records when sizes, offsets or the count need them)."""
    parts = []
    for e in entries:
        csize, usize, off = e["csize"], e["usize"], e["offset"]
        z = []
        if usize >= 0xFFFFFFFF:
            z.append(usize)
            usize = 0xFFFFFFFF
        if csize >= 0xFFFFFFFF:
            z.append(csize)
            csize = 0xFFFFFFFF
        if off >= 0xFFFFFFFF:
            z.append(off)
            off = 0xFFFFFFFF
        extra = struct.pack("<HH", 1, 8 * len(z)) + b"".join(struct.pack("<Q", v) for v in z) if z else b""
        parts.append(_CENTRAL.pack(0x02014B50, e.get("made") or 20, 45 if z else 20, e["flags"], e["method"],
                                   e["mtime"], e["mdate"], e["crc"], csize, usize, len(e["name_raw"]), len(extra),
                                   0, 0, 0, e.get("eattr", 0), off) + e["name_raw"] + extra)
    cd = b"".join(parts)
    count = len(entries)
    if count >= 0xFFFF or len(cd) >= 0xFFFFFFFF or cd_offset >= 0xFFFFFFFF:
        z64 = cd_offset + len(cd)
        return cd + struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, count, count, len(cd), cd_offset) + \
            struct.pack("<IIQI", 0x07064B50, 0, z64, 1) + \
            _EOCD.pack(0x06054B50, 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    return cd + _EOCD.pack(0x06054B50, 0, 0, count, count, len(cd), cd_offset, 0)


_CT_DEFAULTS = {"rels": "application/vnd.openxmlformats-package.relationships+xml", "xml": "application/xml",
                "png": "image/png", "jpeg": "image/jpeg", "jpg": "image/jpeg", "gif": "image/gif",
                "emf": "image/x-emf", "wmf": "image/x-wmf", "tif": "image/tiff", "tiff": "image/tiff",
                "svg": "image/svg+xml", "bin": "application/vnd.openxmlformats-officedocument.oleObject",
                "vml": "application/vnd.openxmlformats-officedocument.vmlDrawing", "mp4": "video/mp4",
                "wav": "audio/wav", "mp3": "audio/mpeg",
                "odttf": "application/vnd.openxmlformats-officedocument.obfuscatedFont"}
_OX = "application/vnd.openxmlformats-officedocument."
_CT_PARTS = [
    (r"word/document\.xml", _OX + "wordprocessingml.document.main+xml"),
    (r"word/(styles|settings|webSettings|fontTable|numbering|footnotes|endnotes|comments)\.xml",
     _OX + "wordprocessingml.{0}+xml"),
    (r"word/(header|footer)\d+\.xml", _OX + "wordprocessingml.{0}+xml"),
    (r"xl/workbook\.xml", _OX + "spreadsheetml.sheet.main+xml"),
    (r"xl/worksheets/sheet\d+\.xml", _OX + "spreadsheetml.worksheet+xml"),
    (r"xl/(sharedStrings|styles|calcChain)\.xml", _OX + "spreadsheetml.{0}+xml"),
    (r"xl/tables/table\d+\.xml", _OX + "spreadsheetml.table+xml"),
    (r"(?:xl|word|ppt)/charts/chart\d+\.xml", _OX + "drawingml.chart+xml"),
    (r"xl/drawings/drawing\d+\.xml", _OX + "drawing+xml"),
    (r"ppt/presentation\.xml", _OX + "presentationml.presentation.main+xml"),
    (r"ppt/(?:slides|slideLayouts|slideMasters|notesSlides|notesMasters|handoutMasters)/"
     r"(slide|slideLayout|slideMaster|notesSlide|notesMaster|handoutMaster)\d+\.xml", _OX + "presentationml.{0}+xml"),
    (r"ppt/(presProps|viewProps|tableStyles)\.xml", _OX + "presentationml.{0}+xml"),
    (r".*/theme/theme\d+\.xml", _OX + "theme+xml"),
    (r"docProps/core\.xml", "application/vnd.openxmlformats-package.core-properties+xml"),
    (r"docProps/app\.xml", _OX + "extended-properties+xml"),
    (r"docProps/custom\.xml", _OX + "custom-properties+xml"),
]


def content_types(names) -> bytes:
    """A [Content_Types].xml for an Office document, made from the names of its parts."""
    exts = sorted({n.rsplit(".", 1)[-1].lower() for n in names if "." in n.rsplit("/", 1)[-1]})
    lines = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
             '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">']
    lines += [f'<Default Extension="{ext}" ContentType="{_CT_DEFAULTS[ext]}"/>' for ext in exts if ext in _CT_DEFAULTS]
    for name in sorted(names):
        for rx, ct in _CT_PARTS:
            m = re.fullmatch(rx, name)
            if m:
                lines.append(f'<Override PartName="/{name}" ContentType="{ct.format(*m.groups())}"/>')
                break
    lines.append("</Types>")
    return "".join(lines).encode()


def _zip(buf, path, reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    end = len(buf)
    t = detect(buf, path)
    plan = Plan(t if t in ZIP_TYPES else "zip")
    centrals, state = _zip_central(buf, end)
    by_name: dict[bytes, dict] = {}
    for c in centrals:
        by_name.setdefault(c["name_raw"], c)
    members: list[dict] = []
    damaged: dict[bytes, str] = {}
    pos = 0
    for n in range(10000000):
        p = buf.find(b"PK\x03\x04", pos, end)
        if p < 0 or p + 30 > end:
            break
        if n % 200 == 0:
            ctl.check()
        m = _zip_member(buf, p, end, by_name, ctl)
        if m["ok"]:
            members.append(m)
            pos = m["end"]               # a stored archive inside isn't searched for members
        else:
            if m.get("name_raw") and m["why"] != "damaged header":
                damaged.setdefault(m["name_raw"], m["why"])
            pos = p + 4
    # the same name twice (an update appended, a stored copy): the last good one counts
    last = {m["name_raw"]: i for i, m in enumerate(members)}
    members = [m for i, m in enumerate(members) if last[m["name_raw"]] == i]
    good = {m["name_raw"] for m in members}
    # central entries inside a member's data belong to an archive stored in this one
    spans = sorted((m["offset"], m["end"]) for m in members)
    starts = [s for s, _e in spans]

    def inside(at: int) -> bool:
        i = bisect.bisect_right(starts, at) - 1
        return i >= 0 and spans[i][0] <= at < spans[i][1]

    centrals = [c for c in centrals if not inside(c["at"])]
    lost = [raw for raw in damaged if raw not in good]
    lost += [c["name_raw"] for c in centrals if c["name_raw"] not in good and c["name_raw"] not in damaged]
    lost_names = [_decode_name(raw, 0x800) for raw in dict.fromkeys(lost)]
    plan.info.update(members=len(members), lost=lost_names)
    if not members:
        plan.problem("No readable file was found in the archive")
        plan.note = "Every member is damaged, or the data isn't a ZIP archive."
        return plan
    cd_ok = state["eocd"] is not None and len(centrals) == state.get("count") and \
        {c["name_raw"] for c in centrals} == good and \
        {c["offset"] for c in centrals} == {m["offset"] for m in members}
    if lost_names:
        shown = ", ".join(lost_names[:5]) + (f" and {len(lost_names) - 5} more" if len(lost_names) > 5 else "")
        k = len(lost_names)
        plan.problem(f"{k} file{'s are' if k > 1 else ' is'} damaged or missing: {shown}",
                     f"Leave out the {k} damaged file{'s' if k > 1 else ''}")
    if state["eocd"] is None:
        plan.problem("The archive's table of contents (central directory) is missing: the archive is cut short "
                     "or its end is damaged", "Write a new table of contents")
    elif not cd_ok:
        plan.problem("The archive's table of contents (central directory) is damaged or doesn't match the files",
                     "Write a new table of contents")
    first = min(m["offset"] for m in members)
    if first > 0 and not cd_ok and not lost_names:
        plan.problem(f"{_n(first)} of other data come before the archive", f"Cut the {_n(first)} before it")
    if state["eocd"] is not None and state["end"] < end:
        plan.problem(f"{_n(end - state['end'])} of other data come after the end of the archive",
                     f"Cut the {_n(end - state['end'])} after the end")
    unverified = [m["name"] for m in members if not m.get("verified")]
    if unverified:
        plan.info["unverified"] = unverified
        plan.note = (f"{len(unverified)} file{'s' if len(unverified) > 1 else ''} couldn't be checked (encrypted, or "
                     "compressed with a method RecoverAll can't decode) and "
                     f"{'were' if len(unverified) > 1 else 'was'} kept as found.")
    # parts a document can't open without
    names = {m["name"] for m in members}
    added: list[tuple[str, bytes, bool]] = []
    mt = next((m for m in members if m["name"] == "mimetype"), None)
    if plan.type in ODF_MIMETYPES and mt is None:
        plan.problem("The “mimetype” entry is missing", "Recreate the “mimetype” entry")
        added.append(("mimetype", ODF_MIMETYPES[plan.type].encode(), True))
    elif plan.type in ODF_MIMETYPES and (mt is not members[0] or mt["method"] != 0) and mt.get("data_start"):
        plan.problem("The “mimetype” entry isn't the first one, uncompressed",
                     "Put the “mimetype” entry first, uncompressed")
        data = bytes(buf[mt["data_start"]:mt["data_start"] + mt["csize"]])
        if mt["method"] == 8:
            data = zlib.decompressobj(-15).decompress(data)
        members.remove(mt)
        added.append(("mimetype", data, True))
    if plan.type in OOXML and "[Content_Types].xml" not in names:
        plan.problem("The document's [Content_Types].xml is missing", "Recreate [Content_Types].xml")
        added.append(("[Content_Types].xml", content_types(names), False))
    if not plan.problems:
        return plan
    mimetype_first = plan.type in ODF_MIMETYPES

    def build() -> list:
        out: list = []
        entries: list[dict] = []
        size = 0

        def add_new(name: str, data: bytes) -> None:
            nonlocal size
            piece, entry = _zip_new_member(name, data, size)
            out.append(piece)
            entries.append(entry)
            size += len(piece)

        for name, data, first_ in added:
            if first_:
                add_new(name, data)
        for m in sorted(members, key=lambda m: 0 if mimetype_first and m["name"] == "mimetype" else 1):
            cd = by_name.get(m["name_raw"]) or {}
            entries.append({"name_raw": m["name_raw"], "flags": m["flags"], "method": m["method"], "mtime": m["mtime"],
                            "mdate": m["mdate"], "crc": m["crc"], "csize": m["csize"], "usize": m["usize"],
                            "offset": size, "eattr": cd.get("eattr", 0), "made": cd.get("made", 20)})
            out.append((m["offset"], m["end"]))
            size += m["end"] - m["offset"]
        for name, data, first_ in added:
            if not first_:
                add_new(name, data)
        out.append(_zip_directory(entries, size))
        return out

    plan.repairable = True
    plan.build = build
    return plan


# ---------------------------------------------------------------------- PDF
_PDF_WS = rb"[\x00\t\n\f\r ]"
_PDF_OBJ = re.compile(rb"(?<![0-9])(\d{1,10})" + _PDF_WS + rb"+(\d{1,5})" + _PDF_WS + rb"+obj(?![A-Za-z0-9])")
_PDF_OBJ_TAIL = re.compile(rb"(?<![0-9])(\d{1,10})" + _PDF_WS + rb"+(\d{1,5})" + _PDF_WS + rb"+$")
_PDF_REF = rb"(\d+)\s+(\d+)\s+R"


class _ObjMatch:
    """Where "N G obj" was found (the same fields as a match of _PDF_OBJ)."""
    __slots__ = ("_start", "_end", "num", "gen")

    def __init__(self, start: int, end: int, num: int, gen: int):
        self._start, self._end, self.num, self.gen = start, end, num, gen

    def start(self) -> int:
        return self._start

    def end(self) -> int:
        return self._end


def _pdf_find_obj(buf, pos: int, end: int) -> _ObjMatch | None:
    """The next "N G obj" from POS: found by the keyword (fast on big files full of digits), then the numbers
    before it."""
    p = pos
    while True:
        k = buf.find(b"obj", p, end)
        if k < 0:
            return None
        after = bytes(buf[k + 3:k + 4])
        if not (after.isalnum() or bytes(buf[max(0, k - 3):k]) == b"end"):
            lo = max(0, k - 64)
            m = _PDF_OBJ_TAIL.search(bytes(buf[lo:k]))
            if m and lo + m.start(1) >= pos and (m.start(1) > 0 or lo == 0):
                return _ObjMatch(lo + m.start(1), k + 3, int(m.group(1)), int(m.group(2)))
        p = k + 3
_PDF_HEADER = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"


def _pdf_dict(buf, pos: int, end: int, limit: int = 256 * KiB) -> bytes:
    """The balanced << … >> starting at POS (after whitespace), b"" if there is none."""
    p = pos
    while p < end and buf[p] in b" \t\r\n\x00\x0c":
        p += 1
    if bytes(buf[p:p + 2]) != b"<<":
        return b""
    depth = 0
    instr = 0
    i = p
    stop = min(end, p + limit)
    while i < stop:
        c = buf[i]
        if instr:
            if c == 0x5C:              # a backslash escapes the next character
                i += 2
                continue
            instr += 1 if c == 0x28 else -1 if c == 0x29 else 0
        elif c == 0x28:
            instr = 1
        elif c == 0x3C and i + 1 < stop and buf[i + 1] == 0x3C:
            depth += 1
            i += 2
            continue
        elif c == 0x3E and i + 1 < stop and buf[i + 1] == 0x3E:
            depth -= 1
            i += 2
            if depth == 0:
                return bytes(buf[p:i])
            continue
        i += 1
    return b""


def _pdf_objects(buf, end: int, ctl: Control) -> tuple[dict[int, tuple[int, int, int]], int, int]:
    """Complete objects {number: (offset, generation, end)} — the last definition of each wins —, the end
    of the last complete object, and how many incomplete objects were left out."""
    objs: dict[int, tuple[int, int, int]] = {}
    last_end = 0
    partial = 0
    pos = 0
    for n in range(20000000):
        m = _pdf_find_obj(buf, pos, end)
        if m is None:
            break
        if n % 1000 == 0:
            ctl.check()
        body = m.end()
        en = buf.find(b"endobj", body, end)
        st = buf.find(b"stream", body, en if en >= 0 else end)
        nxt = _pdf_find_obj(buf, body, en if en >= 0 else end)
        if st >= 0 and (nxt is None or st < nxt.start()):
            # skip the stream's data, which can hold anything (even "endobj")
            data = st + 6 + (2 if bytes(buf[st + 6:st + 8]) == b"\r\n" else 1)
            lm = re.search(rb"/Length\s+(\d+)(?!\s+\d+\s+R)", _pdf_dict(buf, body, st))
            es = buf.find(b"endstream", data + int(lm.group(1)), min(end, data + int(lm.group(1)) + 64)) if lm else -1
            if es < 0:
                es = buf.find(b"endstream", data, end)
            if es < 0:
                partial += 1                 # cut inside a stream: nothing complete follows
                break
            en = buf.find(b"endobj", es, end)
            nxt = _pdf_find_obj(buf, es, en if en >= 0 else end)
        if en < 0 or nxt is not None:
            partial += 1                     # no "endobj" before the next object or the end of the file
            if nxt is None:
                break
            pos = nxt.start()
            continue
        objs[m.num] = (m.start(), m.gen, en + 6)
        last_end = max(last_end, en + 6)
        pos = en + 6
    return objs, last_end, partial


def _pdf_trailers(buf, end: int) -> list[bytes]:
    """The trailer dictionaries — classic "trailer" ones and cross-reference stream dictionaries —
    oldest first."""
    found = []
    for m in re.finditer(rb"trailer" + _PDF_WS + rb"*<<", buf):
        d = _pdf_dict(buf, m.end() - 2, end)
        if d:
            found.append((m.start(), d))
    for m in re.finditer(rb"/Type\s*/XRef\b", buf):
        obj = None
        p = max(0, m.start() - 4096)
        while True:
            o = _pdf_find_obj(buf, p, m.start())
            if o is None:
                break
            obj, p = o, o.end()
        d = _pdf_dict(buf, obj.end(), end) if obj is not None else b""
        if d:
            found.append((obj.start(), d))
    return [d for _, d in sorted(found)]


def _png_unfilter(raw: bytes, cols: int) -> bytes:
    """Undo PNG row filters (1 byte per pixel), as used in PDF cross-reference streams."""
    out = bytearray()
    prev = bytearray(cols)
    stride = cols + 1
    for r in range(len(raw) // stride):
        ft = raw[r * stride]
        row = bytearray(raw[r * stride + 1:(r + 1) * stride])
        for i in range(cols):
            a = row[i - 1] if i else 0
            b = prev[i]
            c = prev[i - 1] if i else 0
            if ft == 1:
                row[i] = (row[i] + a) & 0xFF
            elif ft == 2:
                row[i] = (row[i] + b) & 0xFF
            elif ft == 3:
                row[i] = (row[i] + (a + b) // 2) & 0xFF
            elif ft == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                row[i] = (row[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 0xFF
        out += row
        prev = row
    return bytes(out)


def _pdf_xref_stream_check(buf, body: int, d: bytes, end: int) -> tuple[int, int]:
    """Decode a cross-reference stream (FlateDecode, PNG predictors): (entries pointing nowhere, checked)."""
    try:
        w = [int(x) for x in re.search(rb"/W\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s*\]", d).groups()]
        size = int(re.search(rb"/Size\s+(\d+)", d).group(1))
        im = re.search(rb"/Index\s*\[([\d\s]+)\]", d)
        index = [int(x) for x in im.group(1).split()] if im else [0, size]
        length = int(re.search(rb"/Length\s+(\d+)", d).group(1))
        st = buf.find(b"stream", body, end)
        data = st + 6 + (2 if bytes(buf[st + 6:st + 8]) == b"\r\n" else 1)
        raw = bytes(buf[data:data + length])
        if b"/FlateDecode" in d:
            raw = zlib.decompressobj().decompress(raw)
        width = sum(w)
        pm = re.search(rb"/Predictor\s+(\d+)", d)
        if pm and int(pm.group(1)) >= 10:
            cm = re.search(rb"/Columns\s+(\d+)", d)
            raw = _png_unfilter(raw, int(cm.group(1)) if cm else width)
    except (AttributeError, ValueError, zlib.error):
        return 0, 0                          # can't decode it: don't call it wrong
    bad = checked = 0
    pos = 0
    for first, count in zip(index[0::2], index[1::2]):
        for k in range(count):
            if pos + width > len(raw):
                return bad, checked
            fields = []
            for n in w:
                fields.append(int.from_bytes(raw[pos:pos + n], "big") if n else None)
                pos += n
            if (1 if fields[0] is None else fields[0]) == 1 and checked < 200000:
                checked += 1
                om = _PDF_OBJ.match(buf, fields[1]) if fields[1] is not None and fields[1] < end else None
                if om is None or int(om.group(1)) != first + k:
                    bad += 1
    return bad, checked


def _pdf_xref_ok(buf, end: int) -> tuple[bool, str]:
    """Does the last startxref lead to a cross-reference table (or stream) whose offsets point at objects?"""
    sx = buf.rfind(b"startxref", max(0, end - 64 * KiB), end)
    m = re.compile(rb"startxref\s+(\d+)").match(buf, sx) if sx >= 0 else None
    if m is None:
        return False, "The cross-reference table (the index of the document's objects) is missing"
    off = int(m.group(1))
    if off >= end:
        return False, "The pointer to the cross-reference table is damaged"
    if bytes(buf[off:off + 4]) == b"xref":
        pos = off + 4
        checked = bad = 0
        sub = re.compile(rb"\s*(\d+)\s+(\d+)[ \t]*\r?\n?")
        entry = re.compile(rb"(\d{10}) (\d{5}) ([nf])")
        for _ in range(100000):
            sm = sub.match(buf, pos)
            if not sm:
                break
            first, count = int(sm.group(1)), int(sm.group(2))
            pos = sm.end()
            for k in range(min(count, 5000000)):
                em = entry.match(buf, pos)
                if not em:
                    return False, "The cross-reference table is damaged"
                pos += 20
                if em.group(3) == b"n" and checked < 200000:
                    checked += 1
                    o = int(em.group(1))
                    om = _PDF_OBJ.match(buf, o) if o < end else None
                    if om is None or int(om.group(1)) != first + k:
                        bad += 1
        if bad:
            return False, f"The cross-reference table points to the wrong places ({bad} of {checked} objects)"
        return True, ""
    om = _PDF_OBJ.match(buf, off)
    d = _pdf_dict(buf, om.end(), end) if om else b""
    if b"/XRef" not in d:
        return False, "The cross-reference table isn't where the document says"
    bad, checked = _pdf_xref_stream_check(buf, om.end(), d, end)
    if bad:
        return False, f"The cross-reference stream points to the wrong places ({bad} of {checked} objects)"
    return True, ""


def _pdf(buf, path, reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    plan = Plan("pdf")
    end = len(buf)
    header_missing = buf.find(b"%PDF-", 0, min(end, 1024)) < 0
    objs, last_end, partial = _pdf_objects(buf, end, ctl)
    if not objs:
        plan.problem("No PDF objects were found")
        plan.note = "Nothing of the document is left to rebuild."
        return plan
    if header_missing:
        plan.problem("The PDF header is missing (the start of the file is damaged)", "Add a PDF header")
    ok, why = _pdf_xref_ok(buf, end)
    if not ok:
        plan.problem(why, "Rebuild the cross-reference table from the objects")
    if partial:
        plan.problem(f"{partial} object{'s are' if partial > 1 else ' is'} incomplete (the file is cut short or "
                     "damaged)", "Leave out the incomplete objects")
    if ok and buf.rfind(b"%%EOF", max(0, end - 2048), end) < 0:
        plan.problem("The end of the document (%%EOF) is missing", "Write a new end of the document")
    if not plan.problems:
        return plan
    # where the document starts (its catalog), its info dictionary, and what the last trailer carried along
    xrefs = []
    catalogs = []
    infos = []
    objstms = 0
    for num, (off, gen, oend) in objs.items():
        head = bytes(buf[off:min(oend, off + 8192)])
        if re.search(rb"/Type\s*/Catalog\b", head):
            catalogs.append((off, num, gen))
        elif re.search(rb"/Type\s*/XRef\b", head):
            xrefs.append(off)
        elif re.search(rb"/Type\s*/ObjStm\b", head):
            objstms += 1
        elif re.search(rb"/(Producer|Creator|CreationDate)\b", head) and not re.search(rb"/Type\b", head):
            infos.append((off, num, gen))
    root = info = None
    carried: dict[str, bytes] = {}
    for d in _pdf_trailers(buf, end):
        rm = re.search(rb"/Root\s+" + _PDF_REF, d)
        if rm and (int(rm.group(1)) in objs or xrefs):
            root = (int(rm.group(1)), int(rm.group(2)))
        im = re.search(rb"/Info\s+" + _PDF_REF, d)
        if im and int(im.group(1)) in objs:
            info = (int(im.group(1)), int(im.group(2)))
        for key, rx in (("ID", rb"/ID\s*\[[^\]]*\]"), ("Encrypt", rb"/Encrypt\s+" + _PDF_REF)):
            km = re.search(rx, d)
            if km:
                carried[key] = km.group(0)
    if root is None and catalogs:
        _, num, gen = max(catalogs)
        root = (num, gen)
    if root is None:
        plan.problem("The document's catalog (where its pages start) is missing")
        plan.note = "Without its catalog the pages can't be found (it may have been in a damaged object stream)."
        return plan
    if info is None and infos:
        _, num, gen = max(infos)
        info = (num, gen)
    # objects inside object streams have no offset of their own: the old cross-reference stream finds them
    xref_stm = max(xrefs) if xrefs and (objstms or root[0] not in objs) else None
    size_min = 0
    if xref_stm is not None:
        plan.note = ("This document uses compressed object streams (PDF 1.5+): the objects inside them are found "
                     "through the old cross-reference stream, so they are only reachable if that survived.")
        sm = re.search(rb"/Size\s+(\d+)", _pdf_dict(buf, _PDF_OBJ.match(buf, xref_stm).end(), end))
        size_min = int(sm.group(1)) if sm else 0
    plan.info.update(objects=len(objs), root=root[0])
    shift = len(_PDF_HEADER) if header_missing else 0

    def build() -> list:
        nl = b"" if last_end and buf[last_end - 1] in (0x0A, 0x0D) else b"\n"
        xref_at = shift + last_end + len(nl)
        nums = sorted(n for n in objs if n > 0)
        lines = [b"xref\n0 1\n0000000000 65535 f \n"]
        run: list[bytes] = []
        run_start = 0
        for num in nums:
            if run and num != run_start + len(run):
                lines += [b"%d %d\n" % (run_start, len(run)), *run]
                run = []
            if not run:
                run_start = num
            off, gen, _e = objs[num]
            run.append(b"%010d %05d n \n" % (off + shift, gen))
        if run:
            lines += [b"%d %d\n" % (run_start, len(run)), *run]
        trailer = b"trailer\n<< /Size %d /Root %d %d R" % (max(nums[-1] + 1, size_min), root[0], root[1])
        if info:
            trailer += b" /Info %d %d R" % info
        if xref_stm is not None:
            trailer += b" /XRefStm %d" % (xref_stm + shift)
        for value in carried.values():
            trailer += b" " + value
        trailer += b" >>\n"
        return [_PDF_HEADER if shift else b"", (0, last_end), nl, b"".join(lines), trailer,
                b"startxref\n%d\n%%%%EOF\n" % xref_at]

    plan.repairable = True
    plan.build = build
    return plan


# ---------------------------------------------------------------------- RIFF (WAV, AVI, WebP) and AIFF
def _next_chunk_ok(buf, pos: int, end: int, big: bool = False) -> bool:
    """A plausible chunk header at POS (so a zero-sized chunk before it really is empty)."""
    if pos + 8 > end or not _ascii4(bytes(buf[pos:pos + 4])):
        return False
    return pos + 8 + struct.unpack_from(">I" if big else "<I", buf, pos + 4)[0] <= end


def _chunks_end(buf, pos: int, end: int) -> int:
    """The end of the last complete chunk in a run of chunks from POS (an AVI movi list)."""
    good = pos
    for _ in range(50000000):
        if pos + 8 > end:
            break
        size = struct.unpack_from("<I", buf, pos + 4)[0]
        if not _ascii4(bytes(buf[pos:pos + 4])) or pos + 8 + size > end:
            break
        pos += 8 + size + (size & 1)
        good = min(pos, end)
    return good


def _avi_index(buf, movi: int, movi_end: int) -> tuple[bytes, int]:
    """An idx1 chunk for the chunks of the movi list at MOVI, and the number of video frames."""
    base = movi + 8                          # idx1 offsets count from the "movi" fourcc
    pos = movi + 12
    entries = []
    frames = 0
    while pos + 8 <= movi_end and len(entries) < 20000000:
        cid = bytes(buf[pos:pos + 4])
        size = struct.unpack_from("<I", buf, pos + 4)[0]
        if not _ascii4(cid):
            break
        if cid == b"LIST":
            pos += 12                        # "rec " lists: their chunks follow
            continue
        kind = cid[2:4]
        if kind in (b"dc", b"db", b"wb", b"tx", b"pc"):
            entries.append(struct.pack("<4sIII", cid, 0x10 if kind != b"tx" else 0, pos - base, size))
            frames += kind in (b"dc", b"db")
        pos += 8 + size + (size & 1)
    if not entries:
        return b"", 0
    body = b"".join(entries)
    return b"idx1" + struct.pack("<I", len(body)) + body, frames


def _riff(buf, path, reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    end = len(buf)
    head = bytes(buf[:12])
    t = _riff_type(head) or detect(buf, path)
    plan = Plan(t)
    big = t == "aiff"
    form = "FORM" if big else "RIFF"
    if head[:4] != form.encode() or end < 20:
        plan.problem(f"The {form} header is missing" if head[:4] != form.encode() else "The file is cut short in "
                     "its header")
        plan.note = "The start of the file is damaged; it can't be rebuilt."
        return plan
    word = ">I" if big else "<I"
    noun = "video" if t == "avi" else "picture" if t == "webp" else "sound"
    patches: dict[int, bytes] = {}
    # a large (OpenDML) AVI is several RIFF parts in a row ("AVIX" after the first): only the last part
    # can be cut short, the ones before it are left as they are
    base = 0
    if t == "avi":
        p = 8 + struct.unpack_from("<I", buf, 4)[0]
        while p + 12 <= end and bytes(buf[p:p + 4]) == b"RIFF" and bytes(buf[p + 8:p + 12]) == b"AVIX":
            base = p
            p += 8 + struct.unpack_from("<I", buf, p + 4)[0]
    declared = struct.unpack_from(word, buf, base + 4)[0]
    pos = base + 12
    unit = 1
    comm = None
    real_end = pos
    movi = None
    has_idx = fixed = False
    while pos + 8 <= end:
        cid = bytes(buf[pos:pos + 4])
        size = struct.unpack_from(word, buf, pos + 4)[0]
        if not _ascii4(cid):
            break
        if cid == b"fmt " and pos + 22 <= end:
            unit = max(1, struct.unpack_from("<H", buf, pos + 20)[0])          # nBlockAlign
        if cid == b"COMM" and pos + 16 <= end:
            channels, bits = struct.unpack_from(">H", buf, pos + 8)[0], struct.unpack_from(">H", buf, pos + 14)[0]
            unit = max(1, channels * ((bits + 7) // 8))
            comm = pos
        is_movi = cid == b"LIST" and bytes(buf[pos + 8:pos + 12]) == b"movi"
        if (cid in (b"data", b"SSND") or is_movi) and \
                (pos + 8 + size > end or (size in (0, 0xFFFFFFFF) and not _next_chunk_ok(buf, pos + 8, end, big))):
            if is_movi:
                real = _chunks_end(buf, pos + 12, end) - pos - 8
            elif cid == b"SSND":
                real = 8 + max(0, end - pos - 16) // unit * unit
                if comm is not None:
                    patches[comm + 10] = struct.pack(">I", (real - 8) // unit)     # numSampleFrames
            else:
                real = (end - pos - 8) // unit * unit
            what = "an unfinished recording" if size in (0, 0xFFFFFFFF) else "the file is cut short"
            plan.problem(f"The size of the {noun} data is wrong ({what})",
                         f"Set the size of the {noun} data to what is really there")
            patches[pos + 4] = struct.pack(word, real)
            if is_movi:
                movi = (pos, pos + 8 + real)
            real_end = min(end, pos + 8 + real + (real & 1))
            fixed = True
            break                            # what follows is the incomplete last frame or sample
        elif pos + 8 + size > end:
            plan.problem(f"The file is cut short inside its “{cid.decode(errors='replace').strip()}” part",
                         "Drop the incomplete part")
            break
        if is_movi:
            movi = (pos, pos + 8 + size)
        has_idx = has_idx or cid == b"idx1"
        pos += 8 + size + (size & 1)
        real_end = min(pos, end)
    if real_end < end and not fixed:
        plan.problem(f"{_n(end - real_end)} of other data come after the last complete part",
                     f"Cut the {_n(end - real_end)} at the end")
    extra = b""
    if t == "avi" and base == 0 and movi and not has_idx:
        extra, frames = _avi_index(buf, movi[0], movi[1])
        if extra:
            plan.problem("The video's index (idx1) is missing", "Rebuild the index from the frames")
            avih = buf.find(b"avih", 12, min(end, 64 * KiB))
            if 0 < avih and avih + 28 <= end:
                flags = struct.unpack_from("<I", buf, avih + 20)[0]
                patches[avih + 20] = struct.pack("<I", flags | 0x10)          # AVIF_HASINDEX
                patches[avih + 24] = struct.pack("<I", frames)               # dwTotalFrames
    if declared != real_end + len(extra) - base - 8:
        patches[base + 4] = struct.pack(word, real_end + len(extra) - base - 8)
        if not plan.problems:
            plan.problem(f"The size in the {form} header is wrong", f"Correct the {form} size")
    if not plan.problems:
        return plan
    pieces = _patched(0, real_end, patches) + ([extra] if extra else [])
    plan.repairable = real_end > base + 12
    plan.build = lambda: pieces
    return plan


# ---------------------------------------------------------------------- gzip, bzip2, xz
_COMPRESSED_MAGIC = {"gz": b"\x1f\x8b\x08", "bz2": b"BZh", "xz": b"\xfd7zXZ\x00"}


def _decompress(buf, start: int, end: int, t: str, out: BinaryIO | None, ctl: Control, fine_from: int | None = None) \
        -> tuple[int, bool, int | None]:
    """Decompress from START as far as possible (concatenated members/streams too): (bytes of content,
    complete, where the damage was found — None when the data just stops). From FINE_FROM on the data is
    fed byte by byte, so that everything before the damage comes out (a failing call returns nothing)."""
    magic = _COMPRESSED_MAGIC[t]

    def new():
        return zlib.decompressobj(31) if t == "gz" else bz2.BZ2Decompressor() if t == "bz2" else \
            lzma.LZMADecompressor()

    d = new()
    total = 0
    pos = start
    n = 0
    while pos < end:
        step = 64 * KiB if fine_from is None or pos + 64 * KiB < fine_from else (1 if pos >= fine_from else
                                                                               fine_from - pos)
        piece = buf[pos:min(end, pos + step)]
        try:
            data = d.decompress(piece)
        except (zlib.error, OSError, EOFError, lzma.LZMAError):
            return total, False, pos
        total += len(data)
        if out is not None and data:
            out.write(data)
        n += 1
        if n % 64 == 0:
            ctl.check()
        if d.eof:
            pos += len(piece) - len(d.unused_data)
            if bytes(buf[pos:pos + len(magic)]) == magic:
                d = new()
                continue
            return total, True, None
        pos += len(piece)
    return total, False, None


def _compressed(buf, path, reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    end = len(buf)
    t = detect(buf, path)
    plan = Plan(t)
    magic = _COMPRESSED_MAGIC[t]
    start = 0 if bytes(buf[:len(magic)]) == magic else buf.find(magic, 0, min(end, 1 * MiB))
    if start < 0:
        plan.problem(f"The {t} header is missing")
        plan.note = "The start of the file is damaged: nothing can be decompressed."
        return plan
    total, complete, damaged_at = _decompress(buf, start, end, t, None, ctl)
    fine = damaged_at
    if damaged_at is not None:     # again, byte by byte through the damaged piece, to save all that's readable
        total, complete, damaged_at = _decompress(buf, start, end, t, None, ctl, fine_from=fine)
    plan.info.update(readable=total, complete=complete)
    if start > 0:
        plan.problem(f"{_n(start)} of other data come before the compressed data")
    if complete and not plan.problems:
        return plan
    if not complete:
        plan.problem(f"The file is cut short: the first {_n(total)} of its content can be read" if damaged_at is None
                     else f"The file is damaged at byte {damaged_at}: the first {_n(total)} of its content can be read")
    plan.actions.append(f"Save the {'' if complete else 'readable '}{_n(total)} of the content (uncompressed)")
    plan.repairable = total > 0
    if not total:
        plan.note = "Nothing of the content could be read."
    plan.write = lambda out, c: _decompress(buf, start, end, t, out, c, fine_from=fine)
    return plan


# ---------------------------------------------------------------------- MP3
_MP3_V1L1 = (0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448)
_MP3_V1L2 = (0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384)
_MP3_V1L3 = (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320)
_MP3_V2L1 = (0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256)
_MP3_V2L23 = (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160)
_MP3_RATES = {3: (44100, 48000, 32000), 2: (22050, 24000, 16000), 0: (11025, 12000, 8000)}
_MP3_SYNC = re.compile(rb"\xff[\xe0-\xff]")


def _mp3_frame_at(buf, pos: int) -> int:
    """Length of the MPEG audio frame whose header is at POS, 0 if there is no valid header there."""
    if pos < 0 or pos + 4 > len(buf) or buf[pos] != 0xFF or buf[pos + 1] & 0xE0 != 0xE0:
        return 0
    b1, b2 = buf[pos + 1], buf[pos + 2]
    version, layer, bri, sri = (b1 >> 3) & 3, (b1 >> 1) & 3, b2 >> 4, (b2 >> 2) & 3
    if version == 1 or layer == 0 or bri in (0, 15) or sri == 3:
        return 0
    rate = _MP3_RATES[version][sri]
    pad = (b2 >> 1) & 1
    if layer == 3:                                   # Layer I
        kbps = (_MP3_V1L1 if version == 3 else _MP3_V2L1)[bri]
        return (12 * kbps * 1000 // rate + pad) * 4
    if version == 3:
        kbps = (_MP3_V1L2 if layer == 2 else _MP3_V1L3)[bri]
        return 144 * kbps * 1000 // rate + pad
    return (72 if layer == 1 else 144) * _MP3_V2L23[bri] * 1000 // rate + pad


def _mp3_find(buf, pos: int, end: int, need: int = 3) -> int | None:
    """The next offset from POS where NEED frames follow one another (or run to the end of the file)."""
    for _ in range(2000000):
        m = _MP3_SYNC.search(buf, pos, end)
        if m is None:
            return None
        p = m.start()
        for _k in range(need):
            n = _mp3_frame_at(buf, p)
            if not n or p + n > end:
                break
            p += n
            if p == end:
                return m.start()
        else:
            return m.start()
        pos = m.start() + 1
    return None


def _mp3_tags_end(buf, pos: int, end: int) -> int:
    """The end of the APE / Lyrics3 / ID3v1 tags that start at POS."""
    if bytes(buf[pos:pos + 8]) == b"APETAGEX" and pos + 32 <= end:
        pos = min(end, pos + 32 + struct.unpack_from("<I", buf, pos + 12)[0])
    if bytes(buf[pos:pos + 11]) == b"LYRICSBEGIN":
        e = buf.find(b"LYRICS200", pos, min(end, pos + 64 * KiB))
        e = e if e >= 0 else buf.find(b"LYRICSEND", pos, min(end, pos + 64 * KiB))
        if e >= 0:
            pos = e + 9
    if bytes(buf[pos:pos + 3]) == b"TAG" and pos + 128 <= end:
        pos += 128
    return pos


def _mp3(buf, path, reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    plan = Plan("mp3")
    end = len(buf)
    pieces: list = []
    pos = 0
    if bytes(buf[:3]) == b"ID3" and end >= 10:
        size = ((buf[6] & 0x7F) << 21) | ((buf[7] & 0x7F) << 14) | ((buf[8] & 0x7F) << 7) | (buf[9] & 0x7F)
        tag_end = 10 + size + (10 if buf[5] & 0x10 else 0)
        if tag_end <= end:
            pieces.append((0, tag_end))
            pos = tag_end
    first = _mp3_find(buf, pos, end)
    if first is None:
        plan.problem("No MPEG audio frames were found")
        plan.note = "The sound data is missing or damaged everywhere."
        return plan
    if first > pos:
        plan.problem(f"{_n(first - pos)} of other data come before the sound", f"Cut the {_n(first - pos)} before it")
    frames = gaps = gap_bytes = 0
    pos = seg = first
    for n in range(100000000):
        size = _mp3_frame_at(buf, pos)
        if size and pos + size <= end:
            pos += size
            frames += 1
            if n % 50000 == 0:
                ctl.check()
            continue
        pieces.append((seg, pos))
        if pos >= end or bytes(buf[pos:pos + 3]) == b"TAG" or bytes(buf[pos:pos + 8]) == b"APETAGEX" or \
                bytes(buf[pos:pos + 11]) == b"LYRICSBEGIN":
            break
        nxt = _mp3_find(buf, pos + 1, end)
        if nxt is None:
            break
        gaps += 1                            # a damaged stretch with more sound after it
        gap_bytes += nxt - pos
        pos = seg = nxt
    stop = pos
    tags = _mp3_tags_end(buf, stop, end)
    pieces.append((stop, tags))
    v1 = tags == stop and end - 128 > stop and bytes(buf[end - 128:end - 125]) == b"TAG"
    if v1:
        pieces.append((end - 128, end))      # the ID3v1 tag at the very end, behind other data
    if gaps:
        plan.problem(f"{gaps} damaged stretch{'es' if gaps > 1 else ''} in the sound ({_n(gap_bytes)})",
                     "Drop the damaged stretches (the sound skips there)")
    leftover = (end - 128 if v1 else end) - tags
    if leftover > 0:
        if tags == stop and _mp3_frame_at(buf, stop) and leftover < 2881:
            plan.problem("The file is cut short in its last frame", "Drop the incomplete last frame")
        else:
            plan.problem(f"{_n(leftover)} of other data come after the sound", f"Cut the {_n(leftover)} after it")
    plan.info["frames"] = frames
    if not plan.problems:
        return plan
    final = _merge(pieces)
    plan.repairable = frames > 0
    plan.build = lambda: final
    return plan


# ---------------------------------------------------------------------- MP4 / QuickTime
def _mp4(buf, path, reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    # MP4, MOV, 3GP, M4V: media/mp4repair.py (cut-short files, fragments, and rebuilding a missing index)
    from .media import mp4repair
    return mp4repair.plan(buf, path, reference=reference, data_offset=data_offset, ctl=ctl)


# ---------------------------------------------------------------------- the API
_HANDLERS = {"jpg": _jpeg, "png": _png, "gif": _gif, "zip": _zip, "pdf": _pdf, "riff": _riff,
             "compressed": _compressed, "mp3": _mp3, "mp4": _mp4,
             **{kind: _media_handler(mod, fn) for kind, (mod, fn) in MEDIA_HANDLERS.items()}}
SUPPORTED_TYPES = sorted({"jpg", "png", "gif", "pdf", "wav", "avi", "webp", "aiff", "gz", "bz2", "xz", "mp3",
                          "mp4", "mov", "mkv", "webm", "ts", "m2ts", "mpg", "vob", "wmv", "wma", "asf", "flv"}
                         | ZIP_TYPES | RAW_TYPES)


@contextlib.contextmanager
def _mapped(path: str | Path):
    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if size == 0:
            yield b""
            return
        m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            yield m
        finally:
            m.close()


def _plan(buf, path, reference=None, data_offset=None, ctl: Control = NULL_CONTROL) -> Plan:
    t = detect(buf, path)
    handler = _HANDLERS.get(_kind(t))
    if handler is None:
        plan = Plan(t or "unknown")
        plan.problem("RecoverAll can't check this kind of file" if len(buf) else "The file is empty")
        plan.note = "Files RecoverAll can repair: " + ", ".join(SUPPORTED_TYPES) + "."
        plan.info["unsupported"] = True
        return plan
    try:
        return handler(buf, path, reference=reference, data_offset=data_offset, ctl=ctl)
    except (struct.error, IndexError, ValueError, OverflowError, MemoryError) as exc:
        # damaged in a way the checks above didn't foresee: say so instead of failing
        plan = Plan(t)
        plan.problem(f"The file's structure is damaged in an unexpected way ({type(exc).__name__})")
        plan.note = "RecoverAll can't repair it."
        return plan


def analyze(path: str | Path, reference: str | Path | None = None) -> dict:
    """What is wrong with the file at PATH: {"type", "name", "problems" (plain sentences; [] when it is fine),
    "repairable", "actions" (what repair() would do), "note" (limitations, or what would help), "size",
    "supported", "info"}. With a REFERENCE, what a repair with it would do."""
    with _mapped(path) as buf:
        kind = detect(buf, path)
        plan = _plan(buf, path, reference if reference and _kind(kind) in REFERENCE_KINDS else None)
        size = len(buf)
    repairable = plan.repairable and bool(plan.problems)
    return {"type": plan.type, "name": NAMES.get(plan.type, plan.type.upper()), "problems": plan.problems,
            "repairable": repairable, "actions": plan.actions if repairable else [], "note": plan.note,
            "size": size, "supported": not plan.info.get("unsupported"), "info": plan.info}


def repair(path: str | Path, out_path: str | Path, reference: str | Path | None = None,
           ctl: Control = NULL_CONTROL, data_offset: int | None = None) -> dict:
    """Write a repaired copy of PATH to OUT_PATH; PATH itself is never changed. REFERENCE is an intact file of
    the same kind (for JPEG: a photo from the same camera at the same size, whose header replaces a missing
    one); DATA_OFFSET overrides where a header-less photo's picture data is guessed to start.

    Returns {"ok", "type", "actions_done", "message", "out", "problems"}; "out" is None when nothing was
    written (the file is fine, or it can't be repaired)."""
    path, out_path = Path(path), Path(out_path)
    if os.path.realpath(path) == os.path.realpath(out_path) or \
            (out_path.exists() and os.path.samefile(path, out_path)):
        raise UnsafeOperation("The repaired copy can't replace the damaged file: choose another name or folder")
    tmp = out_path.with_name(f".{out_path.name}.part")
    try:
        with _mapped(path) as buf:
            plan = _plan(buf, path, reference, data_offset, ctl)
            if plan.info.get("output") == "preview" and "(repaired)" in out_path.name:
                # the copy is the picture's preview, not the file: "IMG_1234 (preview).jpg" instead of the
                # usual name (a name the caller chose is kept)
                out_path = _free_name(out_path.with_name(preview_name(path, plan.info.get("output_ext") or "jpg")))
            tmp = out_path.with_name(f".{out_path.name}.part")
            result = {"ok": False, "type": plan.type, "actions_done": [], "out": None, "problems": plan.problems,
                      "info": plan.info}
            if not plan.problems:
                result.update(ok=True, message="No problems found: the file is fine as it is.")
                return result
            if not plan.repairable or (plan.build is None and plan.write is None):
                result["message"] = plan.note or "RecoverAll can't repair this file."
                return result
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp, "wb") as out:
                if plan.write is not None:
                    plan.write(out, ctl)
                else:
                    _write_pieces(buf, plan.build(), out, ctl)
            os.replace(tmp, out_path)
    except OSError as exc:
        return {"ok": False, "type": "", "actions_done": [], "out": None, "problems": [],
                "message": f"Can't repair {path.name}: {exc.strerror or exc}"}
    finally:
        with contextlib.suppress(OSError):
            tmp.unlink()
    give_to_caller(out_path)
    done = list(plan.actions)
    message = ("Repaired: " + "; ".join(a[:1].lower() + a[1:] for a in done) + ".") if done else "Repaired."
    if plan.note:
        message += " " + plan.note
    result.update(ok=True, actions_done=done, message=message, out=str(out_path))
    return result


def _write_pieces(buf, pieces: list, out: BinaryIO, ctl: Control) -> None:
    total = sum(p[1] - p[0] if isinstance(p, tuple) else len(p) for p in pieces) or 1
    done = 0
    for p in pieces:
        if isinstance(p, tuple):
            a, b = p
            while a < b:
                n = min(b - a, _CHUNK)
                out.write(buf[a:a + n])
                a += n
                done += n
                ctl.check()
                if total > 8 * _CHUNK:
                    ctl.progress(done / total, "Writing the repaired copy")
        elif p:
            out.write(p)
            done += len(p)


def preview_name(path: str | Path, ext: str = "jpg") -> str:
    """The name of a photo's saved preview: "IMG_1234.CR2" → "IMG_1234 (preview).jpg"."""
    stem = Path(path).stem or Path(path).name
    return safe_filename(f"{stem} (preview).{ext}")


def _free_name(p: Path) -> Path:
    """P, or "name 2.ext", "name 3.ext"... when P exists."""
    k = 2
    out = p
    while out.exists():
        out = p.with_name(f"{p.stem} {k}{p.suffix}")
        k += 1
    return out


def output_name(path: str | Path, kind: str | None = None) -> str:
    """The repaired copy's name: "IMG_0001 (repaired).jpg"; for a compressed file, its content:
    "notes.txt.gz" → "notes (recovered).txt", "backup.tgz" → "backup (recovered).tar"."""
    name = Path(path).name
    tag = "repaired"
    if kind in ("gz", "bz2", "xz"):
        tag = "recovered"
        low = name.lower()
        for suffix, inner in ((".tgz", ".tar"), (".tbz2", ".tar"), (".tbz", ".tar"), (".txz", ".tar"),
                              (".gz", ""), (".bz2", ""), (".xz", "")):
            if low.endswith(suffix) and len(name) > len(suffix):
                name = name[:-len(suffix)] + inner
                break
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem or len(ext) > 8 or " " in ext:
        return safe_filename(f"{name} ({tag})")
    return safe_filename(f"{stem} ({tag}).{ext}")


def repair_many(paths: list[str | Path], out_dir: str | Path, reference: str | Path | None = None,
                ctl: Control = NULL_CONTROL) -> list[dict]:
    """Repair every file of PATHS into OUT_DIR ("<name> (repaired).<ext>"; a compressed file's readable
    content as "<name> (recovered).<ext>"). Returns one report per file: repair()'s result plus "path"."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    used: set[str] = set()
    for i, p in enumerate(paths):
        ctl.check()
        ctl.progress(i / max(1, len(paths)), f"Repairing {Path(p).name}")
        try:
            with _mapped(p) as buf:
                kind = detect(buf, p)
        except OSError as exc:
            results.append({"path": str(p), "ok": False, "type": "", "actions_done": [], "out": None,
                            "message": f"Can't read {Path(p).name}: {exc.strerror or exc}"})
            continue
        name = output_name(p, kind)
        target = out_dir / name
        k = 2
        while target.name in used or target.exists():
            stem, dot, ext = name.rpartition(".")
            target = out_dir / (f"{stem} {k}.{ext}" if dot and stem else f"{name} {k}")
            k += 1
        used.add(target.name)
        try:
            r = repair(p, target, reference if _kind(kind) in REFERENCE_KINDS else None, ctl)
        except Cancelled:
            raise
        except RallError as exc:
            r = {"ok": False, "type": kind, "actions_done": [], "out": None, "message": str(exc)}
        r["path"] = str(p)
        (ctl.log if r["ok"] else ctl.warn)(f"{Path(p).name}: {r['message']}")
        results.append(r)
    done = sum(1 for r in results if r["ok"] and r["out"])
    ctl.progress(1.0, f"{done} of {len(paths)} file{'s' if len(paths) != 1 else ''} repaired")
    return results
