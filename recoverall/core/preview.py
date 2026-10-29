"""Previews of found files, before recovering them: pictures, text, the text of office documents, archive
listings, and a hex view — plus a check that the content still looks like what the name says (a deleted
JPEG that doesn't start like a JPEG any more was overwritten).

Everything here returns plain JSON (bytes as base64): the helper serves it to the app.
"""

from __future__ import annotations

import base64
import io
import re
import struct
import zipfile
import zlib

from .blockio import Source
from .fs.base import read_head
from .videopreview import VIDEO_EXTS

IMAGE_LIMIT = 12 * 1024 * 1024        # whole pictures up to this size are sent for the preview
TEXT_LIMIT = 64 * 1024
THUMB_LIMIT = 2 * 1024 * 1024

# extension → (offset, magic) the content must start with
MAGIC = {
    "jpg": [(0, b"\xff\xd8\xff")], "jpeg": [(0, b"\xff\xd8\xff")], "png": [(0, b"\x89PNG\r\n\x1a\n")],
    "gif": [(0, b"GIF87a"), (0, b"GIF89a")], "bmp": [(0, b"BM")], "webp": [(8, b"WEBP")],
    "tif": [(0, b"II*\0"), (0, b"MM\0*")], "tiff": [(0, b"II*\0"), (0, b"MM\0*")],
    "cr2": [(0, b"II*\0")], "nef": [(0, b"II*\0"), (0, b"MM\0*")], "arw": [(0, b"II*\0")],
    "dng": [(0, b"II*\0"), (0, b"MM\0*")], "orf": [(0, b"IIRO"), (0, b"IIRS"), (0, b"MMOR")], "rw2": [(0, b"IIU\0")],
    "heic": [(4, b"ftyp")], "heif": [(4, b"ftyp")], "avif": [(4, b"ftyp")], "cr3": [(4, b"ftyp")],
    "mp4": [(4, b"ftyp")], "m4v": [(4, b"ftyp")], "mov": [(4, b"ftyp"), (4, b"moov"), (4, b"mdat"), (4, b"wide"),
                                                          (4, b"free")],
    "3gp": [(4, b"ftyp")], "m4a": [(4, b"ftyp")], "avi": [(8, b"AVI ")], "wav": [(8, b"WAVE")],
    "mkv": [(0, b"\x1a\x45\xdf\xa3")], "webm": [(0, b"\x1a\x45\xdf\xa3")], "flac": [(0, b"fLaC")],
    "ogg": [(0, b"OggS")], "opus": [(0, b"OggS")], "mp3": [(0, b"ID3"), (0, b"\xff\xfb"), (0, b"\xff\xf3"),
                                                          (0, b"\xff\xf2"), (0, b"\xff\xfa")],
    "pdf": [(0, b"%PDF")], "zip": [(0, b"PK\x03\x04"), (0, b"PK\x05\x06")],
    "docx": [(0, b"PK\x03\x04")], "xlsx": [(0, b"PK\x03\x04")], "pptx": [(0, b"PK\x03\x04")],
    "odt": [(0, b"PK\x03\x04")], "ods": [(0, b"PK\x03\x04")], "odp": [(0, b"PK\x03\x04")],
    "epub": [(0, b"PK\x03\x04")], "jar": [(0, b"PK\x03\x04")], "apk": [(0, b"PK\x03\x04")],
    "doc": [(0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")], "xls": [(0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")],
    "ppt": [(0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")], "msg": [(0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")],
    "rar": [(0, b"Rar!\x1a\x07")], "7z": [(0, b"7z\xbc\xaf\x27\x1c")], "gz": [(0, b"\x1f\x8b")],
    "bz2": [(0, b"BZh")], "xz": [(0, b"\xfd7zXZ\0")], "zst": [(0, b"\x28\xb5\x2f\xfd")],
    "psd": [(0, b"8BPS")], "sqlite": [(0, b"SQLite format 3\0")], "exe": [(0, b"MZ")], "dll": [(0, b"MZ")],
    "rtf": [(0, b"{\\rtf")], "pst": [(0, b"!BDN")], "kdbx": [(0, b"\x03\xd9\xa2\x9a")],
}

TEXT_EXTS = set("txt text md csv tsv json xml html htm xhtml log ini cfg conf yaml yml py c h cpp hpp js ts css sh "
                "bash java kt rs go rb php pl sql tex srt sub vtt eml mbox ics vcf svg reg bat ps1 toml".split())


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def check_magic(ext: str, head: bytes) -> bool | None:
    """True if HEAD starts like a .EXT file, False if it doesn't, None when we can't tell."""
    rules = MAGIC.get(ext)
    if not rules:
        return None
    if not head.strip(b"\0"):
        return False
    return any(head[o:o + len(m)] == m for o, m in rules)


def looks_like_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:8192]
    if b"\0" in sample.rstrip(b"\0")[:4096]:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError as exc:
        if exc.start > len(sample) - 4:
            return True
    bad = sum(1 for b in sample if b < 9 or 13 < b < 32)
    return bad < len(sample) * 0.02


def decode_text(data: bytes) -> str:
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", "replace") if data.count(b"\xc3") > 2 else data.decode("cp1252", "replace")


# ---------------------------------------------------------------------- pictures
def _tiff_ifd(t: bytes, off: int, le: bool) -> dict[int, tuple]:
    """Tags of one TIFF IFD: tag → (type, count, value_or_offset)."""
    e = "<" if le else ">"
    out = {}
    if off <= 0 or off + 2 > len(t):
        return out
    n = struct.unpack_from(e + "H", t, off)[0]
    for i in range(min(n, 400)):
        p = off + 2 + i * 12
        if p + 12 > len(t):
            break
        tag, typ, cnt = struct.unpack_from(e + "HHI", t, p)
        val = struct.unpack_from(e + "I", t, p + 8)[0]
        if typ == 3 and cnt == 1:
            val = struct.unpack_from(e + "H", t, p + 8)[0]
        out[tag] = (typ, cnt, val, p + 8)
    return out


def _tiff_next(t: bytes, off: int, le: bool) -> int:
    e = "<" if le else ">"
    if off + 2 > len(t):
        return 0
    n = struct.unpack_from(e + "H", t, off)[0]
    p = off + 2 + n * 12
    return struct.unpack_from(e + "I", t, p)[0] if p + 4 <= len(t) else 0


def exif(tiff: bytes) -> dict:
    """Camera, date, size and the embedded JPEG thumbnail of a TIFF/EXIF block."""
    out: dict = {}
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return out
    le = tiff[:2] == b"II"
    e = "<" if le else ">"
    first = struct.unpack_from(e + "I", tiff, 4)[0]

    def text(tag_entry) -> str:
        typ, cnt, val, p = tag_entry
        if typ != 2:
            return ""
        raw = tiff[p:p + cnt] if cnt <= 4 else tiff[val:val + cnt]
        return raw.split(b"\0")[0].decode("latin-1", "replace").strip()

    ifd0 = _tiff_ifd(tiff, first, le)
    if 0x010F in ifd0:
        out["make"] = text(ifd0[0x010F])
    if 0x0110 in ifd0:
        out["model"] = text(ifd0[0x0110])
    if 0x0132 in ifd0:
        out["date"] = text(ifd0[0x0132])
    if 0x8769 in ifd0:
        sub = _tiff_ifd(tiff, ifd0[0x8769][2], le)
        if 0x9003 in sub:
            out["date"] = text(sub[0x9003])
        if 0xA002 in sub and 0xA003 in sub:
            out["width"], out["height"] = sub[0xA002][2], sub[0xA003][2]
    # thumbnails / previews: IFD1 (JPEG thumbnail) and RAW previews in IFD0/sub-IFDs
    candidates = []
    nxt = _tiff_next(tiff, first, le)
    for ifd in (ifd0, _tiff_ifd(tiff, nxt, le) if nxt else {}):
        if 0x0201 in ifd and 0x0202 in ifd:
            candidates.append((ifd[0x0201][2], ifd[0x0202][2]))
        if ifd.get(0x0103, (0, 0, 0))[2] in (6, 7) and 0x0111 in ifd and 0x0117 in ifd \
                and ifd[0x0111][1] == 1:
            candidates.append((ifd[0x0111][2], ifd[0x0117][2]))
    if 0x014A in ifd0:                       # SubIFDs (DNG, NEF previews)
        typ, cnt, val, p = ifd0[0x014A]
        offs = [val] if cnt == 1 else [struct.unpack_from(e + "I", tiff, val + 4 * i)[0]
                                        for i in range(min(cnt, 8)) if val + 4 * i + 4 <= len(tiff)]
        for o in offs:
            s = _tiff_ifd(tiff, o, le)
            if 0x0201 in s and 0x0202 in s:
                candidates.append((s[0x0201][2], s[0x0202][2]))
    best = None
    for off, n in candidates:
        if 0 < off < len(tiff) and 0 < n and tiff[off:off + 2] == b"\xff\xd8":
            if best is None or n > best[1]:
                best = (off, n)
    if best:
        out["thumb"] = (best[0], best[1])
    return out


def jpeg_exif(data: bytes) -> tuple[dict, bytes]:
    """EXIF details of a JPEG (and the TIFF block they came from)."""
    pos = 2
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker in (0xD9, 0xDA):
            break
        seg = struct.unpack_from(">H", data, pos + 2)[0]
        if marker == 0xE1 and data[pos + 4:pos + 10] == b"Exif\0\0":
            tiff = data[pos + 10:pos + 2 + seg]
            return exif(tiff), tiff
        if marker in (0xC0, 0xC1, 0xC2) and pos + 9 <= len(data):
            h, w = struct.unpack_from(">HH", data, pos + 5)
            return {"width": w, "height": h}, b""
        pos += 2 + seg
    return {}, b""


def image_size(data: bytes) -> tuple[int, int] | None:
    if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
        return struct.unpack_from(">II", data, 16)
    if data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
        return struct.unpack_from("<HH", data, 6)
    if data[:2] == b"BM" and len(data) >= 26:
        w, h = struct.unpack_from("<ii", data, 18)
        return abs(w), abs(h)
    if data[:2] == b"\xff\xd8":
        pos = 2
        while pos + 9 <= len(data) and data[pos] == 0xFF:
            marker = data[pos + 1]
            seg = struct.unpack_from(">H", data, pos + 2)[0]
            if marker in (0xC0, 0xC1, 0xC2, 0xC3):
                h, w = struct.unpack_from(">HH", data, pos + 5)
                return w, h
            if marker in (0xD9, 0xDA):
                break
            pos += 2 + seg
    return None


# ---------------------------------------------------------------------- documents
def office_text(data: bytes, limit: int = TEXT_LIMIT) -> tuple[str, dict]:
    """The plain text of a .docx/.xlsx/.pptx/.odt/.ods/.odp/.epub, and the archive's member list."""
    info: dict = {}
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
    except (zipfile.BadZipFile, ValueError, OSError):
        return "", info
    info["members"] = len(names)
    parts = []
    if "word/document.xml" in names:
        parts = ["word/document.xml"]
    elif any(n.startswith("xl/sharedStrings.xml") for n in names):
        parts = ["xl/sharedStrings.xml"]
    elif any(n.startswith("ppt/slides/slide") for n in names):
        parts = sorted((n for n in names if re.match(r"ppt/slides/slide\d+\.xml$", n)),
                       key=lambda n: int(re.findall(r"\d+", n)[-1]))
    elif "content.xml" in names:
        parts = ["content.xml"]
    else:
        parts = [n for n in names if n.endswith((".xhtml", ".html"))][:20]
    out = []
    size = 0
    for n in parts:
        try:
            xml = z.read(n)
        except (zipfile.BadZipFile, KeyError, zlib.error, OSError, RuntimeError):
            info["damaged"] = True
            continue
        text = re.sub(rb"<(w:p|text:p|a:p|p|br|tr|si)[ />]", b"\n<", xml)
        text = re.sub(rb"<[^>]+>", b"", text)
        t = decode_text(text)
        t = re.sub(r"\n\s*\n+", "\n\n", t)
        out.append(t)
        size += len(t)
        if size > limit:
            break
    import html as _html
    return _html.unescape("\n".join(out))[:limit], info


def zip_listing(data: bytes, limit: int = 200) -> list[str]:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        return [f"{i.filename}  ({i.file_size} bytes)" for i in z.infolist()[:limit]]
    except (zipfile.BadZipFile, ValueError, OSError):
        return []


def pdf_info(data: bytes) -> dict:
    out = {}
    m = re.search(rb"%PDF-(\d\.\d)", data[:1024])
    if m:
        out["version"] = m.group(1).decode()
    for key in (b"Title", b"Author", b"Creator", b"Producer", b"CreationDate"):
        m = re.search(rb"/" + key + rb"\s*\(([^)]{0,200})\)", data)
        if m:
            out[key.decode().lower()] = m.group(1).decode("latin-1", "replace")
    out["pages"] = len(re.findall(rb"/Type\s*/Page[^s]", data))
    return out


# ---------------------------------------------------------------------- the API's answer
def preview(src: Source, entry: dict, limit: int = IMAGE_LIMIT) -> dict:
    """What the app shows for ENTRY (an entry dict from ScanDB.entry with its volume's SRC)."""
    from .filetypes import category
    ext = entry.get("ext") or ""
    size = int(entry.get("size") or 0)
    out: dict = {"kind": "none", "size": size, "ext": ext, "info": {}}
    if entry.get("is_dir"):
        return out
    want = min(size, limit) if size else 0
    cat = category(entry.get("name") or "")
    small = cat in ("photo",) and size <= limit
    head = read_head(src, entry, want if (small or ext in ("docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "pdf",
                                                           "zip") and size <= limit) else min(size, 256 * 1024))
    out["hex"] = b64(head[:4096])
    valid = check_magic(ext, head)
    out["valid"] = valid
    if valid is False:
        out["note"] = (f"The content doesn't start like a .{ext} file: it was probably overwritten "
                       "(or the file was renamed).")
    if not head.strip(b"\0") and size:
        out["note"] = "The first bytes are all zeros: the content was probably wiped or overwritten."
        out["valid"] = False
    if cat == "video" or ext in VIDEO_EXTS:
        return _video_preview(src, entry, out)
    if cat == "photo" or ext in ("jpg", "jpeg", "png", "gif", "bmp", "webp", "tif", "tiff"):
        info: dict = {}
        if head[:2] == b"\xff\xd8":
            info, tiff = jpeg_exif(head)
            dims = image_size(head)
            if dims:
                info["width"], info["height"] = dims
            info.pop("thumb", None)
        elif head[:4] in (b"II*\0", b"MM\0*") or ext in ("cr2", "nef", "arw", "dng", "orf", "rw2", "pef", "srw"):
            info = exif(head)
            thumb = info.pop("thumb", None)
            if thumb:
                off, n = thumb
                out.update(kind="image", data=b64(head[off:off + n]), note=out.get("note") or
                           "Showing the preview the camera stored in the RAW file")
                out["info"] = info
                return out
        else:
            dims = image_size(head)
            if dims:
                info["width"], info["height"] = dims
        out["info"] = info
        if size <= limit and valid is not False:
            out.update(kind="image", data=b64(head))
        return out
    if ext in ("docx", "xlsx", "pptx", "odt", "ods", "odp", "odg", "epub") and size <= limit:
        text, info = office_text(head)
        out["info"] = info
        if text.strip():
            out.update(kind="text", text=text)
        elif info.get("members") is None:
            out["note"] = out.get("note") or "The document's archive structure is damaged (try Repair file)."
        return out
    if ext == "pdf":
        out["info"] = pdf_info(head)
        return out
    if ext in ("zip", "jar", "apk") and size <= limit:
        listing = zip_listing(head)
        if listing:
            out.update(kind="text", text="\n".join(listing))
        return out
    if ext in TEXT_EXTS or (cat in ("document", "other") and looks_like_text(head[:8192])):
        if looks_like_text(head[:TEXT_LIMIT]):
            out.update(kind="text", text=decode_text(head[:TEXT_LIMIT]))
            return out
    out["kind"] = "hex"
    return out


def _video_preview(src: Source, entry: dict, out: dict) -> dict:
    """Details of a video and a picture of its first key frame (see videopreview)."""
    from . import videopreview as vp
    try:
        info, vs = vp.video_details(src, entry)
    except Exception:  # noqa: BLE001 - a damaged video shows no details, never an error
        info, vs = {}, None
    carved = ((entry.get("extra") or {}).get("info") or {})
    if carved.get("needs_index"):
        info["needs_index"] = True
    out["info"] = {k: v for k, v in info.items() if k not in ("poster", "streamable")}
    out["details"] = vp.describe(info)
    if info.get("needs_index"):
        out["note"] = ("The recording was not finished: its index is missing, so players can't open it. Repair "
                       "it with a reference video from the same camera (Repair page → Repair damaged files).")
    pic = None
    if vs is not None and out.get("valid") is not False:
        try:
            pic = vp.poster(vs, info)
        except Exception:  # noqa: BLE001
            pic = None
    out["kind"] = "video"
    out["data"] = b64(pic) if pic else None
    if pic is None and not out.get("note") and (info.get("poster") or info.get("streamable")) \
            and not vp.ffmpeg_available():
        out["note"] = "Install ffmpeg to see a picture from the video."
    return out


def thumbnail(src: Source, entry: dict) -> dict:
    """A small picture for the photo grid: the EXIF/RAW embedded thumbnail when there is one, else the
    whole picture if it's small enough. {"data": base64 or None, "width", "height"}."""
    size = int(entry.get("size") or 0)
    out: dict = {"data": None}
    from .filetypes import category
    if category(entry.get("name") or "") == "video" or (entry.get("ext") or "") in VIDEO_EXTS:
        from . import videopreview as vp
        try:
            info, vs = vp.video_details(src, entry)
            pic = vp.poster(vs, info) if vs is not None else None
        except Exception:  # noqa: BLE001
            pic = None
        if pic:
            out["data"] = b64(pic)
            out["video"] = True
        return out
    head = read_head(src, entry, min(size, 256 * 1024))
    if head[:2] == b"\xff\xd8":
        info, tiff = jpeg_exif(head)
        thumb = exif(tiff).get("thumb") if tiff else None
        if thumb:
            off, n = thumb
            data = tiff[off:off + n]
            if data[:2] == b"\xff\xd8":
                out["data"] = b64(data)
                out["embedded"] = True
                return out
    elif head[:4] in (b"II*\0", b"MM\0*"):
        info = exif(head)
        thumb = info.get("thumb")
        if thumb and thumb[0] + thumb[1] <= len(head):
            out["data"] = b64(head[thumb[0]:thumb[0] + thumb[1]])
            out["embedded"] = True
            return out
    if size <= THUMB_LIMIT and check_magic(entry.get("ext") or "", head) is not False:
        out["data"] = b64(read_head(src, entry, size))
    return out
