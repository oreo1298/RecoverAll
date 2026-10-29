"""Videos for the signature engine: MP4/MOV/3GP/M4V/F4V (ISO media and QuickTime), AVI, Matroska/WebM,
Windows Media (WMV/ASF), Flash video, MPEG program streams (MPG/VOB), MPEG transport streams (TS/MTS/M2TS)
and RealMedia.

Lengths are exact for every format here: the top-level boxes / chunks / elements / objects / tags are walked
(or the recorded size is used), and the MPEG streams are followed pack by pack or packet by packet until the
start codes or sync bytes stop. A video cut short (the rest of it overwritten) is kept with a poor chance.
Phones and cameras record when a video was shot: it names the file.

An MP4/MOV is checked against its index (the movie box, moov), which says where every frame is and how big
it is (media/mp4carve.py does the work):

* Nine frames are looked at where the index puts them (and, when the movie box comes first, the start of the
  frames of the last chunk of sound). When they are all there, the file is in one piece, as found (this is
  what nearly every video gets, and it costs a few small reads).
* When the first frames are there but later ones aren't, the file was fragmented on the disk (big recordings
  on FAT32/exFAT/NTFS often are): its pieces are put back together by searching ahead for the frames that are
  missing (fair chance, the pieces become the file's runs). A movie box at the end of a fragmented file is
  searched for too: such a file shows up as media data with no movie box after it.
* Media data without any movie box, where the frames are valid video (H.264/H.265 NAL units, ProRes, Motion
  JPEG), is a recording that was never finished (the camera lost power, the card was pulled): the media data is
  measured and the file is kept with a poor chance, marked ``needs_index`` for the repair, which rebuilds the
  index from a reference video of the same camera.
* A movie box on its own (its frames would lie inside it: the end of a file whose start is elsewhere) is not a
  file: it is left for the media data to find (above).
"""

from __future__ import annotations

import logging
import struct

from ..media import mp4carve
from .base import CHANCE_FAIR, CHANCE_GOOD, CHANCE_POOR, Format, GiB, Hit, KiB, MiB, Reader
from .common import (
    MKV_EPOCH,
    BytesReader,
    bmff_kind,
    bmff_movie,
    ebml_uint,
    iter_ebml,
    memo,
    moov_info,
    parse_asf,
    plausible_time,
    time_name,
)
from .common import Box as _Box

log = logging.getLogger(__name__)


def _dated(t: float | None) -> tuple[str | None, float | None]:
    if t is not None and plausible_time(t):
        return time_name(t), t
    return None, None


# ---------------------------------------------------------------------- MP4 / MOV
NEEDS_INDEX_NOTE = ("The recording was not finished: its index is missing. Repair it with a reference video "
                    "from the same camera.")
DAMAGED_NOTE = "Part of the video data is not where its index says: it was overwritten, or lies elsewhere."
_PRE_MDAT = frozenset({b"free", b"skip", b"wide", b"uuid", b"pnot", b"junk", b"PICT"})


def _movie_info(mi: dict) -> dict:
    info: dict = {}
    if mi["width"] and mi["height"]:
        info["width"], info["height"] = mi["width"], mi["height"]
    if mi["duration"]:
        info["duration"] = round(mi["duration"], 3)
    return info


def parse_mp4(r: Reader) -> Hit | None:
    m = bmff_movie(r)
    if m is None:
        try:
            return _without_moov(r)
        except Exception:                     # a bug in the checks: no worse than before they existed
            log.debug("MP4 media data check failed at %d", r.start, exc_info=True)
            return None
    if m["audio_only"]:
        return None
    b, mi = m["walk"], m["moov"]
    name, mtime = _dated(mi["ctime"])
    chance = CHANCE_POOR if b.truncated else CHANCE_GOOD
    desc = "QuickTime movie" if m["ext"] == "mov" else None
    hit = Hit(m["ext"], b.end, chance, name=name, mtime=mtime, info=_movie_info(mi), description=desc)
    if b.truncated or b.end is None:
        return hit
    try:
        return _checked(r, b, hit)
    except Exception:                         # a bug in the checks must not lose a video that was found
        log.debug("MP4 sample check failed at %d", r.start, exc_info=True)
        return hit


def _checked(r: Reader, b, hit: Hit) -> Hit | None:
    """HIT (a movie with its movie box) checked against the frames its index lists: as it is, put back
    together from its pieces, marked damaged, or None for a movie box on its own."""
    moov = b.first(b"moov")
    if moov.size is None or moov.size > mp4carve.MAX_MOOV:
        return hit
    buf = r.read(moov.offset, moov.size)
    if len(buf) < moov.size:
        return hit
    mdat = next((x for x in b.boxes if x.type == b"mdat" and x.size), None)
    verdict = mp4carve.quick_check(r, buf, moov.offset, moov_first=mdat is None or mdat.offset > moov.offset)
    if verdict in ("ok", "unknown"):
        return hit
    if verdict == "stray":
        return None
    if mdat is not None and mdat.offset < moov.offset:
        return _damaged(hit)                 # the movie box is right after the media data: nothing moved
    end = mdat.end if mdat is not None else b.end
    asm = mp4carve.assemble(r, mp4carve.read_tables(buf), end, mdat.data if mdat is not None else moov.end)
    if asm is None:
        return hit if b.brand or verdict == "failed" else None
    if asm.fragments == 1:
        return hit if asm.complete else _damaged(hit)
    return _pieces(hit, asm)


def _damaged(hit: Hit) -> Hit:
    return Hit(hit.ext, hit.length, CHANCE_POOR, hit.name, hit.mtime, dict(hit.info or {}, note=DAMAGED_NOTE),
               description=hit.description)


def _pieces(hit: Hit, asm: mp4carve.Assembly) -> Hit:
    info = dict(hit.info or {}, fragments=len(asm.runs))
    if asm.uncertain:
        info["uncertain_cuts"] = asm.uncertain
    if asm.damaged:
        info["damaged_frames"] = asm.damaged
    if not asm.complete:
        info["note"] = DAMAGED_NOTE
    return Hit(hit.ext, sum(n for _o, n in asm.runs), CHANCE_FAIR if asm.complete else CHANCE_POOR, hit.name,
               hit.mtime, info, description=hit.description, runs=asm.runs)


def _mdat_header(r: Reader) -> tuple[bytes, tuple[bytes, ...], int, int, int | None] | None:
    """A movie that starts like one (ftyp, or QuickTime's wide) and reaches its media data box before any
    movie box: (brand, compatible brands, offset of the mdat box, its header size, the size it says or None
    when that is a placeholder: 0, 1 without a 64-bit size, or too small)."""
    pos, brand, compat = 0, b"", ()
    for i in range(16):
        h = r.read(pos, 16)
        if len(h) < 16:
            return None
        size, typ = struct.unpack_from(">I4s", h)
        if i == 0:
            if typ == b"ftyp":
                if not 16 <= size <= 4096:
                    return None
                data = r.read(8, size - 8)
                brand, compat = data[:4], tuple(data[j:j + 4] for j in range(8, len(data) - 3, 4))
                if not all(32 <= c < 127 for c in brand):
                    return None
                pos = size
                continue
            if typ != b"wide":
                return None
        if typ == b"mdat":
            if size == 1:
                large = struct.unpack_from(">Q", h, 8)[0]
                return brand, compat, pos, 16, large if large >= 16 + 1024 else None
            return brand, compat, pos, 8, size if size >= 8 + 1024 else None
        if typ not in _PRE_MDAT or not 8 <= size <= 64 * MiB:
            return None
        pos += size
    return None


def _without_moov(r: Reader) -> Hit | None:
    """Media data with no movie box after it: a fragmented movie whose movie box lies elsewhere (put back
    together), or a recording that was never finished (measured, marked needs_index)."""
    head = _mdat_header(r)
    if head is None:
        return None
    brand, compat, at, hdr, declared = head
    cat, ext = bmff_kind(brand, compat)
    if cat != "video":
        return None
    media = at + hdr
    end = at + declared if declared else None
    if mp4carve.media_kind(r, media) is None:
        return None
    scan = mp4carve.scan_media(r, media, min(r.limit, end if end else media + 64 * GiB))
    if end is not None:                      # a finished movie: its movie box should be somewhere
        hit = _paired(r, ext, media, scan, end)
        if hit is not None:
            return hit
    if scan is None:
        return None
    length = scan.end
    if end is not None and end <= r.limit and end - scan.video_end <= max(64 * KiB, 2 * max(scan.gaps, default=0)):
        length = end                         # the media data box ends where it says
    info = {"needs_index": True, "video": scan.video, "frames": scan.frames, "keyframes": scan.keyframes,
            "media_offset": media, "note": NEEDS_INDEX_NOTE}
    if scan.sound:
        info["audio"] = scan.sound           # "pcm" or "compressed": what lies between the video frames
    return Hit(ext, length, CHANCE_POOR, info=info, description="Unfinished recording (index missing)")


def _paired(r: Reader, ext: str, media: int, scan: mp4carve.MediaScan | None, end: int) -> Hit | None:
    """The movie box of the media data from MEDIA to END, found elsewhere on the disk: the whole file, in
    pieces. SCAN: the walk through the media data (where to start looking), None if even its first frame
    didn't check (the first piece of the file is that short)."""
    found = list(scan.moovs) if scan else []
    found += mp4carve.find_moovs(r, (scan.video_end if scan else media) - mp4carve.BLOCK,
                                 end + mp4carve.SEARCH_WINDOW, back=mp4carve.BACK_WINDOW)
    tried = set()
    for pm in found:
        if pm in tried or (pm - end) % mp4carve.BLOCK or len(tried) >= 32:
            continue
        tried.add(pm)
        got = mp4carve.read_moov(r, pm)
        if got is None or not got[1] or not mp4carve.tables_fit(got[1], media, end):
            continue
        buf, tables = got
        asm = mp4carve.assemble(r, tables, end + len(buf), media, moov=(end, len(buf), pm), need_start=True)
        if asm is None or not asm.complete:
            continue
        mi = moov_info(BytesReader(buf), _Box(b"moov", 0, 8, len(buf)))
        if mi["audio"] and not mi["video"]:
            return None
        name, mtime = _dated(mi["ctime"])
        hit = Hit(ext, end + len(buf), CHANCE_FAIR, name=name, mtime=mtime, info=_movie_info(mi),
                  description="QuickTime movie" if ext == "mov" else None)
        return _pieces(hit, asm) if len(asm.runs) > 1 else hit
    return None


# ---------------------------------------------------------------------- AVI
def parse_avi(r: Reader) -> Hit | None:
    h = r.read(0, 88)
    if len(h) < 88 or h[:4] != b"RIFF" or h[8:12] != b"AVI " or h[12:16] != b"LIST" or h[20:24] != b"hdrl":
        return None
    if h[24:28] != b"avih" or struct.unpack_from("<I", h, 28)[0] < 40:
        return None
    usec, _maxbps, _pad, _flags, frames, _init, streams, _buf, w, ht = struct.unpack_from("<10I", h, 32)
    if not 1 <= streams <= 64 or w > 65536 or ht > 65536:
        return None
    size = struct.unpack_from("<I", h, 4)[0]
    info: dict = {}
    if w and ht:
        info["width"], info["height"] = w, ht
    if usec and frames:
        info["duration"] = round(frames * usec / 1e6, 3)
    if size < 4 + 12 + 56:
        return Hit("avi", None, CHANCE_FAIR, info=info)       # size never written (recording interrupted)
    end = 8 + size + (size & 1)
    for _ in range(1024):                                    # OpenDML: further RIFF AVIX chunks follow
        x = r.read(end, 12)
        if len(x) < 12 or x[:4] != b"RIFF" or x[8:12] != b"AVIX":
            break
        n = struct.unpack_from("<I", x, 4)[0]
        if n < 4:
            break
        end += 8 + n + (n & 1)
    return Hit("avi", end, CHANCE_GOOD, info=info)


# ---------------------------------------------------------------------- Matroska / WebM
EBML_HEADER = 0x1A45DFA3
MKV_SEGMENT = 0x18538067
MKV_CLUSTER = 0x1F43B675
_MKV_TOP = frozenset({0x114D9B74, 0x1549A966, 0x1654AE6B, 0x1C53BB6B, MKV_CLUSTER, 0x1254C367, 0x1043A770,
                      0x1941A469, 0xEC, 0xBF})
_CLUSTER_CHILDREN = frozenset({0xE7, 0xA3, 0xA0, 0xA7, 0xAB, 0xEC, 0xBF, 0x5854, 0xAF})


def _element(r, pos: int) -> tuple[int, int, int | None] | None:
    """(id, data offset, size or None) of the element at POS."""
    d = r.read(pos, 12)
    for eid, data, size in iter_ebml(d):
        return eid, pos + data, size
    return None


def _mkv_walk(r, pos: int) -> tuple[int, bool]:
    """Walk the children of a segment of unknown size: (end, clean) where clean means the walk ended on
    something that isn't Matroska (rather than on a damaged element)."""
    for _ in range(10_000_000):
        e = _element(r, pos)
        if e is None or e[0] not in _MKV_TOP:
            return pos, True
        eid, data, size = e
        if size is None:
            if eid != MKV_CLUSTER:
                return pos, False
            pos = data
            for _ in range(10_000_000):                     # a cluster of unknown size: walk its blocks
                c = _element(r, pos)
                if c is None or c[0] not in _CLUSTER_CHILDREN or c[2] is None:
                    break
                pos = c[1] + c[2]
            continue
        pos = data + size
        if pos > r.limit:
            return pos, False
    return pos, False


def _mkv_meta(buf: bytes) -> dict:
    """Duration, date, picture size and track kinds from the start of a segment's data."""
    out: dict = {"video": False, "audio": False}
    scale = 1_000_000
    for eid, data, size in iter_ebml(buf):
        if size is None or data + size > len(buf):
            break
        if eid == 0x1549A966:                                # Info
            dur = None
            for cid, cd, cs in iter_ebml(buf, data, data + size):
                v = buf[cd:cd + (cs or 0)]
                if cid == 0x2AD7B1:
                    scale = ebml_uint(v) or scale
                elif cid == 0x4489 and cs in (4, 8) and len(v) == cs:
                    dur = struct.unpack(">f" if cs == 4 else ">d", v)[0]
                elif cid == 0x4461 and cs == 8 and len(v) == 8:
                    out["ctime"] = MKV_EPOCH + struct.unpack(">q", v)[0] / 1e9
            if dur:
                out["duration"] = round(dur * scale / 1e9, 3)
        elif eid == 0x1654AE6B:                              # Tracks
            for tid, td, ts in iter_ebml(buf, data, data + size):
                if tid != 0xAE or ts is None:
                    continue
                for fid, fd, fs in iter_ebml(buf, td, td + ts):
                    if fid == 0x83:
                        kind = ebml_uint(buf[fd:fd + (fs or 0)])
                        out["video"] |= kind == 1
                        out["audio"] |= kind == 2
                    elif fid == 0xE0 and fs:
                        for vid, vd, vs in iter_ebml(buf, fd, fd + fs):
                            if vid == 0xB0:
                                out["width"] = ebml_uint(buf[vd:vd + (vs or 0)])
                            elif vid == 0xBA:
                                out["height"] = ebml_uint(buf[vd:vd + (vs or 0)])
        elif eid == MKV_CLUSTER:
            break
    return out


def parse_mkv(r: Reader) -> Hit | None:
    head = r.read(0, 256)
    els = list(iter_ebml(head, 0, 256))
    if not els or els[0][0] != EBML_HEADER or els[0][2] is None or els[0][2] > 200:
        return None
    _, hd, hs = els[0]
    doctype = None
    for eid, data, size in iter_ebml(head, hd, hd + hs):
        if eid == 0x4282 and size:
            doctype = head[data:data + size].rstrip(b"\0")
    if doctype not in (b"matroska", b"webm"):
        return None
    pos = hd + hs
    seg = None
    for _ in range(16):                                      # Void elements may sit before the segment
        e = _element(r, pos)
        if e is None:
            return None
        if e[0] == MKV_SEGMENT:
            seg = e
            break
        if e[0] != 0xEC or e[2] is None:
            return None
        pos = e[1] + e[2]
    if seg is None:
        return None
    _, sdata, ssize = seg
    first = _element(r, sdata)
    if first is None or first[0] not in _MKV_TOP:
        return None
    meta = _mkv_meta(r.read(sdata, 1 * MiB))
    if ssize is not None:
        end, chance = sdata + ssize, CHANCE_GOOD
    else:
        end, clean = _mkv_walk(r, sdata)
        chance = CHANCE_GOOD if clean else CHANCE_POOR
    audio = meta["audio"] and not meta["video"]
    webm = doctype == b"webm"
    ext = ("weba" if webm else "mka") if audio else ("webm" if webm else "mkv")
    info = {k: meta[k] for k in ("width", "height", "duration") if meta.get(k)}
    name, mtime = _dated(meta.get("ctime"))
    return Hit(ext, end, chance, name=name, mtime=mtime, info=info,
               category="audio" if audio else None,
               description=("Matroska audio" if audio else None))


# ---------------------------------------------------------------------- Windows Media
def parse_wmv(r: Reader) -> Hit | None:
    a = memo(r, "asf", parse_asf)
    if a is None or (a["audio"] and not a["video"]):
        return None
    info = {"duration": round(a["duration"], 3)} if a["duration"] else {}
    name, mtime = _dated(a["ctime"])
    return Hit("wmv" if a["video"] else "asf", a["end"], CHANCE_GOOD if a["exact"] else CHANCE_FAIR,
               name=name, mtime=mtime, info=info)


# ---------------------------------------------------------------------- Flash video
def _amf_number(blob: bytes, key: bytes) -> float | None:
    k = struct.pack(">H", len(key)) + key + b"\x00"
    i = blob.find(k)
    if i < 0 or i + len(k) + 8 > len(blob):
        return None
    return struct.unpack_from(">d", blob, i + len(k))[0]


def parse_flv(r: Reader) -> Hit | None:
    h = r.read(0, 13)
    if len(h) < 13 or h[:4] != b"FLV\x01" or h[4] & 0xFA or struct.unpack_from(">II", h, 5) != (9, 0):
        return None
    pos, tags, info = 13, 0, {}
    for _ in range(50_000_000):
        t = r.read(pos, 11)
        if len(t) < 11 or (t[0] & 0x1F) not in (8, 9, 18) or t[0] & 0xC0 or t[8:11] != b"\0\0\0":
            break
        size = int.from_bytes(t[1:4], "big")
        prev = r.read(pos + 11 + size, 4)
        if len(prev) < 4 or struct.unpack(">I", prev)[0] != 11 + size:
            break
        if t[0] == 18 and not info and size < 64 * KiB:
            blob = r.read(pos + 11, size)
            for key in (b"width", b"height", b"duration"):
                v = _amf_number(blob, key)
                if v and 0 < v < 1e7:
                    info[key.decode()] = round(v, 3) if key == b"duration" else int(v)
        pos += 15 + size
        tags += 1
    if tags == 0:
        return None
    return Hit("flv", pos, CHANCE_GOOD, info=info)


# ---------------------------------------------------------------------- MPEG program stream (MPG, VOB)
def _ps_unit(d: bytes, p: int) -> int:
    """Length of the pack header / system header / PES packet at P of D (0: not one)."""
    if d[p:p + 3] != b"\0\0\x01" or p + 6 > len(d):
        return 0
    sid = d[p + 3]
    if sid == 0xBA:
        if d[p + 4] & 0xC0 == 0x40:                          # MPEG-2
            return 14 + (d[p + 13] & 7) if p + 14 <= len(d) else 0
        if d[p + 4] & 0xF0 == 0x20:                          # MPEG-1
            return 12
        return 0
    if sid >= 0xBB:
        return 6 + ((d[p + 4] << 8) | d[p + 5])
    return 0


def parse_mpg(r: Reader) -> Hit | None:
    pos, packs, units = 0, 0, 0
    pack_starts: list[int] = []
    vob = False
    buf, buf_at = b"", 0
    fast_tried = False
    for _ in range(100_000_000):
        if pos + 32 > buf_at + len(buf):
            buf, buf_at = r.read(pos, 256 * KiB), pos
            if len(buf) < 4:
                break
        p = pos - buf_at
        if buf[p:p + 4] == b"\0\0\x01\xb9":                  # program end code
            return _mpg_hit(pos + 4, packs, vob, True)
        n = _ps_unit(buf, p)
        if n == 0:
            break
        sid = buf[p + 3]
        if units == 0 and sid != 0xBA:
            return None
        if sid == 0xBA:
            packs += 1
            if len(pack_starts) < 64:
                pack_starts.append(pos)
        elif sid in (0xBD, 0xBF):
            vob = True
        units += 1
        pos += n
        # packs of one size (DVD: 2048 bytes): check the following ones with strided slices
        if not fast_tried and len(pack_starts) == 64:
            fast_tried = True
            gaps = {b - a for a, b in zip(pack_starts, pack_starts[1:])}
            if len(gaps) == 1:
                stride = gaps.pop()
                nxt = pack_starts[-1] + stride
                if pos <= nxt:
                    good = _stride_run(r, nxt, stride, b"\0\0\x01\xba")
                    packs += good
                    pos = nxt + good * stride
                    buf = b""
    if units < 3:
        return None
    return _mpg_hit(pos, packs, vob, False)


def _mpg_hit(end: int, packs: int, vob: bool, complete: bool) -> Hit | None:
    if packs == 0:
        return None
    ext = "vob" if vob else "mpg"
    return Hit(ext, end, CHANCE_GOOD if complete or packs > 1 else CHANCE_FAIR, info={"packs": packs},
               description="DVD video (VOB)" if vob else None)


def _stride_run(r, pos: int, stride: int, sig: bytes, step_units: int = 4096) -> int:
    """How many consecutive units of STRIDE bytes starting at POS begin with SIG, checked with strided slices
    (no Python loop per unit). The last unit is left for the caller's detailed walk."""
    total = 0
    k = len(sig)
    while True:
        d = r.read(pos, stride * step_units)
        n = len(d) // stride
        if n == 0:
            return max(0, total - 1)
        bad = n
        for j in range(k):
            col = d[j:n * stride:stride]
            want = sig[j:j + 1] * len(col)
            if col != want:
                for i in range(len(col)):
                    if col[i] != sig[j]:
                        bad = min(bad, i)
                        break
        total += bad
        if bad < n or n < step_units:
            return max(0, total - 1)
        pos += n * stride


# ---------------------------------------------------------------------- MPEG transport stream
def _ts_parser(stride: int, lead: int, ext: str):
    def parse(r: Reader) -> Hit | None:
        d = r.read(0, stride * 16)
        if len(d) < stride * 16:
            return None
        if d[lead::stride][:16] != b"G" * 16:
            return None
        pat = 0
        for i in range(16):
            p = i * stride + lead
            if d[p + 1] & 0x80 or not d[p + 3] & 0x30:       # transport error, reserved adaptation control
                return None
            if ((d[p + 1] & 0x1F) << 8 | d[p + 2]) == 0:
                pat += 1
        n = _stride_run(r, lead, stride, b"G") + 1
        end = n * stride
        return Hit(ext, end, CHANCE_GOOD, info={"packets": n},
                   description="AVCHD / Blu-ray video" if ext == "m2ts" else None)
    return parse


# ---------------------------------------------------------------------- RealMedia
_RM_CHUNKS = frozenset({b"PROP", b"MDPR", b"CONT", b"DATA", b"INDX", b"RMMD", b"RJMD", b"RMJE"})


def parse_rm(r: Reader) -> Hit | None:
    h = r.read(0, 18)
    if len(h) < 18 or h[:4] != b".RMF":
        return None
    size, ver = struct.unpack_from(">IH", h, 4)
    if ver > 1 or not 16 <= size <= 64 or struct.unpack_from(">I", h, 14)[0] > 1000:
        return None
    pos, seen = size, set()
    for _ in range(100000):
        c = r.read(pos, 18)
        if len(c) < 10 or c[:4] not in _RM_CHUNKS:
            break
        n = struct.unpack_from(">I", c, 4)[0]
        if n < 10:
            break
        seen.add(c[:4])
        if c[:4] == b"DATA" and len(c) == 18:
            end = _rm_packets(r, pos + 18, struct.unpack_from(">I", c, 10)[0])
            if end is not None and end != pos + n:
                pos = end
                if r.read(pos, 8) == bytes(8):          # the "end header" some writers add
                    pos += 8
                continue
        pos += n
    if not {b"PROP", b"DATA"} <= seen:
        return None
    return Hit("rm", pos, CHANCE_GOOD)


def _rm_packets(r, pos: int, count: int) -> int | None:
    """End of COUNT media packets from POS (each: version, length including the header, ...), or None if
    they don't add up (the DATA chunk's size is then trusted)."""
    if not 0 < count <= 10_000_000:
        return None
    buf, at = b"", pos
    for _ in range(count):
        if pos + 4 > at + len(buf):
            buf, at = r.read(pos, 256 * KiB), pos
        p = pos - at
        if p + 4 > len(buf):
            return None
        ver, n = struct.unpack_from(">HH", buf, p)
        if ver > 1 or n < 12:
            return None
        pos += n
    return pos


FORMATS = [
    Format("mp4", "MP4 / QuickTime video", "video", ("mp4", "mov", "m4v", "3gp", "3g2", "f4v"),
           ((4, b"ftyp"), (4, b"moov"), (4, b"mdat"), (4, b"wide"), (4, b"free"), (4, b"skip"), (4, b"pnot")),
           parse_mp4, max_size=64 * GiB, min_size=256, aliases=("mov", "m4v", "3gp", "3g2", "f4v", "qt")),
    Format("avi", "AVI video", "video", ("avi",), ((8, b"AVI LIST"),), parse_avi, max_size=64 * GiB),
    Format("mkv", "Matroska / WebM video", "video", ("mkv", "webm", "mka", "weba"), ((0, b"\x1a\x45\xdf\xa3"),),
           parse_mkv, max_size=64 * GiB, aliases=("webm", "matroska")),
    Format("wmv", "Windows Media video", "video", ("wmv", "asf"),
           ((0, b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c"),), parse_wmv,
           max_size=16 * GiB, aliases=("asf",)),
    Format("flv", "Flash video", "video", ("flv",), ((0, b"FLV\x01"),), parse_flv, max_size=16 * GiB),
    Format("mpg", "MPEG video", "video", ("mpg", "vob"), ((0, b"\0\0\x01\xba"),), parse_mpg, max_size=16 * GiB,
           aliases=("mpeg", "vob", "m2p")),
    Format("ts", "MPEG transport stream", "video", ("ts",), ((0, b"G"),), _ts_parser(188, 0, "ts"),
           max_size=64 * GiB, min_size=188 * 16, aliases=("mpegts",)),
    Format("m2ts", "AVCHD / Blu-ray video", "video", ("m2ts", "mts"), ((4, b"G"),), _ts_parser(192, 4, "m2ts"),
           max_size=64 * GiB, min_size=192 * 16, aliases=("mts", "m2t")),
    Format("rm", "RealMedia video", "video", ("rm", "rmvb"), ((0, b".RMF\0\0\0"),), parse_rm, max_size=8 * GiB,
           aliases=("rmvb", "ra")),
]
