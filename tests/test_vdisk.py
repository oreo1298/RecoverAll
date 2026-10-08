"""Virtual-disk and forensic images (VHD, VHDX, VDI, VMDK, QCOW2, QCOW, E01) read natively.

The writers here follow each format's specification, checksums included (the VHD one's-complement sum, VHDX
CRC-32C, EWF Adler-32), and build images from a known payload; the readers must give the payload back, holes as
zeros, and damage as zeros recorded in ``bad``. Where qemu-img and ewfacquire are installed, the images they make
are read too, and qemu-img reads the images written here, so the writers are checked by an independent
implementation (CI installs qemu-utils)."""

from __future__ import annotations

import hashlib
import json
import random
import shutil
import struct
import subprocess
import uuid
import zlib
from pathlib import Path

import pytest
from imagekit import MiB, mkfs, mtools_copy, mtools_delete, need, payload

from recoverall.core.blockio import FileSource, open_source
from recoverall.core.errors import FormatError, NotSupported, RallError
from recoverall.core.fsdetect import crc32c
from recoverall.core.vdisk import check_raw_file, detect, ewf_segments

GD_AT_END = 0xFFFFFFFFFFFFFFFF


def disk_payload(size: int, seed: int = 1, holes=(), texty=()) -> bytes:
    """SIZE bytes that don't repeat, with zeroed ranges (HOLES: left unallocated by the writers) and compressible
    ones (TEXTY)."""
    data = bytearray(payload(size, seed))
    for off, n in holes:
        data[off:off + n] = bytes(n)
    for off, n in texty:
        data[off:off + n] = (b"The quick brown fox jumps over the lazy dog. " * (n // 45 + 1))[:n]
    return bytes(data)


def check_image(path, data: bytes, fmt: str, sector: int = 512) -> None:
    """PATH opens as FMT and reads as DATA: whole, in unaligned random pieces, and zeros past the end."""
    src = open_source(str(path))
    try:
        assert src.format == fmt
        assert src.size == len(data)
        assert src.sector_size == sector
        assert src.read(0, src.size) == data
        rnd = random.Random(len(data))
        for _ in range(150):
            off = rnd.randrange(len(data))
            n = rnd.choice((1, 7, 511, 512, 513, 4096, 65537, 300001))
            assert src.read(off, n) == data[off:off + n].ljust(n, b"\0"), (off, n)
        assert src.read(len(data) + 5, 10) == bytes(10)
        assert not src.bad.ranges()
    finally:
        src.close()


def test_crc32c_check_value():
    # the VHDX writers below use the app's CRC-32C: make sure it is the real one (RFC 3720 check value)
    assert crc32c(b"123456789") == 0xE3069283


# ====================================================================== VHD
def vhd_checksum(b) -> int:
    return ~sum(b) & 0xFFFFFFFF                # one's complement of the byte sum (checksum field zero)


def vhd_geometry(size: int) -> tuple[int, int, int]:
    """Cylinders, heads, sectors per track, as the VHD specification's appendix computes them."""
    total = min(size // 512, 65535 * 16 * 255)
    if total >= 65535 * 16 * 63:
        spt, heads = 255, 16
        cth = total // spt
    else:
        spt = 17
        cth = total // spt
        heads = max(4, (cth + 1023) // 1024)
        if cth >= heads * 1024 or heads > 16:
            spt, heads = 31, 16
            cth = total // spt
        if cth >= heads * 1024:
            spt, heads = 63, 16
            cth = total // spt
    return cth // heads, heads, spt


def vhd_footer(size: int, disk_type: int, data_offset: int) -> bytes:
    f = bytearray(512)
    cyl, heads, spt = vhd_geometry(size)
    # "win " (Hyper-V) as the creator: readers then take the size from the footer, not from the geometry
    struct.pack_into(">8sIIQI4sI4sQQHBBI", f, 0, b"conectix", 2, 0x00010000, data_offset, 0x2B5A6E2F, b"win ",
                     0x000A0000, b"Wi2k", size, size, cyl, heads, spt, disk_type)
    f[68:84] = uuid.uuid4().bytes
    struct.pack_into(">I", f, 64, vhd_checksum(f))
    return bytes(f)


def make_vhd(data: bytes, dynamic: bool = True, block: int = 2 * MiB, parent: str = "") -> bytes:
    """A fixed VHD (the disk, then the footer) or a dynamic one: footer copy, dynamic-disk header, BAT, blocks
    (sector bitmap + data, stored in a shuffled order; all-zero blocks left out), footer."""
    size = len(data)
    if not dynamic:
        return data + vhd_footer(size, 2, 0xFFFFFFFFFFFFFFFF)
    n = -(-size // block)
    footer = vhd_footer(size, 4 if parent else 3, 512)
    dyn = bytearray(1024)
    struct.pack_into(">8sQQIII", dyn, 0, b"cxsparse", 0xFFFFFFFFFFFFFFFF, 1536, 0x00010000, n, block)
    if parent:
        dyn[40:56] = uuid.uuid4().bytes
        name = parent.encode("utf-16-be")
        dyn[64:64 + len(name)] = name
    struct.pack_into(">I", dyn, 36, vhd_checksum(dyn))
    bat_bytes = -(-4 * n // 512) * 512
    bat = [0xFFFFFFFF] * (bat_bytes // 4)
    bitmap_len = ((block // 512 + 7) // 8 + 511) // 512 * 512        # one bit per sector, whole sectors
    pos = 1536 + bat_bytes
    body = bytearray()
    order = list(range(n))
    random.Random(n).shuffle(order)
    for i in order:
        chunk = data[i * block:(i + 1) * block].ljust(block, b"\0")
        if not any(chunk):
            continue
        bat[i] = pos // 512
        bitmap = bytearray(bitmap_len)
        for s in range(block // 512):
            if any(chunk[s * 512:(s + 1) * 512]):
                bitmap[s // 8] |= 0x80 >> (s % 8)
        body += bitmap + chunk
        pos += bitmap_len + block
    return footer + bytes(dyn) + struct.pack(f">{len(bat)}I", *bat) + bytes(body) + footer


VHD_DATA = disk_payload(9 * MiB + 7 * 512, 11, holes=[(2 * MiB, 2 * MiB), (6 * MiB + 4096, 8192)],
                        texty=[(5 * MiB, 70000)])


@pytest.mark.parametrize("dynamic,block", [(False, 0), (True, 2 * MiB), (True, 512 * 1024)])
def test_vhd(tmp_path, dynamic, block):
    p = tmp_path / "disk.vhd"
    p.write_bytes(make_vhd(VHD_DATA, dynamic, block or 2 * MiB))
    assert detect(str(p)) == "VHD"
    check_image(p, VHD_DATA, "VHD")


# ====================================================================== VHDX
GUID = {k: uuid.UUID(v).bytes_le for k, v in {
    "bat": "2DC27766-F623-4200-9D64-115E9BFD4A08", "metadata": "8B7CA206-4790-4B9A-B8FE-575F050F886E",
    "params": "CAA16737-FA36-4D43-B3B6-33F0AA44E76B", "size": "2FA54224-CD1B-4876-B211-5DBED83BF4B8",
    "page83": "BECA12AB-B2E6-4523-93EF-C309E000C746", "logical": "8141BF1D-A96F-4709-BA47-F233A8FAAB5F",
    "physical": "CDA348C7-445D-4471-9CC9-E9885251C556", "parent": "A8D35F2D-B30B-454D-ABF7-D3D84834AB0C",
    "vhdx_parent_type": "B04AEFB7-D19E-4A81-B789-25B8E9445913"}.items()}


def vhdx_parent_locator(path: str) -> bytes:
    kv = [("parent_linkage", "{" + str(uuid.uuid4()) + "}"), ("relative_path", path)]
    head = bytearray(20)
    head[:16] = GUID["vhdx_parent_type"]
    struct.pack_into("<HH", head, 16, 0, len(kv))
    entries, strings = bytearray(), bytearray()
    base = 20 + 12 * len(kv)
    for k, v in kv:
        kb, vb = k.encode("utf-16-le"), v.encode("utf-16-le")
        ko = base + len(strings)
        strings += kb
        vo = base + len(strings)
        strings += vb
        entries += struct.pack("<IIHH", ko, vo, len(kb), len(vb))
    return bytes(head + entries + strings)


def make_vhdx(size: int, blocks: dict[int, bytes], block: int = MiB, sector: int = 512,
              states: dict[int, int] | None = None, parent: str = "", log_block: int | None = None) -> bytes:
    """A dynamic VHDX of SIZE bytes holding BLOCKS (block number → data) laid out as Hyper-V does: file type
    identifier, two headers, two region tables, a 1 MiB log, the metadata region, the BAT (payload entries with
    a sector-bitmap entry after every chunk), then the payload blocks (shuffled). STATES gives other states to
    some blocks (0 not present, 2 zero, 3 unmapped). LOG_BLOCK is stored, but marked present only by a log
    entry (an unclean shutdown): the BAT page on disk still says not present."""
    ratio = (1 << 23) * sector // block
    nblocks = -(-size // block)
    total = -(-nblocks // ratio) * (ratio + 1) if parent else nblocks + (nblocks - 1) // ratio
    bat_len = -(-8 * total // MiB) * MiB
    log_off, meta_off, bat_off = MiB, 2 * MiB, 3 * MiB
    data_off = bat_off + bat_len
    img = bytearray(data_off)
    img[:8] = b"vhdxfile"
    creator = "RecoverAll tests".encode("utf-16-le")
    img[8:8 + len(creator)] = creator
    log_guid = uuid.uuid4().bytes_le if log_block is not None else bytes(16)
    for i, at in enumerate((64 * 1024, 128 * 1024)):
        h = bytearray(4096)
        h[:4] = b"head"
        struct.pack_into("<Q", h, 8, 10 + i)                   # sequence number: the second header is current
        h[16:32] = uuid.uuid4().bytes_le                          # file write GUID
        h[32:48] = uuid.uuid4().bytes_le                          # data write GUID
        h[48:64] = log_guid
        struct.pack_into("<HHIQ", h, 64, 0, 1, MiB, log_off)     # log version, version, log length and offset
        struct.pack_into("<I", h, 4, crc32c(bytes(h)))
        img[at:at + 4096] = h
    rt = bytearray(64 * 1024)
    rt[:4] = b"regi"
    struct.pack_into("<II", rt, 8, 2, 0)
    rt[16:48] = GUID["bat"] + struct.pack("<QII", bat_off, bat_len, 1)
    rt[48:80] = GUID["metadata"] + struct.pack("<QII", meta_off, MiB, 1)
    struct.pack_into("<I", rt, 4, crc32c(bytes(rt)))
    img[192 * 1024:256 * 1024] = rt
    img[256 * 1024:320 * 1024] = rt
    m = bytearray(MiB)
    m[:8] = b"metadata"
    items = [("params", struct.pack("<II", block, 2 if parent else 0), 4),     # IsRequired
             ("size", struct.pack("<Q", size), 6),                              # IsVirtualDisk | IsRequired
             ("page83", uuid.uuid4().bytes_le, 6),
             ("logical", struct.pack("<I", sector), 6),
             ("physical", struct.pack("<I", 4096), 6)]
    if parent:
        items.append(("parent", vhdx_parent_locator(parent), 4))
    struct.pack_into("<H", m, 10, len(items))
    off = 64 * 1024
    for i, (key, value, flags) in enumerate(items):
        m[32 + 32 * i:64 + 32 * i] = GUID[key] + struct.pack("<IIII", off, len(value), flags, 0)
        m[off:off + len(value)] = value
        off += -(-len(value) // 8) * 8
    img[meta_off:meta_off + MiB] = m
    bat = bytearray(bat_len)
    pos, body = data_off, bytearray()
    order = sorted(blocks)
    random.Random(len(order)).shuffle(order)
    logged = None
    for i in order:
        k = i + i // ratio
        if (states or {}).get(i, 6) != 6:
            continue
        if i == log_block:
            logged = (k, 6 | (pos // MiB) << 20)
        else:
            struct.pack_into("<Q", bat, 8 * k, 6 | (pos // MiB) << 20)
        body += blocks[i].ljust(block, b"\0")
        pos += block
    for i, st in (states or {}).items():
        if st != 6:
            struct.pack_into("<Q", bat, 8 * (i + i // ratio), st)
    img[bat_off:bat_off + bat_len] = bat
    if logged is not None:
        k, value = logged
        page = (8 * k) // 4096 * 4096
        newpage = bytearray(bat[page:page + 4096])
        struct.pack_into("<Q", newpage, 8 * k - page, value)
        foff = bat_off + page
        size_after = len(img) + len(body)
        entry = bytearray(8192)                                 # one descriptor sector, one data sector
        entry[:4] = b"loge"
        struct.pack_into("<IIQII", entry, 8, len(entry), 0, 1, 1, 0)    # length, tail, sequence, descriptors
        entry[32:48] = log_guid
        struct.pack_into("<QQ", entry, 48, size_after, size_after)       # flushed and last file offset
        entry[64:96] = b"desc" + newpage[4092:] + newpage[:8] + struct.pack("<QQ", foff, 1)
        entry[4096:8192] = b"data" + struct.pack("<I", 0) + newpage[8:4092] + struct.pack("<I", 1)
        struct.pack_into("<I", entry, 4, crc32c(bytes(entry)))
        img[log_off:log_off + len(entry)] = entry
    return bytes(img) + bytes(body)


def blocks_of(data: bytes, block: int) -> dict[int, bytes]:
    return {i: data[o:o + block] for i, o in enumerate(range(0, len(data), block)) if any(data[o:o + block])}


VHDX_DATA = disk_payload(9 * MiB + 3 * 4096, 12, holes=[(MiB, MiB), (5 * MiB, 2 * MiB)], texty=[(3 * MiB, 9000)])


@pytest.mark.parametrize("sector", [512, 4096])
def test_vhdx(tmp_path, sector):
    p = tmp_path / "disk.vhdx"
    blocks = blocks_of(VHDX_DATA, MiB)
    p.write_bytes(make_vhdx(len(VHDX_DATA), blocks, MiB, sector, states={5: 2, 6: 3}))
    assert detect(str(p)) == "VHDX"
    check_image(p, VHDX_DATA, "VHDX", sector)


def test_vhdx_sector_bitmap_entries(tmp_path):
    # 2^23 sectors per chunk: with 512-byte sectors, the payload entries of the second chunk (4 GiB on) come
    # after the first chunk's sector-bitmap entry
    size = 4 * 1024 * MiB + 5 * MiB
    blocks = {i: payload(MiB, 100 + i) for i in (0, 1, 4095, 4096, 4099)}
    p = tmp_path / "big.vhdx"
    p.write_bytes(make_vhdx(size, blocks, MiB, 512))
    assert p.stat().st_size < 16 * MiB
    with open_source(str(p)) as src:
        assert src.size == size
        for i, data in blocks.items():
            assert src.read(i * MiB, MiB) == data
        assert src.read(4095 * MiB + MiB - 100, 200) == blocks[4095][-100:] + blocks[4096][:100]
        assert src.read(2 * MiB, MiB) == bytes(MiB) and src.read(4097 * MiB, 2 * MiB) == bytes(2 * MiB)
        assert src.read(size - 4096, 4096) == bytes(4096)
        assert not src.bad.ranges()


def test_vhdx_unclean_log_is_replayed(tmp_path):
    p = tmp_path / "crashed.vhdx"
    blocks = blocks_of(VHDX_DATA, MiB)
    p.write_bytes(make_vhdx(len(VHDX_DATA), blocks, log_block=4))
    check_image(p, VHDX_DATA, "VHDX")
    # the same file with the log's GUID cleared in both headers: block 4 is not present (zeros)
    raw = bytearray(p.read_bytes())
    for at in (64 * 1024, 128 * 1024):
        raw[at + 48:at + 64] = bytes(16)
        struct.pack_into("<I", raw, at + 4, 0)
        struct.pack_into("<I", raw, at + 4, crc32c(bytes(raw[at:at + 4096])))
    p.write_bytes(raw)
    with open_source(str(p)) as src:
        assert src.read(4 * MiB, MiB) == bytes(MiB)
        assert src.read(0, 4 * MiB) == VHDX_DATA[:4 * MiB]


def test_vhdx_unmapped_block_keeps_its_data(tmp_path):
    # a block the guest discarded (TRIM) but whose place in the file is still known: its old data is read
    p = tmp_path / "trimmed.vhdx"
    raw = bytearray(make_vhdx(len(VHDX_DATA), blocks_of(VHDX_DATA, MiB)))
    bat = 3 * MiB
    e = struct.unpack_from("<Q", raw, bat + 8 * 2)[0]
    struct.pack_into("<Q", raw, bat + 8 * 2, (e & ~7) | 3)
    p.write_bytes(raw)
    check_image(p, VHDX_DATA, "VHDX")


# ====================================================================== VDI
def make_vdi(data: bytes, block: int = MiB, kind: int = 1, zero_entry: int = 0xFFFFFFFF) -> bytes:
    """A VirtualBox 1.1 image: pre-header, header, block map at 1 MiB, blocks from offData (dynamic images
    store them in a shuffled order and leave all-zero blocks out, marked ZERO_ENTRY)."""
    size, n = len(data), -(-len(data) // block)
    off_blocks = MiB
    off_data = off_blocks + -(-4 * n // MiB) * MiB
    h = bytearray(off_blocks)
    h[:40] = b"<<< Oracle VM VirtualBox Disk Image >>>\n"
    struct.pack_into("<IIIII", h, 0x40, 0xBEDA107F, 0x00010001, 0x190, kind, 0)
    h[0x54:0x54 + 20] = b"RecoverAll test disk"
    struct.pack_into("<IIIIIII", h, 0x154, off_blocks, off_data, 0, 0, 0, 512, 0)
    bmap = [zero_entry] * n
    order = list(range(n))
    if kind != 2:
        random.Random(n).shuffle(order)
    stored = bytearray()
    for i in order:
        chunk = data[i * block:(i + 1) * block].ljust(block, b"\0")
        if kind != 2 and not any(chunk):
            continue
        bmap[i] = len(stored) // block
        stored += chunk
    struct.pack_into("<QIIII", h, 0x170, size, block, 0, n, len(stored) // block)
    h[0x188:0x198] = uuid.uuid4().bytes
    h[0x198:0x1A8] = uuid.uuid4().bytes
    if kind == 4:
        h[0x1A8:0x1B8] = uuid.uuid4().bytes                   # the parent's UUID
    table = struct.pack(f"<{n}I", *bmap).ljust(off_data - off_blocks, b"\0")
    return bytes(h) + table + bytes(stored)


VDI_DATA = disk_payload(7 * MiB + 1536, 13, holes=[(2 * MiB, MiB), (4 * MiB, MiB)], texty=[(6 * MiB, 5000)])


@pytest.mark.parametrize("kind,zero_entry", [(1, 0xFFFFFFFF), (1, 0xFFFFFFFE), (2, 0xFFFFFFFF)])
def test_vdi(tmp_path, kind, zero_entry):
    p = tmp_path / "disk.vdi"
    p.write_bytes(make_vdi(VDI_DATA, MiB, kind, zero_entry))
    assert detect(str(p)) == "VDI"
    check_image(p, VDI_DATA, "VDI")


def test_vdi_other_block_size(tmp_path):
    p = tmp_path / "disk.vdi"
    p.write_bytes(make_vdi(VDI_DATA, 256 * 1024))
    check_image(p, VDI_DATA, "VDI")


# ====================================================================== VMDK
def vmdk_header(version: int, flags: int, capacity: int, grain: int, desc: tuple[int, int], gtes: int, rgd: int,
                gd: int, overhead: int, compress: int = 0) -> bytes:
    return struct.pack("<4sIIQQQQIQQQB4sH", b"KDMV", version, flags, capacity, grain, desc[0], desc[1], gtes, rgd, gd,
                       overhead, 0, b"\n \r\n", compress).ljust(512, b"\0")


def vmdk_descriptor(create_type: str, extents: list[str], parent: str = "") -> bytes:
    lines = ["# Disk DescriptorFile", "version=1", 'encoding="UTF-8"', "CID=7a2b9c1d",
             f"parentCID={'1c2d3e4f' if parent else 'ffffffff'}", f'createType="{create_type}"']
    if parent:
        lines.append(f'parentFileNameHint="{parent}"')
    lines += ["", "# Extent description", *extents, "", "# The Disk Data Base", "#DDB", "",
              'ddb.virtualHWVersion = "4"', 'ddb.geometry.cylinders = "20"', 'ddb.geometry.heads = "16"',
              'ddb.geometry.sectors = "63"', 'ddb.adapterType = "ide"', ""]
    return "\n".join(lines).encode()


def make_vmdk_sparse(data: bytes, grain: int = 128, gtes: int = 512, name: str = "disk.vmdk", embed: bool = True,
                     zero_grains=(), parent: str = "") -> bytes:
    """A hosted sparse extent laid out as VMware Workstation does: header, embedded descriptor, redundant grain
    directory and tables, grain directory and tables (all preallocated), then the grains (shuffled). ZERO_GRAINS
    are marked zeroed (GTE 1) instead of left unallocated."""
    capacity = len(data) // 512
    ngrains = -(-capacity // grain)
    ngts = -(-ngrains // gtes)
    gd_sectors, gt_sectors = -(-4 * ngts // 512), -(-4 * gtes // 512)
    desc = vmdk_descriptor("monolithicSparse", [f'RW {capacity} SPARSE "{name}"'], parent) if embed else b""
    desc_at = (1, 20) if embed else (0, 0)
    rgd = 1 + desc_at[1]
    rgt = rgd + gd_sectors
    gd = rgt + ngts * gt_sectors
    gt0 = gd + gd_sectors
    overhead = -(-(gt0 + ngts * gt_sectors) // grain) * grain
    gtes_all = [0] * (ngts * gtes)
    grains = bytearray()
    order = list(range(ngrains))
    random.Random(ngrains).shuffle(order)
    for g in order:
        chunk = data[g * grain * 512:(g + 1) * grain * 512].ljust(grain * 512, b"\0")
        if g in zero_grains:
            assert not any(chunk)
            gtes_all[g] = 1
        elif any(chunk):
            gtes_all[g] = overhead + len(grains) // 512
            grains += chunk
    flags = 0x3 | (0x4 if zero_grains else 0)            # newline test, redundant tables, zeroed-grain entries
    out = bytearray(vmdk_header(1, flags, capacity, grain, desc_at, gtes, rgd, gd, overhead))
    out += desc.ljust(desc_at[1] * 512, b"\0")
    for gd_at, gt_at in ((rgd, rgt), (gd, gt0)):
        assert len(out) == gd_at * 512
        out += struct.pack(f"<{ngts}I", *[gt_at + t * gt_sectors for t in range(ngts)]).ljust(gd_sectors * 512, b"\0")
        out += struct.pack(f"<{ngts * gtes}I", *gtes_all)
    out = out.ljust(overhead * 512, b"\0")
    return bytes(out + grains)


def vmdk_marker(sectors: int, kind: int) -> bytes:
    return struct.pack("<QII", sectors, 0, kind).ljust(512, b"\0")


def make_vmdk_stream(data: bytes, grain: int = 128, gtes: int = 512) -> bytes:
    """A streamOptimized disk as an OVA holds it: header (grain directory "at the end"), descriptor, then for each
    grain table its grains (deflated, behind a grain marker) and the table (behind a marker); the grain directory,
    the footer (a copy of the header that says where the directory is) and the end-of-stream marker."""
    capacity = len(data) // 512
    ngrains = -(-capacity // grain)
    ngts = -(-ngrains // gtes)
    gd_sectors, gt_sectors = -(-4 * ngts // 512), -(-4 * gtes // 512)
    desc = vmdk_descriptor("streamOptimized", [f'RW {capacity} SPARSE "disk.vmdk"'])
    desc_sectors = -(-len(desc) // 512)
    overhead = 128
    flags = 0x30001                                       # newline test, compressed grains, markers

    def header(gd: int) -> bytes:
        return vmdk_header(3, flags, capacity, grain, (1, desc_sectors), gtes, 0, gd, overhead, compress=1)
    out = bytearray(header(GD_AT_END) + desc).ljust(overhead * 512, b"\0")
    gd = [0] * ngts
    for t in range(ngts):
        table = [0] * gtes
        for g in range(t * gtes, min(ngrains, (t + 1) * gtes)):
            chunk = data[g * grain * 512:(g + 1) * grain * 512].ljust(grain * 512, b"\0")
            if not any(chunk):
                continue
            table[g - t * gtes] = len(out) // 512
            comp = zlib.compress(chunk)
            out += (struct.pack("<QI", g * grain, len(comp)) + comp).ljust(-(-(12 + len(comp)) // 512) * 512, b"\0")
        if any(table):
            out += vmdk_marker(gt_sectors, 1)
            gd[t] = len(out) // 512
            out += struct.pack(f"<{gtes}I", *table).ljust(gt_sectors * 512, b"\0")
    out += vmdk_marker(gd_sectors, 2)
    gd_at = len(out) // 512
    out += struct.pack(f"<{ngts}I", *gd).ljust(gd_sectors * 512, b"\0")
    out += vmdk_marker(1, 3) + header(gd_at) + vmdk_marker(0, 0)
    return bytes(out)


VMDK_DATA = disk_payload(6 * MiB + 64 * 1024, 14, holes=[(MiB, 192 * 1024), (3 * MiB, MiB)],
                         texty=[(5 * MiB, 200000)])


def test_vmdk_monolithic_sparse(tmp_path):
    p = tmp_path / "disk.vmdk"
    zero = {g for g in range(MiB // 65536, (MiB + 192 * 1024) // 65536)}
    p.write_bytes(make_vmdk_sparse(VMDK_DATA, zero_grains=zero))
    assert detect(str(p)) == "VMDK"
    check_image(p, VMDK_DATA, "VMDK")
    # a grain table entry pointing past the end of the file: zeros, and recorded
    raw = bytearray(p.read_bytes())
    gd = struct.unpack_from("<Q", raw, 56)[0]
    gt = struct.unpack_from("<I", raw, gd * 512)[0]
    struct.pack_into("<I", raw, gt * 512 + 4 * 2, len(raw) // 512 + 1000)
    p.write_bytes(raw)
    with open_source(str(p)) as src:
        assert src.read(2 * 65536, 65536) == bytes(65536)
        assert src.bad.ranges() == [(2 * 65536, 65536)]
        assert src.read(3 * 65536, 65536) == VMDK_DATA[3 * 65536:4 * 65536]


def test_vmdk_stream_optimized(tmp_path):
    p = tmp_path / "disk.vmdk"
    p.write_bytes(make_vmdk_stream(VMDK_DATA))
    check_image(p, VMDK_DATA, "VMDK")


def test_vmdk_stream_cut_short(tmp_path):
    # an OVA download that stopped: no footer, so no grain directory; the grains that made it are found by
    # walking their markers, the rest reads as zeros and is recorded
    full = make_vmdk_stream(VMDK_DATA)
    p = tmp_path / "partial.vmdk"
    p.write_bytes(full[:len(full) * 2 // 3])
    with open_source(str(p)) as src:
        assert src.size == len(VMDK_DATA)
        data = src.read(0, src.size)
        bad = src.bad.ranges()
        assert bad and bad[-1][0] + bad[-1][1] == len(VMDK_DATA)
        first_bad = bad[0][0]
        assert first_bad > 2 * MiB
        assert data[:first_bad] == VMDK_DATA[:first_bad]
        assert not any(data[first_bad:])


def test_vmdk_descriptor_flat(tmp_path):
    (tmp_path / "disk-flat.vmdk").write_bytes(VMDK_DATA)
    d = tmp_path / "disk.vmdk"
    d.write_bytes(vmdk_descriptor("monolithicFlat", [f'RW {len(VMDK_DATA) // 512} FLAT "disk-flat.vmdk" 0']))
    assert detect(str(d)) == "VMDK"
    check_image(d, VMDK_DATA, "VMDK")


def test_vmdk_descriptor_split_extents(tmp_path):
    # twoGbMaxExtent-style pieces: a flat extent read from an offset, a sparse one, a zero one, a sparse one
    a, b, c = 2 * MiB, MiB + 512 * 64, MiB
    data = bytearray(VMDK_DATA)
    data[a + b:a + b + c] = bytes(c)
    data = bytes(data)
    (tmp_path / "disk-f001.vmdk").write_bytes(payload(4096, 99) + data[:a])
    (tmp_path / "disk-s002.vmdk").write_bytes(make_vmdk_sparse(data[a:a + b], embed=False))
    (tmp_path / "disk-s003.vmdk").write_bytes(make_vmdk_sparse(data[a + b + c:], embed=False))
    d = tmp_path / "disk.vmdk"
    d.write_bytes(vmdk_descriptor("custom", [f'RW {a // 512} FLAT "disk-f001.vmdk" 8',
                                             f'RW {b // 512} SPARSE "disk-s002.vmdk"', f"RW {c // 512} ZERO",
                                             f'RW {(len(data) - a - b - c) // 512} SPARSE "disk-s003.vmdk"']))
    check_image(d, data, "VMDK")
    # one piece missing: the disk still opens, that part reads as zeros and is recorded
    (tmp_path / "disk-s002.vmdk").unlink()
    with open_source(str(d)) as src:
        assert src.read(0, a) == data[:a] and src.read(a, b) == bytes(b)
        assert src.read(a + b + c, 4096) == data[a + b + c:a + b + c + 4096]
        assert src.bad.ranges() == [(a, b)]
    # all missing: a clear error
    for name in ("disk-f001.vmdk", "disk-s003.vmdk"):
        (tmp_path / name).unlink()
    with pytest.raises(RallError, match="missing"):
        open_source(str(d))


# ====================================================================== QCOW2 and QCOW
def make_qcow2(data: bytes, version: int = 3, cluster_bits: int = 16, compress=(), zero=(), backing: str = "",
               backing_fmt: str = "", crypt: int = 0, incompatible: int = 0) -> bytes:
    """A QCOW2 image as qemu lays one out: header (with extensions and the backing file's name), refcount table,
    L1 table, L2 tables, the clusters (shuffled; all-zero ones left unallocated), the COMPRESS clusters deflated
    (raw deflate, 4 KiB window) one after another at sector granularity, and refcount blocks that count every
    cluster. ZERO clusters are version 3 zero clusters."""
    cs = 1 << cluster_bits
    size = len(data)
    n = -(-size // cs)
    l2n = cs // 8
    l1_size = -(-n // l2n)
    l1_clusters = max(1, -(-8 * l1_size // cs))
    nxt = 2 + l1_clusters                      # 0: header, 1: refcount table, then L1
    l1 = [0] * l1_size
    l2: dict[int, list[int]] = {}
    clusters: dict[int, bytes] = {}            # host cluster → content
    refs: dict[int, int] = {0: 1, 1: 1, **{2 + i: 1 for i in range(l1_clusters)}}
    kinds = {}
    for c in range(n):
        chunk = data[c * cs:(c + 1) * cs].ljust(cs, b"\0")
        if c in zero and version >= 3:
            kinds[c] = "zero"
        elif c in compress:
            kinds[c] = "compressed"
        elif any(chunk):
            kinds[c] = "data"
    for c in kinds:
        if c // l2n not in l2:
            l2[c // l2n] = [0] * l2n
            l1[c // l2n] = (nxt * cs) | 1 << 63
            refs[nxt] = 1
            nxt += 1
    order = [c for c in kinds if kinds[c] == "data"]
    random.Random(n).shuffle(order)
    for c in order:
        clusters[nxt] = data[c * cs:(c + 1) * cs].ljust(cs, b"\0")
        l2[c // l2n][c % l2n] = (nxt * cs) | 1 << 63
        refs[nxt] = 1
        nxt += 1
    for c in kinds:
        if kinds[c] == "zero":
            l2[c // l2n][c % l2n] = 1
    blob = bytearray()
    base = nxt * cs
    shift = 62 - (cluster_bits - 8)
    for c in sorted(c for c in kinds if kinds[c] == "compressed"):
        co = zlib.compressobj(9, zlib.DEFLATED, -12)
        comp = co.compress(data[c * cs:(c + 1) * cs].ljust(cs, b"\0")) + co.flush()
        off = base + len(blob)
        extra = ((off + len(comp) - 1) >> 9) - (off >> 9)
        l2[c // l2n][c % l2n] = 1 << 62 | extra << shift | off
        span = (extra + 1) * 512 - (off & 511)
        for hc in range(off // cs, (off + span - 1) // cs + 1):
            refs[hc] = refs.get(hc, 0) + 1
        blob += comp
    blob += bytes(-len(blob) % 512)
    end_cluster = -(-(base + len(blob)) // cs)
    per_block = cs * 8 // 16                   # 16-bit refcounts
    nref = 1
    while -(-(end_cluster + nref) // per_block) > nref:
        nref += 1
    for i in range(nref):
        refs[end_cluster + i] = 1
    total = end_cluster + nref
    out = bytearray(total * cs)
    h = bytearray(cs)
    struct.pack_into(">4sIQIIQIIQQIIQ", h, 0, b"QFI\xfb", version, 0, 0, cluster_bits, size, crypt, l1_size, 2 * cs,
                     cs, 1, 0, 0)
    pos = 72
    if version >= 3:
        struct.pack_into(">QQQII", h, 72, incompatible, 0, 0, 4, 112)    # refcount order 4, header length
        pos = 112
    if backing_fmt:
        fmt = backing_fmt.encode()
        h[pos:pos + 8] = struct.pack(">II", 0xE2792ACA, len(fmt))
        h[pos + 8:pos + 8 + len(fmt)] = fmt
        pos += 8 + -(-len(fmt) // 8) * 8
    pos += 8                                   # the end of the extensions (type 0)
    if backing:
        name = backing.encode()
        h[pos:pos + len(name)] = name
        struct.pack_into(">QI", h, 8, pos, len(name))
    out[:cs] = h
    reftable = [(end_cluster + i) * cs for i in range(nref)]
    struct.pack_into(f">{nref}Q", out, cs, *reftable)
    struct.pack_into(f">{l1_size}Q", out, 2 * cs, *l1)
    for i, table in l2.items():
        at = (l1[i] & 0x00FFFFFFFFFFFE00)
        struct.pack_into(f">{l2n}Q", out, at, *table)
    for hc, content in clusters.items():
        out[hc * cs:(hc + 1) * cs] = content
    out[base:base + len(blob)] = blob
    for hc, count in refs.items():
        struct.pack_into(">H", out, (end_cluster + hc // per_block) * cs + 2 * (hc % per_block), count)
    return bytes(out)


QCOW_DATA = disk_payload(5 * MiB + 3 * 512, 15, holes=[(MiB, 3 * 65536), (2 * MiB, 65536)],
                         texty=[(3 * MiB, 3 * 65536)])
QCOW_COMPRESSED = (48, 49, 50, 60)             # 3 texty clusters, and one of random data
QCOW_ZERO = (32,)                              # a cluster of the 2 MiB hole: a v3 zero cluster


@pytest.mark.parametrize("version,cluster_bits", [(2, 16), (3, 16), (3, 12)])
def test_qcow2(tmp_path, version, cluster_bits):
    p = tmp_path / "disk.qcow2"
    scale = 1 << (16 - cluster_bits)
    comp = {c * scale + k for c in QCOW_COMPRESSED for k in range(scale)}
    zero = {c * scale + k for c in QCOW_ZERO for k in range(scale)}
    p.write_bytes(make_qcow2(QCOW_DATA, version, cluster_bits, comp, zero))
    assert detect(str(p)) == "QCOW2"
    check_image(p, QCOW_DATA, "QCOW2")


def test_qcow2_zero_cluster_hides_backing_data(tmp_path):
    base = disk_payload(len(QCOW_DATA), 77)
    (tmp_path / "base.raw").write_bytes(base)
    p = tmp_path / "overlay.qcow2"
    p.write_bytes(make_qcow2(QCOW_DATA, 3, 16, QCOW_COMPRESSED, QCOW_ZERO, backing="base.raw", backing_fmt="raw"))
    expected = bytearray(QCOW_DATA)
    for c in range(-(-len(QCOW_DATA) // 65536)):
        piece = QCOW_DATA[c * 65536:(c + 1) * 65536]
        if not any(piece) and c not in QCOW_ZERO:          # unallocated here: the backing file shows through
            expected[c * 65536:(c + 1) * 65536] = base[c * 65536:(c + 1) * 65536]
    check_image(p, bytes(expected), "QCOW2")
    # a backing file that is itself a qcow2
    (tmp_path / "base.qcow2").write_bytes(make_qcow2(base, 2, 16))
    p.write_bytes(make_qcow2(QCOW_DATA, 3, 16, QCOW_COMPRESSED, QCOW_ZERO, backing="base.qcow2"))
    check_image(p, bytes(expected), "QCOW2")
    (tmp_path / "base.qcow2").unlink()
    with pytest.raises(NotSupported, match="overlay on “base.qcow2”"):
        open_source(str(p))


def make_qcow1(data: bytes, cluster_bits: int = 12, l2_bits: int = 9, compress=()) -> bytes:
    """The original QCOW: a 48-byte header, the L1 table after it, L2 tables and clusters at cluster boundaries,
    deflated clusters (4 KiB window) at any byte offset, their size in the entry."""
    cs, l2n = 1 << cluster_bits, 1 << l2_bits
    size = len(data)
    l1_size = -(-size // (cs * l2n))
    l1_off = 48
    out = bytearray(-(-(l1_off + 8 * l1_size) // cs) * cs)
    l1 = [0] * l1_size
    l2: dict[int, list[int]] = {}
    for c in range(-(-size // cs)):
        chunk = data[c * cs:(c + 1) * cs].ljust(cs, b"\0")
        if not any(chunk):
            continue
        i = c // l2n
        if i not in l2:
            out += bytes(-len(out) % cs)
            l1[i] = len(out)
            l2[i] = [0] * l2n
            out += bytes(8 * l2n)
        if c in compress:
            co = zlib.compressobj(9, zlib.DEFLATED, -12)
            comp = co.compress(chunk) + co.flush()
            assert len(comp) < cs
            l2[i][c % l2n] = 1 << 63 | len(comp) << (63 - cluster_bits) | len(out)
            out += comp
        else:
            out += bytes(-len(out) % cs)
            l2[i][c % l2n] = len(out)
            out += chunk
    struct.pack_into(">4sIQIIQBBHIQ", out, 0, b"QFI\xfb", 1, 0, 0, 0, size, cluster_bits, l2_bits, 0, 0, l1_off)
    struct.pack_into(f">{l1_size}Q", out, l1_off, *l1)
    for i, table in l2.items():
        struct.pack_into(f">{l2n}Q", out, l1[i], *table)
    return bytes(out)


def test_qcow1(tmp_path):
    p = tmp_path / "old.qcow"
    p.write_bytes(make_qcow1(QCOW_DATA, compress={768, 769, 770}))
    assert detect(str(p)) == "QCOW"
    check_image(p, QCOW_DATA, "QCOW")


# ====================================================================== EWF (E01)
def ewf_section(kind: bytes, offset: int, data: bytes, last: bool = False) -> bytes:
    """A section: its 76-byte descriptor (type, next section, size, Adler-32) and its data. "next" and "done"
    point to themselves and have size 0, as libewf writes them."""
    size = 0 if last else 76 + len(data)
    d = bytearray(76)
    d[:len(kind)] = kind
    struct.pack_into("<QQ", d, 16, offset if last else offset + size, size)
    struct.pack_into("<I", d, 72, zlib.adler32(bytes(d[:72])))
    return bytes(d) + data


def ewf_volume(chunks: int, spc: int, bps: int, sectors: int, guid: bytes) -> bytes:
    v = bytearray(1052)
    v[0] = 1                                   # media type: fixed disk
    struct.pack_into("<IIIQ", v, 4, chunks, spc, bps, sectors)
    v[36] = 1                                  # media flags: physical
    v[52] = 2                                  # compression level: best
    struct.pack_into("<I", v, 56, spc)         # error granularity
    v[64:80] = guid                            # the image's set identifier: the same in every segment
    struct.pack_into("<I", v, 1048, zlib.adler32(bytes(v[:1048])))
    return bytes(v)


def ewf_table(entries: list[int], base: int) -> bytes:
    h = struct.pack("<IIQI", len(entries), 0, base, 0)
    h += struct.pack("<I", zlib.adler32(h))
    e = struct.pack(f"<{len(entries)}I", *entries)
    return h + e + struct.pack("<I", zlib.adler32(e))


def ewf_chunk(chunk: bytes, raw: bool = False) -> tuple[bytes, bool]:
    """A chunk as stored: deflated (zlib) when that is smaller, else as is with its Adler-32 after it."""
    comp = zlib.compress(chunk, 9)
    if not raw and len(comp) < len(chunk):
        return comp, True
    return chunk + struct.pack("<I", zlib.adler32(chunk)), False


def make_e01(data: bytes, folder: Path, name: str = "disk", groups=((0, 40), (40, 70), (70, None)),
             segments=(1, 2, 2), spc: int = 64, errors=(), ext: str = "E") -> list[Path]:
    """An EnCase 6 style image of DATA in segment files NAME.E01, NAME.E02, …: each group of chunks (first, end)
    is a sectors section and its table and table2, in the segment SEGMENTS gives. The first segment has the
    header and volume sections and ends with "next"; the last has a data section, error2 (ERRORS: (first
    sector, count)), hash and "done". Tables of the first segment use absolute offsets (base 0), the others
    offsets relative to their sectors section, as EnCase 6 does."""
    bps = 512
    cs = spc * bps
    nchunks = -(-len(data) // cs)
    nseg = max(segments)
    guid = uuid.uuid4().bytes
    files = []
    for seg in range(1, nseg + 1):
        out = bytearray(EWF_SIG + b"\x01" + struct.pack("<H", seg) + b"\0\0")
        if seg == 1:
            text = "1\nmain\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\n1\tdisk\tRecoverAll\tTester\ttest\t6.1\tLinux\t" \
                   "1700000000\t1700000000\t0\n\n"
            out += ewf_section(b"header", len(out), zlib.compress(text.encode("ascii")))
            out += ewf_section(b"volume", len(out), ewf_volume(nchunks, spc, bps, len(data) // bps, guid))
        else:
            out += ewf_section(b"data", len(out), ewf_volume(nchunks, spc, bps, len(data) // bps, guid))
        for (first, end), where in zip(groups, segments):
            if where != seg:
                continue
            end = nchunks if end is None else min(end, nchunks)
            sectors_at = len(out)
            base = 0 if seg == 1 else sectors_at
            body, entries = bytearray(), []
            for c in range(first, end):
                stored, packed = ewf_chunk(data[c * cs:(c + 1) * cs], raw=c % 7 == 3)
                entries.append((sectors_at + 76 + len(body) - base) | (0x80000000 if packed else 0))
                body += stored
            out += ewf_section(b"sectors", len(out), bytes(body))
            table = ewf_table(entries, base)
            out += ewf_section(b"table", len(out), table)
            out += ewf_section(b"table2", len(out), table)
        if seg == nseg:
            if errors:
                h = struct.pack("<I", len(errors)) + bytes(512)
                h += struct.pack("<I", zlib.adler32(h))
                e = b"".join(struct.pack("<II", s, n) for s, n in errors)
                out += ewf_section(b"error2", len(out), h + e + struct.pack("<I", zlib.adler32(e)))
            md5 = hashlib.md5(data).digest() + bytes(16)
            out += ewf_section(b"hash", len(out), md5 + struct.pack("<I", zlib.adler32(md5)))
            out += ewf_section(b"done", len(out), b"", last=True)
        else:
            out += ewf_section(b"next", len(out), b"", last=True)
        p = folder / f"{name}.{ext}{seg:02d}"
        p.write_bytes(out)
        files.append(p)
    return files


EWF_SIG = b"EVF\x09\x0d\x0a\xff\x00"
E01_DATA = disk_payload(3 * MiB + 21 * 512, 16, holes=[(MiB, 300000)], texty=[(2 * MiB, 100000)])


def test_e01_two_segments(tmp_path):
    files = make_e01(E01_DATA, tmp_path)
    assert [f.name for f in files] == ["disk.E01", "disk.E02"]
    assert detect(str(files[0])) == "E01"
    assert ewf_segments(str(files[1])) == [str(f) for f in files]
    check_image(files[0], E01_DATA, "E01")
    # opening the second segment opens the image from its first
    with open_source(str(files[1])) as src:
        assert src.path == str(files[0]) and src.read(0, 4096) == E01_DATA[:4096]


def test_e01_lowercase_and_chunk_size(tmp_path):
    files = make_e01(E01_DATA, tmp_path, groups=((0, 30), (30, None)), segments=(1, 2), spc=16, ext="e")
    assert files[0].name == "disk.e01"
    check_image(files[0], E01_DATA, "E01")


def test_e01_damaged_parts(tmp_path):
    files = make_e01(E01_DATA, tmp_path, errors=[(100, 8)])
    raw = bytearray(files[1].read_bytes())
    # a damaged table: its copy (table2) is used
    at = raw.index(b"table\0")
    raw[at + 76 + 24 + 8] ^= 0xFF
    files[1].write_bytes(raw)
    with open_source(str(files[0])) as src:
        assert src.read(0, src.size) == E01_DATA
        assert src.bad.ranges() == [(100 * 512, 8 * 512)]    # the sectors the acquisition couldn't read


def test_e01_cut_short(tmp_path):
    # a partial download: the second segment stops in the middle of its last sectors section, before its table
    files = make_e01(E01_DATA, tmp_path)
    raw = files[1].read_bytes()
    last_sectors = raw.rindex(b"sectors\0")
    files[1].write_bytes(raw[:last_sectors + 76 + 20 * 32 * 1024 // 3])
    with open_source(str(files[0])) as src:
        assert src.size == len(E01_DATA)
        data = src.read(0, src.size)
        bad = src.bad.ranges()
        assert len(bad) == 1 and bad[0][0] + bad[0][1] == len(E01_DATA)
        assert bad[0][0] > 70 * 32 * 1024                     # chunks of the cut section were found anyway
        assert data[:bad[0][0]] == E01_DATA[:bad[0][0]] and not any(data[bad[0][0]:])
    # the last segment missing altogether
    files[1].unlink()
    with open_source(str(files[0])) as src:
        assert src.read(0, src.size)[:40 * 32 * 1024] == E01_DATA[:40 * 32 * 1024]
        assert src.bad.ranges() == [(40 * 32 * 1024, len(E01_DATA) - 40 * 32 * 1024)]


# ====================================================================== refused, damaged, raw
def test_refused_with_a_message(tmp_path):
    data = VHD_DATA[:2 * MiB]
    cases = {
        "diff.vhd": (make_vhd(data, parent="C:\\VMs\\base.vhd"), "differencing disk of “C:\\\\VMs\\\\base.vhd”"),
        "diff.vhdx": (make_vhdx(len(data), blocks_of(data, MiB), parent="base.vhdx"), "differencing disk of “base"),
        "snap.vdi": (make_vdi(data, kind=4), "differencing image"),
        "snap.vmdk": (make_vmdk_sparse(data, parent="base.vmdk"), "snapshot .*of “base.vmdk”"),
        "crypt.qcow2": (make_qcow2(data, crypt=1), "encrypted"),
        "sub.qcow2": (make_qcow2(data, incompatible=16), "extended L2"),
        "ext.qcow2": (make_qcow2(data, incompatible=4), "external file"),
        "new.Ex01": (b"EVF2\r\n\x81\x00" + bytes(4096), "EWF2"),
        "files.L01": (b"LVF\x09\x0d\x0a\xff\x00" + bytes(4096), "logical evidence"),
    }
    for name, (content, message) in cases.items():
        p = tmp_path / name
        p.write_bytes(content)
        with pytest.raises(NotSupported, match=message):
            open_source(str(p))
    d = tmp_path / "rdm.vmdk"
    d.write_bytes(vmdk_descriptor("vmfsRawDeviceMap", ['RW 2048 VMFSRDM "rdm-rdmp.vmdk"']))
    with pytest.raises(NotSupported, match="raw device mapping"):
        open_source(str(d))
    d.write_bytes(vmdk_descriptor("custom", ['RW 2048 WHATEVER "x.vmdk"']))
    with pytest.raises(NotSupported, match="type WHATEVER"):
        open_source(str(d))
    d.write_bytes(vmdk_descriptor("monolithicSparse", ['RW 2048 SPARSE "base.vmdk"'], parent="base.vmdk"))
    with pytest.raises(NotSupported, match="snapshot"):
        open_source(str(d))


@pytest.mark.parametrize("kind", ["vhd", "vhdx", "vdi", "vmdk", "qcow2"])
def test_truncated_images_open(tmp_path, kind):
    # a partial download: what made it reads back, the rest is zeros and recorded as unreadable
    data = disk_payload(6 * MiB, 21)
    image = {"vhd": lambda: make_vhd(data), "vhdx": lambda: make_vhdx(len(data), blocks_of(data, MiB)),
             "vdi": lambda: make_vdi(data), "vmdk": lambda: make_vmdk_sparse(data),
             "qcow2": lambda: make_qcow2(data)}[kind]()
    p = tmp_path / f"cut.{kind}"
    p.write_bytes(image[:len(image) * 2 // 3])
    with open_source(str(p)) as src:
        assert src.size == len(data)
        got = src.read(0, src.size)
        assert src.bad.ranges() and src.bad.total < len(data) * 2 // 3
        good = [0] + [o for r in src.bad.ranges() for o in (r[0], r[0] + r[1])] + [len(data)]
        for s, e in zip(good[::2], good[1::2]):
            assert got[s:e] == data[s:e]
        for s, n in src.bad.ranges():
            assert not any(got[s:s + n])


def test_raw_fallback(tmp_path):
    # a raw image that merely has a virtual-disk name, and one whose magic is damaged: plain raw images
    p = tmp_path / "disk.vhd"
    data = disk_payload(MiB, 3)
    p.write_bytes(data)
    assert detect(str(p)) is None
    with open_source(str(p)) as src:
        assert isinstance(src, FileSource) and src.size == MiB and src.read(0, MiB) == data
    q = tmp_path / "broken.vhdx"
    image = bytearray(make_vhdx(2 * MiB, blocks_of(data, MiB)))
    image[:8] = b"VHDXFILE"
    q.write_bytes(image)
    with open_source(str(q)) as src:
        assert isinstance(src, FileSource) and src.size == len(image)
    # the magic is right but nothing else is: a clear error
    q.write_bytes(b"vhdxfile" + bytes(2 * MiB))
    with pytest.raises(FormatError, match="region table"):
        open_source(str(q))
    assert detect(str(tmp_path)) is None and detect(str(tmp_path / "missing.vhd")) is None


def test_detect_needs_few_reads(tmp_path):
    # a raw image is recognized as such from its first 4 KiB and its last sector
    p = tmp_path / "big.img"
    with open(p, "wb") as fh:
        fh.truncate(10 * 1024 * MiB)
    assert detect(str(p)) is None
    with open_source(str(p)) as src:
        assert isinstance(src, FileSource) and src.size == 10 * 1024 * MiB


def test_image_disk_and_guards(tmp_path):
    from recoverall.core.devices import image_disk
    from recoverall.core.fs.tsk import image_args
    from recoverall.core.tools import PROGRAMS
    p = tmp_path / "server.vhdx"
    p.write_bytes(make_vhdx(len(VHDX_DATA), blocks_of(VHDX_DATA, MiB), sector=4096))
    d = image_disk(str(p))
    assert d["format"] == "VHDX" and d["kind"] == "image" and d["size"] == len(VHDX_DATA)
    assert d["display_name"] == "Image (VHDX): server.vhdx" and d["logical_sector"] == 4096
    raw = tmp_path / "plain.img"
    raw.write_bytes(VHDX_DATA)
    d = image_disk(str(raw))
    assert d["format"] == "raw" and d["display_name"] == "Image: plain.img"
    # the image file itself isn't the disk: repairs and tools that read the file are refused
    with pytest.raises(NotSupported, match="VHDX image"):
        check_raw_file(str(p), "Repairing")
    check_raw_file(str(raw), "Repairing")
    with open_source(str(p)) as src, pytest.raises(NotSupported, match="raw image first"):
        image_args(src.region(MiB, MiB))
    assert "ewfmount" not in PROGRAMS and "qemu-nbd" not in PROGRAMS


# ====================================================================== the whole pipeline
FAT_FILES = {"Photos/Holiday photo.png": payload(150_000, 31),
             "Documents/Annual report draft.bin": payload(2 * MiB + 77, 32), "keep.txt": b"keep me\n" * 100}
FAT_DELETED = ["Photos/Holiday photo.png", "Documents/Annual report draft.bin"]


@pytest.fixture(scope="module")
def fat_bytes(tmp_path_factory):
    need("mkfs.fat", "mcopy", "mdel")
    d = tmp_path_factory.mktemp("vfat")
    img = d / "card.img"
    mkfs(img, "fat32", size=64 * MiB, label="VDISK")
    mtools_copy(img, FAT_FILES, d)
    for f in FAT_DELETED:
        mtools_delete(img, f)
    return img.read_bytes()


@pytest.mark.parametrize("kind", ["vhdx", "e01", "vdi"])
def test_quick_scan_inside_image(tmp_path, fat_bytes, kind):
    from recoverall.core.api import LocalAPI, wait_job
    if kind == "vhdx":
        p = tmp_path / "card.vhdx"
        p.write_bytes(make_vhdx(len(fat_bytes), blocks_of(fat_bytes, MiB)))
    elif kind == "vdi":
        p = tmp_path / "card.vdi"
        p.write_bytes(make_vdi(fat_bytes))
    else:
        p = make_e01(fat_bytes, tmp_path, "card", groups=((0, 700), (700, 1500), (1500, None)))[0]
    api = LocalAPI()
    try:
        job = api.start_scan(source=str(p), options={"mode": "quick"})
        done = wait_job(api, job["id"], 120)
        assert done["state"] == "done", done.get("error")
        scan = job["scan"]
        vols = [v for v in api.scan_info(scan=scan)["volumes"] if v["fstype"] != "carved"]
        assert len(vols) == 1 and vols[0]["fstype"] == "fat32" and vols[0]["label"] == "VDISK"
        found = api.scan_search(scan=scan, filters={"deleted": True}, limit=100)["rows"]
        wanted = {f.rsplit("/", 1)[-1]: FAT_FILES[f] for f in FAT_DELETED}
        rows = [r for r in found if r["name"] in wanted]
        assert {r["name"] for r in rows} == set(wanted)
        dest = tmp_path / "out"
        rec = api.start_recover(scan=scan, entries=[r["id"] for r in rows], dest=str(dest), options={})
        res = wait_job(api, rec["id"], 120)
        assert res["state"] == "done", res.get("error")
        for name, content in wanted.items():
            got = list(dest.rglob(name))
            assert got and got[0].read_bytes() == content, name
    finally:
        api.close()


def test_cli_info_and_scan(tmp_path, capsys, fat_bytes):
    from recoverall.cli import main
    p = tmp_path / "card.vdi"
    p.write_bytes(make_vdi(fat_bytes))
    v = tmp_path / "card.vhdx"
    v.write_bytes(make_vhdx(len(fat_bytes), blocks_of(fat_bytes, MiB)))
    assert main(["info", str(v)]) == 0
    out = capsys.readouterr().out
    assert "Image (VHDX): card.vhdx" in out and "Kind         image" in out
    assert main(["--json", "scan", str(p)]) == 0
    res = json.loads(capsys.readouterr().out)
    assert res["scan"] and res["state"] == "done"


# ====================================================================== other implementations
def qemu_img(*args) -> None:
    subprocess.run(["qemu-img", *[str(a) for a in args]], check=True, capture_output=True)


QEMU_CASES = [("vpc", ["-o", "subformat=dynamic"]), ("vpc", ["-o", "subformat=fixed"]), ("vhdx", []),
              ("vhdx", ["-o", "subformat=fixed"]), ("vdi", []), ("vdi", ["-o", "static=on"]), ("vmdk", []),
              ("vmdk", ["-o", "subformat=streamOptimized"]), ("vmdk", ["-o", "subformat=monolithicFlat"]),
              ("vmdk", ["-o", "subformat=twoGbMaxExtentSparse"]), ("qcow2", ["-o", "compat=0.10"]),
              ("qcow2", ["-c"]), ("qcow2", ["-o", "cluster_size=4096"]), ("qcow", [])]


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="qemu-img is not installed")
@pytest.mark.parametrize("fmt,opts", QEMU_CASES)
def test_qemu_img_images(tmp_path, fmt, opts):
    raw = tmp_path / "payload.raw"
    raw.write_bytes(QCOW_DATA)
    out = tmp_path / f"disk.{fmt}"
    qemu_img("convert", "-f", "raw", "-O", fmt, *opts, raw, out)
    with open_source(str(out)) as src:
        assert src.size >= len(QCOW_DATA)          # Virtual PC rounds up to its geometry
        assert src.read(0, len(QCOW_DATA)) == QCOW_DATA
        assert not any(src.read(len(QCOW_DATA), src.size - len(QCOW_DATA)))
        assert not src.bad.ranges()


CROSS_DATA = QCOW_DATA[:4 * MiB] + bytes(MiB) + QCOW_DATA[5 * MiB:]     # with a whole MiB of zeros
# (qemu reads only 512-byte-sector VHDX: the 4 KiB-sector one is checked by test_vhdx alone)
WRITERS = {
    "vpc": lambda d: make_vhd(d), "vpc-fixed": lambda d: make_vhd(d, dynamic=False),
    "vhdx": lambda d: make_vhdx(len(d), blocks_of(d, MiB), states={4: 2}),
    "vdi": lambda d: make_vdi(d), "vdi-fixed": lambda d: make_vdi(d, kind=2),
    "vmdk": lambda d: make_vmdk_sparse(d, zero_grains={g for g in range(len(d) // 65536)
                                                       if not any(d[g * 65536:(g + 1) * 65536])}),
    "vmdk-stream": lambda d: make_vmdk_stream(d),
    "qcow2": lambda d: make_qcow2(d, 3, 16, QCOW_COMPRESSED, QCOW_ZERO),
    "qcow2-v2": lambda d: make_qcow2(d, 2, 12, {768, 769}), "qcow": lambda d: make_qcow1(d, compress={768}),
}


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="qemu-img is not installed")
@pytest.mark.parametrize("kind", sorted(WRITERS))
def test_qemu_img_reads_our_images(tmp_path, kind):
    # the writers above against an independent reader: qemu-img must see the same payload
    fmt = kind.split("-")[0]
    p = tmp_path / f"ours.{fmt}"
    p.write_bytes(WRITERS[kind](CROSS_DATA))
    out = tmp_path / "back.raw"
    qemu_img("convert", "-f", fmt, "-O", "raw", p, out)
    assert out.read_bytes()[:len(CROSS_DATA)] == CROSS_DATA
    if kind.startswith("qcow2"):
        qemu_img("check", p)                       # refcounts and all


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="qemu-img is not installed")
def test_qemu_img_replays_our_vhdx_log(tmp_path):
    p = tmp_path / "crashed.vhdx"
    p.write_bytes(make_vhdx(len(VHDX_DATA), blocks_of(VHDX_DATA, MiB), log_block=4))
    qemu_img("check", "-r", "leaks", p)            # opens it writable: the log is replayed
    out = tmp_path / "back.raw"
    qemu_img("convert", "-O", "raw", p, out)
    assert out.read_bytes() == VHDX_DATA


@pytest.mark.skipif(shutil.which("ewfacquire") is None, reason="ewfacquire (ewf-tools) is not installed")
@pytest.mark.parametrize("fmt,opts", [("encase6", ["-c", "best"]), ("encase5", ["-c", "none"]),
                                      ("ftk", ["-c", "fast", "-b", "128"]), ("smart", ["-c", "best"]),
                                      ("encase1", ["-c", "best"])])
def test_ewfacquire_images(tmp_path, fmt, opts):
    raw = tmp_path / "payload.raw"
    raw.write_bytes(E01_DATA)
    subprocess.run(["ewfacquire", "-u", "-t", tmp_path / "evidence", "-f", fmt, "-S", "1MiB", *opts, raw],
                   check=True, capture_output=True)
    first = sorted(p for p in tmp_path.iterdir() if p.name.startswith("evidence."))[0]
    check_image(first, E01_DATA, "E01")


@pytest.mark.skipif(shutil.which("ewfexport") is None, reason="ewfexport (ewf-tools) is not installed")
def test_ewfexport_reads_our_e01(tmp_path):
    files = make_e01(E01_DATA, tmp_path)
    subprocess.run(["ewfexport", "-u", "-t", tmp_path / "back", "-f", "raw", files[0]], check=True,
                   capture_output=True)
    assert (tmp_path / "back.raw").read_bytes() == E01_DATA
    verify = subprocess.run(["ewfverify", "-q", files[0]], capture_output=True, text=True)
    assert verify.returncode == 0, verify.stdout + verify.stderr
