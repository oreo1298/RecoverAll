"""Video previews: details from the file's own structure and a picture of the first key frame, for videos on
a scanned FAT image (MP4 with its index at the end, MOV with Motion JPEG, Matroska, AVI, an unfinished
recording)."""

import base64

import pytest
from imagekit import MiB, mkfs, mtools_copy, need
from mediakit import cut, make_video

from recoverall.core.api import LocalAPI, wait_job


@pytest.fixture(scope="module")
def video_card(tmp_path_factory):
    need("mkfs.fat", "mcopy")
    d = tmp_path_factory.mktemp("vids")
    clips = {
        "DCIM/CLIP0001.MP4": make_video(d / "a.mp4", "libx264", "aac", seconds=2, size="640x360", fps=30),
        "DCIM/CLIP0002.MOV": make_video(d / "b.mov", "mjpeg", "pcm_s16le", seconds=1),
        "DCIM/CLIP0003.MKV": make_video(d / "c.mkv", "libx264", "aac", seconds=1),
        "DCIM/CLIP0004.AVI": make_video(d / "d.avi", "mpeg4", None, seconds=1),
        "DCIM/HEVC0005.MP4": make_video(d / "e.mp4", "libx265", "aac", seconds=1, vargs=("-tag:v", "hvc1")),
    }
    unfinished = cut(clips["DCIM/CLIP0001.MP4"], d / "u.mp4", 0.6)
    img = mkfs(d / "card.img", "fat32", size=64 * MiB, label="CAM")
    files = {k: v.read_bytes() for k, v in clips.items()}
    files["DCIM/CLIP0006.MP4"] = unfinished.read_bytes()
    mtools_copy(img, files, d)
    return img


def test_video_previews(video_card):
    api = LocalAPI()
    try:
        job = api.start_scan(source=str(video_card), options={"mode": "quick"})
        scan = wait_job(api, job["id"], 120)["result"]["scan"]
        rows = {r["name"]: r for r in api.scan_search(scan=scan, filters={"cats": ["video"]}, limit=50)["rows"]}
        assert len(rows) == 6, rows.keys()

        def show(name):
            return api.preview(scan=scan, entry=rows[name]["id"])
        mp4 = show("CLIP0001.MP4")
        assert mp4["kind"] == "video"
        details = dict(mp4["details"])
        assert details["Length"] == "0:02" and details["Picture"] == "640 × 360 · 30 fps"
        assert details["Video"] == "H.264" and details["Sound"].startswith("AAC stereo")
        assert base64.b64decode(mp4["data"])[:3] == b"\xff\xd8\xff"          # decoded by ffmpeg
        hevc = show("HEVC0005.MP4")
        assert dict(hevc["details"])["Video"] == "H.265 (HEVC)" and hevc["data"]
        mjpeg = show("CLIP0002.MOV")                                         # a frame as it is
        assert dict(mjpeg["details"])["Video"] == "Motion JPEG" and base64.b64decode(mjpeg["data"])[:2] == b"\xff\xd8"
        for name in ("CLIP0003.MKV", "CLIP0004.AVI"):                        # streamable: ffmpeg on the start
            p = show(name)
            assert p["kind"] == "video" and p["data"], name
        unfinished = show("CLIP0006.MP4")
        assert "index is missing" in unfinished["note"] and unfinished["data"] is None
        thumbs = api.thumbnails(scan=scan, entries=[rows["CLIP0001.MP4"]["id"], rows["CLIP0002.MOV"]["id"]])
        assert all(t.get("data") for t in thumbs.values())
    finally:
        api.close()


def test_ffmpeg_runs_unprivileged(monkeypatch):
    """As root, ffmpeg gets the desktop user's ids (or nobody's), never root's."""
    from recoverall.core import videopreview as vp
    monkeypatch.setattr(vp.os, "geteuid", lambda: 0)
    monkeypatch.setenv("PKEXEC_UID", "1234")
    kw = vp._unprivileged()
    assert kw["user"] == 1234 and kw["extra_groups"] == []
    monkeypatch.delenv("PKEXEC_UID")
    monkeypatch.delenv("SUDO_UID", raising=False)
    assert vp._unprivileged()["user"] == 65534
    # garbage never becomes a picture
    assert vp.ffmpeg_frame(b"\x00" * 5000, "h264") is None
