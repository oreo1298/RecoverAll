"""Imaging: copy a disk (or a partition, or a virtual RAID) into an image file first, then recover from the
image. The right thing to do with a failing disk — every extra read can be its last — and with anything
you'll scan more than once.

Two engines, same result (a raw image + a mapfile in GNU ddrescue's format, so the image can be resumed,
improved later, or inspected with ddrescueview):

* GNU ddrescue when it is installed (the best at getting data off dying disks);
* RecoverAll's own imager otherwise: a fast first pass that skips around read errors, then the bad areas
  sector by sector, then retries. Stop it any time; starting again continues from the mapfile.
"""

from __future__ import annotations

import os
import re
import time

from .blockio import Source, open_source
from .errors import Cancelled, RallError, ToolMissing
from .util import fmt_bytes, fmt_rate, stream, which

# ddrescue mapfile block states
NON_TRIED, NON_TRIMMED, NON_SCRAPED, BAD, DONE = "?", "*", "/", "-", "+"
STATE_NAMES = {NON_TRIED: "not tried yet", NON_TRIMMED: "failed (to trim)", NON_SCRAPED: "failed (to scrape)",
               BAD: "unreadable", DONE: "copied"}
MAP_CELLS = 1600


class Mapfile:
    """The block list of a ddrescue mapfile: [(pos, size, state)], always covering [0, size)."""

    def __init__(self, size: int, path: str | None = None):
        self.size = size
        self.path = path
        self.blocks: list[list] = [[0, size, NON_TRIED]]
        self.current_pos = 0
        self.current_status = "?"
        self.current_pass = 1

    @classmethod
    def load(cls, path: str, size: int) -> Mapfile:
        m = cls(size, path)
        try:
            with open(path, encoding="ascii", errors="replace") as fh:
                lines = [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
        except OSError:
            return m
        if not lines:
            return m
        head = lines[0].split()
        try:
            m.current_pos = int(head[0], 0)
            m.current_status = head[1] if len(head) > 1 else "?"
            m.current_pass = int(head[2]) if len(head) > 2 else 1
        except (ValueError, IndexError):
            pass
        blocks = []
        for ln in lines[1:]:
            parts = ln.split()
            if len(parts) < 3:
                continue
            try:
                blocks.append([int(parts[0], 0), int(parts[1], 0), parts[2]])
            except ValueError:
                continue
        if blocks:
            m.blocks = blocks
            m.normalise()
        return m

    def normalise(self) -> None:
        """Sorted, merged, clipped to the size, gaps filled as non-tried."""
        out: list[list] = []
        pos = 0
        for b in sorted(self.blocks):
            p, n, st = b
            if p >= self.size or n <= 0:
                continue
            if p > pos:
                out.append([pos, p - pos, NON_TRIED])
            elif p < pos:
                n -= pos - p
                p = pos
                if n <= 0:
                    continue
            n = min(n, self.size - p)
            if out and out[-1][2] == st and out[-1][0] + out[-1][1] == p:
                out[-1][1] += n
            else:
                out.append([p, n, st])
            pos = p + n
        if pos < self.size:
            out.append([pos, self.size - pos, NON_TRIED])
        self.blocks = out

    def set(self, pos: int, size: int, state: str) -> None:
        """Mark [pos, pos+size) with STATE."""
        end = pos + size
        out: list[list] = []
        for p, n, st in self.blocks:
            e = p + n
            if e <= pos or p >= end:
                out.append([p, n, st])
                continue
            if p < pos:
                out.append([p, pos - p, st])
            if e > end:
                out.append([end, e - end, st])
        out.append([pos, size, state])
        self.blocks = out
        self.normalise()

    def save(self, path: str | None = None) -> None:
        path = path or self.path
        if not path:
            return
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="ascii") as fh:
            fh.write("# Mapfile. Created by RecoverAll (GNU ddrescue format)\n")
            fh.write(f"# Command line: recoverall image\n# Start time:   {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            fh.write("# current_pos  current_status  current_pass\n")
            fh.write(f"0x{self.current_pos:08X}     {self.current_status}               {self.current_pass}\n")
            fh.write("#      pos        size  status\n")
            for p, n, st in self.blocks:
                fh.write(f"0x{p:08X}  0x{n:08X}  {st}\n")
        os.replace(tmp, path)

    def total(self, state: str) -> int:
        return sum(n for _p, n, st in self.blocks if st == state)

    def areas(self, *states: str) -> list[tuple[int, int]]:
        return [(p, n) for p, n, st in self.blocks if st in states]

    def cells(self, n: int = MAP_CELLS) -> str:
        """One character per cell: the worst state in it (- bad, / * failed, ? not tried, + copied)."""
        rank = {DONE: 0, NON_TRIED: 1, NON_SCRAPED: 2, NON_TRIMMED: 3, BAD: 4}
        cells = [DONE] * n
        best = [-1] * n
        size = max(1, self.size)
        for p, length, st in self.blocks:
            a = p * n // size
            b = min(n - 1, (p + length - 1) * n // size)
            r = rank.get(st, 1)
            for i in range(a, b + 1):
                if r > best[i]:
                    best[i] = r
                    cells[i] = st
        return "".join(cells)

    def stats(self) -> dict:
        return {"done": self.total(DONE), "nontried": self.total(NON_TRIED), "nontrimmed": self.total(NON_TRIMMED),
                "nonscraped": self.total(NON_SCRAPED), "bad": self.total(BAD), "bad_areas": len(self.areas(BAD)),
                "size": self.size}


# ---------------------------------------------------------------------- RecoverAll's own imager
class Imager:
    def __init__(self, src: Source, dest: str, mapfile: str, job=None, retries: int = 1, chunk: int = 1024 * 1024):
        self.src = src
        self.dest = dest
        self.map = Mapfile.load(mapfile, src.size) if os.path.exists(mapfile) else Mapfile(src.size, mapfile)
        self.map.path = mapfile
        self.job = job
        self.retries = retries
        self.chunk = chunk
        self.sector = src.sector_size or 512
        self.errors = 0
        self.last_save = time.monotonic()
        self.t0 = time.monotonic()
        self.copied_now = 0
        self.last_good = time.monotonic()
        self._dev = self._device()

    def _device(self) -> tuple[int | None, int]:
        """The file descriptor of the device or image under the source (through regions), and the offset."""
        src, base = self.src, 0
        while getattr(src, "parent", None) is not None and hasattr(src, "offset"):
            base += src.offset
            src = src.parent
        fd = getattr(src, "fd", None)
        return (fd, base) if isinstance(fd, int) and fd >= 0 else (None, 0)

    def _raw(self, pos: int, n: int) -> bytes | None:
        """One read straight from the device, without the Source's sector-by-sector fallback: None on error."""
        fd, base = self._dev
        if fd is None:
            # virtual sources (RAID) fill unreadable sectors with zeros and record them
            before = self.src.bad.total
            data = self.src.read(pos, n)
            if self.src.bad.total != before or self.src.bad.overlaps(self.src.base + pos, n):
                self.errors += 1
                return None
            return data
        try:
            data = os.pread(fd, n, base + pos)
        except OSError:
            self.errors += 1
            return None
        if len(data) < n:
            return None
        return data

    def _write(self, out_fd: int, pos: int, data: bytes) -> None:
        if data.count(0) == len(data):
            return                       # leave a hole: the image file is sparse
        os.pwrite(out_fd, data, pos)

    def report(self, phase: str, force: bool = False) -> None:
        now = time.monotonic()
        if now - self.last_save > 5 or force:
            self.map.save()
            self.last_save = now
        if self.job is None:
            return
        st = self.map.stats()
        elapsed = now - self.t0
        rate = self.copied_now / elapsed if elapsed > 1 else None
        left = st["nontried"] + st["nontrimmed"] + st["nonscraped"]
        msg = f"{phase}: {100.0 * st['done'] / max(1, st['size']):.2f} % copied"
        if st["bad"]:
            msg += f" · {fmt_bytes(st['bad'])} unreadable"
        if rate:
            msg += f" · {fmt_rate(rate)}"
        self.job.update(progress=st["done"] / max(1, st["size"]), message=msg, force=force,
                        stats={"done": st["done"], "total": st["size"], "rate": rate,
                               "eta": left / rate if rate else None, "label": "Copied"},
                        imaging={"cells": self.map.cells(), "phase": phase, "errors": self.errors,
                                 "since_good_read": now - self.last_good, **st})

    def run(self) -> dict:
        out_fd = os.open(self.dest, os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            if os.fstat(out_fd).st_size < self.src.size:
                os.ftruncate(out_fd, self.src.size)
            self.copy_pass(out_fd)
            self.scrape_pass(out_fd)
            for i in range(self.retries):
                if not self.map.areas(BAD):
                    break
                self.retry_pass(out_fd, i + 1)
            os.fsync(out_fd)
        finally:
            os.close(out_fd)
            self.map.save()
        self.report("Finished", force=True)
        return self.map.stats()

    def copy_pass(self, out_fd: int) -> None:
        """Forward pass over what was never tried: big reads; on an error, mark the piece as failed and jump
        ahead (further after every error in a row) so a damaged area doesn't eat the time for the rest."""
        skip = 64 * 1024
        for start, length in self.map.areas(NON_TRIED):
            pos = start
            end = start + length
            while pos < end:
                if self.job is not None:
                    self.job.check()
                n = min(self.chunk, end - pos)
                data = self._raw(pos, n)
                if data is not None:
                    self._write(out_fd, pos, data)
                    self.map.set(pos, n, DONE)
                    self.copied_now += n
                    self.last_good = time.monotonic()
                    skip = 64 * 1024
                    pos += n
                else:
                    self.map.set(pos, n, NON_TRIMMED)
                    pos += n
                    jump = min(skip, end - pos)
                    jump -= jump % self.sector
                    pos += jump                  # the skipped part stays "not tried" for the next pass
                    skip = min(skip * 2, max(64 * 1024 * 1024, self.src.size // 1000))
                self.map.current_pos = pos
                self.map.current_status = "?"
                self.report("Copying")
        # what the jumps left out, backwards (ddrescue's second pass does the same)
        for start, length in reversed(self.map.areas(NON_TRIED)):
            pos = start + length
            while pos > start:
                if self.job is not None:
                    self.job.check()
                n = min(self.chunk, pos - start)
                p = pos - n
                data = self._raw(p, n)
                if data is not None:
                    self._write(out_fd, p, data)
                    self.map.set(p, n, DONE)
                    self.copied_now += n
                    self.last_good = time.monotonic()
                else:
                    self.map.set(p, n, NON_TRIMMED)
                pos = p
                self.report("Copying (backwards)")

    def scrape_pass(self, out_fd: int) -> None:
        """The failed pieces, sector by sector."""
        ss = self.sector
        for start, length in self.map.areas(NON_TRIMMED, NON_SCRAPED):
            pos = start
            while pos < start + length:
                if self.job is not None:
                    self.job.check()
                n = min(ss, start + length - pos)
                data = self._raw(pos, n)
                if data is not None:
                    self._write(out_fd, pos, data)
                    self.map.set(pos, n, DONE)
                    self.copied_now += n
                    self.last_good = time.monotonic()
                else:
                    self.map.set(pos, n, BAD)
                pos += n
                self.map.current_status = "/"
                self.report("Reading the bad areas sector by sector")

    def retry_pass(self, out_fd: int, number: int) -> None:
        ss = self.sector
        for start, length in self.map.areas(BAD):
            for pos in range(start, start + length, ss):
                if self.job is not None:
                    self.job.check()
                n = min(ss, start + length - pos)
                data = self._raw(pos, n)
                if data is not None:
                    self._write(out_fd, pos, data)
                    self.map.set(pos, n, DONE)
                    self.copied_now += n
                self.map.current_pass = 2 + number
                self.report(f"Retrying unreadable sectors (pass {number})")


# ---------------------------------------------------------------------- GNU ddrescue
_RESCUED = re.compile(r"rescued:\s*([\d.]+)\s*([kMGTP]?)B")


def ddrescue_available() -> bool:
    return which("ddrescue") is not None


def run_ddrescue(job, src_path: str, dest: str, mapfile: str, size: int, sector: int, retries: int,
                 offset: int = 0, length: int | None = None) -> dict:
    if not ddrescue_available():
        raise ToolMissing("GNU ddrescue is not installed (Arch, Fedora: ddrescue; Debian, Ubuntu, openSUSE: gddrescue)")
    phases = [["--no-scrape"], ["--idirect", f"--retry-passes={retries}"] if os.path.exists(src_path) and
              not os.path.isfile(src_path) else [f"--retry-passes={retries}"]]
    base = ["ddrescue", "--force", "--mapfile-interval=2,10", "--sparse"]
    if sector and sector != 512:
        base.append(f"--sector-size={sector}")
    if offset:
        base += [f"--input-position={offset}", "--output-position=0"]
    if length:
        base.append(f"--size={length}")
    t0 = time.monotonic()
    last = [0.0]

    def publish(phase: str, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - last[0] < 1.0:
            return
        last[0] = now
        m = Mapfile.load(mapfile, size) if os.path.exists(mapfile) else Mapfile(size)
        if offset:
            # ddrescue's mapfile is in input positions
            m.blocks = [[p - offset, n, s] for p, n, s in m.blocks if p + n > offset]
            m.normalise()
        st = m.stats()
        rate = st["done"] / (now - t0) if now - t0 > 2 else None
        job.update(progress=st["done"] / max(1, size), message=f"{phase}: {100.0 * st['done'] / max(1, size):.2f} % copied"
                   + (f" · {fmt_bytes(st['bad'])} unreadable" if st["bad"] else ""), force=force,
                   stats={"done": st["done"], "total": size, "rate": rate, "label": "Copied"},
                   imaging={"cells": m.cells(), "phase": phase, **st})

    for i, extra in enumerate(phases):
        job.check()
        phase = "Copying" if i == 0 else "Trimming, scraping and retrying the bad areas"
        cmd = [*base, *extra, src_path, dest, mapfile]
        job.log("$ " + " ".join(cmd))
        rr = stream(cmd, lambda line: (publish(phase), job.log(f"ddrescue: {line.strip()}")
                                       if line.strip().startswith(("Copying", "Trimming", "Scraping", "Retrying",
                                                                   "Finished", "Interrupted")) else None),
                    cancelled=lambda: job.cancelled)
        if job.cancelled:
            raise Cancelled("Stopped (the mapfile is saved: start again to continue)")
        if rr.returncode != 0:
            raise RallError(f"ddrescue stopped (exit status {rr.returncode}): {rr.error_text(400)}")
    publish("Finished", force=True)
    m = Mapfile.load(mapfile, size + offset)
    return m.stats()


# ---------------------------------------------------------------------- the job
def run_image(job, source_spec, dest: str, options: dict | None = None) -> dict:
    """Image SOURCE_SPEC into DEST (a raw image file) with a mapfile next to it (DEST.map)."""
    o = dict(options or {})
    mapfile = o.get("mapfile") or dest + ".map"
    retries = int(o.get("retries", 1))
    engine = o.get("engine") or "auto"
    src = open_source(source_spec)
    try:
        if os.path.exists(dest) and os.path.isfile(dest) and not os.path.exists(mapfile) and os.path.getsize(dest):
            raise RallError(f"{dest} exists and has no mapfile: choose another name (nothing is overwritten)")
        path = src.path if getattr(src, "path", "") and not hasattr(src, "members") else ""
        use_dd = engine == "ddrescue" or (engine == "auto" and ddrescue_available() and path and
                                          os.path.exists(path) and not os.path.isfile(path))
        job.set_steps(["Copy what reads easily", "Read the bad areas", "Done"])
        job.step(0, f"{'GNU ddrescue' if use_dd else 'RecoverAll imager'} → {dest}")
        job.log(f"Mapfile: {mapfile} (keep it: imaging can be resumed and improved with it)")
        if use_dd:
            stats = run_ddrescue(job, path, dest, mapfile, src.size, src.sector_size, retries, src.base,
                                 src.size if src.base else None)
        else:
            imager = Imager(src, dest, mapfile, job, retries)
            stats = imager.run()
        _give(dest)
        _give(mapfile)
        job.step(2)
        msg = f"Imaged {fmt_bytes(stats.get('done'))}"
        if stats.get("bad"):
            msg += f"; {fmt_bytes(stats['bad'])} unreadable ({stats.get('bad_areas', 0)} areas, zeros in the image)"
        job.update(message=msg, force=True)
        return {"image": dest, "mapfile": mapfile, **stats}
    finally:
        src.close()


def _give(path: str) -> None:
    from .util import give_to_caller
    if os.path.exists(path):
        give_to_caller(path)
