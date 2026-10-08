"""Long operations (scans, recoveries, partition searches, imaging, repairs) as cancellable jobs with progress,
steps and a log.

A job function gets the :class:`Job` and reports as it goes::

    job.set_steps(["Partitions", "Filesystems", "Signatures", ...])
    job.step(1, "Reading the MFT…")
    job.update(progress=0.42, message="…", stats={"done": ..., "total": ..., "rate": ...})
    job.log("Found 12 345 files")
    job.check()                     # raises Cancelled after job.cancel()

Every update is broadcast as ``{"type": "job", "job": {...}}`` (at most a few per second) and log lines
as ``{"type": "log", "job": id, "lines": [...]}``, so the GUI can follow without polling.
"""

from __future__ import annotations

import itertools
import logging
import threading
import time
import traceback
from collections import deque
from typing import Any, Callable

from .errors import Cancelled, RallError

log = logging.getLogger(__name__)
_ids = itertools.count(1)


class Job:
    def __init__(self, kind: str, keys: list[str], title: str, params: dict, emit: Callable[[dict], None]):
        self.id = f"{int(time.time()) % 1000000:06d}-{next(_ids)}"
        self.kind = kind
        self.keys = keys
        self.title = title
        self.params = params
        self.state = "running"          # running, done, failed, cancelled
        self.progress = 0.0
        self.message = "Starting…"
        self.result: Any = None
        self.error = ""
        self.warnings: list[str] = []
        self.started = time.time()
        self.finished: float | None = None
        self.steps: list[dict] = []
        self.current_step = -1
        self.stats: dict = {}
        self.data: dict = {}            # kind-specific live data (the scan map, counts, …)
        self.lines: deque[tuple[float, str, str]] = deque(maxlen=4000)
        self._line_no = 0
        self._cancel = threading.Event()
        self._emit = emit
        self._last_emit = 0.0
        self._pending_lines: list = []
        self._lock = threading.Lock()
        self.thread: threading.Thread | None = None

    # ------------------------------------------------------------------ for job functions
    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def check(self) -> None:
        if self._cancel.is_set():
            raise Cancelled("Cancelled")

    def sleep(self, seconds: float) -> None:
        if self._cancel.wait(seconds):
            raise Cancelled("Cancelled")

    def set_steps(self, titles: list[str]) -> None:
        self.steps = [{"title": t, "state": "pending", "detail": ""} for t in titles]
        self.update(force=True)

    def step(self, index: int, detail: str = "") -> None:
        """Mark step INDEX as running (and the ones before it as done)."""
        for i, s in enumerate(self.steps):
            if i < index and s["state"] in ("pending", "running"):
                s["state"] = "done"
        if 0 <= index < len(self.steps):
            self.steps[index]["state"] = "running"
            if detail:
                self.steps[index]["detail"] = detail
        self.current_step = index
        if 0 <= index < len(self.steps):
            self.log(f"— {self.steps[index]['title']}")
        self.update(force=True)

    def step_done(self, index: int, detail: str = "", state: str = "done") -> None:
        if 0 <= index < len(self.steps):
            self.steps[index]["state"] = state
            if detail:
                self.steps[index]["detail"] = detail
        self.update(force=True)

    def step_detail(self, detail: str) -> None:
        if 0 <= self.current_step < len(self.steps):
            self.steps[self.current_step]["detail"] = detail

    def warn(self, text: str) -> None:
        if text not in self.warnings:
            self.warnings.append(text)
        self.log(text, "warning")

    def log(self, text: str, level: str = "info") -> None:
        now = time.time()
        with self._lock:
            for line in str(text).splitlines() or [""]:
                self._line_no += 1
                entry = (now, level, line)
                self.lines.append(entry)
                self._pending_lines.append((self._line_no, now, level, line))
        log.log(logging.WARNING if level in ("warning", "error") else logging.DEBUG, "[%s] %s", self.id, text)
        self._flush_lines()

    def _flush_lines(self, force: bool = False) -> None:
        with self._lock:
            if not self._pending_lines:
                return
            if not force and len(self._pending_lines) < 50 and time.monotonic() - self._last_emit < 0.3:
                return
            lines, self._pending_lines = self._pending_lines, []
        self._emit({"type": "log", "job": self.id, "lines": lines})

    def update(self, progress: float | None = None, message: str | None = None, force: bool = False,
               stats: dict | None = None, **data) -> None:
        if progress is not None:
            self.progress = max(0.0, min(1.0, progress))
        if message is not None:
            self.message = message
        if stats:
            self.stats.update(stats)
        if data:
            self.data.update(data)
        now = time.monotonic()
        if force or now - self._last_emit >= 0.25:
            self._last_emit = now
            self._flush_lines(force=True)
            self._emit({"type": "job", "job": self.public(with_data=True)})

    # ------------------------------------------------------------------ state
    def public(self, with_data: bool = False) -> dict:
        d = {"id": self.id, "kind": self.kind, "keys": self.keys, "title": self.title, "state": self.state,
             "progress": self.progress, "message": self.message, "error": self.error, "warnings": self.warnings,
             "started": self.started, "finished": self.finished, "params": self.params, "steps": self.steps,
             "step": self.current_step, "stats": self.stats, "line_no": self._line_no}
        if with_data:
            d["data"] = self.data
        return d

    def full(self) -> dict:
        d = self.public(with_data=True)
        d["result"] = self.result
        return d

    def log_since(self, line_no: int = 0) -> list:
        with self._lock:
            entries = list(self.lines)
        first = self._line_no - len(entries) + 1
        return [(first + i, t, lv, text) for i, (t, lv, text) in enumerate(entries) if first + i > line_no]


class JobRunner:
    def __init__(self, emit: Callable[[dict], None] | None = None, on_finish: Callable[[Job], None] | None = None):
        self.jobs: dict[str, Job] = {}
        self._emit = emit or (lambda _e: None)
        self._on_finish = on_finish
        self._lock = threading.Lock()

    def busy(self, keys: list[str]) -> Job | None:
        with self._lock:
            for j in self.jobs.values():
                if j.state == "running" and set(j.keys) & set(keys):
                    return j
        return None

    def start(self, kind: str, keys: list[str], title: str, fn: Callable[[Job], Any], params: dict | None = None) -> Job:
        with self._lock:
            for j in self.jobs.values():
                if j.state == "running" and set(j.keys) & set(keys):
                    raise RallError(f"“{j.title}” is still running on this disk")
            job = Job(kind, list(keys), title, dict(params or {}), self._emit)
            self.jobs[job.id] = job
            done = [j for j in self.jobs.values() if j.state != "running"]
            for old in sorted(done, key=lambda j: j.started)[:-30]:
                self.jobs.pop(old.id, None)

        def body() -> None:
            try:
                job.result = fn(job)
                job.state = "done"
                job.progress = 1.0
                for s in job.steps:
                    if s["state"] in ("running", "pending"):
                        s["state"] = "done" if s["state"] == "running" else s["state"]
                if job.message in ("Starting…", ""):
                    job.message = "Finished"
            except Cancelled:
                job.state = "cancelled"
                job.message = "Cancelled"
                job.log("Cancelled", "warning")
            except RallError as exc:
                job.state, job.error, job.message = "failed", str(exc), str(exc)
                job.log(str(exc), "error")
            except OSError as exc:
                job.state, job.error = "failed", f"{exc.strerror or exc}" + (f": {exc.filename}" if exc.filename else "")
                job.message = job.error
                job.log(job.error, "error")
            except Exception as exc:  # noqa: BLE001 - reported to the user
                log.error("job %s failed:\n%s", job.kind, traceback.format_exc())
                job.state, job.error, job.message = "failed", f"{type(exc).__name__}: {exc}", str(exc)
                job.log(traceback.format_exc(), "error")
            finally:
                if job.state != "done":
                    for s in job.steps:
                        if s["state"] == "running":
                            s["state"] = "failed" if job.state == "failed" else "cancelled"
                job.finished = time.time()
                if self._on_finish:
                    try:
                        self._on_finish(job)
                    except Exception:  # noqa: BLE001
                        log.exception("job finish hook failed")
                job._flush_lines(force=True)
                self._emit({"type": "job", "job": job.public(with_data=True), "result": job.result})

        job.thread = threading.Thread(target=body, name=f"job-{kind}", daemon=True)
        job.thread.start()
        return job

    def cancel(self, job_id: str) -> bool:
        job = self.jobs.get(job_id)
        if job is None or job.state != "running":
            return False
        job._cancel.set()
        job.log("Stopping…", "warning")
        return True

    def cancel_all(self) -> None:
        for j in list(self.jobs.values()):
            j._cancel.set()

    def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    def list(self) -> list[Job]:
        with self._lock:
            return sorted(self.jobs.values(), key=lambda j: j.started)

    def wait(self, job_id: str, timeout: float | None = None) -> Job | None:
        job = self.jobs.get(job_id)
        if job and job.thread:
            job.thread.join(timeout)
        return job

    def running(self) -> list[Job]:
        return [j for j in self.list() if j.state == "running"]


class JobControl:
    """The Control (see fs.base) a job hands to scanners and readers: progress inside [lo, hi] of the job."""

    def __init__(self, job: Job, lo: float = 0.0, hi: float = 1.0, prefix: str = ""):
        self.job = job
        self.lo = lo
        self.hi = hi
        self.prefix = prefix

    def check(self) -> None:
        self.job.check()

    @property
    def cancelled(self) -> bool:
        return self.job.cancelled

    def progress(self, fraction: float | None = None, message: str | None = None, **stats) -> None:
        p = None if fraction is None else self.lo + (self.hi - self.lo) * max(0.0, min(1.0, fraction))
        msg = None if message is None else (self.prefix + message)
        self.job.update(progress=p, message=msg, stats=stats or None)

    def log(self, text: str, level: str = "info") -> None:
        self.job.log(text, level)

    def warn(self, text: str) -> None:
        self.job.warn(text)

    def sub(self, lo: float, hi: float, prefix: str | None = None) -> JobControl:
        """The part [lo, hi] of this control's own range."""
        span = self.hi - self.lo
        return JobControl(self.job, self.lo + span * lo, self.lo + span * hi,
                          self.prefix if prefix is None else prefix)
