"""The GUI's link to the API: calls run on worker threads, job events arrive as Qt signals on the GUI
thread, the disk list is polled, and administrator access is requested when something needs it."""

from __future__ import annotations

import json
import logging

from PySide6.QtCore import QObject, QTimer, Signal

from ..core.errors import NotPermitted
from . import worker

log = logging.getLogger(__name__)


class Bridge(QObject):
    disks_changed = Signal(list)
    detail_ready = Signal(dict)
    job_changed = Signal(dict)            # a job's public state
    job_log = Signal(str, list)           # job id, [(n, time, level, text)]
    job_finished = Signal(dict)
    message = Signal(str, str)            # text, kind (success/info/warning/error)
    mode_changed = Signal(str)
    access_needed = Signal()
    _event = Signal(object)

    def __init__(self, api, poll_ms: int = 4000):
        super().__init__()
        self.api = api
        self.mode = getattr(api, "mode", "local")
        self.disks: list[dict] = []
        self.details: dict[str, dict] = {}
        self.jobs: dict[str, dict] = {}
        self.hello: dict = {}
        self._disks_json = ""
        self._pending_detail: set[str] = set()
        self._granting = False
        self._after_grant: list = []
        self._event.connect(self._on_event)
        api.add_listener(self._event.emit)
        self.timer = QTimer(self)
        self.timer.setInterval(poll_ms)
        self.timer.timeout.connect(self.fetch_disks)
        self.closed = False

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.call("hello", done=self._got_hello, error=lambda e: None)
        self.fetch_disks()
        self.timer.start()

    def close(self) -> None:
        self.closed = True
        self.timer.stop()
        try:
            self.api.remove_listener(self._event.emit)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.api.close()
        except Exception:  # noqa: BLE001
            pass
        worker.wait_all(2000)

    def _got_hello(self, h: dict) -> None:
        self.hello = h or {}
        self.mode_changed.emit(self.mode)

    @property
    def privileged(self) -> bool:
        return self.mode in ("root", "helper", "demo")

    @property
    def demo(self) -> bool:
        return self.mode == "demo"

    def switch_api(self, api) -> None:
        old = self.api
        try:
            old.remove_listener(self._event.emit)
        except Exception:  # noqa: BLE001
            pass
        self.api = api
        self.mode = getattr(api, "mode", "local")
        api.add_listener(self._event.emit)
        if old is not api:
            worker.run(old.close, None, lambda e: None)
        self.details.clear()
        self._disks_json = ""
        self.call("hello", done=self._got_hello, error=lambda e: None)
        self.fetch_disks()

    # ------------------------------------------------------------------ calls
    def call(self, method: str, done=None, error=None, success: str | None = None, **params) -> None:
        api = self.api

        def fn():
            return getattr(api, method)(**params)

        def ok(result):
            if success:
                self.message.emit(success, "success")
            if done is not None:
                done(result)

        def fail(exc):
            if isinstance(exc, NotPermitted) and not self.privileged:
                self.access_needed.emit()
            if error is not None:
                error(exc)
            else:
                self.message.emit(str(exc), "error")
        worker.run(fn, ok, fail)

    def fetch_disks(self) -> None:
        if self.closed:
            return

        def got(disks):
            text = json.dumps(disks, sort_keys=True, default=str)
            if text == self._disks_json:
                return
            self._disks_json = text
            self.disks = disks
            for d in disks:
                old = self.details.get(d["path"])
                if old and _layout_key(old) != _layout_key(d):
                    self.details.pop(d["path"], None)
            self.disks_changed.emit(disks)
        self.call("list_disks", done=got, error=lambda e: log.warning("list_disks: %s", e))

    def fetch_detail(self, path: str, refresh: bool = False, done=None) -> None:
        if not refresh and path in self.details:
            if done:
                done(self.details[path])
            return
        if path in self._pending_detail and done is None:
            return
        self._pending_detail.add(path)

        def got(d):
            self._pending_detail.discard(path)
            self.details[d["path"]] = d
            self.detail_ready.emit(d)
            if done:
                done(d)

        def fail(e):
            self._pending_detail.discard(path)
            self.message.emit(f"{path}: {e}", "error")
        self.call("disk_detail", done=got, error=fail, path=path)

    def summary(self, path: str) -> dict | None:
        return self.details.get(path) or next((d for d in self.disks if d["path"] == path), None)

    # ------------------------------------------------------------------ access
    def ensure_access(self, then=None) -> None:
        if self.privileged:
            if then:
                then()
            return
        if then:
            self._after_grant.append(then)
        if self._granting:
            return
        self._granting = True
        from ..core.session import start_helper
        self.message.emit("Asking for administrator rights…", "info")

        def ok(api):
            self._granting = False
            self.switch_api(api)
            self.message.emit("Administrator access granted for this session", "success")
            todo, self._after_grant = self._after_grant, []
            for fn in todo:
                fn()

        def fail(e):
            self._granting = False
            self._after_grant = []
            self.message.emit(f"No access: {e}", "error")
        worker.run(start_helper, ok, fail)

    # ------------------------------------------------------------------ events
    def _on_event(self, ev: dict) -> None:
        t = ev.get("type")
        if t == "job":
            job = ev["job"]
            self.jobs[job["id"]] = job
            self.job_changed.emit(job)
            if job["state"] != "running":
                job = dict(job)
                job["result"] = ev.get("result")
                self.jobs[job["id"]] = job
                self.job_finished.emit(job)
                self.details.clear()
                self._disks_json = ""
                QTimer.singleShot(500, self.fetch_disks)
        elif t == "log":
            self.job_log.emit(ev["job"], ev["lines"])

    def running_jobs(self) -> list[dict]:
        return [j for j in self.jobs.values() if j.get("state") == "running"]


def _layout_key(d: dict) -> str:
    return json.dumps([(p.get("start"), p.get("size"), p.get("fstype"), p.get("uuid"), p.get("mountpoints"))
                       for p in d.get("partitions") or []] + [d.get("size"), d.get("pttype")], default=str)
