"""JSON lines between the app and the root helper (the helper's stdin/stdout, started through pkexec).

    request   {"id": 1, "method": "list_sources", "params": {}}
    reply     {"id": 1, "result": ...}      or      {"id": 1, "error": {"type": ..., "message": ...}}
    event     {"event": {...}}              (after a "subscribe" request, pushed at any time)

The helper serves exactly one client — the app that started it — which authenticated through polkit.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import threading
from typing import Callable

from .errors import ERROR_TYPES, NotPermitted, RallError, ServiceError

log = logging.getLogger(__name__)

MAX_LINE = 64 * 1024 * 1024


def _error(exc: Exception) -> dict:
    return {"type": type(exc).__name__, "message": str(exc)}


class Dispatcher:
    """Runs requests against an API object and writes replies/events through ``send``."""

    def __init__(self, api, send: Callable[[dict], None], methods: set[str]):
        self.api = api
        self.send = send
        self.methods = methods
        self.subscribed = False
        self._listener = None

    def handle(self, line: bytes | str) -> None:
        try:
            req = json.loads(line)
            rid = req.get("id")
            method = req.get("method", "")
            params = req.get("params") or {}
            if not isinstance(params, dict):
                raise ValueError("params must be an object")
        except (ValueError, AttributeError):
            self.send({"id": None, "error": {"type": "ProtocolError", "message": "invalid request"}})
            return
        if method not in self.methods:
            self.send({"id": rid, "error": {"type": "ProtocolError", "message": f"unknown method {method}"}})
            return
        if method == "subscribe":
            if not self.subscribed:
                self.subscribed = True
                self._listener = lambda ev: self.send({"event": ev})
                self.api.add_listener(self._listener)
            self.send({"id": rid, "result": True})
            return
        try:
            result = getattr(self.api, method)(**params)
            self.send({"id": rid, "result": result})
        except (RallError, TypeError, ValueError, KeyError, OSError) as exc:
            self.send({"id": rid, "error": _error(exc)})
        except Exception as exc:  # noqa: BLE001 - report instead of dropping the connection
            log.exception("request %s failed", method)
            self.send({"id": rid, "error": _error(exc)})

    def close(self) -> None:
        if self._listener is not None:
            self.api.remove_listener(self._listener)
            self._listener = None


def serve_stdio(api, methods: set[str], infile=None, outfile=None) -> None:
    """The helper: one client on stdin/stdout."""
    inp = infile or sys.stdin.buffer
    out = outfile or sys.stdout.buffer
    lock = threading.Lock()

    def send(obj: dict) -> None:
        data = json.dumps(obj, default=str).encode() + b"\n"
        with lock:
            try:
                out.write(data)
                out.flush()
            except (BrokenPipeError, ValueError, OSError):
                pass

    disp = Dispatcher(api, send, methods)
    send({"event": {"type": "ready"}})
    pending: list[threading.Thread] = []
    try:
        for line in iter(lambda: inp.readline(MAX_LINE), b""):
            if line.strip():
                # every request on its own thread: reading a slow disk must not hold up cancel_job
                t = threading.Thread(target=disp.handle, args=(line,), daemon=True)
                t.start()
                pending = [x for x in pending if x.is_alive()] + [t]
    finally:
        # the client closed its end: answer what it already asked (it may only be reading the replies now)
        for t in pending:
            t.join(60)
        disp.close()


class _Waiter:
    __slots__ = ("event", "reply")

    def __init__(self):
        self.event = threading.Event()
        self.reply: dict | None = None


class Client:
    """The app's end of the pipe to the helper. Thread-safe; events go to subscribed callbacks."""

    def __init__(self, process: subprocess.Popen, timeout: float = 300.0):
        self.process = process
        self.timeout = timeout
        self._rfile = process.stdout
        self._wfile = process.stdin
        self._id = 0
        self._lock = threading.Lock()
        self._waiters: dict[int, _Waiter] = {}
        self._listeners: list[Callable[[dict], None]] = []
        self._subscribed = False
        self._closed = False
        self._ready = threading.Event()
        self.dead = False
        self.on_lost: Callable[[str], None] | None = None
        self._reader = threading.Thread(target=self._read_loop, name="ipc-reader", daemon=True)
        self._reader.start()

    def wait_ready(self, timeout: float) -> bool:
        return self._ready.wait(timeout) and not self.dead

    def _read_loop(self) -> None:
        reason = "the helper stopped"
        try:
            while True:
                line = self._rfile.readline(MAX_LINE)
                if not line:
                    break
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if "event" in msg:
                    ev = msg["event"]
                    if isinstance(ev, dict) and ev.get("type") == "ready":
                        self._ready.set()
                        continue
                    for fn in list(self._listeners):
                        try:
                            fn(ev)
                        except Exception:  # noqa: BLE001
                            log.exception("event callback failed")
                    continue
                w = self._waiters.pop(msg.get("id"), None)
                if w is not None:
                    w.reply = msg
                    w.event.set()
        except (OSError, ValueError) as exc:
            reason = str(exc)
        self.dead = True
        self._ready.set()
        with self._lock:
            waiters = list(self._waiters.values())
            self._waiters.clear()
        for w in waiters:
            w.reply = {"error": {"type": "ServiceError", "message": f"Lost the helper: {reason}"}}
            w.event.set()
        if not self._closed and self.on_lost:
            self.on_lost(reason)

    def close(self) -> None:
        self._closed = True
        try:
            self._wfile.close()
        except OSError:
            pass
        try:
            self.process.wait(10)
        except subprocess.TimeoutExpired:
            self.process.terminate()

    def call(self, method: str, timeout: float | None = None, **params):
        if self.dead:
            raise ServiceError("The administrator helper has stopped: grant access again")
        w = _Waiter()
        with self._lock:
            self._id += 1
            rid = self._id
            self._waiters[rid] = w
            data = json.dumps({"id": rid, "method": method, "params": params}, default=str).encode() + b"\n"
            try:
                self._wfile.write(data)
                self._wfile.flush()
            except (OSError, ValueError) as exc:
                self._waiters.pop(rid, None)
                raise ServiceError(f"Lost the helper: {exc}") from exc
        if not w.event.wait(timeout or self.timeout):
            self._waiters.pop(rid, None)
            raise ServiceError(f"The helper did not answer ({method})")
        reply = w.reply or {}
        if "error" in reply:
            err = reply["error"] or {}
            cls = ERROR_TYPES.get(err.get("type", ""))
            msg = err.get("message", "helper error")
            if cls is not None:
                raise cls(msg)
            if err.get("type") == "PermissionError":
                raise NotPermitted(msg)
            raise ServiceError(msg)
        return reply.get("result")

    def subscribe(self, fn: Callable[[dict], None]) -> None:
        self._listeners.append(fn)
        if not self._subscribed:
            self.call("subscribe")
            self._subscribed = True

    def unsubscribe(self, fn: Callable[[dict], None]) -> None:
        if fn in self._listeners:
            self._listeners.remove(fn)
