"""Run blocking engine/service calls off the GUI thread and deliver results back to it.

``run(fn, done, error)`` executes ``fn()`` on a thread pool; ``done(result)`` or
``error(exc)`` is then called on the GUI thread. The hop back happens through a
queued signal on a QObject that lives in the GUI thread, so plain lambdas are fine
as callbacks. A callback whose widgets were deleted meanwhile is silently skipped.

``SerialQueue`` runs jobs one after another (FIFO): configuration changes must reach the
engine in the order they were made.
"""

from __future__ import annotations

import traceback
from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal


class _Dispatcher(QObject):
    deliver = Signal(object, object)

    def __init__(self) -> None:
        super().__init__()
        self.deliver.connect(self._call, Qt.QueuedConnection)

    @staticmethod
    def _call(fn, arg) -> None:
        if fn is None:
            return
        try:
            fn(arg)
        except RuntimeError as exc:
            # "Internal C++ object already deleted": the requesting widget went away.
            if "already deleted" not in str(exc):
                traceback.print_exc()


_dispatcher: _Dispatcher | None = None


def _get_dispatcher() -> _Dispatcher:
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = _Dispatcher()
    return _dispatcher


class _Job(QRunnable):
    def __init__(self, fn: Callable[[], Any], done, error):
        super().__init__()
        self.setAutoDelete(True)
        self.fn, self.done, self.error = fn, done, error

    def run(self) -> None:
        disp = _get_dispatcher()
        try:
            result = self.fn()
        except Exception as exc:  # noqa: BLE001 - reported to the GUI
            if self.error is None:
                traceback.print_exc()
            disp.deliver.emit(self.error, exc)
            return
        disp.deliver.emit(self.done, result)


_pool: QThreadPool | None = None


def pool() -> QThreadPool:
    global _pool
    if _pool is None:
        _pool = QThreadPool()
        _pool.setMaxThreadCount(12)
        _pool.setExpiryTimeout(30000)
    return _pool


def run(fn: Callable[[], Any], done: Callable[[Any], None] | None = None,
        error: Callable[[Exception], None] | None = None) -> None:
    _get_dispatcher()      # created on the GUI thread before any worker needs it
    pool().start(_Job(fn, done, error))


class SerialQueue:
    """A private one-thread pool: jobs run in submission order."""

    def __init__(self) -> None:
        self._pool = QThreadPool()
        self._pool.setMaxThreadCount(1)
        self._pool.setExpiryTimeout(60000)

    def run(self, fn: Callable[[], Any], done=None, error=None) -> None:
        _get_dispatcher()
        self._pool.start(_Job(fn, done, error))

    def wait(self, msecs: int = 3000) -> None:
        self._pool.waitForDone(msecs)


def wait_all(msecs: int = 3000) -> None:
    if _pool is not None:
        _pool.waitForDone(msecs)
