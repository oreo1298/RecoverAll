"""The PySide6 app."""

from __future__ import annotations

import sys


def _keep_none_alive() -> bool:
    """Work around PySide6 6.12.0, whose functions that return nothing hand back None without a reference.

    Every such call (setPen, setBrush, update, setText, …) lowers None's reference count by one. Python 3.12
    and later make None immortal, so nothing happens there; on 3.10 and 3.11 the count runs out after a few
    thousand paints and the program aborts ("Fatal Python error: none_dealloc"). When a quick test shows the
    leak, None gets a count no program can use up — what Python 3.12 does. Returns True when applied.
    """
    if sys.version_info >= (3, 12) or hasattr(sys, "getobjects"):   # immortal None / a debug build's layout
        return False
    try:
        from PySide6.QtCore import QRect
    except ImportError:
        return False
    rect = QRect()
    rect.setWidth(1)
    before = sys.getrefcount(None)
    for _ in range(200):
        rect.setWidth(1)
    if sys.getrefcount(None) > before - 150:
        return False                                   # this PySide6 is fine
    import ctypes
    ctypes.c_ssize_t.from_address(id(None)).value += 1 << 40
    return True


NONE_WORKAROUND = _keep_none_alive()
