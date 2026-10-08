"""GUI entry point."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .. import APP_ID, __app_name__, __version__

ICON_PATH = Path(__file__).resolve().parent.parent / "data" / "recoverall.svg"


def _app_icon():
    from PySide6.QtGui import QIcon

    themed = QIcon.fromTheme(APP_ID)
    if not themed.isNull():
        return themed
    if ICON_PATH.exists():
        return QIcon(str(ICON_PATH))
    return QIcon()


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="recoverall",
                                     description=f"{__app_name__}: recover deleted files, lost partitions and photos")
    parser.add_argument("--version", action="version", version=f"{__app_name__} {__version__}")
    parser.add_argument("--demo", action="store_true", help="simulated disks (nothing touches your hardware)")
    parser.add_argument("--grant", action="store_true", help="ask for administrator access at start (pkexec)")
    parser.add_argument("--theme", choices=("system", "dark", "light"), help="override the colour theme")
    parser.add_argument("-v", "--verbose", action="store_true")
    args, qt_args = parser.parse_known_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")

    from PySide6.QtCore import QLockFile, Qt
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtWidgets import QApplication, QMessageBox

    from ..core import session
    from .bridge import Bridge
    from .main_window import MainWindow
    from .settings import GuiSettings
    from .theme import theme

    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    QApplication.setApplicationName("recoverall")
    QApplication.setApplicationDisplayName(__app_name__)
    QApplication.setApplicationVersion(__version__)
    QApplication.setOrganizationName("recoverall")
    QGuiApplication.setDesktopFileName(APP_ID)
    app = QApplication.instance() or QApplication([sys.argv[0], *qt_args])
    icon = _app_icon()
    app.setWindowIcon(icon)

    gs = GuiSettings.load()
    theme.apply(app, args.theme or os.environ.get("RALL_THEME") or gs.theme)
    hints = QGuiApplication.styleHints()
    if hasattr(hints, "colorSchemeChanged"):
        hints.colorSchemeChanged.connect(lambda _s: theme.apply(app) if theme.mode == "system" else None)

    runtime = Path(os.environ.get("XDG_RUNTIME_DIR") or os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    runtime.mkdir(parents=True, exist_ok=True)
    lock = QLockFile(str(runtime / f"recoverall{'-demo' if args.demo else ''}.lock"))
    lock.setStaleLockTime(0)
    if not lock.tryLock(100):
        QMessageBox.information(None, __app_name__, f"{__app_name__} is already running.")
        return 0
    try:
        api = session.local_api(demo=args.demo)
    except Exception as exc:  # noqa: BLE001
        QMessageBox.critical(None, __app_name__, str(exc))
        return 1
    bridge = Bridge(api)
    win = MainWindow(bridge, gs, icon)
    bridge.start()
    win.show()
    if args.grant and not bridge.privileged:
        bridge.ensure_access()
    code = app.exec()
    lock.unlock()
    return code


def main() -> int:
    return run(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
