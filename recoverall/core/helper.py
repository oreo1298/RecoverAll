"""The root helper: started by the app through pkexec, serves the API over stdin/stdout for one session.

    pkexec /usr/lib/recoverall/recoverall-helper      (the app does this when you click "Grant access")
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys

from .api import READ_METHODS, WRITE_METHODS, LocalAPI
from .ipc import serve_stdio


def main(argv: list[str] | None = None) -> int:
    from .. import __version__
    parser = argparse.ArgumentParser(prog="recoverall-helper", description="RecoverAll administrator helper")
    parser.add_argument("--stdio", action="store_true", help="serve one client on stdin/stdout (default)")
    parser.add_argument("--version", action="version", version=f"RecoverAll {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, stream=sys.stderr,
                        format="recoverall-helper %(levelname)s %(name)s: %(message)s")
    if os.geteuid() != 0:
        print("recoverall-helper must run as root (the app starts it through pkexec)", file=sys.stderr)
        return 1
    api = LocalAPI("helper")

    def stop(_sig, _frm):
        api.runner.cancel_all()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)
    try:
        serve_stdio(api, READ_METHODS | WRITE_METHODS)
    finally:
        # the app went away: stop the jobs cleanly (ddrescue saves its mapfile, scans are saved) and clean up
        api.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
