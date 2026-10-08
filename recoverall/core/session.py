"""How a client gets an API.

* As root (``sudo cnrctl``, or the app started as root): everything in-process.
* As a user: the disks are listed in-process; reading disks (scans, recovery, partition search) goes
  through the helper, which the app starts once per session with pkexec (one password prompt).
* Demo mode: simulated disks and jobs, nothing touches the hardware.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from .api import LocalAPI, RemoteAPI
from .errors import ServiceError
from .ipc import Client
from .util import which

HELPER_PATHS = ("/usr/lib/recoverall/recoverall-helper", "/opt/recoverall/bin/recoverall-helper",
                "/usr/local/lib/recoverall/recoverall-helper")


def local_api(demo: bool = False):
    if demo:
        from .demo import DemoAPI
        return DemoAPI()
    return LocalAPI()


def helper_command() -> list[str]:
    pkexec = which("pkexec")
    if pkexec is None:
        raise ServiceError("pkexec is not installed (package: polkit); run the app with sudo instead")
    for p in HELPER_PATHS:
        if os.access(p, os.X_OK):
            return [pkexec, p, "--stdio"]
    # running from a source tree or a per-user install: start this Python with this package
    root = str(Path(__file__).resolve().parent.parent.parent)
    boot = (f"import sys; sys.path.insert(0, {root!r}); from recoverall.core.helper import main; "
            "sys.exit(main(['--stdio']))")
    return [pkexec, sys.executable, "-c", boot]


def start_helper(timeout: float = 120.0) -> RemoteAPI:
    """Start the root helper through pkexec (the desktop asks for the password)."""
    if os.environ.get("RALL_NO_HELPER") == "1":
        raise ServiceError("The helper is disabled (RALL_NO_HELPER=1)")
    cmd = helper_command()
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    client = Client(proc)
    if not client.wait_ready(timeout):
        client.close()
        code = proc.poll()
        if code in (126, 127):
            raise ServiceError("Authorization was cancelled")
        raise ServiceError("The helper did not start" + (f" (exit status {code})" if code is not None else ""))
    return RemoteAPI(client, "helper")
