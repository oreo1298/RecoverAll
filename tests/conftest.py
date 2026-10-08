import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_tmp = tempfile.mkdtemp(prefix="rall-tests-")
os.environ["XDG_CONFIG_HOME"] = os.path.join(_tmp, "config")
os.environ["XDG_DATA_HOME"] = os.path.join(_tmp, "data")
os.environ["XDG_CACHE_HOME"] = os.path.join(_tmp, "cache")
os.environ["RALL_STATE_DIR"] = os.path.join(_tmp, "state")
os.environ["RALL_CONFIG_DIR"] = os.path.join(_tmp, "etc")
os.environ["RALL_DEMO_PACE"] = "0.02"          # simulated jobs finish in a second or two
os.environ["RALL_NO_HELPER"] = "1"


class RecordingControl:
    """A Control that records what readers report (and never cancels)."""

    def __init__(self):
        self.messages = []
        self.warnings = []

    def check(self):
        pass

    @property
    def cancelled(self):
        return False

    def progress(self, fraction=None, message=None, **_stats):
        if message:
            self.messages.append(message)

    def log(self, text, level="info"):
        if level == "warning":
            self.warnings.append(text)

    def warn(self, text):
        self.warnings.append(text)


@pytest.fixture
def ctl():
    return RecordingControl()


def make_job():
    from recoverall.core.jobs import Job
    return Job("test", [], "Test", {}, emit=lambda _e: None)


@pytest.fixture
def job():
    return make_job()


def pytest_collection_modifyitems(config, items):
    root = os.geteuid() == 0
    skip = pytest.mark.skip(reason="needs root (loop devices, mounts)")
    for item in items:
        if "root" in item.keywords and not root:
            item.add_marker(skip)
