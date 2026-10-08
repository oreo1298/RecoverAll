"""Where things live: the user's settings, root's scans, partition-table backups, RAID definitions and history."""

from __future__ import annotations

import os
from pathlib import Path

SYSTEM_STATE_DIR = Path("/var/lib/recoverall")
SYSTEM_CONFIG_DIR = Path("/etc/recoverall")


def user_config_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "recoverall"


def user_data_dir() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "recoverall"


def state_dir() -> Path:
    """Root's working folder: scans, partition-table backups, imaging mapfiles, history."""
    if os.environ.get("RALL_STATE_DIR"):
        return Path(os.environ["RALL_STATE_DIR"])
    if os.geteuid() == 0:
        return SYSTEM_STATE_DIR
    return user_data_dir()


def config_dir() -> Path:
    if os.environ.get("RALL_CONFIG_DIR"):
        return Path(os.environ["RALL_CONFIG_DIR"])
    if os.geteuid() == 0:
        return SYSTEM_CONFIG_DIR
    return user_config_dir()


def scans_dir() -> Path:
    return state_dir() / "scans"


def backups_dir() -> Path:
    """Copies of every sector RecoverAll overwrote (partition tables, boot sectors), for Undo."""
    return state_dir() / "backups"


def raid_dir() -> Path:
    return config_dir() / "raid"
