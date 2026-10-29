"""Per-user GUI preferences (``~/.config/recoverall/gui.json``)."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from ..core.config import user_config_dir


@dataclass
class GuiSettings:
    theme: str = "system"
    binary_units: bool = False
    window: dict = field(default_factory=dict)
    recover_folder: str = ""          # where recovered files go (another disk!)
    image_folder: str = ""            # where disk images are saved
    scan_mode: str = "quick"
    keep_paths: bool = True
    restore_times: bool = True
    write_report: bool = True
    repair_after: bool = True         # write repaired copies of recovered files that came back damaged
    show_system: bool = False
    carve_types: list = field(default_factory=lambda: ["photo", "video", "audio", "document", "archive", "email",
                                                       "database", "executable", "other"])
    recent_images: list = field(default_factory=list)
    notify: bool = True
    welcomed: bool = False

    @classmethod
    def load(cls, path: Path | None = None) -> GuiSettings:
        path = path or user_config_dir() / "gui.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in names}) if isinstance(data, dict) else cls()

    def save(self, path: Path | None = None) -> None:
        path = path or user_config_dir() / "gui.json"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".gui-", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(asdict(self), fh, indent=2)
            os.replace(tmp, path)
        except OSError:
            pass
