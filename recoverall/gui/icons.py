"""Stroke icons drawn for this app (24×24, rendered in the theme's colours).

Same design language as the DiskHealth / AquasuiteLinux / EZP2019Linux / FirmwareLab / ReolinkLinux suite:
24×24 line icons with round caps and joins, tinted at render time to the active palette.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

_PATHS: dict[str, str] = {
    # shared with the suite
    "open": '<path d="M3 7.5A1.5 1.5 0 0 1 4.5 6H9l2 2h8.5A1.5 1.5 0 0 1 21 9.5v9A1.5 1.5 0 0 1 19.5 20h-15A1.5 1.5 0 0 1 3 18.5z"/><path d="M3 11h18"/>',
    "save": '<path d="M5 4h11l4 4v11a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1z"/><path d="M8 4v4.5h7V4"/><rect x="7" y="13" width="10" height="7" rx="1"/>',
    "search": '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m20 20-4.8-4.8"/>',
    "database": '<ellipse cx="12" cy="5.5" rx="7.5" ry="2.8"/><path d="M4.5 5.5v13c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8v-13"/><path d="M4.5 12c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5"/><path d="M12 7.6v.1"/>',
    "cancel": '<circle cx="12" cy="12" r="9"/><path d="m15 9-6 6M9 9l6 6"/>',
    "chip": '<rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9.5" y="9.5" width="5" height="5" rx=".6"/><path d="M9.5 2.5V6M14.5 2.5V6M9.5 18v3.5M14.5 18v3.5M2.5 9.5H6M2.5 14.5H6M18 9.5h3.5M18 14.5h3.5"/>',
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M2.5 12h2M19.5 12h2M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"/>',
    "moon": '<path d="M20 14.6A8.2 8.2 0 0 1 9.4 4a8.2 8.2 0 1 0 10.6 10.6z"/>',
    "log": '<path d="m5 16.5 5-4.5-5-4.5"/><path d="M12.5 18H19"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "minus": '<path d="M5 12h14"/>',
    "trash": '<path d="M4.5 7h15"/><path d="M10 11v5.5M14 11v5.5"/><path d="m6.5 7 .9 11.6a1.6 1.6 0 0 0 1.6 1.4h6a1.6 1.6 0 0 0 1.6-1.4L17.5 7"/><path d="M9.5 7V4.5h5V7"/>',
    "edit": '<path d="M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17z"/><path d="m14.5 7.5 2 2"/>',
    "copy": '<rect x="8.5" y="8.5" width="11.5" height="11.5" rx="1.8"/><path d="M15.5 8.5V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7.5a2 2 0 0 0 2 2h2.5"/>',
    "check": '<path d="m5 12.5 4.5 4.5L19.5 7"/>',
    "warning": '<path d="M10.3 4.4 2.9 17.5A2 2 0 0 0 4.6 20.5h14.8a2 2 0 0 0 1.7-3L13.7 4.4a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4.5"/><path d="M12 17.2v.1"/>',
    "error": '<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5"/><path d="M12 16.3v.1"/>',
    "refresh": '<path d="M20 11.5A8 8 0 0 0 5.6 7.2L4 9"/><path d="M4 4.5V9h4.5"/><path d="M4 12.5a8 8 0 0 0 14.4 4.3L20 15"/><path d="M20 19.5V15h-4.5"/>',
    "import": '<path d="M12 4v10"/><path d="m8 10 4 4 4-4"/><path d="M5 16v2.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V16"/>',
    "export": '<path d="M12 14V4"/><path d="m8 8 4-4 4 4"/><path d="M5 16v2.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V16"/>',
    "chevron_down": '<path d="m6.5 9.5 5.5 5.5 5.5-5.5"/>',
    "chevron_up": '<path d="m6.5 14.5 5.5-5.5 5.5 5.5"/>',
    "shield": '<path d="M12 3.2 19 6v5.6c0 4.3-2.9 7.6-7 9.2-4.1-1.6-7-4.9-7-9.2V6z"/><path d="M12 8.5v4"/><path d="M12 15.6v.1"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/>',
    "menu": '<path d="M4 7h16M4 12h16M4 17h16"/>',
    "more": '<circle cx="5" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="19" cy="12" r="1.3"/>',
    "close": '<path d="M6 6l12 12M18 6 6 18"/>',
    "goto": '<path d="M5 4v6.5A3.5 3.5 0 0 0 8.5 14H19"/><path d="m15 10 4 4-4 4"/>',
    "auto": '<path d="M13.5 2.5 5 13.5h6.5l-1 8 8.5-11h-6.5z"/>',
    "chevron_left": '<path d="m14.5 6.5-5.5 5.5 5.5 5.5"/>',
    "chevron_right": '<path d="m9.5 6.5 5.5 5.5-5.5 5.5"/>',
    "play": '<path d="M7.5 5.2v13.6a.8.8 0 0 0 1.2.7l10.6-6.8a.8.8 0 0 0 0-1.4L8.7 4.5a.8.8 0 0 0-1.2.7z"/>',
    "pause": '<rect x="6.5" y="5" width="3.6" height="14" rx="1"/><rect x="13.9" y="5" width="3.6" height="14" rx="1"/>',
    "stop": '<rect x="6" y="6" width="12" height="12" rx="2"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M19.4 14.6a1.5 1.5 0 0 0 .3 1.6l.1.1a1.8 1.8 0 1 1-2.6 2.6l-.1-.1a1.5 1.5 0 0 0-1.6-.3 1.5 1.5 0 0 0-.9 1.4v.2a1.8 1.8 0 1 1-3.6 0v-.1a1.5 1.5 0 0 0-1-1.4 1.5 1.5 0 0 0-1.6.3l-.1.1a1.8 1.8 0 1 1-2.6-2.6l.1-.1a1.5 1.5 0 0 0 .3-1.6 1.5 1.5 0 0 0-1.4-.9h-.2a1.8 1.8 0 1 1 0-3.6h.1a1.5 1.5 0 0 0 1.4-1 1.5 1.5 0 0 0-.3-1.6l-.1-.1a1.8 1.8 0 1 1 2.6-2.6l.1.1a1.5 1.5 0 0 0 1.6.3h.1a1.5 1.5 0 0 0 .9-1.4v-.2a1.8 1.8 0 1 1 3.6 0v.1a1.5 1.5 0 0 0 .9 1.4 1.5 1.5 0 0 0 1.6-.3l.1-.1a1.8 1.8 0 1 1 2.6 2.6l-.1.1a1.5 1.5 0 0 0-.3 1.6v.1a1.5 1.5 0 0 0 1.4.9h.2a1.8 1.8 0 1 1 0 3.6h-.1a1.5 1.5 0 0 0-1.4.9z"/>',
    "folder": '<path d="M3.5 7.5A1.5 1.5 0 0 1 5 6h4.2l2 2H19a1.5 1.5 0 0 1 1.5 1.5v8A1.5 1.5 0 0 1 19 19H5a1.5 1.5 0 0 1-1.5-1.5z"/>',
    "link": '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    "eye": '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/>',
    "power": '<path d="M12 3.5v8"/><path d="M7 6.5a7 7 0 1 0 10 0"/>',
    "sliders": '<path d="M4 8h8M16 8h4M4 16h4M12 16h8"/><circle cx="14" cy="8" r="2.2"/><circle cx="8" cy="16" r="2.2"/>',
    "wrench": '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.2L4 16.8V20h3.2l5.3-5.3a4 4 0 0 0 5.2-5.4l-2.6 2.6-2.5-.6-.6-2.5z"/>',
    "up": '<path d="m6 14.5 6-6 6 6"/>',
    "down": '<path d="m6 9.5 6 6 6-6"/>',
    "left": '<path d="m14.5 6-6 6 6 6"/>',
    "right": '<path d="m9.5 6 6 6-6 6"/>',
    "home": '<path d="M4 11.5 12 4.5l8 7"/><path d="M6.5 9.5V19a1 1 0 0 0 1 1H10v-5h4v5h2.5a1 1 0 0 0 1-1V9.5"/>',
    "target": '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3.5"/><path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3"/>',
    # cooling
    "fan": '<circle cx="12" cy="12" r="1.8"/><path d="M12 10.2c-.4-3.2.6-6.7 3.3-6.7 2.3 0 3.1 2.9 1.2 4.8-1.3 1.3-3 1.9-4.5 1.9z"/><path d="M13.8 12c3.2-.4 6.7.6 6.7 3.3 0 2.3-2.9 3.1-4.8 1.2-1.3-1.3-1.9-3-1.9-4.5z"/><path d="M12 13.8c.4 3.2-.6 6.7-3.3 6.7-2.3 0-3.1-2.9-1.2-4.8 1.3-1.3 3-1.9 4.5-1.9z"/><path d="M10.2 12c-3.2.4-6.7-.6-6.7-3.3 0-2.3 2.9-3.1 4.8-1.2 1.3 1.3 1.9 3 1.9 4.5z"/>',
    "pump": '<circle cx="11" cy="13.5" r="6.5"/><circle cx="11" cy="13.5" r="2.2"/><path d="M11 7V3.5h7.5M17.5 13.5h3"/>',
    "thermometer": '<path d="M14 14.6V5.5a2 2 0 0 0-4 0v9.1a4 4 0 1 0 4 0z"/><path d="M12 10v6.3"/>',
    "droplet": '<path d="M12 3.5s6 6.3 6 10.5a6 6 0 0 1-12 0c0-4.2 6-10.5 6-10.5z"/><path d="M9.3 14.5a2.8 2.8 0 0 0 2.2 2.4"/>',
    "flow": '<path d="M3 8c3-2 6 2 9 0s6 2 9 0"/><path d="M3 13c3-2 6 2 9 0s6 2 9 0"/><path d="M3 18c3-2 6 2 9 0s6 2 9 0"/>',
    "gauge": '<path d="M4.5 17.5a8.5 8.5 0 1 1 15 0"/><path d="m12 13.5 4-4.5"/><circle cx="12" cy="13.5" r="1.2"/>',
    "curve": '<path d="M4 4v16h16"/><path d="M7 16.5c3 0 4.5-2.5 6.2-5.5S16.5 6 19.5 6"/><circle cx="7" cy="16.5" r=".6"/><circle cx="19.5" cy="6" r=".6"/>',
    "delta": '<path d="M12 4.5 20 19H4z"/>',
    "bell": '<path d="M6 16.5V11a6 6 0 0 1 12 0v5.5l1.5 2h-15z"/><path d="M10 20.5a2 2 0 0 0 4 0"/>',
    "layers": '<path d="m12 4 8.5 4.5L12 13 3.5 8.5z"/><path d="m3.5 12.5 8.5 4.5 8.5-4.5"/><path d="m3.5 16.3 8.5 4.2 8.5-4.2"/>',
    "sensor": '<circle cx="12" cy="12" r="2.3"/><path d="M8 8a5.7 5.7 0 0 0 0 8M16 8a5.7 5.7 0 0 1 0 8M5.2 5.2a9.6 9.6 0 0 0 0 13.6M18.8 5.2a9.6 9.6 0 0 1 0 13.6"/>',
    "service": '<rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/><path d="M8 7.5h.1M8 16.5h.1M12 7.5h4M12 16.5h4"/>',
    "plug": '<path d="M9 3v5M15 3v5"/><path d="M6.5 8h11v3a5.5 5.5 0 0 1-11 0z"/><path d="M12 16.5V21"/>',
    "activity": '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    "overview": '<rect x="3.5" y="3.5" width="7" height="9" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="5" rx="1.5"/><rect x="13.5" y="11.5" width="7" height="9" rx="1.5"/><rect x="3.5" y="15.5" width="7" height="5" rx="1.5"/>',
    "pin": '<path d="M9 3.5h6l-1 5.5 3 3.5H7l3-3.5z"/><path d="M12 12.5V21"/>',
    "chart": '<path d="M4 4v16h16"/><path d="m7 15 3.5-4 3 2.5L19 7"/>',
    "formula": '<path d="M15.5 4.5h-2.3a2 2 0 0 0-2 1.7L9.3 18a2 2 0 0 1-2 1.7H5.5"/><path d="M7.5 10.5h7"/><path d="m14 14 5 5M19 14l-5 5"/>',
    "heat": '<path d="M12 21a5.5 5.5 0 0 0 5.5-5.5c0-3.8-3-5.3-3.5-9.5-2 1.5-3 3.5-3 5.5-1-.5-1.8-1.6-2-3C7.3 10 6.5 12.2 6.5 15.5A5.5 5.5 0 0 0 12 21z"/>',
    "backup": '<path d="M20 11.5A8 8 0 1 0 12 20"/><path d="M12 7.5V12l3 2"/><path d="M17 16v5M14.5 18.5 17 16l2.5 2.5"/>',
    "test": '<path d="M9 3.5h6M10 3.5v6L4.8 18.4A1.4 1.4 0 0 0 6 20.5h12a1.4 1.4 0 0 0 1.2-2.1L14 9.5v-6"/><path d="M7.5 15h9"/>',
    # disks
    "hdd": '<rect x="4" y="3" width="16" height="18" rx="2.2"/><circle cx="12" cy="10" r="4.2"/><circle cx="12" cy="10" r=".8"/><path d="m12.6 10.6 3.4 5.4"/><path d="M7.5 18h1"/>',
    "ssd": '<rect x="3" y="5.5" width="18" height="13" rx="2"/><rect x="6" y="8.5" width="5" height="7" rx=".8"/><rect x="13" y="8.5" width="5" height="3" rx=".6"/><path d="M13 14.5h5"/>',
    "nvme": '<rect x="2" y="8" width="20" height="8" rx="1.4"/><path d="M5 8v8M19 10.5h1M19 13.5h1"/><rect x="7.5" y="10" width="4" height="4" rx=".5"/><rect x="13" y="10" width="4" height="4" rx=".5"/>',
    "usb": '<path d="M12 21V5"/><path d="m9 7.5 3-3.5 3 3.5"/><path d="M12 16.5 7 13.5V10"/><path d="m12 14 5-3V9"/><circle cx="7" cy="9" r="1.2"/><rect x="15.8" y="7" width="2.4" height="2.4" rx=".3"/><circle cx="12" cy="20" r="1.4"/>',
    "flash": '<rect x="7" y="9" width="10" height="13" rx="2"/><path d="M9 9V3h6v6"/><path d="M10.5 5.5h.1M13.5 5.5h.1"/>',
    "sdcard": '<path d="M7.5 3h9a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-11a2 2 0 0 1-2-2V7z"/><path d="M9 3v4M12 3v4M15 3v4"/>',
    "virtual": '<rect x="3.5" y="4" width="17" height="12" rx="1.8"/><path d="M8 20h8M12 16v4"/><path d="m9.5 8.5 2.5 2.5 2.5-2.5"/>',
    "heart": '<path d="M12 20s-7.5-4.6-7.5-10A4.3 4.3 0 0 1 12 7.4 4.3 4.3 0 0 1 19.5 10C19.5 15.4 12 20 12 20z"/><path d="M6.5 12h3l1.5-2.5 2 4.5 1.5-2h3"/>',
    "grid": '<rect x="3.5" y="3.5" width="7" height="7" rx="1"/><rect x="13.5" y="3.5" width="7" height="7" rx="1"/><rect x="3.5" y="13.5" width="7" height="7" rx="1"/><rect x="13.5" y="13.5" width="7" height="7" rx="1"/>',
    "speed": '<path d="M4.5 17.5a8.5 8.5 0 1 1 15 0"/><path d="m12 13.5 5-5"/><circle cx="12" cy="13.5" r="1.2"/><path d="M7 13h1M12 7.5v1M16 13h1"/>',
    "report": '<path d="M7 3h7l5 5v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M14 3v5h5"/><path d="M9 13h6M9 17h4"/>',
    "list": '<path d="M9 6h11M9 12h11M9 18h11"/><path d="M4.5 6h.1M4.5 12h.1M4.5 18h.1"/>',
    "eraser": '<path d="m15.5 4.5 4 4a1.4 1.4 0 0 1 0 2L11 19H7l-3-3a1.4 1.4 0 0 1 0-2l9.5-9.5a1.4 1.4 0 0 1 2 0z"/><path d="m9 9.5 5.5 5.5"/><path d="M11 19h9"/>',
    "key": '<circle cx="8" cy="15" r="4"/><path d="m11 12 8.5-8.5M16.5 6.5l2 2M14 9l2 2"/>',
    "unlock": '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7.5a4 4 0 0 1 7.6-1.7"/><path d="M12 15v2"/>',
    "shield_check": '<path d="M12 3.2 19 6v5.6c0 4.3-2.9 7.6-7 9.2-4.1-1.6-7-4.9-7-9.2V6z"/><path d="m9 12 2.2 2.2L15.5 10"/>',
    "write": '<path d="M12 3v12"/><path d="m8 11 4 4 4-4"/><rect x="4" y="17" width="16" height="4" rx="1"/>',
    "read": '<path d="M12 15V3"/><path d="m8 7 4-4 4 4"/><rect x="4" y="17" width="16" height="4" rx="1"/>',
    "tag": '<path d="M3.5 12.2V4.5a1 1 0 0 1 1-1h7.7l8.3 8.3a1.4 1.4 0 0 1 0 2l-6.7 6.7a1.4 1.4 0 0 1-2 0z"/><circle cx="8" cy="8" r="1.4"/>',
    "moon_sleep": '<path d="M19 14.6A8 8 0 0 1 9.4 5a8 8 0 1 0 9.6 9.6z"/><path d="M15 3h4l-4 4h4"/>',
    # cloning and recovery
    "clone": '<rect x="3" y="3.5" width="12" height="9" rx="1.8"/><path d="M15 9h3.2a1.8 1.8 0 0 1 1.8 1.8v7.4a1.8 1.8 0 0 1-1.8 1.8H8.8A1.8 1.8 0 0 1 7 18.2V12.5"/><path d="M6.5 8h4.5"/><path d="M11.5 16.2h4.5"/>',
    "rescue": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="m5.6 5.6 3.6 3.6M14.8 14.8l3.6 3.6M18.4 5.6l-3.6 3.6M9.2 14.8l-3.6 3.6"/>',
    "archive": '<rect x="3" y="4" width="18" height="4.5" rx="1.2"/><path d="M5 8.5v10a1.5 1.5 0 0 0 1.5 1.5h11a1.5 1.5 0 0 0 1.5-1.5v-10"/><path d="M10 12.5h4"/>',
    "restore": '<path d="M4.5 12a7.5 7.5 0 1 0 2.2-5.3L4.5 8.8"/><path d="M4.5 4.3v4.5H9"/><path d="M12 8.5v3.8l2.8 1.7"/>',
    "arrow_right": '<path d="M5 12h14"/><path d="m13 6 6 6-6 6"/>',
    "arrow_down": '<path d="M12 5v14"/><path d="m6 13 6 6 6-6"/>',
    "calendar": '<rect x="3.5" y="5" width="17" height="15.5" rx="2"/><path d="M3.5 10h17M8 3v4M16 3v4"/>',
    "partition": '<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M9.5 7v10M15 7v10"/>',
    "resize": '<path d="M4 12h16"/><path d="m8 8-4 4 4 4M16 8l4 4-4 4"/>',
    "file_image": '<path d="M7 3h7l5 5v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M14 3v5h5"/><circle cx="12.5" cy="14.5" r="3"/><circle cx="12.5" cy="14.5" r=".6"/>',
    "map": '<path d="M3.5 6.5 9 4l6 2.5 5.5-2.5v13.5L15 20l-6-2.5-5.5 2.5z"/><path d="M9 4v13.5M15 6.5V20"/>',
    "bolt": '<path d="M13.5 2.5 5 13.5h6.5l-1 8 8.5-11h-6.5z"/>',
    # recovery
    "camera": '<path d="M4 8.5A1.5 1.5 0 0 1 5.5 7h2.3l1.4-2h5.6l1.4 2h2.3A1.5 1.5 0 0 1 20 8.5v9a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 17.5z"/><circle cx="12" cy="12.8" r="3.6"/>',
    "photo": '<rect x="3.5" y="4.5" width="17" height="15" rx="2"/><circle cx="9" cy="9.5" r="1.6"/><path d="m4 17.5 5-5 3.5 3.5 2.5-2.5 5 4.5"/>',
    "raid": '<rect x="3.5" y="3.5" width="17" height="5" rx="1.4"/><rect x="3.5" y="9.5" width="17" height="5" rx="1.4"/><rect x="3.5" y="15.5" width="17" height="5" rx="1.4"/><path d="M7 6h.1M7 12h.1M7 18h.1M11 6h6M11 12h6M11 18h6"/>',
    "hex": '<path d="M8 4.5c-2 0-2.5 1-2.5 2.5v2.5c0 1.2-.7 2-2 2.5 1.3.5 2 1.3 2 2.5V17c0 1.5.5 2.5 2.5 2.5"/><path d="M16 4.5c2 0 2.5 1 2.5 2.5v2.5c0 1.2.7 2 2 2.5-1.3.5-2 1.3-2 2.5V17c0 1.5-.5 2.5-2.5 2.5"/><path d="M10 9.5h4M10 14.5h4"/>',
    "lock": '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7.5a4 4 0 0 1 8 0V11"/><path d="M12 15v2"/>',
    "undo": '<path d="M9 14 4.5 9.5 9 5"/><path d="M4.5 9.5H14a5.5 5.5 0 0 1 0 11h-3"/>',
    "scan": '<path d="M4 8V5.5A1.5 1.5 0 0 1 5.5 4H8M16 4h2.5A1.5 1.5 0 0 1 20 5.5V8M20 16v2.5a1.5 1.5 0 0 1-1.5 1.5H16M8 20H5.5A1.5 1.5 0 0 1 4 18.5V16"/><path d="M4 12h16"/>',
    "file": '<path d="M7 3h7l5 5v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M14 3v5h5"/>',
    "file_text": '<path d="M7 3h7l5 5v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M14 3v5h5"/><path d="M9 12.5h6M9 15.5h6M9 18.5h3.5"/>',
    "film": '<rect x="3.5" y="4.5" width="17" height="15" rx="2"/><path d="M7.5 4.5v15M16.5 4.5v15M3.5 9h4M3.5 15h4M16.5 9h4M16.5 15h4"/>',
    "music": '<path d="M9 18V6l10-2v12"/><circle cx="6.5" cy="18" r="2.5"/><circle cx="16.5" cy="16" r="2.5"/>',
    "mail": '<rect x="3.5" y="5.5" width="17" height="13" rx="2"/><path d="m4 7 8 6 8-6"/>',
    "box": '<path d="M12 3.5 20 8v8l-8 4.5L4 16V8z"/><path d="m4 8 8 4.5L20 8M12 12.5v8"/>',
    "app": '<rect x="3.5" y="4.5" width="17" height="15" rx="2"/><path d="M3.5 8.5h17M6.5 6.5h.1M9 6.5h.1"/>',
    "trash_restore": '<path d="M4.5 7h15"/><path d="m6.5 7 .9 11.6a1.6 1.6 0 0 0 1.6 1.4h6a1.6 1.6 0 0 0 1.6-1.4L17.5 7"/><path d="M9.5 7V4.5h5V7"/><path d="M12 17v-6M9.5 13.5 12 11l2.5 2.5"/>',
    "folder_search": '<path d="M3.5 7.5A1.5 1.5 0 0 1 5 6h4.2l2 2H19a1.5 1.5 0 0 1 1.5 1.5v3"/><path d="M3.5 7.5v10A1.5 1.5 0 0 0 5 19h6"/><circle cx="16.5" cy="16" r="3"/><path d="m21 20.5-2.3-2.3"/>',
    "stethoscope": '<path d="M6 3.5v5a4 4 0 0 0 8 0v-5"/><path d="M10 12.5v2a5 5 0 0 0 10 0v-1.5"/><circle cx="20" cy="11" r="2"/>',
}
_PATHS["cpu"] = _PATHS["chip"]
_PATHS["dashboard"] = _PATHS["overview"]


def svg(name: str, color: str, stroke: float = 1.9) -> str:
    body = _PATHS[name]
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
            f'stroke="{color}" stroke-width="{stroke}" stroke-linecap="round" '
            f'stroke-linejoin="round">{body}</svg>')


def _render(svg_text: str, size: int, ratio: float = 2.0) -> QPixmap:
    renderer = QSvgRenderer(QByteArray(svg_text.encode()))
    px = QPixmap(int(size * ratio), int(size * ratio))
    px.fill(Qt.transparent)
    painter = QPainter(px)
    painter.setRenderHint(QPainter.Antialiasing)
    renderer.render(painter, QRectF(0, 0, px.width(), px.height()))
    painter.end()
    px.setDevicePixelRatio(ratio)
    return px


@lru_cache(maxsize=512)
def icon(name: str, color: str, disabled_color: str | None = None, size: int = 24) -> QIcon:
    ic = QIcon()
    ic.addPixmap(_render(svg(name, color), size), QIcon.Normal)
    if disabled_color:
        ic.addPixmap(_render(svg(name, disabled_color), size), QIcon.Disabled)
    return ic


def pixmap(name: str, color: str, size: int = 20) -> QPixmap:
    return _render(svg(name, color), size)


def write_svg_file(directory: Path, name: str, color: str, stroke: float = 2.4) -> Path:
    """Write an icon to disk so style sheets can reference it with url()."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}-{color.lstrip('#')}.svg"
    if not path.exists():
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp.write_text(svg(name, color, stroke), encoding="utf-8")
        os.replace(tmp, path)
    return path
