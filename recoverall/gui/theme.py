"""Dark and light themes: colour tokens, Qt palette and style sheet.

Uses the palette and style language of the DiskHealth / AquasuiteLinux / EZP2019Linux / FirmwareLab /
ReolinkLinux / CloneAndRecover suite so the applications read as one product, plus what a recovery tool
needs (partition colours for the disk maps, the scan map's colours, file-browser rows, photo grid tiles).
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from string import Template

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontDatabase, QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication

from . import icons


@dataclass(frozen=True)
class Palette:
    name: str
    dark: bool
    window: str
    surface: str
    surface_alt: str
    raised: str
    border: str
    border_strong: str
    text: str
    text_muted: str
    text_faint: str
    accent: str
    accent_hover: str
    accent_pressed: str
    accent_text: str
    accent_soft: str
    success: str
    warning: str
    danger: str
    info: str
    log_bg: str
    chart_bg: str
    grid: str
    c1: str
    c2: str
    c3: str
    c4: str
    c5: str
    c6: str
    cold: str
    hot: str
    orange: str

    def qcolor(self, token: str) -> QColor:
        return QColor(getattr(self, token))

    @property
    def series(self) -> list[str]:
        return [self.c1, self.c2, self.c3, self.c4, self.c5, self.c6]


DARK = Palette(
    name="dark", dark=True,
    window="#0d1015", surface="#141920", surface_alt="#1a2029", raised="#212833",
    border="#222a35", border_strong="#2e3744",
    text="#e8ecf2", text_muted="#9aa4b4", text_faint="#5c6778",
    accent="#5b8cff", accent_hover="#739dff", accent_pressed="#4a78e3", accent_text="#ffffff",
    accent_soft="rgba(91, 140, 255, 0.20)",
    success="#3ddc97", warning="#f5b945", danger="#ff6b6b", info="#5bc0ff",
    log_bg="#0f1318", chart_bg="#10141a", grid="#1f2631",
    c1="#5b8cff", c2="#3ddc97", c3="#f5b945", c4="#ff6b6b", c5="#b18cff", c6="#5bc0ff",
    cold="#5bc0ff", hot="#ff6b6b", orange="#ff9152",
)

LIGHT = Palette(
    name="light", dark=False,
    window="#f2f4f8", surface="#ffffff", surface_alt="#f6f8fb", raised="#edf1f7",
    border="#e2e7ef", border_strong="#cdd5e1",
    text="#17202b", text_muted="#5b6677", text_faint="#9aa4b3",
    accent="#3a6df0", accent_hover="#4c7cf6", accent_pressed="#2e5bd2", accent_text="#ffffff",
    accent_soft="rgba(58, 109, 240, 0.16)",
    success="#11a064", warning="#c47f08", danger="#d64545", info="#1f86d1",
    log_bg="#ffffff", chart_bg="#fbfcfe", grid="#e9edf3",
    c1="#3a6df0", c2="#11a064", c3="#c47f08", c4="#d64545", c5="#7c5ce0", c6="#1f86d1",
    cold="#1f86d1", hot="#d64545", orange="#e2683c",
)

THEMES = {"dark": DARK, "light": LIGHT}


_QSS = Template("""
* { outline: 0; }
QWidget { color: $text; }
QMainWindow, QDialog { background: $window; }
QWidget#Page { background: $window; }
QToolTip { background: $raised; color: $text; border: 1px solid $border_strong;
           border-radius: 6px; padding: 6px 8px; }

QFrame#Card { background: $surface; border: 1px solid $border; border-radius: 12px; }
QFrame#Inset { background: $surface_alt; border: 1px solid $border; border-radius: 10px; }
QFrame#Tile { background: $surface_alt; border: 1px solid $border; border-radius: 10px; }
QFrame#Tile:hover { border-color: $border_strong; }
QFrame#TileAlert { background: $surface_alt; border: 1px solid $danger; border-radius: 10px; }
QFrame#Divider { background: $border; max-height: 1px; min-height: 1px; border: none; }
QLabel#CardTitle { color: $text_muted; font-weight: 700; }
QLabel#Muted { color: $text_muted; }
QLabel#Faint { color: $text_faint; }
QLabel#Value { font-weight: 600; }
QLabel#BigValue { font-weight: 700; }
QLabel#Heading { font-weight: 700; }
QLabel#Title { font-weight: 700; }
QLabel#AppName { font-weight: 800; }
QLabel#Badge { color: $warning; background: transparent; border: 1px solid $warning;
               border-radius: 9px; padding: 1px 8px; }
QLabel#BadgeDevice { color: $success; background: transparent; border: 1px solid $success;
                     border-radius: 8px; padding: 0 7px; font-weight: 700; }
QLabel#BadgeSoftware { color: $accent; background: transparent; border: 1px solid $accent;
                       border-radius: 8px; padding: 0 7px; font-weight: 700; }
QLabel#BadgeIdle { color: $text_faint; background: transparent; border: 1px solid $border_strong;
                   border-radius: 8px; padding: 0 7px; font-weight: 700; }
QLabel#BadgeAlert { color: #ffffff; background: $danger; border: 1px solid $danger;
                    border-radius: 8px; padding: 0 7px; font-weight: 700; }
QLabel#Pill { background: $surface; border: 1px solid $border_strong; border-radius: 15px;
              padding: 5px 12px; }
QLabel#Banner { background: $raised; border: 1px solid $border_strong; border-radius: 8px;
                padding: 8px 10px; }
QLabel#BannerWarn { background: $raised; border: 1px solid $warning; border-radius: 8px;
                    padding: 8px 10px; }
QLabel#Empty { color: $text_faint; }
QLabel#BadgeOk { color: $success; background: transparent; border: 1px solid $success;
                 border-radius: 8px; padding: 0 7px; font-weight: 700; }
QLabel#BadgeWarn { color: $warning; background: transparent; border: 1px solid $warning;
                   border-radius: 8px; padding: 0 7px; font-weight: 700; }
QLabel#BadgeBad { color: #ffffff; background: $danger; border: 1px solid $danger;
                  border-radius: 8px; padding: 0 7px; font-weight: 700; }
QLabel#BadgeInfo { color: $accent; background: transparent; border: 1px solid $accent;
                   border-radius: 8px; padding: 0 7px; font-weight: 700; }
QFrame#DiskItem { background: transparent; border: 1px solid transparent; border-radius: 10px; }
QFrame#DiskItem:hover { background: $raised; }
QFrame#DiskItemSelected { background: $accent_soft; border: 1px solid $accent; border-radius: 10px; }
QFrame#DiskCard { background: $surface; border: 1px solid $border; border-radius: 12px; }
QFrame#DiskCard:hover { border-color: $border_strong; }
QFrame#DiskCardSelected { background: $surface; border: 1px solid $accent; border-radius: 12px; }
QFrame#Choice { background: $surface_alt; border: 1px solid $border; border-radius: 10px; }
QFrame#Choice:hover { border-color: $text_faint; }
QFrame#ChoiceSelected { background: $accent_soft; border: 1px solid $accent; border-radius: 10px; }
QFrame#ChoiceDisabled { background: $surface; border: 1px dashed $border; border-radius: 10px; }
QFrame#Step { background: transparent; border: none; }
QLabel#StepNum { color: $text_muted; background: $raised; border-radius: 12px; font-weight: 700; }
QLabel#StepNumActive { color: $accent_text; background: $accent; border-radius: 12px; font-weight: 700; }
QLabel#StepNumDone { color: $accent_text; background: $success; border-radius: 12px; font-weight: 700; }
QLabel#StepTitle { color: $text_muted; font-weight: 600; }
QLabel#StepTitleActive { color: $text; font-weight: 700; }
QFrame#StepLine { background: $border_strong; max-height: 2px; min-height: 2px; border: none; }
QFrame#JobStep { background: transparent; border: none; border-radius: 8px; }
QFrame#JobStepActive { background: $accent_soft; border: none; border-radius: 8px; }
QLabel#Hero { font-weight: 800; }
QFrame#Finding { background: $surface_alt; border: 1px solid $border; border-radius: 9px; }
QFrame#Result { background: $surface_alt; border: 1px solid $border; border-radius: 10px; }
QFrame#ResultActive { background: $surface_alt; border: 1px solid $accent; border-radius: 10px; }
QLabel#BannerBad { background: $raised; border: 1px solid $danger; border-radius: 8px; padding: 8px 10px; }
QPushButton#BenchButton { background: $accent; color: $accent_text; border: 1px solid $accent; border-radius: 10px;
                          font-weight: 700; padding: 6px 8px; }
QPushButton#BenchButton:hover { background: $accent_hover; }
QPushButton#BenchButton:disabled { background: $raised; border-color: $border; color: $text_faint; }

QToolBar { background: $surface; border: none; border-bottom: 1px solid $border;
           padding: 6px 10px; spacing: 2px; }
QToolBar::separator { background: $border_strong; width: 1px; margin: 10px 8px; }
QToolButton { background: transparent; border: 1px solid transparent; border-radius: 9px;
              padding: 5px 8px; color: $text; }
QToolButton:hover { background: $raised; }
QToolButton:pressed, QToolButton:checked { background: $border_strong; }
QToolButton:disabled { color: $text_faint; }
QToolButton[accent="true"] { background: $accent; color: $accent_text; }
QToolButton[accent="true"]:hover { background: $accent_hover; }
QToolButton[accent="true"]:pressed { background: $accent_pressed; }
QToolButton[accent="true"]:disabled { background: $raised; color: $text_faint; }
QToolButton::menu-indicator { image: none; width: 0; }
QToolButton#Flat { padding: 4px; border-radius: 8px; }
QToolButton#Disclosure { background: transparent; border: none; color: $text_muted; padding: 2px 6px 2px 0;
                         font-weight: 600; }
QToolButton#Disclosure:hover { color: $text; background: transparent; }
QToolButton#Disclosure:checked { background: transparent; color: $text; }
QLabel#EraseNote { color: $danger; font-weight: 600; }
QFrame#Segmented { background: $surface_alt; border: 1px solid $border_strong; border-radius: 9px; }
QToolButton#Segment { border-radius: 7px; padding: 5px 8px; color: $text_muted; font-weight: 600; }
QToolButton#Segment:hover { background: $raised; color: $text; }
QToolButton#Segment:checked { background: $accent; color: $accent_text; }
QToolButton#Segment:disabled { color: $text_faint; }
QToolButton#Segment:checked:disabled { background: $border_strong; color: $text_muted; }
QToolButton#Chip { background: $surface_alt; border: 1px solid $border_strong; border-radius: 12px;
                   padding: 3px 10px; color: $text_muted; font-weight: 600; }
QToolButton#Chip:hover { color: $text; border-color: $text_faint; }
QToolButton#Chip:checked { background: $accent_soft; border-color: $accent; color: $text; }
QToolBarExtension { background: transparent; border-radius: 7px; }

QPushButton { background: $surface_alt; border: 1px solid $border_strong; border-radius: 8px;
              padding: 7px 14px; }
QPushButton:hover { background: $raised; }
QPushButton:pressed { background: $border; }
QPushButton:checked { background: $accent_soft; border-color: $accent; }
QPushButton:disabled { color: $text_faint; border-color: $border; }
QPushButton:default { border-color: $accent; }
QPushButton[variant="primary"] { background: $accent; color: $accent_text; border: 1px solid $accent;
                                 font-weight: 600; }
QPushButton[variant="primary"]:hover { background: $accent_hover; border-color: $accent_hover; }
QPushButton[variant="primary"]:pressed { background: $accent_pressed; }
QPushButton[variant="primary"]:disabled { background: $raised; border-color: $border;
                                          color: $text_faint; }
QPushButton[variant="danger"] { background: transparent; color: $danger; border: 1px solid $danger; }
QPushButton[variant="danger"]:hover { background: $raised; }
QPushButton[variant="ghost"] { background: transparent; border: 1px solid transparent;
                               color: $accent; padding: 4px 8px; }
QPushButton[variant="ghost"]:hover { background: $raised; }

QLineEdit, QComboBox, QAbstractSpinBox {
    background: $surface_alt; border: 1px solid $border_strong; border-radius: 8px;
    padding: 5px 9px; min-height: 20px;
    selection-background-color: $accent; selection-color: $accent_text; }
QLineEdit:hover, QComboBox:hover, QAbstractSpinBox:hover { border-color: $text_faint; }
QLineEdit:focus, QComboBox:focus, QComboBox:on, QAbstractSpinBox:focus { border: 1px solid $accent; }
QLineEdit:disabled, QComboBox:disabled, QAbstractSpinBox:disabled {
    color: $text_faint; background: $surface; border-color: $border; }
QComboBox::drop-down { border: none; width: 24px; subcontrol-origin: padding;
                       subcontrol-position: center right; }
QComboBox::down-arrow { image: url("$chevron"); width: 12px; height: 12px; }
QComboBox::down-arrow:disabled { image: url("$chevron_faint"); }
QComboBox QAbstractItemView { background: $raised; border: 1px solid $border_strong;
    border-radius: 8px; padding: 4px; outline: 0;
    selection-background-color: $accent; selection-color: $accent_text; }
QAbstractSpinBox::up-button, QAbstractSpinBox::down-button { width: 0; border: none; }

QCheckBox, QRadioButton { spacing: 8px; background: transparent; }
QCheckBox:disabled, QRadioButton:disabled { color: $text_faint; }
QCheckBox::indicator { width: 17px; height: 17px; border-radius: 5px;
                       border: 1px solid $border_strong; background: $surface_alt; }
QCheckBox::indicator:hover { border-color: $accent; }
QCheckBox::indicator:checked { background: $accent; border-color: $accent; image: url("$check"); }
QCheckBox::indicator:checked:disabled { background: $border_strong; border-color: $border_strong; }
QRadioButton::indicator { width: 14px; height: 14px; border-radius: 8px;
                          border: 1px solid $border_strong; background: $surface_alt; }
QRadioButton::indicator:hover { border-color: $accent; }
QRadioButton::indicator:checked { width: 6px; height: 6px; border-radius: 8px;
                                  border: 5px solid $accent; background: $accent_text; }

QSlider::groove:horizontal { height: 6px; background: $raised; border-radius: 3px; }
QSlider::sub-page:horizontal { background: $accent; border-radius: 3px; }
QSlider::add-page:horizontal { background: $raised; border-radius: 3px; }
QSlider::handle:horizontal { background: #ffffff; width: 14px; height: 14px; margin: -5px 0;
                             border-radius: 7px; border: 2px solid $accent; }
QSlider::handle:horizontal:hover { background: $raised; }
QSlider::sub-page:horizontal:disabled { background: $border_strong; }
QSlider::handle:horizontal:disabled { background: $border_strong; border-color: $border_strong; }

QProgressBar { background: $raised; border: none; border-radius: 4px; max-height: 8px;
               min-height: 8px; text-align: center; color: transparent; }
QProgressBar::chunk { background: $accent; border-radius: 4px; }
QProgressBar[state="device"]::chunk { background: $success; }
QProgressBar[state="idle"]::chunk { background: $text_faint; }

QScrollBar:vertical { background: transparent; width: 12px; margin: 3px 2px 3px 2px; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 2px 3px 2px 3px; }
QScrollBar::handle { background: $border_strong; border-radius: 4px; }
QScrollBar::handle:vertical { min-height: 32px; }
QScrollBar::handle:horizontal { min-width: 32px; }
QScrollBar::handle:hover { background: $text_faint; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; border: none; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QScrollArea { background: transparent; border: none; }
QScrollArea > QWidget > QWidget { background: transparent; }

QMenuBar { background: $surface; padding: 3px 6px; border-bottom: 1px solid $border; }
QMenuBar::item { padding: 5px 10px; border-radius: 6px; background: transparent; }
QMenuBar::item:selected, QMenuBar::item:pressed { background: $raised; }
QMenu { background: $raised; border: 1px solid $border_strong; border-radius: 10px; padding: 6px; }
QMenu::item { padding: 6px 26px 6px 10px; border-radius: 6px; }
QMenu::item:selected { background: $accent; color: $accent_text; }
QMenu::item:disabled { color: $text_faint; }
QMenu::separator { height: 1px; background: $border_strong; margin: 5px 8px; }
QMenu::icon { padding-left: 8px; }
QMenu::indicator { width: 14px; height: 14px; left: 6px; }

QTreeView, QTableView, QListView { background: $surface; border: none;
    alternate-background-color: $surface_alt;
    selection-background-color: $accent_soft; selection-color: $text; }
QTreeView::item, QTableView::item { padding: 3px 4px; }
QTreeView::item:selected, QTableView::item:selected { background: $accent_soft; color: $text; }
QListView::item { border-radius: 8px; padding: 2px; margin: 1px 0; }
QListView::item:hover { background: $raised; }
QListView::item:selected { background: $accent_soft; color: $text; }
QTreeView::branch { background: transparent; }
QTreeView::indicator, QListView::indicator, QTableView::indicator {
    width: 15px; height: 15px; border-radius: 4px; border: 1px solid $border_strong; background: $surface_alt; }
QTreeView::indicator:hover, QListView::indicator:hover { border-color: $accent; }
QTreeView::indicator:checked, QListView::indicator:checked, QTableView::indicator:checked {
    background: $accent; border-color: $accent; image: url("$check"); }
QHeaderView { background: transparent; }
QHeaderView::section { background: $surface; color: $text_muted; border: none;
    border-bottom: 1px solid $border; padding: 7px 8px; font-weight: 600; }
QTableCornerButton::section { background: $surface; border: none; }

QStatusBar { background: $surface; border-top: 1px solid $border; min-height: 32px; }
QStatusBar::item { border: none; }
QStatusBar QLabel { padding: 0 4px; }

QSplitter::handle { background: transparent; }
QSplitter::handle:vertical { height: 8px; }
QSplitter::handle:horizontal { width: 8px; }

QPlainTextEdit, QTextBrowser { background: $surface; border: none;
    selection-background-color: $accent; selection-color: $accent_text; }
QPlainTextEdit#Log { background: $log_bg; border: 1px solid $border; border-radius: 10px; padding: 6px 10px; }

QGroupBox { border: 1px solid $border; border-radius: 10px; margin-top: 16px; padding: 12px 10px 10px 10px; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; color: $text_muted; }
QTabWidget::pane { border: none; top: -1px; background: transparent; }
QTabBar::tab { background: transparent; padding: 7px 14px; border-radius: 8px; margin: 2px;
               color: $text_muted; font-weight: 600; }
QTabBar::tab:selected { background: $raised; color: $text; }
QTabBar::tab:hover:!selected { color: $text; }
QDialogButtonBox { dialogbuttonbox-buttons-have-icons: 0; }
QDialogButtonBox QPushButton { min-width: 84px; }
""")

_MONO_FAMILIES = ("JetBrains Mono", "Cascadia Mono", "Fira Code", "Source Code Pro",
                  "Hack", "Noto Sans Mono", "DejaVu Sans Mono", "Liberation Mono", "Ubuntu Mono")


def mono_font(point_size: float | None = None) -> QFont:
    families = set(QFontDatabase.families())
    for family in _MONO_FAMILIES:
        if family in families:
            font = QFont(family)
            break
    else:
        font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
    font.setStyleHint(QFont.Monospace)
    font.setFixedPitch(True)
    if point_size:
        font.setPointSizeF(point_size)
    return font


def system_prefers_dark() -> bool:
    hints = QGuiApplication.styleHints()
    scheme = getattr(hints, "colorScheme", None)
    if scheme is not None:
        value = scheme()
        if value == Qt.ColorScheme.Dark:
            return True
        if value == Qt.ColorScheme.Light:
            return False
    window = QGuiApplication.palette().color(QPalette.Window)
    return window.lightness() < 128 if window.isValid() else True


class ThemeManager(QObject):
    """Holds the active palette and notifies widgets when it changes."""

    changed = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self.mode = "system"
        self.palette: Palette = DARK
        cache = os.environ.get("XDG_CACHE_HOME") or os.path.join(Path.home(), ".cache")
        self._asset_dir = Path(cache) / "recoverall" / "theme"

    def resolve(self, mode: str) -> Palette:
        if mode == "system":
            return DARK if system_prefers_dark() else LIGHT
        return THEMES.get(mode, DARK)

    def apply(self, app: QApplication, mode: str | None = None) -> None:
        if mode is not None:
            self.mode = mode
        p = self.resolve(self.mode)
        self.palette = p
        app.setStyle("Fusion")

        qp = QPalette()
        role = QPalette.ColorRole
        qp.setColor(role.Window, QColor(p.window))
        qp.setColor(role.WindowText, QColor(p.text))
        qp.setColor(role.Base, QColor(p.surface_alt))
        qp.setColor(role.AlternateBase, QColor(p.surface))
        qp.setColor(role.Text, QColor(p.text))
        qp.setColor(role.Button, QColor(p.surface_alt))
        qp.setColor(role.ButtonText, QColor(p.text))
        qp.setColor(role.Highlight, QColor(p.accent))
        qp.setColor(role.HighlightedText, QColor(p.accent_text))
        qp.setColor(role.ToolTipBase, QColor(p.raised))
        qp.setColor(role.ToolTipText, QColor(p.text))
        qp.setColor(role.PlaceholderText, QColor(p.text_faint))
        qp.setColor(role.Link, QColor(p.accent))
        qp.setColor(role.Mid, QColor(p.border_strong))
        qp.setColor(role.Dark, QColor(p.border))
        qp.setColor(role.Light, QColor(p.raised))
        for r in (role.WindowText, role.Text, role.ButtonText):
            qp.setColor(QPalette.Disabled, r, QColor(p.text_faint))
        app.setPalette(qp)

        values = {k: v for k, v in p.__dict__.items() if isinstance(v, str)}
        values.update(self._style_assets(p))
        app.setStyleSheet(_QSS.substitute(values))
        self.changed.emit(p)

    def toggle(self, app: QApplication) -> str:
        new = "light" if self.palette.dark else "dark"
        self.apply(app, new)
        return new

    def _style_assets(self, p: Palette) -> dict[str, str]:
        def write(directory: Path) -> dict[str, str]:
            return {
                "chevron": icons.write_svg_file(directory, "chevron_down", p.text_muted),
                "chevron_faint": icons.write_svg_file(directory, "chevron_down", p.text_faint),
                "check": icons.write_svg_file(directory, "check", p.accent_text, 3.0),
            }

        try:
            paths = write(self._asset_dir / p.name)
        except OSError:
            self._asset_dir = Path(tempfile.mkdtemp(prefix="recoverall-theme-"))
            paths = write(self._asset_dir / p.name)
        return {k: v.as_posix() for k, v in paths.items()}

    def icon(self, name: str, color_token: str = "text"):
        p = self.palette
        return icons.icon(name, getattr(p, color_token), p.text_faint)


theme = ThemeManager()
