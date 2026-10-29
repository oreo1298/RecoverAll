#!/usr/bin/env bash
# Install (or update) RecoverAll on any Linux distribution.
#
#   ./packaging/install.sh             system-wide into /opt/recoverall, with the polkit helper (the app asks for
#                                      your password once per session), menu entry and icon. Recommended.
#   ./packaging/install.sh --user      just for you, in ~/.local (the app still needs your password to read
#                                      disks; image files you own work without)
#
# Options:
#   --deps / --no-deps   install Qt and the optional tools with your package manager (default: ask)
#   --minimal            with --deps: only what the app needs (Python, PySide6, polkit), no optional tools
#   --yes                don't ask (installs the dependencies)
#   --python PATH        the Python 3.10+ to use (default: python3)
#
# Running it again updates the installation in place (settings, scans and history are kept).
# Arch-based distributions: the PKGBUILD (makepkg -si) is the better way.
set -euo pipefail

ORIG_ARGS=("$@")
MODE=system
DEPS=ask
MINIMAL=0
YES=0
PY="${PYTHON:-python3}"
while [ $# -gt 0 ]; do
  case "$1" in
    --user) MODE=user ;;
    --system) MODE=system ;;
    --deps) DEPS=yes ;;
    --no-deps) DEPS=no ;;
    --minimal) MINIMAL=1 ;;
    --yes|-y) YES=1; [ "$DEPS" = ask ] && DEPS=yes ;;
    --python) shift; PY="$1" ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)"; exit 2 ;;
  esac
  shift
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ID="io.github.oreo1298.RecoverAll"

say() { printf '\033[1;34m>>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m!!\033[0m %s\n' "$*"; exit 1; }
ask() {
  [ "$YES" = 1 ] && return 0
  [ -t 0 ] || return 1
  read -r -p "$1 [Y/n] " a
  case "${a:-y}" in y|Y|yes) return 0 ;; *) return 1 ;; esac
}

if [ "$MODE" = system ]; then
  if [ "$(id -u)" != 0 ]; then
    command -v sudo >/dev/null || die "Run this as root, or use --user"
    say "The system-wide install needs root; re-running with sudo"
    exec sudo -E bash "$0" "${ORIG_ARGS[@]}"
  fi
  PREFIX=/opt/recoverall
  BIN=/usr/local/bin
  SHARE=/usr/local/share
else
  [ "$(id -u)" = 0 ] && die "--user installs for a normal user; run it without sudo"
  PREFIX="$HOME/.local/lib/recoverall"
  BIN="$HOME/.local/bin"
  SHARE="${XDG_DATA_HOME:-$HOME/.local/share}"
fi
VENV="$PREFIX/venv"
ROOT=""
[ "$(id -u)" != 0 ] && ROOT="sudo"

# ---------------------------------------------------------------------- dependencies
detect_pm() {
  for pm in pacman apt-get dnf zypper xbps-install apk eopkg emerge nix-env; do
    command -v "$pm" >/dev/null && { echo "$pm"; return; }
  done
  echo none
}
PM="$(detect_pm)"

# What the app needs: Python, Qt (PySide6), util-linux, polkit.
base_pkgs() {
  case "$PM" in
    pacman) echo "python pyside6 qt6-svg util-linux polkit" ;;
    apt-get) echo "python3 python3-venv util-linux fdisk pkexec policykit-1 python3-pyside6.qtwidgets python3-pyside6.qtsvg python3-pyside6.qtgui libxcb-cursor0 libegl1 libxkbcommon-x11-0" ;;
    dnf) echo "python3 python3-pyside6 util-linux polkit" ;;
    zypper) echo "python3 python3-pyside6 util-linux polkit" ;;
    xbps-install) echo "python3 python3-pyside6 util-linux polkit" ;;
    apk) echo "python3 py3-pip util-linux sfdisk lsblk blkid losetup polkit" ;;
    eopkg) echo "python3 util-linux polkit" ;;
    emerge) echo "sys-apps/util-linux sys-auth/polkit dev-python/pyside" ;;
    *) echo "" ;;
  esac
}

# Optional tools: imaging failing disks, health, repairs, encrypted volumes, Btrfs, the second engine.
extra_pkgs() {
  case "$PM" in
    pacman) echo "ddrescue smartmontools sleuthkit ffmpeg e2fsprogs dosfstools exfatprogs ntfs-3g xfsprogs btrfs-progs cryptsetup mdadm" ;;
    apt-get) echo "gddrescue smartmontools sleuthkit ffmpeg e2fsprogs dosfstools exfatprogs ntfs-3g xfsprogs btrfs-progs hfsprogs cryptsetup-bin mdadm" ;;
    dnf) echo "ddrescue smartmontools sleuthkit ffmpeg-free e2fsprogs dosfstools exfatprogs ntfs-3g ntfsprogs xfsprogs btrfs-progs hfsplus-tools cryptsetup mdadm" ;;
    zypper) echo "gddrescue smartmontools sleuthkit ffmpeg e2fsprogs dosfstools exfatprogs ntfs-3g ntfsprogs xfsprogs btrfsprogs cryptsetup mdadm" ;;
    xbps-install) echo "ddrescue smartmontools sleuthkit ffmpeg e2fsprogs dosfstools exfatprogs ntfs-3g xfsprogs btrfs-progs cryptsetup mdadm" ;;
    apk) echo "ddrescue smartmontools sleuthkit ffmpeg e2fsprogs e2fsprogs-extra dosfstools exfatprogs ntfs-3g-progs xfsprogs btrfs-progs cryptsetup mdadm" ;;
    eopkg) echo "ddrescue smartmontools ffmpeg e2fsprogs dosfstools exfatprogs ntfs-3g xfsprogs btrfs-progs cryptsetup mdadm" ;;
    emerge) echo "sys-fs/ddrescue sys-apps/smartmontools app-forensics/sleuthkit media-video/ffmpeg sys-fs/e2fsprogs sys-fs/dosfstools sys-fs/exfatprogs sys-fs/ntfs3g sys-fs/xfsprogs sys-fs/btrfs-progs sys-fs/cryptsetup sys-fs/mdadm" ;;
    *) echo "" ;;
  esac
}

pm_install() {
  # install everything at once; if that fails (a package doesn't exist here), one by one
  local pkgs="$*"
  case "$PM" in
    pacman) $ROOT pacman -S --needed --noconfirm $pkgs && return 0 ;;
    apt-get) $ROOT apt-get install -y --no-install-recommends $pkgs && return 0 ;;
    dnf) $ROOT dnf install -y $pkgs && return 0 ;;
    zypper) $ROOT zypper --non-interactive install --no-recommends $pkgs && return 0 ;;
    xbps-install) $ROOT xbps-install -Sy $pkgs && return 0 ;;
    apk) $ROOT apk add $pkgs && return 0 ;;
    eopkg) $ROOT eopkg install -y $pkgs && return 0 ;;
    emerge) $ROOT emerge --noreplace $pkgs && return 0 ;;
  esac
  return 1
}

install_deps() {
  local pkgs
  pkgs="$(base_pkgs)"
  [ "$MINIMAL" = 1 ] || pkgs="$pkgs $(extra_pkgs)"
  if [ -z "$pkgs" ]; then
    warn "Unknown package manager: install PySide6 and polkit (and optionally ddrescue, sleuthkit, the fsck tools and cryptsetup) yourself"
    return
  fi
  if [ "$PM" = nix-env ]; then
    warn "NixOS: add python3Packages.pyside6 and polkit (optional: ddrescue, sleuthkit, smartmontools, e2fsprogs, dosfstools, exfatprogs, ntfs3g, xfsprogs, btrfs-progs, cryptsetup) to your configuration"
    return
  fi
  if [ "$PM" = apt-get ]; then
    $ROOT apt-get update -qq || true
    local avail=""
    for p in $pkgs; do apt-cache show "$p" >/dev/null 2>&1 && avail="$avail $p"; done
    pkgs="$avail"
  fi
  say "Installing dependencies with $PM: $pkgs"
  if ! pm_install $pkgs; then
    warn "Some packages aren't available here; installing the others one by one"
    for p in $pkgs; do pm_install "$p" >/dev/null 2>&1 || warn "  not installed: $p"; done
  fi
}

need=0
command -v pkexec >/dev/null || need=1
command -v ddrescue >/dev/null || [ -x /usr/sbin/ddrescue ] || [ "$MINIMAL" = 1 ] || need=1
if [ "$DEPS" = yes ] || { [ "$DEPS" = ask ] && [ "$need" = 1 ] && ask "Install the dependencies with $PM (Qt, polkit and the optional recovery tools)?"; }; then
  install_deps || warn "Installing dependencies failed; continuing"
elif [ "$need" = 1 ]; then
  warn "Some tools are missing (see: recoverctl doctor). RecoverAll works without them; run with --deps to install them."
fi

# ---------------------------------------------------------------------- Python 3.10+
# RHEL/Alma/Rocky 9 (3.9) and openSUSE Leap 15 (3.6) ship an older python3 next to newer ones.
py_ok() { command -v "$1" >/dev/null && "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; }
pick_python() {
  for c in "$PY" python3 python3.13 python3.12 python3.11 python3.10; do
    if py_ok "$c"; then PY="$c"; return 0; fi
  done
  return 1
}
if ! pick_python; then
  say "Python 3.10 or newer isn't installed; installing Python 3.11 with $PM"
  case "$PM" in
    dnf) $ROOT dnf install -y python3.11 python3.11-pip || true ;;
    zypper) $ROOT zypper --non-interactive install python311 python311-pip || true ;;
    apt-get) $ROOT apt-get install -y python3.11 python3.11-venv || true ;;
    *) : ;;
  esac
  pick_python || die "Python 3.10 or newer is required (found: $(python3 --version 2>&1))"
fi
say "Using $("$PY" --version 2>&1) ($PY)"

# ---------------------------------------------------------------------- the app
say "Installing RecoverAll into $PREFIX"
mkdir -p "$PREFIX"
if [ ! -x "$VENV/bin/python" ]; then
  "$PY" -m venv --system-site-packages "$VENV" || die "Could not create a virtualenv (Debian/Ubuntu: apt install python3-venv)"
fi
"$VENV/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
extras=""
if "$VENV/bin/python" -c "import PySide6.QtWidgets, PySide6.QtSvg" 2>/dev/null; then
  say "Using the PySide6 of your distribution"
else
  say "PySide6 isn't packaged here: installing PySide6-Essentials from PyPI (~100 MB)"
  extras="gui"
fi
# build from a clean copy: pip writes build/ and *.egg-info next to the sources, and a root-owned leftover in
# your clone would break a later per-user install or update
SRC="$(mktemp -d "${TMPDIR:-/tmp}/recoverall-src.XXXXXX")"
trap 'rm -rf "$SRC"' EXIT
tar -C "$HERE" --exclude=./.git --exclude='*.egg-info' --exclude=./build --exclude=./dist --exclude=./.venv \
  --exclude=__pycache__ -cf - . | tar -C "$SRC" -xf -
"$VENV/bin/python" -m pip install --quiet --upgrade --force-reinstall --no-deps "$SRC" >/dev/null
if [ -n "$extras" ]; then
  "$VENV/bin/python" -m pip install --quiet "$SRC[$extras]" || warn "Installing PySide6 failed: the app won't start (recoverctl still works)"
fi

mkdir -p "$PREFIX/bin" "$BIN"
sed "s#^exec recoverall-helper#exec $VENV/bin/recoverall-helper#" "$HERE/packaging/recoverall-helper" > "$PREFIX/bin/recoverall-helper"
chmod 755 "$PREFIX/bin/recoverall-helper"
for exe in recoverall recoverctl; do
  ln -sf "$VENV/bin/$exe" "$BIN/$exe"
done

say "Menu entry and icon"
install -Dm644 "$HERE/recoverall/data/recoverall.svg" "$SHARE/icons/hicolor/scalable/apps/$APP_ID.svg"
mkdir -p "$SHARE/applications"
sed "s#^Exec=recoverall#Exec=$BIN/recoverall#" "$HERE/data/$APP_ID.desktop" > "$SHARE/applications/$APP_ID.desktop"
install -Dm644 "$HERE/data/$APP_ID.metainfo.xml" "$SHARE/metainfo/$APP_ID.metainfo.xml"
command -v update-desktop-database >/dev/null && update-desktop-database -q "$SHARE/applications" 2>/dev/null || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t "$SHARE/icons/hicolor" 2>/dev/null || true

if [ "$MODE" = system ]; then
  say "polkit helper (the app's “Grant access”)"
  if [ -d /usr/share/polkit-1/actions ]; then
    sed "s#/usr/lib/recoverall/recoverall-helper#$PREFIX/bin/recoverall-helper#" \
      "$HERE/packaging/polkit/$APP_ID.policy" > "/usr/share/polkit-1/actions/$APP_ID.policy"
  else
    warn "polkit isn't installed: start the app with sudo, or install polkit (pkexec)"
  fi
  mkdir -p /var/lib/recoverall/scans /var/lib/recoverall/backups /etc/recoverall
  echo "mode=system" > "$PREFIX/.install-info"
  echo "source=$HERE" >> "$PREFIX/.install-info"
else
  echo "mode=user" > "$PREFIX/.install-info"
  echo "source=$HERE" >> "$PREFIX/.install-info"
  case ":$PATH:" in
    *":$BIN:"*) : ;;
    *) warn "Add $BIN to your PATH:  echo 'export PATH=\"$BIN:\$PATH\"' >> ~/.profile" ;;
  esac
fi

echo
say "Done. Start RecoverAll from your application menu, or run: recoverall   (command line: recoverctl)"
"$VENV/bin/python" -c "import PySide6.QtWidgets" 2>/dev/null || warn "PySide6 is missing: only recoverctl will work"
exit 0
