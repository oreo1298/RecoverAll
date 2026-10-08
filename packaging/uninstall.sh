#!/usr/bin/env bash
# Remove an installation made by packaging/install.sh.
#   ./packaging/uninstall.sh                 the system-wide installation (asks for sudo)
#   ./packaging/uninstall.sh --user          the per-user installation
#   --purge                                  also delete settings, saved scans, history and partition-table backups
# Files you recovered and disk images you made are never touched.
# (Arch package: sudo pacman -Rns recoverall)
set -euo pipefail
APP_ID="io.github.oreo1298.RecoverAll"
MODE=system
PURGE=0
for a in "$@"; do
  case "$a" in
    --user) MODE=user ;;
    --system) MODE=system ;;
    --purge) PURGE=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
  esac
done
if [ "$MODE" = system ] && [ ! -d /opt/recoverall ] && [ -d "$HOME/.local/lib/recoverall" ]; then
  MODE=user
fi

if [ "$MODE" = system ]; then
  if [ "$(id -u)" != 0 ]; then exec sudo bash "$0" "$@"; fi
  rm -f "/usr/share/polkit-1/actions/$APP_ID.policy"
  rm -rf /opt/recoverall
  BIN=/usr/local/bin
  SHARE=/usr/local/share
  if [ "$PURGE" = 1 ]; then
    rm -rf /var/lib/recoverall /etc/recoverall
    echo "Removed, with the saved scans, history and partition-table backups (/var/lib/recoverall, /etc/recoverall)."
  else
    echo "Removed. Kept /var/lib/recoverall (saved scans, history, partition-table backups for Undo) and /etc/recoverall; --purge removes them."
  fi
else
  rm -rf "$HOME/.local/lib/recoverall"
  BIN="$HOME/.local/bin"
  SHARE="${XDG_DATA_HOME:-$HOME/.local/share}"
  echo "Removed from ~/.local."
fi
rm -f "$BIN/recoverall" "$BIN/recoverctl" \
      "$SHARE/applications/$APP_ID.desktop" "$SHARE/metainfo/$APP_ID.metainfo.xml" \
      "$SHARE/icons/hicolor/scalable/apps/$APP_ID.svg"
if [ "$PURGE" = 1 ]; then
  for home in "$HOME" ${SUDO_USER:+$(getent passwd "$SUDO_USER" | cut -d: -f6)}; do
    rm -rf "$home/.config/recoverall" "$home/.local/share/recoverall" "$home/.cache/recoverall"
  done
  echo "Your app settings were removed too."
else
  echo "Your app settings (~/.config/recoverall) were kept."
fi
echo "The files you recovered and the disk images you made were not touched."
