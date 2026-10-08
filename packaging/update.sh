#!/usr/bin/env bash
# Update RecoverAll: pull the latest version and reinstall it the same way it was installed.
#   ./packaging/update.sh            (asks for sudo for a system-wide installation)
# Arch package: git pull && makepkg -sif
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
if [ -d .git ]; then
  echo ">> Fetching the latest version"
  if ! git pull --ff-only; then
    echo "!! git pull didn't work (local changes, or no upstream branch): reinstalling the version in this folder"
  fi
fi
if command -v pacman >/dev/null && pacman -Q recoverall >/dev/null 2>&1; then
  exec makepkg -sif
elif [ -f /opt/recoverall/.install-info ]; then
  exec sudo bash "$HERE/packaging/install.sh" --system --no-deps
elif [ -f "$HOME/.local/lib/recoverall/.install-info" ]; then
  exec bash "$HERE/packaging/install.sh" --user --no-deps
else
  echo "No installation found; installing system-wide."
  exec bash "$HERE/packaging/install.sh"
fi
