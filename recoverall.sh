#!/usr/bin/env bash
# Run RecoverAll straight from this folder, without installing it.
# Needs Python 3.10+ and PySide6 (the recovery engines need nothing else, see the README).
#   ./recoverall.sh            # the app
#   ./recoverall.sh --demo     # with simulated disks: nothing touches your hardware
#   ./recoverall.sh --grant    # ask for administrator access right away (pkexec)
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m recoverall "$@"
