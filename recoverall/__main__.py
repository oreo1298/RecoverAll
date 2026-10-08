"""``python -m recoverall`` launches the GUI (``python -m recoverall.cli`` for the CLI)."""

import sys

from .gui.app import main

sys.exit(main())
