# RecoverAll — convenience targets.
# Arch-based distributions: use the PKGBUILD instead (makepkg -si).

PYTHON ?= python3

.PHONY: help run demo install install-user update uninstall test test-root lint gui-check screenshots dist clean

help:
	@echo "RecoverAll make targets:"
	@echo "  make run            Start the app from this folder"
	@echo "  make demo           Start it with simulated disks"
	@echo "  make install        Install system-wide (sudo)"
	@echo "  make install-user   Install for your user only"
	@echo "  make update         git pull and reinstall the same way"
	@echo "  make uninstall      Remove the installation (settings and scans are kept)"
	@echo "  make test           Run the test suite (tests that mount images need root: make test-root)"
	@echo "  make test-root      Run every test as root (loop devices, kernel mounts)"
	@echo "  make lint           Run ruff"
	@echo "  make screenshots    Regenerate docs/screenshots"
	@echo "  make dist           Build a wheel and sdist"

run:
	./recoverall.sh

demo:
	./recoverall.sh --demo

install:
	./packaging/install.sh

install-user:
	./packaging/install.sh --user

update:
	./packaging/update.sh

uninstall:
	./packaging/uninstall.sh

test:
	QT_QPA_PLATFORM=offscreen $(PYTHON) -m pytest -q

test-root:
	sudo QT_QPA_PLATFORM=offscreen $(shell command -v $(PYTHON)) -m pytest -q

lint:
	ruff check recoverall tests tools

gui-check:
	QT_QPA_PLATFORM=offscreen $(PYTHON) -c "from PySide6.QtWidgets import QApplication; \
	app = QApplication([]); from recoverall.core.session import local_api; \
	from recoverall.gui.bridge import Bridge; from recoverall.gui.main_window import MainWindow; \
	from recoverall.gui.settings import GuiSettings; api = local_api(demo=True); \
	w = MainWindow(Bridge(api), GuiSettings()); api.close(); print('GUI OK')"

screenshots:
	for t in dark light; do $(PYTHON) tools/screenshot.py docs/screenshots --theme $$t; done

dist:
	$(PYTHON) -m build

clean:
	rm -rf build dist ./*.egg-info .pytest_cache .ruff_cache src pkg *.pkg.tar.* tests/.fixtures
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
