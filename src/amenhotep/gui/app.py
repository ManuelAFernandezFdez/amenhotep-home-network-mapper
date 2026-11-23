"""GUI entry point (`amenhotep-gui`). Shows a one-time consent notice before first use."""

from __future__ import annotations

import json
import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from amenhotep.core.paths import data_dir, db_path
from amenhotep.gui.branding import app_icon
from amenhotep.gui.main_window import MainWindow

CONSENT_TEXT = (
    "Amenhotep actively probes the devices on your network (ping/ARP sweeps, port scans, "
    "mDNS and SSDP queries).\n\nUse it only on networks you own or are authorised to "
    "administer. Nothing leaves your computer."
)


def consent_given() -> bool:
    f = data_dir() / "settings.json"
    try:
        return bool(json.loads(f.read_text()).get("consent"))
    except (OSError, ValueError):
        return False


def record_consent() -> None:
    f = data_dir() / "settings.json"
    f.write_text(json.dumps({"consent": True}))
    f.chmod(0o600)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Amenhotep")
    app.setDesktopFileName("amenhotep")  # lets Wayland/GNOME match the window to its icon
    app.setWindowIcon(app_icon())
    if not consent_given():
        answer = QMessageBox.question(
            None, "Amenhotep: authorised use only", CONSENT_TEXT + "\n\nDo you accept?"
        )
        if answer != QMessageBox.StandardButton.Yes:
            return 1
        record_consent()
    window = MainWindow(db_path())
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
