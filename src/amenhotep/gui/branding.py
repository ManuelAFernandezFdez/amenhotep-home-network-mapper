"""Logo, app icon, header banner and About dialog."""

from __future__ import annotations

from importlib import resources
from typing import Any

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from amenhotep import __version__

GOLD = "#e9b44c"
BACKGROUND = "#2a2a2a"
TAGLINE = "Nothing stays hidden from Amun."
EXPANSION = "Appliance Mapping & Enumeration of Network Hardware, Over Thread, Ethernet & Protocols"


def _data_path(name: str) -> str:
    return str(resources.files("amenhotep.data").joinpath(name))


def app_icon() -> QIcon:
    return QIcon(_data_path("logo.svg"))


def logo_pixmap(height: int, wordmark: bool = False) -> QPixmap:
    icon = QIcon(_data_path("logo-wordmark.svg" if wordmark else "logo.svg"))
    width = round(height * 760 / 256) if wordmark else height
    return icon.pixmap(QSize(width, height))


class HeaderBar(QWidget):
    """Slim branded strip shown above the tabs. Colours are fixed so it matches the logo."""

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self.setObjectName("amenhotepHeader")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)  # paint the stylesheet bg
        self.setStyleSheet(
            f"#amenhotepHeader {{ background: {BACKGROUND}; }}"
            f"#amenhotepTitle {{ color: {GOLD}; font: bold 20px 'Georgia', serif; }}"
            "#amenhotepTagline { color: #f2f2f2; font-size: 12px; }"
        )
        self.logo = QLabel()
        self.logo.setPixmap(logo_pixmap(44))
        self.title = QLabel("Amenhotep")
        self.title.setObjectName("amenhotepTitle")
        self.tagline = QLabel(TAGLINE)
        self.tagline.setObjectName("amenhotepTagline")
        for label in (self.title, self.tagline):
            label.setTextFormat(Qt.TextFormat.PlainText)
        text = QVBoxLayout()
        text.setSpacing(0)
        text.addWidget(self.title)
        text.addWidget(self.tagline)
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 6, 12, 6)
        row.addWidget(self.logo)
        row.addLayout(text)
        row.addStretch(1)
        self.setFixedHeight(56)


class AboutDialog(QDialog):
    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("About Amenhotep")
        self.setStyleSheet(f"QDialog {{ background: {BACKGROUND}; }} QLabel {{ color: #f2f2f2; }}")
        banner = QLabel()
        banner.setPixmap(logo_pixmap(150, wordmark=True))
        banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info = QLabel(f"Version {__version__}\n\n{EXPANSION}")
        info.setTextFormat(Qt.TextFormat.PlainText)
        info.setWordWrap(True)
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(banner)
        layout.addWidget(info)
        layout.addWidget(buttons)
        self.setMinimumWidth(480)
