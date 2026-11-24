"""One switch for the whole window: information is read-only until the user allows editing."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal


class EditMode(QObject):
    changed = Signal(bool)

    def __init__(self, enabled: bool = False) -> None:
        super().__init__()
        self._enabled = enabled  # starts read-only

    @property
    def enabled(self) -> bool:
        return self._enabled

    def set(self, enabled: bool) -> None:
        if enabled != self._enabled:
            self._enabled = enabled
            self.changed.emit(enabled)
