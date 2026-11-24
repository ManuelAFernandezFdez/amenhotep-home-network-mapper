"""A two-column Field | Value table whose values can be edited (when editing is allowed)."""

from __future__ import annotations

from functools import partial
from typing import Any

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QInputDialog,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from amenhotep.services.plan import FieldSpec


class FieldTable(QTableWidget):
    edited = Signal(str, object)  # field key, new value

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(0, 2, parent)
        self.setHorizontalHeaderLabels(["Field", "Value"])
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setVisible(False)
        self.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setWordWrap(True)
        self.editable = False
        self._specs: list[FieldSpec] = []
        self.cellDoubleClicked.connect(self._double_clicked)
        self.itemChanged.connect(self._item_changed)

    # ---- content -------------------------------------------------------------------------------
    def set_fields(self, specs: list[FieldSpec]) -> None:
        self._specs = specs
        self.blockSignals(True)
        self.clearContents()
        self.setRowCount(len(specs))
        for r, spec in enumerate(specs):
            label = QTableWidgetItem(spec.label)
            label.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.setItem(r, 0, label)
            if spec.kind == "choice":
                combo = QComboBox()
                for text, data in spec.choices:
                    combo.addItem(text, data)
                i = combo.findData(spec.data)
                combo.setCurrentIndex(max(i, 0))
                combo.setEnabled(self.editable and spec.editable)
                combo.currentIndexChanged.connect(partial(self._combo_changed, spec.key, combo))
                self.setCellWidget(r, 1, combo)
            else:
                shown = spec.value if spec.kind == "text" else spec.value.replace("\n", " ↵ ")
                item = QTableWidgetItem(shown)
                item.setToolTip(spec.value)
                flags = Qt.ItemFlag.ItemIsEnabled
                if spec.kind == "text" and spec.editable and self.editable:
                    flags |= Qt.ItemFlag.ItemIsEditable
                item.setFlags(flags)
                self.setItem(r, 1, item)
        self.blockSignals(False)
        self.resizeRowsToContents()

    def set_editable(self, editable: bool) -> None:
        self.editable = editable
        self.set_fields(self._specs)  # rebuild with the new flags

    # ---- editing -------------------------------------------------------------------------------
    def _emit(self, key: str, value: Any) -> None:
        QTimer.singleShot(0, lambda: self.edited.emit(key, value))  # never rebuild mid-signal

    def _item_changed(self, item: QTableWidgetItem) -> None:
        if item.column() != 1 or not self.editable:
            return
        spec = self._specs[item.row()]
        if spec.kind == "text" and spec.editable and item.text() != spec.value:
            self._emit(spec.key, item.text().strip() or None)

    def _combo_changed(self, key: str, combo: QComboBox, _i: int) -> None:
        if self.editable:
            self._emit(key, combo.currentData())

    def _double_clicked(self, row: int, column: int) -> None:
        spec = self._specs[row]
        if column == 1 and spec.kind == "multiline" and spec.editable and self.editable:
            text, ok = QInputDialog.getMultiLineText(self, spec.label, spec.label + ":", spec.value)
            if ok and text.strip() != spec.value:
                self._emit(spec.key, text.strip() or None)
