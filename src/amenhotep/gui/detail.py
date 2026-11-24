"""Device detail panel: facts, evidence, and manual editing with locked fields."""

from __future__ import annotations

import sqlite3
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from amenhotep.core.models import OS_FAMILIES
from amenhotep.services.classify import DEVICE_TYPES
from amenhotep.store.repo import AreaRow, DeviceRow


def _plain_label() -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)  # LAN-derived text must never be rich text
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class DeviceDetail(QWidget):
    changesSaved = Signal(str, dict)  # device uuid, {field: value}
    unlockRequested = Signal(str, list)  # device uuid, [fields]

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._device: DeviceRow | None = None
        self._editable = True

        self.title = _plain_label()
        self.ip, self.mac, self.hostname = _plain_label(), _plain_label(), _plain_label()
        self.seen = _plain_label()
        self.area = QComboBox()
        self.area.addItem("(unassigned)", None)
        self.os_detail, self.hints = _plain_label(), _plain_label()
        self.presence = _plain_label()
        self.presence.setWordWrap(True)
        self.hints.setWordWrap(True)
        self.name = QLineEdit()
        self.name.setPlaceholderText("Friendly name")
        self.type = QComboBox()
        self.type.addItems(sorted(DEVICE_TYPES))
        self.os = QComboBox()
        self.os.addItems(OS_FAMILIES)
        self.vendor, self.model = QLineEdit(), QLineEdit()
        self.mode = QComboBox()
        self.mode.addItems(["fixed", "roaming"])
        self.notes = QPlainTextEdit()
        self.notes.setFixedHeight(60)
        self.lock_note = _plain_label()
        self.lock_note.setWordWrap(True)

        form = QFormLayout()
        form.addRow("IP", self.ip)
        form.addRow("MAC", self.mac)
        form.addRow("Hostname", self.hostname)
        form.addRow("Area", self.area)
        form.addRow("Last seen", self.seen)
        form.addRow("Presence", self.presence)
        form.addRow("Name", self.name)
        form.addRow("Type", self.type)
        form.addRow("OS", self.os)
        form.addRow("OS detail", self.os_detail)
        form.addRow("Vendor", self.vendor)
        form.addRow("Model", self.model)
        form.addRow("Mode", self.mode)
        form.addRow("Hints", self.hints)
        form.addRow("Notes", self.notes)

        self.save_btn = QPushButton("Save changes")
        self.unlock_btn = QPushButton("Let scans update edited fields")
        self.save_btn.clicked.connect(self._save)
        self.unlock_btn.clicked.connect(self._unlock)
        buttons = QHBoxLayout()
        buttons.addWidget(self.save_btn)
        buttons.addWidget(self.unlock_btn)

        self.evidence = QTableWidget(0, 4)
        self.evidence.setHorizontalHeaderLabels(["Field", "Value", "Conf.", "Source"])
        self.evidence.horizontalHeader().setStretchLastSection(True)
        self.evidence.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        layout = QVBoxLayout(self)
        layout.addWidget(self.title)
        layout.addLayout(form)
        layout.addWidget(self.lock_note)
        layout.addLayout(buttons)
        layout.addWidget(QLabel("Why Amenhotep thinks so (evidence):"))
        layout.addWidget(self.evidence, 1)
        self.clear()

    # ---- state -------------------------------------------------------
    def set_areas(self, areas: list[AreaRow]) -> None:
        self.area.clear()
        self.area.addItem("(unassigned)", None)
        for a in areas:
            self.area.addItem(a.label, a.id)

    def set_editable(self, editable: bool) -> None:
        self._editable = editable
        for w in (self.name, self.vendor, self.model):
            w.setReadOnly(not editable)
        self.notes.setReadOnly(not editable)
        for c in (self.area, self.type, self.os, self.mode):
            c.setEnabled(editable)
        self.save_btn.setEnabled(editable)
        self.unlock_btn.setEnabled(editable and bool(self._device and self._device.locked_fields))

    def clear(self) -> None:
        self._device = None
        self.setEnabled(False)
        self.title.setText("Select a device")
        for label in (
            self.ip,
            self.mac,
            self.hostname,
            self.seen,
            self.presence,
            self.lock_note,
            self.os_detail,
            self.hints,
        ):
            label.setText("")
        self.evidence.setRowCount(0)

    def load(self, device: DeviceRow, evidence: list[sqlite3.Row], presence: str = "") -> None:
        self._device = device
        self.setEnabled(True)
        self.title.setText(device.display_name or device.hostname or device.ip or device.uuid)
        self.ip.setText(device.ip or "-")
        self.mac.setText(device.mac or "-")
        self.hostname.setText(device.hostname or "-")
        self.area.setCurrentIndex(max(self.area.findData(device.area_id), 0))
        self.seen.setText(device.last_seen or "-")
        self.presence.setText(presence or "-")
        self.name.setText(device.display_name or "")
        self.type.setCurrentText(device.device_type)
        self.os.setCurrentText(device.os_family)
        self.os_detail.setText(device.os_detail or "-")
        self.hints.setText(device.hardware_notes or "-")
        self.vendor.setText(device.vendor or "")
        self.model.setText(device.model or "")
        self.mode.setCurrentText(device.location_mode)
        self.notes.setPlainText(device.notes or "")
        locked = ", ".join(device.locked_fields)
        self.lock_note.setText(f"Edited by you (scans won't change): {locked}" if locked else "")
        self.set_editable(self._editable)
        self.evidence.setRowCount(len(evidence))
        for r, e in enumerate(evidence):
            cells = [e["field"], e["value"], f"{e['confidence']:.2f}", e["source"]]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(str(text))
                if e["detail"]:
                    item.setToolTip(str(e["detail"]))
                self.evidence.setItem(r, c, item)

    # ---- editing -----------------------------------------------------
    def collect_changes(self) -> dict[str, Any]:
        """Only fields that differ from the loaded device (so untouched ones are not locked)."""
        d = self._device
        if d is None:
            return {}
        new: dict[str, Any] = {
            "display_name": self.name.text().strip() or None,
            "device_type": self.type.currentText(),
            "os_family": self.os.currentText(),
            "vendor": self.vendor.text().strip() or None,
            "model": self.model.text().strip() or None,
            "location_mode": self.mode.currentText(),
            "notes": self.notes.toPlainText().strip() or None,
        }
        old = {k: getattr(d, k) for k in new}
        changes = {k: v for k, v in new.items() if v != old[k]}
        area_id = self.area.currentData()
        if area_id != d.area_id:
            changes["area_id"] = area_id
        return changes

    def _save(self) -> None:
        changes = self.collect_changes()
        if self._device and changes:
            self.changesSaved.emit(self._device.uuid, changes)

    def _unlock(self) -> None:
        if self._device and self._device.locked_fields:
            self.unlockRequested.emit(self._device.uuid, list(self._device.locked_fields))
