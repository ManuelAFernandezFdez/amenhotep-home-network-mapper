"""Qt item models for the device list. Pure view-model logic; no DB access."""

from __future__ import annotations

import ipaddress
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
)
from PySide6.QtGui import QFont

from amenhotep.store.repo import DeviceRow

# (header, DeviceRow attribute, lockable field name or None)
COLUMNS: list[tuple[str, str, str | None]] = [
    ("Name", "name", "display_name"),
    ("IP", "ip", None),
    ("MAC", "mac", None),
    ("Vendor", "vendor", "vendor"),
    ("OS", "os_family", "os_family"),
    ("Type", "device_type", "device_type"),
    ("Model", "model", "model"),
    ("Area", "area_label", None),
    ("Mode", "location_mode", "location_mode"),
    ("Last seen", "last_seen", None),
    ("Status", "online_label", None),
]

Index = QModelIndex | QPersistentModelIndex


def display_name(d: DeviceRow) -> str:
    return d.display_name or d.hostname or ""


def ip_sort_key(ip: str | None) -> int:
    try:
        return int(ipaddress.IPv4Address(ip or "0.0.0.0"))
    except ValueError:
        return 0


class DeviceTableModel(QAbstractTableModel):
    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._devices: list[DeviceRow] = []

    def set_devices(self, devices: list[DeviceRow]) -> None:
        self.beginResetModel()
        self._devices = list(devices)
        self.endResetModel()

    def device_at(self, row: int) -> DeviceRow:
        return self._devices[row]

    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self._devices)

    def columnCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section][0]
        return None

    def _value(self, d: DeviceRow, column: int) -> Any:
        attr = COLUMNS[column][1]
        return display_name(d) if attr == "name" else getattr(d, attr)

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        d = self._devices[index.row()]
        col = index.column()
        lock = COLUMNS[col][2]
        edited = lock is not None and lock in d.locked_fields
        if role == Qt.ItemDataRole.DisplayRole:
            value = self._value(d, col)
            return "" if value in (None, "unknown") and col != 4 else (value or "")
        if role == Qt.ItemDataRole.UserRole:  # sort key
            if col == 1:
                return ip_sort_key(d.ip)
            return str(self._value(d, col) or "").lower()
        if role == Qt.ItemDataRole.FontRole and edited:
            font = QFont()
            font.setItalic(True)
            return font
        if role == Qt.ItemDataRole.ToolTipRole and col == 4 and d.os_detail and not edited:
            return d.os_detail
        if role == Qt.ItemDataRole.ToolTipRole and edited:
            return "Edited by you: scans will not overwrite this value"
        return None


class DeviceFilterProxy(QSortFilterProxyModel):
    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self.setSortRole(Qt.ItemDataRole.UserRole)
        self.text = ""
        self.device_type = ""  # "" = all
        self.os_family = ""
        self.unclassified_only = False
        self.area = ""  # "" = all, "none" = unassigned, else an area name (zone includes rooms)

    def set_filters(
        self,
        *,
        text: str | None = None,
        device_type: str | None = None,
        os_family: str | None = None,
        unclassified_only: bool | None = None,
        area: str | None = None,
    ) -> None:
        if hasattr(self, "beginFilterChange"):  # Qt >= 6.9
            self.beginFilterChange()
        if text is not None:
            self.text = text.strip().lower()
        if device_type is not None:
            self.device_type = device_type
        if os_family is not None:
            self.os_family = os_family
        if unclassified_only is not None:
            self.unclassified_only = unclassified_only
        if area is not None:
            self.area = area
        if hasattr(self, "endFilterChange"):
            self.endFilterChange()
        else:
            self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: Index) -> bool:
        model = self.sourceModel()
        assert isinstance(model, DeviceTableModel)
        d = model.device_at(source_row)
        if self.device_type and d.device_type != self.device_type:
            return False
        if self.os_family and d.os_family != self.os_family:
            return False
        if self.unclassified_only and d.device_type != "unknown":
            return False
        if self.area == "none" and d.area:
            return False
        if self.area not in ("", "none") and self.area not in (d.area, d.zone):
            return False
        if self.text:
            haystack = " ".join(
                str(v or "")
                for v in (
                    display_name(d),
                    d.ip,
                    d.mac,
                    d.vendor,
                    d.model,
                    d.device_type,
                    d.os_family,
                    d.area_label,
                    d.notes,
                )
            ).lower()
            return self.text in haystack
        return True
