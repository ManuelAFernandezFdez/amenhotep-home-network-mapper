"""Devices tab: filter bar, sortable table, detail panel, bulk edit."""

from __future__ import annotations

from functools import partial
from typing import Any

from PySide6.QtCore import QItemSelectionModel, QPoint, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QMenu,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from amenhotep.core.models import OS_FAMILIES
from amenhotep.gui.detail import DeviceDetail
from amenhotep.gui.models import DeviceFilterProxy, DeviceTableModel
from amenhotep.services.classify import DEVICE_TYPES
from amenhotep.services.presence import presence_for
from amenhotep.store.repo import Repository


class DevicesTab(QWidget):
    refreshed = Signal()  # device data changed (scan, edit, assignment)

    def __init__(self, repo: Repository, parent: Any = None) -> None:
        super().__init__(parent)
        self.repo = repo
        self.model = DeviceTableModel(self)
        self.proxy = DeviceFilterProxy(self)
        self.proxy.setSourceModel(self.model)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search name, IP, MAC, vendor, model…")
        self.search.setClearButtonEnabled(True)
        self.type_filter = QComboBox()
        self.type_filter.addItem("All types", "")
        for t in sorted(DEVICE_TYPES):
            self.type_filter.addItem(t, t)
        self.os_filter = QComboBox()
        self.os_filter.addItem("All OS", "")
        for o in OS_FAMILIES:
            self.os_filter.addItem(o, o)
        self.area_filter = QComboBox()
        self.unclassified = QCheckBox("Unclassified only")

        self.search.textChanged.connect(lambda t: self.proxy.set_filters(text=t))
        self.type_filter.currentIndexChanged.connect(
            lambda _i: self.proxy.set_filters(device_type=self.type_filter.currentData())
        )
        self.os_filter.currentIndexChanged.connect(
            lambda _i: self.proxy.set_filters(os_family=self.os_filter.currentData())
        )
        self.area_filter.currentIndexChanged.connect(
            lambda _i: self.proxy.set_filters(area=self.area_filter.currentData())
        )
        self.unclassified.toggled.connect(lambda v: self.proxy.set_filters(unclassified_only=v))

        bar = QHBoxLayout()
        bar.addWidget(self.search, 1)
        bar.addWidget(self.type_filter)
        bar.addWidget(self.os_filter)
        bar.addWidget(self.area_filter)
        bar.addWidget(self.unclassified)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)
        self.table.sortByColumn(1, Qt.SortOrder.AscendingOrder)

        self.detail = DeviceDetail()
        self.detail.changesSaved.connect(self._apply_changes)
        self.detail.unlockRequested.connect(self._unlock)

        split = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addLayout(bar)
        left_layout.addWidget(self.table)
        split.addWidget(left)
        split.addWidget(self.detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        outer = QVBoxLayout(self)
        outer.addWidget(split)

        self.refresh()

    # ---- data --------------------------------------------------------
    def _reload_area_filter(self) -> None:
        current = self.area_filter.currentData() or ""
        self.area_filter.blockSignals(True)
        self.area_filter.clear()
        self.area_filter.addItem("All areas", "")
        self.area_filter.addItem("Unassigned", "none")
        for a in self.repo.list_areas():
            self.area_filter.addItem(("    " if a.zone else "") + a.name, a.name)
        i = self.area_filter.findData(current)
        self.area_filter.setCurrentIndex(max(i, 0))
        self.area_filter.blockSignals(False)
        self.proxy.set_filters(area=self.area_filter.currentData())

    def refresh(self) -> None:
        self._reload_area_filter()
        keep = self.selected_uuids()
        self.detail.set_areas(self.repo.list_areas())
        self.model.set_devices(self.repo.list_devices())
        self.table.resizeColumnsToContents()
        self.select_uuids(keep)
        self._selection_changed()
        self.refreshed.emit()

    def selected_uuids(self) -> list[str]:
        rows = self.table.selectionModel().selectedRows()
        return [self.model.device_at(self.proxy.mapToSource(i).row()).uuid for i in rows]

    def select_uuids(self, uuids: list[str]) -> None:
        sel = self.table.selectionModel()
        sel.clearSelection()
        wanted = set(uuids)
        for row in range(self.proxy.rowCount()):
            src = self.proxy.mapToSource(self.proxy.index(row, 0)).row()
            if self.model.device_at(src).uuid in wanted:
                sel.select(
                    self.proxy.index(row, 0),
                    QItemSelectionModel.SelectionFlag.Select
                    | QItemSelectionModel.SelectionFlag.Rows,
                )

    def _selection_changed(self, *_: Any) -> None:
        uuids = self.selected_uuids()
        if len(uuids) == 1:
            dev = next(d for d in self.repo.list_devices() if d.uuid == uuids[0])
            self.detail.load(
                dev,
                self.repo.evidence_for(dev.uuid),
                presence_for(self.repo, dev.uuid).summary(),
            )
        else:
            self.detail.clear()
            if len(uuids) > 1:
                self.detail.title.setText(f"{len(uuids)} devices selected (right-click to edit)")

    # ---- editing -----------------------------------------------------
    def _apply_changes(self, uuid: str, changes: dict[str, Any]) -> None:
        self.apply_to([uuid], changes)

    def apply_to(self, uuids: list[str], changes: dict[str, Any]) -> None:
        changes = dict(changes)
        has_area = "area_id" in changes
        area_id = changes.pop("area_id", None)
        for uid in uuids:
            self.repo.set_fields(uid, changes, user=True)
        if has_area:  # an explicit area choice wins over the roaming/fixed auto-area
            self.repo.assign_area(uuids, area_id)
        self.repo.commit()
        self.refresh()

    def assign_area(self, uuids: list[str], area_id: int | None, pin: bool = False) -> None:
        """Move devices to a zone/room; ``pin`` also makes them fixed (night-table clocks)."""
        self.repo.assign_area(uuids, area_id, mode="fixed" if pin else None)
        self.repo.commit()
        self.refresh()

    def _unlock(self, uuid: str, fields: list[str]) -> None:
        self.repo.unlock_fields(uuid, fields)
        self.repo.commit()
        self.refresh()

    def _context_menu(self, pos: QPoint) -> None:
        uuids = self.selected_uuids()
        if not uuids:
            return
        menu = QMenu(self)
        type_menu = menu.addMenu("Set type")
        for t in sorted(DEVICE_TYPES):
            type_menu.addAction(t, partial(self.apply_to, uuids, {"device_type": t}))
        mode_menu = menu.addMenu("Set mode")
        for m in ("fixed", "roaming"):
            mode_menu.addAction(m, partial(self.apply_to, uuids, {"location_mode": m}))
        areas = self.repo.list_areas()
        for title, pin in (("Assign to area", False), ("Pin as fixed in…", True)):
            sub = menu.addMenu(title)
            if not pin:
                sub.addAction("(unassigned)", partial(self.assign_area, uuids, None))
            for a in areas:
                sub.addAction(a.label, partial(self.assign_area, uuids, a.id, pin))
        menu.exec(self.table.viewport().mapToGlobal(pos))
