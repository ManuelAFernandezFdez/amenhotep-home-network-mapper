"""Main window: Devices and Scans tabs (Topology, House 3D, Settings come later)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import QCheckBox, QMainWindow, QTabWidget, QVBoxLayout, QWidget

from amenhotep import __version__
from amenhotep.gui.branding import AboutDialog, HeaderBar, app_icon
from amenhotep.gui.devices_tab import DevicesTab
from amenhotep.gui.editmode import EditMode
from amenhotep.gui.home_tab import HomeTab
from amenhotep.gui.plan_tab import PlanTab
from amenhotep.gui.scan_tab import ScanTab, ServiceFactory, default_factory
from amenhotep.gui.topology_tab import TopologyTab
from amenhotep.services.satisfaction import satisfaction
from amenhotep.services.scan import ScanResult
from amenhotep.store import db
from amenhotep.store.repo import Repository


class MainWindow(QMainWindow):
    def __init__(
        self,
        db_path: Path | str,
        factory: ServiceFactory = default_factory,
        parent: Any = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Amenhotep {__version__}")
        self.setWindowIcon(app_icon())
        self.resize(1250, 720)
        self.conn = db.connect(db_path)
        self.repo = Repository(self.conn)

        self.devices = DevicesTab(self.repo)
        self.home = HomeTab(self.repo)
        self.topology = TopologyTab(self.repo)
        self.plan = PlanTab(self.repo)
        self.plan.changed.connect(self._on_plan_changed)
        self.plan.openDevice.connect(self._open_device)
        self.scans = ScanTab(db_path, self.repo, factory)
        self.scans.scanFinished.connect(self._on_scan_finished)
        self.scans.importFinished.connect(self._on_import_finished)
        self.devices.refreshed.connect(self._update_status)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.devices, "Devices")
        self.tabs.addTab(self.home, "HomeKit && Matter")
        self.tabs.addTab(self.plan, "House")
        self.tabs.addTab(self.topology, "Topology")
        self.tabs.addTab(self.scans, "Scans")
        self.header = HeaderBar()
        central = QWidget()
        column = QVBoxLayout(central)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        column.addWidget(self.header)
        column.addWidget(self.tabs, 1)
        self.setCentralWidget(central)

        self.edit_mode = EditMode()  # read-only until the user ticks the box
        self.edit_box = QCheckBox("Allow editing")
        self.edit_box.setToolTip(
            "Off (default): all information is read-only.\nOn: names, areas, links, positions "
            "and notes can be changed."
        )
        self.edit_box.toggled.connect(self.edit_mode.set)
        self.edit_mode.changed.connect(self._apply_edit_mode)
        self.menuBar().setCornerWidget(self.edit_box, Qt.Corner.TopRightCorner)
        self._apply_edit_mode(False)

        quit_action = QAction("&Quit", self)
        quit_action.triggered.connect(self.close)
        self.menuBar().addMenu("&File").addAction(quit_action)
        about_action = QAction("&About Amenhotep", self)
        about_action.triggered.connect(lambda: AboutDialog(self).exec())
        self.menuBar().addMenu("&Help").addAction(about_action)
        self._update_status()

    def _on_scan_finished(self, _result: ScanResult) -> None:
        self.devices.refresh()
        self.topology.refresh()
        self.plan.refresh()
        self.home.refresh()
        self._update_status()

    def _on_import_finished(self, _result: object) -> None:
        self.devices.refresh()
        self.topology.refresh()
        self.plan.refresh()
        self.home.refresh()
        self._update_status()

    def _apply_edit_mode(self, enabled: bool) -> None:
        for tab in (self.devices, self.home, self.plan, self.topology, self.scans):
            tab.set_editable(enabled)
        self.edit_box.setChecked(enabled)
        self.statusBar().showMessage(
            "Editing allowed" if enabled else "Read-only: tick “Allow editing” to make changes",
            4000,
        )

    def _on_plan_changed(self) -> None:
        self.devices.refresh()
        self.topology.refresh()
        self._update_status()

    def _open_device(self, uuid: str) -> None:
        self.tabs.setCurrentWidget(self.devices)
        self.devices.select_uuids([uuid])

    def _update_status(self) -> None:
        self.statusBar().showMessage(satisfaction(self.repo.list_devices()).message())

    def closeEvent(self, event: QCloseEvent) -> None:
        self.scans.shutdown()
        self.conn.close()
        super().closeEvent(event)
