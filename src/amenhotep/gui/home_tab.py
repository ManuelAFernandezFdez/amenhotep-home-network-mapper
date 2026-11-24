"""HomeKit & Matter tab: HAP accessories, Matter devices (incl. Thread) and border routers."""

from __future__ import annotations

from functools import partial
from typing import Any

from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QInputDialog,
    QLabel,
    QMenu,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from amenhotep.services.matter import MatterDevice, group_matter_nodes
from amenhotep.store.repo import Repository


def _table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.horizontalHeader().setStretchLastSection(True)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setAlternatingRowColors(True)
    t.verticalHeader().setVisible(False)
    return t


def _fill(table: QTableWidget, rows: list[list[str]]) -> None:
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, text in enumerate(row):
            item = QTableWidgetItem(text)  # plain text only: LAN-derived values
            table.setItem(r, c, item)
    table.resizeColumnsToContents()
    table.horizontalHeader().setStretchLastSection(True)


class HomeTab(QWidget):
    def __init__(self, repo: Repository, parent: Any = None) -> None:
        super().__init__(parent)
        self.repo = repo
        self.editable = True
        self._matter: list[MatterDevice] = []

        self.summary = QLabel()
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        self.hap = _table(["Name", "IP", "Category", "Model", "Paired", "Area", "Last seen"])
        self.matter = _table(
            ["Name", "Transport", "Fabrics", "Address", "Area", "Last seen", "Notes"]
        )
        self.matter.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.matter.customContextMenuRequested.connect(self._matter_menu)
        self.routers = _table(["Border router", "IP", "Thread network", "Vendor", "Model", "Notes"])

        layout = QVBoxLayout(self)
        layout.addWidget(self.summary)
        layout.addWidget(QLabel("HomeKit accessories (Wi-Fi / Ethernet, HAP over IP)"))
        layout.addWidget(self.hap, 3)
        layout.addWidget(
            QLabel("Matter devices (right-click to name or place; Thread nodes have no IPv4)")
        )
        layout.addWidget(self.matter, 3)
        layout.addWidget(QLabel("Thread border routers"))
        layout.addWidget(self.routers, 1)
        self.refresh()

    def refresh(self) -> None:
        hap = self.repo.list_homekit()
        _fill(
            self.hap,
            [
                [
                    h.name,
                    h.ip or "",
                    h.category,
                    h.model or "",
                    {True: "yes", False: "NO", None: "?"}[h.paired],
                    h.area or "",
                    h.last_seen or "",
                ]
                for h in hap
            ],
        )
        self._matter = group_matter_nodes(self.repo.list_matter_nodes())
        _fill(
            self.matter,
            [
                [
                    g.label or g.host_name or "(unnamed)",
                    "LAN host"
                    if g.host_uuid
                    else ("Thread (probably)" if g.likely_thread else "IP"),
                    str(g.fabrics),
                    next(
                        (a for a in g.addresses if not a.lower().startswith("fe80")), g.addresses[0]
                    ),
                    g.area or "",
                    max(n.last_seen for n in g.nodes),
                    g.notes_text,
                ]
                for g in self._matter
            ],
        )
        brs = self.repo.list_border_routers()
        _fill(
            self.routers,
            [
                [
                    b.name,
                    b.ip or "",
                    b.network_name or "",
                    b.vendor or "",
                    b.model or "",
                    (b.notes or "").replace("\n", " · "),
                ]
                for b in brs
            ],
        )
        unpaired = sum(1 for h in hap if h.paired is False)
        threads = sum(1 for g in self._matter if g.likely_thread)
        self.summary.setText(
            f"{len(hap)} HomeKit accessories ({unpaired} not paired) · "
            f"{len(self._matter)} Matter devices ({threads} on Thread) · "
            f"{len(brs)} Thread border routers"
        )

    # ---- Matter naming / placement ------------------------------------
    def _selected_matter(self) -> MatterDevice | None:
        rows = self.matter.selectionModel().selectedRows()
        return self._matter[rows[0].row()] if rows else None

    def set_editable(self, editable: bool) -> None:
        self.editable = editable

    def _matter_menu(self, pos: QPoint) -> None:
        item = self.matter.itemAt(pos)
        if item is None or not self.editable:
            return
        self.matter.selectRow(item.row())
        dev = self._matter[item.row()]
        menu = QMenu(self)
        menu.addAction("Name…", partial(self._ask_name, dev))
        menu.addAction("Edit notes…", partial(self._ask_notes, dev))
        sub = menu.addMenu("Place in area")
        sub.addAction("(unassigned)", partial(self.place_matter, dev, None))
        for a in self.repo.list_areas():
            sub.addAction(a.label, partial(self.place_matter, dev, a.id))
        menu.exec(self.matter.viewport().mapToGlobal(pos))

    def _ask_name(self, dev: MatterDevice) -> None:
        text, ok = QInputDialog.getText(self, "Name Matter device", "Name:", text=dev.label or "")
        if ok:
            self.name_matter(dev, text)

    def _ask_notes(self, dev: MatterDevice) -> None:
        text, ok = QInputDialog.getMultiLineText(self, "Matter device notes", "Notes:", dev.notes)
        if ok:
            self.set_matter_notes(dev, text)

    def set_matter_notes(self, dev: MatterDevice, notes: str) -> None:
        for n in dev.nodes:
            self.repo.set_matter_notes(n.instance, notes.strip() or None)
        self.repo.commit()
        self.refresh()

    def name_matter(self, dev: MatterDevice, label: str) -> None:
        for n in dev.nodes:
            self.repo.set_matter_label(n.instance, label, n.area_id)
        self.repo.commit()
        self.refresh()

    def place_matter(self, dev: MatterDevice, area_id: int | None) -> None:
        for n in dev.nodes:
            self.repo.set_matter_label(n.instance, dev.label, area_id)
        self.repo.commit()
        self.refresh()
