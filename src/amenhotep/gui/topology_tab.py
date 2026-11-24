"""Topology tab: the network tree; drag a device onto its switch/AP to link it."""

from __future__ import annotations

from functools import partial
from typing import Any

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QDropEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from amenhotep.services import topology
from amenhotep.store.repo import Repository

UUID_ROLE = Qt.ItemDataRole.UserRole
COLUMNS = ["Device", "Port", "Link", "IP", "Type"]


class _Tree(QTreeWidget):
    dropped = Signal(str, str)  # child uuid, parent uuid

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802 (Qt API)
        src = self.currentItem()
        target = self.itemAt(event.position().toPoint())
        event.ignore()  # never let Qt move the item itself: the DB is the source of truth
        if src and target and (c := src.data(0, UUID_ROLE)) and (p := target.data(0, UUID_ROLE)):
            self.dropped.emit(c, p)


class TopologyTab(QWidget):
    changed = Signal()

    def __init__(self, repo: Repository, parent: Any = None) -> None:
        super().__init__(parent)
        self.repo = repo
        self.tree = _Tree()
        self.tree.setColumnCount(len(COLUMNS))
        self.tree.setHeaderLabels(COLUMNS)
        self.tree.setDragEnabled(True)
        self.tree.setAcceptDrops(True)
        self.tree.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        self.tree.dropped.connect(self.drop_link)
        self.summary = QLabel()
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        add4 = QPushButton("Add 4-port switch")
        add8 = QPushButton("Add 8-port switch")
        add4.clicked.connect(partial(self._add_switch, 4))
        add8.clicked.connect(partial(self._add_switch, 8))
        self.hints = QPushButton("Suggest uplinks…")
        self.hints.clicked.connect(self.show_suggestions)
        row = QHBoxLayout()
        row.addWidget(self.summary, 1)
        row.addWidget(add4)
        row.addWidget(add8)
        row.addWidget(self.hints)
        layout = QVBoxLayout(self)
        layout.addLayout(row)
        layout.addWidget(self.tree, 1)
        layout.addWidget(
            QLabel("Drag a device onto its switch or access point, or right-click → Set uplink…")
        )
        self.refresh()

    # ---- view ---------------------------------------------------------------
    def refresh(self) -> None:
        topo = topology.build(self.repo)
        self.tree.clear()

        def add(parent: QTreeWidget | QTreeWidgetItem, n: topology.Node) -> None:
            cap = topo.ports.get(n.device.uuid)
            name = n.name + (f"  ({topo.used_ports(n)}/{cap} ports)" if cap else "")
            link = n.link
            via = ""
            if link:
                via = link.medium + ("" if link.confirmed else " (suggested)")
            item = QTreeWidgetItem(
                [
                    name,
                    (link.port or "") if link else "",
                    via,
                    n.device.ip or "",
                    n.device.device_type,
                ]
            )
            item.setData(0, UUID_ROLE, n.device.uuid)
            if isinstance(parent, QTreeWidget):
                parent.addTopLevelItem(item)
            else:
                parent.addChild(item)
            for c in n.children:
                add(item, c)

        for r in topo.roots:
            add(self.tree, r)
        if topo.unlinked:
            group = QTreeWidgetItem([f"No uplink yet ({len(topo.unlinked)})"])
            self.tree.addTopLevelItem(group)
            for n in topo.unlinked:
                add(group, n)
        self.tree.expandAll()
        for c in range(len(COLUMNS)):
            self.tree.resizeColumnToContents(c)
        linked = len(self.repo.list_links())
        self.summary.setText(f"{linked} links · {len(topo.unlinked)} devices without an uplink")

    # ---- actions ------------------------------------------------------------
    def _infra(self) -> list[tuple[str, str]]:
        return [
            (d.display_name or d.hostname or d.ip or d.uuid[:8], d.uuid)
            for d in self.repo.list_devices()
            if topology.is_infra(d)
        ]

    def _menu(self, pos: QPoint) -> None:
        item = self.tree.itemAt(pos)
        uid = item.data(0, UUID_ROLE) if item else None
        if not uid:
            return
        menu = QMenu(self)
        menu.addAction("Set uplink…", partial(self._ask_uplink, uid))
        menu.addAction("Remove uplink", partial(self.unlink, uid))
        flag = next(d.is_infrastructure for d in self.repo.list_devices() if d.uuid == uid)
        menu.addAction(
            "Not infrastructure" if flag else "Mark as infrastructure (switch/AP)…",
            partial(self._toggle_infra, uid, flag),
        )
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _ask_uplink(self, child: str) -> None:
        infra = [(n, u) for n, u in self._infra() if u != child]
        if not infra:
            QMessageBox.information(self, "Uplink", "Add a switch or mark an access point first.")
            return
        names = [n for n, _ in infra]
        choice, ok = QInputDialog.getItem(self, "Set uplink", "Plugged into:", names, 0, False)
        if ok:
            self.drop_link(child, dict(infra)[choice])

    def drop_link(self, child: str, parent: str, port: str | None = None) -> bool:
        ports = self.repo.device_ports(parent)
        if port is None and ports:
            used = {lk.port for lk in self.repo.list_links() if lk.parent_uuid == parent}
            free = [str(p) for p in range(1, ports + 1) if str(p) not in used]
            choice, ok = QInputDialog.getItem(
                self, "Switch port", "Port:", ["(unknown)", *free], 0, False
            )
            if not ok:
                return False
            port = None if choice == "(unknown)" else choice
        try:
            self.repo.set_link(child, parent, port=port)
        except ValueError as exc:
            QMessageBox.warning(self, "Cannot link", str(exc))
            return False
        self.repo.commit()
        self._changed()
        return True

    def unlink(self, uid: str) -> None:
        self.repo.remove_link(uid)
        self.repo.commit()
        self._changed()

    def _toggle_infra(self, uid: str, flag: bool) -> None:
        ports = None
        if not flag:
            ports, ok = QInputDialog.getInt(
                self, "Ports", "Number of ports (0 = unknown):", 0, 0, 64
            )
            if not ok:
                return
        self.repo.set_infrastructure(uid, not flag, ports or None)
        self.repo.commit()
        self._changed()

    def _add_switch(self, ports: int) -> None:
        name, ok = QInputDialog.getText(self, "Add switch", "Name:", text=f"TP-Link {ports}-port")
        if ok and name.strip():
            topology.add_switch(self.repo, name.strip()[:64], f"tp-link-{ports}")
            self._changed()

    def show_suggestions(self) -> None:
        found = topology.suggest_uplinks(self.repo)
        if not found:
            QMessageBox.information(self, "Suggestions", "No suggestions.")
            return
        names = {d.uuid: d.display_name or d.ip or d.uuid[:8] for d in self.repo.list_devices()}
        text = "\n".join(f"{names[s.child]} → {names[s.parent]}: {s.reason}" for s in found[:20])
        more = f"\n… and {len(found) - 20} more" if len(found) > 20 else ""
        ans = QMessageBox.question(
            self, "Suggested uplinks", f"{text}{more}\n\nRecord them as suggestions?"
        )
        if ans == QMessageBox.StandardButton.Yes:
            topology.apply_suggestions(self.repo, found)
            self._changed()

    def _changed(self) -> None:
        self.refresh()
        self.changed.emit()
