"""House tab: a flat plan of the selected level (left) and a graphical level selector (right).

Drag a device to place it (dropping it into a room also puts it in that room's area). Wires are
drawn between devices; a wire to another level goes to a passage (riser) you define by clicking
"Add passage" and then the plan. A Wi-Fi-only repeater needs no passage.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import partial
from typing import Any

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QMouseEvent, QPainter, QPen, QResizeEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGraphicsEllipseItem,
    QGraphicsItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from amenhotep.gui.fields import FieldTable
from amenhotep.services import plan
from amenhotep.services.matter import group_matter_nodes
from amenhotep.store.repo import LevelRow, Repository, RiserRow

SCALE = 60.0  # scene units per metre
IRIS, GOLD, RED = QColor("#007ACC"), QColor("#E9B44C"), QColor("#D64545")
TYPE_COLORS = {
    "router": "#007ACC", "switch": "#007ACC", "access-point": "#007ACC", "mesh-node": "#007ACC",
    "network-device": "#007ACC", "camera": "#B5651D", "speaker": "#8E5AC7", "tv": "#8E5AC7",
    "media-player": "#8E5AC7", "smart-plug": "#2E9E6B", "smart-light": "#E9B44C",
    "smart-appliance": "#2E9E6B", "hub": "#D6639B", "iot-sensor": "#D6639B", "phone": "#5A6B7B",
    "tablet": "#5A6B7B", "computer": "#5A6B7B", "laptop": "#5A6B7B", "printer": "#7A7A7A",
}  # fmt: skip
TYPE_COLORS[plan.MATTER_TYPE] = "#C9572B"


class _Marker(QGraphicsEllipseItem):
    def __init__(
        self,
        dev: plan.PlacedDevice,
        radius: float,
        on_release: Callable[[Any], None],
        on_move: Callable[[str], None],
        movable: bool,
    ):
        super().__init__(-radius, -radius, 2 * radius, 2 * radius)
        self.dev, self._on_release, self._on_move = dev, on_release, on_move
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, movable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setZValue(10)
        self.setToolTip(f"{dev.name}\n{dev.detail}")

    def itemChange(self, change: Any, value: Any) -> Any:  # noqa: N802
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            self._on_move(self.dev.uuid)  # let the wires follow while dragging
        return super().itemChange(change, value)

    def mouseReleaseEvent(self, event: Any) -> None:  # noqa: N802
        super().mouseReleaseEvent(event)
        self._on_release(self)


class _RiserItem(QGraphicsRectItem):
    def __init__(
        self, riser: RiserRow, size: float, on_release: Callable[[Any], None], movable: bool
    ):
        super().__init__(-size, -size, 2 * size, 2 * size)
        self.riser, self._on_release = riser, on_release
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, movable)
        self.setZValue(9)

    def mouseReleaseEvent(self, event: Any) -> None:  # noqa: N802
        super().mouseReleaseEvent(event)
        self._on_release(self)


class PlanView(QGraphicsView):
    deviceMoved = Signal(str, float, float, object)  # uuid, fx, fy, room area id or None
    riserMoved = Signal(int, float, float)
    wallMoved = Signal(object)  # list of (area id, x, y, w, h) fractions
    planClicked = Signal(float, float)
    riserMenu = Signal(int, QPointF)
    deviceActivated = Signal(str)
    deviceSelected = Signal(str)  # '' when nothing is selected

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.pick_mode = False  # next click on the plan places a passage
        self._rect = QRectF()
        self._rooms: list[tuple[int, QRectF]] = []
        self._frac: dict[int, list[float]] = {}  # room area id -> x, y, w, h (fractions)
        self._items: dict[int, tuple[QGraphicsRectItem, QGraphicsSimpleTextItem]] = {}
        self.editable = True  # the window turns this off while editing is not allowed
        self._markers: dict[str, _Marker] = {}
        self._lines: list[tuple[Any, plan.Wire]] = []
        self._wall: plan.Wall | None = None
        self._moved: dict[int, plan.Rect] = {}
        self.setMouseTracking(True)
        self._scene.selectionChanged.connect(self._selection_changed)

    def _selection_changed(self) -> None:
        try:
            picked = [i for i in self._scene.selectedItems() if isinstance(i, _Marker)]
        except RuntimeError:  # scene already deleted at shutdown
            return
        self.deviceSelected.emit(picked[0].dev.uuid if picked else "")

    def select_uuid(self, uid: str) -> None:
        for item in self._scene.items():
            if isinstance(item, _Marker) and item.dev.uuid == uid:
                item.setSelected(True)

    # ---- drawing -------------------------------------------------------------------------------
    def show_layout(self, lay: plan.LevelLayout) -> None:
        pal = self.palette()
        text, base, mid = pal.text().color(), pal.base().color(), pal.mid().color()
        sc = self._scene
        self._frac, self._items, self._wall = {}, {}, None  # drop wrappers before clear()
        self._markers, self._lines = {}, []
        sc.clear()
        w, h = lay.level.width * SCALE, lay.level.depth * SCALE
        self._rect = QRectF(0, 0, w, h)
        floor = sc.addRect(self._rect, QPen(text, 2), QBrush(base))
        floor.setZValue(0)
        self._rooms = []
        for aid, name, x, y, rw, rh in lay.rooms:
            r = QRectF(x * w, y * h, rw * w, rh * h)
            self._rooms.append((aid, r))
            self._frac[aid] = [x, y, rw, rh]
            item = sc.addRect(r, QPen(mid, 1.5), QBrush(QColor(0, 122, 204, 22)))
            item.setZValue(1)
            label = QGraphicsSimpleTextItem(name)
            label.setBrush(text)
            label.setPos(r.x() + 6, r.y() + 3)
            label.setZValue(2)
            sc.addItem(label)
            self._items[aid] = (item, label)
        title = QGraphicsSimpleTextItem(
            f"{lay.level.name}   {lay.level.width:g} × {lay.level.depth:g} m"
        )
        title.setBrush(mid)
        title.setFont(QFont(title.font().family(), 9))
        title.setPos(0, -22)
        sc.addItem(title)
        at = {d.uuid: QPointF(d.x * w, d.y * h) for d in lay.devices}
        for wire in lay.wires:
            self._wire(wire, at, w, h)
        for rz in lay.risers:
            self._riser(rz, w, h, text)
        for i, d in enumerate(lay.devices):
            self._device(d, at[d.uuid], text, base, 11 * (i % 2))
        sc.setSceneRect(self._rect.adjusted(-20, -34, 20, 20))
        self.fit()

    def _wire(self, wire: plan.Wire, at: dict[str, QPointF], w: float, h: float) -> None:
        a = QPointF(wire.x1 * w, wire.y1 * h)
        b = QPointF(wire.x2 * w, wire.y2 * h)
        if wire.kind == "missing":
            mark = self._scene.addEllipse(a.x() + 12, a.y() - 26, 16, 16, QPen(RED, 2), QBrush(RED))
            mark.setToolTip(wire.label)
            mark.setZValue(11)
            t = QGraphicsSimpleTextItem("!", mark)
            t.setBrush(QColor("white"))
            t.setPos(a.x() + 17, a.y() - 27)
            return
        pen = QPen(IRIS if wire.kind == "wired" else GOLD, 2.5 if wire.kind == "wired" else 2)
        if wire.kind == "wifi":
            pen.setStyle(Qt.PenStyle.DashLine)
        line = self._scene.addLine(a.x(), a.y(), b.x(), b.y(), pen)
        line.setZValue(5)
        line.setToolTip(wire.label)
        self._lines.append((line, wire))

    def _riser(self, r: RiserRow, w: float, h: float, text: QColor) -> None:
        item = _RiserItem(r, 9, lambda i: self._riser_released(i, w, h), self.editable)
        item.setPos(r.x * w, r.y * h)
        item.setBrush(QBrush(GOLD))
        item.setPen(QPen(text, 1.5))
        item.setToolTip(f"Wire passage: {r.name}\n(drag to move, right-click to edit)")
        self._scene.addItem(item)
        t = QGraphicsSimpleTextItem(r.name, item)
        t.setBrush(text)
        t.setPos(12, -8)

    def _riser_released(self, item: _RiserItem, w: float, h: float) -> None:
        p = item.pos()
        self.riserMoved.emit(item.riser.id, p.x() / w, p.y() / h)

    def _device(
        self, d: plan.PlacedDevice, p: QPointF, text: QColor, base: QColor, drop: float
    ) -> None:
        colour = QColor(TYPE_COLORS.get(d.device_type, "#9AA3AB"))
        m = _Marker(d, 11 if d.infra else 8, self._marker_released, self._follow, self.editable)
        self._markers[d.uuid] = m
        m.setPos(p)
        m.setBrush(QBrush(colour))
        m.setPen(QPen(text if d.online is not False else QColor("#D64545"), 1.5))
        if d.online is False:
            m.setOpacity(0.55)
        self._scene.addItem(m)
        label = QGraphicsSimpleTextItem(d.name if len(d.name) <= 15 else d.name[:14] + "…", m)
        label.setBrush(text)
        label.setFont(QFont(label.font().family(), 8))
        label.setPos(-label.boundingRect().width() / 2, (10 if d.infra else 8) + drop)

    def _follow(self, uuid: str) -> None:
        """A device is being dragged: move the ends of its wires with it."""
        w, h = self._rect.width(), self._rect.height()
        for line, wire in self._lines:
            if uuid not in (wire.a, wire.b):
                continue
            m_a = self._markers.get(wire.a)
            a = m_a.pos() if m_a else QPointF(wire.x1 * w, wire.y1 * h)
            m_b = self._markers.get(wire.b) if wire.b else None
            b = m_b.pos() if m_b else QPointF(wire.x2 * w, wire.y2 * h)
            line.setLine(a.x(), a.y(), b.x(), b.y())

    def _marker_released(self, m: _Marker) -> None:
        p = m.pos()
        w, h = self._rect.width(), self._rect.height()
        fx, fy = min(1.0, max(0.0, p.x() / w)), min(1.0, max(0.0, p.y() / h))
        room = next((aid for aid, r in self._rooms if r.contains(p)), None)
        self.deviceMoved.emit(m.dev.uuid, fx, fy, room)

    # ---- interaction -----------------------------------------------------------------------
    def fit(self) -> None:
        self.fitInView(self._scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def resizeEvent(self, event: QResizeEvent) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.fit()

    # ---- dragging room walls ----------------------------------------------------------------
    def _wall_at(self, p: QPointF) -> plan.Wall | None:
        if not self.editable or not self._frac or self._rect.isEmpty():
            return None
        w, h = self._rect.width(), self._rect.height()
        tol = 6 / max(self.transform().m11(), 0.01)  # about 6 screen pixels
        rooms = {a: (v[0], v[1], v[2], v[3]) for a, v in self._frac.items()}
        for wall in plan.walls(rooms):
            across, along, size_across, size_along = (
                (p.x(), p.y(), w, h) if wall.orient == "v" else (p.y(), p.x(), h, w)
            )
            if abs(across - wall.pos * size_across) <= tol and any(
                lo * size_along - tol <= along <= hi * size_along + tol for lo, hi in wall.segments
            ):
                return wall
        return None

    def _on_device(self, event: QMouseEvent) -> bool:
        """Is the pointer on a device or passage marker (or its label)? Those win over walls."""
        item = self.itemAt(event.position().toPoint())
        while item is not None:
            if isinstance(item, (_Marker, _RiserItem)):
                return True
            item = item.parentItem()
        return False

    def _drag_to(self, wall: plan.Wall, p: QPointF) -> dict[int, plan.Rect]:
        w, h = self._rect.width(), self._rect.height()
        pos = p.x() / w if wall.orient == "v" else p.y() / h
        rooms = {a: (v[0], v[1], v[2], v[3]) for a, v in self._frac.items()}
        moved = plan.move_wall(rooms, wall, pos)
        for aid, (x, y, rw, rh) in moved.items():
            item, label = self._items[aid]
            item.setRect(QRectF(x * w, y * h, rw * w, rh * h))
            label.setPos(x * w + 6, y * h + 3)
        return moved

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        p = self.mapToScene(event.position().toPoint())
        if self._wall is not None:
            self._moved = self._drag_to(self._wall, p)
            return
        if self._on_device(event):
            self.viewport().unsetCursor()
            super().mouseMoveEvent(event)
            return
        wall = None if self.pick_mode else self._wall_at(p)
        if wall is None:
            self.viewport().unsetCursor()
        else:
            self.viewport().setCursor(
                Qt.CursorShape.SizeHorCursor if wall.orient == "v" else Qt.CursorShape.SizeVerCursor
            )
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if self._wall is not None:
            moved, self._wall = self._moved, None
            self.wallMoved.emit([(a, *r) for a, r in moved.items()])
            return
        super().mouseReleaseEvent(event)

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if not self.pick_mode and event.button() == Qt.MouseButton.LeftButton:
            wall = (
                None
                if self._on_device(event)
                else self._wall_at(self.mapToScene(event.position().toPoint()))
            )
            if wall is not None:
                self._wall, self._moved = wall, {}
                return
        if self.pick_mode and self.editable and event.button() == Qt.MouseButton.LeftButton:
            p = self.mapToScene(event.position().toPoint())
            if self._rect.contains(p):
                self.pick_mode = False
                self.viewport().unsetCursor()
                self.planClicked.emit(p.x() / self._rect.width(), p.y() / self._rect.height())
            return
        if event.button() == Qt.MouseButton.RightButton and self.editable:
            item = self.itemAt(event.position().toPoint())
            while item is not None and not isinstance(item, _RiserItem):
                item = item.parentItem()
            if isinstance(item, _RiserItem):
                self.riserMenu.emit(item.riser.id, event.globalPosition())
                return
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        item = self.itemAt(event.position().toPoint())
        while item is not None and not isinstance(item, _Marker):
            item = item.parentItem()
        if isinstance(item, _Marker):
            self.deviceActivated.emit(item.dev.uuid)
            return
        super().mouseDoubleClickEvent(event)


class LevelSelector(QWidget):
    """The house as a side view: floors stacked, gardens and roaming below; click to select."""

    selected = Signal(str)

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self.setMinimumWidth(200)
        self.setMaximumWidth(260)
        self.levels: list[LevelRow] = []
        self.counts: dict[str, int] = {}
        self.risers: list[RiserRow] = []
        self.current = ""
        self._boxes: dict[str, QRectF] = {}
        self.setToolTip("Click a floor, garden or Roaming")

    def set_data(
        self, levels: list[LevelRow], counts: dict[str, int], risers: list[RiserRow], current: str
    ) -> None:
        self.levels, self.counts, self.risers, self.current = levels, counts, risers, current
        self.update()

    def paintEvent(self, _e: Any) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pal = self.palette()
        text, mid = pal.text().color(), pal.mid().color()
        floors = [lv for lv in self.levels if lv.kind == "floor"]
        others = [lv for lv in self.levels if lv.kind != "floor"]
        W, H = self.width(), self.height()
        roof = 26
        fh = max(40.0, min(90.0, (H - roof - 20 - 56 * 2 - 40) / max(1, len(floors))))
        self._boxes = {}
        x0, bw = 12.0, W - 24.0 - 26
        y = 10.0
        p.setPen(QPen(mid, 2))
        p.drawPolygon(
            [QPointF(x0 - 4, y + roof), QPointF(x0 + bw / 2, y), QPointF(x0 + bw + 4, y + roof)]
        )
        y += roof
        centers: dict[str, float] = {}
        for lv in floors:
            self._draw(p, lv, QRectF(x0, y, bw, fh), text)
            centers[lv.id] = y + fh / 2
            y += fh
        # wire passages: a gold bar to the right through the levels each one connects
        for i, r in enumerate(self.risers):
            xr = x0 + bw + 8 + i * 6
            ys = [centers[lid] for lid in r.levels if lid in centers]
            if len(ys) >= 2 and xr < W - 2:
                p.setPen(QPen(GOLD, 3))
                p.drawLine(QPointF(xr, min(ys)), QPointF(xr, max(ys)))
                for cy in ys:
                    p.setBrush(GOLD)
                    p.drawEllipse(QPointF(xr, cy), 3, 3)
        y += 18
        for lv in others:
            h = 46 if lv.kind == "garden" else 36
            self._draw(p, lv, QRectF(x0, y, bw, h), text)
            y += h + 6

    def _draw(self, p: QPainter, lv: LevelRow, r: QRectF, text: QColor) -> None:
        self._boxes[lv.id] = r
        cur = lv.id == self.current
        fill = QColor(0, 122, 204, 90) if cur else QColor(0, 122, 204, 22)
        if lv.kind == "garden":
            fill = QColor(46, 158, 107, 90 if cur else 30)
        elif lv.kind == "roaming":
            fill = QColor(233, 180, 76, 90 if cur else 30)
        p.setBrush(fill)
        p.setPen(QPen(IRIS if cur else self.palette().mid().color(), 3 if cur else 1.5))
        p.drawRoundedRect(r, 4, 4)
        p.setPen(text)
        f = p.font()
        f.setBold(cur)
        p.setFont(f)
        p.drawText(
            r.adjusted(8, 4, -6, -4),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
            lv.name,
        )
        f.setBold(False)
        p.setFont(f)
        n = self.counts.get(lv.id, 0)
        right = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom
        p.drawText(r.adjusted(8, 4, -8, -6), right, f"{n} device{'s' if n != 1 else ''}")

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        pt = event.position()
        for lid, box in self._boxes.items():
            if box.contains(pt):
                self.selected.emit(lid)
                return


class _PassageDialog(QDialog):
    def __init__(self, levels: list[LevelRow], name: str, checked: set[str], parent: Any = None):
        super().__init__(parent)
        self.setWindowTitle("Wire passage")
        form = QFormLayout(self)
        self.name = QLineEdit(name)
        form.addRow("Name", self.name)
        self.boxes: dict[str, QCheckBox] = {}
        for lv in levels:
            box = QCheckBox(lv.name)
            box.setChecked(lv.id in checked)
            self.boxes[lv.id] = box
            form.addRow(box)
        form.addRow(QLabel("The cable goes through every level you tick, at this spot."))
        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        form.addRow(bb)

    def values(self) -> tuple[str, list[str]]:
        return self.name.text(), [k for k, b in self.boxes.items() if b.isChecked()]


class PlanTab(QWidget):
    changed = Signal()  # areas changed by dragging a device into a room
    openDevice = Signal(str)

    def __init__(self, repo: Repository, parent: Any = None) -> None:
        super().__init__(parent)
        self.repo = repo
        plan.seed(repo)
        self.current = "ground"
        self.hidden: set[str] = set()  # device types switched off in the plan
        self.type_panel = QWidget()
        self.type_panel.setFixedWidth(300)
        self._type_host = QVBoxLayout(self.type_panel)
        self._type_host.setContentsMargins(0, 0, 0, 0)
        self._type_inner: QWidget | None = None
        self.selected_uuid = ""
        self._busy = False
        self.info = FieldTable()
        self.info.edited.connect(self._field_edited)
        self.info_hint = QLabel("Click a device on the plan to see its fields here.")
        self.info_hint.setWordWrap(True)
        self.editable = True
        self.view = PlanView()
        self.selector = LevelSelector()
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        self.add_btn = add = QPushButton("Add passage")
        add.setToolTip("Define where a cable passes through the floors: click here, then the plan")
        add.clicked.connect(self.start_passage)
        self.size_btn = size = QPushButton("Level size…")
        size.clicked.connect(self.ask_size)
        self.arrange_btn = arrange = QPushButton("Auto-arrange")
        arrange.setToolTip("Forget manual positions on this level")
        arrange.clicked.connect(self.auto_arrange)
        top = QHBoxLayout()
        top.addWidget(add)
        top.addWidget(size)
        top.addWidget(arrange)
        top.addStretch(1)
        left = QVBoxLayout()
        left.addLayout(top)
        left.addWidget(self.view, 1)
        left.addWidget(self.status)
        margin = QVBoxLayout()
        margin.addWidget(self.type_panel, 1)
        margin.addWidget(QLabel("Selected"))
        margin.addWidget(self.info_hint)
        margin.addWidget(self.info, 2)
        row = QHBoxLayout(self)
        row.addLayout(margin)
        row.addLayout(left, 1)
        row.addWidget(self.selector)
        self.selector.selected.connect(self.select_level)
        self.view.deviceMoved.connect(self.move_device)
        self.view.wallMoved.connect(self.resize_rooms)
        self.view.riserMoved.connect(self.move_riser)
        self.view.planClicked.connect(self.place_passage)
        self.view.riserMenu.connect(self._riser_menu)
        self.view.deviceActivated.connect(self.openDevice)
        self.view.deviceSelected.connect(self._on_selected)
        self.refresh()

    # ---- view ---------------------------------------------------------------------------------
    def select_level(self, level_id: str) -> None:
        self.current = level_id
        self.refresh()

    def refresh(self) -> None:
        plan.ensure_rooms(self.repo)
        levels = self.repo.plan_levels()
        if self.current not in {lv.id for lv in levels}:
            self.current = levels[0].id
        lay = plan.layout(self.repo, self.current, self.hidden)
        self._fill_types(lay.type_counts)
        self._busy = True
        self.view.show_layout(lay)
        if self.selected_uuid:
            self.view.select_uuid(self.selected_uuid)
        self._busy = False
        self._show_info()
        self.selector.set_data(
            levels, plan.device_counts(self.repo), self.repo.plan_risers(), self.current
        )
        lost = plan.unplaced_devices(self.repo)
        parts = [f"{len(lay.devices)} devices on {lay.level.name}"]
        if lost:
            parts.append(
                f"{len(lost)} devices have no floor yet (assign an area on the Devices tab)"
            )
        parts += lay.notes[:2]
        if len(lay.notes) > 2:
            parts.append(f"… and {len(lay.notes) - 2} more notes (hover for all)")
        self.status.setText(" · ".join(parts))
        self.status.setToolTip("\n".join(lay.notes))

    def _on_selected(self, uid: str) -> None:
        if self._busy:
            return
        self.selected_uuid = uid
        self._show_info()

    def _show_info(self) -> None:
        specs = plan.item_fields(self.repo, self.selected_uuid) if self.selected_uuid else []
        self.info.set_fields(specs)
        self.info_hint.setVisible(not specs)

    def _field_edited(self, key: str, value: object) -> None:
        if not self.selected_uuid:
            return
        try:
            area_changed = plan.apply_field(self.repo, self.selected_uuid, key, value)
        except ValueError as exc:
            QMessageBox.warning(self, "Field", str(exc))
            area_changed = False
        self.refresh()
        if area_changed:
            self.changed.emit()

    def set_editable(self, editable: bool) -> None:
        """Read-only mode: nothing can be dragged, resized, added or typed into."""
        self.editable = editable
        self.view.editable = editable
        self.info.set_editable(editable)
        for b in (self.add_btn, self.size_btn, self.arrange_btn):
            b.setEnabled(editable)
        self.refresh()

    def _fill_types(self, counts: dict[str, int]) -> None:
        if self._type_inner is not None:
            self._type_inner.hide()
            self._type_inner.setParent(None)
            self._type_inner.deleteLater()
        self._type_inner = QWidget()
        self._type_host.addWidget(self._type_inner)
        box = QVBoxLayout(self._type_inner)
        box.setContentsMargins(0, 0, 0, 0)
        box.addWidget(QLabel("Show on this level"))
        self.type_checks: dict[str, QCheckBox] = {}
        for t in sorted(counts, key=lambda k: (k != plan.MATTER_TYPE, k)):
            name = "Matter / Thread" if t == plan.MATTER_TYPE else t
            cb = QCheckBox(f"{name} ({counts[t]})")
            cb.setChecked(t not in self.hidden)
            colour = TYPE_COLORS.get(t, "#9AA3AB")
            cb.setStyleSheet(
                f"QCheckBox {{ border-left: 10px solid {colour}; padding-left: 4px; }}"
            )
            cb.toggled.connect(partial(self.set_type_visible, t))
            self.type_checks[t] = cb
            box.addWidget(cb)
        row = QHBoxLayout()
        for text, hide_all in (("All", False), ("None", True)):
            b = QPushButton(text)
            b.clicked.connect(partial(self.set_all_types, counts, hide_all))
            row.addWidget(b)
        box.addLayout(row)
        box.addStretch(1)

    def set_type_visible(self, device_type: str, visible: bool) -> None:
        self.hidden.discard(device_type) if visible else self.hidden.add(device_type)
        self.refresh()

    def set_all_types(self, counts: dict[str, int], hide: bool) -> None:
        self.hidden = set(counts) if hide else set()
        self.refresh()

    # ---- editing ----------------------------------------------------------------------------
    def move_device(self, uuid: str, fx: float, fy: float, room: int | None) -> None:
        # Pin everything on this level where it is now, so moving one device never re-flows
        # the automatically placed others.
        for d in plan.layout(self.repo, self.current).devices:
            if d.uuid == uuid or d.manual:
                continue
            self._store(d.uuid, d.x, d.y)
        self._store(uuid, fx, fy)
        if room is not None:
            self._assign_room(uuid, room)
        self.repo.commit()
        self.refresh()

    def resize_rooms(self, changes: list[tuple[int, float, float, float, float]]) -> None:
        """A wall was dragged: save the rooms and carry hand-placed devices along with them."""
        if not changes:
            return
        old = self.repo.plan_rooms()
        lay = plan.layout(self.repo, self.current)
        for d in lay.devices:
            if not d.manual or d.room_id is None or d.room_id not in old:
                continue
            new = next((c for c in changes if c[0] == d.room_id), None)
            if new is None:
                continue
            o = old[d.room_id]
            fx = (d.x - o.x) / o.w if o.w else 0.5
            fy = (d.y - o.y) / o.h if o.h else 0.5
            self._store(d.uuid, new[1] + fx * new[3], new[2] + fy * new[4])
        for aid, x, y, w, h in changes:
            self.repo.set_plan_room(aid, x, y, w, h)
        self.repo.commit()
        self.refresh()

    def _store(self, uuid: str, x: float, y: float) -> None:
        if uuid.startswith(plan.MATTER_PREFIX):
            self.repo.set_matter_placement(uuid[len(plan.MATTER_PREFIX) :], self.current, x, y)
        else:
            self.repo.set_placement(uuid, self.current, x, y)

    def _assign_room(self, uuid: str, room: int) -> None:
        if uuid.startswith(plan.MATTER_PREFIX):
            inst = uuid[len(plan.MATTER_PREFIX) :]
            for g in group_matter_nodes(self.repo.list_matter_nodes()):
                if min(n.instance for n in g.nodes) == inst:
                    for n in g.nodes:
                        self.repo.set_matter_label(n.instance, g.label, room)
            return
        dev = next(d for d in self.repo.list_devices() if d.uuid == uuid)
        if dev.area_id != room:
            self.repo.assign_area([uuid], room)
            self.changed.emit()

    def auto_arrange(self) -> None:
        self.repo.clear_placements(self.current)
        self.repo.commit()
        self.refresh()

    def ask_size(self) -> None:
        lv = next(lv for lv in self.repo.plan_levels() if lv.id == self.current)
        w, ok = QInputDialog.getDouble(self, "Level size", "Width (m):", lv.width, 1, 200, 1)
        if not ok:
            return
        d, ok = QInputDialog.getDouble(self, "Level size", "Depth (m):", lv.depth, 1, 200, 1)
        if ok:
            self.repo.set_level_size(lv.id, w, d)
            self.repo.commit()
            self.refresh()

    def start_passage(self) -> None:
        self.view.pick_mode = True
        self.view.viewport().setCursor(Qt.CursorShape.CrossCursor)
        self.status.setText("Click the spot on the plan where the cable passes through the floors")

    def place_passage(self, fx: float, fy: float) -> None:
        self._edit_passage(None, fx, fy, "", {self.current})

    def _edit_passage(
        self, riser_id: int | None, fx: float, fy: float, name: str, checked: set[str]
    ) -> None:
        dlg = _PassageDialog(self.repo.plan_levels(), name, checked, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            self.refresh()
            return
        try:
            pname, plevels = dlg.values()
            self.repo.save_riser(riser_id, pname, fx, fy, plevels)
        except ValueError as exc:
            QMessageBox.warning(self, "Wire passage", str(exc))
        self.repo.commit()
        self.refresh()

    def move_riser(self, riser_id: int, fx: float, fy: float) -> None:
        self.repo.move_riser(riser_id, fx, fy)
        self.repo.commit()
        self.refresh()

    def _riser_menu(self, riser_id: int, pos: QPointF) -> None:
        r = next((r for r in self.repo.plan_risers() if r.id == riser_id), None)
        if r is None:
            return
        menu = QMenu(self)
        menu.addAction(
            "Edit passage…", partial(self._edit_passage, r.id, r.x, r.y, r.name, set(r.levels))
        )
        menu.addAction("Delete passage", partial(self.delete_passage, r.id))
        menu.exec(pos.toPoint())

    def delete_passage(self, riser_id: int) -> None:
        self.repo.delete_riser(riser_id)
        self.repo.commit()
        self.refresh()
