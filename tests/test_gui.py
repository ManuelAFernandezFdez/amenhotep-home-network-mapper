import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PySide6.QtCore import Qt  # noqa: E402

from amenhotep.collectors.nmap import NmapCollector  # noqa: E402
from amenhotep.core.models import Observation  # noqa: E402
from amenhotep.gui.main_window import MainWindow  # noqa: E402
from amenhotep.gui.models import COLUMNS, DeviceFilterProxy, DeviceTableModel  # noqa: E402
from amenhotep.services import identity  # noqa: E402
from amenhotep.services.scan import ScanService  # noqa: E402
from amenhotep.store import db  # noqa: E402
from amenhotep.store.repo import Repository  # noqa: E402

pytestmark = pytest.mark.gui

COL = {name: i for i, (name, _, _) in enumerate(COLUMNS)}


class NoNeigh:
    def collect(self):
        return []


def seed(repo):
    for ip, mac, host, facts in [
        ("192.0.2.9", "b8:27:eb:00:00:09", "pi", {"os_family": "linux", "os_accuracy": 95}),
        ("192.0.2.100", "00:17:88:aa:bb:cc", "hue", {"hap_category": 2}),
        ("192.0.2.20", "da:11:22:33:44:55", None, {}),
    ]:
        identity.resolve(repo, Observation(source="t", ip=ip, mac=mac, hostname=host, facts=facts))
    repo.commit()


@pytest.fixture
def window(qtbot, tmp_path):
    path = tmp_path / "gui.db"
    conn = db.connect(path)
    seed(Repository(conn))
    conn.close()
    w = MainWindow(path)
    qtbot.addWidget(w)
    w.edit_mode.set(True)  # the app starts read-only; most tests exercise editing
    return w


@pytest.fixture
def readonly_window(qtbot, tmp_path):
    path = tmp_path / "ro.db"
    conn = db.connect(path)
    seed(Repository(conn))
    conn.close()
    w = MainWindow(path)
    qtbot.addWidget(w)
    return w


def make_factory(xml, runner=None):
    def factory(repo, progress):
        r = runner or (lambda c, t: (0, xml, ""))
        return ScanService(
            repo,
            nmap=NmapCollector(runner=r, nmap_path="/usr/bin/nmap"),
            neigh=NoNeigh(),
            discovery=[],
            progress=progress,
        )

    return factory


# ---- models ----------------------------------------------------------
def test_table_model_and_numeric_ip_sort(window):
    proxy = window.devices.proxy
    proxy.sort(COL["IP"], Qt.SortOrder.AscendingOrder)
    ips = [proxy.index(r, COL["IP"]).data() for r in range(proxy.rowCount())]
    assert ips == ["192.0.2.9", "192.0.2.20", "192.0.2.100"]  # numeric, not lexical


def test_filters(window):
    p = window.devices.proxy
    assert p.rowCount() == 3
    p.set_filters(text="hue")
    assert p.rowCount() == 1
    p.set_filters(text="", unclassified_only=True)
    assert p.rowCount() == 1  # the random-MAC device with no evidence
    p.set_filters(unclassified_only=False, os_family="linux")
    assert p.rowCount() == 1
    p.set_filters(os_family="", device_type="hub")
    assert p.rowCount() == 1


def test_edited_cells_are_italic_with_tooltip(window):
    tab = window.devices
    uid = tab.model.device_at(0).uuid
    tab.apply_to([uid], {"vendor": "Mine"})
    row = next(r for r in range(tab.model.rowCount()) if tab.model.device_at(r).uuid == uid)
    idx = tab.model.index(row, COL["Vendor"])
    assert idx.data(Qt.ItemDataRole.FontRole).italic()
    assert "Edited by you" in idx.data(Qt.ItemDataRole.ToolTipRole)
    assert tab.model.index(row, COL["Type"]).data(Qt.ItemDataRole.FontRole) is None


def test_standalone_model_and_proxy():
    model, proxy = DeviceTableModel(), DeviceFilterProxy()
    proxy.setSourceModel(model)
    assert proxy.rowCount() == 0


# ---- detail panel + editing -----------------------------------------
def select_row_with_ip(tab, ip):
    for r in range(tab.proxy.rowCount()):
        if tab.proxy.index(r, COL["IP"]).data() == ip:
            tab.table.selectRow(r)
            return
    raise AssertionError(ip)


def test_detail_edit_locks_only_changed_fields(window):
    tab = window.devices
    select_row_with_ip(tab, "192.0.2.9")
    d = tab.detail
    assert d.isEnabled() and d.collect_changes() == {}  # untouched => nothing locked
    d.name.setText("Garage Pi")
    d.mode.setCurrentText("roaming")
    d._save()
    dev = next(x for x in tab.repo.list_devices() if x.ip == "192.0.2.9")
    assert dev.display_name == "Garage Pi" and dev.location_mode == "roaming"
    assert set(dev.locked_fields) == {"display_name", "location_mode"}
    # selection survived the refresh and the panel shows the lock
    assert "display_name" in d.lock_note.text()
    assert d.evidence.rowCount() > 0


def test_unlock_lets_scans_update_again(window):
    tab = window.devices
    select_row_with_ip(tab, "192.0.2.9")
    tab.detail.os.setCurrentText("embedded")
    tab.detail._save()
    tab.detail._unlock()
    dev = next(x for x in tab.repo.list_devices() if x.ip == "192.0.2.9")
    assert dev.locked_fields == []
    identity.resolve(
        tab.repo,
        Observation(
            source="t",
            ip="192.0.2.9",
            mac="b8:27:eb:00:00:09",
            facts={"os_family": "linux", "os_accuracy": 95},
        ),
    )
    assert tab.repo.get_field(dev.uuid, "os_family") == "linux"


def test_bulk_edit(window):
    tab = window.devices
    tab.table.selectAll()
    assert len(tab.selected_uuids()) == 3
    assert not tab.detail.isEnabled() and "3 devices" in tab.detail.title.text()
    tab.apply_to(tab.selected_uuids(), {"device_type": "other"})
    assert {d.device_type for d in tab.repo.list_devices()} == {"other"}


def test_lan_text_is_never_rich_text(window):
    tab = window.devices
    evil = "<img src=x onerror=alert(1)><b>boom</b>"
    identity.resolve(
        tab.repo, Observation(source="t", ip="192.0.2.77", hostname=evil, mac="aa:bb:cc:00:00:77")
    )
    tab.repo.commit()
    tab.refresh()
    select_row_with_ip(tab, "192.0.2.77")
    assert tab.detail.title.textFormat() == Qt.TextFormat.PlainText
    assert tab.detail.hostname.textFormat() == Qt.TextFormat.PlainText
    assert tab.detail.title.text() == evil  # shown literally


# ---- scan tab --------------------------------------------------------
def test_scan_from_gui_adds_devices_and_history(qtbot, tmp_path, nmap_xml):
    w = MainWindow(tmp_path / "s.db", factory=make_factory(nmap_xml))
    qtbot.addWidget(w)
    w.scans.target.setText("192.0.2.0/24")
    with qtbot.waitSignal(w.scans.scanFinished, timeout=10000):
        w.scans.start()
        assert not w.scans.start_btn.isEnabled() and w.scans.cancel_btn.isEnabled()
    assert w.scans.start_btn.isEnabled() and not w.scans.is_running()
    assert len(w.repo.list_devices()) == 3
    assert w.devices.model.rowCount() == 3  # refreshed automatically
    assert w.scans.history.rowCount() == 1
    assert w.scans.history.item(0, 4).text() == "done"
    assert "devices known" in w.statusBar().currentMessage()


def test_cancel_stops_scan(qtbot, tmp_path, nmap_xml):
    holder = {}

    def slow_runner(cmd, timeout):
        end = time.monotonic() + 10
        while not holder["svc"].cancel.is_set() and time.monotonic() < end:
            time.sleep(0.02)
        return 0, nmap_xml, ""

    def factory(repo, progress):
        holder["svc"] = make_factory(nmap_xml, slow_runner)(repo, progress)
        return holder["svc"]

    w = MainWindow(tmp_path / "c.db", factory=factory)
    qtbot.addWidget(w)
    w.scans.target.setText("192.0.2.0/24")
    with qtbot.waitSignal(w.scans.scanFinished, timeout=10000):
        w.scans.start()
        qtbot.waitUntil(lambda: "svc" in holder, timeout=5000)
        w.scans.cancel()
    assert w.scans.status.text() == "Scan cancelled"
    assert w.scans.history.item(0, 4).text() == "cancelled"
    assert w.repo.list_devices() == []  # nothing half-written


def test_failed_scan_is_reported_not_raised(qtbot, tmp_path):
    def bad(cmd, timeout):
        return 1, "", "boom"

    w = MainWindow(tmp_path / "f.db", factory=make_factory("", bad))
    qtbot.addWidget(w)
    w.scans.target.setText("192.0.2.0/24")
    w.scans.start()
    qtbot.waitUntil(lambda: not w.scans.is_running(), timeout=10000)
    assert w.scans.status.text().startswith("Scan failed")
    assert w.scans.start_btn.isEnabled()


@pytest.mark.parametrize("bad", ["8.8.8.0/24", "nonsense", "10.0.0.0/8"])
def test_invalid_target_is_refused_without_thread(qtbot, tmp_path, bad):
    w = MainWindow(tmp_path / "t.db")
    qtbot.addWidget(w)
    w.scans.target.setText(bad)
    w.scans.start()
    assert not w.scans.is_running()
    assert w.scans.status.text().startswith("Cannot scan")


def test_closing_during_scan_is_clean(qtbot, tmp_path, nmap_xml):
    holder = {}

    def slow_runner(cmd, timeout):
        end = time.monotonic() + 10
        while not holder["svc"].cancel.is_set() and time.monotonic() < end:
            time.sleep(0.02)
        return 0, nmap_xml, ""

    def factory(repo, progress):
        holder["svc"] = make_factory(nmap_xml, slow_runner)(repo, progress)
        return holder["svc"]

    w = MainWindow(tmp_path / "x.db", factory=factory)
    qtbot.addWidget(w)
    w.scans.target.setText("192.0.2.0/24")
    w.scans.start()
    qtbot.waitUntil(lambda: "svc" in holder, timeout=5000)
    w.close()
    assert not w.scans.is_running()


def test_branding_icon_header_and_about(window, qtbot):
    from amenhotep.gui.branding import AboutDialog

    assert not window.windowIcon().isNull()
    assert window.header.tagline.text() == "Nothing stays hidden from Amun."
    assert not window.header.logo.pixmap().isNull()
    about = AboutDialog(window)
    qtbot.addWidget(about)
    assert "Over Thread" in about.findChildren(type(window.header.title))[1].text()


def test_packaged_logo_matches_assets():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    for src, packaged in (
        ("amenhotep-logo.svg", "logo.svg"),
        ("amenhotep-logo-wordmark.svg", "logo-wordmark.svg"),
    ):
        assert (root / "assets" / src).read_text() == (
            root / "src/amenhotep/data" / packaged
        ).read_text()


def test_scan_tab_imports_a_file_and_lists_it(window, tmp_path):
    from tests.test_homemapper import ROWS, write

    path = write(tmp_path / "HomeMapper Devices-9.csv", ROWS)
    result = window.scans.import_file(str(path))
    assert result is not None and result.rows == 3
    assert window.scans.imports.item(0, 0).text() == "HomeMapper Devices-9.csv"
    assert window.scans.imports.item(0, 2).text() == "3"


def test_topology_tab_drop_links_device_to_switch(window):
    from amenhotep.services import topology

    repo = window.repo
    sw = topology.add_switch(repo, "S8", "tp-link-8")
    dev = repo.list_devices()[0].uuid
    assert window.topology.drop_link(dev, sw, port="2")
    assert repo.list_links()[0].port == "2"
    window.topology.refresh()
    assert "1 links" in window.topology.summary.text()


def test_house_tab_move_into_room_and_passage(window):
    tab = window.plan
    uid = window.repo.list_devices()[0].uuid
    kitchen = window.repo.area_by_name("Kitchen").id
    tab.select_level("ground")
    tab.move_device(uid, 0.1, 0.1, kitchen)
    dev = next(d for d in window.repo.list_devices() if d.uuid == uid)
    assert dev.area_id == kitchen
    assert window.repo.plan_placements()[uid] == ("ground", 0.1, 0.1)
    window.repo.save_riser(None, "Duct", 0.5, 0.5, ["ground", "first"])
    tab.select_level("first")
    assert len(tab.selector.risers) == 1
    tab.delete_passage(tab.repo.plan_risers()[0].id)
    assert tab.repo.plan_risers() == []


def test_house_tab_drag_a_wall_with_the_mouse(window):
    from PySide6.QtCore import QEvent, QPointF
    from PySide6.QtGui import QMouseEvent

    tab = window.plan
    tab.select_level("ground")
    v = tab.view
    vp = v.viewport()

    def ev(kind, pt, btn=Qt.MouseButton.LeftButton, held=Qt.MouseButton.LeftButton):
        return QMouseEvent(
            kind,
            QPointF(pt),
            QPointF(vp.mapToGlobal(pt)),
            btn,
            held,
            Qt.KeyboardModifier.NoModifier,
        )

    def at(fx):
        return v.mapFromScene(QPointF(v._rect.width() * fx, v._rect.height() * 0.3))

    none = Qt.MouseButton.NoButton
    window.show()
    from PySide6.QtWidgets import QApplication

    QApplication.sendEvent(vp, ev(QEvent.Type.MouseButtonPress, at(0.5)))
    QApplication.sendEvent(vp, ev(QEvent.Type.MouseMove, at(0.35)))
    QApplication.sendEvent(
        vp, ev(QEvent.Type.MouseButtonRelease, at(0.35), btn=Qt.MouseButton.LeftButton, held=none)
    )
    kitchen = window.repo.area_by_name("Kitchen").id
    assert abs(window.repo.plan_rooms()[kitchen].w - (0.35 - 0.02)) < 0.02


def test_topology_has_area_column_and_sorts_by_type_and_area(window):
    from amenhotep.gui.topology_tab import COL_AREA, COL_TYPE, COLUMNS

    tab = window.topology
    assert COLUMNS[COL_AREA] == "Area" and COLUMNS[COL_TYPE] == "Type"
    repo = window.repo
    devs = repo.list_devices()
    repo.assign_area([devs[0].uuid], repo.area_by_name("Kitchen").id)
    repo.assign_area([devs[1].uuid], repo.area_by_name("Living room").id)
    tab.refresh()

    def column(col):
        group = tab.tree.topLevelItem(tab.tree.topLevelItemCount() - 1)
        return [group.child(i).text(col) for i in range(group.childCount())]

    tab.sort_by(COL_AREA)  # ascending
    asc = column(COL_AREA)
    filled = [a for a in asc if a]
    assert filled == sorted(filled) and asc[: len(filled)] == filled  # empty areas last
    tab.sort_by(COL_AREA)  # descending
    desc = column(COL_AREA)
    assert [a for a in desc if a] == sorted(filled, reverse=True) and not desc[0] == ""
    tab.sort_by(COL_AREA)  # third click: back to the default order
    assert tab.sort_col is None
    tab.sort_by(COL_TYPE)
    types = column(COL_TYPE)
    assert types == sorted(types)


def test_app_starts_read_only_and_the_checkbox_switches_every_tab(readonly_window):
    w = readonly_window
    w.devices.select_uuids([w.repo.list_devices()[0].uuid])  # an enabled detail panel to look at
    assert not w.edit_box.isChecked() and not w.edit_mode.enabled
    tabs = (w.devices, w.home, w.plan, w.topology, w.scans)
    assert all(
        not t.editable if hasattr(t, "editable") else not t.import_btn.isEnabled() for t in tabs
    )
    assert not w.devices.detail.save_btn.isEnabled() and w.devices.detail.name.isReadOnly()
    assert not w.plan.add_btn.isEnabled() and not w.plan.view.editable
    assert not w.topology.add4.isEnabled() and not w.scans.import_btn.isEnabled()
    w.edit_box.setChecked(True)
    assert w.edit_mode.enabled and w.devices.detail.save_btn.isEnabled()
    assert (
        w.plan.add_btn.isEnabled()
        and w.topology.add4.isEnabled()
        and w.scans.import_btn.isEnabled()
    )
    assert w.plan.view.editable and w.plan.info.editable
    w.edit_box.setChecked(False)
    assert not w.plan.view.editable and not w.devices.detail.save_btn.isEnabled()


def test_read_only_blocks_dragging_in_the_house_view(readonly_window):
    w = readonly_window
    w.repo.assign_area([w.repo.list_devices()[0].uuid], w.repo.area_by_name("Kitchen").id)
    w.repo.commit()
    w.plan.select_level("ground")
    markers = [i for i in w.plan.view._scene.items() if hasattr(i, "dev")]
    assert markers and not any(m.flags() & m.GraphicsItemFlag.ItemIsMovable for m in markers)
    w.edit_mode.set(True)
    markers = [i for i in w.plan.view._scene.items() if hasattr(i, "dev")]
    assert all(m.flags() & m.GraphicsItemFlag.ItemIsMovable for m in markers)


def test_house_field_table_lists_fields_and_edits_them(window):
    from PySide6.QtWidgets import QComboBox

    tab = window.plan
    repo = window.repo
    uid = repo.list_devices()[0].uuid
    tab.selected_uuid = uid
    tab.select_level("ground")
    tab._show_info()
    labels = [tab.info.item(r, 0).text() for r in range(tab.info.rowCount())]
    assert {"Name", "Type", "Vendor", "Area", "IP", "MAC", "Notes"} <= set(labels)
    row = labels.index("Name")
    tab.info.item(row, 1).setText("Edited here")  # edit the value cell
    from PySide6.QtWidgets import QApplication

    QApplication.processEvents()
    import time

    time.sleep(0.05)
    QApplication.processEvents()
    dev = next(d for d in repo.list_devices() if d.uuid == uid)
    assert dev.display_name == "Edited here" and "display_name" in dev.locked_fields
    area_row = [tab.info.item(r, 0).text() for r in range(tab.info.rowCount())].index("Area")
    combo = tab.info.cellWidget(area_row, 1)
    assert isinstance(combo, QComboBox)
    combo.setCurrentIndex(combo.findText("Kitchen · Ground floor"))
    time.sleep(0.05)
    QApplication.processEvents()
    assert next(d for d in repo.list_devices() if d.uuid == uid).area == "Kitchen"


def test_house_field_table_is_read_only_when_editing_is_off(readonly_window):
    tab = readonly_window.plan
    uid = readonly_window.repo.list_devices()[0].uuid
    tab.selected_uuid = uid
    tab._show_info()
    name_item = tab.info.item(0, 1)
    assert not (name_item.flags() & Qt.ItemFlag.ItemIsEditable)
    combo = next(
        tab.info.cellWidget(r, 1) for r in range(tab.info.rowCount()) if tab.info.cellWidget(r, 1)
    )
    assert not combo.isEnabled()


def test_wires_follow_a_device_while_it_is_dragged(window):
    from PySide6.QtCore import QPointF

    tab = window.plan
    repo = window.repo
    a, b = repo.list_devices()[0].uuid, repo.list_devices()[1].uuid
    kitchen = repo.area_by_name("Kitchen").id
    repo.assign_area([a, b], kitchen)
    repo.set_link(b, a)
    tab.select_level("ground")
    view = tab.view
    assert len(view._lines) == 1
    line, _ = view._lines[0]
    marker = view._markers[b]
    marker.setPos(QPointF(10, 20))  # as a drag would
    assert (line.line().x1(), line.line().y1()) == (marker.pos().x(), marker.pos().y())
    moved_a = view._markers[a].pos()
    assert (line.line().x2(), line.line().y2()) == (moved_a.x(), moved_a.y())
