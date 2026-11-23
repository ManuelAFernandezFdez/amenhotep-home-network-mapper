import pytest

from amenhotep.core.models import Observation
from amenhotep.services import identity
from amenhotep.store import db
from amenhotep.store.repo import Repository
from tests.test_gui import COL, MainWindow, seed, select_row_with_ip


def area_id(repo, name):
    return next(a.id for a in repo.list_areas() if a.name == name)


@pytest.fixture
def two(repo):
    ids = [
        identity.resolve(
            repo, Observation(source="t", ip=f"192.0.2.{i}", mac=f"b8:27:eb:00:00:0{i}")
        )
        for i in (1, 2)
    ]
    repo.commit()
    return ids


def dev(repo, uid):
    return next(d for d in repo.list_devices() if d.uuid == uid)


def test_default_areas_seeded_with_hierarchy(repo):
    areas = {a.name: a for a in repo.list_areas()}
    assert areas["Main bedroom"].zone == "First floor" and areas["Main bedroom"].kind == "room"
    assert areas["Third bedroom"].zone == "First floor"
    assert areas["Garden"].kind == "zone" and areas["Garden"].zone is None
    assert areas["Main bedroom"].label == "Main bedroom · First floor"


def test_assign_and_unassign(repo, two):
    repo.assign_area(two, area_id(repo, "Kitchen"))
    d = dev(repo, two[0])
    assert d.area == "Kitchen" and d.zone == "Ground floor"
    assert d.area_label == "Kitchen · Ground floor"
    repo.assign_area(two[:1], None)
    assert dev(repo, two[0]).area_label == ""
    with pytest.raises(ValueError):
        repo.assign_area(two, 9999)


def test_s3_phone_clock_pinned_fixed_in_main_bedroom(repo, two):
    repo.set_fields(two[0], {"location_mode": "roaming"}, user=True)  # phones default to roaming
    repo.assign_area(two[:1], area_id(repo, "Main bedroom"), mode="fixed")
    d = dev(repo, two[0])
    assert d.location_mode == "fixed" and d.area == "Main bedroom"
    assert "location_mode" in d.locked_fields  # scans can never flip it back
    repo.set_fields(two[0], {"location_mode": "roaming"}, user=False)  # a scan tries
    assert dev(repo, two[0]).location_mode == "fixed"


def test_area_survives_rescan(repo, two):
    repo.assign_area(two, area_id(repo, "Garden"))
    repo.commit()
    identity.resolve(repo, Observation(source="nmap", ip="192.0.2.1", mac="b8:27:eb:00:00:01"))
    assert dev(repo, two[0]).area == "Garden"


def test_roaming_mode_and_zone_stay_in_sync(repo, two):
    repo.set_fields(two[0], {"location_mode": "roaming"}, user=True)
    assert dev(repo, two[0]).area == "Roaming"
    repo.set_fields(two[0], {"location_mode": "fixed"}, user=True)
    assert dev(repo, two[0]).area is None
    repo.assign_area(two[1:], area_id(repo, "Roaming"))
    assert dev(repo, two[1]).location_mode == "roaming"
    repo.assign_area(two[1:], area_id(repo, "Kitchen"), mode="fixed")
    repo.set_fields(two[1], {"location_mode": "roaming"}, user=True)
    assert dev(repo, two[1]).area == "Kitchen"  # an existing room is not overwritten


def test_manage_areas(repo, two):
    room = repo.add_area("Attic", "room", area_id(repo, "Second floor"))
    repo.assign_area(two[:1], room)
    repo.rename_area(room, "Loft")
    assert dev(repo, two[0]).area == "Loft"
    repo.delete_area(room)
    assert dev(repo, two[0]).area is None  # device survives, becomes unassigned
    for bad in (
        ("x", "room", None),
        ("x", "zone", 1),
        ("", "zone", None),
        ("a" * 65, "zone", None),
    ):
        with pytest.raises(ValueError):
            repo.add_area(*bad)


# ---- GUI -------------------------------------------------------------------------------------
@pytest.fixture
def window(qtbot, tmp_path):
    path = tmp_path / "gui.db"
    conn = db.connect(path)
    seed(Repository(conn))
    conn.close()
    w = MainWindow(path)
    qtbot.addWidget(w)
    return w


def test_detail_area_combo_saves_and_shows_in_column(window):
    tab = window.devices
    select_row_with_ip(tab, "192.0.2.9")
    d = tab.detail
    assert d.collect_changes() == {}
    d.area.setCurrentIndex(d.area.findText("Main bedroom · First floor"))
    d._save()
    select_row_with_ip(tab, "192.0.2.9")
    assert tab.proxy.index(tab.table.currentIndex().row(), COL["Area"]).data() == (
        "Main bedroom · First floor"
    )
    assert tab.detail.area.currentText() == "Main bedroom · First floor"
    assert tab.detail.collect_changes() == {}


def test_bulk_assign_pin_and_area_filter(window):
    tab = window.devices
    uuids = [d.uuid for d in tab.repo.list_devices() if d.ip in ("192.0.2.9", "192.0.2.100")]
    tab.assign_area(uuids, area_id(tab.repo, "Main bedroom"), pin=True)
    assert all(d.location_mode == "fixed" for d in tab.repo.list_devices() if d.uuid in uuids)
    shown = lambda: {tab.proxy.index(r, COL["IP"]).data() for r in range(tab.proxy.rowCount())}  # noqa: E731
    tab.proxy.set_filters(area="Main bedroom")
    assert shown() == {"192.0.2.9", "192.0.2.100"}
    tab.proxy.set_filters(area="First floor")  # a zone includes its rooms
    assert shown() == {"192.0.2.9", "192.0.2.100"}
    tab.proxy.set_filters(area="none")
    assert shown() == {"192.0.2.20"}
    tab.proxy.set_filters(area="")
    assert len(shown()) == 3
