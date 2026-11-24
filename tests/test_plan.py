import pytest

from amenhotep.core.models import Observation, utcnow
from amenhotep.services import identity, plan
from amenhotep.store import db
from amenhotep.store.repo import Repository


@pytest.fixture
def repo():
    r = Repository(db.connect(":memory:"))
    ts = utcnow()
    for i in range(1, 5):
        identity.resolve(
            r, Observation(source="neigh", ip=f"192.0.2.{i}", mac=f"aa:00:00:00:00:0{i}", ts=ts)
        )
    plan.seed(r)
    return r


def dev(repo, n):
    return repo.device_by_ip(f"192.0.2.{n}")


def test_default_levels_and_rooms(repo):
    ids = [lv.id for lv in repo.plan_levels()]
    assert ids == ["second", "first", "ground", "back_garden", "front_garden", "roaming"]
    assert repo.area_by_name("Front garden") and repo.area_by_name("Back garden")
    assert repo.area_by_name("Mini-office")
    lay = plan.layout(repo, "second")
    assert {r[1] for r in lay.rooms} == {"Mini-office", "Second-floor bedroom"}
    assert len(plan.layout(repo, "first").rooms) == 3
    assert {r[1] for r in plan.layout(repo, "ground").rooms} == {"Kitchen", "Living room"}
    plan.seed(repo)  # idempotent
    assert len(repo.plan_levels()) == 6


def test_device_sits_in_its_room_and_unplaced_listed(repo):
    kitchen = repo.area_by_name("Kitchen").id
    repo.assign_area([dev(repo, 1)], kitchen)
    lay = plan.layout(repo, "ground")
    d = next(x for x in lay.devices if x.uuid == dev(repo, 1))
    room = next(r for r in lay.rooms if r[0] == kitchen)
    assert room[2] <= d.x <= room[2] + room[4] and room[3] <= d.y <= room[3] + room[5]
    assert len(plan.unplaced_devices(repo)) == 3
    repo.assign_area([dev(repo, 2)], repo.area_by_name("Roaming").id)
    assert plan.device_counts(repo)["roaming"] == 1


def test_manual_placement_wins_only_on_its_level(repo):
    repo.assign_area([dev(repo, 1)], repo.area_by_name("Kitchen").id)
    repo.set_placement(dev(repo, 1), "ground", 0.9, 0.1)
    d = plan.layout(repo, "ground").devices[0]
    assert (d.x, d.y, d.manual) == (0.9, 0.1, True)
    repo.assign_area([dev(repo, 1)], repo.area_by_name("Main bedroom").id)  # moved to first floor
    assert not plan.layout(repo, "first").devices[0].manual


def test_cross_floor_wire_needs_a_passage(repo):
    sw, ap = dev(repo, 1), dev(repo, 2)
    repo.assign_area([sw], repo.area_by_name("Kitchen").id)
    repo.assign_area([ap], repo.area_by_name("Main bedroom").id)
    repo.set_link(ap, sw)
    lay = plan.layout(repo, "first")
    assert [w.kind for w in lay.wires] == ["missing"] and lay.notes
    repo.save_riser(None, "Cable duct", 0.5, 0.5, ["ground", "first"])
    for level in ("ground", "first"):
        assert [w.kind for w in plan.layout(repo, level).wires] == ["wired"]
    assert plan.layout(repo, "second").wires == []
    assert [r.name for r in plan.layout(repo, "second").risers] == []


def test_wifi_repeater_needs_no_passage(repo):
    router, rep = dev(repo, 1), dev(repo, 2)
    repo.assign_area([router], repo.area_by_name("Kitchen").id)
    repo.assign_area([rep], repo.area_by_name("Third bedroom").id)
    repo.set_link(rep, router, medium="wifi")
    lay = plan.layout(repo, "first")
    assert lay.wires == [] and any("Wi-Fi link" in n for n in lay.notes)


def test_same_level_wires_and_riser_validation(repo):
    a, b = dev(repo, 1), dev(repo, 2)
    kitchen = repo.area_by_name("Kitchen").id
    repo.assign_area([a, b], kitchen)
    repo.set_link(b, a, port=None)
    assert [w.kind for w in plan.layout(repo, "ground").wires] == ["wired"]
    with pytest.raises(ValueError):
        repo.save_riser(None, "x", 0.1, 0.1, ["ground"])
    with pytest.raises(ValueError):
        repo.save_riser(None, "x", 0.1, 0.1, ["ground", "nowhere"])
    with pytest.raises(ValueError):
        repo.set_level_size("ground", 0, 5)


def test_veranda_and_attic_map_to_levels(repo):
    assert repo.plan_level_areas()[repo.area_by_name("Veranda").id] == "back_garden"
    repo.assign_area([dev(repo, 1)], repo.area_by_name("Veranda").id)
    assert plan.device_counts(repo)["back_garden"] == 1


def test_moving_one_device_does_not_reflow_the_others(repo):
    from amenhotep.gui.plan_tab import PlanTab

    living = repo.area_by_name("Living room").id
    for n in range(1, 5):
        repo.assign_area([dev(repo, n)], living)
    before = {d.uuid: (d.x, d.y) for d in plan.layout(repo, "ground").devices}
    tab = PlanTab(repo)
    tab.select_level("ground")
    tab.move_device(dev(repo, 2), 0.7, 0.7, living)
    after = {d.uuid: (d.x, d.y) for d in plan.layout(repo, "ground").devices}
    assert after[dev(repo, 2)] == (0.7, 0.7)
    assert {u: p for u, p in after.items() if u != dev(repo, 2)} == {
        u: p for u, p in before.items() if u != dev(repo, 2)
    }


def test_type_filter_hides_devices_and_their_wires(repo):
    a, b = dev(repo, 1), dev(repo, 2)
    repo.set_fields(a, {"device_type": "switch"})
    repo.set_fields(b, {"device_type": "camera"})
    kitchen = repo.area_by_name("Kitchen").id
    repo.assign_area([a, b], kitchen)
    repo.set_link(b, a)
    full = plan.layout(repo, "ground")
    assert full.type_counts == {"switch": 1, "camera": 1} and len(full.wires) == 1
    cut = plan.layout(repo, "ground", {"camera"})
    assert [d.device_type for d in cut.devices] == ["switch"] and cut.wires == []
    assert cut.type_counts == full.type_counts  # the panel still lists hidden types


def test_matter_devices_appear_and_can_be_hidden(repo):
    repo.upsert_matter_node("F1-N1", "F1", "N1", ["2001:db8::1"], None)
    repo.set_matter_label("F1-N1", "Coffee", repo.area_by_name("Kitchen").id)
    lay = plan.layout(repo, "ground")
    m = next(d for d in lay.devices if d.device_type == plan.MATTER_TYPE)
    assert m.name == "Coffee" and m.uuid == "matter:F1-N1"
    assert plan.layout(repo, "ground", {plan.MATTER_TYPE}).devices == []
    from amenhotep.gui.plan_tab import PlanTab

    tab = PlanTab(repo)
    tab.select_level("ground")
    tab.move_device(m.uuid, 0.2, 0.3, repo.area_by_name("Living room").id)
    moved = next(d for d in plan.layout(repo, "ground").devices if d.uuid == m.uuid)
    assert (moved.x, moved.y, moved.manual) == (0.2, 0.3, True)
    assert repo.list_matter_nodes()[0].area == "Living room"


def test_selected_item_fields(repo):
    from amenhotep.gui.plan_tab import PlanTab

    a, b = dev(repo, 1), dev(repo, 2)
    repo.assign_area([a, b], repo.area_by_name("Kitchen").id)
    repo.set_fields(a, {"display_name": "Switch X", "notes": "my note"}, user=True)
    repo.set_link(b, a, port="2")
    fields = {f.key: f for f in plan.item_fields(repo, b)}
    assert fields["uplink"].value == "Switch X, port 2 (wired)" and not fields["uplink"].editable
    assert (
        fields["area_id"].kind == "choice" and fields["display_name"].editable
    )
    assert {f.key: f.value for f in plan.item_fields(repo, a)}["notes"] == "my note"
    tab = PlanTab(repo)
    tab.select_level("ground")
    tab.view.select_uuid(a)
    assert tab.selected_uuid == a and tab.info.rowCount() > 10
    tab.refresh()  # selection survives a redraw
    assert tab.info.rowCount() > 10


def test_apply_field_edits_and_read_only_fields(repo):
    u = dev(repo, 1)
    assert plan.apply_field(repo, u, "area_id", repo.area_by_name("Kitchen").id) is True
    plan.apply_field(repo, u, "vendor", "ACME")
    plan.apply_field(repo, u, "serial", "S-1")
    plan.apply_field(repo, u, "is_infrastructure", True)
    d = next(x for x in repo.list_devices() if x.uuid == u)
    assert (d.area, d.vendor, d.is_infrastructure) == ("Kitchen", "ACME", True)
    assert repo.device_by_serial("S-1") == u and "vendor" in d.locked_fields
    with pytest.raises(ValueError):
        plan.apply_field(repo, u, "mac", "x")  # read-only


def test_matter_item_fields_edit(repo):
    repo.upsert_matter_node("F1-N1", "F1", "N1", ["2001:db8::1"], None)
    repo.set_matter_label("F1-N1", "Coffee", repo.area_by_name("Kitchen").id)
    uid = "matter:F1-N1"
    assert {f.key for f in plan.item_fields(repo, uid)} >= {
        "label",
        "area_id",
        "notes",
        "addresses",
    }
    plan.apply_field(repo, uid, "label", "Coffee plug")
    plan.apply_field(repo, uid, "notes", "hello")
    n = repo.list_matter_nodes()[0]
    assert (n.label, n.notes, n.area) == ("Coffee plug", "hello", "Kitchen")


ROOMS = {1: (0.02, 0.02, 0.48, 0.78), 2: (0.50, 0.02, 0.48, 0.78)}


def test_wall_between_rooms_found_and_moved():
    ws = plan.walls(ROOMS)
    assert len(ws) == 1 and ws[0].orient == "v" and ws[0].before == [1] and ws[0].after == [2]
    moved = plan.move_wall(ROOMS, ws[0], 0.7)
    assert moved[1][2] == pytest.approx(0.68) and moved[2][0] == 0.7
    assert moved[2][0] + moved[2][2] == pytest.approx(0.98)  # outer edge unchanged
    far = plan.move_wall(ROOMS, ws[0], 5)  # clamped: neither room may vanish
    assert far[2][2] == pytest.approx(plan.MIN_ROOM)


def test_wall_shared_by_a_row_of_rooms_moves_together():
    rooms = {
        1: (0, 0, 0.5, 0.4),
        2: (0.5, 0, 0.5, 0.4),
        3: (0, 0.4, 0.5, 0.4),
        4: (0.5, 0.4, 0.5, 0.4),
    }
    vertical = next(w for w in plan.walls(rooms) if w.orient == "v")
    assert sorted(vertical.before) == [1, 3] and sorted(vertical.after) == [2, 4]
    assert len(plan.walls(rooms)) == 2  # plus the horizontal wall


def test_dragging_a_wall_saves_rooms_and_carries_placed_devices(repo):
    from amenhotep.gui.plan_tab import PlanTab

    kitchen, living = repo.area_by_name("Kitchen").id, repo.area_by_name("Living room").id
    repo.assign_area([dev(repo, 1)], living)
    tab = PlanTab(repo)
    tab.select_level("ground")
    rooms = repo.plan_rooms()
    wall = plan.walls({a: (r.x, r.y, r.w, r.h) for a, r in rooms.items()})[0]
    d0 = plan.layout(repo, "ground").devices[0]
    repo.set_placement(d0.uuid, "ground", d0.x, d0.y)  # hand-placed
    moved = plan.move_wall({a: (r.x, r.y, r.w, r.h) for a, r in rooms.items()}, wall, 0.3)
    tab.resize_rooms([(a, *r) for a, r in moved.items()])
    new = repo.plan_rooms()
    assert new[kitchen].w == pytest.approx(0.3 - rooms[kitchen].x)
    d1 = plan.layout(repo, "ground").devices[0]
    r = new[living]
    assert r.x <= d1.x <= r.x + r.w  # the device stayed inside its room
