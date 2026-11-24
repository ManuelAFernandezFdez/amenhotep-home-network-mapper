import csv

from amenhotep.core.models import Observation, utcnow
from amenhotep.services import identity
from amenhotep.services.homemapper import import_homemapper, set_block
from amenhotep.store import db
from amenhotep.store.repo import Repository

HEAD = [
    "Name", "Place", "Home", "Zone/Floor", "Room", "Last Scanned", "Last Online", "Category",
    "Found via", "Manufacturer", "Model", "Firmware", "Serial Number", "Battery", "Setup Code",
    "Signal", "Thread Network", "Channel", "Thread Role", "Stability", "Thread Version",
    "Connected via", "Integration", "MAC Address", "IP Address",
]  # fmt: skip
V6 = "2001:1c00:704:bf0:6d30:e17f:b228:42da"


def write(path, rows):
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, HEAD)
        w.writeheader()
        for r in rows:
            w.writerow({h: r.get(h, "") for h in HEAD})
    return path


def make_repo():
    repo = Repository(db.connect(":memory:"))
    ts = utcnow()
    u = identity.resolve(
        repo, Observation(source="neigh", ip="192.0.2.5", mac="b8:27:eb:00:00:05", ts=ts)
    )
    repo.set_fields(u, {"display_name": "My own name", "notes": "keep me"}, user=True)
    repo.upsert_matter_node("F1-N1", "F1", "N1", [V6], None)
    repo.upsert_matter_node("F2-N1", "F2", "N1", [V6], None)
    repo.commit()
    return repo, u


ROWS = [
    {"Name": "Plug", "Room": "Kitchen", "Category": "Outlet", "Manufacturer": "Meross",
     "Model": "MSS210", "Firmware": "4.2.3", "Serial Number": "S1", "IP Address": "192.0.2.5"},
    {"Name": "Mouse", "Room": "Hallway", "Category": "Outlet", "Manufacturer": "Eve Systems",
     "Model": "Eve Energy", "Thread Network": "MyHome2", "Thread Role": "Router",
     "Stability": "restarts=3|attach=1", "IP Address": V6},
    {"Name": "Velux", "Room": "Attic", "Category": "Window Covering", "Manufacturer": "Velux",
     "Model": "shutter", "Serial Number": "V1", "Found via": "HomeKit"},
]  # fmt: skip


def test_merge_keeps_user_edits_and_puts_extras_in_notes(tmp_path):
    repo, u = make_repo()
    r = import_homemapper(repo, write(tmp_path / "HomeMapper Devices-1.csv", ROWS))
    assert (r.rows, r.matched, r.created, r.thread, r.conflicts) == (3, 1, 1, 1, 0)
    d = {x.uuid: x for x in repo.list_devices()}[u]
    assert d.display_name == "My own name"  # user edit kept
    assert d.vendor == "Meross" and d.device_type == "smart-plug"
    assert d.area == "Kitchen"
    assert d.notes.startswith("keep me")
    assert "Firmware: 4.2.3" in d.notes and "Home app name: Plug" in d.notes
    assert repo.device_by_serial("S1") == u
    assert any(x.display_name == "Velux" and x.area == "Attic" for x in repo.list_devices())


def test_thread_details_go_to_matter_notes_and_label(tmp_path):
    repo, _ = make_repo()
    import_homemapper(repo, write(tmp_path / "a.csv", ROWS))
    nodes = repo.list_matter_nodes()
    assert {n.label for n in nodes} == {"Mouse"}  # both fabrics of the same device
    assert all("Thread network: MyHome2" in (n.notes or "") for n in nodes)
    assert all("restarts=3, attach=1" in (n.notes or "") for n in nodes)


def test_reimport_is_idempotent_and_logged(tmp_path):
    repo, _ = make_repo()
    f = write(tmp_path / "HomeMapper Devices-1.csv", ROWS)
    import_homemapper(repo, f)
    count = len(repo.list_devices())
    notes = {d.uuid: d.notes for d in repo.list_devices()}
    import_homemapper(repo, f)
    assert len(repo.list_devices()) == count  # the HomeKit-only row matched by serial/name
    assert {d.uuid: d.notes for d in repo.list_devices() if d.uuid in notes} == notes
    logs = repo.list_imports()
    assert [i.filename for i in logs] == ["HomeMapper Devices-1.csv"] * 2


def test_identity_conflict_changes_nothing_but_notes(tmp_path):
    repo, u = make_repo()
    repo.set_fields(u, {"vendor": "Meross", "model": "MSS210"})
    bad = [{"Name": "Awning", "Category": "Window Covering", "Manufacturer": "Somfy",
            "Model": "Awning", "IP Address": "192.0.2.5"}]  # fmt: skip
    r = import_homemapper(repo, write(tmp_path / "c.csv", bad))
    assert r.conflicts == 1
    d = {x.uuid: x for x in repo.list_devices()}[u]
    assert d.vendor == "Meross" and d.model == "MSS210"
    assert "WARNING" in d.notes


def test_bad_file_rejected(tmp_path):
    repo, _ = make_repo()
    p = tmp_path / "x.csv"
    p.write_text("a,b\n1,2\n")
    try:
        import_homemapper(repo, p)
    except ValueError as exc:
        assert "HomeMapper" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_block_replaced_not_duplicated():
    one = set_block("mine", "f.csv", ["a: 1"])
    two = set_block(one, "f.csv", ["a: 2"])
    assert two.count("[HomeMapper import") == 1 and "a: 2" in two and two.startswith("mine")
    assert set_block(two, "f.csv", []) == "mine"
