from amenhotep.core.models import Observation
from amenhotep.services import identity
from amenhotep.services.satisfaction import Satisfaction, satisfaction
from tests.test_gui import MainWindow  # noqa: F401  (qtbot fixtures live there)
from tests.test_gui import seed as seed_gui


def test_messages():
    assert Satisfaction(0, 0).message().startswith("Amun has nothing to judge")
    assert Satisfaction(23, 23).message() == "Amun is satisfied: 23/23 devices known."
    assert Satisfaction(20, 23).message() == (
        "Amun is not satisfied: 20/23 devices known (3 still hidden)."
    )
    assert not Satisfaction(0, 0).satisfied


def test_unknown_type_means_not_known(repo):
    a = identity.resolve(repo, Observation(source="t", ip="192.0.2.1", mac="da:11:22:33:44:01"))
    identity.resolve(repo, Observation(source="t", ip="192.0.2.2", mac="da:11:22:33:44:02"))
    s = satisfaction(repo.list_devices())
    assert (s.known, s.total) == (0, 2)
    repo.set_fields(a, {"device_type": "printer"}, user=True)
    assert satisfaction(repo.list_devices()).known == 1


def test_status_bar_follows_edits_until_satisfied(qtbot, tmp_path):
    from amenhotep.store import db
    from amenhotep.store.repo import Repository

    path = tmp_path / "s.db"
    conn = db.connect(path)
    seed_gui(Repository(conn))
    conn.close()
    w = MainWindow(path)
    qtbot.addWidget(w)
    assert "not satisfied" in w.statusBar().currentMessage()
    unknown = [d.uuid for d in w.repo.list_devices() if d.device_type == "unknown"]
    w.devices.apply_to(unknown, {"device_type": "other"})
    assert w.statusBar().currentMessage() == "Amun is satisfied: 3/3 devices known."
