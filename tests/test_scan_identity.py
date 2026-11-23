import ipaddress
from pathlib import Path

import pytest

from amenhotep.collectors.nmap import NmapCollector, NmapError
from amenhotep.core.models import Observation
from amenhotep.services import identity
from amenhotep.services.scan import ScanService
from amenhotep.store import db

NET = [ipaddress.ip_network("192.0.2.0/24")]


class FakeNeigh:
    def __init__(self, obs):
        self._obs = obs

    def collect(self):
        return self._obs


def make_service(repo, xml, neigh=()):
    def runner(cmd, timeout):
        return 0, xml, ""

    nmap = NmapCollector(runner=runner, nmap_path="/usr/bin/nmap")
    return ScanService(repo, nmap=nmap, neigh=FakeNeigh(list(neigh)), discovery=[])


def test_full_scan_persists_devices(repo, nmap_xml):
    result = make_service(repo, nmap_xml).run(NET, "standard")
    assert result.status == "done" and result.hosts_seen == 3 and result.new_devices == 3
    devices = {d.ip: d for d in repo.list_devices()}
    pi = devices["192.0.2.1"]
    assert pi.vendor == "Raspberry Pi Foundation" and pi.os_family == "linux"
    assert devices["192.0.2.40"].mac is None
    # randomised MAC flagged, no vendor guess
    assert devices["192.0.2.20"].vendor is None
    row = repo.conn.execute(
        "SELECT mac_random FROM interface WHERE mac='da:11:22:33:44:55'"
    ).fetchone()
    assert row["mac_random"] == 1


def test_rescan_is_idempotent(repo, nmap_xml):
    svc = make_service(repo, nmap_xml)
    svc.run(NET, "standard")
    second = svc.run(NET, "standard")
    assert second.new_devices == 0
    assert len(repo.list_devices()) == 3


def test_neigh_supplies_missing_mac(repo, nmap_xml):
    neigh = [Observation(source="neigh", ip="192.0.2.40", mac="00:17:88:aa:bb:cc")]
    make_service(repo, nmap_xml, neigh).run(NET, "standard")
    d = {x.ip: x for x in repo.list_devices()}["192.0.2.40"]
    assert d.mac == "00:17:88:aa:bb:cc" and d.vendor == "Philips Lighting BV"


def test_out_of_scope_observations_are_dropped(repo, nmap_xml):
    neigh = [Observation(source="neigh", ip="198.51.100.7", mac="aa:aa:aa:aa:aa:01")]
    result = make_service(repo, nmap_xml, neigh).run(NET, "standard")
    assert result.hosts_seen == 3


def test_ip_change_keeps_identity(repo):
    a = Observation(source="t", ip="192.0.2.50", mac="b8:27:eb:00:00:09")
    b = Observation(source="t", ip="192.0.2.51", mac="b8:27:eb:00:00:09")
    assert identity.resolve(repo, a) == identity.resolve(repo, b)
    assert len(repo.list_devices()) == 1 and repo.list_devices()[0].ip == "192.0.2.51"


def test_ip_reassigned_to_other_device(repo):
    first = identity.resolve(
        repo, Observation(source="t", ip="192.0.2.60", mac="b8:27:eb:00:00:0a")
    )
    second = identity.resolve(
        repo, Observation(source="t", ip="192.0.2.60", mac="b8:27:eb:00:00:0b")
    )
    assert first != second
    owners = repo.conn.execute("SELECT device_uuid FROM interface WHERE ip='192.0.2.60'").fetchall()
    assert [r["device_uuid"] for r in owners] == [second]


def test_manual_edits_win(repo, nmap_xml):
    svc = make_service(repo, nmap_xml)
    svc.run(NET, "standard")
    pi = {d.ip: d for d in repo.list_devices()}["192.0.2.1"]
    repo.set_fields(pi.uuid, {"os_family": "embedded", "display_name": "Garage Pi"}, user=True)
    repo.commit()
    svc.run(NET, "standard")
    again = {d.ip: d for d in repo.list_devices()}["192.0.2.1"]
    assert again.os_family == "embedded" and again.display_name == "Garage Pi"


def test_failed_scan_marks_status(repo):
    nmap = NmapCollector(runner=lambda c, t: (1, "", "boom"), nmap_path="/usr/bin/nmap")
    svc = ScanService(repo, nmap=nmap, neigh=FakeNeigh([]), discovery=[])
    with pytest.raises(NmapError):
        svc.run(NET, "quick")
    assert repo.conn.execute("SELECT status FROM scan").fetchone()["status"] == "failed"


def test_schema_copy_matches_model():
    root = Path(__file__).parents[1]
    assert (root / "model/schema.sql").read_text() == (
        root / "src/amenhotep/store/migrations/001_init.sql"
    ).read_text()


def test_db_file_is_private(tmp_path):
    p = tmp_path / "x" / "amenhotep.db"
    db.connect(p).close()
    assert (p.stat().st_mode & 0o777) == 0o600
