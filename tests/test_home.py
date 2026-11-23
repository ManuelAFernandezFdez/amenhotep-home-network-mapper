import pytest

from amenhotep.collectors.mdns import matter_nodes_from_services, observations_from_services
from amenhotep.core.models import Observation
from amenhotep.services import identity
from amenhotep.services.matter import group_matter_nodes
from amenhotep.services.scan import ScanService
from amenhotep.store import db
from amenhotep.store.repo import Repository

FAB1, FAB2 = "0C97C8149A770C81", "2D5292015870D000"
THREAD_A = "2001:1c00:704:bf0:ce35:6115:8e52:4b72"
THREAD_B = "2001:1c00:704:bf0:6d30:e17f:b228:42da"
POD_V6 = "2001:1c00:704:b00:c6a:921:481c:2724"


def svc(type_, name, addrs, txt=None):
    return {
        "type": type_,
        "name": f"{name}.{type_}",
        "server": "h.local.",
        "port": 5540,
        "addresses": addrs,
        "txt": txt or {},
    }


SERVICES = [
    svc("_matter._tcp.local.", f"{FAB1}-000000008FA3FCBD", [THREAD_A]),
    svc("_matter._tcp.local.", f"{FAB2}-000000009F35F5F1", [THREAD_A]),  # same device, 2nd fabric
    svc("_matter._tcp.local.", f"{FAB1}-00000000DD6A9326", [THREAD_B]),
    svc("_matter._tcp.local.", f"{FAB2}-00000000C609A6F6", [POD_V6, "fe80::1"]),  # HomePod
    svc("_matter._tcp.local.", "not-a-matter-instance", [THREAD_B]),
    svc(
        "_hap._tcp.local.",
        "HomePod",
        ["192.168.178.37", POD_V6],
        {"md": "HomePod", "ci": "10", "id": "AA:BB:CC:DD:EE:FF", "sf": "0"},
    ),
    svc(
        "_meshcop._udp.local.",
        "Kitchen",
        ["192.168.178.18", "fe80::2"],
        {"vn": "Apple", "mn": "BorderRouter", "nn": "MyHome2"},
    ),
]


def test_matter_nodes_parsed_and_linked_to_lan_host():
    nodes = {n["instance"]: n for n in matter_nodes_from_services(SERVICES)}
    assert len(nodes) == 4  # malformed instance name ignored
    pod = nodes[f"{FAB2}-00000000C609A6F6"]
    assert pod["host_ip"] == "192.168.178.37"  # matched through the shared IPv6 address
    thread = nodes[f"{FAB1}-000000008FA3FCBD"]
    assert thread["host_ip"] is None and thread["fabric"] == FAB1


def test_border_router_fact_from_meshcop():
    obs = {o.ip: o for o in observations_from_services(SERVICES)}
    assert obs["192.168.178.18"].facts["thread_border_router"] == {
        "network_name": "MyHome2",
        "vendor": "Apple",
        "model": "BorderRouter",
    }


def seed_matter(repo):
    pod = identity.resolve(
        repo,
        Observation(source="mdns", ip="192.168.178.37", facts={"hap_id": "AA", "hap_category": 10}),
    )
    for n in matter_nodes_from_services(SERVICES):
        host = repo.device_by_ip(n["host_ip"]) if n["host_ip"] else None
        repo.upsert_matter_node(n["instance"], n["fabric"], n["node"], n["addresses"], host)
    repo.commit()
    return pod


def test_grouping_merges_multi_admin_and_flags_thread(repo):
    seed_matter(repo)
    groups = group_matter_nodes(repo.list_matter_nodes())
    assert len(groups) == 3  # 2 Thread devices + the HomePod
    threads = [g for g in groups if g.likely_thread]
    assert len(threads) == 2
    two_fabrics = next(g for g in threads if THREAD_A in g.addresses)
    assert two_fabrics.fabrics == 2 and len(two_fabrics.nodes) == 2
    pod = next(g for g in groups if not g.likely_thread)
    assert pod.host_uuid and not pod.likely_thread


def test_matter_label_survives_rescan(repo):
    seed_matter(repo)
    inst = f"{FAB1}-000000008FA3FCBD"
    repo.set_matter_label(inst, "Kitchen plug 1", None)
    seed_matter(repo)  # a later scan sees the same node again
    node = next(n for n in repo.list_matter_nodes() if n.instance == inst)
    assert node.label == "Kitchen plug 1"


def test_border_router_and_homekit_rows(repo):
    for o in observations_from_services(SERVICES):
        identity.resolve(repo, o)
    repo.commit()
    br = repo.list_border_routers()
    assert [(b.ip, b.network_name, b.vendor) for b in br] == [
        ("192.168.178.18", "MyHome2", "Apple")
    ]
    hk = repo.list_homekit()
    assert len(hk) == 1 and hk[0].category == "Sensor" and hk[0].model == "HomePod"


def test_paired_flag_from_status_flags():
    obs = observations_from_services(
        [
            svc("_hap._tcp.local.", "A", ["192.168.1.5"], {"md": "X", "ci": "7", "sf": "0"}),
            svc("_hap._tcp.local.", "B", ["192.168.1.6"], {"md": "Y", "ci": "7", "sf": "1"}),
        ]
    )
    paired = {o.ip: o.facts["hap_paired"] for o in obs}
    assert paired == {"192.168.1.5": True, "192.168.1.6": False}


class FakeMdns:
    name = "mdns"

    def __init__(self):
        self.matter_nodes = matter_nodes_from_services(SERVICES)

    def collect(self, _t=None):
        return observations_from_services(SERVICES)


def test_scan_persists_matter_nodes(repo):
    import ipaddress

    from amenhotep.collectors.nmap import NmapCollector

    svc_ = ScanService(
        repo,
        nmap=NmapCollector(
            runner=lambda c, t: (0, "<nmaprun/>", ""), nmap_path="/usr/bin/nmap", raw_capable=False
        ),
        neigh=type("N", (), {"collect": lambda self: []})(),
        discovery=[FakeMdns()],
    )
    svc_.run([ipaddress.ip_network("192.168.178.0/24")], "standard")
    assert len(repo.list_matter_nodes()) == 4
    assert repo.list_border_routers()


@pytest.fixture
def window(qtbot, tmp_path):
    from amenhotep.gui.main_window import MainWindow

    path = tmp_path / "g.db"
    conn = db.connect(path)
    r = Repository(conn)
    seed_matter(r)
    for o in observations_from_services(SERVICES):
        identity.resolve(r, o)
    r.commit()
    conn.close()
    w = MainWindow(path)
    qtbot.addWidget(w)
    return w


def test_home_tab_shows_counts_and_naming(window):
    h = window.home
    assert "1 HomeKit accessories (0 not paired)" in h.summary.text()
    assert "3 Matter devices (2 on Thread)" in h.summary.text()
    assert h.routers.rowCount() == 1 and h.hap.rowCount() == 1
    two = next(g for g in h._matter if g.fabrics == 2)
    h.name_matter(two, "Kitchen plug 1")
    names = {h.matter.item(r, 0).text() for r in range(h.matter.rowCount())}
    assert "Kitchen plug 1" in names
    kitchen = next(a.id for a in h.repo.list_areas() if a.name == "Kitchen")
    h.place_matter(next(g for g in h._matter if g.label), kitchen)
    assert any(h.matter.item(r, 4).text() == "Kitchen" for r in range(h.matter.rowCount()))
