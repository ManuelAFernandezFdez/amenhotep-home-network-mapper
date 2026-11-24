import pytest

from amenhotep.core.models import Observation, utcnow
from amenhotep.services import identity, topology
from amenhotep.store import db
from amenhotep.store.repo import Repository


@pytest.fixture
def repo():
    r = Repository(db.connect(":memory:"))
    ts = utcnow()
    for ip, mac in [("192.0.2.1", "aa:00:00:00:00:01"), ("192.0.2.5", "aa:00:00:00:00:05"),
                    ("192.0.2.6", "aa:00:00:00:00:06")]:  # fmt: skip
        identity.resolve(r, Observation(source="neigh", ip=ip, mac=mac, ts=ts))
    r.set_fields(r.device_by_ip("192.0.2.1"), {"device_type": "router", "display_name": "Router"})
    r.commit()
    return r


def uid(repo, ip):
    return repo.device_by_ip(ip)


def test_switch_template_and_tree(repo):
    sw = topology.add_switch(repo, "Living switch", "tp-link-8", uplink="Router")
    repo.set_link(uid(repo, "192.0.2.5"), sw, port="3")
    topo = topology.build(repo)
    assert [n.name for n in topo.roots] == ["Router"]
    switch = topo.roots[0].children[0]
    assert switch.name == "Living switch" and topo.ports[sw] == 8
    assert topo.used_ports(switch) == 1
    text = "\n".join(topology.render(topo))
    assert "(1/8 ports used)" in text and "port 3" in text and "No uplink yet (1)" in text


def test_port_rules_and_loops(repo):
    sw = topology.add_switch(repo, "S", "tp-link-4")
    a, b = uid(repo, "192.0.2.5"), uid(repo, "192.0.2.6")
    repo.set_link(a, sw, port="1")
    with pytest.raises(ValueError, match="already used"):
        repo.set_link(b, sw, port="1")
    with pytest.raises(ValueError, match="1-4"):
        repo.set_link(b, sw, port="9")
    with pytest.raises(ValueError, match="loop"):
        repo.set_link(sw, a)  # a is below sw: sw below a would be a cycle
    with pytest.raises(ValueError):
        repo.set_link(a, a)


def test_relink_moves_and_unlink(repo):
    sw = topology.add_switch(repo, "S", "tp-link-4")
    a = uid(repo, "192.0.2.5")
    repo.set_link(a, sw, port="2")
    repo.set_link(a, uid(repo, "192.0.2.1"), medium="wifi")
    assert len(repo.list_links()) == 1 and repo.list_links()[0].port is None
    repo.remove_link(a)
    assert repo.list_links() == []


def test_router_client_list_and_suggestions(repo, tmp_path):
    f = tmp_path / "clients.txt"
    f.write_text(
        "host1 192.0.2.5 AA-00-00-00-00-05 WiFi 5GHz\n"
        "host2 192.0.2.6 aa:00:00:00:00:06 Ethernet\nnoise\n"
    )
    assert topology.import_router_clients(repo, f) == (2, 2)
    found = topology.suggest_uplinks(repo)
    assert {(s.medium) for s in found} == {"wifi", "wired"}
    assert repo.list_links() == []  # suggestions are never silent
    topology.apply_suggestions(repo, found)
    assert all(not lk.confirmed and lk.source == "inferred" for lk in repo.list_links())
    # once a switch exists the "wired -> router" guess is withdrawn
    topology.add_switch(repo, "S", "tp-link-4")
    assert topology.suggest_uplinks(repo) == []


def test_unknown_template_and_name_lookup(repo):
    with pytest.raises(ValueError):
        topology.add_switch(repo, "x", "cisco")
    assert repo.device_by_ip_or_name("router") == uid(repo, "192.0.2.1")
