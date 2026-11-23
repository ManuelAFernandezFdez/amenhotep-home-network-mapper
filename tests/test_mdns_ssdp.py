import ipaddress

from amenhotep.collectors.mdns import clean_txt, hap_facts, observations_from_services
from amenhotep.collectors.nmap import NmapCollector
from amenhotep.collectors.ssdp import (
    location_allowed,
    parse_ssdp_response,
    parse_upnp_description,
)
from amenhotep.core.models import Observation
from amenhotep.services.scan import ScanService

HAP = {
    "type": "_hap._tcp.local.",
    "name": "Kitchen Light._hap._tcp.local.",
    "server": "kitchen-light.local.",
    "port": 51827,
    "addresses": ["192.0.2.31", "fe80::1"],
    "txt": {b"id": b"AA:BB:CC:DD:EE:01", b"md": b"TRADFRI bulb", b"ci": b"5", b"sf": b"0"},
}
INFO = {
    "type": "_device-info._tcp.local.",
    "name": "Bedroom iPad._device-info._tcp.local.",
    "server": "ipad.local.",
    "port": 0,
    "addresses": ["192.0.2.32"],
    "txt": {b"model": b"iPad13,1"},
}


def test_hap_txt_parsing():
    facts = hap_facts({"id": "AA:BB", "md": "Bulb", "ci": "5", "sf": "1"})
    assert facts == {
        "hap_id": "AA:BB",
        "hap_model": "Bulb",
        "hap_category": 5,
        "hap_paired": False,
    }  # sf bit0 set => unpaired
    assert hap_facts({"sf": "0"})["hap_paired"] is True


def test_clean_txt_handles_bytes_garbage_and_limits():
    txt = clean_txt({b"a": b"\xff\xfeok", "b": None, "c": "x" * 1000})
    assert len(txt["c"]) == 256 and txt["b"] == "" and txt["a"].endswith("ok")


def test_observations_from_services():
    obs = {o.ip: o for o in observations_from_services([HAP, INFO])}
    assert set(obs) == {"192.0.2.31", "192.0.2.32"}  # IPv6 ignored
    assert obs["192.0.2.31"].hostname == "kitchen-light"
    assert obs["192.0.2.31"].facts["hap_category"] == 5
    assert obs["192.0.2.32"].facts["apple_model"] == "iPad13,1"


def test_public_mdns_addresses_dropped():
    svc = {**INFO, "addresses": ["8.8.8.8"]}
    assert observations_from_services([svc]) == []


def test_ssdp_response_and_description():
    raw = (
        b"HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.5:80/d.xml\r\n"
        b"SERVER: Linux UPnP/1.0\r\nST: upnp:rootdevice\r\n\r\n"
    )
    h = parse_ssdp_response(raw)
    assert h["location"].endswith("d.xml") and h["server"].startswith("Linux")
    assert parse_ssdp_response(b"NOTIFY * HTTP/1.1\r\n\r\n") == {}
    xml = (
        "<root xmlns='urn:schemas-upnp-org:device-1-0'><device>"
        "<deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>"
        "<friendlyName>Living TV</friendlyName><manufacturer>Samsung</manufacturer>"
        "<modelName>QE55</modelName></device></root>"
    )
    d = parse_upnp_description(xml)
    assert d["manufacturer"] == "Samsung" and d["friendlyName"] == "Living TV"


def test_upnp_description_rejects_xxe():
    xxe = '<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><root><modelName>&e;</modelName></root>'
    assert parse_upnp_description(xxe) == {}


def test_ssdp_location_must_point_back_at_responder():
    assert location_allowed("http://192.0.2.5:80/d.xml", "192.0.2.5")
    assert not location_allowed("http://192.0.2.9/d.xml", "192.0.2.5")  # other host
    assert not location_allowed("http://8.8.8.8/d.xml", "8.8.8.8")  # public
    assert not location_allowed("file:///etc/passwd", "192.0.2.5")
    assert not location_allowed("http://evil.example/d.xml", "192.0.2.5")


class FakeDiscovery:
    name = "fake-mdns"

    def __init__(self, obs):
        self.obs = obs

    def collect(self, _t=None):
        return self.obs


class Boom:
    name = "boom"

    def collect(self, _t=None):
        raise RuntimeError("socket denied")


class NoNeigh:
    def collect(self):
        return []


def test_scan_classifies_homekit_and_apple_devices(repo, nmap_xml):
    discovery = observations_from_services([HAP, INFO])
    svc = ScanService(
        repo,
        nmap=NmapCollector(runner=lambda c, t: (0, nmap_xml, ""), nmap_path="/usr/bin/nmap"),
        neigh=NoNeigh(),
        discovery=[FakeDiscovery(discovery), Boom()],
    )
    net = [ipaddress.ip_network("192.0.2.0/24")]
    result = svc.run(net, "standard")
    assert any("boom collector failed" in w for w in result.warnings)  # scan still succeeds
    devices = {d.ip: d for d in repo.list_devices()}
    bulb = devices["192.0.2.31"]
    assert bulb.device_type == "smart-light" and bulb.model == "TRADFRI bulb"
    ipad = devices["192.0.2.32"]
    assert ipad.os_family == "ipados" and ipad.vendor == "Apple" and ipad.device_type == "tablet"
    hk = repo.conn.execute("SELECT * FROM homekit_accessory").fetchone()
    assert hk["hap_id"] == "AA:BB:CC:DD:EE:01" and hk["category_id"] == 5 and hk["paired"] == 1
    # evidence is explainable
    sources = {e["source"] for e in repo.evidence_for(bulb.uuid)}
    assert "hap" in sources


def test_quick_profile_skips_discovery(repo, nmap_xml):
    class Fail:
        name = "fail"

        def collect(self, _t=None):
            raise AssertionError("must not run in quick profile")

    svc = ScanService(
        repo,
        nmap=NmapCollector(runner=lambda c, t: (0, nmap_xml, ""), nmap_path="/usr/bin/nmap"),
        neigh=NoNeigh(),
        discovery=[Fail()],
    )
    result = svc.run([ipaddress.ip_network("192.0.2.0/24")], "quick")
    assert result.status == "done" and not result.warnings


def test_manual_type_survives_reclassification(repo, nmap_xml):
    obs = Observation(
        source="t", ip="192.0.2.31", mac="aa:bb:cc:00:00:31", facts={"hap_category": 5}
    )
    from amenhotep.services import identity

    uid = identity.resolve(repo, obs)
    repo.set_fields(uid, {"device_type": "smart-plug"}, user=True)
    identity.resolve(repo, obs)
    assert repo.get_field(uid, "device_type") == "smart-plug"
