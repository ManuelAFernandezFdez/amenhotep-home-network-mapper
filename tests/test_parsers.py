import pytest

from amenhotep.collectors import oui
from amenhotep.collectors.neigh import parse_ip_neigh
from amenhotep.collectors.nmap import ParseError, parse_nmap_xml


def test_parse_nmap(nmap_xml):
    obs = {o.ip: o for o in parse_nmap_xml(nmap_xml)}
    assert set(obs) == {"192.0.2.1", "192.0.2.20", "192.0.2.40"}  # down host skipped
    pi = obs["192.0.2.1"]
    assert pi.mac == "b8:27:eb:00:00:01"
    assert pi.hostname == "pi.lan"
    assert pi.facts["ports"] == [
        {"port": 22, "proto": "tcp", "service": "ssh", "product": "OpenSSH", "version": "9.2"}
    ]  # closed port skipped
    assert pi.facts["os_family"] == "linux" and pi.facts["os_accuracy"] == 96
    assert obs["192.0.2.40"].mac is None


def test_rejects_xxe_and_garbage():
    xxe = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun>&e;</nmaprun>'
    with pytest.raises(ParseError):
        parse_nmap_xml(xxe)
    with pytest.raises(ParseError):
        parse_nmap_xml("<html/>")
    with pytest.raises(ParseError):
        parse_nmap_xml("not xml")


def test_long_strings_are_capped():
    xml = (
        '<nmaprun><host><status state="up"/><address addr="192.0.2.9" addrtype="ipv4"/>'
        f'<hostnames><hostname name="{"a" * 5000}"/></hostnames></host></nmaprun>'
    )
    assert len(parse_nmap_xml(xml)[0].hostname) == 256


def test_ip_neigh():
    text = (
        "192.0.2.1 dev wlp3s0 lladdr b8:27:eb:00:00:01 REACHABLE\n"
        "192.0.2.2 dev wlp3s0  FAILED\n"
        "192.0.2.3 dev wlp3s0 lladdr aa:bb:cc:dd:ee:ff STALE\n"
        "192.0.2.4 dev wlp3s0 lladdr 00:00:00:00:00:01 INCOMPLETE\n"
    )
    assert [(o.ip, o.mac) for o in parse_ip_neigh(text)] == [
        ("192.0.2.1", "b8:27:eb:00:00:01"),
        ("192.0.2.3", "aa:bb:cc:dd:ee:ff"),
    ]


def test_oui_lookup():
    assert oui.lookup("b8:27:eb:12:34:56") == "Raspberry Pi Foundation"
    assert oui.lookup("00:50:56:aa:bb:cc") == "VMware, Inc."
    assert oui.lookup("fe:ed:fa:ce:00:00") is None
    assert oui.lookup(None) is None
