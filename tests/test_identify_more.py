import struct

import pytest

from amenhotep.collectors import oui
from amenhotep.collectors.mdns_reverse import (
    MdnsReverseCollector,
    build_query,
    clean_hostname,
    parse_ptr_response,
)
from amenhotep.core.models import Observation
from amenhotep.services import identity

# ---- OUI: MA-M / MA-S, generic IEEE owner --------------------------------------------------
IEEE_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    'MA-L,584849,IEEE Registration Authority,"445 Hoes Lane Piscataway NJ US 08554"\n'
    'MA-M,5848494,"SERNET (SUZHOU) TECHNOLOGIES CORPORATION","NO.8 Tangzhuang Road, Suzhou"\n'
    "MA-S,70B3D5A12,Example Maker Ltd,Somewhere\n"
    "MA-L,B827EB,Raspberry Pi Foundation,Cambridge\n"
)


@pytest.fixture
def ieee_table(tmp_path, monkeypatch):
    monkeypatch.setenv("AMENHOTEP_HOME", str(tmp_path))
    (tmp_path / "oui.csv").write_text(IEEE_CSV)
    oui.reload()
    yield
    oui.reload()


def test_ieee_csv_columns_and_prefix_lengths():
    t = oui.parse_oui_csv(IEEE_CSV)
    assert t["5848494"].startswith("SERNET") and t["70B3D5A12"] == "Example Maker Ltd"
    assert "445 Hoes Lane" not in " ".join(t.values())  # the address column is not the name


def test_longest_prefix_wins_and_generic_owner_is_unknown(ieee_table):
    assert oui.lookup("58:48:49:40:7d:14") == "SERNET (SUZHOU) TECHNOLOGIES CORPORATION"
    assert oui.lookup("70:b3:d5:a1:2f:ff") == "Example Maker Ltd"
    assert oui.lookup("58:48:49:90:00:00") is None  # only "IEEE Registration Authority" owns it
    assert oui.lookup("b8:27:eb:00:00:01") == "Raspberry Pi Foundation"


def test_generic_ieee_vendor_from_nmap_is_not_used(repo, ieee_table):
    obs = Observation(
        source="nmap",
        ip="192.0.2.9",
        mac="58:48:49:90:00:00",
        facts={"nmap_mac_vendor": "Ieee Registration Authority"},
    )
    uid = identity.resolve(repo, obs)
    assert repo.get_field(uid, "vendor") is None


def test_vendor_is_upgraded_when_registry_gets_better(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("AMENHOTEP_HOME", str(tmp_path))
    oui.reload()
    obs = Observation(
        source="nmap",
        ip="192.0.2.9",
        mac="58:48:49:40:7d:14",
        facts={"nmap_mac_vendor": "Ieee Registration Authority"},
    )
    uid = identity.resolve(repo, obs)
    assert repo.get_field(uid, "vendor") is None
    (tmp_path / "oui.csv").write_text(IEEE_CSV)
    oui.reload()
    identity.resolve(repo, obs)
    assert repo.get_field(uid, "vendor").startswith("SERNET")
    oui.reload()


# ---- unicast mDNS reverse lookup ----------------------------------------------------------
def make_response(name: str, rdata_name: str = "Manuels-MacBook-Pro.local", pointer=False) -> bytes:
    def enc(n):
        return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\x00"

    qname = enc("36.178.168.192.in-addr.arpa")
    head = struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 0)
    question = qname + struct.pack("!HH", 12, 0x8001)
    answer_name = b"\xc0\x0c" if pointer else qname  # compression pointer to the question
    rdata = enc(rdata_name)
    answer = answer_name + struct.pack("!HHIH", 12, 0x8001, 120, len(rdata)) + rdata
    return head + question + answer


def test_query_is_a_unicast_ptr_for_the_reverse_name():
    q = build_query("192.168.178.36")
    assert b"\x0236\x03178\x03168\x03192\x07in-addr\x04arpa\x00" in q
    assert q[-4:] == struct.pack("!HH", 12, 0x8001)
    with pytest.raises(ValueError):
        build_query("not an ip")


@pytest.mark.parametrize("pointer", [False, True])
def test_parse_response_with_and_without_compression(pointer):
    assert parse_ptr_response(make_response("x", pointer=pointer)) == "Manuels-MacBook-Pro.local"
    assert clean_hostname("Manuels-MacBook-Pro.local") == "Manuels-MacBook-Pro"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00" * 5,
        b"\xff" * 40,
        make_response("x")[:30],
        b"\x00\x00\x84\x00" + b"\xc0\x0c" * 50,
    ],
)
def test_parse_never_raises_on_garbage(data):
    assert parse_ptr_response(data) is None or isinstance(parse_ptr_response(data), str)


def test_pointer_loop_is_rejected():
    head = struct.pack("!HHHHHH", 0, 0x8400, 1, 0, 0, 0)
    assert parse_ptr_response(head + b"\xc0\x0c" + b"\x00" * 4) is None


def test_collector_ignores_public_and_invalid_addresses():
    assert MdnsReverseCollector().collect_hosts(["8.8.8.8", "nope", "::1"]) == []


def test_mac_hostname_rule_sets_macos_computer(repo):
    obs = Observation(
        source="mdns-reverse", ip="192.0.2.36", mac="3c:22:fb:ee:7a:94", hostname="Some-MacBook-Pro"
    )
    uid = identity.resolve(repo, obs)
    assert repo.get_field(uid, "os_family") == "macos"
    assert repo.get_field(uid, "device_type") == "computer"


# ---- weak iOS guess and reclassify ----------------------------------------------------------
def best_type(repo, uid):
    return repo.get_field(uid, "device_type")


def test_ios_without_model_is_probably_a_phone_but_ipad_hostname_wins(repo):
    ports = {"ports": [{"port": 62078, "service": "tcpwrapped"}]}
    a = identity.resolve(
        repo, Observation(source="nmap", ip="192.0.2.50", mac="da:11:22:33:44:50", facts=ports)
    )
    b = identity.resolve(
        repo,
        Observation(
            source="nmap",
            ip="192.0.2.51",
            mac="da:11:22:33:44:51",
            hostname="Kids-iPad",
            facts=ports,
        ),
    )
    assert best_type(repo, a) == "phone"
    weak = [e for e in repo.evidence_for(a) if e["field"] == "device_type"]
    assert weak and weak[0]["confidence"] <= 0.35  # visibly a guess in the evidence table
    assert best_type(repo, b) == "tablet"


def test_manual_type_beats_weak_ios_guess(repo):
    ports = {"ports": [{"port": 62078, "service": "tcpwrapped"}]}
    uid = identity.resolve(
        repo, Observation(source="nmap", ip="192.0.2.52", mac="da:11:22:33:44:52", facts=ports)
    )
    repo.set_fields(uid, {"device_type": "tablet"}, user=True)
    identity.resolve(
        repo, Observation(source="nmap", ip="192.0.2.52", mac="da:11:22:33:44:52", facts=ports)
    )
    assert best_type(repo, uid) == "tablet"


def test_reclassify_applies_new_rules_to_stored_observations(repo):
    from amenhotep.services.reclassify import reclassify

    scan = repo.start_scan("standard", "192.0.2.0/24")
    obs = Observation(
        source="nmap",
        ip="192.0.2.60",
        mac="da:11:22:33:44:60",
        facts={"ports": [{"port": 62078, "service": "tcpwrapped"}]},
    )
    repo.add_observation(scan, obs)
    named = Observation(source="mdns-reverse", ip="192.0.2.61", mac="da:11:22:33:44:61")
    repo.add_observation(scan, named)
    repo.finish_scan(scan, "done")
    u1 = identity.resolve(repo, obs)
    u2 = identity.resolve(repo, named.model_copy(update={"hostname": "Den-MacBook-Air"}))
    repo.set_fields(u1, {"device_type": "unknown"})  # pretend an older classifier left it unknown
    repo.set_fields(u2, {"device_type": "unknown", "os_family": "unknown"})
    repo.commit()
    assert reclassify(repo) == 2
    assert best_type(repo, u1) == "phone"
    assert (
        best_type(repo, u2) == "computer"
    )  # hostname came from the interface, not the observation
    assert repo.get_field(u2, "os_family") == "macos"


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("iPhone 17 Pro Max A3520", "phone"),
        ("IPAD PRO 12.9 4th Generation", "tablet"),
        ("MacBookPro16,2", "computer"),
        ("Mac16,8", "computer"),
        ("AppleTV11,1", "media-player"),
        ("AudioAccessory5,1", "speaker"),
        ("MSS210", None),
        (None, None),
    ],
)
def test_type_from_model_name(model, expected):
    from amenhotep.services.classify import type_from_model

    assert type_from_model(model) == expected


def test_user_typed_model_types_an_unknown_device_but_not_a_typed_one(repo):
    obs = Observation(source="nmap", ip="192.0.2.70", mac="da:11:22:33:44:70")
    uid = identity.resolve(repo, obs)
    repo.set_fields(uid, {"model": "iPhone 16"}, user=True)
    identity.resolve(repo, obs)
    assert best_type(repo, uid) == "phone"
    repo.set_fields(uid, {"device_type": "tablet"}, user=True)
    identity.resolve(repo, obs)
    assert best_type(repo, uid) == "tablet"
