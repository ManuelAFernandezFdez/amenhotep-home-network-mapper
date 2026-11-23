import pytest

from amenhotep.services.classify import classify, hap_categories, load_rules


def best(evidence, field):
    rows = [e for e in evidence if e.field == field]
    return max(rows, key=lambda e: e.confidence) if rows else None


CASES = [
    # (facts, hostname, vendor, field, expected value)
    ({"apple_model": "iPhone15,2"}, None, None, "os_family", "ios"),
    ({"apple_model": "iPhone15,2"}, None, None, "device_type", "phone"),
    ({"apple_model": "iPad13,1"}, None, None, "os_family", "ipados"),
    ({"apple_model": "Mac14,2"}, None, None, "os_family", "macos"),
    ({"apple_model": "AppleTV11,1"}, None, None, "device_type", "media-player"),
    ({"apple_model": "AudioAccessory5,1"}, None, None, "device_type", "speaker"),
    ({"hap_category": 5, "hap_model": "TRADFRI bulb"}, None, None, "device_type", "smart-light"),
    ({"hap_category": 7}, None, None, "device_type", "smart-plug"),
    ({"hap_category": 2, "hap_model": "Hue Bridge"}, None, None, "model", "Hue Bridge"),
    ({"hap_category": 16}, None, None, "device_type", "access-point"),
    ({"ports": [{"port": 445}, {"port": 3389}]}, None, None, "os_family", "windows"),
    ({}, "DESKTOP-AB12CD3", None, "os_family", "windows"),
    ({}, "Galaxy-S23", None, "device_type", "phone"),
    ({"ports": [{"port": 9100}]}, None, None, "device_type", "printer"),
    ({}, None, "Espressif Inc.", "device_type", "iot-sensor"),
    ({}, None, "TP-Link Technologies Co.,Ltd.", "device_type", "network-device"),
    (
        {"mdns_services": [{"type": "_googlecast._tcp"}], "cast_model": "Chromecast"},
        None,
        None,
        "device_type",
        "media-player",
    ),
    (
        {"upnp_deviceType": "urn:schemas-upnp-org:device:InternetGatewayDevice:1"},
        None,
        None,
        "device_type",
        "router",
    ),
    (
        {"upnp_modelName": "Connect Box", "upnp_manufacturer": "Compal"},
        None,
        None,
        "model",
        "Connect Box",
    ),
]


@pytest.mark.parametrize("facts,hostname,vendor,field,expected", CASES)
def test_classification(facts, hostname, vendor, field, expected):
    ev = best(classify(facts, hostname, vendor), field)
    assert ev is not None and ev.value == expected


def test_mdns_model_beats_nmap_guess():
    facts = {
        "os_family": "macos",
        "os_accuracy": 90,  # nmap says "Apple iOS/macOS"-ish
        "apple_model": "iPhone15,2",
    }
    assert best(classify(facts, None, None), "os_family").value == "ios"


def test_low_accuracy_nmap_os_ignored():
    assert (
        best(classify({"os_family": "linux", "os_accuracy": 60}, None, None), "os_family") is None
    )


def test_rule_with_unknown_condition_never_matches():
    from amenhotep.services.classify import _matches

    assert not _matches({"nonsense": 1}, {"ports": set(), "mdns": set()})


def test_bundled_rules_and_categories_are_valid():
    assert len(load_rules()) >= 15
    assert hap_categories()[5][0] == "smart-light"


def test_user_rules_extend_and_invalid_ones_are_skipped(tmp_path, monkeypatch):
    from amenhotep.core.paths import data_dir
    from amenhotep.services import classify as c

    (data_dir() / "os_rules.yaml").write_text(
        "rules:\n"
        "  - {id: mine, when: {hostname_re: '^nas-'}, set: {device_type: nas}, weight: 0.9}\n"
        "  - {id: bad, when: {}, set: {os_family: beos}, weight: 0.9}\n"
        "  - {id: bad2, when: {}, set: {device_type: spaceship}, weight: 0.9}\n"
    )
    c.reload_rules()
    try:
        ids = {r["id"] for r in c.load_rules()}
        assert "mine" in ids and "bad" not in ids and "bad2" not in ids
    finally:
        (data_dir() / "os_rules.yaml").unlink()
        c.reload_rules()
