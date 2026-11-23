import ipaddress
import subprocess

import pytest

from amenhotep.collectors import nmap as nm
from amenhotep.collectors.nmap import NmapCollector, NmapError, parse_nmap_xml
from amenhotep.core.models import ALLOWED_SCRIPTS, PROFILES, Observation, ScanProfile
from amenhotep.services import identity
from amenhotep.services.scan import ScanService
from tests.conftest import FIXTURES


@pytest.fixture(scope="module")
def fp_obs():
    xml = (FIXTURES / "nmap" / "lan_fingerprint.xml").read_text()
    return {o.ip: o for o in parse_nmap_xml(xml)}


@pytest.fixture
def classified(repo, fp_obs):
    """Run every fixture host through identity+classifier and return devices by IP."""
    for obs in fp_obs.values():
        identity.resolve(repo, obs)
    repo.commit()
    return {d.ip: d for d in repo.list_devices()}


# ---- parsing --------------------------------------------------------------------------------
def test_scripts_and_service_attributes_are_parsed(fp_obs):
    f = fp_obs["192.0.2.27"].facts
    assert f["service_devicetypes"] == ["printer"]
    assert f["http_servers"] == ["HP HTTP Server; HP ENVY 4520 series - F0V63B"]
    assert f["ssl_cert"] == {"cn": "HPB121EB", "org": "HP"}
    assert "http_titles" not in f  # "doesn't have a title" is noise
    assert "fingerprint-strings" not in f["scripts"]  # only allow-listed scripts are kept
    assert fp_obs["192.0.2.1"].facts["ssl_cert"]["org"] == "ARRIS Group Inc."


def test_windows_facts_and_hostname_from_netbios(fp_obs):
    o = fp_obs["192.0.2.50"]
    assert o.facts["smb"]["os"] == "Windows 10 Pro 19045"
    assert o.facts["rdp"]["Product_Version"] == "10.0.19041"
    assert o.facts["nbstat_name"] == "LAPTOP-AB12CD"
    assert o.hostname == "LAPTOP-AB12CD"  # no DNS name => NetBIOS name


def test_os_matches_class_and_cpes(fp_obs):
    f = fp_obs["192.0.2.60"].facts
    assert f["os_detail"] == "Linux 5.4 - 5.10" and f["os_accuracy"] == 97
    assert f["os_family"] == "linux" and f["os_type"] == "general purpose"
    assert len(f["os_matches"]) == 2
    assert fp_obs["192.0.2.62"].facts["os_family"] == "ios"


# ---- classification -------------------------------------------------------------------------
def test_printer_model_from_service_and_vendor_from_cert(classified):
    d = classified["192.0.2.27"]
    assert d.device_type == "printer"
    assert d.model == "HP ENVY 4520 series"  # "printer http config" suffix removed
    assert d.vendor == "HP"
    assert "HP HTTP Server" in d.hardware_notes and "TLS: HPB121EB/HP" in d.hardware_notes


def test_router_identified_without_root(classified):
    d = classified["192.0.2.1"]
    assert d.device_type == "router" and d.vendor in ("ARRIS", "ARRIS Group Inc.")
    assert "lighttpd" in d.hardware_notes and "MiniUPnP" in d.hardware_notes


def test_windows_from_smb_rdp(classified):
    d = classified["192.0.2.50"]
    assert d.os_family == "windows" and d.os_detail == "Windows 10 Pro 19045"
    assert d.display_name is None and d.hostname == "LAPTOP-AB12CD"


def test_privileged_os_detection_results(classified):
    linux = classified["192.0.2.60"]
    assert linux.os_family == "linux" and linux.os_detail == "Linux 5.4 - 5.10"
    wap = classified["192.0.2.61"]
    assert wap.device_type == "access-point" and wap.vendor == "TP-LINK"
    assert wap.model.startswith("TP-LINK TL-WR841N")
    ios = classified["192.0.2.62"]
    assert ios.os_family == "ios" and ios.device_type == "phone"


def test_low_accuracy_os_guess_is_ignored(classified):
    assert classified["192.0.2.63"].os_family == "unknown"


def test_iphone_from_lockdownd_port_without_root(classified):
    d = classified["192.0.2.70"]
    assert d.os_family == "ios" and d.vendor == "Apple"


# ---- command building / privileges -------------------------------------------------------------
def collector(raw: bool | None, runner=lambda c, t: (0, "<nmaprun/>", "")):
    return NmapCollector(runner=runner, nmap_path="/usr/bin/nmap", raw_capable=raw)


def test_standard_without_raw_sockets_warns_with_fix_and_skips_O():
    c = collector(False)
    cmd = c.build_command(["192.0.2.0/24"], PROFILES["standard"])
    assert "-O" not in cmd and "--privileged" not in cmd
    assert any("setcap" in w for w in c.warnings)
    assert "-sV" in cmd and "-p" in cmd and "--script" in cmd


def test_standard_with_raw_sockets_enables_os_detection():
    cmd = collector(True).build_command(["192.0.2.0/24"], PROFILES["standard"])
    assert cmd[1] == "--privileged"  # required when raw sockets come from setcap
    for flag in ("-O", "--osscan-guess", "--osscan-limit", "--max-os-tries"):
        assert flag in cmd


def test_scripts_are_allow_listed():
    for profile in PROFILES.values():
        assert set(profile.scripts) <= ALLOWED_SCRIPTS
    with pytest.raises(ValueError, match="not allowed"):
        ScanProfile(name="x", nmap_args=[], timeout_s=1, scripts=["vuln", "http-title"])
    cmd = collector(False).build_command(["192.0.2.1"], PROFILES["standard"])
    scripts = cmd[cmd.index("--script") + 1].split(",")
    assert set(scripts) <= ALLOWED_SCRIPTS


def test_collect_hosts_uses_Pn_and_validates_ips():
    seen = []
    c = collector(False, runner=lambda cmd, t: seen.append(cmd) or (0, "<nmaprun/>", ""))
    c.collect_hosts(["192.0.2.5", "192.0.2.9"], "standard")
    assert "-Pn" in seen[0] and seen[0][-2:] == ["192.0.2.5", "192.0.2.9"]
    with pytest.raises(ValueError):
        c.collect_hosts(["192.0.2.5; rm -rf /"], "standard")
    assert c.collect_hosts([], "standard") == []


def test_probe_raw_capable(monkeypatch):
    def fake_run(rc):
        return lambda *a, **k: subprocess.CompletedProcess(a, rc, b"", b"")

    monkeypatch.setattr(nm.subprocess, "run", fake_run(0))
    assert nm.probe_raw_capable("/usr/bin/nmap") is True
    monkeypatch.setattr(nm.subprocess, "run", fake_run(1))
    assert nm.probe_raw_capable("/usr/bin/nmap") is False


def test_real_collector_probes_lazily(monkeypatch):
    calls = []
    monkeypatch.setattr(nm, "probe_raw_capable", lambda p: calls.append(p) or True)
    c = NmapCollector(nmap_path="/usr/bin/nmap")
    assert calls == []  # not probed at construction
    assert c.raw_capable and c.raw_capable
    assert calls == ["/usr/bin/nmap"]  # probed once


def test_root_error_triggers_retry_without_O():
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        if "-O" in cmd:
            return 1, "", "TCP/IP fingerprinting requires root privileges"
        return 0, "<nmaprun/>", ""

    c = collector(True, runner)
    c.collect_hosts(["192.0.2.5"], "deep")
    assert len(calls) == 2 and "-O" not in calls[1] and "--max-os-tries" not in calls[1]
    assert calls[1].count("2") == calls[1].count("2")  # args stay well-formed
    assert any("retried without -O" in w for w in c.warnings)


def test_nmap_failure_raises():
    with pytest.raises(NmapError):
        collector(False, lambda c, t: (1, "", "boom")).collect_hosts(["192.0.2.5"], "standard")


# ---- two-phase scan ---------------------------------------------------------------------------
class FakeNeigh:
    def __init__(self, obs):
        self.obs = obs

    def collect(self):
        return self.obs


def test_phase2_scans_hosts_found_only_via_arp_table(repo):
    cmds = []

    def runner(cmd, timeout):
        cmds.append(cmd)
        return 0, "<nmaprun/>", ""

    neigh = [
        Observation(source="neigh", ip="192.0.2.70", mac="da:11:22:33:44:70"),  # drops pings
        Observation(source="neigh", ip="198.51.100.5", mac="aa:aa:aa:aa:aa:aa"),  # out of scope
    ]
    svc = ScanService(
        repo,
        nmap=NmapCollector(runner=runner, nmap_path="/usr/bin/nmap", raw_capable=False),
        neigh=FakeNeigh(neigh),
        discovery=[],
    )
    svc.run([ipaddress.ip_network("192.0.2.0/24")], "standard")
    assert "-sn" in cmds[0]  # phase 1: sweep
    assert "-Pn" in cmds[1] and cmds[1][-1] == "192.0.2.70"  # phase 2: only live, in-scope hosts
    assert "198.51.100.5" not in cmds[1]


# ---- noisy -O guesses ----------------------------------------------------------------------
from amenhotep.services.classify import classify  # noqa: E402


def best(ev, field):
    rows = [e for e in ev if e.field == field]
    return max(rows, key=lambda e: e.confidence).value if rows else None


FORTIGATE_GUESS = {
    "os_matches": [],
    "os_detail": "Fortinet FortiGate 100D firewall",
    "os_accuracy": 92,
    "os_type": "firewall",
    "os_vendor": "Fortinet",
    "ports": [{"port": 62078, "service": "tcpwrapped"}],
}


def test_nmap_guess_discarded_when_strong_source_disagrees():
    ev = classify(FORTIGATE_GUESS, None, None)  # lockdownd port => iOS (0.75)
    assert best(ev, "os_family") == "ios"
    assert best(ev, "device_type") == "phone"  # only the weak iOS guess, never the bogus "router"
    assert best(ev, "model") is None and best(ev, "os_detail") is None
    assert not [e for e in ev if e.source == "nmap-os"]


def test_nmap_guess_kept_when_nothing_contradicts_it():
    facts = {k: v for k, v in FORTIGATE_GUESS.items() if k != "ports"}
    ev = classify(facts, None, None)
    assert best(ev, "device_type") == "router"
    assert best(ev, "model") is None  # "firewall" class is not trusted as a model


def test_phone_class_guess_is_not_used_as_model():
    facts = {
        "os_detail": "Apple iOS 13",
        "os_accuracy": 95,
        "os_type": "phone",
        "os_family": "ios",
        "os_vendor": "Apple",
    }
    ev = classify(facts, None, None)
    assert best(ev, "device_type") == "phone" and best(ev, "model") is None


def test_apple_model_beats_noisy_os_detail_and_apple_tv_is_tvos():
    facts = {
        "apple_model": "AudioAccessory5,1",
        "os_family": "macos",
        "os_accuracy": 90,
        "os_detail": "Apple OS X 10.11 - 10.12",
        "os_type": "general purpose",
    }
    ev = classify(facts, None, None)
    assert best(ev, "os_family") == "embedded"
    assert "AudioAccessory" in best(ev, "os_detail")
    xml = (
        '<nmaprun><host><status state="up"/><address addr="192.0.2.9" addrtype="ipv4"/>'
        '<os><osmatch name="Apple TV 5" accuracy="95"><osclass type="media device" '
        'vendor="Apple" osfamily="iOS" accuracy="95"/></osmatch></os></host></nmaprun>'
    )
    assert parse_nmap_xml(xml)[0].facts["os_family"] == "tvos"


def test_rescan_clears_stale_nmap_os_evidence(repo):
    obs = Observation(
        source="nmap",
        ip="192.0.2.90",
        mac="da:11:22:33:44:90",
        facts={**{k: v for k, v in FORTIGATE_GUESS.items() if k != "ports"}},
    )
    uid = identity.resolve(repo, obs)
    assert repo.get_field(uid, "device_type") == "router"
    obs2 = obs.model_copy(update={"facts": FORTIGATE_GUESS})  # now with the iOS port
    identity.resolve(repo, obs2)
    assert not [e for e in repo.evidence_for(uid) if e["source"] == "nmap-os"]
    assert repo.get_field(uid, "device_type") == "phone"  # stale "router" is gone; weak iOS guess
