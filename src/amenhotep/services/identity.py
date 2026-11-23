"""Identity resolution: map an Observation to a device UUID and apply its facts.

Rules (see DESIGN §4):
- Same MAC => same device (a randomised MAC is just a MAC; we never merge *across* MACs).
- No MAC => match by IP among known interfaces, else create a new device.
- Scans never overwrite fields the user locked.
"""

from __future__ import annotations

from amenhotep.collectors import oui
from amenhotep.core.models import Observation, cap
from amenhotep.core.netutil import is_random_mac, normalize_mac
from amenhotep.services.classify import classify, type_from_model
from amenhotep.store.repo import Repository


def resolve(repo: Repository, obs: Observation) -> str:
    mac = normalize_mac(obs.mac)
    device = repo.device_by_mac(mac) if mac else None
    if device is None and mac is None and obs.ip:
        device = repo.device_by_ip(obs.ip)
    if device is None:
        device = repo.create_device(obs.ts)

    repo.touch_interface(
        device,
        mac=mac,
        mac_random=bool(mac and is_random_mac(mac)),
        ip=obs.ip,
        hostname=obs.hostname,
        ts=obs.ts,
    )
    _apply_facts(repo, device, obs, mac)
    return device


def _apply_facts(repo: Repository, device: str, obs: Observation, mac: str | None) -> None:
    mac_vendor = None
    if mac:
        repo.clear_evidence_source(device, "oui")  # vendor may have changed (new registry data)
    if mac and not is_random_mac(mac):
        mac_vendor = oui.lookup(mac)
        nmap_vendor = obs.facts.get("nmap_mac_vendor")  # MA-L only: may just say "IEEE ..."
        if not mac_vendor and nmap_vendor and not oui.is_generic_owner(nmap_vendor):
            mac_vendor = nmap_vendor
    elif mac:
        repo.replace_evidence(device, "mac", "oui", "randomised (private) MAC address", 0.0)

    if "nmap" in obs.source:  # a fresh nmap result supersedes its earlier -O guesses
        repo.clear_evidence_source(device, "nmap-os")
    for ev in classify(obs.facts, obs.hostname, mac_vendor):
        repo.replace_evidence(device, ev.field, ev.source, ev.value, ev.confidence, ev.detail)
    repo.apply_best_evidence(device)
    hinted = type_from_model(repo.get_field(device, "model"))
    if hinted and repo.get_field(device, "device_type") == "unknown":
        repo.replace_evidence(
            device, "device_type", "model-name", hinted, 0.5, "from the model name"
        )
        repo.apply_best_evidence(device)

    if "hap_id" in obs.facts or obs.facts.get("matter"):
        repo.upsert_homekit(
            device,
            obs.facts.get("hap_id"),
            obs.facts.get("hap_category"),
            obs.facts.get("hap_model"),
            obs.facts.get("hap_paired"),
            protocol="hap" if "hap_id" in obs.facts else "matter",
        )
    br = obs.facts.get("thread_border_router")
    if isinstance(br, dict):
        repo.upsert_border_router(
            device,
            cap(br.get("network_name"), 64),
            cap(br.get("vendor"), 64),
            cap(br.get("model"), 64),
        )
