"""mDNS / DNS-SD collector (HomeKit, Matter, AirPlay, Chromecast, printers, ...)."""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Iterable
from typing import Any

from amenhotep.core.models import Observation, cap

SERVICE_TYPES = [
    "_hap._tcp.local.",
    "_homekit._tcp.local.",
    "_matter._tcp.local.",
    "_meshcop._udp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_companion-link._tcp.local.",
    "_device-info._tcp.local.",
    "_googlecast._tcp.local.",
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_smb._tcp.local.",
    "_ssh._tcp.local.",
    "_http._tcp.local.",
    "_workstation._tcp.local.",
]
MAX_TXT_ITEMS = 32
MAX_SERVICES_PER_HOST = 64


def short_type(service_type: str) -> str:
    return service_type.removesuffix(".local.").removesuffix(".")


def clean_txt(props: dict[Any, Any]) -> dict[str, str]:
    """Decode TXT records defensively; every value is capped and printable-only."""
    out: dict[str, str] = {}
    for key, val in list(props.items())[:MAX_TXT_ITEMS]:
        k = key.decode("utf-8", "replace") if isinstance(key, bytes) else str(key)
        if val is None:
            v = ""
        elif isinstance(val, bytes):
            v = val.decode("utf-8", "replace")
        else:
            v = str(val)
        out[cap(k, 64) or ""] = cap(v, 256) or ""
    return out


def hap_facts(txt: dict[str, str]) -> dict[str, Any]:
    """HomeKit TXT: id (device id), md (model), ci (category), sf (status flags), c# (config)."""
    facts: dict[str, Any] = {"hap_id": txt.get("id"), "hap_model": txt.get("md")}
    if txt.get("ci", "").isdigit():
        facts["hap_category"] = int(txt["ci"])
    if txt.get("sf", "").isdigit():
        facts["hap_paired"] = not (int(txt["sf"]) & 1)  # bit0 set => not yet paired
    return {k: v for k, v in facts.items() if v is not None}


_MATTER_INSTANCE = re.compile(r"^([0-9A-Fa-f]{16})-([0-9A-Fa-f]{16})$")


def _is_v4_lan(addr: str) -> bool:
    try:
        a = ipaddress.IPv4Address(addr)
    except ValueError:
        return False
    return a.is_private or a.is_link_local


def matter_nodes_from_services(services: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Matter operational nodes (_matter._tcp, instance '<fabric>-<node>').

    Thread-based nodes have no IPv4 address, so they are not hosts; they are returned separately.
    ``host_ip`` is set when one of the node's addresses is also an address of a LAN host (e.g. a
    HomePod that is itself a Matter node).
    """
    services = list(services)
    v6_to_v4: dict[str, str] = {}
    for svc in services:
        v4 = next((a for a in svc.get("addresses", []) if _is_v4_lan(a)), None)
        if v4:
            for a in svc.get("addresses", []):
                if ":" in a:
                    v6_to_v4.setdefault(a, v4)
    nodes: dict[str, dict[str, Any]] = {}
    for svc in services:
        if short_type(svc["type"]) != "_matter._tcp":
            continue
        instance = str(svc.get("name", "")).split(".")[0]
        m = _MATTER_INSTANCE.match(instance)
        if not m:
            continue
        addrs = [a for a in svc.get("addresses", []) if ":" in a or _is_v4_lan(a)]
        host_ip = next((v6_to_v4[a] for a in addrs if a in v6_to_v4), None)
        host_ip = host_ip or next((a for a in addrs if _is_v4_lan(a)), None)
        node = nodes.setdefault(
            instance.upper(),
            {
                "instance": instance.upper(),
                "fabric": m.group(1).upper(),
                "node": m.group(2).upper(),
                "addresses": [],
                "host_ip": None,
            },
        )
        node["addresses"] = sorted(set(node["addresses"]) | set(addrs))[:16]
        node["host_ip"] = node["host_ip"] or host_ip
    return list(nodes.values())


def observations_from_services(services: Iterable[dict[str, Any]]) -> list[Observation]:
    """services: dicts {type, name, server, port, addresses, txt}; one Observation per IPv4."""
    by_ip: dict[str, dict[str, Any]] = {}
    for svc in services:
        v4: list[str] = []
        for a in svc.get("addresses", []):
            try:
                addr = ipaddress.IPv4Address(a)
            except ValueError:
                continue
            if addr.is_private or addr.is_link_local:
                v4.append(str(addr))
        for ip in v4[:1]:
            slot = by_ip.setdefault(ip, {"hostname": None, "services": [], "facts": {}})
            server = cap((svc.get("server") or "").removesuffix(".local.").removesuffix("."))
            slot["hostname"] = slot["hostname"] or server or None
            stype = short_type(svc["type"])
            txt = clean_txt(svc.get("txt", {}))
            if len(slot["services"]) < MAX_SERVICES_PER_HOST:
                slot["services"].append(
                    {
                        "type": stype,
                        "name": cap(svc.get("name")),
                        "port": svc.get("port"),
                        "txt": txt,
                    }
                )
            if stype in ("_hap._tcp", "_homekit._tcp"):
                slot["facts"].update(hap_facts(txt))
            if stype == "_matter._tcp":
                slot["facts"]["matter"] = True
            if stype == "_meshcop._udp":  # Thread border router
                slot["facts"]["thread_border_router"] = {
                    "network_name": txt.get("nn"),
                    "vendor": txt.get("vn"),
                    "model": txt.get("mn"),
                }
            if stype == "_device-info._tcp" and txt.get("model"):
                slot["facts"]["apple_model"] = txt["model"]
            if stype == "_airplay._tcp" and txt.get("model"):
                slot["facts"].setdefault("apple_model", txt["model"])
            if stype == "_googlecast._tcp":
                if txt.get("md"):
                    slot["facts"]["cast_model"] = txt["md"]
                if txt.get("fn"):
                    slot["facts"]["cast_name"] = txt["fn"]
    result = []
    for host_ip, slot in by_ip.items():
        facts = {**slot["facts"], "mdns_services": slot["services"]}
        result.append(
            Observation(source="mdns", ip=host_ip, hostname=slot["hostname"], facts=facts)
        )
    return result


class MdnsCollector:
    name = "mdns"

    def __init__(self, duration_s: float = 6.0) -> None:
        self.duration_s = duration_s
        self.matter_nodes: list[dict[str, Any]] = []  # filled by collect()

    def collect(self, _targets: object = None) -> list[Observation]:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

        found: set[tuple[str, str]] = set()

        class Listener(ServiceListener):
            def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                found.add((type_, name))

            def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                found.add((type_, name))

            def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                pass

        zc = Zeroconf()
        try:
            browsers = [ServiceBrowser(zc, t, Listener()) for t in SERVICE_TYPES]
            time.sleep(self.duration_s)
            services: list[dict[str, Any]] = []
            for type_, name in sorted(found):
                info = zc.get_service_info(type_, name, timeout=1500)
                if info is None:
                    continue
                services.append(
                    {
                        "type": type_,
                        "name": name,
                        "server": info.server,
                        "port": info.port,
                        "addresses": info.parsed_addresses(),
                        "txt": info.properties,
                    }
                )
            for b in browsers:
                b.cancel()
        finally:
            zc.close()
        self.matter_nodes = matter_nodes_from_services(services)
        return observations_from_services(services)
