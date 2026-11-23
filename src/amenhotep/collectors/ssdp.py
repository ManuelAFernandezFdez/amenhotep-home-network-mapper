"""SSDP / UPnP collector: M-SEARCH, then fetch each device description (LAN only, size-capped)."""

from __future__ import annotations

import ipaddress
import socket
import time
import urllib.request
from typing import Any
from urllib.parse import urlparse

from defusedxml import ElementTree as SafeET

from amenhotep.core.models import Observation, cap

SSDP_ADDR = ("239.255.255.250", 1900)
MSEARCH = (
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
)
MAX_DESCRIPTION = 256 * 1024
MAX_RESPONSES = 512


def parse_ssdp_response(data: bytes) -> dict[str, str]:
    text = data[:4096].decode("utf-8", "replace")
    lines = text.split("\r\n")
    if not lines or not lines[0].upper().startswith("HTTP/1.1 200"):
        return {}
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = cap(v.strip(), 512) or ""
    return headers


def parse_upnp_description(xml_text: str) -> dict[str, str]:
    """Extract device identity fields from a UPnP root description."""
    try:
        root = SafeET.fromstring(xml_text)
    except Exception:
        return {}
    out: dict[str, str] = {}
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "deviceType"):
            if tag not in out and el.text:
                out[tag] = cap(el.text.strip(), 128) or ""
    return out


def location_allowed(location: str, responder_ip: str) -> bool:
    """Only fetch http URLs that point back at the host that answered (anti-SSRF)."""
    try:
        u = urlparse(location)
        host = ipaddress.IPv4Address(u.hostname or "")
    except ValueError:
        return False
    return u.scheme == "http" and str(host) == responder_ip and host.is_private


def facts_from(headers: dict[str, str], description: dict[str, str]) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    if headers.get("server"):
        facts["ssdp_server"] = headers["server"]
    for key in ("friendlyName", "manufacturer", "modelName", "modelNumber", "deviceType"):
        if description.get(key):
            facts[f"upnp_{key}"] = description[key]
    return facts


class SsdpCollector:
    name = "ssdp"

    def __init__(self, duration_s: float = 3.0, fetch_descriptions: bool = True) -> None:
        self.duration_s = duration_s
        self.fetch = fetch_descriptions

    def collect(self, _targets: object = None) -> list[Observation]:
        responses: dict[str, dict[str, str]] = {}
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(0.5)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(MSEARCH, SSDP_ADDR)
            end = time.monotonic() + self.duration_s
            while time.monotonic() < end and len(responses) < MAX_RESPONSES:
                try:
                    data, (ip, _port) = sock.recvfrom(4096)
                except TimeoutError:
                    continue
                except OSError:
                    break
                headers = parse_ssdp_response(data)
                if headers:
                    responses.setdefault(ip, headers)
        except OSError:
            return []
        finally:
            sock.close()

        observations = []
        for ip, headers in responses.items():
            description: dict[str, str] = {}
            location = headers.get("location", "")
            if self.fetch and location_allowed(location, ip):
                description = self._fetch(location)
            observations.append(
                Observation(source="ssdp", ip=ip, facts=facts_from(headers, description))
            )
        return observations

    @staticmethod
    def _fetch(url: str) -> dict[str, str]:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:  # fixed scheme/host validated
                body = resp.read(MAX_DESCRIPTION + 1)
        except (OSError, ValueError):
            return {}
        if len(body) > MAX_DESCRIPTION:
            return {}
        return parse_upnp_description(body.decode("utf-8", "replace"))
