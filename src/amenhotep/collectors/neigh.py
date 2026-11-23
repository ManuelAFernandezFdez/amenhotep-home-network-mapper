"""Kernel neighbour table (`ip -4 neigh`): unprivileged source of IP<->MAC pairs."""

from __future__ import annotations

import ipaddress
import re
import subprocess

from amenhotep.core.models import Observation
from amenhotep.core.netutil import normalize_mac

_LINE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+(?P<mac>\S+)\s+(?P<rest>.*)$"
)
_BAD_STATES = {"FAILED", "INCOMPLETE"}


def parse_ip_neigh(text: str) -> list[Observation]:
    obs: list[Observation] = []
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        state = m.group("rest").split()[-1] if m.group("rest").split() else ""
        if state in _BAD_STATES:
            continue
        mac = normalize_mac(m.group("mac"))
        try:
            ip = str(ipaddress.IPv4Address(m.group("ip")))
        except ValueError:
            continue
        if mac:
            obs.append(Observation(source="neigh", ip=ip, mac=mac))
    return obs


class NeighCollector:
    name = "neigh"

    def collect(self) -> list[Observation]:
        try:
            out = subprocess.run(
                ["ip", "-4", "neigh", "show"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return []
        return parse_ip_neigh(out)
