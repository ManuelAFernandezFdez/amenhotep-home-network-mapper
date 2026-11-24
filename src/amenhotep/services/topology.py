"""Topology: infrastructure, uplinks, the tree, hints and the router client-list import.

Links are manual by design (the owner's switches are unmanaged: no SNMP, LLDP or MAC table).
Hints are suggestions and are never applied silently.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from amenhotep.store.repo import DeviceRow, LinkRow, Repository

INFRA_TYPES = {"router", "switch", "access-point", "mesh-node", "network-device"}
TEMPLATES = {
    "tp-link-4": ("TP-Link", "unmanaged switch, 4 ports", 4),
    "tp-link-8": ("TP-Link", "unmanaged switch, 8 ports", 8),
}
MAX_CLIENT_FILE = 2_000_000
_WIFI = re.compile(r"wi-?fi|wlan|wireless|\b(2\.4|5)\s?ghz|\b802\.11", re.I)
_WIRED = re.compile(r"ethernet|\blan\b|wired|\beth\d", re.I)
_MAC = re.compile(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", re.I)


@dataclass
class Node:
    device: DeviceRow
    link: LinkRow | None = None
    children: list[Node] = field(default_factory=list)

    @property
    def name(self) -> str:
        d = self.device
        return d.display_name or d.hostname or d.ip or d.uuid[:8]


@dataclass
class Topology:
    roots: list[Node]  # infrastructure with no uplink (the router, ideally)
    unlinked: list[Node]  # ordinary devices with no uplink yet
    ports: dict[str, int]  # uuid -> port count

    def used_ports(self, node: Node) -> int:
        return sum(1 for c in node.children if c.link and c.link.port and c.link.medium == "wired")


def is_infra(d: DeviceRow) -> bool:
    return d.is_infrastructure or d.device_type in INFRA_TYPES


def add_switch(repo: Repository, name: str, template: str, uplink: str | None = None) -> str:
    if template not in TEMPLATES:
        raise ValueError(f"unknown template {template!r}; choose {', '.join(TEMPLATES)}")
    vendor, model, ports = TEMPLATES[template]
    parent = None
    if uplink:
        parent = repo.device_by_ip_or_name(uplink)
        if not parent:
            raise ValueError(f"no unique device matches uplink {uplink!r}")
    uid = repo.add_infrastructure(name, "switch", ports, vendor, model)
    if parent:
        repo.set_link(uid, parent)
    repo.commit()
    return uid


def build(repo: Repository) -> Topology:
    devices = {d.uuid: d for d in repo.list_devices()}
    links = {lk.child_uuid: lk for lk in repo.list_links()}
    nodes = {u: Node(d, links.get(u)) for u, d in devices.items()}
    roots: list[Node] = []
    unlinked: list[Node] = []
    for node in nodes.values():
        parent = nodes.get(node.link.parent_uuid) if node.link else None
        if parent is not None:
            parent.children.append(node)
        elif is_infra(node.device):
            roots.append(node)
        else:
            unlinked.append(node)

    def key(n: Node) -> tuple[int, int, str]:
        port = n.link.port if n.link and n.link.port and n.link.port.isdigit() else None
        return (0 if port else 1, int(port) if port else 0, n.name.lower())

    for n in nodes.values():
        n.children.sort(key=key)
    roots.sort(key=lambda n: (n.device.device_type != "router", n.name.lower()))
    unlinked.sort(key=lambda n: n.name.lower())
    ports = {u: p for u in nodes if (p := repo.device_ports(u))}
    return Topology(roots, unlinked, ports)


def render(topo: Topology) -> list[str]:
    lines: list[str] = []

    def walk(n: Node, depth: int) -> None:
        link = n.link
        via = ""
        if link:
            bits = [f"port {link.port}" if link.port else None, link.medium]
            bits.append("" if link.confirmed else "suggested")
            via = "  [" + ", ".join(b for b in bits if b) + "]"
        cap = topo.ports.get(n.device.uuid)
        slots = f"  ({topo.used_ports(n)}/{cap} ports used)" if cap else ""
        lines.append("  " * depth + f"{n.name}  {n.device.ip or ''}{slots}{via}".rstrip())
        for c in n.children:
            walk(c, depth + 1)

    for r in topo.roots:
        walk(r, 0)
    if topo.unlinked:
        lines.append(f"No uplink yet ({len(topo.unlinked)}):")
        lines += [f"  {n.name}  {n.device.ip or ''}".rstrip() for n in topo.unlinked]
    return lines


@dataclass
class Suggestion:
    child: str
    parent: str
    medium: str
    reason: str


def suggest_uplinks(repo: Repository) -> list[Suggestion]:
    """Cautious hints only: they use what is known (router client list, who exists)."""
    topo = build(repo)
    routers = [n for n in topo.roots if n.device.device_type == "router"]
    if not routers:
        return []
    router = routers[0]
    aps = [n for n in topo.roots if n.device.device_type in ("access-point", "mesh-node")]
    switches = [n for n in topo.roots if n.device.device_type == "switch"]
    mediums = {
        r[0]: r[1]
        for r in repo.conn.execute(
            "SELECT device_uuid, medium FROM interface WHERE medium<>'unknown'"
        ).fetchall()
    }
    out = []
    for n in topo.unlinked:
        medium = mediums.get(n.device.uuid)
        if medium == "wifi" and not aps:
            out.append(Suggestion(n.device.uuid, router.device.uuid, "wifi",
                                  "Wi-Fi client and no other access point is known"))  # fmt: skip
        elif medium == "wired" and not switches:
            out.append(Suggestion(n.device.uuid, router.device.uuid, "wired",
                                  "wired client and no switch is known"))  # fmt: skip
    return out


def apply_suggestions(repo: Repository, suggestions: list[Suggestion]) -> int:
    for s in suggestions:
        repo.set_link(s.child, s.parent, medium=s.medium, source="inferred", confirmed=False)
    repo.commit()
    return len(suggestions)


def import_router_clients(repo: Repository, path: Path | str) -> tuple[int, int]:
    """Read a router client-list export/copy; set each known MAC's medium (wired / Wi-Fi).

    Tolerant of format: every line with a MAC address is read, and the words on that line decide
    Wi-Fi or wired. Returns (lines with a MAC, interfaces updated).
    """
    p = Path(path)
    if p.stat().st_size > MAX_CLIENT_FILE:
        raise ValueError("file too large for a client list")
    seen = updated = 0
    for line in p.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        m = _MAC.search(line)
        if not m:
            continue
        seen += 1
        medium = "wifi" if _WIFI.search(line) else "wired" if _WIRED.search(line) else None
        if medium and repo.set_medium_by_mac(m.group(0).lower().replace("-", ":"), medium):
            updated += 1
    repo.commit()
    return seen, updated
