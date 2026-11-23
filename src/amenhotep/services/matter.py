"""Group Matter operational instances into physical devices.

One Matter device commissioned into several ecosystems ("multi-admin": Apple Home + another app)
announces one ``_matter._tcp`` instance per fabric, all at the same address. Grouping by shared
address shows it as one device with several fabrics.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from amenhotep.store.repo import MatterNodeRow


@dataclass
class MatterDevice:
    addresses: list[str]
    nodes: list[MatterNodeRow] = field(default_factory=list)

    @property
    def fabrics(self) -> int:
        return len({n.fabric for n in self.nodes})

    @property
    def host_uuid(self) -> str | None:
        return next((n.host_uuid for n in self.nodes if n.host_uuid), None)

    @property
    def host_name(self) -> str | None:
        return next((n.host_name for n in self.nodes if n.host_name), None)

    @property
    def label(self) -> str | None:
        return next((n.label for n in self.nodes if n.label), None)

    @property
    def area(self) -> str | None:
        return next((n.area for n in self.nodes if n.area), None)

    @property
    def likely_thread(self) -> bool:
        """IPv6-only and not a known LAN host: almost always a Thread device behind a router."""
        return self.host_uuid is None and not any("." in a for a in self.addresses)


def _routable(addr: str) -> bool:
    return not addr.lower().startswith("fe80:")  # link-local differs per interface


def group_matter_nodes(nodes: list[MatterNodeRow]) -> list[MatterDevice]:
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for n in nodes:
        keys = [a for a in n.addresses if _routable(a)] or [f"inst:{n.instance}"]
        for a in keys[1:]:
            parent[find(a)] = find(keys[0])
        find(keys[0])
    groups: dict[str, MatterDevice] = {}
    for n in nodes:
        keys = [a for a in n.addresses if _routable(a)] or [f"inst:{n.instance}"]
        g = groups.setdefault(find(keys[0]), MatterDevice(addresses=[]))
        g.nodes.append(n)
        g.addresses = sorted(set(g.addresses) | set(n.addresses))
    return sorted(groups.values(), key=lambda g: (g.host_uuid is not None, g.addresses[0]))
