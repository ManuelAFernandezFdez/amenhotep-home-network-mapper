"""ScanService: run collectors, merge observations per IP, resolve identities, persist."""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from amenhotep.collectors.mdns import MdnsCollector
from amenhotep.collectors.mdns_reverse import MdnsReverseCollector
from amenhotep.collectors.neigh import NeighCollector
from amenhotep.collectors.nmap import NmapCollector, ScanCancelled
from amenhotep.collectors.ssdp import SsdpCollector
from amenhotep.core.models import Observation
from amenhotep.services import identity
from amenhotep.store.repo import Repository

ProgressSink = Callable[[str], None]


class DiscoveryCollector(Protocol):
    name: str

    def collect(self, _targets: Any = None) -> list[Observation]: ...


@dataclass
class ScanResult:
    scan_id: int
    status: str
    hosts_seen: int = 0
    new_devices: int = 0
    warnings: list[str] = field(default_factory=list)
    probed: int = 0  # hosts that got a full fingerprint during a watch pass
    new_unknown: list[str] = field(
        default_factory=list
    )  # "ip (vendor)" of new, still-unknown devices


def merge_by_ip(observations: list[Observation]) -> list[Observation]:
    """Combine observations for the same IP so an nmap host gains the MAC from `ip neigh`."""
    merged: dict[str, Observation] = {}
    for obs in observations:
        if not obs.ip:
            continue
        cur = merged.get(obs.ip)
        if cur is None:
            merged[obs.ip] = obs.model_copy(deep=True)
            continue
        cur.mac = cur.mac or obs.mac
        cur.hostname = cur.hostname or obs.hostname
        cur.facts = {**obs.facts, **cur.facts}
        cur.source = f"{cur.source}+{obs.source}" if obs.source not in cur.source else cur.source
    return list(merged.values())


class ScanService:
    def __init__(
        self,
        repo: Repository,
        nmap: NmapCollector | None = None,
        neigh: NeighCollector | None = None,
        discovery: list[DiscoveryCollector] | None = None,
        host_probes: list[Any] | None = None,
        progress: ProgressSink | None = None,
    ) -> None:
        self.repo = repo
        self.nmap = nmap or NmapCollector()
        self.neigh = neigh or NeighCollector()
        self.discovery: list[DiscoveryCollector] = (
            [MdnsCollector(), SsdpCollector()] if discovery is None else discovery
        )
        # real probes only when running with the default (real) discovery collectors
        if host_probes is None:
            host_probes = [MdnsReverseCollector()] if discovery is None else []
        self.host_probes: list[Any] = host_probes
        self.progress = progress or (lambda _msg: None)
        self.cancel = threading.Event()
        self.nmap.cancel = self.cancel

    def _check_cancel(self) -> None:
        if self.cancel.is_set():
            raise ScanCancelled

    def _store_matter_nodes(self) -> None:
        for collector in self.discovery:
            for n in getattr(collector, "matter_nodes", []):
                host = self.repo.device_by_ip(n["host_ip"]) if n.get("host_ip") else None
                self.repo.upsert_matter_node(
                    n["instance"], n["fabric"], n["node"], n["addresses"], host
                )

    def run(self, targets: list[ipaddress.IPv4Network], profile: str) -> ScanResult:
        if profile == "watch":
            return self.watch(targets)
        scan_id = self.repo.start_scan(profile, ",".join(str(t) for t in targets))
        result = ScanResult(scan_id=scan_id, status="running")
        self.nmap.warnings.clear()
        try:
            raw: list[Observation] = []
            for net in targets:  # phase 1: cheap sweep to find who is alive
                self._check_cancel()
                self.progress(f"sweeping {net} …")
                raw.extend(self.nmap.collect(net, "quick"))
            self._check_cancel()
            self.progress("reading neighbour table …")
            raw.extend(self.neigh.collect())
            if (
                profile != "quick"
            ):  # phase 2: fingerprint every live host, even ones that drop pings
                live = sorted(
                    {o.ip for o in raw if o.ip and _in_any(o.ip, targets)},
                    key=lambda ip: tuple(int(x) for x in ip.split(".")),
                )
                self._check_cancel()
                self.progress(
                    f"{profile} fingerprinting of {len(live)} hosts (this takes a while) …"
                )
                raw.extend(self.nmap.collect_hosts(live, profile))
            if profile != "quick":  # mDNS/SSDP listen for a few seconds each
                for collector in self.discovery:
                    self._check_cancel()
                    self.progress(f"{collector.name} discovery …")
                    try:
                        raw.extend(collector.collect(targets))
                    except Exception as exc:  # one flaky source must not fail the scan
                        result.warnings.append(f"{collector.name} collector failed: {exc}")
            if profile != "quick":  # per-host questions (e.g. unicast mDNS reverse lookup)
                live_ips = sorted({o.ip for o in raw if o.ip and _in_any(o.ip, targets)})
                for probe in self.host_probes:
                    self._check_cancel()
                    self.progress(f"{probe.name} probing {len(live_ips)} hosts …")
                    try:
                        raw.extend(probe.collect_hosts(live_ips))
                    except Exception as exc:
                        result.warnings.append(f"{probe.name} probe failed: {exc}")
            result.warnings.extend(self.nmap.warnings)

            in_scope = [o for o in raw if o.ip and _in_any(o.ip, targets)]
            known_before = {d.uuid for d in self.repo.list_devices()}
            fingerprinted = {o.ip for o in raw if o.ip} if profile != "quick" else set()
            for obs in merge_by_ip(in_scope):
                self.repo.add_observation(scan_id, obs)
                uid = identity.resolve(self.repo, obs)
                self.repo.add_sighting(scan_id, uid, obs.ts)
                if obs.ip in fingerprinted:
                    self.repo.mark_probed(uid, obs.ts)
                result.hosts_seen += 1
            self._store_matter_nodes()
            self.repo.prune()
            self.repo.commit()
            result.new_devices = len({d.uuid for d in self.repo.list_devices()} - known_before)
            result.status = "done"
        except ScanCancelled:
            self.repo.conn.rollback()
            self.repo.finish_scan(scan_id, "cancelled")
            result.status = "cancelled"
            return result
        except Exception:
            self.repo.conn.rollback()
            result.status = "failed"
            self.repo.finish_scan(scan_id, "failed")
            raise
        self.repo.finish_scan(scan_id, result.status)
        return result

    # ---- watch: a light pass meant to run every 15-30 minutes ----------------------------------
    MAX_PROBES_PER_PASS = 8

    def watch(self, targets: list[ipaddress.IPv4Network]) -> ScanResult:
        """Who is online right now? Cheap sweep + neighbour table + mDNS, then a full fingerprint
        only for devices that are new or still unidentified (see Repository.devices_needing_probe).

        Running this regularly records *presence*, so devices that are off during a normal scan
        (sleeping IoT, phones, laptops) are caught when they wake up.
        """
        scan_id = self.repo.start_scan("watch", ",".join(str(t) for t in targets))
        result = ScanResult(scan_id=scan_id, status="running")
        self.nmap.warnings.clear()
        try:
            raw: list[Observation] = []
            for net in targets:
                self._check_cancel()
                self.progress(f"sweeping {net} …")
                raw.extend(self.nmap.collect(net, "quick"))
            raw.extend(self.neigh.collect())
            for collector in self.discovery:
                if collector.name != "mdns":  # SSDP etc. only in full scans: keep this pass light
                    continue
                self._check_cancel()
                self.progress("mdns discovery …")
                try:
                    raw.extend(collector.collect(targets))
                except Exception as exc:
                    result.warnings.append(f"{collector.name} collector failed: {exc}")
            live_ips = sorted({o.ip for o in raw if o.ip and _in_any(o.ip, targets)})
            for probe in self.host_probes:
                self._check_cancel()
                try:
                    raw.extend(probe.collect_hosts(live_ips))
                except Exception as exc:
                    result.warnings.append(f"{probe.name} probe failed: {exc}")

            known_before = {d.uuid for d in self.repo.list_devices()}
            present: list[str] = []
            in_scope = [o for o in raw if o.ip and _in_any(o.ip, targets)]
            for obs in merge_by_ip(in_scope):
                self.repo.add_observation(scan_id, obs)
                uid = identity.resolve(self.repo, obs)
                self.repo.add_sighting(scan_id, uid, obs.ts)
                present.append(uid)
                result.hosts_seen += 1
            self._store_matter_nodes()
            self.repo.commit()

            todo = self.repo.devices_needing_probe(present, limit=self.MAX_PROBES_PER_PASS)
            if todo:
                self._check_cancel()
                self.progress(f"fingerprinting {len(todo)} new or unidentified hosts …")
                ips = [ip for _uid, ip in todo]
                for obs in merge_by_ip(self.nmap.collect_hosts(ips, "standard")):
                    self.repo.add_observation(scan_id, obs)
                    identity.resolve(self.repo, obs)
                for uid, _ip in todo:
                    self.repo.mark_probed(uid)
                result.probed = len(todo)
            result.warnings.extend(self.nmap.warnings)

            current = {d.uuid: d for d in self.repo.list_devices()}
            result.new_devices = len(set(current) - known_before)
            result.new_unknown = [
                f"{d.ip} ({d.vendor or 'unknown vendor'})"
                for uid, d in current.items()
                if uid not in known_before and d.device_type == "unknown"
            ]
            self.repo.prune()
            self.repo.commit()
            result.status = "done"
        except ScanCancelled:
            self.repo.conn.rollback()
            self.repo.finish_scan(scan_id, "cancelled")
            result.status = "cancelled"
            return result
        except Exception:
            self.repo.conn.rollback()
            self.repo.finish_scan(scan_id, "failed")
            raise
        self.repo.finish_scan(scan_id, result.status)
        return result


def _in_any(ip: str, nets: list[ipaddress.IPv4Network]) -> bool:
    addr = ipaddress.IPv4Address(ip)
    return any(addr in n for n in nets)
