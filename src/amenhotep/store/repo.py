"""Repository: the only place that writes SQL. All statements are parameterised."""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from amenhotep.core.models import Observation, utcnow


def _iso(ts: datetime | None = None) -> str:
    return (ts or utcnow()).isoformat(timespec="seconds")


@dataclass
class DeviceRow:
    uuid: str
    display_name: str | None
    device_type: str
    os_family: str
    vendor: str | None
    model: str | None
    location_mode: str
    area: str | None
    is_infrastructure: bool
    ip: str | None
    mac: str | None
    hostname: str | None
    last_seen: str | None
    notes: str | None = None
    locked_fields: list[str] = field(default_factory=list)
    os_detail: str | None = None
    hardware_notes: str | None = None
    area_id: int | None = None
    online: bool | None = None  # seen in the latest finished scan (None: no scan yet)
    zone: str | None = None  # parent zone of a room (None for zones and unassigned devices)

    @property
    def online_label(self) -> str:
        return {True: "online", False: "offline", None: ""}[self.online]

    @property
    def area_label(self) -> str:
        """'Main bedroom · First floor' for a room, 'Garden' for a zone, '' if unassigned."""
        if not self.area:
            return ""
        return f"{self.area} · {self.zone}" if self.zone else self.area


@dataclass
class HomekitRow:
    device_uuid: str
    name: str
    ip: str | None
    protocol: str
    category: str
    model: str | None
    paired: bool | None
    area: str | None
    last_seen: str | None


@dataclass
class MatterNodeRow:
    instance: str
    fabric: str
    node: str
    addresses: list[str]
    host_uuid: str | None
    host_name: str | None
    label: str | None
    area: str | None
    last_seen: str
    area_id: int | None = None


@dataclass
class BorderRouterRow:
    device_uuid: str
    name: str
    ip: str | None
    network_name: str | None
    vendor: str | None
    model: str | None
    last_seen: str


@dataclass
class AreaRow:
    id: int
    name: str
    kind: str  # 'zone' | 'room'
    parent_id: int | None
    zone: str | None  # parent zone name for rooms

    @property
    def label(self) -> str:
        return f"{self.name} · {self.zone}" if self.zone else self.name


# Columns a user may lock against scan overwrites.
LOCKABLE = {"display_name", "device_type", "os_family", "vendor", "model", "location_mode"}


class Repository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # ---- scans -------------------------------------------------------
    def start_scan(self, profile: str, target: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO scan(started, profile, target, status) VALUES (?,?,?, 'running')",
            (_iso(), profile, target),
        )
        self.conn.commit()
        return int(cur.lastrowid or 0)

    def finish_scan(self, scan_id: int, status: str) -> None:
        self.conn.execute(
            "UPDATE scan SET finished=?, status=? WHERE id=?", (_iso(), status, scan_id)
        )
        self.conn.commit()

    def add_observation(self, scan_id: int, obs: Observation) -> None:
        self.conn.execute(
            "INSERT INTO observation(scan_id, source, ip, mac, facts_json, ts) "
            "VALUES (?,?,?,?,?,?)",
            (
                scan_id,
                obs.source,
                obs.ip,
                obs.mac,
                json.dumps(obs.facts, default=str),
                _iso(obs.ts),
            ),
        )

    def latest_scan_observations(self) -> list[tuple[Observation, str | None]]:
        """Observations of the newest finished scan, each with the hostname we know for its IP."""
        scan = self.conn.execute(
            "SELECT id FROM scan WHERE status='done' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not scan:
            return []
        out = []
        for r in self.conn.execute(
            "SELECT source, ip, mac, facts_json, ts FROM observation WHERE scan_id=?", (scan["id"],)
        ):
            host = self.conn.execute(
                "SELECT hostname FROM interface WHERE ip=? AND hostname IS NOT NULL "
                "ORDER BY last_seen DESC LIMIT 1",
                (r["ip"],),
            ).fetchone()
            obs = Observation(
                source=r["source"],
                ip=r["ip"],
                mac=r["mac"],
                facts=json.loads(r["facts_json"]),
                ts=datetime.fromisoformat(r["ts"]),
            )
            out.append((obs, host["hostname"] if host else None))
        return out

    # ---- lookup ------------------------------------------------------
    def device_by_mac(self, mac: str) -> str | None:
        row = self.conn.execute("SELECT device_uuid FROM interface WHERE mac=?", (mac,)).fetchone()
        return row["device_uuid"] if row else None

    def device_by_ip(self, ip: str) -> str | None:
        row = self.conn.execute(
            "SELECT device_uuid FROM interface WHERE ip=? ORDER BY last_seen DESC LIMIT 1", (ip,)
        ).fetchone()
        return row["device_uuid"] if row else None

    # ---- writes ------------------------------------------------------
    def create_device(self, ts: datetime) -> str:
        new_id = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO device(uuid, first_seen, last_seen) VALUES (?,?,?)",
            (new_id, _iso(ts), _iso(ts)),
        )
        return new_id

    def locked(self, device_uuid: str) -> set[str]:
        row = self.conn.execute(
            "SELECT locked_fields FROM device WHERE uuid=?", (device_uuid,)
        ).fetchone()
        return set(json.loads(row["locked_fields"])) if row else set()

    def touch_interface(
        self,
        device_uuid: str,
        *,
        mac: str | None,
        mac_random: bool,
        ip: str | None,
        hostname: str | None,
        ts: datetime,
    ) -> None:
        if ip:  # an IP belongs to one interface at a time
            self.conn.execute(
                "UPDATE interface SET ip=NULL WHERE ip=? AND device_uuid<>?", (ip, device_uuid)
            )
        existing = None
        if mac:
            existing = self.conn.execute("SELECT id FROM interface WHERE mac=?", (mac,)).fetchone()
        elif ip:
            existing = self.conn.execute(
                "SELECT id FROM interface WHERE device_uuid=? AND ip=?", (device_uuid, ip)
            ).fetchone()
        if existing:
            self.conn.execute(
                "UPDATE interface SET ip=COALESCE(?, ip), hostname=COALESCE(?, hostname), "
                "last_seen=? WHERE id=?",
                (ip, hostname, _iso(ts), existing["id"]),
            )
        else:
            self.conn.execute(
                "INSERT INTO interface(device_uuid, mac, mac_random, ip, hostname, last_seen) "
                "VALUES (?,?,?,?,?,?)",
                (device_uuid, mac, int(mac_random), ip, hostname, _iso(ts)),
            )
        self.conn.execute("UPDATE device SET last_seen=? WHERE uuid=?", (_iso(ts), device_uuid))

    def set_fields(self, device_uuid: str, fields: dict[str, Any], *, user: bool = False) -> None:
        """Scan-derived updates skip locked fields; user edits lock them."""
        allowed = LOCKABLE | {"hardware_notes", "notes", "os_detail", "is_infrastructure"}
        locked = self.locked(device_uuid)
        for key, value in fields.items():
            if key not in allowed:
                raise ValueError(f"unknown device field {key!r}")
            if not user and key in locked:
                continue
            self.conn.execute(f"UPDATE device SET {key}=? WHERE uuid=?", (value, device_uuid))
            if user and key in LOCKABLE:
                locked.add(key)
        if user:
            self.conn.execute(
                "UPDATE device SET locked_fields=? WHERE uuid=?",
                (json.dumps(sorted(locked)), device_uuid),
            )
            if "location_mode" in fields:
                self._sync_area_with_mode(device_uuid, fields["location_mode"])

    # ---- areas (zones and rooms) ----------------------------------------
    def list_areas(self) -> list[AreaRow]:
        rows = self.conn.execute(
            """SELECT a.id, a.name, a.kind, a.parent_id, z.name AS zone
               FROM area a LEFT JOIN area z ON z.id = a.parent_id
               ORDER BY COALESCE(a.parent_id, a.id), a.parent_id IS NOT NULL, a.name"""
        ).fetchall()
        return [AreaRow(r["id"], r["name"], r["kind"], r["parent_id"], r["zone"]) for r in rows]

    def roaming_zone_id(self) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM area WHERE kind='zone' AND name='Roaming'"
        ).fetchone()
        return int(row[0]) if row else None

    def assign_area(
        self, device_uuids: list[str], area_id: int | None, *, mode: str | None = None
    ) -> None:
        """Put devices in a zone/room (None = unassigned).

        Assigning the Roaming zone makes a device roaming. ``mode='fixed'`` pins it (and locks
        the mode so scans never change it): used for phones/tablets that act as night-table
        clocks.
        """
        if (
            area_id is not None
            and not self.conn.execute("SELECT 1 FROM area WHERE id=?", (area_id,)).fetchone()
        ):
            raise ValueError(f"unknown area {area_id}")
        if mode not in (None, "fixed", "roaming"):
            raise ValueError(f"bad mode {mode!r}")
        if area_id is not None and area_id == self.roaming_zone_id():
            mode = "roaming"
        for uid in device_uuids:
            if mode:
                self.set_fields(uid, {"location_mode": mode}, user=True)
            if area_id is not None or mode != "roaming":
                self.conn.execute("UPDATE device SET area_id=? WHERE uuid=?", (area_id, uid))

    def _sync_area_with_mode(self, device_uuid: str, mode: str) -> None:
        roaming = self.roaming_zone_id()
        row = self.conn.execute(
            "SELECT area_id FROM device WHERE uuid=?", (device_uuid,)
        ).fetchone()
        if not row:
            return
        if mode == "roaming" and row[0] is None:
            self.conn.execute("UPDATE device SET area_id=? WHERE uuid=?", (roaming, device_uuid))
        elif mode == "fixed" and row[0] is not None and row[0] == roaming:
            self.conn.execute("UPDATE device SET area_id=NULL WHERE uuid=?", (device_uuid,))

    def add_area(self, name: str, kind: str, parent_id: int | None = None) -> int:
        name = name.strip()
        if not name or len(name) > 64:
            raise ValueError("area name must be 1-64 characters")
        if kind == "room" and parent_id is None:
            raise ValueError("a room needs a parent zone")
        if kind == "zone" and parent_id is not None:
            raise ValueError("a zone has no parent")
        cur = self.conn.execute(
            "INSERT INTO area(name, kind, parent_id) VALUES (?,?,?)", (name, kind, parent_id)
        )
        return int(cur.lastrowid or 0)

    def rename_area(self, area_id: int, name: str) -> None:
        name = name.strip()
        if not name or len(name) > 64:
            raise ValueError("area name must be 1-64 characters")
        self.conn.execute("UPDATE area SET name=? WHERE id=?", (name, area_id))

    def delete_area(self, area_id: int) -> None:
        """Devices in it become unassigned; rooms of a deleted zone lose their parent."""
        self.conn.execute("DELETE FROM area WHERE id=?", (area_id,))

    def replace_evidence(
        self,
        device_uuid: str,
        field: str,
        source: str,
        value: str,
        confidence: float,
        detail: str | None = None,
    ) -> None:
        self.conn.execute(
            "DELETE FROM evidence WHERE device_uuid=? AND field=? AND source=?",
            (device_uuid, field, source),
        )
        self.conn.execute(
            "INSERT INTO evidence(device_uuid, field, value, confidence, source, detail, seen_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (device_uuid, field, value, confidence, source, detail, _iso()),
        )

    def apply_best_evidence(self, device_uuid: str) -> None:
        """Set each classified field to its highest-confidence evidence (skips locked fields)."""
        for column in (
            "os_family",
            "device_type",
            "vendor",
            "model",
            "os_detail",
            "hardware_notes",
        ):
            row = self.conn.execute(
                "SELECT value FROM evidence WHERE device_uuid=? AND field=? "
                "ORDER BY confidence DESC, seen_at DESC, id DESC LIMIT 1",
                (device_uuid, column),
            ).fetchone()
            if row:
                self.set_fields(device_uuid, {column: row["value"]})
            else:  # evidence withdrawn (e.g. a contradicted nmap guess): fall back to default
                default = "unknown" if column in ("os_family", "device_type") else None
                self.set_fields(device_uuid, {column: default})

    def upsert_homekit(
        self,
        device_uuid: str,
        hap_id: str | None,
        category: int | None,
        model: str | None,
        paired: bool | None,
        protocol: str = "hap",
    ) -> None:
        self.conn.execute(
            "INSERT INTO homekit_accessory"
            "(device_uuid, hap_id, category_id, model, paired, protocol)"
            " VALUES (?,?,?,?,?,?) ON CONFLICT(device_uuid) DO UPDATE SET "
            "hap_id=COALESCE(excluded.hap_id, hap_id), "
            "category_id=COALESCE(excluded.category_id, category_id), "
            "model=COALESCE(excluded.model, model), paired=COALESCE(excluded.paired, paired)",
            (
                device_uuid,
                hap_id,
                category,
                model,
                None if paired is None else int(paired),
                protocol,
            ),
        )

    # ---- Matter / Thread ---------------------------------------------------
    def upsert_matter_node(
        self,
        instance: str,
        fabric: str,
        node: str,
        addresses: list[str],
        host_uuid: str | None,
        ts: datetime | None = None,
    ) -> None:
        now = _iso(ts)
        self.conn.execute(
            "INSERT INTO matter_node(instance, fabric, node, addresses, host_uuid, first_seen,"
            " last_seen) VALUES (?,?,?,?,?,?,?) ON CONFLICT(instance) DO UPDATE SET "
            "addresses=excluded.addresses, last_seen=excluded.last_seen, "
            "host_uuid=COALESCE(excluded.host_uuid, host_uuid)",
            (instance, fabric, node, json.dumps(sorted(addresses)), host_uuid, now, now),
        )

    def set_matter_label(self, instance: str, label: str | None, area_id: int | None) -> None:
        self.conn.execute(
            "UPDATE matter_node SET label=?, area_id=? WHERE instance=?",
            ((label or "").strip()[:64] or None, area_id, instance),
        )

    def list_matter_nodes(self) -> list[MatterNodeRow]:
        rows = self.conn.execute(
            """SELECT m.*, a.name AS area_name,
                      COALESCE(d.display_name, (SELECT hostname FROM interface i
                          WHERE i.device_uuid=d.uuid AND hostname IS NOT NULL LIMIT 1)) AS host_name
               FROM matter_node m LEFT JOIN device d ON d.uuid=m.host_uuid
                    LEFT JOIN area a ON a.id=m.area_id
               ORDER BY m.fabric, m.node"""
        ).fetchall()
        return [
            MatterNodeRow(
                r["instance"],
                r["fabric"],
                r["node"],
                json.loads(r["addresses"]),
                r["host_uuid"],
                r["host_name"],
                r["label"],
                r["area_name"],
                r["last_seen"],
                r["area_id"],
            )
            for r in rows
        ]

    def upsert_border_router(
        self,
        device_uuid: str,
        network_name: str | None,
        vendor: str | None,
        model: str | None,
        ts: datetime | None = None,
    ) -> None:
        self.conn.execute(
            "INSERT INTO thread_border_router(device_uuid, network_name, vendor, model, last_seen)"
            " VALUES (?,?,?,?,?) ON CONFLICT(device_uuid) DO UPDATE SET "
            "network_name=excluded.network_name, vendor=excluded.vendor, model=excluded.model, "
            "last_seen=excluded.last_seen",
            (device_uuid, network_name, vendor, model, _iso(ts)),
        )

    def list_border_routers(self) -> list[BorderRouterRow]:
        rows = self.conn.execute(
            """SELECT b.*, d.display_name,
                      (SELECT ip FROM interface i WHERE i.device_uuid=d.uuid
                           ORDER BY i.last_seen DESC LIMIT 1) AS ip,
                      (SELECT hostname FROM interface i WHERE i.device_uuid=d.uuid
                           AND hostname IS NOT NULL LIMIT 1) AS hostname
               FROM thread_border_router b JOIN device d ON d.uuid=b.device_uuid
               ORDER BY b.network_name, ip"""
        ).fetchall()
        return [
            BorderRouterRow(
                r["device_uuid"],
                r["display_name"] or r["hostname"] or r["ip"] or r["device_uuid"],
                r["ip"],
                r["network_name"],
                r["vendor"],
                r["model"],
                r["last_seen"],
            )
            for r in rows
        ]

    def list_homekit(self) -> list[HomekitRow]:
        from amenhotep.services.classify import hap_categories

        cats = hap_categories()
        rows = self.conn.execute(
            """SELECT h.*, d.display_name, d.last_seen, a.name AS area_name,
                      (SELECT ip FROM interface i WHERE i.device_uuid=d.uuid
                           ORDER BY i.last_seen DESC LIMIT 1) AS ip,
                      (SELECT hostname FROM interface i WHERE i.device_uuid=d.uuid
                           AND hostname IS NOT NULL LIMIT 1) AS hostname
               FROM homekit_accessory h JOIN device d ON d.uuid=h.device_uuid
                    LEFT JOIN area a ON a.id=d.area_id
               ORDER BY d.display_name IS NULL, d.display_name, ip"""
        ).fetchall()
        return [
            HomekitRow(
                r["device_uuid"],
                r["display_name"] or r["hostname"] or r["model"] or r["ip"] or "?",
                r["ip"],
                r["protocol"],
                cats.get(r["category_id"], ("", ""))[1] if r["category_id"] else "",
                r["model"],
                None if r["paired"] is None else bool(r["paired"]),
                r["area_name"],
                r["last_seen"],
            )
            for r in rows
        ]

    def unlock_fields(self, device_uuid: str, fields: list[str]) -> None:
        """Let scans update these fields again (the current value is kept until the next scan)."""
        keep = sorted(self.locked(device_uuid) - set(fields))
        self.conn.execute(
            "UPDATE device SET locked_fields=? WHERE uuid=?", (json.dumps(keep), device_uuid)
        )

    # ---- presence ---------------------------------------------------------
    def add_sighting(self, scan_id: int, device_uuid: str, ts: datetime | None = None) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO sighting(device_uuid, scan_id, ts) VALUES (?,?,?)",
            (device_uuid, scan_id, _iso(ts)),
        )

    def mark_probed(self, device_uuid: str, ts: datetime | None = None) -> None:
        self.conn.execute("UPDATE device SET last_probed=? WHERE uuid=?", (_iso(ts), device_uuid))

    def devices_needing_probe(
        self, device_uuids: list[str], min_age_h: float = 6.0, limit: int = 8
    ) -> list[tuple[str, str]]:
        """(uuid, ip) of devices worth a full fingerprint now.

        Never probed, or still unidentified and not probed recently. Capped, so a pass stays short
        and fragile devices are not hammered.
        """
        cutoff = _iso(utcnow() - timedelta(hours=min_age_h))
        out: list[tuple[str, str]] = []
        for uid in device_uuids:
            row = self.conn.execute(
                "SELECT d.device_type, d.last_probed, "
                "(SELECT ip FROM interface i WHERE i.device_uuid=d.uuid AND ip IS NOT NULL "
                " ORDER BY i.last_seen DESC LIMIT 1) AS ip FROM device d WHERE d.uuid=?",
                (uid,),
            ).fetchone()
            if not row or not row["ip"]:
                continue
            last = row["last_probed"]
            stale_unknown = row["device_type"] == "unknown" and last is not None and last < cutoff
            if last is None or stale_unknown:
                out.append((uid, row["ip"]))
            if len(out) >= limit:
                break
        return out

    def scan_times(self, days: int = 7) -> list[datetime]:
        cutoff = _iso(utcnow() - timedelta(days=days))
        rows = self.conn.execute(
            "SELECT started FROM scan WHERE status='done' AND started>=? "
            "AND id IN (SELECT scan_id FROM sighting) ORDER BY started",  # only checks that logged
            (cutoff,),
        ).fetchall()
        return [datetime.fromisoformat(r["started"]).astimezone() for r in rows]

    def sighting_times(self, days: int = 7) -> dict[str, list[datetime]]:
        """Per device: start time of every finished scan that saw it (local timezone)."""
        cutoff = _iso(utcnow() - timedelta(days=days))
        out: dict[str, list[datetime]] = {}
        for r in self.conn.execute(
            "SELECT g.device_uuid, s.started FROM sighting g JOIN scan s ON s.id=g.scan_id "
            "WHERE s.status='done' AND s.started>=? ORDER BY s.started",
            (cutoff,),
        ):
            out.setdefault(r["device_uuid"], []).append(
                datetime.fromisoformat(r["started"]).astimezone()
            )
        return out

    def online_uuids(self) -> set[str] | None:
        scan = self.conn.execute(
            "SELECT id FROM scan WHERE status='done' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not scan:
            return None
        return {
            r["device_uuid"]
            for r in self.conn.execute(
                "SELECT device_uuid FROM sighting WHERE scan_id=?", (scan["id"],)
            )
        }

    def prune(self, days: int = 90) -> None:
        """Drop scans (and their observations/sightings) older than the retention window."""
        cutoff = _iso(utcnow() - timedelta(days=days))
        self.conn.execute(
            "DELETE FROM scan WHERE started<? AND id NOT IN "
            "(SELECT MAX(id) FROM scan WHERE status='done')",
            (cutoff,),
        )

    def list_scans(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT id, started, finished, profile, target, status FROM scan "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()

    def evidence_for(self, device_uuid: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT field, value, confidence, source, detail FROM evidence WHERE device_uuid=? "
            "ORDER BY field, confidence DESC",
            (device_uuid,),
        ).fetchall()

    def device_by_ip_or_name(self, key: str) -> str | None:
        return self.device_by_ip(key) or (
            (
                r := self.conn.execute(
                    "SELECT device_uuid FROM interface WHERE hostname=? LIMIT 1", (key,)
                ).fetchone()
            )
            and r["device_uuid"]
        )

    def clear_evidence_source(self, device_uuid: str, source: str) -> None:
        self.conn.execute(
            "DELETE FROM evidence WHERE device_uuid=? AND source=?", (device_uuid, source)
        )

    def get_field(self, device_uuid: str, field: str) -> Any:
        if field not in LOCKABLE | {"os_detail"}:
            raise ValueError(field)
        row = self.conn.execute(
            f"SELECT {field} FROM device WHERE uuid=?", (device_uuid,)
        ).fetchone()
        return row[0] if row else None

    # ---- reads -------------------------------------------------------
    def list_devices(self) -> list[DeviceRow]:
        rows = self.conn.execute(
            """
            SELECT d.*, a.name AS area_name, z.name AS zone_name,
                   (SELECT ip FROM interface i WHERE i.device_uuid=d.uuid
                        ORDER BY i.last_seen DESC LIMIT 1) AS ip,
                   (SELECT mac FROM interface i WHERE i.device_uuid=d.uuid
                        ORDER BY i.last_seen DESC LIMIT 1) AS mac,
                   (SELECT hostname FROM interface i WHERE i.device_uuid=d.uuid
                        ORDER BY i.last_seen DESC LIMIT 1) AS hostname
            FROM device d LEFT JOIN area a ON a.id = d.area_id
                          LEFT JOIN area z ON z.id = a.parent_id
            ORDER BY d.last_seen DESC
            """
        ).fetchall()
        online = self.online_uuids()
        return [
            DeviceRow(
                uuid=r["uuid"],
                display_name=r["display_name"],
                device_type=r["device_type"],
                os_family=r["os_family"],
                vendor=r["vendor"],
                model=r["model"],
                location_mode=r["location_mode"],
                area=r["area_name"],
                is_infrastructure=bool(r["is_infrastructure"]),
                ip=r["ip"],
                mac=r["mac"],
                hostname=r["hostname"],
                last_seen=r["last_seen"],
                notes=r["notes"],
                locked_fields=json.loads(r["locked_fields"]),
                os_detail=r["os_detail"],
                hardware_notes=r["hardware_notes"],
                area_id=r["area_id"],
                online=None if online is None else r["uuid"] in online,
                zone=r["zone_name"],
            )
            for r in rows
        ]

    def commit(self) -> None:
        self.conn.commit()
