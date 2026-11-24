"""Import a HomeMapper (iPhone app) CSV export into Devices and Thread/Matter.

HomeMapper lists what the Apple Home app knows: names, rooms, serial numbers, firmware and the
Thread details of each accessory. Each row is merged into what scans found:

* a row is matched to a device by serial, MAC, IPv4 address, then (conservatively) by name;
* a row whose IPv6 address belongs to a Matter node enriches that node (Thread/Matter tab);
* values with no column of their own (firmware, battery, signal, Thread role, ...) go into a
  marked block of the device's or node's Notes, which a re-import replaces, never duplicates;
* an unmatched row becomes a new device, so nothing in the file is lost;
* user edits stay: locked fields and existing names/areas are never overwritten, and a row whose
  identity contradicts the stored device (different vendor *and* model) only adds a note.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path

from amenhotep.core.models import utcnow
from amenhotep.store.repo import DeviceRow, MatterNodeRow, Repository

SOURCE = "homemapper"
CONFIDENCE = 0.9  # what the Home app says beats scan guesses; user edits (locked) still win
MAX_BYTES = 5_000_000

# HomeMapper "Category" -> Amenhotep device_type ("" = leave the type alone)
CATEGORY_TYPES = {
    "outlet": "smart-plug",
    "lightbulb": "smart-light",
    "window covering": "smart-appliance",
    "video doorbell": "camera",
    "ip camera": "camera",
    "bridge": "hub",
    "sensor": "iot-sensor",
    "programmable switch": "other",
    "printer": "printer",
    "homepod": "speaker",
    "speaker": "speaker",
    "apple tv": "media-player",
    "remote device": "",
}
_ALIASES = {"lumi": "aqara", "dexatek": "eve", "homebridgeio": "homebridge"}
_START, _END = "[HomeMapper import: {}]", "[/HomeMapper import]"
_BLOCK_RE = re.compile(r"\[HomeMapper import: [^\]\n]*\].*?\[/HomeMapper import\]\n?", re.DOTALL)


@dataclass
class ImportResult:
    filename: str
    rows: int = 0
    matched: int = 0
    created: int = 0
    thread: int = 0
    conflicts: int = 0
    rooms_created: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)


def _norm(text: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").casefold())


def _same_brand(a: str | None, b: str | None) -> bool:
    x, y = _norm(a), _norm(b)
    if not x or not y:
        return True  # nothing to disagree about
    for alias, canon in _ALIASES.items():
        x, y = x.replace(alias, canon), y.replace(alias, canon)
    return x in y or y in x or x[:5] == y[:5]


def _same_model(a: str | None, b: str | None) -> bool:
    x, y = _norm(a), _norm(b)
    return not x or not y or x in y or y in x


def _addrs(value: str) -> list[str]:
    out = []
    for part in value.split("|"):
        part = part.strip()
        if part:
            try:
                out.append(str(ip_address(part)))
            except ValueError:
                continue
    return out


def _mac(value: str) -> str | None:
    value = value.strip().lower()
    return value if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", value) else None


def set_block(existing: str | None, filename: str, lines: list[str]) -> str | None:
    """Put the import block into ``existing`` notes, replacing an earlier block."""
    base = _BLOCK_RE.sub("", existing or "").rstrip()
    if not lines:
        return base or None
    block = "\n".join([_START.format(filename), *lines, _END])
    return f"{base}\n\n{block}" if base else block


def _clean(row: dict[str, str]) -> dict[str, str]:
    return {k.strip(): (v or "").strip() for k, v in row.items() if k}


def read_rows(path: Path) -> list[dict[str, str]]:
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"{path.name}: file too large for a HomeMapper export")
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or "Name" not in reader.fieldnames:
            raise ValueError(f"{path.name}: not a HomeMapper device export (no Name column)")
        return [_clean(r) for r in reader]


class HomeMapperImporter:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo
        self._areas = {a.name.casefold(): a.id for a in repo.list_areas()}
        self._claimed: set[str] = set()

    # ---- helpers -----------------------------------------------------------
    def _area_id(self, room: str, result: ImportResult) -> int | None:
        if not room:
            return None
        key = room.casefold()
        if key not in self._areas:
            self._areas[key] = self.repo.add_area(room, "zone")  # floor unknown: no guess
            result.rooms_created.append(room)
            result.messages.append(f"{room}: unknown to Amenhotep, added as an area (no floor)")
        return self._areas[key]

    def _match_device(self, row: dict[str, str], by_name: dict[str, list[str]]) -> str | None:
        repo = self.repo
        if row["Serial Number"] and (u := repo.device_by_serial(row["Serial Number"])):
            return u
        if (m := _mac(row["MAC Address"])) and (u := repo.device_by_mac(m)):
            return u
        for ip in _addrs(row["IP Address"]):
            if "." in ip and (u := repo.device_by_ip(ip)):
                return u
        candidates = by_name.get(row["Name"].casefold(), [])
        free = [u for u in candidates if u not in self._claimed]
        return free[0] if len(free) == 1 else None

    def _match_by_unique_model(
        self, pending: list[tuple[dict[str, str], str | None]]
    ) -> list[tuple[dict[str, str], str | None]]:
        """Last resort: one unmatched row and one unclaimed device share the same model."""
        loose = [r for r, u in pending if u is None and _norm(r["Model"])]
        devices = [d for d in self.repo.list_devices() if d.uuid not in self._claimed]
        out = []
        for row, uuid in pending:
            if uuid is None and _norm(row["Model"]):
                key = _norm(row["Model"])
                rows_n = sum(1 for r in loose if _norm(r["Model"]) == key)
                cands = [
                    d
                    for d in devices
                    if _norm(d.model) == key and _same_brand(d.vendor, row["Manufacturer"])
                ]
                if rows_n == 1 and len(cands) == 1:
                    uuid = cands[0].uuid
                    self._claimed.add(uuid)
            out.append((row, uuid))
        return out

    def _name_index(self) -> dict[str, list[str]]:
        """Existing names, also short: 'Salon / Plug' as 'salon', 'Kitchen Lamp' as 'lamp'."""
        index: dict[str, list[str]] = {}
        for d in self.repo.list_devices():
            if d.display_name:
                low = d.display_name.casefold()
                keys = {low, low.split(" / ")[0], low.split(" ", 1)[-1]}
                for key in keys:
                    index.setdefault(key, []).append(d.uuid)
        return index

    # ---- main ------------------------------------------------------------------
    def run(self, path: Path) -> ImportResult:
        repo = self.repo
        result = ImportResult(filename=path.name)
        rows = read_rows(path)
        result.rows = len(rows)
        by_name = self._name_index()
        matter_nodes = repo.list_matter_nodes()
        pending = [(r, self._match_device(r, by_name)) for r in rows]
        self._claimed = {u for _, u in pending if u}
        pending = self._match_by_unique_model(pending)
        for row, uuid in pending:
            self._row(row, uuid, matter_nodes, result)
        repo.add_import_log(
            result.filename,
            result.rows,
            result.matched,
            result.created,
            result.thread,
            result.conflicts,
            result.messages,
        )
        repo.commit()
        return result

    def _row(
        self,
        row: dict[str, str],
        uuid: str | None,
        nodes: list[MatterNodeRow],
        result: ImportResult,
    ) -> None:
        repo = self.repo
        name = row["Name"] or "(unnamed)"
        addrs = _addrs(row["IP Address"])
        v6 = {a for a in addrs if ":" in a and not a.lower().startswith("fe80")}
        hit = [n for n in nodes if v6 & set(n.addresses)]
        is_thread = bool(row["Thread Network"] or row["Thread Role"])
        category = row["Category"]
        ctype = CATEGORY_TYPES.get(category.casefold())

        # -- device: find or create ------------------------------------------------
        existing_note = None
        conflict = False
        if uuid is None and not hit:
            uuid = self._create(row, addrs, ctype, result)
            result.created += 1
            result.messages.append(f"{name}: new device ({category or 'unknown'})")
        elif uuid is not None:
            result.matched += 1
            d = next(d for d in repo.list_devices() if d.uuid == uuid)
            existing_note = d.notes
            conflict = not _same_brand(d.vendor, row["Manufacturer"]) and not _same_model(
                d.model, row["Model"]
            )
            if conflict:
                result.conflicts += 1
                result.messages.append(
                    f"{name}: Home app says {row['Manufacturer']} {row['Model']}, but the device "
                    f"at {', '.join(a for a in addrs if '.' in a)} is {d.vendor} {d.model}: "
                    "identity left unchanged, details added to Notes"
                )
            else:
                self._enrich(uuid, d, row, ctype, result)

        # -- thread / matter ---------------------------------------------------------
        thread_lines = self._thread_lines(row)
        if hit:
            result.thread += 1
            for n in hit:
                if not n.label:
                    repo.set_matter_label(
                        n.instance, name, n.area_id or self._area_id(row["Room"], result)
                    )
                elif n.area_id is None and row["Room"]:
                    repo.set_matter_label(n.instance, n.label, self._area_id(row["Room"], result))
                repo.set_matter_notes(
                    n.instance,
                    set_block(n.notes, result.filename, self._lines(row, name) + thread_lines),
                )
            result.messages.append(f"{name}: matched {len(hit)} Matter node(s)")
        if uuid is None:
            return

        # -- notes of the device (and border router) ------------------------------------
        general = self._lines(row, name)
        if conflict:
            general.insert(0, "WARNING: identity differs from the Home app (see import log)")
        if is_thread and not hit:
            general += thread_lines
        if "border router" in row["Thread Role"].casefold():
            repo.upsert_border_router(
                uuid,
                row["Thread Network"] or None,
                row["Manufacturer"] or None,
                row["Model"] or None,
            )
            br = next((b for b in repo.list_border_routers() if b.device_uuid == uuid), None)
            repo.set_border_router_notes(
                uuid, set_block(br.notes if br else None, result.filename, thread_lines)
            )
        repo.set_fields(uuid, {"notes": set_block(existing_note, result.filename, general)})
        if row["Serial Number"] and not conflict:
            repo.set_serial(uuid, row["Serial Number"])

    def _create(
        self, row: dict[str, str], addrs: list[str], ctype: str | None, result: ImportResult
    ) -> str:
        repo = self.repo
        ts = utcnow()
        uuid = repo.create_device(ts)
        v4 = next((a for a in addrs if "." in a), None)
        mac = _mac(row["MAC Address"])
        if v4 or mac:
            repo.touch_interface(uuid, mac=mac, mac_random=False, ip=v4, hostname=None, ts=ts)
        repo.set_fields(uuid, {"display_name": row["Name"] or None})
        if row["Serial Number"]:
            repo.set_serial(uuid, row["Serial Number"])
        self._evidence(uuid, row, ctype)
        if "HomeKit" in row["Found via"]:
            repo.upsert_homekit(uuid, None, None, row["Model"] or None, None)
        if aid := self._area_id(row["Room"], result):
            repo.assign_area([uuid], aid)
        return uuid

    def _evidence(self, uuid: str, row: dict[str, str], ctype: str | None) -> None:
        repo = self.repo
        for field_, value in (
            ("vendor", row["Manufacturer"]),
            ("model", row["Model"]),
            ("device_type", ctype or ""),
        ):
            if value:
                repo.replace_evidence(uuid, field_, SOURCE, value, CONFIDENCE, "HomeMapper export")
        repo.apply_best_evidence(uuid)

    def _enrich(
        self, uuid: str, d: DeviceRow, row: dict[str, str], ctype: str | None, result: ImportResult
    ) -> None:
        self._evidence(uuid, row, ctype)
        if not d.display_name and row["Name"]:
            self.repo.set_fields(uuid, {"display_name": row["Name"]})
        if d.area_id is None and (aid := self._area_id(row["Room"], result)):
            self.repo.assign_area([uuid], aid)

    @staticmethod
    def _lines(row: dict[str, str], name: str) -> list[str]:
        pairs = [
            ("Home app name", name),
            ("Home / place", " / ".join(p for p in (row["Home"], row["Place"]) if p)),
            ("Zone / floor", row["Zone/Floor"]),
            ("Room (Home app)", row["Room"]),
            ("Category", row["Category"]),
            ("Found via", row["Found via"].replace("|", ", ")),
            ("Manufacturer", row["Manufacturer"]),
            ("Model", row["Model"]),
            ("Firmware", row["Firmware"]),
            ("Serial number", row["Serial Number"]),
            ("Battery", row["Battery"]),
            ("Setup code", row["Setup Code"]),
            ("Signal", row["Signal"]),
            ("Integration", row["Integration"]),
            ("Last scanned", row["Last Scanned"]),
            ("Last online", row["Last Online"] or "never seen online by the Home app"),
            ("Addresses", row["IP Address"].replace("|", ", ")),
        ]
        return [f"{k}: {v}" for k, v in pairs if v]

    @staticmethod
    def _thread_lines(row: dict[str, str]) -> list[str]:
        pairs = [
            ("Thread network", row["Thread Network"]),
            ("Thread channel", row["Channel"]),
            ("Thread role", row["Thread Role"]),
            ("Thread stability", row["Stability"].replace("|", ", ")),
            ("Thread version", row["Thread Version"]),
            ("Connected via", row["Connected via"]),
        ]
        return [f"{k}: {v}" for k, v in pairs if v]


def import_homemapper(repo: Repository, path: Path | str) -> ImportResult:
    return HomeMapperImporter(repo).run(Path(path))
