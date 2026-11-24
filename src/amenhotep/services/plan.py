"""Flat floor plans: levels, rooms, device positions, wire passages ("risers") and wires.

Every level (floor, garden, roaming) is a rectangle; positions are fractions of it. A device sits
on the level of its area (a room belongs to the level of its zone). Wired links are drawn on the
levels they touch; a link between levels needs a passage (riser) that goes through both, else it
is drawn as a "missing passage" warning. A Wi-Fi link needs no passage, so a repeater that is off
the wire only needs a Wi-Fi uplink.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial

from amenhotep.services.matter import MatterDevice, group_matter_nodes
from amenhotep.store.repo import AreaRow, DeviceRow, LevelRow, Repository, RiserRow, RoomRect

MATTER_TYPE = "thread-matter"  # plan-only type for Matter/Thread devices without a LAN host
MATTER_PREFIX = "matter:"
FREE_STRIP = (0.82, 0.98)  # zone-level devices on a floor with rooms go in this strip
ROOM_AREA = (0.02, 0.02, 0.96, 0.78)  # x, y, w, h that rooms share


@dataclass
class PlacedDevice:
    uuid: str
    name: str
    device_type: str
    x: float
    y: float
    infra: bool
    online: bool | None
    room_id: int | None
    manual: bool
    detail: str


@dataclass
class FieldSpec:
    """One row of the field/value table of a selected item."""

    key: str
    label: str
    value: str = ""  # text shown (for a choice: the current choice's text)
    kind: str = "text"  # text | multiline | choice
    editable: bool = False
    choices: list[tuple[str, object]] = field(default_factory=list)
    data: object = None  # current value of a choice


@dataclass
class Wire:
    x1: float
    y1: float
    x2: float
    y2: float
    kind: str  # wired | wifi | missing
    label: str
    child: str
    parent: str
    a: str = ""  # device at (x1, y1)
    b: str | None = None  # device at (x2, y2); None when that end is a passage


@dataclass
class LevelLayout:
    level: LevelRow
    rooms: list[tuple[int, str, float, float, float, float]]
    devices: list[PlacedDevice]
    wires: list[Wire]
    risers: list[RiserRow]
    notes: list[str] = field(default_factory=list)
    type_counts: dict[str, int] = field(default_factory=dict)  # every type on the level, unfiltered


# ---- seeding ----------------------------------------------------------------------------------
_LEVELS = [  # id, name, kind, ord, width, depth, zone names shown on it
    ("second", "Second floor / Attic", "floor", 30, 10, 8, ["Second floor", "Attic"]),
    ("first", "First floor", "floor", 20, 10, 8, ["First floor"]),
    ("ground", "Ground floor", "floor", 10, 10, 8, ["Ground floor"]),
    ("back_garden", "Back garden", "garden", -1, 14, 10, ["Back garden", "Garden", "Veranda"]),
    ("front_garden", "Front garden", "garden", -2, 14, 6, ["Front garden"]),
    ("roaming", "Roaming", "roaming", -3, 10, 6, ["Roaming"]),
]


def seed(repo: Repository) -> None:
    """Create the default levels once (idempotent); add the zones/rooms the plan expects."""
    if repo.plan_levels():
        ensure_rooms(repo)
        return
    garden = repo.area_by_name("Garden")
    if garden and not repo.area_by_name("Back garden"):
        repo.rename_area(garden.id, "Back garden")
    if not repo.area_by_name("Front garden"):
        repo.add_area("Front garden", "zone")
    second = repo.area_by_name("Second floor")
    if second and not repo.area_by_name("Mini-office"):
        repo.add_area("Mini-office", "room", second.id)
    for lid, name, kind, ord_, w, d, zones in _LEVELS:
        repo.add_plan_level(lid, name, kind, ord_, w, d)
        for z in zones:
            area = repo.area_by_name(z)
            if area and area.kind == "zone":
                repo.map_area_to_level(area.id, lid)
    ensure_rooms(repo)
    repo.commit()


def ensure_rooms(repo: Repository) -> None:
    """Give every room of a level a rectangle; re-grid a level's rooms when one is new."""
    mapping = repo.plan_level_areas()
    areas = {a.id: a for a in repo.list_areas()}
    have = repo.plan_rooms()
    by_level: dict[str, list[int]] = {}
    for a in areas.values():
        if a.kind == "room" and a.parent_id in mapping:
            by_level.setdefault(mapping[a.parent_id], []).append(a.id)
    for rooms in by_level.values():
        if all(r in have for r in rooms):
            continue
        rooms.sort(key=lambda i: areas[i].name.casefold())
        n = len(rooms)
        rows = 1 if n <= 3 else 2
        cols = math.ceil(n / rows)
        rx, ry, rw, rh = ROOM_AREA
        for i, aid in enumerate(rooms):
            r, c = divmod(i, cols)
            repo.set_plan_room(aid, rx + rw * c / cols, ry + rh * r / rows, rw / cols, rh / rows)
    repo.commit()


# ---- layout -----------------------------------------------------------------------------------
def _slots(n: int, x: float, y: float, w: float, h: float) -> list[tuple[float, float]]:
    """n spread positions inside a rectangle (fractions), leaving room for the room's title."""
    cols = max(1, min(n, math.ceil(math.sqrt(n))))  # near-square grid keeps labels apart
    rows = math.ceil(n / cols)
    top = 0.22  # keep clear of the label at the top of the room
    out = []
    for i in range(n):
        r, c = divmod(i, cols)
        out.append(
            (
                x + w * (0.1 + 0.8 * (c + 0.5) / cols),
                y + h * (top + (1 - top - 0.08) * (r + 0.5) / rows),
            )
        )
    return out


def _detail(d: DeviceRow) -> str:
    bits = [d.device_type, d.vendor or "", d.model or "", d.ip or ""]
    return " · ".join(b for b in bits if b)


def device_names(repo: Repository) -> dict[str, str]:
    return {d.uuid: d.display_name or d.hostname or d.ip or d.uuid[:8] for d in repo.list_devices()}


def _positions(repo: Repository) -> tuple[dict[str, dict[str, PlacedDevice]], list[DeviceRow]]:
    """Every device's level and position: {level_id: {uuid: PlacedDevice}} + unplaced devices."""
    levels = {lv.id: lv for lv in repo.plan_levels()}
    mapping = repo.plan_level_areas()
    areas = {a.id: a for a in repo.list_areas()}
    rooms = repo.plan_rooms()
    manual = repo.plan_placements()
    out: dict[str, dict[str, PlacedDevice]] = {lid: {} for lid in levels}
    unplaced: list[DeviceRow] = []
    pending: dict[
        tuple[str, int | None], list[tuple[str, Callable[[float, float], PlacedDevice]]]
    ] = {}
    for d in repo.list_devices():
        level: str | None = None
        room: int | None = None
        if d.area_id is not None and d.area_id in areas:
            a = areas[d.area_id]
            level = mapping.get(a.id) or (mapping.get(a.parent_id) if a.parent_id else None)
            room = a.id if a.kind == "room" and a.id in rooms else None
        if d.location_mode == "roaming" and "roaming" in levels and level is None:
            level = "roaming"
        if level is None or level not in levels:
            unplaced.append(d)
            continue
        if d.uuid in manual and manual[d.uuid][0] == level:
            _, x, y = manual[d.uuid]
            out[level][d.uuid] = _placed(d, x, y, room=room, manual=True)
        else:
            pending.setdefault((level, room), []).append(
                ((d.display_name or d.ip or d.uuid).casefold(), partial(_placed, d, room=room))
            )
    _add_matter(repo, out, pending, levels, mapping, areas, rooms)
    for (level, room), devs in pending.items():
        devs.sort(key=lambda t: t[0])
        if room is not None:
            r = rooms[room]
            box = (r.x, r.y, r.w, r.h)
        elif any(rm for rm in rooms if mapping.get(areas[rm].parent_id or -1) == level):
            box = (0.02, FREE_STRIP[0], 0.96, FREE_STRIP[1] - FREE_STRIP[0])
        else:
            box = (0.03, 0.05, 0.94, 0.9)
        for (_, build), (x, y) in zip(devs, _slots(len(devs), *box), strict=True):
            placed = build(x, y)
            out[level][placed.uuid] = placed
    return out, unplaced


def _add_matter(
    repo: Repository,
    out: dict[str, dict[str, PlacedDevice]],
    pending: dict[tuple[str, int | None], list[tuple[str, Callable[[float, float], PlacedDevice]]]],
    levels: dict[str, LevelRow],
    mapping: dict[int, str],
    areas: dict[int, AreaRow],
    rooms: dict[int, RoomRect],
) -> None:
    """Matter/Thread devices that are not LAN hosts (those are already devices)."""
    manual = repo.plan_matter_placements()
    for g in group_matter_nodes(repo.list_matter_nodes()):
        if g.host_uuid:
            continue
        area_id = next((n.area_id for n in g.nodes if n.area_id is not None), None)
        if area_id is None or area_id not in areas:
            continue
        a = areas[area_id]
        level = mapping.get(a.id) or (mapping.get(a.parent_id) if a.parent_id else None)
        if level not in levels:
            continue
        room = a.id if a.kind == "room" and a.id in rooms else None
        inst = min(n.instance for n in g.nodes)
        name = g.label or "(unnamed Matter device)"
        detail = f"Matter/Thread · {g.fabrics} fabric(s)" + (f"\n{g.notes}" if g.notes else "")

        build = partial(_matter_placed, MATTER_PREFIX + inst, name, detail, room)

        if inst in manual and manual[inst][0] == level:
            _, x, y = manual[inst]
            out[level][MATTER_PREFIX + inst] = build(x, y, manual=True)
        else:
            pending.setdefault((level, room), []).append((name.casefold(), build))


def _matter_placed(
    uid: str, name: str, detail: str, room: int | None, x: float, y: float, manual: bool = False
) -> PlacedDevice:
    return PlacedDevice(uid, name, MATTER_TYPE, x, y, False, None, room, manual, detail)


def _placed(
    d: DeviceRow, x: float, y: float, *, room: int | None = None, manual: bool = False
) -> PlacedDevice:
    return PlacedDevice(
        d.uuid,
        d.display_name or d.hostname or d.ip or d.uuid[:8],
        d.device_type,
        x,
        y,
        d.is_infrastructure or d.device_type in ("router", "switch", "access-point", "mesh-node"),
        d.online,
        room,
        manual,
        _detail(d),
    )


def unplaced_devices(repo: Repository) -> list[DeviceRow]:
    return _positions(repo)[1]


def device_counts(repo: Repository) -> dict[str, int]:
    return {lid: len(devs) for lid, devs in _positions(repo)[0].items()}


def layout(
    repo: Repository, level_id: str, hidden: frozenset[str] | set[str] = frozenset()
) -> LevelLayout:
    """Devices and wires of one level; device types in ``hidden`` are left out."""
    levels = {lv.id: lv for lv in repo.plan_levels()}
    if level_id not in levels:
        raise ValueError(f"unknown level {level_id!r}")
    positions, _ = _positions(repo)
    where = {u: (lid, p) for lid, devs in positions.items() for u, p in devs.items()}
    mapping = repo.plan_level_areas()
    parents = {a.id: a.parent_id for a in repo.list_areas()}
    shown = [
        (aid, r.name, r.x, r.y, r.w, r.h)
        for aid, r in repo.plan_rooms().items()
        if mapping.get(parents.get(aid) or -1) == level_id
    ]
    risers = [r for r in repo.plan_risers() if level_id in r.levels]
    wires: list[Wire] = []
    notes: list[str] = []
    for lk in repo.list_links():
        if lk.child_uuid not in where or lk.parent_uuid not in where:
            continue
        (lc, c), (lp, p) = where[lk.child_uuid], where[lk.parent_uuid]
        if level_id not in (lc, lp) or {c.device_type, p.device_type} & set(hidden):
            continue
        label = f"{c.name} → {p.name}" + (f" (port {lk.port})" if lk.port else "")
        if lc == lp:
            kind = "wifi" if lk.medium == "wifi" else "wired"
            wires.append(Wire(c.x, c.y, p.x, p.y, kind, label, c.uuid, p.uuid, c.uuid, p.uuid))
            continue
        if lk.medium == "wifi":  # no cable between levels: just say where it connects
            here, other = (c, lp) if lc == level_id else (p, lc)
            notes.append(f"{here.name}: Wi-Fi link to {levels[other].name}")
            continue
        both = [r for r in repo.plan_risers() if lc in r.levels and lp in r.levels]
        mine = c if lc == level_id else p
        if both:
            r = min(both, key=lambda r: (r.x - mine.x) ** 2 + (r.y - mine.y) ** 2)
            wires.append(
                Wire(
                    mine.x,
                    mine.y,
                    r.x,
                    r.y,
                    "wired",
                    label + f" via {r.name}",
                    c.uuid,
                    p.uuid,
                    mine.uuid,
                )
            )
        else:
            other_lvl = lp if lc == level_id else lc
            wires.append(Wire(mine.x, mine.y, mine.x, mine.y, "missing",
                              f"{label}: no passage between {levels[level_id].name} and "
                              f"{levels[other_lvl].name}", c.uuid, p.uuid, mine.uuid))  # fmt: skip
            notes.append(f"No wire passage between {levels[lc].name} and {levels[lp].name} "
                         f"for {c.name} → {p.name}")  # fmt: skip
    everything = list(positions[level_id].values())
    counts: dict[str, int] = {}
    for d in everything:
        counts[d.device_type] = counts.get(d.device_type, 0) + 1
    return LevelLayout(
        levels[level_id], sorted(shown, key=lambda r: r[1]),
        [d for d in everything if d.device_type not in hidden],
        wires, risers, sorted(set(notes)), counts,
    )  # fmt: skip


def _yes_no(flag: bool) -> list[tuple[str, object]]:
    return [("no", False), ("yes", True)]


def _area_choices(repo: Repository) -> list[tuple[str, object]]:
    return [("(unassigned)", None)] + [(a.label, a.id) for a in repo.list_areas()]


def _find_group(repo: Repository, uid: str) -> MatterDevice | None:
    inst = uid[len(MATTER_PREFIX) :]
    for g in group_matter_nodes(repo.list_matter_nodes()):
        if min(n.instance for n in g.nodes) == inst:
            return g
    return None


def item_fields(repo: Repository, uid: str) -> list[FieldSpec]:
    """Every field of a plan item (a device uuid or ``matter:<instance>``) as table rows."""
    from amenhotep.core.models import OS_FAMILIES
    from amenhotep.services.classify import DEVICE_TYPES

    if uid.startswith(MATTER_PREFIX):
        g = _find_group(repo, uid)
        if g is None:
            return []
        area_id = next((n.area_id for n in g.nodes if n.area_id is not None), None)
        choices = _area_choices(repo)
        return [
            FieldSpec("label", "Name", g.label or "", "text", True),
            FieldSpec("area_id", "Area", "", "choice", True, choices, area_id),
            FieldSpec("kind", "Kind", "Matter / Thread device"),
            FieldSpec("fabrics", "Fabrics", str(g.fabrics)),
            FieldSpec("addresses", "Addresses", ", ".join(g.addresses)),
            FieldSpec("last_seen", "Last seen", max(n.last_seen for n in g.nodes)),
            FieldSpec("notes", "Notes", g.notes, "multiline", True),
        ]
    d = next((x for x in repo.list_devices() if x.uuid == uid), None)
    if d is None:
        return []
    names = device_names(repo)
    link = next((lk for lk in repo.list_links() if lk.child_uuid == uid), None)
    uplink = "-"
    if link:
        uplink = names.get(link.parent_uuid, "?") + (f", port {link.port}" if link.port else "")
        uplink += f" ({link.medium})"
    conn = repo.conn
    row = conn.execute("SELECT serial, first_seen FROM device WHERE uuid=?", (uid,)).fetchone()

    def pick(options: list[str]) -> list[tuple[str, object]]:
        return [(o, o) for o in options]

    return [
        FieldSpec("display_name", "Name", d.display_name or "", "text", True),
        FieldSpec(
            "device_type", "Type", "", "choice", True, pick(sorted(DEVICE_TYPES)), d.device_type
        ),
        FieldSpec("vendor", "Vendor", d.vendor or "", "text", True),
        FieldSpec("model", "Model", d.model or "", "text", True),
        FieldSpec("serial", "Serial", (row["serial"] if row else "") or "", "text", True),
        FieldSpec("os_family", "OS", "", "choice", True, pick(list(OS_FAMILIES)), d.os_family),
        FieldSpec("os_detail", "OS detail", d.os_detail or "", "text", True),
        FieldSpec("area_id", "Area", "", "choice", True, _area_choices(repo), d.area_id),
        FieldSpec(
            "location_mode", "Mode", "", "choice", True, pick(["fixed", "roaming"]), d.location_mode
        ),
        FieldSpec(
            "is_infrastructure",
            "Infrastructure",
            "",
            "choice",
            True,
            _yes_no(True),
            d.is_infrastructure,
        ),
        FieldSpec("ip", "IP", d.ip or "-"),
        FieldSpec("mac", "MAC", d.mac or "-"),
        FieldSpec("hostname", "Hostname", d.hostname or "-"),
        FieldSpec("status", "Status", d.online_label or "unknown"),
        FieldSpec("last_seen", "Last seen", d.last_seen or "-"),
        FieldSpec("uplink", "Uplink", uplink),
        FieldSpec("hints", "Hints", d.hardware_notes or "-"),
        FieldSpec("locked", "Edited by you", ", ".join(d.locked_fields) or "-"),
        FieldSpec("notes", "Notes", d.notes or "", "multiline", True),
    ]


def apply_field(repo: Repository, uid: str, key: str, value: object) -> bool:
    """Save one edited field; returns True when the area changed (so other tabs refresh)."""
    if uid.startswith(MATTER_PREFIX):
        g = _find_group(repo, uid)
        if g is None:
            return False
        for n in g.nodes:
            if key == "label":
                repo.set_matter_label(n.instance, str(value or ""), n.area_id)
            elif key == "area_id":
                repo.set_matter_label(
                    n.instance, g.label, value if isinstance(value, int) else None
                )
            elif key == "notes":
                repo.set_matter_notes(n.instance, str(value) if value else None)
        repo.commit()
        return key in ("area_id", "label")
    if key == "area_id":
        repo.assign_area([uid], value if isinstance(value, int) else None)
    elif key == "serial":
        repo.set_serial(uid, str(value) if value else None)
    elif key == "is_infrastructure":
        repo.set_infrastructure(uid, bool(value))
    elif key in ("display_name", "device_type", "vendor", "model", "os_family", "os_detail",
                 "location_mode", "notes"):  # fmt: skip
        repo.set_fields(uid, {key: value}, user=True)
    else:
        raise ValueError(f"field {key!r} is read-only")
    repo.commit()
    return True


# ---- room walls ---------------------------------------------------------------------------------
MIN_ROOM = 0.08  # smallest room side, as a fraction of the level
_EPS = 1e-4
Rect = tuple[float, float, float, float]  # x, y, w, h (fractions)


@dataclass
class Wall:
    orient: str  # 'v' (a vertical wall, moves in x) or 'h'
    pos: float
    segments: list[tuple[float, float]]  # stretches of the wall that separate two rooms
    before: list[int]  # rooms that end at the wall (left / above)
    after: list[int]  # rooms that start at the wall (right / below)


def walls(rooms: dict[int, Rect]) -> list[Wall]:
    """Shared edges between rooms, grouped by position: dragging one moves all its rooms."""
    found: dict[tuple[str, float], Wall] = {}
    for a, (ax, ay, aw, ah) in rooms.items():
        for b, (bx, by, bw, bh) in rooms.items():
            if a == b:
                continue
            for orient, edge, start, a_lo, a_hi, b_lo, b_hi in (
                ("v", ax + aw, bx, ay, ay + ah, by, by + bh),
                ("h", ay + ah, by, ax, ax + aw, bx, bx + bw),
            ):
                lo, hi = max(a_lo, b_lo), min(a_hi, b_hi)
                if abs(edge - start) > _EPS or hi - lo < _EPS:
                    continue
                w = found.setdefault((orient, round(edge, 3)), Wall(orient, edge, [], [], []))
                w.segments.append((lo, hi))
                if a not in w.before:
                    w.before.append(a)
                if b not in w.after:
                    w.after.append(b)
    return list(found.values())


def clamp_wall(rooms: dict[int, Rect], wall: Wall, pos: float) -> float:
    i = 0 if wall.orient == "v" else 1  # x or y
    lo = max(rooms[a][i] for a in wall.before) + MIN_ROOM
    hi = min(rooms[b][i] + rooms[b][i + 2] for b in wall.after) - MIN_ROOM
    return min(max(pos, lo), max(lo, hi))


def move_wall(rooms: dict[int, Rect], wall: Wall, pos: float) -> dict[int, Rect]:
    """New rectangles of the rooms touching the wall once it moves to ``pos``."""
    pos = clamp_wall(rooms, wall, pos)
    i = 0 if wall.orient == "v" else 1
    out: dict[int, Rect] = {}
    for a in wall.before:
        r = list(rooms[a])
        r[i + 2] = pos - r[i]
        out[a] = (r[0], r[1], r[2], r[3])
    for b in wall.after:
        r = list(rooms[b])
        end = r[i] + r[i + 2]
        r[i], r[i + 2] = pos, end - pos
        out[b] = (r[0], r[1], r[2], r[3])
    return out
