"""Command-line interface: doctor | scan | watch | presence | list | show | reclassify | ..."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import asdict
from ipaddress import IPv4Network
from pathlib import Path

from amenhotep import __version__
from amenhotep.collectors import oui
from amenhotep.collectors.nmap import SETCAP_HINT, NmapCollector, NmapError
from amenhotep.core.lock import single_instance
from amenhotep.core.models import PROFILES
from amenhotep.core.netutil import TargetError, local_networks, validate_target
from amenhotep.core.paths import data_dir, db_path
from amenhotep.services.notify import notify
from amenhotep.services.presence import presence_all
from amenhotep.services.satisfaction import satisfaction
from amenhotep.services.scan import ScanService
from amenhotep.store import db
from amenhotep.store.repo import Repository

TOOLS = {
    "nmap": ("required", "discovery, services, OS detection"),
    "ip": ("required", "neighbour table, local networks"),
    "arp-scan": ("optional", "faster L2 sweep (not used yet)"),
    "avahi-browse": ("optional", "mDNS fallback (planned M2)"),
}


def cmd_doctor(_: argparse.Namespace) -> int:
    ok = True
    print(f"amenhotep {__version__}")
    for tool, (need, why) in TOOLS.items():
        path = shutil.which(tool)
        mark = "ok     " if path else ("MISSING" if need == "required" else "absent ")
        print(f"  [{mark}] {tool:<13} {why}" + (f"  ({path})" if path else ""))
        ok &= bool(path) or need != "required"
    nmap = NmapCollector()
    if nmap.available():
        if nmap.raw_capable:
            print("  [ok     ] raw sockets   OS detection (-O) and ARP scans available")
        else:
            print("  [absent ] raw sockets   OS detection unavailable; enable once with:")
            print(f"              {SETCAP_HINT}")
    nets = local_networks()
    print("  local private networks:", ", ".join(map(str, nets)) or "none found")
    print(f"  database: {db_path()}")
    return 0 if ok else 1


def _targets(spec: str) -> list[IPv4Network] | None:
    try:
        if spec == "auto":
            found = local_networks()
            if not found:
                print("no private local network found; pass --target CIDR", file=sys.stderr)
                return None
            return found
        return [validate_target(t, allow_public=False) for t in spec.split(",")]
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None


def cmd_scan(args: argparse.Namespace) -> int:
    targets = _targets(args.target)
    if targets is None:
        return 2
    conn = db.connect(db_path())
    service = ScanService(Repository(conn), progress=lambda m: print(m, file=sys.stderr))
    if not service.nmap.available():
        print("error: nmap not found; install it (see TOOLS.md)", file=sys.stderr)
        return 1
    try:
        result = service.run(targets, args.profile)
    except NmapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"scan #{result.scan_id} {result.status}: {result.hosts_seen} hosts, "
        f"{result.new_devices} new devices"
        + (f", {result.probed} fingerprinted" if result.probed else "")
    )
    for w in result.warnings:
        print(f"warning: {w}", file=sys.stderr)
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    """One light presence pass; meant for a timer (see assets/install-timer.sh)."""
    targets = _targets(args.target)
    if targets is None:
        return 2
    with single_instance(data_dir() / "watch.lock") as got:
        if not got:
            print("another watch/scan pass is still running; skipping", file=sys.stderr)
            return 0
        conn = db.connect(db_path())
        service = ScanService(Repository(conn), progress=lambda m: print(m, file=sys.stderr))
        if not service.nmap.available():
            print("error: nmap not found; install it (see TOOLS.md)", file=sys.stderr)
            return 1
        try:
            result = service.watch(targets)
        except NmapError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(
            f"watch #{result.scan_id} {result.status}: {result.hosts_seen} online, "
            f"{result.new_devices} new, {result.probed} fingerprinted"
        )
        for w in result.warnings:
            print(f"warning: {w}", file=sys.stderr)
        if args.notify and result.new_unknown:
            notify("New unknown device on your network", "; ".join(result.new_unknown[:5]))
        return 0


def cmd_presence(args: argparse.Namespace) -> int:
    repo = Repository(db.connect(db_path()))
    devices = repo.list_devices()
    info = presence_all(repo, args.days)
    checks = len(repo.scan_times(args.days))
    rows = []
    for d in sorted(devices, key=lambda d: tuple(int(p) for p in (d.ip or "0.0.0.0").split("."))):
        p = info.get(d.uuid)
        if args.offline and d.online:
            continue
        status = {True: "online", False: "OFFLINE", None: "?"}[d.online]
        last = p.last_seen.strftime("%a %H:%M") if p and p.last_seen else "-"
        seen = f"{p.seen}/{p.total}" if p else f"0/{checks}"
        hours = p.summary().split("typically online ")[-1] if p and p.online_hours else "-"
        rows.append(
            (d.ip or "-", (d.display_name or d.hostname or "-")[:26], status, seen, last, hours)
        )
    print(f"{'IP':<16} {'NAME':<26} {'NOW':<8} {'SEEN':<9} {'LAST':<10} TYPICALLY ONLINE")
    for r in rows:
        print(f"{r[0]:<16} {r[1]:<26} {r[2]:<8} {r[3]:<9} {r[4]:<10} {r[5]}")
    print(f"\n{checks} checks in the last {args.days} days.")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    devices = Repository(db.connect(db_path())).list_devices()
    if args.json:
        print(json.dumps([asdict(d) for d in devices], indent=2))
        return 0
    print(f"{'IP':<16} {'MAC':<18} {'VENDOR':<22} {'OS':<8} {'TYPE':<13} {'MODEL':<20} NAME")
    for d in sorted(devices, key=lambda d: tuple(int(p) for p in (d.ip or "0.0.0.0").split("."))):
        name = d.display_name or d.hostname or "-"
        print(
            f"{d.ip or '-':<16} {d.mac or '-':<18} {(d.vendor or '-')[:21]:<22} "
            f"{d.os_family:<8} {d.device_type[:12]:<13} {(d.model or '-')[:19]:<20} {name[:30]}"
        )
    print(f"\n{satisfaction(devices).message()}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    repo = Repository(db.connect(db_path()))
    uid = repo.device_by_ip_or_name(args.key)
    if not uid:
        print(f"no device with IP/hostname {args.key!r}", file=sys.stderr)
        return 1
    d = next(x for x in repo.list_devices() if x.uuid == uid)
    print(f"{d.display_name or d.hostname or d.ip}  ({d.uuid})")
    print(f"  ip {d.ip}  mac {d.mac}  vendor {d.vendor}  os {d.os_family}  type {d.device_type}")
    print(f"  model {d.model}  mode {d.location_mode}  area {d.area}")
    print(f"  os detail: {d.os_detail or '-'}")
    print(f"  hints: {d.hardware_notes or '-'}")
    print("  evidence (field, value, confidence, source):")
    for e in repo.evidence_for(uid):
        print(
            f"    {e['field']:<12} {str(e['value'])[:30]:<30} {e['confidence']:.2f}  {e['source']}"
            + (f"  — {e['detail']}" if e["detail"] else "")
        )
    return 0


def cmd_validate_house(args: argparse.Namespace) -> int:
    try:
        import jsonschema
    except ImportError:
        print("error: install jsonschema (pip install -e '.[dev]')", file=sys.stderr)
        return 1
    path = Path(args.file)
    if path.stat().st_size > 2 * 1024 * 1024:
        print("error: file larger than 2 MB", file=sys.stderr)
        return 1
    schema_path = (
        Path(args.schema)
        if args.schema
        else Path(__file__).parents[2] / "model" / "house.schema.json"
    )
    try:
        jsonschema.validate(json.loads(path.read_text()), json.loads(schema_path.read_text()))
    except (jsonschema.ValidationError, json.JSONDecodeError) as exc:
        print(f"invalid: {getattr(exc, 'message', exc)}", file=sys.stderr)
        return 1
    print("house file is valid")
    return 0


def cmd_reclassify(_args: argparse.Namespace) -> int:
    from amenhotep.services.reclassify import reclassify

    repo = Repository(db.connect(db_path()))
    before = {d.uuid: d.device_type for d in repo.list_devices()}
    n = reclassify(repo)
    changed = sum(1 for d in repo.list_devices() if before.get(d.uuid) != d.device_type)
    print(f"re-evaluated {n} hosts from the last scan; {changed} device types changed")
    print(satisfaction(repo.list_devices()).message())
    return 0


def cmd_import_homemapper(args: argparse.Namespace) -> int:
    from amenhotep.services.homemapper import import_homemapper

    path = Path(args.file).expanduser()
    if not path.is_file():
        print(f"error: {path} is not a file", file=sys.stderr)
        return 2
    repo = Repository(db.connect(db_path()))
    try:
        r = import_homemapper(repo, path)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        f"{r.filename}: {r.rows} rows: {r.matched} merged into devices, {r.created} new, "
        f"{r.thread} Thread/Matter, {r.conflicts} conflicts"
    )
    for room in r.rooms_created:
        print(f"  new room: {room}")
    for m in r.messages:
        print(f"  {m}")
    print(satisfaction(repo.list_devices()).message())
    return 0


def _dev(repo: Repository, key: str) -> str | None:
    uid = repo.device_by_ip_or_name(key)
    if not uid:
        print(
            f"error: no unique device matches {key!r} (IP, hostname, name or uuid)", file=sys.stderr
        )
    return uid


def cmd_topology(_: argparse.Namespace) -> int:
    from amenhotep.services import topology

    repo = Repository(db.connect(db_path()))
    print("\n".join(topology.render(topology.build(repo))) or "no devices yet")
    return 0


def cmd_add_switch(args: argparse.Namespace) -> int:
    from amenhotep.services import topology

    repo = Repository(db.connect(db_path()))
    up = None
    if args.uplink:
        up = _dev(repo, args.uplink)
        if not up:
            return 1
    try:
        uid = topology.add_switch(repo, args.name, f"tp-link-{args.ports}", up)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"added {args.name} ({args.ports} ports): {uid}")
    return 0


def cmd_link(args: argparse.Namespace) -> int:
    repo = Repository(db.connect(db_path()))
    child, parent = _dev(repo, args.child), _dev(repo, args.parent)
    if not child or not parent:
        return 1
    try:
        repo.set_link(child, parent, port=args.port, medium=args.medium)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    repo.commit()
    print("linked")
    return 0


def cmd_unlink(args: argparse.Namespace) -> int:
    repo = Repository(db.connect(db_path()))
    child = _dev(repo, args.child)
    if not child:
        return 1
    repo.remove_link(child)
    repo.commit()
    print("uplink removed")
    return 0


def cmd_suggest_links(args: argparse.Namespace) -> int:
    from amenhotep.services import topology

    repo = Repository(db.connect(db_path()))
    names = {d.uuid: d.display_name or d.ip or d.uuid[:8] for d in repo.list_devices()}
    found = topology.suggest_uplinks(repo)
    for s in found:
        print(f"{names[s.child]} -> {names[s.parent]} ({s.medium}): {s.reason}")
    if not found:
        print("no suggestions")
    elif args.apply:
        print(f"applied {topology.apply_suggestions(repo, found)} (marked as suggested)")
    else:
        print("re-run with --apply to record these as suggested links")
    return 0


def cmd_import_router_clients(args: argparse.Namespace) -> int:
    from amenhotep.services import topology

    repo = Repository(db.connect(db_path()))
    try:
        seen, updated = topology.import_router_clients(repo, Path(args.file).expanduser())
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"{seen} lines with a MAC, {updated} known devices updated (wired/Wi-Fi)")
    return 0


def cmd_update_oui(args: argparse.Namespace) -> int:
    if not args.yes:
        print(
            "This downloads the IEEE MA-L, MA-M and MA-S vendor lists (about 6 MB) from "
            "standards-oui.ieee.org. Re-run with --yes."
        )
        return 2
    print(f"saved {oui.update_from_ieee()} vendor prefixes")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="amenhotep", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", help="check tools and paths").set_defaults(fn=cmd_doctor)
    s = sub.add_parser("scan", help="scan the network")
    s.add_argument("--target", default="auto", help="CIDR[,CIDR…] or 'auto' (default)")
    s.add_argument("--profile", choices=[*sorted(PROFILES), "watch"], default="standard")
    s.set_defaults(fn=cmd_scan)
    w = sub.add_parser("watch", help="light presence pass (run it from a timer)")
    w.add_argument("--target", default="auto", help="CIDR[,CIDR…] or 'auto' (default)")
    w.add_argument(
        "--notify", action="store_true", help="desktop notification for new unknown devices"
    )
    w.set_defaults(fn=cmd_watch)
    pr = sub.add_parser(
        "presence", help="who is online now, and when each device is usually online"
    )
    pr.add_argument("--days", type=int, default=7)
    pr.add_argument(
        "--offline", action="store_true", help="only devices not seen in the last check"
    )
    pr.set_defaults(fn=cmd_presence)
    ls = sub.add_parser("list", help="list known devices")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(fn=cmd_list)
    sh = sub.add_parser("show", help="show a device and its evidence")
    sh.add_argument("key", help="IP or hostname")
    sh.set_defaults(fn=cmd_show)
    v = sub.add_parser("validate-house", help="validate a house.json file")
    v.add_argument("file")
    v.add_argument("--schema")
    v.set_defaults(fn=cmd_validate_house)
    sub.add_parser(
        "reclassify", help="re-run identification on the last scan's data (no network traffic)"
    ).set_defaults(fn=cmd_reclassify)
    im = sub.add_parser("import-homemapper", help="merge a HomeMapper (iPhone) CSV export")
    im.add_argument("file")
    im.set_defaults(fn=cmd_import_homemapper)
    sub.add_parser("topology", help="show the network tree").set_defaults(fn=cmd_topology)
    sw = sub.add_parser("add-switch", help="add an unmanaged TP-Link switch (4 or 8 ports)")
    sw.add_argument("name")
    sw.add_argument("--ports", type=int, choices=(4, 8), required=True)
    sw.add_argument("--uplink", help="device it plugs into (IP, name or uuid)")
    sw.set_defaults(fn=cmd_add_switch)
    lk = sub.add_parser("link", help="set a device's uplink: link CHILD PARENT [--port N]")
    lk.add_argument("child")
    lk.add_argument("parent")
    lk.add_argument("--port")
    lk.add_argument("--medium", choices=("wired", "wifi"), default="wired")
    lk.set_defaults(fn=cmd_link)
    ul = sub.add_parser("unlink", help="remove a device's uplink")
    ul.add_argument("child")
    ul.set_defaults(fn=cmd_unlink)
    sg = sub.add_parser("suggest-links", help="cautious uplink hints (never applied silently)")
    sg.add_argument("--apply", action="store_true")
    sg.set_defaults(fn=cmd_suggest_links)
    rc = sub.add_parser("import-router-clients", help="read wired/Wi-Fi from a router client list")
    rc.add_argument("file")
    rc.set_defaults(fn=cmd_import_router_clients)
    u = sub.add_parser("update-oui", help="download the full IEEE vendor list")
    u.add_argument("--yes", action="store_true")
    u.set_defaults(fn=cmd_update_oui)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
