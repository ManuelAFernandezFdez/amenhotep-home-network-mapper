# Amenhotep

Discover, identify and map every device on your home network — then see them in a 3D model of your house.

**Amenhotep** = **A**ppliance **M**apping & **E**numeration of **N**etwork **H**ardware, **O**ver **T**hread, **E**thernet & **P**rotocols.

### The core story

* Amun = the hidden one. Your tool reveals the hidden devices on your network. Tagline: "Nothing stays hidden from Amun."
* "Satisfied." When every device is identified, Amun is satisfied. You could use that as the all-clear status: "Amun is satisfied: 23/23 devices known." Unknown devices make him unsatisfied.
* Amenhotep, son of Hapu was a famous royal scribe and architect who recorded and built Egypt's great works. That fits a tool that surveys and maps your network.

> Status: **M0–M5 done** (HomeKit & Matter tab: HAP accessories with paired flag, Matter devices incl. Thread, Thread border routers; areas: zones/rooms, bulk assign, pin-as-fixed for night-table phones; Qt GUI: devices table, filters, detail/evidence panel, manual edits, scan tab with cancel; skeleton, SQLite store, nmap/neighbour/mDNS/SSDP collectors, evidence-based classifier incl. HomeKit, CLI: `scan`, `list`, `show`). Topology and 3D follow [ROADMAP.md](ROADMAP.md).

## What it does

- Scans your LAN (switch-connected and Wi-Fi) with nmap, ARP, mDNS and SSDP.
- Identifies **IP, MAC, vendor, OS family (Linux / Windows / iOS / macOS / Android …), device type and hardware model** when it can, with confidence and evidence.
- Recognises **HomeKit** accessories (and Matter) and shows model and category.
- Treats **switches and Wi-Fi mesh repeaters** (first floor, veranda) as devices and shows what hangs off each.
- Lets you assign devices to **zones** (ground / first / second floor, garden, veranda, roaming) and **rooms** (kitchen, main bedroom, secondary bedroom, third bedroom, second-floor bedroom). Phones used as night-table clocks can be pinned as *fixed*.
- Shows a **3D house** with rooms and devices, driven by a hand-editable `house.json`.

## Stack

Python 3.12 · PySide6 (Qt, Qt Quick 3D) · SQLite · nmap. Everything external is listed in [TOOLS.md](TOOLS.md).

## Documents

| Doc | Content |
|-----|---------|
| [SPECIFICATION.md](SPECIFICATION.md) | Requirements, scenarios, acceptance criteria |
| [DESIGN.md](DESIGN.md) | Architecture, data model, 3D format, Mermaid diagrams |
| [TOOLS.md](TOOLS.md) | Every tool/library/data source used |
| [SECURITY.md](SECURITY.md) | Threat model, privilege handling, secure-coding rules |
| [TESTING_STRATEGY.md](TESTING_STRATEGY.md) | Test pyramid, fixtures, quality gates |
| [ROADMAP.md](ROADMAP.md) | Milestones and later ideas |
| [QUICKSTART.md](QUICKSTART.md) | Setup and first run |
| [QUICKSTART-WATCH.md](QUICKSTART-WATCH.md) | Presence watcher: timer set-up, commands, troubleshooting |
| [CLAUDE.md](CLAUDE.md) | Guidance for Claude Code / contributors |
| `*-short.md` | Plain-English summaries: [SPECIFICATION](SPECIFICATION-short.md), [DESIGN](DESIGN-short.md), [SECURITY](SECURITY-short.md), [TESTING_STRATEGY](TESTING_STRATEGY-short.md), [TOOLS](TOOLS-short.md), [ROADMAP](ROADMAP-short.md) |
| [model/](model/) | `schema.sql`, `house.schema.json`, `house.example.json` |

## Scope and ethics

Use only on networks you own or administer. No vulnerability scanning, no brute forcing, no cloud, no telemetry.

## Known limits

- HomeKit room names are not published on the network; assign rooms in Amenhotep.
- Unmanaged switches are invisible to software; link them manually.
- iPhones/Androids with private Wi-Fi addresses change MAC; Amenhotep uses mDNS to help recognise them and suggests merges.
