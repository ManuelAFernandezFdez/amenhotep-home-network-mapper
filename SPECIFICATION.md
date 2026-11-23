# Amenhotep — Specification

Version 0.1 (draft) · 2026-11-22

## 1. Purpose

Amenhotep discovers every device on a home network (wired via switches and wireless via Wi-Fi mesh), identifies what each one is, lets the owner assign it to a place in the house, and shows the result as a device list, a network topology graph, and an editable 3D model of the house.

Single user, single household, one LAN (possibly several VLANs/subnets later). Runs locally; no cloud.

**Amenhotep** = **A**ppliance **M**apping & **E**numeration of **N**etwork **H**ardware, **O**ver **T**hread, **E**thernet & **P**rotocols.

### The core story

* Amun = the hidden one. Your tool reveals the hidden devices on your network. Tagline: "Nothing stays hidden from Amun."
* "Satisfied." When every device is identified, Amun is satisfied. You could use that as the all-clear status: "Amun is satisfied: 23/23 devices known." Unknown devices make him unsatisfied.
* Amenhotep, son of Hapu was a famous royal scribe and architect who recorded and built Egypt's great works. That fits a tool that surveys and maps your network.


### Amun's mood (implemented)

A device is *known* when its device type is not `unknown`. The GUI status bar and `amenhotep list` show "Amun is satisfied: N/N devices known." when all are known, otherwise "Amun is not satisfied: K/N devices known (M still hidden).". It updates after every scan or edit.

## 2. Goals and non-goals

**Goals**
- G1. Discover all IPv4 devices on the LAN(s), including those on Wi-Fi.
- G2. Identify: IP, MAC, hostname, vendor (OUI), OS family (Linux / Windows / iOS / macOS / Android / RTOS-embedded / unknown), device type, and hardware model where possible.
- G3. Identify HomeKit (HAP) accessories and Matter/Thread devices where possible.
- G4. Model switches and Wi-Fi mesh repeaters as devices, and show which devices hang off which.
- G5. Assign each device to an area (see §4) with manual override that survives rescans.
- G6. Render a 3D house with rooms and devices; the layout is a plain text file the user can edit by hand or in the app.
- G7. Qt GUI, Python backend, small embedded DB.

**Non-goals (v1)**
- Packet capture / traffic analysis, vulnerability scanning, intrusion detection.
- Controlling devices (no HomeKit control, no pairing).
- Scanning networks the user does not own.
- Mobile app, multi-user, cloud sync.

## 3. Users and key scenarios

One technical home owner.

| ID | Scenario |
|----|----------|
| S1 | Run a scan; see new/changed/missing devices highlighted. |
| S2 | Open a device, see IP/MAC/OS/hardware guess with confidence and evidence, correct it. |
| S3 | A phone used as a night-table clock is marked "fixed" and pinned to the main bedroom; it is not treated as roaming. |
| S4 | See that the Hue bridge is wired to switch SW-2 port 5, and the laptop is on the first-floor mesh repeater. |
| S5 | Open the 3D view, click a room, see devices in it; drag a device to a new position; save. |
| S6 | Edit `house.json` in a text editor, reload, see the change. |

## 4. Location model

Two independent levels:

**Zones (where, coarse)** — fixed list, editable:
Ground floor · First floor · Second floor · Garden · Veranda · Roaming (moving devices)

**Rooms (where, fine)** — belong to a zone; defaults:

| Room | Zone |
|------|------|
| Kitchen | Ground floor |
| Living room | Ground floor |
| Main bedroom | First floor |
| Secondary bedroom | First floor |
| Third bedroom | First floor |
| Second-floor bedroom | Second floor |
| Garden, Veranda | (zone itself) |

> Assumption: the request's "2rd bedroom" is read as "3rd bedroom". Rooms are data, so this is trivially renamed.

**Location mode** per device:
- `fixed` — has a zone/room; never auto-changed. Used for static devices and for phones/tablets used as clocks.
- `roaming` — zone = Roaming; may be seen on any AP. Position is "last seen via <AP>" only.

Roaming hint: a device that has been seen via more than one AP/port in 7 days is *suggested* as roaming; the user decides.

## 5. Functional requirements

### 5.1 Discovery
| ID | Requirement |
|----|-------------|
| F-D1 | Host discovery on configured CIDR(s) using ARP (same L2) and ICMP/TCP probes. |
| F-D2 | Port/service scan (top-N ports, configurable) with service/version detection. |
| F-D3 | OS fingerprinting via nmap `-O` when privileges allow; fallback to TTL/ports/banner heuristics. |
| F-D4 | MAC vendor lookup using the IEEE registries (MA-L, MA-M, MA-S; bundled seed, updatable); unicast mDNS reverse query for hostnames of silent hosts. Detect randomized (locally administered) MACs and flag them. |
| F-D5 | mDNS/DNS-SD browse (`_hap._tcp`, `_homekit._tcp`, `_matter._tcp`, `_airplay._tcp`, `_companion-link._tcp`, `_device-info._tcp`, `_googlecast._tcp`, `_ipp._tcp`, `_smb._tcp`, `_ssh._tcp`, etc.). |
| F-D6 | SSDP/UPnP discovery (M-SEARCH) and device-description XML fetch for model info. |
| F-D7 | NetBIOS/LLMNR/reverse-DNS name resolution. |
| F-D8 | DHCP lease import (optional): router lease file or API for hostnames and DHCP vendor class (opt. 60). |
| F-D9 | Scans run in background threads/processes; GUI never blocks; progress and cancel supported. |
| F-D10 | Scheduled rescans (optional, default off) and "quick presence" scan (ARP only). |
| F-D11 | Presence history: a light `watch` pass (sweep, neighbour table, mDNS) can run every 15–30 minutes from a timer; each pass records which devices were seen, shows online/offline and typical online hours, fingerprints only new or still-unidentified devices (capped per pass, cool-down 6 h), and can notify about new unknown devices. Data older than 90 days is pruned. |

### 5.2 Identification
| ID | Requirement |
|----|-------------|
| F-I1 | Each device gets `os_family`, `device_type`, `vendor`, `model`, each with a **confidence 0–1** and list of **evidence** items. |
| F-I2 | Evidence sources are ranked (see DESIGN §Classification). User edits have confidence 1.0 and are never overwritten. |
| F-I3 | Device types: router, switch, access-point/mesh-node, computer, laptop, phone, tablet, tv, media-player, speaker, printer, NAS, camera, IoT-sensor, smart-plug/bulb, hub/bridge, game-console, HomeKit-accessory, unknown. |
| F-I4 | HomeKit accessories identified from `_hap._tcp` TXT: `id` (device id), `md` (model), `ci` (category id), `sf` (paired/unpaired flag), `ff`, `c#`. Category mapped to type (e.g. ci=5 Lightbulb, 7 Outlet, 2 Bridge). |
| F-I5 | A single physical device with multiple interfaces (wired + Wi-Fi) can be merged manually; the app suggests merges by hostname/mDNS instance id. |

### 5.3 Topology (switches, mesh, APs)
| ID | Requirement |
|----|-------------|
| F-T1 | Switches, routers, APs and mesh repeaters are first-class devices with `is_infrastructure=true`. |
| F-T2 | Each device has an optional **uplink**: parent device + port label (wired) or SSID/band/RSSI (Wi-Fi). |
| F-T3 | Automatic uplink sources, best effort and optional: router client list (see §5.3.1); SNMP/LLDP only if a managed device is added later. |
| F-T4 | Manual uplink assignment is the **baseline**: the owner's switches are TP-Link *unmanaged* (one 8-port, two 4-port), which expose no SNMP, LLDP or MAC table. |
| F-T7 | Infrastructure device templates: "TP-Link unmanaged switch (4/8 ports)" pre-fills type, port count (ports shown as slots in the UI) and `managed=false`. Models to be supplied by the owner. |
| F-T8 | Port-level assignment: a child can be placed on a specific switch port number (optional, purely informational). |

#### 5.3.1 Router: Ziggo modem-router (Compal/Harris-class Connect Box, ~6–8 years old)
Exact model to be confirmed. Assumptions for this class of device:
- It is the DHCP server and gateway; no SNMP, no TR-064, no public API. Its web UI (default gateway address, usually 192.168.178.1 or 192.168.0.1) lists DHCP clients and may show wired/Wi-Fi per client.
- An optional **RouterImporter** adapter reads that client list (hostname, MAC, IP, connection type) using the owner's admin login stored in the OS keyring. It is read-only, off by default, and failure-tolerant. If the model has no usable page, the adapter is skipped; everything else works from scans.
- The router's built-in Wi-Fi is treated as an access point device ("Ziggo router") and the root of the topology.
- The router **has a web page** (confirmed by the owner), so the RouterImporter is feasible; its exact pages/format are discovered in milestone M6 by inspecting the live UI (read-only).
- **Mesh repeaters (first floor, veranda)** are also Ziggo-supplied, 5+ years old (likely Ziggo WiFi Booster class) and are **wired (Ethernet backhaul)**, so each is a wired child of a switch/router and an access point for Wi-Fi clients. Assumed to be managed only via the router/Ziggo app, with no API of their own. They are modelled as `access-point/mesh-node` devices, linked manually (wired to a switch or Wi-Fi to the router/another repeater). Clients on a repeater are assigned manually; if the router's client list reports the serving node, it is shown as a hint only. Repeaters usually appear on the LAN with their own MAC/IP and an HTTP page, so scans can still find and fingerprint them.
- If the modem is later put in bridge mode behind another router, only the root of the topology changes.
| F-T5 | Topology view: tree/graph with switches, repeaters (first floor, veranda) and children; click to open device. |
| F-T6 | Inferred hints: a mesh node and its clients share the same upstream gateway MAC prefix or RSSI table; shown as suggestions, never applied silently. |

### 5.4 Assignment
| ID | Requirement |
|----|-------------|
| F-A1 | Assign zone, room, location mode, display name, notes per device; bulk assign via multi-select. |
| F-A2 | Assignment keyed by device identity (UUID), not IP; IP changes do not lose it. |
| F-A3 | Device identity resolution order: MAC (non-random) → mDNS/HAP id → hostname+vendor → manual merge. Randomized MACs (iOS/Android private address) get a fresh identity unless merged. |
| F-A4 | Filter/search by zone, room, type, OS, vendor, status (online/offline/new). |

### 5.5 GUI
Qt (PySide6). Main window with tabs/docks:
1. **Devices** — table, filters, detail panel, bulk edit.
2. **Topology** — graph of infrastructure and children.
3. **House 3D** — 3D model; room tree; device palette; edit mode.
4. **Scans** — history, diff between scans, run/cancel, settings.
5. **Settings** — networks, tool paths, SNMP creds (via keyring), OUI update.

### 5.6 3D house
| ID | Requirement |
|----|-------------|
| F-3D1 | Generated from `house.json` (see `model/house.example.json`, DESIGN §3D format). |
| F-3D2 | Floors stacked; rooms extruded from 2D polygons; walls with optional door/window openings; garden and veranda as outdoor slabs. |
| F-3D3 | Devices shown as icons/markers at stored positions inside rooms; colour by status; label on hover. |
| F-3D4 | Devices assigned to a room but without coordinates are auto-placed on a grid within the room and flagged "unplaced". |
| F-3D5 | Edit mode: drag device, set x/y/z numerically, choose mount type; edit rooms by polygon vertices; changes saved to `house.json`. |
| F-3D6 | File is hand-editable, JSON-Schema validated, diff-friendly, versioned (`"format": "amenhotep-house/1"`). |
| F-3D7 | Export to glTF 2.0 (`.glb`) for use in Blender or other viewers. |
| F-3D8 | Floor isolation (show one floor), x-ray walls, camera presets (top, isometric). |

### 5.7 Data and persistence
- SQLite single file (`amenhotep.db`) is the "basic format" DB: zero-admin, in Python stdlib, easy to back up. Schema in `model/schema.sql`.
- House geometry lives in `house.json` (human-editable); the DB stores devices and scan history. Placements reference device UUIDs.
- Export/import: CSV and JSON of devices.

## 6. Non-functional requirements

| ID | Requirement |
|----|-------------|
| N1 | Platform: Linux first (Fedora target); Windows/macOS later. |
| N2 | Scale: ≤ 500 devices, ≤ 5 subnets; full scan of a /24 in < 5 min, quick scan < 30 s. |
| N3 | GUI stays responsive (no blocking calls on the UI thread). |
| N4 | Does not require root for the GUI; privileged scanning via file capabilities or a helper (see SECURITY). |
| N5 | Offline-capable; the only network traffic is to the user's LAN, plus optional OUI list download. |
| N6 | Python 3.12+, PySide6 6.7+. |
| N7 | All third-party tools declared in `TOOLS.md`; the app checks them at startup and degrades gracefully. |
| N8 | Tests and coverage per `TESTING_STRATEGY.md`. |

## 7. Out-of-scope data

HomeKit **room names** are stored in the Apple Home database and are not broadcast on the network. Amenhotep therefore cannot read them; users assign rooms in Amenhotep. A future optional import via a paired HAP controller is listed in the roadmap.

## 8. Acceptance criteria (v1.0)

1. A scan of the home /24 lists ≥ 95% of devices known to be on the network (checked against router DHCP table).
2. Every device shows IP, MAC, vendor, OS family (or `unknown`), with evidence.
3. HomeKit accessories advertising `_hap._tcp` are labelled with model and category.
4. All switches and the two mesh repeaters appear and can have children assigned.
5. Zone/room/location-mode assignment persists across rescans and IP changes.
6. 3D view opens `house.json`, shows rooms and devices; a dragged device keeps its position after restart.
7. Editing `house.json` by hand and reloading is reflected without data loss.
8. Test suite passes; coverage targets met.
