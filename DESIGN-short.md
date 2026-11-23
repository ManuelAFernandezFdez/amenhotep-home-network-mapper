# Amenhotep — Design (short version)

Full version: [DESIGN.md](DESIGN.md)

## The big picture
Three layers. The **GUI** (Qt) shows things. **Services** decide things. **Collectors** gather raw facts from the network. The backend has no Qt code, so it also works from the command line and in tests.

## How a scan becomes knowledge
1. **Collectors** (nmap, neighbour table, mDNS, UPnP, name queries) each report what they saw as a small "observation". They never write to the database.
2. **Identity** decides which device an observation belongs to. A MAC address matches a device. Private (randomised) MACs are flagged and never merged automatically.
3. **Classifier** turns facts into evidence: "this is a Philips light, 0.95 sure, because HomeKit said so". The most trusted evidence wins.
4. **Repository** saves the result in SQLite.

## How it decides what a device is
Evidence has a trust score. Roughly, from most to least trusted: your own edit (1.0), HomeKit and Apple model names (0.95), UPnP model (0.85), nmap OS match (up to 0.85), hostname hints (0.6), open-port patterns (0.5), vendor from the MAC (0.4), TTL (0.2). Rules live in a text file (`os_rules.yaml`), so you can add your own without coding.

## Devices and identity
A device can have several interfaces (a laptop wired and on Wi-Fi). The device has its own ID, so a changed IP never loses your edits. Fields you edited are locked and scans leave them alone.

## Data
SQLite holds devices, interfaces, evidence, scans, areas (zones and rooms), HomeKit accessories, Matter nodes, Thread border routers and presence sightings. The house shape lives in a separate JSON file.

## Network map
Switches, routers and repeaters are devices with links to their children. Links come from you first, then optional hints. Unmanaged switches cannot be detected, so you drag a device onto a switch to link it.

## The 3D house file
A readable JSON file (`amenhotep-house/1`): metres, Z up, floors with height, rooms as 2D outlines that are extruded, openings for doors and windows, and devices placed by their ID. Rooms in the file match rooms in the database. Edits are written safely with a backup. It exports to glTF for Blender.

## The window
Tabs for Devices, HomeKit & Matter and Scans now; Topology and House 3D later. The table is fast and sortable. Long work runs in the background and reports back without freezing the window.

## Fixed vs roaming
A fixed device keeps its room even if seen elsewhere. A roaming device only records where it was last seen.

## Later additions
- **Matter and Thread:** Thread devices have no IPv4 address, so they are stored separately and merged when one device is in several apps.
- **Presence:** each light check records which devices were online; only new or unidentified ones get a full probe, with a cool-down.

## Key decisions
PySide6 for Qt; plain SQLite; nmap as a separate program; mDNS inside Python; a custom editable house format with glTF export; collectors as small plug-ins; manual edits always win.
