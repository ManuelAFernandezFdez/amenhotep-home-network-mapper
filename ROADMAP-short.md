# Amenhotep — Roadmap (short version)

Full version: [ROADMAP.md](ROADMAP.md)

Each step ends with something you can run.

| Step | What you get | State |
|------|-------------|-------|
| M0 Foundations | Project set-up, database, checks that nmap is present | ✅ done |
| M1 Scan core | Command-line scan and device list with IP, MAC, vendor | ✅ done |
| M2 Identification | Names devices from mDNS and UPnP; evidence for every guess | ✅ done |
| M3 Window | The Qt app: device table, filters, detail panel, scans, edits that stick | ✅ done |
| M4 Areas | Zones and rooms, bulk assign, fixed vs roaming, bedside-clock pinning | ✅ done |
| M5 HomeKit & Matter | HomeKit tab with paired flag, Matter devices, Thread border routers | ✅ done |
| M6 Topology | Switches and repeaters as devices; link children by hand; drag-to-link map; optional router client list | next |
| M7 3D viewer | Open the house file and see rooms and devices in 3D | planned |
| M8 3D editor | Drag devices, edit rooms, save with backup, export glTF | planned |
| M9 Hardening and release | Security checklist, packaging, final acceptance run, v1.0 | planned |

## Also done along the way
- Better vendor lookup from all three IEEE lists.
- Asking silent devices for their name directly.
- Presence history: a light check on a timer, online/offline status, typical online hours, a notification for new unknown devices.
- "Amun is satisfied" status: how many devices are known.
- The Amenhotep name, logo and About box.

## Later ideas
A privilege helper with polkit, passive fingerprinting from a mirror port, importing Apple Home room names through a paired controller, support for UniFi, FRITZ!Box, OpenWrt, TP-Link Deco and Eero, a Wi-Fi signal heat map in 3D, and cable routes.

## Open items
Exact models of the router, the two repeaters and the TP-Link switches are still needed for M6.
