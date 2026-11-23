# Amenhotep — Roadmap

Each milestone ends in something runnable. Effort is rough, for one developer part-time.

| # | Milestone | Deliverables | Done when | Est. |
|---|-----------|--------------|-----------|------|
| M0 | Foundations | Repo skeleton, `pyproject.toml`, ruff/mypy/pytest CI, pydantic models, SQLite schema + migrations, settings, tool diagnostics | `pytest` green; `amenhotep doctor` reports nmap presence | 1 wk |
| M1 | Scan core (CLI) | Nmap + ARP collectors, XML parser, OUI lookup, identity resolver, `amenhotep scan` / `amenhotep list` | Home /24 inventory printed with IP, MAC, vendor | 2 wk |
| M2 ✅ | Identification | mDNS collector, SSDP, NetBIOS/rDNS, classifier + `os_rules.yaml`, evidence storage | OS family + type correct for ≥ 80% of devices; evidence visible | 2 wk |
| M3 ✅ | GUI basics | Main window, devices table, filters, detail panel, scan tab with progress/cancel, manual edit with locked fields | Scan from GUI; edit name/type; survive rescan | 2 wk |
| M4 ✅ | Areas & location | Zones/rooms, bulk assign, roaming vs fixed, phone-as-clock pinning | Scenario S3 works | 1 wk |
| M5 ✅ | HomeKit & Matter | HAP category mapping, model, paired flag, accessory view, Matter/Thread border router detection | HomeKit accessories match Home app count | 1 wk |
| M6 | Topology | Infrastructure devices with switch templates (TP-Link unmanaged 4/8 port), manual links with port slots, drag-to-link topology graph, optional Ziggo router client-list importer (wired/Wi-Fi hint), "suggest uplink" hints; SNMP/LLDP collector kept optional for future managed gear | Switches and both repeaters show children, all linked manually in minutes | 2 wk |
| M7 | 3D viewer | `house.json` loader/validator, Qt Quick 3D scene, rooms/floors, device markers, floor isolation, camera presets | Example house renders with devices | 2 wk |
| M8 | 3D editor | Drag/place devices, numeric position, room polygon editing, save with backup, glTF export, unplaced-device flow | Scenarios S5, S6 | 2 wk |
| M9 | Hardening & release | Security checklist, packaging (Flatpak or RPM + pip), docs, acceptance run, lab tests | v1.0 tag | 1–2 wk |

## Later (post 1.0)

- `amenhotep-scan-helper` with polkit for privilege separation.
- ~~Scheduled scans, presence history, "new unknown device" desktop notification.~~ Done: `amenhotep watch`, `presence`, systemd user timer (see QUICKSTART).
- Passive fingerprinting (`p0f`) and DHCP sniffing from a mirror port.
- Import Apple Home room names via a paired HAP controller (opt-in, uses `aiohomekit`).
- Vendor integrations: UniFi, FRITZ!Box (TR-064), OpenWrt (ubus), TP-Link Deco/Omada, Eero.
- Heat-map of Wi-Fi RSSI in the 3D view; cable routes.
- Import floor plans (SVG/DXF) to trace rooms; IFC import.
- IPv6 discovery; multi-subnet / VLAN awareness.
- Windows/macOS support.

## Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Unmanaged TP-Link switches and the old Ziggo router expose nothing | Topology is manual (confirmed for this house) | Manual-first UX with drag-to-link and port slots; router client list as a hint; suggestions never applied silently |
| iOS/Android private MACs | Duplicate devices | mDNS identity; merge suggestions; user guidance |
| Ziggo repeaters/router have no API (confirmed class) | No Wi-Fi client→node map | Manual assignment; router client list hint; adapters only if a future model offers one |
| Qt Quick 3D from Python is less documented | M7 slips | Spike in M0/M1 (render a box scene); fallback: `pyqtgraph.opengl` |
| nmap OS detection noisy on IoT | Wrong hardware guesses | Show confidence + evidence; manual override |
