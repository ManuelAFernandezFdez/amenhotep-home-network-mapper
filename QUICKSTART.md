# Amenhotep — Quickstart

> Status: milestones M0–M5 are implemented (CLI: `doctor`, `scan`, `list`, `show`, `validate-house`, `update-oui`; GUI: `amenhotep-gui` with Devices and Scans tabs). In the GUI, right-click devices → "Assign to area" or "Pin as fixed in…" (night-table phone clocks), or use the Area box in the detail panel; the Area filter includes rooms of a zone. The "HomeKit & Matter" tab lists HAP accessories, Matter devices (Thread nodes are flagged; right-click to name or place them) and Thread border routers. Topology and the 3D view come in later milestones (see [ROADMAP.md](ROADMAP.md)); sections 6–7 describe those.
>
> Python 3.12+ required. `pip install -e ".[dev]"` inside a venv, then `pytest`. Run `amenhotep update-oui --yes` once to download the full IEEE vendor lists (MA-L, MA-M and MA-S, about 6 MB; the bundled one is a small seed). Many small makers share the IEEE's own block, so the MA-M/MA-S lists matter.

## 1. Install system tools (Fedora)

```bash
sudo dnf install nmap arp-scan python3.12 python3-pip
```

Optional: `sudo dnf install avahi-tools net-snmp-utils lldpd`

## 2. Allow raw-socket scans without running the GUI as root

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"
```

Read the trade-off in [SECURITY.md §3](SECURITY.md) first. **Without this step OS fingerprinting (`nmap -O`) is disabled** and Amenhotep falls back to services, web/TLS banners, mDNS and port heuristics. `amenhotep doctor` shows which mode you are in.

## 3. Create the environment

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## 4. Check the setup

```bash
amenhotep doctor
```

Reports which tools are found (nmap, arp-scan, avahi) and which features are available.

## 5. First scan (CLI)

```bash
amenhotep scan --target auto --profile standard
amenhotep list
```

`--target auto` uses the subnets of your local interfaces. Profiles: `quick` (ARP only, seconds), `standard` (ports + services + mDNS/SSDP), `deep` (adds OS detection, slower).

## 6. Launch the GUI

```bash
amenhotep-gui
```

1. **Scans** tab → *Start scan*.
2. **Devices** tab → select devices → *Assign…* choose zone, room, and mode (*fixed* for the iPad night clock).
3. **Topology** tab → mark switches/repeaters, drag devices onto them to set uplinks.
4. **House 3D** tab → *Open house file…*

## 7. Edit the 3D house

Copy the example and edit dimensions and rooms in any text editor:

```bash
cp model/house.example.json ~/.local/share/amenhotep/house.json
```

- Units are metres; Z is up; origin = south-west corner of the ground floor.
- Rooms are polygons (counter-clockwise); add `openings` for doors/windows.
- Positions are `[x, y, z]` with z above the floor.
- Validate any time:

```bash
amenhotep validate-house ~/.local/share/amenhotep/house.json
```

In the app: *House 3D → Edit mode*, drag devices; Save writes back to the same file and keeps `house.json.bak`.

## 8. Validate the SQL schema today

```bash
sqlite3 :memory: < model/schema.sql && echo OK
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Few devices found | Run with ARP/capabilities (step 2); check you are on the same subnet/VLAN |
| No OS guesses | `deep` profile needs raw sockets |
| No HomeKit devices | mDNS blocked by Wi-Fi isolation or firewall (allow UDP 5353) |
| Phone appears twice | Private Wi-Fi address; use *Merge* in the device menu |

## Presence: catching devices that are off during a scan

`amenhotep watch` is a light pass that records who is online and fingerprints only new or unidentified devices. Setting it up as a timer, reading the results and troubleshooting are in [QUICKSTART-WATCH.md](QUICKSTART-WATCH.md).
