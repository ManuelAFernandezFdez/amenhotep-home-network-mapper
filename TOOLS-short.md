# Amenhotep — Tools (short version)

Full version: [TOOLS.md](TOOLS.md)

Everything the app depends on. At startup `amenhotep doctor` checks the system tools and the app switches off any feature whose tool is missing.

## Programs on your computer
| Tool | What it does for us | Needed? |
|------|--------------------|---------|
| **nmap** | Finds devices, scans ports and services, guesses the operating system (needs raw-socket permission for that), reads a few safe info scripts | **Yes** |
| `ip` | Reads the neighbour (ARP) table and your network interfaces | Yes |
| `arp-scan` | Faster, more reliable sweep of your local network | Optional |
| `avahi-utils` | Backup way to listen for devices announcing themselves | Optional |
| `notify-send` | Desktop pop-up for a new unknown device | Optional |
| systemd user timer | Runs the light presence check on a schedule | Optional |
| `net-snmp-utils`, `lldpd` | For managed switches in the future | Optional |

## Python libraries
- **PySide6:** the window and the 3D view.
- **defusedxml:** reads nmap and UPnP XML safely.
- **zeroconf:** listens for devices that announce themselves (HomeKit, Matter, AirPlay, Chromecast).
- **pydantic:** typed data models. **pyyaml:** the classification rules file. **jsonschema:** checks the house file.
- **keyring:** stores passwords safely. **pygltflib:** 3D export.
- Plain **sqlite3** from Python for the database.
- Development: pytest, pytest-qt, hypothesis, ruff, mypy, bandit, pip-audit.

Built in, no extra package: SSDP discovery, and the unicast mDNS question "what is your name?" sent straight to a device.

## Data sources
- **IEEE vendor lists** (three: large, medium and small blocks), to turn a MAC address into a company name. A starter list is bundled; you can download the full ones. This is the only internet access the app makes.
- nmap's own OS fingerprint database, and the public HomeKit category list.

## What goes on your network
ARP, ping, TCP connections, mDNS, UPnP, NetBIOS name lookups, and (for managed gear later) read-only SNMP and LLDP. Nothing leaves your network except the optional vendor-list download.

## Why not the alternatives
scapy needs root inside the program; Fing and Wireshark are not libraries; p0f needs a special network position; a big database server is overkill for a few hundred devices.
