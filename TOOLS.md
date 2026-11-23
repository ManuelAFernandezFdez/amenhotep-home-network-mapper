# Tools and Dependencies

Every external tool and library Amenhotep uses. The app checks the system tools at startup (Settings → Diagnostics) and disables features whose tool is missing.

## System tools

| Tool | Used for | Required? | Privileges | Install (Fedora) |
|------|----------|-----------|------------|------------------|
| `nmap` ≥ 7.94 | Host discovery (`-sn`, ARP), port/service scan (`-sV`), OS fingerprint (`-O`), NSE scripts `upnp-info`, `nbstat`, `snmp-sysdescr`, `dns-service-discovery`; output parsed from XML (`-oX -`) | **Yes** | Raw sockets for ARP and `-O`: grant `cap_net_raw,cap_net_admin+eip` to the nmap binary or use the helper (see SECURITY) | `sudo dnf install nmap` |
| nmap NSE scripts (allow-listed in `core/models.py`) | `banner`, `http-title`, `http-server-header`, `ssl-cert`, `smb-os-discovery`, `rdp-ntlm-info`, `nbstat`, `upnp-info` — read-only identification only; vuln/brute/intrusive categories are blocked | No | none | bundled with nmap |
| `arp-scan` (optional) | Fast, reliable L2 sweep; finds hosts that drop ICMP | No | `cap_net_raw` | `sudo dnf install arp-scan` |
| `ip` (iproute2) | Read neighbour table, interfaces, default route | Yes | none | preinstalled |
| `avahi-utils` (optional) | Fallback `avahi-browse -a -r -t` if python `zeroconf` fails | No | none | `sudo dnf install avahi-tools` |
| `net-snmp-utils` (optional) | Manual debugging of SNMP (`snmpwalk`); app itself uses the Python library | No | none | `sudo dnf install net-snmp-utils` |
| `lldpd` / `lldpctl` (optional) | LLDP neighbour info from the host's NIC | No | root for daemon | `sudo dnf install lldpd` |

## Python libraries

| Package | Purpose |
|---------|---------|
| `PySide6` | Qt GUI, Qt Quick 3D for the house view |
| `python-nmap` **or** own XML parser (`xml.etree`/`defusedxml`) | Parse nmap output (we use `defusedxml` directly; see DESIGN) |
| `defusedxml` | Safe parsing of nmap XML and UPnP descriptions |
| `pyyaml` | Classification rules (`data/os_rules.yaml`, `safe_load` only) |
| `zeroconf` | mDNS/DNS-SD browsing (HomeKit, Matter, AirPlay, Chromecast …) |
| `ssdp`-style: own code over `socket` | SSDP M-SEARCH (small; no dependency) |
| `pysnmp` (or `puresnmp`) | SNMP v2c/v3 for managed switches/APs |
| bundled seed + IEEE `oui.csv` / `mam.csv` / `oui36.csv` | MAC → vendor (longest prefix: MA-S 36-bit, MA-M 28-bit, MA-L 24-bit; a block owned only by the "IEEE Registration Authority" counts as unknown) |
| `notify-send` (libnotify) | optional desktop notification for new unknown devices (`watch --notify`) |
| systemd user timer | optional scheduler for `amenhotep watch` (`assets/install-timer.sh`) |
| built-in unicast mDNS reverse query (UDP 5353) | asks each live host for its name (`collectors/mdns_reverse.py`); same query as `avahi-resolve-address` |
| `keyring` | Store SNMP credentials / router tokens in the OS keyring |
| `jsonschema` | Validate `house.json` |
| `SQLAlchemy` *(optional)* / stdlib `sqlite3` | DB access; v1 uses stdlib `sqlite3` + thin repository layer |
| `pygltflib` (or `trimesh`) | glTF/GLB export |
| `pydantic` v2 | Typed models for devices, scan results, house file |
| `platformdirs` | Config/data directory |
| `pytest`, `pytest-qt`, `pytest-cov`, `hypothesis`, `ruff`, `mypy`, `bandit`, `pip-audit` | Dev/test/QA |

## Data sources

| Source | URL | Use |
|--------|-----|-----|
| IEEE OUI registry (MA-L/MA-M/MA-S) | https://standards-oui.ieee.org/ | MAC vendor; bundled snapshot, user-triggered update (only outbound internet call) |
| nmap OS DB | bundled with nmap | OS fingerprints |
| HAP category list | HomeKit Accessory Protocol spec (public non-commercial) | `ci` → type mapping, in `data/hap_categories.json` |

## Protocols touched on the LAN

ARP, ICMP, TCP connect/SYN, mDNS (UDP 5353 multicast), SSDP (UDP 1900 multicast), NetBIOS (UDP 137), SNMP (UDP 161, read-only), LLDP (L2, passive), HTTP GET to UPnP description URLs found on LAN.

No traffic is sent outside the LAN except the optional OUI download.

## Why not X?

| Alternative | Decision |
|-------------|----------|
| `scapy` | Powerful but heavier and needs root in-process; nmap/arp-scan cover ARP. |
| Fing / Wireshark | Not scriptable libraries; capture not required. |
| `p0f` | Passive fingerprinting needs a sniffing position; deferred (roadmap). |
| Neo4j / Postgres | Overkill for ≤ 500 devices. |
