# Amenhotep — Testing Strategy

Principle: most logic is pure (parse → classify → store), so test it headless against **recorded fixtures**; touch the real network only in a few opt-in integration tests.

## 1. Pyramid

| Level | Scope | Tools | Share |
|-------|-------|-------|------:|
| Unit | parsers, OUI lookup, MAC utils, classifier rules, identity resolver, house model/validation, repository | `pytest`, `hypothesis` | ~65% |
| Component | collectors with fakes (fake subprocess, fake zeroconf), ScanService end-to-end into temp SQLite | `pytest`, `pytest-mock` | ~20% |
| GUI | models/proxies, dialogs, assignment flow, topology & 3D scene building (not pixels) | `pytest-qt`, `QT_QPA_PLATFORM=offscreen` | ~10% |
| Integration (opt-in) | real nmap against a controlled lab (network namespaces/containers) | `pytest -m lab` | ~5% |
| Manual | real home network acceptance run | checklist below | per release |

## 2. Fixtures (the key asset)

`tests/fixtures/` holds anonymised captures:
- `nmap/*.xml` — host discovery, `-sV`, `-O` for: Linux server, Windows 11 PC, iPhone, Android, printer, Synology NAS, Hue bridge, ESP32 plug, managed switch.
- `mdns/*.json` — TXT/SRV records for `_hap._tcp` (bulb ci=5, outlet ci=7, bridge ci=2), `_airplay._tcp`, `_companion-link._tcp`, `_matter._tcp`.
- `ssdp/*.xml` — UPnP device descriptions (TV, router, printer).
- `snmp/*.json` — FDB and LLDP walk results from a switch.
- `house/*.json` — valid and invalid house files.

A script `tools/anonymise_fixture.py` rewrites real captures (MACs → documentation OUIs, IPs → 192.0.2.0/24) so no personal data lands in the repo.

## 3. What to test, concretely

**Parsing & robustness** — nmap XML with missing fields, huge banners, XXE payload, truncated file; mDNS TXT with invalid UTF-8; UPnP XML bombs. Property tests: parsers never raise anything but `ParseError`, never exceed length caps.

**Classification** — table-driven: observation set → expected `(os_family, type, vendor, model, min_confidence)`. Includes the tricky cases: iPhone vs Mac (mDNS model), Android with randomised MAC, Windows with ICMP blocked, "Apple iOS/macOS" nmap ambiguity. Regression: every misclassification found in real use becomes a fixture.

**Identity** — same device on Wi-Fi + wired merges only when instructed; IP change keeps identity; randomised MAC rotation creates suggestion not auto-merge; manual merge/split.

**Manual-wins rule** — property test: after any sequence of scans, locked fields are unchanged.

**Location** — roaming/fixed transitions; a fixed device seen on a different AP keeps its room; phone-as-clock scenario (S3).

**Topology** — links form a forest, one uplink per device, cycle prevention, unmanaged switch manual link, SNMP FDB → port mapping (including ports with uplinks that see many MACs: choose the port where the MAC is learned *and* is not a trunk/uplink).

**Repository/DB** — migrations from v0 → vN on a temp file; foreign keys enforced; concurrent read during write; schema applies cleanly (`sqlite3 :memory: < model/schema.sql`).

**House model** — schema validation, polygon winding/self-intersection, opening within wall length, placement outside its room warns, round-trip load→save is byte-stable (sorted keys, fixed indent), atomic write survives injected failure, glTF export loads back with `pygltflib` and has expected node count.

**GUI** — filter/sort proxy, bulk assign updates DB, scan progress signals update UI without blocking (event loop spin test), 3D scene builder produces one node per room and per placed device, drag handler updates placement.

**Security** — path/arg injection attempts in target field (`10.0.0.0/24; rm -rf`), public CIDR rejected, NSE allow-list enforced, keyring used for secrets (assert nothing in DB/logs), CSV injection.

## 4. Lab integration (`-m lab`)

Linux network namespaces (`ip netns`) with a veth bridge and a few services (sshd, avahi publishing a fake `_hap._tcp`, miniupnpd, snmpd) to verify discovery end-to-end without touching the home network. Requires root; excluded from default runs and CI unless the runner permits.

## 5. Quality gates

| Gate | Target |
|------|--------|
| Line coverage backend (`core`, `collectors`, `services`, `store`) | ≥ 85%; classifier & identity ≥ 95% |
| GUI coverage | ≥ 60% (logic in models/controllers, thin widgets) |
| `ruff`, `mypy --strict` (backend) | zero errors |
| `bandit`, `pip-audit` | no high severity |
| Mutation spot-check (`mutmut`) on classifier | ≥ 70% killed (periodic, not per-PR) |
| Performance | classify 500 devices < 1 s; load 500-device table < 200 ms; full /24 scan fixture replay < 5 s |

## 6. CI layout

1. `lint` (ruff, mypy)
2. `unit+component` (matrix Python 3.12/3.13, Linux)
3. `gui` (offscreen Qt)
4. `security` (bandit, pip-audit)
5. nightly: lab tests, mutation test

## 7. Manual acceptance checklist (per release)

- [ ] Scan finds all devices listed in router DHCP table (± known sleeping ones).
- [ ] HomeKit accessories show model and category; count matches Home app.
- [ ] Both mesh repeaters and all switches present with children.
- [ ] Phone used as night clock stays in its room after leaving/rejoining Wi-Fi.
- [ ] Rescan after IP change keeps names/rooms.
- [ ] 3D: drag a device, restart, position kept; hand-edit `house.json`, reload OK.
- [ ] Invalid `house.json` gives an actionable error, no crash.
- [ ] No unexpected outbound traffic (check with `ss`/firewall log) during scan.
