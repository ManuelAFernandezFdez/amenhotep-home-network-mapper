# Amenhotep — Security

Amenhotep is a tool that actively probes a network and stores an inventory of it. Both aspects need care.

## 1. Threat model

| Asset | Threat | Mitigation |
|-------|--------|-----------|
| The user's LAN | Tool scans networks it should not (misconfiguration, copy-paste CIDR) | Scan targets restricted to RFC 1918 / ULA / link-local ranges and to subnets of local interfaces by default; public ranges blocked; first-run consent screen |
| Inventory DB (`amenhotep.db`) — lists every device, MAC, IP, room | Disclosure to other local users / malware | File mode `0600`, directory `0700`, under `platformdirs` user data dir; no network exposure; exports warn that they contain MACs |
| Credentials (SNMP community / v3 keys, router API tokens) | Leak via DB, logs, config | Stored only in the OS keyring (`keyring`); never in DB, `house.json`, logs or exports; redacted in debug output |
| Privileged scanning | GUI running as root; command injection into nmap | GUI never runs as root; nmap invoked with an argument list (no `shell=True`); targets validated as `ipaddress` objects; privilege via file capabilities (below) |
| Hostile data from the LAN (mDNS names, UPnP XML, SNMP strings, nmap banners) | XML bombs/XXE, injection into UI, path traversal, huge payloads | `defusedxml` for all XML; length caps on every string (e.g. 256 chars); rich text disabled — Qt labels use `Qt.PlainText`; values never used as file paths or in SQL strings (parameterised queries only) |
| `house.json` supplied/edited by hand | Malformed file crashes or exhausts memory | JSON Schema validation, size limit (2 MB), polygon/vertex caps, atomic writes, backup before save |
| Supply chain | Malicious/compromised dependency | Pinned versions with hashes (`pip-compile --generate-hashes`), `pip-audit` in CI, minimal dependency set listed in `TOOLS.md` |
| Network noise/DoS of fragile IoT | Aggressive scan crashes cheap devices | Per-host timeouts and retry caps (`-T4 --max-retries 1 --host-timeout`), light presence passes with probe caps and a 6 h cool-down; planned: confirmation for the "deep" profile and an exclusion list |
| Privacy | Telemetry/cloud leaks | No telemetry; no cloud; only optional user-triggered OUI download over HTTPS with checksum display |

## 2. Authorization and scope

- Intended only for **networks you own or are authorised to administer**. The first-run dialog states this and records acceptance.
- Defaults refuse non-private target ranges; overriding needs an explicit setting and a CLI flag.
- No exploitation, no brute forcing, no default-credential testing, no vulnerability scripts (`nmap --script vuln`, `brute`, `exploit` categories are blocked by an allow-list of NSE scripts).

## 3. Running nmap with least privilege

Preferred, in order:

1. **File capabilities** on the nmap binary (needed for OS detection `-O`; Amenhotep then passes `--privileged` automatically, and `amenhotep doctor` tells you whether it works):
   ```bash
   sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"
   ```
   Note: this lets *any* local user run raw-socket nmap. Acceptable on a single-user machine; on shared machines use option 2.
2. **Dedicated helper** `amenhotep-scan-helper` (polkit action, `pkexec`) that accepts only a validated CIDR + profile name and executes nmap with a fixed argument template. Roadmap item; until then use option 1 or run scans from CLI with `sudo`.
3. **Unprivileged fallback**: TCP connect scan (`-sT`), no OS detection, ARP via the kernel neighbour table (`ip neigh`) after a ping sweep. Reduced accuracy, flagged in the UI.

## 4. Secure coding rules

- No `eval`, `exec`, `pickle`, `yaml.load` (use `safe_load`), no `shell=True`.
- All SQL parameterised; schema changes only via migration scripts.
- Subprocess calls: absolute tool path resolved once at startup, argument list, timeout, bounded stdout size, environment scrubbed.
- Network sockets: fixed multicast groups/ports; receive size caps; timeouts.
- SNMP: read-only, v3 preferred; v2c community read from keyring; never written to logs.
- Logging: no secrets; MAC/IP appear only at DEBUG; log files `0600`.
- Qt: no `setHtml` with LAN-derived text; `QML` loaded from packaged resources only (no remote URLs).
- File I/O: `house.json` and DB paths only from settings or file dialog; atomic writes.
- Exports (CSV): guard against spreadsheet formula injection (prefix cells starting with `= + - @` with `'`).

## 5. Data retention

- Presence passes (`amenhotep watch`) are gentle on fragile IoT: sweep only, at most 8 full fingerprints per pass, 6-hour cool-down for unidentified devices, and a lock file so passes never overlap. The timer runs as your user (no root) and the notification text is neutralised (LAN-derived names are not rendered as markup).

- `observation` rows older than 90 days are pruned (configurable); devices persist.
- "Forget device" deletes its interfaces, evidence and observations.
- Whole-database wipe command: `amenhotep purge`.

## 6. Checks in CI

| Check | Tool |
|-------|------|
| Static security lint | `bandit -r src` |
| Dependency vulnerabilities | `pip-audit` |
| Type safety | `mypy --strict` on backend |
| Secret scanning | `gitleaks` pre-commit |
| Fuzz-ish tests for parsers | `hypothesis` on nmap-XML / mDNS-TXT / UPnP-XML parsers |

## 7. Reporting

Personal project: record issues in the repo tracker; there is no external disclosure process in v1.

## 8. Known limitations

- MAC addresses can be spoofed; identity is advisory, not authentication.
- Passive on-LAN attackers can answer mDNS/SSDP with false data; the UI shows evidence and confidence so it can be reviewed.
- Randomised MACs defeat tracking by design; Amenhotep does not try to defeat that.
