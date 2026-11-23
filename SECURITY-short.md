# Amenhotep — Security (short version)

Full version: [SECURITY.md](SECURITY.md)

## Why it matters
The tool probes your network and keeps a list of every device, MAC address and room. Both need care.

## The main rules
- **Your network only.** Scans are limited to private address ranges, and a first-run screen asks you to confirm you may scan it. Public ranges are refused.
- **No attacks.** No exploits, password guessing or vulnerability scripts. Only a short list of safe, read-only nmap scripts is allowed.
- **Private data stays private.** The database is readable only by you. There is no telemetry and no cloud. The only internet call is the optional download of vendor lists from the IEEE.
- **Secrets** (router password, SNMP keys) go in the system keyring, never in the database, logs or exports.
- **Never trust what the network says.** Device names and XML from the LAN could be hostile, so XML is parsed safely, text is length-limited, shown as plain text, and never used in file paths or SQL.
- **No shell tricks.** Programs are started with fixed argument lists, targets are validated addresses, and the GUI never runs as root.

## Running nmap without root
1. **Preferred:** give the nmap program raw-socket permission once with `setcap`. Good on a single-user machine, since any local user could then run raw-socket nmap.
2. **Later:** a small helper with polkit that accepts only a validated address and profile.
3. **Fallback:** a plain connect scan with no OS detection, clearly marked as less accurate.

## Being gentle
Scans have per-host time limits and a retry cap, and fragile IoT gear is protected: the regular presence check does a light sweep, probes at most 8 devices per pass, waits 6 hours before retrying an unidentified one, and never runs two passes at once.

## Data kept
Scan history older than 90 days is pruned. "Forget device" deletes a device and its evidence. A purge command wipes everything.

## Checks in the build
Security linting, dependency audit, strict type checks, secret scanning, and fuzz-style tests on the parsers.

## Known limits
MAC addresses can be faked, so identity is advisory. Someone on your LAN could send false mDNS or UPnP answers, which is why the UI always shows evidence and confidence. Private MACs are not defeated on purpose.
