# Amenhotep — Testing Strategy (short version)

Full version: [TESTING_STRATEGY.md](TESTING_STRATEGY.md)

## The idea
Most of the code is pure logic: read data, work out what a device is, save it. So almost everything is tested without a network, using **recorded, anonymised samples** (fixtures). Only a few optional tests touch a real network.

## Test levels
| Level | What | Share |
|-------|------|------:|
| Unit | Parsers, vendor lookup, MAC helpers, classification rules, identity, house file, database | ~65% |
| Component | Collectors with fakes, a whole scan into a temporary database | ~20% |
| GUI | Table models, filters, edit flows, scan progress (headless, no pixels) | ~10% |
| Lab (opt-in) | Real nmap against a fake network made of containers or namespaces; needs root | ~5% |
| Manual | A checklist on your real home network before each release | per release |

## Fixtures are the key asset
Samples of nmap output, mDNS records, UPnP descriptions and house files, all anonymised: MACs become documentation prefixes and IPs go to a reserved test range, so no personal data lands in the project. Every wrong guess found on the real network becomes a new fixture.

## What gets tested
- **Bad input:** truncated or hostile XML, invalid text, huge banners. Parsers must fail cleanly and respect length limits.
- **Classification:** a table of "these facts should give this type and OS", including the awkward cases (iPhone vs Mac, randomised MACs, Windows that ignores ping).
- **Identity:** IP changes keep the device; Wi-Fi and wired merge only on request; MAC rotation is a suggestion, never automatic.
- **Your edits win:** after any run of scans, locked fields are unchanged.
- **Location, presence and areas:** roaming vs fixed, the bedside-clock phone, online/offline tracking, pruning.
- **Topology and house file:** no cycles, one uplink per device, valid shapes, saving and reloading gives identical files, writes survive failures.
- **Security:** a malicious target string, a public address, a forbidden nmap script, secrets never in the database or logs, spreadsheet-formula injection.

## Quality gates
Backend coverage at least 85% (classifier and identity 95%), GUI at least 60%, zero lint and strict type errors, no high-severity security findings, and speed targets (500 devices classified in under a second).

## Automation
Lint, then unit and component tests on Python 3.12 and 3.13, then GUI tests, then security checks. Lab and mutation tests run nightly.

## Manual checklist (each release)
The scan finds everything the router lists; HomeKit count matches the Home app; both repeaters and all switches show their children; the clock phone keeps its room; names and rooms survive an IP change; 3D drag and hand-edited house file both work; a broken house file gives a clear error; no unexpected traffic leaves the network.
