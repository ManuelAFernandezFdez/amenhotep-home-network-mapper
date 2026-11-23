# CLAUDE.md — Amenhotep

Home network discovery + mapping tool. Qt (PySide6) GUI, Python backend, SQLite, 3D house view.
Read first: `SPECIFICATION.md` → `DESIGN.md`. Tools are listed in `TOOLS.md`; rules in `SECURITY.md`; test approach in `TESTING_STRATEGY.md`.

## Layout

```
src/amenhotep/{core,collectors,services,store,data,gui}/
tests/ (fixtures in tests/fixtures)
model/ schema.sql · house.schema.json · house.example.json
```

## Commands

```bash
pip install -e ".[dev]"
pytest -q                          # unit + component
QT_QPA_PLATFORM=offscreen pytest -q -m gui
pytest -m lab                      # needs root, netns; opt-in
ruff check . && ruff format --check . && mypy src/amenhotep
bandit -r src && pip-audit
sqlite3 :memory: < model/schema.sql  # schema sanity
```

## Architecture rules

- Backend (`core`, `collectors`, `services`, `store`) **must not import Qt**. GUI talks to services; long work runs in workers and reports via signals.
- Collectors only emit `Observation`s; they never write the DB. Identity → classifier → repository is the only write path.
- **Manual edits win**: respect `device.locked_fields`; scans never overwrite them.
- Device identity is UUID, not IP or MAC. Randomised MACs are flagged, never auto-merged.
- `house.json` is the source of truth for geometry; the DB is the source for devices. Placements reference device UUIDs. Keep the format `amenhotep-house/1`; changing it needs a migration and a schema bump.
- Z is up in files (metres); convert to Qt's Y-up only in the renderer.

## Security musts (details in SECURITY.md)

- Never `shell=True`; subprocess args as list; validate targets with `ipaddress`; private ranges only by default.
- XML only through `defusedxml`; cap string lengths; parameterised SQL only.
- Secrets only in `keyring`, never in DB/logs/exports.
- Qt: plain text for LAN-derived strings.
- No vuln/brute-force nmap scripts. Do not add telemetry or cloud calls.

## Style

- Python 3.12, type hints everywhere in backend (`mypy --strict`), pydantic v2 models, `ruff` format.
- Small modules, pure functions for parsing/classification; table-driven tests.
- Classification rules go in `data/os_rules.yaml`, not code, where possible.
- New collector = new module + fixture + test; register in `collectors/__init__.py`.

## Testing

Every parser and classifier change needs a fixture. Misclassifications found on the real network become anonymised fixtures (`tools/anonymise_fixture.py`). Never commit real MACs/IPs/hostnames.

## Don't

- Don't scan from tests against real networks.
- Don't write to the user's real `house.json`/DB in tests (use `tmp_path`).
- Don't block the UI thread.
- Don't assume HomeKit room names are available; they are not on the wire.

## Open questions

- Answered: switches are TP-Link **unmanaged** (1×8-port, 2×4-port; exact models pending) → topology links are manual-first; no SNMP/LLDP for them.
- Answered: router is a Ziggo modem-router (Compal/Harris class, ~6–8 yrs old; exact model pending) → no SNMP/TR-064; optional client-list importer only.
- Answered: mesh repeaters are Ziggo-supplied, 5+ yrs old and **wired** (Ethernet backhaul) → each is a wired child of a switch/router plus an AP; no API assumed; manual linking, router client list as optional hint. Router has a web page → importer feasible, inspect it in M6. Exact models pending; check whether each repeater shows up on the LAN with its own IP.
- Confirm "2rd bedroom" = third bedroom (assumed).
