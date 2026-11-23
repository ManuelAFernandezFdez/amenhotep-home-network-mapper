"""MAC address -> vendor, from the IEEE OUI registry (bundled seed + optional full list)."""

from __future__ import annotations

import csv
import io
from functools import lru_cache
from importlib import resources
from pathlib import Path

from amenhotep.core.models import cap
from amenhotep.core.paths import data_dir

# MA-L (24-bit), MA-M (28-bit) and MA-S (36-bit) blocks. The IEEE itself owns many MA-L blocks that
# it sub-divides into MA-M/MA-S assignments, so the longest matching prefix wins.
IEEE_REGISTRIES = {
    "oui.csv": "https://standards-oui.ieee.org/oui/oui.csv",
    "mam.csv": "https://standards-oui.ieee.org/oui28/mam.csv",
    "oui36.csv": "https://standards-oui.ieee.org/oui36/oui36.csv",
}
MAX_DOWNLOAD = 12 * 1024 * 1024
PREFIX_LENGTHS = (9, 7, 6)  # hex digits, longest first
_REGISTRY_TAGS = {"MA-L", "MA-M", "MA-S", "CID", "IAB"}
_GENERIC_OWNER = "ieee registration authority"  # says nothing about the real maker


def parse_oui_csv(text: str) -> dict[str, str]:
    """Parse the seed format (`prefix,name`) or an IEEE CSV (`Registry,Assignment,Name,Address`)."""
    table: dict[str, str] = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2:
            continue
        if row[0].strip().upper() in _REGISTRY_TAGS and len(row) >= 3:
            prefix, rest = row[1], row[2:3]  # the address column is not part of the name
        else:
            prefix, rest = row[0], row[1:]
        prefix = prefix.strip().upper()
        if len(prefix) in PREFIX_LENGTHS and all(c in "0123456789ABCDEF" for c in prefix):
            # vendor names may contain unquoted commas in the seed file: re-join the tail
            table[prefix] = cap(", ".join(p.strip() for p in rest if p.strip())) or ""
    return table


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    seed = resources.files("amenhotep.data").joinpath("oui_seed.csv").read_text(encoding="utf-8")
    table = parse_oui_csv(seed)
    for name in IEEE_REGISTRIES:
        full = data_dir() / name
        if full.is_file():
            table.update(parse_oui_csv(full.read_text(encoding="utf-8", errors="replace")))
    return table


def reload() -> None:
    _table.cache_clear()


def lookup(mac: str | None) -> str | None:
    """Vendor for a MAC, using the most specific IEEE block; None if only the IEEE owns it."""
    if not mac:
        return None
    digits = mac.replace(":", "").replace("-", "").upper()
    table = _table()
    for n in PREFIX_LENGTHS:
        name = table.get(digits[:n])
        if name:
            return None if name.lower() == _GENERIC_OWNER else name
    return None


def is_generic_owner(name: str | None) -> bool:
    return (name or "").strip().lower() == _GENERIC_OWNER


def update_from_ieee(dest_dir: Path | None = None) -> int:
    """Download the three registries. Only outbound internet call in the app; user-triggered."""
    import urllib.request

    target_dir = dest_dir or data_dir()
    total = 0
    for name, url in IEEE_REGISTRIES.items():
        req = urllib.request.Request(url, headers={"User-Agent": "amenhotep-oui-update"})
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (fixed https URLs)
            data = resp.read(MAX_DOWNLOAD + 1)
        if len(data) > MAX_DOWNLOAD:
            raise RuntimeError(f"{name} is larger than expected; aborting")
        text = data.decode("utf-8", errors="replace")
        count = len(parse_oui_csv(text))
        if count < (1000 if name == "oui.csv" else 10):
            raise RuntimeError(f"{name} looks invalid; not saving")
        (target_dir / name).write_text(text, encoding="utf-8")
        total += count
    reload()
    return total
