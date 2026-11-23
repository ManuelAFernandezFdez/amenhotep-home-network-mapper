"""SQLite connection and migrations (PRAGMA user_version)."""

from __future__ import annotations

import os
import re
import sqlite3
from importlib import resources
from pathlib import Path

_MIGRATION_RE = re.compile(r"^(\d{3})_.*\.sql$")


def _migrations() -> list[tuple[int, str]]:
    found = []
    for entry in resources.files("amenhotep.store").joinpath("migrations").iterdir():
        m = _MIGRATION_RE.match(entry.name)
        if m:
            found.append((int(m.group(1)), entry.read_text(encoding="utf-8")))
    return sorted(found)


def connect(path: Path | str) -> sqlite3.Connection:
    is_memory = str(path) == ":memory:"
    if not is_memory:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        new = not p.exists()
        if new:
            fd = os.open(p, os.O_CREAT | os.O_WRONLY, 0o600)  # private from creation
            os.close(fd)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")  # GUI reader + scan-worker writer
    if not is_memory:
        conn.execute("PRAGMA journal_mode = WAL")
    migrate(conn)
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    for version, sql in _migrations():
        if version > current:
            conn.executescript(sql)
            conn.execute(f"PRAGMA user_version = {int(version)}")
            conn.commit()
