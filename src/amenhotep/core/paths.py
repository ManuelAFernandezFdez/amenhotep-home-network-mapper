"""Filesystem locations (XDG), with environment overrides for tests."""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    base = os.environ.get("AMENHOTEP_HOME")
    if base:
        p = Path(base)
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        p = root / "amenhotep"
        legacy = root / "homemap"  # data from before the tool was renamed stays where it is
        if not p.exists() and legacy.is_dir():
            p = legacy
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


def db_path() -> Path:
    override = os.environ.get("AMENHOTEP_DB")
    if override:
        return Path(override)
    d = data_dir()
    legacy = d / "homemap.db"
    return legacy if legacy.exists() and not (d / "amenhotep.db").exists() else d / "amenhotep.db"
