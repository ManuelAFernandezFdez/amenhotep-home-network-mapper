"""Single-instance lock so overlapping scheduled scans never run at the same time."""

from __future__ import annotations

import fcntl
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def single_instance(path: Path) -> Iterator[bool]:
    """Yield True when this process got the lock, False when another holder has it."""
    fd = path.open("a+")
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        fd.close()
