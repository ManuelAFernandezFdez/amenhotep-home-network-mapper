"""Presence statistics from sightings: how often and when a device is online."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from amenhotep.store.repo import Repository

MIN_CHECKS_PER_HOUR = 3  # an hour with fewer checks says nothing
ONLINE_RATIO = 0.5  # seen in at least half of that hour's checks => "typically online"


@dataclass
class PresenceInfo:
    seen: int = 0
    total: int = 0
    last_seen: datetime | None = None
    online_hours: list[int] = field(default_factory=list)

    @property
    def ratio(self) -> float:
        return self.seen / self.total if self.total else 0.0

    def summary(self) -> str:
        if not self.total:
            return "no checks yet"
        text = f"seen in {self.seen} of {self.total} checks ({round(self.ratio * 100)}%)"
        hours = hours_label(self.online_hours)
        return f"{text}; typically online {hours}" if hours else text


def summarize(scan_times: list[datetime], seen_times: list[datetime]) -> PresenceInfo:
    """scan_times: every check in the window; seen_times: the checks where the device answered.

    Times should already be in the user's local timezone so hours match the clock on the wall.
    """
    per_hour = Counter(t.hour for t in scan_times)
    seen_hour = Counter(t.hour for t in seen_times)
    hours = [
        h
        for h in range(24)
        if per_hour[h] >= MIN_CHECKS_PER_HOUR and seen_hour[h] / per_hour[h] >= ONLINE_RATIO
    ]
    return PresenceInfo(
        seen=len(seen_times),
        total=len(scan_times),
        last_seen=max(seen_times) if seen_times else None,
        online_hours=hours,
    )


def hours_label(hours: list[int]) -> str:
    """[17,18,19,23] -> '17:00-20:00, 23:00-24:00'."""
    if not hours:
        return ""
    ranges: list[tuple[int, int]] = []
    for h in sorted(set(hours)):
        if ranges and ranges[-1][1] == h:
            ranges[-1] = (ranges[-1][0], h + 1)
        else:
            ranges.append((h, h + 1))
    return ", ".join(f"{a:02d}:00-{b:02d}:00" for a, b in ranges)


def presence_for(repo: Repository, device_uuid: str, days: int = 7) -> PresenceInfo:
    return summarize(repo.scan_times(days), repo.sighting_times(days).get(device_uuid, []))


def presence_all(repo: Repository, days: int = 7) -> dict[str, PresenceInfo]:
    scans = repo.scan_times(days)
    return {uid: summarize(scans, seen) for uid, seen in repo.sighting_times(days).items()}
