"""Amun's mood: satisfied when every device is identified (it has a device type)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from amenhotep.store.repo import DeviceRow


@dataclass(frozen=True)
class Satisfaction:
    known: int
    total: int

    @property
    def satisfied(self) -> bool:
        return self.total > 0 and self.known == self.total

    @property
    def unknown(self) -> int:
        return self.total - self.known

    def message(self) -> str:
        if self.total == 0:
            return "Amun has nothing to judge yet: run a scan."
        if self.satisfied:
            return f"Amun is satisfied: {self.known}/{self.total} devices known."
        return (
            f"Amun is not satisfied: {self.known}/{self.total} devices known "
            f"({self.unknown} still hidden)."
        )


def satisfaction(devices: Iterable[DeviceRow]) -> Satisfaction:
    devs = list(devices)
    return Satisfaction(sum(d.device_type != "unknown" for d in devs), len(devs))
