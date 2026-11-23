"""Backend data models. No Qt imports allowed in this package."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

MAX_STR = 256

OS_FAMILIES = (
    "linux",
    "windows",
    "ios",
    "ipados",
    "macos",
    "tvos",
    "android",
    "embedded",
    "unknown",
)


def utcnow() -> datetime:
    return datetime.now(UTC)


def cap(value: str | None, limit: int = MAX_STR) -> str | None:
    """Truncate untrusted strings coming from the LAN."""
    if value is None:
        return None
    value = "".join(ch for ch in value if ch.isprintable())
    return value[:limit]


class Observation(BaseModel):
    """One fact-bundle from one collector about one host. Immutable by convention."""

    source: str
    ts: datetime = Field(default_factory=utcnow)
    ip: str | None = None
    mac: str | None = None
    hostname: str | None = None
    facts: dict[str, Any] = Field(default_factory=dict)

    @field_validator("hostname")
    @classmethod
    def _cap_hostname(cls, v: str | None) -> str | None:
        return cap(v)


# Only these NSE scripts may ever be run: read-only, "safe"-category identification scripts.
# No vuln/brute/exploit/intrusive categories (see SECURITY.md).
ALLOWED_SCRIPTS = frozenset(
    {
        "banner",
        "http-title",
        "http-server-header",
        "ssl-cert",
        "smb-os-discovery",
        "rdp-ntlm-info",
        "nbstat",
        "upnp-info",
    }
)

# Ports where home/IoT devices tend to listen (iOS lockdownd 62078, AirPlay 7000, Cast 8009...).
IOT_PORTS = (
    "21,22,23,53,80,81,111,135,139,443,445,515,548,554,631,1883,1900,3000,3389,3689,5000,5001,"
    "5009,5222,5555,5900,6668,7000,7100,8000,8008,8009,8080,8081,8123,8443,8883,9000,9100,"
    "9999,10001,49152,49153,49154,62078"
)


class ScanProfile(BaseModel):
    name: str
    nmap_args: list[str]
    timeout_s: int
    ports: str | None = None
    scripts: list[str] = Field(default_factory=list)
    os_detect: bool = False  # adds -O when nmap has raw-socket privileges
    service_scan: bool = False

    @field_validator("scripts")
    @classmethod
    def _only_allowed(cls, v: list[str]) -> list[str]:
        bad = set(v) - ALLOWED_SCRIPTS
        if bad:
            raise ValueError(f"script(s) not allowed: {sorted(bad)}")
        return v


_SCRIPTS = sorted(ALLOWED_SCRIPTS)

PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(name="quick", nmap_args=["-sn", "-n", "-T4"], timeout_s=180),
    "standard": ScanProfile(
        name="standard",
        nmap_args=[
            "-sV",
            "--version-intensity",
            "5",
            "-T4",
            "--max-retries",
            "1",
            "--host-timeout",
            "120s",
        ],
        ports=IOT_PORTS,
        scripts=_SCRIPTS,
        os_detect=True,
        service_scan=True,
        timeout_s=1800,
    ),
    "deep": ScanProfile(
        name="deep",
        nmap_args=[
            "-sV",
            "--version-intensity",
            "7",
            "-T4",
            "--max-retries",
            "2",
            "--host-timeout",
            "300s",
        ],
        ports=f"1-1024,{IOT_PORTS},1025-10000",
        scripts=_SCRIPTS,
        os_detect=True,
        service_scan=True,
        timeout_s=3600,
    ),
}
