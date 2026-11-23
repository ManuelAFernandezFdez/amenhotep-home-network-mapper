"""Network helpers: MAC handling and scan-target validation."""

from __future__ import annotations

import ipaddress
import re
import subprocess

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
MIN_PREFIX_V4 = 16  # refuse anything bigger than a /16


class TargetError(ValueError):
    """Raised when a scan target is not acceptable."""


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    m = mac.strip().lower().replace("-", ":")
    return m if _MAC_RE.match(m) else None


def is_random_mac(mac: str) -> bool:
    """Locally-administered bit set => private/randomised address."""
    return bool(int(mac.split(":")[0], 16) & 0b10)


def validate_target(target: str, allow_public: bool = False) -> ipaddress.IPv4Network:
    """Parse a CIDR/IP, restrict it to private IPv4 space and a sane size."""
    try:
        net = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError as exc:
        raise TargetError(f"invalid target {target!r}") from exc
    if not isinstance(net, ipaddress.IPv4Network):
        raise TargetError("only IPv4 targets are supported in this version")
    if net.prefixlen < MIN_PREFIX_V4:
        raise TargetError(f"target too large (/{net.prefixlen}); minimum is /{MIN_PREFIX_V4}")
    if not allow_public and not (net.is_private or net.is_link_local):
        raise TargetError("public address ranges are refused (set allow_public to override)")
    if net.is_loopback or net.is_multicast:
        raise TargetError("loopback/multicast targets are not scannable")
    return net


def local_networks() -> list[ipaddress.IPv4Network]:
    """Private IPv4 networks of local interfaces (from `ip -4 -o addr`)."""
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return parse_ip_addr(out)


def parse_ip_addr(text: str) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for line in text.splitlines():
        m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+/\d+)", line)
        if not m:
            continue
        try:
            net = ipaddress.IPv4Interface(m.group(1)).network
        except ValueError:
            continue
        if net.is_loopback or not (net.is_private or net.is_link_local):
            continue
        if net.prefixlen < MIN_PREFIX_V4:
            continue
        if net not in nets:
            nets.append(net)
    return nets
