"""Unicast mDNS reverse lookup: ask each host directly "what is your name?".

Many devices (Macs, iPhones, printers) answer a PTR query sent straight to UDP 5353 even when they
were not seen by the multicast browse. It is the same query ``avahi-resolve-address`` sends.
Packets are tiny, bounded and parsed defensively; the answer is untrusted LAN data.
"""

from __future__ import annotations

import ipaddress
import os
import select
import socket
import struct
import time

from amenhotep.core.models import Observation, cap

MDNS_PORT = 5353
MAX_PACKET = 1500
MAX_LABELS = 32
QTYPE_PTR = 12


def build_query(ip: str) -> bytes:
    """DNS query for the reverse name of an IPv4 address, with the unicast-response bit set."""
    addr = ipaddress.IPv4Address(ip)
    labels = [*reversed(str(addr).split(".")), "in-addr", "arpa"]
    qname = b"".join(bytes([len(x)]) + x.encode() for x in labels) + b"\x00"
    header = struct.pack("!HHHHHH", int.from_bytes(os.urandom(2), "big"), 0, 1, 0, 0, 0)
    return header + qname + struct.pack("!HH", QTYPE_PTR, 0x8001)


def _read_name(data: bytes, pos: int) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name; returns (name, position after it in the record)."""
    labels: list[str] = []
    end = -1
    jumps = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated name")
        n = data[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:  # compression pointer
            if pos + 1 >= len(data):
                raise ValueError("truncated pointer")
            if end < 0:
                end = pos + 2
            pos = ((n & 0x3F) << 8) | data[pos + 1]
            jumps += 1
            if jumps > MAX_LABELS:
                raise ValueError("pointer loop")
            continue
        if n > 63 or pos + 1 + n > len(data) or len(labels) >= MAX_LABELS:
            raise ValueError("bad label")
        labels.append(data[pos + 1 : pos + 1 + n].decode("utf-8", "replace"))
        pos += 1 + n
    return ".".join(labels), (end if end >= 0 else pos)


def parse_ptr_response(data: bytes) -> str | None:
    """First PTR target in a response, or None. Never raises on malformed input."""
    try:
        if len(data) < 12 or len(data) > MAX_PACKET:
            return None
        _id, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
        if not flags & 0x8000:  # not a response
            return None
        pos = 12
        for _ in range(min(qd, 4)):
            _, pos = _read_name(data, pos)
            pos += 4
        for _ in range(min(an, 16)):
            _, pos = _read_name(data, pos)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[pos : pos + 10])
            pos += 10
            if rtype == QTYPE_PTR:
                name, _ = _read_name(data, pos)
                return name
            pos += rdlen
    except (ValueError, struct.error):
        return None
    return None


def clean_hostname(name: str) -> str | None:
    name = name.removesuffix(".").removesuffix(".local")
    return cap(name, 128) or None


class MdnsReverseCollector:
    name = "mdns-reverse"

    def __init__(self, timeout_s: float = 2.0) -> None:
        self.timeout_s = timeout_s

    def collect_hosts(self, ips: list[str]) -> list[Observation]:
        valid: list[str] = []
        for ip in ips:
            try:
                a = ipaddress.IPv4Address(ip)
            except ValueError:
                continue
            if a.is_private:  # never send these probes outside the LAN
                valid.append(ip)
        if not valid:
            return []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        found: dict[str, str] = {}
        try:
            for ip in valid:
                try:
                    sock.sendto(build_query(ip), (ip, MDNS_PORT))
                except OSError:
                    continue
            deadline = time.monotonic() + self.timeout_s
            while time.monotonic() < deadline and len(found) < len(valid):
                ready, _, _ = select.select([sock], [], [], max(0.0, deadline - time.monotonic()))
                if not ready:
                    break
                try:
                    data, (src, _port) = sock.recvfrom(MAX_PACKET)
                except OSError:
                    continue
                name = parse_ptr_response(data)
                if src in valid and name:  # only accept answers from the host we asked
                    host = clean_hostname(name)
                    if host:
                        found[src] = host
        finally:
            sock.close()
        return [Observation(source="mdns-reverse", ip=ip, hostname=h) for ip, h in found.items()]
