"""nmap collector: runs nmap as a subprocess (no shell) and parses its XML output.

Fingerprinting inputs gathered (all read-only):
- OS detection (-O) with full osmatch/osclass/CPE data (needs raw sockets, see `raw_capable`)
- service/version detection (-sV): product, version, extrainfo, ostype, devicetype, CPEs
- allow-listed safe NSE scripts (see core.models.ALLOWED_SCRIPTS): http-title, ssl-cert,
  smb-os-discovery, rdp-ntlm-info, nbstat, ...
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable, Iterable
from typing import Any
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as SafeET

from amenhotep.core.models import ALLOWED_SCRIPTS, PROFILES, Observation, ScanProfile, cap
from amenhotep.core.netutil import normalize_mac

MAX_OUTPUT = 20 * 1024 * 1024
MAX_PORTS_PER_HOST = 1024
MAX_SCRIPTS_PER_HOST = 24
SETCAP_HINT = 'sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"'

Runner = Callable[[list[str], int], tuple[int, str, str]]


class NmapError(RuntimeError):
    pass


class ScanCancelled(Exception):
    """Raised when the user cancels a running scan."""


class ParseError(ValueError):
    pass


def default_runner(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    out = proc.stdout[:MAX_OUTPUT].decode("utf-8", errors="replace")
    err = proc.stderr[:65536].decode("utf-8", errors="replace")
    return proc.returncode, out, err


# ---- mapping tables ---------------------------------------------------------------------------
OSFAMILY_MAP = {
    "linux": "linux",
    "windows": "windows",
    "ios": "ios",
    "ipados": "ipados",
    "mac os x": "macos",
    "macos": "macos",
    "os x": "macos",
    "tvos": "tvos",
    "android": "android",
    "freertos": "embedded",
    "vxworks": "embedded",
    "embedded": "embedded",
    "ecos": "embedded",
}

CPE_OS_MAP = [
    ("cpe:/o:microsoft:windows", "windows"),
    ("cpe:/o:linux:linux_kernel", "linux"),
    ("cpe:/o:google:android", "android"),
    ("cpe:/o:apple:iphone_os", "ios"),
    ("cpe:/o:apple:ipados", "ipados"),
    ("cpe:/o:apple:tvos", "tvos"),
    ("cpe:/o:apple:mac_os_x", "macos"),
    ("cpe:/o:apple:macos", "macos"),
    ("cpe:/o:freertos", "embedded"),
    ("cpe:/o:windriver:vxworks", "embedded"),
]


def os_family_from_osclass(osfamily: str | None, vendor: str | None = None) -> str:
    return OSFAMILY_MAP.get((osfamily or "").lower(), "unknown")


def os_family_from_cpes(cpes: Iterable[str]) -> str:
    for cpe in cpes:
        for prefix, family in CPE_OS_MAP:
            if cpe.lower().startswith(prefix):
                return family
    return "unknown"


# ---- XML helpers ------------------------------------------------------------------------------
def _int(value: str | None) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


def _flatten(el: Element, prefix: str = "") -> dict[str, str]:
    """Flatten NSE <elem>/<table> structures into {"subject.commonName": "..."}."""
    out: dict[str, str] = {}
    for child in el:
        key = child.get("key")
        path = f"{prefix}.{key}" if prefix and key else (key or prefix)
        if child.tag == "elem" and path:
            out[path] = cap((child.text or "").strip(), 200) or ""
        elif child.tag == "table":
            out.update(_flatten(child, path))
    return out


def _script_data(scripts: list[Element]) -> dict[str, Any]:
    """Turn NSE results into compact, classifier-friendly facts."""
    facts: dict[str, Any] = {}
    raw: dict[str, str] = {}
    for sc in scripts[:MAX_SCRIPTS_PER_HOST]:
        sid = sc.get("id", "")
        if sid not in ALLOWED_SCRIPTS:
            continue  # ignore anything we did not ask for (e.g. fingerprint-strings)
        output = cap((sc.get("output") or "").replace("\n", " "), 400) or ""
        raw.setdefault(sid, output)
        flat = _flatten(sc)
        if sid == "http-title" and output and "doesn't have a title" not in output:
            facts.setdefault("http_titles", []).append(flat.get("title") or output)
        elif sid == "http-server-header" and output:
            facts.setdefault("http_servers", []).append(output)
        elif sid == "ssl-cert":
            cert = {
                k: v
                for k, v in {
                    "cn": flat.get("subject.commonName"),
                    "org": flat.get("subject.organizationName"),
                    "issuer_org": flat.get("issuer.organizationName"),
                }.items()
                if v
            }
            if cert:
                facts["ssl_cert"] = cert
        elif sid == "smb-os-discovery":
            smb = {
                k: flat[k] for k in ("os", "server", "fqdn", "workgroup", "lanmanager") if k in flat
            }
            if smb:
                facts["smb"] = smb
        elif sid == "rdp-ntlm-info":
            rdp = {
                k: flat[k]
                for k in ("Product_Version", "NetBIOS_Computer_Name", "DNS_Computer_Name")
                if k in flat
            }
            if rdp:
                facts["rdp"] = rdp
        elif sid == "nbstat":
            m = re.search(r"NetBIOS name:\s*([^,\s]+)", output)
            if m:
                facts["nbstat_name"] = cap(m.group(1), 64)
        elif sid == "banner" and output:
            facts.setdefault("banners", []).append(output)
    if raw:
        facts["scripts"] = raw
    return facts


def parse_nmap_xml(xml_text: str) -> list[Observation]:
    try:
        root = SafeET.fromstring(xml_text)
    except Exception as exc:  # defusedxml raises several types (ParseError, EntitiesForbidden...)
        raise ParseError(f"invalid nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ParseError("not an nmap XML document")
    return [obs for host in root.findall("host") if (obs := _parse_host(host)) is not None]


def _parse_ports(host: Element, facts: dict[str, Any], scripts: list[Element]) -> None:
    ports: list[dict[str, Any]] = []
    ports_el = host.find("ports")
    if ports_el is None:
        return
    ostypes: set[str] = set()
    devicetypes: set[str] = set()
    for port in ports_el.findall("port")[:MAX_PORTS_PER_HOST]:
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        scripts.extend(port.findall("script"))
        svc = port.find("service")
        entry: dict[str, Any] = {
            "port": _int(port.get("portid")),
            "proto": cap(port.get("protocol"), 8),
        }
        if svc is not None:
            entry.update(
                service=cap(svc.get("name")),
                product=cap(svc.get("product")),
                version=cap(svc.get("version")),
                extrainfo=cap(svc.get("extrainfo")),
                tunnel=cap(svc.get("tunnel"), 8),
            )
            if svc.get("ostype"):
                ostypes.add(cap(svc.get("ostype"), 40) or "")
                entry["ostype"] = cap(svc.get("ostype"), 40)
            if svc.get("devicetype"):
                devicetypes.add(cap(svc.get("devicetype"), 40) or "")
                entry["devicetype"] = cap(svc.get("devicetype"), 40)
            cpes = [cap(c.text, 120) or "" for c in svc.findall("cpe")][:6]
            if cpes:
                entry["cpes"] = cpes
        ports.append({k: v for k, v in entry.items() if v not in (None, "")})
    if ports:
        facts["ports"] = ports
    if ostypes:
        facts["service_ostypes"] = sorted(ostypes)
    if devicetypes:
        facts["service_devicetypes"] = sorted(devicetypes)


def _parse_os(host: Element, facts: dict[str, Any]) -> None:
    os_el = host.find("os")
    if os_el is None:
        return
    matches: list[dict[str, Any]] = []
    for m in os_el.findall("osmatch")[:5]:
        classes = []
        for c in m.findall("osclass")[:5]:
            classes.append(
                {
                    "type": cap(c.get("type")),
                    "vendor": cap(c.get("vendor")),
                    "osfamily": cap(c.get("osfamily")),
                    "osgen": cap(c.get("osgen")),
                    "accuracy": _int(c.get("accuracy")),
                    "cpes": [cap(x.text, 120) or "" for x in c.findall("cpe")][:4],
                }
            )
        matches.append(
            {"name": cap(m.get("name")), "accuracy": _int(m.get("accuracy")), "classes": classes}
        )
    if not matches:
        return
    facts["os_matches"] = matches
    best = max(matches, key=lambda m: m["accuracy"])
    facts["os_detail"] = best["name"]
    apple_tv = "apple tv" in (best["name"] or "").lower()
    facts["os_accuracy"] = best["accuracy"]
    if best["classes"]:
        top = best["classes"][0]
        family = os_family_from_osclass(top["osfamily"])
        if family == "unknown":
            family = os_family_from_cpes(c for cl in best["classes"] for c in cl["cpes"])
        if apple_tv:
            family = "tvos"  # nmap files tvOS devices under osfamily "iOS"
        if family != "unknown":
            facts["os_family"] = family
        facts["os_type"] = top["type"]
        facts["os_vendor"] = top["vendor"]


def _parse_host(host: Element) -> Observation | None:
    status = host.find("status")
    if status is None or status.get("state") != "up":
        return None
    ip = mac = None
    mac_vendor = None
    for addr in host.findall("address"):
        kind = addr.get("addrtype")
        if kind == "ipv4":
            try:
                ip = str(ipaddress.IPv4Address(addr.get("addr", "")))
            except ValueError:
                continue
        elif kind == "mac":
            mac = normalize_mac(addr.get("addr"))
            mac_vendor = cap(addr.get("vendor"))
    if ip is None:
        return None

    hostname = None
    names = host.find("hostnames")
    if names is not None:
        first = names.find("hostname")
        if first is not None:
            hostname = cap(first.get("name"))

    facts: dict[str, Any] = {}
    if mac_vendor:
        facts["nmap_mac_vendor"] = mac_vendor

    scripts: list[Element] = []
    _parse_ports(host, facts, scripts)
    hs = host.find("hostscript")
    if hs is not None:
        scripts.extend(hs.findall("script"))
    facts.update(_script_data(scripts))
    _parse_os(host, facts)

    # Windows/NetBIOS names are a better hostname than nothing
    if hostname is None:
        hostname = (
            facts.get("nbstat_name")
            or facts.get("smb", {}).get("server")
            or facts.get("rdp", {}).get("NetBIOS_Computer_Name")
        )
    return Observation(source="nmap", ip=ip, mac=mac, hostname=hostname, facts=facts)


# ---- collector --------------------------------------------------------------------------------
def probe_raw_capable(nmap_path: str) -> bool:
    """True if nmap can use raw sockets (root, or setcap + --privileged)."""
    try:
        proc = subprocess.run(
            [nmap_path, "--privileged", "-sS", "-p", "1", "-n", "127.0.0.1", "-oX", "-"],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


class NmapCollector:
    name = "nmap"

    def __init__(
        self,
        runner: Runner | None = None,
        nmap_path: str | None = None,
        raw_capable: bool | None = None,
    ) -> None:
        """`runner` is injectable for tests. With an injected runner we never probe the system
        (raw_capable defaults to False); with the real runner it is probed lazily."""
        self.cancel = threading.Event()
        self._probe = raw_capable is None and runner is None
        self._raw = bool(raw_capable)
        self.runner: Runner = runner or self._cancellable_run
        self.nmap_path = nmap_path or shutil.which("nmap")
        self.warnings: list[str] = []

    @property
    def raw_capable(self) -> bool:
        if self._probe and self.nmap_path:
            self._raw = probe_raw_capable(self.nmap_path)
            self._probe = False
        return self._raw

    def _cancellable_run(self, cmd: list[str], timeout: int) -> tuple[int, str, str]:
        """Like default_runner but terminates nmap promptly when `self.cancel` is set."""
        proc = subprocess.Popen(  # fixed argv, no shell
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        deadline = time.monotonic() + timeout
        while True:
            try:
                out, err = proc.communicate(timeout=0.3)
                break
            except subprocess.TimeoutExpired:
                if self.cancel.is_set():
                    proc.terminate()
                    proc.communicate()
                    raise ScanCancelled from None
                if time.monotonic() > deadline:
                    proc.kill()
                    proc.communicate()
                    raise NmapError(f"nmap timed out after {timeout}s") from None
        return (
            proc.returncode,
            out[:MAX_OUTPUT].decode("utf-8", errors="replace"),
            err[:65536].decode("utf-8", errors="replace"),
        )

    def available(self) -> bool:
        return self.nmap_path is not None

    def build_command(
        self, targets: list[str], profile: ScanProfile, *, assume_up: bool = False
    ) -> list[str]:
        if not self.nmap_path:
            raise NmapError("nmap not found; install it (see TOOLS.md)")
        raw = self.raw_capable
        cmd = [self.nmap_path]
        if raw:
            cmd.append("--privileged")  # needed when raw sockets come from setcap, not uid 0
        cmd += profile.nmap_args
        if assume_up:
            cmd.append("-Pn")  # targets already known to be alive (ARP table)
        if profile.ports:
            cmd += ["-p", profile.ports]
        if profile.scripts:
            cmd += ["--script", ",".join(profile.scripts), "--script-timeout", "10s"]
        if profile.os_detect:
            if raw:
                cmd += ["-O", "--osscan-guess", "--osscan-limit", "--max-os-tries", "2"]
            else:
                msg = (
                    "OS detection skipped: nmap has no raw-socket privileges. "
                    f"Enable it once with: {SETCAP_HINT}"
                )
                if msg not in self.warnings:
                    self.warnings.append(msg)
        return [*cmd, "-oX", "-", *targets]

    def _run(self, cmd: list[str], timeout: int) -> list[Observation]:
        code, out, err = self.runner(cmd, timeout)
        if code != 0 and "-O" in cmd and ("root" in err.lower() or "privileg" in err.lower()):
            self.warnings.append("OS detection needs raw-socket privileges; retried without -O")
            cmd = [c for c in cmd if c not in ("-O", "--osscan-guess", "--osscan-limit")]
            if "--max-os-tries" in cmd:
                i = cmd.index("--max-os-tries")
                del cmd[i : i + 2]
            code, out, err = self.runner(cmd, timeout)
        if code != 0 and not out.strip():
            raise NmapError(f"nmap failed ({code}): {err.strip()[:300]}")
        return parse_nmap_xml(out)

    def collect(self, target: ipaddress.IPv4Network, profile_name: str) -> list[Observation]:
        """Scan a whole network (host discovery + profile)."""
        profile = PROFILES[profile_name]
        return self._run(self.build_command([str(target)], profile), profile.timeout_s)

    def collect_hosts(self, ips: list[str], profile_name: str) -> list[Observation]:
        """Scan specific, already-discovered hosts with -Pn (phones that ignore probes included)."""
        if not ips:
            return []
        profile = PROFILES[profile_name]
        valid = [str(ipaddress.IPv4Address(ip)) for ip in ips]
        cmd = self.build_command(valid, profile, assume_up=True)
        return self._run(cmd, profile.timeout_s)
