"""Evidence-based classifier (pure functions, no DB, no Qt). See DESIGN §3.

Each source contributes Evidence(field, value, confidence, source, detail). The caller stores
all evidence and the highest-confidence value per field wins; manual edits lock a field.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

import yaml

from amenhotep.collectors.nmap import os_family_from_cpes
from amenhotep.core.models import OS_FAMILIES
from amenhotep.core.paths import data_dir

FIELDS = ("os_family", "device_type", "vendor", "model")  # settable by rules
EVIDENCE_COLUMNS = (*FIELDS, "os_detail", "hardware_notes")  # stored on the device row
DEVICE_TYPES = {
    "router",
    "switch",
    "access-point",
    "mesh-node",
    "network-device",
    "computer",
    "laptop",
    "phone",
    "tablet",
    "tv",
    "media-player",
    "speaker",
    "printer",
    "nas",
    "camera",
    "iot-sensor",
    "smart-plug",
    "smart-light",
    "smart-lock",
    "smart-appliance",
    "hub",
    "game-console",
    "other",
    "unknown",
}

# nmap osclass/service "devicetype" -> Amenhotep device_type
NMAP_TYPES = {
    "general purpose": "computer",
    "router": "router",
    "broadband router": "router",
    "firewall": "router",
    "switch": "switch",
    "wap": "access-point",
    "printer": "printer",
    "print server": "printer",
    "media device": "media-player",
    "phone": "phone",
    "voip phone": "phone",
    "pda": "phone",
    "storage-misc": "nas",
    "webcam": "camera",
    "game console": "game-console",
    "bridge": "network-device",
    "hub": "network-device",
    "load balancer": "network-device",
    "remote management": "network-device",
    "voip adapter": "network-device",
    "telecom-misc": "network-device",
    "pbx": "network-device",
    "power-device": "smart-appliance",
}
# nmap hardware-class guesses are only trusted as a *model* for these device classes
MODEL_FROM_OS_TYPES = {
    "router",
    "switch",
    "wap",
    "printer",
    "webcam",
    "storage-misc",
    "media device",
}
SERVICE_OSTYPES = {"windows": "windows", "linux": "linux", "android": "android"}
GENERIC_ORGS = re.compile(
    r"^(internet widgits|unspecified|somecompany|someorganization|default company|none|localhost)",
    re.IGNORECASE,
)
_MODEL_SUFFIX = re.compile(
    r"\s+(printer\s+)?(http|web)\s+(config|server|interface|admin)\w*$", re.I
)

APPLE_MODELS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"^iPhone\d+,\d+"), "ios", "phone"),
    (re.compile(r"^iPad\d+,\d+"), "ipados", "tablet"),
    (re.compile(r"^(Mac\w*|MacBook\w*|iMac\w*|Macmini\w*|MacPro\w*)\d*,\d+"), "macos", "computer"),
    (re.compile(r"^AppleTV\d+,\d+"), "tvos", "media-player"),
    (re.compile(r"^(AudioAccessory|HomePod)\w*"), "embedded", "speaker"),
]


@dataclass(frozen=True)
class Evidence:
    field: str
    value: str
    confidence: float
    source: str
    detail: str | None = None


_MODEL_TYPES = [
    (r"^\s*iphone", "phone"),
    (r"^\s*ipad", "tablet"),
    (r"^\s*(macbook|imac|mac ?mini|mac ?studio|mac ?pro|mac\d)", "computer"),
    (r"^\s*apple ?tv", "media-player"),
    (r"^\s*(homepod|audioaccessory)", "speaker"),
]


def type_from_model(model: str | None) -> str | None:
    """Device type implied by a hardware model name (also when the user typed the model)."""
    for pattern, dtype in _MODEL_TYPES:
        if model and re.search(pattern, model, re.IGNORECASE):
            return dtype
    return None


@lru_cache(maxsize=1)
def hap_categories() -> dict[int, tuple[str, str]]:
    raw = json.loads(
        resources.files("amenhotep.data").joinpath("hap_categories.json").read_text("utf-8")
    )
    return {int(k): (v[0], v[1]) for k, v in raw.items()}


@lru_cache(maxsize=1)
def load_rules() -> list[dict[str, Any]]:
    texts = [resources.files("amenhotep.data").joinpath("os_rules.yaml").read_text("utf-8")]
    user = data_dir() / "os_rules.yaml"
    if user.is_file():
        texts.append(user.read_text("utf-8"))
    rules: list[dict[str, Any]] = []
    for text in texts:
        doc = yaml.safe_load(text) or {}
        for rule in doc.get("rules", []):
            if _valid_rule(rule):
                rules.append(rule)
    return rules


def reload_rules() -> None:
    load_rules.cache_clear()


def _valid_rule(rule: Any) -> bool:
    if not isinstance(rule, dict) or not {"id", "when", "set", "weight"} <= rule.keys():
        return False
    if not isinstance(rule["set"], dict) or not isinstance(rule["when"], dict):
        return False
    if not 0 <= float(rule["weight"]) <= 1:
        return False
    for key, value in rule["set"].items():
        if key not in FIELDS:
            return False
        if key == "os_family" and value not in OS_FAMILIES:
            return False
        if key == "device_type" and value not in DEVICE_TYPES:
            return False
    return True


def _matches(when: dict[str, Any], ctx: dict[str, Any]) -> bool:
    for key, cond in when.items():
        if key == "ports_all":
            if not set(cond) <= ctx["ports"]:
                return False
        elif key == "ports_any":
            if not set(cond) & ctx["ports"]:
                return False
        elif key == "mdns_any":
            if not set(cond) & ctx["mdns"]:
                return False
        elif key in ("hostname_re", "vendor_re", "banner_re", "upnp_re", "web_re"):
            target = ctx[key.removesuffix("_re")]
            if not target or not re.search(cond, target, re.IGNORECASE):
                return False
        else:
            return False  # unknown condition: never match
    return True


def _nmap_evidence(facts: dict[str, Any]) -> list[Evidence]:
    """Evidence from nmap: OS match/class/CPE, services and safe scripts (see collectors.nmap)."""
    ev: list[Evidence] = []
    acc = int(facts.get("os_accuracy", 0))
    ports = facts.get("ports", [])

    if acc >= 70:  # -O results (needs raw sockets); confidence scales with nmap's accuracy
        if facts.get("os_family"):
            ev.append(
                Evidence(
                    "os_family",
                    facts["os_family"],
                    acc / 100 * 0.85,
                    "nmap-os",
                    f"nmap OS match accuracy {acc}%",
                )
            )
        if facts.get("os_detail"):
            ev.append(
                Evidence(
                    "os_detail", facts["os_detail"], acc / 100 * 0.85, "nmap-os", f"accuracy {acc}%"
                )
            )
        os_type = str(facts.get("os_type") or "").lower()
        mapped = NMAP_TYPES.get(os_type)
        if mapped:
            generic = os_type == "general purpose"
            ev.append(
                Evidence(
                    "device_type",
                    mapped,
                    acc / 100 * (0.4 if generic else 0.7),
                    "nmap-os",
                    f"nmap device class: {os_type}",
                )
            )
            if os_type in MODEL_FROM_OS_TYPES and acc >= 90 and facts.get("os_detail"):
                ev.append(
                    Evidence(
                        "model", facts["os_detail"], 0.55, "nmap-os", "hardware-class OS match"
                    )
                )
                if facts.get("os_vendor"):
                    ev.append(Evidence("vendor", facts["os_vendor"], 0.5, "nmap-os"))

    # OS from CPEs attached to services (works without -O)
    cpes = [c for p in ports for c in p.get("cpes", [])]
    fam = os_family_from_cpes(cpes)
    if fam != "unknown":
        ev.append(Evidence("os_family", fam, 0.65, "nmap-cpe", "service CPE"))
    for ostype in facts.get("service_ostypes", []):
        if ostype.lower() in SERVICE_OSTYPES:
            ev.append(
                Evidence(
                    "os_family",
                    SERVICE_OSTYPES[ostype.lower()],
                    0.55,
                    "nmap-svc",
                    f"service reports OS type {ostype}",
                )
            )

    # hardware class + model advertised by services (printers, cameras, routers ...)
    for p in ports:
        dev = str(p.get("devicetype") or "").lower()
        if dev in NMAP_TYPES:
            ev.append(
                Evidence(
                    "device_type",
                    NMAP_TYPES[dev],
                    0.7,
                    "nmap-svc",
                    f"port {p['port']} service devicetype {dev}",
                )
            )
            if p.get("product"):
                model = _MODEL_SUFFIX.sub("", p["product"]).strip()
                if model:
                    ev.append(Evidence("model", model[:80], 0.6, "nmap-svc", f"port {p['port']}"))
            break

    # Windows via SMB / RDP
    smb = facts.get("smb") or {}
    if smb.get("os"):
        low = smb["os"].lower()
        fam = (
            "windows"
            if "windows" in low
            else "linux"
            if re.search(r"samba|unix|linux", low)
            else ""
        )
        if fam:
            ev.append(Evidence("os_family", fam, 0.9, "smb", "smb-os-discovery"))
        ev.append(Evidence("os_detail", smb["os"][:80], 0.9, "smb", "smb-os-discovery"))
    rdp = facts.get("rdp") or {}
    if rdp:
        ev.append(Evidence("os_family", "windows", 0.9, "rdp", "RDP NTLM info"))
        if rdp.get("Product_Version"):
            ev.append(Evidence("os_detail", f"Windows NT {rdp['Product_Version']}", 0.8, "rdp"))

    # TLS certificate organisation is a good vendor hint on embedded devices
    org = (facts.get("ssl_cert") or {}).get("org")
    if org and not GENERIC_ORGS.match(org):
        ev.append(Evidence("vendor", org, 0.55, "tls-cert", "certificate organisation"))

    hints = _hints(facts)
    if hints:
        ev.append(Evidence("hardware_notes", hints, 0.3, "nmap-hints"))
    return ev


def _drop_conflicting_nmap_os(ev: list[Evidence], facts: dict[str, Any]) -> list[Evidence]:
    """nmap -O guesses are noisy on devices with few open ports (an iPhone "matching" a FortiGate).
    If a strong non-nmap source names a different OS family, discard nmap's OS-derived evidence."""
    strong = [
        e for e in ev if e.field == "os_family" and e.confidence >= 0.7 and e.source != "nmap-os"
    ]
    if not strong:
        return ev
    best = max(strong, key=lambda e: e.confidence)
    if facts.get("os_family") == best.value:
        return ev
    return [e for e in ev if e.source != "nmap-os"]


def _hints(facts: dict[str, Any]) -> str:
    parts: list[str] = []
    if facts.get("http_titles"):
        parts.append("Web: " + " | ".join(dict.fromkeys(facts["http_titles"]))[:100])
    if facts.get("http_servers"):
        parts.append("Server: " + " | ".join(dict.fromkeys(facts["http_servers"]))[:120])
    cert = facts.get("ssl_cert") or {}
    if cert:
        parts.append("TLS: " + "/".join(v for v in (cert.get("cn"), cert.get("org")) if v))
    prods = dict.fromkeys(
        f"{p['product']} {p.get('version', '')}".strip()
        for p in facts.get("ports", [])
        if p.get("product")
    )
    if prods:
        parts.append("Services: " + ", ".join(list(prods)[:4]))
    return "; ".join(parts)[:400]


def _web_text(facts: dict[str, Any]) -> str:
    cert = facts.get("ssl_cert") or {}
    return " ".join(
        [
            *facts.get("http_titles", []),
            *facts.get("http_servers", []),
            *facts.get("banners", []),
            cert.get("cn", ""),
            cert.get("org", ""),
            *(f"{p.get('product', '')} {p.get('extrainfo', '')}" for p in facts.get("ports", [])),
        ]
    )


def classify(facts: dict[str, Any], hostname: str | None, mac_vendor: str | None) -> list[Evidence]:
    """Return all evidence derivable from one merged set of facts."""
    ev: list[Evidence] = []

    if mac_vendor:
        ev.append(Evidence("vendor", mac_vendor, 0.40, "oui", "IEEE OUI of the MAC address"))

    ev.extend(_nmap_evidence(facts))

    # HomeKit
    cat = facts.get("hap_category")
    if cat is not None:
        dtype, label = hap_categories().get(int(cat), ("other", f"category {cat}"))
        ev.append(Evidence("device_type", dtype, 0.95, "hap", f"HomeKit category: {label}"))
    if facts.get("hap_model"):
        ev.append(Evidence("model", facts["hap_model"], 0.95, "hap", "HomeKit TXT md"))

    # Apple model identifier (iPhone15,2 ...)
    model = facts.get("apple_model")
    if model:
        ev.append(Evidence("model", model, 0.95, "apple-mdns", "mDNS model identifier"))
        ev.append(Evidence("vendor", "Apple", 0.95, "apple-mdns"))
        for pattern, osf, dtype in APPLE_MODELS:
            if pattern.match(model):
                ev.append(Evidence("os_family", osf, 0.95, "apple-mdns", f"model {model}"))
                ev.append(Evidence("os_detail", f"{osf} (from model {model})", 0.95, "apple-mdns"))
                ev.append(Evidence("device_type", dtype, 0.95, "apple-mdns", f"model {model}"))
                break

    # Chromecast / Google Cast
    if facts.get("cast_model"):
        ev.append(Evidence("model", facts["cast_model"], 0.90, "googlecast", "Cast TXT md"))

    # UPnP description
    if facts.get("upnp_modelName"):
        ev.append(Evidence("model", facts["upnp_modelName"], 0.85, "upnp", "UPnP modelName"))
    if facts.get("upnp_manufacturer"):
        ev.append(Evidence("vendor", facts["upnp_manufacturer"], 0.85, "upnp", "UPnP manufacturer"))

    # Declarative rules
    ports = facts.get("ports", [])
    ctx = {
        "ports": {p["port"] for p in ports},
        "mdns": {s["type"] for s in facts.get("mdns_services", [])},
        "hostname": hostname or "",
        "vendor": mac_vendor or facts.get("upnp_manufacturer") or "",
        "banner": " ".join(
            " ".join(
                str(p.get(k) or "")
                for k in ("service", "product", "version", "extrainfo", "ostype")
            )
            for p in ports
        ),
        "web": _web_text(facts),
        "upnp": " ".join(
            str(facts.get(k) or "")
            for k in ("upnp_manufacturer", "upnp_modelName", "upnp_deviceType", "ssdp_server")
        ),
    }
    for rule in load_rules():
        if _matches(rule["when"], ctx):
            for field, value in rule["set"].items():
                ev.append(Evidence(field, value, float(rule["weight"]), f"rule:{rule['id']}"))
    return _drop_conflicting_nmap_os(ev, facts)
