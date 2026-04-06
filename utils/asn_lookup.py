"""
Session-scoped ASN / RDAP provider lookup via ipwhois (no broad hardcoded ranges).
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

_ASN_CACHE: dict[str, str] = {}
_ASN_LOCK = threading.Lock()

# Last-resort only (DNS / anycast landmarks) — not a cloud catalog.
_FALLBACK_PREFIXES: list[tuple[str, list[str]]] = [
    (
        "Cloudflare",
        [
            "1.1.1.",
            "1.0.0.",
            "104.16.",
            "104.17.",
            "104.18.",
            "104.19.",
            "104.20.",
            "104.21.",
            "172.64.",
            "172.65.",
            "172.66.",
            "172.67.",
        ],
    ),
    ("Google", ["8.8.8.", "8.8.4."]),
]


def _lookup_via_ipwhois(ip: str, timeout: int) -> Optional[str]:
    try:
        from ipwhois import IPWhois
        from ipwhois.exceptions import IPDefinedError

        obj = IPWhois(ip, timeout=max(1, int(timeout)))
        result: dict[str, Any] = obj.lookup_rdap(depth=1)
    except IPDefinedError:
        return "private"
    except Exception:  # noqa: BLE001
        return None

    try:
        org = result.get("asn_description")
        if org and str(org).strip():
            return str(org).strip()
        net = result.get("network")
        if isinstance(net, dict):
            name = net.get("name")
            if name and str(name).strip():
                return str(name).strip()
        cc = result.get("asn_country_code")
        if cc and str(cc).strip():
            return f"AS registry ({str(cc).strip()})"
    except Exception:  # noqa: BLE001
        return None
    return None


def _lookup_via_fallback(ip: str) -> Optional[str]:
    for provider, prefixes in _FALLBACK_PREFIXES:
        for prefix in prefixes:
            if ip.startswith(prefix):
                return provider
    return None


def _normalize_org_name(org: str) -> str:
    if not org:
        return "unknown"
    if org == "private":
        return "private"

    org_upper = org.upper()

    NORM_MAP: list[tuple[str, str]] = [
        ("ORACLE", "Oracle Cloud"),
        ("AMAZON", "Amazon AWS"),
        ("AWS", "Amazon AWS"),
        ("GOOGLE", "Google Cloud"),
        ("MICROSOFT", "Microsoft Azure"),
        ("AZURE", "Microsoft Azure"),
        ("CLOUDFLARE", "Cloudflare"),
        ("DIGITALOCEAN", "DigitalOcean"),
        ("VULTR", "Vultr"),
        ("LINODE", "Linode/Akamai"),
        ("AKAMAI", "Linode/Akamai"),
        ("OVH", "OVH"),
        ("HETZNER", "Hetzner"),
        ("LOCAWEB", "Locaweb"),
        ("HOSTGATOR", "HostGator"),
        ("GODADDY", "GoDaddy"),
        ("FASTLY", "Fastly"),
        ("LEASEWEB", "LeaseWeb"),
        ("CONTABO", "Contabo"),
    ]

    for pattern, label in NORM_MAP:
        if pattern in org_upper:
            return label

    o = org.strip()
    return o[:20].strip() if len(o) > 20 else o


def lookup_provider(ip: str, timeout: int = 3) -> str:
    """
    Resolve organization label for an IPv4/IPv6 address.
    Order: session cache → ipwhois RDAP → minimal prefix fallback → unknown.
    Thread-safe; never raises.
    """
    if not ip or ip == "unresolved":
        return "unknown"
    ip = str(ip).strip()
    if not ip:
        return "unknown"

    with _ASN_LOCK:
        if ip in _ASN_CACHE:
            return _ASN_CACHE[ip]

    org = _lookup_via_ipwhois(ip, timeout)
    if org == "private":
        with _ASN_LOCK:
            _ASN_CACHE[ip] = "private"
        return "private"
    if not org:
        org = _lookup_via_fallback(ip)
    if not org:
        org = "unknown"
    else:
        org = _normalize_org_name(org)

    with _ASN_LOCK:
        _ASN_CACHE[ip] = org
    return org


def lookup_many(
    ips: list[str],
    timeout: int = 3,
    workers: int = 5,
) -> dict[str, str]:
    """
    Parallel provider lookup with session cache. RDAP-friendly low parallelism.
    """
    results: dict[str, str] = {}
    to_lookup: list[str] = []

    with _ASN_LOCK:
        for ip in ips:
            if not ip or ip == "unresolved":
                continue
            ip = str(ip).strip()
            if not ip:
                continue
            if ip in _ASN_CACHE:
                results[ip] = _ASN_CACHE[ip]
            else:
                to_lookup.append(ip)

    unique = list(dict.fromkeys(to_lookup))
    if not unique:
        return results

    max_w = max(1, min(int(workers), len(unique)))
    with ThreadPoolExecutor(max_workers=max_w) as ex:
        futs = {ex.submit(lookup_provider, ip, int(timeout)): ip for ip in unique}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                results[ip] = fut.result(timeout=float(timeout) + 5.0)
            except Exception:  # noqa: BLE001
                results[ip] = "unknown"

    return results


def cache_stats() -> dict[str, int]:
    with _ASN_LOCK:
        total = len(_ASN_CACHE)
        known = sum(1 for v in _ASN_CACHE.values() if v not in ("unknown", ""))
        unknown = sum(1 for v in _ASN_CACHE.values() if v == "unknown")
    return {"total": total, "known": known, "unknown": unknown}


def clear() -> None:
    with _ASN_LOCK:
        _ASN_CACHE.clear()
