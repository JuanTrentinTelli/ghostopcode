"""
GhostOpcode virtual host discovery — Host header fuzzing against concentrated IPs.

Wordlists come from SecLists (Kali) or GhostOpcode subdomain wordlist config;
minimal fallback only when no file is available.
"""

from __future__ import annotations

import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

import config as app_config
from utils.base_module import make_finding
from utils.http_client import make_session
from utils.target_parser import Target

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_PANEL = "#8B9CA8"

console = Console(highlight=False, force_terminal=True)

# SecLists paths — first existing file wins (no large hardcoded wordlists).
WORDLIST_CANDIDATES: tuple[str, ...] = (
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
    "/usr/share/seclists/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt",
)

# Only used when no wordlist file is found — keeps the module usable offline.
FALLBACK_WORDS: tuple[str, ...] = (
    "admin",
    "dev",
    "staging",
    "test",
    "api",
    "internal",
    "portal",
    "vpn",
    "mail",
    "monitor",
)

# Known-FQDN suffix variations (structure only — not a discovery wordlist).
_KNOWN_FQDN_SUFFIXES: tuple[str, ...] = (
    "-dev",
    "-test",
    "-staging",
    "-old",
    "-v2",
    "-api",
    "-admin",
)

# Risk heuristics from hostname/title tokens (not used as scan words).
_RISK_CRITICAL_TOKENS: frozenset[str] = frozenset(
    {
        "admin",
        "panel",
        "console",
        "manage",
        "control",
        "gitlab",
        "jenkins",
        "jira",
        "confluence",
        "grafana",
        "kibana",
        "vpn",
        "internal",
        "intranet",
        "ldap",
    }
)
_RISK_HIGH_TOKENS: frozenset[str] = frozenset(
    {
        "dev",
        "staging",
        "test",
        "homolog",
        "qa",
        "uat",
        "api",
        "erp",
        "crm",
        "billing",
        "monitor",
        "backup",
    }
)

# Baseline page title hints — probing arbitrary Host headers on CDNs yields mass FPs.
CDN_BASELINE_INDICATORS: tuple[str, ...] = (
    "cloudflare",
    "akamai",
    "fastly",
    "cdn",
    "direct ip access not allowed",
)

# Vhost response title hints — proxy/CDN “unknown host” pages, not real backends.
CDN_RESPONSE_INDICATORS: tuple[str, ...] = (
    "dns resolution error",
    "nxdomain",
    "no such host",
    "invalid host",
    "not found",
)


def _title_suggests_cdn_baseline(title: str) -> bool:
    t = (title or "").lower()
    return any(ind in t for ind in CDN_BASELINE_INDICATORS)


def _response_is_cdn_dns_noise(status: int, title: str) -> bool:
    if int(status) == 409:
        return True
    tl = (title or "").lower()
    return any(ind in tl for ind in CDN_RESPONSE_INDICATORS)


def find_wordlist(cfg: dict[str, Any]) -> tuple[str | None, str]:
    """Return (path_or_none, human-readable source label)."""
    custom = cfg.get("wordlist_vhosts") or getattr(
        app_config, "WORDLIST_VHOSTS", None
    )
    if custom and Path(str(custom)).is_file():
        return str(custom), f"custom ({Path(custom).name})"

    for candidate in WORDLIST_CANDIDATES:
        p = Path(candidate)
        if p.is_file():
            return str(p), f"seclists ({p.name})"

    sub_wl = cfg.get("subdomain_wordlist") or getattr(
        app_config, "WORDLIST_SUBDOMAINS", None
    )
    if sub_wl and Path(str(sub_wl)).is_file():
        return str(sub_wl), "ghostopcode subdomain wordlist"

    return None, "none (using minimal fallback)"


def load_wordlist(path: str | None, limit: int) -> list[str]:
    if not path:
        return list(FALLBACK_WORDS)

    words: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                word = line.strip().lower()
                if word and not word.startswith("#"):
                    words.append(word)
                    if len(words) >= limit:
                        break
    except OSError:
        return list(FALLBACK_WORDS)

    return words if words else list(FALLBACK_WORDS)


def build_hostname_list(
    words: list[str],
    target_domain: str,
    known_fqdns: list[str],
) -> list[str]:
    hostnames: set[str] = set()
    domain = target_domain.lower().strip()

    for word in words:
        if "." not in word:
            hostnames.add(f"{word}.{domain}")
        else:
            hostnames.add(word.lower())

    for fqdn in known_fqdns:
        fqdn_l = fqdn.lower().strip()
        if fqdn_l.endswith(f".{domain}"):
            prefix = fqdn_l[: -(len(domain) + 1)]
            if prefix and "." not in prefix:
                for suffix in _KNOWN_FQDN_SUFFIXES:
                    hostnames.add(f"{prefix}{suffix}.{domain}")

    known_set = {f.lower() for f in known_fqdns if f}
    hostnames -= known_set

    hostnames = {h for h in hostnames if h and len(h) > 3}
    return sorted(hostnames)


def _get_ip_grouping(mod: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(mod, dict):
        return {}
    ig = mod.get("ip_grouping")
    if isinstance(ig, dict):
        return ig  # type: ignore[return-value]
    data = mod.get("data")
    if isinstance(data, dict):
        ig2 = data.get("ip_grouping")
        if isinstance(ig2, dict):
            return ig2  # type: ignore[return-value]
    return {}


def get_candidate_ips(
    target: Target,
    session_data: dict[str, Any],
    max_ips: int = 5,
) -> list[dict[str, Any]]:
    raw: list[dict[str, Any]] = []

    for mod_name in ("subfinder_enum", "subdomain_enum"):
        data = session_data.get(mod_name)
        if not isinstance(data, dict) or data.get("status") != "success":
            continue
        ip_grouping = _get_ip_grouping(data)
        prov_map = data.get("ip_providers") or {}
        if not isinstance(prov_map, dict):
            prov_map = {}

        for ip, subs in ip_grouping.items():
            if not ip or ip == "unresolved":
                continue
            if not isinstance(subs, list):
                continue
            fqdns = [
                str(s.get("subdomain") or s.get("fqdn") or "").strip()
                for s in subs
                if isinstance(s, dict)
            ]
            fqdns = [f for f in fqdns if f]
            raw.append(
                {
                    "ip": str(ip),
                    "services": len(subs),
                    "fqdns": fqdns,
                    "provider": str(prov_map.get(ip) or "unknown"),
                }
            )

    multi = [c for c in raw if c["services"] >= 2]
    pool = multi if multi else raw

    pool.sort(key=lambda x: x["services"], reverse=True)
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for c in pool:
        if c["ip"] in seen:
            continue
        seen.add(c["ip"])
        unique.append(c)

    if not unique:
        apex = target.value.strip().lower()
        ip_guess: str | None = None
        if target.is_domain():
            try:
                ip_guess = socket.gethostbyname(apex)
            except OSError:
                ip_guess = None
        elif target.is_ip():
            ip_guess = target.value.strip()

        if ip_guess:
            unique.append(
                {
                    "ip": ip_guess,
                    "services": 1,
                    "fqdns": [apex] if target.is_domain() else [],
                    "provider": "unknown",
                }
            )

    return unique[:max_ips]


def _extract_title(html: str) -> str:
    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        html,
        re.IGNORECASE | re.DOTALL,
    )
    if match:
        return match.group(1).strip()[:80]
    return ""


def get_baseline(
    ip: str,
    port: int,
    scheme: str,
    timeout: int,
    cfg: dict[str, Any],
) -> dict[str, Any] | None:
    session = make_session(cfg)
    try:
        resp = session.get(
            f"{scheme}://{ip}:{port}/",
            headers={"Host": ip},
            timeout=timeout,
            allow_redirects=True,
        )
        return {
            "status": resp.status_code,
            "length": len(resp.content or b""),
            "title": _extract_title(resp.text or ""),
        }
    except Exception:
        return None


def is_different_from_baseline(resp_data: dict[str, Any], baseline: dict[str, Any]) -> bool:
    status_diff = int(resp_data.get("status") or 0) != int(baseline.get("status") or 0)

    blen = int(baseline.get("length") or 0)
    rlen = int(resp_data.get("length") or 0)
    length_diff = False
    if blen > 0:
        length_diff = abs(rlen - blen) / blen > 0.20

    rt = str(resp_data.get("title") or "")
    bt = str(baseline.get("title") or "")
    title_diff = bool(
        rt
        and rt != bt
        and rt not in ("403 Forbidden", "404 Not Found")
    )

    return status_diff or length_diff or title_diff


def _assess_risk(hostname: str, status: int, title: str) -> str:
    h = hostname.lower()
    t = (title or "").lower()
    for tok in _RISK_CRITICAL_TOKENS:
        if tok in h or tok in t:
            return "CRITICAL"
    for tok in _RISK_HIGH_TOKENS:
        if tok in h or tok in t:
            return "HIGH"
    if status in (200, 301, 302):
        return "MEDIUM"
    return "LOW"


def _probe_one_vhost(
    hostname: str,
    url_base: str,
    baseline: dict[str, Any],
    timeout: int,
    cfg: dict[str, Any],
    ip: str,
    port: int,
    scheme: str,
) -> dict[str, Any] | None:
    session = make_session(cfg)
    try:
        resp = session.get(
            url_base,
            headers={"Host": hostname},
            timeout=timeout,
            allow_redirects=True,
        )
        data = {
            "status": resp.status_code,
            "length": len(resp.content or b""),
            "title": _extract_title(resp.text or ""),
        }
        if _response_is_cdn_dns_noise(data["status"], data["title"]):
            return None
        if not is_different_from_baseline(data, baseline):
            return None
        return {
            "hostname": hostname,
            "ip": ip,
            "port": port,
            "scheme": scheme,
            "url": f"{scheme}://{hostname}:{port}/",
            "status": data["status"],
            "length": data["length"],
            "title": data["title"],
            "risk": _assess_risk(hostname, data["status"], data["title"]),
        }
    except Exception:
        return None


def probe_vhosts(
    ip: str,
    port: int,
    scheme: str,
    hostnames: list[str],
    baseline: dict[str, Any],
    timeout: int,
    threads: int,
    cfg: dict[str, Any],
) -> list[dict[str, Any]]:
    url_base = f"{scheme}://{ip}:{port}/"
    found: list[dict[str, Any]] = []
    tw = max(1, min(int(threads), 20))

    with ThreadPoolExecutor(max_workers=tw) as ex:
        futs = {
            ex.submit(
                _probe_one_vhost,
                h,
                url_base,
                baseline,
                timeout,
                cfg,
                ip,
                port,
                scheme,
            ): h
            for h in hostnames
        }
        for fut in as_completed(futs):
            row = fut.result()
            if row:
                found.append(row)

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    found.sort(key=lambda x: risk_order.get(x.get("risk") or "LOW", 4))
    return found


def _display_results(vhosts: list[dict[str, Any]], quiet: bool) -> None:
    if quiet or not vhosts:
        return
    console.print()
    console.print(Text(" [VIRTUAL HOSTS FOUND]", style=f"bold {C_PRI}"))
    tbl = Table(box=box.SIMPLE_HEAD, show_header=True, border_style=C_PANEL)
    tbl.add_column("Hostname", style=C_DIM, max_width=38)
    tbl.add_column("IP", style=C_MUTED, max_width=17)
    tbl.add_column("Port", justify="center", width=6)
    tbl.add_column("Status", justify="center", width=7)
    tbl.add_column("Title", max_width=24)
    tbl.add_column("Risk", justify="center", width=10)

    for v in vhosts[:20]:
        rsk = str(v.get("risk") or "LOW")
        rc = {
            "CRITICAL": "#FF3B3B",
            "HIGH": "#E8C547",
            "MEDIUM": C_DIM,
            "LOW": C_MUTED,
        }.get(rsk, C_MUTED)
        st = int(v.get("status") or 0)
        st_style = C_PRI if st == 200 else C_WARN if st in (301, 302) else C_MUTED
        tbl.add_row(
            str(v.get("hostname") or "")[:38],
            str(v.get("ip") or ""),
            str(v.get("port") or ""),
            Text(str(st), style=st_style),
            (str(v.get("title") or "—"))[:24],
            Text(rsk, style=rc),
        )
    console.print(tbl)
    if len(vhosts) > 20:
        console.print(
            Text(
                f" … and {len(vhosts) - 20} more (see HTML / JSON export)",
                style=C_MUTED,
            )
        )


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Discover virtual hosts via Host header on IPs from session ip_grouping.
    """
    t0 = time.perf_counter()
    quiet = bool(config.get("quiet", False))
    debug = bool(config.get("debug", False))

    base: dict[str, Any] = {
        "module": "vhost_scan",
        "target": target.value.strip(),
        "status": "success",
        "errors": [],
        "warnings": [],
        "vhosts": [],
        "stats": {
            "duration_s": 0.0,
            "total_found": 0,
            "ips_tested": 0,
        },
        "wordlist": "",
        "words_used": 0,
        "findings_flat": [],
    }

    if target.is_cidr():
        base["status"] = "skipped"
        base["warnings"].append("Virtual host scan requires a domain or single IP target.")
        if not quiet:
            console.print(Text("  [SKIP] vhost scan — CIDR not supported.", style=C_WARN))
        base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)
        return base

    if not target.is_domain():
        base["status"] = "skipped"
        base["warnings"].append(
            "vhost scan is designed for a domain target (apex) so hostnames can be built. "
            "Use a domain, or run subfinder/subdomain enum on a domain first in the same session."
        )
        if not quiet:
            console.print(
                Text(
                    "  [SKIP] vhost scan — use a domain target for Host-header fuzzing.",
                    style=C_WARN,
                )
            )
        base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)
        return base

    apex = target.value.strip().lower()
    wl_limit = int(
        config.get("vhost_wordlist_limit")
        or getattr(app_config, "VHOST_WORDLIST_LIMIT", 5000)
        or 5000
    )
    wl_limit = max(50, min(wl_limit, 50_000))

    wl_path, wl_source = find_wordlist(config)
    words = load_wordlist(wl_path, limit=wl_limit)
    base["wordlist"] = wl_source
    base["words_used"] = len(words)

    if not quiet:
        console.print(
            Text(f"\n [i] Wordlist: {wl_source}", style=C_DIM),
        )
        console.print(
            Text(f"     {len(words):,} words loaded", style=C_MUTED),
        )
    if debug:
        console.print(
            Text(
                f"     [DEBUG] path={wl_path or '—'} · limit={wl_limit}",
                style=C_MUTED,
            )
        )

    session_data = config.get("session_results")
    if not isinstance(session_data, dict):
        session_data = {}

    candidates = get_candidate_ips(target, session_data, max_ips=5)
    base["stats"]["ips_tested"] = len(candidates)

    threads = min(int(config.get("threads") or 20), 20)
    timeout = max(3, min(int(config.get("timeout") or 5), 120))

    if not quiet:
        console.print(
            Text(
                f"\n [►] Virtual host discovery on {len(candidates)} IP candidate(s)...",
                style=f"bold {C_DIM}",
            )
        )

    ports_schemes: list[tuple[int, str]] = [(80, "http"), (443, "https"), (8080, "http")]
    all_found: list[dict[str, Any]] = []

    for cand in candidates:
        ip = cand["ip"]
        services = int(cand.get("services") or 0)
        prov = str(cand.get("provider") or "unknown")
        fqdns = list(cand.get("fqdns") or [])

        if not quiet:
            console.print(
                Text(
                    f"\n [►] {ip} ({prov}) — {services} known service(s)",
                    style=f"bold {C_DIM}",
                )
            )

        hostnames = build_hostname_list(words, apex, fqdns)
        if debug:
            console.print(
                Text(
                    f"     [DEBUG] {len(hostnames):,} hostnames (apex + variations − known)",
                    style=C_MUTED,
                )
            )
        if not quiet:
            console.print(
                Text(f"     {len(hostnames):,} hostnames to test", style=C_MUTED),
            )

        for port, scheme in ports_schemes:
            baseline = get_baseline(ip, port, scheme, timeout, config)
            if not baseline:
                continue
            if _title_suggests_cdn_baseline(str(baseline.get("title") or "")):
                if not quiet:
                    console.print(
                        Text(
                            f"     [i] Skip {scheme}:{port} — baseline title looks like CDN "
                            f"(no Host fuzzing)",
                            style=C_MUTED,
                        )
                    )
                continue
            if debug:
                console.print(
                    Text(
                        f"     [DEBUG] Baseline {ip}:{port}/{scheme} → "
                        f"status={baseline.get('status')} len={baseline.get('length')} "
                        f"title={baseline.get('title')!r}"[:120],
                        style=C_MUTED,
                    )
                )

            found = probe_vhosts(
                ip=ip,
                port=port,
                scheme=scheme,
                hostnames=hostnames,
                baseline=baseline,
                timeout=timeout,
                threads=threads,
                cfg=config,
            )
            if found and not quiet:
                console.print(
                    Text(
                        f"     [{scheme}:{port}] {len(found)} virtual host(s) found",
                        style=C_PRI,
                    )
                )
            all_found.extend(found)

    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in all_found:
        key = f"{f.get('hostname')}:{f.get('port')}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    unique.sort(key=lambda x: risk_order.get(x.get("risk") or "LOW", 4))

    base["vhosts"] = unique
    base["stats"]["total_found"] = len(unique)
    base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)

    if not quiet:
        console.print(
            Text(f"\n [✓] {len(unique)} virtual host(s) discovered", style=C_PRI),
        )

    _display_results(unique, quiet)

    findings_flat: list[dict[str, Any]] = []
    for v in unique:
        note = (
            f"{v.get('status')} · {v.get('title') or 'no title'} "
            f"({v.get('ip')}:{v.get('port')})"
        )
        fd = make_finding(
            value=str(v.get("url") or ""),
            category="virtual_host",
            risk=str(v.get("risk") or "LOW").upper(),
            note=note,
            metadata=v,
        )
        findings_flat.append(fd)

    base["findings_flat"] = findings_flat

    if wl_source.startswith("none"):
        base["warnings"].append(
            "No SecLists/GhostOpcode wordlist found — using minimal fallback words only."
        )

    return base
