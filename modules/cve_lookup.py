"""
GhostOpcode — CVE intelligence from NVD API 2.0 (post-recon enrichment).

Correlates port_scan / whois_scan / js_recon signals with published CVEs.
Requires NVD_API_KEY in .env (free at https://nvd.nist.gov/developers/request-an-api-key).
"""

from __future__ import annotations

import copy
import json
import re
import time
from typing import Any

# Terms that must NOT be sent to NVD (IANA names, nmap states, overly generic).
CVE_SKIP_TERMS: frozenset[str] = frozenset(
    {
        "unknown",
        "tcpwrapped",
        "filtered",
        "closed",
        "rsqlserver",
        "wspipe",
        "noadmin",
        "fujitsu-dtcns",
        "cirrossp",
        "tcpmux",
        "compressnet",
        "rje",
        "echo",
        "discard",
        "systat",
        "daytime",
        "qotd",
        "chargen",
        "ftp-data",
        "ftp",
        "ssh",
        "telnet",
        "smtp",
        "time",
        "rlp",
        "nameserver",
        "whois",
        "domain",
        "gopher",
        "finger",
        "www",
        "kerberos",
        "pop2",
        "pop3",
        "auth",
        "uucp-path",
        "nntp",
        "epmap",
        "netbios-ns",
        "netbios-dgm",
        "netbios-ssn",
        "imap",
        "snmp",
        "snmptrap",
        "bgp",
        "irc",
        "ldap",
        "https",
        "smtps",
        "imaps",
        "pop3s",
        "http",
        "tcp",
        "udp",
        "ssl",
        "tls",
    }
)


def should_skip_cve_lookup(software: str) -> bool:
    """
    True if the label is too generic or is an IANA/nmap artefact — skip NVD.
    """
    if not software:
        return True
    s = software.lower().strip()
    if s in CVE_SKIP_TERMS:
        return True
    if len(s) <= 2:
        return True
    if s.isdigit():
        return True
    return False


def build_nvd_query(software: str, version: str | None) -> str:
    """
    Build keywordSearch string: prefer major.minor when version is present
    so NVD returns broader, still relevant hits.
    """
    sw = (software or "").strip()
    if not sw:
        return ""
    if not version:
        return sw
    v = str(version).strip()
    if not v or v.lower() == sw.lower():
        return sw
    parts = v.split(".")
    if len(parts) >= 2:
        short_version = f"{parts[0]}.{parts[1]}"
    else:
        short_version = v
    return f"{sw} {short_version}".strip()


def _dedupe_preserve_strs(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

import requests
from dotenv import load_dotenv
from packaging import version as pkg_version
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from utils.http_client import make_session
from utils.output import debug_log, display_findings

load_dotenv()

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_ACCENT = "#8B9CA8"

console = Console(highlight=False, force_terminal=True)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_GAP_S = 0.62
MAX_429_RETRIES = 3

# Session-scoped (in-process only); cleared at each GhostOpcode session start.
_NVD_CACHE: dict[str, list[dict[str, Any]]] = {}
_NVD_CACHE_HITS = 0
_NVD_CACHE_MISSES = 0


def _make_cache_key(software: str, version: str | None) -> str:
    """Normalized (software, version) for cache lookup — case-insensitive."""
    sw = (software or "").strip().lower()
    ver = (version or "").strip().lower()
    return f"{sw}:{ver}"


def _cache_get(software: str, version: str | None) -> list[dict[str, Any]] | None:
    global _NVD_CACHE_HITS
    key = _make_cache_key(software, version)
    if key not in _NVD_CACHE:
        return None
    _NVD_CACHE_HITS += 1
    return _NVD_CACHE[key]


def _cache_set(
    software: str,
    version: str | None,
    cves: list[dict[str, Any]],
) -> None:
    key = _make_cache_key(software, version)
    _NVD_CACHE[key] = cves


def _cache_clear() -> None:
    """Clear NVD session cache and per-session stats (new interactive session)."""
    global _NVD_CACHE_HITS, _NVD_CACHE_MISSES
    _NVD_CACHE.clear()
    _NVD_CACHE_HITS = 0
    _NVD_CACHE_MISSES = 0


def nvd_cache_stats() -> tuple[int, int]:
    """Return (hits, http_requests) for debug summary."""
    return (_NVD_CACHE_HITS, _NVD_CACHE_MISSES)


def _env_api_key() -> str | None:
    import os

    k = (os.getenv("NVD_API_KEY") or "").strip()
    return k or None


def extract_targets(
    session_results: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Extract software/version pairs from session results.
    Port rows: prefer product over service; skip generic / IANA / nmap noise.
    Returns (targets, skipped_labels) for operator feedback.
    """
    targets: list[dict[str, Any]] = []
    skipped: list[str] = []

    ps = session_results.get("port_scan") or {}
    if isinstance(ps, dict) and ps.get("status") == "success":
        for port in ps.get("ports") or []:
            if not isinstance(port, dict):
                continue
            prod = (port.get("product") or "").strip()
            ver_raw = (port.get("version") or "").strip()
            ver = ver_raw or None
            svc = str(port.get("service") or "?").strip()
            pnum = port.get("port", "?")

            search_term: str | None = None
            if prod and not should_skip_cve_lookup(prod):
                search_term = prod
            elif svc and not should_skip_cve_lookup(svc):
                search_term = svc

            if not search_term:
                useless = prod or svc or "?"
                skipped.append(f"{useless} (port {pnum})")
                continue

            if ver and ver.lower() == search_term.lower():
                ver = None

            targets.append(
                {
                    "software": search_term,
                    "version": ver,
                    "source": f"port {pnum}/{svc}",
                    "context": (port.get("banner") or "")[:500],
                }
            )

    ws = session_results.get("whois_scan") or {}
    if isinstance(ws, dict) and ws.get("status") in ("success", "error"):
        tech = ws.get("tech_stack") or {}
        if not isinstance(tech, dict):
            tech = {}
        for key in ("web_server", "cms", "framework"):
            block = tech.get(key) or {}
            if not isinstance(block, dict):
                continue
            name = (block.get("name") or "").strip()
            if not name:
                continue
            if should_skip_cve_lookup(name):
                skipped.append(f"{name} ({key})")
                continue
            wver = (block.get("version") or "").strip() or None
            targets.append(
                {
                    "software": name,
                    "version": wver,
                    "source": f"{key.replace('_', ' ')} (HTTP fingerprint)",
                    "context": "",
                }
            )

    js = session_results.get("js_recon") or {}
    if isinstance(js, dict) and js.get("status") == "success":
        for ep in (js.get("endpoints") or [])[:40]:
            if not isinstance(ep, dict):
                continue
            url = (ep.get("url") or "").lower()
            cat = (ep.get("category") or "").lower()
            if "wordpress" in url or cat == "wordpress":
                targets.append(
                    {
                        "software": "WordPress",
                        "version": None,
                        "source": "js_recon endpoint pattern",
                        "context": ep.get("url", "")[:200],
                    }
                )
            elif "drupal" in url:
                targets.append(
                    {
                        "software": "Drupal",
                        "version": None,
                        "source": "js_recon endpoint pattern",
                        "context": ep.get("url", "")[:200],
                    }
                )

    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for t in targets:
        key = f"{t['software'].lower()}:{t.get('version') or ''}"
        if key not in seen:
            seen.add(key)
            unique.append(t)

    return unique, _dedupe_preserve_strs(skipped)


def extract_affected_versions(configurations: list[Any]) -> list[dict[str, Any]]:
    """Pull version constraints from NVD configurations → cpeMatch."""
    out: list[dict[str, Any]] = []
    if not isinstance(configurations, list):
        return out
    for conf in configurations:
        if not isinstance(conf, dict):
            continue
        for node in conf.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict):
                    continue
                if match.get("vulnerable") is False:
                    continue
                cpe = str(match.get("criteria") or "")
                exact = None
                parts = cpe.split(":")
                if len(parts) >= 6 and parts[5] not in ("*", "-", ""):
                    exact = parts[5]
                out.append(
                    {
                        "cpe": cpe,
                        "version_exact": exact,
                        "version_start_including": match.get("versionStartIncluding"),
                        "version_end_excluding": match.get("versionEndExcluding"),
                        "version_end_including": match.get("versionEndIncluding"),
                    }
                )
    return out


def _parse_version_loose(
    v: str,
    warnings_out: list[str] | None = None,
) -> Any | None:
    """Best-effort PEP 440 parse; strip OpenSSH-style suffixes."""
    if not v or not str(v).strip():
        return None
    s = str(v).strip()
    m = re.match(r"^(\d+(?:\.\d+)*)", s)
    if m:
        try:
            return pkg_version.parse(m.group(1))
        except Exception as e:  # noqa: BLE001
            if warnings_out is not None and len(warnings_out) < 12:
                warnings_out.append(
                    f"CVE version parse (prefix): {type(e).__name__}: {e}"
                )
    try:
        return pkg_version.parse(s)
    except Exception as e:  # noqa: BLE001
        if warnings_out is not None and len(warnings_out) < 12:
            warnings_out.append(
                f"CVE version parse (full): {type(e).__name__}: {e}"
            )
        return None


def is_version_affected(
    version: str,
    affected_versions: list[dict[str, Any]],
    warnings_out: list[str] | None = None,
) -> bool:
    """Check if version matches CPE ranges. Conservative: True if uncertain."""
    if not affected_versions:
        return True
    v = _parse_version_loose(version, warnings_out)
    if v is None:
        return True
    for aff in affected_versions:
        exact = aff.get("version_exact")
        if exact:
            ev = _parse_version_loose(str(exact), warnings_out)
            if ev is not None and ev == v:
                return True
        start = aff.get("version_start_including")
        end_ex = aff.get("version_end_excluding")
        end_in = aff.get("version_end_including")
        try:
            if start:
                sv = _parse_version_loose(str(start), warnings_out)
                if sv is None:
                    continue
                if v < sv:
                    continue
                if end_ex:
                    evx = _parse_version_loose(str(end_ex), warnings_out)
                    if evx is not None and v < evx:
                        return True
                elif end_in:
                    evi = _parse_version_loose(str(end_in), warnings_out)
                    if evi is not None and v <= evi:
                        return True
                else:
                    return True
        except Exception as e:  # noqa: BLE001
            if warnings_out is not None and len(warnings_out) < 16:
                warnings_out.append(
                    f"CVE version range check: {type(e).__name__}: {e}"
                )
            return True
    return False


def parse_nvd_response(
    data: dict[str, Any],
    software: str,
    version: str | None,
    warnings_out: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Parse NVD 2.0 JSON; filter by version when possible; sort by CVSS desc."""
    cves: list[dict[str, Any]] = []
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return cves

    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        cve = vuln.get("cve") or {}
        if not isinstance(cve, dict):
            continue
        cve_id = cve.get("id") or ""

        descriptions = cve.get("descriptions") or []
        description = "No description available"
        if isinstance(descriptions, list):
            for d in descriptions:
                if isinstance(d, dict) and d.get("lang") == "en":
                    description = str(d.get("value") or description)
                    break

        metrics = cve.get("metrics") or {}
        cvss_score: float | None = None
        cvss_severity: str | None = None
        cvss_vector: str | None = None
        if isinstance(metrics, dict):
            for cvss_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                mlist = metrics.get(cvss_key) or []
                if not mlist or not isinstance(mlist, list):
                    continue
                first = mlist[0]
                if not isinstance(first, dict):
                    continue
                cvss_data = first.get("cvssData") or {}
                if isinstance(cvss_data, dict):
                    bs = cvss_data.get("baseScore")
                    if bs is not None:
                        try:
                            cvss_score = float(bs)
                        except (TypeError, ValueError):
                            cvss_score = None
                    cvss_severity = cvss_data.get("baseSeverity") or first.get(
                        "baseSeverity"
                    )
                    cvss_vector = cvss_data.get("vectorString")
                break

        configurations = cve.get("configurations") or []
        affected = (
            extract_affected_versions(configurations)
            if isinstance(configurations, list)
            else []
        )

        version_affected = True
        if version and affected:
            version_affected = is_version_affected(
                version, affected, warnings_out
            )

        if not version_affected:
            continue

        published = str(cve.get("published") or "")[:10]

        cisa_kev = bool(cve.get("cisaExploitAdd"))
        cisa_info: dict[str, Any] = {}
        if cisa_kev:
            cisa_info = {
                "in_kev": True,
                "exploit_add_date": cve.get("cisaExploitAdd", ""),
                "action_due": cve.get("cisaActionDue", ""),
                "required_action": cve.get("cisaRequiredAction", ""),
            }

        desc_out = description
        if len(desc_out) > 300:
            desc_out = desc_out[:300] + "..."

        cves.append(
            {
                "cve_id": cve_id,
                "description": desc_out,
                "cvss_score": cvss_score,
                "cvss_severity": (str(cvss_severity).upper() if cvss_severity else None),
                "cvss_vector": cvss_vector,
                "published": published,
                "cisa_kev": cisa_kev,
                "cisa_due": cisa_info.get("action_due"),
                "cisa_required_action": cisa_info.get("required_action"),
                "affected_versions": affected[:8],
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "software": software,
                "version": version,
            }
        )

    def sort_key(x: dict[str, Any]) -> tuple[float, str]:
        sc = x.get("cvss_score")
        sc_f = float(sc) if sc is not None else -1.0
        pub = x.get("published") or ""
        return (sc_f, pub)

    return sorted(cves, key=sort_key, reverse=True)


def query_nvd(
    software: str,
    version: str | None,
    api_key: str,
    timeout: int = 12,
    _retry_429: int = 0,
    config: dict[str, Any] | None = None,
    errors_out: list[str] | None = None,
    warnings_out: list[str] | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """
    Query NVD API; never raises; respects rate limits.

    Returns ``(rows, from_cache)``. Cache hits skip HTTP and ``REQUEST_GAP_S``.
    """
    global _NVD_CACHE_MISSES
    keyword = build_nvd_query(software, version)
    if not keyword:
        return ([], False)

    cached = _cache_get(software, version)
    if cached is not None:
        ver_s = version or ""
        debug_log(
            "info",
            detail=(
                f"NVD cache hit: {software} {ver_s} → {len(cached)} CVE(s) (no request)"
            ),
            config=config,
        )
        return (copy.deepcopy(cached), True)

    params: dict[str, Any] = {
        "keywordSearch": keyword[:400],
        "resultsPerPage": 10,
        "startIndex": 0,
    }
    headers = {"apiKey": api_key}
    kw_show = keyword[:72] + ("…" if len(keyword) > 72 else "")
    debug_log(
        "http",
        detail=(
            f"GET {NVD_BASE_URL} keywordSearch={kw_show!r} "
            f"(header apiKey=****)"
        ),
        config=config,
    )
    t_req = time.perf_counter()

    try:
        nvd_cfg = {**(config or {}), "allow_insecure_tls": False}
        session = make_session(nvd_cfg)
        _NVD_CACHE_MISSES += 1
        resp = session.get(
            NVD_BASE_URL,
            params=params,
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 429:
            debug_log(
                "http",
                detail="NVD API",
                result=f"status 429 rate limited · retry {_retry_429 + 1}/{MAX_429_RETRIES}",
                elapsed=time.perf_counter() - t_req,
                config=config,
            )
            if _retry_429 < MAX_429_RETRIES:
                time.sleep(30)
                return query_nvd(
                    software,
                    version,
                    api_key,
                    timeout,
                    _retry_429 + 1,
                    config,
                    errors_out,
                    warnings_out,
                )
            if errors_out is not None:
                errors_out.append(
                    f"NVD API 429 rate limited for {software!s} — exhausted retries"
                )
            _cache_set(software, version, [])
            return ([], False)
        if resp.status_code in (401, 403):
            debug_log(
                "http",
                detail="NVD API",
                result=f"status {resp.status_code} auth rejected",
                elapsed=time.perf_counter() - t_req,
                config=config,
            )
            return ([{"_error": "nvd_auth", "detail": resp.text[:200]}], False)
        resp.raise_for_status()
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError) as e:
            if errors_out is not None:
                errors_out.append(
                    f"NVD JSON decode for {software!s}: {type(e).__name__}: {e}"
                )
            debug_log(
                "http",
                detail="NVD API",
                result=f"JSON decode: {type(e).__name__}",
                elapsed=time.perf_counter() - t_req,
                config=config,
            )
            _cache_set(software, version, [])
            return ([], False)
        if not isinstance(data, dict):
            if errors_out is not None:
                errors_out.append(
                    f"NVD response for {software!s} is not a JSON object "
                    f"(got {type(data).__name__})"
                )
            debug_log(
                "http",
                detail="NVD API",
                result="invalid JSON body",
                elapsed=time.perf_counter() - t_req,
                config=config,
            )
            _cache_set(software, version, [])
            return ([], False)
        parsed = parse_nvd_response(
            data, software, version, warnings_out=warnings_out
        )
        debug_log(
            "http",
            detail="NVD API response",
            result=f"status {resp.status_code} · {len(parsed)} CVE row(s)",
            elapsed=time.perf_counter() - t_req,
            config=config,
        )
        _cache_set(software, version, parsed)
        time.sleep(REQUEST_GAP_S)
        return (parsed, False)
    except requests.exceptions.HTTPError as e:
        if errors_out is not None:
            errors_out.append(
                f"NVD HTTP error for {software!s}: {type(e).__name__}: {e}"
            )
        debug_log(
            "http",
            detail="NVD API",
            result=f"HTTP error: {e!s}"[:160],
            elapsed=time.perf_counter() - t_req,
            config=config,
        )
        _cache_set(software, version, [])
        return ([], False)
    except requests.exceptions.Timeout as e:
        if errors_out is not None:
            errors_out.append(
                f"NVD request timeout for {software!s}: {type(e).__name__}: {e}"
            )
        debug_log(
            "http",
            detail="NVD API",
            result=f"timeout: {type(e).__name__}",
            elapsed=time.perf_counter() - t_req,
            config=config,
        )
        _cache_set(software, version, [])
        return ([], False)
    except requests.exceptions.ConnectionError as e:
        if errors_out is not None:
            errors_out.append(
                f"NVD connection failed for {software!s}: {type(e).__name__}: {e}"
            )
        debug_log(
            "http",
            detail="NVD API",
            result=f"connection: {type(e).__name__}",
            elapsed=time.perf_counter() - t_req,
            config=config,
        )
        _cache_set(software, version, [])
        return ([], False)
    except Exception as e:  # noqa: BLE001
        if errors_out is not None:
            errors_out.append(
                f"CVE lookup failed for {software!s}: {type(e).__name__}: {e}"
            )
        debug_log(
            "http",
            detail="NVD API",
            result=f"error: {type(e).__name__}",
            elapsed=time.perf_counter() - t_req,
            config=config,
        )
        _cache_set(software, version, [])
        return ([], False)


def _severity_bucket(sev: str | None, score: float | None) -> str:
    s = (sev or "").upper()
    if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return s
    if score is not None:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    return "LOW"


def run(session_results: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """
    Post-process session results: NVD lookup per extracted target.
    """
    t0 = time.perf_counter()
    errors: list[str] = []
    api_key = _env_api_key()

    base: dict[str, Any] = {
        "module": "cve_lookup",
        "status": "skipped",
        "targets_checked": 0,
        "findings": [],
        "summary": {
            "total_cves_found": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "in_cisa_kev": 0,
        },
        "errors": errors,
        "warnings": [],
        "risk_summary": {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []},
        "findings_flat": [],
        "skipped_targets": [],
    }

    targets, skipped_targets = extract_targets(session_results)
    base["skipped_targets"] = skipped_targets

    if skipped_targets:
        tail = " · ".join(skipped_targets[:8])
        if len(skipped_targets) > 8:
            tail += " …"
        console.print()
        console.print(
            Text(
                f" [i] Skipped {len(skipped_targets)} unidentified/generic service(s): {tail}",
                style=C_MUTED,
            )
        )

    if not api_key:
        console.print(
            Text(" [!] NVD_API_KEY not found in .env", style=f"bold {C_WARN}")
        )
        console.print(
            Text(
                " [i] Get your free key at: https://nvd.nist.gov/developers/request-an-api-key",
                style=C_MUTED,
            )
        )
        console.print(
            Text(" [i] Add to .env: NVD_API_KEY=your-key-here", style=C_MUTED)
        )
        console.print(Text(" [i] Skipping CVE lookup...", style=C_MUTED))
        return base

    if not targets:
        console.print(
            Text(
                " [i] No software/version signals to correlate — skipping CVE lookup",
                style=C_MUTED,
            )
        )
        base["status"] = "skipped"
        return base

    timeout = max(5, int(config.get("timeout") or 10))
    quiet = bool(config.get("quiet", False))

    console.print()
    console.print(
        Panel(
            Text(
                f" CVE LOOKUP  ·  NVD API  ·  {len(targets)} target(s)",
                style=f"bold {C_PRI}",
            ),
            border_style=C_ACCENT,
            box=box.DOUBLE,
            width=min(console.size.width, 82) if console.size else 82,
        )
    )

    findings: list[dict[str, Any]] = []
    kev_alerts: list[dict[str, Any]] = []
    flat_rows: list[dict[str, Any]] = []
    auth_failed = False
    critical_cvss_ge_9: list[dict[str, Any]] = []
    seen_critical_cve: set[str] = set()

    for tgt in targets:
        software = tgt["software"]
        ver = tgt.get("version")
        src = tgt["source"]
        raw_list, _from_cache = query_nvd(
            software,
            ver,
            api_key,
            timeout=timeout,
            config=config,
            errors_out=errors,
            warnings_out=base["warnings"],
        )
        if (
            raw_list
            and len(raw_list) == 1
            and isinstance(raw_list[0], dict)
            and raw_list[0].get("_error") == "nvd_auth"
        ):
            auth_failed = True
            errors.append("NVD API rejected the key (401/403). Check NVD_API_KEY.")
            break

        cves = [x for x in raw_list if isinstance(x, dict) and x.get("cve_id")]
        label = f"{software}" + (f" {ver}" if ver else "")
        for c in cves:
            sc_raw = c.get("cvss_score")
            if sc_raw is not None:
                try:
                    sc_f = float(sc_raw)
                except (TypeError, ValueError):
                    sc_f = None
                if sc_f is not None and sc_f >= 9.0:
                    cid9 = str(c.get("cve_id") or "")
                    if cid9 and cid9 not in seen_critical_cve:
                        seen_critical_cve.add(cid9)
                        critical_cvss_ge_9.append(
                            {
                                "risk": "CRITICAL",
                                "category": "cve",
                                "value": f"{cid9} — CVSS {sc_raw} — {label}",
                                "note": (str(c.get("description") or ""))[:200],
                            }
                        )
            if c.get("cisa_kev"):
                kev_alerts.append({**c, "source_label": src})
            bucket = _severity_bucket(
                c.get("cvss_severity"),
                c.get("cvss_score"),
            )
            cid = c.get("cve_id") or ""
            if cid and bucket in base["risk_summary"]:
                lst = base["risk_summary"][bucket]
                if cid not in lst:
                    lst.append(cid)

        scores = [x.get("cvss_score") for x in cves if x.get("cvss_score") is not None]
        highest = max(scores) if scores else None
        has_kev = any(x.get("cisa_kev") for x in cves)

        if not quiet:
            console.print()
            console.print(
                Text.assemble(
                    (" [►] ", C_PRI),
                    (label, "bold"),
                    (f"  ({src})", C_DIM),
                )
            )
        if not quiet and not cves:
            console.print(Text("     (no CVE rows returned for this query)", style=C_MUTED))
        for c in cves[:10]:
            sev = c.get("cvss_severity") or "—"
            sc = c.get("cvss_score")
            sc_s = f"{sc}" if sc is not None else "n/a"
            desc = (c.get("description") or "")[:90]
            if len(c.get("description") or "") > 90:
                desc += "…"
            if not quiet:
                line = Text.assemble(
                    ("     ", C_MUTED),
                    (str(c.get("cve_id")), C_DIM),
                    ("  CVSS ", C_MUTED),
                    (sc_s, C_PRI),
                    ("  [", C_MUTED),
                    (str(sev), C_WARN if sev in ("HIGH", "CRITICAL") else C_DIM),
                    ("]  ", C_MUTED),
                    (desc, C_MUTED),
                )
                console.print(line)
            flat_rows.append(
                {
                    "software": label,
                    "cve_id": c.get("cve_id"),
                    "cvss": sc,
                    "severity": sev,
                    "kev": "KEV" if c.get("cisa_kev") else "—",
                    "source": src,
                }
            )

        findings.append(
            {
                "software": software,
                "version": ver,
                "source": src,
                "cves": cves[:10],
                "total_cves": len(cves),
                "highest_cvss": highest,
                "has_kev": has_kev,
            }
        )

    if auth_failed:
        base["status"] = "error"
        base["errors"] = errors
        return base

    for alert in kev_alerts:
        console.print()
        console.print(
            Text(" [!!!] CISA KEV — Known Exploited Vulnerability!", style=f"bold {C_ERR}")
        )
        console.print(
            Text.assemble(
                ("       ", C_MUTED),
                (str(alert.get("cve_id")), f"bold {C_ERR}"),
                ("  ", C_MUTED),
                (str(alert.get("software")), C_DIM),
                ("  CVSS ", C_MUTED),
                (str(alert.get("cvss_score") or "—"), C_ERR),
                ("  [", C_MUTED),
                (str(alert.get("cvss_severity") or "—"), f"bold {C_ERR}"),
                ("]", C_MUTED),
            )
        )
        if alert.get("cisa_due"):
            console.print(
                Text(f"       Action due: {alert['cisa_due']}", style=C_WARN)
            )
        if alert.get("cisa_required_action"):
            ra = str(alert.get("cisa_required_action", ""))
            ra_out = ra[:120] + "…" if len(ra) > 120 else ra
            console.print(Text(f"       Required: {ra_out}", style=C_MUTED))
        console.print(
            Text(
                "       This vulnerability is actively exploited in the wild",
                style=f"bold {C_ERR}",
            )
        )

    if critical_cvss_ge_9:
        display_findings(
            critical_cvss_ge_9,
            module="cve_lookup",
            verbose=bool(config.get("verbose")),
            config=config,
        )

    if quiet:
        high_rows = [
            {
                "risk": "HIGH",
                "category": "cve",
                "value": (
                    f"{r.get('cve_id')} — CVSS {r.get('cvss')} — {r.get('software')}"
                ),
                "note": str(r.get("source") or ""),
            }
            for r in flat_rows
            if str(r.get("severity") or "").upper() == "HIGH"
        ]
        if high_rows:
            display_findings(
                high_rows,
                module="cve_lookup",
                verbose=bool(config.get("verbose")),
                config=config,
            )

    total_cves = sum(len(f["cves"]) for f in findings)
    crit = sum(
        1
        for f in findings
        for c in f["cves"]
        if _severity_bucket(c.get("cvss_severity"), c.get("cvss_score")) == "CRITICAL"
    )
    high = sum(
        1
        for f in findings
        for c in f["cves"]
        if _severity_bucket(c.get("cvss_severity"), c.get("cvss_score")) == "HIGH"
    )
    med = sum(
        1
        for f in findings
        for c in f["cves"]
        if _severity_bucket(c.get("cvss_severity"), c.get("cvss_score")) == "MEDIUM"
    )
    low = sum(
        1
        for f in findings
        for c in f["cves"]
        if _severity_bucket(c.get("cvss_severity"), c.get("cvss_score")) == "LOW"
    )
    kev_n = sum(1 for f in findings for c in f["cves"] if c.get("cisa_kev"))

    base["targets_checked"] = len(targets)
    base["findings"] = findings
    base["findings_flat"] = flat_rows
    base["summary"] = {
        "total_cves_found": total_cves,
        "critical": crit,
        "high": high,
        "medium": med,
        "low": low,
        "in_cisa_kev": kev_n,
    }
    base["status"] = "success"
    base["errors"] = errors

    if flat_rows and not quiet:
        console.print()
        tbl = Table(
            title=Text("CVE intelligence (rollup)", style=f"bold {C_PRI}"),
            box=box.ROUNDED,
            border_style=C_ACCENT,
        )
        tbl.add_column("Software", style=C_DIM)
        tbl.add_column("CVE ID", style=C_DIM)
        tbl.add_column("CVSS", justify="right")
        tbl.add_column("Severity")
        tbl.add_column("KEV")
        for row in flat_rows[:40]:
            sev = str(row.get("severity") or "—")
            tbl.add_row(
                str(row.get("software"))[:28],
                str(row.get("cve_id")),
                str(row.get("cvss") if row.get("cvss") is not None else "—"),
                sev,
                str(row.get("kev")),
            )
        console.print(tbl)

    elapsed = time.perf_counter() - t0
    console.print()
    console.print(Text(" [✓] CVE lookup complete", style=f"bold {C_PRI}"))
    nh, nm = nvd_cache_stats()
    dbg_cache = ""
    if config.get("debug"):
        tot = nh + nm
        pct = int(round(100 * nh / tot)) if tot else 0
        dbg_cache = (
            f"\n     [DEBUG] NVD cache: {nh} hit(s) · {nm} HTTP request(s)"
            f" ({pct}% hits — duplicate (software, version) skipped)"
        )

    console.print(
        Text(
            f"     Targets checked : {len(targets)}\n"
            f"     CVEs found      : {total_cves}\n"
            f"     Critical        : {crit}  ·  High: {high}  ·  Medium: {med}  ·  Low: {low}\n"
            f"     CISA KEV        : {kev_n}"
            + (
                "  (actively exploited in the wild!)"
                if kev_n
                else ""
            )
            + f"\n     Duration        : {elapsed:.1f}s"
            + dbg_cache,
            style=C_DIM,
        )
    )

    base["stats"] = {
        "duration_s": round(elapsed, 2),
        "nvd_cache_hits": nh,
        "nvd_http_requests": nm,
    }
    return base
