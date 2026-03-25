"""
GhostOpcode — CVE intelligence from NVD API 2.0 (post-recon enrichment).

Correlates port_scan / whois_scan / js_recon signals with published CVEs.
Requires NVD_API_KEY in .env (free at https://nvd.nist.gov/developers/request-an-api-key).
"""

from __future__ import annotations

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


def _parse_version_loose(v: str) -> Any | None:
    """Best-effort PEP 440 parse; strip OpenSSH-style suffixes."""
    if not v or not str(v).strip():
        return None
    s = str(v).strip()
    m = re.match(r"^(\d+(?:\.\d+)*)", s)
    if m:
        try:
            return pkg_version.parse(m.group(1))
        except Exception:  # noqa: BLE001
            pass
    try:
        return pkg_version.parse(s)
    except Exception:  # noqa: BLE001
        return None


def is_version_affected(
    version: str,
    affected_versions: list[dict[str, Any]],
) -> bool:
    """Check if version matches CPE ranges. Conservative: True if uncertain."""
    if not affected_versions:
        return True
    v = _parse_version_loose(version)
    if v is None:
        return True
    for aff in affected_versions:
        exact = aff.get("version_exact")
        if exact:
            ev = _parse_version_loose(str(exact))
            if ev is not None and ev == v:
                return True
        start = aff.get("version_start_including")
        end_ex = aff.get("version_end_excluding")
        end_in = aff.get("version_end_including")
        try:
            if start:
                sv = _parse_version_loose(str(start))
                if sv is None:
                    continue
                if v < sv:
                    continue
                if end_ex:
                    evx = _parse_version_loose(str(end_ex))
                    if evx is not None and v < evx:
                        return True
                elif end_in:
                    evi = _parse_version_loose(str(end_in))
                    if evi is not None and v <= evi:
                        return True
                else:
                    return True
        except Exception:  # noqa: BLE001
            return True
    return False


def parse_nvd_response(
    data: dict[str, Any],
    software: str,
    version: str | None,
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
            version_affected = is_version_affected(version, affected)

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
) -> list[dict[str, Any]]:
    """Query NVD API; never raises; respects rate limits."""
    keyword = build_nvd_query(software, version)
    if not keyword:
        return []

    params: dict[str, Any] = {
        "keywordSearch": keyword[:400],
        "resultsPerPage": 10,
        "startIndex": 0,
    }
    headers = {"apiKey": api_key}

    try:
        resp = requests.get(
            NVD_BASE_URL,
            params=params,
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 429:
            if _retry_429 < MAX_429_RETRIES:
                time.sleep(30)
                return query_nvd(
                    software,
                    version,
                    api_key,
                    timeout,
                    _retry_429 + 1,
                )
            return []
        if resp.status_code in (401, 403):
            return [{"_error": "nvd_auth", "detail": resp.text[:200]}]
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            return []
        return parse_nvd_response(data, software, version)
    except requests.exceptions.HTTPError:
        return []
    except Exception:  # noqa: BLE001
        return []


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

    for tgt in targets:
        software = tgt["software"]
        ver = tgt.get("version")
        src = tgt["source"]
        time.sleep(REQUEST_GAP_S)
        raw_list = query_nvd(software, ver, api_key, timeout=timeout)
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
        for c in cves:
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

        label = f"{software}" + (f" {ver}" if ver else "")
        console.print()
        console.print(
            Text.assemble(
                (" [►] ", C_PRI),
                (label, "bold"),
                (f"  ({src})", C_DIM),
            )
        )
        if not cves:
            console.print(Text("     (no CVE rows returned for this query)", style=C_MUTED))
        for c in cves[:10]:
            sev = c.get("cvss_severity") or "—"
            sc = c.get("cvss_score")
            sc_s = f"{sc}" if sc is not None else "n/a"
            desc = (c.get("description") or "")[:90]
            if len(c.get("description") or "") > 90:
                desc += "…"
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

    if flat_rows:
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
            + f"\n     Duration        : {elapsed:.1f}s",
            style=C_DIM,
        )
    )

    base["stats"] = {"duration_s": round(elapsed, 2)}
    return base
