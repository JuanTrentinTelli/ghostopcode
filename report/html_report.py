"""
Render executive HTML report from session data via Jinja2.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup, escape

import config as app_config

from utils.redact import redact_dict
from utils.report_truncate import truncate_report_results

# Pretty names for raw module keys in session.modules_run
MODULE_LABELS: dict[str, str] = {
    "dns_recon": "DNS Recon",
    "subdomain_enum": "Subdomain Enum",
    "whois_scan": "WHOIS",
    "port_scan": "Port Scan",
    "dir_enum": "Dir Enum",
    "harvester": "Harvester",
    "http_methods": "HTTP Methods",
    "js_recon": "JS Recon",
    "hash_module": "Hash Module",
    "waf_detect": "WAF Detection",
    "url_harvester": "URL Harvester",
    "subfinder_enum": "Subfinder Enum",
    "arp_scan": "ARP Scan",
    "packet_sniffer": "Packet Sniffer",
    "cve_lookup": "CVE Lookup (NVD)",
}


def count_findings_by_risk(results: dict[str, Any]) -> dict[str, int]:
    """
    Sum risk across modules. Prefer normalized ``*_findings`` (contract) when
    present; otherwise fall back to legacy ``risk_summary``.
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    if not isinstance(results, dict):
        return counts
    tier_keys = (
        ("critical_findings", "CRITICAL"),
        ("high_findings", "HIGH"),
        ("medium_findings", "MEDIUM"),
        ("low_findings", "LOW"),
    )
    for data in results.values():
        if not isinstance(data, dict):
            continue
        tier_total = 0
        for tk, _sev in tier_keys:
            lst = data.get(tk)
            if isinstance(lst, list):
                tier_total += len(lst)
        if tier_total > 0:
            for tk, sev in tier_keys:
                lst = data.get(tk)
                if isinstance(lst, list):
                    counts[sev] += len(lst)
            continue
        rs = data.get("risk_summary") or {}
        for sev, items in rs.items():
            if sev not in counts:
                continue
            if isinstance(items, list):
                counts[sev] += len(items)
            elif items:
                counts[sev] += 1
    return counts


def _executive_summary(
    results: dict[str, Any],
    risk_counts: dict[str, int],
) -> dict[str, Any]:
    """Roll up dashboard numbers: risk buckets + coarse signal estimate."""
    critical = risk_counts.get("CRITICAL", 0)
    high = risk_counts.get("HIGH", 0)
    medium = risk_counts.get("MEDIUM", 0)
    low = risk_counts.get("LOW", 0)
    info = risk_counts.get("INFO", 0)

    signals = 0
    for _name, data in results.items():
        if not isinstance(data, dict):
            continue
        signals += len(data.get("findings") or [])
        signals += len(data.get("found") or [])
        signals += len(data.get("ports") or [])
        signals += len(data.get("hosts") or [])
        signals += len(data.get("emails") or [])
        signals += len(data.get("endpoints") or [])
        hm = data.get("methods") or {}
        if isinstance(hm, dict):
            for _ep, block in hm.items():
                if isinstance(block, dict):
                    signals += len(block.get("methods_tested") or {})
    if signals == 0:
        signals = max(1, critical + high + medium + low + len(results))

    total_risk = max(1, critical + high + medium + low + info)
    return {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "total_findings": signals,
        "critical_pct": round(100 * critical / total_risk, 2),
        "high_pct": round(100 * high / total_risk, 2),
        "medium_pct": round(100 * medium / total_risk, 2),
        "low_pct": round(100 * low / total_risk, 2),
        "info_pct": round(100 * info / total_risk, 2),
    }


def _risk_color(r: str | None) -> str:
    return {
        "CRITICAL": "#ff4444",
        "HIGH": "#ffa500",
        "MEDIUM": "#ffcc00",
        "LOW": "#58a6ff",
        "INFO": "#8b949e",
    }.get((r or "").upper(), "#8b949e")


def _format_size(s: Any) -> str:
    if not isinstance(s, (int, float)):
        return str(s)
    if s > 1024 * 1024:
        return f"{s / 1024 / 1024:.1f}MB"
    if s > 1024:
        return f"{s / 1024:.1f}KB"
    return f"{int(s)}B"


def _json_pretty(obj: Any) -> Markup:
    """Serialize module payload for HTML — escapes so safe inside autoescape."""
    try:
        text = json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        text = str(obj)
    return Markup(f'<pre class="json-dump">{escape(text)}</pre>')


def generate(session: dict[str, Any], output_dir: str | Path) -> str:
    """
    Write report.html using templates/report.html.j2.
    Returns absolute path to the file.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    output_path = out / "report.html"

    template_dir = Path(__file__).resolve().parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=True,
    )
    env.filters["risk_color"] = _risk_color
    env.filters["format_size"] = _format_size
    env.filters["json_pretty"] = _json_pretty

    template = env.get_template("report.html.j2")
    redacted_session = redact_dict(copy.deepcopy(session))
    _res = redacted_session.get("results")
    if isinstance(_res, dict):
        redacted_session["results"] = truncate_report_results(_res)
    res = redacted_session.get("results") or {}
    if not isinstance(res, dict):
        res = {}
    risk_counts = count_findings_by_risk(res)
    summary = _executive_summary(res, risk_counts)

    html = template.render(
        session=redacted_session,
        results=res,
        summary=summary,
        risk_counts=risk_counts,
        module_labels=MODULE_LABELS,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        version=getattr(app_config, "VERSION", "1.6.0"),
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return str(output_path.resolve())
