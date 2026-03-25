"""
GhostOpcode URL harvester — historical and passive URLs (Wayback, Common Crawl, OTX, optional gau).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from config import DEFAULT_TIMEOUT
from utils.output import detect_sensitive_in_url, display_findings
from utils.target_parser import Target

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_PANEL = "#8B9CA8"

console = Console(highlight=False, force_terminal=True)

# Hard cap on merged URL list before deduplication (operator machine safety)
MAX_URLS_TOTAL = 10_000

# GF-style patterns as data (no scattered regex strings)
GF_PATTERNS: dict[str, dict[str, Any]] = {
    "sqli": {
        "description": "SQL Injection candidates",
        "risk": "CRITICAL",
        "params": [
            "id",
            "user",
            "pass",
            "search",
            "query",
            "order",
            "sort",
            "cat",
            "type",
            "name",
            "item",
            "product",
            "category",
            "page",
        ],
        "regex": r"[?&](?:id|user|pass|search|query|order|sort|"
        r"cat|type|name|item|product|category|page)=",
    },
    "xss": {
        "description": "Cross-Site Scripting candidates",
        "risk": "HIGH",
        "params": [
            "q",
            "s",
            "search",
            "query",
            "keyword",
            "term",
            "lang",
            "ref",
            "redirect",
            "url",
            "next",
            "back",
            "return",
            "r",
            "target",
        ],
        "regex": r"[?&](?:q|s|search|query|keyword|term|lang|"
        r"ref|redirect|url|next|back|return|r|target)=",
    },
    "open_redirect": {
        "description": "Open Redirect candidates",
        "risk": "HIGH",
        "params": [
            "redirect",
            "url",
            "next",
            "return",
            "returnUrl",
            "goto",
            "target",
            "redir",
            "destination",
            "continue",
            "forward",
        ],
        "regex": r"[?&](?:redirect|url|next|return|returnUrl|"
        r"goto|target|redir|destination|continue|forward)=",
    },
    "lfi": {
        "description": "Local File Inclusion candidates",
        "risk": "CRITICAL",
        "params": [
            "file",
            "path",
            "page",
            "include",
            "template",
            "doc",
            "folder",
            "root",
            "dir",
            "inc",
            "locate",
            "show",
            "load",
        ],
        "regex": r"[?&](?:file|path|page|include|template|"
        r"doc|folder|root|dir|inc|locate|show|load)=",
    },
    "ssrf": {
        "description": "Server-Side Request Forgery candidates",
        "risk": "CRITICAL",
        "params": [
            "url",
            "uri",
            "src",
            "source",
            "dest",
            "destination",
            "link",
            "target",
            "host",
            "proxy",
            "fetch",
            "request",
            "api",
        ],
        "regex": r"[?&](?:url|uri|src|source|dest|destination|"
        r"link|target|host|proxy|fetch|request|api)=",
    },
    "rce": {
        "description": "Remote Code Execution candidates",
        "risk": "CRITICAL",
        "params": [
            "cmd",
            "exec",
            "command",
            "execute",
            "ping",
            "query",
            "jump",
            "code",
            "reg",
            "do",
            "func",
            "arg",
            "option",
            "load",
            "process",
            "step",
            "read",
            "function",
        ],
        "regex": r"[?&](?:cmd|exec|command|execute|ping|query|"
        r"jump|code|reg|do|func|arg|option|load|"
        r"process|step|read|function)=",
    },
    "idor": {
        "description": "Insecure Direct Object Reference candidates",
        "risk": "HIGH",
        "params": [
            "id",
            "user_id",
            "account",
            "number",
            "order",
            "no",
            "doc",
            "key",
            "email",
            "group",
            "profile",
            "edit",
            "delete",
        ],
        "regex": r"[?&](?:id|user_id|account|number|order|no|"
        r"doc|key|email|group|profile|edit|delete)=\d+",
    },
    "sensitive_files": {
        "description": "Sensitive file extensions",
        "risk": "HIGH",
        "extensions": [
            ".sql",
            ".bak",
            ".backup",
            ".old",
            ".log",
            ".txt",
            ".xml",
            ".json",
            ".csv",
            ".config",
            ".conf",
            ".env",
            ".yml",
            ".yaml",
            ".key",
            ".pem",
            ".cer",
            ".p12",
        ],
        "regex": r"\.(sql|bak|backup|old|log|txt|xml|json|csv|"
        r"config|conf|env|yml|yaml|key|pem|cer|p12)(?:\?|$)",
    },
    "js_files": {
        "description": "JavaScript files for analysis",
        "risk": "MEDIUM",
        "regex": r"\.js(?:\?|$)",
    },
    "api_endpoints": {
        "description": "API endpoints discovered",
        "risk": "MEDIUM",
        "regex": r"/api/|/v\d+/|/rest/|/graphql|/swagger",
    },
}

_PATTERN_ORDER_BY_RISK: list[str] = [
    "sqli",
    "lfi",
    "ssrf",
    "rce",
    "xss",
    "open_redirect",
    "idor",
    "sensitive_files",
    "js_files",
    "api_endpoints",
]


def fetch_wayback(domain: str, timeout: int, errors: list[str]) -> list[str]:
    """
    Fetch historical URLs from Wayback Machine CDX API (no external tools).

    Queries both the exact host and wildcard subdomains when the name looks
    like an apex domain (single dot in the hostname part).
    """
    base = "http://web.archive.org/cdx/search/cdx"
    urls: set[str] = set()
    # Primary: the FQDN the operator entered
    url_specs = [f"{domain}/*"]
    labels = domain.count(".")
    if labels == 1:
        url_specs.append(f"*.{domain}/*")

    per_query_limit = 4000 if len(url_specs) == 1 else 2500

    for url_spec in url_specs:
        params: dict[str, str | int] = {
            "url": url_spec,
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": per_query_limit,
            "filter": "statuscode:200",
        }
        try:
            resp = requests.get(base, params=params, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list) and len(data) > 1:
                for row in data[1:]:
                    if isinstance(row, list) and row and row[0]:
                        urls.add(str(row[0]).strip())
        except Exception as e:  # noqa: BLE001
            errors.append(f"Wayback ({url_spec}): {e}")

    return list(urls)


def fetch_commoncrawl(domain: str, timeout: int, errors: list[str]) -> list[str]:
    """
    Fetch URLs from the latest Common Crawl CDX index (HTTP JSON lines).
    """
    index_url = "https://index.commoncrawl.org/collinfo.json"
    latest: str | None = None
    try:
        r = requests.get(index_url, timeout=timeout)
        r.raise_for_status()
        indexes = r.json()
        if isinstance(indexes, list) and indexes:
            latest = indexes[0].get("cdx-api")
            if not latest and indexes[0].get("id"):
                latest = (
                    f"https://index.commoncrawl.org/{indexes[0]['id']}-index"
                )
    except Exception as e:  # noqa: BLE001
        errors.append(f"Common Crawl collinfo: {e}")
        latest = "https://index.commoncrawl.org/CC-MAIN-2024-10-index"

    if not latest:
        errors.append("Common Crawl: no index endpoint resolved")
        return []

    params = {
        "url": f"*.{domain}",
        "output": "json",
        "fl": "url",
        "limit": 2000,
    }
    # Also query bare host for single-label style indexes
    urls: set[str] = set()
    for url_pat in (f"*.{domain}", domain):
        params["url"] = url_pat
        try:
            resp = requests.get(latest, params=params, timeout=timeout)
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    u = obj.get("url")
                    if u:
                        urls.add(str(u).strip())
                except json.JSONDecodeError:
                    continue
        except Exception as e:  # noqa: BLE001
            errors.append(f"Common Crawl query ({url_pat}): {e}")

    return list(urls)


def fetch_alienvault(domain: str, timeout: int, errors: list[str]) -> list[str]:
    """
    Fetch URLs from AlienVault OTX URL list for the indicator (domain).
    """
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
    params = {"limit": 500, "page": 1}
    urls: list[str] = []
    try:
        resp = requests.get(url, params=params, timeout=timeout)
        if resp.status_code == 429:
            errors.append("AlienVault OTX: rate limited (429)")
            return []
        if resp.status_code == 403:
            errors.append("AlienVault OTX: forbidden (403) — may require API key")
            return []
        resp.raise_for_status()
        data = resp.json()
        for entry in data.get("url_list") or []:
            if isinstance(entry, dict) and entry.get("url"):
                urls.append(str(entry["url"]).strip())
    except Exception as e:  # noqa: BLE001
        errors.append(f"AlienVault OTX: {e}")
    return list(dict.fromkeys(urls))


def fetch_gau(domain: str, timeout: int, errors: list[str]) -> list[str]:
    """
    Run gau (Get All URLs) if present on PATH; aggregates multiple sources.
    """
    if not shutil.which("gau"):
        return []
    try:
        result = subprocess.run(
            ["gau", "--subs", domain],
            capture_output=True,
            text=True,
            timeout=min(120, max(timeout * 4, 60)),
        )
        if result.returncode != 0 and result.stderr:
            errors.append(f"gau stderr: {result.stderr[:200]}")
        lines = [u.strip() for u in result.stdout.splitlines() if u.strip()]
        return list(dict.fromkeys(lines))
    except subprocess.TimeoutExpired:
        errors.append("gau: subprocess timeout")
    except Exception as e:  # noqa: BLE001
        errors.append(f"gau: {e}")
    return []


def deduplicate_urls(urls: list[str]) -> list[str]:
    """
    Deduplicate URLs by host + path + sorted query parameter *names* (values
    collapsed) so /user?id=1 and /user?id=999 count as one attack surface.
    """
    seen_patterns: set[str] = set()
    unique: list[str] = []

    for url in urls:
        u = url.strip()
        if not u:
            continue
        try:
            parsed = urlparse(u)
            params = parse_qs(parsed.query, keep_blank_values=True)
            param_names = ",".join(sorted(params.keys()))
            if param_names:
                pattern = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_names}"
            else:
                pattern = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if pattern not in seen_patterns:
                seen_patterns.add(pattern)
                unique.append(u)
        except Exception:  # noqa: BLE001
            if u not in unique:
                unique.append(u)

    return unique


def filter_urls(urls: list[str]) -> dict[str, list[str]]:
    """
    Bucket URLs by GF-style vulnerability patterns (regex from GF_PATTERNS).
    """
    results: dict[str, list[str]] = {k: [] for k in GF_PATTERNS}
    compiled: dict[str, re.Pattern[str]] = {}
    for name, pdata in GF_PATTERNS.items():
        rx = pdata.get("regex", "")
        if rx:
            try:
                compiled[name] = re.compile(rx, re.IGNORECASE)
            except re.error:
                continue

    for url in urls:
        for pattern_name, cre in compiled.items():
            if cre.search(url):
                bucket = results[pattern_name]
                if url not in bucket:
                    bucket.append(url)

    return {k: v for k, v in results.items() if v}


def _merge_and_cap(parts: list[list[str]], max_total: int) -> list[str]:
    """Merge URL lists preserving first-seen order, dedupe by string, cap to max_total."""
    seen: set[str] = set()
    merged: list[str] = []
    for part in parts:
        for u in part:
            if u not in seen:
                seen.add(u)
                merged.append(u)
                if len(merged) >= max_total:
                    return merged
    return merged


def _build_risk_summary(findings: dict[str, list[str]]) -> dict[str, list[str]]:
    """Roll pattern buckets into severity lists for reporting."""
    out: dict[str, list[str]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for pname, urls in findings.items():
        pdata = GF_PATTERNS.get(pname) or {}
        risk = str(pdata.get("risk") or "INFO").upper()
        desc = str(pdata.get("description") or pname)
        n = len(urls)
        line = f"{pname}: {n} — {desc}"
        if risk in out:
            out[risk].append(line)
        else:
            out.setdefault("INFO", []).append(line)
    return out


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Harvest historical/passive URLs for a domain from public sources.

    Skips non-domain targets. Never raises; errors are appended to ``errors``.
    """
    t0 = time.perf_counter()
    timeout = int(config.get("timeout") or DEFAULT_TIMEOUT)
    timeout = max(3, timeout)
    verbose = bool(config.get("verbose"))
    errors: list[str] = []

    base: dict[str, Any] = {
        "module": "url_harvester",
        "target": target.value,
        "status": "success",
        "sources": {
            "wayback": {"count": 0, "available": True},
            "commoncrawl": {"count": 0, "available": True},
            "alienvault": {"count": 0, "available": True},
            "gau": {"count": 0, "available": bool(shutil.which("gau"))},
        },
        "total_urls": 0,
        "unique_urls": 0,
        "findings": {},
        "stats": {},
        "errors": errors,
        "risk_summary": {},
    }

    domain = target.value.lower().strip()

    subtitle = f"{domain}  ·  historical + live"
    console.print(
        Panel(
            Text.assemble(
                (" URL HARVESTER  ·  ", f"bold {C_PRI}"),
                (subtitle, C_DIM),
            ),
            border_style=C_PANEL,
            box=box.HEAVY,
            padding=(0, 1),
            width=min(console.size.width, 80) if console.size else 80,
        )
    )

    if not target.is_domain():
        base["status"] = "skipped"
        console.print(
            Text("  [SKIP] URL harvester — domain targets only.", style=C_WARN)
        )
        return base

    # --- Collect ----------------------------------------------------------------
    console.print()
    wb = fetch_wayback(domain, timeout, errors)
    base["sources"]["wayback"]["count"] = len(wb)
    console.print(
        Text.assemble(
            (" [1/4] Wayback Machine...     ", C_DIM),
            (f"{len(wb)} URLs", C_PRI if wb else C_MUTED),
        )
    )

    cc = fetch_commoncrawl(domain, timeout, errors)
    base["sources"]["commoncrawl"]["count"] = len(cc)
    console.print(
        Text.assemble(
            (" [2/4] Common Crawl...        ", C_DIM),
            (f"{len(cc)} URLs", C_PRI if cc else C_MUTED),
        )
    )

    otx = fetch_alienvault(domain, timeout, errors)
    base["sources"]["alienvault"]["count"] = len(otx)
    console.print(
        Text.assemble(
            (" [3/4] AlienVault OTX...       ", C_DIM),
            (f"{len(otx)} URLs", C_PRI if otx else C_MUTED),
        )
    )

    gau_urls: list[str] = []
    if base["sources"]["gau"]["available"]:
        gau_urls = fetch_gau(domain, timeout, errors)
    base["sources"]["gau"]["count"] = len(gau_urls)
    gau_line = f"{len(gau_urls)} URLs" if gau_urls else "n/a (not installed)"
    if not base["sources"]["gau"]["available"]:
        gau_line = "n/a (not installed)"
    console.print(
        Text.assemble(
            (" [4/4] GAU...                  ", C_DIM),
            (gau_line, C_MUTED if not gau_urls else C_PRI),
        )
    )

    raw_pull_total = len(wb) + len(cc) + len(otx) + len(gau_urls)
    merged = _merge_and_cap([wb, cc, otx, gau_urls], MAX_URLS_TOTAL)
    base["total_urls"] = len(merged)
    unique = deduplicate_urls(merged)
    base["unique_urls"] = len(unique)

    console.print(Text(f"       {'─' * 36}", style=C_MUTED))
    console.print(
        Text.assemble(
            ("       Total: ", C_DIM),
            (f"{len(merged)}", C_PRI),
            (" → ", C_MUTED),
            (f"{len(unique)} unique after dedup", C_DIM),
        )
    )

    if len(merged) >= MAX_URLS_TOTAL:
        errors.append(
            f"URL list capped at {MAX_URLS_TOTAL} (merged); increase cap in module if needed"
        )

    findings = filter_urls(unique)
    base["findings"] = findings
    base["risk_summary"] = _build_risk_summary(findings)

    stats: dict[str, Any] = {
        "total_collected": raw_pull_total,
        "after_dedup": len(unique),
        "duration_s": round(time.perf_counter() - t0, 2),
    }
    for pname in GF_PATTERNS:
        stats[pname] = len(findings.get(pname, []))
    base["stats"] = stats

    # --- Scan every URL for secrets in path/query (all collected, deduped) -----
    sensitive_by_url: dict[str, str] = {}
    for u in unique:
        sn = detect_sensitive_in_url(u)
        if sn:
            sensitive_by_url[u] = sn
    sensitive_set = set(sensitive_by_url.keys())
    stats["sensitive_url"] = len(sensitive_by_url)
    base["stats"] = stats

    findings_flat: list[dict[str, Any]] = []
    for u, sn in sensitive_by_url.items():
        findings_flat.append(
            {
                "risk": "CRITICAL",
                "category": "sensitive_url",
                "value": u,
                "note": sn,
            }
        )

    for pname, urls in findings.items():
        pdata = GF_PATTERNS[pname]
        base_risk = str(pdata.get("risk") or "MEDIUM").upper()
        desc = str(pdata.get("description") or pname)
        for u in urls:
            if u in sensitive_set:
                continue
            findings_flat.append(
                {
                    "risk": base_risk,
                    "category": pname,
                    "value": u,
                    "note": desc,
                }
            )

    # --- Filter report -----------------------------------------------------------
    console.print()
    console.print(Text(" [FILTER] Applying vulnerability patterns...", style=f"bold {C_DIM}"))
    console.print()

    _risk_style = {
        "CRITICAL": C_ERR,
        "HIGH": C_WARN,
        "MEDIUM": C_DIM,
        "LOW": C_MUTED,
    }
    for pname in _PATTERN_ORDER_BY_RISK:
        if pname not in findings:
            continue
        pdata = GF_PATTERNS[pname]
        risk = str(pdata.get("risk") or "INFO").upper()
        desc = str(pdata.get("description") or pname)
        n = len(findings[pname])
        style = _risk_style.get(risk, C_MUTED)
        console.print(
            Text.assemble(
                (f" [{risk}] ", style),
                (f"{desc[:32]:<32}", C_DIM),
                (f": {n} URLs", style),
            )
        )

    if findings_flat:
        console.print()
        display_findings(
            findings_flat,
            module="url_harvester",
            verbose=verbose,
        )

    crit = sum(1 for f in findings_flat if f.get("risk") == "CRITICAL")
    high = sum(1 for f in findings_flat if f.get("risk") == "HIGH")
    med = sum(1 for f in findings_flat if f.get("risk") == "MEDIUM")

    console.print()
    console.print(Text(" [✓] URL harvester complete", style=f"bold {C_PRI}"))
    console.print(
        Text(
            "     Sources   : Wayback · Common Crawl · AlienVault"
            + (" · GAU" if gau_urls else ""),
            style=C_DIM,
        )
    )
    console.print(
        Text(
            f"     Collected : {len(merged)} URLs → {len(unique)} unique",
            style=C_DIM,
        )
    )
    console.print(
        Text(
            f"     Critical  : {crit}  ·  High: {high}  ·  Medium: {med}",
            style=C_DIM,
        )
    )
    console.print(
        Text(f"     Duration  : {stats['duration_s']}s", style=C_DIM)
    )

    if not merged:
        console.print()
        console.print(
            Text(
                " [i] No URLs returned — check connectivity, rate limits, or try again later.",
                style=C_WARN,
            )
        )
    if not base["sources"]["gau"]["available"]:
        console.print()
        console.print(
            Text(
                " [i] GAU not installed — install for more sources:",
                style=C_MUTED,
            )
        )
        console.print(
            Text(
                "     go install github.com/lc/gau/v2/cmd/gau@latest",
                style=C_MUTED,
            )
        )

    if verbose and findings:
        console.print()
        console.print(
            Text(f" [verbose] {len(findings)} pattern buckets", style=C_MUTED)
        )

    return base
