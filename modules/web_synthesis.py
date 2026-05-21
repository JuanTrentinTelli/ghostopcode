"""
GhostOpcode web synthesis — correlate dir_enum, url_harvester, and js_recon into one attack-surface view.
"""

from __future__ import annotations
from utils.theme import C_PRI, C_DIM, C_WARN, C_MUTED, C_PANEL, console

import time
from collections import defaultdict
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

from rich import box
from rich.table import Table
from rich.text import Text

from modules.url_harvester import GF_PATTERNS
from utils.base_module import make_finding
from utils.target_parser import Target

_SOURCE_MODULES = ("dir_enum", "url_harvester", "js_recon")

_VULN_CATEGORY_HINTS: dict[str, str] = {
    "sqli": "SQLi candidate",
    "lfi": "LFI candidate",
    "ssrf": "SSRF candidate",
    "rce": "RCE candidate",
    "xss": "XSS candidate",
    "idor": "IDOR candidate",
    "open_redirect": "Open redirect candidate",
    "sensitive_files": "Sensitive file pattern",
    "api_endpoints": "API pattern",
    "js_files": "JS asset",
}

# CRITICAL in synthesis for url_harvester only when these param-based patterns match.
_CRITICAL_PARAM_VULN_CATEGORIES: frozenset[str] = frozenset(
    {"sqli", "lfi", "ssrf", "rce", "xss", "idor"}
)

_STRIP_EXT = (".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".jspx")


def _infer_base_url(target: Target, session_results: dict[str, Any]) -> str:
    for key in ("dir_enum", "js_recon", "http_methods", "waf_detect", "httpx_probe"):
        mod = session_results.get(key)
        if isinstance(mod, dict):
            bu = mod.get("base_url")
            if bu and isinstance(bu, str) and bu.strip():
                return bu.strip().rstrip("/")
    host = target.value.strip()
    return f"https://{host}"


def _normalize_path(path: str) -> str:
    try:
        if not path or not str(path).strip():
            return "/"
        p = str(path).strip()
        if "://" in p:
            p = urlparse(p).path or "/"
        p = p.split("?")[0].split("#")[0]
        p = p.strip() or "/"
        if not p.startswith("/"):
            p = "/" + p
        return p.rstrip("/").lower() or "/"
    except Exception:  # noqa: BLE001
        return "/"


def _dedupe_path_key(path: str) -> str:
    n = _normalize_path(path)
    if n == "/":
        return n
    for ext in _STRIP_EXT:
        if n.endswith(ext):
            n = n[: -len(ext)] or "/"
            break
    return n


def _risk_rank(r: str) -> int:
    order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    rup = str(r or "LOW").upper()
    try:
        return order.index(rup)
    except ValueError:
        return len(order)


def extract_from_dir_enum(module_data: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    found = module_data.get("found")
    if isinstance(found, list) and found:
        rows.extend(x for x in found if isinstance(x, dict))
    if not rows:
        for tier in (
            "critical_findings",
            "high_findings",
            "medium_findings",
            "low_findings",
        ):
            for f in module_data.get(tier) or []:
                if isinstance(f, dict):
                    rows.append(f)

    base = base_url.rstrip("/") + "/"
    for row in rows:
        path = str(row.get("path") or "").strip()
        url = str(row.get("url") or "").strip()
        if not path and url:
            path = urlparse(url).path or "/"
        if not path and not url:
            continue
        val = url if url else path
        if not val.startswith("http"):
            full_url = urljoin(base, path.lstrip("/") if path.startswith("/") else path)
        else:
            full_url = url
        try:
            st = row.get("status")
            status = int(st) if st is not None and str(st).isdigit() else None
        except (TypeError, ValueError):
            status = None
        risk = str(row.get("risk") or "LOW").upper()
        ep: dict[str, Any] = {
            "path": _normalize_path(path or urlparse(full_url).path or "/"),
            "full_url": full_url,
            "params": [],
            "sources": ["dir_enum"],
            "status": status,
            "risk": risk,
            "vuln_hints": [],
            "method": "GET",
        }
        if row.get("source"):
            ep["dir_enum_engine"] = row["source"]
        endpoints.append(ep)
    return endpoints


def _path_has_sensitive_extension(path: str) -> bool:
    """True if path ends with a suffix from url_harvester sensitive_files (e.g. .bak, .env)."""
    p = (path or "").lower().split("?")[0]
    exts = (GF_PATTERNS.get("sensitive_files") or {}).get("extensions") or []
    return any(p.endswith(str(e).lower()) for e in exts)


def _normalize_url_harvester_risk(
    risk: str,
    category: str,
    params: list[str],
    path: str,
) -> str:
    """
    url_harvester marks some path-heuristic rows as CRITICAL (e.g. sensitive_url).
    Synthesis only keeps CRITICAL for param-based vuln classes (SQLi, LFI, …).
    """
    r = str(risk or "LOW").upper()
    cat = (category or "").lower().strip()
    has_params = bool(params)

    if r != "CRITICAL":
        return r

    if cat in ("sensitive_url", "sensitive_path"):
        return "HIGH"

    if not has_params:
        if _path_has_sensitive_extension(path):
            return "HIGH"
        return "MEDIUM"

    if cat not in _CRITICAL_PARAM_VULN_CATEGORIES:
        return "HIGH"

    return "CRITICAL"


def _url_harvester_hints(category: str) -> list[str]:
    cat = (category or "").lower()
    if cat in ("sensitive_url", "sensitive_path"):
        return []
    hints: list[str] = []
    for key, label in _VULN_CATEGORY_HINTS.items():
        if key in cat:
            hints.append(label)
    if not hints and cat:
        hints.append(cat.replace("_", " "))
    return list(dict.fromkeys(hints))


def extract_from_url_harvester(module_data: dict[str, Any]) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    flat = module_data.get("findings_flat")
    if isinstance(flat, list):
        for f in flat:
            if not isinstance(f, dict):
                continue
            value = str(f.get("value") or "").strip()
            if not value:
                continue
            cat = str(f.get("category") or "")
            key = (value.lower(), cat)
            if key in seen:
                continue
            seen.add(key)
            parsed = urlparse(value)
            path = parsed.path or "/"
            params = list(parse_qs(parsed.query).keys()) if parsed.query else []
            risk = _normalize_url_harvester_risk(
                str(f.get("risk") or "LOW"), cat, params, path
            )
            endpoints.append(
                {
                    "path": _normalize_path(path),
                    "full_url": value,
                    "params": params,
                    "sources": ["url_harvester"],
                    "status": None,
                    "risk": risk,
                    "vuln_hints": _url_harvester_hints(cat),
                    "method": "GET",
                }
            )
        return endpoints

    findings = module_data.get("findings")
    if isinstance(findings, dict):
        for pname, urls in findings.items():
            if not isinstance(urls, list):
                continue
            pdata = GF_PATTERNS.get(pname) or {}
            pdata_risk = str(pdata.get("risk") or "MEDIUM").upper()
            for u in urls:
                if not isinstance(u, str) or not u.strip():
                    continue
                value = u.strip()
                key = (value.lower(), str(pname))
                if key in seen:
                    continue
                seen.add(key)
                parsed = urlparse(value)
                path = parsed.path or "/"
                params = list(parse_qs(parsed.query).keys()) if parsed.query else []
                pname_s = str(pname)
                risk = _normalize_url_harvester_risk(
                    pdata_risk, pname_s, params, path
                )
                endpoints.append(
                    {
                        "path": _normalize_path(path),
                        "full_url": value,
                        "params": params,
                        "sources": ["url_harvester"],
                        "status": None,
                        "risk": risk,
                        "vuln_hints": _url_harvester_hints(pname_s),
                        "method": "GET",
                    }
                )
    return endpoints


def extract_from_js_recon(module_data: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    base = base_url.rstrip("/") + "/"
    eps = module_data.get("endpoints")
    if not isinstance(eps, list):
        return endpoints

    for ep in eps:
        if not isinstance(ep, dict):
            continue
        value = str(ep.get("url") or "").strip()
        if not value:
            continue
        category = str(ep.get("category") or "js_endpoint")
        risk = str(ep.get("risk") or "LOW").upper()
        if value.startswith("http"):
            parsed = urlparse(value)
            path = parsed.path or "/"
            params = list(parse_qs(parsed.query).keys()) if parsed.query else []
            full_url = value
        else:
            path = value
            params = []
            full_url = urljoin(base, value.lstrip("/"))
        vuln_hints: list[str] = []
        cl = category.lower()
        if "secret" in cl or "token" in cl:
            vuln_hints.append("hardcoded secret")
        if "api" in cl:
            vuln_hints.append("API endpoint")
        endpoints.append(
            {
                "path": _normalize_path(path),
                "full_url": full_url,
                "params": params,
                "sources": ["js_recon"],
                "status": None,
                "risk": risk,
                "vuln_hints": vuln_hints,
                "method": "unknown",
            }
        )
    return endpoints


def correlate_endpoints(all_endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}

    for ep in all_endpoints:
        key = _dedupe_path_key(ep.get("path") or "/")
        if key == "/" and not ep.get("full_url"):
            continue

        if key not in merged:
            m = dict(ep)
            m["sources"] = list(ep.get("sources") or [])
            m["params"] = list(ep.get("params") or [])
            m["vuln_hints"] = list(ep.get("vuln_hints") or [])
            m["path"] = ep.get("path") or key
            merged[key] = m
            continue

        ex = merged[key]
        for src in ep.get("sources") or []:
            if src not in ex["sources"]:
                ex["sources"].append(src)
        for p in ep.get("params") or []:
            if p not in ex["params"]:
                ex["params"].append(p)
        for hint in ep.get("vuln_hints") or []:
            if hint not in ex["vuln_hints"]:
                ex["vuln_hints"].append(hint)

        if _risk_rank(ep.get("risk")) < _risk_rank(ex.get("risk")):
            ex["risk"] = ep["risk"]

        if ep.get("status") is not None and ex.get("status") is None:
            ex["status"] = ep["status"]

        fu = str(ep.get("full_url") or "")
        if fu and len(fu) > len(str(ex.get("full_url") or "")):
            ex["full_url"] = fu

    result: list[dict[str, Any]] = []
    for _k, ep in merged.items():
        ep["source_count"] = len(ep["sources"])
        ep["interest_score"] = (
            len(ep["sources"]) * 2
            + len(ep["vuln_hints"]) * 3
            + len(ep["params"]) * 1
            + {0: 10, 1: 5, 2: 2, 3: 0, 4: 0}.get(_risk_rank(ep.get("risk")), 0)
        )
        result.append(ep)

    result.sort(key=lambda x: (-int(x.get("interest_score") or 0), x.get("path") or ""))
    return result


def _display_synthesis(synthesized: list[dict[str, Any]], quiet: bool) -> None:
    if quiet or not synthesized:
        return

    console.print()
    console.print(Text(" [WEB SYNTHESIS] Consolidated attack surface", style=f"bold {C_DIM}"))

    top = synthesized[:20]
    tbl = Table(box=box.SIMPLE_HEAD, show_header=True, border_style=C_PANEL)
    tbl.add_column("Path / URL", style=C_DIM, no_wrap=False, max_width=42)
    tbl.add_column("Sources", style=C_MUTED, max_width=22)
    tbl.add_column("Params", style=C_MUTED, max_width=12)
    tbl.add_column("Vuln hints", style=C_WARN, max_width=22)
    tbl.add_column("Risk", justify="center", width=10)

    for ep in top:
        rsk = str(ep.get("risk") or "LOW")
        risk_style = {
            "CRITICAL": "bold #FF3B3B",
            "HIGH": "bold #E8C547",
            "MEDIUM": C_DIM,
            "LOW": C_MUTED,
        }.get(rsk, C_MUTED)

        path = str(ep.get("path") or "/")
        display = path if len(path) <= 42 else path[:39] + "..."
        if int(ep.get("source_count") or 0) >= 2:
            display_cell = Text(display, style="bold")
        else:
            display_cell = Text(display, style=C_DIM)

        sources = " + ".join(ep.get("sources") or [])
        params = ", ".join((ep.get("params") or [])[:3]) or "—"
        hints_l = ep.get("vuln_hints") or []
        hints = ", ".join(hints_l[:2]) if hints_l else "—"

        tbl.add_row(
            display_cell,
            sources[:22] + ("…" if len(sources) > 22 else ""),
            params[:12] + ("…" if len(params) > 12 else ""),
            hints[:22] + ("…" if len(hints) > 22 else ""),
            Text(rsk, style=risk_style),
        )
    console.print(tbl)

    if len(synthesized) > 20:
        console.print(
            Text(
                f" … and {len(synthesized) - 20} more (HTML / JSON export)",
                style=C_MUTED,
            )
        )

    multi_source = [e for e in synthesized if int(e.get("source_count") or 0) >= 2]
    if multi_source:
        console.print()
        console.print(
            Text(
                f" [INTEL] {len(multi_source)} endpoint(s) confirmed by 2+ sources:",
                style=C_PRI,
            )
        )
        for ep in multi_source[:5]:
            console.print(
                Text.assemble(
                    ("   · ", C_MUTED),
                    (str(ep.get("path") or "/"), C_DIM),
                    ("  (", C_MUTED),
                    (" + ".join(ep.get("sources") or []), C_MUTED),
                    (")", C_MUTED),
                )
            )


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Merge web attack-surface signals from dir_enum, url_harvester, and js_recon.

    Reads ``config["session_results"]`` (packed module dicts). Never raises.
    """
    t0 = time.perf_counter()
    quiet = bool(config.get("quiet", False))
    domain = target.value.strip()

    base: dict[str, Any] = {
        "module": "web_synthesis",
        "target": domain,
        "status": "success",
        "errors": [],
        "warnings": [],
        "synthesized": [],
        "total_unique": 0,
        "multi_source": 0,
        "vuln_hints_total": 0,
        "sources_used": [],
        "top_endpoints": [],
        "stats": {
            "raw_extracted": 0,
            "total_unique": 0,
            "multi_source": 0,
            "vuln_hints_total": 0,
            "duration_s": 0.0,
        },
        "findings_flat": [],
    }

    if target.is_cidr():
        base["status"] = "skipped"
        base["warnings"].append("Web synthesis requires a domain or single IP target.")
        if not quiet:
            console.print(
                Text("  [SKIP] Web synthesis — CIDR not supported.", style=C_WARN)
            )
        return base

    session_results = config.get("session_results")
    if not isinstance(session_results, dict):
        session_results = {}

    available: list[str] = []
    for mod in _SOURCE_MODULES:
        data = session_results.get(mod)
        if isinstance(data, dict) and data.get("status") == "success":
            available.append(mod)

    if not available:
        base["status"] = "skipped"
        msg = (
            "No source modules in session. Run [5] dir_enum, [11] url_harvester, "
            "and/or [8] js_recon first."
        )
        base["warnings"].append(msg)
        if not quiet:
            console.print()
            console.print(
                Text(" [i] No web source data in session.", style=C_WARN)
            )
            console.print(
                Text(
                    "     Run one or more of: [5] dir_enum · [11] url_harvester · [8] js_recon",
                    style=C_MUTED,
                )
            )
        return base

    base_url = _infer_base_url(target, session_results)

    if not quiet:
        console.print()
        console.print(
            Text(
                f" [►] Synthesizing web surface from: {' · '.join(available)}",
                style=f"bold {C_DIM}",
            )
        )

    all_eps: list[dict[str, Any]] = []

    if "dir_enum" in available:
        eps = extract_from_dir_enum(session_results["dir_enum"], base_url)
        all_eps.extend(eps)
        if not quiet:
            console.print(Text(f"     dir_enum        → {len(eps):,} paths", style=C_MUTED))

    if "url_harvester" in available:
        eps = extract_from_url_harvester(session_results["url_harvester"])
        all_eps.extend(eps)
        if not quiet:
            console.print(
                Text(f"     url_harvester   → {len(eps):,} URLs", style=C_MUTED)
            )

    if "js_recon" in available:
        eps = extract_from_js_recon(session_results["js_recon"], base_url)
        all_eps.extend(eps)
        if not quiet:
            console.print(Text(f"     js_recon        → {len(eps):,} endpoints", style=C_MUTED))

    base["stats"]["raw_extracted"] = len(all_eps)
    base["sources_used"] = list(available)

    if not quiet:
        console.print(
            Text(
                f"\n [►] Correlating {len(all_eps):,} raw entries...",
                style=f"bold {C_DIM}",
            )
        )

    synthesized = correlate_endpoints(all_eps)
    multi_source = [e for e in synthesized if int(e.get("source_count") or 0) >= 2]
    vuln_rows = [e for e in synthesized if e.get("vuln_hints")]

    base["synthesized"] = synthesized[:500]
    base["total_unique"] = len(synthesized)
    base["multi_source"] = len(multi_source)
    base["vuln_hints_total"] = len(vuln_rows)
    base["top_endpoints"] = synthesized[:20]
    base["stats"]["total_unique"] = len(synthesized)
    base["stats"]["multi_source"] = len(multi_source)
    base["stats"]["vuln_hints_total"] = len(vuln_rows)
    base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)

    if not quiet:
        console.print(
            Text(
                f" [✓] {len(synthesized):,} unique endpoints "
                f"({len(multi_source)} multi-source · {len(vuln_rows)} with vuln hints)",
                style=C_PRI,
            )
        )

    findings_flat: list[dict[str, Any]] = []
    for ep in synthesized:
        risk = str(ep.get("risk") or "LOW").upper()
        sources = " + ".join(ep.get("sources") or [])
        hints = ", ".join(ep.get("vuln_hints") or [])
        params = ep.get("params") or []
        note = f"Sources: {sources}"
        if hints:
            note = f"{note} | {hints}"
        if params:
            note = f"{note} | params: {', '.join(str(p) for p in params[:5])}"
        val = str(ep.get("full_url") or ep.get("path") or "/")
        findings_flat.append(
            make_finding(
                value=val,
                category="web_surface",
                risk=risk,
                note=note,
                metadata=dict(ep),
            )
        )
    base["findings_flat"] = findings_flat

    _display_synthesis(synthesized, quiet)

    if not quiet:
        console.print()
        console.print(Text(" [✓] Web synthesis complete", style=f"bold {C_PRI}"))

    return base
