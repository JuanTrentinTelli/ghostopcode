"""
GhostOpcode WAF / CDN / edge protection detection — passive headers, active probes, timing.
"""

from __future__ import annotations

import time
from typing import Any, Mapping
from urllib.parse import urlparse

import requests
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from config import DEFAULT_TIMEOUT, USER_AGENT
from utils.http_client import make_session, resolve_base_url, session_get
from utils.output import debug_log
from utils.target_parser import Target

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_PANEL = "#8B9CA8"

console = Console(highlight=False, force_terminal=True)

# Sentinel: header must be present with any non-empty value
_ANY: Any = object()

WAF_BLOCK_CODES: frozenset[int] = frozenset({403, 406, 416, 429, 503})

WAF_BLOCK_PATTERNS: tuple[str, ...] = (
    "access denied",
    "blocked",
    "forbidden",
    "security",
    "attack",
    "malicious",
    "waf",
    "firewall",
    "protection",
    "your request has been blocked",
    "please contact the site administrator",
    "request rejected",
    "not acceptable",
    "bad request",
)

# Vendor signatures: headers values are _ANY, a substring, or a list of substrings (any match)
WAF_SIGNATURES: dict[str, dict[str, Any]] = {
    "Cloudflare": {
        "headers": {
            "CF-Ray": _ANY,
            "CF-Cache-Status": _ANY,
            "Server": "cloudflare",
        },
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "confidence": "HIGH",
        "type": "CDN+WAF",
        "note": "Cloudflare — blocks common attacks, rate limits, bot protection",
        "evasion": "Use slow scan, low threads, rotate User-Agents; hunt origin IP if needed",
    },
    "AWS WAF": {
        "headers": {
            "X-Amz-Cf-Id": _ANY,
            "X-Cache": "cloudfront",
            "Via": "cloudfront",
        },
        "confidence": "HIGH",
        "type": "CDN+WAF",
        "note": "AWS WAF + CloudFront edge",
        "evasion": "Review rule groups — misconfigurations are common; test alternate paths",
    },
    "Akamai": {
        "headers": {
            "X-Check-Cacheable": _ANY,
            "X-Akamai-Transformed": _ANY,
            "Server": "akamaighost",
        },
        "confidence": "HIGH",
        "type": "CDN+WAF",
        "note": "Akamai — enterprise CDN and Kona Site Defender possible",
        "evasion": "Encoding and HTTP semantics fuzzing; respect rate limits",
    },
    "Imperva / Incapsula": {
        "headers": {
            "X-Iinfo": _ANY,
            "X-Cdn": "imperva",
        },
        "cookies": ["visid_incap_", "incap_ses_", "nlbi_"],
        "confidence": "HIGH",
        "type": "WAF",
        "note": "Imperva — enterprise WAF, strict rules",
        "evasion": "Encoding bypass, chunked transfer; reduce automated patterns",
    },
    "F5 BIG-IP ASM": {
        "headers": {
            "X-Wa-Info": _ANY,
            "X-Cnection": _ANY,
        },
        "cookies": ["TS", "BIGipServer"],
        "confidence": "HIGH",
        "type": "WAF",
        "note": "F5 BIG-IP — load balancer + ASM",
        "evasion": "Parameter pollution and parser differentials between ASM and origin",
    },
    "ModSecurity": {
        "headers": {
            "Server": ["mod_security", "modsecurity", "apache-coyote"],
        },
        "body_patterns": ["mod_security", "modsecurity", "noyb"],
        "confidence": "HIGH",
        "type": "WAF",
        "note": "ModSecurity — often OWASP CRS; error pages may leak rule ids",
        "evasion": "Encoding, fragmentation, protocol-level variations vs CRS",
    },
    "Sucuri": {
        "headers": {
            "X-Sucuri-Id": _ANY,
            "X-Sucuri-Cache": _ANY,
            "Server": "sucuri",
        },
        "confidence": "HIGH",
        "type": "CDN+WAF",
        "note": "Sucuri — website firewall + CDN",
        "evasion": "Origin discovery; cache poisoning less relevant — focus path bypass",
    },
    "Barracuda": {
        "headers": {
            "X-Barracuda-Connect": _ANY,
            "X-Barracuda-Start-Time": _ANY,
        },
        "cookies": ["barra_counter_session", "bni__barracuda_lb_cookie"],
        "confidence": "HIGH",
        "type": "WAF",
        "note": "Barracuda WAF or ADC in front",
        "evasion": "Slow, varied requests; test API vs HTML surfaces",
    },
    "Fortinet FortiWeb": {
        "headers": {
            "Fortiwafsid": _ANY,
        },
        "cookies": ["FORTIWAFSID"],
        "confidence": "HIGH",
        "type": "WAF",
        "note": "Fortinet FortiWeb",
        "evasion": "Policy-aware fuzzing; watch cookie/session binding",
    },
    "Radware AppWall": {
        "headers": {
            "X-Sl-Compstate": _ANY,
        },
        "cookies": ["slbrts"],
        "confidence": "MEDIUM",
        "type": "WAF",
        "note": "Radware AppWall suspected",
        "evasion": "Throttle automation; vary TLS/JA3 if applicable",
    },
    "Nginx + naxsi": {
        "body_patterns": ["naxsi"],
        "confidence": "MEDIUM",
        "type": "WAF",
        "note": "nginx with NAXSI module",
        "evasion": "Rule-specific bypass research; whitespace and encoding tricks",
    },
    "Wordfence": {
        "body_patterns": ["wordfence"],
        "headers": {
            "X-Wordfence-Cache": _ANY,
        },
        "confidence": "HIGH",
        "type": "WAF",
        "note": "WordPress Wordfence plugin",
        "evasion": "WP-specific vectors; authenticated vs unauthenticated surfaces",
    },
    "Fastly": {
        "headers": {
            "X-Served-By": "cache",
            "X-Cache": _ANY,
            "Via": "varnish",
        },
        "confidence": "MEDIUM",
        "type": "CDN",
        "note": "Fastly / Varnish edge — WAF may be add-on",
        "evasion": "Surrogate-Key and cache semantics; confirm WAF vs CDN-only",
    },
    "StackPath": {
        "headers": {
            "X-Hw": _ANY,
            "Server": "stackpath",
        },
        "confidence": "MEDIUM",
        "type": "CDN+WAF",
        "note": "StackPath edge",
        "evasion": "Low rate, residential-like fingerprint if blocked",
    },
}

WAF_PROBES: list[dict[str, Any]] = [
    {
        "name": "SQLi probe",
        "payload": "?id=1'%20OR%20'1'='1",
        "method": "GET",
        "note": "Classic SQL injection pattern (harmless)",
    },
    {
        "name": "XSS probe",
        "payload": "?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "method": "GET",
        "note": "Basic XSS pattern (harmless)",
    },
    {
        "name": "Path traversal probe",
        "payload": "?file=..%2F..%2F..%2Fetc%2Fpasswd",
        "method": "GET",
        "note": "Directory traversal pattern (harmless)",
    },
    {
        "name": "Scanner UA probe",
        "payload": "",
        "headers": {"User-Agent": "sqlmap/1.0"},
        "method": "GET",
        "note": "Known scanner User-Agent",
    },
]

GENERIC_PROBE_EVASION: list[str] = [
    "Use low thread count (5–10) to reduce rate limits",
    "Add random delays between requests (jitter)",
    "Rotate User-Agent and Accept-Language",
    "Split suspicious tokens across parameters or encoding layers",
    "Compare behaviour on API vs static paths",
]


def _session_headers(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    h = {"User-Agent": USER_AGENT}
    if extra:
        h.update(extra)
    return h


def _header_matches(rule_val: Any, actual: str) -> bool:
    if rule_val is _ANY:
        return bool(actual and actual.strip())
    if isinstance(rule_val, str):
        return rule_val.lower() in actual.lower()
    if isinstance(rule_val, list):
        low = actual.lower()
        return any(x.lower() in low for x in rule_val)
    return False


def _collect_cookie_blob(
    resp: requests.Response,
    warnings: list[str] | None = None,
) -> str:
    parts: list[str] = []
    try:
        for c in resp.cookies:
            parts.append(f"{c.name}={c.value}")
    except Exception as e:  # noqa: BLE001
        if warnings is not None:
            warnings.append(
                f"WAF passive: cookie jar iteration failed: {type(e).__name__}: {e}"
            )
    sc = resp.headers.get("Set-Cookie") or ""
    if sc:
        parts.append(sc)
    return " ".join(parts).lower()


def passive_header_analysis(
    resp: requests.Response,
    warnings: list[str] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """
    Match response headers, cookies, and body against known WAF/CDN signatures.

    Returns the best-matching vendor dict (extended with name, evidence) or None.
    """
    lines: list[str] = []
    best: tuple[int, str, dict[str, Any], list[str]] | None = None
    body_lower = (resp.text or "")[:80000].lower()
    cookie_blob = _collect_cookie_blob(resp, warnings)
    hdrs = {k.lower(): v for k, v in resp.headers.items()}

    for name, sig in WAF_SIGNATURES.items():
        evidence: list[str] = []
        score = 0

        for hk, rule in (sig.get("headers") or {}).items():
            lk = hk.lower()
            actual = hdrs.get(lk)
            if actual is None:
                continue
            if _header_matches(rule, actual):
                score += 3
                if rule is _ANY:
                    evidence.append(f"{hk} header present → {name}")
                elif isinstance(rule, list):
                    evidence.append(f"{hk} matches vendor fingerprint → {name}")
                else:
                    evidence.append(f"{hk}: {actual[:80]} → {name}")

        for ck in sig.get("cookies") or []:
            ckl = ck.lower()
            if ckl in cookie_blob:
                score += 4
                evidence.append(f"cookie pattern `{ck}` → {name}")

        for pat in sig.get("body_patterns") or []:
            if pat.lower() in body_lower:
                score += 2
                evidence.append(f"body contains `{pat}` → {name}")

        if score > 0:
            conf = str(sig.get("confidence") or "MEDIUM")
            if conf == "HIGH":
                score += 1
            if best is None or score > best[0]:
                best = (score, name, sig, evidence)

    if best:
        _, vendor, sig, ev = best
        lines.extend(ev)
        waf_info = {
            "name": vendor,
            "type": sig.get("type", "WAF"),
            "confidence": sig.get("confidence", "MEDIUM"),
            "note": sig.get("note", ""),
            "evasion": sig.get("evasion", ""),
            "evidence": ev,
        }
        return waf_info, lines
    return None, lines


def analyze_probe_response(
    normal_resp: requests.Response,
    probe_resp: requests.Response,
    probe: dict[str, Any],
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """
    Compare baseline response to a probe response for block indicators.

    Avoids false positives on normal 200 HTML pages (common words like
    "security" in marketing copy). Stronger signal when status moves into
    block codes or the probe body looks like a short error/rejection page.
    """
    indicators: list[dict[str, Any]] = []
    n_status = normal_resp.status_code
    p_status = probe_resp.status_code
    status_blocks = p_status in WAF_BLOCK_CODES

    if status_blocks:
        if n_status not in WAF_BLOCK_CODES:
            indicators.append(
                {
                    "type": "status_change",
                    "detail": f"{n_status} → {p_status}",
                    "confidence": "HIGH",
                }
            )
        else:
            indicators.append(
                {
                    "type": "status_block",
                    "detail": f"probe status {p_status}",
                    "confidence": "MEDIUM",
                }
            )

    try:
        n_len = max(len(normal_resp.content or b""), 1)
        p_len = len(probe_resp.content or b"")
        short_error_like = p_len < 8000 and p_len < n_len * 0.35
    except Exception as e:  # noqa: BLE001
        if warnings is not None:
            warnings.append(
                f"WAF probe body metric ({probe.get('name')}): {type(e).__name__}: {e}"
            )
        short_error_like = False

    body_lower = (probe_resp.text or "")[:120000].lower()
    # Keyword hits only when response looks like a block/error, not a full site page
    if status_blocks or short_error_like:
        for pattern in WAF_BLOCK_PATTERNS:
            if pattern in body_lower:
                indicators.append(
                    {
                        "type": "block_message",
                        "detail": f"Body contains: '{pattern}'",
                        "confidence": "HIGH",
                    }
                )
                break

    # New headers are noisy (CDNs vary per URL); use only with block status or 3xx mismatch
    if status_blocks or (p_status != n_status and p_status in {301, 302, 303, 307, 308}):
        nh = {k.lower() for k in normal_resp.headers}
        ph = {k.lower() for k in probe_resp.headers}
        for header in sorted(ph - nh)[:8]:
            indicators.append(
                {
                    "type": "new_header",
                    "detail": f"New header after probe: {header}",
                    "confidence": "MEDIUM",
                }
            )

    try:
        if short_error_like and p_status != n_status:
            indicators.append(
                {
                    "type": "body_size_drop",
                    "detail": "Probe body much smaller than baseline",
                    "confidence": "LOW",
                }
            )
    except Exception as e:  # noqa: BLE001
        if warnings is not None:
            warnings.append(
                f"WAF probe size-drop hint ({probe.get('name')}): "
                f"{type(e).__name__}: {e}"
            )

    return {
        "probe": probe["name"],
        "blocked": len(indicators) > 0,
        "indicators": indicators,
    }


def _build_probe_url(base_url: str, probe: dict[str, Any]) -> str:
    payload = str(probe.get("payload") or "")
    root = base_url.rstrip("/")
    if not payload:
        return root + "/"
    if payload.startswith("?"):
        return root + payload
    return f"{root}/{payload.lstrip('/')}"


def timing_analysis(
    base_url: str,
    timeout: int,
    session: requests.Session,
    config: dict[str, Any],
    ssl_warnings: list[str],
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """
    Compare average latency for benign vs suspicious GET requests.

    A large delay on suspicious requests may suggest deep inspection.
    """
    root = base_url.rstrip("/") + "/"
    probe_url = root.rstrip("/") + "?id=1'OR'1'='1"

    normal_times: list[float] = []
    norm_timeout_noted = False
    norm_other_noted = False
    for _ in range(3):
        try:
            t0 = time.perf_counter()
            r = session_get(
                session,
                root,
                config,
                timeout=timeout,
                allow_redirects=True,
                headers=_session_headers(),
                ssl_warnings=ssl_warnings,
            )
            if r is None:
                normal_times.append(float(timeout))
            else:
                normal_times.append(time.perf_counter() - t0)
        except requests.exceptions.Timeout:
            normal_times.append(float(timeout))
            if warnings is not None and not norm_timeout_noted:
                norm_timeout_noted = True
                warnings.append(
                    "WAF timing: baseline request(s) timed out — samples use full timeout budget"
                )
        except Exception as e:  # noqa: BLE001
            normal_times.append(float(timeout))
            if warnings is not None and not norm_other_noted:
                norm_other_noted = True
                warnings.append(
                    f"WAF timing baseline request failed: {type(e).__name__}: {e}"
                )

    probe_times: list[float] = []
    probe_timeout_noted = False
    probe_other_noted = False
    for _ in range(3):
        try:
            t0 = time.perf_counter()
            r = session_get(
                session,
                probe_url,
                config,
                timeout=timeout,
                allow_redirects=True,
                headers=_session_headers(),
                ssl_warnings=ssl_warnings,
            )
            if r is None:
                probe_times.append(float(timeout))
            else:
                probe_times.append(time.perf_counter() - t0)
        except requests.exceptions.Timeout:
            probe_times.append(float(timeout))
            if warnings is not None and not probe_timeout_noted:
                probe_timeout_noted = True
                warnings.append(
                    "WAF timing: suspicious probe request(s) timed out — delay estimate may be skewed"
                )
        except Exception as e:  # noqa: BLE001
            probe_times.append(float(timeout))
            if warnings is not None and not probe_other_noted:
                probe_other_noted = True
                warnings.append(
                    f"WAF timing probe request failed: {type(e).__name__}: {e}"
                )

    avg_normal = sum(normal_times) / max(len(normal_times), 1)
    avg_probe = sum(probe_times) / max(len(probe_times), 1)
    delay_ms = (avg_probe - avg_normal) * 1000

    return {
        "avg_normal_ms": round(avg_normal * 1000, 1),
        "avg_probe_ms": round(avg_probe * 1000, 1),
        "delay_ms": round(delay_ms, 1),
        "inspection_likely": delay_ms > 500,
    }


def _panel_header_line(title: str, subtitle: str) -> None:
    inner = Text.assemble(
        (title.upper(), f"bold {C_PRI}"),
        ("  ·  ", C_DIM),
        (subtitle, C_DIM),
    )
    console.print(
        Panel(
            inner,
            border_style=C_PANEL,
            box=box.HEAVY,
            padding=(0, 1),
            width=min(console.size.width, 80) if console.size else 80,
        )
    )


def _print_passive_lines(evidence: list[str]) -> None:
    console.print(Text(" [PASSIVE] Analyzing headers and cookies...", style=f"bold {C_DIM}"))
    if not evidence:
        console.print(Text("   └── No strong CDN/WAF fingerprints in headers", style=C_MUTED))
        return
    for i, line in enumerate(evidence):
        sym = "└──" if i == len(evidence) - 1 else "├──"
        console.print(Text(f"   {sym} {line}", style=C_DIM))


def _print_probe_lines(probe_results: list[dict[str, Any]]) -> None:
    console.print(Text(" [ACTIVE] Sending WAF probes...", style=f"bold {C_DIM}"))
    for i, pr in enumerate(probe_results):
        sym = "└──" if i == len(probe_results) - 1 else "├──"
        name = pr.get("probe", "?")
        blocked = pr.get("blocked")
        st = pr.get("status")
        if blocked:
            msg = f"BLOCKED ({st})" if st is not None else "BLOCKED"
            style = C_WARN
        else:
            msg = f"OK ({st})" if st is not None else "OK"
            style = C_MUTED
        console.print(
            Text.assemble(
                (f"   {sym} ", C_MUTED),
                (f"{name:<22}", C_DIM),
                (" → ", C_MUTED),
                (msg, style),
            )
        )


def _print_evasion_hints(waf: dict[str, Any] | None, generic: bool) -> None:
    console.print()
    console.print(Text(" [INTEL] Evasion hints:", style=f"bold {C_WARN}"))
    hints: list[str] = []
    if waf and waf.get("evasion"):
        hints.append(str(waf["evasion"]))
    if generic:
        hints.extend(GENERIC_PROBE_EVASION[:4])
    seen: set[str] = set()
    uniq = []
    for h in hints:
        if h and h not in seen:
            seen.add(h)
            uniq.append(h)
    for i, h in enumerate(uniq):
        sym = "└──" if i == len(uniq) - 1 else "├──"
        console.print(Text(f"   {sym} {h}", style=C_DIM))


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Run layered WAF/CDN detection for a domain or single IP.

    CIDR targets return status ``skipped``. Never raises; errors go to ``errors``.
    """
    t0 = time.perf_counter()
    timeout = int(config.get("timeout") or DEFAULT_TIMEOUT)
    timeout = max(1, timeout)
    verbose = bool(config.get("verbose"))
    quiet = bool(config.get("quiet", False))
    errors: list[str] = []

    out: dict[str, Any] = {
        "module": "waf_detect",
        "target": target.value,
        "status": "success",
        "base_url": None,
        "waf_detected": False,
        "waf": None,
        "detection_methods": {
            "passive_headers": False,
            "active_probes": False,
            "timing": False,
        },
        "probes": [],
        "timing": {},
        "no_waf_detected": False,
        "passive_evidence": [],
        "errors": errors,
        "warnings": [],
    }

    if target.is_cidr():
        out["status"] = "skipped"
        _panel_header_line("WAF DETECTION", f"CIDR {target.value}")
        console.print(
            Text("  [SKIP] WAF detection needs a hostname or single IP.", style=C_WARN)
        )
        return out

    http_session = make_session(config)
    ssl_notes: list[str] = []

    base_url: str | None = None
    try:
        base_url = resolve_base_url(
            target,
            float(timeout),
            config,
            ssl_warnings=ssl_notes,
        )
    except Exception as e:  # noqa: BLE001
        errors.append(f"resolve_base_url: {e}")

    if not base_url:
        out["status"] = "error"
        errors.append("Target unreachable — no working http/https origin")
        console.print(
            Text("  [!] Could not reach target over HTTP/HTTPS", style=f"bold {C_ERR}")
        )
        errors.extend(ssl_notes)
        return out

    out["base_url"] = base_url
    parsed = urlparse(base_url)
    display = f"{parsed.scheme}://{parsed.netloc}"
    _panel_header_line("WAF DETECTION", display)

    normal_resp: requests.Response | None = None
    baseline_url = base_url.rstrip("/") + "/"
    debug_log("http", detail=f"GET {baseline_url} (WAF baseline)", config=config)
    t_bl = time.perf_counter()
    try:
        normal_resp = session_get(
            http_session,
            baseline_url,
            config,
            timeout=timeout,
            allow_redirects=True,
            headers=_session_headers(),
            ssl_warnings=ssl_notes,
        )
        if normal_resp is None:
            raise RuntimeError("baseline GET failed (SSL or connection)")
        debug_log(
            "http",
            detail="WAF baseline response",
            result=f"status {normal_resp.status_code}",
            elapsed=time.perf_counter() - t_bl,
            config=config,
        )
    except Exception as e:  # noqa: BLE001
        errors.append(f"baseline GET: {e}")
        errors.extend(ssl_notes)
        debug_log(
            "http",
            detail="WAF baseline",
            result=f"error: {type(e).__name__}",
            elapsed=time.perf_counter() - t_bl,
            config=config,
        )
        out["status"] = "error"
        console.print(Text(f"  [!] Baseline request failed: {e}", style=f"bold {C_ERR}"))
        return out

    passive_waf, passive_lines = passive_header_analysis(
        normal_resp, out["warnings"]
    )
    out["passive_evidence"] = passive_lines
    if passive_waf:
        out["detection_methods"]["passive_headers"] = True
    if not quiet:
        _print_passive_lines(passive_lines)

    probe_summaries: list[dict[str, Any]] = []
    blocked_count = 0

    for probe in WAF_PROBES:
        time.sleep(0.5)
        url = _build_probe_url(base_url, probe)
        extra_headers = probe.get("headers") or {}
        url_disp = url if len(url) <= 120 else url[:117] + "…"
        debug_log(
            "http",
            detail=f"GET {url_disp} [{probe['name']}]",
            config=config,
        )
        t_pr = time.perf_counter()
        try:
            pr = session_get(
                http_session,
                url,
                config,
                timeout=timeout,
                allow_redirects=True,
                headers=_session_headers(extra_headers),
                ssl_warnings=ssl_notes,
            )
            if pr is None:
                raise RuntimeError("probe GET failed (SSL or connection)")
            analysis = analyze_probe_response(
                normal_resp, pr, probe, out["warnings"]
            )
            blocked = bool(analysis.get("blocked"))
            if blocked:
                blocked_count += 1
                out["detection_methods"]["active_probes"] = True
            st_lbl = (
                "BLOCKED"
                if pr.status_code in WAF_BLOCK_CODES
                else "OK"
            )
            debug_log(
                "http",
                detail=f"WAF probe [{probe['name']}]",
                result=f"status {pr.status_code} · {st_lbl}",
                elapsed=time.perf_counter() - t_pr,
                config=config,
            )
            probe_summaries.append(
                {
                    "probe": probe["name"],
                    "blocked": blocked,
                    "status": pr.status_code,
                    "indicators": analysis.get("indicators", []),
                }
            )
        except requests.exceptions.Timeout:
            out["warnings"].append(f"WAF probe timeout: {probe['name']}")
            debug_log(
                "http",
                detail=f"WAF probe [{probe['name']}]",
                result="timeout",
                elapsed=time.perf_counter() - t_pr,
                config=config,
            )
            probe_summaries.append(
                {
                    "probe": probe["name"],
                    "blocked": False,
                    "status": None,
                    "error": "timeout",
                }
            )
        except Exception as e:  # noqa: BLE001
            err = f"WAF probe failed ({probe['name']}): {type(e).__name__}: {e}"
            errors.append(err)
            debug_log(
                "http",
                detail=f"WAF probe [{probe['name']}]",
                result=f"error: {type(e).__name__}",
                elapsed=time.perf_counter() - t_pr,
                config=config,
            )
            probe_summaries.append(
                {
                    "probe": probe["name"],
                    "blocked": False,
                    "status": None,
                    "error": str(e),
                }
            )

    out["probes"] = probe_summaries
    if not quiet:
        _print_probe_lines(probe_summaries)

    timing: dict[str, Any] = {}
    try:
        timing = timing_analysis(
            base_url,
            timeout,
            http_session,
            config,
            ssl_notes,
            out["warnings"],
        )
        out["timing"] = timing
        out["detection_methods"]["timing"] = True
    except Exception as e:  # noqa: BLE001
        errors.append(f"timing_analysis: {e}")
        out["timing"] = {
            "avg_normal_ms": 0.0,
            "avg_probe_ms": 0.0,
            "delay_ms": 0.0,
            "inspection_likely": False,
        }

    # Decision: identified vendor, or probe/timing suggests edge protection
    waf_info: dict[str, Any] | None = None
    http_block_probes = sum(
        1 for p in probe_summaries if p.get("status") in WAF_BLOCK_CODES
    )

    if passive_waf:
        waf_info = {
            "name": passive_waf["name"],
            "type": passive_waf["type"],
            "confidence": passive_waf["confidence"],
            "note": passive_waf.get("note", ""),
            "evasion": passive_waf.get("evasion", ""),
        }
        out["waf_detected"] = True
    elif http_block_probes >= 2 or (
        http_block_probes == 1
        and any(
            any(
                i.get("type") == "status_change" and i.get("confidence") == "HIGH"
                for i in (p.get("indicators") or [])
            )
            for p in probe_summaries
        )
    ):
        out["waf_detected"] = True
        waf_info = {
            "name": "Unknown edge protection",
            "type": "WAF / IDS (unidentified)",
            "confidence": "MEDIUM",
            "note": "Probes triggered block-like responses; no vendor fingerprint in headers",
            "evasion": "",
        }
        out["detection_methods"]["active_probes"] = True
    elif timing.get("inspection_likely") and blocked_count >= 2:
        out["waf_detected"] = True
        waf_info = {
            "name": "Possible inline inspection",
            "type": "IDS/IPS (heuristic)",
            "confidence": "LOW",
            "note": "Timing delta on suspicious GET; combine with probe results",
            "evasion": "Slow probes, vary payload shapes, confirm on second host/IP",
        }

    out["waf"] = waf_info
    out["no_waf_detected"] = not out["waf_detected"]

    elapsed = time.perf_counter() - t0

    if out["waf_detected"] and waf_info:
        conf = waf_info.get("confidence", "—")
        inner = Text.assemble(
            (" WAF DETECTED: ", f"bold {C_PRI}"),
            (str(waf_info.get("name", "?")), "bold"),
            (f"  [{conf}]", C_WARN),
        )
        console.print(
            Panel(
                inner,
                border_style=C_WARN,
                box=box.HEAVY,
                padding=(0, 1),
                width=min(console.size.width, 80) if console.size else 80,
            )
        )
        console.print(Text(f" Type       : {waf_info.get('type', '—')}", style=C_DIM))
        console.print(Text(f" Confidence : {conf}", style=C_DIM))
        console.print(
            Text(
                f" Blocks     : {blocked_count}/{len(WAF_PROBES)} probes blocked",
                style=C_DIM,
            )
        )
        if not quiet:
            _print_evasion_hints(
                waf_info,
                generic=bool(waf_info.get("name") == "Unknown edge protection"),
            )
    else:
        console.print()
        console.print(Text(" [✓] No WAF detected", style=f"bold {C_PRI}"))
        console.print(
            Text(
                "     All probes returned normal responses (or inconclusive)",
                style=C_MUTED,
            )
        )
        console.print(
            Text(
                "     Target appears to have no obvious CDN/WAF front door",
                style=C_MUTED,
            )
        )
        console.print(
            Text(
                "     [!] Less edge filtering often means larger direct attack surface",
                style=C_WARN,
            )
        )

    timing_note = (
        "inspection delay likely"
        if timing.get("inspection_likely")
        else "no strong inspection delay"
    )
    console.print()
    console.print(Text(" [✓] WAF detection complete", style=f"bold {C_PRI}"))
    if waf_info:
        console.print(
            Text(
                f"     WAF found  : {waf_info.get('name')} ({waf_info.get('type')})",
                style=C_DIM,
            )
        )
        console.print(Text(f"     Confidence : {waf_info.get('confidence')}", style=C_DIM))
    else:
        console.print(Text("     WAF found  : none identified", style=C_DIM))
    console.print(
        Text(
            f"     Probes     : {blocked_count}/{len(WAF_PROBES)} blocked",
            style=C_DIM,
        )
    )
    console.print(Text(f"     Timing     : {timing_note}", style=C_DIM))
    console.print(
        Text(f"     Duration   : {_format_duration_short(elapsed)}", style=C_DIM)
    )

    if verbose and passive_lines:
        console.print(Text(f"\n [verbose] {len(passive_lines)} passive signals", style=C_MUTED))

    errors.extend(ssl_notes)
    return out


def _format_duration_short(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m = int(seconds // 60)
    s = int(seconds % 60)
    return f"{m}m {s}s"
