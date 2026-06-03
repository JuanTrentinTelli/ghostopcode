"""
GhostOpcode httpx integration — HTTP/HTTPS probing, tech fingerprint, TLS metadata.
"""

from __future__ import annotations
from utils.theme import C_PRI, C_DIM, C_ERR, C_WARN, C_MUTED, C_PANEL, console

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from utils.base_module import make_finding
from utils.output import debug_log
from utils.target_parser import Target

_DEFAULT_PORTS = "80,443,8080,8443,8000,8888,3000,5000,9090,9443"


def _normalize_host_for_stdin(raw: str) -> str:
    """
    Strip scheme/path so stdin matches ``echo host | httpx`` (host per line).

    Keeps ``host:port`` when present so portas fora de ``-p`` ainda funcionam.
    """
    h = (raw or "").strip()
    if not h:
        return ""
    low = h.lower()
    for prefix in ("https://", "http://"):
        if low.startswith(prefix):
            h = h[len(prefix) :]
            low = h.lower()
    h = h.split("/")[0].split("?")[0].split("#")[0]
    return h.strip().rstrip(".")


def _httpx_candidate_paths() -> list[str]:
    home = Path.home()
    return [
        "/usr/local/bin/httpx",
        str(home / "go" / "bin" / "httpx"),
        "/root/go/bin/httpx",
        # Kali/Debian package the ProjectDiscovery tool as ``httpx-toolkit`` to
        # avoid colliding with the Python ``httpx`` CLI (also at /usr/bin/httpx).
        # Try it before the bare ``httpx`` so we don't pick the Python library.
        str(shutil.which("httpx-toolkit") or ""),
        "/usr/bin/httpx-toolkit",
        str(shutil.which("httpx") or ""),
    ]


def check_httpx() -> dict[str, Any]:
    """
    Resolve ProjectDiscovery ``httpx`` binary (not the Python library) and read version.

    Never raises.
    """
    binary: str | None = None
    for candidate in _httpx_candidate_paths():
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            binary = candidate
            break

    if not binary:
        return {
            "available": False,
            "error": "httpx (ProjectDiscovery) not found",
            "install": (
                "https://github.com/projectdiscovery/httpx/releases — "
                "e.g. wget the linux_amd64 zip, unzip, sudo mv httpx /usr/local/bin/"
            ),
            "binary": None,
            "version": None,
        }

    try:
        result = subprocess.run(
            [binary, "-version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
        )
        output = (result.stdout or "")
        ansi = re.compile(r"\x1b\[[0-9;]*m")

        def _strip_ansi(s: str) -> str:
            return ansi.sub("", s).strip()

        plain = _strip_ansi(output)
        low = plain.lower()
        looks_pd = (
            "projectdiscovery" in low
            or "current version" in low
            or re.search(r"\bv1\.\d+", plain, re.I) is not None
        )
        if not looks_pd:
            return {
                "available": False,
                "error": (
                    "Found httpx but -version does not match ProjectDiscovery httpx. "
                    "Install from: https://github.com/projectdiscovery/httpx"
                ),
                "binary": binary,
                "version": None,
            }
        version_s = "unknown"
        for line in output.splitlines():
            ls = _strip_ansi(line)
            if re.search(r"v?1\.\d+", ls, re.I) or "version" in ls.lower():
                version_s = ls[:120]
                break
        if version_s == "unknown" and output.strip():
            version_s = _strip_ansi(output.strip().splitlines()[0])[:120]
        version_s = _strip_ansi(version_s)
        vm = re.search(r"(v\d+\.\d+\.\d+)", version_s, re.I)
        if vm:
            version_s = vm.group(1)

        return {
            "available": True,
            "binary": binary,
            "version": version_s,
            "install": None,
        }
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return {
            "available": False,
            "error": f"httpx check failed: {type(e).__name__}: {e}",
            "binary": binary,
            "version": None,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "available": False,
            "error": f"httpx check failed: {type(e).__name__}: {e}",
            "binary": binary,
            "version": None,
        }


def _fqdns_from_dnsx(dnsx_data: dict[str, Any]) -> list[str]:
    out: list[str] = []
    resolved = dnsx_data.get("resolved")
    if not isinstance(resolved, list):
        nested = (dnsx_data.get("data") or {}).get("resolved")
        if isinstance(nested, list):
            resolved = nested
    if not isinstance(resolved, list):
        return out
    for item in resolved:
        if isinstance(item, dict):
            fq = item.get("fqdn") or item.get("host")
            if fq and isinstance(fq, str):
                out.append(fq.lower().strip())
    return out


def _fqdns_from_subfinder(sf: dict[str, Any]) -> list[str]:
    out: list[str] = []
    found = sf.get("found")
    if not isinstance(found, list):
        nested = (sf.get("data") or {}).get("hosts")
        if isinstance(nested, list):
            for h in nested:
                if isinstance(h, dict):
                    fq = h.get("fqdn") or h.get("subdomain")
                    ip = h.get("ip")
                    if fq and ip not in (None, "", "—"):
                        out.append(str(fq).lower().strip())
            return out
    for h in found or []:
        if not isinstance(h, dict):
            continue
        fq = h.get("fqdn") or h.get("subdomain")
        ip = h.get("ip")
        if fq and ip not in (None, "", "—"):
            out.append(str(fq).lower().strip())
    return out


def _fqdns_from_subdomain_enum(sub: dict[str, Any]) -> list[str]:
    out: list[str] = []
    found = sub.get("found")
    if not isinstance(found, list):
        nested = (sub.get("data") or {}).get("subdomains")
        if isinstance(nested, list):
            for h in nested:
                if isinstance(h, dict):
                    fq = h.get("fqdn") or h.get("subdomain")
                    if fq:
                        out.append(str(fq).lower().strip())
            return out
    for h in found or []:
        if not isinstance(h, dict):
            continue
        fq = h.get("fqdn") or h.get("subdomain")
        if fq:
            out.append(str(fq).lower().strip())
    return out


def get_fqdns_for_probe(target: Target, session_data: dict[str, Any]) -> list[str]:
    """
    Prefer dnsx ``resolved``, then subfinder (with IP), then subdomain enum, else apex.
    """
    domain = target.value.lower().strip()

    dnsx_data = session_data.get("dnsx_enum")
    if isinstance(dnsx_data, dict) and dnsx_data.get("status") == "success":
        got = _fqdns_from_dnsx(dnsx_data)
        if got:
            return list(dict.fromkeys(got))

    sf = session_data.get("subfinder_enum")
    if isinstance(sf, dict) and sf.get("status") == "success":
        got = _fqdns_from_subfinder(sf)
        if got:
            return list(dict.fromkeys(got))

    sub = session_data.get("subdomain_enum")
    if isinstance(sub, dict) and sub.get("status") == "success":
        got = _fqdns_from_subdomain_enum(sub)
        if got:
            return list(dict.fromkeys(got))

    return [domain]


def run_httpx(
    fqdns: list[str],
    binary: str,
    threads: int,
    timeout: int,
    ports: str,
    config: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Run httpx; read JSONL from stdout. Never raises.

    Hosts are passed via **stdin** without ``-l -`` — em v1.6.10 ``-l -`` pode
    falhar com "No input provided". ``-nf`` força resultado explícito para HTTP e HTTPS.
    """
    if not fqdns:
        return []

    hto = config.get("httpx_timeout")
    if hto is not None:
        try:
            to_i = max(1, int(hto))
        except (TypeError, ValueError):
            to_i = max(10, int(timeout))
    else:
        to_i = max(10, int(timeout))

    th = max(1, min(50, int(threads)))

    cmd: list[str] = [
        binary,
        "-duc",
        "-silent",
        "-j",
        "-t",
        str(th),
        "-timeout",
        str(to_i),
        "-retries",
        "1",
        "-title",
        "-sc",
        "-cl",
        "-td",
        "-server",
        "-tls-grab",
        "-probe",
        "-nf",
        "-fr",
        "-maxr",
        "3",
        "-p",
        ports or _DEFAULT_PORTS,
    ]

    seen: set[str] = set()
    lines: list[str] = []
    for raw in fqdns:
        norm = _normalize_host_for_stdin(raw)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        lines.append(norm)

    if not lines:
        return []

    stdin_payload = "\n".join(lines)
    if not stdin_payload.endswith("\n"):
        stdin_payload += "\n"

    debug_log(
        action="subprocess",
        detail=" ".join(cmd[:12]) + " ...",
        config=config,
    )

    wall_timeout = max(120.0, min(7200.0, len(fqdns) * 3.0 + 90.0))
    try:
        result = subprocess.run(
            cmd,
            input=stdin_payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=wall_timeout,
        )
    except subprocess.TimeoutExpired:
        return []
    except Exception:  # noqa: BLE001
        return []

    debug_log(
        action="subprocess",
        detail=f"httpx finished — exit {result.returncode}",
        config=config,
    )

    probed: list[dict[str, Any]] = []
    for line in (result.stdout or "").strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            probed.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return probed


def _normalize_tech(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw] if raw.strip() else []
    if isinstance(raw, list):
        out: list[str] = []
        for x in raw:
            if isinstance(x, dict):
                name = x.get("name") or x.get("value") or x.get("technology")
                if name:
                    out.append(str(name))
            elif x is not None:
                s = str(x).strip()
                if s:
                    out.append(s)
        return out
    return []


def _assess_http_risk(
    host: str,
    status_code: int,
    title: str,
    tech: list[str],
    url: str,
) -> str:
    host_lower = (host or "").lower()
    title_lower = (title or "").lower()
    tech_str = " ".join(t.lower() for t in tech)
    url_lower = (url or "").lower()
    _ = url_lower

    critical_tech = (
        "jenkins",
        "jira",
        "confluence",
        "gitlab",
        "grafana",
        "kibana",
        "elasticsearch",
        "phpmyadmin",
        "adminer",
    )
    critical_host = (
        "jira",
        "gitlab",
        "jenkins",
        "admin",
        "panel",
        "control",
        "manage",
        "vpn",
        "remote",
    )
    critical_title = (
        "login",
        "admin",
        "panel",
        "dashboard",
        "control",
        "manage",
        "console",
        "portal",
    )

    for ind in critical_host:
        if ind in host_lower:
            return "CRITICAL"
    for tn in critical_tech:
        if tn in tech_str or tn in title_lower:
            return "CRITICAL"
    for ind in critical_title:
        if ind in title_lower:
            return "CRITICAL"

    high_indicators = (
        "api",
        "dev",
        "staging",
        "test",
        "homolog",
        "ftp",
        "mail",
        "crm",
        "erp",
        "support",
    )
    for ind in high_indicators:
        if ind in host_lower:
            return "HIGH"

    if status_code in (200, 301, 302, 401, 403):
        return "MEDIUM"

    return "LOW"


def count_unique_probe_hosts(probed: list[dict[str, Any]]) -> int:
    """
    FQDNs únicos que tiveram pelo menos uma linha de resultado (não conta host+porta
    como entradas distintas — uma linha por URL, um host pode ter várias URLs).
    """
    seen: set[str] = set()
    for item in probed:
        if not isinstance(item, dict):
            continue
        h = str(item.get("host") or "").strip().lower().rstrip(".")
        if not h:
            u = str(item.get("url") or item.get("final_url") or "").strip()
            if u:
                try:
                    hn = urlparse(u).hostname
                    if hn:
                        h = hn.lower().rstrip(".")
                except (ValueError, TypeError):
                    pass
        if h:
            seen.add(h)
    return len(seen)


def parse_httpx_output(raw_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize httpx JSONL into stable rows + risk."""
    parsed: list[dict[str, Any]] = []

    for item in raw_results:
        url = str(item.get("url") or "").strip()
        host = str(item.get("input") or item.get("host") or "").strip()
        try:
            status_code = int(item.get("status_code") or 0)
        except (TypeError, ValueError):
            status_code = 0

        if status_code == 0 and not url:
            continue

        title = str(item.get("title") or "")
        tech = _normalize_tech(
            item.get("tech") or item.get("technologies") or item.get("tech_detected")
        )
        try:
            content_len = int(item.get("content_length") or item.get("content-length") or 0)
        except (TypeError, ValueError):
            content_len = 0

        cdn_name = str(
            item.get("cdn_name")
            or item.get("cdn-name")
            or item.get("cdn")
            or ""
        ).strip()
        final_url = str(item.get("final_url") or item.get("final-url") or url or "").strip()
        tls = item.get("tls")
        if not isinstance(tls, dict):
            tls = {}

        webserver = str(item.get("webserver") or item.get("server") or "").strip()
        port = item.get("port", "")
        if port is not None and not isinstance(port, str):
            port = str(port)

        parsed_url = urlparse(url or final_url)
        scheme = parsed_url.scheme or ("https" if ":443" in (url or "") else "http")

        cert_info: dict[str, Any] = {}
        if tls:
            cert_info = {
                "subject": tls.get("subject_cn") or tls.get("subject") or "",
                "issuer": tls.get("issuer_cn") or tls.get("issuer") or "",
                "expiry": tls.get("not_after") or tls.get("notAfter") or "",
                "valid": not bool(tls.get("expired")),
            }

        risk = _assess_http_risk(host, status_code, title, tech, url or final_url)

        parsed.append(
            {
                "url": url or final_url,
                "final_url": final_url or url,
                "host": host,
                "scheme": scheme,
                "port": port,
                "status_code": status_code,
                "title": title,
                "tech": tech,
                "webserver": webserver,
                "content_len": content_len,
                "cdn": cdn_name,
                "cert": cert_info,
                "redirected": bool(url and final_url and url != final_url),
                "risk": risk,
            }
        )

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    parsed.sort(key=lambda x: risk_order.get(str(x.get("risk")), 4))
    return parsed


def _display_results(probed: list[dict[str, Any]], quiet: bool) -> None:
    if quiet or not probed:
        return
    console.print()
    console.print(Text(" [HTTP SERVICES] Live hosts", style=f"bold {C_DIM}"))
    tbl = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        border_style=C_PANEL,
    )
    tbl.add_column("URL", style=C_DIM, no_wrap=False, max_width=44)
    tbl.add_column("St", justify="center", width=5)
    tbl.add_column("Title", style=C_MUTED, max_width=26)
    tbl.add_column("Tech", style=C_MUTED, max_width=18)
    tbl.add_column("CDN", style=C_MUTED, max_width=12)
    tbl.add_column("Risk", justify="center", width=10)

    for item in probed[:30]:
        rsk = str(item.get("risk") or "LOW")
        risk_style = {
            "CRITICAL": f"bold {C_ERR}",
            "HIGH": f"bold {C_WARN}",
            "MEDIUM": C_DIM,
            "LOW": C_MUTED,
        }.get(rsk, C_MUTED)

        status = item.get("status_code", "")
        st_style = C_PRI
        if status == 200:
            st_style = C_PRI
        elif status in (301, 302):
            st_style = C_WARN
        elif status in (401, 403, 500):
            st_style = C_ERR

        tech = ", ".join(item.get("tech") or [])[:2]
        title = (item.get("title") or "")[:26]
        cdn = item.get("cdn") or "—"
        url = str(item.get("url") or "")
        if len(url) > 44:
            url = url[:41] + "..."

        tbl.add_row(
            url,
            Text(str(status), style=st_style),
            title,
            tech or "—",
            cdn,
            Text(rsk, style=risk_style),
        )
    console.print(tbl)
    if len(probed) > 30:
        console.print(
            Text(
                f" … and {len(probed) - 30} more (see HTML / JSON export)",
                style=C_MUTED,
            )
        )


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Probe HTTP/HTTPS services with ProjectDiscovery httpx (session FQDNs or apex).

    Never raises.
    """
    t0 = time.perf_counter()
    quiet = bool(config.get("quiet", False))
    domain = target.value.lower().strip()

    base: dict[str, Any] = {
        "module": "httpx_probe",
        "target": domain,
        "status": "success",
        "errors": [],
        "warnings": [],
        "probed": [],
        "live_count": 0,
        "total_fqdns": 0,
        "httpx_version": None,
        "stats": {
            "total_fqdns": 0,
            "live_count": 0,
            "duration_s": 0.0,
        },
        "findings_flat": [],
    }

    if not target.is_domain():
        base["status"] = "skipped"
        if not quiet:
            console.print(
                Text("  [SKIP] httpx probe — domain targets only.", style=C_WARN)
            )
        return base

    hx = check_httpx()
    base["httpx_version"] = hx.get("version")
    if not hx.get("available"):
        base["status"] = "not_installed"
        base["errors"].append(str(hx.get("error") or "httpx unavailable"))
        if not quiet:
            console.print(
                Text("  [!] ProjectDiscovery httpx not found", style=f"bold {C_ERR}")
            )
            inst = hx.get("install") or "github.com/projectdiscovery/httpx"
            console.print(Text(f"  [i] Install: {inst}", style=C_MUTED))
        return base

    binary = str(hx.get("binary") or "httpx")
    threads = min(int(config.get("threads") or 50), 50)
    if config.get("httpx_timeout") is not None:
        try:
            timeout = max(1, int(config.get("httpx_timeout")))
        except (TypeError, ValueError):
            timeout = max(10, int(config.get("timeout") or 10))
    else:
        timeout = max(10, int(config.get("timeout") or 10))
    ports = str(config.get("httpx_ports") or _DEFAULT_PORTS).strip() or _DEFAULT_PORTS

    session_data = config.get("session_results")
    if not isinstance(session_data, dict):
        session_data = {}

    fqdns = get_fqdns_for_probe(target, session_data)
    base["total_fqdns"] = len(fqdns)
    base["stats"]["total_fqdns"] = len(fqdns)

    if not fqdns:
        base["status"] = "error"
        msg = "no FQDNs to probe"
        base["errors"].append(msg)
        base["warnings"].append(msg)
        if not quiet:
            console.print(Text(f" [!] {msg}", style=C_WARN))
        return base

    if not quiet:
        console.print(
            Panel(
                Text.assemble(
                    (" HTTPX PROBE  ·  ", f"bold {C_PRI}"),
                    (domain, C_DIM),
                    ("  ·  HTTP/HTTPS + tech + TLS", C_MUTED),
                ),
                border_style=C_PANEL,
                box=box.HEAVY,
                padding=(0, 1),
                width=min(console.size.width, 80) if console.size else 80,
            )
        )
        console.print(
            Text(
                f" [✓] {hx.get('version') or 'httpx'} ({binary})",
                style=C_PRI,
            )
        )
        console.print(
            Text(
                f"\n [►] Probing {len(fqdns):,} hosts for HTTP/HTTPS services...",
                style=f"bold {C_DIM}",
            )
        )

    raw = run_httpx(fqdns, binary, threads, timeout, ports, config)
    probed = parse_httpx_output(raw)
    base["probed"] = probed
    url_total = len(probed)
    hosts_live = count_unique_probe_hosts(probed)
    base["live_count"] = url_total
    base["stats"]["live_count"] = url_total
    base["stats"]["total_urls_live"] = url_total
    base["stats"]["unique_hosts_live"] = hosts_live
    base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)

    if not quiet:
        console.print(
            Text(
                f" [✓] {hosts_live:,} hosts · {url_total:,} URLs (HTTP/HTTPS)",
                style=C_PRI,
            )
        )

    findings_flat: list[dict[str, Any]] = []
    for item in probed:
        risk = str(item.get("risk") or "LOW").upper()
        title = (item.get("title") or "no title")[:80]
        tech = ", ".join((item.get("tech") or [])[:3])
        note = f"{item.get('status_code')} · {title}"
        if tech:
            note = f"{note} · {tech}"
        findings_flat.append(
            make_finding(
                value=str(item.get("url") or item.get("final_url") or item.get("host")),
                category="http_service",
                risk=risk,
                note=note,
                metadata=item,
            )
        )
    base["findings_flat"] = findings_flat

    _display_results(probed, quiet)

    if not quiet:
        rc = sum(1 for x in probed if x.get("risk") == "CRITICAL")
        rh = sum(1 for x in probed if x.get("risk") == "HIGH")
        console.print()
        console.print(Text(" [✓] httpx probe complete", style=f"bold {C_PRI}"))
        console.print(
            Text(
                f"     Input FQDNs: {len(fqdns):,}  ·  Hosts live: {hosts_live:,}  ·  "
                f"URLs: {url_total:,}  ·  Critical: {rc}  ·  High: {rh}  ·  "
                f"{base['stats']['duration_s']}s",
                style=C_DIM,
            )
        )

    return base
