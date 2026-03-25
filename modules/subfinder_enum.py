"""
GhostOpcode Subfinder integration — passive OSINT subdomains, merge with wordlist enum, DNS enrich.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import dns.exception
import dns.resolver
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import config as app_config
from utils.output import display_findings
from utils.target_parser import Target

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_PANEL = "#8B9CA8"

console = Console(highlight=False, force_terminal=True)

MAX_RESOLVE = 800
RESOLVE_THREADS = 48

# Risk buckets → name tokens (any label may match)
SUBDOMAIN_CATEGORIES: dict[str, tuple[str, ...]] = {
    "CRITICAL": (
        "admin",
        "vpn",
        "remote",
        "rdp",
        "citrix",
        "db",
        "mysql",
        "postgres",
        "redis",
        "elastic",
        "jenkins",
        "gitlab",
        "ci",
        "deploy",
        "intranet",
        "internal",
        "corp",
        "private",
        "safepass",
    ),
    "HIGH": (
        "dev",
        "staging",
        "homolog",
        "test",
        "qa",
        "api",
        "rest",
        "graphql",
        "git",
        "backup",
        "erp",
        "jira",
        "bitrix",
        "crm",
        "ftp",
    ),
    "MEDIUM": (
        "mail",
        "smtp",
        "cdn",
        "static",
        "media",
        "upload",
        "files",
        "shop",
        "portal",
        "chat",
    ),
    "LOW": (
        "www",
        "blog",
        "news",
        "about",
        "contact",
        "lp",
        "vagas",
        "conteudo",
    ),
}

_CATEGORY_LABELS: dict[str, str] = {
    p: p.replace("_", " ")
    for patterns in SUBDOMAIN_CATEGORIES.values()
    for p in patterns
}
_CATEGORY_LABELS["uncategorized"] = "uncategorized"


def check_subfinder() -> dict[str, Any]:
    """
    Check if ``subfinder`` is on PATH and read version string.

    Never raises.
    """
    binary = shutil.which("subfinder")
    if not binary:
        return {
            "available": False,
            "binary": None,
            "version": None,
            "install": (
                "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            ),
        }

    version_s = "unknown"
    try:
        result = subprocess.run(
            ["subfinder", "-version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        blob = (result.stderr or "").strip() or (result.stdout or "").strip()
        if blob:
            m = re.search(r"v[\d.]+", blob)
            version_s = m.group(0) if m else blob.splitlines()[0][:80]
    except Exception:  # noqa: BLE001
        pass

    return {
        "available": True,
        "binary": binary,
        "version": version_s,
        "install": None,
    }


def categorize_subdomain(fqdn: str) -> tuple[str, str]:
    """
    Classify FQDN by matching risk patterns against any hostname label.

    Returns ``(matched_pattern_or_slug, risk)``.
    """
    labels = fqdn.lower().strip(".").split(".")
    for risk, patterns in SUBDOMAIN_CATEGORIES.items():
        for pat in patterns:
            for lab in labels:
                if pat in lab:
                    return pat, risk
    return "uncategorized", "LOW"


def run_subfinder(
    domain: str,
    timeout_s: int,
    verbose: bool,
    errors: list[str],
) -> list[str]:
    """
    Run ProjectDiscovery ``subfinder`` and read FQDNs from a temp output file.

    ``-timeout`` is in **seconds** (subfinder CLI). Never raises.
    """
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            suffix=".txt", prefix="ghostopcode_subfinder_"
        )
        os.close(fd)
    except OSError as e:
        errors.append(f"temp file: {e}")
        return []

    assert tmp_path is not None

    # subfinder -timeout is seconds (default 30 in help)
    sf_to = min(3600, max(30, int(timeout_s)))

    cmd: list[str] = [
        "subfinder",
        "-d",
        domain,
        "-o",
        tmp_path,
        "-silent",
        "-timeout",
        str(sf_to),
        "-recursive",
        "-duc",
    ]

    wall = int(timeout_s) + 60
    try:
        proc = subprocess.run(
            cmd,
            capture_output=not verbose,
            text=True,
            timeout=wall,
        )
        if proc.returncode not in (0, None) and proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()[:500]
            if err:
                errors.append(f"subfinder exit {proc.returncode}: {err}")
    except subprocess.TimeoutExpired:
        errors.append(
            f"subfinder subprocess timed out after {wall}s — partial output may exist"
        )
    except FileNotFoundError:
        errors.append("subfinder binary not found on PATH")
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return []
    except Exception as e:  # noqa: BLE001
        errors.append(f"subfinder run: {e}")

    dom_l = domain.lower().strip(".")
    out: list[str] = []
    try:
        if os.path.isfile(tmp_path):
            with open(tmp_path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    h = line.strip().lower()
                    if not h or h.startswith("#"):
                        continue
                    if dom_l in h and "." in h:
                        out.append(h)
    except OSError as e:
        errors.append(f"read subfinder output: {e}")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return sorted(set(out))


def resolve_subdomain(fqdn: str, timeout_s: int) -> dict[str, Any] | None:
    """
    Resolve ``fqdn`` to an A record (thread-safe via dnspython).

    Returns ``{"fqdn", "ip", "source"}`` or None.
    """
    try:
        res = dns.resolver.Resolver(configure=True)
        to = float(max(1, min(15, timeout_s)))
        res.timeout = to
        res.lifetime = to
        ans = res.resolve(fqdn, "A")
        ip = str(sorted({str(r) for r in ans})[0])
        return {"fqdn": fqdn, "ip": ip, "source": "subfinder"}
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.Timeout,
        dns.exception.DNSException,
        OSError,
        IndexError,
    ):
        return None
    except Exception:  # noqa: BLE001
        return None


def compare_with_wordlist(
    subfinder_results: list[str],
    subdomain_enum_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    """Diff subfinder FQDNs vs prior ``subdomain_enum`` ``found`` list."""
    wordlist_found: list[str] = []
    if isinstance(subdomain_enum_payload, dict):
        for f in subdomain_enum_payload.get("found") or []:
            if isinstance(f, dict) and f.get("fqdn"):
                wordlist_found.append(str(f["fqdn"]).strip().lower())

    sf_set = {x.strip().lower() for x in subfinder_results if x.strip()}
    wl_set = set(wordlist_found)

    only_sf = sf_set - wl_set
    only_wl = wl_set - sf_set
    both = sf_set & wl_set

    return {
        "only_subfinder": sorted(only_sf),
        "only_wordlist": sorted(only_wl),
        "both": sorted(both),
        "new_by_subfinder": len(only_sf),
        "total_subfinder": len(sf_set),
        "total_wordlist": len(wl_set),
    }


def _risk_style(risk: str) -> str:
    if risk == "CRITICAL":
        return f"bold {C_ERR}"
    if risk == "HIGH":
        return f"bold {C_WARN}"
    if risk == "MEDIUM":
        return C_DIM
    return C_MUTED


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m = int(seconds // 60)
    s = int(seconds % 60)
    return f"{m}m {s}s"


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Passive subdomain discovery via subfinder, DNS enrichment, optional wordlist diff.

    Never raises; errors accumulate in ``errors``.
    """
    t0 = time.perf_counter()
    verbose = bool(config.get("verbose"))
    errors: list[str] = []

    default_to = int(getattr(app_config, "SUBFINDER_TIMEOUT", 300))
    timeout_s = int(
        config.get("subfinder_timeout_s") or config.get("timeout") or default_to
    )
    timeout_s = max(30, timeout_s)

    domain = target.value.lower().strip()

    base: dict[str, Any] = {
        "module": "subfinder_enum",
        "target": domain,
        "status": "success",
        "found": [],
        "comparison": {
            "only_subfinder": [],
            "only_wordlist": [],
            "both": [],
            "new_by_subfinder": 0,
            "total_subfinder": 0,
            "total_wordlist": 0,
        },
        "stats": {
            "total_found": 0,
            "resolved": 0,
            "unresolved": 0,
            "new_vs_wordlist": 0,
            "duration_s": 0.0,
        },
        "subfinder_version": None,
        "errors": errors,
    }

    console.print(
        Panel(
            Text.assemble(
                (" SUBFINDER ENUM  ·  ", f"bold {C_PRI}"),
                (domain, C_DIM),
                ("  ·  passive OSINT", C_MUTED),
            ),
            border_style=C_PANEL,
            box=box.HEAVY,
            padding=(0, 1),
            width=min(console.size.width, 80) if console.size else 80,
        )
    )

    if not target.is_domain():
        base["status"] = "skipped"
        console.print(Text("  [SKIP] Subfinder — domain targets only.", style=C_WARN))
        return base

    sf = check_subfinder()
    base["subfinder_version"] = sf.get("version")
    if not sf.get("available"):
        base["status"] = "not_installed"
        console.print(Text("  [!] subfinder not found on this system", style=f"bold {C_ERR}"))
        inst = sf.get("install") or "go install ... subfinder@latest"
        console.print(Text(f"  [i] Install: {inst}", style=C_MUTED))
        console.print(
            Text("  [i] Or: sudo apt install subfinder  (when packaged)", style=C_MUTED)
        )
        return base

    console.print(
        Text(
            f" [✓] subfinder {sf.get('version') or 'detected'} ({sf.get('binary')})",
            style=C_PRI,
        )
    )
    console.print()
    console.print(
        Text(
            f" [►] Running subfinder -d {domain} …",
            style=f"bold {C_DIM}",
        )
    )
    console.print(
        Text(
            "     Certificate Transparency · OSINT sources · passive (default)",
            style=C_MUTED,
        )
    )
    console.print(
        Text(f"     Budget ~{timeout_s}s wall clock", style=C_MUTED),
    )
    console.print()

    prior = config.get("subdomain_enum_results")
    if not isinstance(prior, dict):
        wrapped = config.get("session_results")
        if isinstance(wrapped, dict):
            prior = wrapped.get("subdomain_enum")

    raw_hosts = run_subfinder(domain, timeout_s, verbose, errors)
    if not raw_hosts and errors:
        console.print(
            Text("  [!] No hostnames returned — check errors / API keys / network", style=C_WARN)
        )

    cmp = compare_with_wordlist(raw_hosts, prior if isinstance(prior, dict) else None)
    base["comparison"] = cmp
    only_sf_set = set(cmp["only_subfinder"])
    both_set = set(cmp["both"])

    to_resolve = raw_hosts[:MAX_RESOLVE]
    if len(raw_hosts) > MAX_RESOLVE:
        errors.append(
            f"Resolving first {MAX_RESOLVE} of {len(raw_hosts)} hosts (cap)"
        )

    res_to = min(8, max(3, timeout_s // 60))
    ip_by_host: dict[str, str | None] = {}

    with ThreadPoolExecutor(max_workers=RESOLVE_THREADS) as ex:
        futs = {ex.submit(resolve_subdomain, h, res_to): h for h in to_resolve}
        try:
            for fut in as_completed(futs, timeout=float(timeout_s + 120)):
                h = futs[fut]
                hl = h.lower()
                try:
                    r = fut.result()
                    ip_by_host[hl] = str(r["ip"]) if r and r.get("ip") else None
                except Exception:  # noqa: BLE001
                    ip_by_host[hl] = None
        except TimeoutError:
            errors.append("DNS resolution batch timed out — some IPs missing")
            for h in to_resolve:
                if h.lower() not in ip_by_host:
                    ip_by_host[h.lower()] = None

    found_rows: list[dict[str, Any]] = []
    for h in raw_hosts:
        hl = h.lower()
        ip_val = ip_by_host[hl] if hl in ip_by_host else None
        cat, risk = categorize_subdomain(hl)
        is_new = hl in only_sf_set
        found_rows.append(
            {
                "fqdn": hl,
                "ip": ip_val,
                "source": "subfinder",
                "category": cat,
                "category_label": _CATEGORY_LABELS.get(cat, cat),
                "risk": risk,
                "new": is_new,
            }
        )

    found_rows.sort(
        key=lambda x: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                str(x.get("risk")), 4
            ),
            x.get("fqdn", ""),
        )
    )

    critical_rows = [r for r in found_rows if r.get("risk") == "CRITICAL"]
    if critical_rows:
        display_findings(
            [
                {
                    "risk": "CRITICAL",
                    "category": str(r.get("category") or "subdomain"),
                    "value": f"{r['fqdn']} → {r.get('ip') or '—'}",
                    "note": "High-value subdomain (pattern match)",
                }
                for r in critical_rows
            ],
            module="subfinder_enum",
            verbose=verbose,
        )

    base["found"] = found_rows
    base["stats"]["total_found"] = len(raw_hosts)
    base["stats"]["resolved"] = sum(1 for r in found_rows if r.get("ip"))
    base["stats"]["unresolved"] = sum(1 for r in found_rows if not r.get("ip"))
    base["stats"]["new_vs_wordlist"] = int(cmp.get("new_by_subfinder") or 0)
    base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)

    for row in found_rows[:40]:
        fq = row["fqdn"]
        ip_s = row.get("ip") or "—"
        risk = row.get("risk", "LOW")
        star = " ★ new" if row.get("new") else ""
        console.print(
            Text.assemble(
                (" [+] ", C_PRI),
                (f"{fq:<42}", C_DIM),
                (" → ", C_MUTED),
                (f"{str(ip_s):<15}", C_PRI),
                (" ", ""),
                (f"[{risk}]", _risk_style(risk)),
                (star, C_WARN if row.get("new") else C_MUTED),
            )
        )
    if len(found_rows) > 40:
        console.print(
            Text(
                f"     … {len(found_rows) - 40} more (see HTML report)",
                style=C_MUTED,
            )
        )

    console.print()
    console.print(Text(" [COMPARE] vs wordlist enum:", style=f"bold {C_DIM}"))
    console.print(
        Text(
            f"   ├── Found by BOTH       : {len(both_set)} subdomains",
            style=C_DIM,
        )
    )
    console.print(
        Text(
            f"   ├── Only wordlist       : {len(cmp['only_wordlist'])} subdomains",
            style=C_DIM,
        )
    )
    console.print(
        Text(
            f"   └── Only subfinder      : {cmp['new_by_subfinder']} subdomains ← new intel",
            style=C_WARN,
        )
    )
    oa = cmp["only_subfinder"][:12]
    for i, fq in enumerate(oa):
        cat, risk = categorize_subdomain(fq)
        sym = (
            "└──"
            if i == len(oa) - 1 and len(cmp["only_subfinder"]) <= 12
            else "├──"
        )
        console.print(
            Text(
                f"       {sym} {fq}  [{risk}]  ({cat})",
                style=_risk_style(risk) if risk == "CRITICAL" else C_DIM,
            )
        )
    rest = len(cmp["only_subfinder"]) - len(oa)
    if rest > 0:
        console.print(Text(f"       … and {rest} more only-subfinder hosts", style=C_MUTED))

    if not isinstance(prior, dict) or prior.get("status") != "success":
        console.print(
            Text(
                "   [i] Run [2] Subdomain enum in the same session to diff vs wordlist.",
                style=C_MUTED,
            )
        )

    console.print()
    tbl = Table(
        title=Text("Subfinder findings", style=f"bold {C_PRI}"),
        box=box.ROUNDED,
        border_style=C_PANEL,
        show_lines=True,
    )
    tbl.add_column("Subdomain", style=C_DIM, no_wrap=False)
    tbl.add_column("IP", style=C_PRI)
    tbl.add_column("Category", style=C_MUTED)
    tbl.add_column("Risk", style=C_DIM)
    tbl.add_column("New", justify="center")
    for row in found_rows[:35]:
        tbl.add_row(
            row["fqdn"],
            str(row.get("ip") or "—"),
            str(row.get("category_label") or row.get("category")),
            row.get("risk", "LOW"),
            "★" if row.get("new") else "",
        )
    if len(found_rows) > 35:
        tbl.add_row("…", "…", f"+{len(found_rows) - 35} rows", "", "")
    console.print(tbl)

    rc = sum(1 for r in found_rows if r.get("risk") == "CRITICAL")
    rh = sum(1 for r in found_rows if r.get("risk") == "HIGH")
    rm = sum(1 for r in found_rows if r.get("risk") == "MEDIUM")
    rl = sum(1 for r in found_rows if r.get("risk") == "LOW")

    console.print()
    console.print(Text(" [✓] Subfinder enum complete", style=f"bold {C_PRI}"))
    console.print(
        Text(
            f"     Found      : {len(raw_hosts)} subdomains",
            style=C_DIM,
        )
    )
    console.print(
        Text(
            f"     New vs wordlist : {cmp['new_by_subfinder']}",
            style=C_WARN if cmp["new_by_subfinder"] else C_DIM,
        )
    )
    console.print(
        Text(
            f"     Critical   : {rc}  ·  High: {rh}  ·  Medium: {rm}  ·  Low: {rl}",
            style=C_DIM,
        )
    )
    console.print(
        Text(
            f"     Duration   : {_format_duration(base['stats']['duration_s'])}",
            style=C_DIM,
        )
    )

    return base
