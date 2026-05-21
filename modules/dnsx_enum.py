"""
GhostOpcode dnsx integration — bulk DNS resolution, record enrichment, wildcard detection.
"""

from __future__ import annotations

import json
import re
import secrets
import shutil
import subprocess
import time
from typing import Any

import config as app_config
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from utils.base_module import make_finding
from utils.output import debug_log
from utils.target_parser import Target

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_PANEL = "#8B9CA8"

console = Console(highlight=False, force_terminal=True)


def check_dnsx() -> dict[str, Any]:
    """Check if ``dnsx`` is on PATH and read version string. Never raises."""
    binary = shutil.which("dnsx")
    if not binary:
        return {
            "available": False,
            "error": "dnsx not found",
            "install": "sudo apt install dnsx",
            "binary": None,
            "version": None,
        }
    version_s = "unknown"
    try:
        result = subprocess.run(
            [binary, "-version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        blob = (result.stdout or "") + (result.stderr or "")
        blob = blob.strip()
        if blob:
            m = re.search(r"(?:Current Version:\s*)?(v?[\d.]+)", blob, re.I)
            version_s = m.group(1) if m else blob.splitlines()[0][:80]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return {
            "available": False,
            "error": f"dnsx check failed: {type(e).__name__}: {e}",
            "install": "sudo apt install dnsx",
            "binary": binary,
            "version": None,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "available": False,
            "error": f"dnsx check failed: {type(e).__name__}: {e}",
            "install": "sudo apt install dnsx",
            "binary": binary,
            "version": None,
        }
    return {
        "available": True,
        "binary": binary,
        "version": version_s,
        "install": None,
    }


def _wordlist_path_from_config(config: dict[str, Any]) -> str | None:
    p = (
        config.get("wordlist_subdomains")
        or config.get("subdomain_wordlist")
        or app_config.WORDLIST_SUBDOMAINS
    )
    if p and isinstance(p, str) and p.strip():
        return p.strip()
    return None


def get_fqdns_for_target(
    target: Target,
    session_data: dict[str, Any],
    wordlist_path: str | None = None,
) -> list[str]:
    """
    Build FQDN list for dnsx: session subfinder/subdomain_enum → wordlist → apex only.
    """
    fqdns: set[str] = set()
    domain = target.value.lower().strip()

    for mod_name in ("subfinder_enum", "subdomain_enum"):
        mod = session_data.get(mod_name)
        if not isinstance(mod, dict) or mod.get("status") != "success":
            continue
        found = mod.get("found")
        if not isinstance(found, list):
            continue
        for host in found:
            if not isinstance(host, dict):
                continue
            fqdn = host.get("fqdn") or host.get("subdomain") or host.get("host")
            if fqdn and isinstance(fqdn, str):
                fqdns.add(fqdn.lower().strip())

    if not fqdns and wordlist_path:
        try:
            with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith("#"):
                        fqdns.add(f"{word}.{domain}")
        except OSError:
            pass

    if not fqdns:
        fqdns.add(domain)

    return sorted(fqdns)


def run_dnsx(
    fqdns: list[str],
    record_types: list[str],
    resolvers: list[str],
    threads: int,
    timeout: int,
    dnsx_binary: str,
    config: dict[str, Any],
) -> list[dict[str, Any]]:
    """Run dnsx with JSONL output. Returns parsed objects. Never raises."""
    if not fqdns:
        return []

    to_s = max(1, int(timeout))
    # ``-l -`` reads hostnames from stdin (avoids temp files; works when ``-l /path`` is blocked).
    cmd: list[str] = [
        dnsx_binary,
        "-duc",
        "-l",
        "-",
        "-j",
        "-silent",
        "-t",
        str(max(1, int(threads))),
        "-timeout",
        f"{to_s}s",
        "-retry",
        "2",
        "-re",
        "-cdn",
        "-asn",
    ]

    rts = {str(x).lower().strip() for x in (record_types or []) if x}
    if not rts:
        rts = {"a", "aaaa", "cname", "mx"}
    for rt in sorted(rts):
        if rt in ("a", "aaaa", "cname", "ns", "txt", "mx", "srv", "ptr", "soa"):
            cmd.append(f"-{rt}")

    if resolvers:
        cmd.extend(["-r", ",".join(str(r) for r in resolvers if r)])

    debug_log(action="subprocess", detail=" ".join(cmd), config=config)

    stdin_payload = "\n".join(fqdns)
    if stdin_payload and not stdin_payload.endswith("\n"):
        stdin_payload += "\n"

    wall_timeout = max(90.0, min(3600.0, len(fqdns) * 2.0 + 45.0))
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
        detail=f"dnsx finished — exit {result.returncode}",
        config=config,
    )

    resolved: list[dict[str, Any]] = []
    for line in (result.stdout or "").strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            resolved.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return resolved


def detect_wildcard(
    domain: str,
    timeout: int,
    dnsx_binary: str,
) -> dict[str, Any]:
    """
    Probe a random label under ``domain``. If it resolves to A, wildcard is likely.
    """
    random_sub = secrets.token_hex(8)
    test_fqdn = f"{random_sub}.{domain.lower().strip()}"

    try:
        to_s = max(1, int(timeout))
        result = subprocess.run(
            [
                dnsx_binary,
                "-duc",
                "-d",
                test_fqdn,
                "-a",
                "-j",
                "-silent",
                "-timeout",
                f"{to_s}s",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=to_s + 5,
        )
        for line in (result.stdout or "").strip().splitlines():
            try:
                data = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            if str(data.get("host", "")).lower() != test_fqdn.lower():
                continue
            a_list = data.get("a")
            if isinstance(a_list, list) and a_list:
                wildcard_ip = str(a_list[0])
                return {
                    "detected": True,
                    "wildcard_ip": wildcard_ip,
                    "test_host": test_fqdn,
                    "note": (
                        f"Wildcard DNS detected — {domain} resolves unlikely hostnames "
                        f"to {wildcard_ip}. Results may contain false positives; "
                        "single-A matches to this IP were filtered when possible."
                    ),
                }
        return {"detected": False, "wildcard_ip": None, "test_host": test_fqdn}

    except Exception:  # noqa: BLE001
        return {
            "detected": False,
            "wildcard_ip": None,
            "error": "check failed",
            "test_host": test_fqdn,
        }


def _assess_dns_risk(
    host: str,
    a: list[Any],
    cname: list[Any],
    mx: list[Any],
    txt: list[Any],
    ns: list[Any],
) -> str:
    host_lower = host.lower()

    critical_patterns = (
        "admin",
        "panel",
        "control",
        "manage",
        "gitlab",
        "jenkins",
        "jira",
        "confluence",
        "vpn",
        "remote",
        "rdp",
        "ssh",
        "mysql",
        "postgres",
        "redis",
        "mongo",
        "internal",
        "intranet",
        "corp",
    )
    high_patterns = (
        "api",
        "dev",
        "staging",
        "homolog",
        "test",
        "ftp",
        "sftp",
        "smtp",
        "mail",
        "webmail",
        "crm",
        "erp",
        "support",
        "helpdesk",
    )

    for pattern in critical_patterns:
        if pattern in host_lower:
            return "CRITICAL"
    for pattern in high_patterns:
        if pattern in host_lower:
            return "HIGH"
    if mx:
        return "MEDIUM"
    if cname:
        return "MEDIUM"
    if ns and not a:
        return "MEDIUM"
    _ = txt
    return "LOW"


def _coerce_str_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, str):
        return [val] if val.strip() else []
    if isinstance(val, list):
        out: list[str] = []
        for x in val:
            if x is None:
                continue
            if isinstance(x, dict):
                # MX entries may be objects in some versions
                pref = x.get("host") or x.get("name") or x.get("target")
                if pref:
                    out.append(str(pref))
            else:
                s = str(x).strip()
                if s:
                    out.append(s)
        return out
    return [str(val)] if str(val).strip() else []


def parse_dnsx_output(
    raw_results: list[dict[str, Any]],
    domain: str,
    wildcard_ip: str | None,
) -> list[dict[str, Any]]:
    """Normalize dnsx JSONL rows; drop obvious wildcard-only A dupes."""
    _ = domain
    parsed: list[dict[str, Any]] = []

    for item in raw_results:
        host = str(item.get("host") or "").strip()
        if not host:
            continue

        a_records = _coerce_str_list(item.get("a"))
        aaaa_records = _coerce_str_list(item.get("aaaa"))
        cname = _coerce_str_list(item.get("cname") or item.get("cname-name"))
        mx = _coerce_str_list(item.get("mx"))
        txt = _coerce_str_list(item.get("txt"))
        ns = _coerce_str_list(item.get("ns"))

        cdn_name = str(
            item.get("cdn-name") or item.get("cdn_name") or item.get("cdn") or ""
        ).strip()
        asn_raw = item.get("asn")
        if isinstance(asn_raw, list):
            asn = ", ".join(str(x) for x in asn_raw if x)
        else:
            asn = str(asn_raw or "").strip()
        status_code = str(item.get("status_code") or item.get("rcode") or "")

        if wildcard_ip and len(a_records) == 1 and a_records[0] == wildcard_ip:
            continue

        ip: str | None = a_records[0] if a_records else (cname[0] if cname else None)

        risk = _assess_dns_risk(host, a_records, cname, mx, txt, ns)

        parsed.append(
            {
                "fqdn": host,
                "ip": ip,
                "a": a_records,
                "aaaa": aaaa_records,
                "cname": cname,
                "mx": mx,
                "txt": txt,
                "ns": ns,
                "cdn": cdn_name,
                "asn": asn,
                "status": status_code,
                "ttl": item.get("ttl"),
                "risk": risk,
                "wildcard": False,
            }
        )

    return parsed


def _records_summary(row: dict[str, Any]) -> str:
    parts: list[str] = []
    if row.get("a"):
        parts.append("A")
    if row.get("aaaa"):
        parts.append("AAAA")
    if row.get("cname"):
        parts.append("CNAME")
    if row.get("mx"):
        parts.append("MX")
    if row.get("txt"):
        parts.append("TXT")
    if row.get("ns"):
        parts.append("NS")
    return " · ".join(parts) if parts else "—"


def _display_results(resolved: list[dict[str, Any]], quiet: bool) -> None:
    if quiet or not resolved:
        return
    console.print()
    tbl = Table(
        title=Text("DNS RESULTS (dnsx)", style=f"bold {C_PRI}"),
        box=box.ROUNDED,
        border_style=C_PANEL,
        show_lines=True,
    )
    tbl.add_column("FQDN", style=C_DIM, no_wrap=False)
    tbl.add_column("IP / target", style=C_PRI)
    tbl.add_column("Records", style=C_MUTED)
    tbl.add_column("CDN", style=C_MUTED)
    tbl.add_column("Risk", style=C_DIM)
    for row in resolved[:50]:
        ip_disp = str(row.get("ip") or "—")
        if row.get("mx") and not row.get("a") and not row.get("cname"):
            ip_disp = "MX only"
        tbl.add_row(
            row["fqdn"],
            ip_disp,
            _records_summary(row),
            row.get("cdn") or "—",
            str(row.get("risk") or "LOW"),
        )
    if len(resolved) > 50:
        tbl.add_row("…", f"+{len(resolved) - 50} rows", "", "", "")
    console.print(tbl)


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Bulk-resolve FQDNs with dnsx using session subdomains or wordlist fallback.

    Never raises; errors accumulate in ``errors``.
    """
    t0 = time.perf_counter()
    quiet = bool(config.get("quiet", False))
    domain = target.value.lower().strip()

    base: dict[str, Any] = {
        "module": "dnsx_enum",
        "target": domain,
        "status": "success",
        "errors": [],
        "warnings": [],
        "resolved": [],
        "total_fqdns": 0,
        "total_resolved": 0,
        "wildcard": {"detected": False, "wildcard_ip": None},
        "dnsx_version": None,
        "stats": {
            "total_fqdns": 0,
            "total_resolved": 0,
            "duration_s": 0.0,
        },
        "findings_flat": [],
    }

    if not target.is_domain():
        base["status"] = "skipped"
        if not quiet:
            console.print(
                Text("  [SKIP] dnsx enum — domain targets only.", style=C_WARN)
            )
        return base

    dx = check_dnsx()
    base["dnsx_version"] = dx.get("version")
    if not dx.get("available"):
        base["status"] = "not_installed"
        err_msg = str(dx.get("error") or "dnsx unavailable")
        base["errors"].append(err_msg)
        if not quiet:
            console.print(Text("  [!] dnsx not found on this system", style=f"bold {C_ERR}"))
            inst = dx.get("install") or "sudo apt install dnsx"
            console.print(Text(f"  [i] Install: {inst}", style=C_MUTED))
        return base

    binary = str(dx.get("binary") or "dnsx")

    if not quiet:
        console.print(
            Panel(
                Text.assemble(
                    (" DNSX ENUM  ·  ", f"bold {C_PRI}"),
                    (domain, C_DIM),
                    ("  ·  bulk resolution + wildcard filter", C_MUTED),
                ),
                border_style=C_PANEL,
                box=box.HEAVY,
                padding=(0, 1),
                width=min(console.size.width, 80) if console.size else 80,
            )
        )
        console.print(
            Text(
                f" [✓] dnsx {dx.get('version') or 'detected'} ({binary})",
                style=C_PRI,
            )
        )

    threads = int(config.get("threads") or 50)
    timeout = int(config.get("timeout") or 5)
    record_types = config.get("dnsx_records")
    if not isinstance(record_types, list) or not record_types:
        record_types = ["a", "aaaa", "cname", "mx"]
    resolvers_raw = config.get("resolvers") or []
    resolvers = [str(x) for x in resolvers_raw] if isinstance(resolvers_raw, list) else []

    session_data = config.get("session_results")
    if not isinstance(session_data, dict):
        session_data = {}

    wl = _wordlist_path_from_config(config)
    fqdns = get_fqdns_for_target(target, session_data, wl)
    base["total_fqdns"] = len(fqdns)
    base["stats"]["total_fqdns"] = len(fqdns)

    if not fqdns:
        base["status"] = "error"
        base["errors"].append("no FQDNs to resolve")
        base["warnings"].append("no FQDNs to resolve")
        if not quiet:
            console.print(Text(" [!] No FQDNs to resolve.", style=C_WARN))
        return base

    if not quiet:
        console.print(
            Text(
                f"\n [►] Resolving {len(fqdns):,} FQDNs with dnsx...",
                style=f"bold {C_DIM}",
            )
        )

    wildcard = detect_wildcard(domain, timeout, binary)
    base["wildcard"] = wildcard
    if wildcard.get("detected"):
        note = str(wildcard.get("note") or "Wildcard DNS detected")
        base["warnings"].append(note)
        if not quiet:
            console.print(Text(f" [!] {note}", style=C_WARN))
    elif not quiet:
        console.print(
            Text(
                " [i] Wildcard DNS not detected — results are clean",
                style=C_MUTED,
            )
        )

    raw = run_dnsx(
        fqdns=fqdns,
        record_types=record_types,
        resolvers=resolvers,
        threads=threads,
        timeout=timeout,
        dnsx_binary=binary,
        config=config,
    )

    w_ip = wildcard.get("wildcard_ip")
    w_ip_s = str(w_ip) if w_ip else None

    resolved = parse_dnsx_output(raw, domain, w_ip_s)
    base["resolved"] = resolved
    base["total_resolved"] = len(resolved)
    base["stats"]["total_resolved"] = len(resolved)
    base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)

    if not quiet:
        console.print(
            Text(
                f" [✓] Resolved {len(resolved):,} / {len(fqdns):,} FQDNs",
                style=C_PRI,
            )
        )

    findings_flat: list[dict[str, Any]] = []
    for item in resolved:
        risk = str(item.get("risk") or "LOW").upper()
        if item.get("a"):
            note = f"A: {', '.join(item['a'][:2])}"
        elif item.get("cname"):
            note = f"CNAME: {item['cname'][0]}"
        elif item.get("mx"):
            note = f"MX: {item['mx'][0]}"
        else:
            note = "no A record"
        fd = make_finding(
            value=item["fqdn"],
            category="dns_resolution",
            risk=risk,
            note=note,
            metadata=item,
        )
        findings_flat.append(fd)

    base["findings_flat"] = findings_flat

    _display_results(resolved, quiet)

    if not quiet:
        rc = sum(1 for x in resolved if x.get("risk") == "CRITICAL")
        rh = sum(1 for x in resolved if x.get("risk") == "HIGH")
        console.print()
        console.print(Text(" [✓] dnsx enum complete", style=f"bold {C_PRI}"))
        console.print(
            Text(
                f"     FQDNs input: {len(fqdns):,}  ·  Resolved rows: {len(resolved):,}",
                style=C_DIM,
            )
        )
        console.print(
            Text(
                f"     Critical: {rc}  ·  High: {rh}  ·  Duration: {base['stats']['duration_s']}s",
                style=C_DIM,
            )
        )

    return base
