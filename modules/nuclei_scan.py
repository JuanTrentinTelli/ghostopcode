"""
GhostOpcode nuclei integration — template-based web vulnerability validation (nuclei v3).
"""

from __future__ import annotations
from utils.theme import C_PRI, C_DIM, C_ERR, C_WARN, C_MUTED, C_PANEL, console

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any

from rich import box
from rich.table import Table
from rich.text import Text

from utils.base_module import make_finding
from utils.output import debug_log
from utils.searchsploit import (
    display_exploit_enrichment,
    is_available as searchsploit_available,
    normalize_cve_id,
    search_cve,
    summarize as sploit_summarize,
)
from utils.target_parser import Target

NUCLEI_PROFILES: dict[int, dict[str, Any]] = {
    1: {
        "name": "Exposure",
        "label": "exposures + misconfigs (fast, low noise)",
        "tags": "exposure,misconfiguration,config",
        "severity": "medium,high,critical",
        "note": "Finds exposed files, panels, misconfigs",
        "risk": "LOW",
        "timeout_min": 5,
    },
    2: {
        "name": "CVE scan",
        "label": "known CVEs (recommended)",
        "tags": "cve",
        "severity": "medium,high,critical",
        "note": "Tests for known CVEs with templates",
        "risk": "MEDIUM",
        "timeout_min": 10,
    },
    3: {
        "name": "Full scan",
        "label": "CVE + exposures + takeovers (thorough)",
        "tags": "cve,exposure,misconfiguration,takeover",
        "severity": "low,medium,high,critical",
        "note": "Comprehensive — slower, more noise",
        "risk": "HIGH",
        "timeout_min": 20,
    },
}

_MAX_TARGETS = 50
_MAX_THREADS = 25


def check_nuclei() -> dict[str, Any]:
    """Check if nuclei binary is available; prefer nuclei v3 JSONL output."""
    candidates = [
        shutil.which("nuclei"),
        "/home/kali/go/bin/nuclei",
        "/root/go/bin/nuclei",
        "/usr/local/bin/nuclei",
    ]

    binary: str | None = None
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            binary = candidate
            break

    if not binary:
        return {
            "available": False,
            "error": "nuclei not found",
            "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        }

    try:
        result = subprocess.run(
            [binary, "-version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = (result.stdout or "") + (result.stderr or "")
        ansi = re.compile(r"\x1b\[[0-9;]*m")
        clean = ansi.sub("", output)
        version = ""
        for line in clean.splitlines():
            low = line.lower()
            if "version" in low or "v3." in line or "v2." in line:
                version = line.strip()
                break
        if not version and clean.strip():
            version = clean.strip().splitlines()[0].strip()

        is_v3 = "v3." in clean.lower() or "engine version: v3" in clean.lower()
        return {
            "available": True,
            "binary": binary,
            "version": version,
            "is_v3": is_v3,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "available": False,
            "error": f"nuclei check failed: {type(e).__name__}: {e}",
        }


def get_targets_for_nuclei(target: Target, session_data: dict[str, Any]) -> list[str]:
    """
    Build URL list for nuclei: httpx live URLs, else web_synthesis, else
    subfinder FQDNs, else apex target.
    """
    urls: set[str] = set()

    httpx_data = session_data.get("httpx_probe") or {}
    if isinstance(httpx_data, dict) and httpx_data.get("status") == "success":
        probed = httpx_data.get("probed") or []
        if isinstance(probed, list):
            for item in probed:
                if not isinstance(item, dict):
                    continue
                try:
                    sc = int(item.get("status_code") or 0)
                except (TypeError, ValueError):
                    sc = 0
                if sc not in (200, 301, 302, 401, 403):
                    continue
                url = str(
                    item.get("url") or item.get("final_url") or item.get("final-url") or ""
                ).strip()
                if url:
                    urls.add(url)

    if not urls:
        synthesis_data = session_data.get("web_synthesis") or {}
        if isinstance(synthesis_data, dict) and synthesis_data.get("status") == "success":
            top = synthesis_data.get("top_endpoints") or []
            if isinstance(top, list):
                for ep in top[:30]:
                    if not isinstance(ep, dict):
                        continue
                    u = str(ep.get("full_url") or ep.get("path") or "").strip()
                    if u:
                        urls.add(u)

    if not urls:
        subfinder_data = session_data.get("subfinder_enum") or {}
        if isinstance(subfinder_data, dict) and subfinder_data.get("status") == "success":
            found = subfinder_data.get("found") or []
            if isinstance(found, list):
                for row in found[:20]:
                    if not isinstance(row, dict):
                        continue
                    fqdn = str(
                        row.get("subdomain") or row.get("fqdn") or row.get("host") or ""
                    ).strip()
                    if fqdn:
                        urls.add(f"https://{fqdn}")

    if not urls:
        sub_enum = session_data.get("subdomain_enum") or {}
        if isinstance(sub_enum, dict) and sub_enum.get("status") == "success":
            found = sub_enum.get("found") or []
            if isinstance(found, list):
                for row in found[:20]:
                    if not isinstance(row, dict):
                        continue
                    fqdn = str(row.get("fqdn") or row.get("subdomain") or "").strip()
                    if fqdn:
                        urls.add(f"https://{fqdn}")

    if not urls:
        host = target.value.strip()
        urls.add(f"https://{host}")
        urls.add(f"http://{host}")

    out = sorted(urls)
    return out[:_MAX_TARGETS]


def prompt_nuclei_config(config: dict[str, Any]) -> bool:
    """Profile selection + mandatory CONFIRM; log via session_logger (redacted)."""
    console.print()
    console.print(Text(" [!!!] NUCLEI SCAN WARNING", style="bold yellow"))
    console.print(
        Text(
            "   · Active vulnerability templates will run against the target",
            style=C_WARN,
        )
    )
    console.print(
        Text(
            "   · Some templates may trigger IDS/IPS/WAF alerts",
            style=C_WARN,
        )
    )
    console.print(
        Text(
            "   · Only use on targets with explicit written authorization",
            style=C_WARN,
        )
    )
    console.print()
    console.print(Text(" [NUCLEI] Select scan profile:", style=C_DIM))

    for num, profile in sorted(NUCLEI_PROFILES.items()):
        console.print(
            Text.assemble(
                (f"   [{num}] ", C_PRI),
                (f"{profile['name']:<12}", "default"),
                (" — ", C_MUTED),
                (profile["label"], C_MUTED),
            )
        )

    console.print()
    logger = config.get("session_logger")
    log_op = getattr(logger, "log_operator_action", None) if logger is not None else None

    try:
        choice = input("   Select [default: 1]: ").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        if callable(log_op):
            log_op("Nuclei scan cancelled", "", redact=False, placeholder="")
        console.print(Text(" [i] Nuclei scan cancelled.", style=C_MUTED))
        return False

    profile_num = int(choice) if choice in ("1", "2", "3") else 1
    config["nuclei_profile"] = profile_num
    selected = NUCLEI_PROFILES[profile_num]
    console.print()
    console.print(
        Text(
            f"   Profile: {selected['name']} — {selected['note']}",
            style=C_DIM,
        )
    )
    console.print()

    try:
        confirm = input(
            "   Type 'CONFIRM' to proceed with nuclei scan: "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        if callable(log_op):
            log_op("Nuclei scan cancelled", "", redact=False, placeholder="")
        console.print(Text(" [i] Nuclei scan cancelled.", style=C_MUTED))
        return False

    if confirm != "CONFIRM":
        console.print(Text(" [i] Nuclei scan cancelled.", style=C_MUTED))
        if callable(log_op):
            log_op("Nuclei scan declined", "", redact=False, placeholder="")
        return False

    if callable(log_op):
        log_op(
            f"Nuclei scan authorized (profile: {selected['name']})",
            confirm,
            redact=True,
            placeholder=f"[operator confirmed nuclei {selected['name']} scan]",
        )
    return True


def run_nuclei(
    targets: list[str],
    profile: dict[str, Any],
    binary: str,
    threads: int,
    timeout: int,
    config: dict[str, Any],
) -> tuple[list[dict[str, Any]], str | None]:
    """
    Run nuclei; return (parsed JSONL rows, error_message_or_none).
    Uses -no-interactsh (no OAST callbacks to third parties).
    """
    if not targets:
        return [], None

    targets_file: str | None = None
    output_file: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
            encoding="utf-8",
            newline="\n",
        ) as tmp:
            tmp.write("\n".join(targets))
            targets_file = tmp.name

        fd, output_file = tempfile.mkstemp(suffix=".jsonl", text=True)
        os.close(fd)

        th = max(1, min(int(threads or 10), _MAX_THREADS))
        req_timeout = max(3, min(int(timeout or 10), 120))
        cmd = [
            binary,
            "-l",
            targets_file,
            "-j",
            "-o",
            output_file,
            "-tags",
            str(profile["tags"]),
            "-s",
            str(profile["severity"]),
            "-c",
            str(th),
            "-timeout",
            str(req_timeout),
            "-retries",
            "1",
            "-silent",
            "-ni",
            "-stats",
        ]

        debug_log(
            action="subprocess",
            detail=f"nuclei {profile['name']} — {len(targets)} targets",
            config=config,
        )

        timeout_wall = int(profile.get("timeout_min") or 10) * 60 + len(targets) * 10
        timeout_wall = max(120, min(timeout_wall, 7200))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_wall,
        )

        debug_log(
            action="subprocess",
            detail=f"nuclei finished — exit {result.returncode}",
            config=config,
        )

        findings: list[dict[str, Any]] = []
        if output_file and os.path.isfile(output_file):
            with open(output_file, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return findings, None

    except subprocess.TimeoutExpired:
        return [], "nuclei subprocess timed out (partial results discarded)"
    except Exception as e:  # noqa: BLE001
        return [], f"nuclei run failed: {type(e).__name__}: {e}"
    finally:
        for path in (targets_file, output_file):
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass


def _normalize_cves(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    s = str(raw).strip()
    return [s] if s else []


def parse_nuclei_findings(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map nuclei JSONL lines to GhostOpcode-style rows."""
    severity_map = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "LOW",
        "unknown": "LOW",
    }

    parsed: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        info = item.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        sev_raw = str(info.get("severity") or "unknown").lower()
        risk = severity_map.get(sev_raw, "LOW")

        template_id = str(
            item.get("template-id") or item.get("template_id") or ""
        )
        name = str(info.get("name") or template_id or "nuclei finding")
        description = str(info.get("description") or "")
        matched_at = str(
            item.get("matched-at")
            or item.get("matched_at")
            or item.get("url")
            or ""
        )
        host = str(item.get("host") or "")
        evidence = item.get("extracted-results") or item.get("extracted_results") or []
        if not isinstance(evidence, list):
            evidence = []

        cl = info.get("classification") or {}
        if not isinstance(cl, dict):
            cl = {}
        cves = _normalize_cves(cl.get("cve-id") or cl.get("cve_id"))
        cvss = cl.get("cvss-score") or cl.get("cvss_score")
        tags = info.get("tags") or []
        if not isinstance(tags, list):
            tags = [str(tags)] if tags else []
        reference = info.get("reference") or []
        if not isinstance(reference, list):
            reference = [reference] if reference else []

        parsed.append(
            {
                "template_id": template_id,
                "name": name,
                "description": description,
                "severity": sev_raw,
                "risk": risk,
                "host": host,
                "matched_at": matched_at,
                "evidence": evidence[:3],
                "cves": cves,
                "cvss": cvss,
                "tags": tags,
                "reference": reference[:2],
            }
        )

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    parsed.sort(key=lambda x: risk_order.get(x["risk"], 4))
    return parsed


def _enrich_nuclei_exploits(rows: list[dict[str, Any]]) -> None:
    if not rows or not searchsploit_available():
        return
    for row in rows:
        cves = row.get("cves") or []
        if not cves:
            continue
        all_sploits: list[dict[str, Any]] = []
        seen_edb: set[str] = set()
        for cve_id in cves:
            for ex in search_cve(str(cve_id), timeout=5):
                eid = str(ex.get("edb_id") or "").strip() or str(
                    ex.get("title") or ""
                )
                if eid in seen_edb:
                    continue
                seen_edb.add(eid)
                all_sploits.append(ex)
        if all_sploits:
            row["exploits"] = all_sploits
            row["exploit_summary"] = sploit_summarize(all_sploits)
            row["exploit_count"] = len(all_sploits)


def _display_nuclei_exploit_block(findings: list[dict[str, Any]], quiet: bool) -> None:
    if quiet or not searchsploit_available():
        return
    disp: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in findings:
        if not f.get("exploits"):
            continue
        cves_l = f.get("cves") or []
        cid = normalize_cve_id(str(cves_l[0])) if cves_l else ""
        if not cid:
            cid = "unknown"
        if cid in seen:
            continue
        seen.add(cid)
        disp.append(
            {
                "cve_id": cid,
                "exploits": f["exploits"],
                "exploit_summary": f.get("exploit_summary") or "",
            }
        )
    if disp:
        display_exploit_enrichment(disp, console)


def _display_findings(findings: list[dict[str, Any]], quiet: bool) -> None:
    if quiet or not findings:
        return
    console.print()
    console.print(Text(" [NUCLEI FINDINGS]", style=f"bold {C_PRI}"))
    console.print()

    table = Table(box=box.SIMPLE_HEAD, show_header=True, border_style=C_PANEL)
    table.add_column("Template", style=C_DIM, max_width=30)
    table.add_column("Host", style="default", max_width=32)
    table.add_column("CVE", style=C_MUTED, max_width=16)
    table.add_column("CVSS", justify="center", width=6)
    table.add_column("Risk", justify="center", width=10)
    table.add_column("ExploitDB", style=C_MUTED, max_width=22)

    for f in findings[:25]:
        risk = f.get("risk") or "LOW"
        risk_color = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "blue",
            "LOW": "dim",
        }.get(str(risk), "dim")

        cves_l = f.get("cves") or []
        cve = str(cves_l[0]) if cves_l else "—"
        cvss = str(f.get("cvss")) if f.get("cvss") not in (None, "") else "—"
        host = str(f.get("matched_at") or f.get("host") or "—")
        if len(host) > 32:
            host = host[:29] + "..."

        ex_note = str(f.get("exploit_summary") or "")[:22] or "—"
        table.add_row(
            str(f.get("name") or "")[:30],
            host,
            cve[:16],
            cvss,
            Text(str(risk), style=risk_color),
            ex_note,
        )

    console.print(table)
    if len(findings) > 25:
        console.print(
            Text(
                f" … and {len(findings) - 25} more (see HTML / JSON export)",
                style=C_MUTED,
            )
        )


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Run nuclei against session-derived URLs. Skipped in RUN ALL; requires CONFIRM.
    """
    t0 = time.perf_counter()
    quiet = bool(config.get("quiet", False))

    base: dict[str, Any] = {
        "module": "nuclei_scan",
        "target": target.value.strip(),
        "status": "success",
        "errors": [],
        "warnings": [],
        "findings": [],
        "findings_flat": [],
        "stats": {
            "duration_s": 0.0,
            "targets_scanned": 0,
            "total_findings": 0,
        },
    }

    if target.is_cidr():
        base["status"] = "skipped"
        base["warnings"].append("Nuclei scan is not available for CIDR targets.")
        if not quiet:
            console.print(
                Text("  [SKIP] nuclei — CIDR not supported.", style=C_WARN)
            )
        base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)
        return base

    if config.get("run_all"):
        base["status"] = "skipped"
        base["warnings"].append(
            "Nuclei skipped in RUN ALL — requires profile selection and CONFIRM. "
            "Use [16] individually."
        )
        if not quiet:
            console.print(
                Text(
                    "  [SKIP] nuclei — interactive CONFIRM required (not in RUN ALL).",
                    style=C_WARN,
                )
            )
        base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)
        return base

    nuclei_info = check_nuclei()
    if not nuclei_info.get("available"):
        base["status"] = "not_installed"
        err = str(nuclei_info.get("error") or "nuclei unavailable")
        base["errors"].append(err)
        if not quiet:
            console.print(Text(f"  [!] {err}", style=f"bold {C_ERR}"))
            inst = nuclei_info.get("install") or "https://github.com/projectdiscovery/nuclei"
            console.print(Text(f"  [i] Install: {inst}", style=C_MUTED))
        base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)
        return base

    if not quiet:
        console.print(
            Text(
                f" [✓] {nuclei_info.get('version') or 'nuclei'} ({nuclei_info.get('binary')})",
                style=C_PRI,
            )
        )

    if not prompt_nuclei_config(config):
        base["status"] = "skipped"
        base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)
        return base

    profile = NUCLEI_PROFILES.get(int(config.get("nuclei_profile") or 1), NUCLEI_PROFILES[1])
    session_data = config.get("session_results")
    if not isinstance(session_data, dict):
        session_data = {}

    threads = int(config.get("threads") or 25)
    timeout = int(config.get("timeout") or 10)

    targets = get_targets_for_nuclei(target, session_data)
    base["stats"]["targets_scanned"] = len(targets)

    if not quiet:
        console.print(
            Text(
                f"\n [►] Scanning {len(targets)} target(s) with nuclei ({profile['name']})...",
                style=f"bold {C_DIM}",
            )
        )

    if not nuclei_info.get("is_v3"):
        base["warnings"].append(
            "nuclei v3 recommended — older versions may use different JSONL fields"
        )

    if not targets:
        base["warnings"].append("No target URLs assembled for nuclei.")
        if not quiet:
            console.print(
                Text(" [i] No URLs to scan.", style=C_WARN)
            )
        base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)
        return base

    raw, run_err = run_nuclei(
        targets=targets,
        profile=profile,
        binary=str(nuclei_info["binary"]),
        threads=threads,
        timeout=timeout,
        config=config,
    )
    if run_err:
        base["warnings"].append(run_err)

    findings = parse_nuclei_findings(raw)
    _enrich_nuclei_exploits(findings)
    base["findings"] = findings
    base["stats"]["total_findings"] = len(findings)

    if not quiet:
        console.print(
            Text(f" [✓] Found {len(findings)} finding(s)", style=C_PRI)
        )

    _display_findings(findings, quiet)
    _display_nuclei_exploit_block(findings, quiet)

    findings_flat: list[dict[str, Any]] = []
    for row in findings:
        risk = row["risk"]
        cves = ", ".join(row["cves"]) if row["cves"] else ""
        note = row["name"]
        if cves:
            note = f"{note} — {cves}"
        if row.get("cvss") is not None and str(row.get("cvss")).strip():
            note = f"{note} (CVSS {row['cvss']})"
        if row.get("exploit_summary"):
            note = f"{note} — ExploitDB: {row['exploit_summary']}"

        cat = f"nuclei_{row['template_id']}" if row.get("template_id") else "nuclei"
        fd = make_finding(
            value=str(row.get("matched_at") or row.get("host") or target.value),
            category=cat,
            risk=risk,
            note=note,
            metadata=row,
        )
        findings_flat.append(fd)

    base["findings_flat"] = findings_flat
    base["profile"] = profile["name"]
    base["nuclei_version"] = nuclei_info.get("version") or ""
    base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)
    return base
