"""
ExploitDB local lookup via `searchsploit` (offline). Enriches CVE findings only.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
from collections import Counter
from typing import Any

_SPLOIT_CACHE: dict[str, list[dict[str, Any]]] = {}
_SPLOIT_LOCK = threading.Lock()


def normalize_cve_id(cve_id: str) -> str:
    if not cve_id or not str(cve_id).strip():
        return ""
    s = str(cve_id).strip().upper()
    if not s.startswith("CVE-"):
        s = f"CVE-{s}"
    return s


def is_available() -> bool:
    return shutil.which("searchsploit") is not None


def search_cve(cve_id: str, timeout: int = 10) -> list[dict[str, Any]]:
    if not cve_id:
        return []

    cve_normalized = normalize_cve_id(cve_id)
    if not cve_normalized:
        return []

    with _SPLOIT_LOCK:
        if cve_normalized in _SPLOIT_CACHE:
            return list(_SPLOIT_CACHE[cve_normalized])

    exploits = _query_searchsploit(cve_normalized, timeout)

    with _SPLOIT_LOCK:
        _SPLOIT_CACHE[cve_normalized] = exploits

    return exploits


def _query_searchsploit(cve_id: str, timeout: int) -> list[dict[str, Any]]:
    binary = shutil.which("searchsploit")
    if not binary:
        return []

    try:
        result = subprocess.run(
            [binary, "--cve", cve_id, "--json"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0 or not result.stdout.strip():
            return []

        data = json.loads(result.stdout)

        raw_exploits = (
            data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", [])
        )

        exploits: list[dict[str, Any]] = []
        for item in raw_exploits:
            if not isinstance(item, dict):
                continue
            title = str(item.get("Title") or "").strip()
            edb_id = str(item.get("EDB-ID") or "").strip()
            path = str(item.get("Path") or "").strip()
            e_type = str(item.get("Type") or "").strip()
            platform = str(item.get("Platform") or "").strip()
            date = str(item.get("Date_Published") or "").strip()

            if not title:
                continue

            exploits.append(
                {
                    "title": title,
                    "edb_id": edb_id,
                    "path": path,
                    "type": e_type,
                    "platform": platform,
                    "date": date,
                    "url": (
                        f"https://www.exploit-db.com/exploits/{edb_id}"
                        if edb_id
                        else ""
                    ),
                }
            )

        return exploits

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, ValueError):
        return []


def search_many(
    cve_ids: list[str], timeout: int = 5
) -> dict[str, list[dict[str, Any]]]:
    results: dict[str, list[dict[str, Any]]] = {}
    seen: set[str] = set()
    for raw in cve_ids:
        n = normalize_cve_id(raw)
        if not n or n in seen:
            continue
        seen.add(n)
        results[n] = search_cve(n, timeout)
    return results


def summarize(exploits: list[dict[str, Any]]) -> str:
    if not exploits:
        return "no exploits found"

    count = len(exploits)
    types = [
        str(e.get("type") or "").lower()
        for e in exploits
        if str(e.get("type") or "").strip()
    ]

    type_summary = ""
    if types:
        counts = Counter(types)
        parts = [
            f"{t} × {n}" if n > 1 else t for t, n in counts.most_common(3)
        ]
        type_summary = f" ({', '.join(parts)})"

    return f"{count} exploit{'s' if count > 1 else ''}{type_summary}"


def clear() -> None:
    with _SPLOIT_LOCK:
        _SPLOIT_CACHE.clear()


def display_exploit_enrichment(
    findings_with_exploits: list[dict[str, Any]],
    console: Any,
) -> None:
    if not findings_with_exploits:
        return

    console.print("\n [EXPLOITDB] Local exploit matches\n")

    for finding in findings_with_exploits[:10]:
        cve_id = finding.get("cve_id") or "unknown"
        sploits = finding.get("exploits") or []
        summary = finding.get("exploit_summary") or ""

        console.print(f"   [yellow]{cve_id}[/yellow] — {summary}")

        for sploit in sploits[:3]:
            stype = sploit.get("type") or "—"
            title = str(sploit.get("title") or "")[:60]
            console.print(f"     [dim]·[/dim] [{stype}] {title}")
            if sploit.get("path"):
                console.print(f"       [dim]{sploit['path']}[/dim]")
