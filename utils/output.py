"""
Centralized terminal output for findings by severity (GhostOpcode).
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from rich.console import Console
from rich.text import Text

# Severity → terminal policy (verbose=True overrides MEDIUM/LOW/INFO to full detail)
TERMINAL_VERBOSITY: dict[str, str] = {
    "CRITICAL": "show_all",
    "HIGH": "show_all",
    "MEDIUM": "show_sample",
    "LOW": "summary_only",
    "INFO": "summary_only",
}

C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_DIM = "#6F7F86"
C_MUTED = "#4A5A62"
C_PRI = "#00FF41"
C_BLUE = "#6CA0DC"

console = Console(highlight=False, force_terminal=True)

# (regex, description) — applied to full URL string
_SENSITIVE_URL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"/senha/([^/\?&]{8,})", "Password in URL path"),
    (r"/password/([^/\?&]{8,})", "Password in URL path"),
    (r"[?&]senha=([^&]{4,})", "Password in query param"),
    (r"[?&]password=([^&]{4,})", "Password in query param"),
    (r"[?&]pass=([^&]{4,})", "Password in query param"),
    (r"[?&]passwd=([^&]{4,})", "Password in query param"),
    (r"/([a-zA-Z0-9_-]{24,})(?:/|\?|$)", "Possible token/key in URL path"),
    (
        r"[?&](?:api_key|apikey|api-key|token|access_token|secret|key|auth)=([^&]{8,})",
        "API key/token in param",
    ),
    (r"/private/", "Private path segment in URL"),
    (r"/admin/", "Admin path segment in URL"),
    (r"/internal/", "Internal path segment in URL"),
)


def detect_sensitive_in_url(url: str) -> str | None:
    """
    Flag URLs that may embed secrets, credentials, or high-value paths.

    Returns a short reason string or None if no pattern matched.
    """
    if not url or not url.strip():
        return None
    for pattern, description in _SENSITIVE_URL_PATTERNS:
        try:
            if re.search(pattern, url, re.IGNORECASE):
                return description
        except re.error:
            continue
    return None


def _norm_risk(raw: Any) -> str:
    r = str(raw or "LOW").strip().upper()
    if r in TERMINAL_VERBOSITY:
        return r
    return "LOW"


def _finding_value(f: dict[str, Any]) -> str:
    for key in ("value", "url", "path"):
        v = f.get(key)
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


def display_findings(
    findings: list[dict[str, Any]],
    module: str = "",
    verbose: bool = False,
) -> None:
    """
    Print findings according to ``TERMINAL_VERBOSITY``.

    - CRITICAL / HIGH: always full detail (never suppressed).
    - MEDIUM: top 3 per category unless ``verbose``.
    - LOW / INFO: counts only unless ``verbose``.
    """
    if not findings:
        return

    by_severity: dict[str, list[dict[str, Any]]] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "INFO": [],
    }

    for f in findings:
        rk = _norm_risk(f.get("risk"))
        if rk not in by_severity:
            rk = "LOW"
        by_severity[rk].append(f)

    title_suffix = f" — {module}" if module else ""

    # --- CRITICAL ---
    crit = by_severity["CRITICAL"]
    if crit:
        console.print()
        for finding in crit:
            value = _finding_value(finding)
            note = str(
                finding.get("note")
                or finding.get("description")
                or finding.get("detail")
                or ""
            ).strip()
            category = str(finding.get("category") or finding.get("type") or "finding")

            console.print(
                Text(
                    f" [!!!] CRITICAL — {category}{title_suffix}",
                    style=f"bold {C_ERR}",
                )
            )
            console.print(Text(f"       {value}", style=C_ERR))
            if note:
                console.print(Text(f"       {note}", style=C_WARN))
        console.print()

    # --- HIGH ---
    high = by_severity["HIGH"]
    if high:
        for finding in high:
            value = _finding_value(finding)
            category = str(finding.get("category") or finding.get("type") or "finding")
            note = str(finding.get("note") or finding.get("description") or "").strip()
            console.print(
                Text(f" [!] HIGH — {category}{title_suffix}", style=f"bold {C_WARN}")
            )
            console.print(Text(f"      {value}", style=C_WARN))
            if note:
                console.print(Text(f"      {note}", style=C_DIM))
        console.print()

    # --- MEDIUM ---
    med = by_severity["MEDIUM"]
    if med:
        if verbose:
            for finding in med:
                value = _finding_value(finding)
                category = str(
                    finding.get("category") or finding.get("type") or "misc"
                )
                console.print(
                    Text(
                        f" [i] MEDIUM — {category}{title_suffix}",
                        style=f"bold {C_BLUE}",
                    )
                )
                console.print(Text(f"      {value}", style=C_DIM))
        else:
            medium_by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for f in med:
                cat = str(f.get("category") or f.get("type") or "misc")
                medium_by_cat[cat].append(f)

            for cat, items in sorted(medium_by_cat.items()):
                shown = items[:3]
                rest = len(items) - 3
                for f in shown:
                    value = _finding_value(f)
                    console.print(
                        Text(
                            f" [i] MEDIUM — {cat}{title_suffix}",
                            style=f"bold {C_BLUE}",
                        )
                    )
                    console.print(Text(f"      {value}", style=C_DIM))
                if rest > 0:
                    console.print(
                        Text(
                            f"      … and {rest} more {cat} (see HTML report)",
                            style=C_MUTED,
                        )
                    )
        console.print()

    # --- LOW / INFO ---
    low_n = len(by_severity["LOW"])
    info_n = len(by_severity["INFO"])
    if not verbose:
        if low_n:
            console.print(
                Text(
                    f" [i] {low_n} LOW finding(s) — see HTML report{title_suffix}",
                    style=C_MUTED,
                )
            )
        if info_n:
            console.print(
                Text(
                    f" [i] {info_n} INFO finding(s) — see HTML report{title_suffix}",
                    style=C_MUTED,
                )
            )
    else:
        for bucket, label in (("LOW", "LOW"), ("INFO", "INFO")):
            for finding in by_severity[bucket]:
                value = _finding_value(finding)
                category = str(finding.get("category") or finding.get("type") or "misc")
                console.print(
                    Text(f" [i] {label} — {category}{title_suffix}", style=C_DIM)
                )
                console.print(Text(f"      {value}", style=C_MUTED))

    if verbose and (low_n or info_n):
        console.print()
