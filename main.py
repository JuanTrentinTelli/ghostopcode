#!/usr/bin/env python3
"""
GhostOpcode — local offensive recon framework (interactive shell).
Step 1: structure, terminal UX, and module routing stubs.
"""

from __future__ import annotations

import datetime as _dt
import importlib
import os
import re
import sys
import time
from typing import Any

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import config as app_config

from utils.banner import show_banner
from utils.target_parser import Target, parse_target

# --- Visual tokens (dark / surgical) ------------------------------------------
C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_PANEL = "#8B9CA8"

console = Console(highlight=False, force_terminal=True)


def _print_wordlist_diagnostics() -> None:
    """Show resolved wordlist paths and line counts after banner."""
    entries: list[tuple[str, str | None, str]] = [
        ("Subdomains", app_config.WORDLIST_SUBDOMAINS, "sudo apt install seclists"),
        ("Dirs full", app_config.WORDLIST_DIRS, "sudo apt install seclists wordlists"),
        (
            "Dirs fast",
            app_config.WORDLIST_DIRS_FAST,
            "sudo apt install seclists wordlists",
        ),
        (
            "Dirs small",
            app_config.WORDLIST_DIRS_SMALL,
            "sudo apt install seclists wordlists",
        ),
        ("Files", app_config.WORDLIST_FILES, "sudo apt install seclists"),
        (
            "Passwords",
            app_config.WORDLIST_PASSWORDS,
            "sudo apt install seclists wordlists",
        ),
    ]
    console.print()
    console.print(
        Text(" [CONFIG] Wordlists detected:", style=f"bold {C_DIM}"),
    )
    for i, (label, path, apt_hint) in enumerate(entries):
        sym = "└──" if i == len(entries) - 1 else "├──"
        if path:
            n = app_config.count_lines(path)
            console.print(
                Text.assemble(
                    (f"   {sym} ", C_MUTED),
                    (f"{label:<12}", C_DIM),
                    (": ", C_MUTED),
                    (path + "  ", C_PRI),
                    (f"[{n} words]", C_MUTED),
                )
            )
        else:
            console.print(
                Text.assemble(
                    (f"   {sym} ", C_MUTED),
                    (f"{label:<12}", C_DIM),
                    (": ", C_MUTED),
                    ("[NOT FOUND]", f"bold {C_ERR}"),
                    (" — run: ", C_MUTED),
                    (apt_hint, C_WARN),
                )
            )
    console.print()


# Module key → import path (run(target, config))
_MODULE_IMPORTS: dict[str, str] = {
    "dns": "modules.dns_recon",
    "subs": "modules.subdomain_enum",
    "whois": "modules.whois_scan",
    "ports": "modules.port_scan",
    "dirs": "modules.dir_enum",
}


def run_module(name: str, target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Attempt to import and run a recon module.

    Returns dict with results. Never raises — catches all exceptions
    and returns {"status": "error", "error": str(e)}.
    """
    try:
        mod_path = _MODULE_IMPORTS.get(name)
        if mod_path:
            mod = importlib.import_module(mod_path)
            return mod.run(target, config)
        return {"status": "pending", "findings": [], "module": name}
    except Exception as e:  # noqa: BLE001 — contract: never raise
        return {"status": "error", "error": str(e), "module": name}


def _clear_screen() -> None:
    """Clear terminal using OS-appropriate command."""
    try:
        os.system("clear" if os.name != "nt" else "cls")
    except OSError:
        pass


def _abort() -> None:
    console.print(f"\n[{C_ERR}][!] Aborted by operator.[/{C_ERR}]")
    sys.exit(0)


def _safe_input(prompt: str, default: str | None = None) -> str:
    """
    Read a line from stdin; empty string if EOF.

    On KeyboardInterrupt, abort gracefully.
    """
    try:
        line = input(prompt)
    except KeyboardInterrupt:
        _abort()
    except EOFError:
        return default if default is not None else ""
    return line


def _panel_header(title: str, subtitle: str | None = None) -> Panel:
    """Framed section header in cold gray / matrix accent."""
    if subtitle:
        inner = Text.assemble(
            (title.upper(), f"bold {C_PRI}"),
            ("  ·  ", C_DIM),
            (subtitle, C_DIM),
        )
    else:
        inner = Text(title.upper(), style=f"bold {C_PRI}")
    return Panel(
        Align.left(inner),
        border_style=C_PANEL,
        box=box.HEAVY,
        padding=(0, 1),
        width=min(console.size.width, 80) if console.size else 80,
    )


def _slug_output_name(target: Target) -> str:
    """Filesystem-safe slug for session output directory."""
    s = target.value.replace("/", "_").replace(":", "_")
    return re.sub(r"[^\w.\-]+", "_", s, flags=re.ASCII)[:120] or "session"


# Module registry: id, key, display name, one-line blurb
_MODULE_ROWS: list[tuple[int, str, str, str]] = [
    (1, "dns", "DNS recon", "A/MX/NS/TXT + zone transfer"),
    (2, "subs", "Subdomain enum", "wordlist bruteforce"),
    (3, "whois", "WHOIS", "registration + tech fingerprint"),
    (4, "ports", "Port scan", "socket + nmap + banner grab"),
    (5, "dirs", "Dir enum", "path bruteforce"),
    (6, "harvest", "Harvester", "PDF/DOC/XLS + emails + config leaks"),
    (7, "methods", "HTTP methods", "OPTIONS/PUT/DELETE/TRACE probe"),
    (8, "js", "JS recon", "endpoints + secrets + source maps"),
    (9, "hash", "Hash module", "identify + crack local"),
    (10, "arp", "ARP scan", "CIDR only"),
    (11, "sniff", "Packet sniffer", "CIDR only"),
]


def _menu_separator() -> None:
    """Thin rule between module groups."""
    console.print(Text(f"  {'─' * 41}", style=C_MUTED))


def _render_module_menu(target: Target) -> None:
    """Print module list with [n] or [n/a] per target compatibility."""
    console.print()
    console.print(
        _panel_header("MODULES", str(target)),
    )
    console.print()

    def _line(mid: int, key: str, title: str, blurb: str) -> None:
        ok = target.supports(key)
        if ok:
            tag = Text(f"[{mid}]", style=f"bold {C_PRI}")
        else:
            tag = Text("[n/a]", style=f"bold {C_MUTED}")
        name_part = Text(f"  {title:<22}", style=C_DIM if not ok else "default")
        desc = Text(blurb, style=C_MUTED)
        console.print(Text.assemble(tag, name_part, desc))

    core = _MODULE_ROWS[:9]
    cidr_only = _MODULE_ROWS[9:]

    for mid, key, title, blurb in core:
        _line(mid, key, title, blurb)

    _menu_separator()
    for mid, key, title, blurb in cidr_only:
        _line(mid, key, title, blurb)
    _menu_separator()

    zero = Text("[0]", style=f"bold {C_WARN}")
    console.print(
        Text.assemble(
            zero,
            Text("  RUN ALL", style="bold"),
            Text("            execute all available modules", style=C_MUTED),
        )
    )
    console.print()
    console.print(Text("Select modules (e.g: 1 3 4 · 0 for all):", style=C_DIM))
    console.print(Text("❯ ", style=f"bold {C_PRI}"), end="")


def _parse_module_selection(raw: str, target: Target) -> list[tuple[int, str, str]]:
    """
    Parse operator module selection into ordered (id, key, title) tuples.

    Raises ValueError on invalid tokens or selection of n/a modules.
    """
    s = raw.strip()
    if not s:
        raise ValueError("Selection cannot be empty")

    tokens = s.replace(",", " ").split()
    id_to_row = {mid: (key, title) for mid, key, title, _ in _MODULE_ROWS}

    if len(tokens) == 1 and tokens[0] == "0":
        out: list[tuple[int, str, str]] = []
        for mid, key, title, _ in _MODULE_ROWS:
            if target.supports(key):
                out.append((mid, key, title))
        if not out:
            raise ValueError("No modules available for this target type")
        return out

    seen: set[int] = set()
    result: list[tuple[int, str, str]] = []
    for tok in tokens:
        if not tok.isdigit():
            raise ValueError(f"Invalid token: {tok!r}")
        mid = int(tok)
        if mid == 0:
            raise ValueError("Use 0 alone to run all available modules")
        if mid not in id_to_row:
            raise ValueError(f"Unknown module id: {mid}")
        if mid in seen:
            continue
        seen.add(mid)
        key, title = id_to_row[mid]
        if not target.supports(key):
            raise ValueError(f"Module [{mid}] {title} is not available for this target")
        result.append((mid, key, title))

    if not result:
        raise ValueError("Selection cannot be empty")
    return result


def _prompt_dir_enum_scan_mode(cfg: dict[str, Any]) -> None:
    """When Dir enum is selected, choose fast / normal / full preset."""
    console.print()
    console.print(Text(" [DIR ENUM] Scan mode:", style=f"bold {C_PRI}"))
    console.print(
        Text(
            "  [1] Fast    — ~5k paths, common wordlist  (~30s)",
            style=C_DIM,
        )
    )
    console.print(
        Text(
            "  [2] Normal  — ~87k paths, small wordlist   (~5min)",
            style=C_DIM,
        )
    )
    console.print(
        Text(
            "  [3] Full    — ~220k paths, medium wordlist (~20min)",
            style=C_DIM,
        )
    )
    console.print(
        Text(
            "      (Full adds extensions only for ~50 sensitive stems)",
            style=C_MUTED,
        )
    )
    console.print()
    raw = _safe_input("  Select mode [default: 1]: ")
    if not sys.stdin.isatty():
        console.print()
    tok = (raw.strip() or "1").split()[0] if raw.strip() else "1"
    try:
        mode = int(tok)
        if mode not in (1, 2, 3):
            mode = 1
    except ValueError:
        mode = 1
    cfg["dir_enum_mode"] = mode


def _prompt_config(selected: list[tuple[int, str, str]]) -> dict[str, Any]:
    """Collect threads, timeout, export format with defaults."""
    dt = app_config.DEFAULT_THREADS
    dto = app_config.DEFAULT_TIMEOUT
    cfg: dict[str, Any] = {
        "threads": dt,
        "timeout": dto,
        "export": "no",
        "verbose": False,
        "ports_range": "common",
    }

    if any(key == "dirs" for _, key, _ in selected):
        _prompt_dir_enum_scan_mode(cfg)

    console.print()
    console.print(
        Text.assemble(
            ("  Threads ", C_DIM),
            (f"[default: {dt}]", C_MUTED),
            (": ", C_DIM),
        ),
        end="",
    )
    t_raw = _safe_input("")
    if not sys.stdin.isatty():
        console.print()
    if t_raw.strip():
        try:
            cfg["threads"] = max(1, int(t_raw.strip()))
        except ValueError:
            console.print(
                Text(
                    f"  [!] Invalid threads — using default {dt}",
                    style=C_WARN,
                )
            )

    console.print(
        Text.assemble(
            ("  Timeout in seconds ", C_DIM),
            (f"[default: {dto}]", C_MUTED),
            (": ", C_DIM),
        ),
        end="",
    )
    to_raw = _safe_input("")
    if not sys.stdin.isatty():
        console.print()
    if to_raw.strip():
        try:
            cfg["timeout"] = max(1, int(to_raw.strip()))
        except ValueError:
            console.print(
                Text(
                    f"  [!] Invalid timeout — using default {dto}",
                    style=C_WARN,
                )
            )

    console.print(
        Text.assemble(
            ("  Export report? (json / html / both / no) ", C_DIM),
            ("[default: no]", C_MUTED),
            (": ", C_DIM),
        ),
        end="",
    )
    ex_raw = _safe_input("")
    if not sys.stdin.isatty():
        console.print()
    ex = ex_raw.strip().lower()
    if ex in {"json", "html", "both", "no", ""}:
        if ex:
            cfg["export"] = ex
    else:
        console.print(
            Text("  [!] Unknown export option — using default no", style=C_WARN)
        )

    console.print(
        Text.assemble(
            ("  Ports (common | 1-1024 | 80,443 | 1-65535) ", C_DIM),
            ("[default: common]", C_MUTED),
            (": ", C_DIM),
        ),
        end="",
    )
    pr_raw = _safe_input("")
    if not sys.stdin.isatty():
        console.print()
    if pr_raw.strip():
        cfg["ports_range"] = pr_raw.strip()

    return cfg


def _mission_summary(
    target: Target,
    modules: list[tuple[int, str, str]],
    cfg: dict[str, Any],
) -> None:
    """Render mission summary panel."""
    names = " · ".join(t for _, _, t in modules)
    lines = [
        f"Target   : {target}",
        f"Modules  : {names}",
        f"Threads  : {cfg['threads']}",
        f"Timeout  : {cfg['timeout']}s",
        f"Ports    : {cfg.get('ports_range', 'common')}",
    ]
    if "dir_enum_mode" in cfg:
        _de_labels = {1: "Fast (~5k)", 2: "Normal (~87k)", 3: "Full (~220k)"}
        lines.append(
            f"Dir enum : {_de_labels.get(int(cfg['dir_enum_mode']), cfg['dir_enum_mode'])}"
        )
    lines.append(f"Export   : {cfg['export']}")
    body = "\n".join(lines)
    p = Panel(
        Text(body, style=C_DIM),
        title=Text("MISSION SUMMARY", style=f"bold {C_PRI}"),
        border_style=C_PANEL,
        box=box.HEAVY,
        padding=(0, 1),
        width=min(console.size.width, 80) if console.size else 80,
    )
    console.print()
    console.print(p)
    console.print()
    console.print(Text("[ ENTER to start · CTRL+C to abort ]", style=C_MUTED))
    console.print(Text("❯ ", style=f"bold {C_PRI}"), end="")


def _result_hint(res: dict[str, Any], title: str) -> str | None:
    """One-line summary for results table when a module returns rich metadata."""
    _ = title
    st = res.get("status")
    if st in ("error", "skipped"):
        return None
    mod = res.get("module")
    if mod == "dns_recon":
        n = int(res.get("total_records") or 0)
        t = len(res.get("technologies") or [])
        ax = res.get("axfr") or {}
        parts = [f"{n} records", f"{t} tech"]
        if ax.get("vulnerable"):
            parts.append("AXFR VULN")
        return " · ".join(parts)
    if mod == "subdomain_enum":
        stats = res.get("stats") or {}
        n = len(res.get("found") or [])
        rps = stats.get("req_per_sec", 0)
        return f"{n} subs · {rps} req/s"
    if mod == "whois_scan":
        tech_n = len(res.get("technologies") or [])
        flags = res.get("security_flags") or []
        http = res.get("http") or {}
        ssl = http.get("ssl") or {}
        sans_n = len(ssl.get("sans") or [])
        parts = [f"{tech_n} tech", f"{len(flags)} sec flags"]
        if sans_n:
            parts.append(f"{sans_n} SANs")
        return " · ".join(parts)
    if mod == "port_scan":
        stt = res.get("stats") or {}
        o = int(stt.get("open") or 0)
        rps = stt.get("req_per_sec", 0)
        rs = res.get("risk_summary") or {}
        crit = len(rs.get("CRITICAL") or [])
        return f"{o} open · {rps} req/s · {crit} critical"
    if mod == "dir_enum":
        stt = res.get("stats") or {}
        n = int(stt.get("found") or 0)
        rps = stt.get("req_per_sec", 0)
        rs = res.get("risk_summary") or {}
        crit = len(rs.get("CRITICAL") or [])
        return f"{n} paths · {rps} req/s · {crit} critical"
    return None


def _run_modules_styled(
    modules: list[tuple[int, str, str]],
    target: Target,
    cfg: dict[str, Any],
) -> list[dict[str, Any]]:
    """Execute stubs with short delay and visual feedback."""
    rows: list[dict[str, Any]] = []
    for mid, key, title in modules:
        console.print(
            Text.assemble(
                (" [►] Running ", C_PRI),
                (f"{title} ...", "bold"),
            )
        )
        res = run_module(key, target, cfg)
        status = res.get("status", "unknown")
        if status == "error":
            msg = res.get("error") or (
                (res.get("errors") or ["unknown error"])[0]
                if isinstance(res.get("errors"), list) and res.get("errors")
                else "unknown error"
            )
            console.print(Text(f"     → error: {msg}", style=C_ERR))
        elif res.get("module") == "dns_recon":
            if status == "skipped":
                console.print(Text("     → skipped (wrong target type)", style=C_WARN))
            # Rich report already printed by dns_recon.run()
        elif res.get("module") == "subdomain_enum":
            if status == "skipped":
                console.print(Text("     → skipped (domain only)", style=C_WARN))
            # Rich report already printed by subdomain_enum.run()
        elif res.get("module") == "whois_scan":
            if status == "skipped":
                console.print(Text("     → skipped (domain / IP only)", style=C_WARN))
            # Rich report already printed by whois_scan.run()
        elif res.get("module") == "port_scan":
            if status == "skipped":
                console.print(Text("     → skipped (domain / IP only)", style=C_WARN))
            # Rich report already printed by port_scan.run()
        elif res.get("module") == "dir_enum":
            if status == "skipped":
                console.print(Text("     → skipped (domain / IP only)", style=C_WARN))
            # Rich report already printed by dir_enum.run()
        elif status == "pending":
            console.print(
                Text("     → not implemented yet (stub)", style=C_DIM)
            )
        rows.append(
            {
                "module": title,
                "status": status,
                "findings": res.get("findings", []),
                "error": res.get("error"),
                "result_hint": _result_hint(res, title),
            }
        )
        time.sleep(0.3)
    return rows


def _results_table(rows: list[dict[str, Any]]) -> None:
    """Final results table with rich.table."""
    table = Table(
        title=Text("RESULTS", style=f"bold {C_PRI}"),
        box=box.HEAVY,
        border_style=C_PANEL,
        header_style=f"bold {C_DIM}",
        show_lines=True,
    )
    table.add_column("Module", style=C_DIM)
    table.add_column("Status", style=C_DIM)
    table.add_column("Findings", style=C_MUTED)

    for r in rows:
        hint = r.get("result_hint")
        findings = r.get("findings") or []
        if hint:
            find_s = hint
        elif not findings:
            find_s = "—"
        else:
            find_s = str(len(findings)) + " item(s)"
        st = str(r.get("status", "—"))
        table.add_row(r.get("module", "—"), st, find_s)

    console.print()
    console.print(table)


def main() -> None:
    """Entry: banner → target → modules → config → confirm → stubs → table."""
    _clear_screen()
    show_banner()
    _print_wordlist_diagnostics()

    # --- Target ----------------------------------------------------------------
    console.print(_panel_header("TARGET"))
    console.print()
    console.print(Text("Enter target (domain / IP / CIDR):", style=C_DIM))
    console.print(Text("❯ ", style=f"bold {C_PRI}"), end="")

    target: Target | None = None
    while target is None:
        raw = _safe_input("")
        if not raw.strip():
            console.print(Text("[✗] entrada inválida — tente novamente", style=C_ERR))
            console.print(Text("❯ ", style=f"bold {C_PRI}"), end="")
            continue
        try:
            target = parse_target(raw)
        except ValueError:
            console.print(Text("[✗] entrada inválida — tente novamente", style=C_ERR))
            console.print(Text("❯ ", style=f"bold {C_PRI}"), end="")
        else:
            console.print(
                Text.assemble(
                    ("[✓] ", C_PRI),
                    (f"{target.value}  →  ", "bold"),
                    (target.type.name, f"bold {C_WARN}"),
                )
            )

    assert target is not None

    # --- Modules ---------------------------------------------------------------
    _render_module_menu(target)
    sel_raw = _safe_input("")
    while True:
        try:
            selected = _parse_module_selection(sel_raw, target)
            break
        except ValueError as e:
            console.print(Text(f"  [✗] {e}", style=C_ERR))
            console.print(Text("❯ ", style=f"bold {C_PRI}"), end="")
            sel_raw = _safe_input("")

    # --- Config ----------------------------------------------------------------
    config = _prompt_config(selected)

    # --- Confirm ---------------------------------------------------------------
    _mission_summary(target, selected, config)
    _ = _safe_input("")

    # --- Run -------------------------------------------------------------------
    console.print()
    results = _run_modules_styled(selected, target, config)

    # --- Output dir message ----------------------------------------------------
    _results_table(results)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = _slug_output_name(target)
    out_rel = os.path.join(app_config.OUTPUT_DIR, f"{slug}_{stamp}")
    console.print()
    console.print(
        Text.assemble(
            ("  [✓] Session complete. Output saved to: ", C_PRI),
            (out_rel + "/", C_DIM),
        )
    )

    # Ensure path exists for future steps (empty dir is OK)
    try:
        os.makedirs(app_config.OUTPUT_DIR, exist_ok=True)
        os.makedirs(out_rel, exist_ok=True)
    except OSError as e:
        console.print(Text(f"  [!] Could not create output dir: {e}", style=C_WARN))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _abort()
