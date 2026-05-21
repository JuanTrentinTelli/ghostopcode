"""
GhostOpcode directory / file enumeration — intelligent response analysis, catchall filter, risk intel.
"""

from __future__ import annotations
from utils.theme import C_PRI, C_DIM, C_ERR, C_WARN, C_MUTED, C_ACCENT, console

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from collections import Counter, deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin

import httpx
from rich import box
from rich.console import Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from config import (
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    MAX_URLS_DIR_ENUM,
    USER_AGENT,
    WORDLIST_DIRS,
    WORDLIST_DIRS_FAST,
    WORDLIST_DIRS_SMALL,
)
from utils.http_client import (
    httpx_verify,
    report_ssl_certificate_problem,
    resolve_base_url as _http_resolve_base_url,
)
from utils.output import debug_log, display_findings
from utils.target_parser import Target

DEFAULT_EXTENSIONS = ["php", "html", "js", "txt", "bak", "xml", "json"]

# Curated stems: extension fuzzing only for these (~50) to avoid path explosion
_SENSITIVE_NAMES: frozenset[str] = frozenset(
    {
        "config",
        "configuration",
        "settings",
        "setup",
        "install",
        "backup",
        "bkp",
        "database",
        "db",
        "dump",
        "export",
        "admin",
        "administrator",
        "panel",
        "dashboard",
        "manager",
        "login",
        "auth",
        "api",
        "test",
        "debug",
        "info",
        "index",
        "default",
        "main",
        "app",
        "web",
        "site",
        "wp-config",
        "local",
        "prod",
        "staging",
        "dev",
        "credentials",
        "secret",
        "secrets",
        "password",
        "passwd",
        "env",
        "environment",
        "docker",
        "deploy",
        "release",
    }
)

PATH_CATEGORIES: dict[str, dict[str, Any]] = {
    "git_exposed": {
        "patterns": [
            ".git/head",
            ".git/config",
            ".gitignore",
            ".git/commit_editmsg",
            ".svn/entries",
        ],
        "risk": "CRITICAL",
    },
    "config_files": {
        "patterns": [
            ".env",
            ".env.local",
            ".env.production",
            "config.php",
            "wp-config.php",
            "database.yml",
            "settings.py",
            "application.properties",
            "web.config",
            ".htaccess",
            "config.js",
            "secrets.json",
            "credentials",
        ],
        "risk": "CRITICAL",
    },
    "admin_panel": {
        "patterns": [
            "phpmyadmin",
            "adminer",
            "pma",
            "administrator",
            "admin",
            "panel",
            "dashboard",
            "manager",
            "control",
            "cpanel",
            "plesk",
            "webmin",
        ],
        "risk": "CRITICAL",
    },
    "backup_files": {
        "patterns": [
            ".bak",
            ".old",
            ".backup",
            ".orig",
            ".copy",
            "backup",
            "bkp",
            "~",
            ".swp",
            ".ds_store",
        ],
        "risk": "HIGH",
    },
    "api_endpoints": {
        "patterns": [
            "graphql",
            "swagger-ui",
            "api-docs",
            "openapi.json",
            "swagger.json",
            "api/v1",
            "api/v2",
            "api/v3",
            "rest",
            "/api/",
            "v1/",
            "v2/",
            "v3/",
        ],
        "risk": "HIGH",
    },
    "devops": {
        "patterns": [
            "jenkins",
            "gitlab",
            "docker-compose",
            "dockerfile",
            "makefile",
            ".travis.yml",
            ".github",
            "pipeline",
            "ci/",
            "deploy",
            "deployment",
        ],
        "risk": "HIGH",
    },
    "uploads": {
        "patterns": [
            "upload",
            "uploads",
            "/files",
            "/media",
            "/static",
            "/assets",
            "/public",
            "/storage",
        ],
        "risk": "MEDIUM",
    },
    "logs_debug": {
        "patterns": [
            "access.log",
            "error.log",
            "phpinfo.php",
            "info.php",
            "test.php",
            "debug.php",
            "/logs",
            "/log/",
            "/debug",
            "error_log",
        ],
        "risk": "MEDIUM",
    },
    "public_content": {
        "patterns": [
            "about",
            "contact",
            "login",
            "register",
            "sitemap.xml",
            "robots.txt",
            "favicon.ico",
        ],
        "risk": "LOW",
    },
}

_CATEGORY_ORDER: list[str] = [
    "git_exposed",
    "config_files",
    "admin_panel",
    "backup_files",
    "api_endpoints",
    "devops",
    "uploads",
    "logs_debug",
    "public_content",
]


def resolve_base_url(
    target: Target,
    timeout: float,
    config: dict[str, Any],
    ssl_notes: list[str] | None = None,
    diagnostics: list[str] | None = None,
) -> str | None:
    """Try HTTPS then HTTP; follow redirects to reach the canonical origin."""
    _ = diagnostics  # preserved for call-site compat; errors surface via ssl_notes
    return _http_resolve_base_url(target, timeout, config, ssl_warnings=ssl_notes)


def _body_fingerprint(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]


def detect_catchall(
    base_url: str,
    timeout: float,
    client: httpx.Client,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """
    Detect HTTP catchall/wildcard responses using three random paths.
    """
    result: dict[str, Any] = {
        "detected": False,
        "status_code": None,
        "body_length": None,
        "body_hash": None,
        "strategy": "none",
    }
    samples: list[tuple[int, str]] = []
    for _ in range(3):
        token = secrets.token_hex(10)
        path = f"/__ghostopcode_{token}__"
        url = f"{base_url.rstrip('/')}{path}"
        try:
            r = client.get(url, timeout=timeout)
            body = r.text[:4096]
            samples.append((r.status_code, body))
        except Exception as e:  # noqa: BLE001
            if warnings is not None and len(warnings) < 6:
                warnings.append(
                    f"catchall random-path probe: {type(e).__name__}: {e}"
                )
            samples.append((0, ""))

    statuses = [s[0] for s in samples]
    if not all(st == 200 for st in statuses):
        return result

    lens = [len(b) for _, b in samples]
    hashes = [_body_fingerprint(b) for _, b in samples]

    result["detected"] = True
    result["status_code"] = 200

    if len(set(lens)) == 1:
        result["strategy"] = "length"
        result["body_length"] = lens[0]
        result["body_hash"] = hashes[0]
        return result

    # Varying lengths but maybe same template — use majority hash
    from collections import Counter

    hc = Counter(hashes)
    common_h, cnt = hc.most_common(1)[0]
    if cnt >= 2:
        result["strategy"] = "hash"
        result["body_hash"] = common_h
        result["body_length"] = lens[hashes.index(common_h)]
        return result

    result["strategy"] = "hash"
    result["body_hash"] = hashes[0]
    result["body_length"] = lens[0]
    return result


def build_paths(wordlist_path: str, extensions: list[str]) -> tuple[list[str], int]:
    """
    Load wordlist and build a smart path list.

    Strategy:
    - Words without a dot in the final segment → /word and /word/ only.
    - Words that already include an extension (dot in basename) → /word as-is only.
    - If ``extensions`` is non-empty, only stems in _SENSITIVE_NAMES get
      /word.ext variants (keeps Full mode bounded).
    """
    words: list[str] = []
    p = Path(wordlist_path)
    with p.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            w = line.strip()
            if w and not w.startswith("#"):
                words.append(w)

    raw_n = len(words)
    paths: dict[str, None] = {}

    def add(path: str) -> None:
        if path not in paths:
            paths[path] = None

    ext_clean = [e.lstrip(".").lower() for e in extensions if e.strip()]
    allow_ext = bool(ext_clean)

    for raw in words:
        w = raw.strip().strip("/")
        if not w:
            continue
        last_seg = w.split("/")[-1]
        if "." in last_seg:
            add(f"/{w}")
            continue
        add(f"/{w}")
        add(f"/{w}/")
        if allow_ext and w.lower() in _SENSITIVE_NAMES:
            for ext in ext_clean:
                add(f"/{w}.{ext}")

    return sorted(paths.keys()), raw_n


def _classify_path(path: str) -> tuple[str, str]:
    """Return (category, risk)."""
    pl = path.lower()
    for cat in _CATEGORY_ORDER:
        spec = PATH_CATEGORIES[cat]
        for pat in spec["patterns"]:
            pat_l = pat.lower()
            if pat_l in pl:
                return cat, str(spec["risk"])
    return "uncategorized", "LOW"


def _redirect_note(dest: str | None) -> str:
    if not dest:
        return "Redirect"
    dl = dest.lower()
    if "login" in dl or "signin" in dl or "auth" in dl:
        return "Redirects to login / auth surface"
    if "admin" in dl:
        return "Redirects toward admin area"
    return f"Redirects to {dest[:60]}"


def _interesting_status(status: int) -> bool:
    return status in {
        200,
        201,
        202,
        203,
        204,
        301,
        302,
        303,
        307,
        308,
        401,
        403,
        405,
        500,
        503,
    }


def analyze_probe(
    path: str,
    url: str,
    status: int,
    body_len: int,
    body_fp: str | None,
    redirect_url: str | None,
    catchall: dict[str, Any],
) -> tuple[dict[str, Any] | None, bool]:
    """
    Core dir_enum analysis from status, optional body fingerprint, and length.
    ``body_fp`` None skips hash-based catchall matching (ffuf has no body).
    """
    filtered = False
    st = status

    if st == 404:
        return None, False

    if not _interesting_status(st):
        return None, False

    blen = body_len

    if st == 200 and catchall.get("detected"):
        strat = catchall.get("strategy")
        if strat == "length" and catchall.get("body_length") is not None:
            if blen == catchall["body_length"]:
                return None, True
        if (
            strat == "hash"
            and catchall.get("body_hash")
            and body_fp is not None
        ):
            if body_fp == catchall["body_hash"]:
                return None, True

    if st == 200 and blen == 0 and catchall.get("detected"):
        return None, True

    cat, risk = _classify_path(path)

    if cat == "uncategorized":
        if st in (401, 403):
            risk = "HIGH"
        elif st in (301, 302, 303, 307, 308):
            risk = "MEDIUM"
        elif st in (500, 503, 405):
            risk = "MEDIUM"
        elif st in (200, 201, 202, 203, 204):
            risk = "LOW"

    note = ""
    redir = redirect_url
    if st in (301, 302, 303, 307, 308) and redir:
        note = _redirect_note(redir)
        if any(x in path.lower() for x in ("admin", "panel", "dashboard", "manage")):
            cat, risk = "admin_panel", "CRITICAL"
    elif st == 401:
        note = "Authentication required — path likely exists"
    elif st == 403:
        note = "Forbidden — path likely exists but denied"
    elif st == 405:
        note = "Method not allowed — resource exists"
    elif st == 500:
        note = "Server error — may leak stack traces"
    elif st == 503:
        note = "Service unavailable — endpoint exists"
    elif st in (200, 201, 202, 203, 204):
        if ".env" in path.lower():
            note = "Environment file exposed — may contain secrets"
            cat, risk = "config_files", "CRITICAL"
        elif ".git" in path.lower():
            note = "Git metadata exposed — source may be recoverable"
            cat, risk = "git_exposed", "CRITICAL"
        elif cat == "api_endpoints":
            note = "API surface — enumerate versions and auth"
        elif cat == "backup_files":
            note = "Backup / swap artifact — inspect for leaks"
        else:
            note = "Accessible resource"

    finding: dict[str, Any] = {
        "path": path if path.startswith("/") else "/" + path,
        "url": url,
        "status": st,
        "redirect": redir,
        "size": blen,
        "category": cat,
        "risk": risk,
        "note": note,
    }
    return finding, filtered


def analyze_response(
    path: str,
    url: str,
    status: int,
    body: str,
    headers: dict[str, str],
    redirect_url: str | None,
    catchall: dict[str, Any],
) -> tuple[dict[str, Any] | None, bool]:
    """
    Analyze HTTP response; return (finding or None, was_filtered_by_catchall).
    """
    _ = headers
    bf = _body_fingerprint(body)
    return analyze_probe(
        path, url, status, len(body), bf, redirect_url, catchall
    )


def _check_ffuf() -> dict[str, Any]:
    binary = shutil.which("ffuf")
    if not binary:
        return {"available": False, "binary": None, "version": ""}

    try:
        result = subprocess.run(
            [binary, "-V"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = (result.stdout + result.stderr).strip()
        return {
            "available": True,
            "binary": binary,
            "version": version,
        }
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "binary": None, "version": ""}


def _run_ffuf(
    base_url: str,
    path_tokens: list[str],
    threads: int,
    timeout_per_req: int,
    binary: str,
    config: dict[str, Any],
) -> tuple[list[dict[str, Any]], str | None]:
    """
    Run ffuf with the same path tokens the Python engine would probe.
    Returns (raw result rows, error_message_or_none).
    """
    if not path_tokens:
        return [], None

    out_path: str | None = None
    wl_path: str | None = None
    try:
        fd_wl, wl_path = tempfile.mkstemp(suffix=".txt", text=True)
        with os.fdopen(fd_wl, "w", encoding="utf-8", newline="\n") as wf:
            for p in path_tokens:
                tok = (p or "").lstrip("/")
                if tok:
                    wf.write(tok + "\n")

        fd_out, out_path = tempfile.mkstemp(suffix=".json", text=True)
        os.close(fd_out)

        ff_t = max(1, min(int(threads), 100))
        to = max(1, int(timeout_per_req))

        cmd: list[str] = [
            binary,
            "-u",
            f"{base_url.rstrip('/')}/FUZZ",
            "-w",
            wl_path,
            "-t",
            str(ff_t),
            "-timeout",
            str(to),
            "-o",
            out_path,
            "-of",
            "json",
            "-mc",
            "200,201,202,203,204,301,302,303,307,308,401,403,405,500,503",
            "-fc",
            "404",
            "-s",
            "-r",
            "-H",
            f"User-Agent: {USER_AGENT}",
        ]
        if not httpx_verify(config):
            cmd.append("-k")

        debug_log(
            action="subprocess",
            detail=(
                f"ffuf {base_url.rstrip('/')}/FUZZ "
                f"w={Path(wl_path).name} lines={len(path_tokens)} t={ff_t}"
            ),
            config=config,
        )

        wall_timeout = max(300, min(7200, len(path_tokens) // max(ff_t // 2, 1) + 400))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=float(wall_timeout),
        )

        debug_log(
            action="subprocess",
            detail=f"ffuf finished — exit {result.returncode}",
            config=config,
        )

        try:
            with open(out_path, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError, ValueError):
            return [], "ffuf JSON output missing or invalid"

        if result.returncode != 0 and not (data.get("results") or []):
            msg = (result.stderr or result.stdout or "").strip()[:200]
            return [], f"ffuf exited {result.returncode}" + (f": {msg}" if msg else "")

        raw: list[dict[str, Any]] = []
        for item in data.get("results") or []:
            if not isinstance(item, dict):
                continue
            inp = item.get("input") or {}
            if not isinstance(inp, dict):
                inp = {}
            fuzz = str(inp.get("FUZZ") or "").strip()
            if not fuzz:
                continue
            rel = "/" + fuzz if not fuzz.startswith("/") else fuzz
            st = int(item.get("status") or 0)
            loc = str(item.get("redirectlocation") or "").strip() or None
            raw.append(
                {
                    "path": rel,
                    "url": str(item.get("url") or "").strip(),
                    "status": st,
                    "length": int(item.get("length") or 0),
                    "words": int(item.get("words") or 0),
                    "redirect": loc,
                }
            )

        return raw, None

    except subprocess.TimeoutExpired:
        return [], "ffuf subprocess timed out"
    except OSError as e:
        return [], f"ffuf failed: {type(e).__name__}: {e}"
    finally:
        for pth in (out_path, wl_path):
            if pth:
                try:
                    os.unlink(pth)
                except OSError:
                    pass


def _normalize_ffuf_results(
    raw: list[dict[str, Any]],
    base_url: str,
    catchall: dict[str, Any],
) -> tuple[list[dict[str, Any]], int]:
    """
    Map ffuf rows to the same finding dicts as the Python engine; return filtered count.
    """
    normalized: list[dict[str, Any]] = []
    filtered_n = 0
    host_base = base_url.rstrip("/")

    for item in raw:
        path = str(item.get("path") or "")
        if not path:
            continue
        status = int(item.get("status") or 0)
        url = str(item.get("url") or "").strip() or f"{host_base}{path}"
        length = int(item.get("length") or 0)
        redir = item.get("redirect")
        if isinstance(redir, str) and not redir.strip():
            redir = None

        fn, was_f = analyze_probe(
            path,
            url,
            status,
            length,
            None,
            redir if isinstance(redir, str) else None,
            catchall,
        )
        if was_f:
            filtered_n += 1
        elif fn:
            fn = dict(fn)
            fn["source"] = "ffuf"
            normalized.append(fn)

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    normalized.sort(key=lambda x: risk_order.get(str(x.get("risk")), 4))
    return normalized, filtered_n


def check_git_exposed(base_url: str, timeout: float, client: httpx.Client) -> dict[str, Any]:
    """
    Deep-probe .git exposure: config, commit message, ref logs.
    """
    out: dict[str, Any] = {
        "exposed": False,
        "remote": None,
        "branch": None,
        "last_commit": None,
        "errors": [],
    }
    root = base_url.rstrip("/")

    def fetch(rel: str) -> str | None:
        try:
            r = client.get(f"{root}{rel}", timeout=timeout)
            if r.status_code == 200 and r.text.strip():
                return r.text[:8000]
        except Exception as e:  # noqa: BLE001
            out["errors"].append(str(e))
        return None

    head = fetch("/.git/HEAD")
    if not head:
        return out
    out["exposed"] = True

    cfg = fetch("/.git/config")
    if cfg:
        m = re.search(r"url\s*=\s*(\S+)", cfg)
        if m:
            out["remote"] = m.group(1).strip()

    for line in head.splitlines():
        line = line.strip()
        if line.startswith("ref:"):
            ref = line.split("ref:", 1)[1].strip()
            out["branch"] = ref.split("/")[-1] if ref else None
            break

    msg = fetch("/.git/COMMIT_EDITMSG")
    if msg:
        out["last_commit"] = msg.strip()[:200]

    if not out["last_commit"]:
        logs = fetch("/.git/logs/HEAD")
        if logs:
            last = logs.strip().splitlines()[-1] if logs.strip() else ""
            out["last_commit"] = last[:200] if last else None

    return out


class _DirEnumLiveDisplay:
    """Progress + speed (3s window) + found + recent hits."""

    def __init__(
        self,
        progress: Progress,
        task_id: Any,
        total: int,
        base_url: str,
        get_snapshot: Callable[[], tuple[int, int, int, float, float, list[str]]],
        quiet: bool = False,
    ) -> None:
        self.progress = progress
        self.task_id = task_id
        self.total = total
        self.base_url = base_url
        self._snapshot = get_snapshot
        self.quiet = quiet

    def __rich__(self) -> RenderableType:
        done, n_found, n_filt, elapsed, rps, recent = self._snapshot()
        pct = (done / self.total * 100) if self.total else 0.0
        remaining = max(0, self.total - done)
        eta = (remaining / rps) if rps > 0.1 else 0.0

        self.progress.update(self.task_id, completed=done, total=self.total)

        stats_line = Text.assemble(
            (" Speed: ", C_MUTED),
            (f"{rps:.0f} req/s", C_PRI),
            (" · Found: ", C_MUTED),
            (str(n_found), f"bold {C_WARN}"),
            (" · Filtered: ", C_MUTED),
            (str(n_filt), C_DIM),
            (" · Elapsed: ", C_MUTED),
            (f"{elapsed:.1f}s", C_DIM),
            (" · ETA: ", C_MUTED),
            (f"{eta:.1f}s" if eta < 86400 else "—", C_DIM),
            (f" · {pct:.0f}%", C_MUTED),
        )

        if self.quiet:
            hits_block = Text("")
        elif recent:
            hits_block = Group(
                *[_style_live_hit(ln) for ln in recent],
            )
        else:
            hits_block = Text("")

        return Group(
            self.progress,
            stats_line,
            Text(""),
            hits_block,
        )


def _risk_tag_style(risk: str) -> str:
    if risk == "CRITICAL":
        return f"bold {C_ERR}"
    if risk == "HIGH":
        return f"bold {C_WARN}"
    if risk == "MEDIUM":
        return C_WARN
    if risk == "LOW":
        return C_PRI
    return C_DIM


def _style_live_hit(line: str) -> Text:
    if line.startswith("[CRITICAL]"):
        return Text(line, style=f"bold {C_ERR}")
    if line.startswith("[HIGH]"):
        return Text(line, style=f"bold {C_WARN}")
    if line.startswith("[MEDIUM]"):
        return Text(line, style=C_WARN)
    if line.startswith("[LOW]"):
        return Text(line, style=C_PRI)
    return Text(line, style=C_PRI)


def _hit_line_str(f: dict[str, Any]) -> str:
    risk = f.get("risk", "LOW")
    p = f.get("path", "")
    st = f.get("status", 0)
    sz = f.get("size", 0)
    tag = f"[{risk}]"
    line = f"{tag:<12} {p:<32} {st}"
    if f.get("redirect"):
        line += f"  → {str(f['redirect'])[:40]}"
    else:
        line += f"  {sz}b"
    return line


def _human_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f}MB"
    if n >= 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n}b"


def _render_header(base_url: str, n_paths: int) -> None:
    p = Panel(
        Text(
            f"  DIR ENUM  ·  {base_url}  ·  {n_paths} paths",
            style=f"bold {C_PRI}",
        ),
        border_style=C_ACCENT,
        box=box.DOUBLE,
        width=min(console.size.width, 82) if console.size else 82,
    )
    console.print(p)


def _finding_response_length(finding: dict[str, Any]) -> int | None:
    """Prefer ``size`` (Python engine); ffuf raw used ``length`` before normalize."""
    for key in ("size", "length"):
        v = finding.get(key)
        if v is None:
            continue
        try:
            return int(v)
        except (TypeError, ValueError):
            continue
    return None


def _filter_by_dominant_response_length(
    items: list[dict[str, Any]],
    *,
    threshold: int = 2000,
    dominance_ratio: float = 0.30,
) -> tuple[list[dict[str, Any]], int | None, int]:
    """
    Empirical catch-all: if one response length accounts for more than
    ``dominance_ratio`` of all hits, treat that length as wildcard noise and
    drop rows within ``threshold`` bytes of it. Unknown-length rows are kept.
    Skipped when there is only one hit (cannot infer a distribution).
    Returns (filtered, dominant_length_or_none, num_removed).
    """
    if len(items) < 2:
        return items, None, 0

    size_counts: Counter[int] = Counter()
    for r in items:
        ln = _finding_response_length(r)
        if ln is not None:
            size_counts[ln] += 1

    if not size_counts:
        return items, None, 0

    most_common_size, count = size_counts.most_common(1)[0]
    if count / len(items) <= dominance_ratio:
        return items, None, 0

    n_before = len(items)
    out: list[dict[str, Any]] = []
    for r in items:
        ln = _finding_response_length(r)
        if ln is None:
            out.append(r)
            continue
        if abs(ln - most_common_size) > threshold:
            out.append(r)

    return out, most_common_size, n_before - len(out)


def _print_catchall_notice(catchall: dict[str, Any]) -> None:
    if not catchall.get("detected"):
        console.print(
            Text(
                " [i] Catchall/wildcard not detected — clean enumeration",
                style=C_MUTED,
            )
        )
        return
    strat = catchall.get("strategy", "length")
    bl = catchall.get("body_length")
    console.print(
        Text(
            f" [!] Catchall detected — filtering by body {strat} ({bl} bytes typical)",
            style=f"bold {C_WARN}",
        )
    )
    console.print(
        Text(
            "     False positives will be suppressed automatically",
            style=C_MUTED,
        )
    )


def _print_git_intel(g: dict[str, Any]) -> None:
    if not g.get("exposed"):
        return
    console.print()
    console.print(
        Text(" [!!!] GIT REPOSITORY EXPOSED", style=f"bold {C_ERR}"),
    )
    console.print(
        Text(
            "       Source code may be fully recoverable",
            style=C_WARN,
        )
    )
    if g.get("remote"):
        console.print(Text(f"       ├── Remote  : {g['remote']}", style=C_DIM))
    if g.get("branch"):
        console.print(Text(f"       ├── Branch  : {g['branch']}", style=C_DIM))
    if g.get("last_commit"):
        console.print(
            Text(f"       └── Commit  : {g['last_commit'][:120]!r}", style=C_DIM)
        )


def _engine_summary_line(base: dict[str, Any]) -> str:
    eng = str(base.get("engine") or "python")
    ver = (base.get("engine_ver") or "").strip().split("\n")[0][:80]
    if eng == "ffuf" and ver:
        return f"ffuf ({ver})"
    return eng


def _print_results_table(found: list[dict[str, Any]]) -> None:
    if not found:
        return
    table = Table(
        box=box.ROUNDED,
        border_style=C_ACCENT,
        header_style=f"bold {C_DIM}",
        show_lines=True,
    )
    table.add_column("Path", style=C_PRI, max_width=22)
    table.add_column("Status", style=C_DIM)
    table.add_column("Size", style=C_DIM)
    table.add_column("Note", style=C_MUTED, max_width=36)
    table.add_column("Risk", justify="right")

    for f in sorted(found, key=lambda x: (x.get("risk", ""), x.get("path", ""))):
        st = str(f.get("status", ""))
        if f.get("redirect"):
            sz = f"→ {str(f['redirect'])[:28]}"
        else:
            sz = _human_size(int(f.get("size") or 0))
        note = (f.get("note") or "")[:80]
        table.add_row(
            f.get("path", "")[:22],
            st,
            sz[:24],
            note[:36],
            Text(f"[{f.get('risk', 'LOW')}]", style=_risk_tag_style(str(f.get("risk")))),
        )
    console.print()
    console.print(table)


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Bruteforce web paths with httpx, catchall filtering, categorization, optional git intel.
    """
    t_start = time.perf_counter()
    threads = max(1, int(config.get("threads") or DEFAULT_THREADS))
    timeout = max(1.0, float(config.get("timeout") or DEFAULT_TIMEOUT))
    verbose = bool(config.get("verbose", False))
    quiet = bool(config.get("quiet", False))

    mode_raw = config.get("dir_enum_mode")
    mode = int(mode_raw) if mode_raw is not None else 1
    if mode not in (1, 2, 3):
        mode = 1

    wl_path: str | None = config.get("dir_enum_wordlist")
    if not wl_path:
        if mode == 1:
            wl_path = WORDLIST_DIRS_FAST
        elif mode == 2:
            wl_path = WORDLIST_DIRS_SMALL
        else:
            wl_path = WORDLIST_DIRS

    extensions = list(config.get("extensions") or DEFAULT_EXTENSIONS)
    if mode in (1, 2):
        extensions = []

    base: dict[str, Any] = {
        "module": "dir_enum",
        "target": target.value,
        "dir_enum_mode": mode,
        "status": "skipped",
        "base_url": "",
        "catchall": {
            "detected": False,
            "strategy": "none",
        },
        "found": [],
        "stats": {
            "wordlist_size": 0,
            "paths_tested": 0,
            "found": 0,
            "filtered": 0,
            "duration_s": 0.0,
            "req_per_sec": 0.0,
        },
        "risk_summary": {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []},
        "git_intel": {},
        "errors": [],
        "warnings": [],
        "findings": [],
        "engine": "python",
        "engine_ver": "",
    }

    if target.is_cidr():
        _render_header(target.value, 0)
        console.print(
            Text("  [SKIP] Dir enum — use a domain or single IP.", style=C_WARN)
        )
        return base

    if not wl_path or not Path(wl_path).is_file():
        console.print(Text(" [!] Wordlist not found", style=C_ERR))
        console.print(
            Text(
                " [i] Fast:  SecLists …/Web-Content/common.txt",
                style=C_MUTED,
            )
        )
        console.print(
            Text(
                " [i] Small: dirbuster/directory-list-2.3-small.txt",
                style=C_MUTED,
            )
        )
        console.print(
            Text(
                " [i] Full:  dirbuster/directory-list-2.3-medium.txt",
                style=C_MUTED,
            )
        )
        console.print(
            Text(" [i] Install: sudo apt install wordlists seclists", style=C_MUTED)
        )
        base["status"] = "error"
        base["error"] = "Wordlist not found"
        base["errors"].append(base["error"])
        return base

    try:
        paths, raw_words = build_paths(wl_path, extensions)
    except OSError as e:
        base["status"] = "error"
        base["error"] = str(e)
        base["errors"].append(str(e))
        return base

    if not paths:
        base["status"] = "error"
        base["error"] = "No paths built from wordlist"
        base["errors"].append(base["error"])
        return base

    base["stats"]["wordlist_size"] = raw_words
    base["stats"]["paths_tested"] = len(paths)
    n_total = len(paths)

    limits = httpx.Limits(max_connections=max(threads * 2, 32))
    client = httpx.Client(
        verify=httpx_verify(config),
        follow_redirects=False,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
        limits=limits,
    )

    try:
        base_url = resolve_base_url(
            target,
            timeout,
            config,
            ssl_notes=base["errors"],
            diagnostics=base["warnings"],
        )
        if not base_url:
            base["status"] = "error"
            base["error"] = "Could not reach target over HTTP/HTTPS"
            base["errors"].append(base["error"])
            console.print(Text(f"  [✗] {base['error']}", style=C_ERR))
            return base

        base["base_url"] = base_url
        _render_header(base_url, n_total)

        catchall = detect_catchall(base_url, timeout, client, base["warnings"])
        base["catchall"] = {
            "detected": catchall["detected"],
            "strategy": catchall.get("strategy", "none"),
            "status_code": catchall.get("status_code"),
            "body_length": catchall.get("body_length"),
            "body_hash": catchall.get("body_hash"),
        }
        _print_catchall_notice(catchall)
        if verbose and catchall.get("detected"):
            base["errors"].append(
                f"[verbose] catchall detail: {catchall!r}"
            )

        mode_lbl = {1: "Fast", 2: "Normal", 3: "Full"}.get(mode, "Fast")
        wl_short = Path(wl_path).name
        ffuf_info = _check_ffuf()
        use_ffuf = bool(ffuf_info.get("available"))
        base["engine"] = "python"
        base["engine_ver"] = ""

        if not quiet:
            if use_ffuf:
                ver_line = (ffuf_info.get("version") or "ffuf").split("\n")[0][:100]
                console.print(
                    Text(
                        f" [✓] {ver_line} — using as dir enum engine",
                        style=C_PRI,
                    )
                )
            else:
                console.print(
                    Text(
                        " [i] ffuf not found — using Python engine "
                        "(install ffuf for faster scans: sudo apt install ffuf)",
                        style=C_MUTED,
                    )
                )

        done_count = 0
        found_list: list[dict[str, Any]] = []
        filtered_count = 0
        interrupted = False
        ffuf_ran_ok = False

        if use_ffuf:
            console.print()
            console.print(
                Text(
                    f" [DIR ENUM] {mode_lbl} mode · {wl_short} · ffuf\n"
                    f" [►] {base_url.rstrip('/')}/FUZZ · {n_total} paths · "
                    f"{threads} threads",
                    style=f"bold {C_PRI}",
                )
            )
            console.print()
            raw_ff, err_ff = _run_ffuf(
                base_url,
                paths,
                threads,
                int(max(1, timeout)),
                str(ffuf_info["binary"]),
                config,
            )
            if err_ff:
                base["warnings"].append(f"{err_ff} — falling back to Python engine")
                if not quiet:
                    console.print(
                        Text(
                            f" [i] {err_ff} — falling back to Python engine",
                            style=C_WARN,
                        )
                    )
            else:
                found_list, filtered_count = _normalize_ffuf_results(
                    raw_ff, base_url, catchall
                )
                seen_ff: set[str] = set()
                capped_ff: list[dict[str, Any]] = []
                for fn in found_list:
                    k = str(fn.get("path") or "")
                    if k in seen_ff:
                        continue
                    if MAX_URLS_DIR_ENUM > 0 and len(capped_ff) >= MAX_URLS_DIR_ENUM:
                        break
                    seen_ff.add(k)
                    capped_ff.append(fn)
                found_list = capped_ff
                base["engine"] = "ffuf"
                base["engine_ver"] = (
                    (ffuf_info.get("version") or "").split("\n")[0][:120]
                )
                done_count = n_total
                ffuf_ran_ok = True

        if not ffuf_ran_ok:
            console.print()
            console.print(
                Text(
                    f" [DIR ENUM] {mode_lbl} mode · {wl_short} · python\n"
                    f" [ENUM] Bruteforcing {base_url} — {n_total} paths · "
                    f"{threads} threads",
                    style=f"bold {C_PRI}",
                )
            )
            console.print()

            lock = threading.Lock()
            done_count = 0
            seen_paths: set[str] = set()
            recent_hits: deque[str] = deque(maxlen=14)
            window: deque[float] = deque()
            probe_exc_kinds: set[str] = set()

            def record_done() -> None:
                nonlocal done_count
                with lock:
                    done_count += 1
                    now = time.perf_counter()
                    window.append(now)
                    while window and now - window[0] > 3.0:
                        window.popleft()

            def probe_one(rel_path: str) -> None:
                nonlocal filtered_count
                url = f"{base_url.rstrip('/')}{rel_path}"
                headers_out: dict[str, str] = {}
                body = ""
                status = 0
                loc_abs: str | None = None
                try:
                    h = client.head(url, timeout=timeout)
                    status = h.status_code
                    headers_out = {k.lower(): v for k, v in h.headers.items()}
                    cloc = h.headers.get("location")
                    if cloc:
                        loc_abs = urljoin(url, cloc)

                    if status == 429:
                        time.sleep(2.0)
                        h = client.head(url, timeout=timeout)
                        status = h.status_code
                        cloc = h.headers.get("location")
                        if cloc:
                            loc_abs = urljoin(url, cloc)

                    redirect = status in (301, 302, 303, 307, 308)
                    need_get = not redirect and status not in (404, 410) and (
                        status in (200, 401, 403, 405, 500, 503)
                    )
                    if redirect:
                        need_get = False

                    if need_get:
                        with client.stream("GET", url, timeout=timeout) as g:
                            status = g.status_code
                            chunks: list[bytes] = []
                            n = 0
                            for ch in g.iter_bytes():
                                chunks.append(ch)
                                n += len(ch)
                                if n >= 4096:
                                    break
                            body = b"".join(chunks).decode("utf-8", errors="replace")
                            cloc = g.headers.get("location")
                            if cloc:
                                loc_abs = urljoin(url, cloc)
                            headers_out = {k.lower(): v for k, v in g.headers.items()}

                    if status == 429:
                        time.sleep(2.0)

                    fn, was_f = analyze_response(
                        rel_path,
                        url,
                        status,
                        body,
                        headers_out,
                        loc_abs,
                        catchall,
                    )
                    with lock:
                        if was_f:
                            filtered_count += 1
                        elif fn:
                            key = fn.get("path", "")
                            if key not in seen_paths:
                                if (
                                    MAX_URLS_DIR_ENUM > 0
                                    and len(found_list) >= MAX_URLS_DIR_ENUM
                                ):
                                    pass
                                else:
                                    seen_paths.add(key)
                                    found_list.append(fn)
                                    recent_hits.append(_hit_line_str(fn))

                except httpx.TimeoutException:
                    k = "TimeoutException"
                    with lock:
                        if k not in probe_exc_kinds:
                            probe_exc_kinds.add(k)
                            base["errors"].append(
                                "dir_enum: HTTP timeout during path probes — "
                                "further timeouts omitted"
                            )
                except Exception as e:  # noqa: BLE001
                    k = type(e).__name__
                    with lock:
                        if k not in probe_exc_kinds:
                            probe_exc_kinds.add(k)
                            base["errors"].append(
                                f"dir_enum path probe ({k}): {e} — further {k} omitted"
                            )
                finally:
                    record_done()

            progress = Progress(
                TextColumn("[bold]{task.description}"),
                BarColumn(bar_width=None, style=C_MUTED, complete_style=C_PRI),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
                expand=True,
            )
            task_id = progress.add_task("dir_enum", total=n_total)

            def snapshot() -> tuple[int, int, int, float, float, list[str]]:
                with lock:
                    dc = done_count
                    nf = len(found_list)
                    ft = filtered_count
                    recent = list(recent_hits)
                elapsed = time.perf_counter() - t_start
                rps = len(window) / 3.0 if window else 0.0
                return dc, nf, ft, elapsed, rps, recent

            display = _DirEnumLiveDisplay(
                progress, task_id, n_total, base_url, snapshot, quiet=quiet
            )
            panel = Panel(
                display,
                border_style=C_ACCENT,
                box=box.ROUNDED,
                padding=(0, 1),
            )

            pit = iter(paths)
            exhausted = False
            pending: set[Any] = set()
            max_inflight = min(max(threads * 4, threads), 4096)

            def submit_batch(ex: ThreadPoolExecutor) -> None:
                nonlocal exhausted
                while len(pending) < max_inflight and not exhausted:
                    try:
                        path = next(pit)
                    except StopIteration:
                        exhausted = True
                        break
                    pending.add(ex.submit(probe_one, path))

            executor = ThreadPoolExecutor(max_workers=threads)
            try:
                with Live(panel, console=console, refresh_per_second=12, transient=False):
                    submit_batch(executor)
                    while pending or not exhausted:
                        if pending:
                            done_fs, _ = wait(
                                pending,
                                return_when=FIRST_COMPLETED,
                                timeout=0.25,
                            )
                            for fut in done_fs:
                                pending.discard(fut)
                                try:
                                    fut.result()
                                except Exception as e:  # noqa: BLE001
                                    k = type(e).__name__
                                    with lock:
                                        if k not in probe_exc_kinds:
                                            probe_exc_kinds.add(k)
                                            base["errors"].append(
                                                f"dir_enum worker ({k}): {e} — further {k} omitted"
                                            )
                                submit_batch(executor)
                        else:
                            submit_batch(executor)
            except KeyboardInterrupt:
                interrupted = True
                with lock:
                    base["errors"].append(
                        "[!] Interrupted by operator — partial results"
                    )
                console.print()
                console.print(
                    Text(" [!] Interrupted — partial results", style=f"bold {C_WARN}")
                )
            finally:
                executor.shutdown(wait=not interrupted, cancel_futures=interrupted)

        if found_list:
            found_list, emp_dom, emp_removed = _filter_by_dominant_response_length(
                found_list,
                threshold=2000,
                dominance_ratio=0.30,
            )
            if emp_dom is not None and emp_removed:
                filtered_count += emp_removed
                base["catchall"]["empirical_dominant_length"] = emp_dom
                base["catchall"]["empirical_catchall_filtered"] = emp_removed
                base["warnings"].append(
                    f"Empirical catch-all: dominant size {emp_dom} B "
                    f"(>30% of hits) — dropped {emp_removed} path(s) within ±2000 B"
                )

        duration = time.perf_counter() - t_start
        rps = done_count / duration if duration > 0 else 0.0

        git_hit = any(
            f.get("status") == 200
            and (f.get("path") or "").lower().rstrip("/").endswith("/.git/head")
            for f in found_list
        )
        git_intel: dict[str, Any] = {}
        if git_hit:
            git_intel = check_git_exposed(base_url, timeout, client)
            base["git_intel"] = git_intel
            _print_git_intel(git_intel)

        rs: dict[str, list[str]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }
        for f in found_list:
            rk = str(f.get("risk", "LOW"))
            if rk in rs:
                rs[rk].append(f.get("path", ""))

        base["found"] = found_list
        base["findings"] = found_list
        base["risk_summary"] = rs
        base["stats"]["found"] = len(found_list)
        base["stats"]["filtered"] = filtered_count
        base["stats"]["duration_s"] = round(duration, 2)
        base["stats"]["req_per_sec"] = round(rps, 1)
        base["status"] = "success"

        if MAX_URLS_DIR_ENUM > 0 and len(found_list) >= MAX_URLS_DIR_ENUM:
            base["warnings"].append(
                f"Dir enum results limited to {MAX_URLS_DIR_ENUM:,} paths — "
                "increase MAX_URLS_DIR_ENUM in config.py"
            )
            console.print()
            console.print(
                Text(
                    f" [!] Dir enum hit path limit ({MAX_URLS_DIR_ENUM:,}) — "
                    "increase MAX_URLS_DIR_ENUM in config.py",
                    style=C_WARN,
                )
            )

        critical_paths = [f for f in found_list if f.get("risk") == "CRITICAL"]
        if quiet:
            ch_paths = [
                f
                for f in found_list
                if f.get("risk") in ("CRITICAL", "HIGH")
            ]
            if ch_paths:
                display_findings(
                    ch_paths,
                    module="dir_enum",
                    verbose=verbose,
                    config=config,
                )
        else:
            if critical_paths:
                display_findings(
                    critical_paths,
                    module="dir_enum",
                    verbose=verbose,
                    config=config,
                )
            _print_results_table(found_list)

        crit = len(rs["CRITICAL"])
        hi = len(rs["HIGH"])
        med = len(rs["MEDIUM"])
        lo = len(rs["LOW"])
        catch_txt = (
            "not detected"
            if not catchall.get("detected")
            else f"{catchall.get('strategy')} ({catchall.get('body_length')}b)"
        )

        console.print()
        console.print(
            Text.assemble(
                ("\n [✓] Dir enum complete\n", f"bold {C_PRI}"),
                (f"     Paths tested : {n_total}\n", C_DIM),
                (f"     Found        : {len(found_list)} paths\n", C_DIM),
                (
                    f"     Critical     : {crit}  ·  High: {hi}  ·  "
                    f"Medium: {med}  ·  Low: {lo}\n",
                    C_DIM,
                ),
                (f"     Catchall     : {catch_txt}\n", C_DIM),
                (f"     Engine       : {_engine_summary_line(base)}\n", C_DIM),
                (f"     Speed        : {base['stats']['req_per_sec']} req/s\n", C_DIM),
                (f"     Duration     : {base['stats']['duration_s']}s", C_DIM),
            )
        )

    finally:
        client.close()

    return base
