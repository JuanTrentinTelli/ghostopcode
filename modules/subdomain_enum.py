"""
GhostOpcode subdomain enumeration — threaded DNS bruteforce, wildcard filter, intel.
"""

from __future__ import annotations

import random
import re
import secrets
import string
import threading
import time
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any, Callable

import dns.exception
import dns.resolver
from rich import box

from utils.dns_cache import cache_stats, resolve as dns_resolve
from rich.console import Console, Group, RenderableType
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
    WORDLIST_SUBDOMAINS,
    count_lines,
)
from utils.output import display_findings
from utils.target_parser import Target

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_ACCENT = "#8B9CA8"

console = Console(highlight=False, force_terminal=True)

WORDLIST_CURL_HINT = (
    "     curl -L "
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/"
    "DNS/subdomains-top1million-5000.txt -o wordlists/subdomains-top1million.txt"
)

TAKEOVER_SIGNATURES: dict[str, str] = {
    "s3.amazonaws.com": "AWS S3 bucket — check if unclaimed",
    "amazonaws.com": "AWS S3 bucket — check if unclaimed",
    "github.io": "GitHub Pages — check if repo exists",
    "herokuapp.com": "Heroku — check if app exists",
    "azurewebsites.net": "Azure — check if app exists",
    "vercel.app": "Vercel — check if project exists",
    "netlify.app": "Netlify — check if site exists",
    "pages.dev": "Cloudflare Pages — check if project exists",
    "myshopify.com": "Shopify — check if store exists",
    "ghost.io": "Ghost — check if blog exists",
    "freshdesk.com": "Freshdesk — check if account exists",
    "zendesk.com": "Zendesk — check if account exists",
    "readme.io": "ReadMe — check if docs exist",
}

_GIT_TOKEN = re.compile(r"(^|[.-])git($|[.-])")


def _mentions_git_token(sub: str) -> bool:
    """Avoid false positives like 'digital' matching 'git'."""
    return bool(_GIT_TOKEN.search(sub.lower()))


# (keywords tuple, category_slug, risk) — order: more specific first
_PATTERN_RULES: list[tuple[tuple[str, ...], str, str]] = [
    (("gitlab", "github", "bitbucket", "jenkins", "travis", "circleci", "deploy", "ci"), "devops_cicd", "CRITICAL"),
    (("admin", "painel", "panel", "manager", "dashboard", "wp-admin"), "admin_panel", "CRITICAL"),
    (("vpn", "remote", "rdp", "citrix", "jump"), "remote_access", "CRITICAL"),
    (("mysql", "postgres", "mongo", "redis", "elastic", "database", "db."), "database_exposed", "CRITICAL"),
    (("intranet", "internal", "corp", "local.", "priv"), "internal_exposed", "CRITICAL"),
    (("dev", "staging", "homolog", "test", "qa", "uat", "sandbox"), "dev_environment", "HIGH"),
    (("api", "rest", "graphql", "webhook", ".ws"), "api_endpoint", "HIGH"),
    (("old", "legacy", "backup", "bkp", "archive"), "legacy_system", "HIGH"),
    (("mail", "smtp", "imap", "pop", "webmail", "mx"), "email_infra", "MEDIUM"),
    (("ftp", "sftp", "files", "upload", "cdn"), "file_transfer", "MEDIUM"),
    (("shop", "store", "checkout", "pay", "cart"), "ecommerce", "MEDIUM"),
    (("blog", "news", "static", "assets", "media", "img", "cdn"), "static_content", "LOW"),
]

_CATEGORY_LABELS: dict[str, str] = {
    "dev_environment": "dev environment",
    "admin_panel": "admin panel",
    "api_endpoint": "api endpoint",
    "email_infra": "email",
    "remote_access": "remote access",
    "file_transfer": "file / CDN",
    "database_exposed": "database",
    "devops_cicd": "DevOps / CI-CD",
    "internal_exposed": "internal / corp",
    "legacy_system": "legacy / backup",
    "ecommerce": "e-commerce",
    "static_content": "static / content",
    "git_exposed": "Git / SCM",
    "uncategorized": "uncategorized",
}


def _dns_enum_warn(
    warnings: list[str] | None,
    keys: set[str] | None,
    lock: threading.Lock | None,
    key: str,
    msg: str,
) -> None:
    if warnings is None or keys is None:
        return
    if lock is not None:
        with lock:
            if key in keys:
                return
            keys.add(key)
            warnings.append(msg)
    else:
        if key in keys:
            return
        keys.add(key)
        warnings.append(msg)


def _random_label(length: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _resolve_a_first(
    fqdn: str,
    timeout: int,
    warnings: list[str] | None = None,
    warn_keys: set[str] | None = None,
    lock: threading.Lock | None = None,
) -> str | None:
    """Return first IPv4 address or None. Never raises."""
    try:
        return dns_resolve(fqdn, int(max(1, timeout)))
    except Exception as e:  # noqa: BLE001
        _dns_enum_warn(
            warnings,
            warn_keys,
            lock,
            f"resolve_a:{type(e).__name__}",
            f"_resolve_a_first ({fqdn}): {type(e).__name__}: {e}",
        )
        return None


def detect_wildcard(
    domain: str,
    timeout: int,
    warnings: list[str] | None = None,
    warn_keys: set[str] | None = None,
    lock: threading.Lock | None = None,
) -> str | None:
    """
    Detect wildcard DNS by querying random non-existent-looking subdomains.

    Strategy: generate 3 random 16-char subdomains, query each for A.
    If all resolve to the same IP → wildcard detected → return that IP.
    Otherwise → None.
    """
    ips: list[str] = []
    for _ in range(3):
        sub = _random_label(16)
        fqdn = f"{sub}.{domain}"
        ip = _resolve_a_first(fqdn, timeout, warnings, warn_keys, lock)
        if ip is None:
            return None
        ips.append(ip)
    if ips[0] == ips[1] == ips[2]:
        return ips[0]
    return None


def resolve_subdomain(
    subdomain: str,
    domain: str,
    timeout: int,
    warnings: list[str] | None = None,
    warn_keys: set[str] | None = None,
    lock: threading.Lock | None = None,
) -> dict[str, Any] | None:
    """
    Attempt to resolve a single candidate subdomain.

    Returns dict with findings or None if not found.
    Never raises — all failures return None silently.
    """
    try:
        time.sleep(random.uniform(0.01, 0.05))
        fqdn = f"{subdomain}.{domain}".lower()
        tto = float(timeout)
        to_i = int(max(1, round(tto)))

        direct = dns_resolve(fqdn, to_i)
        if direct:
            return {
                "fqdn": fqdn,
                "subdomain": subdomain,
                "type": "A",
                "ips": [direct],
                "cname": None,
            }

        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = tto
        resolver.lifetime = tto

        try:
            ans = resolver.resolve(fqdn, "A")
            ips_a = sorted({str(r) for r in ans})
            return {
                "fqdn": fqdn,
                "subdomain": subdomain,
                "type": "A",
                "ips": ips_a,
                "cname": None,
            }
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.Timeout:
            return None
        except dns.exception.DNSException:
            pass
        except OSError:
            return None

        try:
            ans = resolver.resolve(fqdn, "CNAME")
            target = str(ans[0].target).rstrip(".").lower()
            cname_ip = dns_resolve(target, to_i)
            ips: list[str] = [cname_ip] if cname_ip else []
            return {
                "fqdn": fqdn,
                "subdomain": subdomain,
                "type": "CNAME",
                "ips": ips,
                "cname": target,
            }
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.Timeout:
            return None
        except dns.exception.DNSException:
            return None
        except OSError:
            return None
    except Exception as e:  # noqa: BLE001
        _dns_enum_warn(
            warnings,
            warn_keys,
            lock,
            f"resolve_sub:{type(e).__name__}",
            f"resolve_subdomain ({subdomain}.{domain}): {type(e).__name__}: {e}",
        )
        return None
    return None


def _classify_subdomain(sub: str) -> tuple[str, str]:
    """Return (category_slug, RISK_LEVEL)."""
    low = sub.lower()
    if _mentions_git_token(sub) and not any(
        k in low for k in ("gitlab", "github", "bitbucket")
    ):
        return "git_exposed", "CRITICAL"
    for keywords, cat, risk in _PATTERN_RULES:
        for kw in keywords:
            if kw.startswith("."):
                if low.endswith(kw) or f"{kw}" in low:
                    return cat, risk
            elif kw in low:
                return cat, risk
    return "uncategorized", "LOW"


def _takeover_message(cname: str | None) -> str | None:
    if not cname:
        return None
    c = cname.lower()
    # Longer keys first for specificity
    for sig, msg in sorted(TAKEOVER_SIGNATURES.items(), key=lambda x: -len(x[0])):
        if sig in c:
            return msg
    return None


def analyze_findings(found: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Analyze discovered subdomains: categories, risk buckets, takeover flags.

    Mutates each item in-place with category, risk, takeover fields.
    """
    categories: dict[str, list[str]] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
    }
    takeover_candidates: list[dict[str, Any]] = []

    for item in found:
        cat, risk = _classify_subdomain(item.get("subdomain", ""))
        item["category"] = cat
        item["risk"] = risk
        msg = _takeover_message(item.get("cname"))
        item["takeover"] = bool(msg)
        if msg:
            takeover_candidates.append(
                {
                    "fqdn": item["fqdn"],
                    "cname": item["cname"],
                    "note": msg,
                }
            )
        categories.setdefault(risk, []).append(item["fqdn"])

    return {
        "categories": categories,
        "takeover_candidates": takeover_candidates,
    }


def _wildcard_filter(
    found: list[dict[str, Any]],
    wildcard_ip: str | None,
) -> tuple[list[dict[str, Any]], int]:
    """Drop findings that only echo the wildcard A record."""
    if not wildcard_ip:
        return found, 0
    kept: list[dict[str, Any]] = []
    filtered = 0
    for item in found:
        ips = item.get("ips") or []
        if ips and all(ip == wildcard_ip for ip in ips):
            filtered += 1
            continue
        kept.append(item)
    return kept, filtered


def _risk_style(risk: str) -> str:
    if risk == "CRITICAL":
        return f"bold {C_ERR}"
    if risk == "HIGH":
        return f"bold {C_WARN}"
    if risk == "MEDIUM":
        return C_WARN
    return C_PRI


class _MissionLiveDisplay:
    """Renderable bundle: progress task + live stats + recent hits (thread-safe)."""

    def __init__(
        self,
        progress: Progress,
        task_id: Any,
        total: int,
        domain: str,
        get_snapshot: Callable[[], tuple[int, int, float, float, list[str]]],
        quiet: bool = False,
    ) -> None:
        self.progress = progress
        self.task_id = task_id
        self.total = total
        self.domain = domain
        self._snapshot = get_snapshot
        self.quiet = quiet

    def __rich__(self) -> RenderableType:
        done, found, elapsed, rps, recent = self._snapshot()
        pct = (done / self.total * 100) if self.total else 0.0
        remaining = max(0, self.total - done)
        eta = (remaining / rps) if rps > 0.1 else 0.0

        self.progress.update(self.task_id, completed=done, total=self.total)

        stats_line = Text.assemble(
            (" Speed: ", C_MUTED),
            (f"{rps:.0f} req/s", C_PRI),
            (" · Found: ", C_MUTED),
            (str(found), f"bold {C_PRI}"),
            (" · Elapsed: ", C_MUTED),
            (f"{elapsed:.1f}s", C_DIM),
            (" · ETA: ", C_MUTED),
            (f"{eta:.1f}s" if eta < 86400 else "—", C_DIM),
            (f" · {pct:.0f}%", C_MUTED),
        )

        if self.quiet:
            hits_block: RenderableType = Text("")
        else:
            hits_block = Text("\n".join(recent), style=C_DIM) if recent else Text("")

        return Group(
            self.progress,
            stats_line,
            Text(""),
            hits_block,
        )


def _load_wordlist(path: Path) -> list[str]:
    words: list[str] = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            w = line.strip()
            if w and not w.startswith("#"):
                words.append(w)
    return words


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Main entry: bruteforce subdomains from wordlist with live progress and intel.
    """
    t_start = time.perf_counter()
    threads = max(1, int(config.get("threads") or DEFAULT_THREADS))
    timeout = max(1, int(config.get("timeout") or DEFAULT_TIMEOUT))
    verbose = bool(config.get("verbose", False))
    quiet = bool(config.get("quiet", False))
    # Never use config["wordlist"] — hash module sets password lists there during RUN ALL.
    wordlist_path: str | None = (
        config.get("subdomain_wordlist") or WORDLIST_SUBDOMAINS
    )

    base: dict[str, Any] = {
        "module": "subdomain_enum",
        "target": target.value,
        "status": "skipped",
        "wildcard": {"detected": False, "ip": None},
        "found": [],
        "stats": {
            "wordlist_size": 0,
            "resolved": 0,
            "filtered": 0,
            "duration_s": 0.0,
            "req_per_sec": 0.0,
        },
        "categories": {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []},
        "takeover_candidates": [],
        "errors": [],
        "warnings": [],
    }

    if not target.is_domain():
        p = Panel(
            Text(
                f"  SUBDOMAIN ENUM  ·  {target.value}  ·  not applicable",
                style=f"bold {C_PRI}",
            ),
            border_style=C_ACCENT,
            box=box.DOUBLE,
            width=min(console.size.width, 82) if console.size else 82,
        )
        console.print(p)
        console.print(
            Text(
                "  [SKIP] Subdomain enum — domain only (not IP/CIDR).",
                style=C_WARN,
            )
        )
        return base

    domain = target.value
    wl_dir = Path("wordlists")
    try:
        wl_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        base["status"] = "error"
        base["error"] = str(e)
        base["errors"].append(str(e))
        return base

    if not wordlist_path:
        console.print(Text(" [✗] No wordlist found.", style=C_ERR))
        console.print(
            Text(
                "     Install SecLists: sudo apt install seclists",
                style=C_DIM,
            )
        )
        console.print(
            Text(
                "     Or download manually to: wordlists/subdomains-top1million.txt",
                style=C_DIM,
            )
        )
        console.print(Text(" [i] Example:", style=C_WARN))
        console.print(Text(WORDLIST_CURL_HINT, style=C_MUTED))
        base["status"] = "error"
        base["error"] = "wordlist not found"
        base["errors"].append(base["error"])
        return base

    wl_path = Path(wordlist_path)
    if not wl_path.is_file():
        console.print(Text(f" [✗] Wordlist not found: {wl_path}", style=C_ERR))
        console.print(
            Text(
                "     Install SecLists: sudo apt install seclists",
                style=C_DIM,
            )
        )
        console.print(
            Text(
                "     Or download manually to: wordlists/subdomains-top1million.txt",
                style=C_DIM,
            )
        )
        console.print(Text(" [i] Example:", style=C_WARN))
        console.print(Text(WORDLIST_CURL_HINT, style=C_MUTED))
        base["status"] = "error"
        base["error"] = f"Wordlist not found: {wl_path}"
        base["errors"].append(base["error"])
        return base

    line_estimate = count_lines(str(wl_path))
    if line_estimate > 100_000:
        console.print(
            Text(
                f" [!] Wordlist has {line_estimate:,} lines — unusually large for "
                f"subdomain brute-force (expected ~5k–20k).",
                style=C_WARN,
            )
        )
        console.print(
            Text(
                " [i] If this is a password list (e.g. rockyou), cancel and fix "
                "WORDLIST_SUBDOMAINS / subdomain_wordlist in config.",
                style=C_MUTED,
            )
        )
        try:
            confirm = input("  Continue anyway? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            confirm = "n"
        if confirm != "y":
            base["status"] = "skipped"
            base["error"] = "Wordlist too large — aborted by operator"
            base["errors"].append(base["error"])
            console.print(
                Text("  [SKIP] Subdomain enum cancelled (wordlist size).", style=C_WARN)
            )
            return base

    try:
        words = _load_wordlist(wl_path)
    except OSError as e:
        base["status"] = "error"
        base["error"] = str(e)
        base["errors"].append(str(e))
        return base

    n_words = len(words)
    base["stats"]["wordlist_size"] = n_words
    if n_words == 0:
        base["status"] = "error"
        base["error"] = "Wordlist is empty"
        base["errors"].append(base["error"])
        return base

    _render_header(domain, n_words)

    lock = threading.Lock()
    dns_warn_keys: set[str] = set()
    w_ip = detect_wildcard(
        domain, timeout, base["warnings"], dns_warn_keys, lock
    )
    if w_ip:
        base["wildcard"] = {"detected": True, "ip": w_ip}
        console.print(Text(f" [!] WILDCARD DNS detected on {domain}", style=C_ERR))
        console.print(Text(f"     All subdomains resolve to: {w_ip}", style=C_WARN))
        console.print(
            Text(
                "     Results will be filtered — only unique IPs shown",
                style=C_DIM,
            )
        )
        console.print(
            Text("     [i] Continuing with deduplication by IP...", style=C_MUTED)
        )
        console.print()
    else:
        base["wildcard"] = {"detected": False, "ip": None}

    done_count = 0
    found_raw: list[dict[str, Any]] = []
    recent_hits: deque[str] = deque(maxlen=14)
    window: deque[float] = deque()
    interrupted = False

    def record_completion() -> None:
        nonlocal done_count
        with lock:
            done_count += 1
            now = time.perf_counter()
            window.append(now)
            while window and now - window[0] > 2.0:
                window.popleft()

    def snapshot() -> tuple[int, int, float, float, list[str]]:
        with lock:
            dc = done_count
            fr = len(found_raw)
            recent = list(recent_hits)
        elapsed = time.perf_counter() - t_start
        rps = len(window) / 2.0 if window else 0.0
        return dc, fr, elapsed, rps, recent

    def on_hit(row: dict[str, Any]) -> None:
        line = _format_hit_line(row)
        with lock:
            found_raw.append(row)
            recent_hits.append(line)

    fut_exc_kinds: set[str] = set()

    def worker(word: str) -> None:
        try:
            r = resolve_subdomain(
                word,
                domain,
                timeout,
                base["warnings"],
                dns_warn_keys,
                lock,
            )
            if r:
                on_hit(r)
        finally:
            record_completion()

    console.print(
        Text(
            f" [SUBS] Bruteforcing {domain} — {n_words} words · {threads} threads",
            style=f"bold {C_PRI}",
        )
    )
    console.print()

    progress = Progress(
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=None, style=C_MUTED, complete_style=C_PRI),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        expand=True,
    )
    task_id = progress.add_task("bruteforce", total=n_words)

    display = _MissionLiveDisplay(
        progress,
        task_id,
        n_words,
        domain,
        lambda: snapshot(),
        quiet=quiet,
    )

    max_inflight = min(max(threads * 4, threads), 4096)
    pending: set[Any] = set()
    it = iter(words)
    exhausted = False

    def submit_batch(ex: ThreadPoolExecutor) -> None:
        nonlocal exhausted
        while len(pending) < max_inflight and not exhausted:
            try:
                w = next(it)
            except StopIteration:
                exhausted = True
                break
            pending.add(ex.submit(worker, w))

    panel = Panel(
        display,
        border_style=C_ACCENT,
        box=box.ROUNDED,
        padding=(0, 1),
    )
    executor = ThreadPoolExecutor(max_workers=threads)
    try:
        with Live(
            panel,
            console=console,
            refresh_per_second=12,
            transient=False,
        ) as live:
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
                                if k not in fut_exc_kinds:
                                    fut_exc_kinds.add(k)
                                    base["errors"].append(
                                        f"subdomain_enum worker ({k}): {e} — further {k} omitted"
                                    )
                        submit_batch(executor)
                else:
                    submit_batch(executor)
                live.update(panel)
    except KeyboardInterrupt:
        interrupted = True
        with lock:
            base["errors"].append(
                "[!] Interrupted by operator — showing partial results"
            )
        console.print()
        console.print(
            Text(
                " [!] Interrupted by operator — showing partial results",
                style=f"bold {C_WARN}",
            )
        )
    finally:
        executor.shutdown(wait=not interrupted, cancel_futures=interrupted)

    duration = time.perf_counter() - t_start
    avg_rps = done_count / duration if duration > 0 else 0.0

    found, filtered_n = _wildcard_filter(found_raw, w_ip)
    analysis = analyze_findings(found)
    base["categories"] = analysis["categories"]
    base["takeover_candidates"] = analysis["takeover_candidates"]
    base["found"] = found
    base["stats"]["resolved"] = len(found)
    base["stats"]["filtered"] = filtered_n
    base["stats"]["duration_s"] = round(duration, 2)
    base["stats"]["req_per_sec"] = round(avg_rps, 1)
    base["status"] = "success"

    console.print()
    if quiet:
        ch_subs = [
            x
            for x in found
            if str(x.get("risk", "LOW")).upper() in ("CRITICAL", "HIGH")
        ]
        if ch_subs:
            display_findings(
                [
                    {
                        "risk": str(x.get("risk", "LOW")).upper(),
                        "category": str(x.get("category") or "subdomain"),
                        "value": _format_hit_line(x).strip(),
                        "note": str(x.get("cname") or "").strip(),
                    }
                    for x in ch_subs
                ],
                module="subdomain_enum",
                verbose=verbose,
                config=config,
            )
    else:
        _render_results_table(found)
    if base["takeover_candidates"]:
        console.print()
        console.print(
            Text(
                " [!] SUBDOMAIN TAKEOVER CANDIDATES DETECTED:",
                style=f"bold {C_WARN}",
            )
        )
        tcs = base["takeover_candidates"]
        for i, tc in enumerate(tcs):
            sym = "├──" if i < len(tcs) - 1 else "└──"
            console.print(
                Text.assemble(
                    (f"   {sym} ", C_MUTED),
                    (tc["fqdn"], C_DIM),
                    ("  →  CNAME: ", C_MUTED),
                    (tc["cname"] or "—", C_PRI),
                    ("  →  ", C_MUTED),
                    (tc["note"], C_WARN),
                )
            )

    wc_line = (
        f"detected → {w_ip}"
        if w_ip
        else "not detected"
    )
    cat = base["categories"]
    console.print()
    console.print(
        Text.assemble(
            ("\n [✓] Subdomain enum complete\n", f"bold {C_PRI}"),
            (f"     Wordlist     : {n_words} words\n", C_DIM),
            (f"     Found        : {len(found)} subdomains\n", C_DIM),
            (
                f"     Critical     : {len(cat['CRITICAL'])}  ·  High: {len(cat['HIGH'])}"
                f"  ·  Medium: {len(cat['MEDIUM'])}  ·  Low: {len(cat['LOW'])}\n",
                C_DIM,
            ),
            (
                f"     Takeover     : {len(base['takeover_candidates'])} candidates\n",
                C_DIM,
            ),
            (f"     Wildcard DNS : {wc_line}\n", C_DIM),
            (f"     Speed        : {avg_rps:.0f} req/s\n", C_DIM),
            (f"     Duration     : {duration:.2f}s", C_DIM),
        )
    )
    if config.get("debug"):
        st = cache_stats()
        console.print(
            Text(
                f"     [DEBUG] DNS cache: {st['resolved']} resolved · "
                f"{st['failed']} failed · {st['total']} total entries",
                style=C_MUTED,
            )
        )

    return base


def _format_hit_line(row: dict[str, Any]) -> str:
    ips = row.get("ips") or []
    ip_s = ips[0] if ips else "—"
    if row.get("type") == "CNAME" and row.get("cname"):
        return f" [+] {row['fqdn']:<40} → {ip_s}  (CNAME: {row['cname']})"
    return f" [+] {row['fqdn']:<40} → {ip_s}"


def _render_header(domain: str, n_words: int) -> None:
    title = f"  SUBDOMAIN ENUM  ·  {domain}  ·  {n_words} words"
    p = Panel(
        Text(title, style=f"bold {C_PRI}"),
        border_style=C_ACCENT,
        box=box.DOUBLE,
        width=min(console.size.width, 82) if console.size else 82,
    )
    console.print(p)


def _render_results_table(found: list[dict[str, Any]]) -> None:
    if not found:
        console.print(Text("  (no subdomains resolved)", style=C_MUTED))
        return
    table = Table(
        box=box.HEAVY,
        border_style=C_ACCENT,
        header_style=f"bold {C_DIM}",
        show_lines=True,
        title=Text("RESULTS BY RISK", style=f"bold {C_MUTED}"),
    )
    table.add_column("Subdomain", style=C_DIM, max_width=36)
    table.add_column("IP", style=C_PRI, max_width=18)
    table.add_column("Category", style=C_MUTED, max_width=22)
    table.add_column("Risk", max_width=14)

    def risk_cell(risk: str) -> Text:
        label = f"[{risk}]"
        return Text(label, style=_risk_style(risk))

    _rk = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for item in sorted(
        found,
        key=lambda x: _rk.get(str(x.get("risk", "LOW")), 9),
    ):
        ips = item.get("ips") or []
        ip_disp = ", ".join(ips[:2])
        if len(ips) > 2:
            ip_disp += "…"
        if not ip_disp:
            ip_disp = item.get("cname") or "—"
        cat = _CATEGORY_LABELS.get(item.get("category", ""), item.get("category", ""))
        table.add_row(
            item.get("fqdn", "—"),
            ip_disp,
            cat,
            risk_cell(str(item.get("risk", "LOW"))),
        )
    console.print(table)

