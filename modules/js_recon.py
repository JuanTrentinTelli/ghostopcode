"""
GhostOpcode JavaScript recon — discovery, API endpoints, secrets, source maps.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config import (
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    MAX_URLS_JS_RECON,
    USER_AGENT,
)
from utils.http_client import get as http_get, head as http_head, resolve_base_url as http_resolve_base_url
from utils.output import display_findings
from utils.target_parser import Target

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_ACCENT = "#8B9CA8"

console = Console(highlight=False, force_terminal=True)

MAX_JS_DOWNLOAD = 10 * 1024 * 1024
LARGE_JS_THRESHOLD = 5 * 1024 * 1024
MAX_ANALYZE_SLICE = 500 * 1024
MAX_JS_FILES_TO_FETCH = 40
SOURCE_MAP_COMMENT_RE = re.compile(
    r"//[#@]\s*sourceMappingURL=([^\s]+?)\s*?$",
    re.MULTILINE | re.IGNORECASE,
)

COMMON_JS_PATHS: list[str] = [
    "/app.js",
    "/main.js",
    "/bundle.js",
    "/index.js",
    "/static/js/main.js",
    "/static/js/bundle.js",
    "/assets/js/app.js",
    "/dist/app.js",
    "/build/app.js",
    "/js/app.js",
    "/js/main.js",
    "/js/bundle.js",
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/pages/_app.js",
    "/_nuxt/app.js",
    "/wp-includes/js/jquery/jquery.min.js",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
]

SKIP_PRIORITY_PATTERNS: list[str] = [
    "jquery",
    "bootstrap",
    "lodash",
    "moment",
    "react.min",
    "vue.min",
    "angular.min",
    "polyfill",
    "modernizr",
    "fontawesome",
    "swiper",
    "slick",
    "aos",
    "gsap",
]

HIGH_PRIORITY_KEYWORDS: tuple[str, ...] = (
    "main",
    "app",
    "bundle",
    "chunk",
    "pages",
    "_app",
    "index",
    "runtime",
    "vendor",
)

ENDPOINT_REGEXES: list[tuple[str, re.Pattern[str]]] = [
    ("fetch", re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.I)),
    ("axios_method", re.compile(r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']', re.I)),
    ("axios_url", re.compile(r'url\s*:\s*["\']([^"\']+)["\']', re.I)),
    ("template_api", re.compile(r"`(/api/v\d+/[^`\"'\\]+)`")),
    ("string_api", re.compile(r'["\'](/api/v?\d*/?[a-zA-Z0-9/_\-?=&.%]+)["\']')),
    ("abs_api", re.compile(r'["\'](https?://[a-zA-Z0-9._\-]+/api/[^"\']+)["\']', re.I)),
    ("baseURL", re.compile(r'baseURL\s*[:=]\s*["\']([^"\']+)["\']', re.I)),
    ("apiUrl", re.compile(r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']', re.I)),
    ("API_URL", re.compile(r'API_URL\s*[:=]\s*["\']([^"\']+)["\']')),
    ("BASE_URL", re.compile(r'BASE_URL\s*[:=]\s*["\']([^"\']+)["\']')),
    ("API_BASE", re.compile(r'API_BASE\s*[:=]\s*["\']([^"\']+)["\']')),
    ("graphql", re.compile(r'["\']([^"\']*graphql[^"\']*)["\']', re.I)),
    ("websocket", re.compile(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']', re.I)),
    ("wss", re.compile(r'["\'](wss?://[^"\']+)["\']', re.I)),
    ("staging", re.compile(
        r'["\'](https?://(?:dev|staging|homolog|test|qa|uat)[a-zA-Z0-9._\-./:?=&%]+)["\']',
        re.I,
    )),
    ("infra_host", re.compile(
        r'["\'](https?://(?:api|internal|backend)\.[a-zA-Z0-9._\-./:?=&%]+)["\']',
        re.I,
    )),
]

ENDPOINT_CATEGORIES: list[dict[str, Any]] = [
    {
        "name": "admin_api",
        "patterns": ("/admin", "/internal", "/management", "/backdoor"),
        "risk": "CRITICAL",
    },
    {
        "name": "auth_api",
        "patterns": ("/auth", "/login", "/token", "/oauth", "/jwt", "/session"),
        "risk": "HIGH",
    },
    {
        "name": "data_api",
        "patterns": ("/api/v", "/rest/", "/graphql", "/data/"),
        "risk": "HIGH",
    },
    {
        "name": "file_api",
        "patterns": ("/upload", "/download", "/export", "/import", "/files"),
        "risk": "HIGH",
    },
    {
        "name": "staging_url",
        "patterns": ("dev.", "staging.", "homolog.", "test.", "qa.", "uat."),
        "risk": "HIGH",
        "note": "Non-production environment URL exposed in JS",
    },
    {
        "name": "internal_url",
        "patterns": ("localhost", "127.0.0.1", "192.168.", "0.0.0.0"),
        "risk": "CRITICAL",
        "note": "Internal network URL hardcoded in public JS",
    },
    {
        "name": "websocket",
        "patterns": ("ws://", "wss://"),
        "risk": "MEDIUM",
    },
    {
        "name": "external_api",
        "patterns": ("https://api.", "https://hooks."),
        "risk": "LOW",
    },
]

FALSE_POSITIVE_SUBSTRINGS: frozenset[str] = frozenset(
    {
        "example",
        "placeholder",
        "your_key_here",
        "insert_key",
        "replace_me",
        "todo",
        "xxxxxxxx",
        "00000000",
        "12345678",
        "test",
        "demo",
        "sample",
        "dummy",
        "undefined",
        "null",
        "${",
        "%s",
        "{id}",
        "{{",
    },
)


def _session_headers() -> dict[str, str]:
    return {"User-Agent": USER_AGENT}


def _human_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f}MB"
    if n >= 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n}b"


def is_false_positive(secret_type: str, value: str, context: str = "") -> bool:
    """Filter obvious placeholder secrets."""
    combined = (value + " " + context).lower()
    for fp in FALSE_POSITIVE_SUBSTRINGS:
        if fp in combined and len(value) < 48:
            return True
    if len(value) < 8:
        return True
    return False


def _looks_private_ip(url: str) -> bool:
    if re.search(
        r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
        url,
    ):
        return True
    return bool(re.search(r"192\.168\.\d{1,3}\.\d{1,3}", url))


def categorize_endpoint(url: str) -> dict[str, Any]:
    """Assign category and risk from URL string."""
    u = url.lower()
    if _looks_private_ip(url):
        return {
            "category": "internal_url",
            "risk": "CRITICAL",
            "note": "Internal network URL hardcoded in public JS",
        }
    for cat in ENDPOINT_CATEGORIES:
        for p in cat["patterns"]:
            if p.lower() in u:
                out = {
                    "category": cat["name"],
                    "risk": cat["risk"],
                    "note": cat.get("note"),
                }
                return out
    if "/api" in u or u.startswith("/v1") or u.startswith("/v2"):
        return {"category": "data_api", "risk": "HIGH", "note": None}
    if u.startswith("http"):
        return {"category": "absolute_url", "risk": "MEDIUM", "note": None}
    return {"category": "relative_path", "risk": "LOW", "note": None}


def is_same_domain(
    map_url: str,
    base_url: str,
    warnings: list[str] | None = None,
) -> bool:
    """
    Check if a URL's host matches the target site's registrable domain.

    Same root domain (including subdomains like static.example.com) → True.
    Different host (e.g. CDN) → False. No hardcoded CDN list.
    """
    if not map_url or not base_url:
        return False
    try:
        map_domain = urlparse(map_url).netloc.lower()
        base_domain = urlparse(base_url).netloc.lower()
    except Exception as e:  # noqa: BLE001
        if warnings is not None:
            warnings.append(
                f"is_same_domain urlparse: {type(e).__name__}: {e}"
            )
        return False
    if not map_domain or not base_domain:
        return False

    def root_domain(domain: str) -> str:
        parts = domain.split(".")
        if len(parts) >= 3 and parts[-2] in ("com", "org", "net", "edu", "gov"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain

    return root_domain(map_domain) == root_domain(base_domain)


def source_map_on_target(
    sm: dict[str, Any],
    js_file_url: str,
    base_url: str,
    warnings: list[str] | None = None,
) -> bool:
    """True if the source map is first-party (inline maps use the script URL host)."""
    if sm.get("type") == "inline":
        return is_same_domain(js_file_url, base_url, warnings)
    mu = sm.get("url")
    if isinstance(mu, str) and mu.strip():
        return is_same_domain(mu, base_url, warnings)
    return False


def _is_library_js_url(u: str) -> bool:
    low = u.lower()
    path = urlparse(u).path.lower()
    name = path.rsplit("/", 1)[-1] if path else low
    return any(s in name or s in path for s in SKIP_PRIORITY_PATTERNS)


def prioritize_js_files(js_urls: list[str]) -> tuple[list[str], list[str]]:
    """
    High-priority app bundles first; library/vendor URLs listed as skipped labels.
    """
    skipped: list[str] = []
    primary: list[tuple[int, str]] = []
    secondary: list[tuple[int, str]] = []
    for u in js_urls:
        if _is_library_js_url(u):
            skipped.append(urlparse(u).path.split("/")[-1] or u)
            secondary.append((10, u))
            continue
        pri = 50
        path = urlparse(u).path.lower()
        if any(k in path for k in HIGH_PRIORITY_KEYWORDS):
            pri = 0
        elif path.endswith(".min.js"):
            pri = 20
        primary.append((pri, u))
    primary.sort(key=lambda x: (x[0], x[1]))
    secondary.sort(key=lambda x: (x[0], x[1]))
    ordered = [u for _, u in primary + secondary]
    seen: set[str] = set()
    out: list[str] = []
    for u in ordered:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out, skipped[:12]


def discover_js_from_html(
    base_url: str,
    timeout: float,
    errors: list[str],
    config: dict[str, Any],
) -> set[str]:
    """
    Collect script URLs from HTML, preload, Next data, and loose URL patterns in scripts.
    """
    found: set[str] = set()
    root = base_url.rstrip("/") + "/"
    try:
        r = http_get(
            root,
            config,
            timeout=timeout,
            allow_redirects=True,
            headers=_session_headers(),
            ssl_warnings=errors,
        )
        if r is None:
            errors.append("HTML discovery: SSL/connection failed")
            return found
        html = r.text or ""
        final_base = urlparse(r.url)
        origin = f"{final_base.scheme}://{final_base.netloc}"

        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script", src=True):
            src = (tag.get("src") or "").strip()
            if src and not src.startswith("data:"):
                found.add(urljoin(r.url, src))
        for tag in soup.find_all("link", href=True):
            if (tag.get("rel") or []) and "preload" in " ".join(tag.get("rel") or []).lower():
                if (tag.get("as") or "").lower() == "script":
                    href = (tag.get("href") or "").strip()
                    if href:
                        found.add(urljoin(r.url, href))

        next_tag = soup.find("script", id="__NEXT_DATA__")
        if next_tag and next_tag.string:
            try:
                data = json.loads(next_tag.string)
                chunks = json.dumps(data)
                for m in re.finditer(r'(/_next/static/[^"\'\\s]+\.js)', chunks):
                    found.add(urljoin(origin, m.group(1)))
            except Exception as e:  # noqa: BLE001
                errors.append(
                    f"__NEXT_DATA__ JSON parse: {type(e).__name__}: {e}"
                )

        for script in soup.find_all("script"):
            if not script.string:
                continue
            chunk = script.string[:200000]
            for m in re.finditer(
                r'["\']((?:https?:)?//[^"\']+\.js(?:\?[^"\']*)?)["\']',
                chunk,
            ):
                u = m.group(1)
                if u.startswith("//"):
                    u = f"{final_base.scheme}:{u}"
                elif u.startswith("/"):
                    u = urljoin(origin + "/", u.lstrip("/"))
                if ".js" in u.lower():
                    found.add(u.split("#")[0])
            for m in re.finditer(r"(/static/[^\"'\\s]+\.js)", chunk):
                found.add(urljoin(origin, m.group(1)))
    except Exception as e:  # noqa: BLE001
        errors.append(f"HTML discovery: {e}")
    return found


def brute_common_js_paths(
    base_url: str,
    timeout: float,
    threads: int,
    errors: list[str],
    config: dict[str, Any],
) -> set[str]:
    """Probe common JS and API-doc paths; add URL if response looks successful."""
    found: set[str] = set()
    base = base_url.rstrip("/")

    def probe(path: str) -> None:
        url = f"{base}/{path.lstrip('/')}"
        try:
            time.sleep(0.02)
            head = http_head(
                url,
                config,
                timeout=timeout,
                allow_redirects=True,
                headers=_session_headers(),
                ssl_warnings=errors,
            )
            if head is None:
                return
            if head.status_code == 405:
                r = http_get(
                    url,
                    config,
                    timeout=timeout,
                    allow_redirects=True,
                    headers=_session_headers(),
                    stream=True,
                    ssl_warnings=errors,
                )
                if r is None:
                    return
                try:
                    code = r.status_code
                    cl = r.headers.get("Content-Length", "0")
                finally:
                    r.close()
            else:
                code = head.status_code
                cl = head.headers.get("Content-Length", "0")
            if code != 200:
                return
            if path.endswith(".json") or "swagger" in path or "openapi" in path or "api-docs" in path:
                found.add(url)
                return
            try:
                sz = int(cl) if cl.isdigit() else 0
            except ValueError:
                sz = 0
            if sz > MAX_JS_DOWNLOAD:
                return
            if path.endswith(".js") or "/chunks/" in path or "/static/" in path:
                found.add(url)
        except Exception as e:  # noqa: BLE001
            errors.append(f"probe {path}: {e}")

    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futs = [ex.submit(probe, p) for p in COMMON_JS_PATHS]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as e:  # noqa: BLE001
                errors.append(str(e))
    return found


def _slice_for_analysis(content: str) -> str:
    if len(content) > LARGE_JS_THRESHOLD:
        return content[:MAX_ANALYZE_SLICE]
    return content


def extract_endpoints(js_content: str, base_url: str, source_name: str) -> list[dict[str, Any]]:
    """Regex-based endpoint and URL extraction from JS text."""
    slice_c = _slice_for_analysis(js_content)
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    origin = urlparse(base_url)
    origin_prefix = f"{origin.scheme}://{origin.netloc}"

    for kind, rx in ENDPOINT_REGEXES:
        for m in rx.finditer(slice_c):
            raw = (m.group(1) if m.lastindex else m.group(0)).strip()
            if not raw or len(raw) < 2:
                continue
            if raw.startswith("data:") or raw.startswith("javascript:"):
                continue
            if raw.startswith("/"):
                full = urljoin(origin_prefix + "/", raw.lstrip("/"))
            elif raw.startswith("//"):
                full = f"{origin.scheme}:{raw}"
            elif not raw.startswith("http"):
                full = urljoin(origin_prefix + "/", raw)
            else:
                full = raw
            full = full.split("#")[0]
            key = full.lower()
            if key in seen:
                continue
            seen.add(key)
            cat = categorize_endpoint(full)
            method = "GET"
            out.append(
                {
                    "url": full,
                    "source": source_name,
                    "category": cat["category"],
                    "risk": cat["risk"],
                    "method": method,
                    "note": cat.get("note"),
                }
            )
    return out


def detect_secrets(js_content: str, filename: str) -> list[dict[str, Any]]:
    """Pattern-scan JS for credentials; values are masked in output."""
    slice_c = _slice_for_analysis(js_content)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    patterns: list[tuple[str, str, re.Pattern[str], str, Callable[[str], str], list[str] | None]] = [
        (
            "aws_access_key",
            "CRITICAL",
            re.compile(r"AKIA[0-9A-Z]{16}"),
            "HIGH",
            lambda v: v[:8] + "****" + v[-4:],
            None,
        ),
        (
            "google_api_key",
            "CRITICAL",
            re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
            "HIGH",
            lambda v: v[:8] + "****",
            None,
        ),
        (
            "stripe_key",
            "CRITICAL",
            re.compile(r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}"),
            "HIGH",
            lambda v: v[:12] + "****",
            None,
        ),
        (
            "github_token",
            "CRITICAL",
            re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
            "HIGH",
            lambda v: v[:8] + "****",
            None,
        ),
        (
            "jwt_token",
            "HIGH",
            re.compile(
                r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+",
            ),
            "MEDIUM",
            lambda v: v[:20] + "...[JWT]",
            None,
        ),
        (
            "firebase_api_key",
            "HIGH",
            re.compile(r"apiKey\s*:\s*['\"]([A-Za-z0-9\-_]{35,})['\"]"),
            "MEDIUM",
            lambda v: v[:8] + "****",
            None,
        ),
        (
            "generic_api_key",
            "HIGH",
            re.compile(
                r"(?:api[_\-]?key|apikey|api[_\-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9\-_]{16,})['\"]",
                re.I,
            ),
            "MEDIUM",
            lambda v: v[:8] + "****",
            None,
        ),
        (
            "generic_secret",
            "HIGH",
            re.compile(
                r"(?:secret|password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
                re.I,
            ),
            "LOW",
            lambda v: v[:4] + "****",
            None,
        ),
        (
            "private_key",
            "CRITICAL",
            re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
            "HIGH",
            lambda _v: "-----BEGIN PRIVATE KEY----- [REDACTED]",
            None,
        ),
        (
            "internal_ip",
            "HIGH",
            re.compile(
                r"(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}",
            ),
            "MEDIUM",
            lambda v: v[:12] + "****",
            None,
        ),
        (
            "database_url",
            "CRITICAL",
            re.compile(
                r"(?:mongodb|postgres|mysql|redis|sqlite)://[^\s'\"<>]+",
                re.I,
            ),
            "HIGH",
            lambda v: (v.split("@")[0][:15] + "****@[redacted]" if "@" in v else v[:20] + "****"),
            None,
        ),
    ]

    aws_secret_rx = re.compile(r"['\"]([0-9a-zA-Z/+]{40})['\"]")

    for name, risk, rx, conf, mask_fn, _ in patterns:
        for m in rx.finditer(slice_c):
            val = m.group(0) if name != "firebase_api_key" else m.group(1)
            if is_false_positive(name, val, slice_c[max(0, m.start() - 80) : m.end() + 80]):
                continue
            sk = (name, val[:32])
            if sk in seen:
                continue
            seen.add(sk)
            findings.append(
                {
                    "type": name,
                    "value": mask_fn(val),
                    "source": filename,
                    "line_hint": f"~offset {m.start()}",
                    "risk": risk,
                    "confidence": conf,
                }
            )

    for m in aws_secret_rx.finditer(slice_c):
        val = m.group(1)
        ctx = slice_c[max(0, m.start() - 120) : m.end() + 120].lower()
        if not any(k in ctx for k in ("aws", "secret", "amazon", "credential")):
            continue
        if is_false_positive("aws_secret", val, ctx):
            continue
        sk = ("aws_secret_key", val[:20])
        if sk in seen:
            continue
        seen.add(sk)
        findings.append(
            {
                "type": "aws_secret_key",
                "value": val[:6] + "****",
                "source": filename,
                "line_hint": f"~offset {m.start()}",
                "risk": "CRITICAL",
                "confidence": "MEDIUM",
            }
        )

    return findings


def check_map_accessible(
    map_url: str,
    timeout: float,
    errors: list[str],
    config: dict[str, Any],
) -> dict[str, Any] | None:
    """Fetch and parse a source map JSON."""
    try:
        r = http_get(
            map_url,
            config,
            timeout=timeout,
            allow_redirects=True,
            headers=_session_headers(),
            ssl_warnings=errors,
        )
        if r is None or r.status_code != 200:
            return None
        try:
            data = r.json()
        except json.JSONDecodeError:
            return {
                "url": map_url,
                "risk": "HIGH",
                "accessible": True,
                "note": "Source map accessible but not parseable JSON",
                "sources_count": 0,
                "source_files": [],
                "has_content": False,
            }
        sources = data.get("sources") or []
        has_content = "sourcesContent" in data
        return {
            "url": map_url,
            "risk": "CRITICAL",
            "accessible": True,
            "sources_count": len(sources),
            "source_files": sources[:20],
            "has_content": has_content,
            "note": (
                "Source code fully embedded in map file"
                if has_content
                else "File paths exposed — source structure revealed"
            ),
        }
    except Exception as e:  # noqa: BLE001
        errors.append(f"source map {map_url}: {e}")
        return None


def check_source_map(
    js_url: str,
    js_content: str,
    timeout: float,
    errors: list[str],
    config: dict[str, Any],
) -> dict[str, Any] | None:
    """Resolve sourceMappingURL comment, inline data URI, or .map sibling."""
    tail = js_content[-2000:] if len(js_content) > 2000 else js_content
    m = SOURCE_MAP_COMMENT_RE.search(tail)
    if m:
        ref = m.group(1).strip()
        if ref.startswith("data:"):
            try:
                header, b64 = ref.split(",", 1)
                if ";base64" in header:
                    raw = base64.b64decode(b64)
                    data = json.loads(raw.decode("utf-8", errors="replace"))
                    sources = data.get("sources") or []
                    return {
                        "type": "inline",
                        "found": True,
                        "url": None,
                        "risk": "CRITICAL",
                        "note": "Inline source map (base64) — original paths in bundle",
                        "sources_count": len(sources),
                        "source_files": sources[:20],
                        "has_content": "sourcesContent" in data,
                    }
            except (ValueError, json.JSONDecodeError, binascii.Error):
                return {
                    "type": "inline",
                    "found": True,
                    "risk": "HIGH",
                    "note": "Inline sourceMappingURL present but could not parse",
                    "sources_count": 0,
                    "source_files": [],
                    "has_content": False,
                }
        map_full = urljoin(js_url, ref)
        got = check_map_accessible(map_full, timeout, errors, config)
        if got:
            got["found"] = True
            got["js_file"] = urlparse(js_url).path.split("/")[-1]
        return got

    sibling = js_url.split("?")[0] + ".map"
    got = check_map_accessible(sibling, timeout, errors, config)
    if got:
        got["found"] = True
        got["js_file"] = urlparse(js_url).path.split("/")[-1]
    return got


def fetch_js(
    url: str,
    timeout: float,
    errors: list[str],
) -> tuple[str | None, int]:
    """Download JS body up to size cap. Returns (text, size) or (None, 0)."""
    try:
        r = http_get(
            url,
            config,
            timeout=timeout,
            allow_redirects=True,
            headers=_session_headers(),
            stream=True,
            ssl_warnings=errors,
        )
        if r is None or r.status_code != 200:
            return None, 0
        cl = r.headers.get("Content-Length")
        if cl and cl.isdigit() and int(cl) > MAX_JS_DOWNLOAD:
            return None, int(cl)
        buf = b""
        for chunk in r.iter_content(65536):
            buf += chunk
            if len(buf) > MAX_JS_DOWNLOAD:
                break
        try:
            return buf.decode("utf-8", errors="replace"), len(buf)
        except Exception as e:  # noqa: BLE001
            errors.append(
                f"JS body decode ({url[:80]}…): {type(e).__name__}: {e}"
            )
            return None, 0
    except Exception as e:  # noqa: BLE001
        errors.append(f"fetch {url}: {e}")
        return None, 0


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Discover JS, extract endpoints/secrets, analyze source maps.
    Never raises.
    """
    t0 = time.perf_counter()
    timeout = max(1.0, float(config.get("timeout") or DEFAULT_TIMEOUT))
    threads = max(1, int(config.get("threads") or DEFAULT_THREADS))
    errors: list[str] = []

    base: dict[str, Any] = {
        "module": "js_recon",
        "target": target.value,
        "status": "pending",
        "base_url": None,
        "js_files": [],
        "endpoints": [],
        "secrets": [],
        "source_maps": [],
        "stats": {
            "js_files_found": 0,
            "js_files_analyzed": 0,
            "endpoints_found": 0,
            "secrets_found": 0,
            "source_maps_found": 0,
            "duration_s": 0.0,
        },
        "risk_summary": {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
        },
        "errors": errors,
        "warnings": [],
        "findings": [],
    }

    if target.is_cidr():
        base["status"] = "skipped"
        console.print(
            Panel(
                Text("  JS RECON  ·  CIDR not supported", style=f"bold {C_PRI}"),
                border_style=C_ACCENT,
                box=box.DOUBLE,
            )
        )
        console.print(Text("  [SKIP] JS recon — domain or IP only.", style=C_WARN))
        return base

    try:
        resolved = http_resolve_base_url(target, timeout, config, ssl_warnings=errors)
        if not resolved:
            base["status"] = "error"
            base["error"] = "Host unreachable (HTTP/HTTPS)"
            errors.append(base["error"])
            console.print(Text(f"  [✗] {base['error']}", style=C_ERR))
            return base

        base["base_url"] = resolved
        quiet = bool(config.get("quiet", False))
        console.print(
            Panel(
                Text(
                    f"  JS RECON  ·  {resolved}  ·  files + secrets + maps",
                    style=f"bold {C_PRI}",
                ),
                border_style=C_ACCENT,
                box=box.DOUBLE,
                width=min(console.size.width, 82) if console.size else 82,
            )
        )

        # --- Phase 1 discovery ---
        console.print(Text("\n [1/4] Discovering JS files...", style=f"bold {C_WARN}"))
        from_html = discover_js_from_html(resolved, timeout, errors, config)
        from_brute = brute_common_js_paths(resolved, timeout, threads, errors, config)
        all_js = set(from_html) | set(from_brute)
        prioritized, skipped_names = prioritize_js_files(sorted(all_js))
        base["stats"]["js_files_found"] = len(prioritized)
        console.print(
            Text(
                f"       {len(prioritized)} files queued · "
                f"{len(skipped_names)} low-priority / library names deprioritized",
                style=C_DIM,
            )
        )
        if skipped_names and not quiet:
            console.print(
                Text(f"       Skipped/low-pri: {' · '.join(skipped_names[:8])}", style=C_MUTED)
            )

        # --- Phase 2–4 fetch + analyze ---
        console.print(Text("\n [2/4] Analyzing JS files...", style=f"bold {C_WARN}"))
        endpoints_map: dict[str, dict[str, Any]] = {}
        all_secrets: list[dict[str, Any]] = []
        source_map_rows: list[dict[str, Any]] = []
        js_file_rows: list[dict[str, Any]] = []
        analyzed = 0

        to_fetch = prioritized[:MAX_JS_FILES_TO_FETCH]
        verbose = bool(config.get("verbose"))

        def work(u: str) -> dict[str, Any]:
            name = urlparse(u).path.split("/")[-1] or "script.js"
            text, size = fetch_js(u, timeout, errors, config)
            row: dict[str, Any] = {
                "url": u,
                "size": _human_size(size) if size else "0",
                "size_bytes": size,
                "analyzed": bool(text),
                "source_map": None,
            }
            if not text:
                return {"row": row, "eps": [], "secs": [], "sm": None, "name": name}
            eps = extract_endpoints(text, resolved, name)
            secs = detect_secrets(text, name)
            sm = check_source_map(u, text, timeout, errors, config)
            if sm and not source_map_on_target(
                sm, u, resolved, base["warnings"]
            ):
                if verbose:
                    hint = sm.get("url") or u
                    console.print(
                        Text(
                            f"   [i] Skipping external source map: {hint}",
                            style=C_DIM,
                        )
                    )
                sm = None
            if sm:
                row["source_map"] = sm
            return {"row": row, "eps": eps, "secs": secs, "sm": sm, "name": name}

        interrupted = False
        js_ep_limited = False
        try:
            with ThreadPoolExecutor(max_workers=min(threads, 16)) as ex:
                futs = {ex.submit(work, u): u for u in to_fetch}
                for fut in as_completed(futs):
                    try:
                        pack = fut.result()
                    except Exception as e:  # noqa: BLE001
                        errors.append(str(e))
                        continue
                    js_file_rows.append(pack["row"])
                    analyzed += 1 if pack["row"]["analyzed"] else 0
                    for ep in pack["eps"]:
                        k = ep["url"].lower()
                        if k in endpoints_map:
                            continue
                        if (
                            MAX_URLS_JS_RECON > 0
                            and len(endpoints_map) >= MAX_URLS_JS_RECON
                        ):
                            js_ep_limited = True
                            break
                        endpoints_map[k] = ep
                    if js_ep_limited:
                        break
                    for s in pack["secs"]:
                        all_secrets.append(s)
                    sm_pack = pack["sm"]
                    if sm_pack and (
                        sm_pack.get("accessible") or sm_pack.get("type") == "inline"
                    ):
                        smr = dict(sm_pack)
                        smr["js_file"] = pack["name"]
                        source_map_rows.append(smr)

                    name = pack["name"]
                    n_ep = len(pack["eps"])
                    n_sc = len(pack["secs"])
                    sm_note = "none"
                    smd = pack["sm"]
                    if smd:
                        if smd.get("type") == "inline":
                            sm_note = "INLINE [CRITICAL]"
                        elif smd.get("accessible"):
                            sm_note = "EXPOSED [CRITICAL]" if smd.get("has_content") else "EXPOSED"
                        else:
                            sm_note = "not found"
                    if not quiet:
                        st = Text.assemble(
                            (f"\n   [►] {name[:42]:<44}", C_PRI),
                            (f"{pack['row']['size']:>8}", C_DIM),
                        )
                        console.print(st)
                        console.print(
                            Text(
                                f"       Endpoints : {n_ep} · Secrets : {n_sc} · Source map: {sm_note}",
                                style=C_MUTED,
                            )
                        )
        except KeyboardInterrupt:
            interrupted = True
            errors.append("Interrupted — partial JS recon results")

        if js_ep_limited:
            base["warnings"].append(
                f"JS endpoint limit reached ({MAX_URLS_JS_RECON:,}) — "
                "increase MAX_URLS_JS_RECON in config.py"
            )
            console.print()
            console.print(
                Text(
                    f" [!] JS endpoint limit reached ({MAX_URLS_JS_RECON:,}) — "
                    "increase MAX_URLS_JS_RECON in config.py",
                    style=C_WARN,
                )
            )

        endpoints_list = list(endpoints_map.values())
        base["js_files"] = sorted(js_file_rows, key=lambda x: x.get("url", ""))
        base["endpoints"] = endpoints_list
        base["secrets"] = all_secrets
        base["source_maps"] = source_map_rows

        for ep in endpoints_list:
            rk = ep.get("risk") or "INFO"
            if rk not in base["risk_summary"]:
                rk = "INFO"
            lst = base["risk_summary"][rk]
            if ep["url"] not in lst:
                lst.append(ep["url"])
        for s in all_secrets:
            rk = s.get("risk") or "INFO"
            if rk not in base["risk_summary"]:
                rk = "INFO"
            tag = f"{s.get('type')}@{s.get('source')}"
            if tag not in base["risk_summary"][rk]:
                base["risk_summary"][rk].append(tag)

        base["stats"]["js_files_analyzed"] = analyzed
        base["stats"]["endpoints_found"] = len(endpoints_list)
        base["stats"]["secrets_found"] = len(all_secrets)
        base["stats"]["source_maps_found"] = len(source_map_rows)
        base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)

        # --- Tables ---
        if endpoints_list:
            ep_ch = [
                e
                for e in endpoints_list
                if e.get("risk") in ("CRITICAL", "HIGH")
            ]
            if quiet and ep_ch:
                display_findings(
                    [
                        {
                            "risk": str(e.get("risk") or "HIGH"),
                            "category": str(e.get("category") or "js_endpoint"),
                            "value": str(e.get("url") or ""),
                            "note": str(e.get("source") or ""),
                        }
                        for e in ep_ch
                    ],
                    module="js_recon",
                    verbose=verbose,
                    config=config,
                )
            elif not quiet:
                console.print()
                console.print(
                    Text(
                        f" [ENDPOINTS] {len(endpoints_list)} discovered",
                        style=f"bold {C_WARN}",
                    )
                )
                tbl = Table(box=box.ROUNDED, border_style=C_ACCENT)
                tbl.add_column("Endpoint", style=C_DIM, max_width=44)
                tbl.add_column("Source", style=C_MUTED)
                tbl.add_column("Category", style=C_DIM)
                tbl.add_column("Risk", style=C_DIM)
                for ep in sorted(
                    endpoints_list, key=lambda x: (x.get("risk", ""), x["url"])
                )[:45]:
                    rk = ep.get("risk", "INFO")
                    style = C_ERR if rk == "CRITICAL" else C_WARN if rk == "HIGH" else C_DIM
                    tbl.add_row(
                        ep["url"][:200],
                        ep.get("source", "—"),
                        ep.get("category", "—"),
                        Text(str(rk), style=style),
                    )
                console.print(tbl)

        if all_secrets:
            sec_show = (
                [s for s in all_secrets if s.get("risk") in ("CRITICAL", "HIGH")]
                if quiet
                else all_secrets[:15]
            )
            if sec_show:
                console.print()
                console.print(Text(" [!!!] SECRETS DETECTED", style=f"bold {C_ERR}"))
                for s in sec_show:
                    console.print(
                        Text(
                            f"   ├── [{s.get('risk')}] {s.get('type')} in {s.get('source')}",
                            style=C_ERR,
                        )
                    )
                    console.print(
                        Text(
                            f"   │              {s.get('value')} (confidence: {s.get('confidence')})",
                            style=C_MUTED,
                        )
                    )

        exposed_maps = [
            m
            for m in source_map_rows
            if m.get("accessible") or m.get("type") == "inline"
        ]
        if exposed_maps:
            console.print()
            console.print(
                Text(" [!!!] SOURCE MAP EXPOSED — CRITICAL", style=f"bold {C_ERR}")
            )
            for m in exposed_maps[:8]:
                console.print(Text(f"   ├── Map: {m.get('url', 'inline')}", style=C_WARN))
                console.print(
                    Text(
                        f"   │    Sources: {m.get('sources_count', 0)} · "
                        f"Embedded content: {m.get('has_content', False)}",
                        style=C_MUTED,
                    )
                )
                sf = m.get("source_files") or []
                if sf:
                    console.print(
                        Text(f"   │    e.g. {' · '.join(str(x) for x in sf[:5])}", style=C_DIM)
                    )

        crit_ep = sum(1 for e in endpoints_list if e.get("risk") == "CRITICAL")
        high_ep = sum(1 for e in endpoints_list if e.get("risk") == "HIGH")
        crit_sec = sum(1 for s in all_secrets if s.get("risk") == "CRITICAL")
        high_sec = sum(1 for s in all_secrets if s.get("risk") == "HIGH")

        base["status"] = "success"
        base["findings"] = endpoints_list + all_secrets + source_map_rows

        console.print()
        console.print(
            Text.assemble(
                ("\n [✓] JS recon complete\n", f"bold {C_PRI}"),
                (
                    f"     JS files    : {len(prioritized)} found · {analyzed} analyzed\n",
                    C_DIM,
                ),
                (
                    f"     Endpoints   : {len(endpoints_list)} "
                    f"({crit_ep} critical · {high_ep} high)\n",
                    C_DIM,
                ),
                (
                    f"     Secrets     : {len(all_secrets)} "
                    f"({crit_sec} critical · {high_sec} high)\n",
                    C_DIM,
                ),
                (
                    f"     Source maps : {len(exposed_maps)} exposed\n",
                    C_DIM,
                ),
                (f"     Duration    : {base['stats']['duration_s']}s", C_DIM),
            )
        )
        if interrupted:
            console.print(Text("  [!] Interrupted — partial results above", style=C_WARN))

    except Exception as e:  # noqa: BLE001
        base["status"] = "error"
        base["error"] = str(e)
        errors.append(str(e))
        console.print(Text(f"  [✗] {e}", style=C_ERR))

    return base
