"""
GhostOpcode HTTP methods probe — OPTIONS, dangerous verbs, XST/WebDAV, headers, CORS.
"""

from __future__ import annotations

import random
import re
import secrets
import string
import time
import urllib3
from typing import Any
from urllib.parse import urlparse, urljoin

import requests
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config import DEFAULT_TIMEOUT, USER_AGENT
from utils.target_parser import Target

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_ACCENT = "#8B9CA8"

console = Console(highlight=False, force_terminal=True)

METHODS_TO_TEST: dict[str, dict[str, Any]] = {
    "GET": {"safe": True, "risk": "INFO", "test": True},
    "POST": {"safe": True, "risk": "INFO", "test": True},
    "PUT": {"safe": False, "risk": "CRITICAL", "test": True},
    "DELETE": {"safe": False, "risk": "CRITICAL", "test": True},
    "PATCH": {"safe": False, "risk": "HIGH", "test": True},
    "OPTIONS": {"safe": True, "risk": "INFO", "test": True},
    "HEAD": {"safe": True, "risk": "INFO", "test": True},
    "TRACE": {"safe": False, "risk": "CRITICAL", "test": True},
    "TRACK": {"safe": False, "risk": "CRITICAL", "test": True},
    "CONNECT": {"safe": False, "risk": "HIGH", "test": True},
    "PROPFIND": {"safe": True, "risk": "MEDIUM", "test": True},
    "PROPPATCH": {"safe": False, "risk": "HIGH", "test": True},
    "MKCOL": {"safe": False, "risk": "HIGH", "test": True},
    "COPY": {"safe": False, "risk": "HIGH", "test": True},
    "MOVE": {"safe": False, "risk": "HIGH", "test": True},
    "LOCK": {"safe": False, "risk": "MEDIUM", "test": True},
    "UNLOCK": {"safe": False, "risk": "MEDIUM", "test": True},
}

TEST_ENDPOINTS: list[str] = [
    "/",
    "/api",
    "/api/v1",
    "/api/v2",
    "/admin",
    "/upload",
    "/files",
    "/rest",
    "/graphql",
    "/xmlrpc.php",
    "/wp-json/",
]

PROPFIND_BODY = """<?xml version="1.0" encoding="utf-8"?>
<propfind xmlns="DAV:">
  <prop><resourcetype/><getcontentlength/></prop>
</propfind>"""

SECURITY_HEADERS: dict[str, dict[str, Any]] = {
    "Strict-Transport-Security": {
        "required": True,
        "risk_if_missing": "MEDIUM",
        "description": "HSTS not set — HTTP downgrade possible",
    },
    "Content-Security-Policy": {
        "required": True,
        "risk_if_missing": "MEDIUM",
        "description": "No CSP — XSS attacks not mitigated",
    },
    "X-Frame-Options": {
        "required": True,
        "risk_if_missing": "LOW",
        "description": "Clickjacking protection missing",
    },
    "X-Content-Type-Options": {
        "required": True,
        "risk_if_missing": "LOW",
        "description": "MIME sniffing not disabled",
    },
    "Referrer-Policy": {
        "required": True,
        "risk_if_missing": "LOW",
        "description": "Referrer leakage possible",
    },
    "Permissions-Policy": {
        "required": True,
        "risk_if_missing": "LOW",
        "description": "Browser features not restricted",
    },
    "Server": {
        "required": False,
        "risk_if_present": "LOW",
        "description": "Server version exposed",
    },
    "X-Powered-By": {
        "required": False,
        "risk_if_present": "LOW",
        "description": "Backend technology exposed",
    },
    "X-AspNet-Version": {
        "required": False,
        "risk_if_present": "LOW",
        "description": "ASP.NET version exposed",
    },
}

XST_HEADER = "X-GhostOpcode-Test"
XST_VALUE = "xst_probe"


def _session_headers() -> dict[str, str]:
    return {"User-Agent": USER_AGENT}


def resolve_base_url(target: Target, timeout: float) -> str | None:
    """Pick working https or http origin for target host."""
    host = target.value
    for scheme in ("https", "http"):
        base = f"{scheme}://{host}".rstrip("/")
        root = base + "/"
        try:
            r = requests.get(
                root,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers=_session_headers(),
            )
            if 0 < r.status_code < 600:
                u = urlparse(r.url)
                return u._replace(path="", params="", query="", fragment="").geturl().rstrip("/")
        except Exception:  # noqa: BLE001
            continue
    return None


def _join_url(base: str, path: str) -> str:
    path = path if path.startswith("/") else "/" + path
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def detect_endpoint_catchall(url: str, timeout: float) -> dict[str, Any]:
    """
    Detect catchall routing: invented HTTP methods should not all return 200.
    Fully dynamic — no framework-specific strings.
    """
    fake_methods = [
        "GHOSTTEST" + "".join(random.choices(string.ascii_uppercase, k=4)),
        "XPROBE" + "".join(random.choices(string.digits, k=4)),
        "NULLMETHOD" + "".join(random.choices(string.ascii_uppercase, k=3)),
    ]
    responses: list[dict[str, Any]] = []
    for method in fake_methods:
        try:
            resp = requests.request(
                method=method,
                url=url,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                headers=_session_headers(),
            )
            responses.append({"method": method, "status": resp.status_code})
        except Exception:  # noqa: BLE001
            responses.append({"method": method, "status": None})

    valid_responses = [r for r in responses if r.get("status") is not None]
    all_200 = bool(valid_responses) and all(
        r["status"] == 200 for r in valid_responses
    )
    # Require at least two real responses; all must be 200 (typical SPA/router trap)
    is_catchall = len(valid_responses) >= 2 and all_200
    catch_status = valid_responses[0]["status"] if valid_responses else None
    evidence = [f"{r['method']} → {r['status']}" for r in responses]
    real_405 = next(
        (r["status"] for r in valid_responses if r["status"] == 405),
        None,
    )
    return {
        "is_catchall": is_catchall,
        "evidence": evidence,
        "catch_status": catch_status,
        "real_405_status": real_405,
    }


def _response_looks_like_html_trap(resp: requests.Response) -> bool:
    """Heuristic: default document page instead of real verb handling."""
    ct = (resp.headers.get("Content-Type") or "").lower()
    if "text/html" in ct:
        return True
    chunk = (resp.text or "")[:6000].lstrip().lower()
    if not chunk:
        return False
    if chunk.startswith("<!doctype") or chunk.startswith("<html"):
        return True
    if "<head" in chunk[:500] and "<body" in chunk[:3000]:
        return True
    return False


def _probe_relpath(endpoint_path: str, filename: str) -> str:
    """Path segment under host for probes (handles endpoint '/')."""
    ep = (endpoint_path or "").strip()
    fn = filename.lstrip("/")
    if not ep or ep == "/":
        return fn
    return f"{ep.strip('/')}/{fn}"


def parse_allow_header(value: str | None) -> list[str]:
    """Split Allow / Public / ACA-Methods into uppercase method tokens."""
    if not value or not value.strip():
        return []
    parts = re.split(r"[,\s]+", value.replace(";", ","))
    return sorted({p.strip().upper() for p in parts if p.strip()})


def probe_options(url: str, timeout: float) -> dict[str, Any]:
    """
    Send OPTIONS and parse Allow / Public / Access-Control-Allow-Methods.
    Does not trust this alone — each method is probed separately.
    """
    out: dict[str, Any] = {
        "status": None,
        "allow": [],
        "public": [],
        "access_control_allow_methods": [],
        "raw_allow": None,
        "error": None,
    }
    try:
        r = requests.options(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers=_session_headers(),
        )
        out["status"] = r.status_code
        al = r.headers.get("Allow") or r.headers.get("allow")
        out["raw_allow"] = al
        out["allow"] = parse_allow_header(al)
        pub = r.headers.get("Public")
        out["public"] = parse_allow_header(pub)
        ac = (
            r.headers.get("Access-Control-Allow-Methods")
            or r.headers.get("access-control-allow-methods")
        )
        out["access_control_allow_methods"] = parse_allow_header(ac)
    except requests.Timeout:
        out["error"] = "timeout"
    except requests.RequestException as e:
        out["error"] = str(e)
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


def endpoint_reachable(url: str, timeout: float) -> tuple[bool, int | None]:
    """True if path does not look like a hard 404 (still probe methods if unsure)."""
    try:
        r = requests.head(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers=_session_headers(),
        )
        code = r.status_code
        if code == 405:
            g = requests.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers=_session_headers(),
                stream=True,
            )
            try:
                code = g.status_code
            finally:
                g.close()
        return code != 404, code
    except Exception:  # noqa: BLE001
        try:
            r = requests.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers=_session_headers(),
                stream=True,
            )
            try:
                c = r.status_code
                return c != 404, c
            finally:
                r.close()
        except Exception:  # noqa: BLE001
            return True, None


def test_put(url_base: str, endpoint_path: str, timeout: float, rid: str) -> dict[str, Any]:
    """
    Non-destructive PUT probe: unique filename under endpoint path.
    """
    rel = _probe_relpath(endpoint_path, f"ghostopcode_probe_{rid}.txt")
    test_url = _join_url(url_base, rel)
    result: dict[str, Any] = {
        "status": None,
        "enabled": False,
        "risk": None,
        "note": None,
        "url": test_url,
        "error": None,
    }
    try:
        r = requests.put(
            test_url,
            data=b"ghostopcode safe probe - remove if seen",
            timeout=timeout,
            verify=False,
            allow_redirects=False,
            headers={
                **_session_headers(),
                "Content-Type": "text/plain",
            },
        )
        result["status"] = r.status_code
        c = r.status_code
        if c == 201:
            result["enabled"] = True
            result["risk"] = "CRITICAL"
            result["note"] = "PUT 201 Created — upload likely accepted"
            result["put_confirmed"] = True
        elif c == 204:
            result["enabled"] = True
            result["risk"] = "CRITICAL"
            result["note"] = "PUT 204 — accepted (verify resource semantics)"
            result["put_confirmed"] = True
        elif c == 200:
            if _response_looks_like_html_trap(r):
                result["enabled"] = False
                result["risk"] = None
                result["note"] = (
                    "PUT 200 with HTML body — likely catchall/router, not real upload"
                )
            else:
                result["enabled"] = True
                result["risk"] = "CRITICAL"
                result["note"] = "PUT 200 non-HTML — possible upload/API accept"
                result["put_confirmed"] = True
        elif c == 403:
            result["enabled"] = True
            result["risk"] = "MEDIUM"
            result["note"] = "PUT recognized but forbidden"
        elif c == 401:
            result["enabled"] = True
            result["risk"] = "LOW"
            result["note"] = "PUT requires authentication"
        elif c in (405, 501):
            result["enabled"] = False
            result["note"] = "PUT not allowed or not implemented"
        elif 400 <= c < 500:
            result["note"] = f"Client error {c}"
        else:
            result["note"] = f"Unexpected {c}"
    except requests.Timeout:
        result["error"] = "timeout"
        result["note"] = "timeout"
    except requests.RequestException as e:
        result["error"] = str(e)
        result["note"] = str(e)
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        result["note"] = str(e)
    return result


def test_delete(url_base: str, endpoint_path: str, timeout: float, rid: str) -> dict[str, Any]:
    """DELETE a guaranteed-nonexistent resource to detect verb support."""
    rel = _probe_relpath(endpoint_path, f"ghostopcode_nonexistent_{rid}")
    test_url = _join_url(url_base, rel)
    result: dict[str, Any] = {
        "status": None,
        "enabled": False,
        "risk": None,
        "note": None,
        "url": test_url,
        "error": None,
    }
    try:
        r = requests.delete(
            test_url,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
            headers=_session_headers(),
        )
        result["status"] = r.status_code
        c = r.status_code
        if c == 404:
            result["enabled"] = True
            result["risk"] = "INFO"
            result["note"] = "DELETE routed — resource missing (safe probe)"
        elif c in (200, 204):
            if _response_looks_like_html_trap(r):
                result["enabled"] = False
                result["risk"] = None
                result["note"] = (
                    "DELETE success with HTML body — likely catchall, not real delete"
                )
            else:
                result["enabled"] = True
                result["risk"] = "CRITICAL"
                result["note"] = (
                    "DELETE returned success on probe path — verify server logic"
                )
        elif c == 403:
            result["enabled"] = True
            result["risk"] = "MEDIUM"
            result["note"] = "DELETE recognized but forbidden"
        elif c in (405, 501):
            result["enabled"] = False
            result["note"] = "DELETE disabled"
        else:
            result["note"] = f"HTTP {c}"
    except requests.Timeout:
        result["error"] = "timeout"
        result["note"] = "timeout"
    except requests.RequestException as e:
        result["error"] = str(e)
        result["note"] = str(e)
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        result["note"] = str(e)
    return result


def test_trace_like(
    url: str,
    timeout: float,
    method: str,
) -> dict[str, Any]:
    """
    TRACE or TRACK — if body echoes custom header, XST-style reflection is likely.
    """
    result: dict[str, Any] = {
        "status": None,
        "enabled": False,
        "risk": None,
        "xst_confirmed": False,
        "note": None,
        "error": None,
    }
    try:
        r = requests.request(
            method,
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
            headers={**_session_headers(), XST_HEADER: XST_VALUE},
        )
        result["status"] = r.status_code
        body = (r.text or "")[:8000]
        if r.status_code == 200 and XST_HEADER in body and XST_VALUE in body:
            result["enabled"] = True
            result["risk"] = "CRITICAL"
            result["xst_confirmed"] = True
            result["note"] = "XST — request headers echoed in response body"
        elif r.status_code == 200:
            ct = (r.headers.get("Content-Type") or "").lower()
            if "text/html" in ct or _response_looks_like_html_trap(r):
                result["enabled"] = False
                result["risk"] = None
                result["note"] = f"{method} 200 with HTML — likely catchall, not XST"
            else:
                result["enabled"] = True
                result["risk"] = "HIGH"
                result["note"] = f"{method} returns 200 — confirm echo manually"
        elif r.status_code in (405, 501):
            result["enabled"] = False
            result["note"] = f"{method} not supported"
        else:
            result["note"] = f"HTTP {r.status_code}"
    except requests.Timeout:
        result["error"] = "timeout"
        result["note"] = "timeout"
    except requests.RequestException as e:
        result["error"] = str(e)
        result["note"] = str(e)
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        result["note"] = str(e)
    return result


def test_propfind(url: str, timeout: float) -> dict[str, Any]:
    """Minimal WebDAV PROPFIND; 207 Multi-Status suggests DAV surface."""
    result: dict[str, Any] = {
        "status": None,
        "enabled": False,
        "risk": None,
        "note": None,
        "error": None,
    }
    try:
        r = requests.request(
            "PROPFIND",
            url,
            data=PROPFIND_BODY,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={
                **_session_headers(),
                "Content-Type": "application/xml",
                "Depth": "1",
            },
        )
        result["status"] = r.status_code
        if r.status_code == 207:
            result["enabled"] = True
            result["risk"] = "HIGH"
            result["note"] = "WebDAV PROPFIND — 207 Multi-Status (listing likely)"
        elif r.status_code == 200 and _response_looks_like_html_trap(r):
            result["enabled"] = False
            result["note"] = "PROPFIND 200 with HTML — likely catchall"
        elif r.status_code in (401, 403):
            result["enabled"] = True
            result["risk"] = "MEDIUM"
            result["note"] = "PROPFIND recognized — auth may protect listing"
        elif r.status_code in (405, 501):
            result["enabled"] = False
            result["note"] = "PROPFIND not supported"
        else:
            result["note"] = f"HTTP {r.status_code}"
    except requests.Timeout:
        result["error"] = "timeout"
        result["note"] = "timeout"
    except requests.RequestException as e:
        result["error"] = str(e)
        result["note"] = str(e)
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        result["note"] = str(e)
    return result


def test_generic_method(url: str, method: str, timeout: float, risk_hint: str) -> dict[str, Any]:
    """HEAD/GET/POST/PATCH/OPTIONS/CONNECT and other verbs with minimal body."""
    result: dict[str, Any] = {
        "status": None,
        "enabled": False,
        "risk": risk_hint if risk_hint != "INFO" else "INFO",
        "note": None,
        "error": None,
    }
    try:
        kwargs: dict[str, Any] = {
            "timeout": timeout,
            "verify": False,
            "allow_redirects": True,
            "headers": _session_headers(),
        }
        if method == "POST":
            kwargs["data"] = b""
        elif method == "PATCH":
            kwargs["data"] = b"{}"
            kwargs["headers"] = {**_session_headers(), "Content-Type": "application/json"}
        r = requests.request(method, url, **kwargs)
        result["status"] = r.status_code
        c = r.status_code
        webdavish = method in (
            "PROPPATCH",
            "MKCOL",
            "COPY",
            "MOVE",
            "LOCK",
            "UNLOCK",
        )
        if webdavish and c in (200, 201, 204, 207) and _response_looks_like_html_trap(r):
            result["enabled"] = False
            result["risk"] = "INFO"
            result["note"] = f"{method} {c} with HTML body — likely catchall"
        elif method == "PATCH" and c in (200, 201, 204) and _response_looks_like_html_trap(
            r
        ):
            result["enabled"] = False
            result["risk"] = None
            result["note"] = f"PATCH {c} with HTML — likely catchall"
        elif method == "OPTIONS" and c < 500:
            result["enabled"] = True
            al = r.headers.get("Allow")
            result["note"] = f"Allow: {al}" if al else "OPTIONS OK"
        elif method == "HEAD" and c < 500:
            result["enabled"] = c != 405
            result["note"] = f"HEAD {c}"
        elif method == "GET" and c < 600:
            result["enabled"] = True
            result["note"] = f"GET {c}"
        elif method == "POST" and c not in (405, 501):
            if c == 200 and _response_looks_like_html_trap(r):
                result["enabled"] = False
                result["note"] = "POST 200 with HTML — likely catchall"
            else:
                result["enabled"] = True
                result["note"] = f"POST {c}"
        elif method == "PATCH" and c not in (405, 501):
            result["enabled"] = True
            result["risk"] = "HIGH" if c in (200, 201, 204) else risk_hint
            result["note"] = f"PATCH {c}"
        elif method == "CONNECT":
            result["enabled"] = c not in (405, 501, 400)
            result["note"] = f"CONNECT {c}"
        elif method in ("PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"):
            if c in (200, 201, 204, 207):
                result["enabled"] = True
                result["risk"] = METHODS_TO_TEST.get(method, {}).get("risk", "HIGH")
                result["note"] = f"{method} accepted ({c})"
            elif c in (405, 501):
                result["enabled"] = False
                result["note"] = f"{method} not supported"
            elif c in (401, 403):
                result["enabled"] = True
                result["risk"] = "MEDIUM"
                result["note"] = f"{method} auth required ({c})"
            else:
                result["note"] = f"{method} {c}"
        else:
            result["enabled"] = c not in (405, 501)
            result["note"] = f"{method} {c}"
    except requests.Timeout:
        result["error"] = "timeout"
        result["note"] = "timeout"
    except requests.RequestException as e:
        result["error"] = str(e)
        result["note"] = str(e)
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        result["note"] = str(e)
    return result


def audit_security_headers(response: requests.Response | None) -> dict[str, Any]:
    """Classify required vs leaking headers from a baseline GET."""
    present: list[str] = []
    missing: list[dict[str, str]] = []
    exposed: list[dict[str, str]] = []
    if response is None:
        return {"present": [], "missing": [], "exposed": []}
    h = {k.lower(): v for k, v in response.headers.items()}
    for name, spec in SECURITY_HEADERS.items():
        lk = name.lower()
        val = h.get(lk)
        if spec.get("required") is True:
            if val:
                present.append(name)
            else:
                missing.append(
                    {
                        "header": name,
                        "risk": str(spec.get("risk_if_missing", "LOW")),
                    }
                )
        elif spec.get("required") is False and spec.get("risk_if_present"):
            if val:
                exposed.append(
                    {
                        "header": name,
                        "value": val[:120],
                        "risk": str(spec.get("risk_if_present")),
                    }
                )
    return {"present": present, "missing": missing, "exposed": exposed}


def test_cors(base_url: str, timeout: float) -> dict[str, Any]:
    """
    Probe CORS with synthetic Origin values (read-only, no credential exfil).
    """
    out: dict[str, Any] = {
        "misconfigured": False,
        "type": None,
        "risk": None,
        "details": None,
    }
    root = _join_url(base_url, "/")
    tests = [
        ("https://evil-ghostopcode.example", "reflected"),
        ("null", "null"),
    ]
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    if host:
        bypass = f"https://{host}.evil-ghostopcode.example"
        tests.append((bypass, "subdomain_bypass"))
    try:
        r0 = requests.get(
            root,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers=_session_headers(),
        )
        acao = (
            r0.headers.get("Access-Control-Allow-Origin")
            or r0.headers.get("access-control-allow-origin")
        )
        if acao == "*":
            out["misconfigured"] = True
            out["type"] = "wildcard"
            out["risk"] = "HIGH"
            out["details"] = "Access-Control-Allow-Origin: *"
            return out
    except Exception:  # noqa: BLE001
        pass

    for origin, kind in tests:
        try:
            r = requests.get(
                root,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers={**_session_headers(), "Origin": origin},
            )
            acao = (
                r.headers.get("Access-Control-Allow-Origin")
                or r.headers.get("access-control-allow-origin")
            )
            if not acao:
                continue
            if acao == "*" and kind != "reflected":
                out["misconfigured"] = True
                out["type"] = "wildcard"
                out["risk"] = "HIGH"
                out["details"] = "Access-Control-Allow-Origin: *"
                return out
            if acao == origin or (origin == "null" and acao.strip().lower() == "null"):
                out["misconfigured"] = True
                out["type"] = "reflected" if kind == "reflected" else kind
                out["risk"] = "CRITICAL" if kind == "reflected" else "HIGH"
                out["details"] = f"ACAO reflects untrusted Origin ({origin[:48]}…)"
                return out
        except Exception:  # noqa: BLE001
            continue
    return out


def _merge_declared_options(opt: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    for key in ("allow", "public", "access_control_allow_methods"):
        for m in opt.get(key) or []:
            seen.add(m.upper())
    return sorted(seen)


def _run_method_probe(
    base: str,
    endpoint_path: str,
    timeout: float,
    rid: str,
) -> dict[str, Any]:
    """Run full method matrix for one endpoint URL (index page of path)."""
    url = _join_url(base, endpoint_path)
    opt = probe_options(url, timeout)
    declared = _merge_declared_options(opt)
    tested: dict[str, Any] = {}

    for method, spec in METHODS_TO_TEST.items():
        if not spec.get("test", True):
            continue
        m = method.upper()
        risk = spec.get("risk", "INFO")
        if m == "PUT":
            tested[m] = test_put(base, endpoint_path, timeout, rid)
        elif m == "DELETE":
            tested[m] = test_delete(base, endpoint_path, timeout, rid)
        elif m == "TRACE":
            tested[m] = test_trace_like(url, timeout, "TRACE")
        elif m == "TRACK":
            tested[m] = test_trace_like(url, timeout, "TRACK")
        elif m == "PROPFIND":
            tested[m] = test_propfind(url, timeout)
        else:
            tested[m] = test_generic_method(url, m, timeout, str(risk))

        # Normalize enabled + risk for table
        row = tested[m]
        if "risk" not in row or row["risk"] is None:
            if row.get("enabled") and risk not in ("INFO", None):
                row["risk"] = risk
            elif row.get("enabled"):
                row["risk"] = "INFO"

    return {
        "options_probe": opt,
        "options_declared": declared,
        "methods_tested": tested,
    }


def _build_risk_summary(
    methods_by_ep: dict[str, Any],
    cors: dict[str, Any],
    sec: dict[str, Any],
    webdav: dict[str, Any],
) -> dict[str, list[str]]:
    rs: dict[str, list[str]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for ep, block in methods_by_ep.items():
        for meth, info in (block.get("methods_tested") or {}).items():
            if info.get("xst_confirmed"):
                t = f"{meth} XST {ep}"
                if t not in rs["CRITICAL"]:
                    rs["CRITICAL"].append(t)
                continue
            r = info.get("risk")
            if r in rs and info.get("enabled"):
                tag = f"{meth} {ep}"
                if tag not in rs[r]:
                    rs[r].append(tag)
    if cors.get("misconfigured"):
        rs[str(cors.get("risk") or "HIGH")].append("CORS " + str(cors.get("type")))
    for m in sec.get("missing") or []:
        rk = m.get("risk", "LOW")
        if rk in rs:
            rs[rk].append("Missing " + m.get("header", ""))
    for e in sec.get("exposed") or []:
        rs["LOW"].append("Exposed " + e.get("header", ""))
    if webdav.get("enabled"):
        rs[str(webdav.get("risk") or "HIGH")].append("WebDAV")
    return rs


def _critical_findings_list(methods_by_ep: dict[str, Any], cors: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    for ep, block in methods_by_ep.items():
        for meth, info in (block.get("methods_tested") or {}).items():
            if info.get("risk") == "CRITICAL" and info.get("enabled"):
                findings.append(f"{meth} on {ep} — {info.get('note', '')}")
            if info.get("xst_confirmed"):
                findings.append(f"TRACE/XST confirmed on {ep}")
    if cors.get("misconfigured"):
        findings.append("CORS: " + str(cors.get("details", "")))
    return findings[:25]


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Probe HTTP methods, security headers, CORS, and WebDAV indicators.
    Never raises.
    """
    t0 = time.perf_counter()
    timeout = max(1.0, float(config.get("timeout") or DEFAULT_TIMEOUT))
    verbose = bool(config.get("verbose", False))
    errors: list[str] = []

    base: dict[str, Any] = {
        "module": "http_methods",
        "target": target.value,
        "status": "pending",
        "base_url": None,
        "methods": {},
        "security_headers": {"present": [], "missing": [], "exposed": []},
        "cors": {
            "misconfigured": False,
            "type": None,
            "risk": None,
            "details": None,
        },
        "webdav": {"enabled": False, "risk": None},
        "critical_findings": [],
        "risk_summary": {},
        "stats": {
            "methods_tested": 0,
            "dangerous": 0,
            "duration_s": 0.0,
            "endpoints_skipped_catchall": 0,
            "endpoints_tested_clean": 0,
        },
        "catchall_skipped": [],
        "errors": errors,
        "findings": [],
    }

    if target.is_cidr():
        base["status"] = "skipped"
        console.print(
            Panel(
                Text("  HTTP METHODS  ·  CIDR not supported", style=f"bold {C_PRI}"),
                border_style=C_ACCENT,
                box=box.DOUBLE,
            )
        )
        console.print(Text("  [SKIP] HTTP methods — domain or IP only.", style=C_WARN))
        return base

    try:
        resolved = resolve_base_url(target, timeout)
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
                Text(f"  HTTP METHODS  ·  {resolved}", style=f"bold {C_PRI}"),
                border_style=C_ACCENT,
                box=box.DOUBLE,
                width=min(console.size.width, 82) if console.size else 82,
            )
        )

        active_endpoints: list[str] = []
        for ep in TEST_ENDPOINTS:
            u = _join_url(resolved, ep)
            ok, code = endpoint_reachable(u, timeout)
            if ok or ep == "/":
                active_endpoints.append(ep)
            elif verbose:
                console.print(Text(f"  [skip] {ep} (HTTP {code})", style=C_MUTED))

        if "/" not in active_endpoints:
            active_endpoints.insert(0, "/")

        baseline_resp: requests.Response | None = None
        try:
            baseline_resp = requests.get(
                _join_url(resolved, "/"),
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers=_session_headers(),
            )
        except Exception as e:  # noqa: BLE001
            errors.append(f"baseline GET: {e}")

        sec = audit_security_headers(baseline_resp)
        base["security_headers"] = sec

        cors = test_cors(resolved, timeout)
        base["cors"] = cors

        methods_out: dict[str, Any] = {}
        catchall_skipped: list[dict[str, Any]] = []
        webdav_hit = False
        methods_count = 0
        dangerous = 0

        for ep in active_endpoints:
            probe_url = _join_url(resolved, ep)
            if ep != "/":
                cinfo = detect_endpoint_catchall(probe_url, timeout)
                if cinfo.get("is_catchall"):
                    catchall_skipped.append({"endpoint": ep, **cinfo})
                    cs = cinfo.get("catch_status")
                    if not quiet:
                        console.print(
                            Text(
                                f" [!] {ep}  → catchall detected "
                                f"(status {cs} for bogus methods) — skipping",
                                style=C_WARN,
                            )
                        )
                    continue

            if not quiet:
                console.print(
                    Text(f" [✓] {ep}  → testing methods (non-catchall)", style=C_PRI),
                )
            rid = secrets.token_hex(6)
            block = _run_method_probe(resolved, ep, timeout, rid)
            methods_out[ep] = block
            for _m, info in block["methods_tested"].items():
                methods_count += 1
                if info.get("risk") in ("CRITICAL", "HIGH") and info.get("enabled"):
                    dangerous += 1
                if info.get("xst_confirmed"):
                    dangerous += 1
                if _m == "PROPFIND" and info.get("enabled") and info.get("status") == 207:
                    webdav_hit = True

        base["methods"] = methods_out
        base["catchall_skipped"] = catchall_skipped
        base["webdav"] = {
            "enabled": webdav_hit,
            "risk": "HIGH" if webdav_hit else None,
        }

        risk_summary = _build_risk_summary(methods_out, cors, sec, base["webdav"])
        base["risk_summary"] = risk_summary
        crit = _critical_findings_list(methods_out, cors)
        base["critical_findings"] = crit
        base["findings"] = crit

        # --- Terminal output ---
        if not quiet:
            for ep, block in methods_out.items():
                decl = block.get("options_declared") or []
                if decl:
                    line = ", ".join(decl)
                    t = Text(
                        f"\n [OPTIONS] Declared methods on {ep}:\n   ",
                        style=f"bold {C_WARN}",
                    )
                    t.append("Allow / ACA: ", style=C_DIM)
                    for i, m in enumerate(decl):
                        style = C_ERR if m in ("PUT", "DELETE", "TRACE", "TRACK") else C_DIM
                        t.append(m, style=style)
                        if i < len(decl) - 1:
                            t.append(", ", style=C_DIM)
                    console.print(t)

                tbl = Table(
                    title=Text(f"Methods @ {ep}", style=f"bold {C_PRI}"),
                    box=box.ROUNDED,
                    border_style=C_ACCENT,
                )
                tbl.add_column("Method", style=C_DIM)
                tbl.add_column("Status", justify="right")
                tbl.add_column("Finding", style=C_MUTED)
                for meth in sorted(block["methods_tested"].keys()):
                    info = block["methods_tested"][meth]
                    st = info.get("status")
                    st_s = str(st) if st is not None else "—"
                    note = info.get("note") or info.get("error") or "—"
                    rk = info.get("risk")
                    if rk == "CRITICAL":
                        note_s = f"[CRITICAL] {note}"
                        style = C_ERR
                    elif rk == "HIGH":
                        note_s = f"[HIGH] {note}"
                        style = C_WARN
                    elif rk == "MEDIUM":
                        note_s = f"[MEDIUM] {note}"
                        style = C_WARN
                    else:
                        note_s = note
                        style = C_MUTED
                    tbl.add_row(meth, st_s, Text(note_s, style=style))
                console.print()
                console.print(tbl)

            console.print()
            console.print(Text(" [HEADERS] Security audit", style=f"bold {C_WARN}"))
            for name in sec.get("present") or []:
                console.print(
                    Text(f"   ✓  {name:<32} present", style=C_PRI),
                )
            for m in sec.get("missing") or []:
                console.print(
                    Text(
                        f"   ✗  {m.get('header', ''):<32} MISSING  [{m.get('risk', 'LOW')}]",
                        style=C_ERR if m.get("risk") == "MEDIUM" else C_WARN,
                    )
                )
            for e in sec.get("exposed") or []:
                console.print(
                    Text(
                        f"   !  {e.get('header', '')}: {e.get('value', '')[:50]}  exposed  [{e.get('risk')}]",
                        style=C_WARN,
                    )
                )

        if cors.get("misconfigured"):
            console.print()
            console.print(Text(" [CORS] Misconfiguration detected!", style=f"bold {C_ERR}"))
            console.print(Text(f"   {cors.get('details', '')}", style=C_WARN))
            console.print(
                Text(f"   → Risk: {cors.get('risk')} ({cors.get('type')})", style=C_MUTED),
            )

        if crit:
            console.print()
            console.print(Text(" [!!!] CRITICAL / HIGH FINDINGS:", style=f"bold {C_ERR}"))
            for f in crit[:12]:
                console.print(Text(f"   ├── {f}", style=C_ERR))

        duration = time.perf_counter() - t0
        base["stats"]["methods_tested"] = methods_count
        base["stats"]["dangerous"] = dangerous
        base["stats"]["duration_s"] = round(duration, 2)
        base["stats"]["endpoints_skipped_catchall"] = len(catchall_skipped)
        base["stats"]["endpoints_tested_clean"] = len(methods_out)
        base["status"] = "success"

        miss_n = len(sec.get("missing") or [])
        exp_n = len(sec.get("exposed") or [])
        console.print()
        console.print(
            Text.assemble(
                ("\n [✓] HTTP methods complete\n", f"bold {C_PRI}"),
                (f"     Methods tested  : {methods_count}\n", C_DIM),
                (f"     Dangerous hits  : {dangerous}\n", C_DIM),
                (
                    f"     Endpoints skipped (catchall) : {len(catchall_skipped)}\n",
                    C_DIM,
                ),
                (
                    f"     Endpoints tested (clean)     : {len(methods_out)}\n",
                    C_DIM,
                ),
                (
                    f"     WebDAV          : {'207 seen' if webdav_hit else 'not detected'}\n",
                    C_DIM,
                ),
                (
                    f"     CORS            : {cors.get('type') or 'no obvious misconfig'}\n",
                    C_DIM,
                ),
                (f"     Sec headers     : {miss_n} missing · {exp_n} exposed\n", C_DIM),
                (f"     Duration        : {duration:.1f}s", C_DIM),
            )
        )

    except Exception as e:  # noqa: BLE001
        base["status"] = "error"
        base["error"] = str(e)
        errors.append(str(e))
        console.print(Text(f"  [✗] {e}", style=C_ERR))

    return base
