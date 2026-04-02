"""
Central HTTP session factory and TLS policy for GhostOpcode modules.

Default: verify TLS certificates. Set config["allow_insecure_tls"]=True only when
the operator explicitly accepts MITM risk (self-signed / internal targets).
"""

from __future__ import annotations

import urllib3
import requests
from requests.exceptions import SSLError
from typing import Any, Optional

from utils.target_parser import Target


def _cfg(config: dict[str, Any] | None) -> dict[str, Any]:
    return config if config is not None else {}


def requests_verify(config: dict[str, Any] | None) -> bool:
    """True → verify server TLS certificates (default)."""
    return not bool(_cfg(config).get("allow_insecure_tls", False))


def httpx_verify(config: dict[str, Any] | None) -> bool:
    """Same policy as :func:`requests_verify` for httpx clients."""
    return requests_verify(config)


def maybe_disable_insecure_warnings(config: dict[str, Any] | None) -> None:
    if _cfg(config).get("allow_insecure_tls"):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def make_session(
    config: dict[str, Any] | None = None,
    timeout: Optional[float] = None,
    user_agent: Optional[str] = None,
) -> requests.Session:
    """
    Build a ``requests.Session`` with GhostOpcode TLS policy and default headers.

    ``timeout`` is reserved for future defaults; per-request timeout is still
    passed to ``get``/``request``.
    """
    _ = timeout
    from config import DEFAULT_USER_AGENT

    cfg = _cfg(config)
    maybe_disable_insecure_warnings(cfg)
    try:
        session = requests.Session()
        session.verify = requests_verify(cfg)
        ua = user_agent or cfg.get("user_agent") or DEFAULT_USER_AGENT
        session.headers.update(
            {
                "User-Agent": ua,
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                ),
                "Accept-Language": "en-US,en;q=0.5",
            }
        )
        return session
    except Exception:
        fallback = requests.Session()
        fallback.verify = True
        return fallback


def report_ssl_certificate_problem(
    url: str,
    config: dict[str, Any] | None,
    *,
    ssl_warnings: list[str] | None = None,
) -> None:
    msg = (
        f"SSL certificate error for {url} — "
        "try selecting TLS=Relaxed in menu for self-signed certs"
    )
    if ssl_warnings is not None:
        ssl_warnings.append(msg)
    if _cfg(config).get("quiet"):
        return
    try:
        from rich.console import Console
        from rich.text import Text

        con = Console(highlight=False, force_terminal=True)
        con.print(Text(f" [!] SSL error: {url}", style="yellow"))
        con.print(
            Text(
                "     Tip: select TLS=Relaxed for self-signed certificates",
                style="dim",
            )
        )
    except Exception:
        print(f"[!] SSL error: {url}")
        print("     Tip: select TLS=Relaxed for self-signed certificates")


def session_request(
    session: requests.Session,
    method: str,
    url: str,
    config: dict[str, Any] | None,
    *,
    ssl_warnings: list[str] | None = None,
    **kwargs: Any,
) -> requests.Response | None:
    try:
        return session.request(method, url, **kwargs)
    except SSLError:
        report_ssl_certificate_problem(url, config, ssl_warnings=ssl_warnings)
        return None


def session_get(
    session: requests.Session,
    url: str,
    config: dict[str, Any] | None,
    *,
    ssl_warnings: list[str] | None = None,
    **kwargs: Any,
) -> requests.Response | None:
    return session_request(
        session, "GET", url, config, ssl_warnings=ssl_warnings, **kwargs
    )


def session_head(
    session: requests.Session,
    url: str,
    config: dict[str, Any] | None,
    *,
    ssl_warnings: list[str] | None = None,
    **kwargs: Any,
) -> requests.Response | None:
    return session_request(
        session, "HEAD", url, config, ssl_warnings=ssl_warnings, **kwargs
    )


def get(
    url: str,
    config: dict[str, Any] | None = None,
    timeout: int | float | None = None,
    *,
    ssl_warnings: list[str] | None = None,
    **kwargs: Any,
) -> requests.Response | None:
    """One-off GET with a fresh session (thread-safe for worker pools)."""
    from config import DEFAULT_TIMEOUT

    cfg = _cfg(config)
    session = make_session(cfg)
    to = timeout if timeout is not None else int(cfg.get("timeout", DEFAULT_TIMEOUT))
    kwargs.setdefault("timeout", to)
    return session_get(session, url, cfg, ssl_warnings=ssl_warnings, **kwargs)


def head(
    url: str,
    config: dict[str, Any] | None = None,
    timeout: int | float | None = None,
    *,
    ssl_warnings: list[str] | None = None,
    **kwargs: Any,
) -> requests.Response | None:
    from config import DEFAULT_TIMEOUT

    cfg = _cfg(config)
    session = make_session(cfg)
    to = timeout if timeout is not None else int(cfg.get("timeout", DEFAULT_TIMEOUT))
    kwargs.setdefault("timeout", to)
    return session_head(session, url, cfg, ssl_warnings=ssl_warnings, **kwargs)


def resolve_base_url(
    target: Target,
    timeout: float,
    config: dict[str, Any],
    *,
    ssl_warnings: list[str] | None = None,
    user_agent: str | None = None,
) -> str | None:
    """Try HTTPS then HTTP root; return canonical origin without path."""
    from urllib.parse import urlparse

    session = make_session(config, user_agent=user_agent)
    host = target.value
    for scheme in ("https", "http"):
        base = f"{scheme}://{host}".rstrip("/")
        root = base + "/"
        r = session_get(
            session,
            root,
            config,
            timeout=timeout,
            allow_redirects=True,
            ssl_warnings=ssl_warnings,
        )
        if r is not None and 0 < r.status_code < 600:
            u = urlparse(r.url)
            return (
                u._replace(path="", params="", query="", fragment="")
                .geturl()
                .rstrip("/")
            )
    return None
