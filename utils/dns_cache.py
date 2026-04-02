"""
Session-scoped DNS cache (in-memory only): hostname → IPv4 via ``socket.gethostbyname``.

Cleared at each GhostOpcode interactive session start (``main``). Thread-safe.
MX/NS/TXT and other record types are not cached here — only forward name resolution.
"""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

_DNS_CACHE: dict[str, str | None] = {}
_DNS_LOCK = threading.Lock()


def resolve(
    fqdn: str,
    timeout: int = 3,
    config: Optional[dict[str, Any]] = None,
) -> str | None:
    """
    Resolve FQDN to one IPv4 (system resolver). Thread-safe.
    Caches ``None`` for failures. Empty host → ``None`` (not cached).
    """
    key = (fqdn or "").strip().lower()
    if not key:
        return None

    with _DNS_LOCK:
        if key in _DNS_CACHE:
            val = _DNS_CACHE[key]
            if config and config.get("debug"):
                from utils.output import debug_log

                debug_log(
                    "info",
                    detail=f"DNS resolve {fqdn} → cache hit: {val or '∅'}",
                    config=config,
                )
            return val

    old = socket.getdefaulttimeout()
    ip: str | None = None
    try:
        socket.setdefaulttimeout(float(timeout))
        ip = socket.gethostbyname(key)
    except OSError:
        ip = None
    finally:
        try:
            socket.setdefaulttimeout(old)
        except OSError:
            pass

    with _DNS_LOCK:
        if key not in _DNS_CACHE:
            _DNS_CACHE[key] = ip
        return _DNS_CACHE[key]


def resolve_many(
    fqdns: list[str],
    timeout: int = 3,
    workers: int = 50,
) -> dict[str, str | None]:
    """
    Resolve many FQDNs in parallel. Uses cache; only uncached names hit the resolver.
    Keys in the result dict match the original strings from ``fqdns``.
    """
    results: dict[str, str | None] = {}
    pending: list[str] = []
    with _DNS_LOCK:
        for raw in fqdns:
            key = (raw or "").strip().lower()
            if not key:
                results[raw] = None
                continue
            if key in _DNS_CACHE:
                results[raw] = _DNS_CACHE[key]
            else:
                pending.append(raw)

    if not pending:
        return results

    max_w = max(1, min(int(workers), len(pending)))
    with ThreadPoolExecutor(max_workers=max_w) as ex:
        futs = {ex.submit(resolve, h.strip(), int(timeout), None): h for h in pending}
        for fut in as_completed(futs):
            orig = futs[fut]
            try:
                results[orig] = fut.result()
            except Exception:  # noqa: BLE001
                results[orig] = None
    return results


def cache_stats() -> dict[str, int]:
    with _DNS_LOCK:
        total = len(_DNS_CACHE)
        resolved = sum(1 for v in _DNS_CACHE.values() if v is not None)
        failed = total - resolved
    return {"total": total, "resolved": resolved, "failed": failed}


def clear() -> None:
    with _DNS_LOCK:
        _DNS_CACHE.clear()
