"""
Redact sensitive values before persisting to report.json, report.html, session.log.
Terminal / in-memory session state must remain unchanged (use deepcopy at call sites).
"""

from __future__ import annotations

import re
from typing import Any, Callable

# ── Padrões de dados sensíveis ─────────────────────────────────────────────

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pass",
    "pwd",
    "senha",
    "secret",
    "segredo",
    "token",
    "api_key",
    "apikey",
    "api_token",
    "access_token",
    "refresh_token",
    "auth_token",
    "bearer",
    "authorization",
    "db_password",
    "database_password",
    "db_pass",
    "mysql_password",
    "postgres_password",
    "redis_password",
    "mongo_password",
    "aws_secret",
    "aws_secret_access_key",
    "azure_client_secret",
    "gcp_key",
    "firebase_key",
    "firebase_token",
    "private_key",
    "private_token",
    "secret_key",
    "signing_key",
    "encryption_key",
    "nvd_api_key",
    "shodan_api_key",
    "censys_secret",
    "slack_token",
    "github_token",
    "gitlab_token",
    "plaintext",
    "cracked_password",
    "password_plain",
}

# Objetos como os de extract_secrets (harvester): type + value
_TYPED_SECRET_TYPES = frozenset(
    {
        "database_password",
        "api_key",
        "aws_key",
        "jwt_secret",
        "private_key",
    }
)


def _is_typed_secret_entry(data: dict[Any, Any]) -> bool:
    t = data.get("type")
    if not isinstance(t, str):
        return False
    tl = _norm_key(t)
    return tl in _TYPED_SECRET_TYPES


NON_SENSITIVE_FIELDS = {
    "module",
    "target",
    "status",
    "risk",
    "category",
    "source",
    "service",
    "protocol",
    "method",
    "type",
    "fqdn",
    "hostname",
    "ip",
    "port",
    "domain",
    "cve_id",
    "cvss_score",
    "published",
    "nvd_url",
    "duration_s",
    "timestamp",
    "version",
}

def _norm_key(key: str) -> str:
    return str(key).lower().replace("-", "_").replace(" ", "_")


def mask_value(value: Any, visible_chars: int = 4) -> Any:
    """
    Mask a sensitive string value; keeps first `visible_chars` visible.
    None / empty string are returned unchanged (no false redaction).
    """
    if value is None:
        return value
    if not isinstance(value, str):
        return "****"
    if len(value) == 0:
        return value
    if len(value) <= visible_chars:
        return "****"
    return value[:visible_chars] + "****"


def _sub_url_segment_cred(m: re.Match[str]) -> str:
    return m.group(1) + mask_value(m.group(2))


def _sub_query_cred(m: re.Match[str]) -> str:
    return m.group(1) + mask_value(m.group(2))


def _sub_long_path_token(m: re.Match[str]) -> str:
    return "/" + mask_value(m.group(1))


def _sub_kv_cred(m: re.Match[str]) -> str:
    return m.group(1) + mask_value(m.group(2))


def _sub_hex_hash(m: re.Match[str]) -> str:
    return mask_value(m.group(1))


# (pattern, replacer) — replacers must return the full replacement span
_REDACT_PATTERN_SUBS: list[tuple[re.Pattern[str], Callable[[re.Match[str]], str]]] = [
    (
        re.compile(
            r"(/(?:senha|password|pass|token|key)/)([^/\?&]{4,})",
            re.IGNORECASE,
        ),
        _sub_url_segment_cred,
    ),
    (
        re.compile(
            r"([?&](?:password|passwd|pass|token|key|secret|api_key)=)([^&]{4,})",
            re.IGNORECASE,
        ),
        _sub_query_cred,
    ),
    (
        re.compile(r"/([A-Za-z0-9]{20,})(?=/|$)"),
        _sub_long_path_token,
    ),
    (
        re.compile(
            r"((?:password|passwd|token|key|secret)\s*[=:]\s*)(\S{4,})",
            re.IGNORECASE,
        ),
        _sub_kv_cred,
    ),
    (
        re.compile(
            r"((?:^|[\n;])(?:[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY|AUTH|PASS)"
            r"[A-Z0-9_]*)\s*[=:]\s*)(\S{4,})",
            re.MULTILINE | re.IGNORECASE,
        ),
        _sub_kv_cred,
    ),
    (
        re.compile(r"\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b"),
        _sub_hex_hash,
    ),
]


def redact_string(text: str) -> str:
    """Scan a string for sensitive patterns and mask matches."""
    if not isinstance(text, str):
        return text
    result = text
    for pattern, repl in _REDACT_PATTERN_SUBS:
        try:
            result = pattern.sub(repl, result)
        except re.error:
            continue
    return result


def redact_dict(
    data: Any,
    depth: int = 0,
    *,
    skip_string_scan: bool = False,
) -> Any:
    """
    Recursively redact sensitive values in dict/list structures (max depth 20).
    Keys in NON_SENSITIVE_FIELDS skip pattern-based string redaction in their subtree.
    """
    if depth > 20:
        return data

    if isinstance(data, dict):
        out: dict[Any, Any] = {}
        for key, value in data.items():
            key_lower = _norm_key(key)
            if (
                key_lower == "value"
                and isinstance(value, str)
                and _is_typed_secret_entry(data)
            ):
                out[key] = mask_value(value)
            elif key_lower in SENSITIVE_KEYS:
                if value is None:
                    out[key] = value
                elif isinstance(value, str):
                    out[key] = mask_value(value)
                elif isinstance(value, list):
                    masked_list: list[Any] = []
                    for v in value:
                        if v is None:
                            masked_list.append(None)
                        elif isinstance(v, str):
                            masked_list.append(mask_value(v) if v else v)
                        else:
                            masked_list.append("****")
                    out[key] = masked_list
                else:
                    out[key] = "****"
            elif key_lower in NON_SENSITIVE_FIELDS:
                out[key] = redact_dict(value, depth + 1, skip_string_scan=True)
            else:
                out[key] = redact_dict(value, depth + 1, skip_string_scan=skip_string_scan)
        return out

    if isinstance(data, list):
        return [
            redact_dict(item, depth + 1, skip_string_scan=skip_string_scan)
            for item in data
        ]

    if isinstance(data, str):
        if skip_string_scan:
            return data
        return redact_string(data)

    return data


def redact_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Redact one finding dict (e.g. URL paths, notes, metadata)."""
    result = dict(finding)
    if "value" in result and isinstance(result["value"], str):
        result["value"] = redact_string(result["value"])
    if "note" in result and isinstance(result["note"], str):
        result["note"] = redact_string(result["note"])
    if "metadata" in result and isinstance(result["metadata"], dict):
        result["metadata"] = redact_dict(result["metadata"])
    return result
