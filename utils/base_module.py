"""
Common contract for GhostOpcode recon modules.

``ModuleResult`` + ``pack_session_result`` give ``main.py`` and reports a stable
shape while preserving legacy flat keys (``records``, ``ports``, …) via merge.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ModuleStatus(Enum):
    SUCCESS = "success"
    ERROR = "error"
    SKIPPED = "skipped"
    NOT_INSTALLED = "not_installed"


# Keys owned by the contract surface (merged last; not duplicated into ``data`` only)
_CONTRACT_SURFACE: frozenset[str] = frozenset(
    {
        "module",
        "target",
        "status",
        "duration_s",
        "critical_findings",
        "high_findings",
        "medium_findings",
        "low_findings",
        "errors",
        "warnings",
        "data",
        "total_findings",
        "has_critical",
        "_ghostopcode_module_contract_v1",
    }
)


@dataclass
class ModuleResult:
    """
    Standard result structure. Serialized dict is backward-compatible with
    existing Jinja/JSON consumers (legacy fields remain at top level).
    """

    module: str
    target: str
    status: str
    duration_s: float = 0.0
    critical_findings: list[dict[str, Any]] = field(default_factory=list)
    high_findings: list[dict[str, Any]] = field(default_factory=list)
    medium_findings: list[dict[str, Any]] = field(default_factory=list)
    low_findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Flatten: legacy ``data`` keys at root + contract fields win."""
        out: dict[str, Any] = dict(self.data)
        tf = (
            len(self.critical_findings)
            + len(self.high_findings)
            + len(self.medium_findings)
            + len(self.low_findings)
        )
        out.update(
            {
                "module": self.module,
                "target": self.target,
                "status": self.status,
                "duration_s": round(float(self.duration_s), 2),
                "critical_findings": list(self.critical_findings),
                "high_findings": list(self.high_findings),
                "medium_findings": list(self.medium_findings),
                "low_findings": list(self.low_findings),
                "errors": list(self.errors),
                "warnings": list(self.warnings),
                "data": dict(self.data),
                "total_findings": tf,
                "has_critical": len(self.critical_findings) > 0,
                "_ghostopcode_module_contract_v1": True,
            }
        )
        return out

    @property
    def is_success(self) -> bool:
        return self.status == ModuleStatus.SUCCESS.value

    @property
    def is_skipped(self) -> bool:
        return self.status == ModuleStatus.SKIPPED.value


def make_finding(
    value: str,
    category: str,
    risk: str,
    note: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalized finding row for tier lists and future correlation."""
    row: dict[str, Any] = {
        "value": value,
        "category": category,
        "risk": str(risk or "LOW").upper(),
        "note": note or "",
    }
    if metadata:
        for k, v in metadata.items():
            if k not in row:
                row[k] = v
    return row


class ModuleTimer:
    """Wall time for module execution."""

    def __init__(self) -> None:
        self.elapsed = 0.0
        self._start: float | None = None

    def __enter__(self) -> ModuleTimer:
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args: Any) -> None:
        if self._start is not None:
            self.elapsed = time.perf_counter() - self._start


def _ensure_str_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, str):
        return [val] if val.strip() else []
    if isinstance(val, list):
        return [str(x) for x in val if x is not None]
    return [str(val)]


def _finding_value_from_obj(obj: dict[str, Any]) -> str:
    for key in ("value", "url", "path", "fqdn", "cve_id"):
        v = obj.get(key)
        if v is not None and str(v).strip():
            return str(v).strip()
    p = obj.get("port")
    if p is not None:
        svc = str(obj.get("service") or "").strip()
        return f"{p}/tcp{f' {svc}' if svc else ''}".strip()
    return str(obj.get("category") or obj.get("type") or "finding")


def _append_tier(
    buckets: dict[str, list[dict[str, Any]]],
    obj: dict[str, Any],
) -> None:
    risk = str(obj.get("risk") or "LOW").upper()
    if risk not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        risk = "LOW"
    cat = str(obj.get("category") or obj.get("type") or "finding")
    note = str(obj.get("note") or obj.get("description") or "")
    val = _finding_value_from_obj(obj)
    meta = {k: v for k, v in obj.items() if k not in ("risk", "category", "type", "note", "description", "value")}
    fd = make_finding(val, cat, risk, note, metadata=meta)
    if risk == "CRITICAL":
        buckets["CRITICAL"].append(fd)
    elif risk == "HIGH":
        buckets["HIGH"].append(fd)
    elif risk == "MEDIUM":
        buckets["MEDIUM"].append(fd)
    else:
        buckets["LOW"].append(fd)


def derive_finding_tiers(base: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """
    Collect CRITICAL/HIGH/MEDIUM/LOW lists from common legacy list shapes.
    Does not remove or alter existing module payloads.
    """
    buckets: dict[str, list[dict[str, Any]]] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
    }
    seen: set[tuple[str, str, str]] = set()

    def add_obj(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        obj = dict(obj)
        # cve_lookup grouped rows: { software, cves[], total_cves, ... } — use findings_flat instead
        if (
            isinstance(obj.get("cves"), list)
            and obj.get("cve_id") is None
            and ("total_cves" in obj or "highest_cvss" in obj)
        ):
            return
        r = obj.get("risk")
        if r is None or (isinstance(r, str) and not str(r).strip()):
            sev = obj.get("severity") or obj.get("cvss_severity")
            if sev is not None and str(sev).strip():
                obj["risk"] = sev
        key = (
            str(obj.get("risk") or ""),
            _finding_value_from_obj(obj),
            str(obj.get("category") or ""),
        )
        if key in seen:
            return
        seen.add(key)
        _append_tier(buckets, obj)

    for tier_key in (
        "critical_findings",
        "high_findings",
        "medium_findings",
        "low_findings",
    ):
        for item in base.get(tier_key) or []:
            add_obj(item)

    for key in ("findings", "found", "ports", "hosts", "secrets", "endpoints"):
        for item in base.get(key) or []:
            add_obj(item)

    for leak in base.get("config_leaks") or []:
        if isinstance(leak, dict) and leak.get("confirmed"):
            add_obj(
                {
                    "risk": "CRITICAL",
                    "category": str(leak.get("signature_key") or "config_leak"),
                    "value": str(leak.get("url") or leak.get("path") or ""),
                    "note": "config leak",
                    **{
                        k: v
                        for k, v in leak.items()
                        if k not in ("risk", "category", "value", "note")
                    },
                }
            )

    flat = base.get("findings_flat")
    if isinstance(flat, list):
        for item in flat:
            add_obj(item)

    return buckets


def _duration_from_legacy(base: dict[str, Any], wall_s: float | None) -> float:
    if base.get("duration_s") is not None:
        try:
            return float(base["duration_s"])
        except (TypeError, ValueError):
            pass
    st = base.get("stats")
    if isinstance(st, dict) and st.get("duration_s") is not None:
        try:
            return float(st["duration_s"])
        except (TypeError, ValueError):
            pass
    if wall_s is not None:
        return float(wall_s)
    return 0.0


def pack_session_result(
    legacy: dict[str, Any],
    wall_duration_s: float | None = None,
) -> dict[str, Any]:
    """
    Normalize any module return dict to the common contract.

    - Preserves all legacy keys at the top level (for HTML/Jinja).
    - Adds ``critical_findings`` … ``low_findings``, ``total_findings``, ``has_critical``.
    - ``errors`` / ``warnings`` are always lists.
    - ``findings_flat`` (if present) is kept verbatim; ``derive_finding_tiers`` may
      dedupe rows when building tier lists — ``main.calculate_session_summary`` uses
      max(tier list, ``findings_flat`` counts) so SESSION COMPLETE matches module totals.
    """
    if legacy.get("_ghostopcode_module_contract_v1"):
        return legacy

    base = dict(legacy)
    mod = str(base.get("module") or "unknown")
    target = str(base.get("target") or "")
    status = str(base.get("status") or "success")

    errs = _ensure_str_list(base.get("errors"))
    if not errs and base.get("error"):
        errs = _ensure_str_list(base.get("error"))
    warns = _ensure_str_list(base.get("warnings"))

    buckets = derive_finding_tiers(base)
    dur = _duration_from_legacy(base, wall_duration_s)

    data = {k: v for k, v in base.items() if k not in _CONTRACT_SURFACE}

    mr = ModuleResult(
        module=mod,
        target=target,
        status=status,
        duration_s=dur,
        critical_findings=buckets["CRITICAL"],
        high_findings=buckets["HIGH"],
        medium_findings=buckets["MEDIUM"],
        low_findings=buckets["LOW"],
        errors=errs,
        warnings=warns,
        data=data,
    )
    return mr.to_dict()


def module_error_dict(module_key: str, target_value: str, message: str) -> dict[str, Any]:
    """Standard error payload when orchestration catches an exception."""
    return pack_session_result(
        {
            "module": module_key,
            "target": target_value,
            "status": ModuleStatus.ERROR.value,
            "errors": [message],
            "error": message,
        }
    )
