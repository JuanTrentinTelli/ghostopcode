"""
Cap total findings serialized into HTML/JSON reports (session RAM may still hold full data).
"""

from __future__ import annotations

import copy
from typing import Any

import config as app_config

_TIER_FIELDS = (
    "critical_findings",
    "high_findings",
    "medium_findings",
    "low_findings",
)


def truncate_report_results(results: dict[str, Any]) -> dict[str, Any]:
    """
    Deep-copy module results and trim * findings lists to MAX_REPORT_FINDINGS total,
    in stable iteration order. Does not mutate the input.
    MAX_REPORT_FINDINGS <= 0 disables (returns a shallow copy of the dict shell only —
    caller should pass a copy of ``results`` if needed; json/html pass deepcopied session).
    """
    max_total = int(getattr(app_config, "MAX_REPORT_FINDINGS", 0) or 0)
    if max_total <= 0:
        return results

    out = copy.deepcopy(results)
    total = 0
    for _mod_name, module_result in out.items():
        if not isinstance(module_result, dict):
            continue
        for field in _TIER_FIELDS:
            findings = module_result.get(field, [])
            if not isinstance(findings, list):
                continue
            remaining = max(0, max_total - total)
            if len(findings) > remaining:
                module_result[field] = findings[:remaining]
                ws = module_result.get("warnings")
                if not isinstance(ws, list):
                    ws = []
                    module_result["warnings"] = ws
                ws.append(
                    f"{field} truncated to {remaining} items in report "
                    "(MAX_REPORT_FINDINGS in config.py)"
                )
            total += len(module_result.get(field, []))
    return out
