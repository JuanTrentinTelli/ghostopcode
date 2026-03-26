"""
Serialize full session dict to indented JSON with safe type coercion.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

import config as app_config


def _default_handler(obj: Any) -> Any:
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if hasattr(obj, "tolist") and callable(obj.tolist):
        try:
            return obj.tolist()
        except Exception:  # noqa: BLE001
            pass
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
    return str(obj)


def generate(session: dict[str, Any], output_dir: str | Path) -> str:
    """
    Write report.json under output_dir.
    Returns absolute path to the file.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    output_path = out / "report.json"

    report = {
        "ghostopcode": {
            "version": getattr(app_config, "VERSION", "1.5.0"),
            "generated": datetime.now().isoformat(timespec="seconds"),
            "report_type": "recon_session",
        },
        **session,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=_default_handler)

    return str(output_path.resolve())
