"""
Group subdomains by resolved IP, enrich with ASN/provider (session cache), terminal table.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from utils.asn_lookup import lookup_many

_RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _row_ip(sub: dict[str, Any]) -> str | None:
    v = sub.get("ip")
    if v is not None and str(v).strip():
        return str(v).strip()
    ips = sub.get("ips")
    if isinstance(ips, list):
        for x in ips:
            if x is not None and str(x).strip():
                return str(x).strip()
    return None


def build_ip_map(subdomains: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Map IP → list of subdomain row dicts (``unresolved`` bucket if no IP)."""
    m: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sub in subdomains:
        ip = _row_ip(sub)
        key = ip if ip else "unresolved"
        m[key].append(sub)
    return dict(m)


def aggregate_ip_risk(subs: list[dict[str, Any]]) -> str:
    if not subs:
        return "LOW"
    highest = "LOW"
    for sub in subs:
        risk = str(sub.get("risk") or "LOW").upper()
        if risk not in _RISK_ORDER:
            risk = "LOW"
        if _RISK_ORDER.index(risk) < _RISK_ORDER.index(highest):
            highest = risk
    return highest


def _short_label(sub: dict[str, Any], domain: str | None) -> str:
    fq = str(sub.get("fqdn") or "").strip().lower()
    dom = (domain or "").strip().lower().strip(".")
    if dom and fq.endswith("." + dom):
        stem = fq[: -(len(dom) + 1)]
        return stem if stem else fq
    sub_only = str(sub.get("subdomain") or "").strip()
    if sub_only:
        return sub_only
    if fq:
        parts = fq.split(".")
        return parts[0] if len(parts) > 1 else fq
    return ""


def _serialize_ip_grouping(
    ip_map: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for ip, subs in ip_map.items():
        if ip == "unresolved":
            continue
        out[ip] = [
            {
                "subdomain": str(s.get("fqdn") or s.get("subdomain") or ""),
                "risk": str(s.get("risk") or "LOW"),
                "category": str(s.get("category") or ""),
            }
            for s in subs
        ]
    return out


def compute_top_ip(ip_map: dict[str, list[dict[str, Any]]]) -> str | None:
    best_k: str | None = None
    best_n = -1
    for ip, subs in ip_map.items():
        if ip == "unresolved":
            continue
        n = len(subs)
        if n > best_n:
            best_n = n
            best_k = ip
    return best_k


def display_ip_grouping(
    ip_map: dict[str, list[dict[str, Any]]],
    config: dict[str, Any],
    console: Console,
    *,
    domain: str | None = None,
    timeout: int = 3,
    provider_by_ip: dict[str, str] | None = None,
    title_style: str = "bold #00FF41",
    dim_style: str = "#6F7F86",
) -> None:
    grouped = {
        ip: subs
        for ip, subs in ip_map.items()
        if ip != "unresolved" and len(subs) >= 2
    }
    if not grouped:
        return

    sorted_ips = sorted(
        grouped.items(),
        key=lambda x: len(x[1]),
        reverse=True,
    )[:10]

    display_ips = [ip for ip, _ in sorted_ips]
    if provider_by_ip is None:
        provider_by_ip = lookup_many(
            display_ips,
            timeout=max(2, int(timeout)),
            workers=5,
        )
    else:
        # Ensure displayed rows have entries (cache may already hold them).
        missing = [ip for ip in display_ips if ip not in provider_by_ip]
        if missing:
            extra = lookup_many(
                missing,
                timeout=max(2, int(timeout)),
                workers=5,
            )
            provider_by_ip = {**provider_by_ip, **extra}

    if config.get("debug"):
        from utils.asn_lookup import cache_stats as asn_cache_stats

        st = asn_cache_stats()
        console.print(
            Text(
                f"     [DEBUG] ASN cache: {st['known']} known · "
                f"{st['unknown']} unknown · {st['total']} total",
                style=dim_style,
            )
        )

    console.print()
    console.print(Text(" [IP GROUPING] Infrastructure map", style=title_style))

    table = Table(box=box.SIMPLE_HEAD, show_header=True)
    table.add_column("IP", style="cyan", width=18, no_wrap=True)
    table.add_column("Provider", style=dim_style, width=18, no_wrap=True)
    table.add_column("Svcs", justify="right", width=5)
    table.add_column("Subdomains", width=44, overflow="ellipsis")
    table.add_column("Risk", justify="center", width=10)

    risk_style = {
        "CRITICAL": "red",
        "HIGH": "yellow",
        "MEDIUM": "blue",
        "LOW": "dim",
        "INFO": "dim",
    }

    for ip, subs in sorted_ips:
        raw_prov = provider_by_ip.get(ip, "unknown")
        prov_cell = raw_prov if raw_prov not in ("unknown", "") else "—"
        risk = aggregate_ip_risk(subs)

        sub_names = [_short_label(s, domain) for s in subs]
        sub_names = [n for n in sub_names if n]
        if not sub_names:
            subs_cell: str | Text = "—"
        elif len(sub_names) <= 4:
            subs_cell = " · ".join(sub_names)
        else:
            subs_cell = Text.assemble(
                (" · ".join(sub_names[:4]) + " ", ""),
                (f"+ {len(sub_names) - 4} more", dim_style),
            )

        table.add_row(
            ip,
            prov_cell,
            str(len(subs)),
            subs_cell,
            Text(risk, style=risk_style.get(risk, "dim")),
        )

    console.print(table)

    top_ip, top_subs = sorted_ips[0]
    top_p = provider_by_ip.get(top_ip, "unknown")
    prov_str = f"({top_p}) " if top_p not in ("unknown", "", "private") else ""

    console.print()
    console.print(
        Text.assemble(
            ("\n [INTEL] Highest concentration: ", title_style),
            (top_ip, "cyan"),
            (" ", ""),
            (f"{prov_str}→ {len(top_subs)} services\n", dim_style),
            ("         ", ""),
            (
                "Consider targeting this IP for virtual host discovery",
                dim_style,
            ),
        )
    )


def build_ip_grouping_report_rows(
    ip_map: dict[str, list[dict[str, Any]]],
    prov_map: dict[str, str],
    domain: str | None,
) -> list[dict[str, Any]]:
    """
    Pre-computed rows for HTML report (IPs with 2+ hostnames), sorted by service count.
    """
    grouped = {
        ip: subs
        for ip, subs in ip_map.items()
        if ip != "unresolved" and len(subs) >= 2
    }
    if not grouped:
        return []

    rows_out: list[dict[str, Any]] = []
    dom = domain.strip().lower() if domain else None
    for ip, subs in sorted(grouped.items(), key=lambda x: len(x[1]), reverse=True):
        labels = [_short_label(s, dom) for s in subs]
        labels = [x for x in labels if x]
        if len(labels) <= 6:
            disp = " · ".join(labels) if labels else "—"
        else:
            disp = " · ".join(labels[:6]) + f" (+{len(labels) - 6} mais)"
        raw_p = prov_map.get(ip, "unknown")
        prov = raw_p if raw_p not in ("unknown", "", "private") else "—"
        rows_out.append(
            {
                "ip": ip,
                "provider": prov,
                "services": len(subs),
                "subdomains_display": disp,
                "risk": aggregate_ip_risk(subs),
            }
        )
    return rows_out


def apply_subdomain_ip_intel(
    base: dict[str, Any],
    rows: list[dict[str, Any]],
    domain: str,
    config: dict[str, Any],
    console: Console,
) -> None:
    """
    Set ``ip_grouping``, ``top_ip``, ``providers``, ``stats.ip_multi_service``;
    print infrastructure table when applicable.
    """
    if not rows:
        return

    ip_map = build_ip_map(rows)
    base["ip_grouping"] = _serialize_ip_grouping(ip_map)
    base["top_ip"] = compute_top_ip(ip_map)

    resolved = [ip for ip in ip_map if ip != "unresolved"]
    to = int(config.get("timeout") or 5)
    to = max(2, min(to, 10))
    prov_map = lookup_many(resolved, timeout=to, workers=5) if resolved else {}

    base["providers"] = sorted(
        {
            p
            for p in prov_map.values()
            if p and p not in ("unknown", "private")
        }
    )

    base["ip_providers"] = {
        ip: prov_map.get(ip, "unknown") for ip in base["ip_grouping"].keys()
    }
    base["ip_grouping_rows"] = build_ip_grouping_report_rows(
        ip_map,
        prov_map,
        domain.strip().lower() if domain else None,
    )

    n_multi = sum(
        1
        for ip, subs in ip_map.items()
        if ip != "unresolved" and len(subs) >= 2
    )
    st = base.setdefault("stats", {})
    if isinstance(st, dict):
        st["ip_multi_service"] = n_multi

    display_ip_grouping(
        ip_map,
        config,
        console,
        domain=domain.strip().lower() if domain else None,
        timeout=to,
        provider_by_ip=prov_map,
    )
