"""
ARP discovery on a local CIDR — vendors, hostnames, risk categories.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import time
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from utils.target_parser import Target

console = Console(highlight=False, force_terminal=True)

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_ACCENT = "#8B9CA8"

OUI_DATABASE: dict[str, str] = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1a:11": "Google",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "00:1b:21": "Intel",
    "00:23:14": "Intel",
    "8c:8d:28": "Intel",
    "00:50:b6": "Good Way Technology",
    "00:e0:4c": "Realtek",
    "00:1a:4b": "Huawei",
    "4c:5e:0c": "Huawei",
    "00:0f:e2": "Huawei",
    "00:25:9c": "Cisco",
    "00:1e:7a": "Cisco",
    "f8:72:ea": "Cisco",
    "00:1c:57": "Cisco",
    "00:26:cb": "Cisco",
    "00:1b:2b": "Cisco",
    "00:60:2f": "Cisco",
    "00:d0:ba": "Cisco",
    "00:17:5a": "Cisco",
    "3c:ce:73": "Apple",
    "a4:d1:8c": "Apple",
    "00:03:93": "Apple",
    "00:1b:63": "Apple",
    "f0:18:98": "Apple",
    "b8:e8:56": "Dell",
    "00:14:22": "Dell",
    "14:18:77": "Dell",
    "00:25:64": "Dell",
    "d4:be:d9": "Dell",
    "f8:db:88": "Dell",
    "00:1a:a0": "Dell",
    "3c:d9:2b": "HP",
    "00:17:a4": "HP",
    "00:1b:78": "HP",
    "10:60:4b": "HP",
    "9c:8e:99": "HP",
    "00:26:55": "HP",
    "00:1f:29": "HP",
    "fc:3f:db": "Microsoft",
    "28:18:78": "Microsoft",
    "00:15:5d": "Microsoft (Hyper-V)",
    "00:03:ff": "Microsoft",
    "00:12:5a": "Fortinet",
    "00:09:0f": "Fortinet",
}

DEVICE_CATEGORIES: dict[str, dict[str, Any]] = {
    "router_gateway": {
        "vendors": ["Cisco", "Fortinet", "Huawei", "MikroTik"],
        "hostnames": ["router", "gateway", "gw", "fw", "firewall"],
        "ports": [22, 23, 80, 443, 161],
        "risk": "CRITICAL",
        "note": "Network gateway — high value target",
    },
    "server": {
        "vendors": ["Dell", "HP", "IBM", "Supermicro"],
        "hostnames": ["srv", "server", "dc", "ad", "exchange"],
        "ports": [22, 80, 443, 3389, 445],
        "risk": "HIGH",
        "note": None,
    },
    "workstation": {
        "vendors": ["Intel", "Realtek"],
        "hostnames": ["pc", "desktop", "ws", "workstation"],
        "ports": [3389, 445, 139],
        "risk": "MEDIUM",
        "note": None,
    },
    "virtual_machine": {
        "vendors": ["VMware", "Microsoft (Hyper-V)", "Microsoft"],
        "hostnames": [],
        "ports": [],
        "risk": "MEDIUM",
        "note": "Virtual machine detected",
    },
    "iot_device": {
        "vendors": ["Raspberry Pi"],
        "hostnames": ["cam", "printer", "phone", "iot"],
        "ports": [80, 8080, 554],
        "risk": "HIGH",
        "note": "IoT class device — often poorly secured",
    },
    "apple_device": {
        "vendors": ["Apple"],
        "hostnames": ["macbook", "iphone", "ipad", "imac"],
        "ports": [22, 548, 5009],
        "risk": "LOW",
        "note": None,
    },
}


def _is_root() -> bool:
    """True if effective UID is 0 (POSIX)."""
    ge = getattr(os, "geteuid", None)
    if callable(ge):
        try:
            return ge() == 0
        except OSError:
            return False
    return False


def get_vendor(mac: str) -> str:
    """Lookup OUI in local database. Returns 'Unknown' if not found."""
    norm = mac.upper().replace("-", ":")
    parts = norm.split(":")
    if len(parts) < 3:
        return "Unknown"
    oui = ":".join(parts[:3])
    return OUI_DATABASE.get(oui, "Unknown")


def resolve_hostname(ip: str, timeout: float) -> str | None:
    """
    Attempt reverse DNS lookup for discovered host.
    Returns hostname or None — never raises.
    """
    _ = timeout  # socket.gethostbyaddr has no timeout in stdlib
    try:
        socket.setdefaulttimeout(min(3.0, max(0.5, timeout)))
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            socket.setdefaulttimeout(None)
        except OSError:
            pass


def categorize_device(
    ip: str,
    mac: str,
    vendor: str,
    hostname: str | None,
    open_ports: list[int],
) -> dict[str, Any]:
    """
    Categorize device type based on vendor, hostname patterns,
    and open ports (if port scan data available).
    """
    _ = mac
    hn = (hostname or "").lower()
    best: dict[str, Any] = {
        "category": "unknown",
        "risk": "LOW",
        "note": "No strong fingerprint",
    }
    best_score = 0
    for cat_name, spec in DEVICE_CATEGORIES.items():
        score = 0
        vendors = spec.get("vendors") or []
        if any(v in vendor for v in vendors):
            score += 3
        hnames = spec.get("hostnames") or []
        if hnames and any(h in hn for h in hnames):
            score += 2
        ports = spec.get("ports") or []
        if ports and open_ports and any(p in open_ports for p in ports):
            score += 2
        if score > best_score:
            best_score = score
            best = {
                "category": cat_name,
                "risk": spec.get("risk", "MEDIUM"),
                "note": spec.get("note"),
            }
    if best_score == 0 and vendor == "Unknown":
        best["note"] = "Unknown vendor — possible IoT or embedded"
        best["risk"] = "MEDIUM"
    return best


def scan_range(cidr: str, timeout: int) -> list[dict[str, str]]:
    """
    Send ARP requests to all IPs in CIDR range.
    Collect responses with IP and MAC address.
    """
    from scapy.all import ARP, Ether, srp  # noqa: PLC0415

    arp_request = ARP(pdst=cidr)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(
        packet,
        timeout=timeout,
        verbose=False,
        retry=1,
    )

    hosts: list[dict[str, str]] = []
    for _sent, received in answered:
        hosts.append(
            {
                "ip": received.psrc,
                "mac": received.hwsrc,
            }
        )
    return hosts


def _range_host_count(cidr: str) -> int:
    """Approximate number of addresses in CIDR (IPv4 hosts() when applicable)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return 0
    if net.version == 4:
        try:
            return sum(1 for _ in net.hosts())
        except ValueError:
            return int(net.num_addresses)
    return int(net.num_addresses)


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    ARP scan a CIDR range to discover live hosts.
    Uses Scapy to send ARP requests and collect replies.
    Requires root/sudo.
    """
    t0 = time.perf_counter()
    errors: list[str] = []
    timeout = int(config.get("timeout") or 5)
    timeout = max(1, min(timeout, 120))

    base: dict[str, Any] = {
        "module": "arp_scan",
        "target": target.value,
        "status": "pending",
        "network": target.value,
        "hosts": [],
        "stats": {
            "range_size": 0,
            "hosts_found": 0,
            "duration_s": 0.0,
        },
        "errors": errors,
        "findings": [],
    }

    if target.is_domain():
        base["status"] = "skipped"
        console.print(
            Panel(
                Text("  ARP SCAN  ·  domain target not supported", style=f"bold {C_PRI}"),
                border_style=C_ACCENT,
                box=box.DOUBLE,
            )
        )
        console.print(Text("  [SKIP] Use a CIDR (e.g. 192.168.1.0/24).", style=C_WARN))
        return base

    if not target.is_cidr():
        base["status"] = "skipped"
        console.print(
            Panel(
                Text("  ARP SCAN  ·  CIDR required", style=f"bold {C_PRI}"),
                border_style=C_ACCENT,
                box=box.DOUBLE,
            )
        )
        console.print(
            Text("  [SKIP] ARP scan needs a network range, not a single IP.", style=C_WARN)
        )
        return base

    cidr = target.value.strip()

    if not _is_root():
        base["status"] = "error"
        base["error"] = "Root required — run with sudo"
        errors.append(base["error"])
        console.print(Text(f"  [✗] {base['error']}", style=C_ERR))
        return base

    try:
        import scapy  # noqa: F401, PLC0415
    except ImportError:
        base["status"] = "error"
        base["error"] = "scapy not installed — pip install scapy"
        errors.append(base["error"])
        console.print(Text(f"  [✗] {base['error']}", style=C_ERR))
        return base

    range_size = _range_host_count(cidr)
    base["stats"]["range_size"] = range_size

    console.print(
        Panel(
            Text(
                f"  ARP SCAN  ·  {cidr}  ·  ~{range_size} addresses",
                style=f"bold {C_PRI}",
            ),
            border_style=C_ACCENT,
            box=box.DOUBLE,
            width=min(console.size.width, 82) if console.size else 82,
        )
    )
    console.print(
        Text("  [i] Requires root — sending ARP requests…", style=C_MUTED),
    )

    try:
        raw_hosts = scan_range(cidr, timeout)
    except Exception as e:  # noqa: BLE001
        errors.append(str(e))
        base["status"] = "error"
        base["error"] = str(e)
        console.print(Text(f"  [✗] ARP scan failed: {e}", style=C_ERR))
        return base

    rows_out: list[dict[str, Any]] = []
    for h in sorted(raw_hosts, key=lambda x: ipaddress.ip_address(x["ip"]).packed):
        ip = h["ip"]
        mac = h["mac"]
        vendor = get_vendor(mac)
        hostname = resolve_hostname(ip, float(timeout))
        cat = categorize_device(ip, mac, vendor, hostname, [])
        row = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "category": cat["category"],
            "risk": cat["risk"],
            "note": cat.get("note"),
        }
        rows_out.append(row)
        rk = cat["risk"]
        rstyle = C_ERR if rk == "CRITICAL" else C_WARN if rk == "HIGH" else C_DIM
        hn = hostname or "—"
        console.print(
            Text.assemble(
                ("  [+] ", C_PRI),
                (f"{ip:<15} ", C_DIM),
                (f"{mac:<17} ", C_MUTED),
                (f"{vendor[:14]:<14} ", C_DIM),
                (f"{str(hn)[:18]:<18} ", C_MUTED),
                (f"[{rk}]", rstyle),
            )
        )

    base["hosts"] = rows_out
    base["stats"]["hosts_found"] = len(rows_out)
    base["stats"]["duration_s"] = round(time.perf_counter() - t0, 2)
    base["status"] = "success"
    base["findings"] = rows_out

    if rows_out:
        console.print()
        tbl = Table(
            title=Text("LIVE MAP", style=f"bold {C_WARN}"),
            box=box.ROUNDED,
            border_style=C_ACCENT,
        )
        tbl.add_column("IP", style=C_DIM)
        tbl.add_column("MAC", style=C_MUTED)
        tbl.add_column("Vendor", style=C_DIM)
        tbl.add_column("Hostname", style=C_MUTED)
        tbl.add_column("Risk", style=C_DIM)
        for r in rows_out:
            tbl.add_row(
                r["ip"],
                r["mac"],
                r["vendor"][:20],
                (r["hostname"] or "—")[:24],
                Text(str(r["risk"]), style=C_ERR if r["risk"] == "CRITICAL" else C_WARN),
            )
        console.print(tbl)

    crit = sum(1 for r in rows_out if r["risk"] == "CRITICAL")
    high = sum(1 for r in rows_out if r["risk"] == "HIGH")
    med = sum(1 for r in rows_out if r["risk"] == "MEDIUM")
    low = sum(1 for r in rows_out if r["risk"] == "LOW")

    console.print()
    console.print(Text(" [✓] ARP scan complete", style=f"bold {C_PRI}"))
    console.print(
        Text(
            f"     Range   : {cidr} (~{range_size} addresses)",
            style=C_DIM,
        )
    )
    console.print(
        Text(
            f"     Found   : {len(rows_out)} active host(s)",
            style=C_DIM,
        )
    )
    console.print(
        Text(
            f"     Critical: {crit}  ·  High: {high}  ·  Medium: {med}  ·  Low: {low}",
            style=C_MUTED,
        )
    )
    console.print(
        Text(
            f"     Duration: {base['stats']['duration_s']}s",
            style=C_MUTED,
        )
    )

    return base
