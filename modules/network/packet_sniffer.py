"""
Passive capture — DNS, cleartext HTTP/FTP/telnet hints, ARP visibility.
"""

from __future__ import annotations

import ipaddress
import os
import time
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from utils.target_parser import Target

console = Console(highlight=False, force_terminal=True)

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_ACCENT = "#8B9CA8"

_MAX_RAW_PREVIEW = 120


def _pkt_warn(
    warnings: list[str] | None,
    once: set[str] | None,
    key: str,
    msg: str,
) -> None:
    if warnings is None or once is None:
        return
    if key in once:
        return
    once.add(key)
    warnings.append(msg)


def _is_root() -> bool:
    ge = getattr(os, "geteuid", None)
    if callable(ge):
        try:
            return ge() == 0
        except OSError:
            return False
    return False


def _mask_value(s: str, keep: int = 4) -> str:
    """Show first `keep` chars only — never print full secrets."""
    s = s.strip()
    if len(s) <= keep:
        return "****"
    return s[:keep] + "****"


def build_filter(target: Target) -> str:
    """
    Build BPF filter string for scapy sniff().
    Filter by target IP if provided, or capture subnet traffic.
    """
    if target.is_ip():
        return f"host {target.value.strip()}"
    if target.is_cidr():
        net = ipaddress.ip_network(target.value.strip(), strict=False)
        if net.version == 4:
            return f"net {net.network_address} mask {net.netmask}"
        # IPv6 — compact bpf varies by platform; use ip6 net if available
        return ""
    return ""


def analyze_packet(
    packet: Any,
    warnings: list[str] | None = None,
    warn_once: set[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Analyze a captured packet and extract intelligence events.
    Returns zero or more small dicts with type + display + finding keys.
    """
    from scapy.layers.dns import DNS  # noqa: PLC0415
    from scapy.layers.inet import IP, TCP  # noqa: PLC0415
    from scapy.layers.l2 import ARP  # noqa: PLC0415
    from scapy.packet import Raw  # noqa: PLC0415

    events: list[dict[str, Any]] = []

    if packet.haslayer(DNS):
        dns = packet[DNS]
        if int(dns.qr) == 0 and dns.qd is not None:
            try:
                qn = dns.qd.qname
                if isinstance(qn, bytes):
                    name = qn.decode("utf-8", errors="replace").rstrip(".")
                else:
                    name = str(qn).rstrip(".")
                if name:
                    events.append(
                        {
                            "type": "dns",
                            "display": f"[DNS]  {packet[IP].src if packet.haslayer(IP) else '?'} → {name}",
                            "dns_name": name,
                            "risk": "LOW",
                        }
                    )
            except Exception as e:  # noqa: BLE001
                _pkt_warn(
                    warnings,
                    warn_once,
                    f"dns_qname:{type(e).__name__}",
                    f"packet DNS qname extract: {type(e).__name__}: {e}",
                )

    if packet.haslayer(ARP):
        arp = packet[ARP]
        try:
            if int(arp.op) in (1, 2):
                sip = getattr(arp, "psrc", None) or ""
                smac = getattr(arp, "hwsrc", None) or ""
                if sip and smac:
                    events.append(
                        {
                            "type": "arp",
                            "display": f"[ARP]  {sip}  mac: {smac}",
                            "new_host": sip,
                            "risk": "LOW",
                        }
                    )
        except Exception as e:  # noqa: BLE001
            _pkt_warn(
                warnings,
                warn_once,
                f"arp_field:{type(e).__name__}",
                f"packet ARP field read: {type(e).__name__}: {e}",
            )

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        ip_ly = packet[IP] if packet.haslayer(IP) else None
        tcp = packet[TCP]
        raw = bytes(packet[Raw])
        src = ip_ly.src if ip_ly else "?"
        dst = ip_ly.dst if ip_ly else "?"

        if tcp.dport == 443 or tcp.sport == 443:
            events.append({"type": "https_count", "display": "", "risk": "LOW"})

        if tcp.dport == 80 or tcp.sport == 80:
            head = raw[:_MAX_RAW_PREVIEW]
            if (
                head.startswith(b"GET ")
                or head.startswith(b"POST ")
                or head.startswith(b"PUT ")
                or head.startswith(b"HEAD ")
                or b"HTTP/" in head[:24]
            ):
                host = None
                auth_hint = False
                try:
                    text = raw.decode("utf-8", errors="replace")
                    for line in text.split("\r\n"):
                        low = line.lower()
                        if low.startswith("host:"):
                            host = line.split(":", 1)[1].strip()[:80]
                        if "authorization:" in low:
                            auth_hint = True
                except Exception as e:  # noqa: BLE001
                    _pkt_warn(
                        warnings,
                        warn_once,
                        f"http_decode:{type(e).__name__}",
                        f"packet HTTP decode: {type(e).__name__}: {e}",
                    )
                    text = ""
                disp = f"[HTTP] {src} → {dst}  {head.splitlines()[0][:60] if head else 'HTTP'}"
                if auth_hint:
                    disp += "  [!] Auth header present"
                ev: dict[str, Any] = {
                    "type": "http",
                    "display": disp,
                    "http_host": host or dst,
                    "risk": "HIGH",
                    "cleartext": auth_hint,
                }
                if auth_hint:
                    ev["cleartext_detail"] = (
                        f"Authorization header seen ({_mask_value('Basic', 4)})"
                    )
                events.append(ev)

        if tcp.dport == 21 or tcp.sport == 21:
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception as e:  # noqa: BLE001
                _pkt_warn(
                    warnings,
                    warn_once,
                    f"ftp_decode:{type(e).__name__}",
                    f"packet FTP decode: {type(e).__name__}: {e}",
                )
                text = ""
            upper = text.upper()
            if "USER " in upper or "PASS " in upper:
                detail_parts: list[str] = []
                for line in text.split("\r\n"):
                    lu = line.upper().strip()
                    if lu.startswith("USER "):
                        u = line.split(None, 1)[1] if len(line.split()) > 1 else ""
                        detail_parts.append(f"USER {_mask_value(u, 4)}")
                    if lu.startswith("PASS "):
                        p = line.split(None, 1)[1] if len(line.split()) > 1 else ""
                        detail_parts.append(f"PASS {_mask_value(p, 4)}")
                events.append(
                    {
                        "type": "ftp",
                        "display": f"[FTP]  {src} ↔ {dst}  cleartext credential line(s)",
                        "risk": "CRITICAL",
                        "cleartext_detail": "; ".join(detail_parts) if detail_parts else "FTP data",
                    }
                )

        if tcp.dport == 23 or tcp.sport == 23:
            preview = _mask_value(raw[:32].decode("utf-8", errors="replace"), 4)
            events.append(
                {
                    "type": "telnet",
                    "display": f"[TELNET] {src} ↔ {dst}  payload: {preview}",
                    "risk": "CRITICAL",
                    "cleartext_detail": "Telnet keystrokes / data (unencrypted)",
                }
            )

    elif packet.haslayer(TCP):
        tcp = packet[TCP]
        if tcp.dport == 443 or tcp.sport == 443:
            events.append({"type": "https_count", "display": "", "risk": "LOW"})

    return events


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Capture network packets on the default interface.
    Analyze protocols; surface cleartext-risk hints (masked).
    Requires root/sudo.

    Duration: config.get("sniff_duration", 30) seconds
    """
    from scapy.all import sniff  # noqa: PLC0415

    t_wall = time.perf_counter()
    errors: list[str] = []
    duration = float(config.get("sniff_duration", 30))
    duration = max(1.0, min(duration, 3600.0))
    verbose = bool(config.get("verbose", False))

    findings: dict[str, Any] = {
        "dns_queries": [],
        "http_hosts": [],
        "new_hosts": [],
        "cleartext_risk": [],
    }
    stats = {
        "total_packets": 0,
        "dns": 0,
        "http": 0,
        "https": 0,
        "other": 0,
    }
    dns_set: set[str] = set()
    http_set: set[str] = set()
    hosts_set: set[str] = set()

    base: dict[str, Any] = {
        "module": "packet_sniffer",
        "target": target.value,
        "status": "pending",
        "duration": int(duration),
        "packets_captured": 0,
        "findings": findings,
        "stats": stats,
        "errors": errors,
        "warnings": [],
    }

    if target.is_domain():
        base["status"] = "skipped"
        console.print(
            Panel(
                Text(
                    "  PACKET SNIFFER  ·  domain not supported",
                    style=f"bold {C_PRI}",
                ),
                border_style=C_ACCENT,
                box=box.DOUBLE,
            )
        )
        console.print(Text("  [SKIP] Use an IP or CIDR.", style=C_WARN))
        return base

    if not _is_root():
        base["status"] = "error"
        base["error"] = "Root required — run with sudo"
        errors.append(base["error"])
        console.print(Text(f"  [✗] {base['error']}", style=C_ERR))
        return base

    try:
        import scapy.all as _sc  # noqa: F401, PLC0415
    except ImportError:
        base["status"] = "error"
        base["error"] = "scapy not installed — pip install scapy"
        errors.append(base["error"])
        console.print(Text(f"  [✗] {base['error']}", style=C_ERR))
        return base

    bpf = build_filter(target)
    label = target.value
    console.print(
        Panel(
            Text(
                f"  PACKET SNIFFER  ·  {label}  ·  {int(duration)}s capture",
                style=f"bold {C_PRI}",
            ),
            border_style=C_ACCENT,
            box=box.DOUBLE,
            width=min(console.size.width, 82) if console.size else 82,
        )
    )
    if bpf:
        console.print(Text(f"  [i] BPF filter: {bpf}", style=C_MUTED))
    console.print(
        Text(
            f"  [i] Capturing for {int(duration)}s — CTRL+C to stop early",
            style=C_MUTED,
        )
    )

    deadline = time.monotonic() + duration

    def stop_filter(_p: Any) -> bool:
        return time.monotonic() >= deadline

    arp_printed: set[str] = set()
    sniff_warnings: list[str] = base["warnings"]
    pkt_warn_once: set[str] = set()

    def packet_handler(pkt: Any) -> None:
        stats["total_packets"] += 1
        try:
            evs = analyze_packet(pkt, sniff_warnings, pkt_warn_once)
        except Exception as e:  # noqa: BLE001
            _pkt_warn(
                sniff_warnings,
                pkt_warn_once,
                f"analyze_packet:{type(e).__name__}",
                f"analyze_packet: {type(e).__name__}: {e}",
            )
            stats["other"] += 1
            return
        if not evs:
            stats["other"] += 1
            return
        saw_other_only = True
        for ev in evs:
            et = ev.get("type")
            if et == "dns":
                stats["dns"] += 1
                saw_other_only = False
                dn = ev.get("dns_name")
                if dn:
                    dns_set.add(dn)
                console.print(Text(f"  {ev['display']}", style=C_DIM))
            elif et == "http":
                stats["http"] += 1
                saw_other_only = False
                hh = ev.get("http_host")
                if hh:
                    http_set.add(str(hh))
                console.print(Text(f"  {ev['display']}", style=C_WARN))
                if ev.get("cleartext") and ev.get("cleartext_detail"):
                    findings["cleartext_risk"].append(
                        {
                            "type": "http_auth_header",
                            "detail": ev["cleartext_detail"],
                            "risk": "HIGH",
                        }
                    )
            elif et == "https_count":
                stats["https"] += 1
                saw_other_only = False
            elif et == "arp":
                saw_other_only = False
                nh = (ev.get("new_host") or "").strip()
                if nh:
                    hosts_set.add(nh)
                if verbose:
                    console.print(Text(f"  {ev['display']}", style=C_MUTED))
                elif nh and nh not in arp_printed:
                    arp_printed.add(nh)
                    console.print(Text(f"  {ev['display']}", style=C_MUTED))
            elif et == "ftp":
                stats["other"] += 1
                saw_other_only = False
                console.print(Text(f"  {ev['display']}", style=C_ERR))
                if ev.get("cleartext_detail"):
                    findings["cleartext_risk"].append(
                        {
                            "type": "ftp_cleartext",
                            "detail": ev["cleartext_detail"],
                            "risk": "CRITICAL",
                        }
                    )
            elif et == "telnet":
                stats["other"] += 1
                saw_other_only = False
                console.print(Text(f"  {ev['display']}", style=C_ERR))
                findings["cleartext_risk"].append(
                    {
                        "type": "telnet",
                        "detail": ev.get("cleartext_detail", "telnet"),
                        "risk": "CRITICAL",
                    }
                )
        if saw_other_only:
            stats["other"] += 1

    try:
        sniff(
            filter=bpf or None,
            prn=packet_handler,
            store=False,
            stop_filter=stop_filter,
        )
    except KeyboardInterrupt:
        errors.append("Interrupted — partial capture")
        console.print(Text("\n  [!] Interrupted — summarizing…", style=C_WARN))
    except Exception as e:  # noqa: BLE001
        errors.append(str(e))
        base["status"] = "error"
        base["error"] = str(e)
        console.print(Text(f"  [✗] Sniff failed: {e}", style=C_ERR))
        return base

    findings["dns_queries"] = sorted(dns_set)
    findings["http_hosts"] = sorted(http_set)
    findings["new_hosts"] = sorted(hosts_set)

    base["packets_captured"] = stats["total_packets"]
    base["status"] = "success"
    base["stats"] = stats
    base["findings"] = findings
    base["duration_elapsed_s"] = round(time.perf_counter() - t_wall, 2)

    console.print()
    console.print(Text(" [✓] Capture complete", style=f"bold {C_PRI}"))
    console.print(
        Text(
            f"     Packets : {stats['total_packets']:,}  "
            f"(DNS {stats['dns']} · HTTP {stats['http']} · "
            f"HTTPS {stats['https']} · other {stats['other']})",
            style=C_DIM,
        )
    )
    console.print(
        Text(
            f"     Unique DNS names: {len(dns_set)} · "
            f"HTTP hosts seen: {len(http_set)} · "
            f"ARP IPs logged: {len(hosts_set)}",
            style=C_MUTED,
        )
    )

    return base
