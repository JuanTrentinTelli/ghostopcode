"""
GhostOpcode port scanner — threaded TCP connect, banner grab, OS inference, attack vectors.
"""

from __future__ import annotations

import re
import shutil
import socket
import ssl
import struct
import threading
import time
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Any, Callable

from rich import box
from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from config import DEFAULT_THREADS, DEFAULT_TIMEOUT
from utils.target_parser import Target

try:
    import nmap  # type: ignore[import-untyped]
except ImportError:
    nmap = None  # type: ignore[misc, assignment]

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_ACCENT = "#8B9CA8"

console = Console(highlight=False, force_terminal=True)

# Preset: aggressive surface map (deduped, order preserved)
_PORT_COMMON_ORDERED: list[int] = [
    21,
    22,
    23,
    3389,
    5900,
    80,
    443,
    8080,
    8443,
    8888,
    8000,
    8008,
    8081,
    8082,
    25,
    465,
    587,
    110,
    995,
    143,
    993,
    3306,
    5432,
    1521,
    1433,
    27017,
    6379,
    9200,
    5984,
    20,
    69,
    445,
    139,
    2049,
    53,
    161,
    162,
    389,
    636,
    2375,
    2376,
    4243,
    9000,
    9090,
    9093,
    8983,
    4848,
    5601,
    4567,
    1194,
    1723,
    500,
    4500,
    111,
    135,
    137,
    138,
    179,
    5000,
    5001,
]

PORT_PRESETS: dict[str, list[int]] = {
    "common": list(dict.fromkeys(_PORT_COMMON_ORDERED)),
}

# Known attack narratives (extend with novel angles)
ATTACK_VECTORS: dict[str, list[str]] = {
    "FTP": [
        "Anonymous login attempt",
        "Brute force credentials",
        "FTP bounce attack",
    ],
    "SSH": [
        "Brute force credentials",
        "Username enumeration",
        "Check for weak ciphers / Terrapin-class downgrade",
    ],
    "Telnet": [
        "Cleartext credentials — sniff traffic",
        "Brute force credentials",
        "CRITICAL: legacy protocol, no encryption",
    ],
    "HTTP": [
        "Directory enumeration",
        "Web vulnerability scanning",
        "Check for default credentials",
    ],
    "HTTPS": [
        "TLS inspection — weak ciphers / cert issues",
        "HTTP smuggling if reverse proxy present",
        "Web vulnerability scanning behind TLS",
    ],
    "SMB": [
        "EternalBlue (MS17-010) check",
        "Null session enumeration",
        "Brute force credentials",
        "Check for SMB signing",
    ],
    "RDP": [
        "BlueKeep (CVE-2019-0708) check",
        "Brute force credentials",
        "NLA disabled check",
    ],
    "MySQL": [
        "CRITICAL: database exposed to internet",
        "Brute force credentials",
        "Check for anonymous access",
    ],
    "PostgreSQL": [
        "CRITICAL: database exposed to internet",
        "Brute force credentials",
        "Check for trust authentication",
    ],
    "Redis": [
        "CRITICAL: check for unauthenticated access",
        "RCE via CONFIG SET / replicaof",
        "Data exfiltration",
    ],
    "MongoDB": [
        "CRITICAL: check for unauthenticated access",
        "Data exfiltration",
        "Check for --auth flag",
    ],
    "Docker": [
        "CRITICAL: Docker API exposed",
        "Container escape",
        "Full host compromise possible",
    ],
    "Elasticsearch": [
        "CRITICAL: check for unauthenticated access",
        "Data exfiltration",
        "Check for security plugin",
    ],
    "VNC": [
        "Brute force / weak password",
        "Cleartext session capture",
    ],
    "SNMP": [
        "Community string brute force (public/private)",
        "Configuration disclosure / network map",
    ],
    "LDAP": [
        "Anonymous bind enumeration",
        "Injection-style attacks on misconfigured directories",
    ],
    "DNS": [
        "Zone transfer attempt (AXFR)",
        "DNS amplification abuse if open resolver",
    ],
    "UNKNOWN": [
        "Fingerprint stack — custom protocol may hide admin interfaces",
        "Rate-limited cred stuffing if auth surface exists",
        "Protocol-specific fuzzing (research-only)",
    ],
}

# (port, service_name, default_risk)
_DEFAULT_BY_PORT: list[tuple[int, str, str]] = [
    (21, "FTP", "HIGH"),
    (22, "SSH", "MEDIUM"),
    (23, "Telnet", "HIGH"),
    (25, "SMTP", "MEDIUM"),
    (53, "DNS", "MEDIUM"),
    (69, "TFTP", "HIGH"),
    (80, "HTTP", "LOW"),
    (110, "POP3", "MEDIUM"),
    (111, "RPC", "HIGH"),
    (135, "MSRPC", "HIGH"),
    (137, "NetBIOS", "HIGH"),
    (138, "NetBIOS", "HIGH"),
    (139, "NetBIOS", "HIGH"),
    (143, "IMAP", "MEDIUM"),
    (179, "BGP", "MEDIUM"),
    (443, "HTTPS", "LOW"),
    (445, "SMB", "HIGH"),
    (465, "SMTPS", "MEDIUM"),
    (587, "SMTP", "MEDIUM"),
    (636, "LDAPS", "MEDIUM"),
    (993, "IMAPS", "MEDIUM"),
    (995, "POP3S", "MEDIUM"),
    (1433, "MSSQL", "CRITICAL"),
    (1521, "Oracle", "CRITICAL"),
    (2049, "NFS", "HIGH"),
    (2375, "Docker", "CRITICAL"),
    (2376, "Docker", "CRITICAL"),
    (3306, "MySQL", "CRITICAL"),
    (3389, "RDP", "HIGH"),
    (4243, "Docker", "HIGH"),
    (4567, "Hazelcast", "HIGH"),
    (4848, "GlassFish", "HIGH"),
    (500, "ISAKMP", "MEDIUM"),
    (5000, "UPnP", "HIGH"),
    (5001, "UPnP", "HIGH"),
    (5432, "PostgreSQL", "CRITICAL"),
    (4500, "IPsec", "MEDIUM"),
    (5601, "Kibana", "HIGH"),
    (5900, "VNC", "HIGH"),
    (5984, "CouchDB", "CRITICAL"),
    (6379, "Redis", "CRITICAL"),
    (8000, "HTTP-ALT", "LOW"),
    (8008, "HTTP-ALT", "LOW"),
    (8080, "HTTP-PROXY", "LOW"),
    (8081, "HTTP-ALT", "LOW"),
    (8082, "HTTP-ALT", "LOW"),
    (8443, "HTTPS-ALT", "LOW"),
    (8888, "HTTP-ALT", "LOW"),
    (8983, "Solr", "HIGH"),
    (9000, "HTTP-ALT", "MEDIUM"),
    (9090, "HTTP-ALT", "MEDIUM"),
    (9093, "HTTP-ALT", "MEDIUM"),
    (9200, "Elasticsearch", "CRITICAL"),
    (1194, "OpenVPN", "MEDIUM"),
    (1723, "PPTP", "HIGH"),
    (161, "SNMP", "HIGH"),
    (162, "SNMP", "MEDIUM"),
    (389, "LDAP", "MEDIUM"),
    (27017, "MongoDB", "CRITICAL"),
]

DEFAULT_PORT_SERVICE: dict[int, tuple[str, str]] = {
    p: (svc, risk) for p, svc, risk in _DEFAULT_BY_PORT
}

# Regex → metadata for banner classification (first match wins; order matters)
_SERVICE_SIGNATURES: list[tuple[re.Pattern[str], dict[str, Any]]] = [
    (
        re.compile(r"SSH-(\d+\.\d+)-OpenSSH_([\d.p]+)", re.I),
        {"service": "SSH", "product": "OpenSSH", "version_group": 2},
    ),
    (
        re.compile(r"SSH-2\.0-dropbear_([\d.]+)", re.I),
        {"service": "SSH", "product": "Dropbear SSH", "version_group": 1},
    ),
    (
        re.compile(
            r"220[^\n]*?(vsftpd|ProFTPD|FileZilla|Pure-FTPd)[^\n]*?([\d.]+)?",
            re.I,
        ),
        {"service": "FTP", "product_group": 1, "version_group": 2},
    ),
    (
        re.compile(r"220[^\n]*ftp", re.I),
        {"service": "FTP", "product": "FTP"},
    ),
    (
        re.compile(r"Server:\s*([^\r\n]+)", re.I),
        {"service": "HTTP", "product_line_group": 1},
    ),
    (
        re.compile(r"220\s+([\w.-]+)\s+ESMTP", re.I),
        {"service": "SMTP", "product_group": 1},
    ),
    (
        re.compile(r"\+OK", re.I),
        {"service": "POP3", "product": "POP3"},
    ),
    (
        re.compile(r"\* OK.*IMAP", re.I),
        {"service": "IMAP", "product": "IMAP"},
    ),
    (
        re.compile(r"Redis|\+PONG", re.I),
        {"service": "Redis", "product": "Redis"},
    ),
    (
        re.compile(r"MongoDB|ismaster", re.I),
        {"service": "MongoDB", "product": "MongoDB"},
    ),
    (
        re.compile(r"MySQL|mysql_native_password|MariaDB", re.I),
        {"service": "MySQL", "product": "MySQL"},
    ),
    (
        re.compile(r"PostgreSQL", re.I),
        {"service": "PostgreSQL", "product": "PostgreSQL"},
    ),
    (
        re.compile(r"Microsoft-IIS/([\d.]+)", re.I),
        {"service": "HTTP", "product": "Microsoft-IIS", "version_group": 1},
    ),
    (
        re.compile(r"nginx/([\d.]+)", re.I),
        {"service": "HTTP", "product": "nginx", "version_group": 1},
    ),
    (
        re.compile(r"Apache[/\s]([\d.]+)?", re.I),
        {"service": "HTTP", "product": "Apache", "version_group": 1},
    ),
    (
        re.compile(r"RDP|Negotiation Request", re.I),
        {"service": "RDP", "product": "Microsoft RDP"},
    ),
]

# Lightweight local CVE / patch reminders (no live API)
_CVE_HINT_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"OpenSSH_7\.|OpenSSH_6\.", re.I), "Legacy OpenSSH — audit CVEs for that branch"),
    (re.compile(r"OpenSSL/1\.0\.|OpenSSL/1\.1\.0", re.I), "Aged OpenSSL — check known TLS CVEs"),
    (re.compile(r"nginx/1\.(16|17|18)\.", re.I), "nginx 1.16–1.18 era — verify patch level"),
    (re.compile(r"Microsoft-IIS/[56]\.", re.I), "Old IIS — verify OS patch + URLScan hardening"),
    (re.compile(r"vsftpd", re.I), "vsftpd — verify distro backports vs public CVEs"),
]


def parse_ports(ports_arg: str) -> list[int]:
    """
    Parse port range argument into list of integers.
    Supports: "common" | "80" | "80,443,8080" | "1-1024" | "1-65535"
    """
    raw = ports_arg.strip().lower()
    if not raw or raw == "common":
        return list(PORT_PRESETS["common"])
    if raw.isdigit():
        p = int(raw)
        if 1 <= p <= 65535:
            return [p]
        return list(PORT_PRESETS["common"])
    if "," in raw:
        out: list[int] = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                out.extend(parse_ports(part))
            elif part.isdigit():
                n = int(part)
                if 1 <= n <= 65535:
                    out.append(n)
        return list(dict.fromkeys(out)) if out else list(PORT_PRESETS["common"])
    if "-" in raw:
        a, _, b = raw.partition("-")
        try:
            lo, hi = int(a.strip()), int(b.strip())
        except ValueError:
            return list(PORT_PRESETS["common"])
        if lo > hi:
            lo, hi = hi, lo
        lo = max(1, min(lo, 65535))
        hi = max(1, min(hi, 65535))
        return list(range(lo, hi + 1))
    return list(PORT_PRESETS["common"])


def tcp_connect(host: str, port: int, timeout: float) -> bool:
    """
    Attempt TCP connection to host:port.
    Returns True if port is open, False otherwise.
    Never raises.
    """
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((host, port))
        return code == 0
    except OSError:
        return False
    except Exception:  # noqa: BLE001
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _recv_available(sock: socket.socket, limit: int = 8192) -> bytes:
    try:
        sock.settimeout(min(2.0, sock.gettimeout() or 2.0))
        return sock.recv(limit)
    except (socket.timeout, OSError, ssl.SSLError):
        return b""


def _http_get_probe(host: str) -> bytes:
    return f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: GhostOpcode/1.0\r\n\r\n".encode(
        "ascii",
        errors="ignore",
    )


def _postgres_ssl_request() -> bytes:
    return struct.pack(">II", 8, 80877103)


def grab_banner(host: str, port: int, timeout: float) -> str | None:
    """
    Attempt to grab service banner from an open port.
    Tries passive recv, then port-specific probes, TLS for HTTPS-like ports.
    Never raises — returns None on any failure.
    """
    use_ssl = port in {443, 8443, 636, 993, 995, 465}
    web_alike = port in {80, 8080, 8000, 8008, 8081, 8082, 8888, 9000, 9090, 9093}

    sock: socket.socket | ssl.SSLSocket | None = None
    chunks: list[bytes] = []

    try:
        plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        plain.settimeout(timeout)
        plain.connect((host, port))

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(plain, server_hostname=host)
        else:
            sock = plain
            plain = None  # ownership transferred

        first = _recv_available(sock)
        if first:
            chunks.append(first)

        # Probes
        probe: bytes | None = None
        if port == 6379:
            probe = b"PING\r\n"
        elif port == 27017:
            probe = (
                b"\x3a\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00"
                b"\xd4\x07\x00\x00"
            )
        elif port == 5432:
            probe = _postgres_ssl_request()
        elif web_alike or (use_ssl and not first):
            probe = _http_get_probe(host)

        if probe:
            try:
                sock.sendall(probe)
            except OSError:
                pass
            extra = _recv_available(sock)
            if extra:
                chunks.append(extra)

        if not chunks and use_ssl and not probe:
            try:
                sock.sendall(_http_get_probe(host))
                chunks.append(_recv_available(sock))
            except OSError:
                pass

        if not chunks:
            return None

        raw = b"".join(chunks)[:16000]
        return raw.decode("latin-1", errors="replace")
    except Exception:  # noqa: BLE001
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if plain is not None:
            try:
                plain.close()
            except OSError:
                pass


def _classify_banner(
    banner: str | None,
    port: int,
    host: str,
) -> tuple[str, str | None, str | None, str | None]:
    """
    Return (service, product, version, banner_note).
    """
    note: str | None = None
    if not banner:
        d = DEFAULT_PORT_SERVICE.get(port)
        if d:
            return d[0], None, None, None
        return "UNKNOWN", None, None, None

    low = banner.lower()
    if port in {443, 8443} and banner.strip():
        note = "(TLS encrypted response / HTTP over TLS)"

    # Binary RDP heuristic
    if port in {3389, 3388} and banner.encode("latin-1", errors="replace")[:2] == b"\x03\x00":
        return "RDP", "Microsoft RDP", None, note

    for rx, meta in _SERVICE_SIGNATURES:
        m = rx.search(banner)
        if not m:
            continue
        service = str(meta["service"])
        if port in {443, 8443} and service == "HTTP":
            service = "HTTPS"
        product = meta.get("product")
        version = None
        if "version_group" in meta:
            g = meta["version_group"]
            if m.lastindex and g <= m.lastindex:
                version = m.group(g)
        if "product_group" in meta:
            g = int(meta["product_group"])
            if m.lastindex and g <= m.lastindex:
                product = m.group(g)
        if "product_line_group" in meta:
            line = m.group(int(meta["product_line_group"])).strip()
            product = line.split("/")[0].strip() if line else None
            vs = re.search(r"([\d.]+[a-z0-9.]*)", line, re.I)
            if vs:
                version = vs.group(1)
        if "+pong" in low or ("redis" in low and "+pong" in banner):
            note = "Redis replied — check AUTH"
        if "mongodb" in low or "ismaster" in low:
            service = "MongoDB"
            product = product or "MongoDB"
        return service, product, version, note

    d = DEFAULT_PORT_SERVICE.get(port)
    if d:
        return d[0], None, None, note
    return "UNKNOWN", None, None, note


def _cve_hints_for_banner(banner: str | None) -> list[str]:
    if not banner:
        return []
    hints: list[str] = []
    for rx, msg in _CVE_HINT_RULES:
        if rx.search(banner):
            hints.append(msg)
    return list(dict.fromkeys(hints))


def _service_risk(service: str, port: int, banner: str | None) -> str:
    base = DEFAULT_PORT_SERVICE.get(port, ("UNKNOWN", "LOW"))[1]
    if service in {"MySQL", "PostgreSQL", "MongoDB", "Redis", "MSSQL", "Oracle"}:
        return "CRITICAL"
    if service == "Docker" or port in {2375, 2376}:
        return "CRITICAL"
    if service == "Elasticsearch" or port == 9200:
        return "CRITICAL"
    if service == "CouchDB" or port == 5984:
        return "CRITICAL"
    if service in {"SMB", "RDP", "Telnet", "VNC"}:
        return "HIGH"
    if service == "FTP":
        return "HIGH"
    if service == "SNMP" or port in {161, 162}:
        return "HIGH"
    if service == "SSH":
        return "MEDIUM"
    if banner and "Server:" in banner and re.search(r"Server:\s*[\w.-]+/[\d.]+", banner):
        if service in {"HTTP", "HTTPS"}:
            return "LOW"
    return base


def _vectors_for(
    service: str,
    port: int,
    risk: str,
) -> list[str]:
    keys = [service]
    if service == "HTTP" and port in {443, 8443}:
        keys.insert(0, "HTTPS")
    vecs: list[str] = []
    for k in keys:
        vecs.extend(ATTACK_VECTORS.get(k, []))
    if not vecs:
        vecs = list(ATTACK_VECTORS["UNKNOWN"])
    # Novel “unknown surface” angles for high-value ports
    if risk in {"CRITICAL", "HIGH"} and service == "UNKNOWN":
        vecs.append(
            "Map to product via TLS ALPN / cert SANs — hidden admin UIs often share certs"
        )
    return list(dict.fromkeys(vecs))


def infer_os(open_ports: list[int], banners: dict[int, str | None]) -> dict[str, Any]:
    """
    Infer operating system from open ports and banner signatures.
    Returns confidence level and reasoning.
    """
    evidence: list[str] = []
    win_score = 0
    lin_score = 0
    net_score = 0

    win_ports = {135, 139, 445, 3389, 1433}
    lin_ports = {22, 111, 2049}
    net_ports = {23, 161, 179}

    for p in open_ports:
        if p in win_ports:
            win_score += 2
            evidence.append(f"port {p} typical Windows service")
        if p in lin_ports:
            lin_score += 2
            evidence.append(f"port {p} common on Unix-like hosts")
        if p in net_ports:
            net_score += 1
            evidence.append(f"port {p} network appliance / legacy")

    blob = " ".join((banners.get(p) or "") for p in open_ports).lower()
    if "windows" in blob or "microsoft" in blob or "iis" in blob:
        win_score += 3
        evidence.append("Windows/IIS fingerprint in banner")
    if "ubuntu" in blob or "debian" in blob or "centos" in blob or "openssh" in blob:
        lin_score += 2
        evidence.append("Linux distro / OpenSSH hint in banner")
    if any(x in blob for x in ("cisco", "juniper", "mikrotik", "huawei")):
        net_score += 3
        evidence.append("embedded / network OS banner keyword")

    if win_score >= 4 and win_score > lin_score:
        return {"os": "Windows", "confidence": "MEDIUM", "evidence": evidence[:8]}
    if lin_score >= 4 and lin_score > win_score:
        return {"os": "Linux/Unix", "confidence": "MEDIUM", "evidence": evidence[:8]}
    if net_score >= 3 and net_score > max(win_score, lin_score):
        return {
            "os": "Network appliance / embedded",
            "confidence": "LOW",
            "evidence": evidence[:8],
        }
    if win_score > 0 or lin_score > 0:
        guess = "Windows" if win_score >= lin_score else "Linux/Unix"
        return {"os": guess, "confidence": "LOW", "evidence": evidence[:8] or ["mixed signals"]}
    return {
        "os": "Unknown",
        "confidence": "LOW",
        "evidence": ["insufficient port/banner signals"],
    }


def _nmap_enrich(host: str, ports: list[int]) -> dict[int, dict[str, str | None]]:
    """
    Optional version detection via python-nmap when nmap binary exists.
    Returns map port → {product, version, extrainfo}.
    """
    out: dict[int, dict[str, str | None]] = {}
    if nmap is None or not ports:
        return out
    if shutil.which("nmap") is None:
        return out
    try:
        nm = nmap.PortScanner()
        portstr = ",".join(str(p) for p in ports)
        nm.scan(
            host,
            portstr,
            arguments="-sV --version-light --host-timeout 90s",
        )
        if host not in nm.all_hosts():
            return out
        tcp = nm[host].get("tcp", {})
        for p_s, info in tcp.items():
            if not isinstance(info, dict):
                continue
            if info.get("state") != "open":
                continue
            try:
                pi = int(p_s)
            except (TypeError, ValueError):
                continue
            out[pi] = {
                "product": info.get("name") or info.get("product"),
                "version": info.get("version"),
                "extrainfo": info.get("extrainfo"),
            }
    except Exception:  # noqa: BLE001
        return out
    return out


class _PortScanLiveDisplay:
    """Progress + live speed / open count / recent OPEN lines."""

    def __init__(
        self,
        progress: Progress,
        task_id: Any,
        total: int,
        host: str,
        get_snapshot: Callable[[], tuple[int, int, float, float, list[str]]],
    ) -> None:
        self.progress = progress
        self.task_id = task_id
        self.total = total
        self.host = host
        self._snapshot = get_snapshot

    def __rich__(self) -> RenderableType:
        done, n_open, elapsed, rps, recent = self._snapshot()
        pct = (done / self.total * 100) if self.total else 0.0
        remaining = max(0, self.total - done)
        eta = (remaining / rps) if rps > 0.1 else 0.0

        self.progress.update(self.task_id, completed=done, total=self.total)

        stats_line = Text.assemble(
            (" Speed: ", C_MUTED),
            (f"{rps:.0f} req/s", C_PRI),
            (" · Open: ", C_MUTED),
            (str(n_open), f"bold {C_WARN}"),
            (" · Elapsed: ", C_MUTED),
            (f"{elapsed:.1f}s", C_DIM),
            (" · ETA: ", C_MUTED),
            (f"{eta:.1f}s" if eta < 86400 else "—", C_DIM),
            (f" · {pct:.0f}%", C_MUTED),
        )

        hits_block = Text("\n".join(recent), style=C_DIM) if recent else Text("")

        return Group(
            self.progress,
            stats_line,
            Text(""),
            hits_block,
        )


def _render_header(target_label: str, n_ports: int) -> None:
    p = Panel(
        Text(
            f"  PORT SCAN  ·  {target_label}  ·  {n_ports} ports",
            style=f"bold {C_PRI}",
        ),
        border_style=C_ACCENT,
        box=box.DOUBLE,
        width=min(console.size.width, 82) if console.size else 82,
    )
    console.print(p)


def _risk_style(risk: str) -> str:
    if risk == "CRITICAL":
        return f"bold {C_ERR}"
    if risk == "HIGH":
        return f"bold {C_WARN}"
    if risk == "MEDIUM":
        return C_WARN
    return C_DIM


def _print_open_table(rows: list[dict[str, Any]]) -> None:
    table = Table(
        box=box.ROUNDED,
        border_style=C_ACCENT,
        header_style=f"bold {C_DIM}",
        show_lines=True,
    )
    table.add_column("Port", style=C_PRI)
    table.add_column("Service", style=C_DIM)
    table.add_column("Version", style=C_DIM, max_width=22)
    table.add_column("Banner / note", style=C_MUTED, max_width=36)
    table.add_column("Risk", justify="right")

    for r in rows:
        ver = r.get("product") or "—"
        if r.get("version"):
            ver = f"{ver} {r['version']}".strip()
        ban = (r.get("banner") or "").replace("\r", " ").replace("\n", " ")[:120]
        ban = ban.strip() or "—"
        if r.get("note"):
            ban = (
                r["note"] if ban == "—" else f"{ban} · {r['note']}"
            )[:120]
        risk = r.get("risk", "LOW")
        table.add_row(
            f"{r['port']}/tcp",
            str(r.get("service", "—")),
            ver[:22] if ver else "—",
            ban,
            Text(f"[{risk}]", style=_risk_style(str(risk))),
        )
    console.print()
    console.print(table)


def _print_vectors(critical_rows: list[dict[str, Any]]) -> None:
    if not critical_rows:
        return
    console.print()
    console.print(
        Text(
            " [VECTORS] Attack surface for critical/high ports:",
            style=f"bold {C_WARN}",
        )
    )
    for i, r in enumerate(critical_rows):
        sym = "└──" if i == len(critical_rows) - 1 else "├──"
        head = f"{sym} {r['port']}/{r.get('service', '?')}"
        console.print(Text(f"   {head}", style=C_DIM))
        vecs = r.get("vectors") or []
        for j, v in enumerate(vecs):
            branch = "   │   " if i != len(critical_rows) - 1 else "       "
            tick = "└" if j == len(vecs) - 1 else "├"
            console.print(Text(f"   {branch}{tick}→  {v}", style=C_MUTED))


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    TCP connect scan, banner grab, OS inference, vectors, optional nmap -sV.
    """
    t_start = time.perf_counter()
    threads = max(1, int(config.get("threads") or DEFAULT_THREADS))
    timeout = max(0.3, float(config.get("timeout") or DEFAULT_TIMEOUT))
    verbose = bool(config.get("verbose", False))
    ports_arg = str(config.get("ports_range") or "common")

    base: dict[str, Any] = {
        "module": "port_scan",
        "target": target.value,
        "status": "skipped",
        "host_ip": "",
        "ports": [],
        "os_inference": {},
        "stats": {
            "total_scanned": 0,
            "open": 0,
            "closed": 0,
            "duration_s": 0.0,
            "req_per_sec": 0.0,
        },
        "risk_summary": {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []},
        "errors": [],
        "findings": [],
    }

    if target.is_cidr():
        _render_header(target.value, 0)
        console.print(
            Text("  [SKIP] Port scan — use a domain or single IP.", style=C_WARN)
        )
        return base

    ports = parse_ports(ports_arg)
    if not ports:
        base["errors"].append("No valid ports to scan")
        base["status"] = "error"
        base["error"] = base["errors"][-1]
        return base

    host_ip = ""
    try:
        host_ip = socket.gethostbyname(target.value)
    except socket.gaierror as e:
        base["status"] = "error"
        base["error"] = f"DNS resolution failed: {e}"
        base["errors"].append(base["error"])
        _render_header(target.value, len(ports))
        console.print(Text(f"  [✗] {base['error']}", style=C_ERR))
        return base
    except OSError as e:
        base["status"] = "error"
        base["error"] = str(e)
        base["errors"].append(str(e))
        return base

    base["host_ip"] = host_ip
    _render_header(target.value, len(ports))
    console.print(
        Text.assemble(
            (" [►] Resolving ", C_MUTED),
            (f"{target.value}", C_DIM),
            (" → ", C_MUTED),
            (host_ip, f"bold {C_PRI}"),
        )
    )
    console.print()

    n_total = len(ports)
    lock = threading.Lock()
    done_count = 0
    open_ports: list[int] = []
    recent_open: deque[str] = deque(maxlen=14)
    window: deque[float] = deque()
    interrupted = False

    def record_done() -> None:
        nonlocal done_count
        with lock:
            done_count += 1
            now = time.perf_counter()
            window.append(now)
            while window and now - window[0] > 2.0:
                window.popleft()

    def on_open(p: int) -> None:
        line = f"[+] {p}/tcp    OPEN   {DEFAULT_PORT_SERVICE.get(p, ('?',))[0]}"
        with lock:
            if p not in open_ports:
                open_ports.append(p)
            recent_open.append(line)

    def worker(port: int) -> None:
        try:
            if tcp_connect(host_ip, port, timeout):
                on_open(port)
        finally:
            record_done()

    console.print(
        Text(
            f" [SCAN] Scanning {host_ip} — {n_total} ports · {threads} threads",
            style=f"bold {C_PRI}",
        )
    )
    console.print()

    progress = Progress(
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=None, style=C_MUTED, complete_style=C_PRI),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        expand=True,
    )
    task_id = progress.add_task("tcp_connect", total=n_total)

    def snapshot() -> tuple[int, int, float, float, list[str]]:
        with lock:
            dc = done_count
            op = len(open_ports)
            recent = list(recent_open)
        elapsed = time.perf_counter() - t_start
        rps = len(window) / 2.0 if window else 0.0
        return dc, op, elapsed, rps, recent

    display = _PortScanLiveDisplay(progress, task_id, n_total, host_ip, snapshot)

    max_inflight = min(max(threads * 4, threads), 4096)
    pending: set[Any] = set()
    pit = iter(ports)
    exhausted = False

    def submit_batch(ex: ThreadPoolExecutor) -> None:
        nonlocal exhausted
        while len(pending) < max_inflight and not exhausted:
            try:
                p = next(pit)
            except StopIteration:
                exhausted = True
                break
            pending.add(ex.submit(worker, p))

    panel = Panel(
        display,
        border_style=C_ACCENT,
        box=box.ROUNDED,
        padding=(0, 1),
    )
    executor = ThreadPoolExecutor(max_workers=threads)
    try:
        with Live(panel, console=console, refresh_per_second=12, transient=False):
            submit_batch(executor)
            while pending or not exhausted:
                if pending:
                    done_fs, _ = wait(
                        pending,
                        return_when=FIRST_COMPLETED,
                        timeout=0.25,
                    )
                    for fut in done_fs:
                        pending.discard(fut)
                        try:
                            fut.result()
                        except Exception as e:  # noqa: BLE001
                            if verbose:
                                with lock:
                                    base["errors"].append(str(e))
                        submit_batch(executor)
                else:
                    submit_batch(executor)
    except KeyboardInterrupt:
        interrupted = True
        with lock:
            base["errors"].append(
                "[!] Interrupted by operator — partial TCP phase results"
            )
        console.print()
        console.print(
            Text(
                " [!] Interrupted — partial results",
                style=f"bold {C_WARN}",
            )
        )
    finally:
        executor.shutdown(wait=not interrupted, cancel_futures=interrupted)

    t_after_tcp = time.perf_counter()
    tcp_phase_s = max(t_after_tcp - t_start, 1e-6)
    rps_connect = done_count / tcp_phase_s

    open_sorted = sorted(set(open_ports))
    banners: dict[int, str | None] = {}

    # Banner phase (sequential — fewer sockets; avoids stampeding target)
    for p in open_sorted:
        b = grab_banner(host_ip, p, min(timeout, 4.0))
        banners[p] = b

    nmap_data = _nmap_enrich(host_ip, open_sorted)

    port_rows: list[dict[str, Any]] = []
    for p in open_sorted:
        banner = banners.get(p)
        service, product, version, note = _classify_banner(banner, p, host_ip)
        nm = nmap_data.get(p) or {}
        if (not product or not version) and nm:
            product = product or nm.get("product")
            ver_nm = nm.get("version")
            if ver_nm:
                version = version or str(ver_nm)
            if nm.get("extrainfo") and verbose:
                note = (note or "") + f" nmap:{nm['extrainfo']}"

        risk = _service_risk(service, p, banner)
        vectors = _vectors_for(service, p, risk)
        cve_hints = _cve_hints_for_banner(banner)
        if cve_hints:
            vectors = vectors + [f"CVE hygiene: {h}" for h in cve_hints[:2]]

        row = {
            "port": p,
            "state": "open",
            "service": service,
            "product": product,
            "version": version,
            "banner": banner,
            "risk": risk,
            "vectors": vectors,
            "note": note,
            "cve_hints": cve_hints,
        }
        if service in {"MySQL", "PostgreSQL", "MongoDB", "Redis"} and p in {
            3306,
            5432,
            27017,
            6379,
        }:
            db_note = "Database should NEVER be exposed to the internet"
            row["note"] = (
                f"{row['note']} — {db_note}" if row.get("note") else db_note
            )
        port_rows.append(row)

    duration = time.perf_counter() - t_start
    n_open = len(open_sorted)

    base["stats"]["total_scanned"] = n_total
    base["stats"]["open"] = n_open
    base["stats"]["closed"] = max(0, n_total - n_open)
    base["stats"]["duration_s"] = round(duration, 2)
    base["stats"]["req_per_sec"] = round(rps_connect, 1)
    base["ports"] = port_rows
    base["findings"] = port_rows
    base["os_inference"] = infer_os(open_sorted, banners)

    rs: dict[str, list[str]] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
    }
    for r in port_rows:
        rk = str(r.get("risk", "LOW"))
        if rk in rs:
            rs[rk].append(str(r["port"]))
    base["risk_summary"] = rs

    _print_open_table(port_rows)

    oi = base["os_inference"]
    console.print()
    console.print(
        Text.assemble(
            (" [OS]   Inference: ", f"bold {C_PRI}"),
            (str(oi.get("os", "Unknown")), C_DIM),
            (f"  (confidence: {oi.get('confidence', 'LOW')})", C_MUTED),
        )
    )
    ev = oi.get("evidence") or []
    if ev:
        console.print(
            Text(f"        Evidence : {' · '.join(ev[:5])}", style=C_MUTED)
        )

    crit_high = [r for r in port_rows if r.get("risk") in {"CRITICAL", "HIGH"}]
    _print_vectors(crit_high)

    rc = len(rs["CRITICAL"])
    rh = len(rs["HIGH"])
    rm = len(rs["MEDIUM"])
    rl = len(rs["LOW"])

    console.print()
    console.print(
        Text.assemble(
            ("\n [✓] Port scan complete\n", f"bold {C_PRI}"),
            (f"     Scanned   : {n_total} ports\n", C_DIM),
            (f"     Open      : {n_open} ports\n", C_DIM),
            (
                f"     Critical  : {rc}  ·  High: {rh}  ·  Medium: {rm}  ·  Low: {rl}\n",
                C_DIM,
            ),
            (
                f"     OS        : {oi.get('os', '?')} ({oi.get('confidence', 'LOW')} confidence)\n",
                C_DIM,
            ),
            (f"     Speed     : {base['stats']['req_per_sec']} req/s\n", C_DIM),
            (f"     Duration  : {base['stats']['duration_s']}s", C_DIM),
        )
    )

    base["status"] = "success"
    if base["errors"] and interrupted:
        base["status"] = "success"
    return base
