"""
GhostOpcode WHOIS + single-shot HTTP fingerprint + SSL intel.
"""

from __future__ import annotations

import re
import shutil
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests
import urllib3
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

import whois
from config import DEFAULT_TIMEOUT, USER_AGENT
from utils.output import debug_log
from utils.target_parser import Target

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None  # type: ignore[misc, assignment]

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    x509 = None  # type: ignore[misc, assignment]
    default_backend = None  # type: ignore[misc, assignment]

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_ACCENT = "#8B9CA8"
C_OK = "#00FF41"

console = Console(highlight=False, force_terminal=True)

PRIVACY_KEYWORDS = (
    "privacy",
    "redacted",
    "protected",
    "withheld",
    "whoisguard",
    "privacyguard",
    "domainsbyproxy",
    "contactprivacy",
    "registrant redacted",
    "data protected",
    "gdpr redacted",
)

_COOKIE_INTEL: list[tuple[str, str]] = [
    ("PHPSESSID", "PHP backend"),
    ("JSESSIONID", "Java / Tomcat"),
    ("ASP.NET_SessionId", "ASP.NET / IIS"),
    ("laravel_session", "Laravel (PHP)"),
    ("django_session", "Django (Python)"),
    ("__cfduid", "Cloudflare"),
    ("__utma", "Google Analytics"),
    ("_ga", "Google Analytics"),
    ("_gid", "Google Analytics"),
    ("wordpress_", "WordPress"),
    ("wp-settings", "WordPress"),
    ("Drupal.visitor", "Drupal"),
    ("CFID", "ColdFusion"),
    ("CFTOKEN", "ColdFusion"),
    ("connect.sid", "Node.js / Express"),
    ("rack.session", "Ruby Rack"),
]


def _cookie_intel_for_name(cookie_name: str) -> str | None:
    """Map Set-Cookie name to technology label (longest / most specific match)."""
    nl = cookie_name.lower()
    best: tuple[int, str] | None = None
    for prefix, label in _COOKIE_INTEL:
        pl = prefix.lower()
        if pl.endswith("_") and nl.startswith(pl):
            score = len(pl)
        elif nl == pl:
            score = len(pl) + 1
        else:
            continue
        if best is None or score > best[0]:
            best = (score, label)
    return best[1] if best else None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_cert_date(s: str) -> datetime | None:
    """Parse ASN.1 / getpeercert date string to UTC-aware datetime."""
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%Y%m%d%H%M%SZ"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _iso_date(d: datetime | None) -> str | None:
    if d is None:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _normalize_whois_date(val: Any) -> datetime | None:
    if val is None:
        return None
    if isinstance(val, list):
        val = next((x for x in val if x is not None), None)
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)
    if isinstance(val, str):
        for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                dt = datetime.strptime(val[:19], fmt[: len(val)])
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def _flatten_whois_blob(w: Any) -> str:
    try:
        return str(w).lower()
    except Exception:  # noqa: BLE001
        return ""


def _privacy_from_blob(blob: str) -> bool:
    return any(k in blob for k in PRIVACY_KEYWORDS)


def check_whois_binary() -> bool:
    """Check if system whois binary is available."""
    return shutil.which("whois") is not None


def is_brazilian_domain(domain: str) -> bool:
    """
    Returns True if domain uses a Brazilian ccTLD.
    Brazilian TLDs: .com.br, .org.br, .net.br, .edu.br,
                    .gov.br, .mil.br, .b.br, .ind.br
    """
    br_tlds = (
        ".com.br",
        ".org.br",
        ".net.br",
        ".edu.br",
        ".gov.br",
        ".mil.br",
        ".b.br",
        ".ind.br",
        ".br",
    )
    d = domain.lower().strip()
    return any(d.endswith(tld) for tld in br_tlds)


def _parse_nicbr_date(date_str: str | None) -> str | None:
    """Convert YYYYMMDD to ISO YYYY-MM-DD."""
    if not date_str or len(date_str) != 8 or not date_str.isdigit():
        return None
    return f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:8]}"


def whois_registrobr(
    domain: str,
    timeout: int,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Query WHOIS for Brazilian domains using system whois binary.
    The registro.br (NIC.br) uses a proprietary format that
    python-whois cannot parse correctly.

    Extracts: owner, registrar, nameservers, dates, status.
    Returns a full normalized dict like whois_domain() on success, or {} on failure.
    Never raises.
    """
    debug_log("subprocess", detail=f"whois {domain}", config=config)
    t0 = time.perf_counter()
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=float(timeout) + 5.0,
            errors="replace",
        )
        raw = (result.stdout or "") + (
            ("\n" + result.stderr) if result.stderr else ""
        )
        debug_log(
            "subprocess",
            detail="whois finished",
            result=f"exit {result.returncode} · {len(raw)} char(s) output",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    except Exception as e:  # noqa: BLE001 — contract: never raise
        debug_log(
            "subprocess",
            detail=f"whois {domain}",
            result=f"error: {type(e).__name__}",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
        return {}

    if not raw.strip():
        return {}

    rl = raw.lower()
    if "no match for" in rl or "not found" in rl and "domain" in rl:
        # NIC.br style failures; avoid treating as success
        if "registro" in rl or "nic.br" in rl:
            return {}

    def extract_one(pattern: str) -> str | None:
        match = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
        if not match:
            return None
        return match.group(1).strip()

    def extract_all(pattern: str) -> list[str]:
        found = re.findall(pattern, raw, re.IGNORECASE | re.MULTILINE)
        return [m.strip() for m in found if m and str(m).strip()]

    # Domain block uses YYYYMMDD; created line may include trailing comment e.g. "#18734"
    created = _parse_nicbr_date(extract_one(r"^created:\s+(\d{8})"))
    changed = _parse_nicbr_date(extract_one(r"^changed:\s+(\d{8})\b"))
    expires = _parse_nicbr_date(extract_one(r"^expires:\s+(\d{8})\b"))

    owner = extract_one(r"^owner:\s+(.+)$")
    responsible = extract_one(r"^responsible:\s+(.+)$")
    country = extract_one(r"^country:\s+(\S+)$") or "BR"

    # Multiple nserver lines; strip optional trailing IPv4 is avoided by \S+ (hostname only)
    nameservers = extract_all(r"^nserver:\s+(\S+)")
    nameservers = list(
        dict.fromkeys(ns.lower().rstrip(".") for ns in nameservers if ns)
    )

    status_vals = extract_all(r"^status:\s+(.+)$")
    emails = extract_all(r"^e-mail:\s+(\S+)")
    emails = list(dict.fromkeys(emails))

    # Strip NIC.br comment lines (%) so banner "Privacy Policy" does not trigger privacy_guard
    body_no_comments = "\n".join(
        ln
        for ln in raw.splitlines()
        if ln.strip() and not ln.lstrip().startswith("%")
    )
    privacy = _privacy_from_blob(body_no_comments.lower())
    if re.search(
        r"(?im)^(?:owner|responsible|person|e-mail):\s*.{0,100}\b("
        r"redacted|withheld|protected\s+for|dados\s+ocultos"
        r")\b",
        body_no_comments,
    ):
        privacy = True
    if re.search(r"(?im)^\s*status:.*\b(suspended|quarantine)\b", body_no_comments):
        privacy = True

    has_domain_line = bool(
        re.search(r"^domain:\s*\S+", raw, re.IGNORECASE | re.MULTILINE)
    )
    if not (
        "nic.br" in rl
        or "registro.br" in rl
        or (has_domain_line and (nameservers or owner or expires))
    ):
        # Unlikely to be a NIC.br response — let caller fall back to python-whois
        return {}

    days_to_expire: int | None = None
    if expires:
        try:
            exp_dt = datetime.strptime(expires, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            days_to_expire = max(0, (exp_dt - _now_utc()).days)
        except ValueError:
            days_to_expire = None

    org = owner or responsible

    return {
        "domain_name": domain,
        "registrar": "Registro.br (NIC.br)",
        "registered_on": created,
        "expires_on": expires,
        "updated_on": changed,
        "days_to_expire": days_to_expire,
        "status": status_vals,
        "nameservers": nameservers,
        "emails": emails,
        "org": org,
        "responsible": responsible,
        "country": country,
        "privacy_guard": privacy,
        "raw": raw[:20000],
        "error": False,
        "error_message": None,
    }


def whois_domain(
    domain: str,
    timeout: int,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Query WHOIS for a domain and extract structured intelligence.
    Brazilian (.br) domains use the system whois binary + NIC.br parser;
    others use python-whois.
    Returns normalized dict; failures become partial rows with error flag.
    Never raises.
    """
    out: dict[str, Any] = {
        "domain_name": domain,
        "registrar": None,
        "registered_on": None,
        "expires_on": None,
        "updated_on": None,
        "days_to_expire": None,
        "status": [],
        "nameservers": [],
        "emails": [],
        "org": None,
        "country": None,
        "privacy_guard": False,
        "raw": "",
        "error": False,
        "error_message": None,
    }

    if is_brazilian_domain(domain):
        if not check_whois_binary():
            console.print(
                Text(
                    "   [!] whois binary not found — install with: sudo apt install whois",
                    style=C_WARN,
                )
            )
        else:
            br_out = whois_registrobr(domain, timeout, config)
            if br_out:
                return br_out

    debug_log("info", detail=f"python-whois lookup {domain}", config=config)
    try:
        socket.setdefaulttimeout(float(timeout))
        w = whois.whois(domain)
        socket.setdefaulttimeout(None)
    except Exception as e:  # noqa: BLE001
        socket.setdefaulttimeout(None)
        out["error"] = True
        out["error_message"] = str(e)
        out["raw"] = str(e)
        return out

    try:
        blob = _flatten_whois_blob(w)
        out["raw"] = str(w)[:20000] if w else ""
        out["privacy_guard"] = _privacy_from_blob(blob)

        dn = getattr(w, "domain_name", None)
        if isinstance(dn, list):
            out["domain_name"] = dn[0] if dn else domain
        elif dn:
            out["domain_name"] = str(dn)

        reg = getattr(w, "registrar", None)
        if reg:
            out["registrar"] = reg if isinstance(reg, str) else str(reg)

        cr = _normalize_whois_date(getattr(w, "creation_date", None))
        ex = _normalize_whois_date(getattr(w, "expiration_date", None))
        up = _normalize_whois_date(getattr(w, "updated_date", None))
        out["registered_on"] = _iso_date(cr)
        out["expires_on"] = _iso_date(ex)
        out["updated_on"] = _iso_date(up)
        if ex:
            delta = ex - _now_utc()
            out["days_to_expire"] = max(0, delta.days)

        st = getattr(w, "status", None)
        if isinstance(st, str):
            out["status"] = [st]
        elif isinstance(st, list):
            out["status"] = [str(s) for s in st if s]
        else:
            out["status"] = []

        ns = getattr(w, "name_servers", None) or getattr(w, "nameservers", None)
        if isinstance(ns, str):
            out["nameservers"] = [ns.lower().rstrip(".")]
        elif isinstance(ns, list):
            out["nameservers"] = [
                str(x).lower().rstrip(".") for x in ns if x
            ]

        em = getattr(w, "emails", None)
        if isinstance(em, str):
            out["emails"] = [em]
        elif isinstance(em, list):
            out["emails"] = [str(x) for x in em if x]

        org = getattr(w, "org", None)
        if org:
            out["org"] = org if isinstance(org, str) else str(org)

        country = getattr(w, "country", None)
        if country:
            out["country"] = country if isinstance(country, str) else str(country)

        if not out["privacy_guard"] and not out["org"] and not out["emails"]:
            out["privacy_guard"] = _privacy_from_blob(blob) or bool(
                "redacted" in blob or "data protected" in blob
            )
    except Exception as e:  # noqa: BLE001
        out["error"] = True
        out["error_message"] = str(e)
        out["errors_detail"] = str(e)

    return out


def whois_ip(ip: str, timeout: int) -> dict[str, Any]:
    """
    Query WHOIS for an IP (ASN, ISP, range, abuse).
    Uses python-whois first, then ipwhois fallback.
    Never raises.
    """
    out: dict[str, Any] = {
        "ip": ip,
        "asn": None,
        "asn_org": None,
        "isp": None,
        "org": None,
        "country": None,
        "city": None,
        "ip_range": None,
        "abuse_email": None,
        "raw": "",
        "error": False,
        "error_message": None,
    }
    try:
        socket.setdefaulttimeout(float(timeout))
        w = whois.whois(ip)
        socket.setdefaulttimeout(None)
        if w:
            out["raw"] = str(w)[:20000]
            # Best-effort attribute mapping (varies by registry)
            for attr, key in (
                ("asn", "asn"),
                ("asn_description", "asn_org"),
                ("org", "org"),
                ("address", "org"),
                ("country", "country"),
                ("city", "city"),
                ("emails", "abuse_email"),
            ):
                v = getattr(w, attr, None)
                if v and not out.get(key):
                    if attr == "emails" and isinstance(v, list):
                        out["abuse_email"] = next(
                            (str(x) for x in v if "abuse" in str(x).lower()),
                            str(v[0]) if v else None,
                        )
                    elif attr == "emails" and isinstance(v, str):
                        out["abuse_email"] = v
                    else:
                        out[key] = v if isinstance(v, str) else str(v)
    except Exception:  # noqa: BLE001
        socket.setdefaulttimeout(None)

    if IPWhois is not None:
        try:
            res = IPWhois(ip).lookup_whois(retry_count=0)
            out["raw"] = (out["raw"] or "") + "\n" + str(res)[:15000]
            asn = res.get("asn") or res.get("asn_registry")
            if asn and not out["asn"]:
                out["asn"] = f"AS{asn}" if str(asn).isdigit() else str(asn)
            desc = res.get("asn_description")
            if desc:
                out["asn_org"] = desc
                out["isp"] = out["isp"] or desc
            net = res.get("network", {}) or {}
            if isinstance(net, dict):
                cidr = net.get("cidr")
                if cidr:
                    out["ip_range"] = cidr
                if net.get("country") and not out["country"]:
                    out["country"] = net["country"]
            for contact in res.get("nets", []) or []:
                if isinstance(contact, dict):
                    if contact.get("cidr") and not out["ip_range"]:
                        out["ip_range"] = contact["cidr"]
                    if contact.get("abuse_emails") and not out["abuse_email"]:
                        ae = contact["abuse_emails"]
                        out["abuse_email"] = (
                            ae.split("\n")[0] if isinstance(ae, str) else str(ae)
                        )
                    if contact.get("city") and not out["city"]:
                        out["city"] = contact["city"]
        except Exception as e:  # noqa: BLE001
            if not out["raw"]:
                out["error"] = True
                out["error_message"] = str(e)
    elif not out["raw"]:
        out["error"] = True
        out["error_message"] = "ipwhois not installed — pip install ipwhois"

    return out


def _cn_from_x509_name(name: Any) -> str | None:
    """Extract first commonName from an x509.Name (cryptography)."""
    if x509 is None or name is None:
        return None
    try:
        for attr in name:
            if attr.oid == x509.NameOID.COMMON_NAME:
                return str(attr.value)
    except Exception:  # noqa: BLE001
        return None
    return None


def _intel_from_der(der: bytes) -> dict[str, Any] | None:
    """
    Parse peer certificate DER when ssl.getpeercert() dict is empty (OpenSSL 3 / Py3.13+).
    Returns fields compatible with check_ssl output subset.
    """
    if x509 is None or default_backend is None or not der:
        return None
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception:  # noqa: BLE001
        return None
    subj_cn = _cn_from_x509_name(cert.subject)
    iss_cn = _cn_from_x509_name(cert.issuer)
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for n in ext.value:
            if isinstance(n, x509.DNSName):
                sans.append(str(n.value))
    except x509.ExtensionNotFound:
        pass
    exp = cert.not_valid_after_utc
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    issued = cert.not_valid_before_utc
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    self_signed = cert.subject == cert.issuer
    return {
        "issued_to": subj_cn,
        "issuer": iss_cn or str(cert.issuer),
        "expires_on": _iso_date(exp),
        "days_to_expire": max(0, (exp - _now_utc()).days),
        "sans": sans,
        "self_signed": self_signed,
        "valid": True,
    }


def check_ssl(host: str, timeout: int) -> dict[str, Any]:
    """
    TLS handshake intel: cert fields, SANs, protocol, cipher.
    Never raises — returns error fields on failure.
    """
    empty: dict[str, Any] = {
        "valid": False,
        "issuer": None,
        "issued_to": None,
        "expires_on": None,
        "days_to_expire": None,
        "sans": [],
        "tls_version": None,
        "cipher": None,
        "self_signed": False,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=float(timeout)) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                vers = ssock.version()
                ciph = ssock.cipher()
                empty["tls_version"] = vers
                if ciph:
                    empty["cipher"] = ciph[0]
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True)
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", ()))
                    iss = dict(x[0] for x in cert.get("issuer", ()))
                    empty["issued_to"] = subj.get("commonName")
                    empty["issuer"] = iss.get("commonName") or str(iss)
                    na = cert.get("notAfter")
                    if na:
                        exp = _parse_cert_date(na)
                        empty["expires_on"] = _iso_date(exp)
                        if exp:
                            empty["days_to_expire"] = max(0, (exp - _now_utc()).days)
                    san = cert.get("subjectAltName") or ()
                    empty["sans"] = [v for k, v in san if k.upper() == "DNS"]
                    empty["valid"] = True
                    empty["self_signed"] = (
                        iss.get("commonName") == subj.get("commonName")
                        and iss.get("commonName") is not None
                    )
                elif der:
                    parsed = _intel_from_der(der)
                    if parsed:
                        empty.update(parsed)
                    else:
                        empty["valid"] = True
                        empty["error"] = "certificate present but could not be parsed"
                else:
                    empty["error"] = "no certificate from peer"
    except Exception as e:  # noqa: BLE001
        empty["error"] = str(e)
    return empty


def extract_from_html(html: str) -> list[str]:
    """
    Pull technology hints from meta generator, asset URLs, comments.
    """
    found: list[str] = []
    if not html:
        return found

    for m in re.finditer(
        r'<meta\s+[^>]*name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
        html,
        re.I,
    ):
        found.append(f"Meta generator: {m.group(1).strip()}")

    if re.search(r"/wp-content/", html, re.I):
        found.append("WordPress paths (/wp-content/)")
    if re.search(r"/sites/default/", html, re.I):
        found.append("Drupal paths (/sites/default/)")
    if re.search(r"/typo3/", html, re.I):
        found.append("TYPO3 paths (/typo3/)")
    if re.search(r"joomla", html, re.I) and "<!--" in html:
        found.append("Possible Joomla (HTML/comments)")
    if re.search(r"wix\.com|wixstatic", html, re.I):
        found.append("Wix assets")
    if re.search(r"react@|react-dom|__NEXT_DATA__", html, re.I):
        found.append("React / possible Next.js")
    if "__NEXT_DATA__" in html:
        found.append("Next.js (__NEXT_DATA__)")

    for cm in re.finditer(r"<!--([^>]{4,120})-->", html):
        chunk = cm.group(1).strip()
        if any(
            k in chunk.lower()
            for k in ("wordpress", "joomla", "drupal", "version", "wp ")
        ):
            found.append(f"HTML comment: {chunk[:80]}")

    return list(dict.fromkeys(found))


def http_fingerprint(
    target: Target,
    timeout: int,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Single GET to HTTPS then HTTP root; capture headers, cookies, HTML snippet.
    Never raises.
    """
    host = target.value
    headers_req = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    result: dict[str, Any] = {
        "reachable": False,
        "protocol": None,
        "status_code": None,
        "status_reason": None,
        "final_url": None,
        "redirect_chain": [],
        "headers": {},
        "cookies": {},
        "cookie_intel": [],
        "html_intel": [],
        "ssl": {},
        "body_sample": "",
    }

    session = requests.Session()
    session.verify = False
    if hasattr(session, "max_redirects"):
        session.max_redirects = 5

    def _attempt(url: str) -> requests.Response | None:
        try:
            return session.get(
                url,
                headers=headers_req,
                timeout=float(timeout),
                allow_redirects=True,
            )
        except requests.exceptions.SSLError:
            return None
        except requests.exceptions.RequestException:
            return None

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        debug_log("http", detail=f"GET {url} (fingerprint)", config=config)
        t_http = time.perf_counter()
        resp = _attempt(url)
        if resp is None:
            debug_log(
                "http",
                detail=f"{scheme.upper()} fingerprint",
                result="no response (SSL error or connection failed)",
                elapsed=time.perf_counter() - t_http,
                config=config,
            )
            continue
        debug_log(
            "http",
            detail=f"{scheme.upper()} fingerprint response",
            result=f"status {resp.status_code} · final URL len={len(resp.url or '')}",
            elapsed=time.perf_counter() - t_http,
            config=config,
        )
        result["reachable"] = True
        result["protocol"] = scheme
        result["status_code"] = resp.status_code
        result["status_reason"] = getattr(resp, "reason", None) or ""
        result["final_url"] = resp.url
        hops = list(resp.history) + [resp]
        if len(hops) > 1:
            parts: list[str] = []
            for i, h in enumerate(hops):
                if i + 1 < len(hops):
                    parts.append(f"{h.url} →")
                else:
                    parts.append(h.url)
            result["redirect_chain"] = [" ".join(parts)]
        else:
            result["redirect_chain"] = []
        result["headers"] = {k: v for k, v in resp.headers.items()}
        result["cookies"] = {k: resp.cookies.get(k) for k in resp.cookies.keys()}
        ci: list[str] = []
        for ck in result["cookies"]:
            lab = _cookie_intel_for_name(ck)
            if lab:
                ci.append(f"{ck} → {lab}")
        result["cookie_intel"] = ci
        text = resp.text[:80000] if resp.text else ""
        result["body_sample"] = text[:4000]
        result["html_intel"] = extract_from_html(text)
        if scheme == "https":
            final_u = (resp.url or "").lower()
            ssl_host = host
            if final_u.startswith("https://"):
                ssl_host = urlparse(resp.url).hostname or host
            result["ssl"] = check_ssl(ssl_host, timeout)
        else:
            result["ssl"] = {}
        break

    return result


def build_tech_stack(
    http_data: dict[str, Any],
) -> dict[str, Any]:
    """
    Correlate headers, cookies, HTML intel, and SSL into a stack model.
    """
    hdrs = {k.lower(): v for k, v in (http_data.get("headers") or {}).items()}
    cookies = http_data.get("cookies") or {}
    cookie_intel_lines = http_data.get("cookie_intel") or []
    html_i = list(http_data.get("html_intel") or []) + list(cookie_intel_lines)
    ssl_i = http_data.get("ssl") or {}

    server = hdrs.get("server", "")
    web_name, web_ver = None, None
    if server:
        parts = server.split("/", 1)
        web_name = parts[0].strip() or None
        web_ver = parts[1].strip() if len(parts) > 1 else None

    backend = None
    backend_conf = "LOW"
    xpb = hdrs.get("x-powered-by")
    if xpb:
        backend = xpb.split(",")[0].strip()
        backend_conf = "HIGH"

    framework = None
    fw_conf = "MEDIUM"
    cookie_names = " ".join(cookies.keys()).lower()
    if "laravel_session" in cookie_names:
        framework = "Laravel"
        fw_conf = "HIGH"
    elif "django_session" in cookie_names:
        framework = "Django"
        fw_conf = "HIGH"
    if hdrs.get("x-powered-by") and "express" in hdrs["x-powered-by"].lower():
        framework = framework or "Express"
        fw_conf = "HIGH"

    cms = None
    cms_ver = None
    cms_conf: str | None = None
    gen = hdrs.get("x-generator")
    if gen:
        cms = gen.split()[0] if gen else gen
        cms_conf = "HIGH"
    if "wordpress" in cookie_names or hdrs.get("x-wp-super-cache"):
        cms = "WordPress"
        cms_conf = "HIGH"
    if hdrs.get("x-drupal-cache") or "drupal" in cookie_names:
        cms = "Drupal"
        cms_conf = "HIGH"
    for line in html_i:
        if "WordPress" in line:
            cms = cms or "WordPress"
            cms_conf = "HIGH"
        if "Drupal" in line:
            cms = cms or "Drupal"
            cms_conf = "HIGH"

    cdn = None
    cdn_conf: str | None = None
    if hdrs.get("cf-ray"):
        cdn = "Cloudflare"
        cdn_conf = "HIGH"
    elif hdrs.get("x-amz-cf-id") or "cloudfront" in hdrs.get("via", "").lower():
        cdn = "AWS CloudFront"
        cdn_conf = "HIGH"
    elif hdrs.get("x-azure-ref"):
        cdn = "Azure"
        cdn_conf = "HIGH"

    analytics: list[str] = []
    if any(x in cookie_names for x in ("_ga", "_gid", "__utma")):
        analytics.append("Google Analytics")

    hsts = bool(hdrs.get("strict-transport-security"))
    csp = bool(hdrs.get("content-security-policy"))
    x_frame = bool(hdrs.get("x-frame-options"))
    acao = (hdrs.get("access-control-allow-origin") or "").strip()
    cors = "wildcard" if acao == "*" else ("set" if acao else "none")

    return {
        "web_server": {
            "name": web_name,
            "version": web_ver,
            "confidence": "HIGH" if web_name else "LOW",
        },
        "backend": {"name": backend, "version": None, "confidence": backend_conf},
        "framework": {"name": framework, "version": None, "confidence": fw_conf},
        "cms": {"name": cms, "version": cms_ver, "confidence": cms_conf},
        "cdn": {"name": cdn, "version": None, "confidence": cdn_conf or "LOW"},
        "analytics": analytics,
        "security": {
            "hsts": hsts,
            "csp": csp,
            "x_frame": x_frame,
            "cors": cors,
        },
        "ssl": ssl_i,
        "raw_headers": http_data.get("headers") or {},
        "html_intel": http_data.get("html_intel") or [],
        "cookie_intel": cookie_intel_lines,
    }


def compute_security_flags(
    tech_stack: dict[str, Any],
    http_data: dict[str, Any],
) -> list[dict[str, str]]:
    """Derive actionable security observations."""
    flags: list[dict[str, str]] = []
    sec = tech_stack.get("security") or {}
    hdrs = {k.lower(): v for k, v in (http_data.get("headers") or {}).items()}
    ssl_i = tech_stack.get("ssl") or {}
    server = hdrs.get("server", "")

    if http_data.get("reachable") and not sec.get("hsts"):
        flags.append(
            {
                "severity": "MEDIUM",
                "message": "HSTS not configured — HTTP downgrade possible",
            }
        )
    if http_data.get("reachable") and not sec.get("csp"):
        flags.append(
            {
                "severity": "MEDIUM",
                "message": "No Content-Security-Policy header",
            }
        )
    if sec.get("cors") == "wildcard":
        flags.append(
            {
                "severity": "HIGH",
                "message": "CORS wildcard — any origin allowed",
            }
        )
    if http_data.get("reachable") and not sec.get("x_frame"):
        flags.append(
            {
                "severity": "LOW",
                "message": "No X-Frame-Options — clickjacking possible",
            }
        )
    if server and "/" in server:
        flags.append(
            {
                "severity": "LOW",
                "message": f"Server version exposed: {server}",
            }
        )
    if ssl_i.get("self_signed"):
        flags.append(
            {"severity": "HIGH", "message": "Self-signed SSL certificate"}
        )
    ssl_days = ssl_i.get("days_to_expire")
    if isinstance(ssl_days, int) and ssl_days < 30 and ssl_days >= 0:
        flags.append(
            {
                "severity": "CRITICAL",
                "message": f"SSL expires in {ssl_days} days",
            }
        )
    if hdrs.get("x-powered-by"):
        flags.append(
            {
                "severity": "LOW",
                "message": f"Backend exposed via X-Powered-By: {hdrs['x-powered-by']}",
            }
        )
    return flags


def _technologies_flat(tech: dict[str, Any]) -> list[str]:
    out: list[str] = []
    ws = tech.get("web_server") or {}
    if ws.get("name"):
        s = ws["name"]
        if ws.get("version"):
            s += f" {ws['version']}"
        out.append(s)
    be = tech.get("backend") or {}
    if be.get("name"):
        out.append(be["name"])
    fw = tech.get("framework") or {}
    if fw.get("name"):
        out.append(fw["name"])
    cms = tech.get("cms") or {}
    if cms.get("name"):
        out.append(cms["name"])
    cdn = tech.get("cdn") or {}
    if cdn.get("name"):
        out.append(cdn["name"])
    out.extend(tech.get("analytics") or [])
    for line in tech.get("cookie_intel") or []:
        if " → " in line:
            out.append(line.split(" → ", 1)[1].strip())
    return list(dict.fromkeys(out))


def _render_header(title: str) -> None:
    p = Panel(
        Text(f"  WHOIS + FINGERPRINT  ·  {title}", style=f"bold {C_PRI}"),
        border_style=C_ACCENT,
        box=box.DOUBLE,
        width=min(console.size.width, 82) if console.size else 82,
    )
    console.print(p)


def _years_ago(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        d = datetime.strptime(iso, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        years = (_now_utc() - d).days // 365
        return f"  ({years} years ago)"
    except ValueError:
        return ""


def _print_whois_domain(w: dict[str, Any]) -> None:
    console.print(Text("\n [WHOIS] Domain Registration", style=f"bold {C_WARN}"))
    exp = w.get("expires_on")
    days = w.get("days_to_expire")
    exp_style = C_OK
    exp_note = ""
    if isinstance(days, int):
        if days < 30:
            exp_style = C_ERR
            exp_note = "  [!!!] EXPIRES SOON"
        elif days < 90:
            exp_style = C_WARN
            exp_note = f"  [!] Expiring in {days} days"

    def line(sym: str, label: str, val: Any, val_style: str = C_DIM) -> None:
        console.print(
            Text.assemble(
                (f"   {sym} ", C_MUTED),
                (f"{label:<14}", C_DIM),
                (": ", C_MUTED),
                (str(val) if val is not None else "—", val_style),
            )
        )

    line("├──", "Registrar", w.get("registrar"))
    line("├──", "Registered", f"{w.get('registered_on') or '—'}{_years_ago(w.get('registered_on'))}")
    exp_txt = f"{exp or '—'}"
    if isinstance(days, int) and exp:
        exp_txt += f"  ({days} days){exp_note}"
    console.print(
        Text.assemble(
            ("   ├── ", C_MUTED),
            ("Expires       ", C_DIM),
            (": ", C_MUTED),
            (exp_txt, exp_style),
        )
    )
    line("├──", "Updated", w.get("updated_on"))
    line("├──", "Org", w.get("org"))
    if w.get("responsible"):
        line("├──", "Responsible", w.get("responsible"))
    line("├──", "Country", w.get("country"))
    ns = " · ".join(w.get("nameservers") or []) or "—"
    line("├──", "Nameservers", ns)
    priv = w.get("privacy_guard")
    priv_txt = "protected (privacy service)" if priv else "not protected"
    priv_style = C_WARN if (not priv and (w.get("emails"))) else C_DIM
    if priv:
        console.print(
            Text.assemble(
                ("   └── ", C_MUTED),
                ("Privacy       ", C_DIM),
                (": ", C_MUTED),
                (priv_txt, C_WARN),
            )
        )
        console.print(
            Text(
                "       [i] Privacy Guard detected — registrant data hidden",
                style=C_MUTED,
            )
        )
    else:
        em = ", ".join(w.get("emails") or []) or "—"
        if w.get("emails"):
            console.print(
                Text.assemble(
                    ("   └── ", C_MUTED),
                    ("Privacy       ", C_DIM),
                    (": ", C_MUTED),
                    (priv_txt, C_DIM),
                )
            )
            console.print(
                Text(f"       [i] Contact emails visible: {em}", style=C_WARN)
            )
        else:
            line("└──", "Privacy", priv_txt, priv_style)


def _print_whois_ip(w: dict[str, Any]) -> None:
    console.print(Text("\n [WHOIS] IP Intelligence", style=f"bold {C_WARN}"))
    cc = w.get("country") or "—"
    city = w.get("city")
    if city:
        cc = f"{cc}  ({city})"

    def line(sym: str, label: str, val: Any) -> None:
        console.print(
            Text.assemble(
                (f"   {sym} ", C_MUTED),
                (f"{label:<14}", C_DIM),
                (": ", C_MUTED),
                (str(val) if val else "—", C_DIM),
            )
        )

    line("├──", "ASN", w.get("asn"))
    line("├──", "ISP", w.get("isp") or w.get("asn_org"))
    line("├──", "Org", w.get("org"))
    line("├──", "Country", cc)
    line("├──", "IP Range", w.get("ip_range"))
    line("└──", "Abuse", w.get("abuse_email"))


def _print_http(http: dict[str, Any]) -> None:
    if not http.get("reachable"):
        console.print(
            Text(
                "\n [HTTP] Target not reachable (HTTPS/HTTP)",
                style=C_WARN,
            )
        )
        return
    proto = http.get("protocol")
    code = http.get("status_code")
    reason = (http.get("status_reason") or "").strip()
    final = http.get("final_url") or ""
    status_tail = ""
    if code is not None:
        status_tail = f"  ({code} {reason})".rstrip() if reason else f"  ({code})"
    console.print(
        Text.assemble(
            ("\n [HTTP] Fingerprint → ", f"bold {C_PRI}"),
            (final, C_DIM),
            (status_tail, C_MUTED),
        )
    )
    if http.get("redirect_chain"):
        console.print(
            Text(
                f"   Redirect chain   : {' '.join(http['redirect_chain'])}",
                style=C_MUTED,
            )
        )
    ssl_i = http.get("ssl") or {}
    if ssl_i.get("issuer") or ssl_i.get("expires_on"):
        console.print(Text("\n [SSL]  Certificate", style=f"bold {C_WARN}"))
        sans = ssl_i.get("sans") or []
        san_txt = " · ".join(sans[:12]) if sans else "—"
        if len(sans) > 12:
            san_txt += f" · … (+{len(sans) - 12})"
        dte = ssl_i.get("days_to_expire")
        exp_lbl = ssl_i.get("expires_on") or "—"
        if isinstance(dte, int):
            exp_lbl += f"  ({dte} days)"
        console.print(
            Text.assemble(
                ("   ├── ", C_MUTED),
                ("Issuer       ", C_DIM),
                (": ", C_MUTED),
                (str(ssl_i.get("issuer") or "—"), C_DIM),
            )
        )
        console.print(
            Text.assemble(
                ("   ├── ", C_MUTED),
                ("Expires      ", C_DIM),
                (": ", C_MUTED),
                (exp_lbl, C_OK if isinstance(dte, int) and dte > 90 else C_WARN),
            )
        )
        console.print(
            Text.assemble(
                ("   ├── ", C_MUTED),
                ("TLS          ", C_DIM),
                (": ", C_MUTED),
                (str(ssl_i.get("tls_version") or "—"), C_PRI),
            )
        )
        console.print(
            Text.assemble(
                ("   └── ", C_MUTED),
                ("SANs         ", C_DIM),
                (": ", C_MUTED),
                (san_txt, C_PRI),
            )
        )
        if sans:
            console.print(
                Text(
                    f"       ↑ {len(sans)} name(s) from certificate (subdomain intel)",
                    style=C_MUTED,
                )
            )


def _print_stack(tech: dict[str, Any]) -> None:
    console.print(Text("\n [STACK] Technology Intelligence", style=f"bold {C_PRI}"))
    hdrs = tech.get("raw_headers") or {}

    def src_for(name: str) -> str:
        low = {k.lower(): v for k, v in hdrs.items()}
        if name == "web" and low.get("server"):
            return "[header: Server]"
        if name == "cdn" and low.get("cf-ray"):
            return "[header: CF-Ray]"
        if name == "backend" and low.get("x-powered-by"):
            return "[header: X-Powered-By]"
        if name == "cookie":
            return "[cookie]"
        return "[correlation]"

    ws = tech.get("web_server") or {}
    val = f"{ws.get('name') or '—'}"
    if ws.get("version"):
        val += f"/{ws['version']}"
    console.print(
        Text.assemble(
            ("   ├── ", C_MUTED),
            ("Web Server   ", C_DIM),
            (": ", C_MUTED),
            (val.ljust(28), C_PRI),
            (src_for("web"), C_MUTED),
        )
    )
    be = tech.get("backend") or {}
    console.print(
        Text.assemble(
            ("   ├── ", C_MUTED),
            ("Backend      ", C_DIM),
            (": ", C_MUTED),
            (str(be.get("name") or "—").ljust(28), C_DIM),
            (src_for("backend") if be.get("name") else "[inferred]", C_MUTED),
        )
    )
    fw = tech.get("framework") or {}
    ck_hint = "—"
    if fw.get("name"):
        ck_hint = src_for("cookie")
    elif tech.get("cookie_intel"):
        ck_hint = "[cookie names]"
    console.print(
        Text.assemble(
            ("   ├── ", C_MUTED),
            ("Framework    ", C_DIM),
            (": ", C_MUTED),
            (str(fw.get("name") or "—").ljust(28), C_DIM),
            (ck_hint, C_MUTED),
        )
    )
    cms = tech.get("cms") or {}
    console.print(
        Text.assemble(
            ("   ├── ", C_MUTED),
            ("CMS          ", C_DIM),
            (": ", C_MUTED),
            (str(cms.get("name") or "—").ljust(28), C_DIM),
            ("[headers/html]", C_MUTED),
        )
    )
    cdn = tech.get("cdn") or {}
    console.print(
        Text.assemble(
            ("   ├── ", C_MUTED),
            ("CDN          ", C_DIM),
            (": ", C_MUTED),
            (str(cdn.get("name") or "—").ljust(28), C_DIM),
            (src_for("cdn") if cdn.get("name") else "—", C_MUTED),
        )
    )
    an = ", ".join(tech.get("analytics") or []) or "—"
    console.print(
        Text.assemble(
            ("   └── ", C_MUTED),
            ("Analytics    ", C_DIM),
            (": ", C_MUTED),
            (an, C_DIM),
        )
    )


def _print_flags(flags: list[dict[str, str]], quiet: bool = False) -> None:
    if not flags:
        return
    shown = (
        [f for f in flags if f.get("severity") in ("CRITICAL", "HIGH")]
        if quiet
        else flags
    )
    if not shown:
        return
    console.print(Text("\n [FLAGS] Security Issues Detected", style=f"bold {C_ERR}"))
    sev_style = {"CRITICAL": C_ERR, "HIGH": C_ERR, "MEDIUM": C_WARN, "LOW": C_MUTED}
    for i, fl in enumerate(shown):
        sym = "└──" if i == len(shown) - 1 else "├──"
        sev = fl.get("severity", "LOW")
        console.print(
            Text.assemble(
                (f"   {sym} ", C_MUTED),
                (f"[{sev}]", sev_style.get(sev, C_DIM)),
                ("     ", ""),
                (fl.get("message", ""), C_DIM),
            )
        )


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    WHOIS (domain or IP) + one-shot HTTP/HTTPS fingerprint + SSL + intel.
    """
    t0 = time.perf_counter()
    timeout = int(config.get("timeout") or DEFAULT_TIMEOUT)
    timeout = max(1, timeout)
    quiet = bool(config.get("quiet", False))
    errors: list[str] = []

    base: dict[str, Any] = {
        "module": "whois_scan",
        "target": target.value,
        "status": "success",
        "whois": {},
        "http": {
            "reachable": False,
            "protocol": None,
            "status_code": None,
            "redirect_chain": [],
            "headers": {},
            "cookies": {},
            "ssl": {},
        },
        "tech_stack": {},
        "security_flags": [],
        "technologies": [],
        "errors": errors,
    }

    if target.is_cidr():
        _render_header(target.value)
        console.print(
            Text("  [SKIP] WHOIS scan — use a domain or single IP.", style=C_WARN)
        )
        base["status"] = "skipped"
        return base

    _render_header(target.value)

    # Phase 1 — WHOIS
    whois_data: dict[str, Any] = {}
    if target.is_domain():
        whois_data = whois_domain(target.value, timeout, config)
        if whois_data.get("error") and whois_data.get("error_message"):
            em = whois_data["error_message"]
            errors.append(f"WHOIS domain: {em}")
            if "429" in em or "rate" in em.lower():
                console.print(
                    Text("   [!] WHOIS rate limit / throttling suspected", style=C_WARN),
                )
        if not quiet:
            _print_whois_domain(whois_data)
    else:
        whois_data = whois_ip(target.value, timeout)
        if whois_data.get("error") and whois_data.get("error_message"):
            errors.append(f"WHOIS IP: {whois_data['error_message']}")
        if not quiet:
            _print_whois_ip(whois_data)

    base["whois"] = whois_data

    if bool(config.get("verbose")) and (whois_data.get("raw") or ""):
        raw_preview = str(whois_data["raw"])[:12000]
        console.print(
            Panel(
                raw_preview,
                title="[verbose] WHOIS raw",
                border_style=C_MUTED,
                expand=False,
            )
        )

    # Phase 2 — HTTP fingerprint (independent)
    http_data = http_fingerprint(target, timeout, config)
    if not http_data.get("reachable"):
        errors.append("HTTP(S) root not reachable")
    base["http"] = {
        "reachable": http_data["reachable"],
        "protocol": http_data["protocol"],
        "status_code": http_data["status_code"],
        "status_reason": http_data.get("status_reason"),
        "final_url": http_data.get("final_url"),
        "redirect_chain": http_data["redirect_chain"],
        "headers": http_data["headers"],
        "cookies": http_data["cookies"],
        "ssl": http_data.get("ssl") or {},
    }

    tech = build_tech_stack(http_data)
    base["tech_stack"] = tech
    flags = compute_security_flags(tech, http_data)
    base["security_flags"] = flags
    base["technologies"] = _technologies_flat(tech)

    if not quiet:
        _print_http(http_data)
        _print_stack(tech)
    _print_flags(flags, quiet=quiet)

    elapsed = time.perf_counter() - t0
    ssl_i = tech.get("ssl") or {}
    ssl_ok = bool(ssl_i.get("valid"))
    ssl_days = ssl_i.get("days_to_expire")
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in flags:
        s = f.get("severity", "LOW")
        if s in sev_counts:
            sev_counts[s] += 1
        else:
            sev_counts["LOW"] += 1

    console.print(
        Text.assemble(
            ("\n [✓] WHOIS + fingerprint complete\n", f"bold {C_PRI}"),
            (f"     Technologies : {len(base['technologies'])} detected\n", C_DIM),
            (
                f"     Security     : {len(flags)} flags "
                f"({sev_counts['CRITICAL']} crit · {sev_counts['HIGH']} high · "
                f"{sev_counts['MEDIUM']} medium · {sev_counts['LOW']} low)\n",
                C_DIM,
            ),
            (
                "     SSL          : "
                f"{'valid' if ssl_ok else 'n/a or invalid'}"
                f"{f' · {ssl_days} days remaining' if isinstance(ssl_days, int) else ''}\n",
                C_DIM,
            ),
            (f"     Duration     : {elapsed:.2f}s", C_DIM),
        )
    )

    if whois_data.get("error") and not http_data.get("reachable"):
        base["status"] = "error"
        base["error"] = "WHOIS and HTTP both failed partially — see errors[]"

    return base
