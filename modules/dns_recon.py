"""
GhostOpcode DNS recon module — passive queries, AXFR probe, technology inference.
"""

from __future__ import annotations

import re
import time
from typing import Any

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from utils.base_module import make_finding
from utils.output import debug_log
from utils.target_parser import Target

# Terminal palette (aligned with framework identity)
C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_ACCENT = "#8B9CA8"

console = Console(highlight=False, force_terminal=True)

# Common SRV prefixes worth probing at zone apex (non-destructive lookups)
_SRV_PROBES = (
    "_sip._tcp",
    "_sip._udp",
    "_xmpp-client._tcp",
    "_xmpp-server._tcp",
    "_ldap._tcp",
    "_kerberos._tcp",
    "_imap._tcp",
    "_submission._tcp",
    "_autodiscover._tcp",
)


def query_record(
    domain: str,
    record_type: str,
    timeout: int,
    config: dict[str, Any] | None = None,
) -> list[str]:
    """
    Query a single DNS record type.

    Returns list of strings with results, or empty list on any failure.
    Never raises.
    """
    debug_log(
        "dns",
        detail=f"query {record_type} for {domain}",
        config=config,
    )
    t0 = time.perf_counter()
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = float(timeout)
        resolver.lifetime = float(timeout)
        ans = resolver.resolve(domain, record_type)
        out = [str(r) for r in ans]
        debug_log(
            "dns",
            detail=f"{record_type} result",
            result=f"{len(out)} record(s)",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
        return out
    except dns.resolver.NXDOMAIN:
        debug_log(
            "dns",
            detail=f"{record_type} result",
            result="NXDOMAIN",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
        return []
    except dns.resolver.NoAnswer:
        debug_log(
            "dns",
            detail=f"{record_type} result",
            result="no answer",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
        return []
    except dns.resolver.Timeout:
        debug_log(
            "dns",
            detail=f"{record_type} result",
            result=f"timeout after {timeout}s — no answer",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
        return []
    except dns.exception.DNSException as e:
        debug_log(
            "dns",
            detail=f"{record_type} result",
            result=f"DNSException: {type(e).__name__}",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
        return []
    except OSError as e:
        debug_log(
            "dns",
            detail=f"{record_type} result",
            result=f"OSError: {type(e).__name__}",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
        return []
    except Exception as e:  # noqa: BLE001 — contract: never raise
        debug_log(
            "dns",
            detail=f"{record_type} result",
            result=f"error: {type(e).__name__}",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
        return []


def attempt_axfr(domain: str, nameserver: str, timeout: int) -> list[str] | None:
    """
    Attempt DNS zone transfer (AXFR) against a nameserver.

    Returns list of records if successful, None if failed/refused.
    This is a passive-aggressive technique — silent and surgical.
    """
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = float(timeout)
        resolver.lifetime = float(timeout)
        try:
            ans = resolver.resolve(nameserver, "A")
            ns_ip = str(ans[0])
        except Exception:  # noqa: BLE001
            try:
                aaaa = resolver.resolve(nameserver, "AAAA")
                ns_ip = str(aaaa[0])
            except Exception:  # noqa: BLE001
                return None

        xfr = dns.query.xfr(ns_ip, domain, timeout=float(timeout))
        zone = dns.zone.from_xfr(xfr)
        if zone is None:
            return None
        # Standard zone text — stable across dnspython versions
        raw = zone.to_text()
        lines = [
            ln.rstrip()
            for ln in raw.splitlines()
            if ln.strip() and not ln.strip().startswith(";")
        ]
        return lines if lines else None
    except dns.exception.FormError:
        return None
    except dns.exception.DNSException:
        return None
    except OSError:
        return None
    except Exception:  # noqa: BLE001
        return None


def _mx_records(
    domain: str,
    timeout: int,
    config: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Resolve MX into structured rows; append timeout/no answer to errors."""
    errors: list[str] = []
    out: list[dict[str, Any]] = []
    debug_log("dns", detail=f"query MX for {domain}", config=config)
    t0 = time.perf_counter()
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = float(timeout)
        resolver.lifetime = float(timeout)
        ans = resolver.resolve(domain, "MX")
        for r in ans:
            out.append({"host": str(r.exchange).rstrip("."), "priority": int(r.preference)})
        out.sort(key=lambda x: x["priority"])
        debug_log(
            "dns",
            detail="MX result",
            result=f"{len(out)} record(s)",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    except dns.resolver.NXDOMAIN:
        debug_log(
            "dns",
            detail="MX result",
            result="NXDOMAIN",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    except dns.resolver.NoAnswer:
        debug_log(
            "dns",
            detail="MX result",
            result="no answer",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    except dns.resolver.Timeout:
        errors.append(f"MX query timeout for {domain}")
        debug_log(
            "dns",
            detail="MX result",
            result=f"timeout after {timeout}s",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    except dns.exception.DNSException as e:
        errors.append(f"MX: {e}")
        debug_log(
            "dns",
            detail="MX result",
            result=f"DNSException: {type(e).__name__}",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    except Exception as e:  # noqa: BLE001
        errors.append(f"MX: {e}")
        debug_log(
            "dns",
            detail="MX result",
            result=f"error: {type(e).__name__}",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    return out, errors


def _soa_record(
    domain: str,
    timeout: int,
    config: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    debug_log("dns", detail=f"query SOA for {domain}", config=config)
    t0 = time.perf_counter()
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = float(timeout)
        resolver.lifetime = float(timeout)
        ans = resolver.resolve(domain, "SOA")
        r = ans[0]
        mname = str(r.mname).rstrip(".")
        rname = str(r.rname).rstrip(".").replace(".", "@", 1) if r.rname else ""
        debug_log(
            "dns",
            detail="SOA result",
            result="1 record",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
        return (
            {
                "mname": mname,
                "rname": rname,
                "serial": int(r.serial),
            },
            errors,
        )
    except dns.resolver.NXDOMAIN:
        debug_log(
            "dns",
            detail="SOA result",
            result="NXDOMAIN",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
        return None, errors
    except dns.resolver.NoAnswer:
        debug_log(
            "dns",
            detail="SOA result",
            result="no answer",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
        return None, errors
    except dns.resolver.Timeout:
        errors.append(f"SOA query timeout for {domain}")
        debug_log(
            "dns",
            detail="SOA result",
            result=f"timeout after {timeout}s",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    except dns.exception.DNSException as e:
        errors.append(f"SOA: {e}")
        debug_log(
            "dns",
            detail="SOA result",
            result=f"DNSException: {type(e).__name__}",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    except Exception as e:  # noqa: BLE001
        errors.append(f"SOA: {e}")
        debug_log(
            "dns",
            detail="SOA result",
            result=f"error: {type(e).__name__}",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    return None, errors


def _srv_records(
    domain: str,
    timeout: int,
    config: dict[str, Any] | None = None,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    found: list[str] = []
    for prefix in _SRV_PROBES:
        name = f"{prefix}.{domain}"
        debug_log("dns", detail=f"query SRV {name}", config=config)
        t0 = time.perf_counter()
        try:
            resolver = dns.resolver.Resolver(configure=True)
            resolver.timeout = float(timeout)
            resolver.lifetime = float(timeout)
            ans = resolver.resolve(name, "SRV")
            for r in ans:
                found.append(
                    f"{name} → {r.priority} {r.weight} {r.port} {r.target}".rstrip()
                )
            debug_log(
                "dns",
                detail=f"SRV {prefix}",
                result=f"{len(ans)} record(s)",
                elapsed=time.perf_counter() - t0,
                config=config,
            )
        except dns.resolver.NXDOMAIN:
            debug_log(
                "dns",
                detail=f"SRV {prefix}",
                result="NXDOMAIN",
                elapsed=time.perf_counter() - t0,
                config=config,
            )
            continue
        except dns.resolver.NoAnswer:
            debug_log(
                "dns",
                detail=f"SRV {prefix}",
                result="no answer",
                elapsed=time.perf_counter() - t0,
                config=config,
            )
            continue
        except dns.resolver.Timeout:
            errors.append(f"SRV timeout: {name}")
            debug_log(
                "dns",
                detail=f"SRV {prefix}",
                result=f"timeout after {timeout}s",
                elapsed=time.perf_counter() - t0,
                config=config,
            )
        except dns.exception.DNSException:
            debug_log(
                "dns",
                detail=f"SRV {prefix}",
                result="DNSException",
                elapsed=time.perf_counter() - t0,
                config=config,
            )
            continue
        except Exception:  # noqa: BLE001
            debug_log(
                "dns",
                detail=f"SRV {prefix}",
                result="error",
                elapsed=time.perf_counter() - t0,
                config=config,
            )
            continue
    return found, errors


def _caa_records(
    domain: str,
    timeout: int,
    config: dict[str, Any] | None = None,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    out: list[str] = []
    debug_log("dns", detail=f"query CAA for {domain}", config=config)
    t0 = time.perf_counter()
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = float(timeout)
        resolver.lifetime = float(timeout)
        ans = resolver.resolve(domain, "CAA")
        for r in ans:
            tag = r.tag.decode() if isinstance(r.tag, bytes) else str(r.tag)
            val = r.value.decode() if isinstance(r.value, bytes) else str(r.value)
            out.append(f"flags={r.flags} tag={tag} value={val}")
        debug_log(
            "dns",
            detail="CAA result",
            result=f"{len(out)} record(s)",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    except dns.resolver.NXDOMAIN:
        debug_log(
            "dns",
            detail="CAA result",
            result="NXDOMAIN",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    except dns.resolver.NoAnswer:
        debug_log(
            "dns",
            detail="CAA result",
            result="no answer",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    except dns.resolver.Timeout:
        errors.append(f"CAA query timeout for {domain}")
        debug_log(
            "dns",
            detail="CAA result",
            result=f"timeout after {timeout}s",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    except dns.exception.DNSException as e:
        errors.append(f"CAA: {e}")
        debug_log(
            "dns",
            detail="CAA result",
            result=f"DNSException: {type(e).__name__}",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    except Exception as e:  # noqa: BLE001
        errors.append(f"CAA: {e}")
        debug_log(
            "dns",
            detail="CAA result",
            result=f"error: {type(e).__name__}",
            elapsed=time.perf_counter() - t0,
            config=config,
        )
    return out, errors


# --- Email surface intelligence (SPF / DMARC / DKIM) ---------------------------

def _txt_rdata_join(rdata: Any) -> str:
    """Join TXT rdata chunks into one string (dnspython may use bytes)."""
    try:
        parts = getattr(rdata, "strings", None)
        if parts:
            out: list[str] = []
            for x in parts:
                if isinstance(x, (bytes, bytearray)):
                    out.append(
                        bytes(x).decode("utf-8", errors="replace").strip('"').strip("'")
                    )
                else:
                    out.append(str(x).strip('"').strip("'"))
            return "".join(out)
    except (TypeError, AttributeError, UnicodeError):
        pass
    return str(rdata).strip('"')


COMMON_DKIM_SELECTORS: tuple[str, ...] = (
    "default",
    "google",
    "mail",
    "email",
    "dkim",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "zoho",
    "sendgrid",
    "mailchimp",
    "mailgun",
    "amazonses",
    "mandrill",
    "postmark",
    "s1",
    "s2",
    "smtp",
    "mx",
)


def parse_spf(txt_records: list[str]) -> dict[str, Any]:
    """
    Parse SPF from apex TXT strings; assess spoofing relevance (not just presence).
    """
    spf_record: str | None = None
    for raw in txt_records:
        s = raw.strip().strip('"').strip("'")
        low = s.lower()
        if low.startswith("v=spf1"):
            spf_record = s
            break

    if not spf_record:
        return {
            "found": False,
            "record": None,
            "risk": "HIGH",
            "risk_reason": (
                "No SPF record — anyone can send email claiming to be this domain "
                "(receivers that only check SPF see no authorized senders list)"
            ),
            "mechanisms": [],
            "all_policy": None,
            "includes_count": 0,
        }

    mechanisms: list[dict[str, str]] = []
    all_policy: str | None = None
    too_permissive = False
    has_all = False

    parts = spf_record.split()
    for part in parts[1:]:
        part_lower = part.lower()
        mech_core = part_lower.lstrip("+-")

        # Terminal all — must not use mech_core == "all" alone: "-all".lstrip("+-") == "all"
        # and would wrongly flag HardFail as overly permissive.
        if part_lower in ("+all", "~all", "-all", "?all", "all"):
            all_policy = (
                part_lower
                if part_lower in ("+all", "~all", "-all", "?all")
                else "+all"
            )
            has_all = True
            if part_lower in ("+all", "?all", "all"):
                too_permissive = True
            continue

        if part_lower.startswith("include:"):
            mechanisms.append(
                {
                    "type": "include",
                    "value": part[8:],
                    "note": f"Delegates policy to {part[8:]}",
                }
            )
        elif part_lower.startswith("ip4:"):
            ip_range = part[4:]
            mechanisms.append(
                {
                    "type": "ip4",
                    "value": ip_range,
                    "note": f"Authorizes IPv4 range {ip_range}",
                }
            )
            if ip_range in ("0.0.0.0/0", "0.0.0.0/1"):
                too_permissive = True
        elif part_lower.startswith("ip6:"):
            mechanisms.append(
                {
                    "type": "ip6",
                    "value": part[4:],
                    "note": f"Authorizes IPv6 range {part[4:]}",
                }
            )
            if part[4:].lower() in ("::/0", "::/1"):
                too_permissive = True
        elif mech_core in ("a", "mx", "ptr"):
            mechanisms.append(
                {
                    "type": mech_core,
                    "value": part,
                    "note": f"Authorizes {mech_core.upper()} lookup for senders",
                }
            )
        elif part_lower.startswith("redirect="):
            mechanisms.append(
                {
                    "type": "redirect",
                    "value": part.partition("=")[2],
                    "note": f"SPF redirects to {part.partition('=')[2]}",
                }
            )
        elif part_lower.startswith("exists:"):
            mechanisms.append(
                {
                    "type": "exists",
                    "value": part[7:],
                    "note": "Dynamic exists: mechanism",
                }
            )

    includes_count = sum(1 for m in mechanisms if m["type"] == "include")

    # CRITICAL: +all, ?all, bare all, missing terminal all, or ip4/ip6 anycast (0.0.0.0/0, ::/0)
    if too_permissive or not has_all:
        risk = "CRITICAL"
        if not has_all:
            risk_reason = (
                "No terminal 'all' mechanism — SPF is incomplete; many receivers "
                "treat this as soft fail or ambiguous (spoofing often possible)"
            )
        elif all_policy == "+all":
            risk_reason = (
                "+all / all — effectively ANY host on the Internet may send as this domain"
            )
        elif all_policy == "?all":
            risk_reason = (
                "?all (Neutral) — failing SPF does not affect acceptance; no anti-spoofing"
            )
        else:
            risk_reason = (
                "Overly permissive SPF (e.g. 0.0.0.0/0 or ::/0) — broad sender authorization"
            )
    elif all_policy == "~all":
        risk = "MEDIUM"
        risk_reason = (
            "~all (SoftFail) — unauthorized senders are marked, not rejected; upgrade to -all"
        )
    elif all_policy == "-all":
        risk = "LOW"
        risk_reason = (
            "HardFail — unauthorized senders rejected. Good configuration"
        )
    else:
        risk = "MEDIUM"
        risk_reason = "SPF present but terminal policy unclear — verify alignment with DMARC"

    return {
        "found": True,
        "record": spf_record,
        "risk": risk,
        "risk_reason": risk_reason,
        "mechanisms": mechanisms,
        "all_policy": all_policy,
        "includes_count": includes_count,
    }


def fetch_and_parse_dmarc(domain: str, timeout: int) -> dict[str, Any]:
    """Fetch _dmarc.<domain> TXT and parse tags; never raises."""
    dmarc_domain = f"_dmarc.{domain.strip().rstrip('.')}"
    dmarc_record: str | None = None
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = float(timeout)
        resolver.lifetime = float(timeout)
        answers = resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            record = _txt_rdata_join(rdata)
            if record.lower().startswith("v=dmarc1"):
                dmarc_record = record
                break
    except Exception:  # noqa: BLE001
        pass

    if not dmarc_record:
        return {
            "found": False,
            "record": None,
            "risk": "CRITICAL",
            "risk_reason": (
                "No DMARC record — receivers cannot enforce a consistent policy for "
                "SPF/DKIM failures; spoofed mail is often delivered with no aggregate reporting"
            ),
            "policy": None,
            "pct": None,
            "rua": None,
            "ruf": None,
            "adkim": None,
            "aspf": None,
            "warnings": [],
        }

    tags: dict[str, str] = {}
    for part in dmarc_record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()

    policy = (tags.get("p") or "none").lower()
    sp = (tags.get("sp") or policy).lower()
    pct_raw = tags.get("pct", "100")
    try:
        pct_int = int(str(pct_raw).rstrip("%").strip())
    except (TypeError, ValueError):
        pct_int = 100
    pct = str(pct_int)
    rua = tags.get("rua")
    ruf = tags.get("ruf")
    adkim = (tags.get("adkim") or "r").lower()
    aspf = (tags.get("aspf") or "r").lower()

    if policy == "none":
        risk = "HIGH"
        risk_reason = (
            "DMARC p=none — monitoring only; failing SPF/DKIM does not change delivery "
            "(common 'transition' state that often never tightens)"
        )
    elif policy == "quarantine":
        if pct_int < 100:
            risk = "MEDIUM"
            risk_reason = (
                f"DMARC p=quarantine at pct={pct} — only {pct}% of failing mail quarantined; "
                f"the rest may still be delivered"
            )
        else:
            risk = "LOW"
            risk_reason = (
                "DMARC p=quarantine at 100% — failing mail should be junked/foldered"
            )
    elif policy == "reject":
        risk = "LOW"
        risk_reason = "DMARC p=reject — failing mail should be blocked at the border"
    else:
        risk = "MEDIUM"
        risk_reason = f"Unusual or unknown DMARC p={policy!r} — verify manually"

    warnings: list[str] = []
    if not rua:
        warnings.append("No rua= — no aggregate DMARC reports to a mailbox you control")
    if adkim == "r":
        warnings.append("adkim=r (relaxed DKIM alignment) — slightly weaker than strict")
    if aspf == "r":
        warnings.append("aspf=r (relaxed SPF alignment) — slightly weaker than strict")

    return {
        "found": True,
        "record": dmarc_record,
        "risk": risk,
        "risk_reason": risk_reason,
        "policy": policy,
        "sp": sp,
        "pct": pct,
        "rua": rua,
        "ruf": ruf,
        "adkim": adkim,
        "aspf": aspf,
        "warnings": warnings,
    }


def check_common_dkim_selectors(domain: str, dkim_timeout: float = 2.0) -> dict[str, Any]:
    """Probe common selector._domainkey names; short per-query timeout."""
    dom = domain.strip().rstrip(".")
    found_selectors: list[dict[str, str]] = []

    for selector in COMMON_DKIM_SELECTORS:
        name = f"{selector}._domainkey.{dom}"
        try:
            resolver = dns.resolver.Resolver(configure=True)
            resolver.timeout = float(dkim_timeout)
            resolver.lifetime = float(dkim_timeout)
            answers = resolver.resolve(name, "TXT")
            for rdata in answers:
                record = _txt_rdata_join(rdata)
                low = record.lower()
                if "v=dkim1" in low or "p=" in low:
                    preview = record[:100] + "…" if len(record) > 100 else record
                    found_selectors.append({"selector": selector, "record": preview})
                    break
        except Exception:  # noqa: BLE001
            continue

    if not found_selectors:
        return {
            "found": False,
            "selectors": [],
            "risk": "MEDIUM",
            "risk_reason": (
                "No DKIM TXT on common selectors — org may use a custom selector, "
                "or outbound mail may be unsigned / third-party relay only"
            ),
        }

    return {
        "found": True,
        "selectors": found_selectors,
        "risk": "LOW",
        "risk_reason": (
            f"{len(found_selectors)} DKIM publication(s) found (common selectors) — "
            "keys published for signing"
        ),
    }


def assess_email_risk(email_security: dict[str, Any]) -> dict[str, Any]:
    """Worst-of-three component risks plus spoofing narrative for reports."""
    spf = email_security.get("spf") or {}
    dmarc = email_security.get("dmarc") or {}
    dkim = email_security.get("dkim") or {}

    risks = [
        str(spf.get("risk") or "HIGH"),
        str(dmarc.get("risk") or "HIGH"),
        str(dkim.get("risk") or "MEDIUM"),
    ]
    risk_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    overall_risk = min(
        risks,
        key=lambda r: risk_order.index(r) if r in risk_order else 99,
    )

    spf_ok = bool(spf.get("found")) and spf.get("all_policy") == "-all"
    dmarc_ok = bool(dmarc.get("found")) and (dmarc.get("policy") or "").lower() == "reject"
    dkim_ok = bool(dkim.get("found"))

    if not spf.get("found") and not dmarc.get("found"):
        spoofing = (
            "TRIVIAL — no SPF and no DMARC; domain is trivially impersonable in many flows"
        )
    elif not dmarc.get("found") or (dmarc.get("policy") or "").lower() == "none":
        spoofing = (
            "LIKELY — DMARC missing or p=none; receivers rarely block spoofed mail "
            "on policy alone"
        )
    elif str(spf.get("risk")) in ("CRITICAL", "HIGH"):
        spoofing = "POSSIBLE — SPF weak or absent; alignment and relay abuse remain viable"
    elif spf_ok and dmarc_ok:
        spoofing = (
            "UNLIKELY (policy) — SPF HardFail + DMARC reject is strong; still test "
            "subdomains and third-party senders"
        )
    else:
        spoofing = "PARTIAL — some controls exist but enforcement or coverage is incomplete"

    return {
        "overall_risk": overall_risk,
        "spoofing_potential": spoofing,
        "spf_ok": spf_ok,
        "dmarc_ok": dmarc_ok,
        "dkim_ok": dkim_ok,
    }


def parse_email_security(
    domain: str,
    txt_records: list[str],
    timeout: int,
) -> dict[str, Any]:
    """
    SPF from apex TXT + live DMARC + DKIM selector probes.
    Never raises — returns minimal safe structure on failure.
    """
    try:
        safe_timeout = max(1, int(timeout))
        result: dict[str, Any] = {
            "spf": parse_spf(txt_records),
            "dmarc": fetch_and_parse_dmarc(domain, safe_timeout),
            "dkim": check_common_dkim_selectors(domain, 2.0),
        }
        result["risk_summary"] = assess_email_risk(result)
        return result
    except Exception:  # noqa: BLE001
        return {
            "spf": {
                "found": False,
                "record": None,
                "risk": "HIGH",
                "risk_reason": "SPF analysis failed — inspect TXT manually",
                "mechanisms": [],
                "all_policy": None,
                "includes_count": 0,
            },
            "dmarc": {
                "found": False,
                "record": None,
                "risk": "HIGH",
                "risk_reason": "DMARC analysis failed — inspect _dmarc TXT manually",
                "policy": None,
                "pct": None,
                "rua": None,
                "ruf": None,
                "adkim": None,
                "aspf": None,
                "warnings": [],
            },
            "dkim": {
                "found": False,
                "selectors": [],
                "risk": "MEDIUM",
                "risk_reason": "DKIM probe failed — try custom selectors",
            },
            "risk_summary": {
                "overall_risk": "HIGH",
                "spoofing_potential": "Assessment unavailable (parser error)",
                "spf_ok": False,
                "dmarc_ok": False,
                "dkim_ok": False,
            },
        }


def _risk_style_for_email(risk: str) -> str:
    r = (risk or "").upper()
    if r == "CRITICAL":
        return C_ERR
    if r == "HIGH":
        return C_WARN
    if r == "MEDIUM":
        return C_DIM
    if r == "LOW":
        return C_PRI
    return C_MUTED


def _email_security_table_row_status(
    label: str,
    block: dict[str, Any],
) -> tuple[str, str]:
    """Human-readable status cell + risk string."""
    if label == "SPF":
        if not block.get("found"):
            return "NOT FOUND — " + str(block.get("risk_reason") or ""), str(
                block.get("risk") or "HIGH"
            )
        pol = block.get("all_policy") or "—"
        short = str(block.get("risk_reason") or "")[:72]
        if len(str(block.get("risk_reason") or "")) > 72:
            short += "…"
        return f"{pol} — {short}", str(block.get("risk") or "MEDIUM")
    if label == "DMARC":
        if not block.get("found"):
            return "NOT FOUND — " + str(block.get("risk_reason") or ""), str(
                block.get("risk") or "CRITICAL"
            )
        p = block.get("policy") or "?"
        pct = block.get("pct")
        tail = str(block.get("risk_reason") or "")[:56]
        if len(str(block.get("risk_reason") or "")) > 56:
            tail += "…"
        return f"p={p} pct={pct} — {tail}", str(block.get("risk") or "MEDIUM")
    # DKIM
    if not block.get("found"):
        return "NOT FOUND (common selectors) — " + str(block.get("risk_reason") or ""), str(
            block.get("risk") or "MEDIUM"
        )
    sel = block.get("selectors") or []
    names = ", ".join(s.get("selector", "?") for s in sel[:4])
    if len(sel) > 4:
        names += ", …"
    return f"selector(s): {names} — {block.get('risk_reason', '')[:48]}", str(
        block.get("risk") or "LOW"
    )


def _render_email_security_panel(email_security: dict[str, Any], quiet: bool) -> None:
    if quiet:
        return
    console.print()
    console.print(Text(" [EMAIL SECURITY]", style=f"bold {C_PRI}"))
    table = Table(
        box=box.HEAVY,
        border_style=C_ACCENT,
        header_style=f"bold {C_DIM}",
        show_lines=True,
    )
    table.add_column("Control", style=C_PRI, no_wrap=True, width=8)
    table.add_column("Status", style=C_DIM)
    table.add_column("Risk", style=C_MUTED, width=12)

    for label, key in (("SPF", "spf"), ("DMARC", "dmarc"), ("DKIM", "dkim")):
        block = email_security.get(key) or {}
        status_txt, risk = _email_security_table_row_status(label, block)
        if len(status_txt) > 86:
            status_txt = status_txt[:83] + "…"
        risk_cell = Text(f"[{risk}]", style=_risk_style_for_email(risk))
        table.add_row(label, status_txt, risk_cell)

    console.print(table)

    rs = email_security.get("risk_summary") or {}
    spoof = rs.get("spoofing_potential") or "—"
    overall = rs.get("overall_risk") or "—"
    console.print()
    console.print(
        Text.assemble(
            (" [INTEL] Email spoofing assessment:\n", f"bold {C_PRI}"),
            ("   └── ", C_MUTED),
            ("Overall: ", C_DIM),
            (f"{overall}", _risk_style_for_email(str(overall))),
            ("  ·  ", C_MUTED),
            (spoof, C_DIM),
        )
    )


def _apply_email_security_findings(
    base: dict[str, Any],
    email_security: dict[str, Any],
) -> None:
    """Attach structured intel + ModuleResult-style finding rows for pack_session_result."""
    base["email_security"] = email_security
    critical: list[dict[str, Any]] = list(base.get("critical_findings") or [])
    high: list[dict[str, Any]] = list(base.get("high_findings") or [])

    spf = email_security.get("spf") or {}
    dmarc = email_security.get("dmarc") or {}
    spf_r = str(spf.get("risk") or "")
    dm_r = str(dmarc.get("risk") or "")

    if spf_r == "CRITICAL":
        critical.append(
            make_finding(
                value=spf.get("record") or "SPF",
                category="spf_misconfiguration",
                risk="CRITICAL",
                note=str(spf.get("risk_reason") or ""),
                metadata={"control": "SPF"},
            )
        )
    elif spf_r == "HIGH":
        high.append(
            make_finding(
                value=spf.get("record") or "SPF missing",
                category="spf_missing_or_weak",
                risk="HIGH",
                note=str(spf.get("risk_reason") or ""),
                metadata={"control": "SPF"},
            )
        )

    if dm_r == "CRITICAL":
        critical.append(
            make_finding(
                value=dmarc.get("record") or "_dmarc TXT missing",
                category="dmarc_missing",
                risk="CRITICAL",
                note=str(dmarc.get("risk_reason") or ""),
                metadata={"control": "DMARC"},
            )
        )
    elif dm_r == "HIGH":
        high.append(
            make_finding(
                value=dmarc.get("record") or "DMARC",
                category="dmarc_monitoring_only",
                risk="HIGH",
                note=str(dmarc.get("risk_reason") or ""),
                metadata={"control": "DMARC"},
            )
        )

    if critical:
        base["critical_findings"] = critical
    if high:
        base["high_findings"] = high


def detect_tech_from_dns(records: dict[str, Any]) -> list[str]:
    """
    Analyze DNS records and infer technologies/services in use.

    Be creative — there's a lot you can learn from DNS alone.
    """
    seen: set[str] = set()
    tech: list[str] = []

    def add(label: str) -> None:
        if label not in seen:
            seen.add(label)
            tech.append(label)

    mx_hosts = " ".join(m.get("host", "").lower() for m in records.get("MX", []))
    if any(x in mx_hosts for x in ("aspmx", "google.com", "googlemail.com")):
        add("Google Workspace")
    if any(x in mx_hosts for x in ("outlook.com", "protection.outlook", "microsoft")):
        add("Microsoft 365")
    if "mailgun" in mx_hosts:
        add("Mailgun SMTP")
    if "sendgrid" in mx_hosts:
        add("SendGrid")
    if "zendesk" in mx_hosts:
        add("Zendesk mail")
    if "mimecast" in mx_hosts:
        add("Mimecast")
    if "proofpoint" in mx_hosts:
        add("Proofpoint")

    ns_joined = " ".join(n.lower() for n in records.get("NS", []))
    if "cloudflare" in ns_joined:
        add("Cloudflare DNS")
    if "awsdns" in ns_joined or "route53" in ns_joined:
        add("Amazon Route 53")
    if "domaincontrol" in ns_joined or "godaddy" in ns_joined:
        add("GoDaddy DNS")
    if "azure-dns" in ns_joined or "azure-dns-" in ns_joined:
        add("Azure DNS")
    if "googledomains" in ns_joined or "googlehosted" in ns_joined:
        add("Google Cloud DNS")
    if "digitalocean" in ns_joined:
        add("DigitalOcean DNS")
    if "nsone" in ns_joined:
        add("NS1 DNS")
    if "dyn.com" in ns_joined or "dynect" in ns_joined:
        add("Oracle Dyn DNS")

    txt_joined = " ".join(t.lower() for t in records.get("TXT", []))
    if "v=spf1" in txt_joined:
        add("SPF configured")
    if "v=dmarc1" in txt_joined:
        add("DMARC configured")
    if "google-site-verification" in txt_joined:
        add("Google Search Console")
    if "ms=" in txt_joined:
        add("Microsoft domain verification")
    if "atlassian-domain-verification" in txt_joined:
        add("Atlassian / Jira")
    if "docusign" in txt_joined:
        add("DocuSign")
    if "facebook-domain-verification" in txt_joined:
        add("Facebook domain verification")
    if "apple-domain-verification" in txt_joined:
        add("Apple domain verification")
    if "stripe-verification" in txt_joined:
        add("Stripe")
    if "hubspot" in txt_joined:
        add("HubSpot")
    if "onetrust" in txt_joined:
        add("OneTrust / cookies")

    cname_joined = " ".join(c.lower() for c in records.get("CNAME", []))
    if "amazonaws.com" in cname_joined:
        add("AWS infrastructure")
    if "azurewebsites.net" in cname_joined or "azure-api.net" in cname_joined:
        add("Azure App Service")
    if "vercel.app" in cname_joined or "vercel-dns" in cname_joined:
        add("Vercel")
    if "netlify.app" in cname_joined or "netlify.com" in cname_joined:
        add("Netlify")
    if "github.io" in cname_joined or "githubusercontent" in cname_joined:
        add("GitHub Pages")
    if "shopify.com" in cname_joined:
        add("Shopify")
    if "cloudfront.net" in cname_joined:
        add("AWS CloudFront")
    if "fastly" in cname_joined:
        add("Fastly CDN")
    if "akamai" in cname_joined or "akadns" in cname_joined:
        add("Akamai CDN")
    if "herokuapp.com" in cname_joined:
        add("Heroku")
    if "pantheonsite.io" in cname_joined:
        add("Pantheon")
    if "wordpress.com" in cname_joined or "wpengine" in cname_joined:
        add("WordPress hosting")

    soa = records.get("SOA") or {}
    serial = soa.get("serial")
    if isinstance(serial, int):
        s = str(serial)
        if re.fullmatch(r"20\d{8}\d{2}", s):
            add("BIND-style serial (YYYYMMDDnn)")

    caa = " ".join(records.get("CAA", []))
    if "letsencrypt" in caa.lower():
        add("Let's Encrypt (CAA)")
    if "digicert" in caa.lower():
        add("DigiCert (CAA)")
    if "pki.goog" in caa.lower():
        add("Google Trust Services (CAA)")

    srv = " ".join(records.get("SRV", [])).lower()
    if "_xmpp" in srv:
        add("XMPP / chat (SRV)")
    if "_sip" in srv:
        add("SIP / VoIP (SRV)")
    if "_ldap" in srv:
        add("LDAP (SRV)")
    if "_kerberos" in srv:
        add("Kerberos (SRV)")
    if "_autodiscover" in srv:
        add("Microsoft Autodiscover (SRV)")

    return tech


def _tech_evidence_lines(records: dict[str, Any]) -> list[tuple[str, str]]:
    """Build (technology, evidence) rows for INTEL panel."""
    lines: list[tuple[str, str]] = []
    for t in detect_tech_from_dns(records):
        ev = ""
        low = t.lower()
        mx_list = records.get("MX") or []
        ns_list = records.get("NS") or []
        txt_list = records.get("TXT") or []
        cn_list = records.get("CNAME") or []
        if "google workspace" in low and mx_list:
            ev = f"MX: {mx_list[0].get('host', '')}"
        elif "microsoft 365" in low and mx_list:
            ev = f"MX: {mx_list[0].get('host', '')}"
        elif "mailgun" in low and mx_list:
            ev = f"MX: {next((m['host'] for m in mx_list if 'mailgun' in m['host'].lower()), '')}"
        elif "sendgrid" in low and mx_list:
            ev = f"MX: {next((m['host'] for m in mx_list if 'sendgrid' in m['host'].lower()), '')}"
        elif "cloudflare" in low and ns_list:
            ev = f"NS: {ns_list[0]}"
        elif "route 53" in low:
            ev = f"NS: {ns_list[0] if ns_list else 'AWS DNS patterns'}"
        elif "spf" in low and txt_list:
            ev = "TXT: v=spf1…"
        elif "dmarc" in low and txt_list:
            ev = next((x for x in txt_list if "dmarc" in x.lower()), "TXT")
        elif "search console" in low:
            ev = next((x[:48] + "…" for x in txt_list if "google-site" in x.lower()), "TXT")
        elif "aws infrastructure" in low and cn_list:
            ev = f"CNAME: {cn_list[0]}"
        elif "vercel" in low and cn_list:
            ev = f"CNAME: {cn_list[0]}"
        elif "github pages" in low and cn_list:
            ev = f"CNAME: {cn_list[0]}"
        elif "bind-style" in low or "bind" in low:
            soa = records.get("SOA") or {}
            ev = f"serial: {soa.get('serial', '')}"
        elif "caa" in low and records.get("CAA"):
            ev = records["CAA"][0][:56] + ("…" if len(records["CAA"][0]) > 56 else "")
        elif "srv" in low and records.get("SRV"):
            ev = records["SRV"][0][:56] + "…" if len(records["SRV"][0]) > 56 else records["SRV"][0]
        else:
            ev = "DNS pattern match"
        lines.append((t, ev))
    return lines


def _count_records(records: dict[str, Any]) -> int:
    n = 0
    for key, val in records.items():
        if key == "SOA":
            if val:
                n += 1
        elif isinstance(val, list):
            n += len(val)
    return n


def _empty_records() -> dict[str, Any]:
    return {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "SOA": {},
        "CNAME": [],
        "PTR": [],
        "SRV": [],
        "CAA": [],
    }


def _check_domain_exists(domain: str, timeout: int) -> tuple[bool, list[str]]:
    """Return (exists, errors). NXDOMAIN => not exists."""
    errors: list[str] = []
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = float(timeout)
        resolver.lifetime = float(timeout)
        resolver.resolve(domain, "A")
        return True, errors
    except dns.resolver.NXDOMAIN:
        return False, errors
    except dns.resolver.NoAnswer:
        try:
            resolver.resolve(domain, "AAAA")
            return True, errors
        except dns.resolver.NXDOMAIN:
            return False, errors
        except Exception:  # noqa: BLE001
            try:
                resolver.resolve(domain, "NS")
                return True, errors
            except dns.resolver.NXDOMAIN:
                return False, errors
            except Exception as e:  # noqa: BLE001
                errors.append(f"Probe: {e}")
                return True, errors
    except dns.resolver.Timeout:
        errors.append(f"A/AAAA probe timeout for {domain}")
        return True, errors
    except dns.exception.DNSException as e:
        errors.append(f"Probe: {e}")
        return True, errors
    except Exception as e:  # noqa: BLE001
        errors.append(f"Probe: {e}")
        return True, errors


def _render_header(label: str) -> None:
    inner = Text(f"  DNS RECON  ·  {label}", style=f"bold {C_PRI}")
    p = Panel(
        inner,
        border_style=C_ACCENT,
        box=box.DOUBLE,
        padding=(0, 2),
        width=min(console.size.width, 78) if console.size else 78,
    )
    console.print(p)


def _render_records_table(rows: list[tuple[str, str, str]]) -> None:
    table = Table(
        box=box.HEAVY,
        border_style=C_ACCENT,
        header_style=f"bold {C_DIM}",
        show_lines=True,
        title=Text("DNS RECORDS", style=f"bold {C_MUTED}"),
    )
    table.add_column("Type", style=C_PRI, no_wrap=True)
    table.add_column("Value", style=C_DIM)
    table.add_column("Info", style=C_MUTED)
    for t, v, info in rows:
        table.add_row(t, v, info)
    console.print(table)


def _gather_table_rows(records: dict[str, Any]) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for ip in records.get("A", []):
        rows.append(("A", ip, "IPv4"))
    for ip6 in records.get("AAAA", []):
        rows.append(("AAAA", ip6, "IPv6"))
    for mx in records.get("MX", []):
        rows.append(
            (
                "MX",
                mx.get("host", ""),
                f"priority: {mx.get('priority', '')}",
            )
        )
    for ns in records.get("NS", []):
        rows.append(("NS", ns, "authoritative"))
    for txt in records.get("TXT", []):
        info = "TXT record"
        low = txt.lower()
        if "v=spf1" in low:
            info = "SPF record"
        elif "v=dmarc1" in low:
            info = "DMARC record"
        elif "dkim" in low:
            info = "DKIM / email auth"
        display = txt if len(txt) <= 64 else txt[:61] + "…"
        rows.append(("TXT", display, info))
    soa = records.get("SOA") or {}
    if soa:
        rows.append(
            (
                "SOA",
                soa.get("mname", ""),
                f"serial: {soa.get('serial', '')}",
            )
        )
    for c in records.get("CNAME", []):
        rows.append(("CNAME", c, "alias"))
    for p in records.get("PTR", []):
        rows.append(("PTR", p.rstrip("."), "reverse"))
    for s in records.get("SRV", []):
        rows.append(("SRV", s[:70] + ("…" if len(s) > 70 else ""), "service"))
    for c in records.get("CAA", []):
        disp = c if len(c) <= 64 else c[:61] + "…"
        rows.append(("CAA", disp, "cert authority"))
    return rows


def _run_axfr_ui(
    domain: str,
    ns_list: list[str],
    timeout: int,
    verbose: bool,
    errors: list[str],
    quiet: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    axfr_state: dict[str, Any] = {
        "attempted": bool(ns_list),
        "vulnerable": False,
        "nameservers_tried": list(ns_list),
        "dump": [],
    }
    if not ns_list:
        axfr_state["attempted"] = False
        return axfr_state, errors

    if not quiet:
        console.print(Text("\n [AXFR] Attempting zone transfer...", style=f"bold {C_WARN}"))
    for i, ns in enumerate(ns_list):
        status_txt = "REFUSED"
        detail = "(expected)"
        dump: list[str] | None = None
        try:
            dump = attempt_axfr(domain, ns, timeout)
        except Exception as e:  # noqa: BLE001
            if verbose:
                console.print(Text(f"   [WARN] AXFR {ns}: {e}", style=C_WARN))
            errors.append(f"AXFR {ns}: {e}")
            status_txt = "ERROR"
            detail = str(e)[:48]

        if dump:
            axfr_state["vulnerable"] = True
            axfr_state["dump"] = dump
            console.print(
                Text(
                    f"\n [!!!] ZONE TRANSFER SUCCESSFUL on {ns}",
                    style="bold blink " + C_ERR,
                )
            )
            console.print(
                Text(
                    " [!!!] THIS IS A CRITICAL MISCONFIGURATION — ALL RECORDS EXPOSED",
                    style=f"bold {C_ERR}",
                )
            )
            shown = min(24, len(dump))
            for j, line in enumerate(dump[:shown]):
                is_last = j == shown - 1 and len(dump) <= shown
                branch = "└──" if is_last else "├──"
                clip = line if len(line) <= 96 else line[:93] + "…"
                console.print(
                    Text.assemble(
                        (f"   {branch} ", C_MUTED),
                        (clip, C_DIM),
                    )
                )
            if len(dump) > shown:
                console.print(
                    Text(f"   └── ... ({len(dump)} records total)", style=C_MUTED)
                )
            console.print()
            break

        if not quiet:
            sym = "├──" if i < len(ns_list) - 1 else "└──"
            console.print(
                Text.assemble(
                    (f"   {sym} ", C_MUTED),
                    (f"{ns}", C_DIM),
                    ("  →  ", C_MUTED),
                    (status_txt, C_DIM),
                    (f"  {detail}" if detail else "", C_MUTED),
                )
            )

    return axfr_state, errors


def run(target: Target, config: dict[str, Any]) -> dict[str, Any]:
    """
    Main entry point for DNS recon module.

    Returns structured dict with all findings.
    """
    t0 = time.perf_counter()
    verbose = bool(config.get("verbose", False))
    quiet = bool(config.get("quiet", False))
    timeout = int(config.get("timeout", 5) or 5)
    timeout = max(1, timeout)

    base: dict[str, Any] = {
        "module": "dns_recon",
        "target": target.value,
        "status": "skipped",
        "records": _empty_records(),
        "axfr": {
            "attempted": False,
            "vulnerable": False,
            "nameservers_tried": [],
            "dump": [],
        },
        "technologies": [],
        "total_records": 0,
        "errors": [],
    }

    if not (target.is_domain() or target.is_ip()):
        base["status"] = "skipped"
        _render_header(target.value)
        console.print(Text("  [SKIP] DNS recon applies to domain or IP only (not CIDR).", style=C_WARN))
        return base

    errors: list[str] = []
    records = _empty_records()

    if target.is_ip():
        _render_header(target.value)
        ip_str = target.value
        try:
            rev = dns.reversename.from_address(ip_str)
            ptr_strings = query_record(str(rev), "PTR", timeout, config)
            records["PTR"] = ptr_strings
            if not ptr_strings:
                errors.append("No PTR record for this address")
        except Exception as e:  # noqa: BLE001
            errors.append(f"PTR: {e}")
            if verbose:
                console.print(Text(f"  [WARN] {e}", style=C_WARN))

        rows = _gather_table_rows(records)
        if rows and not quiet:
            _render_records_table(rows)
        elif not rows:
            console.print(Text("  (no PTR records)", style=C_MUTED))

        technologies = detect_tech_from_dns(records)
        if technologies and not quiet:
            console.print(Text("\n [INTEL] Technologies identified via DNS:", style=f"bold {C_PRI}"))
            for tech, ev in _tech_evidence_lines(records):
                console.print(
                    Text.assemble(
                        ("   ├── ", C_MUTED),
                        (tech.ljust(22), C_DIM),
                        (f" ({ev})", C_MUTED),
                    )
                )

        elapsed = time.perf_counter() - t0
        base.update(
            {
                "status": "success",
                "records": records,
                "technologies": technologies,
                "total_records": _count_records(records),
                "errors": errors,
            }
        )
        axfr_note = "n/a (IP target)"
        console.print(
            Text.assemble(
                ("\n [✓] DNS recon complete\n", f"bold {C_PRI}"),
                (f"     Records found : {base['total_records']}\n", C_DIM),
                (f"     Technologies  : {len(technologies)}\n", C_DIM),
                (f"     AXFR          : {axfr_note}\n", C_DIM),
                (f"     Duration      : {elapsed:.2f}s", C_DIM),
            )
        )
        return base

    domain = target.value
    _render_header(domain)

    exists, probe_errs = _check_domain_exists(domain, timeout)
    errors.extend(probe_errs)
    for e in probe_errs:
        if verbose:
            console.print(Text(f"  [WARN] {e}", style=C_WARN))

    if not exists:
        elapsed = time.perf_counter() - t0
        console.print(Text("  [✗] NXDOMAIN — domain does not exist or has no DNS answers.", style=C_ERR))
        err_msg = f"NXDOMAIN: {domain}"
        base.update(
            {
                "status": "error",
                "error": err_msg,
                "errors": errors + [err_msg],
            }
        )
        console.print(
            Text(
                f"\n [✗] DNS recon failed · Duration: {elapsed:.2f}s",
                style=C_ERR,
            )
        )
        return base

    # Sequential queries per spec
    records["A"] = query_record(domain, "A", timeout, config)
    records["AAAA"] = query_record(domain, "AAAA", timeout, config)
    mx_r, mx_e = _mx_records(domain, timeout, config)
    records["MX"] = mx_r
    errors.extend(mx_e)
    records["NS"] = [
        n.rstrip(".") for n in query_record(domain, "NS", timeout, config)
    ]
    txt = query_record(domain, "TXT", timeout, config)
    records["TXT"] = txt
    soa, soa_e = _soa_record(domain, timeout, config)
    if soa:
        records["SOA"] = soa
    errors.extend(soa_e)
    records["CNAME"] = query_record(domain, "CNAME", timeout, config)
    srv_r, srv_e = _srv_records(domain, timeout, config)
    records["SRV"] = srv_r
    errors.extend(srv_e)
    caa_r, caa_e = _caa_records(domain, timeout, config)
    records["CAA"] = caa_r
    errors.extend(caa_e)

    for e in mx_e + soa_e + srv_e + caa_e:
        if verbose:
            console.print(Text(f"  [WARN] {e}", style=C_WARN))

    table_rows = _gather_table_rows(records)
    if table_rows and not quiet:
        _render_records_table(table_rows)
    elif not table_rows:
        console.print(Text("  (no records collected)", style=C_MUTED))

    email_security = parse_email_security(domain, records["TXT"], timeout)
    _render_email_security_panel(email_security, quiet)
    _apply_email_security_findings(base, email_security)

    ns_for_axfr = list(records["NS"])
    axfr_state, errors = _run_axfr_ui(
        domain, ns_for_axfr, timeout, verbose, errors, quiet=quiet
    )

    technologies = detect_tech_from_dns(records)
    if technologies and not quiet:
        console.print(Text("\n [INTEL] Technologies identified via DNS:", style=f"bold {C_PRI}"))
        for tech, ev in _tech_evidence_lines(records):
            console.print(
                Text.assemble(
                    ("   ├── ", C_MUTED),
                    (tech.ljust(22), C_DIM),
                    (f" ({ev})", C_MUTED),
                )
            )

    elapsed = time.perf_counter() - t0
    total = _count_records(records)
    axfr_line = (
        "VULNERABLE — CRITICAL"
        if axfr_state["vulnerable"]
        else ("not vulnerable" if axfr_state["attempted"] else "skipped (no NS)")
    )

    base.update(
        {
            "status": "success",
            "records": records,
            "axfr": axfr_state,
            "technologies": technologies,
            "total_records": total,
            "errors": errors,
        }
    )

    console.print(
        Text.assemble(
            ("\n [✓] DNS recon complete\n", f"bold {C_PRI}"),
            (f"     Records found : {total}\n", C_DIM),
            (f"     Technologies  : {len(technologies)}\n", C_DIM),
            (f"     AXFR          : {axfr_line}\n", C_DIM),
            (f"     Duration      : {elapsed:.2f}s", C_DIM),
        )
    )

    return base
