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


def query_record(domain: str, record_type: str, timeout: int) -> list[str]:
    """
    Query a single DNS record type.

    Returns list of strings with results, or empty list on any failure.
    Never raises.
    """
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = float(timeout)
        resolver.lifetime = float(timeout)
        ans = resolver.resolve(domain, record_type)
        return [str(r) for r in ans]
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.Timeout:
        return []
    except dns.exception.DNSException:
        return []
    except OSError:
        return []
    except Exception:  # noqa: BLE001 — contract: never raise
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


def _mx_records(domain: str, timeout: int) -> tuple[list[dict[str, Any]], list[str]]:
    """Resolve MX into structured rows; append timeout/no answer to errors."""
    errors: list[str] = []
    out: list[dict[str, Any]] = []
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = float(timeout)
        resolver.lifetime = float(timeout)
        ans = resolver.resolve(domain, "MX")
        for r in ans:
            out.append({"host": str(r.exchange).rstrip("."), "priority": int(r.preference)})
        out.sort(key=lambda x: x["priority"])
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.Timeout:
        errors.append(f"MX query timeout for {domain}")
    except dns.exception.DNSException as e:
        errors.append(f"MX: {e}")
    except Exception as e:  # noqa: BLE001
        errors.append(f"MX: {e}")
    return out, errors


def _soa_record(domain: str, timeout: int) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = float(timeout)
        resolver.lifetime = float(timeout)
        ans = resolver.resolve(domain, "SOA")
        r = ans[0]
        mname = str(r.mname).rstrip(".")
        rname = str(r.rname).rstrip(".").replace(".", "@", 1) if r.rname else ""
        return (
            {
                "mname": mname,
                "rname": rname,
                "serial": int(r.serial),
            },
            errors,
        )
    except dns.resolver.NXDOMAIN:
        return None, errors
    except dns.resolver.NoAnswer:
        return None, errors
    except dns.resolver.Timeout:
        errors.append(f"SOA query timeout for {domain}")
    except dns.exception.DNSException as e:
        errors.append(f"SOA: {e}")
    except Exception as e:  # noqa: BLE001
        errors.append(f"SOA: {e}")
    return None, errors


def _srv_records(domain: str, timeout: int) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    found: list[str] = []
    for prefix in _SRV_PROBES:
        name = f"{prefix}.{domain}"
        try:
            resolver = dns.resolver.Resolver(configure=True)
            resolver.timeout = float(timeout)
            resolver.lifetime = float(timeout)
            ans = resolver.resolve(name, "SRV")
            for r in ans:
                found.append(
                    f"{name} → {r.priority} {r.weight} {r.port} {r.target}".rstrip()
                )
        except dns.resolver.NXDOMAIN:
            continue
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.Timeout:
            errors.append(f"SRV timeout: {name}")
        except dns.exception.DNSException:
            continue
        except Exception:  # noqa: BLE001
            continue
    return found, errors


def _caa_records(domain: str, timeout: int) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    out: list[str] = []
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = float(timeout)
        resolver.lifetime = float(timeout)
        ans = resolver.resolve(domain, "CAA")
        for r in ans:
            tag = r.tag.decode() if isinstance(r.tag, bytes) else str(r.tag)
            val = r.value.decode() if isinstance(r.value, bytes) else str(r.value)
            out.append(f"flags={r.flags} tag={tag} value={val}")
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.Timeout:
        errors.append(f"CAA query timeout for {domain}")
    except dns.exception.DNSException as e:
        errors.append(f"CAA: {e}")
    except Exception as e:  # noqa: BLE001
        errors.append(f"CAA: {e}")
    return out, errors


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
            ptr_strings = query_record(str(rev), "PTR", timeout)
            records["PTR"] = ptr_strings
            if not ptr_strings:
                errors.append("No PTR record for this address")
        except Exception as e:  # noqa: BLE001
            errors.append(f"PTR: {e}")
            if verbose:
                console.print(Text(f"  [WARN] {e}", style=C_WARN))

        rows = _gather_table_rows(records)
        if rows:
            _render_records_table(rows)
        else:
            console.print(Text("  (no PTR records)", style=C_MUTED))

        technologies = detect_tech_from_dns(records)
        if technologies:
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
    records["A"] = query_record(domain, "A", timeout)
    records["AAAA"] = query_record(domain, "AAAA", timeout)
    mx_r, mx_e = _mx_records(domain, timeout)
    records["MX"] = mx_r
    errors.extend(mx_e)
    records["NS"] = [n.rstrip(".") for n in query_record(domain, "NS", timeout)]
    txt = query_record(domain, "TXT", timeout)
    records["TXT"] = txt
    soa, soa_e = _soa_record(domain, timeout)
    if soa:
        records["SOA"] = soa
    errors.extend(soa_e)
    records["CNAME"] = query_record(domain, "CNAME", timeout)
    srv_r, srv_e = _srv_records(domain, timeout)
    records["SRV"] = srv_r
    errors.extend(srv_e)
    caa_r, caa_e = _caa_records(domain, timeout)
    records["CAA"] = caa_r
    errors.extend(caa_e)

    for e in mx_e + soa_e + srv_e + caa_e:
        if verbose:
            console.print(Text(f"  [WARN] {e}", style=C_WARN))

    table_rows = _gather_table_rows(records)
    if table_rows:
        _render_records_table(table_rows)
    else:
        console.print(Text("  (no records collected)", style=C_MUTED))

    ns_for_axfr = list(records["NS"])
    axfr_state, errors = _run_axfr_ui(domain, ns_for_axfr, timeout, verbose, errors)

    technologies = detect_tech_from_dns(records)
    if technologies:
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
