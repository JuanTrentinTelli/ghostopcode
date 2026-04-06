# GhostOpcode

![Version](https://img.shields.io/badge/Version-1.7.0-orange?style=flat-square)
![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

**GhostOpcode** is a **local**, **interactive** Python reconnaissance framework. It runs from the terminal with a Rich UI: pick a target (domain, IP, or CIDR), choose modules, and get structured results plus **JSON**, **HTML**, and **session logs** under `output/`.

**Authorized testing only.** You are responsible for lawful use.

---

## Features

- **16 menu modules** + automatic **CVE lookup** (NVD) when port scan or WHOIS runs in the same session  
- **Target-aware menu**: modules show `[n]` or `[n/a]` depending on domain vs IP vs CIDR  
- **Session chaining**: later modules read **`session_results`** (e.g. Subfinder → dnsx → httpx)  
- **Subdomain intelligence chain** (modules 12–14): passive discovery → DNS validation → live HTTP(S) fingerprinting  
- **IP grouping & ASN hints** (Subfinder + wordlist subdomain enum) via `utils/asn_lookup.py` and `utils/subdomain_intel.py`  
- **Graceful degradation**: external tools (Subfinder, dnsx, ProjectDiscovery httpx) report `not_installed` if binaries are missing  
- **RUN ALL** (`0`): runs every supported module for the target except **Hash** (requires interactive hash input)  
- **Output modes**: normal, quiet (high-value findings only), debug (subprocess / trace hints)  
- **Redaction** and report caps (`utils/redact.py`, `utils/report_truncate.py`, limits in `config.py`)

---

## Requirements

| Component | Notes |
|-----------|--------|
| **Python** | 3.10+ recommended |
| **OS** | Linux-oriented (paths assume Kali/Debian-style wordlists); may run elsewhere with adjusted paths |
| **Privileges** | Some modules need **root** (e.g. raw sockets / Scapy sniffer, some nmap modes) |

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Pinned stack includes: **Rich**, **Jinja2**, **dnspython**, **python-whois**, **BeautifulSoup**, **PyMuPDF**, **openpyxl**, **python-docx**, **requests**, **httpx** (library — not the ProjectDiscovery CLI), **ipwhois**, **cryptography**, **python-nmap**, **Scapy**, **python-dotenv**, **packaging**.

---

## Quick start

```bash
python main.py
```

1. Enter a **domain**, **IPv4/IPv6**, or **CIDR**.  
2. Select module numbers (e.g. `1 4 12`) or **`0`** for RUN ALL.  
3. Confirm threads, timeout, ports, nmap level (if applicable), output mode.  
4. Artifacts land in **`output/<slug>_<timestamp>/`** (gitignored).

Optional **`.env`** (repo root, gitignored):

- **`NVD_API_KEY`** — higher NVD API rate limits for CVE lookup.

---

## Target types and module availability

| Target | Available module keys |
|--------|------------------------|
| **Domain** | dns, subs, whois, ports, dirs, harvest, methods, js, hash, waf, urls, subfinder, dnsx, httpx |
| **Single IP** | dns, whois, ports, dirs, harvest, methods, js, hash, waf, sniff |
| **CIDR** | arp, ports, sniff |

---

## Modules (interactive menu)

| ID | Key | Name | Description |
|----|-----|------|-------------|
| 1 | `dns` | DNS recon | A/MX/NS/TXT (and related) + zone transfer attempt |
| 2 | `subs` | Subdomain enum | Wordlist bruteforce + DNS resolution + IP grouping / ASN intel |
| 3 | `whois` | WHOIS | Registration data + technical fingerprinting |
| 4 | `ports` | Port scan | TCP connect + **nmap** (`python-nmap`) with configurable intensity (3 levels) + banners |
| 5 | `dirs` | Dir enum | Path bruteforce (fast / normal / full wordlist modes) |
| 6 | `harvest` | Harvester | Crawl + PDF/DOC/XLS + emails + config-style leaks |
| 7 | `methods` | HTTP methods | OPTIONS / PUT / DELETE / TRACE (and related) probes |
| 8 | `js` | JS recon | JS files → endpoints, secrets, source maps |
| 9 | `hash` | Hash module | Identify hash type + optional local crack (hashcat / wordlist); **skipped in RUN ALL** |
| 10 | `waf` | WAF detection | Fingerprint WAF / CDN / IDS-style behavior |
| 11 | `urls` | URL harvester | GAU-style historical URLs + pattern matching |
| 12 | `subfinder` | Subfinder | Passive OSINT subdomains (**requires** [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder) binary) + DNS enrichment + IP grouping / ASN |
| 13 | `dnsx` | dnsx | Bulk DNS resolution + wildcard awareness (**requires** [dnsx](https://github.com/projectdiscovery/dnsx) binary); reads prior session `subfinder_enum` / `subdomain_enum` |
| 14 | `httpx` | httpx | Mass HTTP/HTTPS probe (**requires** [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx) CLI, not the Python `httpx` package); prefers dnsx output, then subfinder, then subdomain enum |
| 15 | `arp` | ARP scan | CIDR-only; **Scapy** |
| 16 | `sniff` | Packet sniffer | IP or CIDR; **Scapy** capture |

**CVE lookup** is **not** a menu ID: it runs automatically after the session if **port scan** or **WHOIS** produced usable data, using the NVD API (`modules/cve_lookup.py`).

---

## Subdomain intelligence chain (12 → 13 → 14)

Typical flow on a **domain** target:

```
[12] Subfinder  →  passive hostnames (CT / OSINT) + IP grouping
        ↓
[13] dnsx       →  validate FQDNs in bulk (A/AAAA/CNAME/MX, …), wildcard hint, CDN flags
        ↓
[14] httpx      →  live HTTP/HTTPS services: status, title, tech (Wappalyzer dataset), TLS grab, multiple ports
```

Select together: **`12 13 14`**.  
`main.py` injects **`session_results`** before each module so **dnsx** and **httpx** consume prior outputs without manual file handoff.

**httpx** summary in the RESULTS table uses **unique responding hosts** vs **total URL rows** (multiple schemes/ports per host).

---

## External binaries (optional)

| Binary | Typical install | Used by |
|--------|-----------------|--------|
| **subfinder** | `apt install subfinder` or `go install … subfinder@latest` | Module 12 |
| **dnsx** | `apt install dnsx` or ProjectDiscovery release | Module 13 |
| **httpx** (ProjectDiscovery) | Release binary or `go install … httpx@latest` — must **not** be confused with `pip install httpx` | Module 14 |
| **nmap** | `apt install nmap` | Module 4 (nmap phase) |
| **hashcat** | `apt install hashcat` | Module 9 (optional cracking) |

If a binary is missing, the module sets status **`not_installed`** and prints install hints; the rest of the session continues.

**Resume file:** ProjectDiscovery tools may create `resume.cfg`; it is listed in **`.gitignore`** — do not commit it.

---

## Wordlists

`config.py` resolves wordlists from common **SecLists** / **dirbuster** paths on Kali/Debian, then falls back to a local `wordlists/` folder (gitignored for large files). On startup, GhostOpcode prints which wordlists were found and approximate sizes.

---

## Configuration (`config.py`)

Notable constants:

- **`DEFAULT_THREADS`**, **`DEFAULT_TIMEOUT`** — baseline for prompts  
- **`SUBFINDER_TIMEOUT`** — wall-clock budget for Subfinder  
- **`COMMON_PORTS`** — default port scan set  
- **`OUTPUT_DIR`** — session root (`output/`)  
- **`MAX_*`** caps — URLs, subdomains, findings per tier, report totals (see file comments)

Per-run overrides come from the interactive prompts (threads, timeout, ports expression, nmap level, dir enum mode, harvester options, etc.).

---

## Project layout (high level)

```text
main.py                 # CLI entry, module orchestration, CVE hook
config.py               # Wordlists, limits, version
modules/                # One package per recon module (+ network/)
utils/
  base_module.py        # ModuleResult contract, pack_session_result, make_finding
  target_parser.py      # Domain / IP / CIDR parsing + module compatibility
  dns_cache.py          # Shared DNS resolution cache
  asn_lookup.py         # ASN / org hints (ipwhois / RDAP-oriented)
  subdomain_intel.py    # IP maps, grouping tables for subdomain modules
  http_client.py        # Shared HTTP client / TLS defaults
  redact.py             # Sensitive-value redaction for exports
  logger.py             # Session logging
report/                 # html_report.py, json_report.py
templates/report.html.j2
```

---

## Reports

Each session can produce:

- **JSON** — full structured session (truncation caps apply)  
- **HTML** — executive-style report (Jinja2)  
- **`session.log`** — operator log in the session directory  

Outputs are designed for authorized reporting; use **`redact`**-aware exports when sharing.

---

## Security and legal

- Only test systems you **own** or have **written permission** to assess.  
- Do not commit **`.env`**, **`output/`**, secrets, or raw credentials.  
- Review **`MAX_*`** limits before very large scopes.

---

## Changelog (summary)

| Version | Highlights |
|---------|------------|
| **1.7.0** | Subdomain chain: Subfinder + **dnsx** + **httpx**; **asn_lookup** / **subdomain_intel**; session wiring; README alignment |
| 1.6.0 | Redaction, TLS options, caches, memory limits, path hardening, email auth intel (SPF/DMARC/DKIM), nmap levels, hash skipped in RUN ALL |
| 1.5.0 | Email DNS parsers, quiet/debug modes, base_module refactor |
| ≤ 1.4.x | WAF, URL harvester, Subfinder, CVE automation, earlier module set |

---

## License

See **`LICENSE.md`** (MIT unless stated otherwise in that file).

---

*GhostOpcode v1.7.0 — local offensive recon framework*
