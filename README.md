<div align="center">

```
  ██████  ██   ██  ██████  ███████ ████████
 ██       ██   ██ ██    ██ ██         ██
 ██   ███ ███████ ██    ██ ███████    ██
 ██    ██ ██   ██ ██    ██      ██    ██
  ██████  ██   ██  ██████  ███████    ██

  ██████  ██████   ██████  ██████  ██████  ███████
 ██    ██ ██   ██ ██      ██    ██ ██   ██ ██
 ██    ██ ██████  ██      ██    ██ ██   ██ █████
 ██    ██ ██      ██      ██    ██ ██   ██ ██
  ██████  ██       ██████  ██████  ██████  ███████
```

**v1.4.1 · by GhostOpcode · Python Recon Framework**

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.4.1-orange?style=flat-square)

> Offensive reconnaissance framework — 100% local, no external APIs (optional CVE lookup via NVD only)

</div>

---

## What is GhostOpcode?

GhostOpcode is an **offensive reconnaissance** tool built for penetration testers,
security students, and CTF enthusiasts.

It automates the information-gathering phase before a pentest, wrapping everything
you need to know about a target — domain, IP, or local network — in one **interactive**
CLI. **No command-line arguments required**; run it and follow the menu.

---

## Features

| # | Module | What it does |
|---|--------|--------------|
| 1 | **DNS Recon** | Queries A, MX, NS, TXT, SOA records. Attempts zone transfer (AXFR). Infers technologies from DNS. |
| 2 | **Subdomain Enum** | Discovers subdomains via wordlist bruteforce. Detects wildcard DNS and subdomain takeover candidates. |
| 3 | **WHOIS + Fingerprint** | Domain/IP registration data. Detects web server, CMS, CDN, and backend hints from HTTP headers. Audits SSL certificates. |
| 4 | **Port Scan** | TCP port sweep (any range). Accurate service identification via **nmap -sV**. Banner grabbing. OS inference. |
| 5 | **Dir Enum** | Directory and file bruteforce (Fast / Normal / Full). HTTP catch-all detection. Risk-bucketed findings. |
| 6 | **Harvester** | Crawls the site and pulls PDFs, DOCs, XLS. Extracts emails, names, LinkedIn profiles. Scans for exposed sensitive files (.env, .git, backups). Document metadata extraction. |
| 7 | **HTTP Methods** | Probes dangerous HTTP methods (PUT, DELETE, TRACE). CORS misconfiguration detection. Security header audit. |
| 8 | **JS Recon** | Analyses target JavaScript. Extracts hardcoded API endpoints, secrets (AWS keys, tokens), and exposed source maps. |
| 9 | **Hash Module** | Identifies hash algorithms. Local wordlist cracking (e.g. rockyou). Optional **hashcat** integration. |
| 10 | **WAF Detection** | Identifies WAF/CDN/IPS from headers, probes, and timing. |
| 11 | **URL Harvester** | Historical URLs from Wayback, Common Crawl, OTX, optional gau; vulnerability-style bucketing. |
| 12 | **Subfinder Enum** | Enumeração profunda de subdomínios via subfinder (ProjectDiscovery). Usa Certificate Transparency logs e múltiplas fontes OSINT passivas. Compara com subdomain_enum e destaca subdomínios encontrados apenas pelo subfinder. Mais eficiente e estável no Kali Linux do que o motor passivo anterior. |
| 13 | **ARP Scan** | Finds live hosts on the LAN via ARP. Vendor identification from MAC. Requires a **CIDR** target and **root/sudo**. |
| 14 | **Packet Sniffer** | Live traffic capture. Protocol parsing and passive intel. Requires **root/sudo**. |
| ★ | **CVE Lookup** | Runs automatically after a port scan (when configured). Queries the **NVD** using discovered services and versions. Returns relevant CVEs with CVSS scores. |

---

## Automatic reports

Every session writes **three artifacts** under `output/`:

```
output/
└── target_20260325_143022/
    ├── report.json     # Structured machine-readable results
    ├── report.html     # Visual report (open in a browser)
    └── session.log     # Chronological session log
```

---

## Requirements

- **Python 3.10+**
- **Linux** (Kali Linux recommended)
- **nmap** installed on the system
- **Root/sudo** only for ARP scan and packet sniffer

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/JuanTrentinTelli/ghostopcode.git
cd ghostopcode
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Install wordlists (Kali Linux)

```bash
sudo apt install seclists wordlists
```

GhostOpcode auto-detects standard Kali wordlist paths.
On other distros, see [Wordlists](#wordlists).

### 4. Install nmap

```bash
sudo apt install nmap
```

### Optional external tools

| Ferramenta | Para que serve | Instalação |
|------------|---------------|------------|
| `subfinder` | Enumeração profunda de subdomínios via OSINT passivo | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `hashcat` | Hash cracking com GPU | `sudo apt install hashcat` |
| `gau` | Mais fontes de URLs históricas | `go install github.com/lc/gau/v2/cmd/gau@latest` |

### 5. (Optional) CVE lookup

```bash
# Create a .env file at the project root
echo "NVD_API_KEY=your-key-here" > .env
```

Free API key: https://nvd.nist.gov/developers/request-an-api-key

---

## Usage

```bash
# Default — interactive menu
python main.py

# With root (required for ARP scan and sniffer)
sudo python main.py
```

### Example session

```
Enter target (domain / IP / CIDR):
❯ example.com                   # domain
❯ 192.168.1.1                   # IP
❯ 192.168.1.0/24                # local network (CIDR)

Select modules:
[1] DNS recon
[2] Subdomain enum
...
[0] RUN ALL — runs every module available for the target
```

### Runtime options

| Option | Description | Example |
|--------|-------------|---------|
| Threads | Parallel workers | 50 (default), 200 (aggressive) |
| Timeout | Per-connection timeout | 5s (default), 2s (fast) |
| Ports | Port range | `common`, `1-1024`, `80,443`, `1-65535` |
| Dir mode | Dir enum depth / wordlist | Fast (~30s), Normal (~5min), Full (~20min) |

---

## Wordlists

GhostOpcode resolves wordlists from common Kali paths first.

**Kali Linux:**

```bash
sudo apt install seclists wordlists
```

**Other distros:**

```bash
# SecLists
sudo git clone https://github.com/danielmiessler/SecLists /usr/share/seclists

# rockyou (hash cracking)
# Download: https://github.com/brannondorsey/naive-hashcat/releases
# Save as: wordlists/rockyou.txt
```

**Manual (any OS):** create `wordlists/` and drop your files:

```
wordlists/
├── subdomains-top1million.txt
├── directory-list-2.3-medium.txt
└── rockyou.txt
```

---

## Authorized test targets

Safe hosts for practice (no special permission needed):

| Target | Type | Notes |
|--------|------|-------|
| `scanme.nmap.org` | Domain | Official nmap.org scan target |
| `testphp.vulnweb.com` | Domain | Acunetix test application |
| `45.33.32.156` | IP | scanme.nmap.org address |

---

## Changelog

| Versão | O que mudou |
|--------|-------------|
| **v1.4.1** | Motor passivo de subdomínios: subfinder (substituição da ferramenta anterior, incompatível com Kali Linux atual) |
| v1.4.0 | WAF Detection · URL Harvester · enum passivo de subdomínios · terminal verbosity |
| v1.3.1 | Filtro CVEs genéricos · hotfix logger |
| v1.3.0 | nmap -sV integrado no port scan |
| v1.2.0 | CVE lookup automático com NVD API |
| v1.1.0 | Hotfixes: logger, wordlists, catchall detection |
| v1.0.0 | Lançamento inicial — 12 módulos de recon |

---

## Legal disclaimer

> **Authorized targets only.**
>
> Using this tool against systems **without explicit written permission** is
> **illegal** in most jurisdictions.
>
> The authors are not responsible for misuse. Always obtain proper authorization
> before testing.

---

## Author

**GhostOpcode** · v1.4.1 · Python Recon Framework

[![GitHub](https://img.shields.io/badge/GitHub-JuanTrentinTelli-black?style=flat-square&logo=github)](https://github.com/JuanTrentinTelli/ghostopcode)
