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

**Offensive Recon Framework — 100% local, zero external APIs**

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

</div>

---

## Features

| Module | Description |
|--------|-------------|
| DNS Recon | A/MX/NS/TXT/SOA records + zone transfer (AXFR) attempt |
| Subdomain Enum | Wordlist bruteforce + wildcard detection + takeover check |
| WHOIS | Domain/IP registration + HTTP fingerprint + SSL analysis |
| Port Scan | TCP connect scan + banner grabbing + OS inference |
| Dir Enum | Path bruteforce (Fast/Normal/Full) + catchall detection |
| Harvester | PDF/DOC/XLS files + email extraction + config leak scanner |
| HTTP Methods | OPTIONS/PUT/DELETE/TRACE probe + security headers audit |
| JS Recon | Endpoints + hardcoded secrets + source map detection |
| Hash Module | Hash identification + local crack + hashcat integration |
| ARP Scan | LAN host discovery + vendor/hostname identification |
| Packet Sniffer | Live traffic capture + protocol analysis |

- Interactive CLI menu — no arguments needed
- Automatic JSON + HTML + LOG report generation
- 100% local — zero external APIs, zero internet dependency
- Kali Linux wordlists auto-detected

---

## Requirements

- Python 3.10+
- Linux (Kali recommended)
- Root/sudo for ARP scan and packet sniffer

### System dependencies (Kali Linux)

```bash
sudo apt install seclists wordlists nmap hashcat
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/JuanTrentinTelli/ghostopcode.git
cd ghostopcode

# Install Python dependencies
pip install -r requirements.txt
```

---

## Usage

```bash
# Standard usage — interactive menu
python main.py

# With root (required for ARP scan and packet sniffer)
sudo python main.py
```

### Example session

```
Enter target (domain / IP / CIDR):
❯ example.com

Select modules:
[1] DNS recon
[2] Subdomain enum
...
[0] RUN ALL
```

---

## Wordlists

GhostOpcode auto-detects Kali Linux wordlists.
If running on another distro, install SecLists:

```bash
# Kali
sudo apt install seclists

# Other distros
git clone https://github.com/danielmiessler/SecLists /usr/share/seclists
```

Or place wordlists manually:

```
wordlists/
├── subdomains-top1million.txt
├── directory-list-2.3-medium.txt
└── rockyou.txt
```

---

## Output

Every session generates automatically:

```
output/
└── target_YYYYMMDD_HHMMSS/
    ├── report.json     # structured data
    ├── report.html     # visual report (open in browser)
    ├── session.log     # chronological log
    └── files/          # downloaded files (harvester)
```

---

## Legal

> **For authorized targets only.**
> Using this tool against systems without explicit written permission is illegal.
> The author assumes no responsibility for misuse.
> Always obtain proper authorization before testing.

---

## Author

**GhostOpcode** — v1.0.0

---

## Disclaimer

This tool is intended for:

- Authorized penetration testing
- CTF competitions
- Security research on owned systems
- Educational purposes

**Unauthorized use is illegal and unethical.**
