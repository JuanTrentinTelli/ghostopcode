# GhostOpcode

![Version](https://img.shields.io/badge/Version-1.7.0-orange?style=flat-square)
![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

**GhostOpcode** é um framework interativo de reconhecimento ofensivo **local** (Python): DNS, subdomínios, port scan, HTTP, relatórios JSON/HTML e sessão em disco. Use **apenas** em alvos autorizados.

```bash
python main.py
```

---

## Módulos (menu)

| # | Nome | Descrição |
|---|------|-----------|
| 1 | DNS recon | A/MX/NS/TXT + tentativa de zone transfer |
| 2 | Subdomain enum | Bruteforce com wordlist |
| 3 | WHOIS | Registro + fingerprint técnico |
| 4 | Port scan | Socket + nmap + banner (3 níveis) |
| 5 | Dir enum | Bruteforce de caminhos |
| 6 | Harvester | Crawl + PDF/DOC/XLS + e-mails + vazamentos |
| 7 | HTTP methods | OPTIONS / PUT / DELETE / TRACE |
| 8 | JS recon | Endpoints + segredos + source maps |
| 9 | Hash module | Identificar + crack local |
| 10 | WAF detection | Fingerprint WAF/IDS/CDN |
| 11 | URL harvester | GAU + URLs históricas + padrões |
| 12 | **Subfinder** | Enum passiva de subdomínios (CT + fontes OSINT). Agrupamento por IP com **ASN lookup via RDAP** (sem ranges hardcoded). |
| 13 | **dnsx** | Resolução DNS em massa + deteção de wildcard. Valida FQDNs com A/AAAA/CNAME/MX (e mais), CDN via flags do binário. |
| 14 | **httpx** | Probe HTTP/HTTPS em massa. Título, status, tecnologias (Wappalyzer), TLS, CDN; múltiplas portas por host; stdin + `-nf` para HTTP e HTTPS. |
| 15 | ARP scan | Apenas CIDR |
| 16 | Packet sniffer | IP único ou CIDR |

CVE lookup (NVD) corre automaticamente quando há port scan ou WHOIS na sessão.

---

## Subdomain intelligence chain

Os módulos **12 → 13 → 14** formam uma cadeia que transforma um domínio em **superfície web priorizada**:

```
[12] subfinder  →  subdomínios descobertos passivamente
         ↓            + agrupamento por IP (ASN via RDAP)
[13] dnsx       →  FQDNs validados com registros DNS completos
         ↓            + wildcard + CDN
[14] httpx      →  serviços HTTP/HTTPS vivos
                   + título + tecnologia + status + TLS
```

**Em cerca de 2 minutos** (dependendo do alvo e da rede), o operador obtém:

- Quantos subdomínios existem e onde estão hospedados  
- Indícios de cloud/CDN (via RDAP + probes)  
- IPs que concentram mais serviços (candidatos a vhost / priorização)  
- Serviços web vivos, título, stack e classificação de risco  

**Seleção combinada** (a sessão injeta resultados automaticamente):

```text
→ selecionar: 12 13 14
```

O **dnsx** consome subdomínios já encontrados pelo subfinder (e/ou enum por wordlist); o **httpx** prioriza saída validada do **dnsx**, depois subfinder, depois subdomain enum.

---

## Requisitos

- Python 3.10+  
- Dependências: `pip install -r requirements.txt`  

Wordlists: o projeto tenta caminhos típicos do Kali (SecLists). Veja diagnóstico ao arrancar o `main.py`.

---

## Ferramentas externas (opcionais)

| Ferramenta | Instalação (exemplo) | Uso |
|------------|----------------------|-----|
| **subfinder** | `sudo apt install subfinder` ou `go install … subfinder@latest` | Módulo [12] |
| **dnsx** | `sudo apt install dnsx` | Módulo [13] |
| **httpx** (ProjectDiscovery) | [Releases](https://github.com/projectdiscovery/httpx/releases) — binário Linux ou `go install … httpx@latest` | Módulo [14] |
| **nmap** | `sudo apt install nmap` | Módulo [4] |
| **hashcat** | `sudo apt install hashcat` | Módulo [9] |

Se o binário não existir, o módulo correspondente reporta `not_installed` e o resto do menu continua utilizável.

---

## Saída

- Diretório de sessão sob `output/` (ignorado pelo git)  
- Relatórios **JSON** + **HTML** + **log** por sessão  

---

## Changelog

| Versão | O que mudou |
|--------|-------------|
| **v1.7.0** | **Subdomain intelligence chain:** agrupamento por IP + ASN (RDAP) no subfinder/subdomain enum (`utils/asn_lookup.py`, `utils/subdomain_intel.py`) · módulo **[13] dnsx** — resolução em massa, wildcard, JSONL · módulo **[14] httpx** — probe HTTP/HTTPS, tech/TLS, múltiplas portas, hosts vs URLs no resumo da tabela RESULTS · `resume.cfg` no `.gitignore` |
| v1.6.0 | Segurança de artefatos (redact) · TLS configurável · lazy import · caches NVD/DNS · limites de memória · hardening de paths · intel SPF/DMARC/DKIM · nmap 3 níveis · SESSION COMPLETE · hash skipped no RUN ALL |
| v1.5.0 | Parser SPF/DMARC/DKIM · quiet/debug · refactor `base_module` |
| v1.4.1 | Subfinder no lugar do AMASS |
| v1.4.0 | WAF Detection · URL Harvester · Subfinder · verbosidade no terminal |
| v1.3.1 | Filtro CVEs genéricos · hotfix logger |
| v1.3.0 | nmap -sV no port scan |
| v1.2.0 | CVE lookup automático (NVD API) |
| v1.1.0 | Hotfixes: logger, wordlists, catchall |
| v1.0.0 | Lançamento inicial — recon modular |

---

## Aviso legal

Autorize sempre o alvo por escrito. O uso indevido é da sua exclusiva responsabilidade.

---

*v1.7.0 · by GhostOpcode*
