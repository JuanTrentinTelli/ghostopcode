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

**v1.3.1 · by GhostOpcode · Python Recon Framework**

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.3.1-orange?style=flat-square)

> Framework de reconhecimento ofensivo — 100% local, zero APIs externas (exceto CVE lookup opcional)

</div>

---

## O que é o GhostOpcode?

GhostOpcode é uma ferramenta de **reconhecimento ofensivo** (recon)
desenvolvida para pentesters, estudantes de segurança e entusiastas de CTF.

Ela automatiza a fase de coleta de informações antes de um pentest,
reunindo em uma única interface interativa tudo que você precisa saber
sobre um alvo — domínio, IP ou rede local.

**Não requer argumentos** — basta rodar e seguir o menu interativo.

---

## Funcionalidades

| # | Módulo | O que faz |
|---|--------|-----------|
| 1 | **DNS Recon** | Consulta registros A, MX, NS, TXT, SOA. Tenta zone transfer (AXFR). Detecta tecnologias via DNS. |
| 2 | **Subdomain Enum** | Descobre subdomínios via wordlist + bruteforce. Detecta wildcard DNS e candidatos a subdomain takeover. |
| 3 | **WHOIS + Fingerprint** | Dados de registro do domínio/IP. Detecta web server, CMS, CDN, linguagem backend via headers HTTP. Audita certificado SSL. |
| 4 | **Port Scan** | Varredura TCP de portas (qualquer range). Identificação precisa de serviços via nmap -sV. Banner grabbing. Inferência de SO. |
| 5 | **Dir Enum** | Bruteforce de diretórios e arquivos (Fast/Normal/Full). Detecta catchall HTTP. Categoriza findings por risco. |
| 6 | **Harvester** | Rastreia o site e baixa PDFs, DOCs, XLS. Extrai emails, nomes, perfis LinkedIn. Escaneia arquivos sensíveis expostos (.env, .git, backups). Extrai metadata de documentos. |
| 7 | **HTTP Methods** | Testa métodos HTTP perigosos (PUT, DELETE, TRACE). Detecta CORS misconfiguration. Audita security headers. |
| 8 | **JS Recon** | Analisa arquivos JavaScript do alvo. Extrai endpoints de API hardcoded, secrets (AWS keys, tokens), e source maps expostos. |
| 9 | **Hash Module** | Identifica o algoritmo de um hash. Tenta quebrar via wordlist local (rockyou). Integra com hashcat se disponível. |
| A | **ARP Scan** | Descobre hosts ativos em rede local via ARP. Identifica fabricante pelo MAC address. Requer CIDR como alvo e root/sudo. |
| S | **Packet Sniffer** | Captura tráfego de rede em tempo real. Analisa protocolos e extrai inteligência passiva. Requer root/sudo. |
| ★ | **CVE Lookup** | Roda automaticamente após port scan. Consulta a NVD (National Vulnerability Database) com os serviços e versões encontrados. Retorna CVEs relevantes com CVSS score. |

---

## Relatórios automáticos

Ao final de cada sessão, o GhostOpcode gera **3 arquivos automaticamente**:

```
output/
└── alvo_20260325_143022/
    ├── report.json     # Dados completos estruturados
    ├── report.html     # Relatório visual (abrir no browser)
    └── session.log     # Log cronológico da sessão
```

---

## Requisitos

- **Python 3.10+**
- **Linux** (Kali Linux recomendado)
- **nmap** instalado no sistema
- **Root/sudo** apenas para ARP scan e packet sniffer

---

## Instalação

### 1. Clonar o repositório

```bash
git clone https://github.com/JuanTrentinTelli/ghostopcode.git
cd ghostopcode
```

### 2. Instalar dependências Python

```bash
pip install -r requirements.txt
```

### 3. Instalar wordlists (Kali Linux)

```bash
sudo apt install seclists wordlists
```

O GhostOpcode detecta automaticamente as wordlists do Kali.
Se estiver em outra distro, veja a seção [Wordlists](#wordlists).

### 4. Instalar nmap

```bash
sudo apt install nmap
```

### 5. (Opcional) Configurar CVE lookup

```bash
# Criar arquivo .env na raiz do projeto
echo "NVD_API_KEY=sua-chave-aqui" > .env
```

Obtenha sua chave gratuita em: https://nvd.nist.gov/developers/request-an-api-key

---

## Como usar

```bash
# Uso padrão — menu interativo
python main.py

# Com root (necessário para ARP scan e sniffer)
sudo python main.py
```

### Exemplo de sessão

```
Enter target (domain / IP / CIDR):
❯ exemplo.com                    # domínio
❯ 192.168.1.1                   # IP
❯ 192.168.1.0/24                # rede local (CIDR)

Select modules:
[1] DNS recon
[2] Subdomain enum
...
[0] RUN ALL — executa todos os módulos disponíveis
```

### Configurações disponíveis

| Opção | Descrição | Exemplo |
|-------|-----------|---------|
| Threads | Conexões paralelas | 50 (padrão), 200 (agressivo) |
| Timeout | Tempo por conexão | 5s (padrão), 2s (rápido) |
| Ports | Range de portas | `common`, `1-1024`, `80,443`, `1-65535` |
| Dir mode | Velocidade do dir enum | Fast (~30s), Normal (~5min), Full (~20min) |

---

## Wordlists

O GhostOpcode detecta automaticamente as wordlists do Kali Linux.

**Kali Linux:**

```bash
sudo apt install seclists wordlists
```

**Outras distros:**

```bash
# SecLists
sudo git clone https://github.com/danielmiessler/SecLists /usr/share/seclists

# rockyou (para hash cracking)
# Baixar em: https://github.com/brannondorsey/naive-hashcat/releases
# Salvar em: wordlists/rockyou.txt
```

**Manual (qualquer sistema):**
Crie a pasta `wordlists/` e adicione seus próprios arquivos:

```
wordlists/
├── subdomains-top1million.txt
├── directory-list-2.3-medium.txt
└── rockyou.txt
```

---

## Alvos de teste (autorizados)

Para testar sem precisar de autorização especial:

| Alvo | Tipo | Descrição |
|------|------|-----------|
| `scanme.nmap.org` | Domínio | Servidor oficial do nmap para testes |
| `testphp.vulnweb.com` | Domínio | Servidor vulnerável oficial da Acunetix |
| `45.33.32.156` | IP | IP do scanme.nmap.org |

---

## Changelog

| Versão | O que mudou |
|--------|-------------|
| v1.3.1 | Filtro de CVEs genéricos/unknown |
| v1.3.0 | nmap -sV integrado no port scan para identificação precisa |
| v1.2.0 | CVE lookup automático com NVD API |
| v1.1.0 | Hotfixes: logger, wordlists, catchall detection |
| v1.0.0 | Lançamento inicial — 12 módulos de recon |

---

## Aviso legal

> **Para uso em alvos autorizados apenas.**
>
> O uso desta ferramenta contra sistemas sem autorização
> prévia e por escrito é **ilegal** em praticamente todos os países.
>
> O autor não se responsabiliza pelo mau uso desta ferramenta.
> Sempre obtenha autorização antes de realizar qualquer teste.

---

## Autor

**GhostOpcode** · v1.3.1 · Python Recon Framework

[![GitHub](https://img.shields.io/badge/GitHub-JuanTrentinTelli-black?style=flat-square&logo=github)](https://github.com/JuanTrentinTelli/ghostopcode)
