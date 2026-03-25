# Installation Guide

## Quick Start (Kali Linux)

```bash
git clone https://github.com/JuanTrentinTelli/ghostopcode.git
cd ghostopcode
pip install -r requirements.txt
python main.py
```

## Other Linux distros

```bash
# Install system dependencies
sudo apt install python3 python3-pip nmap       # Debian/Ubuntu
sudo dnf install python3 python3-pip nmap       # Fedora/RHEL
sudo pacman -S python python-pip nmap           # Arch

# Install SecLists (optional but recommended)
sudo git clone https://github.com/danielmiessler/SecLists /usr/share/seclists

# Install rockyou (for hash cracking)
# Download from: https://github.com/brannondorsey/naive-hashcat/releases
# Place at: wordlists/rockyou.txt

# Clone and install
git clone https://github.com/JuanTrentinTelli/ghostopcode.git
cd ghostopcode
pip install -r requirements.txt
python main.py
```

## Virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

## Troubleshooting

### "Permission denied" on ARP scan / sniffer

```bash
sudo python main.py
```

### "Wordlist not found"

```bash
sudo apt install seclists    # Kali/Debian
```

### "Module not found"

```bash
pip install -r requirements.txt --upgrade
```

### nmap not found

```bash
sudo apt install nmap
```
