"""
GhostOpcode central configuration — wordlist resolution, defaults, constants.
"""

from __future__ import annotations

from pathlib import Path


def resolve_wordlist(paths: list[str]) -> str | None:
    """
    Try each path in order and return the first that exists.
    Returns None if none found. Never raises.
    """
    try:
        for path in paths:
            try:
                p = Path(path)
                if p.is_file():
                    return str(p.resolve())
            except OSError:
                continue
        return None
    except Exception:  # noqa: BLE001
        return None


def count_lines(path: str) -> int:
    """Count non-empty lines in a file; returns 0 on any failure."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


# ── Wordlists (Kali SecLists / dirbuster first, then project wordlists/) ─────

WORDLIST_SUBDOMAINS = resolve_wordlist(
    [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "wordlists/subdomains-top1million.txt",
    ]
)

# Fast dir enum (~5k paths) — prefer SecLists common.txt
WORDLIST_DIRS_FAST = resolve_wordlist(
    [
        "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "wordlists/common.txt",
    ]
)

# Normal dir enum (~87k paths) — dirbuster small
WORDLIST_DIRS_SMALL = resolve_wordlist(
    [
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "wordlists/directory-list-2.3-small.txt",
    ]
)

# Full dir enum — medium list + smart extension expansion in dir_enum
WORDLIST_DIRS = resolve_wordlist(
    [
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "wordlists/directory-list-2.3-medium.txt",
    ]
)

WORDLIST_FILES = resolve_wordlist(
    [
        "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
        "wordlists/common-files.txt",
    ]
)

WORDLIST_PASSWORDS = resolve_wordlist(
    [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/seclists/Passwords/rockyou.txt",
        "/usr/share/seclists/Passwords/rockyou.txt",
        "wordlists/rockyou.txt",
    ]
)

# ── Network ─────────────────────────────────────────────────────────────────
DEFAULT_THREADS = 50
DEFAULT_TIMEOUT = 5  # seconds

# Subfinder passive enum (wall-clock budget; CLI ``-timeout`` is also in seconds)
SUBFINDER_TIMEOUT = 300

# ── Port scan ───────────────────────────────────────────────────────────────
COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1723,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    8888,
    27017,
]

# ── User-Agent ────────────────────────────────────────────────────────────────
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
)
USER_AGENT = DEFAULT_USER_AGENT

# ── Output ──────────────────────────────────────────────────────────────────
OUTPUT_DIR = "output"

# ── Meta ────────────────────────────────────────────────────────────────────
VERSION = "1.5.0"
AUTHOR = "GhostOpcode"
