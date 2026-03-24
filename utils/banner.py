"""GhostOpcode terminal banner — ASCII identity and typewriter wake-up."""

from __future__ import annotations

import os
import sys
import time

from rich.console import Console
from rich.text import Text

# Matrix primary — surgical green
_MATRIX = "#00FF41"
_COLD_GRAY = "#8B9CA8"
_DISCLAIMER = "#6B1C1C"

_ASCII_LINES = r"""
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
""".strip("\n")

_INFO_LINE = "v1.0.3  ·  by GhostOpcode  ·  python recon framework"
_DISCLAIMER_LINE = (
    "[ AUTHORIZED TARGETS ONLY — ILLEGAL USE IS YOUR RESPONSIBILITY ]"
)


def _term_columns() -> int:
    """Return terminal width; fall back to 80 if unavailable."""
    try:
        return max(40, os.get_terminal_size().columns)
    except OSError:
        return 80


def _typewriter_plain(text: str, prefix_ansi: str, suffix_reset: str) -> None:
    """Print one character at a time with a light typewriter cadence."""
    sys.stdout.write(prefix_ansi)
    sys.stdout.flush()
    for char in text:
        print(char, end="", flush=True)
        time.sleep(0.018)
    sys.stdout.write(suffix_reset + "\n")
    sys.stdout.flush()


def _rgb_fg(hex_color: str) -> str:
    """Build ANSI 24-bit foreground sequence for typewriter lines."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"\033[38;2;{r};{g};{b}m"


def show_banner() -> None:
    """Display GhostOpcode ASCII banner with typewriter effect."""
    console = Console(highlight=False, force_terminal=True)
    width = _term_columns()

    # ASCII block — instant impact, matrix green
    for line in _ASCII_LINES.splitlines():
        console.print(Text(line, style=_MATRIX))

    # Separator: exact terminal width, subtle texture
    pat = "▓░▒─"
    seam = (pat * ((width // len(pat)) + 1))[:width]
    console.print(Text(seam, style=_COLD_GRAY))

    reset = "\033[0m"
    _typewriter_plain(_INFO_LINE, _rgb_fg(_MATRIX), reset)
    _typewriter_plain(_DISCLAIMER_LINE, _rgb_fg(_DISCLAIMER), reset)
    print()
