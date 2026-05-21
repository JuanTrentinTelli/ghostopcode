"""
GhostOpcode terminal theme — single source of truth for color tokens and console.

Import these instead of redefining per-module:
    from utils.theme import C_PRI, C_DIM, C_ERR, C_WARN, C_MUTED, C_PANEL, C_ACCENT, console
"""

from __future__ import annotations

from rich.console import Console

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_PANEL = "#8B9CA8"
C_ACCENT = "#8B9CA8"

console = Console(highlight=False, force_terminal=True)
