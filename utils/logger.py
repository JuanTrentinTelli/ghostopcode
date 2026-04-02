"""
Session-scoped forensic log: timestamped plain-text lines in session.log.
Keeps one file handle open for the session (thread-safe) to avoid FD exhaustion.
"""

from __future__ import annotations

import re
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import TextIO

from utils.redact import redact_string

_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Whole-line matches only — conservative (menu choices like "1" are not matched).
SENSITIVE_INPUT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^CONFIRM$", re.IGNORECASE),
    re.compile(r"^[a-f0-9]{32,}$", re.IGNORECASE),
    re.compile(r"^\$2[aby]?\$\d+\$[./A-Za-z0-9]{53}$"),
    re.compile(r"^[a-zA-Z0-9+/]{43}=$"),
]

_VULN_CONFIRM_PROMPT = "Type 'CONFIRM' to proceed with vuln scan:"


def _is_sensitive_input_value(value: str) -> bool:
    """True if stripped value matches a sensitive operator-input pattern."""
    v = value.strip()
    if not v:
        return False
    for pattern in SENSITIVE_INPUT_PATTERNS:
        if pattern.match(v):
            return True
    return False


_HASH_LINE = re.compile(r"^\[HASH\]\s+\S")
_HASH_SUMMARY = re.compile(r"^Hash\s*:\s*\S")
_PLAINTEXT_SUMMARY = re.compile(r"^Plaintext\s*:\s*\S")


def _redact_tty_line_if_needed(plain_line: str) -> str:
    """
    Replace echoed prompts / operator lines that must not persist in session.log.
    """
    s = plain_line.strip()
    if not s:
        return plain_line
    if _VULN_CONFIRM_PROMPT in s:
        return "[prompt redacted: vuln scan authorization]"
    if _is_sensitive_input_value(s):
        return "[operator input redacted]"
    if _HASH_LINE.match(s):
        return "[HASH] [value redacted from session log mirror]"
    if _HASH_SUMMARY.match(s):
        return "Hash      : [redacted]"
    if _PLAINTEXT_SUMMARY.match(s):
        return "Plaintext : [redacted]"
    return plain_line


def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)


class _StdoutTee:
    """Duplicate stdout writes to the session log via SessionLogger (no per-line open)."""

    def __init__(self, real: TextIO, logger: "SessionLogger") -> None:
        self._real = real
        self._logger = logger

    def write(self, data: str | bytes) -> int:
        if isinstance(data, bytes):
            s = data.decode("utf-8", errors="replace")
            self._real.write(s)
            self._real.flush()
        else:
            self._real.write(data)
            self._real.flush()
            s = data
        if s and s.strip():
            plain = _strip_ansi(s)
            for part in plain.splitlines():
                if part.strip():
                    self._logger.write_tty(part)
        return len(data)

    def flush(self) -> None:
        self._real.flush()

    def isatty(self) -> bool:
        return self._real.isatty()

    def fileno(self) -> int:
        return self._real.fileno()

    @property
    def encoding(self) -> str:
        return getattr(self._real, "encoding", "utf-8") or "utf-8"

    @property
    def errors(self) -> str | None:
        return getattr(self._real, "errors", None)


class SessionLogger:
    """
    Timestamped session.log: explicit log() + optional stdout tee during module run.
    Single open file handle per session (thread-safe).
    """

    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.output_dir / "session.log"
        self.entries: list[str] = []
        self._orig_stdout: TextIO | None = None
        self._tee: _StdoutTee | None = None
        self._file: TextIO | None = None
        self._lock = threading.Lock()

    def _open_append(self) -> None:
        """Open log for append if not already open (must hold _lock)."""
        if self._file is None or self._file.closed:
            self._file = open(
                self.log_path,
                "a",
                encoding="utf-8",
                errors="replace",
            )

    def write_tty(self, plain_line: str) -> None:
        """Thread-safe line from stdout tee — no ANSI."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        clean = _strip_ansi(plain_line).strip()
        if not clean:
            return
        clean = _redact_tty_line_if_needed(clean)
        redacted = redact_string(clean)
        entry = f"[{ts}] [TTY] {redacted}\n"
        with self._lock:
            self._open_append()
            assert self._file is not None
            self._file.write(entry)
            self._file.flush()

    def log(self, message: str, level: str = "INFO") -> None:
        """Thread-safe log line — file stays open."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        clean_msg = _strip_ansi(message)
        redacted_msg = redact_string(clean_msg)
        entry = f"[{timestamp}] [{level}] {redacted_msg}\n"
        self.entries.append(entry.rstrip("\n"))
        with self._lock:
            self._open_append()
            assert self._file is not None
            self._file.write(entry)
            self._file.flush()

    def _is_sensitive_input(self, value: str) -> bool:
        """Conservative match for operator-typed secrets (used by log_operator_action)."""
        return _is_sensitive_input_value(value)

    def log_operator_action(
        self,
        action: str,
        value: str,
        redact: bool = False,
        placeholder: str = "[operator input]",
    ) -> None:
        """
        Log what the operator did without persisting raw sensitive input.

        Never raises — logging is best-effort and must not break the main flow.
        """
        try:
            vs = (value or "").strip()
            if redact:
                log_value = placeholder if vs else "[empty input]"
            else:
                if not vs:
                    if placeholder == "":
                        self.log(action, level="OPERATOR")
                        return
                    log_value = "[empty input]"
                elif self._is_sensitive_input(vs):
                    log_value = placeholder or "[operator input]"
                else:
                    log_value = vs
            self.log(f"{action}: {log_value}", level="OPERATOR")
        except Exception:  # noqa: BLE001 — best-effort audit line
            pass

    def write_header(self, target: str, modules: list[str]) -> None:
        """Start a fresh log file with session header."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.close()
        if self.log_path.exists():
            self.log_path.unlink()
        self.entries.clear()
        with self._lock:
            self._file = open(
                self.log_path,
                "w",
                encoding="utf-8",
                errors="replace",
            )
        self.log("=" * 70)
        self.log("GHOSTOPCODE — Recon Session")
        self.log(f"Target  : {target}")
        self.log(f"Modules : {', '.join(modules)}")
        self.log(f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("=" * 70)

    def write_footer(self, duration: str) -> None:
        """Append session footer."""
        self.log("=" * 70)
        self.log(f"Session complete — Duration: {duration}")
        self.log(f"Ended : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("=" * 70)

    def start_stdout_tee(self) -> None:
        """Mirror stdout to session.log (shared handle, no open-per-write)."""
        if self._orig_stdout is not None:
            return
        self._orig_stdout = sys.stdout
        self._tee = _StdoutTee(sys.__stdout__, self)
        sys.stdout = self._tee  # type: ignore[assignment]

    def stop_stdout_tee(self) -> None:
        if self._orig_stdout is not None:
            sys.stdout = self._orig_stdout
            self._orig_stdout = None
            self._tee = None

    def close(self) -> None:
        """Flush and close log file (end of session)."""
        with self._lock:
            if self._file is not None and not self._file.closed:
                self._file.flush()
                self._file.close()
            self._file = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass
