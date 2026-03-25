"""
GhostOpcode hash module — identify, local wordlist crack, optional hashcat.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.text import Text

import config as app_config

console = Console(highlight=False, force_terminal=True)

C_PRI = "#00FF41"
C_DIM = "#6F7F86"
C_ERR = "#FF3B3B"
C_WARN = "#E8C547"
C_MUTED = "#4A5A62"
C_ACCENT = "#8B9CA8"

# (name, meta) — order matters for tie-break; structured formats first.
_HASH_SIGNATURES_ITEMS: list[tuple[str, dict[str, Any]]] = [
    (
        "bcrypt",
        {
            "length": None,
            "pattern": r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$",
            "hashcat": 3200,
            "hashlib": None,
            "risk": "LOW",
            "note": "Strong — very slow to crack; prefer GPU hashcat",
        },
    ),
    (
        "WordPress",
        {
            "length": None,
            "pattern": r"^\$P\$[a-zA-Z0-9./]{31}$",
            "hashcat": 400,
            "hashlib": None,
            "risk": "MEDIUM",
            "note": "WordPress phpass — slow but crackable",
        },
    ),
    (
        "SHA512crypt",
        {
            "length": None,
            "pattern": r"^\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}$",
            "hashcat": 1800,
            "hashlib": None,
            "risk": "MEDIUM",
            "note": "Linux shadow hash (SHA-512)",
        },
    ),
    (
        "SHA256crypt",
        {
            "length": None,
            "pattern": r"^\$5\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{43}$",
            "hashcat": 7400,
            "hashlib": None,
            "risk": "MEDIUM",
            "note": "Linux shadow hash (SHA-256)",
        },
    ),
    (
        "MD5crypt",
        {
            "length": None,
            "pattern": r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$",
            "hashcat": 500,
            "hashlib": None,
            "risk": "HIGH",
            "note": "Linux shadow hash (MD5)",
        },
    ),
    (
        "MySQL41",
        {
            "length": 41,
            "pattern": r"^\*[a-fA-F0-9]{40}$",
            "hashcat": 300,
            "hashlib": None,
            "risk": "HIGH",
            "note": "MySQL 4.1+ password hash",
        },
    ),
    (
        "MySQL323",
        {
            "length": 16,
            "pattern": r"^[a-fA-F0-9]{16}$",
            "hashcat": 200,
            "hashlib": None,
            "risk": "CRITICAL",
            "note": "Ancient MySQL hash — trivially crackable",
        },
    ),
    (
        "MD5",
        {
            "length": 32,
            "pattern": r"^[a-fA-F0-9]{32}$",
            "hashcat": 0,
            "hashlib": "md5",
            "risk": "CRITICAL",
            "note": "Broken algorithm — trivially crackable",
        },
    ),
    (
        "NTLM",
        {
            "length": 32,
            "pattern": r"^[a-fA-F0-9]{32}$",
            "hashcat": 1000,
            "hashlib": None,
            "risk": "CRITICAL",
            "note": "Windows password hash — indistinguishable from MD5 by length alone",
        },
    ),
    (
        "MD4",
        {
            "length": 32,
            "pattern": r"^[a-fA-F0-9]{32}$",
            "hashcat": 900,
            "hashlib": None,
            "risk": "HIGH",
            "note": "Legacy — same hex length as MD5",
        },
    ),
    (
        "SHA1",
        {
            "length": 40,
            "pattern": r"^[a-fA-F0-9]{40}$",
            "hashcat": 100,
            "hashlib": "sha1",
            "risk": "HIGH",
            "note": "Deprecated — collision attacks possible",
        },
    ),
    (
        "RIPEMD160",
        {
            "length": 40,
            "pattern": r"^[a-fA-F0-9]{40}$",
            "hashcat": 6000,
            "hashlib": None,
            "risk": "MEDIUM",
            "note": "Same length as SHA1 — ambiguous without context",
        },
    ),
    (
        "SHA224",
        {
            "length": 56,
            "pattern": r"^[a-fA-F0-9]{56}$",
            "hashcat": 1300,
            "hashlib": "sha224",
            "risk": "MEDIUM",
        },
    ),
    (
        "SHA256",
        {
            "length": 64,
            "pattern": r"^[a-fA-F0-9]{64}$",
            "hashcat": 1400,
            "hashlib": "sha256",
            "risk": "MEDIUM",
        },
    ),
    (
        "SHA384",
        {
            "length": 96,
            "pattern": r"^[a-fA-F0-9]{96}$",
            "hashcat": 10800,
            "hashlib": "sha384",
            "risk": "LOW",
        },
    ),
    (
        "SHA512",
        {
            "length": 128,
            "pattern": r"^[a-fA-F0-9]{128}$",
            "hashcat": 1700,
            "hashlib": "sha512",
            "risk": "LOW",
        },
    ),
    (
        "Whirlpool",
        {
            "length": 128,
            "pattern": r"^[a-fA-F0-9]{128}$",
            "hashcat": 6100,
            "hashlib": None,
            "risk": "LOW",
            "note": "Same length as SHA512 — ambiguous without context",
        },
    ),
    (
        "CRC32",
        {
            "length": 8,
            "pattern": r"^[a-fA-F0-9]{8}$",
            "hashcat": 11500,
            "hashlib": None,
            "risk": "INFO",
            "note": "Checksum — not a password hash",
        },
    ),
]

HASH_SIGNATURES: dict[str, dict[str, Any]] = dict(_HASH_SIGNATURES_ITEMS)


def identify_hash(hash_str: str) -> list[dict[str, Any]]:
    """
    Identify possible hash algorithms by length and character pattern.
    Returns candidates sorted by likelihood (structured formats first, then hex families).
    """
    h = hash_str.strip()
    if not h:
        return []

    out: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    order = 0
    for name, meta in _HASH_SIGNATURES_ITEMS:
        plen = meta.get("length")
        if plen is not None and len(h) != plen:
            continue
        try:
            if not re.match(meta["pattern"], h, re.ASCII):
                continue
        except re.error:
            continue
        if name in seen_names:
            continue
        seen_names.add(name)
        conf = "HIGH"
        if name in ("NTLM", "MD4", "RIPEMD160", "Whirlpool"):
            conf = "MEDIUM"
        out.append(
            {
                "algorithm": name,
                "confidence": conf,
                "hashcat_mode": meta.get("hashcat"),
                "hashlib": meta.get("hashlib"),
                "risk": meta.get("risk", "MEDIUM"),
                "note": meta.get("note", ""),
                "sort_key": order,
            }
        )
        order += 1

    return out


def word_variations(word: str) -> list[str]:
    """Generate common password variations from a base word."""
    w = word.rstrip("\n\r")
    if not w:
        return []
    variations = [
        w,
        w.lower(),
        w.upper(),
        w.capitalize(),
        w + "1",
        w + "123",
        w + "!",
        w + "2024",
        w + "2025",
        w + "2026",
        w[0].upper() + w[1:] if len(w) > 1 else w.upper(),
    ]
    return list(dict.fromkeys(variations))


def _ntlm_hex(password: str) -> str | None:
    """NTLM = MD4(UTF-16LE(password)); hex uppercase common."""
    try:
        if "md4" not in hashlib.algorithms_available:
            return None
        d = hashlib.new("md4", password.encode("utf-16le")).hexdigest()
        return d.lower()
    except Exception:  # noqa: BLE001
        return None


def _digest_hex(password: str, hashlib_name: str) -> str | None:
    try:
        h = hashlib.new(hashlib_name, password.encode("utf-8", errors="ignore"))
        return h.hexdigest().lower()
    except Exception:  # noqa: BLE001
        return None


def _speed_str(h_per_sec: float) -> str:
    if h_per_sec >= 1_000_000:
        return f"{h_per_sec / 1_000_000:.1f}M h/s"
    if h_per_sec >= 1_000:
        return f"{h_per_sec / 1_000:.1f}k h/s"
    return f"{h_per_sec:.0f} h/s"


def _sliding_speed_hps(samples: list[tuple[float, int]], now: float, window: float = 2.0) -> float:
    """Hashes per second from (monotonic_time, total_count) samples in the last `window` seconds."""
    cutoff = now - window
    recent = [(t, c) for t, c in samples if t >= cutoff]
    if len(recent) < 2:
        return 0.0
    t0, c0 = recent[0]
    t1, c1 = recent[-1]
    dt = t1 - t0
    if dt <= 0:
        return 0.0
    return (c1 - c0) / dt


def _local_crackable_algorithms(candidates: list[dict[str, Any]]) -> list[str]:
    """Ordered algorithm names we can test with hashlib / md4."""
    names: list[str] = []
    for c in candidates:
        alg = c["algorithm"]
        if c.get("hashlib"):
            if alg not in names:
                names.append(alg)
        elif alg == "NTLM" and "md4" in hashlib.algorithms_available:
            if alg not in names:
                names.append(alg)
    return names


def _check_password_against_algorithms(
    password: str,
    target_lower: str,
    ordered_algos: list[str],
) -> str | None:
    """Return algorithm name if any digest matches target (hex, lower)."""
    for alg in ordered_algos:
        meta = HASH_SIGNATURES.get(alg, {})
        lib = meta.get("hashlib")
        if lib:
            d = _digest_hex(password, lib)
            if d and d == target_lower:
                return alg
        if alg == "NTLM":
            n = _ntlm_hex(password)
            if n and n == target_lower:
                return "NTLM"
    return None


def crack_local(
    hash_str: str,
    algorithm: str,
    hashlib_name: str | None,
    wordlist: str,
    timeout: float,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Brute-force with hashlib (+ optional MD4/NTLM) over a wordlist with Rich progress.
    Uses a 2s sliding window for displayed speed. Respects timeout (seconds); 0 = no limit.
    """
    _ = algorithm
    _ = hashlib_name
    target = hash_str.strip()
    target_lower = target.lower()
    ordered = _local_crackable_algorithms(candidates)
    t0 = time.perf_counter()
    errors: list[str] = []

    if not ordered:
        return {
            "cracked": False,
            "plaintext": None,
            "attempts": 0,
            "duration_s": 0.0,
            "speed": "0 h/s",
            "algorithm": None,
            "errors": ["No hashlib-supported candidate for local crack (try hashcat)"],
        }

    wl_path = Path(wordlist)
    if not wl_path.is_file():
        return {
            "cracked": False,
            "plaintext": None,
            "attempts": 0,
            "duration_s": 0.0,
            "speed": "0 h/s",
            "algorithm": None,
            "errors": [f"Wordlist not found: {wordlist}"],
        }

    attempts = 0
    speed_samples: list[tuple[float, int]] = []
    interrupted = False
    plaintext: str | None = None
    win_alg: str | None = None

    try:
        total_lines = max(1, app_config.count_lines(str(wl_path)))
    except Exception:  # noqa: BLE001
        total_lines = 1

    wl_name = wl_path.name
    primary = ordered[0]
    console.print()
    console.print(
        Text(
            f" [CRACK] Local wordlist — {primary} · {wl_name}",
            style=f"bold {C_WARN}",
        )
    )

    try:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TextColumn("{task.fields[speed]}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"[{C_DIM}]{ordered[0]}[/{C_DIM}]",
                total=total_lines,
                speed="",
            )
            with wl_path.open("r", encoding="utf-8", errors="ignore") as f:
                line_no = 0
                last_ui = time.monotonic()
                for line in f:
                    if timeout > 0 and (time.perf_counter() - t0) >= timeout:
                        errors.append("Local crack stopped: timeout reached")
                        break
                    line_no += 1
                    for var in word_variations(line):
                        attempts += 1
                        hit = _check_password_against_algorithms(
                            var, target_lower, ordered
                        )
                        if hit:
                            plaintext = var
                            win_alg = hit
                            progress.update(
                                task, completed=total_lines, speed=""
                            )
                            break
                    if plaintext:
                        break

                    now_m = time.monotonic()
                    speed_samples.append((now_m, attempts))
                    progress.update(task, completed=min(line_no, total_lines))
                    if now_m - last_ui >= 0.25:
                        last_ui = now_m
                        hps = _sliding_speed_hps(speed_samples, now_m, 2.0)
                        elapsed = time.perf_counter() - t0
                        progress.update(
                            task,
                            speed=f"· [dim]{_speed_str(hps)} · {elapsed:.1f}s[/dim]",
                        )
    except KeyboardInterrupt:
        interrupted = True
        errors.append("Interrupted during local crack")

    duration = time.perf_counter() - t0
    hps = _sliding_speed_hps(speed_samples, time.monotonic(), 2.0) if speed_samples else (
        attempts / duration if duration > 0 else 0.0
    )
    speed_s = _speed_str(hps)

    if plaintext:
        console.print()
        console.print(Text(" [✓] CRACKED (local wordlist)", style=f"bold {C_PRI}"))
        console.print(Text(f"     Plaintext : {plaintext}", style=C_DIM))
        console.print(Text(f"     Algorithm : {win_alg}", style=C_MUTED))
        console.print(
            Text(
                f"     Attempts  : {attempts:,} · Duration: {duration:.2f}s · {speed_s}",
                style=C_MUTED,
            )
        )
    else:
        console.print()
        console.print(Text(" [✗] Not found in wordlist (local)", style=C_ERR))
        console.print(
            Text(
                f"     Tried: {attempts:,} hashes · {speed_s} · {duration:.1f}s",
                style=C_MUTED,
            )
        )
        console.print(
            Text(
                "     Suggestion: hashcat with rules / larger wordlist / GPU",
                style=C_WARN,
            )
        )
        if interrupted:
            console.print(Text("     (stopped early)", style=C_WARN))

    return {
        "cracked": bool(plaintext),
        "plaintext": plaintext,
        "attempts": attempts,
        "duration_s": round(duration, 3),
        "speed": speed_s,
        "algorithm": win_alg,
        "errors": errors,
    }


def check_hashcat() -> str | None:
    """Return path to hashcat binary if available."""
    return shutil.which("hashcat")


def parse_hashcat_output(output: str, hash_str: str) -> str | None:
    """Extract plaintext from hashcat stdout (hash:plain) or pot-style lines."""
    prefix = hash_str.strip()[:16]
    h_lower = hash_str.strip().lower()
    for line in output.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        if line.lower().startswith(h_lower[: min(8, len(h_lower))].lower()):
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1]
        if prefix and line.lower().startswith(prefix.lower()):
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1]
    return None


def _read_outfile(path: str, hash_str: str) -> str | None:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    return parse_hashcat_output(text, hash_str)


def crack_hashcat(
    hash_str: str,
    hashcat_mode: int,
    wordlist: str,
    use_rules: bool = False,
) -> dict[str, Any]:
    """
    Run hashcat attack mode 0 (wordlist); optional best64 rules if path exists.
    Never raises — returns status in dict.
    """
    errors: list[str] = []
    hc = check_hashcat()
    if not hc:
        return {
            "cracked": False,
            "plaintext": None,
            "stdout": "",
            "stderr": "",
            "errors": ["hashcat not found in PATH"],
        }

    wl = Path(wordlist)
    if not wl.is_file():
        return {
            "cracked": False,
            "plaintext": None,
            "stdout": "",
            "stderr": "",
            "errors": [f"Wordlist not found: {wordlist}"],
        }

    rule_paths = [
        "/usr/share/hashcat/rules/best64.rule",
        "/opt/hashcat/rules/best64.rule",
    ]
    rule_file = next((p for p in rule_paths if Path(p).is_file()), None)

    tmpdir = tempfile.mkdtemp(prefix="gohash_")
    hash_file = Path(tmpdir) / "hash.txt"
    out_file = Path(tmpdir) / "cracked.txt"
    try:
        hash_file.write_text(hash_str.strip() + "\n", encoding="utf-8")
        cmd: list[str] = [
            hc,
            "-m",
            str(hashcat_mode),
            "-a",
            "0",
            str(hash_file),
            str(wl),
            "-o",
            str(out_file),
            "--outfile-format",
            "2",
            "--quiet",
            "--potfile-disable",
        ]
        if use_rules and rule_file:
            cmd.extend(["-r", rule_file])

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,
            errors="replace",
        )
        plain = _read_outfile(str(out_file), hash_str)
        if not plain and proc.stdout:
            plain = parse_hashcat_output(proc.stdout, hash_str)
        if proc.returncode not in (0, 1):
            # 1 = exhausted, 0 = cracked or OK
            if not plain:
                errors.append(
                    f"hashcat exit {proc.returncode}: "
                    f"{(proc.stderr or proc.stdout or '')[:200]}"
                )
        return {
            "cracked": bool(plain),
            "plaintext": plain,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "errors": errors,
        }
    except subprocess.TimeoutExpired:
        return {
            "cracked": False,
            "plaintext": None,
            "stdout": "",
            "stderr": "",
            "errors": ["hashcat subprocess timeout (1h cap)"],
        }
    except Exception as e:  # noqa: BLE001
        return {
            "cracked": False,
            "plaintext": None,
            "stdout": "",
            "stderr": "",
            "errors": [str(e)],
        }
    finally:
        try:
            hash_file.unlink(missing_ok=True)
            out_file.unlink(missing_ok=True)
            Path(tmpdir).rmdir()
        except OSError:
            pass


def run_hash(hash_value: str, config: dict[str, Any]) -> dict[str, Any]:
    """
    Identify hash, optionally crack locally and/or with hashcat.
    Never raises; fills errors[] on failure paths.
    """
    t0 = time.perf_counter()
    errors: list[str] = []
    hv = (hash_value or "").strip()
    crack_mode = int(config.get("hash_crack_mode", 1))
    timeout = float(config.get("hash_crack_timeout_s", 0.0) or 0.0)
    wl = (
        config.get("hash_wordlist")
        or config.get("wordlist")
        or app_config.WORDLIST_PASSWORDS
    )
    wl_used = str(wl) if wl else ""

    base: dict[str, Any] = {
        "module": "hash_module",
        "hash": hv,
        "status": "error",
        "candidates": [],
        "crack_result": {
            "cracked": False,
            "plaintext": None,
            "method": None,
            "attempts": 0,
            "duration_s": 0.0,
            "speed": None,
        },
        "hashcat_available": bool(check_hashcat()),
        "wordlist_used": wl_used,
        "errors": errors,
        "findings": [],
    }

    console.print(
        Panel(
            Text(
                "  HASH MODULE  ·  identification + crack",
                style=f"bold {C_PRI}",
            ),
            border_style=C_ACCENT,
            box=box.DOUBLE,
            width=min(console.size.width, 82) if console.size else 82,
        )
    )

    if not hv:
        errors.append("Empty hash")
        console.print(Text("  [✗] Empty hash", style=C_ERR))
        base["status"] = "error"
        return base

    try:
        candidates = identify_hash(hv)
        base["candidates"] = [
            {
                "algorithm": c["algorithm"],
                "confidence": c["confidence"],
                "hashcat_mode": c.get("hashcat_mode"),
                "risk": c.get("risk"),
                "note": c.get("note", ""),
            }
            for c in candidates
        ]

        console.print(Text(f"\n [HASH] {hv[:72]}{'…' if len(hv) > 72 else ''}", style=C_DIM))
        if not candidates:
            console.print(
                Text(
                    " [ID] Unknown hash format (no signature match)",
                    style=f"bold {C_WARN}",
                )
            )
            errors.append("Unknown hash format")
            base["status"] = "identified"
        else:
            console.print(Text("\n [ID] Possible algorithms:", style=f"bold {C_WARN}"))
            for c in candidates:
                risk = c.get("risk", "—")
                note = (c.get("note") or "")[:64]
                console.print(
                    Text.assemble(
                        ("   ├── ", C_MUTED),
                        (f"{c['algorithm']:<12}", C_PRI),
                        (f" conf {c['confidence']:<7}", C_DIM),
                        (f" [{risk}]", C_ERR if risk == "CRITICAL" else C_WARN),
                        (f"  {note}", C_MUTED),
                    )
                )
            if any(c["algorithm"] == "bcrypt" for c in candidates):
                console.print(
                    Text(
                        "   [!] bcrypt is slow — local wordlist will crawl; use hashcat + GPU.",
                        style=C_WARN,
                    )
                )

        if crack_mode == 3:
            base["status"] = "identified" if candidates else "error"
            base["crack_result"]["method"] = None
            console.print(
                Text("\n [✓] Identify-only mode — no crack attempted.", style=C_PRI)
            )
            base["findings"] = base["candidates"]
            base["stats"] = {"duration_s": round(time.perf_counter() - t0, 2)}
            return base

        if not wl:
            errors.append("No wordlist configured (set WORDLIST_PASSWORDS path)")
            console.print(
                Text(
                    "  [✗] No password wordlist found — install rockyou or set wordlist",
                    style=C_ERR,
                )
            )
            base["status"] = "identified" if candidates else "error"
            base["stats"] = {"duration_s": round(time.perf_counter() - t0, 2)}
            return base

        primary = candidates[0] if candidates else None
        primary_alg = primary["algorithm"] if primary else "unknown"
        primary_lib = primary.get("hashlib") if primary else None
        hashcat_mode = primary.get("hashcat_mode") if primary else None

        local_res: dict[str, Any] | None = None
        if crack_mode in (1, 2) and not candidates:
            console.print(
                Text(
                    "  [i] No algorithm match — skipping crack attempts.",
                    style=C_WARN,
                )
            )
            base["status"] = "error"
            base["findings"] = []
            base["stats"] = {"duration_s": round(time.perf_counter() - t0, 2)}
            _print_summary(hv, candidates, base)
            return base

        if crack_mode in (1, 2) and candidates:
            # Skip local bcrypt / crypt() formats hashlib cannot verify cheaply
            skip_local = primary_alg in (
                "bcrypt",
                "WordPress",
                "SHA512crypt",
                "SHA256crypt",
                "MD5crypt",
            )
            if skip_local:
                console.print(
                    Text(
                        f"  [i] Skipping fast local crack for {primary_alg} — use hashcat.",
                        style=C_DIM,
                    )
                )
            else:
                local_res = crack_local(
                    hv,
                    primary_alg,
                    primary_lib,
                    str(wl),
                    timeout,
                    candidates,
                )
                errors.extend(local_res.get("errors") or [])
                base["crack_result"] = {
                    "cracked": local_res["cracked"],
                    "plaintext": local_res.get("plaintext"),
                    "method": "local_wordlist" if local_res["cracked"] else None,
                    "attempts": local_res.get("attempts", 0),
                    "duration_s": local_res.get("duration_s", 0.0),
                    "speed": local_res.get("speed"),
                }
                if local_res["cracked"]:
                    base["status"] = "cracked"
                    base["findings"] = [{"type": "cracked_password", "value": "***"}]
                    base["stats"] = {
                        "duration_s": round(time.perf_counter() - t0, 2),
                    }
                    _print_summary(hv, candidates, base)
                    return base

        if crack_mode == 2 and candidates and primary is not None:
            if not base["hashcat_available"]:
                console.print(
                    Text("  [i] hashcat not installed — skipping GPU phase.", style=C_WARN)
                )
                errors.append("hashcat not available")
            elif hashcat_mode is not None:
                console.print(
                    Text(
                        f"\n [HASHCAT] mode {hashcat_mode} · wordlist attack",
                        style=f"bold {C_WARN}",
                    )
                )
                hc_res = crack_hashcat(hv, int(hashcat_mode), str(wl), use_rules=False)
                errors.extend(hc_res.get("errors") or [])
                if hc_res["cracked"] and hc_res.get("plaintext"):
                    base["crack_result"] = {
                        "cracked": True,
                        "plaintext": hc_res["plaintext"],
                        "method": "hashcat",
                        "attempts": base["crack_result"].get("attempts", 0),
                        "duration_s": round(time.perf_counter() - t0, 3),
                        "speed": None,
                    }
                    base["status"] = "cracked"
                    console.print(
                        Text(" [✓] CRACKED via hashcat", style=f"bold {C_PRI}")
                    )
                    console.print(
                        Text(
                            f"     Plaintext : {hc_res['plaintext']}",
                            style=C_DIM,
                        )
                    )
                    base["findings"] = [{"type": "cracked_password", "value": "***"}]
                    base["stats"] = {
                        "duration_s": round(time.perf_counter() - t0, 2),
                    }
                    _print_summary(hv, candidates, base)
                    return base
                else:
                    if Path("/usr/share/hashcat/rules/best64.rule").is_file() or Path(
                        "/opt/hashcat/rules/best64.rule"
                    ).is_file():
                        console.print(
                            Text(" [HASHCAT] Retrying with best64 rules...", style=C_DIM)
                        )
                        hc2 = crack_hashcat(
                            hv, int(hashcat_mode), str(wl), use_rules=True
                        )
                        errors.extend(hc2.get("errors") or [])
                        if hc2["cracked"] and hc2.get("plaintext"):
                            base["crack_result"] = {
                                "cracked": True,
                                "plaintext": hc2["plaintext"],
                                "method": "hashcat_rules",
                                "attempts": base["crack_result"].get("attempts", 0),
                                "duration_s": round(time.perf_counter() - t0, 3),
                                "speed": None,
                            }
                            base["status"] = "cracked"
                            console.print(
                                Text(
                                    " [✓] CRACKED via hashcat (rules)",
                                    style=f"bold {C_PRI}",
                                )
                            )
                            console.print(
                                Text(
                                    f"     Plaintext : {hc2['plaintext']}",
                                    style=C_DIM,
                                )
                            )
                            base["findings"] = [
                                {"type": "cracked_password", "value": "***"}
                            ]
                            base["stats"] = {
                                "duration_s": round(time.perf_counter() - t0, 2),
                            }
                            _print_summary(hv, candidates, base)
                            return base

        if candidates:
            if crack_mode == 1 and local_res is None and primary_alg in (
                "bcrypt",
                "WordPress",
                "SHA512crypt",
                "SHA256crypt",
                "MD5crypt",
            ):
                base["status"] = "identified"
            elif local_res and not local_res.get("cracked"):
                base["status"] = "not_found"
            elif crack_mode == 2:
                base["status"] = "not_found"
            else:
                base["status"] = "identified"
        else:
            base["status"] = "error"

        base["findings"] = base["candidates"]
        base["stats"] = {"duration_s": round(time.perf_counter() - t0, 2)}
        _print_summary(hv, candidates, base)
        return base

    except Exception as e:  # noqa: BLE001
        errors.append(str(e))
        console.print(Text(f"  [✗] {e}", style=C_ERR))
        base["status"] = "error"
        return base


def _print_summary(
    hv: str,
    candidates: list[dict[str, Any]],
    base: dict[str, Any],
) -> None:
    """Final one-screen summary."""
    cr = base.get("crack_result") or {}
    top = candidates[0]["algorithm"] if candidates else "—"
    risk = candidates[0].get("risk", "—") if candidates else "—"
    st = base.get("status", "—")
    console.print()
    console.print(Text(" [✓] Hash module complete", style=f"bold {C_PRI}"))
    console.print(Text(f"     Hash      : {hv[:64]}{'…' if len(hv) > 64 else ''}", style=C_DIM))
    console.print(
        Text(f"     Algorithm : {top} ({risk})", style=C_MUTED)
    )
    console.print(Text(f"     Status    : {st.upper()}", style=C_MUTED))
    if cr.get("cracked") and cr.get("plaintext"):
        console.print(
            Text(f"     Plaintext : {cr['plaintext']}", style=C_DIM)
        )
        console.print(
            Text(f"     Method    : {cr.get('method')}", style=C_MUTED)
        )
    console.print(
        Text(
            f"     Duration  : {base.get('stats', {}).get('duration_s', 0)}s",
            style=C_MUTED,
        )
    )
