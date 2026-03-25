"""Parse and classify operator target strings (domain, IP, CIDR)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Module compatibility: which logical module keys apply per target type
_DOMAIN_MODULES = frozenset(
    {"dns", "subs", "whois", "ports", "dirs", "harvest", "methods", "js", "hash"}
)
_IP_MODULES = frozenset(
    {"dns", "whois", "ports", "dirs", "harvest", "methods", "js", "hash", "sniff"}
)
_CIDR_MODULES = frozenset({"arp", "ports", "sniff"})


class TargetType(Enum):
    """Classification of a parsed target."""

    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"


@dataclass
class Target:
    """Normalized target with type and helper predicates."""

    raw: str
    type: TargetType
    value: str

    def is_domain(self) -> bool:
        """Return True if target is a hostname/domain."""
        return self.type is TargetType.DOMAIN

    def is_ip(self) -> bool:
        """Return True if target is a single IP address."""
        return self.type is TargetType.IP

    def is_cidr(self) -> bool:
        """Return True if target is a CIDR range."""
        return self.type is TargetType.CIDR

    def supports(self, module: str) -> bool:
        """
        Return True if the module makes sense for this target type.

        Compatibility:
          DOMAIN → dns, subs, whois, ports, dirs, harvest, methods, js, hash
          IP     → dns, whois, ports, dirs, harvest, methods, js, hash, sniff
          CIDR   → arp, ports, sniff
        """
        key = module.lower().strip()
        match self.type:
            case TargetType.DOMAIN:
                return key in _DOMAIN_MODULES
            case TargetType.IP:
                return key in _IP_MODULES
            case TargetType.CIDR:
                return key in _CIDR_MODULES

    def __str__(self) -> str:
        """Human-readable label, e.g. \"exemplo.com [DOMAIN]\"."""
        label = self.type.name
        return f"{self.value} [{label}]"


def _looks_like_ipv4_candidate(s: str) -> bool:
    """Heuristic: string might be intended as IPv4 (for error messages)."""
    if "/" in s:
        s = s.split("/", 1)[0]
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() for p in parts)


def parse_target(raw: str) -> Target:
    """
    Parse and classify the target string.

    Detection order: CIDR → IP → DOMAIN.

    Raises:
        ValueError: If input is empty or not a valid domain, IP, or CIDR.
    """
    if raw is None:
        raise ValueError("Input cannot be empty")

    stripped = raw.strip()
    if not stripped:
        raise ValueError("Input cannot be empty")

    # CIDR (must contain / for network form we accept here)
    if "/" in stripped:
        try:
            net = ipaddress.ip_network(stripped, strict=False)
            return Target(raw=raw, type=TargetType.CIDR, value=str(net))
        except ValueError:
            if _looks_like_ipv4_candidate(stripped):
                host_part = stripped.split("/", 1)[0]
                try:
                    ipaddress.ip_address(host_part)
                except ValueError:
                    pass
                else:
                    raise ValueError(
                        f"'{stripped}' is not a valid IP address"
                    ) from None
            raise ValueError(
                f"'{stripped}' is not a valid domain, IP or CIDR range"
            ) from None

    # Single IP
    try:
        addr = ipaddress.ip_address(stripped)
        return Target(raw=raw, type=TargetType.IP, value=str(addr))
    except ValueError:
        if _looks_like_ipv4_candidate(stripped):
            raise ValueError(f"'{stripped}' is not a valid IP address") from None

    # Domain
    candidate = stripped.lower()
    if _DOMAIN_RE.match(candidate):
        return Target(raw=raw, type=TargetType.DOMAIN, value=candidate)

    raise ValueError(
        f"'{stripped}' is not a valid domain, IP or CIDR range"
    ) from None
