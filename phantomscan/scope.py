"""Target parsing, scope enforcement, and domain utilities."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse


# ── Domain utilities ──────────────────────────────────────────────────────────

_COMMON_SECOND_LEVELS = {"co", "com", "net", "org", "ac", "gov", "edu", "mil"}


def root_domain(host: str) -> str:
    """Best-effort eTLD+1 extraction without external dependencies.

    Examples::

        root_domain("api.example.com")   # "example.com"
        root_domain("foo.co.uk")         # "foo.co.uk"
        root_domain("192.168.1.1")       # "192.168.1.1"
    """
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # Handle two-part TLDs like .co.uk, .com.au
    if len(parts[-1]) == 2 and parts[-2] in _COMMON_SECOND_LEVELS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ── Target dataclass ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Target:
    """A normalized target and its allowed scope."""

    raw: str
    host: str
    target_type: str   # "domain" | "ip" | "cidr"
    scheme: str        # "http" | "https" | ""

    @property
    def base_url(self) -> str:
        """Return a URL suitable for HTTP checks."""
        if self.scheme:
            return f"{self.scheme}://{self.host}"
        return f"https://{self.host}"

    @property
    def root_domain(self) -> str:
        """Return the eTLD+1 for this target's host."""
        return root_domain(self.host)


# ── Parsing ───────────────────────────────────────────────────────────────────


def parse_target(value: str) -> Target:
    """Parse *value* as URL, domain, IPv4, IPv6, or CIDR.

    Strips ports from the host component and lower-cases the result.
    """
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("target must not be empty")

    parsed = urlparse(cleaned if "://" in cleaned else f"//{cleaned}")
    host = parsed.hostname or cleaned
    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else ""

    # Normalise — strip trailing dot, lowercase
    host = host.lower().rstrip(".")

    try:
        ipaddress.ip_network(host, strict=False)
        target_type = "cidr" if "/" in host else "ip"
    except ValueError:
        target_type = "domain"

    return Target(raw=cleaned, host=host, target_type=target_type, scheme=scheme)


# ── Scope enforcement ─────────────────────────────────────────────────────────


def is_in_scope(target: Target, candidate: str) -> bool:
    """Return ``True`` when *candidate* is within the target scope."""
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    host = (parsed.hostname or candidate).lower().rstrip(".")
    if target.target_type == "cidr":
        try:
            network = ipaddress.ip_network(target.host, strict=False)
            return ipaddress.ip_address(host) in network
        except ValueError:
            return False
    if target.target_type == "ip":
        return host == target.host
    return host == target.host or host.endswith(f".{target.host}")
