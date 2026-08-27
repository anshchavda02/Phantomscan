"""Target parsing, scope enforcement, and domain utilities."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse


import tldextract


def root_domain(host: str) -> str:
    """eTLD+1 extraction using tldextract."""
    host = host.lower().strip(".")
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


# ── Target dataclass ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Target:
    """A normalized target and its allowed scope."""

    raw: str
    host: str
    target_type: str   # "domain" | "ip" | "cidr"
    scheme: str        # "http" | "https" | ""
    port: int | None = None

    @property
    def netloc(self) -> str:
        """Return host:port if non-standard port is specified, else host."""
        if self.port and not (self.scheme == "http" and self.port == 80) and not (self.scheme == "https" and self.port == 443):
            return f"{self.host}:{self.port}"
        return self.host

    @property
    def base_url(self) -> str:
        """Return a URL suitable for HTTP checks."""
        scheme = self.scheme or "https"
        if self.port and not (scheme == "http" and self.port == 80) and not (scheme == "https" and self.port == 443):
            return f"{scheme}://{self.host}:{self.port}"
        return f"{scheme}://{self.host}"

    @property
    def root_domain(self) -> str:
        """Return the eTLD+1 for this target's host."""
        return root_domain(self.host)

    @property
    def is_local(self) -> bool:
        """Return True if target is a local, loopback, or private address."""
        if self.host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
            return True
        if self.host.endswith(".local") or self.host.endswith(".internal"):
            return True
        try:
            ip = ipaddress.ip_address(self.host)
            return ip.is_loopback or ip.is_private
        except ValueError:
            return False


# ── Parsing ───────────────────────────────────────────────────────────────────


def parse_target(value: str) -> Target:
    """Parse *value* as URL, domain, IPv4, IPv6, or CIDR.

    Preserves ports in the target representation while separating the hostname.
    """
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("target must not be empty")

    parsed = urlparse(cleaned if "://" in cleaned else f"//{cleaned}")
    host = parsed.hostname or cleaned
    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else ""
    port = parsed.port

    # If host contains a port after stripping scheme (e.g. "localhost:3000")
    if not port and ":" in host and not host.startswith("["):
        parts = host.rsplit(":", 1)
        if parts[1].isdigit():
            host = parts[0]
            port = int(parts[1])

    # Normalise — strip trailing dot, lowercase
    host = host.lower().rstrip(".")

    try:
        ipaddress.ip_network(host, strict=False)
        target_type = "cidr" if "/" in host else "ip"
    except ValueError:
        target_type = "domain"

    return Target(raw=cleaned, host=host, target_type=target_type, scheme=scheme, port=port)


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
