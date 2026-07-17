"""Target parsing and scope enforcement."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class Target:
    """A normalized target and its allowed scope."""

    raw: str
    host: str
    target_type: str
    scheme: str

    @property
    def base_url(self) -> str:
        """Return a URL suitable for HTTP checks."""
        if self.scheme:
            return f"{self.scheme}://{self.host}"
        return f"https://{self.host}"


def parse_target(value: str) -> Target:
    """Parse a target as URL, domain, IP address, or CIDR."""
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("target must not be empty")

    parsed = urlparse(cleaned if "://" in cleaned else f"//{cleaned}")
    host = parsed.hostname or cleaned
    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else ""

    try:
        ipaddress.ip_network(host, strict=False)
        target_type = "cidr" if "/" in host else "ip"
    except ValueError:
        target_type = "domain"

    return Target(raw=cleaned, host=host.lower().rstrip("."), target_type=target_type, scheme=scheme)


def is_in_scope(target: Target, candidate: str) -> bool:
    """Return true when candidate is within the target scope."""
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

