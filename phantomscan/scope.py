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


# ── NormalizedTarget / Target dataclass ─────────────────────────────────────────


@dataclass(frozen=True)
class NormalizedTarget:
    """A normalized target and its allowed scope."""

    original: str = ""
    scheme: str = "http"
    host: str = ""
    port: int = 80
    web_root: str = ""
    is_local: bool = False
    root_domain: str = ""
    target_type: str = "domain"
    raw: str = ""
    has_explicit_scheme: bool = False

    def __post_init__(self) -> None:
        if not self.original and self.raw:
            object.__setattr__(self, "original", self.raw)
        elif not self.raw and self.original:
            object.__setattr__(self, "raw", self.original)

        if not self.web_root and self.host:
            scheme = self.scheme or ("http" if self.is_local else "https")
            if self.port and not (scheme == "http" and self.port == 80) and not (scheme == "https" and self.port == 443):
                object.__setattr__(self, "web_root", f"{scheme}://{self.host}:{self.port}")
            else:
                object.__setattr__(self, "web_root", f"{scheme}://{self.host}")

        if not self.root_domain and self.host:
            object.__setattr__(self, "root_domain", self.host if self.is_local else root_domain(self.host))

    @property
    def base_url(self) -> str:
        """Return the web root URL suitable for HTTP checks."""
        return self.web_root

    @property
    def netloc(self) -> str:
        """Return host:port if non-standard port is specified, else host."""
        if self.port and not (self.scheme == "http" and self.port == 80) and not (self.scheme == "https" and self.port == 443):
            return f"{self.host}:{self.port}"
        return self.host


Target = NormalizedTarget


# ── Parsing & Normalization ───────────────────────────────────────────────────


def normalize_target(raw_target: str) -> NormalizedTarget:
    """Normalize raw target input string into a structured NormalizedTarget."""
    raw = raw_target.strip()
    if not raw:
        raise ValueError("target must not be empty")

    has_explicit_scheme = raw.startswith(("http://", "https://"))
    # Add scheme if missing
    if not has_explicit_scheme:
        host_part = raw.split("/")[0].split("?")[0]
        host_only = host_part.split(":")[0]
        is_local_hint = (
            host_only in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
            or host_only.startswith(
                (
                    "192.168.", "10.", "172.16.", "172.17.",
                    "172.18.", "172.19.", "172.20.", "172.21.",
                    "172.22.", "172.23.", "172.24.", "172.25.",
                    "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.",
                )
            )
            or host_only.endswith((".local", ".internal"))
        )
        if not is_local_hint:
            try:
                ip = ipaddress.ip_address(host_only)
                is_local_hint = ip.is_loopback or ip.is_private
            except ValueError:
                pass

        scheme = "http" if is_local_hint else "https"
        raw_with_scheme = f"{scheme}://{raw}"
    else:
        raw_with_scheme = raw

    parsed = urlparse(raw_with_scheme)
    host = parsed.hostname or raw
    port = parsed.port
    scheme = parsed.scheme or "http"

    # If host contains a port after stripping scheme
    if not port and ":" in host and not host.startswith("["):
        parts = host.rsplit(":", 1)
        if parts[1].isdigit():
            host = parts[0]
            port = int(parts[1])

    host = host.lower().rstrip(".")

    # Web root MUST include non-standard port
    if port and port not in (80, 443):
        web_root = f"{scheme}://{host}:{port}"
    else:
        web_root = f"{scheme}://{host}"

    is_local = (
        host in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
        or host.startswith(
            (
                "192.168.", "10.", "172.16.", "172.17.",
                "172.18.", "172.19.", "172.20.", "172.21.",
                "172.22.", "172.23.", "172.24.", "172.25.",
                "172.26.", "172.27.", "172.28.", "172.29.",
                "172.30.", "172.31.",
            )
        )
        or host.endswith((".local", ".internal"))
    )
    if not is_local:
        try:
            ip = ipaddress.ip_address(host)
            is_local = ip.is_loopback or ip.is_private
        except ValueError:
            pass

    try:
        ipaddress.ip_network(host, strict=False)
        target_type = "cidr" if "/" in host else "ip"
    except ValueError:
        target_type = "domain"

    return NormalizedTarget(
        original=raw_target,
        scheme=scheme,
        host=host,
        port=port or (443 if scheme == "https" else 80),
        web_root=web_root,
        is_local=is_local,
        root_domain=host if is_local else root_domain(host),
        target_type=target_type,
        has_explicit_scheme=has_explicit_scheme,
    )


def parse_target(value: str) -> Target:
    """Parse *value* as URL, domain, IPv4, IPv6, or CIDR."""
    return normalize_target(value)


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
