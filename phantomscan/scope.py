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

    is_cidr = False
    try:
        raw_clean = raw.split("://")[-1].split("?")[0].rstrip("/")
        if "/" in raw_clean:
            cidr_net = ipaddress.ip_network(raw_clean, strict=False)
            is_cidr = True
            host = str(cidr_net)
            target_type = "cidr"
    except ValueError:
        pass

    if not is_cidr:
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


# ── Scope enforcement & ScopePolicy ───────────────────────────────────────────

PRIVATE_IP_RANGES = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / Cloud metadata
    ipaddress.ip_network("::1/128"),        # IPv6 loopback
    ipaddress.ip_network("fd00::/8"),       # IPv6 ULA
)

CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "instance-data",
    "100.100.100.200",  # Alibaba Cloud metadata
}


class ScopePolicy:
    """Centralized security scope policy enforcer (SEC-S01, SEC-S02, SEC-S03)."""

    def __init__(
        self,
        target: NormalizedTarget | None = None,
        allowed_hosts: set[str] | list[str] | None = None,
        allowed_cidrs: list[str] | None = None,
        allow_local: bool = False,
        allow_cloud_metadata: bool = False,
        max_redirects: int = 10,
    ) -> None:
        self.target = target
        self.allow_local = allow_local or (target.is_local if target else False)
        self.allow_cloud_metadata = allow_cloud_metadata
        self.max_redirects = max_redirects

        self.allowed_hosts: set[str] = set()
        if allowed_hosts:
            self.allowed_hosts = {h.lower().strip() for h in allowed_hosts if h}
        elif target and target.host and target.target_type != "cidr":
            self.allowed_hosts = {target.host.lower().strip()}

        self.allowed_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        raw_cidrs = allowed_cidrs or ([] if not target or target.target_type != "cidr" else [target.host])
        for cidr_str in raw_cidrs:
            try:
                self.allowed_cidrs.append(ipaddress.ip_network(cidr_str, strict=False))
            except ValueError:
                pass

    def is_private_ip(self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Return True if ip_obj falls in private, loopback, link-local, or cloud metadata ranges."""
        return any(ip_obj in net for net in PRIVATE_IP_RANGES)

    def validate_target(self, candidate: str) -> tuple[bool, str]:
        """Validate candidate URL or hostname against scope and SSRF policy.

        Returns (is_allowed, reason_message).
        """
        if not candidate:
            return False, "Target candidate is empty"

        raw = candidate.strip()
        parsed = urlparse(raw if "://" in raw else f"//{raw}")
        hostname = (parsed.hostname or raw.split("/")[0].split(":")[0]).lower().rstrip(".")

        if not hostname:
            return False, "Unable to extract valid hostname"

        # 1. Cloud metadata checks (SEC-S02)
        if hostname in CLOUD_METADATA_HOSTS:
            if not self.allow_cloud_metadata:
                return False, f"Cloud metadata endpoint '{hostname}' prohibited"

        # 2. Check if candidate is an IP address
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if self.is_private_ip(ip_obj):
                if not self.allow_local:
                    return False, f"Private/loopback IP '{ip_obj}' is prohibited for non-local targets (SEC-S02)"

            # Check CIDR boundaries
            if self.allowed_cidrs:
                if any(ip_obj in net for net in self.allowed_cidrs):
                    return True, "IP within allowed CIDR scope"
                return False, f"IP '{ip_obj}' is outside declared CIDR scope"

            if self.allowed_hosts:
                ip_str = str(ip_obj)
                if ip_str in self.allowed_hosts:
                    return True, "IP allowed"
                if self.allow_local and ip_obj.is_loopback and any(h in self.allowed_hosts for h in ("localhost", "127.0.0.1", "::1")):
                    return True, "Loopback IP allowed for local target"
                return False, f"IP '{ip_obj}' is not in declared allowed hosts"

            return True, "IP allowed"
        except ValueError:
            pass  # Hostname, not IP

        # 3. Localhost hostname checks
        if hostname in ("localhost", "localhost.localdomain") or hostname.endswith((".local", ".internal")):
            if not self.allow_local:
                return False, f"Internal hostname '{hostname}' is prohibited for non-local targets (SEC-S02)"
            if any(h in self.allowed_hosts for h in ("localhost", "127.0.0.1", "::1")):
                return True, "Localhost allowed"

        # 4. Hostname scope enforcement (SEC-S01)
        if not self.allowed_hosts and not self.allowed_cidrs:
            return True, "No strict scope restrictions declared"

        for allowed_host in self.allowed_hosts:
            if hostname == allowed_host or hostname.endswith(f".{allowed_host}"):
                return True, "Hostname within allowed scope"

        return False, f"Host '{hostname}' is outside declared scan scope"

    def is_url_in_scope(self, url: str) -> bool:
        """Boolean helper for URL validation."""
        allowed, _ = self.validate_target(url)
        return allowed


def is_in_scope(target: Target, candidate: str) -> bool:
    """Return ``True`` when *candidate* is within the target scope."""
    policy = ScopePolicy(target=target)
    allowed, _ = policy.validate_target(candidate)
    return allowed


