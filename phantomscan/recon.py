"""Safe reconnaissance modules."""

from __future__ import annotations

import asyncio
from http.cookies import CookieError, SimpleCookie
from email.utils import parsedate_to_datetime
import json
import logging
import socket
from http.client import HTTPConnection, HTTPSConnection
from typing import Any
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .email_security import root_domain
from .models import Finding, Observation
from .scope import Target


async def resolve_target(target: Target, logger: logging.Logger | None = None) -> list[Observation]:
    """Resolve a domain target using the system resolver."""
    if target.target_type not in {"domain", "ip"}:
        return [Observation("target_type", target.target_type, "scope")]
    if target.target_type == "ip":
        return [Observation("ip", target.host, "input")]

    def lookup() -> list[str]:
        rows = socket.getaddrinfo(target.host, None, proto=socket.IPPROTO_TCP)
        return sorted({row[4][0] for row in rows})

    try:
        ips = await asyncio.to_thread(lookup)
    except socket.gaierror as exc:
        if logger:
            logger.exception("DNS resolution failed for %s: %s", target.host, exc)
        return [Observation("dns_error", str(exc), "resolver")]
    if logger:
        logger.info("Resolved %s to %s", target.host, ips)
    return [Observation("resolved_ips", ips, "resolver")]


async def collect_dns_records(target: Target, logger: logging.Logger | None = None) -> list[Observation]:
    """Collect basic DNS records using the standard resolver."""
    if target.target_type == "ip":
        try:
            host = await asyncio.to_thread(socket.gethostbyaddr, target.host)
            return [Observation("dns_records", {"PTR": [host[0]]}, "resolver")]
        except (socket.herror, socket.gaierror):
            return [Observation("dns_records", {"PTR": []}, "resolver")]
    if target.target_type != "domain":
        return [Observation("dns_records", {}, "resolver")]

    def lookup() -> dict[str, list[str]]:
        records: dict[str, list[str]] = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []}
        try:
            rows = socket.getaddrinfo(target.host, None, socket.AF_INET, socket.SOCK_STREAM)
            records["A"] = sorted({row[4][0] for row in rows})
        except socket.gaierror:
            if logger:
                logger.debug("No A records resolved for %s", target.host)
        try:
            rows = socket.getaddrinfo(target.host, None, socket.AF_INET6, socket.SOCK_STREAM)
            records["AAAA"] = sorted({row[4][0] for row in rows})
        except socket.gaierror:
            if logger:
                logger.debug("No AAAA records resolved for %s", target.host)
        return records

    return [Observation("dns_records", await asyncio.to_thread(lookup), "resolver")]


async def enumerate_subdomains(target: Target, logger: logging.Logger | None = None) -> list[Observation]:
    """Perform safe DNS-only subdomain enumeration for common names."""
    if target.target_type != "domain":
        return [Observation("subdomains", [], "subdomain-enum")]
    labels = [
        "www", "mail", "api", "app", "admin", "portal", "dev", "staging",
        "test", "blog", "shop", "cdn", "static", "assets", "login", "vpn",
        "support", "docs", "status", "m",
    ]

    async def resolve_name(label: str) -> dict[str, Any] | None:
        name = f"{label}.{target.host}"
        try:
            rows = await asyncio.to_thread(socket.getaddrinfo, name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            return None
        ips = sorted({row[4][0] for row in rows})
        return {
            "subdomain": name,
            "ips": ips,
            "source": "dns-common",
            "status": "resolved",
            "interesting": label in {"admin", "portal", "dev", "staging", "login", "vpn"},
        }

    results = await asyncio.gather(*(resolve_name(label) for label in labels))
    found = sorted((item for item in results if item), key=lambda item: (not item["interesting"], item["subdomain"]))
    if logger:
        logger.info("Subdomain enumeration found %s resolving names", len(found))
    return [Observation("subdomains", found, "subdomain-enum")]


async def lookup_whois(target: Target, timeout: float = 15.0, logger: logging.Logger | None = None) -> list[Observation]:
    """Fetch lightweight RDAP/WHOIS-style ownership information when available."""
    if target.target_type == "cidr":
        return [Observation("whois_info", {"status": "skipped", "reason": "CIDR summary not queried"}, "rdap")]
    endpoint = "ip" if target.target_type == "ip" else "domain"
    lookup_name = whois_lookup_name(target)
    url = f"https://rdap.org/{endpoint}/{lookup_name}"

    def fetch() -> dict[str, Any]:
        request = Request(url, headers={"User-Agent": "PhantomScan/2.0 authorized-security-assessment"})
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read(200_000).decode("utf-8", errors="replace"))
        nameservers = [item.get("ldhName") for item in payload.get("nameservers", []) if item.get("ldhName")]
        events = {item.get("eventAction", "event"): item.get("eventDate") for item in payload.get("events", [])}
        entities = [item.get("handle") or item.get("fn") for item in payload.get("entities", [])]
        return {
            "status": "ok",
            "handle": payload.get("handle"),
            "name": payload.get("name") or payload.get("ldhName") or lookup_name,
            "queried": lookup_name,
            "original_target": target.host,
            "registrar": _registrar_name(payload),
            "events": events,
            "nameservers": nameservers,
            "entities": [item for item in entities if item],
            "source": url,
        }

    try:
        info = await asyncio.to_thread(fetch)
    except HTTPError as exc:
        if logger:
            logger.warning("WHOIS/RDAP lookup returned HTTP %s for %s via %s", exc.code, lookup_name, url)
            logger.debug("WHOIS/RDAP HTTP error details: %r", exc)
        info = {
            "status": "unavailable",
            "reason": f"RDAP HTTP {exc.code}: {exc.reason}",
            "queried": lookup_name,
            "original_target": target.host,
            "source": url,
        }
    except (OSError, TimeoutError, ValueError, json.JSONDecodeError, URLError) as exc:
        if logger:
            logger.warning("WHOIS/RDAP lookup unavailable for %s: %s", lookup_name, exc)
            logger.debug("WHOIS/RDAP lookup details: %r", exc)
        info = {
            "status": "unavailable",
            "reason": str(exc),
            "queried": lookup_name,
            "original_target": target.host,
            "source": url,
        }
    return [Observation("whois_info", info, "rdap")]


def _registrar_name(payload: dict[str, Any]) -> str:
    for entity in payload.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for row in vcard[1]:
                    if row and row[0] == "fn":
                        return str(row[3])
            return str(entity.get("handle", ""))
    return ""


def whois_lookup_name(target: Target) -> str:
    """Return the RDAP lookup name for a target."""
    return target.host if target.target_type == "ip" else root_domain(target.host)


async def fetch_headers(target: Target, timeout: float, logger: logging.Logger | None = None) -> tuple[list[Observation], list[Finding]]:
    """Fetch HTTP response headers with a safe GET request."""
    if target.target_type == "cidr":
        return [Observation("http_skipped", "CIDR target", "http")], []

    url = target.base_url
    parsed = urlparse(url)
    conn_cls = HTTPSConnection if parsed.scheme == "https" else HTTPConnection

    def request() -> tuple[int, dict[str, str], str, float]:
        started = datetime.now(timezone.utc)
        conn = conn_cls(parsed.hostname or target.host, timeout=timeout)
        path = parsed.path or "/"
        conn.request("GET", path, headers={"User-Agent": "PhantomScan/2.0 authorized-security-assessment"})
        response = conn.getresponse()
        body = response.read(200_000).decode("utf-8", errors="replace")
        headers = {k.lower(): v for k, v in response.getheaders()}
        conn.close()
        elapsed = (datetime.now(timezone.utc) - started).total_seconds() * 1000
        return response.status, headers, body, elapsed

    try:
        status, headers, body, elapsed_ms = await asyncio.to_thread(request)
    except OSError as exc:
        if logger:
            logger.warning("HTTP request failed for %s: %s", url, exc)
            logger.debug("HTTP request failure details: %r", exc)
        return [Observation("http_error", str(exc), "http")], [
            Finding(
                id="HTTP-REQUEST-FAILED",
                title="HTTP service could not be verified",
                severity="info",
                confidence="high",
                category="web",
                target=url,
                evidence=f"GET {url} failed: {exc}",
                recommendation="Confirm the service is reachable from the assessment network and rerun the scan.",
            )
        ]
    if logger:
        logger.info("HTTP GET %s returned %s in %sms with %s headers", url, status, int(elapsed_ms), len(headers))

    observations = [
        Observation("http_status", status, "http"),
        Observation("headers", headers, "http"),
        Observation("body_sample", body[:2000], "http"),
        Observation("http_response_time_ms", int(elapsed_ms), "http"),
    ]
    findings = analyze_security_headers(url, headers)
    findings.extend(analyze_cookies(url, headers.get("set-cookie", "")))
    return observations, findings


def analyze_security_headers(url: str, headers: dict[str, str]) -> list[Finding]:
    """Create a grouped security header finding."""
    missing: list[str] = []
    expected = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }
    for header, label in expected.items():
        if header not in headers:
            missing.append(label)
    if not missing:
        return []
    severity = "medium" if {"HSTS", "CSP"} & set(missing) else "low"
    return [
        Finding(
            id="SECURITY-HEADERS-GROUPED",
            title="Security Headers Policy Incomplete",
            severity=severity,  # type: ignore[arg-type]
            confidence="high",
            category="web",
            target=url,
            evidence=f"Missing headers: {', '.join(missing)}",
            recommendation="Add the missing defensive headers after testing application compatibility.",
        )
    ]


def analyze_cookies(url: str, set_cookie: str) -> list[Finding]:
    """Analyze cookie flags without over-reporting analytics cookies."""
    if not set_cookie:
        return []
    findings: list[Finding] = []
    cookies = SimpleCookie()
    try:
        cookies.load(set_cookie)
    except CookieError:
        return []
    for name, morsel in cookies.items():
        lower = str(morsel.OutputString()).lower()
        raw_cookie = morsel.OutputString()
        if _is_expired_cookie(raw_cookie):
            continue
        is_tracking = name.startswith(("_ga", "_gid", "_fbp", "_hjid", "__utma", "__utmb")) or name in {"NID", "IDE"}
        severity = "info" if is_tracking else "low"
        if is_tracking and "secure" in lower and "httponly" in lower:
            continue
        if "httponly" not in lower:
            findings.append(
                Finding(
                    id="COOKIE-MISSING-HTTPONLY",
                    title="Cookie missing HttpOnly flag",
                    severity=severity,  # type: ignore[arg-type]
                    confidence="medium",
                    category="web",
                    target=url,
                    evidence=f"Cookie {name} does not include HttpOnly.",
                    recommendation="Set HttpOnly on session cookies that do not need JavaScript access.",
                )
            )
        if "secure" not in lower and not name.startswith("__Secure-"):
            findings.append(
                Finding(
                    id="COOKIE-MISSING-SECURE",
                    title="Cookie missing Secure flag",
                    severity=severity,  # type: ignore[arg-type]
                    confidence="medium",
                    category="web",
                    target=url,
                    evidence=f"Cookie {name} does not include Secure.",
                    recommendation="Set Secure on cookies transmitted over HTTPS.",
                )
            )
    return findings


def detect_technologies(observations: list[Observation]) -> list[Observation]:
    """Infer technologies from headers and HTML sample."""
    headers: dict[str, Any] = {}
    body = ""
    for obs in observations:
        if obs.name == "headers" and isinstance(obs.value, dict):
            headers = obs.value
        if obs.name == "body_sample" and isinstance(obs.value, str):
            body = obs.value.lower()
    tech: list[dict[str, Any]] = []
    server = str(headers.get("server", ""))
    powered = str(headers.get("x-powered-by", ""))
    if server:
        name = "Google Web Server" if server.lower() == "gws" else server.split("/")[0]
        tech.append({"name": name, "source": "server-header", "confidence": 85})
    if powered:
        tech.append({"name": powered.split("/")[0], "source": "x-powered-by", "confidence": 80})
    via = str(headers.get("via", ""))
    if via:
        tech.append({"name": "Proxy/CDN layer", "source": "via-header", "confidence": 65})
    alt_svc = str(headers.get("alt-svc", ""))
    if "h3" in alt_svc.lower():
        tech.append({"name": "HTTP/3 QUIC", "source": "alt-svc", "confidence": 90})
    cookies = str(headers.get("set-cookie", ""))
    if "nid=" in cookies.lower():
        tech.append({"name": "Google cookie stack", "source": "cookie-name", "confidence": 70})
    signatures = {"wp-content": "WordPress", "react": "React", "next": "Next.js", "jquery": "jQuery"}
    for marker, name in signatures.items():
        if marker in body:
            tech.append({"name": name, "source": "html", "confidence": 65})
    return [Observation("technologies", tech, "fingerprint")]


def _is_expired_cookie(raw_cookie: str) -> bool:
    lower = raw_cookie.lower()
    if "expires=" not in lower:
        return False
    try:
        expires = raw_cookie[lower.index("expires=") + 8 :].split(";", 1)[0]
        parsed = parsedate_to_datetime(expires)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed < datetime.now(timezone.utc)
    except (IndexError, TypeError, ValueError):
        return False
