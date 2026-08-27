"""Safe reconnaissance modules.

Provides:
  - DNS resolution and record collection (via dnspython async resolver)
  - WHOIS/RDAP lookups
  - Subdomain enumeration (crt.sh CT logs + DNS brute-force + common names)
  - HTTP header fetching with robust aiohttp client
  - Deep web analysis (sensitive paths, CORS, disclosures, cookie flags)
  - Technology fingerprinting
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import dns.asyncresolver
import dns.exception
import dns.resolver

from .http_client import HTTPResult, RobustHTTPClient, ScanError, http_client
from .models import Finding, Observation
from .scope import Target, root_domain

logger = logging.getLogger(__name__)

# ── DNS helpers ───────────────────────────────────────────────────────────────

_PUBLIC_DNS = ["8.8.8.8", "1.1.1.1"]


def _make_resolver() -> dns.asyncresolver.Resolver:
    """Return an async resolver using public nameservers."""
    r = dns.asyncresolver.Resolver()
    r.nameservers = _PUBLIC_DNS
    return r


# ── Subdomain brute-force wordlist ─────────────────────────────────────────────

_BRUTE_WORDLIST = [
    "www", "mail", "api", "app", "admin", "portal", "dev", "staging",
    "test", "blog", "shop", "cdn", "static", "assets", "login", "vpn",
    "support", "docs", "status", "m", "mobile", "beta", "alpha", "v1",
    "v2", "old", "new", "demo", "preview", "uat", "qa", "prod", "web",
    "smtp", "pop", "imap", "ftp", "sftp", "ssh", "ns1", "ns2", "mx",
    "mx1", "mx2", "email", "webmail", "cpanel", "whm", "git", "gitlab",
    "github", "jenkins", "ci", "cd", "jira", "confluence", "bitbucket",
    "media", "images", "files", "downloads", "uploads", "dashboard",
    "manage", "panel", "internal", "intranet", "corp", "secure",
    "auth", "sso", "oauth", "id", "account", "accounts", "my", "search",
    "api2", "backend", "frontend", "services", "gateway", "proxy",
    "monitor", "metrics", "grafana", "kibana", "elastic", "redis",
    "db", "database", "mysql", "postgres", "mongo", "data", "backup",
    "remote", "rdp", "cloud", "s3", "storage", "assets2", "img",
]

_INTERESTING_KEYWORDS = frozenset({
    "admin", "login", "portal", "dev", "staging", "test", "api", "internal",
    "vpn", "remote", "dashboard", "manage", "panel", "jenkins", "gitlab",
    "jira", "backup", "db", "database", "redis", "elastic", "kibana",
    "grafana", "uat", "prod", "secure", "auth", "sso",
})

_SENSITIVE_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.php",
    "/wp-config.php",
    "/phpinfo.php",
    "/.htaccess",
    "/robots.txt",
    "/sitemap.xml",
    "/.DS_Store",
    "/backup.zip",
    "/admin/",
    "/phpmyadmin/",
    "/server-status",
    "/web.config",
    "/crossdomain.xml",
    "/elmah.axd",
    "/trace.axd",
    "/.well-known/security.txt",
]

# Paths whose HTTP 200 is expected / not a risk finding (e.g., robots.txt is public)
_EXPECTED_PUBLIC = {"robots.txt", "sitemap.xml", ".well-known/security.txt", "crossdomain.xml"}


# ── DNS resolution ─────────────────────────────────────────────────────────────


async def resolve_target(
    target: Target,
    logger: logging.Logger | None = None,
) -> list[Observation]:
    """Resolve a domain target using the dnspython async resolver."""
    log = logger or logging.getLogger(__name__)
    if target.target_type not in {"domain", "ip"}:
        return [Observation("target_type", target.target_type, "scope")]
    if target.is_local or target.target_type == "ip":
        resolved_ip = "127.0.0.1" if target.host == "localhost" else target.host
        return [Observation("ip", resolved_ip, "input"), Observation("resolved_ips", [resolved_ip], "resolver")]

    resolver = _make_resolver()
    try:
        answers = await resolver.resolve(target.host, "A", lifetime=5.0)
        ips = sorted(str(r) for r in answers)
    except dns.resolver.NXDOMAIN:
        log.warning("DNS: NXDOMAIN for %s", target.host)
        return [Observation("dns_error", f"NXDOMAIN: {target.host}", "resolver")]
    except dns.exception.DNSException as exc:
        log.warning("DNS resolution failed for %s: %s", target.host, exc)
        return [Observation("dns_error", str(exc), "resolver")]
    except OSError as exc:
        log.warning("DNS OS error for %s: %s", target.host, exc)
        return [Observation("dns_error", str(exc), "resolver")]

    log.info("Resolved %s -> %s", target.host, ips)
    return [Observation("resolved_ips", ips, "resolver")]


async def collect_dns_records(
    target: Target,
    logger: logging.Logger | None = None,
) -> list[Observation]:
    """Collect A, AAAA, MX, NS, TXT, and CNAME records via dnspython."""
    log = logger or logging.getLogger(__name__)
    if target.is_local:
        ip = "127.0.0.1" if target.host == "localhost" else target.host
        return [Observation("dns_records", {"A": [ip], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}, "resolver")]
    if target.target_type == "ip":
        # PTR reverse lookup
        try:
            ptr = await asyncio.to_thread(socket.gethostbyaddr, target.host)
            return [Observation("dns_records", {"PTR": [ptr[0]]}, "resolver")]
        except (socket.herror, socket.gaierror):
            return [Observation("dns_records", {"PTR": []}, "resolver")]
    if target.target_type != "domain":
        return [Observation("dns_records", {}, "resolver")]

    resolver = _make_resolver()
    records: dict[str, list[str]] = {
        "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [],
    }

    async def _query(rtype: str) -> list[str]:
        try:
            answers = await resolver.resolve(target.host, rtype, lifetime=5.0)
            if rtype == "MX":
                return [f"{r.preference} {str(r.exchange).rstrip('.')}" for r in answers]
            if rtype == "TXT":
                out = []
                for rdata in answers:
                    joined = "".join(
                        s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                        for s in rdata.strings
                    )
                    out.append(joined)
                return out
            return [str(r).rstrip(".") for r in answers]
        except dns.exception.DNSException:
            return []

    results = await asyncio.gather(
        _query("A"), _query("AAAA"), _query("MX"),
        _query("NS"), _query("TXT"), _query("CNAME"),
        return_exceptions=True,
    )
    for rtype, result in zip(("A", "AAAA", "MX", "NS", "TXT", "CNAME"), results):
        if isinstance(result, list):
            records[rtype] = result

    log.info("DNS records for %s: %s", target.host, {k: len(v) for k, v in records.items()})
    return [Observation("dns_records", records, "resolver")]


# ── WHOIS / RDAP ──────────────────────────────────────────────────────────────


async def lookup_whois(
    target: Target,
    timeout: float = 15.0,
    logger: logging.Logger | None = None,
) -> list[Observation]:
    """Fetch lightweight RDAP/WHOIS-style ownership information."""
    log = logger or logging.getLogger(__name__)
    if target.is_local:
        return [Observation("whois_info", {"status": "skipped", "reason": "Local / private address", "queried": target.host}, "rdap")]
    if target.target_type == "cidr":
        return [Observation("whois_info", {"status": "skipped", "reason": "CIDR summary not queried"}, "rdap")]
    endpoint = "ip" if target.target_type == "ip" else "domain"
    lookup_name = target.host if target.target_type == "ip" else root_domain(target.host)
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
            "entities": [e for e in entities if e],
            "source": url,
        }

    try:
        info = await asyncio.to_thread(fetch)
    except HTTPError as exc:
        log.warning("WHOIS/RDAP HTTP %s for %s", exc.code, lookup_name)
        info = {
            "status": "unavailable",
            "reason": f"RDAP HTTP {exc.code}: {exc.reason}",
            "queried": lookup_name,
            "original_target": target.host,
            "source": url,
        }
    except (OSError, TimeoutError, ValueError, json.JSONDecodeError, URLError) as exc:
        log.warning("WHOIS/RDAP unavailable for %s: %s", lookup_name, exc)
        info = {
            "status": "unavailable",
            "reason": str(exc),
            "queried": lookup_name,
            "original_target": target.host,
            "source": url,
        }
    return [Observation("whois_info", info, "rdap")]


def whois_lookup_name(target: Target) -> str:
    """Return the name that would be queried in RDAP/WHOIS for *target*.

    For domain targets this is the eTLD+1 root domain.
    For IP targets this is the IP address itself.

    This function exists for backward compatibility with existing tests and
    callers that need to predict the lookup key without running the full query.
    """
    if target.target_type == "ip":
        return target.host
    return root_domain(target.host)


def _registrar_name(payload: dict[str, Any]) -> str:
    for entity in payload.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for row in vcard[1]:
                    if row and row[0] == "fn":
                        return str(row[3])
            return str(entity.get("handle", ""))
    return ""


# ── Subdomain enumeration ──────────────────────────────────────────────────────


async def enumerate_subdomains(
    target: Target,
    logger: logging.Logger | None = None,
) -> list[Observation]:
    """Three-layer subdomain enumeration.

    Layers:
        1. Certificate Transparency logs via crt.sh
        2. DNS brute-force from built-in wordlist (dnspython async)
        3. Common names quick-check

    Each discovered host is resolved and HTTP-probed to confirm liveness.
    """
    log = logger or logging.getLogger(__name__)
    if target.is_local or target.target_type != "domain":
        return [Observation("subdomains", [], "subdomain-enum")]

    base_domain = root_domain(target.host)
    all_names: set[str] = set()

    # Layer 1: crt.sh Certificate Transparency ────────────────────────────────
    try:
        ct_names = await _query_crtsh(base_domain, log)
        all_names.update(ct_names)
        log.info("crt.sh found %d subdomains for %s", len(ct_names), base_domain)
    except Exception as exc:
        log.warning("crt.sh query failed: %s", exc)

    # Layer 2: DNS brute-force ─────────────────────────────────────────────────
    brute_candidates = [f"{w}.{base_domain}" for w in _BRUTE_WORDLIST]
    brute_found = await _dns_brute(brute_candidates, log)
    new_from_brute = brute_found - all_names
    all_names.update(brute_found)
    log.info("Brute-force found %d new subdomains (%d total)", len(new_from_brute), len(all_names))

    # Validate + HTTP probe all found names ────────────────────────────────────
    if not all_names:
        return [Observation("subdomains", [], "subdomain-enum")]

    tasks = [_validate_subdomain(name, log) for name in all_names]
    raw_results = await asyncio.gather(*tasks, return_exceptions=True)
    found = [r for r in raw_results if isinstance(r, dict) and r.get("resolved")]
    found.sort(key=lambda x: (not x.get("interesting"), x["subdomain"]))
    log.info("Subdomain enumeration complete: %d resolved", len(found))
    return [Observation("subdomains", found, "subdomain-enum")]


async def _query_crtsh(domain: str, log: logging.Logger) -> set[str]:
    """Query crt.sh for certificate transparency entries."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains: set[str] = set()
    async with http_client() as client:
        try:
            result = await client.get(
                url,
                timeout=__import__("aiohttp").ClientTimeout(total=30),
            )
            if result.status == 200:
                try:
                    data = json.loads(result.text())
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return subdomains
                for entry in data:
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name and name.endswith(f".{domain}") and "%" not in name and "*" not in name:
                            subdomains.add(name)
                        elif name == domain:
                            pass  # skip apex
        except Exception as exc:
            log.debug("crt.sh request failed: %s", exc)
    return subdomains


async def _dns_brute(candidates: list[str], log: logging.Logger) -> set[str]:
    """Resolve all candidates concurrently; return those that have A records."""
    resolver = _make_resolver()
    sem = asyncio.Semaphore(50)
    found: set[str] = set()

    async def check(name: str) -> str | None:
        async with sem:
            try:
                await resolver.resolve(name, "A", lifetime=3.0)
                return name
            except dns.exception.DNSException:
                return None

    results = await asyncio.gather(*[check(c) for c in candidates], return_exceptions=True)
    for r in results:
        if isinstance(r, str) and r:
            found.add(r)
    return found


async def _validate_subdomain(name: str, log: logging.Logger) -> dict[str, Any]:
    """Resolve + HTTP-probe a single subdomain and return a metadata dict."""
    resolver = _make_resolver()
    try:
        answers = await resolver.resolve(name, "A", lifetime=3.0)
        ips = [str(r) for r in answers]
    except Exception:
        return {"subdomain": name, "resolved": False}

    status, title = 0, ""
    try:
        async with http_client() as c:
            res = await c.get(
                f"https://{name}",
                retries=1,
                timeout=__import__("aiohttp").ClientTimeout(total=8),
            )
            status = res.status
            title = _extract_title(res.text())
    except Exception:
        try:
            async with http_client() as c:
                res = await c.get(
                    f"http://{name}",
                    retries=1,
                    timeout=__import__("aiohttp").ClientTimeout(total=8),
                )
                status = res.status
                title = _extract_title(res.text())
        except Exception:
            pass

    parts = name.split(".")
    label = parts[0] if parts else name
    interesting = (
        label in _INTERESTING_KEYWORDS
        or any(k in (title or "").lower() for k in _INTERESTING_KEYWORDS)
    )
    return {
        "subdomain": name,
        "ips": ips,
        "resolved": True,
        "http_status": status,
        "title": title,
        "interesting": interesting,
        "source": "enumeration",
    }


def _extract_title(body: str) -> str:
    m = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.I)
    return m.group(1).strip() if m else ""


# ── HTTP header fetching ──────────────────────────────────────────────────────


async def fetch_headers(
    target: Target,
    timeout: float,
    logger: logging.Logger | None = None,
) -> tuple[list[Observation], list[Finding]]:
    """Fetch HTTP response headers with the robust aiohttp client.

    Tries HTTPS first, falls back to plain HTTP when HTTPS is unreachable.
    Returns a 2-tuple of ``(observations, findings)``.
    """
    log = logger or logging.getLogger(__name__)
    if target.target_type == "cidr":
        return [Observation("http_skipped", "CIDR target", "http")], []

    import aiohttp as _aiohttp

    t0 = time.perf_counter()
    result: HTTPResult | None = None
    error: str | None = None

    try:
        async with http_client() as client:
            if target.scheme:
                result = await client.get(
                    target.base_url,
                    timeout=_aiohttp.ClientTimeout(total=timeout),
                )
            else:
                result = await client.try_both_protocols(target.netloc)
    except (ScanError, _aiohttp.ClientError, OSError, asyncio.TimeoutError) as exc:
        error = str(exc)
        log.warning("HTTP request failed for %s: %s", target.netloc, exc)

    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    if error or result is None:
        return [Observation("http_error", error or "unknown", "http")], [
            Finding(
                id="HTTP-REQUEST-FAILED",
                title="HTTP service could not be verified",
                severity="info",
                confidence="high",
                category="web",
                target=target.base_url,
                evidence=f"GET {target.base_url} failed: {error}",
                recommendation="Confirm the service is reachable from the assessment network and rerun the scan.",
            )
        ]

    log.info(
        "HTTP GET %s returned %d in %dms with %d headers",
        result.url, result.status, elapsed_ms, len(result.headers),
    )

    observations = [
        Observation("http_status", result.status, "http"),
        Observation("http_url", result.url, "http"),
        Observation("headers", result.headers, "http"),
        Observation("body_sample", result.text()[:2000], "http"),
        Observation("http_response_time_ms", elapsed_ms, "http"),
        Observation("redirect_chain", result.redirect_chain, "http"),
    ]
    body_text = result.text()
    findings = analyze_security_headers(result.url, result.headers, body_text)
    findings.extend(analyze_cookies(result.url, result.raw_set_cookies))
    return observations, findings


# ── Deep web analysis ─────────────────────────────────────────────────────────


async def deep_analyze_web(
    target: Target,
    base_url: str,
    logger: logging.Logger | None = None,
) -> list[Finding]:
    """Perform deep web application analysis.

    Checks:
        - Sensitive path exposure (concurrent probes)
        - PHP error disclosure
        - Directory listing detection
        - HTTP → HTTPS redirect enforcement
        - CORS wildcard policy
        - Server version disclosure

    Args:
        target: Normalised scan target.
        base_url: The effective URL obtained from :func:`fetch_headers`.
        logger: Optional per-scan logger.

    Returns:
        List of confirmed :class:`Finding` objects.
    """
    log = logger or logging.getLogger(__name__)
    if target.target_type == "cidr":
        return []

    base = base_url.rstrip("/")
    findings: list[Finding] = []
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    if parsed.scheme and parsed.netloc:
        web_root = f"{parsed.scheme}://{parsed.netloc}"
    else:
        web_root = base_url.rstrip("/")

    from modules.sensitive_path_scanner import SensitivePathScanner
    from modules.catch_all_detector import CatchAllDetector
    from modules.template_scanner import TemplateScanner
    from pathlib import Path

    async with http_client() as client:
        # ── Sensitive path probing (concurrent with body verification) ────────
        detector = CatchAllDetector(http_client=client)
        catch_all = await detector.detect(web_root)

        scanner = SensitivePathScanner(http_client=client)
        path_findings = await scanner.scan(web_root, catch_all=catch_all)
        for r in path_findings:
            findings.append(r)
            log.info("Sensitive path found: %s", r.target)

        # ── YAML Template engine scanning ─────────────────────────────────────
        try:
            rules_dir = Path(__file__).parent.parent / "rules"
            if rules_dir.exists():
                tmpl_scanner = TemplateScanner(http_client=client)
                tmpl_findings = await tmpl_scanner.scan(
                    target=web_root,
                    template_dir=rules_dir,
                    tags=None,
                    severity=["critical", "high", "medium"],
                    catch_all=catch_all,
                )
                for tf in tmpl_findings:
                    findings.append(tf)
                    log.info("Template vulnerability found: %s (%s)", tf.title, tf.target)
        except Exception as e:
            log.debug("Template scanning error: %s", e)

        # ── Fetch the main page for body analysis ─────────────────────────────
        try:
            main_url = base_url if (parsed.path and parsed.path != "/") else (web_root + "/")
            main = await client.get(main_url, retries=1)
            body = main.text()
            headers = main.headers

            # CORS analysis
            cors_origin = headers.get("access-control-allow-origin", "")
            if cors_origin == "*":
                cors_creds = headers.get("access-control-allow-credentials", "false").lower()
                if cors_creds == "true":
                    findings.append(
                        Finding(
                            id="CORS-WILDCARD-WITH-CREDENTIALS",
                            title="CORS wildcard with credentials enabled",
                            severity="high",
                            confidence="high",
                            category="web",
                            target=base,
                            evidence=(
                                f"Access-Control-Allow-Origin: {cors_origin}\n"
                                f"Access-Control-Allow-Credentials: {cors_creds}"
                            ),
                            recommendation="Restrict CORS to specific trusted origins rather than using wildcard.",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            id="CORS-WILDCARD-ORIGIN",
                            title="CORS wildcard origin (any domain can cross-request)",
                            severity="low",
                            confidence="high",
                            category="web",
                            target=base,
                            evidence=f"Access-Control-Allow-Origin: {cors_origin}",
                            recommendation="Restrict CORS to specific trusted domains.",
                        )
                    )

            # Server version disclosure
            server = headers.get("server", "")
            if server and re.search(r"\d+\.\d+", server):
                findings.append(
                    Finding(
                        id="SERVER-VERSION-DISCLOSED",
                        title="Web server version disclosed in response header",
                        severity="low",
                        confidence="high",
                        category="web",
                        target=base,
                        evidence=f"Server: {server}",
                        recommendation="Remove the version number from the Server header in your web server configuration.",
                    )
                )

            # X-Powered-By disclosure
            powered = headers.get("x-powered-by", "")
            if powered:
                findings.append(
                    Finding(
                        id="XPOWEREDBY-DISCLOSED",
                        title="X-Powered-By header reveals technology stack",
                        severity="info",
                        confidence="high",
                        category="web",
                        target=base,
                        evidence=f"X-Powered-By: {powered}",
                        recommendation="Remove the X-Powered-By header to reduce fingerprinting surface.",
                    )
                )

            # PHP error disclosure
            if re.search(
                r"(error|exception|stack.?trace|fatal|warning).*?(in|at|on)\s+[/\\][\w/\\.-]+\.php",
                body, re.I,
            ):
                findings.append(
                    Finding(
                        id="PHP-ERROR-DISCLOSURE",
                        title="PHP error message discloses file paths",
                        severity="medium",
                        confidence="high",
                        category="web",
                        target=base,
                        evidence="PHP error or exception message found in HTTP response body.",
                        recommendation="Set display_errors=Off in php.ini and log errors to a file.",
                    )
                )

            # Directory listing detection
            if re.search(
                r"(<title>Index of|Directory listing for|\[To Parent Directory\])",
                body, re.I,
            ):
                findings.append(
                    Finding(
                        id="DIRECTORY-LISTING-ENABLED",
                        title="Directory listing is enabled",
                        severity="medium",
                        confidence="high",
                        category="web",
                        target=base,
                        evidence="Directory listing page detected in HTTP response body.",
                        recommendation="Disable directory listing in your web server configuration (Options -Indexes in Apache; autoindex off in nginx).",
                    )
                )

        except Exception as exc:
            log.debug("Deep body analysis failed: %s", exc)

        # ── HTTP → HTTPS redirect check ────────────────────────────────────────
        if base.startswith("https://"):
            http_url = base.replace("https://", "http://", 1)
            try:
                redirect_result = await client.get(
                    http_url,
                    retries=1,
                    allow_redirects=False,
                    timeout=_aiohttp.ClientTimeout(total=8),
                )
                is_redirect = redirect_result.status in {301, 302, 307, 308}
                # Also accept non-redirect responses that include a Location
                # header pointing to HTTPS (some servers do this).
                location = redirect_result.headers.get("location", "")
                redirects_to_https = location.lower().startswith("https://")
                # Check for meta-refresh or JS redirect to HTTPS in the body
                body_text = redirect_result.text() if hasattr(redirect_result, 'text') else ""
                has_meta_redirect = (
                    'https://' in body_text.lower()
                    and ('http-equiv="refresh"' in body_text.lower()
                         or 'window.location' in body_text.lower())
                )
                if not is_redirect and not redirects_to_https and not has_meta_redirect:
                    findings.append(
                        Finding(
                            id="HTTP-NOT-REDIRECTED-TO-HTTPS",
                            title="HTTP requests are not redirected to HTTPS",
                            severity="medium",
                            confidence="high",
                            category="web",
                            target=http_url,
                            evidence=(
                                f"GET {http_url} returned HTTP {redirect_result.status} "
                                f"instead of a redirect to HTTPS."
                            ),
                            recommendation="Add a server-side redirect (301) from HTTP to HTTPS for all requests.",
                        )
                    )
            except Exception:
                pass  # Can't reach HTTP — treat as non-issue

    return findings


def _path_severity(path: str) -> str:  # type: ignore[return]
    critical = {".env", ".env.local", ".env.production", "wp-config.php", "config.php", ".git/HEAD"}
    high = {"phpinfo.php", ".htaccess", "backup.zip", "web.config", "elmah.axd", "trace.axd"}
    medium = {"admin/", "phpmyadmin/", "server-status"}
    p = path.lstrip("/")
    if any(c in p for c in critical):
        return "critical"
    if any(h in p for h in high):
        return "high"
    if any(m in p for m in medium):
        return "medium"
    return "low"


def _path_is_sensitive_content(body: str, path: str) -> bool:
    """Return True when a nominally public path has genuinely sensitive content.

    Standard public files (robots.txt, sitemap.xml, security.txt) are only
    flagged when they reveal sensitive internal information.  A mere HTTP 200
    for these well-known files is NOT a vulnerability.
    """
    lower = body.lower()
    if "robots.txt" in path:
        # Only flag robots.txt if it reveals sensitive internal paths
        # (admin panels, backup dirs, etc.) — normal Disallow rules are fine.
        sensitive_indicators = (
            "admin", "backup", "database", "phpmyadmin", "config",
            "internal", ".env", "secret", "private", "wp-admin",
        )
        return any(ind in lower for ind in sensitive_indicators)
    if "security.txt" in path:
        # security.txt is an IETF standard (RFC 9116) — having one is a
        # *best practice*, NOT a vulnerability.  Never flag it.
        return False
    if "sitemap.xml" in path:
        # Sitemaps are standard public SEO files — never flag.
        return False
    if "crossdomain.xml" in path:
        # Only flag crossdomain.xml if it has an overly permissive policy
        # that allows any domain to make cross-origin requests.
        return 'domain="*"' in lower or "domain='*'" in lower
    return True


# ── Security header analysis ──────────────────────────────────────────────────


def analyze_security_headers(
    url: str,
    headers: dict[str, str],
    html_body: str = "",
) -> list[Finding]:
    """Create a grouped security header finding for all missing defensive headers.

    Uses :class:`HeaderAnalyzer` for case-insensitive lookups (RFC 7230),
    checks CSP via both HTTP header and ``<meta>`` tag, and resolves the
    ``X-Frame-Options`` / ``frame-ancestors`` overlap correctly.

    Args:
        url: The URL being analysed (used for finding target).
        headers: Raw HTTP response headers (any casing).
        html_body: The HTML response body (used for ``<meta>`` CSP detection).
    """
    from phantomscan.modules.header_analyzer import (
        HeaderAnalyzer,
        check_frame_protection,
        detect_csp,
    )

    ha = HeaderAnalyzer(headers)
    csp_result = detect_csp(headers, html_body)
    frame_result = check_frame_protection(headers, csp_result)

    # Severity map — ceiling is Medium, per calibration rules
    HEADER_SEVERITY: dict[str, str] = {
        "strict-transport-security": "medium",
        "content-security-policy":   "medium",
        "x-content-type-options":    "low",
        "referrer-policy":           "low",
        "permissions-policy":        "low",
    }
    SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2}

    missing: list[tuple[str, str, str]] = []  # (label, impact, severity)

    # HSTS
    if not ha.has_header("strict-transport-security"):
        missing.append((
            "HSTS",
            "Browsers may downgrade to HTTP connections.",
            HEADER_SEVERITY["strict-transport-security"],
        ))

    # CSP — check both header AND meta tag
    if not csp_result.present:
        missing.append((
            "Content-Security-Policy",
            "XSS is harder to mitigate without a CSP.",
            HEADER_SEVERITY["content-security-policy"],
        ))

    # X-Content-Type-Options
    if not ha.has_header("x-content-type-options"):
        missing.append((
            "X-Content-Type-Options",
            "MIME-type sniffing attacks are possible.",
            HEADER_SEVERITY["x-content-type-options"],
        ))

    # Frame protection — only flag if NEITHER XFO nor frame-ancestors present
    if not frame_result.protected:
        missing.append((
            "X-Frame-Options / frame-ancestors",
            frame_result.note,
            "low",
        ))

    # Referrer-Policy
    if not ha.has_header("referrer-policy"):
        missing.append((
            "Referrer-Policy",
            "Full referrer URLs may be leaked to third-party sites.",
            HEADER_SEVERITY["referrer-policy"],
        ))

    # Permissions-Policy
    if not ha.has_header("permissions-policy"):
        missing.append((
            "Permissions-Policy",
            "Browser features (camera, microphone) are unrestricted.",
            HEADER_SEVERITY["permissions-policy"],
        ))

    if not missing:
        return []

    # Overall severity = highest individual component, capped at Medium
    overall_severity = max(
        missing, key=lambda m: SEVERITY_RANK.get(m[2], 0)
    )[2]

    evidence_lines = "\n".join(
        f"Missing: {label} — {impact}" for label, impact, _ in missing
    )

    # Add CSP meta-tag note if relevant
    if csp_result.present and csp_result.source == "meta_tag" and csp_result.note:
        evidence_lines += f"\nNote: {csp_result.note}"

    # Exactly ONE finding object — this is the only code path that creates
    # the grouped header finding
    return [
        Finding(
            id="SECURITY-HEADERS-GROUPED",
            title="Security headers policy incomplete",
            severity=overall_severity,  # type: ignore[arg-type]
            confidence="high",
            category="web",
            target=url,
            evidence=evidence_lines,
            recommendation=(
                "Add missing defensive HTTP response headers in your "
                "web server or application configuration."
            ),
        )
    ]


# ── Cookie analysis ───────────────────────────────────────────────────────────

_TRACKING_PREFIXES = ("_ga", "_gid", "_fbp", "_hjid", "__utma", "__utmb", "__utmc", "__utmz", "_gcl")
_TRACKING_NAMES = {"NID", "IDE", "DSID", "1P_JAR", "CONSENT"}
# Consent/preference cookies that intentionally need JavaScript access
# (e.g., __Secure-STRP is Google's consent management cookie).
_CONSENT_COOKIE_NAMES = {"__Secure-STRP", "__Secure-3PSIDTS", "__Secure-ENID"}
_CONSENT_COOKIE_PREFIXES = ("__Secure-3P",)


def analyze_cookies(url: str, raw_set_cookies: list[str]) -> list[Finding]:
    """Analyse ``Set-Cookie`` header values for missing security flags.

    Args:
        url: URL being analysed (used for finding target).
        raw_set_cookies: Raw ``Set-Cookie`` header strings (one per cookie).

    Returns:
        List of :class:`Finding` objects.
    """
    findings: list[Finding] = []
    for cookie_str in raw_set_cookies:
        parsed = _parse_set_cookie(cookie_str)
        name = parsed.get("name", "")
        if not name:
            continue

        # Skip tracking/analytics cookies
        if (
            name in _TRACKING_NAMES
            or any(name.startswith(p) for p in _TRACKING_PREFIXES)
        ):
            continue

        # Skip consent/preference cookies that intentionally need JS access
        is_consent_cookie = (
            name in _CONSENT_COOKIE_NAMES
            or any(name.startswith(p) for p in _CONSENT_COOKIE_PREFIXES)
        )
        if is_consent_cookie:
            continue

        # Skip cookies that are already expired
        if parsed.get("expired"):
            continue

        # __Secure- prefix implies Secure flag was intended
        secure_prefix = name.startswith("__Secure-") or name.startswith("__Host-")
        has_secure = parsed.get("secure", False) or secure_prefix
        has_httponly = parsed.get("httponly", False)

        is_tracking = False  # already filtered above
        severity = "low"

        if not has_secure:
            findings.append(
                Finding(
                    id=f"COOKIE-MISSING-SECURE-{name.upper()[:30]}",
                    title=f"Cookie missing Secure flag: {name}",
                    severity=severity,  # type: ignore[arg-type]
                    confidence="high",
                    category="web",
                    target=url,
                    evidence=f"Set-Cookie: {cookie_str[:300]}",
                    recommendation="Add the Secure attribute so this cookie is only transmitted over HTTPS.",
                )
            )

        if not has_httponly:
            findings.append(
                Finding(
                    id=f"COOKIE-MISSING-HTTPONLY-{name.upper()[:30]}",
                    title=f"Cookie missing HttpOnly flag: {name}",
                    severity=severity,  # type: ignore[arg-type]
                    confidence="high",
                    category="web",
                    target=url,
                    evidence=f"Set-Cookie: {cookie_str[:300]}",
                    recommendation="Add the HttpOnly attribute to prevent JavaScript access to this cookie.",
                )
            )
    return findings


def _parse_set_cookie(raw: str) -> dict[str, Any]:
    """Parse a raw Set-Cookie string into a dict of attributes."""
    parts = [p.strip() for p in raw.split(";")]
    result: dict[str, Any] = {"secure": False, "httponly": False, "expired": False}
    if not parts:
        return result

    # First part is name=value
    first = parts[0]
    if "=" in first:
        name, _, _ = first.partition("=")
        result["name"] = name.strip()
    else:
        result["name"] = first.strip()

    for attr in parts[1:]:
        lower = attr.lower()
        if lower == "secure":
            result["secure"] = True
        elif lower == "httponly":
            result["httponly"] = True
        elif lower.startswith("expires="):
            try:
                dt = parsedate_to_datetime(attr[8:])
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                result["expired"] = dt < datetime.now(timezone.utc)
            except Exception:
                pass
    return result


# ── Technology detection ──────────────────────────────────────────────────────


def detect_technologies(observations: list[Observation]) -> list[Observation]:
    """Infer technologies from headers, cookies, and HTML body sample."""
    headers: dict[str, Any] = {}
    body = ""
    for obs in observations:
        if obs.name == "headers" and isinstance(obs.value, dict):
            headers = obs.value
        if obs.name == "body_sample" and isinstance(obs.value, str):
            body = obs.value.lower()

    tech: list[dict[str, Any]] = []

    # Server header
    server = str(headers.get("server", ""))
    if server:
        name = "Google Web Server" if server.lower() == "gws" else server.split("/")[0]
        version = ""
        m = re.search(r"/(\d[\d.]+)", server)
        if m:
            version = m.group(1)
        entry: dict[str, Any] = {"name": name, "source": "server-header", "confidence": 85}
        if version:
            entry["version"] = version
        tech.append(entry)

    # X-Powered-By
    powered = str(headers.get("x-powered-by", ""))
    if powered:
        name = powered.split("/")[0]
        entry = {"name": name, "source": "x-powered-by", "confidence": 80}
        m = re.search(r"/(\d[\d.]+)", powered)
        if m:
            entry["version"] = m.group(1)
        tech.append(entry)

    # Via header → proxy/CDN
    via = str(headers.get("via", ""))
    if via:
        tech.append({"name": "Proxy/CDN layer", "source": "via-header", "confidence": 65})

    # HTTP/3 QUIC via Alt-Svc
    alt_svc = str(headers.get("alt-svc", ""))
    if "h3" in alt_svc.lower():
        tech.append({"name": "HTTP/3 QUIC", "source": "alt-svc", "confidence": 90})

    # Cookie-based fingerprinting
    cookies_raw = str(headers.get("set-cookie", "")).lower()
    if "phpsessid" in cookies_raw:
        tech.append({"name": "PHP", "source": "cookie-name", "confidence": 85})
    if "jsessionid" in cookies_raw:
        tech.append({"name": "Java (JVM)", "source": "cookie-name", "confidence": 80})
    if "asp.net_sessionid" in cookies_raw or "aspxauth" in cookies_raw:
        tech.append({"name": "ASP.NET", "source": "cookie-name", "confidence": 85})
    if "nid=" in cookies_raw:
        tech.append({"name": "Google cookie stack", "source": "cookie-name", "confidence": 70})

    # CDN / WAF detection from response headers
    if headers.get("cf-ray"):
        tech.append({"name": "Cloudflare CDN/WAF", "source": "cf-ray-header", "confidence": 95})
    if headers.get("x-amz-cf-id") or headers.get("x-amzn-requestid"):
        tech.append({"name": "AWS CloudFront", "source": "aws-header", "confidence": 90})
    if headers.get("x-cache", "").startswith("HIT") and headers.get("x-served-by"):
        tech.append({"name": "Fastly CDN", "source": "fastly-header", "confidence": 80})
    if headers.get("x-varnish"):
        tech.append({"name": "Varnish Cache", "source": "x-varnish-header", "confidence": 90})
    if "akamai" in str(headers.get("x-check-cacheable", "")).lower():
        tech.append({"name": "Akamai CDN", "source": "akamai-header", "confidence": 80})

    # HTML body signatures
    html_signatures = {
        "wp-content":       "WordPress",
        "wp-includes":      "WordPress",
        "drupal.js":        "Drupal",
        "sites/default":    "Drupal",
        "joomla":           "Joomla",
        "react":            "React",
        "next.js":          "Next.js",
        "nuxt":             "Nuxt.js",
        "angular":          "Angular",
        "vue":              "Vue.js",
        "jquery":           "jQuery",
        "bootstrap":        "Bootstrap",
        "tailwindcss":      "Tailwind CSS",
        "shopify":          "Shopify",
        "wix.com":          "Wix",
        "squarespace":      "Squarespace",
        "laravel":          "Laravel",
        "django":           "Django",
        "rails":            "Ruby on Rails",
        "spring":           "Spring Framework",
    }
    for marker, name in html_signatures.items():
        if marker in body:
            if not any(t["name"] == name for t in tech):
                tech.append({"name": name, "source": "html", "confidence": 65})

    return [Observation("technologies", tech, "fingerprint")]


# ── Internal helpers ─────────────────────────────────────────────────────────


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
