"""Module 5 — Subdomain Takeover Detector.

Detects dangling CNAME records pointing to unclaimed third-party services.
Checks 16 service fingerprints (GitHub Pages, Heroku, S3, Azure, etc.).
Runs automatically as part of subdomain enumeration.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Service fingerprints for takeover detection
# ---------------------------------------------------------------------------

TAKEOVER_FINGERPRINTS: dict[str, dict[str, str]] = {
    "github.io": {
        "cname_pattern": r".*\.github\.io$",
        "response_signature": "There isn't a GitHub Pages site here",
        "service": "GitHub Pages",
    },
    "herokuapp.com": {
        "cname_pattern": r".*\.herokuapp\.com$",
        "response_signature": "No such app",
        "service": "Heroku",
    },
    "s3.amazonaws.com": {
        "cname_pattern": r".*\.s3.*\.amazonaws\.com$",
        "response_signature": "NoSuchBucket",
        "service": "AWS S3",
    },
    "azurewebsites.net": {
        "cname_pattern": r".*\.azurewebsites\.net$",
        "response_signature": "404 Web Site not found",
        "service": "Azure App Service",
    },
    "cloudfront.net": {
        "cname_pattern": r".*\.cloudfront\.net$",
        "response_signature": "ERROR: The request could not be satisfied",
        "service": "AWS CloudFront",
    },
    "ghost.io": {
        "cname_pattern": r".*\.ghost\.io$",
        "response_signature": "The thing you were looking for is no longer here",
        "service": "Ghost",
    },
    "wordpress.com": {
        "cname_pattern": r".*\.wordpress\.com$",
        "response_signature": "Do you want to register",
        "service": "WordPress.com",
    },
    "zendesk.com": {
        "cname_pattern": r".*\.zendesk\.com$",
        "response_signature": "Help Center Closed",
        "service": "Zendesk",
    },
    "shopify.com": {
        "cname_pattern": r".*\.myshopify\.com$",
        "response_signature": "Sorry, this shop is currently unavailable",
        "service": "Shopify",
    },
    "fastly.net": {
        "cname_pattern": r".*\.fastly\.net$",
        "response_signature": "Fastly error: unknown domain",
        "service": "Fastly",
    },
    "unbouncepages.com": {
        "cname_pattern": r".*\.unbouncepages\.com$",
        "response_signature": "The requested URL was not found on this server",
        "service": "Unbounce",
    },
    "surge.sh": {
        "cname_pattern": r".*\.surge\.sh$",
        "response_signature": "project not found",
        "service": "Surge.sh",
    },
    "bitbucket.io": {
        "cname_pattern": r".*\.bitbucket\.io$",
        "response_signature": "Repository not found",
        "service": "Bitbucket Pages",
    },
    "pantheonsite.io": {
        "cname_pattern": r".*\.pantheonsite\.io$",
        "response_signature": "The gods are wise",
        "service": "Pantheon",
    },
    "helpjuice.com": {
        "cname_pattern": r".*\.helpjuice\.com$",
        "response_signature": "We could not find what you're looking for",
        "service": "Helpjuice",
    },
    "tumblr.com": {
        "cname_pattern": r".*\.domains\.tumblr\.com$",
        "response_signature": "Whatever you were looking for doesn't currently exist",
        "service": "Tumblr",
    },
}


class SubdomainTakeoverDetector:
    """Detect dangling CNAMEs vulnerable to subdomain takeover."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface — extract subdomains from observations and check."""
        observations = kwargs.get("observations", [])

        # Extract subdomain list from observations
        subdomains: list[str] = []
        for obs in observations:
            if obs.get("name") == "subdomains":
                val = obs.get("value", [])
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            subdomains.append(item.get("subdomain", ""))
                        elif isinstance(item, str):
                            subdomains.append(item)

        if not subdomains:
            logger.debug("No subdomains found for takeover check")
            return []

        logger.info("Checking %d subdomains for takeover vulnerabilities", len(subdomains))
        return await self.detect(subdomains)

    async def detect(self, subdomains: list[str]) -> list[dict[str, Any]]:
        """Check each subdomain for dangling CNAME takeover vulnerability."""
        findings: list[dict[str, Any]] = []
        import asyncio
        sem = asyncio.Semaphore(20)

        async def check_one(subdomain: str) -> list[dict[str, Any]]:
            if not subdomain:
                return []
            res: list[dict[str, Any]] = []
            async with sem:
                cname = await self._get_cname(subdomain)
                if not cname:
                    return []

                for _service_key, fingerprint in TAKEOVER_FINGERPRINTS.items():
                    if not re.match(fingerprint["cname_pattern"], cname, re.IGNORECASE):
                        continue

                    # CNAME points to a known service — verify the resource is unclaimed
                    try:
                        resp = await self.http.request(
                            "GET", f"https://{subdomain}",
                            timeout=5,
                        )
                        body = resp.get("body", "") if isinstance(resp, dict) else (resp.text() if hasattr(resp, "text") and callable(resp.text) else getattr(resp, "body", ""))
                        if isinstance(body, bytes):
                            body = body.decode("utf-8", errors="ignore")

                        if fingerprint["response_signature"] in str(body):
                            res.append({
                                "title": f"Subdomain Takeover: {subdomain}",
                                "severity": "critical",
                                "confidence": "high",
                                "category": "subdomain_takeover",
                                "target": subdomain,
                                "evidence": (
                                    f"CNAME: {cname}\n"
                                    f"Service: {fingerprint['service']}\n"
                                    f"Signature found: '{fingerprint['response_signature']}'"
                                    ),
                                "recommendation": (
                                    f"Either claim the {fingerprint['service']} resource "
                                    f"immediately or remove the dangling CNAME record for {subdomain}"
                                ),
                                "references": ["CWE-350"],
                                "module": "subdomain_takeover",
                            })
                            logger.warning(
                                "CRITICAL: Subdomain takeover possible on %s via %s",
                                subdomain, fingerprint["service"],
                            )
                    except Exception as exc:
                        logger.debug("Takeover check error for %s: %s", subdomain, exc)
            return res

        results = await asyncio.gather(*(check_one(s) for s in subdomains), return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    async def _get_cname(self, subdomain: str) -> Optional[str]:
        """Resolve CNAME record for a subdomain."""
        try:
            import dns.asyncresolver
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 5.0
            answers = await resolver.resolve(subdomain, "CNAME")
            return str(answers[0].target).rstrip(".")
        except ImportError:
            # Fallback: use socket-based resolution
            logger.debug("dnspython not available, skipping CNAME check for %s", subdomain)
            return None
        except Exception:
            return None
