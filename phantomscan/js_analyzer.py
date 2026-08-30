"""JavaScript bundle analyzer & SPA endpoint extractor.

Scrapes frontend JavaScript bundles (.js) and inline scripts to extract
hidden REST API routes, endpoints, query parameters, and sensitive strings.
Essential for modern Single Page Applications (SPAs) like Angular, React, Vue.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from phantomscan.http_client import RobustHTTPClient
from phantomscan.models import Observation

logger = logging.getLogger(__name__)

# Regex patterns for extracting endpoints from JavaScript
_ROUTE_PATTERNS = [
    # Explicit REST/API routes: "/rest/...", "/api/...", "/v1/..."
    re.compile(r"""["'`]((?:/(?:rest|api|v\d+|b2b|ftp|auth|oauth|admin|graphql|user|users|products|basket|order|order-history|feedback|snippets|encryptionkeys|profile|file-upload|app|dashboard|account|settings|checkout)[a-zA-Z0-9_/\-.:?=&#\[\]$]*)?)["'`]"""),

    # Generic API paths
    re.compile(r"""["'`](/api/[a-zA-Z0-9_/\-.:?=&#\[\]$]+)["'`]"""),

    # Common JS fetch / axios / xhr calls: fetch('/...') or .get('/...')
    re.compile(r"""(?:fetch|\.get|\.post|\.put|\.delete|\.patch|\.request|\$http)\s*\(\s*["'`]((?:/[^"'`\s]+|https?://[^"'`\s]+))["'`]"""),

    # Angular / Vue / React / Next.js route definitions: path: '...'
    re.compile(r"""(?:path|url|endpoint|route|href|to)\s*:\s*["'`]((?:/[^"'`\s]+))["'`]"""),

    # HTML / SPA hash routes: /#/search, /#/login
    re.compile(r"""["'`](/#[a-zA-Z0-9_/\-.:?=&#]*)["'`]"""),

    # GraphQL operation names
    re.compile(r"""(?:query|mutation|subscription)\s+([A-Za-z0-9_]+)\s*(?:\([^\)]*\))?\s*\{"""),
]

# Sensitive keywords / exposed secrets in JavaScript
_SECRET_PATTERNS = [
    (re.compile(r"""(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']""", re.IGNORECASE), "Exposed API / Auth Secret"),
    (re.compile(r"""["'](eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]*)["']"""), "Hardcoded JWT Token"),
    (re.compile(r"""["']((?:AKIA|ASIA)[0-9A-Z]{16})["']"""), "Hardcoded AWS Access Key"),
]



class JSRouteExtractor:
    """Extracts hidden endpoints and routes from SPA JavaScript files."""

    def __init__(self, http: RobustHTTPClient, max_scripts: int = 12) -> None:
        self.http = http
        self.max_scripts = max_scripts

    async def analyze(
        self, base_url: str, html_body: str, logger_inst: logging.Logger | None = None
    ) -> tuple[list[str], list[Observation], list[dict[str, Any]]]:
        """Analyze page HTML and linked JavaScript bundles.

        Returns:
            discovered_urls: List of full URLs found in JS code.
            observations: List of Observation objects.
            secret_findings: List of potential secrets or sensitive disclosures found in JS.
        """
        log = logger_inst or logger
        base = base_url.rstrip("/")
        parsed_base = urlparse(base)
        domain = parsed_base.netloc.lower()

        # Step 1: Find script sources
        script_srcs = set()
        for match in re.finditer(r"""<script[^>]+src=["']([^"']+)["']""", html_body, re.IGNORECASE):
            src = match.group(1).strip()
            if src:
                full_src = urljoin(base + "/", src)
                parsed_src = urlparse(full_src)
                # Keep same-origin scripts or relative scripts
                if not parsed_src.netloc or parsed_src.netloc.lower() == domain or "localhost" in parsed_src.netloc:
                    script_srcs.add(full_src)

        log.info("Discovered %d JavaScript bundle(s) in %s", len(script_srcs), base)

        # Also analyze inline script tags from the initial HTML
        scripts_to_fetch = list(script_srcs)[: self.max_scripts]
        js_contents: list[tuple[str, str]] = [("inline_html", html_body)]

        # Fetch scripts concurrently
        async def fetch_js(url: str) -> tuple[str, str] | None:
            try:
                res = await self.http.get(url, retries=1)
                if res.status == 200 and res.body:
                    return (url, res.text())
            except Exception as exc:
                log.debug("Failed to fetch JS bundle %s: %s", url, exc)
            return None

        if scripts_to_fetch:
            results = await asyncio.gather(*(fetch_js(u) for u in scripts_to_fetch), return_exceptions=True)
            for r in results:
                if isinstance(r, tuple):
                    js_contents.append(r)

        # Step 2: Extract routes & endpoints from all JS content
        discovered_paths: set[str] = set()
        secret_findings: list[dict[str, Any]] = []

        for source_name, content in js_contents:
            if not content:
                continue

            for pattern in _ROUTE_PATTERNS:
                for m in pattern.finditer(content):
                    raw_path = m.group(1).strip()
                    # Filter out common false-positives
                    if (
                        raw_path.startswith("//")
                        or raw_path.startswith("http://")
                        or raw_path.startswith("https://")
                    ):
                        p_parsed = urlparse(raw_path)
                        if p_parsed.netloc and p_parsed.netloc.lower() != domain:
                            continue
                        raw_path = p_parsed.path + (f"?{p_parsed.query}" if p_parsed.query else "")

                    # Clean up path
                    if not raw_path.startswith("/") and not raw_path.startswith("#"):
                        raw_path = "/" + raw_path

                    # Filter out static asset extensions (images, css, fonts)
                    if any(raw_path.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf", ".eot"]):
                        continue

                    # Validate reasonable path length and format
                    if 2 <= len(raw_path) <= 150 and not any(c in raw_path for c in "<>{};"):
                        discovered_paths.add(raw_path)

            # Check for exposed secrets
            for pattern, sec_name in _SECRET_PATTERNS:
                for sm in pattern.finditer(content):
                    secret_val = sm.group(1).strip()
                    # Skip common test/dummy values
                    if secret_val.lower() in {"null", "undefined", "true", "false", "test", "your_key_here"}:
                        continue
                    secret_findings.append({
                        "id": "JS-EXPOSED-SECRET",
                        "title": f"{sec_name} Disclosed in Client-Side JavaScript",
                        "severity": "high",
                        "confidence": "high",
                        "category": "web",
                        "target": source_name if source_name != "inline_html" else base,
                        "evidence": f"Pattern matched: {sec_name}\nLocation: {source_name}\nSnippet: ...{sm.group(0)[:80]}...",
                        "recommendation": "Remove hardcoded credentials, secret keys, and tokens from client-accessible JavaScript files.",
                    })

        discovered_urls: list[str] = []
        for p in sorted(discovered_paths):
            if p.startswith("#"):
                discovered_urls.append(f"{base}/{p}")
            else:
                discovered_urls.append(f"{base}{p}")

        log.info("Extracted %d unique endpoints/routes from JavaScript bundles", len(discovered_urls))

        observations: list[Observation] = [
            Observation("discovered_js_bundles", list(script_srcs), "js-analyzer"),
            Observation("discovered_api_routes", list(sorted(discovered_paths)), "js-analyzer"),
            Observation("discovered_urls", discovered_urls, "js-analyzer"),
        ]

        return discovered_urls, observations, secret_findings
