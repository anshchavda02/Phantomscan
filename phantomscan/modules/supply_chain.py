"""Module 12 — Third Party and Supply Chain Analyzer.

Scans for hardcoded secrets in JS files, missing SRI on CDN scripts,
mixed-content third-party loading, and outdated JS library detection.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:secret|private[_-]?key)[\"'\s]*[:=][\"'\s]*[\"']?([A-Za-z0-9_\-]{20,})", re.I), "Secret Key"),
    (re.compile(r"(?:password|passwd|pwd)[\"'\s]*[:=][\"'\s]*[\"']?([^\s\"']{8,})", re.I), "Password"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub Personal Token"),
    (re.compile(r"gho_[a-zA-Z0-9]{36}"), "GitHub OAuth Token"),
    (re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"), "Slack Token"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "Stripe Live Secret Key"),
    (re.compile(r"sk_test_[0-9a-zA-Z]{24,}"), "Stripe Test Secret Key"),
    (re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}"), "Square OAuth Token"),
    (re.compile(r"(?:bearer|token)[\"'\s]*[:=][\"'\s]*[\"']?([A-Za-z0-9_\-.]{20,})", re.I), "Bearer Token"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "JWT Token"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google Public API Key"),
    (re.compile(r"(?:api[_-]?key|apikey)[\"'\s]*[:=][\"'\s]*[\"']?([A-Za-z0-9_\-]{20,})", re.I), "API Key"),
]

_KNOWN_LIBRARIES: dict[str, re.Pattern[str]] = {
    "jQuery": re.compile(r"\bjquery(?:[.\-/]|\s+)?v?(\d+(?:\.\d+)+)", re.I),
    "Angular": re.compile(r"\bangular(?:[.\-/]|\s+)?v?(\d+(?:\.\d+)+)", re.I),
    "AngularJS": re.compile(r"\bangular(?:\.js|js)(?:[.\-/]|\s+)?v?(\d+(?:\.\d+)+)", re.I),
    "React": re.compile(r"\breact(?:\.production)?(?:[.\-/]|\s+)?v?(\d+(?:\.\d+)+)", re.I),
    "Vue.js": re.compile(r"\bvue(?:[.\-/]|\s+)?v?(\d+(?:\.\d+)+)", re.I),
    "Bootstrap": re.compile(r"\bbootstrap(?:[.\-/]|\s+)?v?(\d+(?:\.\d+)+)", re.I),
    "Lodash": re.compile(r"\blodash(?:[.\-/]|\s+)?v?(\d+(?:\.\d+)+)", re.I),
    "Moment.js": re.compile(r"\bmoment(?:[.\-/]|\s+)?v?(\d+(?:\.\d+)+)", re.I),
}


class SupplyChainAnalyzer:
    """Analyze third-party scripts for secrets, SRI, and outdated libraries."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        target = base_url.rstrip("/")

        # Get main page HTML
        try:
            response = await self.http.get(target + "/", retries=1)
            html_body = response.text()
        except Exception:
            return findings

        # Extract all script sources
        js_urls, inline_scripts = self._extract_scripts(html_body, target)

        # Test 1: Missing SRI on CDN scripts
        sri_findings = self._check_missing_sri(html_body, target)
        findings.extend(sri_findings)

        # Test 2: Mixed content (HTTP scripts on HTTPS page)
        if target.startswith("https"):
            mixed_findings = self._check_mixed_content(html_body)
            findings.extend(mixed_findings)

        # Test 3: Secrets in JS files
        all_js = "\n".join(inline_scripts)
        for js_url in js_urls[:20]:
            try:
                js_response = await self.http.get(js_url, retries=1)
                all_js += "\n" + js_response.text()
            except Exception:
                continue

        secret_findings = self._scan_for_secrets(all_js, target)
        findings.extend(secret_findings)

        # Test 4: Outdated libraries
        lib_findings = self._detect_outdated_libraries(all_js + html_body)
        findings.extend(lib_findings)

        return findings

    def _extract_scripts(
        self, html: str, target: str
    ) -> tuple[list[str], list[str]]:
        js_urls: list[str] = []
        inline_scripts: list[str] = []

        # External scripts
        for match in re.finditer(
            r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I
        ):
            src = match.group(1)
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = target + src
            elif not src.startswith("http"):
                src = target + "/" + src
            js_urls.append(src)

        # Inline scripts
        for match in re.finditer(
            r"<script[^>]*>(.*?)</script>", html, re.I | re.S
        ):
            content = match.group(1).strip()
            if content:
                inline_scripts.append(content)

        return js_urls, inline_scripts

    def _check_missing_sri(
        self, html: str, target: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        no_sri_scripts: list[str] = []

        for match in re.finditer(
            r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', html, re.I
        ):
            tag = match.group(0)
            src = match.group(1)
            # Only check external CDN scripts (not same-origin)
            if ("cdn" in src.lower() or "unpkg" in src.lower()
                or "jsdelivr" in src.lower() or "cdnjs" in src.lower()
                or "cloudflare" in src.lower()):
                if "integrity=" not in tag.lower():
                    no_sri_scripts.append(src)

        if no_sri_scripts:
            findings.append({
                "id": "SC-MISSING-SRI",
                "title": "CDN Scripts Missing Subresource Integrity (SRI)",
                "severity": "medium",
                "confidence": "high",
                "category": "supply-chain",
                "target": target,
                "evidence": (
                    f"{len(no_sri_scripts)} CDN script(s) loaded without SRI:\n" +
                    "\n".join(f"  - {s}" for s in no_sri_scripts[:10])
                ),
                "recommendation": (
                    "Add integrity= and crossorigin= attributes to all "
                    "third-party script tags. Use tools like srihash.org "
                    "to generate hashes."
                ),
            })
        return findings

    def _check_mixed_content(self, html: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        http_scripts: list[str] = []

        for match in re.finditer(
            r'<script[^>]+src=["\'](http://[^"\']+)["\']', html, re.I
        ):
            http_scripts.append(match.group(1))

        if http_scripts:
            findings.append({
                "id": "SC-MIXED-CONTENT",
                "title": "Third-Party Scripts Loaded Over HTTP (Mixed Content)",
                "severity": "high",
                "confidence": "high",
                "category": "supply-chain",
                "target": "",
                "evidence": (
                    f"{len(http_scripts)} script(s) loaded over HTTP:\n" +
                    "\n".join(f"  - {s}" for s in http_scripts[:10])
                ),
                "recommendation": (
                    "Load all scripts over HTTPS. Use protocol-relative "
                    "URLs or explicit HTTPS."
                ),
            })
        return findings

    def _scan_for_secrets(
        self, js_content: str, target: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        found_types: set[str] = set()

        for pattern, secret_type in _SECRET_PATTERNS:
            if secret_type in found_types:
                continue
            matches = pattern.findall(js_content)
            if matches:
                # Filter out common false positives
                real_matches = [
                    m for m in matches
                    if not self._is_false_positive(m, secret_type)
                ]
                if real_matches:
                    found_types.add(secret_type)
                    is_public_id = secret_type == "Google Public API Key"
                    findings.append({
                        "id": f"SC-SECRET-{secret_type.upper().replace(' ', '-')}",
                        "title": f"{secret_type} Exposed in JavaScript" if is_public_id else f"Hardcoded {secret_type} Exposed in JavaScript",
                        "severity": "low" if is_public_id else ("high" if "live" in secret_type.lower() or "AWS" in secret_type else "medium"),
                        "confidence": "high" if secret_type in ("AWS Access Key ID", "Stripe Live Secret Key", "GitHub Personal Token", "Google Public API Key") else "medium",
                        "category": "supply-chain",
                        "target": target,
                        "evidence": (
                            f"Found {len(real_matches)} potential {secret_type}(s) "
                            f"in JavaScript source code.\n"
                            f"Sample (redacted): {self._redact(str(real_matches[0]))}"
                        ),
                        "recommendation": (
                            "Verify that this public client API key is restricted to authorized "
                            "HTTP referrers, origins, and API scopes in its cloud provider console."
                            if is_public_id
                            else (
                                "Remove all secrets from client-side JavaScript. "
                                "Use environment variables and server-side proxy "
                                "endpoints instead. Rotate exposed credentials "
                                "immediately."
                            )
                        ),
                    })
        return findings

    def _detect_outdated_libraries(
        self, content: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for lib_name, pattern in _KNOWN_LIBRARIES.items():
            match = pattern.search(content)
            if match:
                version = match.group(1) if match.lastindex else match.group(0)
                # Validation: version must have digits and not be just punctuation or short invalid string
                if not version or not any(c.isdigit() for c in version) or version.strip(".") == "":
                    continue
                findings.append({
                    "id": f"SC-LIBRARY-{lib_name.upper().replace('.', '')}",
                    "title": f"Third-Party Library Detected: {lib_name} {version}",
                    "severity": "info",
                    "confidence": "high",
                    "category": "supply-chain",
                    "target": "",
                    "evidence": (
                        f"Detected {lib_name} version {version}. "
                        f"Check for known CVEs for this version."
                    ),
                    "recommendation": (
                        f"Verify {lib_name} {version} against known "
                        f"vulnerabilities. Update to the latest stable version."
                    ),
                })
        return findings

    @staticmethod
    def _is_false_positive(match: str, secret_type: str) -> bool:
        if isinstance(match, str):
            lower = match.lower()
            if lower in ("undefined", "null", "true", "false", "none",
                          "placeholder", "example", "your_api_key",
                          "insert_key_here", "xxx"):
                return True
            if len(match) < 8:
                return True
        return False

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) <= 8:
            return "****"
        return value[:4] + "****" + value[-4:]
