"""Module 8 — SSRF Comprehensive Detector.

Tests for direct SSRF (cloud metadata), blind SSRF (OOB), and SSRF bypass
techniques including octal/decimal IP encoding and DNS rebinding hints.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from phantomscan.http_client import RobustHTTPClient
from phantomscan.oob import oob_listener

logger = logging.getLogger(__name__)

CLOUD_METADATA_URLS = [
    ("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/", {}),
    ("AWS IMDSv1 Creds",
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/", {}),
    ("GCP", "http://metadata.google.internal/computeMetadata/v1/",
     {"Metadata-Flavor": "Google"}),
    ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     {"Metadata": "true"}),
    ("DigitalOcean", "http://169.254.169.254/metadata/v1/", {}),
]

SSRF_BYPASS_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    "http://0177.0.0.1",          # octal
    "http://2130706433",           # decimal
    "http://127.1",
    "http://0x7f.0x0.0x0.0x1",    # hex
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
]

_URL_PARAM_NAMES = frozenset({
    "url", "uri", "href", "src", "source", "redirect", "next",
    "return", "target", "dest", "destination", "link", "file",
    "path", "page", "feed", "fetch", "endpoint", "callback",
    "load", "host", "domain", "proxy", "site", "img", "image",
})

_METADATA_SIGNALS = {
    "AWS": ["ami-id", "instance-id", "security-credentials", "iam/security-credentials"],
    "GCP": ["computemetadata", "project-id", "instance/zone", "service-accounts"],
    "Azure": ["compute/vmid", "subscriptionid", "resourcegroupname"],
    "DigitalOcean": ["droplet_id", "droplet_v2"],
}


class SSRFDetector:
    """Detect SSRF vulnerabilities including cloud metadata exposure."""

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
        url_params = self._find_url_params(target, observations)

        # Get baseline response for target page to avoid false positive matches on standard HTML
        baseline_body = ""
        try:
            res = await self.http.get(target, retries=1)
            baseline_body = res.text().lower()
        except Exception:
            pass

        for param_info in url_params[:15]:
            url = param_info["url"]
            param = param_info["name"]

            # Test 1: Cloud metadata via SSRF
            meta_findings = await self._test_cloud_metadata(url, param, baseline_body)
            findings.extend(meta_findings)

            # Test 2: SSRF bypass techniques
            bypass_findings = await self._test_ssrf_bypass(url, param, baseline_body)
            findings.extend(bypass_findings)

            # Test 3: Blind SSRF via OOB
            oob_findings = await self._test_blind_ssrf(url, param)
            findings.extend(oob_findings)

        return findings

    async def _test_cloud_metadata(
        self, url: str, param: str, baseline_body: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for provider, meta_url, extra_headers in CLOUD_METADATA_URLS:
            try:
                response = await self.http.get(
                    url, params={param: meta_url},
                    headers=extra_headers, retries=1,
                )
                body = response.text()
                # Ignore if response status is not 200, or if response is identical to target homepage
                if response.status == 200 and self._contains_metadata(body, provider, baseline_body):
                    findings.append({
                        "id": f"SSRF-CLOUD-{provider.split()[0].upper()}",
                        "title": f"SSRF — {provider} Cloud Metadata Exposed",
                        "severity": "critical",
                        "confidence": "high",
                        "category": "ssrf",
                        "target": url,
                        "evidence": (
                            f"Parameter: {param}\n"
                            f"Metadata URL: {meta_url}\n"
                            f"Response preview: {body[:500]}"
                        ),
                        "recommendation": (
                            f"Block SSRF access to cloud metadata services. "
                            f"For AWS, enforce IMDSv2 (require token). "
                            f"Validate and allowlist all user-supplied URLs. "
                            f"CWE-918, OWASP A10:2021."
                        ),
                        "references": [
                            "https://cwe.mitre.org/data/definitions/918.html",
                            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                        ],
                    })
                    return findings  # one cloud metadata finding is sufficient
            except Exception:
                continue
        return findings

    async def _test_ssrf_bypass(
        self, url: str, param: str, baseline_body: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for bypass_url in SSRF_BYPASS_PAYLOADS:
            try:
                response = await self.http.get(
                    url, params={param: bypass_url},
                    retries=1,
                )
                body = response.text()
                body_lower = body.lower()
                # Check for explicit internal service markers not present in baseline
                if (
                    response.status == 200
                    and len(body) > 50
                    and ("<!doctype html>" not in body_lower or "<title>google" not in body_lower)
                    and body_lower != baseline_body
                    and any(sig in body_lower for sig in ["root:x:0:0", "internal server status", "apache2 ubuntu default page", "welcome to nginx on localhost"])
                ):
                    findings.append({
                        "id": "SSRF-BYPASS-INTERNAL",
                        "title": "SSRF Bypass — Internal Service Accessible",
                        "severity": "high",
                        "confidence": "medium",
                        "category": "ssrf",
                        "target": url,
                        "evidence": (
                            f"Parameter: {param}\n"
                            f"Bypass URL: {bypass_url}\n"
                            f"Response: HTTP {response.status} "
                            f"({len(response.body)} bytes). "
                            f"Internal service content detected."
                        ),
                        "recommendation": (
                            "Implement strict URL validation with allowlists. "
                            "Block all private IP ranges including alternative "
                            "encodings (octal, decimal, hex). CWE-918."
                        ),
                        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
                    })
                    return findings
            except Exception:
                continue
        return findings

    async def _test_blind_ssrf(
        self, url: str, param: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not oob_listener.is_running:
            try:
                oob_listener.start()
            except Exception:
                return findings

        uid, callback_url = oob_listener.generate_payload_url()
        try:
            await self.http.get(url, params={param: callback_url}, retries=1)
        except Exception:
            pass

        await asyncio.sleep(0.5)

        if oob_listener.check_hit(uid):
            findings.append({
                "id": "SSRF-BLIND-OOB",
                "title": "Blind SSRF Confirmed",
                "severity": "high",
                "confidence": "high",
                "category": "ssrf",
                "target": url,
                "evidence": (
                    f"Parameter: {param}\n"
                    f"OOB callback received from target server."
                ),
                "recommendation": (
                    "Restrict outbound requests. Use URL allowlists. "
                    "Block private IP ranges and cloud metadata endpoints. "
                    "CWE-918."
                ),
                "references": ["https://cwe.mitre.org/data/definitions/918.html"],
            })
        return findings

    def _find_url_params(
        self, target: str, observations: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        params: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        def add_url_param(url: str, name: str) -> None:
            key = (url, name)
            if key not in seen and len(params) < 30:
                seen.add(key)
                params.append({"url": url, "name": name})

        for obs in observations:
            val = obs.get("value", "")
            if isinstance(val, str) and val.startswith("http"):
                for name in _URL_PARAM_NAMES:
                    add_url_param(val, name)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and item.startswith("http"):
                        for name in _URL_PARAM_NAMES:
                            add_url_param(item, name)
                    elif isinstance(item, dict) and "url" in item:
                        u = str(item["url"])
                        if u.startswith("http"):
                            for name in _URL_PARAM_NAMES:
                                add_url_param(u, name)

        # Common SSRF probe endpoints
        base = target.rstrip("/")
        for probe_path, param in [
            ("/rest/track-order", "id"),
            ("/api/track", "url"),
            ("/proxy", "url"),
            ("/fetch", "url"),
            ("/api/webhook", "url"),
        ]:
            add_url_param(f"{base}{probe_path}", param)

        return params


    @staticmethod
    def _contains_metadata(body: str, provider: str, baseline_body: str = "") -> bool:
        body_lower = body.lower()

        # Cloud metadata responses are plain text or JSON — NEVER full HTML
        # documents.  If the response contains HTML structure tags, the
        # matched "signal" is just the reflected payload URL in the page's
        # normal HTML output, not real metadata content.
        if any(tag in body_lower for tag in ("<html", "<!doctype html", "<head>", "<title>")):
            return False

        # If body matches baseline, it's just the normal page
        if baseline_body and body_lower == baseline_body:
            return False

        signals = _METADATA_SIGNALS.get(provider.split()[0], [])
        return any(s in body_lower for s in signals)
