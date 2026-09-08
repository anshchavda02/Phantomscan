"""CORS Misconfiguration Analyzer.

Detects CORS misconfigurations including wildcard origins, null origin trust,
and dynamic origin reflection allowing arbitrary external origins with credentials.
"""

from __future__ import annotations

import logging
from typing import Any

from phantomscan.models import Finding

logger = logging.getLogger(__name__)


class CORSAnalyzer:
    """Analyzer for Cross-Origin Resource Sharing (CORS) misconfigurations."""

    TEST_ORIGIN = "https://evil-phantomscan.com"

    def __init__(self, http: Any = None) -> None:
        self.http = http

    def analyze_headers(self, headers: dict[str, str], url: str = "") -> list[Finding]:
        """Passive analysis of CORS response headers."""
        findings: list[Finding] = []
        lowered = {k.lower(): str(v) for k, v in headers.items()}
        cors_origin = lowered.get("access-control-allow-origin", "").strip()
        cors_creds = lowered.get("access-control-allow-credentials", "false").strip().lower()

        if not cors_origin:
            return findings

        if cors_origin == "*":
            if cors_creds == "true":
                findings.append(Finding(
                    id="CORS-WILDCARD-WITH-CREDENTIALS",
                    title="CORS Wildcard with Credentials Enabled",
                    severity="high",
                    confidence="high",
                    verification_method="passive_observation",
                    category="web",
                    target=url,
                    evidence=f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: {cors_creds}",
                    recommendation="Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Use an explicit whitelist of trusted origins.",
                ))
            else:
                findings.append(Finding(
                    id="CORS-WILDCARD-ORIGIN",
                    title="CORS Wildcard Origin Advertised",
                    severity="low",
                    confidence="high",
                    verification_method="passive_observation",
                    category="web",
                    target=url,
                    evidence="Access-Control-Allow-Origin: *",
                    recommendation="Restrict Access-Control-Allow-Origin to trusted application domains if private data is served.",
                ))
        elif cors_origin.lower() == "null":
            findings.append(Finding(
                id="CORS-NULL-ORIGIN-ALLOWED",
                title="CORS Trusts 'null' Origin",
                severity="medium",
                confidence="high",
                verification_method="passive_observation",
                category="web",
                target=url,
                evidence=f"Access-Control-Allow-Origin: null\nAccess-Control-Allow-Credentials: {cors_creds}",
                recommendation="Do not allow origin 'null'. Attackers can exploit sandboxed iframes or local HTML files to access resources.",
            ))

        return findings

    async def test_origin_reflection(self, http_client: Any, url: str) -> list[Finding]:
        """Actively test if an arbitrary origin is reflected with or without credentials."""
        findings: list[Finding] = []
        if not http_client or not url:
            return findings

        try:
            res = await http_client.get(url, headers={"Origin": self.TEST_ORIGIN})
            if not res or getattr(res, "status", 0) >= 500:
                return findings

            headers = getattr(res, "headers", {})
            lowered = {k.lower(): str(v) for k, v in headers.items()}
            acao = lowered.get("access-control-allow-origin", "").strip()
            acac = lowered.get("access-control-allow-credentials", "false").strip().lower()

            if acao == self.TEST_ORIGIN:
                if acac == "true":
                    findings.append(Finding(
                        id="CORS-ARBITRARY-ORIGIN-WITH-CREDENTIALS",
                        title="Critical CORS Origin Reflection with Credentials",
                        severity="critical",
                        confidence="high",
                        verification_method="active_confirmation",
                        category="web",
                        target=url,
                        evidence=(
                            f"Sent Origin: {self.TEST_ORIGIN}\n"
                            f"Received Access-Control-Allow-Origin: {acao}\n"
                            f"Received Access-Control-Allow-Credentials: {acac}"
                        ),
                        recommendation="Validate Origin headers against an explicit, strict server-side whitelist. Never blindly reflect the Origin header when credentials are supported.",
                    ))
                else:
                    findings.append(Finding(
                        id="CORS-ARBITRARY-ORIGIN-REFLECTED",
                        title="Insecure CORS Arbitrary Origin Reflection",
                        severity="medium",
                        confidence="high",
                        verification_method="active_confirmation",
                        category="web",
                        target=url,
                        evidence=(
                            f"Sent Origin: {self.TEST_ORIGIN}\n"
                            f"Received Access-Control-Allow-Origin: {acao}"
                        ),
                        recommendation="Ensure the Origin header is validated against an allowed whitelist instead of being reflected.",
                    ))
        except Exception as exc:
            logger.debug("CORS active reflection test failed for %s: %s", url, exc)

        return findings

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """DAG pipeline execution method for CORS analysis."""
        findings: list[Finding] = []
        tested_urls: set[str] = set()

        # 1. Passive analysis from observations
        for obs in observations:
            name = obs.get("name", "")
            val = obs.get("value")
            if name in ("headers", "http_headers", "response_headers") and isinstance(val, dict):
                findings.extend(self.analyze_headers(val, url=base_url))

        # 2. Active origin reflection testing
        if self.http:
            targets_to_test = [base_url]
            for obs in observations:
                name = obs.get("name", "")
                val = obs.get("value")
                if name in ("discovered_urls", "api_endpoints") and isinstance(val, list):
                    for u in val:
                        if isinstance(u, str) and u.startswith("http") and u not in tested_urls:
                            targets_to_test.append(u)
                            if len(targets_to_test) >= 4:
                                break

            for u in targets_to_test:
                if u in tested_urls:
                    continue
                tested_urls.add(u)
                active_res = await self.test_origin_reflection(self.http, u)
                findings.extend(active_res)

        # Deduplicate findings by id + target
        deduped: dict[str, Finding] = {}
        for f in findings:
            key = f"{f.id}:{f.target}"
            if key not in deduped:
                deduped[key] = f

        return [f.to_dict() if hasattr(f, "to_dict") else f for f in deduped.values()]

