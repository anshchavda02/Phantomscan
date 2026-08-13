"""Module 5 — Blind and Out-of-Band Detector.

Detects blind SSRF, time-based blind SQL injection, blind command injection,
and OOB XXE using PhantomScan's built-in OOB callback server.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from phantomscan.http_client import RobustHTTPClient
from phantomscan.oob import oob_listener

logger = logging.getLogger(__name__)

_BLIND_SQLI_PAYLOADS: list[str] = []  # Moved to sqli_detector.py


_BLIND_CMDI_PAYLOADS = [
    "; sleep 5",
    "| sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
    "& ping -n 6 127.0.0.1 &",
]

_URL_PARAM_NAMES = frozenset({
    "url", "uri", "href", "src", "source", "redirect", "next",
    "return", "target", "dest", "destination", "link", "file",
    "path", "page", "feed", "fetch", "endpoint", "callback",
    "load", "host", "domain", "proxy", "site",
})


class OOBDetector:
    """Detect blind vulnerabilities via timing and OOB callbacks."""

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

        # Start OOB listener if not already running
        if not oob_listener.is_running:
            try:
                oob_listener.start()
            except Exception as exc:
                logger.warning("OOB listener start failed: %s", exc)

        # Gather injectable parameters from observations
        params = self._extract_params(observations)

        # Run blind tests concurrently
        tasks = [
            self._test_blind_sqli(target, params),
            self._test_blind_ssrf(target, params),
            self._test_blind_cmdi(target, params),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.debug("OOB test error: %s", result)

        return findings

    # ── Blind SQL Injection (Time-Based) ─────────────────────────────────────
    # DEPRECATED: Moved to sqli_detector.SQLiDetector with proper multi-layer
    # verification (statistical baseline, 2x reproduction, boolean differential).

    async def _test_blind_sqli(
        self, target: str, params: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """No-op stub — blind SQLi detection moved to sqli_detector.py."""
        return []


    # ── Blind SSRF via OOB ───────────────────────────────────────────────────

    async def _test_blind_ssrf(
        self, target: str, params: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        url_params = [
            p for p in params
            if p.get("name", "").lower() in _URL_PARAM_NAMES
        ]

        for param_info in url_params[:10]:
            url = param_info.get("url", target)
            param_name = param_info.get("name", "url")
            uid, callback_url = oob_listener.generate_payload_url()

            try:
                await self.http.get(
                    url, params={param_name: callback_url},
                    retries=1,
                )
            except Exception:
                pass

            # Also try POST
            try:
                await self.http.post(
                    url, json={param_name: callback_url},
                    retries=1,
                )
            except Exception:
                pass

            hit = False
            for _ in range(10):
                await asyncio.sleep(0.5)
                if oob_listener.check_hit(uid):
                    hit = True
                    break

            if hit:
                findings.append({
                    "id": "BLIND-SSRF-OOB",
                    "title": "Blind SSRF Confirmed via OOB Callback",
                    "severity": "high",
                    "confidence": "high",
                    "category": "ssrf",
                    "target": url,
                    "evidence": (
                        f"Parameter: {param_name}\n"
                        f"OOB callback URL: {callback_url}\n"
                        f"Server made outbound HTTP request to "
                        f"attacker-controlled endpoint."
                    ),
                    "recommendation": (
                        "Validate and restrict outbound URLs. Use allowlists "
                        "for permitted destinations. Block requests to internal "
                        "networks and cloud metadata. CWE-918."
                    ),
                    "references": ["https://cwe.mitre.org/data/definitions/918.html"],
                })
        return findings

    # ── Blind Command Injection ──────────────────────────────────────────────

    async def _test_blind_cmdi(
        self, target: str, params: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for param_info in params[:10]:
            url = param_info.get("url", target)
            param_name = param_info.get("name", "cmd")

            for payload in _BLIND_CMDI_PAYLOADS:
                try:
                    t0 = time.perf_counter()
                    await self.http.get(
                        url, params={param_name: payload},
                        retries=1,
                    )
                    elapsed = time.perf_counter() - t0

                    if elapsed >= 4.5:
                        findings.append({
                            "id": "BLIND-CMDI-TIME",
                            "title": "Blind Command Injection (Time-Based)",
                            "severity": "critical",
                            "confidence": "medium",
                            "category": "injection",
                            "target": url,
                            "evidence": (
                                f"Parameter: {param_name}\n"
                                f"Payload: {payload}\n"
                                f"Response delay: {elapsed:.2f}s "
                                f"(expected ~5s for sleep command)"
                            ),
                            "recommendation": (
                                "Never pass user input to OS commands. Use "
                                "language-specific APIs instead of shell execution. "
                                "CWE-78."
                            ),
                            "references": ["https://cwe.mitre.org/data/definitions/78.html"],
                        })
                        break
                except Exception:
                    continue
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_params(
        observations: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        params: list[dict[str, Any]] = []
        for obs in observations:
            name = str(obs.get("name", ""))
            val = obs.get("value", "")
            if "http_url" in name and isinstance(val, str):
                # Add common test parameter names for the URL
                for p in ("q", "search", "id", "page", "url", "file", "path",
                           "cmd", "input", "data", "query", "name"):
                    params.append({"url": val, "name": p})
        if not params:
            return [{"url": "", "name": "q"}]
        return params
