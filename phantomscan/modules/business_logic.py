"""Module 1 — Business Logic Analyzer.

Detects business-logic flaws that no automated scanner currently finds:
mass assignment, negative value acceptance, timing-based account enumeration,
and HTTP method tampering.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

# Privilege-escalation parameter payloads for mass-assignment testing
_MASS_ASSIGN_PAYLOADS: list[dict[str, Any]] = [
    {"role": "admin"},
    {"isAdmin": True},
    {"admin": 1},
    {"privilege": "superuser"},
    {"user_type": "administrator"},
    {"is_staff": True},
    {"permissions": ["admin"]},
    {"access_level": 9999},
]

_PRIVILEGE_INDICATORS = frozenset({
    "admin", "granted", "elevated", "superuser", "administrator",
    "is_staff", "role", "privilege",
})

_UNEXPECTED_METHODS = ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]


class BusinessLogicAnalyzer:
    """Detect business-logic vulnerabilities in web applications."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Execute all business-logic tests and return findings dicts."""
        findings: list[dict[str, Any]] = []
        target = base_url.rstrip("/")

        # Collect endpoints from observations
        endpoints = self._extract_endpoints(target, observations)

        tasks = [
            self._test_mass_assignment(target, endpoints),
            self._test_negative_values(target, endpoints),
            self._test_timing_enumeration(target),
            self._test_method_tampering(target, endpoints),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.debug("Business logic test error: %s", result)
        return findings

    # ── Mass Assignment ──────────────────────────────────────────────────────

    async def _test_mass_assignment(
        self, target: str, endpoints: list[str]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        test_urls = endpoints or [f"{target}/api/users", f"{target}/api/account",
                                   f"{target}/api/profile", f"{target}/api/register"]
        for url in test_urls:
            for payload in _MASS_ASSIGN_PAYLOADS:
                try:
                    response = await self.http.post(
                        url, json=payload, retries=1,
                    )
                    body = response.text()
                    if response.status == 200 and any(
                        k in body.lower() for k in _PRIVILEGE_INDICATORS
                    ):
                        findings.append({
                            "id": "BL-MASS-ASSIGNMENT",
                            "title": "Potential Mass Assignment Vulnerability",
                            "severity": "high",
                            "confidence": "medium",
                            "category": "business-logic",
                            "target": url,
                            "evidence": (
                                f"Sent {json.dumps(payload)}, got HTTP 200 "
                                f"with privilege indicators in response body"
                            ),
                            "recommendation": (
                                "Implement strict allowlists for request parameters. "
                                "Never bind user-supplied fields directly to internal "
                                "privilege attributes. CWE-915."
                            ),
                            "references": ["https://cwe.mitre.org/data/definitions/915.html"],
                        })
                        break  # one finding per endpoint is enough
                except Exception:
                    continue
        return findings

    # ── Negative Value Acceptance ─────────────────────────────────────────────

    async def _test_negative_values(
        self, target: str, endpoints: list[str]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        candidate_urls = endpoints or [
            f"{target}/api/cart", f"{target}/api/order",
            f"{target}/api/transfer", f"{target}/api/payment",
        ]
        negative_payloads = [
            {"quantity": -1, "price": 100},
            {"amount": -500},
            {"count": -10, "item": "test"},
        ]
        for url in candidate_urls:
            for payload in negative_payloads:
                try:
                    response = await self.http.post(url, json=payload, retries=1)
                    if response.status in (200, 201):
                        findings.append({
                            "id": "BL-NEGATIVE-VALUE",
                            "title": "Negative Value Accepted in Business Operation",
                            "severity": "medium",
                            "confidence": "medium",
                            "category": "business-logic",
                            "target": url,
                            "evidence": (
                                f"Payload {json.dumps(payload)} returned HTTP "
                                f"{response.status}. Application may allow "
                                f"negative quantities or amounts."
                            ),
                            "recommendation": (
                                "Validate that numeric inputs are within expected "
                                "ranges. Reject negative values for quantities, "
                                "amounts, and counts. CWE-840."
                            ),
                            "references": ["https://cwe.mitre.org/data/definitions/840.html"],
                        })
                        break
                except Exception:
                    continue
        return findings

    # ── Account Enumeration via Timing ────────────────────────────────────────

    async def _test_timing_enumeration(self, target: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        login_paths = ["/login", "/api/login", "/auth/login", "/api/auth/signin",
                       "/signin", "/api/v1/login"]
        for path in login_paths:
            url = f"{target}{path}"
            try:
                # Time a request with a definitely-invalid user
                times_invalid: list[float] = []
                for _ in range(3):
                    t0 = time.perf_counter()
                    await self.http.post(
                        url,
                        json={"username": "phantomscan_nonexistent_user_xz9q",
                              "password": "test123"},
                        retries=1,
                    )
                    times_invalid.append(time.perf_counter() - t0)

                # Time a request with common usernames (likely to exist)
                times_valid: list[float] = []
                for user in ("admin", "root", "user", "test"):
                    t0 = time.perf_counter()
                    await self.http.post(
                        url,
                        json={"username": user, "password": "wrong_password_xz9q"},
                        retries=1,
                    )
                    times_valid.append(time.perf_counter() - t0)

                avg_invalid = sum(times_invalid) / len(times_invalid)
                avg_valid = sum(times_valid) / len(times_valid)
                diff_ms = abs(avg_valid - avg_invalid) * 1000

                if diff_ms > 100:
                    findings.append({
                        "id": "BL-TIMING-ENUM",
                        "title": "Account Enumeration via Timing Side-Channel",
                        "severity": "medium",
                        "confidence": "medium",
                        "category": "business-logic",
                        "target": url,
                        "evidence": (
                            f"Average response for invalid users: "
                            f"{avg_invalid * 1000:.0f}ms. "
                            f"Average response for likely-valid users: "
                            f"{avg_valid * 1000:.0f}ms. "
                            f"Difference: {diff_ms:.0f}ms."
                        ),
                        "recommendation": (
                            "Ensure login response times are constant regardless "
                            "of whether the account exists. Use constant-time "
                            "comparison and dummy password hashing. CWE-203."
                        ),
                        "references": ["https://cwe.mitre.org/data/definitions/203.html"],
                    })
                    break  # one finding is enough
            except Exception:
                continue
        return findings

    # ── HTTP Method Tampering ─────────────────────────────────────────────────

    async def _test_method_tampering(
        self, target: str, endpoints: list[str]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        test_urls = endpoints[:10] or [target + "/"]
        for url in test_urls:
            try:
                baseline = await self.http.get(url, retries=1)
            except Exception:
                continue
            for method in _UNEXPECTED_METHODS:
                try:
                    response = await self.http.request(method, url, retries=1)
                    if (
                        response.status == 200
                        and method not in ("OPTIONS",)
                        and response.text() != baseline.text()
                        and len(response.text()) > 50
                    ):
                        findings.append({
                            "id": f"BL-METHOD-TAMPER-{method}",
                            "title": f"HTTP Method Tampering: {method} accepted",
                            "severity": "medium",
                            "confidence": "medium",
                            "category": "business-logic",
                            "target": url,
                            "evidence": (
                                f"{method} {url} returned HTTP {response.status} "
                                f"with {len(response.body)} bytes "
                                f"(differs from GET response)."
                            ),
                            "recommendation": (
                                "Restrict HTTP methods to only those required. "
                                "Return 405 for unexpected methods. CWE-650."
                            ),
                            "references": ["https://cwe.mitre.org/data/definitions/650.html"],
                        })
                except Exception:
                    continue
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_endpoints(
        self, target: str, observations: list[dict[str, Any]]
    ) -> list[str]:
        """Extract API-like endpoints from scan observations."""
        endpoints: list[str] = []
        for obs in observations:
            val = obs.get("value", "")
            if isinstance(val, str) and "/api" in val:
                endpoints.append(val if val.startswith("http") else f"{target}{val}")
            if isinstance(val, dict):
                for v in val.values():
                    if isinstance(v, str) and "/api" in v:
                        endpoints.append(
                            v if v.startswith("http") else f"{target}{v}"
                        )
        return endpoints[:20]
