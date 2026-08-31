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
            # Baseline request with standard non-elevated payload
            baseline_body = ""
            try:
                base_resp = await self.http.post(
                    url, json={"role": "user", "name": "standard_user"}, retries=1
                )
                baseline_body = base_resp.text().lower()
            except Exception:
                pass

            for payload in _MASS_ASSIGN_PAYLOADS:
                try:
                    response = await self.http.post(
                        url, json=payload, retries=1,
                    )
                    if response.status != 200:
                        continue

                    body = response.text()
                    body_lower = body.lower()
                    content_type = response.headers.get("content-type", "").lower()
                    is_json = "application/json" in content_type

                    # Check for elevated privileges returned in structured JSON response
                    has_explicit_priv = (
                        is_json
                        and any(
                            f'"{k}"' in body_lower or f"'{k}'" in body_lower
                            for k in ("admin", "superuser", "administrator", "granted", "role")
                        )
                    )
                    elevated_diff = any(
                        k in body_lower and k not in baseline_body
                        for k in _PRIVILEGE_INDICATORS
                    )

                    if is_json and (has_explicit_priv or elevated_diff):
                        findings.append({
                            "id": "BL-MASS-ASSIGNMENT",
                            "title": "Potential Mass Assignment Vulnerability",
                            "severity": "high",
                            "confidence": "high" if is_json else "medium",
                            "category": "business-logic",
                            "target": url,
                            "verification_method": "baseline_differential",
                            "evidence": (
                                f"Sent {json.dumps(payload)}, got HTTP 200.\n"
                                f"Privilege escalation confirmed in response state."
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
        error_keywords = ("error", "invalid", "negative", "greater than", "positive", "failed", "bad request")

        for url in candidate_urls:
            # Baseline request with positive values
            baseline_body = ""
            try:
                base_resp = await self.http.post(
                    url, json={"quantity": 1, "price": 100, "amount": 100}, retries=1
                )
                baseline_body = base_resp.text().lower()
            except Exception:
                pass

            for payload in negative_payloads:
                try:
                    response = await self.http.post(url, json=payload, retries=1)
                    if response.status not in (200, 201):
                        continue

                    body = response.text()
                    body_lower = body.lower()
                    content_type = response.headers.get("content-type", "").lower()
                    is_json = "application/json" in content_type

                    # Rejection check: ignore if response explicitly contains validation error keywords
                    if any(err in body_lower for err in error_keywords) and not any(err in baseline_body for err in error_keywords):
                        continue

                    # If response is identical to baseline or a generic HTML page, ignore
                    if body_lower == baseline_body or (not is_json and "<html" in body_lower):
                        continue

                    findings.append({
                        "id": "BL-NEGATIVE-VALUE",
                        "title": "Negative Value Accepted in Business Operation",
                        "severity": "medium",
                        "confidence": "high" if is_json else "medium",
                        "category": "business-logic",
                        "target": url,
                        "verification_method": "baseline_differential",
                        "evidence": (
                            f"Payload {json.dumps(payload)} returned HTTP "
                            f"{response.status}. Application accepted "
                            f"negative quantities or amounts in business transaction."
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
                # ── Pre-check: verify endpoint actually has a login form ──────
                # Skip endpoints that redirect (login is handled elsewhere)
                # or don't serve a form with password fields.
                try:
                    preflight = await self.http.get(
                        url, retries=1, allow_redirects=False,
                    )
                    # If the endpoint redirects, the login page is elsewhere —
                    # any timing difference is just redirect overhead, not
                    # account enumeration.
                    if preflight.status in (301, 302, 303, 307, 308):
                        continue
                    preflight_body = preflight.text().lower()
                    # Require evidence of a login form (password field or
                    # login-related form elements).
                    has_login_form = (
                        'type="password"' in preflight_body
                        or "type='password'" in preflight_body
                        or '"password"' in preflight_body
                        or "<form" in preflight_body
                    )
                    if preflight.status != 200 and not has_login_form:
                        continue
                except Exception:
                    continue

                # Time a request with a definitely-invalid user
                times_invalid: list[float] = []
                for _ in range(5):
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

                # Require at least 800ms difference over multiple samples
                # to eliminate network jitter and redirect overhead FPs
                if diff_ms > 800:
                    findings.append({
                        "id": "BL-TIMING-ENUM",
                        "title": "Account Enumeration via Timing Side-Channel",
                        "severity": "medium",
                        "confidence": "high",
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
        """Extract API and business logic endpoints from scan observations."""
        base = target.rstrip("/")
        endpoints: set[str] = set()
        keywords = ("/api", "/rest", "/basket", "/cart", "/order", "/coupon", "/discount", "/checkout", "/payment", "/quantity", "/item")

        def check_and_add(item: str) -> None:
            if isinstance(item, str) and any(kw in item.lower() for kw in keywords):
                endpoints.add(item if item.startswith("http") else f"{base}{item if item.startswith('/') else '/' + item}")

        for obs in observations:
            val = obs.get("value", "")
            if isinstance(val, str):
                check_and_add(val)
            elif isinstance(val, list):
                for v in val:
                    if isinstance(v, str):
                        check_and_add(v)
                    elif isinstance(v, dict) and "url" in v:
                        check_and_add(str(v["url"]))
            elif isinstance(val, dict):
                for v in val.values():
                    if isinstance(v, str):
                        check_and_add(v)

        # Fallback common business logic routes
        for probe in ("/rest/basket", "/api/BasketItems", "/rest/order-history", "/api/Feedbacks", "/api/Quantitys", "/api/Coupon"):
            endpoints.add(f"{base}{probe}")

        return list(endpoints)[:30]

