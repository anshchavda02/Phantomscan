"""SQL Injection Detector with mandatory baseline differential verification.

Implements five verification layers before any SQLi finding is accepted:

1. **Mandatory baseline capture** — original value + benign variant
2. **Error-based detection** — vendor-exact signatures with baseline differential
3. **WAF block exclusion** — via :mod:`waf_detector`
4. **Time-based blind** — 3-sample statistical baseline, 2 independent reproductions
5. **Boolean differential verification** — TRUE/FALSE condition final gate

This module is registered in the advanced module registry and replaces the
time-based blind SQLi logic previously in :class:`OOBDetector`.
"""

from __future__ import annotations

import asyncio
import logging
import random
import statistics
import string
import time
from typing import Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from phantomscan.http_client import RobustHTTPClient
from phantomscan.modules.db_error_signatures import ErrorMatch, find_signature
from phantomscan.modules.waf_detector import is_waf_block_page, classify_waf_response

logger = logging.getLogger(__name__)


# ── Payload sets ──────────────────────────────────────────────────────────────

ERROR_BASED_PAYLOADS: list[str] = [
    "' OR ''='",
    "1' AND '1'='1",
    "'; SELECT 1-- ",
    "' UNION SELECT NULL-- ",
    "1 OR 1=1",
    "' OR 'x'='x",
    "1' ORDER BY 100-- ",
    "') OR ('1'='1",
]

TIME_BASED_PAYLOADS: list[str] = [
    "' AND SLEEP(5)-- -",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
    "1; WAITFOR DELAY '0:0:5'-- ",
    "') AND SLEEP(5)-- -",
]

BOOLEAN_TRUE_PAYLOADS: list[str] = [
    "' OR '1'='1",
    "1 OR 1=1",
]

BOOLEAN_FALSE_PAYLOADS: list[str] = [
    "' AND '1'='2",
    "1 AND 1=2",
]


# ── Response fingerprinting ──────────────────────────────────────────────────


class ResponseFingerprint:
    """Lightweight fingerprint of an HTTP response for differential comparison."""

    def __init__(self, status: int, body: str, headers: dict[str, str]) -> None:
        self.status = status
        self.body_length = len(body)
        self.body = body
        self.headers = headers
        self.error_signatures: set[str] = set()

        # Extract any DB error signatures present
        match = find_signature(body)
        while match:
            self.error_signatures.add(match.signature)
            # Remove matched text and keep scanning for additional signatures
            remaining = body[body.find(match.matched_text) + len(match.matched_text):]
            match = find_signature(remaining) if remaining else None


# ── SQLi Detector ─────────────────────────────────────────────────────────────


class SQLiDetector:
    """Advanced SQL injection detector with multi-layer verification."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http
        self._fp_log: list[dict[str, Any]] = []

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Entry point for the module orchestrator."""
        findings: list[dict[str, Any]] = []
        target = base_url.rstrip("/")

        params = self._extract_params(observations, target)
        for param_info in params[:15]:  # Cap to avoid excessive requests
            url = param_info.get("url", target)
            param_name = param_info.get("name", "q")
            original_value = param_info.get("original_value", "test")

            # Error-based detection
            error_finding = await self._test_error_based(
                url, param_name, original_value
            )
            if error_finding:
                # Final boolean differential verification
                if await self._verify_boolean_differential(url, param_name):
                    findings.append(error_finding)
                else:
                    self._log_fp_suppression(
                        error_finding,
                        "Failed boolean differential verification — "
                        "TRUE/FALSE responses are nearly identical",
                    )

            # Time-based blind detection
            time_finding = await self._test_time_based(
                url, param_name, original_value
            )
            if time_finding:
                findings.append(time_finding)

        return findings

    # ── Error-Based Detection ─────────────────────────────────────────────────

    async def _test_error_based(
        self, url: str, param: str, original_value: str
    ) -> Optional[dict[str, Any]]:
        """Test for error-based SQL injection with mandatory baseline comparison."""

        # Step 1: Capture baseline with ORIGINAL unmodified value
        baseline_resp = await self._send_request(url, param, original_value)
        if baseline_resp is None:
            return None
        baseline_fp = ResponseFingerprint(
            baseline_resp["status"], baseline_resp["body"], baseline_resp["headers"]
        )

        # Step 2: Capture baseline with a benign "different but valid" value
        benign_value = self._generate_benign_variant(original_value)
        benign_resp = await self._send_request(url, param, benign_value)
        if benign_resp is None:
            return None
        benign_fp = ResponseFingerprint(
            benign_resp["status"], benign_resp["body"], benign_resp["headers"]
        )

        # Step 3: Test each error-based payload
        for payload in ERROR_BASED_PAYLOADS:
            response = await self._send_request(url, param, payload)
            if response is None:
                continue

            # Check for WAF block page FIRST
            if is_waf_block_page(response["body"], response["status"]):
                waf_name = classify_waf_response(response["body"])
                logger.debug(
                    "Response is a WAF block page (%s), not a database error — "
                    "payload was BLOCKED, not that injection succeeded. "
                    "Param=%s, Payload=%s",
                    waf_name or "unknown WAF",
                    param,
                    payload,
                )
                continue

            # Check for vendor-exact DB error signature
            error_match = find_signature(response["body"])
            if not error_match:
                continue

            # CRITICAL: Was this error already present in baseline/benign?
            if (
                error_match.signature in baseline_fp.error_signatures
                or error_match.signature in benign_fp.error_signatures
            ):
                logger.debug(
                    "SQLi signature '%s' already present in baseline response — "
                    "not caused by payload, skipping. Param=%s",
                    error_match.signature,
                    param,
                )
                continue

            # Confirmed: error appears ONLY after malicious payload
            return {
                "id": "SQLI-ERROR-BASED",
                "title": f"SQL Injection (Error-Based): Parameter '{param}'",
                "severity": "critical",
                "confidence": "high",
                "category": "injection",
                "target": url,
                "verification_method": "baseline_differential",
                "evidence": (
                    f"Parameter: {param}\n"
                    f"Payload: {payload}\n"
                    f"Database type: {error_match.db_type}\n"
                    f"Error signature: \"{error_match.matched_text[:200]}\"\n"
                    f"Baseline response (original value): no error signature\n"
                    f"Benign probe response: no error signature\n"
                    f"Payload response: {error_match.db_type} error detected"
                ),
                "recommendation": (
                    "Use parameterized queries / prepared statements. "
                    "Never concatenate user input into SQL. CWE-89, "
                    "OWASP A03:2021."
                ),
                "references": ["https://cwe.mitre.org/data/definitions/89.html"],
            }

        return None

    # ── Time-Based Blind Detection ────────────────────────────────────────────

    async def _test_time_based(
        self, url: str, param: str, original_value: str
    ) -> Optional[dict[str, Any]]:
        """Test for time-based blind SQL injection with statistical baseline."""

        # Take 3 baseline timing samples to establish normal variance
        baseline_times: list[float] = []
        for _ in range(3):
            t0 = time.perf_counter()
            resp = await self._send_request(url, param, original_value)
            elapsed = time.perf_counter() - t0
            if resp is not None:
                baseline_times.append(elapsed)
            await asyncio.sleep(0.3)

        if len(baseline_times) < 2:
            logger.debug(
                "Could not establish baseline for time-based SQLi on %s param=%s",
                url, param,
            )
            return None

        baseline_avg = statistics.mean(baseline_times)
        baseline_stdev = (
            statistics.stdev(baseline_times) if len(baseline_times) > 2 else 0.5
        )

        # Test time-based payloads — require 2 independent reproductions
        for payload in TIME_BASED_PAYLOADS:
            confirmations = 0
            attempt_details: list[str] = []

            for attempt in range(2):
                t0 = time.perf_counter()
                resp = await self._send_request(
                    url, param, payload, timeout_seconds=15
                )
                elapsed = time.perf_counter() - t0

                # If the request failed (timeout, connection error, etc.),
                # do NOT count it as evidence of SQL injection delay.
                # A network timeout is an error, not proof of SLEEP() execution.
                if resp is None:
                    attempt_details.append(
                        f"Attempt {attempt + 1}: {elapsed:.2f}s "
                        f"— FAILED (timeout/error, not counted)"
                    )
                    await asyncio.sleep(1)
                    continue

                # Require response to take at least baseline_avg + 4.5s
                # plus 2 standard deviations of baseline variance
                expected_min = baseline_avg + 4.5 + (baseline_stdev * 2)

                if elapsed >= expected_min:
                    confirmations += 1
                    attempt_details.append(
                        f"Attempt {attempt + 1}: {elapsed:.2f}s "
                        f"(threshold: {expected_min:.2f}s) — DELAYED"
                    )
                else:
                    attempt_details.append(
                        f"Attempt {attempt + 1}: {elapsed:.2f}s "
                        f"(threshold: {expected_min:.2f}s) — normal"
                    )

                await asyncio.sleep(1)  # let target recover

            # Require BOTH attempts to independently reproduce
            if confirmations >= 2:
                return {
                    "id": "BLIND-SQLI-TIME",
                    "title": f"Blind SQL Injection (Time-Based): Parameter '{param}'",
                    "severity": "critical",
                    "confidence": "high",
                    "category": "injection",
                    "target": url,
                    "verification_method": "active_confirmation",
                    "evidence": (
                        f"Parameter: {param}\n"
                        f"Payload: {payload}\n"
                        f"Baseline avg: {baseline_avg:.2f}s "
                        f"(stdev: {baseline_stdev:.2f}s, n={len(baseline_times)})\n"
                        + "\n".join(attempt_details)
                    ),
                    "recommendation": (
                        "Use parameterized queries / prepared statements. "
                        "Never concatenate user input into SQL. CWE-89, "
                        "OWASP A03:2021."
                    ),
                    "references": [
                        "https://cwe.mitre.org/data/definitions/89.html",
                    ],
                }

        return None

    # ── Boolean Differential Verification ─────────────────────────────────────

    async def _verify_boolean_differential(
        self, url: str, param: str
    ) -> bool:
        """Final verification: TRUE and FALSE conditions must produce different responses."""
        for true_payload, false_payload in zip(
            BOOLEAN_TRUE_PAYLOADS, BOOLEAN_FALSE_PAYLOADS
        ):
            true_resp = await self._send_request(url, param, true_payload)
            false_resp = await self._send_request(url, param, false_payload)

            if true_resp is None or false_resp is None:
                continue

            length_diff = abs(len(true_resp["body"]) - len(false_resp["body"]))
            status_differs = true_resp["status"] != false_resp["status"]

            if length_diff >= 20 or status_differs:
                logger.debug(
                    "Boolean differential confirmed for %s param=%s: "
                    "length_diff=%d, status_differs=%s",
                    url, param, length_diff, status_differs,
                )
                return True

        logger.info(
            "SQLi candidate for '%s' failed boolean differential verification — "
            "TRUE/FALSE responses are nearly identical. Suppressing.",
            param,
        )
        return False

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    async def _send_request(
        self,
        url: str,
        param: str,
        value: str,
        timeout_seconds: float = 10,
    ) -> Optional[dict[str, Any]]:
        """Send a GET request with param=value and return a response dict."""
        import aiohttp as _aiohttp

        try:
            result = await self.http.get(
                url,
                params={param: value},
                retries=1,
                timeout=_aiohttp.ClientTimeout(total=timeout_seconds),
            )
            return {
                "status": result.status,
                "body": result.text(),
                "headers": result.headers,
            }
        except Exception as exc:
            logger.debug("SQLi probe failed for %s?%s=...: %s", url, param, exc)
            return None

    @staticmethod
    def _generate_benign_variant(original: str) -> str:
        """Generate a benign, different-but-valid-looking value."""
        if original.isdigit():
            # For numeric values, return a different valid number
            return str(int(original) + random.randint(1, 100))
        # For string values, append random alphanumeric suffix
        suffix = "".join(random.choices(string.ascii_lowercase, k=4))
        return f"{original}{suffix}"

    @staticmethod
    def _extract_params(
        observations: list[dict[str, Any]], target: str
    ) -> list[dict[str, Any]]:
        """Extract injectable parameters from scan observations and discovered API routes."""
        params: list[dict[str, Any]] = []
        seen_keys: set[tuple[str, str]] = set()

        def add_param(url: str, name: str, original_val: str = "test") -> None:
            key = (url, name)
            if key not in seen_keys and len(params) < 40:
                seen_keys.add(key)
                params.append({"url": url, "name": name, "original_value": original_val})

        for obs in observations:
            name = str(obs.get("name", ""))
            val = obs.get("value", "")

            # 1. Direct URLs with query parameters
            if ("http_url" in name or "discovered_urls" in name) and isinstance(val, (str, list)):
                url_list = [val] if isinstance(val, str) else val
                for u in url_list:
                    if isinstance(u, str) and u.startswith("http"):
                        parsed = urlparse(u)
                        clean_url = urlunparse(parsed._replace(query=""))
                        qs = parse_qs(parsed.query)
                        for pname, pvalues in qs.items():
                            add_param(clean_url, pname, pvalues[0] if pvalues else "test")
                        # For search/filter/lookup endpoints, test standard parameters
                        if any(kw in parsed.path.lower() for kw in ["search", "product", "user", "order", "item", "query", "filter"]):
                            for p in ("q", "search", "id", "query", "name"):
                                add_param(clean_url, p, "test")

            # 2. Discovered API routes (from JS bundles)
            if "discovered_api_routes" in name and isinstance(val, list):
                for route in val:
                    if isinstance(route, str) and not route.startswith("#"):
                        full_url = f"{target.rstrip('/')}{route}"
                        if any(kw in route.lower() for kw in ["search", "product", "user", "order", "item", "filter", "find"]):
                            for p in ("q", "search", "id", "query"):
                                add_param(full_url, p, "test")

            # 3. OpenAPI endpoints
            if "openapi_endpoints" in name and isinstance(val, list):
                for ep in val:
                    if isinstance(ep, dict) and "url" in ep:
                        ep_url = ep["url"]
                        for param_info in ep.get("parameters", []):
                            if isinstance(param_info, dict) and "name" in param_info:
                                add_param(ep_url, param_info["name"], "test")

        if not params:
            # Fallback tests on base URL and common search routes
            add_param(target, "q", "test")
            add_param(f"{target.rstrip('/')}/rest/products/search", "q", "apple")
            add_param(f"{target.rstrip('/')}/api/products/search", "q", "apple")
            add_param(f"{target.rstrip('/')}/search", "q", "test")

        return params


    def _log_fp_suppression(
        self, candidate: dict[str, Any], reason: str
    ) -> None:
        """Record a suppressed false-positive candidate."""
        self._fp_log.append({
            "suppressed_finding": candidate.get("title", ""),
            "reason": reason,
            "target": candidate.get("target", ""),
        })
        logger.info(
            "FP suppressed: %s — %s", candidate.get("title", ""), reason
        )
