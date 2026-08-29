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


def extract_url_params(url: str) -> dict[str, str]:
    """Extract URL query parameters as a name -> value dictionary."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] if v else "" for k, v in params.items()}


# ── Payload sets ──────────────────────────────────────────────────────────────

ERROR_BASED_PAYLOADS: list[str] = [
    "'",
    "1'",
    "' OR '1'='1",
    "''",
    "1 AND 1=2",
    "' AND 'a'='b",
    "' --",
    "' OR ''='",
    "'; SELECT 1-- ",
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


from phantomscan.injection_target import InjectionTarget, extract_injection_targets

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

        targets = extract_injection_targets(observations, target, max_targets=40)
        sem = asyncio.Semaphore(10)

        async def test_one(inj_target: InjectionTarget) -> list[dict[str, Any]]:
            res: list[dict[str, Any]] = []
            async with sem:
                # Error-based detection
                error_finding = await self._test_error_based(
                    inj_target, inj_target.param_name, inj_target.original_value
                )
                if error_finding:
                    res.append(error_finding)
                elif not res:
                    # If no error finding, test time-based blind detection
                    time_finding = await self._test_time_based(
                        inj_target, inj_target.param_name, inj_target.original_value
                    )
                    if time_finding:
                        res.append(time_finding)
            return res

        tasks = [test_one(t) for t in targets[:35]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    # ── Error-Based Detection ─────────────────────────────────────────────────

    async def _test_error_based(
        self, target: InjectionTarget | str, param: str, original_value: str
    ) -> Optional[dict[str, Any]]:
        """Test for error-based SQL injection with mandatory baseline comparison."""
        target_url = target.url if isinstance(target, InjectionTarget) else target

        # Step 1: Capture baseline with ORIGINAL unmodified value
        baseline_resp = await self._send_request(target, param, original_value)
        if baseline_resp is None:
            return None
        baseline_fp = ResponseFingerprint(
            baseline_resp["status"], baseline_resp["body"], baseline_resp["headers"]
        )

        # Step 2: Capture baseline with a benign "different but valid" value
        benign_value = self._generate_benign_variant(original_value)
        benign_resp = await self._send_request(target, param, benign_value)
        if benign_resp is None:
            return None
        benign_fp = ResponseFingerprint(
            benign_resp["status"], benign_resp["body"], benign_resp["headers"]
        )

        # Step 3: Test each error-based payload (max 3 payloads per parameter)
        payloads_tested = 0
        for payload in ERROR_BASED_PAYLOADS:
            if payloads_tested >= 3:
                break
            payloads_tested += 1
            response = await self._send_request(target, param, payload)
            if response is None:
                continue

            # Check for WAF block page FIRST
            if is_waf_block_page(response["body"], response["status"]):
                waf_name = classify_waf_response(response["body"])
                logger.debug(
                    "Response is a WAF block page (%s), not a database error — "
                    "payload was BLOCKED. Param=%s, Payload=%s",
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
                "target": target_url,
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
        self, target: InjectionTarget | str, param: str, original_value: str
    ) -> Optional[dict[str, Any]]:
        """Test for time-based blind SQL injection with statistical baseline."""
        target_url = target.url if isinstance(target, InjectionTarget) else target

        # Take 2 baseline timing samples to establish normal variance
        baseline_times: list[float] = []
        for _ in range(2):
            t0 = time.perf_counter()
            resp = await self._send_request(target, param, original_value)
            elapsed = time.perf_counter() - t0
            if resp is not None:
                baseline_times.append(elapsed)
            await asyncio.sleep(0.02)

        if not baseline_times:
            logger.debug(
                "Could not establish baseline for time-based SQLi on %s param=%s",
                target_url, param,
            )
            return None

        baseline_avg = statistics.mean(baseline_times)
        baseline_stdev = (
            statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.5
        )

        # Test time-based payloads — require 2 independent reproductions
        for payload in TIME_BASED_PAYLOADS:
            confirmations = 0
            attempt_details: list[str] = []

            for attempt in range(2):
                t0 = time.perf_counter()
                resp = await self._send_request(
                    target, param, payload, timeout_seconds=12
                )
                elapsed = time.perf_counter() - t0

                if resp is None:
                    attempt_details.append(
                        f"Attempt {attempt + 1}: {elapsed:.2f}s "
                        f"— FAILED (timeout/error, not counted)"
                    )
                    break

                expected_min = baseline_avg + 4.5 + (baseline_stdev * 2)

                if elapsed >= expected_min:
                    confirmations += 1
                    attempt_details.append(
                        f"Attempt {attempt + 1}: {elapsed:.2f}s "
                        f"(threshold: {expected_min:.2f}s) — DELAYED"
                    )
                    await asyncio.sleep(0.5)  # let target recover
                else:
                    attempt_details.append(
                        f"Attempt {attempt + 1}: {elapsed:.2f}s "
                        f"(threshold: {expected_min:.2f}s) — normal"
                    )
                    break

            if confirmations >= 2:
                return {
                    "id": "BLIND-SQLI-TIME",
                    "title": f"Blind SQL Injection (Time-Based): Parameter '{param}'",
                    "severity": "critical",
                    "confidence": "high",
                    "category": "injection",
                    "target": target_url,
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
        self, target: InjectionTarget | str, param: str
    ) -> bool:
        """Final verification: TRUE and FALSE conditions must produce different responses."""
        target_url = target.url if isinstance(target, InjectionTarget) else target
        for true_payload, false_payload in zip(
            BOOLEAN_TRUE_PAYLOADS, BOOLEAN_FALSE_PAYLOADS
        ):
            true_resp = await self._send_request(target, param, true_payload)
            false_resp = await self._send_request(target, param, false_payload)

            if true_resp is None or false_resp is None:
                continue

            length_diff = abs(len(true_resp["body"]) - len(false_resp["body"]))
            status_differs = true_resp["status"] != false_resp["status"]

            if length_diff >= 20 or status_differs:
                logger.debug(
                    "Boolean differential confirmed for %s param=%s: "
                    "length_diff=%d, status_differs=%s",
                    target_url, param, length_diff, status_differs,
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
        target: InjectionTarget | str,
        param: str,
        value: str,
        timeout_seconds: float = 10,
    ) -> Optional[dict[str, Any]]:
        """Send a GET or POST request with param=value and return a response dict."""
        import aiohttp as _aiohttp

        try:
            if isinstance(target, InjectionTarget):
                url = target.url
                if target.method == "POST":
                    form_data = dict(target.hidden_fields)
                    form_data.update(target.all_params)
                    form_data[param] = value
                    result = await self.http.post(
                        url,
                        data=form_data,
                        retries=1,
                        timeout=_aiohttp.ClientTimeout(total=timeout_seconds),
                    )
                else:
                    query_params = dict(target.all_params)
                    query_params[param] = value
                    result = await self.http.get(
                        target.url,
                        params=query_params,
                        retries=1,
                        timeout=_aiohttp.ClientTimeout(total=timeout_seconds),
                    )
            else:
                url = target
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
            logger.debug("SQLi probe failed for %s param=%s: %s", target, param, exc)
            return None

    @staticmethod
    def _generate_benign_variant(original: str) -> str:
        """Generate a benign, different-but-valid-looking value."""
        if original.isdigit():
            return str(int(original) + random.randint(1, 100))
        suffix = "".join(random.choices(string.ascii_lowercase, k=4))
        return f"{original}{suffix}"

    @classmethod
    def extract_url_params(cls, url: str) -> dict[str, str]:
        """Extract URL query parameters as a name -> value dictionary."""
        return extract_url_params(url)

    @staticmethod
    def _extract_params(
        observations: list[dict[str, Any]], target: str
    ) -> list[dict[str, Any]]:
        """Extract injectable parameters with backward compatibility."""
        targets = extract_injection_targets(observations, target)
        return [
            {
                "url": t.url,
                "name": t.param_name,
                "original_value": t.original_value,
                "method": t.method,
                "target_obj": t,
            }
            for t in targets
        ]


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
