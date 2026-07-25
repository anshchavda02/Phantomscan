"""Module 6 — Race Condition Detector.

Sends concurrent requests to single-use endpoints (coupon redemption,
transfers, votes) and checks for inconsistent results indicating TOCTOU flaws.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

_RACE_KEYWORDS = frozenset({
    "redeem", "coupon", "discount", "vote", "transfer", "purchase",
    "register", "reset", "verify", "apply", "submit", "checkout",
    "confirm", "activate", "claim", "withdraw", "deposit",
})


class RaceConditionDetector:
    """Detect race conditions by sending concurrent requests."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        concurrent: int = 20,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        target = base_url.rstrip("/")
        endpoints = self._find_race_endpoints(target, observations)

        for url in endpoints[:10]:
            result = await self._test_race(url, concurrent)
            if result:
                findings.append(result)
        return findings

    async def _test_race(
        self, url: str, concurrent: int
    ) -> dict[str, Any] | None:
        tasks = []
        for _ in range(concurrent):
            tasks.append(self._single_request(url))
        results = await asyncio.gather(*tasks, return_exceptions=True)

        statuses = [
            r["status"] for r in results
            if isinstance(r, dict) and "status" in r
        ]
        if not statuses:
            return None

        success_count = sum(1 for s in statuses if s in (200, 201, 204))
        error_count = sum(1 for s in statuses if s >= 400)
        unique_statuses = set(statuses)

        # Race condition signal: if a single-use endpoint succeeds more than once
        if success_count > 1 and len(unique_statuses) > 1:
            return {
                "id": "RACE-CONDITION",
                "title": f"Possible Race Condition: {url.split('/')[-1]}",
                "severity": "high",
                "confidence": "medium",
                "category": "race-condition",
                "target": url,
                "evidence": (
                    f"Sent {concurrent} simultaneous requests to {url}.\n"
                    f"Successes (2xx): {success_count}\n"
                    f"Errors (4xx+): {error_count}\n"
                    f"Unique status codes: {sorted(unique_statuses)}\n"
                    f"Multiple successes on potentially single-use endpoint "
                    f"suggest a race condition. Manual verification required."
                ),
                "recommendation": (
                    "Implement proper locking, database transactions, or "
                    "idempotency keys to prevent concurrent exploitation. "
                    "Use database-level UNIQUE constraints and SELECT FOR UPDATE. "
                    "CWE-362."
                ),
                "references": ["https://cwe.mitre.org/data/definitions/362.html"],
            }

        return None

    async def _single_request(self, url: str) -> dict[str, Any]:
        try:
            response = await self.http.post(url, json={}, retries=1)
            return {"status": response.status, "length": len(response.body)}
        except Exception as exc:
            return {"status": 0, "error": str(exc)}

    def _find_race_endpoints(
        self, target: str, observations: list[dict[str, Any]]
    ) -> list[str]:
        endpoints: list[str] = []
        # Check observations for URL-like values with race keywords
        for obs in observations:
            val = str(obs.get("value", "")).lower()
            if any(kw in val for kw in _RACE_KEYWORDS) and ("http" in val or "/" in val):
                url = obs.get("value", "")
                if isinstance(url, str):
                    endpoints.append(
                        url if url.startswith("http") else f"{target}{url}"
                    )

        # Also generate common race-prone paths
        for kw in ("redeem", "apply-coupon", "transfer", "vote",
                    "checkout", "verify-email", "claim"):
            endpoints.append(f"{target}/api/{kw}")
        return list(set(endpoints))
