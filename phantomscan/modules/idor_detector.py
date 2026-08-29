"""Module 2 — IDOR / BOLA Detector.

Detects Insecure Direct Object References and Broken Object Level
Authorization by manipulating numeric IDs, UUIDs, and query parameters
in discovered URLs.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

_ID_PATTERNS = [
    (r"/(\d{1,10})(?:/|$|\?)", "path_numeric"),
    (r"/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", "path_uuid"),
    (r"/([a-f0-9]{24})(?:/|$|\?)", "path_objectid"),
    (r"[?&]id=(\d+)", "param_id"),
    (r"[?&]user_id=(\d+)", "param_user_id"),
    (r"[?&]order[_-]?id=(\d+)", "param_order"),
    (r"[?&]account=(\d+)", "param_account"),
    (r"[?&]file=(\w+)", "param_file"),
    (r"[?&]doc(?:ument)?=(\d+)", "param_doc"),
    (r"[?&]invoice=(\d+)", "param_invoice"),
]

_DATA_SIGNALS = frozenset({
    "email", "username", "name", "phone", "address", "account",
    "balance", "password", "ssn", "credit", "order", "invoice",
    "user_id", "profile", "created_at", "updated_at",
})


class IDORDetector:
    """Detect IDOR / BOLA vulnerabilities by manipulating object IDs."""

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

        urls = self._collect_urls(target, observations)
        candidates = self._find_id_candidates(urls)

        import asyncio
        sem = asyncio.Semaphore(15)

        async def test_one_candidate(candidate: dict[str, Any]) -> dict[str, Any] | None:
            url = candidate["url"]
            original_id = candidate["id"]
            test_ids = self._generate_test_ids(original_id)

            async with sem:
                for test_id in test_ids:
                    test_url = url.replace(original_id, test_id, 1)
                    if test_url == url:
                        continue
                    try:
                        response = await self.http.get(test_url, retries=1)
                        if response.status == 200 and self._looks_like_data(response.text()):
                            return {
                                "id": "IDOR-BOLA",
                                "title": "Potential IDOR / BOLA — Object ID Manipulation",
                                "severity": "high",
                                "confidence": "medium",
                                "category": "idor",
                                "target": url,
                                "evidence": (
                                    f"Original URL: {url}\n"
                                    f"Modified URL: {test_url}\n"
                                    f"Response: HTTP {response.status} "
                                    f"({len(response.body)} bytes). "
                                    f"Data-like content detected — manual "
                                    f"verification required."
                                ),
                                "recommendation": (
                                    "Implement proper authorization checks: verify "
                                    "that the authenticated user owns the requested "
                                    "object before returning data. Never rely solely "
                                    "on object IDs for access control. CWE-639, "
                                    "OWASP API1:2023 BOLA."
                                ),
                                "references": [
                                    "https://cwe.mitre.org/data/definitions/639.html",
                                    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                                ],
                            }
                    except Exception:
                        continue
            return None

        results = await asyncio.gather(*(test_one_candidate(c) for c in candidates[:30]), return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _collect_urls(
        self, target: str, observations: list[dict[str, Any]]
    ) -> list[str]:
        base = target.rstrip("/")
        urls: set[str] = {f"{base}/"}
        for obs in observations:
            name = str(obs.get("name", ""))
            val = obs.get("value", "")
            if isinstance(val, str) and ("http" in val or "/" in val):
                urls.add(val if val.startswith("http") else f"{base}{val if val.startswith('/') else '/' + val}")
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and ("http" in item or "/" in item):
                        urls.add(item if item.startswith("http") else f"{base}{item if item.startswith('/') else '/' + item}")
                    elif isinstance(item, dict) and "url" in item:
                        u = str(item["url"])
                        urls.add(u if u.startswith("http") else f"{base}{u if u.startswith('/') else '/' + u}")
            if isinstance(val, dict):
                for v in val.values():
                    if isinstance(v, str) and ("http" in v or "/" in v):
                        urls.add(v if v.startswith("http") else f"{base}{v if v.startswith('/') else '/' + v}")

        # Add common REST resource ID probe paths
        for probe_path in (
            "/rest/basket/1",
            "/api/Feedbacks/1",
            "/api/Users/1",
            "/rest/user/authentication-details",
            "/api/BasketItems/1",
            "/rest/order-history/1",
        ):
            urls.add(f"{base}{probe_path}")

        return list(urls)

    def _find_id_candidates(self, urls: list[str]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        seen: set[str] = set()
        for url in urls:
            for pattern, kind in _ID_PATTERNS:
                match = re.search(pattern, url)
                if match:
                    key = (url, match.group(1))
                    if key not in seen:
                        seen.add(key)
                        candidates.append({
                            "url": url,
                            "id": match.group(1),
                            "kind": kind,
                        })
        return candidates

    @staticmethod
    def _generate_test_ids(original: str) -> list[str]:
        try:
            n = int(original)
            return [str(n + 1), str(n - 1), str(n + 100), "1", "0", "99999"]
        except ValueError:
            # UUID or ObjectId — try well-known sentinel values
            if len(original) == 36 and "-" in original:
                return [
                    "00000000-0000-0000-0000-000000000001",
                    "00000000-0000-0000-0000-000000000000",
                ]
            return ["1", "2", "100", "000000000000000000000001"]

    @staticmethod
    def _looks_like_data(body: str) -> bool:
        lower = body.lower()
        if len(lower) < 20:
            return False
        hits = sum(1 for s in _DATA_SIGNALS if s in lower)
        return hits >= 2
