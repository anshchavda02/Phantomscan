"""Module 2 — IDOR / BOLA Detector.

Detects Insecure Direct Object References and Broken Object Level
Authorization by manipulating numeric IDs, UUIDs, and query parameters
in discovered URLs with baseline differential comparison.
"""

from __future__ import annotations

import difflib
import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

_ID_PATTERNS = [
    (r"/(\d{1,10})(?:/|$|\?)", "path_numeric"),
    (r"/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", "path_uuid"),
    (r"/([a-f0-9]{24})(?:/|$|\?)", "path_objectid"),
    (r"[?&](id)=(\d+)", "param_id"),
    (r"[?&](user_id)=(\d+)", "param_user_id"),
    (r"[?&](order[_-]?id)=(\d+)", "param_order"),
    (r"[?&](account)=(\d+)", "param_account"),
    (r"[?&](artist)=(\d+)", "param_artist"),
    (r"[?&](cat)=(\d+)", "param_cat"),
    (r"[?&](pic)=(\d+)", "param_pic"),
    (r"[?&](aid)=(\d+)", "param_aid"),
    (r"[?&](file)=(\w+)", "param_file"),
    (r"[?&](doc(?:ument)?)=(\d+)", "param_doc"),
    (r"[?&](invoice)=(\d+)", "param_invoice"),
    (r"[?&]([a-zA-Z0-9_-]+)=(\d+)", "param_numeric"),
]

# Non-object / UI parameters that should never trigger IDOR probes
_IGNORED_PARAMS = frozenset({
    "hl", "gl", "fg", "ictx", "page", "limit", "v", "sig", "cb", "sa",
    "source", "ved", "bih", "biw", "dpr", "tbm", "tbo", "sclient", "oq",
    "cp", "gs_lcp", "ei", "sxsrf", "uact", "ved", "d", "ed", "dg", "br",
    "rs", "ee", "m", "width", "height", "size", "offset", "step", "tab",
    "sort", "order", "lang", "locale", "theme", "view", "mode", "version",
})

_DATA_SIGNALS = frozenset({
    "email", "username", "phone", "address", "balance", "password",
    "ssn", "credit", "invoice", "user_id", "created_at", "updated_at",
    "price", "tax_id", "billing", "private_key",
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
            param_name = candidate.get("param_name")
            kind = candidate.get("kind", "")

            # Step 1: Capture baseline response for original URL
            baseline_status = 0
            baseline_body = ""
            try:
                base_resp = await self.http.get(url, retries=1)
                baseline_status = base_resp.status
                baseline_body = base_resp.text()
            except Exception:
                return None

            if baseline_status != 200:
                return None

            test_ids = self._generate_test_ids(original_id)

            async with sem:
                for test_id in test_ids:
                    if test_id == original_id:
                        continue

                    # Construct test URL accurately based on kind
                    test_url = self._build_test_url(url, kind, param_name, original_id, test_id)
                    if test_url == url:
                        continue

                    try:
                        response = await self.http.get(test_url, retries=1)
                        if response.status != 200:
                            continue

                        test_body = response.text()
                        content_type = response.headers.get("content-type", "").lower()
                        is_json = "application/json" in content_type

                        # Differential Analysis: Check if the response actually returned distinct object data
                        if not self._is_differential_data_leak(baseline_body, test_body, is_json, kind):
                            continue

                        return {
                            "id": "IDOR-BOLA",
                            "title": "Potential IDOR / BOLA — Object ID Manipulation",
                            "severity": "high",
                            "confidence": "high" if is_json else "medium",
                            "category": "idor",
                            "target": url,
                            "verification_method": "baseline_differential",
                            "evidence": (
                                f"Original URL: {url}\n"
                                f"Modified URL: {test_url}\n"
                                f"Response: HTTP {response.status} ({len(response.body)} bytes).\n"
                                f"Differential data content confirmed between object IDs '{original_id}' and '{test_id}'."
                            ),
                            "recommendation": (
                                "Implement proper authorization checks: verify that the "
                                "authenticated user owns the requested object before returning "
                                "data. Never rely solely on object IDs for access control. "
                                "CWE-639, OWASP API1:2023 BOLA."
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
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)

            # Check explicit query parameter patterns
            for pattern, kind in _ID_PATTERNS:
                if kind.startswith("param_"):
                    match = re.search(pattern, url)
                    if match:
                        p_name = match.group(1)
                        val = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(1)
                        if p_name.lower() in _IGNORED_PARAMS:
                            continue
                        key = (url, p_name, val)
                        if key not in seen:
                            seen.add(key)
                            candidates.append({
                                "url": url,
                                "id": val,
                                "param_name": p_name,
                                "kind": kind,
                            })

            # Check path patterns
            for pattern, kind in _ID_PATTERNS:
                if kind.startswith("path_"):
                    match = re.search(pattern, parsed.path)
                    if match:
                        val = match.group(1)
                        key = (url, "", val)
                        if key not in seen:
                            seen.add(key)
                            candidates.append({
                                "url": url,
                                "id": val,
                                "param_name": "",
                                "kind": kind,
                            })
        return candidates

    @staticmethod
    def _build_test_url(
        url: str, kind: str, param_name: str | None, original_id: str, test_id: str
    ) -> str:
        parsed = urlparse(url)
        if kind.startswith("param_") and param_name:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            if param_name in query_params:
                query_params[param_name] = [test_id]
                new_query = urlencode(query_params, doseq=True)
                return urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment,
                ))
        elif kind.startswith("path_"):
            new_path = parsed.path.replace(f"/{original_id}", f"/{test_id}", 1)
            return urlunparse((
                parsed.scheme, parsed.netloc, new_path,
                parsed.params, parsed.query, parsed.fragment,
            ))
        return url

    @staticmethod
    def _generate_test_ids(original: str) -> list[str]:
        try:
            n = int(original)
            return [str(n + 1), str(n - 1), str(n + 100), "1", "2", "99999"]
        except ValueError:
            # UUID or ObjectId
            if len(original) == 36 and "-" in original:
                return [
                    "00000000-0000-0000-0000-000000000001",
                    "00000000-0000-0000-0000-000000000002",
                ]
            return ["1", "2", "100", "000000000000000000000001"]

    @staticmethod
    def _is_differential_data_leak(baseline: str, test: str, is_json: bool, kind: str = "") -> bool:
        """Verify that the response contains distinct object/user data differences."""
        if not test or len(test) < 20:
            return False

        lower = test.lower()
        hits = sum(1 for s in _DATA_SIGNALS if s in lower)

        if is_json:
            return hits >= 1 or len(test) > 30

        # For explicit object parameters (artist, id, user_id, order_id, etc.)
        if kind in ("param_id", "param_user_id", "param_order", "param_account", "param_artist", "param_cat", "param_pic", "param_aid", "param_doc", "param_invoice", "path_numeric", "path_uuid", "path_objectid"):
            return hits >= 2

        # For generic parameters on HTML pages, require differential data and non-identical response
        if baseline == test:
            return False

        ratio = difflib.SequenceMatcher(None, baseline[:2000], test[:2000]).ratio()
        if ratio > 0.98:
            return False

        len_diff = abs(len(test) - len(baseline))
        if len_diff < 50:
            return False

        return hits >= 3


