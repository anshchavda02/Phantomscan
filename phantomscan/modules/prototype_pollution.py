"""Module 9 — Prototype Pollution Detector.

Detects server-side prototype pollution via __proto__ / constructor.prototype
injection in JSON APIs, and client-side pollution via query parameters.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

_SERVER_PAYLOADS = [
    {"__proto__": {"phantomscan_pp": "detected"}},
    {"constructor": {"prototype": {"phantomscan_pp": "detected"}}},
    {"__proto__": {"isAdmin": True}},
    {"__proto__": {"status": 200}},
]

_CLIENT_QS_PAYLOADS = [
    "__proto__[phantomscan_pp]=detected",
    "__proto__.phantomscan_pp=detected",
    "constructor.prototype.phantomscan_pp=detected",
    "__proto__[isAdmin]=true",
]


class PrototypePollutionDetector:
    """Detect server-side and client-side prototype pollution."""

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
        endpoints = self._find_json_endpoints(target, observations)

        sem = asyncio.Semaphore(15)

        async def test_server_endpoint(url: str) -> dict[str, Any] | None:
            async with sem:
                for payload in _SERVER_PAYLOADS:
                    try:
                        response = await self.http.post(
                            url, json=payload, retries=1,
                        )
                        body = response.text()
                        if (
                            "phantomscan_pp" in body
                            or response.status == 500
                            or ("isAdmin" in body and "true" in body.lower())
                        ):
                            return {
                                "id": "PROTO-POLLUTION-SERVER",
                                "title": "Server-Side Prototype Pollution",
                                "severity": "high",
                                "confidence": "high" if "phantomscan_pp" in body else "medium",
                                "category": "prototype-pollution",
                                "target": url,
                                "evidence": (
                                    f"Payload: {json.dumps(payload)}\n"
                                    f"Response: HTTP {response.status}\n"
                                    f"Body preview: {body[:300]}"
                                ),
                                "recommendation": (
                                    "Sanitize JSON input to reject __proto__ and "
                                    "constructor.prototype keys. Use Object.create(null) "
                                    "for lookup objects. Freeze Object.prototype in "
                                    "Node.js. CWE-1321."
                                ),
                                "references": [
                                    "https://cwe.mitre.org/data/definitions/1321.html",
                                ],
                            }
                    except Exception:
                        continue
            return None

        async def test_client_qs(qs: str) -> dict[str, Any] | None:
            test_url = f"{target}/?{qs}"
            async with sem:
                try:
                    response = await self.http.get(test_url, retries=1)
                    body = response.text()
                    if (
                        response.headers.get("content-type", "").startswith("application/json")
                        and ("\"phantomscan_pp\"" in body or "\"isAdmin\":true" in body)
                    ) or "window.phantomscan_pp" in body or "Object.prototype.phantomscan_pp" in body:
                        return {
                            "id": "PROTO-POLLUTION-CLIENT",
                            "title": "Client-Side Prototype Pollution",
                            "severity": "medium",
                            "confidence": "high",
                            "category": "prototype-pollution",
                            "target": test_url,
                            "evidence": (
                                f"Query string: {qs}\n"
                                f"Pollution marker executed in JS context or JSON API state."
                            ),
                            "recommendation": (
                                "Avoid using object bracket notation with unvalidated user input. "
                                "Freeze Object.prototype. Validate query parameter keys. CWE-1321."
                            ),
                            "references": ["https://cwe.mitre.org/data/definitions/1321.html"],
                        }
                except Exception:
                    pass
            return None

        tasks = [test_server_endpoint(u) for u in endpoints[:15]] + [test_client_qs(qs) for qs in _CLIENT_QS_PAYLOADS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        return findings

    def _find_json_endpoints(
        self, target: str, observations: list[dict[str, Any]]
    ) -> list[str]:
        base = target.rstrip("/")
        endpoints: set[str] = set()
        for obs in observations:
            name = str(obs.get("name", ""))
            val = obs.get("value", "")
            if isinstance(val, str):
                if any(kw in val.lower() for kw in ("/api", "/rest", "json", "graphql")):
                    endpoints.add(val if val.startswith("http") else f"{base}{val if val.startswith('/') else '/' + val}")
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and any(kw in item.lower() for kw in ("/api", "/rest", "json", "graphql")):
                        endpoints.add(item if item.startswith("http") else f"{base}{item if item.startswith('/') else '/' + item}")
                    elif isinstance(item, dict) and "url" in item:
                        u = str(item["url"])
                        endpoints.add(u if u.startswith("http") else f"{base}{u if u.startswith('/') else '/' + u}")

        # Fallback common API paths
        for path in (
            "/api/users", "/api/settings", "/api/config",
            "/api/account", "/api/profile", "/api/v1/data",
            "/rest/user/login", "/api/Feedbacks", "/rest/basket",
            "/api/Challenges", "/rest/products/search"
        ):
            endpoints.add(f"{base}{path}")
        return list(endpoints)

