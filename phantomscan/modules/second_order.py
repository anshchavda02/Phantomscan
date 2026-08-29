"""Module 14 — Second-Order Injection Detector.

Stores injection payloads (XSS, SQLi, SSTI) via user input endpoints and
checks whether they execute when viewed on different pages (profile, admin,
search results).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

_MARKER = "ps" + uuid.uuid4().hex[:8]

_SECOND_ORDER_PAYLOADS = [
    # XSS
    {"type": "xss", "value": f"<img src=x onerror=alert('{_MARKER}')>",
     "detect": _MARKER},
    {"type": "xss", "value": f"<svg onload=alert('{_MARKER}')>",
     "detect": _MARKER},
    # SQLi
    {"type": "sqli", "value": f"' OR '1'='1' -- {_MARKER}",
     "detect": _MARKER},
    # SSTI
    {"type": "ssti", "value": f"${{7*7}}{_MARKER}",
     "detect": f"49{_MARKER}"},
    {"type": "ssti", "value": f"{{{{{_MARKER}}}}}",
     "detect": _MARKER},
]

_INPUT_PATHS = [
    ("/api/register", {"username": "", "email": "", "password": "test1234"}),
    ("/api/profile", {"name": "", "bio": "", "website": ""}),
    ("/api/contact", {"name": "", "message": "", "email": ""}),
    ("/api/feedback", {"comment": "", "subject": ""}),
    ("/api/comments", {"body": "", "author": ""}),
    ("/api/settings", {"display_name": "", "description": ""}),
]

_CHECK_PATHS = [
    "/admin", "/admin/users", "/dashboard", "/profile",
    "/api/users", "/api/comments", "/search",
]


class SecondOrderDetector:
    """Detect second-order injection by storing and checking payloads."""

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

        # Phase 1: Store payloads via input endpoints concurrently
        sem = asyncio.Semaphore(15)

        async def store_one(path: str, template: dict[str, Any], payload_def: dict[str, Any]) -> dict[str, Any] | None:
            url = f"{target}{path}"
            body = {key: payload_def["value"] for key in template}
            async with sem:
                try:
                    response = await self.http.post(url, json=body, retries=1)
                    if response.status in (200, 201, 302):
                        return {
                            "input_url": url,
                            "payload": payload_def,
                        }
                except Exception:
                    pass
            return None

        store_tasks = [
            store_one(path, template, pdef)
            for path, template in _INPUT_PATHS
            for pdef in _SECOND_ORDER_PAYLOADS
        ]
        store_results = await asyncio.gather(*store_tasks, return_exceptions=True)
        stored_payloads = [r for r in store_results if isinstance(r, dict)]

        if not stored_payloads:
            return findings

        # Brief wait for server-side processing
        await asyncio.sleep(0.1)

        # Phase 2: Check output pages for payload execution concurrently
        async def check_one(check_path: str) -> list[dict[str, Any]]:
            check_url = f"{target}{check_path}"
            page_findings: list[dict[str, Any]] = []
            async with sem:
                try:
                    response = await self.http.get(check_url, retries=1)
                    body = response.text()

                    for stored in stored_payloads:
                        detect = stored["payload"]["detect"]
                        ptype = stored["payload"]["type"]

                        if detect in body:
                            page_findings.append({
                                "id": f"SECOND-ORDER-{ptype.upper()}",
                                "title": f"Second-Order {ptype.upper()} Injection",
                                "severity": "high",
                                "confidence": "medium",
                                "category": "second-order",
                                "target": check_url,
                                "evidence": (
                                    f"Injection type: {ptype}\n"
                                    f"Input endpoint: {stored['input_url']}\n"
                                    f"Payload: {stored['payload']['value'][:100]}\n"
                                    f"Detection marker found on: {check_url}\n"
                                    f"The payload was stored and later rendered "
                                    f"on a different page without sanitization."
                                ),
                                "recommendation": (
                                    "Sanitize and encode all stored user input "
                                    "at the point of output, not just at input. "
                                    "Use context-aware encoding (HTML, JS, SQL). "
                                    "CWE-79 (XSS), CWE-89 (SQLi), CWE-1336 (SSTI)."
                                ),
                                "references": [
                                    "https://cwe.mitre.org/data/definitions/79.html",
                                    "https://cwe.mitre.org/data/definitions/89.html",
                                ],
                            })
                            break
                except Exception:
                    pass
            return page_findings

        check_results = await asyncio.gather(*(check_one(cp) for cp in _CHECK_PATHS), return_exceptions=True)
        for r in check_results:
            if isinstance(r, list):
                findings.extend(r)

        return findings
