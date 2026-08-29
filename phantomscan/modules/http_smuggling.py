"""Module 7 — HTTP Request Smuggling Detector.

Detects CL.TE and TE.CL request smuggling via raw TCP payloads
with timing anomaly analysis.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)


class HTTPSmugglingDetector:
    """Detect HTTP request smuggling vulnerabilities."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        parsed = urlparse(base_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if not host:
            return findings

        # Only test on port 80 — raw TCP smuggling doesn't work over TLS
        if port == 443:
            port = 80

        results = await asyncio.gather(
            self._test_clte(host, port),
            self._test_tecl(host, port),
            self._test_tete(host, port),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, dict) and r:
                findings.append(r)

        return findings

    async def _test_clte(
        self, host: str, port: int
    ) -> dict[str, Any] | None:
        """Test CL.TE smuggling: Content-Length wins for front-end,
        Transfer-Encoding wins for back-end."""
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        )
        try:
            result = await self.http.send_raw(host, payload, port=port, timeout=10.0)
            if result.response_time_ms > 5000 or result.status == 0:
                return {
                    "id": "SMUGGLING-CLTE",
                    "title": "Possible HTTP Request Smuggling (CL.TE)",
                    "severity": "high",
                    "confidence": "medium",
                    "category": "http-smuggling",
                    "target": f"http://{host}:{port}",
                    "evidence": (
                        f"CL.TE probe caused timing anomaly: "
                        f"{result.response_time_ms}ms response time "
                        f"(status={result.status}). Server may interpret "
                        f"Content-Length and Transfer-Encoding differently. "
                        f"Manual verification required."
                    ),
                    "recommendation": (
                        "Configure the front-end to normalize requests "
                        "and reject ambiguous Content-Length / "
                        "Transfer-Encoding combinations. Use HTTP/2 "
                        "end-to-end where possible. CWE-444."
                    ),
                    "references": ["https://cwe.mitre.org/data/definitions/444.html"],
                }
        except Exception as exc:
            logger.debug("CL.TE test error: %s", exc)
        return None

    async def _test_tecl(
        self, host: str, port: int
    ) -> dict[str, Any] | None:
        """Test TE.CL smuggling: Transfer-Encoding wins for front-end,
        Content-Length wins for back-end."""
        inner = (
            f"GPOST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1"
        )
        chunk_size = hex(len(inner))[2:]
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{chunk_size}\r\n"
            f"{inner}\r\n"
            f"0\r\n"
            f"\r\n"
        )
        try:
            result = await self.http.send_raw(host, payload, port=port, timeout=10.0)
            if result.response_time_ms > 5000 or result.status == 0:
                return {
                    "id": "SMUGGLING-TECL",
                    "title": "Possible HTTP Request Smuggling (TE.CL)",
                    "severity": "high",
                    "confidence": "medium",
                    "category": "http-smuggling",
                    "target": f"http://{host}:{port}",
                    "evidence": (
                        f"TE.CL probe caused timing anomaly: "
                        f"{result.response_time_ms}ms response time "
                        f"(status={result.status}). Manual verification required."
                    ),
                    "recommendation": (
                        "Reject requests with both Content-Length and "
                        "Transfer-Encoding headers. Normalize at the "
                        "reverse proxy layer. CWE-444."
                    ),
                    "references": ["https://cwe.mitre.org/data/definitions/444.html"],
                }
        except Exception as exc:
            logger.debug("TE.CL test error: %s", exc)
        return None

    async def _test_tete(
        self, host: str, port: int
    ) -> dict[str, Any] | None:
        """Test TE.TE obfuscation variants."""
        obfuscated_te_headers = [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
        ]
        for te_header in obfuscated_te_headers:
            payload = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 6\r\n"
                f"{te_header}\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
                f"X"
            )
            try:
                result = await self.http.send_raw(host, payload, port=port, timeout=10.0)
                if result.response_time_ms > 5000:
                    return {
                        "id": "SMUGGLING-TETE",
                        "title": "Possible HTTP Request Smuggling (TE.TE Obfuscation)",
                        "severity": "high",
                        "confidence": "low",
                        "category": "http-smuggling",
                        "target": f"http://{host}:{port}",
                        "evidence": (
                            f"TE.TE obfuscation probe ({te_header[:40]}) "
                            f"caused timing anomaly: "
                            f"{result.response_time_ms}ms. "
                            f"Manual verification required."
                        ),
                        "recommendation": (
                            "Normalize Transfer-Encoding parsing. Reject "
                            "malformed TE headers at the proxy layer. CWE-444."
                        ),
                        "references": ["https://cwe.mitre.org/data/definitions/444.html"],
                    }
            except Exception:
                continue
        return None
