"""Module 11 — WebSocket Security Tester.

Tests WebSocket endpoints for origin validation bypass, XSS injection
in messages, and authentication-less connections using aiohttp's built-in
WebSocket support (no extra dependency).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

import aiohttp

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

_WS_PATHS = ["/ws", "/websocket", "/socket", "/ws/", "/realtime",
              "/socket.io/", "/sockjs/", "/cable", "/hub"]

_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '<svg onload=alert(1)>',
]


class WebSocketTester:
    """Test WebSocket endpoints for security issues."""

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
        host = parsed.netloc or parsed.hostname or ""
        scheme = "wss" if parsed.scheme == "https" else "ws"

        ws_endpoints = self._discover_ws_endpoints(host, scheme, observations)

        for ws_url in ws_endpoints[:5]:
            origin_result = await self._test_origin_validation(ws_url)
            if origin_result:
                findings.append(origin_result)

            xss_result = await self._test_xss_injection(ws_url)
            if xss_result:
                findings.append(xss_result)

            noauth_result = await self._test_no_auth(ws_url)
            if noauth_result:
                findings.append(noauth_result)

        return findings

    async def _test_origin_validation(self, ws_url: str) -> dict[str, Any] | None:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    ws_url,
                    headers={"Origin": "https://evil.com"},
                    timeout=8,
                    ssl=False,
                ) as ws:
                    await ws.send_str(json.dumps({"type": "ping"}))
                    try:
                        msg = await asyncio.wait_for(ws.receive(), timeout=5)
                        if msg.type in (aiohttp.WSMsgType.TEXT, aiohttp.WSMsgType.BINARY):
                            return {
                                "id": "WS-NO-ORIGIN-CHECK",
                                "title": "WebSocket No Origin Validation",
                                "severity": "medium",
                                "confidence": "high",
                                "category": "websocket",
                                "target": ws_url,
                                "evidence": (
                                    f"Connected from Origin: https://evil.com\n"
                                    f"Server accepted connection and responded: "
                                    f"{str(msg.data)[:200]}"
                                ),
                                "recommendation": (
                                    "Validate the Origin header on WebSocket "
                                    "handshake. Only accept connections from "
                                    "trusted origins. CWE-346."
                                ),
                                "references": [
                                    "https://cwe.mitre.org/data/definitions/346.html",
                                ],
                            }
                    except asyncio.TimeoutError:
                        pass
        except Exception as exc:
            logger.debug("WS origin test failed for %s: %s", ws_url, exc)
        return None

    async def _test_xss_injection(self, ws_url: str) -> dict[str, Any] | None:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    ws_url, timeout=8, ssl=False,
                ) as ws:
                    for payload in _XSS_PAYLOADS:
                        await ws.send_str(
                            json.dumps({"message": payload, "content": payload})
                        )
                        try:
                            msg = await asyncio.wait_for(ws.receive(), timeout=3)
                            if msg.type == aiohttp.WSMsgType.TEXT and payload in str(msg.data):
                                return {
                                    "id": "WS-XSS-REFLECTION",
                                    "title": "WebSocket XSS Reflection",
                                    "severity": "high",
                                    "confidence": "high",
                                    "category": "websocket",
                                    "target": ws_url,
                                    "evidence": (
                                        f"XSS payload reflected in WebSocket response.\n"
                                        f"Payload: {payload}\n"
                                        f"Response: {str(msg.data)[:300]}"
                                    ),
                                    "recommendation": (
                                        "Sanitize and encode all WebSocket message "
                                        "content before rendering in the browser. "
                                        "CWE-79."
                                    ),
                                    "references": [
                                        "https://cwe.mitre.org/data/definitions/79.html",
                                    ],
                                }
                        except asyncio.TimeoutError:
                            continue
        except Exception as exc:
            logger.debug("WS XSS test failed for %s: %s", ws_url, exc)
        return None

    async def _test_no_auth(self, ws_url: str) -> dict[str, Any] | None:
        """Check if WebSocket accepts connections without any auth."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    ws_url, timeout=8, ssl=False,
                ) as ws:
                    # Try to receive any data without sending auth
                    await ws.send_str(json.dumps({"type": "subscribe", "channel": "all"}))
                    try:
                        msg = await asyncio.wait_for(ws.receive(), timeout=5)
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            data = str(msg.data).lower()
                            # If we get data back that isn't an auth error
                            if not any(w in data for w in ("unauthorized", "auth",
                                                            "forbidden", "denied",
                                                            "login")):
                                return {
                                    "id": "WS-NO-AUTH",
                                    "title": "WebSocket Accepts Unauthenticated Connections",
                                    "severity": "medium",
                                    "confidence": "medium",
                                    "category": "websocket",
                                    "target": ws_url,
                                    "evidence": (
                                        f"WebSocket accepted connection and returned "
                                        f"data without authentication.\n"
                                        f"Response: {str(msg.data)[:300]}"
                                    ),
                                    "recommendation": (
                                        "Require authentication before establishing "
                                        "WebSocket connections. Validate session "
                                        "tokens during the handshake. CWE-306."
                                    ),
                                    "references": [
                                        "https://cwe.mitre.org/data/definitions/306.html",
                                    ],
                                }
                    except asyncio.TimeoutError:
                        pass
        except Exception:
            pass
        return None

    def _discover_ws_endpoints(
        self, host: str, scheme: str, observations: list[dict[str, Any]]
    ) -> list[str]:
        endpoints: list[str] = []
        # Check observations for WebSocket indicators
        for obs in observations:
            val = str(obs.get("value", "")).lower()
            if "websocket" in val or "ws://" in val or "wss://" in val:
                ws_re = re.compile(r"wss?://[^\s\"']+")
                for match in ws_re.findall(val):
                    endpoints.append(match)

        # Generate common WS paths
        for path in _WS_PATHS:
            endpoints.append(f"{scheme}://{host}{path}")

        return list(set(endpoints))
