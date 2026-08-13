"""Shared test fixtures for false-positive regression tests."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import asyncio
from dataclasses import dataclass, field

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


@dataclass
class MockHTTPResult:
    """Simulates an HTTPResult from RobustHTTPClient."""
    url: str = "http://test.local"
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    raw_set_cookies: list[str] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    response_time_ms: int = 100
    content_type: str = "text/html"

    def text(self, encoding: str = "utf-8") -> str:
        return self.body.decode(encoding, errors="ignore")


class MockHTTPClient:
    """Mock RobustHTTPClient for testing.

    Can be configured to return specific responses per-URL or a default.
    """

    def __init__(
        self,
        default_response: MockHTTPResult | None = None,
        responses: dict[str, MockHTTPResult] | None = None,
    ) -> None:
        self.default_response = default_response or MockHTTPResult()
        self.responses = responses or {}
        self.request_log: list[dict[str, Any]] = []

    async def get(self, url: str, **kwargs: Any) -> MockHTTPResult:
        params = kwargs.get("params", {})
        self.request_log.append({"method": "GET", "url": url, "params": params, **kwargs})
        # Check for per-URL responses
        for pattern, response in self.responses.items():
            if pattern in url:
                return response
        return self.default_response

    async def post(self, url: str, **kwargs: Any) -> MockHTTPResult:
        self.request_log.append({"method": "POST", "url": url, **kwargs})
        return self.default_response

    async def start(self) -> None:
        pass

    async def close(self) -> None:
        pass


@pytest.fixture
def mock_http_client():
    """Factory fixture for creating MockHTTPClient with configurable responses."""
    def _factory(
        default_response: MockHTTPResult | None = None,
        responses: dict[str, MockHTTPResult] | None = None,
    ) -> MockHTTPClient:
        return MockHTTPClient(default_response, responses)
    return _factory


@pytest.fixture
def normal_200_response():
    """A vanilla 200 OK response with no error signatures."""
    return MockHTTPResult(
        status=200,
        body=b"<html><body>Welcome to our website</body></html>",
        headers={"content-type": "text/html"},
    )


@pytest.fixture
def waf_block_response():
    """A response that looks like a WAF block page."""
    return MockHTTPResult(
        status=403,
        body=(
            b"<html><body>"
            b"<h1>Access Denied</h1>"
            b"<p>Your request has been blocked by our security policy. "
            b"Malicious SQL pattern detected.</p>"
            b"</body></html>"
        ),
        headers={"content-type": "text/html"},
    )
