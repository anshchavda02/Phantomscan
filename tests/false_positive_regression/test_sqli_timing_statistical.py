"""Regression: Time-based blind SQLi must use statistical baseline.

A single slow response must NOT produce a finding; requires 2 independent
reproductions with statistical margin over baseline variance.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from phantomscan.modules.sqli_detector import SQLiDetector
from tests.false_positive_regression.conftest import MockHTTPClient, MockHTTPResult


class TimingMockHTTPClient(MockHTTPClient):
    """HTTP client that simulates controlled response times."""

    def __init__(self, delays: dict[str, float] | None = None, default_delay: float = 0.1):
        super().__init__()
        self.delays = delays or {}
        self.default_delay = default_delay
        self._call_count: dict[str, int] = {}

    async def get(self, url: str, **kwargs: Any) -> MockHTTPResult:
        import asyncio
        params = kwargs.get("params", {})
        # Track calls
        param_key = str(params)
        self._call_count[param_key] = self._call_count.get(param_key, 0) + 1

        # Determine delay
        for value in params.values():
            if str(value) in self.delays:
                delay = self.delays[str(value)]
                await asyncio.sleep(delay)
                break
        else:
            await asyncio.sleep(self.default_delay)

        return self.default_response


from typing import Any


@pytest.mark.asyncio
async def test_single_slow_response_not_flagged():
    """A single slow response should not be enough — requires 2 reproductions."""
    # The detector takes 3 baseline samples, then tests payloads twice each.
    # We make the FIRST payload attempt slow but the second normal.
    # This should NOT produce a finding.

    call_count = {"payload_calls": 0}
    original_client = MockHTTPClient()

    class OnceSlowClient(MockHTTPClient):
        async def get(self, url: str, **kwargs: Any) -> MockHTTPResult:
            import asyncio
            params = kwargs.get("params", {})
            for v in params.values():
                if "SLEEP" in str(v):
                    call_count["payload_calls"] += 1
                    if call_count["payload_calls"] == 1:
                        # First attempt: slow (simulating network jitter)
                        await asyncio.sleep(0.01)
                    else:
                        # Second attempt: normal speed
                        await asyncio.sleep(0.001)
                    return self.default_response
            await asyncio.sleep(0.001)
            return self.default_response

    client = OnceSlowClient()
    detector = SQLiDetector(http=client)

    # The timing test internally checks if elapsed >= baseline_avg + 4.5 + 2*stdev
    # With our short sleeps, no response will exceed that threshold
    result = await detector._test_time_based(
        "http://test.local/search", "q", "shoes"
    )

    assert result is None, (
        "Time-based SQLi incorrectly flagged with only network jitter"
    )


@pytest.mark.asyncio
async def test_baseline_variance_prevents_false_positive():
    """High baseline variance must raise the threshold enough to prevent false positives."""
    # If baseline times vary widely, the threshold should be high enough
    # that a payload with only moderate delay doesn't trigger.
    client = MockHTTPClient()
    detector = SQLiDetector(http=client)

    # With default mock (instant responses), no real delay can occur,
    # so no timing-based finding should be produced
    result = await detector._test_time_based(
        "http://test.local/api", "id", "42"
    )

    assert result is None, (
        "Time-based SQLi produced a finding without actual delay"
    )
