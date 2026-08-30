"""Unit tests for Phase 6: Multi-Stage Injection Engine."""

import unittest
from unittest.mock import AsyncMock, MagicMock

import pytest

from phantomscan.http_client import HTTPResult, RobustHTTPClient
from phantomscan.injection_target import InjectionTarget
from phantomscan.modules.path_traversal import PathTraversalScanner
from phantomscan.modules.race_condition import RaceConditionDetector
from phantomscan.modules.sqli_detector import SQLiDetector
from phantomscan.modules.ssrf_detector import SSRFDetector
from phantomscan.modules.prototype_pollution import PrototypePollutionDetector


@pytest.mark.asyncio
async def test_path_traversal_detection():
    """Detects Linux /etc/passwd disclosure in response body."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    # Baseline: normal html
    mock_http.get = AsyncMock(
        side_effect=[
            HTTPResult("http://example.com/view?file=about.html", 200, {}, {}, b"Welcome to our about page", [], [], 20, "text/html"),
            HTTPResult("http://example.com/view?file=../etc/passwd", 200, {}, {}, b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...", [], [], 25, "text/plain"),
        ]
    )

    scanner = PathTraversalScanner(http=mock_http)
    target = InjectionTarget(url="http://example.com/view", method="GET", param_name="file", original_value="about.html")
    result = await scanner._test_traversal(target, "file")

    assert result is not None
    assert result["id"] == "PATH-TRAVERSAL"
    assert "root:x:0:0" in result["evidence"]


@pytest.mark.asyncio
async def test_path_traversal_waf_block_suppression():
    """PR-D06: WAF 403 block is suppressed and not declared as a vulnerability."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(
        side_effect=[
            HTTPResult("http://example.com/view?file=about.html", 200, {}, {}, b"Normal page", [], [], 20, "text/html"),
            HTTPResult("http://example.com/view?file=../etc/passwd", 403, {}, {}, b"Access Denied - WAF Blocked", [], [], 15, "text/html"),
            HTTPResult("http://example.com/view?file=../../etc/passwd", 403, {}, {}, b"Access Denied - WAF Blocked", [], [], 15, "text/html"),
        ]
    )

    scanner = PathTraversalScanner(http=mock_http)
    target = InjectionTarget(url="http://example.com/view", method="GET", param_name="file", original_value="about.html")
    result = await scanner._test_traversal(target, "file")

    assert result is None


@pytest.mark.asyncio
async def test_race_condition_concurrency_bound():
    """SEC-E03: Concurrency is clamped to at most 20."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.post = AsyncMock(
        return_value=HTTPResult("http://example.com/api/redeem", 200, {}, {}, b'{"status": "ok"}', [], [], 30, "application/json")
    )

    detector = RaceConditionDetector(http=mock_http)
    # Pass 50, detector clamps to 20
    await detector._test_race(url="http://example.com/api/redeem", concurrent=50)
    # mock_http.post should have been called at most 20 times for that single endpoint
    assert mock_http.post.call_count <= 20



@pytest.mark.asyncio
async def test_prototype_pollution_detection():
    """Detect server-side prototype pollution in JSON endpoint."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(
        return_value=HTTPResult(
            "http://example.com/api/profile",
            200,
            {"content-type": "text/html"},
            {},
            b'<html><body>Normal page</body></html>',
            [],
            [],
            25,
            "text/html",
        )
    )
    mock_http.post = AsyncMock(
        return_value=HTTPResult(
            "http://example.com/api/profile",
            200,
            {"content-type": "application/json"},
            {},
            b'{"status": "updated", "phantomscan_pp": "detected"}',
            [],
            [],
            25,
            "application/json",
        )
    )


    detector = PrototypePollutionDetector(http=mock_http)
    findings = await detector.run(
        base_url="http://example.com",
        observations=[{"name": "discovered_api_routes", "value": ["/api/profile"]}],
    )
    assert len(findings) >= 1
    assert findings[0]["id"] == "PROTO-POLLUTION-SERVER"


if __name__ == "__main__":
    unittest.main()
