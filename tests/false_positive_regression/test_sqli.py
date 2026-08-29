"""Regression tests for real SQL injection detection and false positive suppression."""
from __future__ import annotations

from typing import Any
import pytest

from phantomscan.modules.sqli_detector import SQLiDetector, extract_url_params
from tests.false_positive_regression.conftest import MockHTTPClient, MockHTTPResult


@pytest.mark.asyncio
async def test_sqli_no_false_positive_on_waf_block():
    """Mock server returns 403 with WAF message.
    Assert: no SQLi finding produced.
    """
    waf_response = MockHTTPResult(
        status=403,
        body=(
            b"<html><body><h1>403 Forbidden</h1>"
            b"<p>Request blocked by ModSecurity Action. Malicious SQL pattern.</p>"
            b"</body></html>"
        ),
        headers={"content-type": "text/html"},
    )
    client = MockHTTPClient(default_response=waf_response)
    detector = SQLiDetector(http=client)

    result = await detector._test_error_based(
        "http://test.local/search.php", "q", "apple"
    )
    assert result is None, "SQLi detector incorrectly flagged a WAF block response"


@pytest.mark.asyncio
async def test_sqli_no_false_positive_on_baseline_error():
    """Mock server returns same DB error on clean request.
    Assert: no SQLi finding produced (error pre-exists in baseline).
    """
    error_body = (
        b"<html><body>"
        b"Warning: mysqli_query(): check the manual that corresponds to "
        b"your MySQL server version for the right syntax"
        b"</body></html>"
    )
    # Both clean baseline request and payload request return the same error
    client = MockHTTPClient(
        default_response=MockHTTPResult(status=200, body=error_body)
    )
    detector = SQLiDetector(http=client)

    result = await detector._test_error_based(
        "http://test.local/products.php", "id", "1"
    )
    assert result is None, "SQLi detector flagged a pre-existing baseline error"


@pytest.mark.asyncio
async def test_sqli_detects_mysql_error():
    """Mock server returns MySQL error ONLY on injected payload.
    Assert: SQLi Critical finding produced.
    """
    class SQLiMockClient:
        def __init__(self) -> None:
            self.request_log: list[dict[str, Any]] = []

        async def get(self, url: str, **kwargs: Any) -> MockHTTPResult:
            params = kwargs.get("params", {})
            self.request_log.append({"url": url, "params": params})
            val = str(params.get("artist", ""))
            # Return MySQL error only when injection quote or payload is sent
            if "'" in val or "OR" in val or "1=1" in val:
                return MockHTTPResult(
                    status=200,
                    body=b"Warning: mysqli_fetch_array(): Error in your SQL syntax near MySQL server version",
                    headers={"content-type": "text/html"},
                )
            return MockHTTPResult(
                status=200,
                body=b"<html><body>Artists page - valid output</body></html>",
                headers={"content-type": "text/html"},
            )

    client = SQLiMockClient()
    detector = SQLiDetector(http=client)
    observations = [
        {
            "name": "parameterized_urls",
            "value": ["http://test.local/artists.php?artist=1"],
            "source": "crawler",
        }
    ]

    findings = await detector.run("http://test.local", observations)
    assert len(findings) >= 1
    sqli = findings[0]
    assert sqli["id"] == "SQLI-ERROR-BASED"
    assert sqli["severity"].lower() == "critical"
    assert "artist" in sqli["evidence"]
    assert "MySQL" in sqli["evidence"]


def test_sqli_tests_url_parameters():
    """Provide URL with ?id=1&name=test.
    Assert: both 'id' and 'name' parameters are extracted and tested.
    """
    url = "http://test.local/search.php?id=1&name=test"
    params_dict = extract_url_params(url)
    assert "id" in params_dict
    assert params_dict["id"] == "1"
    assert "name" in params_dict
    assert params_dict["name"] == "test"

    # Also verify SQLiDetector._extract_params extracts both parameters
    extracted = SQLiDetector._extract_params([], url)
    names = [p["name"] for p in extracted]
    assert "id" in names
    assert "name" in names
