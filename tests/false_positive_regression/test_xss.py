"""Regression tests for Reflected XSS detection and false positive suppression."""
from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse
import pytest

from phantomscan.modules.xss_scanner import XSSScanner, is_reflected_unencoded
from tests.false_positive_regression.conftest import MockHTTPClient, MockHTTPResult


@pytest.mark.asyncio
async def test_xss_detects_reflection():
    """Mock server echoes payload back unencoded.
    Assert: XSS finding produced.
    """
    class EchoUnencodedClient:
        async def get(self, url: str, **kwargs: Any) -> MockHTTPResult:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            q_val = qs.get("q", [""])[0]
            # Return unencoded reflection of the injected payload
            body = f"<html><body>Search query: {q_val}</body></html>".encode()
            return MockHTTPResult(status=200, body=body, headers={"content-type": "text/html"})

        async def post(self, url: str, **kwargs: Any) -> MockHTTPResult:
            return MockHTTPResult(status=200, body=b"OK", headers={"content-type": "text/html"})

    client = EchoUnencodedClient()
    scanner = XSSScanner(http=client)
    observations = [
        {"name": "parameterized_urls", "value": ["http://test.local/search.php?q=apple"], "source": "crawler"}
    ]

    findings = await scanner.run("http://test.local", observations)
    assert len(findings) >= 1
    xss = findings[0]
    assert xss["id"] in ("XSS-REFLECTED", "XSS-REFLECTED-FORM")
    assert xss["severity"].lower() in ("high", "critical", "medium")
    assert "Parameter: q" in xss["evidence"] or "q" in xss["evidence"]


@pytest.mark.asyncio
async def test_xss_no_false_positive_when_encoded():
    """Mock server HTML-encodes the payload.
    Assert: no XSS finding produced.
    """
    class EchoEncodedClient:
        async def get(self, url: str, **kwargs: Any) -> MockHTTPResult:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            q_val = qs.get("q", [""])[0]
            # Safely HTML-encode angle brackets and quotes
            encoded = (
                q_val.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;")
            )
            body = f"<html><body>Search query: {encoded}</body></html>".encode()
            return MockHTTPResult(status=200, body=body, headers={"content-type": "text/html"})

        async def post(self, url: str, **kwargs: Any) -> MockHTTPResult:
            return MockHTTPResult(status=200, body=b"OK", headers={"content-type": "text/html"})

    client = EchoEncodedClient()
    scanner = XSSScanner(http=client)
    observations = [
        {"name": "parameterized_urls", "value": ["http://test.local/search.php?q=apple"], "source": "crawler"}
    ]

    findings = await scanner.run("http://test.local", observations)
    assert len(findings) == 0, f"Expected 0 findings when payload is HTML encoded, got {len(findings)}"


def test_xss_tests_url_params():
    """Provide URL with ?q=test.
    Assert: 'q' parameter is extracted and tested.
    """
    target = "http://test.local/search.php?q=test"
    extracted = XSSScanner._extract_params([], target)
    param_names = [p["name"] for p in extracted]
    assert "q" in param_names, f"Expected 'q' parameter in extracted params, got {param_names}"

    # Also verify unencoded reflection helper
    raw = "<phantomscan-xss-test>"
    safe_body = "<html><body>Search: &lt;phantomscan-xss-test&gt;</body></html>"
    vuln_body = "<html><body>Search: <phantomscan-xss-test></body></html>"

    assert not is_reflected_unencoded(raw, safe_body)
    assert is_reflected_unencoded(raw, vuln_body)
