"""Regression: SQLi detector must NOT produce false positives.

Tests that WAF block pages, generic "sql" text, and baseline-present
error signatures are correctly excluded from findings.
"""

from __future__ import annotations

import pytest

from phantomscan.modules.sqli_detector import SQLiDetector
from tests.false_positive_regression.conftest import MockHTTPClient, MockHTTPResult


@pytest.mark.asyncio
async def test_sqli_no_false_positive_on_waf_block():
    """A WAF block page containing 'SQL' defensively must NEVER produce a SQLi finding."""
    waf_response = MockHTTPResult(
        status=403,
        body=(
            b"Access Denied - Malicious SQL pattern "
            b"detected by security policy"
        ),
        headers={"content-type": "text/html"},
    )
    client = MockHTTPClient(default_response=waf_response)
    detector = SQLiDetector(http=client)

    result = await detector._test_error_based(
        "http://test.local/search", "q", "shoes"
    )

    assert result is None, (
        "SQLi detector incorrectly flagged a WAF block page as injection"
    )


@pytest.mark.asyncio
async def test_sqli_no_false_positive_on_generic_sql_text():
    """A page that mentions 'SQL' in educational/informational context
    must not be flagged."""
    informational_response = MockHTTPResult(
        status=200,
        body=(
            b"<html><body>"
            b"<h1>Learn SQL Basics</h1>"
            b"<p>SQL stands for Structured Query Language. "
            b"It is used to communicate with databases.</p>"
            b"<p>Common SQL errors include syntax errors when "
            b"writing queries incorrectly.</p>"
            b"</body></html>"
        ),
        headers={"content-type": "text/html"},
    )
    client = MockHTTPClient(default_response=informational_response)
    detector = SQLiDetector(http=client)

    result = await detector._test_error_based(
        "http://test.local/blog", "q", "sql-tutorial"
    )

    assert result is None, (
        "SQLi detector incorrectly flagged informational SQL content"
    )


@pytest.mark.asyncio
async def test_sqli_no_false_positive_on_baseline_present_error():
    """If a DB error signature is already present in the baseline (original value)
    response, the payload response must NOT be flagged — the error is pre-existing."""
    error_body = (
        b"<html><body>"
        b"Warning: mysqli_query(): check the manual that corresponds to "
        b"your MySQL server version for the right syntax"
        b"</body></html>"
    )
    # Both baseline and payload return the same error — it's pre-existing
    response = MockHTTPResult(status=200, body=error_body)
    client = MockHTTPClient(default_response=response)
    detector = SQLiDetector(http=client)

    result = await detector._test_error_based(
        "http://test.local/search", "q", "shoes"
    )

    assert result is None, (
        "SQLi detector incorrectly flagged a pre-existing DB error "
        "signature that was already in the baseline response"
    )


@pytest.mark.asyncio
async def test_sqli_cloudflare_block_not_flagged():
    """Cloudflare challenge page must not produce a SQLi finding."""
    cf_response = MockHTTPResult(
        status=403,
        body=(
            b"<html><head><title>Attention Required! | Cloudflare</title></head>"
            b"<body><h1>Sorry, you have been blocked</h1>"
            b"<p>You are unable to access this website.</p>"
            b"</body></html>"
        ),
        headers={"content-type": "text/html", "cf-ray": "abc123"},
    )
    client = MockHTTPClient(default_response=cf_response)
    detector = SQLiDetector(http=client)

    result = await detector._test_error_based(
        "http://test.local/search", "q", "shoes"
    )

    assert result is None, (
        "SQLi detector incorrectly flagged a Cloudflare block page"
    )


@pytest.mark.asyncio
async def test_sqli_boolean_blind_rejects_dynamic_html_jitter():
    """Verify that natural variance on dynamic HTML pages
    is NOT flagged as boolean SQL injection."""
    from typing import Any
    from phantomscan.injection_target import InjectionTarget

    class DynamicHtmlMockClient:
        def __init__(self) -> None:
            self.call_count = 0

        async def get(self, url: str, **kwargs: Any) -> MockHTTPResult:
            self.call_count += 1
            params = kwargs.get("params", {})
            param_val = str(params.get("q", ""))

            # Base page length is ~890,000 bytes with slight random-like jitter per call (< 1% delta)
            if "OR '1'='1" in param_val:
                length = 899581
            elif "AND '1'='2" in param_val:
                length = 890992
            elif self.call_count % 2 == 0:
                length = 895000
            else:
                length = 891000

            body = b"A" * length
            return MockHTTPResult(status=200, body=body, headers={"content-type": "text/html"})

    client = DynamicHtmlMockClient()
    detector = SQLiDetector(http=client)
    target = InjectionTarget(
        url="https://app.example.com/search",
        method="GET",
        param_name="q",
        original_value="test",
        all_params={"q": "test"},
    )

    finding = await detector._test_boolean_blind(target, "q", "test")
    assert finding is None, (
        "SQLi detector falsely flagged dynamic page jitter as boolean SQLi"
    )


@pytest.mark.asyncio
async def test_sqli_waf_bot_challenge_not_flagged():
    """WAF bot challenge response (HTTP 202 with challenge tokens) must not produce SQLi findings."""
    waf_body = (
        b"<!DOCTYPE html><html><head>"
        b"<script src=\"https://token.waf-provider.com/challenge.js\"></script>"
        b"</head><body><noscript>verify that you're not a robot</noscript></body></html>"
    )
    waf_response = MockHTTPResult(
        status=202,
        body=waf_body,
        headers={
            "server": "EdgeWAF",
            "x-amzn-waf-action": "challenge",
            "access-control-allow-origin": "*",
        },
    )
    client = MockHTTPClient(default_response=waf_response)
    detector = SQLiDetector(http=client)

    result = await detector._test_error_based(
        "http://test.local/search", "q", "shoes"
    )
    assert result is None, "SQLi detector incorrectly flagged a WAF bot challenge response"

