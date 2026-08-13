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
