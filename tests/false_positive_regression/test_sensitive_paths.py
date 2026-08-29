"""Regression tests for sensitive path scanning, web root URL construction, catch-all detection, and 403 handling."""
from __future__ import annotations

import pytest
from modules.sensitive_path_scanner import SensitivePathScanner
from tests.false_positive_regression.conftest import MockHTTPClient, MockHTTPResult


@pytest.mark.asyncio
async def test_probe_uses_web_root():
    """Mock a target at http://example.com/app/page.
    Assert probe URL is http://example.com/.git/HEAD
    NOT http://example.com/app/page/.git/HEAD.
    """
    client = MockHTTPClient(
        default_response=MockHTTPResult(status=404, body=b"Not Found")
    )
    scanner = SensitivePathScanner(http_client=client)
    await scanner.scan("http://example.com/app/page")

    urls_requested = [req["url"] for req in client.request_log]
    assert "http://example.com/.git/HEAD" in urls_requested
    for url in urls_requested:
        assert "/app/page" not in url, f"Probe URL incorrectly contained subpage path: {url}"


@pytest.mark.asyncio
async def test_catchall_suppresses_false_positive():
    """Mock server returns 200+HTML for any path.
    Assert: zero sensitive path findings produced.
    """
    aspnet_html = (
        "<!DOCTYPE html><html><head><title>Portal Login</title></head>"
        "<body><form action='/login.aspx' method='POST'>"
        "<input type='text' name='username' placeholder='Username'>"
        "<input type='password' name='password' placeholder='Password'>"
        "<input type='submit' value='Sign In'>"
        "</form></body></html>"
    )
    client = MockHTTPClient(
        default_response=MockHTTPResult(
            status=200,
            body=aspnet_html.encode("utf-8"),
            headers={"content-type": "text/html; charset=utf-8"},
        )
    )
    scanner = SensitivePathScanner(http_client=client)
    findings = await scanner.scan("https://studentportal.silveroakuni.ac.in/UMSStudents/login.aspx")

    assert len(findings) == 0, f"Expected 0 findings on catch-all server, got: {[f.title for f in findings]}"


@pytest.mark.asyncio
async def test_real_githead_detected():
    """Mock server returns 200 with 'ref: refs/heads/main'.
    Assert: .git/HEAD finding IS produced.
    """
    responses = {
        "/.git/HEAD": MockHTTPResult(
            status=200,
            body=b"ref: refs/heads/main\n",
            headers={"content-type": "text/plain"},
        )
    }
    client = MockHTTPClient(
        default_response=MockHTTPResult(status=404, body=b"Not Found"),
        responses=responses,
    )
    scanner = SensitivePathScanner(http_client=client)
    findings = await scanner.scan("https://example.com")

    git_findings = [f for f in findings if ".git/HEAD" in f.title]
    assert len(git_findings) == 1
    assert git_findings[0].severity.lower() == "critical"
    assert "ref: refs/heads/" in git_findings[0].evidence or "refs/heads/main" in git_findings[0].evidence


@pytest.mark.asyncio
async def test_403_is_info_not_critical():
    """Mock server returns 403 for .git/HEAD.
    Assert: finding severity is 'Info' / 'info' not 'Critical'.
    """
    responses = {
        "/.git/HEAD": MockHTTPResult(
            status=403,
            body=b"Forbidden",
            headers={"content-type": "text/plain"},
        )
    }
    client = MockHTTPClient(
        default_response=MockHTTPResult(status=404, body=b"Not Found"),
        responses=responses,
    )
    scanner = SensitivePathScanner(http_client=client)
    findings = await scanner.scan("https://example.com")

    git_findings = [f for f in findings if ".git/HEAD" in f.title or "SENSITIVE-PATH-BLOCKED" in f.id]
    assert len(git_findings) == 1
    assert git_findings[0].severity.lower() == "info"
    assert git_findings[0].severity.lower() != "critical"
