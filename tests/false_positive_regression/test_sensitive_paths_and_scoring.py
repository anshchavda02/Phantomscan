"""Regression tests for sensitive path false positives, catch-all detection, URL construction, and known-platform scoring."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
import pytest

from modules.catch_all_detector import CatchAllDetector, CatchAllResult
from modules.sensitive_path_scanner import SensitivePathScanner
from modules.response_validator import ResponseContentValidator
from modules.dir_enum import DirectoryEnumerator
from modules.env_debug_scanner import EnvDebugScanner
from modules.orchestrator import ScanOrchestrator
from modules.score_engine import calculate_score, Score
from phantomscan.postprocess import load_known_platform, score, grade, post_process
from phantomscan.scope import root_domain
from tests.false_positive_regression.conftest import MockHTTPClient, MockHTTPResult


@pytest.mark.asyncio
async def test_sensitive_path_aspnet_catchall():
    """Mock ASP.NET server returning 200+HTML for any path.
    Assert: zero sensitive path findings generated.
    """
    aspnet_html = (
        "<!DOCTYPE html><html><head><title>Student Portal Login</title></head>"
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

    # Assert: zero sensitive path findings generated
    assert len(findings) == 0, (
        f"Expected 0 sensitive path findings on ASP.NET catch-all server, got {len(findings)}: "
        f"{[f.title for f in findings]}"
    )


@pytest.mark.asyncio
async def test_sensitive_path_real_githead():
    """Mock server returning 200 + 'ref: refs/heads/main'.
    Assert: .git/HEAD finding IS generated (true positive).
    """
    responses = {
        "/.git/HEAD": MockHTTPResult(
            status=200,
            body=b"ref: refs/heads/main\n",
            headers={"content-type": "text/plain"},
        )
    }

    # All other paths return 404
    client = MockHTTPClient(
        default_response=MockHTTPResult(status=404, body=b"Not Found"),
        responses=responses,
    )

    scanner = SensitivePathScanner(http_client=client)
    findings = await scanner.scan("https://example.com")

    git_findings = [f for f in findings if ".git/HEAD" in f.title]
    assert len(git_findings) == 1
    assert git_findings[0].severity == "critical"
    assert git_findings[0].confidence == "high"
    assert git_findings[0].verification_method == "baseline_differential"


@pytest.mark.asyncio
async def test_sensitive_path_uses_web_root():
    """Assert probe URL is always scheme://host/path.
    Never scheme://host/existing/page/path.
    """
    client = MockHTTPClient(
        default_response=MockHTTPResult(status=404, body=b"Not Found")
    )

    scanner = SensitivePathScanner(http_client=client)
    input_url = "https://studentportal.silveroakuni.ac.in/UMSStudents/login.aspx"
    await scanner.scan(input_url)

    assert len(client.request_log) > 0
    for req in client.request_log:
        url = req["url"]
        # Must NEVER contain the discovered subpage path
        assert "/UMSStudents/login.aspx" not in url, (
            f"Probe URL incorrectly included page path: {url}"
        )
        assert url.startswith("https://studentportal.silveroakuni.ac.in/"), (
            f"Probe URL did not use web root: {url}"
        )


@pytest.mark.asyncio
async def test_catchall_detection():
    """Mock server returning 200 for random UUID path.
    Assert: catch_all.has_catch_all == True.
    """
    custom_404_html = (
        "<!DOCTYPE html><html><body>"
        "<h1>Page Not Found</h1>"
        "<p>The requested resource could not be found, but here is our homepage.</p>"
        "<div>" + ("x" * 200) + "</div>"
        "</body></html>"
    )

    client = MockHTTPClient(
        default_response=MockHTTPResult(
            status=200,
            body=custom_404_html.encode("utf-8"),
            headers={"content-type": "text/html"},
        )
    )

    detector = CatchAllDetector(http_client=client)
    result = await detector.detect("https://example.com/some/path")

    assert result.has_catch_all is True
    assert result.baseline_body_length == len(custom_404_html)


def test_google_score_above_75():
    """Run scoring on google.com known-platform profile.
    Assert: final score >= 75.
    """
    data_dir = Path(__file__).parent.parent.parent / "data"
    platform = load_known_platform(data_dir, "google.com")
    assert platform is not None
    assert platform.get("minimum_score") == 75

    # Even with an empty scan or completeness penalties, platform minimum guarantees >= 75
    clean_findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = [
        {"name": "http_error", "value": "connection timeout"},
        {"name": "tls_error", "value": "unverified"},
    ]

    calculated = score(clean_findings, observations, platform=platform)
    assert calculated >= 75, f"Expected google.com score >= 75, got {calculated}"

    # Also test via calculate_score wrapper
    score_obj = calculate_score(clean_findings, observations=observations, platform=platform)
    assert score_obj.value >= 75
    assert score_obj.grade in ("A+", "A", "B")


def test_fp_runs_before_score():
    """Assert orchestrator execution order:
    fp_postprocessor called before score_engine.
    """
    data_dir = Path(__file__).parent.parent.parent / "data"
    orchestrator = ScanOrchestrator(data_dir=data_dir)

    raw_findings = [
        {
            "id": "WAF-MISSING",
            "title": "No WAF Detected",
            "severity": "medium",
            "confidence": "high",
            "evidence": "No WAF signatures found.",
        }
    ]
    observations = [
        {"name": "open_tcp_ports", "value": [80, 443], "source": "python-portscan"},
        {"name": "ssl_grade", "value": "A+", "source": "python-tls"},
    ]

    clean_findings, suppressed, score_obj = orchestrator.run_pipeline(
        raw_findings=raw_findings,
        observations=observations,
        target_host="google.com",
    )

    # Assert execution order recorded
    assert orchestrator.execution_order == ["fp_postprocessor", "score_engine"]
    # WAF missing was suppressed by known platform
    assert len(clean_findings) == 0
    assert len(suppressed) == 1
    # Score is high because suppressed finding did not penalize score
    assert score_obj.value >= 75


@pytest.mark.asyncio
async def test_env_debug_scanner_rejects_html_catchall():
    """EnvDebugScanner should ignore 200 OK responses with HTML catch-all content."""
    html_body = "<html><body><h1>Sign In</h1><form></form></body></html>"
    client = MockHTTPClient(
        default_response=MockHTTPResult(
            status=200,
            body=html_body.encode("utf-8"),
            headers={"content-type": "text/html"},
        )
    )

    scanner = EnvDebugScanner(http=client)
    findings = await scanner.scan("https://target.com/login.aspx")
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_dir_enum_rejects_html_catchall():
    """DirectoryEnumerator should ignore 200 OK responses with HTML catch-all content."""
    html_body = "<html><body><h1>Error</h1><p>Not found</p><div></div></body></html>"
    client = MockHTTPClient(
        default_response=MockHTTPResult(
            status=200,
            body=html_body.encode("utf-8"),
            headers={"content-type": "text/html"},
        )
    )

    enumerator = DirectoryEnumerator(http_client=client)
    finding = await enumerator.probe_directory("https://target.com/app/login", "/admin/")
    assert finding is None
