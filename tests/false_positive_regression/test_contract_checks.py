"""Contract tests for the 7 canonical false positive regression rules (FP-001 to FP-007).

These tests ensure that known regression flaws permanently remain fixed:
- FP-001: .git/HEAD found via /page.aspx/.git/HEAD (catch-all routing)
- FP-002: SPF Missing reported for www.google.com
- FP-003: No Rate Limiting as Medium for Cloudflare-protected target
- FP-004: Seagate CVE matched to TLS cipher suite
- FP-005: Google.com scored 20/100 (FP filter after score engine)
- FP-006: WAF block page reported as SQL injection confirmed
- FP-007: Expired tracking cookie flagged as security issue
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any
import pytest

from modules.catch_all_detector import CatchAllDetector
from modules.sensitive_path_scanner import SensitivePathScanner
from phantomscan.modules.sqli_detector import SQLiDetector
from phantomscan.modules.finding_gate import gate_finding
from phantomscan.postprocess import load_known_platform, score, post_process
from phantomscan.scope import root_domain, normalize_target
from tests.false_positive_regression.conftest import MockHTTPClient, MockHTTPResult


@pytest.mark.asyncio
async def test_sensitive_path_aspnet_catchall():
    """FP-001: .git/HEAD found via catch-all routing must be suppressed."""
    aspnet_html = (
        "<!DOCTYPE html><html><head><title>Portal Login</title></head>"
        "<body><form action='/login.aspx' method='POST'>"
        "<input type='text' name='username'>"
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
    findings = await scanner.scan("https://example.com/app/login.aspx")

    # Catch-all HTML response on sensitive path probe must produce ZERO findings
    assert len(findings) == 0, f"Expected 0 findings on catch-all server, got: {[f.title for f in findings]}"


def test_email_security_uses_root_domain():
    """FP-002: Email security checks always evaluate the root domain (eTLD+1)."""
    target_www = "www.google.com"
    r_dom = root_domain(target_www)
    assert r_dom == "google.com", f"Expected google.com, got {r_dom}"

    # Also verify complex multi-level TLD
    target_complex = "api.sub.example.co.uk"
    r_dom_complex = root_domain(target_complex)
    assert r_dom_complex == "example.co.uk", f"Expected example.co.uk, got {r_dom_complex}"

    # Test post_process suppression of SPF/DMARC on subdomains
    data_dir = Path(__file__).parent.parent.parent / "data"
    findings = [
        {
            "id": "SPF-MISSING",
            "title": "SPF Missing",
            "severity": "medium",
            "confidence": "high",
            "category": "email",
            "target": "www.google.com",
            "evidence": "No SPF record on subdomain",
            "module": "email_security",
            "verification_method": "external_verification",
        }
    ]
    clean, suppressed, _ = post_process(
        findings=findings,
        observations=[{"name": "root_domain", "value": "google.com"}],
        data_dir=data_dir,
        target_host="www.google.com",
        include_medium=True,
        include_low=True,
    )
    assert len(clean) == 0, "SPF Missing on www.google.com was not suppressed"


def test_rate_limit_passive_only():
    """FP-003: Rate limiting absence is passive-only and never High/Medium with WAF/CDN."""
    # When rate limit headers are absent, finding must not be Medium if WAF or CDN is present
    data_dir = Path(__file__).parent.parent.parent / "data"
    findings = [
        {
            "id": "NO-RATE-LIMIT",
            "title": "No Rate Limiting Detected",
            "severity": "medium",
            "confidence": "medium",
            "category": "anti-automation",
            "target": "https://example.com",
            "evidence": "No rate limiting headers found in passive inspection",
            "module": "anti_automation",
            "verification_method": "passive_observation",
        }
    ]
    observations = [
        {"name": "waf", "value": "Cloudflare WAF"},
        {"name": "cdn", "value": "Cloudflare CDN"},
    ]

    clean, suppressed, _ = post_process(
        findings=findings,
        observations=observations,
        data_dir=data_dir,
        target_host="example.com",
        include_medium=True,
        include_low=True,
    )

    # Must be suppressed because Cloudflare provides edge rate limiting
    assert len(clean) == 0
    assert len(suppressed) >= 1


def test_cve_cpe_exact_match_only():
    """FP-004: CVE lookup must match technology CPE; keyword mismatch must be suppressed."""
    data_dir = Path(__file__).parent.parent.parent / "data"

    # Simulated Seagate CVE erroneously keyword-matched to cipher suite
    findings = [
        {
            "id": "CVE-2022-12345",
            "title": "Seagate Hard Drive Firmware Vulnerability",
            "severity": "high",
            "confidence": "low",
            "category": "cve",
            "target": "https://example.com",
            "evidence": "Keyword match on 'Drive' in cipher suite",
            "module": "cve_lookup",
            "cvss": 0.0,
            "verification_method": "external_verification",
        }
    ]

    clean, suppressed, _ = post_process(
        findings=findings,
        observations=[{"name": "server", "value": "nginx"}],
        data_dir=data_dir,
        target_host="example.com",
        include_medium=True,
        include_low=True,
    )

    # CVSS 0.0 or low confidence / vendor mismatch suppressed
    assert len(clean) == 0


def test_fp_runs_before_score():
    """FP-005: FP PostProcessor must run BEFORE Score Engine so google.com scores >= 75."""
    data_dir = Path(__file__).parent.parent.parent / "data"

    # Simulate raw findings that google.com platform profile suppresses
    raw_findings = [
        {"id": "NO-WAF", "title": "No WAF Detected", "severity": "medium", "confidence": "high", "category": "infra", "evidence": "No WAF header found", "module": "headers", "verification_method": "passive_observation"},
        {"id": "NO-MFA", "title": "No MFA Detected", "severity": "medium", "confidence": "high", "category": "auth", "evidence": "No MFA detected", "module": "auth", "verification_method": "passive_observation"},
        {"id": "NO-RL", "title": "No Rate Limiting Detected", "severity": "medium", "confidence": "high", "category": "rate-limit", "evidence": "No rate limiting header", "module": "rate_limit", "verification_method": "passive_observation"},
        {"id": "MISSING-HSTS", "title": "Missing HSTS Header", "severity": "medium", "confidence": "high", "category": "headers", "evidence": "Missing HSTS header", "module": "headers", "verification_method": "passive_observation"},
    ]

    # Run post_process first
    clean_findings, suppressed_findings, _ = post_process(
        findings=raw_findings,
        observations=[{"name": "server", "value": "Google Frontend"}],
        data_dir=data_dir,
        target_host="google.com",
        include_medium=True,
        include_low=True,
    )

    # Google.com suppresses these findings
    assert len(suppressed_findings) >= 3

    # Calculate score on clean findings
    platform = load_known_platform(data_dir, "google.com")
    final_score = score(clean_findings, observations=[], platform=platform)
    assert final_score >= 75, f"Google.com score was {final_score}, expected >= 75"


@pytest.mark.asyncio
async def test_sqli_no_false_positive_on_waf_block():
    """FP-006: WAF block pages must not be flagged as SQL injection."""
    waf_response = MockHTTPResult(
        status=403,
        body=b"<html><body><h1>Access Denied</h1><p>Request blocked by ModSecurity Action.</p></body></html>",
        headers={"content-type": "text/html"},
    )
    client = MockHTTPClient(default_response=waf_response)
    detector = SQLiDetector(http=client)

    result = await detector._test_error_based("http://example.com/search", "q", "test")
    assert result is None, "WAF block page was incorrectly flagged as SQL injection"


def test_cookie_expired_skipped():
    """FP-007: Expired cookies and analytics tracking cookies are skipped or downgraded."""
    data_dir = Path(__file__).parent.parent.parent / "data"

    # Expired cookie finding
    findings = [
        {
            "id": "COOKIE-MISSING-SECURE",
            "title": "Cookie Missing Secure Flag: old_session",
            "severity": "medium",
            "confidence": "high",
            "category": "cookie",
            "target": "https://example.com",
            "evidence": "Cookie expired in past date: Expires=Thu, 01 Jan 2020 00:00:00 GMT",
            "module": "headers",
            "verification_method": "passive_observation",
        },
        {
            "id": "COOKIE-MISSING-HTTPONLY",
            "title": "Cookie missing HttpOnly flag: _ga",
            "severity": "medium",
            "confidence": "high",
            "category": "cookie",
            "target": "https://example.com",
            "evidence": "Analytics tracking cookie _ga missing HttpOnly flag",
            "module": "headers",
            "verification_method": "passive_observation",
        },
    ]

    clean, suppressed, _ = post_process(
        findings=findings,
        observations=[],
        data_dir=data_dir,
        target_host="example.com",
        include_medium=True,
        include_low=True,
    )

    # Expired cookie must be suppressed (Rule 7)
    assert any("Expired cookie" in s.get("suppression_reason", "") for s in suppressed)

    # Analytics cookie (_ga) must be downgraded to Info (Rule 8)
    ga_finding = [f for f in clean if "_ga" in f.get("title", "")][0]
    assert ga_finding["severity"] == "info"

