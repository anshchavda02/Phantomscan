"""Regression: Missing headers must produce exactly ONE grouped Finding."""

from __future__ import annotations

import pytest

from phantomscan.recon import analyze_security_headers


def test_single_finding_with_all_missing():
    """With all headers missing, must produce exactly 1 Finding, not 6+."""
    headers: dict[str, str] = {"content-type": "text/html"}
    findings = analyze_security_headers("https://test.local", headers)

    assert len(findings) == 1, (
        f"Expected exactly 1 grouped finding, got {len(findings)}"
    )
    assert findings[0].id == "SECURITY-HEADERS-GROUPED"


def test_single_finding_with_some_missing():
    """With some headers missing, must still produce exactly 1 Finding."""
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-type": "text/html",
        # CSP, XCTO, XFO, Referrer-Policy, Permissions-Policy all missing
    }
    findings = analyze_security_headers("https://test.local", headers)

    assert len(findings) == 1, (
        f"Expected exactly 1 grouped finding, got {len(findings)}"
    )


def test_zero_findings_when_all_present():
    """With all headers present, must produce 0 findings."""
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
    }
    findings = analyze_security_headers("https://test.local", headers)

    assert len(findings) == 0, (
        f"All headers present but {len(findings)} findings produced"
    )


def test_grouped_finding_has_all_missing_in_evidence():
    """The grouped finding must list all missing headers in its evidence field."""
    headers: dict[str, str] = {}
    findings = analyze_security_headers("https://test.local", headers)

    assert len(findings) == 1
    evidence = findings[0].evidence
    assert "HSTS" in evidence
    assert "Content-Security-Policy" in evidence
    assert "X-Content-Type-Options" in evidence
