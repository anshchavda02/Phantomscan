"""Regression: Security header finding severity must never exceed Medium."""

from __future__ import annotations

import pytest

from phantomscan.recon import analyze_security_headers


def test_severity_never_exceeds_medium():
    """Even with ALL headers missing, severity must cap at 'medium'."""
    headers: dict[str, str] = {}  # no security headers at all
    findings = analyze_security_headers("https://test.local", headers)

    assert len(findings) == 1
    assert findings[0].severity in ("low", "medium"), (
        f"Header finding severity was '{findings[0].severity}' — "
        f"must never exceed 'medium'"
    )


def test_severity_is_low_when_only_minor_missing():
    """When only low-severity headers are missing, severity must be 'low'."""
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        # Only referrer-policy and permissions-policy missing → low severity
    }
    findings = analyze_security_headers("https://test.local", headers)

    if findings:
        assert findings[0].severity == "low", (
            f"Only minor headers missing but severity was '{findings[0].severity}'"
        )


def test_severity_is_medium_when_hsts_missing():
    """Missing HSTS should produce 'medium' severity (the max ceiling)."""
    headers = {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        # HSTS intentionally absent
    }
    findings = analyze_security_headers("https://test.local", headers)

    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_severity_never_critical():
    """Security headers finding must NEVER be 'critical'."""
    headers: dict[str, str] = {}
    findings = analyze_security_headers("https://test.local", headers)

    for f in findings:
        assert f.severity != "critical", (
            "Header finding must never be 'critical'"
        )


def test_severity_never_high():
    """Security headers finding must NEVER be 'high'."""
    headers: dict[str, str] = {}
    findings = analyze_security_headers("https://test.local", headers)

    for f in findings:
        assert f.severity != "high", (
            "Header finding must never be 'high'"
        )
