"""Regression: Header names must be matched case-insensitively (RFC 7230)."""

from __future__ import annotations

import pytest

from phantomscan.modules.header_analyzer import HeaderAnalyzer


def test_lowercase_headers_recognized():
    """Nginx/Go-style lowercase header names must be recognized."""
    headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
    }
    ha = HeaderAnalyzer(headers)

    assert ha.has_header("Content-Security-Policy") is True
    assert ha.has_header("Strict-Transport-Security") is True
    assert ha.has_header("X-Content-Type-Options") is True
    assert ha.has_header("X-Frame-Options") is True
    assert ha.has_header("Referrer-Policy") is True
    assert ha.has_header("Permissions-Policy") is True


def test_mixed_case_headers_recognized():
    """Mixed-case headers (common from some proxies) must work."""
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
    }
    ha = HeaderAnalyzer(headers)

    assert ha.has_header("content-security-policy") is True
    assert ha.has_header("STRICT-TRANSPORT-SECURITY") is True


def test_uppercase_headers_recognized():
    """Fully uppercase headers must be recognized."""
    headers = {"CONTENT-SECURITY-POLICY": "default-src 'self'"}
    ha = HeaderAnalyzer(headers)

    assert ha.has_header("Content-Security-Policy") is True


def test_get_header_case_insensitive():
    """get_header must return the value regardless of input casing."""
    headers = {"content-security-policy": "default-src 'self'"}
    ha = HeaderAnalyzer(headers)

    assert ha.get_header("Content-Security-Policy") == "default-src 'self'"
    assert ha.get_header("CONTENT-SECURITY-POLICY") == "default-src 'self'"


def test_missing_header_returns_false():
    """Missing headers must return False, not raise."""
    ha = HeaderAnalyzer({})
    assert ha.has_header("Content-Security-Policy") is False
    assert ha.get_header("Content-Security-Policy") is None


def test_analyze_security_headers_with_lowercase_keys():
    """analyze_security_headers must correctly recognize lowercase header keys
    and NOT flag them as missing."""
    from phantomscan.recon import analyze_security_headers

    headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
    }
    findings = analyze_security_headers("https://test.local", headers)

    assert len(findings) == 0, (
        f"All headers are present but {len(findings)} were flagged as missing: "
        f"{[f.evidence for f in findings]}"
    )
