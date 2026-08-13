"""Regression: frame-ancestors in CSP must suppress X-Frame-Options finding."""

from __future__ import annotations

import pytest

from phantomscan.modules.header_analyzer import CSPResult, check_frame_protection
from phantomscan.recon import analyze_security_headers


def test_frame_ancestors_suppresses_xfo_finding():
    """CSP frame-ancestors present means X-Frame-Options is NOT needed."""
    headers = {
        "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        # NOTE: X-Frame-Options intentionally absent
    }
    findings = analyze_security_headers("https://test.local", headers)

    # Should produce zero findings — frame-ancestors covers clickjacking
    assert len(findings) == 0, (
        f"frame-ancestors is present but X-Frame-Options was still flagged: "
        f"{[f.evidence for f in findings]}"
    )


def test_xfo_present_no_frame_ancestors_is_fine():
    """X-Frame-Options without frame-ancestors is still valid protection."""
    csp_result = CSPResult(present=True, source="http_header", policy="default-src 'self'")
    result = check_frame_protection(
        {"x-frame-options": "DENY"}, csp_result
    )
    assert result.protected is True
    assert "X-Frame-Options" in result.mechanism


def test_neither_xfo_nor_frame_ancestors_flagged():
    """Missing both XFO and frame-ancestors must be flagged as unprotected."""
    csp_result = CSPResult(present=True, source="http_header", policy="default-src 'self'")
    result = check_frame_protection({}, csp_result)
    assert result.protected is False


def test_frame_ancestors_in_meta_tag():
    """frame-ancestors in meta-tag CSP should also suppress XFO finding.

    Note: per spec, meta-tag CSP cannot enforce frame-ancestors, but the
    detection should still recognise the intent.
    """
    csp_result = CSPResult(
        present=True,
        source="meta_tag",
        policy="default-src 'self'; frame-ancestors 'self'",
        frame_ancestors="frame-ancestors 'self'",
    )
    result = check_frame_protection({}, csp_result)
    assert result.protected is True


def test_no_duplicate_frame_findings():
    """Must never produce TWO separate findings for XFO and frame-ancestors."""
    headers = {
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        # Both CSP and XFO absent
    }
    findings = analyze_security_headers("https://test.local", headers)

    # Should be exactly 1 grouped finding, containing BOTH CSP and frame protection
    assert len(findings) == 1, (
        f"Expected 1 grouped finding, got {len(findings)}"
    )
    # The evidence should mention frame protection, not have a separate finding
    evidence = findings[0].evidence
    assert "X-Frame-Options" in evidence or "frame-ancestors" in evidence
