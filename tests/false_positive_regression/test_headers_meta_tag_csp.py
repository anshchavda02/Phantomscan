"""Regression: CSP delivered via <meta> tag must be recognized."""

from __future__ import annotations

import pytest

from phantomscan.modules.header_analyzer import detect_csp
from phantomscan.recon import analyze_security_headers


def test_csp_meta_tag_detected():
    """CSP via <meta http-equiv> must be recognized as present."""
    html_body = (
        '<html><head>'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'self'; script-src 'self'\">"
        '</head><body></body></html>'
    )
    result = detect_csp({}, html_body)

    assert result.present is True
    assert result.source == "meta_tag"
    assert "default-src" in result.policy


def test_csp_meta_tag_reversed_attributes():
    """CSP meta tag with content before http-equiv must also work."""
    html_body = (
        '<html><head>'
        "<meta content=\"default-src 'self'\" "
        'http-equiv="Content-Security-Policy">'
        '</head><body></body></html>'
    )
    result = detect_csp({}, html_body)

    assert result.present is True
    assert result.source == "meta_tag"


def test_csp_header_preferred_over_meta():
    """HTTP header CSP must take precedence over meta tag."""
    headers = {"Content-Security-Policy": "default-src 'none'"}
    html_body = (
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'self'\">"
    )
    result = detect_csp(headers, html_body)

    assert result.present is True
    assert result.source == "http_header"
    assert result.policy == "default-src 'none'"


def test_csp_meta_tag_not_flagged_as_missing():
    """analyze_security_headers must NOT flag CSP as missing when delivered via meta tag."""
    headers = {
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
    }
    html_body = (
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'self'\">"
    )
    findings = analyze_security_headers("https://test.local", headers, html_body)

    # CSP is delivered via meta tag, so it should NOT appear as missing
    assert len(findings) == 0, (
        f"CSP is present via meta tag but was flagged: {findings}"
    )


def test_no_csp_anywhere_is_flagged():
    """When CSP is absent from both header and body, it must be flagged."""
    headers = {
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
    }
    findings = analyze_security_headers("https://test.local", headers, "")

    assert len(findings) == 1
    assert "Content-Security-Policy" in findings[0].evidence


def test_csp_meta_frame_ancestors_note():
    """CSP via meta tag should include a note about frame-ancestors limitation."""
    html_body = (
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'self'; frame-ancestors 'none'\">"
    )
    result = detect_csp({}, html_body)

    assert result.present is True
    assert "meta tag" in result.note.lower() or "meta-tag" in result.note.lower()
