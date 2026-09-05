"""Unit tests for Phase 9: External Surface & Reconnaissance Engine."""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from phantomscan.email_security import analyze_email
from phantomscan.http_client import HTTPResult, RobustHTTPClient
from phantomscan.modules.subdomain_takeover import SubdomainTakeoverDetector
from phantomscan.scope import Target, normalize_target


class TestReconSurface(unittest.TestCase):
    def test_email_security_root_domain(self):
        """PR-FP02: Email security resolution uses the root domain (eTLD+1)."""
        target = normalize_target("https://www.api.sub.example.co.uk")
        # Target host is sub.example.co.uk or www.api.sub.example.co.uk, but root domain is example.co.uk
        from phantomscan.scope import root_domain
        r_dom = root_domain(target.host)
        self.assertEqual(r_dom, "example.co.uk")


@pytest.mark.asyncio
async def test_subdomain_takeover_detection():
    """Detect dangling CNAME pointing to unclaimed S3 bucket."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.request = AsyncMock(
        return_value=HTTPResult(
            url="https://assets.mycompany.com",
            status=404,
            headers={"content-type": "application/xml"},
            cookies={},
            body=b"<?xml version='1.0'?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>",
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=50,
            content_type="application/xml",
        )
    )

    detector = SubdomainTakeoverDetector(http=mock_http)
    # Mock _get_cname to return s3.amazonaws.com endpoint
    detector._get_cname = AsyncMock(return_value="my-old-bucket.s3.us-east-1.amazonaws.com")

    findings = await detector.detect(["assets.mycompany.com"])
    assert len(findings) == 1
    assert findings[0]["id"] == "SUBDOMAIN-TAKEOVER"
    assert findings[0]["severity"] == "critical"
    assert "AWS S3" in findings[0]["evidence"]


@pytest.mark.asyncio
async def test_subdomain_takeover_claimed_service():
    """CNAME exists but service is active/claimed (signature absent) -> no finding."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.request = AsyncMock(
        return_value=HTTPResult(
            url="https://docs.mycompany.com",
            status=200,
            headers={"content-type": "text/html"},
            cookies={},
            body=b"<html><body><h1>Welcome to our Documentation!</h1></body></html>",
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=40,
            content_type="text/html",
        )
    )

    detector = SubdomainTakeoverDetector(http=mock_http)
    detector._get_cname = AsyncMock(return_value="mycompany.github.io")

    findings = await detector.detect(["docs.mycompany.com"])
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_email_security_local_target_skip():
    """PR-L01: Local/localhost target skips email security analysis."""
    local_target = Target(
        raw="http://localhost:8080",
        scheme="http",
        host="localhost",
        port=8080,
        target_type="ip",
        is_local=True,
    )
    obs, findings = await analyze_email(local_target)
    assert len(findings) == 0
    assert any("skipped" in o.name for o in obs)


@pytest.mark.asyncio
async def test_subdomain_takeover_netlify():
    """Detect dangling CNAME pointing to unclaimed Netlify site."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.request = AsyncMock(
        return_value=HTTPResult(
            url="https://landing.mycompany.com",
            status=404,
            headers={"content-type": "text/plain"},
            cookies={},
            body=b"Not Found - Request ID: 01HZY...",
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=50,
            content_type="text/plain",
        )
    )
    detector = SubdomainTakeoverDetector(http=mock_http)
    detector._get_cname = AsyncMock(return_value="my-old-site.netlify.app")

    findings = await detector.detect(["landing.mycompany.com"])
    assert len(findings) == 1
    assert findings[0]["id"] == "SUBDOMAIN-TAKEOVER"
    assert "Netlify" in findings[0]["evidence"]


@pytest.mark.asyncio
async def test_subdomain_takeover_vercel():
    """Detect dangling CNAME pointing to unclaimed Vercel deployment."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.request = AsyncMock(
        return_value=HTTPResult(
            url="https://preview.mycompany.com",
            status=404,
            headers={"content-type": "text/html"},
            cookies={},
            body=b"The deployment could not be found on Vercel",
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=50,
            content_type="text/html",
        )
    )
    detector = SubdomainTakeoverDetector(http=mock_http)
    detector._get_cname = AsyncMock(return_value="preview-app.vercel.app")

    findings = await detector.detect(["preview.mycompany.com"])
    assert len(findings) == 1
    assert findings[0]["id"] == "SUBDOMAIN-TAKEOVER"
    assert "Vercel" in findings[0]["evidence"]


if __name__ == "__main__":
    unittest.main()

