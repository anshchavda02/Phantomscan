"""Unit tests for Phase 14: Automated Remediation Engine, CI/CD Pipeline & GitHub Security Advisories Integration."""

import unittest
from unittest.mock import AsyncMock, MagicMock

import pytest

from phantomscan.http_client import HTTPResult, RobustHTTPClient
from phantomscan.modules.remediation_verifier import RemediationVerifier
from phantomscan.modules.ticketing import TicketConfig, TicketingIntegration


class TestRemediationVerifier(unittest.TestCase):
    def test_hmac_token_lifecycle(self):
        """HMAC token generates and validates correctly."""
        finding_id = "FINDING-SQLI-12345"
        token = RemediationVerifier.generate_token(finding_id)
        self.assertTrue(RemediationVerifier.validate_token(finding_id, token))
        self.assertFalse(RemediationVerifier.validate_token(finding_id, "invalid_token_99"))

    def test_verify_link_generation(self):
        """Verification link format."""
        verifier = RemediationVerifier()
        link = verifier.generate_verify_link("FINDING-XSS-999")
        self.assertIn("http://localhost:8420/verify?finding=FINDING-XSS-999&token=", link)


@pytest.mark.asyncio
async def test_remediation_status_resolved():
    """Endpoint no longer contains vulnerability evidence -> RESOLVED."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(
        return_value=HTTPResult(
            url="https://example.com/api/users",
            status=200,
            headers={"content-type": "application/json"},
            cookies={},
            body=b'{"status": "ok", "users": []}',
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=25,
            content_type="application/json",
        )
    )

    verifier = RemediationVerifier(http=mock_http)
    result = await verifier.verify_finding(
        {"id": "SQLI-1", "evidence": "SQL syntax error in database query"},
        "https://example.com/api/users",
    )
    assert result.status == "RESOLVED"


@pytest.mark.asyncio
async def test_remediation_status_still_present():
    """Endpoint still contains vulnerability evidence -> STILL_PRESENT."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.get = AsyncMock(
        return_value=HTTPResult(
            url="https://example.com/api/users",
            status=500,
            headers={"content-type": "text/html"},
            cookies={},
            body=b'<html><body>SQL syntax error in database query</body></html>',
            raw_set_cookies=[],
            redirect_chain=[],
            response_time_ms=25,
            content_type="text/html",
        )
    )

    verifier = RemediationVerifier(http=mock_http)
    result = await verifier.verify_finding(
        {"id": "SQLI-1", "evidence": "SQL syntax error in database query"},
        "https://example.com/api/users",
    )
    assert result.status == "STILL_PRESENT"


@pytest.mark.asyncio
async def test_ticketing_integration_filter():
    """Filter by minimum severity for Jira/Slack notifications."""
    mock_http = MagicMock(spec=RobustHTTPClient)
    mock_http.post = AsyncMock(return_value={"status": 200})

    integration = TicketingIntegration(http=mock_http)
    integration.create_jira_ticket = AsyncMock(return_value=MagicMock(status="created"))

    findings = [
        {"id": "F-1", "title": "SQLi", "severity": "critical"},
        {"id": "F-2", "title": "Info Header", "severity": "info"},
    ]

    config = TicketConfig(provider="jira", min_severity=("critical", "high"))
    results = await integration.create_tickets(findings, config)
    assert len(results) == 1
    integration.create_jira_ticket.assert_called_once()


if __name__ == "__main__":
    unittest.main()
