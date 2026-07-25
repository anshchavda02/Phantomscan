"""Unit tests for the advanced modules orchestrator and specific modules."""

import asyncio
from typing import Any

import pytest
from phantomscan.advanced_scan import run_advanced_modules
from phantomscan.http_client import RobustHTTPClient


class MockResponse:
    def __init__(self, status: int, text_content: str, headers: dict = None, cookies: dict = None):
        self.status = status
        self._text = text_content
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.body = text_content.encode()

    def text(self) -> str:
        return self._text


class MockHTTPClient:
    async def get(self, url: str, **kwargs) -> MockResponse:
        return MockResponse(200, "mocked get response")

    async def post(self, url: str, **kwargs) -> MockResponse:
        return MockResponse(200, "mocked post response")

    async def request(self, method: str, url: str, **kwargs) -> MockResponse:
        return MockResponse(200, "mocked request response")

    async def send_raw(self, host: str, payload: bytes | str, **kwargs) -> Any:
        class MockRawResponse:
            response_time_ms = 100
            status = 200
        return MockRawResponse()

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


@pytest.mark.asyncio
async def test_run_advanced_modules_basic():
    """Test that the orchestrator can run the advanced modules without crashing."""
    target = "example.com"
    base_url = "https://example.com"
    observations = [{"name": "http_url", "value": "https://example.com/api/test"}]
    findings = [{"id": "OLD-FINDING", "title": "Old Finding"}]
    
    mock_http = MockHTTPClient()
    
    # We will just run a small subset to ensure the pipeline works
    # Using modules that don't do complex network stuff immediately
    new_findings, new_obs = await run_advanced_modules(
        target,
        base_url,
        mock_http,  # type: ignore
        observations,
        findings,
        profile="business_logic,idor,vuln_chain",
    )
    
    # It shouldn't crash. It might return 0 findings because the mock doesn't trigger the specific vuln conditions.
    assert isinstance(new_findings, list)
    assert isinstance(new_obs, list)


@pytest.mark.asyncio
async def test_vuln_chain_engine():
    """Test that the vuln chain engine correctly correlates findings."""
    from phantomscan.modules.vuln_chain import VulnChainEngine
    
    engine = VulnChainEngine()
    
    # Provide findings that should trigger the "Account Takeover via CSRF + XSS" chain
    test_findings = [
        {"id": "XSS-REFLECTED", "title": "Reflected Cross-Site Scripting", "severity": "medium"},
        {"id": "CSRF-MISSING", "title": "Missing Cross-Site Request Forgery Token", "severity": "medium"},
        {"id": "UNRELATED", "title": "Some Unrelated Finding", "severity": "low"}
    ]
    
    chain_findings = engine.analyze_chains(test_findings)
    
    assert len(chain_findings) >= 1
    assert any("CSRF" in f["title"] and "XSS" in f["title"] for f in chain_findings)
    assert chain_findings[0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_compliance_reporter():
    """Test that the compliance reporter correctly maps findings."""
    from phantomscan.modules.compliance import ComplianceReporter
    
    reporter = ComplianceReporter()
    
    test_findings = [
        {"id": "SQLI", "title": "SQL Injection Detected", "category": "injection", "evidence": "SQLi found"}
    ]
    
    results = reporter.generate_compliance_report(test_findings, "example.com")
    
    assert len(results) == 3  # OWASP, PCI, NIST
    
    owasp = next(r for r in results if "OWASP" in r["title"])
    assert "A03:2021" in owasp["evidence"]
    assert "FAIL" in owasp["evidence"]


@pytest.mark.asyncio
async def test_ai_narrative_reporter():
    """Test the AI narrative generation."""
    from phantomscan.modules.ai_narrative import AINarrativeReporter
    
    reporter = AINarrativeReporter()
    
    test_findings = [
        {"id": "SQLI", "title": "SQL Injection Detected", "category": "injection", "severity": "critical"}
    ]
    
    narrative = reporter.generate_narrative(test_findings, "example.com")
    
    assert "example.com identified 1 vulnerabilities" in narrative
    assert "CRITICAL" in narrative
    assert "Injection vulnerabilities" in narrative
