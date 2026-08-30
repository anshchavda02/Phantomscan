"""Unit tests for Phase 11: Attack Path Synthesis, Exploitability Validation & Risk Narrative Engine."""

import unittest

import pytest

from phantomscan.modules.ai_narrative import AINarrativeReporter
from phantomscan.modules.attack_path import AttackPathBuilder
from phantomscan.modules.compliance import ComplianceReporter
from phantomscan.modules.vuln_chain import VulnChainEngine



@pytest.mark.asyncio
async def test_vuln_chain_synthesis():
    """Synthesize multi-step attack chain from atomic findings."""
    raw_findings = [
        {"id": "XSS-REFLECTED", "title": "Reflected Cross-Site Scripting", "category": "xss", "severity": "high"},
        {"id": "CSRF-MISSING", "title": "Missing CSRF Protection", "category": "csrf", "severity": "medium"},
    ]

    engine = VulnChainEngine()
    chains = await engine.run(
        base_url="https://example.com",
        observations=[],
        findings=raw_findings,
    )

    assert len(chains) >= 1
    assert any("CSRF + XSS" in c.get("title", "") for c in chains)
    assert any(c.get("severity") == "critical" for c in chains)


@pytest.mark.asyncio
async def test_attack_path_mermaid_generation():
    """Generate Mermaid.js attack graph from chain findings."""
    chain_findings = [
        {
            "id": "CHAIN-CSRF-XSS",
            "title": "Attack Chain: Account Takeover via CSRF + XSS",
            "category": "vuln-chain",
            "severity": "critical",
            "evidence": "1. Attacker crafts payload\n2. CSRF forced action\n3. Account compromised",
        }
    ]

    builder = AttackPathBuilder()
    results = await builder.run(
        base_url="https://example.com",
        observations=[],
        findings=chain_findings,
    )

    assert len(results) == 1
    assert results[0]["id"] == "ATTACK-PATH-GRAPH"
    assert "graph TD" in results[0]["evidence"]
    assert "Attacker -->" in results[0]["evidence"]


@pytest.mark.asyncio
async def test_compliance_mapping():
    """Map findings to OWASP Top 10 and PCI DSS v4."""
    findings = [
        {"id": "SQLI-ERROR", "title": "SQL Injection Detected", "category": "injection", "severity": "critical"},
        {"id": "IDOR-BOLA", "title": "Insecure Direct Object Reference", "category": "idor", "severity": "high"},
    ]

    reporter = ComplianceReporter()
    results = await reporter.run(
        base_url="https://example.com",
        observations=[],
        findings=findings,
    )

    assert len(results) >= 1
    evidence = results[0]["evidence"]
    assert "OWASP Top 10" in evidence
    assert "A01:2021" in evidence or "A03:2021" in evidence



@pytest.mark.asyncio
async def test_ai_narrative_generation():
    """Generate executive narrative summary from findings."""
    findings = [
        {"id": "SQLI-ERROR", "title": "SQL Injection", "category": "injection", "severity": "critical"},
        {"id": "SSL-WEAK", "title": "Weak TLS Cipher", "category": "ssl", "severity": "low"},
    ]

    reporter = AINarrativeReporter()
    results = await reporter.run(
        base_url="https://example.com",
        observations=[],
        findings=findings,
    )

    assert len(results) == 1
    assert results[0]["id"] == "AI-NARRATIVE-SUMMARY"
    assert "PhantomScan Advanced Security assessment" in results[0]["evidence"]
    assert "Injection" in results[0]["evidence"]


if __name__ == "__main__":
    unittest.main()
