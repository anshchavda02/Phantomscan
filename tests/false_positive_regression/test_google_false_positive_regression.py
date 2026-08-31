"""False-Positive Regression Tests for Google.com and modern SPA scan accuracy.

Covers:
1. SSTI multi-stage dynamic math verification (no false flags from coincidental numbers in HTML).
2. JS Analyzer public client key classification (AIza... keys as Low/Info public IDs vs High private secrets).
3. Supply-chain library version extraction without single-dot matches.
4. IDOR / BOLA baseline differential checks against HTML pages.
5. Compliance & AI Narrative clean finding filtering.
"""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

from phantomscan.http_client import RobustHTTPClient, HTTPResult
from phantomscan.injection_target import InjectionTarget
from phantomscan.js_analyzer import JSRouteExtractor
from phantomscan.modules.compliance import ComplianceReporter
from phantomscan.modules.ai_narrative import AINarrativeReporter
from phantomscan.modules.idor_detector import IDORDetector
from phantomscan.modules.ssti_detector import SSTIDetector
from phantomscan.modules.supply_chain import SupplyChainAnalyzer


# ── 1. SSTI Multi-Stage Dynamic Math Verification ─────────────────────────────

@pytest.mark.asyncio
async def test_ssti_rejects_coincidental_numbers_in_dynamic_html():
    """Verify that SSTI detector does not trigger when dynamic responses happen to contain numbers."""
    http = MagicMock(spec=RobustHTTPClient)

    # Baseline response (no 49, no random products)
    baseline_resp = MagicMock(spec=HTTPResult)
    baseline_resp.text.return_value = "<html><body>Google Search Preferences Version 100</body></html>"
    baseline_resp.status = 200

    # Probe response: contains random numbers like '49' and a timestamp, but doesn't compute math
    probe_resp = MagicMock(spec=HTTPResult)
    probe_resp.text.return_value = "<html><body>Preferences saved at timestamp 1740949000 with offset 49</body></html>"
    probe_resp.status = 200

    http.get = AsyncMock(side_effect=[baseline_resp, probe_resp, probe_resp, probe_resp, probe_resp, probe_resp, probe_resp])

    detector = SSTIDetector(http=http)
    target = InjectionTarget(
        url="https://www.google.com/setprefs",
        method="GET",
        param_name="sig",
        original_value="0_test",
        all_params={"sig": "0_test", "hl": "en"},
    )

    result = await detector._test_ssti(target, "sig", "0_test")
    assert result is None, "SSTI detector falsely triggered on coincidental numbers in HTML"


@pytest.mark.asyncio
async def test_ssti_confirms_genuine_template_evaluation():
    """Verify that SSTI detector confirms genuine mathematical evaluation across two stages."""
    http = MagicMock(spec=RobustHTTPClient)

    baseline_resp = MagicMock(spec=HTTPResult)
    baseline_resp.text.return_value = "<html>Hello Guest</html>"
    baseline_resp.status = 200

    async def mock_get(url, **kwargs):
        resp = MagicMock(spec=HTTPResult)
        resp.status = 200
        # If expression is Jinja math, dynamically evaluate and reflect
        import re
        from urllib.parse import unquote_plus
        raw_url = unquote_plus(url)
        m = re.search(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", raw_url)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            resp.text.return_value = f"<html>Result: {a * b}</html>"
        else:
            resp.text.return_value = "<html>Hello Guest</html>"
        return resp

    http.get = AsyncMock(side_effect=mock_get)

    detector = SSTIDetector(http=http)
    target = InjectionTarget(
        url="https://vulnerable.local/profile",
        method="GET",
        param_name="name",
        original_value="guest",
        all_params={"name": "guest"},
    )

    result = await detector._test_ssti(target, "name", "guest")
    assert result is not None, "SSTI detector failed to confirm genuine template evaluation"
    assert result["id"] == "SSTI-INJECTION"
    assert result["severity"] == "critical"
    assert "Confirmation Probe 2:" in result["evidence"]


# ── 2. JS Secret vs Public Identifier Classification ──────────────────────────

@pytest.mark.asyncio
async def test_js_analyzer_classifies_google_api_key_as_low_public_id():
    """Verify Google Public API Key (AIza...) is classified as Low severity public identifier, not High secret."""
    http = MagicMock(spec=RobustHTTPClient)

    js_code = """
    var config = {
        apiKey: "AIzaSyBwQcjgmXUAsw5r4FZXO5t8_EZ_aUm_TGE",
        authDomain: "app.firebaseapp.com",
        projectId: "google-test"
    };
    """
    extractor = JSRouteExtractor(http=http)
    _, _, secrets = await extractor.analyze("https://www.google.com", js_code)

    assert len(secrets) == 1
    sec = secrets[0]
    assert sec["id"] == "JS-PUBLIC-IDENTIFIER"
    assert sec["severity"] == "low"
    assert "Public Google Client API Key" in sec["title"]


@pytest.mark.asyncio
async def test_js_analyzer_classifies_private_keys_as_high_severity():
    """Verify confidential private secrets (AWS, Stripe secret) remain High severity."""
    http = MagicMock(spec=RobustHTTPClient)

    js_code = """
    const awsKey = "AKIAIOSFODNN7EXAMPLE";
    const stripeSecret = "sk_test_51Abcdefghijklmnopqrstuvw";
    """
    extractor = JSRouteExtractor(http=http)
    _, _, secrets = await extractor.analyze("https://example.com", js_code)

    assert len(secrets) == 2
    for sec in secrets:
        assert sec["severity"] == "high"
        assert sec["id"] == "JS-EXPOSED-SECRET"


# ── 3. Supply Chain Library Regex Precision ───────────────────────────────────

def test_supply_chain_ignores_lone_dots_in_minified_code():
    """Verify that angular. or triangular. in JS does not extract '.' as a library version."""
    analyzer = SupplyChainAnalyzer(http=MagicMock(spec=RobustHTTPClient))

    minified_js = """
    var x = {angular: {}};
    function isTriangular(n) { return triangular.calculate(n); }
    angular.element(document).ready(function() {});
    """

    findings = analyzer._detect_outdated_libraries(minified_js)
    assert len(findings) == 0, f"False positive library detections found: {findings}"


def test_supply_chain_extracts_valid_library_version():
    """Verify that genuine version strings like angular.js v1.8.2 are properly detected."""
    analyzer = SupplyChainAnalyzer(http=MagicMock(spec=RobustHTTPClient))

    js_with_ver = """
    /*! AngularJS v1.8.2 | (c) 2010-2020 Google, Inc. | angularjs.org/license */
    """
    findings = analyzer._detect_outdated_libraries(js_with_ver)
    assert len(findings) >= 1
    assert any("1.8.2" in f["title"] for f in findings)


# ── 4. IDOR / BOLA Differential Verification ──────────────────────────────────

@pytest.mark.asyncio
async def test_idor_ignores_static_html_pages_with_numeric_params():
    """Verify IDOR detector ignores HTML search/preference pages where numbers vary but content is static."""
    http = MagicMock(spec=RobustHTTPClient)

    html_page = """
    <html>
        <head><title>Google Preferences</title></head>
        <body>
            <form action="/setprefs">
                <input name="username" type="text" />
                <button name="submit">Save Account Preferences</button>
            </form>
            <p>Profile description and category options.</p>
        </body>
    </html>
    """

    resp = MagicMock(spec=HTTPResult)
    resp.status = 200
    resp.body = html_page.encode("utf-8")
    resp.text.return_value = html_page
    resp.headers = {"content-type": "text/html; charset=utf-8"}

    http.get = AsyncMock(return_value=resp)

    detector = IDORDetector(http=http)
    obs = [{
        "name": "discovered_urls",
        "value": ["https://www.google.com/setprefs?sig=0_test&fg=1&ictx=0"],
    }]

    findings = await detector.run("https://www.google.com", obs)
    assert len(findings) == 0, f"False positive IDOR findings emitted: {findings}"


# ── 5. Compliance & Narrative Clean Finding Filtering ─────────────────────────

def test_compliance_and_narrative_filter_suppressed_findings():
    """Verify compliance reports and AI narrative do not include suppressed or meta findings."""
    raw_findings = [
        {
            "id": "XSS-REFLECTED",
            "title": "Reflected Cross-Site Scripting (XSS)",
            "severity": "high",
            "confidence": "high",
            "category": "injection",
            "evidence": "Injected <script>alert(1)</script>",
        },
        {
            "id": "IDOR-BOLA",
            "title": "Potential IDOR / BOLA — Object ID Manipulation",
            "severity": "high",
            "confidence": "medium",
            "category": "idor",
            "suppression_reason": "Below confidence filter: medium",
        },
        {
            "id": "AI-NARRATIVE-SUMMARY",
            "title": "Executive Summary & Remediation Narrative",
            "severity": "info",
            "confidence": "high",
            "category": "reporting",
        },
    ]

    narrative_rep = AINarrativeReporter()
    text = narrative_rep.generate_narrative(raw_findings, "https://example.com")
    assert "identified 1 vulnerabilities" in text
    assert "idor" not in text.lower()

    compliance_rep = ComplianceReporter()
    comp_findings = compliance_rep.generate_compliance_report(raw_findings, "https://example.com")
    assert len(comp_findings) == 3
    # Check that OWASP Top 10 only counts the 1 real injection finding
    owasp_evidence = comp_findings[0]["evidence"]
    assert "Injection — FAIL (1 findings)" in owasp_evidence
    assert "Broken Access Control — PASS" in owasp_evidence


def test_compliance_benchmarks_no_meta_self_matching():
    """Verify that parse_compliance_data does not fail controls due to COMPLIANCE-* or AI-NARRATIVE evidence."""
    from phantomscan.reporting import parse_compliance_data

    # Simulate google.com scan result with 3 real findings and meta findings
    findings = [
        {
            "id": "SECURITY-HEADERS-GROUPED",
            "title": "Security headers policy incomplete",
            "severity": "medium",
            "category": "web",
            "evidence": "Missing: HSTS, Content-Security-Policy, X-Content-Type-Options",
        },
        {
            "id": "JS-PUBLIC-IDENTIFIER",
            "title": "Public Google Client API Key Disclosed in Client-Side JavaScript",
            "severity": "low",
            "category": "web",
            "evidence": "Pattern matched: Public Google Client API Key",
        },
        {
            "id": "SC-SECRET-GOOGLE-PUBLIC-API-KEY",
            "title": "Google Public API Key Exposed in JavaScript",
            "severity": "low",
            "category": "supply-chain",
            "evidence": "Found 4 potential Google Public API Key(s)",
        },
        {
            "id": "COMPLIANCE-OWASP-TOP10",
            "title": "OWASP Top 10 (2021) Compliance Status",
            "severity": "info",
            "category": "compliance",
            "evidence": "OWASP Top 10 Compliance Assessment:\n  PASS: 9/10  FAIL: 1/10\n  ✓ A01:2021: Broken Access Control — PASS\n  ✓ A02:2021: Cryptographic Failures — PASS\n  ✓ A03:2021: Injection — PASS\n  ✓ A04:2021: Insecure Design — PASS\n  ✗ A05:2021: Security Misconfiguration — FAIL (1 findings)\n  ✓ A06:2021: Vulnerable Components — PASS\n  ✓ A07:2021: Auth Failures — PASS\n  ✓ A08:2021: Software and Data Integrity — PASS\n  ✓ A09:2021: Logging and Monitoring — PASS\n  ✓ A10:2021: SSRF — PASS",
        },
        {
            "id": "COMPLIANCE-PCIDSS",
            "title": "PCI DSS v4.0 Compliance Status",
            "severity": "info",
            "category": "compliance",
            "evidence": "PCI DSS v4.0 Compliance Assessment:\n  PASS: 6/8  FAIL: 2/8",
        },
        {
            "id": "COMPLIANCE-NIST",
            "title": "NIST 800-53 Control Mapping",
            "severity": "info",
            "category": "compliance",
            "evidence": "NIST 800-53 Compliance Assessment:\n  PASS: 6/7  FAIL: 1/7",
        },
        {
            "id": "AI-NARRATIVE-SUMMARY",
            "title": "Executive Summary & Remediation Narrative",
            "severity": "info",
            "category": "reporting",
            "evidence": "The assessment identified 3 vulnerabilities...",
        },
    ]

    comp_data = parse_compliance_data(findings)
    assert len(comp_data.frameworks) == 3

    owasp_fw = next(f for f in comp_data.frameworks if f["name"] == "OWASP Top 10")
    # OWASP should pass 9 out of 10 controls (only A05 Security Misconfiguration fails due to missing headers)
    assert owasp_fw["passed"] == 9
    assert owasp_fw["failed"] == 1
    assert any("A05:2021" in c for c in owasp_fw["failing_controls"])
    # Injection, Broken Access Control, SSRF, etc. MUST NOT be in failing controls
    assert not any("A01:2021" in c for c in owasp_fw["failing_controls"])
    assert not any("A03:2021" in c for c in owasp_fw["failing_controls"])
    assert not any("A10:2021" in c for c in owasp_fw["failing_controls"])

    pci_fw = next(f for f in comp_data.frameworks if f["name"] == "PCI DSS v4.0")
    # PCI DSS should have high pass rate, and not fail on network security, vuln scanning, etc.
    assert pci_fw["passed"] >= 6
    assert not any("1.3" in c for c in pci_fw["failing_controls"])
    assert not any("11.3" in c for c in pci_fw["failing_controls"])

    nist_fw = next(f for f in comp_data.frameworks if f["name"] == "NIST 800-53")
    # NIST 800-53 should have high pass rate
    assert nist_fw["passed"] >= 6
    assert not any("AC-3" in c for c in nist_fw["failing_controls"])
    assert not any("SI-10" in c for c in nist_fw["failing_controls"])

