"""Tests for reporting module."""

import json
from pathlib import Path
from phantomscan.reporting import write_json_report, write_csv_report

def test_write_json_report(tmp_path: Path):
    """Test JSON report generation."""
    out_file = tmp_path / "test.json"
    payload = {"target": "example.com", "score": 90, "findings": []}
    write_json_report(out_file, payload)
    
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["target"] == "example.com"
    assert data["score"] == 90

def test_write_csv_report(tmp_path: Path):
    """Test CSV report generation."""
    out_file = tmp_path / "test.csv"
    payload = {
        "target": "example.com",
        "findings": [
            {
                "title": "Test Vulnerability",
                "severity": "high",
                "confidence": "high",
                "category": "web"
            }
        ]
    }
    write_csv_report(out_file, payload)
    
    assert out_file.exists()
    content = out_file.read_text()
    assert "Target,Title,Severity,Confidence,Category" in content
    assert "example.com,Test Vulnerability,high,high,web" in content


def test_unique_path_generation(tmp_path: Path):
    """Test that existing report files increment counter instead of overwriting."""
    base_file = tmp_path / "example.com_20260731_120000.html"
    base_file.write_text("report 1")

    # Re-implement helper check logic
    def get_unique_path(base_path: Path) -> Path:
        if not base_path.exists():
            return base_path
        stem = base_path.stem
        suffix = base_path.suffix
        counter = 1
        while True:
            candidate = base_path.parent / f"{stem}_{counter}{suffix}"
            if not candidate.exists():
                return candidate
            counter += 1

    unique_1 = get_unique_path(base_file)
    assert unique_1.name == "example.com_20260731_120000_1.html"
    unique_1.write_text("report 2")

    unique_2 = get_unique_path(base_file)
    assert unique_2.name == "example.com_20260731_120000_2.html"


def test_parse_intel_email_security():
    """Test parse_intel EmailSecurityData provider identification and scoring."""
    from phantomscan.reporting import parse_intel
    observations = [
        {"name": "email_domain", "value": "google.com"},
        {"name": "mx_records", "value": ["smtp.google.com"]},
        {"name": "spf_record", "value": "v=spf1 include:_spf.google.com ~all"},
        {"name": "dmarc_record", "value": "v=DMARC1; p=reject; sp=reject;"},
    ]
    intel = parse_intel(observations)
    email = intel.email_security
    assert email.domain == "google.com"
    assert email.provider == "Google Workspace"
    assert email.spf is True
    assert email.dmarc is True
    assert email.score == 10


def test_resolve_reference_url():
    """Test reference resolution for CWEs, CVEs, OWASP, and HTTP URLs."""
    from phantomscan.reporting import resolve_reference_url
    assert resolve_reference_url("CWE-89") == "https://cwe.mitre.org/data/definitions/89.html"
    assert resolve_reference_url("cwe-79") == "https://cwe.mitre.org/data/definitions/79.html"
    assert resolve_reference_url("CVE-2023-1234") == "https://nvd.nist.gov/vuln/detail/CVE-2023-1234"
    assert "owasp.org" in resolve_reference_url("OWASP Top 10 A01:2021")
    assert resolve_reference_url("https://example.com/advisory") == "https://example.com/advisory"


def test_write_html_report_and_remediation_matrix_links(tmp_path: Path):
    """Test that HTML report generates matched anchors between Remediation Matrix and Finding Cards."""
    from phantomscan.reporting import write_html_report
    out_file = tmp_path / "test_report.html"
    payload = {
        "target": "http://localhost:3000",
        "score": 65,
        "grade": "D",
        "findings": [
            {
                "id": "SQLI-ERROR-BASED",
                "title": "SQL Injection in Search",
                "severity": "critical",
                "confidence": "high",
                "category": "sqli",
                "target": "http://localhost:3000/rest/products/search?q=",
                "evidence": "SequelizeDatabaseError: SQLITE_ERROR: near 'q': syntax error",
                "recommendation": "Use parameterized queries.",
                "references": ["CWE-89", "https://owasp.org/www-community/attacks/SQL_Injection"],
            },
            {
                "id": "PROTOTYPE-POLLUTION",
                "title": "Client-Side Prototype Pollution",
                "severity": "high",
                "confidence": "medium",
                "category": "web",
                "target": "http://localhost:3000/#/search",
                "evidence": "window.polluted injected via Object.prototype",
                "recommendation": "Freeze Object.prototype.",
                "references": ["CWE-1321"],
            }
        ],
        "observations": [
            {"name": "http_status", "value": 200},
            {"name": "discovered_api_routes", "value": ["/rest/products/search", "/api/Feedbacks"]}
        ]
    }
    write_html_report(out_file, payload)
    assert out_file.exists()
    html_content = out_file.read_text(encoding="utf-8")

    # Verify that the card IDs match the remediation matrix jump targets
    assert 'id="finding-0-sqli-error-based"' in html_content
    assert 'id="finding-1-prototype-pollution"' in html_content
    assert 'window.scrollToFinding(\'finding-0-sqli-error-based\'' in html_content
    assert 'window.scrollToFinding(\'finding-1-prototype-pollution\'' in html_content
    assert 'window.switchFindingTab(this, \'evidence\')' in html_content
    assert 'window.switchFindingTab(this, \'refs\')' in html_content
    assert 'https://cwe.mitre.org/data/definitions/89.html' in html_content
    assert 'https://cwe.mitre.org/data/definitions/1321.html' in html_content


def test_html_report_rich_data_parsing(tmp_path: Path):
    """Test that all rich finding details, compliance frameworks, and APIs are rendered in the HTML report."""
    from phantomscan.reporting import write_html_report, parse_api_data, parse_compliance_data, parse_supply_chain_data

    # 1. Test parse_api_data
    obs = [
        {"name": "api_endpoints", "value": [{"path": "/api/v1/users", "method": "GET", "authenticated": False}]},
        {"name": "graphql_endpoints", "value": [{"url": "https://example.com/graphql", "introspection_enabled": True}]},
        {"name": "websocket_endpoints", "value": [{"url": "wss://example.com/socket", "origin_validation_bypassed": True}]},
    ]
    findings = [
        {
            "id": "IDOR-USER-PROFILE",
            "title": "Insecure Direct Object Reference in User Profile",
            "severity": "high",
            "confidence": "high",
            "category": "idor",
            "target": "https://example.com/api/v1/users/123",
            "evidence": "User ID switching permitted without token validation",
            "recommendation": "Enforce object-level authorization.",
            "verification_method": "active_confirmation",
            "impact": "Full account takeover of arbitrary user profiles.",
            "cvss_score": 8.6,
            "owasp_category": "A01:2021-Broken Access Control",
            "reproduction_steps": [
                "1. Authenticate as User A.",
                "2. Change URL to /api/v1/users/B.",
                "3. Observe sensitive PII returned."
            ],
            "request_sample": "GET /api/v1/users/456 HTTP/1.1\nHost: example.com",
            "response_sample": "HTTP/1.1 200 OK\n{\"user_id\": 456, \"email\": \"victim@test.com\"}",
        }
    ]

    api_data = parse_api_data(obs, findings)
    assert len(api_data.endpoints) == 1
    assert api_data.endpoints[0]["path"] == "/api/v1/users"
    assert len(api_data.graphql_endpoints) == 1
    assert len(api_data.websocket_endpoints) == 1
    assert len(api_data.auth_issues) == 1

    # 2. Test parse_compliance_data
    comp_data = parse_compliance_data(findings)
    assert len(comp_data.frameworks) == 3
    owasp_fw = next(f for f in comp_data.frameworks if f["name"] == "OWASP Top 10")
    assert owasp_fw["failed"] >= 1

    # 3. Test parse_supply_chain_data with secret masking
    obs_supply = [
        {"name": "secrets_found", "value": [{"type": "OpenAI API Key", "value": "sk-proj-1234567890abcdef"}]},
    ]
    supply_data = parse_supply_chain_data(obs_supply, findings)
    assert len(supply_data.secrets) == 1
    assert supply_data.secrets[0]["value"].endswith("***")
    assert supply_data.secrets[0]["value"].startswith("sk-proj-")

    # 4. Generate HTML and verify rendered badges and sections
    out_file = tmp_path / "rich_report.html"
    payload = {
        "target": "https://example.com",
        "score": 45,
        "grade": "F",
        "findings": findings,
        "observations": obs + obs_supply,
    }
    write_html_report(out_file, payload)
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")

    assert "ACTIVE CONFIRMATION" in content
    assert "CVSS 8.6" in content
    assert "A01:2021-Broken Access Control" in content
    assert "Full account takeover of arbitrary user profiles" in content
    assert "1. Authenticate as User A" in content
    # 5. Verify dynamic executed module telemetry in HTML
    obs_modules = [
        {
            "name": "module_execution",
            "value": {
                "name": "sqli_detector",
                "phase": "active",
                "status": "completed",
                "duration": 0.85,
                "findings": 1,
                "engine": "python",
            }
        },
        {
            "name": "module_execution",
            "value": {
                "name": "graphql_tester",
                "phase": "active",
                "status": "completed",
                "duration": 0.42,
                "findings": 0,
                "engine": "python",
            }
        }
    ]
    payload_telemetry = {
        "target": "https://example.com",
        "score": 75,
        "grade": "C",
        "findings": findings,
        "observations": obs + obs_modules,
    }
    out_telemetry = tmp_path / "telemetry_report.html"
    write_html_report(out_telemetry, payload_telemetry)
    assert out_telemetry.exists()
    telemetry_content = out_telemetry.read_text(encoding="utf-8")

    assert "Executed Modules Telemetry" in telemetry_content
    assert "Sqli Detector" in telemetry_content
    assert "Graphql Tester" in telemetry_content
    assert "+1 finding" in telemetry_content
    assert "0.85s" in telemetry_content




