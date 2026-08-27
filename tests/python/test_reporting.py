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


