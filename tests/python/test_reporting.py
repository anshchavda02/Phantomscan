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
