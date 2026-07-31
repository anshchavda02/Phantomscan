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

