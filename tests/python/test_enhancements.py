"""Tests for new architectural enhancements in PhantomScan.

Validates:
1. Scan Profile-to-Module mapping resolution (owasp, api, bug-bounty).
2. OpenAPI specification endpoint parameter extraction into InjectionTargets.
3. Secret pattern loading and Rule 6.3 masking in JS Analyzer.
4. OASIS SARIF v2.1.0 report generation and schema compliance.
5. 11-column enriched CSV report export.
6. Out-of-Band (OOB) configurable callback host.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from phantomscan.models import Finding, utc_now
from phantomscan.pipeline import PROFILE_MODULE_MAP
from phantomscan.injection_target import extract_injection_targets
from phantomscan.js_analyzer import _mask_secret, _load_secret_patterns, JSRouteExtractor
from phantomscan.sarif_exporter import generate_sarif_report, write_sarif_report
from phantomscan.reporting import write_csv_report
from phantomscan.oob import OOBServer


def test_profile_module_mappings():
    """Verify that PROFILE_MODULE_MAP properly defines sets for profiles."""
    assert "owasp" in PROFILE_MODULE_MAP
    assert "api" in PROFILE_MODULE_MAP
    assert "bug-bounty" in PROFILE_MODULE_MAP

    owasp_mods = PROFILE_MODULE_MAP["owasp"]
    assert "sqli_detector" in owasp_mods
    assert "xss_scanner" in owasp_mods
    assert "idor" in owasp_mods
    assert "ssrf" in owasp_mods

    api_mods = PROFILE_MODULE_MAP["api"]
    assert "jwt_oauth" in api_mods
    assert "graphql" in api_mods
    assert "idor" in api_mods

    bb_mods = PROFILE_MODULE_MAP["bug-bounty"]
    assert "subdomain_takeover" in bb_mods
    assert "sqli_detector" in bb_mods
    assert "race_condition" in bb_mods


def test_openapi_injection_target_extraction():
    """Verify OpenAPI endpoints are extracted into active injection targets."""
    observations = [
        {
            "name": "openapi_endpoints",
            "value": [
                {
                    "path": "/users/{userId}/orders",
                    "method": "GET",
                    "parameters": [
                        {"name": "userId", "in": "path", "required": True},
                        {"name": "filter", "in": "query", "required": False},
                    ],
                },
                {
                    "path": "/api/v1/checkout",
                    "method": "POST",
                    "parameters": [],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "coupon": {"type": "string"},
                                        "quantity": {"type": "integer"},
                                    }
                                }
                            }
                        }
                    },
                },
            ],
            "source": "openapi",
        }
    ]

    targets = extract_injection_targets(observations, base_url="https://api.target.com")
    
    # Check that OpenAPI targets were extracted
    openapi_targets = [t for t in targets if t.target_type in ("openapi_path", "openapi_query", "openapi_body")]
    assert len(openapi_targets) >= 3

    param_names = [t.param_name for t in openapi_targets]
    assert "userId" in param_names
    assert "filter" in param_names
    assert "coupon" in param_names or "quantity" in param_names

    # Check that the URL is populated correctly
    path_target = next(t for t in openapi_targets if t.param_name == "userId")
    assert "/users/1/orders" in path_target.url


def test_rule_6_3_secret_masking():
    """Verify Rule 6.3 secret masking: first 8 chars + ***, never plaintext."""
    assert _mask_secret("sk-proj-1234567890abcdef") == "sk-proj-***"
    assert _mask_secret("short") == "sho***"
    assert _mask_secret("") == ""
    assert _mask_secret("ghp_1234567890abcdef") == "ghp_1234***"


def test_secret_patterns_loading():
    """Verify that centralized secret patterns are loaded from data/secret_patterns.json."""
    patterns = _load_secret_patterns()
    assert len(patterns) >= 10
    
    labels = [p[1] for p in patterns]
    assert any("OpenAI" in l or "AWS" in l or "GitHub" in l or "Stripe" in l for l in labels)


def test_sarif_report_generation(tmp_path: Path):
    """Verify OASIS SARIF v2.1.0 report generation and structural validity."""
    report_data = {
        "target": "example.com",
        "started_at": "2026-09-09T05:00:00Z",
        "duration": 12.5,
        "findings": [
            {
                "id": "PS-SQLI-001",
                "title": "SQL Injection in User Search",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "category": "Injection",
                "cwe": "CWE-89",
                "owasp_category": "A03:2021-Injection",
                "evidence": "MySQL syntax error detected near 'admin'",
                "recommendation": "Use parameterized queries with prepared statements.",
                "target": "https://example.com/search?q=admin",
            },
            {
                "id": "PS-HDR-002",
                "title": "Missing Content-Security-Policy Header",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "category": "Misconfiguration",
                "cwe": "CWE-693",
                "evidence": "CSP header absent from response",
                "recommendation": "Set Content-Security-Policy header.",
                "target": "https://example.com/",
            }
        ]
    }

    sarif = generate_sarif_report(report_data)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    tool = run["tool"]["driver"]
    assert tool["name"] == "PhantomScan"
    assert len(tool["rules"]) == 2

    # Verify rule properties
    sqli_rule = next(r for r in tool["rules"] if r["id"] == "PS-SQLI-001")
    assert sqli_rule["defaultConfiguration"]["level"] == "error"
    assert "CWE-89" in sqli_rule["properties"]["tags"]

    # Verify results
    results = run["results"]
    assert len(results) == 2
    assert results[0]["ruleId"] == "PS-SQLI-001"
    assert results[0]["level"] == "error"
    assert results[1]["level"] == "warning"

    # Verify file writing
    out_file = tmp_path / "scan.sarif.json"
    write_sarif_report(out_file, report_data)
    assert out_file.exists()
    written_data = json.loads(out_file.read_text(encoding="utf-8"))
    assert written_data["version"] == "2.1.0"


def test_enriched_csv_report(tmp_path: Path):
    """Verify enriched CSV contains all 11 security audit columns with backward compatibility."""
    out_file = tmp_path / "audit.csv"
    payload = {
        "target": "https://target.corp",
        "findings": [
            {
                "id": "PS-IDOR-001",
                "title": "Insecure Direct Object Reference",
                "severity": "HIGH",
                "confidence": "HIGH",
                "category": "Authorization",
                "cwe": "CWE-639",
                "owasp_category": "A01:2021-Broken Access Control",
                "evidence": "Accessed account 104 without session owner",
                "recommendation": "Validate user authorization per record ID",
                "fingerprint": "hash_123456",
            }
        ]
    }

    write_csv_report(out_file, payload)
    assert out_file.exists()
    lines = out_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 2

    header = lines[0]
    # Check that original 5 columns start the header
    assert header.startswith("Target,Title,Severity,Confidence,Category")
    # Check that new audit columns are appended
    assert "Finding ID" in header
    assert "CWE" in header
    assert "OWASP" in header
    assert "Evidence" in header
    assert "Recommendation" in header
    assert "Fingerprint" in header

    data_row = lines[1]
    assert "https://target.corp" in data_row
    assert "Insecure Direct Object Reference" in data_row
    assert "CWE-639" in data_row
    assert "hash_123456" in data_row


def test_oob_configurable_callback_host():
    """Verify OOB Server supports custom callback host while maintaining default."""
    server_default = OOBServer(port=9991)
    assert server_default.callback_host == "127.0.0.1"
    uid, payload_url = server_default.generate_payload_url()
    assert "127.0.0.1:9991" in payload_url

    server_custom = OOBServer(port=9992, callback_host="oob.scanner.internal")
    assert server_custom.callback_host == "oob.scanner.internal"
    uid2, payload_url2 = server_custom.generate_payload_url()
    assert "oob.scanner.internal:9992" in payload_url2
