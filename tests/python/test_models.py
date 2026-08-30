"""Tests for data models and contract definitions."""

import pytest
from phantomscan.models import (
    DOMEvidence,
    Evidence,
    Finding,
    HTTPEvidence,
    Observation,
    TLSEvidence,
    TimingEvidence,
    compute_finding_fingerprint,
)
from phantomscan.modules.finding_gate import gate_finding


def test_finding_instantiation():
    """Test valid finding instantiation with default and explicit fields."""
    data = {
        "id": "1",
        "title": "Test Title",
        "severity": "high",
        "confidence": "high",
        "category": "web",
        "target": "example.com",
        "evidence": "test evidence here",
        "recommendation": "test recommendation",
        "references": ["https://example.com/ref"],
        "url": "https://example.com/api/user",
        "method": "POST",
        "parameter": "username",
        "cvss_score": 7.5,
        "reproduction_steps": ["Step 1", "Step 2"],
    }
    finding = Finding.from_dict(data)
    assert finding.title == "Test Title"
    assert finding.severity == "high"
    assert finding.status == "confirmed"
    assert finding.url == "https://example.com/api/user"
    assert finding.method == "POST"
    assert finding.parameter == "username"
    assert finding.cvss_score == 7.5
    assert len(finding.reproduction_steps) == 2
    assert len(finding.fingerprint) == 64  # SHA-256 hex string


def test_finding_invalid_severity():
    """Test invalid severity throws error."""
    data = {
        "id": "1",
        "title": "Test Title",
        "severity": "super_critical",  # Invalid
        "confidence": "high",
        "category": "web",
        "target": "example.com",
        "evidence": "test",
        "recommendation": "test",
        "references": []
    }
    with pytest.raises(ValueError, match="Invalid severity"):
        Finding.from_dict(data)


def test_finding_invalid_status():
    """Test invalid status throws error."""
    data = {
        "id": "1",
        "title": "Test Title",
        "severity": "medium",
        "confidence": "medium",
        "category": "web",
        "target": "example.com",
        "evidence": "valid evidence string",
        "status": "bogus_status",
    }
    with pytest.raises(ValueError, match="Invalid status"):
        Finding.from_dict(data)


def test_deterministic_fingerprinting():
    """Test fingerprint computation consistency and differentiability."""
    fp1 = compute_finding_fingerprint(
        target="example.com",
        url="https://example.com/api/v1/users",
        rule_id="SQLI-001",
        param_name="id",
        method="GET",
        evidence="SQL syntax error near '1'",
    )
    fp2 = compute_finding_fingerprint(
        target="example.com",
        url="https://example.com/api/v1/users",
        rule_id="SQLI-001",
        param_name="id",
        method="GET",
        evidence="SQL syntax error near '1'",
    )
    assert fp1 == fp2
    assert len(fp1) == 64

    # Different parameter -> different fingerprint
    fp3 = compute_finding_fingerprint(
        target="example.com",
        url="https://example.com/api/v1/users",
        rule_id="SQLI-001",
        param_name="email",
        method="GET",
        evidence="SQL syntax error near '1'",
    )
    assert fp1 != fp3


def test_evidence_models():
    """Test typed evidence models serialization."""
    http_ev = HTTPEvidence(
        summary="Reflected XSS in search parameter",
        request_method="GET",
        request_url="https://example.com/search?q=test",
        response_status=200,
        response_body_sample="<div>test</div>",
        response_time_ms=45,
    )
    ev_dict = http_ev.to_dict()
    assert ev_dict["request_method"] == "GET"
    assert ev_dict["response_status"] == 200
    assert ev_dict["response_time_ms"] == 45

    dom_ev = DOMEvidence(
        summary="DOM XSS via location.search",
        source="location.search",
        sink="element.innerHTML",
        taint_path="param q -> div.innerHTML",
    )
    assert dom_ev.to_dict()["sink"] == "element.innerHTML"

    tls_ev = TLSEvidence(
        summary="Valid TLS 1.3 certificate",
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        days_remaining=45,
    )
    assert tls_ev.to_dict()["protocol"] == "TLSv1.3"

    timing_ev = TimingEvidence(
        summary="Statistical time differential SQLi",
        baseline_duration_ms=120.0,
        payload_duration_ms=5130.0,
        time_difference_ms=5010.0,
        samples_collected=5,
    )
    assert timing_ev.to_dict()["time_difference_ms"] == 5010.0


def test_finding_gate_fingerprint_enrichment():
    """Test that gate_finding automatically computes fingerprints for raw dicts."""
    raw_finding = {
        "title": "Exposed Git Repository",
        "severity": "high",
        "confidence": "high",
        "evidence": "ref: refs/heads/main commit index exposed",
        "target": "example.com",
        "url": "https://example.com/.git/HEAD",
    }
    gated = gate_finding(raw_finding)
    assert gated is not None
    assert gated["status"] == "confirmed"
    assert "fingerprint" in gated
    assert len(gated["fingerprint"]) == 64
    assert gated["uid"].startswith("finding-")


def test_observation_instantiation():
    """Test observation serialization."""
    obs = Observation(name="test_obs", value=42, source="test_source")
    assert obs.to_dict()["value"] == 42

    obs2 = Observation.from_dict({"name": "test2", "value": "xyz", "source": "src"})
    assert obs2.name == "test2"

