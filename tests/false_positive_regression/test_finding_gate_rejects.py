"""Regression: FindingGate must reject findings without required fields."""

from __future__ import annotations

import pytest

from phantomscan.modules.finding_gate import gate_finding


def test_rejects_missing_title():
    """Finding without title must be rejected."""
    candidate = {
        "severity": "high",
        "confidence": "high",
        "evidence": "Some evidence text here",
    }
    assert gate_finding(candidate) is None


def test_rejects_missing_severity():
    """Finding without severity must be rejected."""
    candidate = {
        "title": "Test Finding",
        "confidence": "high",
        "evidence": "Some evidence text here",
    }
    assert gate_finding(candidate) is None


def test_rejects_missing_confidence():
    """Finding without confidence must be rejected."""
    candidate = {
        "title": "Test Finding",
        "severity": "high",
        "evidence": "Some evidence text here",
    }
    assert gate_finding(candidate) is None


def test_rejects_missing_evidence():
    """Finding without evidence must be rejected."""
    candidate = {
        "title": "Test Finding",
        "severity": "high",
        "confidence": "high",
    }
    assert gate_finding(candidate) is None


def test_rejects_short_evidence():
    """Finding with evidence < 10 chars must be rejected."""
    candidate = {
        "title": "Test Finding",
        "severity": "high",
        "confidence": "high",
        "evidence": "short",
    }
    assert gate_finding(candidate) is None


def test_rejects_invalid_severity():
    """Finding with non-canonical severity must be rejected."""
    candidate = {
        "title": "Test Finding",
        "severity": "EXTREME",
        "confidence": "high",
        "evidence": "Sufficient evidence text for validation",
    }
    assert gate_finding(candidate) is None


def test_rejects_invalid_confidence():
    """Finding with invalid confidence must be rejected."""
    candidate = {
        "title": "Test Finding",
        "severity": "high",
        "confidence": "maybe",
        "evidence": "Sufficient evidence text for validation",
    }
    assert gate_finding(candidate) is None


def test_rejects_invalid_verification_method():
    """Finding with non-canonical verification_method must be rejected."""
    candidate = {
        "title": "Test Finding",
        "severity": "medium",
        "confidence": "high",
        "evidence": "Sufficient evidence text for validation",
        "verification_method": "gut_feeling",
    }
    assert gate_finding(candidate) is None


def test_accepts_valid_finding():
    """A properly formed finding must pass the gate."""
    candidate = {
        "title": "Test Finding",
        "severity": "medium",
        "confidence": "high",
        "evidence": "Sufficient evidence text for validation",
        "verification_method": "passive_observation",
    }
    result = gate_finding(candidate)
    assert result is not None
    assert result["title"] == "Test Finding"


def test_accepts_empty_verification_method():
    """Empty verification_method (legacy) must be accepted."""
    candidate = {
        "title": "Test Finding",
        "severity": "medium",
        "confidence": "high",
        "evidence": "Sufficient evidence text for validation",
        "verification_method": "",
    }
    result = gate_finding(candidate)
    assert result is not None


def test_accepts_finding_without_verification_method_key():
    """Finding without verification_method key at all (legacy) must be accepted."""
    candidate = {
        "title": "Test Finding",
        "severity": "medium",
        "confidence": "high",
        "evidence": "Sufficient evidence text for validation",
    }
    result = gate_finding(candidate)
    assert result is not None


def test_rejected_findings_logged_to_fp_log():
    """Rejected findings must be appended to fp_log with reason."""
    fp_log: list[dict] = []
    candidate = {
        "title": "Bad Finding",
        "severity": "high",
        "confidence": "high",
        # Missing evidence
    }
    gate_finding(candidate, fp_log=fp_log)

    assert len(fp_log) == 1
    assert "gate_rejection_reason" in fp_log[0]
