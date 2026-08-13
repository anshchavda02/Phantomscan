"""Regression: FindingGate must downgrade Critical/High with LOW confidence."""

from __future__ import annotations

import pytest

from phantomscan.modules.finding_gate import gate_finding


def test_critical_low_confidence_downgraded():
    """Critical finding with LOW confidence must be downgraded to medium."""
    candidate = {
        "title": "Critical Finding",
        "severity": "critical",
        "confidence": "low",
        "evidence": "Sufficient evidence text for validation",
    }
    result = gate_finding(candidate)

    assert result is not None
    assert result["severity"] == "medium", (
        f"Critical+LOW should be downgraded to medium, got {result['severity']}"
    )


def test_high_medium_confidence_downgraded():
    """High finding with MEDIUM confidence must be downgraded to medium."""
    candidate = {
        "title": "High Finding",
        "severity": "high",
        "confidence": "medium",
        "evidence": "Sufficient evidence text for validation",
    }
    result = gate_finding(candidate)

    assert result is not None
    assert result["severity"] == "medium", (
        f"High+MEDIUM should be downgraded to medium, got {result['severity']}"
    )


def test_critical_high_confidence_kept():
    """Critical finding with HIGH confidence must remain critical."""
    candidate = {
        "title": "Critical Finding",
        "severity": "critical",
        "confidence": "high",
        "evidence": "Sufficient evidence text for validation",
    }
    result = gate_finding(candidate)

    assert result is not None
    assert result["severity"] == "critical"


def test_medium_low_confidence_not_downgraded():
    """Medium finding with LOW confidence should NOT be downgraded by the gate
    (downgrading only applies to Critical/High)."""
    candidate = {
        "title": "Medium Finding",
        "severity": "medium",
        "confidence": "low",
        "evidence": "Sufficient evidence text for validation",
    }
    result = gate_finding(candidate)

    assert result is not None
    assert result["severity"] == "medium"


def test_downgrade_adds_gate_note():
    """Downgraded findings must have a _gate_notes entry explaining why."""
    candidate = {
        "title": "High Finding",
        "severity": "high",
        "confidence": "low",
        "evidence": "Sufficient evidence text for validation",
    }
    result = gate_finding(candidate)

    assert result is not None
    assert "_gate_notes" in result
    assert any("Downgraded" in note for note in result["_gate_notes"])
