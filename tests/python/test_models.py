"""Tests for data models."""

import pytest
from phantomscan.models import Finding, Observation

def test_finding_instantiation():
    """Test valid finding instantiation."""
    data = {
        "id": "1",
        "title": "Test Title",
        "severity": "high",
        "confidence": "high",
        "category": "web",
        "target": "example.com",
        "evidence": "test evidence",
        "recommendation": "test recommendation",
        "references": []
    }
    finding = Finding.from_dict(data)
    assert finding.title == "Test Title"
    assert finding.severity == "high"

def test_finding_invalid_severity():
    """Test invalid severity throws error."""
    data = {
        "id": "1",
        "title": "Test Title",
        "severity": "super_critical", # Invalid
        "confidence": "high",
        "category": "web",
        "target": "example.com",
        "evidence": "test",
        "recommendation": "test",
        "references": []
    }
    with pytest.raises(ValueError, match="Invalid severity"):
        Finding.from_dict(data)

def test_observation_instantiation():
    """Test observation serialization."""
    obs = Observation(name="test_obs", value=42, source="test_source")
    assert obs.to_dict()["value"] == 42
    
    obs2 = Observation.from_dict({"name": "test2", "value": "xyz", "source": "src"})
    assert obs2.name == "test2"
