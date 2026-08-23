"""Scoring engine with platform minimum score enforcement."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
from phantomscan.postprocess import grade, score


@dataclass
class Score:
    value: int
    grade: str


def to_grade(value: int) -> str:
    """Return a letter grade for a numeric score."""
    return grade(value)


def calculate_score(
    findings: list[Any],
    intel: Any = None,
    platform: Optional[dict[str, Any]] = None,
    observations: list[Any] | None = None,
) -> Score:
    """Calculate a score from findings, observations/intel, and platform baseline."""
    clean_findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in (findings or [])]
    obs = observations if observations is not None else (intel if isinstance(intel, list) else [])
    clean_obs = [o.to_dict() if hasattr(o, "to_dict") else o for o in obs]

    val = score(clean_findings, clean_obs, platform=platform)
    return Score(value=val, grade=grade(val))


__all__ = ["grade", "score", "calculate_score", "to_grade", "Score"]
