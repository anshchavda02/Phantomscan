"""Scoring engine with platform minimum score enforcement."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
from phantomscan.postprocess import DEDUCTIONS, DEDUCTION_CAPS, grade, score

BONUSES: dict[str, int] = {
    "https": 10,
    "valid_ssl": 10,
    "ssl_grade_a": 5,
    "waf": 5,
    "cdn": 3,
}


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


class ScoreEngine:
    """Score engine implementing deduction caps, bonuses, and platform floors."""

    def __init__(self, platform: Optional[dict[str, Any]] = None) -> None:
        self.platform = platform

    def calculate(self, findings: list[Any], observations: list[Any] | None = None) -> Score:
        return calculate_score(findings, platform=self.platform, observations=observations)


__all__ = [
    "grade",
    "score",
    "calculate_score",
    "to_grade",
    "Score",
    "ScoreEngine",
    "DEDUCTIONS",
    "DEDUCTION_CAPS",
    "BONUSES",
]
