"""Module 11 — Score Trend Predictor.

Uses linear regression on historical security scores to project future scores (e.g. 30 days out)
and warns if a declining security posture is detected.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)


@dataclass
class ScoreEntry:
    date: datetime
    value: int


@dataclass
class TrendPrediction:
    available: bool
    message: str = ""
    current_score: int = 0
    predicted_30_days: int = 0
    trend_direction: str = "stable"  # "improving", "declining", "stable"
    slope_per_day: float = 0.0
    warning_message: str | None = None


class TrendPredictor:
    """Predict security score trends using linear regression."""

    def __init__(self, http: RobustHTTPClient | None = None) -> None:
        self.http = http

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface."""
        history = kwargs.get("score_history", [])
        if history:
            entries = []
            for h in history:
                if isinstance(h, dict) and "date" in h and "value" in h:
                    dt = datetime.fromisoformat(h["date"]) if isinstance(h["date"], str) else h["date"]
                    entries.append(ScoreEntry(date=dt, value=int(h["value"])))
            res = self.predict(entries)
            if res.warning_message:
                return [{
                    "title": "Declining Security Score Trend Detected",
                    "severity": "medium",
                    "confidence": "high",
                    "category": "trend",
                    "target": kwargs.get("base_url", "Target"),
                    "evidence": res.warning_message,
                    "recommendation": "Address open unpatched vulnerabilities to reverse the declining security trend.",
                    "references": [],
                    "module": "trend_predictor",
                }]
        return []

    def predict(self, score_history: list[ScoreEntry]) -> TrendPrediction:
        """Perform linear regression on historical scores."""
        if len(score_history) < 3:
            return TrendPrediction(
                available=False,
                message="Need at least 3 historical scans for trend prediction."
            )

        # Sort by date
        sorted_history = sorted(score_history, key=lambda s: s.date)

        first_date = sorted_history[0].date
        dates = [(s.date - first_date).days for s in sorted_history]
        scores = [s.value for s in sorted_history]

        n = len(dates)
        sum_x = sum(dates)
        sum_y = sum(scores)
        sum_xy = sum(x * y for x, y in zip(dates, scores))
        sum_xx = sum(x * x for x in dates)

        denom = (n * sum_xx - sum_x * sum_x)
        if denom == 0:
            slope = 0.0
        else:
            slope = (n * sum_xy - sum_x * sum_y) / denom

        intercept = (sum_y - slope * sum_x) / n

        last_day = dates[-1]
        predicted_30 = slope * (last_day + 30) + intercept
        predicted_30 = max(0, min(100, int(round(predicted_30))))

        if slope < -0.1:
            trend_direction = "declining"
        elif slope > 0.1:
            trend_direction = "improving"
        else:
            trend_direction = "stable"

        warning_msg = None
        if trend_direction == "declining":
            current_score = scores[-1]
            if slope < 0 and current_score > 50:
                days_to_50 = int((50 - current_score) / slope)
                if 0 < days_to_50 < 60:
                    warning_msg = (
                        f"At the current rate of decline ({round(slope, 2)} pts/day), your security score "
                        f"is projected to drop below 50 within {days_to_50} days."
                    )

        return TrendPrediction(
            available=True,
            current_score=scores[-1],
            predicted_30_days=predicted_30,
            trend_direction=trend_direction,
            slope_per_day=round(slope, 2),
            warning_message=warning_msg,
        )
