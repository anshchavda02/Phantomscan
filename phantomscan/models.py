"""Shared data models for PhantomScan."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class Finding:
    """A normalized security finding."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    target: str
    evidence: str
    recommendation: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class Observation:
    """A non-vulnerability observation from a scan."""

    name: str
    value: Any
    source: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""
        return asdict(self)


@dataclass
class EngineResult:
    """Versioned engine output."""

    schema: str
    engine: str
    status: str
    target: str
    started_at: str
    finished_at: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def skipped(cls, engine: str, target: str, reason: str) -> "EngineResult":
        """Create a skipped engine result."""
        now = utc_now()
        return cls(
            schema="phantomscan.engine.v1",
            engine=engine,
            status="skipped",
            target=target,
            started_at=now,
            finished_at=now,
            warnings=[reason],
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""
        return asdict(self)

