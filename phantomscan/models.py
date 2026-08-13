"""Shared data models for PhantomScan."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
VerificationMethod = Literal[
    "baseline_differential",
    "multi_source_agreement",
    "active_confirmation",
    "external_verification",
    "passive_observation",
    "",  # empty = legacy/unset
]


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


VALID_VERIFICATION_METHODS = {
    "baseline_differential",
    "multi_source_agreement",
    "active_confirmation",
    "external_verification",
    "passive_observation",
    "",
}


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
    verification_method: str = ""
    module: str = ""
    cwe: str = ""

    def __post_init__(self) -> None:
        """Validate fields."""
        valid_severities = {"critical", "high", "medium", "low", "info"}
        valid_confidences = {"high", "medium", "low"}
        if self.severity not in valid_severities:
            raise ValueError(f"Invalid severity: {self.severity}")
        if self.confidence not in valid_confidences:
            raise ValueError(f"Invalid confidence: {self.confidence}")
        if self.verification_method and self.verification_method not in VALID_VERIFICATION_METHODS:
            raise ValueError(
                f"Invalid verification_method: {self.verification_method}"
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Instantiate from dictionary."""
        return cls(
            id=data.get("id", ""),
            title=data.get("title", "Unknown"),
            severity=data.get("severity", "info"),
            confidence=data.get("confidence", "low"),
            category=data.get("category", "general"),
            target=data.get("target", ""),
            evidence=data.get("evidence", ""),
            recommendation=data.get("recommendation", ""),
            references=data.get("references", []),
            verification_method=data.get("verification_method", ""),
            module=data.get("module", ""),
            cwe=data.get("cwe", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""
        return asdict(self)



@dataclass(frozen=True)
class Observation:
    """A non-vulnerability observation from a scan."""

    name: str
    value: Any
    source: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Observation":
        """Instantiate from dictionary."""
        return cls(
            name=data.get("name", "unknown"),
            value=data.get("value"),
            source=data.get("source", "unknown"),
        )

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

