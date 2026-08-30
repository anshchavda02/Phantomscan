"""Shared data models and contract definitions for PhantomScan."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Literal
from urllib.parse import urlparse

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
FindingStatus = Literal[
    "discovered",
    "candidate",
    "verifying",
    "confirmed",
    "unconfirmed",
    "false_positive",
    "suppressed",
    "resolved",
    "reopened",
]


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_CONFIDENCES = {"high", "medium", "low"}
VALID_FINDING_STATUSES = {
    "discovered",
    "candidate",
    "verifying",
    "confirmed",
    "unconfirmed",
    "false_positive",
    "suppressed",
    "resolved",
    "reopened",
}
VALID_VERIFICATION_METHODS = {
    "baseline_differential",
    "multi_source_agreement",
    "active_confirmation",
    "dynamic_confirmed",
    "external_verification",
    "passive_observation",
    "",
}


def compute_finding_fingerprint(
    target: str = "",
    url: str = "",
    rule_id: str = "",
    param_name: str = "",
    method: str = "GET",
    evidence: str = "",
    title: str = "",
    cwe: str = "",
) -> str:
    """Compute a deterministic, immutable SHA-256 fingerprint for a finding.
    
    The fingerprint uniquely identifies the vulnerability by its normalized
    location, rule, parameter, and sanitized evidence context, enabling
    accurate cross-scan deduplication and baseline regression tracking.
    """
    clean_target = (target or "").strip().lower()
    
    # Normalize URL path component
    clean_path = ""
    if url:
        try:
            parsed = urlparse(url.strip())
            clean_path = f"{parsed.netloc.lower()}{parsed.path.rstrip('/') or '/'}"
        except Exception:
            clean_path = url.strip().lower()
    
    clean_rule = (rule_id or title or "").strip().upper()
    clean_param = (param_name or "").strip().lower()
    clean_method = (method or "GET").strip().upper()
    clean_cwe = (cwe or "").strip().upper()
    
    # Sanitize evidence: take first 120 chars without variable whitespace or transient tokens
    sanitized_evidence = re.sub(r"\s+", " ", (evidence or "").strip())[:120]
    
    key_components = [
        clean_target,
        clean_path,
        clean_rule,
        clean_param,
        clean_method,
        clean_cwe,
        sanitized_evidence,
    ]
    raw_key = ":".join(key_components)
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


# ── Structured Evidence Models ────────────────────────────────────────────────


@dataclass(frozen=True)
class Evidence:
    """Base evidence model."""
    summary: str = ""
    verification_type: str = ""
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HTTPEvidence(Evidence):
    """HTTP transaction evidence for request/response vulnerabilities."""
    request_method: str = "GET"
    request_url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body_sample: str = ""
    response_time_ms: int = 0
    diff_from_baseline: str = ""


@dataclass(frozen=True)
class DOMEvidence(Evidence):
    """Client-side DOM vulnerability evidence."""
    source: str = ""
    sink: str = ""
    taint_path: str = ""
    execution_context: str = ""


@dataclass(frozen=True)
class TLSEvidence(Evidence):
    """TLS/SSL cryptographic evidence."""
    protocol: str = ""
    cipher: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    days_remaining: int = 0
    is_expired: bool = False
    is_self_signed: bool = False


@dataclass(frozen=True)
class TimingEvidence(Evidence):
    """Statistical timing differential evidence."""
    baseline_duration_ms: float = 0.0
    payload_duration_ms: float = 0.0
    time_difference_ms: float = 0.0
    std_dev_ms: float = 0.0
    samples_collected: int = 0


# ── Finding Model ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Finding:
    """A normalized, evidence-backed security finding."""

    id: str = ""
    title: str = ""
    severity: Severity = "info"
    confidence: Confidence = "low"
    category: str = "web"
    target: str = ""
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    verification_method: str = ""
    module: str = ""
    cwe: str = ""
    description: str = ""
    uid: str = ""

    # Phase 1: Lifecycle, fingerprinting & rich contextual fields
    status: FindingStatus = "confirmed"
    fingerprint: str = ""
    rule_id: str = ""
    url: str = ""
    method: str = ""
    parameter: str = ""
    request_sample: str = ""
    response_sample: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str = ""
    first_seen: str = field(default_factory=utc_now)
    last_seen: str = field(default_factory=utc_now)
    owasp_category: str = ""
    impact: str = ""
    remediation_guidance: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate and normalize fields."""
        # Normalise severity, confidence, status to lowercase
        sev = str(self.severity).lower() if self.severity else "info"
        conf = str(self.confidence).lower() if self.confidence else "low"
        stat = str(self.status).lower() if self.status else "confirmed"

        object.__setattr__(self, "severity", sev)
        object.__setattr__(self, "confidence", conf)
        object.__setattr__(self, "status", stat)

        if not self.id and self.title:
            gen_id = "FINDING-" + re.sub(r"[^A-Z0-9]+", "-", self.title.upper()).strip("-")[:30]
            object.__setattr__(self, "id", gen_id)
        if not self.recommendation and self.description:
            object.__setattr__(self, "recommendation", self.description)
        if not self.description and self.recommendation:
            object.__setattr__(self, "description", self.recommendation)
        if not self.uid:
            base_id = self.id or "finding"
            clean_slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(base_id).lower()).strip("-")
            object.__setattr__(self, "uid", f"finding-{clean_slug}")
        if not self.rule_id:
            object.__setattr__(self, "rule_id", self.id)

        # Generate deterministic fingerprint if not supplied
        if not self.fingerprint:
            computed_fp = compute_finding_fingerprint(
                target=self.target,
                url=self.url,
                rule_id=self.rule_id or self.id,
                param_name=self.parameter,
                method=self.method,
                evidence=self.evidence,
                title=self.title,
                cwe=self.cwe,
            )
            object.__setattr__(self, "fingerprint", computed_fp)

        # Field validation
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity}")
        if self.confidence not in VALID_CONFIDENCES:
            raise ValueError(f"Invalid confidence: {self.confidence}")
        if self.status not in VALID_FINDING_STATUSES:
            raise ValueError(f"Invalid status: {self.status}")
        if self.verification_method and self.verification_method not in VALID_VERIFICATION_METHODS:
            raise ValueError(
                f"Invalid verification_method: {self.verification_method}"
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Instantiate from dictionary."""
        refs = data.get("references", [])
        if isinstance(refs, str):
            refs = [refs] if refs.strip() else []
        elif not isinstance(refs, list):
            refs = []

        repro = data.get("reproduction_steps", [])
        if isinstance(repro, str):
            repro = [repro] if repro.strip() else []
        elif not isinstance(repro, list):
            repro = []

        meta = data.get("metadata", {})
        if not isinstance(meta, dict):
            meta = {}

        return cls(
            id=str(data.get("id", "")),
            title=str(data.get("title", "Unknown")),
            severity=data.get("severity", "info"),
            confidence=data.get("confidence", "low"),
            category=str(data.get("category", "general")),
            target=str(data.get("target", "")),
            evidence=str(data.get("evidence", "")),
            recommendation=str(data.get("recommendation", "")),
            references=refs,
            verification_method=str(data.get("verification_method", "")),
            module=str(data.get("module", "")),
            cwe=str(data.get("cwe", "")),
            description=str(data.get("description", "")),
            uid=str(data.get("uid", "")),
            status=data.get("status", "confirmed"),
            fingerprint=str(data.get("fingerprint", "")),
            rule_id=str(data.get("rule_id", "")),
            url=str(data.get("url", "")),
            method=str(data.get("method", "")),
            parameter=str(data.get("parameter", "")),
            request_sample=str(data.get("request_sample", "")),
            response_sample=str(data.get("response_sample", "")),
            reproduction_steps=repro,
            cvss_score=float(data["cvss_score"]) if data.get("cvss_score") is not None else None,
            cvss_vector=str(data.get("cvss_vector", "")),
            first_seen=str(data.get("first_seen", "")) or utc_now(),
            last_seen=str(data.get("last_seen", "")) or utc_now(),
            owasp_category=str(data.get("owasp_category", "")),
            impact=str(data.get("impact", "")),
            remediation_guidance=str(data.get("remediation_guidance", "")),
            metadata=meta,
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
            name=str(data.get("name", "unknown")),
            value=data.get("value"),
            source=str(data.get("source", "unknown")),
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


