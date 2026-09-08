"""Finding Deduplication and Response Fingerprinting Engine.

Provides fingerprint-based finding deduplication, occurrence tracking,
confidence calibration, and evidence aggregation across multi-page scans.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


CONFIDENCE_SCORES: dict[str, int] = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEVERITY_SCORES: dict[str, int] = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def compute_response_hash(body: str, status: int = 200, headers: dict[str, str] | None = None) -> str:
    """Compute a deterministic content hash ignoring variable dynamic tokens."""
    cleaned = re.sub(r"[a-f0-9]{32,64}", "", body)
    cleaned = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", "", cleaned)
    cleaned = re.sub(r"<!--.*?-->", "", cleaned, flags=re.DOTALL)
    raw = f"{status}:{len(cleaned)}:{cleaned[:4000]}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


def calibrate_confidence(finding: dict[str, Any] | Any, context: dict[str, Any] | None = None) -> dict[str, Any] | Any:
    """Calibrate finding confidence and severity according to verification method and evidence."""
    is_obj = hasattr(finding, "confidence")
    d = finding.__dict__ if is_obj else finding

    conf = str(d.get("confidence", "MEDIUM")).upper()
    sev = str(d.get("severity", "info")).upper()
    method = str(d.get("verification_method", "")).lower()

    # Passive observation cannot yield HIGH confidence unless specifically external verified
    if method == "passive_observation" and conf == "HIGH":
        if "secret" not in str(d.get("category", "")).lower():
            conf = "MEDIUM"
            if is_obj:
                setattr(finding, "confidence", "MEDIUM")
            else:
                d["confidence"] = "MEDIUM"

    # Critical/High findings require HIGH confidence per FindingGate rule 6
    if sev in ("CRITICAL", "HIGH") and conf != "HIGH":
        if is_obj:
            setattr(finding, "severity", "medium")
            setattr(finding, "downgraded_reason", "Confidence not HIGH for critical/high severity")
        else:
            d["severity"] = "medium"
            d["downgraded_reason"] = "Confidence not HIGH for critical/high severity"

    return finding


@dataclass
class FindingFingerprint:
    """Normalized fingerprint representation of a finding."""

    finding_id: str
    target_path: str
    module: str
    signature: str = ""

    @classmethod
    def from_finding(cls, finding: dict[str, Any] | Any) -> FindingFingerprint:
        f = finding.to_dict() if hasattr(finding, "to_dict") else (finding.__dict__ if hasattr(finding, "__dict__") and not isinstance(finding, dict) else finding)
        fid = str(f.get("id", "")).strip().upper()
        title = str(f.get("title", "")).strip()
        target = str(f.get("target", ""))
        parsed = urlparse(target)
        endpoint_path = parsed.path.rstrip("/") or "/"
        module = str(f.get("module", f.get("category", "general")))
        param = str(f.get("param", f.get("parameter", "")))

        # Stable 20-character hash key
        raw_key = f"{title.lower()}:{module}:{endpoint_path}:{param}"
        stable_hash = hashlib.sha256(raw_key.encode("utf-8", errors="ignore")).hexdigest()[:20]

        return cls(finding_id=fid, target_path=f"{parsed.netloc}{endpoint_path}", module=module, signature=stable_hash)

    @property
    def key(self) -> str:
        return self.signature


class FindingDeduplicator:
    """Deduplicates security findings while merging occurrences and retaining highest confidence/severity."""

    def __init__(self) -> None:
        self._seen: dict[str, dict[str, Any]] = {}
        self._counts: dict[str, int] = {}

    def deduplicate(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Deduplicate findings list, retaining the higher confidence/severity finding when duplicates occur."""
        unique_findings: list[dict[str, Any]] = []

        for f in findings:
            fp = FindingFingerprint.from_finding(f)
            k = fp.key
            if k not in self._seen:
                entry = dict(f)
                entry.setdefault("occurrences", 1)
                self._seen[k] = entry
                self._counts[k] = 1
                unique_findings.append(entry)
            else:
                self._counts[k] += 1
                existing = self._seen[k]
                existing["occurrences"] = self._counts[k]

                # Compare confidence and severity to retain best finding details
                existing_conf = str(existing.get("confidence", "MEDIUM")).upper()
                new_conf = str(f.get("confidence", "MEDIUM")).upper()
                existing_sev = str(existing.get("severity", "INFO")).upper()
                new_sev = str(f.get("severity", "INFO")).upper()

                existing_rank = (CONFIDENCE_SCORES.get(existing_conf, 1), SEVERITY_SCORES.get(existing_sev, 1))
                new_rank = (CONFIDENCE_SCORES.get(new_conf, 1), SEVERITY_SCORES.get(new_sev, 1))

                if new_rank > existing_rank:
                    occurrences = existing["occurrences"]
                    existing.clear()
                    existing.update(f)
                    existing["occurrences"] = occurrences

        return unique_findings
