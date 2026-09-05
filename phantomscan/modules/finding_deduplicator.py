"""Finding Deduplication and Response Fingerprinting Engine.

Provides fingerprint-based finding deduplication, occurrence tracking,
and evidence aggregation across multi-page, multi-parameter scans.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


def compute_response_hash(body: str, status: int = 200, headers: dict[str, str] | None = None) -> str:
    """Compute a deterministic content hash ignoring variable dynamic tokens."""
    # Strip common dynamic tokens (CSRF tokens, viewstates, timestamps, request IDs)
    cleaned = re.sub(r"[a-f0-9]{32,64}", "", body)
    cleaned = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", "", cleaned)
    cleaned = re.sub(r"<!--.*?-->", "", cleaned, flags=re.DOTALL)
    raw = f"{status}:{len(cleaned)}:{cleaned[:4000]}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


@dataclass
class FindingFingerprint:
    """Normalized fingerprint representation of a finding."""

    finding_id: str
    target_path: str
    module: str
    signature: str = ""

    @classmethod
    def from_finding(cls, finding: dict[str, Any]) -> FindingFingerprint:
        fid = str(finding.get("id", "")).strip().upper()
        target = str(finding.get("target", ""))
        parsed = urlparse(target)
        path = parsed.path.rstrip("/") or "/"
        module = str(finding.get("module", finding.get("category", "general")))
        evidence = str(finding.get("evidence", ""))
        sig = hashlib.sha256(evidence[:300].encode("utf-8", errors="ignore")).hexdigest()[:12]
        return cls(finding_id=fid, target_path=f"{parsed.netloc}{path}", module=module, signature=sig)

    @property
    def key(self) -> str:
        return f"{self.finding_id}:{self.target_path}:{self.signature}"


class FindingDeduplicator:
    """Deduplicates security findings while merging occurrences and evidence."""

    def __init__(self) -> None:
        self._seen: dict[str, dict[str, Any]] = {}
        self._counts: dict[str, int] = {}

    def deduplicate(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Deduplicate findings list, preserving order and aggregating occurrences."""
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

        return unique_findings
