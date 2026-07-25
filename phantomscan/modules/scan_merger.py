"""Module 13 — Scan Merge / Dedupe for Teams.

Merge multiple scan result files into a single deduplicated report,
tracking assessor credit and removing duplicate findings across team scans.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)


@dataclass
class MergedScanResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    total_before_merge: int = 0
    total_after_merge: int = 0
    duplicates_removed: int = 0
    assessors: list[str] = field(default_factory=list)


class TeamScanMerger:
    """Merge and deduplicate scan JSON files from multiple assessors/scans."""

    def __init__(self, http: RobustHTTPClient | None = None) -> None:
        self.http = http

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface."""
        scan_files = kwargs.get("scan_files", [])
        if len(scan_files) >= 2:
            res = self.merge_files(scan_files)
            return res.findings
        return []

    def merge_scans(self, scan_results: list[dict[str, Any]]) -> MergedScanResult:
        """Merge a list of raw scan dictionary results into one deduplicated set."""
        all_findings: dict[str, dict[str, Any]] = {}
        total_before = 0
        assessors_set: set[str] = set()

        for scan in scan_results:
            assessor = scan.get("assessor", scan.get("scan_meta", {}).get("assessor", "Anonymous"))
            assessors_set.add(assessor)
            scan_findings = scan.get("findings", [])
            total_before += len(scan_findings)

            for f in scan_findings:
                key = self.finding_key(f)
                if key in all_findings:
                    # Duplicate found — append assessor credit
                    found_by = all_findings[key].get("found_by", [])
                    if assessor not in found_by:
                        found_by.append(assessor)
                    all_findings[key]["found_by"] = found_by
                else:
                    f_copy = dict(f)
                    f_copy["found_by"] = [assessor]
                    all_findings[key] = f_copy

        merged_findings = list(all_findings.values())
        total_after = len(merged_findings)

        return MergedScanResult(
            findings=merged_findings,
            total_before_merge=total_before,
            total_after_merge=total_after,
            duplicates_removed=total_before - total_after,
            assessors=list(assessors_set),
        )

    def merge_files(self, file_paths: list[str]) -> MergedScanResult:
        """Load scan files from disk and merge them."""
        scans: list[dict[str, Any]] = []
        for path_str in file_paths:
            path = Path(path_str)
            if path.exists():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    scans.append(data)
                except Exception as exc:
                    logger.error("Failed to load scan file %s: %s", path_str, exc)

        return self.merge_scans(scans)

    @staticmethod
    def finding_key(finding: dict[str, Any]) -> str:
        """Generate a stable SHA-256 hash key for a finding."""
        raw_str = (
            f"{finding.get('title', '')}:"
            f"{finding.get('category', '')}:"
            f"{finding.get('target', '')}:"
            f"{finding.get('cwe', '')}"
        )
        return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()
