"""Module 2 — Differential Environment Scanner.

Compare staging vs production security posture to identify regressions
(issues fixed in staging but still present in production) and improvements.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)


@dataclass
class DiffEnvironmentResult:
    """Result of comparing two environments."""
    staging_score: int = 0
    production_score: int = 0
    regressions: list[dict[str, Any]] = field(default_factory=list)
    improvements: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""


class DifferentialScanner:
    """Compare staging vs production security posture."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface — typically invoked directly via CLI."""
        return []

    async def compare(
        self,
        staging_results: dict[str, Any],
        production_results: dict[str, Any],
    ) -> DiffEnvironmentResult:
        """Compare two scan result dicts and identify regressions/improvements."""

        staging_findings = staging_results.get("findings", [])
        prod_findings = production_results.get("findings", [])

        staging_score = staging_results.get("score", 0)
        prod_score = production_results.get("score", 0)

        # Build fingerprint sets for comparison
        staging_keys = {self._finding_key(f) for f in staging_findings}
        prod_keys = {self._finding_key(f) for f in prod_findings}

        # Regressions: in prod but NOT in staging (fixed in staging, not deployed)
        regression_keys = prod_keys - staging_keys
        regressions: list[dict[str, Any]] = []
        for f in prod_findings:
            if self._finding_key(f) in regression_keys:
                regressions.append({
                    "title": f"Regression: {f.get('title', 'Unknown')}",
                    "severity": f.get("severity", "info"),
                    "confidence": "high",
                    "category": "regression",
                    "target": f.get("target", ""),
                    "evidence": (
                        f"Staging: NOT present (fixed)\n"
                        f"Production: {f.get('evidence', 'present')}"
                    ),
                    "recommendation": (
                        "Deploy staging fixes to production. "
                        "This issue has been resolved in staging but remains in production."
                    ),
                    "references": f.get("references", []),
                    "module": "diff_env_scanner",
                    "badge": "DEPLOY GAP",
                })

        # Improvements: in staging but NOT in prod (new issues in staging)
        improvement_keys = staging_keys - prod_keys
        improvements: list[dict[str, Any]] = []
        for f in staging_findings:
            if self._finding_key(f) in improvement_keys:
                improvements.append(f)

        summary = (
            f"{len(regressions)} regression(s) found — issues fixed in staging "
            f"but not deployed to production. "
            f"Staging score: {staging_score}/100, Production score: {prod_score}/100."
        )

        return DiffEnvironmentResult(
            staging_score=staging_score,
            production_score=prod_score,
            regressions=regressions,
            improvements=improvements,
            summary=summary,
        )

    @staticmethod
    def _finding_key(finding: dict[str, Any]) -> str:
        """Generate a stable key for deduplication."""
        import hashlib
        components = (
            f"{finding.get('title', '')}:"
            f"{finding.get('category', '')}:"
            f"{finding.get('target', '')}"
        )
        return hashlib.sha256(components.encode()).hexdigest()[:16]
