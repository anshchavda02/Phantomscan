"""Module 17 — Continuous Monitoring with Alerting.

Provides diff-based scan comparison and webhook alerting for new findings.
Designed to run as a single-shot "scan + diff + alert" workflow.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)


class ContinuousMonitor:
    """Compare scan results against baselines and send alerts for new findings."""

    def __init__(self, http: RobustHTTPClient | None = None) -> None:
        self.http = http

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        findings: list[dict[str, Any]] | None = None,
        baseline_path: str | None = None,
        webhook_url: str | None = None,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Compare current findings against baseline and optionally alert."""
        if not findings:
            return []

        result_findings: list[dict[str, Any]] = []
        target = base_url.rstrip("/")

        # Load baseline if it exists
        baseline = self._load_baseline(baseline_path)

        if baseline:
            new_findings = self._diff_findings(baseline, findings)
            resolved_findings = self._find_resolved(baseline, findings)

            if new_findings:
                result_findings.append({
                    "id": "MONITOR-NEW-FINDINGS",
                    "title": f"Continuous Monitor: {len(new_findings)} New Finding(s)",
                    "severity": self._highest_severity(new_findings),
                    "confidence": "high",
                    "category": "monitoring",
                    "target": target,
                    "evidence": (
                        f"Compared against baseline with {len(baseline)} findings.\n"
                        f"New findings:\n" +
                        "\n".join(
                            f"  [{f.get('severity', 'info').upper()}] {f.get('title', '')}"
                            for f in new_findings[:20]
                        )
                    ),
                    "recommendation": (
                        "Investigate new findings since the last baseline scan. "
                        "These may indicate new vulnerabilities introduced by "
                        "recent changes."
                    ),
                })

            if resolved_findings:
                result_findings.append({
                    "id": "MONITOR-RESOLVED",
                    "title": f"Continuous Monitor: {len(resolved_findings)} Finding(s) Resolved",
                    "severity": "info",
                    "confidence": "high",
                    "category": "monitoring",
                    "target": target,
                    "evidence": (
                        f"Resolved since baseline:\n" +
                        "\n".join(
                            f"  ✓ {f.get('title', '')}"
                            for f in resolved_findings[:20]
                        )
                    ),
                    "recommendation": "Continue monitoring for regressions.",
                })

            # Send webhook alert for new critical/high findings
            if webhook_url and new_findings:
                critical_high = [
                    f for f in new_findings
                    if f.get("severity") in ("critical", "high")
                ]
                if critical_high:
                    await self._send_webhook(
                        webhook_url, target, critical_high
                    )
        else:
            result_findings.append({
                "id": "MONITOR-BASELINE-CREATED",
                "title": "Continuous Monitor: Baseline Established",
                "severity": "info",
                "confidence": "high",
                "category": "monitoring",
                "target": target,
                "evidence": (
                    f"No previous baseline found. Current scan with "
                    f"{len(findings)} findings will serve as the baseline."
                ),
                "recommendation": "Run future scans to detect changes.",
            })

        # Save current findings as new baseline
        self._save_baseline(baseline_path, findings)

        return result_findings

    def _load_baseline(self, path: str | None) -> list[dict[str, Any]] | None:
        if not path:
            return None
        p = Path(path)
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load baseline: %s", exc)
            return None

    def _save_baseline(
        self, path: str | None, findings: list[dict[str, Any]]
    ) -> None:
        if not path:
            return
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            p.write_text(
                json.dumps(findings, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("Failed to save baseline: %s", exc)

    def _diff_findings(
        self,
        baseline: list[dict[str, Any]],
        current: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        baseline_keys = {
            self._finding_key(f) for f in baseline
        }
        return [
            f for f in current
            if self._finding_key(f) not in baseline_keys
        ]

    def _find_resolved(
        self,
        baseline: list[dict[str, Any]],
        current: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        current_keys = {
            self._finding_key(f) for f in current
        }
        return [
            f for f in baseline
            if self._finding_key(f) not in current_keys
        ]

    @staticmethod
    def _finding_key(f: dict[str, Any]) -> str:
        return f"{f.get('id', '')}|{f.get('title', '')}|{f.get('target', '')}"

    @staticmethod
    def _highest_severity(findings: list[dict[str, Any]]) -> str:
        order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        best = "info"
        for f in findings:
            sev = f.get("severity", "info")
            if order.get(sev, 0) > order.get(best, 0):
                best = sev
        return best

    async def _send_webhook(
        self,
        webhook_url: str,
        target: str,
        findings: list[dict[str, Any]],
    ) -> None:
        if not self.http:
            return
        payload = {
            "text": (
                f"🚨 PhantomScan Alert: {len(findings)} new "
                f"critical/high finding(s) on {target}"
            ),
            "findings": [
                {
                    "title": f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "target": f.get("target", ""),
                }
                for f in findings[:10]
            ],
            "timestamp": int(time.time()),
        }
        try:
            await self.http.post(webhook_url, json=payload, retries=1)
            logger.info("Webhook alert sent to %s", webhook_url)
        except Exception as exc:
            logger.warning("Webhook alert failed: %s", exc)
