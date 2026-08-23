"""Scan orchestrator defining modular scan execution order."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable, Optional

from modules.fp_postprocessor import apply_rules
from modules.score_engine import calculate_score, Score
from phantomscan.postprocess import load_known_platform
from phantomscan.scope import root_domain

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates scan execution stages ensuring strict ordering:
    1. Scan modules execution -> Raw findings collected
    2. False-positive postprocessing -> Clean findings (false positives suppressed)
    3. Score engine -> Score calculated on CLEAN findings ONLY
    4. Report generation
    """

    def __init__(self, data_dir: Optional[Path] = None) -> None:
        self.data_dir = data_dir or (Path(__file__).parent.parent / "data")
        self.execution_order: list[str] = []

    def postprocess_findings(
        self,
        findings: list[dict[str, Any]],
        observations: list[dict[str, Any]],
        target_host: str,
        fp_log_path: Optional[Path] = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Step 2: Suppress false positives and clean findings."""
        self.execution_order.append("fp_postprocessor")
        r_domain = root_domain(target_host)
        return apply_rules(
            findings=findings,
            observations=observations,
            data_dir=self.data_dir,
            target_host=r_domain,
            fp_log_path=fp_log_path or (self.data_dir.parent / "reports" / "fp_log.json"),
        )

    def calculate_scan_score(
        self,
        clean_findings: list[dict[str, Any]],
        observations: list[dict[str, Any]],
        target_host: str,
    ) -> Score:
        """Step 3: Calculate score on clean findings only."""
        self.execution_order.append("score_engine")
        r_domain = root_domain(target_host)
        platform = load_known_platform(self.data_dir, r_domain)
        return calculate_score(
            findings=clean_findings,
            observations=observations,
            platform=platform,
        )

    def run_pipeline(
        self,
        raw_findings: list[dict[str, Any]],
        observations: list[dict[str, Any]],
        target_host: str,
        fp_log_path: Optional[Path] = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], Score]:
        """Execute post-processing and scoring in strictly validated order."""
        # 1. Post-process (FP filter)
        clean_findings, suppressed, clean_obs = self.postprocess_findings(
            findings=raw_findings,
            observations=observations,
            target_host=target_host,
            fp_log_path=fp_log_path,
        )

        # 2. Score calculation on clean findings
        score_obj = self.calculate_scan_score(
            clean_findings=clean_findings,
            observations=clean_obs,
            target_host=target_host,
        )

        return clean_findings, suppressed, score_obj
