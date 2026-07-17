"""False-positive post-processing entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from phantomscan.postprocess import post_process


def apply_rules(
    findings: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    data_dir: Path,
    target_host: str,
    fp_log_path: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Apply all PhantomScan suppression rules with medium findings included."""
    return post_process(
        findings=findings,
        observations=observations,
        data_dir=data_dir,
        target_host=target_host,
        include_medium=True,
        include_low=False,
        fp_log_path=fp_log_path,
    )

