from __future__ import annotations

import logging
from typing import Any

from phantomscan.asset_graph import AssetGraph
from phantomscan.http_client import RobustHTTPClient
from phantomscan.pipeline import PipelineDAG

logger = logging.getLogger(__name__)


async def run_advanced_modules(
    target: str,
    base_url: str,
    http_client: RobustHTTPClient,
    observations: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    profile: str = "advanced",
    auth_cookie: str | None = None,
    auth_token: str | None = None,
    baseline_path: str | None = None,
    webhook_url: str | None = None,
    source_path: str | None = None,
    check_slopsquatting: bool = False,
    asset_graph: AssetGraph | None = None,
    max_concurrency: int = 15,
    force_all: bool = False,
    **kwargs: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Execute advanced modules orchestrated by the dependency DAG pipeline."""
    dag = PipelineDAG()
    return await dag.execute_pipeline(
        target=target,
        base_url=base_url,
        http_client=http_client,
        observations=observations,
        findings=findings,
        profile=profile,
        asset_graph=asset_graph,
        max_concurrency=max_concurrency,
        force_all=force_all,
        auth_cookie=auth_cookie,
        auth_token=auth_token,
        baseline_path=baseline_path,
        webhook_url=webhook_url,
        source_path=source_path,
        check_slopsquatting=check_slopsquatting,
        **kwargs,
    )

