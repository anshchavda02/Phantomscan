"""Orchestrator for PhantomScan advanced security modules."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from phantomscan.http_client import RobustHTTPClient
from phantomscan.modules import get_all_modules

logger = logging.getLogger(__name__)

# Modules that run after active scanning is complete (post-processing)
_POST_SCAN_MODULES = {
    "vuln_chain", "attack_path", "compliance", "ai_narrative", "continuous_monitor",
    "trend_predictor", "expiry_calendar", "scan_merger"
}


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
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Execute advanced modules based on the selected profile."""
    all_modules = get_all_modules()
    active_findings: list[dict[str, Any]] = list(findings)
    new_observations: list[dict[str, Any]] = list(observations)

    # Determine which modules to run based on profile
    modules_to_run = set()
    if profile == "advanced":
        # Run everything except continuous monitor (requires args)
        modules_to_run = set(all_modules.keys()) - {"continuous_monitor"}
    elif profile == "deep":
        modules_to_run = set(all_modules.keys()) - {"continuous_monitor"}
    elif profile == "monitor":
        modules_to_run = {"continuous_monitor"}
    elif "," in profile:
        modules_to_run = {m.strip() for m in profile.split(",") if m.strip() in all_modules}

    # Setup active modules (those that send traffic)
    active_tasks = []
    for name in modules_to_run:
        if name not in _POST_SCAN_MODULES:
            cls = all_modules[name]
            instance = cls(http=http_client)
            # Pass common kwargs; modules ignore what they don't need
            task = instance.run(
                base_url=base_url,
                observations=new_observations,
                auth_cookie=auth_cookie,
                auth_token=auth_token,
                source_path=source_path,
                check_slopsquatting=check_slopsquatting,
            )
            active_tasks.append((name, task))

    if active_tasks:
        logger.info(f"Running {len(active_tasks)} active advanced modules...")
        results = await asyncio.gather(*(t for _, t in active_tasks), return_exceptions=True)
        
        for (name, _), result in zip(active_tasks, results):
            if isinstance(result, Exception):
                logger.error(f"Module {name} failed: {result}")
            elif isinstance(result, list):
                logger.info(f"Module {name} completed: {len(result)} findings")
                active_findings.extend(result)

    # Setup post-scan modules (analysis only)
    # Order matters: chain engine must run before attack path
    post_order = ["vuln_chain", "attack_path", "compliance", "ai_narrative", "continuous_monitor"]
    
    for name in post_order:
        if name in modules_to_run and name in all_modules:
            logger.info(f"Running post-scan module: {name}...")
            cls = all_modules[name]
            instance = cls(http=http_client)
            try:
                result = await instance.run(
                    base_url=base_url,
                    observations=new_observations,
                    findings=active_findings,
                    baseline_path=baseline_path,
                    webhook_url=webhook_url,
                )
                if isinstance(result, list):
                    active_findings.extend(result)
            except Exception as exc:
                logger.error(f"Post-scan module {name} failed: {exc}")

    return active_findings, new_observations
